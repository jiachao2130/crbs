// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Hub 日志流缓冲：接收 Worker 的 chunked POST，为 CLI / Web UI SSE 提供实时日志读取。
//!
//! 按 `build_id` 分桶的内存缓冲，FIFO 淘汰；上限三层：单条 chunk 1MB
//!（[`MAX_LOG_CHUNK_BYTES`]，超限入口拒收）、单 build 10MB、全局总量 1GiB
//!（[`max_log_buffer_total_bytes`]）。多并发读取者各自独立 offset；构建
//! 完成后日志随产物落盘，此处只留实时内容。

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::Notify;

/// 单个 build 的日志缓冲上限（10MB）。
const MAX_LOG_BUFFER_PER_BUILD: usize = 10 * 1024 * 1024;

/// 所有 build 的日志缓冲总字节上限（生产 1GiB）。per-build 10MB 拦不住
/// concurrent_builds×10MB 灌爆内存，全局兜总账：超限拒收新 chunk（实时
/// tail 降级，磁盘日志不受影响），evict / FIFO 回落可再收。测试值必须
/// 大于 per-build 上限，否则 FIFO 语义先被全局上限踩到。
const fn max_log_buffer_total_bytes() -> usize {
    if cfg!(test) {
        12 * 1024 * 1024
    } else {
        1024 * 1024 * 1024
    }
}

/// 单条日志 chunk 的尺寸上限（1MB）。防恶意/失控 worker 的内存放大。
/// 超限入口拒收：不推进 `next_offset`，后续 chunk offset 保持连续（读端
/// 无空洞）；report_logs 另有同上限的 400 预检让 worker 立即感知。
pub(crate) const MAX_LOG_CHUNK_BYTES: usize = 1024 * 1024;

/// 单条日志 chunk，记录其在该 build 日志流中的起始字节偏移。
#[derive(Debug, Clone)]
struct LogChunk {
    offset: usize,
    data: Bytes,
}

/// 单个 build 的日志缓冲条目。
#[derive(Debug, Default, Clone)]
struct LogBufferEntry {
    /// 按 offset 升序。
    chunks: VecDeque<LogChunk>,
    /// 单调递增，不随淘汰回退。
    next_offset: usize,
    current_size: usize,
    /// 终态墓碑：数据已释放，拦截迟到 chunk / 注册复活。
    terminal: bool,
}

/// 全局日志缓冲。锁全部 `unwrap_or_else(|e| e.into_inner())` 恢复 poison：
/// 只存构建期临时 chunk（不承载持久状态），poison 后继续比 panic 安全——
/// 最坏实时 tail 短暂不完整，不影响已落盘日志。逐 build 变更通知
/// （[`Self::wait_change`]）驱动 log SSE + 兜底轮询；两锁互不嵌套。
#[derive(Debug, Default, Clone)]
pub struct LogBuffer {
    buffers: Arc<Mutex<HashMap<i64, LogBufferEntry>>>,
    /// 逐 build 变更通知句柄（register/append/evict 时 `notify_waiters`）。
    /// 与 entry 解耦的独立 map：SSE 等待方须在 entry 建立之前就能挂上等待
    ///（register 首建 entry 正是等待的事件，Notify 收在 entry 内则此时无从
    /// 取得句柄）。`evict` 连句柄一并移除，残留与 entries 同界。
    notifies: Arc<Mutex<HashMap<i64, Arc<Notify>>>>,
    /// 全局总字节数记账。必须 Arc：`LogBuffer` 是 `Clone` 共享语义，裸字段
    /// 各副本分账、上限失真；只在 `buffers` 持锁段内读写，check-then-act 无竞争。
    total_bytes: Arc<AtomicU64>,
    /// 全局上限首次拒收的 warn 旗标：进程内只警告一次，回落再超限不重刷。
    total_cap_warned: Arc<AtomicBool>,
}

impl LogBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// 追加日志 chunk；返回 `false` = 拒收，两种形态语义分流：
    /// - 终态墓碑 / 单条超 [`MAX_LOG_CHUNK_BYTES`]：状态完全不变，不推进
    ///   `next_offset`，后续 chunk offset 连续（调用方不落盘：409 / 400）。
    /// - 全局总字节达 [`max_log_buffer_total_bytes`]：chunk 不入缓冲，但
    ///   `next_offset` 仍推进被拒窗口长度——report_logs 无视拒收仍落盘，
    ///   不推进则 buffer 永久落后文件位置（终态磁盘补尾重复重放）；窗口
    ///   成为 front_offset 空洞：无更旧存活 chunk 的读者以 start < front
    ///   判洞、从磁盘补回，仍有者在途实时流静默跳过（触顶下 tail 降级
    ///   语义）。evict / FIFO 回落后可再收。单 build 超上限时 FIFO 丢最旧。
    pub fn append(&self, build_id: i64, data: Bytes) -> bool {
        let accepted;
        {
            let mut buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
            let entry = buffers.entry(build_id).or_default();
            if entry.terminal {
                return false;
            }
            if data.len() > MAX_LOG_CHUNK_BYTES {
                return false;
            }
            let len = data.len();
            if self.total_bytes.load(Ordering::Relaxed) + len as u64
                > max_log_buffer_total_bytes() as u64
            {
                if !self.total_cap_warned.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        total_bytes = self.total_bytes.load(Ordering::Relaxed),
                        cap = max_log_buffer_total_bytes(),
                        "Log buffer global cap reached; real-time tail degraded until buffers are evicted (on-disk logs unaffected)"
                    );
                }
                // 拒收仍推进 next_offset（理由见函数 doc）；total_bytes 不变。
                entry.next_offset += len;
                accepted = false;
            } else {
                let offset = entry.next_offset;
                entry.chunks.push_back(LogChunk { offset, data });
                entry.next_offset += len;
                entry.current_size += len;
                self.total_bytes.fetch_add(len as u64, Ordering::Relaxed);

                // FIFO 淘汰永不丢最新一条：条件 `len() > 1` 而非 `!is_empty()`，
                // 至多进行到只剩最后一条（单条 1MB 上限下单条即超限已不可构造）。
                while Self::entry_size(entry) > MAX_LOG_BUFFER_PER_BUILD && entry.chunks.len() > 1 {
                    if let Some(front) = entry.chunks.pop_front() {
                        entry.current_size -= front.data.len();
                        self.total_bytes
                            .fetch_sub(front.data.len() as u64, Ordering::Relaxed);
                    }
                }
                accepted = true;
            }
        }
        // 拒收的 offset 推进对等待读者同样是可见状态变化，照常广播。
        self.notify_change(build_id);
        accepted
    }

    /// 读取从指定 offset 开始的日志 chunk，返回 `(chunks, next_offset,
    /// front_offset)`（同一把锁的原子快照）：`next_offset` 单调递增，供下次
    /// 调用作 `offset`；`front_offset` 为最旧存活 chunk 起点（空 / 墓碑时 =
    /// `next_offset`），更小偏移已被 FIFO 淘汰，读取端据此判洞并从磁盘补读
    /// ——刻意不给独立访问器，防分锁另取的洞检测失真（TOCTOU）。多读取者
    /// 各自 offset 互不干扰。
    pub fn read_since(&self, build_id: i64, offset: usize) -> (Vec<Bytes>, usize, usize) {
        // 委托 with_offsets 单锁快照，仅丢弃各 chunk 偏移（不得二次取锁）。
        let (chunks, next_offset, front_offset) = self.read_since_with_offsets(build_id, offset);
        (
            chunks.into_iter().map(|(_, data)| data).collect(),
            next_offset,
            front_offset,
        )
    }

    /// [`Self::read_since`] 的变体：每 chunk 附带真实起始偏移——从读者 start
    /// 累加派生会在拒收窗口（推进 offset 但不留 chunk）处低估洞长，SSE 事件
    /// id 漂移重投。切片形态（offset 在 chunk 中间）真实起始 = 读者 offset。
    /// 其余字段同 [`Self::read_since`]。
    pub fn read_since_with_offsets(
        &self,
        build_id: i64,
        offset: usize,
    ) -> (Vec<(usize, Bytes)>, usize, usize) {
        let buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = buffers.get(&build_id) else {
            return (Vec::new(), 0, 0);
        };
        let new_offset = entry.next_offset;
        let front_offset = entry.chunks.front().map(|c| c.offset).unwrap_or(new_offset);
        // 队头二分跳过：chunks 按 offset 升序且各 chunk 末尾单调不减（拒收
        // 空洞下 end_i <= start_{i+1} < end_{i+1}），谓词 `end <= offset` 单调；
        // skip 后首 chunk 必有 `end > offset`，切片形态（offset 在 chunk 中间）
        // 不会被误跳。
        let skip = entry
            .chunks
            .partition_point(|c| c.offset + c.data.len() <= offset);
        let chunks = entry
            .chunks
            .iter()
            .skip(skip)
            .map(|chunk| {
                if chunk.offset >= offset {
                    return (chunk.offset, chunk.data.clone());
                }
                // 切片真实起始 = 读者 offset（chunk.offset 低估已消费前缀）。
                let start = offset - chunk.offset;
                (offset, chunk.data.slice(start..))
            })
            .collect();
        (chunks, new_offset, front_offset)
    }

    /// 读取指定 build_id 的日志（从 0 起）；单客户端回退用，多客户端走 `read_since`。
    pub fn read(&self, build_id: i64) -> Vec<Bytes> {
        self.read_since(build_id, 0).0
    }

    /// 为 build_id 注册空缓冲条目：首条日志到达前 `has()` 即 true，SSE / CLI
    /// 实时流提前挂接 buffer 路径；即 base=0 的 [`Self::register_with_base`]。
    pub fn register(&self, build_id: i64) {
        self.register_with_base(build_id, 0);
    }

    /// [`Self::register`] 的带基偏移变体：hub 重启丢内存 LogBuffer 而磁盘
    /// build.log 续写在旧字节数后，新条目若从 0 起编号则 buffer offset 与文件
    /// 偏移永久错位（补尾 / 补洞 / SSE id 全读错）。report_logs 在 `!has()` 且
    /// build.log 已存在时以文件长度作 `base` 重播种，否则走 `register`。
    /// 已存在条目 no-op（后到 base 忽略），墓碑不复活。并发播种窗口依赖
    /// 单上报者假设（同一 build 由单 worker LogBatcher 串行上报）。
    pub fn register_with_base(&self, build_id: i64, base: u64) {
        {
            let mut buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
            if buffers.get(&build_id).is_some_and(|entry| entry.terminal) {
                return;
            }
            buffers.entry(build_id).or_insert_with(|| LogBufferEntry {
                next_offset: base as usize,
                ..LogBufferEntry::default()
            });
        }
        self.notify_change(build_id);
    }

    /// 释放指定 build 的缓冲并标记终态。保留墓碑而非直接删除：迟到 chunk /
    /// 注册（HTTP 重试乱序）不得复活回 buffer 路径，`has` 为 false 使读取端
    /// 回落落盘日志；`next_offset` 保留，已挂接 drain/SSE 的 offset 保持单调。
    /// 每次调用先清扫上一轮墓碑再标记本轮（免后台任务，map 以活跃构建 + 1
    /// 个墓碑为界）。清扫排除目标自身：重复 evict（响应丢失重试）若把自身
    /// 墓碑当上一轮清掉、`get_mut` 落空，迟到 chunk 会经 `or_default` 以
    /// `next_offset=0` 复活（≤10MB 滞留到重启）。
    pub fn evict(&self, build_id: i64) {
        {
            let mut buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
            // 旧墓碑 current_size 已归零，retain 清扫无需逐个 fetch_sub。
            buffers.retain(|k, entry| !entry.terminal || *k == build_id);
            if let Some(entry) = buffers.get_mut(&build_id) {
                // 记账回落按 current_size 递减（重复 evict 减 0 无害）。
                self.total_bytes
                    .fetch_sub(entry.current_size as u64, Ordering::Relaxed);
                entry.terminal = true;
                entry.chunks.clear();
                entry.current_size = 0;
            }
        }
        // 驱逐即广播，随后移除句柄。顺序刻意先广播后移除：若先移除，并发
        // wait_change 会经 notifier 新建句柄挂上，错过终态广播且句柄残留；
        // 先广播的唯一错过窗口是"广播后才注册"，由调用方兜底轮询兜住。
        let notify = self
            .notifies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&build_id)
            .cloned();
        if let Some(notify) = notify {
            notify.notify_waiters();
        }
        self.notifies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&build_id);
    }

    /// 取（或按需创建）build 的变更通知句柄。
    fn notifier(&self, build_id: i64) -> Arc<Notify> {
        self.notifies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(build_id)
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    /// 缓冲变更（register/append/evict）后唤醒该 build 的所有等待方；只在
    /// 数据锁释放后调用（两锁互不嵌套），`notify_waiters` 无 await。
    fn notify_change(&self, build_id: i64) {
        let notify = self
            .notifies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&build_id)
            .cloned();
        if let Some(notify) = notify {
            notify.notify_waiters();
        }
    }

    /// 等待该 build 的下一次缓冲变更。语义同 `Notify::notify_waiters`：不记
    /// permit、只唤醒已挂起方，读与等待之间到达的变更由调用方兜底轮询补上
    ///（错过只多一个兜底间隔的延迟）。
    pub async fn wait_change(&self, build_id: i64) {
        self.notifier(build_id).notified().await;
    }

    /// 检查是否还有该 build_id 的缓冲数据（终态墓碑视为无）。
    pub fn has(&self, build_id: i64) -> bool {
        let buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
        buffers.get(&build_id).is_some_and(|entry| !entry.terminal)
    }

    /// 返回指定 build_id 当前日志流的总字节数（下一条 chunk 的起始偏移）。
    pub fn total_size(&self, build_id: i64) -> Option<usize> {
        let buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
        buffers.get(&build_id).map(|entry| entry.next_offset)
    }

    /// 当前被追踪的 build_id 快照（活跃 + 墓碑）；供后台回收遍历强制驱逐
    /// 滞留墓碑（scheduler.rs），只读。
    pub(crate) fn tracked_build_ids(&self) -> Vec<i64> {
        self.buffers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect()
    }

    /// 测试辅助：notifies map 的 build_id 快照（验证 evict 连带清理句柄）。
    #[cfg(test)]
    pub(crate) fn notify_tracked_ids(&self) -> Vec<i64> {
        self.notifies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect()
    }

    fn entry_size(entry: &LogBufferEntry) -> usize {
        entry.current_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 机制门：register/append/evict 均唤醒 `wait_change` 等待方。
    #[tokio::test]
    async fn log_buffer_wait_change_wakes_on_register_append_evict() {
        let buf = Arc::new(LogBuffer::new());

        // 先挂起等待方（notify_waiters 只唤醒已注册者），写入方延迟落笔保证注册先行。
        let writer = buf.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            writer.register(1);
            writer.append(1, Bytes::from("x"));
        });
        let woke =
            tokio::time::timeout(std::time::Duration::from_secs(2), buf.wait_change(1)).await;
        assert!(
            woke.is_ok(),
            "register/append must wake wait_change within 2s"
        );

        let evictor = buf.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            evictor.evict(1);
        });
        let woke =
            tokio::time::timeout(std::time::Duration::from_secs(2), buf.wait_change(1)).await;
        assert!(woke.is_ok(), "evict must wake wait_change within 2s");
    }

    #[test]
    fn log_buffer_register_creates_empty_entry() {
        let buf = LogBuffer::new();
        assert!(!buf.has(1));
        buf.register(1);
        assert!(buf.has(1));
        assert_eq!(buf.total_size(1), Some(0));
        assert!(buf.read(1).is_empty());
        buf.append(1, Bytes::from("x"));
        assert_eq!(buf.total_size(1), Some(1));
    }

    /// register_with_base：新建条目从 base 起编号（hub 重启续写场景）；已有
    /// 条目 no-op；墓碑不复活。
    #[test]
    fn log_buffer_register_with_base_seeds_offset_and_is_noop_on_existing() {
        let buf = LogBuffer::new();
        buf.register_with_base(1, 1234);
        assert!(buf.has(1));
        assert_eq!(buf.total_size(1), Some(1234), "new entry starts at base");
        assert!(buf.read(1).is_empty(), "base is offset only, no chunk data");

        buf.register_with_base(1, 999);
        assert_eq!(
            buf.total_size(1),
            Some(1234),
            "existing entry must not be reseeded"
        );

        buf.evict(1);
        buf.register_with_base(1, 7777);
        assert!(!buf.has(1), "tombstone must not be resurrected");
        assert_eq!(
            buf.total_size(1),
            Some(1234),
            "tombstone keeps its next_offset"
        );
    }

    /// base 播种后 next_offset = base + len，读取偏移含 base，与落盘文件位置
    /// 对齐（重启续写场景的消费端不变量）。
    #[test]
    fn log_buffer_register_with_base_appends_numbered_from_base() {
        let buf = LogBuffer::new();
        buf.register_with_base(1, 100);
        assert!(buf.append(1, Bytes::from("abc")));
        assert!(buf.append(1, Bytes::from("defg")));
        assert_eq!(
            buf.total_size(1),
            Some(100 + 7),
            "next_offset = base + appended len"
        );

        let (chunks, next, front) = buf.read_since_with_offsets(1, 0);
        assert_eq!(
            chunks,
            vec![(100, Bytes::from("abc")), (103, Bytes::from("defg"))],
            "real chunk offsets must include the base"
        );
        assert_eq!(next, 107);
        assert_eq!(front, 100);

        let (chunks, next, _) = buf.read_since(1, 103);
        assert_eq!(chunks, vec![Bytes::from("defg")]);
        assert_eq!(next, 107);
    }

    #[test]
    fn log_buffer_append_and_read() {
        let buf = LogBuffer::new();
        buf.append(1, Bytes::from("hello "));
        buf.append(1, Bytes::from("world"));
        let data = buf.read(1);
        let combined: Vec<u8> = data.iter().flat_map(|b| b.iter().cloned()).collect();
        assert_eq!(String::from_utf8(combined).unwrap(), "hello world");
    }

    #[test]
    fn log_buffer_read_since_returns_incremental_data() {
        let buf = LogBuffer::new();
        buf.append(1, Bytes::from("hello "));
        let (chunks, offset, _) = buf.read_since(1, 0);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], Bytes::from("hello "));
        assert_eq!(offset, 6);

        buf.append(1, Bytes::from("world"));
        let (chunks, offset, _) = buf.read_since(1, 6);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], Bytes::from("world"));
        assert_eq!(offset, 11);

        let (chunks, offset, _) = buf.read_since(1, 11);
        assert!(chunks.is_empty());
        assert_eq!(offset, 11);
    }

    #[test]
    fn log_buffer_read_since_offset_inside_chunk() {
        let buf = LogBuffer::new();
        buf.append(1, Bytes::from("hello world"));
        let (chunks, offset, _) = buf.read_since(1, 6);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], Bytes::from("world"));
        assert_eq!(offset, 11);
    }

    #[test]
    fn log_buffer_multiple_readers_independent() {
        let buf = LogBuffer::new();
        buf.append(1, Bytes::from("abc"));

        let reader_a = buf.read_since(1, 0);
        let reader_b = buf.read_since(1, 0);
        assert_eq!(reader_a.0.len(), 1);
        assert_eq!(reader_b.0.len(), 1);
        assert_eq!(reader_a.1, 3);
        assert_eq!(reader_b.1, 3);

        buf.append(1, Bytes::from("def"));
        let (chunks_a, _, _) = buf.read_since(1, reader_a.1);
        let (chunks_b, _, _) = buf.read_since(1, reader_b.1);
        assert_eq!(chunks_a[0], Bytes::from("def"));
        assert_eq!(chunks_b[0], Bytes::from("def"));
    }

    #[test]
    fn log_buffer_read_since_after_eviction_does_not_reset() {
        // 11 条满 1MB chunk 累计超 10MB 触发 FIFO，验证 offset 单调不回拨。
        let buf = LogBuffer::new();
        for _ in 0..11 {
            assert!(buf.append(1, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES])));
        }
        let (_, first_offset, _) = buf.read_since(1, 0);
        assert!(first_offset > MAX_LOG_BUFFER_PER_BUILD);

        let (chunks, second_offset, _) = buf.read_since(1, first_offset);
        assert!(chunks.is_empty());
        assert_eq!(second_offset, first_offset);

        assert!(buf.append(1, Bytes::from("tail")));
        let (chunks, third_offset, _) = buf.read_since(1, second_offset);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], Bytes::from("tail"));
        assert!(third_offset > second_offset);
    }

    /// front_offset 语义：offset < front 即 FIFO 已淘汰区（SSE 据此补读空洞）；
    /// 缓冲空 / 墓碑时 front == next（无空洞可补）。
    #[test]
    fn log_buffer_read_since_reports_front_offset_after_eviction() {
        let buf = LogBuffer::new();
        buf.append(1, Bytes::from("hello "));
        let (chunks, next, front) = buf.read_since(1, 0);
        assert_eq!(chunks.len(), 1);
        assert_eq!(next, 6);
        assert_eq!(front, 0, "no eviction yet: front is the first chunk offset");

        // FIFO 淘汰后 front 前跳过淘汰区，且严格小于 next（仍有存活内容）。
        for _ in 0..11 {
            assert!(buf.append(1, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES])));
        }
        let (_, next, front) = buf.read_since(1, 0);
        assert!(front > 0, "front must advance past the evicted prefix");
        assert!(front < next, "front must stay behind the live chunks");

        // 终态驱逐清空 chunks（墓碑保留 next_offset）。
        buf.evict(1);
        let (chunks, next, front) = buf.read_since(1, 0);
        assert!(chunks.is_empty());
        assert_eq!(front, next, "empty buffer has no hole to backfill");
    }

    #[test]
    fn log_buffer_fifo_eviction() {
        let buf = LogBuffer::new();
        for _ in 0..11 {
            assert!(buf.append(1, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES])));
        }
        let data = buf.read(1);
        let total: usize = data.iter().map(|b| b.len()).sum();
        assert!(
            total <= MAX_LOG_BUFFER_PER_BUILD,
            "multi-chunk overflow must be trimmed to the limit"
        );
    }

    /// 淘汰到剩最后一条即止（`len() > 1` 保证最新一条始终可读）；单条上限
    /// 拒收后用多条满尺寸 chunk 构造等价超限形态钉住该不变量。
    #[test]
    fn log_buffer_single_oversized_chunk_keeps_latest_readable() {
        let buf = LogBuffer::new();
        for _ in 0..11 {
            assert!(buf.append(1, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES])));
        }
        let (chunks, offset, _) = buf.read_since(1, 0);
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(
            total, MAX_LOG_BUFFER_PER_BUILD,
            "the latest chunks must stay readable, trimmed to the limit"
        );
        assert_eq!(offset, 11 * MAX_LOG_CHUNK_BYTES);

        // 后续追加照常淘汰最旧（len() > 1 成立），旧末尾续读只有新 chunk。
        assert!(buf.append(1, Bytes::from("tail")));
        let (chunks, _, _) = buf.read_since(1, 11 * MAX_LOG_CHUNK_BYTES);
        let joined: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(joined, b"tail".to_vec());
    }

    /// 单条超限入口拒收：不 push、不推进 offset，后续 offset 连续无空洞。
    #[test]
    fn append_rejects_oversized_single_chunk() {
        let buf = LogBuffer::new();
        buf.register(1);
        assert!(buf.append(1, Bytes::from("ok")));
        assert_eq!(buf.total_size(1), Some(2));

        assert!(!buf.append(1, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES + 1])));
        assert_eq!(
            buf.total_size(1),
            Some(2),
            "rejected chunk must not advance offset"
        );
        assert_eq!(buf.read(1).len(), 1);

        // 后续 chunk offset 连续，读到完整 "oktail" 无空洞。
        assert!(buf.append(1, Bytes::from("tail")));
        let (chunks, offset, _) = buf.read_since(1, 0);
        let joined: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(joined, b"oktail".to_vec());
        assert_eq!(offset, 6);
    }

    /// 全局总字节上界：多 build 累计触顶拒收新 append，但 next_offset 仍推进
    ///（对齐落盘文件位置，理由见 append doc）；per-build 10MB 语义不受影响。
    /// 拒收经 clone 副本发起，钉住全局记账随 Clone 共享。
    #[test]
    fn log_buffer_global_total_cap_rejects_new_append() {
        let buf = LogBuffer::new();
        for _ in 0..11 {
            assert!(buf.append(1, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES])));
        }
        let data = buf.read(1);
        let total: usize = data.iter().map(|c| c.len()).sum();
        assert_eq!(
            total, MAX_LOG_BUFFER_PER_BUILD,
            "per-build 10MB semantics must be unaffected by the global cap"
        );

        // 10MB + 2×1MB = 12MB = 测试全局上限（边界值放行）。
        let clone = buf.clone();
        assert!(clone.append(2, Bytes::from(vec![b'y'; MAX_LOG_CHUNK_BYTES])));
        assert!(clone.append(2, Bytes::from(vec![b'y'; MAX_LOG_CHUNK_BYTES])));
        // 顶满后经原副本拒收：不入缓冲，但 next_offset 推进过被拒窗口。
        assert!(!buf.append(2, Bytes::from("z")));
        assert_eq!(
            buf.total_size(2),
            Some(2 * MAX_LOG_CHUNK_BYTES + 1),
            "rejected append must still advance next_offset past the skipped window"
        );
        let (chunks, next, _) = clone.read_since(2, 2 * MAX_LOG_CHUNK_BYTES);
        assert!(chunks.is_empty(), "rejected chunk must not be readable");
        assert_eq!(next, 2 * MAX_LOG_CHUNK_BYTES + 1);

        // 回落后再收的 chunk 从推进后 offset 连续编号，续读无重复字节。
        buf.evict(1);
        assert!(buf.append(2, Bytes::from("tail")));
        let (chunks, next, _) = buf.read_since(2, 2 * MAX_LOG_CHUNK_BYTES + 1);
        let joined: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(joined, b"tail".to_vec());
        assert_eq!(next, 2 * MAX_LOG_CHUNK_BYTES + 5);
    }

    /// 拒收窗口的洞语义：无存活 chunk 的 build `front == next` 且严格大于
    /// 读者 start，读取端以 `start < front` 判洞、从磁盘补读 [start, front)
    ///（被拒 chunk 已落盘，可补回）。
    #[test]
    fn log_buffer_global_cap_rejected_window_is_backfillable_hole() {
        let buf = LogBuffer::new();
        for _ in 0..11 {
            assert!(buf.append(1, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES])));
        }
        assert!(buf.append(2, Bytes::from(vec![b'y'; MAX_LOG_CHUNK_BYTES])));
        assert!(buf.append(2, Bytes::from(vec![b'y'; MAX_LOG_CHUNK_BYTES])));
        // 12MB 触顶：build 3 首条 chunk 即被拒收。
        buf.register(3);
        assert!(!buf.append(3, Bytes::from(vec![b'z'; 4096])));
        let (chunks, next, front) = buf.read_since(3, 0);
        assert!(chunks.is_empty(), "rejected chunk must not be readable");
        assert_eq!(
            next, 4096,
            "rejected first chunk still advances next_offset"
        );
        assert_eq!(front, next, "no live chunks: front collapses onto next");
        assert!(
            front > 0,
            "reader start(0) < front: hole branch backfills [start, front) from disk"
        );
    }

    /// with_offsets 返回真实起始偏移：拒收窗口之后的 chunk 偏移含洞长（SSE
    /// id 派生不低估洞长）；切片形态真实起始 = 读者 offset。read_since 委托
    /// 同一实现，仅丢弃偏移。
    #[test]
    fn log_buffer_read_since_with_offsets_reports_real_chunk_offsets() {
        let buf = LogBuffer::new();
        buf.append(1, Bytes::from("hello "));
        buf.append(1, Bytes::from("world"));
        let (chunks, next, front) = buf.read_since_with_offsets(1, 0);
        assert_eq!(
            chunks,
            vec![(0, Bytes::from("hello ")), (6, Bytes::from("world"))]
        );
        assert_eq!(next, 11);
        assert_eq!(front, 0);

        // 切片真实起始 = 读者 offset（8），不是 chunk 起点（6）。
        let (chunks, _, _) = buf.read_since_with_offsets(1, 8);
        assert_eq!(chunks, vec![(8, Bytes::from("rld"))]);
        let (data, next, _) = buf.read_since(1, 8);
        assert_eq!(data, vec![Bytes::from("rld")]);
        assert_eq!(next, 11);
        buf.evict(1);

        // 触顶后 build 4 首条 chunk 被拒（next_offset 仍推进 4096），回落后
        // 再收的 chunk 从 4096 起编——须报告含洞长的真实偏移，而非从 start
        // 重算的 0。
        for _ in 0..11 {
            assert!(buf.append(2, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES])));
        }
        assert!(buf.append(3, Bytes::from(vec![b'y'; MAX_LOG_CHUNK_BYTES])));
        assert!(buf.append(3, Bytes::from(vec![b'y'; MAX_LOG_CHUNK_BYTES])));
        buf.register(4);
        assert!(!buf.append(4, Bytes::from(vec![b'z'; 4096])));
        buf.evict(2);
        assert!(buf.append(4, Bytes::from("tail")));
        let (chunks, next, front) = buf.read_since_with_offsets(4, 0);
        assert_eq!(
            chunks,
            vec![(4096, Bytes::from("tail"))],
            "real offset must include the rejected-window length"
        );
        assert_eq!(next, 4096 + 4);
        assert_eq!(front, 4096);
        let (data, next, front) = buf.read_since(4, 0);
        assert_eq!(data, vec![Bytes::from("tail")]);
        assert_eq!(next, 4096 + 4);
        assert_eq!(front, 4096);
    }

    /// evict 释放全局记账（清空 current_size 并递减总账），计数回落可再收。
    #[test]
    fn log_buffer_global_total_cap_recovers_after_evict() {
        let buf = LogBuffer::new();
        for _ in 0..11 {
            assert!(buf.append(1, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES])));
        }
        assert!(buf.append(2, Bytes::from(vec![b'y'; MAX_LOG_CHUNK_BYTES])));
        assert!(buf.append(2, Bytes::from(vec![b'y'; MAX_LOG_CHUNK_BYTES])));
        // 12MB 触顶拒收（next_offset 仍推进 1 字节）。
        assert!(!buf.append(2, Bytes::from("z")));
        // 驱逐 build 1 释放 10MB 记账后可再收；新 chunk 从推进后 offset 起编。
        buf.evict(1);
        assert!(buf.append(2, Bytes::from("z")));
        assert_eq!(buf.total_size(2), Some(2 * MAX_LOG_CHUNK_BYTES + 2));
    }

    #[test]
    fn log_buffer_evict_releases_entry_and_blocks_resurrection() {
        let buf = LogBuffer::new();
        buf.register(1);
        buf.append(1, Bytes::from("hello"));
        assert!(buf.has(1));

        buf.evict(1);
        assert!(!buf.has(1));
        // 已挂接读取端 offset 保持单调（drain 循环依赖）。
        let (chunks, offset, _) = buf.read_since(1, 5);
        assert!(chunks.is_empty());
        assert_eq!(offset, 5);

        buf.append(1, Bytes::from("late"));
        buf.register(1);
        assert!(!buf.has(1));
        let (chunks, _, _) = buf.read_since(1, 0);
        assert!(chunks.is_empty());
    }

    #[test]
    fn log_buffer_evict_keeps_other_builds() {
        let buf = LogBuffer::new();
        buf.append(1, Bytes::from("a"));
        buf.append(2, Bytes::from("b"));
        buf.evict(1);
        assert!(!buf.has(1));
        assert!(buf.has(2));
        assert_eq!(buf.total_size(2), Some(1));
        let (chunks, _, _) = buf.read_since(2, 0);
        assert_eq!(chunks.len(), 1);
    }

    #[test]
    fn log_buffer_evict_twice_keeps_tombstone_against_late_chunks() {
        // 重复 evict（响应丢失重试）不得把自身墓碑当上一轮清掉——否则迟到
        // chunk 经 or_default 以 next_offset=0 复活（≤10MB 滞留到重启）。
        let buf = LogBuffer::new();
        buf.register(1);
        buf.append(1, Bytes::from("hello"));
        buf.evict(1);
        buf.evict(1);
        buf.append(1, Bytes::from("late"));
        buf.register(1);
        assert!(!buf.has(1));
        // 墓碑保留 next_offset=5（复活路径会归零重新计数）。
        assert_eq!(buf.total_size(1), Some(5));
        let (chunks, offset, _) = buf.read_since(1, 0);
        assert!(chunks.is_empty());
        assert_eq!(offset, 5);
    }

    #[test]
    fn log_buffer_evict_sweeps_stale_tombstones() {
        let buf = LogBuffer::new();
        buf.append(1, Bytes::from("a"));
        buf.append(2, Bytes::from("b"));
        buf.evict(1);
        {
            let buffers = buf.buffers.lock().unwrap();
            assert_eq!(buffers.len(), 2);
            assert!(buffers.contains_key(&1));
        }
        buf.evict(2);
        {
            let buffers = buf.buffers.lock().unwrap();
            assert_eq!(buffers.len(), 1);
            assert!(buffers.contains_key(&2));
        }
        // 目标条目不存在时同样顺带清扫（2 被清掉）。
        buf.evict(99);
        {
            let buffers = buf.buffers.lock().unwrap();
            assert!(buffers.is_empty());
        }
    }

    #[test]
    fn log_buffer_evict_concurrent_with_append_no_panic() {
        let buf = LogBuffer::new();
        buf.register(2);
        std::thread::scope(|s| {
            for _ in 0..4 {
                let b = buf.clone();
                s.spawn(move || {
                    for _ in 0..1000 {
                        b.append(1, Bytes::from(vec![b'x'; 64]));
                        b.append(2, Bytes::from(vec![b'y'; 64]));
                        let _ = b.read_since(1, 0);
                        let _ = b.read_since(2, 0);
                    }
                });
            }
            for _ in 0..1000 {
                buf.evict(1);
            }
        });
        // 未 panic 即通过（并发最后一笔写可能是 append，真实系统 worker 先
        // 停流再 report 无此竞争）；join 后补确定性驱逐再断言。
        buf.evict(1);
        assert!(!buf.has(1));
        assert!(buf.has(2));
    }
}
