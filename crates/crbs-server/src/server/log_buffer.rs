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
//!
//! FIFO 淘汰命中的时间线标记行先固定存（单 build 上限 1MiB），供 phase
//! 时间线扫描经 [`LogBuffer::read_timeline_text`] 读取；固定存不进字节流，
//! `read` / 偏移 / `total_size` 语义不变。

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::Notify;

const MAX_LOG_BUFFER_PER_BUILD: usize = 10 * 1024 * 1024;

const TIMELINE_LINE_PREFIXES: [&str; 4] = [
    "# CRBS_PHASE_",
    "# CRBS_SUBPHASE ",
    "Executing(%",
    "error: Bad exit status from ",
];

/// 字节行是否命中任一时间线标记前缀。最长前缀字节数：残头达到该长度即可确定是否标记行，无需再拼窗口补全。
pub(crate) fn is_timeline_marker_line(line: &[u8]) -> bool {
    TIMELINE_LINE_PREFIXES
        .iter()
        .any(|prefix| line.starts_with(prefix.as_bytes()))
}

const MAX_TIMELINE_PREFIX_BYTES: usize = {
    let mut max = 0;
    let mut i = 0;
    while i < TIMELINE_LINE_PREFIXES.len() {
        let len = TIMELINE_LINE_PREFIXES[i].len();
        if len > max {
            max = len;
        }
        i += 1;
    }
    max
};

const MAX_PINNED_BYTES_PER_BUILD: usize = 1024 * 1024;

const fn max_log_buffer_total_bytes() -> usize {
    if cfg!(test) {
        12 * 1024 * 1024
    } else {
        1024 * 1024 * 1024
    }
}

/// 单条日志 chunk 的尺寸上限（1MB），防止失控或恶意 worker 造成内存放大。
/// 超限在入口拒收：状态不变、不推进 `next_offset`，后续 chunk 偏移保持
/// 连续（读取端无空洞）；report_logs 另有同上限的 400 预检让 worker 及早
/// 感知。
pub(crate) const MAX_LOG_CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
struct LogChunk {
    offset: usize,
    data: Bytes,
}

#[derive(Debug, Default, Clone)]
struct LogBufferEntry {
    chunks: VecDeque<LogChunk>,

    next_offset: usize,
    current_size: usize,

    terminal: bool,

    pinned: Vec<u8>,

    pending_head: Vec<u8>,

    pinned_overflow: bool,
}

#[derive(Debug, Default, Clone)]
/// 全局日志缓冲。按 build_id 分桶的内存缓冲，FIFO 淘汰；上限三层：单条 chunk 1MB（超限入口拒收）、单 build 10MB、全局总量 1GiB（超限拒收新 chunk，
/// 实时 tail 降级，磁盘日志不受影响）。锁全部 unwrap_or_else(into_inner) 恢复 poison——只存构建期临时 chunk，poison 后继续比 panic
/// 安全。
pub struct LogBuffer {
    buffers: Arc<Mutex<HashMap<i64, LogBufferEntry>>>,

    notifies: Arc<Mutex<HashMap<i64, Arc<Notify>>>>,

    total_bytes: Arc<AtomicU64>,

    total_cap_warned: Arc<AtomicBool>,
}

impl LogBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// 追加日志 chunk，返回 `false` 表示拒收，两种拒收形态语义不同：
    ///
    /// - 终态墓碑或单条超 [`MAX_LOG_CHUNK_BYTES`]：状态完全不变，不推进
    ///   `next_offset`，后续 chunk 偏移保持连续（调用方对应 409 / 400）。
    /// - 全局总字节达上限（[`max_log_buffer_total_bytes`]）：chunk 不入缓冲，
    ///   但 `next_offset` 仍推进被拒窗口的长度。理由：report_logs 无视拒收
    ///   照常落盘，若不推进，缓冲偏移会永久落后于文件位置，终态补尾时重复
    ///   重放；被拒窗口表现为 `front_offset` 语义下的空洞——无更旧存活
    ///   chunk 的读者以 `start < front_offset` 判洞并从磁盘补回，仍持有
    ///   更旧 chunk 的读者在途实时流静默跳过该窗口（触顶下的 tail 降级）。
    ///   evict 或 FIFO 淘汰释放容量后可再次接收。
    ///
    /// 单 build 超出 10MB 上限时按 FIFO 丢弃最旧 chunk，最新一条始终保留。
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

                entry.next_offset += len;
                accepted = false;
            } else {
                let offset = entry.next_offset;
                entry.chunks.push_back(LogChunk { offset, data });
                entry.next_offset += len;
                entry.current_size += len;
                self.total_bytes.fetch_add(len as u64, Ordering::Relaxed);

                let mut popped: Vec<u8> = Vec::new();
                while Self::entry_size(entry) > MAX_LOG_BUFFER_PER_BUILD && entry.chunks.len() > 1 {
                    if let Some(front) = entry.chunks.pop_front() {
                        entry.current_size -= front.data.len();
                        self.total_bytes
                            .fetch_sub(front.data.len() as u64, Ordering::Relaxed);
                        popped.extend_from_slice(&front.data);
                    }
                }
                Self::pin_evicted_markers(entry, &popped);
                accepted = true;
            }
        }

        self.notify_change(build_id);
        accepted
    }

    /// 读取指定 build 自 `offset` 起的日志 chunk，返回 `(chunks, next_offset,
    /// front_offset)`，三者取自同一把锁的原子快照：`next_offset` 单调递增，
    /// 供下次调用作 `offset`；`front_offset` 为最旧存活 chunk 的起点（缓冲
    /// 空、墓碑时等于 `next_offset`），更小偏移已被 FIFO 淘汰，读取端据此
    /// 判洞并从磁盘补读。不提供单独的 front_offset 访问器：分两次取锁会使
    /// 洞检测失真（TOCTOU）。多个读取者的 offset 互不干扰。
    pub fn read_since(&self, build_id: i64, offset: usize) -> (Vec<Bytes>, usize, usize) {
        let (chunks, next_offset, front_offset) = self.read_since_with_offsets(build_id, offset);
        (
            chunks.into_iter().map(|(_, data)| data).collect(),
            next_offset,
            front_offset,
        )
    }

    /// [`Self::read_since`] 的变体：每个 chunk 附带真实起始偏移。从读者
    /// start 累加推导会在拒收窗口（偏移已推进但不保留 chunk）处低估洞长，
    /// 导致 SSE 事件 id 漂移、事件重投；切片形态（offset 落在 chunk 中间）
    /// 的真实起始即读者 offset。返回值其余字段同 [`Self::read_since`]。
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

                let start = offset - chunk.offset;
                (offset, chunk.data.slice(start..))
            })
            .collect();
        (chunks, new_offset, front_offset)
    }

    /// 读取指定 build 的全部缓冲日志（从偏移 0 起）；供单客户端回退读取，
    /// 多客户端增量场景走 [`Self::read_since`]。
    pub fn read(&self, build_id: i64) -> Vec<Bytes> {
        self.read_since(build_id, 0).0
    }

    /// 为 build 注册空缓冲条目：首条日志到达前 `has()` 即返回 true，SSE 与
    /// CLI 实时流得以提前挂接缓冲路径。等价于 base 为 0 的
    /// [`Self::register_with_base`]。
    pub fn register(&self, build_id: i64) {
        self.register_with_base(build_id, 0);
    }

    /// [`Self::register`] 的带基偏移变体：hub 重启后内存缓冲丢失而磁盘
    /// build.log 按原字节数续写，新条目若从 0 起编号会使缓冲偏移与文件偏移
    /// 永久错位（补尾、补洞、SSE 事件 id 全部读错）；调用方在 `!has()` 且
    /// build.log 已存在时以文件长度作 `base` 播种，否则走
    /// [`Self::register`]。已存在条目为 no-op（后到的 base 被忽略），墓碑
    /// 不复活。并发播种的正确性依赖单上报者假设：同一 build 的日志由单个
    /// worker 串行上报。
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

    /// 释放指定 build 的缓冲并标记终态，保留墓碑而非直接删除：迟到 chunk
    /// 与注册（HTTP 重试乱序）不得复活回缓冲路径，`has` 变为 false 使读取
    /// 端转读磁盘日志；`next_offset` 保留，已挂接的 drain / SSE 偏移保持
    /// 单调。墓碑不携带数据：chunks 与固定存的标记行一并释放。每次调用先
    /// 清扫上一轮墓碑再标记本轮（免后台任务，条目数以活跃构建加一个墓碑为
    /// 界）；清扫排除目标自身——重复 evict（响应丢失重试）若把自身墓碑当作
    /// 上一轮清掉，`get_mut` 落空，迟到 chunk 会经 `or_default` 以
    /// `next_offset=0` 复活（至多 10MB 滞留到重启）。
    pub fn evict(&self, build_id: i64) {
        {
            let mut buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());

            buffers.retain(|k, entry| !entry.terminal || *k == build_id);
            if let Some(entry) = buffers.get_mut(&build_id) {
                self.total_bytes
                    .fetch_sub(entry.current_size as u64, Ordering::Relaxed);
                entry.terminal = true;
                entry.chunks.clear();
                entry.current_size = 0;
                entry.pinned.clear();
                entry.pending_head.clear();
                entry.pinned_overflow = false;
            }
        }

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

    fn notifier(&self, build_id: i64) -> Arc<Notify> {
        self.notifies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(build_id)
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

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

    /// 等待指定 build 的下一次缓冲变更。语义同 `Notify::notify_waiters`：
    /// 不记 permit、只唤醒已挂起的等待方，读取与进入等待之间到达的变更由
    /// 调用方兜底轮询补上（错过只增加一个轮询间隔的延迟）。
    pub async fn wait_change(&self, build_id: i64) {
        self.notifier(build_id).notified().await;
    }

    /// 检查指定 build 是否仍有缓冲数据（终态墓碑视为无）。
    pub fn has(&self, build_id: i64) -> bool {
        let buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
        buffers.get(&build_id).is_some_and(|entry| !entry.terminal)
    }

    /// 判断指定 build 是否无活跃条目（不存在或已被 `evict` 标记为终态）；
    /// 回收循环据此跳过该 build，避免每轮重复查库与告警。
    pub(crate) fn is_tombstone(&self, build_id: i64) -> bool {
        let buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
        match buffers.get(&build_id) {
            None => true,
            Some(entry) => entry.terminal && entry.current_size == 0,
        }
    }

    /// 返回固定存标记行、未成行残头与存活窗口拼接的连续视图，仅供 phase
    /// 时间线扫描消费；字节流、偏移与 `total_size` 语义均不含该视图内容。
    pub(crate) fn read_timeline_text(&self, build_id: i64) -> Vec<u8> {
        let buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = buffers.get(&build_id) else {
            return Vec::new();
        };
        let mut out =
            Vec::with_capacity(entry.pinned.len() + entry.pending_head.len() + entry.current_size);
        out.extend_from_slice(&entry.pinned);
        out.extend_from_slice(&entry.pending_head);
        for chunk in &entry.chunks {
            out.extend_from_slice(&chunk.data);
        }
        out
    }

    fn pin_evicted_markers(entry: &mut LogBufferEntry, popped: &[u8]) {
        let mut joined = std::mem::take(&mut entry.pending_head);
        joined.extend_from_slice(popped);
        match joined.iter().rposition(|&b| b == b'\n') {
            Some(pos) => {
                Self::pin_matching_lines(entry, &joined[..=pos]);
                entry.pending_head = joined.split_off(pos + 1);
            }
            None => entry.pending_head = joined,
        }
        if entry.pending_head.is_empty() {
            return;
        }

        if entry.pending_head.len() > MAX_PINNED_BYTES_PER_BUILD
            || (entry.pending_head.len() >= MAX_TIMELINE_PREFIX_BYTES
                && !is_timeline_marker_line(&entry.pending_head))
        {
            entry.pending_head.clear();
            return;
        }
        Self::try_pin_pending_from_window(entry);
    }

    fn pin_matching_lines(entry: &mut LogBufferEntry, complete: &[u8]) {
        let mut start = 0;
        while let Some(nl) = complete[start..].iter().position(|&b| b == b'\n') {
            let end = start + nl + 1;
            let line = &complete[start..end];
            if is_timeline_marker_line(line) {
                Self::pin_line(entry, line);
            }
            start = end;
        }
    }

    fn try_pin_pending_from_window(entry: &mut LogBufferEntry) {
        let mut nl_pos = None;
        let mut scanned = 0usize;
        for chunk in &entry.chunks {
            if let Some(rel) = chunk.data.iter().position(|&b| b == b'\n') {
                nl_pos = Some(scanned + rel);
                break;
            }
            scanned += chunk.data.len();
        }
        let Some(end) = nl_pos else {
            return;
        };
        let mut line = std::mem::take(&mut entry.pending_head);
        line.reserve((end + 1).saturating_sub(line.len()));
        let mut remaining = end + 1;
        for chunk in &entry.chunks {
            if remaining == 0 {
                break;
            }
            let take = remaining.min(chunk.data.len());
            line.extend_from_slice(&chunk.data[..take]);
            remaining -= take;
        }
        if is_timeline_marker_line(&line) {
            Self::pin_line(entry, &line);
        }
    }

    fn pin_line(entry: &mut LogBufferEntry, line: &[u8]) {
        if entry.pinned_overflow {
            return;
        }
        if entry.pinned.len() + line.len() > MAX_PINNED_BYTES_PER_BUILD {
            entry.pinned_overflow = true;
            tracing::warn!(
                pinned_bytes = entry.pinned.len(),
                cap = MAX_PINNED_BYTES_PER_BUILD,
                "Pinned phase-marker store exceeded cap; further early markers are dropped from the live timeline (on-disk log unaffected)"
            );
            return;
        }
        entry.pinned.extend_from_slice(line);
    }

    /// 返回指定 build 当前日志流的总字节数，即下一条 chunk 的起始偏移。
    pub fn total_size(&self, build_id: i64) -> Option<usize> {
        let buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
        buffers.get(&build_id).map(|entry| entry.next_offset)
    }

    /// 返回当前被追踪的 build_id 快照（活跃条目与墓碑）；供后台回收遍历
    /// 强制驱逐滞留墓碑，只读。
    pub(crate) fn tracked_build_ids(&self) -> Vec<i64> {
        self.buffers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn notify_tracked_ids(&self) -> Vec<i64> {
        self.notifies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn pinned_state(&self, build_id: i64) -> (usize, usize, bool) {
        let buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
        buffers
            .get(&build_id)
            .map(|entry| {
                (
                    entry.pinned.len(),
                    entry.pending_head.len(),
                    entry.pinned_overflow,
                )
            })
            .unwrap_or((0, 0, false))
    }

    fn entry_size(entry: &LogBufferEntry) -> usize {
        entry.current_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn log_buffer_wait_change_wakes_on_register_append_evict() {
        let buf = Arc::new(LogBuffer::new());

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

    #[test]
    fn log_buffer_read_since_reports_front_offset_after_eviction() {
        let buf = LogBuffer::new();
        buf.append(1, Bytes::from("hello "));
        let (chunks, next, front) = buf.read_since(1, 0);
        assert_eq!(chunks.len(), 1);
        assert_eq!(next, 6);
        assert_eq!(front, 0, "no eviction yet: front is the first chunk offset");

        for _ in 0..11 {
            assert!(buf.append(1, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES])));
        }
        let (_, next, front) = buf.read_since(1, 0);
        assert!(front > 0, "front must advance past the evicted prefix");
        assert!(front < next, "front must stay behind the live chunks");

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

        assert!(buf.append(1, Bytes::from("tail")));
        let (chunks, _, _) = buf.read_since(1, 11 * MAX_LOG_CHUNK_BYTES);
        let joined: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(joined, b"tail".to_vec());
    }

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

        assert!(buf.append(1, Bytes::from("tail")));
        let (chunks, offset, _) = buf.read_since(1, 0);
        let joined: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(joined, b"oktail".to_vec());
        assert_eq!(offset, 6);
    }

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

        let clone = buf.clone();
        assert!(clone.append(2, Bytes::from(vec![b'y'; MAX_LOG_CHUNK_BYTES])));
        assert!(clone.append(2, Bytes::from(vec![b'y'; MAX_LOG_CHUNK_BYTES])));

        assert!(!buf.append(2, Bytes::from("z")));
        assert_eq!(
            buf.total_size(2),
            Some(2 * MAX_LOG_CHUNK_BYTES + 1),
            "rejected append must still advance next_offset past the skipped window"
        );
        let (chunks, next, _) = clone.read_since(2, 2 * MAX_LOG_CHUNK_BYTES);
        assert!(chunks.is_empty(), "rejected chunk must not be readable");
        assert_eq!(next, 2 * MAX_LOG_CHUNK_BYTES + 1);

        buf.evict(1);
        assert!(buf.append(2, Bytes::from("tail")));
        let (chunks, next, _) = buf.read_since(2, 2 * MAX_LOG_CHUNK_BYTES + 1);
        let joined: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(joined, b"tail".to_vec());
        assert_eq!(next, 2 * MAX_LOG_CHUNK_BYTES + 5);
    }

    #[test]
    fn log_buffer_global_cap_rejected_window_is_backfillable_hole() {
        let buf = LogBuffer::new();
        for _ in 0..11 {
            assert!(buf.append(1, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES])));
        }
        assert!(buf.append(2, Bytes::from(vec![b'y'; MAX_LOG_CHUNK_BYTES])));
        assert!(buf.append(2, Bytes::from(vec![b'y'; MAX_LOG_CHUNK_BYTES])));

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

        let (chunks, _, _) = buf.read_since_with_offsets(1, 8);
        assert_eq!(chunks, vec![(8, Bytes::from("rld"))]);
        let (data, next, _) = buf.read_since(1, 8);
        assert_eq!(data, vec![Bytes::from("rld")]);
        assert_eq!(next, 11);
        buf.evict(1);

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

    #[test]
    fn log_buffer_global_total_cap_recovers_after_evict() {
        let buf = LogBuffer::new();
        for _ in 0..11 {
            assert!(buf.append(1, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES])));
        }
        assert!(buf.append(2, Bytes::from(vec![b'y'; MAX_LOG_CHUNK_BYTES])));
        assert!(buf.append(2, Bytes::from(vec![b'y'; MAX_LOG_CHUNK_BYTES])));

        assert!(!buf.append(2, Bytes::from("z")));

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
        let buf = LogBuffer::new();
        buf.register(1);
        buf.append(1, Bytes::from("hello"));
        buf.evict(1);
        buf.evict(1);
        buf.append(1, Bytes::from("late"));
        buf.register(1);
        assert!(!buf.has(1));

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

        buf.evict(1);
        assert!(!buf.has(1));
        assert!(buf.has(2));
    }

    #[test]
    fn is_timeline_marker_line_matches_shared_prefix_set() {
        for line in [
            "# CRBS_PHASE_START build 1.0",
            "# CRBS_PHASE_END build 0 2.0",
            "# CRBS_PHASE_SKIP setup shared_layer",
            "# CRBS_SUBPHASE 12:00 check",
            "Executing(%build)",
            "error: Bad exit status from /bin/sh (%check)",
        ] {
            assert!(is_timeline_marker_line(line.as_bytes()), "{line:?}");
        }
        for line in [
            "normal compiler output",
            "",
            "x# CRBS_PHASE_START a 1.0",
            "Executing(foo)",
        ] {
            assert!(!is_timeline_marker_line(line.as_bytes()), "{line:?}");
        }
    }

    #[test]
    fn log_buffer_pinned_markers_survive_fifo_trim() {
        let buf = LogBuffer::new();
        let mut first =
            String::from("# CRBS_PHASE_START setup 1.0\n# CRBS_PHASE_END setup 0 2.0\n");
        let markers_len = first.len();
        first.extend(std::iter::repeat_n('a', MAX_LOG_CHUNK_BYTES - markers_len));
        assert!(buf.append(1, Bytes::from(first)));
        for _ in 0..10 {
            assert!(buf.append(1, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES])));
        }

        let (pinned_len, pending_len, overflow) = buf.pinned_state(1);
        assert_eq!(pinned_len, markers_len, "both marker lines must be pinned");
        assert_eq!(
            pending_len, 0,
            "non-marker filler tail must not stay pending"
        );
        assert!(!overflow);

        let streamed: Vec<u8> = buf.read(1).iter().flat_map(|b| b.iter().copied()).collect();
        assert_eq!(streamed.len(), 10 * MAX_LOG_CHUNK_BYTES);
        assert!(!streamed
            .windows(b"# CRBS_PHASE".len())
            .any(|w| w == b"# CRBS_PHASE"));
        assert_eq!(buf.total_size(1), Some(11 * MAX_LOG_CHUNK_BYTES));

        let view = buf.read_timeline_text(1);
        let text = String::from_utf8_lossy(&view);
        let spans = crbs_core::engine::profile::parse_phase_markers(&text);
        assert_eq!(spans.len(), 1, "{spans:?}");
        assert_eq!(spans[0].name, "setup");
        assert_eq!(spans[0].state(), "done");
        assert_eq!(spans[0].start, 1.0);
        assert_eq!(spans[0].end, Some(2.0));
        assert_eq!(text.matches("CRBS_PHASE").count(), 2, "no duplicate pins");

        assert_eq!(view.len(), pinned_len + pending_len + streamed.len());
    }

    #[test]
    fn log_buffer_marker_straddling_trim_boundary_pinned_once() {
        let buf = LogBuffer::new();
        let head = b"# CRBS_PHASE_ST";
        let tail = b"ART build 7.5\n";

        let mut first = vec![b'a'; MAX_LOG_CHUNK_BYTES - head.len() - 1];
        first.push(b'\n');
        first.extend_from_slice(head);
        assert!(buf.append(1, Bytes::from(first)));
        let mut second = tail.to_vec();
        second.resize(MAX_LOG_CHUNK_BYTES, b'x');
        assert!(buf.append(1, Bytes::from(second)));
        for _ in 0..9 {
            assert!(buf.append(1, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES])));
        }

        let (pinned_len, pending_len, _) = buf.pinned_state(1);
        assert_eq!(
            pinned_len,
            head.len() + tail.len(),
            "straddled marker must be pinned complete"
        );
        assert_eq!(
            pending_len, 0,
            "peek completion must clear the pending head"
        );
        let view = buf.read_timeline_text(1);
        let text = String::from_utf8_lossy(&view);
        assert_eq!(text.matches("# CRBS_PHASE_START build 7.5").count(), 1);
        let spans = crbs_core::engine::profile::parse_phase_markers(&text);
        assert_eq!(spans.len(), 1, "{spans:?}");
        assert_eq!(spans[0].name, "build");
        assert_eq!(spans[0].start, 7.5);
        assert_eq!(spans[0].state(), "running");

        assert!(buf.append(1, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES])));
        let (pinned_len, _, _) = buf.pinned_state(1);
        assert_eq!(pinned_len, head.len() + tail.len(), "must not double-pin");
        let view = buf.read_timeline_text(1);
        let text = String::from_utf8_lossy(&view);
        assert_eq!(text.matches("CRBS_PHASE_START").count(), 1);
    }

    #[test]
    fn log_buffer_pinned_cap_stops_pin_without_panicking() {
        let buf = LogBuffer::new();

        let line = "# CRBS_PHASE_START testname 1.0\n";
        assert_eq!(line.len(), 32);
        assert_eq!(
            line.len() * (MAX_LOG_CHUNK_BYTES / line.len()),
            MAX_LOG_CHUNK_BYTES
        );
        let mut chunk = String::with_capacity(MAX_LOG_CHUNK_BYTES);
        for _ in 0..MAX_LOG_CHUNK_BYTES / line.len() {
            chunk.push_str(line);
        }
        let chunk_bytes = Bytes::from(chunk);

        for _ in 0..12 {
            assert!(buf.append(1, chunk_bytes.clone()));
        }

        let (pinned_len, pending_len, overflow) = buf.pinned_state(1);
        assert_eq!(
            pinned_len, MAX_PINNED_BYTES_PER_BUILD,
            "marker-dense chunks pin right up to the cap"
        );
        assert!(overflow, "the next evicted marker line must trip the cap");
        assert_eq!(
            pending_len, 0,
            "chunks end on line boundaries: no pending head"
        );
    }

    #[test]
    fn log_buffer_pending_head_dropped_when_line_cannot_be_marker() {
        let buf = LogBuffer::new();
        let mut first = vec![b'a'; MAX_LOG_CHUNK_BYTES - 1];
        first.push(b'\n');
        assert!(buf.append(1, Bytes::from(first)));
        for _ in 0..11 {
            assert!(buf.append(1, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES])));
        }

        let (pinned_len, pending_len, _) = buf.pinned_state(1);
        assert_eq!(pinned_len, 0);
        assert_eq!(pending_len, 0, "non-marker head must be dropped");
        assert_eq!(buf.read_timeline_text(1).len(), 10 * MAX_LOG_CHUNK_BYTES);
    }

    #[test]
    fn log_buffer_pending_head_bounded_by_pin_cap() {
        let buf = LogBuffer::new();
        let mut first = b"# CRBS_PHASE_".to_vec();
        first.resize(MAX_LOG_CHUNK_BYTES, b'a');
        assert!(buf.append(1, Bytes::from(first)));
        for _ in 0..11 {
            assert!(buf.append(1, Bytes::from(vec![b'x'; MAX_LOG_CHUNK_BYTES])));
        }

        let (pinned_len, pending_len, overflow) = buf.pinned_state(1);
        assert_eq!(pinned_len, 0, "unterminated line must not be pinned");
        assert_eq!(pending_len, 0, "oversized pending head must be dropped");
        assert!(!overflow);
        assert_eq!(buf.read_timeline_text(1).len(), 10 * MAX_LOG_CHUNK_BYTES);
    }

    #[test]
    fn log_buffer_is_tombstone_lifecycle() {
        let buf = LogBuffer::new();
        assert!(
            buf.is_tombstone(1),
            "id without an entry must be inert (skip-safe)"
        );
        buf.register(1);
        buf.append(1, Bytes::from("x"));
        assert!(!buf.is_tombstone(1), "live entry must not be a tombstone");
        assert!(!buf.read_timeline_text(1).is_empty());
        buf.evict(1);
        assert!(buf.is_tombstone(1));
        assert!(!buf.has(1));
        assert!(
            buf.read_timeline_text(1).is_empty(),
            "tombstone carries no timeline payload"
        );
    }
}
