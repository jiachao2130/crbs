// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建资源采样：构建脚本进程存续期间从宿主侧只读采集内存与 CPU 用量。
//!
//! 两种口径按后端自动分派（[`crate::engine::backend::SpawnedChild`] 是否携带 cgroup
//! payload 路径），各级独立间隔（采样分级）。cgroup 口径（nspawn + cgroup v2）读
//! `{scope}/payload/` 的 `memory.stat`（`anon` 现值，运行期维护峰值）与 `cpu.stat`
//!（`usage_usec` 增量）：容器进程全在 payload 子目录（scope 根仅 nspawn 监护进程）。
//! /proc 口径（无 cgroup payload）：chroot pgid 匹配为主，`pgrp == child_pid` 与
//! `kill_process_tree` 杀伤范围对齐（spawn 设 `process_group(0)`、exec 不改 pgid）；
//! nspawn + cgroup v1 宿主按 machine scope 归属——容器 init 开新会话/进程组，pgid
//! 匹配抓不到容器进程；nspawn 领导进程也不迁入 scope，scope 目录名自 machine 名
//! 确定性构造（machined 注册形态 `machine-{escaped}.scope`，转义形优先）。内存主
//! 口径读 memory 层级该 scope 的 `memory.stat` `total_rss`（层次化累计本 cgroup 与
//! 全部子孙，共享页只计一次，量纲与 v2 `anon` 对齐，同报 cgroup 口径标签）；memory
//! 层级/scope 未显形或 `total_rss` 行缺失退逐 PID：每 tick 按控制器层级探测首个
//! 存在目录（machined 注册异步，未显形 tick 记空、不记峰值），递归收集 scope 子树
//! 全部 `cgroup.procs`（容器内 systemd 再分层，直属 procs 不够）→ /proc 逐 PID RSS
//! 求和（退出竞态跳过，共享页重复计数保守上界，proc 口径标签）。CPU 两口径都优先
//! scope 级 `cpuacct.usage`（层次化累计、不漏已退出进程），缺失退逐 PID utime+stime。
//! 逐 PID 兜底单次遍历 /proc，每进程一份 `<pid>/stat` 同取 pgrp(5)/utime(14)/
//! stime(15)/rss(24)。
//!
//! 停止条件：根 pid（spawn 的直接子进程）从宿主 /proc 消失（防 PID 复用）；采样全程只读宿主 /proc 与 cgroupfs，读取失败一律降级缺值，绝不影响构建结果与时长。
//!
//! tmpfs 峰值另走 `TmpfsWatch` 观测目标（prepare 产出，两处挂载点互斥）：
//! shared_layer 构建读 BUILD tmpfs 挂载点、全内存构建读自身独立 memroot 挂载
//! 点，均经 statfs 读挂载实例的绝对用量（f_type 非 tmpfs 的 tick 拒采——umount
//! 后挂载点路径仍在但底层已换 overlay），峰值跨 tick 取 max，读失败 tick 缺值
//! 不回填。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

const DEFAULT_PAGE_SIZE_BYTES: i64 = 4096;
/// /proc stat 时钟频率缺省值（`sysconf(_SC_CLK_TCK)` 失败回退；Linux 用户态恒为 USER_HZ=100）。
const DEFAULT_CLK_TCK: i64 = 100;
/// 样本数上限（4096 × 15s ≈ 17 小时，防长构建无限堆积；达上限停止采样、保留已有样本）。
const MAX_SAMPLES: usize = 4096;
/// cgroup 文件未就绪时静默重试的 tick 数；超过后转 warn 节流（nspawn 启动初期 ENOENT 属预期）。
const CGROUP_WARMUP_TICKS: u32 = 3;
/// 采样异常 warn 的节流窗口（每 N 个异常 tick 告警一次，首败必告警）。
const SAMPLE_WARN_EVERY: u32 = 20;
/// cgroup 口径采样间隔缺省（秒）：读单文件成本可忽略，尖峰截断减半；
/// 仅当配置未显式给 `resource_sample_interval_cgroup_secs` 时生效。
pub(crate) const DEFAULT_CGROUP_SAMPLE_INTERVAL_SECS: u64 = 5;

/// cgroupfs 挂载根（v1 scope 归属探测）：v1 宿主各控制器层级挂其下子目录
///（`systemd` / `memory` / `cpu,cpuacct`，systemd 标准布局）。
const CGROUP_FS_ROOT: &str = "/sys/fs/cgroup";

/// v1 宿主 machined scope 的固定挂点（各控制器层级下同名目录）。
const V1_MACHINE_SLICE: &str = "machine.slice";

/// v1 宿主 scope 子树遍历的控制器层级（按序取首个存在目录）：`name=systemd`
/// 层级在 machined 宿主必有，`memory` 层级兜底；各层级子树同构，遍历任一即得
/// 全量 PID。
const V1_SCOPE_TREE_HIERARCHIES: [&str; 2] = ["systemd", "memory"];

/// v1 宿主 CPU 用量层级（按序探测 `cpuacct.usage`）：组合挂载 `cpu,cpuacct`
/// 在前，分离挂载 `cpuacct` 兜底。
const V1_CPUACCT_HIERARCHIES: [&str; 2] = ["cpu,cpuacct", "cpuacct"];

/// `builds.sample_backend` 取值：cgroup 口径（v2 `anon` / v1 `memory.stat`
/// `total_rss`，共享页只计一次，量纲对齐）。
pub const SAMPLE_BACKEND_CGROUP: &str = "cgroup";
/// `builds.sample_backend` 取值：/proc 进程树口径（共享页重复计数上界）。
pub const SAMPLE_BACKEND_PROC: &str = "proc";

/// peak_rss 终值合理性上限（占宿主 MemTotal 比例）：求和超物理内存即共享页重复
/// 计数的直接证据，整值拒收不截断（截断会把污染值伪装成可信值）。
const PEAK_RSS_SANITY_FRACTION: f64 = 0.90;

/// tmpfs 文件系统魔数（linux `include/uapi/linux/magic.h` 的 `TMPFS_MAGIC`，
/// statfs(2) 返回的 `f_type` 判定值）：umount 收尾后的 BUILD 挂载点路径仍在
/// 而底层已换 overlay，非 tmpfs 一律拒采，防止把磁盘 overlay 的 used 误记为
/// tmpfs 峰值。
const TMPFS_MAGIC: i64 = 0x0102_1994;

/// statfs 字段类型归一：各架构 libc 的字段符号不一致（sw_64 的
/// `f_blocks/f_bfree` 为有符号 `c_long`，常见架构为 `u64`）。实际值恒非负；
/// 负值（异常）降级 None。
fn statfs_word_u64(v: impl TryInto<u64>) -> Option<u64> {
    v.try_into().ok()
}

/// 读 `path` 所在文件系统的 tmpfs 已用量（KB，单次 statfs O(1)）：f_type 非
/// [`TMPFS_MAGIC`] 或读失败 → `None`（tick 缺值降级）。used =
/// `(f_blocks − f_bfree) × f_frsize`，字节算术异常（frsize ≤ 0 / 溢出）同样
/// 缺值降级，绝不产出可疑值。
pub(crate) fn read_tmpfs_used_kb(path: &Path) -> Option<i64> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut buf: nix::libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY：c_path 与 buf 均由本函数持有，statfs 只读前者、只写后者。
    let rc = unsafe { nix::libc::statfs(c_path.as_ptr(), &mut buf) };
    if rc != 0 || buf.f_type as i64 != TMPFS_MAGIC {
        return None;
    }
    let used_blocks = statfs_word_u64(buf.f_blocks)?.saturating_sub(statfs_word_u64(buf.f_bfree)?);
    let frsize = statfs_word_u64(buf.f_frsize)?;
    if frsize == 0 {
        return None;
    }
    i64::try_from(used_blocks.checked_mul(frsize)? / 1024).ok()
}

/// 构建自身 tmpfs 挂载实例的观测目标（prepare 产出，两处挂载点互斥；
/// `None` = 不适用——`build_tmpfs` 关闭）。指向本构建专属的挂载点，statfs
/// 绝对读数即本构建精确占用，并发构建互不可见。采样循环逐 tick 调
/// [`TmpfsWatch::sample_kb`]，峰值跨 tick 取 max。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TmpfsWatch {
    /// 挂载点路径；收尾 umount 后 f_type 校验自动失明（路径仍在但底层已换
    /// overlay / 磁盘）。
    pub(crate) path: PathBuf,
}

impl TmpfsWatch {
    /// 本 tick 的 tmpfs 占用读数（KB）；读失败 / 非 tmpfs → `None`（该 tick
    /// 不产生 tmpfs 值，峰值保持既有累计）。
    pub(crate) fn sample_kb(&self) -> Option<i64> {
        read_tmpfs_used_kb(&self.path)
    }
}

/// 一次构建的累计资源用量（与 `builds` 表资源列一一对应）；`None` 字段 = 不可得
///（非 Linux / 无 /proc 与 cgroup / 采样失败 / 采样关闭 / 内核不支持），落库 NULL。
/// [`serde::Serialize`] 供 worker 上报 payload 直接内嵌（新字段 `skip_serializing_if`
/// 整体缺席，hub 侧 `#[serde(default)]` 兼容老协议）。
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct ResourceUsage {
    /// 构建期内存峰值 KB。主口径 = cgroup 内存采样峰值（v2 `anon` / v1
    /// `memory.stat` `total_rss`，共享页只计一次）；不可得时依次退 `memory.peak`
    ///（含文件页缓存，高估方向）、/proc RSS 求和（pgid 匹配集或 v1 scope 子树
    /// 兜底，共享页重复计数，保守上界）。终值超宿主 MemTotal 90% 拒收落 NULL
    ///（重复计数证据，采样器 `PEAK_RSS_SANITY_FRACTION`）。
    pub peak_rss_kb: Option<i64>,
    /// 构建期累计 CPU 时间（秒）：cgroup `cpu.stat` 增量或 /proc utime+stime 求和换算。
    pub cpu_secs: Option<f64>,
    /// 采样窗内平均占用核数的 90 分位（每样本 `delta_cpu_secs / interval_secs`，机器无关的绝对核数口径）。
    pub cpu_p90_cores: Option<f64>,
    /// cgroup `memory.peak` 高水位 KB（含文件页缓存的总内存口径，收尾单次读取；
    /// 展示与 cap-OOM 判定用，不作 sizing 主口径）。/proc 口径恒 `None`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_total_kb: Option<i64>,
    /// cgroup `io.stat` 各设备 wbytes 求和（字节，累计写足迹）。/proc 口径恒 `None`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_wbytes: Option<i64>,
    /// cgroup `memory.events` 的 oom_kill > 0（per-build 独立 scope，值即本次计数）。
    /// `None` = 文件不可得；`Some(false)` = 读到 0（cgroup 口径可用的证据）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_killed: Option<bool>,
    /// 采样口径标签（[`SAMPLE_BACKEND_CGROUP`] / [`SAMPLE_BACKEND_PROC`]）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_backend: Option<&'static str>,
    /// 执行节点核数：engine 层无从知晓，由 worker 上报层附加（与心跳 ncpu 同源）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_ncpu: Option<i64>,
    /// 构建期间构建自身 tmpfs 挂载实例占用（KB，与 peak_rss_kb 同单位）的峰值：
    /// shared_layer 构建读 BUILD tmpfs 挂载点、全内存构建读独立 memroot 挂载
    /// 点，statfs 绝对值（见 `TmpfsWatch`）。`None` = 不适用（`build_tmpfs`
    /// 关闭）或采样不可得。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_tmpfs_kb: Option<i64>,
}

impl ResourceUsage {
    /// 全字段为空（等价"无数据"，写库侧据此落 NULL）。
    fn is_empty(&self) -> bool {
        self.peak_rss_kb.is_none()
            && self.cpu_secs.is_none()
            && self.cpu_p90_cores.is_none()
            && self.peak_total_kb.is_none()
            && self.disk_wbytes.is_none()
            && self.oom_killed.is_none()
            && self.sample_backend.is_none()
            && self.sample_ncpu.is_none()
            && self.peak_tmpfs_kb.is_none()
    }

    /// 附加执行节点核数（worker 上报层在 engine 返回后调用；engine 侧恒 `None`）。
    pub fn with_sample_ncpu(mut self, ncpu: Option<i64>) -> Self {
        self.sample_ncpu = ncpu;
        self
    }
}

/// 跨 phase 共享的采样累计状态（Mutex 内字段全部由采样任务在 tick 中更新）。
#[derive(Debug, Default)]
struct SampleState {
    /// 每样本的平均占用核数（`delta_cpu_secs / interval_secs`）。
    rates: Vec<f64>,
    /// 累计 CPU 秒（全部正增量之和）。
    cpu_total_secs: f64,
    have_cpu: bool,
    /// 内存峰值 KB：cgroup 口径为 anon 采样峰值；/proc 口径为 RSS 求和采样峰值。
    peak_rss_kb: Option<i64>,
    /// cgroup `memory.peak` 兜底值 KB（anon 采样不可得时的退路）。
    mem_peak_kb: Option<i64>,
    /// `memory.peak` 高水位 KB（收尾单次采集；多 phase 各自重立 scope，取跨 phase 最大）。
    peak_total_kb: Option<i64>,
    /// `io.stat` wbytes 设备求和（多 phase scope 计数清零，跨 phase 累加）。
    disk_wbytes: Option<i64>,
    /// oom_kill 检出（多 phase 任一 >0 即 true；全 phase 不可得才 `None`）。
    oom_killed: Option<bool>,
    /// 本构建采样口径（spawn_phase 按 payload 有无记录缺省；tick 内存读数按实测
    /// 路径更新，标签反映末次有读数的路径）。
    backend: Option<&'static str>,
    /// tmpfs 峰值 KB（逐 tick max；None = 无观测目标或全部 tick 不可得）。
    peak_tmpfs_kb: Option<i64>,
    /// 宿主 MemTotal KB（每 phase 开局读一次 /proc/meminfo；读失败 None，
    /// peak_rss 终值合理性检查跳过）。
    host_mem_total_kb: Option<i64>,
    /// peak_rss 理性拒收告警已发（finish 可多次调用，warn 只发一次）。
    peak_rss_sanity_warned: bool,
}

/// Option 的 max 合并：任一侧 Some 取较大者，双侧 None 保持 None。
fn max_opt(prev: Option<i64>, cur: Option<i64>) -> Option<i64> {
    match (prev, cur) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, None) => a,
        (None, b) => b,
    }
}

/// Option 的加法合并：任一侧 None 退另一侧（缺 phase 读数不吞掉已有累计）。
fn add_opt(prev: Option<i64>, cur: Option<i64>) -> Option<i64> {
    match (prev, cur) {
        (Some(a), Some(b)) => Some(a.saturating_add(b)),
        (a, None) => a,
        (None, b) => b,
    }
}

/// oom_kill 的跨 phase OR 合并：任一 phase 检出即 true，双侧 `Some(false)` 才 false。
fn or_opt(prev: Option<bool>, cur: Option<bool>) -> Option<bool> {
    match (prev, cur) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (a, None) => a,
        (None, b) => b,
        (Some(false), Some(false)) => Some(false),
    }
}

/// 从累计状态聚合出资源用量（`finish` 与快照读共用同一口径），并做 peak_rss
/// 终值合理性检查：> [`PEAK_RSS_SANITY_FRACTION`] × 宿主 MemTotal 整值拒收（求和
/// 超物理内存即共享页重复计数的直接证据）。需可变状态置告警一次标志；宿主
/// MemTotal 不可得（/proc/meminfo 读失败）时跳过检查。
fn aggregate(state: &mut SampleState) -> ResourceUsage {
    let mut usage = ResourceUsage {
        // 列口径：anon/total_rss 采样峰值 > memory.peak 兜底 > /proc 求和（方向注释见 builds 表 schema）。
        peak_rss_kb: state.peak_rss_kb.or(state.mem_peak_kb),
        cpu_secs: state.have_cpu.then_some(state.cpu_total_secs),
        cpu_p90_cores: percentile(&state.rates, 0.9),
        peak_total_kb: state.peak_total_kb,
        disk_wbytes: state.disk_wbytes,
        oom_killed: state.oom_killed,
        sample_backend: state.backend,
        sample_ncpu: None,
        peak_tmpfs_kb: state.peak_tmpfs_kb,
    };
    if let Some(peak) = usage.peak_rss_kb {
        if let Some(total_kb) = state.host_mem_total_kb {
            let threshold_kb = (total_kb as f64 * PEAK_RSS_SANITY_FRACTION) as i64;
            if peak > threshold_kb {
                // memory.peak 兜底值含文件页缓存，cache-heavy 构建合法逼近阈值——
                // 误伤可接受：值仍留在 peak_total_kb，拒收是防重复计数扩散的保守取向。
                usage.peak_rss_kb = None;
                if !state.peak_rss_sanity_warned {
                    state.peak_rss_sanity_warned = true;
                    tracing::warn!(
                        peak_rss_kb = peak,
                        threshold_kb,
                        "peak_rss exceeds 90% of host MemTotal; rejecting value (suspected shared-page double counting)"
                    );
                }
            }
        }
    }
    usage
}

/// 采样累计状态的共享快照句柄：引擎创建采样器时把句柄放入调用方提供的槽位
///（`BuildEngine::with_resource_snapshot_slot`），调用方（worker poller 总预算
/// abort 路径）在任务体被 abort、引擎局部状态随 future 丢弃后，仍能读到已累计值。
#[derive(Clone, Debug)]
pub struct ResourceSnapshot {
    state: Arc<Mutex<SampleState>>,
}

impl ResourceSnapshot {
    /// 汇总当前累计状态；全程无任何样本时返回 `None`（口径与 `ResourceSampler::finish` 一致）。
    pub fn finish(&self) -> Option<ResourceUsage> {
        let usage = aggregate(&mut lock_state(&self.state));
        (!usage.is_empty()).then_some(usage)
    }
}

/// 快照槽位：引擎按构建写入最新采样器的句柄，abort 方按引用读。
pub type ResourceSnapshotSlot = Arc<Mutex<Option<ResourceSnapshot>>>;

/// 新建空快照槽位（poller 领任务时创建、随任务体传入引擎）。
pub fn new_resource_snapshot_slot() -> ResourceSnapshotSlot {
    Arc::new(Mutex::new(None))
}

/// 读取槽位内快照的当前累计值；槽位为空（未进采样阶段 / 双口径均关闭）返回 `None`。
/// Mutex 中毒取内部值继续（缺值优于 panic，与采样侧同一降级姿态）。
pub fn snapshot_slot_resources(slot: &ResourceSnapshotSlot) -> Option<ResourceUsage> {
    let guard = match slot.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.as_ref().and_then(|s| s.finish())
}

/// 采样器：一次构建一个实例，跨脚本 phase（如 reproduce 两阶段）共享累计
/// 状态。双口径间隔独立（cgroup 读单文件、/proc 遍历进程树）；
/// 两者都为 0 时构造返回 `None`（采样整体关闭）。
pub(crate) struct ResourceSampler {
    /// /proc 口径间隔；0 = 该口径关闭（不牵连 cgroup 口径）。
    proc_interval: Duration,
    /// cgroup 口径间隔；0 = 该口径关闭。
    cgroup_interval: Duration,
    state: Arc<Mutex<SampleState>>,
}

impl ResourceSampler {
    /// `proc_interval_secs` 来自 `resource_sample_interval_secs`（语义不变：0 关
    /// /proc 口径）；`cgroup_interval_secs` 来自 `resource_sample_interval_cgroup_secs`，
    /// `None` = 未配置，落 [`DEFAULT_CGROUP_SAMPLE_INTERVAL_SECS`] 常量，`Some(0)` 关
    /// cgroup 口径。
    pub(crate) fn from_intervals(
        proc_interval_secs: u64,
        cgroup_interval_secs: Option<u32>,
    ) -> Option<Self> {
        let cgroup_secs = cgroup_interval_secs
            .map(u64::from)
            .unwrap_or(DEFAULT_CGROUP_SAMPLE_INTERVAL_SECS);
        if proc_interval_secs == 0 && cgroup_secs == 0 {
            return None;
        }
        Some(Self {
            proc_interval: Duration::from_secs(proc_interval_secs),
            cgroup_interval: Duration::from_secs(cgroup_secs),
            state: Arc::new(Mutex::new(SampleState::default())),
        })
    }

    /// 共享快照句柄（abort 兜底取值用；与 `finish` 读同一份状态）。
    pub(crate) fn snapshot(&self) -> ResourceSnapshot {
        ResourceSnapshot {
            state: Arc::clone(&self.state),
        }
    }

    /// 为一个脚本 phase 启动采样任务（spawn 拿到 child_pid 后调用）。返回
    /// `(任务句柄, 停止信号)`：调用方 outcome 解析后先发停止信号、再限时 join；任务在根 pid 消失或 stop 到达后收尾（cgroup 口径收尾做终态单次采集）。
    /// `cgroup_payload` 在 → cgroup v2 口径；`None` → /proc 口径，`v1_scope_machine`
    /// 为 Some（nspawn + cgroup v1 宿主的 machine 名）时按 machine scope 子树
    /// 归属、None 时 pgid 匹配。`tmpfs_watch` 为 prepare 产出的 tmpfs 观测目标
    /// （构建级恒定，逐 phase 透传）。本 phase 对应口径间隔为 0（关闭）时不
    /// spawn，返回 `None`。
    pub(crate) fn spawn_phase(
        &self,
        child_pid: u32,
        cgroup_payload: Option<&str>,
        v1_scope_machine: Option<&str>,
        proc_root: &Path,
        tmpfs_watch: Option<&TmpfsWatch>,
    ) -> Option<(tokio::task::JoinHandle<()>, Arc<Notify>)> {
        let (interval, backend) = match cgroup_payload {
            Some(_) => (self.cgroup_interval, SAMPLE_BACKEND_CGROUP),
            None => (self.proc_interval, SAMPLE_BACKEND_PROC),
        };
        if interval.is_zero() {
            return None;
        }
        {
            let mut st = lock_state(&self.state);
            st.backend = Some(backend);
        }
        let payload = cgroup_payload.map(PathBuf::from);
        // 口径互斥：payload 在 = cgroup v2，v1 scope 归属不参与
        let v1_machine = if payload.is_none() {
            v1_scope_machine.map(String::from)
        } else {
            None
        };
        let stop = Arc::new(Notify::new());
        let state = Arc::clone(&self.state);
        let handle = tokio::spawn(run_sampling_loop(
            SampleTarget {
                child_pid,
                cgroup_payload: payload,
                v1_machine,
                cgroup_fs_root: PathBuf::from(CGROUP_FS_ROOT),
                proc_root: proc_root.to_path_buf(),
                tmpfs: tmpfs_watch.cloned(),
            },
            interval,
            state,
            stop.clone(),
        ));
        Some((handle, stop))
    }

    /// 汇总当前累计状态；全程无任何样本时返回 `None`。
    pub(crate) fn finish(&self) -> Option<ResourceUsage> {
        let usage = aggregate(&mut lock_state(&self.state));
        (!usage.is_empty()).then_some(usage)
    }
}

/// Mutex 中毒恢复读取：采样写侧不会 panic，中毒只可能来自持有方 bug——取内部值继续（缺值优于 panic，采样绝不影响构建）。
fn lock_state(state: &Mutex<SampleState>) -> std::sync::MutexGuard<'_, SampleState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// 就近秩法 p 分位：升序排序后取 `ceil(p * n)` 位（1-based），空序列为 None。
fn percentile(sorted_source: &[f64], p: f64) -> Option<f64> {
    if sorted_source.is_empty() {
        return None;
    }
    let mut sorted = sorted_source.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = sorted.len();
    let rank = ((p * n as f64).ceil() as usize).clamp(1, n);
    sorted.get(rank - 1).copied()
}

/// 单次采样任务的目标与注入点（spawn_phase 构造，循环与 tick 透传；字段全
/// owned 便于 spawn_blocking 按值捕获）。
#[derive(Clone)]
struct SampleTarget {
    /// spawn 的直接子进程（nspawn 领导 / chroot 脚本进程），宿主 /proc 消失即停采。
    child_pid: u32,
    /// cgroup v2 payload 目录；None = /proc 口径（与 `v1_machine` 互斥）。
    cgroup_payload: Option<PathBuf>,
    /// v1 scope 归属 machine 名（nspawn + cgroup v1 宿主）；None = pgid 兜底口径。
    v1_machine: Option<String>,
    /// cgroupfs 挂载根（v1 scope 层级探测；测试注入点）。
    cgroup_fs_root: PathBuf,
    /// 宿主 /proc 根（测试注入点）。
    proc_root: PathBuf,
    /// tmpfs 观测目标（prepare 产出；None = 不采样 tmpfs）。
    tmpfs: Option<TmpfsWatch>,
}

/// 采样循环：每 interval 采一次样，根 pid 消失或 stop 信号到达后收尾。
async fn run_sampling_loop(
    target: SampleTarget,
    interval: Duration,
    state: Arc<Mutex<SampleState>>,
    stop: Arc<Notify>,
) {
    // 宿主 MemTotal 每 phase 开局读一次（peak_rss 终值合理性检查基准；读失败跳过
    // 检查不致命）。proc_root 即生产 /proc 注入点，meminfo 随之可测。
    let proc_root = target.proc_root.clone();
    let mem_total_kb = tokio::task::spawn_blocking(move || read_mem_total_kb(&proc_root))
        .await
        .ok()
        .flatten();
    lock_state(&state).host_mem_total_kb = mem_total_kb;
    let mut last_cpu_secs: Option<f64> = None;
    // 与 last_cpu_secs 同帧的时刻：延迟/错过 tick 时按真实间隔折算核数，
    // 固定 interval 会把"两拍并一拍"的增量放大成 2x。
    let mut last_cpu_at: Option<std::time::Instant> = None;
    let mut cgroup_warmup_left = CGROUP_WARMUP_TICKS;
    let mut failure_ticks: u32 = 0;

    loop {
        // 单次 /proc 扫描与 cgroup 文件读取都是阻塞 IO（慢 NFS 挂载的 /proc 下同理）：走 spawn_blocking 移出 async 线程。
        let target_owned = target.clone();
        let tick = tokio::task::spawn_blocking(move || sample_tick(&target_owned)).await;
        match &tick {
            Ok(Some(sample)) => {
                failure_ticks = 0;
                if sample.rss_kb.is_some() {
                    let mut st = lock_state(&state);
                    st.peak_rss_kb = st.peak_rss_kb.max(sample.rss_kb);
                    // 口径标签随内存读数实测路径更新（Some ⇔ 本 tick rss 有值，
                    // 印证读数口径）：v1 memory.stat 主口径报 cgroup、逐 PID 兜底
                    // 报 proc，覆盖 spawn 缺省标签。
                    if let Some(backend) = sample.backend {
                        st.backend = Some(backend);
                    }
                }
                if sample.tmpfs_kb.is_some() {
                    let mut st = lock_state(&state);
                    st.peak_tmpfs_kb = st.peak_tmpfs_kb.max(sample.tmpfs_kb);
                }
                if let Some(cpu) = sample.cpu_secs {
                    let now = std::time::Instant::now();
                    if let (Some(prev), Some(prev_at)) = (last_cpu_secs, last_cpu_at) {
                        let delta = cpu - prev;
                        let elapsed = now.duration_since(prev_at).as_secs_f64();
                        if delta.is_finite() && delta > 0.0 && elapsed > 0.0 {
                            let mut st = lock_state(&state);
                            st.have_cpu = true;
                            st.cpu_total_secs += delta;
                            st.rates.push(delta / elapsed);
                        }
                    }
                    last_cpu_secs = Some(cpu);
                    last_cpu_at = Some(now);
                } else {
                    // 读数中断后恢复：旧基线可能跨越大段空窗，丢弃重立。
                    last_cpu_secs = None;
                    last_cpu_at = None;
                }
                if target.cgroup_payload.is_some()
                    && sample.rss_kb.is_none()
                    && sample.cpu_secs.is_none()
                    && cgroup_warmup_left > 0
                {
                    cgroup_warmup_left -= 1;
                }
            }
            Ok(None) => break,
            // join 失败仅见于运行时关闭：不计异常 tick 直接继续，收尾由 stop 信号兜底
            //（sample_read_failed 对 Err 恒 false，failure_ticks 不因此累加）。
            Err(_) => {}
        }

        if sample_read_failed(&tick, target.cgroup_payload.is_some(), cgroup_warmup_left) {
            failure_ticks = failure_ticks.saturating_add(1);
            if failure_ticks == 1 || failure_ticks % SAMPLE_WARN_EVERY == 0 {
                tracing::warn!(
                    child_pid = target.child_pid,
                    failures = failure_ticks,
                    "resource sampling unavailable (non-fatal); continuing"
                );
            }
        }

        let sampled = lock_state(&state).rates.len();
        if sampled >= MAX_SAMPLES {
            tracing::debug!(
                child_pid = target.child_pid,
                samples = sampled,
                "resource sample cap reached; stopping sampling"
            );
            break;
        }

        // 等待下一 tick：stop 信号优先于定时醒来（构建结束后立即收尾，不吃满一个 interval 的 join 超时）。
        tokio::select! {
            _ = stop.notified() => break,
            _ = tokio::time::sleep(interval) => {}
        }
    }

    // 收尾终态单次采集（cgroup 口径）：memory.peak 高水位 → peak_total_kb、
    // io.stat wbytes 设备求和 → disk_wbytes、memory.events oom_kill → oom_killed。
    // 文件不可得（systemd 已回收 / 内核不支持）→ 对应维度 None，绝不影响构建。
    // 同 machine 名每次 spawn 重立 scope（前容器 reap 后 systemd 释放，计数清零），
    // 多 phase 聚合：peak 取最大、wbytes 累加、oom 任一检出即 true。
    if let Some(payload) = &target.cgroup_payload {
        let peak_path = payload.join("memory.peak");
        let io_path = payload.join("io.stat");
        let events_path = payload.join("memory.events");
        let (peak_total, disk_wbytes, oom_kill) = tokio::task::spawn_blocking(move || {
            (
                read_memory_peak_kb(&peak_path),
                read_io_stat_wbytes(&io_path),
                read_named_file_value(&events_path, "oom_kill"),
            )
        })
        .await
        .unwrap_or((None, None, None));
        {
            let mut st = lock_state(&state);
            st.peak_total_kb = max_opt(st.peak_total_kb, peak_total);
            st.disk_wbytes = add_opt(st.disk_wbytes, disk_wbytes);
            st.oom_killed = or_opt(st.oom_killed, oom_kill.map(|v| v > 0));
        }

        // 既有兜底：anon 采样不可得时 memory.peak 退作 peak_rss（builds.peak_rss_kb
        // 列口径；systemd 回收竞态下可能已消失，ENOENT 静默）。
        let anon_missing = lock_state(&state).peak_rss_kb.is_none();
        if anon_missing && peak_total.is_some() {
            lock_state(&state).mem_peak_kb = peak_total;
        }
    }
}

/// 读 `io.stat` 全设备 `wbytes` 求和（字节）：每行 `dev:minor rbytes=N …
/// wbytes=N …`（key=value token 形态），任一 token 解析失败只丢该值；
/// 文件不存在 / 全部不可解析返回 `None`。
fn read_io_stat_wbytes(path: &Path) -> Option<i64> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut total: i64 = 0;
    let mut seen = false;
    for token in text.split_whitespace() {
        if let Some(v) = token.strip_prefix("wbytes=") {
            if let Ok(n) = v.parse::<i64>() {
                seen = true;
                total = total.saturating_add(n);
            }
        }
    }
    seen.then_some(total)
}

/// 读 cgroup 控制文件中 `name` 对应的整数值（`memory.events` 的 oom_kill 等）；
/// 文件不存在 / 值缺失返回 `None`。
fn read_named_file_value(path: &Path, name: &str) -> Option<i64> {
    let text = std::fs::read_to_string(path).ok()?;
    parse_named_value(&text, name)
}

/// 本 tick 是否属"读不到数据"的异常形态（节流告警用）：根消失 None 非异常、join Err 不计、cgroup 预热期内双缺不计。
fn sample_read_failed(
    tick: &Result<Option<TickSample>, tokio::task::JoinError>,
    is_cgroup: bool,
    warmup_left: u32,
) -> bool {
    match tick {
        Ok(Some(sample)) => {
            is_cgroup && sample.rss_kb.is_none() && sample.cpu_secs.is_none() && warmup_left == 0
        }
        _ => false,
    }
}

struct TickSample {
    /// 本 tick 内存用量 KB（cgroup：anon / v1 `total_rss` 现值；/proc：pgid 匹配
    /// 集或 v1 scope 子树 RSS 求和；文件未就绪时为 None）。
    rss_kb: Option<i64>,
    /// 本 tick 内存读数的口径标签（Some ⇔ rss_kb 有值，印证读数口径）；None =
    /// 本 tick 无内存读数，沿用既有标签。
    backend: Option<&'static str>,
    /// 本 tick 的累计 CPU 秒（cgroup `usage_usec`；/proc：cpuacct.usage 或
    /// utime+stime 求和）。
    cpu_secs: Option<f64>,
    /// 本 tick 的 tmpfs 占用 KB（观测目标在场的 tick 才有值；读失败 / 非 tmpfs
    /// 为 None）。
    tmpfs_kb: Option<i64>,
}

/// 采集一个 tick。返回 `None` = 根 pid 已从宿主 /proc 消失（停止采样）。
fn sample_tick(target: &SampleTarget) -> Option<TickSample> {
    // /proc/<pid> 不存在即认为子进程已退出；PID 复用窗口（退出→复用→再读到同号进程）被"消失即停"收窄到最小，即便命中也只多采一 tick、随后 stop/join 兜底。
    if !target.proc_root.join(target.child_pid.to_string()).exists() {
        return None;
    }
    let mut tick = match (&target.cgroup_payload, target.v1_machine.as_deref()) {
        (Some(payload), _) => sample_cgroup(payload),
        (None, Some(machine)) => sample_v1_scope_tree(
            &target.proc_root,
            &target.cgroup_fs_root,
            target.child_pid,
            machine,
        ),
        (None, None) => sample_proc_tree(&target.proc_root, target.child_pid),
    };
    // tmpfs 读数独立于内存/CPU 口径：读失败（含 umount 后底层换 overlay）只丢
    // 本 tick，不牵连其余维度。
    tick.tmpfs_kb = target.tmpfs.as_ref().and_then(TmpfsWatch::sample_kb);
    Some(tick)
}

/// cgroup 口径单 tick：读 payload 的 `memory.stat`（anon）与 `cpu.stat`（usage_usec）；任一文件暂缺（scope 未就绪 / 已被回收）返回对应 None，不致命。
fn sample_cgroup(payload: &Path) -> TickSample {
    let rss_kb = std::fs::read_to_string(payload.join("memory.stat"))
        .ok()
        .and_then(|s| parse_named_value(&s, "anon"))
        .map(|bytes| bytes / 1024);
    let cpu_secs = std::fs::read_to_string(payload.join("cpu.stat"))
        .ok()
        .and_then(|s| parse_named_value(&s, "usage_usec"))
        .map(|usec| usec as f64 / 1_000_000.0);
    TickSample {
        backend: rss_kb.map(|_| SAMPLE_BACKEND_CGROUP),
        rss_kb,
        cpu_secs,
        tmpfs_kb: None,
    }
}

/// 取 key/value 行文本里 `name` 对应的原始整数值（cgroup 控制文件通用形态），单位换算由调用方负责。
fn parse_named_value(text: &str, name: &str) -> Option<i64> {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some(name) {
            return parts.next()?.parse().ok();
        }
    }
    None
}

/// /proc 口径单 tick：单次遍历 /proc，取 `pgrp == child_pid` 集合，RSS 页数求和（×页大小）与 utime+stime 求和（÷CLK_TCK）；共享页重复计入，保守上界（见模块注释）。
fn sample_proc_tree(proc_root: &Path, child_pid: u32) -> TickSample {
    let page_size = page_size_bytes();
    let clk_tck = clk_tck();
    let mut rss_kb_total: Option<i64> = None;
    let mut cpu_ticks_total: u64 = 0;
    let entries = match std::fs::read_dir(proc_root) {
        Ok(e) => e,
        // /proc 整体不可读（极端容器环境）：本 tick 无数据，不致命。
        Err(_) => {
            return TickSample {
                rss_kb: None,
                backend: None,
                cpu_secs: None,
                tmpfs_kb: None,
            }
        }
    };
    for entry in entries.flatten() {
        // 只认数字目录（进程目录）。
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            // 进程在扫描间隙退出：跳过（快照一致性以单次遍历为准）。
            continue;
        };
        let Some(parsed) = parse_proc_stat(&stat) else {
            continue;
        };
        // pgid 匹配为主口径：与 kill_process_tree 的杀伤范围精确对齐。
        if parsed.pgrp != child_pid as i64 {
            continue;
        }
        let _ = pid;
        rss_kb_total =
            Some(rss_kb_total.unwrap_or(0) + (parsed.rss_pages as i64) * page_size / 1024);
        cpu_ticks_total += parsed.utime.saturating_add(parsed.stime);
    }
    TickSample {
        backend: rss_kb_total.map(|_| SAMPLE_BACKEND_PROC),
        rss_kb: rss_kb_total,
        cpu_secs: Some(cpu_ticks_total as f64 / clk_tck as f64),
        tmpfs_kb: None,
    }
}

/// `/proc/<pid>/stat` 关键字段（字段号按 proc(5)：pgrp=5、utime=14、stime=15、rss=24）。
#[derive(Debug, PartialEq, Eq)]
struct ProcStatFields {
    pgrp: i64,
    utime: u64,
    stime: u64,
    rss_pages: u64,
}

/// 解析 `/proc/<pid>/stat`：comm 字段可含空格与括号，按**最后一个** `)` 切开
/// 后再按空白切字段——此后 rest[N-3] 对应字段 N（state=3 起）。
fn parse_proc_stat(content: &str) -> Option<ProcStatFields> {
    let close = content.rfind(')')?;
    let rest: Vec<&str> = content[close + 1..].split_whitespace().collect();
    // rest[0]=state(3)，最长需要 rss(24) → rest[21]，至少 22 个字段。
    if rest.len() < 22 {
        return None;
    }
    Some(ProcStatFields {
        pgrp: rest[2].parse().ok()?,
        utime: rest[11].parse().ok()?,
        stime: rest[12].parse().ok()?,
        rss_pages: rest[21].parse().ok()?,
    })
}

/// v1 宿主 scope 归属单 tick：内存主口径读 memory 层级该 scope 的 `memory.stat`
/// `total_rss`（层次化累计本 cgroup 与全部子孙，共享页只计一次，量纲与 v2 anon
/// 对齐、同报 cgroup 口径标签——存量 proc 口径画像行遇之走升级重置清零重学）；
/// memory 层级/scope 未显形（machined 注册异步）或 `total_rss` 行缺失退逐 PID：
/// scope 目录名候选自 machine 名确定性构造、按控制器层级探测首个存在目录，递归
/// 收集 scope 子树全部 `cgroup.procs`（容器内 systemd 再分层，直属 procs 不够）
/// → /proc 逐 PID stat 求和（退出竞态跳过、共享页重复计数，报 proc 口径标签）。
/// CPU 优先 scope 级 `cpuacct.usage`（层次化累计、不漏已退出进程），缺失退逐
/// PID utime+stime；主口径与 cpuacct 皆得时免 scope 树遍历。scope 未显形且
/// memory.stat 缺失的 tick 记空集，不记峰值也不立 CPU 基线；树根不可读（非不
/// 存在）且无 memory.stat 主口径时降级 pgid 兜底。
fn sample_v1_scope_tree(
    proc_root: &Path,
    cgroup_fs_root: &Path,
    child_pid: u32,
    machine_name: &str,
) -> TickSample {
    let dir_names = v1_scope_dir_names(machine_name);
    // 内存主口径与 CPU 层次化读数先行：皆得则免逐 PID 遍历（per-PID 求和降级为
    // memory.stat 不可得的最后兜底）。
    let mem_rss_kb = read_v1_scope_memory_rss_kb(cgroup_fs_root, &dir_names);
    let cpu_from_cpuacct = read_cpuacct_usage_secs(cgroup_fs_root, &dir_names);
    if let (Some(rss_kb), Some(cpu_secs)) = (mem_rss_kb, cpu_from_cpuacct) {
        return TickSample {
            rss_kb: Some(rss_kb),
            backend: Some(SAMPLE_BACKEND_CGROUP),
            cpu_secs: Some(cpu_secs),
            tmpfs_kb: None,
        };
    }

    // 兜底路径需 scope 目录（pids 来源）：探测层级 × 目录名形态全组合（machined
    // 注册竞态容忍：未显形同空集处理）；memory.stat 主口径在场可单独出值。
    let Some(scope_dir) = V1_SCOPE_TREE_HIERARCHIES
        .iter()
        .flat_map(|hier| {
            dir_names
                .iter()
                .map(|name| cgroup_fs_root.join(hier).join(V1_MACHINE_SLICE).join(name))
                .collect::<Vec<_>>()
        })
        .find(|dir| dir.is_dir())
    else {
        return TickSample {
            rss_kb: mem_rss_kb,
            backend: mem_rss_kb.map(|_| SAMPLE_BACKEND_CGROUP),
            cpu_secs: cpu_from_cpuacct,
            tmpfs_kb: None,
        };
    };
    let mut pids = Vec::new();
    if !collect_scope_pids(&scope_dir, &mut pids) {
        // 树根不可读（权限等非竞态错误）：memory.stat 主口径在场则保它（不与
        // pgid 口径混量纲）；否则 scope 口径不可用，降级 pgid 兜底
        if let Some(rss_kb) = mem_rss_kb {
            return TickSample {
                rss_kb: Some(rss_kb),
                backend: Some(SAMPLE_BACKEND_CGROUP),
                cpu_secs: cpu_from_cpuacct,
                tmpfs_kb: None,
            };
        }
        tracing::debug!(
            child_pid = child_pid,
            scope_dir = %scope_dir.display(),
            "machine scope tree unreadable; falling back to pgid matching"
        );
        return sample_proc_tree(proc_root, child_pid);
    }
    let page_size = page_size_bytes();
    let clk_tck = clk_tck();
    // RSS 只在 memory.stat 主口径缺失时累计（同 tick 不混两口径）。
    let mut rss_kb_total: Option<i64> = None;
    let mut cpu_ticks_total: u64 = 0;
    // stat 读到过进程：兜底 CPU 才立基线（全集读空立 0 基线，会把恢复后的
    // 正增量放大成速率尖峰）。
    let mut saw_any_proc = false;
    for pid in pids {
        let Ok(stat) = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")) else {
            // 进程在采集间隙退出：跳过，不致命
            continue;
        };
        let Some(parsed) = parse_proc_stat(&stat) else {
            continue;
        };
        saw_any_proc = true;
        if mem_rss_kb.is_none() {
            rss_kb_total =
                Some(rss_kb_total.unwrap_or(0) + (parsed.rss_pages as i64) * page_size / 1024);
        }
        cpu_ticks_total += parsed.utime.saturating_add(parsed.stime);
    }
    let rss_kb = mem_rss_kb.or(rss_kb_total);
    // 逐 PID CPU 兜底仅在 stat 读到过进程时生效（全集读空不立 0 基线）。
    let cpu_secs =
        cpu_from_cpuacct.or_else(|| saw_any_proc.then(|| cpu_ticks_total as f64 / clk_tck as f64));
    TickSample {
        backend: rss_kb.map(|_| {
            if mem_rss_kb.is_some() {
                SAMPLE_BACKEND_CGROUP
            } else {
                SAMPLE_BACKEND_PROC
            }
        }),
        rss_kb,
        cpu_secs,
        tmpfs_kb: None,
    }
}

/// v1 memory 层级 scope 的 `memory.stat` `total_rss`（字节 → KB）：层次化累计
/// 本 cgroup 与全部子孙（局部 `rss` 行只计直属收费页，容器进程全在子 cgroup 会
/// 整体漏计），共享页只计一次，量纲与 v2 `anon` 对齐。memory 层级 / scope 未
/// 显形 / 行缺失 → None（调用方退逐 PID 求和）；逐行解析失败只丢该值。
fn read_v1_scope_memory_rss_kb(cgroup_fs_root: &Path, dir_names: &[String]) -> Option<i64> {
    dir_names.iter().find_map(|name| {
        let path = cgroup_fs_root
            .join("memory")
            .join(V1_MACHINE_SLICE)
            .join(name)
            .join("memory.stat");
        let text = std::fs::read_to_string(path).ok()?;
        parse_named_value(&text, "total_rss").map(|bytes| bytes / 1024)
    })
}

/// 宿主 MemTotal（KB）：`<proc_root>/meminfo` 的 `MemTotal:` 行（行值原生 KB）。
/// 读失败 / 行缺失 / 解析失败 → None（peak_rss 终值合理性检查跳过，不致命）。
fn read_mem_total_kb(proc_root: &Path) -> Option<i64> {
    let text = std::fs::read_to_string(proc_root.join("meminfo")).ok()?;
    let line = text.lines().find_map(|l| l.strip_prefix("MemTotal:"))?;
    line.trim_end_matches("kB").trim().parse().ok()
}

/// machine scope 目录名候选（转义形优先）：machined 注册形态确定为
/// `machine-{escaped}.scope`（`-` → `\x2d`，与 kill 链路同源），余三形态兜底
/// 不赌单形态。与 kill/limits 探测的形态集合一致，仅顺序按注册形态调前。
fn v1_scope_dir_names(machine_name: &str) -> [String; 4] {
    let escaped = crate::engine::backend::nspawn::systemd_escape_dash(machine_name);
    [
        format!("machine-{escaped}.scope"),
        format!("machine-{machine_name}.scope"),
        format!("{escaped}.scope"),
        format!("{machine_name}.scope"),
    ]
}

/// 递归收集 scope 子树全部 `cgroup.procs` 的 PID（单层级内每进程恰属一个
/// cgroup，跨层不重不漏）；子目录读失败 / 文件缺失静默跳过（容器收尾并发拆除
/// 的竞态，不致命）。返回 false = 根目录读失败且非不存在（权限等），调用方
/// 降级 pgid 兜底。
fn collect_scope_pids(dir: &Path, pids: &mut Vec<u32>) -> bool {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => return e.kind() == std::io::ErrorKind::NotFound,
    };
    if let Ok(text) = std::fs::read_to_string(dir.join("cgroup.procs")) {
        for pid in text
            .split_whitespace()
            .filter_map(|s| s.parse::<u32>().ok())
        {
            pids.push(pid);
        }
    }
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_scope_pids(&path, pids);
        }
    }
    true
}

/// scope 的 `cpuacct.usage`（纳秒 → 秒；层次化累计：含全部子 cgroup 与已退出
/// 进程）。CPU 层级 × 目录名候选逐根探测；文件不可得返回 `None`（调用方退逐
/// PID 求和）。
fn read_cpuacct_usage_secs(cgroup_fs_root: &Path, dir_names: &[String]) -> Option<f64> {
    for hier in V1_CPUACCT_HIERARCHIES {
        for name in dir_names {
            let path = cgroup_fs_root
                .join(hier)
                .join(V1_MACHINE_SLICE)
                .join(name)
                .join("cpuacct.usage");
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(ns) = text.trim().parse::<u64>() {
                    return Some(ns as f64 / 1_000_000_000.0);
                }
            }
        }
    }
    None
}

/// 单位页字节数（i64；sysconf 失败返回负值，回退 4096）。
fn page_size_bytes() -> i64 {
    let v = unsafe { nix::libc::sysconf(nix::libc::_SC_PAGESIZE) };
    if v > 0 {
        v
    } else {
        DEFAULT_PAGE_SIZE_BYTES
    }
}

fn clk_tck() -> i64 {
    let v = unsafe { nix::libc::sysconf(nix::libc::_SC_CLK_TCK) };
    if v > 0 {
        v
    } else {
        DEFAULT_CLK_TCK
    }
}

/// 读 `memory.peak`（字节）换算 KB；文件不存在（systemd 已回收）返回 None。
fn read_memory_peak_kb(path: &Path) -> Option<i64> {
    let text = std::fs::read_to_string(path).ok()?;
    text.trim().parse::<i64>().ok().map(|v| v / 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    fn proc_entry(root: &Path, pid: u32, pgrp: i64, utime: u64, stime: u64, rss: u64) {
        let dir = root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        // 真实 stat 形态：comm 含空格与括号，干扰字段切分。
        fs::write(
            dir.join("stat"),
            format!(
                "{pid} (some proc (v1)) S {pgrp} {pgrp} 0 0 -1 4194560 0 0 0 0 {utime} {stime} 0 0 20 0 1 0 18446744073709551615 100 {rss} 0 0 0 0 0 0 0\n"
            ),
        )
        .unwrap();
    }

    #[test]
    fn parse_proc_stat_handles_parens_in_comm() {
        let stat = "4242 (make (j1)) S 1000 4242 0 0 -1 4194560 1 2 3 4 11 7 0 0 20 0 1 0 1 100 512 0 0 0 0\n";
        let parsed = parse_proc_stat(stat).unwrap();
        assert_eq!(parsed.pgrp, 4242);
        assert_eq!(parsed.utime, 11);
        assert_eq!(parsed.stime, 7);
        assert_eq!(parsed.rss_pages, 512);
    }

    #[test]
    fn parse_proc_stat_rejects_garbage() {
        assert!(parse_proc_stat("").is_none());
        assert!(parse_proc_stat("1 (x) S 1").is_none());
    }

    /// /proc 口径：只收 pgrp == child_pid 的进程；RSS/CPU 求和；根 pid 在集合内（process_group(0) 后 pgid == pid）。
    #[test]
    fn sample_proc_tree_collects_pgid_group_only() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        proc_entry(root, 5000, 5000, 10, 5, 100); // 根（pgid==pid）
        proc_entry(root, 5001, 5000, 20, 10, 200); // 组内子进程
        proc_entry(root, 5002, 9999, 99, 99, 400); // 别组，必须排除
        proc_entry(root, 4999, 4999, 1, 1, 50); // 无关进程

        let tick = sample_proc_tree(root, 5000);
        // (100 + 200) 页 × 页大小（页大小平台相关：Linux 常见 4K、macOS arm64 16K），与实现同一 sysconf 口径换算 KB。
        let kb_per_page = page_size_bytes() / 1024;
        assert_eq!(tick.rss_kb, Some((100 + 200) * kb_per_page));
        // (10+5+20+10) ticks / 100 = 0.45 s
        assert!((tick.cpu_secs.unwrap() - 0.45).abs() < 1e-9);
    }

    #[test]
    fn sample_tick_stops_when_root_pid_gone() {
        let tmp = tempfile::tempdir().unwrap();
        let target = SampleTarget {
            child_pid: 12345,
            cgroup_payload: None,
            v1_machine: None,
            cgroup_fs_root: PathBuf::from(CGROUP_FS_ROOT),
            proc_root: tmp.path().to_path_buf(),
            tmpfs: None,
        };
        assert!(sample_tick(&target).is_none());
    }

    #[test]
    fn sample_cgroup_reads_anon_and_usage_usec() {
        let tmp = tempfile::tempdir().unwrap();
        let payload = tmp.path().join("payload");
        fs::create_dir_all(&payload).unwrap();
        fs::write(payload.join("memory.stat"), "anon 262144000\nfile 100\n").unwrap();
        fs::write(
            payload.join("cpu.stat"),
            "usage_usec 1500000\nuser_usec 1000000\n",
        )
        .unwrap();

        let tick = sample_cgroup(&payload);
        // 262144000 / 1024 = 256000 KB
        assert_eq!(tick.rss_kb, Some(256_000));
        // 1500000 usec = 1.5 s
        assert!((tick.cpu_secs.unwrap() - 1.5).abs() < 1e-9);
    }

    #[test]
    fn sample_cgroup_tolerates_missing_scope_files() {
        let tmp = tempfile::tempdir().unwrap();
        let payload = tmp.path().join("payload");
        fs::create_dir_all(&payload).unwrap();
        let tick = sample_cgroup(&payload);
        assert_eq!(tick.rss_kb, None);
        assert_eq!(tick.cpu_secs, None);
    }

    /// 采样循环端到端（fixture /proc 根注入）：采到 pgid 组样本后 stop 信号立即收尾，finish() 给出峰值 / 累计 CPU / p90。
    #[tokio::test]
    async fn sampling_loop_accumulates_and_stops_on_signal() {
        let tmp = tempfile::tempdir().unwrap();
        proc_entry(tmp.path(), 7000, 7000, 0, 0, 100);
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        let (handle, stop) = sampler
            .spawn_phase(7000, None, None, tmp.path(), None)
            .expect("proc interval > 0 must spawn");

        for _ in 0..100 {
            if sampler.finish().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        stop.notify_one();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("stop signal must end the loop promptly")
            .unwrap();

        let usage = sampler.finish().expect("rss sample collected");
        assert_eq!(usage.peak_rss_kb, Some(100 * page_size_bytes() / 1024));
        assert!(
            usage.cpu_secs.is_none(),
            "首个样本无增量基线，不得产出 CPU 值"
        );
        assert_eq!(usage.cpu_p90_cores, None);
    }

    /// 根 pid 主动消失（删 fixture 目录）→ 循环自行退出，无需 stop。
    #[tokio::test]
    async fn sampling_loop_exits_when_root_disappears() {
        let tmp = tempfile::tempdir().unwrap();
        proc_entry(tmp.path(), 8000, 8000, 0, 0, 100);
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        let (handle, _stop) = sampler
            .spawn_phase(8000, None, None, tmp.path(), None)
            .expect("proc interval > 0 must spawn");

        tokio::time::sleep(Duration::from_millis(20)).await;
        fs::remove_dir_all(tmp.path().join("8000")).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("root pid disappearance must end the loop")
            .unwrap();
    }

    /// finish() 聚合语义：峰值取最大、CPU 取正增量之和、p90 为就近秩分位。
    #[test]
    fn finish_aggregates_peak_cpu_and_percentile() {
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        {
            let mut st = lock_state(&sampler.state);
            st.peak_rss_kb = Some(300);
            st.have_cpu = true;
            st.cpu_total_secs = 2.5;
            st.rates = vec![0.5, 2.0, 1.0, 4.0, 3.0];
        }
        let usage = sampler.finish().unwrap();
        assert_eq!(usage.peak_rss_kb, Some(300));
        assert!((usage.cpu_secs.unwrap() - 2.5).abs() < 1e-9);
        // 5 样本 p90 = ceil(4.5)=5 → 第 5 位 = 4.0
        assert!((usage.cpu_p90_cores.unwrap() - 4.0).abs() < 1e-9);
    }

    #[test]
    fn finish_falls_back_to_memory_peak() {
        let tmp = tempfile::tempdir().unwrap();
        let payload = tmp.path().join("payload");
        fs::create_dir_all(&payload).unwrap();
        fs::write(payload.join("memory.peak"), format!("{}", 8 * 1024 * 1024)).unwrap();

        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        lock_state(&sampler.state).mem_peak_kb = read_memory_peak_kb(&payload.join("memory.peak"));
        let usage = sampler.finish().unwrap();
        // 8 MiB = 8192 KB
        assert_eq!(usage.peak_rss_kb, Some(8192));
    }

    /// 采样分级间隔选择：双键组合 → 各口径间隔 / 关闭；任一键为 0 只关对应口径。
    #[test]
    fn interval_tiering_selection_matrix() {
        // 新键缺失：cgroup 落 5s 常量、proc 用现有键。
        let s = ResourceSampler::from_intervals(15, None).unwrap();
        assert_eq!(s.proc_interval, Duration::from_secs(15));
        assert_eq!(
            s.cgroup_interval,
            Duration::from_secs(DEFAULT_CGROUP_SAMPLE_INTERVAL_SECS)
        );
        assert_eq!(DEFAULT_CGROUP_SAMPLE_INTERVAL_SECS, 5);
        // Some(n) 显式覆盖；Some(0) 只关 cgroup、proc 不受牵连。
        let s = ResourceSampler::from_intervals(3, Some(9)).unwrap();
        assert_eq!(s.proc_interval, Duration::from_secs(3));
        assert_eq!(s.cgroup_interval, Duration::from_secs(9));
        let s = ResourceSampler::from_intervals(15, Some(0)).unwrap();
        assert_eq!(s.proc_interval, Duration::from_secs(15));
        assert!(s.cgroup_interval.is_zero());
        // 现有键 0 只关 proc、cgroup 仍按新键（缺失 → 5s）。
        let s = ResourceSampler::from_intervals(0, None).unwrap();
        assert!(s.proc_interval.is_zero());
        assert_eq!(
            s.cgroup_interval,
            Duration::from_secs(DEFAULT_CGROUP_SAMPLE_INTERVAL_SECS)
        );
        // 双口径全关 → 不构造采样器。
        assert!(ResourceSampler::from_intervals(0, Some(0)).is_none());
    }

    /// spawn_phase 按口径选间隔：payload 有无决定用哪个间隔；对应口径关闭返回 None。
    #[tokio::test]
    async fn spawn_phase_selects_interval_per_backend() {
        let tmp = tempfile::tempdir().unwrap();
        proc_entry(tmp.path(), 6000, 6000, 0, 0, 1);
        // proc 关闭：无 payload → 不 spawn；cgroup 关闭：有 payload → 不 spawn。
        let closed_proc = ResourceSampler::from_intervals(0, Some(5)).unwrap();
        assert!(closed_proc
            .spawn_phase(6000, None, None, tmp.path(), None)
            .is_none());
        assert!(
            closed_proc
                .spawn_phase(6000, Some("unused/payload"), None, tmp.path(), None)
                .is_some(),
            "cgroup 口径开启：payload 路径必须照常 spawn（间隔与路径真实性无关，循环首 tick 才读文件）"
        );
        // v1 scope 归属同属 proc 口径：proc 间隔 0 一样不 spawn。
        assert!(closed_proc
            .spawn_phase(6000, None, Some("unused-machine"), tmp.path(), None)
            .is_none());
        let closed_cgroup = ResourceSampler::from_intervals(5, Some(0)).unwrap();
        assert!(closed_cgroup
            .spawn_phase(6000, Some("unused/payload"), None, tmp.path(), None)
            .is_none());
        assert!(closed_cgroup
            .spawn_phase(6000, None, None, tmp.path(), None)
            .is_some());
    }

    /// cgroup 口径终态单次采集：fake payload 目录 → memory.peak / io.stat wbytes
    /// 求和 / oom_kill 原值判定 + sample_backend=cgroup；/proc 口径对应维度 None。
    #[tokio::test]
    async fn cgroup_tail_collects_terminal_single_shot() {
        let tmp = tempfile::tempdir().unwrap();
        let payload = tmp.path().join("payload");
        fs::create_dir_all(&payload).unwrap();
        fs::write(payload.join("memory.stat"), "anon 262144000\nfile 100\n").unwrap();
        fs::write(payload.join("cpu.stat"), "usage_usec 1500000\n").unwrap();
        fs::write(
            payload.join("memory.peak"),
            format!("{}", 512 * 1024 * 1024),
        )
        .unwrap();
        // 两设备 wbytes 求和：1234 + 2 = 1236。
        fs::write(
            payload.join("io.stat"),
            "8:0 rbytes=100 rios=1 wbytes=1234 wios=2 dbytes=0 dios=0\n\
             8:16 rbytes=5 rios=1 wbytes=2 wios=1 dbytes=0 dios=0\n",
        )
        .unwrap();
        fs::write(payload.join("memory.events"), "oom_kill 2\noom 3\n").unwrap();

        proc_entry(tmp.path(), 6100, 6100, 0, 0, 1);
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        let (handle, stop) = sampler
            .spawn_phase(6100, payload.to_str(), None, tmp.path(), None)
            .expect("cgroup interval defaults on");
        stop.notify_one();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("stop must end the loop")
            .unwrap();

        let usage = sampler.finish().expect("cgroup samples collected");
        assert_eq!(usage.sample_backend, Some(SAMPLE_BACKEND_CGROUP));
        // 512 MiB = 524288 KB；memory.peak 单调高水位现值直接成为 peak_total。
        assert_eq!(usage.peak_total_kb, Some(512 * 1024));
        assert_eq!(usage.disk_wbytes, Some(1236));
        assert_eq!(usage.oom_killed, Some(true));
        // anon 采样可得 → peak_rss 走主口径，memory.peak 不退作 peak_rss。
        assert_eq!(usage.peak_rss_kb, Some(256_000));
        assert_eq!(usage.sample_ncpu, None, "sample_ncpu 由 worker 上报层附加");
    }

    /// /proc 口径终态：peak_total/disk_wbytes/oom_killed 恒 None，backend=proc。
    #[tokio::test]
    async fn proc_backend_leaves_cgroup_only_dimensions_none() {
        let tmp = tempfile::tempdir().unwrap();
        proc_entry(tmp.path(), 6200, 6200, 0, 0, 64);
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        let (handle, stop) = sampler
            .spawn_phase(6200, None, None, tmp.path(), None)
            .expect("proc interval on");
        stop.notify_one();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("stop must end the loop")
            .unwrap();

        let usage = sampler.finish().expect("proc samples collected");
        assert_eq!(usage.sample_backend, Some(SAMPLE_BACKEND_PROC));
        assert_eq!(usage.peak_total_kb, None);
        assert_eq!(usage.disk_wbytes, None);
        assert_eq!(usage.oom_killed, None);
        assert_eq!(usage.peak_rss_kb, Some(64 * page_size_bytes() / 1024));
    }

    /// v1 scope 归属夹具：领导进程 /proc 项（空目录即可——领导进程不迁入
    /// scope，归属自 machine 名构造）、嵌套 scope 树（根层不可读 pid + 嵌套
    /// service 层本测试进程——跨层收齐的唯一来源）、可选 scope 级 cpuacct.usage
    /// 与 memory 层级 `memory.stat`（total_rss = 102400 字节 → 100 KB，与逐 PID
    /// 求和的 128 页值不同以钉死读数来源）。
    /// machine 名 `crbs-test-01` → machined 注册目录名 `machine-crbs\x2dtest\x2d01.scope`。
    fn v1_scope_fixture(tmp: &Path, with_cpuacct: bool, with_memory: bool) -> (PathBuf, PathBuf) {
        let proc_root = tmp.join("proc");
        let cg_root = tmp.join("sys/fs/cgroup");
        let my_pid = std::process::id();
        proc_entry(&proc_root, my_pid, my_pid as i64, 7, 3, 128);

        let leader_dir = proc_root.join("4242");
        fs::create_dir_all(&leader_dir).unwrap();

        let scope = cg_root.join("systemd/machine.slice/machine-crbs\\x2dtest\\x2d01.scope");
        fs::create_dir_all(scope.join("system.slice/test.service")).unwrap();
        fs::write(scope.join("cgroup.procs"), "999999\n").unwrap();
        fs::write(
            scope.join("system.slice/test.service/cgroup.procs"),
            format!("{my_pid}\n"),
        )
        .unwrap();

        if with_cpuacct {
            let cpuacct =
                cg_root.join("cpu,cpuacct/machine.slice/machine-crbs\\x2dtest\\x2d01.scope");
            fs::create_dir_all(&cpuacct).unwrap();
            fs::write(cpuacct.join("cpuacct.usage"), "1500000000\n").unwrap();
        }
        if with_memory {
            let mem = cg_root.join("memory/machine.slice/machine-crbs\\x2dtest\\x2d01.scope");
            fs::create_dir_all(&mem).unwrap();
            fs::write(
                mem.join("memory.stat"),
                "cache 100\nrss 4096\ntotal_cache 204800\ntotal_rss 102400\n",
            )
            .unwrap();
        }
        (proc_root, cg_root)
    }

    /// scope 目录名候选：machined 注册形态 `machine-{escaped}.scope` 居首，
    /// 转义形先于原样形，四形态集合与 kill 链路一致。
    #[test]
    fn v1_scope_dir_names_escaped_form_first() {
        let names = v1_scope_dir_names("crbs-test-01");
        assert_eq!(
            names[0], "machine-crbs\\x2dtest\\x2d01.scope",
            "machined 注册形态居首"
        );
        assert_eq!(names[1], "machine-crbs-test-01.scope");
        assert_eq!(names[2], "crbs\\x2dtest\\x2d01.scope");
        assert_eq!(names[3], "crbs-test-01.scope");
    }

    /// v1 scope 归属采集（memory 层级缺位的逐 PID 兜底形态）：嵌套 scope 树跨层
    /// 收齐、RSS 求和、cpuacct.usage 优先、退出竞态 PID 跳过。
    #[test]
    fn sample_v1_scope_tree_collects_nested_scope_and_prefers_cpuacct() {
        let tmp = tempfile::tempdir().unwrap();
        let (proc_root, cg_root) = v1_scope_fixture(tmp.path(), true, false);

        let tick = sample_v1_scope_tree(&proc_root, &cg_root, 4242, "crbs-test-01");
        assert_eq!(
            tick.rss_kb,
            Some(128 * page_size_bytes() / 1024),
            "RSS 只来自嵌套 service 层的本测试进程（根层 pid 不可读，跳过）"
        );
        assert_eq!(tick.backend, Some(SAMPLE_BACKEND_PROC));
        assert!(
            (tick.cpu_secs.unwrap() - 1.5).abs() < 1e-9,
            "cpuacct.usage 优先于逐 PID 求和"
        );
    }

    /// cpuacct 层级缺失 → CPU 退逐 PID utime+stime 求和。
    #[test]
    fn sample_v1_scope_tree_cpu_falls_back_to_per_pid_sum() {
        let tmp = tempfile::tempdir().unwrap();
        let (proc_root, cg_root) = v1_scope_fixture(tmp.path(), false, false);

        let tick = sample_v1_scope_tree(&proc_root, &cg_root, 4242, "crbs-test-01");
        assert_eq!(tick.rss_kb, Some(128 * page_size_bytes() / 1024));
        // (7 + 3) ticks / CLK_TCK=100
        assert!((tick.cpu_secs.unwrap() - 0.1).abs() < 1e-9);
    }

    /// memory.stat `total_rss` 解析：字节 → KB；局部 `rss` 行 / 缺行不顶替；
    /// 文件缺失 → None（调用方退逐 PID 求和）。
    #[test]
    fn read_v1_scope_memory_rss_kb_parses_total_rss() {
        let tmp = tempfile::tempdir().unwrap();
        let scope = tmp
            .path()
            .join("memory/machine.slice/machine-crbs\\x2dtest\\x2d01.scope");
        fs::create_dir_all(&scope).unwrap();
        let names = v1_scope_dir_names("crbs-test-01");

        fs::write(
            scope.join("memory.stat"),
            "cache 100\nrss 4096\ntotal_cache 204800\ntotal_rss 102400\n",
        )
        .unwrap();
        // 102400 字节 → 100 KB；只认层次化 total_rss（局部 rss 行是直属收费页口径）。
        assert_eq!(read_v1_scope_memory_rss_kb(tmp.path(), &names), Some(100));

        fs::write(scope.join("memory.stat"), "cache 100\nrss 4096\n").unwrap();
        assert_eq!(
            read_v1_scope_memory_rss_kb(tmp.path(), &names),
            None,
            "total_rss 行缺失 → None（退逐 PID 兜底），不得拿局部 rss 行凑数"
        );

        fs::remove_file(scope.join("memory.stat")).unwrap();
        assert_eq!(read_v1_scope_memory_rss_kb(tmp.path(), &names), None);
    }

    /// 内存主口径：memory.stat total_rss 在场 → RSS 读 memstat 值（非逐 PID 求和）、
    /// 报 cgroup 口径标签、CPU 仍走 cpuacct。
    #[test]
    fn sample_v1_scope_tree_prefers_memory_stat_total_rss() {
        let tmp = tempfile::tempdir().unwrap();
        let (proc_root, cg_root) = v1_scope_fixture(tmp.path(), true, true);

        let tick = sample_v1_scope_tree(&proc_root, &cg_root, 4242, "crbs-test-01");
        assert_eq!(
            tick.rss_kb,
            Some(100),
            "total_rss = 102400 字节 → 100 KB，与逐 PID 求和的 128 页值不同以钉死来源"
        );
        assert_eq!(tick.backend, Some(SAMPLE_BACKEND_CGROUP));
        assert!((tick.cpu_secs.unwrap() - 1.5).abs() < 1e-9);
    }

    /// total_rss 行缺失 → RSS 退逐 PID /proc 求和并报 proc 口径标签（CPU 不受牵连）。
    #[test]
    fn sample_v1_scope_tree_total_rss_missing_falls_back_to_proc_sum() {
        let tmp = tempfile::tempdir().unwrap();
        let (proc_root, cg_root) = v1_scope_fixture(tmp.path(), true, false);
        // memory 层级在、memory.stat 只有局部行（无 total_rss）。
        let mem = cg_root.join("memory/machine.slice/machine-crbs\\x2dtest\\x2d01.scope");
        fs::create_dir_all(&mem).unwrap();
        fs::write(mem.join("memory.stat"), "cache 100\nrss 4096\n").unwrap();

        let tick = sample_v1_scope_tree(&proc_root, &cg_root, 4242, "crbs-test-01");
        assert_eq!(tick.rss_kb, Some(128 * page_size_bytes() / 1024));
        assert_eq!(tick.backend, Some(SAMPLE_BACKEND_PROC));
        assert!((tick.cpu_secs.unwrap() - 1.5).abs() < 1e-9);
    }

    /// memory.stat 主口径在场而 cpuacct 缺失：RSS 仍读 memstat（不混逐 PID 口径），
    /// CPU 退逐 PID utime+stime。
    #[test]
    fn sample_v1_scope_tree_memory_stat_with_per_pid_cpu_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let (proc_root, cg_root) = v1_scope_fixture(tmp.path(), false, true);

        let tick = sample_v1_scope_tree(&proc_root, &cg_root, 4242, "crbs-test-01");
        assert_eq!(tick.rss_kb, Some(100));
        assert_eq!(tick.backend, Some(SAMPLE_BACKEND_CGROUP));
        // (7 + 3) ticks / CLK_TCK=100
        assert!((tick.cpu_secs.unwrap() - 0.1).abs() < 1e-9);
    }

    /// scope 未显形（machined 注册异步）/ 空树 → 全 None：不产生假峰值也不立 0 基线。
    #[test]
    fn sample_v1_scope_tree_yields_no_data_without_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        let cg_root = tmp.path().join("sys/fs/cgroup");
        fs::create_dir_all(proc_root.join("4242")).unwrap();

        // machine 名给定而 scope 目录未显形（注册竞态）。
        let tick = sample_v1_scope_tree(&proc_root, &cg_root, 4242, "crbs-test-01");
        assert_eq!(tick.rss_kb, None);
        assert_eq!(tick.cpu_secs, None);

        // scope 目录在但空。
        let scope = cg_root.join("systemd/machine.slice/machine-crbs\\x2dtest\\x2d01.scope");
        fs::create_dir_all(&scope).unwrap();
        let tick = sample_v1_scope_tree(&proc_root, &cg_root, 4242, "crbs-test-01");
        assert_eq!(tick.rss_kb, None);
        assert_eq!(tick.cpu_secs, None);

        // cgroup.procs 只有已退出 pid（/proc 读失败）→ 仍无数据。
        fs::write(scope.join("cgroup.procs"), "999999\n").unwrap();
        let tick = sample_v1_scope_tree(&proc_root, &cg_root, 4242, "crbs-test-01");
        assert_eq!(tick.rss_kb, None);
        assert_eq!(tick.cpu_secs, None);
    }

    /// 树根不可读（权限拒绝，非 root 运行前提）→ 降级 pgid 兜底。
    #[test]
    fn sample_v1_scope_tree_falls_back_to_pgid_when_root_unreadable() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let (proc_root, cg_root) = v1_scope_fixture(tmp.path(), false, false);
        // pgid 兜底数据源：领导进程 stat（pgrp == pid）。
        proc_entry(&proc_root, 4242, 4242, 1, 1, 50);

        let scope = cg_root.join("systemd/machine.slice/machine-crbs\\x2dtest\\x2d01.scope");
        std::fs::set_permissions(&scope, std::fs::Permissions::from_mode(0o000)).unwrap();
        let tick = sample_v1_scope_tree(&proc_root, &cg_root, 4242, "crbs-test-01");
        std::fs::set_permissions(&scope, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(
            tick.rss_kb,
            Some(50 * page_size_bytes() / 1024),
            "scope 树不可读 → pgid 匹配集（仅领导进程）"
        );
        assert!((tick.cpu_secs.unwrap() - 0.02).abs() < 1e-9);
    }

    /// v1 scope 归属端到端（run_sampling_loop 直调以注入 cgroupfs 根）：scope 树
    /// 跨层收齐 → peak_rss；cgroup 专属维度恒 None；首 tick 只立基线无增量。
    #[tokio::test]
    async fn v1_scope_loop_attributes_scope_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let (proc_root, cg_root) = v1_scope_fixture(tmp.path(), true, false);
        let state = Arc::new(Mutex::new(SampleState::default()));
        let stop = Arc::new(Notify::new());
        let handle = tokio::spawn(run_sampling_loop(
            SampleTarget {
                child_pid: 4242,
                cgroup_payload: None,
                v1_machine: Some("crbs-test-01".to_string()),
                cgroup_fs_root: cg_root.clone(),
                proc_root: proc_root.clone(),
                tmpfs: None,
            },
            Duration::from_secs(1),
            Arc::clone(&state),
            Arc::clone(&stop),
        ));
        stop.notify_one();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("stop must end the loop")
            .unwrap();

        let usage = aggregate(&mut lock_state(&state));
        assert_eq!(usage.peak_rss_kb, Some(128 * page_size_bytes() / 1024));
        assert!(usage.cpu_secs.is_none(), "首 tick 只有基线无增量");
        assert_eq!(usage.peak_total_kb, None);
        assert_eq!(usage.disk_wbytes, None);
        assert_eq!(usage.oom_killed, None);
    }

    /// v1 归属下 scope 永未显形（machined 未注册）：无样本值、backend 仍 proc、
    /// 不产生假峰值（pgid 兜底会立 Some(0.0) CPU 基线，skip 路径 cpu 恒 None）。
    #[tokio::test]
    async fn v1_scope_loop_without_scope_yields_no_values() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fs::create_dir_all(proc_root.join("4242")).unwrap();

        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        let (handle, stop) = sampler
            .spawn_phase(4242, None, Some("crbs-not-registered"), &proc_root, None)
            .expect("proc interval on");
        stop.notify_one();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("stop must end the loop")
            .unwrap();

        let usage = sampler.finish().expect("backend 标签使聚合非空");
        assert_eq!(usage.sample_backend, Some(SAMPLE_BACKEND_PROC));
        assert_eq!(usage.peak_rss_kb, None);
        assert_eq!(usage.cpu_secs, None);
        assert_eq!(usage.cpu_p90_cores, None);
        assert_eq!(usage.peak_total_kb, None);
        assert_eq!(usage.disk_wbytes, None);
        assert_eq!(usage.oom_killed, None);
    }

    /// v1 归属端到端（memory.stat 主口径）：peak_rss 读 total_rss、backend 升为
    /// cgroup 标签（与 v2 anon 同口径），cgroup 专属维度（memory.peak/io/oom）
    /// 在 v1 无 payload 时恒 None。run_sampling_loop 直调以注入 cgroupfs 根。
    #[tokio::test]
    async fn v1_scope_loop_reports_cgroup_backend_via_memory_stat() {
        let tmp = tempfile::tempdir().unwrap();
        let (proc_root, cg_root) = v1_scope_fixture(tmp.path(), true, true);
        let state = Arc::new(Mutex::new(SampleState::default()));
        let stop = Arc::new(Notify::new());
        let handle = tokio::spawn(run_sampling_loop(
            SampleTarget {
                child_pid: 4242,
                cgroup_payload: None,
                v1_machine: Some("crbs-test-01".to_string()),
                cgroup_fs_root: cg_root,
                proc_root,
                tmpfs: None,
            },
            Duration::from_secs(1),
            Arc::clone(&state),
            Arc::clone(&stop),
        ));
        stop.notify_one();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("stop must end the loop")
            .unwrap();

        let usage = aggregate(&mut lock_state(&state));
        assert_eq!(usage.sample_backend, Some(SAMPLE_BACKEND_CGROUP));
        assert_eq!(usage.peak_rss_kb, Some(100), "total_rss 字节 → KB");
        assert_eq!(usage.peak_total_kb, None);
        assert_eq!(usage.disk_wbytes, None);
        assert_eq!(usage.oom_killed, None);
    }

    /// peak_rss 终值合理性检查：> 0.9×宿主 MemTotal 整值拒收（含 memory.peak 兜底
    /// 路径）、阈值内保留、MemTotal 不可得跳过检查、其他维度不受牵连。
    #[test]
    fn aggregate_rejects_peak_rss_over_host_memtotal() {
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        {
            let mut st = lock_state(&sampler.state);
            st.host_mem_total_kb = Some(1000);
            st.peak_rss_kb = Some(901);
            st.peak_total_kb = Some(5000);
            st.backend = Some(SAMPLE_BACKEND_PROC);
        }
        let usage = sampler.finish().unwrap();
        assert_eq!(
            usage.peak_rss_kb, None,
            "超 MemTotal 90%（901 > 900）整值拒收"
        );
        assert_eq!(usage.peak_total_kb, Some(5000), "只拒 peak_rss 维");
        assert_eq!(usage.sample_backend, Some(SAMPLE_BACKEND_PROC));

        // 阈值边界内保留：0.9×1000 = 900。
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        lock_state(&sampler.state).host_mem_total_kb = Some(1000);
        lock_state(&sampler.state).peak_rss_kb = Some(900);
        assert_eq!(sampler.finish().unwrap().peak_rss_kb, Some(900));

        // memory.peak 兜底路径同受检查；本 fixture 只注入兜底观测（生产构型里
        // spawn 期已带口径记录），拒收后 peak_rss 一列落 NULL。
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        {
            let mut st = lock_state(&sampler.state);
            st.host_mem_total_kb = Some(1000);
            st.mem_peak_kb = Some(901);
        }
        assert!(sampler.finish().is_none());

        // 宿主 MemTotal 不可得（/proc/meminfo 读失败）：跳过检查保留原值。
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        lock_state(&sampler.state).peak_rss_kb = Some(901);
        assert_eq!(sampler.finish().unwrap().peak_rss_kb, Some(901));
    }

    /// 循环端到端合理性检查：fixture /proc 根带 meminfo（MemTotal 1000 KB），逐 PID
    /// 求和峰值超阈值 → 终值拒收落 None（backend 标签仍在，聚合非空）。
    #[tokio::test]
    async fn sampling_loop_sanity_rejects_over_memtotal_peak() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("meminfo"),
            "MemTotal:        1000 kB\nMemFree: 10 kB\n",
        )
        .unwrap();
        // 1024 页 × 页大小（4K/16K 平台均 ≥ 4096 KB）> 900 KB 阈值。
        proc_entry(tmp.path(), 7400, 7400, 0, 0, 1024);
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        let (handle, stop) = sampler
            .spawn_phase(7400, None, None, tmp.path(), None)
            .expect("proc interval on");
        stop.notify_one();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("stop must end the loop")
            .unwrap();

        let usage = sampler.finish().expect("backend 标签使聚合非空");
        assert_eq!(usage.peak_rss_kb, None, "峰值 4096+ KB > 900 KB 阈值，拒收");
        assert_eq!(usage.sample_backend, Some(SAMPLE_BACKEND_PROC));
    }

    /// /proc/meminfo MemTotal 解析：原值 KB 提取；文件缺失 / 行缺失 / 值非法 → None。
    #[test]
    fn read_mem_total_kb_parses_and_tolerates_gaps() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("meminfo"),
            "MemTotal:       16324364 kB\nMemFree:        1000 kB\n",
        )
        .unwrap();
        assert_eq!(read_mem_total_kb(tmp.path()), Some(16_324_364));

        fs::write(tmp.path().join("meminfo"), "MemFree: 1 kB\n").unwrap();
        assert_eq!(read_mem_total_kb(tmp.path()), None);
        assert_eq!(read_mem_total_kb(&tmp.path().join("nonexistent")), None);
    }

    /// cgroup 终态采集的降级矩阵：peak 文件缺失 → peak_total None；oom_kill=0 →
    /// Some(false)（口径可用证据）；io.stat 缺失 → disk_wbytes None；多 phase
    /// 聚合：peak 取最大、wbytes 累加、oom 任一检出即 true。
    #[tokio::test]
    async fn cgroup_tail_degrades_and_merges_across_phases() {
        let tmp = tempfile::tempdir().unwrap();
        proc_entry(tmp.path(), 6300, 6300, 0, 0, 1);
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        // phase 1：peak=100KB、wbytes=10、无 oom_kill 行（不可得）。
        let p1 = tmp.path().join("p1");
        fs::create_dir_all(&p1).unwrap();
        fs::write(p1.join("memory.peak"), format!("{}", 100 * 1024)).unwrap();
        fs::write(p1.join("io.stat"), "8:0 rbytes=1 wbytes=10\n").unwrap();
        let (h1, s1) = sampler
            .spawn_phase(6300, p1.to_str(), None, tmp.path(), None)
            .expect("cgroup on");
        s1.notify_one();
        tokio::time::timeout(Duration::from_secs(2), h1)
            .await
            .unwrap()
            .unwrap();
        // phase 2：peak=60KB（低于 phase 1，max 不回退）、wbytes=5（累加）、oom_kill=0。
        let p2 = tmp.path().join("p2");
        fs::create_dir_all(&p2).unwrap();
        fs::write(p2.join("memory.peak"), format!("{}", 60 * 1024)).unwrap();
        fs::write(p2.join("io.stat"), "8:0 rbytes=1 wbytes=5\n").unwrap();
        fs::write(p2.join("memory.events"), "oom 1\noom_kill 0\n").unwrap();
        let (h2, s2) = sampler
            .spawn_phase(6300, p2.to_str(), None, tmp.path(), None)
            .expect("cgroup on");
        s2.notify_one();
        tokio::time::timeout(Duration::from_secs(2), h2)
            .await
            .unwrap()
            .unwrap();

        let usage = sampler.finish().unwrap();
        assert_eq!(usage.peak_total_kb, Some(100));
        assert_eq!(usage.disk_wbytes, Some(15));
        assert_eq!(usage.oom_killed, Some(false), "读到 0 是口径可用的证据");
    }

    /// 快照句柄与采样器共享同一份状态：引擎把 snapshot 放进槽位后，abort 方
    /// 从 snapshot_slot_resources 读到同一累计值（abort 保样本机制的核心不变量）。
    #[test]
    fn snapshot_slot_shares_state_with_sampler() {
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        let slot = new_resource_snapshot_slot();
        {
            let mut g = match slot.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            *g = Some(sampler.snapshot());
        }
        // 引擎侧累计（模拟采样任务写状态）。
        lock_state(&sampler.state).peak_rss_kb = Some(4321);
        assert_eq!(sampler.finish().unwrap().peak_rss_kb, Some(4321));
        let via_slot = snapshot_slot_resources(&slot).expect("slot snapshot must see samples");
        assert_eq!(via_slot.peak_rss_kb, Some(4321));
        // 空槽位 → None（未进采样阶段）。
        assert_eq!(snapshot_slot_resources(&new_resource_snapshot_slot()), None);
    }

    /// with_sample_ncpu 附加语义：worker 上报层注入，不影响其余字段。
    #[test]
    fn with_sample_ncpu_attaches_worker_cores() {
        let usage = ResourceUsage {
            peak_rss_kb: Some(10),
            ..Default::default()
        }
        .with_sample_ncpu(Some(8));
        assert_eq!(usage.sample_ncpu, Some(8));
        assert_eq!(usage.peak_rss_kb, Some(10));
        assert_eq!(usage.sample_backend, None);
    }

    /// Option 合并辅助的边界：None 吸收、max/saturating_add/OR 语义。
    #[test]
    fn option_merge_helpers() {
        assert_eq!(max_opt(None, None), None);
        assert_eq!(max_opt(Some(3), None), Some(3));
        assert_eq!(max_opt(Some(3), Some(7)), Some(7));
        assert_eq!(add_opt(None, None), None);
        assert_eq!(add_opt(Some(2), Some(3)), Some(5));
        assert_eq!(add_opt(None, Some(3)), Some(3));
        assert_eq!(or_opt(None, None), None);
        assert_eq!(or_opt(Some(false), Some(true)), Some(true));
        assert_eq!(or_opt(Some(true), None), Some(true));
        assert_eq!(or_opt(None, Some(false)), Some(false));
        assert_eq!(or_opt(Some(false), Some(false)), Some(false));
    }

    #[test]
    fn zero_interval_disables_sampler() {
        assert!(ResourceSampler::from_intervals(0, Some(0)).is_none());
    }

    #[test]
    fn finish_is_none_without_samples() {
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        assert!(sampler.finish().is_none());
    }

    #[test]
    fn percentile_edges() {
        assert_eq!(percentile(&[], 0.9), None);
        assert!((percentile(&[7.0], 0.9).unwrap() - 7.0).abs() < 1e-9);
        // n=3, p=0.9 → ceil(2.7)=3 → 第 3 位
        assert!((percentile(&[1.0, 2.0, 3.0], 0.9).unwrap() - 3.0).abs() < 1e-9);
    }

    /// statfs 读取器真读：/dev/shm 在 systemd Linux 恒为 tmpfs（dev tmpfs 挂载），
    /// tempdir 建在其内即"tempdir tmpfs 上真读"。共享实例上其他消费者（含并行
    /// 测试）并发变动，不比先后读数——预置 4 MiB 文件在测量期间存续，读数 ≥
    /// 4096 KB 是确定下界，证明 used = (blocks−bfree)×frsize 计算通路真实生效。
    #[test]
    fn read_tmpfs_used_kb_reads_tmpfs_tempdir() {
        let Ok(tmp) = tempfile::tempdir_in("/dev/shm") else {
            // 无 /dev/shm 的极简环境：真读面由下方 /proc 拒绝与不存在路径覆盖。
            return;
        };
        std::fs::write(tmp.path().join("payload.bin"), vec![0u8; 4 * 1024 * 1024]).unwrap();
        let used = read_tmpfs_used_kb(tmp.path()).expect("/dev/shm must be tmpfs on Linux");
        assert!(
            used >= 4 * 1024,
            "4 MiB 预置文件在测量期间存续，读数必须 ≥ 4096 KB: {used}"
        );
    }

    /// statfs 读取器拒绝面：非 tmpfs（/proc 恒为 procfs）、不存在路径（读失败）
    /// 一律 None——f_type 校验是 umount 后挂载点误采的唯一防线。
    #[test]
    fn read_tmpfs_used_kb_rejects_non_tmpfs_and_missing_path() {
        assert_eq!(
            read_tmpfs_used_kb(Path::new("/proc")),
            None,
            "procfs 不是 tmpfs，必须拒采"
        );
        assert_eq!(
            read_tmpfs_used_kb(Path::new("/crbs-nonexistent-tmpfs-probe")),
            None
        );
    }

    /// statfs 字段归一：无符号（常见架构）与有符号（sw_64）都收敛到 u64；
    /// 负值属异常，降级 None。
    #[test]
    fn statfs_word_u64_normalizes_signed_and_unsigned_fields() {
        assert_eq!(statfs_word_u64(4_096u64), Some(4_096));
        assert_eq!(statfs_word_u64(4_096i64), Some(4_096));
        assert_eq!(statfs_word_u64(0i64), Some(0));
        assert_eq!(statfs_word_u64(-1i64), None);
    }

    /// 观测目标读数语义（真 tmpfs 路径）：专属挂载点产出非负绝对读数；非
    /// tmpfs 路径拒采（该 tick 缺值，峰值不回退）。
    #[test]
    fn tmpfs_watch_sample_kb_semantics() {
        let Ok(tmp) = tempfile::tempdir_in("/dev/shm") else {
            return;
        };
        let watch = TmpfsWatch {
            path: tmp.path().to_path_buf(),
        };
        assert!(
            watch.sample_kb().unwrap_or(-1) >= 0,
            "专属挂载点产出绝对用量读数"
        );

        // 非 tmpfs 路径：读数 None（该 tick 不产生 tmpfs 值）。
        let proc_watch = TmpfsWatch {
            path: PathBuf::from("/proc"),
        };
        assert_eq!(proc_watch.sample_kb(), None);
    }

    /// 峰值累计器语义：各 tick 取 max（低值不回退）、None 穿透（无观测目标 /
    /// 全 tick 不可得 → 该维度 None，不吞其他维度的非空）。
    #[test]
    fn tmpfs_peak_takes_tick_max_and_none_passthrough() {
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        {
            let mut st = lock_state(&sampler.state);
            st.peak_tmpfs_kb = Some(300);
        }
        assert_eq!(sampler.finish().unwrap().peak_tmpfs_kb, Some(300));
        {
            // 低于既有峰值的 tick：max 不回退。
            let mut st = lock_state(&sampler.state);
            st.peak_tmpfs_kb = st.peak_tmpfs_kb.max(Some(120));
        }
        assert_eq!(sampler.finish().unwrap().peak_tmpfs_kb, Some(300));

        // None 穿透：内存有值而 tmpfs 无观测 → peak_tmpfs_kb 保持 None。
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        lock_state(&sampler.state).peak_rss_kb = Some(1);
        let usage = sampler.finish().unwrap();
        assert_eq!(usage.peak_tmpfs_kb, None);
    }

    /// 采样循环端到端（真实 tmpfs 观测目标）：BUILD 形态 watch 指向 /dev/shm 内
    /// tempdir，预置 8 MiB 文件后任意 tick 的读数 ≥ 8192 KB，峰值由此下界钉住
    /// 管道（spawn_phase → SampleTarget → tick → 状态累计）真实贯通。
    #[tokio::test]
    async fn sampling_loop_accumulates_tmpfs_peak_via_watch() {
        let Ok(shm) = tempfile::tempdir_in("/dev/shm") else {
            return;
        };
        std::fs::write(shm.path().join("big.bin"), vec![0u8; 8 * 1024 * 1024]).unwrap();

        proc_entry(shm.path(), 7200, 7200, 0, 0, 1);
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        let watch = TmpfsWatch {
            path: shm.path().to_path_buf(),
        };
        let (handle, stop) = sampler
            .spawn_phase(7200, None, None, shm.path(), Some(&watch))
            .expect("proc interval on");
        stop.notify_one();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("stop must end the loop")
            .unwrap();

        let usage = sampler.finish().expect("rss+tmpfs samples collected");
        // 共享实例上其他消费者并发变动，不钉具体值：预置 8 MiB 后任意 tick 读数
        // ≥ 8192 KB（本测试自身的写入只增不减，是读数的确定下界），峰值非 None
        // 即证明 spawn_phase → SampleTarget → tick → 状态累计管道贯通。
        assert!(
            usage.peak_tmpfs_kb.unwrap_or(0) >= 8 * 1024,
            "tmpfs 峰值必须 ≥ 预置文件体积: {:?}",
            usage.peak_tmpfs_kb
        );
        assert_eq!(usage.peak_rss_kb, Some(page_size_bytes() / 1024));
    }

    /// 非 tmpfs 观测目标（/proc）在循环内逐 tick 拒采：峰值保持 None，内存口径
    /// 不受牵连——f_type 校验的循环级回归。
    #[tokio::test]
    async fn sampling_loop_rejects_non_tmpfs_watch() {
        let tmp = tempfile::tempdir().unwrap();
        proc_entry(tmp.path(), 7300, 7300, 0, 0, 64);
        let sampler = ResourceSampler::from_intervals(1, None).unwrap();
        let watch = TmpfsWatch {
            path: PathBuf::from("/proc"),
        };
        let (handle, stop) = sampler
            .spawn_phase(7300, None, None, tmp.path(), Some(&watch))
            .expect("proc interval on");
        stop.notify_one();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("stop must end the loop")
            .unwrap();

        let usage = sampler.finish().expect("proc samples collected");
        assert_eq!(usage.peak_tmpfs_kb, None, "非 tmpfs 观测不得产出峰值");
        assert_eq!(usage.peak_rss_kb, Some(64 * page_size_bytes() / 1024));
    }
}
