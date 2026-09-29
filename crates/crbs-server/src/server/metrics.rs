// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 进程级 metrics counter 基建：AppState 挂
//! `AtomicU64` 计数组，调度/学习路径 method 化自增；抓取时并入
//! [`crate::server::routes::health::MetricsSnapshot`] 渲染 `# TYPE ... counter`，
//! JSON `/api/v1/metrics` 镜像。重启清零由 Prometheus rate() 容忍。
//!
//! label 只有编译期枚举（无用户输入、无转义面）：每个维度一个 ALL 常量，
//! 渲染按全集补零——缺数据 / 查询失败不收缩 label 集，抓取端按 label 做
//! 率值才有稳定向量（沿用 `ALL_VERDICTS` 既有模式）。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// `crbs_build_oom_total` 的 kind 维度全集（渲染/JSON 补零与 label 集恒定的唯一来源）。
pub const ALL_OOM_KINDS: [BuildOomKind; 3] =
    [BuildOomKind::Cap, BuildOomKind::Node, BuildOomKind::Unknown];

/// `crbs_profile_updates_total` 的 outcome 维度全集。
pub const ALL_PROFILE_UPDATES: [ProfileUpdateKind; 4] = [
    ProfileUpdateKind::Learned,
    ProfileUpdateKind::Censored,
    ProfileUpdateKind::CapHitExcluded,
    ProfileUpdateKind::Reset,
];

/// `crbs_dispatch_admit_rejects_total` 的 dimension 维度全集（调度派发路径；
/// arch/capacity 细分留在归因内存态，指标只留 no_fit 一个粗粒度）。
pub const ALL_DISPATCH_REJECTS: [DispatchRejectDimension; 7] = [
    DispatchRejectDimension::Mem,
    DispatchRejectDimension::Ncpu,
    DispatchRejectDimension::Disk,
    DispatchRejectDimension::WatermarkMem,
    DispatchRejectDimension::WatermarkCpu,
    DispatchRejectDimension::WatermarkTmpfs,
    DispatchRejectDimension::NoFit,
];

/// OOM 分类 kind（终态上报路径判定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildOomKind {
    /// 撞任务自身 memory_max 上限（用户配置问题，不进删失学习）。
    Cap,
    /// 节点容量截断（failed 终态 + oom_kill 检出，进删失学习）。
    Node,
    /// OOM 检出但 cap 判定输入缺失（peak 与声明皆不可得），不学习。
    Unknown,
}

impl BuildOomKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BuildOomKind::Cap => "cap",
            BuildOomKind::Node => "node",
            BuildOomKind::Unknown => "unknown",
        }
    }
}

/// 画像更新 outcome（学习写入接线按 [`crbs_core::ProfileUpdateDecision`] 计数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileUpdateKind {
    /// succeeded 样本折叠进 EMA。
    Learned,
    /// node-OOM 删失抬升 max。
    Censored,
    /// cap-OOM 排除（限额非需求）。
    CapHitExcluded,
    /// proc→cgroup 升级清零重起算。
    Reset,
}

impl ProfileUpdateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProfileUpdateKind::Learned => "learned",
            ProfileUpdateKind::Censored => "censored",
            ProfileUpdateKind::CapHitExcluded => "cap_hit_excluded",
            ProfileUpdateKind::Reset => "reset",
        }
    }
}

/// 派发准入拒绝维度（planner 决策路径；硬下限三维来自 eligible 过滤的
/// fail-closed 判定，水位两维来自准入门单维判定，watermark_tmpfs 来自学习
/// tmpfs 门转正（resource_tmpfs_gate_enforced），no_fit = 架构/容量/init 门
/// 聚合）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchRejectDimension {
    /// 硬下限-内存（worker mem_total 不足或遥测缺失）。
    Mem,
    /// 硬下限-核数（worker ncpu 不足或遥测缺失）。
    Ncpu,
    /// 硬下限-磁盘（worker disk_free 不足或未上报）。
    Disk,
    /// 内存水位（`used + Σ权重 ≥ mem_total × 90%`）。
    WatermarkMem,
    /// CPU 水位（`load1 + Σp90 ≥ ncpu × 水位系数`）。
    WatermarkCpu,
    /// 学习 tmpfs 门转正拒绝（节点 tmpfs 容量 < 学习峰值；开关默认关）。
    WatermarkTmpfs,
    /// 无合格节点（架构不匹配 / 容量满 / init 门聚合）。
    NoFit,
}

impl DispatchRejectDimension {
    pub fn as_str(self) -> &'static str {
        match self {
            DispatchRejectDimension::Mem => "mem",
            DispatchRejectDimension::Ncpu => "ncpu",
            DispatchRejectDimension::Disk => "disk",
            DispatchRejectDimension::WatermarkMem => "watermark_mem",
            DispatchRejectDimension::WatermarkCpu => "watermark_cpu",
            DispatchRejectDimension::WatermarkTmpfs => "watermark_tmpfs",
            DispatchRejectDimension::NoFit => "no_fit",
        }
    }
}

/// 进程级计数器组：字段显式展开（AtomicU64 数组 + 索引换可读性差，规模
/// 个位数不值得宏）；快照走 [`Self::snapshot`] 输出 label → 计数全量映射。
#[derive(Default)]
pub struct MetricsCounters {
    build_oom_cap: AtomicU64,
    build_oom_node: AtomicU64,
    build_oom_unknown: AtomicU64,
    profile_learned: AtomicU64,
    profile_censored: AtomicU64,
    profile_cap_hit_excluded: AtomicU64,
    profile_reset: AtomicU64,
    // ===== dispatch 系 =====
    dispatch_reject_hard_mem: AtomicU64,
    dispatch_reject_hard_ncpu: AtomicU64,
    dispatch_reject_hard_disk: AtomicU64,
    dispatch_reject_watermark_mem: AtomicU64,
    dispatch_reject_watermark_cpu: AtomicU64,
    dispatch_reject_watermark_tmpfs: AtomicU64,
    dispatch_reject_no_fit: AtomicU64,
    dispatch_no_candidate_ticks: AtomicU64,
    dispatch_assigned: AtomicU64,
    dispatch_soft_fallbacks: AtomicU64,
    /// 最近 tick 耗时（毫秒；gauge，last/max 两值分开存——Prometheus 单值
    /// gauge 渲染为两个指标名）。
    dispatch_tick_last_ms: AtomicU64,
    dispatch_tick_max_ms: AtomicU64,
}

impl MetricsCounters {
    pub fn incr_build_oom(&self, kind: BuildOomKind) {
        let cell = match kind {
            BuildOomKind::Cap => &self.build_oom_cap,
            BuildOomKind::Node => &self.build_oom_node,
            BuildOomKind::Unknown => &self.build_oom_unknown,
        };
        cell.fetch_add(1, Ordering::Relaxed);
    }

    pub fn incr_profile_update(&self, outcome: ProfileUpdateKind) {
        let cell = match outcome {
            ProfileUpdateKind::Learned => &self.profile_learned,
            ProfileUpdateKind::Censored => &self.profile_censored,
            ProfileUpdateKind::CapHitExcluded => &self.profile_cap_hit_excluded,
            ProfileUpdateKind::Reset => &self.profile_reset,
        };
        cell.fetch_add(1, Ordering::Relaxed);
    }

    /// kind → 计数（快照/渲染/测试共用；Counter 侧无缺数据概念，补零由渲染
    /// 按 ALL 全集兜底）。
    pub fn build_oom_total(&self, kind: BuildOomKind) -> u64 {
        let cell = match kind {
            BuildOomKind::Cap => &self.build_oom_cap,
            BuildOomKind::Node => &self.build_oom_node,
            BuildOomKind::Unknown => &self.build_oom_unknown,
        };
        cell.load(Ordering::Relaxed)
    }

    pub fn profile_updates_total(&self, outcome: ProfileUpdateKind) -> u64 {
        let cell = match outcome {
            ProfileUpdateKind::Learned => &self.profile_learned,
            ProfileUpdateKind::Censored => &self.profile_censored,
            ProfileUpdateKind::CapHitExcluded => &self.profile_cap_hit_excluded,
            ProfileUpdateKind::Reset => &self.profile_reset,
        };
        cell.load(Ordering::Relaxed)
    }

    /// 全量快照（label 全集，含零值）：JSON 镜像与 Prometheus 渲染同源。
    pub fn build_oom_snapshot(&self) -> BTreeMap<&'static str, u64> {
        ALL_OOM_KINDS
            .iter()
            .map(|k| (k.as_str(), self.build_oom_total(*k)))
            .collect()
    }

    pub fn profile_updates_snapshot(&self) -> BTreeMap<&'static str, u64> {
        ALL_PROFILE_UPDATES
            .iter()
            .map(|k| (k.as_str(), self.profile_updates_total(*k)))
            .collect()
    }

    // ===== dispatch 系 =====

    pub fn incr_dispatch_admit_reject(&self, dimension: DispatchRejectDimension) {
        let cell = match dimension {
            DispatchRejectDimension::Mem => &self.dispatch_reject_hard_mem,
            DispatchRejectDimension::Ncpu => &self.dispatch_reject_hard_ncpu,
            DispatchRejectDimension::Disk => &self.dispatch_reject_hard_disk,
            DispatchRejectDimension::WatermarkMem => &self.dispatch_reject_watermark_mem,
            DispatchRejectDimension::WatermarkCpu => &self.dispatch_reject_watermark_cpu,
            DispatchRejectDimension::WatermarkTmpfs => &self.dispatch_reject_watermark_tmpfs,
            DispatchRejectDimension::NoFit => &self.dispatch_reject_no_fit,
        };
        cell.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dispatch_admit_rejects_total(&self, dimension: DispatchRejectDimension) -> u64 {
        let cell = match dimension {
            DispatchRejectDimension::Mem => &self.dispatch_reject_hard_mem,
            DispatchRejectDimension::Ncpu => &self.dispatch_reject_hard_ncpu,
            DispatchRejectDimension::Disk => &self.dispatch_reject_hard_disk,
            DispatchRejectDimension::WatermarkMem => &self.dispatch_reject_watermark_mem,
            DispatchRejectDimension::WatermarkCpu => &self.dispatch_reject_watermark_cpu,
            DispatchRejectDimension::WatermarkTmpfs => &self.dispatch_reject_watermark_tmpfs,
            DispatchRejectDimension::NoFit => &self.dispatch_reject_no_fit,
        };
        cell.load(Ordering::Relaxed)
    }

    /// 有空槽有 pending 但零派发的 tick。
    pub fn incr_no_candidate_ticks(&self) {
        self.dispatch_no_candidate_ticks
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn no_candidate_ticks_total(&self) -> u64 {
        self.dispatch_no_candidate_ticks.load(Ordering::Relaxed)
    }

    /// 实际派发成功数。
    pub fn incr_dispatch_assigned(&self) {
        self.dispatch_assigned.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dispatch_assigned_total(&self) -> u64 {
        self.dispatch_assigned.load(Ordering::Relaxed)
    }

    /// censored 超龄兜底（实际派发才计数）。
    pub fn incr_soft_fallbacks(&self) {
        self.dispatch_soft_fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn soft_fallbacks_total(&self) -> u64 {
        self.dispatch_soft_fallbacks.load(Ordering::Relaxed)
    }

    /// 记录一次调度 tick 耗时（毫秒，gauge）：last 覆写、max 单调抬升。
    pub fn record_dispatch_tick_ms(&self, ms: u64) {
        self.dispatch_tick_last_ms.store(ms, Ordering::Relaxed);
        self.dispatch_tick_max_ms.fetch_max(ms, Ordering::Relaxed);
    }

    /// (last_ms, max_ms)。
    pub fn dispatch_tick_ms(&self) -> (u64, u64) {
        (
            self.dispatch_tick_last_ms.load(Ordering::Relaxed),
            self.dispatch_tick_max_ms.load(Ordering::Relaxed),
        )
    }

    pub fn dispatch_admit_rejects_snapshot(&self) -> BTreeMap<&'static str, u64> {
        ALL_DISPATCH_REJECTS
            .iter()
            .map(|k| (k.as_str(), self.dispatch_admit_rejects_total(*k)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 自增与快照：label 全集恒定、零值补齐、互不串位。
    #[test]
    fn counters_increment_and_snapshot_cover_all_labels() {
        let c = MetricsCounters::default();
        // 初始全零，label 全集补齐。
        let snap = c.build_oom_snapshot();
        assert_eq!(snap.len(), ALL_OOM_KINDS.len());
        assert!(snap.values().all(|v| *v == 0));

        c.incr_build_oom(BuildOomKind::Cap);
        c.incr_build_oom(BuildOomKind::Cap);
        c.incr_build_oom(BuildOomKind::Node);
        assert_eq!(c.build_oom_total(BuildOomKind::Cap), 2);
        assert_eq!(c.build_oom_total(BuildOomKind::Node), 1);
        assert_eq!(c.build_oom_total(BuildOomKind::Unknown), 0);
        let snap = c.build_oom_snapshot();
        assert_eq!(snap.get("cap"), Some(&2));
        assert_eq!(snap.get("node"), Some(&1));
        assert_eq!(snap.get("unknown"), Some(&0));

        c.incr_profile_update(ProfileUpdateKind::Learned);
        c.incr_profile_update(ProfileUpdateKind::Reset);
        assert_eq!(c.profile_updates_total(ProfileUpdateKind::Learned), 1);
        assert_eq!(c.profile_updates_total(ProfileUpdateKind::Reset), 1);
        assert_eq!(c.profile_updates_total(ProfileUpdateKind::Censored), 0);
        let snap = c.profile_updates_snapshot();
        assert_eq!(snap.len(), ALL_PROFILE_UPDATES.len());
        assert_eq!(snap.get("learned"), Some(&1));
        assert_eq!(snap.get("censored"), Some(&0));
        assert_eq!(snap.get("cap_hit_excluded"), Some(&0));
        assert_eq!(snap.get("reset"), Some(&1));
    }

    /// dispatch 系计数与 tick gauge（last 覆写 / max 单调抬升）。
    #[test]
    fn dispatch_counters_and_tick_gauge() {
        let c = MetricsCounters::default();
        let snap = c.dispatch_admit_rejects_snapshot();
        assert_eq!(snap.len(), ALL_DISPATCH_REJECTS.len());
        assert!(snap.values().all(|v| *v == 0));

        c.incr_dispatch_admit_reject(DispatchRejectDimension::Mem);
        c.incr_dispatch_admit_reject(DispatchRejectDimension::WatermarkMem);
        c.incr_dispatch_admit_reject(DispatchRejectDimension::WatermarkMem);
        c.incr_dispatch_admit_reject(DispatchRejectDimension::WatermarkCpu);
        c.incr_dispatch_admit_reject(DispatchRejectDimension::NoFit);
        assert_eq!(
            c.dispatch_admit_rejects_total(DispatchRejectDimension::WatermarkMem),
            2
        );
        assert_eq!(c.dispatch_admit_rejects_snapshot().get("no_fit"), Some(&1));

        c.incr_no_candidate_ticks();
        c.incr_dispatch_assigned();
        c.incr_dispatch_assigned();
        c.incr_soft_fallbacks();
        assert_eq!(c.no_candidate_ticks_total(), 1);
        assert_eq!(c.dispatch_assigned_total(), 2);
        assert_eq!(c.soft_fallbacks_total(), 1);

        c.record_dispatch_tick_ms(5);
        c.record_dispatch_tick_ms(12);
        c.record_dispatch_tick_ms(3);
        assert_eq!(
            c.dispatch_tick_ms(),
            (3, 12),
            "last overwrites, max ratchets"
        );
    }

    /// label 字面量冻结（Prometheus 抓取端与看板按字符串匹配，漂移即断链）。
    #[test]
    fn label_strings_are_frozen() {
        assert_eq!(
            ALL_OOM_KINDS.map(|k| k.as_str()),
            ["cap", "node", "unknown"]
        );
        assert_eq!(
            ALL_PROFILE_UPDATES.map(|k| k.as_str()),
            ["learned", "censored", "cap_hit_excluded", "reset"]
        );
        assert_eq!(
            ALL_DISPATCH_REJECTS.map(|k| k.as_str()),
            [
                "mem",
                "ncpu",
                "disk",
                "watermark_mem",
                "watermark_cpu",
                "watermark_tmpfs",
                "no_fit"
            ]
        );
    }
}
