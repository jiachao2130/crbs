// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 单候选决策纯函数：架构/容量/init/硬下限过滤、水位门与 censored 兜底。

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use crbs_core::{DispatchCandidate, WorkerStatus};

use super::super::{
    watermark_reject_dimension, AdmitWatermarks, CommittedLoad, ResolvedResourceProfile,
    WatermarkDimension,
};
use super::learned_gates::{tmpfs_gate_outcome, GateOutcome};
use super::{RejectReason, LAST_RESORT_AFTER_SECS};
use crate::server::metrics::DispatchRejectDimension;

/// planner 单候选决策（四出口）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum PlannerDecision {
    /// least-loaded 序首个合格节点正常派发。
    Dispatch { worker_id: i64 },
    /// censored 超龄兜底：eligible 中 headroom 最大节点。
    SoftFallback { worker_id: i64 },
    /// 无合格节点（附归因细类）。
    NoFit { reason: RejectReason },
    /// 水位阻塞（附触发维度；非 censored 或未超龄）。`head_load` = 遍历序
    /// 首节点上的生效折算压载（在跑 Σ + 候选自身，按该节点核数折算），
    /// 归因随行供 UI 展示水位占用。
    WatermarkBlocked {
        dimension: crate::server::scheduler::WatermarkDimension,
        head_load: CommittedLoad,
    },
}

/// 候选架构匹配（纯函数，镜像分布式 pick 的 claim 谓词）：精确 arch 命中；
/// noarch 行 host_arches IS NULL = 不限制、非 NULL = CSV 成员判定；NULL-arch
/// 行不参与（分布式 pick 谓词不命中 NULL 行，仅本地路径实际领取）。
pub(super) fn candidate_arch_matches(candidate: &DispatchCandidate, worker_arch: &str) -> bool {
    match candidate.arch.as_deref() {
        Some(a) if a == worker_arch => true,
        Some("noarch") => match candidate.host_arches.as_deref() {
            None => true,
            Some(csv) => csv.split(',').any(|s| s == worker_arch),
        },
        _ => false,
    }
}

/// steering 规范化余量评分（纯函数）：mem 维 `(total×水位系数 − used − Σmem)/total`、
/// cpu 维 `(ncpu − load1 − Σcpu)/ncpu`，节点得分 = 两维 min（瓶颈维归一）。
/// 规范化消除绝对偏大——60% 满的大节点不再赢过比例更空的小节点。某维遥测
/// 缺失该维不参与（与准入门失败时放行同向）；两维全缺 = `None`（不冒充最宽裕）。
pub(super) fn normalized_headroom_score(
    worker: &WorkerStatus,
    load: CommittedLoad,
    watermarks: AdmitWatermarks,
) -> Option<f64> {
    let mem = match (worker.mem_total_kb, worker.mem_used_pct) {
        (Some(total_kb), Some(used_pct)) => {
            let total_kb = total_kb as f64;
            Some((total_kb * watermarks.mem - total_kb * used_pct / 100.0 - load.mem_kb) / total_kb)
        }
        _ => None,
    };
    let cpu = match (worker.load1, worker.ncpu) {
        (Some(load1), Some(ncpu)) if ncpu > 0 => {
            Some((ncpu as f64 - load1 - load.cpu_cores) / ncpu as f64)
        }
        _ => None,
    };
    match (mem, cpu) {
        (Some(m), Some(c)) => Some(m.min(c)),
        (m, c) => m.or(c),
    }
}

/// steering 全序（规范化余量评分降序）：有分节点排无分节点前——缺遥测节点
/// 的名义余量不冒充"最宽裕"；并列与无分节点保持传入序（eligible 是
/// least-loaded 序，序首 tie-break 确定）；全组无分 = 传入序原样（退化为
/// 序首，失败时放行方向：有节点可派就派）。censored 软兜底与 heavy steering
/// 共用本序。
pub(super) fn steering_order<'a>(
    eligible: &[&'a WorkerStatus],
    committed: &HashMap<i64, CommittedLoad>,
    watermarks: AdmitWatermarks,
) -> Vec<&'a WorkerStatus> {
    let mut scored: Vec<(&'a WorkerStatus, Option<f64>)> = eligible
        .iter()
        .map(|&w| {
            let load = committed.get(&w.id).copied().unwrap_or_default();
            (w, normalized_headroom_score(w, load, watermarks))
        })
        .collect();
    scored.sort_by(|a, b| match (a.1, b.1) {
        (Some(sa), Some(sb)) => sb.total_cmp(&sa),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    scored.into_iter().map(|(w, _)| w).collect()
}

/// 兜底超龄判定（纯函数）：`None`（尚无水位全拒记录）= 未超龄。
pub(super) fn fallback_expired(first_watermark_reject_age: Option<Duration>) -> bool {
    first_watermark_reject_age.is_some_and(|age| age >= Duration::from_secs(LAST_RESORT_AFTER_SECS))
}

/// 硬下限单维（归因/指标 label 的最小粒度，label 值 `mem|ncpu|disk`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HardReqDimension {
    Mem,
    Ncpu,
    Disk,
}

impl HardReqDimension {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            HardReqDimension::Mem => "mem",
            HardReqDimension::Ncpu => "ncpu",
            HardReqDimension::Disk => "disk",
        }
    }
}

/// 硬下限解析结果（逐维：builds.req_* 任务显式 > declared 声明
///（精确 arch → 'any'）> 无）。`resource_requirements_enabled=false` 时由
/// 调用方置默认值（全 None = 整段过滤跳过）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EffectiveHardReq {
    pub min_mem_kb: Option<i64>,
    pub min_ncpu: Option<i64>,
    pub min_disk_kb: Option<i64>,
}

impl EffectiveHardReq {
    pub(crate) fn has_any(&self) -> bool {
        self.min_mem_kb.is_some() || self.min_ncpu.is_some() || self.min_disk_kb.is_some()
    }

    /// 首个有声明维（mem → ncpu → disk 固定序；全无声明时不可达）。
    pub(crate) fn first_dimension(&self) -> HardReqDimension {
        if self.min_mem_kb.is_some() {
            HardReqDimension::Mem
        } else if self.min_ncpu.is_some() {
            HardReqDimension::Ncpu
        } else {
            HardReqDimension::Disk
        }
    }
}

/// worker 可承载性判定（纯函数，失败即拒绝）：逐维独立，要求维遥测
/// 缺失 = 不可承载（声明是契约；与水位门的失败时放行有意分叉）。满足返回
/// `None`，拒则给出首个不满足维。
pub(crate) fn worker_satisfies_hard_req(
    worker: &WorkerStatus,
    req: &EffectiveHardReq,
) -> Option<HardReqDimension> {
    if let Some(min) = req.min_mem_kb {
        match worker.mem_total_kb {
            Some(total) if total >= min => {}
            _ => return Some(HardReqDimension::Mem),
        }
    }
    if let Some(min) = req.min_ncpu {
        match worker.ncpu {
            Some(n) if n >= min => {}
            _ => return Some(HardReqDimension::Ncpu),
        }
    }
    if let Some(min) = req.min_disk_kb {
        match worker.disk_free_kb {
            Some(free) if free >= min => {}
            _ => return Some(HardReqDimension::Disk),
        }
    }
    None
}

/// [`decide_candidate`] 的决策输入快照（字段均无隐式依赖、无状态）。
pub(crate) struct DecideCandidateInput<'a> {
    pub candidate: &'a DispatchCandidate,
    pub profile: ResolvedResourceProfile,
    pub hard_req: EffectiveHardReq,
    /// 必须已按派发序排序（eligible 保持该序；非 heavy 按此序逐节点验门）。
    pub workers: &'a [WorkerStatus],
    pub active: &'a HashMap<i64, i64>,
    pub committed: &'a HashMap<i64, CommittedLoad>,
    pub init_by_worker: &'a HashMap<i64, HashSet<String>>,
    pub first_watermark_reject_age: Option<Duration>,
    /// heavy 判定结果（steering 开关关时恒 false，决策路径与序首路径逐位一致）。
    pub steer_heavy: bool,
    /// 分布式水位门总闸：false 时跳过第 6/7 步（放置序选中的节点直接派发）。
    pub watermark_enabled: bool,
    /// 准入水位系数运行值（server.toml，加载期校验 >0）。
    pub watermarks: AdmitWatermarks,
    /// 学习 tmpfs 门转正开关：true 时第 6 步逐节点水位通过后追加 tmpfs 门
    ///（[`tmpfs_gate_outcome`] 同口径），拒绝进顺延、归因 `Tmpfs` 维。
    pub tmpfs_gate_enforced: bool,
}

/// 单候选决策（纯函数）：架构/空槽/init 门/硬下限四级 eligible 过滤 + 候选
/// 权重进门的水位判定 + censored 超龄兜底。
pub(crate) fn decide_candidate(input: DecideCandidateInput<'_>) -> PlannerDecision {
    let DecideCandidateInput {
        candidate,
        profile,
        hard_req,
        workers,
        active,
        committed,
        init_by_worker,
        first_watermark_reject_age,
        steer_heavy,
        watermark_enabled,
        watermarks,
        tmpfs_gate_enforced,
    } = input;
    let arch_ok: Vec<&WorkerStatus> = workers
        .iter()
        .filter(|w| candidate_arch_matches(candidate, &w.arch))
        .collect();
    if arch_ok.is_empty() {
        return PlannerDecision::NoFit {
            reason: RejectReason::NoFitArch,
        };
    }
    let capacity_ok: Vec<&WorkerStatus> = arch_ok
        .into_iter()
        .filter(|w| active.get(&w.id).copied().unwrap_or(0) < w.capacity)
        .collect();
    if capacity_ok.is_empty() {
        return PlannerDecision::NoFit {
            reason: RejectReason::NoFitCapacity,
        };
    }
    let init_ok: Vec<&WorkerStatus> = capacity_ok
        .into_iter()
        .filter(|w| {
            init_by_worker
                .get(&w.id)
                .is_none_or(|products| !products.contains(&candidate.product))
        })
        .collect();
    if init_ok.is_empty() {
        return PlannerDecision::NoFit {
            reason: RejectReason::InitGated,
        };
    }

    let eligible: Vec<&WorkerStatus> = if hard_req.has_any() {
        let mut first_blocked: Option<HardReqDimension> = None;
        let kept: Vec<&WorkerStatus> = init_ok
            .into_iter()
            .filter(|w| match worker_satisfies_hard_req(w, &hard_req) {
                None => true,
                Some(dim) => {
                    first_blocked.get_or_insert(dim);
                    false
                }
            })
            .collect();
        if kept.is_empty() {
            return PlannerDecision::NoFit {
                reason: RejectReason::NoFitHardReq {
                    dimension: first_blocked.unwrap_or(HardReqDimension::Mem),
                },
            };
        }
        kept
    } else {
        init_ok
    };

    let order: Vec<&WorkerStatus> = if steer_heavy {
        steering_order(&eligible, committed, watermarks)
    } else {
        eligible.to_vec()
    };
    if !watermark_enabled {
        return PlannerDecision::Dispatch {
            worker_id: order[0].id,
        };
    }
    let mut head_reject: Option<(WatermarkDimension, CommittedLoad)> = None;
    for w in order {
        let load = committed
            .get(&w.id)
            .copied()
            .unwrap_or_default()
            .plus(&profile.weight, w.ncpu);
        match watermark_reject_dimension(w, load, watermarks) {
            None => {}
            Some(dimension) => {
                if head_reject.is_none() {
                    head_reject = Some((dimension, load));
                }
                continue;
            }
        }
        if tmpfs_gate_enforced
            && profile.gate_learned
            && tmpfs_gate_outcome(profile.gate_max_tmpfs_kb, w.mem_total_kb) == GateOutcome::Reject
        {
            if head_reject.is_none() {
                head_reject = Some((WatermarkDimension::Tmpfs, load));
            }
            continue;
        }
        return PlannerDecision::Dispatch { worker_id: w.id };
    }
    let (dimension, head_load) =
        head_reject.unwrap_or((WatermarkDimension::Mem, CommittedLoad::default()));
    if profile.censored && fallback_expired(first_watermark_reject_age) {
        let target = steering_order(&eligible, committed, watermarks)[0];
        PlannerDecision::SoftFallback {
            worker_id: target.id,
        }
    } else {
        PlannerDecision::WatermarkBlocked {
            dimension,
            head_load,
        }
    }
}

/// 水位维度 → 指标 label（planner 决策与本地水位门共用的落点）。
pub(crate) fn watermark_dimension_metric(
    dimension: crate::server::scheduler::WatermarkDimension,
) -> DispatchRejectDimension {
    match dimension {
        crate::server::scheduler::WatermarkDimension::Mem => DispatchRejectDimension::WatermarkMem,
        crate::server::scheduler::WatermarkDimension::Cpu => DispatchRejectDimension::WatermarkCpu,
        crate::server::scheduler::WatermarkDimension::Tmpfs => {
            DispatchRejectDimension::WatermarkTmpfs
        }
    }
}
