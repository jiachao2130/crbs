// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 学习门影子判定：派发落点按已学习键的 learned_max_* 逐门评估并落决策
//! 日志——影子只记录，不实际拒绝、不参与放置与过滤（`resource_learned_
//! gates_enabled`，默认关）。
//!
//! 门语义（仅对 CAS 领取成功的落点节点评估；CAS 失败不记录）：
//! - 内存门：节点可用内存（`mem_total_kb × (1 − mem_used_pct/100)`，心跳现值）
//!   ≥ `learned_max_mem_kb × 1.2`；used_pct 缺失 = 门跳过。
//! - tmpfs 门：节点 tmpfs 余量 ≥ `learned_max_tmpfs_kb`；容量 = mem_total/2，
//!   已用按 0 参与（影子先行）；学习值缺失 = 门不适用。
//! - 未学习键（无画像行 / learned_samples = 0）：不门控，维持现状。

use tracing::debug;

use crbs_core::{DispatchCandidate, WorkerStatus};

use super::super::ResolvedResourceProfile;

/// 内存门裕量系数：需求 = `learned_max_mem_kb × 1.2`（学习 max 是单构建峰值
/// 观测上界，20% 裕量吸收心跳间隔内的波动与口径误差）。
pub(crate) const LEARNED_MEM_HEADROOM: f64 = 1.2;

/// tmpfs 容量占节点内存比：与内核默认 tmpfs 挂载（ram 感知 size=50%）同源；
/// 已用项影子期按 0，接真实余量遥测后改此处。
const TMPFS_CAPACITY_MEM_RATIO: f64 = 0.5;

/// 单门结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateOutcome {
    /// 输入缺失（学习值 NULL / 节点遥测缺失）：门跳过（fail-open 同向）。
    Skipped,
    /// 判定放行（含恰好压线：可用 ≥ 需求）。
    Pass,
    /// 判定会拒（影子期不实际拒绝）。
    Reject,
}

impl GateOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            GateOutcome::Skipped => "skip",
            GateOutcome::Pass => "pass",
            GateOutcome::Reject => "reject",
        }
    }
}

/// 学习门对（内存门 + tmpfs 门）对单个落点节点的判定结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LearnedGateDecision {
    /// 未学习键：两门不参与，无决策记录。
    NotLearned,
    /// 已学习键：逐门结论（影子记录输入）。
    Evaluated {
        mem: GateOutcome,
        tmpfs: GateOutcome,
    },
}

/// 学习门判定（纯函数）：`learned` = 键已学习（learned_samples ≥ 1）。边界
/// 语义：可用/余量恰好等于需求 = 放行（≥）。
pub(crate) fn evaluate_learned_gates(
    worker: &WorkerStatus,
    learned: bool,
    max_mem_kb: Option<i64>,
    max_tmpfs_kb: Option<i64>,
) -> LearnedGateDecision {
    if !learned {
        return LearnedGateDecision::NotLearned;
    }
    // 内存门：used_pct 与 total 任一缺失即跳过（换算不出可用内存，绝不冒充
    // "判拒"——影子门与水位门同向 fail-open）。
    let mem = match (max_mem_kb, worker.mem_total_kb, worker.mem_used_pct) {
        (Some(need), Some(total_kb), Some(used_pct)) => {
            let available_kb = total_kb as f64 * (1.0 - used_pct / 100.0);
            if available_kb >= need as f64 * LEARNED_MEM_HEADROOM {
                GateOutcome::Pass
            } else {
                GateOutcome::Reject
            }
        }
        _ => GateOutcome::Skipped,
    };
    let tmpfs = tmpfs_gate_outcome(max_tmpfs_kb, worker.mem_total_kb);
    LearnedGateDecision::Evaluated { mem, tmpfs }
}

/// tmpfs 门单门判定（纯函数，影子记录与转正拒绝共用同一口径）：节点 tmpfs
/// 容量（mem_total × [`TMPFS_CAPACITY_MEM_RATIO`]，已用按 0）≥ 学习 tmpfs
/// 峰值 = 放行（压线即过）。需求缺失 / 节点 mem_total 缺失 = 跳过
///（fail-open 同向），调用方按门语义处置（影子记 skip、转正放行）。
pub(crate) fn tmpfs_gate_outcome(
    max_tmpfs_kb: Option<i64>,
    mem_total_kb: Option<i64>,
) -> GateOutcome {
    match (max_tmpfs_kb, mem_total_kb) {
        (Some(need), Some(total_kb)) => {
            let capacity_kb = total_kb as f64 * TMPFS_CAPACITY_MEM_RATIO;
            if capacity_kb >= need as f64 {
                GateOutcome::Pass
            } else {
                GateOutcome::Reject
            }
        }
        _ => GateOutcome::Skipped,
    }
}

/// 派发落点影子记录：键已学习时逐门落一条 debug 决策日志（build/worker/门名/
/// 输入/结论）；未学习键零输出。仅日志通道——无指标、无归因、无 note。
pub(crate) fn record_shadow_decision(
    candidate: &DispatchCandidate,
    worker: &WorkerStatus,
    profile: &ResolvedResourceProfile,
) {
    let LearnedGateDecision::Evaluated { mem, tmpfs } = evaluate_learned_gates(
        worker,
        profile.gate_learned,
        profile.gate_max_mem_kb,
        profile.gate_max_tmpfs_kb,
    ) else {
        return;
    };
    debug!(
        build_id = %candidate.id,
        pkg = %candidate.pkg_name,
        worker_id = %worker.id,
        gate = "learned_mem",
        learned_max_mem_kb = ?profile.gate_max_mem_kb,
        mem_total_kb = ?worker.mem_total_kb,
        mem_used_pct = ?worker.mem_used_pct,
        verdict = mem.as_str(),
        "Learned gate shadow decision"
    );
    debug!(
        build_id = %candidate.id,
        pkg = %candidate.pkg_name,
        worker_id = %worker.id,
        gate = "learned_tmpfs",
        learned_max_tmpfs_kb = ?profile.gate_max_tmpfs_kb,
        mem_total_kb = ?worker.mem_total_kb,
        verdict = tmpfs.as_str(),
        "Learned gate shadow decision"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真值表辅助 worker：只填内存遥测两维，其余字段测试无关。
    fn worker_with_mem(mem_total_kb: Option<i64>, mem_used_pct: Option<f64>) -> WorkerStatus {
        WorkerStatus {
            id: 1,
            name: "w1".into(),
            arch: "x86_64".into(),
            capacity: 2,
            status: "online".into(),
            last_heartbeat: None,
            version: "test".into(),
            has_secret: false,
            load1: None,
            ncpu: None,
            cpu_util_pct: None,
            mem_used_pct,
            mem_total_kb,
            disk_free_kb: None,
            resource_caps: None,
            created_at: None,
            secret_expires_at: None,
        }
    }

    /// 内存门 1.2× 裕量边界两态 + used_pct NULL 跳过 + 未学习键直通。
    #[test]
    fn mem_gate_margin_boundary_and_skip_paths() {
        // total=10000, used=40% → 可用 6000；需求 5000×1.2=6000 恰好压线 = 放行。
        let boundary = worker_with_mem(Some(10_000), Some(40.0));
        assert_eq!(
            evaluate_learned_gates(&boundary, true, Some(5_000), None),
            LearnedGateDecision::Evaluated {
                mem: GateOutcome::Pass,
                tmpfs: GateOutcome::Skipped,
            }
        );
        // 需求 5001×1.2=6012 > 6000 = 拒。
        assert_eq!(
            evaluate_learned_gates(&boundary, true, Some(5_001), None),
            LearnedGateDecision::Evaluated {
                mem: GateOutcome::Reject,
                tmpfs: GateOutcome::Skipped,
            }
        );
        // used_pct NULL（含 total NULL）= 门跳过。
        let no_used = worker_with_mem(Some(10_000), None);
        assert_eq!(
            evaluate_learned_gates(&no_used, true, Some(5_000), None),
            LearnedGateDecision::Evaluated {
                mem: GateOutcome::Skipped,
                tmpfs: GateOutcome::Skipped,
            }
        );
        let no_total = worker_with_mem(None, Some(40.0));
        assert_eq!(
            evaluate_learned_gates(&no_total, true, Some(5_000), None),
            LearnedGateDecision::Evaluated {
                mem: GateOutcome::Skipped,
                tmpfs: GateOutcome::Skipped,
            }
        );
        // 未学习键：输入齐备也直通。
        assert_eq!(
            evaluate_learned_gates(&boundary, false, Some(5_000), Some(4_000)),
            LearnedGateDecision::NotLearned
        );
    }

    /// tmpfs 门：学习值 NULL 不门控 / 超容拒 / 恰好压线放行 / total 缺失跳过。
    #[test]
    fn tmpfs_gate_null_not_gated_and_capacity_boundary() {
        let full = worker_with_mem(Some(2_000_000), Some(95.0)); // 容量 = 1_000_000，与 used_pct 无关
                                                                 // 学习值 NULL = 门不适用。
        assert_eq!(
            evaluate_learned_gates(&full, true, None, None),
            LearnedGateDecision::Evaluated {
                mem: GateOutcome::Skipped,
                tmpfs: GateOutcome::Skipped,
            }
        );
        // 需求 1_000_000 = 容量，恰好压线 = 放行。
        assert_eq!(
            evaluate_learned_gates(&full, true, None, Some(1_000_000)),
            LearnedGateDecision::Evaluated {
                mem: GateOutcome::Skipped,
                tmpfs: GateOutcome::Pass,
            }
        );
        // 超容 1 KB = 拒。
        assert_eq!(
            evaluate_learned_gates(&full, true, None, Some(1_000_001)),
            LearnedGateDecision::Evaluated {
                mem: GateOutcome::Skipped,
                tmpfs: GateOutcome::Reject,
            }
        );
        // total NULL = 容量换算不出，跳过。
        let no_total = worker_with_mem(None, Some(10.0));
        assert_eq!(
            evaluate_learned_gates(&no_total, true, None, Some(100)),
            LearnedGateDecision::Evaluated {
                mem: GateOutcome::Skipped,
                tmpfs: GateOutcome::Skipped,
            }
        );
    }

    /// 两门独立并存：mem 拒 + tmpfs 过互不影响（逐门结论同落）。
    #[test]
    fn gates_evaluate_independently() {
        let tight = worker_with_mem(Some(2_000_000), Some(99.0)); // 可用 20_000 < 100_000×1.2
        assert_eq!(
            evaluate_learned_gates(&tight, true, Some(100_000), Some(500_000)),
            LearnedGateDecision::Evaluated {
                mem: GateOutcome::Reject,
                tmpfs: GateOutcome::Pass,
            }
        );
    }
}
