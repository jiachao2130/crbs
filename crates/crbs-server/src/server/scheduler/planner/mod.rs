// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! build-outer planner：候选外层主循环、硬下限 eligible 过滤（失败即拒绝）、
//! 归因内存态、censored 超龄兜底与 heavy steering 选点；单 worker 单 tick
//! 新增派发按 `max(2, capacity/8)` 上限平滑 refill 振幅。
//!
//! 权重源 = 画像表有效权重（`resource_profile_weights_enabled`，三维键批量
//! 缓存）；硬下限解析链 = builds.req_* > declared（精确 arch → 'any'，
//! `resource_requirements_enabled`）。派发原子性由 state 层指定 CAS 承担，
//! 决策是"建议"。

/// 候选扫描深度：按 partial 索引序读取后做内存过滤，线性开销随该值微增；
/// 取值过小只损失本调度周期的派发量，不产生正确性问题。
pub(crate) const DISPATCH_CANDIDATE_LIMIT: i64 = 512;

/// censored 兜底超龄（秒）：首次被水位全维度拒绝后持续全拒达到该时长，才
/// 启动兜底放行。计时为进程内状态，重启后清空重新起算——诊断性兜底可接
/// 受该代价。
pub(crate) const LAST_RESORT_AFTER_SECS: u64 = 1800;

/// ponytail: 有校准数据后可升格为 server.toml 键（与 heavy_srpm_bytes 并列）。
const HEAVY_EFFECTIVE_WEIGHT_MEM_KB: i64 = 1024 * 1024;

const REFILL_CAP_DIVISOR: i64 = 8;

const REFILL_CAP_MIN: i64 = 2;

/// ponytail: 有运维诉求时可升格为 server.toml 键（与 heavy_srpm_bytes 并列）。
fn per_tick_refill_cap(capacity: i64) -> i64 {
    (capacity / REFILL_CAP_DIVISOR).max(REFILL_CAP_MIN)
}

fn is_heavy_candidate(
    hard_req: &EffectiveHardReq,
    weight: &super::PackageResourceWeight,
    srpm_size_bytes: Option<i64>,
    heavy_srpm_bytes: i64,
) -> bool {
    hard_req.has_any()
        || weight
            .peak_rss_kb
            .is_some_and(|kb| kb >= HEAVY_EFFECTIVE_WEIGHT_MEM_KB as f64)
        || (heavy_srpm_bytes > 0 && srpm_size_bytes.is_some_and(|size| size >= heavy_srpm_bytes))
}

mod attribution;
mod decide;
mod learned_gates;
#[cfg(test)]
mod tests;
mod tick;

pub(crate) use attribution::{DispatchAttribution, RejectAttribution, RejectReason};
pub(crate) use decide::{
    decide_candidate, watermark_dimension_metric, worker_satisfies_hard_req, DecideCandidateInput,
    EffectiveHardReq, HardReqDimension, PlannerDecision,
};
pub(crate) use learned_gates::record_shadow_decision;
pub(crate) use tick::{hard_req_dimension_metric, notify_hard_req_stall, run_tick};
