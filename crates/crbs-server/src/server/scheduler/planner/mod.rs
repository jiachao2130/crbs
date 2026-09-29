// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! build-outer planner：候选外层主循环、硬下限 eligible 过滤（fail-closed）、
//! 归因内存态、censored 超龄兜底与 heavy steering 选点；单 worker 单 tick
//! 新增派发按 `max(2, capacity/8)` 上限平滑 refill 振幅。
//!
//! 权重源 = 画像表有效权重（`resource_profile_weights_enabled`，三维键批量
//! 缓存）；硬下限解析链 = builds.req_* > declared（精确 arch → 'any'，
//! `resource_requirements_enabled`）。派发原子性由 state 层指定 CAS 承担，
//! 决策是"建议"。

/// 候选扫描深度（partial 索引序读 + 内存过滤线性微增，过小只损失本 tick
/// 派发量，无正确性悬崖）。
pub(crate) const DISPATCH_CANDIDATE_LIMIT: i64 = 512;

/// censored 兜底超龄（秒）：首次水位全拒后持续全拒此时长才兜底（内存态
/// 计时，重启清空重新起算——诊断性兜底可接受）。
pub(crate) const LAST_RESORT_AFTER_SECS: u64 = 1800;

/// heavy 判定的有效权重阈值（KB）：取轻包门槛默认值同值——画像认定"非轻包"
/// 的重包尾部即 steering 对象，未画像重包由 srpm 臂补洞。不随
/// `resource_profile_min_peak_rss_kb` 联动（写入门槛是采集侧旋钮，调度阈值
/// 是消费侧常量，改其一不得漂移另一）。
/// ponytail: 有校准数据后可升格为 server.toml 键（与 heavy_srpm_bytes 并列）。
const HEAVY_EFFECTIVE_WEIGHT_MEM_KB: i64 = 1024 * 1024;

/// 单 worker 单 tick 新增派发上限的容量除数（cap = `capacity / 8` 向下取整）。
const REFILL_CAP_DIVISOR: i64 = 8;
/// 单 worker 单 tick 新增派发下限：小容量节点保底，防除法吞掉补位。
const REFILL_CAP_MIN: i64 = 2;

/// 单 worker 单 tick 新增派发上限（纯函数）：`max(2, capacity / 8)`。限制
/// 单轮补位振幅：水位门自锁解除或空载 worker 入池时，一轮最多补这么多；
/// 派发成功不睡 tick（主循环 `Ok(true)` 即续跑），实际节奏是背靠背轮各领
/// 一份预算，不是按钟表摊开——超限候选留队列下轮重判（预算每轮重置，
/// 不分优先级配额）。
/// ponytail: 有运维诉求时可升格为 server.toml 键（与 heavy_srpm_bytes 并列）。
fn per_tick_refill_cap(capacity: i64) -> i64 {
    (capacity / REFILL_CAP_DIVISOR).max(REFILL_CAP_MIN)
}

/// heavy 判定（三臂独立 OR）：req 声明任一维存在，或有效权重 mem
/// 达 [`HEAVY_EFFECTIVE_WEIGHT_MEM_KB`]，或 SRPM 体积达 `heavy_srpm_bytes`
///（0 = 该臂禁用；未画像重包的补洞）。cpu 权重不进判定（重包语义按内存轴）。
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
