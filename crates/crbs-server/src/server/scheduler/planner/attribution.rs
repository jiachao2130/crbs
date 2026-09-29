// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 派发归因内存态：pending 构建最近拒绝原因与水位首拒时刻。

use std::collections::HashMap;
use std::time::Instant;

use super::decide::HardReqDimension;
use crate::server::scheduler::{CommittedLoad, WatermarkDimension};

// ===== 派发归因内存态 =====

/// pending 构建的最近拒绝原因（徽章/tooltip 消费）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectReason {
    /// 无匹配架构 worker。
    NoFitArch,
    /// 架构匹配但容量全满。
    NoFitCapacity,
    /// 水位阻塞（首次全拒时刻供兜底超龄判定）；dimension = 遍历序首节点的
    /// 拒绝维（mem/cpu 水位，或转正的学习 tmpfs 门），UI 按维展示对照压载。
    WatermarkBlocked { dimension: WatermarkDimension },
    /// init 门（worker 同 product 活跃 init）。
    InitGated,
    /// 硬下限无人满足（fail-closed：要求维遥测缺失同判不满足）；dimension =
    /// eligible 序首个不合格 worker 的首个不满足维（多 worker 各缺不同维时
    /// 归因首见维，诊断性近似）。
    NoFitHardReq { dimension: HardReqDimension },
    /// 后台闸。无写入方：候选流 SQL 已按闸过滤、被闸行不进 planner 视野
    ///（CAS 复查失败与"被抢"不可分辨，不记）；枚举定义齐，供本地伪 worker
    /// 与 UI 消费面。
    #[allow(dead_code)]
    BackgroundGated,
}

impl RejectReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RejectReason::NoFitArch => "no_fit_arch",
            RejectReason::NoFitCapacity => "no_fit_capacity",
            RejectReason::WatermarkBlocked { .. } => "watermark_blocked",
            RejectReason::InitGated => "init_gated",
            RejectReason::NoFitHardReq { .. } => "no_fit_hard_req",
            RejectReason::BackgroundGated => "background_gated",
        }
    }
}

/// 单个 pending 构建的归因条目（诊断性质，重启清空）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct RejectAttribution {
    /// 最近一次拒绝原因。
    pub reason: RejectReason,
    /// 首次水位全拒时刻（兜底超龄判定输入；只进不退，跨原因保留——兜底救
    /// 删失自锁，不因短暂容量/架构抖动重置等待钟）。
    pub first_watermark_reject_at: Option<Instant>,
    /// 首次硬下限全拒时刻（停滞提示判定输入；只进不退，跨原因保留）。
    pub first_hard_req_reject_at: Option<Instant>,
    /// 硬下限停滞提示是否已落 note（只提示一次；重启复位）。
    pub hard_req_stall_noted: bool,
    /// 最近水位拒的生效折算压载：遍历序首节点上的在跑 Σ + 候选自身权重，
    /// cpu/mem 维均按该节点核数折算后的量（UI 水位占用展示输入）。
    pub watermark_effective_load: Option<CommittedLoad>,
    /// 最近更新时刻。
    pub updated_at: Instant,
}

/// build_id → 最近拒绝归因（进程内存态）。std::sync::Mutex 仅查插删不跨
/// await；容量封顶淘汰最旧一条（优先淘汰无等待钟的条目——水位首拒与硬下限
/// 首拒是兜底/停滞判定的输入，不是纯诊断字段，整表清空会把等待钟归零）。
pub(crate) struct DispatchAttribution {
    entries: std::sync::Mutex<HashMap<i64, RejectAttribution>>,
}

pub(super) const ATTRIBUTION_CAPACITY: usize = 4096;

/// 容量满时淘汰一条：先挑无任何等待钟的最旧条目，全都有钟才牺牲最旧者。
fn evict_oldest(entries: &mut HashMap<i64, RejectAttribution>) {
    let victim = entries
        .iter()
        .filter(|(_, a)| {
            a.first_watermark_reject_at.is_none() && a.first_hard_req_reject_at.is_none()
        })
        .min_by_key(|(_, a)| a.updated_at)
        .or_else(|| entries.iter().min_by_key(|(_, a)| a.updated_at))
        .map(|(id, _)| *id);
    if let Some(id) = victim {
        entries.remove(&id);
    }
}

impl Default for DispatchAttribution {
    fn default() -> Self {
        Self::new()
    }
}

impl DispatchAttribution {
    pub(crate) fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<i64, RejectAttribution>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 记录无合格节点归因；既有等待钟保留（见 [`RejectAttribution`]）。
    pub(crate) fn record_no_fit(&self, build_id: i64, reason: RejectReason) {
        let mut guard = self.lock();
        if guard.len() >= ATTRIBUTION_CAPACITY && !guard.contains_key(&build_id) {
            evict_oldest(&mut guard);
        }
        let now = Instant::now();
        let entry = guard.entry(build_id).or_insert(RejectAttribution {
            reason,
            first_watermark_reject_at: None,
            first_hard_req_reject_at: None,
            hard_req_stall_noted: false,
            watermark_effective_load: None,
            updated_at: now,
        });
        entry.reason = reason;
        if matches!(reason, RejectReason::NoFitHardReq { .. }) {
            entry.first_hard_req_reject_at.get_or_insert(now);
        }
        entry.updated_at = now;
    }

    /// 记录水位拒绝：首次全拒时刻只在首次设置（超龄判定基准）；`dimension` =
    /// 序首节点拒绝维，`load` = 该节点的生效折算压载，随条目更新供 UI 展示。
    pub(crate) fn record_water_reject(
        &self,
        build_id: i64,
        dimension: WatermarkDimension,
        load: CommittedLoad,
    ) {
        let mut guard = self.lock();
        if guard.len() >= ATTRIBUTION_CAPACITY && !guard.contains_key(&build_id) {
            evict_oldest(&mut guard);
        }
        let now = Instant::now();
        let entry = guard.entry(build_id).or_insert(RejectAttribution {
            reason: RejectReason::WatermarkBlocked { dimension },
            first_watermark_reject_at: None,
            first_hard_req_reject_at: None,
            hard_req_stall_noted: false,
            watermark_effective_load: None,
            updated_at: now,
        });
        entry.reason = RejectReason::WatermarkBlocked { dimension };
        entry.first_watermark_reject_at.get_or_insert(now);
        entry.watermark_effective_load = Some(load);
        entry.updated_at = now;
    }

    /// 硬下限停滞提示一次性置位：true = 本次首次置位（调用方落 note）。
    pub(crate) fn mark_hard_req_stall_noted(&self, build_id: i64) -> bool {
        let mut guard = self.lock();
        let Some(entry) = guard.get_mut(&build_id) else {
            return false;
        };
        if entry.hard_req_stall_noted {
            false
        } else {
            entry.hard_req_stall_noted = true;
            true
        }
    }

    /// 停滞提示置位回滚：note 落库失败时调用，让下个 tick 重试——单次写
    /// 失败不能让一次性提示永久丢失。
    pub(crate) fn unmark_hard_req_stall_noted(&self, build_id: i64) {
        if let Some(entry) = self.lock().get_mut(&build_id) {
            entry.hard_req_stall_noted = false;
        }
    }

    /// 构建离开 pending（实际派发成功）后清除。
    pub(crate) fn clear(&self, build_id: i64) {
        self.lock().remove(&build_id);
    }

    /// 归因快照（UI/API 消费面）。
    pub(crate) fn get(&self, build_id: i64) -> Option<RejectAttribution> {
        self.lock().get(&build_id).copied()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// 预置水位首拒时刻（集成测试模拟超龄，免真实等待）。
    #[cfg(test)]
    pub(crate) fn seed_first_watermark_reject(&self, build_id: i64, at: Instant) {
        let mut guard = self.lock();
        let now = Instant::now();
        let entry = guard.entry(build_id).or_insert(RejectAttribution {
            reason: RejectReason::WatermarkBlocked {
                dimension: WatermarkDimension::Mem,
            },
            first_watermark_reject_at: None,
            first_hard_req_reject_at: None,
            hard_req_stall_noted: false,
            watermark_effective_load: None,
            updated_at: now,
        });
        entry.reason = RejectReason::WatermarkBlocked {
            dimension: WatermarkDimension::Mem,
        };
        entry.first_watermark_reject_at = Some(at);
        entry.updated_at = now;
    }

    /// 预置硬下限首拒时刻（集成测试模拟停滞，免真实等待）。
    #[cfg(test)]
    pub(crate) fn seed_first_hard_req_reject(&self, build_id: i64, at: Instant) {
        let mut guard = self.lock();
        let now = Instant::now();
        let entry = guard.entry(build_id).or_insert(RejectAttribution {
            reason: RejectReason::NoFitHardReq {
                dimension: HardReqDimension::Mem,
            },
            first_watermark_reject_at: None,
            first_hard_req_reject_at: None,
            hard_req_stall_noted: false,
            watermark_effective_load: None,
            updated_at: now,
        });
        entry.reason = RejectReason::NoFitHardReq {
            dimension: HardReqDimension::Mem,
        };
        entry.first_hard_req_reject_at = Some(at);
        entry.updated_at = now;
    }
}
