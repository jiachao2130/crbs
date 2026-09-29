// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 回填播种：窗口取样分组、组级轻包门槛与逐样本折算。

use super::{
    next_learned_state, LearnedState, PackageResourceProfile, ResourceSampleOutcome, SampleBackend,
};
use crate::error::DbResultExt;

/// 回填取样窗口的单行（声明面批量解析的中间形态；全空声明视为未声明）。
pub(super) struct DeclaredRow {
    pub(super) arch: String,
    pub(super) min_mem_kb: Option<i64>,
    pub(super) min_ncpu: Option<i64>,
    pub(super) min_disk_kb: Option<i64>,
}

impl DeclaredRow {
    pub(super) fn has_any(&self) -> bool {
        self.min_mem_kb.is_some() || self.min_ncpu.is_some() || self.min_disk_kb.is_some()
    }
}

/// 回填统计（server 启动日志用）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProfileBackfillStats {
    /// 折算播种的画像行数（含声明-only 空行的 learned 组补齐）。
    pub seeded: u64,
    /// 已有学习样本被条件 upsert 保留跳过的键数。
    pub skipped_occupied: u64,
    /// 全轻窗口（组级门槛以下）不播种的键数。
    pub skipped_light: u64,
}

/// 回填窗口单样本：`(peak_rss_kb, cpu_p90_cores, sample_ncpu)`。
type BackfillSample = (i64, Option<f64>, Option<i64>);

/// 回填样本按三维键分组（插入序 = 首见序，即组间时间序）。
pub(super) type BackfillSampleGroups =
    std::collections::HashMap<(String, String, String), Vec<BackfillSample>>;

/// 组级轻包门槛：窗口内至少一条样本达到门槛才播种（门槛语义与在线学习
/// 相同——`peak < min` 为轻包）。`None` = 不设门槛。
pub(super) fn backfill_group_meets_min_peak(
    samples: &[BackfillSample],
    min_peak_rss_kb: Option<i64>,
) -> bool {
    match min_peak_rss_kb {
        None => true,
        Some(min) => samples.iter().any(|(peak, _, _)| *peak >= min),
    }
}

/// 时间正序折叠回填样本（复用在线单样本决策纯函数，保证与逐单折算一致）。
/// 样本统一按 cgroup 口径喂入——同口径不触发 sticky/重置分支，折算纯做 EMA/
/// max 递推；落列前 `learned_backend` 置 NULL（历史样本无既立口径）。
/// 返回 `None` = 空窗口（调用方查询保证非空，防御臂）。
pub(super) fn fold_backfill_samples(
    samples_oldest_first: &[BackfillSample],
    key: &(&str, &str, &str),
    headroom: f64,
) -> Option<LearnedState> {
    let mut current: Option<LearnedState> = None;
    for (peak_rss_kb, cpu_p90, sample_ncpu) in samples_oldest_first {
        let outcome = ResourceSampleOutcome::Succeeded {
            // 占位口径：全组同口径，sticky/重置分支不可达。
            backend: SampleBackend::Cgroup,
            peak_rss_kb: *peak_rss_kb,
            peak_tmpfs_kb: None,
            cpu_p90_cores: *cpu_p90,
            sample_ncpu: *sample_ncpu,
        };
        let (next, _) = next_learned_state(
            current.as_ref(),
            &outcome,
            None,
            headroom,
            key.0,
            key.1,
            key.2,
        );
        current = next;
    }
    let mut state = current?;
    state.backend = None;
    Some(state)
}

/// 按列名解码画像行（列名与 [`sql::PROFILE_COLUMNS`] 对齐，漂移经 db_ctx
/// 报错浮出；learned_censored 列是 INTEGER 0/1）。
pub(super) fn profile_from_row(row: &sqlx::any::AnyRow) -> crate::Result<PackageResourceProfile> {
    use sqlx::Row as _;
    const CTX: &str = "decode resource profile row";
    Ok(PackageResourceProfile {
        product: row.try_get("product").db_ctx(CTX)?,
        source_name: row.try_get("source_name").db_ctx(CTX)?,
        arch: row.try_get("arch").db_ctx(CTX)?,
        declared_min_mem_kb: row.try_get("declared_min_mem_kb").db_ctx(CTX)?,
        declared_min_ncpu: row.try_get("declared_min_ncpu").db_ctx(CTX)?,
        declared_min_disk_kb: row.try_get("declared_min_disk_kb").db_ctx(CTX)?,
        declared_updated_at: row.try_get("declared_updated_at").db_ctx(CTX)?,
        learned_ema_mem_kb: row.try_get("learned_ema_mem_kb").db_ctx(CTX)?,
        learned_max_mem_kb: row.try_get("learned_max_mem_kb").db_ctx(CTX)?,
        learned_ema_tmpfs_kb: row.try_get("learned_ema_tmpfs_kb").db_ctx(CTX)?,
        learned_max_tmpfs_kb: row.try_get("learned_max_tmpfs_kb").db_ctx(CTX)?,
        learned_ema_ncpu: row.try_get("learned_ema_ncpu").db_ctx(CTX)?,
        learned_max_ncpu: row.try_get("learned_max_ncpu").db_ctx(CTX)?,
        learned_samples: row.try_get("learned_samples").db_ctx(CTX)?,
        learned_sample_ncpu: row.try_get("learned_sample_ncpu").db_ctx(CTX)?,
        learned_backend: row.try_get("learned_backend").db_ctx(CTX)?,
        learned_censored: row.try_get::<i64, _>("learned_censored").db_ctx(CTX)? != 0,
        learned_updated_at: row.try_get("learned_updated_at").db_ctx(CTX)?,
        created_at: row.try_get("created_at").db_ctx(CTX)?,
        updated_at: row.try_get("updated_at").db_ctx(CTX)?,
    })
}
