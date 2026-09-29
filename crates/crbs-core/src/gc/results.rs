// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 本地结果 GC：结果目录与日志的宽限回收。

use std::path::Path;

use crate::config::CrbsConfig;
use crate::engine::gc::run_result_gc_standalone;
use crate::state::StateStore;
use crate::types::GcResultsSummary;

pub(crate) async fn gc_results(
    product: Option<&str>,
    dry_run: bool,
    cfg: &CrbsConfig,
    artifact_dir: Option<&Path>,
    state: &StateStore,
) -> crate::Result<GcResultsSummary> {
    let outcome = run_result_gc_standalone(product, dry_run, cfg, artifact_dir, state).await?;
    Ok(GcResultsSummary {
        removed: if dry_run { 0 } else { outcome.removed },
        would_remove: if dry_run { outcome.would_remove } else { 0 },
        bytes: outcome.bytes,
        policy_removed: if dry_run { 0 } else { outcome.policy_removed },
        // skipped 观测计数与 dry-run 无关，原样透传。
        skipped_latest: outcome.skipped_latest,
        skipped_missing: outcome.skipped_missing,
        skipped_invalid: outcome.skipped_invalid,
        failed: outcome.failed,
        // dry-run 无磁盘变更 → 留空；实删透传受影响产品供 GC 触发点 regen。
        affected_products: if dry_run {
            Vec::new()
        } else {
            outcome.affected_products
        },
    })
}
