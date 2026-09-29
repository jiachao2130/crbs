// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 整仓重建批次驱动器：把 running 批次按拓扑轮次推进到终态。单一推进入口
//! [`batch_driver_tick`]（可独立调用，测试 seed-then-call），由 [`spawn_batch_driver`]
//! 挂的监督循环周期调用（5s 兜底 + worker_notify 唤醒）。每 tick 对每个 running 批次：
//! 对账在途（released 项按 task 子构建聚合终态——崩溃恢复的事实源）→ 当前轮推进
//!（最小含非终态项的轮内 pending 限量释放，每 tick 每批次 ≤200；非首轮先跑轮间栅栏：
//! `assemble_for_product` 对账式组装产品 repo、与在途 regen 在 `.repodata-{arch}.lock` 串行，
//! 栅栏完成的下一 tick 才释放）→ 恢复轮（failed 且更低轮全部 succeeded 者按
//! `chain_max_recovery_rounds` 预算 reset 重入）→ 收尾（finish completed/partial；
//! `on_failure=abort` 首个构建失败项即中止）→ 残留对账（每 tick 附带：preparing/planning
//! 超 30 分钟收口 failed("interrupted")，清 hub 崩溃悬挂；running 由对账自然接管）。
//!
//! 释放即建 task（[`fan_out_builds`]）：priority=-1 后台优先级（校验层 0-2 不放行负值，
//! 不与用户构建抢队）；SRPM 源指向批次暂存且 `allow_move=false`，每目标架构一个子构建，
//! 项终态 = task 聚合；发布默认 `repo_publish=1`（newest-wins）；追溯回填 `builds.batch_id`。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crbs_core::error::CrbsError;
use crbs_core::types::{build_phase_is_terminal, PRIORITY_BACKGROUND};
use crbs_core::{BatchItemRecord, BatchRecord, BuildOptions};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::server::error::ApiError;
use crate::server::repo_regen::assemble_for_product;
use crate::server::routes::builds::service::cancel_distributed_build;
use crate::server::routes::builds::{
    ensure_shared_result_dir, fan_out_builds, map_noarch_to_concrete, FanOutArgs,
};
use crate::server::scheduler::spawn_supervised_loop;
use crate::server::state::AppState;

const BATCH_DRIVER_TICK_SECS: u64 = 5;

const RELEASE_CAP_PER_TICK: usize = 200;

const ORPHAN_BATCH_GRACE: Duration = Duration::from_secs(30 * 60);

const BATCH_TASK_USER: &str = "batch";

/// 活跃重复 Conflict 的文案基准（builds.rs `active_duplicate_conflict` 稳定前缀）：命中即 skipped_conflict，其余走失败臂。
const ACTIVE_DUP_MARK: &str = "an active build for";

const ITEM_ERROR_MAX_CHARS: usize = 300;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// 单次 tick 的推进结果（日志与测试断言面；经 test_support 桥给集成测试；finished 含孤儿对账）。
pub struct TickReport {
    pub released: usize,
    pub reconciled: usize,
    pub advanced_round: bool,
    pub barrier_ran: bool,
    pub finished: usize,
}

/// 单 tick 对每个 running 批次推进一步：核对在途（released 项按 task 子构建聚合终态，崩溃恢复以它为准）→ 推进当前轮（最小含非终态项的轮内限量释放，每 tick
/// ≤200；非首轮先等轮间栅栏：assemble_for_product 组装产品 repo，与在途 regen 在 .repodata-{arch}.lock 串行，栅栏完成的下一 tick
/// 才释放）→ 恢复轮（failed 且更低轮全部 succeeded 者按预算 reset 重入）→ 收尾（completed/partial；on_failure=abort
/// 首个构建失败即中止）→ 悬挂清理（preparing/planning 超 30 分钟收口 failed，清崩溃残留）。单批次失败只 warn 不中断其余批次（下一 tick 幂等重试）。
pub(crate) async fn batch_driver_tick(app: &Arc<AppState>) -> crbs_core::Result<TickReport> {
    let mut report = TickReport::default();
    sweep_orphan_batches(app, &mut report).await;

    let running = app.state_store.list_batches_in_status(&["running"]).await?;
    for batch in running {
        if let Err(e) = drive_batch(app, &batch, &mut report).await {
            warn!(
                batch_id = batch.id,
                error = ?e,
                "Batch drive step failed; will retry next tick"
            );
        }
    }
    Ok(report)
}

async fn drive_batch(
    app: &Arc<AppState>,
    batch: &BatchRecord,
    report: &mut TickReport,
) -> crbs_core::Result<()> {
    let store = &app.state_store;
    let batch_id = batch.id;

    let product = resolve_batch_product(app, batch, report).await?;

    reconcile_released_items(store, batch_id, report).await?;

    if let Some(r) = minimal_active_round(store, batch_id).await? {
        let first_round = store.batch_rounds(batch_id).await?.first().copied();
        if Some(r) != first_round && !barrier_passed(app, batch_id, r) {
            info!(
                batch_id = batch_id,
                round = r,
                product = %product,
                "Batch round barrier: assembling product repo before releasing next round"
            );
            report.barrier_ran = true;
            if let Err(e) = assemble_for_product(app, &product).await {
                if is_terminal_batch_error(&e) {
                    close_unreadable_batch(
                        app,
                        batch,
                        &format!("barrier assemble failed: {e}"),
                        report,
                    )
                    .await;
                    cleanup_batch_staging(app, &product, batch_id);
                    return Ok(());
                }
                return Err(e);
            }
            mark_barrier_passed(app, batch_id, r);
            return Ok(());
        }
        if let Err(e) = release_round(app, batch, &product, r, report).await {
            if is_terminal_batch_error(&e) {
                // 配置/架构类错误每 tick 重试都不会成功：按不可驱动批次收口，
                // 释放配额与在飞 task；瞬时 DB/IO 错误仍留待下 tick。
                close_unreadable_batch(app, batch, &format!("release round failed: {e}"), report)
                    .await;
                cleanup_batch_staging(app, &product, batch_id);
                return Ok(());
            }
            return Err(e);
        }
    }

    let summary = store.batch_item_summary(batch_id).await?;
    if batch.on_failure == "abort" && summary.failed_with_task > 0 {
        abort_batch(app, batch, report).await?;
        cleanup_batch_staging(app, &product, batch_id);
        return Ok(());
    }

    if summary.pending + summary.released == 0 {
        if batch.on_failure == "continue" && try_recovery_round(app, batch, &product).await? {
            return Ok(());
        }
        finish_batch_if_done(app, batch, &summary, report).await?;
        cleanup_batch_staging(app, &product, batch_id);
    }
    Ok(())
}

/// 核对 released 项的 task 子构建终态（timeout 并入 failed 记 error）；在跑或尚无子构建的跳过，下一 tick 再看。
async fn reconcile_released_items(
    store: &crbs_core::StateStore,
    batch_id: i64,
    report: &mut TickReport,
) -> crbs_core::Result<()> {
    let released = store.items_in_state(batch_id, "released").await?;
    let rounds_touched: HashSet<i64> = released.iter().map(|i| i.round).collect();

    for item in released {
        let Some(task_id) = item.task_id else {
            warn!(
                batch_id = batch_id,
                item_id = item.id,
                pkg = %item.pkg_name,
                "Released item has no task_id; leaving for manual inspection"
            );
            continue;
        };
        let Some(outcome) = task_terminal_outcome(store, task_id).await? else {
            continue;
        };
        let (state, code, message) = match outcome {
            TaskOutcome::Succeeded => ("succeeded", None, None),
            TaskOutcome::Failed(err) => {
                ("failed", Some("build_failed"), Some(truncate_chars(&err)))
            }
            TaskOutcome::Cancelled => ("cancelled", Some("task_cancelled"), None),
        };
        match store
            .mark_item_terminal(batch_id, item.id, state, code, message.as_deref())
            .await
        {
            Ok(()) => {
                report.reconciled += 1;
                info!(
                    batch_id = batch_id,
                    item_id = item.id,
                    task_id = task_id,
                    pkg = %item.pkg_name,
                    state = state,
                    "Batch item reconciled from task outcome"
                );
            }

            Err(CrbsError::Conflict { .. }) => {
                debug!(
                    batch_id = batch_id,
                    item_id = item.id,
                    "Item already terminal when reconciling; concurrent close won"
                );
            }
            Err(e) => return Err(e),
        }
    }

    for r in rounds_touched {
        if round_fully_terminal(store, batch_id, r).await? {
            report.advanced_round = true;
            break;
        }
    }
    Ok(())
}

/// task 终态聚合结果（None = 在飞）；聚合序 {failed, timeout} > succeeded >
/// cancelled。与 tasks lifecycle `aggregate_child_phases`（failed > cancelled >
/// timeout > succeeded）不同序：timeout 并入 failed（项状态域无此变体），
/// {cancelled, timeout} 混合子构建在此判 failed、在 lifecycle 判 cancelled。
enum TaskOutcome {
    Succeeded,
    Failed(String),
    Cancelled,
}

async fn task_terminal_outcome(
    store: &crbs_core::StateStore,
    task_id: i64,
) -> crbs_core::Result<Option<TaskOutcome>> {
    let builds = store.get_builds_by_task_id(task_id).await?;
    if !builds.is_empty() {
        if !builds.iter().all(|b| build_phase_is_terminal(&b.phase)) {
            return Ok(None);
        }
        if let Some(b) = builds
            .iter()
            .find(|b| b.phase == "failed" || b.phase == "timeout")
        {
            let err = b
                .error_summary
                .clone()
                .unwrap_or_else(|| format!("build {}", b.phase));
            return Ok(Some(TaskOutcome::Failed(err)));
        }
        if builds.iter().all(|b| b.phase == "succeeded") {
            return Ok(Some(TaskOutcome::Succeeded));
        }
        return Ok(Some(TaskOutcome::Cancelled));
    }

    let phase = store.get_task(task_id).await?.map(|t| t.phase);
    match phase.as_deref() {
        Some("cancelled") => Ok(Some(TaskOutcome::Cancelled)),
        Some(p) if build_phase_is_terminal(p) => Ok(Some(TaskOutcome::Failed(format!(
            "task {p} without builds"
        )))),
        _ => Ok(None),
    }
}

async fn minimal_active_round(
    store: &crbs_core::StateStore,
    batch_id: i64,
) -> crbs_core::Result<Option<i64>> {
    for r in store.batch_rounds(batch_id).await? {
        let items = store.items_in_round(batch_id, r).await?;
        if items
            .iter()
            .any(|i| i.state == "pending" || i.state == "released")
        {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

async fn round_fully_terminal(
    store: &crbs_core::StateStore,
    batch_id: i64,
    round: i64,
) -> crbs_core::Result<bool> {
    Ok(store
        .items_in_round(batch_id, round)
        .await?
        .iter()
        .all(|i| !matches!(i.state.as_str(), "pending" | "released")))
}

async fn release_round(
    app: &Arc<AppState>,
    batch: &BatchRecord,
    product: &str,
    round: i64,
    report: &mut TickReport,
) -> crbs_core::Result<()> {
    let store = &app.state_store;
    let pending: Vec<BatchItemRecord> = store
        .items_in_round(batch.id, round)
        .await?
        .into_iter()
        .filter(|i| i.state == "pending")
        .collect();
    if pending.is_empty() {
        return Ok(());
    }

    let result_dir = app.result_dir_for_or_default(product).await;
    tokio::fs::create_dir_all(&result_dir)
        .await
        .map_err(|e| CrbsError::from_io_context("create batch result dir", e))?;
    ensure_shared_result_dir(&result_dir).await;
    let arches = resolve_batch_arches(app, batch, product).await?;

    for item in pending.into_iter().take(RELEASE_CAP_PER_TICK) {
        if let ReleaseOutcome::Released =
            release_item(app, batch, &item, product, &result_dir, &arches).await
        {
            report.released += 1;
        }
    }
    Ok(())
}

enum ReleaseOutcome {
    Released,

    Closed,
}

/// 释放即建 task（fan_out_builds）：priority=-1 后台优先级（不与用户构建抢队）；SRPM 源指向批次暂存且 allow_move=false；发布默认
/// repo_publish=1（newest-wins）；回填 builds.batch_id。
async fn release_item(
    app: &Arc<AppState>,
    batch: &BatchRecord,
    item: &BatchItemRecord,
    product: &str,
    result_dir: &Path,
    arches: &[String],
) -> ReleaseOutcome {
    let store = &app.state_store;

    let Some(staging) = item.srpm_staging_path.as_deref() else {
        warn!(
            batch_id = batch.id,
            item_id = item.id,
            pkg = %item.pkg_name,
            "Pending item has no srpm staging path; marking failed"
        );
        return close_pending_item(
            store,
            batch.id,
            item.id,
            "failed",
            "no_staging_path",
            "pending item has no srpm staging path",
        )
        .await;
    };

    let opts = BuildOptions {
        priority: Some(PRIORITY_BACKGROUND),
        dist: batch.dist.clone(),
        ..Default::default()
    };

    let task_id = match fan_out_builds(
        app.clone(),
        FanOutArgs {
            product: product.to_string(),
            result_dir: result_dir.to_path_buf(),
            srpm_paths: vec![PathBuf::from(staging)],
            opts,
            source_names: Vec::new(),
            arches: arches.to_vec(),
            submit_user: BATCH_TASK_USER.to_string(),
            submit_user_id: None,
            allow_move: false,
            collapse_noarch: true,

            arch_explicit: false,
            skip_unsupported_arches: true,
            task_labels: Vec::new(),
        },
    )
    .await
    {
        Ok(outcome) => outcome.task_id,

        Err(ApiError::Conflict(ref msg)) if msg.contains(ACTIVE_DUP_MARK) => {
            info!(
                batch_id = batch.id,
                item_id = item.id,
                pkg = %item.pkg_name,
                "Active duplicate build; marking item skipped_conflict"
            );
            return close_pending_item(
                store,
                batch.id,
                item.id,
                "skipped_conflict",
                "active_build_conflict",
                &truncate_chars(msg),
            )
            .await;
        }
        Err(e) => {
            let msg = e.message().to_string();
            warn!(
                batch_id = batch.id,
                item_id = item.id,
                pkg = %item.pkg_name,
                error = %msg,
                "Batch item task creation failed; marking failed"
            );
            return close_pending_item(
                store,
                batch.id,
                item.id,
                "failed",
                "task_create_failed",
                &truncate_chars(&msg),
            )
            .await;
        }
    };

    if let Err(e) = store.attach_task_builds_to_batch(task_id, batch.id).await {
        warn!(
            batch_id = batch.id,
            task_id = task_id,
            error = ?e,
            "Attach task builds to batch failed (traceability only)"
        );
    }

    match store.mark_item_released(batch.id, item.id, task_id).await {
        Ok(()) => {
            info!(
                batch_id = batch.id,
                item_id = item.id,
                task_id = task_id,
                pkg = %item.pkg_name,
                "Batch item released"
            );
            app.worker_notify.notify_one();
            ReleaseOutcome::Released
        }

        Err(CrbsError::Conflict { .. }) => {
            info!(
                batch_id = batch.id,
                item_id = item.id,
                task_id = task_id,
                "Batch left running during release; cancelling just-created task"
            );
            cancel_task_builds(app, task_id).await;
            ReleaseOutcome::Closed
        }
        Err(e) => {
            // DB 瞬时故障：补偿取消任务、项留 pending，下一 tick 重试。
            warn!(
                batch_id = batch.id,
                item_id = item.id,
                task_id = task_id,
                error = ?e,
                "Mark item released failed; cancelling task and deferring to next tick"
            );
            cancel_task_builds(app, task_id).await;
            ReleaseOutcome::Closed
        }
    }
}

async fn close_pending_item(
    store: &crbs_core::StateStore,
    batch_id: i64,
    item_id: i64,
    state: &str,
    code: &str,
    message: &str,
) -> ReleaseOutcome {
    match store
        .mark_pending_item_terminal(batch_id, item_id, state, Some(code), Some(message))
        .await
    {
        Ok(()) | Err(CrbsError::Conflict { .. }) => ReleaseOutcome::Closed,
        Err(e) => {
            warn!(
                batch_id = batch_id,
                item_id = item_id,
                error = ?e,
                "Close pending item after dispatch failure failed; retrying next tick"
            );
            ReleaseOutcome::Closed
        }
    }
}

async fn resolve_batch_arches(
    app: &Arc<AppState>,
    batch: &BatchRecord,
    product: &str,
) -> crbs_core::Result<Vec<String>> {
    let product_arches = match app.state_store.resolve_any_product_by_name(product).await {
        Ok(r) => r.config.arches.clone(),
        Err(e) => {
            warn!(
                product = %product,
                error = ?e,
                "Resolve product config for batch arches failed; using batch arch_targets only"
            );
            Vec::new()
        }
    };
    let mut arches = super::plan::parse_arch_targets(batch.id, batch.arch_targets.as_deref())?;
    if arches.is_empty() {
        arches = product_arches.clone();
    }
    if arches.iter().any(|a| a == "noarch") {
        arches = map_noarch_to_concrete(arches, &product_arches, product).map_err(|e| {
            CrbsError::ValidationFailed {
                message: e.message().to_string(),
            }
        })?;
    }
    if arches.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "batch {} has no target arches: arch_targets empty and product '{}' \
                 declares none",
                batch.id, product
            ),
        });
    }
    Ok(arches)
}

fn barrier_passed(app: &AppState, batch_id: i64, round: i64) -> bool {
    app.batch_barrier_passed
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&(batch_id, round))
}

fn mark_barrier_passed(app: &AppState, batch_id: i64, round: i64) {
    app.batch_barrier_passed
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert((batch_id, round));
}

fn clear_barrier_marks(app: &AppState, batch_id: i64) {
    app.batch_barrier_passed
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(b, _)| *b != batch_id);
}

fn cleanup_batch_staging(app: &Arc<AppState>, product: &str, batch_id: i64) {
    let app = app.clone();
    let product = product.to_string();
    tokio::spawn(async move {
        let root = app.result_dir_for_or_default(&product).await;
        let dir = root.join("batches").join(batch_id.to_string());
        match tokio::fs::remove_dir_all(&dir).await {
            Ok(()) => tracing::info!(batch_id, "Batch staging removed"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(
                batch_id,
                path = %dir.display(),
                error = %e,
                "Failed to remove batch staging"
            ),
        }
    });
}

async fn try_recovery_round(
    app: &Arc<AppState>,
    batch: &BatchRecord,
    product: &str,
) -> crbs_core::Result<bool> {
    let store = &app.state_store;
    let summary = store.batch_item_summary(batch.id).await?;
    if summary.failed == 0 {
        return Ok(false);
    }
    let budget = recovery_budget(app, product).await;
    let mut items = Vec::new();
    for r in store.batch_rounds(batch.id).await? {
        items.extend(store.items_in_round(batch.id, r).await?);
    }
    let candidates = recovery_candidates(&items, budget);
    if candidates.is_empty() {
        return Ok(false);
    }
    let reset = store.reset_items_to_pending(batch.id, &candidates).await?;
    if reset > 0 {
        info!(
            batch_id = batch.id,
            reset = reset,
            budget = budget,
            "Batch recovery round: failed items re-queued"
        );
    }
    Ok(reset > 0)
}

async fn recovery_budget(app: &Arc<AppState>, product: &str) -> usize {
    app.state_store
        .resolve_any_product_by_name(product)
        .await
        .ok()
        .and_then(|r| r.config.chain_max_recovery_rounds)
        .unwrap_or(app.crbs_config.chain_max_recovery_rounds)
}

fn recovery_candidates(items: &[BatchItemRecord], max_recovery_rounds: usize) -> Vec<i64> {
    let round_clean: HashMap<i64, bool> = {
        let mut m: HashMap<i64, bool> = HashMap::new();
        for i in items {
            let e = m.entry(i.round).or_insert(true);
            *e = *e && i.state == "succeeded";
        }
        m
    };
    items
        .iter()
        .filter(|i| i.state == "failed")
        .filter(|i| (i.attempt as usize) < max_recovery_rounds)
        // 候选轮以下每轮须全 succeeded（更高轮不参与判定）。
        .filter(|i| round_clean.iter().all(|(r, clean)| *r >= i.round || *clean))
        .map(|i| i.id)
        .collect()
}

async fn finish_batch_if_done(
    app: &Arc<AppState>,
    batch: &BatchRecord,
    summary: &crbs_core::BatchProgress,
    report: &mut TickReport,
) -> crbs_core::Result<()> {
    let status = if summary.failed == 0 {
        "completed"
    } else {
        "partial"
    };
    let notes = format!(
        "finished: {} succeeded, {} failed, {} skipped, {} cancelled",
        summary.succeeded,
        summary.failed,
        summary.dep_skipped + summary.skipped_conflict + summary.arch_skipped,
        summary.cancelled
    );
    match app
        .state_store
        .finish_batch(batch.id, status, Some(&notes))
        .await
    {
        Ok(()) => {
            info!(batch_id = batch.id, status = status, "Batch finished");
            report.finished += 1;
            clear_barrier_marks(app, batch.id);
            Ok(())
        }

        Err(CrbsError::Conflict { .. }) => {
            debug!(batch_id = batch.id, "Batch already terminal when finishing");
            clear_barrier_marks(app, batch.id);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

async fn abort_batch(
    app: &Arc<AppState>,
    batch: &BatchRecord,
    report: &mut TickReport,
) -> crbs_core::Result<()> {
    let store = &app.state_store;
    warn!(batch_id = batch.id, "Aborting batch (on_failure=abort)");
    let (_, task_ids) = store
        .fail_unfinished_items(
            batch.id,
            "batch_aborted",
            "on_failure=abort: aborted after first item failure",
        )
        .await?;
    for task_id in task_ids {
        cancel_task_builds(app, task_id).await;
    }
    match store
        .finish_batch(
            batch.id,
            "failed",
            Some("aborted: on_failure=abort after first item failure"),
        )
        .await
    {
        Ok(()) => {
            report.finished += 1;
            info!(batch_id = batch.id, "Batch aborted and finished failed");
        }
        Err(CrbsError::Conflict { .. }) => {
            debug!(batch_id = batch.id, "Batch already terminal when aborting");
        }
        Err(e) => return Err(e),
    }
    clear_barrier_marks(app, batch.id);
    Ok(())
}

async fn sweep_orphan_batches(app: &Arc<AppState>, report: &mut TickReport) {
    let stale = match app
        .state_store
        .list_batches_in_status(&["preparing", "planning"])
        .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!(error = ?e, "Orphan batch sweep: list preparing/planning failed");
            return;
        }
    };
    for batch in stale {
        if !created_before_grace(&batch.created_at) {
            continue;
        }

        match app
            .state_store
            .get_app_meta(&super::batch_heartbeat_key(batch.id))
            .await
        {
            Ok(Some(ts)) => {
                let fresh = ts
                    .parse::<i64>()
                    .ok()
                    .map(|t| chrono::Utc::now().timestamp() - t < super::BATCH_HEARTBEAT_STALE_SECS)
                    .unwrap_or(false);
                if fresh {
                    continue;
                }
            }
            Ok(None) => {}
            Err(e) => {
                warn!(
                    batch_id = batch.id,
                    error = ?e,
                    "batch heartbeat read failed; deferring reap to next sweep"
                );
                continue;
            }
        }
        info!(
            batch_id = batch.id,
            status = %batch.status,
            "Reaping interrupted batch (preparing/planning beyond grace)"
        );
        if let Err(e) = super::plan::take_failed_and_clear_items(&app.state_store, batch.id).await {
            warn!(
                batch_id = batch.id,
                error = ?e,
                "Orphan batch sweep: normalize items failed; retrying next tick"
            );
            continue;
        }
        if let Err(e) = app
            .state_store
            .finish_batch(
                batch.id,
                "failed",
                Some("interrupted: hub restart or stuck prepare/plan (orphan sweep)"),
            )
            .await
        {
            warn!(
                batch_id = batch.id,
                error = ?e,
                "Orphan batch sweep: finish failed; retrying next tick"
            );
            continue;
        }
        report.finished += 1;
    }

    match app
        .state_store
        .list_app_meta_keys_by_prefix(super::BATCH_HEARTBEAT_KEY_PREFIX)
        .await
    {
        Ok(keys) => {
            for key in keys {
                let Some(id) = key
                    .strip_prefix(super::BATCH_HEARTBEAT_KEY_PREFIX)
                    .and_then(|s| s.parse::<i64>().ok())
                else {
                    continue;
                };

                let active = matches!(
                    app.state_store.get_batch(id).await,
                    Ok(Some(b)) if b.status == "preparing" || b.status == "planning"
                );
                if active {
                    continue;
                }
                if let Err(e) = app.state_store.delete_app_meta(&key).await {
                    warn!(
                        key = %key,
                        error = ?e,
                        "Orphan batch sweep: heartbeat key GC failed; retrying next tick"
                    );
                }
            }
        }
        Err(e) => {
            warn!(error = ?e, "Orphan batch sweep: list heartbeat keys failed");
        }
    }
}

fn created_before_grace(created_at: &str) -> bool {
    match crbs_core::util::parse_db_time(created_at) {
        Some(t) => {
            let grace =
                chrono::Duration::from_std(ORPHAN_BATCH_GRACE).unwrap_or(chrono::Duration::MAX);
            chrono::Utc::now().naive_utc().signed_duration_since(t) > grace
        }
        None => false,
    }
}

fn is_terminal_batch_error(e: &crbs_core::error::CrbsError) -> bool {
    matches!(
        e,
        crbs_core::error::CrbsError::ValidationFailed { .. }
            | crbs_core::error::CrbsError::ProductChainInvalid { .. }
            | crbs_core::error::CrbsError::NotFound { .. }
    )
}

async fn resolve_batch_product(
    app: &Arc<AppState>,
    batch: &BatchRecord,
    report: &mut TickReport,
) -> crbs_core::Result<String> {
    let unresolved = |reason: String| -> CrbsError { CrbsError::Internal(reason) };
    let Some(product_id) = batch.product_id else {
        let reason = format!("batch {} has no product; cannot drive", batch.id);
        close_unreadable_batch(app, batch, &reason, report).await;
        return Err(unresolved(reason));
    };
    match app.state_store.get_product_by_id(product_id).await? {
        Some(p) => Ok(p.name),
        None => {
            let reason = format!("product id={product_id} of batch {} not found", batch.id);
            close_unreadable_batch(app, batch, &reason, report).await;
            Err(unresolved(reason))
        }
    }
}

async fn close_unreadable_batch(
    app: &Arc<AppState>,
    batch: &BatchRecord,
    reason: &str,
    report: &mut TickReport,
) {
    let store = &app.state_store;
    warn!(
        batch_id = batch.id,
        reason = reason,
        "Closing batch with unreadable product"
    );
    let task_ids = match store
        .fail_unfinished_items(batch.id, "batch_unreadable", reason)
        .await
    {
        Ok((_, task_ids)) => task_ids,
        Err(e) => {
            warn!(batch_id = batch.id, error = ?e, "Sweep unreadable batch items failed");
            return;
        }
    };
    for task_id in task_ids {
        cancel_task_builds(app, task_id).await;
    }
    if let Err(e) = store.finish_batch(batch.id, "failed", Some(reason)).await {
        warn!(batch_id = batch.id, error = ?e, "Finish unreadable batch failed");
        return;
    }
    report.finished += 1;
    clear_barrier_marks(app, batch.id);
}

async fn cancel_task_builds(app: &Arc<AppState>, task_id: i64) {
    let store = &app.state_store;
    let children = match store.get_builds_by_task_id(task_id).await {
        Ok(c) => c,
        Err(e) => {
            warn!(task_id = task_id, error = ?e, "List task builds for cancel failed");
            return;
        }
    };
    for build in children {
        if build_phase_is_terminal(&build.phase) {
            continue;
        }
        let token = app.active_builds.lock().await.get(&build.id).cloned();
        match token {
            Some(cancel) => cancel.cancel(),
            None => {
                if let Err(e) = cancel_distributed_build(app, build.id).await {
                    if !matches!(e, ApiError::Conflict(_)) {
                        warn!(
                            task_id = task_id,
                            build_id = build.id,
                            error = ?e,
                            "Cancel task child build failed"
                        );
                    }
                }
            }
        }
    }
    if let Err(e) = store.finalize_cancelled_task(task_id).await {
        warn!(task_id = task_id, error = ?e, "Finalize cancelled task failed");
    }
}

/// running：先软取消 released 项的 task（worker 上报时生效），再统一 cancelled 未终态项
/// 并 finish（计数同事务同步，对账成立）；preparing/planning 的 total_items 恒 0，先清计划
/// 归零再 finish，否则计数漂移被对账拒绝。鉴权/审计由路由层管。
pub(crate) async fn cancel_batch(
    app: &Arc<AppState>,
    batch_id: i64,
    operator: &str,
) -> Result<(), ApiError> {
    let store = &app.state_store;
    let batch = store
        .get_batch(batch_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::NotFound(format!("batch {batch_id} not found")))?;
    if !matches!(batch.status.as_str(), "preparing" | "planning" | "running") {
        return Err(ApiError::Conflict(format!(
            "batch {batch_id} is already terminal (status '{}'); nothing to cancel",
            batch.status
        )));
    }

    if batch.status == "running" {
        let (_, task_ids) = store
            .cancel_unfinished_items(
                batch_id,
                "batch_cancelled",
                &format!("cancelled by {operator}"),
            )
            .await
            .map_err(ApiError::from)?;

        for task_id in task_ids {
            cancel_task_builds(app, task_id).await;
        }
    } else {
        super::plan::take_failed_and_clear_items(store, batch_id)
            .await
            .map_err(ApiError::from)?;
    }
    store
        .finish_batch(
            batch_id,
            "cancelled",
            Some(&format!("cancelled by {operator}")),
        )
        .await
        .map_err(ApiError::from)?;
    match resolve_batch_product(app, &batch, &mut TickReport::default()).await {
        Ok(product) => cleanup_batch_staging(app, &product, batch_id),
        Err(e) => warn!(
            batch_id = batch_id,
            error = ?e,
            "Batch staging cleanup skipped: product resolution failed"
        ),
    }
    clear_barrier_marks(app, batch_id);
    info!(batch_id = batch_id, operator = operator, "Batch cancelled");
    Ok(())
}

pub(crate) fn spawn_batch_driver(app: Arc<AppState>, cancel: CancellationToken) {
    spawn_supervised_loop("batch_driver", cancel, move |cancel| {
        let app = app.clone();
        async move { run_batch_driver_loop(app, cancel).await }
    });
}

async fn run_batch_driver_loop(app: Arc<AppState>, cancel: CancellationToken) {
    info!("Batch driver started");
    loop {
        if cancel.is_cancelled() {
            break;
        }
        match batch_driver_tick(&app).await {
            Ok(report) => {
                if report != TickReport::default() {
                    info!(
                        released = report.released,
                        reconciled = report.reconciled,
                        advanced_round = report.advanced_round,
                        barrier_ran = report.barrier_ran,
                        finished = report.finished,
                        "Batch driver tick"
                    );
                }
            }
            Err(e) => warn!(error = %e, "Batch driver tick failed"),
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(BATCH_DRIVER_TICK_SECS)) => {}
            _ = app.worker_notify.notified() => {}
            _ = cancel.cancelled() => {
                info!("Batch driver shutting down");
                break;
            }
        }
    }
}

fn truncate_chars(s: &str) -> String {
    s.chars().take(ITEM_ERROR_MAX_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crbs_core::config::ServerConfig;
    use crbs_core::{BatchInsert, BuildInsert, NewBatchItem, StateStore};

    use crate::test_support::{seed_product, setup_app};

    async fn seed_running_batch(
        store: &StateStore,
        product_id: i64,
        arch_targets: Option<&str>,
        on_failure: &str,
        total: i64,
    ) -> i64 {
        let id = store
            .insert_batch(BatchInsert {
                product_id: Some(product_id),
                created_by: None,
                source_repo_url: "https://example.com/repo",
                dist: None,
                arch_targets_json: arch_targets,
                on_failure,
                force_all: false,
                request_json: None,
            })
            .await
            .unwrap();
        store.set_batch_planning(id).await.unwrap();
        store.set_batch_running(id, total).await.unwrap();
        id
    }

    async fn seed_planning_batch(store: &StateStore, product_id: i64) -> i64 {
        let id = store
            .insert_batch(BatchInsert {
                product_id: Some(product_id),
                created_by: None,
                source_repo_url: "https://example.com/repo",
                dist: None,
                arch_targets_json: None,
                on_failure: "continue",
                force_all: false,
                request_json: None,
            })
            .await
            .unwrap();
        store.set_batch_planning(id).await.unwrap();
        id
    }

    fn stage_fake_srpm(tmp: &tempfile::TempDir, batch_id: i64, nevra: &str) -> String {
        let dir = tmp
            .path()
            .join("results")
            .join("batches")
            .join(batch_id.to_string())
            .join("srpms");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(format!("{nevra}.rpm"));
        std::fs::write(&p, b"fake-srpm-bytes").unwrap();
        p.display().to_string()
    }

    async fn seed_pending_item(
        store: &StateStore,
        tmp: &tempfile::TempDir,
        batch_id: i64,
        pkg: &str,
        round: i64,
        staged: bool,
    ) -> BatchItemRecord {
        let nevra = format!("{pkg}-1.0-1.el9.src");
        let staging = if staged {
            Some(stage_fake_srpm(tmp, batch_id, &nevra))
        } else {
            None
        };
        store
            .insert_batch_items(
                batch_id,
                &[NewBatchItem {
                    pkg_name: pkg,
                    srpm_nevra: Some(&nevra),
                    srpm_staging_path: staging.as_deref(),
                    round,
                }],
            )
            .await
            .unwrap();
        store
            .items_in_state(batch_id, "pending")
            .await
            .unwrap()
            .into_iter()
            .find(|i| i.pkg_name == pkg)
            .unwrap()
    }

    async fn seed_terminal_item(
        store: &StateStore,
        batch_id: i64,
        pkg: &str,
        state: &str,
    ) -> BatchItemRecord {
        let task_id = crate::test_support::seed_task(store, "p1", pkg).await;
        let item = store
            .items_in_state(batch_id, "pending")
            .await
            .unwrap()
            .into_iter()
            .find(|i| i.pkg_name == pkg)
            .unwrap();
        store
            .mark_item_released(batch_id, item.id, task_id)
            .await
            .unwrap();
        store
            .mark_item_terminal(batch_id, item.id, state, None, None)
            .await
            .unwrap();
        store
            .items_in_state(batch_id, state)
            .await
            .unwrap()
            .into_iter()
            .find(|i| i.id == item.id)
            .unwrap()
    }

    async fn seed_released_item_with_builds(
        store: &StateStore,
        batch_id: i64,
        pkg: &str,
        arches: &[&str],
    ) -> (i64, Vec<i64>) {
        let task_id = crate::test_support::seed_task(store, "p1", pkg).await;
        let item = store
            .items_in_state(batch_id, "pending")
            .await
            .unwrap()
            .into_iter()
            .find(|i| i.pkg_name == pkg)
            .unwrap();
        store
            .mark_item_released(batch_id, item.id, task_id)
            .await
            .unwrap();
        let mut ids = Vec::new();
        for arch in arches {
            ids.push(
                store
                    .insert_build(BuildInsert {
                        product: "p1",
                        pkg_name: pkg,
                        phase: "pending",
                        backend: "chroot",
                        user: "batch",
                        arch: Some(arch),
                        task_id: Some(task_id),
                        ..Default::default()
                    })
                    .await
                    .unwrap(),
            );
        }
        (task_id, ids)
    }

    async fn batch_status(store: &StateStore, batch_id: i64) -> String {
        store.get_batch(batch_id).await.unwrap().unwrap().status
    }

    async fn item_in_state(
        store: &StateStore,
        batch_id: i64,
        pkg: &str,
        state: &str,
    ) -> Option<BatchItemRecord> {
        store
            .items_in_state(batch_id, state)
            .await
            .unwrap()
            .into_iter()
            .find(|i| i.pkg_name == pkg)
    }

    fn item(id: i64, round: i64, state: &str, attempt: i64) -> BatchItemRecord {
        BatchItemRecord {
            id,
            batch_id: 1,
            pkg_name: format!("p{id}"),
            srpm_nevra: None,
            srpm_staging_path: None,
            round,
            state: state.to_string(),
            attempt,
            task_id: None,
            error_code: None,
            error_message: None,
            updated_at: String::new(),
        }
    }

    #[test]
    fn recovery_candidates_round_approximation_and_budget() {
        let items = vec![
            item(1, 0, "succeeded", 0),
            item(2, 0, "failed", 0),
            item(3, 1, "failed", 0),
            item(4, 1, "failed", 5),
            item(5, 2, "succeeded", 0),
        ];
        let clean = vec![
            item(1, 0, "succeeded", 0),
            item(3, 1, "failed", 0),
            item(4, 1, "failed", 5),
            item(6, 1, "skipped_conflict", 0),
            item(7, 2, "failed", 0),
        ];
        let got = recovery_candidates(&items, 1);
        assert_eq!(got, vec![2], "failed lower round cascades out");

        let got = recovery_candidates(&clean, 1);
        assert_eq!(got, vec![3]);
        assert!(recovery_candidates(&clean, 0).is_empty());
    }

    #[test]
    fn created_before_grace_expires_only_old_frames() {
        let old = (chrono::Utc::now() - chrono::Duration::minutes(31))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        let fresh = (chrono::Utc::now() - chrono::Duration::minutes(1))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        assert!(created_before_grace(&old));
        assert!(!created_before_grace(&fresh));
        assert!(!created_before_grace("not-a-time"), "bad frame never reaps");
    }

    #[tokio::test]
    async fn tick_releases_are_capped_per_tick() {
        let (app, tmp) = setup_app().await;
        let store = &app.state_store;
        seed_product(store, 1, "p1").await;
        let batch = seed_running_batch(store, 1, Some(r#"["x86_64"]"#), "continue", 203).await;
        for i in 0..203 {
            seed_pending_item(store, &tmp, batch, &format!("pkg-{i:03}"), 0, true).await;
        }

        let r1 = batch_driver_tick(&app).await.unwrap();
        assert_eq!(r1.released, 200, "first tick caps at 200");
        assert_eq!(
            store.items_in_state(batch, "pending").await.unwrap().len(),
            3
        );

        let r2 = batch_driver_tick(&app).await.unwrap();
        assert_eq!(r2.released, 3, "second tick drains the remainder");
        assert!(store
            .items_in_state(batch, "pending")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn tick_release_creates_background_task_with_arch_fanout() {
        let (app, tmp) = setup_app().await;
        let store = &app.state_store;
        seed_product(store, 1, "p1").await;
        let batch =
            seed_running_batch(store, 1, Some(r#"["x86_64","aarch64"]"#), "continue", 1).await;
        seed_pending_item(store, &tmp, batch, "hello", 0, true).await;

        let report = batch_driver_tick(&app).await.unwrap();
        assert_eq!(report.released, 1);

        let item = item_in_state(store, batch, "hello", "released")
            .await
            .unwrap();
        let task_id = item.task_id.unwrap();
        let task_priority: i64 = sqlx::query_scalar("SELECT priority FROM tasks WHERE id = $1")
            .bind(task_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(task_priority, -1, "task carries PRIORITY_BACKGROUND");

        let rows: Vec<(i64, i64)> =
            sqlx::query_as("SELECT priority, batch_id FROM builds WHERE task_id = $1 ORDER BY id")
                .bind(task_id)
                .fetch_all(store.pool())
                .await
                .unwrap();
        assert_eq!(rows.len(), 2, "one build per target arch");
        for (priority, batch_id) in &rows {
            assert_eq!(*priority, -1, "each build is background priority");
            assert_eq!(*batch_id, batch, "builds attributed to the batch");
        }
    }

    #[tokio::test]
    async fn tick_reconciles_released_item_from_task_terminal_state() {
        let (app, _tmp) = setup_app().await;
        let store = &app.state_store;
        seed_product(store, 1, "p1").await;
        let batch = seed_running_batch(store, 1, Some(r#"["x86_64"]"#), "continue", 1).await;
        store
            .insert_batch_items(
                batch,
                &[NewBatchItem {
                    pkg_name: "alpha",
                    srpm_nevra: Some("alpha-1.0-1.el9.src"),
                    srpm_staging_path: None,
                    round: 0,
                }],
            )
            .await
            .unwrap();
        let (_task_id, builds) =
            seed_released_item_with_builds(store, batch, "alpha", &["x86_64"]).await;
        for b in &builds {
            store.complete_build(*b, "succeeded", None).await.unwrap();
        }

        let report = batch_driver_tick(&app).await.unwrap();
        assert_eq!(report.reconciled, 1);
        assert_eq!(
            report.finished, 1,
            "single-item batch finishes on reconcile"
        );
        assert!(item_in_state(store, batch, "alpha", "succeeded")
            .await
            .is_some());
        assert_eq!(batch_status(store, batch).await, "completed");
    }

    #[tokio::test]
    async fn tick_marks_item_skipped_conflict_on_active_duplicate() {
        let (app, tmp) = setup_app().await;
        let store = &app.state_store;
        seed_product(store, 1, "p1").await;
        let batch = seed_running_batch(store, 1, Some(r#"["x86_64"]"#), "continue", 1).await;
        let item = seed_pending_item(store, &tmp, batch, "hello", 0, true).await;

        let staging = PathBuf::from(item.srpm_staging_path.clone().unwrap());
        let dup_pkg = crbs_core::util::srpm_display_name(&staging).to_string();
        let other_task = crate::test_support::seed_task(store, "p1", &dup_pkg).await;
        store
            .insert_build(BuildInsert {
                product: "p1",
                pkg_name: &dup_pkg,
                phase: "pending",
                backend: "chroot",
                user: "someone",
                arch: Some("x86_64"),
                task_id: Some(other_task),
                ..Default::default()
            })
            .await
            .unwrap();

        let report = batch_driver_tick(&app).await.unwrap();
        assert_eq!(report.released, 0, "conflicting item is not released");
        let skipped = item_in_state(store, batch, "hello", "skipped_conflict")
            .await
            .expect("item must close as skipped_conflict");
        assert_eq!(skipped.error_code.as_deref(), Some("active_build_conflict"));

        assert_eq!(batch_status(store, batch).await, "completed");
    }

    async fn seed_valid_product(store: &crbs_core::StateStore, id: i64, name: &str) {
        seed_product(store, id, name).await;
        let cfg = crbs_core::config::ProductConfig {
            base_packages: vec!["bash".into()],
            repos: vec![crbs_core::config::RepoConfig {
                name: "base".into(),
                baseurl: "http://example/repo".into(),
                gpgcheck: false,
                ..Default::default()
            }],
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        sqlx::query("UPDATE products SET config_json = $1 WHERE id = $2")
            .bind(json)
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn tick_barrier_assembles_between_rounds_before_releasing_next() {
        let (app, tmp) = setup_app().await;
        let store = &app.state_store;
        seed_valid_product(store, 1, "p1").await;
        let batch = seed_running_batch(store, 1, Some(r#"["x86_64"]"#), "continue", 2).await;
        store
            .insert_batch_items(
                batch,
                &[
                    NewBatchItem {
                        pkg_name: "base",
                        srpm_nevra: Some("base-1.0-1.el9.src"),
                        srpm_staging_path: None,
                        round: 0,
                    },
                    NewBatchItem {
                        pkg_name: "app",
                        srpm_nevra: Some("app-1.0-1.el9.src"),
                        srpm_staging_path: Some(&stage_fake_srpm(&tmp, batch, "app-1.0-1.el9.src")),
                        round: 1,
                    },
                ],
            )
            .await
            .unwrap();
        seed_terminal_item(store, batch, "base", "succeeded").await;

        let r1 = batch_driver_tick(&app).await.unwrap();
        assert!(r1.barrier_ran, "barrier must run before releasing round 1");
        assert_eq!(
            r1.released, 0,
            "round 1 must not release on the barrier tick"
        );
        assert!(item_in_state(store, batch, "app", "pending")
            .await
            .is_some());

        let r2 = batch_driver_tick(&app).await.unwrap();
        assert!(!r2.barrier_ran);
        assert_eq!(r2.released, 1);
        assert!(item_in_state(store, batch, "app", "released")
            .await
            .is_some());
    }

    #[tokio::test]
    async fn tick_barrier_assemble_creates_repo_packages_dir() {
        let (app, tmp) = setup_app().await;
        let store = &app.state_store;
        seed_valid_product(store, 1, "p1").await;
        let batch = seed_running_batch(store, 1, Some(r#"["x86_64"]"#), "continue", 2).await;
        store
            .insert_batch_items(
                batch,
                &[
                    NewBatchItem {
                        pkg_name: "base",
                        srpm_nevra: Some("base-1.0-1.el9.src"),
                        srpm_staging_path: None,
                        round: 0,
                    },
                    NewBatchItem {
                        pkg_name: "app",
                        srpm_nevra: Some("app-1.0-1.el9.src"),
                        srpm_staging_path: Some(&stage_fake_srpm(&tmp, batch, "app-1.0-1.el9.src")),
                        round: 1,
                    },
                ],
            )
            .await
            .unwrap();
        seed_terminal_item(store, batch, "base", "succeeded").await;

        let arch_repo = app
            .result_dir_for_or_default("p1")
            .await
            .join("_repo")
            .join("p1")
            .join("x86_64");
        tokio::fs::create_dir_all(&arch_repo).await.unwrap();

        let _ = batch_driver_tick(&app).await;
        assert!(
            arch_repo.join("Packages").is_dir(),
            "assemble must converge Packages/ before createrepo"
        );
    }

    #[tokio::test]
    async fn tick_recovery_resets_failed_and_finishes_partial_at_budget() {
        let (app, tmp) = setup_app().await;
        let store = &app.state_store;
        seed_product(store, 1, "p1").await;
        let batch = seed_running_batch(store, 1, Some(r#"["x86_64"]"#), "continue", 1).await;
        seed_pending_item(store, &tmp, batch, "flaky", 0, true).await;
        let failed = seed_terminal_item(store, batch, "flaky", "failed").await;
        assert_eq!(failed.attempt, 0);

        batch_driver_tick(&app).await.unwrap();
        let pending = item_in_state(store, batch, "flaky", "pending")
            .await
            .expect("failed item re-queued");
        assert_eq!(pending.attempt, 1);

        let r = batch_driver_tick(&app).await.unwrap();
        assert_eq!(r.released, 1);
        let released = item_in_state(store, batch, "flaky", "released")
            .await
            .unwrap();
        let builds = store
            .get_builds_by_task_id(released.task_id.unwrap())
            .await
            .unwrap();
        for b in &builds {
            store
                .complete_build_with_error(b.id, "failed", None, Some("boom again"))
                .await
                .unwrap();
        }

        batch_driver_tick(&app).await.unwrap();
        assert!(item_in_state(store, batch, "flaky", "failed")
            .await
            .is_some());
        assert_eq!(batch_status(store, batch).await, "partial");
    }

    #[tokio::test]
    async fn tick_recovery_cascade_excludes_failed_with_dirty_lower_round() {
        let (app, _tmp) = setup_app().await;
        let store = &app.state_store;
        seed_product(store, 1, "p1").await;
        let batch = seed_running_batch(store, 1, Some(r#"["x86_64"]"#), "continue", 2).await;
        store
            .insert_batch_items(
                batch,
                &[
                    NewBatchItem {
                        pkg_name: "low",
                        srpm_nevra: Some("low-1.0-1.el9.src"),
                        srpm_staging_path: None,
                        round: 0,
                    },
                    NewBatchItem {
                        pkg_name: "high",
                        srpm_nevra: Some("high-1.0-1.el9.src"),
                        srpm_staging_path: None,
                        round: 1,
                    },
                ],
            )
            .await
            .unwrap();
        seed_terminal_item(store, batch, "low", "failed").await;
        seed_terminal_item(store, batch, "high", "failed").await;

        batch_driver_tick(&app).await.unwrap();
        assert!(
            item_in_state(store, batch, "low", "pending")
                .await
                .is_some(),
            "lowest-round failed item re-queues"
        );
        assert!(
            item_in_state(store, batch, "high", "failed")
                .await
                .is_some(),
            "higher-round failed item stays failed (cascade)"
        );
    }

    #[tokio::test]
    async fn tick_aborts_batch_on_first_reconciled_failure() {
        let (app, tmp) = setup_app().await;
        let store = &app.state_store;
        seed_product(store, 1, "p1").await;
        let batch = seed_running_batch(store, 1, Some(r#"["x86_64"]"#), "abort", 2).await;
        seed_pending_item(store, &tmp, batch, "bad", 0, true).await;
        seed_pending_item(store, &tmp, batch, "good", 0, true).await;

        batch_driver_tick(&app).await.unwrap();
        assert_eq!(
            store.items_in_state(batch, "released").await.unwrap().len(),
            2
        );

        let bad = item_in_state(store, batch, "bad", "released")
            .await
            .unwrap();
        for b in store
            .get_builds_by_task_id(bad.task_id.unwrap())
            .await
            .unwrap()
        {
            store
                .complete_build_with_error(b.id, "failed", None, Some("nope"))
                .await
                .unwrap();
        }

        let report = batch_driver_tick(&app).await.unwrap();
        assert_eq!(report.finished, 1);
        assert_eq!(batch_status(store, batch).await, "failed");
        let good = item_in_state(store, batch, "good", "failed")
            .await
            .expect("in-flight item swept on abort");
        assert_eq!(good.error_code.as_deref(), Some("batch_aborted"));
        let good_task = good.task_id.unwrap();
        for b in store.get_builds_by_task_id(good_task).await.unwrap() {
            assert_eq!(b.phase, "cancelled", "in-flight build cancelled on abort");
        }
    }

    #[tokio::test]
    async fn cancel_batch_cascades_and_is_idempotent() {
        let (app, tmp) = setup_app().await;
        let store = &app.state_store;
        seed_product(store, 1, "p1").await;
        let batch = seed_running_batch(store, 1, Some(r#"["x86_64"]"#), "continue", 2).await;
        seed_pending_item(store, &tmp, batch, "flying", 0, true).await;
        seed_pending_item(store, &tmp, batch, "waiting", 0, true).await;
        batch_driver_tick(&app).await.unwrap();
        assert_eq!(
            store.items_in_state(batch, "released").await.unwrap().len(),
            2
        );

        cancel_batch(&app, batch, "alice").await.unwrap();
        assert_eq!(batch_status(store, batch).await, "cancelled");
        for pkg in ["flying", "waiting"] {
            let item = item_in_state(store, batch, pkg, "cancelled")
                .await
                .unwrap_or_else(|| panic!("{pkg} must be swept to cancelled"));
            assert!(item.error_message.unwrap().contains("alice"));
        }
        let flying_task = sqlx::query_scalar::<_, i64>(
            "SELECT task_id FROM batch_items WHERE batch_id = $1 AND pkg_name = 'flying'",
        )
        .bind(batch)
        .fetch_one(store.pool())
        .await
        .unwrap();
        for b in store.get_builds_by_task_id(flying_task).await.unwrap() {
            assert_eq!(b.phase, "cancelled");
        }

        let err = cancel_batch(&app, batch, "alice").await.unwrap_err();
        assert!(matches!(err, ApiError::Conflict(_)), "{err:?}");

        let planning = seed_planning_batch(store, 1).await;
        store
            .insert_failed_batch_items(
                planning,
                &[crbs_core::FailedBatchItem {
                    pkg_name: "wet",
                    srpm_nevra: None,
                    error_code: "srpm_download_failed",
                    error_message: "HTTP 503",
                }],
            )
            .await
            .unwrap();
        cancel_batch(&app, planning, "alice").await.unwrap();
        assert_eq!(batch_status(store, planning).await, "cancelled");
        assert_eq!(
            store.batch_item_summary(planning).await.unwrap().total(),
            0,
            "plan cleared on planning-batch cancel"
        );
        let rec = store.get_batch(planning).await.unwrap().unwrap();
        assert_eq!(rec.n_failed, 0, "prepare-time failure counter normalized");
    }

    #[tokio::test]
    async fn tick_reaps_stale_planning_batch_and_keeps_fresh_one() {
        let (app, _tmp) = setup_app().await;
        let store = &app.state_store;
        seed_product(store, 1, "p1").await;
        seed_product(store, 2, "p2").await;
        let stale = seed_planning_batch(store, 1).await;
        let old = (chrono::Utc::now() - chrono::Duration::minutes(31))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        sqlx::query("UPDATE build_batches SET created_at = $1 WHERE id = $2")
            .bind(&old)
            .bind(stale)
            .execute(store.pool())
            .await
            .unwrap();
        let fresh = seed_planning_batch(store, 2).await;

        let report = batch_driver_tick(&app).await.unwrap();
        assert_eq!(report.finished, 1, "only the stale batch is reaped");
        assert_eq!(batch_status(store, stale).await, "failed");
        let rec = store.get_batch(stale).await.unwrap().unwrap();
        assert!(rec.notes.unwrap().contains("interrupted"));
        assert_eq!(batch_status(store, fresh).await, "planning");
    }

    #[tokio::test]
    async fn sweep_keeps_aged_batch_with_fresh_heartbeat() {
        let (app, _tmp) = setup_app().await;
        let store = &app.state_store;
        seed_product(store, 1, "p1").await;
        let batch = seed_planning_batch(store, 1).await;
        let old = (chrono::Utc::now() - chrono::Duration::minutes(31))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        sqlx::query("UPDATE build_batches SET created_at = $1 WHERE id = $2")
            .bind(&old)
            .bind(batch)
            .execute(store.pool())
            .await
            .unwrap();

        crate::server::batches::touch_batch_heartbeat(store, batch).await;
        let report = batch_driver_tick(&app).await.unwrap();
        assert_eq!(report.finished, 0, "fresh heartbeat must hold the reaper");
        assert_eq!(batch_status(store, batch).await, "planning");

        let stale_hb = (chrono::Utc::now().timestamp()
            - crate::server::batches::BATCH_HEARTBEAT_STALE_SECS
            - 60)
            .to_string();
        store
            .set_app_meta(
                &crate::server::batches::batch_heartbeat_key(batch),
                &stale_hb,
            )
            .await
            .unwrap();
        let report = batch_driver_tick(&app).await.unwrap();
        assert_eq!(report.finished, 1, "stale heartbeat lets the reaper in");
        assert_eq!(batch_status(store, batch).await, "failed");
    }

    #[tokio::test]
    async fn sweep_reclaims_heartbeat_keys_of_departed_batches() {
        let (app, _tmp) = setup_app().await;
        let store = &app.state_store;
        seed_product(store, 1, "p1").await;
        seed_product(store, 2, "p2").await;
        let live = seed_planning_batch(store, 1).await;
        store
            .set_app_meta(&crate::server::batches::batch_heartbeat_key(live), "0")
            .await
            .unwrap();

        let dead = seed_planning_batch(store, 2).await;
        store
            .finish_batch(dead, "failed", Some("test terminal"))
            .await
            .unwrap();
        store
            .set_app_meta(&crate::server::batches::batch_heartbeat_key(dead), "0")
            .await
            .unwrap();
        store.set_app_meta("batch:hb:oops", "x").await.unwrap();

        let _report = batch_driver_tick(&app).await.unwrap();
        assert!(
            store
                .get_app_meta(&crate::server::batches::batch_heartbeat_key(live))
                .await
                .unwrap()
                .is_some(),
            "preparing/planning batch keeps its heartbeat key"
        );
        assert!(
            store
                .get_app_meta(&crate::server::batches::batch_heartbeat_key(dead))
                .await
                .unwrap()
                .is_none(),
            "departed batch's heartbeat key is reclaimed"
        );
        assert!(
            store.get_app_meta("batch:hb:oops").await.unwrap().is_some(),
            "prefix-colliding non-heartbeat key untouched"
        );
    }

    #[tokio::test]
    async fn insert_items_into_terminal_batch_is_refused() {
        let (app, _tmp) = setup_app().await;
        let store = &app.state_store;
        seed_product(store, 1, "p1").await;
        let batch = store
            .insert_batch(BatchInsert {
                product_id: Some(1),
                created_by: None,
                source_repo_url: "https://example.com/repo",
                dist: None,
                arch_targets_json: None,
                on_failure: "continue",
                force_all: false,
                request_json: None,
            })
            .await
            .unwrap();
        store
            .finish_batch(batch, "cancelled", Some("test terminal"))
            .await
            .unwrap();

        let row = crbs_core::NewBatchItem {
            pkg_name: "pkg",
            srpm_nevra: Some("pkg-1.0-1"),
            srpm_staging_path: Some("/tmp/pkg-1.0-1.src.rpm"),
            round: 0,
        };
        let err = store.insert_batch_items(batch, &[row]).await.unwrap_err();
        assert!(
            err.to_string().contains("already terminal"),
            "expected terminal refusal, got: {err}"
        );
        let failed = crbs_core::FailedBatchItem {
            pkg_name: "pkg2",
            srpm_nevra: None,
            error_code: "srpm_download_failed",
            error_message: "late writer",
        };
        let err = store
            .insert_failed_batch_items(batch, &[failed])
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("already terminal"),
            "expected terminal refusal for failed items, got: {err}"
        );
    }

    #[tokio::test]
    async fn tick_picks_up_in_flight_work_across_restart() {
        let (app, tmp) = setup_app().await;
        let store = &app.state_store;
        seed_product(store, 1, "p1").await;
        let batch =
            seed_running_batch(store, 1, Some(r#"["x86_64","aarch64"]"#), "continue", 1).await;
        seed_pending_item(store, &tmp, batch, "resume", 0, true).await;

        assert_eq!(batch_driver_tick(&app).await.unwrap().released, 1);

        let app2 = Arc::new(AppState::for_test(
            store.clone(),
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let item = item_in_state(store, batch, "resume", "released")
            .await
            .unwrap();
        for b in store
            .get_builds_by_task_id(item.task_id.unwrap())
            .await
            .unwrap()
        {
            store.complete_build(b.id, "succeeded", None).await.unwrap();
        }

        let report = batch_driver_tick(&app2).await.unwrap();
        assert_eq!(report.reconciled, 1);
        assert_eq!(report.finished, 1);
        assert_eq!(batch_status(store, batch).await, "completed");
    }
}
