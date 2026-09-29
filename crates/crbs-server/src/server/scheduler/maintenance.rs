// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 调度维护循环：worker 心跳超时回收、运行任务重派与库保留。

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::server::state::AppState;

use super::spawn_supervised_loop;

/// Worker 心跳超时（秒）：超时视为离线；`assigned` 任务此时长后回收重派
/// （第一档）；worker 详情页遥测 stale 判定复用本阈值。语义孪生：crbs-core
/// state workers SQL 的 `WORKER_STALE_HEARTBEAT_SECS`（同值 120）——
/// **改其一必须同步另一个**。
pub(crate) const WORKER_HEARTBEAT_TIMEOUT_SECS: u64 = 120;
/// `running` 任务的回收阈值（秒）：双倍超时（第二档）——已开跑任务失联更久
/// 才重派，防心跳抖动/瞬时过载把仍在构建的任务重复派发、两台交错上传同一
/// `{artifact_dir}/{build_id}/`。
pub(crate) const WORKER_RUNNING_RECLAIM_TIMEOUT_SECS: u64 = 2 * WORKER_HEARTBEAT_TIMEOUT_SECS;
/// 回收任务检查间隔（秒）。
pub(crate) const RECLAIMER_INTERVAL_SECS: u64 = 30;

/// 启动 Worker 离线任务回收器。
pub(crate) fn spawn_reclaimer(app: Arc<AppState>, cancel: CancellationToken) {
    spawn_supervised_loop("worker_reclaimer", cancel, move |cancel| {
        let app = app.clone();
        async move { run_reclaimer_loop(app, cancel).await }
    });
}

/// DB 行保留任务间隔（秒）：每天一次。
pub(crate) const DB_RETENTION_INTERVAL_SECS: u64 = 86_400;

/// 启动 DB 行保留任务：定期删除超期历史行（audit_logs/worker_tasks/builds/tasks），
/// 限住 SQLite 体积；`db_retention_days=0` 时不启动。
pub(crate) fn spawn_db_retention(app: Arc<AppState>, cancel: CancellationToken) {
    let days = app.server_config.db_retention_days;
    if days == 0 {
        info!("DB retention disabled (db_retention_days=0); telemetry pruning stays active");
        spawn_supervised_loop("telemetry_retention", cancel, move |cancel| {
            let app = app.clone();
            async move { run_telemetry_retention_loop(app, cancel).await }
        });
        return;
    }
    spawn_supervised_loop("db_retention", cancel, move |cancel| {
        let app = app.clone();
        let days = days;
        async move { run_db_retention_loop(app, days, cancel).await }
    });
}

/// 全局 retention 关闭时的遥测专用循环：14 天固定上限，独立于业务历史保留。
pub(crate) async fn run_telemetry_retention_loop(app: Arc<AppState>, cancel: CancellationToken) {
    let mut interval = tokio::time::interval(Duration::from_secs(DB_RETENTION_INTERVAL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = cancel.cancelled() => break,
        }
        match app
            .state_store
            .prune_worker_telemetry_samples_default()
            .await
        {
            Ok(n) if n > 0 => {
                info!(pruned = n, "Telemetry retention pruned old samples")
            }
            Ok(_) => {}
            Err(e) => warn!(error = %e, "Telemetry retention iteration failed"),
        }
    }
}

/// 保留任务主循环：每天执行一次 `prune_old_records`。
pub(crate) async fn run_db_retention_loop(
    app: Arc<AppState>,
    days: u64,
    cancel: CancellationToken,
) {
    info!(
        retention_days = days,
        interval_secs = DB_RETENTION_INTERVAL_SECS,
        "DB retention started"
    );

    // 迭代失败告警节流（日级档 every=2）：首败告警、隔次告警，持续故障
    // 每两天一条而非沉默 20 天。
    let mut prune_warn = crbs_core::util::WarnThrottle::new(2);

    let mut interval = tokio::time::interval(Duration::from_secs(DB_RETENTION_INTERVAL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = cancel.cancelled() => {
                info!("DB retention shutting down");
                break;
            }
        }

        match app.state_store.prune_old_records(days).await {
            Ok(stats) if stats.total() > 0 => {
                prune_warn.reset();
                info!(
                    audit_logs = stats.audit_logs,
                    worker_tasks = stats.worker_tasks,
                    builds = stats.builds,
                    tasks = stats.tasks,
                    product_history = stats.product_history,
                    worker_telemetry_samples = stats.worker_telemetry_samples,
                    "DB retention pruned old records"
                );
            }
            Ok(_) => prune_warn.reset(),
            Err(e) => {
                if prune_warn.fail() {
                    warn!(
                        error = %e,
                        consecutive_failures = prune_warn.consecutive(),
                        "DB retention iteration failed"
                    );
                }
            }
        }
    }
}

/// 过期 UI 会话清理间隔（秒）：每 6 小时。刻意不挂 `db_retention_days` 的
/// prune——凭据过期与业务历史保留语义不同，retention=0 不应连坐禁用凭据
/// 清理（否则 session 表无限积累）。
pub(crate) const SESSION_CLEANUP_INTERVAL_SECS: u64 = 6 * 3600;

/// 启动过期会话清理任务：删除 `expires_at` 已过期的 sessions 行；
/// **不受任何配置开关控制**。
pub(crate) fn spawn_session_cleanup(app: Arc<AppState>, cancel: CancellationToken) {
    spawn_supervised_loop("session_cleanup", cancel, move |cancel| {
        let app = app.clone();
        async move { run_session_cleanup_loop(app, cancel).await }
    });
}

/// 会话清理主循环：每 6 小时执行一次 [`session_cleanup_tick`]。
pub(crate) async fn run_session_cleanup_loop(app: Arc<AppState>, cancel: CancellationToken) {
    info!(
        interval_secs = SESSION_CLEANUP_INTERVAL_SECS,
        "Expired session cleanup started"
    );

    // 迭代失败告警节流（every=2：6h 档一次 warn）。
    let mut cleanup_warn = crbs_core::util::WarnThrottle::new(2);

    let mut interval = tokio::time::interval(Duration::from_secs(SESSION_CLEANUP_INTERVAL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = cancel.cancelled() => {
                info!("Expired session cleanup shutting down");
                break;
            }
        }

        match session_cleanup_tick(&app).await {
            Ok((removed_sessions, removed_tokens))
                if removed_sessions > 0 || removed_tokens > 0 =>
            {
                cleanup_warn.reset();
                info!(
                    removed_sessions,
                    removed_tokens, "Expired sessions and tokens pruned"
                );
            }
            Ok(_) => cleanup_warn.reset(),
            Err(e) => {
                if cleanup_warn.fail() {
                    warn!(
                        error = %e,
                        consecutive_failures = cleanup_warn.consecutive(),
                        "Expired session cleanup iteration failed"
                    );
                }
            }
        }
    }
}

/// 单次清理：删除全部 `expires_at <= now` 的 sessions 行与过期/已撤销的
/// user_tokens 行，返回 `(删除 sessions 行数, 删除 tokens 行数)`。
pub(crate) async fn session_cleanup_tick(
    app: &Arc<AppState>,
) -> Result<(u64, u64), crbs_core::error::CrbsError> {
    let now = chrono::Utc::now().to_rfc3339();
    let removed_sessions = app.state_store.delete_all_expired_sessions(&now).await?;
    let removed_tokens = app.state_store.delete_expired_user_tokens(&now).await?;
    Ok((removed_sessions, removed_tokens))
}

/// 孤儿任务清扫间隔（秒）。
pub(crate) const ORPHAN_SWEEP_INTERVAL_SECS: u64 = 60;
/// 孤儿判定宽限（分钟）：pending 且 0 构建超此时长才判孤儿（正常提交毫秒级
/// 建好 builds，5 分钟足以排除在途提交）。
pub(crate) const ORPHAN_GRACE_MINUTES: u64 = 5;
/// auto-replay 对账轮次间隔：每 30 轮（30 分钟）。启动对账（bootstrap.rs）
/// 只覆盖进程起点，运行期钩子丢失（DB 瞬断下查询失败）由本档收口——纯读 +
/// 补钩子，30 分钟足够。
pub(crate) const AUTO_REPLAY_RECONCILE_EVERY_ROUNDS: u64 = 30;

/// 启动孤儿任务清扫：定期把"0 构建的 pending 任务"标记为 failed。task 与
/// builds 展开非原子，handler 建好前出错/被取消（客户端断连）留下调度与
/// 崩溃恢复都无法拾起的行；submit 的 RAII 守护管常见场景，本清扫兜底硬崩溃。
pub(crate) fn spawn_orphan_sweeper(app: Arc<AppState>, cancel: CancellationToken) {
    spawn_supervised_loop("orphan_sweeper", cancel, move |cancel| {
        let app = app.clone();
        async move { run_orphan_sweeper_loop(app, cancel).await }
    });
}

/// 孤儿清扫主循环：每 `ORPHAN_SWEEP_INTERVAL_SECS` 一次 `sweep_orphaned_tasks`，
/// 并周期修复僵尸活跃构建；interval 首 tick 立即触发，启动即清一次存量。
pub(crate) async fn run_orphan_sweeper_loop(app: Arc<AppState>, cancel: CancellationToken) {
    info!(
        interval_secs = ORPHAN_SWEEP_INTERVAL_SECS,
        grace_minutes = ORPHAN_GRACE_MINUTES,
        "Orphan task sweeper started"
    );

    let mut interval = tokio::time::interval(Duration::from_secs(ORPHAN_SWEEP_INTERVAL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // 迭代失败告警节流（60s 档 every=20）：三个 DB 操作各自独立计数——共享
    // 实例时任一操作成功会复位其它操作的失败计数，节流形同虚设。
    let mut sweep_warn = crbs_core::util::WarnThrottle::new(20);
    let mut reconcile_warn = crbs_core::util::WarnThrottle::new(20);
    let mut zombie_repair_warn = crbs_core::util::WarnThrottle::new(20);

    let mut rounds: u64 = 0;

    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = cancel.cancelled() => {
                info!("Orphan task sweeper shutting down");
                break;
            }
        }

        match app
            .state_store
            .sweep_orphaned_tasks(ORPHAN_GRACE_MINUTES)
            .await
        {
            Ok(n) if n > 0 => {
                sweep_warn.reset();
                warn!(
                    count = n,
                    "Swept orphaned tasks (pending with no builds) to failed"
                )
            }
            Ok(_) => sweep_warn.reset(),
            Err(e) => {
                if sweep_warn.fail() {
                    warn!(
                        error = %e,
                        consecutive_failures = sweep_warn.consecutive(),
                        "Orphan task sweep iteration failed"
                    );
                }
            }
        }

        match app.state_store.reconcile_stale_task_phases().await {
            Ok(n) if n > 0 => {
                reconcile_warn.reset();
                warn!(
                    count = n,
                    "Reconciled stale task phases (all builds terminal)"
                )
            }
            Ok(_) => reconcile_warn.reset(),
            Err(e) => {
                if reconcile_warn.fail() {
                    warn!(
                        error = %e,
                        consecutive_failures = reconcile_warn.consecutive(),
                        "Stale task phase reconcile iteration failed"
                    );
                }
            }
        }

        // 兜底周期清扫：server 运行期间（非仅启动时）crbs_pid 已死的活跃构建记录，
        // 置为 failed 并释放 SharedLayer 引用，避免任务永远卡在进行状态。
        match app.state_store.repair_all_zombie_active_builds().await {
            Ok((repaired_ids, live)) if !repaired_ids.is_empty() => {
                zombie_repair_warn.reset();
                warn!(
                    repaired = repaired_ids.len(),
                    live, "Repaired zombie active builds (dead crbs_pid)"
                );
                // DB 侧翻终态的修复路径补终态钩子——重放构建翻 failed 时比对
                // 行需要钩子落库；重置回 pending 的崩溃窗口行由守卫 no-op。
                for id in repaired_ids {
                    crate::server::replay::spawn_on_build_terminal(app.clone(), id);
                }
            }
            Ok(_) => zombie_repair_warn.reset(),
            Err(e) => {
                if zombie_repair_warn.fail() {
                    warn!(
                        error = %e,
                        consecutive_failures = zombie_repair_warn.consecutive(),
                        "Zombie build repair iteration failed"
                    );
                }
            }
        }

        // 暂存 SRPM 副本 GC（60s 档）：清理终态 build 残留的
        // `{upload_dir}/{build_id}/`，防无界增长（Guard 不触发路径的兜底）。
        crate::server::staging::sweep_stale_staging(&app).await;

        // Worker 日志目录孤儿 GC（同档兜底）：`{artifact_dir}/{build_id}/` 在
        // DB 行被 prune 后失去回收链路，按"行不存在 + mtime 宽限"清理。
        crate::server::artifacts_gc::sweep_orphan_artifact_dirs(&app).await;

        // task 源码目录 GC（同档兜底）：`{result_root}/{task_id}/source/` 副本
        // 在 tasks 行被 prune 后失去回收链路，按"行不存在 + mtime 宽限"清理。
        crate::server::tasks_gc::sweep_orphan_task_dirs(&app).await;

        // hub-local 产物登记崩溃窗口 reconcile（同档兜底，详见函数注释）。
        crate::server::routes::builds::reconcile_artifact_registration(&app).await;

        rounds = rounds.wrapping_add(1);
        if rounds % AUTO_REPLAY_RECONCILE_EVERY_ROUNDS == 0 {
            reconcile_missing_auto_replay(&app).await;
        }
    }
}

/// auto-replay 创建侧对账：查"deterministic + 全 succeeded + 无 replay"的源
/// 任务并补发终态钩子（重走 maybe_auto_replay 全套门禁，幂等：已有 replay
/// 血缘的不入候选集）。列表查询失败 error + 审计留痕
/// （`auto_replay_reconcile_failure`），不中断循环——下一轮再收口。
pub(crate) async fn reconcile_missing_auto_replay(app: &Arc<AppState>) {
    match app.state_store.list_tasks_missing_auto_replay().await {
        Ok(candidates) if !candidates.is_empty() => {
            info!(
                count = candidates.len(),
                "Reconciling fully-succeeded deterministic tasks without any replay task"
            );
            for (_task_id, trigger_build_id) in candidates {
                crate::server::replay::spawn_on_build_terminal(app.clone(), trigger_build_id);
            }
        }
        Ok(_) => {}
        Err(e) => {
            error!(
                error = %e,
                "Failed to list tasks missing auto replay; skipping this round"
            );
            if let Err(audit_err) = app
                .state_store
                .audit_log(
                    "system",
                    "system",
                    "auto_replay_reconcile_failure",
                    None,
                    Some(
                        &serde_json::json!({
                            "stage": "list_tasks_missing_auto_replay",
                            "error": e.to_string(),
                        })
                        .to_string(),
                    ),
                )
                .await
            {
                crate::server::routes::warn_audit_log_failure(&audit_err, "audit_log");
            }
        }
    }
}

/// 回收器主循环：定期检查离线 Worker 并回收 stuck 任务。
pub(crate) async fn run_reclaimer_loop(app: Arc<AppState>, cancel: CancellationToken) {
    info!(
        "Worker reclaimer started (assigned_timeout={}s, running_timeout={}s, interval={}s)",
        WORKER_HEARTBEAT_TIMEOUT_SECS, WORKER_RUNNING_RECLAIM_TIMEOUT_SECS, RECLAIMER_INTERVAL_SECS
    );

    let mut interval = tokio::time::interval(Duration::from_secs(RECLAIMER_INTERVAL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // 迭代失败告警节流（30s 档 every=20）：两操作独立计数（共享时任一成功
    // 复位另一的失败计数）。
    let mut reclaim_warn = crbs_core::util::WarnThrottle::new(20);
    let mut terminal_sweep_warn = crbs_core::util::WarnThrottle::new(20);
    // evict 的 get_build 失败告警同口径节流（独立计数，理由同上）。
    let mut evict_warn = crbs_core::util::WarnThrottle::new(20);

    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = cancel.cancelled() => {
                info!("Worker reclaimer shutting down");
                break;
            }
        }

        match reclaim_offline_workers(&app).await {
            Ok(()) => reclaim_warn.reset(),
            Err(e) => {
                if reclaim_warn.fail() {
                    warn!(
                        error = %e,
                        consecutive_failures = reclaim_warn.consecutive(),
                        "Reclaimer iteration failed"
                    );
                }
            }
        }

        match release_terminal_worker_tasks(&app).await {
            Ok(()) => terminal_sweep_warn.reset(),
            Err(e) => {
                if terminal_sweep_warn.fail() {
                    warn!(
                        error = %e,
                        consecutive_failures = terminal_sweep_warn.consecutive(),
                        "Terminal worker_task sweep failed"
                    );
                }
            }
        }

        // 终态滞留 LogBuffer 条目强制驱逐（24h 宽限，详见函数注释）。
        evict_stale_terminal_log_buffers(&app, &mut evict_warn).await;
    }
}

/// 终态滞留 LogBuffer 条目的强制驱逐宽限：终态超 24h 仍滞留（无落盘日志
/// 可回落时 `evict_log_buffer_if_persisted` 不驱逐）→ 回收器强制驱逐。
pub(crate) const STALE_TERMINAL_LOG_BUFFER_GRACE: Duration = Duration::from_secs(24 * 3600);

/// 强制驱逐终态滞留的 LogBuffer 条目（reclaimer 兜底）。
/// [`release_terminal_worker_tasks`] 只在落盘日志可解析时驱逐（保守路径——
/// 无落盘副本时驱逐会把可读实时缓冲降级成 404），代价是失败未上传条目
/// （≤10MB/条）滞留内存到重启。本回收对每个 tracked id 复核 DB：终态且
/// `completed_at` 超宽限 → 强制驱逐（复用墓碑机制，迟到读者回落落盘日志
/// /404，零读取端改动；notifies 连带清理）；行被 prune → 直接驱逐；DB
/// 错误 warn 跳本轮，告警经 `warn_throttle` 节流。
pub(crate) async fn evict_stale_terminal_log_buffers(
    app: &Arc<AppState>,
    warn_throttle: &mut crbs_core::util::WarnThrottle,
) {
    for build_id in app.log_buffer.tracked_build_ids() {
        match app.state_store.get_build(build_id).await {
            Ok(Some(record)) => {
                warn_throttle.reset();
                if !crate::server::routes::logs::build_phase_is_terminal(&record.phase) {
                    continue;
                }
                let Some(completed_at) = record.completed_at.as_deref() else {
                    // 终态但 completed_at 缺失（脏行）：无法判定超期，保守保留。
                    continue;
                };
                if !completed_at_older_than(completed_at, STALE_TERMINAL_LOG_BUFFER_GRACE) {
                    continue;
                }
                warn!(
                    build_id = %build_id,
                    grace_secs = STALE_TERMINAL_LOG_BUFFER_GRACE.as_secs(),
                    "Evicting stale terminal LogBuffer entry (terminal state older than grace)"
                );
                app.log_buffer.evict(build_id);
            }
            Ok(None) => {
                // 行被 prune：无任何潜在读取方，直接驱逐。
                warn_throttle.reset();
                warn!(build_id = %build_id, "Evicting LogBuffer entry for pruned build row");
                app.log_buffer.evict(build_id);
            }
            Err(e) => {
                if warn_throttle.fail() {
                    warn!(
                        error = %e,
                        consecutive_failures = warn_throttle.consecutive(),
                        "Stale terminal LogBuffer evict iteration failed; skipping this round"
                    );
                }
                return;
            }
        }
    }
}

/// `completed_at`（DB 文本帧 `crbs_core::util::DB_TIME_FMT`，UTC 墙钟，双方言
/// 一致）是否早于 `grace` 之前；解析失败保守视为未超期。
pub(crate) fn completed_at_older_than(completed_at: &str, grace: Duration) -> bool {
    let Some(t) = crbs_core::util::parse_db_time(completed_at) else {
        return false;
    };
    (chrono::Utc::now() - t.and_utc()).num_seconds() > grace.as_secs() as i64
}

/// 查找离线 Worker 并回收其 stuck 任务（双阈值，见 `WORKER_HEARTBEAT_TIMEOUT_SECS`）。
/// 两档列表都在任何回收写之前读取——`reclaim_*` 置 offline 而
/// `list_offline_workers` 只查 online，先读后写防第二档列表被写空。快照是
/// 事务外读：各档阈值透传给 `reclaim_*`，回收事务内首条语句复查心跳仍超阈值
/// 才动手，快照后恢复心跳的 worker 本轮跳过（防误 offline + 重派双执行）。
/// 第三档：优雅停机 offline 行（`worker_mark_offline` 同时刷新心跳，计时与
/// 硬崩溃同刻度）按 `WORKER_RUNNING_RECLAIM_TIMEOUT_SECS` 查
/// `list_gone_workers` 全量回收；快速重启走注册回收
/// （reclaim_running_assignments_on_register）先到先收；无 assignment 时
/// `reclaim_worker_tasks` 幂等 no-op。gone 列表同样先于回收写读取。
pub(crate) async fn reclaim_offline_workers(app: &Arc<AppState>) -> crbs_core::Result<()> {
    let offline = app
        .state_store
        .list_offline_workers(WORKER_HEARTBEAT_TIMEOUT_SECS as i64)
        .await?;

    // 失联超过双倍阈值的子集：running 任务也回收。
    let long_offline: HashSet<i64> = if offline.is_empty() {
        HashSet::new()
    } else {
        app.state_store
            .list_offline_workers(WORKER_RUNNING_RECLAIM_TIMEOUT_SECS as i64)
            .await?
            .into_iter()
            .map(|(worker_id, _)| worker_id)
            .collect()
    };

    let gone = app
        .state_store
        .list_gone_workers(WORKER_RUNNING_RECLAIM_TIMEOUT_SECS as i64)
        .await?;

    // 统一成 (id, name, 全量档?)：offline 按双阈值分档、gone 恒全量档，
    // 两列表按 status 天然不交。
    let tiers: Vec<(i64, String, bool)> = offline
        .into_iter()
        .map(|(worker_id, name)| (worker_id, name, long_offline.contains(&worker_id)))
        .chain(
            gone.into_iter()
                .map(|(worker_id, name)| (worker_id, name, true)),
        )
        .collect();

    for (worker_id, worker_name, full) in tiers {
        let affected = if full {
            app.state_store
                .reclaim_worker_tasks(worker_id, WORKER_RUNNING_RECLAIM_TIMEOUT_SECS as i64)
                .await?
        } else {
            app.state_store
                .reclaim_assigned_worker_tasks(worker_id, WORKER_HEARTBEAT_TIMEOUT_SECS as i64)
                .await?
        };

        if !affected.is_empty() {
            for (task_id, build_id) in &affected {
                let build_msg = match build_id {
                    Some(bid) => format!("build_id = {}", bid),
                    None => "init_task".to_string(),
                };
                warn!(
                    worker_id = %worker_id,
                    worker_name = %worker_name,
                    task_id = %task_id,
                    "Reclaimed stuck task from offline worker: {}",
                    build_msg,
                );
            }
            app.worker_notify.notify_one();
        }
    }

    Ok(())
}

/// 兜底 sweep：释放所有指向已终态 build 的僵尸 worker_task（弥补
/// `report_result` 终态写入因崩溃/漏写丢失）。不重置 build（已正确完成），
/// 释放后唤醒调度器复检 pending。同时驱逐 LogBuffer（仅落盘日志可解析时，
/// 与 `report_result` 终态路径同语义——否则 ≤10MB/build 滞留内存到重启）。
pub(crate) async fn release_terminal_worker_tasks(app: &Arc<AppState>) -> crbs_core::Result<()> {
    let (released, build_ids) = app.state_store.release_terminal_worker_tasks().await?;
    if released > 0 {
        warn!(
            released = released,
            "Released stuck worker_tasks pointing to terminal builds"
        );
        for build_id in build_ids {
            crate::server::worker::routes::evict_log_buffer_if_persisted(app, build_id).await;
        }
        app.worker_notify.notify_one();
    }
    Ok(())
}
