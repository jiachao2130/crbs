// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 后台调度器：按优先级从 pending 队列选取任务，分配到可用构建槽；提交纯
//! 入队（不 429）由调度器消费。模式：auto（Worker 优先，无可用回退本地）/
//! local_only（仅本地）/ distributed_only（仅 Worker）。
//!
//! 分布式派发引擎 = build-outer planner（[`planner`]）：候选外层
//! 主循环、硬下限 eligible 过滤（`resource_requirements_enabled`）、三维画像
//! 键有效权重进水位门（`resource_profile_weights_enabled`）、censored 超龄
//! 兜底与派发归因。hub 本地构建另有独立水位门
//!（`resource_local_watermark_enabled` 默认关）：[`try_local_build`] 逐候选按
//! 伪 worker（/proc 自采遥测）判硬下限与水位，被拒候选跳过、顺延下一候选
//!（不阻塞远端派发）；本地硬下限随 `resource_requirements_enabled` 走同款
//! fail-closed 判定。
//! 画像回填由 [`spawn_profile_backfill_then_scheduler`] 先行
//! 执行一次，完成后再启动调度器主循环。

mod local;
mod maintenance;
pub(crate) mod planner;
mod profiles;
#[cfg(test)]
mod tests;

pub(crate) use local::{parse_proc_mem_total_kb, try_local_build};
pub(crate) use maintenance::{
    spawn_db_retention, spawn_orphan_sweeper, spawn_reclaimer, spawn_session_cleanup,
    WORKER_HEARTBEAT_TIMEOUT_SECS,
};
pub(crate) use profiles::{
    committed_from_active, load_resource_profiles, profile_key, sort_workers_for_dispatch,
    spawn_profile_backfill_then_scheduler, watermark_reject_dimension, AdmitWatermarks,
    CommittedLoad, PackageResourceWeight, ProfileKey, ResolvedResourceProfile, ResourceProfileMap,
    ResourceWeightCache, WatermarkDimension, COMMITTED_RAMP_SECS,
};

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crbs_core::config::SchedulerMode;

use crate::server::state::AppState;

/// 监督重启的退避起点（5s）与上限（60s），指数递增。
const SUPERVISED_RESTART_BACKOFF_START: Duration = Duration::from_secs(5);
const SUPERVISED_RESTART_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// 兜底轮询 tick 的基准间隔（秒）：无 notify 时的兜底轮询。
const SCHEDULER_TICK_SECS: u64 = 2;

/// DB 持续故障期兜底 tick 的退避上限（秒）：摊薄每 2s 一次注定失败的建连；
/// 30s 远低于调度时效要求，恢复后下一轮 tick 立即归位。
const SCHEDULER_TICK_BACKOFF_MAX_SECS: u64 = 30;

/// 兜底 tick 的等待秒数：连续 DB 失败 n 次时间隔 2s→4s→8s→16s→30s（封顶）；
/// 首败保持基准 2s 保快速恢复，成功由调用方 reset 计数归位。
fn tick_backoff_secs(consecutive_failures: u64) -> u64 {
    // 移位钳到 4：2→4→8→16→(32→封顶 30)，同时防巨计数溢出。
    let shift = consecutive_failures.saturating_sub(1).min(4);
    SCHEDULER_TICK_SECS
        .saturating_mul(1u64 << shift)
        .min(SCHEDULER_TICK_BACKOFF_MAX_SECS)
}

/// 监督式后台循环 spawn：循环体 panic 后 `error!` 并按指数退避（5s 起、上限
/// 60s）重启；正常 return（如 cancel 退出）或监督期间已取消则不再重启。
/// `make_loop` 每次重启重新调用拿全新 Future（上一轮资源随 drop 释放），
/// 循环体自身负责在 `cancel` 触发时 return。返回监督任务 JoinHandle（测试
/// 等待退出用）；`pub(crate)` 供批次驱动循环（batches/driver.rs）复用。
pub(crate) fn spawn_supervised_loop<F, Fut>(
    name: &'static str,
    cancel: CancellationToken,
    make_loop: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn(CancellationToken) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut backoff = SUPERVISED_RESTART_BACKOFF_START;
        loop {
            if cancel.is_cancelled() {
                return;
            }
            let handle = tokio::spawn(make_loop(cancel.clone()));
            match handle.await {
                Ok(()) => {
                    info!(task = name, "Supervised background loop exited");
                    return;
                }
                Err(e) if e.is_panic() => {
                    error!(
                        task = name,
                        backoff_secs = backoff.as_secs(),
                        "Background loop panicked; restarting with backoff"
                    );
                }
                // 被 abort 等非 panic 终止：视同正常退出，不重启。
                Err(_) => {
                    info!(
                        task = name,
                        "Supervised background loop aborted; not restarting"
                    );
                    return;
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = cancel.cancelled() => return,
            }
            backoff = std::cmp::min(backoff * 2, SUPERVISED_RESTART_BACKOFF_MAX);
        }
    })
}

/// 启动后台调度器。
pub(crate) fn spawn_scheduler(app: Arc<AppState>, cancel: CancellationToken) {
    spawn_supervised_loop("build_scheduler", cancel, move |cancel| {
        let app = app.clone();
        async move { run_scheduler_loop(app, cancel).await }
    });
}

/// 调度器主循环。
async fn run_scheduler_loop(app: Arc<AppState>, cancel: CancellationToken) {
    info!("Build scheduler started");

    // 稳态告警节流（2s 兜底 tick × 持续 DB 故障 = 刷屏）：首败告警、
    // 之后每第 20 次连续失败告警一次，成功复位。
    let mut dispatch_warn = crbs_core::util::WarnThrottle::new(20);
    let mut local_warn = crbs_core::util::WarnThrottle::new(20);

    loop {
        if cancel.is_cancelled() {
            info!("Build scheduler shutting down");
            break;
        }

        let mode = app.server_config.scheduler_mode.clone();

        if mode != SchedulerMode::LocalOnly {
            match planner::run_tick(&app).await {
                Ok(true) => {
                    dispatch_warn.reset();
                    continue;
                }
                Ok(false) => dispatch_warn.reset(),
                Err(e) => {
                    if dispatch_warn.fail() {
                        warn!(error = %e, consecutive_failures = dispatch_warn.consecutive(), "Failed to dispatch to worker");
                    }
                }
            }
        }

        if mode != SchedulerMode::DistributedOnly {
            match try_local_build(&app, &cancel).await {
                Ok(true) => {
                    local_warn.reset();
                    continue;
                }
                Ok(false) => local_warn.reset(),
                Err(e) => {
                    if local_warn.fail() {
                        warn!(error = %e, consecutive_failures = local_warn.consecutive(), "Failed to start local build");
                    }
                }
            }
        }

        // 无事可做：等待 notify 或兜底轮询，兜底间隔按连续 DB 失败次数指数
        // 退避（tick_backoff_secs）；notify 路径（worker 注册/新任务）立即唤醒。
        let consecutive = dispatch_warn.consecutive().max(local_warn.consecutive());
        let tick = Duration::from_secs(tick_backoff_secs(consecutive));
        tokio::select! {
            _ = tokio::time::sleep(tick) => {}
            _ = app.worker_notify.notified() => {}
            _ = cancel.cancelled() => {
                info!("Build scheduler shutting down");
                break;
            }
        }
    }
}

/// 快速失败收口（request_json 解析失败 / SRPM 缺失两路径共用）：build 翻
/// failed + 终态钩子 + active_builds 移除；DB 写失败仅 warn——行滞留非终态
/// 由孤儿清扫兜底。permit 释放与 continue 留在调用方。
async fn fail_build_quick(app: &Arc<AppState>, build_id: i64, message: &str) {
    if let Err(db_err) = app
        .state_store
        .complete_build_with_error(build_id, "failed", None, Some(message))
        .await
    {
        warn!(
            build_id = %build_id,
            err = ?db_err,
            "Failed to mark build failed; build row may stay non-terminal until orphan sweep"
        );
    }
    // 翻终态（快速失败路径）补终态钩子——重放构建翻 failed 时比对行需要钩子
    // 落库；重复钩子由 insert_replay_if_absent 查重吸收，真 DB 错时钩子终态
    // 守卫 no-op。
    crate::server::replay::spawn_on_build_terminal(app.clone(), build_id);
    {
        let mut map = app.active_builds.lock().await;
        map.remove(&build_id);
    }
}
