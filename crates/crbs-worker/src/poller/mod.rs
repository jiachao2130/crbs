// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 任务拉取循环：长轮询从 Hub 获取任务，执行后上报结果。

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::WorkerConfig;
use crate::executor::BuildResult;
use crate::sweep::{ActiveBuildGuard, ActiveBuildIds};
use crbs_core::error::CrbsError;

/// poll 失败退避的基准间隔（秒）：首败后等 5s，保留快速恢复。
const POLL_RETRY_BASE_SECS: u64 = 5;

/// poll 失败退避的间隔上限（秒）：摊薄 hub 不可达时的无效重试；poller 不写心跳，
/// 60s 退避不影响 hub 失联判定。
const POLL_RETRY_MAX_SECS: u64 = 60;

/// 认证拒绝退出的在跑任务 drain 窗口（对齐 main.rs 信号 shutdown 的 30s）：
/// 完不成即放弃，hub 240s reclaimer 兜底。
const AUTH_EXIT_DRAIN: Duration = Duration::from_secs(30);

/// 下一次 poll 重试等待秒数：连续失败 5s 起 ×2 指数、封顶 60s；成功由调用方 reset。
fn poll_retry_delay_secs(consecutive_failures: u64) -> u64 {
    // 移位上限 4：5→10→20→40→(80→封顶 60)，同时防巨计数溢出。
    let shift = consecutive_failures.saturating_sub(1).min(4);
    POLL_RETRY_BASE_SECS
        .saturating_mul(1u64 << shift)
        .min(POLL_RETRY_MAX_SECS)
}

async fn sleep_or_cancel(cancel_token: &CancellationToken, d: Duration) {
    tokio::select! {
        _ = cancel_token.cancelled() => {}
        _ = tokio::time::sleep(d) => {}
    }
}

/// poller 存活看门狗的失活窗口（秒）：poll 循环单轮内最长合法等待是 poll 长轮询
/// （客户端超时上限 125s）+ 退避封顶 60s，远低于本窗口；超窗即结构性挂死
/// （await 永不就绪的阻塞点），重启已验证可恢复。
const POLLER_WATCHDOG_STALL_SECS: u64 = 600;

const POLLER_WATCHDOG_CHECK_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Default)]
struct PollerLiveness(Arc<AtomicU64>);

impl PollerLiveness {
    fn mark_active(&self) {
        self.0.store(unix_now_secs(), Ordering::Relaxed);
    }

    fn last_active_secs(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 失活判定（纯函数）：静默超过 POLLER_WATCHDOG_STALL_SECS 才报 Some；时钟回拨
/// （now < last）不误报。
fn poller_stalled_for(last_active_secs: u64, now_secs: u64) -> Option<u64> {
    now_secs
        .checked_sub(last_active_secs)
        .filter(|&silence| silence > POLLER_WATCHDOG_STALL_SECS)
}

/// 启动 poller 存活看门狗：poller 正常退出路径（shutdown / 认证拒绝）都先 cancel
/// 主 token，看门狗随 cancel 退出，不误杀优雅关机；发现失活直接 exit(1)——该路径
/// 无需清理（进程退出即运行时终止，hub 由心跳超时回收兜底）。
fn spawn_poller_watchdog(
    liveness: PollerLiveness,
    cancel_token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = cancel_token.cancelled() => return,
                _ = tokio::time::sleep(POLLER_WATCHDOG_CHECK_INTERVAL) => {
                    let last = liveness.last_active_secs();
                    if let Some(silence) = poller_stalled_for(last, unix_now_secs()) {
                        error!(
                            last_active_unix_secs = last,
                            silence_secs = silence,
                            "Poller loop stalled (no iteration for over 10 minutes); \
                             exiting so the service manager restarts this worker"
                        );
                        std::process::exit(1);
                    }
                }
            }
        }
    })
}

/// 启动任务拉取后台任务。
pub fn spawn_poller(
    worker_id: i64,
    cfg: WorkerConfig,
    active_tasks: Arc<AtomicI32>,
    active_build_ids: ActiveBuildIds,
    cancel_registry: CancelRegistry,
    cancel_token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let capacity = cfg.capacity.max(1) as usize;
        let semaphore = Arc::new(tokio::sync::Semaphore::new(capacity));
        let mut join_set = tokio::task::JoinSet::new();

        let liveness = PollerLiveness::default();
        liveness.mark_active();
        let _watchdog = spawn_poller_watchdog(liveness.clone(), cancel_token.clone());

        let mut poll_warn = crbs_core::util::WarnThrottle::new(20);

        // 磁盘/内存门独立计数：共享实例时任一放行会复位另一门的告警节流。
        let mut disk_warn = crbs_core::util::WarnThrottle::new(20);
        let mut mem_warn = crbs_core::util::WarnThrottle::new(20);

        let executed_assignments = ExecutedAssignments::default();
        let build_root = std::path::PathBuf::from(&cfg.build_dir);

        loop {
            liveness.mark_active();

            if cancel_token.is_cancelled() {
                if join_set.is_empty() {
                    info!("Poller received shutdown signal, exiting");
                    break;
                }
                if let Some(Err(e)) = join_set.join_next().await {
                    warn!(error = %e, "Task join error during shutdown");
                }
                continue;
            }

            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tokio::select! {
                        _ = cancel_token.cancelled() => {
                            info!("Poller received shutdown signal, waiting for tasks");
                        }
                        _ = tokio::time::sleep(Duration::from_millis(200)) => {}
                        Some(res) = join_set.join_next() => {
                            if let Err(e) = res {
                                warn!(error = %e, "Task join error");
                            }
                        }
                    }
                    continue;
                }
            };

            let min_free_bytes = cfg.min_free_disk_bytes();
            if min_free_bytes > 0 {
                // 磁盘余量门槛：拦"领取→失败→再领"的空转，只拦新任务的领取——在跑构建、
                // 心跳（保持 online 收尾在跑任务）与 semaphore 满载等待均不受影响。
                let available = free_disk_bytes(&build_root).await;
                if gate_blocks(&available, min_free_bytes) {
                    if disk_warn.fail() {
                        warn!(
                            build_dir = %build_root.display(),
                            available_bytes = available.as_ref().unwrap_or(&0),
                            min_free_bytes = min_free_bytes,
                            consecutive_skips = disk_warn.consecutive(),
                            "Free disk below watermark; skipping assignment poll \
                             this round (in-flight builds and heartbeats continue)"
                        );
                    }
                    drop(permit);
                    sleep_or_cancel(&cancel_token, Duration::from_secs(2)).await;
                    continue;
                }

                match &available {
                    Ok(_) => disk_warn.reset(),
                    Err(e) => {
                        if disk_warn.fail() {
                            warn!(
                                build_dir = %build_root.display(),
                                error = %e,
                                "Disk watermark check failed; polling anyway (fail-open)"
                            );
                        }
                    }
                }
            }

            let min_free_mem_bytes = cfg.min_free_mem_bytes();
            if min_free_mem_bytes > 0 {
                let available = mem_available_bytes().await;
                if gate_blocks(&available, min_free_mem_bytes) {
                    if mem_warn.fail() {
                        warn!(
                            available_bytes = available.as_ref().unwrap_or(&0),
                            min_free_bytes = min_free_mem_bytes,
                            consecutive_skips = mem_warn.consecutive(),
                            "Free memory below watermark; skipping assignment poll \
                             this round (in-flight builds and heartbeats continue)"
                        );
                    }
                    drop(permit);
                    sleep_or_cancel(&cancel_token, Duration::from_secs(2)).await;
                    continue;
                }

                match &available {
                    Ok(_) => mem_warn.reset(),
                    Err(e) => {
                        if mem_warn.fail() {
                            warn!(
                                error = %e,
                                "Memory watermark check failed; polling anyway (fail-open)"
                            );
                        }
                    }
                }
            }

            match poll_once(worker_id, &cfg, &cancel_token).await {
                Ok(Some(task)) => {
                    poll_warn.reset();

                    if cancel_registry.contains(task.assignment_id) {
                        // 在途去重（见 CancelRegistry）：判定与注册之间无 await 且
                        // poller 是唯一注册方，无竞态；debug 而非 info（重投递稳态下
                        // 执行期每轮命中一条，是常态）。
                        debug!(
                            assignment_id = %task.assignment_id,
                            "Redelivered assignment is already executing here; ignoring duplicate dispatch"
                        );
                        drop(permit);
                        sleep_or_cancel(&cancel_token, Duration::from_secs(2)).await;
                        continue;
                    }

                    if executed_assignments.contains(task.assignment_id) {
                        // 已完成且成功上报的不再执行（分工：在途查注册表；guard
                        // 移除后才到达的重投递只有本集合能拦）。
                        debug!(
                            assignment_id = %task.assignment_id,
                            "Redelivered assignment already completed and reported here; ignoring duplicate dispatch"
                        );
                        drop(permit);
                        sleep_or_cancel(&cancel_token, Duration::from_secs(2)).await;
                        continue;
                    }

                    if task.redelivered {
                        warn!(
                            assignment_id = %task.assignment_id,
                            build_id = %task.build_id,
                            "Redelivered assignment is not executing in this process; executing it \
                             now. Expected when the original poll response was lost, but if another \
                             live process shares this worker identity (same worker.toml name+token \
                             -> same worker id) it may already be executing this build; check for \
                             duplicate worker processes"
                        );
                    }
                    info!(
                        assignment_id = %task.assignment_id,
                        task_id = ?task.task_id,
                        "Assignment received, executing"
                    );
                    let task_cancel = cancel_token.child_token();
                    let active_tasks = active_tasks.clone();
                    let active_build_ids = active_build_ids.clone();
                    let cfg = cfg.clone();
                    let executed_for_task = executed_assignments.clone();
                    let probe_interval = Duration::from_secs(ownership_probe_interval_secs(
                        cfg.heartbeat_interval_secs,
                    ));

                    let cancel_guard = CancelRegistrationGuard::new(
                        cancel_registry.clone(),
                        task.assignment_id,
                        task_cancel.clone(),
                    );

                    let budget = assignment_budget(&task, &cfg);
                    let resource_slot = crbs_core::engine::new_resource_snapshot_slot();
                    join_set.spawn(async move {
                        let _permit = permit;
                        let _guard = ActiveTaskGuard::new(active_tasks);

                        let _build_ids_guard =
                            ActiveBuildGuard::new(active_build_ids, task.assignment_id);
                        let _cancel_guard = cancel_guard;

                        let task_for_inner = task.clone();
                        let cfg_for_inner = cfg.clone();

                        // 再包一层 spawn 捕获 panic 并补报 failed，防 Hub 卡 building。
                        // 资源快照槽位同随任务体：内层写入、本层 abort 后读（保样本见
                        // 预算超时臂）。
                        let slot_for_abort = std::sync::Arc::clone(&resource_slot);
                        let mut inner = tokio::spawn(async move {
                            execute_task(
                                worker_id,
                                &cfg_for_inner,
                                &task_for_inner,
                                task_cancel,
                                &executed_for_task,
                                probe_interval,
                                resource_slot,
                            )
                            .await
                        });

                        let inner_result = match budget {
                            Some(b) => match tokio::time::timeout(b, &mut inner).await {
                                Ok(r) => r,
                                Err(_) => {
                                    // 总预算作为兜底：引擎内部遗漏超时的阻塞点不得
                                    // 永久占用 permit 与 hub running 行；超时 abort 任务体
                                    // （future Drop 触发 cleanup_guard，自带 30s 预算）后按
                                    // panic 补报臂口径回报 failed（init 同样补报——run_init
                                    // 被 abort 未能自行上报终态）。None（显式不限时）不设预算。
                                    error!(
                                        assignment_id = %task.assignment_id,
                                        task_id = ?task.task_id,
                                        budget_secs = b.as_secs(),
                                        "Assignment exceeded total execution budget; aborting \
                                         and reporting failed"
                                    );
                                    inner.abort();
                                    if tokio::time::timeout(ASSIGNMENT_ABORT_JOIN, &mut inner)
                                        .await
                                        .is_err()
                                    {
                                        warn!(
                                            assignment_id = %task.assignment_id,
                                            "Aborted task did not finish teardown in time; \
                                             cleanup continues in background"
                                        );
                                    }

                                    // abort 保样本：任务体被 abort、引擎随 future 丢弃，
                                    // 已采样值仍可从共享槽位读到（尽力而为，读时点现值；
                                    // 采不到 = None，与取消情形区分）。
                                    let resources =
                                        crbs_core::engine::snapshot_slot_resources(&slot_for_abort);
                                    report_terminal_failure_with_resources(
                                        &cfg,
                                        worker_id,
                                        &task,
                                        format!(
                                            "assignment execution exceeded total budget of {} seconds",
                                            b.as_secs()
                                        ),
                                        resources,
                                    )
                                    .await;

                                    return;
                                }
                            },
                            None => inner.await,
                        };
                        match inner_result {
                            Ok(Ok(())) => {}
                            Ok(Err(CrbsError::Cancelled)) => {
                                info!(
                                    assignment_id = %task.assignment_id,
                                    task_id = ?task.task_id,
                                    "Assignment cancelled"
                                );

                                // 引擎启动前的取消（如 SRPM 下载 select 点）从未上报
                                // 终态——补报 cancelled，hub 不用等 240s reclaimer。
                                // init 终态归 run_init 上报，跳过防双重上报（第二份被
                                // hub 409 幂等吸收）。
                                if task.kind != "init" {
                                    report_terminal_after_cancel(
                                        &cfg,
                                        worker_id,
                                        &task,
                                        &BuildResult::terminal("cancelled", None, None),
                                    )
                                    .await;
                                }
                            }
                            Ok(Err(e)) => {
                                warn!(
                                    assignment_id = %task.assignment_id,
                                    task_id = ?task.task_id,
                                    error = %e,
                                    "Assignment execution failed"
                                );
                                report_task_failure(&cfg, worker_id, &task, e.to_string()).await;
                            }
                            Err(join_err) => {
                                let panic_msg = join_failure_message(join_err);
                                warn!(
                                    assignment_id = %task.assignment_id,
                                    task_id = ?task.task_id,
                                    error = %panic_msg,
                                    "Assignment execution failed"
                                );
                                report_terminal_failure(&cfg, worker_id, &task, panic_msg).await;
                            }
                        }
                    });
                }
                Ok(None) => {
                    poll_warn.reset();
                    drop(permit);
                    sleep_or_cancel(&cancel_token, Duration::from_secs(2)).await;
                }
                Err(e) => {
                    drop(permit);

                    if crate::error::is_auth_rejected(&e) {
                        error!(error = %e, "Poll rejected by auth (401/403), shutting down poller");

                        // 直接 break 会 detach 在跑构建（终态上报被已取消的主 token 拦截，
                        // hub 等 240s reclaimer）——先取消主 token（停新 poll + 引擎
                        // 取消），再带上限 drain：在跑构建以 cancelled 收尾、独立 token
                        // 在窗口内送达终态；超时放行交 reclaimer。
                        cancel_token.cancel();
                        let drained = tokio::time::timeout(AUTH_EXIT_DRAIN, async {
                            while let Some(res) = join_set.join_next().await {
                                if let Err(e) = res {
                                    warn!(error = %e, "Task join error during auth-exit drain");
                                }
                            }
                        })
                        .await
                        .is_ok();
                        if !drained {
                            warn!(
                                pending_tasks = join_set.len(),
                                "Auth-exit drain window elapsed with tasks still running; \
                                 abandoning them to the hub heartbeat-timeout reclaimer"
                            );
                        }
                        break;
                    }
                    if poll_warn.fail() {
                        warn!(
                            error = %e,
                            consecutive_failures = poll_warn.consecutive(),
                            "Poll failed"
                        );
                    }

                    sleep_or_cancel(
                        &cancel_token,
                        Duration::from_secs(poll_retry_delay_secs(poll_warn.consecutive())),
                    )
                    .await;
                }
            }
        }
    })
}

async fn poll_once(
    worker_id: i64,
    cfg: &WorkerConfig,
    cancel_token: &CancellationToken,
) -> crbs_core::Result<Option<AssignedTask>> {
    let client = cfg.build_http_client().await?;

    // wait 与客户端超时对齐：留 5s 给服务端 wait 到期后的补查（含重投递查询）+
    // 响应组装。限定在 1..=115：上限保证客户端超时恒大于服务端 wait（服务端 clamp
    // 120s）；下限防饱和出 0——wait=0 退化成忙轮询且对服务端非法。
    let wait = cfg.poll_timeout_secs.saturating_sub(5).clamp(1, 115);
    let url = format!(
        "{}/api/v1/workers/{}/assignments?wait={}",
        cfg.hub_url, worker_id, wait
    );

    let request = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(cfg.poll_timeout_secs))
        .send();

    let resp = tokio::select! {
        _ = cancel_token.cancelled() => {
            return Ok(None);
        }
        result = request => {
            result.map_err(|e| crate::error::reqwest("poll assignments", e))?
        }
    };

    if resp.status().as_u16() == 204 {
        return Ok(None);
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(crate::error::http_response_error(
            "poll assignments",
            status,
            text,
        ));
    }

    let task: AssignedTask = resp
        .json()
        .await
        .map_err(|e| crate::error::reqwest("decode assignment", e))?;
    Ok(Some(task))
}

#[derive(Clone, serde::Deserialize)]
/// 分配到的任务。Debug 手工脱敏：srpm_url / reproduce_packages_url 带签名 token，
/// 进日志即泄漏。
pub struct AssignedTask {
    pub assignment_id: i64,
    pub task_id: Option<i64>,
    pub build_id: i64,
    pub product: String,
    #[serde(default)]
    pub srpm_url: String,
    #[serde(default)]
    pub build_options: serde_json::Value,
    #[serde(default)]
    pub product_config: String,

    pub reproduce_packages_url: Option<String>,

    #[serde(default = "default_kind")]
    pub kind: String,

    pub init_product: Option<String>,

    #[serde(default)]
    pub product_repo_enabled: bool,

    #[serde(default)]
    pub redelivered: bool,
}

impl std::fmt::Debug for AssignedTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssignedTask")
            .field("assignment_id", &self.assignment_id)
            .field("task_id", &self.task_id)
            .field("build_id", &self.build_id)
            .field("product", &self.product)
            .field("srpm_url", &"<redacted>")
            .field("kind", &self.kind)
            .finish()
    }
}

fn default_kind() -> String {
    "build".to_string()
}

mod cancel;
mod execute;
mod probes;
mod report;

use cancel::CancelRegistrationGuard;
use execute::{execute_task, ActiveTaskGuard, ASSIGNMENT_ABORT_JOIN};
use probes::{gate_blocks, mem_available_bytes, ownership_probe_interval_secs};
use report::{
    report_task_failure, report_terminal_failure, report_terminal_failure_with_resources,
};
#[cfg(test)]
mod tests;

pub(crate) use cancel::{CancelRegistry, ExecutedAssignments};
pub(crate) use execute::assignment_budget;
pub(crate) use probes::free_disk_bytes;
pub(crate) use report::{join_failure_message, report_build_result, report_terminal_after_cancel};
