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

/// poll 失败退避的间隔上限（秒）：摊薄 hub 不可达时的无效重试；poller
/// 不写心跳，60s 退避不影响 hub 失联判定。
const POLL_RETRY_MAX_SECS: u64 = 60;

/// 认证拒绝退出的在跑任务 drain 窗口（对齐 main.rs 信号 shutdown 的 30s）：
/// 完不成即放弃，hub 240s reclaimer 兜底。
const AUTH_EXIT_DRAIN: Duration = Duration::from_secs(30);

/// 下一次 poll 重试等待秒数：连续失败 5s 起 ×2 指数、封顶 60s；成功由
/// 调用方 reset，重新从 5s 起。
fn poll_retry_delay_secs(consecutive_failures: u64) -> u64 {
    // 移位钳到 4：5→10→20→40→(80→封顶 60)，同时防巨计数溢出。
    let shift = consecutive_failures.saturating_sub(1).min(4);
    POLL_RETRY_BASE_SECS
        .saturating_mul(1u64 << shift)
        .min(POLL_RETRY_MAX_SECS)
}

/// 取消感知睡眠：取消与到期两臂对调用方等价（各点位取消臂均为空动作），
/// 仅等待时长参数化；取消时立即返回以免拖住 shutdown。
async fn sleep_or_cancel(cancel_token: &CancellationToken, d: Duration) {
    tokio::select! {
        _ = cancel_token.cancelled() => {}
        _ = tokio::time::sleep(d) => {}
    }
}

/// poller 存活看门狗的失活窗口（秒）：poll 循环单轮内最长合法等待是 poll
/// 长轮询（客户端超时上限 125s）+ 退避封顶 60s，远低于本窗口；超窗即结构性
/// 挂死（await 永不就绪的阻塞点），重启已验证可恢复。
const POLLER_WATCHDOG_STALL_SECS: u64 = 600;

/// 看门狗巡检周期：发现延迟 = 巡检周期内的抖动，远小于失活窗口。
const POLLER_WATCHDOG_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// poller 循环的活跃心跳（unix 秒）：poll 循环每轮迭代写入，看门狗独立
/// task 读取——两者互不监控时 poller 静默挂死不可恢复，看门狗兜底 exit(1)
/// 交 systemd 拉起。
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

/// 失活判定（纯函数）：静默超过 [`POLLER_WATCHDOG_STALL_SECS`] 才报 Some；
/// 时钟回拨（now < last）不误报。
fn poller_stalled_for(last_active_secs: u64, now_secs: u64) -> Option<u64> {
    now_secs
        .checked_sub(last_active_secs)
        .filter(|&silence| silence > POLLER_WATCHDOG_STALL_SECS)
}

/// 启动 poller 存活看门狗：poller 正常退出路径（shutdown / 认证拒绝）都先
/// cancel 主 token，看门狗随 cancel 退出，不误杀优雅关机；发现失活直接
/// `exit(1)`——该路径无需清理（进程退出即运行时终止，hub 由心跳超时回收兜底）。
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
        // 存活心跳 + 看门狗：poll 循环每轮迭代 mark，看门狗独立 task 监控。
        let liveness = PollerLiveness::default();
        liveness.mark_active();
        let _watchdog = spawn_poller_watchdog(liveness.clone(), cancel_token.clone());
        // 稳态告警节流：hub 不可达时首败告警、每第 20 次连续失败一次，成功复位。
        let mut poll_warn = crbs_core::util::WarnThrottle::new(20);
        // 水位门告警节流同款；磁盘/内存门独立计数——共享实例时任一放行
        // 会复位另一门的告警节流。
        let mut disk_warn = crbs_core::util::WarnThrottle::new(20);
        let mut mem_warn = crbs_core::util::WarnThrottle::new(20);
        // 已执行 assignment 去重集合（succeeded 上报后登记）。
        let executed_assignments = ExecutedAssignments::default();
        let build_root = std::path::PathBuf::from(&cfg.build_dir);

        loop {
            // 每轮迭代刷新存活心跳（含 capacity 自旋/水位门跳过轮——循环仍在
            // 推进即存活；挂死特征是单轮 await 永不就绪）。
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

            // capacity 满则等已有任务完成或取消信号。
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

            // 磁盘水位门：拦"领取→失败→再领"的失败泵，只拦新领取——在跑
            // 构建、心跳（保持 online 收尾在跑任务）与 semaphore 满载等待
            // 路径均不受影响。
            let min_free_bytes = cfg.min_free_disk_bytes();
            if min_free_bytes > 0 {
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
                // 放行：高于水位（复位节流）或查询失败（fail-open 告警留痕）。
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

            // 内存水位门：OOM 会从单个构建失败恶化为拖垮同机其他构建/
            // 系统服务；语义与磁盘门同款（只拦新领取，fail-open，0 = 关闭）。
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
                // 放行：高于水位（复位节流）或读失败（fail-open 告警留痕）。
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
                    // 在途去重（见 CancelRegistry）：判定与注册之间无 await 且
                    // poller 是唯一注册方，无竞态；debug 而非 info（重投递稳态
                    // 下执行期每轮命中一条，是常态）。
                    if cancel_registry.contains(task.assignment_id) {
                        debug!(
                            assignment_id = %task.assignment_id,
                            "Redelivered assignment is already executing here; ignoring duplicate dispatch"
                        );
                        drop(permit);
                        sleep_or_cancel(&cancel_token, Duration::from_secs(2)).await;
                        continue;
                    }
                    // 已完成且成功上报的不再执行（分工：在途查注册表；guard
                    // 移除后才到达的重投递只有本集合能拦）。
                    if executed_assignments.contains(task.assignment_id) {
                        debug!(
                            assignment_id = %task.assignment_id,
                            "Redelivered assignment already completed and reported here; ignoring duplicate dispatch"
                        );
                        drop(permit);
                        sleep_or_cancel(&cancel_token, Duration::from_secs(2)).await;
                        continue;
                    }
                    // 重投递 + 注册表未命中有两种 wire 层不可区分的形态：
                    // a) 首 poll 响应丢失（重投递的设计目标，必须执行——跳过
                    //    则 build 永久卡 running、capacity 泄漏）；b) 同身份双
                    //    进程误配置（对端在执行）。裁定只 warn 不跳、照常执行
                    //    （跳过会把误配置代价转嫁给 a 的恢复路径）；噪声有界，
                    //    注册后重投递命中上方 debug 去重。
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
                    // 注册同步前移到 spawn 之前：注册前窗口内下一轮 poll 的
                    // 重投递会绕过去重二次 spawn；guard 随任务体移动进 spawn
                    // 持有，不双重插入。
                    let cancel_guard = CancelRegistrationGuard::new(
                        cancel_registry.clone(),
                        task.assignment_id,
                        task_cancel.clone(),
                    );
                    // 领到任务后先定总预算（engine 超时口径见 assignment_budget），
                    // 与任务体一起 move 进 spawn。资源快照槽位同随任务体：内层
                    // 写入、本层 abort 后读（保样本见预算超时臂）。
                    let budget = assignment_budget(&task, &cfg);
                    let resource_slot = crbs_core::engine::new_resource_snapshot_slot();
                    join_set.spawn(async move {
                        let _permit = permit; // hold slot until task finishes
                        let _guard = ActiveTaskGuard::new(active_tasks);
                        // 磁盘 sweeper 据此排除在途构建的下载目录（按
                        // assignment 键控：reclaim 重派同 build_id 的新旧执行
                        // 各占一条）。
                        let _build_ids_guard =
                            ActiveBuildGuard::new(active_build_ids, task.assignment_id);
                        let _cancel_guard = cancel_guard;

                        // 再包一层 spawn 捕获 panic 并补报 failed，防 Hub 卡 building。
                        let task_for_inner = task.clone();
                        let cfg_for_inner = cfg.clone();
                        // 槽位同时被内层（写入）与预算超时臂（abort 后读）持有。
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

                        // 总预算兜底：引擎内部遗漏超时的阻塞点不得永久占用
                        // permit 与 hub running 行；超时 abort 任务体（future
                        // Drop 触发 cleanup_guard，自带 30s 有界预算）后按
                        // panic 补报臂口径回报 failed（init 同样补报——run_init
                        // 被 abort 未能自行上报终态）。None（显式不限时）不设预算。
                        let inner_result = match budget {
                            Some(b) => match tokio::time::timeout(b, &mut inner).await {
                                Ok(r) => r,
                                Err(_) => {
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
                                    // abort 保样本：任务体被 abort、引擎随 future
                                    // 丢弃，已采样值仍可从共享槽位读到（尽力而为，
                                    // 读时点现值；采不到 = None，与取消口径区分）。
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
                                    // permit 随任务体 return 归还。
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
                                // 引擎启动前的取消（如 SRPM 下载 select 点）
                                // 从未上报终态——补报 cancelled，hub 不用等
                                // 240s reclaimer。init 终态归 run_init 上报，
                                // 跳过防双重上报（第二份被 hub 409 幂等吸收）。
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
                    // 与取消信号竞争：shutdown 立即醒，不被 2s 休眠拖住。
                    poll_warn.reset();
                    drop(permit);
                    sleep_or_cancel(&cancel_token, Duration::from_secs(2)).await;
                }
                Err(e) => {
                    drop(permit);
                    // 仅认证/授权失败（401/403）退出；其余 4xx 可能暂态，退避
                    // 续跑不杀小时级构建。
                    if crate::error::is_auth_rejected(&e) {
                        error!(error = %e, "Poll rejected by auth (401/403), shutting down poller");
                        // 直接 break 会 detach 在跑构建（终态上报被已取消主
                        // token 吞掉，hub 等 240s reclaimer）——先取消主 token
                        //（停新 poll + 引擎取消），再有界 drain：在跑构建以
                        // cancelled 收尾、独立 token 在窗口内送达终态；超时
                        // 放行交 reclaimer。
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
                    // 指数退避（见 poll_retry_delay_secs）；不影响在跑任务
                    //（permit 已随任务持有）。
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

/// 从 Hub 拉取一次任务。
async fn poll_once(
    worker_id: i64,
    cfg: &WorkerConfig,
    cancel_token: &CancellationToken,
) -> crbs_core::Result<Option<AssignedTask>> {
    let client = cfg.build_http_client().await?;
    // wait 与客户端超时对齐：留 5s 给服务端 wait 到期后的兜底重查（含
    // 重投递查询）+ 响应组装。钳 1..=115：上限保证客户端超时恒大于服务端
    // wait（服务端 clamp 120s）；下限防饱和出 0——wait=0 退化成忙轮询且
    // 对服务端非法。
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
        return Ok(None); // 无任务
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

/// 分配到的任务。Debug 手工脱敏：`srpm_url` / `reproduce_packages_url`
/// 带签名 token，`?task` 日志一次即泄漏。
#[derive(Clone, serde::Deserialize)]
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
    /// reproduce 模式下来源 build 的签名下载 URL；非 reproduce 为 None。
    pub reproduce_packages_url: Option<String>,
    /// 任务类型：build 或 init。缺失时视为 build（向后兼容旧 hub）。
    #[serde(default = "default_kind")]
    pub kind: String,
    /// init 模式下要重建的产品名；build 模式为 None。
    pub init_product: Option<String>,
    /// 产品是否可注入；旧 hub 不下发该字段 → false（保守不注入）。
    #[serde(default)]
    pub product_repo_enabled: bool,
    /// 是否为 hub 对未确认 running 行的重投递（首查领取不携带，旧 hub 恒
    /// `false`）；不可区分两形态的裁定见 spawn_poller 内 warn 处。
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

// ---- 阳性归属探针 ----

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
