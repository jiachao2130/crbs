// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 任务执行器：下载 SRPM、调用 BuildEngine、上报结果。

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crbs_core::effective_build_timeout;
use crbs_core::error::CrbsError;
use crbs_core::StateStore;

use crate::config::{ensure_safe_build_dir, WorkerConfig, HTTP_FALLBACK_TIMEOUT_SECS};
use crate::executor::log_stream::stream_build_log_to_hub;
use crate::executor::upload::{upload_build_outputs, upload_log_files};
use crate::poller::AssignedTask;
use crate::retry::{retry_with_backoff, retry_with_timeout};

mod log_stream;
mod result;
mod upload;

pub use result::{report_phase, report_result, report_result_with_timeout, BuildResult};

pub(crate) const INIT_ENGINE_TIMEOUT_SECS: u64 = 3 * 3600;

/// 入口取消检查：令牌已取消即返回 Cancelled。
fn ensure_not_cancelled(cancel_token: Option<&CancellationToken>) -> crbs_core::Result<()> {
    if cancel_token.is_some_and(|t| t.is_cancelled()) {
        return Err(CrbsError::Cancelled);
    }
    Ok(())
}

/// 本进程在途构建的 hub build id 集：镜像播种拆引信的认领排除集。镜像行 attach 时
/// 写入的 pid 是本进程自身，"pid == 本进程"区分不了在途与陈旧残留（hub 允许同 NVR
/// 异 arch 的两个构建并发活跃，本地行 arch 恒 NULL、归一后必撞同一 identity）；
/// 注册先于播种（行存在 ⇒ 已注册，种子到 attach 只有亚毫秒窗），认领侧据此放行
/// 陈旧行、放走在途行。
static IN_FLIGHT_HUB_BUILD_IDS: std::sync::LazyLock<std::sync::Mutex<HashSet<i64>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashSet::new()));

struct InFlightHubBuildGuard {
    build_id: i64,
}

impl InFlightHubBuildGuard {
    fn new(build_id: i64) -> Self {
        IN_FLIGHT_HUB_BUILD_IDS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(build_id);
        Self { build_id }
    }
}

impl Drop for InFlightHubBuildGuard {
    fn drop(&mut self) {
        IN_FLIGHT_HUB_BUILD_IDS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.build_id);
    }
}

/// 镜像播种前的拆引信（陈旧活跃行的存量自愈）：complete/相位写失败被静默忽略的
/// 陈旧活跃行 pid 恰为本进程、僵尸回收按 pid 存活判定永不触发，同 identity 再派时
/// 播种撞 uq_active_builds_identity → attach 降级 → 引擎自插撞活跃复查 → Conflict
/// 判败。此处把可确证属本进程残留的阻塞行收口为 failed，播种即无索引碰撞。
/// 三重认领门，缺一不动行：pid 归属本进程（NULL = 播种后 attach 前的半写入残留，
/// 同认——不可能属在途执行，在途行注册先于播种）；不在本进程在途集（防误杀并发
/// 同 identity 的他 build 行）；非本次 build id（同 id 重派走 seed 的终态重置分支，
/// 不归本函数）。他进程名下的行一律不动；误杀在途行的最坏后果 = 该行后续终态写
/// 被检查拒绝（warn），hub 侧不受影响。失败仅 warn，播种碰撞维持既有降级路径。
async fn claim_stale_self_build_rows(
    state: &crbs_core::StateStore,
    product: &str,
    pkg_name: &str,
    incoming_build_id: i64,
) {
    let candidates = match state.list_claimable_active_rows(product, pkg_name).await {
        Ok(rows) => rows,
        Err(e) => {
            warn!(
                build_id = %incoming_build_id,
                error = %e,
                "Failed to list stale-row claim candidates before mirror seed; leaving rows untouched"
            );
            return;
        }
    };
    if candidates.is_empty() {
        return;
    }
    let pid = std::process::id() as i64;
    let in_flight = IN_FLIGHT_HUB_BUILD_IDS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    for (id, crbs_pid) in candidates {
        let owned = match crbs_pid {
            None => true,
            Some(p) => p == pid,
        };
        if !owned || id == incoming_build_id || in_flight.contains(&id) {
            continue;
        }
        let pid_note = match crbs_pid {
            Some(p) => format!("pid {p}"),
            None => "no pid recorded".to_string(),
        };
        let summary = format!(
            "stale active row claimed at mirror seed ({pid_note}, not in flight): \
             leftover of an earlier assignment in this worker process"
        );
        match state.mark_stale_local_build_failed(id, &summary).await {
            Ok(n) if n > 0 => {
                info!(
                    build_id = %id,
                    pkg_name = %pkg_name,
                    "Claimed stale active build row before mirror seed (self-heal)"
                );
            }
            Ok(_) => {}
            Err(e) => {
                warn!(
                    build_id = %id,
                    error = %e,
                    "Failed to claim stale active build row before mirror seed; seeding may hit the identity conflict"
                );
            }
        }
    }
}

/// 执行单个构建任务。resource_slot：poller 预算 abort 后的样本保留槽位——引擎建
/// 采样器时把句柄写入，任务体被 abort 后 poller 仍可读已累计值。
pub async fn run_build(
    cfg: &WorkerConfig,
    worker_id: i64,
    task: &AssignedTask,
    cancel_token: CancellationToken,
    resource_slot: crbs_core::engine::ResourceSnapshotSlot,
) -> crbs_core::Result<BuildResult> {
    let build_root = PathBuf::from(&cfg.build_dir);
    // 确保 build_dir 安全（不在 /tmp，无符号链接攻击）——必须先于首个写路径
    // download_srpm 的 create_dir_all。
    ensure_safe_build_dir(&build_root).await?;

    // 注册先于一切本地库写入（播种拆引信的在途排除前提：行存在 ⇒ 已注册）。
    let _in_flight_guard = InFlightHubBuildGuard::new(task.build_id);

    let srpm_path = download_srpm(cfg, task, &cancel_token).await?;
    let mut download_guard = BuildDownloadGuard::new(srpm_path.clone(), build_root.clone());
    info!(
        assignment_id = %task.assignment_id,
        task_id = ?task.task_id,
        srpm = %srpm_path.display(),
        "SRPM downloaded"
    );

    let state = Arc::new(StateStore::new(&build_root).await?);

    let opts: crbs_core::BuildOptions = serde_json::from_value(task.build_options.clone())
        .map_err(|e| CrbsError::ValidationFailed {
            message: format!("parse build_options: {}", e),
        })?;

    // reproduce：backend / 资源限制不读复现请求——走与正常构建相同的解析链，容器
    // /proc 挂载语义与源构建同态。
    let engine_construction_opts = if opts.reproduce_from_build_id.is_some() {
        crbs_core::engine_options_for_reproduce_construction(&opts)
    } else {
        opts.clone()
    };
    let engine = crbs_core::build_engine_from_options(
        &task.product,
        &engine_construction_opts,
        state.clone(),
        Some(hub_product_config(task)?),
        Some(&PathBuf::from(&cfg.crbs_root)),
    )
    .await?;
    let engine = crbs_core::apply_options_to_engine(engine, &opts)?;

    let engine = engine
        // 显式 pin crbs_root = worker.toml crbs_root：引擎默认值变更不得随之改变
        // worker 的结果/状态位置。
        .with_timeout(
            // hang 构建会永久占用 hub running 行 + worker permit（只要心跳还在 reclaimer
            // 就不会回收）→ 超时落 worker.toml 的 build_timeout_secs。
            effective_build_timeout(opts.timeout, cfg.build_timeout_secs)
                .map(std::time::Duration::from_secs),
        )
        .with_resource_snapshot_slot(resource_slot);

    let network = engine.config().network;
    let product_repo_url = crbs_core::engine::product_repo::decide_product_repo_url(
        &cfg.hub_url,
        &task.product,
        opts.arch.as_deref(),
        cfg.arch(),
        &engine.config().arches,
        task.product_repo_enabled,
        network,
    );
    let engine = if let Some(url) = product_repo_url {
        info!(
            assignment_id = %task.assignment_id,
            task_id = ?task.task_id,
            baseurl = %url,
            "Injecting hub product repo into build chroot",
        );
        engine.with_product_repo_url(url)
    } else {
        engine
    };

    let (mut reproduce_env, engine) = if let Some(src_id) = opts.reproduce_from_build_id {
        match prepare_worker_reproduce(cfg, task, engine, &cancel_token).await {
            Ok((env, re_engine)) => {
                info!(
                    assignment_id = %task.assignment_id,
                    source_build_id = %src_id,
                    restored = env.restored_count,
                    "Worker reproduce environment prepared"
                );
                (Some(env), re_engine)
            }
            Err(e) => {
                debug!(
                    assignment_id = %task.assignment_id,
                    source_build_id = %src_id,
                    error = %e,
                    "Failed to prepare worker reproduce environment"
                );
                return Err(e);
            }
        }
    } else {
        (None, engine)
    };

    let task_cancel = cancel_token.child_token();
    // 日志流用子 token：shutdown 或构建完成都会取消它，仅本任务生命周期内有效。
    let log_cancel = task_cancel.clone();

    let pkg_name = match crbs_core::engine::srpm_pkg_name(&srpm_path) {
        Ok(p) => p,
        Err(e) => {
            if let Some(env) = reproduce_env.take() {
                env.teardown().await;
            }
            return Err(e);
        }
    };

    claim_stale_self_build_rows(&state, &task.product, &pkg_name, task.build_id).await;
    // lifecycle 落 hub id 空间：attach hub 下发的 build_id（本地行缺失先播种镜像行），
    // profile.json / crbs-artifacts.json / 结果目录叶子统一 hub id，不写本地自增 id。
    // 播种/attach 失败降级 warn：本地记账缺失不阻断构建，引擎自插行兜底。
    let lifecycle = match crbs_core::engine::BuildLifecycle::attach_remote(
        state.clone(),
        task.build_id,
        &task.product,
        &pkg_name,
        std::process::id() as i64,
    )
    .await
    {
        Ok(l) => Some(l),
        Err(e) => {
            warn!(
                assignment_id = %task.assignment_id,
                build_id = %task.build_id,
                error = %e,
                "Attach hub build lifecycle failed; engine falls back to a local build row"
            );
            None
        }
    };

    let (result_dir_tx, result_dir_rx) = tokio::sync::watch::channel::<Option<PathBuf>>(None);

    let engine_result_root = engine.config().result_dir.clone();
    // 引擎前置回报确切 result_dir 的 watch 通道：避免同包并发时 mtime 扫描误报
    // 兄弟构建日志。
    let log_task = tokio::spawn(stream_build_log_to_hub(
        cfg.clone(),
        worker_id,
        task.clone(),
        pkg_name,
        engine_result_root.clone(),
        result_dir_rx,
        log_cancel,
    ));

    let mut result = engine
        .build_with_dir(&srpm_path, &task_cancel, lifecycle, Some(result_dir_tx))
        .await;

    if let Some(usage) = result.resources.as_mut() {
        // sample_ncpu 由 worker 上报层附加（engine 层无从知晓，与心跳 ncpu 同源）；
        // 探测失败保持 None（不掩盖引擎已采值）。
        usage.sample_ncpu = crate::caps::worker_ncpu();
    }

    task_cancel.cancel();
    // join 失败不静默：panic 被 tokio 包装成 JoinError，is_panic warn。
    if let Err(e) = log_task.await {
        if e.is_panic() {
            warn!(
                assignment_id = %task.assignment_id,
                build_id = %task.build_id,
                error = %crate::poller::join_failure_message(e),
                "Log stream task failed"
            );
        } else {
            debug!(
                assignment_id = %task.assignment_id,
                "Log stream task cancelled at join (defensive; no abort path exists)"
            );
        }
    }

    // 构建正常走完，disarm 撤销 Drop 清理（显式清理见 BuildDownloadGuard）。
    download_guard.disarm();
    cleanup_build_download_dir(&srpm_path, &build_root).await;

    let build_result = match &result.outputs {
        Ok(outputs) => {
            info!(
                assignment_id = %task.assignment_id,
                task_id = ?task.task_id,
                result_dir = %outputs.result_dir.display(),
                "Build succeeded"
            );

            let artifacts_json_path = outputs.result_dir.join("crbs-artifacts.json");
            match crbs_core::engine::artifact_harvest::collect_artifacts(
                &outputs.result_dir,
                Some(&cancel_token),
            )
            .await
            {
                Ok(mut artifacts) => {
                    artifacts.build_id = Some(outputs.build_id);
                    match serde_json::to_string_pretty(&artifacts) {
                        Ok(json_str) => {
                            match write_artifacts_json(&artifacts_json_path, json_str.as_bytes())
                                .await
                            {
                                Ok(()) => {
                                    tracing::debug!(path = %artifacts_json_path.display(), "crbs-artifacts.json written");
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        path = %artifacts_json_path.display(),
                                        error = %e,
                                        "Failed to write crbs-artifacts.json"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "Failed to serialize crbs-artifacts.json"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "collect_artifacts failed, continuing without metadata");
                }
            }

            let upload_ok =
                match upload_build_outputs(cfg, task, outputs, Some(&cancel_token)).await {
                    Ok(()) => {
                        info!(
                            assignment_id = %task.assignment_id,
                            task_id = ?task.task_id,
                            "Artifacts uploaded successfully"
                        );
                        true
                    }
                    Err(e) => {
                        warn!(
                            assignment_id = %task.assignment_id,
                            task_id = ?task.task_id,
                            error = %e,
                            "Failed to upload artifacts"
                        );
                        false
                    }
                };

            let engine_notes = state
                .get_build(outputs.build_id)
                .await
                .ok()
                .flatten()
                .and_then(|r| r.error_summary)
                .filter(|s| !s.is_empty());

            Ok(BuildResult {
                phase: "succeeded".to_string(),

                result_dir: None,
                error: if upload_ok {
                    None
                } else {
                    Some("artifact upload failed; artifacts must be fetched from the worker".into())
                },
                notes: engine_notes,

                resources: result.resources,

                local_result_dir: Some(outputs.result_dir.clone()),

                engine_build_id: Some(outputs.build_id),
                engine_result_root: Some(engine_result_root),
            })
        }
        Err(e) => {
            let phase = failure_phase(e);
            if phase == "cancelled" {
                info!(
                    assignment_id = %task.assignment_id,
                    task_id = ?task.task_id,
                    "Build cancelled"
                );
                Ok(BuildResult::terminal(phase, None, result.resources))
            } else {
                warn!(
                    assignment_id = %task.assignment_id,
                    task_id = ?task.task_id,
                    phase = phase,
                    error = %e,
                    "Build failed"
                );
                let log_paths = result.existing_log_paths().await;
                if log_paths.is_empty() {
                    warn!(
                        assignment_id = %task.assignment_id,
                        task_id = ?task.task_id,
                        result_dir = %result.result_dir.display(),
                        "No build.log found in result_dir after failure"
                    );
                }

                if let Err(upload_err) = upload_log_files(
                    cfg,
                    task,
                    &result.result_dir,
                    &log_paths,
                    Some(&cancel_token),
                )
                .await
                {
                    warn!(
                        assignment_id = %task.assignment_id,
                        task_id = ?task.task_id,
                        error = %upload_err,
                        "Failed to upload build logs"
                    );
                }
                Ok(BuildResult::terminal(
                    phase,
                    Some(e.to_string()),
                    result.resources,
                ))
            }
        }
    };

    if let Some(env) = reproduce_env.take() {
        env.teardown().await;
    }

    build_result
}

/// 构建错误→上报 phase 的映射：Cancelled→cancelled、Timeout→timeout、其余→failed
/// （与引擎侧同规则，hub 终态白名单已含 timeout）。pub(crate) 供 poller 归属探针
/// 复用，防两处规则漂移。
pub(crate) fn failure_phase(e: &CrbsError) -> &'static str {
    match e {
        CrbsError::Cancelled => "cancelled",
        CrbsError::Timeout => "timeout",
        _ => "failed",
    }
}

/// Hub 下发产品配置的失败即拒绝出口：空串 → Err——worker 无可靠本地
/// products/*.toml，静默回退会让构建跑在与 hub 认知脱节的产品定义上。
fn hub_product_config(task: &AssignedTask) -> crbs_core::Result<&str> {
    if task.product_config.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "assignment {} for product '{}' carries an empty product_config; refusing to \
                 fall back to local products/*.toml on the worker (upgrade the hub so it sends \
                 the product config)",
                task.assignment_id, task.product
            ),
        });
    }
    Ok(&task.product_config)
}

/// 执行远程 init 任务：使用 hub 下发的产品配置重建 base_os，并把结果上报
/// 到 hub（复用 report_result 端点，hub 侧按 kind=init 分流）。
pub async fn run_init(
    cfg: &WorkerConfig,
    worker_id: i64,
    task: &AssignedTask,
    cancel_token: CancellationToken,
    executed_assignments: &crate::poller::ExecutedAssignments,
) -> crbs_core::Result<()> {
    let product = task
        .init_product
        .as_deref()
        .or(if task.product.is_empty() {
            None
        } else {
            Some(&task.product)
        })
        .ok_or_else(|| CrbsError::ValidationFailed {
            message: "init assignment has no product".into(),
        })?;

    info!(
        assignment_id = %task.assignment_id,
        worker_id = %worker_id,
        product = %product,
        "Remote init: rebuilding base_os"
    );

    let result = run_init_inner(cfg, product, task, &cancel_token).await;

    report_init_result(
        cfg,
        worker_id,
        task,
        &result,
        &cancel_token,
        executed_assignments,
    )
    .await;

    result
}

/// init 结果上报与去重登记（与 build 路径 `poller::report_build_result` 的
/// 双成功记录同构）：succeeded 且上报被接受时登记 `ExecutedAssignments`，
/// 此后 reclaimer 重投递命中派发前查重、不再重执行；失败、上报被取消或耗
/// 尽重试均不登记（hub 未落账终态，重执行是唯一收敛路径）。
///
/// 上报被取消不等于没有终态：drain 取消令牌后 report_result 入口即返回
/// Cancelled，hub 侧 worker_tasks 滞留 running，has_active_init 按 (worker,
/// product) 持续阻断派发（滞留行要等 worker 重启重注册才被清理）——照
/// build 侧 `poller::report_terminal_after_cancel` 以独立短超时令牌补报真
/// 实 phase。hub 对非 succeeded 一律落 failed（cancelled 与真失败不可分辨，
/// 补报的价值在解除阻断）；重试中途被取消的成功 init 补报 succeeded 并登
/// 记去重，防止双跑。hub 幂等：已终态返回 409，重试层映射为送达成功，重复
/// 上报无害。
pub(crate) async fn report_init_result(
    cfg: &WorkerConfig,
    worker_id: i64,
    task: &AssignedTask,
    result: &crbs_core::Result<()>,
    cancel_token: &CancellationToken,
    executed_assignments: &crate::poller::ExecutedAssignments,
) {
    let succeeded = result.is_ok();
    let (phase, error) = match result {
        Ok(()) => ("succeeded".to_string(), None),
        Err(CrbsError::Cancelled) => ("cancelled".to_string(), None),
        Err(e) => ("failed".to_string(), Some(e.to_string())),
    };

    let build_result = BuildResult::terminal(&phase, error, None);

    match report_result(cfg, worker_id, task, &build_result, Some(cancel_token)).await {
        Ok(()) => {
            if succeeded {
                executed_assignments.record(task.assignment_id);
            }
        }
        Err(CrbsError::Cancelled) => {
            let reported =
                crate::poller::report_terminal_after_cancel(cfg, worker_id, task, &build_result)
                    .await;
            if reported && succeeded {
                executed_assignments.record(task.assignment_id);
            }
        }
        Err(e) => {
            warn!(
                assignment_id = %task.assignment_id,
                error = %e,
                "Failed to report init result to hub"
            );
        }
    }
}

async fn run_init_inner(
    cfg: &WorkerConfig,
    product: &str,
    task: &AssignedTask,
    cancel_token: &CancellationToken,
) -> crbs_core::Result<()> {
    let build_dir = PathBuf::from(&cfg.build_dir);
    ensure_safe_build_dir(&build_dir).await?;

    let state = Arc::new(StateStore::new(&build_dir).await?);

    let opts = crbs_core::BuildOptions::default();
    let engine = crbs_core::build_engine_from_options(
        product,
        &opts,
        state.clone(),
        Some(hub_product_config(task)?),
        Some(&PathBuf::from(&cfg.crbs_root)),
    )
    .await?;

    // init 整链超时：内部 base 安装自带 7200s 回退，此处对整链（快照解析 + 安装 +
    // overlay + post_init + swap 收尾）封 3h 上限——无上限时 hang 的 init 永久占用
    // worker permit 与 hub init 行。poller 的 init 总预算以本常量为源。
    let engine = engine.with_timeout(Some(std::time::Duration::from_secs(
        INIT_ENGINE_TIMEOUT_SECS,
    )));

    // init(true) 原子重建（临时目录 + rename swap）；bypass_guard=true 跳过 active
    // 检查（worker 是执行者）。
    engine.init(true, Some(cancel_token), None, true).await?;

    info!(
        assignment_id = %task.assignment_id,
        product = %product,
        "Remote init completed: base_os rebuilt"
    );

    Ok(())
}

/// SRPM 下载单次尝试超时：SRPM 可达数百 MB，重试层默认 30s 会在慢链路误杀正常
/// 下载，与 HTTP_FALLBACK_TIMEOUT_SECS 对齐。
const SRPM_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(HTTP_FALLBACK_TIMEOUT_SECS);

/// 从 Hub 下载 SRPM 到本地临时文件：send + 状态码检查 + 流式落盘整体包进
/// retry_with_timeout，瞬时错误不判死；任何阶段取消立即返 Cancelled。尝试内读/写
/// 失败先清理半截文件所在的 {assignment_id}/ 目录再返回。
async fn download_srpm(
    cfg: &WorkerConfig,
    task: &AssignedTask,
    cancel_token: &CancellationToken,
) -> crbs_core::Result<PathBuf> {
    let url = format!("{}{}", cfg.hub_url, task.srpm_url);
    let build_root = PathBuf::from(&cfg.build_dir);

    // 下载目录按 assignment_id（而非 build_id）命名隔离：reclaim 重派同一 build_id 时
    // 两次执行共享 {build_dir}/{build_id}/ 会同名互覆、先结束方 teardown 删对方
    // 文件；assignment_id 一次领取至多一个执行，同 NVR 并发也各落独立子目录。
    let build_dir = build_root.join(task.assignment_id.to_string());

    let result = retry_with_timeout(
        "download srpm",
        Some(cancel_token),
        SRPM_DOWNLOAD_TIMEOUT,
        || async {
            let client = cfg.build_http_client().await?;
            let request = client.get(&url).send();

            let resp = tokio::select! {
                _ = cancel_token.cancelled() => return Err(CrbsError::Cancelled),
                result = request => {
                    result.map_err(|e| crate::error::reqwest("download srpm", e))?
                }
            };

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(crate::error::http_response_error(
                    "download srpm",
                    status,
                    text,
                ));
            }

            tokio::fs::create_dir_all(&build_dir)
                .await
                .map_err(|e| CrbsError::from_io_context("create build download dir", e))?;

            #[cfg(unix)]
            enforce_group_rw(&build_dir, 0o2770, "build download dir").await;

            let filename = resolve_download_filename(
                resp.headers()
                    .get(reqwest::header::CONTENT_DISPOSITION)
                    .and_then(|v| v.to_str().ok()),
                &task.product,
                task.assignment_id,
            )?;
            let srpm_path = build_dir.join(&filename);

            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o660)
                .open(&srpm_path)
                .await
                .map_err(|e| CrbsError::from_io_context("create srpm file", e))?;
            #[cfg(unix)]
            enforce_group_rw(&srpm_path, 0o660, "srpm file").await;

            let mut resp = resp;
            loop {
                let chunk = tokio::select! {
                    _ = cancel_token.cancelled() => {
                        drop(file);
                        cleanup_dir_if_under_root(&build_dir, &build_root).await;
                        return Err(CrbsError::Cancelled);
                    }
                    chunk = resp.chunk() => match chunk {
                        Ok(c) => c,

                        Err(e) => {
                            drop(file);
                            cleanup_dir_if_under_root(&build_dir, &build_root).await;
                            return Err(crate::error::reqwest("read srpm chunk", e));
                        }
                    },
                };

                match chunk {
                    Some(bytes) => {
                        if let Err(e) = file.write_all(&bytes).await {
                            drop(file);
                            cleanup_dir_if_under_root(&build_dir, &build_root).await;
                            return Err(CrbsError::from_io_context("write srpm chunk", e));
                        }
                    }
                    None => break,
                }
            }

            Ok(srpm_path)
        },
    )
    .await;

    match result {
        Ok(path) => Ok(path),

        Err(e) => {
            cleanup_dir_if_under_root(&build_dir, &build_root).await;
            Err(e)
        }
    }
}

#[cfg(unix)]
async fn enforce_group_rw(path: &std::path::Path, mode: u32, label: &'static str) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await {
        warn!(
            path = %path.display(),
            error = %e,
            "Failed to chmod {label}; group rw may not be in effect"
        );
    }
    crbs_core::privilege::chown_to_crbs_group_async(path, false, label).await;
}

/// 写 crbs-artifacts.json 并补权限不变量（0660 + crbs 组）：该文件被 hub/UI 消费，
/// root worker 落的 0644/root:root 会让组内身份读取受限。
/// open 的 .mode 受 umask 削减且 chown 不补 mode，须显式 chmod（chmod 失败 warn、
/// 归组失败仅 debug——非 root 进程 chown 必 EPERM，预期路径）。
async fn write_artifacts_json(path: &std::path::Path, content: &[u8]) -> crbs_core::Result<()> {
    use tokio::io::AsyncWriteExt;

    // 结果目录对构建容器可写：同名 symlink 指向宿主文件时 create/truncate 会跟随
    // 改写目标（随后 chmod/chown 也落到目标）。先删条目本身（symlink 只删链接）再
    // create_new（O_EXCL）：重建链接只会让创建失败，绝不跟随写。
    match tokio::fs::remove_file(path).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(CrbsError::from_io_context(
                "clear stale crbs-artifacts.json",
                e,
            ))
        }
    }
    let mut f = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o660)
        .open(path)
        .await
        .map_err(|e| CrbsError::from_io_context("create crbs-artifacts.json", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).await
        {
            warn!(
                path = %path.display(),
                error = %e,
                "Failed to chmod crbs-artifacts.json to 0660; group rw may not be in effect"
            );
        }
    }
    f.write_all(content)
        .await
        .map_err(|e| CrbsError::from_io_context("write crbs-artifacts.json", e))?;
    f.sync_all().await.ok();
    drop(f);
    crbs_core::privilege::chown_to_crbs_group_async(path, false, "artifacts.json").await;
    Ok(())
}

struct BuildDownloadGuard {
    srpm_path: PathBuf,
    build_root: PathBuf,
    armed: bool,
}

/// run_build 前置步骤的 SRPM 下载目录清理守卫：前置步骤早退会绕过构建结束时的
/// 显式清理（`?` 早退与 panic 均触发 Drop）；收尾阶段 disarm 后由正常路径显式
/// await 清理。
impl BuildDownloadGuard {
    fn new(srpm_path: PathBuf, build_root: PathBuf) -> Self {
        Self {
            srpm_path,
            build_root,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for BuildDownloadGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let srpm_path = std::mem::take(&mut self.srpm_path);
        let build_root = std::mem::take(&mut self.build_root);

        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    cleanup_build_download_dir(&srpm_path, &build_root).await;
                });
            }
            Err(_) => {
                warn!(
                    srpm = %srpm_path.display(),
                    "BuildDownloadGuard dropped outside a tokio runtime; SRPM download dir leaks"
                );
            }
        }
    }
}

async fn cleanup_build_download_dir(srpm_path: &std::path::Path, build_root: &std::path::Path) {
    let Some(parent) = srpm_path.parent() else {
        return;
    };
    cleanup_dir_if_under_root(parent, build_root).await;
}

async fn cleanup_dir_if_under_root(dir: &std::path::Path, build_root: &std::path::Path) {
    if !dir_strictly_under_root(dir, build_root) {
        warn!(dir = %dir.display(), "Refusing to clean unexpected SRPM download dir");
        return;
    }
    if let Err(e) = tokio::fs::remove_dir_all(dir).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(dir = %dir.display(), error = %e, "Failed to remove build download dir");
        }
    }
}

/// `dir` 是否严格位于 `build_root` 之下且不等于其本身（删除前置断言，
/// executor 清理与 sweep 残留回收共用）。`Path::starts_with` 的前缀匹配挡
/// 不住 ParentDir（`build_root/1001/../../victim` 会放行），故要求
/// strip_prefix 成功且剩余组件不含 ParentDir 与 CurDir。
pub(crate) fn dir_strictly_under_root(dir: &std::path::Path, build_root: &std::path::Path) -> bool {
    dir != build_root
        && dir.strip_prefix(build_root).is_ok_and(|rel| {
            !rel.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        })
}

/// 判断下载文件名是否为单个 Normal 路径组件（词法判定）：拒绝空串、`/`、
/// `\`、`.`、`..`、绝对形态与 NUL——否则经 join 加 `File::create` 可写出
/// per-build 目录之外的文件。
fn is_single_component_filename(name: &str) -> bool {
    if name.is_empty() || name.contains(['/', '\\', '\0']) {
        return false;
    }
    let mut components = std::path::Path::new(name).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

/// 解析 SRPM 下载文件名：
/// - 无头或不可解析、单组件但不以 `.src.rpm` 结尾时，回退
///   `product-assignment_id` 占位名（只在本执行目录内使用）。
/// - 非单个 Normal 路径组件时直接报错拒绝下载（warn 加 Err）：恶意或被攻
///   陷的 Hub 借文件名实施路径穿越时，不再信任其响应体。
fn resolve_download_filename(
    content_disposition: Option<&str>,
    product: &str,
    assignment_id: i64,
) -> crbs_core::Result<String> {
    let placeholder = format!("{}-{assignment_id}.src.rpm", product);

    if !is_single_component_filename(&placeholder) {
        return Err(CrbsError::ValidationFailed {
            message: format!("unsafe product name for SRPM download placeholder: {product:?}"),
        });
    }
    let Some(header) = content_disposition else {
        return Ok(placeholder);
    };
    let Some(name) = parse_filename_from_content_disposition(header) else {
        return Ok(placeholder);
    };
    if !is_single_component_filename(&name) {
        warn!(
            filename = %name,
            assignment_id,
            "Hub returned unsafe SRPM filename, rejecting download"
        );
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "unsafe SRPM filename in Content-Disposition for assignment {assignment_id}: {name:?}"
            ),
        });
    }
    if !name.ends_with(".src.rpm") {
        return Ok(placeholder);
    }
    Ok(name)
}

fn parse_filename_from_content_disposition(header: &str) -> Option<String> {
    for part in header.split(';') {
        let part = part.trim();
        if let Some(value) = part
            .strip_prefix("filename*=UTF-8'")
            .or_else(|| part.strip_prefix("filename*="))
        {
            return Some(value.trim().to_string());
        }
        if let Some(value) = part.strip_prefix("filename=\"") {
            return value
                .strip_suffix('"')
                .or_else(|| value.rsplit_once('"').map(|(s, _)| s))
                .map(|s| s.to_string());
        }
        if let Some(value) = part.strip_prefix("filename=") {
            return Some(value.trim().to_string());
        }
    }
    None
}

async fn prepare_worker_reproduce(
    cfg: &crate::config::WorkerConfig,
    task: &crate::poller::AssignedTask,
    engine: crbs_core::engine::BuildEngine,
    cancel_token: &CancellationToken,
) -> crbs_core::Result<(
    crbs_core::engine::reproduce::ReproduceEnv,
    crbs_core::engine::BuildEngine,
)> {
    use crbs_core::engine::reproduce;

    let url = require_reproduce_packages_url(task)?;

    let build_dir = PathBuf::from(&cfg.build_dir);
    // reproduce：下载 build_packages.json 恢复包建复现快照仓；json 的 TempDir guard
    // 持有到构建结束、函数尾显式 teardown（GB 级同步删除不上 async 线程）。
    let json_tmp_dir =
        crbs_core::engine::cache::spawn_blocking_tempdir_in(build_dir, "json tmp dir").await?;
    let json_path = json_tmp_dir.path().join("build_packages.json");

    let full_url = format!("{}{}", cfg.hub_url, url);

    let src_dir = json_tmp_dir.path().to_path_buf();
    let mut json_tmp_guard = crbs_core::engine::cache::TempDirGuard::new(json_tmp_dir);
    let body = match download_build_packages_json(cfg, &full_url, cancel_token).await {
        Ok(body) => body,
        Err(e) => return Err(e),
    };
    tokio::fs::write(&json_path, &body)
        .await
        .map_err(|e| CrbsError::from_io_context("write build_packages.json", e))?;

    let env = match reproduce::prepare_reproduce_env(&src_dir, engine.config(), Some(cancel_token))
        .await
    {
        Ok(env) => env,
        Err(e) => return Err(e),
    };

    if let Some(dir) = json_tmp_guard.disarm() {
        drop_tempdir_off_worker(dir).await;
    }

    let engine = reproduce::apply_reproduce_engine(engine, &env);

    Ok((env, engine))
}

/// reproduce assignment 检查：缺 reproduce_packages_url → ValidationFailed 直接报错
///（消息点名缺口）。
fn require_reproduce_packages_url(task: &AssignedTask) -> crbs_core::Result<&str> {
    task.reproduce_packages_url
        .as_deref()
        .ok_or_else(|| CrbsError::ValidationFailed {
            message: "reproduce mode but no reproduce_packages_url in assignment".into(),
        })
}

async fn drop_tempdir_off_worker(dir: tempfile::TempDir) {
    if let Err(e) = tokio::task::spawn_blocking(move || drop(dir)).await {
        warn!(
            error = %e,
            "Temp dir drop task failed; dir left for sweeper (.tmp prefix) cleanup"
        );
    }
}

async fn download_build_packages_json(
    cfg: &WorkerConfig,
    full_url: &str,
    cancel_token: &CancellationToken,
) -> crbs_core::Result<bytes::Bytes> {
    retry_with_backoff(
        "download build_packages.json",
        Some(cancel_token),
        || async {
            let client = cfg.build_http_client().await?;
            let request = client.get(full_url).send();
            let resp = tokio::select! {
                _ = cancel_token.cancelled() => return Err(CrbsError::Cancelled),
                result = request => {
                    result.map_err(|e| crate::error::reqwest("download build_packages.json", e))?
                }
            };
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(crate::error::http_response_error(
                    "download build_packages.json",
                    status,
                    text,
                ));
            }
            let body = tokio::select! {
                _ = cancel_token.cancelled() => return Err(CrbsError::Cancelled),
                body = resp.bytes() => {
                    body.map_err(|e| crate::error::reqwest("read build_packages.json body", e))?
                }
            };
            Ok(body)
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::test_cfg;

    #[test]
    fn hub_product_config_rejects_empty_and_accepts_nonempty() {
        let task = AssignedTask {
            assignment_id: 7,
            task_id: Some(5),
            build_id: 14,
            product: "ule3".to_string(),
            srpm_url: String::new(),
            build_options: serde_json::Value::Null,
            product_config: String::new(),
            reproduce_packages_url: None,
            kind: "build".to_string(),
            init_product: None,
            product_repo_enabled: true,
            redelivered: false,
        };

        let err = hub_product_config(&task).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("product_config"), "msg: {msg}");
        assert!(msg.contains("ule3"), "msg: {msg}");
        assert!(msg.contains('7'), "msg: {msg}");
        assert!(msg.contains("refus"), "must refuse local fallback: {msg}");

        let nonempty = AssignedTask {
            product_config: "base_packages = [\"bash\"]\n".to_string(),
            ..task
        };
        assert_eq!(
            hub_product_config(&nonempty).unwrap(),
            "base_packages = [\"bash\"]\n"
        );
    }

    #[test]
    fn test_failure_phase_maps_timeout_and_cancelled() {
        assert_eq!(failure_phase(&CrbsError::Cancelled), "cancelled");
        assert_eq!(failure_phase(&CrbsError::Timeout), "timeout");
        assert_eq!(
            failure_phase(&CrbsError::io_message("rpm -qp failed".to_string())),
            "failed"
        );
        assert_eq!(
            failure_phase(&CrbsError::ValidationFailed {
                message: "bad opts".into()
            }),
            "failed"
        );
    }

    #[tokio::test]
    async fn per_build_download_dirs_are_isolated() {
        let tmp = tempfile::tempdir().unwrap();
        let build_root = tmp.path().to_path_buf();

        let filename = "same-name-1.0-1.src.rpm";
        let dir_a = build_root.join("1001");
        let dir_b = build_root.join("1002");
        tokio::fs::create_dir_all(&dir_a).await.unwrap();
        tokio::fs::create_dir_all(&dir_b).await.unwrap();
        let srpm_a = dir_a.join(filename);
        let srpm_b = dir_b.join(filename);
        tokio::fs::write(&srpm_a, b"AAAA").await.unwrap();
        tokio::fs::write(&srpm_b, b"BBBB").await.unwrap();

        assert_ne!(srpm_a, srpm_b);

        cleanup_build_download_dir(&srpm_a, &build_root).await;
        assert!(!srpm_a.exists(), "build A SRPM should be removed");
        assert!(!dir_a.exists(), "build A dir should be removed");
        assert!(srpm_b.exists(), "build B SRPM must survive A's teardown");
        assert_eq!(tokio::fs::read(&srpm_b).await.unwrap(), b"BBBB");
    }

    #[tokio::test]
    async fn cleanup_refuses_to_delete_build_root_or_outside() {
        let tmp = tempfile::tempdir().unwrap();
        let build_root = tmp.path().join("build");
        tokio::fs::create_dir_all(&build_root).await.unwrap();

        let srpm_at_root = build_root.join("x.src.rpm");
        tokio::fs::write(&srpm_at_root, b"x").await.unwrap();
        cleanup_build_download_dir(&srpm_at_root, &build_root).await;
        assert!(build_root.is_dir(), "build_root must not be removed");

        let outside_dir = tmp.path().join("outside");
        tokio::fs::create_dir_all(&outside_dir).await.unwrap();
        let srpm_outside = outside_dir.join("y.src.rpm");
        tokio::fs::write(&srpm_outside, b"y").await.unwrap();
        cleanup_build_download_dir(&srpm_outside, &build_root).await;
        assert!(outside_dir.is_dir(), "outside dir must not be removed");
    }

    #[tokio::test]
    async fn cleanup_refuses_traversal_parent_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let build_root = tmp.path().join("build");
        tokio::fs::create_dir_all(&build_root).await.unwrap();
        let victim = tmp.path().join("victim");
        tokio::fs::create_dir_all(&victim).await.unwrap();
        let keep = victim.join("keep.txt");
        tokio::fs::write(&keep, b"keep").await.unwrap();

        let srpm_path = build_root.join("1001").join("../../victim/x.src.rpm");
        cleanup_build_download_dir(&srpm_path, &build_root).await;
        assert!(keep.exists(), "victim file must survive");
        assert!(victim.is_dir(), "victim dir must survive");
    }

    #[test]
    fn test_is_single_component_filename() {
        assert!(is_single_component_filename("pkg-1.0.src.rpm"));
        assert!(is_single_component_filename("pkg..name-1.0.src.rpm"));

        assert!(!is_single_component_filename("a/b.src.rpm"));
        assert!(!is_single_component_filename("../x.src.rpm"));
        assert!(!is_single_component_filename(".."));
        assert!(!is_single_component_filename("."));
        assert!(!is_single_component_filename(""));
        assert!(!is_single_component_filename("/etc/x.src.rpm"));
        assert!(!is_single_component_filename("a\\b.src.rpm"));
        assert!(!is_single_component_filename("a\0b.src.rpm"));
    }

    #[test]
    fn test_resolve_download_filename() {
        let ok = |cd: Option<&str>| resolve_download_filename(cd, "prod", 42);

        assert_eq!(
            ok(Some("attachment; filename=\"pkg-1.0-1.src.rpm\"")).unwrap(),
            "pkg-1.0-1.src.rpm"
        );
        for evil in [
            "attachment; filename=\"../../etc/evil.src.rpm\"",
            "attachment; filename=\"sub/dir/x.src.rpm\"",
            "attachment; filename=\"/abs/evil.src.rpm\"",
            "attachment; filename=\"..\"",
            "attachment; filename=\"\"",
        ] {
            assert!(
                ok(Some(evil)).is_err(),
                "malicious Content-Disposition must be rejected: {evil}"
            );
        }
        assert_eq!(
            ok(Some("attachment; filename=\"notes.txt\"")).unwrap(),
            "prod-42.src.rpm"
        );
        assert_eq!(ok(None).unwrap(), "prod-42.src.rpm");
        assert_eq!(ok(Some("attachment")).unwrap(), "prod-42.src.rpm");

        assert!(resolve_download_filename(None, "../evil", 42).is_err());
        assert!(resolve_download_filename(Some("attachment"), "../evil", 42).is_err());
        assert_eq!(
            resolve_download_filename(None, "prod", 42).unwrap(),
            "prod-42.src.rpm"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_artifacts_json_lands_exact_0660() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("crbs-artifacts.json");

        write_artifacts_json(&path, b"{}").await.unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "artifacts.json must land at exact 0660");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_artifacts_json_does_not_follow_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("host-file");
        std::fs::write(&target, b"host").unwrap();
        let path = tmp.path().join("crbs-artifacts.json");
        std::os::unix::fs::symlink(&target, &path).unwrap();

        write_artifacts_json(&path, b"{}").await.unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"host");
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
        assert!(!std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    fn reproduce_task(reproduce_packages_url: Option<String>) -> AssignedTask {
        AssignedTask {
            assignment_id: 7,
            task_id: Some(5),
            build_id: 14,
            product: "ule3".to_string(),
            srpm_url: String::new(),
            build_options: serde_json::Value::Null,
            product_config: String::new(),
            reproduce_packages_url,
            kind: "build".to_string(),
            init_product: None,
            product_repo_enabled: true,
            redelivered: false,
        }
    }

    #[tokio::test]
    async fn drop_tempdir_off_worker_removes_dir() {
        let outer = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir_in(outer.path()).unwrap();
        let path = dir.path().to_path_buf();
        assert!(path.is_dir());

        drop_tempdir_off_worker(dir).await;

        assert!(
            !path.exists(),
            "temp dir must be removed off the worker thread"
        );
    }

    #[test]
    fn require_reproduce_packages_url_rejects_missing_url() {
        let err = require_reproduce_packages_url(&reproduce_task(None)).unwrap_err();
        assert!(
            matches!(err, CrbsError::ValidationFailed { .. }),
            "err: {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("reproduce_packages_url"), "msg: {msg}");
        assert!(msg.contains("reproduce mode"), "msg: {msg}");

        let with_url = reproduce_task(Some("/api/v1/builds/14/packages.json".to_string()));
        assert_eq!(
            require_reproduce_packages_url(&with_url).unwrap(),
            "/api/v1/builds/14/packages.json"
        );
    }

    async fn serve_503_then_200(listener: tokio::net::TcpListener, body: &'static str) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for i in 0..2 {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];

            loop {
                let n = sock.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&buf).to_lowercase();
            let method = head
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().next())
                .unwrap_or("");
            assert_eq!(method, "get", "build_packages.json must be fetched via GET");
            let resp: String = if i == 0 {
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
            };
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();
        }
    }

    #[tokio::test]
    async fn download_build_packages_json_retries_transient_5xx() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_503_then_200(listener, "[]"));

        let cfg = test_cfg(format!("http://{}", addr), None).await;
        let cancel = CancellationToken::new();
        let body = download_build_packages_json(
            &cfg,
            &format!("http://{}/api/v1/builds/14/packages.json", addr),
            &cancel,
        )
        .await
        .unwrap();

        assert_eq!(&body[..], b"[]", "must return the retried 200 body");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn download_build_packages_json_cancel_returns_cancelled() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.unwrap();
            accepted_tx.send(()).unwrap();

            std::future::pending::<()>().await;
        });

        let cfg = test_cfg(format!("http://{}", addr), None).await;
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let url = format!("http://{}/api/v1/builds/14/packages.json", addr);
        let download =
            tokio::spawn(
                async move { download_build_packages_json(&cfg, &url, &task_cancel).await },
            );

        accepted_rx.await.unwrap();
        cancel.cancel();
        let err = download.await.unwrap().unwrap_err();
        assert!(
            matches!(err, CrbsError::Cancelled),
            "in-flight cancel must surface Cancelled, got: {err}"
        );
        server.abort();
    }
}

#[cfg(test)]
mod dir_strictly_under_root_tests {
    use super::dir_strictly_under_root;
    use std::path::Path;

    #[test]
    fn rejects_escape_and_foreign_paths() {
        let root = Path::new("/var/lib/crbs-worker/builds");
        assert!(dir_strictly_under_root(&root.join("1001"), root));
        assert!(dir_strictly_under_root(&root.join("1001/rpms"), root));
        assert!(
            !dir_strictly_under_root(root, root),
            "root itself must be rejected"
        );
        assert!(!dir_strictly_under_root(
            Path::new("/var/lib/crbs-worker"),
            root
        ));
        assert!(!dir_strictly_under_root(
            &root.join("1001/../../victim"),
            root
        ));
        assert!(!dir_strictly_under_root(
            &root.join("../builds-victim"),
            root
        ));
    }
}

#[cfg(test)]
mod mirror_seed_claim_tests {
    use super::{claim_stale_self_build_rows, InFlightHubBuildGuard};

    static CLAIM_SERIALIZER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn claim_test_store() -> (tempfile::TempDir, std::sync::Arc<crbs_core::StateStore>) {
        let tmp = tempfile::tempdir().unwrap();
        let state = std::sync::Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        (tmp, state)
    }

    #[tokio::test]
    async fn stale_self_row_claimed_before_mirror_seed_unblocks_attach() {
        let _serial = CLAIM_SERIALIZER.lock().await;
        let (_tmp, state) = claim_test_store().await;
        let pid = std::process::id() as i64;

        crbs_core::engine::BuildLifecycle::attach_remote(
            state.clone(),
            100,
            "mydist",
            "hello-1.0-1",
            pid,
        )
        .await
        .unwrap();

        assert_eq!(
            state.get_build(100).await.unwrap().unwrap().phase,
            "pending"
        );

        claim_stale_self_build_rows(&state, "mydist", "hello-1.0-1", 200).await;

        let claimed = state.get_build(100).await.unwrap().unwrap();
        assert_eq!(
            claimed.phase, "failed",
            "stale self row must be claimed to failed"
        );
        assert!(
            claimed
                .error_summary
                .as_deref()
                .unwrap_or("")
                .contains("mirror seed"),
            "claim summary must be discoverable: {:?}",
            claimed.error_summary
        );

        let lifecycle = crbs_core::engine::BuildLifecycle::attach_remote(
            state.clone(),
            200,
            "mydist",
            "hello-1.0-1",
            pid,
        )
        .await
        .unwrap_or_else(|e| panic!("attach must succeed after claim, got: {e}"));
        assert_eq!(
            lifecycle.build_id(),
            200,
            "new build must land on its own hub id, not adopt the stale row"
        );
        lifecycle
            .complete(crbs_core::engine::BuildOutcome::Succeeded, None)
            .await
            .unwrap();
        assert_eq!(
            state.get_build(200).await.unwrap().unwrap().phase,
            "succeeded",
            "new build lifecycle must complete normally"
        );

        claim_stale_self_build_rows(&state, "mydist", "hello-1.0-1", 300).await;
        assert_eq!(
            state.get_build(100).await.unwrap().unwrap().phase,
            "failed",
            "re-claim must not resurrect or rewrite the terminal row"
        );
    }

    #[tokio::test]
    async fn null_pid_leftover_row_is_claimed() {
        let _serial = CLAIM_SERIALIZER.lock().await;
        let (_tmp, state) = claim_test_store().await;

        state
            .seed_remote_build_mirror(100, "mydist", "hello-1.0-1")
            .await
            .unwrap();

        claim_stale_self_build_rows(&state, "mydist", "hello-1.0-1", 200).await;

        assert_eq!(
            state.get_build(100).await.unwrap().unwrap().phase,
            "failed",
            "half-written leftover (NULL pid) must be claimable"
        );
    }

    #[tokio::test]
    async fn foreign_pid_row_not_claimed_and_attach_still_fails() {
        let _serial = CLAIM_SERIALIZER.lock().await;
        let (_tmp, state) = claim_test_store().await;
        let pid = std::process::id() as i64;

        crbs_core::engine::BuildLifecycle::attach_remote(
            state.clone(),
            100,
            "mydist",
            "hello-1.0-1",
            1,
        )
        .await
        .unwrap();

        claim_stale_self_build_rows(&state, "mydist", "hello-1.0-1", 200).await;

        let row = state.get_build(100).await.unwrap().unwrap();
        assert_eq!(row.phase, "pending", "foreign row must stay untouched");
        assert_eq!(row.crbs_pid, Some(1), "foreign row pid must stay untouched");
        assert!(
            crbs_core::engine::BuildLifecycle::attach_remote(
                state.clone(),
                200,
                "mydist",
                "hello-1.0-1",
                pid,
            )
            .await
            .is_err(),
            "unclaimed blocking row keeps the existing attach failure path (engine fallback -> conflict)"
        );
    }

    #[tokio::test]
    async fn in_flight_row_not_claimed() {
        let _serial = CLAIM_SERIALIZER.lock().await;
        let (_tmp, state) = claim_test_store().await;
        let pid = std::process::id() as i64;

        crbs_core::engine::BuildLifecycle::attach_remote(
            state.clone(),
            100,
            "mydist",
            "hello-1.0-1",
            pid,
        )
        .await
        .unwrap();
        let _in_flight = InFlightHubBuildGuard::new(100);

        claim_stale_self_build_rows(&state, "mydist", "hello-1.0-1", 200).await;

        let row = state.get_build(100).await.unwrap().unwrap();
        assert_eq!(
            row.phase, "pending",
            "in-flight row must be excluded from claiming"
        );
        assert!(
            crbs_core::engine::BuildLifecycle::attach_remote(
                state.clone(),
                200,
                "mydist",
                "hello-1.0-1",
                pid,
            )
            .await
            .is_err(),
            "concurrent same-identity seed keeps the existing failure path"
        );
    }
}
