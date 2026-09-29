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

/// 远程 init 的引擎整链超时（秒）：base 安装内部已有 7200s 回退，整链再封
/// 3h 上限（构成见 `run_init_inner`）；poller 的 init 总预算以本常量为源。
pub(crate) const INIT_ENGINE_TIMEOUT_SECS: u64 = 3 * 3600;

/// 入口取消守卫：令牌已取消即返回 `Cancelled`，未传或未取消放行。
fn ensure_not_cancelled(cancel_token: Option<&CancellationToken>) -> crbs_core::Result<()> {
    if cancel_token.is_some_and(|t| t.is_cancelled()) {
        return Err(CrbsError::Cancelled);
    }
    Ok(())
}

/// 本进程在途构建的 hub build id 集：镜像播种拆引信的认领排除集。镜像行
/// attach 时写入的 pid 是本进程自身，"pid == 本进程"区分不了在途与陈旧残留
///（hub 允许同 NVR 异 hub arch 的两个构建并发活跃，派到同一 worker 时本地行
/// arch 恒 NULL、归一后必撞同一 identity）；注册先于播种（行存在 ⇒ 已注册，
/// 种子到 attach 只有亚毫秒窗），认领侧据此放行陈旧行、放走在途行。Mutex
/// 短临界区（insert/remove/快照 clone），不跨 await。
static IN_FLIGHT_HUB_BUILD_IDS: std::sync::LazyLock<std::sync::Mutex<HashSet<i64>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashSet::new()));

/// 注册一个 hub build id 进入在途集；Drop 移除（panic 安全）。
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

/// 镜像播种前的拆引信（陈旧活跃行的存量自愈）：complete/相位
/// 写失败被吞遗留的陈旧活跃行 pid 恰为本进程、僵尸回收按 pid 存活判定永不
/// 触发，同 identity 再派时播种撞 uq_active_builds_identity → attach 降级 →
/// 引擎自插撞活跃复查 → Conflict 判败。此处把可确证属本进程残留的阻塞行
/// 收口为 failed，播种即无索引碰撞。三重认领门，缺一不动行：
/// - pid 归属本进程（NULL = 播种后 attach 前的半写入残留，同认——不可能属
///   在途执行，在途行注册先于播种）；
/// - 不在本进程在途集（防误杀并发同 identity 的他 build 行）；
/// - 非本次 build id（同 id 重派走 seed 的终态重置分支，不归本函数）。
///
/// 他进程名下的行一律不动（别人的历史，交启动期 GC）；误杀在途行的最坏
/// 后果 = 该行后续终态写被守卫拒绝（warn），hub 侧不受影响。失败仅 warn，
/// 播种碰撞维持既有降级路径。
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

/// 执行单个构建任务。`resource_slot`：poller 预算 abort 兜底快照槽位——
/// 引擎建采样器时把句柄写入，任务体被 abort 后 poller 仍可读已累计值。
pub async fn run_build(
    cfg: &WorkerConfig,
    worker_id: i64,
    task: &AssignedTask,
    cancel_token: CancellationToken,
    resource_slot: crbs_core::engine::ResourceSnapshotSlot,
) -> crbs_core::Result<BuildResult> {
    // 确保 build_dir 安全（不在 /tmp，无符号链接攻击）——必须先于首个写路径
    // download_srpm 的 create_dir_all。
    let build_root = PathBuf::from(&cfg.build_dir);
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

    // 产品配置来自 Hub 下发：空串 fail-closed 拒绝，不做本地 products/*.toml
    // 回退（见 [`hub_product_config`]）。
    let opts: crbs_core::BuildOptions = serde_json::from_value(task.build_options.clone())
        .map_err(|e| CrbsError::ValidationFailed {
            message: format!("parse build_options: {}", e),
        })?;

    // reproduce：backend / 资源限制不读复现请求——走与正常构建相同的解析链
    //（create_backend ← config.backend 全局→产品→默认），容器 /proc 挂载语义
    // 与源构建同态；no_network 与其余选项仍随请求。
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
        // 显式 pin crbs_root = worker.toml crbs_root：引擎默认值变更不得漂移
        // worker 的结果/状态位置。
        Some(&PathBuf::from(&cfg.crbs_root)),
    )
    .await?;
    let engine = crbs_core::apply_options_to_engine(engine, &opts)?;
    // 超时兜底：apply_options_to_engine 只透传显式 timeout（None = 引擎默认
    // 无超时），hang 构建永久占用 hub running 行 + worker permit（心跳活着
    // reclaimer 永不回收）→ 落 worker.toml 的 build_timeout_secs。
    let engine = engine
        .with_timeout(
            effective_build_timeout(opts.timeout, cfg.build_timeout_secs)
                .map(std::time::Duration::from_secs),
        )
        .with_resource_snapshot_slot(resource_slot);

    // 本地推导产品 repo baseurl：product_repo_enabled=false / network=false /
    // init 任务不注入；noarch 映射到产品配置第一个具体 arch（hub 不发布 noarch 目录）。
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

    // reproduce：下载 build_packages.json 恢复包建复现快照仓（解析域 = 记录
    // 全集）；env 的 TempDir guard 持有到构建结束、函数尾显式 teardown（GB 级
    // 同步删除不上 async 线程）。
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
                // 双报收敛：同一 e 由 poller 的 warn 统一报告，此处降 debug
                // 只留 source_build_id 结构化上下文。
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

    // 日志流用子 token：shutdown 或构建完成都会取消它，仅本任务生命周期内有效。
    let task_cancel = cancel_token.child_token();
    let log_cancel = task_cancel.clone();

    // pkg_name 仅在引擎未回报确切 result_dir 时作 mtime 扫描降级定位（旧引擎/异常）。
    let pkg_name = match crbs_core::engine::srpm_pkg_name(&srpm_path) {
        Ok(p) => p,
        Err(e) => {
            // 早退须先 teardown reproduce_env（TempDir guard 不能随 return Drop，同函数尾）。
            if let Some(env) = reproduce_env.take() {
                env.teardown().await;
            }
            return Err(e);
        }
    };

    // lifecycle 落 hub id 空间：attach hub 下发的 build_id（本地行缺失先播种
    // 镜像行，见 BuildLifecycle::attach_remote），profile.json /
    // crbs-artifacts.json / 结果目录叶子统一 hub id，不写本地自增 id。
    // 播种/attach 失败降级 warn：本地记账缺失不阻断构建，引擎自插行兜底
    //（artifact 元数据回落本地 id）。播种前先拆引信：本进程陈旧活跃行认领
    // 收口为 failed，同 identity 再派不再撞 uq_active_builds_identity 判败。
    claim_stale_self_build_rows(&state, &task.product, &pkg_name, task.build_id).await;
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

    // 引擎前置回报确切 result_dir 的 watch 通道：避免同包并发 mtime 扫描误报兄弟构建日志。
    let (result_dir_tx, result_dir_rx) = tokio::sync::watch::channel::<Option<PathBuf>>(None);

    let engine_result_root = engine.config().result_dir.clone();
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

    // sample_ncpu 由 worker 上报层附加（engine 层无从知晓，与心跳 ncpu 同源）；
    // 探测失败保持 None（不掩盖引擎已采值），三处 BuildResult 组装共用本值。
    if let Some(usage) = result.resources.as_mut() {
        usage.sample_ncpu = crate::caps::worker_ncpu();
    }

    // 取消日志流并等待；join 失败不静默（panic 被 tokio 吞成 JoinError，is_panic warn）。
    task_cancel.cancel();
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

    // 构建正常走完，disarm 撤销 Drop 兜底（显式清理见 [`BuildDownloadGuard`]）。
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

            // 采集产物元数据，失败非致命；取消用外层 token（task_cancel 已 cancel）。
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
            // 软告警备注回传：引擎写进 worker 本地 build 行 error_summary
            //（hub 行看不到），读本地行带回由 hub 落库；读取失败仅降级不带 notes。
            let engine_notes = state
                .get_build(outputs.build_id)
                .await
                .ok()
                .flatten()
                .and_then(|r| r.error_summary)
                .filter(|s| !s.is_empty());

            Ok(BuildResult {
                phase: "succeeded".to_string(),
                // 不回传本地路径给 Hub（避免泄露 Worker 目录结构）。
                result_dir: None,
                error: if upload_ok {
                    None
                } else {
                    Some("artifact upload failed; artifacts must be fetched from the worker".into())
                },
                notes: engine_notes,
                // 资源采样随终态上报（失败/取消路径同样尽力取已采值）。
                resources: result.resources,
                // 本地产物目录：上报失败时的告警定位与人工恢复依据（不进 payload）。
                local_result_dir: Some(outputs.result_dir.clone()),
                // 引擎本地 build_id（结果目录叶子名后缀）：上报成功后的删除
                // 断言用（poller::report_build_result）。
                engine_build_id: Some(outputs.build_id),
                engine_result_root: Some(engine_result_root),
            })
        }
        Err(e) => {
            // 三分映射见 [`failure_phase`]；错误文本不变，phase 只影响归类。
            let phase = failure_phase(e);
            if phase == "cancelled" {
                // 取消是 shutdown / hub 取消的正常稳态路径，与 poller 侧同为 info。
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
                // 即使 build.log 缺失，也要尝试上传 crbs-logs/（函数内部空集 no-op）。
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

    // 构建已结束，显式 teardown reproduce 临时环境（GB 级同步 remove_dir_all
    // 不上 async 线程，teardown 内部走 spawn_blocking）。
    if let Some(env) = reproduce_env.take() {
        env.teardown().await;
    }

    build_result
}

/// 构建错误→上报 phase 的映射：Cancelled→cancelled、Timeout→timeout、其余
/// →failed（与引擎侧 complete_setup_failure 同规则，hub 终态白名单已含
/// timeout）。pub(crate) 供 poller 归属探针复用，防两处口径漂移。
pub(crate) fn failure_phase(e: &CrbsError) -> &'static str {
    match e {
        CrbsError::Cancelled => "cancelled",
        CrbsError::Timeout => "timeout",
        _ => "failed",
    }
}

/// Hub 下发产品配置的 fail-closed 出口：空串 → `Err`，非空 → 借用引用——
/// worker 无可靠本地 `products/*.toml`，静默回退会让构建跑在与 hub 认知
/// 脱节的产品定义上。
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

/// 执行远程 init 任务：用 hub 下发的产品配置重建 base_os，上报结果到 hub
///（复用 report_result 端点，hub 侧按 kind=init 分流）。
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

/// init 结果上报与去重登记（同 build 路径 `poller::report_build_result` 的双成功
/// record）：succeeded 且上报被接受 → 登记 `ExecutedAssignments`，此后
/// reclaimer 重投递命中派发前查重不再重执行；失败 / 上报被取消 / 耗尽重试
/// 不登记（hub 未落账终态，重执行是唯一收敛）。
///
/// 上报被取消 ≠ 没有终态：drain 取消 token 后 report_result 入口即返
/// Cancelled，hub 侧 worker_tasks 滞 running、has_active_init 按 (worker,
/// product) 持续阻断派发（滞留行要等 worker 重启重注册才被清）——照 build 侧
/// `poller::report_terminal_after_cancel` 用独立短超时 token 补报真实 phase。
/// hub 对非 succeeded 一律落 failed（cancelled 与真失败不可分辨，补报价值在
/// 解除阻断）；重试中途被取消的成功 init 补报 succeeded 并登记去重防双跑。
/// hub 幂等：已终态 → 409 → 重试层映射送达成功，重复上报 no-op。
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
            // token 已取消 → 常规入口即返 Cancelled，独立 token 补报真实 phase。
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

    // 空串 fail-closed 拒绝、不回退本地文件（见 [`hub_product_config`]）。
    let opts = crbs_core::BuildOptions::default();
    let engine = crbs_core::build_engine_from_options(
        product,
        &opts,
        state.clone(),
        Some(hub_product_config(task)?),
        Some(&PathBuf::from(&cfg.crbs_root)),
    )
    .await?;
    // init 整链超时：内部 base 安装自带 7200s 回退，此处对整链（快照解析 +
    // 安装 + overlay + post_init + swap 收尾）封 3h 上限——无上限时 hang 的
    // init 永久占用 worker permit 与 hub init 行。poller 的 init 总预算以本
    // 常量为源（见 poller::assignment_budget）。
    let engine = engine.with_timeout(Some(std::time::Duration::from_secs(
        INIT_ENGINE_TIMEOUT_SECS,
    )));

    // init(true) 原子重建（临时目录 + rename swap）；bypass_guard=true 跳过 active 守卫（worker 是执行者）。
    engine.init(true, Some(cancel_token), None, true).await?;

    info!(
        assignment_id = %task.assignment_id,
        product = %product,
        "Remote init completed: base_os rebuilt"
    );

    Ok(())
}

/// SRPM 下载单次尝试超时：SRPM 可达数百 MB，重试层默认 30s 会在慢链路误杀
/// 正常下载，与 [`HTTP_FALLBACK_TIMEOUT_SECS`] 对齐。
const SRPM_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(HTTP_FALLBACK_TIMEOUT_SECS);

/// 从 Hub 下载 SRPM 到本地临时文件：send + 状态码检查 + 流式落盘整体包进
/// [`retry_with_timeout`]，瞬时错误不判死；任何阶段取消立即返 `Cancelled`。
/// 尝试内读/写失败先清理半截文件所在的 `{assignment_id}/` 目录再返回。
async fn download_srpm(
    cfg: &WorkerConfig,
    task: &AssignedTask,
    cancel_token: &CancellationToken,
) -> crbs_core::Result<PathBuf> {
    let url = format!("{}{}", cfg.hub_url, task.srpm_url);
    let build_root = PathBuf::from(&cfg.build_dir);
    // 下载目录按 assignment_id（非 build_id）键控：reclaim 重派同一 build_id 时
    // 两次执行共享 `{build_dir}/{build_id}/` 会同名互覆、先结束方 teardown 删
    // 对方文件；assignment_id 一次领取至多一个执行，同 NVR 并发也各落独立子目录。
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

            // 权限不变量：叶子目录 2770 + crbs 组。
            #[cfg(unix)]
            enforce_group_rw(&build_dir, 0o2770, "build download dir").await;

            // 优先用 Content-Disposition 文件名（保留原始 SRPM 名）；必须为单个
            // Normal 路径组件，否则 fail-closed——worker 特权运行，`File::create`
            // 会跟随 `/`、`..` 逃出 per-build 目录。
            let filename = resolve_download_filename(
                resp.headers()
                    .get(reqwest::header::CONTENT_DISPOSITION)
                    .and_then(|v| v.to_str().ok()),
                &task.product,
                task.assignment_id,
            )?;
            let srpm_path = build_dir.join(&filename);

            // 流式分 chunk 写入（大 SRPM 不全量读入内存）；取消时删除本 build
            // 整个下载子目录。权限：.mode(0o660) 受 umask 削减（022 → 0640）
            // 且 chown 不补 mode，open 后显式 set_permissions（不受 umask
            // 影响），失败 warn。
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
                        // 读失败：半截子目录不能残留（assignment_id 不复用），清理后交重试层。
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
        // 兜底清理：最后一次尝试可能失败于 create_dir 之后、内部清理之前
        //（如文件名校验早退）；幂等（NotFound 容忍），对 Cancelled 同样适用。
        Err(e) => {
            cleanup_dir_if_under_root(&build_dir, &build_root).await;
            Err(e)
        }
    }
}

/// 写 crbs-artifacts.json 并补权限不变量（0660 + crbs 组）：该文件被 hub/UI
/// 消费，root worker 落的 0644/root:root 会让组内身份读取受限。
/// 权限不变量落地（open 的 .mode 受 umask 削减且 chown 不补 mode，须显式
/// chmod）：chmod 失败 warn（通常意味着权限未生效）、归组失败仅 debug
///（非 root 进程 chown 必 EPERM，预期路径）。下载目录与 SRPM 文件两个创建点
/// 共用；artifacts.json 的归组在 write 之后，时序不同不合用。
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

async fn write_artifacts_json(path: &std::path::Path, content: &[u8]) -> crbs_core::Result<()> {
    use tokio::io::AsyncWriteExt;
    // 结果目录对构建容器可写：同名 symlink 指向宿主文件时 create/truncate 会
    // 跟随改写目标（随后 chmod/chown 也落到目标）。先删条目本身（symlink 只删
    // 链接）再 create_new（O_EXCL）：重建链接只会让创建失败，绝不跟随写。
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
    // .mode(0o660) 受 umask 削减且 chown 不补 mode，open 后显式 chmod，失败 warn。
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

/// run_build 前置步骤的 SRPM 下载目录清理守卫：前置步骤早退会绕过构建结束
/// 处的显式清理，泄漏 SRPM 与下载子目录（assignment_id 不复用，残留只增不
/// 减）。Drop 兜底（覆盖 `?` 早退与 panic）；收尾阶段 [`Self::disarm`] 后由
/// 末尾显式 await 清理接管。
struct BuildDownloadGuard {
    srpm_path: PathBuf,
    build_root: PathBuf,
    armed: bool,
}

impl BuildDownloadGuard {
    fn new(srpm_path: PathBuf, build_root: PathBuf) -> Self {
        Self {
            srpm_path,
            build_root,
            armed: true,
        }
    }

    /// 撤销 Drop 清理：调用方将显式清理（需要 await 完成，Drop 做不到）。
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for BuildDownloadGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Drop 不能 await → 后台清理（cleanup 自带隔离与词法护栏，失败仅 warn）。
        let srpm_path = std::mem::take(&mut self.srpm_path);
        let build_root = std::mem::take(&mut self.build_root);
        // worker drain 卸载运行时后 Drop 可能落在 runtime 之外：裸 tokio::spawn
        // 会 panic-in-drop 直接带崩进程。
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

/// 删除本 assignment 专属的 SRPM 下载子目录：只删 `srpm_path` 父目录（安全判定
/// 见 [`cleanup_dir_if_under_root`]）。
async fn cleanup_build_download_dir(srpm_path: &std::path::Path, build_root: &std::path::Path) {
    let Some(parent) = srpm_path.parent() else {
        return;
    };
    cleanup_dir_if_under_root(parent, build_root).await;
}

/// 删除 `dir`，前提是严格位于 `build_root` 之下且不等于根本身（判定见
/// [`dir_strictly_under_root`]）。
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

/// `dir` 是否严格位于 `build_root` 之下且不等于其本身（删除前置断言，executor
/// 清理与 sweep 残留回收共用）。`Path::starts_with` 前缀匹配挡不住 ParentDir
///（`build_root/1001/../../victim` 会放行），故要求 strip_prefix 成功且剩余
/// 组件不含 ParentDir/CurDir。
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

/// 判断下载文件名是否为单个 Normal 路径组件（词法）：拒绝空串、`/`、`\`、
/// `.`、`..`、绝对形态与 NUL——经 join + `File::create` 可写出 per-build 目录。
fn is_single_component_filename(name: &str) -> bool {
    if name.is_empty() || name.contains(['/', '\\', '\0']) {
        return false;
    }
    let mut components = std::path::Path::new(name).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

/// 解析 SRPM 下载文件名：
/// - 无头/不可解析、单组件但不以 `.src.rpm` 结尾 → 回退 `product-assignment_id`
///   占位名（只在本执行目录内用）。
/// - 非单个 Normal 路径组件 → fail-closed 拒绝下载（warn + Err）：恶意/被攻陷
///   Hub 借文件名穿越时，不应继续信任其响应体。
fn resolve_download_filename(
    content_disposition: Option<&str>,
    product: &str,
    assignment_id: i64,
) -> crbs_core::Result<String> {
    let placeholder = format!("{}-{assignment_id}.src.rpm", product);
    // 占位名同样必须单组件：product 来自 hub，含 `..`/`/` 时会经 build_dir.join
    // 逃出下载目录（header 派生的文件名已单独校验）。
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

/// 从 `Content-Disposition` 提取 `filename`（或 `filename*`）值：仅处理常见
/// 形式，不展开 RFC 5987 编码，复杂场景回退占位名。
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

/// worker 侧 reproduce 环境准备：从 Hub 下载 build_packages.json（签名 URL，
/// Bearer 认证）写入临时目录，`prepare_reproduce_env` 恢复包建复现快照仓，
/// 再用钩子重配 engine（复现解析域旗标 + 比对锚）。返回 `(env, engine)`：
/// env 的 guard 须持有到构建结束。
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

    // 下载 build_packages.json 到临时目录（只用本次构建）。临时文件权限
    // 豁免：进程内即读即弃（无跨身份/跨进程读者），不做 chmod/chown。
    let build_dir = PathBuf::from(&cfg.build_dir);
    let json_tmp_dir =
        crbs_core::engine::cache::spawn_blocking_tempdir_in(build_dir, "json tmp dir").await?;
    let json_path = json_tmp_dir.path().join("build_packages.json");

    let full_url = format!("{}{}", cfg.hub_url, url);
    // Err 早退不得随 `?` 在 async 线程同步 remove_dir_all（TempDir Drop 是同步
    // 删除）。下载 / 落盘 / prepare 三处 Err 臂由 TempDirGuard（crbs-core
    // engine::cache）兜底：guard Drop 清目录；成功路径 disarm 后显式 await 移交。
    let src_dir = json_tmp_dir.path().to_path_buf();
    let mut json_tmp_guard = crbs_core::engine::cache::TempDirGuard::new(json_tmp_dir);
    let body = match download_build_packages_json(cfg, &full_url, cancel_token).await {
        Ok(body) => body,
        Err(e) => return Err(e),
    };
    tokio::fs::write(&json_path, &body)
        .await
        .map_err(|e| CrbsError::from_io_context("write build_packages.json", e))?;

    // json_tmp_dir 须存活到 prepare_reproduce_env 完成（它读该 JSON），
    // 之后的释放走 drop_tempdir_off_worker。
    let env = match reproduce::prepare_reproduce_env(&src_dir, engine.config(), Some(cancel_token))
        .await
    {
        Ok(env) => env,
        Err(e) => return Err(e),
    };
    // 成功路径：disarm 取回 TempDir，显式 await 移交 drop。
    if let Some(dir) = json_tmp_guard.disarm() {
        drop_tempdir_off_worker(dir).await;
    }

    // 隔离旗标链收口在 crbs-core apply_reproduce_engine（按回放仓库模式
    // 分派）：Snapshot 下 hub 产品仓是漂移滚动源、与 local_repo 互斥（
    // mount_common_features fail-fast）必须清除，比对锚 / 复现快照仓 / 复现
    // 解析域旗标就位；BaseOnly（记录集无 sha 条目）退回正常解析域。
    let engine = reproduce::apply_reproduce_engine(engine, &env);

    Ok((env, engine))
}

/// reproduce assignment 守卫：缺 `reproduce_packages_url` 时 fail-fast
/// （ValidationFailed）。
fn require_reproduce_packages_url(task: &AssignedTask) -> crbs_core::Result<&str> {
    task.reproduce_packages_url
        .as_deref()
        .ok_or_else(|| CrbsError::ValidationFailed {
            message: "reproduce mode but no reproduce_packages_url in assignment".into(),
        })
}

/// 把 `tempfile::TempDir` 移入 `spawn_blocking` 串行 drop：Drop 是同步
/// `remove_dir_all`（可能落在 NFS 慢存储的 build_dir 上），不能在 tokio
/// worker 线程直接 Drop。JoinError 仅 warn：残留由 sweeper 的 `.tmp` 前缀兜底。
async fn drop_tempdir_off_worker(dir: tempfile::TempDir) {
    if let Err(e) = tokio::task::spawn_blocking(move || drop(dir)).await {
        warn!(
            error = %e,
            "Temp dir drop task failed; dir left for sweeper (.tmp prefix) cleanup"
        );
    }
}

/// 从 Hub 下载 build_packages.json：send / bytes 均与取消令牌竞争，整体包进
/// [`retry_with_backoff`]（JSON 小，默认 30s 超时足够），瞬时错误不判死。
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

    /// `hub_product_config` 直测——空 product_config fail-closed 拒绝（消息含
    /// product_config / product 名 / assignment_id 且明言不回退本地文件）；
    /// 非空原样借用。
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

    /// 三分映射：超时报 timeout、取消报 cancelled、其余报 failed。
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

    /// 不同 assignment、相同 filename → 各落各自子目录互不覆盖；一侧 teardown
    /// 后另一侧 SRPM 仍存在（reclaim 重派同 build_id 的两次执行同理）。
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

    /// 安全护栏：拒绝清理 build_root 本身或 build_root 之外的路径。
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

    /// 安全护栏（组件级）：词法 `starts_with` 的前缀匹配挡不住 ParentDir，
    /// `build/1001/../../victim` 这类 parent 必须拒绝清理。
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

    /// 任何可用于 `File::create` 逃出 per-build 目录的形态（分隔符、`.`、`..`、
    /// 绝对路径、NUL、空）都拒绝。
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

    /// 恶意文件名 → 拒绝下载（Err，不回退占位名不落盘）；良性无 .src.rpm
    /// 后缀 / 无头 → 占位名。
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

        // 占位名同样受单组件约束：恶意 product 不得逃出下载目录。
        assert!(resolve_download_filename(None, "../evil", 42).is_err());
        assert!(resolve_download_filename(Some("attachment"), "../evil", 42).is_err());
        assert_eq!(
            resolve_download_filename(None, "prod", 42).unwrap(),
            "prod-42.src.rpm"
        );
    }

    /// 回归：必须落确切 0660——`.mode(0o660)` 受 umask 削减（022 下实落
    /// 0640），open 后显式 set_permissions 不受 umask 影响，可断言确切 mode。
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

    /// 预植 symlink：目标内容不得被改写，链接被替换为普通文件。
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

    // ---- prepare_worker_reproduce 分支直测 ----
    // 本体需要 BuildEngine，公共组装路径经 create_backend available() 检查
    //（Linux 非 root / macOS 必失败），worker 侧无法构造——直测可抽层：URL
    // 守卫（下）、JSON 下载 retry+取消链（mock hub）；旗标链与 Err 臂清理在
    // crbs-core（apply_reproduce_engine 单测 / TempDirGuard 行为测试）。

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

    /// drop_tempdir_off_worker 实删目录（async 线程上不跑同步 remove_dir_all）。
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

    /// 缺 reproduce_packages_url → ValidationFailed fail-fast（消息点名缺口）；
    /// 带 URL 原样借用。
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

    /// mock hub：首个请求回 503（瞬时错误），第二个回 200 + body（带
    /// Connection: close，reqwest 重试新建连接）；仅接受 GET。
    async fn serve_503_then_200(listener: tokio::net::TcpListener, body: &'static str) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for i in 0..2 {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            // 读到 header 结束即可（GET 无 body）。
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

    /// 瞬时 503 后恢复 → 退避重试拿到 JSON body（瞬时错误不判死 reproduce 构建）。
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

    /// 请求在途时取消 → 立即返回 Cancelled（不等 hub 响应 / 不耗满重试）；
    /// mock hub 接受连接后持住不回应，经 oneshot 同步"已接受"再取消。
    #[tokio::test]
    async fn download_build_packages_json_cancel_returns_cancelled() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.unwrap();
            accepted_tx.send(()).unwrap();
            // 持住连接不回应，直到测试结束（任务随 runtime abort）。
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

    /// 普通子路径放行；根本身、根外、含 `..` 的逃逸形态一律拒绝（`starts_with`
    /// 前缀匹配会放行 `../`；`.` 组件被 components() 归一化，无逃逸面）。
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

// ---- 镜像播种拆引信（claim_stale_self_build_rows）----
// 场景与断言对应陈旧活跃行冲突：complete 被吞失败
// 留下的本进程活跃行（arch NULL、pid=worker 自身）封死同 identity 后续
// 构建，attach 降级后 Conflict 判败。

#[cfg(test)]
mod mirror_seed_claim_tests {
    use super::{claim_stale_self_build_rows, InFlightHubBuildGuard};

    /// 在途注册表是进程级单例：四个测试共享它，必须串行进入（否则本测试
    /// 注册的 id 恰为其他测试的陈旧行 id，认领被误排除）。
    static CLAIM_SERIALIZER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// 拆引信测试夹具：独立 StateStore + 本进程 pid。
    async fn claim_test_store() -> (tempfile::TempDir, std::sync::Arc<crbs_core::StateStore>) {
        let tmp = tempfile::tempdir().unwrap();
        let state = std::sync::Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        (tmp, state)
    }

    /// 地雷 e2e：上一轮遗留的镜像行（pid=本进程）滞留 building，同 identity
    /// 新 build（hub id 200）播种前被拆引信认领收口 failed → attach_remote
    /// 走完播种全程落自身 hub id，不再判败；认领幂等（终态守卫，二次 0 行）；
    /// 新行生命周期完整可走（终态写不撞守卫）。
    #[tokio::test]
    async fn stale_self_row_claimed_before_mirror_seed_unblocks_attach() {
        let _serial = CLAIM_SERIALIZER.lock().await;
        let (_tmp, state) = claim_test_store().await;
        let pid = std::process::id() as i64;

        // 上一轮：镜像行播种 + attach（pid=本进程），终态写"失败被吞"→ 滞留 building。
        crbs_core::engine::BuildLifecycle::attach_remote(
            state.clone(),
            100,
            "mydist",
            "hello-1.0-1",
            pid,
        )
        .await
        .unwrap();
        // attach 只播种 + 写 pid，phase 尚为 pending（start_building 才翻
        // building）；pending 同属活跃态，撞索引语义一致。
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

        // 本轮：播种无索引碰撞，新行落自身 hub id。
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

        // 认领幂等：已终态行再认领为 0 行 no-op（行保持 failed）。
        claim_stale_self_build_rows(&state, "mydist", "hello-1.0-1", 300).await;
        assert_eq!(
            state.get_build(100).await.unwrap().unwrap().phase,
            "failed",
            "re-claim must not resurrect or rewrite the terminal row"
        );
    }

    /// 播种后 attach 前崩溃的半写入残留（crbs_pid NULL）：同认领——NULL pid
    /// 不可能属在途执行（在途注册先于播种），认领不误伤。
    #[tokio::test]
    async fn null_pid_leftover_row_is_claimed() {
        let _serial = CLAIM_SERIALIZER.lock().await;
        let (_tmp, state) = claim_test_store().await;

        // 仅播种不 attach：crbs_pid NULL 的活跃行。
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

    /// 保真约束：他进程名下的活跃行不动——认领跳过、播种仍撞索引、
    /// attach_remote 维持既有失败降级路径，真实重复保护不被稀释。
    #[tokio::test]
    async fn foreign_pid_row_not_claimed_and_attach_still_fails() {
        let _serial = CLAIM_SERIALIZER.lock().await;
        let (_tmp, state) = claim_test_store().await;
        let pid = std::process::id() as i64;

        // pid=1（非本进程）的活跃行。
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

    /// 在途排除：同 identity 并发他 build 的行（已注册在途集、pid=本进程）
    /// 不认领——防误杀真并发构建（hub 允许同 NVR 异 arch 并发活跃，本地行
    /// arch 恒 NULL 归一后相撞）；行不动、attach 维持失败路径。
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
