// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 提交扇出检查：任务与上传资源的回滚/去重生命周期。

use std::path::PathBuf;
use std::sync::Arc;

use axum::Json;
use crbs_core::types::PRIORITY_DEFAULT;

use crate::server::error::ApiError;
use crate::server::routes::builds::service::cancel_distributed_build;
use crate::server::routes::builds::BuildOptions;
use crate::server::state::AppState;

use super::reproduce::{assert_deterministic_submit_preconditions, repro_mode_note_text};
use super::start::{inject_noarch_target, start_build, StartBuildArgs};

/// fan-out 清理守护（RAII）：`create_task` 完成与首个 build 建成之间出错
/// 或取消，会留下"零构建的 pending 任务"，调度与崩溃恢复都无法拾起——
/// armed 状态的 Drop 将任务标为 failed 并清理任务目录；首个 build 建成后
/// 调用 `disarm` 解除；进程硬崩溃的残留由 sweep 兜底回收。
pub(super) struct TaskFanOutGuard {
    state_store: Arc<crbs_core::StateStore>,
    task_id: i64,
    task_dir: PathBuf,
    disarmed: bool,
}

impl TaskFanOutGuard {
    pub(super) fn new(
        state_store: Arc<crbs_core::StateStore>,
        task_id: i64,
        task_dir: PathBuf,
    ) -> Self {
        Self {
            state_store,
            task_id,
            task_dir,
            disarmed: false,
        }
    }

    pub(super) fn disarm(&mut self) {
        self.disarmed = true;
    }
}

// Drop 为同步上下文，DB/目录清理是异步：交由当前运行时后台执行。
impl Drop for TaskFanOutGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        let state_store = self.state_store.clone();
        let task_id = self.task_id;
        let task_dir = self.task_dir.clone();

        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    match state_store.mark_task_failed(task_id).await {

                        Ok(_) => tracing::warn!(
                            task_id,
                            "build fan-out incomplete (submission failed or cancelled); marked task failed"
                        ),
                        Err(e) => tracing::warn!(
                            task_id,
                            error = %e,
                            "fan-out guard: failed to mark task failed"
                        ),
                    }
                    if let Err(e) = tokio::fs::remove_dir_all(&task_dir).await {
                        tracing::debug!(
                            task_id,
                            error = %e,
                            path = %task_dir.display(),
                            "fan-out guard: task dir cleanup failed"
                        );
                    }
                });
            }
            Err(_) => {
                tracing::warn!(
                    task_id,
                    "fan-out guard dropped outside a tokio runtime; task may stay pending with no builds"
                );
            }
        }
    }
}

/// multipart 上传的 `.incoming/{uuid}` 请求目录清理守护（RAII）：成功、出
/// 错或取消路径的 Drop 都在后台删除该目录（move 路径仅删空目录，copy 路径
/// 清理残留文件）；Drop 时点晚于 `fan_out_builds`、早于其 `?` 返回，此时删
/// 除上传残件仍正确。
pub(super) struct IncomingUploadGuard {
    req_dir: Option<PathBuf>,
}

impl IncomingUploadGuard {
    pub(super) fn new(req_dir: Option<PathBuf>) -> Self {
        Self { req_dir }
    }
}

// Drop 为同步上下文，目录清理是异步：交由当前运行时后台执行。
impl Drop for IncomingUploadGuard {
    fn drop(&mut self) {
        let Some(req_dir) = self.req_dir.take() else {
            return;
        };

        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    if let Err(e) = tokio::fs::remove_dir_all(&req_dir).await {
                        if e.kind() != std::io::ErrorKind::NotFound {
                            tracing::debug!(
                                path = %req_dir.display(),
                                error = %e,
                                "incoming upload guard: cleanup failed"
                            );
                        }
                    }
                });
            }
            Err(_) => {
                tracing::warn!(
                    path = %req_dir.display(),
                    "incoming upload guard dropped outside a tokio runtime; .incoming subdir may leak"
                );
            }
        }
    }
}

/// 创建用户可见的 Task：写 tasks 表、创建任务目录、按输入顺序复制全部
/// source SRPM。`request_json` 为 task 级选项（arch 为 None），供 rebuild
/// 复现原提交；返回的 guard 由调用方在首个 build 建成后 disarm。
pub(super) async fn create_task(
    app: Arc<AppState>,
    args: &FanOutArgs,
    request_json: &str,
) -> Result<(i64, PathBuf, Vec<PathBuf>, TaskFanOutGuard), ApiError> {
    let first_srpm = args
        .srpm_paths
        .first()
        .ok_or_else(|| ApiError::Validation("at least one SRPM is required".into()))?;

    let pkg_names: Vec<String> = if args.source_names.is_empty() {
        args.srpm_paths
            .iter()
            .map(|p| crbs_core::util::srpm_display_name(p).to_string())
            .collect()
    } else {
        args.source_names
            .iter()
            .map(|n| n.strip_suffix(".src.rpm").unwrap_or(n).to_string())
            .collect()
    };
    let pkg_name = pkg_names
        .first()
        .cloned()
        .unwrap_or_else(|| crbs_core::util::srpm_display_name(first_srpm).to_string());
    let pkg_names_json = serde_json::to_string(&pkg_names)
        .map_err(|e| ApiError::log_and_internal_with_context("serialize pkg_names", e))?;

    let task = crbs_core::TaskInsert {
        product: &args.product,
        pkg_name: &pkg_name,
        user: &args.submit_user,
        user_id: args.submit_user_id,
        phase: "pending",
        priority: args.opts.priority.unwrap_or(PRIORITY_DEFAULT),
        srpm_path: None,
        result_dir: None,
        request_json: Some(request_json),
        pkg_names: Some(&pkg_names_json),
    };

    let task_id = if args.task_labels.is_empty() {
        app.state_store.insert_task(task).await
    } else {
        app.state_store
            .create_task_with_labels(task, &args.task_labels)
            .await
    }
    .map_err(|e| ApiError::log_and_internal_with_context("insert task", e))?;

    let task_dir = args.result_dir.join(task_id.to_string());
    let guard = TaskFanOutGuard::new(app.state_store.clone(), task_id, task_dir.clone());
    let source_dir = task_dir.join("source");
    tokio::fs::create_dir_all(&source_dir)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("create task source dir", e))?;

    let mut source_srpms = Vec::with_capacity(args.srpm_paths.len());
    for (idx, srpm_path) in args.srpm_paths.iter().enumerate() {
        let file_name = args
            .source_names
            .get(idx)
            .filter(|n| !n.is_empty())
            .cloned()
            .unwrap_or_else(|| {
                srpm_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown.src.rpm")
                    .to_string()
            });
        let source_srpm = source_dir.join(&file_name);
        if tokio::fs::try_exists(&source_srpm).await.unwrap_or(false) {
            return Err(ApiError::Validation(format!(
                "duplicate srpm filename in task: {}",
                file_name
            )));
        }
        tokio::fs::copy(srpm_path, &source_srpm)
            .await
            .map_err(|e| {
                ApiError::log_and_internal_with_context("copy srpm to task source dir", e)
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                tokio::fs::set_permissions(&source_srpm, std::fs::Permissions::from_mode(0o660))
                    .await
            {
                tracing::warn!(
                    path = %source_srpm.display(),
                    error = %e,
                    "Failed to chmod task source srpm to 0660"
                );
            }
            crbs_core::privilege::chown_to_crbs_group_async(
                &source_srpm,
                false,
                "task source srpm",
            )
            .await;
        }
        source_srpms.push(source_srpm);
    }

    app.state_store
        .update_task_srpm_path(task_id, source_srpms[0].to_str().unwrap_or(""))
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("update task srpm_path", e))?;

    app.state_store
        .update_task_result_dir(task_id, Some(task_dir.to_str().unwrap_or("")))
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("update task result_dir", e))?;

    Ok((task_id, task_dir, source_srpms, guard))
}

/// `fan_out_builds` 的参数集合（submit 与 rebuild 共用）。`opts` 为 task 级
/// 选项（arch 为 None）；`allow_move` 表示上传临时文件在单架构单包时以
/// rename 进入暂存，其余场景 copy 并保留原件；`collapse_noarch` 由 submit
/// 与 batches 传 true、rebuild 传 false（忠实还原原任务的架构意图），实际
/// 生效还要求产品未开启 `noarch_per_arch`。
pub(crate) struct FanOutArgs {
    pub product: String,
    pub result_dir: PathBuf,
    pub srpm_paths: Vec<PathBuf>,
    pub opts: BuildOptions,
    pub arches: Vec<String>,
    pub submit_user: String,
    pub submit_user_id: Option<i64>,
    pub allow_move: bool,
    pub collapse_noarch: bool,

    /// 架构是否由用户显式指定：true 为显式 arch 请求，遇 spec 架构约束不兼
    /// 容时默认拒绝整个提交；false 为产品默认扇出、rebuild 或批次路径，遇
    /// 不兼容跳过该架构。判别来源见 `BuildRequest::arch_list`。
    pub arch_explicit: bool,

    /// 显式请求遇不兼容架构时跳过而非拒绝（`--skip-unsupported-arches`）。
    pub skip_unsupported_arches: bool,

    /// 任务真名（SRPM header N-V-R，与 `srpm_paths` 一一对应）：task source
    /// 存档与 worker 下载落盘均使用该名；为空表示沿用上传文件名（multipart
    /// 已重命名的路径自洽）。
    pub source_names: Vec<String>,

    /// 任务标签（提交时声明的任务级元数据）：与任务行同事务写入；空表示无
    /// 标签。
    pub task_labels: Vec<(String, String)>,
}

/// `fan_out_builds` 的展开结果。
#[derive(Debug)]
pub(crate) struct FanOutOutcome {
    /// 新建任务 id。
    pub task_id: i64,

    /// 全部子构建 id（提交顺序）。
    pub build_ids: Vec<i64>,

    /// 提交期因 spec 架构约束跳过、未创建的子构建，格式为
    /// `"pkg: arch (reason)"`；无跳过时为空。
    pub skipped_arches: Vec<String>,
}

/// 单个 SRPM 的架构展开裁决（与 rpm 6.0.2 实测口径一致）。
#[derive(Debug)]
pub(super) struct SrpmArchPlan {
    /// 实际参与扇出的架构（已剔除跳过项）。
    pub(super) arches: Vec<String>,

    /// 纯 noarch 收敛对该 SRPM 是否保持：ExcludeArch 非空即关闭——收敛构建
    /// 可被任意 worker 领取、宿主不可预知，此时退回每架构 noarch-target 子
    /// 构建；收敛是优化，遇约束让步。
    pub(super) collapse: bool,

    /// 被跳过的 (arch, 原因)，供响应与告警点名。
    pub(super) skipped: Vec<(String, String)>,
}

/// 单 SRPM 架构展开裁决（纯函数，可单测）。`srpm_arch` 为 header ARCH（空
/// 串表示探测失败）；`constraints` 为头标签评估值（空表示无约束或探测失
/// 败，保守放行）。拒绝时返回 Err 文案，供 400 响应或退出码 4 点名架构、
/// 约束来源与取值。
pub(super) fn plan_srpm_arches(
    pkg_name: &str,
    srpm_arch: &str,
    constraints: &crbs_core::engine::depsolve::ArchConstraints,
    requested: &[String],
    collapse_global: bool,
    explicit: bool,
    skip_flag: bool,
) -> Result<SrpmArchPlan, String> {
    if srpm_arch.is_empty() || (constraints.exclusive.is_empty() && constraints.exclude.is_empty())
    {
        return Ok(SrpmArchPlan {
            arches: requested.to_vec(),
            collapse: collapse_global && srpm_arch == "noarch",
            skipped: Vec::new(),
        });
    }

    let mut kept = Vec::with_capacity(requested.len());
    let mut skipped = Vec::new();
    for arch in requested {
        match constraints.incompatible_for(srpm_arch, arch) {
            Some(reason) => skipped.push((arch.clone(), reason)),
            None => kept.push(arch.clone()),
        }
    }

    if kept.is_empty() {
        let detail = skipped
            .iter()
            .map(|(a, r)| format!("{a}: {r}"))
            .collect::<Vec<_>>()
            .join(", ");

        return Err(format!(
            "{pkg_name}: no requested architecture is buildable ({detail})"
        ));
    }

    if !skipped.is_empty() && explicit && !skip_flag {
        let detail = skipped
            .iter()
            .map(|(a, r)| format!("{a}: {r}"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "{pkg_name}: requested architecture not supported by spec ({detail}); \
             drop the arch, fix the spec, or pass --skip-unsupported-arches"
        ));
    }

    let collapse = collapse_global && srpm_arch == "noarch" && constraints.exclude.is_empty();
    Ok(SrpmArchPlan {
        arches: kept,
        collapse,
        skipped,
    })
}

/// fan-out 部分展开的补偿取消（best-effort）：对 task 下全部非终态子构建
/// 执行 [`cancel_distributed_build`]（终态守卫加同事务聚合父 task，幂
/// 等）。按 task 维度查询而非依赖调用方已收集的 ids 收口——`start_build`
/// 可能在插行之后才失败，该行不在 ids 内。失败仅 warn（终态竞态 Conflict
/// 降为 debug）；task 可能以部分架构子集推进，由 `sweep_orphaned_tasks` 与
/// `reconcile_stale_task_phases` 兜底。
pub(super) async fn compensate_partial_fan_out(app: &Arc<AppState>, task_id: i64) {
    let children = match app.state_store.get_builds_by_task_id(task_id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                task_id,
                error = %e,
                "fan-out compensation: failed to list child builds; task may advance with partial arches"
            );
            return;
        }
    };
    for build in children {
        if crbs_core::types::build_phase_is_terminal(&build.phase) {
            continue;
        }
        if let Err(e) = cancel_distributed_build(app, build.id).await {
            if matches!(e, ApiError::Conflict(_)) {
                tracing::debug!(
                    task_id,
                    build_id = build.id,
                    "fan-out compensation: child already terminal between list and cancel"
                );
            } else {
                tracing::warn!(
                    task_id,
                    build_id = build.id,
                    error = ?e,
                    "fan-out compensation: failed to cancel child build"
                );
            }
        }
    }
}

/// 创建 Task 并按 arch × srpm 展开子构建（submit 与 rebuild 共用），返回
/// [`FanOutOutcome`]。校验类拒绝（--target 门、架构预检）先于 `create_task`
/// 对暂存 SRPM 裁决，400 零副作用（无任务行、无结果目录、无 tombstone）。
/// 展开非原子：任一子构建失败即整体 Err + 对全部已建子构建补偿取消
/// （best-effort；兜底 `sweep_orphaned_tasks` / `reconcile_stale_task_phases`）；
/// [`TaskFanOutGuard`] 仅覆盖 task 创建后"0 个 build 建成"窗口。
pub(crate) async fn fan_out_builds(
    app: Arc<AppState>,
    args: FanOutArgs,
) -> Result<FanOutOutcome, ApiError> {
    let (deterministic, resolved_product) =
        assert_deterministic_submit_preconditions(&app, &args).await?;

    let noarch_collapse = args.collapse_noarch
        && !args.arches.is_empty()
        && match &resolved_product {
            Some(r) => r.config.noarch_per_arch != Some(true),
            None => true,
        };

    let request_json = serde_json::to_string(&args.opts)
        .map_err(|e| ApiError::log_and_internal_with_context("serialize task build options", e))?;

    let pinned_target: Option<&str> = args.opts.target.as_deref();
    if let Some(t) = pinned_target {
        if !args.arches.iter().any(|a| a == t) {
            return Err(ApiError::Validation(format!(
                "--target {t} is outside this product's build arches [{}]; \
                 --target pins the build to a single arch — cross-arch builds use --arches",
                args.arches.join(" ")
            )));
        }
    }
    let fanout_arches: Vec<String> = match pinned_target {
        Some(t) => vec![t.to_string()],
        None => args.arches.clone(),
    };

    let probed: Vec<Option<(String, crbs_core::engine::depsolve::ArchConstraints)>> =
        crbs_core::engine::depsolve::parse_arch_and_constraints_from_srpms(&args.srpm_paths, None)
            .await
            .into_iter()
            .zip(args.srpm_paths.iter())
            .map(|(res, path)| match res {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = ?e,
                        "SRPM arch/constraints parse failed; skipping noarch target injection and arch precheck for it"
                    );
                    None
                }
            })
            .collect();

    let mut skipped_arches: Vec<String> = Vec::new();
    let mut arch_plans: Vec<SrpmArchPlan> = Vec::with_capacity(args.srpm_paths.len());
    for (src_idx, srpm_path) in args.srpm_paths.iter().enumerate() {
        let (srpm_arch, constraints) = probed[src_idx].clone().unwrap_or_default();
        let pkg_name = args
            .source_names
            .get(src_idx)
            .map(|n| n.strip_suffix(".src.rpm").unwrap_or(n))
            .unwrap_or_else(|| crbs_core::util::srpm_display_name(srpm_path));
        let plan = plan_srpm_arches(
            pkg_name,
            &srpm_arch,
            &constraints,
            &fanout_arches,
            noarch_collapse,
            args.arch_explicit,
            args.skip_unsupported_arches,
        )
        .map_err(|e| {
            ApiError::Validation(match pinned_target {
                Some(t) => format!(
                    "{e}; --target {t} conflicts with the spec arch constraints — \
                     choose another --target or use --arches"
                ),
                None => format!("{e}; fix the spec or adjust --arch"),
            })
        })?;
        for (arch, reason) in &plan.skipped {
            tracing::warn!(
                pkg = %pkg_name,
                arch = %arch,
                reason = %reason,
                "skipping unsupported arch per SRPM header"
            );
            skipped_arches.push(format!("{pkg_name}: {arch} ({reason})"));
        }
        arch_plans.push(plan);
    }

    let (task_id, task_dir, source_srpms, mut guard) =
        create_task(app.clone(), &args, &request_json).await?;

    let mut canonical_sha_by_source: std::collections::HashMap<PathBuf, String> =
        std::collections::HashMap::new();
    for source in &source_srpms {
        match crbs_core::engine::artifact_harvest::sha256_file(source).await {
            Ok(sha) => {
                canonical_sha_by_source.insert(source.clone(), sha);
            }
            Err(e) => {
                tracing::warn!(
                    path = %source.display(),
                    error = %e,
                    "Failed to hash source SRPM for canonical anchor; leaving NULL"
                );
            }
        }
    }

    let move_source = args.allow_move && fanout_arches.len() == 1 && args.srpm_paths.len() == 1;

    let mut ids = Vec::with_capacity(fanout_arches.len() * args.srpm_paths.len());

    let replay_params_by_source: std::collections::HashMap<PathBuf, (Option<String>, Option<i64>)> =
        if args.opts.repro_from_srpm {
            let mut map = std::collections::HashMap::new();
            for source in &source_srpms {
                match crbs_core::engine::depsolve::probe_srpm_replay_params(source, None).await {
                    Ok(params) => {
                        map.insert(source.clone(), params);
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %source.display(),
                            error = ?e,
                            "repro-from-srpm probe failed; refusing submission"
                        );
                        return Err(ApiError::Validation(format!(
                            "repro-from-srpm probe failed for {}: refusing submission \
                         (corrupt SRPM?)",
                            source
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("srpm")
                        )));
                    }
                }
            }
            map
        } else {
            std::collections::HashMap::new()
        };

    let product_buildhost: Option<String> = if args.opts.repro_from_srpm {
        app.state_store
            .resolve_any_product_by_name(&args.product)
            .await
            .ok()
            .map(|r| {
                r.config
                    ._buildhost
                    .clone()
                    .filter(|h| !h.is_empty())
                    .unwrap_or_else(|| "crbs".to_string())
            })
    } else {
        None
    };

    for arch in &fanout_arches {
        for (src_idx, (srpm_path, source_srpm)) in
            args.srpm_paths.iter().zip(source_srpms.iter()).enumerate()
        {
            let arch_plan = &arch_plans[src_idx];
            if !arch_plan.arches.iter().any(|a| a == arch) {
                continue;
            }

            let collapsed_noarch = arch_plan.collapse;
            if collapsed_noarch
                && arch_plan.arches.first().or_else(|| fanout_arches.first()) != Some(arch)
            {
                continue;
            }
            let mut arch_opts = args.opts.clone();
            arch_opts.arch = Some(if collapsed_noarch {
                "noarch".to_string()
            } else {
                arch.clone()
            });
            arch_opts.arch_list.clear();
            if let Some((srpm_arch, _)) = &probed[src_idx] {
                if let Some(t) = inject_noarch_target(srpm_arch, arch_opts.target.as_deref()) {
                    arch_opts.target = Some(t);
                }
            }

            if let Some((host, time)) = replay_params_by_source.get(source_srpm) {
                arch_opts.replay_build_host = host.clone();
                arch_opts.replay_build_time = *time;
            }

            let build_pkg_name = args
                .source_names
                .get(src_idx)
                .map(|n| n.strip_suffix(".src.rpm").unwrap_or(n).to_string());

            let noarch_host_override = if arch_opts.arch.as_deref() == Some("noarch") {
                if args.arch_explicit {
                    {
                        let kept: Vec<&str> = arch_plan
                            .arches
                            .iter()
                            .map(String::as_str)
                            .filter(|a| *a != "noarch")
                            .collect();
                        (!kept.is_empty()).then(|| kept.join(","))
                    }
                } else {
                    pinned_target.filter(|a| *a != "noarch").map(str::to_string)
                }
            } else {
                None
            };
            let (_, Json(resp)) = match start_build(
                app.clone(),
                StartBuildArgs {
                    task_id,
                    task_dir: task_dir.clone(),
                    source_srpm: source_srpm.clone(),
                    pkg_name: build_pkg_name,
                    product: args.product.clone(),
                    srpm_path: srpm_path.clone(),
                    opts: arch_opts,
                    uploaded: move_source,
                    submit_user: args.submit_user.clone(),
                    submit_user_id: args.submit_user_id,
                    canonical_srpm_sha256: canonical_sha_by_source.get(source_srpm).cloned(),
                    host_arches: noarch_host_override,
                },
            )
            .await
            {
                Ok(ok) => ok,

                Err(e) => {
                    tracing::warn!(
                        task_id,
                        error = ?e,
                        "fan-out incomplete; cancelling already-created child builds"
                    );
                    compensate_partial_fan_out(&app, task_id).await;
                    return Err(e);
                }
            };

            if deterministic {
                for id in &resp.ids {
                    if let Err(e) = app.state_store.set_build_deterministic(*id, true).await {
                        tracing::warn!(
                            task_id,
                            build_id = id,
                            error = %e,
                            "Failed to set builds.deterministic flag at submit"
                        );
                    }
                }
            }

            if args.opts.repro_from_srpm {
                let (host, time) = replay_params_by_source
                    .get(source_srpm)
                    .cloned()
                    .unwrap_or((None, None));
                let note =
                    repro_mode_note_text(host.as_deref(), time, product_buildhost.as_deref());
                for id in &resp.ids {
                    if let Err(e) = app.state_store.append_build_note(*id, &note).await {
                        tracing::warn!(
                            task_id,
                            build_id = id,
                            error = %e,
                            "Failed to append repro-from-srpm mode note"
                        );
                    }
                }
            }
            ids.extend(resp.ids);
            guard.disarm();
        }
    }

    Ok(FanOutOutcome {
        task_id,
        build_ids: ids,
        skipped_arches,
    })
}
