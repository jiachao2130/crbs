// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 提交扇出守卫：任务与上传资源的回滚/去重生命周期。

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

/// Fan-out 清理守护（RAII）：`create_task` 与首个 build 建成之间出错/取消会
/// 留下"0 构建的 pending 任务"（调度与崩溃恢复均无法拾起）——armed Drop 标
/// `failed` 并清理任务目录，首个 build 建成后 `disarm`；硬崩溃由 sweep 兜底。
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

impl Drop for TaskFanOutGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        let state_store = self.state_store.clone();
        let task_id = self.task_id;
        let task_dir = self.task_dir.clone();
        // Drop 为同步上下文，DB/目录清理是异步：交由当前运行时后台执行。
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    match state_store.mark_task_failed(task_id).await {
                        // 0 行 = 任务已不在 pending（如已被并发取消）：终态保持先到者，不算错误。
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

/// multipart 上传的 `.incoming/{uuid}` 请求目录清理守护（RAII）：成功、出错或
/// 取消的 Drop 都在后台删除该目录（move 路径仅删空目录，copy 清残留）；Drop
/// 晚于 `fan_out_builds`，早于 fan_out 的 `?` 返回时删上传残件亦正确。
pub(super) struct IncomingUploadGuard {
    req_dir: Option<PathBuf>,
}

impl IncomingUploadGuard {
    pub(super) fn new(req_dir: Option<PathBuf>) -> Self {
        Self { req_dir }
    }
}

impl Drop for IncomingUploadGuard {
    fn drop(&mut self) {
        let Some(req_dir) = self.req_dir.take() else {
            return;
        };
        // Drop 为同步上下文，目录清理是异步：交由当前运行时后台执行。
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

/// 创建用户可见的 Task：写 tasks 表、建任务目录、按输入序复制全部 source SRPM；
/// `request_json`（task 级选项，arch=None）供 rebuild 重放，`guard` 由
/// `fan_out_builds` 在首个 build 建成后 disarm。
pub(super) async fn create_task(
    app: Arc<AppState>,
    args: &FanOutArgs,
    request_json: &str,
) -> Result<(i64, PathBuf, Vec<PathBuf>, TaskFanOutGuard), ApiError> {
    let first_srpm = args
        .srpm_paths
        .first()
        .ok_or_else(|| ApiError::Validation("at least one SRPM is required".into()))?;
    // source_names 兼任落盘文件名（带 .src.rpm 后缀）；显示名入库前剥后缀，
    // 对齐 fan-out 的 build_pkg_name 口径；空则退回文件名派生。
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
    // 标签与任务行同事务：避免任务已可见而无标签的半写状态。
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
        // 落盘名优先取 source_names（header N-V-R 真名）：任务显示名/结果
        // 目录/worker 下载名三处口径随之一致；multipart 路径已在 incoming
        // 域重命名，此处对 JSON/reproduce 路径生效。
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
        // 权限不变量：copy 继承源文件模式且 root 运行下属主变 root——补
        // 0660 + crbs 组，保证三身份可读写。
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
/// 选项（arch=None）；`allow_move`：上传临时文件仅单架构单包时 rename 暂存，
/// 其余 copy 保留原件。`collapse_noarch`：submit/batches 传 true，rebuild 传
/// false（忠实还原原任务架构意图）；生效还要求产品 `noarch_per_arch != true`。
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
    /// 架构是否用户显式指定：true = 显式 arch 请求（遇 spec 架构约束不兼容
    /// 默认拒绝整个提交）；false = 产品默认 fan-out / rebuild / 批次（遇不兼容
    /// 跳过该架构）。判别来源见 BuildRequest.arch_list。
    pub arch_explicit: bool,
    /// 显式请求遇不兼容时跳过而非拒绝（`--skip-unsupported-arches`）。
    pub skip_unsupported_arches: bool,
    /// 任务真名（SRPM header N-V-R，与 srpm_paths 对齐）：task source 存档与
    /// worker 下载落盘名。空 = 沿用上传文件名（multipart 已重命名的路径自洽）。
    pub source_names: Vec<String>,
    /// 任务标签（提交时声明的任务级元数据）：与任务行同事务写入；空 = 无标签。
    pub task_labels: Vec<(String, String)>,
}

/// `fan_out_builds` 的展开结果。
#[derive(Debug)]
pub(crate) struct FanOutOutcome {
    /// 新建任务 id。
    pub task_id: i64,
    /// 全部子构建 id（提交序）。
    pub build_ids: Vec<i64>,
    /// 提交期因 spec 架构约束跳过未创建的子构建（"pkg: arch (reason)"，
    /// 无跳过 = 空）。
    pub skipped_arches: Vec<String>,
}

/// 单 SRPM 的架构展开裁决（rpm 6.0.2 实测口径）。
#[derive(Debug)]
pub(super) struct SrpmArchPlan {
    /// 实际参与 fan-out 的架构（已剔除跳过项）。
    pub(super) arches: Vec<String>,
    /// 纯 noarch 收敛对该 SRPM 是否保持。ExcludeArch 非空即关闭（收敛构建可被
    /// 任意 worker 领取、宿主不可预知），退回每架构 noarch-target 子构建——
    /// 收敛是优化，遇约束让步。
    pub(super) collapse: bool,
    /// 被跳过的 (arch, 原因)（响应/告警点名用）。
    pub(super) skipped: Vec<(String, String)>,
}

/// 单 SRPM 架构展开裁决（纯函数，可单测）。`srpm_arch` 为 header ARCH
/// （空串 = 探测失败）；`constraints` 为头标签评估值（空 = 无约束/探测失败，
/// 保守放行）。拒绝返回 Err(文案)（400/exit 4 点名架构、约束来源与取值）。
pub(super) fn plan_srpm_arches(
    pkg_name: &str,
    srpm_arch: &str,
    constraints: &crbs_core::engine::depsolve::ArchConstraints,
    requested: &[String],
    collapse_global: bool,
    explicit: bool,
    skip_flag: bool,
) -> Result<SrpmArchPlan, String> {
    // 探测失败/无约束：维持现状（预检是优化不是安全裁决，rpmbuild 仍是权威）。
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
        // noarch target：ExclusiveArch 豁免（实测）；ExcludeArch 检查对象是构建
        // 宿主架构，派发架构 = worker 绑定架构为宿主代理（派发不变量）。
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
        // 指引文案由调用方按 pin 与否补齐（pin 下 "adjust --arch" 失真）。
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

    // ExcludeArch 非空即关闭收敛（宿主不可预知），与结构体文档口径一致。
    let collapse = collapse_global && srpm_arch == "noarch" && constraints.exclude.is_empty();
    Ok(SrpmArchPlan {
        arches: kept,
        collapse,
        skipped,
    })
}

/// fan-out 部分展开的补偿取消（best-effort）：对 task 下全部非终态子构建执行
/// [`cancel_distributed_build`]（终态守卫 + 同事务聚合父 task，幂等）。按 task
/// 而非调用方已收集的 ids 收口——`start_build` 可能在插行后才失败，该孤儿
/// 不在 ids 里。失败仅 warn（终态竞态 Conflict 降 debug）；task 可能以部分
/// arch 子集推进，兜底 `sweep_orphaned_tasks` / `reconcile_stale_task_phases`。
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
            // list 与 cancel 之间被 worker 转入终态：0 行 CAS Conflict，先到者
            // 生效、无需补偿——降 debug 防噪声。
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
    // 确定性 submit 侧断言：按 hub 合并生效值（产品链 + hub 全局
    // 兜底 + 请求 stage 覆盖）提交即拒；构建启动路径各自再校验，防提交后
    // 配置漂移静默失锚。
    let (deterministic, resolved_product) =
        assert_deterministic_submit_preconditions(&app, &args).await?;

    // 纯 noarch 收敛生效值：路径允许 && 产品未开 noarch_per_arch（= 恢复每架构
    // 构建并激活 cross-arch 互比）；配置读不到视为未开启；arches 空不收敛（防模零）。
    let noarch_collapse = args.collapse_noarch
        && !args.arches.is_empty()
        && match &resolved_product {
            Some(r) => r.config.noarch_per_arch != Some(true),
            None => true,
        };

    let request_json = serde_json::to_string(&args.opts)
        .map_err(|e| ApiError::log_and_internal_with_context("serialize task build options", e))?;

    // --target 显式钉单一目标架构：生效构建架构收敛为 target 字面值，fan-out/
    // 约束预检只围绕它展开。target 不在产品构建架构集合内统一 400（unconstrained
    // spec 的错标产物与 constrained spec 的 late-fail 都是这条防线消灭的对象），
    // 跨架构构建引导到 --arches。纯输入校验，先于 create_task：拒绝零副作用。
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

    // 逐 SRPM 解析 intrinsic arch + 架构约束（批量 rpm -qp 一次拿全），供
    // noarch target 注入判定与提交期架构预检。探测对象是提交输入的暂存
    // SRPM——预检拒绝必须发生在 create_task 之前（拒绝零副作用：无任务行、
    // 无结果目录、无 tombstone），任务目录副本是逐字节拷贝，裁决等价。
    // 结果与 srpm_paths 按序对齐；单项解析失败保守按"无信息"处理（不注入、
    // 不预检拦截），仅 warn——预检是优化不是安全裁决，rpmbuild 仍是权威。
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

    // 提交期架构预检（先于 create_task）：按 SRPM 头 ExclusiveArch/ExcludeArch
    // 评估值剔除不兼容架构（noarch：ExclusiveArch 豁免、ExcludeArch 查宿主代理）。
    // 拒绝在此直接 400，不产生任务行/结果目录/guard tombstone；计划与
    // srpm_paths 按序对齐，扇出循环按下标取用。
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
                // pin 下请求集收敛为 target 单值，kept-empty 即 target 撞约束；
                // "adjust --arch" 指引对 pin 失真，换专属文案。
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

    // 血缘锚：每份 source SRPM 计算一次原样字节 sha256（source/ 副本即提交
    // 字节，全部架构子构建共享；失败降级 None，由比对侧 missing_unsigned
    // 暴露）。所有新构建都落锚：内容哈希是 `?srpm_sha256=` 反查与复现比对的
    // 共用索引，不再只限 deterministic / repro-from-srpm。
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

    // 多架构/多包时保留原始 SRPM（用 copy 而非 move）。
    let move_source = args.allow_move && fanout_arches.len() == 1 && args.srpm_paths.len() == 1;

    let mut ids = Vec::with_capacity(fanout_arches.len() * args.srpm_paths.len());

    // repro-from-srpm：逐源 SRPM 探测头参数，值只进 build 级 options（task 级
    // request_json 只携带旗标——rebuild 复用旗标重新探测，值幂等）。探测失败 =
    // 硬失败 400（首个子构建未建成，guard 仍 armed，Drop 收口 task，无需补偿）。
    // 信封只点名文件名不含路径（服务端路径不进信封；全路径在 warn 留痕）。
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

    // 产品 crbs 自产 `_buildhost`（mode note 判断 SRPM 头是否出自 crbs 产品
    // 构建）：生效值与引擎合并口径一致（空串归一缺省 "crbs"）；解析失败跳过比对。
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
            // 提交期架构预检的剔除在该 SRPM 的计划内生效：不兼容架构不创建子构建。
            let arch_plan = &arch_plans[src_idx];
            if !arch_plan.arches.iter().any(|a| a == arch) {
                continue;
            }
            // 纯 noarch SRPM 收敛为单构建：builds.arch 记语义值 "noarch"，领取
            // 谓词 `arch = $1 OR arch = 'noarch'` 放行任意 worker（先到先得）；
            // 混合包与解析失败源不受影响（每架构各建）；发布侧 noarch 硬链天然
            // 支持单架构产出铺满各架构 repo。收敛仅在该 SRPM 无架构约束跳过
            // 时保持（预检关闭它 = 退回每架构 noarch-target 子构建）。
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
            // repro-from-srpm 回放值（同源 SRPM 的全部架构子构建共享同值）。
            if let Some((host, time)) = replay_params_by_source.get(source_srpm) {
                arch_opts.replay_build_host = host.clone();
                arch_opts.replay_build_time = *time;
            }

            // NEVR 真名覆盖：pkg_name 用 header 解析值而非上传文件名派生
            let build_pkg_name = args
                .source_names
                .get(src_idx)
                .map(|n| n.strip_suffix(".src.rpm").unwrap_or(n).to_string());
            // noarch 行且架构为用户显式点名：点名集即宿主约束（用户意图覆盖
            // 产品偏好；arch_list 即将清空，覆盖须在此传入）。
            let noarch_host_override = if arch_opts.arch.as_deref() == Some("noarch") {
                if args.arch_explicit {
                    // 'noarch' 是内容语义 token 不是 worker 架构——物化进宿主集
                    // 会造出永无 worker 匹配的死行（显式 --arches noarch 的边角）；
                    // 过滤后为空则回退产品偏好。
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
                    // --target 也是用户的显式宿主意图（纯 noarch 收敛后 arch
                    // 字段是 noarch，不能只看 arch_explicit）。
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
                // 部分展开：补偿取消已建子构建后返回原始错误（不被补偿噪声掩盖）。
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
            // deterministic 产品插入默认行（deterministic=0）后翻标记
            //（插入后置标记）；失败仅 warn 留痕。
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
            // repro-from-srpm 模式 note（激活必注）：文案见下方纯函数；失败仅 warn。
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
