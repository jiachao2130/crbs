// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 任务重建/复现路由：源任务解析、子构建重建与幂等。

use super::*;

/// 重建指定 Task：用留存源码与记录选项重新入队，返回新 Task。
pub(crate) async fn rebuild_task(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<
    (
        StatusCode,
        Json<crate::server::routes::builds::BuildResponse>,
    ),
    ApiError,
> {
    let outcome = rebuild_task_for_user(&app, id, auth.as_ref().map(|ext| &ext.0)).await?;
    Ok((StatusCode::ACCEPTED, Json(outcome)))
}

/// 复现指定 Task：在锁定的依赖快照（build_packages.json）下重建各 arch 子构建，返回新 Task。
pub(crate) async fn reproduce_task(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<
    (
        StatusCode,
        Json<crate::server::routes::builds::BuildResponse>,
    ),
    ApiError,
> {
    let outcome = reproduce_task_for_user(&app, id, auth.as_ref().map(|ext| &ext.0)).await?;
    Ok((StatusCode::ACCEPTED, Json(outcome)))
}

/// 重建 Task 的核心逻辑：权限与 cancel 对齐（原提交者或 operator/admin）。
/// 源码读自 `{result_dir}/{task_id}/source/`（result_dir 缺失按产品配置回退），
/// 选项取 task 级 request_json 剥离 arch，架构列表取子构建去重值缺失时按产品配置重解析。
pub(crate) async fn rebuild_task_for_user(
    app: &Arc<AppState>,
    task_id: i64,
    auth: Option<&AuthContext>,
) -> Result<crate::server::routes::builds::BuildResponse, ApiError> {
    use crate::server::routes::builds::{fan_out_builds, resolve_arches, FanOutOutcome};

    let ctx = auth.ok_or(ApiError::Unauthorized(
        "authentication required to rebuild".into(),
    ))?;
    let task = app
        .state_store
        .get_task(task_id)
        .await?
        .ok_or_else(|| ApiError::not_found("task", task_id))?;

    if !ctx.can_cancel(&task.user) {
        return Err(ApiError::PermissionDenied(
            "you do not have permission to rebuild this task".into(),
        ));
    }

    let info = app
        .state_store
        .get_task_rebuild_info(task_id)
        .await?
        .ok_or_else(|| ApiError::not_found("task rebuild info", task_id))?;

    // 借用而非移出 result_dir：后续 parse_replay_opts / finish_replay_outcome
    // 按整结构借用/移动 info。
    let task_dir = match &info.result_dir {
        Some(d) => std::path::PathBuf::from(d),
        None => app
            .result_dir_for(&info.product)
            .await
            .map_err(|e| ApiError::log_and_internal_with_context("resolve result_dir", e))?
            .join(task_id.to_string()),
    };
    let source_dir = task_dir.join("source");

    let mut srpms = Vec::new();
    // 仅 NotFound（源码随结果 GC 与 task 目录对账清扫共存亡）折叠为 GC 语义 409，
    // 其余 read_dir 错误走 500，不误报"已被 GC"。
    let mut entries = match tokio::fs::read_dir(&source_dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ApiError::Conflict(
                "source srpms no longer available (results may have been GC'd); cannot rebuild"
                    .into(),
            ));
        }
        Err(e) => {
            return Err(ApiError::log_and_internal_with_context(
                "read task source dir",
                e,
            ))
        }
    };
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("read task source dir", e))?
    {
        if entry.file_name().to_string_lossy().ends_with(".src.rpm") {
            srpms.push(entry.path());
        }
    }
    srpms.sort();
    if srpms.is_empty() {
        return Err(ApiError::Conflict(
            "source srpms no longer available (results may have been GC'd); cannot rebuild".into(),
        ));
    }

    // 多包任务按记录的提交序（pkg_names）重排 SRPM；单包任务保持文件名序。
    if task.pkg_names.len() > 1 {
        let mut ordered = Vec::with_capacity(srpms.len());
        for name in &task.pkg_names {
            if let Some(pos) = srpms
                .iter()
                .position(|p| crbs_core::util::srpm_display_name(p) == name)
            {
                ordered.push(srpms.remove(pos));
            }
        }
        ordered.extend(srpms);
        srpms = ordered;
    }

    let opts = parse_replay_opts(&info, ctx, "rebuild")?;
    let req_min =
        crbs_core::build_options::ReqMinKb::from_options(&opts).map_err(ApiError::from)?;

    crate::server::routes::builds::check_build_chain_visibility(app, &info.product, Some(ctx))
        .await?;

    let mut arches = app.state_store.get_task_arches(task_id).await?;
    if arches.is_empty() {
        arches = resolve_arches(app, &info.product, None, Some(ctx)).await?;
    }

    let result_dir = prepare_replay_result_dir(app, &info.product, "rebuild").await?;

    crate::server::routes::builds::validate_replay_caps(&srpms, &arches)?;

    // 提交去重短路（与 submit 同口径）：重放 pkg 已有活跃构建即 409；置于全部
    // 输入校验之后、任何 insert 之前——400/403 先于 409 回报。
    {
        let pkg_names: Vec<String> = srpms
            .iter()
            .map(|p| crbs_core::util::srpm_display_name(p).to_string())
            .collect();
        crate::server::routes::builds::ensure_no_active_duplicate(app, &info.product, &pkg_names)
            .await?;
    }

    let FanOutOutcome {
        task_id: new_task_id,
        build_ids: ids,
        skipped_arches,
    } = fan_out_builds(
        app.clone(),
        crate::server::routes::builds::FanOutArgs {
            product: info.product.clone(),
            result_dir,
            srpm_paths: srpms,
            opts,
            source_names: Vec::new(),
            arches,
            submit_user: ctx.user.clone(),
            submit_user_id: ctx.user_id,
            allow_move: false,
            // 忠实还原原任务架构意图：不收敛 noarch、不受 noarch_per_arch 开关影响。
            collapse_noarch: false,
            task_labels: Vec::new(),
            // rebuild 非用户显式 arch 请求：预检按跳过语义（不拒绝），忠实还原
            // 原任务可构建子集。
            arch_explicit: false,
            skip_unsupported_arches: true,
        },
    )
    .await?;

    Ok(finish_replay_outcome(ReplayOutcomeArgs {
        app,
        ctx,
        task_id,
        new_task_id,
        ids,
        skipped_arches,
        info,
        req_min,
        op: "rebuild",
        verb: "rebuilt",
    })
    .await)
}

/// 复现 Task 的核心逻辑：与 rebuild 的区别是按锁定的依赖快照（非当前仓库）重建，
/// 各 arch 子构建携带来源 build ID（`reproduce_from_build_id`），执行端读来源
/// build 的 build_packages.json 恢复环境（cache-first + url 回退）；权限同 rebuild。
pub(crate) async fn reproduce_task_for_user(
    app: &Arc<AppState>,
    task_id: i64,
    auth: Option<&AuthContext>,
) -> Result<crate::server::routes::builds::BuildResponse, ApiError> {
    use crate::server::routes::builds::{reproduce_fan_out, ReproduceFanOutArgs};

    let ctx = auth.ok_or(ApiError::Unauthorized(
        "authentication required to reproduce".into(),
    ))?;
    let task = app
        .state_store
        .get_task(task_id)
        .await?
        .ok_or_else(|| ApiError::not_found("task", task_id))?;

    if !ctx.can_cancel(&task.user) {
        return Err(ApiError::PermissionDenied(
            "you do not have permission to reproduce this task".into(),
        ));
    }

    // 整链可见性检查（与 rebuild 同口径）：产品转私有/链上出现不可见祖先后，
    // 原 submitter 不得经 reproduce 再 fan-out。
    crate::server::routes::builds::check_build_chain_visibility(app, &task.product, Some(ctx))
        .await?;

    let info = app
        .state_store
        .get_task_rebuild_info(task_id)
        .await?
        .ok_or_else(|| ApiError::not_found("task rebuild info", task_id))?;

    let opts = parse_replay_opts(&info, ctx, "reproduce")?;
    let req_min =
        crbs_core::build_options::ReqMinKb::from_options(&opts).map_err(ApiError::from)?;

    let children = app.state_store.get_builds_by_task_id(task_id).await?;

    // 进行中判定含 pending/assigned：否则落入下方过滤分支误报
    // "only succeeded builds can be reproduced"（尚未开跑 ≠ 不可复现）。
    if children.is_empty() {
        return Err(ApiError::Conflict(format!(
            "task {} has no child builds; cannot reproduce",
            task_id
        )));
    }
    for child in &children {
        if matches!(child.phase.as_str(), "pending" | "assigned" | "building") {
            return Err(ApiError::Conflict(format!(
                "task {} is still in progress (child build {})",
                task_id, child.id
            )));
        }
    }

    // 回放对象 = 任务的 succeeded 子构建集合：混合成败任务按 succeeded
    // 子集扇出（失败子构建自然缺席重放任务），全部失败才 409。
    // 409 文案取"首个非 succeeded 子构建状态"（UI flash 按其逐字映射）。
    let succeeded: Vec<crbs_core::BuildRecord> = children
        .iter()
        .filter(|c| c.phase == "succeeded")
        .cloned()
        .collect();
    if succeeded.is_empty() {
        return Err(match children.iter().find(|c| c.phase != "succeeded") {
            Some(child) => ApiError::Conflict(format!(
                "task {} child build {} has status '{}' (only succeeded builds can be reproduced)",
                task_id, child.id, child.phase
            )),
            // 不可达兜底：children 非空、无进行中、无 succeeded ⇒ 必有终态失败子构建。
            None => ApiError::Conflict(format!(
                "task {} has no succeeded child builds; cannot reproduce",
                task_id
            )),
        });
    }

    let entries = collect_reproduce_entries(app, task_id, &info, succeeded).await?;

    if entries.is_empty() {
        return Err(ApiError::Conflict(
            "no reproducible child builds (none recorded build_packages.json); \
             enable reproduce_enabled and rebuild first"
                .into(),
        ));
    }

    // 去重豁免：程序化 reproduce_from_build_id（HTTP 提交入口强制清零，用户无法
    // 伪造）属验证性重放，不走 ensure_no_active_duplicate；并发后盾是 insert_build
    // 事务内活跃去重（插入点 409，先到者生效）。规模上限：SRPM 取条目数，arch 取去重集合。
    let mut entry_arches: Vec<String> = entries.iter().map(|e| e.arch.clone()).collect();
    entry_arches.sort();
    entry_arches.dedup();
    crate::server::routes::builds::validate_replay_caps_by_len(entries.len(), &entry_arches)?;

    let result_dir = prepare_replay_result_dir(app, &info.product, "reproduce").await?;

    let (new_task_id, ids) = reproduce_fan_out(
        app.clone(),
        ReproduceFanOutArgs {
            product: info.product.clone(),
            result_dir,
            opts,
            entries,
            submit_user: ctx.user.clone(),
            submit_user_id: ctx.user_id,
            source_pkg_name: info.pkg_name.clone(),
        },
    )
    .await?;

    Ok(finish_replay_outcome(ReplayOutcomeArgs {
        app,
        ctx,
        task_id,
        new_task_id,
        ids,
        skipped_arches: Vec::new(),
        info,
        req_min,
        op: "reproduce",
        verb: "reproduced",
    })
    .await)
}

/// 解析 task 记录的构建选项为重放选项（rebuild / reproduce 共用）：剥 arch 与
/// arch_list，优先级改取记录值。serde 细节（含记录内容片段）只进日志，响应保持
/// Internal 固定文案；重放优先级按当前操作者重过提交校验（0-2 + operator-for-2）
/// ——operator 以下不得借重放继承原提交者的 critical 优先级。`op` 仅入 409 文案。
fn parse_replay_opts(
    info: &crbs_core::TaskRebuildInfo,
    ctx: &AuthContext,
    op: &str,
) -> Result<crbs_core::BuildOptions, ApiError> {
    let request_json = info.request_json.clone().ok_or_else(|| {
        ApiError::Conflict(format!("task has no recorded build options; cannot {op}"))
    })?;
    let mut opts: crbs_core::BuildOptions = serde_json::from_str(&request_json)
        .map_err(|e| ApiError::log_and_internal_with_context("parse recorded build options", e))?;
    opts.arch = None;
    opts.arch_list.clear();
    crate::server::validation::validate_build_priority(info.priority, ctx.is_operator())?;
    opts.priority = Some(info.priority);
    Ok(opts)
}

/// 解析产品 result_dir 并建目录 + 共享组权限收口（rebuild / reproduce 共用）；
/// `op` 仅入失败日志上下文。
async fn prepare_replay_result_dir(
    app: &Arc<AppState>,
    product: &str,
    op: &str,
) -> Result<std::path::PathBuf, ApiError> {
    let result_dir = app.result_dir_for(product).await.map_err(|e| {
        ApiError::log_and_internal_with_context(format!("resolve result_dir for {op}"), e)
    })?;
    tokio::fs::create_dir_all(&result_dir)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("create result_dir", e))?;
    crate::server::routes::builds::ensure_shared_result_dir(&result_dir).await;
    Ok(result_dir)
}

/// 重放收尾参数（`op`/`verb` 为 rebuild / reproduce 的文案对偶）。
struct ReplayOutcomeArgs<'a> {
    app: &'a Arc<AppState>,
    ctx: &'a AuthContext,
    task_id: i64,
    new_task_id: i64,
    ids: Vec<i64>,
    skipped_arches: Vec<String>,
    info: crbs_core::TaskRebuildInfo,
    /// 源任务放置契约下限的 KB 物化值（随 request_json 反序列化继承，回显
    /// 契约：rebuild/reproduce 响应与子构建落列同源）。
    req_min: crbs_core::build_options::ReqMinKb,
    op: &'a str,
    verb: &'a str,
}

/// 重放成功收尾（rebuild / reproduce 共用）：审计 + 结构化日志 + 响应组装。
/// 审计 action 取 `{op}_task`；日志动词 `verb`（rebuilt / reproduced）是不规则
/// 变化，无法从 `op` 派生，由调用方成对传入。
async fn finish_replay_outcome(
    args: ReplayOutcomeArgs<'_>,
) -> crate::server::routes::builds::BuildResponse {
    let ReplayOutcomeArgs {
        app,
        ctx,
        task_id,
        new_task_id,
        ids,
        skipped_arches,
        info,
        req_min,
        op,
        verb,
    } = args;
    let detail = serde_json::json!({
        "from_task_id": task_id,
        "new_task_id": new_task_id,
        "build_ids": ids,
    })
    .to_string();
    let _ = app
        .state_store
        .audit_log(
            &ctx.user,
            &ctx.role,
            &format!("{op}_task"),
            Some(&task_id.to_string()),
            Some(&detail),
        )
        .await;

    tracing::info!(
        from_task_id = task_id,
        new_task_id = new_task_id,
        user = %ctx.user,
        "Task {verb}"
    );

    crate::server::routes::builds::BuildResponse {
        task_id: new_task_id,
        ids,
        phase: "pending",
        product: info.product,
        submitted_at: chrono::Utc::now(),
        pkg_name: info.pkg_name,
        skipped_arches,
        req_min_mem_kb: req_min.mem,
        req_min_ncpu: req_min.ncpu,
        req_min_disk_kb: req_min.disk,
    }
}

/// 为 task 的 succeeded 子构建逐个组装 reproduce 条目（用户 reproduce 与 hub
/// 自动跟跑共用）。调用方传入 succeeded 子构建子集（用户路径按"succeeded-only
/// 扇出"过滤；auto replay 任务全子构建 succeeded，传入即全集）。逐子构建：
/// ①hub 上存在 build_packages.json（无则跳过该 arch，不阻塞其它）；②source/ 下按
/// srpm_display_name 定位提交时复制的原始 SRPM——不能用各 {arch}/SRPMS/ 下
/// rpmbuild 重新生成的（构建环境差异可能与原始不一致）；NotFound 折叠为 GC 409，
/// 迭代中途 read 失败同样 500 而非静默跳过。历史 noarch 映射产品首个具体 arch（不作派发键）。
pub(crate) async fn collect_reproduce_entries(
    app: &Arc<AppState>,
    task_id: i64,
    info: &crbs_core::TaskRebuildInfo,
    children: Vec<crbs_core::BuildRecord>,
) -> Result<Vec<crate::server::routes::builds::ReproduceArchEntry>, ApiError> {
    use crate::server::routes::builds::ReproduceArchEntry;

    let task_dir = match info.result_dir.clone() {
        Some(d) => std::path::PathBuf::from(d),
        None => app
            .result_dir_for(&info.product)
            .await
            .map_err(|e| ApiError::log_and_internal_with_context("resolve result_dir", e))?
            .join(task_id.to_string()),
    };
    let source_dir = task_dir.join("source");
    let result_root = app.result_dir_for_or_default(&info.product).await;

    let mut entries = Vec::new();
    for child in &children {
        let arch = match child.arch.as_deref() {
            Some(a) if !a.is_empty() => a.to_string(),
            _ => continue,
        };
        let (ctid, carch) = match (child.task_id, child.arch.as_deref()) {
            (Some(t), Some(a)) => (t, a),
            _ => continue,
        };
        let src_dir = crate::server::routes::builds::service::resolve_build_packages_dir(
            &result_root,
            ctid,
            carch,
            child.id,
        )
        .await;
        if src_dir.is_none() {
            tracing::warn!(
                task_id = %task_id,
                build_id = %child.id,
                arch = %arch,
                "source build has no build_packages.json; skipping in reproduce"
            );
            continue;
        }

        let pkg_name = &child.pkg_name;
        let srpm_path = match tokio::fs::read_dir(&source_dir).await {
            Ok(mut entries_rd) => {
                let mut found = None;
                loop {
                    match entries_rd.next_entry().await {
                        Ok(Some(e)) => {
                            let p = e.path();
                            if p.extension().map(|x| x == "rpm").unwrap_or(false)
                                && crbs_core::util::srpm_display_name(&p) == pkg_name
                            {
                                found = Some(p);
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            return Err(ApiError::log_and_internal_with_context(
                                "read task source dir",
                                e,
                            ));
                        }
                    }
                }
                found
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(ApiError::log_and_internal_with_context(
                    "read task source dir",
                    e,
                ));
            }
        }
        .ok_or_else(|| {
            ApiError::Conflict(
                "source srpms no longer available (results may have been GC'd); cannot reproduce"
                    .into(),
            )
        })?;

        entries.push(ReproduceArchEntry {
            arch,
            source_build_id: child.id,
            srpm_path,
        });
    }

    // noarch 复现保留原值 arch='noarch'：产物目录定位与回放锚探测都按原值
    // 进行；派发由 reproduce_fan_out 钉的 builds.host_arches（源构建实际宿主
    // 架构）约束，仅同架构 worker 可领取——依赖快照与宿主架构一致。

    Ok(entries)
}
