// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建提交公共流程：限额、共享结果目录、架构解析与幂等检查。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, FromRequest, State};
use axum::http::StatusCode;
use axum::Json;
use crbs_core::types::BuildRequest;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::builds::multipart::extract_multipart_build;
use crate::server::routes::builds::types::BuildResponse;
use crate::server::routes::builds::validation::ensure_disk_space;
use crate::server::routes::builds::BuildOptions;
use crate::server::routes::warn_audit_log_failure;
use crate::server::state::AppState;
use crate::server::validation::{validate_product_name, validate_srpm_path};

use fanout::IncomingUploadGuard;

mod fanout;
mod reproduce;
mod start;
#[cfg(test)]
mod tests;

pub(crate) use fanout::{fan_out_builds, FanOutArgs, FanOutOutcome};
pub(crate) use reproduce::{
    reproduce_fan_out, validate_replay_caps, validate_replay_caps_by_len, ReproduceArchEntry,
    ReproduceFanOutArgs,
};
pub(crate) use start::{check_build_chain_visibility, map_noarch_to_concrete, resolve_arches};
/// 单次提交允许的最大 SRPM 数量（JSON 与 multipart 入口共用）——防一次
/// 请求展开超大规模 fan-out（srpm × arch）压垮调度与磁盘。
pub(crate) const MAX_SRPMS_PER_SUBMIT: usize = 64;

/// 单次提交允许的最大架构数量（入口共用）；产品声明的 arches 超上限同样
/// 拒绝——CLI 需显式指定更少的 arch 提交。
pub(crate) const MAX_ARCHES_PER_SUBMIT: usize = 8;

/// JSON 提交分支的 per-request body 上限：2MB（对齐 axum 默认值；JSON 只是
/// 元数据，超限 = 客户端误塞文件本体）。内层 insert 覆盖路由级 ~1GB 上限。
pub(crate) const JSON_SUBMIT_LIMIT_BYTES: usize = 1024 * 1024 * 2;

/// rejection 映射：body 超过 [`JSON_SUBMIT_LIMIT_BYTES`] → 413；其余 rejection
///（语法 / 反序列化 / content-type 等）维持 400 折叠。
fn map_json_rejection(rej: JsonRejection) -> ApiError {
    match rej {
        JsonRejection::BytesRejection(
            axum::extract::rejection::BytesRejection::FailedToBufferBody(
                axum::extract::rejection::FailedToBufferBody::LengthLimitError(_),
            ),
        ) => ApiError::PayloadTooLarge(format!(
            "JSON request body exceeds {} bytes; use multipart/form-data to upload SRPMs",
            JSON_SUBMIT_LIMIT_BYTES
        )),
        other => ApiError::Validation(format!("parse json: {}", other)),
    }
}

/// 结果根目录设为共享模式（crbs 组、setgid、group rwx）——本地 CLI 需在同目录创建 `{product}/{pkg_name}` 子目录；失败仅 warn。
pub(crate) async fn ensure_shared_result_dir(result_dir: &Path) {
    let crbs_gid = match crbs_core::privilege::crbs_group_gid_async().await {
        Ok(gid) => gid,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to lookup crbs group gid; result_dir may not be shared");
            return;
        }
    };
    let uid = nix::unistd::getuid().as_raw();
    let path = result_dir.to_path_buf();
    let path_for_warn = path.clone();
    match tokio::task::spawn_blocking(move || {
        crbs_core::privilege::chown(&path, uid, crbs_gid, false)?;
        crbs_core::privilege::chmod(&path, 0o2770, false)
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::warn!(path = %path_for_warn.display(), error = %e, "Failed to set result_dir to shared mode");
        }
        Err(e) => {
            tracing::warn!(path = %path_for_warn.display(), error = %e, "Failed to spawn blocking task for result_dir permissions");
        }
    }
}

/// 构建提交入口：按 Content-Type 分发 multipart / JSON 流程，入队统一由 `start_build` 处理。
pub(crate) async fn submit_build(
    State(app): State<Arc<AppState>>,
    mut req: axum::extract::Request,
) -> Result<(StatusCode, Json<BuildResponse>), ApiError> {
    let auth_ctx = req.extensions().get::<AuthContext>().cloned();
    if let Some(ref ctx) = auth_ctx {
        if !ctx.can_submit() {
            return Err(ApiError::PermissionDenied(
                "viewer role cannot submit builds".into(),
            ));
        }
    }

    let content_type = match req.headers().get(axum::http::header::CONTENT_TYPE) {
        Some(v) => v
            .to_str()
            .map_err(|e| ApiError::Validation(format!("invalid Content-Type header: {}", e)))?,
        None => "",
    };

    let submit_user = auth_ctx
        .as_ref()
        .map(|ctx| ctx.user.clone())
        .unwrap_or_default();
    let result: Result<(StatusCode, Json<BuildResponse>), ApiError> =
        if content_type.starts_with("multipart/form-data") {
            // 磁盘预检在消费 multipart 流之前（否则客户端传完整个 SRPM 才收
            // 400），按与 extract_multipart_build 同源的 body 上限查 SRPM 实际
            // 流入的 upload_dir（可独立卷）而非 crbs_root——查错卷会误拒/漏拒。
            ensure_disk_space(
                &app.upload_dir(),
                app.server_config.upload_max_size_bytes() as u64,
            )
            .await?;
            let multipart = axum::extract::Multipart::from_request(req, &app)
                .await
                .map_err(|e| ApiError::Validation(format!("parse multipart: {}", e)))?;
            let extracted = extract_multipart_build(
                multipart,
                &app.upload_dir(),
                app.server_config.upload_max_size_bytes(),
            )
            .await?;
            submit_multipart_builds_common(
                &app,
                auth_ctx.as_ref(),
                extracted.product,
                extracted.srpm_paths,
                extracted.opts,
                extracted.labels,
                "api",
            )
            .await
            .map(|resp| (StatusCode::ACCEPTED, Json(resp)))
        } else {
            // per-request 2MB 上限内层 insert 覆盖路由级 ~1GB 上限；超限折 413。
            DefaultBodyLimit::max(JSON_SUBMIT_LIMIT_BYTES).apply(&mut req);
            let Json(build_req) = Json::<BuildRequest>::from_request(req, &app)
                .await
                .map_err(map_json_rejection)?;
            let outcome =
                submit_json_builds(app.clone(), build_req, &submit_user, auth_ctx.as_ref()).await;
            if let Ok((_, Json(ref resp))) = outcome {
                finish_submit_success(&app, auth_ctx.as_ref(), resp, "api").await;
            }
            outcome
        };

    result
}

/// 提交成功后的收尾（各入口共用）：唤醒调度器 + 审计；`source` 区分入口写审计 detail。
async fn finish_submit_success(
    app: &Arc<AppState>,
    auth_ctx: Option<&AuthContext>,
    resp: &BuildResponse,
    source: &str,
) {
    // 提交成功即唤醒调度器：否则新任务最多等 2s 兜底轮询才被拾起。
    app.worker_notify.notify_one();
    let Some(ctx) = auth_ctx else {
        return;
    };
    let detail = serde_json::json!({
        "product": resp.product,
        "count": resp.ids.len(),
        "source": source,
    })
    .to_string();
    if let Err(e) = app
        .state_store
        .audit_log(
            &ctx.user,
            &ctx.role,
            "submit_build",
            Some(&resp.task_id.to_string()),
            Some(&detail),
        )
        .await
    {
        warn_audit_log_failure(&e, "audit_log");
    }
}

/// multipart 提交核心（API 与 Web UI 表单共用）：入队 → 唤醒调度器 + 审计。
/// 权限门禁在内部 `submit_multipart_builds` 链路上执行；调用方需先完成入口
/// 自身门禁（UI 的 builder+ 与 CSRF 校验）。
pub(crate) async fn submit_multipart_builds_common(
    app: &Arc<AppState>,
    auth_ctx: Option<&AuthContext>,
    product: String,
    srpm_paths: Vec<PathBuf>,
    opts: BuildOptions,
    raw_labels: Vec<String>,
    source: &str,
) -> Result<BuildResponse, ApiError> {
    let submit_user = auth_ctx.map(|ctx| ctx.user.clone()).unwrap_or_default();
    let (_, Json(resp)) = submit_multipart_builds(
        app.clone(),
        product,
        srpm_paths,
        opts,
        &raw_labels,
        &submit_user,
        auth_ctx,
    )
    .await?;
    finish_submit_success(app, auth_ctx, &resp, source).await;
    Ok(resp)
}

/// 提交人权限检查（入口共用）：builder+ 角色门槛 + ACL viewer 角色检查
///（登录且非 operator 时查，仅 viewer 拒绝）；产品级放行由链上
/// `check_build_chain_visibility` 承担（ACL 不收窄提交范围）；无记录或产品
/// 不存在放行。
pub(crate) async fn ensure_can_submit_to_product(
    app: &Arc<AppState>,
    product: &str,
    auth_ctx: Option<&AuthContext>,
    submit_user_id: Option<i64>,
) -> Result<(), ApiError> {
    let Some(ctx) = auth_ctx else {
        return Ok(());
    };

    if !ctx.can_submit() {
        return Err(ApiError::PermissionDenied(format!(
            "you are not allowed to submit to product '{}'",
            product
        )));
    }

    if let Some(uid) = submit_user_id {
        if !ctx.is_operator() {
            match app.state_store.get_product_acl_role(uid, product).await {
                Ok(Some(role)) if role == "viewer" => {
                    return Err(ApiError::PermissionDenied(format!(
                        "you only have viewer access to product '{}'; cannot submit builds",
                        product
                    )));
                }
                Ok(_) => {}
                Err(crbs_core::error::CrbsError::NotFound { .. }) => {}
                Err(e) => {
                    return Err(ApiError::log_and_internal_with_context(
                        "check product ACL role",
                        e,
                    ));
                }
            }
        }
    }

    Ok(())
}

/// 校验最终架构数不超上限（JSON 与 multipart 入口共用，含产品声明多 arch 的场景）。
pub(crate) fn ensure_arch_count_within_limit(arches: &[String]) -> Result<(), ApiError> {
    if arches.len() > MAX_ARCHES_PER_SUBMIT {
        return Err(ApiError::Validation(format!(
            "too many arches in one submission: {} (max {}); specify fewer arches via --arch",
            arches.len(),
            MAX_ARCHES_PER_SUBMIT
        )));
    }
    Ok(())
}

/// 提交去重短路：产品下同 pkg_name 已有活跃构建（pending/assigned/
/// building）时拒绝 409，消息含全部冲突 pkg。
///
/// 契约：任何 insert 之前、每 SRPM 集合一次，绝不放进 `start_build` /
/// fan-out 循环——arch × srpm 展开会让同 pkg 第二行撞刚 insert 的第一行，
/// 自误伤。SELECT 与 insert 间有并发窗口，权威检查在 `insert_build` 事务内
///（命中同 409），此处仅快速失败 UX。
pub(crate) async fn ensure_no_active_duplicate(
    app: &Arc<AppState>,
    product: &str,
    pkg_names: &[String],
) -> Result<(), ApiError> {
    let names: Vec<&str> = pkg_names.iter().map(String::as_str).collect();
    let active = app
        .state_store
        .active_builds_for_pkg_names(product, &names)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("check active builds", e))?;
    if active.is_empty() {
        return Ok(());
    }
    let conflicts: Vec<String> = active
        .iter()
        .map(|b| {
            format!(
                "build for '{}' is already active in product '{}' (task {}, build {}, phase {})",
                b.pkg_name,
                product,
                b.task_id
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                b.build_id,
                b.phase
            )
        })
        .collect();
    Err(ApiError::Conflict(format!(
        "{}; wait for it to finish or cancel it before resubmitting",
        conflicts.join("; ")
    )))
}

/// JSON 提交流程：校验请求 → 创建 Task → 按架构创建子构建 → 返回 task_id。
/// SRPM 集合 → header N-V-R 真名（按输入序）：解析失败（损坏/非 RPM）→ 400，
/// 错误信封 = 文件名（不可解码回落 "srpm"）+ 底层错误。JSON 与 multipart 两个
/// 提交入口共用；multipart 拿真名后再做 incoming 重命名。
async fn resolve_srpm_nevrs(paths: &[PathBuf]) -> Result<Vec<String>, ApiError> {
    let parsed = crbs_core::engine::depsolve::parse_nevr_from_srpms(paths, None).await;
    let mut out = Vec::with_capacity(parsed.len());
    for (path, res) in paths.iter().zip(parsed) {
        let nevr = res.map_err(|e| {
            ApiError::Validation(format!(
                "{}: {}",
                path.file_name().and_then(|n| n.to_str()).unwrap_or("srpm"),
                e
            ))
        })?;
        out.push(nevr);
    }
    Ok(out)
}

async fn submit_json_builds(
    app: Arc<AppState>,
    req: BuildRequest,
    submit_user: &str,
    auth_ctx: Option<&AuthContext>,
) -> Result<(StatusCode, Json<BuildResponse>), ApiError> {
    validate_product_name(&req.product)?;

    let submit_user_id = auth_ctx.and_then(|ctx| ctx.user_id);

    ensure_can_submit_to_product(&app, &req.product, auth_ctx, submit_user_id).await?;

    if req.srpms.is_empty() {
        return Err(ApiError::Validation("at least one SRPM is required".into()));
    }
    if req.srpms.len() > MAX_SRPMS_PER_SUBMIT {
        return Err(ApiError::Validation(format!(
            "too many SRPMs in one submission: {} (max {}); split into multiple submissions",
            req.srpms.len(),
            MAX_SRPMS_PER_SUBMIT
        )));
    }

    if let Some(p) = req.options.priority {
        crate::server::validation::validate_build_priority(
            p,
            auth_ctx.is_some_and(|ctx| ctx.is_operator()),
        )?;
    }

    // 持有自有数据而非借用 req，下方整体移出 req.options。
    let cli_arches: Option<Vec<String>> = if let Some(ref list) = req.arch_list {
        if list.is_empty() {
            None
        } else {
            Some(list.clone())
        }
    } else {
        req.options.arch.clone().map(|arch| vec![arch])
    };

    // opts.arch 仅参与上面的 cli_arches 解析，实际架构由循环逐架构覆盖。
    let mut opts = req.options;
    opts.arch = None;
    // 标签在入口统一校验（数量/长度上限、控制字符、重复键）：非法输入 400。
    let labels: Vec<(String, String)> = req
        .labels
        .iter()
        .map(|l| (l.key.clone(), l.value.clone()))
        .collect();
    crbs_core::validation::validate_task_labels(&labels)
        .map_err(|e| ApiError::Validation(e.to_string()))?;
    // HTTP 输入边界：reproduce_from_build_id 只允许服务端 reproduce 路径设置；
    // 因 worker 需从任务 JSON 反序列化读取，不能用 serde(skip_deserializing)，
    // 只能在入口清除客户端提交值。
    opts.reproduce_from_build_id = None;
    // 早期校验（fail-closed）：提交阶段即拒，避免 202 后执行期才异步失败。
    crbs_core::validate_options(&opts)?;

    let mut paths = Vec::with_capacity(req.srpms.len());
    let upload_dir = app.upload_dir();
    tokio::fs::create_dir_all(&upload_dir)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("create upload_dir", e))?;
    for srpm in &req.srpms {
        validate_srpm_path(srpm, &upload_dir).await?;
        paths.push(PathBuf::from(srpm));
    }

    // 去重短路（insert 前、每 SRPM 集合一次）。JSON 入口的 srpms 是 hub
    // 本地路径（不重命名提交者文件），任务真名仍以 header N-V-R 为准——
    // 解析失败（损坏/非 RPM）→ 400 拒绝。名称同时作为 create_task 的
    // 存档落盘名，worker 下载名随之对齐。
    let nevr = resolve_srpm_nevrs(&paths).await?;
    ensure_no_active_duplicate(&app, &req.product, &nevr).await?;

    ensure_disk_space(&app.crbs_root, app.server_config.min_free_disk_bytes()).await?;

    check_build_chain_visibility(&app, &req.product, auth_ctx).await?;
    let arches = resolve_arches(&app, &req.product, cli_arches.as_deref(), auth_ctx).await?;
    ensure_arch_count_within_limit(&arches)?;
    let submitted_at = chrono::Utc::now();

    let result_dir = app.result_dir_for(&req.product).await.map_err(|e| {
        ApiError::log_and_internal_with_context("resolve result_dir for disk check", e)
    })?;
    tokio::fs::create_dir_all(&result_dir)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("create result_dir", e))?;
    ensure_shared_result_dir(&result_dir).await;
    ensure_disk_space(&result_dir, app.server_config.min_free_disk_bytes()).await?;

    let skip_unsupported_arches = opts.skip_unsupported_arches;
    // 放置契约下限解析（响应回显与子构建落列同源；validate_options 已过语法，
    // 此处结果不可失败，Err 仅为重放路径兜底）。
    let req_min =
        crbs_core::build_options::ReqMinKb::from_options(&opts).map_err(ApiError::from)?;
    let FanOutOutcome {
        task_id,
        build_ids: ids,
        skipped_arches,
    } = fan_out_builds(
        app.clone(),
        FanOutArgs {
            product: req.product.clone(),
            result_dir,
            srpm_paths: paths,
            opts,
            arches,
            submit_user: submit_user.to_string(),
            submit_user_id,
            allow_move: false,
            collapse_noarch: true,
            arch_explicit: cli_arches.is_some(),
            skip_unsupported_arches,
            source_names: nevr.iter().map(|n| format!("{}.src.rpm", n)).collect(),
            task_labels: labels,
        },
    )
    .await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(BuildResponse {
            task_id,
            ids,
            phase: "pending",
            product: req.product,
            submitted_at,
            pkg_name: nevr.first().cloned().unwrap_or_default(),
            skipped_arches,
            req_min_mem_kb: req_min.mem,
            req_min_ncpu: req_min.ncpu,
            req_min_disk_kb: req_min.disk,
        }),
    ))
}

/// multipart 标签原文解析：语法（`KEY=VALUE`）、数量/长度上限与重复键校验
/// 全在入口收口，非法输入 400，不进入 fan-out。
fn parse_submit_labels(raw: &[String]) -> Result<Vec<(String, String)>, ApiError> {
    let labels = raw
        .iter()
        .map(|s| crbs_core::validation::parse_task_label_arg(s))
        .collect::<crbs_core::Result<Vec<_>>>()
        .map_err(|e| ApiError::Validation(e.to_string()))?;
    crbs_core::validation::validate_task_labels(&labels)
        .map_err(|e| ApiError::Validation(e.to_string()))?;
    Ok(labels)
}

/// Multipart 提交流程：创建 Task → 按架构创建子构建 → 返回 task_id。
async fn submit_multipart_builds(
    app: std::sync::Arc<AppState>,
    product: String,
    srpm_paths: Vec<PathBuf>,
    mut opts: BuildOptions,
    raw_labels: &[String],
    submit_user: &str,
    auth_ctx: Option<&AuthContext>,
) -> Result<(StatusCode, Json<BuildResponse>), ApiError> {
    validate_product_name(&product)?;
    let labels = parse_submit_labels(raw_labels)?;

    // 消费后清理本次请求的 .incoming/{uuid} 子目录，覆盖所有出错/取消返回路径。
    let _incoming_guard = IncomingUploadGuard::new(
        crate::server::routes::builds::multipart::request_incoming_dir_of(
            &app.upload_dir(),
            &srpm_paths,
        ),
    );

    // 与 JSON 入口对齐：防御性清 reproduce_from_build_id + 同一套早期校验。
    opts.reproduce_from_build_id = None;
    crbs_core::validate_options(&opts)?;

    let submit_user_id = auth_ctx.and_then(|ctx| ctx.user_id);

    ensure_can_submit_to_product(&app, &product, auth_ctx, submit_user_id).await?;

    if srpm_paths.len() > MAX_SRPMS_PER_SUBMIT {
        return Err(ApiError::Validation(format!(
            "too many SRPMs in one submission: {} (max {}); split into multiple submissions",
            srpm_paths.len(),
            MAX_SRPMS_PER_SUBMIT
        )));
    }

    // 与 JSON 入口同一套优先级校验。
    if let Some(p) = opts.priority {
        crate::server::validation::validate_build_priority(
            p,
            auth_ctx.is_some_and(|ctx| ctx.is_operator()),
        )?;
    }

    // 任务真名以 SRPM header 的 N-V-R 为准（与上传文件名解耦，防重命名
    // 导致审计/结果目录失真）：解析失败（损坏/非 RPM）→ 400 拒绝，先于
    // 去重 409（"输入错误先于状态冲突"同序）。解析后 incoming 文件重命名
    // 为 {N-V-R}.src.rpm，worker 下载落盘名与结果目录随之对齐。
    // ponytail: 解析与重命名两段推进，复合故障（前序 rename 失败 + 后续
    // 解析失败）时先报解析 400 而非 rename 500——两条均为失败路径、暂存域
    // 由 guard 统一清理；如需严格保错误序可回退为逐条交错。
    let pkg_names = resolve_srpm_nevrs(&srpm_paths).await?;
    let srpm_paths: Vec<PathBuf> = {
        let mut paths = Vec::with_capacity(srpm_paths.len());
        for (path, nevr) in srpm_paths.iter().zip(&pkg_names) {
            // incoming 文件重命名为真名（.incoming/{uuid} 属本请求暂存域，安全）
            let dir = path
                .parent()
                .ok_or_else(|| ApiError::Validation("SRPM path has no parent".into()))?;
            let renamed = dir.join(format!("{}.src.rpm", nevr));
            if renamed != *path {
                tokio::fs::rename(path, &renamed).await.map_err(|e| {
                    ApiError::log_and_internal_with_context("rename incoming SRPM to N-V-R", e)
                })?;
            }
            paths.push(renamed);
        }
        paths
    };
    ensure_no_active_duplicate(&app, &product, &pkg_names).await?;

    ensure_disk_space(&app.crbs_root, app.server_config.min_free_disk_bytes()).await?;

    check_build_chain_visibility(&app, &product, auth_ctx).await?;
    // 与 JSON 入口同一判别口径：arch_list 非空 = 用户显式指定（空表 = 产品
    // 默认 fan-out，预检按跳过处理）。
    let arch_explicit_multipart = !opts.arch_list.is_empty();
    let arches = resolve_arches(&app, &product, Some(opts.arch_list.as_slice()), auth_ctx).await?;
    ensure_arch_count_within_limit(&arches)?;

    let submitted_at = chrono::Utc::now();

    let result_dir = app.result_dir_for(&product).await.map_err(|e| {
        ApiError::log_and_internal_with_context("resolve result_dir for disk check", e)
    })?;
    tokio::fs::create_dir_all(&result_dir)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("create result_dir", e))?;
    ensure_shared_result_dir(&result_dir).await;
    ensure_disk_space(&result_dir, app.server_config.min_free_disk_bytes()).await?;

    let skip_unsupported_arches = opts.skip_unsupported_arches;
    // 放置契约下限解析（响应回显与子构建落列同源；validate_options 已过语法，
    // 此处结果不可失败，Err 仅为重放路径兜底）。
    let req_min =
        crbs_core::build_options::ReqMinKb::from_options(&opts).map_err(ApiError::from)?;
    let FanOutOutcome {
        task_id,
        build_ids: ids,
        skipped_arches,
    } = fan_out_builds(
        app.clone(),
        FanOutArgs {
            product: product.clone(),
            result_dir,
            srpm_paths,
            opts,
            arches,
            submit_user: submit_user.to_string(),
            submit_user_id,
            allow_move: true,
            collapse_noarch: true,
            // multipart 入口的显式判别与 JSON 入口同口径（arch_list 非空 =
            // 显式请求）；skip_unsupported_arches 经 multipart.rs 字段臂落
            // opts（CLI --skip-unsupported-arches 远端提交通道）。
            arch_explicit: arch_explicit_multipart,
            skip_unsupported_arches,
            source_names: Vec::new(),
            task_labels: labels,
        },
    )
    .await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(BuildResponse {
            task_id,
            ids,
            phase: "pending",
            product,
            submitted_at,
            pkg_name: pkg_names.first().cloned().unwrap_or_default(),
            skipped_arches,
            req_min_mem_kb: req_min.mem,
            req_min_ncpu: req_min.ncpu,
            req_min_disk_kb: req_min.disk,
        }),
    ))
}
