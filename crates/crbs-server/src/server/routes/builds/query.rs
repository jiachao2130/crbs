// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建查询与取消路由：可见性过滤、分页与复现状态。

use std::sync::Arc;

use axum::extract::{Extension, Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;

use crate::server::auth::visibility::ensure_product_visible_for_record;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::builds::service;
use crate::server::state::AppState;

use super::types::{
    sanitize_build_record, BuildListResponse, CancelResponse, DiffQuery, ListQuery,
    UpdatePriorityRequest,
};

/// 构建详情：`Json<BuildRecord>` 经 [`sanitize_build_record`] 脱敏，`result_dir` / `srpm_path`（服务端绝对路径）不回显（null）。
pub(crate) async fn get_build(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<crbs_core::BuildRecord>, ApiError> {
    let record = service::fetch_build_with_rpms(&app, id, auth.as_ref().map(|ext| &ext.0)).await?;
    Ok(Json(sanitize_build_record(record)))
}

/// `GET /api/v1/builds/{id}/reproducibility` 响应。
#[derive(serde::Serialize)]
pub(crate) struct BuildReproducibilityResponse {
    pub build_id: i64,
    /// 该 build 作为 source（或 replay）的全部比对行，按 id 升序。
    pub results: Vec<crbs_core::ReproducibilityRecord>,
}

/// `GET /api/v1/builds/{id}/reproducibility`：verdict 比对行查询；
/// 可见性与 get_build 同口径（产品可见性，经 fetch_build_with_rpms）。
pub(crate) async fn get_build_reproducibility(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<BuildReproducibilityResponse>, ApiError> {
    service::fetch_build_with_rpms(&app, id, auth.as_ref().map(|ext| &ext.0)).await?;
    let results = app.state_store.list_reproducibility_for_build(id).await?;
    Ok(Json(BuildReproducibilityResponse {
        build_id: id,
        results,
    }))
}

pub(crate) async fn list_builds(
    State(app): State<Arc<AppState>>,
    Query(mut q): Query<ListQuery>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<BuildListResponse>, ApiError> {
    // 省略 limit 默认 200（与显式上限一致），杜绝无 LIMIT 全表读取。
    let limit = q.limit.or(Some(crate::server::validation::MAX_LIST_LIMIT));
    crate::server::validation::validate_list_pagination(limit, q.offset)?;
    q.limit = limit;
    // priority 是 UI-only 过滤（API 契约不含该参数），恒传 None。
    let mut resp =
        service::list_builds_for_user(&app, &q, auth.as_ref().map(|ext| &ext.0), None).await?;
    // 列表逐条脱敏：不回显服务端绝对路径（同 detail 口径）。
    resp.builds = resp.builds.into_iter().map(sanitize_build_record).collect();

    Ok(Json(resp))
}

pub(crate) async fn cancel_build(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<(StatusCode, Json<CancelResponse>), ApiError> {
    let outcome = service::cancel_build_for_user(&app, id, auth.as_ref().map(|ext| &ext.0)).await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(CancelResponse {
            cancelled: outcome.cancelled,
            id,
            message: outcome.message,
        }),
    ))
}

pub(crate) async fn publish_build(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let outcome =
        service::set_build_publish_for_user(&app, id, true, auth.as_ref().map(|ext| &ext.0))
            .await?;
    Ok(Json(publish_response(id, &outcome)))
}

pub(crate) async fn unpublish_build(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let outcome =
        service::set_build_publish_for_user(&app, id, false, auth.as_ref().map(|ext| &ext.0))
            .await?;
    Ok(Json(publish_response(id, &outcome)))
}

fn publish_response(id: i64, outcome: &service::PublishBuildOutcome) -> serde_json::Value {
    serde_json::json!({
        "build_id": id,
        "product": outcome.product,
        "repo_publish": outcome.repo_publish,
        "arches": outcome.report.arches,
        "linked": outcome.report.linked,
        "unlinked": outcome.report.unlinked,
        "skipped_missing": outcome.report.skipped_missing,
        "skipped_exdev": outcome.report.skipped_exdev,
        "skipped_other": outcome.report.skipped_other,
    })
}

pub(crate) async fn diff_build(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
    Query(q): Query<DiffQuery>,
) -> Result<Json<crbs_core::diff::DiffResult>, ApiError> {
    service::fetch_build_with_rpms(&app, id, auth.as_ref().map(|ext| &ext.0)).await?;

    // against（右侧）同受可见性约束：compute_diff 内部只有 user_filter
    // （viewer/operator 为 None；功能参数，非权限）、无产品可见性判定，
    // 不前置检查则 viewer 可 diff 私有产品；非数字 against 保持 400 Validation。
    let against_id: i64 = q.against.parse().map_err(|_| {
        ApiError::Validation(format!("against must be a number, got '{}'", q.against))
    })?;
    // 校验性取回：compute_diff 会再查一遍，这里只为右侧构建过 404 / 产品可见性检查。
    service::fetch_build_with_rpms(&app, against_id, auth.as_ref().map(|ext| &ext.0)).await?;

    let user_filter = service::diff_user_filter(auth.as_ref().map(|ext| &ext.0));
    // result_dir 安全根 = server 世界配置（GC 同款 pin）：pin 到 app.crbs_root
    // 并按 AppState 回填显式 result_dir——core 不重读 /etc/crbs/crbs.toml
    //（server-only / root 不一致部署会全拒），显式根部署不回填则 worker 落库路径全拒（500）。
    let mut global = crbs_core::config::CrbsConfig::load_async()
        .await?
        .pinned_to_root(&app.crbs_root);
    global.result_dir = app.explicit_result_dir();
    let result = crbs_core::diff::compute_diff(
        &app.state_store,
        &global,
        &id.to_string(),
        &q.against,
        user_filter,
    )
    .await?;
    Ok(Json(result))
}

pub(crate) async fn update_priority(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<UpdatePriorityRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if let Some(ctx) = auth.as_ref() {
        if !ctx.can_priority() {
            return Err(ApiError::PermissionDenied(
                "only operator or admin can change build priority".into(),
            ));
        }
    }

    // is_operator=true：operator+ 门控已在上方完成，仅跳过 priority=2 重复检查（与提交侧同口径，operator/admin 均可设 critical）。
    crate::server::validation::validate_build_priority(req.priority, true)?;

    // 原子更新：先 UPDATE，再区分 NotFound vs Conflict，避免竞态窗口。
    match app
        .state_store
        .update_build_priority(id, req.priority)
        .await
    {
        Ok(()) => {}
        Err(crbs_core::error::CrbsError::ValidationFailed { .. }) => {
            let record = app.state_store.get_build(id).await?;
            return match record {
                Some(_) => Err(ApiError::Conflict(
                    "can only update priority for pending builds".into(),
                )),
                None => Err(ApiError::not_found("build", id)),
            };
        }
        Err(e) => return Err(e.into()),
    }

    if let Some(ctx) = auth.as_ref() {
        let detail = serde_json::json!({ "priority": req.priority }).to_string();
        let _ = app
            .state_store
            .audit_log(
                &ctx.user,
                &ctx.role,
                "change_priority",
                Some(&id.to_string()),
                Some(&detail),
            )
            .await;
    }

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "id": id,
            "priority": req.priority,
        })),
    ))
}

/// 下载构建 SRPM。认证：签名 query token（dispatch 生成，10 分钟有效）优先，
/// 回退 Bearer Token（worker 角色或构建所有者）。
#[derive(serde::Deserialize)]
pub(crate) struct SrpmDownloadQuery {
    pub token: Option<String>,
}

/// 下载双端点（SRPM / build_packages.json）共用鉴权前奏：取 build 行 +
/// 签名 query token 校验（dispatch 生成，命中即放行）+ 回退 Bearer
///（worker 豁免 / 产品可见性 / 匿名 401）；匿名拒绝文案按端点语义由调用方传入。
async fn fetch_download_authorized(
    app: &Arc<AppState>,
    auth: &Option<Extension<AuthContext>>,
    q: &SrpmDownloadQuery,
    id: i64,
    unauthorized_msg: &'static str,
) -> Result<crbs_core::BuildRecord, ApiError> {
    let record = app
        .state_store
        .get_build(id)
        .await?
        .ok_or_else(|| ApiError::not_found("build", id))?;

    let token_valid = q
        .token
        .as_deref()
        .map(|token| app.srpm_token_signer.validate(id, token))
        .unwrap_or(false);

    if !token_valid {
        if let Some(ctx) = auth.as_ref() {
            // worker 与签名 token 同为机器身份：private 产品经 dispatch /
            // worker secret 取件，不走用户产品 ACL。
            if ctx.role != "worker" {
                ensure_product_visible_for_record(app, &record.product, Some(&ctx.0)).await?;
            }
        } else {
            // 匿名 → 401；403 保留给已认证但产品不可见（上方产品级检查）。
            return Err(ApiError::Unauthorized(unauthorized_msg.into()));
        }
    }
    Ok(record)
}

pub(crate) async fn download_srpm(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
    Query(q): Query<SrpmDownloadQuery>,
) -> Result<axum::response::Response, ApiError> {
    let record = fetch_download_authorized(
        &app,
        &auth,
        &q,
        id,
        "missing authentication for SRPM download",
    )
    .await?;

    let srpm_path_str = match record.srpm_path {
        Some(ref p) => p.as_str(),
        None => return Err(ApiError::not_found("srpm", id)),
    };
    let result_root = app.result_dir_for_or_default(&record.product).await;
    let srpm_path = match crbs_core::util::validate_result_dir(srpm_path_str, &result_root).await {
        Ok(path) => path,
        Err(e) => {
            // Validation 细节含服务端绝对路径，只进日志不进响应，状态码保持 400。
            tracing::warn!(build_id = %id, error = %e, "Invalid srpm_path while resolving SRPM download");
            return Err(ApiError::Validation("invalid srpm_path".into()));
        }
    };
    if !srpm_path.exists() {
        return Err(ApiError::not_found("srpm", id));
    }

    let file = tokio::fs::File::open(&srpm_path)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("open srpm", e))?;
    let stream = tokio_util::io::ReaderStream::new(file);

    let filename = srpm_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("package.src.rpm");

    let body = axum::body::Body::from_stream(stream);

    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "application/x-rpm")
        // 产物快照禁止缓存留存（与 download_artifact 同口径）。
        .header(axum::http::header::CACHE_CONTROL, "no-store")
        .header(
            axum::http::header::CONTENT_DISPOSITION,
            // 共享 helper：RFC 5987 ext-value + ASCII 兜底。
            crate::server::routes::artifacts::download::content_disposition(filename),
        )
        .body(body)
        .map_err(|e| ApiError::log_and_internal_with_context("build srpm response body", e))
}

/// 下载 `build_packages.json`（reproduce 复现清单，worker 取来源构建的环境包清单）；
/// 认证同 `download_srpm`：签名 query token（dispatch 生成）优先，回退 Bearer Token。
pub(crate) async fn download_build_packages(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
    Query(q): Query<SrpmDownloadQuery>,
) -> Result<axum::response::Response, ApiError> {
    let record = fetch_download_authorized(
        &app,
        &auth,
        &q,
        id,
        "missing authentication for build-packages download",
    )
    .await?;

    let (task_id, arch) = match (record.task_id, record.arch.as_deref()) {
        (Some(tid), Some(a)) => (tid, a),
        _ => {
            return Err(ApiError::not_found("build packages", id));
        }
    };
    let result_root = app.result_dir_for_or_default(&record.product).await;
    let src_dir = crate::server::routes::builds::service::resolve_build_packages_dir(
        &result_root,
        task_id,
        arch,
        id,
    )
    .await
    .ok_or_else(|| ApiError::not_found("build packages", id))?;
    let json_path = src_dir.join("build_packages.json");

    let file = tokio::fs::File::open(&json_path)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("open build_packages.json", e))?;
    let stream = tokio_util::io::ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);

    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        // 产物快照禁止缓存留存（与 download_artifact 同口径）。
        .header(axum::http::header::CACHE_CONTROL, "no-store")
        .header(
            axum::http::header::CONTENT_DISPOSITION,
            // 固定 ASCII 文件名，无需 RFC 5987 扩展。
            "attachment; filename=\"build_packages.json\"",
        )
        .body(body)
        .map_err(|e| ApiError::log_and_internal_with_context("build-packages response body", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_context(user: &str, role: &str) -> AuthContext {
        AuthContext {
            user: user.into(),
            role: role.into(),
            ..Default::default()
        }
    }

    /// 详情产品可见性（同 tasks get_task）：viewer 对 private 产品 403（产品级检查兜底）、public 200。
    #[tokio::test]
    async fn get_build_checks_product_visibility() {
        use crate::server::state::AppState;

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));

        let owner_id = store.create_user("owner", "builder").await.unwrap();
        for (name, owner_id, visibility) in [
            ("secret", Some(owner_id), crbs_core::VISIBILITY_PRIVATE),
            ("openfed", None, crbs_core::VISIBILITY_PUBLIC),
        ] {
            store
                .create_product(crbs_core::CreateProductInput {
                    name,
                    display_name: None,
                    owner_id,
                    parent_id: None,
                    visibility,
                    config: &crbs_core::config::ProductConfig::default(),
                    changed_by_user_id: None,
                    reason: Some("test seed"),
                })
                .await
                .unwrap();
        }

        let insert_build = |product: &'static str| {
            let store = store.clone();
            async move {
                let task_id = crate::test_support::seed_task(&store, product, "pkg").await;
                store
                    .insert_build(crbs_core::BuildInsert {
                        product,
                        pkg_name: "pkg",
                        phase: "succeeded",
                        backend: "chroot",
                        // 提交者是别人：产品级检查独立把门，与提交者身份无关。
                        user: "alice",
                        task_id: Some(task_id),
                        ..Default::default()
                    })
                    .await
                    .unwrap()
            }
        };

        let secret_id = insert_build("secret").await;
        let result = get_build(
            State(app.clone()),
            AxumPath(secret_id),
            Some(Extension(auth_context("eve", "viewer"))),
        )
        .await;
        assert!(
            matches!(result, Err(ApiError::PermissionDenied(_))),
            "private product build detail must be denied for viewer"
        );

        let public_id = insert_build("openfed").await;
        let result = get_build(
            State(app),
            AxumPath(public_id),
            Some(Extension(auth_context("eve", "viewer"))),
        )
        .await;
        assert!(result.is_ok());
    }

    /// download_srpm 响应头契约：`Cache-Control: no-store` + 共享 content_disposition
    /// 的 RFC 5987 形态（非 ASCII → ext-value + ASCII 兜底）；worker 机器身份豁免 ACL。
    #[tokio::test]
    async fn download_srpm_sets_no_store_and_rfc5987_content_disposition() {
        use crate::server::state::AppState;

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));

        // 结果根 {crbs_root}/results（for_test 默认），落非 ASCII 文件名 SRPM。
        let result_root = tmp.path().join("results");
        tokio::fs::create_dir_all(&result_root).await.unwrap();
        let srpm_path = result_root.join("包-1.0.src.rpm");
        tokio::fs::write(&srpm_path, b"fake srpm").await.unwrap();

        let task_id = crate::test_support::seed_task(&store, "fedora", "pkg").await;
        let build_id = store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "pkg",
                phase: "succeeded",
                backend: "chroot",
                user: "alice",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .set_build_request_info(build_id, srpm_path.to_str().unwrap(), "{}")
            .await
            .unwrap();

        let response = download_srpm(
            State(app),
            AxumPath(build_id),
            Some(Extension(auth_context("worker-1", "worker"))),
            Query(SrpmDownloadQuery { token: None }),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let headers = response.headers();
        assert_eq!(
            headers
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "download response must not be cached"
        );
        assert_eq!(
            headers
                .get(axum::http::header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok()),
            Some(
                "attachment; filename=\"-1.0.src.rpm\"; \
                 filename*=UTF-8''%E5%8C%85-1.0.src.rpm"
            ),
            "non-ASCII srpm file name must use RFC 5987 ext-value with ASCII fallback"
        );
    }

    /// 匿名回归：无 token 无凭据 → 两下载端点都 401；签名 token / worker Bearer 才可取件。
    #[tokio::test]
    async fn download_endpoints_reject_anonymous_requests_with_unauthorized() {
        use crate::server::state::AppState;

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));

        let task_id = crate::test_support::seed_task(&store, "fedora", "pkg").await;
        let build_id = store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "pkg",
                phase: "succeeded",
                backend: "chroot",
                user: "alice",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        // 既有 build 行（否则先撞 404，测不到匿名分支）：无 token 无凭据 → 401。
        let result = download_srpm(
            State(app.clone()),
            AxumPath(build_id),
            None,
            Query(SrpmDownloadQuery { token: None }),
        )
        .await;
        assert!(
            matches!(result, Err(ApiError::Unauthorized(_))),
            "anonymous srpm download must be 401: {result:?}"
        );

        let result = download_build_packages(
            State(app),
            AxumPath(build_id),
            None,
            Query(SrpmDownloadQuery { token: None }),
        )
        .await;
        assert!(
            matches!(result, Err(ApiError::Unauthorized(_))),
            "anonymous build-packages download must be 401: {result:?}"
        );
    }
}
