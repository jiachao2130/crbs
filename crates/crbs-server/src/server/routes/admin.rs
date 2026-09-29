// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Admin 管理端点：用户、Token、产品 ACL、Worker 操作、仓库重建。
//!
//! 除特别说明外仅限 `admin` 角色访问。

use std::sync::Arc;

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crbs_core::auth::secret::{Secret, SecretHash, SecretKind};
use crbs_core::error::CrbsError;
use crbs_core::InitConflict;
use crbs_core::{AuditLog, AuditLogFilter, User, UserToken};

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::{audit_event, require_admin};
use crate::server::state::AppState;
use crate::server::validation::{validate_product_name, validate_user_name};

const VALID_ROLES: &[&str] = &["admin", "operator", "builder", "viewer"];

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/admin/audit-logs", get(list_audit_logs))
        .route("/api/v1/admin/users", post(create_user).get(list_users))
        .route(
            "/api/v1/admin/users/{id}",
            get(get_user).put(update_user).delete(disable_user),
        )
        .route(
            "/api/v1/admin/users/{id}/tokens",
            post(create_token).get(list_tokens),
        )
        .route(
            "/api/v1/admin/users/{id}/tokens/{tid}",
            delete(revoke_token),
        )
        .route(
            "/api/v1/admin/products/{product}/acl",
            post(grant_acl).get(list_acl),
        )
        .route(
            "/api/v1/admin/products/{product}/acl/{user_id}",
            delete(revoke_acl),
        )
        .route("/api/v1/admin/workers/{id}/init", post(init_worker))
        .route(
            "/api/v1/admin/products/{product}/rebuild-repo",
            post(rebuild_repo),
        )
}

/// 管理写操作的三臂收口：Conflict（业务守卫，如最后活跃管理员）原样透传
/// 409，其余附上下文落 500。
fn conflict_or_internal(ctx: &'static str, e: CrbsError) -> ApiError {
    match e {
        CrbsError::Conflict { message } => ApiError::Conflict(message),
        other => ApiError::log_and_internal_with_context(ctx, other),
    }
}

fn validate_role(role: &str) -> Result<(), ApiError> {
    if VALID_ROLES.contains(&role) {
        Ok(())
    } else {
        Err(ApiError::Validation(format!(
            "invalid role '{}'; expected one of: admin, operator, builder, viewer",
            role
        )))
    }
}

#[derive(Deserialize)]
pub(crate) struct AuditLogQuery {
    pub user: Option<String>,
    pub role: Option<String>,
    pub action: Option<String>,
    pub target: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Serialize)]
pub(crate) struct AuditLogListResponse {
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
    pub logs: Vec<AuditLog>,
}

pub(crate) async fn list_audit_logs(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    Query(q): Query<AuditLogQuery>,
) -> Result<Json<AuditLogListResponse>, ApiError> {
    require_admin(auth)?;

    // 分页参数上限校验（limit ≤ 200 / offset ≤ 1_000_000，超限 400），
    // 与 builds / tasks 列表同口径。
    crate::server::validation::validate_list_pagination(q.limit, q.offset)?;

    // state 层 filter 是 i64：limit 未传（0）由 normalized_limit 归一到
    // 默认 100，offset 未传按 0。
    let filter = AuditLogFilter {
        user: q.user.as_deref(),
        role: q.role.as_deref(),
        action: q.action.as_deref(),
        target: q.target.as_deref(),
        since: q.since.as_deref(),
        until: q.until.as_deref(),
        limit: q.limit.unwrap_or(0) as i64,
        offset: q.offset.unwrap_or(0) as i64,
    };
    // 回显实际生效值（与 SQL 实际应用一致）：API 上限 200 已在入口拦下，
    // 未传 limit 时 state 层默认 100，offset 钳非负。
    let effective_limit = filter.normalized_limit();
    let effective_offset = filter.offset.max(0);

    let (total, logs) = tokio::try_join!(
        app.state_store.count_audit_logs(AuditLogFilter {
            user: filter.user,
            role: filter.role,
            action: filter.action,
            target: filter.target,
            since: filter.since,
            until: filter.until,
            limit: 0,
            offset: 0,
        }),
        app.state_store.list_audit_logs(filter)
    )
    .map_err(|e| match e {
        // since/until 解析失败是调用方输入问题 → 400（其余按内部错误处理）。
        crbs_core::error::CrbsError::ValidationFailed { .. } => ApiError::from(e),
        other => ApiError::log_and_internal_with_context("list audit logs", other),
    })?;

    Ok(Json(AuditLogListResponse {
        total,
        limit: effective_limit,
        offset: effective_offset,
        logs,
    }))
}

#[derive(Deserialize)]
pub(crate) struct CreateUserRequest {
    pub name: String,
    pub role: String,
}

#[derive(Deserialize, Default)]
pub(crate) struct UpdateUserRequest {
    pub role: Option<String>,
    pub status: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct UserResponse {
    pub id: i64,
    pub name: String,
    pub role: String,
    pub status: String,
    pub created_at: String,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            name: u.name,
            role: u.role,
            status: u.status,
            created_at: u.created_at,
        }
    }
}

pub(crate) async fn create_user(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), ApiError> {
    let ctx = require_admin(auth)?;
    validate_user_name(&req.name)?;
    validate_role(&req.role)?;

    // 避免用户名冲突时返回 500
    if app
        .state_store
        .find_user_by_name(&req.name)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("check existing user", e))?
        .is_some()
    {
        return Err(ApiError::Conflict(format!(
            "user '{}' already exists",
            req.name
        )));
    }

    let id = app
        .state_store
        .create_user(&req.name, &req.role)
        .await
        .map_err(|e| match e {
            // 并发窗口：预检通过后他人抢先插入同名用户 → UNIQUE 冲突映射 409
            // （与 CrbsError::AlreadyExists 语义一致），而非 500。判定文本与
            // products 层 is_unique_violation_msg 同口径（SQLite/PG 双方言）。
            crbs_core::error::CrbsError::Database(ref msg)
                if msg.contains("UNIQUE constraint failed")
                    || msg.contains("duplicate key value violates unique constraint") =>
            {
                ApiError::Conflict(format!("user '{}' already exists", req.name))
            }
            other => ApiError::log_and_internal_with_context("create user", other),
        })?;

    let user = app
        .state_store
        .get_user(id)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("get user after create", e))?
        .ok_or_else(|| ApiError::Internal("user disappeared after create".into()))?;

    audit_event(&app, &ctx, "create_user", Some(&id.to_string()), None).await;

    Ok((StatusCode::CREATED, Json(user.into())))
}

pub(crate) async fn list_users(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<Vec<UserResponse>>, ApiError> {
    require_admin(auth)?;
    let users = app
        .state_store
        .list_users()
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("list users", e))?;
    Ok(Json(users.into_iter().map(Into::into).collect()))
}

pub(crate) async fn get_user(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<UserResponse>, ApiError> {
    require_admin(auth)?;
    let user = app
        .state_store
        .get_user(id)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("get user", e))?
        .ok_or_else(|| ApiError::not_found("user", id))?;
    Ok(Json(user.into()))
}

pub(crate) async fn update_user(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    let ctx = require_admin(auth)?;

    // 全量校验先行：role/status 取值都通过后再落库——纯输入校验错误
    // 不得带部分提交副作用（如 role 已改 + 整体 400）。
    if let Some(role) = req.role.as_deref() {
        validate_role(role)?;
    }
    if let Some(status) = req.status.as_deref() {
        if status != "active" && status != "disabled" {
            return Err(ApiError::Validation(
                "status must be 'active' or 'disabled'".into(),
            ));
        }
    }

    if let Some(role) = req.role.as_deref() {
        // 最后活跃管理员守卫的 Conflict 是业务结果（409），不能压成 500。
        app.state_store
            .set_user_role(id, role)
            .await
            .map_err(|e| conflict_or_internal("set user role", e))?;
    }

    if let Some(status) = req.status.as_deref() {
        app.state_store
            .set_user_status(id, status)
            .await
            .map_err(|e| conflict_or_internal("set user status", e))?;
    }

    let user = app
        .state_store
        .get_user(id)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("get user after update", e))?
        .ok_or_else(|| ApiError::not_found("user", id))?;

    let detail = serde_json::json!({
        "role": req.role,
        "status": req.status,
    })
    .to_string();
    audit_event(
        &app,
        &ctx,
        "update_user",
        Some(&id.to_string()),
        Some(&detail),
    )
    .await;

    Ok(Json(user.into()))
}

pub(crate) async fn disable_user(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<StatusCode, ApiError> {
    let ctx = require_admin(auth)?;

    // 盲 204 → 404：set_user_status 对不存在的 id 是 no-op UPDATE，先确认
    // 用户存在（revoke_token 同款预检；update_user 由收尾 get_user 兜 404）。
    app.state_store
        .get_user(id)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("get user before disable", e))?
        .ok_or_else(|| ApiError::not_found("user", id))?;

    // 禁用最后活跃管理员同样被守卫拦截（409），保持语义透传。
    app.state_store
        .set_user_status(id, "disabled")
        .await
        .map_err(|e| conflict_or_internal("disable user", e))?;

    audit_event(&app, &ctx, "disable_user", Some(&id.to_string()), None).await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub(crate) struct CreateTokenRequest {
    pub name: Option<String>,
    pub expires_in_days: Option<u32>,
}

#[derive(Serialize)]
pub(crate) struct TokenResponse {
    pub id: i64,
    pub token: String,
    pub name: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct TokenListEntry {
    pub id: i64,
    pub name: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl From<UserToken> for TokenListEntry {
    fn from(t: UserToken) -> Self {
        Self {
            id: t.id,
            name: t.name,
            created_at: t.created_at,
            expires_at: t.expires_at,
            revoked_at: t.revoked_at,
        }
    }
}

pub(crate) async fn create_token(
    State(app): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<(StatusCode, Json<TokenResponse>), ApiError> {
    let ctx = require_admin(auth)?;

    let user = app
        .state_store
        .get_user(user_id)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("get user for token", e))?
        .ok_or_else(|| ApiError::not_found("user", user_id))?;
    if user.status != "active" {
        // 409：user.status 是资源状态前置（目标用户存在但状态冲突），非请求
        // 参数错误。
        return Err(ApiError::Conflict(
            "cannot create token for disabled user".into(),
        ));
    }

    // 上限 3650 天（约 10 年）：防误传/滥用生成近乎永不过期的 token。
    // 校验先行于 Secret::generate（无副作用）：非法请求不消耗一次熵生成。
    const MAX_TOKEN_EXPIRES_IN_DAYS: u32 = 3650;
    if let Some(days) = req.expires_in_days {
        if days > MAX_TOKEN_EXPIRES_IN_DAYS {
            return Err(ApiError::Validation(format!(
                "expires_in_days must be at most {MAX_TOKEN_EXPIRES_IN_DAYS} days"
            )));
        }
    }

    let secret = Secret::generate(SecretKind::UserToken)
        .map_err(|e| ApiError::log_and_internal_with_context("generate token", e))?;
    let hash = SecretHash::from_plain(secret.as_str());
    let expires_at = req
        .expires_in_days
        .map(|days| (chrono::Utc::now() + chrono::Duration::days(days as i64)).to_rfc3339());

    let id = app
        .state_store
        .create_user_token(
            user_id,
            req.name.as_deref(),
            hash.as_str(),
            expires_at.as_deref(),
        )
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("create user token", e))?;

    let detail = serde_json::json!({
        "user_id": user_id,
        "name": req.name,
        "expires_in_days": req.expires_in_days,
    })
    .to_string();
    audit_event(
        &app,
        &ctx,
        "create_user_token",
        Some(&id.to_string()),
        Some(&detail),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(TokenResponse {
            id,
            token: secret.as_str().to_string(),
            name: req.name,
            expires_at,
        }),
    ))
}

pub(crate) async fn list_tokens(
    State(app): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<Vec<TokenListEntry>>, ApiError> {
    require_admin(auth)?;

    let tokens = app
        .state_store
        .list_user_tokens(user_id)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("list user tokens", e))?;
    Ok(Json(tokens.into_iter().map(Into::into).collect()))
}

pub(crate) async fn revoke_token(
    State(app): State<Arc<AppState>>,
    Path((user_id, token_id)): Path<(i64, i64)>,
    auth: Option<Extension<AuthContext>>,
) -> Result<StatusCode, ApiError> {
    let ctx = require_admin(auth)?;

    // 校验 token 确实属于该用户，避免跨用户误操作。
    let token = app
        .state_store
        .list_user_tokens(user_id)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("list user tokens", e))?
        .into_iter()
        .find(|t| t.id == token_id)
        .ok_or_else(|| ApiError::not_found("token", token_id))?;

    app.state_store
        .revoke_user_token(token.id)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("revoke user token", e))?;

    audit_event(
        &app,
        &ctx,
        "revoke_user_token",
        Some(&token_id.to_string()),
        Some(&user_id.to_string()),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub(crate) struct GrantAclRequest {
    pub user_id: i64,
}

#[derive(Serialize)]
pub(crate) struct AclUserResponse {
    pub id: i64,
    pub name: String,
    pub role: String,
}

impl From<User> for AclUserResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            name: u.name,
            role: u.role,
        }
    }
}

pub(crate) async fn grant_acl(
    State(app): State<Arc<AppState>>,
    Path(product): Path<String>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<GrantAclRequest>,
) -> Result<StatusCode, ApiError> {
    let ctx = require_admin(auth)?;
    validate_product_name(&product)?;

    let target_user = app
        .state_store
        .get_user(req.user_id)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("get user for acl", e))?
        .ok_or_else(|| ApiError::Validation(format!("user id {} does not exist", req.user_id)))?;

    if target_user.status != "active" {
        // 409：user.status 资源状态前置（同 create_token 的 disabled user
        // 守卫，400→409 同族收口），非请求参数错误。
        return Err(ApiError::Conflict(format!(
            "user '{}' is not active (status: {}); cannot grant ACL",
            target_user.name, target_user.status
        )));
    }

    app.state_store
        .grant_product_acl(req.user_id, &product)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("grant product acl", e))?;

    let detail =
        serde_json::json!({ "user_id": req.user_id, "user_name": target_user.name }).to_string();
    audit_event(
        &app,
        &ctx,
        "grant_product_acl",
        Some(&product),
        Some(&detail),
    )
    .await;

    // 204 而非 201：底层是幂等 upsert（ON CONFLICT(product_id,user_id)
    // DO UPDATE SET role，见 sql::INSERT_PRODUCT_ACL），重复授予不是创建
    // 新资源、也没有新 id 可回填。
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn list_acl(
    State(app): State<Arc<AppState>>,
    Path(product): Path<String>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<Vec<AclUserResponse>>, ApiError> {
    require_admin(auth)?;
    validate_product_name(&product)?;

    let users = app
        .state_store
        .list_users_by_product(&product)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("list users by product", e))?;
    Ok(Json(users.into_iter().map(Into::into).collect()))
}

pub(crate) async fn revoke_acl(
    State(app): State<Arc<AppState>>,
    Path((product, user_id)): Path<(String, i64)>,
    auth: Option<Extension<AuthContext>>,
) -> Result<StatusCode, ApiError> {
    let ctx = require_admin(auth)?;
    validate_product_name(&product)?;

    let granted = app
        .state_store
        .is_product_acl_granted(user_id, &product)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("check product acl", e))?;
    if !granted {
        return Err(ApiError::not_found(
            "product acl",
            format!("{product}#{user_id}"),
        ));
    }

    app.state_store
        .revoke_product_acl(user_id, &product)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("revoke product acl", e))?;

    let detail = serde_json::json!({ "user_id": user_id }).to_string();
    audit_event(
        &app,
        &ctx,
        "revoke_product_acl",
        Some(&product),
        Some(&detail),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

// ======== 远程重建 base_os ========

#[derive(Deserialize)]
pub(crate) struct InitRequest {
    product: String,
}

/// 远程重建指定 Worker 上的 base_os。
///
/// 仅 admin。building 保护采用 per-product 粒度：仅当该 worker 上目标 product 有
/// 在途构建时才返回 409，其它 product 的构建不受影响。init 期间由 dispatch 层
/// 通过 has_active_init(worker, product) 阻止向该 (worker, product) 派新任务，
/// init 不修改 worker 的整体 status。
pub(crate) async fn init_worker(
    State(app): State<Arc<AppState>>,
    Path(worker_id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<InitRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let ctx = require_admin(auth)?;
    validate_product_name(&req.product)?;

    // 确认 worker 存在且在线
    let worker = app
        .state_store
        .get_worker(worker_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("worker", worker_id))?;
    if worker.status == "offline" {
        // offline 是资源状态冲突而非请求参数问题 → 409（同语义端点
        // product init / gc 均以 202/409 表达异步受理与冲突）。
        return Err(ApiError::Conflict(format!(
            "worker {} is offline, cannot init",
            worker_id
        )));
    }

    // arch 门禁与 UI 入口共用（见 worker::admin::ensure_init_arch_compatible）。
    if let Err(mismatch) = crate::server::worker::admin::ensure_init_arch_compatible(
        &app,
        worker_id,
        &worker.arch,
        &req.product,
    )
    .await
    {
        return Err(ApiError::Conflict(format!(
            "worker {} (arch '{}') does not support product '{}' arches {:?}",
            worker_id, mismatch.worker_arch, req.product, mismatch.arches
        )));
    }

    // per-product building 保护 + 重复 init 检查，在事务内原子完成。
    match app
        .state_store
        .try_assign_init_to_worker(worker_id, &req.product)
        .await
        .map_err(ApiError::from)?
    {
        Ok(assignment_id) => {
            // 通知 worker 立即拉取
            crate::server::worker::dispatch::notify_workers(&app, Some(worker_id)).await;

            let detail = serde_json::json!({
                "worker_id": worker_id,
                "worker_name": worker.name,
                "product": req.product,
                "assignment_id": assignment_id,
            })
            .to_string();
            audit_event(&app, &ctx, "init_base_os", Some(&worker_id.to_string()), Some(&detail))
                .await;

            tracing::info!(
                worker_id = %worker_id,
                worker_name = %worker.name,
                product = %req.product,
                assignment_id = %assignment_id,
                user = %ctx.user,
                "Init base_os dispatched"
            );

            // 异步受理（派发后由 worker 执行）→ 202，与 product init / gc
            // 同语义端点口径一致。
            Ok((
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "status": "dispatched",
                    "assignment_id": assignment_id,
                    "worker_id": worker_id,
                    "product": req.product,
                })),
            ))
        }
        Err(InitConflict::Building(n)) => Err(ApiError::Conflict(format!(
            "worker {} has {} building build(s) for product {}; wait for completion or cancel before init",
            worker_id, n, req.product
        ))),
        Err(InitConflict::AlreadyActive) => Err(ApiError::Conflict(format!(
            "worker {} already has an active init assignment for product {}",
            worker_id, req.product
        ))),
    }
}

/// `POST /api/v1/admin/products/{product}/rebuild-repo`
///
/// 管理员触发某产品发布 repo 的对账式全量重建（兜底收敛）。同步执行：撞
/// `.repodata-{arch}.lock` 超时等失败归属操作员，转 500 提示可重试。
pub(crate) async fn rebuild_repo(
    State(app): State<Arc<AppState>>,
    Path(product): Path<String>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ctx = require_admin(auth)?;
    validate_product_name(&product)?;

    // 产品存在性预检：不存在的产品直接 404（对齐 UI 版同款）。没有预检时
    // assemble 对双空集返回 Ok = 静默 200 空 arches 报告；regen 侧 NotFound
    // 哨兵经 log_and_internal_with_context 会折叠成 500。
    match app.state_store.get_product_by_name(&product).await {
        Ok(Some(_)) => {}
        Ok(None) => return Err(ApiError::not_found("product", &product)),
        Err(e) => {
            return Err(ApiError::log_and_internal_with_context("load product", e));
        }
    }

    let report = crate::server::repo_regen::assemble_for_product(&app, &product)
        .await
        .map_err(|e| match e {
            // 预检与 assemble 之间产品被删除的窄竞态兜底：同款 404。
            CrbsError::NotFound { .. } => ApiError::not_found("product", &product),
            other => ApiError::log_and_internal_with_context("rebuild product repo", other),
        })?;

    let detail = serde_json::json!({
        "product": product,
        "arches": report.arches,
        "linked": report.linked,
        "unlinked": report.unlinked,
    })
    .to_string();
    audit_event(&app, &ctx, "rebuild_repo", Some(&product), Some(&detail)).await;

    tracing::info!(
        product = %product,
        arches = ?report.arches,
        linked = report.linked,
        unlinked = report.unlinked,
        user = %ctx.user,
        "Product repo rebuilt via admin command"
    );

    Ok(Json(serde_json::json!({
        "status": "rebuilt",
        "product": product,
        "arches": report.arches,
        "linked": report.linked,
        "unlinked": report.unlinked,
        "skipped_missing": report.skipped_missing,
        "skipped_exdev": report.skipped_exdev,
        "skipped_other": report.skipped_other,
    })))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::server::state::AppState;
    use crbs_core::config::ServerConfig;
    use crbs_core::StateStore;

    #[test]
    fn validate_role_accepts_known_roles() {
        for role in ["admin", "operator", "builder", "viewer"] {
            assert!(validate_role(role).is_ok());
        }
    }

    #[test]
    fn validate_role_rejects_unknown() {
        assert!(validate_role("hacker").is_err());
    }

    fn admin_ctx() -> AuthContext {
        AuthContext {
            user: "admin".into(),
            role: "admin".into(),
            ..Default::default()
        }
    }

    async fn test_app_state() -> (Arc<AppState>, Arc<StateStore>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let app_state = Arc::new(AppState::for_test(
            store.clone(),
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        (app_state, store, tmp)
    }

    async fn create_test_product(store: &crbs_core::StateStore, name: &str) {
        store
            .create_product(crbs_core::CreateProductInput {
                name,
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: "public",
                config: &crbs_core::config::ProductConfig::default(),
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();
    }

    /// 带 arches 的产品：必须同时给 base_packages/repos，否则 chain-resolve
    /// 出口校验拒绝、arch 门禁走 fail-open 兜底，测不到 membership 判定。
    async fn create_test_product_with_arches(
        store: &crbs_core::StateStore,
        name: &str,
        arches_toml: &str,
    ) {
        let config = crbs_core::config::ProductConfig::from_str(&format!(
            "base_packages = [\"bash\"]\narches = {arches_toml}\n\n[[repos]]\n\
             name = \"base\"\nbaseurl = \"http://example.com/base/$basearch\"\n\
             gpgcheck = false\n"
        ))
        .unwrap();
        store
            .create_product(crbs_core::CreateProductInput {
                name,
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: "public",
                config: &config,
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn grant_acl_rejects_disabled_user() {
        let (app_state, store, _tmp) = test_app_state().await;
        let user_id = store.create_user("bob", "builder").await.unwrap();
        store.set_user_status(user_id, "disabled").await.unwrap();
        create_test_product(&store, "fedora").await;

        let result = grant_acl(
            State(app_state),
            Path("fedora".to_string()),
            Some(Extension(admin_ctx())),
            Json(GrantAclRequest { user_id }),
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        // 400→409：status 前置是资源状态冲突，钉 Conflict 防 400 回归。
        assert!(
            matches!(err, ApiError::Conflict(ref msg) if msg.contains("not active")),
            "expected Conflict, got: {err:?}"
        );
    }

    /// 400→409：为 disabled 用户创建 token 是资源状态前置冲突（409），
    /// 非请求参数错误（400）；与 grant_acl 的 not-active 守卫同族。
    #[tokio::test]
    async fn create_token_rejects_disabled_user_with_conflict() {
        let (app_state, store, _tmp) = test_app_state().await;
        let user_id = store.create_user("dave", "builder").await.unwrap();
        store.set_user_status(user_id, "disabled").await.unwrap();

        let result = create_token(
            State(app_state),
            Path(user_id),
            Some(Extension(admin_ctx())),
            Json(CreateTokenRequest {
                name: None,
                expires_in_days: None,
            }),
        )
        .await;

        match result {
            Err(ApiError::Conflict(msg)) => {
                assert!(msg.contains("disabled user"), "unexpected error: {msg}");
            }
            other => panic!("expected Conflict, got {:?}", other.err()),
        }
    }

    #[tokio::test]
    async fn revoke_acl_returns_not_found_when_not_granted() {
        let (app_state, store, _tmp) = test_app_state().await;
        let user_id = store.create_user("bob", "builder").await.unwrap();
        create_test_product(&store, "fedora").await;

        let result = revoke_acl(
            State(app_state),
            Path(("fedora".to_string(), user_id)),
            Some(Extension(admin_ctx())),
        )
        .await;

        assert!(matches!(result, Err(ApiError::NotFound(_))));
    }

    #[tokio::test]
    async fn revoke_acl_succeeds_when_granted() {
        let (app_state, store, _tmp) = test_app_state().await;
        let user_id = store.create_user("bob", "builder").await.unwrap();
        create_test_product(&store, "fedora").await;
        store.grant_product_acl(user_id, "fedora").await.unwrap();

        let result = revoke_acl(
            State(app_state),
            Path(("fedora".to_string(), user_id)),
            Some(Extension(admin_ctx())),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), StatusCode::NO_CONTENT);
    }

    /// expires_in_days 超过 3650 上限被 400 拒绝，上限内正常签发。
    #[tokio::test]
    async fn create_token_caps_expires_in_days() {
        let (app_state, store, _tmp) = test_app_state().await;
        let user_id = store.create_user("alice", "builder").await.unwrap();

        let result = create_token(
            State(app_state.clone()),
            Path(user_id),
            Some(Extension(admin_ctx())),
            Json(CreateTokenRequest {
                name: None,
                expires_in_days: Some(3651),
            }),
        )
        .await;
        assert!(
            matches!(result, Err(ApiError::Validation(_))),
            "expires_in_days > 3650 must be rejected"
        );

        let result = create_token(
            State(app_state),
            Path(user_id),
            Some(Extension(admin_ctx())),
            Json(CreateTokenRequest {
                name: None,
                expires_in_days: Some(3650),
            }),
        )
        .await;
        assert!(
            result.is_ok(),
            "3650 days must pass, got {:?}",
            result.err()
        );
    }

    /// role 合法 + status 非法 → 400 且 role **未落库**（校验全量前置，
    /// 纯输入错误不得带部分提交副作用）。
    #[tokio::test]
    async fn update_user_invalid_status_leaves_role_unchanged() {
        let (app_state, store, _tmp) = test_app_state().await;
        let user_id = store.create_user("carol", "builder").await.unwrap();

        let result = update_user(
            State(app_state),
            Path(user_id),
            Some(Extension(admin_ctx())),
            Json(UpdateUserRequest {
                role: Some("operator".into()),
                status: Some("bogus".into()),
            }),
        )
        .await;

        assert!(
            matches!(result, Err(ApiError::Validation(_))),
            "invalid status must be rejected"
        );
        let user = store.get_user(user_id).await.unwrap().unwrap();
        assert_eq!(
            user.role, "builder",
            "role must not be committed when status validation fails"
        );
    }

    // 制造一个 building 状态的 build 及其对应的 running worker_tasks 行，
    // 用于 init gating 的测试。
    async fn seed_building(store: &crbs_core::StateStore, worker_id: i64, product: &str) {
        use crbs_core::BuildInsert;
        let task_id = crate::test_support::seed_task(store, product, "pkg").await;
        let build_id = store
            .insert_build(BuildInsert {
                product,
                pkg_name: "pkg",
                backend: "chroot",
                user: "test",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .assign_build_to_worker(build_id, worker_id)
            .await
            .unwrap();
        sqlx::query("UPDATE builds SET phase = 'building' WHERE id = ?")
            .bind(build_id)
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE worker_tasks SET status = 'running' WHERE build_id = ?")
            .bind(build_id)
            .execute(store.pool())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn init_worker_rejects_when_target_product_is_building() {
        let (app_state, store, _tmp) = test_app_state().await;
        let worker_id = store
            .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
            .await
            .unwrap();
        seed_building(&store, worker_id, "mydist").await;

        let result = init_worker(
            State(app_state),
            Path(worker_id),
            Some(Extension(admin_ctx())),
            Json(InitRequest {
                product: "mydist".into(),
            }),
        )
        .await;

        match result {
            Err(ApiError::Conflict(msg)) => {
                assert!(
                    msg.contains("mydist"),
                    "expected product in message: {}",
                    msg
                );
            }
            other => panic!("expected Conflict, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn init_worker_allows_other_product_when_building_a_different_one() {
        let (app_state, store, _tmp) = test_app_state().await;
        let worker_id = store
            .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
            .await
            .unwrap();
        // worker 正在为 fedora 构建；不应阻塞 mydist 的 init。
        seed_building(&store, worker_id, "fedora").await;

        let result = init_worker(
            State(app_state.clone()),
            Path(worker_id),
            Some(Extension(admin_ctx())),
            Json(InitRequest {
                product: "mydist".into(),
            }),
        )
        .await;

        let (status, _body) = result.expect("init for a non-building product should be accepted");
        // 异步受理 → 202 ACCEPTED（与 product init / gc 同语义端点一致）。
        assert_eq!(status, StatusCode::ACCEPTED);

        // 断言 init 期间 worker.status 未被改动（init 只按 (worker, product)
        // 粒度暂停派发，不切换整机状态）。
        let worker = store.get_worker(worker_id).await.unwrap().unwrap();
        assert_eq!(worker.status, "online");

        // 断言 has_active_init 已生效，供 dispatch gating 使用。
        assert!(store.has_active_init(worker_id, "mydist").await.unwrap());
    }

    /// arch 门禁：worker arch 不在产品声明 arches 内 → 409，消息带 worker
    /// arch 与产品 arches（`-w` 路径据此直接可读）；assignment 不落库。
    #[tokio::test]
    async fn init_worker_rejects_arch_mismatch_with_conflict() {
        let (app_state, store, _tmp) = test_app_state().await;
        let worker_id = store
            .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
            .await
            .unwrap();
        create_test_product_with_arches(&store, "mydist", "[\"aarch64\"]").await;

        let result = init_worker(
            State(app_state),
            Path(worker_id),
            Some(Extension(admin_ctx())),
            Json(InitRequest {
                product: "mydist".into(),
            }),
        )
        .await;

        match result {
            Err(ApiError::Conflict(msg)) => {
                assert!(
                    msg.contains("x86_64") && msg.contains("mydist") && msg.contains("aarch64"),
                    "expected arch detail in message: {msg}"
                );
            }
            other => panic!("expected Conflict, got {:?}", other),
        }
        assert!(
            !store.has_active_init(worker_id, "mydist").await.unwrap(),
            "rejected init must not leave an active assignment"
        );
    }

    /// arch 门禁放行：worker arch 在产品 arches 内 → 202 正常受理。
    #[tokio::test]
    async fn init_worker_accepts_matching_arch() {
        let (app_state, store, _tmp) = test_app_state().await;
        let worker_id = store
            .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
            .await
            .unwrap();
        create_test_product_with_arches(&store, "mydist", "[\"x86_64\", \"aarch64\"]").await;

        let result = init_worker(
            State(app_state),
            Path(worker_id),
            Some(Extension(admin_ctx())),
            Json(InitRequest {
                product: "mydist".into(),
            }),
        )
        .await;

        let (status, _body) = result.expect("matching arch must be accepted");
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    /// 产品未声明 arches（空列表）→ 门禁 fail-open，保持既有受理行为。
    #[tokio::test]
    async fn init_worker_skips_arch_gate_when_product_declares_no_arches() {
        let (app_state, store, _tmp) = test_app_state().await;
        let worker_id = store
            .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
            .await
            .unwrap();
        create_test_product_with_arches(&store, "mydist", "[]").await;

        let result = init_worker(
            State(app_state),
            Path(worker_id),
            Some(Extension(admin_ctx())),
            Json(InitRequest {
                product: "mydist".into(),
            }),
        )
        .await;

        let (status, _body) = result.expect("no declared arches must not block init");
        assert_eq!(status, StatusCode::ACCEPTED);
    }
}
