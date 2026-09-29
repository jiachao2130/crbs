// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产品管理端点：CRUD + 初始化/清理。
//!
//! - `POST/PUT/DELETE /api/v1/products[/{name}]` admin-only CRUD；`GET` 按
//!   visibility + owner ACL 过滤；
//! - `POST .../init` / `POST .../clean` 为异步 BuildEngine 任务；clean 只清
//!   磁盘产物，删 DB 行走 `DELETE /{name}`。

use std::sync::Arc;

use axum::extract::{Extension, Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::server::auth::visibility::{
    check_chain_visibility, is_owner_or_admin, is_product_content_visible_to,
};
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::warn_audit_log_failure;
use crate::server::state::{AppState, ProductTask, ProductTaskStatus};
use crate::server::validation::{validate_product_name, validate_product_name_for_write};
use crbs_core::config::{ProductConfig, ProductDetail};
use crbs_core::error::CrbsError;
use crbs_core::DbResultExt;
use crbs_core::{
    CreateProductInput, ProductConfigHistoryEntry, ProductRecord, ProductStub, UpdateOutcome,
};

/// 写前校验，与加载期同规则：按链合并后的生效值判定（deterministic 链上 OR、build_target/dnf_cache_enabled 默认继承父层），
/// 坏组合落库会在下一次加载时 500 自锁，提前拦为 400。
async fn validate_gpg_preconditions_for_write(
    app: &AppState,
    parent_id: Option<i64>,
    config: &ProductConfig,
) -> Result<(), ApiError> {
    let effective = app
        .state_store
        .effective_config_for_write(parent_id, config)
        .await?;
    let build_target = effective
        .build_target
        .clone()
        .unwrap_or_else(|| app.crbs_config.build_target.clone());
    crbs_core::config::validation::validate_deterministic_preconditions(
        effective.deterministic,
        &build_target,
        effective
            .dnf_cache_enabled
            .unwrap_or(app.crbs_config.dnf_cache_enabled),
    )
    .map_err(ApiError::from)
}

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/products", get(list_products).post(create_product))
        .route(
            "/api/v1/products/{name}",
            get(get_product).put(update_product).delete(delete_product),
        )
        .route("/api/v1/products/{name}/init", post(init_product))
        .route("/api/v1/products/{name}/clean", post(clean_product))
        .route(
            "/api/v1/products/{name}/resolved",
            get(get_product_resolved),
        )
        .route("/api/v1/products/{name}/history", get(list_product_history))
        .route(
            "/api/v1/products/{name}/history/{revision}",
            get(get_product_history_revision),
        )
        .route("/api/v1/products/tasks/{id}", get(get_product_task_status))
        .route(
            "/api/v1/products/{name}/acl",
            get(list_product_acl)
                .post(grant_product_acl)
                .delete(revoke_product_acl),
        )
        .route(
            "/api/v1/products/{name}/visibility",
            post(update_product_visibility),
        )
        .route(
            "/api/v1/products/{name}/transfer",
            post(transfer_product_ownership),
        )
}

#[derive(Deserialize, Default)]
pub(crate) struct InitRequest {
    #[serde(default)]
    pub force: bool,
}

#[derive(Serialize)]
pub(crate) struct ProductTaskResponse {
    pub task_id: String,
    pub status: &'static str,
    pub product: String,
    pub op: &'static str,
}

#[derive(Serialize)]
pub(crate) struct ProductTaskStatusResponse {
    pub task_id: String,
    pub status: &'static str,
    pub product: String,
    pub op: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

/// `POST /api/v1/products` 请求体：`visibility` 缺省为 `"public"`（官方产品，
/// owner_id 为 NULL，与 schema CHECK 口径一致）；`reason` 记入 history 供
/// 审计。
#[derive(Deserialize)]
pub(crate) struct CreateProductBody {
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub parent_id: Option<i64>,
    #[serde(default)]
    pub visibility: Option<String>,
    pub config: ProductConfig,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct CreateProductResponse {
    pub id: i64,
    pub name: String,
    pub revision: i64,
    pub base_os_revision: i64,
}

/// `PUT /api/v1/products/{name}` 请求体：`expected_revision` 必填，拒绝盲
/// 写。`parent_id` 为三态语义（`Option<Option<i64>>`）：字段缺席表示不改
/// parent；`null` 表示脱离父链成为根产品；数值表示挂到新父产品并走写路径
/// 校验。服务端执行顺序为先更新 config（expected_revision 乐观锁），再执
/// 行 re-parent——后者以 config 更新产生的新 revision 为门，乐观锁契约覆
/// 盖复合写全程；任一步失败即返回，响应中的 revision 取最终值。
#[derive(Deserialize)]
pub(crate) struct UpdateProductBody {
    pub expected_revision: i64,
    pub config: ProductConfig,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_option_i64")]
    pub parent_id: Option<Option<i64>>,
}

fn deserialize_optional_option_i64<'de, D>(deserializer: D) -> Result<Option<Option<i64>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<i64>::deserialize(deserializer).map(Some)
}

#[derive(Serialize)]
pub(crate) struct UpdateProductResponse {
    pub revision: i64,
    pub base_os_revision: i64,
    pub base_os_bumped: bool,
}

impl From<UpdateOutcome> for UpdateProductResponse {
    fn from(o: UpdateOutcome) -> Self {
        Self {
            revision: o.revision,
            base_os_revision: o.base_os_revision,
            base_os_bumped: o.base_os_bumped,
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct ProductAclRequest {
    pub username: String,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct UpdateVisibilityRequest {
    pub visibility: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub expected_revision: i64,
}

#[derive(Deserialize)]
pub(crate) struct TransferOwnershipRequest {
    pub new_owner_username: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub expected_revision: i64,
}

#[derive(Serialize)]
pub(crate) struct ProductAclEntry {
    pub user_id: i64,
    pub username: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub(crate) struct ProductHistoryEntryDto {
    pub revision: i64,
    pub base_os_revision: i64,
    pub config: serde_json::Value,
    pub changed_by_user_id: Option<i64>,
    pub changed_at: String,
    pub reason: Option<String>,
}

impl TryFrom<ProductConfigHistoryEntry> for ProductHistoryEntryDto {
    type Error = CrbsError;

    fn try_from(e: ProductConfigHistoryEntry) -> Result<Self, Self::Error> {
        let config: serde_json::Value = serde_json::from_str(&e.config_json).db_ctx(&format!(
            "parse history config_json (product_id={}, revision={})",
            e.product_id, e.revision
        ))?;
        Ok(Self {
            revision: e.revision,
            base_os_revision: e.base_os_revision,
            config,
            changed_by_user_id: e.changed_by_user_id,
            changed_at: e.changed_at,
            reason: e.reason,
        })
    }
}

fn check_product_management(app: &AppState) -> Result<(), ApiError> {
    if !app.allow_product_management {
        return Err(ApiError::PermissionDenied(
            "product management is disabled".into(),
        ));
    }
    Ok(())
}

fn require_admin(auth: Option<&AuthContext>, op: &str) -> Result<(), ApiError> {
    if let Some(ctx) = auth {
        if !ctx.can_manage_product() {
            return Err(ApiError::PermissionDenied(format!("only admin can {}", op)));
        }
    } else {
        return Err(ApiError::Unauthorized(format!(
            "authentication required to {}",
            op
        )));
    }
    Ok(())
}

fn require_builder(auth: Option<&AuthContext>, op: &str) -> Result<(), ApiError> {
    if let Some(ctx) = auth {
        if !ctx.is_builder() {
            return Err(ApiError::PermissionDenied(format!(
                "only builder or above can {}",
                op
            )));
        }
    } else {
        return Err(ApiError::Unauthorized(format!(
            "authentication required to {}",
            op
        )));
    }
    Ok(())
}

/// 单调性校验（create / update re-parent 共用）：public 产品不能挂含 private 祖先的链——否则 outsider 经 public child 的
/// chain_resolve 可遍历到 private ancestor 的 name；admin 也不豁免。
async fn ensure_no_private_ancestor(app: &AppState, parent_id: i64) -> Result<(), ApiError> {
    let mut cursor = Some(parent_id);
    let mut visited = std::collections::HashSet::new();
    while let Some(ancestor_id) = cursor {
        if !visited.insert(ancestor_id) || visited.len() >= 8 {
            break;
        }
        let ancestor = app
            .state_store
            .get_product_by_id(ancestor_id)
            .await?
            .ok_or_else(|| ApiError::not_found("product", ancestor_id))?;
        if ancestor.visibility != crbs_core::VISIBILITY_PUBLIC {
            return Err(ApiError::Conflict(format!(
                "public product cannot attach to private ancestor '{}'; unpublish first",
                ancestor.name
            )));
        }
        cursor = ancestor.parent_id;
    }
    Ok(())
}

/// 列出当前请求者可见的产品名；出参保持 `Vec<String>` 形状以兼容 CLI 与
/// UI。
pub(crate) async fn list_products(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<Vec<String>>, ApiError> {
    let stubs: Vec<ProductStub> = app.state_store.list_products().await?;
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);
    let mut names: Vec<String> = stubs
        .into_iter()
        .filter(|s| is_product_content_visible_to(s.owner_id, &s.visibility, &s.name, auth_ref))
        .map(|s| s.name)
        .collect();
    names.sort();
    Ok(Json(names))
}

/// 查看单个产品的合并后配置详情（product 层 + CrbsConfig + server 覆盖）。
/// 访问控制：public 产品或认证后的 admin/owner；不可见一律返回 404，不区
/// 分"不存在"与"无权限"，避免存在性泄露。
pub(crate) async fn get_product(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<ProductDetail>, ApiError> {
    validate_product_name(&name)?;

    let record = load_visible_record(&app, &name, auth.as_ref()).await?;
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);

    check_chain_visibility(&app, record.id, auth_ref).await?;

    let cfg = app
        .state_store
        .load_merged_config_for_product_by_id(record.id, &name)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("load product config", e))?;

    let parent_name = match record.parent_id {
        Some(pid) => app
            .state_store
            .get_product_by_id(pid)
            .await?
            .map(|p| p.name),
        None => None,
    };
    let mut detail =
        ProductDetail::from(cfg).with_graph_meta(Some(record.id), record.parent_id, parent_name);
    app.apply_display_paths(&mut detail, &name).await;
    Ok(Json(detail.with_revision(record.revision)))
}

/// 返回该产品链解析后的 TOML（content-type 为 application/toml），作为磁
/// 盘同步桥：CLI 本地命令（build/reproduce/sign 等）仍读取磁盘 TOML，运维
/// 以 `crbs products export <name> --remote <profile>` 将 hub DB 的权威配
/// 置写回本地，防止两端漂移。访问控制同 [`get_product`]。
pub(crate) async fn get_product_resolved(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Response, ApiError> {
    validate_product_name(&name)?;
    let record = load_visible_record(&app, &name, auth.as_ref()).await?;
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);

    check_chain_visibility(&app, record.id, auth_ref).await?;
    let toml = app.state_store.chain_resolve_to_toml(record.id).await?;

    let body: String = (*toml).clone();
    let mut resp = body.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/toml; charset=utf-8"),
    );

    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(resp)
}

/// 列出该产品的全部历史版本（按 revision 降序）。history 仅保存本层
/// config_json、按本产品 id 查表，不做链可见性检查。
pub(crate) async fn list_product_history(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<Vec<ProductHistoryEntryDto>>, ApiError> {
    validate_product_name(&name)?;
    let record = load_visible_record(&app, &name, auth.as_ref()).await?;
    let entries = app.state_store.list_product_history(record.id).await?;
    let dto = entries
        .into_iter()
        .map(ProductHistoryEntryDto::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(dto))
}

/// 读取该产品指定 revision 的历史快照（同 [`list_product_history`]：仅本
/// 层 config_json，不做链可见性检查）。
pub(crate) async fn get_product_history_revision(
    State(app): State<Arc<AppState>>,
    Path((name, revision)): Path<(String, i64)>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<ProductHistoryEntryDto>, ApiError> {
    validate_product_name(&name)?;
    let record = load_visible_record(&app, &name, auth.as_ref()).await?;
    match app
        .state_store
        .get_product_history_revision(record.id, revision)
        .await?
    {
        Some(entry) => Ok(Json(ProductHistoryEntryDto::try_from(entry)?)),
        None => Err(ApiError::not_found(
            "product history revision",
            format!("{name}#{revision}"),
        )),
    }
}

async fn load_visible_record(
    app: &AppState,
    name: &str,
    auth: Option<&Extension<AuthContext>>,
) -> Result<ProductRecord, ApiError> {
    let record = match app.state_store.get_product_by_name(name).await? {
        Some(r) => r,
        None => return Err(ApiError::not_found("product", name)),
    };
    let ctx_ref = auth.map(|Extension(ctx)| ctx);
    if !is_product_content_visible_to(record.owner_id, &record.visibility, &record.name, ctx_ref) {
        return Err(ApiError::not_found("product", name));
    }
    Ok(record)
}

/// 管理端点（update/delete/acl/publish/transfer 族）与 UI 编辑页的产品装
/// 载：按名取行并做 owner/admin 判定，任一不满足即返回同名 404，不泄露存
/// 在性。产品名校验由调用方按各自口径执行（create 严格、URL 宽松），本函
/// 数不重复校验。
pub(crate) async fn load_record_for_owner_or_admin(
    app: &AppState,
    name: &str,
    auth: Option<&AuthContext>,
) -> Result<ProductRecord, ApiError> {
    let record = match app.state_store.get_product_by_name(name).await? {
        Some(r) => r,
        None => return Err(ApiError::not_found("product", name)),
    };
    if !is_owner_or_admin(record.owner_id, auth) {
        return Err(ApiError::not_found("product", name));
    }
    Ok(record)
}

/// 创建产品：写 products 行并生成 revision=1 的 history 快照。name 冲突返
/// 回 409，名字非法返回 400，角色不足返回 403。admin 可创建官方产品
/// （owner_id 为 NULL、visibility 为 public）或私人产品；builder 仅能创建
/// 私人产品（owner_id 为自身）。
pub(crate) async fn create_product(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<CreateProductBody>,
) -> Result<(StatusCode, Json<CreateProductResponse>), ApiError> {
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);
    require_builder(auth_ref, "create products")?;

    validate_product_name_for_write(&req.name)?;

    let is_admin = auth_ref.map(|c| c.is_admin()).unwrap_or(false);
    let (owner_id, visibility) = if is_admin {
        let vis = req
            .visibility
            .as_deref()
            .unwrap_or(crbs_core::VISIBILITY_PUBLIC);
        let owner_id = if vis == crbs_core::VISIBILITY_PUBLIC {
            None
        } else {
            auth_ref.and_then(|c| c.user_id)
        };
        (owner_id, vis)
    } else {
        if req.visibility.is_some()
            && req.visibility.as_deref() != Some(crbs_core::VISIBILITY_PRIVATE)
        {
            return Err(ApiError::Validation(
                "only admin can set non-private visibility".into(),
            ));
        }
        let owner_id = auth_ref
            .and_then(|c| c.user_id)
            .ok_or_else(|| ApiError::PermissionDenied("builder requires user_id".into()))?;
        (Some(owner_id), crbs_core::VISIBILITY_PRIVATE)
    };

    if let Some(pid) = req.parent_id {
        let parent = app
            .state_store
            .get_product_by_id(pid)
            .await?
            .ok_or_else(|| ApiError::not_found("product", pid))?;
        if !is_product_content_visible_to(
            parent.owner_id,
            &parent.visibility,
            &parent.name,
            auth_ref,
        ) {
            return Err(ApiError::not_found("product", pid));
        }

        if visibility == crbs_core::VISIBILITY_PUBLIC {
            ensure_no_private_ancestor(&app, pid).await?;
        }
    }

    validate_gpg_preconditions_for_write(app.as_ref(), req.parent_id, &req.config).await?;

    let id = app
        .state_store
        .create_product(CreateProductInput {
            name: &req.name,
            display_name: req.display_name.as_deref(),
            owner_id,
            parent_id: req.parent_id,
            visibility,
            config: &req.config,
            changed_by_user_id: auth_ref.and_then(|c| c.user_id),
            reason: req.reason.as_deref(),
        })
        .await?;

    if let Some(ctx) = auth_ref {
        let detail = serde_json::json!({
            "id": id, "visibility": visibility, "parent_id": req.parent_id,
        })
        .to_string();
        if let Err(e) = app
            .state_store
            .audit_log(
                &ctx.user,
                &ctx.role,
                "create_product",
                Some(&req.name),
                Some(&detail),
            )
            .await
        {
            warn_audit_log_failure(&e, "audit_log");
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(CreateProductResponse {
            id,
            name: req.name,
            revision: 1,
            base_os_revision: 1,
        }),
    ))
}

/// 更新产品配置：`expected_revision` 不命中返回 409。携带 `parent_id` 时
/// 在 config 更新之后执行 re-parent，两步各自独立事务、各自推进 revision
/// 并写 history，响应中的 revision 为最终值。权限：admin 拥有全部产品，
/// owner 限自己的私人产品，其余 404。
pub(crate) async fn update_product(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<UpdateProductBody>,
) -> Result<Json<UpdateProductResponse>, ApiError> {
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);

    validate_product_name(&name)?;

    let record = load_record_for_owner_or_admin(&app, &name, auth_ref).await?;

    if let Some(Some(pid)) = req.parent_id {
        let parent = app
            .state_store
            .get_product_by_id(pid)
            .await?
            .ok_or_else(|| ApiError::not_found("product", pid))?;
        if !is_product_content_visible_to(
            parent.owner_id,
            &parent.visibility,
            &parent.name,
            auth_ref,
        ) {
            return Err(ApiError::not_found("product", pid));
        }

        if record.visibility == crbs_core::VISIBILITY_PUBLIC {
            ensure_no_private_ancestor(&app, pid).await?;
        }

        app.state_store
            .validate_parent_id(Some(record.id), pid)
            .await?;
    }

    let effective_parent = req.parent_id.unwrap_or(record.parent_id);
    validate_gpg_preconditions_for_write(app.as_ref(), effective_parent, &req.config).await?;

    let mut outcome = app
        .state_store
        .update_product_config(
            record.id,
            &req.config,
            auth_ref.and_then(|c| c.user_id),
            req.reason.as_deref(),
            Some(req.expected_revision),
        )
        .await?;

    if let Some(new_parent) = req.parent_id {
        outcome = app
            .state_store
            .update_product_parent(
                record.id,
                new_parent,
                auth_ref.and_then(|c| c.user_id),
                req.reason.as_deref(),
                Some(outcome.revision),
            )
            .await?;
    }

    if let Some(ctx) = auth_ref {
        let detail = serde_json::json!({
            "id": record.id,
            "expected_revision": req.expected_revision,
            "new_revision": outcome.revision,
            "base_os_bumped": outcome.base_os_bumped,
            "parent_id_changed": req.parent_id.is_some(),
        })
        .to_string();
        if let Err(e) = app
            .state_store
            .audit_log(
                &ctx.user,
                &ctx.role,
                "update_product",
                Some(&name),
                Some(&detail),
            )
            .await
        {
            warn_audit_log_failure(&e, "audit_log");
        }
    }

    let old_publish = record.config.repo_publish.unwrap_or(true);
    let new_publish = req.config.repo_publish.unwrap_or(true);
    if old_publish != new_publish {
        crate::server::repo_regen::regenerate_product_repo(&app, &name).await;
    }

    Ok(Json(UpdateProductResponse::from(outcome)))
}

/// 删除产品行（FK CASCADE 连带删除 history；缓存清理由 state 层内部处
/// 理）。不触发磁盘产物回收——那是 `POST /{name}/clean` 的职责。权限：
/// admin 拥有全部产品，owner 限自己的私人产品，其余 404（不泄露存在性）。
pub(crate) async fn delete_product(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
) -> Result<StatusCode, ApiError> {
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);
    validate_product_name(&name)?;

    let record = load_record_for_owner_or_admin(&app, &name, auth_ref).await?;

    let result_root = app.result_dir_for_or_default(&name).await;

    let (builds_cancelled, tasks_cancelled) = app.state_store.delete_product(record.id).await?;

    crate::server::repo_regen::remove_product_repo(&result_root, &name).await;

    if let Some(ctx) = auth_ref {
        let detail = serde_json::json!({
            "id": record.id,
            "builds_cancelled": builds_cancelled,
            "tasks_cancelled": tasks_cancelled
        })
        .to_string();
        if let Err(e) = app
            .state_store
            .audit_log(
                &ctx.user,
                &ctx.role,
                "delete_product_row",
                Some(&name),
                Some(&detail),
            )
            .await
        {
            warn_audit_log_failure(&e, "audit_log");
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

fn has_running_product_task(
    tasks: &std::collections::HashMap<String, ProductTask>,
    product: &str,
    op: &str,
) -> bool {
    tasks.values().any(|t| {
        matches!(t.status, ProductTaskStatus::Running) && t.product == product && t.op == op
    })
}

/// 异步初始化产品。
pub(crate) async fn init_product(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<InitRequest>,
) -> Result<(StatusCode, Json<ProductTaskResponse>), ApiError> {
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);
    require_admin(auth_ref, "initialize products")?;
    check_product_management(&app)?;
    validate_product_name(&name)?;

    crbs_core::validation::ensure_product_config_ready(&name).await?;

    let task_id = uuid::Uuid::new_v4().to_string();
    let started_at = chrono::Utc::now();
    let product = name.clone();

    {
        let mut tasks = app.product_tasks.lock().await;
        // 并发 init 去重——同 (product, op) 已有 Running 时 409，不叠加注册
        //（两任务会并发跑 flock 互斥外的同套引擎动作）。
        if has_running_product_task(&tasks, &name, "init") {
            return Err(ApiError::Conflict(format!(
                "product {} already has an active init task",
                name
            )));
        }
        tasks.insert(
            task_id.clone(),
            ProductTask {
                status: ProductTaskStatus::Running,
                product: product.clone(),
                op: "init",
                started_at,
            },
        );
    }

    let product_tasks = app.product_tasks.clone();
    let app_for_engine = app.clone();
    let retention = app
        .server_config
        .product_result_retention
        .unwrap_or(app.server_config.gc_result_retention);
    let log_sanitization = app.server_config.log_sanitization.clone();

    spawn_supervised_product_task(
        product_tasks,
        task_id.clone(),
        product.clone(),
        "init",
        retention,
        async move {
            let engine = crbs_core::engine::BuildEngine::new_with_state_pinned_root(
                &product,
                None,
                None,
                None,
                app_for_engine.state_store.clone(),
                &app_for_engine.crbs_root,
            )
            .await?
            .with_log_sanitization(log_sanitization);

            engine.init(req.force, None, None, false).await?;
            Ok(())
        },
    );

    if let Some(ctx) = auth_ref {
        let detail = serde_json::json!({ "force": req.force }).to_string();
        if let Err(e) = app
            .state_store
            .audit_log(
                &ctx.user,
                &ctx.role,
                "init_product",
                Some(&name),
                Some(&detail),
            )
            .await
        {
            warn_audit_log_failure(&e, "audit_log");
        }
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(ProductTaskResponse {
            task_id,
            status: "running",
            product: name,
            op: "init",
        }),
    ))
}

/// 异步清理磁盘产物，不删除 DB 行——删除产品记录走
/// `DELETE /api/v1/products/{name}`。
pub(crate) async fn clean_product(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
) -> Result<(StatusCode, Json<ProductTaskResponse>), ApiError> {
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);
    require_admin(auth_ref, "clean product artifacts")?;
    check_product_management(&app)?;
    validate_product_name(&name)?;

    let task_id = uuid::Uuid::new_v4().to_string();
    let started_at = chrono::Utc::now();
    let product = name.clone();

    {
        let mut tasks = app.product_tasks.lock().await;

        if has_running_product_task(&tasks, &name, "clean") {
            return Err(ApiError::Conflict(format!(
                "product {} already has an active clean task",
                name
            )));
        }
        tasks.insert(
            task_id.clone(),
            ProductTask {
                status: ProductTaskStatus::Running,
                product: product.clone(),
                op: "clean",
                started_at,
            },
        );
    }

    let product_tasks = app.product_tasks.clone();
    let app_for_engine = app.clone();
    let retention = app
        .server_config
        .product_result_retention
        .unwrap_or(app.server_config.gc_result_retention);
    let log_sanitization = app.server_config.log_sanitization.clone();

    spawn_supervised_product_task(
        product_tasks,
        task_id.clone(),
        product.clone(),
        "clean",
        retention,
        async move {
            let engine = crbs_core::engine::BuildEngine::new_with_state_pinned_root(
                &product,
                None,
                None,
                None,
                app_for_engine.state_store.clone(),
                &app_for_engine.crbs_root,
            )
            .await?
            .with_log_sanitization(log_sanitization);

            engine.clean(false).await?;
            Ok(())
        },
    );

    if let Some(ctx) = auth_ref {
        if let Err(e) = app
            .state_store
            .audit_log(&ctx.user, &ctx.role, "clean_product", Some(&name), None)
            .await
        {
            warn_audit_log_failure(&e, "audit_log");
        }
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(ProductTaskResponse {
            task_id,
            status: "running",
            product: name,
            op: "clean",
        }),
    ))
}

pub(crate) async fn get_product_task_status(
    State(app): State<Arc<AppState>>,
    Path(id): Path<String>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<ProductTaskStatusResponse>, ApiError> {
    if let Some(ctx) = auth.as_ref() {
        if !ctx.is_operator() {
            return Err(ApiError::PermissionDenied(
                "only operator/admin can view product task status".into(),
            ));
        }
    }

    let tasks = app.product_tasks.lock().await;
    let task = tasks
        .get(&id)
        .ok_or_else(|| ApiError::not_found("task", &id))?;

    let (status, error) = match &task.status {
        ProductTaskStatus::Running => ("running", None),
        ProductTaskStatus::Succeeded => ("succeeded", None),
        ProductTaskStatus::Failed(e) => ("failed", Some(e.clone())),
    };

    Ok(Json(ProductTaskStatusResponse {
        task_id: id,
        status,
        product: task.product.clone(),
        op: task.op,
        error,
        started_at: task.started_at,
    }))
}

fn spawn_supervised_product_task(
    product_tasks: Arc<tokio::sync::Mutex<std::collections::HashMap<String, ProductTask>>>,
    task_id: String,
    product: String,
    op: &'static str,
    retention: usize,
    body: impl std::future::Future<Output = crbs_core::Result<()>> + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let result = tokio::spawn(body).await;
        let mut tasks = product_tasks.lock().await;
        if let Some(task) = tasks.get_mut(&task_id) {
            task.status = match result {
                Ok(Ok(())) => ProductTaskStatus::Succeeded,
                Ok(Err(e)) => {
                    tracing::warn!(task_id = %task_id, product = %product, op, error = %e, "Product task failed");
                    ProductTaskStatus::Failed(e.safe_message())
                }
                Err(join_err) => {
                    tracing::error!(task_id = %task_id, product = %product, op, error = %join_err, "Product background task panicked");
                    ProductTaskStatus::Failed("background task panicked".into())
                }
            };
        }
        prune_product_tasks(&mut tasks, retention);
    })
}

fn prune_product_tasks(
    tasks: &mut std::collections::HashMap<String, ProductTask>,
    retention: usize,
) {
    if retention == 0 || tasks.len() <= retention {
        return;
    }
    let mut ids: Vec<_> = tasks.iter().collect();
    ids.sort_by_key(|item| std::cmp::Reverse(item.1.started_at));

    let to_remove: Vec<_> = ids
        .into_iter()
        .filter(|(_, t)| !matches!(t.status, ProductTaskStatus::Running))
        .skip(retention)
        .map(|(k, _)| k.clone())
        .collect();
    for id in to_remove {
        tasks.remove(&id);
    }
}

/// 列出产品的全部授权用户。权限：admin 或产品 owner；其余 404（不泄露
/// 存在性）。
pub(crate) async fn list_product_acl(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<Vec<ProductAclEntry>>, ApiError> {
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);
    validate_product_name(&name)?;

    load_record_for_owner_or_admin(&app, &name, auth_ref).await?;

    let users = app.state_store.list_users_by_product(&name).await?;
    let mut entries = Vec::with_capacity(users.len());
    for user in users {
        entries.push(ProductAclEntry {
            user_id: user.id,
            username: user.name,
            role: user.role,
            created_at: user.created_at,
        });
    }

    Ok(Json(entries))
}

/// 授予用户产品访问权限（ACL）。权限：admin 或产品 owner；其余 404（不
/// 泄露存在性）。
pub(crate) async fn grant_product_acl(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<ProductAclRequest>,
) -> Result<StatusCode, ApiError> {
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);
    validate_product_name(&name)?;

    let record = load_record_for_owner_or_admin(&app, &name, auth_ref).await?;

    let target_user = app
        .state_store
        .find_user_by_name(&req.username)
        .await?
        .ok_or_else(|| ApiError::Validation(format!("user '{}' not found", req.username)))?;

    if Some(target_user.id) == record.owner_id {
        return Err(ApiError::Validation(
            "product owner already has full access (ACL not needed)".into(),
        ));
    }

    let role = req.role.as_deref().unwrap_or("viewer");
    if !["viewer", "builder", "admin"].contains(&role) {
        return Err(ApiError::Validation(format!(
            "invalid role '{}'; must be one of: viewer, builder, admin",
            role
        )));
    }

    app.state_store
        .grant_product_acl_with_role(target_user.id, &name, role)
        .await?;

    if let Some(ctx) = auth_ref {
        let detail =
            serde_json::json!({ "target_user": req.username, "role": role, "product_id": record.id })
                .to_string();
        if let Err(e) = app
            .state_store
            .audit_log(
                &ctx.user,
                &ctx.role,
                "grant_product_acl",
                Some(&name),
                Some(&detail),
            )
            .await
        {
            warn_audit_log_failure(&e, "audit_log");
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

/// 撤销用户产品 ACL。权限：admin 或产品 owner；其余 404（不泄露存在性）。
/// 契约：DELETE 请求须携带 JSON body `{"username": ...}`——客户端未随请求
/// 提供 body 时会被 axum 的 Json extractor 以 415 拒绝，属预期行为而非服务
/// 端缺陷。
pub(crate) async fn revoke_product_acl(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<ProductAclRequest>,
) -> Result<StatusCode, ApiError> {
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);
    validate_product_name(&name)?;

    let record = load_record_for_owner_or_admin(&app, &name, auth_ref).await?;

    let target_user = app
        .state_store
        .find_user_by_name(&req.username)
        .await?
        .ok_or_else(|| ApiError::Validation(format!("user '{}' not found", req.username)))?;

    let granted = app
        .state_store
        .is_product_acl_granted(target_user.id, &name)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("check product acl", e))?;
    if !granted {
        return Err(ApiError::not_found(
            "product acl",
            format!("{name}#{}", target_user.id),
        ));
    }

    app.state_store
        .revoke_product_acl(target_user.id, &name)
        .await?;

    if let Some(ctx) = auth_ref {
        let detail =
            serde_json::json!({ "target_user": req.username, "product_id": record.id }).to_string();
        if let Err(e) = app
            .state_store
            .audit_log(
                &ctx.user,
                &ctx.role,
                "revoke_product_acl",
                Some(&name),
                Some(&detail),
            )
            .await
        {
            warn_audit_log_failure(&e, "audit_log");
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

/// 更新产品可见性（publish/unpublish）。权限：admin 拥有全部产品；owner
/// 仅限自己的私人产品。publish 后产品连同整条继承链对所有用户可见。
pub(crate) async fn update_product_visibility(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<UpdateVisibilityRequest>,
) -> Result<Json<UpdateProductResponse>, ApiError> {
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);
    validate_product_name(&name)?;

    if req.visibility != crbs_core::VISIBILITY_PUBLIC
        && req.visibility != crbs_core::VISIBILITY_PRIVATE
    {
        return Err(ApiError::Validation(format!(
            "invalid visibility '{}'; must be '{}' or '{}'",
            req.visibility,
            crbs_core::VISIBILITY_PUBLIC,
            crbs_core::VISIBILITY_PRIVATE
        )));
    }

    let record = load_record_for_owner_or_admin(&app, &name, auth_ref).await?;

    if record.visibility == crbs_core::VISIBILITY_PUBLIC
        && record.owner_id.is_none()
        && req.visibility == crbs_core::VISIBILITY_PRIVATE
    {
        return Err(ApiError::Conflict(
            "official (ownerless) products cannot be unpublished; use transfer to assign an owner first".into(),
        ));
    }

    if req.visibility == crbs_core::VISIBILITY_PRIVATE {
        let has_public_descendants = app.state_store.has_public_descendants(record.id).await?;
        if has_public_descendants {
            return Err(ApiError::Conflict(
                "cannot unpublish product with public descendants (would leak private ancestor chain)".into(),
            ));
        }
    }

    if req.visibility == crbs_core::VISIBILITY_PUBLIC {
        let mut ancestor_id = record.parent_id;
        while let Some(aid) = ancestor_id {
            let ancestor = app
                .state_store
                .get_product_by_id(aid)
                .await?
                .ok_or_else(|| ApiError::not_found("product", aid))?;
            if ancestor.visibility != crbs_core::VISIBILITY_PUBLIC {
                return Err(ApiError::Validation(format!(
                    "cannot publish product with private ancestor '{}' (would leak private ancestor chain)",
                    ancestor.name
                )));
            }
            ancestor_id = ancestor.parent_id;
        }
    }

    let outcome = app
        .state_store
        .update_product_visibility(
            record.id,
            &req.visibility,
            auth_ref.and_then(|c| c.user_id),
            req.reason.as_deref(),
            Some(req.expected_revision),
        )
        .await?;

    if let Some(ctx) = auth_ref {
        let detail = serde_json::json!({
            "product_id": record.id,
            "old_visibility": record.visibility,
            "new_visibility": req.visibility,
        })
        .to_string();
        if let Err(e) = app
            .state_store
            .audit_log(
                &ctx.user,
                &ctx.role,
                "update_product_visibility",
                Some(&name),
                Some(&detail),
            )
            .await
        {
            warn_audit_log_failure(&e, "audit_log");
        }
    }

    Ok(Json(UpdateProductResponse::from(outcome)))
}

/// 转让产品所有权。权限：admin 可转让任何产品；owner 仅限自己的私人产品。
/// 官方产品转让给用户时自动转为 private（满足 SCHEMA CHECK），私人产品保
/// 持可见性不变；原 owner 此后失去可见性（除非被授予 ACL）；存在 public
/// 后代时须先降级，避免可见性泄漏。
pub(crate) async fn transfer_product_ownership(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<TransferOwnershipRequest>,
) -> Result<Json<UpdateProductResponse>, ApiError> {
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);
    validate_product_name(&name)?;

    let record = load_record_for_owner_or_admin(&app, &name, auth_ref).await?;

    if record.owner_id.is_none() {
        let has_public_descendants = app.state_store.has_public_descendants(record.id).await?;
        if has_public_descendants {
            return Err(ApiError::Conflict(
                "cannot transfer official product with public descendants \
                 (transfer turns product private which would leak via public children)"
                    .into(),
            ));
        }
    }

    let new_owner = app
        .state_store
        .find_user_by_name(&req.new_owner_username)
        .await?
        .ok_or_else(|| {
            ApiError::Validation(format!("user '{}' not found", req.new_owner_username))
        })?;

    if Some(new_owner.id) == record.owner_id {
        return Err(ApiError::Validation(
            "cannot transfer product to the current owner".into(),
        ));
    }

    let outcome = app
        .state_store
        .transfer_product_ownership(
            record.id,
            new_owner.id,
            auth_ref.and_then(|c| c.user_id),
            req.reason.as_deref(),
            Some(req.expected_revision),
        )
        .await?;

    if let Some(ctx) = auth_ref {
        let detail = serde_json::json!({
            "product_id": record.id,
            "old_owner_id": record.owner_id,
            "new_owner_id": new_owner.id,
            "new_owner_username": req.new_owner_username,
            "builds_cancelled": outcome.builds_cancelled,
            "tasks_cancelled": outcome.tasks_cancelled,
        })
        .to_string();
        if let Err(e) = app
            .state_store
            .audit_log(
                &ctx.user,
                &ctx.role,
                "transfer_product_ownership",
                Some(&name),
                Some(&detail),
            )
            .await
        {
            warn_audit_log_failure(&e, "audit_log");
        }
    }

    Ok(Json(UpdateProductResponse {
        revision: outcome.revision,
        base_os_revision: outcome.base_os_revision,
        base_os_bumped: outcome.base_os_bumped,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::auth::AuthContext;
    use crate::server::state::AppState;
    use axum::extract::Extension;
    use std::sync::Arc;

    fn admin_ctx(user_id: i64) -> AuthContext {
        AuthContext {
            user: "admin".into(),
            role: "admin".into(),
            user_id: Some(user_id),
            ..Default::default()
        }
    }

    async fn test_app() -> (Arc<AppState>, Arc<crbs_core::StateStore>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        (app, store, tmp)
    }

    fn create_body(
        name: &str,
        parent: Option<i64>,
        visibility: Option<&str>,
    ) -> Json<CreateProductBody> {
        Json(CreateProductBody {
            name: name.into(),
            display_name: None,
            parent_id: parent,
            visibility: visibility.map(str::to_string),
            config: ProductConfig::default(),
            reason: Some("monotonicity test".into()),
        })
    }

    #[tokio::test]
    async fn create_product_rejects_public_child_under_private_parent() {
        let (app, store, _tmp) = test_app().await;
        let admin_id = store.create_user("admin", "admin").await.unwrap();

        let private_parent = store
            .create_product(crbs_core::CreateProductInput {
                name: "private-parent",
                display_name: None,
                owner_id: Some(admin_id),
                parent_id: None,
                visibility: crbs_core::VISIBILITY_PRIVATE,
                config: &ProductConfig::default(),
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();

        let result = create_product(
            State(app),
            Some(Extension(admin_ctx(admin_id))),
            create_body(
                "child-prod",
                Some(private_parent),
                Some(crbs_core::VISIBILITY_PUBLIC),
            ),
        )
        .await;

        match result {
            Err(ApiError::Conflict(msg)) => {
                assert!(
                    msg.contains("private ancestor"),
                    "expected monotonicity message, got: {msg}"
                );
            }
            other => panic!("expected Conflict, got {:?}", other.err()),
        }
    }

    #[tokio::test]
    async fn unpublish_official_product_conflicts() {
        let (app, store, _tmp) = test_app().await;
        let admin_id = store.create_user("admin", "admin").await.unwrap();

        store
            .create_product(crbs_core::CreateProductInput {
                name: "official-prod",
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: crbs_core::VISIBILITY_PUBLIC,
                config: &ProductConfig::default(),
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();

        let result = update_product_visibility(
            State(app),
            Path("official-prod".to_string()),
            Some(Extension(admin_ctx(admin_id))),
            Json(UpdateVisibilityRequest {
                visibility: crbs_core::VISIBILITY_PRIVATE.to_string(),
                reason: None,
                expected_revision: 0,
            }),
        )
        .await;

        match result {
            Err(ApiError::Conflict(msg)) => {
                assert!(
                    msg.contains("cannot be unpublished"),
                    "unexpected error: {msg}"
                );
            }
            other => panic!("expected Conflict, got {:?}", other.err()),
        }
    }

    #[tokio::test]
    async fn create_product_allows_compliant_parents() {
        let (app, store, _tmp) = test_app().await;
        let admin_id = store.create_user("admin", "admin").await.unwrap();

        let public_parent = store
            .create_product(crbs_core::CreateProductInput {
                name: "public-parent",
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: crbs_core::VISIBILITY_PUBLIC,
                config: &ProductConfig::default(),
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();
        let result = create_product(
            State(app.clone()),
            Some(Extension(admin_ctx(admin_id))),
            create_body(
                "public-child",
                Some(public_parent),
                Some(crbs_core::VISIBILITY_PUBLIC),
            ),
        )
        .await;
        assert!(result.is_ok(), "public child under public parent must pass");

        let result = create_product(
            State(app),
            Some(Extension(admin_ctx(admin_id))),
            create_body("private-child", None, Some(crbs_core::VISIBILITY_PRIVATE)),
        )
        .await;
        assert!(result.is_ok(), "private child must pass");
    }

    #[tokio::test]
    async fn init_and_clean_conflict_with_running_same_op_task() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let server_config = crbs_core::config::ServerConfig {
            allow_product_management: true,
            ..crbs_core::config::ServerConfig::default()
        };
        let app = Arc::new(AppState::for_test(
            store.clone(),
            server_config,
            tmp.path().to_path_buf(),
        ));

        let _env = crate::test_support::lock_config_env();
        let cfg_dir = tempfile::tempdir().unwrap();
        std::env::set_var("CRBS_CONFIG_DIR", cfg_dir.path());
        tokio::fs::create_dir_all(cfg_dir.path().join("products"))
            .await
            .unwrap();
        tokio::fs::write(
            cfg_dir.path().join("products").join("conflict-prod.toml"),
            "[product]\nproduct = \"conflict-prod\"\n",
        )
        .await
        .unwrap();
        let admin_id = store.create_user("admin", "admin").await.unwrap();
        let ctx = Some(Extension(admin_ctx(admin_id)));
        let product = "conflict-prod".to_string();

        let running = |op: &'static str| ProductTask {
            status: ProductTaskStatus::Running,
            product: product.clone(),
            op,
            started_at: chrono::Utc::now(),
        };

        app.product_tasks
            .lock()
            .await
            .insert("t-init".to_string(), running("init"));
        let res = init_product(
            State(app.clone()),
            Path(product.clone()),
            ctx.clone(),
            Json(InitRequest { force: false }),
        )
        .await;
        match res {
            Err(ApiError::Conflict(msg)) => assert!(
                msg.contains("already has an active init task"),
                "unexpected conflict message: {msg}"
            ),
            other => panic!(
                "expected Conflict for concurrent init, got {:?}",
                other.err()
            ),
        }

        app.product_tasks
            .lock()
            .await
            .insert("t-clean".to_string(), running("clean"));
        let res = clean_product(State(app), Path(product), ctx).await;
        match res {
            Err(ApiError::Conflict(msg)) => assert!(
                msg.contains("already has an active clean task"),
                "unexpected conflict message: {msg}"
            ),
            other => panic!(
                "expected Conflict for concurrent clean, got {:?}",
                other.err()
            ),
        }
    }

    #[test]
    fn require_admin_unauthenticated_maps_to_401() {
        let err = require_admin(None, "initialize products").unwrap_err();
        assert!(
            matches!(err, ApiError::Unauthorized(_)),
            "expected Unauthorized, got {err:?}"
        );

        let err = require_admin(
            Some(&AuthContext {
                user: "bob".into(),
                role: "builder".into(),
                ..Default::default()
            }),
            "initialize products",
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::PermissionDenied(_)));
    }

    #[tokio::test]
    async fn supervised_product_task_marks_panicked_task_failed() {
        let (app, _store, _tmp) = test_app().await;
        let task_id = "panic-task".to_string();
        {
            let mut tasks = app.product_tasks.lock().await;
            tasks.insert(
                task_id.clone(),
                ProductTask {
                    status: ProductTaskStatus::Running,
                    product: "demo".into(),
                    op: "init",
                    started_at: chrono::Utc::now(),
                },
            );
        }

        let supervisor = spawn_supervised_product_task(
            app.product_tasks.clone(),
            task_id.clone(),
            "demo".to_string(),
            "init",
            10,
            async { panic!("intentional test panic") },
        );
        supervisor.await.unwrap();

        let tasks = app.product_tasks.lock().await;
        match tasks.get(&task_id) {
            Some(ProductTask {
                status: ProductTaskStatus::Failed(msg),
                ..
            }) => assert_eq!(msg, "background task panicked"),
            other => panic!(
                "expected Failed status after task panic, got {:?}",
                other.map(|t| &t.status)
            ),
        }
    }

    #[test]
    fn prune_product_tasks_skips_running_entries() {
        let now = chrono::Utc::now();
        let task = |status: ProductTaskStatus, age_hours: i64| ProductTask {
            status,
            product: "demo".into(),
            op: "init",
            started_at: now - chrono::Duration::hours(age_hours),
        };
        let mut tasks = std::collections::HashMap::new();

        tasks.insert("t-running".to_string(), task(ProductTaskStatus::Running, 3));
        tasks.insert("t-old".to_string(), task(ProductTaskStatus::Succeeded, 2));
        tasks.insert(
            "t-mid".to_string(),
            task(ProductTaskStatus::Failed("x".into()), 1),
        );
        tasks.insert("t-new".to_string(), task(ProductTaskStatus::Succeeded, 0));

        prune_product_tasks(&mut tasks, 2);

        assert!(
            tasks.contains_key("t-running"),
            "Running 条目不得被逐出（查重与状态接口依赖它）"
        );
        assert!(!tasks.contains_key("t-old"), "逐出名额由最老终态条目承担");

        assert!(tasks.contains_key("t-mid") && tasks.contains_key("t-new"));
        assert_eq!(tasks.len(), 3, "终态条目收敛到 retention，Running 豁免在外");
    }

    #[tokio::test]
    async fn get_product_overrides_path_fields_with_server_values() {
        let (app, store, _tmp) = test_app().await;

        let cfg = ProductConfig {
            base_packages: vec!["bash".to_string()],
            repos: vec![crbs_core::config::RepoConfig {
                name: "base".to_string(),
                baseurl: "http://example.com/repo".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        store
            .create_product(crbs_core::CreateProductInput {
                name: "mydist",
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: crbs_core::VISIBILITY_PUBLIC,
                config: &cfg,
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();

        let detail = get_product(State(app.clone()), Path("mydist".to_string()), None)
            .await
            .unwrap()
            .0;

        assert_eq!(detail.crbs_root, app.crbs_root);
        assert_eq!(
            detail.result_dir,
            app.result_dir_for_or_default("mydist").await
        );
    }
}
