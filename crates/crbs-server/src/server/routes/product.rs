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

/// 写前校验，与加载期同口径：按链合并后的生效值判定（deterministic 链上
/// OR、build_target/dnf_cache_enabled 缺省继承父层），坏组合落库会在下一
/// 次加载时 500 自锁，提前拦为 400。
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

// --- 请求/响应 DTO ---------------------------------------------------------

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

/// `POST /api/v1/products` 请求体。`visibility` 缺省 `"public"`（官方产品，
/// owner_id=NULL；schema CHECK 同源）；`reason` 写入 history 供审计。
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

/// `PUT /api/v1/products/{name}` 请求体。`expected_revision` **必填**（拒绝盲写）。
///
/// `parent_id` 三态（`Option<Option<i64>>` + `double_option`）：缺席 → 不改
/// parent；`null` → detach（变根产品）；`42` → set（走写路径校验）。顺序：先
/// config（expected_revision gate）再 re-parent——后者以 config 更新返回的新
/// revision 为门（乐观锁契约覆盖复合写全程）；任一失败即返回，响应 revision
/// 取最终值。
#[derive(Deserialize)]
pub(crate) struct UpdateProductBody {
    pub expected_revision: i64,
    pub config: ProductConfig,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_option_i64")]
    pub parent_id: Option<Option<i64>>,
}

/// serde helper：三态区分。`#[serde(default)]` 覆盖字段缺席（→ `None`），本函数
/// 仅在字段**存在**时被调用：`null` → `Some(None)`；`42` → `Some(Some(42))`。
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

// --- 内部辅助 --------------------------------------------------------------

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
        // 未认证 → 401；403 保留给"已认证但角色不足"。
        return Err(ApiError::Unauthorized(format!(
            "authentication required to {}",
            op
        )));
    }
    Ok(())
}

/// 要求 builder 或以上角色（创建私人产品的门槛）。
fn require_builder(auth: Option<&AuthContext>, op: &str) -> Result<(), ApiError> {
    if let Some(ctx) = auth {
        if !ctx.is_builder() {
            return Err(ApiError::PermissionDenied(format!(
                "only builder or above can {}",
                op
            )));
        }
    } else {
        // 未认证 → 401；403 保留给"已认证但角色不足"。
        return Err(ApiError::Unauthorized(format!(
            "authentication required to {}",
            op
        )));
    }
    Ok(())
}

// --- 读端点 ----------------------------------------------------------------

/// 单调性校验（create / update re-parent 共用；publish 另有内联祖先环，
/// 带 visited/深度 8 环防护与 Conflict 变体）：public 产品不能挂
/// 含 private 祖先的链——否则 outsider 经 public child 的 chain_resolve 可
/// 遍历到 private ancestor 的 name；admin 也不豁免。查的是"祖先链是否全
/// public"，非 check_chain_visibility 的"用户是否可见祖先"。
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
            // 可见性限制的状态冲突 → 409（与 state 层 DeleteRestricted→409 同族）。
            return Err(ApiError::Conflict(format!(
                "public product cannot attach to private ancestor '{}'; unpublish first",
                ancestor.name
            )));
        }
        cursor = ancestor.parent_id;
    }
    Ok(())
}

/// 列出当前请求者可见的产品名（`Vec<String>` 出参形状为 CLI/UI 兼容保留）。
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

/// 查看单个产品的合并后配置详情（product-layer + CrbsConfig + server override）。
/// 访问控制：public 或（认证后）admin/owner；不可见 → 404，不区分"不存在"与
/// "无权限"（避免存在性泄露命名）。
pub(crate) async fn get_product(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<ProductDetail>, ApiError> {
    validate_product_name(&name)?;

    let record = load_visible_record(&app, &name, auth.as_ref()).await?;
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);
    // 链上所有节点必须可见（私有祖先不可泄露）
    check_chain_visibility(&app, record.id, auth_ref).await?;

    let cfg = app
        .state_store
        .load_merged_config_for_product_by_id(record.id, &name)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("load product config", e))?;

    // parent_name 需回查一次；FK 下 parent 必存在，缺失 = DB 已损坏，退化 None 不报错。
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

/// 返回该产品链解析后的 TOML（`content-type: application/toml`）。
///
/// **磁盘同步桥**：CLI 本地命令（build/reproduce/sign 等）仍读磁盘 TOML，
/// 运维用 `crbs products export <name> --remote <profile> >
/// /etc/crbs/products/<name>.toml` 把 hub DB 权威配置刷回本地防 drift。
/// 访问控制同 `get_product`。
pub(crate) async fn get_product_resolved(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Response, ApiError> {
    validate_product_name(&name)?;
    let record = load_visible_record(&app, &name, auth.as_ref()).await?;
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);
    // 链上所有节点必须可见（私有祖先不可泄露）
    check_chain_visibility(&app, record.id, auth_ref).await?;
    let toml = app.state_store.chain_resolve_to_toml(record.id).await?;

    // `chain_resolve_to_toml` 返回 `Arc<String>`，克隆进 body（缓存仍复用 Arc）。
    let body: String = (*toml).clone();
    let mut resp = body.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/toml; charset=utf-8"),
    );
    // resolved 是随写变的权威快照，export 桥刷盘前不得被中间层缓存（裸 no-store）。
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(resp)
}

/// 列出该产品的所有历史版本（revision DESC）。history 仅存本层 config_json、
/// 按本产品 id 查表，不走 chain visibility。
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

/// 读取该产品指定 revision 的历史快照（同上：仅本层 config_json，不走
/// chain visibility）。
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

/// 按 name 读取产品记录并按可见性过滤；不可见 → 404（与 get_product 保持一致）。
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

/// 管理端点（update/delete/acl/publish/transfer 族）与 UI 编辑页的产品装载：
/// 按名取行 + owner/admin 判定，任一不满足 → 同名 404（不泄露存在性）。
/// 名校验由调用方自带（create 严、URL 宽），不并入。
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

// --- 写端点 (admin-only) ---------------------------------------------------

/// 创建产品（写 products + revision=1 的 history 快照）。name 冲突 → 409；
/// 名字非法 → 400；非 builder → 403。admin 可创建官方产品（owner_id=NULL,
/// visibility=public）或私人产品；builder 只能创建私人产品（owner_id=self）。
pub(crate) async fn create_product(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<CreateProductBody>,
) -> Result<(StatusCode, Json<CreateProductResponse>), ApiError> {
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);
    require_builder(auth_ref, "create products")?;
    // create：新名字入库，走严格版（含 ≤128 长度上限）。
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

    // fork 权限检查：设置了 parent_id 时，要求对父产品 can_see
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

        // 单调性校验：public 产品不得挂含 private 祖先的链（admin 也不豁免）。
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

/// 更新产品配置（`expected_revision` 不命中 → 409）。携带 `parent_id` 时在
/// config 更新后再走 re-parent，两步各自事务、各自 bump revision + 写
/// history，响应 `revision` 为最终值。权限：admin 所有 / owner 私人 / 其他 404。
pub(crate) async fn update_product(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<UpdateProductBody>,
) -> Result<Json<UpdateProductResponse>, ApiError> {
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);
    // URL name 是既有产品标识（不可变），走宽松版：长度上限只挡 create 新名字。
    validate_product_name(&name)?;

    let record = load_record_for_owner_or_admin(&app, &name, auth_ref).await?;

    // re-parent 可见性检查：设置新 parent 时，要求对新 parent 可 see
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

        // 单调性校验（leak 向量与 admin 不豁免见 ensure_no_private_ancestor）。
        if record.visibility == crbs_core::VISIBILITY_PUBLIC {
            ensure_no_private_ancestor(&app, pid).await?;
        }

        // fail-fast：撞 cycle 直接拒绝
        app.state_store
            .validate_parent_id(Some(record.id), pid)
            .await?;
    }

    // 校验用更新后的 parent（None = 保持现值，Some(None) = 摘链）。
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

    // re-parent 以 config 更新返回的新 revision 为门——无门则乐观锁只盖前半
    // 段，并发写者可插在两事务之间被静默叠加；门不命中 → 409，任一失败即
    // 返回，客户端按新 revision 重试。
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

    // `repo_publish` 翻转 → 立即重建该产品 repo（否则等下一次 build/GC 才生效）；
    // 配置已提交，regen 失败仅 warn（下次触发或 `rebuild-repo` 收敛）。
    let old_publish = record.config.repo_publish.unwrap_or(true);
    let new_publish = req.config.repo_publish.unwrap_or(true);
    if old_publish != new_publish {
        crate::server::repo_regen::regenerate_product_repo(&app, &name).await;
    }

    Ok(Json(UpdateProductResponse::from(outcome)))
}

/// 删除产品行（FK CASCADE 连带 history；缓存清理由 state 层内部处理）。不触发
/// 磁盘产物 GC——那是 `POST /{name}/clean` 的职责。权限：admin 所有 / owner
/// 私人 / 其他 404（不泄露存在性）。
pub(crate) async fn delete_product(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
) -> Result<StatusCode, ApiError> {
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);
    validate_product_name(&name)?;

    let record = load_record_for_owner_or_admin(&app, &name, auth_ref).await?;

    // 删除前解析 result_root：删除后产品配置不可读，自定义 result_dir 会丢失。
    let result_root = app.result_dir_for_or_default(&name).await;

    let (builds_cancelled, tasks_cancelled) = app.state_store.delete_product(record.id).await?;

    // 顺手清理 `_repo/{product}` 子树（路径断言见 repo_regen）；失败仅 warn（行已删）。
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

// --- 异步 init / clean ------------------------------------------------------

/// 同 (product, op) 是否已有 Running 任务。调用方持 `product_tasks` 锁调用，
/// check-and-insert 之间无 await、无 TOCTOU。
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

    // 先生成配置模板；若模板刚生成，引擎后续会报错提示用户编辑，行为与 CLI 一致。
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
            // server 世界：pin crbs_root = server root，复用 AppState 的 StateStore。
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
            // HTTP 路径保留 active build 守卫
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

/// 异步清理磁盘产物，**不删 DB 行**——删产品记录走 `DELETE /api/v1/products/{name}`。
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
        // 并发 clean 去重（同 init）。
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
            // 同 init_product：pin crbs_root = server root。
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
            // HTTP 路径保留 active build 守卫
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

/// spawn 异步 init/clean 任务并监督 panic（两 handler 共用）。裸 `tokio::spawn`
/// 的 JoinError 被静默丢弃、条目永停 Running；监督层在内层 spawn 上 await，
/// panic → Failed("background task panicked") 后照常 prune。返回 JoinHandle（测试用）。
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
                    // to_string() 可能带内部路径/系统细节：operator 可见的状态
                    // 接口只回 safe_message，完整错误进 tracing。
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
    // Running 不进逐出候选——被逐出则状态接口立即 404、同 (product, op) 查重
    // miss，重开双注册窗口。豁免后总数可暂超 retention：Running 必迁终态
    //（监督层兜底），下次 prune 收敛。
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

// --- ACL 管理 ----------------------------------------------------------------

/// 列出产品的所有授权用户。权限：admin 或产品 owner；其他 404（不泄露存在性）。
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

/// 授予用户产品访问权限（ACL）。权限：admin 或产品 owner；其他 404（不泄露存在性）。
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

    // 204 而非 201：底层是幂等 upsert（ON CONFLICT DO UPDATE），重复授予非新建资源。
    Ok(StatusCode::NO_CONTENT)
}

/// 撤销用户产品 ACL。权限：admin 或产品 owner；其他 404（不泄露存在性）。
/// 契约：DELETE 需携带 JSON body `{"username": ...}`——客户端剥离 body 会被
/// axum 的 Json extractor 以 415 拒绝，不是服务端 bug。
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

    // state 层 revoke 返回的 u64 是级联取消的构建数，不能当存在性判据；先
    // 预检授权是否存在，未授权 404（重复 revoke 报 404 而非静默 204）。
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

/// 更新产品可见性（publish/unpublish）。权限：admin 所有；owner 仅私人产品。
/// publish 后产品连同整条继承链对所有用户可见。
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

    // 官方产品（owner_id=None）不能 unpublish（SCHEMA 要求 owner_id!=NULL OR
    // public）；私有化需先 transfer。409：资源状态冲突，与下方预检同族。
    if record.visibility == crbs_core::VISIBILITY_PUBLIC
        && record.owner_id.is_none()
        && req.visibility == crbs_core::VISIBILITY_PRIVATE
    {
        return Err(ApiError::Conflict(
            "official (ownerless) products cannot be unpublished; use transfer to assign an owner first".into(),
        ));
    }

    // unpublish 前检查 public 后代（防泄露私有祖先链）；409 同 state 层守卫。
    if req.visibility == crbs_core::VISIBILITY_PRIVATE {
        let has_public_descendants = app.state_store.has_public_descendants(record.id).await?;
        if has_public_descendants {
            return Err(ApiError::Conflict(
                "cannot unpublish product with public descendants (would leak private ancestor chain)".into(),
            ));
        }
    }

    // publish 前检查整条祖先链全 public（防泄露；读路径 check_chain_visibility 兜底）。
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

/// 转让产品所有权。权限：admin 任何产品；owner 仅自己的私人产品。官方产品
/// 转让给用户时**自动变 private**（满足 SCHEMA CHECK），私人产品保持
/// visibility；旧 owner 失去可见性（除非被授 ACL）；有 public 后代需先降级
///（避免 leak）。
pub(crate) async fn transfer_product_ownership(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<TransferOwnershipRequest>,
) -> Result<Json<UpdateProductResponse>, ApiError> {
    let auth_ref = auth.as_ref().map(|Extension(ctx)| ctx);
    validate_product_name(&name)?;

    let record = load_record_for_owner_or_admin(&app, &name, auth_ref).await?;

    // 官方产品转让后自动变 private，需先确保无 public 后代（私人 private 的
    // 后代必 private，免检）；409 同 state 层 DeleteRestricted 守卫。
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

    // 旧 base_os 目录会变孤儿（需用户手动迁移数据）；暂不回 warning，直接放行。

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

    /// 单调性：admin 创建 public 子产品挂到 private 父产品下必须 409。
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

    /// 官方（ownerless）产品 unpublish → 409（与 public-descendant 预检同族）。
    #[tokio::test]
    async fn unpublish_official_product_conflicts() {
        let (app, store, _tmp) = test_app().await;
        let admin_id = store.create_user("admin", "admin").await.unwrap();

        // owner_id=None 官方产品（SCHEMA 要求其必为 public）。
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

    /// 单调性正例：public 父 + public 子照常创建；private 子也允许。
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

        // private 子（根产品）：单调性不受影响。
        let result = create_product(
            State(app),
            Some(Extension(admin_ctx(admin_id))),
            create_body("private-child", None, Some(crbs_core::VISIBILITY_PRIVATE)),
        )
        .await;
        assert!(result.is_ok(), "private child must pass");
    }

    /// 同 (product, op) 已有 Running 任务 → 409，不再叠加注册新任务。预置
    /// Running 直接命中冲突分支——检查在 spawn 前，不触发后台引擎。
    #[tokio::test]
    async fn init_and_clean_conflict_with_running_same_op_task() {
        // 校验在 check_product_management 门之后：需开启管理开关的 ServerConfig（test_app 默认关闭）。
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
        // init_product 在冲突检查前会同步生成配置模板（CRBS_CONFIG_DIR 缺省
        // /etc/crbs）——重定向到测试私有目录并预置产品配置（存在即就绪，否则
        // 走"请编辑模板"400 分支）。env 须持共享守卫 lock_config_env：并行测试
        //（server/mod.rs 亦 set 该变量）下裸 set_var/remove_var 竞态互覆；守卫
        // 持进程锁，drop 恢复原值（不能无条件 remove）。
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

        // init：同 op Running 命中 409。
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

        // clean：同 op Running 命中 409（op 维度隔离：init 的 Running 不拦 clean）。
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

        // CRBS_CONFIG_DIR 恢复由 _env（ConfigEnvGuard）drop 完成（有原值 set 回，无则 remove）。
    }

    /// L-d：未认证访问 admin 端点返回 401（对齐 admin.rs），而非 403。
    #[test]
    fn require_admin_unauthenticated_maps_to_401() {
        let err = require_admin(None, "initialize products").unwrap_err();
        assert!(
            matches!(err, ApiError::Unauthorized(_)),
            "expected Unauthorized, got {err:?}"
        );
        // 已认证但角色不足仍是 403。
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

    /// 任务体 panic 时监督层把条目置为 Failed("background task panicked")，不停留 Running。
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

    /// prune 跳过 Running——逐出会让状态接口 404、并发查重 miss 重开双注册
    /// 窗口；豁免后总数可暂超 retention（Running 必迁终态，下次 prune 收敛），
    /// 逐出名额由终态条目承担。
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
        // 最老条目为 Running（按 started_at 排序首当其冲），另有 3 个较新终态条目。
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
        // 保留最近 2 个终态条目 + Running 豁免（总数 3 > retention，暂态）。
        assert!(tasks.contains_key("t-mid") && tasks.contains_key("t-new"));
        assert_eq!(tasks.len(), 3, "终态条目收敛到 retention，Running 豁免在外");
    }

    /// 详情端点路径字段必须回填 server 生效值：merged config 的 crbs_root 属
    /// 引擎世界（crbs.toml），hub 实际构建产物 pin 在 server root，透出引擎
    /// root 会指向 hub 上不存在的路径。
    #[tokio::test]
    async fn get_product_overrides_path_fields_with_server_values() {
        let (app, store, _tmp) = test_app().await;
        // 根产品链校验要求非空 base_packages/repos，空 Default 只允许 Fork 子产品用。
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
