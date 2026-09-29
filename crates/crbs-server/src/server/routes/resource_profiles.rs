// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 包资源画像管理端点（声明管理面）：
//! declared 放置契约的查询与 set/unset，仅限 hub admin（下限影响全集群派发，
//! 不放产品 ACL admin）。键以源码包基础名（builds.name）为准，同一源码包
//! 跨版本共享声明与学习画像。写路径列组隔离由 state 层保证（PUT 只写
//! declared 组、永不触碰 learned），DELETE 只清 declared 列不删行。

use std::sync::Arc;

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crbs_core::PackageResourceProfile;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::{audit_event, require_admin};
use crate::server::state::AppState;
use crate::server::validation::validate_product_name;

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/resource-profiles", get(list_profiles))
        .route(
            "/api/v1/resource-profiles/{product}/{source}/{arch}",
            get(get_profile).put(set_profile).delete(unset_profile),
        )
}

/// PUT 请求体：declared 三维全量语义（缺省维 = 显式未声明，upsert 列组隔离）。
#[derive(Deserialize)]
pub(crate) struct SetResourceProfileRequest {
    pub min_mem_kb: Option<i64>,
    pub min_ncpu: Option<i64>,
    pub min_disk_kb: Option<i64>,
}

#[derive(Serialize)]
pub(crate) struct ResourceProfileListResponse {
    pub product: String,
    pub total: i64,
    pub profiles: Vec<PackageResourceProfile>,
}

#[derive(Deserialize)]
pub(crate) struct ListProfilesQuery {
    pub product: String,
}

/// declared 下限上界（提交期同界）：KB 常量与 BuildOptions 同源。
fn validate_declared_value(
    min_mem_kb: Option<i64>,
    min_ncpu: Option<i64>,
    min_disk_kb: Option<i64>,
) -> Result<(), ApiError> {
    if let Some(v) = min_mem_kb {
        if v <= 0 || v > crbs_core::build_options::MAX_REQ_MIN_MEM_KB {
            return Err(ApiError::Validation(format!(
                "min_mem_kb must be 1..={}",
                crbs_core::build_options::MAX_REQ_MIN_MEM_KB
            )));
        }
    }
    if let Some(v) = min_disk_kb {
        if v <= 0 || v > crbs_core::build_options::MAX_REQ_MIN_DISK_KB {
            return Err(ApiError::Validation(format!(
                "min_disk_kb must be 1..={}",
                crbs_core::build_options::MAX_REQ_MIN_DISK_KB
            )));
        }
    }
    if let Some(v) = min_ncpu {
        if !(1..=i64::from(crbs_core::build_options::MAX_REQ_MIN_NCPU)).contains(&v) {
            return Err(ApiError::Validation(format!(
                "min_ncpu must be 1..={}",
                crbs_core::build_options::MAX_REQ_MIN_NCPU
            )));
        }
    }
    Ok(())
}

/// 画像行读取 + 缺行 404 收口（GET 单键；PUT/DELETE 前置检查共用）。
async fn profile_or_404(
    app: &AppState,
    product: &str,
    source: &str,
    arch: &str,
) -> Result<PackageResourceProfile, ApiError> {
    app.state_store
        .get_profile(product, source, arch)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "resource profile {product}/{source}/{arch} not found"
            ))
        })
}

async fn product_exists(app: &AppState, product: &str) -> Result<bool, ApiError> {
    app.state_store
        .product_row_exists(product)
        .await
        .map_err(ApiError::from)
}

/// `GET /api/v1/resource-profiles?product=X`
///
/// 产品内画像行全列列举（declared + learned 全组；分页由调用方裁剪）。
pub(crate) async fn list_profiles(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    Query(q): Query<ListProfilesQuery>,
) -> Result<Json<ResourceProfileListResponse>, ApiError> {
    require_admin(auth)?;
    validate_product_name(&q.product)?;
    if !product_exists(&app, &q.product).await? {
        return Err(ApiError::NotFound(format!(
            "product {} not found",
            q.product
        )));
    }
    let profiles = app
        .state_store
        .list_profiles_by_product(&q.product)
        .await
        .map_err(ApiError::from)?;
    let total = profiles.len() as i64;
    Ok(Json(ResourceProfileListResponse {
        product: q.product,
        total,
        profiles,
    }))
}

/// `GET /api/v1/resource-profiles/{product}/{source}/{arch}`
pub(crate) async fn get_profile(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    Path((product, source, arch)): Path<(String, String, String)>,
) -> Result<Json<PackageResourceProfile>, ApiError> {
    require_admin(auth)?;
    validate_product_name(&product)?;
    Ok(Json(profile_or_404(&app, &product, &source, &arch).await?))
}

/// `PUT /api/v1/resource-profiles/{product}/{source}/{arch}`
///
/// 写 declared 三维（全 None = 显式清空该键声明，仅对已存在的画像行生效），
/// 学习组与行内 learned 列组不动（列组隔离）。审计 + 画像权重
/// 缓存按源码包失效（'any' 行影响该包全部 arch 键的解析）。
pub(crate) async fn set_profile(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    Path((product, source, arch)): Path<(String, String, String)>,
    Json(body): Json<SetResourceProfileRequest>,
) -> Result<Json<PackageResourceProfile>, ApiError> {
    let ctx = require_admin(auth)?;
    validate_product_name(&product)?;
    if source.is_empty() || arch.is_empty() {
        return Err(ApiError::Validation(
            "source and arch path segments must be non-empty".into(),
        ));
    }
    validate_declared_value(body.min_mem_kb, body.min_ncpu, body.min_disk_kb)?;
    if !product_exists(&app, &product).await? {
        return Err(ApiError::NotFound(format!("product {product} not found")));
    }
    if body.min_mem_kb.is_none() && body.min_ncpu.is_none() && body.min_disk_kb.is_none() {
        // 全 None + 缺行：upsert 会造出 declared 全空的惰性幽灵行（后续只能
        // 再 unset 一次才能清掉），与 GET 单键缺失同口径 404，不落库。
        profile_or_404(&app, &product, &source, &arch).await?;
    }
    app.state_store
        .set_declared_requirements(
            &product,
            &source,
            &arch,
            body.min_mem_kb,
            body.min_ncpu,
            body.min_disk_kb,
        )
        .await
        .map_err(ApiError::from)?;
    let detail = serde_json::json!({
        "min_mem_kb": body.min_mem_kb,
        "min_ncpu": body.min_ncpu,
        "min_disk_kb": body.min_disk_kb,
    });
    audit_event(
        &app,
        &ctx,
        "set_resource_profile",
        Some(&format!("{product}/{source}/{arch}")),
        Some(&detail.to_string()),
    )
    .await;
    app.resource_weight_cache.invalidate_pkg(&product, &source);
    Ok(Json(profile_or_404(&app, &product, &source, &arch).await?))
}

/// `DELETE /api/v1/resource-profiles/{product}/{source}/{arch}`
///
/// 只清 declared 列（置 NULL），不删行——learned 是不可再生学习资产。
/// 行不存在时幂等成功；审计 + 权重缓存按源码包失效。
pub(crate) async fn unset_profile(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    Path((product, source, arch)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let ctx = require_admin(auth)?;
    validate_product_name(&product)?;
    if source.is_empty() || arch.is_empty() {
        return Err(ApiError::Validation(
            "source and arch path segments must be non-empty".into(),
        ));
    }
    app.state_store
        .unset_declared_requirements(&product, &source, &arch)
        .await
        .map_err(ApiError::from)?;
    audit_event(
        &app,
        &ctx,
        "unset_resource_profile",
        Some(&format!("{product}/{source}/{arch}")),
        None,
    )
    .await;
    app.resource_weight_cache.invalidate_pkg(&product, &source);
    Ok(StatusCode::NO_CONTENT)
}
