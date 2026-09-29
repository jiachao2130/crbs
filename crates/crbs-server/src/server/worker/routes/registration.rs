// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! Worker 注册与凭据管理。

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

use super::heartbeat::sanitize_resource_caps;
use super::require_operator;

fn validate_worker_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty() || name.len() > 64 {
        return Err(ApiError::Validation(
            "worker name must be 1-64 characters".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.')
    {
        return Err(ApiError::Validation(
            "worker name contains invalid characters".into(),
        ));
    }
    // hub 本地车道伪 worker 的专用名，外部 worker 注册不得占用。
    if name == crbs_core::HUB_LOCAL_WORKER_NAME {
        return Err(ApiError::Validation(format!(
            "worker name '{}' is reserved for the hub local lane",
            crbs_core::HUB_LOCAL_WORKER_NAME
        )));
    }
    Ok(())
}

fn validate_worker_arch(arch: &str) -> Result<(), ApiError> {
    if arch.is_empty() || arch.len() > 32 {
        return Err(ApiError::Validation(
            "worker arch must be 1-32 characters".into(),
        ));
    }
    if !arch
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(ApiError::Validation(
            "worker arch contains invalid characters".into(),
        ));
    }
    Ok(())
}

pub(super) async fn list_workers(
    State(app): State<Arc<AppState>>,
    auth: Option<axum::extract::Extension<AuthContext>>,
) -> Result<Json<Vec<crbs_core::WorkerStatus>>, ApiError> {
    let _ctx = require_operator(&auth)?;

    let workers = app
        .state_store
        .list_workers()
        .await
        .map_err(ApiError::from)?;
    Ok(Json(workers))
}

// ======== 注册 Worker ========

#[derive(Deserialize)]
pub struct RegisterRequest {
    name: String,
    arch: String,
    capacity: i64,
    #[serde(default)]
    version: String,
    /// 采集能力位图（worker 启动探测；位定义见 state 层 RESOURCE_CAP_* 常量）。
    /// 缺字段 / null → None（落 NULL，按能力不可用降级）。
    #[serde(default)]
    resource_caps: Option<i64>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    #[serde(rename = "id")]
    worker_id: i64,
    status: &'static str,
    /// 启动 GC 守卫：hub DB 是否有活跃（building）构建——同机部署时 worker
    /// 启动期孤儿挂载 GC（priv-helper 无条件 MNT_DETACH crbs_root 下全部挂载）
    /// 会杀掉其活跃挂载，worker 据此跳过。序列化对齐 HeartbeatResponse 扩展
    /// 约定：顶层可选字段、不加 `deny_unknown_fields`。
    #[serde(skip_serializing_if = "Option::is_none")]
    has_active_local_builds: Option<bool>,
}

pub(super) async fn register_worker(
    State(app): State<Arc<AppState>>,
    auth: Option<axum::extract::Extension<AuthContext>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    // operator/admin 可代注册任意 worker；worker 角色只能用自身 token 绑定的
    // 名称注册（防名称劫持）。匿名 → 401、已认证角色不足 403。
    let ctx = auth
        .as_ref()
        .ok_or(ApiError::Unauthorized("authentication required".into()))?;

    // 非 worker 角色的代注册是管理操作：viewer/builder token 不得写 worker
    // 注册表（防 suspended/draining 被翻回 online、幽灵 worker 撑爆调度队列）。
    if ctx.role != "worker" {
        require_operator(&auth)?;
    }

    validate_worker_name(&req.name)?;
    validate_worker_arch(&req.arch)?;
    // capacity 上限钳制：仅 >0 检查时 i64::MAX 幽灵 worker 会形成
    // 派发-回收-再派发 的队列 DoS。
    const MAX_WORKER_CAPACITY: i64 = 1024;
    if !(1..=MAX_WORKER_CAPACITY).contains(&req.capacity) {
        return Err(ApiError::Validation(format!(
            "capacity must be in 1..={MAX_WORKER_CAPACITY}, got {cap}",
            cap = req.capacity
        )));
    }

    if ctx.role == "worker" && req.name != ctx.user {
        return Err(ApiError::PermissionDenied(format!(
            "token is bound to worker '{}', cannot register '{}'",
            ctx.user, req.name
        )));
    }

    let worker_id = app
        .state_store
        .upsert_worker(
            &req.name,
            &req.arch,
            req.capacity,
            &req.version,
            "online",
            sanitize_resource_caps(req.resource_caps),
        )
        .await
        .map_err(ApiError::from)?;

    // 重注册说明进程活着：DB 停在 'offline' 时补翻 online；
    // `worker_recover_online` 的 `WHERE status='offline'` 不覆盖
    // suspended/draining 管理员状态（与心跳路径同一约束）。
    if app
        .state_store
        .worker_recover_online(worker_id)
        .await
        .map_err(ApiError::from)?
    {
        tracing::info!(
            worker_id = %worker_id,
            name = %req.name,
            "Worker recovered online on re-register"
        );
    }

    // worker 自身（重）注册 = 进程（重）启动：秒级重启让 reclaimer（要求心跳
    // 超龄）永远看不到它，名下 running assignment 需在此回收（否则 build 永久
    // 卡 building、容量泄漏）。仅限自注册——代注册的存量 worker 进程可能仍
    // 活着，重置 running 会双执行；assigned 行由重启后 poll 重新交付。
    if ctx.role == "worker" {
        let reclaimed = app
            .state_store
            .reclaim_running_assignments_on_register(worker_id)
            .await
            .map_err(ApiError::from)?;
        for (task_id, build_id) in &reclaimed {
            tracing::warn!(
                worker_id = %worker_id,
                name = %req.name,
                task_id = %task_id,
                build_id = ?build_id,
                "Reclaimed running assignment on worker (re-)register"
            );
        }
    }

    // 启动 GC 守卫：口径与 engine::gc::should_skip_orphan_cleanup 同序——先
    // 僵尸修复（crbs_pid 已死不计数；远程构建 crbs_pid=NULL 恒视为存活），
    // 再 count_building_builds。查询失败 → Some(true)（宁可不清理也不误卸
    // 活跃挂载）。
    crbs_core::engine::gc::repair_zombie_builds(&app.state_store).await;
    let has_active_local_builds = match app.state_store.count_building_builds().await {
        Ok(count) => Some(count > 0),
        Err(e) => {
            tracing::warn!(
                worker_id = worker_id,
                error = %e,
                "Failed to count building builds for startup-gc guard; conservatively reporting active builds"
            );
            Some(true)
        }
    };

    Ok(Json(RegisterResponse {
        worker_id,
        status: "registered",
        has_active_local_builds,
    }))
}

// ======== Worker secret 管理 / 删除（operator/admin）========

/// 核心逻辑与审计在 worker::admin 共享模块；此处仅鉴权、错误映射与响应组装。
pub(super) async fn rotate_worker_secret(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<axum::extract::Extension<AuthContext>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ctx = require_operator(&auth)?;
    // 明文一次性返回，与 create_token 等 secret 签发端点口径一致。
    let secret = super::super::admin::rotate_secret(&app.state_store, &ctx.user, &ctx.role, id)
        .await
        .map_err(super::super::admin::WorkerAdminError::into_api_error)?;
    Ok(Json(serde_json::json!({
        "status": "rotated",
        "worker_id": id,
        "secret": secret,
    })))
}

pub(super) async fn revoke_worker_secret(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<axum::extract::Extension<AuthContext>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ctx = require_operator(&auth)?;
    super::super::admin::revoke_secret(&app.state_store, &ctx.user, &ctx.role, id)
        .await
        .map_err(super::super::admin::WorkerAdminError::into_api_error)?;
    Ok(Json(serde_json::json!({
        "status": "revoked",
        "worker_id": id,
    })))
}

pub(super) async fn remove_worker(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<axum::extract::Extension<AuthContext>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ctx = require_operator(&auth)?;
    let name = super::super::admin::remove_worker(&app.state_store, &ctx.user, &ctx.role, id)
        .await
        .map_err(super::super::admin::WorkerAdminError::into_api_error)?;
    Ok(Json(serde_json::json!({
        "status": "removed",
        "worker_id": id,
        "name": name,
    })))
}

// ======== 测试 ========

#[cfg(test)]
mod tests {
    use super::validate_worker_name;

    /// 保留名拒绝：hub 本地车道伪 worker 名不得被外部 worker 注册占用。
    #[test]
    fn worker_name_validation_rejects_reserved_hub_local() {
        assert!(validate_worker_name("w-1").is_ok());
        assert!(validate_worker_name(crbs_core::HUB_LOCAL_WORKER_NAME).is_err());
    }
}
