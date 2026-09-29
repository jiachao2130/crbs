// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! Worker API 路由：注册、心跳、取件、结果与日志上报。

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

mod dispatch;
mod heartbeat;
mod logs;
mod registration;
mod results;

use dispatch::poll_tasks;
use heartbeat::worker_heartbeat;
use logs::{report_logs, REPORT_LOGS_BODY_HEADROOM};
use registration::{
    list_workers, register_worker, remove_worker, revoke_worker_secret, rotate_worker_secret,
};
pub(crate) use results::evict_log_buffer_if_persisted;
use results::report_result;
/// 校验 role=worker：未认证 401、已认证角色不足 403。
fn require_worker_role(
    auth: &Option<axum::extract::Extension<AuthContext>>,
) -> Result<&AuthContext, ApiError> {
    match auth.as_ref() {
        Some(ctx) if ctx.role == "worker" => Ok(ctx),
        Some(_) => Err(ApiError::PermissionDenied(
            "worker endpoints require role=worker".into(),
        )),
        None => Err(ApiError::Unauthorized(
            "authentication required to access worker endpoints".into(),
        )),
    }
}

pub(super) fn require_own_worker(
    auth: &Option<axum::extract::Extension<AuthContext>>,
    path_worker_id: i64,
) -> Result<&AuthContext, ApiError> {
    let ctx = require_worker_role(auth)?;
    match ctx.worker_id {
        Some(id) if id == path_worker_id => Ok(ctx),
        _ => Err(ApiError::PermissionDenied(
            "worker can only access its own resources".into(),
        )),
    }
}

pub(super) fn require_operator(
    auth: &Option<axum::extract::Extension<AuthContext>>,
) -> Result<&AuthContext, ApiError> {
    // 未认证 → 401（403 保留给"已认证但角色不足"，与 require_admin 口径一致）。
    let ctx = auth
        .as_ref()
        .ok_or(ApiError::Unauthorized("authentication required".into()))?;
    if !ctx.is_operator() {
        return Err(ApiError::PermissionDenied(
            "requires operator or admin role".into(),
        ));
    }
    Ok(ctx)
}

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/workers", get(list_workers))
        .route("/api/v1/workers/register", post(register_worker))
        .route("/api/v1/workers/{id}/heartbeat", post(worker_heartbeat))
        .route("/api/v1/workers/{id}/assignments", get(poll_tasks))
        .route(
            "/api/v1/workers/{id}/assignments/{assignment_id}/result",
            post(report_result),
        )
        .route(
            "/api/v1/workers/{id}/assignments/{assignment_id}/logs",
            post(report_logs).layer(DefaultBodyLimit::max(
                crate::server::log_buffer::MAX_LOG_CHUNK_BYTES + REPORT_LOGS_BODY_HEADROOM,
            )),
        )
        .route(
            "/api/v1/workers/{id}/secret/rotate",
            post(rotate_worker_secret),
        )
        .route(
            "/api/v1/workers/{id}/secret/revoke",
            post(revoke_worker_secret),
        )
        .route("/api/v1/workers/{id}/remove", post(remove_worker))
}

// ======== 列出 Worker ========

#[cfg(test)]
mod tests;
