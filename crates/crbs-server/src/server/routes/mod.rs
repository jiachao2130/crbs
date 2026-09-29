// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! HTTP 路由模块根：子路由声明、审计辅助与管理员门控。

pub(crate) mod admin;
pub(crate) mod artifacts;
pub(crate) mod batches;
pub(crate) mod builds;
pub(crate) mod gc;
pub(crate) mod health;
pub(crate) mod logs;
pub(crate) mod nihao;
pub(crate) mod product;
pub(crate) mod profile;
pub(crate) mod repo;
pub(crate) mod reproducibility;
pub(crate) mod resource_profiles;
pub(crate) mod tasks;
pub(crate) mod ui;

use axum::extract::Extension;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

/// 复现看板口径常量（stats API 与 UI 看板必须同值）：一级组显示预算与缺省
/// 时间窗。单点声明防两份手抄漂移。
pub(crate) const REPLAY_GROUP_LIMIT: usize = 20;
pub(crate) const REPRO_DEFAULT_WINDOW_DAYS: i64 = 30;

/// 审计写失败统一 warn（主操作已提交、审计仅补记的站点）：文案与字段口径
/// 收敛单一出处防调用点漂移；`action` 区分补记来源（多数站点固定 "audit_log"）。
pub(crate) fn warn_audit_log_failure(error: &crbs_core::error::CrbsError, action: &str) {
    tracing::warn!(
        error = %error,
        action = action,
        "audit log write failed (mutation already committed)"
    );
}

/// 管理端点审计写（admin / resource-profile 等管理面站点共用）：失败仅
/// warn——主操作已提交，审计缺口不阻断（见 [`warn_audit_log_failure`]）。
pub(crate) async fn audit_event(
    app: &AppState,
    ctx: &AuthContext,
    action: &str,
    target: Option<&str>,
    detail: Option<&str>,
) {
    if let Err(e) = app
        .state_store
        .audit_log(&ctx.user, &ctx.role, action, target, detail)
        .await
    {
        warn_audit_log_failure(&e, action);
    }
}

/// 仅-admin 端点统一门（匿名 401 / 登录非 admin 403）：管理面共用单一出处。
pub(crate) fn require_admin(auth: Option<Extension<AuthContext>>) -> Result<AuthContext, ApiError> {
    let ctx = auth
        .ok_or_else(|| ApiError::Unauthorized("admin authentication required".into()))?
        .0;
    if !ctx.is_admin() {
        return Err(ApiError::PermissionDenied(
            "only admin can access this endpoint".into(),
        ));
    }
    Ok(ctx)
}
