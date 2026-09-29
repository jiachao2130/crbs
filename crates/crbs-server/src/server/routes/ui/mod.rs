// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Web UI 公开路由（只读仪表盘 + SSE 实时刷新 + 取消按钮）。

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::http::Method;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use tower_http::limit::RequestBodyLimitLayer;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

mod components;
mod error_page;
mod i18n;
mod pages;
mod service;
mod sse;

pub(crate) use service::check_public_access;
/// DB 故障期兜底轮询的退避乘数（CLI 日志流与 SSE 各循环共享同一曲线）。
pub(crate) use sse::sse_db_retry_backoff_multiplier;

/// `state` 供 error_page 中间件派生错误页导航栏的 logout CSRF token。
pub(crate) fn public_router(state: &Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(pages::home::home_page))
        .route("/ui", get(pages::home::home_page))
        .route("/ui/", get(pages::home::home_page))
        // 首页最近任务片段：dashboard SSE 节流拉取换新目标（可见性与首页同口径）。
        .route(
            "/ui/home/recent-tasks",
            get(pages::home::recent_tasks_fragment),
        )
        .route("/ui/favicon.svg", get(components::favicon))
        // SSE 五端点（dashboard/build/task/log/worker 流）HEAD 显式短路 204（复用 preference_head）：
        // axum GET→HEAD 回落会跑完整 GET handler（DB 查 + spawn 空转），显式 `.head()` 让探测/预取零成本拿 2xx。
        .route(
            "/ui/events",
            get(sse::dashboard_sse).head(pages::theme::preference_head),
        )
        .route("/ui/builds", get(pages::builds::list_builds_page))
        .route(
            "/ui/builds/{id}",
            get(pages::builds::build_detail_page).post(pages::builds::cancel_build_submit),
        )
        .route(
            "/ui/builds/{id}/changelog",
            get(pages::changelog::build_changelog_page),
        )
        .route("/ui/builds/{id}/logs", get(pages::builds::build_logs_page))
        .route(
            "/ui/builds/{id}/logs/stream",
            get(sse::log_sse).head(pages::theme::preference_head),
        )
        .route(
            "/ui/builds/{id}/events",
            get(sse::build_sse).head(pages::theme::preference_head),
        )
        .route("/ui/tasks", get(pages::tasks::list_tasks_page))
        // 提交构建页：静态段 new 优先于下方 {id} 参数段。POST multipart 与 API 提交
        // 端点同款双层请求体上限（multipart 提取器默认 2MB 会掐）：2×upload_max + 余量，
        // 供校验失败返回前吸干剩余请求体（drain_multipart_for_error）；先注册路由再套 layer，只作用本子路由。
        .merge({
            let body_limit = crate::server::routes::builds::upload_body_limit_bytes(
                state.server_config.upload_max_size_bytes(),
            );
            Router::new()
                .route(
                    "/ui/tasks/new",
                    get(pages::task_new::new_task_page).post(pages::task_new::new_task_submit),
                )
                .layer(DefaultBodyLimit::max(body_limit))
                .layer(RequestBodyLimitLayer::new(body_limit))
        })
        .route(
            "/ui/tasks/{id}",
            get(pages::tasks::task_detail_page).post(pages::tasks::cancel_task_submit),
        )
        // task 作用域 changelog（胜出子构建 SRPM 优先解析）。
        .route(
            "/ui/tasks/{id}/changelog",
            get(pages::changelog::task_changelog_page),
        )
        .route(
            "/ui/tasks/{id}/rebuild",
            post(pages::tasks::rebuild_task_submit),
        )
        .route(
            "/ui/tasks/{id}/reproduce",
            post(pages::tasks::reproduce_task_submit),
        )
        .route(
            "/ui/tasks/{id}/events",
            get(sse::task_sse).head(pages::theme::preference_head),
        )
        .route("/ui/products", get(pages::products::list_products_page))
        .route(
            "/ui/products/new",
            get(pages::product_editor::new_product_page)
                .post(pages::product_editor::new_product_submit),
        )
        .route(
            "/ui/products/{name}",
            get(pages::products::product_detail_page),
        )
        .route(
            "/ui/products/{name}/profiles.csv",
            get(pages::product_profiles::product_profiles_csv),
        )
        .route(
            "/ui/products/{name}/packages/{source}",
            get(pages::product_profiles::package_profile_page),
        )
        .route(
            "/ui/products/{name}/packages/{source}/floors",
            post(pages::product_profiles::package_floors_post),
        )
        .route(
            "/ui/products/{name}/visibility",
            post(pages::products::product_visibility_post),
        )
        .route(
            "/ui/products/{name}/acl",
            post(pages::products::product_acl_grant),
        )
        .route(
            "/ui/products/{name}/acl/{username}/revoke",
            post(pages::products::product_acl_revoke),
        )
        .route(
            "/ui/products/{name}/transfer",
            post(pages::products::product_transfer_post),
        )
        .route(
            "/ui/products/{name}/rebuild-repo",
            post(pages::products::product_rebuild_repo_post),
        )
        .route(
            "/ui/products/{name}/edit",
            get(pages::product_editor::edit_product_page)
                .post(pages::product_editor::edit_product_submit),
        )
        .route(
            "/ui/products/{name}/history",
            get(pages::products::product_history_page),
        )
        .route(
            "/ui/products/{name}/history/diff",
            get(pages::products::product_history_diff_page),
        )
        .route("/ui/packages", get(pages::packages::package_list_page))
        .route(
            "/ui/packages/{name}",
            get(pages::packages::package_detail_page),
        )
        .route("/ui/search", get(pages::search::search_page))
        .route("/ui/workers", get(pages::workers::list_workers_page))
        .route(
            "/ui/reproducibility",
            get(pages::reproducibility::reproducibility_page),
        )
        .route(
            "/ui/workers/{id}",
            get(pages::workers::worker_detail_page).post(pages::workers::admin_worker_action),
        )
        .route(
            "/ui/workers/{id}/events",
            get(sse::worker_sse).head(pages::theme::preference_head),
        )
        .route(
            "/ui/workers/{id}/remove",
            post(pages::workers::admin_worker_remove),
        )
        // /ui/admin 路径族统一 gate：admin 子 router 单独构建、整体挂 route_layer
        // 后 merge（route_layer 只作用于本子 router，不外溢主链上先注册的公开路由）；
        // 无会话 → 401 / 非 admin → 403 前移至此，handler 内检查（含 CSRF）保留。
        .merge({
            Router::new()
                .route("/ui/admin", get(pages::admin::admin_dashboard_page))
                .route(
                    "/ui/admin/users",
                    get(pages::admin::admin_users_page).post(pages::admin::admin_user_create),
                )
                .route(
                    "/ui/admin/users/{id}",
                    get(pages::admin::admin_user_detail_page),
                )
                .route(
                    "/ui/admin/users/{id}/role",
                    post(pages::admin::admin_user_set_role),
                )
                .route(
                    "/ui/admin/users/{id}/status",
                    post(pages::admin::admin_user_set_status),
                )
                .route(
                    "/ui/admin/users/{id}/password",
                    post(pages::admin::admin_user_reset_password),
                )
                .route(
                    "/ui/admin/users/{id}/tokens",
                    post(pages::admin::admin_token_create),
                )
                .route(
                    "/ui/admin/users/{id}/tokens/{tid}/revoke",
                    post(pages::admin::admin_token_revoke),
                )
                .route(
                    "/ui/admin/users/{id}/acl",
                    post(pages::admin::admin_acl_grant),
                )
                .route(
                    "/ui/admin/users/{id}/acl/{product}/revoke",
                    post(pages::admin::admin_acl_revoke),
                )
                .route("/ui/admin/audit", get(pages::admin::admin_audit_page))
                .route(
                    "/ui/admin/settings",
                    get(pages::settings::settings_page).post(pages::settings::settings_submit),
                )
                .route_layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    admin_gate_middleware,
                ))
        })
        // GC 页挂 /ui/admin 前缀但门槛是 operator（同 API can_gc()），不经上方 admin 网关：独立子 router 挂 operator 网关。
        .merge({
            Router::new()
                .route(
                    "/ui/admin/gc",
                    get(pages::gc::gc_page).post(pages::gc::gc_trigger_post),
                )
                .route_layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    operator_gate_middleware,
                ))
        })
        // 批次页（/ui/batches）：门槛 operator（同 API ensure_operator），独立 operator 网关同 GC 页。
        .merge({
            Router::new()
                .route("/ui/batches", get(pages::batches::list_batches_page))
                .route(
                    "/ui/batches/{id}",
                    get(pages::batches::batch_detail_page)
                        .post(pages::batches::cancel_batch_submit),
                )
                .route_layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    operator_gate_middleware,
                ))
        })
        .route("/ui/logout", post(pages::auth::logout_submit))
        .route("/ui/me", get(pages::me::me_page))
        .route("/ui/me/password", post(pages::me::me_password_submit))
        .route(
            "/ui/me/sessions/{sid}/revoke",
            post(pages::me::me_session_revoke),
        )
        .route(
            "/ui/me/sessions/revoke-all",
            post(pages::me::me_sessions_revoke_all),
        )
        .route("/ui/me/tokens", post(pages::me::me_token_create))
        .route(
            "/ui/me/tokens/{tid}/revoke",
            post(pages::me::me_token_revoke),
        )
        // 登录双模式：GET 单页双表单；POST 拆两目标（nonce cookie Path=/ui/login 前缀同时覆盖两个 POST）。
        .route("/ui/login", get(pages::auth::login_page))
        .route(
            "/ui/login/password",
            post(pages::auth::login_password_submit),
        )
        .route("/ui/login/token", post(pages::auth::login_token_submit))
        // 注册：开关门控 + nonce/CSRF + 限流。
        .route(
            "/ui/register",
            get(pages::register::register_page).post(pages::register::register_submit),
        )
        // 主题/语言/分页偏好三端点（公开段）：POST 表单改 cookie + 303，不收 GET
        // （prefetch 误触发/代理缓存副作用面；分级 CSRF 见 theme::require_preference_csrf）。
        .route("/ui/set-theme", post(pages::theme::set_theme))
        .route("/ui/set-lang", post(i18n::set_lang))
        .route("/ui/set-page-size", post(pages::page_size::set_page_size))
        // 404/405 fallback 渲染标准 HTML 错误页：axum 默认两者都是空体且不经过
        // error_page_middleware（只重写 JSON）；都在 `.layer` 前注册以经过 UI 中间件层。
        .fallback(error_page::ui_not_found_fallback)
        .method_not_allowed_fallback(error_page::ui_method_not_allowed_fallback)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            error_page::error_page_middleware,
        ))
        // ?lang= 覆盖头必须注册在 error_page 层之后（后注册 = 更外层 = 先执行），错误页渲染与各 handler 才能看到。
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            i18n::lang_query_middleware,
        ))
}

/// /ui/admin 路径族网关：会话存在且为 admin 才放行，错误口径与 handler 侧
/// `require_admin_session` 一致（error_page 中间件把 JSON 信封渲染成 HTML 错误页）。
/// 只拦 GET/POST，其余方法放行给 axum 方法路由产出 405（route_inventory 门控
/// 探测依赖该语义）；HEAD 经 GET 派生落放行分支，仍由 handler 内 `require_admin_session` 把关。
async fn admin_gate_middleware(
    auth: Option<axum::extract::Extension<AuthContext>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();
    if method != Method::GET && method != Method::POST {
        return next.run(req).await;
    }
    match auth {
        Some(ext) if ext.0.is_admin() => next.run(req).await,
        Some(_) => {
            ApiError::PermissionDenied("only admin can perform this action".into()).into_response()
        }
        None => ApiError::Unauthorized("admin authentication required".into()).into_response(),
    }
}

/// /ui/admin/gc 网关：门槛是 operator 或 admin（与页面 handler `require_operator_page`、
/// API `can_gc()` 同谓词）。匿名请求放行给 handler：该页 CSRF 校验先于身份判定
/// （匿名 POST 坏 CSRF 得 403 而非 401），网关只前移"已认证但权限不足"的拒绝。
async fn operator_gate_middleware(
    auth: Option<axum::extract::Extension<AuthContext>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();
    if method != Method::GET && method != Method::POST {
        return next.run(req).await;
    }
    if let Some(ext) = auth {
        if !ext.0.is_operator() {
            return ApiError::PermissionDenied("operator privileges required".into())
                .into_response();
        }
    }
    next.run(req).await
}
