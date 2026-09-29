// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! API Token 认证（Bearer）与管理。
//!
//! 默认启用认证：除 health/version 外所有端点需 `Authorization: Bearer <token>`。
//! - `crbs_tok_...`：DB-backed 用户 token，查 `user_tokens` 表
//! - `crbs_wkr_...`：Worker secret，查 `workers.secret_hash`
//!
//! UI 会话凭据 `crbs_sess_...` **永不被 Bearer 接受**：只经 `crbs_session` cookie
//! 走 [`resolve_session_value`]，服务 UI 页面与 GET 下载；API 写方法只认
//! Authorization 头（cookie 一律 401），无上述前缀的 token 一律 401。

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method};
use axum::middleware::Next;
use axum::response::Response;

use crbs_core::auth::secret::{Secret, SecretKind};

use crate::server::error::ApiError;
use crate::server::state::AppState;

mod cache;
pub(crate) use cache::AuthCache;

pub(crate) mod visibility;

/// 认证中间件共享状态：仅持有 `AppState`（查 worker secret / DB 用户 token）。
#[derive(Clone)]
pub(crate) struct AuthMiddlewareState {
    pub app_state: Arc<AppState>,
}

/// 判断请求是否为 `/api/` 前缀的写方法（非 GET/HEAD/OPTIONS）。
fn is_api_write(method: &Method, path: &str) -> bool {
    path.starts_with("/api/") && !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// 从 `Authorization: Bearer <token>` 头提取 token（大小写兼容 `Bearer`/`bearer`）。
fn bearer_token_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| {
            h.strip_prefix("Bearer ")
                .or_else(|| h.strip_prefix("bearer "))
        })
}

/// 认证中间件：提取 Bearer token 按前缀分流。`crbs_wkr_` 查
/// `workers.secret_hash`（角色固定 `worker`）；`crbs_tok_` 查 `user_tokens`
///（按 role / product_acl 构造上下文）；其他前缀 401。成功注入 `AuthContext`，
/// 失败 401；StateStore 故障必须 503（fail-closed：绝不因 DB 错误放行、不得
/// 误报成 "invalid token"）。
///
/// CSRF 收敛：`/api/` 写方法（非 GET/HEAD/OPTIONS）只认 Authorization 头，
/// cookie-only 一律 401——跨站表单可自动带 Cookie 但带不了自定义头。Cookie
/// 认证仅面向 Web UI 会话与浏览器 GET 下载（`optional_auth_middleware`）。
pub(crate) async fn auth_middleware(
    State(auth_state): State<Arc<AuthMiddlewareState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Err = 认证后端故障（5xx），Ok(None) 才是未提供/无效 token（401），不可混同。
    let ctx = if is_api_write(request.method(), request.uri().path()) {
        match bearer_token_from_headers(request.headers()) {
            Some(token) => resolve_token_value(&auth_state, token).await,
            None => {
                return Err(ApiError::Unauthorized(
                    "API write requests require the Authorization header; \
                     cookie-based authentication is not accepted for API write methods"
                        .into(),
                ));
            }
        }
    } else {
        resolve_token(&auth_state, request.headers()).await
    };

    let ctx = ctx?.ok_or_else(|| {
        ApiError::Unauthorized("missing or invalid Authorization: Bearer token".into())
    })?;

    request.extensions_mut().insert(ctx);
    Ok(next.run(request).await)
}

/// 可选认证中间件：按 `resolve_token` 三级优先链解析（`Authorization` Bearer →
/// `crbs_session` Cookie → `crbs_token` Cookie），成功注入 `AuthContext`，
/// 无/无效注入 `None` 不强制 401；持有 token 但 DB 校验失败仍 503
///（fail-closed，不静默降级为匿名，与强制路径同口径）。
pub(crate) async fn optional_auth_middleware(
    State(auth_state): State<Arc<AuthMiddlewareState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let ctx = resolve_token(&auth_state, request.headers()).await?;
    if let Some(ctx) = ctx {
        request.extensions_mut().insert(ctx);
    }
    Ok(next.run(request).await)
}

/// 从请求头解析凭据并返回 `AuthContext`（UI / 浏览器 GET 链路）。优先级：
/// 1. `Authorization: Bearer`（最高；仅 `crbs_tok_`/`crbs_wkr_`，`crbs_sess_` 永不被 Bearer 接受）
/// 2. `Cookie: crbs_session=`：session 有效则忽略 crbs_token；无效（撤销/过期/
///    坏格式）不阻断请求，继续走 crbs_token——请求级优先链，无"模式锁定"
/// 3. `Cookie: crbs_token=`（token 粘贴登录）
///
/// 无/无效凭据返回 `Ok(None)`，StateStore 故障返回 `Err`（5xx）。cookie 路径仅
/// 适用 GET/HEAD，API 写方法的 cookie 由 [`auth_middleware`] 显式拒绝。cookie
/// 解析复用 `csrf.rs` 提取函数避免两份手写解析漂移（空值 `crbs_token=` 在两条
/// 路径下同样过不了前缀校验，行为等价）。
pub(crate) async fn resolve_token(
    auth_state: &Arc<AuthMiddlewareState>,
    headers: &HeaderMap,
) -> Result<Option<AuthContext>, ApiError> {
    if let Some(bearer) = bearer_token_from_headers(headers) {
        return resolve_token_value(auth_state, bearer).await;
    }
    if let Some(session_value) = crate::server::csrf::session_cookie_from_headers(headers) {
        if let Some(ctx) = resolve_session_value(&auth_state.app_state, &session_value).await? {
            return Ok(Some(ctx));
        }
    }
    let Some(token) = crate::server::csrf::token_cookie_from_headers(headers) else {
        return Ok(None);
    };
    resolve_token_value(auth_state, &token).await
}

/// 解析单个 token 字符串并返回 `AuthContext`。`crbs_sess_` 前缀（UI 会话）永远
/// 返回未认证（会话只经 `crbs_session` cookie 走 [`resolve_session_value`]，
/// 隔离"浏览器凭据进 API 头"的误用面）。
pub(crate) async fn resolve_token_value(
    auth_state: &Arc<AuthMiddlewareState>,
    token: &str,
) -> Result<Option<AuthContext>, ApiError> {
    match SecretKind::from_prefix(token) {
        Some(SecretKind::WorkerSecret) => resolve_worker_secret(&auth_state.app_state, token).await,
        Some(SecretKind::UserToken) => resolve_user_token(&auth_state.app_state, token).await,
        // crbs_sess_ 是凭据类型错误 → Ok(None)/401，非后端故障（5xx）。
        Some(SecretKind::Session) => Ok(None),
        None => Ok(None),
    }
}

/// 校验 `crbs_session` cookie 值并返回 `AuthContext`。判定链：格式（前缀+长度）
/// → hash 查 `sessions` 表 → 未撤销 → 未过期（绝对过期，RFC3339）→ 用户
/// active；任一环失败 `Ok(None)`，StateStore 故障 `Err`（5xx，与 token 路径
/// 同口径）。hash 派生值为 key 走 [`AuthCache`]（代数相同且 TTL 内命中零查询），
/// 未命中回源 [`cache::resolve_session_value_uncached`]（3 条查询）并回填正向
/// 结果，凭据原文不进缓存。`AuthContext` 与 token 路径同构，`token_expires_at`
/// 填会话绝对过期时间。
pub(crate) async fn resolve_session_value(
    app_state: &AppState,
    value: &str,
) -> Result<Option<AuthContext>, ApiError> {
    let Ok(secret) = Secret::parse(value) else {
        return Ok(None);
    };
    let hash = secret.hash();
    // 代数在回源**之前**读取、回填按同一代数记账：回源期间落库的用户域写
    // 会 bump 代数，本快照在下一次请求即失配回源，不会把陈旧身份染成新代数。
    let generation = app_state.state_store.user_generation();
    let key = cache::CacheKey::session(&hash);
    if let Some(ctx) = app_state.auth_cache.lookup(&key, generation) {
        return Ok(Some(ctx));
    }
    match cache::resolve_session_value_uncached(app_state, hash.as_str()).await? {
        Some(ctx) => {
            app_state.auth_cache.fill(key, generation, ctx.clone());
            Ok(Some(ctx))
        }
        // 负结果不缓存：无效/撤销/过期/禁用逐请求精确判定，新凭据不被旧负缓存遮蔽
        None => Ok(None),
    }
}

/// 使用 `AppState` 校验单个 token：成功 `Ok(Some)`；无效 `Ok(None)`（按登录
/// 失败处理）；StateStore 故障 `Err`（[`resolve_token_value`] 已映射 503）经
/// `?` 传播为全局 5xx——DB 瞬断不得误报成"token 无效"。
pub(crate) async fn authenticate_token(
    app_state: &Arc<AppState>,
    token: &str,
) -> Result<Option<AuthContext>, ApiError> {
    let auth_state = Arc::new(AuthMiddlewareState {
        app_state: app_state.clone(),
    });
    resolve_token_value(&auth_state, token).await
}

/// 已认证用户上下文：角色、用户标识与产品 ACL，供各端点做权限检查。
#[derive(Debug, Clone, Default)]
pub(crate) struct AuthContext {
    pub user: String,
    pub role: String,
    /// DB 用户 ID；worker secret 认证时为 `None`。
    pub user_id: Option<i64>,
    /// Worker ID；仅 worker secret 认证时填充。
    pub worker_id: Option<i64>,
    /// 允许访问的产品列表。空表示无显式产品限制（无 ACL 记录时不限制）。
    pub allowed_products: Vec<String>,
    /// DB-backed token 的过期时间；worker secret 为 `None`。
    pub token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl AuthContext {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
    pub fn is_operator(&self) -> bool {
        self.role == "operator" || self.is_admin()
    }
    pub fn is_builder(&self) -> bool {
        self.role == "builder" || self.is_operator()
    }

    pub fn can_submit(&self) -> bool {
        self.is_builder()
    }

    pub fn can_cancel(&self, build_user: &str) -> bool {
        // 空 user = 无提交者的遗留记录，"本人"分支无从命中，仅 operator/admin 可取消。
        if build_user.is_empty() {
            return self.is_operator();
        }
        self.is_operator() || self.user == build_user
    }
    pub fn can_gc(&self) -> bool {
        self.is_operator()
    }
    /// 能否修改构建优先级（PATCH priority）：operator 及以上，与提交侧 priority=2 同一角色门槛。
    pub fn can_priority(&self) -> bool {
        self.is_operator()
    }
    /// 能否管理产品（init/delete）
    pub fn can_manage_product(&self) -> bool {
        self.is_admin()
    }
}

/// 查 worker secret hash，命中返回 worker 角色的 `AuthContext`；`Ok(None)` =
/// 格式错误或 hash 不匹配（401），StateStore 故障 `Err`（5xx）。
///
/// hash 派生值为 key 走 [`AuthCache`]（与 user token / session 同形态，TTL 内
/// 命中零查询），未命中回源 [`cache::resolve_worker_secret_uncached`]（1 条
/// 查询）并回填正向结果，凭据原文不进缓存。失效：改 secret→身份映射的写
///（`upsert_worker` / `set_worker_secret` / `clear_worker_secret` /
/// `delete_worker_if_offline` 成功）bump 用户域代数，下一请求即回源；心跳 /
/// touch / mark_offline 不 bump（映射未变，快照仍正确）。兜底 TTL（10s）：
/// 删除/换钥后旧凭据 401 最多延迟 10s。
pub(crate) async fn resolve_worker_secret(
    app_state: &AppState,
    token: &str,
) -> Result<Option<AuthContext>, ApiError> {
    let Ok(secret) = Secret::parse(token) else {
        return Ok(None);
    };
    let hash = secret.hash();
    // 与 session 路径同一记账顺序：代数先读、回填沿用；worker 域写复用
    // 同一计数器（宁多勿漏，连带用户凭据多回源一次无害）。
    let generation = app_state.state_store.user_generation();
    let key = cache::CacheKey::worker_secret(&hash);
    if let Some(ctx) = app_state.auth_cache.lookup(&key, generation) {
        return Ok(Some(ctx));
    }
    match cache::resolve_worker_secret_uncached(app_state, hash.as_str()).await? {
        Some(ctx) => {
            app_state.auth_cache.fill(key, generation, ctx.clone());
            Ok(Some(ctx))
        }
        // 负结果不缓存：无效 secret 逐请求精确判定，新注册 worker 不被负缓存遮蔽
        None => Ok(None),
    }
}

/// 查 DB-backed 用户 token，命中返回带 product ACL 的 `AuthContext`；`Ok(None)`
/// = token 无效/撤销/过期/用户被禁用（401），StateStore 故障 `Err`（5xx）。hash
/// 派生值为 key 走 [`AuthCache`]（代数相同且 TTL 内命中零查询），未命中回源
/// [`cache::resolve_user_token_uncached`]（3 条查询）并回填，凭据原文不进缓存。
pub(crate) async fn resolve_user_token(
    app_state: &AppState,
    token: &str,
) -> Result<Option<AuthContext>, ApiError> {
    let Ok(secret) = Secret::parse(token) else {
        return Ok(None);
    };
    let hash = secret.hash();
    // 与 session 路径同一记账顺序：代数先读、回填沿用。
    let generation = app_state.state_store.user_generation();
    let key = cache::CacheKey::user_token(&hash);
    if let Some(ctx) = app_state.auth_cache.lookup(&key, generation) {
        return Ok(Some(ctx));
    }
    match cache::resolve_user_token_uncached(app_state, hash.as_str()).await? {
        Some(ctx) => {
            app_state.auth_cache.fill(key, generation, ctx.clone());
            Ok(Some(ctx))
        }
        // 负结果不缓存：无效/撤销/过期/禁用凭据逐请求精确判定
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crbs_core::StateStore;

    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    #[test]
    fn is_api_write_classifies_methods_and_paths() {
        for m in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            assert!(is_api_write(&m, "/api/v1/workers/1/remove"), "{m}");
        }
        for m in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(!is_api_write(&m, "/api/v1/builds/1/artifacts"), "{m}");
        }
        // UI 路由的 POST（表单）不走 Authorization-only 分支（由 CSRF 校验防护）。
        assert!(!is_api_write(&Method::POST, "/ui/logout"));
    }

    /// cookie-only 的 API 写请求 → 401，且错误信息说明需要 Authorization 头。
    #[tokio::test]
    async fn api_write_rejects_cookie_only_authentication() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let user_id = store.create_user("cookie-admin", "admin").await.unwrap();
        let secret = Secret::generate(SecretKind::UserToken).unwrap();
        store
            .create_user_token(
                user_id,
                None,
                crbs_core::auth::secret::SecretHash::from_plain(secret.as_str()).as_str(),
                None,
            )
            .await
            .unwrap();

        let app_state = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_worker(app_state).await;

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/test")
                    .header("Cookie", format!("crbs_token={}", secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes).into_owned();
        assert!(
            body.contains("Authorization header"),
            "error should explain the Authorization header requirement: {body}"
        );

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/test")
                    .header("Cookie", format!("crbs_token={}", secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    async fn test_router_with_worker(app_state: Arc<AppState>) -> Router<()> {
        let auth_state = Arc::new(AuthMiddlewareState { app_state });
        Router::<Arc<AuthMiddlewareState>>::new()
            .route("/test", get(|| async { "ok" }))
            // /api/ 前缀 + any：命中 is_api_write 判定，且避免 GET-only 把 POST 短路成 405 绕过中间件。
            .route("/api/v1/test", axum::routing::any(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                auth_state.clone(),
                auth_middleware,
            ))
            .with_state(auth_state)
    }

    /// 构造回显 `AuthContext.user` 的测试路由：双 cookie 优先级断言需区分
    /// 认证的是"谁"，固定 "ok" 做不到（写拒绝语义由 test_router_with_worker 覆盖）。
    async fn test_router_with_identity(app_state: Arc<AppState>) -> Router<()> {
        async fn whoami(axum::Extension(ctx): axum::Extension<AuthContext>) -> String {
            ctx.user
        }
        let auth_state = Arc::new(AuthMiddlewareState { app_state });
        Router::<Arc<AuthMiddlewareState>>::new()
            .route("/test", get(whoami))
            .layer(axum::middleware::from_fn_with_state(
                auth_state.clone(),
                auth_middleware,
            ))
            .with_state(auth_state)
    }

    /// 建用户 + 会话行，返回 (用户名, 明文 session Secret)。
    async fn seed_session(
        store: &Arc<StateStore>,
        name: &str,
        expires: chrono::DateTime<chrono::Utc>,
    ) -> (String, Secret) {
        let user_id = store.create_user(name, "builder").await.unwrap();
        let secret = Secret::generate(SecretKind::Session).unwrap();
        store
            .create_session(
                user_id,
                secret.hash().as_str(),
                &expires.to_rfc3339(),
                Some("test-agent"),
            )
            .await
            .unwrap();
        (name.to_string(), secret)
    }

    /// `crbs_sess_` 永不被 API Bearer 接受（GET/POST 都 401，即使 DB 有会话行）。
    #[tokio::test]
    async fn bearer_session_prefix_always_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let (_name, secret) = seed_session(
            &store,
            "alice",
            chrono::Utc::now() + chrono::Duration::days(7),
        )
        .await;

        let app_state = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_worker(app_state).await;

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/test")
                    .header("Authorization", format!("Bearer {}", secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    /// crbs_session cookie 认证 GET（UI 页面 / 浏览器下载同链路）；API 写仍 401。
    #[tokio::test]
    async fn session_cookie_authenticates_get_but_not_api_write() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let (_name, secret) = seed_session(
            &store,
            "alice",
            chrono::Utc::now() + chrono::Duration::days(7),
        )
        .await;

        let app_state = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_worker(app_state).await;
        let cookie = format!("crbs_session={}", secret.as_str());

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/test")
                    .header("Cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    /// 优先级钉住：双 cookie 下 session 有效只认 session（alice），撤销后回落 crbs_token（bob）——请求级优先链。
    #[tokio::test]
    async fn session_priority_over_token_cookie_and_fallback_when_revoked() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let (_alice, session_secret) = seed_session(
            &store,
            "alice",
            chrono::Utc::now() + chrono::Duration::days(7),
        )
        .await;

        let bob_id = store.create_user("bob", "builder").await.unwrap();
        let bob_token = Secret::generate(SecretKind::UserToken).unwrap();
        store
            .create_user_token(
                bob_id,
                None,
                crbs_core::auth::secret::SecretHash::from_plain(bob_token.as_str()).as_str(),
                None,
            )
            .await
            .unwrap();

        let app_state = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_identity(app_state).await;

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header(
                        "Cookie",
                        format!(
                            "crbs_session={}; crbs_token={}",
                            session_secret.as_str(),
                            bob_token.as_str()
                        ),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), b"alice", "A2: valid session must win");

        let session_row = store
            .find_session_by_hash(session_secret.hash().as_str())
            .await
            .unwrap()
            .unwrap();
        store.revoke_session(session_row.id).await.unwrap();
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header(
                        "Cookie",
                        format!(
                            "crbs_session={}; crbs_token={}",
                            session_secret.as_str(),
                            bob_token.as_str()
                        ),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), b"bob", "invalid session falls back to token");
    }

    /// 过期 session 不认证；用户被禁用后 session 立即失效。
    #[tokio::test]
    async fn expired_or_disabled_session_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let (_expired_name, expired_secret) = seed_session(
            &store,
            "carol",
            chrono::Utc::now() - chrono::Duration::hours(1),
        )
        .await;

        let app_state = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_worker(app_state).await;

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header(
                        "Cookie",
                        format!("crbs_session={}", expired_secret.as_str()),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);

        let (_name, active_secret) = seed_session(
            &store,
            "dave",
            chrono::Utc::now() + chrono::Duration::days(7),
        )
        .await;
        let dave_id = store.find_user_by_name("dave").await.unwrap().unwrap().id;
        store.set_user_status(dave_id, "disabled").await.unwrap();
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Cookie", format!("crbs_session={}", active_secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn middleware_accepts_valid_worker_secret() {
        use crbs_core::auth::secret::{Secret, SecretKind};

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let worker_id = store
            .upsert_worker("w1", "x86_64", 1, "0.15.0-dev", "online", None)
            .await
            .unwrap();
        let secret = Secret::generate(SecretKind::WorkerSecret).unwrap();
        store
            .set_worker_secret(worker_id, secret.hash().as_str())
            .await
            .unwrap();

        let app_state = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_worker(app_state).await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn middleware_rejects_worker_secret_not_in_db() {
        use crbs_core::auth::secret::{Secret, SecretKind};

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let app_state = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_worker(app_state).await;

        let secret = Secret::generate(SecretKind::WorkerSecret).unwrap();
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn middleware_rejects_malformed_worker_secret() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let app_state = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_worker(app_state).await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", "Bearer crbs_wkr_short")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    /// StateStore 故障（DB 瞬断）→ 503 而非 401：token 有效只是查库失败，不得丢失语义成 "invalid token"。
    #[tokio::test]
    async fn middleware_maps_state_store_failure_to_503_not_401() {
        use crbs_core::auth::secret::{Secret, SecretHash, SecretKind};

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());

        let user_id = store.create_user("alice", "builder").await.unwrap();
        let user_secret = Secret::generate(SecretKind::UserToken).unwrap();
        store
            .create_user_token(
                user_id,
                None,
                SecretHash::from_plain(user_secret.as_str()).as_str(),
                None,
            )
            .await
            .unwrap();
        let worker_secret = Secret::generate(SecretKind::WorkerSecret).unwrap();

        let app_state = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_worker(app_state).await;

        store.pool().close().await;

        for token in [worker_secret.as_str(), user_secret.as_str()] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/test")
                        .header("Authorization", format!("Bearer {}", token))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "DB failure must surface as 5xx, not 401"
            );
        }
    }

    /// authenticate_token 的 DB 故障必须返回 `Err`（503 形态）而非 `Ok(None)`——
    /// 后端故障不得吞成"token 无效"。
    #[tokio::test]
    async fn authenticate_token_maps_state_store_failure_to_err() {
        use crbs_core::auth::secret::{Secret, SecretKind};

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let secret = Secret::generate(SecretKind::UserToken).unwrap();

        let app_state = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));

        store.pool().close().await;

        let result = authenticate_token(&app_state, secret.as_str()).await;
        assert!(
            matches!(
                result,
                Err(crate::server::error::ApiError::ServiceUnavailable(_))
            ),
            "DB failure must propagate as 5xx, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn middleware_accepts_valid_db_user_token() {
        use crbs_core::auth::secret::{Secret, SecretHash, SecretKind};

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let user_id = store.create_user("alice", "builder").await.unwrap();
        let secret = Secret::generate(SecretKind::UserToken).unwrap();
        store
            .create_user_token(
                user_id,
                Some("laptop"),
                SecretHash::from_plain(secret.as_str()).as_str(),
                None,
            )
            .await
            .unwrap();

        let app_state = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_worker(app_state).await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn middleware_rejects_revoked_db_user_token() {
        use crbs_core::auth::secret::{Secret, SecretHash, SecretKind};

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let user_id = store.create_user("alice", "builder").await.unwrap();
        let secret = Secret::generate(SecretKind::UserToken).unwrap();
        let token_id = store
            .create_user_token(
                user_id,
                None,
                SecretHash::from_plain(secret.as_str()).as_str(),
                None,
            )
            .await
            .unwrap();
        store.revoke_user_token(token_id).await.unwrap();

        let app_state = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_worker(app_state).await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn middleware_rejects_expired_db_user_token() {
        use crbs_core::auth::secret::{Secret, SecretHash, SecretKind};

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let user_id = store.create_user("alice", "builder").await.unwrap();
        let secret = Secret::generate(SecretKind::UserToken).unwrap();
        let expired = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        store
            .create_user_token(
                user_id,
                None,
                SecretHash::from_plain(secret.as_str()).as_str(),
                Some(&expired),
            )
            .await
            .unwrap();

        let app_state = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_worker(app_state).await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn middleware_accepts_unexpired_db_user_token() {
        use crbs_core::auth::secret::{Secret, SecretHash, SecretKind};

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let user_id = store.create_user("alice", "builder").await.unwrap();
        let secret = Secret::generate(SecretKind::UserToken).unwrap();
        let future = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        store
            .create_user_token(
                user_id,
                None,
                SecretHash::from_plain(secret.as_str()).as_str(),
                Some(&future),
            )
            .await
            .unwrap();

        let app_state = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_worker(app_state).await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn middleware_rejects_disabled_db_user() {
        use crbs_core::auth::secret::{Secret, SecretHash, SecretKind};

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let user_id = store.create_user("alice", "builder").await.unwrap();
        let secret = Secret::generate(SecretKind::UserToken).unwrap();
        store
            .create_user_token(
                user_id,
                None,
                SecretHash::from_plain(secret.as_str()).as_str(),
                None,
            )
            .await
            .unwrap();
        store.set_user_status(user_id, "disabled").await.unwrap();

        let app_state = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_worker(app_state).await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    /// 建用户 + 用户 token，返回 (user_id, 明文 token Secret)。
    async fn seed_user_token(store: &Arc<StateStore>, name: &str, role: &str) -> (i64, Secret) {
        let user_id = store.create_user(name, role).await.unwrap();
        let secret = Secret::generate(SecretKind::UserToken).unwrap();
        store
            .create_user_token(
                user_id,
                None,
                crbs_core::auth::secret::SecretHash::from_plain(secret.as_str()).as_str(),
                None,
            )
            .await
            .unwrap();
        (user_id, secret)
    }

    /// Bearer 认证 GET /test，断言 200 并返回回显身份串。
    async fn get_identity(router: &Router<()>, token: &Secret) -> String {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", token.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8_lossy(&body).into_owned()
    }

    /// 构造回显 `user:role:allowed_products` 的路由（缓存失效测试需区分角色/ACL 维度）。
    async fn test_router_with_profile(app_state: Arc<AppState>) -> Router<()> {
        async fn whoami(axum::Extension(ctx): axum::Extension<AuthContext>) -> String {
            format!(
                "{}:{}:{}",
                ctx.user,
                ctx.role,
                ctx.allowed_products.join(",")
            )
        }
        let auth_state = Arc::new(AuthMiddlewareState { app_state });
        Router::<Arc<AuthMiddlewareState>>::new()
            .route("/test", get(whoami))
            .layer(axum::middleware::from_fn_with_state(
                auth_state.clone(),
                auth_middleware,
            ))
            .with_state(auth_state)
    }

    /// 同凭据二连请求只回源一次：第二次命中缓存（回源计数不涨），身份一致。
    #[tokio::test]
    async fn same_credential_second_request_served_from_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let (_id, secret) = seed_user_token(&store, "alice", "builder").await;

        let app_state = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_profile(app_state.clone()).await;

        assert_eq!(get_identity(&router, &secret).await, "alice:builder:");
        assert_eq!(app_state.auth_cache.rebuild_count(), 1);

        assert_eq!(get_identity(&router, &secret).await, "alice:builder:");
        assert_eq!(
            app_state.auth_cache.rebuild_count(),
            1,
            "second request must be served from cache, not re-sourced"
        );
    }

    /// 角色变更即时生效：set_user_role bump 代数 → 下一请求即新身份。
    #[tokio::test]
    async fn role_change_is_visible_on_next_request() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let (alice, secret) = seed_user_token(&store, "alice", "builder").await;

        let app_state = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_profile(app_state.clone()).await;

        assert_eq!(get_identity(&router, &secret).await, "alice:builder:");

        store.set_user_role(alice, "viewer").await.unwrap();

        assert_eq!(
            get_identity(&router, &secret).await,
            "alice:viewer:",
            "role change must take effect on the very next request"
        );
        assert_eq!(
            app_state.auth_cache.rebuild_count(),
            2,
            "generation mismatch must force exactly one re-source"
        );
    }

    /// ACL 撤销即时生效：revoke_product_acl bump 代数 → 下一请求 allowed_products 已清空。
    #[tokio::test]
    async fn acl_revoke_is_visible_on_next_request() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let (alice, secret) = seed_user_token(&store, "alice", "builder").await;
        store
            .create_product(crbs_core::CreateProductInput {
                name: "foo",
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
        store.grant_product_acl(alice, "foo").await.unwrap();

        let app_state = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_profile(app_state.clone()).await;

        assert_eq!(get_identity(&router, &secret).await, "alice:builder:foo");

        store.revoke_product_acl(alice, "foo").await.unwrap();

        assert_eq!(
            get_identity(&router, &secret).await,
            "alice:builder:",
            "ACL revoke must take effect on the very next request"
        );
        assert_eq!(app_state.auth_cache.rebuild_count(), 2);
    }

    /// TTL 过期回源：代数未变也须在 TTL 后重建（兜底收口遗漏的写路径）。
    /// sqlx acquire 超时定时器与 tokio paused time 冲突（快进误触超时），故短 TTL + 真实短睡眠。
    #[tokio::test]
    async fn ttl_expiry_re_sources_even_when_generation_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let (_id, secret) = seed_user_token(&store, "alice", "builder").await;

        // 50ms 短 TTL（真实 10s）；Arc 尚未共享，get_mut 必然成功。
        let mut app_state = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        Arc::get_mut(&mut app_state)
            .expect("app_state not shared yet")
            .auth_cache = AuthCache::with_ttl(std::time::Duration::from_millis(50));
        let router = test_router_with_profile(app_state.clone()).await;

        assert_eq!(get_identity(&router, &secret).await, "alice:builder:");
        assert_eq!(app_state.auth_cache.rebuild_count(), 1);

        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        assert_eq!(get_identity(&router, &secret).await, "alice:builder:");
        assert_eq!(
            app_state.auth_cache.rebuild_count(),
            2,
            "TTL expiry must force a re-source even without a generation bump"
        );
    }

    /// 建 worker + secret，返回 (worker_id, 明文 secret Secret)。
    async fn seed_worker_secret(store: &Arc<StateStore>, name: &str) -> (i64, Secret) {
        let worker_id = store
            .upsert_worker(name, "x86_64", 2, "test", "online", None)
            .await
            .unwrap();
        let secret = Secret::generate(SecretKind::WorkerSecret).unwrap();
        store
            .set_worker_secret(worker_id, secret.hash().as_str())
            .await
            .unwrap();
        (worker_id, secret)
    }

    /// 同一 worker secret 二连请求只回源一次（第二次命中缓存，回源计数不涨）。
    #[tokio::test]
    async fn same_worker_secret_second_request_served_from_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let (_id, secret) = seed_worker_secret(&store, "w-cache").await;

        let app_state = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_worker(app_state.clone()).await;

        // 固定 "ok" 路由即可：缓存命中与否看 rebuild_count，认证成败看状态码。
        for _ in 0..2 {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/test")
                        .header("Authorization", format!("Bearer {}", secret.as_str()))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::OK);
        }
        assert_eq!(app_state.auth_cache.rebuild_count(), 1);
    }

    /// 删除 worker 即时失效：删除成功 bump 代数 → 下一请求 401。
    #[tokio::test]
    async fn worker_delete_invalidates_cache_on_next_request() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let (worker_id, secret) = seed_worker_secret(&store, "w-del").await;

        let app_state = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_worker(app_state.clone()).await;

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(app_state.auth_cache.rebuild_count(), 1);

        // 唯一删除入口 delete_worker_if_offline；种子 online，先下线再删。
        // 成功删除 bump 代数 → 下一请求 401。
        store.worker_mark_offline(worker_id).await.unwrap();
        let outcome = store.delete_worker_if_offline(worker_id).await.unwrap();
        assert_eq!(outcome, crbs_core::DeleteWorkerOutcome::Deleted);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "deleted worker's secret must stop authenticating immediately"
        );
    }

    /// 换密钥即时失效：set_worker_secret bump 代数 → 旧 secret 下一请求 401、新 secret 正常。
    #[tokio::test]
    async fn worker_secret_rotation_invalidates_old_secret_on_next_request() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let (worker_id, old_secret) = seed_worker_secret(&store, "w-rotate").await;

        let app_state = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let router = test_router_with_worker(app_state.clone()).await;

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", old_secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let new_secret = Secret::generate(SecretKind::WorkerSecret).unwrap();
        store
            .set_worker_secret(worker_id, new_secret.hash().as_str())
            .await
            .unwrap();

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", old_secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "rotated-out secret must stop authenticating immediately"
        );

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", new_secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    /// TTL 过期回源（worker 侧）：代数未变也须 TTL 后重建——删除后 401 最多延迟 10s 的兜底。
    #[tokio::test]
    async fn worker_secret_ttl_expiry_re_sources_even_when_generation_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let (_id, secret) = seed_worker_secret(&store, "w-ttl").await;

        let mut app_state = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        Arc::get_mut(&mut app_state)
            .expect("app_state not shared yet")
            .auth_cache = AuthCache::with_ttl(std::time::Duration::from_millis(50));
        let router = test_router_with_worker(app_state.clone()).await;

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(app_state.auth_cache.rebuild_count(), 1);

        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", secret.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            app_state.auth_cache.rebuild_count(),
            2,
            "TTL expiry must force a re-source even without a generation bump"
        );
    }

    /// 提交门槛只看角色（builder+），与 ACL 记录无关；产品级放行由提交链上的
    /// check_build_chain_visibility（内容级可见性）承担，ACL viewer 禁提交由
    /// ensure_can_submit_to_product 内的 ACL 角色检查承担。
    #[test]
    fn can_submit_is_role_gate_independent_of_product_acl() {
        let builder_no_acl = AuthContext {
            user: "alice".into(),
            role: "builder".into(),
            ..Default::default()
        };
        assert!(builder_no_acl.can_submit());

        let builder_with_acl = AuthContext {
            user: "bob".into(),
            role: "builder".into(),
            allowed_products: vec!["fedora".into()],
            ..Default::default()
        };
        assert!(builder_with_acl.can_submit());

        let operator = AuthContext {
            user: "carol".into(),
            role: "operator".into(),
            allowed_products: vec!["centos".into()],
            ..Default::default()
        };
        assert!(operator.can_submit());

        let viewer = AuthContext {
            user: "dave".into(),
            role: "viewer".into(),
            ..Default::default()
        };
        assert!(!viewer.can_submit());
    }

    /// 空 user 的遗留记录无"本人"可匹配，取消仅 operator/admin；具名记录仍
    /// operator/本人两分支，行为不变。
    #[test]
    fn can_cancel_empty_user_records_operator_only() {
        let builder = AuthContext {
            user: "alice".into(),
            role: "builder".into(),
            ..Default::default()
        };
        assert!(
            !builder.can_cancel(""),
            "builder must not cancel legacy records"
        );
        assert!(builder.can_cancel("alice"), "builder cancels own records");
        assert!(!builder.can_cancel("bob"));

        let viewer = AuthContext {
            user: "eve".into(),
            role: "viewer".into(),
            ..Default::default()
        };
        assert!(!viewer.can_cancel(""));

        let operator = AuthContext {
            user: "bob".into(),
            role: "operator".into(),
            ..Default::default()
        };
        assert!(operator.can_cancel(""));

        let admin = AuthContext {
            user: "carol".into(),
            role: "admin".into(),
            ..Default::default()
        };
        assert!(admin.can_cancel(""));
    }
}
