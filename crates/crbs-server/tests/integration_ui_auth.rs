// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 认证页集成测试：登录双模式（密码/session、token/清对方 cookie）、
//! 失败重渲染（保留输入 + 统一文案 + aria-invalid）、限流（429 无剩余次数 +
//! 时钟推进恢复）、must_change 临时行为、logout 真撤销 + session 模式 CSRF、
//! 注册全流程（开关/建号/直登/审计/重名/短密码/confirm）、admin settings
//! 开关切换 + 审计 + 非 admin 403。

// 整个文件是测试 crate：测试辅助函数（seed_* 等）不带 #[test] 属性，
// clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::setup_app;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use crbs_core::auth::password::{hash_password, verify_password};
use crbs_core::config::ServerConfig;
use crbs_core::AuditLogFilter;
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::state::AppState;

/// 可手动推进的假时钟（限流窗口恢复测试用）。
struct FakeClock(std::sync::Mutex<Instant>);

impl FakeClock {
    fn new() -> Arc<Self> {
        Arc::new(Self(std::sync::Mutex::new(Instant::now())))
    }
    fn as_fn(self: &Arc<Self>) -> Arc<dyn Fn() -> Instant + Send + Sync> {
        let this = self.clone();
        Arc::new(move || *this.0.lock().unwrap())
    }
    fn advance(&self, d: Duration) {
        *self.0.lock().unwrap() += d;
    }
}

/// 带（可推进的）登录限流时钟的 setup。
async fn setup_app_with_clock(
    clock: &Arc<FakeClock>,
) -> (Arc<AppState>, axum::Router, tempfile::TempDir) {
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test_with_login_clock(
        state_store,
        ServerConfig::default(),
        tmp_dir.path().to_path_buf(),
        clock.as_fn(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    (app_state, app, tmp_dir)
}

/// 建用户 + 设置密码（must_change 可控），返回 user id。
async fn seed_password_user(
    state: &AppState,
    name: &str,
    role: &str,
    plain: &str,
    must_change: bool,
) -> i64 {
    let id = state
        .state_store
        .create_user(name, role)
        .await
        .expect("create user");
    let hash = hash_password(plain).expect("hash password");
    state
        .state_store
        .set_user_password(id, &hash, must_change)
        .await
        .expect("set password");
    id
}

/// GET /ui/login：抽取 (nonce cookie 值, csrf token, 页面 HTML)。
async fn login_get(app: &axum::Router, query: &str) -> (String, String, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ui/login{query}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /ui/login");
    assert_eq!(response.status(), StatusCode::OK);
    let nonce = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| c.strip_prefix("crbs_login_nonce="))
        .map(|v| v.split(';').next().unwrap_or(v).to_string())
        .expect("login nonce cookie");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let html = String::from_utf8_lossy(&bytes).into_owned();
    let csrf = common::extract_csrf_token(&html).expect("csrf token in login page");
    (nonce, csrf, html)
}

/// 从 Set-Cookie 头集合中提取指定 cookie 的值。
fn cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| {
            c.strip_prefix(&format!("{name}="))
                .map(|v| v.split(';').next().unwrap_or(v).to_string())
        })
}

fn all_set_cookies(headers: &axum::http::HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect()
}

/// POST /ui/login/password。
async fn login_password_post(
    app: &axum::Router,
    nonce: &str,
    csrf: &str,
    username: &str,
    password: &str,
    next: Option<&str>,
) -> axum::response::Response {
    let mut body = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        csrf
    );
    if let Some(next) = next {
        body.push_str(&format!("&next={}", urlencoding::encode(next)));
    }
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login/password")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", format!("crbs_login_nonce={nonce}"))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("POST /ui/login/password")
}

async fn body_string(response: axum::response::Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn audit_rows(state: &AppState, action: &str) -> Vec<crbs_core::AuditLog> {
    state
        .state_store
        .list_audit_logs(AuditLogFilter {
            action: Some(action),
            limit: 100,
            ..Default::default()
        })
        .await
        .expect("list audit logs")
}

// ---------------------------------------------------------------------------
// 密码登录
// ---------------------------------------------------------------------------

/// 密码登录成功：303 到 ?next=；种 crbs_session（HttpOnly / 7 天）；
/// 清 crbs_token 与 nonce；审计 login_success(mode=password)；session 可认证。
#[tokio::test]
async fn password_login_success_issues_session_and_audits() {
    let (state, app, _tmp) = setup_app().await;
    seed_password_user(&state, "alice", "builder", "correct horse battery", false).await;

    let (nonce, csrf, _html) = login_get(&app, "?next=/ui/builds").await;
    let response = login_password_post(
        &app,
        &nonce,
        &csrf,
        "alice",
        "correct horse battery",
        Some("/ui/builds"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/builds"),
        "valid next must be honored"
    );

    let cookies = all_set_cookies(response.headers());
    let session = cookie_value(response.headers(), "crbs_session").expect("crbs_session set");
    assert!(session.starts_with("crbs_sess_"), "{session}");
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("crbs_session=crbs_sess_")
                && c.contains("HttpOnly")
                && c.contains("SameSite=Lax")
                && c.contains("Path=/")
                && c.contains("Max-Age=604800")),
        "session cookie attributes: {cookies:?}"
    );
    // 切模式登录清对方 cookie + 登录 nonce。
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("crbs_token=;") && c.contains("Max-Age=0")),
        "crbs_token must be cleared: {cookies:?}"
    );
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("crbs_login_nonce=;") && c.contains("Max-Age=0")),
        "nonce must be cleared: {cookies:?}"
    );

    // session cookie 可认证受保护页面。
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/admin/users")
                .header("Cookie", format!("crbs_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "builder is not admin but is authenticated (not 401)"
    );

    // 审计行：login_success，detail 含 mode=password；密码明文绝不出现。
    let rows = audit_rows(&state, "login_success").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].user, "alice");
    assert!(rows[0].detail.as_deref().unwrap_or("").contains("password"));
    assert!(!format!("{rows:?}").contains("correct horse"));
}

/// 修复回归：next 含非 ASCII（如中文搜索词）时，Location 头必须百分号
/// 编码后下发（HeaderValue::from_str 对 obs-text 放行，原始多字节字符上 wire
/// 违反 RFC 9110 Location=URI-reference）——跳转目标语义不变，而非 500 或
/// 裸 UTF-8 字节。
#[tokio::test]
async fn password_login_non_ascii_next_is_percent_encoded() {
    let (state, app, _tmp) = setup_app().await;
    seed_password_user(&state, "alice", "builder", "correct horse battery", false).await;

    let (nonce, csrf, _html) = login_get(&app, "").await;
    let response = login_password_post(
        &app,
        &nonce,
        &csrf,
        "alice",
        "correct horse battery",
        Some("/ui/search?q=中文"),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "non-ASCII next must not fail the success path"
    );
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/search?q=%E4%B8%AD%E6%96%87"),
        "non-ASCII bytes must be percent-encoded, ASCII kept verbatim"
    );
    assert!(
        cookie_value(response.headers(), "crbs_session").is_some(),
        "session cookie still issued"
    );
}

/// 密码登录失败：200 重渲染表单、保留用户名、统一文案、aria-invalid；
/// 密码不回填；审计 login_failure(reason=invalid_credentials)。
#[tokio::test]
async fn password_login_failure_rerenders_form_with_username_kept() {
    let (state, app, _tmp) = setup_app().await;
    seed_password_user(&state, "alice", "builder", "correct horse battery", false).await;

    let (nonce, csrf, _html) = login_get(&app, "").await;
    let response = login_password_post(&app, &nonce, &csrf, "alice", "wrong password!", None).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "failure must re-render (200), not 401"
    );
    assert!(cookie_value(response.headers(), "crbs_login_nonce").is_some());
    let html = body_string(response).await;
    assert!(html.contains("Invalid username or password."), "{html}");
    assert!(
        html.contains(r#"value="alice""#),
        "username must be kept: {html}"
    );
    assert!(html.contains("aria-invalid=\"true\""), "{html}");
    assert!(
        !html.contains("wrong password!"),
        "password must never be echoed back: {html}"
    );
    let rows = audit_rows(&state, "login_failure").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].user, "alice");
    assert!(rows[0]
        .detail
        .as_deref()
        .unwrap_or("")
        .contains("invalid_credentials"));
}

/// 未设密码用户（token-only）登录失败：与密码错的文案一致（不泄露"用户存在"）。
#[tokio::test]
async fn password_login_user_without_password_gets_unified_error() {
    let (state, app, _tmp) = setup_app().await;
    state
        .state_store
        .create_user("tokenonly", "builder")
        .await
        .unwrap();

    let (nonce, csrf, _html) = login_get(&app, "").await;
    let response =
        login_password_post(&app, &nonce, &csrf, "tokenonly", "whatever-pass", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_string(response).await;
    assert!(html.contains("Invalid username or password."), "{html}");
    // 与"用户不存在"路径同一文案：不泄露该用户存在。
    let (nonce, csrf, _html) = login_get(&app, "").await;
    let response =
        login_password_post(&app, &nonce, &csrf, "no-such-user", "whatever-pass", None).await;
    let html2 = body_string(response).await;
    assert!(html2.contains("Invalid username or password."), "{html2}");
}

/// CSRF 缺失（无 nonce cookie）→ 401（"missing login session"，先于凭据校验）。
#[tokio::test]
async fn password_login_without_nonce_cookie_is_401() {
    let (_state, app, _tmp) = setup_app().await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login/password")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from("username=alice&password=x&csrf_token=deadbeef"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// must_change_password=true：303 到 /ui/me?must_change=1（替代 next）+
/// 种 session；/ui/me 的常驻横幅由后续流程清理。
#[tokio::test]
async fn password_login_must_change_redirects_to_me() {
    let (state, app, _tmp) = setup_app().await;
    seed_password_user(&state, "bob", "builder", "correct horse battery", true).await;

    let (nonce, csrf, _html) = login_get(&app, "?next=/ui/builds").await;
    let response = login_password_post(
        &app,
        &nonce,
        &csrf,
        "bob",
        "correct horse battery",
        Some("/ui/builds"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/me?must_change=1"),
        "must_change must override next (A1)"
    );
    assert!(cookie_value(response.headers(), "crbs_session").is_some());

    // /ui/me 带 ?must_change=1 渲染 flash + 常驻横幅。
    let session = cookie_value(response.headers(), "crbs_session").expect("session cookie");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/me?must_change=1")
                .header("Cookie", format!("crbs_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_string(response).await;
    assert!(
        html.contains("An administrator has reset your password"),
        "persistent banner must show: {html}"
    );
    assert!(html.contains("Please set a new password"), "{html}");
}

/// 限流：第 11 次 429，文案只给分钟（无剩余次数）；推进时钟过窗口后恢复；
/// 审计 login_failure(reason=rate_limited)。
#[tokio::test]
async fn password_login_rate_limited_then_recovers_after_window() {
    let clock = FakeClock::new();
    let (state, app, _tmp) = setup_app_with_clock(&clock).await;
    seed_password_user(&state, "alice", "builder", "correct horse battery", false).await;

    for i in 0..10 {
        let (nonce, csrf, _html) = login_get(&app, "").await;
        let response =
            login_password_post(&app, &nonce, &csrf, "alice", "wrong password!", None).await;
        assert_eq!(response.status(), StatusCode::OK, "attempt {i}");
    }

    // 第 11 次：429，文案带 "Too many attempts" 与分钟数，不带剩余次数。
    let (nonce, csrf, _html) = login_get(&app, "").await;
    let response = login_password_post(&app, &nonce, &csrf, "alice", "wrong password!", None).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let html = body_string(response).await;
    assert!(html.contains("Too many attempts."), "{html}");
    assert!(html.contains("minutes"), "{html}");
    assert!(
        !html.contains("attempts left") && !html.contains("remaining"),
        "A8: must not leak remaining attempts: {html}"
    );

    let rows = audit_rows(&state, "login_failure").await;
    assert!(
        rows.iter()
            .any(|r| r.detail.as_deref().unwrap_or("").contains("rate_limited")),
        "{rows:?}"
    );

    // 窗口推进 301s：正确密码登录恢复。
    clock.advance(Duration::from_secs(301));
    let (nonce, csrf, _html) = login_get(&app, "").await;
    let response =
        login_password_post(&app, &nonce, &csrf, "alice", "correct horse battery", None).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

/// token 模式成功：种 crbs_token + 清 crbs_session（对称）+ 审计。
#[tokio::test]
async fn token_login_success_clears_session_cookie() {
    let (state, app, _tmp) = setup_app().await;
    let token =
        crbs_server::server::seed_user_token_for_test(&state.state_store, "carol", "viewer")
            .await
            .expect("seed token");

    let (nonce, csrf, _html) = login_get(&app, "").await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", format!("crbs_login_nonce={nonce}"))
                .body(Body::from(format!("token={token}&csrf_token={csrf}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/")
    );
    let cookies = all_set_cookies(response.headers());
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with(&format!("crbs_token={token}"))),
        "crbs_token must be set: {cookies:?}"
    );
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("crbs_session=;") && c.contains("Max-Age=0")),
        "crbs_session must be cleared (A2): {cookies:?}"
    );

    let rows = audit_rows(&state, "login_success").await;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].detail.as_deref().unwrap_or("").contains("token"));
}

// ---------------------------------------------------------------------------
// logout（session 真撤销 + csrf_token_for_request 双模式）
// ---------------------------------------------------------------------------

/// session 模式 logout：nav 表单 CSRF 由 crbs_session 派生；
/// logout 后服务端撤销（同 cookie 再访问受保护页 → 401）；审计 logout。
#[tokio::test]
async fn logout_with_session_cookie_revokes_session_server_side() {
    let (state, app, _tmp) = setup_app().await;
    seed_password_user(&state, "root", "admin", "correct horse battery", false).await;

    let (nonce, csrf, _html) = login_get(&app, "").await;
    let response =
        login_password_post(&app, &nonce, &csrf, "root", "correct horse battery", None).await;
    let session = cookie_value(response.headers(), "crbs_session").expect("session cookie");
    let cookie = format!("crbs_session={session}");

    // 带 session cookie 访问 admin 页：200（session 认证）。
    let page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/admin/users")
                .header("Cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let page_html = body_string(page).await;
    // nav logout 表单内嵌了由 crbs_session 派生的 CSRF（csrf_token_for_request
    // 扩展为双模式派生链的钉子）。
    let logout_csrf = common::extract_csrf_token(&page_html).expect("nav logout csrf token");

    // POST /ui/logout：用页面下发的 CSRF。
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/logout")
                .header("Cookie", &cookie)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("csrf_token={logout_csrf}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookies = all_set_cookies(response.headers());
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("crbs_session=;") && c.contains("Max-Age=0")),
        "session cookie cleared: {cookies:?}"
    );

    // 同一 session cookie 再访问受保护页 → 401（服务端已撤销，非仅清 cookie）。
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/admin/users")
                .header("Cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "revoked session must not authenticate"
    );

    let rows = audit_rows(&state, "logout").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].user, "root");
}

// ---------------------------------------------------------------------------
// 注册
// ---------------------------------------------------------------------------

async fn register_get(app: &axum::Router) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/ui/register")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /ui/register")
}

async fn register_post(
    app: &axum::Router,
    nonce: &str,
    csrf: &str,
    username: &str,
    password: &str,
    confirm: &str,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/register")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", format!("crbs_register_nonce={nonce}"))
                .body(Body::from(format!(
                    "username={}&password={}&confirm_password={}&csrf_token={}",
                    urlencoding::encode(username),
                    urlencoding::encode(password),
                    urlencoding::encode(confirm),
                    csrf
                )))
                .unwrap(),
        )
        .await
        .expect("POST /ui/register")
}

/// 开关关闭（缺省）：GET 页面可达显示提示（非 404）；POST 403。
#[tokio::test]
async fn register_closed_get_shows_notice_and_post_is_403() {
    let (state, app, _tmp) = setup_app().await;
    let response = register_get(&app).await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_string(response).await;
    assert!(html.contains("Registration is currently closed"), "{html}");

    // 关闭页不发放表单 nonce（没有可提交的表单）。
    let page = register_get(&app).await;
    assert!(
        cookie_value(page.headers(), "crbs_register_nonce").is_none(),
        "closed page must not seed a form nonce"
    );

    // 开关在"取表单"与"提交"之间被关闭（真实运维时序）：用开放期取得的有效
    // nonce+CSRF 提交 → 通过 CSRF 层后命中开关分支 → 403 + 关闭提示页。
    state
        .state_store
        .set_app_meta("registration_enabled", "true")
        .await
        .unwrap();
    let page = register_get(&app).await;
    let nonce = cookie_value(page.headers(), "crbs_register_nonce").expect("nonce while open");
    let html = body_string(page).await;
    let csrf = common::extract_csrf_token(&html).expect("csrf while open");
    state
        .state_store
        .set_app_meta("registration_enabled", "false")
        .await
        .unwrap();

    let response = register_post(
        &app,
        &nonce,
        &csrf,
        "somebody",
        "a-long-password",
        "a-long-password",
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "switch must reject the POST"
    );
    let html = body_string(response).await;
    assert!(html.contains("Registration is currently closed"), "{html}");
    // 用户未创建。
    assert!(state
        .state_store
        .find_user_by_name("somebody")
        .await
        .unwrap()
        .is_none());
}

/// 开关开放：完整注册流程 = viewer 用户 + 密码落库 + 直接登录（种 session）+
/// 审计 register；重名/短密码/confirm 不匹配各自重渲染提示。
#[tokio::test]
async fn register_open_flow_creates_viewer_and_signs_in() {
    let (state, app, _tmp) = setup_app().await;
    state
        .state_store
        .set_app_meta("registration_enabled", "true")
        .await
        .unwrap();

    // GET：表单 + nonce + 登录页出现注册入口。
    let page = register_get(&app).await;
    assert_eq!(page.status(), StatusCode::OK);
    let nonce = cookie_value(page.headers(), "crbs_register_nonce").expect("register nonce");
    let html = body_string(page).await;
    assert!(html.contains(r#"action="/ui/register""#), "{html}");
    let csrf = common::extract_csrf_token(&html).expect("register csrf");
    let (_ln, _lc, login_html) = login_get(&app, "").await;
    assert!(
        login_html.contains(r#"href="/ui/register""#),
        "login page must link to register when open: {login_html}"
    );

    // POST：创建 + 直登。
    let response = register_post(
        &app,
        &nonce,
        &csrf,
        "newuser",
        "a-long-password",
        "a-long-password",
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/")
    );
    assert!(
        cookie_value(response.headers(), "crbs_session").is_some(),
        "register signs in"
    );
    // 注册 nonce cookie 成功即清（Path 与种植侧精确同源 /ui/register）。
    let clear_cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter(|c| c.starts_with("crbs_register_nonce=;"))
        .collect::<Vec<_>>();
    assert_eq!(
        clear_cookies,
        ["crbs_register_nonce=; HttpOnly; SameSite=Lax; Path=/ui/register; Max-Age=0"],
        "register success must clear the nonce cookie"
    );

    let user = state
        .state_store
        .find_user_by_name("newuser")
        .await
        .unwrap()
        .expect("user created");
    assert_eq!(user.role, "viewer");
    assert_eq!(user.status, "active");
    let auth_row = state
        .state_store
        .get_user_auth_row(user.id)
        .await
        .unwrap()
        .expect("auth row");
    assert!(auth_row.password_hash.is_some());
    assert!(!auth_row.must_change_password);
    assert!(verify_password(
        "a-long-password",
        auth_row.password_hash.as_deref().unwrap()
    ));

    let rows = audit_rows(&state, "register").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].user, "newuser");
    assert_eq!(
        rows[0].target.as_deref(),
        Some(user.id.to_string().as_str())
    );

    // 新用户能用密码直接登录（注册密码立即生效）。
    let (nonce, csrf, _html) = login_get(&app, "").await;
    let response =
        login_password_post(&app, &nonce, &csrf, "newuser", "a-long-password", None).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

/// 注册校验：重名 / 短密码 / confirm 不匹配 / 非法用户名 → 200 重渲染 + 提示。
#[tokio::test]
async fn register_validation_errors_rerender_with_messages() {
    let (state, app, _tmp) = setup_app().await;
    state
        .state_store
        .set_app_meta("registration_enabled", "true")
        .await
        .unwrap();
    seed_password_user(&state, "taken", "builder", "correct horse battery", false).await;

    let cases: &[(&str, &str, &str, &str)] = &[
        // (username, password, confirm, 预期消息)
        (
            "taken",
            "a-long-password",
            "a-long-password",
            "already taken",
        ),
        ("newuser", "short", "short", "at least 10 characters"),
        (
            "newuser",
            "a-long-password",
            "different-password",
            "Passwords do not match",
        ),
        (
            "Bad Name!",
            "a-long-password",
            "a-long-password",
            "Invalid username",
        ),
    ];
    for (username, password, confirm, expected) in cases {
        let page = register_get(&app).await;
        let nonce = cookie_value(page.headers(), "crbs_register_nonce").expect("nonce");
        let html = body_string(page).await;
        let csrf = common::extract_csrf_token(&html).expect("csrf");
        let response = register_post(&app, &nonce, &csrf, username, password, confirm).await;
        assert_eq!(response.status(), StatusCode::OK, "case {username}");
        let html = body_string(response).await;
        assert!(html.contains(expected), "expected {expected:?}: {html}");
        // 用户名保留（合法用户名场景）。
        if *username == "newuser" {
            assert!(html.contains(r#"value="newuser""#));
        }
        // 密码不回填。
        assert!(
            !html.contains("a-long-password\" "),
            "password must not be echoed: {html}"
        );
    }

    // 全部失败后库里没有 newuser。
    assert!(state
        .state_store
        .find_user_by_name("newuser")
        .await
        .unwrap()
        .is_none());
}

// ---------------------------------------------------------------------------
// Admin settings（注册开关）
// ---------------------------------------------------------------------------

/// admin 切换开关：POST → KV 落库 + 审计 + 303 回本页；GET 展示状态。
#[tokio::test]
async fn admin_settings_toggles_registration_and_audits() {
    let (state, app, _tmp) = setup_app().await;
    let admin_token =
        crbs_server::server::seed_user_token_for_test(&state.state_store, "root", "admin")
            .await
            .expect("seed admin");
    let cookie = format!("crbs_token={admin_token}");

    // GET：初始关闭态。
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/admin/settings")
                .header("Cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_string(response).await;
    assert!(html.contains("Registration"), "{html}");
    assert!(html.contains("closed"), "{html}");
    let csrf = common::extract_csrf_token(&html).expect("settings csrf");

    // POST 开启。
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/settings")
                .header("Cookie", &cookie)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "registration_enabled=on&csrf_token={csrf}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/admin/settings?status=saved")
    );
    assert_eq!(
        state
            .state_store
            .get_app_meta("registration_enabled")
            .await
            .unwrap()
            .as_deref(),
        Some("true")
    );
    let rows = audit_rows(&state, "update_registration_setting").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].user, "root");
    assert!(rows[0].detail.as_deref().unwrap_or("").contains("true"));

    // 开关生效：注册页现在开放。
    let response = register_get(&app).await;
    let html = body_string(response).await;
    assert!(html.contains(r#"action="/ui/register""#), "{html}");
}

/// 非 admin：GET 403，POST 403（require_admin_session / require_admin_page）。
#[tokio::test]
async fn admin_settings_denies_non_admin() {
    let (state, app, _tmp) = setup_app().await;
    let viewer_token =
        crbs_server::server::seed_user_token_for_test(&state.state_store, "looker", "viewer")
            .await
            .expect("seed viewer");
    let cookie = format!("crbs_token={viewer_token}");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/admin/settings")
                .header("Cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/settings")
                .header("Cookie", &cookie)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from("registration_enabled=on&csrf_token=deadbeef"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        state
            .state_store
            .get_app_meta("registration_enabled")
            .await
            .unwrap(),
        None,
        "switch must stay unset"
    );
}

/// auth_enabled=false：登录/注册页显示"认证已禁用"说明（免认证模式提示）。
#[tokio::test]
async fn login_and_register_show_auth_disabled_note() {
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    let config = ServerConfig {
        auth_enabled: false,
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        state_store,
        config,
        tmp_dir.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_string(response).await;
    assert!(html.contains("Authentication is disabled"), "{html}");

    let response = register_get(&app).await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_string(response).await;
    assert!(html.contains("Authentication is disabled"), "{html}");
}

/// 中文渲染（crbs_lang=zh cookie 触发）：登录页与注册关闭页的中文文案。
#[tokio::test]
async fn login_and_register_pages_render_bilingual() {
    let (_state, app, _tmp) = setup_app().await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .header("Cookie", "crbs_lang=zh")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let html = body_string(response).await;
    assert!(html.contains("登录 CRBS"), "{html}");
    assert!(
        !html.contains("用户名或密码错误"),
        "no error line on GET: {html}"
    );
    assert!(html.contains(r#"lang="zh-CN""#), "{html}");

    // 注册关闭页中文。
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/register")
                .header("Cookie", "crbs_lang=zh")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let html = body_string(response).await;
    assert!(html.contains("注册功能当前未开放"), "{html}");
}

/// 认证品牌页：登录/注册走裸页版式（page_bare，无 nav /
/// footer / 全局脚本），渲染 .login-page / .login-card / .seg 品牌卡结构；
/// 表单契约（action / 字段）不变。
#[tokio::test]
async fn login_and_register_render_bare_brand_chrome() {
    let (state, app, _tmp) = setup_app().await;
    state
        .state_store
        .set_app_meta("registration_enabled", "true")
        .await
        .unwrap();

    // 登录页：品牌卡结构 + 无 nav / footer chrome。
    let (_nonce, _csrf, html) = login_get(&app, "").await;
    assert!(html.contains(r#"class="login-page""#), "{html}");
    assert!(html.contains(r#"class="login-card""#), "{html}");
    assert!(html.contains(r#"class="seg""#), "{html}");
    assert!(
        !html.contains("class=\"nav"),
        "bare login must not render nav chrome: {html}"
    );
    assert!(
        !html.contains(r#"class="site-footer""#),
        "bare login must not render footer chrome: {html}"
    );

    // 注册页（开放态）：同一裸品牌卡 + 表单 action 契约保留。
    let page = register_get(&app).await;
    assert_eq!(page.status(), StatusCode::OK);
    let html = body_string(page).await;
    assert!(html.contains(r#"class="login-page""#), "{html}");
    assert!(html.contains(r#"class="login-card""#), "{html}");
    assert!(html.contains(r#"action="/ui/register""#), "{html}");
    assert!(
        !html.contains("class=\"nav"),
        "bare register must not render nav chrome: {html}"
    );
    assert!(
        !html.contains(r#"class="site-footer""#),
        "bare register must not render footer chrome: {html}"
    );
}

/// 修复回归：密码会话（仅 `crbs_session`，无 `crbs_token`）用户的 CSRF
/// 基值契约——products（visibility 等 5 个 POST）/ GC 触发 / 编辑器
/// （new+edit）校验侧统一走 `csrf_base_from_headers`（会话优先，渲染侧
/// 同源），不得回落 token-only 的 `session_token_from_headers`（否则密码
/// 会话用户全部 401 "missing session token"）；三组各验一个代表端点。
#[tokio::test]
async fn password_session_csrf_accepted_on_product_gc_and_editor_posts() {
    use crbs_core::config::ProductConfig;
    use crbs_core::CreateProductInput;

    let (state, app, _tmp) = setup_app().await;
    let uid = state
        .state_store
        .create_user("sessadmin", "admin")
        .await
        .expect("create user");
    let hash = hash_password("Sess-Admin-2026").expect("hash password");
    state
        .state_store
        .set_user_password(uid, &hash, false)
        .await
        .expect("set password");

    // 密码登录：只拿 crbs_session，不携带任何 crbs_token。
    let (nonce, login_csrf, _html) = login_get(&app, "").await;
    let resp = login_password_post(
        &app,
        &nonce,
        &login_csrf,
        "sessadmin",
        "Sess-Admin-2026",
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let session = cookie_value(resp.headers(), "crbs_session").expect("session cookie");
    let cookie = format!("crbs_session={session}");

    // 种子公开产品（编辑器 check 与 visibility POST 的靶子）。
    let config = ProductConfig::from_str(
        "base_packages = [\"bash\"]\narches = [\"x86_64\"]\n\n[[repos]]\nname = \"base\"\nbaseurl = \"http://example.com/base/$basearch\"\ngpgcheck = false\n",
    )
    .expect("sample product toml parses");
    state
        .state_store
        .create_product(CreateProductInput {
            name: "sessprod",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &config,
            changed_by_user_id: None,
            reason: Some("seed"),
        })
        .await
        .expect("seed product");

    // ① 编辑器 edit POST（action=check，只校验不落库）：200 非 401。
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/products/sessprod/edit")
                .header("Cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    let csrf = common::extract_csrf_token(&html).expect("csrf on edit page");
    let rev_marker = "name=\"expected_revision\" value=\"";
    let rev_start = html.find(rev_marker).expect("expected_revision input") + rev_marker.len();
    let revision = html[rev_start..]
        .split('"')
        .next()
        .expect("revision value")
        .to_string();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/products/sessprod/edit")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", &cookie)
                .body(Body::from(format!(
                    "action=check&expected_revision={revision}&reason=session-csrf-check&config_toml={}&csrf_token={csrf}",
                    urlencoding::encode(
                        "base_packages = [\"bash\"]\narches = [\"x86_64\"]\n\n[[repos]]\nname = \"base\"\nbaseurl = \"http://example.com/base/$basearch\"\ngpgcheck = false\n"
                    ),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "editor POST must accept password session (was 401)"
    );

    // ② products visibility POST：详情页（会话渲染侧派生 csrf）→ 303 非 401。
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/products/sessprod")
                .header("Cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    let csrf = common::extract_csrf_token(&html).expect("csrf on detail page");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/products/sessprod/visibility")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", &cookie)
                .body(Body::from(format!(
                    "visibility=private&expected_revision={revision}&csrf_token={csrf}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "visibility POST must accept password session (was 401)"
    );

    // ③ GC 触发 POST（dry-run）：303 非 401。
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/admin/gc")
                .header("Cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    let csrf = common::extract_csrf_token(&html).expect("csrf on gc page");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/gc")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", &cookie)
                .body(Body::from(format!(
                    "dry_run=true&results=true&product=&csrf_token={csrf}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "gc POST must accept password session (was 401)"
    );
}
