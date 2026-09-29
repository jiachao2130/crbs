// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! /ui/me 个人中心集成测试：页面门控（session/token/匿名/viewer）、总览带
//! 计数、改密（连锁撤销 / must_change 清零 / token-only 设密变体 / 双语
//! flash）、admin 重置全链（一次性页 no-store / 全会话撤销 / 横幅）、
//! 会话与 token 自管（越权 404 / revoke-all 保留本机）、nav-user 入口、时长卡。

// 测试辅助函数（seed_* 等）不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::setup_app;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use crbs_core::auth::password::{hash_password, verify_password};
use crbs_core::auth::secret::{Secret, SecretKind};
use crbs_core::{AuditLogFilter, TaskInsert};
use crbs_server::server::state::AppState;

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

/// 直接落一条会话行（"其它设备"），返回可作 cookie 的明文 secret。
async fn seed_session(state: &AppState, user_id: i64, agent: &str) -> String {
    let secret = Secret::generate(SecretKind::Session).expect("session secret");
    state
        .state_store
        .create_session(
            user_id,
            secret.hash().as_str(),
            &(chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339(),
            Some(agent),
        )
        .await
        .expect("seed session");
    secret.as_str().to_string()
}

/// GET /ui/login：抽取 (nonce cookie, csrf token)。
async fn login_get(app: &axum::Router) -> (String, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/login")
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
    let html = body_string(response).await;
    let csrf = common::extract_csrf_token(&html).expect("csrf token in login page");
    (nonce, csrf)
}

/// POST /ui/login/password，成功返回 session cookie 值。
async fn login_password(app: &axum::Router, username: &str, password: &str) -> String {
    let (nonce, csrf) = login_get(app).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login/password")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", format!("crbs_login_nonce={nonce}"))
                .body(Body::from(format!(
                    "username={}&password={}&csrf_token={}",
                    urlencoding::encode(username),
                    urlencoding::encode(password),
                    csrf
                )))
                .unwrap(),
        )
        .await
        .expect("POST /ui/login/password");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| c.strip_prefix("crbs_session="))
        .map(|v| v.split(';').next().unwrap_or(v).to_string())
        .expect("session cookie")
}

/// 从一次性展示页抽取 secret（.secret-value div 文本）。
fn extract_secret(html: &str) -> Option<String> {
    let marker = r#"class="secret-value" id="crbs-secret-value""#;
    let start = html.find(marker)? + marker.len();
    let rest = &html[start..];
    let start = rest.find('>')? + 1;
    let end = rest[start..].find("</div>")?;
    Some(rest[start..start + end].to_string())
}

async fn body_string(response: axum::response::Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn get_with_cookie(app: &axum::Router, cookie: &str, path: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("Cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET")
}

async fn post_form(
    app: &axum::Router,
    cookie: &str,
    path: &str,
    body: String,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", cookie)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("POST")
}

/// POST /ui/me/password，断言 303 并返回 Location（改密 flash 断言用）。
async fn me_password_location(app: &axum::Router, cookie: &str, body: String) -> String {
    let response = post_form(app, cookie, "/ui/me/password", body).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("location")
        .to_string()
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

/// session/token/viewer 均 200：卡标题 + 身份条 + 总览带 + nav-user 入口；
/// token 模式 token-only 文案；匿名 401 归 integration_ui_redirects.rs 表驱动契约。
#[tokio::test]
async fn me_page_renders_for_session_token_and_viewer() {
    let (state, app, _tmp) = setup_app().await;
    seed_password_user(&state, "alice", "builder", "correct horse battery", false).await;
    let viewer_token =
        crbs_server::server::seed_user_token_for_test(&state.state_store, "looker", "viewer")
            .await
            .expect("seed viewer");

    let session = login_password(&app, "alice", "correct horse battery").await;
    let response = get_with_cookie(&app, &format!("crbs_session={session}"), "/ui/me").await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_string(response).await;
    for expected in [
        "Security",
        "API tokens",
        "My products",
        "Recent tasks",
        "Active sessions",
        "Change password",
        "This device",
    ] {
        assert!(html.contains(expected), "missing {expected}: {html}");
    }
    // 身份条 + 总览带结构。
    assert!(html.contains("me-band"), "{html}");
    assert!(html.contains("class=\"avatar\""), "{html}");
    assert!(html.contains("badge accent"), "{html}");
    assert!(html.contains("me-overview"), "{html}");
    assert!(html.contains("sys-strip"), "{html}");
    assert!(html.contains("me-gauge-pct"), "{html}");
    // Expires 列 col-time 定宽（.me-card CSS），钉布局修复防回退百分比弹性列。
    assert!(html.contains(r#"col class="col-time""#), "{html}");
    assert!(
        html.contains(r#"<a class="nav-user" href="/ui/me" title="alice">alice</a>"#),
        "{html}"
    );

    let response = get_with_cookie(&app, &format!("crbs_token={viewer_token}"), "/ui/me").await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_string(response).await;
    assert!(
        html.contains("Token mode has no server-side sessions"),
        "{html}"
    );
    assert!(html.contains("Set password"), "{html}");
    assert!(
        !html.contains("Current password"),
        "A4: token-only user must not see current-password field: {html}"
    );
}

/// 总览带数字与 store 过滤口径对上（for_user 计数 + token 数 + owned 产品数）。
#[tokio::test]
async fn me_overview_strip_counts_match_store_filters() {
    let (state, app, _tmp) = setup_app().await;
    let alice =
        seed_password_user(&state, "alice", "builder", "correct horse battery", false).await;

    for (user, phase) in [
        ("alice", "succeeded"),
        ("alice", "succeeded"),
        ("alice", "succeeded"),
        ("alice", "building"),
        ("alice", "pending"),
        ("bob", "failed"),
        ("bob", "failed"),
    ] {
        state
            .state_store
            .insert_task(TaskInsert {
                product: "fedora",
                pkg_name: "pkg",
                user,
                phase,
                ..Default::default()
            })
            .await
            .unwrap();
    }
    state
        .state_store
        .create_user_token(alice, Some("ci"), "hash-1", None)
        .await
        .unwrap();
    for name in ["zeta", "alpha"] {
        state
            .state_store
            .create_product(crbs_core::CreateProductInput {
                name,
                display_name: None,
                owner_id: Some(alice),
                parent_id: None,
                visibility: "private",
                config: &crbs_core::config::ProductConfig::default(),
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();
    }

    let session = login_password(&app, "alice", "correct horse battery").await;
    let response = get_with_cookie(&app, &format!("crbs_session={session}"), "/ui/me").await;
    let html = body_string(response).await;
    for (label, value) in [
        ("My tasks", "5"),
        ("Building", "1"),
        ("Queued", "1"),
        ("Tokens", "1"),
        ("Owned products", "2"),
    ] {
        let needle = format!(r#">{label}</span><span class="value">{value}</span>"#);
        assert!(html.contains(&needle), "strip {label}={value}: {html}");
    }
    // My products 卡：owner 徽章 + 产品名链接（无 via-ACL 场景）。
    assert!(html.contains("zeta"), "{html}");
    assert!(html.contains("alpha"), "{html}");
    assert!(html.contains(r#"badge accent">owner"#), "{html}");
    // Recent tasks 卡：只列 alice 的任务（bob 的噪声不在）。
    assert!(!html.contains(">bob<"), "{html}");
}

/// 错误当前密码 → error flash；正确改密 → 其它会话撤销、本机保留、must_change 清零、新密码可登录。
#[tokio::test]
async fn password_change_flow_revokes_other_sessions_and_clears_must_change() {
    let (state, app, _tmp) = setup_app().await;
    let alice = seed_password_user(&state, "alice", "builder", "old-password-1", true).await;
    let other_device = seed_session(&state, alice, "Firefox / Linux").await;

    let session = login_password(&app, "alice", "old-password-1").await;
    let cookie = format!("crbs_session={session}");
    let page = body_string(get_with_cookie(&app, &cookie, "/ui/me").await).await;
    assert!(
        page.contains("An administrator has reset your password"),
        "{page}"
    );
    let csrf = common::extract_csrf_token(&page).expect("csrf in me page");

    // 错误当前密码 → 303 error flash（统一文案，不泄露哪个错）。
    let response = post_form(
        &app,
        &cookie,
        "/ui/me/password",
        format!(
            "current_password={}&new_password={}&confirm_password={}&csrf_token={}",
            "wrong-password",
            urlencoding::encode("new-password-12"),
            urlencoding::encode("new-password-12"),
            csrf
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("location");
    assert!(location.starts_with("/ui/me?error="), "{location}");
    let html = body_string(get_with_cookie(&app, &cookie, location).await).await;
    assert!(html.contains("Current password is incorrect."), "{html}");

    let response = post_form(
        &app,
        &cookie,
        "/ui/me/password",
        format!(
            "current_password={}&new_password={}&confirm_password={}&csrf_token={}",
            urlencoding::encode("old-password-1"),
            urlencoding::encode("new-password-12"),
            urlencoding::encode("mismatch-99"),
            csrf
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap();
    let html = body_string(get_with_cookie(&app, &cookie, location).await).await;
    assert!(html.contains("do not match"), "{html}");

    let response = post_form(
        &app,
        &cookie,
        "/ui/me/password",
        format!(
            "current_password={}&new_password={}&confirm_password={}&csrf_token={}",
            urlencoding::encode("old-password-1"),
            urlencoding::encode("new-password-12"),
            urlencoding::encode("new-password-12"),
            csrf
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/me?status=password_changed")
    );

    let response = get_with_cookie(&app, &format!("crbs_session={other_device}"), "/ui/me").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let html =
        body_string(get_with_cookie(&app, &cookie, "/ui/me?status=password_changed").await).await;
    assert!(
        !html.contains("An administrator has reset your password"),
        "banner must clear after self-change: {html}"
    );
    assert!(html.contains("Password changed."), "{html}");

    let row = state
        .state_store
        .get_user_auth_row(alice)
        .await
        .unwrap()
        .unwrap();
    assert!(!row.must_change_password);
    assert!(verify_password(
        "new-password-12",
        row.password_hash.as_deref().unwrap()
    ));
    let rows = audit_rows(&state, "password_change").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].user, "alice");
}

/// zh 校验失败 flash 本地化：crbs_lang=zh 时错误文案走双语表（对齐注册页模板），
/// Location 不携带英文原文；无语言提示仍英文。
#[tokio::test]
async fn password_change_failure_flash_is_localized_for_zh() {
    let (state, app, _tmp) = setup_app().await;
    seed_password_user(&state, "alice", "builder", "old-password-1", false).await;
    let session = login_password(&app, "alice", "old-password-1").await;
    // crbs_lang=zh cookie：POST handler 与页面渲染共用同一 lang 协商。
    let cookie = format!("crbs_session={session}; crbs_lang=zh");
    let page = body_string(get_with_cookie(&app, &cookie, "/ui/me").await).await;
    let csrf = common::extract_csrf_token(&page).expect("csrf in me page");
    let form = |current: &str, new: &str, confirm: &str| {
        format!(
            "current_password={}&new_password={}&confirm_password={}&csrf_token={}",
            urlencoding::encode(current),
            urlencoding::encode(new),
            urlencoding::encode(confirm),
            csrf
        )
    };

    let location = me_password_location(
        &app,
        &cookie,
        form("wrong-password", "new-password-12", "new-password-12"),
    )
    .await;
    assert!(location.starts_with("/ui/me?error="), "{location}");
    assert!(
        location.contains(urlencoding::encode("当前密码不正确。").as_ref()),
        "{location}"
    );
    // 真渲染 round-trip：多字节文案经 ?error= 编码往返后须原样呈现，非仅在 Location。
    let html = body_string(get_with_cookie(&app, &cookie, &location).await).await;
    assert!(
        html.contains("当前密码不正确"),
        "zh flash not rendered: {html}"
    );

    // confirm 不一致 → 中文 flash（复用注册页同文案 key）。
    let location = me_password_location(
        &app,
        &cookie,
        form("old-password-1", "new-password-12", "mismatch-99"),
    )
    .await;
    assert!(
        location.contains(urlencoding::encode("两次输入的密码不一致。").as_ref()),
        "{location}"
    );

    // 密码过短 → 策略文案本地化（RegisterPasswordToo* 双语模板）。
    let location =
        me_password_location(&app, &cookie, form("old-password-1", "short", "short")).await;
    assert!(
        location.contains(urlencoding::encode("密码至少需要 10 个字符。").as_ref()),
        "{location}"
    );

    // 无语言提示默认 en：英文文案不回归。
    let en_cookie = format!("crbs_session={session}");
    let location = me_password_location(
        &app,
        &en_cookie,
        form("wrong-password", "new-password-12", "new-password-12"),
    )
    .await;
    assert!(
        location.contains(urlencoding::encode("Current password is incorrect.").as_ref()),
        "{location}"
    );
}

/// token-only 用户（无密码）看到"设置密码"变体（无 Current password），无 current 字段提交成功落库。
#[tokio::test]
async fn password_set_variant_for_token_only_user() {
    let (state, app, _tmp) = setup_app().await;
    let token =
        crbs_server::server::seed_user_token_for_test(&state.state_store, "tokenonly", "builder")
            .await
            .expect("seed token");
    let cookie = format!("crbs_token={token}");
    let page = body_string(get_with_cookie(&app, &cookie, "/ui/me").await).await;
    assert!(page.contains("Set password"), "{page}");
    assert!(!page.contains("Current password"), "{page}");
    let csrf = common::extract_csrf_token(&page).expect("csrf");

    let response = post_form(
        &app,
        &cookie,
        "/ui/me/password",
        format!(
            "new_password={}&confirm_password={}&csrf_token={}",
            urlencoding::encode("first-password-1"),
            urlencoding::encode("first-password-1"),
            csrf
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/me?status=password_changed")
    );

    // token 改密连锁：撤销全部（0 条）会话不影响本 token 认证；设密后新密码可登录。
    let user = state
        .state_store
        .find_user_by_name("tokenonly")
        .await
        .unwrap()
        .unwrap();
    let row = state
        .state_store
        .get_user_auth_row(user.id)
        .await
        .unwrap()
        .unwrap();
    assert!(verify_password(
        "first-password-1",
        row.password_hash.as_deref().unwrap()
    ));
    let response = get_with_cookie(&app, &cookie, "/ui/me").await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "token credential must survive password set"
    );
}

/// admin 重置 → 一次性页（临时密码 + no-store）→ 会话全撤销 + must_change
/// 置位 → 临时密码登录 → 303 /ui/me?must_change=1 → 横幅 → 改密 → 横幅消失。
#[tokio::test]
async fn admin_reset_password_full_chain() {
    let (state, app, _tmp) = setup_app().await;
    let admin_token =
        crbs_server::server::seed_user_token_for_test(&state.state_store, "root", "admin")
            .await
            .expect("seed admin");
    let admin_cookie = format!("crbs_token={admin_token}");
    let bob = seed_password_user(&state, "bob", "builder", "bob-password-1", false).await;
    let bob_session = seed_session(&state, bob, "bob-laptop").await;

    let page =
        body_string(get_with_cookie(&app, &admin_cookie, &format!("/ui/admin/users/{bob}")).await)
            .await;
    assert!(page.contains("Reset password"), "{page}");
    let csrf = common::extract_csrf_token(&page).expect("admin csrf");

    let response = post_form(
        &app,
        &admin_cookie,
        &format!("/ui/admin/users/{bob}/password"),
        format!("csrf_token={csrf}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let html = body_string(response).await;
    assert!(html.contains("Temporary password for bob"), "{html}");
    assert!(html.contains("must set a new password"), "{html}");
    let temp = extract_secret(&html).expect("temp password");
    assert_eq!(temp.chars().count(), 16, "{temp}");
    assert!(temp.chars().all(|c| c.is_ascii_alphanumeric()), "{temp}");

    let response = get_with_cookie(&app, &format!("crbs_session={bob_session}"), "/ui/me").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let row = state
        .state_store
        .get_user_auth_row(bob)
        .await
        .unwrap()
        .unwrap();
    assert!(row.must_change_password);
    assert!(!verify_password(
        "bob-password-1",
        row.password_hash.as_deref().unwrap()
    ));

    let rows = audit_rows(&state, "password_reset").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].user, "root");
    assert_eq!(rows[0].target.as_deref(), Some(bob.to_string().as_str()));

    let (nonce, login_csrf) = login_get(&app).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login/password")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", format!("crbs_login_nonce={nonce}"))
                .body(Body::from(format!(
                    "username=bob&password={}&csrf_token={}",
                    urlencoding::encode(&temp),
                    login_csrf
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
        Some("/ui/me?must_change=1")
    );
    let session = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| c.strip_prefix("crbs_session="))
        .map(|v| v.split(';').next().unwrap_or(v).to_string())
        .expect("session");
    let cookie = format!("crbs_session={session}");
    let html = body_string(get_with_cookie(&app, &cookie, "/ui/me").await).await;
    assert!(
        html.contains("An administrator has reset your password"),
        "banner must show: {html}"
    );

    let csrf = common::extract_csrf_token(&html).expect("csrf");
    let response = post_form(
        &app,
        &cookie,
        "/ui/me/password",
        format!(
            "current_password={}&new_password={}&confirm_password={}&csrf_token={}",
            urlencoding::encode(&temp),
            urlencoding::encode("bob-password-2"),
            urlencoding::encode("bob-password-2"),
            csrf
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let html = body_string(get_with_cookie(&app, &cookie, "/ui/me").await).await;
    assert!(
        !html.contains("An administrator has reset your password"),
        "{html}"
    );
    let row = state
        .state_store
        .get_user_auth_row(bob)
        .await
        .unwrap()
        .unwrap();
    assert!(!row.must_change_password);
}

/// 撤销他人会话行 → 404；revoke-all 保留本机、撤销其它；本机行有 Log out。
#[tokio::test]
async fn session_revoke_scoped_and_revoke_all_keeps_current() {
    let (state, app, _tmp) = setup_app().await;
    let alice =
        seed_password_user(&state, "alice", "builder", "correct horse battery", false).await;
    let bob = seed_password_user(&state, "bob", "builder", "correct horse battery", false).await;
    let other_device = seed_session(&state, alice, "Firefox / Linux").await;
    let bob_session = seed_session(&state, bob, "bob-phone").await;

    let session = login_password(&app, "alice", "correct horse battery").await;
    let cookie = format!("crbs_session={session}");
    let html = body_string(get_with_cookie(&app, &cookie, "/ui/me").await).await;
    assert!(html.contains("This device"), "{html}");
    assert!(html.contains("Log out this device"), "{html}");
    assert!(html.contains("(2 devices)"), "{html}");
    assert!(html.contains("Firefox / Linux"), "{html}");
    assert!(html.contains("Sign out all other devices"), "{html}");
    let csrf = common::extract_csrf_token(&html).expect("csrf");

    // bob 的会话行 id：alice 试撤销 → 404（列表按自己过滤，找不到）。
    let bob_row = state
        .state_store
        .find_session_by_hash(Secret::parse(&bob_session).expect("parse").hash().as_str())
        .await
        .unwrap()
        .unwrap();
    let response = post_form(
        &app,
        &cookie,
        &format!("/ui/me/sessions/{}/revoke", bob_row.id),
        format!("csrf_token={csrf}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = get_with_cookie(&app, &format!("crbs_session={bob_session}"), "/ui/me").await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = post_form(
        &app,
        &cookie,
        "/ui/me/sessions/revoke-all",
        format!("csrf_token={csrf}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/me?status=sessions_revoked")
    );
    let response = get_with_cookie(&app, &format!("crbs_session={other_device}"), "/ui/me").await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "other device must be revoked"
    );
    let response = get_with_cookie(&app, &cookie, "/ui/me").await;
    assert_eq!(response.status(), StatusCode::OK, "current must survive");

    // 单行撤销 alice 的另一设备行（other2）→ 其 cookie 失效。
    let other2 = seed_session(&state, alice, "Chrome / macOS").await;
    let html = body_string(get_with_cookie(&app, &cookie, "/ui/me").await).await;
    let csrf = common::extract_csrf_token(&html).expect("csrf");
    let other_row = state
        .state_store
        .find_session_by_hash(Secret::parse(&other2).expect("parse").hash().as_str())
        .await
        .unwrap()
        .unwrap();
    let response = post_form(
        &app,
        &cookie,
        &format!("/ui/me/sessions/{}/revoke", other_row.id),
        format!("csrf_token={csrf}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let response = get_with_cookie(&app, &format!("crbs_session={other2}"), "/ui/me").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let rows = audit_rows(&state, "session_revoke").await;
    assert_eq!(rows.len(), 2, "{rows:?}"); // 1 单行 + 1 revoke-all
}

/// 创建 → 一次性页（no-store + 明文 token）；撤销自己 ok；撤销他人 404；列表只含自己的。
#[tokio::test]
async fn token_self_management_create_and_scoped_revoke() {
    let (state, app, _tmp) = setup_app().await;
    let alice_token =
        crbs_server::server::seed_user_token_for_test(&state.state_store, "alice", "builder")
            .await
            .expect("seed alice");
    crbs_server::server::seed_user_token_for_test(&state.state_store, "bob", "viewer")
        .await
        .expect("seed bob");
    let cookie = format!("crbs_token={alice_token}");

    let page = body_string(get_with_cookie(&app, &cookie, "/ui/me").await).await;
    let csrf = common::extract_csrf_token(&page).expect("csrf");
    // 初始列表只含自己的 seed token——用户徽章同为 active，按 token 名单元格计数而非徽章。
    assert_eq!(page.matches(r#"title="test">test<"#).count(), 1, "{page}");

    let response = post_form(
        &app,
        &cookie,
        "/ui/me/tokens",
        format!("name=ci-2026&expires_in_days=90&csrf_token={csrf}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let html = body_string(response).await;
    assert!(html.contains("Token created"), "{html}");
    let secret = extract_secret(&html).expect("new token");
    assert!(secret.starts_with("crbs_tok_"), "{secret}");
    assert!(
        !html.contains(alice_token.as_str()),
        "seed token plaintext must not leak: {html}"
    );

    let alice_id = state
        .state_store
        .find_user_by_name("alice")
        .await
        .unwrap()
        .unwrap()
        .id;
    let tokens = state.state_store.list_user_tokens(alice_id).await.unwrap();
    assert_eq!(tokens.len(), 2);
    let new_row = tokens
        .iter()
        .find(|t| t.name.as_deref() == Some("ci-2026"))
        .expect("new token row");
    assert!(new_row.expires_at.is_some());
    let rows = audit_rows(&state, "create_user_token").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].user, "alice");

    let bob_id = state
        .state_store
        .find_user_by_name("bob")
        .await
        .unwrap()
        .unwrap()
        .id;
    let bob_tokens = state.state_store.list_user_tokens(bob_id).await.unwrap();
    let response = post_form(
        &app,
        &cookie,
        &format!("/ui/me/tokens/{}/revoke", bob_tokens[0].id),
        format!("csrf_token={csrf}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        state.state_store.list_user_tokens(bob_id).await.unwrap()[0]
            .revoked_at
            .is_none(),
        "bob token untouched"
    );

    let response = post_form(
        &app,
        &cookie,
        &format!("/ui/me/tokens/{}/revoke", new_row.id),
        format!("csrf_token={csrf}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/me?status=token_revoked")
    );
    let html =
        body_string(get_with_cookie(&app, &cookie, "/ui/me?status=token_revoked").await).await;
    assert!(!html.contains("ci-2026"), "{html}");
    assert!(html.contains("Token revoked."), "{html}");
    assert!(
        html.contains(r#"class="action-button danger-ghost""#),
        "{html}"
    );
    let rows = audit_rows(&state, "revoke_user_token").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].user, "alice");

    let response = post_form(
        &app,
        &cookie,
        "/ui/me/tokens",
        format!("name=&csrf_token={csrf}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert!(location.starts_with("/ui/me?error="), "{location}");

    // zh 空名 flash 本地化 round-trip（对齐 password_change_failure_flash_is_localized_for_zh）。
    let zh_cookie = format!("crbs_token={alice_token}; crbs_lang=zh");
    let response = post_form(
        &app,
        &zh_cookie,
        "/ui/me/tokens",
        format!("name=&csrf_token={csrf}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert!(
        location.contains(urlencoding::encode("名称不能为空").as_ref()),
        "{location}"
    );
    let html = body_string(get_with_cookie(&app, &zh_cookie, location).await).await;
    assert!(
        html.contains("名称不能为空"),
        "zh flash not rendered: {html}"
    );
}

/// me_token_create 重名预检：与已撤销的同名旧 token 撞名 → 303 定向 error
/// flash + DB 行数不变。seed 用 revoked 同名行钉住"预检查全量（含 revoked）"
/// ——UNIQUE(user_id, name) 部分索引把已撤销行也算进名字空间，active-only 视图漏判。
#[tokio::test]
async fn me_token_create_rejects_duplicate_name_including_revoked() {
    let (state, app, _tmp) = setup_app().await;
    let alice_token =
        crbs_server::server::seed_user_token_for_test(&state.state_store, "alice", "builder")
            .await
            .expect("seed alice");
    let cookie = format!("crbs_token={alice_token}");
    let alice_id = state
        .state_store
        .find_user_by_name("alice")
        .await
        .unwrap()
        .unwrap()
        .id;

    let secret = Secret::generate(SecretKind::UserToken).expect("token secret");
    let revoked_id = state
        .state_store
        .create_user_token(alice_id, Some("ci-old"), secret.hash().as_str(), None)
        .await
        .unwrap();
    state
        .state_store
        .revoke_user_token(revoked_id)
        .await
        .unwrap();
    let before = state
        .state_store
        .list_user_tokens(alice_id)
        .await
        .unwrap()
        .len();

    let page = body_string(get_with_cookie(&app, &cookie, "/ui/me").await).await;
    let csrf = common::extract_csrf_token(&page).expect("csrf");

    let response = post_form(
        &app,
        &cookie,
        "/ui/me/tokens",
        format!("name=ci-old&expires_in_days=90&csrf_token={csrf}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    assert!(
        location.contains("error=") && location.contains("already%20in%20use"),
        "duplicate-name flash missing: {location}"
    );
    assert_eq!(
        state
            .state_store
            .list_user_tokens(alice_id)
            .await
            .unwrap()
            .len(),
        before,
        "rejected duplicate must not create a new token row"
    );

    // zh 撞名 flash 本地化 round-trip（对齐 password_change_failure_flash_is_localized_for_zh）。
    let zh_cookie = format!("crbs_token={alice_token}; crbs_lang=zh");
    let response = post_form(
        &app,
        &zh_cookie,
        "/ui/me/tokens",
        format!("name=ci-old&expires_in_days=90&csrf_token={csrf}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert!(
        location.contains(urlencoding::encode("名称已被占用").as_ref()),
        "{location}"
    );
    let html = body_string(get_with_cookie(&app, &zh_cookie, location).await).await;
    assert!(
        html.contains("名称已被占用"),
        "zh flash not rendered: {html}"
    );
}

/// 令牌卡只列活跃 token（已撤销不渲染）、新→旧、封顶 10 条 + 底部未展示计数；总览带 Tokens = 真实活跃数。
#[tokio::test]
async fn token_card_lists_active_only_capped_at_ten_with_count() {
    let (state, app, _tmp) = setup_app().await;
    let alice =
        seed_password_user(&state, "alice", "builder", "correct horse battery", false).await;

    // 12 个活跃 token（t01 最旧 → t12 最新）+ 1 个已撤销（不应渲染）。
    for i in 1..=12 {
        state
            .state_store
            .create_user_token(alice, Some(&format!("t{i:02}")), &format!("hash-{i}"), None)
            .await
            .unwrap();
    }
    let dead = state
        .state_store
        .create_user_token(alice, Some("t-dead"), "hash-dead", None)
        .await
        .unwrap();
    state.state_store.revoke_user_token(dead).await.unwrap();

    let session = login_password(&app, "alice", "correct horse battery").await;
    let html =
        body_string(get_with_cookie(&app, &format!("crbs_session={session}"), "/ui/me").await)
            .await;
    // 封顶 10：最旧两个（t01/t02）与已撤销（t-dead）不渲染。
    for name in ["t01", "t02", "t-dead"] {
        assert!(!html.contains(name), "{name} must not render: {html}");
    }
    let pos_newest = html.find("t12").expect("t12 row");
    let pos_oldest = html.find("t03").expect("t03 row");
    assert!(pos_newest < pos_oldest, "newest-first ordering: {html}");
    // 超出封顶提示：12 活跃 - 10 展示 = 2 未显示。
    assert!(html.contains("2 more tokens not shown"), "{html}");
    // 总览带计数 = 真实活跃数（12，不被 10 条封顶截断）。
    assert!(
        html.contains(r#"<span class="label">Tokens</span><span class="value">12</span>"#),
        "{html}"
    );
}

/// 中文渲染（生而双语）：/ui/me 全卡中文文案。
#[tokio::test]
async fn me_page_renders_bilingual() {
    let (state, app, _tmp) = setup_app().await;
    seed_password_user(&state, "alice", "builder", "correct horse battery", false).await;
    let session = login_password(&app, "alice", "correct horse battery").await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/me")
                .header("Cookie", format!("crbs_session={session}; crbs_lang=zh"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_string(response).await;
    for expected in [
        "个人中心",
        "安全",
        "API 令牌",
        "我的产品",
        "最近任务",
        "活跃会话",
        "本机",
        "我的任务",
        "持有的产品",
        r#"lang="zh-CN""#,
    ] {
        assert!(html.contains(expected), "missing {expected}: {html}");
    }
}

/// /ui/me 渲染时长卡（scope=me：只算 alice 自己的构建；bob 样本不进窗口）；zh 标题双语；无趋势卡。
#[tokio::test]
async fn me_page_renders_duration_chart_without_trend() {
    let (state, app, _tmp) = setup_app().await;
    let _alice =
        seed_password_user(&state, "alice", "builder", "correct horse battery", false).await;

    // alice 一条 succeeded 构建（user 列口径 = builds."user"）。
    let build_id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "vim-9.1.0-4.el9",
            phase: "succeeded",
            arch: Some("x86_64"),
            user: "alice",
            task_id: Some(
                crbs_server::test_support::seed_task(
                    &state.state_store,
                    "fedora",
                    "vim-9.1.0-4.el9",
                )
                .await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    let completed = (chrono::Utc::now() - chrono::TimeDelta::minutes(10))
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string();
    sqlx::query("UPDATE builds SET completed_at = $1, duration = $2 WHERE id = $3")
        .bind(&completed)
        .bind(600_i64)
        .bind(build_id)
        .execute(state.state_store.pool())
        .await
        .unwrap();
    // bob 的构建（不进 alice 时长卡）。
    let bob_build = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "bob-pkg-1.0-1",
            phase: "succeeded",
            arch: Some("x86_64"),
            user: "bob",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "bob-pkg-1.0-1")
                    .await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET completed_at = $1, duration = $2 WHERE id = $3")
        .bind(&completed)
        .bind(9999_i64)
        .bind(bob_build)
        .execute(state.state_store.pool())
        .await
        .unwrap();

    let session = login_password(&app, "alice", "correct horse battery").await;
    let response = get_with_cookie(&app, &format!("crbs_session={session}"), "/ui/me").await;
    let html = body_string(response).await;
    // 时长卡独占整行（裸 viz-panel，无 cols-2 双列）。
    assert!(html.contains("Recent build durations"), "{html}");
    assert!(!html.contains("cols-2"), "{html}");
    assert!(!html.contains("Success rate trend"), "{html}");
    assert!(!html.contains("trend-chart"), "{html}");
    assert!(
        html.contains(r#"aria-label="Durations of the last 1 succeeded builds, longest 10m 0s""#),
        "{html}"
    );
    assert!(html.contains("vim-9.1.0-4.el9 · x86_64"), "{html}");
    assert!(!html.contains("bob-pkg-1.0-1"), "{html}");

    let response = get_with_cookie(
        &app,
        &format!("crbs_session={session}; crbs_lang=zh"),
        "/ui/me",
    )
    .await;
    let zh = body_string(response).await;
    assert!(zh.contains("最近构建时长"), "{zh}");
    assert!(!zh.contains("成功率趋势"), "{zh}");
}
