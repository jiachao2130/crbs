// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

// 整个文件是测试 crate：测试辅助函数（seed_* 等）不带 #[test] 属性，
// clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::{PublicAccessConfig, ServerConfig};
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;

fn server_config_with_public_access(public_access: PublicAccessConfig) -> ServerConfig {
    ServerConfig {
        public_access,
        ..ServerConfig::default()
    }
}

fn server_config_with_both(
    public_access: PublicAccessConfig,
    web_ui_enabled: bool,
) -> ServerConfig {
    ServerConfig {
        public_access,
        web_ui_enabled,
        ..ServerConfig::default()
    }
}

async fn setup_app_with_config(
    roles: &[(&str, &str)],
    public_access: PublicAccessConfig,
) -> (
    Arc<AppState>,
    axum::Router,
    tempfile::TempDir,
    std::collections::HashMap<String, String>,
) {
    setup_app_with_full_config(roles, server_config_with_public_access(public_access)).await
}

async fn setup_app_with_full_config(
    roles: &[(&str, &str)],
    server_config: ServerConfig,
) -> (
    Arc<AppState>,
    axum::Router,
    tempfile::TempDir,
    std::collections::HashMap<String, String>,
) {
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        state_store,
        server_config,
        tmp_dir.path().to_path_buf(),
    ));

    let mut tokens = std::collections::HashMap::new();
    for (name, role) in roles {
        let raw = seed_user_token_for_test(&app_state.state_store, name, role)
            .await
            .expect("seed user token");
        tokens.insert((*name).to_string(), raw);
    }
    let app = create_test_app_with_auth(app_state.clone());
    (app_state, app, tmp_dir, tokens)
}

async fn insert_build_with_artifact(
    state: &AppState,
    tmp_dir: &std::path::Path,
    user: &str,
) -> i64 {
    let result_dir = tmp_dir.join("results").join(user).join("pkg").join("1");
    tokio::fs::create_dir_all(&result_dir).await.unwrap();
    tokio::fs::write(result_dir.join("hello.rpm"), b"dummy rpm")
        .await
        .unwrap();

    let result_dir_str = result_dir.to_string_lossy().to_string();

    state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg",
            phase: "succeeded",
            result_dir: Some(&result_dir_str),
            backend: "chroot",
            user,
            arch: Some("x86_64"),
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap()
}

// -------------- UI 默认公开访问 --------------

#[tokio::test]
async fn ui_dashboard_public_by_default() {
    let roles: &[(&str, &str)] = &[];
    let (_state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    let response = app
        .oneshot(Request::builder().uri("/ui/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn ui_builds_public_by_default() {
    let roles: &[(&str, &str)] = &[];
    let (_state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/builds")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// -------------- UI 关闭公开访问后需认证：表驱动契约见 integration_ui_redirects.rs --------------

// -------------- 认证后 UI 可访问（view 关闭时）--------------

#[tokio::test]
async fn ui_dashboard_accessible_with_auth_when_view_disabled() {
    let roles: &[(&str, &str)] = &[("viewer-token", "viewer")];
    let public_access = PublicAccessConfig {
        view: false,
        logs: true,
        download: true,
    };
    let (_state, app, _tmp, tokens) = setup_app_with_config(roles, public_access).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["viewer-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// -------------- 产物下载公开访问 --------------

#[tokio::test]
async fn artifact_download_public_by_default() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let id = insert_build_with_artifact(&state, tmp.path(), "alice").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/builds/{}/artifacts/download?file=hello.rpm",
                    id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // 公开下载不仅可达，还要真的吐出产物字节（对照 integration_worker.rs 的
    // SRPM 下载断言写法）。
    let downloaded = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(downloaded.as_ref(), b"dummy rpm");
}

/// result_dir 指向 result root 之外的构建，产物下载 400 且响应
/// body 不回显服务端绝对路径——Validation 细节（含根外路径与 result root）
/// 只进日志不进响应。
#[tokio::test]
async fn artifact_download_invalid_result_dir_does_not_leak_paths() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    // result_dir 指向 root 外的真实目录（/etc，保证 canonicalize 命中的是
    // "escapes root" 而非 NotFound 分支——两者都必须不泄路径）。
    let outside_dir = "/etc";
    let task_id = crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg").await;
    let id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg",
            phase: "succeeded",
            result_dir: Some(outside_dir),
            backend: "chroot",
            user: "alice",
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/builds/{}/artifacts/download?file=hello.rpm",
                    id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(
        !body.contains(outside_dir),
        "response must not echo the outside path, got: {body}"
    );
    let result_root = tmp.path().join("results");
    assert!(
        !body.contains(result_root.to_str().unwrap()),
        "response must not leak the result root, got: {body}"
    );
}

#[tokio::test]
async fn artifact_download_requires_auth_when_disabled() {
    let roles: &[(&str, &str)] = &[];
    let public_access = PublicAccessConfig {
        view: true,
        logs: true,
        download: false,
    };
    let (state, app, tmp, _tokens) = setup_app_with_config(roles, public_access).await;
    let id = insert_build_with_artifact(&state, tmp.path(), "alice").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/builds/{}/artifacts/download?file=hello.rpm",
                    id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn artifact_download_with_bearer_token_when_disabled() {
    let roles: &[(&str, &str)] = &[("alice-token", "viewer")];
    let public_access = PublicAccessConfig {
        view: true,
        logs: true,
        download: false,
    };
    let (state, app, tmp, tokens) = setup_app_with_config(roles, public_access).await;
    let id = insert_build_with_artifact(&state, tmp.path(), "alice-token").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/builds/{}/artifacts/download?file=hello.rpm",
                    id
                ))
                .header("Authorization", format!("Bearer {}", tokens["alice-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn artifact_download_with_cookie_token_when_disabled() {
    let roles: &[(&str, &str)] = &[("alice-token", "viewer")];
    let public_access = PublicAccessConfig {
        view: true,
        logs: true,
        download: false,
    };
    let (state, app, tmp, tokens) = setup_app_with_config(roles, public_access).await;
    let id = insert_build_with_artifact(&state, tmp.path(), "alice-token").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/builds/{}/artifacts/download?file=hello.rpm",
                    id
                ))
                .header("Cookie", format!("crbs_token={}", tokens["alice-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// -------------- 登录页 --------------

#[tokio::test]
async fn login_page_is_always_public() {
    let roles: &[(&str, &str)] = &[];
    let public_access = PublicAccessConfig {
        view: false,
        logs: false,
        download: false,
    };
    let (_state, app, _tmp, _tokens) = setup_app_with_config(roles, public_access).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_sets_cookie_on_valid_token() {
    let roles: &[(&str, &str)] = &[("viewer-token", "viewer")];
    let public_access = PublicAccessConfig {
        view: true,
        logs: true,
        download: false,
    };
    let (state, app, tmp, tokens) = setup_app_with_config(roles, public_access).await;
    let id = insert_build_with_artifact(&state, tmp.path(), "viewer-token").await;

    // 1. 取登录页 nonce cookie 与 CSRF token
    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let login_cookie = login_response
        .headers()
        .get("set-cookie")
        .expect("Set-Cookie should be present")
        .to_str()
        .unwrap()
        .to_string();
    assert!(login_cookie.contains("crbs_login_nonce"));
    let body = axum::body::to_bytes(login_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    let csrf_token = common::extract_csrf_token(&text).expect("CSRF token should be present");

    // 2. 携带有效 token + CSRF 提交登录
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", login_cookie)
                .body(Body::from(format!(
                    "token={}&csrf_token={}",
                    tokens["viewer-token"], csrf_token
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .expect("Set-Cookie header should be present");
    let cookie = set_cookie.to_str().unwrap();
    assert!(cookie.contains(&format!("crbs_token={}", tokens["viewer-token"])));
    assert!(
        !cookie.contains("Secure"),
        "cookie should not contain Secure without TLS"
    );
    assert!(
        cookie.contains("Max-Age=604800"),
        "user token cookie should have default 7-day Max-Age"
    );

    // 使用 cookie 下载
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/builds/{}/artifacts/download?file=hello.rpm",
                    id
                ))
                .header("Cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_cookie_sets_max_age_for_db_token() {
    use crbs_core::auth::secret::{Secret, SecretHash, SecretKind};

    let roles: &[(&str, &str)] = &[];
    let (state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    let user_id = state
        .state_store
        .create_user("alice", "builder")
        .await
        .unwrap();
    let secret = Secret::generate(SecretKind::UserToken).unwrap();
    let future = "2099-12-31T23:59:59+00:00";
    state
        .state_store
        .create_user_token(
            user_id,
            Some("laptop"),
            SecretHash::from_plain(secret.as_str()).as_str(),
            Some(future),
        )
        .await
        .unwrap();

    // 1. 取登录页 nonce cookie 与 CSRF token
    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let login_cookie = login_response
        .headers()
        .get("set-cookie")
        .expect("Set-Cookie should be present")
        .to_str()
        .unwrap()
        .to_string();
    let body = axum::body::to_bytes(login_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    let csrf_token = common::extract_csrf_token(&text).expect("CSRF token should be present");

    // 2. 携带有效 DB token + CSRF 提交登录
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", login_cookie)
                .body(Body::from(format!(
                    "token={}&csrf_token={}",
                    secret.as_str(),
                    csrf_token
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let set_cookie = response
        .headers()
        .get("set-cookie")
        .expect("Set-Cookie header should be present");
    let cookie = set_cookie.to_str().unwrap();
    assert!(cookie.contains("crbs_token="));
    assert!(cookie.contains("Max-Age="));
    let start = cookie.find("Max-Age=").unwrap() + "Max-Age=".len();
    let rest = &cookie[start..];
    let end = rest.find(';').unwrap_or(rest.len());
    let max_age: i64 = rest[..end].parse().unwrap();
    assert!(max_age > 0);
}

#[tokio::test]
async fn login_rejects_invalid_token() {
    let roles: &[(&str, &str)] = &[];
    let (_state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let login_cookie = login_response
        .headers()
        .get("set-cookie")
        .expect("Set-Cookie should be present")
        .to_str()
        .unwrap()
        .to_string();
    let body = axum::body::to_bytes(login_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    let csrf_token = common::extract_csrf_token(&text).expect("CSRF token should be present");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", login_cookie)
                .body(Body::from(format!(
                    "token=invalid-token&csrf_token={}",
                    csrf_token
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    // 登录失败就地重渲染表单（200，非 401）。
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_rejects_missing_csrf_token() {
    let roles: &[(&str, &str)] = &[("viewer-token", "viewer")];
    let (_state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from("token=viewer-token"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_clears_token_cookie() {
    let roles: &[(&str, &str)] = &[("admin-token", "admin")];
    let (_state, app, _tmp, tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let cookie = cookie_header(&tokens["admin-token"]);

    // 取已登录页面，从 nav-logout 表单提取 CSRF token
    let page_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .header("Cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let page_body = axum::body::to_bytes(page_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let page_html = String::from_utf8_lossy(&page_body);
    let csrf_token = common::extract_csrf_token(&page_html)
        .expect("page should contain CSRF token for logged-in user");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/logout")
                .header("Cookie", cookie)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("csrf_token={}", csrf_token)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    // logout 清两类会话 cookie（session 模式 + token 模式都覆盖）。
    let all_cookies: Vec<&str> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    for name in ["crbs_token=", "crbs_session="] {
        let cleared = all_cookies
            .iter()
            .find(|c| c.starts_with(name))
            .unwrap_or_else(|| panic!("{name} clear cookie missing: {all_cookies:?}"));
        assert!(cleared.contains("Max-Age=0"), "{cleared}");
    }
}

#[tokio::test]
async fn login_redirect_response_body_is_minimal() {
    let roles: &[(&str, &str)] = &[("viewer-token", "viewer")];
    let (_state, app, _tmp, tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    // 1. 取登录页
    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let login_cookie = login_response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let body = axum::body::to_bytes(login_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    let csrf_token = common::extract_csrf_token(&text).expect("CSRF token should be present");

    // 2. 携带有效 token 提交，断言 303 + 极简 body
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", login_cookie)
                .body(Body::from(format!(
                    "token={}&csrf_token={}",
                    tokens["viewer-token"], csrf_token
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        response.headers().get("content-security-policy").is_none(),
        "303 redirect should not carry CSP"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body).to_lowercase();
    assert!(
        !text.contains("<style"),
        "303 redirect body should not inline styles"
    );
    assert!(text.contains("redirecting"));
}

#[tokio::test]
async fn logout_redirect_response_body_is_minimal() {
    let roles: &[(&str, &str)] = &[("admin-token", "admin")];
    let (_state, app, _tmp, tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let cookie = cookie_header(&tokens["admin-token"]);

    // 取已登录页面，从 nav-logout 表单提取 CSRF token
    let page_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .header("Cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let page_body = axum::body::to_bytes(page_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let page_html = String::from_utf8_lossy(&page_body);
    let csrf_token = common::extract_csrf_token(&page_html)
        .expect("page should contain CSRF token for logged-in user");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/logout")
                .header("Cookie", cookie)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("csrf_token={}", csrf_token)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        response.headers().get("content-security-policy").is_none(),
        "303 redirect should not carry CSP"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body).to_lowercase();
    assert!(
        !text.contains("<style"),
        "303 redirect body should not inline styles"
    );
    assert!(text.contains("redirecting"));
}

#[tokio::test]
async fn login_invalid_token_response_has_csp() {
    let roles: &[(&str, &str)] = &[];
    let (_state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let login_cookie = login_response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let body = axum::body::to_bytes(login_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    let csrf_token = common::extract_csrf_token(&text).expect("CSRF token should be present");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", login_cookie)
                .body(Body::from(format!(
                    "token=invalid-token&csrf_token={}",
                    csrf_token
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    // 登录失败就地重渲染表单（200，非 401 整页错误）。
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().contains_key("content-security-policy"),
        "login failure re-render should have CSP"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("Invalid token."));
}

// -------------- web_ui_enabled 开关 --------------

#[tokio::test]
async fn ui_routes_return_404_when_web_ui_disabled() {
    let roles: &[(&str, &str)] = &[];
    let server_config = server_config_with_both(PublicAccessConfig::default(), false);
    let (_state, app, _tmp, _tokens) = setup_app_with_full_config(roles, server_config).await;

    for path in ["/", "/ui/", "/ui/builds", "/ui/login"] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "path={} should be disabled",
            path
        );
    }
}

#[tokio::test]
async fn health_and_download_still_work_when_web_ui_disabled() {
    let roles: &[(&str, &str)] = &[];
    let server_config = server_config_with_both(PublicAccessConfig::default(), false);
    let (state, app, tmp, _tokens) = setup_app_with_full_config(roles, server_config).await;
    let id = insert_build_with_artifact(&state, tmp.path(), "alice").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/builds/{}/artifacts/download?file=hello.rpm",
                    id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn ui_routes_enabled_by_default() {
    let roles: &[(&str, &str)] = &[];
    let (_state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    let response = app
        .oneshot(Request::builder().uri("/ui/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// -------------- 公开状态摘要端点 --------------

#[tokio::test]
async fn public_status_endpoint_is_public() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    state
        .state_store
        .insert_task(crbs_core::TaskInsert {
            product: "fedora",
            pkg_name: "pkg",
            user: "alice",
            phase: "succeeded",
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // status 含实时任务计数，禁缓存——health/version/status 三探针均钉 no-store。
    assert_eq!(
        response.headers().get(axum::http::header::CACHE_CONTROL),
        Some(&axum::http::HeaderValue::from_static("no-store"))
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(json["version"].as_str().is_some());
    assert_eq!(json["tasks"]["total"], 1);
    assert_eq!(json["tasks"]["succeeded"], 1);
    assert_eq!(json["tasks"]["failed"], 0);
    assert!(json["workers"]["online"].is_number());
}

#[tokio::test]
async fn public_status_does_not_expose_disk_info() {
    let roles: &[(&str, &str)] = &[];
    let (_state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("disk").is_none());
    assert!(json.get("concurrency").is_none());
    assert!(json.get("crbs_root").is_none());
}

// -------------- UI 分页与过滤 --------------

/// 构建种子挂在 task 下：builds.task_id NOT NULL，build 行必须挂任务。
async fn insert_build(state: &AppState, product: &str, phase: &str, user: &str) -> i64 {
    let task_id = state
        .state_store
        .insert_task(crbs_core::TaskInsert {
            product,
            pkg_name: "pkg",
            phase,
            user,
            ..Default::default()
        })
        .await
        .unwrap();
    state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product,
            pkg_name: "pkg",
            phase,
            backend: "chroot",
            user,
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn ui_builds_pagination_uses_limit_and_offset() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    for _ in 0..5 {
        insert_build(&state, "fedora", "succeeded", "alice").await;
    }

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/builds?limit=2&offset=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("alice"));
    assert!(text.contains("Next →"));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/builds?limit=2&offset=4")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("← Previous"));
}

#[tokio::test]
async fn ui_builds_filters_by_product() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    insert_build(&state, "fedora", "succeeded", "alice").await;
    insert_build(&state, "centos", "succeeded", "bob").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/builds?product=fedora")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("alice"));
    assert!(!text.contains("bob"));
}

#[tokio::test]
async fn ui_tasks_filters_by_product() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    state
        .state_store
        .insert_task(crbs_core::TaskInsert {
            product: "fedora",
            pkg_name: "pkg",
            phase: "succeeded",
            user: "alice",
            user_id: None,
            priority: 0,
            result_dir: None,
            srpm_path: None,
            ..Default::default()
        })
        .await
        .unwrap();
    state
        .state_store
        .insert_task(crbs_core::TaskInsert {
            product: "centos",
            pkg_name: "pkg",
            phase: "succeeded",
            user: "bob",
            user_id: None,
            priority: 0,
            result_dir: None,
            srpm_path: None,
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/tasks?product=fedora")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("alice"));
    assert!(!text.contains("bob"));
}

// -------------- Phase 3: SSE + 取消按钮 -------------

fn cookie_header(token: &str) -> String {
    format!("crbs_token={}", token)
}

fn extract_login_nonce_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    let set_cookie = headers.get("set-cookie")?.to_str().ok()?;
    set_cookie
        .strip_prefix("crbs_login_nonce=")
        .and_then(|rest| rest.split(';').next().map(|s| s.trim().to_string()))
}

async fn insert_pending_task(state: &AppState, user: &str) -> i64 {
    state
        .state_store
        .insert_task(crbs_core::TaskInsert {
            product: "fedora",
            pkg_name: "pkg",
            user,
            user_id: None,
            phase: "pending",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap()
}

async fn insert_pending_build(state: &AppState, user: &str) -> i64 {
    state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg",
            backend: "chroot",
            user,
            arch: Some("x86_64"),
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn ui_build_detail_shows_cancel_button_for_owner() {
    let roles: &[(&str, &str)] = &[("builder-token", "builder")];
    let (state, app, _tmp, tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let id = insert_pending_build(&state, "builder-token").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ui/builds/{}", id))
                .header("Cookie", cookie_header(&tokens["builder-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("Cancel"));
    assert!(common::extract_csrf_token(&text).is_some());
}

#[tokio::test]
async fn ui_build_cancel_requires_csrf_token() {
    let roles: &[(&str, &str)] = &[("builder-token", "builder")];
    let (state, app, _tmp, tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let id = insert_pending_build(&state, "builder-token").await;

    // 先获取页面中的 CSRF token
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ui/builds/{}", id))
                .header("Cookie", cookie_header(&tokens["builder-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    let csrf_token = common::extract_csrf_token(&text).expect("CSRF token should be present");

    // 不带 CSRF token 应被拒绝
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/builds/{}", id))
                .header("Cookie", cookie_header(&tokens["builder-token"]))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from("csrf_token="))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // 错误的 CSRF token 也应被拒绝
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/builds/{}", id))
                .header("Cookie", cookie_header(&tokens["builder-token"]))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from("csrf_token=wrong"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // 正确的 CSRF token 应成功取消 pending 构建
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/builds/{}", id))
                .header("Cookie", cookie_header(&tokens["builder-token"]))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("csrf_token={}", csrf_token)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        location.contains("status=cancelled"),
        "location was: {}",
        location
    );
}

#[tokio::test]
async fn ui_build_cancel_terminal_build_redirects_with_error() {
    let roles: &[(&str, &str)] = &[("builder-token", "builder")];
    let (state, app, _tmp, tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let terminal_id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg",
            phase: "succeeded",
            backend: "chroot",
            user: "builder-token",
            arch: Some("x86_64"),
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    // 终端构建页面不展示取消按钮，因此从另一个非终端构建页面获取 CSRF token。
    let pending_id = insert_pending_build(&state, "builder-token").await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ui/builds/{}", pending_id))
                .header("Cookie", cookie_header(&tokens["builder-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    let csrf_token = common::extract_csrf_token(&text).expect("CSRF token should be present");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/builds/{}", terminal_id))
                .header("Cookie", cookie_header(&tokens["builder-token"]))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("csrf_token={}", csrf_token)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("error"), "location was: {}", location);
}

#[tokio::test]
async fn ui_build_cancel_non_owner_rejected() {
    let roles: &[(&str, &str)] = &[("builder-token", "builder"), ("other-token", "builder")];
    let (state, app, _tmp, tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let id = insert_pending_build(&state, "builder-token").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/builds/{}", id))
                .header("Cookie", cookie_header(&tokens["other-token"]))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from("csrf_token=anything"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn ui_build_detail_hides_cancel_for_bearer_auth() {
    let roles: &[(&str, &str)] = &[("builder-token", "builder")];
    let (state, app, _tmp, tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let id = insert_pending_build(&state, "builder-token").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/ui/builds/{}", id))
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(!text.contains("Cancel"));
}

#[tokio::test]
async fn ui_builds_limit_is_clamped() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    // 超过 UI_PAGE_SIZE_MAX（200，cookie 档位放宽后 page_size_or_default
    // 的 clamp 上限，见 ui/service.rs）条构建，验证 limit=99999 被压到 200：
    // 页面只渲染 200 行，Total 仍报全量。
    let total = 205;
    for _ in 0..total {
        insert_build(&state, "fedora", "succeeded", "alice").await;
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/builds?limit=99999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    let rows = html.matches(r#"class="clickable-row""#).count();
    assert_eq!(
        rows, 200,
        "limit=99999 must be clamped to UI_PAGE_SIZE_MAX=200 rows; got {rows}"
    );
    assert!(
        html.contains(r#"<span class="count-chip">205</span>"#),
        "total must reflect all builds, not the clamped page size: {html}"
    );
}

#[tokio::test]
async fn ui_task_cancel_with_csrf_token_succeeds() {
    let roles: &[(&str, &str)] = &[("builder-token", "builder")];
    let (state, app, _tmp, tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let id = insert_pending_task(&state, "builder-token").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ui/tasks/{}", id))
                .header("Cookie", cookie_header(&tokens["builder-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    let csrf_token = common::extract_csrf_token(&text).expect("CSRF token should be present");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/tasks/{}", id))
                .header("Cookie", cookie_header(&tokens["builder-token"]))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("csrf_token={}", csrf_token)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("status=cancelled"));

    // 重新加载页面，确认 phase 已更新
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/ui/tasks/{}", id))
                .header("Cookie", cookie_header(&tokens["builder-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("cancelled"));
    assert!(!text.contains("Cancel"));
}

#[tokio::test]
async fn ui_task_cancel_non_owner_rejected() {
    let roles: &[(&str, &str)] = &[("builder-token", "builder"), ("other-token", "builder")];
    let (state, app, _tmp, tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let id = insert_pending_task(&state, "builder-token").await;

    // other-token 只能获取页面，但没有取消按钮（因为不是 owner/operator）
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ui/tasks/{}", id))
                .header("Cookie", cookie_header(&tokens["other-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(!text.contains("Cancel"));

    // 即使伪造带 CSRF token 的 POST，也因权限不足被拒绝
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/tasks/{}", id))
                .header("Cookie", cookie_header(&tokens["other-token"]))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from("csrf_token=anything"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// -------------- SSE 端点 --------------

fn assert_event_stream(response: &axum::response::Response) {
    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        content_type.starts_with("text/event-stream"),
        "expected text/event-stream, got {}",
        content_type
    );
}

#[tokio::test]
async fn ui_dashboard_sse_public_by_default() {
    let roles: &[(&str, &str)] = &[];
    let (_state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_event_stream(&response);
}

/// HEAD /ui/events 显式短路 204（不进 GET handler——回落会执行
/// 一次性 DB 查 + spawn 空转后 200 空 body）；204 属 2xx，探针兼容。
/// 同族三个 build/task/log SSE 端点共享同一短路 handler，此处钉一个代表。
#[tokio::test]
async fn head_ui_events_short_circuits_204() {
    let roles: &[(&str, &str)] = &[];
    let (_state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/ui/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        response.headers().get("content-type").is_none()
            || !response.headers()["content-type"]
                .to_str()
                .unwrap_or("")
                .starts_with("text/event-stream"),
        "HEAD must not open an SSE stream"
    );

    // 同 URI GET 行为不受影响：200 + text/event-stream。
    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_event_stream(&response);
}

#[tokio::test]
async fn ui_build_sse_public_by_default() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let id = insert_build(&state, "fedora", "succeeded", "alice").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/ui/builds/{}/events", id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_event_stream(&response);
}

#[tokio::test]
async fn ui_task_sse_public_by_default() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let id = insert_pending_task(&state, "alice").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/ui/tasks/{}/events", id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_event_stream(&response);
}

#[tokio::test]
async fn ui_log_sse_public_by_default() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let id = insert_build_with_artifact(&state, tmp.path(), "alice").await;

    // 在 result_dir 写入 build.log，让 log_sse 走文件回退路径。
    let record = state.state_store.get_build(id).await.unwrap().unwrap();
    let result_dir = record.result_dir.unwrap();
    let result_root = state.result_dir_for_or_default(&record.product).await;
    let base = crbs_core::util::validate_result_dir(&result_dir, &result_root)
        .await
        .unwrap();
    tokio::fs::write(base.join("build.log"), b"hello sse log")
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/ui/builds/{}/logs/stream", id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_event_stream(&response);
}

// -------------- CSP 与 nonce --------------

fn extract_csp_nonce(response: &axum::response::Response) -> Option<String> {
    let csp = response
        .headers()
        .get("content-security-policy")?
        .to_str()
        .ok()?;
    let prefix = "nonce-";
    let start = csp.find(prefix)? + prefix.len();
    let rest = &csp[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_alphanumeric())
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

fn extract_nonce_from_html(html: &str, tag: &str) -> Option<String> {
    let prefix = format!("<{} nonce=\"", tag);
    let start = html.find(&prefix)? + prefix.len();
    let rest = &html[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[tokio::test]
async fn ui_pages_set_csp_and_security_headers() {
    let roles: &[(&str, &str)] = &[];
    let (_state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    for path in [
        "/ui/",
        "/ui/login",
        "/ui/builds",
        "/ui/tasks",
        "/ui/products",
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "path={}", path);
        assert!(
            response.headers().contains_key("content-security-policy"),
            "CSP header missing for path={}",
            path
        );
        let csp = response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        // style-src 放宽为 'unsafe-inline' + 扩展协议源（扩展 link-hint 定位
        // 样式被 nonce-only style-src 拦截：<link> 引用的扩展样式表文件还需协议
        // 源放行）；script-src 必须仍携带 nonce（XSS 主防线）。
        assert!(
            csp.contains(
                "style-src 'self' 'unsafe-inline' safari-web-extension: chrome-extension:"
            ),
            "style-src must allow inline + extension scheme styles for path={}, got: {csp}",
            path
        );
        assert!(
            csp.contains("script-src 'self' 'nonce-"),
            "script-src must stay nonce-gated for path={}, got: {csp}",
            path
        );
        assert_eq!(
            response
                .headers()
                .get("x-frame-options")
                .unwrap()
                .to_str()
                .unwrap(),
            "DENY",
            "X-Frame-Options for path={}",
            path
        );
        assert_eq!(
            response
                .headers()
                .get("x-content-type-options")
                .unwrap()
                .to_str()
                .unwrap(),
            "nosniff",
            "X-Content-Type-Options for path={}",
            path
        );
    }
}

#[tokio::test]
async fn ui_dashboard_inline_nonce_matches_csp() {
    let roles: &[(&str, &str)] = &[];
    let (_state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    let response = app
        .oneshot(Request::builder().uri("/ui/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let csp = response
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .expect("CSP header should be present");
    // style-src 放宽为 'unsafe-inline'（扩展 link-hint 定位样式被 nonce-only
    // style-src 拦截），CSP 中仅 script-src 携带 nonce。
    assert!(csp.contains("style-src 'self' 'unsafe-inline'"), "{csp}");
    let csp_nonce = extract_csp_nonce(&response).expect("CSP nonce should be present");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    let style_nonce =
        extract_nonce_from_html(&text, "style").expect("style nonce should be present");
    let script_nonce =
        extract_nonce_from_html(&text, "script").expect("script nonce should be present");
    // <style> 上的 nonce 属性保留（无害），与 script 共用同一 nonce。
    assert_eq!(style_nonce, script_nonce);
    assert_eq!(script_nonce, csp_nonce);
    assert!(text.contains("EventSource('/ui/events')"));
}

#[tokio::test]
async fn ui_build_detail_inline_nonce_matches_csp() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let id = insert_build_with_artifact(&state, tmp.path(), "alice").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/ui/builds/{}", id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let csp_nonce = extract_csp_nonce(&response).expect("CSP nonce should be present");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    let script_nonce =
        extract_nonce_from_html(&text, "script").expect("script nonce should be present");
    assert_eq!(script_nonce, csp_nonce);
    assert!(text.contains(&format!("/ui/builds/{}/events", id)));
}

#[tokio::test]
async fn ui_build_logs_inline_nonce_matches_csp() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let id = insert_build_with_artifact(&state, tmp.path(), "alice").await;
    // 日志页只在 live（非终态）构建中内联 SSE 脚本；直接构造 UI 前置状态
    // （终态不可变守卫禁止 update_build_phase 把 succeeded 改回 building）。
    sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
        .bind(id)
        .execute(state.state_store.pool())
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/ui/builds/{}/logs", id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let csp_nonce = extract_csp_nonce(&response).expect("CSP nonce should be present");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    let script_nonce =
        extract_nonce_from_html(&text, "script").expect("script nonce should be present");
    assert_eq!(script_nonce, csp_nonce);
    assert!(text.contains(&format!("/ui/builds/{}/logs/stream", id)));
}

/// 日志页闭环：building 日志页的 `.log-actions` 渲染四元素（live 指示灯 +
/// Follow 开关 + Jump to bottom + Download 常驻链接）；终态页不嵌 stream 脚本、
/// 无操作条（仅钉住契约）。
#[tokio::test]
async fn ui_build_logs_live_page_renders_log_action_controls() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let id = insert_build_with_artifact(&state, tmp.path(), "alice").await;
    sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
        .bind(id)
        .execute(state.state_store.pool())
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ui/builds/{}/logs", id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains(r#"class="log-actions""#), "{text}");
    assert!(text.contains(r#"class="live-indicator""#), "{text}");
    assert!(text.contains(r#"id="follow-toggle""#), "{text}");
    assert!(text.contains("checked"), "Follow must default on: {text}");
    assert!(text.contains(r#"id="jump-bottom""#), "{text}");
    assert!(
        text.contains(&format!(r#"href="/api/v1/builds/{}/logs?offset=0""#, id)),
        "Download must link the full-log API endpoint: {text}"
    );

    // 终态（原始 succeeded）：不嵌 stream 脚本，也不渲染 live 操作条。
    sqlx::query("UPDATE builds SET phase = 'succeeded' WHERE id = $1")
        .bind(id)
        .execute(state.state_store.pool())
        .await
        .unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/ui/builds/{}/logs", id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        !text.contains(&format!("/ui/builds/{}/logs/stream", id)),
        "terminal page must not embed the stream script: {text}"
    );
    assert!(
        !text.contains(r#"class="log-actions""#),
        "terminal page has no live action bar: {text}"
    );
}

#[tokio::test]
async fn ui_task_detail_inline_nonce_matches_csp() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let id = insert_pending_task(&state, "alice").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/ui/tasks/{}", id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let csp_nonce = extract_csp_nonce(&response).expect("CSP nonce should be present");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    let script_nonce =
        extract_nonce_from_html(&text, "script").expect("script nonce should be present");
    assert_eq!(script_nonce, csp_nonce);
    assert!(text.contains(&format!("/ui/tasks/{}/events", id)));
}

#[tokio::test]
async fn ui_redirect_response_does_not_leak_csp() {
    let roles: &[(&str, &str)] = &[("viewer-token", "viewer")];
    let (_state, app, _tmp, tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    // 获取登录页 nonce cookie 和 CSRF token
    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let login_cookie =
        extract_login_nonce_cookie(login_response.headers()).expect("login nonce cookie");
    let body = axum::body::to_bytes(login_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    let csrf_token = common::extract_csrf_token(&text).expect("CSRF token should be present");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", format!("crbs_login_nonce={}", login_cookie))
                .body(Body::from(format!(
                    "token={}&csrf_token={}",
                    tokens["viewer-token"], csrf_token
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        !response.headers().contains_key("content-security-policy"),
        "redirect responses should not set CSP"
    );
    assert!(response.headers().contains_key("location"));
}

// -------------- UI 错误页（JSON → HTML 重写）--------------

/// UI 路由撞到 404 时，中间件将后端 JSON 重写为 HTML 错误页（状态码保留）。
#[tokio::test]
async fn ui_missing_build_returns_html_error_page() {
    let roles: &[(&str, &str)] = &[];
    let (_state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/builds/999999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        content_type.starts_with("text/html"),
        "expected html error page, got content-type {content_type}"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("Back to dashboard"), "body: {text}");
    assert!(text.contains("404 Not Found"), "body: {text}");
}

/// API 路由的 404 仍返回 JSON——中间件只挂在 UI 路由，不影响 API 行为。
#[tokio::test]
async fn api_missing_build_stays_json() {
    let roles: &[(&str, &str)] = &[("viewer-token", "viewer")];
    let (_state, app, _tmp, tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/builds/999999")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["viewer-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        content_type.starts_with("application/json"),
        "API 404 should remain JSON, got content-type {content_type}"
    );
}

/// 登录失败返回 HTML 登录页（200 就地重渲染），中间件不应把它重写成错误页。
#[tokio::test]
async fn login_failure_stays_html_login_page() {
    let roles: &[(&str, &str)] = &[];
    let (_state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let login_cookie = login_response
        .headers()
        .get("set-cookie")
        .expect("Set-Cookie should be present")
        .to_str()
        .unwrap()
        .to_string();
    let body = axum::body::to_bytes(login_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    let csrf_token = common::extract_csrf_token(&text).expect("CSRF token should be present");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", login_cookie)
                .body(Body::from(format!(
                    "token=invalid-token&csrf_token={}",
                    csrf_token
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    // 登录失败就地重渲染表单（200），保留输入与统一文案。
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        content_type.starts_with("text/html"),
        "login failure should stay HTML, got content-type {content_type}"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("Invalid token."), "body: {text}");
    assert!(
        !text.contains("Back to dashboard"),
        "login page must not be rewritten into the error page: {text}"
    );
}

// -------------- 详情页产物元数据来自 build_artifacts 表 --------------

/// build 详情页优先渲染 DB 产物表（File/Kind/Arch/Size 四列 + 卡头 changelog 入口）。
#[tokio::test]
async fn ui_build_detail_renders_db_artifact_table() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, _tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;

    let id = insert_build(&state, "fedora", "succeeded", "alice").await;

    let sha = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let artifact = crbs_core::NewArtifact {
        relative_path: "x86_64/hello-1.0-1.x86_64.rpm".to_string(),
        kind: crbs_core::ArtifactKind::Rpm,
        size_bytes: 512,
        sha256: sha.to_string(),
        unsigned_sha256: None,
        arch: Some("x86_64".to_string()),
        name: Some("hello".to_string()),
        version: Some("1.0".to_string()),
        release: Some("1".to_string()),
        epoch: None,
        metadata_json: None,
        signed: true,
    };
    let mut tx = state.state_store.pool().begin().await.unwrap();
    state
        .state_store
        .insert_artifacts_tx(&mut tx, id, &[artifact], "2026-07-25 00:00:00")
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/ui/builds/{}", id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);

    // 表内无 SHA256 列：指纹反查走 API by-sha256 端点，表内零输出
    //（表头、短前缀、title 全值均不渲染）。
    assert!(
        !text.contains("SHA256"),
        "artifact table must not have SHA256 header: {text}"
    );
    assert!(
        !text.contains(&sha[..12]),
        "artifact table must not render sha prefix: {text}"
    );
    assert!(!text.contains(sha), "full sha256 must not render: {text}");
    // NEVRA（文件名列 basename 载体）
    assert!(
        text.contains("hello-1.0-1"),
        "body should contain NEVRA: {text}"
    );
    // size 字符串（与组件同一 humansize 调用）
    let expected_size = humansize::format_size(512u64, humansize::DECIMAL);
    assert!(
        text.contains(&expected_size),
        "body should contain size string {expected_size}: {text}"
    );
    // signed 列不在产物表：构建级属性走 Details 侧栏 Signed 行（side-kv
    // dt/dd，非 th）。不能断言裸 "signed"——"assigned" 含该
    // 子串（CSS 注释与 PHASE_LABELS 注入）。
    assert!(
        !text.contains("<th>Signed</th>"),
        "artifact table must not have Signed header: {text}"
    );
    assert!(
        !text.contains(">signed<"),
        "artifact table must not contain signed badge text: {text}"
    );
    // 走 DB 表格路径（含表头）而非磁盘 ul
    assert!(
        text.contains("<th>Kind</th>"),
        "body should render artifact table header"
    );
    // changelog 入口上移产物卡头——rpm 行在场时恰一个 build 作用域
    // 链接；行内 sha 作用域链接零输出。
    let changelog_href = format!("/ui/builds/{id}/changelog");
    assert_eq!(
        text.matches(&changelog_href).count(),
        1,
        "exactly one card-header changelog link: {text}"
    );
    assert_eq!(
        text.matches("class=\"changelog-link\"").count(),
        1,
        "no extra inline changelog links: {text}"
    );
    assert!(
        !text.contains("/ui/artifacts/"),
        "no sha-scoped changelog href must remain: {text}"
    );
}

// -------------- 匿名下载编排元数据（crbs download 无 token profile）--------------

/// 建带制品的 build 并返回 (task_id, build_id)；private 时先建私有产品行。
async fn insert_build_for_product(
    state: &AppState,
    tmp_dir: &std::path::Path,
    product: &str,
    visibility: &str,
) -> (i64, i64) {
    if visibility == crbs_core::VISIBILITY_PRIVATE {
        state
            .state_store
            .create_product(crbs_core::CreateProductInput {
                name: product,
                display_name: None,
                owner_id: Some(
                    state
                        .state_store
                        .create_user("owner", "builder")
                        .await
                        .unwrap(),
                ),
                parent_id: None,
                visibility: crbs_core::VISIBILITY_PRIVATE,
                config: &crbs_core::config::ProductConfig {
                    base_packages: vec!["bash".into()],
                    repos: vec![crbs_core::config::RepoConfig {
                        name: "base".into(),
                        baseurl: "http://example.com/repo".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();
    }
    let result_dir = tmp_dir.join("results").join(product).join("pkg").join("1");
    tokio::fs::create_dir_all(&result_dir).await.unwrap();
    tokio::fs::write(result_dir.join("hello.rpm"), b"dummy rpm")
        .await
        .unwrap();
    let result_dir_str = result_dir.to_string_lossy().to_string();
    let task_id = crbs_server::test_support::seed_task(&state.state_store, product, "pkg").await;
    let build_id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product,
            pkg_name: "pkg",
            phase: "succeeded",
            result_dir: Some(&result_dir_str),
            backend: "chroot",
            user: "alice",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    // 清单端点读 build_artifacts 表（非磁盘）：补一行 on_disk 制品。
    let now = chrono::Utc::now()
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string();
    let mut tx = state.state_store.pool().begin().await.unwrap();
    state
        .state_store
        .insert_artifacts_tx(
            &mut tx,
            build_id,
            &[crbs_core::NewArtifact {
                relative_path: "RPMS/x86_64/hello.rpm".into(),
                kind: crbs_core::ArtifactKind::Rpm,
                size_bytes: 9,
                sha256: "deadbeef".into(),
                unsigned_sha256: None,
                arch: Some("x86_64".into()),
                name: Some("hello".into()),
                version: Some("1.0".into()),
                release: Some("1".into()),
                epoch: None,
                metadata_json: None,
                signed: false,
            }],
            &now,
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (task_id, build_id)
}

#[tokio::test]
async fn public_download_info_anonymous_public_product_ok_and_sanitized() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let (task_id, build_id) =
        insert_build_for_product(&state, tmp.path(), "mydist", crbs_core::VISIBILITY_PUBLIC).await;
    // 挂真实归属：worker 名是内部主机名（拓扑信息），匿名面必须脱敏——
    // 无归属时 worker 恒 None，断言不设防。
    let worker_id = state
        .state_store
        .upsert_worker(
            "sanitize-node-w1",
            "x86_64",
            2,
            "0.15.0-dev",
            "online",
            None,
        )
        .await
        .unwrap();
    // 夹具落的是终态行：分配要求 pending，先翻回（直连 fixture 语义，不走
    // 状态机守卫）。
    sqlx::query("UPDATE builds SET phase = 'pending' WHERE id = $1")
        .bind(build_id)
        .execute(state.state_store.pool())
        .await
        .unwrap();
    state
        .state_store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/public/tasks/{}", task_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = std::str::from_utf8(&body).unwrap();
    assert!(body.contains("\"pkg_name\":\"pkg\""), "body: {body}");
    // 脱敏断言：服务端绝对路径与提交者字段不出现在匿名响应。
    assert!(
        !body.contains(tmp.path().to_string_lossy().as_ref()),
        "result path leaked: {body}"
    );
    assert!(!body.contains("\"user\""), "user field leaked: {body}");
    assert!(
        !body.contains("sanitize-node-w1") && !body.contains("\"worker\""),
        "worker attribution leaked to anonymous API: {body}"
    );
}

#[tokio::test]
async fn public_download_info_private_product_anonymous_denied() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let (task_id, _build_id) =
        insert_build_for_product(&state, tmp.path(), "secret", crbs_core::VISIBILITY_PRIVATE).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/public/tasks/{}", task_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn public_download_info_requires_auth_when_download_disabled() {
    let public_access = PublicAccessConfig {
        view: true,
        logs: true,
        download: false,
    };
    let roles: &[(&str, &str)] = &[("operator-token", "operator")];
    let (state, app, tmp, tokens) = setup_app_with_config(roles, public_access).await;
    let (task_id, _build_id) =
        insert_build_for_product(&state, tmp.path(), "mydist", crbs_core::VISIBILITY_PUBLIC).await;

    let anon = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/public/tasks/{}", task_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anon.status(), StatusCode::UNAUTHORIZED);

    let authed = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/public/tasks/{}", task_id))
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["operator-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authed.status(), StatusCode::OK);
}

#[tokio::test]
async fn public_artifacts_list_anonymous_public_product_ok() {
    let roles: &[(&str, &str)] = &[];
    let (state, app, tmp, _tokens) =
        setup_app_with_config(roles, PublicAccessConfig::default()).await;
    let (_task_id, build_id) =
        insert_build_for_product(&state, tmp.path(), "mydist", crbs_core::VISIBILITY_PUBLIC).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/public/builds/{}/artifacts", build_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = std::str::from_utf8(&body).unwrap();
    assert!(body.contains("hello.rpm"), "body: {body}");
    assert!(
        !body.contains(tmp.path().to_string_lossy().as_ref()),
        "result path leaked: {body}"
    );
}

#[tokio::test]
async fn public_artifacts_list_requires_auth_when_download_disabled() {
    let public_access = PublicAccessConfig {
        view: true,
        logs: true,
        download: false,
    };
    let roles: &[(&str, &str)] = &[];
    let (state, app, tmp, _tokens) = setup_app_with_config(roles, public_access).await;
    let (_task_id, build_id) =
        insert_build_for_product(&state, tmp.path(), "mydist", crbs_core::VISIBILITY_PUBLIC).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/public/builds/{}/artifacts", build_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
