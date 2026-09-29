// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! UI 会话（`crbs_session` cookie）集成测试，钉住：session cookie 认证 UI
//! 页面与 GET 下载；API Bearer `crbs_sess_…` 恒 401；双 cookie 并存只认
//! session，撤销后回落 `crbs_token`（请求级优先链，非会话模式降级）。

// 测试 crate：seed_* 等辅助函数不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::auth::secret::{Secret, SecretHash, SecretKind};
use crbs_core::config::{PublicAccessConfig, ServerConfig};
use crbs_core::StateStore;
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::state::AppState;

/// 建带认证中间件的测试 App（session 下载测试须传 download=false，否则下载端点匿名可达、断言无区分度）。
async fn setup_app(
    server_config: ServerConfig,
) -> (Arc<AppState>, axum::Router, tempfile::TempDir) {
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        state_store,
        server_config,
        tmp_dir.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    (app_state, app, tmp_dir)
}

/// 建用户 + 会话行，返回 (user_id, 明文 session Secret)。
async fn seed_session(store: &StateStore, name: &str, role: &str) -> (i64, Secret) {
    let user_id = store.create_user(name, role).await.unwrap();
    let secret = Secret::generate(SecretKind::Session).unwrap();
    let expires = (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339();
    store
        .create_session(
            user_id,
            secret.hash().as_str(),
            &expires,
            Some("integration"),
        )
        .await
        .unwrap();
    (user_id, secret)
}

/// 建用户 + token 行，返回 (user_id, 明文 token Secret)。
async fn seed_token(store: &StateStore, name: &str, role: &str) -> (i64, Secret) {
    let user_id = store.create_user(name, role).await.unwrap();
    let secret = Secret::generate(SecretKind::UserToken).unwrap();
    store
        .create_user_token(
            user_id,
            Some("integration"),
            SecretHash::from_plain(secret.as_str()).as_str(),
            None,
        )
        .await
        .unwrap();
    (user_id, secret)
}

/// session cookie 认证 UI 页面：dashboard 200 且 nav 显示会话用户名。
#[tokio::test]
async fn session_cookie_accesses_ui_dashboard_with_identity() {
    let (app_state, app, _tmp) = setup_app(ServerConfig::default()).await;
    let (_uid, secret) = seed_session(&app_state.state_store, "alice", "builder").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/")
                .header("Cookie", format!("crbs_session={}", secret.as_str()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("nav-user") && html.contains("alice"),
        "authenticated dashboard must show session user name"
    );
}

/// API Bearer 永不接受 crbs_sess_：GET 与写方法都 401，即使 DB 中确有对应会话行。
#[tokio::test]
async fn bearer_session_value_rejected_on_api() {
    let (app_state, app, _tmp) = setup_app(ServerConfig::default()).await;
    let (_uid, secret) = seed_session(&app_state.state_store, "alice", "builder").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/tasks")
                .header("Authorization", format!("Bearer {}", secret.as_str()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/tasks")
                .header("Authorization", format!("Bearer {}", secret.as_str()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// GET 下载端点接受 session cookie；写 API 带 session cookie 依旧 401——cookie 非
/// API 写凭据（CSRF 面）；浏览器内下载可用，`is_api_write` 不变式不破。
#[tokio::test]
async fn session_cookie_allows_get_download_but_not_api_write() {
    let server_config = ServerConfig {
        public_access: PublicAccessConfig {
            view: true,
            logs: true,
            download: false,
        },
        ..ServerConfig::default()
    };
    let (app_state, app, tmp) = setup_app(server_config).await;

    let user = "alice";
    let result_dir = tmp.path().join("results").join(user).join("pkg").join("1");
    tokio::fs::create_dir_all(&result_dir).await.unwrap();
    tokio::fs::write(result_dir.join("hello.rpm"), b"dummy rpm")
        .await
        .unwrap();
    let result_dir_str = result_dir.to_string_lossy().to_string();
    let build_id = app_state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg",
            phase: "succeeded",
            result_dir: Some(&result_dir_str),
            backend: "chroot",
            user,
            task_id: Some(
                crbs_server::test_support::seed_task(&app_state.state_store, "fedora", "pkg").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let (_uid, secret) = seed_session(&app_state.state_store, user, "builder").await;
    let cookie = format!("crbs_session={}", secret.as_str());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/builds/{build_id}/artifacts/download?file=hello.rpm"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/builds/{build_id}/artifacts/download?file=hello.rpm"
                ))
                .header("Cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let downloaded = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(downloaded.as_ref(), b"dummy rpm");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/tasks")
                .header("Cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a2_session_priority_and_token_fallback_after_revoke() {
    let (app_state, app, _tmp) = setup_app(ServerConfig::default()).await;
    let (alice_id, session_secret) = seed_session(&app_state.state_store, "alice", "builder").await;
    let (_bob_id, token_secret) = seed_token(&app_state.state_store, "bob", "builder").await;
    let _ = alice_id;

    let both = format!(
        "crbs_session={}; crbs_token={}",
        session_secret.as_str(),
        token_secret.as_str()
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/")
                .header("Cookie", &both)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains(r#"<a class="nav-user" href="/ui/me" title="alice">alice</a>"#),
        "A2: valid session must win over token"
    );
    assert!(
        !html.contains(r#"href="/ui/me" title="bob""#),
        "bob must not appear as session user"
    );

    let session_row = app_state
        .state_store
        .find_session_by_hash(session_secret.hash().as_str())
        .await
        .unwrap()
        .unwrap();
    app_state
        .state_store
        .revoke_session(session_row.id)
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/")
                .header("Cookie", &both)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("bob"),
        "invalid session falls back to token cookie"
    );
}
