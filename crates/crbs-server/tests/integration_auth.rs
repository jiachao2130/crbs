// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

// 文件级放行 unwrap/expect：seed_* 等测试辅助函数不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到。
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::auth::secret::{Secret, SecretHash, SecretKind};
use crbs_core::config::ServerConfig;
use crbs_core::StateStore;
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;

/// 创建带认证中间件的测试 App（仅校验 DB 用户 token / worker secret）。
async fn setup_app_with_auth() -> (Arc<AppState>, axum::Router, tempfile::TempDir) {
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;

    let server_config = ServerConfig::default();
    let app_state = Arc::new(AppState::for_test(
        state_store,
        server_config,
        tmp_dir.path().to_path_buf(),
    ));

    let app = create_test_app_with_auth(app_state.clone());
    (app_state, app, tmp_dir)
}

async fn seed_user_token(store: &StateStore, role: &str, products: &[&str]) -> Secret {
    let user_id = store.create_user("alice", role).await.unwrap();
    for product in products {
        // 先建产品再授权 ACL；测试产品需含最少 base_packages，避免 resolve_arches 报错
        let cfg = crbs_core::config::ProductConfig {
            base_packages: vec!["bash".to_string()],
            repos: vec![crbs_core::config::RepoConfig {
                name: "base".to_string(),
                baseurl: "http://example.com/repo".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        store
            .create_product(crbs_core::CreateProductInput {
                name: product,
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: "public",
                config: &cfg,
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();
        // 默认 ACL role 是 viewer，这里显式 grant builder 权限以便测试提交
        store
            .grant_product_acl_with_role(user_id, product, "builder")
            .await
            .unwrap();
    }
    let secret = Secret::generate(SecretKind::UserToken).unwrap();
    store
        .create_user_token(
            user_id,
            Some("test"),
            SecretHash::from_plain(secret.as_str()).as_str(),
            None,
        )
        .await
        .unwrap();
    secret
}

#[tokio::test]
async fn test_db_user_token_submit_allowed() {
    let (app_state, app, _tmp) = setup_app_with_auth().await;
    let secret = seed_user_token(&app_state.state_store, "builder", &["fedora"]).await;

    let upload_dir = app_state.upload_dir();
    tokio::fs::create_dir_all(&upload_dir).await.unwrap();
    let srpm_path = common::make_srpm_in_uploads(&upload_dir, "test").await;

    let body = serde_json::json!({
        "product": "fedora",
        "srpms": [srpm_path.to_str().unwrap()],
    })
    .to_string();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/builds")
                .method("POST")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", secret.as_str()))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

/// ACL 不收窄提交范围：builder 持 centos 的 ACL，仍可提交无 ACL 的 public
/// 产品 fedora（产品级放行由提交链 check_build_chain_visibility 承担）。
#[tokio::test]
async fn test_db_user_token_submit_public_product_outside_acl_allowed() {
    let (app_state, app, _tmp) = setup_app_with_auth().await;
    let secret = seed_user_token(&app_state.state_store, "builder", &["centos"]).await;

    let upload_dir = app_state.upload_dir();
    tokio::fs::create_dir_all(&upload_dir).await.unwrap();
    let srpm_path = common::make_srpm_in_uploads(&upload_dir, "test").await;

    let body = serde_json::json!({
        "product": "fedora",
        "srpms": [srpm_path.to_str().unwrap()],
    })
    .to_string();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/builds")
                .method("POST")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", secret.as_str()))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::ACCEPTED,
        "public products must stay submittable regardless of ACL records"
    );
}

/// private 产品无 ACL 的提交被链可见性拒绝（404 掩码，不泄漏存在性）。
#[tokio::test]
async fn test_db_user_token_private_product_without_acl_rejected() {
    let (app_state, app, _tmp) = setup_app_with_auth().await;
    let secret = seed_user_token(&app_state.state_store, "builder", &["centos"]).await;

    let owner_id = app_state
        .state_store
        .create_user("secret-owner", "builder")
        .await
        .unwrap();
    app_state
        .state_store
        .create_product(crbs_core::CreateProductInput {
            name: "secret-product",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: "private",
            config: &crbs_core::config::ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("acl submit test"),
        })
        .await
        .unwrap();

    let upload_dir = app_state.upload_dir();
    tokio::fs::create_dir_all(&upload_dir).await.unwrap();
    let srpm_path = common::make_srpm_in_uploads(&upload_dir, "test").await;

    let body = serde_json::json!({
        "product": "secret-product",
        "srpms": [srpm_path.to_str().unwrap()],
    })
    .to_string();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/builds")
                .method("POST")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", secret.as_str()))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "private product without ACL must stay hidden behind the 404 mask"
    );
}

#[tokio::test]
async fn test_no_prefix_token_rejected() {
    let (_app_state, app, _tmp) = setup_app_with_auth().await;

    // 无 `crbs_tok_` / `crbs_wkr_` 前缀的 token 一律拒绝。
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/builds")
                .method("GET")
                .header("Authorization", "Bearer deadbeef12345678")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

fn extract_nav_logout_csrf(html: &str) -> String {
    let anchor = html.find(r#"class="nav-logout""#).expect("nav-logout form");
    let tail = &html[anchor..];
    let marker = r#"name="csrf_token" value=""#;
    let start = tail.find(marker).expect("csrf_token hidden input");
    let value_start = &tail[start + marker.len()..];
    let end = value_start
        .find('"')
        .expect("csrf_token value terminated by quote");
    value_start[..end].to_string()
}

#[tokio::test]
async fn ui_logout_with_csrf_token_from_page_succeeds() {
    let (app_state, app, _tmp) = setup_app_with_auth().await;
    let secret = seed_user_token_for_test(&app_state.state_store, "logout-ok", "builder")
        .await
        .expect("seed token");
    let cookie = format!("crbs_token={secret}");

    let page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/builds")
                .header("Cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(page.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes).into_owned();
    assert!(
        html.contains(r#"action="/ui/logout""#),
        "logout form missing"
    );
    let csrf = extract_nav_logout_csrf(&html);
    assert!(!csrf.is_empty(), "csrf token must be embedded in nav form");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/logout")
                .method("POST")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", &cookie)
                .body(Body::from(format!("csrf_token={csrf}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let all_cookies: Vec<&str> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    for name in ["crbs_token=;", "crbs_session=;"] {
        assert!(
            all_cookies
                .iter()
                .any(|c| c.starts_with(name) && c.contains("Max-Age=0")),
            "{name} must be cleared: {all_cookies:?}"
        );
    }
}

#[tokio::test]
async fn ui_logout_without_csrf_token_rejected_and_session_survives() {
    let (app_state, app, _tmp) = setup_app_with_auth().await;
    let secret = seed_user_token_for_test(&app_state.state_store, "logout-ng", "builder")
        .await
        .expect("seed token");
    let cookie = format!("crbs_token={secret}");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/logout")
                .method("POST")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/builds")
                .header("Cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
