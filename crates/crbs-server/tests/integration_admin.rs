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

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::ServerConfig;
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;

async fn setup_app_with_auth(
    roles: &[(&str, &str)],
) -> (
    Arc<AppState>,
    axum::Router,
    tempfile::TempDir,
    std::collections::HashMap<String, String>,
) {
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    let server_config = ServerConfig::default();
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

#[tokio::test]
async fn admin_can_create_user() {
    let (_state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    let body = serde_json::json!({
        "name": "alice",
        "role": "builder",
    })
    .to_string();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["name"], "alice");
    assert_eq!(json["role"], "builder");
}

#[tokio::test]
async fn admin_create_user_rejects_invalid_slug() {
    let (_state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    for bad_name in ["Alice", "alice smith", "alice/bob", "alice.bob"] {
        let body = serde_json::json!({
            "name": bad_name,
            "role": "builder",
        })
        .to_string();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/users")
                    .header("Content-Type", "application/json")
                    .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "user name '{}' should be rejected as invalid slug",
            bad_name
        );
    }
}

#[tokio::test]
async fn non_admin_cannot_create_user() {
    let (_state, app, _tmp, tokens) = setup_app_with_auth(&[("builder-token", "builder")]).await;

    let body = serde_json::json!({
        "name": "bob",
        "role": "builder",
    })
    .to_string();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("Content-Type", "application/json")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_can_manage_user_lifecycle() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    // 创建
    let body = serde_json::json!({
        "name": "carol",
        "role": "builder",
    })
    .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    // 先钉死状态码再 parse body，失败时不至于在 unwrap 处丢失语义。
    assert_eq!(response.status(), StatusCode::CREATED);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let user: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let id = user["id"].as_i64().unwrap();

    // 列表
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let list: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert!(list.iter().any(|u| u["name"] == "carol"));

    // 查询
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/admin/users/{}", id))
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 更新角色
    let body = serde_json::json!({ "role": "operator" }).to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/admin/users/{}", id))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let user: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(user["role"], "operator");

    // 禁用
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/users/{}", id))
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let user = state.state_store.get_user(id).await.unwrap().unwrap();
    assert_eq!(user.status, "disabled");
}

/// DELETE /admin/users/{id} 对缺失用户回 404 而非 204
/// （set_user_status 对缺失行是 no-op UPDATE，无存在性信号，404 靠 handler 预检）。
#[tokio::test]
async fn disable_missing_user_returns_not_found() {
    let (_state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/admin/users/999999")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// admin rebuild-repo 对不存在产品回 404（error=="not_found" 信封、不写审计行）。
/// 无预检时的失败形态：assemble 对双空集静默 200 空 arches 报告，regen 侧
/// NotFound 哨兵经 log_and_internal_with_context 折叠成 500。
#[tokio::test]
async fn rebuild_repo_missing_product_returns_not_found() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/products/no-such-product/rebuild-repo")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "not_found", "envelope error code: {json}");

    let logs = state
        .state_store
        .list_audit_logs(crbs_core::AuditLogFilter {
            action: Some("rebuild_repo"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        logs.is_empty(),
        "rejected rebuild must not write an audit row, got: {logs:?}"
    );
}

/// 最后活跃管理员守卫：对唯一活跃 admin 的降级（PUT role）与禁用
/// （DELETE）返回 409 + error=="conflict" 且状态未变；双 admin 场景回归
/// 200 / 204。
#[tokio::test]
async fn last_active_admin_guard_returns_conflict() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;
    let sole = state
        .state_store
        .find_user_by_name("admin-token")
        .await
        .unwrap()
        .unwrap()
        .id;

    // PUT 降级
    let body = serde_json::json!({ "role": "viewer" }).to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/admin/users/{sole}"))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(err["error"], "conflict");
    assert!(
        err["message"]
            .as_str()
            .is_some_and(|m| m.contains("last active admin")),
        "got: {err}"
    );
    assert_eq!(
        state
            .state_store
            .get_user(sole)
            .await
            .unwrap()
            .unwrap()
            .role,
        "admin"
    );

    // DELETE 禁用
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/users/{sole}"))
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        state
            .state_store
            .get_user(sole)
            .await
            .unwrap()
            .unwrap()
            .status,
        "active"
    );
}

/// 双活跃 admin 回归：另一活跃 admin 存在时降级/禁用放行（200/204），
/// 提升方向也放行。
#[tokio::test]
async fn demote_disable_allowed_with_second_active_admin() {
    let (state, app, _tmp, tokens) =
        setup_app_with_auth(&[("admin-a", "admin"), ("admin-b", "admin")]).await;
    let a = state
        .state_store
        .find_user_by_name("admin-a")
        .await
        .unwrap()
        .unwrap()
        .id;

    // 降级其一
    let body = serde_json::json!({ "role": "viewer" }).to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/admin/users/{a}"))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", tokens["admin-a"]))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 提升回来（升级方向恒放行）；admin-a 已是 viewer，须用仍是活跃
    // admin 的 admin-b token。
    let body = serde_json::json!({ "role": "admin" }).to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/admin/users/{a}"))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", tokens["admin-b"]))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 禁用其一
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/users/{a}"))
                .header("Authorization", format!("Bearer {}", tokens["admin-b"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn admin_can_manage_token_lifecycle() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    let user_id = state
        .state_store
        .create_user("dave", "builder")
        .await
        .unwrap();

    let body = serde_json::json!({
        "name": "laptop",
        "expires_in_days": 30,
    })
    .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{}/tokens", user_id))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let token: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let token_id = token["id"].as_i64().unwrap();
    let plain = token["token"].as_str().unwrap();
    assert!(plain.starts_with("crbs_tok_"));

    // 列表
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/admin/users/{}/tokens", user_id))
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let list: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert!(list.iter().any(|t| t["id"] == token_id));

    // 撤销
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/admin/users/{}/tokens/{}",
                    user_id, token_id
                ))
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let tokens = state.state_store.list_user_tokens(user_id).await.unwrap();
    let t = tokens.into_iter().find(|t| t.id == token_id).unwrap();
    assert!(t.revoked_at.is_some());
}

async fn create_test_product(state: &Arc<AppState>, name: &str) {
    state
        .state_store
        .create_product(crbs_core::CreateProductInput {
            name,
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
}

#[tokio::test]
async fn admin_can_manage_product_acl() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    let user_id = state
        .state_store
        .create_user("eve", "builder")
        .await
        .unwrap();

    // 先创建产品
    create_test_product(&state, "foo").await;

    // 授予
    let body = serde_json::json!({ "user_id": user_id }).to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/products/foo/acl")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // 列表
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/products/foo/acl")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let list: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert!(list
        .iter()
        .any(|u| u["id"] == user_id && u["name"] == "eve"));

    // 撤销
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/products/foo/acl/{}", user_id))
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let acls = state
        .state_store
        .list_products_by_user(user_id)
        .await
        .unwrap();
    assert!(acls.is_empty());
}

#[tokio::test]
async fn invalid_role_is_rejected() {
    let (_state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    let body = serde_json::json!({
        "name": "frank",
        "role": "hacker",
    })
    .to_string();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_can_query_audit_logs() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    state
        .state_store
        .audit_log("admin", "admin", "user.create", Some("alice"), None)
        .await
        .unwrap();
    state
        .state_store
        .audit_log(
            "operator",
            "operator",
            "build.submit",
            Some("foo:bar"),
            None,
        )
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/audit-logs?action=user.create")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let logs = json["logs"].as_array().unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0]["action"], "user.create");
    assert_eq!(json["total"].as_i64().unwrap(), 1);
    // 分页回显实际生效值：不带 limit/offset 请求时回显 state 层
    // 默认（limit 100 / offset 0），与 SQL 实际应用值一致（超范围 limit 在
    // 入口 400 拒绝而非钳制，见 validate_list_pagination）。
    assert_eq!(json["limit"].as_i64().unwrap(), 100);
    assert_eq!(json["offset"].as_i64().unwrap(), 0);
}

#[tokio::test]
async fn non_admin_cannot_query_audit_logs() {
    let (_state, app, _tmp, tokens) = setup_app_with_auth(&[("builder-token", "builder")]).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/audit-logs")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn duplicate_user_name_returns_conflict() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    state
        .state_store
        .create_user("alice", "builder")
        .await
        .unwrap();

    let body = serde_json::json!({ "name": "alice", "role": "builder" }).to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn revoke_token_rejects_cross_user_mismatch() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    // 创建两个用户，user_b 签发一个 token
    let user_a = state
        .state_store
        .create_user("alice", "builder")
        .await
        .unwrap();
    let user_b = state
        .state_store
        .create_user("bob", "builder")
        .await
        .unwrap();
    let token_b = state
        .state_store
        .create_user_token(user_b, None, "hash_b", None)
        .await
        .unwrap();

    // 用 user_a 的路径撤销 user_b 的 token
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/users/{}/tokens/{}", user_a, token_b))
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "cross-user revoke should return 404"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "not_found");
    let msg = json["message"].as_str().unwrap();
    assert!(
        msg.contains("token") && msg.contains(&token_b.to_string()),
        "message should name the resource and id: {msg}"
    );

    let tokens_b = state.state_store.list_user_tokens(user_b).await.unwrap();
    let t = tokens_b.into_iter().find(|t| t.id == token_b).unwrap();
    assert!(t.revoked_at.is_none(), "token should not be revoked");
}

#[tokio::test]
async fn create_user_writes_audit_log() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    let body = serde_json::json!({ "name": "audited_user", "role": "builder" }).to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let logs = state
        .state_store
        .list_audit_logs(crbs_core::AuditLogFilter {
            action: Some("create_user"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        logs.iter()
            .any(|l| l.action == "create_user" && l.user == "admin-token"),
        "create_user should be audited with actor=admin-token, got: {:?}",
        logs
    );
}

#[tokio::test]
async fn grant_product_acl_writes_audit_log() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    let user_id = state
        .state_store
        .create_user("carol", "builder")
        .await
        .unwrap();

    // 先创建产品
    create_test_product(&state, "mydist").await;

    let body = serde_json::json!({ "user_id": user_id }).to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/products/mydist/acl")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let logs = state
        .state_store
        .list_audit_logs(crbs_core::AuditLogFilter {
            action: Some("grant_product_acl"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        logs.iter()
            .any(|l| l.action == "grant_product_acl" && l.user == "admin-token"),
        "grant_product_acl should be audited, got: {:?}",
        logs
    );
}

#[tokio::test]
async fn revoke_token_writes_audit_log() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    let user_id = state
        .state_store
        .create_user("dave", "builder")
        .await
        .unwrap();
    let token_id = state
        .state_store
        .create_user_token(user_id, None, "hash_d", None)
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/admin/users/{}/tokens/{}",
                    user_id, token_id
                ))
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let logs = state
        .state_store
        .list_audit_logs(crbs_core::AuditLogFilter {
            action: Some("revoke_user_token"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        logs.iter().any(|l| l.action == "revoke_user_token"),
        "revoke_user_token should be audited, got: {:?}",
        logs
    );
}
