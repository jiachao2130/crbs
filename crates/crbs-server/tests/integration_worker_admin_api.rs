// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Worker secret 管理 / 删除 API 集成测试：`POST /api/v1/workers/{id}/secret/rotate`、
//! `/secret/revoke`、`/remove`（operator/admin）：RBAC、DB 效果（hash 轮换 / has_secret /
//! 行删除）与审计行；三操作走 server::worker::admin 共享核心，与 UI 表单路径同源。

// 文件级放行：测试辅助函数（seed_* 等）不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use crbs_core::auth::secret::{Secret, SecretHash, SecretKind, PREFIX_WORKER_SECRET};
use crbs_core::{AuditLog, AuditLogFilter};
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;
use tower::ServiceExt;

mod common;

use common::setup_app;

/// POST 空请求体，返回 (status, json)；成功与错误响应体均为 JSON。
async fn post(app: &axum::Router, uri: &str, token: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json = serde_json::from_slice(&bytes).expect("response body is JSON");
    (status, json)
}

async fn audit_rows(state: &AppState, action: &str) -> Vec<AuditLog> {
    state
        .state_store
        .list_audit_logs(AuditLogFilter {
            action: Some(action),
            ..Default::default()
        })
        .await
        .expect("list audit logs")
}

/// operator 全流程：rotate（明文一次性返回 + 审计）→ revoke（has_secret=false + 审计）
/// → remove（离线前置 + 行删除 + 审计）。
#[tokio::test]
async fn operator_can_rotate_revoke_and_remove_worker() {
    let (state, app, _tmp) = setup_app().await;
    let op_token = seed_user_token_for_test(&state.state_store, "op-flow", "operator")
        .await
        .expect("seed operator token");
    let worker_id = state
        .state_store
        .upsert_worker("flow-worker", "x86_64", 1, "test", "online", None)
        .await
        .expect("upsert worker");
    let old_secret = Secret::generate(SecretKind::WorkerSecret).expect("generate old secret");
    state
        .state_store
        .set_worker_secret(worker_id, old_secret.hash().as_str())
        .await
        .expect("seed old secret");

    let (status, body) = post(
        &app,
        &format!("/api/v1/workers/{worker_id}/secret/rotate"),
        &op_token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "rotated");
    assert_eq!(body["worker_id"].as_i64(), Some(worker_id));
    let new_secret = body["secret"]
        .as_str()
        .expect("secret in response")
        .to_string();
    assert!(
        new_secret.starts_with(PREFIX_WORKER_SECRET),
        "rotate should return a worker secret, got: {new_secret}"
    );

    let found = state
        .state_store
        .find_worker_by_secret(SecretHash::from_plain(&new_secret).as_str())
        .await
        .expect("find by new secret")
        .expect("new secret hash should authenticate");
    assert_eq!(found.id, worker_id);
    assert!(
        state
            .state_store
            .find_worker_by_secret(old_secret.hash().as_str())
            .await
            .expect("find by old secret")
            .is_none(),
        "old secret must stop authenticating after rotate"
    );

    let logs = audit_rows(&state, "rotate_worker_secret").await;
    assert_eq!(logs.len(), 1, "exactly one rotate audit row");
    assert_eq!(logs[0].user, "op-flow");
    assert_eq!(
        logs[0].target.as_deref(),
        Some(worker_id.to_string().as_str())
    );

    let (status, body) = post(
        &app,
        &format!("/api/v1/workers/{worker_id}/secret/revoke"),
        &op_token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "revoked");
    assert_eq!(body["worker_id"].as_i64(), Some(worker_id));

    let worker = state
        .state_store
        .get_worker(worker_id)
        .await
        .expect("get worker")
        .expect("worker still exists after revoke");
    assert!(!worker.has_secret, "has_secret must be false after revoke");
    assert!(
        state
            .state_store
            .find_worker_by_secret(SecretHash::from_plain(&new_secret).as_str())
            .await
            .expect("find by revoked secret")
            .is_none(),
        "revoked secret must not authenticate"
    );
    let logs = audit_rows(&state, "revoke_worker_secret").await;
    assert_eq!(logs.len(), 1, "exactly one revoke audit row");
    assert_eq!(
        logs[0].target.as_deref(),
        Some(worker_id.to_string().as_str())
    );

    state
        .state_store
        .worker_mark_offline(worker_id)
        .await
        .expect("mark worker offline");
    let (status, body) = post(
        &app,
        &format!("/api/v1/workers/{worker_id}/remove"),
        &op_token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "removed");
    assert_eq!(body["worker_id"].as_i64(), Some(worker_id));
    assert_eq!(body["name"], "flow-worker");
    assert!(
        state
            .state_store
            .get_worker(worker_id)
            .await
            .expect("get worker")
            .is_none(),
        "worker row must be gone after remove"
    );
    let logs = audit_rows(&state, "delete_worker").await;
    assert_eq!(logs.len(), 1, "exactly one delete audit row");
    assert_eq!(
        logs[0].target.as_deref(),
        Some(worker_id.to_string().as_str())
    );
}

/// admin 是 operator 超集，同样可操作。
#[tokio::test]
async fn admin_can_rotate_worker_secret() {
    let (state, app, _tmp) = setup_app().await;
    let admin_token = seed_user_token_for_test(&state.state_store, "root-admin", "admin")
        .await
        .expect("seed admin token");
    let worker_id = state
        .state_store
        .upsert_worker("admin-rotated", "aarch64", 1, "test", "online", None)
        .await
        .expect("upsert worker");

    let (status, body) = post(
        &app,
        &format!("/api/v1/workers/{worker_id}/secret/rotate"),
        &admin_token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["secret"]
            .as_str()
            .is_some_and(|s| s.starts_with(PREFIX_WORKER_SECRET)),
        "admin rotate should return a worker secret: {body}"
    );
    assert!(
        state
            .state_store
            .get_worker(worker_id)
            .await
            .expect("get worker")
            .expect("worker exists")
            .has_secret
    );
}

/// builder / viewer 对三个端点均 403。
#[tokio::test]
async fn builder_and_viewer_are_forbidden() {
    let (state, app, _tmp) = setup_app().await;
    let builder = seed_user_token_for_test(&state.state_store, "b-forbidden", "builder")
        .await
        .expect("seed builder token");
    let viewer = seed_user_token_for_test(&state.state_store, "v-forbidden", "viewer")
        .await
        .expect("seed viewer token");
    let worker_id = state
        .state_store
        .upsert_worker("rbac-worker", "x86_64", 1, "test", "online", None)
        .await
        .expect("upsert worker");

    for token in [&builder, &viewer] {
        for sub in ["secret/rotate", "secret/revoke", "remove"] {
            let (status, body) =
                post(&app, &format!("/api/v1/workers/{worker_id}/{sub}"), token).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{sub} should be 403: {body}");
            assert_eq!(body["error"], "permission_denied");
        }
    }
}

/// 在线 worker remove → 409，冲突消息与 UI 路径（共享核心）一致。
#[tokio::test]
async fn remove_online_worker_returns_conflict() {
    let (state, app, _tmp) = setup_app().await;
    let op_token = seed_user_token_for_test(&state.state_store, "op-conflict", "operator")
        .await
        .expect("seed operator token");
    let worker_id = state
        .state_store
        .upsert_worker("busy-worker", "x86_64", 1, "test", "online", None)
        .await
        .expect("upsert worker");

    let (status, body) = post(
        &app,
        &format!("/api/v1/workers/{worker_id}/remove"),
        &op_token,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let msg = body["message"].as_str().expect("conflict message");
    assert!(
        msg.contains("is online") && msg.contains("busy-worker"),
        "conflict message should name the online worker: {msg}"
    );
    assert!(audit_rows(&state, "delete_worker").await.is_empty());
}

#[tokio::test]
async fn rotate_missing_worker_returns_not_found() {
    let (state, app, _tmp) = setup_app().await;
    let op_token = seed_user_token_for_test(&state.state_store, "op-404", "operator")
        .await
        .expect("seed operator token");

    let (status, body) = post(&app, "/api/v1/workers/999999/secret/rotate", &op_token).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "not_found");
    let msg = body["message"].as_str().unwrap();
    assert!(
        msg.contains("worker") && msg.contains("999999"),
        "message should name the resource and id: {msg}"
    );
}

/// API 写方法的 CSRF 收敛：cookie-only → 401（跨站表单能带 cookie 但带不了
/// Authorization 头）；同一 token 走 Authorization 头 → 正常执行。
#[tokio::test]
async fn api_write_rejects_cookie_only_and_accepts_header() {
    let (state, app, _tmp) = setup_app().await;
    let op_token = seed_user_token_for_test(&state.state_store, "op-cookie", "operator")
        .await
        .expect("seed operator token");
    let worker_id = state
        .state_store
        .upsert_worker("cookie-worker", "x86_64", 1, "test", "online", None)
        .await
        .expect("upsert worker");
    state
        .state_store
        .worker_mark_offline(worker_id)
        .await
        .expect("mark worker offline");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/workers/{worker_id}/remove"))
                .header("Cookie", format!("crbs_token={op_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8_lossy(&bytes).into_owned();
    assert!(
        body.contains("Authorization header"),
        "error should explain the Authorization header requirement: {body}"
    );
    assert!(
        state
            .state_store
            .get_worker(worker_id)
            .await
            .expect("get worker")
            .is_some(),
        "cookie-only write must not remove the worker"
    );

    let (status, body) = post(
        &app,
        &format!("/api/v1/workers/{worker_id}/remove"),
        &op_token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "removed");
}
