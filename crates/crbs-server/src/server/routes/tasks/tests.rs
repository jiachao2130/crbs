// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use crbs_core::config::ServerConfig;
use crbs_core::{BuildInsert, NvrGroupFilter, StateStore, TaskInsert};
use tower::ServiceExt;

use super::list::list_name_groups_for_user;
use crate::server::auth::AuthContext;
use crate::server::create_test_app_with_auth;
use crate::server::seed_user_token_for_test;
use crate::server::state::AppState;

struct TestTokens {
    admin: String,
    operator: String,
    builder: String,
    other: String,
}

async fn seed_tokens(store: &StateStore) -> TestTokens {
    TestTokens {
        admin: seed_user_token_for_test(store, "admin", "admin")
            .await
            .unwrap(),
        operator: seed_user_token_for_test(store, "operator", "operator")
            .await
            .unwrap(),
        builder: seed_user_token_for_test(store, "builder", "builder")
            .await
            .unwrap(),
        other: seed_user_token_for_test(store, "other", "builder")
            .await
            .unwrap(),
    }
}

#[tokio::test]
async fn get_task_returns_task_and_child_builds() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let tok = seed_tokens(&store).await;
    let app = create_test_app_with_auth(app_state);

    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            user: "builder",
            user_id: None,
            phase: "building",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();

    store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "foo",
            phase: "building",

            result_dir: Some("/var/lib/crbs/results/fedora/foo/20260918/build-1"),
            backend: "chroot",
            user: "builder",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "foo",
            backend: "chroot",
            user: "builder",
            arch: Some("aarch64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/tasks/{}", task_id))
                .header("Authorization", format!("Bearer {}", tok.builder))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8_lossy(&bytes).into_owned();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["id"], task_id);
    assert_eq!(json["phase"], "building");
    assert_eq!(json["builds"].as_array().unwrap().len(), 2);

    for build in json["builds"].as_array().unwrap() {
        assert!(
            build.get("result_dir").is_some(),
            "result_dir key must be kept (null), got: {build}"
        );
        assert!(build["result_dir"].is_null());
    }
    assert!(
        !body.contains("/var/lib/crbs/results"),
        "server-side absolute path must not appear in the response body: {body}"
    );
}

#[tokio::test]
async fn get_task_allows_other_builder_on_orphan_product() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let tok = seed_tokens(&store).await;
    let app = create_test_app_with_auth(app_state);

    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            user: "builder",
            user_id: None,
            phase: "pending",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/tasks/{}", task_id))
                .header("Authorization", format!("Bearer {}", tok.other))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "builder must read other users' tasks on visible products"
    );
}

#[tokio::test]
async fn get_task_denies_builder_on_private_product_without_acl() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let tok = seed_tokens(&store).await;
    let app = create_test_app_with_auth(app_state);

    let owner_id = store.create_user("secret-owner", "builder").await.unwrap();
    store
        .create_product(crbs_core::CreateProductInput {
            name: "secret-product",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: "private",
            config: &crbs_core::config::ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("task visibility test"),
        })
        .await
        .unwrap();

    let task_id = store
        .insert_task(TaskInsert {
            product: "secret-product",
            pkg_name: "foo",
            user: "secret-owner",
            user_id: None,
            phase: "pending",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/tasks/{}", task_id))
                .header("Authorization", format!("Bearer {}", tok.other))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_tasks_respects_user_isolation() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let tok = seed_tokens(&store).await;
    let app = create_test_app_with_auth(app_state);

    let task_a = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            user: "builder",
            user_id: None,
            phase: "pending",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();
    let task_b = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "bar",
            user: "other",
            user_id: None,
            phase: "pending",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/tasks")
                .header("Authorization", format!("Bearer {}", tok.builder))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["total"], 2);
    let ids: Vec<i64> = json["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_i64().unwrap())
        .collect();
    assert!(ids.contains(&task_a));
    assert!(ids.contains(&task_b));

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/tasks")
                .header("Authorization", format!("Bearer {}", tok.admin))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["total"], 2);
    let ids: Vec<i64> = json["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_i64().unwrap())
        .collect();
    assert!(ids.contains(&task_a));
    assert!(ids.contains(&task_b));
}

#[tokio::test]
async fn cancel_task_marks_pending_children_cancelled() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let tok = seed_tokens(&store).await;
    let app = create_test_app_with_auth(app_state);

    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            user: "builder",
            user_id: None,
            phase: "pending",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();

    let build_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "foo",
            backend: "chroot",
            user: "builder",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/tasks/{}/cancel", task_id))
                .header("Authorization", format!("Bearer {}", tok.builder))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["task_id"], task_id);
    assert_eq!(json["cancelled_build_ids"], serde_json::json!([build_id]));

    let task = store.get_task(task_id).await.unwrap().unwrap();
    assert_eq!(task.phase, "cancelled");
    let build = store.get_build(build_id).await.unwrap().unwrap();
    assert_eq!(build.phase, "cancelled");
}

#[tokio::test]
async fn cancel_task_denies_other_builder() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let tok = seed_tokens(&store).await;
    let app = create_test_app_with_auth(app_state);

    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            user: "builder",
            user_id: None,
            phase: "pending",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/tasks/{}/cancel", task_id))
                .header("Authorization", format!("Bearer {}", tok.other))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cancel_terminal_task_returns_conflict() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let tok = seed_tokens(&store).await;
    let app = create_test_app_with_auth(app_state);

    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            user: "builder",
            user_id: None,
            phase: "succeeded",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/tasks/{}/cancel", task_id))
                .header("Authorization", format!("Bearer {}", tok.builder))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn cancel_task_returns_409_when_fanout_races_empty_children_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let tok = seed_tokens(&store).await;
    let app = create_test_app_with_auth(app_state);

    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            user: "builder",
            user_id: None,
            phase: "pending",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();

    let store2 = StateStore::new(tmp.path()).await.unwrap();
    let mut guard_conn = store2.pool().acquire().await.unwrap();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *guard_conn)
        .await
        .unwrap();

    let token = tok.builder.clone();
    let handle = tokio::spawn(async move {
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/tasks/{}/cancel", task_id))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    sqlx::query(
        "INSERT INTO builds (product, pkg_name, phase, task_id) \
         VALUES ('fedora','foo','pending',$1)",
    )
    .bind(task_id)
    .execute(&mut *guard_conn)
    .await
    .unwrap();
    sqlx::query("COMMIT")
        .execute(&mut *guard_conn)
        .await
        .unwrap();
    drop(guard_conn);

    let response = handle.await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        json.to_string().contains("retry"),
        "conflict body must point at retry: {json}"
    );

    assert_eq!(
        store.get_task(task_id).await.unwrap().unwrap().phase,
        "pending"
    );
}

#[tokio::test]
async fn cancel_task_finalize_error_returns_500_and_task_stays_pending() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let tok = seed_tokens(&store).await;
    let app = create_test_app_with_auth(app_state);

    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            user: "builder",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();

    sqlx::query(
        "CREATE TRIGGER fail_cancel_task BEFORE UPDATE ON tasks \
         WHEN NEW.phase = 'cancelled' \
         BEGIN SELECT RAISE(ABORT, 'forced cancel failure'); END",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/tasks/{}/cancel", task_id))
                .header("Authorization", format!("Bearer {}", tok.builder))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "finalize failure must surface as 500, not a silent 202"
    );

    sqlx::query("DROP TRIGGER fail_cancel_task")
        .execute(store.pool())
        .await
        .unwrap();

    assert_eq!(
        store.get_task(task_id).await.unwrap().unwrap().phase,
        "pending"
    );
}

#[tokio::test]
async fn cancel_task_with_failed_and_building_children_aggregates_failed() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let tok = seed_tokens(&store).await;
    let app = create_test_app_with_auth(app_state);

    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            user: "builder",
            phase: "building",
            ..Default::default()
        })
        .await
        .unwrap();

    let failed_build = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "foo",
            phase: "failed",
            backend: "chroot",
            user: "builder",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    let building_build = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "foo",
            phase: "building",
            backend: "chroot",
            user: "builder",
            arch: Some("aarch64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/tasks/{}/cancel", task_id))
                .header("Authorization", format!("Bearer {}", tok.builder))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json["cancelled_build_ids"],
        serde_json::json!([building_build]),
        "only the active child is cancelled"
    );
    assert_eq!(
        json["skipped_build_ids"],
        serde_json::json!([failed_build]),
        "already-terminal child is skipped"
    );

    let build = store.get_build(building_build).await.unwrap().unwrap();
    assert_eq!(build.phase, "cancelled");

    let task = store.get_task(task_id).await.unwrap().unwrap();
    assert_eq!(task.phase, "failed");
    assert!(
        task.completed_at.is_some(),
        "cancel must record completed_at"
    );
    assert!(task.duration.is_some());
}

#[tokio::test]
async fn get_task_checks_product_visibility() {
    use crate::server::auth::visibility::ensure_product_visible_for_record;

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let tok = seed_tokens(&store).await;
    let app = create_test_app_with_auth(app_state.clone());

    let owner_id = store.create_user("owner", "builder").await.unwrap();
    let _ = store
        .create_product(crbs_core::CreateProductInput {
            name: "secret",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: crbs_core::VISIBILITY_PRIVATE,
            config: &crbs_core::config::ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();
    let secret_task = store
        .insert_task(TaskInsert {
            product: "secret",
            pkg_name: "foo",
            user: "other",
            phase: "succeeded",
            ..Default::default()
        })
        .await
        .unwrap();

    let orphan_task = store
        .insert_task(TaskInsert {
            product: "deleted-product",
            pkg_name: "bar",
            user: "other",
            phase: "succeeded",
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/tasks/{}", secret_task))
                .header("Authorization", format!("Bearer {}", tok.other))
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
                .method("GET")
                .uri(format!("/api/v1/tasks/{}", orphan_task))
                .header("Authorization", format!("Bearer {}", tok.other))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/tasks/{}", secret_task))
                .header("Authorization", format!("Bearer {}", tok.admin))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    assert!(
        ensure_product_visible_for_record(&app_state, "deleted-product", None)
            .await
            .is_ok()
    );
    assert!(
        ensure_product_visible_for_record(&app_state, "secret", None)
            .await
            .is_err()
    );
}

async fn seed_rebuildable_task(
    store: &StateStore,
    tmp: &tempfile::TempDir,
    user: &str,
) -> (i64, std::path::PathBuf) {
    seed_rebuildable_task_with_opts(store, tmp, user, &crbs_core::BuildOptions::default()).await
}

async fn seed_rebuildable_task_with_opts(
    store: &StateStore,
    tmp: &tempfile::TempDir,
    user: &str,
    opts: &crbs_core::BuildOptions,
) -> (i64, std::path::PathBuf) {
    let opts_json = serde_json::to_string(opts).unwrap();
    let pkg_names = serde_json::to_string(&["foo-1.0-1", "bar-2.0-1"]).unwrap();
    let task_dir = tmp.path().join("results").join("1");

    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo-1.0-1",
            user,
            phase: "failed",
            result_dir: Some(task_dir.to_str().unwrap()),
            request_json: Some(&opts_json),
            pkg_names: Some(&pkg_names),
            ..Default::default()
        })
        .await
        .unwrap();

    let source = task_dir.join("source");
    tokio::fs::create_dir_all(&source).await.unwrap();
    tokio::fs::write(source.join("foo-1.0-1.src.rpm"), b"fake-srpm")
        .await
        .unwrap();
    tokio::fs::write(source.join("bar-2.0-1.src.rpm"), b"fake-srpm")
        .await
        .unwrap();

    let build_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "foo-1.0-1",
            phase: "failed",
            backend: "nspawn",
            user,
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .set_build_request_info(build_id, "/src/foo-1.0-1.src.rpm", &opts_json)
        .await
        .unwrap();

    (task_id, task_dir)
}

async fn post_rebuild(
    app: axum::Router,
    task_id: i64,
    token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/tasks/{}/rebuild", task_id));
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {}", t));
    }
    let response = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
    (status, json)
}

fn rebuild_app(store: &Arc<StateStore>, tmp: &tempfile::TempDir) -> axum::Router {
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    create_test_app_with_auth(app_state)
}

#[tokio::test]
async fn rebuild_task_creates_new_task_with_recorded_options() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let tok = seed_tokens(&store).await;
    let app = rebuild_app(&store, &tmp);
    let (task_id, _dir) = seed_rebuildable_task(&store, &tmp, "builder").await;

    let (status, json) = post_rebuild(app, task_id, Some(&tok.builder)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "body: {}", json);

    let new_task_id = json["task_id"].as_i64().unwrap();
    assert_ne!(new_task_id, task_id);

    assert_eq!(json["ids"].as_array().unwrap().len(), 2);
    assert_eq!(json["product"], "fedora");

    let new_task = store.get_task(new_task_id).await.unwrap().unwrap();
    assert_eq!(new_task.user, "builder");
    assert_eq!(new_task.pkg_names, vec!["foo-1.0-1", "bar-2.0-1"]);

    let new_source = std::path::PathBuf::from(new_task.result_dir.unwrap()).join("source");
    let mut entries = tokio::fs::read_dir(&new_source).await.unwrap();
    let mut count = 0;
    while entries.next_entry().await.unwrap().is_some() {
        count += 1;
    }
    assert_eq!(count, 2);
}

#[tokio::test]
async fn rebuild_task_inherits_req_min_from_request_json() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let tok = seed_tokens(&store).await;
    let app = rebuild_app(&store, &tmp);
    let opts: crbs_core::BuildOptions =
        serde_json::from_str(r#"{"min_mem": "4G", "min_disk": "2T", "min_ncpu": 8}"#).unwrap();
    let (task_id, _dir) = seed_rebuildable_task_with_opts(&store, &tmp, "builder", &opts).await;

    let (status, json) = post_rebuild(app, task_id, Some(&tok.builder)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "body: {}", json);

    assert_eq!(
        json["req_min_mem_kb"],
        serde_json::json!(4i64 * 1024 * 1024)
    );
    assert_eq!(json["req_min_ncpu"], serde_json::json!(8));
    assert_eq!(
        json["req_min_disk_kb"],
        serde_json::json!(2i64 * 1024 * 1024 * 1024)
    );

    for id in json["ids"].as_array().unwrap() {
        let rec = store
            .get_build(id.as_i64().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.req_min_mem_kb, Some(4 * 1024 * 1024));
        assert_eq!(rec.req_min_ncpu, Some(8));
        assert_eq!(rec.req_min_disk_kb, Some(2 * 1024 * 1024 * 1024));
    }
}

#[tokio::test]
async fn rebuild_task_denies_other_user() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let tok = seed_tokens(&store).await;
    let app = rebuild_app(&store, &tmp);
    let (task_id, _dir) = seed_rebuildable_task(&store, &tmp, "builder").await;

    let (status, _json) = post_rebuild(app, task_id, Some(&tok.other)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rebuild_task_requires_auth() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let _tok = seed_tokens(&store).await;
    let app = rebuild_app(&store, &tmp);
    let (task_id, _dir) = seed_rebuildable_task(&store, &tmp, "builder").await;

    let (status, _json) = post_rebuild(app, task_id, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rebuild_task_operator_allowed_and_owns_new_task() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let tok = seed_tokens(&store).await;
    let app = rebuild_app(&store, &tmp);
    let (task_id, _dir) = seed_rebuildable_task(&store, &tmp, "builder").await;

    let (status, json) = post_rebuild(app, task_id, Some(&tok.admin)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "body: {}", json);
    let new_task = store
        .get_task(json["task_id"].as_i64().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(new_task.user, "admin");
}

#[tokio::test]
async fn rebuild_task_missing_source_returns_conflict() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let tok = seed_tokens(&store).await;
    let app = rebuild_app(&store, &tmp);

    let opts_json = serde_json::to_string(&crbs_core::BuildOptions::default()).unwrap();
    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            user: "builder",
            phase: "succeeded",
            result_dir: Some(tmp.path().join("gone").to_str().unwrap()),
            request_json: Some(&opts_json),
            ..Default::default()
        })
        .await
        .unwrap();

    let (status, _json) = post_rebuild(app, task_id, Some(&tok.builder)).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn rebuild_task_without_recorded_options_conflicts() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let tok = seed_tokens(&store).await;
    let app = rebuild_app(&store, &tmp);

    let task_dir = tmp.path().join("results").join("1");
    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo-1.0-1",
            user: "builder",
            phase: "failed",
            result_dir: Some(task_dir.to_str().unwrap()),
            ..Default::default()
        })
        .await
        .unwrap();

    let source = task_dir.join("source");
    tokio::fs::create_dir_all(&source).await.unwrap();
    tokio::fs::write(source.join("foo-1.0-1.src.rpm"), b"fake-srpm")
        .await
        .unwrap();

    let (status, _json) = post_rebuild(app, task_id, Some(&tok.builder)).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn rebuild_task_validates_replayed_priority() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let tok = seed_tokens(&store).await;
    let app = rebuild_app(&store, &tmp);
    let (task_id, _dir) = seed_rebuildable_task(&store, &tmp, "builder").await;

    sqlx::query("UPDATE tasks SET priority = 2 WHERE id = $1")
        .bind(task_id)
        .execute(store.pool())
        .await
        .unwrap();
    let (status, _json) = post_rebuild(app.clone(), task_id, Some(&tok.builder)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, json) = post_rebuild(app.clone(), task_id, Some(&tok.admin)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "body: {}", json);

    sqlx::query("UPDATE builds SET phase = 'cancelled' WHERE phase IN ('pending', 'assigned', 'building', 'running')")
        .execute(store.pool())
        .await
        .unwrap();

    let (task_op, _dir_op) = seed_rebuildable_task(&store, &tmp, "builder").await;
    sqlx::query("UPDATE tasks SET priority = 2 WHERE id = $1")
        .bind(task_op)
        .execute(store.pool())
        .await
        .unwrap();
    let (status, json) = post_rebuild(app.clone(), task_op, Some(&tok.operator)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "body: {}", json);

    let (task2, _dir2) = seed_rebuildable_task(&store, &tmp, "builder").await;
    sqlx::query("UPDATE tasks SET priority = 5 WHERE id = $1")
        .bind(task2)
        .execute(store.pool())
        .await
        .unwrap();
    let (status, _json) = post_rebuild(app, task2, Some(&tok.admin)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rebuild_task_corrupt_request_json_returns_redacted_internal_error() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let tok = seed_tokens(&store).await;
    let app = rebuild_app(&store, &tmp);
    let (task_id, _dir) = seed_rebuildable_task(&store, &tmp, "builder").await;

    sqlx::query("UPDATE tasks SET request_json = '{corrupt' WHERE id = $1")
        .bind(task_id)
        .execute(store.pool())
        .await
        .unwrap();

    let (status, json) = post_rebuild(app, task_id, Some(&tok.builder)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {json}");
    assert_eq!(json["message"], "internal error", "body: {json}");
    assert_eq!(json["error"], "internal_error", "body: {json}");
}

#[tokio::test]
async fn cancel_task_reports_failed_builds_separately_from_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let tok = seed_tokens(&store).await;
    let app = create_test_app_with_auth(app_state);

    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            user: "builder",
            phase: "building",
            ..Default::default()
        })
        .await
        .unwrap();

    let pending_build = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "foo",
            phase: "pending",
            backend: "chroot",
            user: "builder",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    let done_build = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "foo",
            phase: "failed",
            backend: "chroot",
            user: "builder",
            arch: Some("aarch64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    sqlx::query(
        "CREATE TRIGGER fail_cancel BEFORE UPDATE ON builds \
         WHEN NEW.phase = 'cancelled' \
         BEGIN SELECT RAISE(ABORT, 'forced cancel failure'); END",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/tasks/{}/cancel", task_id))
                .header("Authorization", format!("Bearer {}", tok.builder))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json["cancelled_build_ids"],
        serde_json::json!([]),
        "failed cancel must not be reported as cancelled"
    );
    assert_eq!(
        json["skipped_build_ids"],
        serde_json::json!([done_build]),
        "only the already-terminal child is skipped"
    );
    assert_eq!(
        json["failed_build_ids"],
        serde_json::json!([pending_build]),
        "cancel failure must land in failed_build_ids, not skipped"
    );
    let message = json["message"].as_str().unwrap();
    assert!(
        message.contains("failed"),
        "message should distinguish failures: {message}"
    );
}

#[tokio::test]
async fn list_name_groups_for_user_narrows_user_and_groups_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));

    let mk = |pkg: &'static str, user: &'static str| {
        let store = &store;
        async move {
            store
                .insert_task(TaskInsert {
                    product: "fedora",
                    pkg_name: pkg,
                    user,
                    phase: "succeeded",
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };
    mk("foo-1.0-1", "builder").await;
    mk("foo-2.0-1", "builder").await;
    mk("bar-1.0-1", "other").await;

    let builder = AuthContext {
        user: "builder".to_string(),
        role: "builder".to_string(),
        ..Default::default()
    };
    let resp = list_name_groups_for_user(&app_state, NvrGroupFilter::default(), Some(&builder))
        .await
        .unwrap();
    assert_eq!(resp.total, 2);
    assert_eq!(resp.groups.len(), 2);
    let foo = resp.groups.iter().find(|g| g.pkg_name == "foo").unwrap();
    assert_eq!(foo.attempts, 2);

    let operator = AuthContext {
        user: "root".to_string(),
        role: "operator".to_string(),
        ..Default::default()
    };
    let resp = list_name_groups_for_user(&app_state, NvrGroupFilter::default(), Some(&operator))
        .await
        .unwrap();
    assert_eq!(resp.total, 2);
    assert!(resp.groups.iter().any(|g| g.pkg_name == "bar"));
}

#[tokio::test]
async fn list_tasks_filters_by_label_and_detail_returns_labels() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let tok = seed_tokens(&store).await;
    let app = create_test_app_with_auth(app_state);

    let labels = vec![
        (
            "git-repo".to_string(),
            "https://example.com/a.git".to_string(),
        ),
        ("git-commit".to_string(), "abc123".to_string()),
    ];
    let labeled_id = store
        .create_task_with_labels(
            TaskInsert {
                product: "fedora",
                pkg_name: "foo",
                user: "builder",
                phase: "pending",
                ..Default::default()
            },
            &labels,
        )
        .await
        .unwrap();
    let plain_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "bar",
            user: "builder",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/tasks?label=git-repo=https%3A%2F%2Fexample.com%2Fa.git")
                .header("Authorization", format!("Bearer {}", tok.builder))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["total"], 1, "only the labeled task must match: {json}");
    assert_eq!(json["tasks"][0]["id"], labeled_id);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/tasks?label=git-repo=https%3A%2F%2Fexample.com%2Fb.git")
                .header("Authorization", format!("Bearer {}", tok.builder))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["total"], 0);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/tasks/{labeled_id}"))
                .header("Authorization", format!("Bearer {}", tok.builder))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let returned: Vec<(String, String)> = json["labels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            (
                l["key"].as_str().unwrap().to_string(),
                l["value"].as_str().unwrap().to_string(),
            )
        })
        .collect();

    let mut expected = labels.clone();
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(returned, expected);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/tasks?label=noequals")
                .header("Authorization", format!("Bearer {}", tok.builder))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/tasks")
                .header("Authorization", format!("Bearer {}", tok.builder))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let ids: Vec<i64> = json["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_i64().unwrap())
        .collect();
    assert!(ids.contains(&labeled_id) && ids.contains(&plain_id));
}
