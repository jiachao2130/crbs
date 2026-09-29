// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Worker API 测试：Worker 注册与凭据管理。

use super::*;

#[tokio::test]
async fn register_recovers_offline_worker_but_not_admin_status() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let (worker_id, token) = seed_worker_secret_for_test(&store, "w-recover", "x86_64")
        .await
        .unwrap();

    let register = || {
        let app = app.clone();
        let token = token.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/workers/register")
                    .header("Authorization", format!("Bearer {}", token))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"name":"w-recover","arch":"x86_64","capacity":1}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };

    sqlx::query("UPDATE workers SET status = 'offline' WHERE id = $1")
        .bind(worker_id)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(register().await.status(), StatusCode::OK);
    let w = store.get_worker(worker_id).await.unwrap().unwrap();
    assert_eq!(w.status, "online");

    sqlx::query("UPDATE workers SET status = 'suspended' WHERE id = $1")
        .bind(worker_id)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(register().await.status(), StatusCode::OK);
    let w = store.get_worker(worker_id).await.unwrap().unwrap();
    assert_eq!(w.status, "suspended");
}

#[tokio::test]
async fn register_reclaims_running_assignment_but_heartbeat_does_not() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let (worker_id, token) = seed_worker_secret_for_test(&store, "w-reclaim", "x86_64")
        .await
        .unwrap();

    let build_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(crate::test_support::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();
    let (assignment_id, _) = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    sqlx::query("UPDATE worker_tasks SET status = 'running' WHERE id = $1")
        .bind(assignment_id)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
        .bind(build_id)
        .execute(store.pool())
        .await
        .unwrap();

    let hb = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/workers/{worker_id}/heartbeat"))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"status":"online"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(hb.status(), StatusCode::OK);
    let wt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks WHERE id = $1")
        .bind(assignment_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(wt, 1, "heartbeat must not reclaim running assignment");
    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "building");

    let reg = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/workers/register")
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"name":"w-reclaim","arch":"x86_64","capacity":1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reg.status(), StatusCode::OK);
    let wt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks WHERE id = $1")
        .bind(assignment_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(wt, 0, "register must reclaim the running assignment");
    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "pending", "reclaimed build must return to pending");
}

#[tokio::test]
async fn register_response_reports_has_active_local_builds() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let (_worker_id, token) = seed_worker_secret_for_test(&store, "w-guard", "x86_64")
        .await
        .unwrap();

    let register = || {
        let app = app.clone();
        let token = token.clone();
        async move {
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/workers/register")
                        .header("Authorization", format!("Bearer {}", token))
                        .header("Content-Type", "application/json")
                        .body(Body::from(
                            r#"{"name":"w-guard","arch":"x86_64","capacity":1}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        }
    };

    let body = register().await;
    assert_eq!(
        body["has_active_local_builds"],
        serde_json::Value::Bool(false),
        "empty hub must report no active builds, got: {body}"
    );

    store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            phase: "building",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(crate::test_support::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();
    let body = register().await;
    assert_eq!(
        body["has_active_local_builds"],
        serde_json::Value::Bool(true),
        "building row must report active builds, got: {body}"
    );
}
