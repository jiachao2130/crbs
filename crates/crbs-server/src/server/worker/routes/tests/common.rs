// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! Worker API 测试共享夹具：构建、分配与日志上报辅助。

use super::*;

/// 带 auth 的 app + worker + 已分配 assignment 的公共夹具；结尾流式上报
/// 一段日志注册 LogBuffer。
pub(super) async fn setup_worker_build_with_streamed_log() -> (
    axum::Router,
    Arc<AppState>,
    String,
    i64,
    i64,
    tempfile::TempDir,
) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());

    let (worker_id, token) = seed_worker_secret_for_test(&store, "w-log-evict", "x86_64")
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

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/{worker_id}/assignments/{assignment_id}/logs"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from("hello build"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(app_state.log_buffer.has(build_id));

    (app, app_state, token, assignment_id, build_id, tmp)
}

pub(super) async fn report_terminal(app: &axum::Router, token: &str, assignment_id: i64) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/result"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"phase":"failed"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// POST 一段日志（可选幂等序号），返回状态码。
pub(super) async fn post_log_chunk(
    app: &axum::Router,
    token: &str,
    assignment_id: i64,
    seq: Option<u64>,
    body: &'static str,
) -> StatusCode {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/workers/1/assignments/{assignment_id}/logs"
        ))
        .header("Authorization", format!("Bearer {}", token));
    if let Some(seq) = seq {
        builder = builder.header("X-Crbs-Log-Seq", seq.to_string());
    }
    app.clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap()
        .status()
}

/// cancelled 收账两臂共用夹具：app + worker + pending build + assignment，
/// wt 置 running（worker 已 claim 现场），不流式日志、无注入。
pub(super) async fn setup_worker_build(
    worker_name: &str,
) -> (
    axum::Router,
    Arc<StateStore>,
    String,
    i64,
    i64,
    i64,
    tempfile::TempDir,
) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state);
    let (worker_id, token) = seed_worker_secret_for_test(&store, worker_name, "x86_64")
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
    store
        .update_worker_task_status(assignment_id, "running")
        .await
        .unwrap();
    (app, store, token, worker_id, assignment_id, build_id, tmp)
}
