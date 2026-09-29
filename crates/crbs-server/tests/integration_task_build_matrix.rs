// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2/
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! task/build 行为矩阵集成测试：task＝提交 / build＝执行 的资源语义在
//! API 与 UI 两面的钉桩。本文件覆盖 12 格中的其余格（CLI 格在 crates/crbs
//! crate 内）：API status/logs/list、UI cancel（双范围）、UI status（下钻）、UI logs（渲染）；
//! API cancel/submit 别名两格见 integration_rbac / integration_api。

// 测试辅助函数不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::ServerConfig;
use crbs_core::{BuildInsert, TaskInsert};
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;

mod common;

async fn setup() -> (Arc<AppState>, axum::Router, String, tempfile::TempDir) {
    let _ = common::TEST_CONFIG_DIR.path();
    crbs_server::test_support::init_test_logging();
    let (state_store, tmp) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        state_store,
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let admin = seed_user_token_for_test(&app_state.state_store, "matrix-admin", "admin")
        .await
        .expect("seed admin token");
    let app = crbs_server::server::create_test_app_with_auth(app_state.clone());
    (app_state, app, admin, tmp)
}

async fn get_page(app: &axum::Router, token: &str, path: &str) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("Cookie", format!("crbs_token={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn get_json(app: &axum::Router, token: &str, path: &str) -> (StatusCode, serde_json::Value) {
    let (status, body) = get_page(app, token, path).await;
    (
        status,
        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
    )
}

/// POST 表单（urlencoded + token cookie），返回 (status, Location)。
async fn post_form(
    app: &axum::Router,
    token: &str,
    path: &str,
    csrf: &str,
) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", format!("crbs_token={token}"))
                .body(Body::from(format!("csrf_token={csrf}")))
                .unwrap(),
        )
        .await
        .unwrap();
    let location = response
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    (response.status(), location)
}

async fn insert_task(state: &AppState, pkg_name: &str, phase: &str) -> i64 {
    state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name,
            user: "ui-tester",
            phase,
            ..Default::default()
        })
        .await
        .unwrap()
}

async fn insert_build(
    state: &AppState,
    task_id: i64,
    arch: &str,
    phase: &str,
    result_dir: Option<String>,
) -> i64 {
    state
        .state_store
        .insert_build(BuildInsert {
            product: "mydist",
            pkg_name: "hello-1.0-1.fc42",
            phase,
            result_dir: result_dir.as_deref(),
            backend: "chroot",
            user: "ui-tester",
            priority: crbs_core::types::PRIORITY_DEFAULT,
            arch: Some(arch),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap()
}

async fn build_phase(state: &AppState, build_id: i64) -> String {
    state
        .state_store
        .get_build(build_id)
        .await
        .unwrap()
        .unwrap()
        .phase
}

async fn task_phase(state: &AppState, task_id: i64) -> String {
    state
        .state_store
        .get_task(task_id)
        .await
        .unwrap()
        .unwrap()
        .phase
}

/// UI cancel 格：/ui/tasks/{id} 表单级联取消整任务；/ui/builds/{id} 表单只
/// 取消单个构建（同任务兄弟构建与任务相位不动）——双表单各按自身范围。
#[tokio::test]
async fn ui_cancel_task_cascades_while_build_cancel_is_single_scope() {
    let (state, app, admin, _tmp) = setup().await;

    let task_a = insert_task(&state, "cascade-me-1.0-1.fc42", "building").await;
    let a1 = insert_build(&state, task_a, "x86_64", "pending", None).await;
    let a2 = insert_build(&state, task_a, "aarch64", "pending", None).await;

    // 呈现钉：任务页 cancel 表单 POST 到 /ui/tasks/{id}，文案为级联语义。
    let (status, html) = get_page(&app, &admin, &format!("/ui/tasks/{task_a}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(&format!(r#"action="/ui/tasks/{task_a}""#)),
        "task page cancel form must post to /ui/tasks/{{id}}: {html}"
    );
    assert!(
        html.contains("All its child builds will be cancelled."),
        "task cancel copy must state cascade semantics: {html}"
    );
    let csrf = common::extract_csrf_token(&html).expect("csrf token in task cancel form");

    let (status, location) = post_form(&app, &admin, &format!("/ui/tasks/{task_a}"), &csrf).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "cancel redirect");
    assert_eq!(location, format!("/ui/tasks/{task_a}?status=cancelled"));
    assert_eq!(build_phase(&state, a1).await, "cancelled");
    assert_eq!(build_phase(&state, a2).await, "cancelled");
    assert_eq!(
        task_phase(&state, task_a).await,
        "cancelled",
        "task phase must aggregate after cascading cancel"
    );

    let task_b = insert_task(&state, "single-scope-1.0-1.fc42", "building").await;
    let b1 = insert_build(&state, task_b, "x86_64", "pending", None).await;
    let b2 = insert_build(&state, task_b, "aarch64", "pending", None).await;

    // 呈现钉：表单 POST 到 /ui/builds/{id}，文案标明单构建范围（管理面定位）。
    let (status, html) = get_page(&app, &admin, &format!("/ui/builds/{b1}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(&format!(r#"action="/ui/builds/{b1}""#)),
        "build page cancel form must post to /ui/builds/{{id}}: {html}"
    );
    assert!(
        html.contains("Only this build is stopped and marked as cancelled"),
        "build cancel copy must state single-build scope: {html}"
    );
    let csrf = common::extract_csrf_token(&html).expect("csrf token in build cancel form");

    let (status, location) = post_form(&app, &admin, &format!("/ui/builds/{b1}"), &csrf).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "cancel redirect");
    assert_eq!(location, format!("/ui/builds/{b1}?status=cancelled"));
    assert_eq!(build_phase(&state, b1).await, "cancelled");
    assert_eq!(
        build_phase(&state, b2).await,
        "pending",
        "sibling build must keep running"
    );
    assert_eq!(
        task_phase(&state, task_b).await,
        "building",
        "task must stay non-terminal while a sibling build is still active"
    );
}

/// UI status/logs：任务详情页 arch 矩阵下钻到子构建页；构建页有日志入口；日志页渲染终态日志内容。
#[tokio::test]
async fn ui_task_detail_drills_down_to_child_build_and_logs() {
    let (state, app, admin, tmp) = setup().await;

    let result_dir = tmp.path().join("results").join("1").join("x86_64");
    tokio::fs::create_dir_all(&result_dir).await.unwrap();
    tokio::fs::write(result_dir.join("build.log"), "matrix-log-line-1\n")
        .await
        .unwrap();

    let task = insert_task(&state, "drilldown-1.0-1.fc42", "succeeded").await;
    let build = insert_build(
        &state,
        task,
        "x86_64",
        "succeeded",
        Some(result_dir.display().to_string()),
    )
    .await;

    let (status, html) = get_page(&app, &admin, &format!("/ui/tasks/{task}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(&format!(r#"href="/ui/builds/{build}?back="#)),
        "task detail must link down to child build pages: {html}"
    );

    let (status, html) = get_page(&app, &admin, &format!("/ui/builds/{build}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(&format!("/ui/builds/{build}/logs")),
        "build page must link to its logs page: {html}"
    );

    let (status, html) = get_page(&app, &admin, &format!("/ui/builds/{build}/logs")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("matrix-log-line-1"),
        "logs page must render terminal log content: {html}"
    );
}

/// API logs 格：日志归属 build 不改——GET /api/v1/builds/{id}/logs 仍按
/// build id 供日志（offset=0 拉全量）。
#[tokio::test]
async fn api_logs_stay_build_scoped() {
    let (state, app, admin, tmp) = setup().await;

    let result_dir = tmp.path().join("results").join("2").join("x86_64");
    tokio::fs::create_dir_all(&result_dir).await.unwrap();
    tokio::fs::write(
        result_dir.join("build.log"),
        "api-log-line-1\napi-log-line-2\n",
    )
    .await
    .unwrap();

    let task = insert_task(&state, "api-logs-1.0-1.fc42", "succeeded").await;
    let build = insert_build(
        &state,
        task,
        "x86_64",
        "succeeded",
        Some(result_dir.display().to_string()),
    )
    .await;

    let (status, body) = get_page(
        &app,
        &admin,
        &format!("/api/v1/builds/{build}/logs?offset=0"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("api-log-line-1"), "log body: {body}");
    assert!(body.contains("api-log-line-2"), "log body: {body}");
}

/// API status/list：tasks 域（列表 + 详情含子构建）与 builds 域（列表 + 单条执行详情）并存，各按自身 id 空间服务。
#[tokio::test]
async fn api_status_and_list_serve_both_domains() {
    let (state, app, admin, _tmp) = setup().await;

    let task = insert_task(&state, "domains-1.0-1.fc42", "building").await;
    let build = insert_build(&state, task, "x86_64", "pending", None).await;

    let (status, json) = get_json(&app, &admin, "/api/v1/tasks").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        json["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["id"].as_i64() == Some(task)),
        "tasks list must contain the task: {json}"
    );
    let (status, json) = get_json(&app, &admin, &format!("/api/v1/tasks/{task}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["id"].as_i64().unwrap(), task);
    assert_eq!(
        json["builds"][0]["id"].as_i64().unwrap(),
        build,
        "task detail must embed child builds: {json}"
    );

    // builds 域：同数字走 build id 空间；单条与列表行均为完整 BuildRecord（含 id / task_id）。
    let (status, json) = get_json(&app, &admin, &format!("/api/v1/builds/{build}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["id"].as_i64().unwrap(), build);
    assert_eq!(json["task_id"].as_i64().unwrap(), task);
    let (status, json) = get_json(&app, &admin, "/api/v1/builds").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        json["builds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["id"].as_i64() == Some(build)),
        "builds list must contain the build: {json}"
    );
}
