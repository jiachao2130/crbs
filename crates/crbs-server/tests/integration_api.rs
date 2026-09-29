// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::ServerConfig;
use crbs_server::server::create_test_app;
use crbs_server::server::state::AppState;

/// 创建测试用的 AppState 和 Router。
/// 返回 (AppState, Router, TempDir) —— TempDir 必须保持存活到测试结束。
async fn setup_app() -> (Arc<AppState>, axum::Router, tempfile::TempDir) {
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;

    let server_config = ServerConfig::default();
    let app_state = Arc::new(AppState::for_test(
        state_store,
        server_config,
        tmp_dir.path().to_path_buf(),
    ));

    let app = create_test_app(app_state.clone());
    (app_state, app, tmp_dir)
}

#[tokio::test]
async fn test_health_endpoint() {
    let (_state, app, _tmp) = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    // 探针响应禁缓存（中间层/浏览器不得留存 liveness 快照）。
    assert_eq!(
        response.headers().get(axum::http::header::CACHE_CONTROL),
        Some(&axum::http::HeaderValue::from_static("no-store"))
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn test_version_endpoint() {
    let (_state, app, _tmp) = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    // version 随部署变化，同样禁缓存。
    assert_eq!(
        response.headers().get(axum::http::header::CACHE_CONTROL),
        Some(&axum::http::HeaderValue::from_static("no-store"))
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["version"]
        .as_str()
        .unwrap()
        .contains(env!("CARGO_PKG_VERSION")));
}

#[tokio::test]
async fn test_metrics_endpoint() {
    let (_state, app, _tmp) = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/metrics")
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
    assert!(json["uptime_seconds"].is_number());
    assert!(json["concurrency"]["max"].is_number());
    assert!(json["concurrency"]["available"].is_number());
}

#[tokio::test]
async fn test_metrics_prometheus_endpoint() {
    let (_state, app, _tmp) = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("text/plain; charset=utf-8")
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("# TYPE crbs_builds_phase gauge"));
    assert!(text.contains("crbs_builds_phase{phase=\"pending\"} 0\n"));
    assert!(text.contains("crbs_builds_total 0\n"));
    assert!(text.lines().any(|l| l.starts_with("crbs_uptime_seconds ")));
    assert!(text
        .lines()
        .any(|l| l.starts_with("crbs_disk_available_bytes ")));
}

#[tokio::test]
async fn test_builds_list_empty() {
    let (_state, app, _tmp) = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/builds")
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
    assert_eq!(json["total"], 0);
    assert!(json["builds"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_builds_get_not_found() {
    let (_state, app, _tmp) = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/builds/999999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "not_found");
    let msg = json["message"].as_str().unwrap();
    assert!(
        msg.contains("build") && msg.contains("999999"),
        "message should name the resource and id: {msg}"
    );
}

/// task 域 404 响应体 message 应含资源名与 id（与 build 域用例同口径）。
#[tokio::test]
async fn test_task_get_not_found_message_names_resource_and_id() {
    let (_state, app, _tmp) = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/tasks/999999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "not_found");
    let msg = json["message"].as_str().unwrap();
    assert!(
        msg.contains("task") && msg.contains("999999"),
        "message should name the resource and id: {msg}"
    );
}

#[tokio::test]
async fn test_artifacts_not_found() {
    let (_state, app, _tmp) = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/builds/999999/artifacts/result_dir")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // build 不存在 → 404（该路径形态无匹配路由/记录缺失均以 404 收口）
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// `POST /api/v1/tasks` 是 `POST /api/v1/builds` 的提交别名——同 handler。
/// 钉住：别名提交成功且响应形态一致（task_id + ids），提交产物
/// 经 `GET /api/v1/tasks/{id}` 可读回；`/api/v1/builds` 提交端点同请求体同响应。
#[tokio::test]
async fn test_tasks_submit_alias_matches_builds_submit() {
    let (state, app, tmp) = setup_app().await;

    // seed 产品（hub 路径以 SQLite 为权威源）。
    let product_toml = r#"
base_packages = ["bash", "rpm-build"]

[[repos]]
name = "base"
baseurl = "http://example.com/base/$basearch"
gpgcheck = false
"#;
    let config = crbs_core::config::ProductConfig::from_str(product_toml).unwrap();
    state
        .state_store
        .create_product(crbs_core::CreateProductInput {
            name: "aliasprod",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &config,
            changed_by_user_id: None,
            reason: Some("integration test setup"),
        })
        .await
        .unwrap();

    // 测试 SRPM 放在 upload_dir 下满足 enqueue 的 allowed_root 校验。
    let upload_dir = tmp.path().join("uploads");
    tokio::fs::create_dir_all(&upload_dir).await.unwrap();

    let submit = |uri: &str, srpm: std::path::PathBuf| {
        let app = app.clone();
        let uri = uri.to_string();
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header("Content-Type", "application/json")
                        .body(Body::from(
                            serde_json::json!({
                                "product": "aliasprod",
                                "srpms": [srpm.to_str().unwrap()]
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, body)
        }
    };

    // 别名端点：成功且形态与 builds 提交一致。两次提交各自独立 SRPM 文件。
    let srpm_a = common::make_minimal_srpm(&upload_dir, "alias-a", "1.0", "1");
    let (status, body) = submit("/api/v1/tasks", srpm_a).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "alias submit body: {}",
        String::from_utf8_lossy(&body)
    );
    let alias_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(alias_json["task_id"].is_i64(), "alias body: {alias_json}");
    assert!(
        alias_json["ids"].is_array(),
        "alias body should carry build ids: {alias_json}"
    );

    // `/api/v1/builds` 提交端点：同请求体同响应形态（回归钉）。
    let srpm_b = common::make_minimal_srpm(&upload_dir, "alias-b", "1.0", "1");
    let (status, body) = submit("/api/v1/builds", srpm_b).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "builds submit body: {}",
        String::from_utf8_lossy(&body)
    );
    let builds_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(builds_json["task_id"].is_i64());
    assert!(builds_json["ids"].is_array());

    // 别名提交的 task 经 tasks 详情端点可读回（提交即建 task）。
    let task_id = alias_json["task_id"].as_i64().unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/tasks/{task_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let detail: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(detail["id"].as_i64().unwrap(), task_id);
    assert!(
        detail["builds"].as_array().is_some(),
        "task detail should embed child builds: {detail}"
    );
}

/// 磁盘预检不满足时提交 400，但响应体不得回显服务端
/// 绝对路径（upload_dir / crbs_root / result_dir）与字节数细节——这些只进
/// 日志，响应固定文案。
#[tokio::test]
async fn test_submit_insufficient_disk_space_does_not_leak_server_paths() {
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    // min_free_disk_gb 恒不满足（饱和乘法后仍 > 任何真实卷余量）→ 预检必 400。
    let app_state = Arc::new(AppState::for_test(
        state_store,
        ServerConfig {
            min_free_disk_gb: usize::MAX,
            ..Default::default()
        },
        tmp_dir.path().to_path_buf(),
    ));
    let app = create_test_app(app_state.clone());

    // SRPM 放在 upload_dir 下满足 enqueue 的路径校验（文件真实存在）。
    let upload_dir = tmp_dir.path().join("uploads");
    tokio::fs::create_dir_all(&upload_dir).await.unwrap();
    let srpm_path = common::make_srpm_in_uploads(&upload_dir, "diskleak").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/builds")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "product": "diskleak",
                        "srpms": [srpm_path.to_str().unwrap()]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "validation_failed");
    let msg = json["message"].as_str().unwrap();
    assert!(
        msg.contains("insufficient disk space"),
        "fixed client-facing text expected: {msg}"
    );
    assert!(
        !msg.contains(tmp_dir.path().to_str().unwrap()),
        "response must not echo the server root, got: {msg}"
    );
    assert!(
        !msg.contains("uploads"),
        "response must not echo the upload dir, got: {msg}"
    );
    assert!(
        !msg.contains("bytes"),
        "response must not echo byte-count details, got: {msg}"
    );
}

/// build detail/list 响应脱敏：`result_dir` / `srpm_path` 是服务端文件系统
/// 绝对路径，DB 行里有值也不得回显（置 null 而非删键：响应键集稳定，null
/// 对客户端 BuildRecord 的 Option 字段即 None，缺键亦然，均不破坏解析）。
#[tokio::test]
async fn build_detail_and_list_strip_server_absolute_paths() {
    let (state, app, tmp) = setup_app().await;

    // public 产品 + 终态构建；result_dir / srpm_path 落真实值（在
    // {crbs_root}/results 下，详情的 validate_result_dir 才放行）。
    state
        .state_store
        .create_product(crbs_core::CreateProductInput {
            name: "san-prod",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &crbs_core::config::ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();

    let task_id = crbs_server::test_support::seed_task(&state.state_store, "san-prod", "pkg").await;
    let build_id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "san-prod",
            pkg_name: "pkg",
            phase: "succeeded",
            backend: "chroot",
            user: "alice",
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let result_dir = tmp.path().join("results").join("san-prod").join("task-1");
    tokio::fs::create_dir_all(result_dir.join("RPMS").join("x86_64"))
        .await
        .unwrap();
    tokio::fs::write(
        result_dir
            .join("RPMS")
            .join("x86_64")
            .join("pkg-1-1.fc42.x86_64.rpm"),
        b"rpm-bytes",
    )
    .await
    .unwrap();
    let srpm_path = result_dir.join("SRPMS").join("pkg-1-1.fc42.src.rpm");
    tokio::fs::create_dir_all(srpm_path.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(&srpm_path, b"srpm-bytes").await.unwrap();
    state
        .state_store
        .update_build_info(build_id, Some(result_dir.to_str().unwrap()), None, "chroot")
        .await
        .unwrap();
    state
        .state_store
        .set_build_request_info(build_id, srpm_path.to_str().unwrap(), "{}")
        .await
        .unwrap();

    let server_root = tmp.path().to_str().unwrap();

    // detail：两字段 null，且整个响应体不出现服务器根路径。
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/builds/{build_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(
        json["result_dir"].is_null(),
        "detail must null result_dir: {text}"
    );
    assert!(
        json["srpm_path"].is_null(),
        "detail must null srpm_path: {text}"
    );
    assert!(
        !text.contains(server_root),
        "detail response must not echo server absolute paths: {text}"
    );
    // 服务端仍按 result_dir 扫描产物：rpms 列表是相对文件名（非路径）。
    assert!(
        json["rpms"].as_array().is_some_and(|r| r.len() == 1),
        "rpm file names must still be listed as relative names: {text}"
    );
    assert!(!text.contains("RPMS/x86_64"));

    // list：内嵌 BuildRecord 同口径。
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/builds")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let entry = json["builds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["id"].as_i64() == Some(build_id))
        .unwrap_or_else(|| panic!("seeded build missing from list: {text}"));
    assert!(
        entry["result_dir"].is_null(),
        "list entry must null result_dir: {text}"
    );
    assert!(
        entry["srpm_path"].is_null(),
        "list entry must null srpm_path: {text}"
    );
    assert!(
        !text.contains(server_root),
        "list response must not echo server absolute paths: {text}"
    );
}
