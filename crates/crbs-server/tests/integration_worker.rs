// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Worker 端到端集成测试。
//!
//! 用 `create_test_app_with_auth` 构造带认证的 Hub Router，模拟 Worker 注册、心跳、
//! 拉取任务、下载 SRPM、上报结果、上传产物、查看产物列表的完整链路。

// 整个文件是测试 crate：测试辅助函数（seed_* 等）不带 #[test] 属性，
// clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use crbs_core::auth::secret::{Secret, SecretKind};
use crbs_core::config::ServerConfig;
use crbs_core::BuildInsert;
use crbs_core::StateStore;
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn build_multipart_body(
    boundary: &str,
    manifest: &str,
    file_name: &str,
    content: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"manifest\"\r\n");
    body.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
    body.extend_from_slice(manifest.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n",
            file_name
        )
        .as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(content);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    body
}

/// 注册 Worker 并为其设置 secret，返回 (worker_id, secret_token)。
/// 注册接口对非 worker 角色要求 operator/admin token（worker token 仅可
/// 注册自身绑定名称）；后续接口必须使用本 Worker 的 secret。
async fn worker_register(
    app: &axum::Router,
    app_state: &Arc<AppState>,
    name: &str,
    arch: &str,
    op_token: &str,
) -> (i64, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/workers/register")
                .header("Authorization", format!("Bearer {}", op_token))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "name": name,
                        "arch": arch,
                        "capacity": 2,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let worker_id = json["id"].as_i64().unwrap();

    let secret = Secret::generate(SecretKind::WorkerSecret).unwrap();
    // 通过内部 StateStore 写入 secret_hash（测试直接操作 DB，不走 HTTP）
    app_state
        .state_store
        .set_worker_secret(worker_id, secret.hash().as_str())
        .await
        .unwrap();

    (worker_id, secret.as_str().to_string())
}

async fn worker_heartbeat(app: &axum::Router, worker_id: i64, token: &str) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/workers/{}/heartbeat", worker_id))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"status":"online"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// 心跳并返回原始响应体文本（取消下行通知断言用）。
async fn worker_heartbeat_body(app: &axum::Router, worker_id: i64, token: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/workers/{}/heartbeat", worker_id))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"status":"online"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn poll_task(app: &axum::Router, worker_id: i64, token: &str) -> Option<serde_json::Value> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/workers/{}/assignments?wait=1", worker_id))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    match response.status() {
        StatusCode::NO_CONTENT => return None,
        StatusCode::OK => {}
        other => panic!("unexpected poll status: {}", other),
    }

    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    if json["assignment_id"].is_null() {
        None
    } else {
        Some(json)
    }
}

/// Seed 一条 official 产品到 DB，让 fail-closed dispatch 能命中 chain_resolve。
/// dispatch 对 DB 中不存在的产品走 NotInDb → fail_assignment 拒绝下发，
/// 只写磁盘或不写配置都拿不到任务，需显式 seed 一条最小配置到 products 表。
async fn seed_test_product(store: &StateStore, name: &str) {
    let toml_body = "\
base_packages = [\"bash\", \"rpm-build\"]\n\
arches = [\"x86_64\"]\n\
\n\
[[repos]]\n\
name = \"base\"\n\
baseurl = \"http://example.com/base/$basearch\"\n\
gpgcheck = false\n";
    let config = crbs_core::config::ProductConfig::from_str(toml_body)
        .unwrap_or_else(|e| panic!("test product toml for '{}' failed to parse: {}", name, e));
    store
        .create_product(crbs_core::CreateProductInput {
            name,
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &config,
            changed_by_user_id: None,
            reason: Some("integration test setup"),
        })
        .await
        .unwrap_or_else(|e| panic!("seed test product '{}' into DB: {}", name, e));
}

async fn report_result(
    app: &axum::Router,
    worker_id: i64,
    assignment_id: i64,
    phase: &str,
    token: &str,
) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/{}/assignments/{}/result",
                    worker_id, assignment_id
                ))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::json!({"phase": phase}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// 终态幂等回归：succeeded 上报成功后 assignment 已终态，重复 report_result
/// 必须 409（worker 重试层据此识别"已达终态"），且 DB phase 保持 succeeded
/// 不被后续上报覆盖。
#[tokio::test]
async fn worker_report_result_after_terminal_returns_409_and_keeps_phase() {
    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let op_token = seed_user_token_for_test(&app_state.state_store, "test-operator", "operator")
        .await
        .unwrap();

    let (worker_id, token) =
        worker_register(&app, &app_state, "worker-01", "x86_64", &op_token).await;
    seed_test_product(&store, "fedora").await;

    let build_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(crbs_server::test_support::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();
    let (assignment_id, _task_id) = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    // 首次上报成功（helper 内断言 200）。
    report_result(&app, worker_id, assignment_id, "succeeded", &token).await;

    // 终态后重复上报 → 409，DB phase 保持 succeeded。
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/{}/assignments/{}/result",
                    worker_id, assignment_id
                ))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({"phase": "failed"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let record = store
        .get_build(build_id)
        .await
        .expect("query build")
        .expect("build row exists");
    assert_eq!(record.phase, "succeeded");
}

/// 失败原因落库：worker 上报 failed + error 文本 → builds.error_summary
/// 持久化（store 层截断，此处验证正常长度原文透传）。
#[tokio::test]
async fn worker_report_result_failed_persists_error_summary() {
    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let op_token = seed_user_token_for_test(&app_state.state_store, "test-operator", "operator")
        .await
        .unwrap();

    let (worker_id, token) =
        worker_register(&app, &app_state, "worker-err", "x86_64", &op_token).await;
    seed_test_product(&store, "fedora").await;

    let build_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(crbs_server::test_support::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();
    let (assignment_id, _task_id) = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/{}/assignments/{}/result",
                    worker_id, assignment_id
                ))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "phase": "failed",
                        "error": "exit_code=1 phase=build subphase=rpmbuild reason=mock build failure",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let record = store
        .get_build(build_id)
        .await
        .expect("query build")
        .expect("build row exists");
    assert_eq!(record.phase, "failed");
    assert_eq!(
        record.error_summary.as_deref(),
        Some("exit_code=1 phase=build subphase=rpmbuild reason=mock build failure")
    );
}

#[tokio::test]
async fn worker_endpoints_rejected_when_auth_disabled() {
    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        store,
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));

    // 未启用认证（无 auth 中间件）Worker 端点仍拒绝：handler 自查凭据，
    // 防本地 daemon 模式被任意调用。
    let app = crbs_server::server::create_test_app(app_state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/workers/register")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"name":"w","arch":"x86_64","capacity":1}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    // 匿名（无凭据）请求 → 401；403 保留给"已认证但角色不足"。
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn worker_lifecycle_register_heartbeat_and_forbidden_without_token() {
    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        store,
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let op_token = seed_user_token_for_test(&app_state.state_store, "test-operator", "operator")
        .await
        .unwrap();

    // 无认证访问 register 被认证中间件拒绝，返回 401
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/workers/register")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"name":"w","arch":"x86_64","capacity":1}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // worker 角色只能注册与自身绑定的名称，注册其它名称应被拒绝
    let (_tw_id, tw_secret) =
        worker_register(&app, &app_state, "test-worker", "x86_64", &op_token).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/workers/register")
                .header("Authorization", format!("Bearer {}", tw_secret))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"name":"w","arch":"x86_64","capacity":1}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // operator token 可代为注册 worker
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/workers/register")
                .header("Authorization", format!("Bearer {}", op_token))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"name":"admin-registered","arch":"x86_64","capacity":1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 正常注册 + 心跳（必须使用 Worker 自己的 secret）
    let (worker_id, token) =
        worker_register(&app, &app_state, "worker-01", "x86_64", &op_token).await;
    worker_heartbeat(&app, worker_id, &token).await;

    // 使用其他 Worker 的 secret 访问本 Worker 心跳应被拒绝
    let (_other_worker_id, other_token) =
        worker_register(&app, &app_state, "worker-02", "x86_64", &op_token).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/workers/{}/heartbeat", worker_id))
                .header("Authorization", format!("Bearer {}", other_token))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"status":"online"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// 心跳遥测落库：带 load1/ncpu/cpu_util_pct/mem_used_pct 的心跳写列；随后旧式
/// payload（仅 status）的心跳把各列覆写回 NULL（诚实降级）。
#[tokio::test]
async fn worker_heartbeat_persists_load_telemetry() {
    use sqlx::Row;

    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        store,
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let op_token = seed_user_token_for_test(&app_state.state_store, "test-operator", "operator")
        .await
        .unwrap();

    let (worker_id, token) =
        worker_register(&app, &app_state, "worker-telemetry", "x86_64", &op_token).await;

    // 心跳携带遥测（active_tasks 是 worker 真实心跳键，hub 对未知键默认忽略）
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/workers/{}/heartbeat", worker_id))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"status":"online","active_tasks":1,"load1":0.52,"ncpu":8,"cpu_util_pct":66.5,"mem_used_pct":37.5}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let row =
        sqlx::query("SELECT load1, ncpu, cpu_util_pct, mem_used_pct FROM workers WHERE id = $1")
            .bind(worker_id)
            .fetch_one(app_state.state_store.pool())
            .await
            .unwrap();
    assert_eq!(row.get::<Option<f64>, _>("load1"), Some(0.52));
    assert_eq!(row.get::<Option<i64>, _>("ncpu"), Some(8));
    assert_eq!(row.get::<Option<f64>, _>("cpu_util_pct"), Some(66.5));
    assert_eq!(row.get::<Option<f64>, _>("mem_used_pct"), Some(37.5));

    // 稀疏心跳（仅 status）：遥测列覆写为 NULL
    worker_heartbeat(&app, worker_id, &token).await;
    let row =
        sqlx::query("SELECT load1, ncpu, cpu_util_pct, mem_used_pct FROM workers WHERE id = $1")
            .bind(worker_id)
            .fetch_one(app_state.state_store.pool())
            .await
            .unwrap();
    assert_eq!(row.get::<Option<f64>, _>("load1"), None);
    assert_eq!(row.get::<Option<i64>, _>("ncpu"), None);
    assert_eq!(row.get::<Option<f64>, _>("cpu_util_pct"), None);
    assert_eq!(row.get::<Option<f64>, _>("mem_used_pct"), None);
}

#[tokio::test]
async fn worker_end_to_end_dispatch_download_upload_and_list() {
    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let op_token = seed_user_token_for_test(&app_state.state_store, "test-operator", "operator")
        .await
        .unwrap();

    // 1. 注册 Worker
    let (worker_id, token) =
        worker_register(&app, &app_state, "worker-01", "x86_64", &op_token).await;

    // 1b. Seed 产品到 DB —— fail-closed dispatch 要求产品必须在 DB 中，
    // 否则 read_product_config 会走 NotInDb → fail_assignment 分支，任务永不下发。
    seed_test_product(&store, "fedora").await;

    // 2. 创建一个 pending 构建，指定与 Worker 相同的架构
    let build_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(crbs_server::test_support::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();

    // 3. 准备 SRPM 文件和请求信息
    let srpm_content = b"fake srpm content";
    let result_dir = tmp.path().join("results");
    tokio::fs::create_dir_all(&result_dir).await.unwrap();
    let srpm_path = result_dir.join("test.src.rpm");
    tokio::fs::write(&srpm_path, srpm_content).await.unwrap();
    store
        .set_build_request_info(build_id, srpm_path.to_str().unwrap(), r#"{"priority":0}"#)
        .await
        .unwrap();

    // 4. 手动把任务分配给 Worker（调度器未启动，直接模拟调度结果）
    let (assignment_id, _task_id) = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    // 5. Worker 长轮询拿到任务
    let task = poll_task(&app, worker_id, &token)
        .await
        .expect("should receive task");
    assert_eq!(task["assignment_id"].as_i64(), Some(assignment_id));
    assert_eq!(task["build_id"].as_i64(), Some(build_id));
    // 正常领取（首查 CAS 路径）不带重投递标记。
    assert!(
        task.get("redelivered").is_none(),
        "claim response must not carry the redelivery marker: {task}"
    );
    let srpm_url = task["srpm_url"].as_str().unwrap();

    // 6. Worker 用签名时效 token 下载 SRPM（同时携带 Bearer 以通过 auth 中间件）
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("{}{}", srpm_url, "&download=1"))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let downloaded = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(downloaded.as_ref(), srpm_content.as_slice());

    // 7. Worker 上传产物（生产时序：executor 先上传、poller 后上报终态——
    //    upload 期间 build 仍非终态；hub 侧终态守卫据此拒收迟到上传）。
    let artifact_content = b"fake rpm content";
    let manifest = serde_json::json!({ "hello.rpm": sha256_hex(artifact_content) }).to_string();
    let boundary = "----integration-test";
    let body = build_multipart_body(boundary, &manifest, "hello.rpm", artifact_content);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let upload_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(upload_json["uploaded"], serde_json::json!(["hello.rpm"]));

    // 8. Worker 上报构建成功
    report_result(&app, worker_id, assignment_id, "succeeded", &token).await;

    // 8b. （回归）：构建成功回报后，worker_task 必须迁出 running 以释放调度容量。
    //     否则已完成的构建会永久占用 worker 槽位，导致后续任务死锁 pending。
    let active = store.count_worker_active_tasks(worker_id).await.unwrap();
    assert_eq!(
        active, 0,
        "worker_task 应在构建回报 succeeded 后被释放（容量归零）"
    );

    // 9. Operator 查看产物列表
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/builds/{}/artifacts", build_id))
                .header("Authorization", format!("Bearer {}", op_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let list_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(list_json["rpms"], serde_json::json!(["hello.rpm"]));
}

#[tokio::test]
async fn worker_upload_artifacts_for_unassigned_build_rejected() {
    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let op_token = seed_user_token_for_test(&app_state.state_store, "test-operator", "operator")
        .await
        .unwrap();

    // 1. 注册两个 Worker：worker-01 持有 assignment，worker-02 是越权方
    let (worker_a_id, token_a) =
        worker_register(&app, &app_state, "worker-01", "x86_64", &op_token).await;
    let (_worker_b_id, token_b) =
        worker_register(&app, &app_state, "worker-02", "x86_64", &op_token).await;
    seed_test_product(&store, "fedora").await;

    // 2. 创建一个 pending 构建并分配给 worker-01（worker-02 无该 build 的分配行）
    let build_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(crbs_server::test_support::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .assign_build_to_worker(build_id, worker_a_id)
        .await
        .unwrap();

    // 3. worker-02 尝试上传 worker-01 的 build 产物 → 必须 403
    let artifact_content = b"forged rpm content";
    let manifest = serde_json::json!({ "hello.rpm": sha256_hex(artifact_content) }).to_string();
    let boundary = "----integration-test";
    let body = build_multipart_body(boundary, &manifest, "hello.rpm", artifact_content);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", token_b))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "unassigned worker upload must be rejected"
    );

    // 4. worker-01（持有 assignment）上传同一产物 → 必须 200（正常路径回归）
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", token_a))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "assigned worker upload must succeed"
    );
}

#[tokio::test]
async fn worker_end_to_end_uploads_nested_artifact() {
    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let op_token = seed_user_token_for_test(&app_state.state_store, "test-operator", "operator")
        .await
        .unwrap();

    let (worker_id, token) =
        worker_register(&app, &app_state, "worker-01", "x86_64", &op_token).await;

    seed_test_product(&store, "fedora").await;

    let build_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(crbs_server::test_support::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();

    let srpm_content = b"fake srpm content";
    let srpm_path = tmp.path().join("test.src.rpm");
    tokio::fs::write(&srpm_path, srpm_content).await.unwrap();
    store
        .set_build_request_info(build_id, srpm_path.to_str().unwrap(), r#"{"priority":0}"#)
        .await
        .unwrap();

    let (assignment_id, _task_id) = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    // 生产时序：先上传（build 仍非终态）、后上报 succeeded。
    let artifact_content = b"fake nested rpm content";
    let file_name = "RPMS/x86_64/hello.rpm";
    let manifest = serde_json::json!({ file_name: sha256_hex(artifact_content) }).to_string();
    let boundary = "----integration-nested";
    let body = build_multipart_body(boundary, &manifest, file_name, artifact_content);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let upload_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(upload_json["uploaded"], serde_json::json!([file_name]));

    report_result(&app, worker_id, assignment_id, "succeeded", &token).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/builds/{}/artifacts", build_id))
                .header("Authorization", format!("Bearer {}", op_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let list_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(list_json["rpms"], serde_json::json!([file_name]));
}

/// 取消下行通路端到端：dispatch → 用户经 HTTP 取消 → 下一次
/// 心跳响应携带 `cancelled_assignments`（assignment id）；取消前的心跳响应体
/// 逐字节保持 `{"accepted":true}`（字段缺席）。
#[tokio::test]
async fn worker_heartbeat_notifies_dispatched_build_cancellation() {
    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let op_token = seed_user_token_for_test(&app_state.state_store, "test-operator", "operator")
        .await
        .unwrap();

    let (worker_id, token) =
        worker_register(&app, &app_state, "worker-cancel", "x86_64", &op_token).await;
    seed_test_product(&store, "fedora").await;

    let build_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(crbs_server::test_support::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();
    // 派发只领就绪行，水合对 NULL request_json fail-closed（release
    // 回队列）——补齐两列模拟真实链路（set_build_request_info 先于派发完成）。
    store
        .set_build_request_info(build_id, "/tmp/hello.src.rpm", r#"{"arch":"x86_64"}"#)
        .await
        .unwrap();
    let (assignment_id, _task_id) = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    // Worker 长轮询拿到任务（dispatch 成功，assignment 已下发、build 推进
    // building）。
    let task = poll_task(&app, worker_id, &token)
        .await
        .expect("should receive task");
    assert_eq!(task["assignment_id"].as_i64(), Some(assignment_id));

    // 取消前的心跳：无取消通知，响应体逐字节保持旧形态。
    assert_eq!(
        worker_heartbeat_body(&app, worker_id, &token).await,
        r#"{"accepted":true}"#
    );

    // 用户经 HTTP 取消该分布式构建（operator 权限，走 cancel_distributed_build）。
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/cancel", build_id))
                .header("Authorization", format!("Bearer {}", op_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    // 下一次心跳：响应携带该 assignment id（worker 侧据此触发即时击杀）。
    let body = worker_heartbeat_body(&app, worker_id, &token).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["accepted"], true);
    assert_eq!(
        json["cancelled_assignments"],
        serde_json::json!([assignment_id]),
        "body: {body}"
    );
}

#[tokio::test]
async fn worker_poll_returns_empty_when_no_assigned_task() {
    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        store,
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let op_token = seed_user_token_for_test(&app_state.state_store, "test-operator", "operator")
        .await
        .unwrap();

    let (worker_id, token) =
        worker_register(&app, &app_state, "worker-02", "aarch64", &op_token).await;
    let task = poll_task(&app, worker_id, &token).await;
    assert!(task.is_none());
}

/// poll 响应丢失重投递：hub 已把 assignment CAS 到 running、build 翻
/// building（事务 COMMIT 在 HTTP 响应前、响应丢失），存活的 worker 再 poll
/// 不应恒 204——wait 到期路径复查未确认 running 行，按与正常领取完全相同的
/// 字段集重发（200 带体：含签名 srpm_url 与产品配置）。
#[tokio::test]
async fn worker_poll_redelivers_unconfirmed_running_assignment() {
    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let op_token = seed_user_token_for_test(&app_state.state_store, "test-operator", "operator")
        .await
        .unwrap();

    let (worker_id, token) =
        worker_register(&app, &app_state, "worker-redeliver", "x86_64", &op_token).await;
    seed_test_product(&store, "fedora").await;

    let build_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(crbs_server::test_support::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();
    let srpm_path = tmp.path().join("hello.src.rpm");
    tokio::fs::write(&srpm_path, b"x").await.unwrap();
    store
        .set_build_request_info(
            build_id,
            srpm_path.to_str().unwrap(),
            r#"{"arch":"x86_64"}"#,
        )
        .await
        .unwrap();
    let (assignment_id, _task_id) = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    // 模拟响应丢失：正常领取事务已提交（running/building），但 worker 从未
    // 收到响应（绕过 poll 直接裸 SQL 推进）。`$N` 占位符与 PG 方言测试兼容
    //（先例 integration_gc.rs；SQLite 侧同义）。
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

    // wait=0：wait 立即到期 → 重投递路径命中 running 行 → 200 带完整任务字段。
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/workers/{}/assignments?wait=0", worker_id))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["assignment_id"].as_i64(), Some(assignment_id));
    assert_eq!(json["build_id"].as_i64(), Some(build_id));
    assert_eq!(json["product"].as_str(), Some("fedora"));
    assert_eq!(json["kind"].as_str(), Some("build"));
    assert!(
        json["srpm_url"]
            .as_str()
            .is_some_and(|u| u.starts_with("/api/v1/builds/") && u.contains("token=")),
        "srpm_url 必须与正常领取同样带签名 token: {json}"
    );
    assert!(
        json["product_config"]
            .as_str()
            .is_some_and(|c| c.contains("base_packages")),
        "产品配置必须随重投递下发: {json}"
    );
    // 重投递响应携带 redelivered=true（worker 侧据此对注册表未知的
    // 重投递打双进程排查 warn）；正常领取不携带该字段（见上文 claim 断言）。
    assert_eq!(json["redelivered"], serde_json::json!(true), "{json}");

    // 重投递不改变 DB 状态（不重置回 pending——那会复刻双执行）。
    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "building");
}

/// fail-closed 回归：产品未 seed 到 DB 时，dispatch 必须拒绝下发，
/// build 被 fail_assignment 标记为 failed，Worker 长轮询取不到任务。
#[tokio::test]
async fn worker_dispatch_fails_closed_when_product_missing_from_db() {
    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig {
            result_dir: Some(tmp.path().join("results")),
            ..Default::default()
        },
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let op_token = seed_user_token_for_test(&app_state.state_store, "test-operator", "operator")
        .await
        .unwrap();

    let (worker_id, token) =
        worker_register(&app, &app_state, "worker-fc", "x86_64", &op_token).await;

    // 故意不 seed 产品"ghost-product"到 DB
    let build_id = store
        .insert_build(BuildInsert {
            product: "ghost-product",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(
                crbs_server::test_support::seed_task(&store, "ghost-product", "hello").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    let srpm_path = tmp.path().join("ghost.src.rpm");
    tokio::fs::write(&srpm_path, b"x").await.unwrap();
    store
        .set_build_request_info(build_id, srpm_path.to_str().unwrap(), r#"{"priority":0}"#)
        .await
        .unwrap();

    // 手动分配（调度器未启动）
    let _ = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    // Worker 长轮询：dispatch 应走 NotInDb → fail_assignment 分支，返回 None
    let task = poll_task(&app, worker_id, &token).await;
    assert!(
        task.is_none(),
        "expected fail-closed to yield no task for product not in DB, got: {:?}",
        task
    );

    // build 应已被标记为 failed（fail_assignment 的行为），不再是 pending/assigned
    let record = store
        .get_build(build_id)
        .await
        .expect("query build")
        .expect("build row exists");
    assert_eq!(
        record.phase, "failed",
        "expected phase=failed after fail-closed dispatch, got '{}'",
        record.phase
    );
}
