// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 多架构构建集成测试。

// 整个文件是测试 crate：测试辅助函数（seed_* 等）不带 #[test] 属性，
// clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::ServerConfig;
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;
use serde_json::json;

async fn setup_app_with_auth() -> (
    Arc<AppState>,
    axum::Router,
    tempfile::TempDir,
    std::collections::HashMap<String, String>,
) {
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    // 测试用临时目录可能不足 1GB，禁用磁盘空间检查。
    let server_config = ServerConfig {
        min_free_disk_gb: 0,
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        state_store,
        server_config,
        tmp_dir.path().to_path_buf(),
    ));

    let mut tokens = std::collections::HashMap::new();
    for (name, role) in [("builder-token", "builder"), ("operator-token", "operator")] {
        let raw = seed_user_token_for_test(&app_state.state_store, name, role)
            .await
            .expect("seed user token");
        tokens.insert(name.to_string(), raw);
    }

    let app = create_test_app_with_auth(app_state.clone());
    (app_state, app, tmp_dir, tokens)
}

/// 设置测试产品配置（声明多架构支持）：磁盘 + DB 双写——chain_resolve 等
/// hub 路径以 SQLite 为权威源，磁盘写入保留兼容。
async fn setup_test_product(app_state: &Arc<AppState>, tmp_dir: &tempfile::TempDir) {
    let product_dir = tmp_dir.path().join("products");
    tokio::fs::create_dir_all(&product_dir).await.unwrap();
    let product_toml = r#"
base_packages = ["bash", "rpm-build"]
arches = ["x86_64", "aarch64"]

[[repos]]
name = "base"
baseurl = "http://example.com/base/$basearch"
gpgcheck = false
"#;
    tokio::fs::write(product_dir.join("testarch.toml"), product_toml)
        .await
        .unwrap();
    seed_product_into_db(app_state, "testarch", product_toml).await;
}

/// 设置测试产品配置（不写 arches，单架构模式）。同上——磁盘 + DB 双写。
async fn setup_test_product_no_arches(app_state: &Arc<AppState>, tmp_dir: &tempfile::TempDir) {
    let product_dir = tmp_dir.path().join("products");
    tokio::fs::create_dir_all(&product_dir).await.unwrap();
    let product_toml = r#"
base_packages = ["bash", "rpm-build"]

[[repos]]
name = "base"
baseurl = "http://example.com/base/$basearch"
gpgcheck = false
"#;
    tokio::fs::write(product_dir.join("testcompat.toml"), product_toml)
        .await
        .unwrap();
    seed_product_into_db(app_state, "testcompat", product_toml).await;
}

/// 把 product TOML 解析并 seed 进 DB，让 chain_resolve 能命中：服务端所有
/// 涉及产品的 hub 路径均从 SQLite 读，只写磁盘会绕过实际生产代码路径。
async fn seed_product_into_db(app_state: &Arc<AppState>, name: &str, toml_body: &str) {
    let config = crbs_core::config::ProductConfig::from_str(toml_body)
        .unwrap_or_else(|e| panic!("test product toml for '{}' failed to parse: {}", name, e));
    app_state
        .state_store
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

/// 在 upload_dir 下创建一个测试 SRPM，满足 enqueue 的 allowed_root 校验。
async fn make_test_srpm(tmp: &tempfile::TempDir) -> std::path::PathBuf {
    let upload_dir = tmp.path().join("uploads");
    tokio::fs::create_dir_all(&upload_dir).await.unwrap();
    let srpm_path = common::make_srpm_in_uploads(&upload_dir, "dummy").await;
    srpm_path
}

#[tokio::test]
async fn test_single_arch_submit_backward_compat() {
    let (state, app, tmp, tokens) = setup_app_with_auth().await;
    setup_test_product_no_arches(&state, &tmp).await;

    // 提交单架构构建（产品不写 arches，退回到本地架构）
    let srpm_path = make_test_srpm(&tmp).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/builds")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({
                        "product": "testcompat",
                        "srpms": [srpm_path.to_str().unwrap()]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["ids"].as_array().unwrap().len(), 1);
    assert!(json["task_id"].is_i64());
}

#[tokio::test]
async fn test_multi_arch_submit_creates_multiple_builds() {
    let (state, app, tmp, tokens) = setup_app_with_auth().await;
    setup_test_product(&state, &tmp).await;

    // 注册两个不同架构的 worker
    for (name, arch) in [("w1", "x86_64"), ("w2", "aarch64")] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/workers/register")
                    .header(
                        "Authorization",
                        format!("Bearer {}", tokens["operator-token"]),
                    )
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({"name": name, "arch": arch, "capacity": 2}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // 提交多架构构建
    let srpm_path = make_test_srpm(&tmp).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/builds")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({
                        "product": "testarch",
                        "srpms": [srpm_path.to_str().unwrap()],
                        "arch_list": ["x86_64", "aarch64"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // 验证返回 task_id 和 2 个 build_id
    assert!(json["task_id"].is_i64());
    let task_id = json["task_id"].as_i64().unwrap();
    let ids = json["ids"].as_array().unwrap();
    assert_eq!(ids.len(), 2);

    // 验证每个 build 的 arch 字段（直接查数据库）
    let id0 = ids[0].as_i64().unwrap();
    let id1 = ids[1].as_i64().unwrap();
    let db_build1 = state.state_store.get_build(id0).await.unwrap().unwrap();
    let db_build2 = state.state_store.get_build(id1).await.unwrap().unwrap();

    let arches: Vec<String> = vec![db_build1.arch.unwrap(), db_build2.arch.unwrap()];
    assert!(arches.contains(&"x86_64".to_string()));
    assert!(arches.contains(&"aarch64".to_string()));

    // 验证 task_id 能查询到关联构建
    let task_builds = state
        .state_store
        .get_builds_by_task_id(task_id)
        .await
        .unwrap();
    assert_eq!(task_builds.len(), 2);
}

#[tokio::test]
async fn test_multi_arch_subset_from_cli() {
    let (state, app, tmp, tokens) = setup_app_with_auth().await;
    setup_test_product(&state, &tmp).await;

    // 产品配置了 x86_64 和 aarch64，CLI 只指定 x86_64
    let srpm_path = make_test_srpm(&tmp).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/builds")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({
                        "product": "testarch",
                        "srpms": [srpm_path.to_str().unwrap()],
                        "arch_list": ["x86_64"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        status == StatusCode::ACCEPTED,
        "expected 202 Accepted, got {}: {}",
        status,
        String::from_utf8_lossy(&body)
    );
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // 只创建一个 build
    assert_eq!(json["ids"].as_array().unwrap().len(), 1);
    // 单架构也创建 task
    assert!(json["task_id"].is_i64());
}

#[tokio::test]
async fn test_multi_arch_rejects_invalid_arch() {
    let (state, app, tmp, tokens) = setup_app_with_auth().await;
    setup_test_product(&state, &tmp).await;

    // 产品只支持 x86_64 和 aarch64，提交 riscv64 应该被拒绝
    let srpm_path = make_test_srpm(&tmp).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/builds")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({
                        "product": "testarch",
                        "srpms": [srpm_path.to_str().unwrap()],
                        "arch_list": ["riscv64"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// 提交入口必须剥离客户端提交的 reproduce_from_build_id：该字段只允许由
/// 服务端 reproduce 路径程序化设置，用户值不得流入创建的构建选项。
#[tokio::test]
async fn test_submit_strips_client_set_reproduce_from_build_id() {
    let (state, app, tmp, tokens) = setup_app_with_auth().await;
    setup_test_product_no_arches(&state, &tmp).await;
    let srpm_path = make_test_srpm(&tmp).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/builds")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({
                        "product": "testcompat",
                        "srpms": [srpm_path.to_str().unwrap()],
                        "reproduce_from_build_id": 999999
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let task_id = json["task_id"].as_i64().unwrap();

    // task 级 request_json 即创建出的构建选项：客户端设置值不应到达这里
    let info = state
        .state_store
        .get_task_rebuild_info(task_id)
        .await
        .unwrap()
        .expect("task rebuild info");
    let opts: crbs_core::BuildOptions =
        serde_json::from_str(info.request_json.as_deref().unwrap()).unwrap();
    assert_eq!(
        opts.reproduce_from_build_id, None,
        "client-submitted reproduce_from_build_id must be stripped at ingress"
    );
}

/// 执行期才校验的选项（backend/memory_max/cpu_quota/stage/retry/define）应
/// 在提交时即被拒绝（400），而不是 202 后异步失败。
#[tokio::test]
async fn test_submit_validates_options_early() {
    let (state, app, tmp, tokens) = setup_app_with_auth().await;
    setup_test_product_no_arches(&state, &tmp).await;
    let srpm_path = make_test_srpm(&tmp).await;

    for (label, extra) in [
        ("retry", json!({"retry": 4294967295u64})),
        ("memory_max", json!({"memory_max": "4X"})),
        ("cpu_quota", json!({"cpu_quota": "abc"})),
        ("backend", json!({"backend": "docker"})),
        ("stage", json!({"stage": "xx"})),
        ("define", json!({"define": ["=V"]})),
    ] {
        let mut body = json!({
            "product": "testcompat",
            "srpms": [srpm_path.to_str().unwrap()],
        });
        if let serde_json::Value::Object(map) = &mut body {
            if let serde_json::Value::Object(extra_map) = extra {
                for (k, v) in extra_map {
                    map.insert(k.clone(), v.clone());
                }
            }
        }
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/builds")
                    .header(
                        "Authorization",
                        format!("Bearer {}", tokens["builder-token"]),
                    )
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "option '{}' should be rejected at submit",
            label
        );
    }
}
