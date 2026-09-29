// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 包资源画像管理面 API 集成测试：admin 门、declared set/unset 往返（列组
//! 隔离）、参数校验、审计落点。

// 整个文件是测试 crate：测试辅助函数（seed_* 等）不带 #[test] 属性，
// clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::ProductConfig;
use crbs_core::CreateProductInput;
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;

async fn setup_app(
    roles: &[(&str, &str)],
) -> (
    Arc<AppState>,
    axum::Router,
    tempfile::TempDir,
    std::collections::HashMap<String, String>,
) {
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        state_store,
        crbs_core::config::ServerConfig::default(),
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

async fn seed_product(state: &AppState, name: &str) -> i64 {
    let cfg = ProductConfig::default();
    state
        .state_store
        .create_product(CreateProductInput {
            name,
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &cfg,
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap_or_else(|e| panic!("seed product '{}': {}", name, e))
}

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<String>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header("Authorization", format!("Bearer {t}"));
    }
    let request = builder
        .header("Content-Type", "application/json")
        .body(Body::from(body.unwrap_or_default()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

/// set → get → list 往返：declared 三维落列、学习组不受影响、行回读一致。
#[tokio::test]
async fn resource_profile_set_get_list_roundtrip() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")]).await;
    seed_product(&state, "mydist").await;
    // 预置学习面行（列组隔离断言的对照物）。
    state
        .state_store
        .apply_learning_sample(
            "mydist",
            "gcc",
            "x86_64",
            &crbs_core::ResourceSampleOutcome::Succeeded {
                backend: crbs_core::SampleBackend::Cgroup,
                peak_rss_kb: 600_000,
                peak_tmpfs_kb: None,
                cpu_p90_cores: Some(2.0),
                sample_ncpu: Some(8),
            },
            Some(0),
            crbs_core::DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();

    let (status, body) = call(
        &app,
        "PUT",
        "/api/v1/resource-profiles/mydist/gcc/x86_64",
        Some(&tokens["admin-token"]),
        Some(r#"{"min_mem_kb":8388608,"min_ncpu":4}"#.into()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["declared_min_mem_kb"], 8388608);
    assert_eq!(body["declared_min_ncpu"], 4);
    assert_eq!(body["declared_min_disk_kb"], serde_json::Value::Null);
    // 列组隔离：learned 组原样。
    assert_eq!(body["learned_ema_mem_kb"], 600_000);
    assert_eq!(body["learned_samples"], 1);

    let (status, body) = call(
        &app,
        "GET",
        "/api/v1/resource-profiles/mydist/gcc/x86_64",
        Some(&tokens["admin-token"]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["declared_min_mem_kb"], 8388608);

    let (status, body) = call(
        &app,
        "GET",
        "/api/v1/resource-profiles?product=mydist",
        Some(&tokens["admin-token"]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["total"], 1);
    assert_eq!(body["profiles"].as_array().unwrap().len(), 1);
}

/// DELETE 只清 declared 列、不删行（learned 学习资产保留）；未写声明的行
/// 幂等 204。
#[tokio::test]
async fn resource_profile_delete_clears_declared_only() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")]).await;
    seed_product(&state, "mydist").await;
    state
        .state_store
        .apply_learning_sample(
            "mydist",
            "gcc",
            "x86_64",
            &crbs_core::ResourceSampleOutcome::Succeeded {
                backend: crbs_core::SampleBackend::Cgroup,
                peak_rss_kb: 600_000,
                peak_tmpfs_kb: None,
                cpu_p90_cores: None,
                sample_ncpu: None,
            },
            Some(0),
            crbs_core::DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let (status, _) = call(
        &app,
        "PUT",
        "/api/v1/resource-profiles/mydist/gcc/x86_64",
        Some(&tokens["admin-token"]),
        Some(r#"{"min_mem_kb":1024}"#.into()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = call(
        &app,
        "DELETE",
        "/api/v1/resource-profiles/mydist/gcc/x86_64",
        Some(&tokens["admin-token"]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (status, body) = call(
        &app,
        "GET",
        "/api/v1/resource-profiles/mydist/gcc/x86_64",
        Some(&tokens["admin-token"]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["declared_min_mem_kb"], serde_json::Value::Null);
    // 行还在（learned 保留）：DELETE 不删行。
    assert_eq!(body["learned_ema_mem_kb"], 600_000);

    // 幂等：再次 DELETE 204。
    let (status, _) = call(
        &app,
        "DELETE",
        "/api/v1/resource-profiles/mydist/gcc/x86_64",
        Some(&tokens["admin-token"]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// 权限：无 token 401、viewer 403（hub admin 专用，不放产品 ACL admin）。
#[tokio::test]
async fn resource_profile_requires_admin_role() {
    let (_state, app, _tmp, tokens) =
        setup_app(&[("viewer-token", "viewer"), ("admin-token", "admin")]).await;
    let (status, _) = call(
        &app,
        "GET",
        "/api/v1/resource-profiles?product=mydist",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(
        &app,
        "GET",
        "/api/v1/resource-profiles?product=mydist",
        Some(&tokens["viewer-token"]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(
        &app,
        "PUT",
        "/api/v1/resource-profiles/mydist/gcc/x86_64",
        Some(&tokens["viewer-token"]),
        Some(r#"{"min_mem_kb":1024}"#.into()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// 校验：负值/超上界 400；产品不存在 404；GET 缺 product 参数 400；未建行
/// 的键 GET 404。
#[tokio::test]
async fn resource_profile_validation_and_missing_product() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")]).await;
    // mem 超上界（1 TiB = 1073741824 KB）。
    let (status, _) = call(
        &app,
        "PUT",
        "/api/v1/resource-profiles/mydist/gcc/x86_64",
        Some(&tokens["admin-token"]),
        Some(r#"{"min_mem_kb":1073741825}"#.into()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // 负值。
    let (status, _) = call(
        &app,
        "PUT",
        "/api/v1/resource-profiles/mydist/gcc/x86_64",
        Some(&tokens["admin-token"]),
        Some(r#"{"min_ncpu":-1}"#.into()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // 产品不存在。
    let (status, _) = call(
        &app,
        "PUT",
        "/api/v1/resource-profiles/nodist/gcc/x86_64",
        Some(&tokens["admin-token"]),
        Some(r#"{"min_mem_kb":1024}"#.into()),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &app,
        "GET",
        "/api/v1/resource-profiles?product=nodist",
        Some(&tokens["admin-token"]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // 缺 product 参数。
    let (status, _) = call(
        &app,
        "GET",
        "/api/v1/resource-profiles",
        Some(&tokens["admin-token"]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // GET 未建画像行的键 404。
    seed_product(&state, "mydist").await;
    let (status, _) = call(
        &app,
        "GET",
        "/api/v1/resource-profiles/mydist/gcc/x86_64",
        Some(&tokens["admin-token"]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// set 与 unset 各落一条审计（admin audit-logs API 可查）。
#[tokio::test]
async fn resource_profile_set_unset_write_audit_logs() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")]).await;
    seed_product(&state, "mydist").await;
    let t = &tokens["admin-token"];
    let (status, _) = call(
        &app,
        "PUT",
        "/api/v1/resource-profiles/mydist/gcc/x86_64",
        Some(t),
        Some(r#"{"min_mem_kb":1024}"#.into()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &app,
        "DELETE",
        "/api/v1/resource-profiles/mydist/gcc/x86_64",
        Some(t),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = call(
        &app,
        "GET",
        "/api/v1/admin/audit-logs?action=set_resource_profile",
        Some(t),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1);
    assert_eq!(
        body["logs"].as_array().unwrap()[0]["target"],
        "mydist/gcc/x86_64"
    );
    let (status, body) = call(
        &app,
        "GET",
        "/api/v1/admin/audit-logs?action=unset_resource_profile",
        Some(t),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1);
}

/// PUT 三维全 None 的分支：缺行 404 不造 declared 全空的幽灵行；已有行照常
/// 显式清空 declared（行保留，learned 不动）。
#[tokio::test]
async fn resource_profile_put_all_none_never_creates_ghost_row() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")]).await;
    seed_product(&state, "mydist").await;
    let all_none = r#"{"min_mem_kb":null,"min_ncpu":null,"min_disk_kb":null}"#.to_string();
    let t = &tokens["admin-token"];

    // 缺行：404，且不落幽灵行。
    let (status, _) = call(
        &app,
        "PUT",
        "/api/v1/resource-profiles/mydist/gcc/x86_64",
        Some(t),
        Some(all_none.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        state
            .state_store
            .get_profile("mydist", "gcc", "x86_64")
            .await
            .unwrap()
            .is_none(),
        "all-None PUT on a missing key must not create a profile row"
    );

    // 已有行（先写声明再预置学习面）：全 None 清空 declared，learned 保留。
    let (status, _) = call(
        &app,
        "PUT",
        "/api/v1/resource-profiles/mydist/gcc/x86_64",
        Some(t),
        Some(r#"{"min_mem_kb":1024}"#.into()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    state
        .state_store
        .apply_learning_sample(
            "mydist",
            "gcc",
            "x86_64",
            &crbs_core::ResourceSampleOutcome::Succeeded {
                backend: crbs_core::SampleBackend::Cgroup,
                peak_rss_kb: 600_000,
                peak_tmpfs_kb: None,
                cpu_p90_cores: None,
                sample_ncpu: None,
            },
            Some(0),
            crbs_core::DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let (status, body) = call(
        &app,
        "PUT",
        "/api/v1/resource-profiles/mydist/gcc/x86_64",
        Some(t),
        Some(all_none),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["declared_min_mem_kb"], serde_json::Value::Null);
    assert_eq!(body["learned_ema_mem_kb"], 600_000);
}
