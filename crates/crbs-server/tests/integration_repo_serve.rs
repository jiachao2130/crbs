// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 集成测试：`GET /repo/{product}/{arch}/{*path}` 发布型 repo 服务与可见性门。

// 测试 crate：辅助函数（seed_* 等）不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::{ProductConfig, ServerConfig};
use crbs_core::CreateProductInput;
use crbs_server::server::create_test_app;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;

async fn setup() -> (Arc<AppState>, axum::Router, tempfile::TempDir) {
    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        store,
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app(app_state.clone());
    (app_state, app, tmp)
}

/// 在 `{crbs_root}/results/_repo/{product}/{arch}/{rel}` 写一个 repo 文件。
async fn write_repo_file(crbs_root: &Path, product: &str, arch: &str, rel: &str, body: &str) {
    let full = crbs_root
        .join("results")
        .join("_repo")
        .join(product)
        .join(arch)
        .join(rel);
    tokio::fs::create_dir_all(full.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(&full, body).await.unwrap();
}

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, Vec<u8>) {
    let (status, _cache_control, bytes) = get_with_headers(app, uri).await;
    (status, bytes)
}

/// [`get`] 的带响应头变体：额外返回 Cache-Control 头的值（缺失为 `None`）。
async fn get_with_headers(app: &axum::Router, uri: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let cache_control = resp
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, cache_control, bytes)
}

/// public 产品 repomd.xml 200 且内容正确；私有同名文件 404；产品不存在 404；文件缺失 404（ServeFile 层，非可见性门）。
#[tokio::test]
async fn public_repo_served_private_and_missing_404() {
    let (state, app, tmp) = setup().await;
    let crbs_root = tmp.path();

    state
        .state_store
        .create_product(CreateProductInput {
            name: "pub-prod",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();

    let _token = seed_user_token_for_test(&state.state_store, "owner", "builder")
        .await
        .unwrap();
    let owner_id = state
        .state_store
        .find_user_by_name("owner")
        .await
        .unwrap()
        .unwrap()
        .id;
    state
        .state_store
        .create_product(CreateProductInput {
            name: "priv-prod",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: "private",
            config: &ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();

    // 两个产品磁盘上都有 repomd.xml：私有 404 证明门按可见性而非文件存在性。
    let repomd = "<repomd><data/></repomd>";
    write_repo_file(
        crbs_root,
        "pub-prod",
        "x86_64",
        "repodata/repomd.xml",
        repomd,
    )
    .await;
    write_repo_file(
        crbs_root,
        "priv-prod",
        "x86_64",
        "repodata/repomd.xml",
        repomd,
    )
    .await;

    let (status, body) = get(&app, "/repo/pub-prod/x86_64/repodata/repomd.xml").await;
    assert_eq!(status, StatusCode::OK, "public repomd.xml must be served");
    assert_eq!(body, repomd.as_bytes());

    let (status, _) = get(&app, "/repo/priv-prod/x86_64/repodata/repomd.xml").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "private repo must 404");

    let (status, _) = get(&app, "/repo/ghost/x86_64/repodata/repomd.xml").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "missing product must 404");

    let (status, _) = get(&app, "/repo/pub-prod/x86_64/repodata/absent.xml").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "missing file must 404");
}

/// 路径穿越（`..`）被拒 → 404，不逃逸 `_repo/{product}/{arch}` 命名空间。
#[tokio::test]
async fn path_traversal_rejected() {
    let (state, app, tmp) = setup().await;
    state
        .state_store
        .create_product(CreateProductInput {
            name: "pub-prod",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();
    let secret = tmp.path().join("results").join("secret.txt");
    tokio::fs::create_dir_all(secret.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(&secret, "top secret").await.unwrap();

    let (status, _) = get(&app, "/repo/pub-prod/x86_64/../../secret.txt").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "traversal must be rejected");
}

/// Cache-Control 分流：repomd.xml no-cache（dnf 新鲜度判据，每次 IMS 再验证），其余 repodata/ 300s，.rpm 1h 公共缓存，未覆盖路径不加头。
#[tokio::test]
async fn cache_control_by_repo_path_class() {
    let (state, app, tmp) = setup().await;
    let crbs_root = tmp.path();

    state
        .state_store
        .create_product(CreateProductInput {
            name: "pub-prod",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();

    write_repo_file(
        crbs_root,
        "pub-prod",
        "x86_64",
        "repodata/repomd.xml",
        "<repomd/>",
    )
    .await;
    write_repo_file(
        crbs_root,
        "pub-prod",
        "x86_64",
        "repodata/primary.xml.gz",
        "gz",
    )
    .await;
    write_repo_file(
        crbs_root,
        "pub-prod",
        "x86_64",
        "Packages/foo-1.0-1.fc42.x86_64.rpm",
        "rpm-bytes",
    )
    .await;
    write_repo_file(crbs_root, "pub-prod", "x86_64", "header.html", "<h1/>").await;

    let (status, cache_control, _) =
        get_with_headers(&app, "/repo/pub-prod/x86_64/repodata/repomd.xml").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        cache_control.as_deref(),
        Some("no-cache"),
        "repomd.xml must be revalidated every time"
    );

    let (status, cache_control, _) =
        get_with_headers(&app, "/repo/pub-prod/x86_64/repodata/primary.xml.gz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        cache_control.as_deref(),
        Some("max-age=300"),
        "secondary metadata may be cached briefly"
    );

    // .rpm 仅 1h 公共缓存：同 NVR 重建会换同名文件字节，长 TTL（如 30d）下 dnf
    // 拿旧字节对新 repodata 校验和失败、窗口即 TTL 时长；chroot 每次全新、长 TTL 零收益，IMS 304 仍省带宽。
    let (status, cache_control, _) = get_with_headers(
        &app,
        "/repo/pub-prod/x86_64/Packages/foo-1.0-1.fc42.x86_64.rpm",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        cache_control.as_deref(),
        Some("public, max-age=3600"),
        "RPM bytes can be swapped by same-NVR rebuilds; keep the stale window bounded to 1h"
    );

    let (status, cache_control, _) =
        get_with_headers(&app, "/repo/pub-prod/x86_64/header.html").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        cache_control.is_none(),
        "unclassified paths keep no Cache-Control header"
    );
}

/// DB 故障透传标准 5xx 错误信封（池不可用 → 503），不得把后端故障伪装成
/// "产品不存在"404——那会静默降级成"服务正常但无此产品"；种子产品与文件齐备，证明 5xx 非 404 语义。
#[tokio::test]
async fn repo_db_error_maps_5xx_error_envelope() {
    let (state, app, tmp) = setup().await;

    state
        .state_store
        .create_product(CreateProductInput {
            name: "pub-prod",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();
    write_repo_file(
        tmp.path(),
        "pub-prod",
        "x86_64",
        "repodata/repomd.xml",
        "<r/>",
    )
    .await;

    state.state_store.pool().close().await;

    let (status, _, bytes) =
        get_with_headers(&app, "/repo/pub-prod/x86_64/repodata/repomd.xml").await;
    assert!(
        status.is_server_error(),
        "DB failure must surface as 5xx, got {status}"
    );
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json["error"], "service_unavailable",
        "error envelope must carry the machine code: {json}"
    );
    assert!(
        json["message"].as_str().is_some_and(|m| !m.is_empty()),
        "envelope message must be present: {json}"
    );
}

/// 可见性翻转按代数即时失效：public → 200（缓存填充）→ 翻 private 后必须
/// 立即 404（代数 bump 驱逐缓存，而非等 TTL 过期）→ 翻回 public 恢复 200。
#[tokio::test]
async fn repo_visibility_flip_invalidates_cache_by_generation() {
    let (state, app, tmp) = setup().await;
    let crbs_root = tmp.path();

    // schema CHECK（owner_id IS NOT NULL OR visibility='public'）：可翻 private 的产品须有 owner。
    let _token = seed_user_token_for_test(&state.state_store, "flip-owner", "builder")
        .await
        .unwrap();
    let owner_id = state
        .state_store
        .find_user_by_name("flip-owner")
        .await
        .unwrap()
        .unwrap()
        .id;
    let product_id = state
        .state_store
        .create_product(CreateProductInput {
            name: "flip-prod",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: "public",
            config: &ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();
    write_repo_file(
        crbs_root,
        "flip-prod",
        "x86_64",
        "repodata/repomd.xml",
        "<repomd/>",
    )
    .await;

    let uri = "/repo/flip-prod/x86_64/repodata/repomd.xml";

    let (status, _) = get(&app, uri).await;
    assert_eq!(status, StatusCode::OK);

    // 翻 private：update_product_visibility bump 用户域代数 → 缓存未命中回源 404；
    // 若无代数失效（只剩 10s TTL），此处读到陈旧 public 结论误回 200。
    state
        .state_store
        .update_product_visibility(product_id, "private", None, Some("test flip"), None)
        .await
        .unwrap();
    let (status, _) = get(&app, uri).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "private flip must take effect immediately via generation invalidation"
    );

    state
        .state_store
        .update_product_visibility(product_id, "public", None, Some("test flip back"), None)
        .await
        .unwrap();
    let (status, _) = get(&app, uri).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "public flip must take effect immediately via generation invalidation"
    );
}
