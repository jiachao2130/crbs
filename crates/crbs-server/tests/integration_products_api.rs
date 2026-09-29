// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 集成测试：产品 CRUD + expected_revision → 409 + RBAC 可见性。

// 整个文件是测试 crate：测试辅助函数（seed_* 等）不带 #[test] 属性，
// clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::{ProductConfig, ServerConfig};
use crbs_core::CreateProductInput;
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;

mod common;

use common::TEST_CONFIG_DIR;

/// 最小可解析 TOML；测试的行为都只依赖 `base_packages` 与 `repos` 的存在。
const SAMPLE_TOML: &str = "\
base_packages = [\"bash\", \"rpm-build\"]
arches = [\"x86_64\"]

[[repos]]
name = \"base\"
baseurl = \"http://example.com/base/$basearch\"
gpgcheck = false
";

fn sample_config() -> ProductConfig {
    ProductConfig::from_str(SAMPLE_TOML).expect("sample product toml parses")
}

fn config_as_json_value() -> serde_json::Value {
    serde_json::to_value(sample_config()).expect("serialize sample product config")
}

/// 共享配置目录见 `tests/common/mod.rs`（`CRBS_CONFIG_DIR` 指向可写 tempdir，
/// 避免产品配置解析读取 `/etc/crbs/crbs.toml`、`/var/lib/crbs/*` 触发
/// Permission denied）。
async fn setup_app(
    roles: &[(&str, &str)],
    allow_product_management: bool,
) -> (
    Arc<AppState>,
    axum::Router,
    tempfile::TempDir,
    std::collections::HashMap<String, String>,
) {
    let _ = TEST_CONFIG_DIR.path();
    crbs_server::test_support::init_test_logging();
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    let server_config = ServerConfig {
        allow_product_management,
        ..ServerConfig::default()
    };
    let app_state = Arc::new(AppState::for_test(
        state_store,
        server_config,
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

async fn read_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body bytes");
    serde_json::from_slice(&bytes).expect("response body is JSON")
}

async fn user_id(state: &AppState, name: &str) -> i64 {
    state
        .state_store
        .find_user_by_name(name)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("user '{}' should exist", name))
        .id
}

/// 直接经 state 层 seed 一个产品；配合 read-visibility 与 update/delete/history 测试。
async fn seed_product(
    state: &AppState,
    name: &str,
    visibility: &str,
    owner_id: Option<i64>,
) -> i64 {
    let cfg = sample_config();
    state
        .state_store
        .create_product(CreateProductInput {
            name,
            display_name: None,
            owner_id,
            parent_id: None,
            visibility,
            config: &cfg,
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap_or_else(|e| panic!("seed product '{}': {}", name, e))
}

fn admin_body() -> serde_json::Value {
    serde_json::json!({
        "name": "test-prod",
        "display_name": "Test",
        "visibility": "public",
        "config": config_as_json_value(),
        "reason": "create via api",
    })
}

// -------- create_product --------

#[tokio::test]
async fn create_product_success() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(admin_body().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = read_json(resp).await;
    assert_eq!(body["name"], "test-prod");
    assert_eq!(body["revision"], 1);
    assert_eq!(body["base_os_revision"], 1);

    let rec = state
        .state_store
        .get_official_product_by_name("test-prod")
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(rec.visibility, "public");
    assert!(
        rec.owner_id.is_none(),
        "admin API creates official rows (owner_id IS NULL)"
    );
}

#[tokio::test]
async fn create_product_rejects_duplicate_name() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;
    seed_product(&state, "dup", "public", None).await;

    let mut body = admin_body();
    body["name"] = serde_json::Value::String("dup".into());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn create_product_rejects_invalid_name() {
    let (_state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;

    let mut body = admin_body();
    body["name"] = serde_json::Value::String("has spaces".into());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_product_rejects_uppercase_and_unicode_names() {
    // Regression：server 写路径用 `validate_product_name_for_write` 收严到
    // slug `^[a-z0-9_-]+$`，避免 hub DB 里出现无法 seed / URL 传参异常的
    // slug；core `validate_product` 更宽（is_ascii_alphanumeric，放行大写），
    // 下列输入必须显式返回 400。
    let bad_names = ["My3", "产品", "hello.world", "café"];
    for bad in bad_names {
        let (_state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;
        let mut body = admin_body();
        body["name"] = serde_json::Value::String(bad.into());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/products")
                    .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "name '{}' should be rejected",
            bad
        );
    }
}

/// builder 可创建私人产品，但不能创建 public 产品（仅 admin 可设非 private 可见性）。
/// create 门槛 require_builder：viewer 403，operator/admin 同样放行。
#[tokio::test]
async fn create_product_rejects_builder_public_and_viewer_create() {
    let (state, app, _tmp, tokens) = setup_app(
        &[("builder-token", "builder"), ("viewer-token", "viewer")],
        false,
    )
    .await;

    // viewer 完全不能创建 → 403
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["viewer-token"]),
                )
                .header("Content-Type", "application/json")
                .body(Body::from(admin_body().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // builder 试图创建 public 产品 → 400
    let mut body = admin_body();
    body["visibility"] = serde_json::json!("public");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products")
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
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // builder 创建 private 产品 → 201
    let mut body = admin_body();
    body["name"] = serde_json::json!("builder-private");
    body["visibility"] = serde_json::json!("private");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products")
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
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 验证 owner_id = self 且 visibility=private
    let record = state
        .state_store
        .get_product_by_name("builder-private")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.visibility, "private");
    assert!(record.owner_id.is_some());
}

// -------- update_product --------

#[tokio::test]
async fn update_product_success() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;
    seed_product(&state, "up1", "public", None).await;

    // 修改一个非触发字段（`nocheck`）以避免 base_os 抬升。
    let mut cfg = sample_config();
    cfg.nocheck = Some(true);
    let body = serde_json::json!({
        "expected_revision": 1,
        "config": serde_json::to_value(&cfg).unwrap(),
        "reason": "toggle nocheck",
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/products/up1")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["revision"], 2);
    assert_eq!(body["base_os_revision"], 1);
    assert_eq!(body["base_os_bumped"], false);
}

#[tokio::test]
async fn update_product_bumps_base_os_when_trigger_field_changes() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;
    seed_product(&state, "up2", "public", None).await;

    // base_packages 是 base_os trigger 字段
    let mut cfg = sample_config();
    cfg.base_packages.push("git".into());
    let body = serde_json::json!({
        "expected_revision": 1,
        "config": serde_json::to_value(&cfg).unwrap(),
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/products/up2")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["revision"], 2);
    assert_eq!(body["base_os_revision"], 2);
    assert_eq!(body["base_os_bumped"], true);
}

#[tokio::test]
async fn update_product_returns_409_on_stale_revision() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;
    seed_product(&state, "up3", "public", None).await;

    let mut cfg = sample_config();
    cfg.nocheck = Some(true);
    let body = serde_json::json!({
        "expected_revision": 99,
        "config": serde_json::to_value(&cfg).unwrap(),
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/products/up3")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn update_product_returns_400_when_expected_revision_missing() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;
    seed_product(&state, "up4", "public", None).await;

    let body = serde_json::json!({
        "config": config_as_json_value(),
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/products/up4")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    // 缺 `expected_revision` → axum Json 提取拒绝：400 或 422（axum 版本相关，
    // 我们只保证是 4xx 客户端错误，不是 200/5xx）
    let status = resp.status();
    assert!(
        matches!(
            status,
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
        ),
        "unexpected status: {}",
        status
    );
}

#[tokio::test]
async fn update_product_returns_404_for_unknown_name() {
    let (_state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;

    let body = serde_json::json!({
        "expected_revision": 1,
        "config": config_as_json_value(),
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/products/no-such-product")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // 404 message 参数化：message 应含资源名（product）与请求的 name。
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "not_found");
    let msg = json["message"].as_str().unwrap();
    assert!(
        msg.contains("product") && msg.contains("no-such-product"),
        "message should name the resource and id: {msg}"
    );
}

// -------- delete_product --------

#[tokio::test]
async fn delete_product_success() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;
    seed_product(&state, "del1", "public", None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/products/del1")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let rec = state
        .state_store
        .get_official_product_by_name("del1")
        .await
        .unwrap();
    assert!(rec.is_none());
}

#[tokio::test]
async fn delete_product_returns_404_on_missing() {
    let (_state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/products/no-such")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// -------- 列表 / 查询可见性 --------

#[tokio::test]
async fn list_products_filters_by_visibility() {
    let (state, app, _tmp, tokens) = setup_app(&[("viewer-token", "viewer")], false).await;
    // 私有产品需要 owner_id（schema CHECK）；seed 一个 helper 用户作 owner。
    let helper_id = state
        .state_store
        .create_user("helper", "viewer")
        .await
        .unwrap();
    seed_product(&state, "pub1", "public", None).await;
    seed_product(&state, "priv1", "private", Some(helper_id)).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["viewer-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Vec<String> = serde_json::from_value(read_json(resp).await).unwrap();
    assert!(body.contains(&"pub1".to_string()));
    assert!(!body.contains(&"priv1".to_string()));
}

#[tokio::test]
async fn list_products_owner_sees_own_private() {
    let (state, app, _tmp, tokens) = setup_app(&[("owner-token", "viewer")], false).await;
    let owner_id = user_id(&state, "owner-token").await;
    let other_id = state
        .state_store
        .create_user("other", "viewer")
        .await
        .unwrap();
    seed_product(&state, "mine", "private", Some(owner_id)).await;
    seed_product(&state, "yours", "private", Some(other_id)).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products")
                .header("Authorization", format!("Bearer {}", tokens["owner-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Vec<String> = serde_json::from_value(read_json(resp).await).unwrap();
    assert!(body.contains(&"mine".to_string()));
    assert!(!body.contains(&"yours".to_string()));
}

#[tokio::test]
async fn get_product_returns_404_when_private_and_not_owner() {
    let (state, app, _tmp, tokens) = setup_app(&[("viewer-token", "viewer")], false).await;
    let owner_id = state
        .state_store
        .create_user("secret-owner", "viewer")
        .await
        .unwrap();
    seed_product(&state, "hidden", "private", Some(owner_id)).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products/hidden")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["viewer-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// 产品链逐节点可见性检查。
///
/// 场景：public child 继承 private parent（owner=A）。
/// 外部用户（不是 owner）访问 child：
/// - leaf 是 public，本身可见
/// - 但 parent 是 private 且调用者不是 owner
/// - 整条链检查应该失败，返回 404（不泄露 private parent 存在）
#[tokio::test]
async fn chain_resolve_hides_private_ancestor_from_outsider() {
    let (state, app, _tmp, tokens) = setup_app(&[("outsider-token", "viewer")], false).await;
    let owner_id = state
        .state_store
        .create_user("chain-owner", "builder")
        .await
        .unwrap();

    // parent：private（仅 owner 可见）
    let parent_id = seed_product(&state, "secret-base", "private", Some(owner_id)).await;
    // child：public（leaf 人人可见，但祖先藏 private）
    let child_id = seed_product(&state, "public-child", "public", None).await;

    // re-parent：child -> parent
    state
        .state_store
        .update_product_parent(
            child_id,
            Some(parent_id),
            None,
            Some("test inheritance"),
            None,
        )
        .await
        .unwrap();

    // 外部用户访问 child：404（因为 ancestor 是 private 且不可见）
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products/public-child")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["outsider-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // resolved 端点同样返回 404
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products/public-child/resolved")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["outsider-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// owner 能看到自己的私人产品，能拿 resolved，outsider 拿不到
#[tokio::test]
async fn private_product_visible_only_to_owner_and_acl() {
    let (state, app, _tmp, tokens) = setup_app(
        &[("builder-token", "builder"), ("viewer-token", "viewer")],
        false,
    )
    .await;
    let owner_id = state
        .state_store
        .find_user_by_name("builder-token")
        .await
        .unwrap()
        .unwrap()
        .id;

    // 建一个私人产品
    let _product_id = seed_product(&state, "my-private-product", "private", Some(owner_id)).await;

    // owner 能看到 detail
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products/my-private-product")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // owner 能拿到 resolved
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products/my-private-product/resolved")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // outsider 看不到
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products/my-private-product")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["viewer-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// 官方产品 unpublish 直接拒绝（需 transfer 给 owner 才能变 private）
#[tokio::test]
async fn official_product_cannot_be_unpublished() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;
    seed_product(&state, "official-prod", "public", None).await;

    // admin 尝试 unpublish → 409（官方产品不能直接 unpublish，需先 transfer）
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/official-prod/visibility")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"visibility": "private", "expected_revision": 1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    // 官方产品 unpublish 守卫：归 409 状态冲突族（非 400）
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

/// 官方产品 transfer 给用户后自动变为 private
#[tokio::test]
async fn transfer_official_product_turns_private() {
    let (state, app, _tmp, tokens) = setup_app(
        &[("admin-token", "admin"), ("new-owner-token", "builder")],
        false,
    )
    .await;
    seed_product(&state, "official-prod", "public", None).await;
    let new_owner_id = state
        .state_store
        .find_user_by_name("new-owner-token")
        .await
        .unwrap()
        .unwrap()
        .id;

    // admin transfer 给用户
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/official-prod/transfer")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"new_owner_username": "new-owner-token", "expected_revision": 1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 验证产品已变为 private，且 owner 正确
    let record = state
        .state_store
        .get_product_by_name("official-prod")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.visibility, "private");
    assert_eq!(record.owner_id, Some(new_owner_id));

    // 新 owner 能看到
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products/official-prod")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["new-owner-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// publish 单调性：有私人祖先的产品不能 publish
#[tokio::test]
async fn cannot_publish_product_with_private_ancestor() {
    let (state, app, _tmp, tokens) = setup_app(
        &[("owner-token", "builder"), ("admin-token", "admin")],
        false,
    )
    .await;
    let owner_id = state
        .state_store
        .find_user_by_name("owner-token")
        .await
        .unwrap()
        .unwrap()
        .id;

    // 建一个私人父产品
    let parent_id = state
        .state_store
        .create_product(CreateProductInput {
            name: "private-parent",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: "private",
            config: &sample_config(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();

    // 建一个私人子产品（继承父产品）
    let _child_id = state
        .state_store
        .create_product(CreateProductInput {
            name: "private-child",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: Some(parent_id),
            visibility: "private",
            config: &sample_config(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();

    // owner 尝试 publish child → 400（因为父产品是 private）
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/private-child/visibility")
                .header("Authorization", format!("Bearer {}", tokens["owner-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"visibility": "public", "expected_revision": 1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = read_json(resp).await;
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("private ancestor"));

    // 先 publish 父产品
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/private-parent/visibility")
                .header("Authorization", format!("Bearer {}", tokens["owner-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"visibility": "public", "expected_revision": 1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 现在可以 publish 子产品了
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/private-child/visibility")
                .header("Authorization", format!("Bearer {}", tokens["owner-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"visibility": "public", "expected_revision": 1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// public 产品 re-parent 到 private parent → 409 拒绝（防经 chain 泄漏 private 祖先）
#[tokio::test]
async fn public_product_cannot_reparent_to_private_ancestor() {
    let (state, app, _tmp, tokens) = setup_app(
        &[("owner-token", "builder"), ("admin-token", "admin")],
        false,
    )
    .await;
    let owner_id = state
        .state_store
        .find_user_by_name("owner-token")
        .await
        .unwrap()
        .unwrap()
        .id;

    // 建一个私人父产品
    let private_parent_id = state
        .state_store
        .create_product(CreateProductInput {
            name: "private-parent",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: "private",
            config: &sample_config(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();

    // 建一个 public 子产品（根）
    let _public_child_id = state
        .state_store
        .create_product(CreateProductInput {
            name: "public-child",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: "public",
            config: &sample_config(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();

    // 尝试把 public child 挂到 private parent 下 → 409（与 state 层
    // DeleteRestricted→409 守卫同族）
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/products/public-child")
                .header("Authorization", format!("Bearer {}", tokens["owner-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "expected_revision": 1,
                        "parent_id": private_parent_id,
                        "config": config_as_json_value(),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = read_json(resp).await;
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("private ancestor"));

    // 先把父产品 publish
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/private-parent/visibility")
                .header("Authorization", format!("Bearer {}", tokens["owner-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"visibility": "public", "expected_revision": 1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 现在父产品是 public，可以挂了
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/products/public-child")
                .header("Authorization", format!("Bearer {}", tokens["owner-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "expected_revision": 1,
                        "parent_id": private_parent_id,
                        "config": config_as_json_value(),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// private 产品 re-parent 到 private parent → 允许（owner 对两者都有访问权限时）
#[tokio::test]
async fn private_product_can_reparent_to_private_ancestor_when_owner() {
    let (state, app, _tmp, tokens) = setup_app(&[("owner-token", "builder")], false).await;
    let owner_id = state
        .state_store
        .find_user_by_name("owner-token")
        .await
        .unwrap()
        .unwrap()
        .id;

    // 建一个私人父产品
    let parent_id = state
        .state_store
        .create_product(CreateProductInput {
            name: "private-parent",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: "private",
            config: &sample_config(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();

    // 建一个私人子产品（根）
    state
        .state_store
        .create_product(CreateProductInput {
            name: "private-child",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: "private",
            config: &sample_config(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();

    // owner 可以把 private child 挂到 private parent 下（两者都是 owner 的）
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/products/private-child")
                .header("Authorization", format!("Bearer {}", tokens["owner-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "expected_revision": 1,
                        "parent_id": parent_id,
                        "config": config_as_json_value(),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// 创建产品与官方产品同名 → 409 AlreadyExists
#[tokio::test]
async fn create_product_conflict_with_official_returns_409() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;
    seed_product(&state, "official-prod", "public", None).await;

    // 试图创建同名产品
    let mut body = admin_body();
    body["name"] = serde_json::json!("official-prod");
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = read_json(resp).await;
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("namespace is global"));
}

/// 创建产品与他人私人产品同名 → 409 AlreadyExists
#[tokio::test]
async fn create_product_conflict_with_others_private_returns_409() {
    let (state, app, _tmp, tokens) = setup_app(
        &[("admin-token", "admin"), ("owner-token", "builder")],
        false,
    )
    .await;
    let owner_id = state
        .state_store
        .find_user_by_name("owner-token")
        .await
        .unwrap()
        .unwrap()
        .id;
    // owner 创建私人产品
    state
        .state_store
        .create_product(CreateProductInput {
            name: "someones-private",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: "private",
            config: &sample_config(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    // admin 试图创建同名产品 → 冲突
    let mut body = admin_body();
    body["name"] = serde_json::json!("someones-private");
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = read_json(resp).await;
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("namespace is global"));
}

/// unpublish 私人产品时存在外部 child（owner 不同）→ 409
#[tokio::test]
async fn unpublish_with_external_child_returns_409() {
    let (state, app, _tmp, tokens) = setup_app(
        &[("alice-token", "builder"), ("bob-token", "builder")],
        false,
    )
    .await;
    let alice_id = state
        .state_store
        .find_user_by_name("alice-token")
        .await
        .unwrap()
        .unwrap()
        .id;
    let bob_id = state
        .state_store
        .find_user_by_name("bob-token")
        .await
        .unwrap()
        .unwrap()
        .id;

    // alice 创建 public parent
    let parent_id = state
        .state_store
        .create_product(CreateProductInput {
            name: "alice-public",
            display_name: None,
            owner_id: Some(alice_id),
            parent_id: None,
            visibility: "public",
            config: &sample_config(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    // bob 创建 private child 挂到 alice 的 public parent 下
    state
        .state_store
        .create_product(CreateProductInput {
            name: "bob-child",
            display_name: None,
            owner_id: Some(bob_id),
            parent_id: Some(parent_id),
            visibility: "private",
            config: &sample_config(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    // alice 试图 unpublish parent → 409（外部 child 存在）
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/alice-public/visibility")
                .header("Authorization", format!("Bearer {}", tokens["alice-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"visibility": "private", "expected_revision": 1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = read_json(resp).await;
    assert!(body["message"].as_str().unwrap().contains("external child"));
}

/// transfer 官方产品存在外部 child → 409
#[tokio::test]
async fn transfer_official_with_external_child_returns_409() {
    let (state, app, _tmp, tokens) =
        setup_app(&[("admin-token", "admin"), ("bob-token", "builder")], false).await;
    let bob_id = state
        .state_store
        .find_user_by_name("bob-token")
        .await
        .unwrap()
        .unwrap()
        .id;

    // 官方产品
    let parent_id = seed_product(&state, "official-parent", "public", None).await;

    // bob 创建 child 挂到官方 parent 下
    state
        .state_store
        .create_product(CreateProductInput {
            name: "bob-child",
            display_name: None,
            owner_id: Some(bob_id),
            parent_id: Some(parent_id),
            visibility: "private",
            config: &sample_config(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    // admin 试图 transfer 官方产品给 bob → 409（外部 child 存在）
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/official-parent/transfer")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"new_owner_username": "bob-token", "expected_revision": 1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = read_json(resp).await;
    assert!(body["message"].as_str().unwrap().contains("external child"));
}

/// unpublish 时存在 public 后代 → 409（路由预检与 state 层
/// DeleteRestricted→409 守卫同族）
#[tokio::test]
async fn unpublish_with_public_descendant_returns_409() {
    let (state, app, _tmp, tokens) = setup_app(&[("alice-token", "builder")], false).await;
    let alice_id = state
        .state_store
        .find_user_by_name("alice-token")
        .await
        .unwrap()
        .unwrap()
        .id;

    // alice 的 public parent + 同 owner 的 public child（无外部 child，命中
    // 的是路由层 public 后代预检而非 state 层 external child 守卫）
    let parent_id = state
        .state_store
        .create_product(CreateProductInput {
            name: "alice-public",
            display_name: None,
            owner_id: Some(alice_id),
            parent_id: None,
            visibility: "public",
            config: &sample_config(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();
    state
        .state_store
        .create_product(CreateProductInput {
            name: "alice-child",
            display_name: None,
            owner_id: Some(alice_id),
            parent_id: Some(parent_id),
            visibility: "public",
            config: &sample_config(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    // alice 试图 unpublish parent → 409（public 后代会泄漏私有祖先链）
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/alice-public/visibility")
                .header("Authorization", format!("Bearer {}", tokens["alice-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"visibility": "private", "expected_revision": 1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = read_json(resp).await;
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("public descendants"));
}

/// transfer 官方产品存在 public 后代 → 409（同上；子产品同为官方
/// ownerless，排除 external child 守卫，命中路由层预检）
#[tokio::test]
async fn transfer_official_with_public_descendant_returns_409() {
    let (state, app, _tmp, tokens) =
        setup_app(&[("admin-token", "admin"), ("bob-token", "builder")], false).await;

    // 官方 parent + 官方（ownerless）public child
    let parent_id = seed_product(&state, "official-parent", "public", None).await;
    state
        .state_store
        .create_product(CreateProductInput {
            name: "official-child",
            display_name: None,
            owner_id: None,
            parent_id: Some(parent_id),
            visibility: "public",
            config: &sample_config(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    // admin 试图 transfer 官方产品给 bob → 409（transfer 变 private 会经
    // public child 泄漏）
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/official-parent/transfer")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"new_owner_username": "bob-token", "expected_revision": 1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = read_json(resp).await;
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("public descendants"));
}

// -------- history --------

#[tokio::test]
async fn get_product_history_returns_entries_desc() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;
    let id = seed_product(&state, "hist", "public", None).await;

    let mut cfg = sample_config();
    cfg.releasever = Some("40".into());
    state
        .state_store
        .update_product_config(id, &cfg, None, Some("bump releasever"), Some(1))
        .await
        .unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products/hist/history")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let entries: Vec<serde_json::Value> = serde_json::from_value(read_json(resp).await).unwrap();
    assert_eq!(entries.len(), 2);
    // DESC 排序（新的 rev 靠前）
    assert_eq!(entries[0]["revision"], 2);
    assert_eq!(entries[1]["revision"], 1);
}

#[tokio::test]
async fn get_product_history_specific_revision() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;
    seed_product(&state, "onerev", "public", None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products/onerev/history/1")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let entry = read_json(resp).await;
    assert_eq!(entry["revision"], 1);
    assert_eq!(entry["reason"], "test seed");
}

// -------- moved 端点 --------

#[tokio::test]
async fn moved_clean_endpoint_still_works_via_post() {
    // clean 走 BuildEngine，需要 allow_product_management=true 才能过前置检查。
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], true).await;
    seed_product(&state, "cleanme", "public", None).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/cleanme/clean")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    // 202 Accepted：任务已 spawn（后台执行结果与否不影响本用例）
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // DELETE /products/{name} 语义是删除 DB 行（204）；clean 需走 POST /clean。
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/products/cleanme")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

// -------- resolved（~ 导出桥接）--------

#[tokio::test]
async fn resolved_returns_toml_for_public_product() {
    // 官方产品：任意认证角色可读；认证继承 `routes::product::router()` 的
    // auth_middleware 包装，与其它产品 GET 端点一致（ops 经
    // `crbs products export --remote <profile>` 传 token）。
    // Content-Type 为 application/toml，body 可 round-trip 回等价 ProductConfig
    //（base_packages / repos 至少能对上）。
    let (state, app, _tmp, tokens) = setup_app(&[("viewer-token", "viewer")], false).await;
    seed_product(&state, "mydist", "public", None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products/mydist/resolved")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["viewer-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .expect("content-type present")
        .to_str()
        .expect("content-type is ascii");
    assert!(
        ct.starts_with("application/toml"),
        "unexpected content-type: {}",
        ct
    );
    // resolved 配置快照随写变化，响应禁缓存。
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("collect body");
    let body = String::from_utf8(bytes.to_vec()).expect("utf-8 body");
    // Round-trip：能被 ProductConfig 重新解析且 base_packages / repos 与 seed 相等。
    let parsed = ProductConfig::from_str(&body).expect("resolved TOML parses back");
    assert_eq!(parsed.base_packages, vec!["bash", "rpm-build"]);
    assert_eq!(parsed.repos.len(), 1);
    assert_eq!(parsed.repos[0].name, "base");
}

#[tokio::test]
async fn resolved_returns_404_for_unknown_product() {
    let (_state, app, _tmp, tokens) = setup_app(&[("viewer-token", "viewer")], false).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products/nope/resolved")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["viewer-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn resolved_hides_private_product_from_non_owner() {
    // 私人产品对非 admin / 非 owner 应返回 404（不泄漏存在性），与 get_product 一致。
    // owner 可见的用例见 private_product_visible_only_to_owner_and_acl。
    let (state, app, _tmp, tokens) = setup_app(&[("intruder-token", "viewer")], false).await;
    let secret_owner = state
        .state_store
        .create_user("secret-owner", "viewer")
        .await
        .unwrap();
    seed_product(&state, "secret", "private", Some(secret_owner)).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products/secret/resolved")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["intruder-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─────────────────── re-parent + fork API ───────────────────

/// 父层 build_target=ba + 子层 deterministic=true（缺省继承 ba）：写前须拦
/// 400，否则落库后加载即 500。子层显式 bb 覆盖父层 ba 后合法放行。
#[tokio::test]
async fn create_product_rejects_det_child_inheriting_parent_ba() {
    let (_state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;

    let mut parent_cfg = config_as_json_value();
    parent_cfg["build_target"] = serde_json::json!("ba");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "name": "ba-parent",
                        "visibility": "public",
                        "reason": "test",
                        "config": parent_cfg,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "non-det parent with build_target=ba is legal"
    );
    let parent = read_json(resp).await;
    let parent_id = parent["id"].as_i64().expect("create body carries id");

    let mut child = config_as_json_value();
    child["deterministic"] = serde_json::json!(true);
    child["dnf_cache_enabled"] = serde_json::json!(true);
    if let Some(obj) = child.as_object_mut() {
        obj.remove("build_target");
    }
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "name": "det-child",
                        "visibility": "public",
                        "reason": "test",
                        "parent_id": parent_id,
                        "config": child.clone(),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "det child inheriting parent ba must 400"
    );
    let body = read_json(resp).await;
    assert!(
        body.to_string().contains("build_target 'ba'"),
        "error must name the inherited bad value: {body}"
    );

    // 子层显式 bb 覆盖父层 ba → 链生效值合法，同一 fork 形态放行。
    let mut child_bb = child;
    child_bb["build_target"] = serde_json::json!("bb");
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "name": "det-child-bb",
                        "visibility": "public",
                        "reason": "test",
                        "parent_id": parent_id,
                        "config": child_bb,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "explicit bb overrides parent ba"
    );
}

/// POST /products 带不存在的 parent_id → 404（core NotFound → ApiError 映射），
/// 守卫写路径存在性检查。
#[tokio::test]
async fn create_product_with_missing_parent_returns_not_found() {
    let (_state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;
    let mut body = admin_body();
    body["parent_id"] = serde_json::json!(9_999_999);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// PUT /products/{name} 把 parent_id 指向自己的后代 → 400 Validation
///（ProductChainCycle → ApiError::Validation）。
#[tokio::test]
async fn update_product_reparent_to_descendant_returns_400() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;

    // r <- m
    let r = seed_product(&state, "r", "public", None).await;
    let empty = ProductConfig::default();
    let m = state
        .state_store
        .create_product(CreateProductInput {
            name: "m",
            display_name: None,
            owner_id: None,
            parent_id: Some(r),
            visibility: "public",
            config: &empty,
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    // 试图把 r 挪成 m 的 child → cycle
    let r_rec = state
        .state_store
        .get_product_by_id(r)
        .await
        .unwrap()
        .unwrap();
    let body = serde_json::json!({
        "expected_revision": r_rec.revision,
        "config": config_as_json_value(),
        "parent_id": m,
        "reason": "test cycle rejection",
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/products/r")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 副作用检查：r 的 parent 与 revision 都没动
    let after = state
        .state_store
        .get_product_by_id(r)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.parent_id, None);
    assert_eq!(after.revision, r_rec.revision);
}

/// re-parent detach（`parent_id: null`）happy path。
#[tokio::test]
async fn update_product_reparent_detach_succeeds() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-token", "admin")], false).await;
    let root = seed_product(&state, "root", "public", None).await;
    let empty = ProductConfig::default();
    let leaf = state
        .state_store
        .create_product(CreateProductInput {
            name: "leaf",
            display_name: None,
            owner_id: None,
            parent_id: Some(root),
            visibility: "public",
            config: &empty,
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();
    let before = state
        .state_store
        .get_product_by_id(leaf)
        .await
        .unwrap()
        .unwrap();

    let body = serde_json::json!({
        "expected_revision": before.revision,
        "config": config_as_json_value(),
        "parent_id": serde_json::Value::Null,
        "reason": "detach",
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/products/leaf")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let after = state
        .state_store
        .get_product_by_id(leaf)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.parent_id, None);
    // config 更新 + re-parent 各 bump 一次 → +2
    assert_eq!(after.revision, before.revision + 2);
}

/// GET /products/{name} 详情含 id + parent_id + parent_name 字段
///（CLI 的 products fork 依赖 id）。
#[tokio::test]
async fn get_product_detail_includes_parent_graph_meta() {
    let (state, app, _tmp, tokens) = setup_app(&[("viewer-token", "viewer")], false).await;
    let root = seed_product(&state, "root", "public", None).await;
    // leaf 用空 config，避免 chain 出口的 repo 重名护栏（root 有名叫 "base" 的 repo）
    let empty = ProductConfig::default();
    let _leaf = state
        .state_store
        .create_product(CreateProductInput {
            name: "leaf",
            display_name: None,
            owner_id: None,
            parent_id: Some(root),
            visibility: "public",
            config: &empty,
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products/leaf")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["viewer-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["parent_name"], "root");
    assert_eq!(body["parent_id"], root);
    assert!(
        body.get("id").is_some(),
        "leaf detail should carry its own id"
    );

    // root 自身无 parent → parent 字段缺席（skip_serializing_if）
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products/root")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["viewer-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body.get("parent_id"), None);
    assert_eq!(body.get("parent_name"), None);
}

/// ACL builder/admin 角色可以正确授予（grant API 三角色放行）
#[tokio::test]
async fn grant_acl_builder_admin_roles_work() {
    let (state, app, _tmp, tokens) = setup_app(
        &[
            ("admin-token", "admin"),
            ("owner-token", "builder"),
            ("builder-token", "builder"),
            ("viewer-token", "viewer"),
        ],
        false,
    )
    .await;

    // owner 创建私人产品
    let owner_id = state
        .state_store
        .find_user_by_name("owner-token")
        .await
        .unwrap()
        .unwrap()
        .id;
    state
        .state_store
        .create_product(CreateProductInput {
            name: "private-prod",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: "private",
            config: &sample_config(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    // 1. grant builder 角色
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/private-prod/acl")
                .header("Authorization", format!("Bearer {}", tokens["owner-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"username": "builder-token", "role": "builder"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // 2. grant admin 角色
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/private-prod/acl")
                .header("Authorization", format!("Bearer {}", tokens["owner-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"username": "viewer-token", "role": "admin"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // 3. 无效角色 → 400
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/private-prod/acl")
                .header("Authorization", format!("Bearer {}", tokens["owner-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"username": "admin-token", "role": "invalid-role"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = read_json(resp).await;
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("must be one of: viewer, builder, admin"));
}

/// 官方产品 transfer 给用户时，同事务内 cancel 所有 pending/building builds
#[tokio::test]
async fn transfer_official_product_cancels_builds() {
    let (state, app, _tmp, tokens) =
        setup_app(&[("admin-token", "admin"), ("new-owner", "builder")], false).await;

    // admin 创建官方产品（owner_id=None，visibility=public）
    state
        .state_store
        .create_product(CreateProductInput {
            name: "official-prod",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &sample_config(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    // 获取产品 ID 与 admin 用户 ID
    let product = state
        .state_store
        .get_product_by_name("official-prod")
        .await
        .unwrap()
        .unwrap();
    let admin = state
        .state_store
        .find_user_by_name("admin-token")
        .await
        .unwrap()
        .unwrap();

    // 创建 pending build（模拟 worker 未开始构建）。
    // builds.task_id NOT NULL：先插本地任务行承接。
    // 双方言写法：$N 占位符 + "user" 引号（PG 保留字；SQLite 同样接受）。
    let task_id: i64 = sqlx::query_scalar(
        "INSERT INTO tasks (product, pkg_name, \"user\", phase, product_id)
             VALUES ('official-prod', 'test-pkg', 'admin', 'pending', $1) RETURNING id",
    )
    .bind(product.id)
    .fetch_one(state.state_store.pool())
    .await
    .unwrap();
    sqlx::query(
            "INSERT INTO builds (product, product_id, pkg_name, name, version, release, phase, arch, result_dir, backend, \"user\", user_id, task_id)
             VALUES ('official-prod', $1, 'test-pkg', 'test-pkg', '1.0.0', '1', 'pending', 'x86_64', '/tmp', 'mock', 'admin', $2, $3)",
        )
        .bind(product.id)
        .bind(admin.id)
        .bind(task_id)
        .execute(state.state_store.pool())
        .await
        .unwrap();

    // 验证 build 确实是 pending
    let phase: Option<String> =
        sqlx::query_scalar("SELECT phase FROM builds WHERE product_id = $1")
            .bind(product.id)
            .fetch_optional(state.state_store.pool())
            .await
            .unwrap();
    assert_eq!(phase.as_deref(), Some("pending"));

    // admin transfer 官方产品给 new-owner（自动变为 private，触发 cancel）
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/official-prod/transfer")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"new_owner_username": "new-owner", "expected_revision": 1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 断言 build 已被 cancel
    let phase2: Option<String> =
        sqlx::query_scalar("SELECT phase FROM builds WHERE product_id = $1")
            .bind(product.id)
            .fetch_one(state.state_store.pool())
            .await
            .unwrap();
    assert_eq!(phase2.as_deref(), Some("cancelled"));
}

// -------- ACL 边界测试 --------

/// grant 无效 role → 返回 400
#[tokio::test]
async fn acl_grant_invalid_role_returns_bad_request() {
    let (state, app, _tmp, tokens) = setup_app(
        &[("admin-token", "admin"), ("viewer-token", "viewer")],
        false,
    )
    .await;

    // admin 创建产品（admin 即 owner，拥有全部权限）
    let admin_id = user_id(&state, "admin-token").await;
    let _prod_id = seed_product(&state, "test-product", "private", Some(admin_id)).await;

    // 授予无效角色
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/test-product/acl")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"username": "viewer-token", "role": "superuser"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// owner 对自己的产品始终可见（可见性判定 owner 优先于 ACL，无需显式授权）
#[tokio::test]
async fn product_owner_can_see_own_product_regardless_of_acl() {
    let (state, app, _tmp, tokens) = setup_app(&[("owner-token", "builder")], false).await;
    let owner_user_id = user_id(&state, "owner-token").await;

    // 创建带 owner 的私有产品
    let _prod_id = seed_product(&state, "my-product", "private", Some(owner_user_id)).await;

    // owner 可见产品（无需显式 ACL）
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/products/my-product")
                .header("Authorization", format!("Bearer {}", tokens["owner-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
