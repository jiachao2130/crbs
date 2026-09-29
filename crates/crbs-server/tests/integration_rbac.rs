// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

// 整个文件是测试 crate：测试辅助函数（seed_* 等）不带 #[test] 属性，
// clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::ServerConfig;
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;

mod common;

/// 创建带认证的测试 App，按 `roles` 在 DB 中创建用户+token，返回 name→原始 token 映射。
async fn setup_app_with_auth(
    roles: &[(&str, &str)],
) -> (
    Arc<AppState>,
    axum::Router,
    tempfile::TempDir,
    std::collections::HashMap<String, String>,
) {
    setup_app_with_auth_config(roles, ServerConfig::default()).await
}

/// 同 [`setup_app_with_auth`]，但允许注入自定义 [`ServerConfig`]。
async fn setup_app_with_auth_config(
    roles: &[(&str, &str)],
    server_config: ServerConfig,
) -> (
    Arc<AppState>,
    axum::Router,
    tempfile::TempDir,
    std::collections::HashMap<String, String>,
) {
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
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

// -------------- viewer 不能提交构建 --------------

#[tokio::test]
async fn viewer_cannot_submit_build() {
    let (_state, app, _tmp, tokens) = setup_app_with_auth(&[("viewer-token", "viewer")]).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/builds")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["viewer-token"]),
                )
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"product":"test","srpms":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// -------------- builder 可以提交构建 --------------

#[tokio::test]
async fn builder_can_submit_build() {
    let (_state, app, _tmp, tokens) = setup_app_with_auth(&[("builder-token", "builder")]).await;

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
                .body(Body::from(r#"{"product":"test","srpms":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    // builder 角色权限通过（非 403），请求因 srpms 为空被参数校验拒绝 → 400。
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "validation_failed");
    assert!(
        json["message"]
            .as_str()
            .unwrap_or_default()
            .contains("at least one SRPM is required"),
        "unexpected validation message: {}",
        json["message"]
    );
}

// -------------- enqueue: SRPM 路径必须位于 upload 目录内 --------------

#[tokio::test]
async fn enqueue_rejects_srpm_outside_upload_dir() {
    let (_state, app, tmp, tokens) = setup_app_with_auth(&[("builder-token", "builder")]).await;

    // 在 upload_dir 外放一个 .src.rpm
    let outside_srpm = tmp.path().join("outside.src.rpm");
    std::fs::File::create(&outside_srpm).unwrap();

    let body = serde_json::json!({
        "product": "fedora",
        "srpms": [outside_srpm.to_str().unwrap()],
    })
    .to_string();

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
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -------------- list_builds: 产品可见性为唯一读边界，可见产品内不分提交者 --------------

#[tokio::test]
async fn list_builds_builder_sees_all_within_visible_products() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("builder-token", "builder")]).await;

    // 插入两条记录，一条是 builder 的，一条是别人的；产品无 products 行（孤儿豁免），
    // 登录 builder 须与 operator 同权看到两条。
    state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg1",
            backend: "chroot",
            user: "builder-token",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg1").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg2",
            backend: "chroot",
            user: "other-user",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg2").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/builds")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
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
    let builds = json["builds"].as_array().unwrap();
    assert_eq!(
        builds.len(),
        2,
        "visible-product builds must not be narrowed by submitter"
    );
}

// -------------- list_builds: operator 看全部 --------------

#[tokio::test]
async fn list_builds_operator_sees_all() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("op-token", "operator")]).await;

    state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg1",
            backend: "chroot",
            user: "user-a",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg1").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg2",
            backend: "chroot",
            user: "user-b",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg2").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/builds")
                .header("Authorization", format!("Bearer {}", tokens["op-token"]))
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
    assert_eq!(json["total"], 2);
}

// -------------- cancel_build: builder 不能取消别人的 --------------

#[tokio::test]
async fn cancel_build_non_owner_rejected() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("builder-token", "builder")]).await;

    let id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg1",
            backend: "chroot",
            user: "other-user",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg1").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/cancel", id))
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// -------------- cancel_build: builder 可以取消自己的 --------------

#[tokio::test]
async fn cancel_build_owner_allowed() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("builder-token", "builder")]).await;

    let id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg1",
            backend: "chroot",
            user: "builder-token",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg1").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/cancel", id))
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // pending 构建可被 owner 取消：软取消成功 → 202，DB phase 翻 cancelled。
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let record = state.state_store.get_build(id).await.unwrap().unwrap();
    assert_eq!(record.phase, "cancelled");
}

// -------------- cancel_build: operator 可以取消任何人的 --------------

#[tokio::test]
async fn cancel_build_operator_allowed() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("op-token", "operator")]).await;

    let id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg1",
            backend: "chroot",
            user: "any-user",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg1").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/cancel", id))
                .header("Authorization", format!("Bearer {}", tokens["op-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // operator 可取消任何人的 pending 构建：202，DB phase 翻 cancelled。
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let record = state.state_store.get_build(id).await.unwrap().unwrap();
    assert_eq!(record.phase, "cancelled");
}

// -------------- update_priority: operator 放行，builder 被拒 --------------

#[tokio::test]
async fn update_priority_operator_allowed_builder_rejected() {
    let (state, app, _tmp, tokens) =
        setup_app_with_auth(&[("builder-token", "builder"), ("op-token", "operator")]).await;

    let id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg1",
            backend: "chroot",
            user: "any",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg1").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    // operator 及以上可改优先级（can_priority = is_operator）；critical=2。
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/builds/{}/priority", id))
                .header("Authorization", format!("Bearer {}", tokens["op-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"priority":2}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // operator 以下（builder）仍 403，即便申请 critical。
    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/builds/{}/priority", id))
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"priority":2}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// -------------- update_priority: admin 允许 --------------

#[tokio::test]
async fn update_priority_admin_allowed() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    let id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg1",
            backend: "chroot",
            user: "any",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg1").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/builds/{}/priority", id))
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"priority":1}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// -------------- gc: builder 被拒（gate = operator+，admin 同过）--------------

#[tokio::test]
async fn gc_non_operator_rejected() {
    let (_state, app, _tmp, tokens) = setup_app_with_auth(&[("builder-token", "builder")]).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/gc")
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"dry_run":true,"results":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// -------------- gc: operator 允许 --------------

#[tokio::test]
async fn gc_operator_allowed() {
    let (_state, app, _tmp, tokens) = setup_app_with_auth(&[("op-token", "operator")]).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/gc")
                .header("Authorization", format!("Bearer {}", tokens["op-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"dry_run":true,"results":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

// -------------- product init: 非 admin 被拒绝 --------------

#[tokio::test]
async fn product_init_non_admin_rejected() {
    let (_state, app, _tmp, tokens) = setup_app_with_auth(&[("op-token", "operator")]).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/test/init")
                .header("Authorization", format!("Bearer {}", tokens["op-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"force":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// -------------- product init: admin 过 RBAC，但 product_management 默认关闭仍拒 403 --------------

#[tokio::test]
async fn product_init_admin_allowed_or_disabled() {
    let (_state, app, _tmp, tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/test/init")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"force":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    // admin 权限检查（can_manage_product）通过；但 allow_product_management
    // 默认关闭，check_product_management 拒绝 → 403，且错误语义明确。
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "permission_denied");
    assert_eq!(json["message"], "product management is disabled");
}

/// allowed 分支：`allow_product_management=true` 时 admin init 放行。
/// 真实语义分两跳：首次调用生成产品配置模板并以 400 提示"编辑后再试"，
/// 模板就位后的第二次调用 → 202 ACCEPTED（异步 init task）。
#[tokio::test]
async fn product_init_admin_accepted_when_management_enabled() {
    // ensure_product_config_ready 会向配置目录写模板：指向共享 tempdir，
    // 避免非 root 环境写 /etc/crbs 失败把响应变成 500。
    let _ = common::TEST_CONFIG_DIR.path();
    let server_config = ServerConfig {
        allow_product_management: true,
        ..ServerConfig::default()
    };
    // TempDir 必须存活到测试结束（state DB 位于其下）。
    let (_state, app, _tmp, tokens) =
        setup_app_with_auth_config(&[("admin-token", "admin")], server_config).await;

    // 首次：生成模板 → 400，错误信息指向刚生成的模板路径。
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/init-allowed-prod/init")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"force":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["message"]
            .as_str()
            .unwrap_or_default()
            .contains("template generated"),
        "unexpected message: {}",
        json["message"]
    );

    // 模板已就位：再次 init → 202。
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/init-allowed-prod/init")
                .header("Authorization", format!("Bearer {}", tokens["admin-token"]))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"force":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

// -------------- product clean: 非 admin 被拒绝 --------------

#[tokio::test]
async fn product_clean_non_admin_rejected() {
    let (_state, app, _tmp, tokens) = setup_app_with_auth(&[("op-token", "operator")]).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/products/test/clean")
                .header("Authorization", format!("Bearer {}", tokens["op-token"]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// -------------- artifacts: 无认证可以访问（公开端点）--------------

#[tokio::test]
async fn artifacts_download_no_auth() {
    // 不需要 auth 中间件
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    let server_config = ServerConfig::default();
    let app_state = Arc::new(AppState::for_test(
        state_store,
        server_config,
        tmp_dir.path().to_path_buf(),
    ));
    let app = crbs_server::server::create_test_app(app_state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/builds/999999/artifacts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // 404 因为没有这个 build（认证不是必须的——未返回 401）
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// -------------- 未认证请求被拒绝 --------------

#[tokio::test]
async fn unauthenticated_request_rejected() {
    let (_state, app, _tmp, _tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/builds")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// -------------- 无效 token 被拒绝 --------------

#[tokio::test]
async fn invalid_token_rejected() {
    let (_state, app, _tmp, _tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/builds")
                .header("Authorization", "Bearer wrong-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// -------------- health 端点始终公开 --------------

#[tokio::test]
async fn health_endpoint_public() {
    let (_state, app, _tmp, _tokens) = setup_app_with_auth(&[("admin-token", "admin")]).await;

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
}

// -------------- get_build: 产品可见性为唯一读边界 --------------

#[tokio::test]
async fn get_build_builder_view_own() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("builder-token", "builder")]).await;

    let id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg1",
            backend: "chroot",
            user: "builder-token",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg1").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/builds/{}", id))
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// 登录 builder 可见 public/孤儿产品上他人提交的构建（可见即见全部，不分提交者）。
#[tokio::test]
async fn get_build_builder_views_others_on_orphan_product() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("builder-token", "builder")]).await;

    let id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg1",
            backend: "chroot",
            user: "other-user",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg1").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/builds/{}", id))
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "builder must see other users' builds on visible products"
    );
}

/// private 产品无 ACL 的 builder 详情 403（产品级判定独立把门，与提交者无关）。
#[tokio::test]
async fn get_build_builder_forbidden_on_private_product_without_acl() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("builder-token", "builder")]).await;

    let owner_id = state
        .state_store
        .create_user("secret-owner", "builder")
        .await
        .unwrap();
    state
        .state_store
        .create_product(crbs_core::CreateProductInput {
            name: "secret-product",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: "private",
            config: &crbs_core::config::ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("rbac visibility test"),
        })
        .await
        .unwrap();

    let id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "secret-product",
            pkg_name: "pkg1",
            backend: "chroot",
            user: "secret-owner",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "secret-product", "pkg1")
                    .await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/builds/{}", id))
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "private product without ACL must stay hidden from builder"
    );
}

/// private 产品持 ACL 的 builder 可见该产品全部构建（含他人提交的）。
#[tokio::test]
async fn get_build_builder_with_acl_views_private_product_others_builds() {
    let (state, app, _tmp, tokens) =
        setup_app_with_auth(&[("builder-token", "builder"), ("peer", "operator")]).await;

    let builder_id = state
        .state_store
        .find_user_by_name("builder-token")
        .await
        .unwrap()
        .unwrap()
        .id;
    // owner 用独立用户，避免 owner bypass 盖过 ACL 路径。
    let owner_id = state
        .state_store
        .create_user("priv-owner", "builder")
        .await
        .unwrap();
    state
        .state_store
        .create_product(crbs_core::CreateProductInput {
            name: "acl-product",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: "private",
            config: &crbs_core::config::ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("rbac visibility test"),
        })
        .await
        .unwrap();
    state
        .state_store
        .grant_product_acl(builder_id, "acl-product")
        .await
        .unwrap();

    // operator 提交的构建：ACL 持有者不分提交者全可见。
    let id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "acl-product",
            pkg_name: "pkg1",
            backend: "chroot",
            user: "peer",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "acl-product", "pkg1")
                    .await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/builds/{}", id))
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "ACL grantee must see all builds (any submitter) on the private product"
    );
}

// -------------- diff_build: builder 的 diff 范围受 compute_diff user_filter 功能约束 --------------

/// 可见性前置（fetch_build_with_rpms）对孤儿产品放行后，builder diff 他人构建
/// 落 compute_diff 的 user_filter（diff 的功能参数）：resolve 不到 → 404。
#[tokio::test]
async fn diff_build_builder_cannot_view_others() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("builder-token", "builder")]).await;

    let id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg1",
            phase: "succeeded",
            backend: "chroot",
            user: "other-user",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg1").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/builds/{}/diff?against=1", id))
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "orphan-product left side passes the product gate; the 404 comes from \
         compute_diff's user_filter (functional diff scope)"
    );
}

#[tokio::test]
async fn diff_build_builder_cannot_diff_against_others() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("builder-token", "builder")]).await;

    let own_id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "own-pkg",
            phase: "succeeded",
            backend: "chroot",
            user: "builder-token",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "own-pkg").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let other_id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "other-pkg",
            phase: "succeeded",
            backend: "chroot",
            user: "other-user",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "other-pkg")
                    .await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/builds/{}/diff?against={}",
                    own_id, other_id
                ))
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // 左构建是自己的，against 构建是别人的：产品级前置已放行（孤儿产品），
    // 404 来自 compute_diff user_filter（diff 的功能参数，builder 只 diff
    // 自己的构建）对右侧的 resolve 过滤。
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// diff 的 against（右侧）构建同样受产品可见性约束。
///
/// viewer 的 diff user_filter 为 None，compute_diff 内部只有 user_filter
/// 判定、无产品可见性检查（空串 user 连该判定也绕过）——缺 against 侧
/// 前置检查时 viewer 可 diff 私有产品下的构建。故 handler 对 against
/// 侧先走 fetch_build_with_rpms 全套检查（404 / 产品可见性）。
#[tokio::test]
async fn diff_build_viewer_cannot_diff_against_private_product_build() {
    let (state, app, tmp, tokens) = setup_app_with_auth(&[("viewer-token", "viewer")]).await;

    // 官方 public 产品入 DB：compute_diff 的 chain-resolve 按名查产品，
    // 缺行会 404；且配置必须过 chain 校验（默认 ProductConfig 的
    // base_packages 为空会被 resolve 拒绝），照抄 by-sha256 测试的最小
    // 合法 toml。
    let fedora_toml = "\
base_packages = [\"bash\", \"rpm-build\"]\n\
arches = [\"x86_64\"]\n\
\n\
[[repos]]\n\
name = \"base\"\n\
baseurl = \"http://example.com/base/$basearch\"\n\
gpgcheck = false\n";
    let fedora_config = crbs_core::config::ProductConfig::from_str(fedora_toml).unwrap();
    state
        .state_store
        .create_product(crbs_core::CreateProductInput {
            name: "fedora",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &fedora_config,
            changed_by_user_id: None,
            reason: Some("diff visibility test"),
        })
        .await
        .unwrap();

    // 左侧 + 对照右侧：public 产品下、结果目录真实落盘（result root =
    // {crbs_root}/results，AppState::for_test 默认派生）。
    let result_root = tmp.path().join("results");
    let mk_visible_build = |pkg: &'static str, sub: &'static str| {
        let state = state.clone();
        let dir = result_root.join(sub);
        async move {
            tokio::fs::create_dir_all(&dir).await.unwrap();
            let dir_str = dir.to_string_lossy().to_string();
            state
                .state_store
                .insert_build(crbs_core::BuildInsert {
                    product: "fedora",
                    pkg_name: pkg,
                    phase: "succeeded",
                    result_dir: Some(&dir_str),
                    backend: "chroot",
                    user: "",
                    task_id: Some(
                        crbs_server::test_support::seed_task(&state.state_store, "fedora", pkg)
                            .await,
                    ),
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };
    let left_id = mk_visible_build("left-pkg", "diff-left").await;
    let visible_against_id = mk_visible_build("right-pkg", "diff-right").await;

    // 私有产品 + 其下 user 为空串的构建：产品级检查独立把门，
    // 提交者身份不参与——产品可见性单独把门。
    let owner_id = state
        .state_store
        .create_user("secret-owner", "builder")
        .await
        .unwrap();
    state
        .state_store
        .create_product(crbs_core::CreateProductInput {
            name: "secret-product",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: "private",
            config: &crbs_core::config::ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("diff visibility test"),
        })
        .await
        .unwrap();
    let private_id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "secret-product",
            pkg_name: "secret-pkg",
            phase: "succeeded",
            backend: "chroot",
            user: "",
            task_id: Some(
                crbs_server::test_support::seed_task(
                    &state.state_store,
                    "secret-product",
                    "secret-pkg",
                )
                .await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let get = |against: i64| {
        let app = app.clone();
        let token = tokens["viewer-token"].clone();
        async move {
            app.oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/builds/{}/diff?against={}",
                        left_id, against
                    ))
                    .header("Authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };

    // against 私有产品构建 → 403（产品可见性在 compute_diff 前拦下）。
    assert_eq!(
        get(private_id).await.status(),
        StatusCode::FORBIDDEN,
        "viewer must not diff against a private-product build"
    );

    // 对照：against 可见构建 → 200。
    assert_eq!(
        get(visible_against_id).await.status(),
        StatusCode::OK,
        "diff against a visible build must keep working"
    );
}

// -------------- list_artifacts: 产品可见性为唯一读边界 --------------

/// 登录 builder 可列孤儿产品上他人提交的构建的产物清单（可见即见全部）。
#[tokio::test]
async fn list_artifacts_builder_lists_others_on_orphan_product() {
    let (state, app, _tmp, tokens) = setup_app_with_auth(&[("builder-token", "builder")]).await;

    let id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg1",
            phase: "succeeded",
            backend: "chroot",
            user: "other-user",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg1").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/builds/{}/artifacts", id))
                .header(
                    "Authorization",
                    format!("Bearer {}", tokens["builder-token"]),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "builder must list artifacts of other users' builds on visible products"
    );
}

/// 安全测试：私人产品的产物 SHA256 指纹被无权限用户反查时，结果必须为空。
///
/// 验证点：by-sha256 端点必须使用 products 表的 live visibility 数据（不是冻结列），
/// 且逐行静默过滤，不泄漏"存在但你不能看"。
#[tokio::test]
async fn by_sha256_fingerprint_private_product_artifact_returns_empty_for_anonymous() {
    let (state, app, _tmp, _tokens) = setup_app_with_auth(&[]).await;

    // 0. 先创建 owner 用户（FK 约束需要）
    let owner_id = state
        .state_store
        .create_user("test-owner", "builder")
        .await
        .unwrap();

    // 1. 创建私人产品（visibility = private）
    let toml_body = "\
base_packages = [\"bash\", \"rpm-build\"]\n\
arches = [\"x86_64\"]\n\
\n\
[[repos]]\n\
name = \"base\"\n\
baseurl = \"http://example.com/base/$basearch\"\n\
gpgcheck = false\n";
    let config = crbs_core::config::ProductConfig::from_str(toml_body).unwrap();
    state
        .state_store
        .create_product(crbs_core::CreateProductInput {
            name: "private-package",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: "private",
            config: &config,
            changed_by_user_id: None,
            reason: Some("security test"),
        })
        .await
        .unwrap();

    // 2. 插入该产品下的构建 + 产物
    let build_id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "private-package",
            pkg_name: "secret-pkg",
            phase: "succeeded",
            backend: "chroot",
            user: "owner",
            user_id: Some(owner_id),
            task_id: Some(
                crbs_server::test_support::seed_task(
                    &state.state_store,
                    "private-package",
                    "secret-pkg",
                )
                .await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    // 插入一条 artifact（有已知 SHA256）
    let artifact_sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let mut tx = state.state_store.pool().begin().await.unwrap();
    state
        .state_store
        .insert_artifacts_tx(
            &mut tx,
            build_id,
            &[crbs_core::NewArtifact {
                relative_path: "secret.rpm".into(),
                kind: crbs_core::ArtifactKind::Rpm,
                size_bytes: 1024,
                sha256: artifact_sha.into(),
                unsigned_sha256: None,
                arch: Some("x86_64".into()),
                name: Some("secret-pkg".into()),
                version: Some("1.0".into()),
                release: Some("1".into()),
                epoch: None,
                metadata_json: None,
                signed: false,
            }],
            "2026-01-01 00:00:00",
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // 3. 另一个用户（非 owner）用这个 SHA 反查 —— 必须返回空，不能泄漏私人产品的存在
    let other_token = seed_user_token_for_test(&state.state_store, "other-user", "builder")
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/builds/artifacts/by-sha256/{}",
                    artifact_sha
                ))
                .header("Authorization", format!("Bearer {}", other_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // 必须 200 OK（不能 403，403 会泄漏"存在但你不能看"）
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 0, "private artifact leaked via fingerprint!");
    assert_eq!(json["matches"].as_array().unwrap().len(), 0);
}
