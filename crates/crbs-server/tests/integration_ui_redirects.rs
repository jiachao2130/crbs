// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of this software at
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! UI 未登录门控契约（表驱动收敛）：匿名 GET（页面/SSE）统一 401；UI POST 端点在 CSRF 校验前 403。
//! 路由存在性与 Public/Role 门控分类属另一层面，由 integration_route_inventory.rs 钉住，互不替代。

// 测试辅助函数（seed_* 等）不带 #[test]，clippy 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::{PublicAccessConfig, ServerConfig};
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::state::AppState;

/// 匿名门控的开关形态：对应公开访问三元组的哪一项被关闭（或全默认）。
#[derive(Clone, Copy)]
enum Gate {
    /// `public_access.view = false`：浏览类页面/SSE 全部要求认证。
    ViewDisabled,
    /// `public_access.logs = false`：日志页/日志流要求认证。
    LogsDisabled,
    /// 默认全开：页面本身仍受会话/角色门（/ui/me、/ui/tasks/new、admin 页）。
    Default,
}

impl Gate {
    fn public_access(self) -> PublicAccessConfig {
        match self {
            Gate::ViewDisabled => PublicAccessConfig {
                view: false,
                logs: true,
                download: true,
            },
            Gate::LogsDisabled => PublicAccessConfig {
                view: true,
                logs: false,
                download: true,
            },
            Gate::Default => PublicAccessConfig::default(),
        }
    }
}

/// 一行 = 一个受保护 UI 路径的匿名门控契约。
struct Row {
    desc: &'static str,
    /// `{id}` 占位符在 needs_build 时替换为真实 build id。
    path: &'static str,
    needs_build: bool,
    gate: Gate,
    /// 额外断言 401 HTML 错误页带 login CTA 且含该 urlencoded `next=` 回跳串；SSE 行不断言。
    login_cta_html: Option<&'static str>,
}

#[tokio::test]
async fn ui_protected_paths_anonymous_gate_contract() {
    let rows = [
        Row { desc: "dashboard requires auth when view disabled (ui_dashboard_requires_auth_when_view_disabled)", path: "/ui/", needs_build: false, gate: Gate::ViewDisabled, login_cta_html: None },
        Row { desc: "builds requires auth when view disabled (ui_builds_requires_auth_when_view_disabled)", path: "/ui/builds", needs_build: false, gate: Gate::ViewDisabled, login_cta_html: None },
        Row { desc: "build detail requires auth when view disabled (ui_build_detail_requires_auth_when_view_disabled)", path: "/ui/builds/{id}", needs_build: true, gate: Gate::ViewDisabled, login_cta_html: None },
        Row { desc: "tasks requires auth when view disabled (ui_tasks_requires_auth_when_view_disabled)", path: "/ui/tasks", needs_build: false, gate: Gate::ViewDisabled, login_cta_html: None },
        Row { desc: "products requires auth when view disabled (ui_products_requires_auth_when_view_disabled)", path: "/ui/products", needs_build: false, gate: Gate::ViewDisabled, login_cta_html: None },
        Row { desc: "build SSE requires auth when view disabled (ui_build_sse_requires_auth_when_view_disabled)", path: "/ui/builds/{id}/events", needs_build: true, gate: Gate::ViewDisabled, login_cta_html: None },
        Row { desc: "dashboard SSE requires auth when view disabled (ui_dashboard_sse_requires_auth_when_view_disabled)", path: "/ui/events", needs_build: false, gate: Gate::ViewDisabled, login_cta_html: None },
        Row { desc: "logs requires auth when logs disabled (ui_logs_requires_auth_when_logs_disabled)", path: "/ui/builds/{id}/logs", needs_build: true, gate: Gate::LogsDisabled, login_cta_html: None },
        Row { desc: "log SSE requires auth when logs disabled (ui_log_sse_requires_auth_when_logs_disabled)", path: "/ui/builds/{id}/logs/stream", needs_build: true, gate: Gate::LogsDisabled, login_cta_html: None },
        Row { desc: "task new page denies anonymous (anonymous_get_returns_401)", path: "/ui/tasks/new", needs_build: false, gate: Gate::Default, login_cta_html: None },
        Row { desc: "me page denies anonymous (me_page ... denies_anonymous 段)", path: "/ui/me", needs_build: false, gate: Gate::Default, login_cta_html: None },
        Row { desc: "admin page 401 HTML with login CTA + next (unauthorized_ui_page_renders_login_cta_with_next)", path: "/ui/admin/users?name=x", needs_build: false, gate: Gate::Default, login_cta_html: Some("/ui/login?next=%2Fui%2Fadmin%2Fusers%3Fname%3Dx") },
    ];

    for row in rows {
        let (state, app, tmp) = setup_app(row.gate).await;
        let path = if row.needs_build {
            let id = insert_build_with_artifact(&state, tmp.path()).await;
            row.path.replace("{id}", &id.to_string())
        } else {
            row.path.to_string()
        };

        let response = app
            .oneshot(Request::builder().uri(&path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "row `{}`: anonymous GET {path} must be gated",
            row.desc
        );

        if let Some(expected_cta) = row.login_cta_html {
            let content_type = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            assert!(
                content_type
                    .as_deref()
                    .is_some_and(|ct| ct.starts_with("text/html")),
                "row `{}`: 401 must be rewritten to HTML, got {content_type:?}",
                row.desc
            );
            let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let html = String::from_utf8_lossy(&bytes).into_owned();
            assert!(
                html.contains("Login to continue"),
                "row `{}`: {html}",
                row.desc
            );
            assert!(
                html.contains(expected_cta),
                "row `{}`: CTA next must carry path+query (urlencoded): {html}",
                row.desc
            );
        }
    }
}

/// UI POST 端点匿名语义：auth 中间件在 CSRF 校验前拒绝 → 403（与其它 UI POST 端点一致）。
#[tokio::test]
async fn ui_post_without_session_rejected_before_csrf() {
    let (_state, app, _tmp) = setup_app(Gate::Default).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/gc")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", "crbs_token=no-such-token")
                .body(Body::from("csrf_token=whatever&dry_run=true"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

async fn setup_app(gate: Gate) -> (Arc<AppState>, axum::Router, tempfile::TempDir) {
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        state_store,
        ServerConfig {
            public_access: gate.public_access(),
            ..ServerConfig::default()
        },
        tmp_dir.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    (app_state, app, tmp_dir)
}

/// 详情/日志行需要真实存在的 build id：门控在中间件层先于 handler 触发，行存在性同时钉住"先门控后判存在"。
async fn insert_build_with_artifact(state: &AppState, tmp_dir: &std::path::Path) -> i64 {
    let result_dir = tmp_dir.join("results").join("alice").join("pkg").join("1");
    tokio::fs::create_dir_all(&result_dir).await.unwrap();
    tokio::fs::write(result_dir.join("hello.rpm"), b"dummy rpm")
        .await
        .unwrap();

    let result_dir_str = result_dir.to_string_lossy().to_string();

    state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg",
            phase: "succeeded",
            result_dir: Some(&result_dir_str),
            backend: "chroot",
            user: "alice",
            arch: Some("x86_64"),
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", "pkg").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap()
}
