// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 双保险网：UI 404/405 fallback 渲染带安全头的 HTML 错误页；非 UI（API）路径保持默认空 404。

// 文件级放行 unwrap/expect：seed_* 等测试辅助函数不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

mod common;

use common::body_text;
use common::setup_app;

// 公开访问默认开启（view=true），匿名可达 UI 页面。

/// 未匹配 /ui/*：HTML 404（标题+文案+导航）+ 与正常页一致的安全头（CSP nonce / nosniff），而非空体 404。
#[tokio::test]
async fn unknown_ui_path_renders_html_404_with_security_headers() {
    let (_state, app, _tmp) = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let csp = response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let csp = csp.unwrap_or_default();
    assert!(
        csp.contains("script-src 'self' 'nonce-"),
        "CSP must carry a script nonce, got: {csp}"
    );
    assert_eq!(
        response
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );

    let html = body_text(response).await;
    assert!(html.contains("<h1>404 Not Found</h1>"), "body: {html}");
    assert!(
        html.contains("The page you are looking for does not exist."),
        "body: {html}"
    );
    assert!(html.contains("← Back to dashboard"), "body: {html}");
}

/// UI 路由方法不符（/ui/tasks 仅注册 GET）：405 + HTML 错误页——router 级 fallback 不拦 405，method_not_allowed_fallback 兜住。
#[tokio::test]
async fn wrong_method_on_ui_route_renders_html_405() {
    let (_state, app, _tmp) = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/ui/tasks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    assert!(
        content_type
            .as_deref()
            .is_some_and(|ct| ct.starts_with("text/html")),
        "405 body must be HTML, got content-type: {content_type:?}"
    );

    let html = body_text(response).await;
    assert!(!html.is_empty(), "405 body must not be empty");
    assert!(html.contains("405"), "body: {html}");
    assert!(
        html.contains("<h1>405 Method Not Allowed</h1>"),
        "body: {html}"
    );
}

/// 非 UI 路径保持 axum 默认空 404：fallback 经 Router::merge 传遍整个 router，必须按路径分流、不改 API 契约。
#[tokio::test]
async fn unknown_api_path_keeps_plain_404() {
    let (_state, app, _tmp) = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let html = body_text(response).await;
    assert!(
        !html.contains("<h1>"),
        "non-UI paths must not get the HTML error page, body: {html}"
    );
}
