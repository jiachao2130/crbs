// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! package 详情页 NVR 分组视图 / 尝试列表视图 + 可见性后过滤集成测试。

// 文件级放行：测试辅助函数（seed_* 等）不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::ProductConfig;
use crbs_core::{CreateProductInput, TaskInsert};
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;

mod common;

use common::body_text;
use common::setup_app;

// 公开访问默认开启（view=true），匿名可达 UI 页面。

async fn insert_task(state: &AppState, product: &str, pkg_name: &str, user: &str) -> i64 {
    state
        .state_store
        .insert_task(TaskInsert {
            product,
            pkg_name,
            user,
            phase: "failed",
            ..Default::default()
        })
        .await
        .unwrap()
}

/// 默认视图：同 NVR 的两次尝试 → 页面里该 NVR 只出现一次，Attempts=2。
#[tokio::test]
async fn package_detail_group_view_collapses_same_nvr() {
    let (state, app, _tmp) = setup_app().await;
    insert_task(&state, "mydist", "openssh-8.7p1-4.el9", "chao").await;
    insert_task(&state, "mydist", "openssh-8.7p1-4.el9", "chao").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/packages/openssh")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;

    assert!(
        html.contains("Versions"),
        "should render group view heading"
    );
    assert!(
        html.contains("<span class=\"count-chip\">1</span>"),
        "same NVR must collapse into one group, body: {html}"
    );
    assert!(html.contains("openssh-8.7p1-4.el9"));
    assert!(
        html.contains("<span class=\"count-badge\">2</span>"),
        "attempts count badge should show 2, body: {html}"
    );
}

/// `?nvr=` 视图：同 NVR 的两次尝试都列出，不同 NVR 被精确过滤排除。
#[tokio::test]
async fn package_detail_attempts_view_lists_all_attempts() {
    let (state, app, _tmp) = setup_app().await;
    let id1 = insert_task(&state, "mydist", "openssh-8.7p1-4.el9", "chao").await;
    let id2 = insert_task(&state, "mydist", "openssh-8.7p1-4.el9", "chao").await;
    insert_task(&state, "mydist", "openssh-8.7p1-3.el9", "chao").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/packages/openssh?nvr=openssh-8.7p1-4.el9")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;

    // 术语定则：此处的"尝试"实为任务（提交）列表，正名（key 名不动）。
    assert!(
        html.contains("Submissions (2)"),
        "should show 2 submissions"
    );
    assert!(html.contains(&format!("/ui/tasks/{}", id1)));
    assert!(html.contains(&format!("/ui/tasks/{}", id2)));
    assert!(!html.contains("openssh-8.7p1-3.el9"));
}

/// 极值 offset（> i64::MAX）两视图都必须钳到 MAX_LIST_OFFSET：不钳时
/// `offset as i64` 变负，SQLite 视作 0 渲染首页（PG 直接 500），钳后越界空页。
#[tokio::test]
async fn package_detail_extreme_offset_is_clamped() {
    let (state, app, _tmp) = setup_app().await;
    let id = insert_task(&state, "mydist", "openssh-8.7p1-4.el9", "chao").await;

    for (uri, nvr_view) in [
        ("/ui/packages/openssh?offset=9300000000000000000", false),
        (
            "/ui/packages/openssh?nvr=openssh-8.7p1-4.el9&offset=9300000000000000000",
            true,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "uri: {uri}");
        let html = body_text(response).await;
        assert!(
            !html.contains(&format!("/ui/tasks/{id}")),
            "clamped offset must yield an empty page, not offset-0 fallback: {html}"
        );
        if !nvr_view {
            // nvr 视图标题/页头恒回显参数 NVR，只有分组视图可用 NVR 串判行缺席。
            assert!(
                !html.contains("openssh-8.7p1-4.el9"),
                "group view must not fall back to offset 0: {html}"
            );
        }
    }
}

/// 匿名访问：私有产品的任务分组对匿名用户不可见（可见性后过滤生效）。
#[tokio::test]
async fn package_detail_group_view_hides_private_product_for_anon() {
    let (state, app, _tmp) = setup_app().await;

    // seed 一个 owner 用户拿 owner_id（私有产品 schema CHECK 要求非空 owner_id）。
    seed_user_token_for_test(&state.state_store, "owner", "builder")
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
            name: "secret",
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

    insert_task(&state, "secret", "hidden-1.0-1", "owner").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/packages/hidden")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;

    assert!(
        html.contains("No versions"),
        "private product group must be hidden from anonymous, body: {html}"
    );
    assert!(!html.contains("hidden-1.0-1"));
}

/// 跨 public/private 产品的 NVR：匿名按 attempt 维度（非 group 维度）看到 public
/// 部分的 attempts/latest；回归 `/ui/packages/tmux` 的 "No versions" bug。
#[tokio::test]
async fn package_detail_group_view_shows_latest_visible_attempt_for_mixed_visibility() {
    let (state, app, _tmp) = setup_app().await;

    // ule3 必须显式 seed 进 products 表（集成测试不调 bootstrap）：否则 ule3 attempts
    // 走"孤儿"路径、secret 又被可见性过滤 → visible_products 空，SQL 1=0 兜底，验不到 public 可见。
    state
        .state_store
        .create_product(CreateProductInput {
            name: "ule3",
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

    seed_user_token_for_test(&state.state_store, "owner", "builder")
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
            name: "secret",
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

    // 3 个 public attempts (ule3) + 1 个 private attempt (id 最大)；id4 用 succeeded
    // 相位让"latest 取最新可见 attempt"可观察：private 泄漏进聚合则 Latest 显示 succeeded。
    let _id1 = insert_task(&state, "ule3", "tmux-3.2a-3.oe2203sp4", "chao").await;
    let _id2 = insert_task(&state, "ule3", "tmux-3.2a-3.oe2203sp4", "chao").await;
    let _id3 = insert_task(&state, "ule3", "tmux-3.2a-3.oe2203sp4", "chao").await;
    let _id4 = state
        .state_store
        .insert_task(TaskInsert {
            product: "secret",
            pkg_name: "tmux-3.2a-3.oe2203sp4",
            user: "chao",
            phase: "succeeded",
            ..Default::default()
        })
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/packages/tmux")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;

    // 匿名：徽章只含 3 个 public attempts；latest = 最新可见 attempt（failed，非 id4 的 private succeeded），链接落回包维度。
    assert!(
        html.contains("<span class=\"count-chip\">1</span>"),
        "body: {html}"
    );
    assert!(html.contains("tmux-3.2a-3.oe2203sp4"));
    assert!(
        html.contains(r#"<span class="count-badge">3</span>"#),
        "attempts badge must count visible attempts only, body: {html}"
    );
    assert!(
        html.contains(r#"<a href="/ui/packages/tmux?nvr=tmux-3.2a-3.oe2203sp4">"#),
        "latest phase must link to the package's attempts view: {html}"
    );
    // 负断言打相位 pill：整页 contains("succeeded") 会命中内联 CSS 的 .phase-chip.succeeded。
    assert!(
        !html.contains(r#"<span class="status succeeded">"#),
        "private latest attempt must not be shown to anonymous, body: {html}"
    );
}

/// Package 列表的 name 子串过滤生效；无匹配空态；输入框回显当前值；空串视为未过滤。
#[tokio::test]
async fn package_list_filters_by_name_substring() {
    let (state, app, _tmp) = setup_app().await;
    insert_task(&state, "mydist", "hello-1.0-1", "chao").await;
    insert_task(&state, "mydist", "vim-2.0-1", "chao").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/packages?name=ell")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains("/ui/packages/hello"), "body: {html}");
    assert!(!html.contains("/ui/packages/vim"), "body: {html}");
    assert!(
        html.contains("name=\"name\" value=\"ell\""),
        "filter input should re-render the current value, body: {html}"
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/packages?name=nosuchpkg")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        html.contains("No packages found"),
        "no-match filter should show empty state, body: {html}"
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/packages?name=")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let html = body_text(response).await;
    assert!(html.contains("/ui/packages/hello"), "body: {html}");
    assert!(html.contains("/ui/packages/vim"), "body: {html}");
}

/// 过滤值在分页链接中保留（翻页不丢 name 参数）。
#[tokio::test]
async fn package_list_pagination_preserves_name_filter() {
    let (state, app, _tmp) = setup_app().await;
    insert_task(&state, "mydist", "hello-1.0-1", "chao").await;
    insert_task(&state, "mydist", "shell-2.0-1", "chao").await;
    insert_task(&state, "mydist", "libtool-3.0-1", "chao").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ui/packages?name=l&limit=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        html.contains(r#"<h1>Packages <span class="count-chip">3</span></h1>"#),
        "all three names contain 'l', body: {html}"
    );
    // Next 链接保留 name 过滤（maud 转义 & 为 &amp;）。
    assert!(
        html.contains("/ui/packages?name=l&amp;offset=2"),
        "pagination link must preserve the name filter, body: {html}"
    );
}
