// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2/
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 全局搜索集成测试：nav 搜索框与 "/" 快捷键脚本渲染、task#/build# 直达（可见性不泄露）、产品/包名前缀区、空态、查询词转义。

// 测试 crate：seed_* 等辅助函数无 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use crbs_core::config::ProductConfig;
use crbs_core::{BuildInsert, CreateProductInput, TaskInsert};
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;
use tower::ServiceExt;

mod common;

use common::setup_app;

// 公开访问默认开启（view=true），匿名可达 UI 页面。

/// 多角色 fixture：bob=builder（私有产品 owner）、carol=viewer、op=operator；返回三个登录 token（crbs_token cookie 用）。
async fn seed_users(state: &AppState) -> (String, String, String) {
    let bob = seed_user_token_for_test(&state.state_store, "bob", "builder")
        .await
        .unwrap();
    let carol = seed_user_token_for_test(&state.state_store, "carol", "viewer")
        .await
        .unwrap();
    let op = seed_user_token_for_test(&state.state_store, "op", "operator")
        .await
        .unwrap();
    (bob, carol, op)
}

/// 最小合法根产品：base_packages + repos 非空，否则链出口校验不过 → `load_product_summaries` warn 跳过 → 产品区不出现。
fn root_config(name: &str) -> ProductConfig {
    ProductConfig::from_str(&format!(
        "product = \"{name}\"\nbase_packages = [\"bash\"]\n\n[[repos]]\nname = \"base\"\nbaseurl = \"http://mirror.example.com/{name}/base/$basearch\"\n"
    ))
    .expect("root product toml parses")
}

/// 公共根产品 mydist + 私有根产品 mypriv（owner=bob，共享 "my" 前缀，供产品前缀区可见性断言）。
async fn seed_products(state: &AppState) {
    state
        .state_store
        .create_product(CreateProductInput {
            name: "mydist",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &root_config("mydist"),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();
    let bob_id = state
        .state_store
        .find_user_by_name("bob")
        .await
        .unwrap()
        .unwrap()
        .id;
    state
        .state_store
        .create_product(CreateProductInput {
            name: "mypriv",
            display_name: None,
            owner_id: Some(bob_id),
            parent_id: None,
            visibility: "private",
            config: &root_config("mypriv"),
            changed_by_user_id: Some(bob_id),
            reason: Some("test seed"),
        })
        .await
        .unwrap();
}

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

async fn insert_build(state: &AppState, product: &str, pkg_name: &str, user: &str) -> i64 {
    // builds.task_id NOT NULL：先插本地任务行再挂 build。
    let task_id = crbs_server::test_support::seed_task(&state.state_store, product, pkg_name).await;
    state
        .state_store
        .insert_build(BuildInsert {
            product,
            pkg_name,
            phase: "succeeded",
            backend: "chroot",
            user,
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap()
}

async fn get_page(app: &axum::Router, token: Option<&str>, path: &str) -> String {
    let mut builder = Request::builder().uri(path);
    if let Some(token) = token {
        builder = builder.header("Cookie", format!("crbs_token={token}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "GET {path}");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// nav 搜索框（GET 表单 action=/ui/search）与 "/" 快捷键脚本在所有页面输出；语言 cookie 切换占位文案。
#[tokio::test]
async fn nav_search_form_and_shortcut_script_render() {
    let (_state, app, _tmp) = setup_app().await;
    let html = get_page(&app, None, "/ui/").await;
    assert!(
        html.contains(r#"<form class="nav-search" method="get" action="/ui/search">"#),
        "{html}"
    );
    assert!(
        html.contains(r#"input type="search" name="q" aria-label="Search…" placeholder="Search…""#),
        "{html}"
    );
    assert!(html.contains("__crbsSearchFocusBound"), "{html}");
    assert!(html.contains("keydown"), "{html}");
    assert!(html.contains(".nav-search input"), "{html}");

    let html = get_page(&app, None, "/ui/?lang=zh").await;
    assert!(html.contains(r#"placeholder="搜索…""#), "{html}");
}

/// task# 直达可见性：公共产品对 viewer 开放，私有仅 owner/operator；不可见与不存在同形态，整区不渲染不泄露存在性。
#[tokio::test]
async fn search_task_direct_hit_respects_visibility() {
    let (state, app, _tmp) = setup_app().await;
    let (bob, carol, op) = seed_users(&state).await;
    seed_products(&state).await;

    let public_task = insert_task(&state, "mydist", "openssh-8.7p1-4.el9", "bob").await;
    let private_task = insert_task(&state, "mypriv", "hidden-1.0-1", "bob").await;

    let html = get_page(&app, Some(&carol), &format!("/ui/search?q={public_task}")).await;
    assert!(
        html.contains(&format!(
            r#"<a href="/ui/tasks/{public_task}">Task #{public_task}</a>"#
        )),
        "{html}"
    );
    assert!(html.contains("Direct matches"), "{html}");

    let html = get_page(&app, Some(&carol), &format!("/ui/search?q={private_task}")).await;
    assert!(
        !html.contains(&format!("/ui/tasks/{private_task}")),
        "{html}"
    );
    assert!(!html.contains("Direct matches"), "{html}");

    let html = get_page(&app, Some(&bob), &format!("/ui/search?q={private_task}")).await;
    assert!(
        html.contains(&format!(r#"<a href="/ui/tasks/{private_task}">"#)),
        "{html}"
    );
    let html = get_page(&app, Some(&op), &format!("/ui/search?q={private_task}")).await;
    assert!(
        html.contains(&format!(r#"<a href="/ui/tasks/{private_task}">"#)),
        "{html}"
    );

    let html = get_page(&app, Some(&carol), "/ui/search?q=99999").await;
    assert!(!html.contains("Direct matches"), "{html}");
}

/// build# 直达：公共产品构建对 viewer 可见，链接旁带 NVR。
#[tokio::test]
async fn search_build_direct_hit_shows_nvr() {
    let (state, app, _tmp) = setup_app().await;
    let (_bob, carol, _op) = seed_users(&state).await;
    seed_products(&state).await;

    let build = insert_build(&state, "mydist", "vim-enhanced-9.1.0-4.el9", "bob").await;

    let html = get_page(&app, Some(&carol), &format!("/ui/search?q={build}")).await;
    assert!(
        html.contains(&format!(
            r#"<a href="/ui/builds/{build}">Build #{build}</a>"#
        )),
        "{html}"
    );
    assert!(html.contains("vim-enhanced-9.1.0-4.el9"), "{html}");
}

/// 产品前缀区：大小写不敏感前缀匹配；私有产品仅 owner 可见，匿名/非授权不见。
#[tokio::test]
async fn search_product_prefix_respects_visibility() {
    let (state, app, _tmp) = setup_app().await;
    let (bob, _carol, _op) = seed_users(&state).await;
    seed_products(&state).await;

    let html = get_page(&app, None, "/ui/search?q=my").await;
    assert!(
        html.contains(r#"<a href="/ui/products/mydist">mydist</a>"#),
        "{html}"
    );
    assert!(!html.contains("mypriv"), "{html}");

    let html = get_page(&app, None, "/ui/search?q=MY").await;
    assert!(html.contains(r#"/ui/products/mydist"#), "{html}");

    let html = get_page(&app, Some(&bob), "/ui/search?q=my").await;
    assert!(html.contains(r#"/ui/products/mydist"#), "{html}");
    assert!(html.contains(r#"/ui/products/mypriv"#), "{html}");
}

/// 包名前缀区：前缀（非子串）匹配，私有产品包名不外泄。
#[tokio::test]
async fn search_package_prefix_matches_and_hides_private() {
    let (state, app, _tmp) = setup_app().await;
    let (bob, carol, _op) = seed_users(&state).await;
    seed_products(&state).await;

    insert_task(&state, "mydist", "openssh-8.7p1-4.el9", "bob").await;
    insert_task(&state, "mydist", "openldap-2.6.1-1.el9", "bob").await;
    insert_task(&state, "mydist", "bash-5.2.26-3.el9", "bob").await;
    insert_task(&state, "mypriv", "hidden-1.0-1", "bob").await;

    let html = get_page(&app, Some(&carol), "/ui/search?q=open").await;
    assert!(
        html.contains(r#"<a href="/ui/packages?name=openssh">openssh</a>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<a href="/ui/packages?name=openldap">openldap</a>"#),
        "{html}"
    );
    assert!(!html.contains("?name=bash"), "{html}");

    // 私有包名匿名不可见、owner 可见；不能裸断言 "hidden"（内联 style.css 自带 overflow: hidden）。
    let html = get_page(&app, None, "/ui/search?q=hid").await;
    assert!(!html.contains("?name=hidden"), "{html}");
    assert!(!html.contains("hidden-1.0"), "{html}");
    let html = get_page(&app, Some(&bob), "/ui/search?q=hid").await;
    assert!(
        html.contains(r#"<a href="/ui/packages?name=hidden">hidden</a>"#),
        "{html}"
    );

    // 子串命中但前缀不命中：全区空 → 统一空态。
    let html = get_page(&app, Some(&carol), "/ui/search?q=ssh").await;
    assert!(!html.contains("?name=openssh"), "{html}");
    assert!(html.contains("No results"), "{html}");
}

/// 空 q：200 + 自动聚焦的页内搜索框 + 提示行（不重复 h1 标题，空态不带 empty-title）；有 q 回填不聚焦。
#[tokio::test]
async fn search_empty_query_renders_focused_form() {
    let (_state, app, _tmp) = setup_app().await;

    let html = get_page(&app, None, "/ui/search").await;
    assert!(
        html.contains(r#"<form class="search-box" method="get" action="/ui/search">"#),
        "{html}"
    );
    assert!(html.contains("autofocus"), "{html}");
    assert!(html.contains("press Enter"), "{html}");
    assert!(!html.contains("No results"), "{html}");
    assert_eq!(html.matches("<h1>").count(), 1, "{html}");
    assert!(
        !html.contains(r#"<div class="empty-title">Search</div>"#),
        "{html}"
    );

    let html = get_page(&app, None, "/ui/search?q=abc").await;
    assert!(
        html.contains(r#"value="abc""#) && !html.contains("autofocus"),
        "{html}"
    );
}

/// 查询词 HTML 转义（maud 自动转义的回归钉子）：h1 与输入框均不出原始标签。
#[tokio::test]
async fn search_query_is_html_escaped() {
    let (_state, app, _tmp) = setup_app().await;
    let html = get_page(
        &app,
        None,
        "/ui/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    )
    .await;
    assert!(html.contains("Search: &lt;script&gt;"), "{html}");
    assert!(!html.contains("<script>alert"), "{html}");
}
