// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org/MulanPSL2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 一致性打磨集成测试：page-head、back 透传白名单、nav aria-current/⚙/用户名、
//! packages 新列、audit Target 映射与空态、401 `?next=` 回跳、phase 过滤白名单、空态 aria。

// 测试 crate：seed_* 等辅助函数无 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use crbs_core::{BuildInsert, TaskInsert};
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;
use tower::ServiceExt;

mod common;

use common::setup_app_with_admin;

async fn get_page(app: &axum::Router, token: &str, path: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("Cookie", format!("crbs_token={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// `builds.task_id` NOT NULL：先插本地任务再挂 build；详情页类测试统一走此 helper。
async fn insert_task_build(state: &AppState, pkg: &'static str, phase: &'static str) -> i64 {
    let task = crbs_server::test_support::seed_task(&state.state_store, "mydist", pkg).await;
    state
        .state_store
        .insert_build(BuildInsert {
            task_id: Some(task),
            ..sample_build(pkg, phase)
        })
        .await
        .unwrap()
}

fn sample_build(pkg: &'static str, phase: &'static str) -> BuildInsert<'static> {
    BuildInsert {
        product: "mydist",
        pkg_name: pkg,
        phase,
        backend: "chroot",
        user: "ui-tester",
        arch: Some("x86_64"),
        ..Default::default()
    }
}

// --- 1. 详情页 page-head：主操作进标题行右上 ---

/// build 详情：cancel 表单与 View logs 位于 page-head 的 header-actions，dl 后无重复按钮。
#[tokio::test]
async fn build_detail_page_head_moves_cancel_and_logs_into_header() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let build = insert_task_build(&state, "head-pkg-1.0-1.fc42", "building").await;

    let html = get_page(&app, &admin_token, &format!("/ui/builds/{build}")).await;
    assert!(html.contains(r#"<div class="page-head">"#), "{html}");
    assert!(
        html.contains("<h1>Build #"),
        "h1 must stay in page-head: {html}"
    );
    let head_at = html.find(r#"<div class="page-head">"#).expect("page-head");
    let actions_at = html
        .find(r#"<div class="header-actions">"#)
        .expect("actions");
    assert!(actions_at > head_at, "actions must follow the h1: {html}");
    let dl_at = html.find(r#"<dl class="side-kv">"#).expect("side-kv");
    assert!(
        actions_at < dl_at,
        "actions must precede the side-kv: {html}"
    );
    assert!(
        html.contains(&format!(r#"action="/ui/builds/{build}""#)),
        "cancel form must live in header-actions: {html}"
    );
    assert!(
        html.contains(&format!(r#"href="/ui/builds/{build}/logs""#)),
        "View logs link must be in header-actions: {html}"
    );
    // 唯一 action-form（nav-logout 表单不计）。
    assert_eq!(
        html.matches(r#"class="action-form""#).count(),
        1,
        "cancel form must not be duplicated below the dl: {html}"
    );
    // phase 徽章容器 = live region（SSE 改写目标）。
    assert!(
        html.contains(r#"<span aria-live="polite">"#),
        "phase wrapper must be a live region: {html}"
    );
}

/// task 详情：cancel/rebuild 进 header-actions；子构建 cell 是 live region 且带 back=当前 task URL。
#[tokio::test]
async fn task_detail_page_head_moves_actions_and_child_links_carry_back() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let task = state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name: "thead-pkg-1.0-1.fc42",
            user: "ui-tester",
            phase: "building",
            ..Default::default()
        })
        .await
        .unwrap();
    let child = state
        .state_store
        .insert_build(BuildInsert {
            task_id: Some(task),
            ..sample_build("thead-pkg-1.0-1.fc42", "building")
        })
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, &format!("/ui/tasks/{task}")).await;
    assert!(html.contains(r#"<div class="page-head">"#), "{html}");
    let actions_at = html
        .find(r#"<div class="header-actions">"#)
        .expect("actions");
    let dl_at = html.find(r#"<dl class="side-kv">"#).expect("side-kv");
    assert!(
        actions_at < dl_at,
        "actions must precede the side-kv: {html}"
    );
    assert!(
        html.contains(&format!(r#"action="/ui/tasks/{task}""#)),
        "cancel form missing: {html}"
    );
    assert!(
        html.contains(&format!(r#"action="/ui/tasks/{task}/rebuild""#)),
        "rebuild form missing: {html}"
    );
    assert_eq!(
        html.matches(r#"class="action-form""#).count(),
        2,
        "exactly cancel+rebuild forms, no duplicates: {html}"
    );
    // phase 徽章容器 = live region（SSE 改写目标）。
    assert!(
        html.contains(r#"<span aria-live="polite">"#),
        "phase wrapper must be a live region: {html}"
    );
    assert!(
        html.contains(&format!(
            r#"href="/ui/builds/{child}?back=%2Fui%2Ftasks%2F{task}""#
        )),
        "child build link must carry back to the task page: {html}"
    );
    assert!(
        html.contains(r#"aria-live="polite""#),
        "arch cell must be a live region: {html}"
    );
}

/// task 详情页 DOM 契约双侧钉（SSR 锚点 × SSE 脚本消费同一份 HTML）：
/// arch cell `data-build-id` 与 `matrix-summary[data-pattern]` 由 table.rs / tasks.rs
/// 渲染、sse_script.rs 同选择器更新；两侧分属两模块，单测各自仍绿，集成层钉会合点。
#[tokio::test]
async fn task_page_pins_arch_matrix_dom_contract_for_sse() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let task = state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name: "sse-pkg-1.0-1.fc42",
            user: "ui-tester",
            phase: "building",
            ..Default::default()
        })
        .await
        .unwrap();
    let x86 = state
        .state_store
        .insert_build(BuildInsert {
            task_id: Some(task),
            ..sample_build("sse-pkg-1.0-1.fc42", "building")
        })
        .await
        .unwrap();
    let arm = state
        .state_store
        .insert_build(BuildInsert {
            task_id: Some(task),
            arch: Some("aarch64"),
            ..sample_build("sse-pkg-1.0-1.fc42", "building")
        })
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, &format!("/ui/tasks/{task}")).await;
    assert!(
        html.contains(&format!(r#"data-build-id="{x86}""#)),
        "x86_64 arch cell anchor missing: {html}"
    );
    assert!(
        html.contains(&format!(r#"data-build-id="{arm}""#)),
        "aarch64 arch cell anchor missing: {html}"
    );
    // SSR 侧：data-pattern 为默认 En 模板原文。
    assert!(
        html.contains(
            r#"class="matrix-summary" data-pattern="{0} arches · {1} succeeded · {2} failed""#
        ),
        "matrix summary pattern missing: {html}"
    );
    // 脚本侧：SSE 消费同批选择器（children → cell 定位 + 摘要按 data-pattern 整句重算）。
    assert!(
        html.contains("updateChildren(data.children);"),
        "SSE script must consume the children payload: {html}"
    );
    assert!(
        html.contains(r#"'[data-build-id="' + ch.id + '"]'"#),
        "SSE script must locate cells by data-build-id: {html}"
    );
    assert!(
        html.contains(".matrix-summary[data-pattern]"),
        "SSE script must recompute the summary from data-pattern: {html}"
    );
}

/// 通知按钮：live 详情页（build + task）渲染 hidden 按钮 + 武装脚本，终态页
/// 不渲染；匿名浏览（无操作权限 task 页）同样渲染——通知是纯前端能力，不门控。
#[tokio::test]
async fn notify_button_renders_on_live_detail_pages_only() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let live_build = insert_task_build(&state, "notify-pkg-1.0-1.fc42", "building").await;
    let done_build = insert_task_build(&state, "notify-pkg-1.0-1.fc42", "succeeded").await;
    let live_task = state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name: "notify-pkg-1.0-1.fc42",
            user: "ui-tester",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();
    let done_task = state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name: "notify-pkg-1.0-1.fc42",
            user: "ui-tester",
            phase: "failed",
            ..Default::default()
        })
        .await
        .unwrap();

    // live build/task：按钮 + 武装脚本都在（subject 注入 NVR）。
    let html = get_page(&app, &admin_token, &format!("/ui/builds/{live_build}")).await;
    assert!(
        html.contains(
            r#"<button id="crbs-notify" type="button" class="action-button secondary" hidden>"#
        ),
        "live build detail must render the hidden notify button: {html}"
    );
    assert!(
        html.contains("window.__crbsNotify = 'notify-pkg-1.0-1.fc42';"),
        "arming script must embed the NVR subject: {html}"
    );
    // 拒绝态可恢复：denied 分支只设 title/textContent（不 disable），granted
    // 分支保持 disabled + enabled 文案；btn.disabled 仅此一处，SSE 脚本不写。
    assert!(
        html.contains("navigator.permissions && navigator.permissions.query"),
        "notify script must feature-detect the Permissions API: {html}"
    );
    assert!(
        html.contains(
            "btn.title = 'Blocked in browser settings — re-allow notifications for this site, then try again';"
        ),
        "denied state must carry the recovery hint as title: {html}"
    );
    let denied_at = html.find("function showDenied() {").expect("showDenied fn");
    let apply_at = html.find("function applyStatus").expect("applyStatus fn");
    assert!(
        !html[denied_at..apply_at].contains("btn.disabled = true;"),
        "denied branch must not disable the button: {html}"
    );
    assert!(
        html.contains("btn.disabled = true;"),
        "granted branch keeps the disabled semantics: {html}"
    );
    assert!(
        html.contains("btn.textContent = 'Notifications on';"),
        "granted branch keeps the enabled label: {html}"
    );
    let html = get_page(&app, &admin_token, &format!("/ui/tasks/{live_task}")).await;
    assert!(
        html.contains(r#"<button id="crbs-notify""#),
        "live task detail must render the notify button: {html}"
    );

    // 终态页：无按钮、无武装脚本。断言钉 `<button id="crbs-notify">` 而非裸
    // "crbs-notify" 子串——style.css 头注契约（内联进每页）也含该选择器，裸子串误伤。
    let html = get_page(&app, &admin_token, &format!("/ui/builds/{done_build}")).await;
    assert!(
        !html.contains(r#"<button id="crbs-notify""#),
        "terminal build: {html}"
    );
    assert!(
        !html.contains("window.__crbsNotify = "),
        "terminal build must not arm notify: {html}"
    );
    let html = get_page(&app, &admin_token, &format!("/ui/tasks/{done_task}")).await;
    assert!(
        !html.contains(r#"<button id="crbs-notify""#),
        "terminal task: {html}"
    );
    assert!(
        !html.contains("window.__crbsNotify = "),
        "terminal task must not arm notify: {html}"
    );

    // 匿名（无 cookie）：live task 页无操作权限，仍因通知按钮渲染 header-actions。
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ui/tasks/{live_task}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes).into_owned();
    assert!(
        html.contains(r#"<button id="crbs-notify""#),
        "anonymous viewer must still get the notify button: {html}"
    );
}

// --- 2. back 透传：列表带参 + 详情白名单校验 ---

/// builds 列表给详情链接追加 back（含过滤参数）；详情页 back 白名单放行 / 回退。
#[tokio::test]
async fn builds_list_and_detail_pass_back_through_whitelist() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let build = insert_task_build(&state, "back-pkg-1.0-1.fc42", "failed").await;

    let html = get_page(&app, &admin_token, "/ui/builds?phase=failed").await;
    assert!(
        html.contains(&format!(
            r#"href="/ui/builds/{build}?back=%2Fui%2Fbuilds%3Fphase%3Dfailed"#
        )),
        "detail link must carry the current list URL as back: {html}"
    );

    // 详情（合法 back，含 query 与页码）：返回链接回来源列表。
    let html = get_page(
        &app,
        &admin_token,
        &format!("/ui/builds/{build}?back=%2Fui%2Fbuilds%3Fphase%3Dfailed%26offset%3D50"),
    )
    .await;
    assert!(
        html.contains(r#"href="/ui/builds?phase=failed&amp;offset=50""#),
        "back link must return to the source list with filters: {html}"
    );

    // 非法 back（外部 URL / 非 /ui/ 路径）与缺失：回退默认列表页。
    for bad in [
        "https%3A%2F%2Fevil.example%2Fui%2Fbuilds",
        "%2Fapi%2Fv1%2Fbuilds",
    ] {
        let html = get_page(
            &app,
            &admin_token,
            &format!("/ui/builds/{build}?back={bad}"),
        )
        .await;
        assert!(
            html.contains(r#"<a href="/ui/builds">← Back to builds</a>"#),
            "illegal back must fall back to the default list: {html}"
        );
    }
    let html = get_page(&app, &admin_token, &format!("/ui/builds/{build}")).await;
    assert!(
        html.contains(r#"<a href="/ui/builds">← Back to builds</a>"#),
        "{html}"
    );
}

/// admin user 列表带 back，user 详情按白名单回放（管理端同链路抽查）。
#[tokio::test]
async fn admin_users_list_and_detail_pass_back_through_whitelist() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let user_id = state
        .state_store
        .create_user("back-user", "builder")
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, "/ui/admin/users?role=builder").await;
    assert!(
        html.contains(&format!(
            r#"href="/ui/admin/users/{user_id}?back=%2Fui%2Fadmin%2Fusers%3Frole%3Dbuilder"#
        )),
        "user detail link must carry the list URL as back: {html}"
    );

    let html = get_page(
        &app,
        &admin_token,
        &format!("/ui/admin/users/{user_id}?back=%2Fui%2Fadmin%2Fusers%3Frole%3Dbuilder"),
    )
    .await;
    assert!(
        html.contains(r#"href="/ui/admin/users?role=builder""#),
        "{html}"
    );
    let html = get_page(
        &app,
        &admin_token,
        &format!("/ui/admin/users/{user_id}?back=%2F%2Fevil.example%2Fx"),
    )
    .await;
    assert!(
        html.contains(r#"<a href="/ui/admin/users">← Back to users</a>"#),
        "{html}"
    );
}

// --- 3. nav：Dashboard 项 / aria-current / 登录用户名 ---

#[tokio::test]
async fn nav_renders_dashboard_item_aria_current_and_username() {
    let (_state, app, _tmp, admin_token) = setup_app_with_admin().await;

    let html = get_page(&app, &admin_token, "/ui/builds").await;
    assert!(
        html.contains(r#"<a class="active" aria-current="page" href="/ui/builds">Builds</a>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<a class="" href="/ui/">Dashboard</a>"#),
        "Dashboard must be the first nav item (inactive here): {html}"
    );
    // 工具区顺序（admin 会话）：主题 → 语言 → ⚙ → 用户名 → 角色徽章；Admin 无文本导航项。
    let theme_at = html
        .find(r#"<form method="post" action="/ui/set-theme" class="nav-pref-form">"#)
        .expect("theme POST form");
    let lang_at = html
        .find(r#"<form method="post" action="/ui/set-lang" class="nav-pref-form">"#)
        .expect("lang POST form");
    let gear_at = html
        .find(r#"<a class="nav-icon-btn" href="/ui/admin" title="Admin" aria-label="Admin">⚙</a>"#)
        .expect("admin gear button");
    let user_at = html.find(r#"<a class="nav-user""#).expect("nav-user");
    let role_at = html.find(r#"<span class="nav-role">"#).expect("nav-role");
    assert!(
        theme_at < lang_at && lang_at < gear_at && gear_at < user_at && user_at < role_at,
        "tool order must be theme < lang < admin gear < nav-user < nav-role: {html}"
    );
    assert!(
        !html.contains(r#"href="/ui/admin">Admin</a>"#),
        "Admin must not be a nav text link anymore: {html}"
    );
    assert!(
        html.contains(r#"<a class="nav-user" href="/ui/me" title="admin-op">admin-op</a>"#),
        "{html}"
    );

    let html = get_page(&app, &admin_token, "/ui/").await;
    assert!(
        html.contains(r#"<a class="active" aria-current="page" href="/ui/">Dashboard</a>"#),
        "{html}"
    );
    // 非当前页不带 aria-current（抽查 Builds 项）。
    let builds_link_at = html
        .find(r#"href="/ui/builds">Builds"#)
        .expect("Builds link");
    assert!(
        !html[builds_link_at..].starts_with(r#"href="/ui/builds">Builds"#)
            || !html[..builds_link_at].ends_with("aria-current=\"page\" "),
        "inactive items must not carry aria-current: {html}"
    );
}

/// nav ⚙：仅 admin 会话渲染（Admin 入口不可见）；admin 页上 ⚙ 带 active + aria-current。
#[tokio::test]
async fn nav_admin_gear_is_admin_only_and_activates_on_admin_pages() {
    let (_state, app, _tmp, admin_token) = setup_app_with_admin().await;

    // admin 页：⚙ active + aria-current。
    let html = get_page(&app, &admin_token, "/ui/admin").await;
    assert!(
        html.contains(
            r#"<a class="nav-icon-btn active" aria-current="page" href="/ui/admin" title="Admin" aria-label="Admin">⚙</a>"#
        ),
        "{html}"
    );

    // admin 会话 Builds 页：⚙ 常驻但非 active。
    let html = get_page(&app, &admin_token, "/ui/builds").await;
    assert!(
        html.contains(
            r#"<a class="nav-icon-btn" href="/ui/admin" title="Admin" aria-label="Admin">⚙</a>"#
        ),
        "{html}"
    );

    // 匿名首页：无 ⚙（admin-only 门槛）。
    let html = get_page(&app, "", "/ui/").await;
    assert!(
        !html.contains(r#"href="/ui/admin""#),
        "anonymous must not see admin gear: {html}"
    );
}

// --- 4. packages 列表新列：Latest phase / Submissions / Last build ---

#[tokio::test]
async fn packages_list_renders_phase_attempts_and_last_build_columns() {
    let (state, app, _tmp, _admin_token) = setup_app_with_admin().await;
    // 同名两次尝试：latest = MAX(id)（第二次，succeeded）。
    let _first = state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name: "colpkg-1.0-1",
            user: "ui-tester",
            phase: "failed",
            ..Default::default()
        })
        .await
        .unwrap();
    let latest = state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name: "colpkg-1.0-1",
            user: "ui-tester",
            phase: "succeeded",
            ..Default::default()
        })
        .await
        .unwrap();

    let html = get_page(&app, &_admin_token, "/ui/packages").await;
    for th in [
        "<th>Name</th>",
        "<th>Latest phase</th>",
        r#"<th class="num">Submissions</th>"#,
        r#"<th class="num">Last build</th>"#,
    ] {
        assert!(html.contains(th), "column header {th} missing: {html}");
    }
    assert!(
        html.contains(r#"<a href="/ui/packages/colpkg">2</a>"#),
        "submissions must link to the package detail page: {html}"
    );
    assert!(
        html.contains(r#"<a href="/ui/packages/colpkg"><span class="status success">"#),
        "latest phase must link back to the package detail page: {html}"
    );
    assert!(
        !html.contains(&format!(r#"/ui/tasks/{latest}"#)),
        "packages list must not link to tasks directly: {html}"
    );
    assert!(
        html.contains(r#"<span class="status success"><span class="dot"></span>succeeded</span>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"href="/ui/packages/colpkg?back=%2Fui%2Fpackages""#),
        "name link must carry back to the list: {html}"
    );
    // 两 attempt 折叠为 1 组（h1 count-chip）。
    assert!(
        html.contains(r#"<h1>Packages <span class="count-chip">1</span></h1>"#),
        "{html}"
    );
}

// --- 5. audit：Target 链接映射 + 空态；admin 首页 GC 卡 ---

#[tokio::test]
async fn audit_page_links_targets_and_admin_dashboard_has_gc_card() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let user_id = state
        .state_store
        .create_user("audit-target-user", "viewer")
        .await
        .unwrap();
    state
        .state_store
        .audit_log(
            "admin-op",
            "admin",
            "create_user",
            Some(&user_id.to_string()),
            None,
        )
        .await
        .unwrap();
    state
        .state_store
        .audit_log("admin-op", "admin", "cancel_build", Some("42"), None)
        .await
        .unwrap();
    state
        .state_store
        .audit_log("admin-op", "admin", "gc", Some("01234567-89ab-cdef"), None)
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, "/ui/admin/audit").await;
    assert!(
        html.contains(&format!(
            r#"<a href="/ui/admin/users/{user_id}">{user_id}</a>"#
        )),
        "{html}"
    );
    assert!(html.contains(r#"<a href="/ui/builds/42">42</a>"#), "{html}");
    assert!(
        html.contains(">01234567-89ab-cdef</td>"),
        "gc target must stay plain text: {html}"
    );

    let html = get_page(&app, &admin_token, "/ui/admin/audit?target=nomatch").await;
    assert!(html.contains("No audit entries"), "{html}");
    assert!(html.contains("empty-state"), "{html}");

    let html = get_page(&app, &admin_token, "/ui/admin").await;
    assert!(html.contains(r#"href="/ui/admin/gc""#), "{html}");
    assert!(html.contains("Garbage Collection"), "{html}");
}

// --- 6. 401 闭环：login ?next= 回跳（login CTA 契约见 integration_ui_redirects.rs） ---

async fn login_get(app: &axum::Router, query: &str) -> (String, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ui/login{query}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("login nonce cookie")
        .to_owned();
    let nonce = set_cookie
        .split(';')
        .next()
        .and_then(|kv| kv.split('=').nth(1))
        .expect("nonce value")
        .to_owned();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes).into_owned();
    let marker = r#"name="csrf_token" value=""#;
    let start = html.find(marker).expect("csrf hidden input") + marker.len();
    let csrf = html[start..]
        .split('"')
        .next()
        .unwrap_or_default()
        .to_owned();
    (nonce, csrf)
}

/// login `?next=`：合法目标 303 回跳；非法 / 缺失回退 /ui/（CSRF：login_nonce cookie + 表单 csrf token）。
#[tokio::test]
async fn login_next_redirects_to_whitelisted_target_only() {
    let (_state, app, _tmp, _admin_token) = setup_app_with_admin().await;
    let user_token = seed_user_token_for_test(&_state.state_store, "login-user", "builder")
        .await
        .expect("seed user token");

    async fn login_post(
        app: &axum::Router,
        nonce: &str,
        csrf: &str,
        next: &str,
        user_token: &str,
    ) -> axum::response::Response {
        let body = format!("token={user_token}&csrf_token={csrf}&next={next}");
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ui/login/token")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Cookie", format!("crbs_login_nonce={nonce}"))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    let (nonce, csrf) = login_get(&app, "?next=/ui/builds").await;
    let response = login_post(&app, &nonce, &csrf, "/ui/builds", &user_token).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/builds"),
        "valid next must redirect back to the source page"
    );
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(set_cookie.contains("crbs_token="), "{set_cookie}");

    // 非法 next（外部 URL）：回退 /ui/（open redirect 防护）。
    let (nonce, csrf) = login_get(&app, "?next=https://evil.example/ui/builds").await;
    let response = login_post(
        &app,
        &nonce,
        &csrf,
        "https://evil.example/ui/builds",
        &user_token,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/"),
        "illegal next must fall back to /ui/"
    );

    // 缺失 next：默认 /ui/。
    let (nonce, csrf) = login_get(&app, "").await;
    let response = login_post(&app, &nonce, &csrf, "", &user_token).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/"),
        "missing next must keep the /ui/ default"
    );
}

// --- 7. phase 过滤白名单：未知值按未过滤处理 ---

#[tokio::test]
async fn unknown_phase_filter_is_ignored_instead_of_emptying_list() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    insert_task_build(&state, "phasefil-pkg-1.0-1.fc42", "succeeded").await;

    let html = get_page(&app, &admin_token, "/ui/builds?phase=bogus").await;
    assert!(
        html.contains("phasefil-pkg"),
        "unknown phase must be treated as unfiltered: {html}"
    );
    assert!(
        html.contains(r#"<span class="count-chip">1</span>"#),
        "{html}"
    );
    // 下拉回显 All（未知值不透传）。
    assert!(
        html.contains(r#"<option value="" selected>All</option>"#),
        "{html}"
    );

    let html = get_page(&app, &admin_token, "/ui/tasks?phase=bogus").await;
    assert!(
        html.contains(r#"<span class="count-chip">1</span>"#),
        "{html}"
    );

    let html = get_page(&app, &admin_token, "/ui/builds?phase=succeeded").await;
    assert!(
        html.contains(r#"<span class="count-chip">1</span>"#),
        "{html}"
    );
    let html = get_page(&app, &admin_token, "/ui/builds?phase=failed").await;
    assert!(html.contains("No builds found"), "{html}");
}

// --- 8. 空态与 aria：dashboard recent tasks 空态、日志页 role="log" ---

#[tokio::test]
async fn dashboard_empty_recent_tasks_and_log_page_role_log() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;

    let html = get_page(&app, &admin_token, "/ui/").await;
    assert!(html.contains("No recent tasks"), "{html}");

    // building 日志页：#log-output 带 role="log"（SSE 追加目标）。
    let build = insert_task_build(&state, "rolelog-pkg-1.0-1.fc42", "building").await;
    let html = get_page(&app, &admin_token, &format!("/ui/builds/{build}/logs")).await;
    assert!(
        html.contains(r#"pre id="log-output" role="log""#),
        "log output must expose role=log: {html}"
    );
}
