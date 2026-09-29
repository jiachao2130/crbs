// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Admin users 列表页过滤+分页（GET）集成测试。
//! 复用 crbs_token cookie 会话（GET 页面无需 CSRF）。
//! seed 管理员 `admin-op`（role=admin，status=active）计入各用例数据断言。

// 测试辅助函数（seed_* 等）不带 #[test]，clippy allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::setup_app_with_admin;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_server::server::seed_user_token_for_test;

async fn get_page(app: &axum::Router, admin_token: &str, path: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("Cookie", format!("crbs_token={admin_token}"))
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

/// /ui/admin 路径族统一网关（route_layer）：无会话 → 401、非 admin → 403、admin → 200。
#[tokio::test]
async fn admin_prefix_gate_rejects_anonymous_and_non_admin() {
    let (_state, app, _tmp, admin_token) = setup_app_with_admin().await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // viewer 同 store 种在同一 app 上断言 403：PG 腿下 create_test_store 共享
    // 同一库且每次 DROP SCHEMA 重置——第二个 store 会抹掉 app 的 admin 行，
    // 401 断言必挂（SQLite 双临时库掩盖了这一结构问题）。
    let viewer_token = seed_user_token_for_test(&_state.state_store, "view-op", "viewer")
        .await
        .expect("seed viewer token");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/admin")
                .header("Cookie", format!("crbs_token={viewer_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/admin")
                .header("Cookie", format!("crbs_token={admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 未注册方法（PROPFIND）穿透网关交方法路由 → 405（route_inventory 的 public 门控探测契约）。
    let response = app
        .oneshot(
            Request::builder()
                .method("PROPFIND")
                .uri("/ui/admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

/// 过滤条件回显（input value / option selected 布尔属性）+ 表格按条件过滤。
#[tokio::test]
async fn admin_users_page_filters_by_name_and_role() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    state
        .state_store
        .create_user("alice", "admin")
        .await
        .expect("create alice");
    state
        .state_store
        .create_user("alina", "viewer")
        .await
        .expect("create alina");
    state
        .state_store
        .create_user("bob", "builder")
        .await
        .expect("create bob");

    let html = get_page(&app, &admin_token, "/ui/admin/users?name=ali&role=admin").await;

    assert!(html.contains(r#"value="ali""#), "name echo missing");
    assert!(
        html.contains(r#"<option value="admin" selected>"#),
        "role option not selected"
    );
    // 表格只剩 alice（alina 角色 viewer、bob 名字不匹配、admin-op 名字不匹配）。
    assert!(
        html.contains(r#"<td class="ellipsis" title="alice"><span class="user-cell">"#),
        "alice row missing"
    );
    assert!(
        !html.contains(r#"<td class="ellipsis" title="alina"><span class="user-cell">"#),
        "alina should be filtered out"
    );
    assert!(
        !html.contains(r#"<td class="ellipsis" title="bob"><span class="user-cell">"#),
        "bob should be filtered out"
    );
    assert!(
        !html.contains(r#"<td class="ellipsis" title="admin-op"><span class="user-cell">"#),
        "admin-op should be filtered out"
    );
}

/// status 查询参数双语义：active/disabled 是过滤器，created 等无效值只触发 flash、不过滤列表。
#[tokio::test]
async fn admin_users_page_status_param_filters_or_flashes() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    state
        .state_store
        .create_user("alice", "builder")
        .await
        .expect("create alice");
    let erin = state
        .state_store
        .create_user("erin", "viewer")
        .await
        .expect("create erin");
    state
        .state_store
        .set_user_status(erin, "disabled")
        .await
        .expect("disable erin");

    let html = get_page(&app, &admin_token, "/ui/admin/users?status=disabled").await;
    assert!(
        html.contains(r#"<td class="ellipsis" title="erin"><span class="user-cell">"#),
        "erin row missing"
    );
    assert!(
        !html.contains(r#"<td class="ellipsis" title="alice"><span class="user-cell">"#),
        "active user should be filtered out"
    );
    assert!(html.contains(r#"<option value="disabled" selected>"#));

    let html = get_page(&app, &admin_token, "/ui/admin/users?status=created").await;
    assert!(
        html.contains(r#"<td class="ellipsis" title="alice"><span class="user-cell">"#),
        "list must stay unfiltered"
    );
    assert!(html.contains("User created."), "flash message missing");
}

/// 分页链接保留过滤参数：带过滤 + offset 页面的 Previous 回链第一页（丢弃 offset）。
#[tokio::test]
async fn admin_users_page_pagination_links_preserve_filters() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    state
        .state_store
        .create_user("alice", "admin")
        .await
        .expect("create alice");

    let html = get_page(
        &app,
        &admin_token,
        "/ui/admin/users?name=ali&role=admin&offset=50",
    )
    .await;
    // maud 属性转义：& 渲染为 &amp;。
    assert!(
        html.contains(r#"href="/ui/admin/users?name=ali&amp;role=admin""#),
        "prev link must keep filter params"
    );
}

/// 用户数超过一页（UI_PAGE_SIZE=50）时出现 Next；第二页切片正确且 Next 禁用。
#[tokio::test]
async fn admin_users_page_paginates_large_user_set() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    for i in 0..55 {
        state
            .state_store
            .create_user(&format!("bulk-user-{i:02}"), "viewer")
            .await
            .expect("create bulk user");
    }
    // admin-op + 55 = 56 > 50。
    let html = get_page(&app, &admin_token, "/ui/admin/users").await;
    assert!(
        html.contains(r#"href="/ui/admin/users?offset=50""#),
        "Next link missing"
    );
    assert!(html.contains("1-50 of 56"), "pagination info wrong");
    assert!(html.contains(r#"<td class="ellipsis" title="bulk-user-48"><span class="user-cell">"#));
    assert!(
        !html.contains(r#"<td class="ellipsis" title="bulk-user-50"><span class="user-cell">"#),
        "page 1 overflow"
    );

    let html = get_page(&app, &admin_token, "/ui/admin/users?offset=50").await;
    assert!(html.contains("51-56 of 56"), "page 2 info wrong");
    assert!(html.contains(r#"<td class="ellipsis" title="bulk-user-50"><span class="user-cell">"#));
    assert!(html.contains(r#"<td class="ellipsis" title="bulk-user-54"><span class="user-cell">"#));
    assert!(
        !html.contains(r#"<td class="ellipsis" title="bulk-user-01"><span class="user-cell">"#),
        "page 2 overflow"
    );
    assert!(
        !html.contains(r#"href="/ui/admin/users?offset=100""#),
        "Next must not link past the end"
    );
}

/// offset 越过末页（total>0）→ 页切片空但仍渲染表卡 + prev 链接（可回第一页）；
/// empty-state 判据是 total==0 而非页切片空；区间收敛到 total、不倒挂。
#[tokio::test]
async fn admin_users_page_offset_beyond_last_page_renders_table_card() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    for i in 0..3 {
        state
            .state_store
            .create_user(&format!("over-user-{i:02}"), "viewer")
            .await
            .expect("create user");
    }
    // total = 4（含 admin-op）但 offset=50 越过末页：页切片为空。
    let html = get_page(&app, &admin_token, "/ui/admin/users?offset=50").await;

    // 表卡照常渲染；empty-state 断言用渲染形态而非裸类名，避免命中 style.css 内联规则文本。
    assert!(html.contains(r#"class="table-card""#), "{html}");
    assert!(!html.contains(r#"class="empty-state""#), "{html}");
    assert!(
        html.contains(r#"<a href="/ui/admin/users">←"#),
        "prev link must fall back to the bare list URL: {html}"
    );
    assert!(html.contains("4-4 of 4"), "{html}");
}

/// GET 用户详情页提取表单内嵌 CSRF token（role/status 表单共用）。
async fn csrf_for_user_page(app: &axum::Router, admin_token: &str, id: i64) -> String {
    let html = get_page(app, admin_token, &format!("/ui/admin/users/{id}")).await;
    common::extract_csrf_token(&html).expect("CSRF token should be present in admin user forms")
}

async fn post_user_form(
    app: &axum::Router,
    admin_token: &str,
    uri: &str,
    form_body: &str,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", format!("crbs_token={admin_token}"))
                .body(Body::from(form_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// 最后活跃管理员守卫（UI）：对唯一活跃 admin 提 status/role 表单 → 303 带签名 ?error=，DB 不变。
#[tokio::test]
async fn admin_user_forms_reject_last_active_admin() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let sole = state
        .state_store
        .find_user_by_name("admin-op")
        .await
        .unwrap()
        .unwrap()
        .id;
    let csrf = csrf_for_user_page(&app, &admin_token, sole).await;

    let response = post_user_form(
        &app,
        &admin_token,
        &format!("/ui/admin/users/{sole}/status"),
        &format!("csrf_token={csrf}&status=disabled"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    assert!(
        location.contains("error=") && location.contains("last%20active%20admin"),
        "guard flash missing from Location: {location}"
    );
    assert_eq!(
        state
            .state_store
            .get_user(sole)
            .await
            .unwrap()
            .unwrap()
            .status,
        "active",
        "rejected disable must not change status"
    );

    let response = post_user_form(
        &app,
        &admin_token,
        &format!("/ui/admin/users/{sole}/role"),
        &format!("csrf_token={csrf}&role=viewer"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    assert!(
        location.contains("error=") && location.contains("last%20active%20admin"),
        "guard flash missing from Location: {location}"
    );
    assert_eq!(
        state
            .state_store
            .get_user(sole)
            .await
            .unwrap()
            .unwrap()
            .role,
        "admin",
        "rejected demote must not change role"
    );
}

/// set_role/set_status 存在性预检：不存在 id → 303 error flash "not found"；成功路径 role/status 均落库。
#[tokio::test]
async fn admin_user_forms_missing_user_flashes_not_found_and_success_path() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let viewer = state
        .state_store
        .create_user("victim", "viewer")
        .await
        .unwrap();
    let csrf = csrf_for_user_page(&app, &admin_token, viewer).await;

    for uri_and_body in [
        (
            "/ui/admin/users/99999/role",
            format!("csrf_token={csrf}&role=operator"),
        ),
        (
            "/ui/admin/users/99999/status",
            format!("csrf_token={csrf}&status=disabled"),
        ),
    ] {
        let (uri, body) = uri_and_body;
        let response = post_user_form(&app, &admin_token, uri, &body).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("Location")
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();
        assert!(
            location.contains("error=") && location.contains("not%20found"),
            "not-found flash missing from Location: {location}"
        );
    }

    let response = post_user_form(
        &app,
        &admin_token,
        &format!("/ui/admin/users/{viewer}/role"),
        &format!("csrf_token={csrf}&role=operator"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    assert!(
        location.contains("status=role_updated"),
        "success redirect missing: {location}"
    );
    assert_eq!(
        state
            .state_store
            .get_user(viewer)
            .await
            .unwrap()
            .unwrap()
            .role,
        "operator"
    );

    let response = post_user_form(
        &app,
        &admin_token,
        &format!("/ui/admin/users/{viewer}/status"),
        &format!("csrf_token={csrf}&status=disabled"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        state
            .state_store
            .get_user(viewer)
            .await
            .unwrap()
            .unwrap()
            .status,
        "disabled"
    );
}

/// admin 表单错误 flash zh round-trip：覆盖 0 参（创建用户名含空白）与 2 参
///（撤销不存在的 token——zh 模板重排 {0}/{1} 语序）；POST/GET 共用 crbs_lang=zh 协商 cookie。
#[tokio::test]
async fn admin_form_error_flashes_are_localized_for_zh() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let viewer = state
        .state_store
        .create_user("zh-target", "viewer")
        .await
        .unwrap();
    let zh_cookie = format!("crbs_token={admin_token}; crbs_lang=zh");

    let html = get_page(&app, &admin_token, "/ui/admin/users").await;
    let csrf = common::extract_csrf_token(&html).expect("CSRF token in create-user form");
    let response = post_user_form_with_cookie(
        &app,
        &zh_cookie,
        "/ui/admin/users",
        &format!("csrf_token={csrf}&name=has%20space&role=viewer"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    assert!(location.starts_with("/ui/admin/users?error="), "{location}");
    assert!(
        location.contains(urlencoding::encode("用户名不能包含空白字符").as_ref()),
        "{location}"
    );
    let html = get_with_cookie(&app, &zh_cookie, &location).await;
    assert!(
        html.contains("用户名不能包含空白字符。"),
        "zh flash not rendered: {html}"
    );

    // 2 参：en 模板 token {0} not found for user {1}，zh 重排 {0}/{1} 语序。
    let csrf = csrf_for_user_page(&app, &admin_token, viewer).await;
    let response = post_user_form_with_cookie(
        &app,
        &zh_cookie,
        &format!("/ui/admin/users/{viewer}/tokens/9999/revoke"),
        &format!("csrf_token={csrf}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    assert!(
        location.starts_with(&format!("/ui/admin/users/{viewer}?error=")),
        "{location}"
    );
    assert!(
        location.contains(urlencoding::encode("未找到用户").as_ref()),
        "{location}"
    );
    let html = get_with_cookie(&app, &zh_cookie, &location).await;
    assert!(
        html.contains(&format!("未找到用户 {viewer} 的 token 9999。")),
        "zh flash not rendered: {html}"
    );
}

/// POST UI 表单（完整 cookie 串，便于附加 crbs_lang）。
async fn post_user_form_with_cookie(
    app: &axum::Router,
    cookie: &str,
    uri: &str,
    form_body: &str,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", cookie)
                .body(Body::from(form_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// GET 任意 UI 页面（完整 cookie 串，便于附加 crbs_lang），返回 HTML 文本。
async fn get_with_cookie(app: &axum::Router, cookie: &str, uri: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("Cookie", cookie)
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
