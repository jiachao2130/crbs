// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of this Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 每页条数偏好：set-page-size 写 cookie（值/Referer 白名单、303 回跳）与列表页 cookie 生效（query > cookie > 默认 50）。

// 文件级放行 unwrap/expect：seed_* 等测试辅助函数不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use crbs_core::{BuildInsert, TaskInsert};

mod common;

use common::body_text;
use common::setup_app_with_admin;

/// POST /ui/set-page-size（表单 size=v）→ 303 + `crbs_page_size=v` cookie + 回跳
/// Referer 路径；白名单 50/100/200 原样入 cookie，非法值只 303、不写 cookie。
#[tokio::test]
async fn set_page_size_validates_value_sets_cookie_and_redirects() {
    let (_state, app, _tmp, _token) = setup_app_with_admin().await;
    let referer = "http://crbs.local/ui/builds?phase=failed";

    for value in ["50", "100", "200"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ui/set-page-size")
                    .header(header::REFERER, referer)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!("size={value}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "size={value}");
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/ui/builds?phase=failed"),
            "size={value}: same-site UI referer keeps path+query"
        );
        let expected_cookie =
            format!("crbs_page_size={value}; Path=/; Max-Age=31536000; SameSite=Lax; HttpOnly");
        assert_eq!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .and_then(|v| v.to_str().ok()),
            Some(expected_cookie.as_str()),
            "size={value}"
        );
    }

    for body in ["size=7", "size=500", "size=0", "size=abc", ""] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ui/set-page-size")
                    .header(header::REFERER, referer)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "body={body}");
        assert!(
            response.headers().get(header::SET_COOKIE).is_none(),
            "body={body}: invalid size must not set a cookie"
        );
    }
}

/// 回跳白名单与 set-theme 同款：仅 /ui/ 前缀站内路径采纳，站外 / 协议相对 / 无 Referer 一律回 /ui/（防 open redirect）。
#[tokio::test]
async fn set_page_size_referer_target_is_whitelisted_to_ui_paths() {
    let (_state, app, _tmp, _token) = setup_app_with_admin().await;

    let keep_case = (
        "https://crbs.local/ui/builds?offset=50",
        "/ui/builds?offset=50",
    );
    for (referer, expect_location) in [keep_case]
        .into_iter()
        .chain(common::REFERER_FALLBACK_CASES.iter().copied())
    {
        let response =
            common::post_preference_form(&app, "/ui/set-page-size", "size=100", Some(referer))
                .await;
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "referer={referer}"
        );
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some(expect_location),
            "referer={referer}"
        );
    }

    let response = common::post_preference_form(&app, "/ui/set-page-size", "size=100", None).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/")
    );
}

fn sample_build<'a>(pkg: &'a str, phase: &'a str) -> BuildInsert<'a> {
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

async fn get_page(app: &axum::Router, token: &str, uri: &str, cookie: Option<&str>) -> String {
    // 会话 token 与 page-size cookie 合并进同一个 Cookie 头（重复 .header 会整头覆盖）。
    let mut cookies = vec![format!("crbs_token={token}")];
    if let Some(cookie) = cookie {
        cookies.push(cookie.to_string());
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, cookies.join("; "))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    body_text(response).await
}

/// builds 列表（usize 路径）：无 cookie 默认 50；cookie=100 生效；`?limit=` 覆盖 cookie（query > cookie > 默认）。
#[tokio::test]
async fn builds_list_honors_page_size_cookie_and_query_wins() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    // builds.task_id NOT NULL：build 行必须挂任务。
    let task_id = state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name: "ps-pkg-1.0-1.fc42",
            phase: "succeeded",
            user: "ui-tester",
            ..Default::default()
        })
        .await
        .unwrap();
    for i in 0..60 {
        state
            .state_store
            .insert_build(BuildInsert {
                task_id: Some(task_id),
                ..sample_build(&format!("ps-pkg-{i}-1.0-1.fc42"), "succeeded")
            })
            .await
            .unwrap();
    }

    let html = get_page(&app, &admin_token, "/ui/builds", None).await;
    assert!(html.contains("1-50 of 60"), "{html}");
    assert!(html.contains(r#"href="/ui/builds?offset=50""#), "{html}");
    assert!(
        html.contains(r#"<button type="submit" class="pill active">50</button>"#),
        "{html}"
    );

    let html = get_page(&app, &admin_token, "/ui/builds", Some("crbs_page_size=100")).await;
    assert!(html.contains("1-60 of 60"), "{html}");
    assert!(
        html.contains(r#"<button type="submit" class="pill active">100</button>"#),
        "{html}"
    );

    let html = get_page(
        &app,
        &admin_token,
        "/ui/builds?limit=25",
        Some("crbs_page_size=100"),
    )
    .await;
    assert!(html.contains("1-25 of 60"), "{html}");
    // limit 不进分页 URL：next 只带 offset。
    assert!(html.contains(r#"href="/ui/builds?offset=25""#), "{html}");
    assert_eq!(html.matches(r#"class="pill active""#).count(), 0, "{html}");

    // 非法 cookie（白名单外）：回落默认 50。
    let html = get_page(&app, &admin_token, "/ui/builds", Some("crbs_page_size=42")).await;
    assert!(html.contains("1-50 of 60"), "{html}");
}

/// workers 列表（i64 clamp 路径）：cookie 同样生效（分页药丸在此类页面也渲染）。
#[tokio::test]
async fn workers_list_honors_page_size_cookie() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    for i in 0..3 {
        state
            .state_store
            .upsert_worker(
                &format!("ps-worker-{i}"),
                "x86_64",
                2,
                "0.15.0",
                "online",
                None,
            )
            .await
            .unwrap();
    }

    let html = get_page(
        &app,
        &admin_token,
        "/ui/workers",
        Some("crbs_page_size=200"),
    )
    .await;
    assert!(html.contains("1-3 of 3"), "{html}");
    assert!(
        html.contains(r#"<button type="submit" class="pill active">200</button>"#),
        "{html}"
    );
}

/// 写端点仅 POST：GET/HEAD /ui/set-page-size 一律 405，且无 Set-Cookie / Location 副作用。
#[tokio::test]
async fn get_and_head_set_page_size_are_method_not_allowed() {
    let (_state, app, _tmp, _token) = setup_app_with_admin().await;
    common::assert_preference_writer_rejects_get_head(&app, "/ui/set-page-size?size=100").await;

    let response = common::post_preference_form(&app, "/ui/set-page-size", "size=100", None).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(cookie.starts_with("crbs_page_size=100;"), "got {cookie}");
    assert!(response.headers().get(header::LOCATION).is_some());
}
