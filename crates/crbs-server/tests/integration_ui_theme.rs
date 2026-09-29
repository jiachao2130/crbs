// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 手动主题切换：/ui/set-theme（POST 表单）的 Set-Cookie + 303 回跳、Referer 校验、
//! 分级 CSRF、按 crbs_theme cookie 渲染 <html data-theme>、导航栏主题单按钮。

// 测试辅助函数不带 #[test] 属性，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

mod common;

use common::body_text;
use common::setup_app;

/// POST /ui/set-theme（表单 theme=v）→ 303 + `crbs_theme=v` cookie + 回跳 Referer 路径；
/// 白名单原样入 cookie，非法值/缺参静默按 auto；匿名分级 CSRF 放行。
#[tokio::test]
async fn set_theme_validates_value_sets_cookie_and_redirects() {
    let (_state, app, _tmp) = setup_app().await;
    let referer = "http://crbs.local/ui/builds?phase=failed";

    for value in ["dark", "light", "auto"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ui/set-theme")
                    .header(header::REFERER, referer)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!("theme={value}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "theme={value}");
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/ui/builds?phase=failed"),
            "theme={value}: same-site UI referer keeps path+query"
        );
        let expected_cookie =
            format!("crbs_theme={value}; Path=/; Max-Age=31536000; SameSite=Lax; HttpOnly");
        assert_eq!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .and_then(|v| v.to_str().ok()),
            Some(expected_cookie.as_str()),
            "theme={value}"
        );
    }

    for body in ["theme=hack", ""] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ui/set-theme")
                    .header(header::REFERER, referer)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "body={body}");
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            cookie.starts_with("crbs_theme=auto;"),
            "body={body}: expected fallback cookie, got {cookie}"
        );
    }
}

/// CSRF 分级：带会话凭据（crbs_token cookie）的 POST 必须携带 csrf_token——缺/错 403；匿名放行。
#[tokio::test]
async fn set_theme_requires_csrf_token_when_session_present() {
    let (_state, app, _tmp) = setup_app().await;
    let referer = "http://crbs.local/ui/";

    for (label, body) in [
        ("missing token", "theme=dark"),
        ("wrong token", "theme=dark&csrf_token=bogus"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ui/set-theme")
                    .header(header::REFERER, referer)
                    .header(header::COOKIE, "crbs_token=crbs_tok_sessionbase")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{label}: session-backed POST without valid CSRF must be rejected"
        );
        assert!(
            response.headers().get(header::SET_COOKIE).is_none(),
            "{label}: rejected POST must not set cookies"
        );
    }

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/set-theme")
                .header(header::REFERER, referer)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("theme=dark"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER, "anonymous POST");
}

/// 回跳目标白名单：仅 /ui/ 开头（且非 // 协议相对）的 Referer 路径被采纳，path+query
/// 原样保留；站外 / 非 UI 站内 / 协议相对 / 无 Referer 一律回 /ui/（防 open redirect）。
#[tokio::test]
async fn set_theme_referer_target_is_whitelisted_to_ui_paths() {
    let (_state, app, _tmp) = setup_app().await;

    let keep_case = (
        "https://crbs.local/ui/builds?phase=failed&task_id=7",
        "/ui/builds?phase=failed&task_id=7",
    );
    for (referer, expect_location) in [keep_case]
        .into_iter()
        .chain(common::REFERER_FALLBACK_CASES.iter().copied())
    {
        let response =
            common::post_preference_form(&app, "/ui/set-theme", "theme=dark", Some(referer)).await;
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

    let response = common::post_preference_form(&app, "/ui/set-theme", "theme=dark", None).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/")
    );
}

/// crbs_theme cookie → <html data-theme>：dark/light 输出对应属性，Auto（缺失或
/// 非法值）不输出属性（走系统媒体查询）；公开首页匿名可达（public access 默认开启）。
#[tokio::test]
async fn page_html_tag_reflects_theme_cookie() {
    let (_state, app, _tmp) = setup_app().await;

    let cases: &[(&str, &str)] = &[
        ("crbs_theme=dark", "<html lang=\"en\" data-theme=\"dark\">"),
        (
            "crbs_theme=light",
            "<html lang=\"en\" data-theme=\"light\">",
        ),
        ("crbs_theme=hack", "<html lang=\"en\">"),
        ("crbs_token=other", "<html lang=\"en\">"),
    ];
    for (cookie, expect_tag) in cases {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ui/")
                    .header(header::COOKIE, *cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "cookie={cookie}");
        let html = body_text(response).await;
        assert!(
            html.contains(expect_tag),
            "cookie={cookie}: expected {expect_tag} in body head: {}",
            &html[..html.len().min(200)]
        );
    }

    let response = app
        .oneshot(Request::builder().uri("/ui/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let html = body_text(response).await;
    assert!(
        html.contains("<html lang=\"en\">"),
        "auto theme must not emit data-theme"
    );
}

/// 导航栏主题单按钮（无 JS）：字形 = 当前主题（◐/☀/☾），hidden theme 携带循环下一态
///（auto→light→dark→auto）；aria/title 含"当前态 — 切换到下一态"；匿名 hidden csrf_token 空串。
#[tokio::test]
async fn nav_theme_button_shows_current_icon_and_posts_next_state() {
    let (_state, app, _tmp) = setup_app().await;

    let cases: &[(&str, &str, &str, &str)] = &[
        (
            "crbs_theme=dark",
            "☾",
            "auto",
            "Theme: Dark — switch to Auto",
        ),
        (
            "crbs_theme=light",
            "☀",
            "dark",
            "Theme: Light — switch to Dark",
        ),
        (
            "crbs_theme=auto",
            "◐",
            "light",
            "Theme: Auto — switch to Light",
        ),
        (
            "crbs_theme=hack",
            "◐",
            "light",
            "Theme: Auto — switch to Light",
        ),
    ];
    for (cookie, icon, next_value, aria) in cases {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ui/")
                    .header(header::COOKIE, *cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "cookie={cookie}");
        let html = body_text(response).await;
        let form_prefix = r#"<form method="post" action="/ui/set-theme" class="nav-pref-form">"#;
        let form_at = html
            .find(form_prefix)
            .unwrap_or_else(|| panic!("cookie={cookie}: theme POST form missing: {html}"));
        let expected_hidden = format!(
            r#"{form_prefix}<input type="hidden" name="theme" value="{next_value}"><input type="hidden" name="csrf_token" value="">"#,
        );
        assert!(
            html[form_at..].starts_with(&expected_hidden),
            "cookie={cookie}: hidden theme/csrf fields must carry next state: {html}"
        );
        let button = format!(
            r#"<button type="submit" class="nav-icon-btn" title="{aria}" aria-label="{aria}">{icon}</button>"#
        );
        assert!(
            html[form_at..].contains(&button),
            "cookie={cookie}: submit button must show '{icon}' with aria '{aria}': {html}"
        );
    }

    let response = app
        .oneshot(Request::builder().uri("/ui/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let html = body_text(response).await;
    assert!(html.contains(r#"<input type="hidden" name="theme" value="light">"#));
    assert!(html.contains(r#">◐</button>"#));

    // 不得渲染三态药丸容器 .nav-theme。
    assert!(!html.contains("nav-theme"));
}

/// GET /ui/set-theme 未注册（写端点仅 POST）：GET/HEAD 一律 405，无 Set-Cookie/Location 副作用。
#[tokio::test]
async fn get_and_head_set_theme_are_method_not_allowed() {
    let (_state, app, _tmp) = setup_app().await;
    common::assert_preference_writer_rejects_get_head(&app, "/ui/set-theme?theme=dark").await;

    let response = common::post_preference_form(&app, "/ui/set-theme", "theme=dark", None).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response.headers().get(header::SET_COOKIE).is_some());
    assert!(response.headers().get(header::LOCATION).is_some());
}
