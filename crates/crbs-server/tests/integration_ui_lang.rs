// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 国际化集成测试：/ui/set-lang（Set-Cookie + 303 回跳 + Referer 白名单）、?lang= 分享链接、
//! crbs_lang cookie、Accept-Language 协商、html lang、nav 语言药丸高亮、默认英文回归。

// 测试 crate：辅助函数不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

mod common;

use common::body_text;
use common::setup_app;

async fn get(app: &axum::Router, uri: &str, headers: &[(&str, &str)]) -> String {
    get_expect(app, uri, headers, StatusCode::OK).await
}

async fn get_expect(
    app: &axum::Router,
    uri: &str,
    headers: &[(&str, &str)],
    expect: StatusCode,
) -> String {
    let mut builder = Request::builder().uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), expect, "GET {uri}");
    body_text(response).await
}

/// POST /ui/set-lang（表单 lang=v）→ 303 + `crbs_lang=v` cookie 回跳 Referer；白名单 en/zh 原样入 cookie，非法值/缺参静默回 en。
#[tokio::test]
async fn set_lang_validates_value_sets_cookie_and_redirects() {
    let (_state, app, _tmp) = setup_app().await;
    let referer = "http://crbs.local/ui/tasks?phase=failed";

    for value in ["en", "zh"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ui/set-lang")
                    .header(header::REFERER, referer)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!("lang={value}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "lang={value}");
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/ui/tasks?phase=failed"),
            "lang={value}: same-site UI referer keeps path+query"
        );
        let expected_cookie =
            format!("crbs_lang={value}; Path=/; Max-Age=31536000; SameSite=Lax; HttpOnly");
        // 回归守卫（曾 handler 与 ?lang= middleware 双写）：crbs_lang 恰一份，且为全响应唯一 Set-Cookie。
        let lang_cookies: Vec<&str> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter(|c| c.starts_with("crbs_lang="))
            .collect();
        assert_eq!(lang_cookies, vec![expected_cookie.as_str()], "lang={value}");
        assert_eq!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            1,
            "lang={value}"
        );
    }

    for body in ["lang=hack", "lang=zh-CN", ""] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ui/set-lang")
                    .header(header::REFERER, referer)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "body={body}");
        let lang_cookies: Vec<&str> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter(|c| c.starts_with("crbs_lang="))
            .collect();
        assert_eq!(
            lang_cookies.len(),
            1,
            "body={body}: exactly one crbs_lang Set-Cookie, got {lang_cookies:?}"
        );
        assert!(
            lang_cookies[0].starts_with("crbs_lang=en;"),
            "body={body}: expected fallback cookie, got {:?}",
            lang_cookies[0]
        );
    }
}

/// 回跳目标白名单：仅 /ui/ 开头（且非 // 协议相对）的 Referer 被采纳；站外/非 UI 站内/无 Referer 一律回 /ui/。
#[tokio::test]
async fn set_lang_referer_target_is_whitelisted_to_ui_paths() {
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
            common::post_preference_form(&app, "/ui/set-lang", "lang=zh", Some(referer)).await;
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

    let response = common::post_preference_form(&app, "/ui/set-lang", "lang=zh", None).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/")
    );
}

/// `?lang=zh` 分享链接：Set-Cookie + 本次渲染即中文（不等 cookie 二次往返）；非法值不写 cookie、不影响语言。
#[tokio::test]
async fn lang_query_param_sets_cookie_and_renders_zh_immediately() {
    let (_state, app, _tmp) = setup_app().await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/tasks?lang=zh")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok()),
        Some("crbs_lang=zh; Path=/; Max-Age=31536000; SameSite=Lax; HttpOnly")
    );
    let html = body_text(response).await;
    assert!(
        html.contains("<html lang=\"zh-CN\""),
        "page head: {}",
        &html[..html.len().min(400)]
    );
    // 样板页中文文案：h1（带 count-chip）/ 过滤按钮 / 空态标题（空库 → 空态分支）。
    assert!(
        html.contains("<h1>任务 <span class=\"count-chip\">0</span></h1>"),
        "page head: {}",
        &html[..html.len().min(600)]
    );
    assert!(
        html.contains("过滤</button>"),
        "page head: {}",
        &html[..html.len().min(600)]
    );
    assert!(
        html.contains("未找到任务"),
        "page head: {}",
        &html[..html.len().min(600)]
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/tasks?lang=xx")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter(|c| c.starts_with("crbs_lang="))
        .count();
    assert_eq!(set_cookies, 0, "invalid ?lang= must not set the cookie");
    let html = body_text(response).await;
    assert!(
        html.contains("<h1>Tasks <span class=\"count-chip\">0</span></h1>"),
        "page head: {}",
        &html[..html.len().min(600)]
    );
    assert!(
        html.contains("No tasks found"),
        "page head: {}",
        &html[..html.len().min(600)]
    );
}

/// crbs_lang cookie → 页面中文 + html lang="zh-CN"；非法 cookie 回落 En。
#[tokio::test]
async fn page_respects_crbs_lang_cookie() {
    let (_state, app, _tmp) = setup_app().await;

    let html = get(&app, "/ui/", &[("cookie", "crbs_lang=zh")]).await;
    assert!(
        html.contains("<html lang=\"zh-CN\""),
        "page head: {}",
        &html[..html.len().min(200)]
    );
    assert!(
        html.contains("<h1>仪表盘"),
        "page head: {}",
        &html[..html.len().min(600)]
    );
    assert!(
        html.contains("最近任务"),
        "page head: {}",
        &html[..html.len().min(1200)]
    );

    for cookie in ["crbs_lang=hack", "crbs_lang=ZH", "crbs_token=abc"] {
        let html = get(&app, "/ui/", &[("cookie", cookie)]).await;
        assert!(html.contains("<html lang=\"en\""), "cookie={cookie}");
        assert!(html.contains("<h1>Dashboard"), "cookie={cookie}");
    }

    // 伪造的 x-crbs-lang 覆盖头必须被 middleware 剥除（无 ?lang 时）：客户端输入不得覆盖 cookie 偏好（信任边界）。
    for headers in [
        &[("x-crbs-lang", "zh")] as &[(&str, &str)],
        &[("x-crbs-lang", "zh"), ("cookie", "crbs_lang=en")],
    ] {
        let html = get(&app, "/ui/", headers).await;
        assert!(html.contains("<html lang=\"en\""), "headers={headers:?}");
        assert!(html.contains("<h1>Dashboard"), "headers={headers:?}");
    }

    // 合法 ?lang 参数注入的覆盖头优先于伪造头与 cookie（middleware insert 覆写）。
    let html = get(&app, "/ui/?lang=zh", &[("x-crbs-lang", "en")]).await;
    assert!(
        html.contains("<html lang=\"zh-CN\""),
        "?lang wins over forged header"
    );
}

/// Accept-Language 协商：zh* 前缀 → 中文；非 zh → 英文。
#[tokio::test]
async fn accept_language_negotiates_zh() {
    let (_state, app, _tmp) = setup_app().await;

    for al in ["zh-CN,zh;q=0.9,en;q=0.8", "zh", "zh-TW,en;q=0.5"] {
        let html = get(&app, "/ui/", &[("accept-language", al)]).await;
        assert!(
            html.contains("<html lang=\"zh-CN\""),
            "Accept-Language: {al}"
        );
        assert!(html.contains("仪表盘"), "Accept-Language: {al}");
    }

    for al in ["en-US,en;q=0.9", "ja", "*"] {
        let html = get(&app, "/ui/", &[("accept-language", al)]).await;
        assert!(html.contains("<html lang=\"en\""), "Accept-Language: {al}");
        assert!(html.contains("Dashboard"), "Accept-Language: {al}");
    }

    let html = get(
        &app,
        "/ui/",
        &[("cookie", "crbs_lang=en"), ("accept-language", "zh-CN")],
    )
    .await;
    assert!(
        html.contains("<html lang=\"en\""),
        "cookie beats negotiation"
    );
}

/// nav 语言单按钮：显示当前语言自称（zh 页"中"/en 页"EN"），hidden lang 指向另一语言；aria/title 为"当前 — 切换到目标"语义。
#[tokio::test]
async fn nav_lang_button_shows_current_and_posts_other_language() {
    let (_state, app, _tmp) = setup_app().await;

    let html = get(&app, "/ui/", &[("cookie", "crbs_lang=zh")]).await;
    assert!(
        html.contains(
            r#"<form method="post" action="/ui/set-lang" class="nav-pref-form"><input type="hidden" name="lang" value="en"><input type="hidden" name="csrf_token" value=""><button type="submit" class="nav-icon-btn" title="语言：中 — 切换到 EN" aria-label="语言：中 — 切换到 EN">中</button>"#
        ),
        "zh page button must show 中 and post en: {html}"
    );

    let html = get(&app, "/ui/", &[("cookie", "crbs_lang=en")]).await;
    assert!(
        html.contains(
            r#"<input type="hidden" name="lang" value="zh"><input type="hidden" name="csrf_token" value=""><button type="submit" class="nav-icon-btn" title="Language: EN — switch to 中" aria-label="Language: EN — switch to 中">EN</button>"#
        ),
        "en page button must show EN and post zh: {html}"
    );

    // 语言切换只渲染单按钮，不渲染 .nav-lang 容器。
    assert!(!html.contains("nav-lang"));
}

/// 错误页双语：404 fallback 的标题与提示随语言（cookie / ?lang= 均可达）。
#[tokio::test]
async fn error_page_localizes_title_and_message() {
    let (_state, app, _tmp) = setup_app().await;

    let html = get_expect(
        &app,
        "/ui/nonexistent",
        &[("cookie", "crbs_lang=zh")],
        StatusCode::NOT_FOUND,
    )
    .await;
    assert!(
        html.contains("404 未找到"),
        "page head: {}",
        &html[..html.len().min(600)]
    );
    assert!(
        html.contains("你访问的页面不存在。"),
        "page head: {}",
        &html[..html.len().min(600)]
    );
    assert!(
        html.contains("← 返回仪表盘"),
        "page head: {}",
        &html[..html.len().min(600)]
    );

    // ?lang= 覆盖（middleware 注入 → 错误页渲染同链路）。
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/nonexistent?lang=zh")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let html = body_text(response).await;
    assert!(
        html.contains("404 未找到"),
        "page head: {}",
        &html[..html.len().min(600)]
    );

    let html = get_expect(&app, "/ui/nonexistent", &[], StatusCode::NOT_FOUND).await;
    assert!(
        html.contains("404 Not Found"),
        "page head: {}",
        &html[..html.len().min(600)]
    );
    assert!(
        html.contains("The page you are looking for does not exist."),
        "page head: {}",
        &html[..html.len().min(600)]
    );
}

/// 默认（无任何语言输入）英文回归：样板页与 chrome 不受影响。
#[tokio::test]
async fn english_pages_unchanged_by_default() {
    let (_state, app, _tmp) = setup_app().await;

    let html = get(&app, "/ui/", &[]).await;
    assert!(
        html.contains("<html lang=\"en\""),
        "page head: {}",
        &html[..html.len().min(200)]
    );
    for expected in [
        ">Dashboard</a>",
        ">Builds</a>",
        ">Tasks</a>",
        "Task states",
        "Success rate",
        "Recent tasks",
        "API health",
    ] {
        assert!(html.contains(expected), "missing {expected:?}");
    }

    let html = get(&app, "/ui/tasks", &[]).await;
    assert!(
        html.contains("<h1>Tasks <span class=\"count-chip\">0</span></h1>"),
        "page head: {}",
        &html[..html.len().min(600)]
    );
    assert!(
        html.contains("placeholder=\"e.g. mydist\""),
        "page head: {}",
        &html[..html.len().min(800)]
    );
    assert!(
        html.contains("placeholder=\"e.g. hello\""),
        "page head: {}",
        &html[..html.len().min(800)]
    );
    assert!(!html.contains("全部"), "zh must not leak into en page");
    assert!(
        html.contains("<option value=\"\" selected>All</option>"),
        "page head: {}",
        &html[..html.len().min(800)]
    );
    assert!(
        html.contains("Filter</button>"),
        "page head: {}",
        &html[..html.len().min(800)]
    );
}

/// GET/HEAD /ui/set-lang 未注册（写端点仅 POST）：一律 405，且无 Set-Cookie/Location 副作用。
#[tokio::test]
async fn get_and_head_set_lang_are_method_not_allowed() {
    let (_state, app, _tmp) = setup_app().await;
    common::assert_preference_writer_rejects_get_head(&app, "/ui/set-lang").await;

    let response = common::post_preference_form(&app, "/ui/set-lang", "lang=zh", None).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(cookie.starts_with("crbs_lang=zh;"), "got {cookie}");
    assert!(response.headers().get(header::LOCATION).is_some());
}

/// 303 body 文案与 `<html lang>` 随目标语言输出；oneshot 不自动跟随，直接读 303 body。
#[tokio::test]
async fn set_lang_redirect_body_follows_requested_language() {
    let (_state, app, _tmp) = setup_app().await;
    for (value, needle, html_lang) in [("zh", "正在跳转…", "zh-CN"), ("en", "Redirecting...", "en")]
    {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ui/set-lang")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!("lang={value}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "lang={value}");
        let body = body_text(response).await;
        assert!(body.contains(needle), "lang={value}: {body}");
        assert!(
            body.contains(&format!(r#"lang="{html_lang}""#)),
            "lang={value}: {body}"
        );
    }

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/set-lang")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(""))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let body = body_text(response).await;
    assert!(body.contains("Redirecting..."), "{body}");
    assert!(body.contains(r#"lang="en""#), "{body}");
}
