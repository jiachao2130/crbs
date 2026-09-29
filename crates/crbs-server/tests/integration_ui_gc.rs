// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! GC 管理页（/ui/admin/gc）集成测试：operator+ 门槛、表单默认值、POST 复用 API 触发路径（异步入队 + flash）、无效参数组合 flash error。

// 文件级放行 unwrap/expect：seed_* 等测试辅助函数不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到。
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

use common::extract_csrf_token;

/// GC 后台 task 经 `CrbsConfig::load_async()` 读 CRBS_CONFIG_DIR（可写 tempdir），须先初始化共享配置目录。
async fn setup() -> (
    Arc<AppState>,
    axum::Router,
    String,
    String,
    tempfile::TempDir,
) {
    let _ = common::TEST_CONFIG_DIR.path();
    crbs_server::test_support::init_test_logging();
    let (state_store, tmp) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        state_store,
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let op_token = seed_user_token_for_test(&app_state.state_store, "gc-op", "operator")
        .await
        .expect("seed operator token");
    let viewer_token = seed_user_token_for_test(&app_state.state_store, "gc-viewer", "viewer")
        .await
        .expect("seed viewer token");
    let app = create_test_app_with_auth(app_state.clone());
    (app_state, app, op_token, viewer_token, tmp)
}

async fn get_page(app: &axum::Router, token: &str, path: &str) -> (StatusCode, String) {
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
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn post_gc(
    app: &axum::Router,
    token: &str,
    csrf: &str,
    body: &str,
) -> (StatusCode, Option<String>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/gc")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", format!("crbs_token={token}"))
                .body(Body::from(format!(
                    "csrf_token={csrf}{}",
                    if body.is_empty() {
                        String::new()
                    } else {
                        format!("&{body}")
                    }
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let location = response
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (response.status(), location)
}

/// 普通用户（viewer）GET → 403（与 API can_gc 门槛一致的页面门槛）。
#[tokio::test]
async fn viewer_cannot_access_gc_page() {
    let (_state, app, _op, viewer, _tmp) = setup().await;
    let (status, _body) = get_page(&app, &viewer, "/ui/admin/gc").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// operator GET → 200：dry-run 默认勾选（开关卡片）、历史表重启即失注记、破坏性警示条、GcRequest 对应选项卡片、折叠说明。
#[tokio::test]
async fn operator_gc_page_shows_form_with_dry_run_default() {
    let (_state, app, op, _viewer, _tmp) = setup().await;
    let (status, html) = get_page(&app, &op, "/ui/admin/gc").await;
    assert_eq!(status, StatusCode::OK);
    // maud 空属性开关渲染为裸 checked，包在 .switch 里。
    assert!(
        html.contains(r#"<input type="checkbox" name="dry_run" value="true" checked>"#),
        "dry-run checkbox must default checked: {html}"
    );
    assert!(html.contains(r#"class="switch""#), "{html}");
    assert!(html.contains(r#"class="dryrun-row""#), "{html}");
    for field in ["results", "orphan_mounts", "cache", "all", "policy"] {
        assert!(
            html.contains(&format!(r#"name="{field}""#)),
            "checkbox '{field}' missing: {html}"
        );
        assert!(
            !html.contains(&format!(r#"name="{field}" value="true" checked>"#)),
            "checkbox '{field}' must default unchecked: {html}"
        );
    }
    assert!(html.contains(r#"class="gc-opt""#), "{html}");
    assert!(html.contains(r#"name="product""#), "{html}");
    assert!(html.contains("cleared on restart"), "{html}");
    assert!(html.contains("Dry-run"), "{html}");
    // SSR 安全方向：danger + data-confirm，无 JS 时确认后才提交；dry-run 默认勾选，误确认也只多跑一次 dry-run。
    assert!(html.contains(r#"id="gc-submit-btn""#), "{html}");
    assert!(
        html.contains(r#"class="action-button danger" type="submit" id="gc-submit-btn""#),
        "{html}"
    );
    assert!(html.contains("Run GC without dry-run:"), "{html}");
    assert!(html.contains("gc-destructive-warning"), "{html}");
    assert!(html.contains(r#"<details class="help">"#), "{html}");
    assert!(html.contains("What does GC do?"), "{html}");
}

/// POST dry-run + results → 303 flash 成功，gc_tasks 异步入队（与 API `POST /api/v1/gc` 的 202 入队同路径），GET 回页渲染 flash 与历史表行。
#[tokio::test]
async fn post_dry_run_triggers_gc_task_and_flashes() {
    let (state, app, op, _viewer, _tmp) = setup().await;

    let (status, html) = get_page(&app, &op, "/ui/admin/gc").await;
    assert_eq!(status, StatusCode::OK);
    let csrf = extract_csrf_token(&html).expect("CSRF token in gc form");

    let (status, location) = post_gc(&app, &op, &csrf, "dry_run=true&results=true").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location.as_deref(),
        Some("/ui/admin/gc?status=gc_started"),
        "success must redirect with gc_started flash: {location:?}"
    );

    {
        let tasks = state.gc_tasks.lock().await;
        assert_eq!(tasks.len(), 1, "gc task must be registered");
    }

    let (status, html) = get_page(&app, &op, "/ui/admin/gc?status=gc_started").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Garbage collection started."), "{html}");

    // 等后台 GC 到终态，避免测试运行时退出时任务被中断。
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let done = {
                let tasks = state.gc_tasks.lock().await;
                tasks
                    .values()
                    .all(|t| !matches!(t.status, crbs_server::server::state::GcTaskStatus::Running))
            };
            if done {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;

    // 终态打点：finished_at 与 status 同锁写入，且不早于 started_at。
    {
        let tasks = state.gc_tasks.lock().await;
        let t = tasks
            .values()
            .next()
            .expect("gc task retained after terminal state");
        assert!(
            !matches!(t.status, crbs_server::server::state::GcTaskStatus::Running),
            "task must be terminal here"
        );
        let finished = t
            .finished_at
            .expect("finished_at stamped on terminal state");
        assert!(
            finished >= t.started_at,
            "finished_at {finished} < started_at {}",
            t.started_at
        );
    }

    // 终态后历史表：chips 统计，Duration 列渲染真实时长（finished_at 秒差过 format_duration_secs）。
    let (status, html) = get_page(&app, &op, "/ui/admin/gc").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(r#"class="chips""#), "{html}");
    assert!(html.contains("results <b>"), "{html}");
    assert!(html.contains(r#"<th class="num">Duration</th>"#), "{html}");
    // 轮询窗口 10s 内必达终态 → Duration 为秒级，渲染 "Ns" 文本。
    let duration_rendered =
        (0..=15).any(|n| html.contains(&format!(r#"<td class="num">{n}s</td>"#)));
    assert!(
        duration_rendered,
        "duration cell should render real seconds: {html}"
    );
}

/// 无效参数组合（dry_run 无任何 scope）→ validate_gc_request 拒绝 → 303 flash error（带签名），GET 回页渲染具体错误文本。
#[tokio::test]
async fn post_invalid_combo_flashes_error() {
    let (_state, app, op, _viewer, _tmp) = setup().await;
    let (status, html) = get_page(&app, &op, "/ui/admin/gc").await;
    assert_eq!(status, StatusCode::OK);
    let csrf = extract_csrf_token(&html).expect("CSRF token in gc form");

    let (status, location) = post_gc(&app, &op, &csrf, "dry_run=true").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("error redirect carries Location");
    assert!(
        location.starts_with("/ui/admin/gc?error="),
        "expected error flash redirect, got: {location}"
    );
    assert!(
        location.contains("&es="),
        "error flash must be signed: {location}"
    );

    let (status, html) = get_page(&app, &op, &location).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("dry_run must be used with results, orphan_mounts, cache, or policy"),
        "{html}"
    );
}

/// CSRF 伪造：有效 operator 会话 + 真 token 篡改一位回发 → 403，且无副作用（gc_tasks 不入列、审计无新行）。
#[tokio::test]
async fn post_with_tampered_csrf_token_is_rejected_without_side_effects() {
    let (state, app, op, _viewer, _tmp) = setup().await;
    let (status, html) = get_page(&app, &op, "/ui/admin/gc").await;
    assert_eq!(status, StatusCode::OK);
    let real = extract_csrf_token(&html).expect("CSRF token in gc form");

    let mut chars: Vec<char> = real.chars().collect();
    let last = chars.pop().expect("non-empty csrf token");
    chars.push(if last == 'a' { 'b' } else { 'a' });
    let forged: String = chars.into_iter().collect();
    assert_ne!(forged, real);

    let (status, _location) = post_gc(&app, &op, &forged, "dry_run=true&results=true").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // action="gc" 是 start_gc_task 的唯一审计动作，该过滤即覆盖。
    {
        let tasks = state.gc_tasks.lock().await;
        assert!(
            tasks.is_empty(),
            "forged CSRF must not enqueue a GC task: {tasks:?}"
        );
    }
    let logs = state
        .state_store
        .list_audit_logs(crbs_core::AuditLogFilter {
            action: Some("gc"),
            ..Default::default()
        })
        .await
        .expect("list audit logs");
    assert!(logs.is_empty(), "forged CSRF must not write audit rows");
}

/// zh round-trip：validate_gc_request 的 Validation 按字面量映射双语 key（en 行为由 post_invalid_combo_flashes_error 钉住）。
#[tokio::test]
async fn post_invalid_combo_flash_is_localized_for_zh() {
    let (_state, app, op, _viewer, _tmp) = setup().await;
    let (status, html) = get_page(&app, &op, "/ui/admin/gc").await;
    assert_eq!(status, StatusCode::OK);
    let csrf = extract_csrf_token(&html).expect("CSRF token in gc form");

    // zh cookie：POST handler 与页面渲染共用同一 lang 协商。
    let zh_cookie = format!("crbs_token={op}; crbs_lang=zh");
    let (status, location) = post_gc_with_cookie(&app, &zh_cookie, &csrf, "dry_run=true").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("error redirect carries Location");
    assert!(location.starts_with("/ui/admin/gc?error="), "{location}");
    assert!(
        location.contains(urlencoding::encode("dry_run 需与").as_ref()),
        "{location}"
    );

    let (status, html) = get_page_with_cookie(&app, &zh_cookie, &location).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("dry_run 需与 results、orphan_mounts、cache 或 policy 一起使用。"),
        "zh flash not rendered: {html}"
    );
}

/// POST GC 表单（完整 cookie 串，便于附加 crbs_lang）。
async fn post_gc_with_cookie(
    app: &axum::Router,
    cookie: &str,
    csrf: &str,
    body: &str,
) -> (StatusCode, Option<String>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/gc")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", cookie)
                .body(Body::from(format!(
                    "csrf_token={csrf}{}",
                    if body.is_empty() {
                        String::new()
                    } else {
                        format!("&{body}")
                    }
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let location = response
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (response.status(), location)
}

async fn get_page_with_cookie(app: &axum::Router, cookie: &str, uri: &str) -> (StatusCode, String) {
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
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}
