// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! task/build 操作表单（cancel/rebuild/reproduce）错误 flash 的 zh round-trip 集成测试：
//! 服务层消息是 API JSON 信封共用字面量，UI handler 侧映射双语 key；303 Location 携带编码后中文 flash，GET 回放页逐字呈现。

// seed_* 等测试辅助函数无 #[test] 属性，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::ServerConfig;
use crbs_core::{BuildInsert, TaskInsert};
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;

mod common;

use common::extract_csrf_token;

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
    let admin = seed_user_token_for_test(&app_state.state_store, "act-admin", "admin")
        .await
        .expect("seed admin token");
    let viewer = seed_user_token_for_test(&app_state.state_store, "act-viewer", "viewer")
        .await
        .expect("seed viewer token");
    let app = create_test_app_with_auth(app_state.clone());
    (app_state, app, admin, viewer, tmp)
}

/// GET 任意 UI 页面（完整 cookie 串，便于附加 crbs_lang），返回 (status, html)。
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

/// POST 操作表单（urlencoded + 完整 cookie 串；表单体仅 csrf_token 一个字段），返回 (status, Location)。
async fn post_action_with_cookie(
    app: &axum::Router,
    cookie: &str,
    uri: &str,
    csrf: &str,
) -> (StatusCode, Option<String>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", cookie)
                .body(Body::from(format!("csrf_token={csrf}")))
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

/// 直接经 state 层 seed 一个 task（user 与 admin 的 can_cancel 兼容）。
async fn seed_task(
    state: &AppState,
    phase: &str,
    result_dir: Option<&str>,
    request_json: Option<&str>,
) -> i64 {
    state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name: "act-pkg-1.0-1.fc42",
            user: "ui-tester",
            phase,
            result_dir,
            request_json,
            ..Default::default()
        })
        .await
        .unwrap()
}

/// seed 一个挂到指定 task 的子构建。
async fn seed_build(state: &AppState, task_id: i64, phase: &str) -> i64 {
    state
        .state_store
        .insert_build(BuildInsert {
            task_id: Some(task_id),
            product: "mydist",
            pkg_name: "act-pkg-1.0-1.fc42",
            phase,
            backend: "chroot",
            user: "ui-tester",
            arch: Some("x86_64"),
            ..Default::default()
        })
        .await
        .unwrap()
}

/// cancel Ok 臂 flash（子构建全终态跳过 → "no cancellable child builds"）zh round-trip。
#[tokio::test]
async fn cancel_task_no_cancellable_flash_is_localized_for_zh() {
    let (state, app, admin, _viewer, _tmp) = setup().await;
    let task = seed_task(&state, "building", None, None).await;
    seed_build(&state, task, "succeeded").await;

    let zh_cookie = format!("crbs_token={admin}; crbs_lang=zh");
    let (status, html) = get_page_with_cookie(&app, &zh_cookie, &format!("/ui/tasks/{task}")).await;
    assert_eq!(status, StatusCode::OK);
    let csrf = extract_csrf_token(&html).expect("csrf in task cancel form");

    let (status, location) =
        post_action_with_cookie(&app, &zh_cookie, &format!("/ui/tasks/{task}"), &csrf).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("error redirect carries Location");
    assert!(
        location.starts_with(&format!("/ui/tasks/{task}?error=")),
        "{location}"
    );
    assert!(
        location.contains(urlencoding::encode("没有可取消的子构建").as_ref()),
        "{location}"
    );

    let (status, html) = get_page_with_cookie(&app, &zh_cookie, &location).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("没有可取消的子构建。"),
        "zh flash not rendered: {html}"
    );
}

/// cancel Err 臂 PermissionDenied（viewer 取消他人任务）flash zh round-trip；
/// NotFound 臂的 flash 落在不存在页（GET 404）无法回放断言，故用本变体钉同一 helper 映射。
#[tokio::test]
async fn cancel_task_permission_flash_is_localized_for_zh() {
    let (state, app, _admin, viewer, _tmp) = setup().await;
    let task = seed_task(&state, "building", None, None).await;

    // viewer 页无 cancel 表单，csrf 从 /ui/me 取（csrf 派生自 cookie，与页面无关）。
    let zh_cookie = format!("crbs_token={viewer}; crbs_lang=zh");
    let (_, html) = get_page_with_cookie(&app, &zh_cookie, "/ui/me").await;
    let csrf = extract_csrf_token(&html).expect("csrf in me page form");

    let (status, location) =
        post_action_with_cookie(&app, &zh_cookie, &format!("/ui/tasks/{task}"), &csrf).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("error redirect carries Location");
    assert!(
        location.starts_with(&format!("/ui/tasks/{task}?error=")),
        "{location}"
    );
    assert!(
        location.contains(urlencoding::encode("你没有权限取消该任务").as_ref()),
        "{location}"
    );

    let (status, html) = get_page_with_cookie(&app, &zh_cookie, &location).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("你没有权限取消该任务。"),
        "zh flash not rendered: {html}"
    );
}

/// build cancel Err 臂 PermissionDenied（viewer 取消他人构建）flash zh round-trip。
#[tokio::test]
async fn cancel_build_permission_flash_is_localized_for_zh() {
    let (state, app, _admin, viewer, _tmp) = setup().await;
    let task = seed_task(&state, "building", None, None).await;
    let build = seed_build(&state, task, "building").await;

    let zh_cookie = format!("crbs_token={viewer}; crbs_lang=zh");
    let (_, html) = get_page_with_cookie(&app, &zh_cookie, "/ui/me").await;
    let csrf = extract_csrf_token(&html).expect("csrf in me page form");

    let (status, location) =
        post_action_with_cookie(&app, &zh_cookie, &format!("/ui/builds/{build}"), &csrf).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("error redirect carries Location");
    assert!(
        location.starts_with(&format!("/ui/builds/{build}?error=")),
        "{location}"
    );
    assert!(
        location.contains(urlencoding::encode("你没有权限取消该构建").as_ref()),
        "{location}"
    );

    let (status, html) = get_page_with_cookie(&app, &zh_cookie, &location).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("你没有权限取消该构建。"),
        "zh flash not rendered: {html}"
    );
}

/// rebuild Conflict（source 目录缺失 → GC 语义 409）flash zh round-trip。
#[tokio::test]
async fn rebuild_source_gc_flash_is_localized_for_zh() {
    let (state, app, admin, _viewer, tmp) = setup().await;
    let ghost_dir = tmp.path().join("ghost-results").join("1");
    let task = seed_task(&state, "failed", Some(&ghost_dir.to_string_lossy()), None).await;

    let zh_cookie = format!("crbs_token={admin}; crbs_lang=zh");
    let (_, html) = get_page_with_cookie(&app, &zh_cookie, &format!("/ui/tasks/{task}")).await;
    let csrf = extract_csrf_token(&html).expect("csrf in task rebuild form");

    let (status, location) = post_action_with_cookie(
        &app,
        &zh_cookie,
        &format!("/ui/tasks/{task}/rebuild"),
        &csrf,
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("error redirect carries Location");
    assert!(
        location.starts_with(&format!("/ui/tasks/{task}?error=")),
        "{location}"
    );
    assert!(
        location.contains(urlencoding::encode("源码 SRPM 已不可用").as_ref()),
        "{location}"
    );

    let (status, html) = get_page_with_cookie(&app, &zh_cookie, &location).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("源码 SRPM 已不可用（结果可能已被 GC）；无法重建。"),
        "zh flash not rendered: {html}"
    );
}

/// reproduce Conflict（无记录构建选项；缺 request_json 在读子构建前即 409）flash zh round-trip，与 rebuild 同族但措辞不同、各自钉住。
#[tokio::test]
async fn reproduce_no_options_flash_is_localized_for_zh() {
    let (state, app, admin, _viewer, _tmp) = setup().await;
    let task = seed_task(&state, "failed", None, None).await;

    let zh_cookie = format!("crbs_token={admin}; crbs_lang=zh");
    let (_, html) = get_page_with_cookie(&app, &zh_cookie, &format!("/ui/tasks/{task}")).await;
    let csrf = extract_csrf_token(&html).expect("csrf in task rebuild form");

    let (status, location) = post_action_with_cookie(
        &app,
        &zh_cookie,
        &format!("/ui/tasks/{task}/reproduce"),
        &csrf,
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("error redirect carries Location");
    assert!(
        location.starts_with(&format!("/ui/tasks/{task}?error=")),
        "{location}"
    );
    assert!(
        location.contains(urlencoding::encode("任务未记录构建选项").as_ref()),
        "{location}"
    );

    let (status, html) = get_page_with_cookie(&app, &zh_cookie, &location).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("任务未记录构建选项；无法复现。"),
        "zh flash not rendered: {html}"
    );
}

/// 3 参 key（`FmtKey::FlashReplayChildNotSucceeded`）zh round-trip：request_json 必须在
/// （否则先命中 no-options 409）且子构建 failed（终态非 succeeded）；插参 {0}=task id、{1}=子构建 id、{2}=phase。
#[tokio::test]
async fn reproduce_child_not_succeeded_flash_is_localized_for_zh() {
    let (state, app, admin, _viewer, _tmp) = setup().await;
    let task = seed_task(&state, "failed", None, Some("{}")).await;
    let build = seed_build(&state, task, "failed").await;

    let zh_cookie = format!("crbs_token={admin}; crbs_lang=zh");
    let (_, html) = get_page_with_cookie(&app, &zh_cookie, &format!("/ui/tasks/{task}")).await;
    let csrf = extract_csrf_token(&html).expect("csrf in task action form");

    let (status, location) = post_action_with_cookie(
        &app,
        &zh_cookie,
        &format!("/ui/tasks/{task}/reproduce"),
        &csrf,
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("error redirect carries Location");
    assert!(
        location.starts_with(&format!("/ui/tasks/{task}?error=")),
        "{location}"
    );
    assert!(location.contains(
        urlencoding::encode(&format!("任务 {task} 的子构建 {build} 状态为 failed")).as_ref()
    ));

    let (status, html) = get_page_with_cookie(&app, &zh_cookie, &location).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(&format!(
            "任务 {task} 的子构建 {build} 状态为 failed（只有成功的构建才能复现）。"
        )),
        "zh flash not rendered: {html}"
    );
}
