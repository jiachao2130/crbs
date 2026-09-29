// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 提交构建页 /ui/tasks/new 集成测试。复用 crbs_token cookie 会话 + 表单内嵌
//! CSRF（multipart 文本字段）；上传走与 API 相同的 multipart 提取与提交核心，
//! 文件名与内容（RPM 魔数 ED AB EE DB）均在 extractor 校验；坏包提交期就地
//! 回显（见 post_bad_srpm_rerenders_form_with_error）。

// 测试 crate：辅助函数不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::{ProductConfig, ServerConfig};
use crbs_core::AuditLogFilter;
use crbs_core::CreateProductInput;
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;

mod common;

use common::TEST_CONFIG_DIR;

/// 声明双架构的产品（data-arches 数据源）。
const ARCH_TOML: &str = "\
base_packages = [\"bash\", \"rpm-build\"]
arches = [\"x86_64\", \"aarch64\"]

[[repos]]
name = \"base\"
baseurl = \"http://example.com/base/$basearch\"
gpgcheck = false
";

async fn setup_app(
    roles: &[(&str, &str)],
) -> (
    Arc<AppState>,
    axum::Router,
    tempfile::TempDir,
    HashMap<String, String>,
) {
    let _ = TEST_CONFIG_DIR.path();
    crbs_server::test_support::init_test_logging();
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    // 测试临时目录可能不足默认 1GB，禁用磁盘空间检查（integration_multi_arch 同款）。
    let app_state = Arc::new(AppState::for_test(
        state_store,
        ServerConfig {
            min_free_disk_gb: 0,
            ..Default::default()
        },
        tmp_dir.path().to_path_buf(),
    ));

    let mut tokens = HashMap::new();
    for (name, role) in roles {
        let raw = seed_user_token_for_test(&app_state.state_store, name, role)
            .await
            .expect("seed user token");
        tokens.insert((*name).to_string(), raw);
    }
    let app = create_test_app_with_auth(app_state.clone());
    (app_state, app, tmp_dir, tokens)
}

async fn user_id(state: &AppState, name: &str) -> i64 {
    state
        .state_store
        .find_user_by_name(name)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("user '{name}' should exist"))
        .id
}

async fn seed_product(state: &AppState, name: &str, owner_id: Option<i64>, toml: &str) {
    let config = ProductConfig::from_str(toml).unwrap_or_else(|e| panic!("toml parses: {e}"));
    state
        .state_store
        .create_product(CreateProductInput {
            name,
            display_name: None,
            owner_id,
            parent_id: None,
            visibility: if owner_id.is_some() {
                "private"
            } else {
                "public"
            },
            config: &config,
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap_or_else(|e| panic!("seed product '{name}': {e}"));
}

/// 构造能过 magic 预检的假 SRPM：[`crbs_core::util::RPM_MAGIC`] 4 字节前缀 + 任意负载。
/// 合法最小 SRPM（NEVR=hello-1.0-1）：提交入口按 header N-V-R 解析任务真名，
/// 非 RPM 字节会被 400 拒——表单成功路径必须喂真包。
fn hello_srpm() -> Vec<u8> {
    std::fs::read(env!("CARGO_MANIFEST_DIR").to_owned() + "/tests/fixtures/hello-1.0-1.src.rpm")
        .expect("test fixture SRPM missing")
}

fn multipart_body(boundary: &str, fields: &[(&str, &str)], files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    for (file_name, content) in files {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"srpm\"; filename=\"{file_name}\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(content);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

async fn get_new_task_page(app: &axum::Router, token: Option<&str>) -> (StatusCode, String) {
    let mut builder = Request::builder().uri("/ui/tasks/new");
    if let Some(t) = token {
        builder = builder.header("Cookie", format!("crbs_token={t}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// POST /ui/tasks/new（可选 XHR 头），返回 (status, Location, body, Content-Type)。
async fn post_new_task(
    app: &axum::Router,
    token: &str,
    body: Vec<u8>,
    xhr: bool,
) -> (StatusCode, Option<String>, String, Option<String>) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/ui/tasks/new")
        .header("Cookie", format!("crbs_token={token}"))
        .header("Content-Type", "multipart/form-data; boundary=crbstest");
    if xhr {
        builder = builder.header("X-Requested-With", "crbs-ui");
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let content_type = response
        .headers()
        .get("Content-Type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        location,
        String::from_utf8_lossy(&bytes).into_owned(),
        content_type,
    )
}

fn task_id_from_location(location: &str) -> i64 {
    location
        .strip_prefix("/ui/tasks/")
        .and_then(|rest| rest.split('?').next())
        .and_then(|id| id.parse().ok())
        .unwrap_or_else(|| panic!("unexpected location: {location}"))
}

async fn task_count(state: &AppState) -> usize {
    state
        .state_store
        .list_tasks(&crbs_core::types::TaskListFilter::default())
        .await
        .expect("list tasks")
        .0
}

/// viewer GET → 403（builder+ 门禁）。
#[tokio::test]
async fn viewer_get_denied() {
    let (_state, app, _tmp, tokens) = setup_app(&[("carol", "viewer"), ("bob", "builder")]).await;
    let (status, _html) = get_new_task_page(&app, Some(&tokens["carol"])).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// builder GET → 200：表单要素齐全（csrf 隐藏域、data-arches、noscript arch
/// 回退、优先级下拉、进度脚本），下拉只含可提交产品（builder 按 ACL 收窄，admin 全量）。
#[tokio::test]
async fn builder_get_renders_form_and_filters_products() {
    let (state, app, _tmp, tokens) = setup_app(&[
        ("admin-op", "admin"),
        ("ora", "operator"),
        ("alice", "builder"),
        ("bob", "builder"),
    ])
    .await;
    let bob = user_id(&state, "bob").await;
    let alice = user_id(&state, "alice").await;
    seed_product(&state, "mydist", None, ARCH_TOML).await;
    seed_product(&state, "mypriv", Some(bob), ARCH_TOML).await;
    // alice 有 mydist 的 builder ACL → allowed_products=[mydist]，mypriv 不可提交。
    state
        .state_store
        .grant_product_acl_with_role(alice, "mydist", "builder")
        .await
        .expect("grant alice acl");

    let (status, html) = get_new_task_page(&app, Some(&tokens["alice"])).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(r#"<form class="form-card" id="new-task-form""#),
        "{html}"
    );
    assert!(html.contains(r#"name="csrf_token""#), "{html}");
    assert!(
        html.contains(r#"data-arches="x86_64,aarch64""#),
        "declared arches missing from options: {html}"
    );
    assert!(
        html.contains(r#"name="arch""#),
        "noscript arch fallback missing: {html}"
    );
    assert!(html.contains(r#"<option value="0""#), "{html}");
    assert!(html.contains(r#"<option value="1""#), "{html}");
    assert!(
        !html.contains(r#"<option value="2""#),
        "critical requires operator role: {html}"
    );
    // 进度脚本（nonce 内联 + XHR 头标记 + 上限预检）。
    assert!(html.contains("X-Requested-With"), "{html}");
    assert!(html.contains("upload-progress"), "{html}");
    assert!(html.contains(r#"<option value="mydist""#), "{html}");
    assert!(
        !html.contains(r#"<option value="mypriv""#),
        "product without submit permission must be filtered out: {html}"
    );

    // 产品 owner（无 ACL 记录）视角：两个都可见（空 ACL = 不限 + owner 可见）。
    let (status, html) = get_new_task_page(&app, Some(&tokens["bob"])).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(r#"<option value="mydist""#), "{html}");
    assert!(html.contains(r#"<option value="mypriv""#), "{html}");

    // operator 视角：critical 选项可见（is_operator 放行，含 admin）；私有产品
    // 内容级可见性无 operator bypass（仅 owner/admin/ACL），下拉仍只含 mydist。
    let (status, html) = get_new_task_page(&app, Some(&tokens["ora"])).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(r#"<option value="mydist""#), "{html}");
    assert!(
        !html.contains(r#"<option value="mypriv""#),
        "private product content visibility has no operator bypass: {html}"
    );
    assert!(html.contains(r#"<option value="2""#), "{html}");

    let (status, html) = get_new_task_page(&app, Some(&tokens["admin-op"])).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(r#"<option value="mydist""#), "{html}");
    assert!(html.contains(r#"<option value="mypriv""#), "{html}");
    assert!(html.contains(r#"<option value="2""#), "{html}");
}

/// 标签输入：空行 + 添加按钮 + 克隆模板齐全；提交的重复 label 字段入库，
/// 空行（无 JS 时留下的空输入）被忽略。
#[tokio::test]
async fn label_rows_render_and_submit_persists_labels() {
    let (state, app, _tmp, tokens) = setup_app(&[("bob", "builder")]).await;
    seed_product(&state, "mydist", None, ARCH_TOML).await;
    let (status, html) = get_new_task_page(&app, Some(&tokens["bob"])).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(r#"<div class="label-rows" id="label-rows">"#),
        "{html}"
    );
    assert!(html.contains(r#"id="label-add-button""#), "{html}");
    assert!(
        html.contains(r#"<template id="label-row-template">"#),
        "{html}"
    );
    assert!(
        html.contains(r#"name="label" value="" placeholder="key=value" maxlength="321""#),
        "{html}"
    );
    let csrf = common::extract_csrf_token(&html).expect("CSRF token on form");

    let body = multipart_body(
        "crbstest",
        &[
            ("csrf_token", &csrf),
            ("product", "mydist"),
            ("label", "ci=1234"),
            ("label", ""),
            ("label", "branch=main"),
        ],
        &[("hello-1.0-1.src.rpm", &hello_srpm())],
    );
    let (status, location, _body, _ct) = post_new_task(&app, &tokens["bob"], body, false).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let task_id = task_id_from_location(&location.expect("success redirect"));
    assert_eq!(
        state
            .state_store
            .get_task_labels(task_id)
            .await
            .expect("get task labels"),
        vec![
            ("branch".to_string(), "main".to_string()),
            ("ci".to_string(), "1234".to_string()),
        ]
    );
}

/// ACL 仅为 viewer 的产品：GET 下拉排除（提交会被拒，见下方 POST 用例）。
#[tokio::test]
async fn viewer_acl_product_excluded_from_dropdown() {
    let (state, app, _tmp, tokens) = setup_app(&[("alice", "builder")]).await;
    let alice = user_id(&state, "alice").await;
    seed_product(&state, "mydist", None, ARCH_TOML).await;
    state
        .state_store
        .grant_product_acl_with_role(alice, "mydist", "viewer")
        .await
        .expect("grant viewer acl");

    let (status, html) = get_new_task_page(&app, Some(&tokens["alice"])).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !html.contains(r#"<option value="mydist""#),
        "viewer-only ACL product must be excluded: {html}"
    );
}

#[tokio::test]
async fn tasks_list_shows_new_build_link_for_builder_only() {
    let (_state, app, _tmp, tokens) = setup_app(&[("bob", "builder"), ("carol", "viewer")]).await;
    for (token, expect) in [(&tokens["bob"], true), (&tokens["carol"], false)] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ui/tasks")
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
        let html = String::from_utf8_lossy(&bytes).into_owned();
        assert_eq!(
            html.contains(r#"href="/ui/tasks/new""#),
            expect,
            "new-build link visibility wrong: {html}"
        );
    }
}

#[tokio::test]
async fn post_with_missing_or_bad_csrf_rejected() {
    let (state, app, _tmp, tokens) = setup_app(&[("bob", "builder")]).await;
    seed_product(&state, "mydist", None, ARCH_TOML).await;
    let (status, _html) = get_new_task_page(&app, Some(&tokens["bob"])).await;
    assert_eq!(status, StatusCode::OK);

    let body = multipart_body(
        "crbstest",
        &[("product", "mydist")],
        &[("hello-1.0-1.src.rpm", &hello_srpm())],
    );
    let (status, location, _body, _ct) = post_new_task(&app, &tokens["bob"], body, false).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(location.is_none());

    let body = multipart_body(
        "crbstest",
        &[("csrf_token", "deadbeef"), ("product", "mydist")],
        &[("hello-1.0-1.src.rpm", &hello_srpm())],
    );
    let (status, _location, _body, _ct) = post_new_task(&app, &tokens["bob"], body, false).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // CSRF 失败路径回收了 .incoming 暂存（不泄漏已落盘文件）。
    let incoming = state.upload_dir().join(".incoming");
    let left: Vec<_> = std::fs::read_dir(&incoming)
        .map(|rd| rd.filter_map(|e| e.ok()).collect())
        .unwrap_or_default();
    assert!(
        left.is_empty(),
        ".incoming must be cleaned after CSRF failure"
    );
    assert!(task_count(&state).await == 0);
}

/// 成功提交：303 → /ui/tasks/{id}?status=submitted；store 里有 pending 任务；
/// 审计行带 source=ui；详情页渲染 submitted flash。
#[tokio::test]
async fn post_success_redirects_to_task_detail_and_audits() {
    let (state, app, _tmp, tokens) = setup_app(&[("bob", "builder")]).await;
    seed_product(&state, "mydist", None, ARCH_TOML).await;
    let (status, html) = get_new_task_page(&app, Some(&tokens["bob"])).await;
    assert_eq!(status, StatusCode::OK);
    let csrf = common::extract_csrf_token(&html).expect("CSRF token on form");

    let body = multipart_body(
        "crbstest",
        &[
            ("csrf_token", &csrf),
            ("product", "mydist"),
            ("priority", "0"),
        ],
        &[("hello-1.0-1.src.rpm", &hello_srpm())],
    );
    let (status, location, _body, _ct) = post_new_task(&app, &tokens["bob"], body, false).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("success redirect carries Location");
    let task_id = task_id_from_location(&location);
    assert_eq!(
        location,
        format!("/ui/tasks/{task_id}?status=submitted"),
        "unexpected location: {location}"
    );

    let task = state
        .state_store
        .get_task(task_id)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("task {task_id} exists"));
    assert_eq!(task.product, "mydist");
    assert_eq!(task.phase, "pending");
    assert_eq!(task.user, "bob");

    let logs = state
        .state_store
        .list_audit_logs(AuditLogFilter {
            action: Some("submit_build"),
            ..Default::default()
        })
        .await
        .expect("list audit logs");
    assert_eq!(logs.len(), 1, "exactly one submit_build audit row");
    assert_eq!(logs[0].user, "bob");
    let detail = logs[0].detail.as_deref().expect("audit detail present");
    assert!(detail.contains("\"source\":\"ui\""), "detail: {detail}");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&location)
                .header("Cookie", format!("crbs_token={}", tokens["bob"]))
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
    // flash 文案 "Task submitted." 为术语定则（非笔误）。
    assert!(html.contains("Task submitted."), "flash missing: {html}");
}

/// noscript 空 arch 字段视为未提交：按提示"留空使用默认架构"操作的请求走
/// 产品默认架构成功（multipart 提取期跳过空段，见 multipart.rs）。
#[tokio::test]
async fn post_with_blank_arch_uses_product_default() {
    let (state, app, _tmp, tokens) = setup_app(&[("bob", "builder")]).await;
    seed_product(&state, "mydist", None, ARCH_TOML).await;
    let (status, html) = get_new_task_page(&app, Some(&tokens["bob"])).await;
    assert_eq!(status, StatusCode::OK);
    let csrf = common::extract_csrf_token(&html).expect("CSRF token on form");

    let body = multipart_body(
        "crbstest",
        &[("csrf_token", &csrf), ("product", "mydist"), ("arch", "")],
        &[("hello-1.0-1.src.rpm", &hello_srpm())],
    );
    let (status, location, _body, _ct) = post_new_task(&app, &tokens["bob"], body, false).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "blank arch must be treated as not submitted: {location:?}"
    );
}

/// 验证失败（arch 合法但不在产品声明集）→ 200 重渲染表单 + 错误横幅 + 保留
/// product 输入。未知产品名走磁盘产品向后兼容反而可提交成功，故失败路径用
/// 未声明 arch 触发；格式非法 arch 在提取期即被拒且不回填，错误横幅两条路径一致。
#[tokio::test]
async fn post_undeclared_arch_rerenders_form_with_error() {
    let (state, app, _tmp, tokens) = setup_app(&[("bob", "builder")]).await;
    seed_product(&state, "mydist", None, ARCH_TOML).await;
    let (status, html) = get_new_task_page(&app, Some(&tokens["bob"])).await;
    assert_eq!(status, StatusCode::OK);
    let csrf = common::extract_csrf_token(&html).expect("CSRF token on form");

    let body = multipart_body(
        "crbstest",
        &[
            ("csrf_token", &csrf),
            ("product", "mydist"),
            ("arch", "ppc64le"),
            ("label", "ci=1234"),
            ("label", "branch=main"),
        ],
        &[("hello-1.0-1.src.rpm", &hello_srpm())],
    );
    let (status, location, body, ct) = post_new_task(&app, &tokens["bob"], body, false).await;
    assert_eq!(status, StatusCode::OK, "re-rendered form must be 200");
    assert!(location.is_none(), "re-render must not carry a Location");
    assert!(ct.as_deref().is_none_or(|c| c.starts_with("text/html")));
    assert!(
        body.contains("Submit failed:"),
        "localized error banner missing: {body}"
    );
    assert!(
        body.contains("ppc64le"),
        "machine error detail should be shown: {body}"
    );
    // 保留用户输入：product 回选（selected 在 data-arches 之后渲染）。
    assert!(
        body.contains(r#"<option value="mydist" data-arches="x86_64,aarch64" selected"#),
        "product selection must be preserved: {body}"
    );
    assert!(
        body.contains(r#"value="ppc64le" placeholder="x86_64,aarch64""#),
        "noscript arch input must be refilled: {body}"
    );
    assert!(
        body.contains(r#"id="arch-checkboxes" data-selected="ppc64le""#),
        "preserved arch must reach the JS checkbox group via data-selected: {body}"
    );
    // 标签行按提交值回显（行数与内容保留）。
    assert!(
        body.contains(r#"name="label" value="ci=1234""#),
        "submitted labels must be preserved: {body}"
    );
    assert!(
        body.contains(r#"name="label" value="branch=main""#),
        "submitted labels must be preserved: {body}"
    );
    assert!(task_count(&state).await == 0);
}

/// 坏包（垃圾内容，无 RPM 魔数）→ 提取期 200 就地回显：错误横幅（message
/// failure）带机器消息与文件名，不建任务、不留 .incoming 上传副本。
#[tokio::test]
async fn post_bad_srpm_rerenders_form_with_error() {
    let (state, app, _tmp, tokens) = setup_app(&[("bob", "builder")]).await;
    seed_product(&state, "mydist", None, ARCH_TOML).await;
    let (status, html) = get_new_task_page(&app, Some(&tokens["bob"])).await;
    assert_eq!(status, StatusCode::OK);
    let csrf = common::extract_csrf_token(&html).expect("CSRF token on form");

    let body = multipart_body(
        "crbstest",
        &[("csrf_token", &csrf), ("product", "mydist")],
        &[("bad-1.0-1.src.rpm", b"garbage")],
    );
    let (status, location, body, ct) = post_new_task(&app, &tokens["bob"], body, false).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "bad srpm re-renders in place: {body}"
    );
    assert!(
        location.is_none(),
        "bad srpm must not redirect: {location:?}"
    );
    assert!(ct.as_deref().is_none_or(|c| c.starts_with("text/html")));
    assert!(
        body.contains(r#"class="message failure""#),
        "failure banner element missing: {body}"
    );
    assert!(
        body.contains("Submit failed:"),
        "localized error banner missing: {body}"
    );
    assert!(
        body.contains("bad-1.0-1.src.rpm"),
        "machine error should name the rejected file: {body}"
    );
    assert!(
        body.contains("magic"),
        "machine error should mention magic bytes: {body}"
    );
    assert!(task_count(&state).await == 0);
    let incoming = state.upload_dir().join(".incoming");
    let left: Vec<_> = std::fs::read_dir(&incoming)
        .map(|rd| rd.filter_map(|e| e.ok()).collect())
        .unwrap_or_default();
    assert!(
        left.is_empty(),
        ".incoming must be cleaned after bad srpm rejection"
    );
}

/// viewer ACL 产品上的提交 → 权限失败重渲染（ensure_can_submit_to_product 口径）。
#[tokio::test]
async fn post_to_viewer_acl_product_rerenders_with_error() {
    let (state, app, _tmp, tokens) = setup_app(&[("alice", "builder")]).await;
    let alice = user_id(&state, "alice").await;
    seed_product(&state, "mydist", None, ARCH_TOML).await;
    state
        .state_store
        .grant_product_acl_with_role(alice, "mydist", "viewer")
        .await
        .expect("grant viewer acl");
    let (status, html) = get_new_task_page(&app, Some(&tokens["alice"])).await;
    assert_eq!(status, StatusCode::OK);
    let csrf = common::extract_csrf_token(&html).expect("CSRF token on form");

    let body = multipart_body(
        "crbstest",
        &[("csrf_token", &csrf), ("product", "mydist")],
        &[("hello-1.0-1.src.rpm", &hello_srpm())],
    );
    let (status, _location, body, _ct) = post_new_task(&app, &tokens["alice"], body, false).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "permission failure re-renders: {body}"
    );
    // alice 无任何可提交产品（viewer ACL 产品已被下拉过滤）→ 空态 + 错误横幅（不静默吞错）。
    assert!(
        body.contains("viewer access"),
        "permission error banner missing: {body}"
    );
    assert!(
        body.contains("No products available"),
        "empty state expected: {body}"
    );
    assert!(task_count(&state).await == 0);
}

/// XHR 模式：成功 → 200 JSON redirect；失败 → 200 JSON error（非 HTML 错误页）。
#[tokio::test]
async fn xhr_mode_returns_json_redirect_or_error() {
    let (state, app, _tmp, tokens) = setup_app(&[("bob", "builder")]).await;
    seed_product(&state, "mydist", None, ARCH_TOML).await;
    let (status, html) = get_new_task_page(&app, Some(&tokens["bob"])).await;
    assert_eq!(status, StatusCode::OK);
    let csrf = common::extract_csrf_token(&html).expect("CSRF token on form");

    let body = multipart_body(
        "crbstest",
        &[("csrf_token", &csrf), ("product", "mydist")],
        &[("hello-1.0-1.src.rpm", &hello_srpm())],
    );
    let (status, location, body, ct) = post_new_task(&app, &tokens["bob"], body, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(location.is_none(), "XHR success must not 303");
    assert!(
        ct.as_deref()
            .is_some_and(|c| c.starts_with("application/json")),
        "content type: {ct:?}"
    );
    let json: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("{e}: {body}"));
    let redirect = json["redirect"]
        .as_str()
        .unwrap_or_else(|| panic!("{body}"));
    let task_id = task_id_from_location(redirect);
    assert_eq!(redirect, format!("/ui/tasks/{task_id}?status=submitted"));
    assert!(state.state_store.get_task(task_id).await.unwrap().is_some());

    // 失败（坏 csrf + XHR）→ 200 JSON error（error_page 中间件不重写 200）。
    let body = multipart_body(
        "crbstest",
        &[("csrf_token", "deadbeef"), ("product", "mydist")],
        &[("hello-1.0-1.src.rpm", &hello_srpm())],
    );
    let (status, location, body, ct) = post_new_task(&app, &tokens["bob"], body, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(location.is_none());
    assert!(
        ct.as_deref()
            .is_some_and(|c| c.starts_with("application/json")),
        "content type: {ct:?}"
    );
    let json: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("{e}: {body}"));
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|s| s.contains("Submit failed")),
        "error json: {body}"
    );
}
