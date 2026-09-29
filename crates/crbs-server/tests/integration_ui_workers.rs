// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Worker 详情页 Admin actions（UI 表单 POST）集成测试：复用 crbs_token cookie
//! 会话（auth 接受该 cookie；表单内嵌 session 派生的 CSRF token，提取后回发）。

// 文件级放行：辅助函数不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::auth::secret::SecretHash;
use crbs_core::AuditLogFilter;

mod common;

use common::extract_csrf_token;
use common::setup_app_with_admin;

/// 用 crbs_token cookie 会话 GET 详情页，提取表单内嵌的 CSRF token。
async fn csrf_for_worker_page(app: &axum::Router, admin_token: &str, worker_id: i64) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ui/workers/{worker_id}"))
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
    let text = String::from_utf8_lossy(&bytes);
    extract_csrf_token(&text).expect("CSRF token should be present in admin forms")
}

async fn post_worker_action(
    app: &axum::Router,
    admin_token: &str,
    worker_id: i64,
    form_body: String,
) -> (StatusCode, Option<String>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/workers/{worker_id}"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", format!("crbs_token={admin_token}"))
                .body(Body::from(form_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let location = response
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    (response.status(), location)
}

/// 用 crbs_token cookie 会话 GET 列表页，返回 200 响应的 HTML 文本。
async fn get_workers_page(app: &axum::Router, admin_token: &str, uri: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
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

/// 匿名 GET（无 cookie/Authorization）：用于公开访问边界断言。
async fn get_workers_page_anonymous(app: &axum::Router, uri: &str) -> String {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// 统计 HTML 中 worker 数据行数（每行一个 class="clickable-row"）。
fn count_worker_rows(html: &str) -> usize {
    html.matches("class=\"clickable-row\"").count()
}

/// admin POST action=init（在线 worker + 合法 product）→ 303 回详情页且带
/// status=init_dispatched，DB 出现活跃 init assignment 与 init_base_os 审计行。
#[tokio::test]
async fn admin_init_action_dispatches_base_os_init() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let worker_id = state
        .state_store
        .upsert_worker("build-worker", "x86_64", 2, "test", "online", None)
        .await
        .expect("upsert online worker");

    let csrf = csrf_for_worker_page(&app, &admin_token, worker_id).await;
    let (status, location) = post_worker_action(
        &app,
        &admin_token,
        worker_id,
        format!("action=init&product=mydist&csrf_token={csrf}"),
    )
    .await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    let expected = format!("/ui/workers/{worker_id}?status=init_dispatched");
    assert_eq!(
        location.as_deref(),
        Some(expected.as_str()),
        "success should redirect with init_dispatched status"
    );

    assert!(
        state
            .state_store
            .has_active_init(worker_id, "mydist")
            .await
            .expect("query active init"),
        "init assignment should be active after dispatch"
    );

    let logs = state
        .state_store
        .list_audit_logs(AuditLogFilter {
            action: Some("init_base_os"),
            ..Default::default()
        })
        .await
        .expect("list audit logs");
    assert_eq!(logs.len(), 1, "exactly one init_base_os audit row");
    let expected_target = worker_id.to_string();
    assert_eq!(logs[0].target.as_deref(), Some(expected_target.as_str()));
    let detail = logs[0].detail.as_deref().expect("audit detail present");
    assert!(
        detail.contains("\"product\":\"mydist\""),
        "detail: {detail}"
    );
    assert!(
        detail.contains("\"worker_name\":\"build-worker\""),
        "detail: {detail}"
    );
}

/// worker 离线时 init 被拒绝：303 带 error，且不产生 init assignment。
#[tokio::test]
async fn admin_init_action_rejects_offline_worker() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let worker_id = state
        .state_store
        .upsert_worker("sleepy-worker", "x86_64", 1, "test", "online", None)
        .await
        .expect("upsert worker");
    state
        .state_store
        .worker_mark_offline(worker_id)
        .await
        .expect("mark worker offline");

    let csrf = csrf_for_worker_page(&app, &admin_token, worker_id).await;
    let (status, location) = post_worker_action(
        &app,
        &admin_token,
        worker_id,
        format!("action=init&product=mydist&csrf_token={csrf}"),
    )
    .await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("error redirect carries Location");
    assert!(
        location.contains("error=") && location.contains("offline"),
        "offline worker should be rejected with error, got {location}"
    );
    assert!(
        !state
            .state_store
            .has_active_init(worker_id, "mydist")
            .await
            .expect("query active init"),
        "no init assignment should be created for offline worker"
    );
}

/// admin POST action=rotate → 200 渲染 secret reveal box（经 worker::admin 共享核心，
/// 与 REST API 同源），一次性明文与 DB hash 匹配，rotate_worker_secret 审计行恰一条。
#[tokio::test]
async fn admin_rotate_action_reveals_new_secret() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let worker_id = state
        .state_store
        .upsert_worker("rotate-worker", "x86_64", 1, "test", "online", None)
        .await
        .expect("upsert worker");

    let csrf = csrf_for_worker_page(&app, &admin_token, worker_id).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/workers/{worker_id}"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", format!("crbs_token={admin_token}"))
                .body(Body::from(format!("action=rotate&csrf_token={csrf}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains("secret-reveal"),
        "rotate success should render the secret reveal box: {text}"
    );

    // 节点 tabindex="-1" 是复制失败分支的 focus 目标。
    let marker = r#"id="crbs-secret-value" tabindex="-1">"#;
    let start = text.find(marker).expect("secret value node") + marker.len();
    let secret = text[start..]
        .split('<')
        .next()
        .unwrap_or_default()
        .to_string();
    let found = state
        .state_store
        .find_worker_by_secret(SecretHash::from_plain(&secret).as_str())
        .await
        .expect("find by rotated secret");
    assert_eq!(
        found.map(|w| w.id),
        Some(worker_id),
        "revealed secret must match the DB hash: {secret}"
    );

    let logs = state
        .state_store
        .list_audit_logs(AuditLogFilter {
            action: Some("rotate_worker_secret"),
            ..Default::default()
        })
        .await
        .expect("list audit logs");
    assert_eq!(logs.len(), 1, "exactly one rotate_worker_secret audit row");
    assert_eq!(
        logs[0].target.as_deref(),
        Some(worker_id.to_string().as_str())
    );
}

/// 列表页过滤：?name= 子串 + ?arch= 子串 → 200、表单回显、表格只剩交集行。
#[tokio::test]
async fn workers_list_page_filters_by_name_and_arch() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    for (name, arch) in [
        ("build-worker-1", "x86_64"),
        ("build-worker-2", "aarch64"),
        ("other-worker", "x86_64"),
    ] {
        state
            .state_store
            .upsert_worker(name, arch, 1, "test", "online", None)
            .await
            .expect("upsert worker");
    }

    let html = get_workers_page(&app, &admin_token, "/ui/workers?name=build&arch=x86_64").await;

    assert!(html.contains("value=\"build\""), "{html}");
    assert!(html.contains("value=\"x86_64\""), "{html}");
    assert!(
        html.contains(r#"<td class="ellipsis" title="build-worker-1">build-worker-1</td>"#),
        "{html}"
    );
    assert!(
        !html.contains(r#"<td class="ellipsis" title="build-worker-2">build-worker-2</td>"#),
        "{html}"
    );
    assert!(
        !html.contains(r#"<td class="ellipsis" title="other-worker">other-worker</td>"#),
        "{html}"
    );
    assert_eq!(count_worker_rows(&html), 1);
    assert!(
        html.contains(r#"<h1>Workers <span class="count-chip">1</span></h1>"#),
        "{html}"
    );
}

/// 状态过滤：?status=offline → 只显示离线 worker，下拉回显选中 offline。
#[tokio::test]
async fn workers_list_page_filters_by_status_and_echoes_selection() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    state
        .state_store
        .upsert_worker("online-worker", "x86_64", 1, "test", "online", None)
        .await
        .expect("upsert worker");
    let offline = state
        .state_store
        .upsert_worker("offline-worker", "x86_64", 1, "test", "online", None)
        .await
        .expect("upsert worker");
    state
        .state_store
        .worker_mark_offline(offline)
        .await
        .expect("mark offline");

    let html = get_workers_page(&app, &admin_token, "/ui/workers?status=offline").await;

    assert!(
        html.contains("<option value=\"offline\" selected>offline</option>"),
        "status select must echo the offline selection: {html}"
    );
    assert!(
        html.contains(r#"<td class="ellipsis" title="offline-worker">offline-worker</td>"#),
        "{html}"
    );
    assert!(
        !html.contains(r#"<td class="ellipsis" title="online-worker">online-worker</td>"#),
        "{html}"
    );
    assert_eq!(count_worker_rows(&html), 1);
}

/// status 双语义：非过滤值（flash 消息 worker_removed）不缩小行集，仅渲染消息。
#[tokio::test]
async fn workers_list_page_status_flash_value_does_not_filter() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    for name in ["alpha-worker", "beta-worker"] {
        state
            .state_store
            .upsert_worker(name, "x86_64", 1, "test", "online", None)
            .await
            .expect("upsert worker");
    }

    let html = get_workers_page(&app, &admin_token, "/ui/workers?status=worker_removed").await;

    assert!(
        html.contains("Worker removed."),
        "worker_removed should render as flash message: {html}"
    );
    assert_eq!(count_worker_rows(&html), 2);
    assert!(
        html.contains(r#"<td class="ellipsis" title="alpha-worker">alpha-worker</td>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<td class="ellipsis" title="beta-worker">beta-worker</td>"#),
        "{html}"
    );
}

/// 分页：60 个 worker 命中同一过滤器 → 首页 50 行 + Next 带 offset=50 且保留过滤参数；第二页只含剩余 10 行。
#[tokio::test]
async fn workers_list_page_paginates_large_worker_sets() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    for i in 0..60 {
        state
            .state_store
            .upsert_worker(
                &format!("batch-worker-{i:02}"),
                "x86_64",
                1,
                "test",
                "online",
                None,
            )
            .await
            .expect("upsert worker");
    }

    let html = get_workers_page(&app, &admin_token, "/ui/workers?name=batch").await;
    assert_eq!(
        count_worker_rows(&html),
        50,
        "first page shows UI_PAGE_SIZE=50 rows"
    );
    assert!(html.contains("1-50 of 60"), "{html}");
    // 过滤参数必须保留在分页链接中（maud 会把 & 转义为 &amp;）。
    assert!(
        html.contains("<a href=\"/ui/workers?name=batch&amp;offset=50\">Next"),
        "Next link must keep filters and carry offset=50: {html}"
    );
    assert!(
        html.contains(r#"<td class="ellipsis" title="batch-worker-00">batch-worker-00</td>"#),
        "{html}"
    );
    assert!(
        !html.contains(r#"<td class="ellipsis" title="batch-worker-50">batch-worker-50</td>"#),
        "{html}"
    );

    let html = get_workers_page(&app, &admin_token, "/ui/workers?name=batch&offset=50").await;
    assert_eq!(
        count_worker_rows(&html),
        10,
        "second page shows the remaining 10 rows"
    );
    assert!(html.contains("51-60 of 60"), "{html}");
    assert!(
        html.contains(r#"<td class="ellipsis" title="batch-worker-59">batch-worker-59</td>"#),
        "{html}"
    );
    assert!(
        !html.contains(r#"<td class="ellipsis" title="batch-worker-00">batch-worker-00</td>"#),
        "{html}"
    );
}

/// Load 列（active/capacity）：批量统计 worker_tasks 活跃数；详情页同显当前 load。
#[tokio::test]
async fn workers_list_page_shows_load_column() {
    use crbs_core::BuildInsert;

    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let busy = state
        .state_store
        .upsert_worker("busy-worker", "x86_64", 2, "test", "online", None)
        .await
        .expect("upsert busy worker");
    let idle = state
        .state_store
        .upsert_worker("idle-worker", "x86_64", 4, "test", "online", None)
        .await
        .expect("upsert idle worker");

    for pkg in ["load-a-1.0-1.fc42", "load-b-1.0-1.fc42"] {
        let build_id = state
            .state_store
            .insert_build(BuildInsert {
                product: "mydist",
                pkg_name: pkg,
                backend: "chroot",
                user: "ui-tester",
                arch: Some("x86_64"),
                task_id: Some(
                    crbs_server::test_support::seed_task(&state.state_store, "mydist", pkg).await,
                ),
                ..Default::default()
            })
            .await
            .expect("insert build");
        state
            .state_store
            .assign_build_to_worker(build_id, busy)
            .await
            .expect("assign to worker");
    }

    let html = get_workers_page(&app, &admin_token, "/ui/workers").await;
    assert!(html.contains("<th class=\"num\">Load</th>"), "{html}");
    // Load 列 = 容量占用条（title 承载 active/capacity 原始数；色阶同遥测条）。
    assert!(
        html.contains(
            r#"<span class="load-bar failure" title="2 of 2 slots busy"><i style="width:100%"></i></span> <span class="load-pct">100%</span>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<span class="load-bar success" title="0 of 4 slots busy"><i style="width:0%"></i></span> <span class="load-pct">0%</span>"#
        ),
        "{html}"
    );

    let html = get_workers_page(&app, &admin_token, &format!("/ui/workers/{busy}")).await;
    assert!(html.contains(r#"<dt>Load</dt><dd>2/2</dd>"#), "{html}");
    let html = get_workers_page(&app, &admin_token, &format!("/ui/workers/{idle}")).await;
    assert!(html.contains(r#"<dt>Load</dt><dd>0/4</dd>"#), "{html}");
}

/// 详情页 Active builds 区块：分配中的 build（worker_tasks assigned/running 且
/// kind='build'）以表格列出并链接到构建页；无分配的 worker 显示空态文案。
#[tokio::test]
async fn worker_detail_page_lists_active_builds() {
    use crbs_core::BuildInsert;

    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let busy = state
        .state_store
        .upsert_worker("busy-worker", "x86_64", 2, "test", "online", None)
        .await
        .expect("upsert busy worker");
    let idle = state
        .state_store
        .upsert_worker("idle-worker", "x86_64", 4, "test", "online", None)
        .await
        .expect("upsert idle worker");

    let build_id = state
        .state_store
        .insert_build(BuildInsert {
            product: "mydist",
            pkg_name: "active-pkg-1.0-1.fc42",
            backend: "chroot",
            user: "ui-tester",
            arch: Some("x86_64"),
            task_id: Some(
                crbs_server::test_support::seed_task(
                    &state.state_store,
                    "mydist",
                    "active-pkg-1.0-1.fc42",
                )
                .await,
            ),
            ..Default::default()
        })
        .await
        .expect("insert build");
    state
        .state_store
        .assign_build_to_worker(build_id, busy)
        .await
        .expect("assign to worker");

    let html = get_workers_page(&app, &admin_token, &format!("/ui/workers/{busy}")).await;
    assert!(html.contains("<h2>Active builds</h2>"), "{html}");
    assert!(
        html.contains(&format!(r#"href="/ui/builds/{build_id}""#)),
        "active build row must link to the build page: {html}"
    );
    assert!(
        html.contains("active-pkg-1.0-1.fc42"),
        "active build package missing: {html}"
    );
    assert!(html.contains(r#"<dt>Load</dt><dd>1/2</dd>"#), "{html}");

    // idle worker：空态 empty_state（标题不带句号）。
    let html = get_workers_page(&app, &admin_token, &format!("/ui/workers/{idle}")).await;
    assert!(html.contains("<h2>Active builds</h2>"), "{html}");
    assert!(html.contains("No active builds on this worker"), "{html}");
    assert!(
        !html.contains(&format!(r#"href="/ui/builds/{build_id}""#)),
        "idle worker must not list another worker's build: {html}"
    );
}

/// UI 的 init action 与 HTTP API 共用 arch 门禁：aarch64-only 产品不能派给
/// x86_64 worker，且拒绝时不得落活跃 assignment。
#[tokio::test]
async fn admin_init_action_rejects_arch_mismatch_from_ui() {
    use crbs_core::CreateProductInput;

    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let config = crbs_core::config::ProductConfig::from_str(
        "base_packages = [\"bash\"]\narches = [\"aarch64\"]\n\n[[repos]]\n\
         name = \"base\"\nbaseurl = \"http://example.com/base/$basearch\"\ngpgcheck = false\n",
    )
    .unwrap();
    state
        .state_store
        .create_product(CreateProductInput {
            name: "arch-only",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &config,
            changed_by_user_id: None,
            reason: Some("init arch gate test"),
        })
        .await
        .unwrap();
    let worker_id = state
        .state_store
        .upsert_worker("arch-worker", "x86_64", 2, "test", "online", None)
        .await
        .unwrap();
    let csrf = csrf_for_worker_page(&app, &admin_token, worker_id).await;
    let (status, location) = post_worker_action(
        &app,
        &admin_token,
        worker_id,
        format!("action=init&product=arch-only&csrf_token={csrf}"),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.as_deref().is_some_and(|l| l.contains("error=")));
    assert!(
        !state
            .state_store
            .has_active_init(worker_id, "arch-only")
            .await
            .unwrap(),
        "rejected UI init must not create an assignment"
    );
}

/// 匿名访问 Worker 详情：私有产品的活跃/近期 build 与 init 产品名不得出现；
/// 孤儿产品（测试里的 mydist 无 products 行）按 builds/tasks 列表同口径放行。
#[tokio::test]
async fn worker_detail_hides_private_product_builds_from_anonymous() {
    use crbs_core::{BuildInsert, CreateProductInput};

    let (state, app, _tmp, _admin_token) = setup_app_with_admin().await;
    let admin_id = state
        .state_store
        .find_user_by_name("admin-op")
        .await
        .unwrap()
        .unwrap()
        .id;
    let config = crbs_core::config::ProductConfig::from_str(
        "base_packages = [\"bash\"]\n\n[[repos]]\nname = \"base\"\n\
         baseurl = \"http://example.com/base/$basearch\"\ngpgcheck = false\n",
    )
    .unwrap();
    state
        .state_store
        .create_product(CreateProductInput {
            name: "priv-prod",
            display_name: None,
            owner_id: Some(admin_id),
            parent_id: None,
            visibility: "private",
            config: &config,
            changed_by_user_id: None,
            reason: Some("worker visibility test"),
        })
        .await
        .unwrap();
    let worker_id = state
        .state_store
        .upsert_worker("vis-worker", "x86_64", 2, "test", "online", None)
        .await
        .unwrap();

    for (product, pkg) in [
        ("mydist", "public-pkg-1.0-1.fc42"),
        ("priv-prod", "private-pkg-1.0-1.fc42"),
    ] {
        let build_id = state
            .state_store
            .insert_build(BuildInsert {
                product,
                pkg_name: pkg,
                backend: "chroot",
                user: "ui-tester",
                arch: Some("x86_64"),
                task_id: Some(
                    crbs_server::test_support::seed_task(&state.state_store, product, pkg).await,
                ),
                ..Default::default()
            })
            .await
            .unwrap();
        state
            .state_store
            .assign_build_to_worker(build_id, worker_id)
            .await
            .unwrap();
    }

    let html = get_workers_page_anonymous(&app, &format!("/ui/workers/{worker_id}")).await;
    assert!(html.contains("public-pkg-1.0-1.fc42"), "{html}");
    assert!(!html.contains("private-pkg-1.0-1.fc42"), "{html}");
    assert!(!html.contains("priv-prod"), "{html}");
}

/// CPU/内存遥测列：有采样 → mini 条 + % 数字（色阶 <70 绿 / 70–90 琥珀 / >90 红；
/// CPU 主值 = 利用率、load1/ncpu 齐备时 title 带负载辅助口径，缺任一整体省略
/// title）；缺利用率采样 → "—"。
#[tokio::test]
async fn workers_list_page_renders_cpu_and_memory_telemetry() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let tel = state
        .state_store
        .upsert_worker("tel-worker", "x86_64", 2, "test", "online", None)
        .await
        .expect("upsert telemetry worker");
    state
        .state_store
        .worker_touch_heartbeat(
            tel,
            crbs_core::WorkerTelemetry {
                load1: Some(4.0),
                ncpu: Some(8),
                cpu_util_pct: Some(50.0),
                mem_used_pct: Some(85.0),
                mem_total_kb: None,
                disk_free_kb: None,
            },
            None,
        )
        .await
        .expect("seed telemetry");
    let over = state
        .state_store
        .upsert_worker("over-worker", "x86_64", 2, "test", "online", None)
        .await
        .expect("upsert overloaded worker");
    state
        .state_store
        .worker_touch_heartbeat(
            over,
            crbs_core::WorkerTelemetry {
                load1: Some(16.0),
                ncpu: Some(8),
                cpu_util_pct: Some(95.0),
                mem_used_pct: None,
                mem_total_kb: None,
                disk_free_kb: None,
            },
            None,
        )
        .await
        .expect("seed overload telemetry");
    let plain = state
        .state_store
        .upsert_worker("plain-worker", "x86_64", 2, "test", "online", None)
        .await
        .expect("upsert plain worker");
    state
        .state_store
        .worker_touch_heartbeat(plain, crbs_core::WorkerTelemetry::default(), None)
        .await
        .expect("clear telemetry");
    let util_only = state
        .state_store
        .upsert_worker("util-only-worker", "x86_64", 2, "test", "online", None)
        .await
        .expect("upsert util-only worker");
    state
        .state_store
        .worker_touch_heartbeat(
            util_only,
            crbs_core::WorkerTelemetry {
                load1: None,
                ncpu: None,
                cpu_util_pct: Some(30.0),
                mem_used_pct: None,
                mem_total_kb: None,
                disk_free_kb: None,
            },
            None,
        )
        .await
        .expect("seed util-only telemetry");

    let html = get_workers_page(&app, &admin_token, "/ui/workers").await;

    assert!(html.contains(r#"<th class="num">CPU</th>"#), "{html}");
    assert!(html.contains(r#"<th class="num">Memory</th>"#), "{html}");
    // 主值 = cpu_util_pct（利用率条），title 带负载辅助口径（FmtKey::CpuUtilTitle）。
    assert!(
        html.contains(
            r#"<span class="load-bar success" title="CPU 50% · load 1m 4.00 / 8 cores"><i style="width:50%"></i></span> <span class="load-pct">50%</span>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<span class="load-bar warn"><i style="width:85%"></i></span> <span class="load-pct">85%</span>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<span class="load-bar failure" title="CPU 95% · load 1m 16.00 / 8 cores"><i style="width:95%"></i></span> <span class="load-pct">95%</span>"#
        ),
        "{html}"
    );
    // 缺 load1/ncpu：title 整体省略（不拼空洞段），只剩裸条 + % 数字。
    assert!(
        html.contains(
            r#"<span class="load-bar success"><i style="width:30%"></i></span> <span class="load-pct">30%</span>"#
        ),
        "{html}"
    );
    assert!(html.contains("<td class=\"num\">—</td>"), "{html}");

    // zh 变体（?lang=zh 分享链接语义）：列表 zh 表头（i18n 表 ThCpu/ThMemory）。
    let html = get_workers_page(&app, &admin_token, "/ui/workers?lang=zh").await;
    assert!(html.contains(r#"<th class="num">CPU</th>"#), "{html}");
    assert!(html.contains(r#"<th class="num">内存</th>"#), "{html}");
    // 详情现值条（zh）：CPU 组标签同词 "CPU"、负载组倍数 0.5×（4.0/8）+
    // 绝对口径 tooltip（FmtKey::LoadAvgTitle zh）、内存组 title 旧词复钉。
    let html = get_workers_page(&app, &admin_token, &format!("/ui/workers/{tel}?lang=zh")).await;
    assert!(
        html.contains(r#"<span class="tel-now-label">CPU</span>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<span class="tel-now-label">负载</span>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<span id="w-load-val" title="负载 4.00 / 8 核（可运行 + 不可中断任务队列，含 IO 等待）">0.5×</span>"#),
        "{html}"
    );
    assert!(html.contains("已用 85%"), "{html}");
    // w-cpu-extra 明文通道与 "CPU 负载" 标签不得回归。
    assert!(!html.contains("w-cpu-extra"), "{html}");
    assert!(!html.contains("CPU 负载"), "{html}");
}

/// 详情页遥测卡（主列）+ stale：CPU/Mem 条（列表同款 load-bar）+ Telemetry
/// time 行；心跳超 120s（scheduler 判离线同款阈值）后 stale 标记在遥测时间
/// 一处出现（stale span 恒渲染、hidden 切换——SSE 按 id 反隐藏），值本体仍如实呈现。
#[tokio::test]
async fn worker_detail_page_renders_telemetry_and_marks_stale() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let worker_id = state
        .state_store
        .upsert_worker("tel-worker", "x86_64", 2, "test", "online", None)
        .await
        .expect("upsert worker");
    state
        .state_store
        .worker_touch_heartbeat(
            worker_id,
            crbs_core::WorkerTelemetry {
                load1: Some(4.0),
                ncpu: Some(8),
                cpu_util_pct: Some(50.0),
                mem_used_pct: Some(85.0),
                mem_total_kb: None,
                disk_free_kb: None,
            },
            None,
        )
        .await
        .expect("seed telemetry");

    let html = get_workers_page(&app, &admin_token, &format!("/ui/workers/{worker_id}")).await;
    assert!(html.contains("<h2>Telemetry</h2>"), "{html}");
    // CPU 行：利用率条（列表同款形态，绝对负载只在条 title）。
    assert!(
        html.contains(
            r#"<span id="w-cpu-bar" class="load-bar success" title="CPU 50% · load 1m 4.00 / 8 cores"><i style="width:50%"></i></span> <span id="w-cpu-pct" class="load-pct">50%</span>"#
        ),
        "{html}"
    );
    // 负载组：倍数值 + 绝对口径 tooltip（FmtKey::LoadAvgTitle）；CPU 组标签
    // 短词 "CPU"；w-cpu-extra 明文通道不得回归。
    assert!(
        html.contains(r#"<span id="w-load-val" title="load 4.00 / 8 cores (runnable + uninterruptible queue, includes IO wait)">0.5×</span>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<span class="tel-now-label">CPU</span>"#),
        "{html}"
    );
    assert!(!html.contains("w-cpu-extra"), "{html}");
    // Memory 行：条 + %（title 已用 % 口径）。
    assert!(
        html.contains(
            r#"<span id="w-mem-bar" class="load-bar warn" title="85% used"><i style="width:85%"></i></span> <span id="w-mem-pct" class="load-pct">85%</span>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(r#"<span class="tel-now-label">Telemetry time</span>"#),
        "{html}"
    );
    // 新鲜心跳：stale 标记元素恒渲染但隐藏（SSE 反隐藏契约）。
    assert!(
        html.contains(r#"<span id="w-tel-stale" class="telemetry-stale" hidden"#),
        "{html}"
    );

    // 心跳置为 10 分钟前（超 WORKER_HEARTBEAT_TIMEOUT_SECS=120s）→ stale。
    // 时间戳 Rust 侧算好再绑定：datetime('now',…) 是 SQLite 方言，PG 无此函数（42883）。
    let stale_at = (chrono::Utc::now() - chrono::TimeDelta::minutes(10))
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string();
    sqlx::query("UPDATE workers SET last_heartbeat = $1 WHERE id = $2")
        .bind(&stale_at)
        .bind(worker_id)
        .execute(state.state_store.pool())
        .await
        .expect("age heartbeat");
    let html = get_workers_page(&app, &admin_token, &format!("/ui/workers/{worker_id}")).await;
    assert!(
        html.contains(r#"<span id="w-tel-stale" class="telemetry-stale" title="Sampled at the last heartbeat, which is now overdue.">(stale)</span>"#),
        "{html}"
    );
    // stale 只标记遥测时间组，负载倍数与 CPU 条原值不受影响。
    assert!(
        html.contains(r#"<span id="w-load-val" title="load 4.00 / 8 cores (runnable + uninterruptible queue, includes IO wait)">0.5×</span>"#),
        "{html}"
    );
}

/// 夹具：直插一条遥测采样（浮点用 SQL 字面量落列，时间 Rust 侧按 DB_TIME_FMT
/// 算好再绑定——方言感知的时间函数是 SQLite 语法，PG 腿不可用）。
async fn seed_sample(
    state: &std::sync::Arc<crbs_server::server::state::AppState>,
    worker_id: i64,
    mins_ago: i64,
    cpu: f64,
) {
    let ts = (chrono::Utc::now() - chrono::TimeDelta::minutes(mins_ago))
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string();
    sqlx::query(&format!(
        "INSERT INTO worker_telemetry_samples \
         (worker_id, sampled_at, cpu_util_pct, mem_used_pct, load1, ncpu, mem_total_kb) \
         VALUES ($1, $2, {cpu}, 40.0, 1.25, 8, 16000000)"
    ))
    .bind(worker_id)
    .bind(ts)
    .execute(state.state_store.pool())
    .await
    .expect("seed telemetry sample");
}

/// 遥测趋势面板：seed 采样后渲染 SVG 双序列 + data-payload + 悬停脚本；
/// 档位链接 `?range=` 生效、非法值回落 24h、空数据渲染空态文案。
#[tokio::test]
async fn worker_detail_page_renders_telemetry_chart_and_range_picker() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let worker_id = state
        .state_store
        .upsert_worker("chart-worker", "x86_64", 2, "test", "online", None)
        .await
        .expect("upsert worker");
    seed_sample(&state, worker_id, 50, 10.0).await;
    seed_sample(&state, worker_id, 30, 20.0).await;
    seed_sample(&state, worker_id, 5, 30.0).await;
    // 窗外点（>1h）：只应出现在默认 24h 档的 payload 里。
    seed_sample(&state, worker_id, 120, 90.0).await;

    // 默认 24h 档：SVG 双序列 + 线端点 + data-payload + 悬停脚本（nonce 内联）。
    let html = get_workers_page(&app, &admin_token, &format!("/ui/workers/{worker_id}")).await;
    assert!(html.contains(r#"class="tel-line tel-line-cpu""#), "{html}");
    assert!(html.contains(r#"class="tel-line tel-line-mem""#), "{html}");
    assert!(html.contains(r#"class="tel-area tel-area-cpu""#), "{html}");
    assert!(html.contains("data-payload="), "{html}");
    assert!(html.contains("wtel-cross"), "{html}");
    assert!(html.contains("pointermove"), "{html}");
    // 汇总行（原始数据口径）。
    assert!(html.contains("Peak CPU 90%"), "{html}");
    assert!(html.contains("memory peak 40%"), "{html}");
    // 档位三链接齐备，active 落在 24h（默认）。
    assert!(
        html.contains(&format!(
            r#"<a href="/ui/workers/{worker_id}?range=24h" class="active""#
        )),
        "{html}"
    );
    assert!(
        html.contains(&format!(r#"href="/ui/workers/{worker_id}?range=1h""#)),
        "{html}"
    );
    assert!(
        html.contains(&format!(r#"href="/ui/workers/{worker_id}?range=7d""#)),
        "{html}"
    );

    // 1h 档：窗外点被 since 过滤（payload 只有窗内 3 点 → 90% 峰值不出现）。
    let html = get_workers_page(
        &app,
        &admin_token,
        &format!("/ui/workers/{worker_id}?range=1h"),
    )
    .await;
    assert!(
        html.contains(&format!(
            r#"<a href="/ui/workers/{worker_id}?range=1h" class="active""#
        )),
        "{html}"
    );
    assert!(html.contains("Peak CPU 30%"), "{html}");
    assert!(
        !html.contains("Peak CPU 90%"),
        "out-of-window point must be filtered: {html}"
    );

    // 7d 档同样生效。
    let html = get_workers_page(
        &app,
        &admin_token,
        &format!("/ui/workers/{worker_id}?range=7d"),
    )
    .await;
    assert!(
        html.contains(&format!(
            r#"<a href="/ui/workers/{worker_id}?range=7d" class="active""#
        )),
        "{html}"
    );

    // 非法 range 值回落 24h（不报错、active 落 24h 档）。
    let html = get_workers_page(
        &app,
        &admin_token,
        &format!("/ui/workers/{worker_id}?range=hack"),
    )
    .await;
    assert!(
        html.contains(&format!(
            r#"<a href="/ui/workers/{worker_id}?range=24h" class="active""#
        )),
        "invalid range must fall back to 24h: {html}"
    );

    // 空数据：空态文案，SVG 不渲染。
    let empty_worker = state
        .state_store
        .upsert_worker("chart-empty", "x86_64", 2, "test", "online", None)
        .await
        .expect("upsert empty worker");
    let html = get_workers_page(&app, &admin_token, &format!("/ui/workers/{empty_worker}")).await;
    assert!(html.contains("No telemetry history yet"), "{html}");
    assert!(
        !html.contains(r#"class="tel-line tel-line-cpu""#),
        "no SVG series on empty data: {html}"
    );
    assert!(
        !html.contains("data-payload="),
        "no hover payload on empty data: {html}"
    );
}

/// init 冲突（gate 按 building 计数拒绝）的 3 参错误 flash zh round-trip：
/// worker id / 构建数 / 产品名实值随中文句渲染。
#[tokio::test]
async fn admin_init_conflict_building_flash_is_localized_for_zh() {
    use crbs_core::BuildInsert;

    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let worker_id = state
        .state_store
        .upsert_worker("zh-init-worker", "x86_64", 2, "test", "online", None)
        .await
        .expect("upsert online worker");
    let build_id = state
        .state_store
        .insert_build(BuildInsert {
            product: "mydist",
            pkg_name: "zh-conflict-1.0-1.fc42",
            backend: "chroot",
            user: "ui-tester",
            arch: Some("x86_64"),
            task_id: Some(
                crbs_server::test_support::seed_task(
                    &state.state_store,
                    "mydist",
                    "zh-conflict-1.0-1.fc42",
                )
                .await,
            ),
            ..Default::default()
        })
        .await
        .expect("insert build");
    state
        .state_store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .expect("assign to worker");

    let csrf = csrf_for_worker_page(&app, &admin_token, worker_id).await;
    let zh_cookie = format!("crbs_token={admin_token}; crbs_lang=zh");
    let (status, location) = post_worker_action_with_cookie(
        &app,
        &zh_cookie,
        worker_id,
        format!("action=init&product=mydist&csrf_token={csrf}"),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("error redirect carries Location");
    assert!(
        location.starts_with(&format!("/ui/workers/{worker_id}?error=")),
        "{location}"
    );
    assert!(
        location.contains(
            urlencoding::encode(&format!("Worker {worker_id} 有 1 个产品 mydist")).as_ref()
        ),
        "{location}"
    );

    let html = get_workers_page_with_cookie(&app, &zh_cookie, &location).await;
    assert!(
        html.contains(&format!(
            "Worker {worker_id} 有 1 个产品 mydist 的构建仍在进行；请等待完成或取消后再初始化 base_os。"
        )),
        "zh flash not rendered: {html}"
    );
}

/// remove 在线 worker 冲突 flash zh round-trip（共享核心 WorkerOnline 结构化变体 → 双语模板，1 参 worker 名）。
#[tokio::test]
async fn admin_worker_remove_online_conflict_flash_is_localized_for_zh() {
    let (_state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let worker_id = _state
        .state_store
        .upsert_worker("zh-online-worker", "x86_64", 2, "test", "online", None)
        .await
        .expect("upsert online worker");

    let csrf = csrf_for_worker_page(&app, &admin_token, worker_id).await;
    let zh_cookie = format!("crbs_token={admin_token}; crbs_lang=zh");
    let (status, location) =
        post_remove_with_cookie(&app, &zh_cookie, worker_id, format!("csrf_token={csrf}")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("error redirect carries Location");
    assert!(
        location.starts_with(&format!("/ui/workers/{worker_id}?error=")),
        "{location}"
    );
    assert!(
        location.contains(urlencoding::encode("Worker zh-online-worker 在线").as_ref()),
        "{location}"
    );
    let html = get_workers_page_with_cookie(&app, &zh_cookie, &location).await;
    assert!(
        html.contains("Worker zh-online-worker 在线；请撤销其密钥或等待其离线后再移除。"),
        "zh flash not rendered: {html}"
    );
}

/// POST worker action（完整 cookie 串，便于附加 crbs_lang）。
async fn post_worker_action_with_cookie(
    app: &axum::Router,
    cookie: &str,
    worker_id: i64,
    form_body: String,
) -> (StatusCode, Option<String>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/workers/{worker_id}"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", cookie)
                .body(Body::from(form_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let location = response
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    (response.status(), location)
}

/// POST /ui/workers/{id}/remove（完整 cookie 串）。
async fn post_remove_with_cookie(
    app: &axum::Router,
    cookie: &str,
    worker_id: i64,
    form_body: String,
) -> (StatusCode, Option<String>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/workers/{worker_id}/remove"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", cookie)
                .body(Body::from(form_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let location = response
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    (response.status(), location)
}

/// GET 任意 UI 页面（完整 cookie 串，便于附加 crbs_lang），返回 HTML 文本。
async fn get_workers_page_with_cookie(app: &axum::Router, cookie: &str, uri: &str) -> String {
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

/// 详情页 Danger zone 迁移：rotate/revoke/init/remove 四个 danger-row 进
/// .danger-zone 卡；admin 表单 action 与 hidden 字段（CSRF/路由契约）不变。
#[tokio::test]
async fn worker_detail_page_renders_danger_zone_with_intact_form_actions() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let worker_id = state
        .state_store
        .upsert_worker("dz-worker", "x86_64", 1, "test", "online", None)
        .await
        .expect("upsert worker");

    let html = get_workers_page(&app, &admin_token, &format!("/ui/workers/{worker_id}")).await;
    assert!(
        html.contains(r#"class="admin-section danger-zone""#),
        "{html}"
    );
    assert!(html.contains("<h2>Danger zone</h2>"), "{html}");
    // 三个 /ui/workers/{id} 动作表单（rotate/revoke/init）+ remove 独立表单。
    assert_eq!(
        html.matches(&format!(r#"action="/ui/workers/{worker_id}""#))
            .count(),
        3,
        "rotate/revoke/init forms must keep the shared action: {html}"
    );
    assert!(
        html.contains(&format!(r#"action="/ui/workers/{worker_id}/remove""#)),
        "{html}"
    );
    for action in ["rotate", "revoke", "init"] {
        assert!(
            html.contains(&format!(
                r#"<input type="hidden" name="action" value="{action}">"#
            )),
            "missing {action} hidden field: {html}"
        );
    }
    // 每个表单各带一份 CSRF hidden（4 份；另有 nav logout + 主题/语言偏好三份）。
    assert_eq!(
        html.matches(r#"name="csrf_token""#).count(),
        4 + 3,
        "four danger-zone forms must each embed a CSRF token: {html}"
    );
    // init 产品下拉保留。
    assert!(html.contains(r#"name="product""#), "{html}");
}

/// Recent builds 卡：最近分配（含终态行）按分配倒序列出，终态行带 data-done
/// 耗时、运行中行实时耗时；上限 10 行由 SQL LIMIT 保证（此处只验证行内容）。
#[tokio::test]
async fn worker_detail_page_lists_recent_builds() {
    use crbs_core::BuildInsert;

    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let worker_id = state
        .state_store
        .upsert_worker("recent-worker", "x86_64", 2, "test", "online", None)
        .await
        .expect("upsert worker");

    // 终态行：assign → complete（completed_at 落 builds 表）。
    let done_id = state
        .state_store
        .insert_build(BuildInsert {
            product: "mydist",
            pkg_name: "recent-done-1.0-1.fc42",
            backend: "chroot",
            user: "ui-tester",
            arch: Some("x86_64"),
            task_id: Some(
                crbs_server::test_support::seed_task(
                    &state.state_store,
                    "mydist",
                    "recent-done-1.0-1.fc42",
                )
                .await,
            ),
            ..Default::default()
        })
        .await
        .expect("insert done build");
    state
        .state_store
        .assign_build_to_worker(done_id, worker_id)
        .await
        .expect("assign done build");
    state
        .state_store
        .complete_build(done_id, "succeeded", None)
        .await
        .expect("complete build");
    state
        .state_store
        .update_worker_task_status_for_build(done_id, "completed")
        .await
        .expect("complete assignment");

    // 运行中行：只 assign（phase=assigned，completed_at NULL）。
    let running_id = state
        .state_store
        .insert_build(BuildInsert {
            product: "mydist",
            pkg_name: "recent-run-1.0-1.fc42",
            backend: "chroot",
            user: "ui-tester",
            arch: Some("x86_64"),
            task_id: Some(
                crbs_server::test_support::seed_task(
                    &state.state_store,
                    "mydist",
                    "recent-run-1.0-1.fc42",
                )
                .await,
            ),
            ..Default::default()
        })
        .await
        .expect("insert running build");
    state
        .state_store
        .assign_build_to_worker(running_id, worker_id)
        .await
        .expect("assign running build");

    let html = get_workers_page(&app, &admin_token, &format!("/ui/workers/{worker_id}")).await;
    // 卡头 h2 与 count-chip 之间无空格（同 Artifacts 卡形态）；h2 id 供 SSE
    // 定位 chip 做行集增减同步。
    assert!(
        html.contains(
            r#"<h2 id="w-recent-head">Recent builds<span class="count-chip">2</span></h2>"#
        ),
        "{html}"
    );
    // 行定位键 + 终态行 data-done（SSE 徽章/耗时更新契约）。
    assert!(
        html.contains(&format!(r#"<tr data-recent-build="{done_id}">"#)),
        "{html}"
    );
    assert!(
        html.contains(&format!(r#"<tr data-recent-build="{running_id}">"#)),
        "{html}"
    );
    assert!(
        html.contains("recent-done-1.0-1.fc42") && html.contains("recent-run-1.0-1.fc42"),
        "{html}"
    );
    // 运行中行 phase 徽章（assigned → running 修饰类）且无 data-done。
    assert!(
        html.contains(r#"<span class="badge running">assigned</span>"#),
        "{html}"
    );
    let running_row = html
        .split(&format!(r#"<tr data-recent-build="{running_id}">"#))
        .nth(1)
        .expect("running row body");
    let running_cell = running_row
        .split("</tr>")
        .next()
        .expect("running row cells");
    assert!(running_cell.contains("recent-dur"), "{running_cell}");
    assert!(running_cell.contains("data-start="), "{running_cell}");
    assert!(!running_cell.contains("data-done="), "{running_cell}");
    // 终态行带 data-done。
    let done_row = html
        .split(&format!(r#"<tr data-recent-build="{done_id}">"#))
        .nth(1)
        .expect("done row body");
    let done_cell = done_row.split("</tr>").next().expect("done row cells");
    assert!(done_cell.contains("data-done="), "{done_cell}");
}

/// Base OS inits 卡：每产品最近一次 init（Rust 侧按产品去重），终态行成败
/// 徽章、活跃行 running 徽章。
#[tokio::test]
async fn worker_detail_page_lists_recent_inits() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let worker_id = state
        .state_store
        .upsert_worker("init-worker", "x86_64", 1, "test", "online", None)
        .await
        .expect("upsert worker");

    let first = state
        .state_store
        .try_assign_init_to_worker(worker_id, "mydist")
        .await
        .expect("assign init mydist")
        .expect("no conflict");
    state
        .state_store
        .complete_init_assignment(first, true, None)
        .await
        .expect("complete init");
    let second = state
        .state_store
        .try_assign_init_to_worker(worker_id, "otherdist")
        .await
        .expect("assign init otherdist")
        .expect("no conflict");

    let html = get_workers_page(&app, &admin_token, &format!("/ui/workers/{worker_id}")).await;
    assert!(
        html.contains(r#"<h2>Base OS inits<span class="count-chip">2</span></h2>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<td class="ellipsis" title="mydist">mydist</td>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<td class="ellipsis" title="otherdist">otherdist</td>"#),
        "{html}"
    );
    // mydist 已完成 → success 徽章；otherdist 活跃 → running 徽章（zh 显示名）。
    assert!(
        html.contains(r#"<span class="badge success">succeeded</span>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<span class="badge running">running</span>"#),
        "{html}"
    );
    let _ = second;
}

/// 离线 worker：Active builds 空态走离线文案；离线页不渲染 SSE 脚本
///（reload 终态事件后落回本形态，无脚本故不成环）。
#[tokio::test]
async fn worker_detail_page_offline_shows_offline_empty_state_without_sse() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let worker_id = state
        .state_store
        .upsert_worker("gone-worker", "x86_64", 1, "test", "online", None)
        .await
        .expect("upsert worker");
    state
        .state_store
        .worker_mark_offline(worker_id)
        .await
        .expect("mark offline");

    let html = get_workers_page(&app, &admin_token, &format!("/ui/workers/{worker_id}")).await;
    assert!(html.contains("Worker is offline"), "{html}");
    assert!(html.contains("once the worker is back online"), "{html}");
    assert!(
        !html.contains(&format!("/ui/workers/{worker_id}/events")),
        "offline page must not embed the worker SSE script: {html}"
    );
}

/// Details 侧栏补行：Registered（created_at）与 Memory total（human）；无
/// secret_expires_at 时 Expires 行不出现。
#[tokio::test]
async fn worker_detail_page_details_card_shows_registered_and_memory_total() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let worker_id = state
        .state_store
        .upsert_worker("details-worker", "x86_64", 1, "test", "online", None)
        .await
        .expect("upsert worker");
    state
        .state_store
        .worker_touch_heartbeat(
            worker_id,
            crbs_core::WorkerTelemetry {
                mem_total_kb: Some(16_000_000),
                disk_free_kb: None,
                ..Default::default()
            },
            None,
        )
        .await
        .expect("seed mem total");

    let html = get_workers_page(&app, &admin_token, &format!("/ui/workers/{worker_id}")).await;
    assert!(html.contains("<dt>Created</dt>"), "{html}");
    assert!(html.contains("<dt>Memory total</dt>"), "{html}");
    // 16_000_000 KB ≈ 15.3 GiB（二进制单位 human 化）。
    assert!(html.contains("GiB"), "{html}");
    assert!(!html.contains("<dt>Expires</dt>"), "{html}");
}
