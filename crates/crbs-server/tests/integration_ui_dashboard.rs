// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY, FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 仪表盘（首页）集成测试：任务状态环形图（图例行 = phase 过滤链接）、
//! 成功率仪表、Workers 每架构在线条、operator 系统状态条门槛与 SSE 图表更新契约。

// 测试 crate：seed_* 等辅助函数不带 #[test]，clippy 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::ServerConfig;
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;

/// seed（op=operator、bob=builder），默认公开访问（匿名可看首页）。
async fn setup_app_with_roles() -> (
    Arc<AppState>,
    axum::Router,
    tempfile::TempDir,
    String,
    String,
) {
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        state_store,
        ServerConfig::default(),
        tmp_dir.path().to_path_buf(),
    ));
    let op_token = seed_user_token_for_test(&app_state.state_store, "op", "operator")
        .await
        .expect("seed operator token");
    let bob_token = seed_user_token_for_test(&app_state.state_store, "bob", "builder")
        .await
        .expect("seed builder token");
    let app = create_test_app_with_auth(app_state.clone());
    (app_state, app, tmp_dir, op_token, bob_token)
}

async fn get_home(app: &axum::Router, token: Option<&str>) -> String {
    let mut builder = Request::builder().uri("/ui/");
    if let Some(t) = token {
        builder = builder.header("Cookie", format!("crbs_token={t}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// 插入一条 task（产品无 products 行 → 孤儿豁免，对所有角色可见）。
async fn insert_task(state: &AppState, phase: &'static str) -> i64 {
    state
        .state_store
        .insert_task(crbs_core::TaskInsert {
            product: "fedora",
            pkg_name: "pkg",
            user: "alice",
            phase,
            ..Default::default()
        })
        .await
        .unwrap()
}

/// 六种 phase 收进一张环形图——SVG 扇区 + 可点击图例行，href 过滤参数
/// running→building、queued→pending；timeout 用拆分 --timeout 令牌；SSE 按 StatusResponse 字段重算 #dash-*。
#[tokio::test]
async fn dashboard_renders_donut_with_legend_links_and_sse_updates() {
    let (state, app, _tmp, _op, _bob) = setup_app_with_roles().await;
    insert_task(&state, "timeout").await;
    insert_task(&state, "cancelled").await;
    insert_task(&state, "cancelled").await;

    let html = get_home(&app, None).await;
    assert!(html.contains(r#"class="viz-grid""#), "{html}");
    // aria-live 收窄：整区 live 已撤，live 语义在 donut 环心/图例行/workers 计数。
    assert!(
        !html.contains(r#"class="viz-grid" role="region" aria-live="polite""#),
        "whole-grid live region must stay removed: {html}"
    );
    assert!(
        html.contains(r#"class="viz-grid" role="region" aria-label="#),
        "region semantics must survive the narrowing: {html}"
    );
    assert!(
        html.contains(r#"<div class="donut-center" aria-live="polite">"#),
        "donut center counts must carry the narrowed live region: {html}"
    );
    assert!(html.contains(r#"id="dash-donut-total">3<"#), "{html}");
    for (phase, href) in [
        ("running", "/ui/tasks?phase=building"),
        ("queued", "/ui/tasks?phase=pending"),
        ("succeeded", "/ui/tasks?phase=succeeded"),
        ("failed", "/ui/tasks?phase=failed"),
        ("timeout", "/ui/tasks?phase=timeout"),
        ("cancelled", "/ui/tasks?phase=cancelled"),
    ] {
        assert!(
            html.contains(&format!(r#"circle class="seg" data-phase="{phase}""#)),
            "donut seg {phase} missing: {html}"
        );
        assert!(
            html.contains(&format!(
                r#"class="legend-row" data-phase="{phase}" href="{href}""#
            )),
            "legend row {phase} -> {href} missing: {html}"
        );
    }
    assert!(
        html.contains("title=\"cancelled · 2 tasks · 66.7% — click to view list\""),
        "{html}"
    );
    assert!(html.contains(r#"stroke="var(--timeout)""#), "{html}");
    assert!(html.contains("running: t.building"), "{html}");
    assert!(html.contains("queued: t.pending"), "{html}");
    assert!(
        html.contains("getElementById('dash-donut-total')"),
        "{html}"
    );
    assert!(
        html.contains("getElementById('dash-workers-online')"),
        "{html}"
    );
    assert!(
        html.contains(r#"<span class="hint-r" aria-live="polite">"#),
        "workers online count must carry the narrowed live region: {html}"
    );
    assert!(html.contains("EventSource('/ui/events')"), "{html}");
    assert!(html.contains("Recent tasks"), "{html}");
    assert!(html.contains("View all tasks"), "{html}");
    assert!(html.contains("<th>Status</th>"), "{html}");
}

/// 最近任务链接语义：包名单元格链接 /ui/tasks/{id} 并接管行点击（row-target），
/// ID 单元格纯文本；ellipsis 类与 title 属性保留。
#[tokio::test]
async fn dashboard_recent_task_package_link_targets_task_page() {
    let (state, app, _tmp, _op, _bob) = setup_app_with_roles().await;
    let id_a = insert_task(&state, "succeeded").await;
    let id_b = insert_task(&state, "failed").await;

    let html = get_home(&app, None).await;

    // 包名单元格：href 指向该次任务页，显示文本为 NVR（与 name 可解析与否无关）。
    for id in [id_a, id_b] {
        assert!(
            html.contains(&format!(
                r#"<td class="ellipsis" title="pkg"><a class="row-target" href="/ui/tasks/{id}">pkg</a></td>"#
            )),
            "package cell of task {id} must link to its task page: {html}"
        );
        assert!(
            html.contains(&format!("<td>{id}</td>")),
            "ID cell must be plain text: {html}"
        );
    }
    // 每行恰一个 row-target（clickable_rows_script 跳行内首个 a.row-target）。
    let rows = html.matches(r#"tr class="clickable-row""#).count();
    let targets = html.matches(r#"class="row-target""#).count();
    assert_eq!(rows, 2, "{html}");
    assert_eq!(targets, rows, "exactly one row-target per row: {html}");
}

/// SSE 换新管道：首页带 `#recent-tasks` 容器与节流拉取脚本（幂等行绑定器）；
/// 片段路由 `/ui/home/recent-tasks` 与首页同一渲染源（行标记逐字节一致），
/// 且只输出片段（不带整页 chrome）。
#[tokio::test]
async fn dashboard_recent_tasks_fragment_route_matches_page_source() {
    let (state, app, _tmp, _op, _bob) = setup_app_with_roles().await;
    let id = insert_task(&state, "succeeded").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/home/recent-tasks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let fragment = String::from_utf8_lossy(&bytes).into_owned();
    assert!(
        fragment.contains(&format!(
            r#"<a class="row-target" href="/ui/tasks/{id}">pkg</a>"#
        )),
        "fragment must carry the task row: {fragment}"
    );
    assert!(
        !fragment.contains("<!DOCTYPE") && !fragment.contains("<html"),
        "fragment must be a partial, not a full page: {fragment}"
    );

    let html = get_home(&app, None).await;
    assert!(html.contains(r#"id="recent-tasks""#), "{html}");
    assert!(
        html.contains("fetch('/ui/home/recent-tasks')"),
        "dashboard script must refetch the fragment: {html}"
    );
    assert!(
        html.contains("window.__crbsBindClickableRows"),
        "row click binding must be the idempotent global binder: {html}"
    );
}

/// 系统状态条是 operator+ 的服务端门槛：匿名与 builder 首页响应中不含状态条
///（非 CSS 隐藏），成功率仪表不受限。负断言用 class="..." 形式（内联 style.css 含 .sys-strip 文本）。
#[tokio::test]
async fn dashboard_sys_strip_hidden_for_anonymous_and_regular_user() {
    let (_state, app, _tmp, _op, bob) = setup_app_with_roles().await;

    for html in [get_home(&app, None).await, get_home(&app, Some(&bob)).await] {
        assert!(!html.contains(r#"class="sys-strip""#), "{html}");
        assert!(
            !html.contains("Uptime"),
            "non-operator must not see sys strip: {html}"
        );
        assert!(html.contains("Success rate"), "{html}");
    }
}

/// operator 首页渲染系统状态条四项（数据源与 /api/v1/metrics 一致）。
#[tokio::test]
async fn dashboard_sys_strip_shown_for_operator() {
    let (_state, app, _tmp, op, _bob) = setup_app_with_roles().await;

    let html = get_home(&app, Some(&op)).await;
    assert!(html.contains(r#"class="sys-strip""#), "{html}");
    for label in ["Uptime", "Queue", "Concurrency", "Disk available"] {
        assert!(
            html.contains(label),
            "sys strip item {label} missing: {html}"
        );
    }
    assert!(!html.contains("computed on page load"), "{html}");
}

/// 成功率仪表 = 最近 200 条可见任务的 succeeded 占比（静态，页面加载时
/// 计算）；无数据时空环 + "—" 占位；口径说明带真实分子/分母。
#[tokio::test]
async fn dashboard_gauge_computes_recent_share() {
    let (state, app, _tmp, _op, _bob) = setup_app_with_roles().await;

    // 空库：无样本 → 占位符（maud 原样输出 em dash 字符）。
    let html = get_home(&app, None).await;
    assert!(html.contains("Success rate"), "{html}");
    assert!(html.contains(r#"id="dash-gauge-pct">—<"#), "{html}");

    for _ in 0..3 {
        insert_task(&state, "succeeded").await;
    }
    insert_task(&state, "failed").await;
    let html = get_home(&app, None).await;
    assert!(html.contains(r#"id="dash-gauge-pct">75%<"#), "{html}");
    assert!(
        html.contains("<b>3</b> / <b>4</b> recent tasks succeeded"),
        "{html}"
    );
}

/// 空态环形图（零任务：扇区弧长 0 不可见）——SSR 补中性满环 circle.seg-empty
///（--border 令牌，同 gauge .track）；首任务出现后 SSE 脚本按类移除（见 sse_script 单测）。
#[tokio::test]
async fn dashboard_empty_state_renders_neutral_ring_only_when_total_zero() {
    let (state, app, _tmp, _op, _bob) = setup_app_with_roles().await;

    let html = get_home(&app, None).await;
    assert!(html.contains(r#"id="dash-donut-total">0<"#), "{html}");
    assert!(
        html.contains(r#"circle class="seg-empty" r="81""#),
        "empty-state ring missing: {html}"
    );
    assert!(html.contains(r#"id="dash-gauge-pct">—<"#), "{html}");

    // 首个任务出现：空态环消失、正常扇区在位（负断言用元素标记形式，内联 CSS 含 .seg-empty 文本）。
    insert_task(&state, "succeeded").await;
    let html = get_home(&app, None).await;
    assert!(html.contains(r#"id="dash-donut-total">1<"#), "{html}");
    assert!(
        !html.contains(r#"circle class="seg-empty""#),
        "non-empty donut must not render the empty-state ring: {html}"
    );
}

/// Workers 面板按架构渲染在线条形；h3 的 online 总数是 SSE 更新目标；
/// 无注册 worker 时渲染空态而非空面板。
#[tokio::test]
async fn dashboard_workers_panel_renders_arch_rows() {
    let (state, app, _tmp, _op, _bob) = setup_app_with_roles().await;

    // 空库 → 空态（class="..." 形式断言：内联 style.css 本身含 .arch-row 文本）。
    let html = get_home(&app, None).await;
    assert!(html.contains("No workers registered"), "{html}");
    assert!(
        !html.contains(r#"class="arch-row""#),
        "no arch rows expected: {html}"
    );

    let w1 = state
        .state_store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    let w2 = state
        .state_store
        .upsert_worker("w2", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    let html = get_home(&app, None).await;
    assert!(html.contains(r#"id="dash-workers-online">2<"#), "{html}");
    assert!(html.contains(r#"<span class="a">x86_64</span>"#), "{html}");
    assert!(html.contains("2/2 online"), "{html}");
    assert!(html.contains("bar = online ratio"), "{html}");
    assert!(html.contains(r#"href="/ui/workers""#), "{html}");

    // CPU 均值 chip 仅渲染有遥测的架构（无遥测行 n span 后即行尾）。
    state
        .state_store
        .worker_touch_heartbeat(
            w1,
            crbs_core::WorkerTelemetry {
                load1: Some(1.0),
                ncpu: Some(4),
                cpu_util_pct: Some(50.0),
                mem_used_pct: None,
                mem_total_kb: None,
                disk_free_kb: None,
            },
            None,
        )
        .await
        .unwrap();
    state
        .state_store
        .worker_touch_heartbeat(
            w2,
            crbs_core::WorkerTelemetry {
                load1: Some(3.0),
                ncpu: Some(4),
                cpu_util_pct: Some(50.0),
                mem_used_pct: None,
                mem_total_kb: None,
                disk_free_kb: None,
            },
            None,
        )
        .await
        .unwrap();
    state
        .state_store
        .upsert_worker("w3", "aarch64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    let html = get_home(&app, None).await;
    assert!(
        html.contains(
            r#"<span class="badge success" title="Average CPU utilization of online workers">avg 50%</span>"#
        ),
        "{html}"
    );
    assert!(
        html.contains("1/1 online</span></div>"),
        "arch without telemetry must not render an avg chip: {html}"
    );
}

/// 全局页脚（page() 骨架渲染）：版本号 + API health 链接跨页面出现。
#[tokio::test]
async fn site_footer_with_version_appears_across_pages() {
    let (_state, app, _tmp, op, _bob) = setup_app_with_roles().await;
    // 测试 crate 同属 crbs-server 包，CARGO_PKG_VERSION 与 page() 渲染一致。
    let version = env!("CARGO_PKG_VERSION");
    for uri in ["/ui/", "/ui/builds", "/ui/tasks"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("Cookie", format!("crbs_token={op}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "page {uri}");
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&bytes).into_owned();
        assert!(
            html.contains(r#"<footer class="site-footer">"#),
            "footer missing on {uri}: {html}"
        );
        assert!(
            html.contains(&format!("CRBS <b>{version}</b>")),
            "version missing on {uri}: {html}"
        );
        assert!(
            html.contains(r#"href="/api/v1/health""#),
            "health link missing on {uri}: {html}"
        );
    }
}

/// 直插 succeeded 构建并补 duration/completed_at（insert_build 不写终态字段）。
async fn seed_finished_build(state: &AppState, pkg: &'static str, arch: &'static str, dur: i64) {
    let id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: pkg,
            phase: "succeeded",
            arch: Some(arch),
            user: "alice",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, "fedora", pkg).await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    let completed = (chrono::Utc::now() - chrono::TimeDelta::minutes(10))
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string();
    sqlx::query("UPDATE builds SET completed_at = $1, duration = $2 WHERE id = $3")
        .bind(&completed)
        .bind(dur)
        .bind(id)
        .execute(state.state_store.pool())
        .await
        .unwrap();
}

/// home 无时长卡（products / me 页保留同款）：有 succeeded 样本也不输出时长图，
/// viz-grid、donut、gauge、workers 不受影响；负断言用元素标记形式
///（内联 style.css 含 .dur-chart/.dur-row 规则文本）。
#[tokio::test]
async fn dashboard_has_no_duration_chart() {
    let (state, app, _tmp, op_token, _bob) = setup_app_with_roles().await;
    seed_finished_build(&state, "vim-9.1.0-4.el9", "x86_64", 600).await;
    seed_finished_build(&state, "bash-5.2.26-3.el9", "aarch64", 300).await;

    let html = get_home(&app, Some(&op_token)).await;
    assert!(!html.contains(r#"<div class="dur-chart""#), "{html}");
    assert!(!html.contains(r#"<div class="dur-row""#), "{html}");
    assert!(!html.contains("Recent build durations"), "{html}");
    assert!(!html.contains("Success rate trend"), "{html}");
    assert!(!html.contains("trend-chart"), "{html}");
    assert!(html.contains(r#"class="viz-grid""#), "{html}");
    // 种子构建都挂任务行，donut 按任务构建口径计入全部样本。
    assert!(html.contains(r#"id="dash-donut-total">2<"#), "{html}");
    assert!(html.contains("Success rate"), "{html}");
    assert!(html.contains(r#"id="dash-workers-online">0<"#), "{html}");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/")
                .header("Cookie", format!("crbs_token={op_token}"))
                .header("Accept-Language", "zh-CN,zh;q=0.9")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let zh = String::from_utf8_lossy(&bytes).into_owned();
    assert!(!zh.contains("最近构建时长"), "{zh}");
}
