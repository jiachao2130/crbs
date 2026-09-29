// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 数据列集成测试：builds Priority 列/过滤、task 详情 Duration/Completed、列表相对时间渲染。

// 测试 crate：辅助函数（seed_* 等）不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

mod common;

use common::setup_app_with_admin;

use crbs_core::types::{PRIORITY_CRITICAL, PRIORITY_DEFAULT};
use crbs_core::{BuildInsert, TaskInsert};
use crbs_server::server::state::AppState;

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

fn sample_build(
    pkg: &'static str,
    priority: crbs_core::types::BuildPriority,
) -> BuildInsert<'static> {
    BuildInsert {
        product: "mydist",
        pkg_name: pkg,
        phase: "succeeded",
        backend: "chroot",
        user: "ui-tester",
        priority,
        arch: Some("x86_64"),
        ..Default::default()
    }
}

/// seed 挂在任务下的构建并返回 build id：builds.task_id NOT NULL，build 必须挂任务。
async fn insert_task_build(state: &AppState, build: BuildInsert<'static>) -> i64 {
    let task = state
        .state_store
        .insert_task(TaskInsert {
            product: build.product,
            pkg_name: build.pkg_name,
            user: build.user,
            phase: build.phase,
            ..Default::default()
        })
        .await
        .unwrap();
    state
        .state_store
        .insert_build(BuildInsert {
            task_id: Some(task),
            ..build
        })
        .await
        .unwrap()
}

/// Priority 列渲染 + ?priority= 过滤：过滤只剩对应档、Total 同步、下拉回显选中；无过滤时三档标签齐全。
#[tokio::test]
async fn builds_list_renders_priority_column_and_filters_by_priority() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    insert_task_build(
        &state,
        sample_build("normal-pkg-1.0-1.fc42", PRIORITY_DEFAULT),
    )
    .await;
    // 1 = 高优。
    let high = insert_task_build(&state, sample_build("high-pkg-1.0-1.fc42", 1)).await;
    let _critical = insert_task_build(
        &state,
        sample_build("critical-pkg-1.0-1.fc42", PRIORITY_CRITICAL),
    )
    .await;

    let html = get_page(&app, &admin_token, "/ui/builds").await;
    assert!(html.contains("<th>Priority</th>"), "{html}");
    for label in ["normal", "high", "critical"] {
        assert!(html.contains(&format!("<td>{label}</td>")), "{html}");
    }
    assert!(
        html.contains(r#"<span class="count-chip">3</span>"#),
        "{html}"
    );

    let html = get_page(&app, &admin_token, "/ui/builds?priority=1").await;
    assert!(
        html.contains(&format!(r#"href="/ui/builds/{high}?back="#)),
        "high build row missing (with back param): {html}"
    );
    assert!(
        !html.contains("normal-pkg") && !html.contains("critical-pkg"),
        "priority=1 must filter out other priorities: {html}"
    );
    assert!(
        html.contains(r#"<span class="count-chip">1</span>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<option value="1" selected>high</option>"#),
        "priority select must echo the high selection: {html}"
    );
    // 列内 product/phase 链接保留 priority 过滤参数（maud 属性内 & 转义为 &amp;）。
    assert!(
        html.contains(r#"href="/ui/builds?product=mydist&amp;priority=1""#),
        "priority filter must survive in row links: {html}"
    );

    let html = get_page(&app, &admin_token, "/ui/builds?priority=0").await;
    assert!(html.contains("normal-pkg"), "{html}");
    assert!(
        !html.contains("high-pkg") && !html.contains("critical-pkg"),
        "priority=0 must filter out high/critical: {html}"
    );
}

/// 越界 priority 值视为未过滤（不 400），列表不缩小。
#[tokio::test]
async fn builds_list_out_of_range_priority_is_ignored() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    insert_task_build(
        &state,
        sample_build("normal-pkg-1.0-1.fc42", PRIORITY_DEFAULT),
    )
    .await;

    let html = get_page(&app, &admin_token, "/ui/builds?priority=9").await;
    assert!(html.contains("normal-pkg"), "{html}");
    assert!(
        html.contains(r#"<span class="count-chip">1</span>"#),
        "{html}"
    );
}

/// 全空串表单参数不 400：浏览器 GET 表单把选中 select、清空文本框以空串
/// 回传，priority 须按字符串宽容解析。
#[tokio::test]
async fn builds_list_empty_form_params_do_not_400() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    insert_task_build(
        &state,
        sample_build("normal-pkg-1.0-1.fc42", PRIORITY_DEFAULT),
    )
    .await;

    let html = get_page(
        &app,
        &admin_token,
        "/ui/builds?product=&name=&phase=&arch=&priority=&sort=",
    )
    .await;
    assert!(html.contains("normal-pkg"), "{html}");
    assert!(
        html.contains(r#"<span class="count-chip">1</span>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<option value="" selected>All</option>"#),
        "{html}"
    );
}

/// builds 列表渲染全部构建（所有构建均挂任务，列表无视图区分）。
#[tokio::test]
async fn builds_list_renders_all_builds() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    insert_task_build(
        &state,
        sample_build("taskbuild-pkg-1.0-1.fc42", PRIORITY_DEFAULT),
    )
    .await;

    let html = get_page(&app, &admin_token, "/ui/builds").await;
    assert!(html.contains("taskbuild-pkg"), "{html}");
    assert!(
        html.contains(r#"<span class="count-chip">1</span>"#),
        "{html}"
    );
}

/// builds.task_id NOT NULL：先插任务行再挂 build，供构建行与任务字段解耦的测试用。
async fn insert_direct_build(
    state: &AppState,
    pkg: &'static str,
    priority: crbs_core::types::BuildPriority,
) -> i64 {
    let task = crbs_server::test_support::seed_task(&state.state_store, "mydist", pkg).await;
    state
        .state_store
        .insert_build(BuildInsert {
            task_id: Some(task),
            ..sample_build(pkg, priority)
        })
        .await
        .unwrap()
}

/// task 详情：Duration 人类可读 + Completed 绝对时间；未完成任务两字段统一 "—"。
#[tokio::test]
async fn task_detail_shows_duration_and_completed() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;

    let done = state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name: "done-pkg-1.0-1.fc42",
            user: "ui-tester",
            phase: "succeeded",
            ..Default::default()
        })
        .await
        .unwrap();
    // duration 聚合在引擎 complete 事务里，这里直接落库终态字段。
    sqlx::query(
        "UPDATE tasks SET completed_at = '2026-08-26 08:30:00', duration = 222 WHERE id = $1",
    )
    .bind(done)
    .execute(state.state_store.pool())
    .await
    .unwrap();

    let html = get_page(&app, &admin_token, &format!("/ui/tasks/{done}")).await;
    // 侧栏（side-kv）时间保持绝对口径（code mono），相对时间仅限 page-meta 行。
    assert!(html.contains(r#"<dt>Duration</dt>"#), "{html}");
    assert!(
        html.contains(r#"<dd>3m 42s</dd>"#),
        "duration should render human-readable: {html}"
    );
    assert!(html.contains(r#"<dt>Completed</dt>"#), "{html}");
    let side_at = html
        .find(r#"<div class="detail-side">"#)
        .expect("detail-side");
    // 终态无 Cancel → 无 danger 卡（show_cancel 仅限非终态）；侧栏顺序在下方 pending 页断言。
    assert!(
        !html[side_at..].contains(r#"admin-section danger-zone"#),
        "terminal task must not render danger zone: {html}"
    );
    // 详情卡的第一个闭 div 之前即 Details 全部内容（side-kv 无内层 div）。
    let side_end = html[side_at..]
        .find("</div>")
        .map(|i| i + side_at)
        .expect("details card close");
    assert!(
        !html[side_at..side_end].contains(" ago"),
        "side-kv times must stay absolute: {html}"
    );

    let pending = state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name: "pending-pkg-1.0-1.fc42",
            user: "ui-tester",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();
    let html = get_page(&app, &admin_token, &format!("/ui/tasks/{pending}")).await;
    assert!(html.contains(r#"<dt>Duration</dt><dd>—</dd>"#), "{html}");
    assert!(
        html.contains(r#"<dt>Completed</dt><dd><code>—</code></dd>"#),
        "{html}"
    );
    // 非终态 + admin → Cancel 在 Danger zone 卡内，且 Details 在前（沉底座位）。
    let side_at = html
        .find(r#"<div class="detail-side">"#)
        .expect("pending detail-side");
    let danger_at = side_at
        + html[side_at..]
            .find(r#"<div class="admin-section danger-zone""#)
            .expect("danger zone after details");
    assert!(
        html[side_at..danger_at].contains(r#"side-kv"#),
        "details card precedes danger zone: {html}"
    );
}

/// 列表时间列（builds Started / tasks Submitted）走相对时间：`<span title="绝对时间">相对时间</span>`。
#[tokio::test]
async fn list_pages_render_relative_time_for_time_columns() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let build = insert_task_build(
        &state,
        BuildInsert {
            phase: "building",
            ..sample_build("reltime-pkg-1.0-1.fc42", PRIORITY_DEFAULT)
        },
    )
    .await;
    let started = (chrono::Utc::now() - chrono::TimeDelta::minutes(3))
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string();
    sqlx::query("UPDATE builds SET started_at = $1 WHERE id = $2")
        .bind(&started)
        .bind(build)
        .execute(state.state_store.pool())
        .await
        .unwrap();

    let task = state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name: "reltime-pkg-1.0-1.fc42",
            user: "ui-tester",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();
    let submitted = (chrono::Utc::now() - chrono::TimeDelta::minutes(5))
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string();
    sqlx::query("UPDATE tasks SET submitted_at = $1 WHERE id = $2")
        .bind(&submitted)
        .bind(task)
        .execute(state.state_store.pool())
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, "/ui/builds").await;
    assert!(
        html.contains(">3 min ago</span>"),
        "builds Started column should be relative: {html}"
    );
    assert!(
        html.contains("<span title=\""),
        "relative time should carry absolute title: {html}"
    );

    let html = get_page(&app, &admin_token, "/ui/tasks").await;
    assert!(
        html.contains(">5 min ago</span>"),
        "tasks Submitted column should be relative: {html}"
    );
}

/// failed 且 error_summary 非空 → 详情页渲 message failure 卡片（含 View logs 链接）；succeeded 无卡片。
#[tokio::test]
async fn build_detail_renders_error_summary_for_failed_build() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;

    // failed build：带 error_summary（插入活跃态，complete 的终态守卫才接受）。
    let failed_task =
        crbs_server::test_support::seed_task(&state.state_store, "mydist", "failed-pkg-1.0-1.fc42")
            .await;
    let failed = state
        .state_store
        .insert_build(BuildInsert {
            phase: "building",
            task_id: Some(failed_task),
            ..sample_build("failed-pkg-1.0-1.fc42", PRIORITY_DEFAULT)
        })
        .await
        .unwrap();
    state
        .state_store
        .complete_build_with_error(
            failed,
            "failed",
            None,
            Some("exit_code=1 phase=build subphase=rpmbuild reason=mock build failure"),
        )
        .await
        .unwrap();

    let ok = insert_direct_build(&state, "ok-pkg-1.0-1.fc42", PRIORITY_DEFAULT).await;
    state
        .state_store
        .complete_build(ok, "succeeded", None)
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, &format!("/ui/builds/{failed}")).await;
    assert!(
        html.contains(r#"class="message failure failure-box""#),
        "{html}"
    );
    assert!(
        html.contains("exit_code=1 phase=build subphase=rpmbuild reason=mock build failure"),
        "{html}"
    );
    // View logs 出现两次：横幅链接 + 详情页既有链接。
    assert_eq!(
        html.matches(&format!(r#"href="/ui/builds/{failed}/logs""#))
            .count(),
        2,
        "{html}"
    );

    let html = get_page(&app, &admin_token, &format!("/ui/builds/{ok}")).await;
    assert!(!html.contains(r#"class="message failure"#), "{html}");
}

/// 失败横幅直达日志段：横幅链接携带失败 span 标记行 ?line=（spans 全文件扫描、
/// 行号真实）；多失败 span 取最后一个，无标记降级为不带 line 原链接。fixture
/// 覆盖失败判定两分支：闭合 span END 非零退出、未闭合 span（set -e 下失败步不打 END，同样入选）。
#[tokio::test]
async fn build_detail_error_banner_links_to_failed_phase_line() {
    let (state, app, tmp, admin_token) = setup_app_with_admin().await;
    let failed_task = crbs_server::test_support::seed_task(
        &state.state_store,
        "mydist",
        "bannerline-pkg-1.0-1.fc42",
    )
    .await;
    let failed = state
        .state_store
        .insert_build(BuildInsert {
            phase: "building",
            task_id: Some(failed_task),
            ..sample_build("bannerline-pkg-1.0-1.fc42", PRIORITY_DEFAULT)
        })
        .await
        .unwrap();
    // install-deps 闭合失败（END exit 1）+ build 未闭合失败，横幅取最后一个（build，START 在第 3 行）。
    let dir = tmp.path().join("results").join(failed.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("build.log"),
        "# CRBS_PHASE_START install-deps 10.0\n\
         # CRBS_PHASE_END install-deps 1 12.0\n\
         # CRBS_PHASE_START build 12.0\n\
         cc -O2 kernel.c\n",
    )
    .unwrap();
    // result_dir 须经 complete 落库（complete 的 SET 会覆盖手工 UPDATE）。
    state
        .state_store
        .complete_build_with_error(
            failed,
            "failed",
            Some(dir.to_str().unwrap()),
            Some("exit_code=2 phase=build"),
        )
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, &format!("/ui/builds/{failed}")).await;
    // 横幅链接带 build START 标记行 ?line=3；页头 View logs 主入口不带 line。
    assert!(
        html.contains(&format!(r#"href="/ui/builds/{failed}/logs?line=3""#)),
        "{html}"
    );
    assert!(!html.contains("→</small>"), "{html}");
}

/// Builds 列 count-badge 下钻 + 着色：badge 链到 /ui/builds?task_id=&phase=
/// 过滤视图（修饰类与 phase_badge 同族令牌）；展示序固定：building（执行段）在 succeeded（终态段）前。
#[tokio::test]
async fn task_list_build_counts_link_to_filtered_builds_and_use_phase_colors() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let task = state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name: "counts-pkg-1.0-1.fc42",
            user: "ui-tester",
            phase: "building",
            ..Default::default()
        })
        .await
        .unwrap();
    for (phase, arch) in [("building", "x86_64"), ("succeeded", "aarch64")] {
        state
            .state_store
            .insert_build(BuildInsert {
                phase,
                arch: Some(arch),
                task_id: Some(task),
                ..sample_build("counts-pkg-1.0-1.fc42", PRIORITY_DEFAULT)
            })
            .await
            .unwrap();
    }

    let html = get_page(&app, &admin_token, "/ui/tasks").await;
    for phase in ["building", "succeeded"] {
        assert!(
            html.contains(&format!(
                r#"href="/ui/builds?task_id={task}&amp;phase={phase}""#
            )),
            "{html}"
        );
    }
    assert!(
        html.contains(r#"<span class="count-badge running">building: 1</span>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<span class="count-badge success">succeeded: 1</span>"#),
        "{html}"
    );
    let building_at = html.find("count-badge running").expect("building badge");
    let succeeded_at = html.find("count-badge success").expect("succeeded badge");
    assert!(building_at < succeeded_at, "{html}");
}

/// pending/assigned 构建日志页：内联脚本监听 build SSE，phase 离开排队态即整页 reload。
#[tokio::test]
async fn pending_build_log_page_auto_refreshes_when_started() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let task = state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name: "pendinglog-pkg-1.0-1.fc42",
            user: "ui-tester",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();
    let build = state
        .state_store
        .insert_build(BuildInsert {
            phase: "pending",
            task_id: Some(task),
            ..sample_build("pendinglog-pkg-1.0-1.fc42", PRIORITY_DEFAULT)
        })
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, &format!("/ui/builds/{build}/logs")).await;
    assert!(
        html.contains(
            "Build has not started yet. This page will refresh automatically when it starts."
        ),
        "{html}"
    );
    assert!(
        html.contains(&format!("new EventSource('/ui/builds/{build}/events')")),
        "{html}"
    );
    assert!(
        html.contains("location.reload()"),
        "pending log page must reload on start: {html}"
    );
}

/// 终态日志页截断提示用人类可读大小（humansize DECIMAL，与产物表同口径）。
#[tokio::test]
async fn terminal_build_log_truncation_notice_uses_human_sizes() {
    let (state, app, tmp, admin_token) = setup_app_with_admin().await;
    let build = insert_direct_build(&state, "biglog-pkg-1.0-1.fc42", PRIORITY_DEFAULT).await;
    // build.log 300 KiB > 256 KiB 内联上限（result root = <crbs_root>/results）。
    let dir = tmp.path().join("results").join(build.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("build.log"), vec![b'x'; 300 * 1024]).unwrap();
    sqlx::query("UPDATE builds SET result_dir = $1 WHERE id = $2")
        .bind(dir.to_str().unwrap())
        .bind(build)
        .execute(state.state_store.pool())
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, &format!("/ui/builds/{build}/logs")).await;
    // 262144 → "262.14 kB"，307200 → "307.20 kB"（humansize 定点两位小数）。
    assert!(
        html.contains("Showing last 262.14 kB of 307.20 kB total."),
        "{html}"
    );
    assert!(!html.contains(" bytes of "), "{html}");
}

/// build.log 带 CRBS_PHASE 标记 → 详情/日志页渲阶段时间线（含 failed 步与时长）；dl 后、artifacts 前。
#[tokio::test]
async fn build_pages_render_phase_timeline_from_log_markers() {
    let (state, app, tmp, admin_token) = setup_app_with_admin().await;
    let build = state
        .state_store
        .insert_build(BuildInsert {
            phase: "failed",
            task_id: Some(
                crbs_server::test_support::seed_task(
                    &state.state_store,
                    "mydist",
                    "phased-pkg-1.0-1.fc42",
                )
                .await,
            ),
            ..sample_build("phased-pkg-1.0-1.fc42", PRIORITY_DEFAULT)
        })
        .await
        .unwrap();
    let dir = tmp.path().join("results").join(build.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("build.log"),
        "# CRBS_PHASE_START install-srpm 100.0\n\
         rpm output\n\
         # CRBS_PHASE_END install-srpm 0 100.4\n\
         # CRBS_PHASE_START install-deps 100.4\n\
         dnf output\n\
         # CRBS_PHASE_END install-deps 2 165.5\n",
    )
    .unwrap();
    sqlx::query("UPDATE builds SET result_dir = $1 WHERE id = $2")
        .bind(dir.to_str().unwrap())
        .bind(build)
        .execute(state.state_store.pool())
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, &format!("/ui/builds/{build}")).await;
    assert!(
        html.contains(r#"<div class="phase-timeline">"#),
        "detail page timeline missing: {html}"
    );
    assert!(
        html.contains(r#"class="phase-step done" data-phase="install-srpm""#),
        "{html}"
    );
    assert!(
        html.contains(r#"class="phase-step failed" data-phase="install-deps""#),
        "{html}"
    );
    // 详情页步骤为 span 不可点：全文件行号遇截断 tail 会错位，锚形态只留日志页终态分支。
    assert!(!html.contains("<a class=\"phase-step"), "{html}");
    // 时长：0.4s（亚秒）与 65.1s（超分钟走 1m 5s 口径）。
    assert!(html.contains(r#">0.4s</span>"#), "{html}");
    assert!(html.contains(r#">1m 5s</span>"#), "{html}");

    let html = get_page(&app, &admin_token, &format!("/ui/builds/{build}/logs")).await;
    assert!(
        html.contains(r#"class="phase-step failed" data-phase="install-deps""#),
        "logs page timeline missing: {html}"
    );
    // 终态日志页步骤可点：href 携带该 phase 标记行（install-deps START 在 fixture 第 4 行）。
    assert!(
        html.contains(&format!(
            r#"<a class="phase-step failed" data-phase="install-deps" data-start="100.4" href="/ui/builds/{build}/logs?line=4">"#
        )),
        "{html}"
    );

    // ?line=N 行锚定：内联 nonce'd 脚本带目标行号 + 高亮类名（详情页失败面板跳转落点契约）。
    let html = get_page(
        &app,
        &admin_token,
        &format!("/ui/builds/{build}/logs?line=2"),
    )
    .await;
    assert!(html.contains("var target = 2;"), "{html}");
    assert!(html.contains("log-line-hit"), "{html}");

    // live（building）页 phase-step 保持 span：preview tail 行号不可靠 + SSE 脚本整串改写 className。
    sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
        .bind(build)
        .execute(state.state_store.pool())
        .await
        .unwrap();
    let html = get_page(&app, &admin_token, &format!("/ui/builds/{build}/logs")).await;
    assert!(
        html.contains(r#"<span class="phase-step failed" data-phase="install-deps""#),
        "{html}"
    );
    assert!(!html.contains("<a class=\"phase-step"), "{html}");
}

/// 标记扫描为全文件流式（非 64KB tail 窗口）：首部 >64KB 噪声 + 双 SKIP 夹
/// 三步的真实管线标记，早期步骤标记不得因窗口截断丢失。
#[tokio::test]
async fn build_phase_timeline_reads_markers_across_large_logs() {
    let (state, app, tmp, admin_token) = setup_app_with_admin().await;
    let build = insert_direct_build(&state, "bigphase-pkg-1.0-1.fc42", PRIORITY_DEFAULT).await;
    // 首部噪声：2000 行 × ~44 字节 ≈ 88KB，验证标记扫描不依赖任何窗口。
    let mut log = String::new();
    for i in 0..2000 {
        log.push_str(&format!("noise line {i:04} rpm build output padding xx\n"));
    }
    log.push_str("# CRBS_PHASE_SKIP ccache-init ccache_disabled\n");
    log.push_str("# CRBS_PHASE_START install-srpm 100.0\n");
    log.push_str("# CRBS_PHASE_END install-srpm 0 100.4\n");
    log.push_str("# CRBS_PHASE_START install-deps 100.4\n");
    log.push_str("# CRBS_PHASE_END install-deps 0 130.0\n");
    log.push_str("# CRBS_PHASE_START build 130.0\n");
    log.push_str("# CRBS_PHASE_END build 0 190.5\n");
    log.push_str("# CRBS_PHASE_SKIP ccache-summary ccache_disabled\n");
    let dir = tmp.path().join("results").join(build.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("build.log"), log).unwrap();
    sqlx::query("UPDATE builds SET result_dir = $1 WHERE id = $2")
        .bind(dir.to_str().unwrap())
        .bind(build)
        .execute(state.state_store.pool())
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, &format!("/ui/builds/{build}")).await;
    // 3 个可见步均被扫到；ccache 工具步骤（恒 0s 非构建阶段）按名隐藏：不渲染、不聚进 skip-chip。
    for phase in ["install-srpm", "install-deps", "build"] {
        assert!(
            html.contains(&format!(r#"data-phase="{phase}""#)),
            "phase step {phase} missing from timeline: {html}"
        );
    }
    for phase in ["ccache-init", "ccache-summary"] {
        assert!(
            !html.contains(&format!(r#"data-phase="{phase}""#)),
            "hidden tool phase {phase} must not render: {html}"
        );
    }
    assert!(
        !html.contains(r#"class="skip-chip""#),
        "hidden tool phases must not aggregate into a chip: {html}"
    );
    assert!(
        html.contains(r#"class="phase-step done" data-phase="install-srpm""#),
        "{html}"
    );
    assert!(html.contains(r#">0.4s</span>"#), "{html}");
}

/// 终态日志页时间线数据源 = 全文件流式 phase_timeline_spans（与详情页同源）：
/// >256KB 日志头部标记不随内联 tail 丢失；截断 tail 下行号超页内范围，步骤
/// 渲静态 span 不出死链（可点契约 = 行号与页内文本自洽）。
#[tokio::test]
async fn terminal_log_page_timeline_scans_markers_beyond_inline_tail() {
    let (state, app, tmp, admin_token) = setup_app_with_admin().await;
    let build = insert_direct_build(&state, "bigtail-pkg-1.0-1.fc42", PRIORITY_DEFAULT).await;
    // 头部真实标记 + 尾部噪声把标记推出 256KB 内联窗口（7000×~48B ≈ 336KB）。
    let mut log = String::from(
        "# CRBS_PHASE_START install-srpm 100.0\n\
         # CRBS_PHASE_END install-srpm 0 100.4\n\
         # CRBS_PHASE_START build 100.4\n\
         # CRBS_PHASE_END build 0 200.0\n",
    );
    for i in 0..7000 {
        log.push_str(&format!(
            "noise line {i:04} rpm build output padding xxxxx\n"
        ));
    }
    let dir = tmp.path().join("results").join(build.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("build.log"), log).unwrap();
    sqlx::query("UPDATE builds SET result_dir = $1 WHERE id = $2")
        .bind(dir.to_str().unwrap())
        .bind(build)
        .execute(state.state_store.pool())
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, &format!("/ui/builds/{build}/logs")).await;
    assert!(html.contains("Showing last"), "{html}");
    assert!(
        html.contains(r#"<div class="phase-timeline">"#),
        "timeline must render even when markers fall outside the inline tail: {html}"
    );
    assert!(
        html.contains(r#"class="phase-step done" data-phase="install-srpm""#),
        "{html}"
    );
    assert!(html.contains(r#">0.4s</span>"#), "{html}");
    assert!(
        html.contains(r#"class="phase-step done" data-phase="build""#),
        "{html}"
    );
    assert!(!html.contains("<a class=\"phase-step"), "{html}");
}

/// live（building）日志页恒渲染 .phase-timeline 容器：无标记（无 result_dir、
/// LogBuffer 未注册）时渲 pending 骨架，SSE 标记到达后由 log_sse_script
/// 就地推进；容器缺位经 timelineEl() 自建，否则 SSR 空窗后标记全丢。
#[tokio::test]
async fn building_log_page_always_renders_phase_timeline_with_skeleton() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let build = insert_direct_build(&state, "liveskel-pkg-1.0-1.fc42", PRIORITY_DEFAULT).await;
    sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
        .bind(build)
        .execute(state.state_store.pool())
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, &format!("/ui/builds/{build}/logs")).await;
    assert!(
        html.contains(r#"<div class="phase-timeline">"#),
        "live log page must always render the timeline container: {html}"
    );
    for name in [
        "prepare-layer",
        "install-srpm",
        "install-deps",
        "build",
        "collect-artifacts",
    ] {
        assert!(
            html.contains(&format!(
                r#"class="phase-step pending" data-phase="{name}""#
            )),
            "missing skeleton step {name}: {html}"
        );
    }
    assert!(html.contains("function timelineEl()"), "{html}");
    assert!(!html.contains("if (!timeline) return;"), "{html}");
}

/// `?which=root` 被 axum 静默忽略：页面与 API 一律回落 build.log，无 log-tab。
#[tokio::test]
async fn log_page_and_api_ignore_legacy_which_param_and_serve_build_log() {
    let (state, app, tmp, admin_token) = setup_app_with_admin().await;
    let build = insert_direct_build(&state, "whichlegacy-pkg-1.0-1.fc42", PRIORITY_DEFAULT).await;
    let dir = tmp.path().join("results").join(build.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("build.log"), "build-log-only\n").unwrap();
    // 旧结果目录遗留的 root.log：不读取、不迁移。
    std::fs::write(dir.join("root.log"), "legacy-root-log\n").unwrap();
    sqlx::query("UPDATE builds SET result_dir = $1 WHERE id = $2")
        .bind(dir.to_str().unwrap())
        .bind(build)
        .execute(state.state_store.pool())
        .await
        .unwrap();

    let html = get_page(
        &app,
        &admin_token,
        &format!("/ui/builds/{build}/logs?which=root"),
    )
    .await;
    assert!(html.contains("build-log-only"), "{html}");
    assert!(!html.contains("legacy-root-log"), "{html}");
    assert!(!html.contains("log-tab"), "{html}");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/builds/{build}/logs?offset=0&which=root"))
                .header("Authorization", format!("Bearer {admin_token}"))
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
    assert!(text.contains("build-log-only"), "{text}");
    assert!(!text.contains("legacy-root-log"), "{text}");
}

/// build 详情生命周期行（并入 Details 卡）：pending 构建只渲染 Queued 活状态行
/// （"至今"走秒 span）；派发 → 认领（worker_tasks.started_at）→ 完成
/// （builds.completed_at）后渲染 Queued/Picked up（含执行 worker 链接）/Ran/
/// Completed 四行定格值。
#[tokio::test]
async fn build_detail_renders_lifecycle_stages() {
    use crbs_core::BuildInsert;

    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let worker_id = state
        .state_store
        .upsert_worker("lc-worker", "x86_64", 1, "test", "online", None)
        .await
        .unwrap();

    // 刚提交、未派发：只有 Queued 行，值为"至今"走秒 span（data-ts/data-tpl）。
    let build = state
        .state_store
        .insert_build(BuildInsert {
            phase: "pending",
            task_id: Some(
                crbs_server::test_support::seed_task(
                    &state.state_store,
                    "mydist",
                    "lc-pkg-1.0-1.fc42",
                )
                .await,
            ),
            ..sample_build("lc-pkg-1.0-1.fc42", PRIORITY_DEFAULT)
        })
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, &format!("/ui/builds/{build}")).await;
    assert!(html.contains("<dt>Queued</dt>"), "{html}");
    // 活状态走秒 span：起点（data-ts）+ i18n 模板（data-tpl）。
    assert!(html.contains(r#"class="lc-so-far""#), "{html}");
    assert!(html.contains(r#"data-ts="#), "{html}");
    assert!(html.contains(r#"data-tpl="{0} so far""#), "{html}");
    // 缺派发：只有 Queued 行。
    assert!(!html.contains("<dt>Picked up</dt>"), "{html}");
    assert!(!html.contains("<dt>Ran</dt>"), "{html}");
    assert!(!html.contains("<dt>Completed</dt>"), "{html}");

    // 派发 → 认领（started_at）→ 完成（completed_at）：四行全值 + worker 链接。
    state
        .state_store
        .assign_build_to_worker(build, worker_id)
        .await
        .unwrap();
    let started = (chrono::Utc::now() - chrono::TimeDelta::minutes(2))
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string();
    sqlx::query("UPDATE worker_tasks SET started_at = $1 WHERE build_id = $2")
        .bind(&started)
        .bind(build)
        .execute(state.state_store.pool())
        .await
        .unwrap();
    state
        .state_store
        .complete_build(build, "succeeded", None)
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, &format!("/ui/builds/{build}")).await;
    // 三段定格时长行齐备，活状态走秒 span 消失（脚本本体含 .lc-so-far 选择器，
    // 只可断言 span 形态缺席）。
    assert!(!html.contains(r#"class="lc-so-far""#), "{html}");
    assert!(!html.contains("<dt>Queued</dt><dd>—</dd>"), "{html}");
    assert!(html.contains("<dt>Picked up</dt>"), "{html}");
    assert!(html.contains("<dt>Ran</dt>"), "{html}");
    // Finished 行（复用 LabelCompleted 文案 "Completed"）保留绝对+相对时间。
    assert!(html.contains("<dt>Completed</dt><dd><code>"), "{html}");
    // 认领段带执行 worker 链接（worker 名 → worker 页）。
    assert!(
        html.contains(r#"<a class="id-link" href="/ui/workers/1">lc-worker</a>"#),
        "{html}"
    );
}
