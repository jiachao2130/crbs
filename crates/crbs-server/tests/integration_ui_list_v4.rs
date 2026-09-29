// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 列表页共享组件集成测试：相位 chips（计数与种子对账、过滤链接 URL、
//! active 态）、激活过滤 chips（渲染 + 移除链接）、#ID mono 链接、user_cell
//! avatar。products / workers / packages / admin users / audit 套用同款要素。

// 测试 crate：辅助函数（seed_* 等）不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::{ProductConfig, ServerConfig};
use crbs_core::{BuildInsert, CreateProductInput, TaskInsert};
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;

mod common;

use common::TEST_CONFIG_DIR;

async fn setup_app_with_admin() -> (Arc<AppState>, axum::Router, tempfile::TempDir, String) {
    let _ = TEST_CONFIG_DIR.path();
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        state_store,
        ServerConfig::default(),
        tmp_dir.path().to_path_buf(),
    ));
    let admin_token = seed_user_token_for_test(&app_state.state_store, "admin-op", "admin")
        .await
        .expect("seed admin token");
    let app = create_test_app_with_auth(app_state.clone());
    (app_state, app, tmp_dir, admin_token)
}

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

fn sample_build(pkg: &'static str, phase: &'static str) -> BuildInsert<'static> {
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

/// seed 一条挂在任务下的构建并返回 build id（默认视图仅显示任务构建）。
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

/// 相位 chips 计数与种子对账（2 succeeded + 1 failed）；product 过滤下计数收窄到该产品。
#[tokio::test]
async fn builds_phase_chips_reconcile_with_seed() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    for (pkg, phase) in [
        ("ok-a-pkg-1.0-1.fc42", "succeeded"),
        ("ok-b-pkg-1.0-1.fc42", "succeeded"),
        ("bad-pkg-1.0-1.fc42", "failed"),
    ] {
        insert_task_build(&state, sample_build(pkg, phase)).await;
    }
    insert_task_build(
        &state,
        BuildInsert {
            product: "fedora",
            pkg_name: "other-pkg-1.0-1.fc42",
            ..sample_build("other-pkg-1.0-1.fc42", "succeeded")
        },
    )
    .await;

    let html = get_page(&app, &admin_token, "/ui/builds").await;
    assert!(html.contains(r#"<div class="phase-chips">"#), "{html}");
    // h1 count-chip 与 All chip 都是全量口径（含 fedora 行：无 product 过滤）。
    assert!(
        html.contains(r#"<h1>Builds <span class="count-chip">4</span></h1>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<a class="phase-chip active" href="/ui/builds"><b>4</b> All</a>"#),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<a class="phase-chip succeeded" href="/ui/builds?phase=succeeded"><b>3</b> Succeeded</a>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<a class="phase-chip failed" href="/ui/builds?phase=failed"><b>1</b> Failed</a>"#
        ),
        "{html}"
    );

    let html = get_page(&app, &admin_token, "/ui/builds?product=mydist").await;
    assert!(
        html.contains(
            r#"<a class="phase-chip active" href="/ui/builds?product=mydist"><b>3</b> All</a>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<a class="phase-chip succeeded" href="/ui/builds?product=mydist&amp;phase=succeeded"><b>2</b> Succeeded</a>"#
        ),
        "{html}"
    );
}

/// chip 链接 URL 保留当前其它过滤参数且 phase 正确、active 类正确。
#[tokio::test]
async fn phase_chip_links_preserve_filters_and_mark_active() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    for (pkg, phase) in [
        ("ok-a-pkg-1.0-1.fc42", "succeeded"),
        ("bad-pkg-1.0-1.fc42", "failed"),
    ] {
        insert_task_build(&state, sample_build(pkg, phase)).await;
    }

    let html = get_page(
        &app,
        &admin_token,
        "/ui/builds?product=mydist&phase=succeeded",
    )
    .await;
    assert!(
        html.contains(
            r#"<a class="phase-chip succeeded active" href="/ui/builds?product=mydist&amp;phase=succeeded"><b>1</b> Succeeded</a>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<a class="phase-chip failed" href="/ui/builds?product=mydist&amp;phase=failed"><b>1</b> Failed</a>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(r#"<a class="phase-chip" href="/ui/builds?product=mydist"><b>2</b> All</a>"#),
        "{html}"
    );

    let html = get_page(&app, &admin_token, "/ui/tasks?phase=failed").await;
    assert!(
        html.contains(
            r#"<a class="phase-chip failed active" href="/ui/tasks?phase=failed"><b>1</b> Failed</a>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(r#"<a class="phase-chip" href="/ui/tasks"><b>2</b> All</a>"#),
        "{html}"
    );
}

/// 激活过滤 chips：f-chip（label: value + ✕ 移除链接）出现，remove 去掉该参数且保留其它；无过滤时不渲染容器。
#[tokio::test]
async fn filter_chips_render_and_remove_links_drop_own_param() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    insert_task_build(
        &state,
        BuildInsert {
            priority: 1, // 高优
            ..sample_build("hi-pkg-1.0-1.fc42", "succeeded")
        },
    )
    .await;

    let html = get_page(
        &app,
        &admin_token,
        "/ui/builds?product=mydist&phase=succeeded",
    )
    .await;
    // phase 的 remove：去掉 phase、保留 product（列头/标签用 Status）。
    assert!(
        html.contains(
            r#"<span class="f-chip">Status: Succeeded <a href="/ui/builds?product=mydist" title="Remove filter">✕</a></span>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<span class="f-chip">Product: mydist <a href="/ui/builds?phase=succeeded" title="Remove filter">✕</a></span>"#
        ),
        "{html}"
    );

    // priority chip 的 value 走显示名（high）。
    let html = get_page(&app, &admin_token, "/ui/builds?priority=1").await;
    assert!(
        html.contains(r#"<span class="f-chip">Priority: high <a href="/ui/builds" title="Remove filter">✕</a></span>"#),
        "{html}"
    );

    // 无过滤：不渲染容器；断言钉 DOM 形态 `<div class="filter-chips">`（内联 CSS 类名不算）。
    let html = get_page(&app, &admin_token, "/ui/builds").await;
    assert!(!html.contains(r#"<div class="filter-chips">"#), "{html}");
}

/// 任务标签：?label=key=value 只留带该标签的任务，激活 chip 可移除；相位 chips
/// 与列表同口径（含 label 过滤）；详情页 pill 链回同标签过滤列表。
#[tokio::test]
async fn task_label_filter_chip_and_detail_pills() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let tagged = state
        .state_store
        .create_task_with_labels(
            TaskInsert {
                product: "mydist",
                pkg_name: "tagged-pkg-1.0-1.fc42",
                user: "ui-tester",
                phase: "succeeded",
                ..Default::default()
            },
            &[
                ("branch".to_string(), "main".to_string()),
                ("ci".to_string(), "1234".to_string()),
            ],
        )
        .await
        .unwrap();
    state
        .state_store
        .insert_build(BuildInsert {
            task_id: Some(tagged),
            ..sample_build("tagged-pkg-1.0-1.fc42", "succeeded")
        })
        .await
        .unwrap();
    insert_task_build(&state, sample_build("untagged-pkg-1.0-1.fc42", "succeeded")).await;

    let html = get_page(&app, &admin_token, "/ui/tasks?label=ci%3D1234").await;
    assert!(html.contains("tagged-pkg-1.0-1.fc42"), "{html}");
    assert!(!html.contains("untagged-pkg-1.0-1.fc42"), "{html}");
    assert!(
        html.contains(
            r#"<span class="f-chip">Labels: ci=1234 <a href="/ui/tasks" title="Remove filter">✕</a></span>"#
        ),
        "{html}"
    );
    // chips 计数同口径：All=1；链接保留 label 并追加 phase。
    assert!(
        html.contains(
            r#"<a class="phase-chip active" href="/ui/tasks?label=ci%3D1234"><b>1</b> All</a>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<a class="phase-chip succeeded" href="/ui/tasks?label=ci%3D1234&amp;phase=succeeded"><b>1</b> Succeeded</a>"#
        ),
        "{html}"
    );

    // 详情页 pill：key/value 两段，href 为编码后的同标签过滤 URL。
    let html = get_page(&app, &admin_token, &format!("/ui/tasks/{tagged}")).await;
    assert!(
        html.contains(r#"<a class="task-label" href="/ui/tasks?label=ci%3D1234" title="ci=1234">"#),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<span class="task-label-key">ci</span><span class="task-label-value">1234</span>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<a class="task-label" href="/ui/tasks?label=branch%3Dmain" title="branch=main">"#
        ),
        "{html}"
    );

    // 无过滤时激活 chip 容器不渲染（与其它列表页同口径）。
    let html = get_page(&app, &admin_token, "/ui/tasks").await;
    assert!(!html.contains(r#"<div class="filter-chips">"#), "{html}");
}

/// ID 列 # 前缀 + mono 链接（row-target 契约）；User 列 avatar 首字母；空用户名 "?" avatar + 空串文本。
#[tokio::test]
async fn id_link_and_user_cell_render() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let first = insert_task_build(&state, sample_build("cell-pkg-1.0-1.fc42", "succeeded")).await;
    let _empty_user = insert_task_build(
        &state,
        BuildInsert {
            user: "",
            ..sample_build("anon-pkg-1.0-1.fc42", "succeeded")
        },
    )
    .await;

    let html = get_page(&app, &admin_token, "/ui/builds").await;
    assert!(html.contains("<th>Status</th>"), "{html}");
    // row-target 契约：整行点击脚本按它定位。
    assert!(
        html.contains(&format!(
            r#"<a class="row-target id-link" href="/ui/builds/{first}?back="#
        )),
        "{html}"
    );
    assert!(
        html.contains(&format!(">#{first}</a>")),
        "id link text must be #{first}: {html}"
    );
    assert!(
        html.contains(
            r#"<span class="user-cell"><span class="avatar" aria-hidden="true">U</span>ui-tester</span>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<span class="user-cell"><span class="avatar" aria-hidden="true">?</span></span>"#
        ),
        "empty user must render ? avatar with empty text: {html}"
    );

    let html = get_page(&app, &admin_token, "/ui/tasks").await;
    assert!(html.contains(r#"class="row-target id-link""#), "{html}");
    assert!(html.contains("<th>Status</th>"), "{html}");
    assert!(
        html.contains(
            r#"<span class="user-cell"><span class="avatar" aria-hidden="true">U</span>ui-tester</span>"#
        ),
        "{html}"
    );
}

// products / workers / packages / admin users / audit 套用同款列表要素。

/// 最小可解析 TOML（根产品必须声明至少一个 repo，chain-resolve 出口校验）。
const PRODUCT_TOML: &str = "\
base_packages = [\"bash\", \"rpm-build\"]
arches = [\"x86_64\"]

[[repos]]
name = \"base\"
baseurl = \"http://example.com/base/$basearch\"
gpgcheck = false
";

async fn seed_product(state: &AppState, name: &str, visibility: &str) {
    // DB CHECK：private 产品必须挂 owner——取种子的 admin-op。
    let owner_id = if visibility == "private" {
        Some(
            state
                .state_store
                .find_user_by_name("admin-op")
                .await
                .unwrap()
                .expect("admin-op exists")
                .id,
        )
    } else {
        None
    };
    state
        .state_store
        .create_product(CreateProductInput {
            name,
            display_name: None,
            owner_id,
            parent_id: None,
            visibility,
            config: &ProductConfig::from_str(PRODUCT_TOML).expect("product toml parses"),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap_or_else(|e| panic!("seed product '{name}': {e}"));
}

/// workers 列表：h1 count-chip、卡头过滤条、?status= 激活 f-chip（值显示名；remove 去该参数、保留其余、offset 归零）。
#[tokio::test]
async fn workers_list_v4_count_chip_card_toolbar_and_status_chip() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    state
        .state_store
        .upsert_worker("edge-x86-01", "x86_64", 2, "test", "online", None)
        .await
        .unwrap();
    let offline = state
        .state_store
        .upsert_worker("arm-a64-01", "aarch64", 1, "test", "online", None)
        .await
        .unwrap();
    state
        .state_store
        .worker_mark_offline(offline)
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, "/ui/workers").await;
    assert!(
        html.contains(r#"<h1>Workers <span class="count-chip">2</span></h1>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<div class="table-card"><form class="filter-bar""#),
        "{html}"
    );
    assert!(!html.contains(r#"<div class="filter-chips">"#), "{html}");

    let html = get_page(&app, &admin_token, "/ui/workers?name=arm&status=offline").await;
    assert!(
        html.contains(r#"<h1>Workers <span class="count-chip">1</span></h1>"#),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<span class="f-chip">Name: arm <a href="/ui/workers?status=offline" title="Remove filter">✕</a></span>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<span class="f-chip">Status: offline <a href="/ui/workers?name=arm" title="Remove filter">✕</a></span>"#
        ),
        "{html}"
    );
}

/// admin users 列表：h1 count-chip、卡头过滤条、?role= 激活 f-chip、Name 列 avatar、ID 列 #N mono 链接。
#[tokio::test]
async fn admin_users_list_v4_chips_card_toolbar_and_user_cell() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    let vera = state
        .state_store
        .create_user("vera", "viewer")
        .await
        .unwrap();
    state
        .state_store
        .create_user("victor", "builder")
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, "/ui/admin/users").await;
    // admin-op + vera + victor。
    assert!(
        html.contains(r#"<h1>Users <span class="count-chip">3</span></h1>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<div class="table-card"><form class="filter-bar""#),
        "{html}"
    );

    let html = get_page(&app, &admin_token, "/ui/admin/users?role=viewer").await;
    assert!(
        html.contains(r#"<h1>Users <span class="count-chip">1</span></h1>"#),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<span class="f-chip">Role: viewer <a href="/ui/admin/users" title="Remove filter">✕</a></span>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<td class="ellipsis" title="vera"><span class="user-cell"><span class="avatar" aria-hidden="true">V</span>vera</span></td>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(&format!(
            r#"><a class="row-target id-link" href="/ui/admin/users/{vera}?back="#
        )),
        "{html}"
    );
    assert!(
        html.contains(&format!(">#{vera}</a>")),
        "id link text must be #{vera}: {html}"
    );
}

/// products 列表：h1 count-chip、卡头过滤条、?visibility= 激活 f-chip（值显示名；name/visibility 参数语义不变，remove 互不干扰）。
#[tokio::test]
async fn products_list_v4_count_chip_and_visibility_chip() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    seed_product(&state, "mydist", "public").await;
    seed_product(&state, "mypriv", "private").await;

    let html = get_page(&app, &admin_token, "/ui/products").await;
    assert!(
        html.contains(r#"<h1>Products <span class="count-chip">2</span></h1>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<div class="table-card"><form class="filter-bar""#),
        "{html}"
    );

    let html = get_page(&app, &admin_token, "/ui/products?visibility=private").await;
    assert!(
        html.contains(r#"<h1>Products <span class="count-chip">1</span></h1>"#),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<span class="f-chip">Visibility: private <a href="/ui/products" title="Remove filter">✕</a></span>"#
        ),
        "{html}"
    );
    // avatar 行来自 mypriv（private 产品 owner = 种子 admin-op）。
    assert!(
        html.contains(
            r#"<span class="user-cell"><span class="avatar" aria-hidden="true">A</span>admin-op</span>"#
        ),
        "{html}"
    );

    let html = get_page(
        &app,
        &admin_token,
        "/ui/products?name=my&visibility=private",
    )
    .await;
    assert!(
        html.contains(
            r#"<span class="f-chip">Name: my <a href="/ui/products?visibility=private" title="Remove filter">✕</a></span>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<span class="f-chip">Visibility: private <a href="/ui/products?name=my" title="Remove filter">✕</a></span>"#
        ),
        "{html}"
    );
}

/// packages 列表：h1 count-chip、卡头过滤条、?product=/?name= 激活 f-chip（remove 去自身参数、保留对方、offset 归零）。
#[tokio::test]
async fn packages_list_v4_count_chip_card_toolbar_and_filter_chips() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    insert_task_build(&state, sample_build("chip-pkg-1.0-1.fc42", "succeeded")).await;

    let html = get_page(&app, &admin_token, "/ui/packages").await;
    assert!(
        html.contains(r#"<h1>Packages <span class="count-chip">1</span></h1>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<div class="table-card"><form class="filter-bar""#),
        "{html}"
    );

    let html = get_page(&app, &admin_token, "/ui/packages?product=mydist&name=chip").await;
    assert!(
        html.contains(
            r#"<span class="f-chip">Product: mydist <a href="/ui/packages?name=chip" title="Remove filter">✕</a></span>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<span class="f-chip">Package: chip <a href="/ui/packages?product=mydist" title="Remove filter">✕</a></span>"#
        ),
        "{html}"
    );
}

/// audit 列表：h1 count-chip、卡头过滤条、User 列 user_cell。
#[tokio::test]
async fn audit_list_v4_count_chip_card_toolbar_and_user_cell() {
    let (state, app, _tmp, admin_token) = setup_app_with_admin().await;
    state
        .state_store
        .audit_log("admin-op", "admin", "create_user", Some("42"), None)
        .await
        .unwrap();

    let html = get_page(&app, &admin_token, "/ui/admin/audit").await;
    assert!(
        html.contains(r#"<h1>Audit Logs <span class="count-chip">1</span></h1>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<div class="table-card"><form class="filter-bar""#),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<span class="user-cell"><span class="avatar" aria-hidden="true">A</span>admin-op</span>"#
        ),
        "{html}"
    );
}
