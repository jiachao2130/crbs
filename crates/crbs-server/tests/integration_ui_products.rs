// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产品详情页 Maintenance / Rebuild repo（UI 表单 POST）集成测试。
//!
//! 复用 crbs_token cookie 会话：CSRF token 从详情页 HTML 提取回发；空产品
//! assemble 是合法路径（候选集空、`_repo` 不存在 → 空 report，无需 createrepo_c）。

// 测试辅助函数（seed_* 等）不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
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

/// 最小可解析 TOML；根产品必须声明至少一个 repo（chain-resolve 出口校验）。
const SAMPLE_TOML: &str = "\
base_packages = [\"bash\", \"rpm-build\"]
arches = [\"x86_64\"]

[[repos]]
name = \"base\"
baseurl = \"http://example.com/base/$basearch\"
gpgcheck = false
";

fn sample_config() -> ProductConfig {
    ProductConfig::from_str(SAMPLE_TOML).expect("sample product toml parses")
}

/// 共享配置目录见 `tests/common/mod.rs`：`CRBS_CONFIG_DIR` 指向可写 tempdir，避免读 `/etc/crbs` 触发 Permission denied。
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
    let app_state = Arc::new(AppState::for_test(
        state_store,
        ServerConfig::default(),
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

/// 直接经 state 层 seed 一个产品（`owner_id=None` 为官方 public 产品）。
async fn seed_product(state: &AppState, name: &str, owner_id: Option<i64>) {
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
            config: &sample_config(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap_or_else(|e| panic!("seed product '{name}': {e}"));
}

/// GET 产品详情页，返回 (status, html)。
async fn get_product_page(app: &axum::Router, token: &str, name: &str) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ui/products/{name}"))
                .header("Cookie", format!("crbs_token={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// POST rebuild-repo 表单，返回 (status, Location)。
async fn post_rebuild_repo(
    app: &axum::Router,
    token: &str,
    name: &str,
    csrf: &str,
) -> (StatusCode, Option<String>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/products/{name}/rebuild-repo"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", format!("crbs_token={token}"))
                .body(Body::from(format!("csrf_token={csrf}")))
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

async fn rebuild_repo_audit_rows(state: &AppState) -> Vec<crbs_core::AuditLog> {
    state
        .state_store
        .list_audit_logs(AuditLogFilter {
            action: Some("rebuild_repo"),
            ..Default::default()
        })
        .await
        .expect("list audit logs")
}

/// admin POST 重建（空产品，无构建产物）→ 303 带 status=repo_rebuilt；审计行
/// action=rebuild_repo、target=产品名、detail 与 API 侧同结构。
#[tokio::test]
async fn admin_rebuild_repo_redirects_and_audits() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-op", "admin")]).await;
    seed_product(&state, "mydist", None).await;

    // 详情页对 admin 渲染 Maintenance 区块与 rebuild 表单。
    let (status, html) = get_product_page(&app, &tokens["admin-op"], "mydist").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("<h2>Danger zone</h2>"), "{html}");
    assert!(html.contains("/ui/products/mydist/rebuild-repo"), "{html}");
    let csrf = common::extract_csrf_token(&html).expect("CSRF token should be present");

    let (status, location) = post_rebuild_repo(&app, &tokens["admin-op"], "mydist", &csrf).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location.as_deref(),
        Some("/ui/products/mydist?status=repo_rebuilt"),
        "success should redirect with repo_rebuilt status"
    );

    let logs = rebuild_repo_audit_rows(&state).await;
    assert_eq!(logs.len(), 1, "exactly one rebuild_repo audit row");
    assert_eq!(logs[0].target.as_deref(), Some("mydist"));
    let detail = logs[0].detail.as_deref().expect("audit detail present");
    assert!(
        detail.contains("\"product\":\"mydist\""),
        "detail: {detail}"
    );
    assert!(detail.contains("\"arches\""), "detail: {detail}");
}

/// 非 admin（产品 owner，builder 角色）POST → 404、无审计行；详情页不渲染 Maintenance 区块。
#[tokio::test]
async fn owner_builder_rebuild_repo_returns_404() {
    let (state, app, _tmp, tokens) = setup_app(&[("builder-op", "builder")]).await;
    let builder = user_id(&state, "builder-op").await;
    seed_product(&state, "mydist", Some(builder)).await;

    // owner（非 admin）能看到带 CSRF 的管理区块，但看不到 Maintenance。
    let (status, html) = get_product_page(&app, &tokens["builder-op"], "mydist").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!html.contains("<h2>Maintenance</h2>"), "{html}");
    let csrf = common::extract_csrf_token(&html).expect("CSRF token should be present");

    let (status, _location) = post_rebuild_repo(&app, &tokens["builder-op"], "mydist", &csrf).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        rebuild_repo_audit_rows(&state).await.is_empty(),
        "no rebuild_repo audit row for non-admin"
    );
}

/// admin POST 到不存在的产品 → 404（与权限失败同口径，防探测）。
#[tokio::test]
async fn admin_rebuild_repo_missing_product_returns_404() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-op", "admin")]).await;
    // CSRF token 按 session 派生，从任意渲染表单的页面取（目标产品页本身 404）。
    seed_product(&state, "anchor-prod", None).await;
    let (status, html) = get_product_page(&app, &tokens["admin-op"], "anchor-prod").await;
    assert_eq!(status, StatusCode::OK);
    let csrf = common::extract_csrf_token(&html).expect("CSRF token should be present");

    let (status, _location) =
        post_rebuild_repo(&app, &tokens["admin-op"], "no-such-product", &csrf).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        rebuild_repo_audit_rows(&state).await.is_empty(),
        "no rebuild_repo audit row for missing product"
    );
}

// ==== 列表页过滤 + 分页（name/visibility 过滤、50/页、批量加载） ====

/// GET 产品列表页，返回 (status, html)。
async fn get_products_page(app: &axum::Router, token: &str, query: &str) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ui/products{query}"))
                .header("Cookie", format!("crbs_token={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// name 模糊匹配（contains，大小写不敏感）+ visibility 精确过滤 + 过滤回显。
#[tokio::test]
async fn products_page_filters_by_name_and_visibility() {
    let (state, app, _tmp, tokens) =
        setup_app(&[("admin-op", "admin"), ("owner-bob", "builder")]).await;
    let bob = user_id(&state, "owner-bob").await;
    seed_product(&state, "mydist", None).await;
    seed_product(&state, "fedora40", None).await;
    seed_product(&state, "mypriv", Some(bob)).await; // private

    let (status, html) = get_products_page(&app, &tokens["admin-op"], "?visibility=private").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(r#"href="/ui/products/mypriv?"#),
        "private product row missing: {html}"
    );
    assert!(
        !html.contains(r#"href="/ui/products/mydist?"#),
        "public product must be filtered out by visibility=private"
    );
    assert!(
        html.contains(r#"<option value="private" selected>"#),
        "visibility option not selected: {html}"
    );

    let (status, html) = get_products_page(&app, &tokens["admin-op"], "?name=my").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(r#"href="/ui/products/mydist?"#), "{html}");
    assert!(html.contains(r#"href="/ui/products/mypriv?"#), "{html}");
    assert!(
        !html.contains(r#"href="/ui/products/fedora40""#),
        "name filter must exclude non-matching products"
    );
    assert!(html.contains(r#"value="my""#), "{html}");

    let (status, html) = get_products_page(&app, &tokens["admin-op"], "?name=MY").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(r#"href="/ui/products/mydist?"#), "{html}");
}

/// Visibility 列渲染 + 私有产品对无关用户不可见（可见性过滤不回归）。
#[tokio::test]
async fn products_page_shows_visibility_and_hides_private() {
    let (state, app, _tmp, tokens) = setup_app(&[
        ("admin-op", "admin"),
        ("owner-bob", "builder"),
        ("carol", "viewer"),
    ])
    .await;
    let bob = user_id(&state, "owner-bob").await;
    seed_product(&state, "mydist", None).await;
    seed_product(&state, "mypriv", Some(bob)).await; // private

    let (status, html) = get_products_page(&app, &tokens["admin-op"], "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("<th>Visibility</th>"), "{html}");
    assert!(html.contains(r#"href="/ui/products/mypriv?"#), "{html}");

    let (status, html) = get_products_page(&app, &tokens["carol"], "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("<th>Visibility</th>"), "{html}");
    assert!(html.contains(r#"href="/ui/products/mydist?"#), "{html}");
    assert!(
        !html.contains(r#"href="/ui/products/mypriv?"#),
        "private product must be hidden from unrelated users"
    );
}

/// 超一页（UI_PAGE_SIZE=50）时 Next 出现、第二页切片正确且末页 Next 禁用；分页链接与 users
/// 列表同格式（pagination_links raw_filter_qs + 过滤参数保留）；过滤命中不足一页时不渲染 Next。
#[tokio::test]
async fn products_page_paginates_large_product_set() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-op", "admin")]).await;
    for i in 0..55 {
        seed_product(&state, &format!("bulk-prod-{i:02}"), None).await;
    }
    seed_product(&state, "mydist", None).await;

    let (status, html) = get_products_page(&app, &tokens["admin-op"], "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(r#"href="/ui/products?offset=50""#),
        "Next link missing: {html}"
    );
    assert!(html.contains("1-50 of 56"), "pagination info wrong: {html}");
    assert!(html.contains(r#"href="/ui/products/bulk-prod-48?"#));
    assert!(
        !html.contains(r#"href="/ui/products/bulk-prod-50?"#),
        "page 1 overflow"
    );

    let (status, html) = get_products_page(&app, &tokens["admin-op"], "?offset=50").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("51-56 of 56"), "page 2 info wrong: {html}");
    assert!(html.contains(r#"href="/ui/products/bulk-prod-50?"#));
    assert!(html.contains(r#"href="/ui/products/mydist?"#));
    assert!(
        !html.contains(r#"href="/ui/products?offset=100""#),
        "Next must not link past the end"
    );

    let (status, html) =
        get_products_page(&app, &tokens["admin-op"], "?name=mydist&offset=0").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("1-1 of 1"), "{html}");
    assert!(
        !html.contains(r#"href="/ui/products?name=mydist&amp;offset=50""#),
        "no Next link for single-row filter result"
    );
}

// ==== 产品列表页活动聚合（Tasks / Last build 列） ====

/// 直插任务并显式落 submitted/completed 时间（insert_task 默认 submitted_at=now，无法断言 MAX(COALESCE) 与相对时间形态）。
async fn seed_task_with_times(
    state: &AppState,
    product: &str,
    pkg: &str,
    phase: &str,
    submitted_min_ago: i64,
    completed_min_ago: Option<i64>,
) {
    let id = state
        .state_store
        .insert_task(crbs_core::TaskInsert {
            product,
            pkg_name: pkg,
            user: "admin",
            phase,
            ..Default::default()
        })
        .await
        .unwrap();
    let ago = |m: i64| {
        (chrono::Utc::now() - chrono::TimeDelta::minutes(m))
            .format(crbs_core::util::DB_TIME_FMT)
            .to_string()
    };
    sqlx::query("UPDATE tasks SET submitted_at = $1, completed_at = $2 WHERE id = $3")
        .bind(ago(submitted_min_ago))
        .bind(completed_min_ago.map(ago))
        .bind(id)
        .execute(state.state_store.pool())
        .await
        .unwrap();
}

/// 活动列对账：mydist Tasks=3、Last build = MAX(COALESCE) 最新活动（in-flight submitted
/// 晚于终态 completed）；零任务行 0/"—"；base_os_revision/Backend 收进详情页；zh 列头双语。
#[tokio::test]
async fn products_page_activity_columns_reconcile_with_seed_tasks() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin", "admin")]).await;
    seed_product(&state, "mydist", None).await;
    seed_product(&state, "idle-prod", None).await;

    seed_task_with_times(
        &state,
        "mydist",
        "bash-5.2-1.x86_64",
        "succeeded",
        2900,
        Some(2880),
    )
    .await;
    seed_task_with_times(
        &state,
        "mydist",
        "bash-5.2-2.x86_64",
        "succeeded",
        40,
        Some(30),
    )
    .await;
    seed_task_with_times(&state, "mydist", "vim-9.1-1.x86_64", "pending", 5, None).await;

    let (status, html) = get_products_page(&app, &tokens["admin"], "").await;
    assert_eq!(status, StatusCode::OK);
    for expected in [
        r#"<th class="num">Tasks</th>"#,
        r#"<th class="num">Last build</th>"#,
        "<th>Name</th>",
        "<th>Owner</th>",
        "<th>Build target</th>",
    ] {
        assert!(html.contains(expected), "missing {expected}: {html}");
    }
    assert!(
        html.contains(r#"<td class="num">3</td>"#),
        "mydist task count: {html}"
    );
    assert!(
        html.contains(">5 min ago</span>"),
        "mydist last build rel time (latest activity = in-flight submitted_at): {html}"
    );
    assert!(
        html.contains(r#"<td class="num">0</td>"#),
        "idle-prod zero count: {html}"
    );
    assert!(
        html.contains(r#"<td class="num">—</td>"#),
        "idle-prod last build dash: {html}"
    );
    assert!(
        !html.contains("base_os_revision"),
        "list must drop base_os_revision column: {html}"
    );
    assert!(
        !html.contains("<th>Backend</th>"),
        "list must drop Backend column: {html}"
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/products")
                .header("Cookie", format!("crbs_token={}", tokens["admin"]))
                .header("Accept-Language", "zh-CN,zh;q=0.9")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let zh = String::from_utf8_lossy(&bytes).into_owned();
    assert!(zh.contains(r#"<th class="num">任务</th>"#), "{zh}");
    assert!(zh.contains(r#"<th class="num">最近构建</th>"#), "{zh}");
}

/// 详情页 General 区保留 base_os_revision 行与 Backend 有效值（product 覆盖 →
/// 全局 → 默认；SAMPLE_TOML 未设 backend → 默认 nspawn）。
#[tokio::test]
async fn product_detail_keeps_base_os_revision_and_backend_rows() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin", "admin")]).await;
    seed_product(&state, "mydist", None).await;

    let (status, html) = get_product_page(&app, &tokens["admin"], "mydist").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("base_os_revision"), "{html}");
    assert!(html.contains("<dt>Backend</dt>"), "{html}");
    assert!(html.contains("nspawn"), "effective backend default: {html}");
}

// ==== 管理操作安全化（303 flash / 服务端表单报错 / username 展示） ====

/// 构造 x-www-form-urlencoded 请求体（键值百分号编码，config_toml 换行/引号等自由文本安全穿过 serde_urlencoded）。
fn form_body(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// POST UI 表单，返回 (status, Location, body)——body 供 200 重渲染表单的断言。
async fn post_ui_form_with_cookie(
    app: &axum::Router,
    cookie: &str,
    uri: &str,
    body: &str,
) -> (StatusCode, Option<String>, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", cookie)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        location,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// POST UI 表单（crbs_token cookie 会话），返回 (status, Location, body)。
async fn post_ui_form(
    app: &axum::Router,
    token: &str,
    uri: &str,
    body: &str,
) -> (StatusCode, Option<String>, String) {
    post_ui_form_with_cookie(app, &format!("crbs_token={token}"), uri, body).await
}

/// GET 任意 UI 页面（完整 cookie 串，可附加 crbs_lang 等偏好 cookie），返回 (status, html)。
async fn get_ui_page_with_cookie(
    app: &axum::Router,
    cookie: &str,
    uri: &str,
) -> (StatusCode, String) {
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
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// GET 任意 UI 页面（crbs_token cookie 会话），返回 (status, html)。
async fn get_ui_page(app: &axum::Router, token: &str, uri: &str) -> (StatusCode, String) {
    get_ui_page_with_cookie(app, &format!("crbs_token={token}"), uri).await
}

/// owner POST visibility（private→public，root 无祖先链）→ 303 带 status=visibility_updated。
#[tokio::test]
async fn visibility_post_success_redirects_with_status() {
    let (state, app, _tmp, tokens) = setup_app(&[("owner-bob", "builder")]).await;
    let bob = user_id(&state, "owner-bob").await;
    seed_product(&state, "mypriv", Some(bob)).await; // private，revision 1

    let (status, html) = get_product_page(&app, &tokens["owner-bob"], "mypriv").await;
    assert_eq!(status, StatusCode::OK);
    let csrf = common::extract_csrf_token(&html).expect("CSRF token should be present");

    let (status, location, _body) = post_ui_form(
        &app,
        &tokens["owner-bob"],
        "/ui/products/mypriv/visibility",
        &form_body(&[
            ("csrf_token", csrf.as_str()),
            ("visibility", "public"),
            ("expected_revision", "1"),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location.as_deref(),
        Some("/ui/products/mypriv?status=visibility_updated"),
        "success should redirect with visibility_updated status"
    );
}

/// revision 不匹配 → 303 带签名 error flash；跟随重定向渲染具体错误文案（非固定 fallback）。
#[tokio::test]
async fn visibility_post_revision_mismatch_redirects_with_signed_error_flash() {
    let (state, app, _tmp, tokens) = setup_app(&[("owner-bob", "builder")]).await;
    let bob = user_id(&state, "owner-bob").await;
    seed_product(&state, "mypriv", Some(bob)).await; // revision 1

    let (status, html) = get_product_page(&app, &tokens["owner-bob"], "mypriv").await;
    assert_eq!(status, StatusCode::OK);
    let csrf = common::extract_csrf_token(&html).expect("CSRF token should be present");

    let (status, location, _body) = post_ui_form(
        &app,
        &tokens["owner-bob"],
        "/ui/products/mypriv/visibility",
        &form_body(&[
            ("csrf_token", csrf.as_str()),
            ("visibility", "public"),
            ("expected_revision", "99"),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("error redirect carries Location");
    assert!(
        location.starts_with("/ui/products/mypriv?error="),
        "error flash should target the product page: {location}"
    );
    assert!(
        location.contains("&es="),
        "flash must carry the HMAC signature: {location}"
    );

    let (status, html) = get_ui_page(&app, &tokens["owner-bob"], &location).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("expected revision 99, current 1"),
        "signed error text should be rendered: {html}"
    );
    assert!(
        !html.contains("Operation failed."),
        "unsigned fallback must not replace the signed flash: {html}"
    );
}

/// zh cookie 下 revision 冲突 → 303 Location 含中文编码串，round-trip GET 后
/// body 呈现中文（POST 与 GET 共用同一 lang 协商 cookie）。
#[tokio::test]
async fn visibility_post_revision_conflict_flash_is_localized_for_zh() {
    let (state, app, _tmp, tokens) = setup_app(&[("owner-bob", "builder")]).await;
    let bob = user_id(&state, "owner-bob").await;
    seed_product(&state, "mypriv", Some(bob)).await; // revision 1

    let (status, html) = get_product_page(&app, &tokens["owner-bob"], "mypriv").await;
    assert_eq!(status, StatusCode::OK);
    let csrf = common::extract_csrf_token(&html).expect("CSRF token should be present");

    let zh_cookie = format!("crbs_token={}; crbs_lang=zh", tokens["owner-bob"]);
    let (status, location, _body) = post_ui_form_with_cookie(
        &app,
        &zh_cookie,
        "/ui/products/mypriv/visibility",
        &form_body(&[
            ("csrf_token", csrf.as_str()),
            ("visibility", "public"),
            ("expected_revision", "99"),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("error redirect carries Location");
    assert!(
        location.starts_with("/ui/products/mypriv?error="),
        "error flash should target the product page: {location}"
    );
    assert!(
        location.contains(urlencoding::encode("产品已被他人更新").as_ref()),
        "{location}"
    );

    // round-trip：多字节文案经 ?error= 编码往返必须原样渲染。
    let (status, html) = get_ui_page_with_cookie(&app, &zh_cookie, &location).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("产品已被他人更新（期望版本 99，当前 1）"),
        "zh flash not rendered: {html}"
    );
}

/// 官方产品 unpublish 的 0 参错误 flash zh round-trip：303 Location 含中文编码串，GET 后呈现完整中文句。
#[tokio::test]
async fn visibility_official_private_flash_is_localized_for_zh() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-op", "admin")]).await;
    seed_product(&state, "my-official", None).await; // 官方 public，revision 1

    let (status, html) = get_product_page(&app, &tokens["admin-op"], "my-official").await;
    assert_eq!(status, StatusCode::OK);
    let csrf = common::extract_csrf_token(&html).expect("CSRF token should be present");

    let zh_cookie = format!("crbs_token={}; crbs_lang=zh", tokens["admin-op"]);
    let (status, location, _body) = post_ui_form_with_cookie(
        &app,
        &zh_cookie,
        "/ui/products/my-official/visibility",
        &form_body(&[
            ("csrf_token", csrf.as_str()),
            ("visibility", "private"),
            ("expected_revision", "1"),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("error redirect carries Location");
    assert!(
        location.starts_with("/ui/products/my-official?error="),
        "{location}"
    );
    assert!(
        location.contains(urlencoding::encode("官方产品不能设为私有").as_ref()),
        "{location}"
    );

    let (status, html) = get_ui_page_with_cookie(&app, &zh_cookie, &location).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("官方产品不能设为私有；请先转让所有权。"),
        "zh flash not rendered: {html}"
    );
}

/// ACL grant 目标用户不存在的 1 参错误 flash zh round-trip：占位符实值（用户名）随中文句渲染。
#[tokio::test]
async fn acl_grant_user_not_found_flash_is_localized_for_zh() {
    let (state, app, _tmp, tokens) = setup_app(&[("owner-bob", "builder")]).await;
    let bob = user_id(&state, "owner-bob").await;
    seed_product(&state, "mypriv", Some(bob)).await;

    let (status, html) = get_product_page(&app, &tokens["owner-bob"], "mypriv").await;
    assert_eq!(status, StatusCode::OK);
    let csrf = common::extract_csrf_token(&html).expect("CSRF token should be present");

    let zh_cookie = format!("crbs_token={}; crbs_lang=zh", tokens["owner-bob"]);
    let (status, location, _body) = post_ui_form_with_cookie(
        &app,
        &zh_cookie,
        "/ui/products/mypriv/acl",
        &form_body(&[
            ("csrf_token", csrf.as_str()),
            ("username", "ghost"),
            ("role", "viewer"),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("error redirect carries Location");
    assert!(
        location.starts_with("/ui/products/mypriv?error="),
        "{location}"
    );
    assert!(
        location.contains(urlencoding::encode("用户 ghost 不存在").as_ref()),
        "{location}"
    );

    let (status, html) = get_ui_page_with_cookie(&app, &zh_cookie, &location).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("用户 ghost 不存在。"),
        "zh flash not rendered: {html}"
    );
}

/// transfer POST 成功（官方产品→用户，事务内自动转 private）→ 303 带
/// status=ownership_transferred；Ownership 区块显示新 owner username 而非 user#id。
#[tokio::test]
async fn transfer_post_redirects_and_detail_shows_owner_username() {
    let (state, app, _tmp, tokens) =
        setup_app(&[("admin-op", "admin"), ("newowner", "builder")]).await;
    seed_product(&state, "mydist", None).await; // 官方 public，revision 1

    let (status, html) = get_product_page(&app, &tokens["admin-op"], "mydist").await;
    assert_eq!(status, StatusCode::OK);
    let csrf = common::extract_csrf_token(&html).expect("CSRF token should be present");

    let (status, location, _body) = post_ui_form(
        &app,
        &tokens["admin-op"],
        "/ui/products/mydist/transfer",
        &form_body(&[
            ("csrf_token", csrf.as_str()),
            ("new_owner_username", "newowner"),
            ("expected_revision", "1"),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location.as_deref(),
        Some("/ui/products/mydist?status=ownership_transferred"),
        "success should redirect with ownership_transferred status"
    );

    let (status, html) = get_product_page(&app, &tokens["admin-op"], "mydist").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(">newowner<"), "{html}");
    assert!(
        !html.contains("user#"),
        "owner must render as username, not user#id: {html}"
    );
}

/// ACL grant / revoke → 各自 303 status flash；grant 后 ACL 表格出现该用户行，revoke 后回空态。
#[tokio::test]
async fn acl_grant_and_revoke_redirect_with_status() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-op", "admin"), ("carol", "viewer")]).await;
    seed_product(&state, "mydist", None).await;

    let (status, html) = get_product_page(&app, &tokens["admin-op"], "mydist").await;
    assert_eq!(status, StatusCode::OK);
    let csrf = common::extract_csrf_token(&html).expect("CSRF token should be present");

    let (status, location, _body) = post_ui_form(
        &app,
        &tokens["admin-op"],
        "/ui/products/mydist/acl",
        &form_body(&[
            ("csrf_token", csrf.as_str()),
            ("username", "carol"),
            ("role", "viewer"),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location.as_deref(),
        Some("/ui/products/mydist?status=acl_granted"),
        "grant should redirect with acl_granted status"
    );

    let (status, html) = get_product_page(&app, &tokens["admin-op"], "mydist").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(r#"title="carol">carol</td>"#),
        "granted ACL row missing: {html}"
    );
    // ACL 表必须有 table-wrap 横滚 + acl-table 定宽保护（col-granted 定宽，
    // 表级 min-width 见 style.css），四列表头 User/Role/Granted/Action 结构不变。
    let wrap_pos = html
        .find(r#"<div class="table-wrap"><table class="fixed acl-table">"#)
        .unwrap_or_else(|| {
            panic!("ACL table should be wrapped in .table-wrap with fixed acl-table: {html}")
        });
    let granted_col_pos = html
        .find(r#"<col class="col-granted">"#)
        .unwrap_or_else(|| {
            panic!("ACL Granted column should use fixed-width col-granted class: {html}")
        });
    let acl_head = r#"<thead><tr><th>User</th><th>Role</th><th class="num">Granted</th><th>Action</th></tr></thead>"#;
    let acl_head_pos = html
        .find(acl_head)
        .unwrap_or_else(|| panic!("ACL table four-column header missing: {html}"));
    assert!(
        wrap_pos < granted_col_pos && granted_col_pos < acl_head_pos,
        "ACL fixed-width Granted col and four-column header should sit inside the table-wrap: {html}"
    );

    let (status, location, _body) = post_ui_form(
        &app,
        &tokens["admin-op"],
        "/ui/products/mydist/acl/carol/revoke",
        &form_body(&[("csrf_token", csrf.as_str())]),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location.as_deref(),
        Some("/ui/products/mydist?status=acl_revoked"),
        "revoke should redirect with acl_revoked status"
    );

    let (status, html) = get_product_page(&app, &tokens["admin-op"], "mydist").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("No ACL entries configured."),
        "revoke should empty the ACL table: {html}"
    );
}

/// private + 空 owner + 合法 TOML → 200 重渲染表单（服务端报错非 400），保留输入；产品不入库。
#[tokio::test]
async fn new_product_post_private_without_owner_rerenders_form_with_error() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-op", "admin")]).await;

    let (status, html) = get_ui_page(&app, &tokens["admin-op"], "/ui/products/new").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("Private products require an owner."),
        "H6 hint text missing from admin form: {html}"
    );
    assert!(
        html.contains("setCustomValidity"),
        "H6 guard script missing from admin form: {html}"
    );
    let csrf = common::extract_csrf_token(&html).expect("CSRF token should be present");

    let (status, location, body) = post_ui_form(
        &app,
        &tokens["admin-op"],
        "/ui/products/new",
        &form_body(&[
            ("csrf_token", csrf.as_str()),
            ("name", "h6-prod"),
            ("display_name", ""),
            ("parent_name", ""),
            ("owner", ""),
            ("visibility", "private"),
            ("config_toml", SAMPLE_TOML),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "re-rendered form must be 200");
    assert!(
        location.is_none(),
        "form re-render must not carry a Location"
    );
    assert!(
        body.contains("Private products require an owner."),
        "H6 server-side error banner missing: {body}"
    );
    assert!(body.contains(r#"value="h6-prod""#), "{body}");
    assert!(
        state
            .state_store
            .get_product_by_name("h6-prod")
            .await
            .unwrap()
            .is_none(),
        "product must not be created"
    );
}

/// history 页 "Changed by" 显示 username（admin publish 触发 revision 变更后），而非 user#id 回退。
#[tokio::test]
async fn product_history_page_shows_changer_username() {
    let (state, app, _tmp, tokens) =
        setup_app(&[("admin-op", "admin"), ("owner-bob", "builder")]).await;
    let bob = user_id(&state, "owner-bob").await;
    let admin = user_id(&state, "admin-op").await;
    seed_product(&state, "mypriv", Some(bob)).await; // private，revision 1

    let record = state
        .state_store
        .get_product_by_name("mypriv")
        .await
        .unwrap()
        .expect("seeded product");
    state
        .state_store
        .update_product_visibility(record.id, "public", Some(admin), None, None)
        .await
        .expect("publish product");

    let (status, html) =
        get_ui_page(&app, &tokens["admin-op"], "/ui/products/mypriv/history").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("admin-op"),
        "history 'Changed by' must show the username: {html}"
    );
    assert!(
        !html.contains("user#"),
        "history must not fall back to user#id: {html}"
    );
}

/// 配置 diff（base_packages 行改写 + 新增 releasever 行）→ del/ins 行按类渲染；
/// From/To radio 默认 from=次新（r1）、to=最新（r2），打开即对比最近一次变更。
#[tokio::test]
async fn product_history_diff_renders_known_change() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-op", "admin")]).await;
    let admin = user_id(&state, "admin-op").await;
    seed_product(&state, "diffprod", None).await; // r1：bash + rpm-build

    let updated = ProductConfig::from_str(
        "\
base_packages = [\"bash\", \"rpm-build\", \"vim-enhanced\"]
arches = [\"x86_64\"]
releasever = \"9\"

[[repos]]
name = \"base\"
baseurl = \"http://example.com/base/$basearch\"
gpgcheck = false
",
    )
    .expect("updated product toml parses");
    let record = state
        .state_store
        .get_product_by_name("diffprod")
        .await
        .unwrap()
        .expect("seeded product");
    state
        .state_store
        .update_product_config(record.id, &updated, Some(admin), None, None)
        .await
        .expect("bump to r2");

    let (status, html) =
        get_ui_page(&app, &tokens["admin-op"], "/ui/products/diffprod/history").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(r#"name="from" value="1" checked"#),
        "from radio r1 must be default-checked: {html}"
    );
    assert!(
        html.contains(r#"name="to" value="2" checked"#),
        "to radio r2 must be default-checked: {html}"
    );
    assert!(html.contains("Compare revisions"), "{html}");

    let (status, html) = get_ui_page(
        &app,
        &tokens["admin-op"],
        "/ui/products/diffprod/history/diff?from=1&to=2",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(r#"class="diff-line diff-del""#),
        "removed row class missing: {html}"
    );
    assert!(
        html.contains(r#"class="diff-line diff-ins""#),
        "added row class missing: {html}"
    );
    assert!(
        html.contains(
            r#"<span class="diff-text">base_packages = [&quot;bash&quot;, &quot;rpm-build&quot;]</span>"#
        ),
        "old base_packages line must appear as removed content: {html}"
    );
    assert!(
        html.contains(
            r#"<span class="diff-text">base_packages = [&quot;bash&quot;, &quot;rpm-build&quot;, &quot;vim-enhanced&quot;]</span>"#
        ),
        "new base_packages line must appear as added content: {html}"
    );
    assert!(
        html.contains(r#"<span class="diff-text">releasever = &quot;9&quot;</span>"#),
        "releasever line must appear as added content: {html}"
    );
    // 行号列语义：del 行新侧留空、ins 行老侧留空。
    assert!(
        html.contains(r#"<span class="diff-ln"></span><span class="diff-sign">-</span>"#),
        "removed rows must leave the new-side line number empty: {html}"
    );
    assert!(
        html.contains(r#"diff-ins"><span class="diff-ln"></span><span class="diff-ln">"#),
        "added rows must leave the old-side line number empty: {html}"
    );
    assert!(html.contains("From"), "{html}");
    assert!(html.contains("r2 by admin-op"), "{html}");
}

/// diff 无变更态：from==to 与内容相同的相邻 revision（revision 抬升但归一
/// TOML 一致）均渲染 empty_state 空态、不渲染 diff 块；zh 文案 Accept-Language 协商。
#[tokio::test]
async fn product_history_diff_no_changes_state() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-op", "admin")]).await;
    seed_product(&state, "sameprod", None).await; // r1

    let record = state
        .state_store
        .get_product_by_name("sameprod")
        .await
        .unwrap()
        .expect("seeded product");
    state
        .state_store
        .update_product_config(record.id, &sample_config(), None, None, None)
        .await
        .expect("bump to r2 with identical config");

    for uri in [
        "/ui/products/sameprod/history/diff?from=2&to=2",
        "/ui/products/sameprod/history/diff?from=1&to=2",
    ] {
        let (status, html) = get_ui_page(&app, &tokens["admin-op"], uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert!(html.contains("empty-state"), "{uri}: {html}");
        assert!(
            html.contains("No configuration changes"),
            "{uri}: empty-state title missing: {html}"
        );
        assert!(
            !html.contains(r#"class="diff-block""#),
            "{uri}: must not render a diff block: {html}"
        );
    }

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/products/sameprod/history/diff?from=1&to=2")
                .header("Cookie", format!("crbs_token={}", tokens["admin-op"]))
                .header("Accept-Language", "zh")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes);
    assert!(html.contains("配置无变更"), "zh empty-state title: {html}");
}

/// diff 参数校验：revision 越界 / 非正 / 缺参 → 404（与产品缺失同口径）。
#[tokio::test]
async fn product_history_diff_invalid_revision_is_404() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-op", "admin")]).await;
    seed_product(&state, "oneprod", None).await; // 仅 r1

    for uri in [
        "/ui/products/oneprod/history/diff?from=1&to=99", // 越界
        "/ui/products/oneprod/history/diff?from=0&to=1",  // 非正
        "/ui/products/oneprod/history/diff",              // 缺参
    ] {
        let (status, _html) = get_ui_page(&app, &tokens["admin-op"], uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
    }
}

/// diff fail-soft：单侧快照 config_json 损坏（旧 schema / 非法 JSON）时不 500——
/// 损坏侧回显原文 + HistoryDiffRawFallback notice（仅损坏侧带 revision 号），完好侧照常归一。
#[tokio::test]
async fn product_history_diff_corrupt_snapshot_falls_back_to_raw() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-op", "admin")]).await;
    let admin = user_id(&state, "admin-op").await;
    seed_product(&state, "rustyprod", None).await; // r1

    let updated = ProductConfig::from_str(
        "\
base_packages = [\"bash\", \"rpm-build\"]
arches = [\"x86_64\"]
releasever = \"9\"

[[repos]]
name = \"base\"
baseurl = \"http://example.com/base/$basearch\"
gpgcheck = false
",
    )
    .expect("updated product toml parses");
    let record = state
        .state_store
        .get_product_by_name("rustyprod")
        .await
        .unwrap()
        .expect("seeded product");
    state
        .state_store
        .update_product_config(record.id, &updated, Some(admin), None, None)
        .await
        .expect("bump to r2");

    // 直接改库损坏 r1 快照为旧 schema 非法 JSON；双方言用 $N 占位符（PG prepared protocol 不接受 SQLite 的 ?）。
    sqlx::query("UPDATE product_config_history SET config_json = '{\"legacy_field\": true}' WHERE product_id = $1 AND revision = 1")
        .bind(record.id)
        .execute(state.state_store.pool())
        .await
        .expect("corrupt r1 snapshot");

    let (status, html) = get_ui_page(
        &app,
        &tokens["admin-op"],
        "/ui/products/rustyprod/history/diff?from=1&to=2",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "corrupt snapshot must not 500: {html}"
    );
    assert!(
        html.contains("revision 1 snapshot is corrupted or from an older schema"),
        "r1 raw-fallback notice missing: {html}"
    );
    assert!(
        !html.contains("revision 2 snapshot is corrupted"),
        "healthy r2 must not carry a notice: {html}"
    );
    assert!(
        html.contains(r#"<span class="diff-text">{&quot;legacy_field&quot;: true}</span>"#),
        "raw r1 config_json must be echoed in the diff: {html}"
    );
    assert!(
        html.contains(r#"<span class="diff-text">releasever = &quot;9&quot;</span>"#),
        "healthy r2 side must still render normalized TOML: {html}"
    );
}

/// 可见性门禁与 history 页一致：无 ACL viewer 对私有产品 history/diff 均 404 防探测；owner 可见。
#[tokio::test]
async fn product_history_diff_private_product_hidden_from_viewer() {
    let (state, app, _tmp, tokens) =
        setup_app(&[("owner-bob", "builder"), ("mallory", "viewer")]).await;
    let bob = user_id(&state, "owner-bob").await;
    seed_product(&state, "mypriv", Some(bob)).await; // private，r1
    let record = state
        .state_store
        .get_product_by_name("mypriv")
        .await
        .unwrap()
        .expect("seeded product");
    state
        .state_store
        .update_product_config(record.id, &sample_config(), None, None, None)
        .await
        .expect("bump to r2");

    for uri in [
        "/ui/products/mypriv/history",
        "/ui/products/mypriv/history/diff?from=1&to=2",
    ] {
        let (status, _html) = get_ui_page(&app, &tokens["mallory"], uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
    }

    let (status, html) = get_ui_page(
        &app,
        &tokens["owner-bob"],
        "/ui/products/mypriv/history/diff?from=1&to=2",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("empty-state"), "{html}");
}

/// 单 revision 无从比较：history 页不渲染 From/To radio 与对比按钮，表格照常展示。
#[tokio::test]
async fn product_history_single_revision_hides_compare_controls() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin-op", "admin")]).await;
    seed_product(&state, "solo", None).await; // 仅 r1

    let (status, html) = get_ui_page(&app, &tokens["admin-op"], "/ui/products/solo/history").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!html.contains(r#"name="from""#), "{html}");
    assert!(!html.contains(r#"name="to""#), "{html}");
    assert!(!html.contains("Compare revisions"), "{html}");
    assert!(html.contains(r#"<td class="num">1</td>"#), "{html}");
}

/// 详情页总览带：strip + 成功率 gauge，数字与种子任务对账（Tasks=6 / Running=1 /
/// Queued=1 / Packages=2 / r1 / 成功率 3/6=50%）；zh 文案 Accept-Language 协商。
#[tokio::test]
async fn product_detail_page_shows_overview_band_with_reconciled_counts() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin", "admin")]).await;
    seed_product(&state, "mydist", None).await; // public，revision 1

    for (pkg, phase) in [
        ("bash-5.2-1.x86_64", "succeeded"),
        ("bash-5.2-2.x86_64", "succeeded"),
        ("coreutils-9.4-1.x86_64", "succeeded"),
        ("bash-5.2-3.x86_64", "failed"),
        ("bash-5.3-1.x86_64", "building"),
        ("coreutils-9.5-1.x86_64", "pending"),
    ] {
        state
            .state_store
            .insert_task(crbs_core::TaskInsert {
                product: "mydist",
                pkg_name: pkg,
                user: "admin",
                phase,
                ..Default::default()
            })
            .await
            .unwrap();
    }

    let (status, html) = get_product_page(&app, &tokens["admin"], "mydist").await;
    assert_eq!(status, StatusCode::OK);
    // 带结构：strip + gauge 同行（复用 /ui/me 的布局类）。
    assert!(html.contains("me-overview"), "band container: {html}");
    assert!(html.contains("sys-strip"), "{html}");
    assert!(html.contains("product-gauge-pct"), "{html}");
    for expected in [
        r#"<span class="label">Tasks</span><span class="value">6</span>"#,
        r#"<span class="label">Running</span><span class="value">1</span>"#,
        r#"<span class="label">Queued</span><span class="value">1</span>"#,
        r#"<span class="label">Packages</span><span class="value">2</span>"#,
        r#"<span class="label">Revision</span><span class="value">r1</span>"#,
        r#"<div class="big" id="product-gauge-pct">50%</div>"#,
    ] {
        assert!(html.contains(expected), "missing {expected}: {html}");
    }
    // 新鲜度 + 窗口口径标注。
    assert!(!html.contains("computed on page load"), "{html}");
    assert!(html.contains("window: last 200 tasks"), "{html}");
    assert!(html.contains("Last build"), "{html}");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/products/mydist")
                .header("Cookie", format!("crbs_token={}", tokens["admin"]))
                .header("Accept-Language", "zh-CN,zh;q=0.9")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let zh = String::from_utf8_lossy(&bytes).into_owned();
    for expected in [
        "任务总数",
        "运行中",
        "排队中",
        "最近构建",
        "包数",
        "修订版本",
        "窗口：最近 200 个任务",
    ] {
        assert!(zh.contains(expected), "zh missing {expected}: {zh}");
    }
}

/// 产品总览带对零任务产品渲染空带（0/—）而不报错。
#[tokio::test]
async fn product_detail_page_band_handles_empty_product() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin", "admin")]).await;
    seed_product(&state, "empty-prod", None).await;

    let (status, html) = get_product_page(&app, &tokens["admin"], "empty-prod").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("me-overview"), "{html}");
    for expected in [
        r#"<span class="label">Tasks</span><span class="value">0</span>"#,
        r#"<span class="label">Packages</span><span class="value">0</span>"#,
        r#"<div class="big" id="product-gauge-pct">—</div>"#,
    ] {
        assert!(html.contains(expected), "missing {expected}: {html}");
    }
}

/// 窗口内有样本且全失败 → gauge "0%"（danger 空弧），不得回落无样本 "—" 占位（0% 修复回归钉）。
#[tokio::test]
async fn product_detail_page_band_all_failed_shows_zero_percent() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin", "admin")]).await;
    seed_product(&state, "failing-prod", None).await;

    for pkg in ["bash-5.2-1.x86_64", "bash-5.2-2.x86_64"] {
        state
            .state_store
            .insert_task(crbs_core::TaskInsert {
                product: "failing-prod",
                pkg_name: pkg,
                user: "admin",
                phase: "failed",
                ..Default::default()
            })
            .await
            .unwrap();
    }

    let (status, html) = get_product_page(&app, &tokens["admin"], "failing-prod").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(r#"<div class="big" id="product-gauge-pct">0%</div>"#),
        "all-failed window must render 0%% gauge, not the no-sample dash: {html}"
    );
    // 0% 弧长为 0（offset = 满周长），配色落 danger 档。
    assert!(html.contains(r#"stroke="var(--danger)""#), "{html}");
    assert!(html.contains(r#"stroke-dashoffset="301.59""#), "{html}");
}

// ==== 统计图：最近构建时长 ====

/// 详情页渲染时长卡（scope=product：只算该产品构建，他产品样本不进窗口）；无趋势卡；zh 标题双语。
#[tokio::test]
async fn product_detail_renders_duration_chart_without_trend() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin", "admin")]).await;
    seed_product(&state, "mydist", None).await;
    seed_product(&state, "other", None).await;

    for (product, phase, mins_ago) in [
        ("mydist", "succeeded", 100),
        ("mydist", "succeeded", 80),
        ("mydist", "succeeded", 60),
        ("mydist", "failed", 40),
        ("other", "failed", 20),
    ] {
        seed_task_with_times(
            &state,
            product,
            "pkg-1.0-1",
            phase,
            mins_ago,
            Some(mins_ago - 5),
        )
        .await;
    }
    let build_id = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "mydist",
            pkg_name: "httpd-2.4.62-1.el9",
            phase: "succeeded",
            arch: Some("x86_64"),
            user: "admin",
            task_id: Some(
                crbs_server::test_support::seed_task(
                    &state.state_store,
                    "mydist",
                    "httpd-2.4.62-1.el9",
                )
                .await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    let ago = |m: i64| {
        (chrono::Utc::now() - chrono::TimeDelta::minutes(m))
            .format(crbs_core::util::DB_TIME_FMT)
            .to_string()
    };
    sqlx::query("UPDATE builds SET completed_at = $1, duration = $2 WHERE id = $3")
        .bind(ago(10))
        .bind(600_i64)
        .bind(build_id)
        .execute(state.state_store.pool())
        .await
        .unwrap();
    let other_build = state
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "other",
            pkg_name: "alien-pkg-1.0-1",
            phase: "succeeded",
            arch: Some("x86_64"),
            user: "admin",
            task_id: Some(
                crbs_server::test_support::seed_task(
                    &state.state_store,
                    "other",
                    "alien-pkg-1.0-1",
                )
                .await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET completed_at = $1, duration = $2 WHERE id = $3")
        .bind(ago(5))
        .bind(9999_i64)
        .bind(other_build)
        .execute(state.state_store.pool())
        .await
        .unwrap();

    let (status, html) = get_product_page(&app, &tokens["admin"], "mydist").await;
    assert_eq!(status, StatusCode::OK);
    // 时长卡独占整行（裸 viz-panel）+ 卡标题。
    assert!(html.contains("Recent build durations"), "{html}");
    assert!(!html.contains("cols-2"), "{html}");
    assert!(!html.contains("Success rate trend"), "{html}");
    assert!(!html.contains("trend-chart"), "{html}");
    assert!(
        html.contains(r#"aria-label="Durations of the last 1 succeeded builds, longest 10m 0s""#),
        "{html}"
    );
    assert!(html.contains("httpd-2.4.62-1.el9 · x86_64"), "{html}");
    assert!(!html.contains("alien-pkg-1.0-1"), "{html}");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/products/mydist")
                .header("Cookie", format!("crbs_token={}", tokens["admin"]))
                .header("Accept-Language", "zh-CN,zh;q=0.9")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let zh = String::from_utf8_lossy(&bytes).into_owned();
    assert!(zh.contains("最近构建时长"), "{zh}");
    assert!(!zh.contains("成功率趋势"), "{zh}");
}

// ==== 产品配置读路径零文件系统副作用——锁 handler → config load 整链在真实路由上
// 的行为（core 层单测见 config/tests.rs::merge_configs_survives_unwritable_runtime_dirs）====

/// 目录置 0500，drop 时恢复 0755（TempDir 清理与同二进制后续测试需要写权限）。
struct ReadonlyGuard {
    path: std::path::PathBuf,
}

impl ReadonlyGuard {
    fn new(path: &std::path::Path) -> Self {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500)).expect("chmod 0500");
        Self {
            path: path.to_path_buf(),
        }
    }
}

impl Drop for ReadonlyGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o755));
    }
}

/// ccache 父目录只读（0500）时，详情/编辑页 200 且不创建 ccache 子目录。
#[tokio::test]
async fn product_pages_render_200_when_ccache_parent_readonly() {
    // root 不受 DAC 检查约束，造不出 EACCES，跳过（config/tests.rs 先例）。
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let (state, app, _tmp, tokens) = setup_app(&[("admin", "admin")]).await;
    seed_product(&state, "ro-ccache-prod", None).await;

    // ccache 目录派生：{crbs_root}/ccache/{product}（config/merge.rs），crbs_root 见共享 TEST_CONFIG_DIR 的 crbs.toml。
    let ccache_parent = TEST_CONFIG_DIR.path().join("crbs_root").join("ccache");
    std::fs::create_dir_all(&ccache_parent).expect("mkdir ccache parent");
    let product_ccache = ccache_parent.join("ro-ccache-prod");
    assert!(
        !product_ccache.exists(),
        "baseline: product ccache dir must not exist"
    );

    let token = &tokens["admin"];
    let _guard = ReadonlyGuard::new(&ccache_parent);

    let (detail_status, _body) = get_product_page(&app, token, "ro-ccache-prod").await;
    let (edit_status, _edit_body) =
        get_ui_page(&app, token, "/ui/products/ro-ccache-prod/edit").await;

    assert_eq!(detail_status, StatusCode::OK, "detail page must not 500");
    assert_eq!(edit_status, StatusCode::OK, "edit page must not 500");
    assert!(
        !product_ccache.exists(),
        "read path must not create the product ccache dir"
    );
}

/// 新建表单 visibility 非法值 → 重渲染（200 非 PRG）zh 错误 banner
///（与产品页 FlashInvalidVisibility 措辞不同，各自保真）。
#[tokio::test]
async fn new_product_invalid_visibility_banner_is_localized_for_zh() {
    let (_state, app, _tmp, tokens) = setup_app(&[("ed-admin", "admin")]).await;

    let (status, html) = get_ui_page(&app, &tokens["ed-admin"], "/ui/products/new").await;
    assert_eq!(status, StatusCode::OK);
    let csrf = common::extract_csrf_token(&html).expect("CSRF token should be present");

    let zh_cookie = format!("crbs_token={}; crbs_lang=zh", tokens["ed-admin"]);
    let (status, _location, body) = post_ui_form_with_cookie(
        &app,
        &zh_cookie,
        "/ui/products/new",
        &form_body(&[
            ("csrf_token", csrf.as_str()),
            ("name", "vis-editor-x"),
            ("display_name", ""),
            ("parent_name", ""),
            ("owner", ""),
            ("visibility", "bogus"),
            ("config_toml", SAMPLE_TOML),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("无效的可见性值 bogus；应为 public 或 private。"),
        "zh banner not rendered: {body}"
    );
}

/// 新建撞名 → create_product AlreadyExists（core 变体）映射为中文 banner（1 参模板）。
#[tokio::test]
async fn new_product_name_taken_banner_is_localized_for_zh() {
    let (state, app, _tmp, tokens) = setup_app(&[("ed-admin", "admin")]).await;
    seed_product(&state, "dup-taken", None).await;

    let (status, html) = get_ui_page(&app, &tokens["ed-admin"], "/ui/products/new").await;
    assert_eq!(status, StatusCode::OK);
    let csrf = common::extract_csrf_token(&html).expect("CSRF token should be present");

    let zh_cookie = format!("crbs_token={}; crbs_lang=zh", tokens["ed-admin"]);
    let (status, _location, body) = post_ui_form_with_cookie(
        &app,
        &zh_cookie,
        "/ui/products/new",
        &form_body(&[
            ("csrf_token", csrf.as_str()),
            ("name", "dup-taken"),
            ("display_name", ""),
            ("parent_name", ""),
            ("owner", ""),
            ("visibility", "public"),
            ("config_toml", SAMPLE_TOML),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("产品名 dup-taken 已被占用（命名空间全局共享）。"),
        "zh banner not rendered: {body}"
    );
}

// ===== 资源画像（源码包维度）=====

/// 学习一条 succeeded 样本（source 是画像键，不是 NVR）。
async fn learn_sample(
    state: &AppState,
    source: &str,
    arch: &str,
    peak: i64,
    cpu: Option<f64>,
    ncpu: Option<i64>,
) {
    use crbs_core::{ResourceSampleOutcome, SampleBackend, DEFAULT_CENSOR_HEADROOM};
    state
        .state_store
        .apply_learning_sample(
            "mydist",
            source,
            arch,
            &ResourceSampleOutcome::Succeeded {
                backend: SampleBackend::Cgroup,
                peak_rss_kb: peak,
                peak_tmpfs_kb: None,
                cpu_p90_cores: cpu,
                sample_ncpu: ncpu,
            },
            Some(0),
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
}

/// 通用 GET（携带 token cookie），返回 (status, body, content-type)。
async fn get_ui(
    app: &axum::Router,
    token: &str,
    uri: &str,
) -> (StatusCode, String, Option<String>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("Cookie", format!("crbs_token={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
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
        String::from_utf8_lossy(&bytes).into_owned(),
        content_type,
    )
}

/// POST 源码包声明下限表单，返回 (status, Location)。
async fn post_floors(
    app: &axum::Router,
    token: &str,
    product: &str,
    source: &str,
    body: &str,
) -> (StatusCode, Option<String>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/products/{product}/packages/{source}/floors"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", format!("crbs_token={token}"))
                .body(Body::from(body.to_string()))
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

/// 产品页画像包列表：源码包级分组（同包多架构折叠为一行）、有效内存
/// 降序、声明/删失徽章、50/页分页（51 包 → "1-50 of 51" + `offset=50`）。
#[tokio::test]
async fn product_page_groups_profiles_by_source_package() {
    use crbs_core::{ResourceSampleOutcome, SampleBackend, DEFAULT_CENSOR_HEADROOM};
    let (state, app, _tmp, tokens) = setup_app(&[("admin", "admin")]).await;
    seed_product(&state, "mydist", None).await;

    state
        .state_store
        .set_declared_requirements("mydist", "hot-pkg", "x86_64", Some(8388608), Some(4), None)
        .await
        .unwrap();
    learn_sample(&state, "hot-pkg", "x86_64", 2_097_152, Some(2.5), Some(8)).await;
    // 同源码包第二架构：必须折叠进同一包行。
    learn_sample(&state, "hot-pkg", "aarch64", 1_048_576, None, None).await;
    // 删失行：node-OOM max = 峰值 × 1.25（有效内存排序第一）。
    state
        .state_store
        .apply_learning_sample(
            "mydist",
            "oom-pkg",
            "x86_64",
            &ResourceSampleOutcome::NodeOom {
                backend: SampleBackend::Cgroup,
                peak_rss_kb: 10_000_000,
                peak_tmpfs_kb: None,
                cpu_p90_cores: None,
                sample_ncpu: None,
            },
            Some(0),
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    // 49 个填充包（共 51 个源码包，触发 50/页分页）。
    for i in 0..49 {
        learn_sample(
            &state,
            &format!("pkg{i}"),
            "x86_64",
            100_000 + i * 1_000,
            None,
            None,
        )
        .await;
    }

    let (status, html) = get_product_page(&app, &tokens["admin"], "mydist").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("Resource requirements &amp; profiles"),
        "profile section missing: {html}"
    );
    assert!(
        html.contains("/ui/products/mydist/packages/hot-pkg"),
        "package detail link missing: {html}"
    );
    // 同包两架构只出一行：aarch64 徽章与 x86_64 徽章同处 hot-pkg 行。
    let hot_at = html.find("packages/hot-pkg").expect("hot-pkg link");
    let hot_row_end = html[hot_at..].find("</tr>").map(|i| hot_at + i).unwrap();
    let hot_row = &html[hot_at..hot_row_end];
    assert!(hot_row.contains("x86_64"), "arch badge x86_64: {hot_row}");
    assert!(hot_row.contains("aarch64"), "arch badge aarch64: {hot_row}");
    // 删失包有效内存（12.5M KB ≈ 11.9G）排在 hot-pkg 之前。
    let pos_oom = html.find("oom-pkg").expect("oom-pkg row");
    let pos_hot = html.find("packages/hot-pkg").expect("hot-pkg row");
    assert!(pos_oom < pos_hot, "censored heavy row must sort first");
    assert!(html.contains("censored"), "censored badge missing: {html}");
    assert!(html.contains("11.9G"), "effective mem for oom-pkg: {html}");
    assert!(
        html.contains("x86_64: 8.0G / 4 / —"),
        "declared composite: {html}"
    );
    // 分页：51 包 → 第 1-50 条 + Next 链接。
    assert!(html.contains("1-50 of 51"), "pagination info: {html}");
    assert!(html.contains("offset=50"), "next page link missing: {html}");

    // 第二页：只剩最低有效内存的 pkg0。
    let (status, html, _) = get_ui(&app, &tokens["admin"], "/ui/products/mydist?offset=50").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("51-51 of 51"), "page2 range: {html}");
    assert!(
        html.contains("pkg0"),
        "page2 must show the last row: {html}"
    );
    assert!(
        !html.contains("packages/hot-pkg"),
        "page2 must not repeat: {html}"
    );
}

/// 源码包详情页：按架构画像明细 + 最近构建历史；admin 可见声明下限编辑表单。
#[tokio::test]
async fn package_profile_page_shows_arch_rows_and_admin_editor() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin", "admin"), ("viewer", "viewer")]).await;
    seed_product(&state, "mydist", None).await;
    state
        .state_store
        .set_declared_requirements("mydist", "hot-pkg", "x86_64", Some(8388608), Some(4), None)
        .await
        .unwrap();
    learn_sample(&state, "hot-pkg", "x86_64", 2_097_152, Some(2.5), Some(8)).await;

    let (status, html, _) = get_ui(
        &app,
        &tokens["admin"],
        "/ui/products/mydist/packages/hot-pkg",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Per-arch profiles"), "{html}");
    assert!(html.contains("8.0G / 4 / —"), "declared: {html}");
    assert!(html.contains("2.0G / 2.0G"), "learned ema/max: {html}");
    assert!(html.contains("2.5 @8C"), "cpu p90 @nC: {html}");
    assert!(
        html.contains("/ui/products/mydist/packages/hot-pkg/floors"),
        "admin floors form missing: {html}"
    );
    assert!(
        html.contains("No builds found"),
        "history empty state: {html}"
    );

    // viewer 只读：表格在、编辑表单不在。
    let (status, html, _) = get_ui(
        &app,
        &tokens["viewer"],
        "/ui/products/mydist/packages/hot-pkg",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("2.0G / 2.0G"), "{html}");
    assert!(
        !html.contains("/ui/products/mydist/packages/hot-pkg/floors"),
        "viewer must not see floors form: {html}"
    );

    // 不存在的源码包 → 404。
    let (status, _, _) = get_ui(&app, &tokens["admin"], "/ui/products/mydist/packages/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// hub admin 声明下限编辑：set/unset 落库并写审计；非 admin 403。
#[tokio::test]
async fn package_floors_post_requires_admin_and_audits() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin", "admin"), ("viewer", "viewer")]).await;
    seed_product(&state, "mydist", None).await;
    learn_sample(&state, "hot-pkg", "x86_64", 2_097_152, None, None).await;

    let (_, html, _) = get_ui(
        &app,
        &tokens["admin"],
        "/ui/products/mydist/packages/hot-pkg",
    )
    .await;
    let csrf = common::extract_csrf_token(&html).expect("CSRF token should be present");
    let body =
        format!("csrf_token={csrf}&arch=x86_64&min_mem=6G&min_ncpu=6&min_disk=10G&action=set");
    let (status, location) = post_floors(&app, &tokens["admin"], "mydist", "hot-pkg", &body).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location.as_deref(),
        Some("/ui/products/mydist/packages/hot-pkg?status=profile_floors_updated")
    );
    let profile = state
        .state_store
        .get_profile("mydist", "hot-pkg", "x86_64")
        .await
        .unwrap()
        .expect("profile row");
    assert_eq!(profile.declared_min_mem_kb, Some(6 * 1024 * 1024));
    assert_eq!(profile.declared_min_ncpu, Some(6));
    assert_eq!(profile.declared_min_disk_kb, Some(10 * 1024 * 1024));

    let logs = state
        .state_store
        .list_audit_logs(AuditLogFilter {
            action: Some("set_resource_profile"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(logs.len(), 1, "set audit row: {logs:?}");
    assert_eq!(logs[0].target.as_deref(), Some("mydist/hot-pkg/x86_64"));

    // 非 admin：403 且不落库。
    let (_, viewer_html, _) = get_ui(
        &app,
        &tokens["viewer"],
        "/ui/products/mydist/packages/hot-pkg",
    )
    .await;
    let viewer_csrf =
        common::extract_csrf_token(&viewer_html).expect("viewer CSRF token should be present");
    let viewer_body = format!(
        "csrf_token={viewer_csrf}&arch=x86_64&min_mem=1G&min_ncpu=1&min_disk=1G&action=set"
    );
    let (status, _) = post_floors(&app, &tokens["viewer"], "mydist", "hot-pkg", &viewer_body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let profile = state
        .state_store
        .get_profile("mydist", "hot-pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(profile.declared_min_mem_kb, Some(6 * 1024 * 1024));

    // unset 清空声明并写审计。
    let body = format!("csrf_token={csrf}&arch=x86_64&min_mem=&min_ncpu=&min_disk=&action=unset");
    let (status, _) = post_floors(&app, &tokens["admin"], "mydist", "hot-pkg", &body).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let profile = state
        .state_store
        .get_profile("mydist", "hot-pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(profile.declared_min_mem_kb, None);
    assert_eq!(profile.declared_min_ncpu, None);
    assert_eq!(profile.declared_min_disk_kb, None);
    let logs = state
        .state_store
        .list_audit_logs(AuditLogFilter {
            action: Some("unset_resource_profile"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(logs.len(), 1, "unset audit row: {logs:?}");
}

/// 声明下限可为尚无画像行的架构（含 `any` 兜底键）仅创建声明行；
/// 非法架构名被拒且不落库。
#[tokio::test]
async fn package_floors_post_creates_declared_only_arch() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin", "admin")]).await;
    seed_product(&state, "mydist", None).await;
    learn_sample(&state, "hot-pkg", "x86_64", 2_097_152, None, None).await;

    let (_, html, _) = get_ui(
        &app,
        &tokens["admin"],
        "/ui/products/mydist/packages/hot-pkg",
    )
    .await;
    let csrf = common::extract_csrf_token(&html).expect("CSRF token should be present");
    assert!(
        html.contains("name=\"arch\"") && html.contains("Add floors for another arch"),
        "new-arch form missing: {html}"
    );

    let body = format!("csrf_token={csrf}&arch=any&min_mem=8G&min_ncpu=8&min_disk=20G&action=set");
    let (status, location) = post_floors(&app, &tokens["admin"], "mydist", "hot-pkg", &body).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location.as_deref(),
        Some("/ui/products/mydist/packages/hot-pkg?status=profile_floors_updated")
    );
    let profile = state
        .state_store
        .get_profile("mydist", "hot-pkg", "any")
        .await
        .unwrap()
        .expect("declared-only any row");
    assert_eq!(profile.declared_min_mem_kb, Some(8 * 1024 * 1024));
    assert_eq!(profile.declared_min_ncpu, Some(8));
    assert_eq!(profile.declared_min_disk_kb, Some(20 * 1024 * 1024));
    assert_eq!(profile.learned_samples, 0);

    // `any` 行参与声明回退查找。
    let declared = state
        .state_store
        .find_declared_requirements("mydist", "hot-pkg", "aarch64")
        .await
        .unwrap()
        .expect("any fallback declared requirements");
    assert_eq!(declared.min_mem_kb, Some(8 * 1024 * 1024));

    let (_, html, _) = get_ui(
        &app,
        &tokens["admin"],
        "/ui/products/mydist/packages/hot-pkg",
    )
    .await;
    assert!(
        html.contains(">any<") && html.contains("8.0G"),
        "any row should render: {html}"
    );

    // 非法架构名拒绝。
    let body = format!("csrf_token={csrf}&arch=bad/arch&min_mem=1G&min_ncpu=&min_disk=&action=set");
    let (status, _) = post_floors(&app, &tokens["admin"], "mydist", "hot-pkg", &body).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(state
        .state_store
        .get_profile("mydist", "hot-pkg", "bad/arch")
        .await
        .unwrap()
        .is_none());
}

/// 画像 CSV 导出：每源码包每架构一行，原始 KB/核数与过滤参数生效。
#[tokio::test]
async fn product_profiles_csv_exports_filtered_rows() {
    let (state, app, _tmp, tokens) = setup_app(&[("admin", "admin")]).await;
    seed_product(&state, "mydist", None).await;
    state
        .state_store
        .set_declared_requirements("mydist", "hot-pkg", "x86_64", Some(8388608), Some(4), None)
        .await
        .unwrap();
    learn_sample(&state, "hot-pkg", "x86_64", 2_097_152, Some(2.5), Some(8)).await;
    learn_sample(&state, "hot-pkg", "aarch64", 1_048_576, None, None).await;
    learn_sample(&state, "other-pkg", "x86_64", 3_000_000, None, None).await;

    let (status, csv, content_type) = get_ui(
        &app,
        &tokens["admin"],
        "/ui/products/mydist/profiles.csv?profile_q=hot",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some("text/csv; charset=utf-8"));
    let mut lines = csv.lines();
    assert!(
        lines
            .next()
            .unwrap()
            .starts_with("product,source_name,arch,declared_min_mem_kb"),
        "{csv}"
    );
    let rows: Vec<&str> = lines.collect();
    assert_eq!(
        rows.len(),
        2,
        "one row per arch of the filtered package: {csv}"
    );
    assert!(rows
        .iter()
        .any(|r| r.starts_with("mydist,hot-pkg,x86_64,8388608,4,")));
    assert!(rows
        .iter()
        .any(|r| r.starts_with("mydist,hot-pkg,aarch64,,,")));
    assert!(!csv.contains("other-pkg"), "filter must apply: {csv}");
}
