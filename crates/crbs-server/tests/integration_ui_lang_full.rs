// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2/
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 国际化（全量迁移回归）：每个迁移页面（builds 列表/详情/日志/changelog、task 详情/changelog、
//! products 列表/详情/历史、product_editor、packages、workers、admin、GC、搜索、提交任务）
//! 在 `crbs_lang=zh` 下渲染关键中文文案（chrome + 内容），默认英文回归不变。

// 测试 crate：辅助函数不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::TimeDelta;
use tower::ServiceExt;

use crbs_core::config::{ProductConfig, ServerConfig};
use crbs_core::{BuildInsert, CreateProductInput, TaskInsert};
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;

mod common;

use common::TEST_CONFIG_DIR;

/// 根产品配置（root 必须声明至少一个 repo，chain-resolve 出口校验）。
const PRODUCT_TOML: &str = "\
product = \"mydist\"
base_packages = [\"bash\", \"rpm-build\"]

[[repos]]
name = \"base\"
baseurl = \"http://mirror.example.com/mydist/base/$basearch\"
gpgcheck = true
";

fn utc_past(minutes: i64) -> String {
    (chrono::Utc::now() - TimeDelta::minutes(minutes))
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string()
}

struct Fixture {
    app: axum::Router,
    /// AppState 句柄（种子里再建产品等 store 操作用）。
    state: Arc<AppState>,
    admin_cookie: String,
    task_id: i64,
    build_id: i64,
    user_id: i64,
    worker_id: i64,
    /// 根产品 mydist 的 id（父产品行渲染断言用）。
    product_id: i64,
    /// SQLite 库文件所在 tempdir：持有到测试结束，提前 drop = "unable to open
    /// database file"。
    _tmp: tempfile::TempDir,
}

async fn setup_fixture() -> Fixture {
    let _ = TEST_CONFIG_DIR.path();
    crbs_server::test_support::init_test_logging();
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    let state = Arc::new(AppState::for_test(
        state_store,
        ServerConfig::default(),
        tmp_dir.path().to_path_buf(),
    ));

    let admin_token = seed_user_token_for_test(&state.state_store, "admin-op", "admin")
        .await
        .expect("seed admin");
    let user = state
        .state_store
        .find_user_by_name("admin-op")
        .await
        .expect("find admin")
        .expect("admin exists");

    let product_id = state
        .state_store
        .create_product(CreateProductInput {
            name: "mydist",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &ProductConfig::from_str(PRODUCT_TOML).expect("product toml parses"),
            changed_by_user_id: None,
            reason: Some("seed"),
        })
        .await
        .expect("create product");

    let task_id = state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name: "hello-1.0-1.el9",
            user: "admin-op",
            phase: "succeeded",
            ..Default::default()
        })
        .await
        .expect("insert task");

    let build_id = state
        .state_store
        .insert_build(BuildInsert {
            product: "mydist",
            pkg_name: "hello-1.0-1.el9",
            phase: "succeeded",
            backend: "chroot",
            user: "admin-op",
            arch: Some("x86_64"),
            task_id: Some(
                crbs_server::test_support::seed_task(
                    &state.state_store,
                    "mydist",
                    "hello-1.0-1.el9",
                )
                .await,
            ),
            ..Default::default()
        })
        .await
        .expect("insert build");
    sqlx::query("UPDATE builds SET started_at = $1, completed_at = $2, task_id = $3 WHERE id = $4")
        .bind(utc_past(60))
        .bind(utc_past(30))
        .bind(task_id)
        .bind(build_id)
        .execute(state.state_store.pool())
        .await
        .expect("set build fields");

    let worker_id = state
        .state_store
        .upsert_worker("edge-x86-01", "x86_64", 4, "0.15.0-dev", "online", None)
        .await
        .expect("seed worker");

    Fixture {
        app: create_test_app_with_auth(state.clone()),
        state,
        admin_cookie: format!("crbs_token={admin_token}"),
        task_id,
        build_id,
        user_id: user.id,
        worker_id,
        product_id,
        _tmp: tmp_dir,
    }
}

/// GET 并断言状态；`zh=true` 附加 crbs_lang=zh cookie。
async fn get(fx: &Fixture, uri: &str, admin: bool, zh: bool, expect: StatusCode) -> String {
    let mut builder = Request::builder().uri(uri);
    let mut cookies = Vec::new();
    if admin {
        cookies.push(fx.admin_cookie.clone());
    }
    if zh {
        cookies.push("crbs_lang=zh".to_string());
    }
    if !cookies.is_empty() {
        builder = builder.header("Cookie", cookies.join("; "));
    }
    let response = fx
        .app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .expect("oneshot request");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8_lossy(&bytes).into_owned();
    assert_eq!(
        status,
        expect,
        "GET {uri}: expected {expect}, got {status}: {}",
        head_chars(&body, 800)
    );
    body
}

/// panic 消息用的头部截断：按字符边界取前 n 个字符（字节硬切会切进多字节
/// 汉字导致 panic-in-panic）。
fn head_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn assert_all(html: &str, expected: &[&str], ctx: &str) {
    for e in expected {
        assert!(
            html.contains(e),
            "{ctx}: missing {e:?}\nhead: {}",
            head_chars(html, 500)
        );
    }
}

/// builds 列表 / 详情 / 日志页双语。
#[tokio::test]
async fn builds_pages_render_zh_and_en() {
    let fx = setup_fixture().await;

    let zh = get(&fx, "/ui/builds", false, true, StatusCode::OK).await;
    assert_all(
        &zh,
        &[
            // h1 = 导航名 + 总数 chip（fixture 1 条任务构建）。
            "<h1>构建 <span class=\"count-chip\">1</span></h1>",
            "开始时间",
            // 列表列头正名"状态"（旧名"阶段"）。
            "<th>状态</th>",
        ],
        "builds-zh",
    );
    assert!(
        !zh.contains("<h1>Builds</h1>"),
        "builds-zh must not keep en h1"
    );

    let en = get(&fx, "/ui/builds", false, false, StatusCode::OK).await;
    assert_all(
        &en,
        &[
            "<h1>Builds <span class=\"count-chip\">1</span></h1>",
            "Started",
            "<th>Status</th>",
        ],
        "builds-en",
    );

    let zh = get(
        &fx,
        &format!("/ui/builds/{}", fx.build_id),
        false,
        true,
        StatusCode::OK,
    )
    .await;
    assert_all(
        &zh,
        &[
            "构建 #",
            "查看日志",
            "← 返回构建列表",
            "阶段",
            "后端",
            "产物",
            "暂无产物",
            "实时更新已启用",
        ],
        "build-detail-zh",
    );

    let zh = get(
        &fx,
        &format!("/ui/builds/{}/logs", fx.build_id),
        false,
        true,
        StatusCode::OK,
    )
    .await;
    assert_all(
        &zh,
        &[" 日志</h1>", "← 返回构建", "没有可用的日志。"],
        "build-logs-zh",
    );

    let en = get(
        &fx,
        &format!("/ui/builds/{}/logs", fx.build_id),
        false,
        false,
        StatusCode::OK,
    )
    .await;
    assert_all(
        &en,
        &[" logs</h1>", "← Back to build", "No logs available."],
        "build-logs-en",
    );
}

/// task 详情页双语（列表页由 integration_ui_lang 钉住）。
#[tokio::test]
async fn task_detail_renders_zh_and_en() {
    let fx = setup_fixture().await;

    let zh = get(
        &fx,
        &format!("/ui/tasks/{}", fx.task_id),
        false,
        true,
        StatusCode::OK,
    )
    .await;
    assert_all(
        &zh,
        &[
            "<h1>任务 #",
            "← 返回任务列表",
            "提交时间",
            "时长",
            "完成时间",
            "子构建",
            "产物",
        ],
        "task-detail-zh",
    );

    let en = get(
        &fx,
        &format!("/ui/tasks/{}", fx.task_id),
        false,
        false,
        StatusCode::OK,
    )
    .await;
    assert_all(
        &en,
        &[
            "<h1>Task #",
            "← Back to tasks",
            "Submitted",
            "Duration",
            "Completed",
            "Child builds",
        ],
        "task-detail-en",
    );
}

/// products 列表 / 详情 / 历史 + 编辑器双语。
#[tokio::test]
async fn products_pages_render_zh_and_en() {
    let fx = setup_fixture().await;

    let zh = get(&fx, "/ui/products", false, true, StatusCode::OK).await;
    assert_all(
        &zh,
        &[
            // h1 带总数 count-chip（fixture：1 个产品）。
            "<h1>产品 <span class=\"count-chip\">1</span></h1>",
            "父产品",
            "可见性",
            "所有者",
            "构建目标",
        ],
        "products-zh",
    );

    let en = get(&fx, "/ui/products", false, false, StatusCode::OK).await;
    assert_all(
        &en,
        &[
            "<h1>Products <span class=\"count-chip\">1</span></h1>",
            "Parent",
            "Visibility",
            "Owner",
            "Build target",
        ],
        "products-en",
    );

    // 父产品行占位符泄漏回归——带父产品的详情页（en/zh 两侧）必须
    // 渲染完整 "(id=N)" 句，且不得残留字面 "{1}"（缺席参数不被 interpolate
    // 替换、原样漏出）。
    fx.state
        .state_store
        .create_product(CreateProductInput {
            name: "mydist-app",
            display_name: None,
            owner_id: None,
            parent_id: Some(fx.product_id),
            visibility: "public",
            config: &ProductConfig::from_str(PRODUCT_TOML).expect("product toml parses"),
            changed_by_user_id: None,
            reason: Some("seed child"),
        })
        .await
        .expect("create child product");
    let pid = fx.product_id.to_string();

    let zh = get(&fx, "/ui/products/mydist-app", false, true, StatusCode::OK).await;
    assert_all(
        &zh,
        &[
            // zh 模板 "{0}（id={1}）"。
            &format!("mydist（id={pid}）"),
        ],
        "product-parent-zh",
    );
    assert!(
        !zh.contains("（id={"),
        "product-parent-zh: unresolved placeholder leaked: {}",
        head_chars(&zh, 800)
    );
    assert!(
        !zh.contains(&format!("mydist（id={pid}）mydist")),
        "product-parent-zh: parent name must not render twice"
    );
    // 紧邻负断言只拦一种形态；pname 整句必须恰渲染 1 次——
    // 非紧邻的重复（任意位置）同样被拒。（裸数 "mydist" 子串不可行：href 与
    // 子产品名 "mydist-app" 都含该子串，必误报。）
    assert_eq!(
        zh.matches(&format!("mydist（id={pid}）")).count(),
        1,
        "product-parent-zh: parent sentence must render exactly once: {}",
        head_chars(&zh, 800)
    );

    let en = get(&fx, "/ui/products/mydist-app", false, false, StatusCode::OK).await;
    assert_all(
        &en,
        &[
            // en 模板 "{0} (id={1})"。
            &format!("mydist (id={pid})"),
        ],
        "product-parent-en",
    );
    assert!(
        !en.contains("(id={"),
        "product-parent-en: unresolved placeholder leaked: {}",
        head_chars(&en, 800)
    );
    assert!(
        !en.contains(&format!("mydist (id={pid})mydist")),
        "product-parent-en: parent name must not render twice"
    );
    // 同 zh 侧——pname 整句恰渲染 1 次。
    assert_eq!(
        en.matches(&format!("mydist (id={pid})")).count(),
        1,
        "product-parent-en: parent sentence must render exactly once: {}",
        head_chars(&en, 800)
    );

    let zh = get(&fx, "/ui/products/mydist", false, true, StatusCode::OK).await;
    assert_all(
        &zh,
        &[
            "<h1>产品：mydist<span class=\"count-chip\">",
            "详细信息",
            "软件源",
            "RPM 宏",
            "钩子",
            "基础软件包",
        ],
        "product-detail-zh",
    );

    let zh = get(
        &fx,
        "/ui/products/mydist/history",
        false,
        true,
        StatusCode::OK,
    )
    .await;
    assert_all(
        &zh,
        &["<h1>产品历史：mydist</h1>", "变更时间", "变更人", "原因"],
        "product-history-zh",
    );

    // 编辑页（admin）：编辑表单标签。
    let zh = get(&fx, "/ui/products/mydist/edit", true, true, StatusCode::OK).await;
    assert_all(
        &zh,
        &[
            "<h1>编辑：mydist</h1>",
            "产品配置（TOML）",
            "变更原因（可选）",
            "检查",
            "保存",
        ],
        "product-edit-zh",
    );

    // 新建页（admin）。
    let zh = get(&fx, "/ui/products/new", true, true, StatusCode::OK).await;
    assert_all(
        &zh,
        &["<h1>新建产品</h1>", "显示名（可选）", "创建"],
        "product-new-zh",
    );

    let en = get(&fx, "/ui/products/new", true, false, StatusCode::OK).await;
    assert_all(
        &en,
        &["<h1>New Product</h1>", "Display name (optional)", "Create"],
        "product-new-en",
    );
}

/// packages 列表 / 详情双语。
#[tokio::test]
async fn packages_pages_render_zh_and_en() {
    let fx = setup_fixture().await;

    let zh = get(&fx, "/ui/packages", false, true, StatusCode::OK).await;
    assert_all(
        &zh,
        &[
            // h1 带总数 count-chip（fixture：1 个包名组）。
            "<h1>软件包 <span class=\"count-chip\">1</span></h1>",
            "名称",
            "最新状态",
            // 术语定则：Attempts 键名不动，文案正名为任务/提交语义。
            "提交数",
            "最近构建",
        ],
        "packages-zh",
    );

    let en = get(&fx, "/ui/packages", false, false, StatusCode::OK).await;
    assert_all(
        &en,
        &[
            "<h1>Packages <span class=\"count-chip\">1</span></h1>",
            "Name",
            "Latest phase",
            "Submissions",
            "Last build",
        ],
        "packages-en",
    );

    let zh = get(&fx, "/ui/packages/hello", false, true, StatusCode::OK).await;
    assert_all(
        &zh,
        &[
            "<h1>软件包：hello<span class=\"count-chip\">",
            "← 返回软件包列表",
            "版本历史",
        ],
        "package-detail-zh",
    );
}

/// workers 列表 / 详情双语（在线徽章、心跳列）。
#[tokio::test]
async fn workers_pages_render_zh_and_en() {
    let fx = setup_fixture().await;

    let zh = get(&fx, "/ui/workers", false, true, StatusCode::OK).await;
    assert_all(
        &zh,
        &[
            // h1 带总数 count-chip（fixture：1 台 worker）。
            "<h1>Worker <span class=\"count-chip\">1</span></h1>",
            "名称",
            "容量",
            "负载",
            "状态",
            "最近心跳",
            "版本",
            ">在线</span>",
        ],
        "workers-zh",
    );

    let en = get(&fx, "/ui/workers", false, false, StatusCode::OK).await;
    assert_all(
        &en,
        &[
            "<h1>Workers <span class=\"count-chip\">1</span></h1>",
            "Capacity",
            "Load",
            "Last heartbeat",
        ],
        "workers-en",
    );

    let detail_uri = format!("/ui/workers/{}", fx.worker_id);
    let zh = get(&fx, &detail_uri, false, true, StatusCode::OK).await;
    assert_all(
        &zh,
        &[
            "← 返回 Worker 列表",
            "进行中的构建",
            "该 Worker 暂无进行中的构建",
        ],
        "worker-detail-zh",
    );
    assert!(
        !zh.contains("持有密钥"),
        "credential metadata must stay admin-only on the public worker page"
    );

    let zh_admin = get(&fx, &detail_uri, true, true, StatusCode::OK).await;
    assert_all(&zh_admin, &["持有密钥"], "worker-detail-zh-admin");
}

/// admin 首页 / 用户列表 / 用户详情 / 审计页双语（admin 会话）。
#[tokio::test]
async fn admin_pages_render_zh_and_en() {
    let fx = setup_fixture().await;

    let zh = get(&fx, "/ui/admin", true, true, StatusCode::OK).await;
    assert_all(
        &zh,
        &[
            "<h1>管理</h1>",
            "用户",
            "审计日志",
            "垃圾回收",
            "轮换密钥、移除离线 Worker。",
        ],
        "admin-zh",
    );

    let zh = get(&fx, "/ui/admin/users", true, true, StatusCode::OK).await;
    assert_all(
        &zh,
        &[
            // h1 带总数 count-chip（fixture：仅 admin-op 一人）。
            "<h1>用户 <span class=\"count-chip\">1</span></h1>",
            "创建用户",
            "角色",
            "创建时间",
            ">启用</span>",
        ],
        "admin-users-zh",
    );

    let en = get(&fx, "/ui/admin/users", true, false, StatusCode::OK).await;
    assert_all(
        &en,
        &[
            "<h1>Users <span class=\"count-chip\">1</span></h1>",
            "Create user",
            ">active</span>",
        ],
        "admin-users-en",
    );

    let zh = get(
        &fx,
        &format!("/ui/admin/users/{}", fx.user_id),
        true,
        true,
        StatusCode::OK,
    )
    .await;
    assert_all(
        &zh,
        &["<h1>用户 #", "详细信息", "重置密码", "令牌", "产品 ACL"],
        "admin-user-detail-zh",
    );

    let zh = get(&fx, "/ui/admin/audit", true, true, StatusCode::OK).await;
    assert_all(
        &zh,
        &[
            // h1 带总数 count-chip（fixture：无审计行 → 0）。
            "<h1>审计日志 <span class=\"count-chip\">0</span></h1>",
            "时间",
            "目标",
            "详情",
            "暂无审计记录",
        ],
        "admin-audit-zh",
    );

    let en = get(&fx, "/ui/admin/audit", true, false, StatusCode::OK).await;
    assert_all(
        &en,
        &[
            "<h1>Audit Logs <span class=\"count-chip\">0</span></h1>",
            "Time",
            "Target",
            "Detail",
        ],
        "admin-audit-en",
    );
}

/// GC 管理页双语（operator+，admin 会话可达）。
#[tokio::test]
async fn gc_page_renders_zh_and_en() {
    let fx = setup_fixture().await;

    let zh = get(&fx, "/ui/admin/gc", true, true, StatusCode::OK).await;
    assert_all(
        &zh,
        &[
            // h1 带任务计数 count-chip（fixture：无 GC 历史 → 0）。
            "<h1>垃圾回收 <span class=\"count-chip\">0</span></h1>",
            "危险操作：",
            "试运行",
            "构建结果",
            "孤儿挂载",
            "应用保留策略",
            "执行 GC",
            "最近 GC 任务",
            "暂无 GC 任务",
            "GC 做什么？",
        ],
        "gc-zh",
    );

    let en = get(&fx, "/ui/admin/gc", true, false, StatusCode::OK).await;
    assert_all(
        &en,
        &[
            "<h1>Garbage collection <span class=\"count-chip\">0</span></h1>",
            "Destructive:",
            "Dry run",
            "Run GC",
            "Recent GC tasks",
            "No GC tasks yet",
        ],
        "gc-en",
    );
}

/// zh 未钉页面补断言——搜索结果页、admin 设置页、提交任务页、
/// build/task changelog 页。changelog 源文件不可达（build 无 result_dir，
/// 产物行只作页面上下文），解析必败 fail-soft，钉空态 zh 文案（空态也是
/// 有效钉：模板/键被删改或回退英文时在此失败）。
#[tokio::test]
async fn search_settings_task_new_changelog_render_zh() {
    let fx = setup_fixture().await;

    // 搜索结果页：前缀区（产品名前缀）+ zh 标题（全角冒号是 zh 模板形态）。
    let zh = get(&fx, "/ui/search?q=my", false, true, StatusCode::OK).await;
    assert_all(&zh, &["<h1>搜索：my</h1>"], "search-prefix-zh");

    // 搜索结果页：直达区（任务号直达，链接文案 zh）。
    let zh = get(
        &fx,
        &format!("/ui/search?q={}", fx.task_id),
        false,
        true,
        StatusCode::OK,
    )
    .await;
    assert_all(
        &zh,
        &[
            "<h2>直达结果</h2>",
            &format!(
                r#"<a href="/ui/tasks/{}">任务 #{}</a>"#,
                fx.task_id, fx.task_id
            ),
        ],
        "search-direct-zh",
    );
    // en 回归：直达区标题不回退 zh。
    let en = get(
        &fx,
        &format!("/ui/search?q={}", fx.task_id),
        false,
        false,
        StatusCode::OK,
    )
    .await;
    assert_all(
        &en,
        &[
            "<h2>Direct matches</h2>",
            &format!(
                r#"<a href="/ui/tasks/{}">Task #{}</a>"#,
                fx.task_id, fx.task_id
            ),
        ],
        "search-direct-en",
    );

    // admin 设置页（admin 会话）：页头 + 注册卡 + 开关当前态（默认已关闭）。
    let zh = get(&fx, "/ui/admin/settings", true, true, StatusCode::OK).await;
    assert_all(
        &zh,
        &[
            "<h1>设置</h1>",
            "注册",
            "已关闭",
            "开放注册",
            "允许自助创建账号，新账号默认为访客角色。",
            "保存",
        ],
        "settings-zh",
    );
    let en = get(&fx, "/ui/admin/settings", true, false, StatusCode::OK).await;
    assert_all(
        &en,
        &[
            "<h1>Settings</h1>",
            "Registration",
            "closed",
            "Open registration",
            "Save",
        ],
        "settings-en",
    );

    // 提交任务页（admin ≥ builder；fixture 有可提交产品 → 完整表单分支）。
    let zh = get(&fx, "/ui/tasks/new", true, true, StatusCode::OK).await;
    assert_all(
        &zh,
        &[
            "<h1>提交任务</h1>",
            "← 返回任务列表",
            "SRPM 文件（.src.rpm，可多选）",
            "将 .src.rpm 文件拖拽到此处",
            "架构（可选）",
            "优先级",
            "提交</button>",
        ],
        "task-new-zh",
    );

    // 给 fixture 构建挂一条 RPM 产物行（文件不存在 → 解析必败 fail-soft）。
    // task changelog 的胜出子构建解析要求至少一条在盘 rpm/srpm 行，否则
    // API 层直接 404（不泄漏存在性），页面无空态可钉。
    let mut tx = fx.state.state_store.pool().begin().await.unwrap();
    fx.state
        .state_store
        .insert_artifacts_tx(
            &mut tx,
            fx.build_id,
            &[crbs_core::NewArtifact {
                relative_path: "RPMS/hello-1.0-1.x86_64.rpm".to_string(),
                kind: crbs_core::ArtifactKind::Rpm,
                size_bytes: 1024,
                sha256: "a".repeat(64),
                unsigned_sha256: None,
                arch: Some("x86_64".to_string()),
                name: Some("hello".to_string()),
                version: Some("1.0".to_string()),
                release: Some("1".to_string()),
                epoch: None,
                metadata_json: None,
                signed: false,
            }],
            "2026-08-31 00:00:00",
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // build changelog 页：源文件不可达（无 result_dir）→ fail-soft 空态
    // （面包屑 + 空态标题/提示 zh）。
    let zh = get(
        &fx,
        &format!("/ui/builds/{}/changelog", fx.build_id),
        false,
        true,
        StatusCode::OK,
    )
    .await;
    assert_all(
        &zh,
        &[
            "<h1>RPM 变更日志</h1>",
            "变更日志不可用",
            "未能读取该产物的变更日志",
        ],
        "build-changelog-zh",
    );

    // task changelog 页：同 fail-soft 空态。
    let zh = get(
        &fx,
        &format!("/ui/tasks/{}/changelog", fx.task_id),
        false,
        true,
        StatusCode::OK,
    )
    .await;
    assert_all(
        &zh,
        &["<h1>RPM 变更日志</h1>", "变更日志不可用"],
        "task-changelog-zh",
    );
}

/// flash 双语：?status= 成功消息与未签名 ?error= 固定文案按页面语言渲染。
#[tokio::test]
async fn flash_messages_localize_per_page_language() {
    let fx = setup_fixture().await;

    let zh = get(
        &fx,
        &format!("/ui/builds/{}?status=cancelled", fx.build_id),
        false,
        true,
        StatusCode::OK,
    )
    .await;
    assert!(zh.contains("取消请求已接受。"), "flash-zh: {zh}");

    let en = get(
        &fx,
        &format!("/ui/builds/{}?status=cancelled", fx.build_id),
        false,
        false,
        StatusCode::OK,
    )
    .await;
    assert!(en.contains("Cancel request accepted."), "flash-en: {en}");

    // 未签名 ?error=：固定文案（不反射原文），zh 渲染中文兜底。
    let zh = get(
        &fx,
        &format!("/ui/tasks/{}?error=evil.example", fx.task_id),
        false,
        true,
        StatusCode::OK,
    )
    .await;
    assert!(zh.contains("操作失败。"), "flash-err-zh: {zh}");
    assert!(
        !zh.contains("evil.example"),
        "flash-err-zh must not reflect text"
    );
}
