// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 手动视觉预览生成器（UI 页面截图自审的数据源）。
//!
//! 与其它 integration_ui_* 测试同一套 harness（create_test_store +
//! AppState::for_test + seed_user_token_for_test + create_test_app_with_auth），
//! 但 seed 一份"富数据集"：六 phase 任务、双产品（公共根 + 私有子）、NVR
//! 分组与多次尝试、带产物的构建、双架构四台 worker（在线/心跳过期/离线）、
//! 审计行、GC 历史。每个页面 oneshot GET 后把响应体写入
//! `target/ui-preview/<name>.html`，供截图脚本按 file:// 截图（JS/SSE 驱动
//! 的动态内容不覆盖，看到的即 SSR 初值）。运行：
//!
//! ```sh
//! cargo test -p crbs-server --test ui_preview -- --ignored --nocapture
//! ```

// 整个文件是测试 crate：测试辅助函数（seed_* 等）不带 #[test] 属性，
// clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::TimeDelta;
use tower::ServiceExt;

use crbs_core::config::{ProductConfig, ServerConfig};
use crbs_core::types::{GcOrphanMountsSummary, GcResultsSummary, GcSummary};
use crbs_core::{BuildInsert, CreateProductInput, TaskInsert};
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::{AppState, GcTask, GcTaskStatus};

mod common;

use common::TEST_CONFIG_DIR;

/// 公共根产品：双 repo + rpm 宏（root 必须声明至少一个 repo）。
const MYDIST_TOML: &str = "\
product = \"mydist\"
base_packages = [\"bash\", \"rpm-build\", \"fedora-release\"]
arches = [\"x86_64\", \"aarch64\"]

[rpm_macros]
dist = \".mydist\"
vendor = \"ULE Project\"

[[repos]]
name = \"base\"
baseurl = \"http://mirror.example.com/mydist/base/$basearch\"
gpgcheck = true

[[repos]]
name = \"updates\"
baseurl = \"http://mirror.example.com/mydist/updates/$basearch\"
gpgcheck = true
";

/// `update_product_config` 造历史 revision 用的变体（每次多一个 base package）。
fn mydist_toml_rev(extra_pkg: &str) -> String {
    format!(
        "product = \"mydist\"\n\
         base_packages = [\"bash\", \"rpm-build\", \"fedora-release\", \"{extra_pkg}\"]\n\
         arches = [\"x86_64\", \"aarch64\"]\n\
         \n\
         [rpm_macros]\n\
         dist = \".mydist\"\n\
         vendor = \"ULE Project\"\n\
         \n\
         [[repos]]\n\
         name = \"base\"\n\
         baseurl = \"http://mirror.example.com/mydist/base/$basearch\"\n\
         gpgcheck = true\n"
    )
}

fn utc_past(minutes: i64) -> String {
    (chrono::Utc::now() - TimeDelta::minutes(minutes))
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string()
}

fn sample_build(pkg: &'static str, phase: &'static str) -> BuildInsert<'static> {
    BuildInsert {
        product: "mydist",
        pkg_name: pkg,
        phase,
        backend: "chroot",
        user: "op",
        arch: Some("x86_64"),
        ..Default::default()
    }
}

async fn insert_task(state: &AppState, phase: &'static str, nvr: &'static str) -> i64 {
    state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name: nvr,
            user: "op",
            phase,
            ..Default::default()
        })
        .await
        .expect("insert task")
}

/// 补齐任务时间列：submitted_at 相对现在偏移 `submitted_min_ago` 分钟；
/// 终态任务同时落 completed_at 与 duration（秒）。
async fn set_task_times(
    state: &AppState,
    id: i64,
    submitted_min_ago: i64,
    completed_min_ago: Option<i64>,
    duration: Option<i64>,
) {
    let completed_at = completed_min_ago.map(utc_past).unwrap_or_default();
    let duration_v = duration.unwrap_or(-1);
    sqlx::query(
        "UPDATE tasks SET submitted_at = $1, completed_at = $2, \
         duration = CASE WHEN $3 >= 0 THEN $3 ELSE NULL END WHERE id = $4",
    )
    .bind(utc_past(submitted_min_ago))
    .bind(completed_at)
    .bind(duration_v)
    .bind(id)
    .execute(state.state_store.pool())
    .await
    .expect("set task times");
}

#[ignore = "manual visual-preview generator: dumps rendered UI pages to target/ui-preview for screenshot review"]
#[tokio::test]
async fn dump_ui_previews() {
    let _ = TEST_CONFIG_DIR.path();
    crbs_server::test_support::init_test_logging();

    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    let state = Arc::new(AppState::for_test(
        state_store,
        ServerConfig::default(),
        tmp_dir.path().to_path_buf(),
    ));

    // --- 用户：admin + operator + builder（私有产品 owner）+ ACL viewer + 禁用 viewer。
    let admin_token = seed_user_token_for_test(&state.state_store, "admin-op", "admin")
        .await
        .expect("seed admin");
    seed_user_token_for_test(&state.state_store, "op", "operator")
        .await
        .expect("seed operator");
    seed_user_token_for_test(&state.state_store, "bob", "builder")
        .await
        .expect("seed builder");
    let carol_token = seed_user_token_for_test(&state.state_store, "carol", "viewer")
        .await
        .expect("seed carol");
    seed_user_token_for_test(&state.state_store, "erin", "viewer")
        .await
        .expect("seed erin");
    // seed_user_token_for_test 返回的是 token 明文；取 user id 走名字查询。
    let erin_id = state
        .state_store
        .find_user_by_name("erin")
        .await
        .expect("find erin")
        .expect("erin exists")
        .id;
    state
        .state_store
        .set_user_status(erin_id, "disabled")
        .await
        .expect("disable erin");
    let carol_id = state
        .state_store
        .find_user_by_name("carol")
        .await
        .expect("find carol")
        .expect("carol exists")
        .id;
    let bob_id = state
        .state_store
        .find_user_by_name("bob")
        .await
        .expect("find bob")
        .expect("bob exists")
        .id;
    let op_id = state
        .state_store
        .find_user_by_name("op")
        .await
        .expect("find op")
        .expect("op exists")
        .id;

    // --- 注册开关（预览）：开放态，供 register/register-zh 页渲染表单。
    state
        .state_store
        .set_app_meta("registration_enabled", "true")
        .await
        .expect("open registration for preview");

    // --- 产品：公共根 mydist（双 repo + 宏 + ACL 行 + 3 个历史 revision）+ 私有子 mypriv。
    let mydist_id = state
        .state_store
        .create_product(CreateProductInput {
            name: "mydist",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &ProductConfig::from_str(MYDIST_TOML).expect("mydist toml parses"),
            changed_by_user_id: None,
            reason: Some("initial import"),
        })
        .await
        .expect("create mydist");
    // 两次配置变更 → 历史页 3 个 revision（changed_by=op，diff 页摘要行可见）。
    for (i, extra) in ["createrepo_c", "dnf5"].iter().enumerate() {
        let cfg = ProductConfig::from_str(&mydist_toml_rev(extra)).expect("rev toml parses");
        state
            .state_store
            .update_product_config(mydist_id, &cfg, Some(op_id), Some("preview revision"), None)
            .await
            .unwrap_or_else(|e| panic!("mydist revision {}: {e}", i + 2));
    }
    state
        .state_store
        .grant_product_acl_with_role(carol_id, "mydist", "builder")
        .await
        .expect("grant carol acl on mydist");
    state
        .state_store
        .grant_product_acl_with_role(op_id, "mydist", "viewer")
        .await
        .expect("grant op acl on mydist");
    state
        .state_store
        .create_product(CreateProductInput {
            name: "mypriv",
            display_name: None,
            owner_id: Some(bob_id),
            parent_id: Some(mydist_id),
            visibility: "private",
            config: &ProductConfig::from_str(MYDIST_TOML).expect("mypriv toml parses"),
            changed_by_user_id: Some(bob_id),
            reason: Some("preview seed"),
        })
        .await
        .expect("create mypriv");

    // --- 任务：六 phase 全覆盖 + 时间跨度几分钟到几天（仪表盘环形图/仪表数据源）。
    // succeeded x4 / failed x2 / timeout x1 / cancelled x1 / building x1 / pending x2 = 11。
    let t = insert_task(&state, "pending", "openssh-8.7p1-4.el9").await;
    set_task_times(&state, t, 5, None, None).await;
    let t = insert_task(&state, "pending", "kernel-6.12.0-1.el9").await;
    set_task_times(&state, t, 2, None, None).await;
    let task_building = insert_task(&state, "building", "vim-enhanced-9.1.0-4.el9").await;
    set_task_times(&state, task_building, 65, None, None).await;
    let task_done = insert_task(&state, "succeeded", "openssh-8.7p1-4.el9").await;
    set_task_times(&state, task_done, 2885, Some(2880), Some(480)).await;
    let t = insert_task(&state, "succeeded", "vim-enhanced-9.1.0-4.el9").await;
    set_task_times(&state, t, 4325, Some(4320), Some(612)).await;
    let t = insert_task(&state, "succeeded", "httpd-2.4.62-1.el9").await;
    set_task_times(&state, t, 7205, Some(7200), Some(1300)).await;
    let t = insert_task(&state, "succeeded", "bash-5.2.26-3.el9").await;
    set_task_times(&state, t, 8645, Some(8640), Some(95)).await;
    let t = insert_task(&state, "failed", "kernel-6.12.0-1.el9").await;
    set_task_times(&state, t, 1445, Some(1440), Some(221)).await;
    let t = insert_task(&state, "failed", "httpd-2.4.62-1.el9").await;
    set_task_times(&state, t, 8645, Some(8640), Some(92)).await;
    let t = insert_task(&state, "timeout", "kernel-6.12.0-1.el9").await;
    set_task_times(&state, t, 365, Some(360), Some(3600)).await;
    let t = insert_task(&state, "cancelled", "tmux-3.2a-3.el9").await;
    set_task_times(&state, t, 35, Some(30), Some(4)).await;

    // --- 统计图种子：admin-op（me 预览登录者）名下 12 条 mydist 终态任务，
    // 交替 succeeded/failed、时间自 ~9 天前向最近推进——否则 /ui/me 总览带
    // strip + gauge 全空态；home / product-detail 的 mydist gauge 同享密度。
    for (i, (pkg, phase)) in [
        ("zstd-1.5.7-1.el9", "succeeded"),
        ("tar-1.35-2.el9", "failed"),
        ("sed-4.9-3.el9", "succeeded"),
        ("grep-3.11-4.el9", "succeeded"),
        ("coreutils-9.5-6.el9", "failed"),
        ("findutils-4.9.1-1.el9", "succeeded"),
        ("less-668-1.el9", "succeeded"),
        ("make-4.4.1-4.el9", "failed"),
        ("patch-2.7.6-15.el9", "succeeded"),
        ("diffutils-3.7-9.el9", "succeeded"),
        ("awk-5.3.0-3.el9", "failed"),
        ("ed-1.19-3.el9", "succeeded"),
    ]
    .into_iter()
    .enumerate()
    {
        let mins_ago = 13000 - (i as i64) * 720;
        let mins_done = mins_ago - 6;
        let t = state
            .state_store
            .insert_task(TaskInsert {
                product: "mydist",
                pkg_name: pkg,
                user: "admin-op",
                phase,
                ..Default::default()
            })
            .await
            .expect("insert admin-op task");
        set_task_times(
            &state,
            t,
            mins_ago,
            Some(mins_done),
            Some(120 + (i as i64) * 17 % 900),
        )
        .await;
    }

    // --- worker：双架构四台 —— 在线 / 在线但心跳过期（stale）/ 在线 / 离线。
    let busy_worker = state
        .state_store
        .upsert_worker("edge-x86-01", "x86_64", 4, "0.15.0-dev", "online", None)
        .await
        .expect("upsert edge-x86-01");
    let stale_worker = state
        .state_store
        .upsert_worker("edge-x86-02", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .expect("upsert edge-x86-02");
    state
        .state_store
        .upsert_worker("arm-a64-01", "aarch64", 2, "0.14.2", "online", None)
        .await
        .expect("upsert arm-a64-01");
    let offline_worker = state
        .state_store
        .upsert_worker("arm-a64-02", "aarch64", 1, "0.14.0", "online", None)
        .await
        .expect("upsert arm-a64-02");
    state
        .state_store
        .worker_mark_offline(offline_worker)
        .await
        .expect("mark arm-a64-02 offline");
    // 心跳过期：status 仍 online，但 last_heartbeat 拉到 10 分钟前 → 列表/详情
    // 降级渲染 warn "stale" 徽章（阈值 300s）。
    sqlx::query("UPDATE workers SET last_heartbeat = $1 WHERE id = $2")
        .bind(utc_past(10))
        .bind(stale_worker)
        .execute(state.state_store.pool())
        .await
        .expect("age edge-x86-02 heartbeat");

    // --- 构建：building（带实时日志目录）+ succeeded（带 DB 产物行）+ failed + pending。
    let result_root = state.result_dir_for_or_default("mydist").await;
    let live_dir = result_root.join("preview-live-build");
    std::fs::create_dir_all(&live_dir).expect("create live result dir");
    // 头部 CRBS_PHASE 标记：SKIP + done + 未闭合 running 的混合形态，覆盖
    // 详情页时间线的截图形态；时间戳取近期固定值（running 步服务端只渲染
    // "…"，不依赖 now）。
    let log_text = "# CRBS_PHASE_START prepare-layer 1787999999.5\n\
                    # CRBS_PHASE_END prepare-layer 0 1788000000.0\n\
                    # CRBS_PHASE_SKIP ccache-init ccache_disabled\n\
                    # CRBS_PHASE_START install-srpm 1788000000.0\n\
                    # CRBS_PHASE_END install-srpm 0 1788000001.0\n\
                    # CRBS_PHASE_START install-deps 1788000002.0\n\
                    mockbuild: about to spawn mock\n\
                    :: installing base system packages\n\
                    :: running rpmbuild -ba openssh.spec\n\
                    Executing(%prep): /bin/sh -e /var/tmp/rpm-tmp.abc123\n\
                    + cd /builddir/build/BUILD\n\
                    + umask 022\n\
                    Building target platforms: x86_64\n\
                    Wrote: /builddir/build/SRPMS/openssh-8.7p1-4.el9.src.rpm\n\
                    :: waiting for worker heartbeat\n";
    std::fs::write(live_dir.join("build.log"), log_text).expect("write build.log");

    let build_live = state
        .state_store
        .insert_build(BuildInsert {
            phase: "building",
            // task_building 已先行创建；下方 UPDATE 会再次写同一 task_id。
            task_id: Some(task_building),
            ..sample_build("openssh-8.7p1-4.el9", "building")
        })
        .await
        .expect("insert building build");
    sqlx::query("UPDATE builds SET started_at = $1, result_dir = $2, task_id = $3 WHERE id = $4")
        .bind(utc_past(40))
        .bind(live_dir.to_str().expect("live dir utf8"))
        .bind(task_building)
        .bind(build_live)
        .execute(state.state_store.pool())
        .await
        .expect("set building build fields");

    let task_ok = crbs_server::test_support::seed_task(
        &state.state_store,
        "mydist",
        "vim-enhanced-9.1.0-4.el9",
    )
    .await;
    let build_ok = state
        .state_store
        .insert_build(BuildInsert {
            task_id: Some(task_ok),
            ..sample_build("vim-enhanced-9.1.0-4.el9", "succeeded")
        })
        .await
        .expect("insert succeeded build");
    sqlx::query(
        "UPDATE builds SET started_at = $1, completed_at = $2, duration = $3 WHERE id = $4",
    )
    .bind(utc_past(4330))
    .bind(utc_past(4320))
    .bind(612_i64)
    .bind(build_ok)
    .execute(state.state_store.pool())
    .await
    .expect("set succeeded build times");

    // --- 构建时长条形图样本：几条不同 NVR/arch 的 succeeded 构建
    // （completed_at 递减，时长拉开梯度——时长卡多行有内容可截）。
    for (pkg, arch, mins_ago, dur) in [
        ("httpd-2.4.62-1.el9", "x86_64", 610, 1300_i64),
        ("httpd-2.4.62-1.el9", "aarch64", 640, 1455),
        ("bash-5.2.26-3.el9", "x86_64", 1300, 95),
        ("openssh-8.7p1-4.el9", "x86_64", 2780, 480),
        ("openssh-8.7p1-4.el9", "aarch64", 2810, 502),
    ] {
        // builds.task_id NOT NULL：standalone 构建不可再插入，
        // 每条时长样本构建挂到自己的任务下（相位/用户与构建一致）。
        let task_id = insert_task(&state, "succeeded", pkg).await;
        let id = state
            .state_store
            .insert_build(BuildInsert {
                arch: Some(arch),
                task_id: Some(task_id),
                ..sample_build(pkg, "succeeded")
            })
            .await
            .expect("insert duration-chart build");
        sqlx::query(
            "UPDATE builds SET started_at = $1, completed_at = $2, duration = $3 WHERE id = $4",
        )
        .bind(utc_past(mins_ago + 10))
        .bind(utc_past(mins_ago))
        .bind(dur)
        .bind(id)
        .execute(state.state_store.pool())
        .await
        .expect("set duration-chart build times");
    }
    // admin-op 名下一条（/ui/me 预览登录者是 admin-op——否则个人时长卡空态）。
    // 构建挂任务（user 同为 admin-op，个人中心计数一致）。
    let me_task = state
        .state_store
        .insert_task(TaskInsert {
            product: "mydist",
            pkg_name: "dnf5-5.2.5-1.el9",
            user: "admin-op",
            phase: "succeeded",
            ..Default::default()
        })
        .await
        .expect("insert admin-op task");
    let me_build = state
        .state_store
        .insert_build(BuildInsert {
            arch: Some("x86_64"),
            user: "admin-op",
            task_id: Some(me_task),
            ..sample_build("dnf5-5.2.5-1.el9", "succeeded")
        })
        .await
        .expect("insert admin-op build");
    sqlx::query(
        "UPDATE builds SET started_at = $1, completed_at = $2, duration = $3 WHERE id = $4",
    )
    .bind(utc_past(500))
    .bind(utc_past(495))
    .bind(210_i64)
    .bind(me_build)
    .execute(state.state_store.pool())
    .await
    .expect("set admin-op build times");

    let task_failed =
        crbs_server::test_support::seed_task(&state.state_store, "mydist", "kernel-6.12.0-1.el9")
            .await;
    let build_failed = state
        .state_store
        .insert_build(BuildInsert {
            task_id: Some(task_failed),
            ..sample_build("kernel-6.12.0-1.el9", "failed")
        })
        .await
        .expect("insert failed build");
    sqlx::query("UPDATE builds SET started_at = $1, completed_at = $2 WHERE id = $3")
        .bind(utc_past(1450))
        .bind(utc_past(1440))
        .bind(build_failed)
        .execute(state.state_store.pool())
        .await
        .expect("set failed build times");
    // 失败原因摘要：让详情页截图覆盖 message failure 卡片。
    sqlx::query("UPDATE builds SET error_summary = $1 WHERE id = $2")
        .bind("script rpmbuild -ba failed: exit_code=1; phase=build; subphase=compile; reason=gcc: error: no such file or directory: main.c")
        .bind(build_failed)
        .execute(state.state_store.pool())
        .await
        .expect("set failed build error summary");
    // 失败构建 build.log：全生命周期标记 + build 子阶段 +
    // %check 失败归属——失败面板（自动展开 + 错误摘录 + 日志行锚点）进截图协议。
    let failed_dir = result_root.join("preview-failed-build");
    std::fs::create_dir_all(&failed_dir).expect("create failed result dir");
    let failed_log = "# CRBS_PHASE_START prepare-layer 1787999999.5\n\
                      # CRBS_PHASE_END prepare-layer 0 1788000000.0\n\
                      # CRBS_PHASE_SKIP ccache-init ccache_disabled\n\
                      # CRBS_PHASE_START install-srpm 1788000000.0\n\
                      # CRBS_PHASE_END install-srpm 0 1788000000.1\n\
                      # CRBS_PHASE_START install-deps 1788000000.2\n\
                      # CRBS_PHASE_END install-deps 0 1788000051.2\n\
                      # CRBS_PHASE_START build 1788000051.3\n\
                      Executing(%prep): /bin/sh -e /var/tmp/rpm-tmp.aaa\n\
                      + cd /builddir/build/BUILD\n\
                      + /usr/bin/patch -p1 < kernel-6.12-custom.patch\n\
                      Executing(%build): /bin/sh -e /var/tmp/rpm-tmp.bbb\n\
                      + make -j8\n\
                      Executing(%install): /bin/sh -e /var/tmp/rpm-tmp.ccc\n\
                      + make install DESTDIR=/builddir/build/BUILDROOT\n\
                      Executing(%check): /bin/sh -e /var/tmp/rpm-tmp.ddd\n\
                      + make check\n\
                      PASS: test-sort\n\
                      FAIL: test-parse (exit 1)\n\
                      error: Bad exit status from /var/tmp/rpm-tmp.ddd (%check)\n";
    std::fs::write(failed_dir.join("build.log"), failed_log).expect("write failed build.log");
    sqlx::query("UPDATE builds SET result_dir = $1 WHERE id = $2")
        .bind(failed_dir.to_str().expect("failed dir utf8"))
        .bind(build_failed)
        .execute(state.state_store.pool())
        .await
        .expect("set failed build result_dir");

    let task_pending =
        crbs_server::test_support::seed_task(&state.state_store, "mydist", "kernel-6.12.0-1.el9")
            .await;
    let build_pending = state
        .state_store
        .insert_build(BuildInsert {
            task_id: Some(task_pending),
            ..sample_build("kernel-6.12.0-1.el9", "pending")
        })
        .await
        .expect("insert pending build");
    state
        .state_store
        .assign_build_to_worker(build_pending, busy_worker)
        .await
        .expect("assign pending build to busy worker");

    // 成功构建的产物元数据（build_artifacts 表）：2 rpm + 1 srpm。
    for (path, kind, size, name, version, release, arch) in [
        (
            "results/x86_64/vim-enhanced-9.1.0-4.el9.x86_64.rpm",
            "rpm",
            4_211_664i64,
            "vim-enhanced",
            "9.1.0",
            "4.el9",
            "x86_64",
        ),
        (
            "results/x86_64/vim-common-9.1.0-4.el9.x86_64.rpm",
            "rpm",
            12_582_912,
            "vim-common",
            "9.1.0",
            "4.el9",
            "x86_64",
        ),
        (
            "results/SRPMS/vim-enhanced-9.1.0-4.el9.src.rpm",
            "srpm",
            16_777_216,
            "vim-enhanced",
            "9.1.0",
            "4.el9",
            "src",
        ),
    ] {
        sqlx::query(
            "INSERT INTO build_artifacts \
             (build_id, relative_path, kind, size_bytes, sha256, arch, name, version, \
              release, epoch, signed, on_disk, metadata_json, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, 0, 1, NULL, $10)",
        )
        .bind(build_ok)
        .bind(path)
        .bind(kind)
        .bind(size)
        .bind("deadbeef".repeat(8))
        .bind(arch)
        .bind(name)
        .bind(version)
        .bind(release)
        .bind(utc_past(4320))
        .execute(state.state_store.pool())
        .await
        .expect("insert build artifact row");
    }

    // --- 审计行：多 action、多角色、带/不带 detail。
    for (actor, role, action, target, detail) in [
        (
            "admin-op",
            "admin",
            "create_user",
            Some("carol"),
            Some(r#"{"role":"viewer"}"#),
        ),
        (
            "admin-op",
            "admin",
            "rotate_worker_secret",
            Some("13"),
            Some(r#"{"worker_name":"arm-a64-02"}"#),
        ),
        (
            "op",
            "operator",
            "gc",
            Some("3f2b8c1a"),
            Some(r#"{"dry_run":true,"results":true}"#),
        ),
        (
            "bob",
            "builder",
            "product_visibility",
            Some("mypriv"),
            Some(r#"{"visibility":"private"}"#),
        ),
        (
            "op",
            "operator",
            "rebuild_repo",
            Some("mydist"),
            Some(r#"{"arches":["x86_64","aarch64"]}"#),
        ),
        ("op", "operator", "cancel_build", Some("1002"), None),
    ] {
        state
            .state_store
            .audit_log(actor, role, action, target, detail)
            .await
            .expect("seed audit row");
    }

    // --- GC 历史（内存 AppState.gc_tasks，重启即失）：一次 dry-run 成功 + 一次失败。
    {
        let now = chrono::Utc::now();
        let mut tasks = state.gc_tasks.lock().await;
        tasks.insert(
            "3f2b8c1a-77d2-4e55-9a10-d8c04a1b2f3e".into(),
            GcTask {
                status: GcTaskStatus::Succeeded(GcSummary {
                    results: Some(GcResultsSummary {
                        removed: 0,
                        would_remove: 7,
                        bytes: 500_000_000,
                        policy_removed: 0,
                        skipped_latest: 0,
                        skipped_missing: 0,
                        skipped_invalid: 0,
                        failed: 0,
                        affected_products: Vec::new(),
                    }),
                    orphan_mounts: Some(GcOrphanMountsSummary {
                        found: 1,
                        cleaned: 0,
                        removed_dirs: 0,
                        dry_run: true,
                    }),
                    package_cache: None,
                    shared_layers: None,
                }),
                started_at: now - TimeDelta::minutes(25),
                finished_at: Some(now - TimeDelta::minutes(25) + TimeDelta::seconds(90)),
            },
        );
        tasks.insert(
            "9c1d5e2f-3a4b-4c6d-8e7f-a0b1c2d3e4f5".into(),
            GcTask {
                status: GcTaskStatus::Failed(
                    "result dir busy: mydist repo assembly in progress".into(),
                ),
                started_at: now - TimeDelta::hours(2),
                finished_at: Some(now - TimeDelta::hours(2) + TimeDelta::seconds(5)),
            },
        );
    }

    let app = create_test_app_with_auth(state.clone());

    // --- 逐页 dump：(文件名, URI, 会话 cookie, 主题 cookie, 语言 cookie, 期望状态)。
    // 主题 cookie 带 -dark 后缀条目：暗色自审数据源（服务端按 cookie 注入
    // data-theme，等价于截图协议 --cookie crbs_theme=dark）。
    // 语言 cookie 带 -zh 后缀条目：中文 SSR 变体，供双语截图自审。
    // 六元组类型别名绕开 clippy::type_complexity。
    type PreviewPage<'a> = (
        &'a str,
        String,
        Option<&'a str>,
        Option<&'a str>,
        Option<&'a str>,
        StatusCode,
    );
    let pages: Vec<PreviewPage> = vec![
        (
            "home",
            "/ui/".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "home-dark",
            "/ui/".into(),
            Some(&admin_token),
            Some("dark"),
            None,
            StatusCode::OK,
        ),
        // 视觉回归钉子：viewer（7 链接 + user/Logout，无 GC/Admin 链接）
        // 是 1440 内容宽 1200 内 nav 单行的临界角色；admin 链接多，窄内容
        // 宽必然换行。
        (
            "home-viewer",
            "/ui/".into(),
            Some(&carol_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "builds",
            "/ui/builds".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "build-detail",
            format!("/ui/builds/{build_ok}"),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "build-detail-live",
            format!("/ui/builds/{build_live}"),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "build-detail-failed",
            format!("/ui/builds/{build_failed}"),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "build-logs",
            format!("/ui/builds/{build_live}/logs"),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "tasks",
            "/ui/tasks".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        // 提交构建页（admin 视角：产品下拉 + 双架构复选框数据源 + critical 优先级）。
        (
            "tasks-new",
            "/ui/tasks/new".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "task-detail",
            format!("/ui/tasks/{task_done}"),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "products",
            "/ui/products".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "products-dark",
            "/ui/products".into(),
            Some(&admin_token),
            Some("dark"),
            None,
            StatusCode::OK,
        ),
        (
            "product-detail",
            "/ui/products/mydist".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "product-history",
            "/ui/products/mydist/history".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        // 配置 diff：r2→r3（+dnf5），seed 已含 3 个历史 revision。
        (
            "product-history-diff",
            "/ui/products/mydist/history/diff?from=2&to=3".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "product-new",
            "/ui/products/new".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "product-edit",
            "/ui/products/mydist/edit".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "packages",
            "/ui/packages".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "package-detail",
            "/ui/packages/openssh".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "package-attempts",
            "/ui/packages/openssh?nvr=openssh-8.7p1-4.el9".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        // changelog 整页：build 作用域（build_ok 带产物行，rpm 不在盘 →
        // fail-soft 空态，仍走整页 chrome 与分页元信息）+ 中文变体 + task
        // 作用域（胜出子构建链路，源同为 build_ok 的产物行）。
        (
            "build-changelog",
            format!("/ui/builds/{build_ok}/changelog"),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "build-changelog-zh",
            format!("/ui/builds/{build_ok}/changelog"),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "task-changelog",
            format!("/ui/tasks/{task_ok}/changelog"),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        // 全局搜索两形态：直达（q=task id，同时命中 Build #4 显示 NVR）与
        // 前缀（zh，q=vim 命中包名区）。q 无法同时命中直达与前缀区，分两页覆盖。
        (
            "search-direct",
            format!("/ui/search?q={task_done}"),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "search-prefix-zh",
            "/ui/search?q=vim".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "workers",
            "/ui/workers".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "worker-detail",
            format!("/ui/workers/{busy_worker}"),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "admin",
            "/ui/admin".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "admin-users",
            "/ui/admin/users".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "admin-user-detail",
            format!("/ui/admin/users/{op_id}"),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "admin-audit",
            "/ui/admin/audit".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "gc",
            "/ui/admin/gc".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        // 管理员设置页（注册开关卡片）。
        (
            "admin-settings",
            "/ui/admin/settings".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        // 个人中心（token 模式：admin_token 经 crbs_token cookie）。
        (
            "me",
            "/ui/me".into(),
            Some(&admin_token),
            None,
            None,
            StatusCode::OK,
        ),
        (
            "me-zh",
            "/ui/me".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        // 登录双模式 + 注册页（注册开放态：seed 阶段已打开开关）。
        (
            "login",
            "/ui/login".into(),
            None,
            None,
            None,
            StatusCode::OK,
        ),
        (
            "login-zh",
            "/ui/login".into(),
            None,
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "register",
            "/ui/register".into(),
            None,
            None,
            None,
            StatusCode::OK,
        ),
        (
            "register-zh",
            "/ui/register".into(),
            None,
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "not-found",
            "/ui/nonexistent".into(),
            None,
            None,
            None,
            StatusCode::NOT_FOUND,
        ),
        // 中文 SSR 变体（crbs_lang=zh）：chrome（nav/footer）+ 样板页
        // （dashboard / tasks 列表 / 错误页）为中文。
        (
            "home-zh",
            "/ui/".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "tasks-zh",
            "/ui/tasks".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "tasks-new-zh",
            "/ui/tasks/new".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "not-found-zh",
            "/ui/nonexistent".into(),
            None,
            None,
            Some("zh"),
            StatusCode::NOT_FOUND,
        ),
        // 中文 SSR 变体：全量迁移页面（列表 + 详情 + admin/GC）整页中文。
        (
            "builds-zh",
            "/ui/builds".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "build-detail-zh",
            format!("/ui/builds/{build_ok}"),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "build-logs-zh",
            format!("/ui/builds/{build_live}/logs"),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "task-detail-zh",
            format!("/ui/tasks/{task_done}"),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "products-zh",
            "/ui/products".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "product-detail-zh",
            "/ui/products/mydist".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "product-new-zh",
            "/ui/products/new".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "product-edit-zh",
            "/ui/products/mydist/edit".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "packages-zh",
            "/ui/packages".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "workers-zh",
            "/ui/workers".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "admin-zh",
            "/ui/admin".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "admin-users-zh",
            "/ui/admin/users".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "admin-user-detail-zh",
            format!("/ui/admin/users/{op_id}"),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "admin-audit-zh",
            "/ui/admin/audit".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "gc-zh",
            "/ui/admin/gc".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
        (
            "admin-settings-zh",
            "/ui/admin/settings".into(),
            Some(&admin_token),
            None,
            Some("zh"),
            StatusCode::OK,
        ),
    ];

    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"))
        .join("ui-preview");
    std::fs::create_dir_all(&target_dir).expect("create ui-preview dir");
    // 清掉上次运行的旧 dump，避免截图脚本捡到陈旧页面。
    for entry in std::fs::read_dir(&target_dir).expect("read ui-preview dir") {
        let entry = entry.expect("dir entry");
        if entry.path().extension().is_some_and(|e| e == "html") {
            std::fs::remove_file(entry.path()).expect("remove stale dump");
        }
    }

    // nav logo 的 /ui/favicon.svg 在 file:// 截图下解析不到（每张截图都带
    // 破图图标，污染视觉审查）。dump 前改写为 data: URI——SVG 取自服务端
    // 同一路由的真身（单一真源，不复制 assets）；# 与 " 按 data URI 规则
    // 百分号编码，换行剥除，空格浏览器容忍原样。
    let favicon_attr = {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ui/favicon.svg")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("favicon request");
        assert_eq!(resp.status(), StatusCode::OK, "favicon route should exist");
        let svg = String::from_utf8_lossy(
            &to_bytes(resp.into_body(), usize::MAX)
                .await
                .expect("favicon body"),
        )
        .into_owned();
        format!(
            "src=\"data:image/svg+xml,{}\"",
            svg.replace('#', "%23")
                .replace('"', "%22")
                .replace('\n', "")
        )
    };

    for (name, uri, cookie, theme, lang, expect_status) in &pages {
        let mut builder = Request::builder().uri(uri);
        // Cookie 头：会话 token、主题偏好与语言偏好按需拼接。
        let mut cookies = Vec::new();
        if let Some(token) = cookie {
            cookies.push(format!("crbs_token={token}"));
        }
        if let Some(theme) = theme {
            cookies.push(format!("crbs_theme={theme}"));
        }
        if let Some(lang) = lang {
            cookies.push(format!("crbs_lang={lang}"));
        }
        if !cookies.is_empty() {
            builder = builder.header("Cookie", cookies.join("; "));
        }
        let response = app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .expect("oneshot request");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let html = String::from_utf8_lossy(&bytes).into_owned();
        let html = html.replace("src=\"/ui/favicon.svg\"", &favicon_attr);
        assert_eq!(
            status, *expect_status,
            "{uri}: expected {expect_status}, got {status}: {html}"
        );
        let out = target_dir.join(format!("{name}.html"));
        std::fs::write(&out, &html).unwrap_or_else(|e| panic!("write {out:?}: {e}"));
        println!("dumped {uri} -> {}", out.display());
    }

    // 产品总览带：product-detail 变体（seed 已含六 phase 任务）必须渲染
    // strip + gauge；截图脚本据此页面自审带的视觉呈现。
    let product_detail_html = std::fs::read_to_string(target_dir.join("product-detail.html"))
        .expect("read product-detail dump");
    for marker in ["me-overview", "sys-strip", "product-gauge-pct"] {
        assert!(
            product_detail_html.contains(marker),
            "product-detail overview band missing {marker}"
        );
    }

    // 产品列表活动列：断言 32 = seed 的 mydist 任务总数（11 基础 + 12 统计
    // + 5 时长样本 + 1 me + 3 seed_task），mypriv 零任务（截图覆盖 "—" 空态）。
    let products_html =
        std::fs::read_to_string(target_dir.join("products.html")).expect("read products dump");
    for marker in [
        "<th class=\"num\">Tasks</th>",
        // 列头含对齐类（num），断言按当前 DOM 结构取整头。
        "<th class=\"num\">Last build</th>",
        "<td class=\"num\">32</td>",
    ] {
        assert!(
            products_html.contains(marker),
            "products list missing {marker}"
        );
    }

    // 时长卡仅 product-detail / me 保留，home 变体无时长图也无趋势卡：
    // dur-chart/dur-row 断言取元素标记（内联 CSS 含同名选择器文本，裸子串
    // 会误中 CSS）；product-detail / me 各含时长卡标题（截图自审数据源）。
    let home_html = std::fs::read_to_string(target_dir.join("home.html")).expect("read home dump");
    for marker in [
        r#"<div class="dur-chart""#,
        r#"<div class="dur-row""#,
        "Recent build durations",
    ] {
        assert!(
            !home_html.contains(marker),
            "duration chart must be gone from home: {marker}"
        );
    }
    assert!(
        !home_html.contains("trend-chart"),
        "trend chart must be gone: home"
    );
    for name in ["product-detail", "me"] {
        let page_html = std::fs::read_to_string(target_dir.join(format!("{name}.html")))
            .unwrap_or_else(|e| {
                panic!("read {name} dump: {e}");
            });
        assert!(
            page_html.contains("Recent build durations"),
            "{name} duration card missing"
        );
        assert!(
            !page_html.contains("trend-chart"),
            "trend chart must be gone: {name}"
        );
        // me 变体（admin-op 登录）：个人时长卡有数据。
        if name == "me" {
            assert!(
                page_html.contains("dnf5-5.2.5-1.el9"),
                "me duration chart missing admin-op build"
            );
        }
    }

    // 种子钉子：live build 的 build.log 带 CRBS_PHASE 标记 → 详情页时间线
    // 渲染步进条混合态。fixture 里的 ccache-init SKIP 属隐藏工具步骤
    // （HIDDEN_TOOL_PHASES），不渲染也不聚 chip——skip 仅 ccache 步骤携带
    // （ccache_disabled），skip-chip 无处渲染，截图无从覆盖。
    let build_live_html = std::fs::read_to_string(target_dir.join("build-detail-live.html"))
        .expect("read build-detail-live dump");
    for marker in [
        r#"class="phase-step done" data-phase="prepare-layer""#,
        r#"class="phase-step done" data-phase="install-srpm""#,
        r#"class="phase-step running" data-phase="install-deps""#,
    ] {
        assert!(
            build_live_html.contains(marker),
            "live build detail timeline missing {marker}"
        );
    }
    assert!(
        !build_live_html.contains(r#"data-phase="ccache-init""#),
        "hidden tool phase must not render in live build detail"
    );

    println!(
        "\nui-preview: {} pages written to {}",
        pages.len(),
        target_dir.display()
    );
}

/// 空 dashboard 变体（全新安装：零任务、零构建、零 worker、零产品）——donut
/// 空态满环（circle.seg-empty）与 gauge "—" 占位的截图自审数据源。主 fixture
/// 是单条富种子数据集，空态无法在旁落一页，须独立空库 harness；输出同一
/// target/ui-preview 目录（home-empty.html），不触碰主 61 页 dump。运行：
///
/// ```sh
/// cargo test -p crbs-server --test ui_preview dump_ui_preview_empty_dashboard -- --ignored --nocapture
/// ```
#[ignore = "manual visual-preview generator: dumps the empty-install dashboard to target/ui-preview for screenshot review"]
#[tokio::test]
async fn dump_ui_preview_empty_dashboard() {
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
    let app = create_test_app_with_auth(state.clone());

    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"))
        .join("ui-preview");
    std::fs::create_dir_all(&target_dir).expect("create ui-preview dir");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/")
                .header("Cookie", format!("crbs_token={admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("home request");
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8_lossy(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body"),
    )
    .into_owned();
    // 空态钉子：donut 空态满环在位（中性 track 形态）+ 环心 0；gauge 走
    // 常驻 track 灰环 + "—" 占位。
    for marker in [
        r#"circle class="seg-empty" r="81""#,
        r#"id="dash-donut-total">0<"#,
        r#"id="dash-gauge-pct">—<"#,
    ] {
        assert!(html.contains(marker), "empty dashboard missing {marker}");
    }
    let out = target_dir.join("home-empty.html");
    std::fs::write(&out, &html).expect("write home-empty dump");
    println!("dumped /ui/ (empty install) -> {}", out.display());
}
