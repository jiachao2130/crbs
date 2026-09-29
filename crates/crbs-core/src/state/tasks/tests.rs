// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 任务状态层测试：生命周期、查询过滤与并发边界。

use super::*;
use crate::state::test_state::create_test_store;

#[tokio::test]
async fn task_lifecycle() {
    let (store, _tmp) = create_test_store().await;

    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            user: "alice",
            user_id: None,
            phase: "pending",
            priority: 0,
            srpm_path: Some("/tmp/foo.src.rpm"),
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();

    let task = store.get_task(task_id).await.unwrap().unwrap();
    assert_eq!(task.product, "fedora");
    assert_eq!(task.pkg_name, "foo");
    assert_eq!(task.phase, "pending");

    let mut conn = store.pool().acquire().await.unwrap();
    let rows = update_task_phase_on(&mut conn, task_id, "building")
        .await
        .unwrap();
    assert_eq!(rows, 1);
    let task = store.get_task(task_id).await.unwrap().unwrap();
    assert_eq!(task.phase, "building");

    // 终态写入由 complete_build 聚合路径完成（见 task_phase_aggregation_from_children）。
}

/// 终态守卫：已终态 task 不被迟到的中间态 / failed / 取消收口写入翻转
/// （先到者生效；0 行返回表示守卫拒绝，不是错误）。
#[tokio::test]
async fn terminal_task_phase_not_flipped_by_late_writes() {
    let (store, _tmp) = create_test_store().await;
    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            phase: "succeeded",
            ..Default::default()
        })
        .await
        .unwrap();

    let mut conn = store.pool().acquire().await.unwrap();
    assert_eq!(
        update_task_phase_on(&mut conn, task_id, "building")
            .await
            .unwrap(),
        0
    );
    assert_eq!(store.mark_task_failed(task_id).await.unwrap(), 0);
    store.finalize_cancelled_task(task_id).await.unwrap();

    let task = store.get_task(task_id).await.unwrap().unwrap();
    assert_eq!(task.phase, "succeeded");
}

/// fan-out 守护与用户取消的竞态：0-build pending 任务先被取消（cancelled
/// 终态 + completed_at），守护迟到的 mark_task_failed 不得翻成 failed。
#[tokio::test]
async fn mark_task_failed_does_not_flip_cancelled_pending_task() {
    let (store, _tmp) = create_test_store().await;
    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();

    store.finalize_cancelled_task(task_id).await.unwrap();
    let task = store.get_task(task_id).await.unwrap().unwrap();
    assert_eq!(task.phase, "cancelled");
    assert!(
        task.completed_at.is_some(),
        "cancel must record completed_at"
    );

    assert_eq!(store.mark_task_failed(task_id).await.unwrap(), 0);
    assert_eq!(
        store.get_task(task_id).await.unwrap().unwrap().phase,
        "cancelled"
    );
}

/// 契约洞：`finalize_cancelled_task` 三态透出。
/// - Finalized：子构建先全部落终态（cancelled）→ 聚合写入成功；
/// - Superseded：空子路径 0 行拒写——单线程下用"task 已被并发写终态"
///   构造（终态守卫拒写；真实竞态是 fan-out 的 NOT EXISTS 拒写，两者在
///   0 行上不可区分，语义同为"task 状态在取消途中被并发改变"，路由层
///   测试用写锁序列化构造 fan-out 形态）；
/// - ChildrenActive：仍有活跃（pending）子构建，per-build cancel 后的
///   软收敛语义。
#[tokio::test]
async fn finalize_cancelled_task_reports_three_outcomes() {
    let (store, _tmp) = create_test_store().await;

    // Finalized：先取消子（落终态）再 finalize → 聚合出 cancelled 且写入成功。
    // （build 终态不走 update_build_phase——它只许 assigned/building 中间态，
    // 直接 SQL 与守卫测试同款。）
    let done = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "done",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();
    let done_build = store
        .insert_build(crate::BuildInsert {
            product: "fedora",
            pkg_name: "done",
            phase: "pending",
            backend: "chroot",
            user: "alice",
            arch: Some("x86_64"),
            task_id: Some(done),
            ..Default::default()
        })
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET phase = 'cancelled' WHERE id = $1")
        .bind(done_build)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        store.finalize_cancelled_task(done).await.unwrap(),
        FinalizeOutcome::Finalized
    );
    assert_eq!(
        store.get_task(done).await.unwrap().unwrap().phase,
        "cancelled"
    );

    // Superseded：0-build task 在取消途中被并发写终态 → 快照读空 +
    // 终态守卫拒写 0 行 → 取消未生效信号。
    let raced = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "raced",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();
    sqlx::query("UPDATE tasks SET phase = 'succeeded' WHERE id = $1")
        .bind(raced)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        store.finalize_cancelled_task(raced).await.unwrap(),
        FinalizeOutcome::Superseded
    );
    // 先到者生效：终态不被取消翻转。
    assert_eq!(
        store.get_task(raced).await.unwrap().unwrap().phase,
        "succeeded"
    );

    // ChildrenActive：仍有 pending 活跃子 → 软收敛（保持原 phase，不报错）。
    let active = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "active",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .insert_build(crate::BuildInsert {
            product: "fedora",
            pkg_name: "active",
            phase: "pending",
            backend: "chroot",
            user: "alice",
            arch: Some("x86_64"),
            task_id: Some(active),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        store.finalize_cancelled_task(active).await.unwrap(),
        FinalizeOutcome::ChildrenActive
    );
    assert_eq!(
        store.get_task(active).await.unwrap().unwrap().phase,
        "pending"
    );
}

/// `sql::complete_task` 写入自带"无活跃子构建"CAS 谓词，消除
/// `finalize_cancelled_task` 快照读与写入之间的 TOCTOU 间隙：
/// - 仍有 pending 子构建 → 0 行拒绝，task 保持 pending；
/// - 子构建全部终态（cancelled）→ 1 行落库，completed_at 非空。
/// （0-build task 的 NOT EXISTS 平凡真，由 terminal_task_phase_not_flipped_
/// by_late_writes / mark_task_failed_does_not_flip_cancelled_pending_task 钉住。）
#[tokio::test]
async fn complete_task_write_guard_rejects_when_active_child_exists() {
    let (store, _tmp) = create_test_store().await;
    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();
    let build_id = store
        .insert_build(crate::BuildInsert {
            product: "fedora",
            pkg_name: "foo",
            phase: "pending",
            backend: "chroot",
            user: "alice",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    // 子构建仍 pending（活跃）→ 终态写入被拒（0 行），task 不被翻转。
    let mut conn = store.pool().acquire().await.unwrap();
    let rows = complete_task_on(&mut conn, store.dialect(), task_id, "cancelled")
        .await
        .unwrap();
    drop(conn);
    assert_eq!(rows, 0, "active child build must block terminal write");
    assert_eq!(
        store.get_task(task_id).await.unwrap().unwrap().phase,
        "pending"
    );

    // 子构建落终态（cancelled）→ 写入放行（1 行），completed_at 一并落库。
    sqlx::query("UPDATE builds SET phase = 'cancelled' WHERE id = $1")
        .bind(build_id)
        .execute(store.pool())
        .await
        .unwrap();
    let mut conn = store.pool().acquire().await.unwrap();
    let rows = complete_task_on(&mut conn, store.dialect(), task_id, "cancelled")
        .await
        .unwrap();
    drop(conn);
    assert_eq!(rows, 1);
    let task = store.get_task(task_id).await.unwrap().unwrap();
    assert_eq!(task.phase, "cancelled");
    assert!(task.completed_at.is_some());
}

#[tokio::test]
async fn mark_task_failed_sets_terminal_phase_and_completed_at() {
    let (store, _tmp) = create_test_store().await;
    let task_id = store
        .insert_task(TaskInsert {
            product: "ule3",
            pkg_name: "httpd",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();

    store.mark_task_failed(task_id).await.unwrap();
    let task = store.get_task(task_id).await.unwrap().unwrap();
    assert_eq!(task.phase, "failed");
    assert!(task.completed_at.is_some());
}

#[tokio::test]
async fn sweep_orphaned_tasks_marks_only_zero_build_pending_past_grace() {
    let (store, _tmp) = create_test_store().await;
    let pool = store.pool();

    let mk = |pkg: &'static str, phase: &'static str| {
        let store = &store;
        async move {
            store
                .insert_task(TaskInsert {
                    product: "ule3",
                    pkg_name: pkg,
                    phase,
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };
    // 回拨 submitted_at：绑定 Rust 侧 UTC TEXT（与生产 sweep SQL 的比较帧
    // 同一 UTC 墙钟——PG 侧 to_char(NOW() AT TIME ZONE 'UTC')，会话时区无关）。
    let backdate = |id: i64| {
        let past = (chrono::Utc::now() - chrono::TimeDelta::minutes(60))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        async move {
            sqlx::query("UPDATE tasks SET submitted_at = $1 WHERE id = $2")
                .bind(past)
                .bind(id)
                .execute(pool)
                .await
                .unwrap();
        }
    };

    // 1) 孤儿：pending + 0 构建 + 超宽限 → 应被清扫。
    let orphan = mk("orphan", "pending").await;
    backdate(orphan).await;
    // 2) 有构建的 pending（即使超期）→ 保留。
    let with_build = mk("ok", "pending").await;
    backdate(with_build).await;
    store
        .insert_build(crate::BuildInsert {
            product: "ule3",
            pkg_name: "ok",
            phase: "pending",
            backend: "chroot",
            user: "t",
            task_id: Some(with_build),
            ..Default::default()
        })
        .await
        .unwrap();
    // 3) 0 构建但在宽限期内（刚提交）→ 保留。
    let recent = mk("recent", "pending").await;
    // 4) 非 pending（succeeded）且 0 构建 → 保留。
    let done = mk("done", "succeeded").await;
    backdate(done).await;

    let swept = store.sweep_orphaned_tasks(5).await.unwrap();
    assert_eq!(swept, 1);

    let orphan_task = store.get_task(orphan).await.unwrap().unwrap();
    assert_eq!(orphan_task.phase, "failed");
    assert!(orphan_task.completed_at.is_some());
    assert_eq!(
        store.get_task(with_build).await.unwrap().unwrap().phase,
        "pending"
    );
    assert_eq!(
        store.get_task(recent).await.unwrap().unwrap().phase,
        "pending"
    );
    assert_eq!(
        store.get_task(done).await.unwrap().unwrap().phase,
        "succeeded"
    );
}

#[tokio::test]
async fn task_phase_aggregation_from_children() {
    let (store, _tmp) = create_test_store().await;

    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            user: "alice",
            user_id: None,
            phase: "pending",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();

    let build_x86 = store
        .insert_build(crate::BuildInsert {
            product: "fedora",
            pkg_name: "foo",
            backend: "chroot",
            user: "alice",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    let build_aarch64 = store
        .insert_build(crate::BuildInsert {
            product: "fedora",
            pkg_name: "foo",
            backend: "chroot",
            user: "alice",
            arch: Some("aarch64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    // 一个子构建进入 building，Task 变为 building
    store
        .update_build_phase(build_x86, "building")
        .await
        .unwrap();
    let task = store.get_task(task_id).await.unwrap().unwrap();
    assert_eq!(task.phase, "building");

    // 第一个子构建成功，任务仍保持 building
    store
        .complete_build(build_x86, "succeeded", None)
        .await
        .unwrap();
    let task = store.get_task(task_id).await.unwrap().unwrap();
    assert_eq!(task.phase, "building");

    // 第二个子构建失败，任务聚合为 failed 并记录完成时间
    store
        .complete_build(build_aarch64, "failed", None)
        .await
        .unwrap();
    let task = store.get_task(task_id).await.unwrap().unwrap();
    assert_eq!(task.phase, "failed");
    assert!(task.completed_at.is_some());
}

#[tokio::test]
async fn list_package_names_filters_by_product_and_user() {
    let (store, _tmp) = create_test_store().await;

    store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo-1.0-1",
            user: "alice",
            user_id: None,
            phase: "pending",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();

    store
        .insert_task(TaskInsert {
            product: "centos",
            pkg_name: "bar-2.0-1",
            user: "alice",
            user_id: None,
            phase: "pending",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();

    store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "baz-1.0-1",
            user: "bob",
            user_id: None,
            phase: "pending",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();

    // 无过滤：按字母序返回所有 name（total 与页数据一起返回）
    let (total, names) = store
        .list_package_names(None, None, None, None, None, 0)
        .await
        .unwrap();
    assert_eq!(names, vec!["bar", "baz", "foo"]);
    assert_eq!(total, 3);

    // 按 product 过滤
    let (_, names) = store
        .list_package_names(Some("fedora"), None, None, None, None, 0)
        .await
        .unwrap();
    assert_eq!(names, vec!["baz", "foo"]);

    // 按 user 过滤
    let (_, names) = store
        .list_package_names(None, Some("bob"), None, None, None, 0)
        .await
        .unwrap();
    assert_eq!(names, vec!["baz"]);

    // product + user 同时过滤
    let (_, names) = store
        .list_package_names(Some("fedora"), Some("bob"), None, None, None, 0)
        .await
        .unwrap();
    assert_eq!(names, vec!["baz"]);

    // 按 name 子串过滤（/ui/packages 的 Package 框）：含 "a" 的 bar/baz。
    let (total, names) = store
        .list_package_names(None, None, Some("a"), None, None, 0)
        .await
        .unwrap();
    assert_eq!(names, vec!["bar", "baz"]);
    assert_eq!(total, 2);
    // 子串而非前缀："az" 也命中 baz。
    let (_, names) = store
        .list_package_names(None, None, Some("az"), None, None, 0)
        .await
        .unwrap();
    assert_eq!(names, vec!["baz"]);
    // 空串与纯空白视为未过滤。
    let (total, _) = store
        .list_package_names(None, None, Some("  "), None, None, 0)
        .await
        .unwrap();
    assert_eq!(total, 3);
    // 与 product 过滤可叠加。
    let (_, names) = store
        .list_package_names(Some("centos"), None, Some("a"), None, None, 0)
        .await
        .unwrap();
    assert_eq!(names, vec!["bar"]);

    // 可见性白名单：只看 fedora（列表外的产品被排除）。注意孤儿豁免——
    // products 表无行的产品视为孤儿保持可见，先登记产品再测排除。
    sqlx::query(
        "INSERT INTO products (name, visibility, config_json) VALUES ('fedora', 'public', '{}')",
    )
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO products (name, visibility, config_json) VALUES ('centos', 'public', '{}')",
    )
    .execute(store.pool())
    .await
    .unwrap();
    let visible = vec!["fedora".to_string()];
    let (total, names) = store
        .list_package_names(None, None, None, Some(&visible), None, 0)
        .await
        .unwrap();
    assert_eq!(names, vec!["baz", "foo"]);
    assert_eq!(total, 2);

    // SQL 分页：limit=2 / offset=1。
    let (total, names) = store
        .list_package_names(None, None, None, None, Some(2), 1)
        .await
        .unwrap();
    assert_eq!(names, vec!["baz", "foo"]);
    assert_eq!(total, 3);
}

/// LIKE 通配符转义回归共用种子：四个基础名，lib% / lib_d 含通配符，
/// libx / libXd 是 % / _ 通配未转义时会误命中的对照组。
async fn seed_wildcard_named_tasks(store: &StateStore) {
    for pkg in ["lib%-1.0-1", "libx-1.0-1", "lib_d-1.0-1", "libXd-1.0-1"] {
        store
            .insert_task(TaskInsert {
                product: "fedora",
                pkg_name: pkg,
                user: "alice",
                user_id: None,
                phase: "pending",
                priority: 0,
                srpm_path: None,
                result_dir: None,
                ..Default::default()
            })
            .await
            .unwrap();
    }
}

/// /ui/packages 的 name 子串过滤（site：list_package_names）：搜 "lib%"
/// 只命中字面 lib%（未转义时 "%lib%%" 四个全中），搜 "lib_" 只命中 lib_d。
#[tokio::test]
async fn list_package_names_escapes_like_wildcards() {
    let (store, _tmp) = create_test_store().await;
    seed_wildcard_named_tasks(&store).await;

    let (_, names) = store
        .list_package_names(None, None, Some("lib%"), None, None, 0)
        .await
        .unwrap();
    assert_eq!(names, vec!["lib%"]);

    let (_, names) = store
        .list_package_names(None, None, Some("lib_"), None, None, 0)
        .await
        .unwrap();
    assert_eq!(names, vec!["lib_d"]);

    // 不含通配符的子串搜索行为不变（四个基础名都含 "lib"）。
    let (_, names) = store
        .list_package_names(None, None, Some("lib"), None, None, 0)
        .await
        .unwrap();
    assert_eq!(names.len(), 4);
}

/// packages 列表页 name 粒度分组（site：list_name_groups）：filter.name
/// 是 name 列子串匹配，% / _ 按字面匹配。
#[tokio::test]
async fn list_name_groups_escapes_like_wildcards() {
    let (store, _tmp) = create_test_store().await;
    seed_wildcard_named_tasks(&store).await;

    let (_, groups) = store
        .list_name_groups(&crate::state::NvrGroupFilter {
            name: Some("lib%"),
            ..Default::default()
        })
        .await
        .unwrap();
    let names: Vec<&str> = groups.iter().map(|g| g.pkg_name.as_str()).collect();
    assert_eq!(names, vec!["lib%"]);

    let (_, groups) = store
        .list_name_groups(&crate::state::NvrGroupFilter {
            name: Some("lib_"),
            ..Default::default()
        })
        .await
        .unwrap();
    let names: Vec<&str> = groups.iter().map(|g| g.pkg_name.as_str()).collect();
    assert_eq!(names, vec!["lib_d"]);
}

/// pkg_name 前缀匹配（site：push_common_filters，经 list_nvr_groups /
/// list_tasks / list_builds 共用）：搜 "lib%" 只匹配以字面 "lib%" 开头
/// 的 pkg_name（未转义时 "lib%%" 四个全中），搜 "lib_" 同理排除 libXd。
#[tokio::test]
async fn pkg_name_prefix_filter_escapes_like_wildcards() {
    let (store, _tmp) = create_test_store().await;
    seed_wildcard_named_tasks(&store).await;

    let (_, groups) = store
        .list_nvr_groups(&crate::state::NvrGroupFilter {
            name: Some("lib%"),
            ..Default::default()
        })
        .await
        .unwrap();
    let names: Vec<&str> = groups.iter().map(|g| g.pkg_name.as_str()).collect();
    assert_eq!(names, vec!["lib%-1.0-1"]);

    let (_, groups) = store
        .list_nvr_groups(&crate::state::NvrGroupFilter {
            name: Some("lib_"),
            ..Default::default()
        })
        .await
        .unwrap();
    let names: Vec<&str> = groups.iter().map(|g| g.pkg_name.as_str()).collect();
    assert_eq!(names, vec!["lib_d-1.0-1"]);
}

#[tokio::test]
async fn task_pkg_names_roundtrip_and_empty_on_absent() {
    let (store, _tmp) = create_test_store().await;

    // 写入全量 pkg_names。
    let id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo-1.0-1",
            user: "alice",
            request_json: Some("{}"),
            pkg_names: Some("[\"foo-1.0-1\",\"bar-2.0-1\"]"),
            ..Default::default()
        })
        .await
        .unwrap();
    let t = store.get_task(id).await.unwrap().unwrap();
    assert_eq!(t.pkg_names, vec!["foo-1.0-1", "bar-2.0-1"]);
    assert_eq!(t.pkg_label(), "foo-1.0-1 +1");

    // pkg_names 列为 NULL：不回退填充，返回空；展示回退到 pkg_name。
    let legacy = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "baz-3.0-1",
            user: "alice",
            user_id: None,
            phase: "pending",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();
    let t2 = store.get_task(legacy).await.unwrap().unwrap();
    assert!(t2.pkg_names.is_empty());
    assert_eq!(t2.pkg_label(), "baz-3.0-1");

    // 非法 JSON 同样返回空，不报错。
    sqlx::query("UPDATE tasks SET pkg_names = 'not-json' WHERE id = $1")
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
    let t3 = store.get_task(id).await.unwrap().unwrap();
    assert!(t3.pkg_names.is_empty());
}

#[tokio::test]
async fn task_rebuild_queries() {
    let (store, _tmp) = create_test_store().await;

    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            user: "alice",
            phase: "failed",
            priority: 1,
            result_dir: Some("/results/1"),
            request_json: Some("{\"stage\":\"bb\"}"),
            ..Default::default()
        })
        .await
        .unwrap();

    let info = store.get_task_rebuild_info(task_id).await.unwrap().unwrap();
    assert_eq!(info.product, "fedora");
    assert_eq!(info.user, "alice");
    assert_eq!(info.priority, 1);
    assert_eq!(info.result_dir.as_deref(), Some("/results/1"));
    assert_eq!(info.request_json.as_deref(), Some("{\"stage\":\"bb\"}"));

    assert!(store.get_task_arches(task_id).await.unwrap().is_empty());

    // 子构建写入后：arches 去重保序。
    for arch in ["x86_64", "aarch64", "x86_64"] {
        let build_id = store
            .insert_build(crate::BuildInsert {
                product: "fedora",
                pkg_name: "foo",
                phase: "failed",
                backend: "nspawn",
                user: "alice",
                priority: 1,
                arch: Some(arch),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .set_build_request_info(build_id, "/src/foo.src.rpm", "{\"arch\":\"x86_64\"}")
            .await
            .unwrap();
    }

    let arches = store.get_task_arches(task_id).await.unwrap();
    assert_eq!(arches, vec!["x86_64", "aarch64"]);
}

#[tokio::test]
async fn list_nvr_groups_aggregates_by_pkg_name() {
    let (store, _tmp) = create_test_store().await;

    let mk = |pkg: &'static str| {
        let store = &store;
        async move {
            store
                .insert_task(TaskInsert {
                    product: "mydist",
                    pkg_name: pkg,
                    user: "chao",
                    phase: "failed",
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };

    // 两次同 NVR 尝试 + 一次不同 NVR。
    let _first = mk("openssh-8.7p1-4.el9").await;
    let _other = mk("openssh-8.7p1-3.el9").await;
    let latest = mk("openssh-8.7p1-4.el9").await;

    let (total, groups) = store
        .list_nvr_groups(&crate::state::NvrGroupFilter::default())
        .await
        .unwrap();

    // 两个分组；按 latest_id DESC，最新一次尝试（openssh-…-4.el9）在前。
    assert_eq!(total, 2);
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].pkg_name, "openssh-8.7p1-4.el9");
    assert_eq!(groups[0].attempts, 2);
    assert_eq!(groups[0].latest_task_id, latest);
    assert_eq!(groups[0].product, "mydist");
    assert_eq!(groups[0].user, "chao");
    assert_eq!(groups[1].pkg_name, "openssh-8.7p1-3.el9");
    assert_eq!(groups[1].attempts, 1);
}

#[tokio::test]
async fn list_tasks_nvr_filter_matches_exact_pkg_name_only() {
    let (store, _tmp) = create_test_store().await;

    let mk = |pkg: &'static str| {
        let store = &store;
        async move {
            store
                .insert_task(TaskInsert {
                    product: "mydist",
                    pkg_name: pkg,
                    user: "chao",
                    phase: "failed",
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };

    mk("openssh-8.7p1-4.el9").await;
    mk("openssh-8.7p1-4.el9").await;
    mk("openssh-8.7p1-3.el9").await;
    // 前缀相同但更长：精确匹配必须排除（证明不是 LIKE 前缀）。
    mk("openssh-8.7p1-4.el9x").await;

    let (total, tasks) = store
        .list_tasks(&crate::types::TaskListFilter {
            nvr: Some("openssh-8.7p1-4.el9"),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(total, 2);
    assert_eq!(tasks.len(), 2);
    assert!(tasks.iter().all(|t| t.pkg_name == "openssh-8.7p1-4.el9"));
}

/// total 是过滤后总数（不是当前页长度）；空页（offset 越界）窗口函数
/// 无行，靠独立 COUNT 兜底保住 total。
#[tokio::test]
async fn list_tasks_visible_products_total_survives_pagination() {
    use crate::config::ProductConfig;
    use crate::state::products::CreateProductInput;

    let (store, _tmp) = create_test_store().await;

    let _ = store
        .create_product(CreateProductInput {
            name: "ule3",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: crate::VISIBILITY_PUBLIC,
            config: &ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();
    let owner_id = store.create_user("owner", "builder").await.unwrap();
    let _ = store
        .create_product(CreateProductInput {
            name: "secret",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: crate::VISIBILITY_PRIVATE,
            config: &ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();

    let mk = |pkg: &'static str, product: &'static str| {
        let store = &store;
        async move {
            store
                .insert_task(TaskInsert {
                    product,
                    pkg_name: pkg,
                    user: "chao",
                    phase: "succeeded",
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };
    mk("a-1.0-1", "ule3").await;
    mk("b-1.0-1", "ule3").await;
    mk("c-1.0-1", "secret").await; // 不可见
    mk("d-1.0-1", "deleted-product").await; // 孤儿豁免：可见

    let visible = vec!["ule3".to_string()];
    let (total, page1) = store
        .list_tasks(&crate::types::TaskListFilter {
            visible_products: Some(visible.clone()),
            limit: Some(2),
            offset: Some(0),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 3, "ule3 x2 + orphan; secret hidden");
    assert_eq!(page1.len(), 2);
    assert!(page1.iter().all(|t| t.product != "secret"));

    let (total, page2) = store
        .list_tasks(&crate::types::TaskListFilter {
            visible_products: Some(visible.clone()),
            limit: Some(2),
            offset: Some(2),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 3);
    assert_eq!(page2.len(), 1);

    // offset 越界的空页：窗口函数无行可取，COUNT 兜底必须仍返回真实 total。
    let (total, empty) = store
        .list_tasks(&crate::types::TaskListFilter {
            visible_products: Some(visible),
            limit: Some(2),
            offset: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 3, "empty page must keep the real total");
    assert!(empty.is_empty());
}

#[tokio::test]
async fn list_nvr_groups_paginates_group_count() {
    let (store, _tmp) = create_test_store().await;

    for pkg in ["pkgA-1.0-1", "pkgB-1.0-1", "pkgC-1.0-1"] {
        store
            .insert_task(TaskInsert {
                product: "mydist",
                pkg_name: pkg,
                user: "chao",
                phase: "failed",
                ..Default::default()
            })
            .await
            .unwrap();
    }

    // 第 1 页：limit 2 → 2 组，total 反映全部 3 组。
    let (total, page1) = store
        .list_nvr_groups(&crate::state::NvrGroupFilter {
            limit: Some(2),
            offset: Some(0),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 3);
    assert_eq!(page1.len(), 2);

    // 第 2 页：offset 2 → 剩 1 组。
    let (total, page2) = store
        .list_nvr_groups(&crate::state::NvrGroupFilter {
            limit: Some(2),
            offset: Some(2),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 3);
    assert_eq!(page2.len(), 1);
}

/// 基础过滤：visible_products = ["ule3"] 时，private 产品上的 attempt
/// 不计入 `attempts` / `latest_task_id`。
#[tokio::test]
async fn list_nvr_groups_filters_by_visible_products() {
    use crate::config::ProductConfig;
    use crate::state::products::CreateProductInput;

    let (store, _tmp) = create_test_store().await;

    // 私人产品需要 owner_id，先 seed 一个用户。
    let owner_id = store.create_user("owner", "builder").await.unwrap();
    let _ = store
        .create_product(CreateProductInput {
            name: "secret",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: crate::VISIBILITY_PRIVATE,
            config: &ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();

    let mk = |pkg: &'static str, product: &'static str| {
        let store = &store;
        async move {
            store
                .insert_task(TaskInsert {
                    product,
                    pkg_name: pkg,
                    user: "chao",
                    phase: "succeeded",
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };

    // 2 次 ule3 + 1 次 secret（id 最大，模拟 latest 落在 private）
    let _a = mk("tmux-3.2a-3.oe2203sp4", "ule3").await;
    let _b = mk("tmux-3.2a-3.oe2203sp4", "ule3").await;
    let latest_private = mk("tmux-3.2a-3.oe2203sp4", "secret").await;

    let (total, groups) = store
        .list_nvr_groups(&crate::state::NvrGroupFilter {
            visible_products: Some(vec!["ule3".to_string()]),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(total, 1);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].attempts, 2);
    assert_ne!(groups[0].latest_task_id, latest_private);
    assert_eq!(groups[0].product, "ule3");
}

/// 孤儿豁免：已删产品的 attempts 必须仍对所有人可见。
/// 锁：`list_products` 不返回已删产品 → 孤儿名永远进不了 `visible_products`，
/// SQL 必须靠 `OR product NOT IN (SELECT name FROM products)` 单独兜底。
#[tokio::test]
async fn list_nvr_groups_orphan_product_attempts_remain_visible() {
    let (store, _tmp) = create_test_store().await;

    // 插入 attempt 但不在 products 表里创建（孤儿）
    let orphan_attempt = store
        .insert_task(TaskInsert {
            product: "deleted-product",
            pkg_name: "tmux-3.2a",
            user: "chao",
            phase: "succeeded",
            ..Default::default()
        })
        .await
        .unwrap();

    // visible_products = ["ule3"]（不含 deleted-product）：孤儿仍须可见。
    let (total, groups) = store
        .list_nvr_groups(&crate::state::NvrGroupFilter {
            name: Some("tmux"),
            visible_products: Some(vec!["ule3".to_string()]),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(total, 1, "orphan product attempts must remain visible");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].attempts, 1);
    assert_eq!(groups[0].latest_task_id, orphan_attempt);
    assert_eq!(groups[0].product, "deleted-product");
}

/// 空白名单：现存产品全部不可见，仅孤儿（products 表无行）豁免可见，
/// `Some(empty)` 只拼孤儿豁免子句。锁实现对空列表不得短路跳过子句
///（会语义反转成看到一切）；seed ule3（public）/ secret（private）两个
/// 现存产品与products 表无行的孤儿 attempt 构成场景。
#[tokio::test]
async fn list_nvr_groups_empty_visible_products_hides_everything() {
    use crate::config::ProductConfig;
    use crate::state::products::CreateProductInput;

    let (store, _tmp) = create_test_store().await;

    // seed ule3 为 public 产品；直接传 Some(vec![]) 绕过
    // compute_visible_products，模拟 anon 空名单视角。
    let _ = store
        .create_product(CreateProductInput {
            name: "ule3",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: crate::VISIBILITY_PUBLIC,
            config: &ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();
    // secret 为 private + owner：现存产品，对 anon 不可见。
    let owner_id = store.create_user("owner", "builder").await.unwrap();
    let _ = store
        .create_product(CreateProductInput {
            name: "secret",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: crate::VISIBILITY_PRIVATE,
            config: &ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();

    // ule3 / secret 各一条 attempt（空名单下不可见）+
    // 已删产品 deleted-product 上一条（孤儿豁免，可见）
    store
        .insert_task(TaskInsert {
            product: "ule3",
            pkg_name: "tmux-3.2a",
            user: "chao",
            phase: "succeeded",
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .insert_task(TaskInsert {
            product: "secret",
            pkg_name: "openssh-9.0-1",
            user: "chao",
            phase: "succeeded",
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .insert_task(TaskInsert {
            product: "deleted-product", // 不在 products 表
            pkg_name: "orphan-pkg-1.0",
            user: "chao",
            phase: "succeeded",
            ..Default::default()
        })
        .await
        .unwrap();

    let (total, groups) = store
        .list_nvr_groups(&crate::state::NvrGroupFilter {
            visible_products: Some(vec![]),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(
        total, 1,
        "empty visible_products: only orphans without a products row should be visible, got groups: {groups:?}"
    );
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].pkg_name, "orphan-pkg-1.0");
}

/// name 粒度分组：同一基础名的多个 NVR 归并一组；attempts 是组内 task
/// 总数（跨 NVR 求和），latest_* 取组内 MAX(id) 那一行。
#[tokio::test]
async fn list_name_groups_aggregates_by_base_name() {
    let (store, _tmp) = create_test_store().await;

    let mk = |pkg: &'static str, phase: &'static str| {
        let store = &store;
        async move {
            store
                .insert_task(TaskInsert {
                    product: "mydist",
                    pkg_name: pkg,
                    user: "chao",
                    phase,
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };

    // tmux 三个 NVR 共 4 次尝试（两次重试同 NVR）+ vim 1 次；
    // 组内最新一次（最后插入的 tmux）是 succeeded。
    let _a = mk("tmux-3.2a-3.oe2203sp4", "failed").await;
    let _b = mk("tmux-3.2a-2.oe2203sp4", "failed").await;
    let _c = mk("tmux-3.2a-3.oe2203sp4", "failed").await;
    let vim_latest = mk("vim-9.0-1.oe2203sp4", "succeeded").await;
    let tmux_latest = mk("tmux-3.2a-4.oe2203sp4", "succeeded").await;

    let (total, groups) = store
        .list_name_groups(&crate::state::NvrGroupFilter::default())
        .await
        .unwrap();

    // 两个分组（tmux / vim）；按 latest_id DESC，tmux（最新 task）在前。
    assert_eq!(total, 2);
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].pkg_name, "tmux");
    assert_eq!(groups[0].attempts, 4, "attempts 是组内全部 task 数");
    assert_eq!(groups[0].latest_task_id, tmux_latest);
    assert_eq!(groups[0].phase, "succeeded", "phase 取组内最新一次");
    assert_eq!(groups[0].product, "mydist");
    assert_eq!(groups[0].user, "chao");
    assert!(groups[0].submitted_at.is_some());
    assert_eq!(groups[1].pkg_name, "vim");
    assert_eq!(groups[1].attempts, 1);
    assert_eq!(groups[1].latest_task_id, vim_latest);
}

/// name 过滤是子串语义（`name LIKE '%q%'`，同 /ui/packages 列表页
/// Package 框 / list_package_names）：中缀也要命中，空串视为未过滤。
#[tokio::test]
async fn list_name_groups_filters_by_name_substring() {
    let (store, _tmp) = create_test_store().await;

    let mk = |pkg: &'static str| {
        let store = &store;
        async move {
            store
                .insert_task(TaskInsert {
                    product: "mydist",
                    pkg_name: pkg,
                    user: "chao",
                    phase: "failed",
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };

    mk("tmux-3.2a-3.oe2203sp4").await;
    mk("emacs-28.2-1").await;
    mk("emacs-28.1-1").await;

    // "mux" 是 tmux 的中缀（证明不是前缀匹配）。
    let (total, groups) = store
        .list_name_groups(&crate::state::NvrGroupFilter {
            name: Some("mux"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].pkg_name, "tmux");

    // "macs" 命中 emacs，且过滤发生在归并后的组上（两个 NVR 一组）。
    let (total, groups) = store
        .list_name_groups(&crate::state::NvrGroupFilter {
            name: Some("macs"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(groups[0].pkg_name, "emacs");
    assert_eq!(groups[0].attempts, 2);

    // 空串与纯空白视为未过滤（filter_form 未填字段以空串回传）。
    let (total, _) = store
        .list_name_groups(&crate::state::NvrGroupFilter {
            name: Some("  "),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 2);
}

#[tokio::test]
async fn list_name_groups_paginates_group_count() {
    let (store, _tmp) = create_test_store().await;

    // 3 个基础名 4 条 task（pkgA 两个 NVR）。
    for pkg in ["pkgA-1.0-1", "pkgA-2.0-1", "pkgB-1.0-1", "pkgC-1.0-1"] {
        store
            .insert_task(TaskInsert {
                product: "mydist",
                pkg_name: pkg,
                user: "chao",
                phase: "failed",
                ..Default::default()
            })
            .await
            .unwrap();
    }

    // 第 1 页：limit 2 → 2 组，total 反映全部 3 组。
    let (total, page1) = store
        .list_name_groups(&crate::state::NvrGroupFilter {
            limit: Some(2),
            offset: Some(0),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 3);
    assert_eq!(page1.len(), 2);

    // 第 2 页：offset 2 → 剩 1 组。
    let (total, page2) = store
        .list_name_groups(&crate::state::NvrGroupFilter {
            limit: Some(2),
            offset: Some(2),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 3);
    assert_eq!(page2.len(), 1);

    // 排序 latest_id DESC：第 1 页是最新两组（pkgC/pkgB），pkgA（组内
    // 最新 task 是第 2 条）落在第 2 页；total 是组数不是行数，pkgA 的
    // 两次尝试归并后 attempts=2。
    assert!(page1
        .iter()
        .all(|g| g.pkg_name != "pkgA" && g.attempts == 1));
    assert_eq!(page2[0].pkg_name, "pkgA");
    assert_eq!(page2[0].attempts, 2);
}

/// 可见性白名单（与 list_nvr_groups_filters_by_visible_products 同款
/// 场景）：private 产品上的 attempt 不计入 attempts / latest。
#[tokio::test]
async fn list_name_groups_filters_by_visible_products() {
    use crate::config::ProductConfig;
    use crate::state::products::CreateProductInput;

    let (store, _tmp) = create_test_store().await;

    // 私人产品需要 owner_id，先 seed 一个用户。
    let owner_id = store.create_user("owner", "builder").await.unwrap();
    let _ = store
        .create_product(CreateProductInput {
            name: "secret",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: crate::VISIBILITY_PRIVATE,
            config: &ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();

    let mk = |pkg: &'static str, product: &'static str| {
        let store = &store;
        async move {
            store
                .insert_task(TaskInsert {
                    product,
                    pkg_name: pkg,
                    user: "chao",
                    phase: "succeeded",
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };

    // 2 次 ule3 + 1 次 secret（id 最大，模拟 latest 落在 private）
    let _a = mk("tmux-3.2a-3.oe2203sp4", "ule3").await;
    let _b = mk("tmux-3.2a-4.oe2203sp4", "ule3").await;
    let latest_private = mk("tmux-3.2a-5.oe2203sp4", "secret").await;

    let (total, groups) = store
        .list_name_groups(&crate::state::NvrGroupFilter {
            visible_products: Some(vec!["ule3".to_string()]),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(total, 1);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].pkg_name, "tmux");
    assert_eq!(groups[0].attempts, 2);
    assert_ne!(groups[0].latest_task_id, latest_private);
    assert_eq!(groups[0].product, "ule3");
}

#[tokio::test]
async fn insert_task_resolves_official_product_id_inline() {
    use crate::config::ProductConfig;
    use crate::state::products::CreateProductInput;

    let (store, _tmp) = create_test_store().await;

    // create_test_store 并不 seed 产品（产品 seed 走 seed_products_from_dir），
    // 这里显式创建官方产品 fedora（owner_id = None）以覆盖解析路径。
    let _ = store
        .create_product(CreateProductInput {
            name: "fedora",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: crate::VISIBILITY_PUBLIC,
            config: &ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();

    let id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "hello-1.0-1.fc42",
            user: "alice",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();
    let product_id: Option<i64> = sqlx::query_scalar("SELECT product_id FROM tasks WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert!(product_id.is_some());

    // 官方产品不存在：product_id 落 NULL，不报错。
    let id2 = store
        .insert_task(TaskInsert {
            product: "no-such-product",
            pkg_name: "hello-1.0-1.fc42",
            user: "alice",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();
    let product_id2: Option<i64> = sqlx::query_scalar("SELECT product_id FROM tasks WHERE id = $1")
        .bind(id2)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert!(product_id2.is_none());
}

#[tokio::test]
async fn reconcile_repairs_task_stuck_with_terminal_builds() {
    let (store, _tmp) = create_test_store().await;

    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "hello-1.0-1.fc42",
            user: "alice",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();
    for arch in ["x86_64", "aarch64"] {
        store
            .insert_build(crate::state::BuildInsert {
                product: "fedora",
                pkg_name: "hello-1.0-1.fc42",
                phase: "pending",
                backend: "chroot",
                user: "alice",
                arch: Some(arch),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    // 模拟崩溃窗口：builds 全部终态，但聚合从未发生（task 卡 building）
    sqlx::query("UPDATE builds SET phase = 'succeeded' WHERE task_id = $1")
        .bind(task_id)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE tasks SET phase = 'building' WHERE id = $1")
        .bind(task_id)
        .execute(store.pool())
        .await
        .unwrap();

    let repaired = store.reconcile_stale_task_phases().await.unwrap();
    assert_eq!(repaired, 1);
    let task = store.get_task(task_id).await.unwrap().unwrap();
    assert_eq!(task.phase, "succeeded");
    assert!(task.completed_at.is_some());
}

#[tokio::test]
async fn reconcile_skips_active_children_and_terminal_tasks() {
    let (store, _tmp) = create_test_store().await;

    // task A：仍有 pending 子构建 → 不动
    let task_a = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "a-1.0-1.fc42",
            user: "alice",
            phase: "building",
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .insert_build(crate::state::BuildInsert {
            product: "fedora",
            pkg_name: "a-1.0-1.fc42",
            phase: "pending",
            backend: "chroot",
            user: "alice",
            arch: Some("x86_64"),
            task_id: Some(task_a),
            ..Default::default()
        })
        .await
        .unwrap();

    // task B：已终态 + 子构建全终态 → 不回退、不重复计数
    let task_b = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "b-1.0-1.fc42",
            user: "alice",
            phase: "succeeded",
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .insert_build(crate::state::BuildInsert {
            product: "fedora",
            pkg_name: "b-1.0-1.fc42",
            phase: "succeeded",
            backend: "chroot",
            user: "alice",
            arch: Some("x86_64"),
            task_id: Some(task_b),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(store.reconcile_stale_task_phases().await.unwrap(), 0);
    assert_eq!(
        store.get_task(task_a).await.unwrap().unwrap().phase,
        "building"
    );
    assert_eq!(
        store.get_task(task_b).await.unwrap().unwrap().phase,
        "succeeded"
    );
}

/// get_child_build_summaries 的 duration 回填：活跃子构建为 None，
/// complete_build 之后为 Some（值本身随执行时长，只断言非空）。
#[tokio::test]
async fn get_child_build_summaries_includes_duration() {
    let (store, _tmp) = create_test_store().await;
    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            user: "alice",
            user_id: None,
            phase: "building",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();
    let build_id = store
        .insert_build(crate::BuildInsert {
            product: "fedora",
            pkg_name: "foo",
            phase: "building",
            backend: "chroot",
            user: "alice",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let summaries = store.get_child_build_summaries(task_id).await.unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].phase, "building");
    assert_eq!(summaries[0].duration, None);

    store
        .complete_build(build_id, "succeeded", None)
        .await
        .unwrap();
    let summaries = store.get_child_build_summaries(task_id).await.unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].phase, "succeeded");
    assert!(summaries[0].duration.is_some());
}

/// 回归：arch=NULL 的 build 行不得让 get_child_build_summaries panic——
/// 列定义 `arch TEXT DEFAULT ''` 可空，engine 本地构建（lifecycle 不带
/// arch）与历史 fixture INSERT 均产生 NULL 行；解码侧按仓库 "无 arch"
/// 惯例回落空串（COALESCE(arch,'') 同口径）。
#[tokio::test]
async fn get_child_build_summaries_tolerates_null_arch() {
    let (store, _tmp) = create_test_store().await;
    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "foo",
            user: "alice",
            user_id: None,
            phase: "building",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();
    // arch: None → SQL NULL（本回归的触发行）
    store
        .insert_build(crate::BuildInsert {
            product: "fedora",
            pkg_name: "foo",
            phase: "building",
            backend: "chroot",
            user: "alice",
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let summaries = store.get_child_build_summaries(task_id).await.unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(
        summaries[0].arch, "",
        "NULL arch must decode as empty string"
    );
    assert_eq!(summaries[0].phase, "building");
}

/// 批量产品活动聚合：total 与 list_tasks 逐产品对账；last_task_at 取
/// MAX(COALESCE(completed_at, submitted_at))（completed_at 优先、进行中回退
/// submitted_at）；无任务产品不出现；空入参不发 SQL 直接返回空 map。
#[tokio::test]
async fn product_activity_for_products_reconciles_with_list_tasks() {
    let (store, _tmp) = create_test_store().await;

    // 显式落时间：insert_task 默认 submitted_at=now，不便断言 MAX 语义。
    async fn seed(
        store: &StateStore,
        product: &str,
        pkg: &str,
        phase: &str,
        submitted: &str,
        completed: Option<&str>,
    ) {
        let id = store
            .insert_task(TaskInsert {
                product,
                pkg_name: pkg,
                user: "alice",
                phase,
                ..Default::default()
            })
            .await
            .unwrap();
        sqlx::query("UPDATE tasks SET submitted_at = $1, completed_at = $2 WHERE id = $3")
            .bind(submitted)
            .bind(completed)
            .bind(id)
            .execute(&store.pool)
            .await
            .unwrap();
    }

    // alpha：终态任务里最新 completed_at（08-25）必须赢过更早的 completed
    // （08-20）与更早的 pending submitted（08-21）。
    seed(
        &store,
        "alpha",
        "a-1.0-1",
        "succeeded",
        "2026-08-20 09:00:00",
        Some("2026-08-20 10:00:00"),
    )
    .await;
    seed(
        &store,
        "alpha",
        "a-1.0-2",
        "succeeded",
        "2026-08-25 12:00:00",
        Some("2026-08-25 12:30:00"),
    )
    .await;
    seed(
        &store,
        "alpha",
        "a-2.0-1",
        "pending",
        "2026-08-21 09:00:00",
        None,
    )
    .await;
    // beta：仅一条进行中任务 → last 回退 submitted_at。
    seed(
        &store,
        "beta",
        "b-1.0-1",
        "building",
        "2026-08-26 08:00:00",
        None,
    )
    .await;
    // gamma：零任务。

    let products: Vec<String> = ["alpha", "beta", "gamma"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let activity = store
        .product_activity_for_products(&products)
        .await
        .unwrap();

    let alpha = activity.get("alpha").expect("alpha present");
    assert_eq!(alpha.total_tasks, 3);
    assert_eq!(
        alpha.last_task_at.as_deref(),
        Some("2026-08-25 12:30:00"),
        "MAX must pick the latest completed_at across alpha's tasks"
    );
    let beta = activity.get("beta").expect("beta present");
    assert_eq!(beta.total_tasks, 1);
    assert_eq!(
        beta.last_task_at.as_deref(),
        Some("2026-08-26 08:00:00"),
        "in-flight task falls back to submitted_at"
    );
    assert!(
        !activity.contains_key("gamma"),
        "zero-task product must be absent (caller defaults to 0/—)"
    );

    // total 与 list_tasks 逐产品对账。
    for (product, expected_total) in [("alpha", 3usize), ("beta", 1usize), ("gamma", 0usize)] {
        let (total, _) = store
            .list_tasks(&crate::types::TaskListFilter {
                product: Some(product),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(total, expected_total, "{product} list_tasks total");
        let batch = activity
            .get(product)
            .map(|a| a.total_tasks as usize)
            .unwrap_or(0);
        assert_eq!(batch, expected_total, "{product} batch total");
    }

    // 空入参：直接空 map，不产生 SQL（列表页空页路径）。
    assert!(store
        .product_activity_for_products(&[])
        .await
        .unwrap()
        .is_empty());
}

/// list_tasks 排序显式臂（UI 排序下拉直接喂这些值，见 build_task_order_by）：
/// `submitted_desc` 按 (submitted_at DESC, id DESC) 双键；`id_asc` 升序；
/// 未知值宽松回落 id DESC——UI 表单的 id_desc 也走该臂，收紧为 400 前必须
/// 先补显式臂。
#[tokio::test]
async fn list_tasks_order_by_arms_covered() {
    let (store, _tmp) = create_test_store().await;

    // 乱序 seed：A(01-02) B(01-03) C(01-02)——C 与 A 同时刻，二级序落在 id。
    let mut ids = Vec::new();
    for (pkg, submitted) in [
        ("a-1.0-1", "2026-01-02 09:00:00"),
        ("b-1.0-1", "2026-01-03 09:00:00"),
        ("c-1.0-1", "2026-01-02 09:00:00"),
    ] {
        let id = store
            .insert_task(TaskInsert {
                product: "fedora",
                pkg_name: pkg,
                user: "alice",
                phase: "succeeded",
                ..Default::default()
            })
            .await
            .unwrap();
        // 显式落 submitted_at（UTC 墙钟 TEXT，与生产比较帧同帧）。
        sqlx::query("UPDATE tasks SET submitted_at = $1 WHERE id = $2")
            .bind(submitted)
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap();
        ids.push(id);
    }

    let order = |order_by: &'static str| {
        let store = &store;
        async move {
            let (_, rows) = store
                .list_tasks(&crate::types::TaskListFilter {
                    order_by: Some(order_by),
                    ..Default::default()
                })
                .await
                .unwrap();
            rows.into_iter().map(|t| t.id).collect::<Vec<_>>()
        }
    };

    let cases: &[(&str, Vec<i64>)] = &[
        // 时间倒序；同时刻（A/C）按 id 倒序（二级序）。
        ("submitted_desc", vec![ids[1], ids[2], ids[0]]),
        // 升序。
        ("id_asc", ids.clone()),
        // 未知值宽松回落 id DESC。
        ("definitely-not-a-sort", vec![ids[2], ids[1], ids[0]]),
    ];
    for (order_by, expected) in cases {
        assert_eq!(&order(order_by).await, expected, "order_by={order_by}");
    }
}

/// 任务标签：与任务行同事务落库，按键排序回读；标签过滤精确命中
/// (key, value) 且不跨任务串值。
#[tokio::test]
async fn create_task_with_labels_persists_and_filters() {
    let (store, _tmp) = create_test_store().await;
    let id = store
        .create_task_with_labels(
            TaskInsert {
                product: "fedora",
                pkg_name: "with-labels",
                user: "alice",
                phase: "succeeded",
                ..Default::default()
            },
            &[
                (
                    "git-repo".to_string(),
                    "https://example.com/r.git".to_string(),
                ),
                ("git-commit".to_string(), "aaa111".to_string()),
            ],
        )
        .await
        .unwrap();
    let other = store
        .create_task_with_labels(
            TaskInsert {
                product: "fedora",
                pkg_name: "other-labels",
                user: "alice",
                phase: "succeeded",
                ..Default::default()
            },
            &[("git-commit".to_string(), "bbb222".to_string())],
        )
        .await
        .unwrap();

    assert_eq!(
        store.get_task_labels(id).await.unwrap(),
        vec![
            ("git-commit".to_string(), "aaa111".to_string()),
            (
                "git-repo".to_string(),
                "https://example.com/r.git".to_string()
            ),
        ],
        "labels must read back ordered by key"
    );

    let (total, rows) = store
        .list_tasks(&crate::types::TaskListFilter {
            label: Some(("git-commit".to_string(), "aaa111".to_string())),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(rows[0].id, id);
    assert_ne!(rows[0].id, other);

    let (total, _) = store
        .list_tasks(&crate::types::TaskListFilter {
            label: Some(("git-commit".to_string(), "nope".to_string())),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 0);
}

/// 标签组校验在事务前拒重复键：不留孤儿任务行。
#[tokio::test]
async fn create_task_with_duplicate_label_key_leaves_no_task_row() {
    let (store, _tmp) = create_test_store().await;
    let err = store
        .create_task_with_labels(
            TaskInsert {
                product: "fedora",
                pkg_name: "dup-label",
                user: "alice",
                ..Default::default()
            },
            &[
                ("git-commit".to_string(), "aaa".to_string()),
                ("git-commit".to_string(), "bbb".to_string()),
            ],
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("duplicate task label key"));
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks WHERE pkg_name = 'dup-label'")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(n, 0, "validation must run before the task insert");
}

/// 任务删除级联清理标签（FK ON DELETE CASCADE）。
#[tokio::test]
async fn delete_task_cascades_labels() {
    let (store, _tmp) = create_test_store().await;
    let id = store
        .create_task_with_labels(
            TaskInsert {
                product: "fedora",
                pkg_name: "cascade-labels",
                user: "alice",
                ..Default::default()
            },
            &[("alias".to_string(), "nightly".to_string())],
        )
        .await
        .unwrap();
    assert_eq!(store.get_task_labels(id).await.unwrap().len(), 1);

    sqlx::query("DELETE FROM tasks WHERE id = $1")
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
    assert!(store.get_task_labels(id).await.unwrap().is_empty());
}
