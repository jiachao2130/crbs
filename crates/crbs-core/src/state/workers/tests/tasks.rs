// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 任务计数、终态与生命周期查询。

use super::common::*;
use super::*;

/// count_active_tasks_by_worker 单条聚合各 worker 活跃数，
/// 终态 task 不计入；无活跃任务的 worker 不出现在 map 中。
#[tokio::test]
async fn test_count_active_tasks_by_worker_groups_by_worker() {
    let (store, _tmp) = create_test_store().await;

    let w1 = store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    let w2 = store
        .upsert_worker("w2", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    let mut ids = Vec::new();
    for pkg in ["a", "b", "c"] {
        ids.push(
            seed_build(
                &store,
                "mydist",
                pkg,
                "pending",
                "x86_64",
                PRIORITY_DEFAULT,
                crate::state::test_state::seed_task(&store, "mydist", pkg).await,
            )
            .await,
        );
    }
    store.assign_build_to_worker(ids[0], w1).await.unwrap();
    store.assign_build_to_worker(ids[1], w1).await.unwrap();
    store.assign_build_to_worker(ids[2], w2).await.unwrap();

    let counts = store.count_active_tasks_by_worker().await.unwrap();
    assert_eq!(counts.get(&w1), Some(&2), "w1: {counts:?}");
    assert_eq!(counts.get(&w2), Some(&1), "w2: {counts:?}");

    let assignment: i64 =
        sqlx::query_scalar("SELECT id FROM worker_tasks WHERE build_id = $1 AND worker_id = $2")
            .bind(ids[0])
            .bind(w1)
            .fetch_one(store.pool())
            .await
            .unwrap();
    store
        .update_worker_task_status(assignment, "completed")
        .await
        .unwrap();

    let counts = store.count_active_tasks_by_worker().await.unwrap();
    assert_eq!(counts.get(&w1), Some(&1), "w1: {counts:?}");
    assert_eq!(counts.get(&w2), Some(&1), "w2: {counts:?}");
    assert_eq!(counts.len(), 2, "workers without active tasks are absent");
}

/// `list_worker_active_build_pkgs` 爬坡窗口谓词：started_at NULL（已派未起跑）
/// 与窗口内起跑的行供给；窗口外起跑的行不再算在跑压载（load1 已承载）。
#[tokio::test]
async fn list_worker_active_build_pkgs_respects_ramp_window() {
    let (store, _tmp) = create_test_store().await;
    let w1 = store
        .upsert_worker("w1", "x86_64", 4, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    // 同产品多种子错开 arch（活跃去重）。
    let fresh = seed_building(&store, w1, "mydist", "x86_64").await;
    let stale = seed_building(&store, w1, "mydist", "aarch64").await;
    let unstarted = seed_building(&store, w1, "mydist", "riscv64").await;
    let ramp_secs = 90;
    sqlx::query(&format!(
        "UPDATE builds SET started_at = {} WHERE id = $1",
        sql_time_offset(store.dialect(), "-30 seconds")
    ))
    .bind(fresh)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(&format!(
        "UPDATE builds SET started_at = {} WHERE id = $1",
        sql_time_offset(store.dialect(), "-900 seconds")
    ))
    .bind(stale)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query("UPDATE builds SET started_at = NULL WHERE id = $1")
        .bind(unstarted)
        .execute(store.pool())
        .await
        .unwrap();

    let rows = store
        .list_worker_active_build_pkgs(ramp_secs)
        .await
        .unwrap();
    // 行首元是 worker_id 非 build id：按 arch 辨认三条种子（x86_64 = 窗口内、
    // aarch64 = 窗口外、riscv64 = NULL 未起跑）。
    let mut arches: Vec<&str> = rows
        .iter()
        .map(|(.., arch)| arch.as_deref().unwrap_or(""))
        .collect();
    arches.sort_unstable();
    assert_eq!(
        arches,
        vec!["riscv64", "x86_64"],
        "unstarted (NULL) and in-window rows supply Σ; stale started rows do not: {rows:?}"
    );
}

/// `list_worker_active_builds`：`count_worker_active_tasks` 的列表等价物——
/// 只列活跃（assigned/running）的 build 分配，排除终态 build 分配与 init 任务，
/// 行数与 count 的 build 部分（kind='build'）一致。
#[tokio::test]
async fn test_list_worker_active_builds_lists_active_builds_only() {
    let (store, _tmp) = create_test_store().await;

    let w1 = store
        .upsert_worker("w1", "x86_64", 4, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    let w2 = store
        .upsert_worker("w2", "x86_64", 4, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    // 同产品多种子须错开 arch（活跃去重按 product+pkg+arch 全局判、不按 worker；下同）。
    let live_a = seed_building(&store, w1, "mydist", "x86_64").await;
    let live_b = seed_building(&store, w1, "mydist", "aarch64").await;
    let done = seed_building(&store, w1, "mydist", "x86").await;
    // 终态迁移要同时写 build.phase 与 worker_tasks.status（否则 init gate 仍按
    // building 计数，拒绝为同产品派发 init）。
    sqlx::query("UPDATE builds SET phase = 'succeeded' WHERE id = $1")
        .bind(done)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE worker_tasks SET status = 'completed' WHERE build_id = $1")
        .bind(done)
        .execute(store.pool())
        .await
        .unwrap();
    // w2：一条活跃。
    seed_building(&store, w2, "mydist", "i686").await;
    // 活跃 init（kind='init'，无 build 行，不得出现在列表中；产品用 fedora——
    // mydist 仍有 building build，init gate 会拒绝）。
    store
        .try_assign_init_to_worker(w1, "fedora")
        .await
        .unwrap()
        .expect("init assignment should be created");

    let rows = store.list_worker_active_builds(w1).await.unwrap();
    let mut ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
    ids.sort();
    assert_eq!(ids, vec![live_a, live_b], "rows: {rows:?}");
    // 行内容：package / phase / started（COALESCE 回退 assigned_at，非 NULL）。
    let row = rows.iter().find(|r| r.id == live_a).unwrap();
    assert_eq!(row.pkg_name, "pkg");
    assert_eq!(row.phase, "building");
    assert!(
        row.started_at.as_deref().is_some_and(|s| !s.is_empty()),
        "started_at falls back to assigned_at: {row:?}"
    );

    // 与 count 的 build 部分一致（init 也计入 count，故 count = builds + init = 3）。
    assert_eq!(store.count_worker_active_tasks(w1).await.unwrap(), 3);
    assert_eq!(rows.len(), 2, "init task must not appear in the list");

    assert_eq!(store.list_worker_active_builds(w2).await.unwrap().len(), 1);
}

#[tokio::test]
async fn count_worker_building_builds_for_product_filters_by_product() {
    let (store, _tmp) = create_test_store().await;
    let worker_id = store
        .upsert_worker("w1", "x86_64", 4, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    seed_building(&store, worker_id, "mydist", "x86_64").await;
    seed_building(&store, worker_id, "mydist", "aarch64").await;
    seed_building(&store, worker_id, "fedora", "x86_64").await;

    assert_eq!(
        store
            .count_worker_building_builds_for_product(worker_id, "mydist")
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        store
            .count_worker_building_builds_for_product(worker_id, "fedora")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .count_worker_building_builds_for_product(worker_id, "unknown")
            .await
            .unwrap(),
        0
    );
}

// COUNT_WORKER_BUILDING_FOR_PRODUCT 按 JOIN b.phase 过滤终态：未终结 phase
//（assigned / building / running 等）都计入，仅 build 终态后放行 init。
#[tokio::test]
async fn count_worker_building_builds_for_product_excludes_terminal_statuses() {
    let (store, _tmp) = create_test_store().await;
    let worker_id = store
        .upsert_worker("w1", "x86_64", 4, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    let b1 = seed_building(&store, worker_id, "mydist", "x86_64").await;
    sqlx::query("UPDATE worker_tasks SET status = 'assigned' WHERE build_id = $1")
        .bind(b1)
        .execute(store.pool())
        .await
        .unwrap();
    seed_building(&store, worker_id, "mydist", "aarch64").await;
    let b3 = seed_building(&store, worker_id, "mydist", "x86").await;
    sqlx::query("UPDATE worker_tasks SET status = 'running' WHERE build_id = $1")
        .bind(b3)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        store
            .count_worker_building_builds_for_product(worker_id, "mydist")
            .await
            .unwrap(),
        3
    );

    for (terminal, arch) in [
        ("succeeded", "i686"),
        ("failed", "ppc64le"),
        ("cancelled", "riscv64"),
    ] {
        let bid = seed_building(&store, worker_id, "mydist", arch).await;
        sqlx::query("UPDATE builds SET phase = $1 WHERE id = $2")
            .bind(terminal)
            .bind(bid)
            .execute(store.pool())
            .await
            .unwrap();
    }
    assert_eq!(
        store
            .count_worker_building_builds_for_product(worker_id, "mydist")
            .await
            .unwrap(),
        3,
        "terminal build tasks must not gate init"
    );
}

#[tokio::test]
async fn has_active_init_is_scoped_by_worker_and_product() {
    let (store, _tmp) = create_test_store().await;
    let w1 = store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    let w2 = store
        .upsert_worker("w2", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    assert!(!store.has_active_init(w1, "mydist").await.unwrap());

    let a1 = store
        .try_assign_init_to_worker(w1, "mydist")
        .await
        .unwrap()
        .expect("init assignment should be created");
    assert!(store.has_active_init(w1, "mydist").await.unwrap());
    assert!(!store.has_active_init(w1, "fedora").await.unwrap());
    assert!(!store.has_active_init(w2, "mydist").await.unwrap());

    sqlx::query("UPDATE worker_tasks SET status = 'running' WHERE id = $1")
        .bind(a1)
        .execute(store.pool())
        .await
        .unwrap();
    assert!(store.has_active_init(w1, "mydist").await.unwrap());

    store
        .complete_init_assignment(a1, true, None)
        .await
        .unwrap();
    assert!(!store.has_active_init(w1, "mydist").await.unwrap());
}

/// count_worker_building_builds_for_product 计入 assigned-but-not-yet-building，
/// 关闭 init 与已承诺但未开工 build 并发的窄窗口。
#[tokio::test]
async fn count_worker_building_builds_for_product_includes_assigned_not_running() {
    let (store, _tmp) = create_test_store().await;
    let worker_id = store
        .upsert_worker("w1", "x86_64", 4, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    // 仅 assigned（两侧状态均不推进 building/running）。
    let build_id = seed_build(
        &store,
        "mydist",
        "pkg",
        "pending",
        "x86_64",
        PRIORITY_DEFAULT,
        crate::state::test_state::seed_task(&store, "mydist", "pkg").await,
    )
    .await;
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    assert_eq!(
        store
            .count_worker_building_builds_for_product(worker_id, "mydist")
            .await
            .unwrap(),
        1,
        "assigned-but-not-yet-building build must be counted"
    );
}

/// result_json 必须与 success 一致——失败且无 error 详情写兜底文案；
/// 终态守卫让重复 complete 幂等 no-op（不覆写先到的终态记录）。
#[tokio::test]
async fn complete_init_assignment_json_matches_status_and_guards_terminal() {
    let (store, _tmp) = create_test_store().await;
    let worker_id = store
        .upsert_worker("w1", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();
    let a_ok = store
        .try_assign_init_to_worker(worker_id, "p1")
        .await
        .unwrap()
        .unwrap();
    let a_fail = store
        .try_assign_init_to_worker(worker_id, "p2")
        .await
        .unwrap()
        .unwrap();

    store
        .complete_init_assignment(a_ok, true, None)
        .await
        .unwrap();
    // success=false 且 error=None：写兜底文案，不写与 status 矛盾的 {"success":true}。
    store
        .complete_init_assignment(a_fail, false, None)
        .await
        .unwrap();

    let json_of = |id: i64| {
        let store = &store;
        async move {
            sqlx::query_scalar::<_, String>("SELECT result_json FROM worker_tasks WHERE id = $1")
                .bind(id)
                .fetch_one(store.pool())
                .await
                .unwrap()
        }
    };
    assert_eq!(json_of(a_ok).await, r#"{"success":true}"#);
    assert_eq!(
        json_of(a_fail).await,
        r#"{"error":"init failed without error detail"}"#
    );

    store
        .complete_init_assignment(a_ok, false, Some("late failure"))
        .await
        .unwrap();
    assert_eq!(
        json_of(a_ok).await,
        r#"{"success":true}"#,
        "terminal guard must keep the first completion"
    );
}

/// 状态词汇表守卫——未知词返回 Validation 错误；终态行拒绝回退活跃态
///（SQL 守卫 0 行 no-op，终态保持）。
#[tokio::test]
async fn update_worker_task_status_guards_vocabulary_and_regression() {
    let (store, _tmp) = create_test_store().await;
    let worker_id = store
        .upsert_worker("w1", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();
    let build_id = seed_build(
        &store,
        "mydist",
        "pkg",
        "pending",
        "x86_64",
        PRIORITY_DEFAULT,
        crate::state::test_state::seed_task(&store, "mydist", "pkg").await,
    )
    .await;
    let (assignment_id, _) = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    // 未知词（如 builds.phase 的 "building"）不得 verbatim 落进 worker_tasks。
    for bad in ["building", "succeeded", "timeout", ""] {
        let err = store.update_worker_task_status(assignment_id, bad).await;
        assert!(
            matches!(err, Err(CrbsError::ValidationFailed { .. })),
            "status {bad:?} must be rejected"
        );
        let err = store
            .update_worker_task_status_for_build(build_id, bad)
            .await;
        assert!(
            matches!(err, Err(CrbsError::ValidationFailed { .. })),
            "status {bad:?} must be rejected (for_build)"
        );
    }

    store
        .update_worker_task_status(assignment_id, "completed")
        .await
        .unwrap();
    store
        .update_worker_task_status(assignment_id, "running")
        .await
        .unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM worker_tasks WHERE id = $1")
        .bind(assignment_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(status, "completed", "terminal status must not regress");
}

/// 终态 stamp completed_at：置终态时 completed_at 非空，retention
///（prune_old_records）据此可删该行；非终态不 stamp、不被删。for_build 同语义。
#[tokio::test]
async fn update_worker_task_status_stamps_completed_at_on_terminal() {
    async fn completed_at(store: &StateStore, id: i64) -> Option<String> {
        sqlx::query_scalar("SELECT completed_at FROM worker_tasks WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap()
    }
    async fn task_status(store: &StateStore, id: i64) -> Option<String> {
        sqlx::query_scalar("SELECT status FROM worker_tasks WHERE id = $1")
            .bind(id)
            .fetch_optional(store.pool())
            .await
            .unwrap()
    }

    let (store, _tmp) = create_test_store().await;
    let worker_id = store
        .upsert_worker("w1", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();
    let task_id = crate::state::test_state::seed_task(&store, "mydist", "pkg").await;
    let build_id = seed_build(
        &store,
        "mydist",
        "pkg",
        "pending",
        "x86_64",
        PRIORITY_DEFAULT,
        task_id,
    )
    .await;
    let (assignment_id, _) = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    // 非终态不 stamp；retention 不删 completed_at NULL 行（prune 下限 1 天，不碰新行）。
    store
        .update_worker_task_status(assignment_id, "running")
        .await
        .unwrap();
    assert_eq!(
        completed_at(&store, assignment_id).await,
        None,
        "running must not stamp completed_at"
    );
    store.prune_old_records(1).await.unwrap();
    assert_eq!(
        task_status(&store, assignment_id).await.as_deref(),
        Some("running"),
        "row with NULL completed_at must survive retention"
    );

    store
        .update_worker_task_status(assignment_id, "completed")
        .await
        .unwrap();
    assert!(
        completed_at(&store, assignment_id).await.is_some(),
        "terminal status must stamp completed_at"
    );
    // 回拨 completed_at 模拟过期（prune API 下限 1 天）：stamp 值参与 retention 判定。
    sqlx::query(&format!(
        "UPDATE worker_tasks SET completed_at = {} WHERE id = $1",
        sql_time_offset(store.dialect(), "-2 days")
    ))
    .bind(assignment_id)
    .execute(store.pool())
    .await
    .unwrap();
    store.prune_old_records(1).await.unwrap();
    assert_eq!(
        task_status(&store, assignment_id).await,
        None,
        "stamped terminal row must be prunable by retention"
    );

    // 第二条 build 错开 arch（活跃去重；首条仍 building）。
    let build_id2 = seed_build(
        &store,
        "mydist",
        "pkg",
        "pending",
        "aarch64",
        PRIORITY_DEFAULT,
        task_id,
    )
    .await;
    let (assignment_id2, _) = store
        .assign_build_to_worker(build_id2, worker_id)
        .await
        .unwrap();
    store
        .update_worker_task_status_for_build(build_id2, "cancelled")
        .await
        .unwrap();
    assert!(
        completed_at(&store, assignment_id2).await.is_some(),
        "for_build terminal status must stamp completed_at"
    );
}

/// 行级单测：`get_worker_task_meta` 四元组在 assigned 行 / 终态行 /
/// 行缺失三态下的取值（report_logs / report_result 入口共用的合并查询）。
#[tokio::test]
async fn test_get_worker_task_meta_row_states() {
    let (store, _tmp) = create_test_store().await;

    let worker_id = store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    let task_id = crate::state::test_state::seed_task(&store, "mydist", "pkg").await;
    let build_id = seed_build(
        &store,
        "mydist",
        "pkg",
        "building",
        "x86_64",
        PRIORITY_DEFAULT,
        task_id,
    )
    .await;

    let insert_row = |status: &'static str| {
        let store = &store;
        async move {
            let id: i64 = sqlx::query_scalar(
                "INSERT INTO worker_tasks (build_id, worker_id, task_id, status) \
                 VALUES ($1, $2, $3, $4) RETURNING id",
            )
            .bind(build_id)
            .bind(worker_id)
            .bind(task_id)
            .bind(status)
            .fetch_one(store.pool())
            .await
            .unwrap();
            id
        }
    };
    let assigned_id = insert_row("assigned").await;
    let completed_id = insert_row("completed").await;

    let (b, w, k, s) = store.get_worker_task_meta(assigned_id).await.unwrap();
    assert_eq!(b, Some(build_id));
    assert_eq!(w, Some(worker_id));
    assert_eq!(k.as_deref(), Some("build"));
    assert_eq!(s.as_deref(), Some("assigned"));

    // 终态行：同样完整（终态后行保留，端点据此做 409 截断）。
    let (b, w, k, s) = store.get_worker_task_meta(completed_id).await.unwrap();
    assert_eq!(b, Some(build_id));
    assert_eq!(w, Some(worker_id));
    assert_eq!(k.as_deref(), Some("build"));
    assert_eq!(s.as_deref(), Some("completed"));

    // 行缺失：四元组全 None（worker_id None 让入口的归属校验落入 403）。
    let meta = store.get_worker_task_meta(9_999_999).await.unwrap();
    assert_eq!(
        meta,
        (None, None, None, None),
        "missing row must yield all-None tuple"
    );
}

/// workers 侧两处手写四值终态 IN 列表（const SQL 无法挂运行时渲染器的
/// 结构性豁免点位）与单源常量 TERMINAL_BUILD_PHASES 的同步钉：加第 5 终态
/// 或字面量漂移必红。
#[test]
fn workers_sql_terminal_in_lists_match_terminal_build_phases() {
    use crate::state::test_state::assert_terminal_in_lists;

    assert_terminal_in_lists(
        super::sql::COUNT_WORKER_BUILDING_FOR_PRODUCT,
        1,
        "COUNT_WORKER_BUILDING_FOR_PRODUCT",
    );
    assert_terminal_in_lists(
        &super::sql::release_terminal_worker_tasks(crate::state::Dialect::Sqlite),
        1,
        "release_terminal_worker_tasks",
    );
}

/// `list_worker_recent_builds`：含终态行、按分配行 id 倒序、init 行不入列；
/// completed_at 只在终态 build 上有值（running 行 NULL 供 UI 实时计时）。
#[tokio::test]
async fn test_list_worker_recent_builds_orders_by_assignment_desc() {
    let (store, _tmp) = create_test_store().await;

    let w1 = store
        .upsert_worker("w1", "x86_64", 2, "test", "online", None)
        .await
        .unwrap();
    let mut ids = Vec::new();
    for pkg in ["rc-a", "rc-b", "rc-c"] {
        ids.push(
            seed_build(
                &store,
                "mydist",
                pkg,
                "pending",
                "x86_64",
                PRIORITY_DEFAULT,
                crate::state::test_state::seed_task(&store, "mydist", pkg).await,
            )
            .await,
        );
    }
    for id in &ids {
        store.assign_build_to_worker(*id, w1).await.unwrap();
    }
    store
        .complete_build(ids[0], "succeeded", None)
        .await
        .unwrap();
    store
        .update_worker_task_status_for_build(ids[0], "completed")
        .await
        .unwrap();
    // init 行不进 Recent builds。
    store
        .try_assign_init_to_worker(w1, "fedora")
        .await
        .unwrap()
        .unwrap();

    let rows = store.list_worker_recent_builds(w1).await.unwrap();
    assert_eq!(rows.len(), 3, "init row excluded: {rows:?}");
    // 分配行 id 倒序：最新分配（rc-c）在最前。
    let pkg_names: Vec<&str> = rows.iter().map(|r| r.pkg_name.as_str()).collect();
    assert_eq!(pkg_names, ["rc-c", "rc-b", "rc-a"], "{rows:?}");
    let done = rows.iter().find(|r| r.id == ids[0]).unwrap();
    assert_eq!(done.phase, "succeeded");
    assert!(
        done.completed_at.is_some(),
        "terminal build carries completed_at"
    );
    let running = rows.iter().find(|r| r.id == ids[2]).unwrap();
    assert!(
        running.completed_at.is_none(),
        "active build has no completed_at"
    );
    assert!(
        running.started_at.is_some(),
        "started_at falls back to assigned_at"
    );
}

/// `list_worker_recent_inits`：每产品最近一次（Rust 侧按 init_product 去重，
/// 保最新）；completed_at 在终态行有值、活跃行 NULL。
#[tokio::test]
async fn test_list_worker_recent_inits_keeps_latest_per_product() {
    let (store, _tmp) = create_test_store().await;

    let w1 = store
        .upsert_worker("w1", "x86_64", 1, "test", "online", None)
        .await
        .unwrap();

    // mydist 第一次 init：完成。
    let first = store
        .try_assign_init_to_worker(w1, "mydist")
        .await
        .unwrap()
        .unwrap();
    store
        .complete_init_assignment(first, true, None)
        .await
        .unwrap();
    // mydist 第二次 init：活跃（去重后应保留这条最新行）。
    store
        .try_assign_init_to_worker(w1, "mydist")
        .await
        .unwrap()
        .unwrap();
    // otherdist 一次活跃 init。
    store
        .try_assign_init_to_worker(w1, "otherdist")
        .await
        .unwrap()
        .unwrap();

    let rows = store.list_worker_recent_inits(w1).await.unwrap();
    assert_eq!(rows.len(), 2, "one row per product: {rows:?}");
    let mydist = rows.iter().find(|r| r.product == "mydist").unwrap();
    assert_eq!(mydist.status, "assigned", "latest mydist init wins");
    assert!(mydist.completed_at.is_none());
    let otherdist = rows.iter().find(|r| r.product == "otherdist").unwrap();
    assert!(otherdist.completed_at.is_none());
}

/// `get_build_lifecycle`：四时刻与 worker 标识按最新分配行取值；无分配行的
/// build 只有 submitted_at（builds.created_at，NULL 回退 tasks.submitted_at）；
/// 行不存在的 build 返回 None。
#[tokio::test]
async fn test_get_build_lifecycle_stages() {
    let (store, _tmp) = create_test_store().await;
    let w1 = store
        .upsert_worker("lc-w", "x86_64", 1, "test", "online", None)
        .await
        .unwrap();

    // 无分配：只有 Submitted。
    let pending = seed_build(
        &store,
        "mydist",
        "lc-pending",
        "pending",
        "x86_64",
        PRIORITY_DEFAULT,
        crate::state::test_state::seed_task(&store, "mydist", "lc-pending").await,
    )
    .await;
    let lc = store.get_build_lifecycle(pending).await.unwrap().unwrap();
    assert!(lc.submitted_at.is_some(), "created_at present: {lc:?}");
    assert!(lc.assigned_at.is_none() && lc.started_at.is_none() && lc.completed_at.is_none());
    assert!(lc.worker_id.is_none() && lc.worker_name.is_none());

    // 派发 + 认领（started_at 经 claim 语义 stamp）+ 完成。
    let claimed = seed_build(
        &store,
        "mydist",
        "lc-claimed",
        "pending",
        "x86_64",
        PRIORITY_DEFAULT,
        crate::state::test_state::seed_task(&store, "mydist", "lc-claimed").await,
    )
    .await;
    store.assign_build_to_worker(claimed, w1).await.unwrap();
    let assignment: i64 = sqlx::query_scalar("SELECT id FROM worker_tasks WHERE build_id = $1")
        .bind(claimed)
        .fetch_one(store.pool())
        .await
        .unwrap();
    sqlx::query(&format!(
        "UPDATE worker_tasks SET started_at = {} WHERE id = {assignment}",
        sql_time_offset(store.dialect, "-60 seconds"),
    ))
    .execute(store.pool())
    .await
    .unwrap();
    store
        .complete_build(claimed, "succeeded", None)
        .await
        .unwrap();

    let lc = store.get_build_lifecycle(claimed).await.unwrap().unwrap();
    assert!(lc.submitted_at.is_some(), "{lc:?}");
    assert!(lc.assigned_at.is_some(), "{lc:?}");
    assert!(lc.started_at.is_some(), "{lc:?}");
    assert!(lc.completed_at.is_some(), "{lc:?}");
    assert_eq!(lc.worker_id, Some(w1));
    assert_eq!(lc.worker_name.as_deref(), Some("lc-w"));

    // 行不存在（已清理）→ None。
    let missing = store.get_build_lifecycle(i64::MAX - 1).await.unwrap();
    assert!(missing.is_none());
}
