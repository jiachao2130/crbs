// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 分配、回收与释放语义。

use super::common::*;
use super::*;

/// latest_assigned_worker_name 取 build 最近一次 assignment（id 最大）
/// 的 worker 名；不限定状态（终态后行保留）；无 assignment 的 build → None。
#[tokio::test]
async fn latest_assigned_worker_name_picks_latest_assignment_regardless_of_status() {
    let (store, _tmp) = create_test_store().await;

    let w_old = store
        .upsert_worker("w-old", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    let w_new = store
        .upsert_worker("w-new", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    // 直接 INSERT 两条同 build assignment（模拟离线回收重派）：id 最大即最近
    // 一次分配；首条置终态。
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
    for (worker_id, status) in [(w_old, "completed"), (w_new, "running")] {
        sqlx::query(
            "INSERT INTO worker_tasks (build_id, worker_id, task_id, status) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(build_id)
        .bind(worker_id)
        .bind(task_id)
        .bind(status)
        .execute(store.pool())
        .await
        .unwrap();
    }

    assert_eq!(
        store.latest_assigned_worker_name(build_id).await.unwrap(),
        Some("w-new".to_string())
    );

    sqlx::query(
        "UPDATE worker_tasks SET status = 'completed' WHERE build_id = $1 AND worker_id = $2",
    )
    .bind(build_id)
    .bind(w_new)
    .execute(store.pool())
    .await
    .unwrap();
    assert_eq!(
        store.latest_assigned_worker_name(build_id).await.unwrap(),
        Some("w-new".to_string())
    );

    let orphan_task = crate::state::test_state::seed_task(&store, "mydist", "orphan").await;
    let unassigned = seed_build(
        &store,
        "mydist",
        "orphan",
        "pending",
        "x86_64",
        PRIORITY_DEFAULT,
        orphan_task,
    )
    .await;
    assert_eq!(
        store.latest_assigned_worker_name(unassigned).await.unwrap(),
        None
    );
}

/// `list_cancelled_assignment_ids_for_worker`（心跳取消通知数据源）：返回本
/// worker 名下 build 已取消的 assignment id；他 worker / 非取消 build 不返回；
/// init 行（build_id NULL）被 JOIN 天然排除。关键语义：信号源是
/// builds.phase='cancelled'（first-winner 终态）而非 worker_tasks.status——
/// best-effort 写失败后行滞留 running，≤30s 被 release_terminal_worker_tasks
/// 清成终态，按 status 过滤会永久丢通知，已清终态的行仍须返回。
#[tokio::test]
async fn list_cancelled_assignment_ids_for_worker_sources_from_build_phase() {
    let (store, _tmp) = create_test_store().await;

    let w1 = store
        .upsert_worker("w1", "x86_64", 4, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    let w2 = store
        .upsert_worker("w2", "x86_64", 4, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    // 取消只翻 builds.phase，行 status 滞留 running（模拟 best-effort 写失败现场）。
    let cancelled_build = seed_building(&store, w1, "mydist", "x86_64").await;
    let cancelled_assignment: i64 =
        sqlx::query_scalar("SELECT id FROM worker_tasks WHERE build_id = $1")
            .bind(cancelled_build)
            .fetch_one(store.pool())
            .await
            .unwrap();
    store.mark_build_cancelled(cancelled_build).await.unwrap();

    seed_building(&store, w1, "mydist", "aarch64").await;
    let other_build = seed_building(&store, w2, "mydist", "x86_64").await;
    store.mark_build_cancelled(other_build).await.unwrap();
    // 活跃 init（build_id NULL，JOIN 天然不命中；用 fedora 避开 mydist 的 init gate）。
    store
        .try_assign_init_to_worker(w1, "fedora")
        .await
        .unwrap()
        .expect("init assignment should be created");

    // sweep 前：取消即返回（行 status 仍 running）。
    let ids = store
        .list_cancelled_assignment_ids_for_worker(w1)
        .await
        .unwrap();
    assert_eq!(ids, vec![cancelled_assignment], "before sweep: {ids:?}");

    // 兜底 sweep：滞留 running 取消行按 build phase 映射翻 'cancelled'（双方言一致，≤30s 内）。
    let (released, _) = store.release_terminal_worker_tasks().await.unwrap();
    assert!(released >= 1, "sweep must reclaim the stale rows");
    let wt_status: String = sqlx::query_scalar("SELECT status FROM worker_tasks WHERE id = $1")
        .bind(cancelled_assignment)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        wt_status, "cancelled",
        "sweep must map the cancelled build's row to 'cancelled'"
    );

    // sweep 后仍返回：钉住 join 语义（信号源 builds.phase，与 wt.status 无关）。
    let ids = store
        .list_cancelled_assignment_ids_for_worker(w1)
        .await
        .unwrap();
    assert_eq!(ids, vec![cancelled_assignment], "after sweep: {ids:?}");

    let ids_w2 = store
        .list_cancelled_assignment_ids_for_worker(w2)
        .await
        .unwrap();
    assert_eq!(ids_w2.len(), 1);
    assert_ne!(ids_w2[0], cancelled_assignment);
}

#[tokio::test]
async fn test_release_assignment_resets_build_to_pending() {
    let (store, _tmp) = create_test_store().await;

    let worker_id = store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
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

    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "assigned");

    store
        .release_assignment(assignment_id, build_id)
        .await
        .unwrap();

    let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM worker_tasks WHERE worker_id = $1 AND status IN ('assigned', 'running')",
        )
        .bind(worker_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);

    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "pending");
}

/// 上传归属精确到 assignment：同 worker 重派后旧 assignment id 不再命中；
/// None（不精确匹配 attempt）仅命中当前活跃行。
#[tokio::test]
async fn ownership_requires_current_assignment_after_redispatch() {
    let (store, _tmp) = create_test_store().await;

    let worker_id = store
        .upsert_worker("w-owner", "x86_64", 1, "0.15.0-dev", "online", None)
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

    let (old_assignment, _) = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    assert!(store
        .worker_assigned_to_build(worker_id, build_id, Some(old_assignment))
        .await
        .unwrap());
    store
        .release_assignment(old_assignment, build_id)
        .await
        .unwrap();
    let (new_assignment, _) = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    assert_ne!(old_assignment, new_assignment);

    assert!(
        !store
            .worker_assigned_to_build(worker_id, build_id, Some(old_assignment))
            .await
            .unwrap(),
        "stale attempt must not match the new assignment"
    );
    assert!(store
        .worker_assigned_to_build(worker_id, build_id, Some(new_assignment))
        .await
        .unwrap());
}

/// 迟到报告守卫：assignment 已被 reclaimer 回收重派（行已删）后，
/// 迟到的 fail_assignment 不得把重派后新 worker 在跑的构建（building）打成
/// failed——DELETE rows_affected 为 0 时跳过 complete_build_update。
#[tokio::test]
async fn test_fail_assignment_on_reclaimed_assignment_is_noop() {
    let (store, _tmp) = create_test_store().await;
    let worker_id = store
        .upsert_worker("w-late-fail", "x86_64", 2, "0.15.0-dev", "online", None)
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

    // 模拟回收重派后的现场：assignment 行已删、build 被新 worker 拉起（building）。
    sqlx::query("DELETE FROM worker_tasks WHERE id = $1")
        .bind(assignment_id)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
        .bind(build_id)
        .execute(store.pool())
        .await
        .unwrap();

    store
        .fail_assignment(assignment_id, build_id)
        .await
        .unwrap();

    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        phase, "building",
        "late failure report on reclaimed assignment must not fail the reassigned build"
    );
}

/// 迟到释放守卫：assignment 已被回收重派（行已删）后，迟到的
/// release_assignment 不得把重派后新 worker 在跑的构建经
/// RESET_BUILD_TO_PENDING 拉回 pending 造成双执行。
#[tokio::test]
async fn test_release_assignment_on_reclaimed_assignment_is_noop() {
    let (store, _tmp) = create_test_store().await;
    let worker_id = store
        .upsert_worker("w-late-release", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    let build_id = seed_build(
        &store,
        "mydist",
        "pkg-rel",
        "pending",
        "x86_64",
        PRIORITY_DEFAULT,
        crate::state::test_state::seed_task(&store, "mydist", "pkg-rel").await,
    )
    .await;
    let (assignment_id, _) = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    sqlx::query("DELETE FROM worker_tasks WHERE id = $1")
        .bind(assignment_id)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
        .bind(build_id)
        .execute(store.pool())
        .await
        .unwrap();

    store
        .release_assignment(assignment_id, build_id)
        .await
        .unwrap();

    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        phase, "building",
        "late release on reclaimed assignment must not reset the reassigned build"
    );
}

/// 回收重置 pending 时一并重置 started_at：死 worker 上耗掉的时间不得经
/// sql_priority_wait_weight（按等待秒计权）转为插队优先级、也不得拉高
/// list_stale_builds_base 的年龄判定。全部 RESET 调用点共享同一 SQL，此处经
/// release_assignment 钉住。
#[tokio::test]
async fn test_release_assignment_resets_started_at_on_requeue() {
    let (store, _tmp) = create_test_store().await;
    let worker_id = store
        .upsert_worker("w-reset-release", "x86_64", 2, "test", "online", None)
        .await
        .unwrap();
    let build_id = seed_build(
        &store,
        "test",
        "pkg-rel-rs",
        "pending",
        "x86_64",
        PRIORITY_DEFAULT,
        crate::state::test_state::seed_task(&store, "test", "pkg-rel-rs").await,
    )
    .await;
    let (assignment_id, _) = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    crate::state::test_state::set_build_started_at(&store, build_id, "-1 hour").await;
    let aged = build_started_at(&store, build_id).await;

    store
        .release_assignment(assignment_id, build_id)
        .await
        .unwrap();

    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        phase, "pending",
        "released build must be requeued as pending"
    );

    let reset = build_started_at(&store, build_id).await;
    assert!(
        reset > aged,
        "requeued build's started_at must restart wait timing, got aged={aged}, reset={reset}"
    );
}

#[tokio::test]
async fn test_reclaim_worker_tasks_resets_builds_and_offlines_worker() {
    let (store, _tmp) = create_test_store().await;

    let worker_id = store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    let mut builds = Vec::new();
    for pkg in ["p1", "p2"] {
        builds.push(
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
    for &b in &builds {
        store.assign_build_to_worker(b, worker_id).await.unwrap();
    }
    age_worker_heartbeat(&store, worker_id, "-300 seconds").await;

    let affected = store.reclaim_worker_tasks(worker_id, 240).await.unwrap();
    assert_eq!(affected.len(), 2);

    for &b in &builds {
        let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
            .bind(b)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(phase, "pending");
    }
    let tasks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks WHERE worker_id = $1")
        .bind(worker_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(tasks, 0);
    let status: String = sqlx::query_scalar("SELECT status FROM workers WHERE id = $1")
        .bind(worker_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(status, "offline");
}

/// 重试预算耗尽的 assigned 行回收：reset 守卫拒绝后必须就地转 failed，
/// 不得删掉 assignment 留下永卡 assigned 的孤儿（zombie 修复不扫 assigned）。
#[tokio::test]
async fn reclaim_exhausted_attempt_fails_build_instead_of_orphaning() {
    let (store, _tmp) = create_test_store().await;

    let worker_id = store
        .upsert_worker("w-exhausted", "x86_64", 1, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    let task_id = crate::state::test_state::seed_task(&store, "mydist", "p1").await;
    let build_id = seed_build(
        &store,
        "mydist",
        "p1",
        "pending",
        "x86_64",
        PRIORITY_DEFAULT,
        task_id,
    )
    .await;
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET attempt = $1 WHERE id = $2")
        .bind(crate::state::MAX_BUILD_ATTEMPTS)
        .bind(build_id)
        .execute(store.pool())
        .await
        .unwrap();
    age_worker_heartbeat(&store, worker_id, "-300 seconds").await;

    let affected = store.reclaim_worker_tasks(worker_id, 240).await.unwrap();
    assert_eq!(affected.len(), 1);

    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        phase, "failed",
        "exhausted retry must fail the build, not orphan an assigned row"
    );
    let assignments: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks WHERE worker_id = $1")
            .bind(worker_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(assignments, 0);
}

/// 回收置 offline 带 `status IN ('online','offline')` 谓词：suspended/draining
/// 等管理员保留态不被覆盖（任务清理与 status 改写解耦——保留态行的
/// worker_tasks 清理照常执行，仅 status 改写被拒）；online 行照常翻 offline。
#[tokio::test]
async fn reclaim_offline_preserves_admin_statuses() {
    let (store, _tmp) = create_test_store().await;

    for admin_status in ["suspended", "draining"] {
        let id = store
            .upsert_worker(
                &format!("w-{admin_status}"),
                "x86_64",
                2,
                "0.15.0-dev",
                "online",
                None,
            )
            .await
            .unwrap();
        sqlx::query("UPDATE workers SET status = $1 WHERE id = $2")
            .bind(admin_status)
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap();
        age_worker_heartbeat(&store, id, "-300 seconds").await;

        // affected 空（保留态行无任务可清），status 原样保持。
        let affected = store.reclaim_worker_tasks(id, 240).await.unwrap();
        assert!(affected.is_empty());
        let status: String = sqlx::query_scalar("SELECT status FROM workers WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(status, admin_status, "回收不得覆盖管理员保留态");
    }

    let id = store
        .upsert_worker("w-online", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    age_worker_heartbeat(&store, id, "-300 seconds").await;
    store.reclaim_worker_tasks(id, 240).await.unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM workers WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(status, "offline");
}

/// 保留态行带 stuck 任务时：任务清理（删 worker_tasks + build 回 pending）
/// 照常执行、affected 如实回报，仅 status 改写被谓词拒绝——回收不因保留态
/// 丢任务清理（worker 确已失联，任务必须重派）。
#[tokio::test]
async fn reclaim_offline_with_stuck_task_cleans_tasks_and_preserves_status() {
    let (store, _tmp) = create_test_store().await;

    let id = store
        .upsert_worker(
            "w-suspended-stuck",
            "x86_64",
            2,
            "0.15.0-dev",
            "online",
            None,
        )
        .await
        .unwrap();
    sqlx::query("UPDATE workers SET status = $1 WHERE id = $2")
        .bind("suspended")
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();

    let task_id = crate::state::test_state::seed_task(&store, "mydist", "stuck").await;
    let build_id = seed_build(
        &store,
        "mydist",
        "stuck",
        "pending",
        "x86_64",
        PRIORITY_DEFAULT,
        task_id,
    )
    .await;
    store.assign_build_to_worker(build_id, id).await.unwrap();
    age_worker_heartbeat(&store, id, "-300 seconds").await;

    let affected = store.reclaim_worker_tasks(id, 240).await.unwrap();
    assert_eq!(affected, vec![(task_id, Some(build_id))]);

    let tasks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks WHERE worker_id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(tasks, 0);
    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "pending");

    let status: String = sqlx::query_scalar("SELECT status FROM workers WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(status, "suspended", "回收不得覆盖管理员保留态");
}

#[tokio::test]
async fn test_release_terminal_worker_tasks_frees_capacity_without_touching_build() {
    let (store, _tmp) = create_test_store().await;

    let worker_id = store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    let mut ids = Vec::new();
    for pkg in ["done", "live"] {
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
    let (done_build, live_build) = (ids[0], ids[1]);

    store
        .assign_build_to_worker(done_build, worker_id)
        .await
        .unwrap();
    store
        .assign_build_to_worker(live_build, worker_id)
        .await
        .unwrap();
    assert_eq!(store.count_worker_active_tasks(worker_id).await.unwrap(), 2);

    // done_build 完成但其 worker_task 滞留 running（模拟上报写丢失）。
    store
        .complete_build(done_build, "succeeded", None)
        .await
        .unwrap();

    let (released, build_ids) = store.release_terminal_worker_tasks().await.unwrap();
    assert_eq!(released, 1, "只应释放指向终态 build 的 worker_task");
    assert_eq!(
        build_ids,
        vec![done_build],
        "RETURNING 应给出被释放的终态 build"
    );

    assert_eq!(store.count_worker_active_tasks(worker_id).await.unwrap(), 1);

    // sweep 绝不重置 build（done_build 仍 succeeded）。
    let done_phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(done_build)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(done_phase, "succeeded");

    let done_wt_status: String =
        sqlx::query_scalar("SELECT status FROM worker_tasks WHERE build_id = $1")
            .bind(done_build)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(done_wt_status, "completed");
}

/// 兜底 sweep 的终态词汇映射：僵尸 worker_task 行按关联 build 的 phase 收尾
///（succeeded→completed、cancelled→cancelled、failed/timeout→failed，与上报
/// 路径 report_result 映射同口径）；活跃 build 的行不动。双方言（create_test_store）。
#[tokio::test]
async fn release_terminal_worker_tasks_maps_build_phase_to_task_status() {
    let (store, _tmp) = create_test_store().await;
    let worker_id = store
        .upsert_worker("w-sweep", "x86_64", 8, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    let mk_zombie = |pkg: &'static str, phase: &'static str| {
        let store = &store;
        async move {
            let task_id = crate::state::test_state::seed_task(store, "mydist", pkg).await;
            let build_id = seed_build(
                store,
                "mydist",
                pkg,
                "pending",
                "x86_64",
                PRIORITY_DEFAULT,
                task_id,
            )
            .await;
            store
                .assign_build_to_worker(build_id, worker_id)
                .await
                .unwrap();
            // 模拟上报写丢失：build 已终态，worker_tasks 行滞留 running。
            sqlx::query("UPDATE builds SET phase = $1 WHERE id = $2")
                .bind(phase)
                .bind(build_id)
                .execute(store.pool())
                .await
                .unwrap();
            build_id
        }
    };
    let b_ok = mk_zombie("p-ok", "succeeded").await;
    let b_ko = mk_zombie("p-ko", "failed").await;
    let b_cxl = mk_zombie("p-cxl", "cancelled").await;
    let b_tmo = mk_zombie("p-tmo", "timeout").await;
    let b_live = mk_zombie("p-live", "building").await;

    let (released, build_ids) = store.release_terminal_worker_tasks().await.unwrap();
    assert_eq!(released, 4, "只有指向终态 build 的僵尸行被收尾");
    let mut swept = build_ids;
    swept.sort_unstable();
    let mut expected = [b_ok, b_ko, b_cxl, b_tmo];
    expected.sort_unstable();
    assert_eq!(swept, expected);

    let wt_status = |build_id: i64| {
        let store = &store;
        async move {
            sqlx::query_scalar::<_, String>("SELECT status FROM worker_tasks WHERE build_id = $1")
                .bind(build_id)
                .fetch_one(store.pool())
                .await
                .unwrap()
        }
    };
    assert_eq!(wt_status(b_ok).await, "completed");
    assert_eq!(wt_status(b_ko).await, "failed");
    assert_eq!(wt_status(b_cxl).await, "cancelled");
    assert_eq!(wt_status(b_tmo).await, "failed", "timeout 映射同 failed");
    assert_eq!(
        wt_status(b_live).await,
        "assigned",
        "活跃 build 的行不动（fixture：assign 后未拉取，仍 assigned）"
    );
}

#[tokio::test]
async fn test_check_assigned_task_marks_running() {
    let (store, _tmp) = create_test_store().await;

    let worker_id = store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
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
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    let task = store.check_assigned_task(worker_id).await.unwrap();
    assert!(task.is_some());

    let wt_status: String =
        sqlx::query_scalar("SELECT status FROM worker_tasks WHERE worker_id = $1")
            .bind(worker_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(wt_status, "running");
    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "building");

    assert!(store
        .check_assigned_task(worker_id)
        .await
        .unwrap()
        .is_none());
}

/// 重投递查询：own worker + running + building 命中；assigned（未开跑，
/// 正常领取路径可取）/ 他人 worker 的 running / 终态 build 的 running 不命中。
#[tokio::test]
async fn list_running_assignments_for_worker_selects_own_running_building() {
    let (store, _tmp) = create_test_store().await;
    let w1 = store
        .upsert_worker("w-redeliver", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    let w2 = store
        .upsert_worker("w-other", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    let mk_build = |pkg: &'static str| {
        let store = &store;
        async move {
            seed_build(
                store,
                "mydist",
                pkg,
                "pending",
                "x86_64",
                PRIORITY_DEFAULT,
                crate::state::test_state::seed_task(store, "mydist", pkg).await,
            )
            .await
        }
    };
    let b_assigned = mk_build("p-asg").await;
    let b_running = mk_build("p-run").await;
    let b_other = mk_build("p-other").await;
    let b_terminal = mk_build("p-done").await;

    let (a_running, _) = store.assign_build_to_worker(b_running, w1).await.unwrap();
    let (_a_assigned, _) = store.assign_build_to_worker(b_assigned, w1).await.unwrap();
    let (a_other, _) = store.assign_build_to_worker(b_other, w2).await.unwrap();
    let (a_terminal, _) = store.assign_build_to_worker(b_terminal, w1).await.unwrap();

    // running+building（响应丢失形态）：本 worker 命中。
    for (aid, bid) in [(a_running, b_running), (a_other, b_other)] {
        sqlx::query("UPDATE worker_tasks SET status = 'running' WHERE id = $1")
            .bind(aid)
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
            .bind(bid)
            .execute(store.pool())
            .await
            .unwrap();
    }
    // 终态 build 的 running 行（report 丢失）：build 非 building 不命中。
    sqlx::query("UPDATE worker_tasks SET status = 'running' WHERE id = $1")
        .bind(a_terminal)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET phase = 'succeeded' WHERE id = $1")
        .bind(b_terminal)
        .execute(store.pool())
        .await
        .unwrap();

    let got = store.list_running_assignments_for_worker(w1).await.unwrap();
    assert_eq!(got.len(), 1);
    match &got[0] {
        AssignedTaskInfo::Build {
            assignment_id,
            build_id,
            ..
        } => {
            assert_eq!(*assignment_id, a_running);
            assert_eq!(*build_id, b_running);
        }
        other => panic!("expected Build variant for the running row, got: {other:?}"),
    }
    let other_running = store.list_running_assignments_for_worker(w2).await.unwrap();
    assert_eq!(other_running.len(), 1);
    match &other_running[0] {
        AssignedTaskInfo::Build { assignment_id, .. } => assert_eq!(*assignment_id, a_other),
        other => panic!("w2 must see its own running row, got: {other:?}"),
    }
    let w3 = store
        .upsert_worker("w-assigned-only", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    let b3 = mk_build("p-w3").await;
    store.assign_build_to_worker(b3, w3).await.unwrap();
    assert!(store
        .list_running_assignments_for_worker(w3)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn test_fail_assignment_removes_record_and_fails_build() {
    let (store, _tmp) = create_test_store().await;

    let worker_id = store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
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

    store
        .fail_assignment(assignment_id, build_id)
        .await
        .unwrap();

    let tasks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks WHERE id = $1")
        .bind(assignment_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(tasks, 0);
    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "failed");
}

/// 终态守卫（cancel vs worker 拉取）：cancel 后 check_assigned_task 不得把
/// build 从 cancelled 拉回 building、worker_task 从 cancelled 拉回 running。
#[tokio::test]
async fn test_check_assigned_task_does_not_undo_cancel() {
    let (store, _tmp) = create_test_store().await;

    let worker_id = store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
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
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    // 竞态中间态：cancel 已写 build（cancelled）、worker_task 仍 assigned——
    // SET_BUILD_BUILDING 守卫必须拒绝拉回 building（否则撤销取消）。
    store.mark_build_cancelled(build_id).await.unwrap();

    // SET_BUILD_BUILDING 的 rows_affected 校验：0 行（已 cancelled）与
    // assignment CAS 失败同型——ROLLBACK 后按"无任务"返回，绝不下发。
    let task = store.check_assigned_task(worker_id).await.unwrap();
    assert!(
        task.is_none(),
        "must not dispatch a build whose phase already left 'assigned'"
    );

    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        phase, "cancelled",
        "SET_BUILD_BUILDING guard must not pull a cancelled build back to building"
    );

    // ROLLBACK 撤销 running 标记：worker_task 回 assigned，交 reclaimer 收尾。
    let wt_status: String =
        sqlx::query_scalar("SELECT status FROM worker_tasks WHERE build_id = $1")
            .bind(build_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(wt_status, "assigned");
}

/// 终态守卫（cancel vs reclaimer）：cancel 后 reclaim 不得把 build 重置回 pending。
#[tokio::test]
async fn test_reclaim_does_not_reset_cancelled_build() {
    let (store, _tmp) = create_test_store().await;

    let worker_id = store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
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
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    // 竞态中间态：cancel 已写 build（cancelled）、worker_task 仍 assigned——
    // RESET_BUILD_TO_PENDING 守卫必须拒绝重置回 pending（否则已取消构建重新排队）。
    store.mark_build_cancelled(build_id).await.unwrap();
    age_worker_heartbeat(&store, worker_id, "-300 seconds").await;

    let affected = store.reclaim_worker_tasks(worker_id, 240).await.unwrap();
    assert_eq!(
        affected.len(),
        1,
        "stuck list sees the still-assigned worker_task (race window)"
    );

    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        phase, "cancelled",
        "RESET_BUILD_TO_PENDING guard must not requeue a cancelled build"
    );
}

/// SET_BUILD_ASSIGNED 的 phase='pending' 守卫——对非 pending 的 build
/// 分配返回 Conflict（防双分配/复活终态），且事务回滚不留 worker_task 行。
#[tokio::test]
async fn assign_build_to_worker_refuses_non_pending_build() {
    let (store, _tmp) = create_test_store().await;
    let w1 = store
        .upsert_worker("w1", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();
    let w2 = store
        .upsert_worker("w2", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();

    // 两条 build 错开 arch：避开活跃去重（与本测试无关）。
    let mk_build = |phase: &'static str, arch: &'static str| {
        let store = &store;
        async move {
            seed_build(
                store,
                "mydist",
                "pkg",
                phase,
                arch,
                PRIORITY_DEFAULT,
                crate::state::test_state::seed_task(store, "mydist", "pkg").await,
            )
            .await
        }
    };
    let double = mk_build("pending", "x86_64").await;
    let cancelled = mk_build("pending", "aarch64").await;

    store.assign_build_to_worker(double, w1).await.unwrap();

    let err = store.assign_build_to_worker(double, w2).await;
    assert!(
        matches!(err, Err(CrbsError::Conflict { .. })),
        "double assignment must be refused, got {err:?}"
    );
    let cnt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks WHERE worker_id = $1")
        .bind(w2)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        cnt, 0,
        "rolled-back assignment must leave no worker_task row"
    );

    store.mark_build_cancelled(cancelled).await.unwrap();
    let err = store.assign_build_to_worker(cancelled, w2).await;
    assert!(
        matches!(err, Err(CrbsError::Conflict { .. })),
        "cancelled build must not be assignable, got {err:?}"
    );
}

/// 毒丸封顶：attempt 达上限后 reset 守卫拒绝（不再无限重排），收口助手
/// 把活跃行转终态 failed——不收口会永卡 building/pending 边缘无人消费。
#[tokio::test]
async fn retry_budget_caps_poison_pill_reentry() {
    let (store, _tmp) = create_test_store().await;
    let task_id = crate::state::test_state::seed_task(&store, "test", "poison").await;
    let build_id = seed_build(&store, "test", "poison", "building", "x86_64", 0, task_id).await;
    // 预算耗尽形态：三次重入已计满。
    sqlx::query("UPDATE builds SET attempt = $1 WHERE id = $2")
        .bind(crate::state::MAX_BUILD_ATTEMPTS)
        .bind(build_id)
        .execute(store.pool())
        .await
        .unwrap();

    // reset 守卫拒绝（attempt < MAX 不再满足）。
    let reset = sqlx::query(&super::sql::reset_build_to_pending(store.dialect))
        .bind(build_id)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        reset.rows_affected(),
        0,
        "budget-exhausted row must not requeue"
    );

    let mut conn = store.pool().acquire().await.expect("acquire conn");
    let closed = store
        .fail_build_if_retry_exhausted(&mut conn, build_id)
        .await
        .unwrap();
    assert!(closed, "exhausted building row must be closed");
    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "failed");
    // 终态后助手幂等（不再命中活跃谓词）。
    let again = store
        .fail_build_if_retry_exhausted(&mut conn, build_id)
        .await
        .unwrap();
    assert!(!again, "terminal row must not be re-closed");
}
