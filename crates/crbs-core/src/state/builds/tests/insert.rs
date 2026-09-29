// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 插入路径：活跃去重、task 终态守卫与 schema 索引谓词对齐。

use super::common::*;
use super::*;

/// 放置契约下限随 insert_build 落列（守卫形态同列集）：声明值 KB/核
/// 读回逐位一致；同一 task 的兄弟构建各自携带（fan_out 子构建继承由
/// 提交侧逐行传入，不在 SQL 层）。
#[tokio::test]
async fn insert_build_persists_req_min_columns() {
    let (_tmp, store) = tmp_store().await;
    let task_id = crate::state::test_state::seed_task(&store, "fedora", "rr-req-1.0").await;
    let id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "rr-req-1.0",
            phase: "pending",
            backend: "chroot",
            user: "alice",
            task_id: Some(task_id),
            req_min_mem_kb: Some(4 * 1024 * 1024),
            req_min_ncpu: Some(8),
            req_min_disk_kb: Some(2 * 1024 * 1024 * 1024),
            ..Default::default()
        })
        .await
        .unwrap();
    let rec = store.get_build(id).await.unwrap().unwrap();
    assert_eq!(rec.req_min_mem_kb, Some(4 * 1024 * 1024));
    assert_eq!(rec.req_min_ncpu, Some(8));
    assert_eq!(rec.req_min_disk_kb, Some(2 * 1024 * 1024 * 1024));

    // 守卫形态（INSERT ... SELECT ... WHERE EXISTS）同列集。
    let task2 = crate::state::test_state::seed_task(&store, "fedora", "rr-req-1.1").await;
    let id2 = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "rr-req-1.1",
            phase: "pending",
            backend: "chroot",
            user: "alice",
            task_id: Some(task2),
            req_min_mem_kb: Some(1024),
            ..Default::default()
        })
        .await
        .unwrap();
    let rec = store.get_build(id2).await.unwrap().unwrap();
    assert_eq!(rec.req_min_mem_kb, Some(1024));
    assert_eq!(rec.req_min_ncpu, None);
    assert_eq!(rec.req_min_disk_kb, None);
}

/// 普通与守卫插入形态均在入队时落 created_at；历史回灌与 worker 镜像行才可空。
#[tokio::test]
async fn insert_build_sets_created_at() {
    let (_tmp, store) = tmp_store().await;
    let id = store
        .insert_build(sample_insert(&store).await)
        .await
        .unwrap();
    let created_at: Option<String> =
        sqlx::query_scalar("SELECT created_at FROM builds WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(created_at.is_some(), "created_at must be set on insert");

    let task_id =
        crate::state::test_state::seed_task(&store, "fedora", "created-at-guarded-1.0").await;
    let guarded_id = exec_guarded_insert(&store, task_id, "pending", "created-at-guarded-1.0")
        .await
        .expect("guarded insert must return id");
    let guarded_created_at: Option<String> =
        sqlx::query_scalar("SELECT created_at FROM builds WHERE id = $1")
            .bind(guarded_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(
        guarded_created_at.is_some(),
        "guarded insert must set created_at"
    );
}

/// insert_build 未显式写双轴值时，两列均落 DB 默认值 1（默认发布 + 默认消费）。
#[tokio::test]
async fn insert_build_defaults_repo_axes_to_true() {
    let (_tmp, store) = tmp_store().await;
    let id = store
        .insert_build(sample_insert(&store).await)
        .await
        .unwrap();
    assert_eq!(repo_publish_of(&store, id).await, 1);
    assert_eq!(repo_consume_of(&store, id).await, 1);
}

/// 双轴生效值快照：insert_build 显式传入的 repo_publish / repo_consume
/// 原样落列（提交时合流在调用方，state 层只忠实存储）。
#[tokio::test]
async fn insert_build_persists_repo_axis_flags() {
    let (_tmp, store) = tmp_store().await;
    let task_id = crate::state::test_state::seed_task(&store, "fedora", "axis-1.0-1.fc42").await;
    let id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "axis-1.0-1.fc42",
            phase: "pending",
            backend: "chroot",
            user: "alice",
            repo_publish: false,
            repo_consume: false,
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(repo_publish_of(&store, id).await, 0);
    assert_eq!(repo_consume_of(&store, id).await, 0);
}

/// task 关联守卫：终态 task 拒绝挂新 build（fan-out 短路）；非终态正常
/// 插入；task 不存在 fail-closed。
#[tokio::test]
async fn insert_build_rejects_terminal_task() {
    let (_tmp, store) = tmp_store().await;
    let mk = |task_id: i64| BuildInsert {
        product: "fedora",
        pkg_name: "hello-1.0-1.fc42",
        phase: "pending",
        backend: "chroot",
        user: "alice",
        task_id: Some(task_id),
        ..Default::default()
    };

    let live_task = crate::state::test_state::seed_task(&store, "fedora", "t-live").await;
    store.insert_build(mk(live_task)).await.unwrap();

    for terminal in ["succeeded", "failed", "cancelled", "timeout"] {
        let task_id = crate::state::test_state::seed_task(&store, "fedora", "t-dead").await;
        sqlx::query("UPDATE tasks SET phase = $1 WHERE id = $2")
            .bind(terminal)
            .bind(task_id)
            .execute(store.pool())
            .await
            .unwrap();
        let err = store.insert_build(mk(task_id)).await.unwrap_err();
        match err {
            crate::error::CrbsError::ValidationFailed { message } => {
                assert!(
                    message.contains("terminal"),
                    "unexpected message for {terminal}: {message}"
                );
            }
            other => panic!("expected ValidationFailed for {terminal}, got {other:?}"),
        }
    }

    let err = store.insert_build(mk(999_999)).await.unwrap_err();
    assert!(matches!(
        err,
        crate::error::CrbsError::ValidationFailed { .. }
    ));
}

/// 守卫 INSERT 形态：收口复查-INSERT 语句间隙（裸 INSERT 会给刚终态
/// task 挂可执行 build）。间隙无法单线程复现，用 SQL 形态断言 + 直执
/// 守卫 SQL 的行为断言（绕过先行拒绝的 Rust 复查）。
#[tokio::test]
async fn insert_build_guarded_pins_task_terminal_guard() {
    let (store, _tmp) = create_test_store().await;

    // 形态断言：task 关联带 INSERT...SELECT + EXISTS；裸形态不带守卫。
    let guarded = crate::state::builds::sql::insert_build_guarded(crate::state::Dialect::Sqlite);
    assert!(guarded.contains("INSERT INTO builds"), "got: {guarded}");
    assert!(
        guarded.contains(" SELECT "),
        "must be INSERT...SELECT form, got: {guarded}"
    );
    assert!(
        guarded.contains("EXISTS"),
        "must carry task guard, got: {guarded}"
    );
    assert!(
        guarded.contains("phase NOT IN ('succeeded', 'failed', 'cancelled', 'timeout')"),
        "guard must reject terminal tasks, got: {guarded}"
    );
    let plain = crate::state::builds::sql::insert_build(crate::state::Dialect::Sqlite);
    assert!(
        !plain.contains("EXISTS"),
        "plain form (no task_id) must stay unguarded, got: {plain}"
    );

    // 场景一：终态 task × 活跃 phase → 0 行（守卫在 INSERT 点拒绝）。
    let dead = crate::state::test_state::seed_task(&store, "fedora", "g-dead").await;
    sqlx::query("UPDATE tasks SET phase = 'cancelled' WHERE id = $1")
        .bind(dead)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        exec_guarded_insert(&store, dead, "pending", "g-dead-1.0-1").await,
        None,
        "terminal task must reject runnable build at the INSERT point"
    );

    // 场景二：终态 task × 终态 build（历史记账）→ 放行。
    let hist = exec_guarded_insert(&store, dead, "succeeded", "g-hist-1.0-1")
        .await
        .expect("terminal build row is pure history bookkeeping; must pass");
    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(hist)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "succeeded");

    let live = crate::state::test_state::seed_task(&store, "fedora", "g-live").await;
    assert!(
        exec_guarded_insert(&store, live, "pending", "g-live-1.0-1")
            .await
            .is_some(),
        "active task must accept runnable build"
    );

    // 公共 API 全链路：终态 task × 终态 build 经复查 + 守卫双双放行。
    store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "g-hist2-1.0-1",
            phase: "failed",
            backend: "chroot",
            user: "alice",
            task_id: Some(dead),
            ..Default::default()
        })
        .await
        .unwrap();
}

/// 守卫 SQL 两处终态 IN 字面量与 TERMINAL_BUILD_PHASES 等值——漂移必红
///（单条 contains 抓不到集合分叉）。
#[test]
fn insert_build_guarded_terminal_in_lists_match_terminal_build_phases() {
    use crate::state::test_state::assert_terminal_in_lists;
    assert_terminal_in_lists(
        &crate::state::builds::sql::insert_build_guarded(crate::state::Dialect::Sqlite),
        2,
        "INSERT_BUILD_GUARDED",
    );
}

/// 复查 phase 集合与两个 active 收口索引（`idx_builds_product_pkg_active`
/// partial、`uq_active_builds_identity` unique）的谓词须逐字同序同值：
/// 改值或乱序都令索引退化 SCAN 或收口面与复查判定分叉（查询仍绿、静默
/// 劣化）。集合互比防同处同改漏网，有序 contains 钉防乱序；两侧 baseline
/// 漂移必红。
#[test]
fn exists_active_duplicate_build_phase_set_matches_index_predicates() {
    use crate::state::test_state::sql_in_value_sets;

    // 有序钉（查询侧）：contains 钉住字面量序列。
    assert!(
        crate::state::builds::sql::EXISTS_ACTIVE_DUPLICATE_BUILD
            .contains("phase IN ('pending', 'assigned', 'building')"),
        "phase set/order drifted from the active-duplicate index predicates; \
         update query/baselines in lockstep: {}",
        crate::state::builds::sql::EXISTS_ACTIVE_DUPLICATE_BUILD
    );

    // 集合互比：恰一组 IN 与两侧 baseline 等值；未来加第二组 IN 时
    // len 断言必红。
    let query_sets = sql_in_value_sets(crate::state::builds::sql::EXISTS_ACTIVE_DUPLICATE_BUILD);
    assert_eq!(
        query_sets.len(),
        1,
        "EXISTS_ACTIVE_DUPLICATE_BUILD must carry exactly one IN group \
         (the active phase set), got {query_sets:?}"
    );
    for (dialect, baseline) in [
        ("sqlite", include_str!("../../schema.sql")),
        ("pg", include_str!("../../schema.pg.sql")),
    ] {
        for name in ["idx_builds_product_pkg_active", "uq_active_builds_identity"] {
            let ddl = baseline_index_ddl(baseline, name);
            // DDL 侧有序钉（集合比对抓不到乱序）。
            assert!(
                ddl.contains("phase IN ('pending', 'assigned', 'building')"),
                "{dialect} baseline {name} predicate order drifted \
                 from the duplicate-check query; update query/baselines in lockstep: {ddl}"
            );
            let index_sets = sql_in_value_sets(&ddl);
            assert_eq!(
                index_sets.len(),
                1,
                "{dialect} baseline {name} must carry exactly one IN group \
                 (the active phase set), got {index_sets:?}"
            );
            assert_eq!(
                query_sets[0], index_sets[0],
                "phase set drifted from the index predicate ({name}, {dialect} baseline); \
                 update query/baselines in lockstep: query={:?} index={:?}",
                query_sets[0], index_sets[0]
            );
        }
    }
}

/// 事务内去重：同标识活跃行 → Conflict(409)；异 arch、首行终态后放行；
/// NULL 对 NULL 亦命中（引擎本地构建并发双开形态）。
#[tokio::test]
async fn insert_build_rejects_active_duplicate() {
    let (store, _tmp) = create_test_store().await;
    let task_id = crate::state::test_state::seed_task(&store, "fedora", "hello-1.0-1.fc42").await;
    let mk = |arch: Option<&'static str>| {
        let store = &store;
        async move {
            store
                .insert_build(BuildInsert {
                    product: "fedora",
                    pkg_name: "hello-1.0-1.fc42",
                    phase: "pending",
                    backend: "chroot",
                    user: "alice",
                    arch,
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
        }
    };

    // 同 product+pkg+arch：第二个 pending 插入 → Conflict，消息含三者。
    let first = mk(Some("x86_64")).await.unwrap();
    let err = mk(Some("x86_64")).await.unwrap_err();
    match err {
        crate::error::CrbsError::Conflict { ref message } => {
            assert!(
                message.contains("fedora")
                    && message.contains("hello-1.0-1.fc42")
                    && message.contains("x86_64"),
                "conflict message must identify product/pkg/arch, got: {message}"
            );
        }
        other => panic!("expected Conflict, got {other:?}"),
    }

    // 不同 arch：不冲突（同包多架构 fan-out 的正当形态）。
    mk(Some("aarch64")).await.unwrap();

    // 首个构建转终态（cancelled）后：同标识再插放行（重提交）。
    store.mark_build_cancelled(first).await.unwrap();
    mk(Some("x86_64")).await.unwrap();

    // NULL 对 NULL：本地构建并发双开形态，同样命中去重。
    let _ = mk(None).await.unwrap();
    let err = mk(None).await.unwrap_err();
    assert!(
        matches!(err, crate::error::CrbsError::Conflict { .. }),
        "NULL-arch active duplicate must conflict, got {err:?}"
    );
}

/// 绕过去重直接 INSERT（模拟复查挡不住的并发双插）：uq_active_builds_identity
/// 是提交点唯一收口。NULL-arch / 同 arch 同键二插被拒，异 arch 与终态放行，
/// 冲突可被 is_unique_violation 识别。
#[tokio::test]
async fn uq_active_builds_identity_backstop_beyond_recheck() {
    let (store, _tmp) = create_test_store().await;
    let task_id = crate::state::test_state::seed_task(&store, "fedora", "hello-1.0-1.fc42").await;

    async fn raw_insert(
        store: &StateStore,
        task_id: i64,
        pkg: &str,
        arch: Option<&str>,
        phase: &str,
    ) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO builds (product, pkg_name, phase, backend, \"user\", task_id, arch) \
             VALUES ($1, $2, $3, 'chroot', '', $4, $5)",
        )
        .bind("fedora")
        .bind(pkg)
        .bind(phase)
        .bind(task_id)
        .bind(arch)
        .execute(store.pool())
        .await
        .map(|_| ())
        .map_err(|e| crate::error::CrbsError::Database(format!("insert build: {e}")))
    }

    raw_insert(&store, task_id, "hello-1.0-1.fc42", None, "pending")
        .await
        .unwrap();
    raw_insert(
        &store,
        task_id,
        "hello-1.0-1.fc42",
        Some("x86_64"),
        "pending",
    )
    .await
    .unwrap();

    // 同键 NULL-arch 活跃二插 → 唯一索引兜底拒绝。
    let err = raw_insert(&store, task_id, "hello-1.0-1.fc42", None, "building")
        .await
        .unwrap_err();
    assert!(
        crate::error::is_unique_violation(&err),
        "second active NULL-arch row must violate uq_active_builds_identity, got: {err:?}"
    );

    let err = raw_insert(
        &store,
        task_id,
        "hello-1.0-1.fc42",
        Some("x86_64"),
        "pending",
    )
    .await
    .unwrap_err();
    assert!(
        crate::error::is_unique_violation(&err),
        "second active same-arch row must violate uq_active_builds_identity, got: {err:?}"
    );

    // 异 arch 放行；终态（不进索引谓词）同键重复放行。
    raw_insert(
        &store,
        task_id,
        "hello-1.0-1.fc42",
        Some("aarch64"),
        "pending",
    )
    .await
    .unwrap();
    for phase in ["succeeded", "failed"] {
        raw_insert(&store, task_id, "hello-1.0-1.fc42", None, phase)
            .await
            .unwrap();
    }
}
