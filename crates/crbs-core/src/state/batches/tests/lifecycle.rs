// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 批次与项状态机测试。

use super::common::*;
use super::*;

#[tokio::test]
async fn batch_lifecycle_happy_path_record_roundtrip_and_input_validation() {
    let (store, _tmp) = create_test_store().await;

    for err in [
        store
            .insert_batch(BatchInsert {
                product_id: None,
                created_by: None,
                source_repo_url: "  ",
                dist: None,
                arch_targets_json: None,
                on_failure: "continue",
                force_all: false,
                request_json: None,
            })
            .await
            .unwrap_err(),
        store
            .insert_batch(BatchInsert {
                product_id: None,
                created_by: None,
                source_repo_url: "https://r",
                dist: None,
                arch_targets_json: None,
                on_failure: "halt",
                force_all: false,
                request_json: None,
            })
            .await
            .unwrap_err(),
    ] {
        assert!(
            matches!(err, CrbsError::ValidationFailed { .. }),
            "expected ValidationFailed, got {err:?}"
        );
    }

    let id = store
        .insert_batch(BatchInsert {
            product_id: None,
            created_by: None,
            source_repo_url: "https://example.com/repo",
            dist: Some("el10"),
            arch_targets_json: Some(r#"["x86_64","aarch64"]"#),
            on_failure: "abort",
            force_all: true,
            request_json: Some(r#"{"k":1}"#),
        })
        .await
        .unwrap();
    let rec = store.get_batch(id).await.unwrap().unwrap();
    assert_eq!(rec.status, "preparing", "new batch starts preparing");
    assert_eq!(rec.source_repo_url, "https://example.com/repo");
    assert_eq!(rec.dist.as_deref(), Some("el10"));
    assert_eq!(rec.arch_targets.as_deref(), Some(r#"["x86_64","aarch64"]"#));
    assert_eq!(rec.on_failure, "abort");
    assert!(rec.force_all);
    assert_eq!(rec.request_json.as_deref(), Some(r#"{"k":1}"#));
    assert!(rec.created_at.len() >= 19, "created_at from column DEFAULT");
    assert!(rec.started_at.is_none());
    assert!(rec.finished_at.is_none());
    assert_eq!(
        (
            rec.total_items,
            rec.n_succeeded,
            rec.n_failed,
            rec.n_skipped,
            rec.n_cancelled
        ),
        (0, 0, 0, 0, 0)
    );

    assert!(store.get_batch(-1).await.unwrap().is_none());

    store.set_batch_planning(id).await.unwrap();
    let rec = store.get_batch(id).await.unwrap().unwrap();
    assert_eq!(rec.status, "planning");
    assert!(
        rec.started_at.is_some(),
        "started_at set when leaving preparing"
    );
    assert!(matches!(
        store.set_batch_planning(id).await.unwrap_err(),
        CrbsError::Conflict { .. }
    ));

    store.set_batch_running(id, 0).await.unwrap();
    assert_eq!(store.get_batch(id).await.unwrap().unwrap().total_items, 0);
    assert!(matches!(
        store.set_batch_running(id, 5).await.unwrap_err(),
        CrbsError::Conflict { .. }
    ));
    assert!(matches!(
        store.set_batch_planning(id).await.unwrap_err(),
        CrbsError::Conflict { .. }
    ));

    store
        .finish_batch(id, "completed", Some("all green"))
        .await
        .unwrap();
    let rec = store.get_batch(id).await.unwrap().unwrap();
    assert_eq!(rec.status, "completed");
    assert_eq!(rec.notes.as_deref(), Some("all green"));
    assert!(rec.finished_at.is_some());
    assert!(matches!(
        store.finish_batch(id, "failed", None).await.unwrap_err(),
        CrbsError::Conflict { .. }
    ));

    let err = store.finish_batch(id, "running", None).await.unwrap_err();
    assert!(matches!(err, CrbsError::ValidationFailed { .. }));
    let err = store.finish_batch(-1, "completed", None).await.unwrap_err();
    assert!(matches!(err, CrbsError::NotFound { .. }));
}

/// CAS 余量：preparing 直跳 running 拒、可直接取消收尾；planning 允许 finish（规划失败收口）。
#[tokio::test]
async fn batch_lifecycle_cas_matrix_side_paths() {
    let (store, _tmp) = create_test_store().await;

    let b1 = seed_batch(&store).await;
    assert!(matches!(
        store.set_batch_running(b1, 1).await.unwrap_err(),
        CrbsError::Conflict { .. }
    ));
    store.finish_batch(b1, "cancelled", None).await.unwrap();
    assert_eq!(
        store.get_batch(b1).await.unwrap().unwrap().status,
        "cancelled"
    );

    let b2 = seed_batch(&store).await;
    store.set_batch_planning(b2).await.unwrap();
    store.finish_batch(b2, "failed", None).await.unwrap();
    assert_eq!(store.get_batch(b2).await.unwrap().unwrap().status, "failed");
}

/// 释放门禁：仅 running 批次可释放；重复释放 / 未知项拒。
#[tokio::test]
async fn mark_item_released_gated_on_running_batch() {
    let (store, _tmp) = create_test_store().await;
    let batch = seed_batch(&store).await;
    store.set_batch_planning(batch).await.unwrap();
    store
        .insert_batch_items(
            batch,
            &[NewBatchItem {
                pkg_name: "alpha",
                srpm_nevra: None,
                srpm_staging_path: None,
                round: 0,
            }],
        )
        .await
        .unwrap();
    let item = pending_ids(&store, batch).await.remove(0);

    let batch_prep = seed_batch(&store).await;
    store
        .insert_batch_items(
            batch_prep,
            &[NewBatchItem {
                pkg_name: "alpha",
                srpm_nevra: None,
                srpm_staging_path: None,
                round: 0,
            }],
        )
        .await
        .unwrap();
    let item_prep = pending_ids(&store, batch_prep).await.remove(0);
    assert!(matches!(
        store
            .mark_item_released(batch_prep, item_prep, 1)
            .await
            .unwrap_err(),
        CrbsError::Conflict { .. }
    ));

    let err = store.mark_item_released(batch, item, 1).await.unwrap_err();
    assert!(
        matches!(err, CrbsError::Conflict { .. }),
        "planning gate: {err:?}"
    );

    store.set_batch_running(batch, 1).await.unwrap();
    let task_id = seed_task(&store, "fedora", "alpha").await;
    store
        .mark_item_released(batch, item, task_id)
        .await
        .unwrap();
    let rec = store.items_in_state(batch, "released").await.unwrap();
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0].task_id, Some(task_id));
    assert!(matches!(
        store
            .mark_item_released(batch, item, task_id)
            .await
            .unwrap_err(),
        CrbsError::Conflict { .. }
    ));
    assert!(matches!(
        store
            .mark_item_released(batch, -1, task_id)
            .await
            .unwrap_err(),
        CrbsError::Conflict { .. }
    ));

    assert_eq!(counters(&store, batch).await, (1, 0, 0, 0, 0));
}

#[tokio::test]
async fn mark_item_terminal_counters_strictly_track_states() {
    let (store, _tmp) = create_test_store().await;
    let batch = seed_running_batch(&store, &["p1", "p2", "p3", "p4", "p5"]).await;
    let ids = pending_ids(&store, batch).await;

    // 逐项释放（各挂真 task 行，FK 才放行）。
    let pkgs = ["p1", "p2", "p3", "p4", "p5"];
    for (item, pkg) in ids.iter().zip(pkgs) {
        let task_id = seed_task(&store, "fedora", pkg).await;
        store
            .mark_item_released(batch, *item, task_id)
            .await
            .unwrap();
    }

    let err = store
        .mark_item_terminal(batch, -1, "succeeded", None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, CrbsError::Conflict { .. }));

    let err = store
        .mark_item_terminal(batch, ids[0], "building", None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, CrbsError::ValidationFailed { .. }));

    let outcomes = [
        (0usize, "succeeded", None, None),
        (1, "failed", Some("build_failed"), Some("rpmbuild exited 1")),
        (2, "dep_skipped", Some("dep_failed"), Some("dep p1 failed")),
        (
            3,
            "skipped_conflict",
            Some("noarch_conflict"),
            Some("noarch clash"),
        ),
        (4, "cancelled", None, None),
    ];
    for (idx, state, code, msg) in outcomes {
        store
            .mark_item_terminal(batch, ids[idx], state, code, msg)
            .await
            .unwrap();
    }
    assert_eq!(counters(&store, batch).await, (5, 1, 1, 2, 1));
    let summary = store.batch_item_summary(batch).await.unwrap();
    assert_eq!(
        (
            summary.succeeded,
            summary.failed,
            summary.dep_skipped,
            summary.skipped_conflict,
            summary.cancelled
        ),
        (1, 1, 1, 1, 1)
    );
    assert_eq!(summary.terminal(), 5);

    let failed = store.items_in_state(batch, "failed").await.unwrap();
    assert_eq!(failed[0].error_code.as_deref(), Some("build_failed"));
    assert_eq!(
        failed[0].error_message.as_deref(),
        Some("rpmbuild exited 1")
    );

    let err = store
        .mark_item_terminal(batch, ids[0], "failed", None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, CrbsError::Conflict { .. }));
    assert_eq!(counters(&store, batch).await, (5, 1, 1, 2, 1));

    store.finish_batch(batch, "partial", None).await.unwrap();
}

/// finish 总数对账失败路径：计数器与项状态脱钩时拒绝完成，批次保持原态。
#[tokio::test]
async fn finish_batch_rejects_counter_drift() {
    let (store, _tmp) = create_test_store().await;
    let batch = seed_running_batch(&store, &["d1", "d2"]).await;
    let ids = pending_ids(&store, batch).await;
    for (item, pkg) in ids.iter().zip(["d1", "d2"]) {
        let task_id = seed_task(&store, "fedora", pkg).await;
        store
            .mark_item_released(batch, *item, task_id)
            .await
            .unwrap();
        store
            .mark_item_terminal(batch, *item, "succeeded", None, None)
            .await
            .unwrap();
    }
    assert_eq!(counters(&store, batch).await, (2, 2, 0, 0, 0));

    // 裸 SQL 写坏计数器（模拟漂移）：n_succeeded 虚增 1。
    sqlx::query("UPDATE build_batches SET n_succeeded = 3 WHERE id = $1")
        .bind(batch)
        .execute(store.pool())
        .await
        .unwrap();
    let err = store
        .finish_batch(batch, "completed", None)
        .await
        .unwrap_err();
    match err {
        CrbsError::Internal(message) => {
            assert!(message.contains("counter drift"), "got: {message}");
        }
        other => panic!("expected Internal, got {other:?}"),
    }
    assert_eq!(
        store.get_batch(batch).await.unwrap().unwrap().status,
        "running"
    );

    sqlx::query("UPDATE build_batches SET n_succeeded = 2 WHERE id = $1")
        .bind(batch)
        .execute(store.pool())
        .await
        .unwrap();
    store.finish_batch(batch, "completed", None).await.unwrap();
}

#[tokio::test]
async fn reset_items_to_pending_recovery_round() {
    let (store, _tmp) = create_test_store().await;
    let batch = seed_running_batch(&store, &["r1", "r2", "r3"]).await;
    let ids = pending_ids(&store, batch).await;
    let states = ["failed", "succeeded", "dep_skipped"];
    for (item, (pkg, state)) in ids.iter().zip(["r1", "r2", "r3"].iter().zip(states)) {
        let task_id = seed_task(&store, "fedora", pkg).await;
        store
            .mark_item_released(batch, *item, task_id)
            .await
            .unwrap();
        store
            .mark_item_terminal(batch, *item, state, Some("boom"), Some("b"))
            .await
            .unwrap();
    }
    assert_eq!(counters(&store, batch).await, (3, 1, 1, 1, 0));

    assert_eq!(store.reset_items_to_pending(batch, &[]).await.unwrap(), 0);

    let reset = store
        .reset_items_to_pending(batch, &[ids[0], -1])
        .await
        .unwrap();
    assert_eq!(reset, 1, "non-failed / unknown ids are silently skipped");
    let item = store
        .items_in_state(batch, "pending")
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.id == ids[0])
        .unwrap();
    assert_eq!(item.attempt, 1);
    assert!(item.error_code.is_none() && item.error_message.is_none());
    assert_eq!(counters(&store, batch).await, (3, 1, 0, 1, 0));

    assert_eq!(
        store
            .reset_items_to_pending(batch, &[ids[1]])
            .await
            .unwrap(),
        0
    );

    let task_id = seed_task(&store, "fedora", "r1").await;
    store
        .mark_item_released(batch, ids[0], task_id)
        .await
        .unwrap();
    store
        .mark_item_terminal(batch, ids[0], "failed", Some("boom"), Some("b"))
        .await
        .unwrap();
    let item = store.get_batch(batch).await.unwrap().unwrap();
    assert_eq!((item.n_failed, item.n_succeeded, item.n_skipped), (1, 1, 1));
    assert_eq!(item.total_items, 3);
    let items = store.unfinished_items(batch).await.unwrap();
    assert!(items.is_empty(), "all terminal again");
    let rounds_item = store
        .items_in_state(batch, "failed")
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.id == ids[0])
        .unwrap();
    // attempt = 恢复轮次数：首次 0，一次 reset 后恒 1（重跑再失败不再累加）。
    assert_eq!(rounds_item.attempt, 1);
    store.finish_batch(batch, "partial", None).await.unwrap();
}

/// 取消收尾与恢复轮竞态：批次已终态时 reset 必须 0 行（不得把 failed 翻回
/// pending、不得再减 n_failed——否则终态批次计数漂移且无驱动器收尾）。
#[tokio::test]
async fn reset_items_to_pending_rejects_terminal_batch() {
    let (store, _tmp) = create_test_store().await;
    let batch = seed_running_batch(&store, &["r1"]).await;
    let ids = pending_ids(&store, batch).await;
    let task_id = seed_task(&store, "fedora", "r1").await;
    store
        .mark_item_released(batch, ids[0], task_id)
        .await
        .unwrap();
    store
        .mark_item_terminal(batch, ids[0], "failed", Some("boom"), Some("b"))
        .await
        .unwrap();
    store.finish_batch(batch, "cancelled", None).await.unwrap();

    assert_eq!(
        store
            .reset_items_to_pending(batch, &[ids[0]])
            .await
            .unwrap(),
        0,
        "terminal batch must not resurrect failed items"
    );
    assert_eq!(counters(&store, batch).await, (1, 0, 1, 0, 0));
    assert_eq!(
        store.get_batch(batch).await.unwrap().unwrap().status,
        "cancelled"
    );
}

#[tokio::test]
async fn fail_unfinished_items_sweeps_pending_and_released() {
    let (store, _tmp) = create_test_store().await;
    let batch = seed_running_batch(&store, &["f1", "f2", "f3", "f4"]).await;
    let ids = pending_ids(&store, batch).await;
    let task_id = seed_task(&store, "fedora", "f1").await;
    store
        .mark_item_released(batch, ids[0], task_id)
        .await
        .unwrap();
    store
        .mark_item_terminal(batch, ids[0], "succeeded", None, None)
        .await
        .unwrap();
    let released_task = seed_task(&store, "fedora", "f2").await;
    store
        .mark_item_released(batch, ids[1], released_task)
        .await
        .unwrap();

    let (swept, task_ids) = store
        .fail_unfinished_items(batch, "batch_aborted", "on_failure=abort after f1")
        .await
        .unwrap();
    assert_eq!(swept, 3, "pending + released swept, terminal untouched");
    assert_eq!(
        task_ids,
        vec![released_task],
        "sweep must return the released item's task for cancellation"
    );
    assert_eq!(counters(&store, batch).await, (4, 1, 3, 0, 0));
    for item in store.items_in_state(batch, "failed").await.unwrap() {
        assert_eq!(item.error_code.as_deref(), Some("batch_aborted"));
        assert!(item.error_message.unwrap().contains("abort"));
    }
    assert!(store.unfinished_items(batch).await.unwrap().is_empty());

    assert_eq!(
        store
            .fail_unfinished_items(batch, "batch_aborted", "again")
            .await
            .unwrap(),
        (0, Vec::new())
    );

    store.finish_batch(batch, "failed", None).await.unwrap();
}

/// 派发失败直收终态：pending → skipped_conflict/failed（含计数器）；非 pending 项拒、非法终态名拒。
#[tokio::test]
async fn mark_pending_item_terminal_closes_dispatch_failures() {
    let (store, _tmp) = create_test_store().await;
    let batch = seed_running_batch(&store, &["d1", "d2"]).await;
    let ids = pending_ids(&store, batch).await;

    let err = store
        .mark_pending_item_terminal(batch, ids[0], "building", None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, CrbsError::ValidationFailed { .. }));

    store
        .mark_pending_item_terminal(
            batch,
            ids[0],
            "skipped_conflict",
            Some("active_build_conflict"),
            Some("an active build already exists"),
        )
        .await
        .unwrap();
    store
        .mark_pending_item_terminal(batch, ids[1], "failed", Some("task_create_failed"), None)
        .await
        .unwrap();
    assert_eq!(counters(&store, batch).await, (2, 0, 1, 1, 0));
    let skipped = store
        .items_in_state(batch, "skipped_conflict")
        .await
        .unwrap();
    assert_eq!(
        skipped[0].error_code.as_deref(),
        Some("active_build_conflict")
    );

    // 非 pending（已终态）项二次收口 → Conflict，计数器不漂移。
    assert!(matches!(
        store
            .mark_pending_item_terminal(batch, ids[0], "failed", None, None)
            .await
            .unwrap_err(),
        CrbsError::Conflict { .. }
    ));
    assert_eq!(counters(&store, batch).await, (2, 0, 1, 1, 0));
    store.finish_batch(batch, "partial", None).await.unwrap();
}

/// 取消收尾镜像：pending+released → cancelled、n_cancelled 同步、幂等、finish 对账通过。
#[tokio::test]
async fn cancel_unfinished_items_sweeps_to_cancelled() {
    let (store, _tmp) = create_test_store().await;
    let batch = seed_running_batch(&store, &["c1", "c2", "c3"]).await;
    let ids = pending_ids(&store, batch).await;
    let released_task = seed_task(&store, "fedora", "c1").await;
    store
        .mark_item_released(batch, ids[0], released_task)
        .await
        .unwrap();

    let (swept, task_ids) = store
        .cancel_unfinished_items(batch, "batch_cancelled", "cancelled by tester")
        .await
        .unwrap();
    assert_eq!(swept, 3, "pending + released swept, terminal untouched");
    assert_eq!(
        task_ids,
        vec![released_task],
        "sweep must return the released item's task for cancellation"
    );
    assert_eq!(counters(&store, batch).await, (3, 0, 0, 0, 3));
    for item in store.items_in_state(batch, "cancelled").await.unwrap() {
        assert_eq!(item.error_code.as_deref(), Some("batch_cancelled"));
        assert!(item.error_message.unwrap().contains("tester"));
    }
    assert!(store.unfinished_items(batch).await.unwrap().is_empty());

    assert_eq!(
        store
            .cancel_unfinished_items(batch, "batch_cancelled", "again")
            .await
            .unwrap(),
        (0, Vec::new())
    );
    store.finish_batch(batch, "cancelled", None).await.unwrap();
}
