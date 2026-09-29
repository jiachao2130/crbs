// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 批次写入路径测试。

use super::common::*;
use super::*;

#[tokio::test]
async fn insert_batch_items_bulk_unique_conflict_and_planning_reentry() {
    let (store, _tmp) = create_test_store().await;
    let batch = seed_batch(&store).await;
    store.set_batch_planning(batch).await.unwrap();

    fn rows<'a>(names: &[&'a str]) -> Vec<NewBatchItem<'a>> {
        names
            .iter()
            .enumerate()
            .map(|(i, p)| NewBatchItem {
                pkg_name: p,
                srpm_nevra: None,
                srpm_staging_path: None,
                round: (i % 2) as i64,
            })
            .collect()
    }

    assert_eq!(store.insert_batch_items(batch, &[]).await.unwrap(), 0);
    assert_eq!(
        store
            .insert_batch_items(batch, &rows(&["a", "b", "c"]))
            .await
            .unwrap(),
        3
    );
    assert_eq!(store.batch_rounds(batch).await.unwrap(), vec![0, 1]);
    assert_eq!(store.items_in_round(batch, 0).await.unwrap().len(), 2);
    assert_eq!(store.items_in_round(batch, 1).await.unwrap().len(), 1);
    let summary = store.batch_item_summary(batch).await.unwrap();
    assert_eq!(summary.pending, 3);
    assert_eq!(summary.total(), 3);

    // UNIQUE 冲突归一 Conflict（带包名）；整批回滚不留半写。
    let err = store
        .insert_batch_items(batch, &rows(&["d", "a"]))
        .await
        .unwrap_err();
    match err {
        CrbsError::Conflict { message } => {
            assert!(
                message.contains("'a'"),
                "conflict must name the pkg: {message}"
            );
        }
        other => panic!("expected Conflict, got {other:?}"),
    }
    assert!(store.items_in_state(batch, "pending").await.unwrap().len() == 3);

    assert_eq!(store.delete_batch_items(batch).await.unwrap(), 3);
    assert_eq!(
        store
            .insert_batch_items(batch, &rows(&["x", "y"]))
            .await
            .unwrap(),
        2
    );
    assert_eq!(store.batch_item_summary(batch).await.unwrap().total(), 2);

    // 收口前须把计划项全部终态化（否则总数对账拒绝完成）；终态批次清计划 0 行。
    store.set_batch_running(batch, 2).await.unwrap();
    let ids = pending_ids(&store, batch).await;
    for (item, pkg) in ids.iter().zip(["x", "y"]) {
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
    store.finish_batch(batch, "completed", None).await.unwrap();
    assert_eq!(store.delete_batch_items(batch).await.unwrap(), 0);
    assert_eq!(store.batch_item_summary(batch).await.unwrap().total(), 2);
}

/// 准备期失败项：字段/暂存路径/错误落值、n_failed 同事务同步；notes 仅非终态可写。
#[tokio::test]
async fn insert_failed_batch_items_and_notes_invariants() {
    let (store, _tmp) = create_test_store().await;
    let batch = seed_batch(&store).await;

    assert_eq!(
        store.insert_failed_batch_items(batch, &[]).await.unwrap(),
        0
    );

    let n = store
        .insert_failed_batch_items(
            batch,
            &[
                FailedBatchItem {
                    pkg_name: "bad-pkg",
                    srpm_nevra: Some("bad-pkg-1.0-1.el9.src"),
                    error_code: "srpm_download_failed",
                    error_message: "HTTP 503 after 3 attempts",
                },
                FailedBatchItem {
                    pkg_name: "wet-pkg",
                    srpm_nevra: None,
                    error_code: "disk_below_watermark",
                    error_message: "free space below minimum",
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(n, 2);

    let failed = store.items_in_state(batch, "failed").await.unwrap();
    assert_eq!(failed.len(), 2);
    let bad = failed.iter().find(|i| i.pkg_name == "bad-pkg").unwrap();
    assert_eq!(bad.round, 0);
    assert_eq!(bad.attempt, 0);
    assert_eq!(bad.srpm_staging_path, None);
    assert_eq!(bad.error_code.as_deref(), Some("srpm_download_failed"));
    assert_eq!(
        bad.error_message.as_deref(),
        Some("HTTP 503 after 3 attempts")
    );

    assert_eq!(counters(&store, batch).await, (0, 0, 2, 0, 0));

    store
        .set_batch_notes(batch, "skipped(already built): a, b")
        .await
        .unwrap();
    assert_eq!(
        store
            .get_batch(batch)
            .await
            .unwrap()
            .unwrap()
            .notes
            .as_deref(),
        Some("skipped(already built): a, b")
    );
    let done = seed_batch(&store).await;
    store.finish_batch(done, "cancelled", None).await.unwrap();
    assert!(matches!(
        store.set_batch_notes(done, "late").await.unwrap_err(),
        CrbsError::Conflict { .. }
    ));
}

/// plan 期架构跳过落账：直插终态 arch_skipped（保留暂存路径 + 原因），
/// n_skipped 随 bump、summary 聚合计数、finish 对账（arch_skipped 计 skipped
/// 桶、零 failed → completed）；空行集幂等；终态批次拒写。
#[tokio::test]
async fn insert_arch_skipped_items_land_terminal_with_n_skipped() {
    let (store, _tmp) = create_test_store().await;
    let batch = seed_batch(&store).await;
    store.set_batch_planning(batch).await.unwrap();

    // 空行集幂等（plan 常见路径：无跳过项时不开事务）。
    assert_eq!(
        store
            .insert_arch_skipped_batch_items(batch, &[])
            .await
            .unwrap(),
        0
    );

    let rows = vec![
        SkippedBatchItem {
            pkg_name: "exc-1.0-1",
            srpm_nevra: Some("exc-1.0-1"),
            srpm_staging_path: Some("/staging/exc-1.0-1.src.rpm"),
            error_code: "arch_unsupported",
            error_message: "x86_64: not in ExclusiveArch [aarch64]",
        },
        SkippedBatchItem {
            pkg_name: "excl-1.0-1",
            srpm_nevra: Some("excl-1.0-1"),
            srpm_staging_path: Some("/staging/excl-1.0-1.src.rpm"),
            error_code: "arch_unsupported",
            error_message: "x86_64: excluded by ExcludeArch [x86_64]",
        },
    ];
    assert_eq!(
        store
            .insert_arch_skipped_batch_items(batch, &rows)
            .await
            .unwrap(),
        2
    );

    // 终态行：状态/原因/暂存路径齐；计数器 n_skipped=2。
    let skipped = store.items_in_state(batch, "arch_skipped").await.unwrap();
    assert_eq!(skipped.len(), 2);
    assert_eq!(skipped[0].error_code.as_deref(), Some("arch_unsupported"));
    assert!(skipped[0]
        .error_message
        .as_deref()
        .unwrap()
        .contains("ExclusiveArch"));
    assert_eq!(
        skipped[0].srpm_staging_path.as_deref(),
        Some("/staging/exc-1.0-1.src.rpm")
    );
    assert!(matches!(
        store.unfinished_items(batch).await.unwrap().as_slice(),
        []
    ));
    // 计数前置：n_skipped 已 bump，total_items 待交棒（set_batch_running）落定。
    assert_eq!(counters(&store, batch).await, (0, 0, 0, 2, 0));

    // summary 聚合口径：arch_skipped 单列且 terminal/total 计入。
    let summary = store.batch_item_summary(batch).await.unwrap();
    assert_eq!(summary.arch_skipped, 2);
    assert_eq!(summary.terminal(), 2);
    assert_eq!(summary.total(), 2);

    // 交棒 running 后由 driver 收口：零 failed → completed 对账通过。
    store.set_batch_running(batch, 2).await.unwrap();
    assert_eq!(counters(&store, batch).await, (2, 0, 0, 2, 0));
    store.finish_batch(batch, "completed", None).await.unwrap();

    // 终态批次拒写。
    assert!(matches!(
        store
            .insert_arch_skipped_batch_items(
                batch,
                &[SkippedBatchItem {
                    pkg_name: "late",
                    srpm_nevra: None,
                    srpm_staging_path: None,
                    error_code: "arch_unsupported",
                    error_message: "late",
                }],
            )
            .await
            .unwrap_err(),
        CrbsError::Conflict { .. }
    ));
}

/// plan 失败/取消收口：清空计划必须回退 arch_skipped 的 n_skipped，否则
/// finish_batch 对账永久拒绝、批次卡在 planning 占配额。
#[tokio::test]
async fn clear_batch_items_rolls_back_skipped_counter() {
    let (store, _tmp) = create_test_store().await;
    let batch = seed_batch(&store).await;
    store.set_batch_planning(batch).await.unwrap();
    let rows = [SkippedBatchItem {
        pkg_name: "arch-skipped-1.0-1",
        srpm_nevra: Some("arch-skipped-1.0-1"),
        srpm_staging_path: Some("/staging/arch-skipped-1.0-1.src.rpm"),
        error_code: "arch_unsupported",
        error_message: "not in target arch",
    }];
    store
        .insert_arch_skipped_batch_items(batch, &rows)
        .await
        .unwrap();
    assert_eq!(counters(&store, batch).await, (0, 0, 0, 1, 0));

    let cleared = store
        .clear_batch_items_rollback_counters(batch)
        .await
        .unwrap();
    assert_eq!(cleared.len(), 1);
    assert_eq!(cleared[0].state, "arch_skipped");
    assert!(store
        .items_in_state(batch, "arch_skipped")
        .await
        .unwrap()
        .is_empty());
    assert_eq!(counters(&store, batch).await, (0, 0, 0, 0, 0));
    store.finish_batch(batch, "failed", None).await.unwrap();
}

/// product_id 外键 roundtrip：真实产品行挂批次后 record 透出 Some(id)。
#[tokio::test]
async fn insert_batch_with_product_fk_roundtrip() {
    let (store, _tmp) = create_test_store().await;
    sqlx::query(
        "INSERT INTO products (id, name, visibility, config_json, revision, base_os_revision) \
         VALUES ($1, 'batchprod', 'public', '{}', 1, 1)",
    )
    .bind(7i64)
    .execute(store.pool())
    .await
    .unwrap();
    let id = store
        .insert_batch(BatchInsert {
            product_id: Some(7),
            created_by: None,
            source_repo_url: "https://example.com/repo",
            dist: None,
            arch_targets_json: None,
            on_failure: "continue",
            force_all: false,
            request_json: None,
        })
        .await
        .unwrap();
    let rec = store.get_batch(id).await.unwrap().unwrap();
    assert_eq!(rec.product_id, Some(7));
    assert_eq!(rec.created_by, None);
}

fn quota_batch_insert(product_id: Option<i64>) -> BatchInsert<'static> {
    BatchInsert {
        product_id,
        created_by: None,
        source_repo_url: "https://example.com/repo",
        dist: None,
        arch_targets_json: None,
        on_failure: "continue",
        force_all: false,
        request_json: None,
    }
}

/// 配额守卫的原子性回归门：全局上限 2、已有 1 个在途时，两个不同产品
/// 并发抢最后一个名额——check-then-insert 会双双越过上限，事务内复查
/// （SQLite BEGIN IMMEDIATE 串行化）必须恰好一败。
#[tokio::test]
async fn insert_batch_quota_checked_serializes_concurrent_global_cap() {
    let (store, _tmp) = create_test_store().await;
    let store = std::sync::Arc::new(store);
    for (id, name) in [(7i64, "qp-a"), (8, "qp-b"), (9, "qp-c")] {
        sqlx::query(
            "INSERT INTO products (id, name, visibility, config_json, revision, base_os_revision) \
             VALUES ($1, $2, 'public', '{}', 1, 1)",
        )
        .bind(id)
        .bind(name)
        .execute(store.pool())
        .await
        .unwrap();
    }
    store
        .insert_batch_quota_checked(quota_batch_insert(Some(7)), 2)
        .await
        .unwrap();

    let a = {
        let store = store.clone();
        tokio::spawn(async move {
            store
                .insert_batch_quota_checked(quota_batch_insert(Some(8)), 2)
                .await
        })
    };
    let b = {
        let store = store.clone();
        tokio::spawn(async move {
            store
                .insert_batch_quota_checked(quota_batch_insert(Some(9)), 2)
                .await
        })
    };
    let (ra, rb) = (a.await.unwrap(), b.await.unwrap());
    let ok = [&ra, &rb].iter().filter(|r| r.is_ok()).count();
    let conflicts = [&ra, &rb]
        .iter()
        .filter(|r| matches!(r, Err(CrbsError::Conflict { .. })))
        .count();
    assert_eq!(
        (ok, conflicts),
        (1, 1),
        "exactly one cross-product submission may pass: {ra:?} {rb:?}"
    );
    assert_eq!(
        store.count_active_batches().await.unwrap(),
        2,
        "global cap must not be exceeded"
    );
}

/// 每产品单活由事务内复查拒绝（唯一索引仍是提交点兜底）。
#[tokio::test]
async fn insert_batch_quota_checked_rejects_second_active_for_product() {
    let (store, _tmp) = create_test_store().await;
    sqlx::query(
        "INSERT INTO products (id, name, visibility, config_json, revision, base_os_revision) \
         VALUES ($1, 'qp-single', 'public', '{}', 1, 1)",
    )
    .bind(7i64)
    .execute(store.pool())
    .await
    .unwrap();
    store
        .insert_batch_quota_checked(quota_batch_insert(Some(7)), 2)
        .await
        .unwrap();
    let err = store
        .insert_batch_quota_checked(quota_batch_insert(Some(7)), 2)
        .await
        .unwrap_err();
    assert!(
        matches!(err, CrbsError::Conflict { ref message } if message.contains("already has an active batch")),
        "per-product quota must reject: {err:?}"
    );
    assert_eq!(store.count_active_batches().await.unwrap(), 1);
}
