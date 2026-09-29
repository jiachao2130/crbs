// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 批次 state 测试共享夹具。

use super::*;

/// 建一个 preparing 批次（全 NULL 可空外键，最短夹具）。
pub(super) async fn seed_batch(store: &StateStore) -> i64 {
    store
        .insert_batch(BatchInsert {
            product_id: None,
            created_by: None,
            source_repo_url: "https://example.com/repo",
            dist: None,
            arch_targets_json: None,
            on_failure: "continue",
            force_all: false,
            request_json: None,
        })
        .await
        .unwrap()
}

/// 建一个 running 批次：pkgs 各一项，round 按奇偶分成 0/1 两轮。
pub(super) async fn seed_running_batch(store: &StateStore, pkgs: &[&str]) -> i64 {
    let id = seed_batch(store).await;
    store.set_batch_planning(id).await.unwrap();
    let rows: Vec<NewBatchItem> = pkgs
        .iter()
        .enumerate()
        .map(|(i, p)| NewBatchItem {
            pkg_name: p,
            srpm_nevra: None,
            srpm_staging_path: None,
            round: (i % 2) as i64,
        })
        .collect();
    store.insert_batch_items(id, &rows).await.unwrap();
    store
        .set_batch_running(id, pkgs.len() as i64)
        .await
        .unwrap();
    id
}

/// 批次内所有 pending 项的 id（id ASC）。
pub(super) async fn pending_ids(store: &StateStore, batch_id: i64) -> Vec<i64> {
    store
        .items_in_state(batch_id, "pending")
        .await
        .unwrap()
        .into_iter()
        .map(|i| i.id)
        .collect()
}

/// 直读批次计数器（对账断言用，不经 record 映射）。
pub(super) async fn counters(store: &StateStore, batch_id: i64) -> (i64, i64, i64, i64, i64) {
    sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(
        "SELECT total_items, n_succeeded, n_failed, n_skipped, n_cancelled \
         FROM build_batches WHERE id = $1",
    )
    .bind(batch_id)
    .fetch_one(store.pool())
    .await
    .unwrap()
}
