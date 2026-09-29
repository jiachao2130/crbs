// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 批次查询测试。

use super::common::*;
use super::*;

#[tokio::test]
async fn active_batch_queries_and_listing() {
    let (store, _tmp) = create_test_store().await;

    // 产品行先建（FK 强制）；A: running + 终态，B: preparing，C: 无批次。
    for pid in [101, 202] {
        sqlx::query(
            "INSERT INTO products (id, name, visibility, config_json, revision, \
             base_os_revision) VALUES ($1, $2, 'public', '{}', 1, 1)",
        )
        .bind(pid)
        .bind(format!("p{pid}"))
        .execute(store.pool())
        .await
        .unwrap();
    }
    let a_running = seed_running_batch(&store, &["a1"]).await;
    sqlx::query("UPDATE build_batches SET product_id = 101 WHERE id = $1")
        .bind(a_running)
        .execute(store.pool())
        .await
        .unwrap();
    let a_done = seed_batch(&store).await;
    store.set_batch_planning(a_done).await.unwrap();
    store.finish_batch(a_done, "completed", None).await.unwrap();
    // 终态后才能挂到同一产品（活跃期受每产品单活唯一索引约束）。
    sqlx::query("UPDATE build_batches SET product_id = 101 WHERE id = $1")
        .bind(a_done)
        .execute(store.pool())
        .await
        .unwrap();
    let b_preparing = seed_batch(&store).await;
    sqlx::query("UPDATE build_batches SET product_id = 202 WHERE id = $1")
        .bind(b_preparing)
        .execute(store.pool())
        .await
        .unwrap();

    assert_eq!(
        store.active_batch_for_product(101).await.unwrap(),
        Some(a_running),
        "terminal batch excluded, active returned"
    );
    assert_eq!(
        store.active_batch_for_product(202).await.unwrap(),
        Some(b_preparing)
    );
    assert_eq!(store.active_batch_for_product(303).await.unwrap(), None);
    assert_eq!(store.count_active_batches().await.unwrap(), 2);

    let newest_first = store.list_batches(1).await.unwrap();
    assert_eq!(newest_first.len(), 1);
    assert_eq!(newest_first[0].id, b_preparing);
    assert!(store.list_batches(0).await.unwrap().is_empty());
    assert!(store.list_batches(-1).await.unwrap().is_empty());
    let all = store.list_batches(10).await.unwrap();
    let mut sorted = all.iter().map(|b| b.id).collect::<Vec<_>>();
    sorted.sort_unstable();
    assert_eq!(sorted.len(), 3);

    let active = store
        .list_batches_in_status(&["preparing", "planning", "running"])
        .await
        .unwrap();
    let ids: Vec<i64> = active.iter().map(|b| b.id).collect();
    assert_eq!(
        ids,
        vec![a_running, b_preparing],
        "id ASC, terminal excluded"
    );
    assert_eq!(
        store.list_batches_in_status(&["completed"]).await.unwrap()[0].id,
        a_done
    );
    assert!(store.list_batches_in_status(&[]).await.unwrap().is_empty());
}
