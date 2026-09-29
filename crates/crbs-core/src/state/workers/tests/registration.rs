// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! Worker 注册、查询与删除。

use super::common::*;
use super::*;

#[tokio::test]
async fn test_delete_worker_cleans_worker_tasks() {
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

    // 唯一删除入口 delete_worker_if_offline：种子为 online，先下线再删；
    // 其附带把名下非终态 build 重置回 pending（本例本就是 pending，不影响断言）。
    store.worker_mark_offline(worker_id).await.unwrap();
    let outcome = store.delete_worker_if_offline(worker_id).await.unwrap();
    assert_eq!(outcome, DeleteWorkerOutcome::Deleted);

    let tasks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks WHERE worker_id = $1")
        .bind(worker_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(tasks, 0);
    let workers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workers WHERE id = $1")
        .bind(worker_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(workers, 0);
}

#[tokio::test]
async fn list_workers_filtered_filters_and_paginates() {
    let (store, _tmp) = create_test_store().await;

    let build_x86_1 = store
        .upsert_worker("build-x86-1", "x86_64", 2, "0.15.0", "online", None)
        .await
        .unwrap();
    store
        .upsert_worker("build-x86-2", "x86_64", 2, "0.15.0", "online", None)
        .await
        .unwrap();
    store
        .upsert_worker("build-arm-1", "aarch64", 4, "0.15.0", "online", None)
        .await
        .unwrap();
    let build_arm_2 = store
        .upsert_worker("build-arm-2", "aarch64", 4, "0.15.0", "online", None)
        .await
        .unwrap();
    // test-x86-1 / build-x86-1 保持 online，供 status 过滤区分在线集。
    store
        .upsert_worker("test-x86-1", "x86_64", 1, "0.15.0", "online", None)
        .await
        .unwrap();
    let test_x86_2 = store
        .upsert_worker("test-x86-2", "x86_64", 1, "0.15.0", "online", None)
        .await
        .unwrap();
    // upsert_worker 固定写 online，离线用 worker_mark_offline 翻转。
    for id in [build_arm_2, test_x86_2] {
        store.worker_mark_offline(id).await.unwrap();
    }

    let got = store
        .list_workers_filtered(&WorkerFilter {
            name: Some("build"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(got.len(), 4);
    assert!(got.iter().all(|w| w.name.starts_with("build-")));

    let got = store
        .list_workers_filtered(&WorkerFilter {
            arch: Some("x86_64"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(got.len(), 4);
    assert!(got.iter().all(|w| w.arch == "x86_64"));

    let got = store
        .list_workers_filtered(&WorkerFilter {
            status: Some("offline"),
            ..Default::default()
        })
        .await
        .unwrap();
    let names: Vec<&str> = got.iter().map(|w| w.name.as_str()).collect();
    assert_eq!(names, vec!["build-arm-2", "test-x86-2"]);

    let got = store
        .list_workers_filtered(&WorkerFilter {
            name: Some("test"),
            arch: Some("x86"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(got.len(), 2);

    // has_secret 派生与无参 list_workers 一致。
    store
        .set_worker_secret(build_x86_1, "hash-1")
        .await
        .unwrap();
    let got = store
        .list_workers_filtered(&WorkerFilter {
            name: Some("build-x86-1"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(got.len(), 1);
    assert!(got[0].has_secret);

    // 分页切片与 list_workers 全量 ORDER BY id 对齐。
    let all = store.list_workers().await.unwrap();
    let page = store
        .list_workers_filtered(&WorkerFilter {
            limit: 2,
            offset: 2,
            ..Default::default()
        })
        .await
        .unwrap();
    let expect: Vec<i64> = all.iter().skip(2).take(2).map(|w| w.id).collect();
    let got: Vec<i64> = page.iter().map(|w| w.id).collect();
    assert_eq!(got, expect);

    // count 与过滤联合，且忽略 limit/offset。
    let count = store
        .count_workers_filtered(&WorkerFilter {
            arch: Some("aarch64"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(count, 2);
    let count = store
        .count_workers_filtered(&WorkerFilter {
            limit: 1,
            offset: 4,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(count, 6);
}

/// LIKE 通配符转义：name/arch 过滤按字面匹配 %/_（"100%" 不命中 "100x"，
/// "x86_64" 不命中 "x86A64"）。
#[tokio::test]
async fn list_workers_filtered_escapes_like_wildcards() {
    let (store, _tmp) = create_test_store().await;
    store
        .upsert_worker("w-100%o2", "x86_64", 2, "0.15.0", "online", None)
        .await
        .unwrap();
    store
        .upsert_worker("w-100x1", "x86_64", 2, "0.15.0", "online", None)
        .await
        .unwrap();
    store
        .upsert_worker("w-other", "x86A64", 2, "0.15.0", "online", None)
        .await
        .unwrap();

    let got = store
        .list_workers_filtered(&WorkerFilter {
            name: Some("100%"),
            ..Default::default()
        })
        .await
        .unwrap();
    let names: Vec<&str> = got.iter().map(|w| w.name.as_str()).collect();
    assert_eq!(names, vec!["w-100%o2"]);

    let got = store
        .list_workers_filtered(&WorkerFilter {
            arch: Some("x86_64"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(got.len(), 2);
    assert!(got.iter().all(|w| w.arch == "x86_64"));
}

/// worker 重新注册（upsert 冲突分支）不得把 suspended/draining 强翻回
/// online——状态只由显式管理操作或 recover_online 改变。
#[tokio::test]
async fn test_upsert_worker_preserves_admin_status() {
    let (store, _tmp) = create_test_store().await;

    let worker_id = store
        .upsert_worker("w-admin-state", "x86_64", 2, "1.0.0", "online", None)
        .await
        .unwrap();
    sqlx::query("UPDATE workers SET status = 'suspended' WHERE id = $1")
        .bind(worker_id)
        .execute(store.pool())
        .await
        .unwrap();

    store
        .upsert_worker("w-admin-state", "x86_64", 4, "1.0.1", "online", None)
        .await
        .unwrap();

    let status: String = sqlx::query_scalar("SELECT status FROM workers WHERE id = $1")
        .bind(worker_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        status, "suspended",
        "re-register must not flip admin status"
    );
}

/// 超时判定三态——心跳过期的 online 被选中；心跳新鲜的 online 不选；
/// 已非 online（即使心跳过期）不选。直接 UPDATE last_heartbeat 到过去构造。
#[tokio::test]
async fn list_offline_workers_selects_timed_out_online_only() {
    let (store, _tmp) = create_test_store().await;
    let stale = store
        .upsert_worker("w-stale", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();
    let _fresh = store
        .upsert_worker("w-fresh", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();
    let offline = store
        .upsert_worker("w-offline", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();

    for id in [stale, offline] {
        age_worker_heartbeat(&store, id, "-300 seconds").await;
    }
    sqlx::query("UPDATE workers SET status = 'offline' WHERE id = $1")
        .bind(offline)
        .execute(store.pool())
        .await
        .unwrap();

    let got = store.list_offline_workers(120).await.unwrap();
    assert_eq!(got, vec![(stale, "w-stale".to_string())]);
}

/// 三态：offline+过龄选中；offline+新鲜、online+过龄不选（归 list_offline_workers）。
#[tokio::test]
async fn list_gone_workers_selects_stale_offline_only() {
    let (store, _tmp) = create_test_store().await;
    let gone = store
        .upsert_worker("w-gone", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();
    let _fresh_offline = store
        .upsert_worker("w-fresh-off", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();
    let stale_online = store
        .upsert_worker("w-stale-on", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();

    store.worker_mark_offline(gone).await.unwrap();
    store.worker_mark_offline(_fresh_offline).await.unwrap();
    for id in [gone, stale_online] {
        age_worker_heartbeat(&store, id, "-300 seconds").await;
    }

    let got = store.list_gone_workers(240).await.unwrap();
    assert_eq!(
        got,
        vec![(gone, "w-gone".to_string())],
        "只选 offline+过龄；offline+新鲜与 online+过龄都不选"
    );
}

/// count_workers_by_arch 按架构聚合注册 / 在线数。online 口径 =
/// status='online' 且 2min 内有心跳（与 count_online_workers 一致）；total 为
/// 全部注册行（workers 硬删除，无 revoked 概念），按 arch 字典序返回。
#[tokio::test]
async fn test_count_workers_by_arch_groups_registration_and_online() {
    let (store, _tmp) = create_test_store().await;

    store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    let w2 = store
        .upsert_worker("w2", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    store
        .upsert_worker("w3", "aarch64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    // 预置未连接行（`crbs-server worker add`）：计入 total，不计入 online。
    store
        .upsert_worker("w4", "loongarch64", 2, "0.15.0-dev", "offline", None)
        .await
        .unwrap();

    store.worker_mark_offline(w2).await.unwrap();
    sqlx::query(&format!(
        "UPDATE workers SET last_heartbeat = {} WHERE name = 'w3'",
        sql_time_offset(store.dialect(), "-10 minutes")
    ))
    .execute(store.pool())
    .await
    .unwrap();

    let rows = store.count_workers_by_arch().await.unwrap();
    let counts: Vec<(String, i64, i64)> = rows
        .iter()
        .map(|r| (r.arch.clone(), r.online, r.total))
        .collect();
    assert_eq!(
        counts,
        vec![
            ("aarch64".into(), 0, 1),
            ("loongarch64".into(), 0, 1),
            ("x86_64".into(), 1, 2),
        ],
        "arch aggregation: {counts:?}"
    );

    let online_sum: i64 = rows.iter().map(|r| r.online).sum();
    assert_eq!(
        online_sum as usize,
        store.count_online_workers(None).await.unwrap()
    );
}
