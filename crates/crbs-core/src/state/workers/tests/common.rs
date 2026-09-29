// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! Worker 状态测试共享夹具：构建/心跳数据播种与查询辅助。

use super::*;

/// 读 build 的 started_at（RFC3339 定宽 UTC TEXT，字典序即时序）。
pub(super) async fn build_started_at(store: &StateStore, id: i64) -> String {
    sqlx::query_scalar("SELECT started_at FROM builds WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap()
}

/// 回收测试夹具：心跳回拨到 offset 之前——回收事务内首条语句复查心跳新鲜度，
/// 新鲜心跳整轮跳过（空回收），回收测试必须先造"失联"前提。
pub(super) async fn age_worker_heartbeat(store: &StateStore, worker_id: i64, offset: &str) {
    sqlx::query(&format!(
        "UPDATE workers SET last_heartbeat = {} WHERE id = $1",
        sql_time_offset(store.dialect(), offset)
    ))
    .bind(worker_id)
    .execute(store.pool())
    .await
    .unwrap();
}

// 插入 building build + running worker_tasks 行；status 用生命周期词汇（'running'），
// 不 verbatim 写 builds.phase（COUNT_WORKER_BUILDING_FOR_PRODUCT 经 JOIN b.phase 过滤）。
// arch 由调用方传入：同 product+pkg+arch 活跃去重，同产品多种子须错开 arch。
pub(super) async fn seed_building(
    store: &StateStore,
    worker_id: i64,
    product: &str,
    arch: &str,
) -> i64 {
    let task_id = crate::state::test_state::seed_task(store, product, "pkg").await;
    let build_id = seed_build(
        store,
        product,
        "pkg",
        "pending",
        arch,
        PRIORITY_DEFAULT,
        task_id,
    )
    .await;
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
        .bind(build_id)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE worker_tasks SET status = 'running' WHERE build_id = $1")
        .bind(build_id)
        .execute(store.pool())
        .await
        .unwrap();
    build_id
}

/// 夹具：直插一条遥测采样行（浮点以 SQL 字面量落列，规避 Any 驱动浮点绑定
/// 钉型坑；时间走 sql_time_offset 双方言渲染）。
pub(super) async fn seed_telemetry_sample(
    store: &StateStore,
    worker_id: i64,
    offset: &str,
    cpu: f64,
) {
    sqlx::query(&format!(
        "INSERT INTO worker_telemetry_samples \
         (worker_id, sampled_at, cpu_util_pct, mem_used_pct, load1, ncpu, mem_total_kb) \
         VALUES ($1, {}, {cpu}, 40.0, 1.5, 8, 16000000)",
        sql_time_offset(store.dialect(), offset),
    ))
    .bind(worker_id)
    .execute(store.pool())
    .await
    .unwrap();
}

pub(super) async fn sample_count(store: &StateStore, worker_id: i64) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM worker_telemetry_samples WHERE worker_id = $1")
        .bind(worker_id)
        .fetch_one(store.pool())
        .await
        .unwrap()
}
