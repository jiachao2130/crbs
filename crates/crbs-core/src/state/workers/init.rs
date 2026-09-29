// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Worker 状态存储方法。

use super::*;
use crate::state::rollback_and_return;

impl StateStore {
    /// 事务内原子检查并分配 init 任务（TOCTOU 防护）：查活跃 build → 查活跃
    /// init → 插入，冲突返回 `Ok(Err(InitConflict))`，不做 HTTP 语义映射。
    pub async fn try_assign_init_to_worker(
        &self,
        worker_id: i64,
        product: &str,
    ) -> crate::Result<Result<i64, InitConflict>> {
        // 读-then-写：DEFERRED 事务先读后写撞不可重试 SQLITE_BUSY_SNAPSHOT，begin_write() 先拿写锁。
        let mut conn = self.begin_write().await?;

        // BEGIN 后任何错误（含 COMMIT 失败）返回前先 ROLLBACK，避免带写锁连接回池（SQLite/PG 池污染）。
        let building_count: i64 = match sqlx::query_scalar(sql::COUNT_WORKER_BUILDING_FOR_PRODUCT)
            .bind(worker_id)
            .bind(product)
            .fetch_one(&mut *conn)
            .await
            .db_ctx("count worker building builds for product")
        {
            Ok(v) => v,
            Err(e) => rollback_and_return!(conn, e),
        };
        if building_count > 0 {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Ok(Err(InitConflict::Building(building_count)));
        }

        let has_init = match sqlx::query_scalar::<_, i64>(sql::HAS_ACTIVE_INIT)
            .bind(worker_id)
            .bind(product)
            .fetch_optional(&mut *conn)
            .await
            .db_ctx("check active init in tx")
        {
            Ok(v) => v,
            Err(e) => rollback_and_return!(conn, e),
        };
        if has_init.is_some() {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Ok(Err(InitConflict::AlreadyActive));
        }

        let assignment_id =
            match sqlx::query_scalar::<_, i64>(&sql::insert_init_assignment(self.dialect))
                .bind(worker_id)
                .bind(product)
                .fetch_one(&mut *conn)
                .await
                .db_ctx("assign init in tx")
            {
                Ok(v) => v,
                // PG 并发双插被 uq_worker_tasks_active_init 拒绝 → 已活跃。
                Err(e)
                    if crate::error::is_unique_violation(&crate::error::CrbsError::Database(
                        e.to_string(),
                    )) =>
                {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    return Ok(Err(InitConflict::AlreadyActive));
                }
                Err(e) => rollback_and_return!(conn, e),
            };

        match sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit tx")
        {
            Ok(_) => {}
            Err(e) => rollback_and_return!(conn, e),
        }

        // 新 init assignment 迁移即广播；冲突分支未落行，不广播。
        self.notify_state_changed();
        Ok(Ok(assignment_id))
    }

    /// 统计指定 Worker 上特定 product 的活跃 build assignment 数（活跃 = kind='build'
    /// 且 builds.phase 未终结，非 succeeded/failed/cancelled/timeout）。per-product
    /// init gating 用：仍有已承诺 build 即拒 init，避免与持旧 base_os 引用的 build 并发。
    pub async fn count_worker_building_builds_for_product(
        &self,
        worker_id: i64,
        product: &str,
    ) -> crate::Result<i64> {
        let count: i64 = sqlx::query_scalar(sql::COUNT_WORKER_BUILDING_FOR_PRODUCT)
            .bind(worker_id)
            .bind(product)
            .fetch_one(self.pool())
            .await
            .db_ctx("count worker building builds for product")?;

        Ok(count)
    }

    /// 判断指定 (worker, product) 是否存在尚未完成的 init assignment（status
    /// 'assigned'/'running' 即活跃），有则 dispatch 暂不派发该 product 的 build，直到 init 完成。
    pub async fn has_active_init(&self, worker_id: i64, product: &str) -> crate::Result<bool> {
        let row: Option<(i64,)> = sqlx::query_as(sql::HAS_ACTIVE_INIT)
            .bind(worker_id)
            .bind(product)
            .fetch_optional(self.pool())
            .await
            .db_ctx("has active init")?;

        Ok(row.is_some())
    }

    /// 标记 init assignment 完成（成功或失败）。不触碰 builds 表（init 无 build
    /// 行）；SQL 终态守卫（仅 assigned/running 可落终态）使重复上报为幂等 no-op。
    /// `result_json` 与 `success` 一致：成功 `{"success": true}`，失败 `{"error": ...}`。
    pub async fn complete_init_assignment(
        &self,
        assignment_id: i64,
        success: bool,
        error: Option<&str>,
    ) -> crate::Result<()> {
        let status = if success { "completed" } else { "failed" };
        let result_json = if success {
            serde_json::json!({ "success": true }).to_string()
        } else {
            let detail = error.unwrap_or("init failed without error detail");
            serde_json::json!({ "error": detail }).to_string()
        };
        sqlx::query(&sql::complete_init_assignment(self.dialect))
            .bind(status)
            .bind(&result_json)
            .bind(assignment_id)
            .execute(&self.pool)
            .await
            .db_ctx("complete init assignment")?;

        // init 落终态即广播。
        self.notify_state_changed();
        Ok(())
    }
}
