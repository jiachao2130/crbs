// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 批次与批次项查询。

use super::sql;
use super::types::{BatchItemRecord, BatchProgress, BatchRecord};
use crate::error::DbResultExt;
use crate::state::StateStore;
use sqlx::any::AnyRow;
use sqlx::Row;

/// 按列名解码批次行（列名与 [`sql::BATCH_COLUMNS`] 对齐，漂移即 `try_get` 经 db_ctx 报错浮出）。
pub(super) fn batch_from_row(mut row: AnyRow) -> crate::Result<BatchRecord> {
    const CTX: &str = "decode batch row";
    let opt = |row: &mut AnyRow, col: &'static str| -> crate::Result<Option<String>> {
        row.try_get::<Option<String>, _>(col).db_ctx(CTX)
    };
    Ok(BatchRecord {
        id: row.try_get::<i64, _>("id").db_ctx(CTX)?,
        product_id: row.try_get::<Option<i64>, _>("product_id").db_ctx(CTX)?,
        created_by: row.try_get::<Option<i64>, _>("created_by").db_ctx(CTX)?,
        status: row.try_get::<String, _>("status").db_ctx(CTX)?,
        source_repo_url: row.try_get::<String, _>("source_repo_url").db_ctx(CTX)?,
        source_fingerprint: opt(&mut row, "source_fingerprint")?,
        dist: opt(&mut row, "dist")?,
        arch_targets: opt(&mut row, "arch_targets")?,
        on_failure: row.try_get::<String, _>("on_failure").db_ctx(CTX)?,
        force_all: row.try_get::<i64, _>("force_all").db_ctx(CTX)? != 0,
        total_items: row.try_get::<i64, _>("total_items").db_ctx(CTX)?,
        n_succeeded: row.try_get::<i64, _>("n_succeeded").db_ctx(CTX)?,
        n_failed: row.try_get::<i64, _>("n_failed").db_ctx(CTX)?,
        n_skipped: row.try_get::<i64, _>("n_skipped").db_ctx(CTX)?,
        n_cancelled: row.try_get::<i64, _>("n_cancelled").db_ctx(CTX)?,
        request_json: opt(&mut row, "request_json")?,
        notes: opt(&mut row, "notes")?,
        created_at: row.try_get::<String, _>("created_at").db_ctx(CTX)?,
        started_at: opt(&mut row, "started_at")?,
        finished_at: opt(&mut row, "finished_at")?,
    })
}

/// 按列名解码批次项行（列名与 [`sql::ITEM_COLUMNS`] 清单对齐）。
pub(super) fn item_from_row(row: AnyRow) -> crate::Result<BatchItemRecord> {
    const CTX: &str = "decode batch item row";
    Ok(BatchItemRecord {
        id: row.try_get::<i64, _>("id").db_ctx(CTX)?,
        batch_id: row.try_get::<i64, _>("batch_id").db_ctx(CTX)?,
        pkg_name: row.try_get::<String, _>("pkg_name").db_ctx(CTX)?,
        srpm_nevra: row.try_get::<Option<String>, _>("srpm_nevra").db_ctx(CTX)?,
        srpm_staging_path: row
            .try_get::<Option<String>, _>("srpm_staging_path")
            .db_ctx(CTX)?,
        round: row.try_get::<i64, _>("round").db_ctx(CTX)?,
        state: row.try_get::<String, _>("state").db_ctx(CTX)?,
        attempt: row.try_get::<i64, _>("attempt").db_ctx(CTX)?,
        task_id: row.try_get::<Option<i64>, _>("task_id").db_ctx(CTX)?,
        error_code: row.try_get::<Option<String>, _>("error_code").db_ctx(CTX)?,
        error_message: row
            .try_get::<Option<String>, _>("error_message")
            .db_ctx(CTX)?,
        updated_at: row.try_get::<String, _>("updated_at").db_ctx(CTX)?,
    })
}

impl StateStore {
    /// 按 id 取单条批次记录（`build_batches` 全列，计数器口径见模块契约）；不存在 None。
    pub async fn get_batch(&self, id: i64) -> crate::Result<Option<BatchRecord>> {
        let row = sqlx::query(&sql::batch_by_id())
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("get batch")?;
        row.map(batch_from_row).transpose()
    }

    /// 批次列表（id DESC）；`limit <= 0` 返回空（PG 拒负 LIMIT），调用方须在上游绑定上限（对齐 pagination_clause）。
    pub async fn list_batches(&self, limit: i64) -> crate::Result<Vec<BatchRecord>> {
        if limit <= 0 {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(&sql::list_batches())
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list batches")?;
        rows.into_iter().map(batch_from_row).collect()
    }

    /// 产品的在途批次（preparing/planning/running）id，无则 None。
    pub async fn active_batch_for_product(&self, product_id: i64) -> crate::Result<Option<i64>> {
        sqlx::query_scalar(sql::ACTIVE_BATCH_FOR_PRODUCT)
            .bind(product_id)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("get active batch for product")
    }

    /// 全库在途批次计数（preparing/planning/running）。
    pub async fn count_active_batches(&self) -> crate::Result<i64> {
        sqlx::query_scalar(sql::COUNT_ACTIVE_BATCHES)
            .fetch_one(&self.pool)
            .await
            .db_ctx("count active batches")
    }

    /// 某拓扑轮次的全部项（id ASC）。
    pub async fn items_in_round(
        &self,
        batch_id: i64,
        round: i64,
    ) -> crate::Result<Vec<BatchItemRecord>> {
        let rows = sqlx::query(&sql::items_in_round())
            .bind(batch_id)
            .bind(round)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list batch items in round")?;
        rows.into_iter().map(item_from_row).collect()
    }

    /// 批次的拓扑轮次去重清单（升序）。
    pub async fn batch_rounds(&self, batch_id: i64) -> crate::Result<Vec<i64>> {
        sqlx::query_scalar(sql::BATCH_ROUNDS)
            .bind(batch_id)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list batch rounds")
    }

    /// 项状态计数聚合（进度看板与 total_items 对账用）。
    pub async fn batch_item_summary(&self, batch_id: i64) -> crate::Result<BatchProgress> {
        let row = sqlx::query(sql::batch_item_summary())
            .bind(batch_id)
            .fetch_one(&self.pool)
            .await
            .db_ctx("get batch item summary")?;
        let dec = |col: &'static str| -> crate::Result<i64> {
            row.try_get::<i64, _>(col).db_ctx("decode batch summary")
        };
        Ok(BatchProgress {
            pending: dec("pending")?,
            released: dec("released")?,
            succeeded: dec("succeeded")?,
            failed: dec("failed")?,
            failed_with_task: dec("failed_with_task")?,
            dep_skipped: dec("dep_skipped")?,
            skipped_conflict: dec("skipped_conflict")?,
            arch_skipped: dec("arch_skipped")?,
            cancelled: dec("cancelled")?,
        })
    }

    /// 处于指定状态的项（id ASC）；非法 state 查不出行（不额外校验）。
    pub async fn items_in_state(
        &self,
        batch_id: i64,
        state: &str,
    ) -> crate::Result<Vec<BatchItemRecord>> {
        let rows = sqlx::query(&sql::items_in_state())
            .bind(batch_id)
            .bind(state)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list batch items in state")?;
        rows.into_iter().map(item_from_row).collect()
    }

    /// 按状态集列批次（id ASC，启动对账扫崩溃残留）；空状态集返回空（IN () 双方言非法，Rust 侧短路）。
    pub async fn list_batches_in_status(
        &self,
        statuses: &[&str],
    ) -> crate::Result<Vec<BatchRecord>> {
        if statuses.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = crate::state::db::in_placeholders(1, statuses.len())?;
        let statement = format!(
            "SELECT {} FROM build_batches WHERE status IN ({placeholders}) ORDER BY id ASC",
            sql::BATCH_COLUMNS
        );
        let mut query = sqlx::query(&statement);
        for s in statuses {
            query = query.bind(s);
        }
        let rows = query
            .fetch_all(&self.pool)
            .await
            .db_ctx("list batches in status")?;
        rows.into_iter().map(batch_from_row).collect()
    }

    /// 批次的未完成项（pending / released，id ASC）——崩溃恢复的事实源。
    pub async fn unfinished_items(&self, batch_id: i64) -> crate::Result<Vec<BatchItemRecord>> {
        let rows = sqlx::query(&sql::unfinished_items())
            .bind(batch_id)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list unfinished batch items")?;
        rows.into_iter().map(item_from_row).collect()
    }
}
