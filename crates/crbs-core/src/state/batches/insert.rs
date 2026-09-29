// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 批次行与批次项写入。

use super::sql::{self, PG_BATCH_QUOTA_LOCK_SQL};
use super::types::{BatchInsert, FailedBatchItem, NewBatchItem, SkippedBatchItem};
use crate::error::{CrbsError, DbResultExt};
use crate::state::{rollback_and_return, StateStore};

/// item 插入的终态守卫（调用方 BEGIN 后、插入前调用）：批次被孤儿清扫/取消收口后，
/// 迟到的 prepare 后台任务不得再写入悬空 item 行——行会挂在无 driver 消费的终态
/// 批次下，污染计数与列表。活跃三态放行，终态或行缺失拒插；事务语义由调用方的
/// `rollback_and_return!` 收口。隔离边界：SQLite `begin_write` 持写锁天然串行；
/// PG READ COMMITTED 有"守卫过→sweep finish→插入提交"理论窗口（触发需心跳停更
/// ≥600s），残余仅 n_failed 计数漂移。
async fn ensure_batch_not_terminal(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    batch_id: i64,
) -> crate::Result<()> {
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM build_batches WHERE id = $1")
            .bind(batch_id)
            .fetch_optional(&mut **conn)
            .await
            .db_ctx("guard: read batch status for item insert")?;
    match status.as_deref() {
        Some("preparing" | "planning" | "running") => Ok(()),
        Some(other) => Err(CrbsError::Conflict {
            message: format!("batch {batch_id} already terminal ('{other}'); refusing item insert"),
        }),
        None => Err(CrbsError::Conflict {
            message: format!("batch {batch_id} not found; refusing item insert"),
        }),
    }
}

/// 批次行插入的前置校验（Rust 侧可读错误；CHECK 约束兜底）。
fn validate_batch_insert(source_repo_url: &str, on_failure: &str) -> crate::Result<()> {
    if source_repo_url.trim().is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: "source_repo_url must not be empty".to_string(),
        });
    }
    if !matches!(on_failure, "continue" | "abort") {
        return Err(CrbsError::ValidationFailed {
            message: format!("on_failure must be 'continue' or 'abort', got '{on_failure}'"),
        });
    }
    Ok(())
}

impl StateStore {
    /// 建批次行（status='preparing'，created_at 走列 DEFAULT）；`on_failure` 限
    /// `continue`/`abort`（CHECK 兜底，Rust 前置校验给可读错误），`source_repo_url` 非空。
    pub async fn insert_batch(&self, params: BatchInsert<'_>) -> crate::Result<i64> {
        let BatchInsert {
            product_id,
            created_by,
            source_repo_url,
            dist,
            arch_targets_json,
            on_failure,
            force_all,
            request_json,
        } = params;
        validate_batch_insert(source_repo_url, on_failure)?;
        let id: i64 = sqlx::query_scalar(sql::INSERT_BATCH)
            .bind(product_id)
            .bind(created_by)
            .bind(source_repo_url)
            .bind(dist)
            .bind(arch_targets_json)
            .bind(on_failure)
            .bind(i64::from(force_all))
            .bind(request_json)
            .fetch_one(&self.pool)
            .await
            .db_ctx("insert batch")?;
        self.notify_state_changed();
        Ok(id)
    }

    /// [`Self::insert_batch`] 的配额守卫变体：把"每产品至多一个在途批次 +
    /// 全局在途上限 `global_cap`"检查与插入收进同一写事务。
    ///
    /// 闭合并发跨产品提交的 TOCTOU（check-then-insert 可让两个产品
    /// 同时越过全局上限）：SQLite 侧 `BEGIN IMMEDIATE` 串行化写者即够；
    /// PostgreSQL 侧全局计数无单行可锁，用事务级 advisory lock 串行化所有
    /// 经本方法创建的批次（键与迁移锁互异，随提交/回滚自动释放）。配额
    /// 命中返回 `Conflict`（409）。
    pub async fn insert_batch_quota_checked(
        &self,
        params: BatchInsert<'_>,
        global_cap: i64,
    ) -> crate::Result<i64> {
        let BatchInsert {
            product_id,
            created_by,
            source_repo_url,
            dist,
            arch_targets_json,
            on_failure,
            force_all,
            request_json,
        } = params;
        validate_batch_insert(source_repo_url, on_failure)?;

        let mut conn = self.begin_write().await?;

        if self.dialect.is_postgres() {
            if let Err(e) = sqlx::query(PG_BATCH_QUOTA_LOCK_SQL)
                .execute(&mut *conn)
                .await
                .db_ctx("batch quota advisory lock")
            {
                rollback_and_return!(conn, e);
            }
        }

        if let Some(product_id) = product_id {
            match sqlx::query_as::<_, (i64, String)>(sql::ACTIVE_BATCH_FOR_PRODUCT_NAMED)
                .bind(product_id)
                .fetch_optional(&mut *conn)
                .await
                .db_ctx("check active batch for product")
            {
                Ok(Some((active, name))) => rollback_and_return!(
                    conn,
                    CrbsError::Conflict {
                        message: format!(
                            "product '{name}' already has an active batch (id {active})"
                        ),
                    }
                ),
                Ok(None) => {}
                Err(e) => rollback_and_return!(conn, e),
            }
        }

        let active_total: i64 = match sqlx::query_scalar(sql::COUNT_ACTIVE_BATCHES)
            .fetch_one(&mut *conn)
            .await
            .db_ctx("count active batches")
        {
            Ok(v) => v,
            Err(e) => rollback_and_return!(conn, e),
        };
        if active_total >= global_cap {
            rollback_and_return!(
                conn,
                CrbsError::Conflict {
                    message: format!(
                        "global active batch limit reached ({active_total} in flight, cap {global_cap})"
                    ),
                }
            );
        }

        let inserted = sqlx::query_scalar::<_, i64>(sql::INSERT_BATCH)
            .bind(product_id)
            .bind(created_by)
            .bind(source_repo_url)
            .bind(dist)
            .bind(arch_targets_json)
            .bind(on_failure)
            .bind(i64::from(force_all))
            .bind(request_json)
            .fetch_one(&mut *conn)
            .await
            .db_ctx("insert batch")
            // 同产品唯一索引在提交点兜底（本事务已先复查），归一 Conflict。
            .map_err(|e| {
                if crate::error::is_unique_violation(&e) {
                    CrbsError::Conflict {
                        message: "product already has an active batch".into(),
                    }
                } else {
                    e
                }
            });
        let id = match inserted {
            Ok(id) => id,
            Err(e) => rollback_and_return!(conn, e),
        };

        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit insert batch")
        {
            rollback_and_return!(conn, e);
        }
        self.notify_state_changed();
        Ok(id)
    }

    /// 批量写入重建计划（单事务）；UNIQUE(batch_id, pkg_name) 冲突归一 Conflict
    /// （消息含包名）。幂等重入先 [`Self::delete_batch_items`] 清旧计划。返回插入行数。
    pub async fn insert_batch_items(
        &self,
        batch_id: i64,
        rows: &[NewBatchItem<'_>],
    ) -> crate::Result<usize> {
        if rows.is_empty() {
            return Ok(0);
        }
        let mut conn = self.begin_write().await?;
        if let Err(e) = ensure_batch_not_terminal(&mut conn, batch_id).await {
            rollback_and_return!(conn, e);
        }
        for row in rows {
            if let Err(e) = sqlx::query(sql::INSERT_ITEM)
                .bind(batch_id)
                .bind(row.pkg_name)
                .bind(row.srpm_nevra)
                .bind(row.srpm_staging_path)
                .bind(row.round)
                .execute(&mut *conn)
                .await
                // 先 db_ctx 再判唯一冲突（包装后 Display 含驱动文本，is_unique_violation 才可达）。
                .db_ctx("insert batch item")
                .map_err(|e| {
                    if crate::error::is_unique_violation(&e) {
                        CrbsError::Conflict {
                            message: format!(
                                "package '{}' already has an item in batch {batch_id}",
                                row.pkg_name
                            ),
                        }
                    } else {
                        e
                    }
                })
            {
                rollback_and_return!(conn, e);
            }
        }
        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit batch write")
        {
            rollback_and_return!(conn, e);
        }
        self.notify_state_changed();
        Ok(rows.len())
    }

    /// 批量写入**准备期失败**项（单事务）：state 直接落 'failed'，同事务逐行 bump
    /// `n_failed`——这些项不经 pending→released 状态机，[`Self::mark_item_terminal`]
    /// 的计数同步覆盖不到，必须在此一次写平。终态守卫同 [`Self::insert_batch_items`]。
    /// 返回插入行数。
    pub async fn insert_failed_batch_items(
        &self,
        batch_id: i64,
        rows: &[FailedBatchItem<'_>],
    ) -> crate::Result<usize> {
        if rows.is_empty() {
            return Ok(0);
        }
        let mut conn = self.begin_write().await?;
        if let Err(e) = ensure_batch_not_terminal(&mut conn, batch_id).await {
            rollback_and_return!(conn, e);
        }
        for row in rows {
            if let Err(e) = sqlx::query(sql::INSERT_FAILED_ITEM)
                .bind(batch_id)
                .bind(row.pkg_name)
                .bind(row.srpm_nevra)
                .bind(row.error_code)
                .bind(row.error_message)
                .execute(&mut *conn)
                .await
                .db_ctx("insert failed batch item")
            {
                rollback_and_return!(conn, e);
            }
            if let Err(e) = sqlx::query(&sql::bump_counter("n_failed"))
                .bind(batch_id)
                .execute(&mut *conn)
                .await
                .db_ctx("bump n_failed for prepare-time item failure")
            {
                rollback_and_return!(conn, e);
            }
        }
        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit batch write")
        {
            rollback_and_return!(conn, e);
        }
        self.notify_state_changed();
        Ok(rows.len())
    }

    /// plan 期架构跳过项落账：直插终态 `arch_skipped` 行，逐行 bump `n_skipped`
    /// （与 insert_failed_batch_items 同一事务口径；批次须非终态）。
    pub async fn insert_arch_skipped_batch_items(
        &self,
        batch_id: i64,
        rows: &[SkippedBatchItem<'_>],
    ) -> crate::Result<usize> {
        if rows.is_empty() {
            return Ok(0);
        }
        let mut conn = self.begin_write().await?;
        if let Err(e) = ensure_batch_not_terminal(&mut conn, batch_id).await {
            rollback_and_return!(conn, e);
        }
        for row in rows {
            if let Err(e) = sqlx::query(sql::INSERT_ARCH_SKIPPED_ITEM)
                .bind(batch_id)
                .bind(row.pkg_name)
                .bind(row.srpm_nevra)
                .bind(row.srpm_staging_path)
                .bind(row.error_code)
                .bind(row.error_message)
                .execute(&mut *conn)
                .await
                .db_ctx("insert arch-skipped batch item")
            {
                rollback_and_return!(conn, e);
            }
            if let Err(e) = sqlx::query(&sql::bump_counter("n_skipped"))
                .bind(batch_id)
                .execute(&mut *conn)
                .await
                .db_ctx("bump n_skipped for plan-time arch skip")
            {
                rollback_and_return!(conn, e);
            }
        }
        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit batch write")
        {
            rollback_and_return!(conn, e);
        }
        self.notify_state_changed();
        Ok(rows.len())
    }
}
