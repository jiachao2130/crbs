// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 批次与批次项的状态机流转、计数器维护。

use super::query::item_from_row;
use super::sql;
use super::types::BatchItemRecord;
use crate::error::{CrbsError, DbResultExt};
use crate::state::{rollback_and_return, StateStore};

/// 项终态全集（[`StateStore::mark_item_terminal`] 接受的 state 域）。
const TERMINAL_ITEM_STATES: [&str; 6] = [
    "succeeded",
    "failed",
    "dep_skipped",
    "skipped_conflict",
    "arch_skipped",
    "cancelled",
];

/// 批次终态全集（[`StateStore::finish_batch`] 接受的 status 域）。
const BATCH_TERMINAL_STATUSES: [&str; 4] = ["completed", "partial", "failed", "cancelled"];

/// 终态 → 计数器列固定映射（模块头注口径的单源）；非法入参返 None，调用方转 ValidationFailed。
fn terminal_counter_column(state: &str) -> Option<&'static str> {
    match state {
        "succeeded" => Some("n_succeeded"),
        "failed" => Some("n_failed"),
        "dep_skipped" | "skipped_conflict" | "arch_skipped" => Some("n_skipped"),
        "cancelled" => Some("n_cancelled"),
        _ => None,
    }
}

impl StateStore {
    /// preparing → planning CAS；0 行 = 已不在 preparing（并发迁移/先到者）→ Conflict。
    pub async fn set_batch_planning(&self, id: i64) -> crate::Result<()> {
        let result = sqlx::query(&sql::set_batch_planning(self.dialect))
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("set batch planning")?;
        if result.rows_affected() == 0 {
            return Err(CrbsError::Conflict {
                message: format!("batch {id} is not in 'preparing'; concurrent transition?"),
            });
        }
        self.notify_state_changed();
        Ok(())
    }

    /// planning → running CAS，同语句原子写入 total_items（计划规模落库）。
    pub async fn set_batch_running(&self, id: i64, total_items: i64) -> crate::Result<()> {
        let result = sqlx::query(sql::SET_BATCH_RUNNING)
            .bind(id)
            .bind(total_items)
            .execute(&self.pool)
            .await
            .db_ctx("set batch running")?;
        if result.rows_affected() == 0 {
            return Err(CrbsError::Conflict {
                message: format!("batch {id} is not in 'planning'; concurrent transition?"),
            });
        }
        self.notify_state_changed();
        Ok(())
    }

    /// 非终态 → 终态 CAS，finished_at 落值。事务内先做总数对账：`sum(n_*) ==
    /// total_items` 不成立即拒绝完成（见模块头注"计数器口径"）；`status` 限四终态
    /// 之一，0 行 = 已终态（先到者生效）→ Conflict。
    pub async fn finish_batch(
        &self,
        id: i64,
        status: &str,
        notes: Option<&str>,
    ) -> crate::Result<()> {
        if !BATCH_TERMINAL_STATUSES.contains(&status) {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "batch status must be one of {BATCH_TERMINAL_STATUSES:?}, got '{status}'"
                ),
            });
        }
        let mut conn = self.begin_write().await?;

        // 对账前置读：行不存在 → NotFound；计数漂移 → Internal（代码缺陷信号）。
        let counters =
            match sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(sql::SELECT_BATCH_COUNTERS)
                .bind(id)
                .fetch_optional(&mut *conn)
                .await
                .db_ctx("read batch counters for finish")
            {
                Ok(c) => c,
                Err(e) => rollback_and_return!(conn, e),
            };
        let Some((total, n_ok, n_fail, n_skip, n_cancel)) = counters else {
            rollback_and_return!(
                conn,
                CrbsError::NotFound {
                    message: format!("batch {id} not found"),
                }
            );
        };
        let terminal_sum = n_ok + n_fail + n_skip + n_cancel;
        if terminal_sum != total {
            rollback_and_return!(
                conn,
                CrbsError::Internal(format!(
                    "batch {id} counter drift: n_succeeded({n_ok}) + n_failed({n_fail}) + \
                     n_skipped({n_skip}) + n_cancelled({n_cancel}) = {terminal_sum} \
                     != total_items({total}); refusing to finish"
                ))
            );
        }

        let affected = match sqlx::query(&sql::finish_batch(self.dialect))
            .bind(id)
            .bind(status)
            .bind(notes)
            .execute(&mut *conn)
            .await
            .db_ctx("finish batch")
        {
            Ok(r) => r.rows_affected(),
            Err(e) => rollback_and_return!(conn, e),
        };
        if affected == 0 {
            rollback_and_return!(
                conn,
                CrbsError::Conflict {
                    message: format!(
                        "batch {id} is already terminal; finish raced a terminal write"
                    ),
                }
            );
        }
        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit batch write")
        {
            rollback_and_return!(conn, e);
        }
        self.notify_state_changed();
        Ok(())
    }

    /// 更新批次 notes（仅非终态可写，0 行 → Conflict）；供准备服务落增量跳过名单等元数据。
    pub async fn set_batch_notes(&self, id: i64, notes: &str) -> crate::Result<()> {
        let result = sqlx::query(sql::SET_BATCH_NOTES)
            .bind(id)
            .bind(notes)
            .execute(&self.pool)
            .await
            .db_ctx("set batch notes")?;
        if result.rows_affected() == 0 {
            return Err(CrbsError::Conflict {
                message: format!("batch {id} is terminal or missing; notes are immutable"),
            });
        }
        self.notify_state_changed();
        Ok(())
    }

    /// 清批次计划（仅非终态批次可清）；返回删除行数，终态/无计划均为 0。
    pub async fn delete_batch_items(&self, batch_id: i64) -> crate::Result<u64> {
        let result = sqlx::query(sql::DELETE_BATCH_ITEMS)
            .bind(batch_id)
            .execute(&self.pool)
            .await
            .db_ctx("delete batch items")?;
        let affected = result.rows_affected();
        if affected > 0 {
            self.notify_state_changed();
        }
        Ok(affected)
    }

    /// 清空计划并按被删行的终态回退 `n_*` 镜像（plan 重写/启动期失败收口）。
    /// 只允许非终态批次（DELETE_BATCH_ITEMS 的 status guard）；返回删除前快照，
    /// 调用方据此重插 failed/skipped 行。任一计数器/删除行数不匹配即回滚，
    /// 绝不留下“行已删、计数仍在”的批次——那会让 finish 永久对账失败并占配额。
    pub async fn clear_batch_items_rollback_counters(
        &self,
        batch_id: i64,
    ) -> crate::Result<Vec<BatchItemRecord>> {
        let mut conn = self.begin_write().await?;
        let rows = match sqlx::query(&format!(
            "SELECT {} FROM batch_items WHERE batch_id = $1 ORDER BY id ASC",
            sql::ITEM_COLUMNS
        ))
        .bind(batch_id)
        .fetch_all(&mut *conn)
        .await
        .db_ctx("list batch items for clear")
        {
            Ok(rows) => rows,
            Err(e) => rollback_and_return!(conn, e),
        };
        if rows.is_empty() {
            if let Err(e) = sqlx::query("COMMIT")
                .execute(&mut *conn)
                .await
                .db_ctx("commit batch write")
            {
                rollback_and_return!(conn, e);
            }
            return Ok(Vec::new());
        }

        let items: Vec<BatchItemRecord> = match rows.into_iter().map(item_from_row).collect() {
            Ok(items) => items,
            Err(e) => rollback_and_return!(conn, e),
        };

        let deleted = match sqlx::query(sql::DELETE_BATCH_ITEMS)
            .bind(batch_id)
            .execute(&mut *conn)
            .await
            .db_ctx("delete batch items for clear")
        {
            Ok(r) => r.rows_affected(),
            Err(e) => rollback_and_return!(conn, e),
        };
        if deleted as usize != items.len() {
            rollback_and_return!(
                conn,
                CrbsError::Internal(format!(
                    "batch {batch_id} item clear raced with another writer: \
                     expected {} rows, deleted {deleted}",
                    items.len()
                ))
            );
        }

        for state in TERMINAL_ITEM_STATES {
            let count = items.iter().filter(|item| item.state == state).count() as i64;
            let Some(column) = terminal_counter_column(state) else {
                continue;
            };
            if count == 0 {
                continue;
            }
            let statement = format!(
                "UPDATE build_batches SET {column} = {column} - $2 \
                 WHERE id = $1 AND {column} >= $2"
            );
            let affected = match sqlx::query(&statement)
                .bind(batch_id)
                .bind(count)
                .execute(&mut *conn)
                .await
                .db_ctx("rollback batch counter for clear")
            {
                Ok(r) => r.rows_affected(),
                Err(e) => rollback_and_return!(conn, e),
            };
            if affected != 1 {
                rollback_and_return!(
                    conn,
                    CrbsError::Internal(format!(
                        "batch {batch_id} counter {column} is smaller than cleared rows \
                         ({count}); refusing to leave a drifted batch"
                    ))
                );
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
        Ok(items)
    }

    /// 释放项去构建：pending → released，绑定 task。仅 running 批次可释放，
    /// 非 pending 项拒（重复释放是竞态信号）——均 Conflict。released 非终态，计数器不动。
    pub async fn mark_item_released(
        &self,
        batch_id: i64,
        item_id: i64,
        task_id: i64,
    ) -> crate::Result<()> {
        let result = sqlx::query(&sql::mark_item_released(self.dialect))
            .bind(batch_id)
            .bind(item_id)
            .bind(task_id)
            .execute(&self.pool)
            .await
            .db_ctx("mark batch item released")?;
        if result.rows_affected() == 0 {
            return Err(CrbsError::Conflict {
                message: format!(
                    "cannot release item {item_id} in batch {batch_id}: \
                     batch not running or item not pending"
                ),
            });
        }
        self.notify_state_changed();
        Ok(())
    }

    /// 在途项收口终态：released → 终态 CAS，同事务对 `terminal_counter_column`
    /// 映射的计数器 +1。0 行（项非 released / 批次不符）→ Conflict。
    pub async fn mark_item_terminal(
        &self,
        batch_id: i64,
        item_id: i64,
        state: &str,
        error_code: Option<&str>,
        error_message: Option<&str>,
    ) -> crate::Result<()> {
        let Some(column) = terminal_counter_column(state) else {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "item state must be one of {TERMINAL_ITEM_STATES:?}, got '{state}'"
                ),
            });
        };
        let mut conn = self.begin_write().await?;
        let affected = match sqlx::query(&sql::mark_item_terminal(self.dialect))
            .bind(batch_id)
            .bind(item_id)
            .bind(state)
            .bind(error_code)
            .bind(error_message)
            .execute(&mut *conn)
            .await
            .db_ctx("mark batch item terminal")
        {
            Ok(r) => r.rows_affected(),
            Err(e) => rollback_and_return!(conn, e),
        };
        if affected == 0 {
            rollback_and_return!(
                conn,
                CrbsError::Conflict {
                    message: format!(
                        "cannot mark item {item_id} in batch {batch_id} as '{state}': \
                         item is not in 'released' state"
                    ),
                }
            );
        }
        let bumped = match sqlx::query(&sql::bump_counter(column))
            .bind(batch_id)
            .execute(&mut *conn)
            .await
            .db_ctx("bump batch terminal counter")
        {
            Ok(r) => r.rows_affected(),
            Err(e) => rollback_and_return!(conn, e),
        };
        if bumped != 1 {
            // 项行与批次行同 FK CASCADE，项在则批次行必在；0 行 = 不变量破坏，显式失败不静默丢计数。
            rollback_and_return!(
                conn,
                CrbsError::Internal(format!(
                    "batch {batch_id} row vanished while marking item {item_id} terminal"
                ))
            );
        }
        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit batch write")
        {
            rollback_and_return!(conn, e);
        }
        self.notify_state_changed();
        Ok(())
    }

    /// 恢复轮：指定 failed 项重置回 pending（attempt +1，错误信息清空），n_failed
    /// 同事务按翻转数减回（否则重跑对账炸）。仅 failed 可重置（其余静默跳过）；返回翻转行数。
    pub async fn reset_items_to_pending(
        &self,
        batch_id: i64,
        item_ids: &[i64],
    ) -> crate::Result<u64> {
        if item_ids.is_empty() {
            return Ok(0);
        }
        let placeholders = crate::state::db::in_placeholders(2, item_ids.len())?;
        let statement = sql::reset_items_to_pending(self.dialect, &placeholders);
        let mut conn = self.begin_write().await?;
        let mut query = sqlx::query(&statement).bind(batch_id);
        for id in item_ids {
            query = query.bind(id);
        }
        let reset = match query
            .execute(&mut *conn)
            .await
            .db_ctx("reset batch items to pending")
        {
            Ok(r) => r.rows_affected(),
            Err(e) => rollback_and_return!(conn, e),
        };
        if reset > 0 {
            let dec = match sqlx::query(
                "UPDATE build_batches SET n_failed = n_failed - $2 WHERE id = $1",
            )
            .bind(batch_id)
            .bind(reset as i64)
            .execute(&mut *conn)
            .await
            .db_ctx("decrement n_failed for reset")
            {
                Ok(r) => r.rows_affected(),
                Err(e) => rollback_and_return!(conn, e),
            };
            if dec != 1 {
                rollback_and_return!(
                    conn,
                    CrbsError::Internal(format!(
                        "batch {batch_id} row vanished while resetting {reset} items to pending"
                    ))
                );
            }
        }
        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit batch write")
        {
            rollback_and_return!(conn, e);
        }
        if reset > 0 {
            self.notify_state_changed();
        }
        Ok(reset)
    }

    /// 批次中止/取消收尾：全部未派发（pending）与在途（released）项收口为 failed
    /// （error_code/message 记原因），n_failed 同事务按翻转数同步保证 finish 对账。
    /// 返回 `(翻转项数, 被翻转项的 task_id)`：task 列表与 UPDATE 同事务取定，
    /// 调用方据此取消在途 task，关闭"快照→翻转"窗口（刚 released 的项不漏取消）。
    pub async fn fail_unfinished_items(
        &self,
        batch_id: i64,
        error_code: &str,
        message: &str,
    ) -> crate::Result<(u64, Vec<i64>)> {
        let mut conn = self.begin_write().await?;
        let task_ids: Vec<i64> = match sqlx::query_scalar(sql::UNFINISHED_TASK_IDS)
            .bind(batch_id)
            .fetch_all(&mut *conn)
            .await
            .db_ctx("list unfinished batch task ids")
        {
            Ok(ids) => ids,
            Err(e) => rollback_and_return!(conn, e),
        };
        let failed = match sqlx::query(&sql::fail_unfinished_items(self.dialect))
            .bind(batch_id)
            .bind(error_code)
            .bind(message)
            .execute(&mut *conn)
            .await
            .db_ctx("fail unfinished batch items")
        {
            Ok(r) => r.rows_affected(),
            Err(e) => rollback_and_return!(conn, e),
        };
        if failed > 0 {
            let bumped = match sqlx::query(
                "UPDATE build_batches SET n_failed = n_failed + $2 WHERE id = $1",
            )
            .bind(batch_id)
            .bind(failed as i64)
            .execute(&mut *conn)
            .await
            .db_ctx("bump n_failed for unfinished items")
            {
                Ok(r) => r.rows_affected(),
                Err(e) => rollback_and_return!(conn, e),
            };
            if bumped != 1 {
                rollback_and_return!(
                    conn,
                    CrbsError::Internal(format!(
                        "batch {batch_id} row vanished while failing unfinished items"
                    ))
                );
            }
        }
        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit batch write")
        {
            rollback_and_return!(conn, e);
        }
        if failed > 0 {
            self.notify_state_changed();
        }
        Ok((failed, task_ids))
    }

    /// 派发失败直收终态：pending → 终态 CAS，同事务对 `terminal_counter_column`
    /// 映射的计数器 +1。驱动器专用：task 创建/启动失败的项从未释放（无 task_id），走不了
    /// [`Self::mark_item_terminal`] 的 released 通道（skipped_conflict 与派发 failed 均走此）。0 行 → Conflict。
    pub async fn mark_pending_item_terminal(
        &self,
        batch_id: i64,
        item_id: i64,
        state: &str,
        error_code: Option<&str>,
        error_message: Option<&str>,
    ) -> crate::Result<()> {
        let Some(column) = terminal_counter_column(state) else {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "item state must be one of {TERMINAL_ITEM_STATES:?}, got '{state}'"
                ),
            });
        };
        let mut conn = self.begin_write().await?;
        let affected = match sqlx::query(&sql::mark_pending_item_terminal(self.dialect))
            .bind(batch_id)
            .bind(item_id)
            .bind(state)
            .bind(error_code)
            .bind(error_message)
            .execute(&mut *conn)
            .await
            .db_ctx("mark pending batch item terminal")
        {
            Ok(r) => r.rows_affected(),
            Err(e) => rollback_and_return!(conn, e),
        };
        if affected == 0 {
            rollback_and_return!(
                conn,
                CrbsError::Conflict {
                    message: format!(
                        "cannot mark item {item_id} in batch {batch_id} as '{state}': \
                         item is not in 'pending' state"
                    ),
                }
            );
        }
        let bumped = match sqlx::query(&sql::bump_counter(column))
            .bind(batch_id)
            .execute(&mut *conn)
            .await
            .db_ctx("bump batch terminal counter")
        {
            Ok(r) => r.rows_affected(),
            Err(e) => rollback_and_return!(conn, e),
        };
        if bumped != 1 {
            rollback_and_return!(
                conn,
                CrbsError::Internal(format!(
                    "batch {batch_id} row vanished while marking item {item_id} terminal"
                ))
            );
        }
        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit batch write")
        {
            rollback_and_return!(conn, e);
        }
        self.notify_state_changed();
        Ok(())
    }

    /// 取消收尾：全部未终态（pending + released）项统一收口 cancelled，n_cancelled
    /// 同事务按翻转数同步（fail_unfinished_items 的镜像），保证 finish 对账成立。
    /// 返回 `(翻转项数, 被翻转项的 task_id)`（同事务取定，用途见 fail_unfinished_items）。
    pub async fn cancel_unfinished_items(
        &self,
        batch_id: i64,
        error_code: &str,
        message: &str,
    ) -> crate::Result<(u64, Vec<i64>)> {
        let mut conn = self.begin_write().await?;
        let task_ids: Vec<i64> = match sqlx::query_scalar(sql::UNFINISHED_TASK_IDS)
            .bind(batch_id)
            .fetch_all(&mut *conn)
            .await
            .db_ctx("list unfinished batch task ids")
        {
            Ok(ids) => ids,
            Err(e) => rollback_and_return!(conn, e),
        };
        let cancelled = match sqlx::query(&sql::cancel_unfinished_items(self.dialect))
            .bind(batch_id)
            .bind(error_code)
            .bind(message)
            .execute(&mut *conn)
            .await
            .db_ctx("cancel unfinished batch items")
        {
            Ok(r) => r.rows_affected(),
            Err(e) => rollback_and_return!(conn, e),
        };
        if cancelled > 0 {
            let bumped = match sqlx::query(
                "UPDATE build_batches SET n_cancelled = n_cancelled + $2 WHERE id = $1",
            )
            .bind(batch_id)
            .bind(cancelled as i64)
            .execute(&mut *conn)
            .await
            .db_ctx("bump n_cancelled for cancelled items")
            {
                Ok(r) => r.rows_affected(),
                Err(e) => rollback_and_return!(conn, e),
            };
            if bumped != 1 {
                rollback_and_return!(
                    conn,
                    CrbsError::Internal(format!(
                        "batch {batch_id} row vanished while cancelling unfinished items"
                    ))
                );
            }
        }
        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit batch write")
        {
            rollback_and_return!(conn, e);
        }
        if cancelled > 0 {
            self.notify_state_changed();
        }
        Ok((cancelled, task_ids))
    }
}
