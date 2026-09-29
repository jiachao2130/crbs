// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Task 状态存储方法。

use super::*;
use crate::types::build_phase_is_terminal;

mod sql {
    use crate::state::Dialect;

    /// 中间态更新；终态守卫 = 取消 × 完成竞态先到者生效，
    /// rows_affected 为 0 表示守卫拒绝。
    pub(super) const UPDATE_TASK_PHASE: &str = "UPDATE tasks SET phase = $1 WHERE id = $2 AND phase NOT IN ('succeeded', 'failed', 'cancelled', 'timeout')";

    /// 标记任务失败：仅 `pending` 可被翻转——迟到的 fan-out 守护不得把已
    /// `cancelled` 的 0-build 任务翻成 `failed`，0 行 = 守卫拒绝。duration
    /// 自 submitted_at 起算（孤儿 task 无 started_at），与 complete_task 同口径。
    pub(super) fn mark_task_failed(dialect: Dialect) -> String {
        format!(
            "UPDATE tasks SET phase = 'failed', completed_at = {}, duration = {} \
             WHERE id = $1 AND phase = 'pending'",
            dialect.sql_now(),
            dialect.sql_seconds_since("submitted_at")
        )
    }

    /// 兜底清扫 orphan pending task（提交在途异常退出）；duration 自
    /// submitted_at 起算，与 complete_task 同口径。
    pub(super) fn sweep_orphaned_tasks(dialect: Dialect) -> String {
        let duration_expr = dialect.sql_seconds_since("submitted_at");
        match dialect {
            Dialect::Sqlite => format!("UPDATE tasks SET phase = 'failed', completed_at = datetime('now'), duration = {duration_expr} \
                 WHERE phase = 'pending' \
                   AND submitted_at <= datetime('now', '-' || $1 || ' minutes') \
                   AND NOT EXISTS (SELECT 1 FROM builds WHERE builds.task_id = tasks.id)"),
            #[cfg(feature = "postgres")]
            // TEXT 帧比较（submitted_at 是 UTC 墙钟 TEXT）：to_timestamp 按会话
            // 时区解析会把 TZ≠UTC 的宽限窗口反转，刚创建的 task 即被误判孤儿。
            Dialect::Postgres => format!("UPDATE tasks SET phase = 'failed', completed_at = to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'), duration = {duration_expr} \
                 WHERE phase = 'pending' \
                   AND submitted_at <= to_char((NOW() AT TIME ZONE 'UTC') - $1::BIGINT * INTERVAL '1 minute', 'YYYY-MM-DD HH24:MI:SS') \
                   AND NOT EXISTS (SELECT 1 FROM builds WHERE builds.task_id = tasks.id)"),
        }
    }

    /// 完成任务（方言感知时间计算）。双重 CAS 守卫：task 自身终态（先到者
    /// 生效）+ 活跃子构建守卫——快照读与写入间 PG BEGIN 不锁行，事务外写入
    /// 恰落间隙会让"全部终态"快照过期，写入谓词消除该 TOCTOU；0-build 的
    /// NOT EXISTS 平凡真。rows_affected 为 0 = 任一守卫拒绝（非错误）。
    pub(super) fn complete_task(dialect: Dialect) -> String {
        format!(
            "UPDATE tasks \
             SET phase = $1, \
                 completed_at = {}, \
                 duration = {} \
             WHERE id = $2 \
               AND phase NOT IN ('succeeded', 'failed', 'cancelled', 'timeout') \
               AND NOT EXISTS (SELECT 1 FROM builds \
                               WHERE builds.task_id = tasks.id \
                                 AND builds.phase NOT IN ('succeeded', 'failed', \
                                                          'cancelled', 'timeout'))",
            dialect.sql_now(),
            dialect.sql_seconds_since("submitted_at")
        )
    }

    pub(super) const LIST_BUILD_PHASES_BY_TASK: &str =
        "SELECT phase FROM builds WHERE task_id = $1";

    /// 卡死 task 恢复候选：task 非终态、有子构建、且子构建全部终态。无假终态
    /// 窗口故无需宽限期：未提交 build 终态对其他连接不可见（read committed /
    /// SQLite 写锁），提交时聚合已在同事务完成；builds 又随 task 展开一次建齐。
    pub(super) const LIST_STUCK_TASKS: &str = "SELECT DISTINCT t.id FROM tasks t \
         WHERE t.phase IN ('pending', 'building', 'assigned') \
           AND EXISTS (SELECT 1 FROM builds b WHERE b.task_id = t.id) \
           AND NOT EXISTS (SELECT 1 FROM builds b WHERE b.task_id = t.id \
                           AND b.phase NOT IN ('succeeded', 'failed', 'cancelled', 'timeout'))";
}

/// `finalize_cancelled_task` 的三态收口结果。契约要点：Superseded = 空子路径
/// 竞态拒写，取消未生效、task 仍会被派发，调用方必须显式报错（HTTP 409 /
/// CLI 退出）；ChildrenActive = 软收敛，按取消已受理处理（路由维持 202）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizeOutcome {
    /// 终态写入成功，取消目标达成。
    Finalized,
    /// 空子路径竞态拒写：取消未生效（task 状态在取消途中被并发改变）。
    Superseded,
    /// 非空子路径软收敛：per-build cancel 已生效，task phase 维持现状。
    ChildrenActive,
}

impl StateStore {
    /// 将任务标记为失败（终态），记录完成时间：收口"已建 task 行但未建成
    /// 任何构建"的假 `pending` 孤儿（提交/重建在 task 与 builds 间非原子
    /// 展开的清理）。返回受影响行数，0 = 已不在 `pending`（守卫拒绝，
    /// 非错误）。
    pub async fn mark_task_failed(&self, id: i64) -> crate::Result<u64> {
        let result = sqlx::query(&sql::mark_task_failed(self.dialect))
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("mark task failed")?;
        let affected = result.rows_affected();
        if affected > 0 {
            self.notify_state_changed();
        }
        Ok(affected)
    }

    /// 清扫"孤儿任务"：`pending` 且无子构建、提交早于 `grace_minutes`（排除
    /// 在途提交）的任务置 `failed`，返回本次标记数。task 与 builds 展开非原子
    /// 的兜底（handler 建好 builds 前出错/被取消留下 0 构建 `pending` 行，
    /// 调度与崩溃恢复均无法拾起）；`NOT EXISTS` 对 NULL task_id 安全。
    pub async fn sweep_orphaned_tasks(&self, grace_minutes: u64) -> crate::Result<u64> {
        let result = sqlx::query(&sql::sweep_orphaned_tasks(self.dialect))
            .bind(grace_minutes as i64)
            .execute(&self.pool)
            .await
            .db_ctx("sweep orphaned tasks")?;
        let affected = result.rows_affected();
        if affected > 0 {
            self.notify_state_changed();
        }
        Ok(affected)
    }

    /// 取消流程收口父 task 终态（server cancel 专用）：无子构建直接写
    /// `cancelled`；子构建全终态按 `aggregate_child_phases` 推导（与
    /// complete_build 聚合同一口径）；仍有非终态子构建保持原 phase 仅 warn。
    /// 写入带 completed_at / duration + 双重 CAS（见 `sql::complete_task`），返回 [`FinalizeOutcome`]。
    pub async fn finalize_cancelled_task(&self, task_id: i64) -> crate::Result<FinalizeOutcome> {
        let mut conn = self.pool.acquire().await.db_ctx("acquire conn")?;
        let children = build_phases_on(&mut conn, task_id).await?;
        let empty_children = children.is_empty();
        let new_phase = if empty_children {
            "cancelled"
        } else {
            match StateStore::aggregate_child_phases(&children) {
                Some(p) if build_phase_is_terminal(p) => p,
                derived => {
                    tracing::warn!(
                        task_id = %task_id,
                        derived = ?derived,
                        "children not all terminal after cancel; leaving task phase as-is"
                    );
                    return Ok(FinalizeOutcome::ChildrenActive);
                }
            }
        };
        let rows = complete_task_on(&mut conn, self.dialect, task_id, new_phase).await?;
        if rows > 0 {
            self.notify_state_changed();
            return Ok(FinalizeOutcome::Finalized);
        }
        if empty_children {
            // 快照读为空但写入被拒（契约洞）：fan-out 子构建恰落间隙提交，或
            // task 已被并发写终态——取消未生效，透出 Superseded 显式失败。
            tracing::warn!(
                task_id = %task_id,
                "cancel of empty task raced a concurrent write; cancel superseded"
            );
            return Ok(FinalizeOutcome::Superseded);
        }
        // 非空路径 0 行：幂等重取消（先到者生效）或间隙出现活跃子构建，软收敛。
        tracing::warn!(
            task_id = %task_id,
            phase = new_phase,
            "task already terminal or active child build appeared when finalizing cancel; write skipped"
        );
        Ok(FinalizeOutcome::ChildrenActive)
    }

    /// 聚合指定 build 所属 task 的阶段（build 无 task_id 时为 no-op；
    /// 聚合规则见 `aggregate_task_phase_on`）。
    pub async fn aggregate_task_phase_for_build(&self, build_id: i64) -> crate::Result<()> {
        let mut conn = self.pool.acquire().await.db_ctx("acquire conn")?;
        let task_id: Option<i64> = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(build_id)
            .fetch_optional(&mut *conn)
            .await
            .db_ctx("get build task id")?
            .flatten();
        match task_id {
            Some(task_id) => {
                let outcome = aggregate_task_phase_on(&mut conn, self.dialect, task_id).await;
                // 通知收口点：聚合实现跑在裸连接上拿不到 &self，上移到本入口。
                if outcome.is_ok() {
                    self.notify_state_changed();
                }
                outcome
            }
            None => Ok(()),
        }
    }

    /// 池连接版按 task 聚合（reconcile 清扫与外部调用入口）。
    pub async fn aggregate_task_phase_for_task(&self, task_id: i64) -> crate::Result<()> {
        let mut conn = self.pool.acquire().await.db_ctx("acquire conn")?;
        let outcome = aggregate_task_phase_on(&mut conn, self.dialect, task_id).await;
        // 通知收口点：同 aggregate_task_phase_for_build。
        if outcome.is_ok() {
            self.notify_state_changed();
        }
        outcome
    }

    /// 自愈清扫：修复"子构建全部终态、task 却卡在非终态"的行，兜住所有聚合
    /// 遗漏窗口（存量数据 / best-effort 聚合失败 / 新增写路径遗漏）。幂等。
    pub async fn reconcile_stale_task_phases(&self) -> crate::Result<usize> {
        let ids: Vec<i64> = sqlx::query_scalar(sql::LIST_STUCK_TASKS)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list stuck tasks for reconcile")?;
        let mut repaired = 0;
        for task_id in ids {
            match self.aggregate_task_phase_for_task(task_id).await {
                Ok(()) => repaired += 1,
                Err(e) => {
                    tracing::warn!(task_id = %task_id, error = %e, "Reconcile stale task phase failed")
                }
            }
        }
        Ok(repaired)
    }

    fn aggregate_child_phases(children: &[String]) -> Option<&'static str> {
        if children.is_empty() {
            return None;
        }
        let all_final = children.iter().all(|b| build_phase_is_terminal(b.as_str()));
        if all_final {
            if children.iter().any(|b| b == "failed") {
                Some("failed")
            } else if children.iter().any(|b| b == "cancelled") {
                Some("cancelled")
            } else if children.iter().any(|b| b == "timeout") {
                Some("timeout")
            } else {
                Some("succeeded")
            }
        } else if children
            .iter()
            .any(|b| matches!(b.as_str(), "building" | "assigned"))
        {
            Some("building")
        } else if children.iter().any(|b| build_phase_is_terminal(b.as_str())) {
            // 部分子构建已终态、其余仍 pending：任务已在进行中，不回退到 pending
            Some("building")
        } else {
            Some("pending")
        }
    }
}

/// 事务内/池上共用的 task 聚合辅助查询：只取聚合所需列，避免整行映射复制。
async fn task_phase_on(
    conn: &mut sqlx::AnyConnection,
    task_id: i64,
) -> crate::Result<Option<String>> {
    let phase: Option<String> = sqlx::query_scalar("SELECT phase FROM tasks WHERE id = $1")
        .bind(task_id)
        .fetch_optional(&mut *conn)
        .await
        .db_ctx("get task phase")?;
    Ok(phase)
}

async fn build_phases_on(
    conn: &mut sqlx::AnyConnection,
    task_id: i64,
) -> crate::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(sql::LIST_BUILD_PHASES_BY_TASK)
        .bind(task_id)
        .fetch_all(&mut *conn)
        .await
        .db_ctx("list build phases by task")?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// 带终态守卫的中间态更新，返回受影响行数（0 = 任务已终态、写入被拒绝）。
pub(super) async fn update_task_phase_on(
    conn: &mut sqlx::AnyConnection,
    task_id: i64,
    phase: &str,
) -> crate::Result<u64> {
    let result = sqlx::query(sql::UPDATE_TASK_PHASE)
        .bind(phase)
        .bind(task_id)
        .execute(&mut *conn)
        .await
        .db_ctx("update task phase")?;
    Ok(result.rows_affected())
}

/// 带双重 CAS 守卫的终态写入（completed_at / duration 一并落库，守卫见
/// `sql::complete_task`）；返回行数 0 = 守卫拒绝。供 tasks 模块测试直调。
pub(super) async fn complete_task_on(
    conn: &mut sqlx::AnyConnection,
    dialect: Dialect,
    task_id: i64,
    phase: &str,
) -> crate::Result<u64> {
    let result = sqlx::query(&sql::complete_task(dialect))
        .bind(phase)
        .bind(task_id)
        .execute(&mut *conn)
        .await
        .db_ctx("complete task")?;
    Ok(result.rows_affected())
}

/// 在给定连接上聚合 task 阶段（事务内复用：可读到同事务未提交的 build 终态）。
/// 规则：任一子构建 building/assigned → task building；全部终态 →
/// failed > cancelled > timeout > succeeded；已终态 task 不回退、children
/// 为空不动。写入自带终态守卫：裸池调用与并发 complete_build 事务竞态时
/// UPDATE 落 0 行 no-op，不会把终态回退成 building（reconcile 清扫兜底）。
pub(crate) async fn aggregate_task_phase_on(
    conn: &mut sqlx::AnyConnection,
    dialect: Dialect,
    task_id: i64,
) -> crate::Result<()> {
    let children = build_phases_on(conn, task_id).await?;
    if children.is_empty() {
        return Ok(());
    }

    let current_phase = match task_phase_on(conn, task_id).await? {
        Some(p) => p,
        None => return Ok(()),
    };
    if build_phase_is_terminal(current_phase.as_str()) {
        return Ok(());
    }

    let new_phase = match StateStore::aggregate_child_phases(&children) {
        Some(p) => p,
        None => return Ok(()),
    };
    if new_phase == current_phase {
        return Ok(());
    }

    let rows = if build_phase_is_terminal(new_phase) {
        complete_task_on(conn, dialect, task_id, new_phase).await?
    } else {
        update_task_phase_on(conn, task_id, new_phase).await?
    };
    if rows == 0 {
        tracing::debug!(
            task_id = %task_id,
            new_phase = new_phase,
            "task phase aggregation raced a terminal write; update skipped"
        );
    }
    Ok(())
}

/// bulk 取消路径的 task 收口，[`StateStore::finalize_cancelled_task`] 的
/// 事务内版本：子构建已在同一事务内先行取消，逐 task 按子构建聚合推导
/// 终态——0 子构建 → `cancelled`；全终态 → `aggregate_child_phases`
///（failed > cancelled > timeout > succeeded；已有 failed/timeout 收口
/// `failed`，与用户单任务取消同口径）；仍有活跃子构建 → 保持原 phase 软
/// 收敛（reconcile 清扫兜底）。终态写入走 [`complete_task_on`]（completed_at
/// / duration 自 submitted_at 起算，双重 CAS 守卫），返回 0 = 软收敛或守卫
/// 拒绝，调用方计入实际翻转任务数。
pub(crate) async fn finalize_cancelled_task_on(
    conn: &mut sqlx::AnyConnection,
    dialect: Dialect,
    task_id: i64,
) -> crate::Result<u64> {
    let children = build_phases_on(conn, task_id).await?;
    let new_phase = if children.is_empty() {
        "cancelled"
    } else {
        match StateStore::aggregate_child_phases(&children) {
            Some(p) if build_phase_is_terminal(p) => p,
            derived => {
                tracing::warn!(
                    task_id = %task_id,
                    derived = ?derived,
                    "children not all terminal after bulk cancel; leaving task phase as-is"
                );
                return Ok(0);
            }
        }
    };
    complete_task_on(conn, dialect, task_id, new_phase).await
}

/// 本文件手写四值终态 IN 列表（const SQL 无法挂运行时渲染器的结构性豁免）
/// 与单源常量的同步钉：UPDATE_TASK_PHASE 一处、complete_task 两处、
/// LIST_STUCK_TASKS 一处；未来加第 5 终态或任一处字面量漂移必红。
#[cfg(test)]
mod terminal_in_list_pins {
    use super::sql;
    use crate::state::test_state::assert_terminal_in_lists;

    #[test]
    fn lifecycle_sql_terminal_in_lists_match_terminal_build_phases() {
        assert_terminal_in_lists(sql::UPDATE_TASK_PHASE, 1, "UPDATE_TASK_PHASE");
        // 双守卫各携带一个终态 IN 列表（方言无关字面量，SQLite 腿覆盖）。
        assert_terminal_in_lists(
            &sql::complete_task(crate::state::Dialect::Sqlite),
            2,
            "complete_task",
        );
        assert_terminal_in_lists(sql::LIST_STUCK_TASKS, 1, "LIST_STUCK_TASKS");
    }
}
