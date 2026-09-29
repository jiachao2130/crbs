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

mod sql {
    use crate::state::Dialect;

    /// 插入任务（方言感知时间）。product_id 由标量子查询按官方产品名（owner_id
    /// IS NULL，全局唯一至多一行）内联解析，不存在落 NULL；内联消除两步
    /// SELECT+INSERT 之间产品被并发删除的悬空引用。
    pub(super) fn insert_task(dialect: Dialect) -> String {
        format!(
            "INSERT INTO tasks (product, pkg_name, name, version, release, \"user\", user_id, phase, priority, srpm_path, result_dir, request_json, pkg_names, product_id, submitted_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, \
                     (SELECT id FROM products WHERE name = $1 AND owner_id IS NULL), {}) \
             RETURNING id",
            dialect.sql_now()
        )
    }

    pub(super) const UPDATE_TASK_RESULT_DIR: &str =
        "UPDATE tasks SET result_dir = $1 WHERE id = $2";
    pub(super) const UPDATE_TASK_SRPM_PATH: &str = "UPDATE tasks SET srpm_path = $1 WHERE id = $2";
    pub(super) const INSERT_TASK_LABEL: &str =
        "INSERT INTO task_labels (task_id, key, value) VALUES ($1, $2, $3)";
    pub(super) const SELECT_TASK_LABELS: &str =
        "SELECT key, value FROM task_labels WHERE task_id = $1 ORDER BY key";
}

/// 任务插入执行体：pool 与事务连接共用（`create_task_with_labels` 原子性）。
async fn insert_task_row<'e, E>(
    executor: E,
    dialect: Dialect,
    task: &TaskInsert<'_>,
) -> crate::Result<i64>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let (name, version, release) = crate::util::split_nvr(task.pkg_name);

    sqlx::query_scalar::<_, i64>(&sql::insert_task(dialect))
        .bind(task.product)
        .bind(task.pkg_name)
        .bind(name)
        .bind(version)
        .bind(release)
        .bind(task.user)
        .bind(task.user_id)
        .bind(task.phase)
        .bind(task.priority)
        .bind(task.srpm_path)
        .bind(task.result_dir)
        .bind(task.request_json)
        .bind(task.pkg_names)
        .fetch_one(executor)
        .await
        .db_ctx("insert task")
}

impl StateStore {
    /// 插入任务记录并返回自增 ID。
    pub async fn insert_task(&self, task: TaskInsert<'_>) -> crate::Result<i64> {
        let id = insert_task_row(&self.pool, self.dialect, &task).await?;
        self.notify_state_changed();
        Ok(id)
    }

    /// 事务内插入任务行与其标签（全成或全不成）；标签先过组校验。
    pub async fn create_task_with_labels(
        &self,
        task: TaskInsert<'_>,
        labels: &[(String, String)],
    ) -> crate::Result<i64> {
        crate::validation::validate_task_labels(labels)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .db_ctx("begin create task with labels")?;
        let id = insert_task_row(&mut *tx, self.dialect, &task).await?;
        for (key, value) in labels {
            sqlx::query(sql::INSERT_TASK_LABEL)
                .bind(id)
                .bind(key)
                .bind(value)
                .execute(&mut *tx)
                .await
                .db_ctx("insert task label")?;
        }
        tx.commit().await.db_ctx("commit create task with labels")?;
        self.notify_state_changed();
        Ok(id)
    }

    /// 读取任务标签（按键排序）；未知任务返回空列表。
    pub async fn get_task_labels(&self, task_id: i64) -> crate::Result<Vec<(String, String)>> {
        let rows = sqlx::query(sql::SELECT_TASK_LABELS)
            .bind(task_id)
            .fetch_all(&self.pool)
            .await
            .db_ctx("get task labels")?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get::<String, _>("key"), r.get::<String, _>("value")))
            .collect())
    }

    /// 更新任务结果目录。
    pub async fn update_task_result_dir(
        &self,
        id: i64,
        result_dir: Option<&str>,
    ) -> crate::Result<()> {
        sqlx::query(sql::UPDATE_TASK_RESULT_DIR)
            .bind(result_dir)
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("update task result_dir")?;
        Ok(())
    }

    /// 更新任务 SRPM 路径。
    pub async fn update_task_srpm_path(&self, id: i64, srpm_path: &str) -> crate::Result<()> {
        sqlx::query(sql::UPDATE_TASK_SRPM_PATH)
            .bind(srpm_path)
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("update task srpm_path")?;
        Ok(())
    }
}
