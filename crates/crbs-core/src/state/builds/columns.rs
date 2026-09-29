// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建列级更新（签名/发布轴/确定性/血缘/SRPM 体积）与取件、优先级统计。

use std::collections::HashMap;

use super::completion::priority_count_map;
use super::sql;
use crate::error::DbResultExt;
use crate::state::{pending_build_info_from_row, Dialect, PendingBuildInfo, StateStore};
use crate::types::BuildPriority;

impl StateStore {
    /// 更新签名完成标记（幂等；行不存在时静默 no-op）。
    pub async fn update_build_signed(&self, id: i64, signed: bool) -> crate::Result<()> {
        sqlx::query(sql::UPDATE_BUILD_SIGNED)
            .bind(if signed { 1i64 } else { 0i64 })
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("update build signed")?;
        Ok(())
    }

    /// 设置 repo 发布开关：false = 产物从 repo 候选集消失（unpublish），true
    /// 恢复（publish）。仅翻标志不动磁盘，收敛由后续 regen 完成。
    pub async fn set_build_repo_publish(&self, id: i64, publish: bool) -> crate::Result<()> {
        sqlx::query(sql::UPDATE_BUILD_REPO_PUBLISH)
            .bind(if publish { 1i64 } else { 0i64 })
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("update build repo_publish")?;
        Ok(())
    }

    /// 设置确定性模式标记：deterministic 模式下宏组 / env 基线 / 溯源
    /// 硬门生效，重放比对/自动跟跑以它为触发。插入走 DB 默认值 0。
    pub async fn set_build_deterministic(&self, id: i64, deterministic: bool) -> crate::Result<()> {
        sqlx::query(sql::UPDATE_BUILD_DETERMINISTIC)
            .bind(if deterministic { 1i64 } else { 0i64 })
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("update build deterministic")?;
        Ok(())
    }

    /// 批次归属回填：task 下 batch_id IS NULL 的构建行标到批次（fan-out 建队
    /// 后调用）。不抢占既有归属；纯元数据写，返回翻转行数。
    pub async fn attach_task_builds_to_batch(
        &self,
        task_id: i64,
        batch_id: i64,
    ) -> crate::Result<u64> {
        let result = sqlx::query(sql::ATTACH_TASK_BUILDS_TO_BATCH)
            .bind(batch_id)
            .bind(task_id)
            .execute(&self.pool)
            .await
            .db_ctx("attach task builds to batch")?;
        Ok(result.rows_affected())
    }

    /// 写血缘锚：输入 SRPM 原样字节 sha256（任务内各 arch 子构建
    /// 共享同值），幂等。0 行报 NotFound（调用方 warn 包装为 best-effort）。
    pub async fn set_build_canonical_srpm_sha256(
        &self,
        id: i64,
        sha256: &str,
    ) -> crate::Result<()> {
        let result = sqlx::query(sql::UPDATE_BUILD_CANONICAL_SRPM)
            .bind(sha256)
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("update build canonical_srpm_sha256")?;
        if result.rows_affected() == 0 {
            return Err(crate::error::CrbsError::NotFound {
                message: format!("build {id} not found"),
            });
        }
        Ok(())
    }

    /// 写 SRPM 原样字节大小（heavy steering 的"重包"判据输入；staging
    /// 完成后提交侧调用）。幂等覆盖。0 行报 NotFound（调用方 best-effort warn）。
    pub async fn set_build_srpm_size_bytes(&self, id: i64, size_bytes: i64) -> crate::Result<()> {
        let result = sqlx::query(sql::UPDATE_BUILD_SRPM_SIZE)
            .bind(size_bytes)
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("update build srpm_size_bytes")?;
        if result.rows_affected() == 0 {
            return Err(crate::error::CrbsError::NotFound {
                message: format!("build {id} not found"),
            });
        }
        Ok(())
    }

    /// 读取重放来源 ID：解析 request_json 的 `reproduce_from_build_id`。
    /// None = 普通构建或不可解析（按普通处理）；判 replay 的单一事实源。
    pub async fn get_build_reproduce_source(&self, id: i64) -> crate::Result<Option<i64>> {
        let json: Option<Option<String>> = sqlx::query_scalar(sql::SELECT_REQUEST_JSON)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("select request_json for reproduce source")?;
        let Some(Some(text)) = json else {
            return Ok(None);
        };
        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        Ok(value
            .get("reproduce_from_build_id")
            .and_then(serde_json::Value::as_i64))
    }

    /// 任务详情页/API 的复现血缘（双向）：`replay_source` = 本任务是复现任务
    /// 时的 (源构建 id, 源任务 id)；`replays` = 指向本任务子构建的复现任务
    /// (task_id, phase)。LIKE 粗筛防畸形 request_json 的 cast 报错，键值合法性
    /// 由 id 文本比对保证（非数字值自然不命中）。
    pub async fn task_lineage(&self, task_id: i64) -> crate::Result<crate::types::TaskLineage> {
        // 血缘键提取与 id 文本化按方言分叉（PG: ::json->>/::text；SQLite:
        // json_extract/CAST）；提取包 CASE 短路——方言 WHERE/投影无求值顺序保证。
        let (lineage_expr, lineage_expr_b, id_text_expr) = match self.dialect {
            Dialect::Sqlite => (
                "json_extract(request_json, '$.reproduce_from_build_id')",
                "json_extract(b.request_json, '$.reproduce_from_build_id')",
                "CAST(id AS TEXT)",
            ),
            #[cfg(feature = "postgres")]
            Dialect::Postgres => (
                "request_json::json->>'reproduce_from_build_id'",
                "b.request_json::json->>'reproduce_from_build_id'",
                "id::text",
            ),
        };
        let replay_source_sql = format!(
            "SELECT src.id, src.task_id FROM builds src \
             WHERE src.task_id IS NOT NULL AND {id_text_expr} IN \
                 (SELECT CASE WHEN request_json LIKE '%reproduce_from_build_id%' \
                              THEN {lineage_expr} END FROM builds \
                  WHERE task_id = $1) \
             ORDER BY src.id LIMIT 1"
        );
        let replays_sql = format!(
            "SELECT DISTINCT t.id, t.phase FROM tasks t \
             JOIN builds b ON b.task_id = t.id \
             WHERE t.id != $1 \
               AND CASE WHEN b.request_json LIKE '%reproduce_from_build_id%' \
                        THEN {lineage_expr_b} END \
                    IN (SELECT {id_text_expr} FROM builds WHERE task_id = $1) \
             ORDER BY t.id"
        );
        let replay_source: Option<(i64, i64)> = sqlx::query_as(&replay_source_sql)
            .bind(task_id)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("select replay source for task")?;
        let replays: Vec<(i64, String)> = sqlx::query_as(&replays_sql)
            .bind(task_id)
            .fetch_all(&self.pool)
            .await
            .db_ctx("select replay tasks for task")?;
        Ok(crate::types::TaskLineage {
            replay_source: replay_source
                .map(|(build_id, task_id)| crate::types::LineageSource { build_id, task_id }),
            replays: replays
                .into_iter()
                .map(|(task_id, phase)| crate::types::ReplayRef { task_id, phase })
                .collect(),
        })
    }

    /// 读取提交时的原始 request JSON；无该行或列值为 NULL 时返回 `None`
    ///（早期构建入库时尚未记录 request_json）。
    pub async fn get_build_request_json(&self, build_id: i64) -> crate::Result<Option<String>> {
        let json: Option<Option<String>> = sqlx::query_scalar(sql::SELECT_REQUEST_JSON)
            .bind(build_id)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("select build request_json")?;
        Ok(json.flatten())
    }

    /// 向 error_summary 追加非失败态提示（软告警通道）：追加不覆盖，超长由
    /// SQL 侧截断。失败态文案由 complete 系写入，本方法只补成功构建的软提示。
    pub async fn append_build_note(&self, id: i64, note: &str) -> crate::Result<()> {
        sqlx::query(sql::APPEND_BUILD_NOTE)
            .bind(id)
            .bind(note)
            .execute(&self.pool)
            .await
            .db_ctx("append build note to error_summary")?;
        Ok(())
    }

    /// 重置 pending 构建的 started_at（崩溃恢复后）：避免旧任务因排队时长
    /// 累积获得不公平调度优势。
    pub async fn reset_pending_build_timestamp(&self, id: i64) -> crate::Result<()> {
        sqlx::query(&sql::reset_pending_build_timestamp(self.dialect))
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("reset pending build timestamp")?;
        Ok(())
    }

    /// 按本地架构原子选取并锁定下一个 pending 构建（置 building）。仅取
    /// 就绪行（srpm_path / request_json 非空）——调用方对 RETURNING 列按
    /// `Some` 消费依赖此契约。条件更新：目标被并发取走则 UPDATE 落空
    /// 返回 `None`，调用方释放 permit 回退。
    pub async fn pick_and_lock_pending_for_local_arch(
        &self,
        arch: &str,
        priority_filter: Option<BuildPriority>,
    ) -> crate::Result<Option<PendingBuildInfo>> {
        let with_priority = priority_filter.is_some();
        let sql = sql::pick_and_lock_pending(self.dialect, with_priority);
        let mut q = sqlx::query(&sql).bind(arch);
        if let Some(p) = priority_filter {
            q = q.bind(p);
        }
        let row = q
            .fetch_optional(&self.pool)
            .await
            .db_ctx("pick and lock pending for local arch")?;

        let picked = row.map(|r| pending_build_info_from_row(&r));
        // 本地调度迁移（pending → building）即广播；None 无状态变化不广播。
        if picked.is_some() {
            self.notify_state_changed();
        }
        Ok(picked)
    }

    /// 更新构建任务的优先级（仅 pending 状态可修改）。
    pub async fn update_build_priority(
        &self,
        id: i64,
        priority: BuildPriority,
    ) -> crate::Result<()> {
        let result = sqlx::query(sql::UPDATE_BUILD_PRIORITY_IF_PENDING)
            .bind(priority)
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("update build priority")?;

        if result.rows_affected() == 0 {
            return Err(crate::error::CrbsError::ValidationFailed {
                message: format!("Build {} is not in pending state or does not exist", id),
            });
        }
        Ok(())
    }

    /// 统计各优先级的 pending 任务数量。
    pub async fn count_pending_by_priority(&self) -> crate::Result<HashMap<BuildPriority, i64>> {
        let rows = sqlx::query(sql::COUNT_PENDING_BY_PRIORITY)
            .fetch_all(&self.pool)
            .await
            .db_ctx("count pending by priority")?;
        Ok(priority_count_map(rows))
    }

    /// 各优先级的本地活跃构建数（building 且无活跃 worker_tasks 行）：本地槽
    /// 预留计算用；distributed 并发由 per-worker capacity 约束，不计入。
    pub async fn count_local_building_by_priority(
        &self,
    ) -> crate::Result<HashMap<BuildPriority, i64>> {
        let rows = sqlx::query(sql::COUNT_LOCAL_BUILDING_BY_PRIORITY)
            .fetch_all(&self.pool)
            .await
            .db_ctx("count local builds by priority")?;
        Ok(priority_count_map(rows))
    }

    /// 按 id 批量取 (id, product, source_name, arch)：本地取件预检（水位门/
    /// 硬下限）的在跑权重与下限解析输入——active_builds 内存注册表只持有 id，
    /// 三维权重键需 (product, source_name, arch) 全量（source_name = builds.name
    /// 源码包基础名）。爬坡窗口谓词（`ramp_secs`）与分布式 Σ 供数同口径：
    /// started_at 在派发与领取时即写入，窗口内起跑的行才算在跑压载，爬满后
    /// 的负载已体现在宿主 load1 中；NULL 臂仅防御历史脏行（视同爬坡期计入）。
    /// arch 经 NULLIF 归一（PG 空串 / SQLite NULL 同语义）。id 集来自进程内存，
    /// 行数以 max_local_builds 为上界；超 bind 上限报错（调用方按缺数据降级为
    /// 空 Σ）。
    pub async fn list_build_pkgs_by_ids(
        &self,
        ids: &[i64],
        ramp_secs: i64,
    ) -> crate::Result<Vec<(i64, String, String, Option<String>)>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = crate::state::db::in_placeholders(1, ids.len())?;
        let sql = format!(
            "SELECT id, product, name, NULLIF(arch, '') FROM builds \
             WHERE id IN ({placeholders}) \
               AND (started_at IS NULL OR started_at >= {})",
            self.dialect.sql_seconds_ago(ramp_secs)
        );
        let mut q = sqlx::query_as::<_, (i64, String, String, Option<String>)>(&sql);
        for id in ids {
            q = q.bind(id);
        }
        q.fetch_all(&self.pool)
            .await
            .db_ctx("list build pkgs by ids")
    }
}
