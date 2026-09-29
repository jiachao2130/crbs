// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! GC 查询与安全集合：活跃结果目录、层引用与删除候选。

use std::collections::HashMap;
use std::path::PathBuf;

use sqlx::Row;
use tracing::warn;

use super::{layer_record_from_row, LayerRecord, StateStore};
use crate::error::DbResultExt;

mod sql {
    use crate::state::Dialect;

    pub(super) fn list_layers_for_gc(dialect: Dialect) -> String {
        format!(
            "SELECT digest, path, product, status, ref_count, created_at, scheduled_gc_at \
             FROM layers \
             WHERE status = 'complete' AND ref_count = 0 AND scheduled_gc_at <= {}",
            dialect.sql_now()
        )
    }

    pub(super) const LIST_ACTIVE_BUILD_RESULT_DIRS: &str =
        "SELECT result_dir FROM builds WHERE phase = 'building'";

    pub(super) const LIST_ALL_RESULT_DIRS: &str =
        "SELECT result_dir FROM builds WHERE result_dir IS NOT NULL";

    pub(super) const LIST_TASK_RESULT_DIRS: &str =
        "SELECT id, product, result_dir FROM tasks WHERE result_dir IS NOT NULL";

    pub(super) const LIST_BUILD_RESULT_DIRS_FOR_TASK: &str =
        "SELECT id, result_dir FROM builds WHERE task_id = $1";

    pub(super) fn upsert_package_urls_multi(dialect: Dialect, rows: usize) -> String {
        let (ts, excluded) = match dialect {
            Dialect::Sqlite => ("strftime('%s','now')", "excluded"),
            #[cfg(feature = "postgres")]
            Dialect::Postgres => ("EXTRACT(EPOCH FROM NOW())::bigint", "EXCLUDED"),
        };
        let rows_sql: Vec<String> = (0..rows)
            .map(|i| {
                let b = i * 3;
                format!("(${},${},${}, {ts}, {ts})", b + 1, b + 2, b + 3)
            })
            .collect();
        format!(
            "INSERT INTO package_urls \
             (repo_baseurl, nevra, url, created_at, last_used_at) \
             VALUES {} \
             ON CONFLICT (repo_baseurl, nevra) DO UPDATE SET \
                 url = {excluded}.url, \
                 last_used_at = {excluded}.last_used_at",
            rows_sql.join(","),
        )
    }

    pub(super) fn purge_stale_package_urls(dialect: Dialect, days: i64) -> String {
        match dialect {
            Dialect::Sqlite => format!(
                "DELETE FROM package_urls \
                 WHERE last_used_at <= strftime('%s','now', '-{} days')",
                days
            ),
            #[cfg(feature = "postgres")]
            Dialect::Postgres => format!(
                "DELETE FROM package_urls \
                 WHERE last_used_at <= EXTRACT(EPOCH FROM (NOW() - INTERVAL '{} days'))::bigint",
                days
            ),
        }
    }

    pub(super) const SELECT_PACKAGE_URLS_TEMPLATE: &str = "SELECT nevra, url FROM package_urls \
         WHERE repo_baseurl = $1 AND nevra IN ({})";

    pub(super) fn touch_package_urls(dialect: Dialect, placeholders: &str) -> String {
        match dialect {
            Dialect::Sqlite => format!(
                "UPDATE package_urls \
                 SET last_used_at = strftime('%s','now') \
                 WHERE repo_baseurl = $1 AND nevra IN ({})",
                placeholders
            ),
            #[cfg(feature = "postgres")]
            Dialect::Postgres => format!(
                "UPDATE package_urls \
                 SET last_used_at = EXTRACT(EPOCH FROM NOW())::bigint \
                 WHERE repo_baseurl = $1 AND nevra IN ({})",
                placeholders
            ),
        }
    }
}

/// ponytail: 250 行在慢节点约毫秒级，放大需以最慢节点单块实测为准（升级路径：
/// 调常量）；绑定数 3×250=750 远低于 MAX_BIND_PARAMS=30000 双方言兜底。
const PUT_CHUNK_ROWS: usize = 250;

impl StateStore {
    /// 列出层 GC 候选：`complete` 状态、引用计数为零且 `scheduled_gc_at` 已到
    /// 期（到期判断由方言时间函数求值），返回完整 `LayerRecord`。
    pub async fn list_layers_for_gc(&self) -> crate::Result<Vec<LayerRecord>> {
        let rows = sqlx::query(&sql::list_layers_for_gc(self.dialect))
            .fetch_all(&self.pool)
            .await
            .db_ctx("list layers for gc")?;

        let records = rows
            .into_iter()
            .map(|r| layer_record_from_row(&r))
            .collect();

        Ok(records)
    }

    /// 列出活跃构建（`phase='building'`）的 result_dir 集合，NULL 已剔除，作
    /// 为挂载泄漏清理的保护集：清理只允许触碰集合之外的路径。集合口径为单一
    /// building 状态——不扩到 pending/assigned（繁忙队列的 pending 行恒存在，
    /// 会使保护集恒非空、清理失效），重置回 pending 等待重派的构建不算泄漏。
    /// 已知窄窗：行被重置 pending 而 worker 仍持挂载时，该目录不在集合内，
    /// 同机部署存在误清理可能。
    pub async fn list_active_build_result_dirs(&self) -> crate::Result<Vec<PathBuf>> {
        let rows = sqlx::query(sql::LIST_ACTIVE_BUILD_RESULT_DIRS)
            .fetch_all(&self.pool)
            .await
            .db_ctx("query active builds")?;
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                let dir: Option<String> = r.get("result_dir");
                dir.map(PathBuf::from)
            })
            .collect())
    }

    /// 列出所有构建记录中仍指向有效 result_dir 的路径，供包缓存 GC 扫描使用。
    pub async fn list_all_result_dirs(&self) -> crate::Result<Vec<PathBuf>> {
        let rows = sqlx::query(sql::LIST_ALL_RESULT_DIRS)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list result dirs")?;

        Ok(rows
            .into_iter()
            .map(|r| PathBuf::from(r.get::<String, _>("result_dir")))
            .collect())
    }

    /// 列出任务的 `(task_id, product, result_dir)`，作为 GC 引用扫描入口：
    /// 任务目录下的 recipe.json 是 retention 窗口内免驱逐引用的来源。
    pub async fn list_task_result_dirs(&self) -> crate::Result<Vec<(i64, String, PathBuf)>> {
        let rows = sqlx::query(sql::LIST_TASK_RESULT_DIRS)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list task result dirs for recipe GC pinning")?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<i64, _>("id"),
                    r.get::<String, _>("product"),
                    PathBuf::from(r.get::<String, _>("result_dir")),
                )
            })
            .collect())
    }

    /// 列出指定任务下子构建的 `(build_id, result_dir)`，result_dir 可为
    /// NULL，未落盘的子构建由调用方按缺失跳过。该清单是各子构建
    /// build_packages.json 的唯一引用来源，不依赖 recipe 字段重建布局。
    pub async fn list_build_result_dirs_for_task(
        &self,
        task_id: i64,
    ) -> crate::Result<HashMap<i64, Option<String>>> {
        let rows = sqlx::query(sql::LIST_BUILD_RESULT_DIRS_FOR_TASK)
            .bind(task_id)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list build result dirs for recipe GC pinning")?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<i64, _>("id"),
                    r.get::<Option<String>, _>("result_dir"),
                )
            })
            .collect())
    }

    /// 批量获取已缓存的 package URL，返回命中的 `(nevra -> url)` 映射，未
    /// 命中的 nevra 不出现在结果中；命中项同步刷新 last_used_at。
    pub async fn get_package_urls(
        &self,
        repo_baseurl: &str,
        nevras: &[String],
    ) -> crate::Result<HashMap<String, String>> {
        if nevras.is_empty() {
            return Ok(HashMap::new());
        }

        let placeholders = crate::state::db::in_placeholders(2, nevras.len())?;
        let select_sql = sql::SELECT_PACKAGE_URLS_TEMPLATE.replace("{}", &placeholders);

        let mut query = sqlx::query(&select_sql).bind(repo_baseurl);
        for nevra in nevras {
            query = query.bind(nevra);
        }

        let rows = query
            .fetch_all(&self.pool)
            .await
            .db_ctx("get package urls")?;

        let hit_nevras: Vec<String> = rows.iter().map(|r| r.get::<String, _>("nevra")).collect();
        if !hit_nevras.is_empty() {
            let placeholders = crate::state::db::in_placeholders(2, hit_nevras.len())?;
            let touch_sql = sql::touch_package_urls(self.dialect, &placeholders);
            let mut touch = sqlx::query(&touch_sql).bind(repo_baseurl);
            for nevra in &hit_nevras {
                touch = touch.bind(nevra);
            }
            if let Err(e) = touch.execute(&self.pool).await {
                let sanitized = crate::logging::redact_userinfo(repo_baseurl);
                warn!(repo = %sanitized, error = %e, "Failed to touch package_urls");
            }
        }

        Ok(rows
            .into_iter()
            .map(|r| (r.get::<String, _>("nevra"), r.get::<String, _>("url")))
            .collect())
    }

    /// 批量 upsert package URL，空 map 直接返回不开事务。nevra 排序后按块
    /// 拆分，每块在独立事务中执行一条多行 upsert；`UNIQUE(repo_baseurl,
    /// nevra)` 冲突时原地更新 url 与 last_used_at，行身份与 created_at 保持
    /// 不变，时间取各自方言时钟。
    ///
    /// 分块是并发边界：块大小即单事务写锁持有时长预算，块间释放写锁供其他
    /// 写者穿插，并发峰值下不累积锁等待。部分提交契约：前块已提交、后续块
    /// 失败即返回 Err；upsert 幂等，调用方按 best-effort 处理，重试自然收敛。
    /// 按 nevra 排序固定分块切点，相同数据得到相同分块，失败现场可复现。
    pub async fn put_package_urls(
        &self,
        repo_baseurl: &str,
        urls: &HashMap<String, String>,
    ) -> crate::Result<()> {
        if urls.is_empty() {
            return Ok(());
        }

        let mut entries: Vec<(&str, &str)> = urls
            .iter()
            .map(|(nevra, url)| (nevra.as_str(), url.as_str()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));

        for chunk in entries.chunks(PUT_CHUNK_ROWS) {
            let upsert_sql = sql::upsert_package_urls_multi(self.dialect, chunk.len());
            let mut query = sqlx::query(&upsert_sql);
            for (nevra, url) in chunk {
                query = query.bind(repo_baseurl).bind(*nevra).bind(*url);
            }
            let mut tx = self
                .pool
                .begin()
                .await
                .db_ctx("begin package_urls chunk tx")?;
            query
                .execute(&mut *tx)
                .await
                .db_ctx("put package urls chunk")?;
            tx.commit().await.db_ctx("commit package_urls chunk tx")?;
        }

        Ok(())
    }

    /// 删除 `last_used_at` 早于 `now - ttl_days` 的 package URL 记录，时间
    /// 计算按方言执行，返回删除行数；`ttl_days` 先经 i64 饱和截断再参与运算
    /// 以防溢出。
    pub async fn purge_stale_package_urls(&self, ttl_days: u64) -> crate::Result<usize> {
        let purge_sql = sql::purge_stale_package_urls(
            self.dialect,
            crate::util::u64_to_i64_saturating(ttl_days),
        );
        let rows = sqlx::query(&purge_sql)
            .execute(&self.pool)
            .await
            .db_ctx("purge stale package urls")?
            .rows_affected();

        Ok(rows as usize)
    }
}
