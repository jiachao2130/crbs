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

    /// 不变量：挂载存在 ⇒ phase='building'（pick/claim 翻相先于挂载建立）。
    /// 不得扩到 pending/assigned：繁忙队列 pending 恒存在会让活跃目录集恒
    /// 非空，杀死全局孤儿清理。对比 gc.rs::LIST_LEAKED_LAYERS 有意用三态
    ///（reclaim 重置回 pending 的行会重派复用，不算泄漏）。
    /// 已知残余窄窗：假性 reclaim（行重置 pending 而 worker 仍持挂载）时本集
    /// 合漏检，同机部署下孤儿 GC 存在误卸窗口。
    pub(super) const LIST_ACTIVE_BUILD_RESULT_DIRS: &str =
        "SELECT result_dir FROM builds WHERE phase = 'building'";

    pub(super) const LIST_ALL_RESULT_DIRS: &str =
        "SELECT result_dir FROM builds WHERE result_dir IS NOT NULL";

    pub(super) const LIST_TASK_RESULT_DIRS: &str =
        "SELECT id, product, result_dir FROM tasks WHERE result_dir IS NOT NULL";

    /// 按任务列子构建 (build_id, result_dir)——GC per-build 钉住通道（无方言差异）。
    pub(super) const LIST_BUILD_RESULT_DIRS_FOR_TASK: &str =
        "SELECT id, result_dir FROM builds WHERE task_id = $1";

    /// 按行数参数化的多行 VALUES upsert（方言感知，时间源各按方言取、每行独立
    /// 求值）：列清单 / ON CONFLICT 冲突列与更新列逐列镜像，双方言此处语法一致，
    /// 统一 `ON CONFLICT DO UPDATE`（原地更新，行身份与 created_at 不变；回归测试
    /// upsert_package_url_updates_in_place_keeping_row_identity）；SQLite 禁用
    /// INSERT OR REPLACE（delete+reinsert 会重置 created_at）。占位符 $N 三连号
    /// 双方言通用（与单行写法同语法）；`rows` ≥ 1 由调用方分块保证。
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

    /// 动态 IN(?,?,...) 占位符由调用方按 nevras 数量拼接后 format! 到 `{}` 位置（通用 SQL，无方言差异）。
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

/// put_package_urls 分块行数：块大小 = 单事务写锁持有时长预算。
/// ponytail: 250 行在慢节点约毫秒级，放大需以最慢节点单块实测为准（升级路径：
/// 调常量）；绑定数 3×250=750 远低于 MAX_BIND_PARAMS=30000 双方言兜底。
const PUT_CHUNK_ROWS: usize = 250;

impl StateStore {
    /// 层 GC 候选：`complete` 且 `ref_count = 0` 且 `scheduled_gc_at <= now`（now 由方言
    /// 时间函数生成），返回完整 `LayerRecord`。
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

    /// 活跃构建（`phase='building'`）的 result_dir 集（NULL 剔除），孤儿挂载清理的保护集；
    /// 集合口径（不扩 pending/assigned、reclaim 三态不算泄漏）见 `sql::LIST_ACTIVE_BUILD_RESULT_DIRS`。
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

    /// 列出所有仍指向有效 result_dir 的路径（用于包缓存 GC 扫描）。
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

    /// GC 钉住扫描入口：任务目录下的 recipe.json 是 retention 窗口内免驱逐引用的来源。
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

    /// 按任务列子构建 `(build_id, result_dir)`，result_dir 可 NULL（未落盘的
    /// 子构建由调用方按缺失跳过）；钉住 per-build build_packages.json 的
    /// 唯一指针，不从 recipe 字段重建布局（collect_recipe_pinned_sha256）。
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

    /// 批量获取已缓存 package URL：返回命中 `(nevra -> url)`（未命中不出现），命中即刷新 last_used_at。
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
            // hit 列表 ⊆ select 入参列表，占位符守卫必过，`?` 仅为签名传播。
            let placeholders = crate::state::db::in_placeholders(2, hit_nevras.len())?;
            let touch_sql = sql::touch_package_urls(self.dialect, &placeholders);
            let mut touch = sqlx::query(&touch_sql).bind(repo_baseurl);
            for nevra in &hit_nevras {
                touch = touch.bind(nevra);
            }
            if let Err(e) = touch.execute(&self.pool).await {
                // baseurl 可能内嵌凭证，脱敏后落日志。
                let sanitized = crate::logging::redact_userinfo(repo_baseurl);
                warn!(repo = %sanitized, error = %e, "Failed to touch package_urls");
            }
        }

        Ok(rows
            .into_iter()
            .map(|r| (r.get::<String, _>("nevra"), r.get::<String, _>("url")))
            .collect())
    }

    /// 批量 upsert package URL（空 map 不开事务）：nevra 排序后按 PUT_CHUNK_ROWS
    /// 分块，每块独立事务执行一条多行 upsert；UNIQUE(repo_baseurl, nevra) 冲突
    /// 原地更新 url / last_used_at（行身份与 created_at 不变，双方言 ON CONFLICT，
    /// 时间各取方言时钟）。
    ///
    /// - 块边界 = 单事务写锁持有时长上界，块间释放写锁让其他写者穿插，并发
    ///   波峰下锁链不累积（本分块形态的存在理由）。
    /// - 部分提交契约：前块已提交、后续某块失败即返回 Err；upsert 幂等，写入方
    ///   按 best-effort warn 处理，失败重试自然收敛。
    /// - 排序动机：HashMap 遍历序不稳定，按 nevra 排序固定分块切点，同数据
    ///   同块（分块结果与失败现场可复现）。
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

    /// 删除 `last_used_at <= now - ttl_days` 的 package URL（时间按方言），返回删除行数；
    /// `ttl_days` 以 i64 饱和截断防溢出。
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
