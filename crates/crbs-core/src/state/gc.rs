// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 状态库 GC：结果行、构建记录与过期数据的候选筛选和删除。

use std::path::{Path, PathBuf};

use sqlx::any::AnyRow;
use sqlx::Row;
use tracing::{error, info, warn};

use super::{
    build_record_from_row, layer_record_from_row, rollback_and_return, Dialect, BUILD_COLUMNS,
};
use crate::error::DbResultExt;

mod sql {
    use super::BUILD_COLUMNS;
    use crate::state::Dialect;

    pub(super) const LIST_PRODUCTS_WITH_RESULTS: &str = "SELECT DISTINCT product FROM builds \
         WHERE phase != 'building' AND completed_at IS NOT NULL AND result_dir IS NOT NULL";

    /// 结果 GC 候选基础子句；调用方追加 `AND product = ?` 与 `ORDER BY`；$1 是完整时间偏移 SQL 片段（方言感知）。
    pub(super) fn list_results_for_gc_base() -> String {
        "SELECT id, product, pkg_name, result_dir \
         FROM builds \
         WHERE phase != 'building' \
           AND completed_at IS NOT NULL \
           AND result_dir IS NOT NULL \
           AND completed_at <= {TIME_OFFSET}"
            .to_string()
    }

    /// per-package 超额剔除的内层 CTE 基础子句；调用方按需追加 `AND product = ?`。
    // 便携：ROW_NUMBER() OVER 是 SQL:2003 标准，SQLite 3.25+ / Postgres 均支持。
    // 候选防线不变量（test_per_pkg_excess_never_selects_newest_completed_build 钉住）：
    // `phase != 'building'` 活跃构建、未落终态完成时间的行绝不入候选（进行中产物随时
    // 可能被上报/引用；pending 行即使 phase 已翻终态也不入）；ROW_NUMBER 按 (product,
    // pkg_name) 分区 `completed_at DESC` 编号，最新终态构建恒 rn=1、任何有效 max
    //（>=1，require_positive_usize 保证）下不入选——超额回收永不删包最新成功产物。
    pub(super) const LIST_RESULTS_EXCEEDING_PER_PKG_INNER: &str =
        "SELECT id, product, pkg_name, result_dir, completed_at, \
                ROW_NUMBER() OVER (PARTITION BY product, pkg_name ORDER BY completed_at DESC) AS rn \
         FROM builds \
         WHERE phase != 'building' \
           AND completed_at IS NOT NULL \
           AND result_dir IS NOT NULL";

    /// per-package 超额剔除的外层包装：`{INNER}` 由调用方 replace 为内层 SQL。
    pub(super) const LIST_RESULTS_EXCEEDING_PER_PKG_OUTER: &str =
        "SELECT id, product, pkg_name, result_dir FROM ({INNER}) sub WHERE rn > $1 ORDER BY completed_at ASC";

    pub(super) const CLEAR_BUILD_RESULT_DIR: &str =
        "UPDATE builds SET result_dir = NULL WHERE id = $1";

    /// hub-local 产物登记崩溃窗口的 reconcile 候选集：`phase='succeeded'`、
    /// `result_dir` 非空、`build_artifacts` 零行。`NOT EXISTS` 匹配任意行（含结果
    /// GC 翻 `on_disk=0` 的保留行），产物已 GC 但行仍在的构建不会误判为漏登记；
    /// BUILD_COLUMNS 内联展开、双方言可移植。`EXISTS products` 按 **name** 过滤已删
    /// 产品（目录归结果 GC 回收，无产物可补）；必须用 name 而非 `product_id IS NOT
    /// NULL`：insert_build 自动解析 official-only，私人产品构建 product_id 恒 NULL 会漏修复。
    pub(super) fn list_succeeded_without_artifacts() -> String {
        format!(
            "SELECT {BUILD_COLUMNS} FROM builds \
             WHERE phase = 'succeeded' \
               AND result_dir IS NOT NULL AND result_dir != '' \
               AND NOT EXISTS (SELECT 1 FROM build_artifacts a WHERE a.build_id = builds.id) \
               AND EXISTS (SELECT 1 FROM products p WHERE p.name = builds.product)"
        )
    }

    /// 僵尸构建查询基础子句；调用方按需追加 `AND product = ?`。BUILD_COLUMNS 内联展开。
    /// 注意：started_at 是 TEXT 类型，PostgreSQL 需转 timestamp。
    pub(super) fn list_stale_builds_base(dialect: Dialect) -> String {
        match dialect {
            Dialect::Sqlite => format!(
                "SELECT {BUILD_COLUMNS} FROM builds \
                 WHERE phase = 'building' \
                   AND datetime(started_at, '+' || $1 || ' minutes') <= datetime('now')"
            ),
            #[cfg(feature = "postgres")]
            Dialect::Postgres => format!(
                "SELECT {BUILD_COLUMNS} FROM builds \
                 WHERE phase = 'building' \
                   AND started_at::timestamp + INTERVAL '1 minute' * $1 <= (NOW() AT TIME ZONE 'UTC')"
            ),
        }
    }

    pub(super) const SELECT_LAYER_DIGEST_FOR_BUILDING: &str =
        "SELECT layer_digest FROM builds WHERE id = $1 AND phase = 'building'";

    /// 将 building 状态的构建标记为 failed（方言感知时间）；终态 duration 同步落值
    ///（started_at 起算、NULL 传播 NULL，口径对齐 complete_build / mark_build_cancelled）。
    pub(super) fn mark_build_failed_if_building(dialect: Dialect) -> String {
        format!(
            "UPDATE builds \
             SET phase = 'failed', completed_at = {}, duration = {} \
             WHERE id = $1 AND phase = 'building'",
            dialect.sql_now(),
            dialect.sql_seconds_since("started_at")
        )
    }

    /// 泄漏 layer 定位（ref_count > 0 但无 pending/assigned/building 引用）；LEFT
    /// JOIN 替代子查询。phase 过滤必须放 JOIN 条件：builds 是历史账本、终态行永存，
    /// 不限 phase 则近期终态行把泄漏伪装成合法引用，检测对该层永久盲区；引用计数只
    /// 反映活跃构建（build 开始 inc、cleanup guard 终态前 dec）。三态有意：reclaim
    /// 重置回 pending 的行将重派复用；building-only 差异见 gc_queries.rs（设计非漂移）。
    pub(super) const LIST_LEAKED_LAYERS: &str =
        "SELECT l.digest, l.path, l.product, l.status, l.ref_count, l.created_at, l.scheduled_gc_at \
         FROM layers l \
         LEFT JOIN builds b ON l.digest = b.layer_digest \
           AND b.phase IN ('pending', 'assigned', 'building') \
         WHERE l.ref_count > 0 AND b.id IS NULL";
}

/// Result GC 候选记录。
#[derive(Debug, Clone)]
pub struct ResultGcCandidate {
    pub id: i64,
    pub product: String,
    pub pkg_name: String,
    pub result_dir: PathBuf,
}

fn map_rows_to_candidates(rows: Vec<AnyRow>) -> Vec<ResultGcCandidate> {
    rows.into_iter()
        .map(|r| ResultGcCandidate {
            id: r.get::<i64, _>("id"),
            product: r.get("product"),
            pkg_name: r.get("pkg_name"),
            result_dir: PathBuf::from(r.get::<String, _>("result_dir")),
        })
        .collect()
}

impl super::StateStore {
    /// 查询所有有候选结果的不同产品（用于无 --product 时分产品应用 grace_hours）。
    pub async fn list_products_with_results(&self) -> crate::Result<Vec<String>> {
        let rows = sqlx::query(sql::LIST_PRODUCTS_WITH_RESULTS)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list products with results")?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<String, _>("product"))
            .collect())
    }

    /// 查询过期结果目录候选。
    pub async fn list_results_for_gc(
        &self,
        product: Option<&str>,
        grace_hours: u64,
    ) -> crate::Result<Vec<ResultGcCandidate>> {
        let time_offset = format!("-{} hours", grace_hours);
        let time_sql = match self.dialect {
            Dialect::Sqlite => format!("datetime('now', '{}')", time_offset),
            #[cfg(feature = "postgres")]
            Dialect::Postgres => format!(
                "to_char((NOW() AT TIME ZONE 'UTC') + INTERVAL '{}', 'YYYY-MM-DD HH24:MI:SS')",
                time_offset
            ),
        };
        let mut sql_buf = sql::list_results_for_gc_base();
        sql_buf = sql_buf.replace("{TIME_OFFSET}", &time_sql);
        if product.is_some() {
            sql_buf.push_str(" AND product = $1");
        }
        sql_buf.push_str(" ORDER BY completed_at ASC");

        let mut q = sqlx::query(&sql_buf);
        if let Some(p) = product {
            q = q.bind(p);
        }

        let rows = q
            .fetch_all(&self.pool)
            .await
            .db_ctx("list results for gc")?;
        Ok(map_rows_to_candidates(rows))
    }

    /// 每个 (product, pkg_name) 超过 `max_count` 的最旧 result_dir。
    pub async fn list_results_exceeding_count_per_pkg(
        &self,
        product: Option<&str>,
        max_count: usize,
    ) -> crate::Result<Vec<ResultGcCandidate>> {
        let max = max_count as i64;
        let mut inner = String::from(sql::LIST_RESULTS_EXCEEDING_PER_PKG_INNER);
        let mut outer = String::from(sql::LIST_RESULTS_EXCEEDING_PER_PKG_OUTER);
        if product.is_some() {
            inner.push_str(" AND product = $1");
            outer = outer.replace("rn > $1", "rn > $2");
        }
        let sql_buf = outer.replace("{INNER}", &inner);

        let mut q = sqlx::query(&sql_buf);
        if let Some(p) = product {
            q = q.bind(p);
        }
        q = q.bind(max);

        let rows = q
            .fetch_all(&self.pool)
            .await
            .db_ctx("list results exceeding count per pkg")?;
        Ok(map_rows_to_candidates(rows))
    }

    /// completed_at 超过 `retention_days` 的所有 result_dir。
    pub async fn list_results_older_than_days(
        &self,
        product: Option<&str>,
        days: u64,
    ) -> crate::Result<Vec<ResultGcCandidate>> {
        let time_sql = self.sql_days_ago(crate::util::u64_to_i64_saturating(days));
        let mut sql_buf = sql::list_results_for_gc_base();
        sql_buf = sql_buf.replace("{TIME_OFFSET}", &time_sql);
        if product.is_some() {
            sql_buf.push_str(" AND product = $1");
        }
        sql_buf.push_str(" ORDER BY completed_at ASC");

        let mut q = sqlx::query(&sql_buf);
        if let Some(p) = product {
            q = q.bind(p);
        }

        let rows = q
            .fetch_all(&self.pool)
            .await
            .db_ctx("list results older than days")?;
        Ok(map_rows_to_candidates(rows))
    }

    /// 清空构建记录的 result_dir（GC 成功后调用，保留历史记录）。
    pub async fn clear_build_result_dir(&self, id: i64) -> crate::Result<()> {
        sqlx::query(sql::CLEAR_BUILD_RESULT_DIR)
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("clear build result dir")?;
        Ok(())
    }

    /// 列出 building/pending 超过指定分钟数的记录（僵尸检测；pending 一并计入，
    /// 防崩溃后卡队列的行漏扫——started_at 为 NULL 的行不入集）；product = None
    /// 全局、Some 只查该产品。
    pub async fn list_stale_builds(
        &self,
        stale_minutes: i64,
        product: Option<&str>,
    ) -> crate::Result<Vec<super::BuildRecord>> {
        let mut sql_buf = sql::list_stale_builds_base(self.dialect);
        if product.is_some() {
            sql_buf.push_str(" AND product = $2");
        }

        let mut q = sqlx::query(&sql_buf).bind(stale_minutes);
        if let Some(p) = product {
            q = q.bind(p);
        }

        let rows = q.fetch_all(&self.pool).await.db_ctx("list stale builds")?;

        Ok(rows
            .into_iter()
            .map(|r| build_record_from_row(&r))
            .collect())
    }

    /// 列出"succeeded + result_dir 非空 + build_artifacts 零行"的构建，供周期
    /// reconcile 重采集 + 幂等 upsert 兜底：hub-local 的 engine 翻 succeeded（含
    /// result_dir 落库）与独立事务 insert_artifacts_tx 之间有崩溃窗口。零产物行对
    /// succeeded 非常规合法态：两条上传路径都在终态前落产物行、结果 GC 只翻 on_disk
    /// 不删行、retention prune 只删 result_dir IS NULL 的构建——合法零行仅剩目录本就
    /// 空的病态构建（collect 后为空应跳过）；已删产品不在候选集（EXISTS 过滤，见 sql 注释）。
    pub async fn list_succeeded_builds_without_artifacts(
        &self,
    ) -> crate::Result<Vec<super::BuildRecord>> {
        let rows = sqlx::query(&sql::list_succeeded_without_artifacts())
            .fetch_all(&self.pool)
            .await
            .db_ctx("list succeeded builds without artifacts")?;
        Ok(rows
            .into_iter()
            .map(|r| build_record_from_row(&r))
            .collect())
    }

    /// 批量修复僵尸构建为 failed 并递减关联 layer 的 ref_count（单事务批量）。
    pub async fn repair_stale_builds(&self, ids: &[i64]) -> crate::Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }

        // begin_write() 先拿写锁：避免 DEFERRED 读后升级撞 SQLITE_BUSY_SNAPSHOT。
        let mut conn = self.begin_write().await?;

        // BEGIN 后任何错误（含 COMMIT 失败）先 ROLLBACK，防开着事务的连接回池（SQLite 持写锁 / PG 池污染）。
        let mark_failed_sql = sql::mark_build_failed_if_building(self.dialect);

        let mut layer_digests: Vec<String> = Vec::new();
        let mut repaired = 0usize;

        for id in ids {
            // layer_digest 可为 NULL（崩溃构建可能尚未关联 layer）；scalar 类型必须
            // Option<String>，否则 Any 驱动 NULL 解码 String 报错——僵尸永修不了、阻塞孤儿清理守卫。
            let layer_digest: Option<String> = match sqlx::query_scalar::<_, Option<String>>(
                sql::SELECT_LAYER_DIGEST_FOR_BUILDING,
            )
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .db_ctx("query layer_digest")
            {
                Ok(v) => v.flatten(),
                Err(e) => rollback_and_return!(conn, e),
            };

            let updated = match sqlx::query(&mark_failed_sql)
                .bind(id)
                .execute(&mut *conn)
                .await
                .db_ctx("repair stale build")
            {
                Ok(r) => r,
                Err(e) => rollback_and_return!(conn, e),
            };

            if updated.rows_affected() > 0 {
                if let Some(digest) = layer_digest {
                    layer_digests.push(digest);
                }
                repaired += 1;
            }
        }

        // 批量递减 ref_count：必须用归零即安装 scheduled_gc_at 的 SQL——裸 dec 到 0 后
        // 该行对 list_layers_for_gc（schedule <= now）与 list_leaked_layers（ref > 0）
        // 两个回收器都不可见，永久泄漏。宽限恒用编译期默认 168h、非 operator 配置的
        // shared_layer_gc_grace_hours（state 释放侧签名不携带引擎全局配置；漂移全图见
        // engine/shell.rs dec 消费点注释）。三类口径：① 引擎侧 dec（shell、cleanup_guard、
        // build/mod.rs 回滚）= operator 配置；② state 释放侧（本处、zombie.rs、users.rs
        // ACL revoke、products 删除/转移、fast-path 回滚）= 恒 168h；③ CLI 取消 stale
        // build（crbs/src/cmd/mod.rs）= 0（执行者已死，立即进候选）。①②漂移仅影响调度时刻，ref=0 闸门保证在用层不被 GC。
        let grace_hours = crate::config::defaults::default_shared_layer_gc_grace_hours() as i64;
        for digest in layer_digests {
            if let Err(e) = self
                .layer_ref_dec_in_tx(&mut conn, &digest, grace_hours)
                .await
            {
                // 透传即可：内层已 db_ctx（含 Database/DatabaseUnavailable 分类），
                // 二次包 Database(format!) 会降级分类（503/is_transient 丢失）且
                // Display 双重嵌套；tx 版结构上产不出 LayerNotFound（仅非 tx 版特判）。
                rollback_and_return!(conn, e);
            }
        }

        match sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit tx")
        {
            Ok(_) => {}
            Err(e) => rollback_and_return!(conn, e),
        }

        Ok(repaired)
    }

    /// 泄漏检测：ref_count > 0 但无活跃构建引用的 layer；引用计数只反映活跃构建
    ///（build 起 inc、终态前 dec），JOIN 限活跃 phase 的理由见 `sql::LIST_LEAKED_LAYERS`。
    pub async fn list_leaked_layers(&self) -> crate::Result<Vec<super::LayerRecord>> {
        let rows = sqlx::query(sql::LIST_LEAKED_LAYERS)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list leaked layers")?;

        Ok(rows
            .into_iter()
            .map(|r| layer_record_from_row(&r))
            .collect())
    }

    /// 运行垃圾回收：清理过期共享层，返回清理层数。安全边界：每行 `path` 必须位于
    /// `{shared_layers_root}/{digest}` 之下，删除前经 `crate::gc::assert_delete_under_root`
    /// 断言严格位于根之下——DB 行可疑（路径逃逸）时跳过该行记 error，不删目录也不删行。
    pub async fn run_gc(&self, shared_layers_root: &Path) -> crate::Result<usize> {
        use fs4::tokio::AsyncFileExt;

        let layers = self.list_layers_for_gc().await?;
        let mut cleaned = 0usize;

        for layer in &layers {
            // path 必须落在 {root}/{digest} 命名空间内：不匹配即可疑行（手工改库/迁移残留），跳过不删行。
            let expected_ns = shared_layers_root.join(&layer.digest);
            if !Path::new(&layer.path).starts_with(&expected_ns) {
                warn!(
                    digest = %layer.digest,
                    path = %layer.path,
                    shared_layers_root = %shared_layers_root.display(),
                    "layer path outside its digest namespace; skipping GC for suspicious DB row"
                );
                continue;
            }
            let layer_dir = std::path::Path::new(&layer.path).parent().ok_or_else(|| {
                crate::error::CrbsError::Database(format!(
                    "layer path has no parent: {}",
                    layer.path
                ))
            })?;
            let lock_path = layer_dir.join(".lock");

            let lock_file = match tokio::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&lock_path)
                .await
            {
                Ok(f) => f,
                // 目录已不存在：崩在"删目录后、删行前"窗口的残留，直接补删行自愈。
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    match self.delete_layer(&layer.digest).await {
                        Ok(()) => cleaned += 1,
                        Err(e) => warn!(
                            digest = %layer.digest,
                            error = %e,
                            "Failed to delete layer record during GC"
                        ),
                    }
                    continue;
                }
                Err(e) => {
                    // 静默跳过（EACCES/0644 历史锁文件、EIO 等）会让该层永久不可 GC，至少留日志。
                    warn!(
                        digest = %layer.digest,
                        path = %lock_path.display(),
                        error = %e,
                        "Failed to open layer lock during GC, skipping layer"
                    );
                    continue;
                }
            };

            if lock_file.try_lock_exclusive().is_ok() {
                // create(true) 锁文件受 umask 影响（0644），跨身份 GC 会 EACCES——同 orphan GC 修正权限。
                let lp = lock_path.clone();
                let _ = tokio::task::spawn_blocking(move || crate::gc::fix_created_lock_perms(&lp))
                    .await;
                // TOCTOU 复检：list 到拿 flock 间可能有构建 inc 引用计数（复用快路径不过 flock），仍为 0 才删。
                match self.get_layer_ref_count(&layer.digest).await {
                    Ok(Some(0)) => {}
                    // 已被引用，或行已被并发 GC 删除
                    Ok(_) => continue,
                    Err(e) => {
                        warn!(
                            digest = %layer.digest,
                            error = %e,
                            "Failed to recheck layer ref_count during GC, skipping"
                        );
                        continue;
                    }
                }
                // 最终防线：layer_dir 须严格位于 shared_layers 根下（防 path = {root}/{digest} 误删根自身）。
                if let Err(e) = crate::gc::assert_delete_under_root(shared_layers_root, layer_dir) {
                    error!(
                        digest = %layer.digest,
                        path = %layer_dir.display(),
                        error = %e,
                        "Refusing to remove layer dir outside shared_layers root during GC"
                    );
                    continue;
                }
                // 先摘 merged 残挂载（创建半途崩溃遗留的 overlay 挂载点）：setuid 后端
                // rm 是裸 remove_dir_all，会穿 bind 删宿主 lower 层文件；helper 后端有
                // st_dev 边界但残挂载 rm ENOTEMPTY 永久失败（同孤儿目录 GC cleanup_orphan_layer_dirs）。
                // umount 失败照删：MNT_DETACH 对 busy 几乎总成功，失败多为"非挂载点"，照删才是自愈。
                let merged = layer_dir.join("merged");
                if tokio::fs::try_exists(&merged).await.unwrap_or(false) {
                    if let Err(e) = crate::privilege::umount_detach(merged.clone()).await {
                        warn!(
                            digest = %layer.digest,
                            path = %merged.display(),
                            error = %e,
                            "Failed to umount merged before GC removal, continuing"
                        );
                    }
                }
                // 先删目录、成功后才删 DB 行：反序留下".complete 在磁盘、DB 行已缺失"，
                // 该 digest 复用 inc 永久 LayerNotFound（仅锁内自愈兜底）。走特权 rm_rf：
                // root/builder 属主层树对非 root GC 进程 EACCES，普通 remove_dir_all
                // 永久泄漏且每轮重复失败（同 clean.rs）。
                match crate::privilege::rm_rf_async(&[layer_dir]).await {
                    Ok(()) => {
                        if let Err(e) = self.delete_layer(&layer.digest).await {
                            warn!(
                                digest = %layer.digest,
                                error = %e,
                                "Failed to delete layer record during GC"
                            );
                        }
                        cleaned += 1;
                    }
                    Err(e) => {
                        warn!(
                            path = %layer_dir.display(),
                            error = %e,
                            "Failed to remove layer dir during GC; keeping DB row"
                        );
                    }
                }
            }
        }

        // layer_packages 行不随层行删除（有意：为高频翻转 digest 留 restore 快路径）；
        // repo 指纹/依赖集变化后不再重现的 digest 无限累积（每行一份 NEVRA 文本），按年龄修剪。
        const ORPHAN_LAYER_PACKAGES_RETENTION_DAYS: i64 = 30;
        match self
            .delete_orphan_layer_packages(ORPHAN_LAYER_PACKAGES_RETENTION_DAYS)
            .await
        {
            Ok(n) if n > 0 => info!(rows = n, "Pruned orphan layer_packages rows"),
            Ok(_) => {}
            Err(e) => warn!(error = %e, "Failed to prune orphan layer_packages rows"),
        }

        Ok(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use crate::state::products::CreateProductInput;
    use crate::state::test_state::{create_test_store, seed_task};
    use crate::state::BuildInsert;

    /// gc 清扫路径僵尸修复翻 failed 必须补写终态 duration（曾是补写唯一缺口；zombie 路径走 complete_build 已带）。
    #[tokio::test]
    async fn repair_stale_builds_writes_terminal_duration() {
        let (store, _tmp) = create_test_store().await;
        let task_id = seed_task(&store, "fedora", "hello").await;
        let id = store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "building",
                backend: "chroot",
                user: "test",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        let repaired = store.repair_stale_builds(&[id]).await.unwrap();
        assert_eq!(repaired, 1);

        let rec = store.get_build(id).await.unwrap().unwrap();
        assert_eq!(rec.phase, "failed");
        assert!(rec.completed_at.is_some(), "repair should set completed_at");
        assert!(
            rec.duration >= Some(0),
            "repair should set duration (started_at 起算，非负)"
        );
    }

    /// 不存在/已删产品的 succeeded 行不在候选集（目录归结果 GC 回收）；私人产品构建
    ///（product_id 恒 NULL——insert_build 自动解析 official-only）必须仍在候选集，防口径过宽。
    #[tokio::test]
    async fn list_succeeded_without_artifacts_filters_by_product_existence() {
        let (store, tmp) = create_test_store().await;
        let tmp = tmp.unwrap();

        let owner = store.create_user("alice", "builder").await.unwrap();
        for (name, owner_id, visibility) in [
            ("privprod", Some(owner), "private"),
            ("offprod", None, "public"),
            ("goneprod", None, "public"),
        ] {
            store
                .create_product(CreateProductInput {
                    name,
                    display_name: None,
                    owner_id,
                    parent_id: None,
                    visibility,
                    config: &crate::config::ProductConfig::default(),
                    changed_by_user_id: None,
                    reason: Some("reconcile candidate test seed"),
                })
                .await
                .unwrap();
        }

        let seed = |product: &'static str| {
            let store = store.clone();
            let result_dir = tmp.path().join("results").join(product).join("r");
            async move {
                let task_id = seed_task(&store, product, "pkg").await;
                let dir_str = result_dir.to_string_lossy().to_string();
                store
                    .insert_build(BuildInsert {
                        product,
                        pkg_name: "pkg",
                        phase: "succeeded",
                        result_dir: Some(dir_str.as_str()),
                        backend: "chroot",
                        user: "test",
                        task_id: Some(task_id),
                        ..Default::default()
                    })
                    .await
                    .unwrap()
            }
        };

        let priv_id = seed("privprod").await;
        let off_id = seed("offprod").await;
        let gone_id = seed("goneprod").await;
        let ghost_id = seed("ghostprod").await;

        // 已删产品：product TEXT 保留、product_id 置 NULL（FK ON DELETE SET NULL），phase 仍 succeeded。
        let gone_product_id: i64 =
            sqlx::query_scalar("SELECT id FROM products WHERE name = 'goneprod'")
                .fetch_one(store.pool())
                .await
                .unwrap();
        store.delete_product(gone_product_id).await.unwrap();

        let candidates = store
            .list_succeeded_builds_without_artifacts()
            .await
            .unwrap();
        let ids: Vec<i64> = candidates.iter().map(|b| b.id).collect();
        assert!(!ids.contains(&ghost_id), "从未存在的产品不在候选集");
        assert!(!ids.contains(&gone_id), "已删产品不在候选集");
        assert!(
            ids.contains(&priv_id),
            "私人产品构建（product_id NULL）必须仍在候选集"
        );
        assert!(ids.contains(&off_id), "官方产品构建在候选集");
    }
}
