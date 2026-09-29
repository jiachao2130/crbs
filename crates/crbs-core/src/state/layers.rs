// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 共享层状态表：创建、路径查询与引用计数增减。

use sqlx::Row;

use super::StateStore;
use crate::error::{CrbsError, DbResultExt};

mod sql {
    use crate::state::Dialect;

    /// 插入或累加 layer（方言感知时间函数）。
    /// 冲突时 ref_count 在现有值上累加（excluded.ref_count）不重置：重置会把
    /// 并发复用 / 重建的两个构建计数压回 1，GC 可能在构建期间删在用层。
    pub(super) fn upsert_layer(dialect: Dialect) -> String {
        match dialect {
            Dialect::Sqlite => {
                "INSERT INTO layers (digest, path, product, status, ref_count, created_at) \
                 VALUES ($1, $2, $3, 'complete', $4, datetime('now')) \
                 ON CONFLICT(digest) DO UPDATE SET \
                     path = excluded.path, \
                     product = excluded.product, \
                     status = excluded.status, \
                     ref_count = ref_count + excluded.ref_count, \
                     created_at = excluded.created_at"
                    .to_string()
            }
            #[cfg(feature = "postgres")]
            Dialect::Postgres => {
                "INSERT INTO layers (digest, path, product, status, ref_count, created_at) \
                 VALUES ($1, $2, $3, 'complete', $4, to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')) \
                 ON CONFLICT (digest) DO UPDATE SET \
                     path = EXCLUDED.path, \
                     product = EXCLUDED.product, \
                     status = EXCLUDED.status, \
                     ref_count = layers.ref_count + EXCLUDED.ref_count, \
                     created_at = EXCLUDED.created_at"
                    .to_string()
            }
        }
    }

    pub(super) const SELECT_LAYER_PATH: &str = "SELECT path FROM layers WHERE digest = $1";

    pub(super) const SELECT_LATEST_COMPLETE_LAYER_FOR_PRODUCT: &str =
        "SELECT digest, path FROM layers \
         WHERE product = $1 AND status = 'complete' \
         ORDER BY created_at DESC LIMIT 1";

    /// 原子 +1；未命中返回 RowNotFound（映射为 LayerNotFound）。
    /// 须同时清掉历史 dec 留下的 scheduled_gc_at：dec 到 0（已装 schedule）后
    /// 复用 inc 的层若保留旧 schedule，`list_layers_for_gc` 判定与 ref_count 复检竞态可在挂载中删层。
    pub(super) const INCREMENT_LAYER_REF_COUNT: &str =
        "UPDATE layers SET ref_count = ref_count + 1, scheduled_gc_at = NULL \
         WHERE digest = $1 RETURNING ref_count";

    /// 原子 -1 并在归零时**同一条语句**调度 GC（方言感知）：分两条时进程崩溃
    /// 会留下 ref_count=0 且 scheduled_gc_at NULL 的行，GC 永不命中，永久泄漏。
    /// CASE 读 UPDATE 前列值（双方言一致）；`ref_count > 0` 守卫防负计数（负数
    /// 永不满足 GC 的 ref_count=0 条件）。SQLite 须 `'+' || $1 || ' hours'` 拼接：
    /// `datetime('now', $1)` 对整数绑定是无效修饰符，得 NULL。
    pub(super) fn decrement_layer_ref(dialect: Dialect) -> String {
        match dialect {
            Dialect::Sqlite => {
                "UPDATE layers SET \
                     ref_count = ref_count - 1, \
                     scheduled_gc_at = CASE WHEN ref_count - 1 = 0 \
                         THEN datetime('now', '+' || $1 || ' hours') \
                         ELSE scheduled_gc_at END \
                 WHERE digest = $2 AND ref_count > 0 RETURNING ref_count"
                    .to_string()
            }
            #[cfg(feature = "postgres")]
            Dialect::Postgres => {
                "UPDATE layers SET \
                     ref_count = ref_count - 1, \
                     scheduled_gc_at = CASE WHEN ref_count - 1 = 0 \
                         THEN to_char((NOW() AT TIME ZONE 'UTC') + ($1::INTEGER || ' hours')::INTERVAL, 'YYYY-MM-DD HH24:MI:SS') \
                         ELSE scheduled_gc_at END \
                 WHERE digest = $2 AND ref_count > 0 RETURNING ref_count"
                    .to_string()
            }
        }
    }

    pub(super) const SELECT_LAYER_REF_COUNT: &str =
        "SELECT ref_count FROM layers WHERE digest = $1";

    pub(super) const DELETE_LAYER: &str = "DELETE FROM layers WHERE digest = $1";

    /// 泄漏重置：ref_count 归 0，scheduled_gc_at 为 NULL 时补装 schedule、已有
    /// schedule 保持原值（不推迟既有 GC）——不补装则 `list_layers_for_gc` 永不
    /// 命中、永久泄漏。WHERE `ref_count = $3`（调用方传的泄漏扫描快照值）：
    /// 扫描到重置间层被并发复用时命中不上 0 行，不得归零在用计数。PG 统一 `AT TIME ZONE 'UTC'`（见 Dialect::sql_now 帧一致）。
    pub(super) fn reset_layer_ref(dialect: Dialect) -> String {
        match dialect {
            Dialect::Sqlite => {
                "UPDATE layers SET \
                     ref_count = 0, \
                     scheduled_gc_at = CASE WHEN scheduled_gc_at IS NULL \
                         THEN datetime('now', '+' || $1 || ' hours') \
                         ELSE scheduled_gc_at END \
                 WHERE digest = $2 AND ref_count = $3"
                    .to_string()
            }
            #[cfg(feature = "postgres")]
            Dialect::Postgres => {
                "UPDATE layers SET \
                     ref_count = 0, \
                     scheduled_gc_at = CASE WHEN scheduled_gc_at IS NULL \
                         THEN to_char((NOW() AT TIME ZONE 'UTC') + ($1::INTEGER || ' hours')::INTERVAL, 'YYYY-MM-DD HH24:MI:SS') \
                         ELSE scheduled_gc_at END \
                 WHERE digest = $2 AND ref_count = $3"
                    .to_string()
            }
        }
    }

    /// 事务内子句：删指定产品的 layers。须与 DELETE_LAYER_PACKAGES_FOR_PRODUCT 同 tx。
    pub(super) const DELETE_LAYERS_FOR_PRODUCT: &str = "DELETE FROM layers WHERE product = $1";

    /// 事务内子句：删指定产品的 layer_packages。
    pub(super) const DELETE_LAYER_PACKAGES_FOR_PRODUCT: &str =
        "DELETE FROM layer_packages WHERE product = $1";

    /// 排除式删除 SQL：None（keep 为空）退化为全删常量；Some 拼调用方经
    /// `db::in_placeholders` 外提的 `$N` 串——值全走绑定不拼字面量，超限守卫
    /// 在片段生成处。
    pub(super) fn delete_for_product_except_sql(base: &str, not_in: Option<&str>) -> String {
        match not_in {
            None => base.to_string(),
            Some(placeholders) => format!("{base} AND digest NOT IN ({placeholders})"),
        }
    }

    /// 列出指定产品的 (digest, path)（clean 回收共享层目录用）。
    pub(super) const LIST_LAYERS_FOR_PRODUCT: &str =
        "SELECT digest, path FROM layers WHERE product = $1";
}

impl StateStore {
    /// 插入或累加 layer 记录；冲突累加语义与并发理由见 `sql::upsert_layer`。
    pub async fn insert_layer(
        &self,
        digest: &str,
        path: &str,
        product: &str,
        ref_count: i64,
    ) -> crate::Result<()> {
        sqlx::query(&sql::upsert_layer(self.dialect))
            .bind(digest)
            .bind(path)
            .bind(product)
            .bind(ref_count)
            .execute(&self.pool)
            .await
            .db_ctx("insert layer")?;
        Ok(())
    }

    /// 按 digest 查询 layer 路径。
    pub async fn get_layer_path(&self, digest: &str) -> crate::Result<Option<String>> {
        let path: Option<String> = sqlx::query_scalar(sql::SELECT_LAYER_PATH)
            .bind(digest)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("get layer path")?;
        Ok(path)
    }

    /// 查询产品最新的已完成 SharedLayer（用于 shell/debug 复用构建环境）。
    pub async fn get_latest_layer_for_product(
        &self,
        product: &str,
    ) -> crate::Result<Option<(String, String)>> {
        let row = sqlx::query(sql::SELECT_LATEST_COMPLETE_LAYER_FOR_PRODUCT)
            .bind(product)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("get latest layer")?;

        Ok(row.map(|r| (r.get("digest"), r.get("path"))))
    }

    /// 增加引用计数，返回新值；层不存在（如并发 GC 已删）返回 `CrbsError::LayerNotFound` 而非 "no rows"。
    pub async fn layer_ref_inc(&self, digest: &str) -> crate::Result<i64> {
        let count: i64 = sqlx::query_scalar(sql::INCREMENT_LAYER_REF_COUNT)
            .bind(digest)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| match e {
                sqlx::Error::RowNotFound => crate::error::CrbsError::LayerNotFound {
                    digest: digest.into(),
                },
                // 豁免 .db_ctx：RowNotFound 须特判为领域错误 LayerNotFound，db_ctx 丢错误分类。
                _ => crate::error::CrbsError::Database(format!("layer ref inc: {}", e)),
            })?;
        Ok(count)
    }

    /// 减少引用计数，返回新值；归零即调度 GC，原子性/CASE/守卫语义见
    /// `sql::decrement_layer_ref`。计数已 0 时 UPDATE 不命中，返回
    /// `CrbsError::LayerNotFound`，调用方 warn-and-continue。
    pub async fn layer_ref_dec(&self, digest: &str, grace_hours: u64) -> crate::Result<i64> {
        let count: i64 = sqlx::query_scalar(&sql::decrement_layer_ref(self.dialect))
            .bind(crate::util::u64_to_i64_saturating(grace_hours))
            .bind(digest)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| match e {
                sqlx::Error::RowNotFound => crate::error::CrbsError::LayerNotFound {
                    digest: digest.into(),
                },
                // 豁免 .db_ctx：RowNotFound 须特判为领域错误 LayerNotFound，db_ctx 丢错误分类。
                _ => crate::error::CrbsError::Database(format!("layer ref dec: {}", e)),
            })?;
        Ok(count)
    }

    /// 查询 layer 引用计数；层不存在返回 `Ok(None)`（区分“未记录”与 DB 错误）。
    pub async fn get_layer_ref_count(&self, digest: &str) -> crate::Result<Option<i64>> {
        let count: Option<i64> = sqlx::query_scalar(sql::SELECT_LAYER_REF_COUNT)
            .bind(digest)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("get layer ref count")?;
        Ok(count)
    }

    /// 事务内递减共享层引用（同 [`Self::layer_ref_dec`]：归零即装 GC schedule），
    /// 供与业务变更同事务的调用方使用（如产品取消路径）。`Ok(0)` = 层行不存在
    /// 或 ref 已 0——按"无引用可释放"容忍，不得回滚业务事务；其余 DB 错误照传。
    pub(crate) async fn layer_ref_dec_in_tx(
        &self,
        conn: &mut sqlx::AnyConnection,
        digest: &str,
        grace_hours: i64,
    ) -> crate::Result<u64> {
        let res = sqlx::query(&sql::decrement_layer_ref(self.dialect))
            .bind(grace_hours)
            .bind(digest)
            .execute(&mut *conn)
            .await
            .db_ctx("decrement layer ref in tx")?;
        Ok(res.rows_affected())
    }

    /// 列出指定产品的 (digest, path)，供 clean 在删行前回收共享层目录。
    pub async fn list_layers_for_product(
        &self,
        product: &str,
    ) -> crate::Result<Vec<(String, String)>> {
        let rows = sqlx::query(sql::LIST_LAYERS_FOR_PRODUCT)
            .bind(product)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list layers for product")?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let digest: String = row.try_get(0).map_err(|e| {
                CrbsError::Database(format!("list layers for product: digest column: {e}"))
            })?;
            let path: String = row.try_get(1).map_err(|e| {
                CrbsError::Database(format!("list layers for product: path column: {e}"))
            })?;
            out.push((digest, path));
        }
        Ok(out)
    }

    /// 修剪孤儿 layer_packages 行：digest 已不在 layers 表且早于保留期；
    /// gc_shared_layers 尾部调用。保留期内不动（restore 快路径，见 persist.rs）。
    pub async fn delete_orphan_layer_packages(&self, retention_days: i64) -> crate::Result<u64> {
        let sql = format!(
            "DELETE FROM layer_packages WHERE digest NOT IN (SELECT digest FROM layers) \
             AND created_at < {}",
            self.dialect.sql_days_ago(retention_days)
        );
        let res = sqlx::query(&sql)
            .execute(&self.pool)
            .await
            .db_ctx("delete orphan layer_packages")?;
        Ok(res.rows_affected())
    }

    /// 删除 layer 记录。
    pub(crate) async fn delete_layer(&self, digest: &str) -> crate::Result<()> {
        sqlx::query(sql::DELETE_LAYER)
            .bind(digest)
            .execute(&self.pool)
            .await
            .db_ctx("delete layer")?;
        Ok(())
    }

    /// 重置 layer 的 ref_count 为 0（修复泄漏），返回受影响行数。快照 CAS 与
    /// 补装 schedule 语义见 `sql::reset_layer_ref`；0 行 = 并发已改动，warn 跳过。
    pub async fn reset_layer_ref_count(
        &self,
        digest: &str,
        grace_hours: u64,
        expected_ref_count: i64,
    ) -> crate::Result<u64> {
        let res = sqlx::query(&sql::reset_layer_ref(self.dialect))
            .bind(crate::util::u64_to_i64_saturating(grace_hours))
            .bind(digest)
            .bind(expected_ref_count)
            .execute(&self.pool)
            .await
            .db_ctx("reset layer ref_count")?;
        Ok(res.rows_affected())
    }

    /// 删除指定产品的 layers 和 layer_packages 记录（clean 调用），排除
    /// `keep_digests`。keep 的行必须保留：ref ≠ 0 的层留给行驱动 GC 回收，行删了
    /// GC 就发现不了盘上层目录（孤儿挂载 GC 又跳过带 `.complete` 的目录），GB 级
    /// 永久泄漏；layer_packages 与 layer 行同生死（keep 的一并保 restore 快路径）。
    pub async fn delete_layers_for_product_except(
        &self,
        product: &str,
        keep_digests: &[String],
    ) -> crate::Result<(usize, usize)> {
        let mut tx = self.pool.begin().await.db_ctx("begin tx")?;

        // NOT IN 片段（$2 起，product 占 $1）外提生成一次两处复用；超限守卫在此生效。
        let keep_len = keep_digests.len();
        let not_in = if keep_len == 0 {
            None
        } else {
            Some(crate::state::db::in_placeholders(2, keep_len)?)
        };
        let layers_sql =
            sql::delete_for_product_except_sql(sql::DELETE_LAYERS_FOR_PRODUCT, not_in.as_deref());
        let mut layers_q = sqlx::query(&layers_sql).bind(product);
        for d in keep_digests {
            layers_q = layers_q.bind(d);
        }
        let layers_deleted = layers_q
            .execute(&mut *tx)
            .await
            .db_ctx("delete layers for product except")?
            .rows_affected();

        let pkgs_sql = sql::delete_for_product_except_sql(
            sql::DELETE_LAYER_PACKAGES_FOR_PRODUCT,
            not_in.as_deref(),
        );
        let mut pkgs_q = sqlx::query(&pkgs_sql).bind(product);
        for d in keep_digests {
            pkgs_q = pkgs_q.bind(d);
        }
        let pkgs_deleted = pkgs_q
            .execute(&mut *tx)
            .await
            .db_ctx("delete layer_packages for product except")?
            .rows_affected();

        tx.commit().await.db_ctx("commit tx")?;

        Ok((layers_deleted as usize, pkgs_deleted as usize))
    }
}

#[cfg(test)]
mod tests {
    use crate::state::StateStore;

    #[tokio::test]
    async fn layer_ref_dec_schedules_gc_exactly_when_reaching_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();

        sqlx::query(
            "INSERT INTO layers (digest, path, product, status, ref_count, created_at) \
             VALUES ('d1', '/tmp/l1', 'p1', 'complete', 2, '2026-01-01 00:00:00')",
        )
        .execute(store.pool())
        .await
        .unwrap();

        // 2 -> 1：不调度 GC
        assert_eq!(store.layer_ref_dec("d1", 24).await.unwrap(), 1);
        let scheduled: Option<String> =
            sqlx::query_scalar("SELECT scheduled_gc_at FROM layers WHERE digest = 'd1'")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert!(scheduled.is_none());

        // 1 -> 0：调度 GC
        assert_eq!(store.layer_ref_dec("d1", 24).await.unwrap(), 0);
        let scheduled: Option<String> =
            sqlx::query_scalar("SELECT scheduled_gc_at FROM layers WHERE digest = 'd1'")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert!(scheduled.is_some());

        // 已为 0：守卫命中，LayerNotFound（调用方按 warn-and-continue 处理）
        let err = store.layer_ref_dec("d1", 24).await.unwrap_err();
        assert!(matches!(err, crate::error::CrbsError::LayerNotFound { .. }));
    }

    #[tokio::test]
    async fn layer_ref_inc_clears_scheduled_gc_after_dec_to_zero() {
        // 回归：复用 inc 必须清掉历史 dec 的 schedule，否则 GC 判定与复用竞态可删挂载中层。
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();

        store
            .insert_layer("d-inc", "/tmp/l-inc", "p1", 1)
            .await
            .unwrap();
        assert_eq!(store.layer_ref_dec("d-inc", 24).await.unwrap(), 0);
        let scheduled: Option<String> =
            sqlx::query_scalar("SELECT scheduled_gc_at FROM layers WHERE digest = 'd-inc'")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert!(scheduled.is_some(), "dec 到 0 必须装上 schedule");

        assert_eq!(store.layer_ref_inc("d-inc").await.unwrap(), 1);
        let scheduled: Option<String> =
            sqlx::query_scalar("SELECT scheduled_gc_at FROM layers WHERE digest = 'd-inc'")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert!(
            scheduled.is_none(),
            "复用 inc 必须清掉历史 dec 留下的 scheduled_gc_at"
        );
    }

    #[tokio::test]
    async fn reset_layer_ref_count_installs_schedule_when_unset() {
        // 回归：scheduled_gc_at 为 NULL 的行永不进 GC 候选；reset 须补装且不改写已有 schedule。
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();

        // 泄漏态：ref_count > 0 且无 schedule。
        store
            .insert_layer("d-reset", "/tmp/l-reset", "p1", 3)
            .await
            .unwrap();
        // 快照值不匹配（并发变化）→ 0 行，不动计数。
        assert_eq!(
            store.reset_layer_ref_count("d-reset", 24, 2).await.unwrap(),
            0,
            "stale snapshot must not reset"
        );
        assert_eq!(
            store.get_layer_ref_count("d-reset").await.unwrap(),
            Some(3),
            "并发变化后 reset 必须跳过，不得归零在用计数"
        );
        assert_eq!(
            store.reset_layer_ref_count("d-reset", 24, 3).await.unwrap(),
            1,
            "snapshot match must reset"
        );
        assert_eq!(
            store.get_layer_ref_count("d-reset").await.unwrap(),
            Some(0),
            "reset 必须归零计数"
        );
        let scheduled: Option<String> =
            sqlx::query_scalar("SELECT scheduled_gc_at FROM layers WHERE digest = 'd-reset'")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert!(
            scheduled.is_some(),
            "scheduled 为 NULL 的层 reset 后必须被装上 schedule"
        );

        // 已有 schedule 的行 reset 保持原值（不推迟既有 GC 时间）。
        store
            .insert_layer("d-keep", "/tmp/l-keep", "p1", 1)
            .await
            .unwrap();
        assert_eq!(store.layer_ref_dec("d-keep", 1).await.unwrap(), 0);
        let before: String =
            sqlx::query_scalar("SELECT scheduled_gc_at FROM layers WHERE digest = 'd-keep'")
                .fetch_one(store.pool())
                .await
                .unwrap();
        store.reset_layer_ref_count("d-keep", 48, 0).await.unwrap();
        let after: String =
            sqlx::query_scalar("SELECT scheduled_gc_at FROM layers WHERE digest = 'd-keep'")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(before, after, "已有 schedule 的行 reset 不得改写");
    }

    #[tokio::test]
    async fn insert_layer_upsert_increments_ref_count_on_conflict() {
        // 回归：冲突时 ref_count 必须累加不重置——重置把并发双构建计数压回 1，GC 可删在用层。
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();

        store
            .insert_layer("d-up", "/l/upper", "fedora", 1)
            .await
            .unwrap();
        assert_eq!(store.get_layer_ref_count("d-up").await.unwrap(), Some(1));

        store
            .insert_layer("d-up", "/l/upper2", "fedora", 1)
            .await
            .unwrap();
        assert_eq!(store.get_layer_ref_count("d-up").await.unwrap(), Some(2));
        // path 以最新注册为准。
        assert_eq!(
            store.get_layer_path("d-up").await.unwrap().as_deref(),
            Some("/l/upper2")
        );
    }

    #[tokio::test]
    async fn delete_layers_for_product_except_keeps_listed_digests() {
        // 回归：keep 的 digest 行必须保留——行没了行驱动 GC 发现不了盘上层目录，GB 级泄漏。
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();

        store
            .insert_layer("d-keep", "/tmp/l-keep", "p1", 2)
            .await
            .unwrap();
        store
            .insert_layer("d-del", "/tmp/l-del", "p1", 0)
            .await
            .unwrap();
        store
            .insert_layer("d-other-product", "/tmp/l-op", "p2", 0)
            .await
            .unwrap();
        for (digest, product) in [("d-keep", "p1"), ("d-del", "p1"), ("d-other-product", "p2")] {
            sqlx::query(
                "INSERT INTO layer_packages (digest, product, packages, created_at) \
                 VALUES ($1, $2, '[]', '2026-01-01 00:00:00')",
            )
            .bind(digest)
            .bind(product)
            .execute(store.pool())
            .await
            .unwrap();
        }

        let (layers, pkgs) = store
            .delete_layers_for_product_except("p1", &["d-keep".to_string()])
            .await
            .unwrap();
        assert_eq!(layers, 1, "只删未排除的 1 行");
        assert_eq!(pkgs, 1);
        assert_eq!(
            store.get_layer_path("d-keep").await.unwrap().as_deref(),
            Some("/tmp/l-keep"),
            "排除的 digest 行必须保留（行驱动 GC 的回收入口）"
        );
        assert_eq!(store.get_layer_path("d-del").await.unwrap(), None);
        assert_eq!(
            store
                .get_layer_path("d-other-product")
                .await
                .unwrap()
                .as_deref(),
            Some("/tmp/l-op"),
            "其它产品的行不受影响"
        );
        let kept_pkgs: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM layer_packages WHERE digest = 'd-keep'")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(kept_pkgs, 1);

        // 空 keep 列表退化为全删。
        let (layers2, _) = store
            .delete_layers_for_product_except("p1", &[])
            .await
            .unwrap();
        assert_eq!(layers2, 1);
        assert_eq!(store.get_layer_path("d-keep").await.unwrap(), None);
    }
}
