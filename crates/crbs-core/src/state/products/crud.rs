// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产品仓库：`products` / `product_config_history` 表的 CRUD。
//! 契约：`revision` 每次 update 单调 +1（drives history + chain-resolve 缓存失效）；
//! `base_os_revision` 仅触发字段变化时抬到 `= revision`，否则保持不变。
//! `update_product_config` 用 `BEGIN IMMEDIATE`（写锁）+ 可选 `expected_revision`（乐观并发），
//! 命中冲突返回 `RevisionConflict { expected, current }`，server 映射 HTTP 409。
//! 可见性检查放 server 层（`AuthContext` 在 crbs-server）。
use super::*;
use crate::state::rollback_and_return;

impl StateStore {
    /// 新建产品并同事务落首条 history（revision / base_os_revision 初始 1）：parent 给定时
    /// 先过环/存在/深度校验（[`Self::validate_parent_id`]）；唯一名检查在 `begin_write()`
    /// 写锁内（无 TOCTOU），重名返回 `AlreadyExists`（命名空间全局）。返回新产品 id。
    pub async fn create_product(&self, input: CreateProductInput<'_>) -> crate::Result<i64> {
        let config_json = serde_json::to_string(input.config).db_ctx("serialize product config")?;

        let mut conn = self.begin_write().await?;
        // begin_write() 先取写锁（SQLite: BEGIN IMMEDIATE, Postgres: BEGIN），唯一名检查在锁内，无 TOCTOU。
        // 父链校验也必须在写事务内：事务外校验与并发 reparent/delete 交错会
        // 插入超深链或得到裸 FK Database 错误。
        if let Some(pid) = input.parent_id {
            if let Err(e) = Self::validate_parent_id_tx(&mut conn, None, pid).await {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(e);
            }
        }

        let exists: Option<i64> =
            match sqlx::query_scalar("SELECT id FROM products WHERE name = $1")
                .bind(input.name)
                .fetch_optional(&mut *conn)
                .await
                .db_ctx("check product name uniqueness")
            {
                Ok(r) => r,
                Err(e) => rollback_and_return!(conn, e),
            };
        if exists.is_some() {
            rollback_and_return!(
                conn,
                CrbsError::AlreadyExists {
                    message: format!(
                        "product name '{}' is taken (namespace is global)",
                        input.name
                    ),
                }
            );
        }

        let id = match insert_product_and_history_tx(&mut conn, &input, &config_json).await {
            Ok(id) => id,
            Err(e) => rollback_and_return!(conn, e),
        };

        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit create_product")
        {
            rollback_and_return!(conn, e);
        }
        Ok(id)
    }

    /// 按 id 取产品完整记录（含解析后 config）；不存在 None。
    pub async fn get_product_by_id(&self, id: i64) -> crate::Result<Option<ProductRecord>> {
        let row = sqlx::query_as::<_, ProductRow>(sql::SELECT_PRODUCT_BY_ID)
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .db_ctx("get product by id")?;
        match row {
            Some(r) => Ok(Some(r.into_record()?)),
            None => Ok(None),
        }
    }

    /// 按名取产品完整记录（含解析后 config）；同名多行时官方行（`owner_id IS NULL`）优先，不存在 None。
    pub async fn get_product_by_name(&self, name: &str) -> crate::Result<Option<ProductRecord>> {
        let row = sqlx::query_as::<_, ProductRow>(sql::SELECT_PRODUCT_BY_NAME)
            .bind(name)
            .fetch_optional(self.pool())
            .await
            .db_ctx("get product by name")?;
        match row {
            Some(r) => Ok(Some(r.into_record()?)),
            None => Ok(None),
        }
    }

    /// 轻量存在性查询（按名，不拉整行、不解析 config）；需完整记录时用 [`Self::get_product_by_name`]。
    pub async fn product_row_exists(&self, name: &str) -> crate::Result<bool> {
        let id: Option<i64> = sqlx::query_scalar("SELECT id FROM products WHERE name = $1 LIMIT 1")
            .bind(name)
            .fetch_optional(self.pool())
            .await
            .db_ctx("check product row exists")?;
        Ok(id.is_some())
    }

    /// 按名取官方产品（`owner_id IS NULL`），私人同名行不命中；不存在 None。
    pub async fn get_official_product_by_name(
        &self,
        name: &str,
    ) -> crate::Result<Option<ProductRecord>> {
        let row = sqlx::query_as::<_, ProductRow>(sql::SELECT_OFFICIAL_PRODUCT_BY_NAME)
            .bind(name)
            .fetch_optional(self.pool())
            .await
            .db_ctx("get official product by name")?;
        match row {
            Some(r) => Ok(Some(r.into_record()?)),
            None => Ok(None),
        }
    }

    /// 全部产品的轻量列表（[`ProductStub`]，不解析 config_json），按 name 升序。
    pub async fn list_products(&self) -> crate::Result<Vec<ProductStub>> {
        sqlx::query_as::<_, ProductStubRow>(sql::LIST_PRODUCTS)
            .fetch_all(self.pool())
            .await
            .db_ctx("list products")
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    /// 列出指定 owner 的产品（[`Self::list_products`] 的 owner 过滤镜像）。
    pub async fn list_products_by_owner(&self, owner_id: i64) -> crate::Result<Vec<ProductStub>> {
        sqlx::query_as::<_, ProductStubRow>(sql::LIST_PRODUCTS_BY_OWNER)
            .bind(owner_id)
            .fetch_all(self.pool())
            .await
            .db_ctx("list products by owner")
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    /// 一次载入全部产品完整行（含解析后 config）供批量内存父链解析；配置级表几十行量级，全量载入可接受。
    pub(crate) async fn list_all_products(&self) -> crate::Result<Vec<ProductRecord>> {
        let rows = sqlx::query_as::<_, ProductRow>(sql::LIST_PRODUCTS_FULL)
            .fetch_all(self.pool())
            .await
            .db_ctx("list all products")?;
        rows.into_iter().map(ProductRow::into_record).collect()
    }

    /// 更新产品配置并写 history、COMMIT 后失效 resolve 缓存（revision / base_os_revision /
    /// 乐观并发语义见模块契约）；任一 SQL 失败整体回滚，返回 [`UpdateOutcome`]。
    pub async fn update_product_config(
        &self,
        id: i64,
        new_config: &ProductConfig,
        changed_by_user_id: Option<i64>,
        reason: Option<&str>,
        expected_revision: Option<i64>,
    ) -> crate::Result<UpdateOutcome> {
        let new_json = serde_json::to_string(new_config).db_ctx("serialize new config")?;
        let new_value: serde_json::Value =
            serde_json::from_str(&new_json).db_ctx("reparse new config json")?;

        // `pool().begin()` 起 DEFERRED 事务，SQLite 首写才升 RESERVED；begin_write 显式
        // 方言写锁（SQLite BEGIN IMMEDIATE / PostgreSQL BEGIN），并发 update 更早发现竞争。
        let mut conn = self.begin_write().await?;

        // 以下任何早退都要先 ROLLBACK（COMMIT 成功后无需清理）。
        let row: Option<(i64, i64, Option<i64>, String)> =
            match sqlx::query_as(sql::SELECT_PRODUCT_REV_SNAPSHOT)
                .bind(id)
                .fetch_optional(&mut *conn)
                .await
                .db_ctx("select product revision snapshot")
            {
                Ok(r) => r,
                Err(e) => rollback_and_return!(conn, e),
            };

        let (old_rev, old_base_os_rev, parent_id, old_json) = match row {
            Some(r) => r,
            None => rollback_and_return!(
                conn,
                CrbsError::NotFound {
                    message: format!("product id={} not found", id),
                }
            ),
        };

        if let Some(expected) = expected_revision {
            if expected != old_rev {
                rollback_and_return!(
                    conn,
                    CrbsError::RevisionConflict {
                        expected,
                        current: old_rev,
                    }
                );
            }
        }

        let old_value: serde_json::Value = match serde_json::from_str(&old_json) {
            Ok(v) => v,
            Err(e) => rollback_and_return!(
                conn,
                CrbsError::Database(format!("parse old config json for id={}: {}", id, e))
            ),
        };
        let base_os_bumped = base_os_fields_changed(&old_value, &new_value);
        let new_rev = old_rev + 1;
        let new_base_os_rev = if base_os_bumped {
            new_rev
        } else {
            old_base_os_rev
        };

        // 乐观守卫 `AND revision = old_rev`：PG 的 BEGIN 不锁行，SELECT 快照到 UPDATE 间并发提交抬走
        // revision，0 行转 RevisionConflict（server 409）；SQLite 被 IMMEDIATE 串行化，结构性不可触发（双保险）。
        let result = match sqlx::query(&sql::update_product_config(self.dialect))
            .bind(&new_json)
            .bind(new_rev)
            .bind(new_base_os_rev)
            .bind(id)
            .bind(old_rev)
            .execute(&mut *conn)
            .await
            .db_ctx("update product config")
        {
            Ok(r) => r,
            Err(e) => rollback_and_return!(conn, e),
        };
        if result.rows_affected() == 0 {
            // 0 行 = revision 被并发抬走（行快照时仍在，否则已 NotFound）；回读 current，落空（并发删除窄窗）按 NotFound。
            let current: Option<i64> = match sqlx::query_scalar(sql::SELECT_PRODUCT_REVISION)
                .bind(id)
                .fetch_optional(&mut *conn)
                .await
                .db_ctx("re-read product revision after lost update")
            {
                Ok(r) => r,
                Err(e) => rollback_and_return!(conn, e),
            };
            match current {
                Some(current) => rollback_and_return!(
                    conn,
                    CrbsError::RevisionConflict {
                        expected: old_rev,
                        current,
                    }
                ),
                None => rollback_and_return!(
                    conn,
                    CrbsError::NotFound {
                        message: format!("product id={} not found", id),
                    }
                ),
            }
        }

        if let Err(e) = sqlx::query(sql::INSERT_HISTORY)
            .bind(id)
            .bind(new_rev)
            .bind(&new_json)
            .bind(parent_id)
            .bind(new_base_os_rev)
            .bind(changed_by_user_id)
            .bind(reason)
            .execute(&mut *conn)
            .await
            .db_ctx("insert product history")
        {
            rollback_and_return!(conn, e);
        }

        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit update_product_config")
        {
            rollback_and_return!(conn, e);
        }

        // 写路径不变量：缓存失效须在 commit 后、返回前（早则并发读拿旧值回填，晚则读到陈旧）；
        // 连带失效全部后代（chain_resolve 依赖祖先链）。
        self.invalidate_resolve_warned(id).await;

        Ok(UpdateOutcome {
            revision: new_rev,
            base_os_revision: new_base_os_rev,
            base_os_bumped,
        })
    }
}
