// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产品删除：child 引用检查 + 级联取消关联构建/任务，同一写事务内完成（模块契约见 mod.rs）。
use super::*;
use crate::state::rollback_and_return;

impl StateStore {
    /// 删除产品（单写事务全或无）：有 child 产品则 `DeleteRestricted` 拒绝；先同事务级联
    /// 取消活跃构建/任务再删行，返回 `(取消 build 数, 取消 task 数)`；提交后失效 resolve
    /// 缓存 + bump 用户域代数（失败仅 warn 不回滚）。
    pub async fn delete_product(&self, id: i64) -> crate::Result<(u64, u64)> {
        let mut conn = self.begin_write().await?;

        let exists: Option<i64> = match sqlx::query_scalar("SELECT 1 FROM products WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .db_ctx("check product exists")
        {
            Ok(r) => r,
            Err(e) => rollback_and_return!(conn, e),
        };
        if exists.is_none() {
            rollback_and_return!(
                conn,
                CrbsError::NotFound {
                    message: format!("product id={} not found", id),
                }
            );
        }

        let child_count: i64 = match sqlx::query_scalar(sql::COUNT_CHILD_PRODUCTS)
            .bind(id)
            .fetch_one(&mut *conn)
            .await
            .db_ctx("count child products")
        {
            Ok(c) => c,
            Err(e) => rollback_and_return!(conn, e),
        };
        if child_count > 0 {
            rollback_and_return!(
                conn,
                CrbsError::DeleteRestricted {
                    message: format!(
                        "product has {} child product(s); re-parent or delete them first",
                        child_count
                    ),
                }
            );
        }

        let cancel_counts = match self.cancel_builds_and_tasks_tx(id, &mut conn).await {
            Ok(c) => c,
            Err(e) => rollback_and_return!(conn, e),
        };

        // 画像孤儿清理：按 product 名删画像行——行键是名字不是
        // id，必须在删产品行前取名；同事务保证删产品与清画像原子。
        let product_name: String =
            match sqlx::query_scalar("SELECT name FROM products WHERE id = $1")
                .bind(id)
                .fetch_one(&mut *conn)
                .await
                .db_ctx("select product name for profile cleanup")
            {
                Ok(n) => n,
                Err(e) => rollback_and_return!(conn, e),
            };
        if let Err(e) = sqlx::query(sql::DELETE_PROFILES_BY_PRODUCT)
            .bind(&product_name)
            .execute(&mut *conn)
            .await
            .db_ctx("delete orphan resource profiles")
        {
            rollback_and_return!(conn, e);
        }

        let result = match sqlx::query(sql::DELETE_PRODUCT)
            .bind(id)
            .execute(&mut *conn)
            .await
            .db_ctx("delete product")
        {
            Ok(r) => r,
            Err(e) => rollback_and_return!(conn, e),
        };
        if result.rows_affected() == 0 {
            rollback_and_return!(
                conn,
                CrbsError::NotFound {
                    message: format!("product id={} not found", id),
                }
            );
        }

        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit delete_product")
        {
            rollback_and_return!(conn, e);
        }

        // 写路径不变量：删除必清缓存，否则盲信命中返回已删产品 stale 配置（失败语义见 invalidate_resolve_warned）。
        self.invalidate_resolve_warned(id).await;
        // bump 用户域代数：删除即不可见，repo 公开通道可见性短缓存随之即时失效。
        self.bump_user_generation();
        Ok(cancel_counts)
    }
}
