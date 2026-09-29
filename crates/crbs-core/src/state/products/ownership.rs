// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产品仓库：`products` / `product_config_history` 表的 CRUD。契约：
//! - `revision` 每次 update 单调 +1，drives history + chain-resolve 缓存失效；
//!   `base_os_revision` 仅触发字段变化时抬到 `= revision`，否则不变。
//! - `update_product_config` 用 `BEGIN IMMEDIATE` + 可选 `expected_revision`（乐观并发），
//!   冲突返回 `RevisionConflict { expected, current }`（server 层映射 409）。
//! - 可见性检查放 server 层（依赖 `AuthContext`，crbs-core 不引用）。
use super::*;
use crate::state::rollback_and_return;

/// [`StateStore::transfer_commit_tx`] 的参数包：transfer 终局写入的语义字段；`conn` 生命周期贯穿事务，不进包。
struct TransferCommitParams<'a> {
    id: i64,
    new_owner_id: i64,
    new_visibility: &'a str,
    new_rev: i64,
    old_json: &'a str,
    parent_id: Option<i64>,
    old_base_os_rev: i64,
    changed_by_user_id: Option<i64>,
    reason: Option<&'a str>,
}

impl StateStore {
    /// 翻转产品可见性（revision +1 + history，乐观并发同模块契约）：→public 要求祖先链
    /// 全 public（publish 单调性，环/超深防御 walk）；→private 要求无外部 child，且同事务
    /// 取消该产品活跃构建/任务；提交后失效 resolve 缓存 + bump 用户域代数。
    /// `base_os_revision` 不动（`base_os_bumped` 恒 false）。
    pub async fn update_product_visibility(
        &self,
        id: i64,
        visibility: &str,
        changed_by_user_id: Option<i64>,
        reason: Option<&str>,
        expected_revision: Option<i64>,
    ) -> crate::Result<UpdateOutcome> {
        let mut conn = self.begin_write().await?;

        #[allow(clippy::type_complexity)]
        let row: Option<(i64, i64, Option<i64>, String, Option<i64>)> = match sqlx::query_as(
            "SELECT revision, base_os_revision, parent_id, config_json, owner_id \
                 FROM products WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .db_ctx("select product for update")
        {
            Ok(r) => r,
            Err(e) => rollback_and_return!(conn, e),
        };

        let (old_rev, old_base_os_rev, parent_id, old_json, current_owner_id) = match row {
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

        // publish 单调性：private→public 需所有祖先 public。环/深度防御镜像 walk_chain：
        // 写路径 validate_parent_id 已拦环，此处 defense-in-depth（防手工改库），防写锁内死循环。
        if visibility == VISIBILITY_PUBLIC {
            use crate::state::product_resolve::MAX_CHAIN_DEPTH;
            use std::collections::HashSet;

            let mut visited: HashSet<i64> = HashSet::new();
            let mut cursor = parent_id;
            while let Some(pid) = cursor {
                if !visited.insert(pid) {
                    let mut chain: Vec<String> = visited.iter().map(|i| i.to_string()).collect();
                    chain.sort();
                    rollback_and_return!(conn, CrbsError::ProductChainCycle { chain });
                }
                if visited.len() >= MAX_CHAIN_DEPTH {
                    rollback_and_return!(
                        conn,
                        CrbsError::ProductChainTooDeep {
                            max: MAX_CHAIN_DEPTH,
                        }
                    );
                }
                let ancestor: Option<(String, String, Option<i64>)> =
                    match sqlx::query_as(sql::SELECT_VISIBILITY_AND_PARENT)
                        .bind(pid)
                        .fetch_optional(&mut *conn)
                        .await
                        .db_ctx("check ancestor visibility")
                    {
                        Ok(r) => r,
                        Err(e) => rollback_and_return!(conn, e),
                    };
                match ancestor {
                    Some((ancestor_visibility, ancestor_name, ancestor_parent)) => {
                        if ancestor_visibility != VISIBILITY_PUBLIC {
                            rollback_and_return!(conn, CrbsError::ProductChainInvalid {
                                product: ancestor_name,
                                reason: "ancestor is private; cannot publish product with private ancestor".into(),
                            });
                        }
                        cursor = ancestor_parent;
                    }
                    None => {
                        // 父行缺失 = DB 不一致，按 Database 错误回滚。
                        rollback_and_return!(
                            conn,
                            CrbsError::Database(format!(
                                "parent product id={} not found (inconsistent DB)",
                                pid
                            ))
                        );
                    }
                }
            }
        }

        // unpublish (private) 时检查是否有外部 child（owner 不同的子产品）
        if visibility == VISIBILITY_PRIVATE {
            let external_children = match self
                .count_external_children(id, current_owner_id, &mut conn)
                .await
            {
                Ok(n) => n,
                Err(e) => rollback_and_return!(conn, e),
            };
            if external_children > 0 {
                rollback_and_return!(conn, CrbsError::DeleteRestricted {
                    message: format!(
                        "product has {} external child product(s); re-parent or transfer them first to unpublish",
                        external_children
                    ),
                });
            }

            // 取消该产品全部 pending/building 构建与任务（与 delete/transfer 共用 cancel_builds_and_tasks_tx）。
            if let Err(e) = self.cancel_builds_and_tasks_tx(id, &mut conn).await {
                rollback_and_return!(conn, e);
            }
        }

        let new_rev = old_rev + 1;

        if let Err(e) = sqlx::query(&format!(
            "UPDATE products SET visibility = $1, revision = $2, updated_at = {} WHERE id = $3",
            self.dialect.sql_now()
        ))
        .bind(visibility)
        .bind(new_rev)
        .bind(id)
        .execute(&mut *conn)
        .await
        .db_ctx("update product visibility")
        {
            rollback_and_return!(conn, e);
        }

        if let Err(e) = sqlx::query(sql::INSERT_HISTORY)
            .bind(id)
            .bind(new_rev)
            .bind(&old_json)
            .bind(parent_id)
            .bind(old_base_os_rev)
            .bind(changed_by_user_id)
            .bind(reason)
            .execute(&mut *conn)
            .await
            .db_ctx("insert product visibility history")
        {
            rollback_and_return!(conn, e);
        }

        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit update visibility")
        {
            rollback_and_return!(conn, e);
        }

        // 提交后失效（失败语义见 invalidate_resolve_warned）。
        self.invalidate_resolve_warned(id).await;
        // 可见性翻转（含 unpublish）必须即时生效：repo 公开通道短缓存以用户域代数失效（transfer 同款 bump）。
        self.bump_user_generation();

        Ok(UpdateOutcome {
            revision: new_rev,
            base_os_revision: old_base_os_rev,
            base_os_bumped: false,
        })
    }

    /// 转让产品所有权（revision +1 + history）：新 owner 名下已有同名产品则 `AlreadyExists`
    ///（命名空间全局）；官方（owner NULL）→私人自动翻 `private`（SCHEMA CHECK 要求），仅该
    /// 方向检查外部 child 并同事务取消活跃构建/任务，私人间转让 visibility 不变、不取消；
    /// 取消计数随 `TransferOutcome` 返回。
    pub async fn transfer_product_ownership(
        &self,
        id: i64,
        new_owner_id: i64,
        changed_by_user_id: Option<i64>,
        reason: Option<&str>,
        expected_revision: Option<i64>,
    ) -> crate::Result<TransferOutcome> {
        #[derive(sqlx::FromRow)]
        struct TransferRow {
            revision: i64,
            base_os_revision: i64,
            parent_id: Option<i64>,
            config_json: String,
            visibility: String,
            owner_id: Option<i64>,
            name: String,
        }

        let mut conn = self.begin_write().await?;

        let row: Option<TransferRow> = match sqlx::query_as(
            "SELECT revision, base_os_revision, parent_id, config_json, visibility, owner_id, name \
             FROM products WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .db_ctx("select product for transfer")
        {
            Ok(r) => r,
            Err(e) => rollback_and_return!(conn, e),
        };

        let TransferRow {
            revision: old_rev,
            base_os_revision: old_base_os_rev,
            parent_id,
            config_json: old_json,
            visibility,
            owner_id: current_owner_id,
            name,
        } = match row {
            Some(r) => r,
            None => rollback_and_return!(
                conn,
                CrbsError::NotFound {
                    message: format!("product id={} not found", id),
                }
            ),
        };

        let exists: Option<i64> = match sqlx::query_scalar(
            "SELECT id FROM products WHERE owner_id = $1 AND name = $2 AND id != $3",
        )
        .bind(new_owner_id)
        .bind(&name)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .db_ctx("check transfer name collision")
        {
            Ok(r) => r,
            Err(e) => rollback_and_return!(conn, e),
        };
        if exists.is_some() {
            rollback_and_return!(
                conn,
                CrbsError::AlreadyExists {
                    message: format!(
                        "new owner already has a product named '{}' (namespace is global)",
                        name
                    ),
                }
            );
        }

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

        let new_rev = old_rev + 1;
        // 官方（owner_id=None）→用户自动转 private（满足 SCHEMA CHECK）；私人间转让 visibility 不变。
        let new_visibility = if current_owner_id.is_none() {
            VISIBILITY_PRIVATE
        } else {
            visibility.as_str()
        };

        // 仅官方→私人（visibility 翻转）检查外部 child 并 cancel；私人间转让不做。
        // 外部判断用 current_owner_id 而非 new_owner_id：官方产品的有主 child 全是外部。
        let (builds_cancelled, tasks_cancelled) = if current_owner_id.is_none()
            && new_visibility == VISIBILITY_PRIVATE
        {
            let external_children = match self
                .count_external_children(id, current_owner_id, &mut conn)
                .await
            {
                Ok(n) => n,
                Err(e) => rollback_and_return!(conn, e),
            };
            if external_children > 0 {
                rollback_and_return!(conn, CrbsError::DeleteRestricted {
                    message: format!(
                        "product has {} external child product(s); re-parent or transfer them first to take private",
                        external_children
                    ),
                });
            }

            // 同事务内取消该产品 pending/building 构建与任务（unpublish/delete/revoke 同款）。
            match self.cancel_builds_and_tasks_tx(id, &mut conn).await {
                Ok(c) => c,
                Err(e) => rollback_and_return!(conn, e),
            }
        } else {
            (0, 0)
        };

        self.transfer_commit_tx(
            &mut conn,
            TransferCommitParams {
                id,
                new_owner_id,
                new_visibility,
                new_rev,
                old_json: &old_json,
                parent_id,
                old_base_os_rev,
                changed_by_user_id,
                reason,
            },
        )
        .await?;

        Ok(TransferOutcome {
            revision: new_rev,
            base_os_revision: old_base_os_rev,
            base_os_bumped: false,
            builds_cancelled,
            tasks_cancelled,
        })
    }

    /// transfer 公共尾部：UPDATE + history + COMMIT + 失效 resolve cache；任一步失败先 ROLLBACK 再返回。
    async fn transfer_commit_tx(
        &self,
        conn: &mut sqlx::AnyConnection,
        params: TransferCommitParams<'_>,
    ) -> crate::Result<()> {
        let TransferCommitParams {
            id,
            new_owner_id,
            new_visibility,
            new_rev,
            old_json,
            parent_id,
            old_base_os_rev,
            changed_by_user_id,
            reason,
        } = params;
        if let Err(e) = sqlx::query(&format!(
            "UPDATE products SET owner_id = $1, visibility = $2, revision = $3, updated_at = {} WHERE id = $4",
            self.dialect.sql_now()
        ))
        .bind(new_owner_id)
        .bind(new_visibility)
        .bind(new_rev)
        .bind(id)
        .execute(&mut *conn)
        .await
        .db_ctx("update product owner")
        {
            rollback_and_return!(conn, e);
        }

        if let Err(e) = sqlx::query(sql::INSERT_HISTORY)
            .bind(id)
            .bind(new_rev)
            .bind(old_json)
            .bind(parent_id)
            .bind(old_base_os_rev)
            .bind(changed_by_user_id)
            .bind(reason)
            .execute(&mut *conn)
            .await
            .db_ctx("insert product transfer history")
        {
            rollback_and_return!(conn, e);
        }

        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit transfer ownership")
        {
            rollback_and_return!(conn, e);
        }

        // 提交后失效（失败语义见 invalidate_resolve_warned）。
        self.bump_user_generation();
        self.invalidate_resolve_warned(id).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! `update_product_visibility` / `transfer_product_ownership` 最小检查：官方→私人（含 cancel）、私人→私人、共享尾部、publish walk。

    use super::*;

    async fn store_with_user() -> (tempfile::TempDir, StateStore, i64) {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new_with_db_path(&tmp.path().join("state.db"), tmp.path())
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (name, role) VALUES ('alice', 'operator')")
            .execute(store.pool())
            .await
            .unwrap();
        let user_id: i64 = sqlx::query_scalar("SELECT id FROM users")
            .fetch_one(store.pool())
            .await
            .unwrap();
        (tmp, store, user_id)
    }

    fn official<'a>(
        name: &'a str,
        config: &'a crate::config::ProductConfig,
    ) -> CreateProductInput<'a> {
        CreateProductInput {
            name,
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config,
            changed_by_user_id: None,
            reason: None,
        }
    }

    /// 全流程：官方→私人（cancel + visibility 翻转）→ 私人→私人（无 cancel）→ publish 回 public（空 ancestor walk）。
    #[tokio::test]
    async fn transfer_and_visibility_roundtrip() {
        let (_tmp, store, user_id) = store_with_user().await;
        let config = crate::config::ProductConfig::default();
        let id = store
            .create_product(official("prod", &config))
            .await
            .unwrap();

        // 一条 pending 构建：官方→私人 transfer 应在事务内取消。builds.task_id NOT NULL，
        // 先插任务行承接；task 行经裸 SQL 种入、product_id 为 NULL——正是 name 口径要覆盖的形态。
        sqlx::query(
            "INSERT INTO tasks (product, pkg_name, user, phase) VALUES ('prod', 'x', '', 'pending')",
        )
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO builds (product, pkg_name, phase, user_id, product_id, task_id) \
             VALUES ('prod', 'x', 'pending', $1, $2, (SELECT MAX(id) FROM tasks))",
        )
        .bind(user_id)
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();

        let out = store
            .transfer_product_ownership(id, user_id, None, Some("to alice"), None)
            .await
            .unwrap();
        assert_eq!(out.revision, 2);
        assert_eq!(
            out.builds_cancelled, 1,
            "pending build cancelled on official->private"
        );
        assert_eq!(
            out.tasks_cancelled, 1,
            "pending task must be finalized by name (product_id NULL row included)"
        );
        let task_phase: String =
            sqlx::query_scalar("SELECT phase FROM tasks WHERE product = 'prod'")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(
            task_phase, "cancelled",
            "task's only child build was cancelled in the same tx; finalize aggregates to cancelled"
        );
        let rec = store.get_product_by_id(id).await.unwrap().unwrap();
        assert_eq!(rec.owner_id, Some(user_id));
        assert_eq!(rec.visibility, VISIBILITY_PRIVATE);

        let out = store
            .transfer_product_ownership(id, user_id, None, Some("self-transfer"), None)
            .await
            .unwrap();
        assert_eq!(out.revision, 3);
        assert_eq!(out.builds_cancelled, 0);
        assert_eq!(out.tasks_cancelled, 0);

        // publish 回 public：root 无祖先，ancestor walk 直接通过。
        let out = store
            .update_product_visibility(id, VISIBILITY_PUBLIC, None, Some("publish"), None)
            .await
            .unwrap();
        assert_eq!(out.revision, 4);
        let rec = store.get_product_by_id(id).await.unwrap().unwrap();
        assert_eq!(rec.visibility, VISIBILITY_PUBLIC);

        // history：create 1 + transfer 2 + visibility 1 = 4 行。
        assert_eq!(store.list_product_history(id).await.unwrap().len(), 4);
    }
}
