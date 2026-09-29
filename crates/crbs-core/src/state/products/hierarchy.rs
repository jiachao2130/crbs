// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产品仓库：`products` / `product_config_history` 表的 CRUD。契约：`revision` 每次
//! update 单调 +1（驱动 history 与 chain-resolve 缓存失效）；`base_os_revision` 仅触发
//! 字段变化时抬到 `= revision`；`update_product_config` 事务 `BEGIN IMMEDIATE` + 可选
//! `expected_revision`（乐观并发），冲突返回 `RevisionConflict { expected, current }`
//!（server 映射 409）；可见性检查放 server 层（`AuthContext` 不在 crbs-core）。
use super::*;
use crate::state::rollback_and_return;

impl StateStore {
    /// 递归检查产品 public 后代（unpublish/转让官方产品前泄漏检查）：BFS，`visited` 防环，深度上限 32。
    pub async fn has_public_descendants(&self, product_id: i64) -> crate::Result<bool> {
        use std::collections::{HashSet, VecDeque};

        const MAX_DEPTH: usize = 32;

        let mut visited = HashSet::new();
        visited.insert(product_id);
        let mut queue = VecDeque::new();
        queue.push_back((product_id, 0usize));

        while let Some((pid, depth)) = queue.pop_front() {
            if depth >= MAX_DEPTH {
                continue;
            }
            let children: Vec<(i64, String)> = sqlx::query_as(sql::SELECT_CHILDREN_ID_VISIBILITY)
                .bind(pid)
                .fetch_all(self.pool())
                .await
                .db_ctx("check public descendants")?;
            for (child_id, visibility) in children {
                if !visited.insert(child_id) {
                    continue;
                }
                if visibility == VISIBILITY_PUBLIC {
                    return Ok(true);
                }
                queue.push_back((child_id, depth + 1));
            }
        }

        Ok(false)
    }

    /// 池上校验（server 层预检 / 测试用）；写路径必须在事务内改走 `validate_parent_id_tx`，否则 TOCTOU。
    pub async fn validate_parent_id(
        &self,
        self_id: Option<i64>,
        new_parent: i64,
    ) -> crate::Result<()> {
        let mut conn = self.pool.acquire().await.db_ctx("acquire conn")?;
        Self::validate_parent_id_tx(&mut conn, self_id, new_parent).await
    }

    /// [`Self::validate_parent_id`] 的事务内版本：写锁内沿 parent 链向上走，
    /// 校验 new_parent 存在、不经 `self_id`、无环、深度不超限。
    pub(super) async fn validate_parent_id_tx(
        conn: &mut sqlx::AnyConnection,
        self_id: Option<i64>,
        new_parent: i64,
    ) -> crate::Result<()> {
        use crate::state::product_resolve::MAX_CHAIN_DEPTH;
        use std::collections::HashSet;

        let mut visited: HashSet<i64> = HashSet::new();
        let mut cur = Some(new_parent);
        let mut depth: usize = 0;
        while let Some(id) = cur {
            if Some(id) == self_id {
                return Err(CrbsError::ProductChainCycle {
                    chain: vec![
                        format!("self={}", id),
                        format!("via new_parent={}", new_parent),
                    ],
                });
            }
            if !visited.insert(id) {
                let mut chain: Vec<String> = visited.iter().map(|i| i.to_string()).collect();
                chain.sort();
                return Err(CrbsError::ProductChainCycle { chain });
            }
            depth += 1;
            if depth >= MAX_CHAIN_DEPTH {
                return Err(CrbsError::ProductChainTooDeep {
                    max: MAX_CHAIN_DEPTH,
                });
            }
            // `Option<Option<i64>>`：外层 None = 行不存在（NotFound），内层 None = 到根停下。
            let next: Option<Option<i64>> = sqlx::query_scalar(sql::SELECT_PARENT_ID_ONLY)
                .bind(id)
                .fetch_optional(&mut *conn)
                .await
                .db_ctx("validate_parent_id load")?;
            match next {
                None => {
                    return Err(CrbsError::NotFound {
                        message: format!("parent product id={} not found", id),
                    });
                }
                Some(p) => cur = p,
            }
        }
        Ok(())
    }

    /// re-parent / detach（`new_parent = None`）。`expected_revision`：Some 要求事务内快照
    /// revision 命中，否则 `RevisionConflict`（server 映射 409）；None = 无门，内部乐观守卫仍生效。
    pub async fn update_product_parent(
        &self,
        id: i64,
        new_parent: Option<i64>,
        changed_by_user_id: Option<i64>,
        reason: Option<&str>,
        expected_revision: Option<i64>,
    ) -> crate::Result<UpdateOutcome> {
        let mut conn = self.begin_write().await?;

        // 环/深度校验必须在写锁内：池上预检有 TOCTOU——并发 reparent 可同时过校验再各自提交，拼出环。
        if let Some(pid) = new_parent {
            if let Err(e) = Self::validate_parent_id_tx(&mut conn, Some(id), pid).await {
                rollback_and_return!(conn, e);
            }
        }

        let row: Option<(i64, i64, Option<i64>, String)> =
            match sqlx::query_as(sql::SELECT_PRODUCT_REV_SNAPSHOT)
                .bind(id)
                .fetch_optional(&mut *conn)
                .await
                .db_ctx("select product revision snapshot for reparent")
            {
                Ok(r) => r,
                Err(e) => rollback_and_return!(conn, e),
            };
        let (old_rev, base_os_rev, old_parent, old_json) = match row {
            Some(r) => r,
            None => rollback_and_return!(
                conn,
                CrbsError::NotFound {
                    message: format!("product id={} not found", id),
                }
            ),
        };

        // PUT products 复合写 = config 更新 + reparent 两事务：无调用方门（None）时乐观锁
        // 契约只盖前半段——并发写者可插在两事务之间、reparent 静默叠在其上。
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
        // parent 实际变化（reparent / detach）→ 继承链换根，合并结果视同 base_os 内容变更，
        // base_os_revision 抬到 = revision；no-op reparent 只 bump revision 不抬 base_os。
        let parent_changed = old_parent != new_parent;
        let new_base_os_rev = if parent_changed { new_rev } else { base_os_rev };

        // 乐观守卫：UPDATE 带 `AND revision = old_rev`（事务内快照），0 行转 RevisionConflict，
        // 兜 PG SELECT→UPDATE 间并发提交；SQLite BEGIN IMMEDIATE 串行化下结构性不可触发。
        let result = match sqlx::query(&sql::update_product_parent(self.dialect))
            .bind(new_parent)
            .bind(new_rev)
            .bind(id)
            .bind(new_base_os_rev)
            .bind(old_rev)
            .execute(&mut *conn)
            .await
            .db_ctx("update parent")
        {
            Ok(r) => r,
            Err(e) => rollback_and_return!(conn, e),
        };
        if result.rows_affected() == 0 {
            let current: Option<i64> = match sqlx::query_scalar(sql::SELECT_PRODUCT_REVISION)
                .bind(id)
                .fetch_optional(&mut *conn)
                .await
                .db_ctx("re-read product revision after lost reparent")
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
            .bind(&old_json)
            .bind(new_parent)
            .bind(new_base_os_rev)
            .bind(changed_by_user_id)
            .bind(reason)
            .execute(&mut *conn)
            .await
            .db_ctx("insert reparent history")
        {
            rollback_and_return!(conn, e);
        }

        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit update_product_parent")
        {
            rollback_and_return!(conn, e);
        }

        // 递归失效 self + 后代的 resolve cache（提交后调用，失败语义见 invalidate_resolve_warned）。
        self.invalidate_resolve_warned(id).await;

        Ok(UpdateOutcome {
            revision: new_rev,
            base_os_revision: new_base_os_rev,
            base_os_bumped: parent_changed,
        })
    }
}
