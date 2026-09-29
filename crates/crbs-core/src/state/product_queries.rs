// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产品维度活跃构建查询：计数、提交者去重与在途包判定。

use super::types::ActiveBuildRef;
use super::StateStore;
use crate::error::DbResultExt;

mod sql {
    // active 集合含 'assigned'：已派发未启动也是活跃构建，漏掉会让
    // dispatched-but-not-started 的 build 绕过 init/clean 的 active 守卫。
    pub(super) const COUNT_ACTIVE_FOR_PRODUCT: &str =
        "SELECT COUNT(*) FROM builds WHERE product = $1 AND phase IN ('building', 'pending', 'assigned')";

    pub(super) const LIST_ACTIVE_BUILD_USERS_FOR_PRODUCT: &str =
        "SELECT DISTINCT \"user\" AS \"user\" FROM builds \
         WHERE product = $1 AND phase IN ('building', 'pending', 'assigned') \
           AND \"user\" != $2 AND \"user\" != ''";

    /// 提交去重短路查询：`{}` 由调用方按 pkg_names 数量拼动态 `$n` IN 占位符
    /// （gc_queries SELECT_PACKAGE_URLS_TEMPLATE 同款）；active 口径同 COUNT_ACTIVE_FOR_PRODUCT（含 'assigned'）。
    pub(super) const SELECT_ACTIVE_BUILDS_FOR_PKG_NAMES_TEMPLATE: &str = "\
        SELECT pkg_name, id AS build_id, phase, task_id FROM builds \
         WHERE product = $1 AND pkg_name IN ({}) \
           AND phase IN ('pending', 'assigned', 'building')";
}

impl StateStore {
    /// 查询指定产品下 active（building + pending + assigned）状态的 build 数量。
    pub async fn count_active_for_product(&self, product: &str) -> crate::Result<i64> {
        let count: i64 = sqlx::query_scalar(sql::COUNT_ACTIVE_FOR_PRODUCT)
            .bind(product)
            .fetch_one(&self.pool)
            .await
            .db_ctx("count active builds")?;
        Ok(count)
    }

    /// 查询指定产品下其他用户的活跃 build 用户名；过滤空用户名旧记录，避免错误消息出现空串。
    pub async fn active_build_users_for_product(
        &self,
        product: &str,
        exclude_user: &str,
    ) -> crate::Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(sql::LIST_ACTIVE_BUILD_USERS_FOR_PRODUCT)
            .bind(product)
            .bind(exclude_user)
            .fetch_all(&self.pool)
            .await
            .db_ctx("active build users")?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    /// 查询产品下给定 pkg_name 集合的活跃构建（提交去重短路用）；active 口径同
    /// [`Self::count_active_for_product`]。空切片直接返回空 Vec——`IN ()` 双方言均非法，Rust 侧短路。
    pub async fn active_builds_for_pkg_names(
        &self,
        product: &str,
        pkg_names: &[&str],
    ) -> crate::Result<Vec<ActiveBuildRef>> {
        if pkg_names.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = crate::state::db::in_placeholders(2, pkg_names.len())?;
        let select_sql =
            sql::SELECT_ACTIVE_BUILDS_FOR_PKG_NAMES_TEMPLATE.replace("{}", &placeholders);
        let mut query = sqlx::query_as(&select_sql).bind(product);
        for name in pkg_names {
            query = query.bind(name);
        }
        let rows: Vec<(String, i64, String, Option<i64>)> = query
            .fetch_all(&self.pool)
            .await
            .db_ctx("active builds for pkg names")?;
        Ok(rows
            .into_iter()
            .map(|(pkg_name, build_id, phase, task_id)| ActiveBuildRef {
                pkg_name,
                build_id,
                phase,
                task_id,
            })
            .collect())
    }
}
