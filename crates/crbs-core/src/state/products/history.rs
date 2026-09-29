// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产品配置历史（`product_config_history`）查询：全量按 `revision` 降序 / 按 revision 精确取单条；
//! 不做可见性过滤——检查在 server 层（模块契约见 mod.rs）。
use super::*;

impl StateStore {
    /// 产品全部配置历史，`revision` 降序（新→旧）。
    pub async fn list_product_history(
        &self,
        product_id: i64,
    ) -> crate::Result<Vec<ProductConfigHistoryEntry>> {
        sqlx::query_as::<_, HistoryRow>(sql::LIST_HISTORY)
            .bind(product_id)
            .fetch_all(self.pool())
            .await
            .db_ctx("list product history")
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    /// 取产品指定 `revision` 的单条历史；无该版本 None。
    pub async fn get_product_history_revision(
        &self,
        product_id: i64,
        revision: i64,
    ) -> crate::Result<Option<ProductConfigHistoryEntry>> {
        sqlx::query_as::<_, HistoryRow>(sql::SELECT_HISTORY_REV)
            .bind(product_id)
            .bind(revision)
            .fetch_optional(self.pool())
            .await
            .db_ctx("get product history rev")
            .map(|opt| opt.map(Into::into))
    }
}
