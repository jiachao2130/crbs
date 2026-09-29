// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 共享层与包清单的关联读写。

use super::StateStore;
use crate::error::DbResultExt;

mod sql {
    use crate::state::Dialect;

    /// Upsert layer packages：双后端统一 ON CONFLICT DO UPDATE（SQLite ≥ 3.24，
    /// artifacts.rs 已依赖同款语法）；冲突时覆盖 product/packages、保留 created_at，
    /// 同一输入两后端状态一致。
    pub(super) fn upsert_layer_packages(_dialect: Dialect) -> String {
        "INSERT INTO layer_packages (digest, product, packages) VALUES ($1, $2, $3) \
         ON CONFLICT (digest) DO UPDATE SET \
            product = EXCLUDED.product, \
            packages = EXCLUDED.packages"
            .to_string()
    }

    pub(super) const SELECT_LAYER_PACKAGES: &str =
        "SELECT packages FROM layer_packages WHERE digest = $1";
}

impl StateStore {
    /// 持久化 SharedLayer 的包列表（upsert，覆盖旧值）。
    pub async fn insert_layer_packages(
        &self,
        digest: &str,
        product: &str,
        packages: &str,
    ) -> crate::Result<()> {
        sqlx::query(&sql::upsert_layer_packages(self.dialect))
            .bind(digest)
            .bind(product)
            .bind(packages)
            .execute(&self.pool)
            .await
            .db_ctx("insert layer_packages")?;
        Ok(())
    }

    /// 查询持久化的包列表（用于恢复 SharedLayer）。
    pub async fn get_layer_packages(&self, digest: &str) -> crate::Result<Option<String>> {
        let text: Option<String> = sqlx::query_scalar(sql::SELECT_LAYER_PACKAGES)
            .bind(digest)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("get layer_packages")?;
        Ok(text)
    }
}
