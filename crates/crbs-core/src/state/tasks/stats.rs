// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Task 状态存储方法。

use super::*;

/// 单产品活动聚合行（[`StateStore::product_activity_for_products`] 产出；
/// `total_tasks` 计全部相位）。`last_task_at` 与 `TaskRecord::submitted_at`/
/// `completed_at` 同型：DB 墙钟 TEXT（`YYYY-MM-DD HH24:MI:SS`，UTC）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductActivity {
    pub total_tasks: i64,
    /// 最近一次构建时间（completed_at 优先、进行中回退 submitted_at）；无任务为 None。
    pub last_task_at: Option<String>,
}

impl StateStore {
    /// 按产品可见性过滤的 phase 计数（`None` = 不过滤）：不过滤会把私有产品
    /// 构建活动量（存在性 + 体量）泄露给匿名访客/普通用户；三态语义同
    /// `apply_visible_products`。
    pub async fn count_tasks_by_phase_visible(
        &self,
        visible_products: Option<&[String]>,
    ) -> crate::Result<HashMap<String, i64>> {
        Ok(self
            .count_tasks_by_phase_scoped(visible_products, None, None, None)
            .await?
            .into_iter()
            .collect())
    }

    /// list_tasks 同口径过滤的 phase 计数内核（相位 chips）：可见性白名单 +
    /// `product` 等值 + `name` 包名前缀 + `label` 精确 (key, value)（复用
    /// `build_task_list_where`）；空 phase 不出现。
    pub async fn count_tasks_by_phase_scoped(
        &self,
        visible_products: Option<&[String]>,
        product: Option<&str>,
        name: Option<&str>,
        label: Option<(&str, &str)>,
    ) -> crate::Result<Vec<(String, i64)>> {
        let visible_owned = visible_products.map(<[String]>::to_vec);
        let (where_sql, mut binds) =
            Self::build_task_list_where(product, None, None, name, None, label);
        let where_sql =
            Self::apply_visible_products(where_sql, &mut binds, visible_owned.as_ref())?;
        let sql =
            format!("SELECT phase, COUNT(*) AS cnt FROM tasks WHERE {where_sql} GROUP BY phase");
        let mut q = sqlx::query(&sql);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .db_ctx("count tasks by phase (scoped)")?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get("phase"), r.get::<i64, _>("cnt")))
            .collect())
    }

    /// 最近 `limit` 条任务的相位序列（统计图，id DESC newest-first）。
    /// `visible_products` 三态语义同 [`Self::apply_visible_products`]；
    /// `user` / `product` 精确等值，`LIMIT $N` 绑定双方言通用。
    async fn recent_task_phase_series_scoped(
        &self,
        visible_products: Option<&[String]>,
        user: Option<&str>,
        product: Option<&str>,
        limit: i64,
    ) -> crate::Result<Vec<String>> {
        let (where_sql, binds) = Self::scoped_user_product_where(visible_products, user, product)?;
        let sql = format!(
            "SELECT phase FROM tasks WHERE {where_sql} ORDER BY id DESC LIMIT ${}",
            binds.len() + 1
        );
        let mut q = sqlx::query(&sql);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        let rows = q
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .db_ctx("recent task phase series")?;
        Ok(rows.into_iter().map(|r| r.get("phase")).collect())
    }

    /// scoped 版的全局薄包装（仪表盘趋势图）。
    pub async fn recent_task_phase_series(
        &self,
        visible_products: Option<&[String]>,
        limit: i64,
    ) -> crate::Result<Vec<String>> {
        self.recent_task_phase_series_scoped(visible_products, None, None, limit)
            .await
    }

    /// for_user 薄包装（/ui/me 个人趋势图）。
    pub async fn recent_task_phase_series_for_user(
        &self,
        user: &str,
        limit: i64,
    ) -> crate::Result<Vec<String>> {
        self.recent_task_phase_series_scoped(None, Some(user), None, limit)
            .await
    }

    /// for_product 薄包装（产品详情页趋势图；可见性由调用方校验，此处不过滤）。
    pub async fn recent_task_phase_series_for_product(
        &self,
        product: &str,
        limit: i64,
    ) -> crate::Result<Vec<String>> {
        self.recent_task_phase_series_scoped(None, None, Some(product), limit)
            .await
    }

    /// 按用户过滤的 phase 计数（/ui/me 个人总览带）：追加 `user = $1` 判等；自己的任务自己可见，无可见性豁免。
    pub async fn count_tasks_by_phase_for_user(
        &self,
        user: &str,
    ) -> crate::Result<HashMap<String, i64>> {
        let rows = sqlx::query(
            "SELECT phase, COUNT(*) AS cnt FROM tasks WHERE \"user\" = $1 GROUP BY phase",
        )
        .bind(user)
        .fetch_all(&self.pool)
        .await
        .db_ctx("count tasks by phase for user")?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let phase: String = r.get("phase");
                let count: i64 = r.get("cnt");
                (phase, count)
            })
            .collect())
    }

    /// 按产品过滤的 phase 计数（产品详情页总览带）：追加 `product = $1`；可见性由调用方对产品本身校验，此处不再过滤。
    pub async fn count_tasks_by_phase_for_product(
        &self,
        product: &str,
    ) -> crate::Result<HashMap<String, i64>> {
        let rows = sqlx::query(
            "SELECT phase, COUNT(*) AS cnt FROM tasks WHERE product = $1 GROUP BY phase",
        )
        .bind(product)
        .fetch_all(&self.pool)
        .await
        .db_ctx("count tasks by phase for product")?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let phase: String = r.get("phase");
                let count: i64 = r.get("cnt");
                (phase, count)
            })
            .collect())
    }

    /// 批量产品活动聚合（产品列表页 Tasks / Last build 列），单条 GROUP BY 查询
    /// 消除逐产品 N+1。last = MAX(COALESCE(completed_at, submitted_at))：UTC 墙钟
    /// TEXT 字典序即时间序（双方言同语义），与详情页"最新一条任务"在乱序完成时
    /// 可能略有出入。IN 占位符同 `apply_visible_products` 白名单（双方言通用）；
    /// 无任务产品不出现（调用方缺省 0 / "—"），空列表返回空 map，不发 SQL。
    pub async fn product_activity_for_products(
        &self,
        products: &[String],
    ) -> crate::Result<HashMap<String, ProductActivity>> {
        if products.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = crate::state::db::in_placeholders(1, products.len())?;
        let sql = format!(
            "SELECT product, COUNT(*) AS cnt, MAX(COALESCE(completed_at, submitted_at)) AS last_at \
             FROM tasks WHERE product IN ({}) GROUP BY product",
            placeholders
        );
        let mut q = sqlx::query(&sql);
        for p in products {
            q = q.bind(p.as_str());
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .db_ctx("product activity for products")?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let product: String = r.get("product");
                (
                    product,
                    ProductActivity {
                        total_tasks: r.get("cnt"),
                        last_task_at: r.get("last_at"),
                    },
                )
            })
            .collect())
    }
}
