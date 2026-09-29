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

mod sql {
    use super::BUILD_COLUMNS;

    /// 任务列清单，与 `TaskRecord` 字段一一对应须同步；`"user" AS "user"`：USER 是
    /// PG 保留字，列名/别名都须加引号（SQLite 双引号别名合法），别名确保 row.get 命中。
    pub(super) const TASK_COLUMNS: &str = "id, product, pkg_name, name, version, release, \"user\" AS \"user\", phase, priority, srpm_path, \
         result_dir, submitted_at, completed_at, duration, pkg_names";

    pub(super) fn select_task_by_id() -> String {
        format!("SELECT {TASK_COLUMNS} FROM tasks WHERE id = $1")
    }

    /// 列表查询模板：`{WHERE}`/`{ORDER}`/`{PAGE}` 由调用方 replace，`COUNT(*) OVER ()` 单次扫描带过滤后总数。
    pub(super) fn list_tasks_template() -> String {
        format!(
            "SELECT {TASK_COLUMNS}, COUNT(*) OVER () AS total \
             FROM tasks WHERE {{WHERE}} ORDER BY {{ORDER}}{{PAGE}}"
        )
    }

    pub(super) const SELECT_TASK_REBUILD_INFO: &str = "SELECT product, \"user\" AS \"user\", priority, result_dir, request_json, pkg_name FROM tasks WHERE id = $1";

    /// task 下子构建去重 arch（按首次出现序）：PG 禁 `DISTINCT + ORDER BY id`
    ///（SELECT 列不在 ORDER BY），`GROUP BY arch ORDER BY MIN(id)` 双后端可移植保序。
    pub(super) const LIST_TASK_ARCHES: &str =
        "SELECT arch FROM builds WHERE task_id = $1 AND arch <> '' GROUP BY arch ORDER BY MIN(id)";

    /// 去版本包名列表模板：`{WHERE}` 由调用方 replace。
    pub(super) const LIST_PACKAGE_NAMES_TEMPLATE: &str =
        "SELECT DISTINCT name FROM tasks WHERE {WHERE} AND name <> '' ORDER BY name";

    /// 按 task_id 聚合 build phase 计数：`{IDS}` 由调用方 replace 为占位符列表。
    pub(super) const COUNT_BUILDS_BY_TASK_TEMPLATE: &str =
        "SELECT task_id, phase, COUNT(*) AS cnt FROM builds \
         WHERE task_id IN ({IDS}) GROUP BY task_id, phase";

    /// 分组列代码常量（完整 NVR / 基础包名）；列名拼进 SQL 无法参数化，绝不能来自用户输入。
    pub(super) const GROUP_COL_PKG_NAME: &str = "pkg_name";
    pub(super) const GROUP_COL_NAME: &str = "name";

    /// 分组总数模板：`{WHERE}` 由调用方 replace；`group_col` 只接受上述代码常量。
    pub(super) fn count_task_groups_template(group_col: &str) -> String {
        format!("SELECT COUNT(*) FROM (SELECT {group_col} FROM tasks WHERE {{WHERE}} GROUP BY {group_col}) g")
    }

    /// 分组分页模板：`{WHERE}`/`{PAGE}` 由调用方 replace；最新行 = MAX(id) 回 JOIN
    ///（双后端可移植），排序固定 latest_id DESC，分组键输出别名固定 `group_key`。
    pub(super) fn list_task_groups_template(group_col: &str) -> String {
        format!(
            "SELECT g.{group_col} AS group_key, g.attempts AS attempts, \
                    t.id AS latest_id, t.product AS product, t.phase AS phase, \
                    t.\"user\" AS \"user\", t.submitted_at AS submitted_at \
             FROM ( \
                 SELECT {group_col}, COUNT(*) AS attempts, MAX(id) AS latest_id \
                 FROM tasks WHERE {{WHERE}} GROUP BY {group_col} \
             ) g \
             JOIN tasks t ON t.id = g.latest_id \
             ORDER BY g.latest_id DESC{{PAGE}}"
        )
    }

    pub(super) fn list_builds_by_task_id() -> String {
        format!("SELECT {BUILD_COLUMNS} FROM builds WHERE task_id = $1 ORDER BY arch")
    }

    /// worker 列取该构建最新一次 build 型归属的 worker 名（attempt 重试产生
    /// 多行，最新即当前/最终归属；无归属（本地构建）为 NULL）。
    pub(super) const LIST_CHILD_BUILD_SUMMARIES: &str = "SELECT id, arch, phase, result_dir, started_at, duration, \
        (SELECT w.name FROM worker_tasks wt JOIN workers w ON w.id = wt.worker_id \
         WHERE wt.build_id = builds.id AND wt.kind = 'build' ORDER BY wt.id DESC LIMIT 1) AS worker \
        FROM builds WHERE task_id = $1 ORDER BY arch";
}

/// 解析 tasks.pkg_names（JSON 数组），NULL/非法 → 空列表；单包展示由 `TaskRecord.pkg_name`/`pkg_label` 兜底。
fn task_pkg_names(raw: Option<String>) -> Vec<String> {
    raw.as_deref()
        .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
        .unwrap_or_default()
}

/// 从含 `sql::TASK_COLUMNS` 的行构造 [`TaskRecord`]（get_task / list_tasks 共用）。
fn task_record_from_row(r: &sqlx::any::AnyRow) -> TaskRecord {
    let pkg_name: String = r.get("pkg_name");
    let pkg_names = task_pkg_names(r.get("pkg_names"));
    TaskRecord {
        id: r.get::<i64, _>("id"),
        product: r.get("product"),
        pkg_name,
        name: r.get("name"),
        version: r.get("version"),
        release: r.get("release"),
        user: r.get("user"),
        phase: r.get("phase"),
        priority: r.get::<i64, _>("priority") as BuildPriority,
        srpm_path: r.get("srpm_path"),
        result_dir: r.get("result_dir"),
        submitted_at: r.get("submitted_at"),
        completed_at: r.get("completed_at"),
        duration: r.get("duration"),
        pkg_names,
    }
}

/// 任务分组粒度：完整 NVR（pkg_name）或基础包名（name，去版本）。
#[derive(Clone, Copy)]
enum TaskGroupCol {
    /// 完整 NVR 分组（packages 详情页视图 A）。
    Nvr,
    /// 基础包名分组（packages 列表页）。
    Name,
}

impl TaskGroupCol {
    /// SQL 列名，代码常量（见 `sql::GROUP_COL_*`）——绝不能由用户输入决定。
    fn as_sql(self) -> &'static str {
        match self {
            Self::Nvr => sql::GROUP_COL_PKG_NAME,
            Self::Name => sql::GROUP_COL_NAME,
        }
    }
}

impl StateStore {
    /// 按 task_id 查询单条任务记录。
    pub async fn get_task(&self, id: i64) -> crate::Result<Option<TaskRecord>> {
        let row = sqlx::query(&sql::select_task_by_id())
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("get task")?;

        Ok(row.map(|r| task_record_from_row(&r)))
    }

    /// 查询任务列表（过滤 + 分页），默认 id 降序，`order_by` 可覆盖为
    /// `submitted_desc` / `id_asc`；返回 `(total, records)`，total 为满足过滤的
    /// 总数（与分页无关）。`user` 过滤含旧记录 user = ''；`visible_products`
    /// 下沉 SQL（显式可见 + 孤儿豁免），语义同 [`StateStore::list_nvr_groups`]。
    pub async fn list_tasks(
        &self,
        filter: &crate::types::TaskListFilter<'_>,
    ) -> crate::Result<(usize, Vec<TaskRecord>)> {
        let (where_sql, mut binds) = Self::build_task_list_where(
            filter.product,
            filter.user,
            filter.phase,
            filter.name,
            filter.nvr,
            filter.label.as_ref().map(|(k, v)| (k.as_str(), v.as_str())),
        );
        let where_sql =
            Self::apply_visible_products(where_sql, &mut binds, filter.visible_products.as_ref())?;

        let pagination_sql = crate::state::db::pagination_clause(
            self.dialect,
            filter.limit,
            filter.offset,
            binds.len() + 1,
        );
        let order_sql = Self::build_task_order_by(filter.order_by);
        let select_sql = sql::list_tasks_template()
            .replace("{WHERE}", &where_sql)
            .replace("{ORDER}", order_sql)
            .replace("{PAGE}", &pagination_sql);
        let mut q = sqlx::query(&select_sql);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        // 契约：limit/offset None = 有意全量（内部调用方客户端过滤）；用户入口须在上游
        // 封顶（server validate_list_pagination / MAX_LIST_LIMIT），勿在此给缺省强插 LIMIT。
        if let Some(limit) = filter.limit {
            q = q.bind(limit as i64);
        }
        if let Some(offset) = filter.offset {
            q = q.bind(offset as i64);
        }
        let rows = q.fetch_all(&self.pool).await.db_ctx("list tasks")?;

        // 空页（offset 越界/无行）时窗口函数无行，退回独立 COUNT 保 total（分页控件依赖）。
        let total: usize = match rows.first().and_then(|r| r.try_get::<i64, _>("total").ok()) {
            Some(t) => t as usize,
            None => {
                let count_sql = format!("SELECT COUNT(*) FROM tasks WHERE {where_sql}");
                let mut q = sqlx::query_scalar::<_, i64>(&count_sql);
                for b in &binds {
                    q = q.bind(b.as_str());
                }
                q.fetch_one(&self.pool).await.db_ctx("count tasks")? as usize
            }
        };
        let records = rows.into_iter().map(|r| task_record_from_row(&r)).collect();

        Ok((total, records))
    }

    /// 查询 rebuild 重放所需的 task 档案（product/user/priority/result_dir/request_json）。
    pub async fn get_task_rebuild_info(&self, id: i64) -> crate::Result<Option<TaskRebuildInfo>> {
        let row = sqlx::query(sql::SELECT_TASK_REBUILD_INFO)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("get task rebuild info")?;

        Ok(row.map(|r| TaskRebuildInfo {
            product: r.get("product"),
            user: r.get("user"),
            priority: r.get::<i64, _>("priority") as BuildPriority,
            result_dir: r.get("result_dir"),
            request_json: r.get("request_json"),
            pkg_name: r.get("pkg_name"),
        }))
    }

    /// 返回 task 下子构建的去重架构列表（按首次出现序）。
    pub async fn get_task_arches(&self, id: i64) -> crate::Result<Vec<String>> {
        let rows = sqlx::query(sql::LIST_TASK_ARCHES)
            .bind(id)
            .fetch_all(&self.pool)
            .await
            .db_ctx("get task arches")?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<String, _>("arch"))
            .collect())
    }

    /// 列出去版本包名（DISTINCT name）：可选 product/user/name（子串）过滤，字母升序。
    pub async fn list_package_names(
        &self,
        product: Option<&str>,
        user: Option<&str>,
        name: Option<&str>,
        visible_products: Option<&[String]>,
        limit: Option<usize>,
        offset: usize,
    ) -> crate::Result<(usize, Vec<String>)> {
        let (where_sql, mut binds) =
            Self::build_task_list_where(product, user, None, None, None, None);
        // 可见性白名单（三态语义同 apply_visible_products）：漏掉时私有产品的
        // 包名存在性/数量元数据会从 /ui/packages 泄出。
        let visible_owned;
        let visible: Option<&Vec<String>> = match visible_products {
            None => None,
            Some(vs) => {
                visible_owned = vs.to_vec();
                Some(&visible_owned)
            }
        };
        let mut parts = vec![Self::apply_visible_products(
            where_sql, &mut binds, visible,
        )?];
        // name 框子串过滤：escape_like 转义（\ % _）+ ESCAPE '\' 字面匹配（push_filter $N 编号）。
        if let Some(name) = name.map(str::trim).filter(|v| !v.is_empty()) {
            crate::state::db::push_filter(
                &mut parts,
                &mut binds,
                "name LIKE $N ESCAPE '\\'",
                format!("%{}%", crate::state::db::escape_like(name)),
            );
        }
        let where_sql = parts.join(" AND ");

        // DISTINCT 拿不到窗口 total，用独立 COUNT；子查询必须带别名（PG 报
        // "subquery in FROM must have an alias"）。
        let count_sql = format!(
            "SELECT COUNT(*) FROM (SELECT DISTINCT name FROM tasks WHERE {where_sql} AND name <> '') sub"
        );
        let mut q = sqlx::query_scalar::<_, i64>(&count_sql);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        let total = q
            .fetch_one(&self.pool)
            .await
            .db_ctx("count package names")? as usize;

        let page_sql = sql::LIST_PACKAGE_NAMES_TEMPLATE.replace("{WHERE}", &where_sql)
            + &crate::state::db::pagination_clause(
                self.dialect,
                limit,
                if offset > 0 { Some(offset) } else { None },
                binds.len() + 1,
            );
        let mut q = sqlx::query(&page_sql);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        if let Some(limit) = limit {
            q = q.bind(limit as i64);
        }
        if offset > 0 {
            q = q.bind(offset as i64);
        }
        let rows = q.fetch_all(&self.pool).await.db_ctx("list package names")?;
        Ok((
            total,
            rows.into_iter()
                .map(|r| r.get::<String, _>("name"))
                .collect(),
        ))
    }

    /// 查询任务记录（id 降序）并聚合各 task 下 phase 子构建计数；返回
    /// `(total, Vec<(TaskRecord, HashMap<phase, count>)>)`。
    pub async fn list_tasks_with_counts(
        &self,
        filter: &crate::types::TaskListFilter<'_>,
    ) -> crate::Result<(usize, Vec<(TaskRecord, HashMap<String, i64>)>)> {
        let (total, tasks) = self.list_tasks(filter).await?;
        if tasks.is_empty() {
            return Ok((total, Vec::new()));
        }

        let ids: Vec<i64> = tasks.iter().map(|t| t.id).collect();
        let placeholders = crate::state::db::in_placeholders(1, ids.len())?;
        let sql_buf = sql::COUNT_BUILDS_BY_TASK_TEMPLATE.replace("{IDS}", &placeholders);
        let mut q = sqlx::query(&sql_buf);
        for id in &ids {
            q = q.bind(*id);
        }
        let rows = q
            .fetch_all(self.pool())
            .await
            .db_ctx("list task build counts")?;

        let mut counts: HashMap<i64, HashMap<String, i64>> = HashMap::new();
        for row in rows {
            let task_id: i64 = row.get("task_id");
            let phase: String = row.get("phase");
            let cnt: i64 = row.get("cnt");
            counts.entry(task_id).or_default().insert(phase, cnt);
        }

        let out = tasks
            .into_iter()
            .map(|t| {
                let c = counts.remove(&t.id).unwrap_or_default();
                (t, c)
            })
            .collect();

        Ok((total, out))
    }

    /// 按主 NVR（pkg_name）分组，返回每组尝试次数 + 最新任务关键字段；最新行取
    /// `MAX(id)` 回 JOIN（双后端可移植），排序固定 `latest_id DESC`；返回
    /// `(total_groups, Vec<NvrGroupSummary>)`。可见性按 attempt 维度（非
    /// per-group）：`Some(list)` 时 inner WHERE 拼 `(product IN (...) OR 孤儿豁免)`
    /// ——孤儿名永远进不了 `visible_products`（`list_products` 只返回现存产品），
    /// 豁免必须 SQL 层做；三态语义详见 `StateStore::apply_visible_products`。
    pub async fn list_nvr_groups(
        &self,
        filter: &crate::state::NvrGroupFilter<'_>,
    ) -> crate::Result<(usize, Vec<crate::state::NvrGroupSummary>)> {
        self.list_task_groups(TaskGroupCol::Nvr, filter).await
    }

    /// 按基础包名（name，去版本）分组，返回每组尝试次数 + 最新任务关键字段
    ///（WebUI packages 列表页数据源）。与 [`StateStore::list_nvr_groups`] 共用
    /// 底层，仅两处粒度差异：分组列为 `name`（`split_nvr` 拆出的基础名）；
    /// `filter.name` 是 name 列子串匹配（nvr 版为 pkg_name 前缀匹配）。
    /// `NvrGroupSummary.pkg_name` 装的是基础包名而非完整 NVR。
    pub async fn list_name_groups(
        &self,
        filter: &crate::state::NvrGroupFilter<'_>,
    ) -> crate::Result<(usize, Vec<crate::state::NvrGroupSummary>)> {
        self.list_task_groups(TaskGroupCol::Name, filter).await
    }

    /// list_nvr_groups / list_name_groups 共用底层（COUNT + 分页两段查询，分组列
    /// 见 [`TaskGroupCol::as_sql`]）；可见性按 attempt 维度，三态白名单见 apply_visible_products。
    async fn list_task_groups(
        &self,
        col: TaskGroupCol,
        filter: &crate::state::NvrGroupFilter<'_>,
    ) -> crate::Result<(usize, Vec<crate::state::NvrGroupSummary>)> {
        // WHERE 按粒度分叉：name 过滤语义不同（前缀 vs 子串），其余全共享。
        let (parts, mut binds) = match col {
            // NVR 粒度：不按 phase/精确 NVR 过滤（尝试视图职责）；name = pkg_name 前缀匹配（兼容粘贴完整 NVR）。
            TaskGroupCol::Nvr => {
                let (where_sql, binds) = Self::build_task_list_where(
                    filter.product,
                    filter.user,
                    None,
                    filter.name,
                    None,
                    None,
                );
                (vec![where_sql], binds)
            }
            // name 粒度：name 框 = name 列子串匹配（同 list_package_names）；
            // 排除空 name 行（`name <> ''` 防御）。
            TaskGroupCol::Name => {
                let (where_sql, mut binds) = Self::build_task_list_where(
                    filter.product,
                    filter.user,
                    None,
                    None,
                    None,
                    None,
                );
                let mut parts = vec![where_sql, "name <> ''".to_string()];
                if let Some(name) = filter.name.map(str::trim).filter(|v| !v.is_empty()) {
                    crate::state::db::push_filter(
                        &mut parts,
                        &mut binds,
                        "name LIKE $N ESCAPE '\\'",
                        format!("%{}%", crate::state::db::escape_like(name)),
                    );
                }
                (parts, binds)
            }
        };
        let where_sql = Self::apply_visible_products(
            parts.join(" AND "),
            &mut binds,
            filter.visible_products.as_ref(),
        )?;

        let group_col = col.as_sql();
        let total: i64 = {
            let count_sql =
                sql::count_task_groups_template(group_col).replace("{WHERE}", &where_sql);
            let mut q = sqlx::query_scalar::<_, i64>(&count_sql);
            for b in &binds {
                q = q.bind(b.as_str());
            }
            q.fetch_one(&self.pool).await.db_ctx("count task groups")?
        };

        let pagination_sql = crate::state::db::pagination_clause(
            self.dialect,
            filter.limit,
            filter.offset,
            binds.len() + 1,
        );
        let select_sql = sql::list_task_groups_template(group_col)
            .replace("{WHERE}", &where_sql)
            .replace("{PAGE}", &pagination_sql);
        let mut q = sqlx::query(&select_sql);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        if let Some(limit) = filter.limit {
            q = q.bind(limit as i64);
        }
        if let Some(offset) = filter.offset {
            q = q.bind(offset as i64);
        }
        let rows = q.fetch_all(&self.pool).await.db_ctx("list task groups")?;

        let groups = rows
            .into_iter()
            .map(|r| crate::state::NvrGroupSummary {
                pkg_name: r.get("group_key"),
                attempts: r.get::<i64, _>("attempts"),
                latest_task_id: r.get::<i64, _>("latest_id"),
                product: r.get("product"),
                phase: r.get("phase"),
                user: r.get("user"),
                submitted_at: r.get("submitted_at"),
            })
            .collect();

        Ok((total as usize, groups))
    }

    /// 构造 list_tasks 的 WHERE 子句与绑定参数列表。
    pub(super) fn build_task_list_where(
        product: Option<&str>,
        user: Option<&str>,
        phase: Option<&str>,
        name: Option<&str>,
        nvr: Option<&str>,
        label: Option<(&str, &str)>,
    ) -> (String, Vec<String>) {
        let mut parts = Vec::new();
        let mut binds: Vec<String> = Vec::new();
        crate::state::db::push_common_filters(&mut parts, &mut binds, product, user, phase, name);
        if let Some(nvr) = nvr.filter(|v| !v.is_empty()) {
            crate::state::db::push_filter(&mut parts, &mut binds, "pkg_name = $N", nvr.to_string());
        }
        if let Some((key, value)) = label {
            let key_idx = binds.len() + 1;
            let value_idx = key_idx + 1;
            parts.push(format!(
                "EXISTS (SELECT 1 FROM task_labels tl \
                 WHERE tl.task_id = tasks.id AND tl.key = ${key_idx} AND tl.value = ${value_idx})"
            ));
            binds.push(key.to_string());
            binds.push(value.to_string());
        }
        if parts.is_empty() {
            ("1=1".to_string(), binds)
        } else {
            (parts.join(" AND "), binds)
        }
    }

    /// 把可见性白名单注入列表 WHERE（list_tasks / list_nvr_groups / list_builds
    /// 共用）。三态：`None` 不过滤（admin/operator bypass）；`Some(empty)` 仅拼孤儿
    /// 豁免 `product NOT IN (SELECT name FROM products)`（现存产品全不可见，已删
    /// 产品历史仍可见）；`Some(non_empty)` 拼 `(product IN (...) OR 孤儿豁免)`；IN
    /// 占位符经 `db::in_placeholders` 收口（超限 ValidationFailed 而非驱动参数号错误），故返回 `Result`。
    pub(crate) fn apply_visible_products(
        where_sql: String,
        binds: &mut Vec<String>,
        visible: Option<&Vec<String>>,
    ) -> crate::Result<String> {
        let Some(visible) = visible else {
            return Ok(where_sql);
        };
        let orphan_clause = "product NOT IN (SELECT name FROM products)";
        let visibility_clause = if visible.is_empty() {
            orphan_clause.to_string()
        } else {
            let base_idx = binds.len();
            let placeholders = crate::state::db::in_placeholders(base_idx + 1, visible.len())?;
            let in_clause = format!("product IN ({})", placeholders);
            format!("({} OR {})", in_clause, orphan_clause)
        };
        for name in visible {
            binds.push(name.clone());
        }
        Ok(if where_sql == "1=1" {
            visibility_clause
        } else {
            format!("({}) AND {}", where_sql, visibility_clause)
        })
    }

    /// scoped 统计查询的公共 WHERE 前奏（recent_task_phase_series_scoped /
    /// recent_succeeded_build_durations_scoped 共用）：`user`/`product` 等值
    /// push_filter 后叠加 [`Self::apply_visible_products`] 白名单；绑定顺序
    /// user → product → 可见性 IN 集，SELECT 主体与行映射留调用方。
    pub(crate) fn scoped_user_product_where(
        visible_products: Option<&[String]>,
        user: Option<&str>,
        product: Option<&str>,
    ) -> crate::Result<(String, Vec<String>)> {
        let visible_owned = visible_products.map(<[String]>::to_vec);
        let (mut parts, mut binds) = (Vec::new(), Vec::new());
        if let Some(user) = user {
            crate::state::db::push_filter(
                &mut parts,
                &mut binds,
                "\"user\" = $N",
                user.to_string(),
            );
        }
        if let Some(product) = product {
            crate::state::db::push_filter(
                &mut parts,
                &mut binds,
                "product = $N",
                product.to_string(),
            );
        }
        let where_sql = if parts.is_empty() {
            "1=1".to_string()
        } else {
            parts.join(" AND ")
        };
        let where_sql =
            Self::apply_visible_products(where_sql, &mut binds, visible_owned.as_ref())?;
        Ok((where_sql, binds))
    }
    fn build_task_order_by(order_by: Option<&str>) -> &'static str {
        match order_by {
            Some("submitted_desc") => "submitted_at DESC, id DESC",
            Some("id_asc") => "id ASC",
            // 未知 sort 值宽松回退 id DESC（既定裁定）；UI 表单的 id_desc 也
            // 依赖本臂，收紧为 400 前必须先补显式臂。
            _ => "id DESC",
        }
    }

    /// 查询任务下的所有子构建记录（按架构排序）。
    pub async fn get_builds_by_task_id(&self, task_id: i64) -> crate::Result<Vec<BuildRecord>> {
        let rows = sqlx::query(&sql::list_builds_by_task_id())
            .bind(task_id)
            .fetch_all(&self.pool)
            .await
            .db_ctx("get builds by task_id")?;

        Ok(rows
            .into_iter()
            .map(|r| build_record_from_row(&r))
            .collect())
    }

    /// 查询任务下的子构建（id/arch/phase/result_dir/duration 摘要）。
    pub async fn get_child_build_summaries(
        &self,
        task_id: i64,
    ) -> crate::Result<Vec<crate::types::ChildBuildSummary>> {
        let rows = sqlx::query(sql::LIST_CHILD_BUILD_SUMMARIES)
            .bind(task_id)
            .fetch_all(&self.pool)
            .await
            .db_ctx("get child build summaries")?;

        Ok(rows
            .into_iter()
            .map(|r| crate::types::ChildBuildSummary {
                id: r.get::<i64, _>("id"),
                // arch 列可空（engine 本地构建/早期 fixture 不写 arch，列定义无
                // NOT NULL）：非空 TEXT 解码在 NULL 行 panic，按仓库"无 arch"惯例
                // 回落空串。
                arch: r.get::<Option<String>, _>("arch").unwrap_or_default(),
                phase: r.get("phase"),
                result_dir: r.get("result_dir"),
                started_at: r.get("started_at"),
                duration: r.get("duration"),
                worker: r.get("worker"),
            })
            .collect())
    }
}
