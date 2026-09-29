// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建计数、列表、镜像播种与按 id 读取。

use std::collections::HashMap;

use sqlx::Row;

use super::sql;
use crate::error::DbResultExt;
use crate::state::{
    build_record_from_row, pending_build_info_from_row, BuildRecord, PendingBuildInfo, StateStore,
    TaskInsert,
};
use crate::types::{build_phase_is_terminal, BuildPriority};

impl StateStore {
    /// 按 phase 分组统计构建数量；不存在的 phase 不出现在结果中。
    pub async fn count_builds_by_phase(&self) -> crate::Result<HashMap<String, i64>> {
        Ok(self
            .count_builds_by_phase_scoped(None, None, None, None)
            .await?
            .into_iter()
            .collect())
    }

    /// 带 list_builds 同口径过滤的 phase 计数（相位 chips）：复用
    /// `build_list_where` / `apply_visible_products`；空 phase 不出现。
    pub async fn count_builds_by_phase_scoped(
        &self,
        visible_products: Option<&[String]>,
        product: Option<&str>,
        name: Option<&str>,
        arch: Option<&str>,
    ) -> crate::Result<Vec<(String, i64)>> {
        let visible_owned = visible_products.map(<[String]>::to_vec);
        let (where_sql, mut binds) =
            Self::build_list_where(product, None, None, name, None, arch, None);
        let where_sql =
            Self::apply_visible_products(where_sql, &mut binds, visible_owned.as_ref())?;
        let sql =
            format!("SELECT phase, COUNT(*) AS cnt FROM builds WHERE {where_sql} GROUP BY phase");
        let mut q = sqlx::query(&sql);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .db_ctx("count builds by phase (scoped)")?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get("phase"), r.get::<i64, _>("cnt")))
            .collect())
    }

    /// 产品 succeeded 构建的裸源包名去重集合（整仓重建增量判定事实源；只按
    /// 包名、不做版本级判定）。列取 `name`（裸包名）：与 N-V-R 形态的
    /// `pkg_name` 永不相交，用错列增量永不触发。
    pub async fn list_succeeded_source_names(&self, product: &str) -> crate::Result<Vec<String>> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT name FROM builds WHERE product = $1 AND phase = 'succeeded'",
        )
        .bind(product)
        .fetch_all(&self.pool)
        .await
        .db_ctx("list succeeded source names")?;
        Ok(rows)
    }

    /// 持久化构建请求信息，用于 server 崩溃后恢复 pending 任务。
    pub async fn set_build_request_info(
        &self,
        id: i64,
        srpm_path: &str,
        request_json: &str,
    ) -> crate::Result<()> {
        sqlx::query(sql::SET_BUILD_REQUEST_INFO)
            .bind(srpm_path)
            .bind(request_json)
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("set build request info")?;
        Ok(())
    }

    /// 写入产品配置快照（构建创建 / hub 派发时点的链式合并 TOML 原文）。
    /// 失败影响溯源但不阻断构建，调用方按 warn-only 处理。
    pub async fn set_build_product_config_toml(
        &self,
        id: i64,
        product_config_toml: &str,
    ) -> crate::Result<()> {
        sqlx::query(sql::SET_BUILD_PRODUCT_CONFIG_TOML)
            .bind(product_config_toml)
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("set build product config toml")?;
        Ok(())
    }

    /// 读取产品配置快照；`None` = 构建不存在或该行未锚定。
    pub async fn get_build_product_config_toml(&self, id: i64) -> crate::Result<Option<String>> {
        let row: Option<Option<String>> = sqlx::query_scalar(sql::SELECT_BUILD_PRODUCT_CONFIG_TOML)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("get build product config toml")?;
        Ok(row.flatten())
    }

    /// 更新构建记录的 crbs_pid。返回行数：0 = 构建不存在。
    pub async fn update_build_crbs_pid(&self, id: i64, crbs_pid: i64) -> crate::Result<u64> {
        let result = sqlx::query(sql::UPDATE_BUILD_CRBS_PID)
            .bind(crbs_pid)
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("update build crbs_pid")?;
        Ok(result.rows_affected())
    }

    /// worker 本地库播种 hub build_id 镜像行（幂等）：缺失时插本地 task 行 +
    /// 指定 id 的 build 行（显式 id = hub 下发值）；同名同包的活跃行原样复用
    ///（reclaim 重执行续跑），终态行重置 pending（本库已收尾而 hub 侧上报丢失
    /// 后的重派重执行入口）。镜像行让 worker 侧 lifecycle 落在 hub id 空间——
    /// profile.json / crbs-artifacts.json / 结果目录叶子不写本地自增 id。
    pub async fn seed_remote_build_mirror(
        &self,
        build_id: i64,
        product: &str,
        pkg_name: &str,
    ) -> crate::Result<()> {
        let Some(record) = self.get_build(build_id).await? else {
            let task_id = self
                .insert_task(TaskInsert {
                    product,
                    pkg_name,
                    user: "",
                    user_id: None,
                    phase: "pending",
                    priority: 0,
                    srpm_path: None,
                    result_dir: None,
                    request_json: None,
                    pkg_names: None,
                })
                .await?;
            let (name, version, release) = crate::util::split_nvr(pkg_name);
            sqlx::query(&sql::insert_build_with_id(self.dialect))
                .bind(build_id)
                .bind(product)
                .bind(pkg_name)
                .bind(name)
                .bind(version)
                .bind(release)
                .bind("pending")
                .bind("")
                .bind(task_id)
                .execute(&self.pool)
                .await
                .db_ctx("insert remote build mirror row")?;
            return Ok(());
        };
        // 身份守卫：hub id 与本地自增序列共用一个整数空间，回退路径自插的引擎
        // 行可能恰好占住该 id——异名行拒绝复用/重置（attach 由调用方降级走
        // 引擎自插行，不碰他人历史）。
        if record.product != product || record.pkg_name != pkg_name {
            return Err(crate::error::CrbsError::ValidationFailed {
                message: format!(
                    "build id {build_id} collision: local row is {}/{}, refusing to seed mirror for {product}/{pkg_name}",
                    record.product, record.pkg_name
                ),
            });
        }
        if build_phase_is_terminal(&record.phase) {
            sqlx::query(&sql::reset_mirror_build_row(self.dialect))
                .bind(build_id)
                .execute(&self.pool)
                .await
                .db_ctx("reset remote build mirror row")?;
        }
        Ok(())
    }

    /// 列出所有带持久化请求信息的 pending 构建。
    pub async fn list_pending_with_request_info(&self) -> crate::Result<Vec<PendingBuildInfo>> {
        let rows = sqlx::query(sql::LIST_PENDING_WITH_REQUEST_INFO)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list pending with request info")?;

        Ok(rows
            .into_iter()
            .map(|r| pending_build_info_from_row(&r))
            .collect())
    }

    /// 按 build_id 查询单条构建记录。
    pub async fn get_build(&self, id: i64) -> crate::Result<Option<BuildRecord>> {
        let row = sqlx::query(&sql::select_build_by_id())
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("get build")?;

        Ok(row.map(|r| build_record_from_row(&r)))
    }

    /// 构建的重排次数（attempt）：上传归属校验用——重派后必须携带
    /// assignment id，首轮 attempt 允许缺省。行不存在返回 None。
    pub async fn get_build_attempt(&self, id: i64) -> crate::Result<Option<i64>> {
        let row: Option<i64> = sqlx::query_scalar("SELECT attempt FROM builds WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("get build attempt")?;
        Ok(row)
    }

    /// 批量点查构建行 phase（只含存在的行，供按 presence 分流）；单条
    /// `WHERE id IN` 消除 N+1。IN 参数上限由 in_placeholders 守卫
    ///（MAX_BIND_PARAMS=30_000），超限走"跳过本轮"保守分支。
    pub async fn get_existing_build_phases(
        &self,
        build_ids: &[i64],
    ) -> crate::Result<HashMap<i64, String>> {
        if build_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = crate::state::db::in_placeholders(1, build_ids.len())?;
        let sql_text = format!(
            "SELECT id, phase FROM builds WHERE id IN ({})",
            placeholders
        );
        let mut q = sqlx::query(&sql_text);
        for &id in build_ids {
            q = q.bind(id);
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .db_ctx("get existing build phases")?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get::<i64, _>("id"), r.get::<String, _>("phase")))
            .collect())
    }

    /// 统计 building 构建数量。GC 决策用：构建期间共享资源可能被引用但未入
    /// 持久化清单，应暂停回收。
    pub async fn count_building_builds(&self) -> crate::Result<i64> {
        let count: i64 = sqlx::query_scalar(sql::COUNT_BUILDING_BUILDS)
            .fetch_one(&self.pool)
            .await
            .db_ctx("count building builds")?;
        Ok(count)
    }

    /// 查询构建记录（过滤分页）；默认 id 降序，`order_by` 可覆盖 started_desc
    /// / id_asc，`user` 过滤含旧记录 user = ''。`visible_products` Some 时 SQL
    /// 层可见性过滤（分页前，total 同口径），None 不过滤。返回 `(total, records)`；
    /// 空页（offset 越界）退回独立 COUNT 保 total（与 tasks 侧同口径）。
    pub async fn list_builds(
        &self,
        filter: &crate::types::BuildListFilter<'_>,
    ) -> crate::Result<(usize, Vec<BuildRecord>)> {
        let (where_sql, mut binds) = Self::build_list_where(
            filter.product,
            filter.user,
            filter.phase,
            filter.name,
            filter.source_name,
            filter.arch,
            filter.srpm_sha256,
        );
        // 可见性白名单先注入：IN 名单追加进 binds，后续占位符编号基于新长度。
        let mut where_sql =
            Self::apply_visible_products(where_sql, &mut binds, filter.visible_products.as_ref())?;
        let mut task_id_bind: Option<i64> = None;
        if let Some(id) = filter.task_id {
            let task_id_idx = binds.len() + 1;
            where_sql = format!("{} AND task_id = ${task_id_idx}", where_sql);
            task_id_bind = Some(id);
        }
        // priority 是 INTEGER 列，须 typed bind：字符串 bind 在 SQLite 按存储类
        // 比较恒假、PG 类型不匹配。
        let mut priority_bind: Option<BuildPriority> = None;
        if let Some(p) = filter.priority {
            let priority_idx = binds.len() + task_id_bind.is_some() as usize + 1;
            where_sql = format!("{} AND priority = ${priority_idx}", where_sql);
            priority_bind = Some(p);
        }

        let pagination_sql = crate::state::db::pagination_clause(
            self.dialect,
            filter.limit,
            filter.offset,
            binds.len() + task_id_bind.is_some() as usize + priority_bind.is_some() as usize + 1,
        );
        let order_sql = Self::build_order_by(filter.order_by);
        let select_sql = sql::list_builds_template()
            .replace("{WHERE}", &where_sql)
            .replace("{ORDER}", order_sql)
            .replace("{PAGE}", &pagination_sql);
        let mut q = sqlx::query(&select_sql);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        if let Some(id) = task_id_bind {
            q = q.bind(id);
        }
        if let Some(p) = priority_bind {
            q = q.bind(p);
        }
        if let Some(limit) = filter.limit {
            q = q.bind(limit as i64);
        }
        if let Some(offset) = filter.offset {
            q = q.bind(offset as i64);
        }
        let rows = q.fetch_all(&self.pool).await.db_ctx("list builds")?;

        // 空页（offset 越界/无行）时窗口函数无行，退回独立 COUNT 保 total（分页控件依赖）。
        let total: usize = match rows.first().and_then(|r| r.try_get::<i64, _>("total").ok()) {
            Some(t) => t as usize,
            None => {
                let count_sql = format!("SELECT COUNT(*) FROM builds WHERE {where_sql}");
                let mut q = sqlx::query_scalar::<_, i64>(&count_sql);
                for b in &binds {
                    q = q.bind(b.as_str());
                }
                // where_sql 尾部的 task_id/priority 占位符与主查询同序补绑。
                if let Some(id) = task_id_bind {
                    q = q.bind(id);
                }
                if let Some(p) = priority_bind {
                    q = q.bind(p);
                }
                q.fetch_one(&self.pool).await.db_ctx("count builds")? as usize
            }
        };
        let records = rows
            .into_iter()
            .map(|r| build_record_from_row(&r))
            .collect();

        Ok((total, records))
    }

    /// 产品内给定源码包集合（`builds.name`）各自最近一次构建（id 最大者）：
    /// 产品页画像包列表的"最新构建"列，集合取画像当前页（≤ page_size），
    /// 聚合不扫产品全量。无构建的声明-only 包不出现在结果里。
    pub async fn latest_builds_by_source(
        &self,
        product: &str,
        sources: &[&str],
    ) -> crate::Result<Vec<crate::state::LatestSourceBuild>> {
        if sources.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = crate::state::db::in_placeholders(2, sources.len())?;
        let sql = format!(
            "SELECT b.name AS source_name, b.id, b.pkg_name, b.arch, b.phase, b.completed_at \
             FROM builds b \
             JOIN (SELECT name, MAX(id) AS max_id FROM builds \
                   WHERE product = $1 AND name IN ({placeholders}) GROUP BY name) m \
               ON b.id = m.max_id"
        );
        let mut q = sqlx::query(&sql).bind(product);
        for s in sources {
            q = q.bind(*s);
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .db_ctx("latest builds by source")?;
        Ok(rows
            .into_iter()
            .map(|r| crate::state::LatestSourceBuild {
                source_name: r.get("source_name"),
                id: r.get("id"),
                pkg_name: r.get("pkg_name"),
                arch: r.get("arch"),
                phase: r.get("phase"),
                completed_at: r.get("completed_at"),
            })
            .collect())
    }

    /// 构造 list_builds 的 WHERE 子句与绑定参数列表（按绑定顺序）。
    fn build_list_where(
        product: Option<&str>,
        user: Option<&str>,
        phase: Option<&str>,
        name: Option<&str>,
        source_name: Option<&str>,
        arch: Option<&str>,
        srpm_sha256: Option<&str>,
    ) -> (String, Vec<String>) {
        let mut parts = Vec::new();
        let mut binds: Vec<String> = Vec::new();
        crate::state::db::push_common_filters(&mut parts, &mut binds, product, user, phase, name);
        if let Some(source) = source_name.filter(|v| !v.is_empty()) {
            crate::state::db::push_filter(&mut parts, &mut binds, "name = $N", source.to_string());
        }
        if let Some(arch) = arch.filter(|v| !v.is_empty()) {
            crate::state::db::push_filter(&mut parts, &mut binds, "arch = $N", arch.to_string());
        }
        if let Some(sha) = srpm_sha256.filter(|v| !v.is_empty()) {
            crate::state::db::push_filter(
                &mut parts,
                &mut binds,
                "canonical_srpm_sha256 = $N",
                sha.to_string(),
            );
        }
        if parts.is_empty() {
            ("1=1".to_string(), binds)
        } else {
            (parts.join(" AND "), binds)
        }
    }

    fn build_order_by(order_by: Option<&str>) -> &'static str {
        match order_by {
            Some("started_desc") => "started_at DESC, id DESC",
            Some("id_asc") => "id ASC",
            // 未知 sort 值宽松回退 id DESC（既定裁定）；UI 表单的 id_desc 也
            // 依赖本臂，收紧为 400 前必须先补显式臂。
            _ => "id DESC",
        }
    }

    /// 查询指定 PID 的所有 in-progress 构建记录。
    pub async fn list_in_progress_by_pid(&self, pid: i64) -> crate::Result<Vec<BuildRecord>> {
        let rows = sqlx::query(&sql::list_in_progress_by_pid())
            .bind(pid)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list in-progress by pid")?;

        let records = rows
            .into_iter()
            .map(|r| build_record_from_row(&r))
            .collect();

        Ok(records)
    }

    /// 最近 `limit` 个 succeeded 构建的时长样本（条形图）。scope：可见性三态
    ///（`apply_visible_products`）+ `user`/`product` 等值；只取 duration 非空
    /// 行；completed_at UTC TEXT 字典序即时间序，双方言通用。
    async fn recent_succeeded_build_durations_scoped(
        &self,
        visible_products: Option<&[String]>,
        user: Option<&str>,
        product: Option<&str>,
        limit: i64,
    ) -> crate::Result<Vec<crate::types::BuildDurationSample>> {
        let (where_sql, binds) = Self::scoped_user_product_where(visible_products, user, product)?;
        let where_sql = format!("phase = 'succeeded' AND duration IS NOT NULL AND ({where_sql})");
        let sql = format!(
            "SELECT pkg_name, arch, duration FROM builds WHERE {where_sql} \
             ORDER BY completed_at DESC, id DESC LIMIT ${}",
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
            .db_ctx("recent succeeded build durations")?;
        Ok(rows
            .into_iter()
            .map(|r| crate::types::BuildDurationSample {
                pkg_name: r.get("pkg_name"),
                arch: r.get::<Option<String>, _>("arch").unwrap_or_default(),
                duration_secs: r.get("duration"),
            })
            .collect())
    }

    /// scoped 版的全局薄包装（仪表盘，可见性口径同 [`Self::list_builds`]）。
    pub async fn recent_succeeded_build_durations(
        &self,
        visible_products: Option<&[String]>,
        limit: i64,
    ) -> crate::Result<Vec<crate::types::BuildDurationSample>> {
        self.recent_succeeded_build_durations_scoped(visible_products, None, None, limit)
            .await
    }

    /// scoped 版的 for_user 薄包装（/ui/me）。
    pub async fn recent_succeeded_build_durations_for_user(
        &self,
        user: &str,
        limit: i64,
    ) -> crate::Result<Vec<crate::types::BuildDurationSample>> {
        self.recent_succeeded_build_durations_scoped(None, Some(user), None, limit)
            .await
    }

    /// scoped 版的 for_product 薄包装（产品详情页；可见性由调用方校验）。
    pub async fn recent_succeeded_build_durations_for_product(
        &self,
        product: &str,
        limit: i64,
    ) -> crate::Result<Vec<crate::types::BuildDurationSample>> {
        self.recent_succeeded_build_durations_scoped(None, None, Some(product), limit)
            .await
    }
}
