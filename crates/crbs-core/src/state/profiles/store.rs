// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 画像 state 读写：学习样本消费、声明面 CRUD、批量读取与回填播种。

use super::backfill::{
    backfill_group_meets_min_peak, fold_backfill_samples, profile_from_row, BackfillSampleGroups,
    DeclaredRow,
};
use super::{
    next_learned_state, read_learned_state_on, sql, upsert_learned_state_on, validate_profile_key,
    DeclaredRequirements, LearnedWeightSnapshot, PackageResourceProfile, ProfileBackfillStats,
    ProfileUpdateDecision, ResourceSampleOutcome,
};
use crate::error::DbResultExt;
use crate::state::{rollback_and_return, StateStore};

impl StateStore {
    /// 终态样本喂入学习面（best-effort 维护画像，调用方失败仅 warn 不阻塞
    /// 终态写入）。行为：
    /// - CapOom 忽略（限额非需求）；键有空值防御跳过；
    /// - 轻包门槛（`min_peak_rss_kb`）以下的 Succeeded 不写行；
    /// - Succeeded 折叠 EMA（α=0.4）并推进 samples/max；NodeOom 删失只抬
    ///   max（×headroom）、ema 不动、samples 计入；
    /// - 口径 sticky：cgroup 粘滞（忽略 proc 样本），proc→cgroup 清零重算。
    ///
    /// 列组隔离：只写 learned_* 组，永不触碰 declared_*。返回本次学习决策
    ///（供调用方 metrics 计数；Skipped/CapHitExcluded 不发生写入）。
    pub async fn apply_learning_sample(
        &self,
        product: &str,
        source_name: &str,
        arch: &str,
        outcome: &ResourceSampleOutcome,
        min_peak_rss_kb: Option<i64>,
        headroom: f64,
    ) -> crate::Result<ProfileUpdateDecision> {
        if matches!(outcome, ResourceSampleOutcome::CapOom) {
            tracing::debug!(
                product = %product,
                source = %source_name,
                arch = %arch,
                "cap-OOM resource sample ignored for profile learning"
            );
            return Ok(ProfileUpdateDecision::CapHitExcluded);
        }
        if product.is_empty() || source_name.is_empty() || arch.is_empty() {
            tracing::debug!(
                product = %product,
                source = %source_name,
                arch = %arch,
                "empty-key resource sample skipped for profile learning"
            );
            return Ok(ProfileUpdateDecision::Skipped);
        }
        // headroom 是删失抬升乘数：<1 或非有限会让 max 不抬甚至倒降（违背
        // 只抬不降不变量）。
        if !headroom.is_finite() || headroom < 1.0 {
            return Err(crate::error::CrbsError::ValidationFailed {
                message: format!(
                    "profile learning headroom must be a finite value >= 1.0, got {headroom}"
                ),
            });
        }

        // 写事务包住读改写：SQLite BEGIN IMMEDIATE 串行化并发终态上报的 EMA
        // 递推；PG READ COMMITTED 下读改写可竞态，last-writer-wins 只漂移
        // 统计量，列组隔离保证 declared 组不受影响。
        let mut conn = self
            .begin_write()
            .await
            .db_ctx("begin profile learning tx")?;

        let current = match read_learned_state_on(&mut conn, product, source_name, arch).await {
            Ok(v) => v,
            Err(e) => rollback_and_return!(conn, e),
        };
        let (next, decision) = next_learned_state(
            current.as_ref(),
            outcome,
            min_peak_rss_kb,
            headroom,
            product,
            source_name,
            arch,
        );

        if let Some(state) = next {
            if let Err(e) =
                upsert_learned_state_on(&mut conn, self.dialect, product, source_name, arch, &state)
                    .await
            {
                rollback_and_return!(conn, e);
            }
        }

        if let Err(e) = sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit profile learning")
        {
            rollback_and_return!(conn, e);
        }
        Ok(decision)
    }

    /// 写声明面（hub admin 显式钉入的放置契约）：UPSERT 只写 declared 四列
    ///（含 declared_updated_at），学习组与行身份列不动。全 None = 显式置空
    ///（该行三维全部未声明）；删行请走 [`Self::unset_declared_requirements`]
    /// 语义（也只清列）。
    pub async fn set_declared_requirements(
        &self,
        product: &str,
        source_name: &str,
        arch: &str,
        min_mem_kb: Option<i64>,
        min_ncpu: Option<i64>,
        min_disk_kb: Option<i64>,
    ) -> crate::Result<()> {
        validate_profile_key(product, source_name, arch)?;
        sqlx::query(&sql::upsert_declared(self.dialect))
            .bind(product)
            .bind(source_name)
            .bind(arch)
            .bind(min_mem_kb)
            .bind(min_ncpu)
            .bind(min_disk_kb)
            .execute(&self.pool)
            .await
            .db_ctx("upsert declared requirements")?;
        self.notify_state_changed();
        Ok(())
    }

    /// 清声明面：只清 declared 四列（置 NULL），**不删行**——行内 learned
    /// 是不可再生的学习资产。行不存在时幂等（0 行影响）。
    pub async fn unset_declared_requirements(
        &self,
        product: &str,
        source_name: &str,
        arch: &str,
    ) -> crate::Result<()> {
        validate_profile_key(product, source_name, arch)?;
        sqlx::query(&sql::unset_declared(self.dialect))
            .bind(product)
            .bind(source_name)
            .bind(arch)
            .execute(&self.pool)
            .await
            .db_ctx("unset declared requirements")?;
        self.notify_state_changed();
        Ok(())
    }

    /// 声明面查找：精确 arch 优先，未命中回退 arch='any'（架构无关哨兵）。
    /// 行存在但声明三维全空视为未声明（继续回退）——'any' 契约不因精确
    /// arch 行仅被学习路径创建而失效。
    pub async fn find_declared_requirements(
        &self,
        product: &str,
        source_name: &str,
        arch: &str,
    ) -> crate::Result<Option<DeclaredRequirements>> {
        match self.declared_for_arch(product, source_name, arch).await? {
            Some(hit) => Ok(Some(hit)),
            None => self.declared_for_arch(product, source_name, "any").await,
        }
    }

    /// 单 arch 声明行读取（精确/回退两跳共用）；声明三维全空按未声明处理。
    async fn declared_for_arch(
        &self,
        product: &str,
        source_name: &str,
        arch: &str,
    ) -> crate::Result<Option<DeclaredRequirements>> {
        let row = sqlx::query_as::<_, (String, Option<i64>, Option<i64>, Option<i64>)>(
            sql::SELECT_DECLARED,
        )
        .bind(product)
        .bind(source_name)
        .bind(arch)
        .fetch_optional(&self.pool)
        .await
        .db_ctx("find declared requirements")?;
        Ok(row.and_then(|(arch, mem, ncpu, disk)| {
            (mem.is_some() || ncpu.is_some() || disk.is_some()).then_some(DeclaredRequirements {
                arch,
                min_mem_kb: mem,
                min_ncpu: ncpu,
                min_disk_kb: disk,
            })
        }))
    }

    /// 单键画像行读取（供 API/UI 详情）。
    pub async fn get_profile(
        &self,
        product: &str,
        source_name: &str,
        arch: &str,
    ) -> crate::Result<Option<PackageResourceProfile>> {
        let sql_text = format!(
            "SELECT {} FROM package_resource_profiles \
             WHERE product = $1 AND source_name = $2 AND arch = $3",
            sql::PROFILE_COLUMNS
        );
        let row = sqlx::query(&sql_text)
            .bind(product)
            .bind(source_name)
            .bind(arch)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("get resource profile")?;
        row.map(|r| profile_from_row(&r)).transpose()
    }

    /// 产品内画像行全列列举（按键升序，确定性、方言中立；资源画像卡的 top-N
    /// 与分页由调用方裁剪）。
    pub async fn list_profiles_by_product(
        &self,
        product: &str,
    ) -> crate::Result<Vec<PackageResourceProfile>> {
        let sql_text = format!(
            "SELECT {} FROM package_resource_profiles \
             WHERE product = $1 ORDER BY source_name, arch",
            sql::PROFILE_COLUMNS
        );
        let rows = sqlx::query(&sql_text)
            .bind(product)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list resource profiles")?;
        rows.iter().map(profile_from_row).collect()
    }

    /// 画像行总数（metrics gauge 用；COUNT(*) 全表口径，声明/学习面不分）。
    pub async fn count_profiles(&self) -> crate::Result<i64> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM package_resource_profiles")
            .fetch_one(&self.pool)
            .await
            .db_ctx("count resource profiles")?;
        Ok(n)
    }

    /// 批量读学习面权重四元组（三维键精确匹配，调度器 Σ 水位的回源点；
    /// 禁调度热路径逐键 N+1）。键无行 / 学习样本为 0 的行不在返回 map 中
    ///（消费侧按"未知权重"降级）。空键集不发 SQL。
    pub async fn learned_weights_batch(
        &self,
        keys: &[(String, String, String)],
    ) -> crate::Result<std::collections::HashMap<(String, String, String), LearnedWeightSnapshot>>
    {
        use std::collections::HashMap;
        let mut out: HashMap<(String, String, String), LearnedWeightSnapshot> = HashMap::new();
        if keys.is_empty() {
            return Ok(out);
        }
        let tuples = crate::state::db::row_value_in_placeholders3(1, keys.len())?;
        let sql_text = format!(
            "SELECT product, source_name, arch, learned_ema_mem_kb, learned_max_mem_kb, \
                    learned_ema_ncpu, learned_sample_ncpu, learned_censored \
             FROM package_resource_profiles \
             WHERE (product, source_name, arch) IN {tuples}"
        );
        let mut query = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                Option<i64>,
                Option<i64>,
                Option<f64>,
                Option<i64>,
                i64,
            ),
        >(&sql_text);
        for (product, source, arch) in keys {
            query = query.bind(product).bind(source).bind(arch);
        }
        let rows = query
            .fetch_all(&self.pool)
            .await
            .db_ctx("learned weights batch")?;
        for (product, source, arch, ema_mem, max_mem, ema_ncpu, sample_ncpu, censored) in rows {
            out.insert(
                (product, source, arch),
                LearnedWeightSnapshot {
                    ema_mem_kb: ema_mem,
                    max_mem_kb: max_mem,
                    ema_ncpu,
                    sample_ncpu,
                    censored: censored != 0,
                },
            );
        }
        Ok(out)
    }

    /// 批量解析声明面（调度器硬下限的逐维回退源）：键
    /// (product, source_name, arch)，精确 arch 行优先、未命中回退 'any' 哨兵、
    /// 声明三维全空视为未声明（继续回退）——与
    /// [`Self::find_declared_requirements`] 单键语义同源，禁调度热路径 N+1。
    /// 未命中声明的键不在返回 map 中。空键集不发 SQL。
    pub async fn declared_requirements_batch(
        &self,
        keys: &[(String, String, String)],
    ) -> crate::Result<std::collections::HashMap<(String, String, String), DeclaredRequirements>>
    {
        use std::collections::HashMap;
        let mut out: HashMap<(String, String, String), DeclaredRequirements> = HashMap::new();
        if keys.is_empty() {
            return Ok(out);
        }
        let tuples = crate::state::db::row_value_in_placeholders(1, keys.len())?;
        let sql_text = format!(
            "SELECT product, source_name, arch, declared_min_mem_kb, declared_min_ncpu, declared_min_disk_kb \
             FROM package_resource_profiles \
             WHERE (product, source_name) IN {tuples}"
        );
        let mut query = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                Option<i64>,
                Option<i64>,
                Option<i64>,
            ),
        >(&sql_text);
        for (product, source, _) in keys {
            query = query.bind(product).bind(source);
        }
        let rows = query
            .fetch_all(&self.pool)
            .await
            .db_ctx("declared requirements batch")?;

        // (product, source_name) → 各 arch 行（含全空声明行：精确行"存在但
        // 未声明"不阻塞 'any' 回退，语义同 declared_for_arch）。
        let mut by_pair: HashMap<(String, String), Vec<DeclaredRow>> = HashMap::new();
        for (product, source, arch, mem, ncpu, disk) in rows {
            by_pair
                .entry((product, source))
                .or_default()
                .push(DeclaredRow {
                    arch,
                    min_mem_kb: mem,
                    min_ncpu: ncpu,
                    min_disk_kb: disk,
                });
        }
        for (product, source, arch) in keys {
            let Some(rows) = by_pair.get(&(product.clone(), source.clone())) else {
                continue;
            };
            let hit = rows
                .iter()
                .find(|r| r.arch == *arch && r.has_any())
                .or_else(|| rows.iter().find(|r| r.arch == "any" && r.has_any()));
            if let Some(row) = hit {
                out.insert(
                    (product.clone(), source.clone(), arch.clone()),
                    DeclaredRequirements {
                        arch: row.arch.clone(),
                        min_mem_kb: row.min_mem_kb,
                        min_ncpu: row.min_ncpu,
                        min_disk_kb: row.min_disk_kb,
                    },
                );
            }
        }
        Ok(out)
    }

    /// 回填播种（权重源切换前置，一次性幂等）：按
    /// (product, builds.name, arch) 取最近 5 条 succeeded 峰值样本
    ///（peak_rss_kb 非空；arch 空串/NULL 的旧行跳过），**时间正序**复用
    /// `next_learned_state` 折算播种（与在线逐单折算逐位一致，权重源切换
    /// 连续）。
    ///
    /// 轻包门槛（`min_peak_rss_kb`）按**组级**套用：窗口内至少一条样本达到
    /// 门槛才播种。全轻窗口的键在线学习永不建行/永不刷新，播种它只会造出
    /// 冻结在旧 EMA 的僵尸权重；重包窗口则整窗折叠、逐样本不过滤，保留与
    /// 既有权重源逐位一致的切换连续性。
    ///
    /// 只填 `learned_samples = 0` 的行：条件 upsert 原子判空（并发终态上报
    /// 先建行时本播种让位），绝不覆盖已有学习；`learned_backend` 恒 NULL
    ///（无既立口径，首个真实样本按 sticky 规则落口径、保留播种值）。不写
    /// declared。app_meta 幂等标记与"失败不阻断启动"策略在 server 侧。
    pub async fn backfill_learned_from_builds(
        &self,
        min_peak_rss_kb: Option<i64>,
        headroom: f64,
    ) -> crate::Result<ProfileBackfillStats> {
        // headroom 是删失抬升乘数：<1 或非有限违背只抬不降不变量（成功通道
        // 虽不消费，入参校验与 apply_learning_sample 同口径）。
        if !headroom.is_finite() || headroom < 1.0 {
            return Err(crate::error::CrbsError::ValidationFailed {
                message: format!(
                    "profile learning headroom must be a finite value >= 1.0, got {headroom}"
                ),
            });
        }
        let rows = sqlx::query_as::<_, (String, String, String, i64, Option<f64>, Option<i64>)>(
            sql::SELECT_BACKFILL_SAMPLES,
        )
        .fetch_all(&self.pool)
        .await
        .db_ctx("select backfill sample window")?;

        // SQL 已按 (product, source_name, arch, rn DESC) 排序：rn=1 最新，
        // 倒序遍历即时间正序，组内顺序直接喂折算链。
        let mut grouped: BackfillSampleGroups = std::collections::HashMap::new();
        let mut order: Vec<(String, String, String)> = Vec::new();
        for (product, source, arch, peak_rss_kb, cpu_p90, sample_ncpu) in rows {
            let key = (product, source, arch);
            if !grouped.contains_key(&key) {
                order.push(key.clone());
            }
            grouped
                .entry(key)
                .or_default()
                .push((peak_rss_kb, cpu_p90, sample_ncpu));
        }
        let mut stats = ProfileBackfillStats::default();
        for key in &order {
            let Some(samples) = grouped.get(key) else {
                continue;
            };
            if !backfill_group_meets_min_peak(samples, min_peak_rss_kb) {
                stats.skipped_light += 1;
                continue;
            }
            let Some(state) = fold_backfill_samples(
                samples,
                &(key.0.as_str(), key.1.as_str(), key.2.as_str()),
                headroom,
            ) else {
                continue;
            };
            let ema_ncpu = state.ema_ncpu.map(|v| v.to_string());
            let max_ncpu = state.max_ncpu.map(|v| v.to_string());
            let result = sqlx::query(&sql::upsert_backfill_learned(self.dialect))
                .bind(&key.0)
                .bind(&key.1)
                .bind(&key.2)
                .bind(state.ema_mem_kb)
                .bind(state.max_mem_kb)
                .bind(ema_ncpu)
                .bind(max_ncpu)
                .bind(state.samples)
                .bind(state.sample_ncpu)
                .execute(&self.pool)
                .await
                .db_ctx("backfill profile learned state")?;
            if result.rows_affected() > 0 {
                stats.seeded += 1;
            } else {
                stats.skipped_occupied += 1;
            }
        }
        Ok(stats)
    }
}
