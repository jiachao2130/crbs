// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 复现率统计查询（看板与指标）。
//!
//! 分母口径（单一事实源见 [`super::reproducibility`] 模块头）：分母 = `same` + `diff` + `build_failed`
//!（包自身问题）；`dep_unavailable` / `infra_error` 是基础设施问题，单独统计不进分母。本模块只出
//! 原子计数（verdict × kind / verdict × product / 时间桶），rate 等派生指标由看板计算。
//!
//! kind 口径：看板/指标查询统一只计 `kind='replay'`（逐构建重放比对，复现率的
//! 定义面）；`cross_arch_noarch` 是 noarch 发布漂移的独立观测面，行留 DB 但不入
//! 板、不入指标。
//!
//! 窗口修剪：retention 行级删除超期 builds 后经 `source_build_id` ON DELETE CASCADE
//! 级联删其 `build_reproducibility` 行（见 `state/retention.rs`、schema.sql 表注）；
//! `days` 窗口越过保留期时早期数据已被修剪，统计是"窗口内现存行"而非"曾发生事件"口径。
//!
//! 双方言策略：时间过滤不用方言日期函数——`compared_at` 是 UTC 墙钟 TEXT（字典序
//! 即时间序），cutoff 由 Rust 按 [`crate::util::DB_TIME_FMT`] 生成后 TEXT 绑定比较
//! （与写入同帧）；分桶拉原始行 Rust 侧做（行数 = 比对次数，受抽样/后台档约束量级
//! 很小，量级上去再下沉 SQL 窗口函数）。可见性复用 `StateStore::apply_visible_products`
//! （未限定 `product` 列 JOIN 后唯一属 `builds`，两方言解析一致）。

use std::collections::BTreeMap;

use sqlx::Row;

use super::reproducibility::KIND_REPLAY;
use crate::error::{CrbsError, DbResultExt};
use crate::state::StateStore;
use crate::util::{parse_db_time, DB_TIME_FMT};

/// 统计窗口上限（天）：`days` 超限报 ValidationFailed 而非静默放大查询。
pub const MAX_STATS_DAYS: i64 = 3650;

/// kind × verdict 聚合行（[`StateStore::reproducibility_verdict_counts`]）。
/// 看板口径下 `kind` 恒为 `replay`（查询已过滤）；结构保留供 API `by_kind` 兼容。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct KindVerdictCount {
    pub kind: String,
    pub verdict: String,
    pub count: i64,
}

/// product × verdict 聚合行（[`StateStore::reproducibility_counts_by_product`]）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProductVerdictCount {
    pub product: String,
    pub verdict: String,
    pub count: i64,
}

/// 复现记录 drill-down 原始行（kind='replay'，[`StateStore::reproducibility_replay_groups`]）：
/// 比对行 + 双侧 builds 展示列——product / pkg_name / source_task_id 取 source 构建，
/// 重放侧只取 task_id（group key）与 arch。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReproReplayRow {
    pub id: i64,
    pub source_build_id: i64,
    pub replay_build_id: Option<i64>,
    pub verdict: String,
    pub detail_json: Option<String>,
    pub compared_at: String,
    pub product: String,
    pub pkg_name: String,
    pub source_task_id: Option<i64>,
    pub replay_task_id: Option<i64>,
    pub replay_arch: Option<String>,
}

/// 复现记录第一级分组：一个重放任务一组（replay 构建已删的孤儿行按源构建各成
/// 一组，见 [`fold_replay_groups`]；UI 复现记录列表与 stats API `replays` 共用形态）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReproReplayGroup {
    /// group key：重放任务的 task_id（None = replay 构建已删的孤儿组，UI 显示 "—"）。
    pub replay_task_id: Option<i64>,
    pub source_task_id: Option<i64>,
    pub product: String,
    /// 组内首包名（API 冗余展示列；组头展示用全量去重列表 pkg_names）。
    pub pkg_name: String,
    /// 组内去重源包名（保序 = 组内首现序；多包复现任务不丢包名）。
    pub pkg_names: Vec<String>,
    /// 组内最近比对时间（UTC TEXT，字典序即时间序）。
    pub latest_compared_at: String,
    /// 覆盖架构（组内去重升序；无 arch 行跳过）。
    pub arches: Vec<String>,
    /// verdict → 计数（组内构建对）。
    pub verdicts: BTreeMap<String, i64>,
    /// 构建对（arch 升序、None 侧垫底；全一致组 detail_json 已剥离，见 [`fold_replay_groups`]）。
    pub pairs: Vec<ReproReplayRow>,
}

impl ReproReplayGroup {
    /// 全一致组判定：组内全部构建对 verdict=same（不可展开判定、展开分组的
    /// 共用谓词；fold 剥离发生在组构造前，持同一谓词的行内实现）。
    pub fn all_same(&self) -> bool {
        self.pairs.iter().all(|p| p.verdict == "same")
    }
}

/// 时间序列桶：只含有数据的桶（空档由看板侧补零），桶内 verdict 计数缺键按 0 读。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReproSeriesBucket {
    pub bucket: String,
    /// verdict → 计数（BTreeMap 保证 JSON 键序稳定）。
    pub counts: BTreeMap<String, i64>,
}

/// `days` 参数 → WHERE cutoff 绑定值：`None` / `Some(0)` = 全部时间；`Some(n)` =
/// `compared_at >= (now - n days)`（UTC TEXT）；负数与超 [`MAX_STATS_DAYS`] 报 ValidationFailed。
pub(crate) fn repro_stats_cutoff(days: Option<i64>) -> crate::Result<Option<String>> {
    let Some(days) = days else {
        return Ok(None);
    };
    if !(0..=MAX_STATS_DAYS).contains(&days) {
        return Err(CrbsError::ValidationFailed {
            message: format!("days must be within 0..={MAX_STATS_DAYS}"),
        });
    }
    if days == 0 {
        return Ok(None);
    }
    let cutoff = chrono::Utc::now() - chrono::TimeDelta::days(days);
    Ok(Some(cutoff.format(DB_TIME_FMT).to_string()))
}

/// replay 口径查询的前置 scope：cutoff + kind 过滤 + 产品可见性，产出绑定
/// 序列与 WHERE 文本（双方言占位符拼装集中在 [`scoped_where`]）。四个 stats
/// 查询共用同一起点。
fn replay_scope(
    visible_products: Option<&[String]>,
    days: Option<i64>,
) -> crate::Result<(Vec<String>, String)> {
    let cutoff = repro_stats_cutoff(days)?;
    let mut binds: Vec<String> = Vec::new();
    let where_sql = scoped_where(
        vec![format!("r.kind = '{}'", KIND_REPLAY)],
        &mut binds,
        cutoff.as_deref(),
        visible_products,
    )?;
    Ok((binds, where_sql))
}

/// 拼接可见性过滤后的公共 WHERE（cutoff 绑定在前、可见性占位符接续编号）。
fn scoped_where(
    mut parts: Vec<String>,
    binds: &mut Vec<String>,
    cutoff: Option<&str>,
    visible: Option<&[String]>,
) -> crate::Result<String> {
    if let Some(c) = cutoff {
        crate::state::db::push_filter(&mut parts, binds, "r.compared_at >= $N", c.to_string());
    }
    let joined = if parts.is_empty() {
        "1=1".to_string()
    } else {
        parts.join(" AND ")
    };
    // apply_visible_products 生成未限定 product 谓词——JOIN 后该列唯一属 builds（r 表无 product 列）。
    let visible_owned = visible.map(<[String]>::to_vec);
    StateStore::apply_visible_products(joined, binds, visible_owned.as_ref())
}

/// 共用 FROM 片段：JOIN 取 builds.product 供可见性过滤（按主键连接，不丢行）。
const FROM_JOIN_BUILDS: &str =
    "FROM build_reproducibility r JOIN builds b ON b.id = r.source_build_id";

/// verdict 聚合行折叠为 verdict → 计数表（跨 kind 合计；`replay_rows` 口径下
/// kind 已过滤为单值，合计即 replay 口径）。
pub fn fold_verdict_totals(rows: &[KindVerdictCount]) -> BTreeMap<String, i64> {
    let mut totals = BTreeMap::new();
    for row in rows {
        *totals.entry(row.verdict.clone()).or_insert(0) += row.count;
    }
    totals
}

/// product × verdict 聚合行折叠为 product → verdict → 计数嵌套表（看板取数形态）。
pub fn fold_product_counts(
    rows: &[ProductVerdictCount],
) -> BTreeMap<String, BTreeMap<String, i64>> {
    let mut by_product: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
    for row in rows {
        *by_product
            .entry(row.product.clone())
            .or_default()
            .entry(row.verdict.clone())
            .or_insert(0) += row.count;
    }
    by_product
}

/// 组键复合：replay 侧 task_id 优先，孤儿行按源构建回落（变体即谓词）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ReplayGroupKey {
    /// 重放任务 task_id（replay 构建存活）。
    Replay(i64),
    /// source_build_id（replay_task_id = NULL 的孤儿行）。
    Source(i64),
}

/// 复现记录行折叠为组。组键复合语义：`replay_task_id` 有值按重放任务一组；
/// replay 构建被 retention 删除后该列为 NULL 的孤儿行按 `source_build_id`
/// 各自成组——并入共享 NULL 键会把不相关 source 的组头与 verdict 汇总跨源
/// 串扰。组序 = 组内最近比对时间倒序；构建对序 = arch 升序（None 垫底）。
/// `limit` 截断组数（看板显示预算，截断在排序后生效）。不变量：全一致组
///（组内全部 verdict=same）剥离 detail_json——组不可展开，明细载荷不出 state 层。
pub fn fold_replay_groups(rows: &[ReproReplayRow], limit: usize) -> Vec<ReproReplayGroup> {
    let mut order: Vec<ReplayGroupKey> = Vec::new();
    let mut grouped: BTreeMap<ReplayGroupKey, Vec<&ReproReplayRow>> = BTreeMap::new();
    for row in rows {
        let key = match row.replay_task_id {
            Some(t) => ReplayGroupKey::Replay(t),
            None => ReplayGroupKey::Source(row.source_build_id),
        };
        if !grouped.contains_key(&key) {
            order.push(key.clone());
        }
        grouped.entry(key).or_default().push(row);
    }
    let mut groups: Vec<ReproReplayGroup> = order
        .into_iter()
        .filter_map(|key| {
            let mut members = grouped.remove(&key)?;
            members.sort_by(|a, b| {
                a.replay_arch
                    .is_none()
                    .cmp(&b.replay_arch.is_none())
                    .then_with(|| a.replay_arch.cmp(&b.replay_arch))
                    .then_with(|| a.id.cmp(&b.id))
            });
            let pairs: Vec<ReproReplayRow> = members.into_iter().cloned().collect();
            let latest_compared_at = pairs
                .iter()
                .map(|p| p.compared_at.as_str())
                .max()
                .unwrap_or_default()
                .to_string();
            let mut arches: Vec<String> =
                pairs.iter().filter_map(|p| p.replay_arch.clone()).collect();
            arches.sort();
            arches.dedup();
            let mut verdicts: BTreeMap<String, i64> = BTreeMap::new();
            let mut pkg_names: Vec<String> = Vec::new();
            for p in &pairs {
                *verdicts.entry(p.verdict.clone()).or_insert(0) += 1;
                if !pkg_names.contains(&p.pkg_name) {
                    pkg_names.push(p.pkg_name.clone());
                }
            }
            // 全一致组不可展开：明细载荷就地剥离（DB 原行不受影响）。
            let all_same = pairs.iter().all(|p| p.verdict == "same");
            let mut pairs = pairs;
            if all_same {
                for p in &mut pairs {
                    p.detail_json = None;
                }
            }
            let head = pairs.first()?;
            Some(ReproReplayGroup {
                replay_task_id: match key {
                    ReplayGroupKey::Replay(t) => Some(t),
                    ReplayGroupKey::Source(_) => None,
                },
                source_task_id: head.source_task_id,
                product: head.product.clone(),
                pkg_name: head.pkg_name.clone(),
                pkg_names,
                latest_compared_at,
                arches,
                verdicts,
                pairs,
            })
        })
        .collect();
    groups.sort_by(|a, b| b.latest_compared_at.cmp(&a.latest_compared_at));
    groups.truncate(limit);
    groups
}

/// 桶键：`compared_at` → UTC 日桶（`YYYY-MM-DD`）；非 DB 帧返回 None（该行仅从时间序列缺席，verdict 合计不受影响）。
pub(crate) fn series_bucket_key(compared_at: &str) -> Option<String> {
    let t = parse_db_time(compared_at)?;
    Some(t.format("%Y-%m-%d").to_string())
}

impl StateStore {
    /// replay 口径 verdict 计数（看板/指标统一只计 `kind='replay'`；
    /// `cross_arch_noarch` 观测行不入板）。`visible_products` 三态语义（None = bypass /
    /// Some = 白名单 + 孤儿豁免）同 `apply_visible_products`；`days` 见 `repro_stats_cutoff`；
    /// verdict 全集由调用方按 ALL_VERDICTS 补零。
    pub async fn reproducibility_verdict_counts(
        &self,
        visible_products: Option<&[String]>,
        days: Option<i64>,
    ) -> crate::Result<Vec<KindVerdictCount>> {
        let (binds, where_sql) = replay_scope(visible_products, days)?;
        let sql = format!(
            "SELECT r.kind AS kind, r.verdict AS verdict, COUNT(*) AS cnt \
             {FROM_JOIN_BUILDS} WHERE {where_sql} GROUP BY r.kind, r.verdict \
             ORDER BY r.kind, r.verdict"
        );
        let mut q = sqlx::query(&sql);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .db_ctx("reproducibility verdict counts")?;
        Ok(rows
            .into_iter()
            .map(|r| KindVerdictCount {
                kind: r.get("kind"),
                verdict: r.get("verdict"),
                count: r.get("cnt"),
            })
            .collect())
    }

    /// product × verdict 计数（按产品小表；产品取 source build 的 product；replay 口径）。
    pub async fn reproducibility_counts_by_product(
        &self,
        visible_products: Option<&[String]>,
        days: Option<i64>,
    ) -> crate::Result<Vec<ProductVerdictCount>> {
        let (binds, where_sql) = replay_scope(visible_products, days)?;
        let sql = format!(
            "SELECT b.product AS product, r.verdict AS verdict, COUNT(*) AS cnt \
             {FROM_JOIN_BUILDS} WHERE {where_sql} GROUP BY b.product, r.verdict \
             ORDER BY b.product, r.verdict"
        );
        let mut q = sqlx::query(&sql);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .db_ctx("reproducibility counts by product")?;
        Ok(rows
            .into_iter()
            .map(|r| ProductVerdictCount {
                product: r.get("product"),
                verdict: r.get("verdict"),
                count: r.get("cnt"),
            })
            .collect())
    }

    /// 时间序列：拉窗口内原始行在 Rust 侧按自然日分桶（双方言策略见模块头；replay 口径）。
    pub async fn reproducibility_series(
        &self,
        visible_products: Option<&[String]>,
        days: Option<i64>,
    ) -> crate::Result<Vec<ReproSeriesBucket>> {
        let (binds, where_sql) = replay_scope(visible_products, days)?;
        let sql = format!(
            "SELECT r.verdict AS verdict, r.compared_at AS compared_at \
             {FROM_JOIN_BUILDS} WHERE {where_sql}"
        );
        let mut q = sqlx::query(&sql);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .db_ctx("reproducibility series raw rows")?;

        let mut buckets: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
        for r in rows {
            let verdict: String = r.get("verdict");
            let compared_at: String = r.get("compared_at");
            let Some(key) = series_bucket_key(&compared_at) else {
                continue;
            };
            *buckets.entry(key).or_default().entry(verdict).or_insert(0) += 1;
        }
        Ok(buckets
            .into_iter()
            .map(|(bucket, counts)| ReproSeriesBucket { bucket, counts })
            .collect())
    }

    /// 复现记录 drill-down 分组（kind='replay'，两段式限宽拉取）：第一段轻量投影
    ///（不含 detail_json）取窗口内行，[`fold_replay_groups`] 选组截 `limit` 后第二段
    /// 仅按选中非全一致组的比对行 id 取 detail_json 回填——窗口全量 detail 载荷不出
    /// 库；全一致组 detail 按不变量不出 state 层，不进第二段 id 集。可见性 / days 语义
    /// 同聚合查询。第二段按 id 主键直取（id 集已过第一段可见性过滤），两段间隙的
    /// retention 删除表现为该行缺 detail，不回填不报错。
    pub async fn reproducibility_replay_groups(
        &self,
        visible_products: Option<&[String]>,
        days: Option<i64>,
        limit: usize,
    ) -> crate::Result<Vec<ReproReplayGroup>> {
        let (binds, where_sql) = replay_scope(visible_products, days)?;
        // 第一段轻量投影：`product` / `pkg_name` 列唯一属 source 构建表 b，保住
        // apply_visible_products 未限定列名的双方言不变量；重放侧以投影子查询 JOIN。
        let sql = format!(
            "SELECT r.id, r.source_build_id, r.replay_build_id, r.verdict, r.compared_at, \
                    b.product AS product, b.pkg_name AS pkg_name, \
                    b.task_id AS source_task_id, rb.task_id AS replay_task_id, \
                    rb.arch AS replay_arch \
             FROM build_reproducibility r \
             JOIN builds b ON b.id = r.source_build_id \
             LEFT JOIN (SELECT id, task_id, arch FROM builds) rb ON rb.id = r.replay_build_id \
             WHERE {where_sql} ORDER BY r.id DESC"
        );
        let mut q = sqlx::query(&sql);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .db_ctx("reproducibility replay light rows")?;
        let light: Vec<ReproReplayRow> = rows
            .into_iter()
            .map(|r| ReproReplayRow {
                id: r.get("id"),
                source_build_id: r.get("source_build_id"),
                replay_build_id: r.get("replay_build_id"),
                verdict: r.get("verdict"),
                detail_json: None,
                compared_at: r.get("compared_at"),
                product: r.get("product"),
                pkg_name: r.get("pkg_name"),
                source_task_id: r.get("source_task_id"),
                replay_task_id: r.get("replay_task_id"),
                replay_arch: r.get("replay_arch"),
            })
            .collect();
        let mut groups = fold_replay_groups(&light, limit);
        let detail_ids: Vec<i64> = groups
            .iter()
            .filter(|g| !g.all_same())
            .flat_map(|g| g.pairs.iter().map(|p| p.id))
            .collect();
        if detail_ids.is_empty() {
            return Ok(groups);
        }
        // 第二段：detail 仅随选中 id 出库（双方言编号占位符，复用 db 层守卫）。
        let placeholders = crate::state::db::in_placeholders(1, detail_ids.len())?;
        let sql = format!(
            "SELECT r.id, r.detail_json FROM build_reproducibility r \
             WHERE r.id IN ({placeholders})"
        );
        let mut q = sqlx::query(&sql);
        for id in &detail_ids {
            q = q.bind(id);
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .db_ctx("reproducibility replay detail backfill")?;
        let mut details: BTreeMap<i64, Option<String>> = rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<i64, _>("id"),
                    r.get::<Option<String>, _>("detail_json"),
                )
            })
            .collect();
        for g in &mut groups {
            if g.all_same() {
                continue;
            }
            for p in &mut g.pairs {
                if let Some(d) = details.remove(&p.id) {
                    p.detail_json = d;
                }
            }
        }
        Ok(groups)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_state::create_test_store;

    /// fixture：建 task + builds + 直接 INSERT build_reproducibility 行
    ///（显式 compared_at 覆盖窗口过滤与分桶；绕过 insert_reproducibility 默认 now——统计消费原始行）。
    async fn seed(store: &StateStore, rows: &[(&str, i64, Option<i64>, &str, String)]) {
        sqlx::query(
            "INSERT INTO tasks (product, pkg_name, \"user\", phase) VALUES ('t', 'p', '', 'succeeded')",
        )
        .execute(store.pool())
        .await
        .unwrap();
        for id in 1..=4 {
            sqlx::query(&format!(
                "INSERT INTO builds (id, product, pkg_name, phase, backend, \"user\", task_id) \
                 VALUES ({id}, 'prod', 'p-1.0-{id}', 'succeeded', 'chroot', '', 1)"
            ))
            .execute(store.pool())
            .await
            .unwrap();
        }
        for (kind, source, replay, verdict, at) in rows {
            sqlx::query(
                "INSERT INTO build_reproducibility (kind, source_build_id, replay_build_id, verdict, compared_at) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(kind)
            .bind(source)
            .bind(replay)
            .bind(verdict)
            .bind(at)
            .execute(store.pool())
            .await
            .unwrap();
        }
    }

    fn at_days_ago(days: i64, hour: u32) -> String {
        let day = (chrono::Utc::now() - chrono::TimeDelta::days(days)).format("%Y-%m-%d");
        format!("{day} {hour:02}:00:00")
    }

    #[test]
    fn fold_and_bucket_key_helpers() {
        let rows = vec![
            KindVerdictCount {
                kind: "replay".into(),
                verdict: "same".into(),
                count: 2,
            },
            KindVerdictCount {
                kind: "replay".into(),
                verdict: "diff".into(),
                count: 1,
            },
            KindVerdictCount {
                kind: "cross_arch_noarch".into(),
                verdict: "same".into(),
                count: 3,
            },
        ];
        let totals = fold_verdict_totals(&rows);
        assert_eq!(totals.get("same"), Some(&5));
        assert_eq!(totals.get("diff"), Some(&1));

        let by_product = fold_product_counts(&[
            ProductVerdictCount {
                product: "a".into(),
                verdict: "same".into(),
                count: 1,
            },
            ProductVerdictCount {
                product: "a".into(),
                verdict: "same".into(),
                count: 2,
            },
        ]);
        assert_eq!(by_product["a"]["same"], 3);

        assert_eq!(
            series_bucket_key("2026-01-01 00:00:00"),
            Some("2026-01-01".into())
        );
        assert_eq!(series_bucket_key("nope"), None);
    }

    /// 孤儿行组键回落（retention 删 replay 构建后 replay_task_id = NULL）：不同
    /// source 的孤儿行各成一组（组头各归各源、verdict 不跨源合并），同源多行
    /// 仍归一组；孤儿组 replay_task_id = None。
    #[test]
    fn fold_replay_groups_orphan_rows_fall_back_to_source_key() {
        // compared_at 用 id 垫日期（id ≤ 9 保证两位日），组序 = 最近比对倒序可预期。
        let row = |id: i64, source: i64, product: &str, pkg: &str, task: i64, verdict: &str| {
            ReproReplayRow {
                id,
                source_build_id: source,
                replay_build_id: None,
                verdict: verdict.into(),
                detail_json: None,
                compared_at: format!("2026-01-0{id} 00:00:00"),
                product: product.into(),
                pkg_name: pkg.into(),
                source_task_id: Some(task),
                replay_task_id: None,
                replay_arch: Some("x86_64".into()),
            }
        };
        let rows = vec![
            row(1, 11, "pa", "pkg-a", 101, "diff"),
            row(2, 22, "pb", "pkg-b", 202, "same"),
            row(3, 11, "pa", "pkg-a", 101, "same"),
            row(4, 33, "pc", "pkg-c", 303, "diff"),
        ];
        let groups = fold_replay_groups(&rows, 10);
        assert_eq!(
            groups.len(),
            3,
            "orphan rows of unrelated sources must not merge: {groups:?}"
        );
        assert!(groups.iter().all(|g| g.replay_task_id.is_none()));
        // 组序 = 最近比对倒序：source 33（id 4）→ 11（id 3）→ 22（id 2）。
        assert_eq!(groups[0].pairs[0].source_build_id, 33);
        assert_eq!(groups[0].product, "pc");
        assert_eq!(groups[0].source_task_id, Some(303));
        assert_eq!(groups[0].pkg_names, vec!["pkg-c".to_string()]);
        assert_eq!(groups[0].verdicts.get("diff"), Some(&1));
        // 同源两行归一组，组头取该源自己的列。
        assert_eq!(groups[1].product, "pa");
        assert_eq!(groups[1].source_task_id, Some(101));
        assert_eq!(groups[1].pkg_names, vec!["pkg-a".to_string()]);
        assert_eq!(groups[1].verdicts.get("diff"), Some(&1));
        assert_eq!(groups[1].verdicts.get("same"), Some(&1));
        assert_eq!(groups[1].pairs.len(), 2);
        assert_eq!(groups[2].product, "pb");
        assert_eq!(groups[2].verdicts.get("same"), Some(&1));
    }

    #[test]
    fn cutoff_validation() {
        assert_eq!(repro_stats_cutoff(None).unwrap(), None);
        assert_eq!(repro_stats_cutoff(Some(0)).unwrap(), None);
        assert!(repro_stats_cutoff(Some(30)).unwrap().is_some());
        assert!(repro_stats_cutoff(Some(-1)).is_err());
        assert!(repro_stats_cutoff(Some(MAX_STATS_DAYS + 1)).is_err());
    }

    /// 聚合/分桶/占比口径 roundtrip：verdict 计数、按产品、日桶、days 窗口；
    /// cross_arch_noarch 行留 DB 但不入板（kind='replay' 过滤）。
    #[tokio::test]
    async fn reproducibility_stats_aggregation_roundtrip() {
        let (store, _tmp) = create_test_store().await;
        // fixture 8 行；day-2 两行是旧窗口（days=2）边界敏感行，40 天前 1 行仅全部时间窗口可见。
        let rows = [
            ("replay", 1, Some(2), "same", at_days_ago(0, 10)),
            ("replay", 1, Some(2), "diff", at_days_ago(1, 10)),
            ("replay", 3, Some(4), "same", at_days_ago(1, 11)),
            ("replay", 1, Some(2), "same", at_days_ago(2, 10)),
            ("replay", 3, Some(4), "build_failed", at_days_ago(2, 11)),
            ("replay", 1, Some(2), "dep_unavailable", at_days_ago(0, 11)),
            ("cross_arch_noarch", 1, None, "same", at_days_ago(0, 12)),
            ("replay", 3, Some(4), "infra_error", at_days_ago(40, 10)),
        ];
        seed(&store, &rows).await;

        let counts = store
            .reproducibility_verdict_counts(None, None)
            .await
            .unwrap();
        let totals = fold_verdict_totals(&counts);
        assert_eq!(totals.get("same"), Some(&3), "cross_arch 行不入板");
        assert_eq!(totals.get("diff"), Some(&1));
        assert_eq!(totals.get("build_failed"), Some(&1));
        assert_eq!(totals.get("dep_unavailable"), Some(&1));
        assert_eq!(totals.get("infra_error"), Some(&1));
        assert!(
            counts.iter().all(|c| c.kind == "replay"),
            "board scope is kind='replay' only: {counts:?}"
        );

        // 近 3 天窗口（取 3 而非 2：cutoff 带当前时刻，day-2 行在"当前时刻早于行内
        // 10:00"的运行日会掉出 2 天窗，3 天窗对时刻无关）：infra_error（40 天前）不在计数内。
        let recent = store
            .reproducibility_verdict_counts(None, Some(3))
            .await
            .unwrap();
        let recent_totals = fold_verdict_totals(&recent);
        assert_eq!(recent_totals.values().sum::<i64>(), 6);
        assert!(!recent_totals.contains_key("infra_error"));

        let by_product = store
            .reproducibility_counts_by_product(None, None)
            .await
            .unwrap();
        let folded = fold_product_counts(&by_product);
        assert_eq!(folded["prod"]["same"], 3);
        assert_eq!(folded["prod"]["diff"], 1);
        assert_eq!(folded["prod"]["dep_unavailable"], 1);
        assert_eq!(by_product.len(), 5, "product × verdict 各一行");

        let daily = store.reproducibility_series(None, None).await.unwrap();
        assert_eq!(daily.len(), 4, "3 recent days + 1 old day: {daily:?}");
        // 桶按时间升序（BTreeMap 迭代序），末桶 = 最近一天（day-0 共 2 行 replay）。
        let recent_day_total: i64 = daily
            .last()
            .map(|b| b.counts.values().sum::<i64>())
            .unwrap();
        assert_eq!(recent_day_total, 2);
    }

    /// 复现记录分组查询（两段式）+ [`fold_replay_groups`] 契约：kind='replay'
    /// 过滤（cross_arch 行不出现）、group key = 重放任务 task_id、组序 = 组内最近
    /// 比对倒序、构建对序 = arch 升序、verdict/架构/包名聚合、全一致组剥离
    /// detail_json（不可展开组不出明细载荷，组序无关行序）、limit 截断在排序后
    /// 生效、detail 仅随选中展开组回填（超限组整体不出现）。
    #[tokio::test]
    async fn replay_rows_grouping_contract() {
        let (store, _tmp) = create_test_store().await;
        // task 1 = 源任务（builds 1/3/5），task 2/3 = 两个重放任务（builds 2/4/6）。
        for _ in 0..3 {
            sqlx::query(
                "INSERT INTO tasks (product, pkg_name, \"user\", phase) \
                 VALUES ('t', 'p', '', 'succeeded')",
            )
            .execute(store.pool())
            .await
            .unwrap();
        }
        for (id, task, arch) in [
            (1, 1, "x86_64"),
            (2, 2, "x86_64"),
            (3, 1, "aarch64"),
            (4, 3, "aarch64"),
            (5, 1, "x86_64"),
            (6, 3, "x86_64"),
        ] {
            sqlx::query(&format!(
                "INSERT INTO builds (id, product, pkg_name, phase, backend, \"user\", task_id, arch) \
                 VALUES ({id}, 'prod', 'p-{id}.0', 'succeeded', 'chroot', '', {task}, '{arch}')"
            ))
            .execute(store.pool())
            .await
            .unwrap();
        }
        let detail = r#"{"rpm":[{"file":"a.rpm"}]}"#;
        for (kind, source, replay, verdict, at) in [
            // 重放任务 2：单构建对全一致（detail 应被剥离且不进回填 id 集）。
            ("replay", 1i64, Some(2i64), "same", at_days_ago(0, 10)),
            // 重放任务 3：双构建对混合 verdict（detail 保留），最近比对时间更早。
            ("replay", 3, Some(4), "diff", at_days_ago(1, 10)),
            ("replay", 5, Some(6), "build_failed", at_days_ago(0, 12)),
            // 观测面行：kind 过滤的判别锚。
            ("cross_arch_noarch", 1, None, "same", at_days_ago(0, 11)),
        ] {
            sqlx::query(
                "INSERT INTO build_reproducibility (kind, source_build_id, replay_build_id, verdict, detail_json, compared_at) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(kind)
            .bind(source)
            .bind(replay)
            .bind(verdict)
            .bind(detail)
            .bind(at)
            .execute(store.pool())
            .await
            .unwrap();
        }

        let groups = store
            .reproducibility_replay_groups(None, None, 10)
            .await
            .unwrap();
        assert_eq!(groups.len(), 2, "cross_arch row filtered: {groups:?}");
        // 组序：最近比对倒序（task 3 的 day-0 12:00 晚于 task 2 的 day-0 10:00）。
        assert_eq!(groups[0].replay_task_id, Some(3));
        assert_eq!(groups[1].replay_task_id, Some(2));
        // 组 3：arch 升序（aarch64 在前）、verdict 聚合、源任务/product/pkg 取 source 构建。
        assert_eq!(
            groups[0].arches,
            vec!["aarch64".to_string(), "x86_64".to_string()]
        );
        assert_eq!(groups[0].verdicts.get("diff"), Some(&1));
        assert_eq!(groups[0].verdicts.get("build_failed"), Some(&1));
        assert_eq!(groups[0].source_task_id, Some(1));
        assert_eq!(groups[0].pkg_name, "p-3.0");
        // 多包重放任务：组内去重包名保序（构建对序 = arch 升序）。
        assert_eq!(
            groups[0].pkg_names,
            vec!["p-3.0".to_string(), "p-5.0".to_string()]
        );
        assert_eq!(groups[0].pairs.len(), 2);
        assert_eq!(groups[0].pairs[0].replay_arch.as_deref(), Some("aarch64"));
        assert!(
            groups[0].pairs[0]
                .detail_json
                .as_deref()
                .is_some_and(|d| d.contains("a.rpm")),
            "expandable selected group gets detail backfilled"
        );
        // 组 2（全一致）：detail_json 剥离且不进回填 id 集，verdict 汇总 only same。
        assert_eq!(groups[1].verdicts.get("same"), Some(&1));
        assert_eq!(groups[1].pairs.len(), 1);
        assert!(
            groups[1].pairs[0].detail_json.is_none(),
            "all-same group must not carry detail payload"
        );

        // limit 截断在排序后生效：只留最近组（超限组整体不出现，detail 不为其回填）。
        let limited = store
            .reproducibility_replay_groups(None, None, 1)
            .await
            .unwrap();
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].replay_task_id, Some(3));
        assert!(limited[0].pairs[0].detail_json.is_some());
        let empty = store
            .reproducibility_replay_groups(None, None, 0)
            .await
            .unwrap();
        assert!(empty.is_empty());
    }

    /// 复现记录查询可见性：白名单外私有产品行不可见，孤儿豁免同聚合查询。
    #[tokio::test]
    async fn replay_rows_respect_visibility() {
        let (store, _tmp) = create_test_store().await;
        sqlx::query(
            "INSERT INTO tasks (product, pkg_name, \"user\", phase) VALUES ('t', 'p', '', 'succeeded')",
        )
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO builds (id, product, pkg_name, phase, backend, \"user\", task_id) \
             VALUES (1, 'secret', 's-1.0-1', 'succeeded', 'chroot', '', 1)",
        )
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO builds (id, product, pkg_name, phase, backend, \"user\", task_id) \
             VALUES (3, 'orphan', 'o-1.0-3', 'succeeded', 'chroot', '', 1)",
        )
        .execute(store.pool())
        .await
        .unwrap();
        // 重放侧构建行（replay_build_id FK 指向 builds）。
        for (id, product) in [(2i64, "secret"), (4, "orphan")] {
            sqlx::query(
                "INSERT INTO builds (id, product, pkg_name, phase, backend, \"user\", task_id, arch) \
                 VALUES ($1, $2, 'r-1.0', 'succeeded', 'chroot', '', 1, 'x86_64')",
            )
            .bind(id)
            .bind(product)
            .execute(store.pool())
            .await
            .unwrap();
        }
        sqlx::query("INSERT INTO users (id, name, role) VALUES (1, 'alice', 'builder')")
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO products (name, visibility, config_json, owner_id) \
             VALUES ('secret', 'private', '{}', 1)",
        )
        .execute(store.pool())
        .await
        .unwrap();
        let now = crate::util::db_now_utc();
        for (source, replay) in [(1i64, 2i64), (3, 4)] {
            sqlx::query(
                "INSERT INTO build_reproducibility (kind, source_build_id, replay_build_id, verdict, compared_at) \
                 VALUES ('replay', $1, $2, 'diff', $3)",
            )
            .bind(source)
            .bind(replay)
            .bind(&now)
            .execute(store.pool())
            .await
            .unwrap();
        }

        let groups = store
            .reproducibility_replay_groups(Some(&[]), None, 10)
            .await
            .unwrap();
        assert_eq!(groups.len(), 1, "only the orphan-exempt row survives");
        assert_eq!(groups[0].product, "orphan");
        assert_eq!(groups[0].replay_task_id, Some(1));
        // 三占位符组合（cutoff + 可见性 + IN 段）：编号错则双方言直接炸。
        let scoped = store
            .reproducibility_replay_groups(Some(&[]), Some(30), 10)
            .await
            .unwrap();
        assert_eq!(scoped.len(), 1);
    }

    /// 可见性过滤：白名单外私有产品比对行不可见，孤儿（无 products 行）豁免可见。
    #[tokio::test]
    async fn reproducibility_stats_respects_visibility() {
        let (store, _tmp) = create_test_store().await;
        sqlx::query(
            "INSERT INTO tasks (product, pkg_name, \"user\", phase) VALUES ('t', 'p', '', 'succeeded')",
        )
        .execute(store.pool())
        .await
        .unwrap();
        // build 1 挂私有产品，build 3 挂孤儿产品（products 表无行）。
        sqlx::query(
            "INSERT INTO builds (id, product, pkg_name, phase, backend, \"user\", task_id) \
             VALUES (1, 'secret', 's-1.0-1', 'succeeded', 'chroot', '', 1)",
        )
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO builds (id, product, pkg_name, phase, backend, \"user\", task_id) \
             VALUES (3, 'orphan', 'o-1.0-3', 'succeeded', 'chroot', '', 1)",
        )
        .execute(store.pool())
        .await
        .unwrap();
        // 私有产品 CHECK 要求 owner_id 非空（或 public），先落 owner。
        sqlx::query("INSERT INTO users (id, name, role) VALUES (1, 'alice', 'builder')")
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO products (name, visibility, config_json, owner_id) \
             VALUES ('secret', 'private', '{}', 1)",
        )
        .execute(store.pool())
        .await
        .unwrap();
        let now = crate::util::db_now_utc();
        for (source, verdict) in [(1i64, "same"), (3, "diff")] {
            sqlx::query(
                "INSERT INTO build_reproducibility (kind, source_build_id, replay_build_id, verdict, compared_at) \
                 VALUES ('replay', $1, NULL, $2, $3)",
            )
            .bind(source)
            .bind(verdict)
            .bind(&now)
            .execute(store.pool())
            .await
            .unwrap();
        }

        let visible = vec!["secret".to_string()];
        let counts = store
            .reproducibility_verdict_counts(Some(&visible), None)
            .await
            .unwrap();
        let totals = fold_verdict_totals(&counts);
        assert_eq!(totals.get("same"), Some(&1));
        assert_eq!(totals.get("diff"), Some(&1), "orphan product stays visible");

        let counts = store
            .reproducibility_verdict_counts(Some(&[]), None)
            .await
            .unwrap();
        let totals = fold_verdict_totals(&counts);
        assert_eq!(totals.get("diff"), Some(&1));
        assert!(!totals.contains_key("same"), "private product filtered out");

        // by_product 同步过滤：白名单含 secret → 私有产品行可见、孤儿豁免行照旧（两产品各一行）。
        let by_product = store
            .reproducibility_counts_by_product(Some(&visible), None)
            .await
            .unwrap();
        let folded_product = fold_product_counts(&by_product);
        assert_eq!(
            folded_product["secret"]["same"], 1,
            "whitelisted private product must stay visible"
        );
        assert_eq!(
            folded_product["orphan"]["diff"], 1,
            "orphan product stays visible in by_product"
        );

        let series = store.reproducibility_series(Some(&[]), None).await.unwrap();
        let series_total: i64 = series.iter().map(|b| b.counts.values().sum::<i64>()).sum();
        assert_eq!(
            series_total, 1,
            "empty whitelist: only the orphan-exempt row survives in series"
        );
    }
}
