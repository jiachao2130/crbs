// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Chain-resolve + 沿 parent_id 链合并的缓存。
//!
//! # 不变量：write ⇒ invalidate
//!
//! 命中缓存即盲信（不复核 DB revision），前提：所有对 `products` /
//! `product_config_history` 的写入都走 `StateStore` 方法，并在事务 commit 后
//! 调用 `invalidate_resolve_recursive`——链上任一层变化影响全部 descendants，
//! 只清单点会让 descendant 读到旧合并值（create 无需 invalidate：新产品不在
//! 缓存；delete 的 descendants 被 `parent_id ... ON DELETE RESTRICT` 阻止）。
//! 新写路径（re-parent、owner transfer 等）必须同样递归 invalidate；review 靠
//! grep 裸 `UPDATE products` / `DELETE FROM products` 守护，命中须在方法内部。

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLockReadGuard, RwLockWriteGuard};

use crate::config::merge::merge_product_configs;
use crate::config::ProductConfig;
use crate::error::CrbsError;
use crate::error::DbResultExt;
use crate::state::products::{ProductRecord, ProductSummary};
use crate::state::StateStore;

/// 链最大深度（含 root 与 leaf）= 8：write-path `validate_parent_id`
/// 与 read-path `walk_chain` 同一常量，防止 DoS。
pub const MAX_CHAIN_DEPTH: usize = 8;

/// `recipe_retention_days` 的 chrono 安全上界（天）：GC 钉住窗口消费点
/// `chrono::Duration::days`（gc/shared_layers.rs `pin_shared_recipes`）从
/// 106_751_991_168 起溢出 panic（TimeDelta 秒域 i64::MAX/1000 ÷ 86400）；取
/// chrono 界而非 i64::MAX——后者会让 GC 钉住路径 panic 而非回绕。
const MAX_RETENTION_DAYS: i64 = 106_751_991_167;

/// Chain-resolve 结果（最小形状：config + 链上 `base_os_revision` max）。
#[derive(Debug, Clone)]
pub struct ResolvedProduct {
    pub config: ProductConfig,
    /// 链上各层 `base_os_revision` 的 max，供展示/审计；无运行时门控消费者
    /// （worker 侧漂移检测由 `.requested` 指纹承担，见 `engine/init/mod.rs`）。
    pub base_os_revision: i64,
}

/// 缓存 entry：resolve 结果 + 一次算好的 TOML，避免 dispatch 热路径重复序列化。
#[derive(Clone)]
pub(super) struct CachedResolve {
    pub(super) resolved: Arc<ResolvedProduct>,
    pub(super) toml: Arc<String>,
}

/// SQLite 递归 CTE：给定 `root_id`，返回 root 之下所有 descendant id（不含
/// root 自己），供 `invalidate_resolve_recursive` 清缓存用。CTE 名用
/// `descendants`：`desc` 是 SQL 保留字（SQLite 宽容接受，PG 语法错）。
const SELECT_DESCENDANTS_SQL: &str = "\
    WITH RECURSIVE descendants(id) AS (\
        SELECT id FROM products WHERE id = $1 \
        UNION ALL \
        SELECT p.id FROM products p JOIN descendants d ON p.parent_id = d.id\
    ) \
    SELECT id FROM descendants WHERE id != $1\
";

/// 出口校验：合并后的 `ProductConfig` 必须满足最小构建先决条件。
///
/// 只检"形状"：`base_packages` / `repos` 非空（合并冲突由
/// `check_repo_names_unique` 独立负责）。校验必须在链出口而非 create/update
/// 入口——入口只见单层，合并后才知最终 shape。报错一律拿 leaf slug
///（用户提交入口），中间层 slug 放 `reason`。repos 字段校验返回
/// `ValidationFailed`：server 写 DB 的配置不过文件加载校验，此处是
/// point-of-use 单一咽喉，覆盖全部 DB 读路径与库中既有坏行（`../` repo 名
/// 可穿越 chroot root 写宿主，换行可注入 `.repo` 指令）。
pub(super) fn validate_resolved_shape(
    leaf_slug: &str,
    resolved: &ProductConfig,
) -> crate::Result<()> {
    if resolved.base_packages.is_empty() {
        return Err(CrbsError::ProductChainInvalid {
            product: leaf_slug.to_string(),
            reason: "resolved base_packages is empty (root layer must declare at least one)"
                .to_string(),
        });
    }
    if resolved.repos.is_empty() {
        return Err(CrbsError::ProductChainInvalid {
            product: leaf_slug.to_string(),
            reason: "resolved repos is empty (root layer must declare at least one)".to_string(),
        });
    }
    for repo in &resolved.repos {
        if let Err(e) = crate::config::validation::validate_repo_config(repo) {
            return Err(CrbsError::ValidationFailed {
                message: format!("product '{}': {}", leaf_slug, e),
            });
        }
    }
    // rpm_macros（键名 / dist 值白名单）：宏键拼进 rpmbuild --define，坏键
    //（空格/%/-/.）要到构建期 rpmbuild 才爆且难定位；dist 值与 CLI --dist 同格
    // 合并，白名单不得被 config 定义绕过。与 repos 同一出口收口。
    if let Some(macros) = &resolved.rpm_macros {
        for (key, value) in macros {
            if let Err(e) = crate::build_options::validate_rpm_macro_entry(key, value) {
                return Err(CrbsError::ValidationFailed {
                    message: format!("product '{}': {}", leaf_slug, e),
                });
            }
        }
    }
    // noarch 偏好集 token 白名单：值物化进 builds.host_arches CSV 并进领取
    // SQL 的成员判定，坏 token（含逗号等）是注入面，配置期拒绝。子集校验
    //（产品 arches 非空时）：偏好含产品外架构 → 物化后永无 worker 匹配的
    // 死行，fail-fast 拒绝整个链；arches 为空（单架构按提交指定）无从比对，
    // 仅白名单。
    for arch in &resolved.noarch_preferred_arches {
        if let Err(e) = crate::validation::validate_arch(arch) {
            return Err(CrbsError::ValidationFailed {
                message: format!("product '{}': noarch_preferred_arches: {e}", leaf_slug),
            });
        }
        if arch == "noarch" {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "product '{}': noarch_preferred_arches must name worker host arches, \
                     not the content token 'noarch'",
                    leaf_slug
                ),
            });
        }
    }
    if !resolved.noarch_preferred_arches.is_empty() && !resolved.arches.is_empty() {
        if let Some(offending) = resolved
            .noarch_preferred_arches
            .iter()
            .find(|a| !resolved.arches.contains(a))
        {
            return Err(CrbsError::ProductChainInvalid {
                product: leaf_slug.to_string(),
                reason: format!(
                    "noarch_preferred_arches contains {offending:?} which is not in the \
                     product arches {:?} — gated noarch builds would never dispatch",
                    resolved.arches
                ),
            });
        }
    }
    // recipe_retention_days 上界，两个故障半边：u64 > i64::MAX 回绕负数（全部
    // recipe 判到窗口外、钉住被整体禁用）；超 chrono panic 界
    // [`MAX_RETENTION_DAYS`] 直接 panic。取更紧的 chrono 界覆盖两半边；GC
    // 消费点对 resolve 失败降级默认 90 天，拒写行为安全。
    if let Some(v) = resolved.recipe_retention_days {
        if v > MAX_RETENTION_DAYS as u64 {
            return Err(CrbsError::ProductChainInvalid {
                product: leaf_slug.to_string(),
                reason: format!(
                    "recipe_retention_days = {v} exceeds the chrono-safe limit of \
                     {MAX_RETENTION_DAYS} days (GC pinning window would panic)"
                ),
            });
        }
    }
    // resource_overrides 有限正值：画像值直接进调度准入门的量纲运算，负值/
    // NaN/无穷会把"已用量 + 权重 < 水位"比较变恒真/恒假（负 mem_gb 凭空腾内存）。
    if let Some(overrides) = &resolved.resource_overrides {
        for (pkg, o) in overrides {
            let bad = |field: &str, value: f64| CrbsError::ValidationFailed {
                message: format!(
                    "product '{leaf_slug}': resource_overrides.{pkg}.{field} = {value} \
                         must be a finite positive number"
                ),
            };
            if !o.mem_gb.is_finite() || o.mem_gb <= 0.0 {
                return Err(bad("mem_gb", o.mem_gb));
            }
            if !o.cpu_cores.is_finite() || o.cpu_cores <= 0.0 {
                return Err(bad("cpu_cores", o.cpu_cores));
            }
        }
    }
    Ok(())
}

/// 跨链 repo `name` 唯一性检查，按**合并后的累加器**语义：child 非空 `repos`
/// 整体 REPLACE 父层累计（含更早层的 append），REPLACE 掉的同名不算冲突；只有
/// **存活到合并结果**里的同名（典型：`+repos` 追加撞上继承来的 repo）才报
/// `ProductChainInvalid`，`reason` 同时给两个 source-layer slug。层内
/// `repos` ∪ `repos_append` 同名两次也报错（防单层 typo）。
pub(super) fn check_repo_names_unique(
    chain: &[ProductRecord],
    leaf_slug: &str,
) -> crate::Result<()> {
    let mut seen: HashMap<&str, &str> = HashMap::new();
    for layer in chain {
        let src = layer.name.as_str();
        if !layer.config.repos.is_empty() {
            seen.clear();
        }
        let mut layer_seen: HashSet<&str> = HashSet::new();
        for repo in layer
            .config
            .repos
            .iter()
            .chain(layer.config.repos_append.iter())
        {
            if !layer_seen.insert(repo.name.as_str()) {
                return Err(CrbsError::ProductChainInvalid {
                    product: leaf_slug.to_string(),
                    reason: format!(
                        "repo name {:?} appears twice within layer {:?}",
                        repo.name, src
                    ),
                });
            }
            if let Some(&first_src) = seen.get(repo.name.as_str()) {
                return Err(CrbsError::ProductChainInvalid {
                    product: leaf_slug.to_string(),
                    reason: format!(
                        "repo name {:?} appears in both {:?} and {:?}",
                        repo.name, first_src, src
                    ),
                });
            }
            seen.insert(repo.name.as_str(), src);
        }
    }
    Ok(())
}

/// 合并产品链并校验结果（共享逻辑）；输入 `chain` 须 root→leaf 顺序且非空。
/// root 层 `+field` 先折进 base 再逐层 `merge_product_configs`（child 的
/// `_append` 由其内部消耗）。出口统一：剥离 `crbs_root`（机器本地路径，所有
/// 消费方必忽略/覆盖，且已不在 BASE_OS_TRIGGER_FIELDS，保留会误导"编辑可
/// 触发重建"）；`product` 覆写为 leaf slug（透传语义下出口可能是 root 写的
/// 标识，resolved TOML 首行应显示 leaf）。只改出口 accumulator，不动
/// `merge_product_configs` 的"父层值透传"契约（独立有测试钉住）。
/// 加载校验与写前校验共用此循环。
fn merge_chain_configs(chain: &[ProductRecord]) -> ProductConfig {
    debug_assert!(!chain.is_empty(), "chain must be non-empty");
    let mut acc = chain[0].config.clone();
    acc.fold_appends_into_base();
    for layer in &chain[1..] {
        acc = merge_product_configs(&acc, &layer.config);
    }
    acc
}

fn merge_and_validate_chain(
    chain: &[ProductRecord],
    leaf_slug: &str,
) -> crate::Result<ProductConfig> {
    debug_assert!(!chain.is_empty(), "chain must be non-empty");
    let mut acc = merge_chain_configs(chain);
    acc.crbs_root = None;
    acc.product = Some(leaf_slug.to_string());
    check_repo_names_unique(chain, leaf_slug)?;
    validate_resolved_shape(leaf_slug, &acc)?;
    Ok(acc)
}

impl StateStore {
    /// 读锁：poison 时降级为 poison 前最后状态——脏读上限是"看到某个曾提交
    /// 过的 resolve 结果"，无正确性代价。
    fn resolve_cache_read(&self) -> RwLockReadGuard<'_, HashMap<i64, CachedResolve>> {
        self.resolve_cache.read().unwrap_or_else(|e| e.into_inner())
    }

    /// 写锁：poison 时清空缓存自愈——上次写路径中途 panic 可能留下半构建
    /// entry，清空后全部 miss → 回源。
    fn resolve_cache_write(&self) -> RwLockWriteGuard<'_, HashMap<i64, CachedResolve>> {
        self.resolve_cache.write().unwrap_or_else(|e| {
            let mut g = e.into_inner();
            g.clear();
            g
        })
    }

    /// 沿 `parent_id` 从 leaf 走到 root，返回 root→leaf 顺序（`chain[0]` = root）。
    /// **环检测**：`HashSet` 记已见 id，revisit 即 `ProductChainCycle`——写路径
    /// `validate_parent_id` 已拦环，此处是读路径 defense-in-depth（防手工改库 /
    /// 未来 bug）。**深度上限**：`chain.len() >= MAX_CHAIN_DEPTH` →
    /// `ProductChainTooDeep`。
    async fn walk_chain(&self, leaf_id: i64) -> crate::Result<Vec<ProductRecord>> {
        let mut chain: Vec<ProductRecord> = Vec::new();
        let mut visited: HashSet<i64> = HashSet::new();
        let mut cursor = Some(leaf_id);

        while let Some(id) = cursor {
            if !visited.insert(id) {
                let mut cycle_slugs: Vec<String> =
                    chain.iter().rev().map(|r| r.name.clone()).collect();
                if let Some(existing) = chain.iter().find(|r| r.id == id) {
                    cycle_slugs.push(existing.name.clone());
                }
                return Err(CrbsError::ProductChainCycle { chain: cycle_slugs });
            }
            if chain.len() >= MAX_CHAIN_DEPTH {
                return Err(CrbsError::ProductChainTooDeep {
                    max: MAX_CHAIN_DEPTH,
                });
            }
            let record = self
                .get_product_by_id(id)
                .await?
                .ok_or_else(|| CrbsError::NotFound {
                    message: format!("product id={} not found in chain walk", id),
                })?;
            let parent = record.parent_id;
            chain.push(record);
            cursor = parent;
        }

        chain.reverse();
        Ok(chain)
    }

    /// 写前校验用：候补 config 当 leaf 沿 parent 链合并，取与加载期一致的合并
    /// 结果（deterministic 链上 OR、缺省字段继承父层，单看本产品显式值看不见）。
    /// 不做 resolved-shape 校验（模板型中间产品允许不满足 standalone 形态）；
    /// 不进 resolve 缓存（候补未落库）。
    pub async fn effective_config_for_write(
        &self,
        parent_id: Option<i64>,
        candidate: &ProductConfig,
    ) -> crate::Result<ProductConfig> {
        let mut chain = match parent_id {
            Some(pid) => self.walk_chain(pid).await?,
            None => Vec::new(),
        };
        // 候补的记录字段（id/name 等）不参与合并，占位即可。
        chain.push(ProductRecord {
            id: 0,
            name: String::new(),
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: String::new(),
            config: candidate.clone(),
            revision: 0,
            base_os_revision: 0,
            created_at: String::new(),
            updated_at: String::new(),
        });
        Ok(merge_chain_configs(&chain))
    }

    /// Chain-resolve 单个产品：沿 `parent_id` 链 root→leaf 逐层合并，
    /// `base_os_revision` 取链上最大值；找不到 → `NotFound`。缓存：read-lock
    /// 查 → miss 则 drop 锁回源 → write-lock 插入；命中即盲信，一致性由写路径
    /// `invalidate_resolve_recursive` 维护。并发 miss 重复回源可接受，不做
    /// singleflight。
    pub async fn chain_resolve(&self, product_id: i64) -> crate::Result<Arc<ResolvedProduct>> {
        if let Some(hit) = self.resolve_cache_read().get(&product_id) {
            return Ok(Arc::clone(&hit.resolved));
        }

        // 代数快照：失效（写路径）先 bump 再 remove。若本 miss 的 DB 读取与
        // 失效交错，代数已变则只返回不回填——否则失效前读到的旧快照会被
        // 重新插入，缓存永久陈旧到下一次写。
        let generation = self
            .resolve_generation
            .load(std::sync::atomic::Ordering::Acquire);
        let entry = self.build_resolve_entry(product_id).await?;
        let resolved = Arc::clone(&entry.resolved);
        if self
            .resolve_generation
            .load(std::sync::atomic::Ordering::Acquire)
            == generation
        {
            self.resolve_cache_write().insert(product_id, entry);
        }
        Ok(resolved)
    }

    /// 与 `chain_resolve` 同源结果，返回缓存的 TOML（共享 entry，一次算好
    /// 双份）；dispatch 热路径用。
    pub async fn chain_resolve_to_toml(&self, product_id: i64) -> crate::Result<Arc<String>> {
        if let Some(hit) = self.resolve_cache_read().get(&product_id) {
            return Ok(Arc::clone(&hit.toml));
        }

        let generation = self
            .resolve_generation
            .load(std::sync::atomic::Ordering::Acquire);
        let entry = self.build_resolve_entry(product_id).await?;
        let toml = Arc::clone(&entry.toml);
        if self
            .resolve_generation
            .load(std::sync::atomic::Ordering::Acquire)
            == generation
        {
            self.resolve_cache_write().insert(product_id, entry);
        }
        Ok(toml)
    }

    /// 从 DB 拉整条链 + 逐层合并 + 出口校验，构造 resolve 缓存条目。合并走
    /// `merge_and_validate_chain`；`base_os_revision` 取链上 max（`unwrap_or`
    /// 兜底防链退化 panic）。
    async fn build_resolve_entry(&self, product_id: i64) -> crate::Result<CachedResolve> {
        let chain = self.walk_chain(product_id).await?;
        let leaf_slug = chain.last().map(|r| r.name.clone()).ok_or_else(|| {
            crate::error::CrbsError::NotFound {
                message: format!("product {} resolved to empty chain", product_id),
            }
        })?;

        let acc = merge_and_validate_chain(&chain, &leaf_slug)?;

        // 链上 base_os_revision 最大值：任一层 base_os 触发字段更新都算落后
        let base_os_revision = chain.iter().map(|r| r.base_os_revision).max().unwrap_or(1);

        // resource_overrides 是 hub 调度侧消费的画像（scheduler 权重查询读
        // resolved config），**不下发 worker**：worker 侧 `ProductConfig`
        // 禁未知键。与 crbs_root（acc 直接置 None）不同，本键只从 wire TOML
        // 剔除、resolved config 保留。
        let mut wire = acc.clone();
        wire.resource_overrides = None;
        let toml = Arc::new(wire.to_toml_string()?);
        let resolved = Arc::new(ResolvedProduct {
            config: acc,
            base_os_revision,
        });
        Ok(CachedResolve { resolved, toml })
    }

    /// 使某产品**及其全部 descendant** 的缓存失效。**必须**在所有修改链配置或
    /// 拓扑的写路径（`update_product_config` / `delete_product` / re-parent 等）
    /// 事务提交后调用——只清 target 会让 descendant 读到旧合并值；沿
    /// `SELECT_DESCENDANTS_SQL` 递归 CTE 一次拉齐。走 `resolve_cache_write`
    ///（poison 自愈）。
    pub(super) async fn invalidate_resolve_recursive(&self, root_id: i64) -> crate::Result<()> {
        let descendants: Vec<i64> = sqlx::query_scalar(SELECT_DESCENDANTS_SQL)
            .bind(root_id)
            .fetch_all(self.pool())
            .await
            .db_ctx("query descendants")?;

        // 先 bump 再 remove：并发 miss 若已读过旧代数，会在插入前复核失败而
        // 放弃回填；"remove 后 bump"窗口内的回填则不会被后续操作清掉。
        self.resolve_generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut cache = self.resolve_cache_write();
        cache.remove(&root_id);
        for id in descendants {
            cache.remove(&id);
        }
        Ok(())
    }

    /// 遗留的单点失效：**仅测试** / 明确无 descendant 的场景用；生产路径统一
    /// 走 `invalidate_resolve_recursive`。
    #[cfg(test)]
    pub(super) fn invalidate_resolve(&self, product_id: i64) {
        self.resolve_generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.resolve_cache_write().remove(&product_id);
    }

    /// 批量产出列表页摘要：一条 SQL 载入全部产品行，父链 walk + 合并 + 出口
    /// 校验全在内存完成（复用 `merge_and_validate_chain`，与逐行 `chain_resolve`
    /// 同语义），不读不写 `resolve_cache`。`backend` / `build_target` 只回链合并
    /// 后的**产品层覆盖值**（`None` = 未设置），全局回退由调用方单次
    /// `CrbsConfig::load_async` 完成。单链解析失败（环 / 过深 / 校验不过）→
    /// `warn` 跳过该行；DB 故障才 `Err`。
    pub async fn load_product_summaries(&self) -> crate::Result<Vec<ProductSummary>> {
        let records = self.list_all_products().await?;
        let by_id: HashMap<i64, &ProductRecord> = records.iter().map(|r| (r.id, r)).collect();

        let mut summaries = Vec::with_capacity(records.len());
        for record in &records {
            // 内存版 walk_chain：沿 parent_id 向上，环 / 深度守卫与 DB 版一致。
            let mut chain: Vec<&ProductRecord> = Vec::new();
            let mut visited: HashSet<i64> = HashSet::new();
            let mut cursor = Some(record.id);
            let walk_result: crate::Result<()> = (|| {
                while let Some(id) = cursor {
                    if !visited.insert(id) {
                        return Err(CrbsError::ProductChainCycle {
                            chain: chain.iter().rev().map(|r| r.name.clone()).collect(),
                        });
                    }
                    if chain.len() >= MAX_CHAIN_DEPTH {
                        return Err(CrbsError::ProductChainTooDeep {
                            max: MAX_CHAIN_DEPTH,
                        });
                    }
                    let node = by_id.get(&id).ok_or_else(|| CrbsError::NotFound {
                        message: format!("product id={id} not found in chain walk"),
                    })?;
                    cursor = node.parent_id;
                    chain.push(node);
                }
                chain.reverse();
                Ok(())
            })();

            let merged: crate::Result<crate::config::ProductConfig> = match walk_result {
                Ok(()) => {
                    let owned: Vec<ProductRecord> = chain.into_iter().cloned().collect();
                    merge_and_validate_chain(&owned, &record.name)
                }
                Err(e) => Err(e),
            };
            match merged {
                Ok(cfg) => summaries.push(ProductSummary {
                    id: record.id,
                    name: record.name.clone(),
                    owner_id: record.owner_id,
                    parent_id: record.parent_id,
                    parent_name: record
                        .parent_id
                        .and_then(|pid| by_id.get(&pid).map(|p| p.name.clone())),
                    visibility: record.visibility.clone(),
                    revision: record.revision,
                    base_os_revision: record.base_os_revision,
                    backend: cfg.backend,
                    build_target: cfg.build_target,
                }),
                Err(e) => {
                    tracing::warn!(
                        product = %record.name,
                        error = %e,
                        "Failed to resolve product chain for list; skipping row"
                    );
                }
            }
        }
        Ok(summaries)
    }

    /// 按名取产品记录；不存在统一 NotFound（any 语义，可见性由调用方负责）。
    async fn get_product_record_or_not_found(&self, name: &str) -> crate::Result<ProductRecord> {
        self.get_product_by_name(name)
            .await?
            .ok_or_else(|| CrbsError::NotFound {
                message: format!("product '{}' not found in database", name),
            })
    }

    /// 按 slug 从 DB 出发 chain-resolve 出**合并后的** `Config`，全局层用调用方
    /// 传入的 `CrbsConfig`（server GC 传 pin 到 server root 的配置，CLI 传引擎
    /// 全局），不重读 `/etc/crbs/crbs.toml`。any 语义（by-name，可见性由调用方
    /// 负责；口径与 [`Self::load_merged_config_for_any_product_by_name`] 一致）
    /// 是结果 GC 的硬要求：私人产品构建与已删产品遗留目录都要能回收，
    /// official-only 会让这类候选每轮 skipped_invalid、永不回收。结果 GC 的
    /// 安全根必须用它：GC 内部重读引擎全局配置会把 server pin 的 root 架空——
    /// server-only 部署或 root 不一致时全部候选判 outside result root 而
    /// skipped，GC 静默零回收。
    pub async fn load_merged_config_for_product_with_root(
        &self,
        name: &str,
        global: &crate::config::CrbsConfig,
    ) -> crate::Result<crate::config::Config> {
        let record = self.get_product_record_or_not_found(name).await?;
        let toml = self.chain_resolve_to_toml(record.id).await?;
        crate::config::Config::load_with_product_config_and_global_async(
            name,
            &toml,
            global.clone(),
        )
        .await
    }

    /// 按 id 加载合并后的产品配置（支持官方/私人产品，可见性校验由调用方负责）。
    pub async fn load_merged_config_for_product_by_id(
        &self,
        id: i64,
        name: &str,
    ) -> crate::Result<crate::config::Config> {
        let toml = self.chain_resolve_to_toml(id).await?;
        crate::config::Config::load_with_product_config_async(name, &toml).await
    }

    /// 按名称加载合并后的产品配置（any 语义，不做可见性校验）：内部操作
    ///（签名、result_dir 查找等）产品存在即允许加载；面向用户的端点须先过
    /// `check_chain_visibility` / `is_visible_to`。本组 `load_merged_config_*`
    /// 均只读消费，Config 加载不创建运行时目录——目录只在构建执行路径
    ///（engine `build_from_parts` / CLI `load_product_config` funnel）显式创建。
    pub async fn load_merged_config_for_any_product_by_name(
        &self,
        name: &str,
    ) -> crate::Result<crate::config::Config> {
        let record = self.get_product_record_or_not_found(name).await?;
        let toml = self.chain_resolve_to_toml(record.id).await?;
        crate::config::Config::load_with_product_config_async(name, &toml).await
    }

    /// 按名称 chain-resolve 产品（any 语义，不做可见性校验；内部操作用，
    /// 面向用户的端点须先做可见性校验）。
    pub async fn resolve_any_product_by_name(
        &self,
        name: &str,
    ) -> crate::Result<Arc<ResolvedProduct>> {
        let record = self.get_product_record_or_not_found(name).await?;
        self.chain_resolve(record.id).await
    }

    /// 测试专用：直接读缓存 entry 计数。生产代码禁用。
    #[cfg(test)]
    pub(super) fn resolve_cache_len(&self) -> usize {
        self.resolve_cache_read().len()
    }

    /// 编辑预览：把 leaf 的配置替换为 `candidate`，走链合并+校验，返回合并后
    /// TOML（`update_product_config` 落库前的链级语义预检）；不读不写缓存。
    pub async fn resolve_preview_for_edit(
        &self,
        product_id: i64,
        candidate: &ProductConfig,
    ) -> crate::Result<String> {
        let mut chain = self.walk_chain(product_id).await?;
        let leaf_slug =
            chain
                .last()
                .map(|r| r.name.clone())
                .ok_or_else(|| CrbsError::NotFound {
                    message: format!("product {} resolved to empty chain", product_id),
                })?;
        if let Some(leaf) = chain.last_mut() {
            leaf.config = candidate.clone();
        }
        let merged = merge_and_validate_chain(&chain, &leaf_slug)?;
        merged.to_toml_string()
    }

    /// 新建预览：以 `candidate` 作为 leaf，构建 parent 链 + 合并校验，返回合并
    /// 后 TOML。`parent_id = None` 时单层链。不读不写 `resolve_cache`。
    pub async fn resolve_preview_for_create(
        &self,
        parent_id: Option<i64>,
        name: &str,
        candidate: &ProductConfig,
    ) -> crate::Result<String> {
        let mut chain = if let Some(pid) = parent_id {
            let parent_chain = self.walk_chain(pid).await?;
            if parent_chain.len() >= MAX_CHAIN_DEPTH {
                return Err(CrbsError::ProductChainTooDeep {
                    max: MAX_CHAIN_DEPTH,
                });
            }
            parent_chain
        } else {
            Vec::new()
        };

        // 合成 leaf 记录（id=-1 等占位值不影响 merge/validate 语义）
        chain.push(ProductRecord {
            id: -1,
            name: name.to_string(),
            display_name: None,
            owner_id: None,
            parent_id,
            visibility: "public".to_string(),
            config: candidate.clone(),
            revision: 1,
            base_os_revision: 1,
            created_at: String::new(),
            updated_at: String::new(),
        });

        let merged = merge_and_validate_chain(&chain, name)?;
        merged.to_toml_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProductConfig, RepoConfig};
    use crate::state::products::CreateProductInput;
    use crate::state::StateStore;
    use tempfile::TempDir;

    fn sample_config() -> ProductConfig {
        ProductConfig {
            product: Some("mydist".into()),
            base_packages: vec!["bash".into(), "gcc".into()],
            repos: vec![RepoConfig {
                name: "base".into(),
                baseurl: "http://example/repo".into(),
                enabled: true,
                gpgcheck: false,
                gpgkey: None,
                priority: 99,
                cost: 1000,
                module_hotfixes: false,
                exclude: vec![],
                includepkgs: vec![],
                extra: None,
            }],
            ..Default::default()
        }
    }

    async fn fresh_store() -> (StateStore, TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new_with_db_path(&tmp.path().join("state.db"), tmp.path())
            .await
            .unwrap();
        (store, tmp)
    }

    fn official<'a>(name: &'a str, cfg: &'a ProductConfig) -> CreateProductInput<'a> {
        CreateProductInput {
            name,
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: cfg,
            changed_by_user_id: None,
            reason: None,
        }
    }

    #[tokio::test]
    async fn resolve_missing_product_returns_not_found() {
        let (store, _tmp) = fresh_store().await;
        let err = store.chain_resolve(9999).await.unwrap_err();
        assert!(matches!(err, CrbsError::NotFound { .. }));
        assert_eq!(store.resolve_cache_len(), 0);
    }

    #[tokio::test]
    async fn resolve_populates_cache_on_first_read() {
        let (store, _tmp) = fresh_store().await;
        let cfg = sample_config();
        let id = store
            .create_product(official("mydist", &cfg))
            .await
            .unwrap();
        assert_eq!(store.resolve_cache_len(), 0);

        let r = store.chain_resolve(id).await.unwrap();
        assert_eq!(r.config.base_packages, vec!["bash", "gcc"]);
        assert_eq!(r.base_os_revision, 1);
        assert_eq!(store.resolve_cache_len(), 1);
    }

    #[tokio::test]
    async fn resolve_toml_uses_shared_cache_entry() {
        // chain_resolve 与 chain_resolve_to_toml 共享 entry：不触发第二次回源。
        let (store, _tmp) = fresh_store().await;
        let cfg = sample_config();
        let id = store
            .create_product(official("mydist", &cfg))
            .await
            .unwrap();

        let toml = store.chain_resolve_to_toml(id).await.unwrap();
        assert!(toml.contains("base_packages"));
        assert_eq!(store.resolve_cache_len(), 1);

        let r = store.chain_resolve(id).await.unwrap();
        assert_eq!(r.config.base_packages, vec!["bash", "gcc"]);
        assert_eq!(store.resolve_cache_len(), 1);
    }

    /// 盲信不变量的文档化测试：命中缓存后裸 SQL 修改产品行，chain_resolve 仍
    /// 返回旧值——写路径必须走 StateStore 方法并 invalidate，裸 UPDATE 属违约。
    #[tokio::test]
    async fn cache_hit_blind_trusts_and_ignores_raw_sql_update() {
        let (store, _tmp) = fresh_store().await;
        let cfg = sample_config();
        let id = store
            .create_product(official("mydist", &cfg))
            .await
            .unwrap();

        let _ = store.chain_resolve(id).await.unwrap();

        // 裸 SQL 改配置——故意绕过 StateStore、不 invalidate
        let mut new_cfg = cfg.clone();
        new_cfg.base_packages.push("git".into());
        let new_json = serde_json::to_string(&new_cfg).unwrap();
        sqlx::query("UPDATE products SET config_json = $1, revision = 999 WHERE id = $2")
            .bind(&new_json)
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap();

        // 盲信：仍拿旧值——期望新值即意味着塞进了 DB 复核，违背 hit 零回源。
        let r = store.chain_resolve(id).await.unwrap();
        assert_eq!(r.config.base_packages, vec!["bash", "gcc"]);
    }

    #[tokio::test]
    async fn update_product_config_invalidates_cache() {
        // 走正规写路径 update_product_config：commit 后 invalidate，chain_resolve 拿新值。
        let (store, _tmp) = fresh_store().await;
        let cfg = sample_config();
        let id = store
            .create_product(official("mydist", &cfg))
            .await
            .unwrap();

        let r1 = store.chain_resolve(id).await.unwrap();
        assert_eq!(r1.config.base_packages, vec!["bash", "gcc"]);
        assert_eq!(store.resolve_cache_len(), 1);

        let mut new_cfg = cfg.clone();
        new_cfg.base_packages.push("git".into());
        let out = store
            .update_product_config(id, &new_cfg, None, None, None)
            .await
            .unwrap();
        assert_eq!(out.revision, 2);
        assert_eq!(store.resolve_cache_len(), 0);

        let r2 = store.chain_resolve(id).await.unwrap();
        assert_eq!(r2.config.base_packages, vec!["bash", "gcc", "git"]);
        assert_eq!(r2.base_os_revision, 2);
    }

    #[tokio::test]
    async fn update_expected_revision_conflict_does_not_invalidate() {
        // RevisionConflict 事务已 ROLLBACK，缓存里的旧值应保留（不能滥失效）。
        let (store, _tmp) = fresh_store().await;
        let cfg = sample_config();
        let id = store
            .create_product(official("mydist", &cfg))
            .await
            .unwrap();

        let _ = store.chain_resolve(id).await.unwrap();
        assert_eq!(store.resolve_cache_len(), 1);

        let mut new_cfg = cfg.clone();
        new_cfg.base_packages.push("git".into());
        let err = store
            .update_product_config(id, &new_cfg, None, None, Some(99))
            .await
            .unwrap_err();
        assert!(matches!(err, CrbsError::RevisionConflict { .. }));

        assert_eq!(store.resolve_cache_len(), 1);
        let r = store.chain_resolve(id).await.unwrap();
        assert_eq!(r.config.base_packages, vec!["bash", "gcc"]);
    }

    #[tokio::test]
    async fn delete_product_invalidates_cache() {
        let (store, _tmp) = fresh_store().await;
        let cfg = sample_config();
        let id = store
            .create_product(official("mydist", &cfg))
            .await
            .unwrap();
        let _ = store.chain_resolve(id).await.unwrap();
        assert_eq!(store.resolve_cache_len(), 1);

        store.delete_product(id).await.unwrap();
        assert_eq!(store.resolve_cache_len(), 0);

        let err = store.chain_resolve(id).await.unwrap_err();
        assert!(matches!(err, CrbsError::NotFound { .. }));
    }

    #[tokio::test]
    async fn cloned_store_shares_cache() {
        // StateStore 是 Clone；Arc<RwLock> 保证 clone 共享同一缓存——否则
        // server clone-into-tasks 后写路径 invalidate 会漏掉其它 clone 的缓存。
        let (store, _tmp) = fresh_store().await;
        let cfg = sample_config();
        let id = store
            .create_product(official("mydist", &cfg))
            .await
            .unwrap();

        let store2 = store.clone();
        let _ = store.chain_resolve(id).await.unwrap();
        assert_eq!(store.resolve_cache_len(), 1);
        assert_eq!(store2.resolve_cache_len(), 1);

        let mut new_cfg = cfg.clone();
        new_cfg.base_packages.push("git".into());
        store2
            .update_product_config(id, &new_cfg, None, None, None)
            .await
            .unwrap();
        assert_eq!(store.resolve_cache_len(), 0);
        assert_eq!(store2.resolve_cache_len(), 0);
    }

    /// 出口校验：resolve 出 leaf 空 `base_packages` → `ProductChainInvalid`，
    /// 消息带 leaf slug + reason。
    #[tokio::test]
    async fn resolve_rejects_empty_base_packages_at_exit() {
        let (store, _tmp) = fresh_store().await;
        let cfg = sample_config();
        let id = store
            .create_product(official("mydist", &cfg))
            .await
            .unwrap();

        // 裸 SQL 抹空 base_packages：update 写路径（skip_serializing_if empty）
        // 事前拦不掉，只有出口 gating 能兜。
        let mut empty_cfg = cfg.clone();
        empty_cfg.base_packages.clear();
        let blob = serde_json::to_string(&empty_cfg).unwrap();
        sqlx::query("UPDATE products SET config_json = $1 WHERE id = $2")
            .bind(&blob)
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap();
        // 裸 SQL 绕过 StateStore invalidate 契约，测试里手动清一次
        store.invalidate_resolve(id);

        let err = store.chain_resolve(id).await.unwrap_err();
        assert!(
            matches!(
                &err,
                CrbsError::ProductChainInvalid { product, reason }
                    if product == "mydist" && reason.contains("base_packages")
            ),
            "got: {:?}",
            err
        );
    }

    /// 出口校验：resolve 出 leaf 空 `repos` → 报 `ProductChainInvalid`。
    #[tokio::test]
    async fn resolve_rejects_empty_repos_at_exit() {
        let (store, _tmp) = fresh_store().await;
        let cfg = sample_config();
        let id = store
            .create_product(official("mydist", &cfg))
            .await
            .unwrap();

        let mut empty_cfg = cfg.clone();
        empty_cfg.repos.clear();
        let blob = serde_json::to_string(&empty_cfg).unwrap();
        sqlx::query("UPDATE products SET config_json = $1 WHERE id = $2")
            .bind(&blob)
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap();
        store.invalidate_resolve(id);

        let err = store.chain_resolve(id).await.unwrap_err();
        assert!(
            matches!(
                &err,
                CrbsError::ProductChainInvalid { product, reason }
                    if product == "mydist" && reason.contains("repos")
            ),
            "got: {:?}",
            err
        );
    }

    /// noarch 偏好集坏 token（含逗号 = CSV 注入面）必须在 resolve 出口拒绝。
    #[test]
    fn validate_resolved_shape_rejects_bad_noarch_preference_token() {
        let mut cfg = ProductConfig {
            base_packages: vec!["bash".into()],
            repos: vec![RepoConfig {
                name: "r".into(),
                baseurl: "http://r/".into(),
                gpgcheck: false,
                ..Default::default()
            }],
            noarch_preferred_arches: vec!["x86_64,loongarch64".into()],
            ..Default::default()
        };
        cfg.repos[0].gpgkey = None;
        let err = validate_resolved_shape("leaf", &cfg).unwrap_err();
        assert!(
            format!("{err}").contains("noarch_preferred_arches"),
            "must name the offending key: {err}"
        );

        cfg.noarch_preferred_arches = vec!["noarch".into()];
        let err = validate_resolved_shape("leaf", &cfg).unwrap_err();
        assert!(
            format!("{err}").contains("host arches"),
            "content token noarch must be rejected: {err}"
        );

        cfg.noarch_preferred_arches = vec!["x86_64".into()];
        assert!(validate_resolved_shape("leaf", &cfg).is_ok());
    }

    /// 偏好集含产品架构之外 token：物化后永无 worker 匹配（死行），
    /// resolve 出口 fail-fast（产品 arches 非空时的子集校验）。
    #[test]
    fn validate_resolved_shape_rejects_preference_outside_product_arches() {
        let mut cfg = ProductConfig {
            base_packages: vec!["bash".into()],
            repos: vec![RepoConfig {
                name: "r".into(),
                baseurl: "http://r/".into(),
                gpgcheck: false,
                ..Default::default()
            }],
            arches: vec!["x86_64".into(), "aarch64".into()],
            noarch_preferred_arches: vec!["x86_64".into(), "riscv64".into()],
            ..Default::default()
        };
        cfg.repos[0].gpgkey = None;
        let err = validate_resolved_shape("leaf", &cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("riscv64") && msg.contains("never dispatch"),
            "must name the offending arch and consequence: {msg}"
        );

        // 子集合法 + 单架构产品（arches 空）仅白名单不比对。
        cfg.noarch_preferred_arches = vec!["x86_64".into()];
        assert!(validate_resolved_shape("leaf", &cfg).is_ok());
        cfg.arches = Vec::new();
        cfg.noarch_preferred_arches = vec!["riscv64".into()];
        assert!(
            validate_resolved_shape("leaf", &cfg).is_ok(),
            "single-arch product (no arches list) skips the subset check"
        );
    }

    /// `validate_resolved_shape` 直接测试：空 config 守 shape 语义。
    #[test]
    fn validate_resolved_shape_rejects_empty() {
        let cfg = ProductConfig::default();
        let err = validate_resolved_shape("leaf-slug", &cfg).unwrap_err();
        assert!(matches!(
            err,
            CrbsError::ProductChainInvalid { ref product, .. } if product == "leaf-slug"
        ));
    }

    /// `validate_resolved_shape` 完整 sample 通过：非空 base_packages/repos → Ok。
    #[test]
    fn validate_resolved_shape_accepts_sample() {
        let cfg = sample_config();
        assert!(validate_resolved_shape("leaf-slug", &cfg).is_ok());
    }

    /// rpm_macros 键名坏值（含 `%`）在出口拒绝，错误带 leaf slug。
    #[test]
    fn validate_resolved_shape_rejects_bad_macro_key() {
        let mut cfg = sample_config();
        let mut macros = std::collections::BTreeMap::new();
        macros.insert("%_topdir".to_string(), "/x".to_string());
        cfg.rpm_macros = Some(macros);
        let err = validate_resolved_shape("leaf-slug", &cfg).unwrap_err();
        match err {
            CrbsError::ValidationFailed { message } => {
                assert!(message.contains("leaf-slug"), "got: {}", message);
                assert!(message.contains("%_topdir"), "got: {}", message);
            }
            other => panic!("expected ValidationFailed, got: {:?}", other),
        }
    }

    /// recipe_retention_days 上界：回绕半边（u64 > i64::MAX → 钉住被整体禁用）
    /// 与 panic 半边（超 chrono 界）取更紧的 chrono 界——边界值放行，界 +1 与
    /// i64::MAX 拒绝，正常值放行。
    #[test]
    fn validate_resolved_shape_rejects_recipe_retention_days_overflow() {
        for bad_value in [106_751_991_168u64, i64::MAX as u64, i64::MAX as u64 + 1] {
            let mut bad = sample_config();
            bad.recipe_retention_days = Some(bad_value);
            let err = validate_resolved_shape("leaf-slug", &bad).unwrap_err();
            assert!(
                matches!(&err, CrbsError::ProductChainInvalid { product, reason }
                    if product == "leaf-slug" && reason.contains("recipe_retention_days")),
                "value {bad_value}, got: {:?}",
                err
            );
        }

        let mut edge = sample_config();
        edge.recipe_retention_days = Some(106_751_991_167);
        assert!(
            validate_resolved_shape("leaf-slug", &edge).is_ok(),
            "chrono 安全界边界值不得误拒"
        );

        let mut normal = sample_config();
        normal.recipe_retention_days = Some(90);
        assert!(validate_resolved_shape("leaf-slug", &normal).is_ok());
    }

    // ===== DB 路径产品 repos 字段校验（chroot 穿越 + .repo 注入防线）=====

    /// 合法 repos（含 gpgkey / exclude / includepkgs / extra 注释与键值行）通过。
    #[test]
    fn validate_resolved_shape_accepts_repo_with_full_fields() {
        let cfg = ProductConfig {
            base_packages: vec!["bash".into()],
            repos: vec![RepoConfig {
                name: "everything".into(),
                baseurl: "http://example/repo".into(),
                gpgkey: Some("http://example/key.gpg".into()),
                exclude: vec!["kernel*".into()],
                includepkgs: vec!["pkg-one".into()],
                extra: Some("# comment\nsslverify=0\n\nproxy=http://proxy:8080\n".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(validate_resolved_shape("leaf-slug", &cfg).is_ok());
    }

    /// repo name `../evil`（chroot 穿越形态）→ 拒绝，消息带 repo 名与 leaf slug。
    #[test]
    fn validate_resolved_shape_rejects_repo_name_traversal() {
        let cfg = ProductConfig {
            base_packages: vec!["bash".into()],
            repos: vec![repo_conf("../evil", "http://example/repo")],
            ..Default::default()
        };
        let err = validate_resolved_shape("leaf-slug", &cfg).unwrap_err();
        assert!(
            matches!(&err, CrbsError::ValidationFailed { message }
                if message.contains("leaf-slug") && message.contains("../evil")),
            "got: {:?}",
            err
        );
    }

    /// baseurl 含换行（.repo 指令注入形态）→ 拒绝。
    #[test]
    fn validate_resolved_shape_rejects_baseurl_with_newline() {
        let cfg = ProductConfig {
            base_packages: vec!["bash".into()],
            repos: vec![repo_conf("base", "http://example/repo\ngpgcheck=0")],
            ..Default::default()
        };
        let err = validate_resolved_shape("leaf-slug", &cfg).unwrap_err();
        assert!(
            matches!(&err, CrbsError::ValidationFailed { message }
                if message.contains("baseurl")
                && !message.contains('\n')
                && message.contains("gpgcheck")),
            "got: {:?}",
            err
        );
    }

    /// extra 值含 \r（注入形态）→ 拒绝，消息定位到 repo 名与 extra 字段。
    #[test]
    fn validate_resolved_shape_rejects_control_chars_in_extra_value() {
        let cfg = ProductConfig {
            base_packages: vec!["bash".into()],
            repos: vec![RepoConfig {
                name: "base".into(),
                baseurl: "http://example/repo".into(),
                extra: Some("proxy=http://proxy:8080\rgpgcheck=0".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let err = validate_resolved_shape("leaf-slug", &cfg).unwrap_err();
        assert!(
            matches!(&err, CrbsError::ValidationFailed { message }
                if message.contains("'base'") && message.contains("extra")),
            "got: {:?}",
            err
        );
    }

    // ===== check_repo_names_unique：按合并语义（REPLACE 消歧）=====

    fn repo_conf(name: &str, url: &str) -> RepoConfig {
        RepoConfig {
            name: name.into(),
            baseurl: url.into(),
            ..Default::default()
        }
    }

    /// 造合成 layer 记录（id 等占位值不影响查重语义）。
    fn layer_rec(
        name: &str,
        repos: Vec<RepoConfig>,
        repos_append: Vec<RepoConfig>,
    ) -> ProductRecord {
        ProductRecord {
            id: 0,
            name: name.to_string(),
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public".to_string(),
            config: ProductConfig {
                repos,
                repos_append,
                ..Default::default()
            },
            revision: 1,
            base_os_revision: 1,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    /// child 非空 repos REPLACE 父层：同名 repo 是覆盖而非跨层冲突。
    #[test]
    fn check_repo_names_unique_replace_same_name_is_not_conflict() {
        let chain = vec![
            layer_rec("root", vec![repo_conf("base", "http://root/")], vec![]),
            layer_rec("child", vec![repo_conf("base", "http://child/")], vec![]),
        ];
        assert!(check_repo_names_unique(&chain, "child").is_ok());
    }

    /// REPLACE 连更早层的 append 一起作废：mid `+repos` 追加的 repo 名被
    /// leaf 的非空 repos 覆盖后，不再参与撞名判定。
    #[test]
    fn check_repo_names_unique_replace_wipes_earlier_append() {
        let chain = vec![
            layer_rec("root", vec![repo_conf("base", "http://root/")], vec![]),
            layer_rec("mid", vec![], vec![repo_conf("epel", "http://mid/")]),
            layer_rec("leaf", vec![repo_conf("epel", "http://leaf/")], vec![]),
        ];
        assert!(check_repo_names_unique(&chain, "leaf").is_ok());
    }

    /// 存活到合并结果的跨层撞名（append 撞 append）仍要报错，reason 带两层 slug。
    #[test]
    fn check_repo_names_unique_append_append_conflict_across_layers() {
        let chain = vec![
            layer_rec("root", vec![repo_conf("base", "http://root/")], vec![]),
            layer_rec("mid", vec![], vec![repo_conf("epel", "http://mid/")]),
            layer_rec("leaf", vec![], vec![repo_conf("epel", "http://leaf/")]),
        ];
        let err = check_repo_names_unique(&chain, "leaf").unwrap_err();
        assert!(
            matches!(
                &err,
                CrbsError::ProductChainInvalid { product, reason }
                    if product == "leaf"
                    && reason.contains("\"epel\"")
                    && reason.contains("mid")
                    && reason.contains("leaf")
            ),
            "got: {:?}",
            err
        );
    }

    // ===== chain walk + merge + fold + recursive invalidate =====

    /// Helper："最小合法" child config（无 base_packages，靠 parent 继承）——
    /// 出口校验只看合并后 shape，不看单层是否非空（fork 常见形态）。
    fn empty_child_config() -> ProductConfig {
        ProductConfig::default()
    }

    async fn create_chain(store: &StateStore, prefix: &str, depth: usize) -> Vec<i64> {
        let mut ids = Vec::with_capacity(depth);
        for i in 0..depth {
            let name = format!("{}-{}", prefix, i);
            let parent = if i == 0 { None } else { Some(ids[i - 1]) };
            // 只有 root 层带 base_packages/repos；child 层空 config，靠继承
            let cfg = if i == 0 {
                sample_config()
            } else {
                empty_child_config()
            };
            let id = store
                .create_product(CreateProductInput {
                    name: &name,
                    parent_id: parent,
                    ..official(&name, &cfg)
                })
                .await
                .unwrap();
            ids.push(id);
        }
        ids
    }

    /// walk_chain 单层：等价行为，只返回自己一层，root→leaf 顺序即 `[leaf]`。
    #[tokio::test]
    async fn walk_chain_single_layer() {
        let (store, _tmp) = fresh_store().await;
        let cfg = sample_config();
        let id = store.create_product(official("solo", &cfg)).await.unwrap();
        let chain = store.walk_chain(id).await.unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].id, id);
        assert_eq!(chain[0].name, "solo");
        assert!(chain[0].parent_id.is_none());
    }

    /// walk_chain 三层：root → mid → leaf，验证 root→leaf 顺序 + parent_id 链正确。
    #[tokio::test]
    async fn walk_chain_three_layers() {
        let (store, _tmp) = fresh_store().await;
        let ids = create_chain(&store, "trio", 3).await;

        let chain = store.walk_chain(ids[2]).await.unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].id, ids[0]);
        assert_eq!(chain[1].id, ids[1]);
        assert_eq!(chain[2].id, ids[2]);
        assert_eq!(chain[0].parent_id, None);
        assert_eq!(chain[1].parent_id, Some(ids[0]));
        assert_eq!(chain[2].parent_id, Some(ids[1]));
    }

    /// walk_chain 环检测（读路径 defense-in-depth）：正常创建 a → b 后裸 SQL
    /// 把 a.parent 改成 b 造环，从 b 出发第二次遇到 a 时 visited hit →
    /// `ProductChainCycle`。
    #[tokio::test]
    async fn walk_chain_detects_cycle() {
        let (store, _tmp) = fresh_store().await;
        let a = store
            .create_product(official("a", &sample_config()))
            .await
            .unwrap();
        let b = store
            .create_product(CreateProductInput {
                name: "b",
                parent_id: Some(a),
                ..official("b", &empty_child_config())
            })
            .await
            .unwrap();
        // 裸 SQL：a.parent = b，造环
        sqlx::query("UPDATE products SET parent_id = $1 WHERE id = $2")
            .bind(b)
            .bind(a)
            .execute(store.pool())
            .await
            .unwrap();

        let err = store.walk_chain(b).await.unwrap_err();
        assert!(
            matches!(err, CrbsError::ProductChainCycle { ref chain } if !chain.is_empty()),
            "expected ProductChainCycle, got: {:?}",
            err
        );
    }

    /// walk_chain 深度上限：create 拿 9 个 id 后裸 SQL 连成 9 层链
    ///（`MAX_CHAIN_DEPTH = 8`，避开 write-path 校验），walk 时触发
    /// `ProductChainTooDeep`——读路径自守，防手工改库或未来 bug。
    #[tokio::test]
    async fn walk_chain_depth_cap_reached() {
        let (store, _tmp) = fresh_store().await;
        const DEPTH: usize = 9;
        let mut ids = Vec::with_capacity(DEPTH);
        for i in 0..DEPTH {
            let cfg = if i == 0 {
                sample_config()
            } else {
                empty_child_config()
            };
            let name = format!("layer-{}", i);
            let id = store
                .create_product(CreateProductInput {
                    // 先都建平行；下一步裸 SQL 连
                    parent_id: None,
                    ..official(&name, &cfg)
                })
                .await
                .unwrap();
            ids.push(id);
        }
        // 裸 SQL 连成 0 ← 1 ← 2 ← ... ← 8
        for i in 1..DEPTH {
            sqlx::query("UPDATE products SET parent_id = $1 WHERE id = $2")
                .bind(ids[i - 1])
                .bind(ids[i])
                .execute(store.pool())
                .await
                .unwrap();
        }

        let err = store.walk_chain(ids[DEPTH - 1]).await.unwrap_err();
        assert!(
            matches!(err, CrbsError::ProductChainTooDeep { max } if max == MAX_CHAIN_DEPTH),
            "expected ProductChainTooDeep, got: {:?}",
            err
        );
    }

    /// 链合并输出剥离 crbs_root——root 带 `crbs_root: Some(...)` 时，输出
    /// TOML 不含该键（机器本地路径，所有出口必被忽略）。
    #[tokio::test]
    async fn chain_output_strips_crbs_root() {
        let (store, _tmp) = fresh_store().await;
        let mut cfg = sample_config();
        cfg.crbs_root = Some(std::path::PathBuf::from("/var/lib/crbs-machine-local"));
        let id = store
            .create_product(official("root-with-crbs-root", &cfg))
            .await
            .unwrap();

        let r = store.chain_resolve(id).await.unwrap();
        assert!(
            r.config.crbs_root.is_none(),
            "resolved config should not carry crbs_root"
        );
        let toml = store.chain_resolve_to_toml(id).await.unwrap();
        assert!(
            !toml.contains("crbs_root"),
            "resolved TOML must not contain crbs_root: {}",
            toml
        );
    }

    /// 下发 TOML 剔除 resource_overrides、resolved config 保留——画像键 hub
    /// 调度侧消费，wire 上绝不下发（worker 侧 `ProductConfig` 禁未知键）；
    /// 剥离只发生在 wire TOML 副本上。
    #[tokio::test]
    async fn chain_output_strips_resource_overrides_from_toml_only() {
        let (store, _tmp) = fresh_store().await;
        let mut cfg = sample_config();
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert(
            "gcc".to_string(),
            crate::config::ResourceOverride {
                mem_gb: 16.0,
                cpu_cores: 8.0,
            },
        );
        cfg.resource_overrides = Some(overrides);
        let id = store
            .create_product(official("root-with-overrides", &cfg))
            .await
            .unwrap();

        let r = store.chain_resolve(id).await.unwrap();
        let ov = r
            .config
            .resource_overrides
            .as_ref()
            .expect("hub-side resolved config keeps resource_overrides");
        assert_eq!(ov.get("gcc").map(|o| o.mem_gb), Some(16.0));

        let toml = store.chain_resolve_to_toml(id).await.unwrap();
        assert!(
            !toml.contains("resource_overrides"),
            "resolved TOML must not contain resource_overrides: {}",
            toml
        );
        // 下发形态必须能被禁未知键的 ProductConfig 解析。
        crate::config::ProductConfig::from_str(&toml)
            .expect("dispatched TOML must parse on a worker without the new key");
    }

    /// resource_overrides 取值有限正值：负值 / NaN 在链出口校验被拒。
    #[tokio::test]
    async fn chain_output_rejects_invalid_resource_overrides() {
        let (store, _tmp) = fresh_store().await;
        let mut cfg = sample_config();
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert(
            "gcc".to_string(),
            crate::config::ResourceOverride {
                mem_gb: -1.0,
                cpu_cores: 8.0,
            },
        );
        cfg.resource_overrides = Some(overrides);
        let id = store
            .create_product(official("bad-overrides", &cfg))
            .await
            .unwrap();

        let err = store.chain_resolve(id).await.unwrap_err();
        assert!(
            err.to_string().contains("mem_gb"),
            "expected resource_overrides validation error, got: {err}"
        );
    }

    /// 链出口把 `product` 覆写为 leaf slug——root 写了 `product`、leaf 未写时
    /// merge 透传 root 的 slug，resolved TOML 首行应显示 leaf 而非 root。
    #[tokio::test]
    async fn chain_output_overwrites_product_with_leaf_slug() {
        let (store, _tmp) = fresh_store().await;
        let mut root_cfg = sample_config();
        root_cfg.product = Some("root-slug".into());
        let root_id = store
            .create_product(official("root-slug", &root_cfg))
            .await
            .unwrap();
        let leaf_id = store
            .create_product(CreateProductInput {
                name: "leaf-name",
                parent_id: Some(root_id),
                ..official("leaf-name", &empty_child_config())
            })
            .await
            .unwrap();

        let r = store.chain_resolve(leaf_id).await.unwrap();
        assert_eq!(r.config.product.as_deref(), Some("leaf-name"));
        let toml = store.chain_resolve_to_toml(leaf_id).await.unwrap();
        assert!(
            toml.contains("product = \"leaf-name\""),
            "resolved TOML should carry leaf slug: {}",
            toml
        );
        assert!(
            !toml.contains("root-slug"),
            "resolved TOML must not carry root slug: {}",
            toml
        );
    }

    /// 三层链 append 合并：root [bash, gcc] + `+base_packages` [make] + [git]
    /// → merged = [bash, gcc, make, git]。
    #[tokio::test]
    async fn chain_resolve_three_layer_merge() {
        let (store, _tmp) = fresh_store().await;
        let root_id = store
            .create_product(official("root", &sample_config()))
            .await
            .unwrap();
        let mid_cfg = ProductConfig {
            base_packages_append: vec!["make".into()],
            ..Default::default()
        };
        let mid_id = store
            .create_product(CreateProductInput {
                name: "mid",
                parent_id: Some(root_id),
                ..official("mid", &mid_cfg)
            })
            .await
            .unwrap();
        let leaf_cfg = ProductConfig {
            base_packages_append: vec!["git".into()],
            ..Default::default()
        };
        let leaf_id = store
            .create_product(CreateProductInput {
                name: "leaf",
                parent_id: Some(mid_id),
                ..official("leaf", &leaf_cfg)
            })
            .await
            .unwrap();

        let r = store.chain_resolve(leaf_id).await.unwrap();
        assert_eq!(r.config.base_packages, vec!["bash", "gcc", "make", "git"]);
        assert_eq!(r.config.repos.len(), 1);
        assert_eq!(r.config.repos[0].name, "base");
        // 输出 TOML 不应含 `+base_packages` key（fold 消耗，wire 干净）
        let toml = store.chain_resolve_to_toml(leaf_id).await.unwrap();
        assert!(
            !toml.contains("+base_packages"),
            "resolved TOML still contains +base_packages: {}",
            toml
        );
    }

    /// 关键坑：root 层自身的 `+base_packages` 必须先 fold 进 base，否则后续
    /// child merge 保留 base 时丢掉 append。
    #[tokio::test]
    async fn chain_resolve_root_plus_field_folded_at_entry() {
        let (store, _tmp) = fresh_store().await;
        let mut root_cfg = sample_config();
        root_cfg.base_packages_append = vec!["systemd".into()];
        let root_id = store
            .create_product(official("root-with-plus", &root_cfg))
            .await
            .unwrap();
        // child 层空，纯继承
        let child_id = store
            .create_product(CreateProductInput {
                name: "empty-child",
                display_name: None,
                owner_id: None,
                parent_id: Some(root_id),
                visibility: "public",
                config: &empty_child_config(),
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();

        let r = store.chain_resolve(child_id).await.unwrap();
        assert_eq!(r.config.base_packages, vec!["bash", "gcc", "systemd"]);
    }

    /// base_os_revision 取链上最大值：抬 mid 的 revision（触发字段更新），
    /// leaf resolve 出的应等于 mid 的。
    #[tokio::test]
    async fn chain_resolve_base_os_revision_is_chain_max() {
        let (store, _tmp) = fresh_store().await;
        let ids = create_chain(&store, "trio-bo", 3).await;
        // mid 层修改 base_packages（触发 base_os_revision 抬升）
        let mut new_mid = empty_child_config();
        new_mid.base_packages = vec!["from-mid".into()];
        let out = store
            .update_product_config(ids[1], &new_mid, None, None, None)
            .await
            .unwrap();
        assert!(
            out.base_os_bumped,
            "mid update should bump base_os_revision"
        );
        assert_eq!(out.base_os_revision, 2);

        // leaf 处应 = max(root=1, mid=2, leaf=1) = 2
        let r = store.chain_resolve(ids[2]).await.unwrap();
        assert_eq!(r.base_os_revision, 2);
    }

    /// 跨层 repo name 冲突：root 有 repo `base`，child `+repos` 又追加同名 `base`
    /// → resolve 报 `ProductChainInvalid`，reason 里带两层 slug。
    #[tokio::test]
    async fn chain_resolve_rejects_repo_name_conflict_across_layers() {
        let (store, _tmp) = fresh_store().await;
        let root_id = store
            .create_product(official("root-repo", &sample_config()))
            .await
            .unwrap();
        let child_cfg = ProductConfig {
            repos_append: vec![RepoConfig {
                name: "base".into(),
                baseurl: "http://child/repo".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let child_id = store
            .create_product(CreateProductInput {
                name: "child-conflict",
                parent_id: Some(root_id),
                ..official("child-conflict", &child_cfg)
            })
            .await
            .unwrap();

        let err = store.chain_resolve(child_id).await.unwrap_err();
        assert!(
            matches!(
                &err,
                CrbsError::ProductChainInvalid { product, reason }
                    if product == "child-conflict"
                    && reason.contains("\"base\"")
                    && reason.contains("root-repo")
                    && reason.contains("child-conflict")
            ),
            "expected Q6 cross-layer conflict, got: {:?}",
            err
        );
    }

    /// child 非空 repos REPLACE 父层：同名是覆盖而非冲突，合并结果只剩 child 那份。
    #[tokio::test]
    async fn chain_resolve_child_repos_replace_parent_same_name() {
        let (store, _tmp) = fresh_store().await;
        let root_id = store
            .create_product(official("root-repo", &sample_config()))
            .await
            .unwrap();
        let child_cfg = ProductConfig {
            repos: vec![RepoConfig {
                name: "base".into(),
                baseurl: "http://child/repo".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let child_id = store
            .create_product(CreateProductInput {
                name: "child-replace",
                parent_id: Some(root_id),
                ..official("child-replace", &child_cfg)
            })
            .await
            .unwrap();

        let r = store.chain_resolve(child_id).await.unwrap();
        assert_eq!(r.config.repos.len(), 1);
        assert_eq!(r.config.repos[0].name, "base");
        assert_eq!(r.config.repos[0].baseurl, "http://child/repo");
    }

    /// 单层内 repo name 重复：`repos` 与 `repos_append` 同名 → 报 `ProductChainInvalid`。
    #[tokio::test]
    async fn chain_resolve_rejects_repo_name_duplicate_within_single_layer() {
        let (store, _tmp) = fresh_store().await;
        let mut cfg = sample_config();
        cfg.repos_append = vec![RepoConfig {
            name: "base".into(),
            baseurl: "http://second/".into(),
            ..Default::default()
        }];
        let id = store
            .create_product(official("self-conflict", &cfg))
            .await
            .unwrap();

        let err = store.chain_resolve(id).await.unwrap_err();
        assert!(
            matches!(
                &err,
                CrbsError::ProductChainInvalid { product, reason }
                    if product == "self-conflict"
                    && reason.contains("twice within layer")
            ),
            "expected Q6 within-layer conflict, got: {:?}",
            err
        );
    }

    /// invalidate_resolve_recursive：三层链各自填满缓存后更新 root，
    /// root + 所有 descendants 的 entry 全清。
    #[tokio::test]
    async fn invalidate_resolve_recursive_purges_descendants() {
        let (store, _tmp) = fresh_store().await;
        let ids = create_chain(&store, "recur", 3).await;
        for id in &ids {
            let _ = store.chain_resolve(*id).await.unwrap();
        }
        assert_eq!(store.resolve_cache_len(), 3);

        // 更新 root（走正规写路径）
        let mut new_root = sample_config();
        new_root.base_packages.push("added".into());
        let _ = store
            .update_product_config(ids[0], &new_root, None, None, None)
            .await
            .unwrap();

        assert_eq!(store.resolve_cache_len(), 0);

        let r = store.chain_resolve(ids[2]).await.unwrap();
        assert!(r.config.base_packages.contains(&"added".into()));
    }

    // ── resolve_preview_for_edit / resolve_preview_for_create 测试 ──

    /// 编辑预览：child 只用 `+field` 追加补齐 parent 的 base_packages/repos → 预览通过。
    #[tokio::test]
    async fn preview_edit_plus_field_appends_parent() {
        let (store, _tmp) = fresh_store().await;
        let root_cfg = sample_config();
        let root_id = store
            .create_product(official("root", &root_cfg))
            .await
            .unwrap();
        let child_cfg = ProductConfig {
            base_packages_append: vec!["extra-pkg".into()],
            repos_append: vec![RepoConfig {
                name: "epel".into(),
                baseurl: "http://epel/".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let child_input = CreateProductInput {
            name: "child",
            parent_id: Some(root_id),
            ..official("child", &child_cfg)
        };
        let child_id = store.create_product(child_input).await.unwrap();

        let mut edited = child_cfg.clone();
        edited.base_packages_append.push("vim".into());
        let toml = store
            .resolve_preview_for_edit(child_id, &edited)
            .await
            .unwrap();
        assert!(toml.contains("extra-pkg"));
        assert!(toml.contains("vim"));
        assert!(toml.contains("epel"));
        assert_eq!(store.resolve_cache_len(), 0);
    }

    /// 编辑预览：leaf 追加 repo 与 parent 重名 → ProductChainInvalid。
    #[tokio::test]
    async fn preview_edit_repo_name_conflict() {
        let (store, _tmp) = fresh_store().await;
        let root_cfg = sample_config();
        let root_id = store
            .create_product(official("root", &root_cfg))
            .await
            .unwrap();

        let child_cfg = ProductConfig::default();
        let child_input = CreateProductInput {
            name: "child",
            parent_id: Some(root_id),
            ..official("child", &child_cfg)
        };
        let child_id = store.create_product(child_input).await.unwrap();

        let conflict = ProductConfig {
            repos_append: vec![RepoConfig {
                name: "base".into(), // 与 root 的 "base" 冲突
                baseurl: "http://other/".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let err = store
            .resolve_preview_for_edit(child_id, &conflict)
            .await
            .unwrap_err();
        assert!(
            matches!(
                &err,
                CrbsError::ProductChainInvalid { product, reason }
                    if product == "child" && reason.contains("base")
            ),
            "expected repo name conflict, got: {:?}",
            err
        );
    }

    /// 创建预览：root 无 parent，candidate 空 base_packages → validate_resolved_shape 报错。
    #[tokio::test]
    async fn preview_create_root_empty_base_packages() {
        let (store, _tmp) = fresh_store().await;
        let empty = ProductConfig::default();
        let err = store
            .resolve_preview_for_create(None, "newprod", &empty)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, CrbsError::ProductChainInvalid { product, reason }
                if product == "newprod"
                && reason.contains("base_packages is empty")),
            "expected empty base_packages error, got: {:?}",
            err
        );
    }

    /// 创建预览：root 有合法 candidate → 合并后 TOML 包含 candidate 内容。
    #[tokio::test]
    async fn preview_create_root_success() {
        let (store, _tmp) = fresh_store().await;
        let cfg = sample_config();
        let toml = store
            .resolve_preview_for_create(None, "newroot", &cfg)
            .await
            .unwrap();
        assert!(toml.contains("bash"));
        assert!(toml.contains("gcc"));
        assert_eq!(store.resolve_cache_len(), 0);
    }

    /// 创建预览：挂在 parent 下的 child，只用 +field → 预览通过。
    #[tokio::test]
    async fn preview_create_under_parent_with_append() {
        let (store, _tmp) = fresh_store().await;
        let root_cfg = sample_config();
        let root_id = store
            .create_product(official("root", &root_cfg))
            .await
            .unwrap();

        let child_cfg = ProductConfig {
            base_packages_append: vec!["vim".into()],
            repos_append: vec![RepoConfig {
                name: "epel".into(),
                baseurl: "http://epel/".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let toml = store
            .resolve_preview_for_create(Some(root_id), "newchild", &child_cfg)
            .await
            .unwrap();
        assert!(toml.contains("bash")); // 继承自 root
        assert!(toml.contains("vim")); // child 追加
        assert!(toml.contains("epel")); // child 追加
    }

    /// dry-run 不污染 resolve 缓存：预览前后 chain_resolve 结果一致。
    #[tokio::test]
    async fn preview_does_not_pollute_cache() {
        let (store, _tmp) = fresh_store().await;
        let cfg = sample_config();
        let id = store.create_product(official("prod", &cfg)).await.unwrap();

        let before = store.chain_resolve(id).await.unwrap();
        assert_eq!(store.resolve_cache_len(), 1);

        let mut edited = cfg.clone();
        edited.base_packages.push("vim".into());
        let _ = store.resolve_preview_for_edit(id, &edited).await.unwrap();
        assert_eq!(store.resolve_cache_len(), 1);

        let after = store.chain_resolve(id).await.unwrap();
        assert_eq!(before.config.base_packages, after.config.base_packages);
    }

    /// with_root 变体是 any 语义——私人产品 by-name 也能解析，
    /// 且产品层 result_dir override 在合并结果中生效（结果 GC 的安全根来源）。
    #[tokio::test]
    async fn load_merged_config_with_root_resolves_private_product_override() {
        let (store, tmp) = fresh_store().await;
        let owner = store.create_user("alice", "builder").await.unwrap();

        let mut cfg = sample_config();
        cfg.result_dir = Some(tmp.path().join("private-results"));
        let input = CreateProductInput {
            name: "secret",
            display_name: None,
            owner_id: Some(owner),
            parent_id: None,
            visibility: "private",
            config: &cfg,
            changed_by_user_id: None,
            reason: None,
        };
        store.create_product(input).await.unwrap();

        let global = crate::config::CrbsConfig {
            crbs_root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let merged = store
            .load_merged_config_for_product_with_root("secret", &global)
            .await
            .unwrap();
        // 产品层 override > 全局显式 > 随 root 派生（merge 语义）。
        assert_eq!(merged.result_dir, tmp.path().join("private-results"));
    }

    /// with_root 变体对不存在/已删产品保持 NotFound 上抛
    ///（GC 删除段按全局根回退消费该语义）。
    #[tokio::test]
    async fn load_merged_config_with_root_missing_product_is_not_found() {
        let (store, tmp) = fresh_store().await;
        let global = crate::config::CrbsConfig {
            crbs_root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let err = store
            .load_merged_config_for_product_with_root("ghost", &global)
            .await
            .unwrap_err();
        assert!(matches!(err, CrbsError::NotFound { .. }));
    }
}
