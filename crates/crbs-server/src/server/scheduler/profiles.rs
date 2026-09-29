// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 调度准入共享件：水位阈值、权重缓存与画像键。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::server::state::AppState;
use crbs_core::WorkerStatus;

use super::spawn_scheduler;

/// 准入水位系数对（运行值）：planner 与 hub 本地水位门共用。默认值与有效性
///（>0，加载期 fail-fast）单一事实源在 crbs-core `ServerConfig` 的 serde
/// 默认与加载校验——[`Self::from_config`] 只读不改；测试基线用
/// `from_config(&ServerConfig::default())`。
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct AdmitWatermarks {
    /// 内存水位系数：`used + Σ权重 ≥ mem_total × 该值` 即拒。
    pub mem: f64,
    /// CPU 水位系数：`load1 + Σp90 ≥ ncpu × 该值` 即拒。
    pub cpu: f64,
}

impl AdmitWatermarks {
    pub(crate) fn from_config(config: &crbs_core::config::ServerConfig) -> Self {
        Self {
            mem: config.resource_mem_watermark,
            cpu: config.resource_cpu_watermark,
        }
    }
}

/// 折算护栏的饱和度下限：学习时 `p90 核数 ≥ 0.5 × 采样核数`（-j$(nproc)
/// 打满）才算并行度随节点伸缩的"饱和包"，否则该包并发受依赖图上限约束、
/// 不随节点规模缩放，cpu/mem 都按原值比对——按比例折算会系统性低估小节点
/// 上的占用。硬安全闸（learned 内存门 ×1.2、tmpfs 门）不折算：折算值只进
/// Σ 压载与 steering 评分（放置效率），安全职责留在绝对值硬闸。
/// ponytail: 有跨节点校准数据后可调/升格 server.toml 键。
pub(crate) const ELASTIC_MIN_SATURATION: f64 = 0.5;

/// Σ 供给的爬坡窗口（秒）：只计"派发后未爬满"的在跑构建。load1 是 1 分钟
/// 阻尼平均，-wave 构建爬坡 60–90s 内可见——爬满后在跑权重已体现在 load1
/// 中，再全额计 Σ 即时间维双计，会把门冻死在自身负载上（重包稳态期连小包
/// 都进不去）。谓词落在供数查询（分布式 [`crate::server::scheduler::planner`]
/// 与 hub 本地车道共用）；started_at 在派发（assigned）与领取（building）时
/// 即写入，NULL 臂仅防御历史脏行（视同爬坡期必计）。
pub(crate) const COMMITTED_RAMP_SECS: i64 = 90;

/// 包资源画像缓存 TTL（5 分钟）：调度 2s 级热路径逐轮回源放大读；即时生效
/// 由 report_result 终态钩子定点失效兜住（构建完成产新样本）。
pub(crate) const WEIGHT_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
/// 画像缓存定容上限：触满先清过期，仍满整体清空（最坏退化为一次全量回源）。
pub(crate) const WEIGHT_CACHE_CAPACITY: usize = 4096;

/// 三维画像缓存/回源键：(product, source_name, arch)。source_name 是
/// builds.name 源码包基础名（NVR 去 version/release），同一源码包跨版本共享
/// 画像与声明。arch 与 builds.arch 执行口径一致（noarch 按 'noarch' 聚合）；
/// NULL/空串归一为 ""（画像表对空 arch 无行，权重按未知降级）。
pub(crate) type ProfileKey = (String, String, String);

/// 键归一：候选/活跃行的 arch 列（Option 形态）折成缓存键维度。
pub(crate) fn profile_key(product: &str, source_name: &str, arch: Option<&str>) -> ProfileKey {
    (
        product.to_string(),
        source_name.to_string(),
        arch.unwrap_or_default().to_string(),
    )
}

/// 单包资源权重（派发权重，缓存值）：`None` = 该维度未知（无学习值且无静态
/// 覆盖）。未知维度不计入准入门的 Σ 项——缺数据降级而非阻塞。
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub(crate) struct PackageResourceWeight {
    pub peak_rss_kb: Option<f64>,
    pub cpu_p90_cores: Option<f64>,
    /// 采样核数（`learned_sample_ncpu`）：p90 核数与峰值 RSS 都是采样机并行度
    /// 的函数，cpu/mem 两维消费侧按目标节点折算（见 [`Self::elastic_scale`]）。
    /// 静态覆盖与旧样本为 `None`——不缩放。
    pub cpu_sample_ncpu: Option<i64>,
}

impl PackageResourceWeight {
    /// cpu/mem 两维共用的折算系数：仅饱和包（[`ELASTIC_MIN_SATURATION`] 见
    /// const 文档）且采样/目标基准齐全时按 `min(1, target/sample)` 缩放
    ///（只降不升），否则 `None` = 原值比对。大核机学到的 p90/peak_rss 直接
    /// 套到小节点会恒超 CPU 水位（`load1 + Σ ≥ ncpu × 100%`）或被内存水位
    /// 不必要拒绝（小节点 -j 减半、真实需求同步减半）。
    fn elastic_scale(&self, target_ncpu: Option<i64>) -> Option<f64> {
        let sample = self.cpu_sample_ncpu?;
        let target = target_ncpu?;
        if sample <= 0 || target <= 0 {
            return None;
        }
        if self.cpu_p90_cores? < sample as f64 * ELASTIC_MIN_SATURATION {
            return None;
        }
        Some((target as f64 / sample as f64).min(1.0))
    }

    /// 目标节点上的 CPU 权重：饱和包按 [`Self::elastic_scale`] 折算，否则原值。
    pub(crate) fn cpu_cores_on(&self, target_ncpu: Option<i64>) -> f64 {
        let cores = self.cpu_p90_cores.unwrap_or(0.0);
        match self.elastic_scale(target_ncpu) {
            Some(scale) => cores * scale,
            None => cores,
        }
    }

    /// 目标节点上的内存权重：`peak_rss_kb × min(1, target_ncpu/sample_ncpu)`，
    /// 与 [`Self::cpu_cores_on`] 同系数同护栏（预测内存 = 峰值 × target/S，
    /// 代数上与 cpu 折算同构；跨节点单核内存实测稳定）。无折算基准或护栏
    /// 不命中时返回原值。
    pub(crate) fn mem_kb_on(&self, target_ncpu: Option<i64>) -> f64 {
        let kb = self.peak_rss_kb.unwrap_or(0.0);
        match self.elastic_scale(target_ncpu) {
            Some(scale) => kb * scale,
            None => kb,
        }
    }

    /// 该包在目标节点上是否按折算口径计量（护栏命中 / 无基准 = false 原值）；
    /// heavy 落位打点随行——预测值是否折算必须可见。
    pub(crate) fn scales_on(&self, target_ncpu: Option<i64>) -> bool {
        self.elastic_scale(target_ncpu).is_some()
    }
}

/// 缓存值全量：权重 + 删失标志（censored 兜底判定的输入，随三维画像行）
/// + 学习门影子输入（`resource_learned_gates_enabled` 开才回源，随行缓存）。
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub(crate) struct ResolvedResourceProfile {
    pub weight: PackageResourceWeight,
    pub censored: bool,
    /// 键已学习（learned_samples ≥ 1）：无画像行 / 零样本 = false，两门直通。
    pub gate_learned: bool,
    /// 学习峰值内存 KB（内存门需求，× 1.2 裕量后比对节点可用内存）。
    pub gate_max_mem_kb: Option<i64>,
    /// 学习 tmpfs 峰值 KB（tmpfs 门需求，比对节点 mem_total/2 容量）。
    pub gate_max_tmpfs_kb: Option<i64>,
}

/// [`ProfileKey`] → 解析画像的映射形态（缓存/回源/Σ 折算共用签名）。
pub(crate) type ResourceProfileMap = HashMap<ProfileKey, ResolvedResourceProfile>;

/// 目标 worker 在跑构建的权重合计（已知量求和，未知权重计 0）。
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct CommittedLoad {
    pub mem_kb: f64,
    pub cpu_cores: f64,
}

impl CommittedLoad {
    /// 累加一个在跑构建的权重；`target_ncpu` = 该构建所在节点的核数
    ///（cpu/mem 维按采样核数折算（饱和护栏共用），同节点全部构建共用同一
    /// 折算基准）。
    pub(crate) fn add(&mut self, w: &PackageResourceWeight, target_ncpu: Option<i64>) {
        self.mem_kb += w.mem_kb_on(target_ncpu);
        self.cpu_cores += w.cpu_cores_on(target_ncpu);
    }

    /// Σ 项再叠一个候选权重（planner"候选权重进门"判定用），折算口径同 [`Self::add`]。
    pub(crate) fn plus(
        &self,
        w: &PackageResourceWeight,
        target_ncpu: Option<i64>,
    ) -> CommittedLoad {
        CommittedLoad {
            mem_kb: self.mem_kb + w.mem_kb_on(target_ncpu),
            cpu_cores: self.cpu_cores + w.cpu_cores_on(target_ncpu),
        }
    }
}

/// [`ProfileKey`] → 资源画像的内存态缓存（TTL [`WEIGHT_CACHE_TTL`] + 定容）。
/// std::sync::Mutex：查插删不跨 await（回源在锁外）；毒化恢复数据继续服务。
pub(crate) struct ResourceWeightCache {
    entries: std::sync::Mutex<HashMap<ProfileKey, (ResolvedResourceProfile, tokio::time::Instant)>>,
    ttl: Duration,
}

impl ResourceWeightCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(HashMap::new()),
            ttl: WEIGHT_CACHE_TTL,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: std::sync::Mutex::new(HashMap::new()),
            ttl,
        }
    }

    fn lock_entries(
        &self,
    ) -> std::sync::MutexGuard<
        '_,
        HashMap<ProfileKey, (ResolvedResourceProfile, tokio::time::Instant)>,
    > {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 查缓存：TTL 未过才命中；过期条目视同不存在（由调用方回源后 fill 覆盖）。
    pub(crate) fn lookup(
        &self,
        product: &str,
        source_name: &str,
        arch: &str,
    ) -> Option<ResolvedResourceProfile> {
        let guard = self.lock_entries();
        let (profile, filled_at) = guard.get(&(
            product.to_string(),
            source_name.to_string(),
            arch.to_string(),
        ))?;
        (filled_at.elapsed() < self.ttl).then_some(*profile)
    }

    /// 批量查缓存（planner Σ 共用的批量入口）：返回 (命中, miss 键集)，
    /// miss 由调用方一次批量回源后 `fill_many` 合并——TTL 语义与单键一致。
    pub(crate) fn lookup_many(&self, keys: &[ProfileKey]) -> (ResourceProfileMap, Vec<ProfileKey>) {
        let mut hits = HashMap::new();
        let mut misses = Vec::new();
        for key in keys {
            match self.lookup(&key.0, &key.1, &key.2) {
                Some(profile) => {
                    hits.insert(key.clone(), profile);
                }
                None => misses.push(key.clone()),
            }
        }
        (hits, misses)
    }

    /// 回填（未知画像同样入缓存，防冷包每轮回源；触满策略见上）。
    pub(crate) fn fill(&self, key: &ProfileKey, profile: ResolvedResourceProfile) {
        let mut guard = self.lock_entries();
        if guard.len() >= WEIGHT_CACHE_CAPACITY && !guard.contains_key(key) {
            guard.retain(|_, (_, filled_at)| filled_at.elapsed() < self.ttl);
            if guard.len() >= WEIGHT_CACHE_CAPACITY {
                guard.clear();
            }
        }
        guard.insert(key.clone(), (profile, tokio::time::Instant::now()));
    }

    /// 批量回填（触满策略逐键同 [`Self::fill`]）。
    pub(crate) fn fill_many(&self, profiles: &HashMap<ProfileKey, ResolvedResourceProfile>) {
        for (key, profile) in profiles {
            self.fill(key, *profile);
        }
    }

    /// 定点失效：构建终态后调用，下次查询重新回源（新样本进 EMA 窗口）。
    pub(crate) fn invalidate(&self, product: &str, source_name: &str, arch: &str) {
        self.lock_entries().remove(&(
            product.to_string(),
            source_name.to_string(),
            arch.to_string(),
        ));
    }

    /// 按源码包失效（declared 管理面写后调用）：'any' 声明行影响该包全部
    /// arch 键的解析结果（精确 arch → 'any' 回退），定点单键清不干净——包级清。
    pub(crate) fn invalidate_pkg(&self, product: &str, source_name: &str) {
        self.lock_entries()
            .retain(|k, _| !(k.0 == product && k.1 == source_name));
    }

    /// 整体清空（启动回填播种后调用）：播种结果覆盖全表，回填前缓存过的
    /// "无画像"未知值在 TTL 内不再可信。
    pub(crate) fn clear(&self) {
        self.lock_entries().clear();
    }
}

/// 批量查包资源画像：缓存优先，miss 合并一次批量回源（学习面权重批查 +
/// 按 distinct product 解析静态覆盖），结果回填缓存。供 planner 候选集与
/// 本地水位门 Σ 折算共用——"禁 N+1"的收口点。
///
/// 权重源：`resource_profile_weights_enabled` 开 = 画像表
/// 有效权重（censored 期 mem 取 max(ema, max)——删失下界比 ema 更接近真值，
/// 不消费 max 则 OOM 包永远得不到保护）；关 = Σ 只剩 overrides。
/// 学习值缺维逐维回退 `resource_overrides`，全缺 = 未知（不计入 Σ，不阻塞
/// 派发）。回源 DB 错误一律降级为"未知画像"，不向派发主流程传错。
pub(crate) async fn load_resource_profiles(
    app: &Arc<AppState>,
    keys: Vec<ProfileKey>,
) -> ResourceProfileMap {
    // 去重保序：同键重复查询只回源一次。
    let mut seen = std::collections::HashSet::new();
    let keys: Vec<ProfileKey> = keys
        .into_iter()
        .filter(|k| seen.insert(k.clone()))
        .collect();

    let (mut profiles, misses) = app.resource_weight_cache.lookup_many(&keys);
    if misses.is_empty() {
        return profiles;
    }

    // 静态覆盖是两开关共用的逐维回退源；产品解析失败/未配置该包 → 空表。
    let distinct_products: Vec<String> = misses
        .iter()
        .map(|k| k.0.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let overrides = static_overrides_for_products(app, &distinct_products).await;

    let learned = if app.server_config.resource_profile_weights_enabled {
        match app.state_store.learned_weights_batch(&misses).await {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, count = misses.len(), "Failed to batch-load learned weights; treating as unknown");
                HashMap::new()
            }
        }
    } else {
        HashMap::new()
    };

    // 学习门影子输入：随画像同批回源同缓存（TTL 同权重）；影子开关与 tmpfs
    // 转正开关均关时不回源。DB 错误降级为"未学习"（两门直通），不向派发主
    // 流程传错。
    let gates = if app.server_config.resource_learned_gates_enabled
        || app.server_config.resource_tmpfs_gate_enforced
    {
        match app.state_store.learned_gate_batch(&misses).await {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, count = misses.len(), "Failed to batch-load learned gate inputs; treating keys as unlearned");
                HashMap::new()
            }
        }
    } else {
        HashMap::new()
    };

    let mut backfill = ResourceProfileMap::new();
    for key in &misses {
        let ovr = overrides
            .get(&key.0)
            .and_then(|m| m.get(&key.1))
            .copied()
            .unwrap_or((None, None));
        let (weight, censored) = match learned.get(key) {
            Some(snapshot) => (
                effective_weight_from_learned(snapshot, ovr),
                snapshot.censored,
            ),
            None => (
                PackageResourceWeight {
                    peak_rss_kb: ovr.0,
                    cpu_p90_cores: ovr.1,
                    cpu_sample_ncpu: None,
                },
                false,
            ),
        };
        let gate = gates.get(key);
        backfill.insert(
            key.clone(),
            ResolvedResourceProfile {
                weight,
                censored,
                gate_learned: gate.is_some(),
                gate_max_mem_kb: gate.and_then(|g| g.max_mem_kb),
                gate_max_tmpfs_kb: gate.and_then(|g| g.max_tmpfs_kb),
            },
        );
    }
    app.resource_weight_cache.fill_many(&backfill);
    for (key, profile) in backfill {
        profiles.insert(key, profile);
    }
    profiles
}

/// 有效权重：censored=1 期间 mem 取 max(ema, max)（删失期 max
/// 是更接近真值的下界；ema 为 NULL 的冷启动重包靠它进 Σ），解锁后回 ema；
/// cpu 无删失语义恒取 ema（采样核数随行，消费侧按目标节点折算）。缺维回退
/// 产品静态覆盖——静态值是绝对核数，不带采样核数。
pub(crate) fn effective_weight_from_learned(
    snapshot: &crbs_core::LearnedWeightSnapshot,
    static_override: (Option<f64>, Option<f64>),
) -> PackageResourceWeight {
    let learned_mem_kb = if snapshot.censored {
        match (snapshot.ema_mem_kb, snapshot.max_mem_kb) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    } else {
        snapshot.ema_mem_kb
    };
    PackageResourceWeight {
        peak_rss_kb: learned_mem_kb.map(|v| v as f64).or(static_override.0),
        cpu_p90_cores: snapshot.ema_ncpu.or(static_override.1),
        cpu_sample_ncpu: snapshot
            .ema_ncpu
            .and(snapshot.sample_ncpu)
            .filter(|n| *n > 0),
    }
}

/// 源码包基础名 → 静态覆盖换算值 (mem_kb, cpu_cores)。
pub(crate) type ProductOverrideMap = HashMap<String, (Option<f64>, Option<f64>)>;

/// 批量解析产品静态资源覆盖（`resource_overrides`）：每个 distinct product
/// 解析一次（回源单包画像时逐对解析是隐藏 N+1）。产品解析失败/未配置该包
/// → 空表（调用方按未知降级）。
pub(crate) async fn static_overrides_for_products(
    app: &Arc<AppState>,
    products: &[String],
) -> HashMap<String, ProductOverrideMap> {
    let mut out: HashMap<String, ProductOverrideMap> = HashMap::new();
    for product in products {
        let resolved = match app.state_store.resolve_any_product_by_name(product).await {
            Ok(r) => r,
            Err(e) => {
                debug!(product = %product, error = %e, "Failed to resolve product for static resource override");
                continue;
            }
        };
        if let Some(map) = resolved.config.resource_overrides.as_ref() {
            let converted: ProductOverrideMap = map
                .iter()
                .map(|(pkg, o)| {
                    (
                        pkg.clone(),
                        (Some(o.mem_gb * 1024.0 * 1024.0), Some(o.cpu_cores)),
                    )
                })
                .collect();
            out.insert(product.clone(), converted);
        }
    }
    out
}

/// 派发遍历序（确定性）：`active/capacity` 升序 → `load1/ncpu` 升序 → `id` 升序。
/// 遥测缺失（无采样 / 非 Linux，load1/ncpu NULL）的负载比按 +∞——排在
/// 同档已测节点之后，不冒充"最闲"；浮点全程 `total_cmp`，NaN 也有确定序。
pub(crate) fn sort_workers_for_dispatch(
    workers: &mut [WorkerStatus],
    active_by_worker: &HashMap<i64, i64>,
) {
    workers.sort_by(|a, b| {
        let key = |w: &WorkerStatus| {
            let capacity = w.capacity.max(1) as f64;
            let utilization = active_by_worker.get(&w.id).copied().unwrap_or(0) as f64 / capacity;
            (utilization, worker_load_ratio(w), w.id)
        };
        let (ua, la, ia) = key(a);
        let (ub, lb, ib) = key(b);
        ua.total_cmp(&ub)
            .then_with(|| la.total_cmp(&lb))
            .then(ia.cmp(&ib))
    });
}

/// `load1/ncpu` 归一化负载比；任一缺失 → +∞（降级语义见上）。
pub(crate) fn worker_load_ratio(worker: &WorkerStatus) -> f64 {
    match (worker.load1, worker.ncpu) {
        (Some(load1), Some(ncpu)) if ncpu > 0 => load1 / ncpu as f64,
        _ => f64::INFINITY,
    }
}

/// 水位拒绝维度（planner 归因/指标细分用）。Tmpfs 是学习门转正的拒绝维
///（[`super::planner::learned_gates`] 同口径谓词），与 mem/cpu 共用拒绝/顺延/
/// 归因通道，非水位语义。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WatermarkDimension {
    Mem,
    Cpu,
    Tmpfs,
}

/// 派发准入门（纯函数）：目标 worker 实时遥测 + 在跑权重合计是否仍在水位内。
/// - 内存：`mem_total_kb × mem_used_pct/100 + Σ peak_rss_kb < mem_total_kb × 水位系数`
/// - CPU：`load1 + Σ CPU 权重 < ncpu × 水位系数`（Σ 已按本节点核数折算，
///   见 [`PackageResourceWeight::cpu_cores_on`]）
///
/// **遥测缺失 = 跳过该维度（直接放行）**：mem_total_kb / load1 / ncpu NULL
/// 时无换算基准，只靠轮转与容量兜底——绝不因缺遥测阻塞派发（超载预防，
/// 非正确性闸门）。拒则给出先触发的维度（内存先判）。水位系数运行值来自
/// server.toml（[`AdmitWatermarks`]），有效性由加载期 fail-fast 保证。
pub(crate) fn watermark_reject_dimension(
    worker: &WorkerStatus,
    load: CommittedLoad,
    watermarks: AdmitWatermarks,
) -> Option<WatermarkDimension> {
    if let (Some(total_kb), Some(used_pct)) = (worker.mem_total_kb, worker.mem_used_pct) {
        let total_kb = total_kb as f64;
        let used_kb = total_kb * used_pct / 100.0;
        if used_kb + load.mem_kb >= total_kb * watermarks.mem {
            return Some(WatermarkDimension::Mem);
        }
    }
    if let (Some(load1), Some(ncpu)) = (worker.load1, worker.ncpu) {
        if ncpu > 0 && load1 + load.cpu_cores >= ncpu as f64 * watermarks.cpu {
            return Some(WatermarkDimension::Cpu);
        }
    }
    None
}

/// 在跑构建权重合计（纯函数，planner 与本地水位门共用）：(worker, product,
/// source_name, arch) 活跃行按 worker 折算 Σ；画像缺行计 0（缺数据降级，
/// 不阻塞派发）。`active_rows` 须由供数查询按爬坡窗口
///（[`COMMITTED_RAMP_SECS`]）预过滤——本函数不做时间维判定。
/// `worker_ncpu` = worker_id → 核数（CPU 维按各节点折算；缺项不缩放）。
pub(crate) fn committed_from_active(
    active_rows: &[(i64, String, String, Option<String>)],
    profiles: &ResourceProfileMap,
    worker_ncpu: &HashMap<i64, i64>,
) -> HashMap<i64, CommittedLoad> {
    let mut committed: HashMap<i64, CommittedLoad> = HashMap::new();
    for (worker_id, product, source, arch) in active_rows {
        if let Some(p) = profiles.get(&profile_key(product, source, arch.as_deref())) {
            let ncpu = worker_ncpu.get(worker_id).copied();
            committed
                .entry(*worker_id)
                .or_default()
                .add(&p.weight, ncpu);
        }
    }
    committed
}

// ===== 画像回填：启动后台一次性幂等播种 =====

/// 回填幂等标记键（app_meta）：成功跑过一次即置位，重启不再执行。值为完成
/// 时刻（RFC3339），仅诊断用——幂等性由"只填 learned_samples=0 行"的条件
/// upsert 与标记位共同保证，标记误删重跑亦安全。
pub(crate) const PROFILE_BACKFILL_MARKER: &str = "resource_profiles_backfilled_at";

/// 启动画像回填，完成后再启动调度器：
/// 回填结果必须对调度器首个 tick 可见，故两者串行；回填失败/标记读失败仅
/// warn 不阻断——调度器照常启动，权重源退化为"无历史学习值"（下次启动重试）。
pub(crate) fn spawn_profile_backfill_then_scheduler(app: Arc<AppState>, cancel: CancellationToken) {
    tokio::spawn(async move {
        let backfill_app = app.clone();
        tokio::select! {
            _ = run_profile_backfill_once(&backfill_app) => {}
            _ = cancel.cancelled() => return,
        }
        spawn_scheduler(app, cancel);
    });
}

/// 回填单次执行：标记检查 → 折算播种 → 置标记。任何一步失败 warn 后返回
///（不置标记，下次启动重跑；播种只填空行，重跑幂等）。
pub(crate) async fn run_profile_backfill_once(app: &Arc<AppState>) {
    match app.state_store.get_app_meta(PROFILE_BACKFILL_MARKER).await {
        Ok(Some(_)) => {
            debug!("Profile backfill already completed; skipping");
            return;
        }
        Ok(None) => {}
        Err(e) => {
            warn!(error = %e, "Failed to read profile backfill marker; skipping this start");
            return;
        }
    }
    info!("Running one-shot package resource profile backfill from build history");
    match app
        .state_store
        .backfill_learned_from_builds(
            Some(app.server_config.resource_profile_min_peak_rss_kb),
            app.server_config.resource_censor_headroom,
        )
        .await
    {
        Ok(stats) => {
            info!(
                seeded = stats.seeded,
                skipped_occupied = stats.skipped_occupied,
                skipped_light = stats.skipped_light,
                "Profile backfill completed"
            );
            // 播种覆盖整表：回填前查询过的缓存（多为"无画像"未知值）在 TTL
            // 内不再可信，整体清空让首个调度 tick 重新回源读播种值。
            app.resource_weight_cache.clear();
            if let Err(e) = app
                .state_store
                .set_app_meta(PROFILE_BACKFILL_MARKER, &chrono::Utc::now().to_rfc3339())
                .await
            {
                warn!(error = %e, "Failed to set profile backfill marker; next start will re-run (idempotent)");
            }
        }
        Err(e) => {
            warn!(error = %e, "Profile backfill failed; will retry on next start (startup not blocked)");
            // 播种逐键提交：失败前可能已写部分行，缓存若在回填前有回源值须
            // 整体作废（与成功臂同口径）。
            app.resource_weight_cache.clear();
        }
    }
}
