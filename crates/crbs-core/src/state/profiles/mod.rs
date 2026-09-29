// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 包资源画像 state 层：声明面（declared_*，hub admin 显式钉入的放置契约）与
//! 学习面（learned_*，构建终态 best-effort 维护）同表双列组。
//!
//! 列组隔离是硬约束：学习 upsert 只写 learned_*，声明写只写 declared_*——
//! 读改写竞态 last-writer-wins 只漂移统计量、不同列组互不吞写。
//! 学习决策（EMA/删失/口径 sticky）抽成纯函数，DB 层只做读写。

use super::Dialect;
use crate::error::DbResultExt;

mod backfill;
mod store;
#[cfg(test)]
mod tests;

pub use backfill::ProfileBackfillStats;

/// 删失默认余量：node-OOM 样本按 `峰值 × 1.25` 抬升学习上限（只抬不降）。
/// config 默认值与学习决策共用此单一事实源。
pub const DEFAULT_CENSOR_HEADROOM: f64 = 1.25;

/// EMA 折叠系数 α：递推 ema = 0.4×样本 + 0.6×前值（第 6 个及更早样本残留
/// 总和 0.6^5≈7.8% 的软尾，等价于带软尾的 5 样本窗口）。
const EMA_ALPHA: f64 = 0.4;

/// 样本主口径（不混算）：cgroup anon 与 /proc 共享页重复计量纲不同。
/// sticky-cgroup：cgroup 一经建立即粘滞；proc→cgroup 首个样本清零重起算。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SampleBackend {
    /// cgroup 内存口径（v2 `anon` / v1 `memory.stat` `total_rss`，共享页只计
    /// 一次，量纲对齐，sizing 主口径）。
    Cgroup,
    /// /proc 进程树求和口径（共享页重复计数，量纲偏高）。
    Proc,
}

impl SampleBackend {
    /// 列存储/传输用的规范化小写形态。
    pub fn as_str(self) -> &'static str {
        match self {
            SampleBackend::Cgroup => "cgroup",
            SampleBackend::Proc => "proc",
        }
    }

    /// 列值解析（CHECK 域内的两种形态；域外返回 None）。
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cgroup" => Some(SampleBackend::Cgroup),
            "proc" => Some(SampleBackend::Proc),
            _ => None,
        }
    }
}

/// 终态单次资源样本（学习输入）；outcome 决定折叠通道，样本主口径随样本
/// 携带（画像学习不跨口径混算）。
#[derive(Debug, Clone)]
pub enum ResourceSampleOutcome {
    /// 构建成功：EMA 折叠通道（轻包门槛以下的样本跳过）。
    Succeeded {
        /// 样本主口径（cgroup anon / /proc）。
        backend: SampleBackend,
        /// 构建期峰值内存 KB（sizing 主口径）。
        peak_rss_kb: i64,
        /// 构建自身 tmpfs 实例占用峰值 KB（None = 无观测，tmpfs 维不折叠）。
        peak_tmpfs_kb: Option<i64>,
        /// 采样窗内平均占用核数 90 分位（机器无关核数口径）。
        cpu_p90_cores: Option<f64>,
        /// 执行节点核数（解读画像的必要上下文）。
        sample_ncpu: Option<i64>,
    },
    /// 节点 OOM（撞节点内存上限被内核杀）：删失通道——max 只抬不降、ema 不动。
    NodeOom {
        /// 样本主口径。
        backend: SampleBackend,
        /// 被杀时刻的峰值内存 KB（真实需求的下界）。
        peak_rss_kb: i64,
        /// 构建自身 tmpfs 实例占用峰值 KB（None = 无观测，tmpfs 维不动）。
        peak_tmpfs_kb: Option<i64>,
        /// 杀前观测的 CPU p90（不折叠进 ema，仅留档）。
        cpu_p90_cores: Option<f64>,
        /// 执行节点核数。
        sample_ncpu: Option<i64>,
    },
    /// 撞任务自身 memory_max 的 cap-OOM：不进学习（cap 是"最多许用"不是
    /// "需要"）。调用方不应传入；本层收到记 debug 后忽略。
    CapOom,
}

/// 单样本学习决策（apply 返回值，供调用方按 outcome 计数）：Learned/Censored/
/// Reset 各对应一次画像写入，CapHitExcluded 对应 cap-OOM 排除，Skipped =
/// 无写入（轻包门槛以下 / sticky 忽略 proc 样本 / 空键防御跳过）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileUpdateDecision {
    /// succeeded 样本折叠进 EMA（含首样本建行）。
    Learned,
    /// node-OOM 删失抬升 max（含首样本建行）。
    Censored,
    /// proc→cgroup 升级清零重起算。
    Reset,
    /// cap-OOM 不进学习（限额非需求）。
    CapHitExcluded,
    /// 无写入：轻包门槛以下 / sticky 忽略 / 空键。
    Skipped,
}

/// 声明面解析结果：命中的声明行 arch（精确 arch 或 'any' 哨兵）+ 三维下限。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeclaredRequirements {
    /// 命中的声明行 arch。
    pub arch: String,
    /// 内存硬下限 KB；NULL = 该维未声明。
    pub min_mem_kb: Option<i64>,
    /// 核数硬下限；NULL = 该维未声明。
    pub min_ncpu: Option<i64>,
    /// 磁盘硬下限 KB；NULL = 该维未声明。
    pub min_disk_kb: Option<i64>,
}

/// 画像行（声明面 + 学习面全列；serde 供后续 API/UI 复用）。键 =
/// `(product, source_name, arch)`；source_name 是 builds.name 的源码包基础名
/// （NVR 去掉 version/release），同一源码包跨版本共享一行。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageResourceProfile {
    pub product: String,
    pub source_name: String,
    pub arch: String,
    pub declared_min_mem_kb: Option<i64>,
    pub declared_min_ncpu: Option<i64>,
    pub declared_min_disk_kb: Option<i64>,
    pub declared_updated_at: Option<String>,
    pub learned_ema_mem_kb: Option<i64>,
    pub learned_max_mem_kb: Option<i64>,
    /// tmpfs 峰值 EMA/最大（样本缺 tmpfs 值时不折叠，两列维持原值）。
    pub learned_ema_tmpfs_kb: Option<i64>,
    pub learned_max_tmpfs_kb: Option<i64>,
    pub learned_ema_ncpu: Option<f64>,
    pub learned_max_ncpu: Option<f64>,
    pub learned_samples: i64,
    pub learned_sample_ncpu: Option<i64>,
    /// 样本主口径（'cgroup'/'proc'；NULL = 回填行尚无真实样本）。
    pub learned_backend: Option<String>,
    /// 删失期标记：true 期间消费侧有效权重 = max(ema, max)。
    pub learned_censored: bool,
    pub learned_updated_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// 学习面现值快照：apply 前读出 → 决策纯函数输入 → 决策输出照此落列。
#[derive(Debug, Clone, PartialEq)]
struct LearnedState {
    ema_mem_kb: Option<i64>,
    max_mem_kb: Option<i64>,
    ema_tmpfs_kb: Option<i64>,
    max_tmpfs_kb: Option<i64>,
    ema_ncpu: Option<f64>,
    max_ncpu: Option<f64>,
    samples: i64,
    sample_ncpu: Option<i64>,
    backend: Option<SampleBackend>,
    censored: bool,
}

/// 学习面权重快照（调度器 Σ 水位回源值，三维键一行）；有效权重：
/// censored 期 mem 取 max(ema, max)，其余维取 ema。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LearnedWeightSnapshot {
    /// EMA 峰值内存 KB（只折叠 succeeded）。
    pub ema_mem_kb: Option<i64>,
    /// 删失抬升的峰值内存下界 KB（只抬不降）。
    pub max_mem_kb: Option<i64>,
    /// CPU p90 核数 EMA（无删失语义）。
    pub ema_ncpu: Option<f64>,
    /// 最近样本的采样节点核数（消费侧按目标节点折算 CPU 权重的基准；
    /// 旧样本/回填样本可能为 NULL）。
    pub sample_ncpu: Option<i64>,
    /// 删失期标记。
    pub censored: bool,
}

/// 单样本学习决策（DB 层照输出落列；键三元组仅供 sticky 忽略分支的 warn
/// 可观测性）。state 为 None = 本样本不产生任何写入：CapOom（限额非需求）、
/// 轻包门槛以下的 Succeeded、sticky-cgroup 忽略的 proc 样本（计数不计）；
/// decision 供计数面区分 learned/censored/reset/skipped。
fn next_learned_state(
    current: Option<&LearnedState>,
    outcome: &ResourceSampleOutcome,
    min_peak_rss_kb: Option<i64>,
    headroom: f64,
    product: &str,
    source_name: &str,
    arch: &str,
) -> (Option<LearnedState>, ProfileUpdateDecision) {
    let (backend, peak_rss_kb, peak_tmpfs_kb, cpu_p90, sample_ncpu, succeeded) = match outcome {
        ResourceSampleOutcome::Succeeded {
            backend,
            peak_rss_kb,
            peak_tmpfs_kb,
            cpu_p90_cores,
            sample_ncpu,
        } => (
            *backend,
            *peak_rss_kb,
            *peak_tmpfs_kb,
            *cpu_p90_cores,
            *sample_ncpu,
            true,
        ),
        ResourceSampleOutcome::NodeOom {
            backend,
            peak_rss_kb,
            peak_tmpfs_kb,
            cpu_p90_cores,
            sample_ncpu,
        } => (
            *backend,
            *peak_rss_kb,
            *peak_tmpfs_kb,
            *cpu_p90_cores,
            *sample_ncpu,
            false,
        ),
        // cap-OOM 撞的是任务自身 memory_max：限额 ≠ 需求，不进画像。
        ResourceSampleOutcome::CapOom => {
            return (None, ProfileUpdateDecision::CapHitExcluded);
        }
    };

    // 轻包门槛：门槛以下的 Succeeded 不写画像行（零打扰）；OOM 通道不受
    // 门槛——OOM 样本必超门槛，轻包变重靠删失通道自愈闭合。
    if succeeded && min_peak_rss_kb.is_some_and(|min| peak_rss_kb < min) {
        return (None, ProfileUpdateDecision::Skipped);
    }

    let Some(cur) = current else {
        return (
            Some(init_learned_state(
                peak_rss_kb,
                peak_tmpfs_kb,
                cpu_p90,
                sample_ncpu,
                backend,
                succeeded,
                headroom,
            )),
            if succeeded {
                ProfileUpdateDecision::Learned
            } else {
                ProfileUpdateDecision::Censored
            },
        );
    };

    // sticky-cgroup：cgroup 一经建立即粘滞，proc 样本直接忽略（计数不计），
    // 绝不跨口径混算。
    if cur.backend == Some(SampleBackend::Cgroup) && backend == SampleBackend::Proc {
        // 静默 skip 对外不可见（画像数值冻结、排查像"学习停了"），显式 warn。
        tracing::warn!(
            product = %product,
            source = %source_name,
            arch = %arch,
            profile_backend = SampleBackend::Cgroup.as_str(),
            sample_backend = SampleBackend::Proc.as_str(),
            "profile learning skipped: sticky cgroup backend ignores proc sample (ema/max/samples untouched)"
        );
        return (None, ProfileUpdateDecision::Skipped);
    }
    // 升级重置：proc → cgroup 首个样本清零 mem/ncpu 的 EMA/max/samples 重起算
    //（只换标签不清数值 = 跨口径混算）。tmpfs 是 statfs 绝对值、与采样口径
    // 无关：保留历史并在本样本带观测时折叠。回填行 backend=NULL：无既立口径
    // 可升级，按本样本口径折叠、保留回填播种值。
    if cur.backend == Some(SampleBackend::Proc) && backend == SampleBackend::Cgroup {
        let mut state = init_learned_state(
            peak_rss_kb,
            peak_tmpfs_kb,
            cpu_p90,
            sample_ncpu,
            backend,
            succeeded,
            headroom,
        );
        (state.ema_tmpfs_kb, state.max_tmpfs_kb) = fold_tmpfs(
            cur.ema_tmpfs_kb,
            cur.max_tmpfs_kb,
            peak_tmpfs_kb,
            succeeded,
            headroom,
        );
        return (Some(state), ProfileUpdateDecision::Reset);
    }

    let decision = if succeeded {
        ProfileUpdateDecision::Learned
    } else {
        ProfileUpdateDecision::Censored
    };
    if succeeded {
        let (ema_tmpfs_kb, max_tmpfs_kb) = fold_tmpfs(
            cur.ema_tmpfs_kb,
            cur.max_tmpfs_kb,
            peak_tmpfs_kb,
            true,
            headroom,
        );
        return (
            Some(LearnedState {
                ema_mem_kb: Some(ema_fold_i64(cur.ema_mem_kb, peak_rss_kb)),
                max_mem_kb: Some(max_i64(cur.max_mem_kb, peak_rss_kb)),
                ema_tmpfs_kb,
                max_tmpfs_kb,
                ema_ncpu: match cpu_p90 {
                    // 无 p90 的样本不折叠 cpu 维（保持前值），只推进 mem/samples。
                    Some(p90) => Some(ema_fold_f64(cur.ema_ncpu, p90)),
                    None => cur.ema_ncpu,
                },
                max_ncpu: max_f64(cur.max_ncpu, cpu_p90),
                samples: cur.samples + 1,
                sample_ncpu,
                backend: Some(backend),
                censored: false,
            }),
            decision,
        );
    }
    // 删失（node-OOM）：max = max(max, 样本×headroom) 只抬不降；EMA 不动
    //（下界样本不可信）；samples 计入（含删失样本）；cpu 维度无删失语义
    // 不动（p90 是杀前观测）；tmpfs 维只有带观测的样本才抬 max。
    let (_, max_tmpfs_kb) = fold_tmpfs(
        cur.ema_tmpfs_kb,
        cur.max_tmpfs_kb,
        peak_tmpfs_kb,
        false,
        headroom,
    );
    (
        Some(LearnedState {
            max_mem_kb: Some(max_i64(
                cur.max_mem_kb,
                censored_floor(peak_rss_kb, headroom),
            )),
            max_tmpfs_kb,
            samples: cur.samples + 1,
            sample_ncpu,
            censored: true,
            backend: cur.backend.or(Some(backend)),
            ..cur.clone()
        }),
        decision,
    )
}

/// 首样本/重起算初始化：Succeeded 按 EMA 首项落值；删失样本只有 max 抬升、
/// EMA 保持 NULL（EMA 只折叠 succeeded，删失后的首个成功样本才起算）。
fn init_learned_state(
    peak_rss_kb: i64,
    peak_tmpfs_kb: Option<i64>,
    cpu_p90: Option<f64>,
    sample_ncpu: Option<i64>,
    backend: SampleBackend,
    succeeded: bool,
    headroom: f64,
) -> LearnedState {
    LearnedState {
        ema_mem_kb: succeeded.then_some(peak_rss_kb),
        max_mem_kb: Some(if succeeded {
            peak_rss_kb
        } else {
            censored_floor(peak_rss_kb, headroom)
        }),
        ema_tmpfs_kb: if succeeded { peak_tmpfs_kb } else { None },
        max_tmpfs_kb: if succeeded {
            peak_tmpfs_kb
        } else {
            peak_tmpfs_kb.map(|t| censored_floor(t, headroom))
        },
        ema_ncpu: if succeeded { cpu_p90 } else { None },
        max_ncpu: if succeeded { cpu_p90 } else { None },
        samples: 1,
        sample_ncpu,
        backend: Some(backend),
        censored: !succeeded,
    }
}

/// tmpfs 维折叠：与 mem 采样口径无关（升级重置时保留历史）。succeeded
/// 折叠 EMA 且 max 只抬不降；删失只抬 max、EMA 不动；样本无观测时两列
/// 维持前值。
fn fold_tmpfs(
    cur_ema: Option<i64>,
    cur_max: Option<i64>,
    peak_tmpfs_kb: Option<i64>,
    succeeded: bool,
    headroom: f64,
) -> (Option<i64>, Option<i64>) {
    match (succeeded, peak_tmpfs_kb) {
        (true, Some(t)) => (Some(ema_fold_i64(cur_ema, t)), Some(max_i64(cur_max, t))),
        (false, Some(t)) => (cur_ema, Some(max_i64(cur_max, censored_floor(t, headroom)))),
        _ => (cur_ema, cur_max),
    }
}

/// EMA 整数折叠（KB）：0.4×样本 + 0.6×前值四舍五入取整；首项直落样本值。
fn ema_fold_i64(prev: Option<i64>, sample: i64) -> i64 {
    match prev {
        None => sample,
        Some(p) => (EMA_ALPHA * sample as f64 + (1.0 - EMA_ALPHA) * p as f64).round() as i64,
    }
}

/// EMA 浮点折叠（cpu p90 核数）：同系数、不取整。
fn ema_fold_f64(prev: Option<f64>, sample: f64) -> f64 {
    match prev {
        None => sample,
        Some(p) => EMA_ALPHA * sample + (1.0 - EMA_ALPHA) * p,
    }
}

/// 删失下界：样本 × headroom 四舍五入取整（OOM 真实需求 ≥ 观测峰值 × 余量）。
fn censored_floor(sample: i64, headroom: f64) -> i64 {
    (sample as f64 * headroom).round() as i64
}

/// Option 包络取最大（NULL 视为无前值，直落样本值）。
fn max_i64(prev: Option<i64>, sample: i64) -> i64 {
    prev.map_or(sample, |p| p.max(sample))
}

/// Option 浮点取最大（两侧皆 None 保持 None）。
fn max_f64(prev: Option<f64>, sample: Option<f64>) -> Option<f64> {
    match (prev, sample) {
        (None, s) => s,
        (p, None) => p,
        (Some(a), Some(b)) => Some(a.max(b)),
    }
}

mod sql {
    use crate::state::Dialect;

    /// 学习面 upsert（只写 learned 列组）：ON CONFLICT DO UPDATE 逐列点名，
    /// created_at/declared 组/updated_at 不在列清单即不被触碰。
    /// 浮点列 TEXT 绑定 + SQL CAST（驱动钉型坑见 `Dialect::float_param_cast`）。
    pub(super) fn upsert_learned(dialect: Dialect) -> String {
        format!(
            "INSERT INTO package_resource_profiles \
                 (product, source_name, arch, learned_ema_mem_kb, learned_max_mem_kb, \
                  learned_ema_tmpfs_kb, learned_max_tmpfs_kb, \
                  learned_ema_ncpu, learned_max_ncpu, learned_samples, learned_sample_ncpu, \
                  learned_backend, learned_censored, learned_updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, {ema_ncpu}, {max_ncpu}, $10, $11, $12, $13, {now}) \
             ON CONFLICT (product, source_name, arch) DO UPDATE SET \
                learned_ema_mem_kb = EXCLUDED.learned_ema_mem_kb, \
                learned_max_mem_kb = EXCLUDED.learned_max_mem_kb, \
                learned_ema_tmpfs_kb = EXCLUDED.learned_ema_tmpfs_kb, \
                learned_max_tmpfs_kb = EXCLUDED.learned_max_tmpfs_kb, \
                learned_ema_ncpu = EXCLUDED.learned_ema_ncpu, \
                learned_max_ncpu = EXCLUDED.learned_max_ncpu, \
                learned_samples = EXCLUDED.learned_samples, \
                learned_sample_ncpu = EXCLUDED.learned_sample_ncpu, \
                learned_backend = EXCLUDED.learned_backend, \
                learned_censored = EXCLUDED.learned_censored, \
                learned_updated_at = EXCLUDED.learned_updated_at",
            ema_ncpu = dialect.float_param_cast(8),
            max_ncpu = dialect.float_param_cast(9),
            now = dialect.sql_now(),
        )
    }

    /// 声明面 upsert（只写 declared 四列，含 declared_updated_at）：学习组与
    /// 行身份列不动——两写方列组互斥，last-writer-wins 无实害。
    pub(super) fn upsert_declared(dialect: Dialect) -> String {
        format!(
            "INSERT INTO package_resource_profiles \
                 (product, source_name, arch, declared_min_mem_kb, declared_min_ncpu, \
                  declared_min_disk_kb, declared_updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, {now}) \
             ON CONFLICT (product, source_name, arch) DO UPDATE SET \
                declared_min_mem_kb = EXCLUDED.declared_min_mem_kb, \
                declared_min_ncpu = EXCLUDED.declared_min_ncpu, \
                declared_min_disk_kb = EXCLUDED.declared_min_disk_kb, \
                declared_updated_at = EXCLUDED.declared_updated_at",
            now = dialect.sql_now(),
        )
    }

    /// 删除语义 = 只清 declared 四列不删行（行内 learned 是不可再生的学习
    /// 资产）；行不存在时 0 行影响、幂等。
    pub(super) fn unset_declared(dialect: Dialect) -> String {
        format!(
            "UPDATE package_resource_profiles \
             SET declared_min_mem_kb = NULL, declared_min_ncpu = NULL, \
                 declared_min_disk_kb = NULL, declared_updated_at = {now} \
             WHERE product = $1 AND source_name = $2 AND arch = $3",
            now = dialect.sql_now(),
        )
    }

    /// 学习面现值（决策纯函数的输入；读在写事务内执行）。
    pub(super) const SELECT_LEARNED_STATE: &str = "\
        SELECT learned_ema_mem_kb, learned_max_mem_kb, learned_ema_tmpfs_kb, learned_max_tmpfs_kb, \
               learned_ema_ncpu, learned_max_ncpu, \
               learned_samples, learned_sample_ncpu, learned_backend, learned_censored \
        FROM package_resource_profiles \
        WHERE product = $1 AND source_name = $2 AND arch = $3";

    /// 回填取样：每 (product, 源码包基础名, arch) 最近 5 条 succeeded
    /// 峰值样本（builds.name 为源码包基础名，跨版本共享画像键），行级过滤
    /// peak_rss_kb IS NOT NULL（与 EMA 选样口径同款，权重源切换连续）；
    /// rn=1 最新，外层 ORDER BY rn DESC = 时间正序（折算输入序）。arch
    /// 空串/NULL 的旧行跳过（无键可归）。ROW_NUMBER 窗口 SQLite 3.25+ /
    /// PG 通用（builds.rs 批量样本同论证）。
    pub(super) const SELECT_BACKFILL_SAMPLES: &str = "\
        SELECT product, name AS source_name, arch, peak_rss_kb, cpu_p90_cores, sample_ncpu FROM ( \
            SELECT product, name, arch, peak_rss_kb, cpu_p90_cores, sample_ncpu, \
                   ROW_NUMBER() OVER ( \
                       PARTITION BY product, name, arch \
                       ORDER BY completed_at DESC, id DESC \
                   ) AS rn \
            FROM builds \
            WHERE phase = 'succeeded' AND peak_rss_kb IS NOT NULL \
              AND COALESCE(arch, '') <> '' \
        ) AS s \
        WHERE rn <= 5 \
        ORDER BY s.product, s.name, s.arch, s.rn DESC";

    /// 回填播种 upsert：学习组列 + ON CONFLICT 附加 `WHERE learned_samples = 0`
    ///（只填空行的原子判空，已有学习的行 0 行影响由调用方计数）；
    /// learned_backend 恒 NULL、censored 恒 0（回填只折叠 succeeded）。
    pub(super) fn upsert_backfill_learned(dialect: Dialect) -> String {
        format!(
            "INSERT INTO package_resource_profiles \
                 (product, source_name, arch, learned_ema_mem_kb, learned_max_mem_kb, \
                  learned_ema_ncpu, learned_max_ncpu, learned_samples, learned_sample_ncpu, \
                  learned_backend, learned_censored, learned_updated_at) \
             VALUES ($1, $2, $3, $4, $5, {ema_ncpu}, {max_ncpu}, $8, $9, NULL, 0, {now}) \
             ON CONFLICT (product, source_name, arch) DO UPDATE SET \
                learned_ema_mem_kb = EXCLUDED.learned_ema_mem_kb, \
                learned_max_mem_kb = EXCLUDED.learned_max_mem_kb, \
                learned_ema_ncpu = EXCLUDED.learned_ema_ncpu, \
                learned_max_ncpu = EXCLUDED.learned_max_ncpu, \
                learned_samples = EXCLUDED.learned_samples, \
                learned_sample_ncpu = EXCLUDED.learned_sample_ncpu, \
                learned_updated_at = EXCLUDED.learned_updated_at \
             WHERE package_resource_profiles.learned_samples = 0",
            ema_ncpu = dialect.float_param_cast(6),
            max_ncpu = dialect.float_param_cast(7),
            now = dialect.sql_now(),
        )
    }

    /// 声明面单键读取（find 的精确/回退两跳共用）。
    pub(super) const SELECT_DECLARED: &str = "\
        SELECT arch, declared_min_mem_kb, declared_min_ncpu, declared_min_disk_kb \
        FROM package_resource_profiles \
        WHERE product = $1 AND source_name = $2 AND arch = $3";

    /// 画像行全列（get / list 共用列清单，漂移经行解码 db_ctx 报错浮出）。
    pub(super) const PROFILE_COLUMNS: &str = "\
        product, source_name, arch, \
        declared_min_mem_kb, declared_min_ncpu, declared_min_disk_kb, declared_updated_at, \
        learned_ema_mem_kb, learned_max_mem_kb, learned_ema_tmpfs_kb, learned_max_tmpfs_kb, \
        learned_ema_ncpu, learned_max_ncpu, \
        learned_samples, learned_sample_ncpu, learned_backend, learned_censored, learned_updated_at, \
        created_at, updated_at";
}

/// 学习面现值读取（写事务连接上执行；无行返回 None）。口径列域外值（CHECK
/// 域外不可达）按 NULL 处理：视为无既立口径，按本样本口径折叠。
async fn read_learned_state_on(
    conn: &mut sqlx::AnyConnection,
    product: &str,
    source_name: &str,
    arch: &str,
) -> crate::Result<Option<LearnedState>> {
    let row = sqlx::query_as::<
        _,
        (
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<f64>,
            Option<f64>,
            i64,
            Option<i64>,
            Option<String>,
            i64,
        ),
    >(sql::SELECT_LEARNED_STATE)
    .bind(product)
    .bind(source_name)
    .bind(arch)
    .fetch_optional(&mut *conn)
    .await
    .db_ctx("read profile learned state")?;
    Ok(row.map(
        |(
            ema_mem,
            max_mem,
            ema_tmpfs,
            max_tmpfs,
            ema_ncpu,
            max_ncpu,
            samples,
            sample_ncpu,
            backend,
            censored,
        )| {
            LearnedState {
                ema_mem_kb: ema_mem,
                max_mem_kb: max_mem,
                ema_tmpfs_kb: ema_tmpfs,
                max_tmpfs_kb: max_tmpfs,
                ema_ncpu,
                max_ncpu,
                samples,
                sample_ncpu,
                backend: backend.as_deref().and_then(SampleBackend::parse),
                censored: censored != 0,
            }
        },
    ))
}

/// 学习面落列（写事务连接上执行）：upsert 只点名列 learned 组。
async fn upsert_learned_state_on(
    conn: &mut sqlx::AnyConnection,
    dialect: Dialect,
    product: &str,
    source_name: &str,
    arch: &str,
    state: &LearnedState,
) -> crate::Result<()> {
    // 浮点列 TEXT 绑定 + SQL CAST：绕开 Any 驱动 NULL 浮点钉 FLOAT4 的坑。
    let ema_ncpu = state.ema_ncpu.map(|v| v.to_string());
    let max_ncpu = state.max_ncpu.map(|v| v.to_string());
    sqlx::query(&sql::upsert_learned(dialect))
        .bind(product)
        .bind(source_name)
        .bind(arch)
        .bind(state.ema_mem_kb)
        .bind(state.max_mem_kb)
        .bind(state.ema_tmpfs_kb)
        .bind(state.max_tmpfs_kb)
        .bind(ema_ncpu)
        .bind(max_ncpu)
        .bind(state.samples)
        .bind(state.sample_ncpu)
        .bind(state.backend.map(SampleBackend::as_str))
        .bind(i64::from(state.censored))
        .execute(&mut *conn)
        .await
        .db_ctx("upsert profile learned state")?;
    Ok(())
}

/// 键合法性：三元组均非空（空串造出不可寻址的画像行；学习通道对空键防御
/// 跳过，声明通道 fail-closed 拒绝）。
fn validate_profile_key(product: &str, source_name: &str, arch: &str) -> crate::Result<()> {
    if product.is_empty() || source_name.is_empty() || arch.is_empty() {
        return Err(crate::error::CrbsError::ValidationFailed {
            message: "profile key (product, source_name, arch) must be non-empty".to_string(),
        });
    }
    Ok(())
}
