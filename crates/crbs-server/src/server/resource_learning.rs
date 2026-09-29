// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 终态资源样本 → 包资源画像学习。
//!
//! 两个终态来源共用本模块：分布式 worker 终态上报（`worker::routes::report_result`）
//! 与 hub 本地构建收尾（`routes::builds::enqueue::execute::execute_build`）。
//! reclaimer 重置 pending 的重试路径不触发学习（学习只挂终态）。
//! 全程 best-effort：失败仅 warn，不阻塞终态。

use std::sync::Arc;

use crate::server::state::AppState;

// ======== OOM 分类与画像学习接线 ========

/// OOM 归因阈值系数：cap 判定与"无 peak 时 mem_total 保守下界样本"共用
///（两处 0.9 同源；代码常量不配置化）。
const OOM_WATERMARK: f64 = 0.90;

/// cap-OOM 归因 note（软告警通道，error_summary 追加；UI 黄卡展示）。
const CAP_OOM_NOTE: &str = "\nwarning: build hit its own memory_max cap; \
                            the declared limit is likely too small for this package";

/// OOM 分类的纯输入：终态 phase + sanitize 后的终态采集值 + hub 侧换算的
/// 声明 cap 与节点内存总量。
#[derive(Debug, Clone, Copy, PartialEq)]
struct OomClassifyInput<'a> {
    /// 终态 phase（succeeded/failed/timeout/cancelled）。
    phase: &'a str,
    /// cgroup memory.events oom_kill 检出；None = 口径不可用（chroot / 未采集）。
    oom_killed: Option<bool>,
    /// memory.peak 总内存口径峰值 KB（含文件页缓存）。
    peak_total_kb: Option<i64>,
    /// anon 口径峰值 KB（sizing 主口径）。
    peak_rss_kb: Option<i64>,
    /// 任务声明 memory_max 换算 KB（None = 未声明 / "0" 无限 / 解析失败）。
    memory_max_kb: Option<i64>,
    /// 执行节点 mem_total KB（无 peak 时 node-OOM 保守下界样本的来源）。
    node_mem_total_kb: Option<i64>,
    /// 样本口径：proc 口径峰值是共享页重复计数的保守上界，不做 cap 阈值对比；
    /// None = 标签缺失（历史行 / 采样前即死），维持原 cap 判定逻辑。
    backend: Option<crbs_core::SampleBackend>,
}

/// OOM 分类决策（纯函数输出）。学习通道只消费 `Node`；cap-OOM 只计数 + 归因。
#[derive(Debug, Clone, Copy, PartialEq)]
enum OomDecision {
    /// 无 OOM 信号（oom_killed 非 true）：按原样走 succeeded/failed。
    None,
    /// succeeded 终态带 OOM：容量足够，不计数不学习。
    SuccessIgnored,
    /// 撞自身 memory_max 上限：计数 cap、归因 note、不进删失学习。
    Cap,
    /// 节点容量截断：计数 node、进删失学习；样本 KB 缺失时计数但不学习。
    Node { censor_sample_kb: Option<i64> },
    /// OOM 但无法归因（cap 已声明而两 peak 皆缺）：计数 unknown、不学习。
    Unknown,
}

impl OomDecision {
    /// 计数面 kind（None/SuccessIgnored 不进 `crbs_build_oom_total`）。
    fn kind(self) -> Option<crate::server::metrics::BuildOomKind> {
        match self {
            OomDecision::Cap => Some(crate::server::metrics::BuildOomKind::Cap),
            OomDecision::Node { .. } => Some(crate::server::metrics::BuildOomKind::Node),
            OomDecision::Unknown => Some(crate::server::metrics::BuildOomKind::Unknown),
            OomDecision::None | OomDecision::SuccessIgnored => None,
        }
    }
}

/// OOM 分类（纯函数，矩阵测试直喂）：
/// - 成功构建内子进程被 OOM 不算（终态成功说明容量足够）；
/// - proc 口径样本保守通道：峰值是共享页重复计数的保守上界，与 cgroup cap
///   阈值不同量纲（拿它对比会误判方向），跳过 cap 分支、oom_kill 事件单独
///   决定 node 通道；
/// - cap 判定先于 node：总内存口径峰值 ≥ 0.9×cap 即 cap-OOM（peak_total 缺失
///   时退 anon 口径 peak_rss；两 peak 皆缺无法判 cap → unknown）；
/// - 非 cap 的 OOM 只有 failed 终态才是 node-OOM（timeout 不参与学习，其 OOM
///   信号不计数）；
/// - 无 peak 的 node-OOM 以 mem_total×0.9 为保守下界样本（节点容量下界）。
fn classify_oom(input: &OomClassifyInput<'_>) -> OomDecision {
    if input.oom_killed != Some(true) {
        return OomDecision::None;
    }
    if input.phase == "succeeded" {
        return OomDecision::SuccessIgnored;
    }
    if input.backend == Some(crbs_core::SampleBackend::Proc) {
        return input.node_decision();
    }
    if let Some(cap_kb) = input.memory_max_kb {
        let threshold = (cap_kb as f64 * OOM_WATERMARK) as i64;
        // cap 口径用总内存峰值（memory.max 计入 file cache，anon 对比会漏判）；
        // peak_total 不可得退 anon，两皆缺记 unknown 不学习。
        let observed = input.peak_total_kb.or(input.peak_rss_kb);
        match observed {
            Some(peak) if peak >= threshold => return OomDecision::Cap,
            Some(_) => return input.node_decision(),
            None => return OomDecision::Unknown,
        }
    }
    input.node_decision()
}

impl OomClassifyInput<'_> {
    /// 非 cap 分支：node-OOM 要求终态 failed；样本取 anon 峰值，缺失退总内存
    /// 口径（删失下界偏保守方向），再缺按节点容量 0.9 兜底；全缺则只计数。
    fn node_decision(&self) -> OomDecision {
        if self.phase != "failed" {
            return OomDecision::None;
        }
        let censor_sample_kb = self.peak_rss_kb.or(self.peak_total_kb).or_else(|| {
            self.node_mem_total_kb
                .map(|m| (m as f64 * OOM_WATERMARK) as i64)
        });
        OomDecision::Node { censor_sample_kb }
    }
}

/// request_json 里的任务级 memory_max → KB：cap-OOM 判定输入。解析/换算失败
/// 降 None（按未声明处理走向 node 通道——提交期已过 validate_memory_max，
/// 此处失败只能是库内手工数据，保守不归因）。
fn request_memory_max_kb(request_json: &str) -> Option<i64> {
    #[derive(serde::Deserialize)]
    struct RequestCap {
        #[serde(default)]
        memory_max: Option<String>,
    }
    let cap: RequestCap = serde_json::from_str(request_json).ok()?;
    let raw = cap.memory_max?;
    match crbs_core::config::parse_memory_max_kb(&raw) {
        // "0" = 无限制，不构成 cap。
        Ok(kb) if kb > 0 => Some(kb),
        Ok(_) => None,
        Err(e) => {
            tracing::debug!(error = %e, "request_json memory_max unparseable; treating as unset");
            None
        }
    }
}

/// 学习样本主口径：worker 上报的 sample_backend 优先；缺字段按构建实际
/// backend 列推导——'nspawn' 必在 cgroup 限制域（cgroup 口径）、'chroot'
/// 无 cgroup（/proc 口径）；其余防御跳过（不学习）。
/// v1 `memory.stat` `total_rss` 样本与 v2 anon 同报 'cgroup'（量纲对齐）；存量
/// proc 口径画像行遇 cgroup 样本走升级重置清零重学，部署期画像行重置兜底 sticky 冲突。
fn sample_backend_of(
    resources: &crbs_core::engine::ResourceUsage,
    build_backend: Option<&str>,
) -> Option<crbs_core::SampleBackend> {
    if let Some(b) = resources.sample_backend {
        return crbs_core::SampleBackend::parse(b);
    }
    match build_backend {
        Some("nspawn") => Some(crbs_core::SampleBackend::Cgroup),
        Some("chroot") => Some(crbs_core::SampleBackend::Proc),
        _ => None,
    }
}

// ======== 学习入口（两个终态来源共用）========

/// node-OOM 无 peak 时保守下界样本的内存总量来源。
#[derive(Debug, Clone, Copy)]
pub(crate) enum NodeMemSource {
    /// 分布式 worker：读 workers 表心跳 mem_total_kb。
    Worker(i64),
    /// hub 本地构建：读本机 /proc/meminfo MemTotal。
    HubLocal,
}

async fn resolve_node_mem_total(app: &Arc<AppState>, source: NodeMemSource) -> Option<i64> {
    match source {
        NodeMemSource::Worker(worker_id) => match app.state_store.get_worker(worker_id).await {
            Ok(Some(w)) => w.mem_total_kb,
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    worker_id = %worker_id,
                    error = %e,
                    "Failed to load worker mem_total for node-OOM sample; conservative sample unavailable"
                );
                None
            }
        },
        NodeMemSource::HubLocal => match tokio::fs::read_to_string("/proc/meminfo").await {
            Ok(meminfo) => match crate::server::scheduler::parse_proc_mem_total_kb(&meminfo) {
                Some(total) => Some(total),
                None => {
                    tracing::warn!(
                        "Failed to parse /proc/meminfo MemTotal for node-OOM sample; conservative sample unavailable"
                    );
                    None
                }
            },
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to read /proc/meminfo for node-OOM sample; conservative sample unavailable"
                );
                None
            }
        },
    }
}

/// 构建行资源列 → `ResourceUsage`（hub 本地构建学习样本回读；与 worker 上报
/// 经 `sanitize_resources` 落库的列一一同构）。全 NULL → None（无观测不学习）。
pub(crate) fn record_resources(
    rec: &crbs_core::BuildRecord,
) -> Option<crbs_core::engine::ResourceUsage> {
    let sample_backend = rec.sample_backend.as_deref().and_then(|b| match b {
        crbs_core::engine::SAMPLE_BACKEND_CGROUP => Some(crbs_core::engine::SAMPLE_BACKEND_CGROUP),
        crbs_core::engine::SAMPLE_BACKEND_PROC => Some(crbs_core::engine::SAMPLE_BACKEND_PROC),
        _ => None,
    });
    let usage = crbs_core::engine::ResourceUsage {
        peak_rss_kb: rec.peak_rss_kb,
        cpu_secs: rec.cpu_secs,
        cpu_p90_cores: rec.cpu_p90_cores,
        peak_total_kb: rec.peak_total_kb,
        disk_wbytes: rec.disk_wbytes,
        oom_killed: rec.oom_killed,
        sample_backend,
        sample_ncpu: rec.sample_ncpu,
        peak_tmpfs_kb: rec.peak_tmpfs_kb,
    };
    (usage != crbs_core::engine::ResourceUsage::default()).then_some(usage)
}

/// 终态学习统一入口：写画像 → 失效调度权重缓存的固定顺序收口。
///
/// 顺序不变量：失效必须在学习写入之后。反序时并发 tick 可能在两步之间把
/// 旧权重回填缓存，新 EMA 样本要等 TTL（5min）才对派发可见。
pub(crate) async fn apply_terminal_learning(
    app: &Arc<AppState>,
    rec: &crbs_core::BuildRecord,
    phase: &str,
    resources: Option<&crbs_core::engine::ResourceUsage>,
    node_mem: NodeMemSource,
) {
    apply_profile_learning(app, rec, phase, resources, node_mem).await;
    // 画像键 = 源码包基础名（builds.name），版本不参与。
    app.resource_weight_cache.invalidate(
        &rec.product,
        &rec.name,
        rec.arch.as_deref().unwrap_or_default(),
    );
}

/// 终态样本喂入画像学习面（best-effort：失败仅 warn 不阻塞终态）。
/// 调用点 = 终态写入成功后（worker 上报 / hub 本地收尾）；失败重试路径
///（reclaimer 重置 pending）不经过此处——学习只挂终态。
async fn apply_profile_learning(
    app: &Arc<AppState>,
    rec: &crbs_core::BuildRecord,
    phase: &str,
    resources: Option<&crbs_core::engine::ResourceUsage>,
    node_mem: NodeMemSource,
) {
    // 取消不是执行方的能力度量（resources 恒 None），显式短路防御。
    if phase == "cancelled" {
        return;
    }
    // 无资源观测：无样本无信号，不学习不计数。
    let Some(resources) = resources else {
        return;
    };

    if phase == "succeeded" {
        // EMA 只折叠内存观测完备的成功样本（peak_rss 是学习样本主键：缺该维
        // 的样本整行不学，tmpfs 维不单独建行——影子门按未学习放行）；成功
        // 构建内子进程被 OOM 不算容量截断（终态成功说明容量足够），峰值
        // 照常折叠 EMA——不进 OOM 分类计数（分类只在 failed/timeout 分支做）。
        let Some(peak_rss_kb) = resources.peak_rss_kb else {
            return;
        };
        let Some(backend) = sample_backend_of(resources, rec.backend.as_deref()) else {
            tracing::debug!(
                build_id = %rec.id,
                "profile learning skipped: sample backend undeterminable"
            );
            return;
        };
        feed_learning(
            app,
            rec,
            &crbs_core::ResourceSampleOutcome::Succeeded {
                backend,
                peak_rss_kb,
                peak_tmpfs_kb: resources.peak_tmpfs_kb,
                cpu_p90_cores: resources.cpu_p90_cores,
                sample_ncpu: resources.sample_ncpu,
            },
        )
        .await;
        warn_declared_deviation(app, rec, peak_rss_kb).await;
        return;
    }

    // failed/timeout：仅 OOM 检出才有分类；普通失败不参与学习。
    if resources.oom_killed != Some(true) {
        return;
    }
    // cap 判定输入：request_json 的 memory_max + 节点内存总量（后者仅无 peak
    // 的删失样本兜底用，终态一次行查成本可忽略）。
    let memory_max_kb = match app.state_store.get_build_request_json(rec.id).await {
        Ok(json) => json.as_deref().and_then(request_memory_max_kb),
        Err(e) => {
            tracing::warn!(
                build_id = %rec.id,
                error = %e,
                "Failed to load request_json for cap-OOM check; treating as unset"
            );
            None
        }
    };
    let node_mem_total_kb = resolve_node_mem_total(app, node_mem).await;
    let decision = classify_oom(&OomClassifyInput {
        phase,
        oom_killed: resources.oom_killed,
        peak_total_kb: resources.peak_total_kb,
        peak_rss_kb: resources.peak_rss_kb,
        memory_max_kb,
        node_mem_total_kb,
        backend: sample_backend_of(resources, rec.backend.as_deref()),
    });

    if let Some(kind) = decision.kind() {
        app.metrics.incr_build_oom(kind);
    }
    match decision {
        OomDecision::Cap => {
            // 撞 cap 是用户配置问题：不进删失学习（更大节点一样撞），归因走
            // 软告警 note 通道（failed 的 error_summary 是失败摘要，note 追加
            // 不覆盖，UI 层已有黄卡/失败摘要区分）。
            app.metrics
                .incr_profile_update(crate::server::metrics::ProfileUpdateKind::CapHitExcluded);
            if let Err(e) = app
                .state_store
                .append_build_note(rec.id, CAP_OOM_NOTE)
                .await
            {
                tracing::warn!(
                    build_id = %rec.id,
                    error = %e,
                    "Failed to append cap-OOM attribution note"
                );
            }
        }
        OomDecision::Node {
            censor_sample_kb: Some(sample_kb),
        } => {
            let Some(backend) = sample_backend_of(resources, rec.backend.as_deref()) else {
                tracing::debug!(
                    build_id = %rec.id,
                    "profile censoring skipped: sample backend undeterminable"
                );
                return;
            };
            feed_learning(
                app,
                rec,
                &crbs_core::ResourceSampleOutcome::NodeOom {
                    backend,
                    peak_rss_kb: sample_kb,
                    peak_tmpfs_kb: resources.peak_tmpfs_kb,
                    cpu_p90_cores: resources.cpu_p90_cores,
                    sample_ncpu: resources.sample_ncpu,
                },
            )
            .await;
        }
        // 无样本可删失（无 peak 且节点 mem_total 未知）：计数留痕、不学习。
        OomDecision::Node {
            censor_sample_kb: None,
        } => {
            tracing::debug!(
                build_id = %rec.id,
                "node-OOM without any memory sample; counted but not learned"
            );
        }
        // unknown 已计数；None/SuccessIgnored 无动作。
        OomDecision::Unknown | OomDecision::None | OomDecision::SuccessIgnored => {}
    }
}

/// apply 包装：best-effort（失败仅 warn）、决策映射 `crbs_profile_updates_total`
/// 计数（Skipped = 轻包门槛以下 / sticky 忽略 / 空键，不计数）。
async fn feed_learning(
    app: &Arc<AppState>,
    rec: &crbs_core::BuildRecord,
    outcome: &crbs_core::ResourceSampleOutcome,
) {
    let min_peak_rss_kb = Some(app.server_config.resource_profile_min_peak_rss_kb);
    let headroom = app.server_config.resource_censor_headroom;
    // arch 空（历史行）由 apply 层防御跳过（决策 Skipped）。
    let arch = rec.arch.as_deref().unwrap_or("");
    match app
        .state_store
        .apply_learning_sample(
            &rec.product,
            &rec.name,
            arch,
            outcome,
            min_peak_rss_kb,
            headroom,
        )
        .await
    {
        Ok(decision) => match decision {
            crbs_core::ProfileUpdateDecision::Skipped => {}
            crbs_core::ProfileUpdateDecision::Learned => app
                .metrics
                .incr_profile_update(crate::server::metrics::ProfileUpdateKind::Learned),
            crbs_core::ProfileUpdateDecision::Censored => app
                .metrics
                .incr_profile_update(crate::server::metrics::ProfileUpdateKind::Censored),
            crbs_core::ProfileUpdateDecision::Reset => app
                .metrics
                .incr_profile_update(crate::server::metrics::ProfileUpdateKind::Reset),
            crbs_core::ProfileUpdateDecision::CapHitExcluded => app
                .metrics
                .incr_profile_update(crate::server::metrics::ProfileUpdateKind::CapHitExcluded),
        },
        Err(e) => tracing::warn!(
            build_id = %rec.id,
            product = %rec.product,
            pkg = %rec.pkg_name,
            error = %e,
            "Failed to apply resource profile learning sample (terminal state unaffected)"
        ),
    }
}

/// 偏差告警单向阈值：实测峰值 > 声明 × 1.5 → 构建 note
/// 提示声明过低；反向（声明远高于实测）不告警——故意余量是路由指令。
const DECLARED_DEVIATION_FACTOR: f64 = 1.5;

/// 偏差单向告警（best-effort，失败仅 warn 不阻塞终态）：succeeded 样本的
/// 实测峰值对照本构建**生效的**放置内存下限——任务级 `req_min_mem_kb` 优先，
/// 其次 declared 精确 arch → 'any' 回退（与调度硬下限解析链同源），
/// 超阈值追加 build note 走 error_summary 黄卡通道。
async fn warn_declared_deviation(
    app: &Arc<AppState>,
    rec: &crbs_core::BuildRecord,
    peak_rss_kb: i64,
) {
    let min_mem_kb = match rec.req_min_mem_kb {
        Some(task_min) => Some(task_min),
        None => {
            let arch = rec.arch.as_deref().unwrap_or("");
            match app
                .state_store
                .find_declared_requirements(&rec.product, &rec.name, arch)
                .await
            {
                Ok(d) => d.and_then(|d| d.min_mem_kb),
                Err(e) => {
                    tracing::warn!(
                        build_id = %rec.id,
                        error = %e,
                        "Failed to load declared requirements for deviation check"
                    );
                    return;
                }
            }
        }
    };
    let Some(min_mem_kb) = min_mem_kb else {
        return;
    };
    if (peak_rss_kb as f64) <= min_mem_kb as f64 * DECLARED_DEVIATION_FACTOR {
        return;
    }
    let note = format!(
        "\nwarning: measured peak rss {peak_rss_kb} KB exceeds the effective placement \
         min_mem {min_mem_kb} KB by more than {}x; the placement floor looks too low",
        DECLARED_DEVIATION_FACTOR
    );
    if let Err(e) = app.state_store.append_build_note(rec.id, &note).await {
        tracing::warn!(
            build_id = %rec.id,
            error = %e,
            "Failed to append declared-deviation note"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ======== OOM 分类器决策矩阵（纯函数）========

    /// 矩阵基线输入构造器：oom_killed=true 的 failed 终态，其余缺省。
    fn oom_input(phase: &str) -> OomClassifyInput<'_> {
        OomClassifyInput {
            phase,
            oom_killed: Some(true),
            peak_total_kb: None,
            peak_rss_kb: None,
            memory_max_kb: None,
            node_mem_total_kb: None,
            backend: None,
        }
    }

    #[test]
    fn oom_classifier_matrix() {
        use OomDecision as D;

        // 无信号：oom_killed 缺失 / false 一律 None（chroot / 未采集）。
        for oom in [None, Some(false)] {
            let mut i = oom_input("failed");
            i.oom_killed = oom;
            assert_eq!(classify_oom(&i), D::None);
        }

        // 成功构建内子进程被 OOM：容量足够，不计数不学习（即便峰值超 cap 阈值）。
        let mut i = oom_input("succeeded");
        i.memory_max_kb = Some(1000);
        i.peak_total_kb = Some(5000);
        assert_eq!(classify_oom(&i), D::SuccessIgnored);

        // cap-OOM：总内存口径峰值 ≥ 0.9×cap；峰值低则走 node 分支。
        let mut i = oom_input("failed");
        i.memory_max_kb = Some(1000);
        i.peak_total_kb = Some(900);
        assert_eq!(classify_oom(&i), D::Cap);
        let mut i = oom_input("failed");
        i.memory_max_kb = Some(1000);
        i.peak_total_kb = Some(899);
        i.peak_rss_kb = Some(500);
        assert_eq!(
            classify_oom(&i),
            D::Node {
                censor_sample_kb: Some(500)
            }
        );

        // peak_total 缺失退 anon 口径（memory.max 计入 file cache，只能向前退）。
        let mut i = oom_input("failed");
        i.memory_max_kb = Some(1000);
        i.peak_rss_kb = Some(900);
        assert_eq!(classify_oom(&i), D::Cap);
        let mut i = oom_input("failed");
        i.memory_max_kb = Some(1000);
        i.peak_rss_kb = Some(899);
        assert_eq!(
            classify_oom(&i),
            D::Node {
                censor_sample_kb: Some(899)
            }
        );

        // cap 已声明而两 peak 皆缺：无法判 cap → unknown，不学习。
        let mut i = oom_input("failed");
        i.memory_max_kb = Some(1000);
        assert_eq!(classify_oom(&i), D::Unknown);

        // cap 命中不看终态词汇（failed/timeout 都归因）；timeout 非 cap 不进
        // node 通道（node-OOM 只定义 failed 通道）。
        let mut i = oom_input("timeout");
        i.memory_max_kb = Some(1000);
        i.peak_total_kb = Some(900);
        assert_eq!(classify_oom(&i), D::Cap);
        let mut i = oom_input("timeout");
        i.memory_max_kb = Some(1000);
        i.peak_total_kb = Some(899);
        assert_eq!(classify_oom(&i), D::None);
        assert_eq!(classify_oom(&oom_input("timeout")), D::None);

        // 无 cap 的 node-OOM：failed 才进删失；样本 anon 优先 → 总内存口径 →
        // mem_total×0.9 保守下界；全缺只计数不学习。
        let mut i = oom_input("failed");
        i.peak_rss_kb = Some(500);
        i.peak_total_kb = Some(600);
        assert_eq!(
            classify_oom(&i),
            D::Node {
                censor_sample_kb: Some(500)
            }
        );
        let mut i = oom_input("failed");
        i.peak_total_kb = Some(600);
        assert_eq!(
            classify_oom(&i),
            D::Node {
                censor_sample_kb: Some(600)
            }
        );
        let mut i = oom_input("failed");
        i.node_mem_total_kb = Some(1000);
        assert_eq!(
            classify_oom(&i),
            D::Node {
                censor_sample_kb: Some(900)
            }
        );
        assert_eq!(
            classify_oom(&oom_input("failed")),
            D::Node {
                censor_sample_kb: None
            }
        );

        // cgroup 口径样本维持原 cap 判定：peak_total ≥ 0.9×cap 归 Cap。
        let mut i = oom_input("failed");
        i.backend = Some(crbs_core::SampleBackend::Cgroup);
        i.memory_max_kb = Some(1000);
        i.peak_total_kb = Some(900);
        assert_eq!(classify_oom(&i), D::Cap);

        // proc 口径样本保守通道：峰值是共享页重复计数上界，与 cap 阈值不同量纲，
        // 跳过 cap 分支——即便峰值远超 0.9×cap 也走 node 通道（failed 才删失）。
        let mut i = oom_input("failed");
        i.backend = Some(crbs_core::SampleBackend::Proc);
        i.memory_max_kb = Some(1000);
        i.peak_total_kb = Some(5000);
        i.peak_rss_kb = Some(4000);
        assert_eq!(
            classify_oom(&i),
            D::Node {
                censor_sample_kb: Some(4000)
            }
        );
        // proc 口径 timeout 终态：不进 node 通道（node-OOM 只定义 failed 通道）。
        let mut i = oom_input("timeout");
        i.backend = Some(crbs_core::SampleBackend::Proc);
        i.memory_max_kb = Some(1000);
        i.peak_total_kb = Some(5000);
        assert_eq!(classify_oom(&i), D::None);
        // proc 口径两 peak 皆缺：failed 只计数不学习（无 mem_total 时）。
        let mut i = oom_input("failed");
        i.backend = Some(crbs_core::SampleBackend::Proc);
        i.memory_max_kb = Some(1000);
        assert_eq!(
            classify_oom(&i),
            D::Node {
                censor_sample_kb: None
            }
        );
    }

    /// request_json memory_max 解析：合法后缀换算 KB、"0"/缺键按未声明、
    /// 非法 JSON / 非法值防御降 None。
    #[test]
    fn request_memory_max_kb_matrix() {
        assert_eq!(
            request_memory_max_kb(r#"{"backend":"nspawn","memory_max":"1G"}"#),
            Some(1_048_576)
        );
        assert_eq!(
            request_memory_max_kb(r#"{"memory_max":"512M"}"#),
            Some(524_288)
        );
        assert_eq!(
            request_memory_max_kb(r#"{"memory_max":"1048576"}"#),
            Some(1024)
        );
        // "0" = 无限制 → 未声明。
        assert_eq!(request_memory_max_kb(r#"{"memory_max":"0"}"#), None);
        assert_eq!(request_memory_max_kb(r#"{"backend":"chroot"}"#), None);
        assert_eq!(request_memory_max_kb("not-json"), None);
        assert_eq!(
            request_memory_max_kb(r#"{"memory_max":"4X"}"#),
            None,
            "提交期校验漏网的库内手工数据：解析失败按未声明保守处理"
        );
    }

    /// 构建行资源列 → ResourceUsage：全 NULL = None，sample_backend 白名单外
    /// 降 None，8 列逐一映射。
    #[test]
    fn record_resources_maps_row_columns() {
        let rec = sample_record();
        assert_eq!(
            record_resources(&rec),
            None,
            "all-NULL resource columns must map to no sample"
        );

        let mut rec = sample_record();
        rec.peak_rss_kb = Some(1_000_000);
        rec.peak_total_kb = Some(1_200_000);
        rec.cpu_secs = Some(9.5);
        rec.cpu_p90_cores = Some(2.5);
        rec.disk_wbytes = Some(42);
        rec.oom_killed = Some(false);
        rec.sample_backend = Some("cgroup".into());
        rec.sample_ncpu = Some(16);
        assert_eq!(
            record_resources(&rec),
            Some(crbs_core::engine::ResourceUsage {
                peak_rss_kb: Some(1_000_000),
                peak_total_kb: Some(1_200_000),
                cpu_secs: Some(9.5),
                cpu_p90_cores: Some(2.5),
                disk_wbytes: Some(42),
                oom_killed: Some(false),
                sample_backend: Some(crbs_core::engine::SAMPLE_BACKEND_CGROUP),
                sample_ncpu: Some(16),
                peak_tmpfs_kb: None,
            })
        );

        let mut rec = sample_record();
        rec.peak_rss_kb = Some(1);
        rec.sample_backend = Some("bogus".into());
        assert_eq!(
            record_resources(&rec).and_then(|u| u.sample_backend),
            None,
            "unknown sample_backend must be dropped, not passed through"
        );
    }

    /// 最小构建行（资源列全 NULL）；仅 record_resources 测试消费。
    fn sample_record() -> crbs_core::BuildRecord {
        crbs_core::BuildRecord {
            id: 1,
            product: "p".into(),
            pkg_name: "k".into(),
            name: "k".into(),
            version: "1".into(),
            release: "1".into(),
            phase: "succeeded".into(),
            result_dir: None,
            srpm_path: None,
            started_at: None,
            completed_at: None,
            duration: None,
            layer_digest: None,
            base_os_digest: None,
            backend: Some("nspawn".into()),
            user: "u".into(),
            user_id: None,
            crbs_pid: None,
            arch: Some("x86_64".into()),
            task_id: Some(1),
            rpms: Vec::new(),
            signed: false,
            priority: crbs_core::PRIORITY_DEFAULT,
            error_summary: None,
            deterministic: false,
            repo_publish: false,
            repo_consume: true,
            canonical_srpm_sha256: None,
            peak_rss_kb: None,
            peak_total_kb: None,
            cpu_secs: None,
            cpu_p90_cores: None,
            disk_wbytes: None,
            oom_killed: None,
            sample_backend: None,
            sample_ncpu: None,
            peak_tmpfs_kb: None,
            req_min_mem_kb: None,
            req_min_ncpu: None,
            req_min_disk_kb: None,
        }
    }
}
