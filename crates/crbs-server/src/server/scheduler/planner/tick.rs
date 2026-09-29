// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! tick 主循环：快照加载、逐候选决策落点、CAS 实派发与归因推进。

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crbs_core::{DeclaredRequirements, DispatchCandidate, WorkerStatus};
use tracing::{debug, info, warn};

use super::super::{
    committed_from_active, load_resource_profiles, profile_key, sort_workers_for_dispatch,
    AdmitWatermarks, CommittedLoad, ProfileKey, ResourceProfileMap,
};
use super::{
    decide_candidate, is_heavy_candidate, per_tick_refill_cap, record_shadow_decision,
    watermark_dimension_metric, DecideCandidateInput, EffectiveHardReq, HardReqDimension,
    PlannerDecision, RejectReason, DISPATCH_CANDIDATE_LIMIT,
};
use crate::server::metrics::DispatchRejectDimension;
use crate::server::state::AppState;
use crate::server::worker::dispatch::notify_workers;

// ===== tick 主循环 =====

/// tick 序号源（决策日志关联字段；进程内单调）。
static TICK_SEQ: AtomicU64 = AtomicU64::new(0);

fn next_tick_seq() -> u64 {
    TICK_SEQ.fetch_add(1, Ordering::Relaxed)
}

/// 单 tick 输入快照：候选 × 已排序 worker × 容量/Σ/init 门内存态 × 批量画像
/// × 批量声明（硬下限回退源，requirements 关时不加载）。
struct TickContext {
    candidates: Vec<DispatchCandidate>,
    workers: Vec<WorkerStatus>,
    active: HashMap<i64, i64>,
    committed: HashMap<i64, CommittedLoad>,
    /// worker_id → 核数（CPU 权重按节点折算与派发后 Σ 推进共用）。
    worker_ncpu: HashMap<i64, i64>,
    /// worker_id → 本 tick 新增派发上限（refill 平滑，见
    /// [`per_tick_refill_cap`]）；派发循环按 worker 独立计数消费。
    refill_cap: HashMap<i64, i64>,
    init_by_worker: HashMap<i64, HashSet<String>>,
    profiles: ResourceProfileMap,
    declared: HashMap<ProfileKey, DeclaredRequirements>,
}

/// 加载 tick 快照；`None` = 无需决策（无在线 worker / 全忙短路 / 无候选）。
/// 全忙短路在候选查询之前（所有 worker 无空槽时跳过候选查询）。
async fn load_tick_context(app: &Arc<AppState>) -> crbs_core::Result<Option<TickContext>> {
    let workers = app.state_store.list_online_workers(None).await?;
    if workers.is_empty() {
        return Ok(None);
    }
    let active = app.state_store.count_active_tasks_by_worker().await?;
    if workers
        .iter()
        .all(|w| active.get(&w.id).copied().unwrap_or(0) >= w.capacity)
    {
        return Ok(None);
    }
    let candidates = app
        .state_store
        .list_pending_dispatch_candidates(DISPATCH_CANDIDATE_LIMIT)
        .await?;
    if candidates.is_empty() {
        return Ok(None);
    }

    let mut workers = workers;
    sort_workers_for_dispatch(&mut workers, &active);

    let refill_cap: HashMap<i64, i64> = workers
        .iter()
        .map(|w| (w.id, per_tick_refill_cap(w.capacity)))
        .collect();

    let mut init_by_worker: HashMap<i64, HashSet<String>> = HashMap::new();
    for (worker_id, product) in app.state_store.list_active_init_worker_products().await? {
        init_by_worker.entry(worker_id).or_default().insert(product);
    }

    // 批量画像：在跑键 ∪ 候选键一次回源（Σ 折算与候选权重同源同批，禁 N+1）。
    // 供数限爬坡窗口（见 COMMITTED_RAMP_SECS），防在跑权重在 load1 双计。
    let active_rows = app
        .state_store
        .list_worker_active_build_pkgs(super::super::COMMITTED_RAMP_SECS)
        .await?;
    let mut keys: Vec<ProfileKey> = active_rows
        .iter()
        .map(|(_, product, source, arch)| profile_key(product, source, arch.as_deref()))
        .collect();
    keys.extend(
        candidates
            .iter()
            .map(|c| profile_key(&c.product, &c.source_name, c.arch.as_deref())),
    );
    let profiles = load_resource_profiles(app, keys).await;
    let worker_ncpu: HashMap<i64, i64> = workers
        .iter()
        .filter_map(|w| w.ncpu.map(|n| (w.id, n)))
        .collect();
    let committed = committed_from_active(&active_rows, &profiles, &worker_ncpu);

    // 批量声明（硬下限逐维回退源）：requirements 关时整段跳过。
    let declared = if app.server_config.resource_requirements_enabled {
        let declared_keys: Vec<ProfileKey> = candidates
            .iter()
            .map(|c| profile_key(&c.product, &c.source_name, c.arch.as_deref()))
            .collect();
        app.state_store
            .declared_requirements_batch(&declared_keys)
            .await?
    } else {
        HashMap::new()
    };

    Ok(Some(TickContext {
        candidates,
        workers,
        active,
        committed,
        worker_ncpu,
        refill_cap,
        init_by_worker,
        profiles,
        declared,
    }))
}

/// 单候选决策 + 归因/指标落点，返回 (决策, heavy steering 判定)——落位
/// 打点按 steer_heavy 区分（见 [`assign_candidate`]）。硬下限解析（逐维：
/// builds.req_* 显式 > declared 声明 > 无）在批量加载的 ctx.declared 上内存
/// 回退；requirements 关时 req 恒空、过滤段自然跳过。
async fn decide_with_telemetry(
    app: &Arc<AppState>,
    candidate: &DispatchCandidate,
    ctx: &TickContext,
) -> (PlannerDecision, bool) {
    let key = profile_key(
        &candidate.product,
        &candidate.source_name,
        candidate.arch.as_deref(),
    );
    let profile = ctx.profiles.get(&key).copied().unwrap_or_default();
    let declared = ctx.declared.get(&key);
    let hard_req = if app.server_config.resource_requirements_enabled {
        EffectiveHardReq {
            min_mem_kb: candidate
                .req_min_mem_kb
                .or(declared.and_then(|d| d.min_mem_kb)),
            min_ncpu: candidate.req_min_ncpu.or(declared.and_then(|d| d.min_ncpu)),
            min_disk_kb: candidate
                .req_min_disk_kb
                .or(declared.and_then(|d| d.min_disk_kb)),
        }
    } else {
        EffectiveHardReq::default()
    };
    let first_reject_age = app
        .dispatch_attribution
        .get(candidate.id)
        .and_then(|a| a.first_watermark_reject_at)
        .map(|t| t.elapsed());
    // heavy steering：开关关时判定整体短路，决策路径与既有序首路径逐位一致。
    let steer_heavy = app.server_config.resource_steering_enabled
        && is_heavy_candidate(
            &hard_req,
            &profile.weight,
            candidate.srpm_size_bytes,
            app.server_config.resource_heavy_srpm_bytes,
        );
    let decision = decide_candidate(DecideCandidateInput {
        candidate,
        profile,
        hard_req,
        workers: &ctx.workers,
        active: &ctx.active,
        committed: &ctx.committed,
        init_by_worker: &ctx.init_by_worker,
        first_watermark_reject_age: first_reject_age,
        steer_heavy,
        watermark_enabled: app.server_config.resource_dispatch_watermark_enabled,
        watermarks: AdmitWatermarks::from_config(&app.server_config),
        tmpfs_gate_enforced: app.server_config.resource_tmpfs_gate_enforced,
    });
    match decision {
        PlannerDecision::Dispatch { .. } | PlannerDecision::SoftFallback { .. } => {}
        PlannerDecision::NoFit { reason } => {
            // 硬下限拒绝按触发维细分指标（mem|ncpu|disk）；其余 no_fit
            // 聚合（架构/容量/init 门细分归归因内存态）。
            let dimension = match reason {
                RejectReason::NoFitHardReq { dimension } => dimension,
                _ => {
                    app.metrics
                        .incr_dispatch_admit_reject(DispatchRejectDimension::NoFit);
                    app.dispatch_attribution.record_no_fit(candidate.id, reason);
                    debug!(
                        build_id = %candidate.id,
                        pkg = %candidate.pkg_name,
                        reason = reason.as_str(),
                        "Planner no-fit attribution"
                    );
                    return (decision, steer_heavy);
                }
            };
            app.metrics
                .incr_dispatch_admit_reject(hard_req_dimension_metric(dimension));
            app.dispatch_attribution.record_no_fit(candidate.id, reason);
            debug!(
                build_id = %candidate.id,
                pkg = %candidate.pkg_name,
                dimension = dimension.as_str(),
                "Planner hard-floor reject attribution"
            );
            notify_hard_req_stall(app, candidate, dimension, &hard_req, "distributed").await;
        }
        PlannerDecision::WatermarkBlocked {
            dimension,
            head_load,
        } => {
            app.metrics
                .incr_dispatch_admit_reject(watermark_dimension_metric(dimension));
            app.dispatch_attribution
                .record_water_reject(candidate.id, dimension, head_load);
            debug!(
                build_id = %candidate.id,
                pkg = %candidate.pkg_name,
                dimension = ?dimension,
                head_mem_kb = head_load.mem_kb,
                head_cpu_cores = head_load.cpu_cores,
                "Planner watermark reject attribution"
            );
        }
    }
    (decision, steer_heavy)
}

/// 硬下限维度 → 指标 label（`dimension=mem|ncpu|disk`）。
pub(crate) fn hard_req_dimension_metric(dimension: HardReqDimension) -> DispatchRejectDimension {
    match dimension {
        HardReqDimension::Mem => DispatchRejectDimension::Mem,
        HardReqDimension::Ncpu => DispatchRejectDimension::Ncpu,
        HardReqDimension::Disk => DispatchRejectDimension::Disk,
    }
}

/// 硬下限声明摘要（停滞 note 的可复核内容）。
fn floor_summary(req: &EffectiveHardReq) -> String {
    let mut parts = Vec::new();
    if let Some(v) = req.min_mem_kb {
        parts.push(format!("mem={v}KB"));
    }
    if let Some(v) = req.min_ncpu {
        parts.push(format!("ncpu={v}"));
    }
    if let Some(v) = req.min_disk_kb {
        parts.push(format!("disk={v}KB"));
    }
    parts.join(" ")
}

/// 硬下限停滞提示：首次硬下限拒绝持续超过 `resource_hard_req_stall_secs`
/// 后落一条 note——声明超集群能力时构建会永久 pending，只有 UI 徽章不足以
/// 让人发现。每个构建只落一次（内存标记，重启复位；重复 note 幂等可容忍）。
/// `source` 区分触发路径（分布式 planner / hub 本地取件）。
pub(crate) async fn notify_hard_req_stall(
    app: &Arc<AppState>,
    candidate: &DispatchCandidate,
    dimension: HardReqDimension,
    req: &EffectiveHardReq,
    source: &str,
) {
    let stall_secs = app.server_config.resource_hard_req_stall_secs;
    if stall_secs == 0 {
        return;
    }
    let Some(age) = app
        .dispatch_attribution
        .get(candidate.id)
        .and_then(|a| a.first_hard_req_reject_at)
        .map(|t| t.elapsed())
    else {
        return;
    };
    if age < std::time::Duration::from_secs(stall_secs) {
        return;
    }
    if !app
        .dispatch_attribution
        .mark_hard_req_stall_noted(candidate.id)
    {
        return;
    }
    let note = format!(
        "\nwarning: resource floor not satisfiable by any online worker \
         (dimension={}, {}; {source} scheduler); build stays pending until a \
         capable worker joins — cancel it if the floor is wrong",
        dimension.as_str(),
        floor_summary(req),
    );
    if let Err(e) = app.state_store.append_build_note(candidate.id, &note).await {
        warn!(
            build_id = %candidate.id,
            error = %e,
            "Failed to append hard-floor stall note; will retry on next tick"
        );
        app.dispatch_attribution
            .unmark_hard_req_stall_noted(candidate.id);
    } else {
        warn!(
            build_id = %candidate.id,
            pkg = %candidate.pkg_name,
            dimension = dimension.as_str(),
            age_secs = age.as_secs(),
            "Hard-floor stall note appended"
        );
    }
}

/// 实派发指定候选到指定 worker（CAS 失败 = 被抢/谓词失效，归因保持原样，
/// 调用方继续下一候选）；成功推进内存态（Σ/空槽/归因清除）供同 tick 后续
/// 候选立即可见。`fallback` = censored 兜底（补 note + 指标）；`steer_heavy`
/// = heavy steering 判定命中（落位打点，见 [`crate::server::metrics`] 计数
/// 之外的结构化验证日志）。
async fn assign_candidate(
    app: &Arc<AppState>,
    ctx: &mut TickContext,
    candidate: &DispatchCandidate,
    worker_id: i64,
    fallback: bool,
    steer_heavy: bool,
    tick_seq: u64,
) -> crbs_core::Result<bool> {
    let profile = ctx
        .profiles
        .get(&profile_key(
            &candidate.product,
            &candidate.source_name,
            candidate.arch.as_deref(),
        ))
        .copied()
        .unwrap_or_default();
    let Some(assignment) = app
        .state_store
        .assign_specific_build_to_worker(candidate.id, worker_id)
        .await?
    else {
        return Ok(false);
    };

    let ncpu = ctx.worker_ncpu.get(&worker_id).copied();
    {
        let committed = ctx.committed.entry(worker_id).or_default();
        committed.add(&profile.weight, ncpu);
    }
    *ctx.active.entry(worker_id).or_insert(0) += 1;
    app.dispatch_attribution.clear(candidate.id);

    if fallback {
        app.metrics.incr_soft_fallbacks();
        // 软告警通道：note → error_summary → 详情页黄卡（现有机制零 UI 改动）。
        if let Err(e) = app
            .state_store
            .append_build_note(
                candidate.id,
                "\nwarning: soft watermark fallback (censored build past 30min of full watermark rejection; dispatched to max-headroom worker)",
            )
            .await
        {
            warn!(
                build_id = %candidate.id,
                error = %e,
                "Failed to append soft fallback note"
            );
        }
    }
    app.metrics.incr_dispatch_assigned();
    info!(
        engine = "planner",
        tick = tick_seq,
        build_id = %candidate.id,
        assignment_id = %assignment.assignment_id,
        task_id = ?assignment.task_id,
        worker_id = %worker_id,
        fallback,
        "Build dispatched to worker"
    );
    // heavy 落位打点（轮 4 KPI 验证数据源）：预测折算权重 + 采样基准 +
    // 是否折算（护栏命中 = false，预测值即原值）。
    if steer_heavy {
        info!(
            engine = "planner",
            build_id = %candidate.id,
            task_id = ?candidate.task_id,
            worker_id = %worker_id,
            predicted_mem_kb = profile.weight.mem_kb_on(ncpu),
            predicted_cores = profile.weight.cpu_cores_on(ncpu),
            sample_ncpu = profile.weight.cpu_sample_ncpu,
            cpu_p90_cores = profile.weight.cpu_p90_cores,
            peak_rss_kb = profile.weight.peak_rss_kb,
            scaled = profile.weight.scales_on(ncpu),
            "Heavy candidate placed via steering"
        );
    }
    notify_workers(app, Some(worker_id)).await;
    Ok(true)
}

/// 实派发 tick（planner 接管形态）：主循环，调度器主循环的分布式派发入口。
/// 返回是否有派发。
pub(crate) async fn run_tick(app: &Arc<AppState>) -> crbs_core::Result<bool> {
    let started = Instant::now();
    let Some(mut ctx) = load_tick_context(app).await? else {
        return Ok(false);
    };
    let tick_seq = next_tick_seq();
    // 候选表移出 ctx 再遍历：派发会推进 ctx（Σ/空槽），与迭代借用分离。
    let candidates = std::mem::take(&mut ctx.candidates);
    let mut dispatched = 0usize;
    // 本 tick 各 worker 已新增派发数（refill 预算计数，tick 结束即弃）。
    let mut refilled: HashMap<i64, i64> = HashMap::new();
    for candidate in &candidates {
        let (decision, steer_heavy) = decide_with_telemetry(app, candidate, &ctx).await;
        let (worker_id, fallback) = match decision {
            PlannerDecision::Dispatch { worker_id } => (worker_id, false),
            PlannerDecision::SoftFallback { worker_id } => (worker_id, true),
            // NoFit / WatermarkBlocked 的归因与指标在 decide_with_telemetry 落点。
            _ => continue,
        };
        // refill 平滑：该 worker 本 tick 预算用尽 → 候选留队列下 tick 重判；
        // 非拒绝语义，归因原样保留（censored 等待钟不动），预算不分优先级。
        if ctx
            .refill_cap
            .get(&worker_id)
            .is_some_and(|cap| refilled.get(&worker_id).copied().unwrap_or(0) >= *cap)
        {
            debug!(
                build_id = %candidate.id,
                pkg = %candidate.pkg_name,
                worker_id = %worker_id,
                "Per-tick refill cap reached; candidate stays queued"
            );
            continue;
        }
        if assign_candidate(
            app,
            &mut ctx,
            candidate,
            worker_id,
            fallback,
            steer_heavy,
            tick_seq,
        )
        .await?
        {
            *refilled.entry(worker_id).or_insert(0) += 1;
            dispatched += 1;
            // 学习门影子记录：只对 CAS 领取成功的实际落点节点评估并落决策
            // 日志，不影响派发（开关默认关；键未学习时零输出）。
            if app.server_config.resource_learned_gates_enabled {
                let profile = ctx
                    .profiles
                    .get(&profile_key(
                        &candidate.product,
                        &candidate.source_name,
                        candidate.arch.as_deref(),
                    ))
                    .copied()
                    .unwrap_or_default();
                if let Some(worker) = ctx.workers.iter().find(|w| w.id == worker_id) {
                    record_shadow_decision(candidate, worker, &profile);
                }
            }
        }
    }
    if dispatched == 0 {
        app.metrics.incr_no_candidate_ticks();
    }
    app.metrics
        .record_dispatch_tick_ms(started.elapsed().as_millis() as u64);
    Ok(dispatched > 0)
}
