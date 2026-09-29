// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! hub 本地取件调度：伪 worker 水位门、准入门与选取。

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info_span, warn, Instrument};

use crbs_core::error::CrbsError;
use crbs_core::types::PRIORITY_DEFAULT;
use crbs_core::WorkerStatus;

use crate::server::routes::builds::{execute_build, mark_build_failed, BuildOptions};
use crate::server::state::AppState;

use super::planner;
use super::profiles::{
    committed_from_active, load_resource_profiles, profile_key, watermark_reject_dimension,
    AdmitWatermarks, CommittedLoad, ProfileKey, ResourceProfileMap, COMMITTED_RAMP_SECS,
};
use super::{fail_build_quick, WatermarkDimension};

// ===== hub 本地伪 worker：/proc 遥测自采与本地水位门 =====

/// 尝试在本地启动构建：每轮排水到槽满（lock 的 phase→building 反映到下一次
/// count），返回 `Ok(true)` = 至少启动一个。shutdown：`cancel` 触发即停止
/// 排水（不启动注定被取消的新构建）；permit 获取与 `cancel` 竞争，槽满时
/// 不长持 `acquire_owned().await` 卡死调度循环。准入按候选逐个判定（见
/// [`load_local_admission_snapshot`] / [`local_candidate_reject`]）：硬下限
///（契约，fail-closed）与水位门（建议，fail-open）拒绝的候选跳过并顺延下一
/// 候选，队首不阻塞后续；通过后以指定 id CAS 领取（0 行 = 被抢，顺延）。
pub(crate) async fn try_local_build(
    app: &Arc<AppState>,
    cancel: &CancellationToken,
) -> crbs_core::Result<bool> {
    let mut any_started = false;
    loop {
        if cancel.is_cancelled() {
            break;
        }

        // 1. 资源预留仅针对本地槽；distributed 构建由 per-worker capacity 约束。
        let total_slots = app.max_local_builds;
        let reserve_ratio = app.server_config.low_priority_reserve_ratio;
        let reserved_for_default = ((total_slots as f64 * reserve_ratio).ceil() as usize).max(1);

        // 2. 本地各优先级 running 数（不含 distributed）。
        let running_by_priority = app.state_store.count_local_building_by_priority().await?;

        let default_running = running_by_priority
            .get(&PRIORITY_DEFAULT)
            .copied()
            .unwrap_or(0) as usize;
        let must_reserve = reserved_for_default.saturating_sub(default_running);

        let total_running: usize = running_by_priority.values().map(|v| *v as usize).sum();
        let available = total_slots.saturating_sub(total_running);

        if available == 0 {
            break;
        }

        let priority_filter = if must_reserve > 0 && available <= must_reserve {
            Some(PRIORITY_DEFAULT)
        } else {
            None
        };

        // 3. 先拿 semaphore 再取候选；select 与 cancel 竞争——槽满（permit
        //    被分钟级 repo regen 持有）时 shutdown 立即打断排水。
        let permit = tokio::select! {
            _ = cancel.cancelled() => break,
            permit = app.build_semaphore.clone().acquire_owned() => permit,
        };
        let permit = permit.map_err(|_| CrbsError::Internal("build semaphore closed".into()))?;

        // 4. 本地候选流 peek（就绪 + 本地架构 claim + 后台闸，score 序）。
        let local_arch = std::env::consts::ARCH;
        let peeked = app
            .state_store
            .peek_local_candidates(local_arch, planner::DISPATCH_CANDIDATE_LIMIT)
            .await?;
        if peeked.is_empty() {
            drop(permit);
            break;
        }

        // 5. 低优预留：限 Default 而队列无 Default → 回退全量，防槽空转饿死
        //    高优（既有反饥饿语义）。
        let candidates: Vec<&crbs_core::DispatchCandidate> = match priority_filter {
            Some(p) => {
                let filtered: Vec<&crbs_core::DispatchCandidate> =
                    peeked.iter().filter(|c| c.priority == p).collect();
                if filtered.is_empty() {
                    peeked.iter().collect()
                } else {
                    filtered
                }
            }
            None => peeked.iter().collect(),
        };

        // 6. 逐候选准入 + CAS 领取：硬下限（契约，fail-closed）与水位门（建议，
        //    fail-open）按候选独立判定，被拒候选跳过并顺延下一候选（队首不
        //    阻塞后续；归因与指标照记）；CAS 0 行（被抢/谓词失效）同样顺延。
        //    两开关均关 → 快照装载与判定整段跳过，取件语义与历史一致。
        let admission = if app.server_config.resource_requirements_enabled
            || app.server_config.resource_local_watermark_enabled
        {
            Some(load_local_admission_snapshot(app, &peeked, local_arch).await?)
        } else {
            None
        };
        let mut locked = None;
        for candidate in candidates {
            if let Some(reject) = admission
                .as_ref()
                .and_then(|admission| local_candidate_reject(admission, candidate))
            {
                record_local_reject(app, candidate, reject).await;
                continue;
            }
            if let Some(info) = app
                .state_store
                .lock_specific_local_build(candidate.id, local_arch)
                .await?
            {
                // 离开 pending：与分布式派发成功同口径清归因（否则徽章残留）。
                app.dispatch_attribution.clear(candidate.id);
                locked = Some(info);
                break;
            }
        }
        let Some(info) = locked else {
            drop(permit);
            break;
        };
        let build_id = info.id;

        let task_cancel = CancellationToken::new();
        {
            let mut map = app.active_builds.lock().await;
            map.insert(build_id, task_cancel.clone());
        }

        // 7. 解析构建选项（失败 → 标记 failed 并继续，不阻塞其它任务）。
        let opts = match serde_json::from_str::<BuildOptions>(&info.request_json) {
            Ok(o) => o,
            Err(e) => {
                warn!(build_id = %build_id, error = %e, "Failed to parse request_json, marking failed");
                fail_build_quick(app, build_id, &format!("invalid build request: {e}")).await;
                drop(permit);
                continue;
            }
        };

        // 8. 检查 SRPM 文件是否存在（失败 → 标记 failed 并继续）。
        let srpm_path = std::path::PathBuf::from(&info.srpm_path);
        if !tokio::fs::try_exists(&srpm_path).await.unwrap_or(false) {
            warn!(build_id = %build_id, path = %srpm_path.display(), "Staged SRPM missing, marking failed");
            fail_build_quick(
                app,
                build_id,
                &format!("staged SRPM missing: {}", srpm_path.display()),
            )
            .await;
            drop(permit);
            continue;
        }

        // 9. 调用 execute_build。
        let app_clone = app.clone();
        let product = info.product;
        let span = info_span!(
            "execute_build",
            build_id = %build_id,
            priority = %opts.priority.unwrap_or(PRIORITY_DEFAULT)
        );
        tokio::spawn(async move {
            // 内层 spawn + 外层 await：panic 的 JoinError 不被静默丢弃——否则
            // build 停留 building 且 crbs_pid 为存活 server pid，zombie 修复
            // （只修死 pid）覆盖不到。
            let app_for_exec = app_clone.clone();
            let exec = tokio::spawn(
                async move {
                    execute_build(
                        app_for_exec,
                        build_id,
                        product,
                        srpm_path,
                        opts,
                        permit,
                        task_cancel,
                    )
                    .await;
                }
                .instrument(span),
            );
            if let Err(join_err) = exec.await {
                error!(
                    build_id = %build_id,
                    error = %join_err,
                    "Local build executor panicked; marking build failed"
                );
                // mark_build_failed 走 complete_build 的终态守卫：
                // panic 若恰好与正常完成竞态，终态保持先到者，不会覆盖。
                if let Err(e) = mark_build_failed(
                    &app_clone.state_store,
                    build_id,
                    Some(&join_err.to_string()),
                )
                .await
                {
                    warn!(
                        build_id = %build_id,
                        error = %e,
                        "Failed to mark panicked build as failed"
                    );
                }
                // panic 兜底翻终态后的终态钩子；mark 失败时钩子守卫 no-op。
                crate::server::replay::spawn_on_build_terminal(app_clone.clone(), build_id);
            }
        });

        any_started = true;
    }

    Ok(any_started)
}

// ===== hub 本地伪 worker：/proc 遥测自采与本地水位门 =====

/// 本地伪 worker 在 committed_from_active 折算表中的 id 占位：单伪 worker 恒 0，
/// 仅作 fold 键，不与真实 workers.id（自增从 1 起）比较。
pub(crate) const LOCAL_PSEUDO_WORKER_ID: i64 = 0;

/// hub 伪 worker 遥测（本地水位门输入）：口径与 crbs-worker 心跳的
/// `sample_load_telemetry` 语义孪生（loadavg load1、available_parallelism
/// ncpu、meminfo MemAvailable 反推 used% 与 MemTotal）——改其一须同步另一个。
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct HubLoadTelemetry {
    pub(crate) load1: f64,
    pub(crate) ncpu: i64,
    pub(crate) mem_used_pct: f64,
    pub(crate) mem_total_kb: i64,
}

/// 采样 hub 自身负载遥测：任一读取/解析失败整体 `None`（门 fail-open 放行，
/// 与分布式准入门"缺遥测不阻塞"同向）。`proc_dir` 形参供测试注入（生产传
/// "/proc"）；/proc 读是微秒级，直接 tokio::fs（heartbeat.rs 同款惯例）。
pub(crate) async fn sample_hub_load_telemetry(proc_dir: &Path) -> Option<HubLoadTelemetry> {
    let loadavg = tokio::fs::read_to_string(proc_dir.join("loadavg"))
        .await
        .ok()?;
    let meminfo = tokio::fs::read_to_string(proc_dir.join("meminfo"))
        .await
        .ok()?;
    Some(HubLoadTelemetry {
        load1: parse_proc_load1(&loadavg)?,
        ncpu: std::thread::available_parallelism().ok()?.get() as i64,
        mem_used_pct: parse_proc_mem_used_pct(&meminfo)?,
        mem_total_kb: parse_proc_mem_total_kb(&meminfo)?,
    })
}

/// /proc/loadavg 首列（1 分钟平均）。
pub(crate) fn parse_proc_load1(s: &str) -> Option<f64> {
    s.split_whitespace().next()?.parse().ok()
}

/// /proc/meminfo MemTotal/MemAvailable → 已用百分比；旧内核无 MemAvailable 行
/// → None（优于用 MemFree 高估已用）。
pub(crate) fn parse_proc_mem_used_pct(s: &str) -> Option<f64> {
    let mut total = None;
    let mut available = None;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = parse_proc_meminfo_kb(rest);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available = parse_proc_meminfo_kb(rest);
        }
    }
    let (total, available) = (total?, available?);
    if total <= 0.0 || available > total {
        return None;
    }
    Some((1.0 - available / total) * 100.0)
}

/// /proc/meminfo MemTotal（KB）原值提取（内存水位换算基准；本地构建学习
/// node-OOM 无 peak 样本的保守下界同源）。
pub(crate) fn parse_proc_mem_total_kb(s: &str) -> Option<i64> {
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            return parse_proc_meminfo_kb(rest).map(|v| v as i64);
        }
    }
    None
}

pub(crate) fn parse_proc_meminfo_kb(rest: &str) -> Option<f64> {
    rest.trim_end_matches("kB").trim().parse().ok()
}

/// hub 伪 worker：容量 = 本地槽、遥测 = /proc 自采，构造成
/// WorkerStatus 以复用与分布式准入门同源的 [`watermark_reject_dimension`]。
/// 遥测缺失 → None（门 fail-open：非 Linux / /proc 读失败时不给本地构建加门）。
pub(crate) fn hub_pseudo_worker(
    telemetry: Option<HubLoadTelemetry>,
    local_arch: &str,
    capacity: usize,
) -> Option<WorkerStatus> {
    let t = telemetry?;
    Some(WorkerStatus {
        id: LOCAL_PSEUDO_WORKER_ID,
        name: crbs_core::HUB_LOCAL_WORKER_NAME.into(),
        arch: local_arch.to_string(),
        capacity: capacity as i64,
        status: "online".into(),
        last_heartbeat: None,
        version: "local".into(),
        has_secret: false,
        load1: Some(t.load1),
        ncpu: Some(t.ncpu),
        cpu_util_pct: None,
        mem_used_pct: Some(t.mem_used_pct),
        mem_total_kb: Some(t.mem_total_kb),
        disk_free_kb: None,
        resource_caps: None,
        created_at: None,
        secret_expires_at: None,
    })
}

/// 本地活跃行（准入快照）：active_builds 内存注册表的
/// (product, source_name, arch) 行取失败降级空集（缺数据不阻塞，同分布式门）。
pub(crate) async fn local_active_rows(
    app: &Arc<AppState>,
) -> Vec<(String, String, Option<String>)> {
    let active_ids: Vec<i64> = app.active_builds.lock().await.keys().copied().collect();
    match app
        .state_store
        .list_build_pkgs_by_ids(&active_ids, COMMITTED_RAMP_SECS)
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|(_, product, source, arch)| (product, source, arch))
            .collect(),
        Err(e) => {
            debug!(
                error = %e,
                count = active_ids.len(),
                "Failed to load local active build pairs; treating committed load as empty"
            );
            Vec::new()
        }
    }
}

/// 本地取件单轮准入门快照：在跑 Σ/画像/声明与伪 worker 遥测一次装载，本轮
/// 全部候选复用（与 planner 的批量回源同源，禁逐候选 N+1）。`declared` 仅在
/// `resource_requirements_enabled` 开启时加载；`pseudo_worker` 遥测缺失 =
/// `None`（硬下限 fail-closed、水位门 fail-open 的分叉由判定函数承担）。
pub(crate) struct LocalAdmissionSnapshot {
    requirements_enabled: bool,
    watermark_enabled: bool,
    /// 准入水位系数运行值（server.toml，加载期校验 >0）。
    watermarks: AdmitWatermarks,
    declared: HashMap<ProfileKey, crbs_core::DeclaredRequirements>,
    profiles: ResourceProfileMap,
    committed: CommittedLoad,
    pseudo_worker: Option<WorkerStatus>,
}

/// 装载本地准入快照：画像键 = 活跃键 ∪ 本轮到候选键（Σ 折算与候选权重同批
/// 同源）；声明批量回源只在硬下限开关开启时发生；遥测采样失败降级 `None`。
pub(crate) async fn load_local_admission_snapshot(
    app: &Arc<AppState>,
    candidates: &[crbs_core::DispatchCandidate],
    local_arch: &str,
) -> crbs_core::Result<LocalAdmissionSnapshot> {
    let active_rows = local_active_rows(app).await;
    let mut keys: Vec<ProfileKey> = active_rows
        .iter()
        .map(|(p, s, a)| profile_key(p, s, a.as_deref()))
        .collect();
    keys.extend(
        candidates
            .iter()
            .map(|c| profile_key(&c.product, &c.source_name, c.arch.as_deref())),
    );
    let profiles = load_resource_profiles(app, keys).await;
    let pseudo_worker = hub_pseudo_worker(
        sample_hub_load_telemetry(Path::new("/proc")).await,
        local_arch,
        app.max_local_builds,
    );
    let ncpu = pseudo_worker.as_ref().and_then(|w| w.ncpu);
    let worker_ncpu: HashMap<i64, i64> = ncpu
        .map(|n| (LOCAL_PSEUDO_WORKER_ID, n))
        .into_iter()
        .collect();
    let rows: Vec<(i64, String, String, Option<String>)> = active_rows
        .iter()
        .map(|(p, s, a)| (LOCAL_PSEUDO_WORKER_ID, p.clone(), s.clone(), a.clone()))
        .collect();
    let committed = committed_from_active(&rows, &profiles, &worker_ncpu)
        .remove(&LOCAL_PSEUDO_WORKER_ID)
        .unwrap_or_default();

    let requirements_enabled = app.server_config.resource_requirements_enabled;
    let declared = if requirements_enabled {
        let keys: Vec<ProfileKey> = candidates
            .iter()
            .map(|c| profile_key(&c.product, &c.source_name, c.arch.as_deref()))
            .collect();
        app.state_store.declared_requirements_batch(&keys).await?
    } else {
        HashMap::new()
    };

    Ok(LocalAdmissionSnapshot {
        requirements_enabled,
        watermark_enabled: app.server_config.resource_local_watermark_enabled,
        watermarks: AdmitWatermarks::from_config(&app.server_config),
        declared,
        profiles,
        committed,
        pseudo_worker,
    })
}

/// 本地单候选拒绝原因（归因/指标落点的最小粒度）。
pub(crate) enum LocalAdmitReject {
    /// 硬下限不满足（含要求维遥测缺失 fail-closed），维度同 planner 归因；
    /// 随行生效下限供停滞 note 复核。
    HardReq(planner::HardReqDimension, planner::EffectiveHardReq),
    /// 候选权重进门后超水位（遥测缺失 fail-open 不放这里）；随行生效折算
    /// 压载（伪 worker 的在跑 Σ + 候选自身，按伪 worker 核数折算）。
    Watermark(WatermarkDimension, CommittedLoad),
}

/// 本地单候选准入判定（纯函数）：硬下限逐维 fail-closed（要求维遥测缺失 =
/// 不承载；无任何声明维整段跳过）→ 候选权重进门的伪 worker 水位判（遥测
/// 缺失 fail-open）。被拒返回原因，通过返回 `None`；调用方跳过被拒候选、
/// 顺延下一候选。
pub(crate) fn local_candidate_reject(
    snapshot: &LocalAdmissionSnapshot,
    candidate: &crbs_core::DispatchCandidate,
) -> Option<LocalAdmitReject> {
    let key = profile_key(
        &candidate.product,
        &candidate.source_name,
        candidate.arch.as_deref(),
    );
    if snapshot.requirements_enabled {
        let declared = snapshot.declared.get(&key);
        let req = planner::EffectiveHardReq {
            min_mem_kb: candidate
                .req_min_mem_kb
                .or(declared.and_then(|d| d.min_mem_kb)),
            min_ncpu: candidate.req_min_ncpu.or(declared.and_then(|d| d.min_ncpu)),
            min_disk_kb: candidate
                .req_min_disk_kb
                .or(declared.and_then(|d| d.min_disk_kb)),
        };
        if req.has_any() {
            match &snapshot.pseudo_worker {
                // 伪 worker 缺失 = 全维遥测缺失：有声明即 fail-closed。
                None => return Some(LocalAdmitReject::HardReq(req.first_dimension(), req)),
                Some(worker) => {
                    if let Some(dimension) = planner::worker_satisfies_hard_req(worker, &req) {
                        return Some(LocalAdmitReject::HardReq(dimension, req));
                    }
                }
            }
        }
    }
    if snapshot.watermark_enabled {
        if let Some(worker) = &snapshot.pseudo_worker {
            let weight = snapshot
                .profiles
                .get(&key)
                .map(|p| p.weight)
                .unwrap_or_default();
            let load = snapshot.committed.plus(&weight, worker.ncpu);
            if let Some(dimension) = watermark_reject_dimension(worker, load, snapshot.watermarks) {
                return Some(LocalAdmitReject::Watermark(dimension, load));
            }
        }
    }
    None
}

/// 本地拒绝落点：指标 + 派发归因 + 诊断日志（与 planner 决策落点同口径）；
/// 硬下限拒绝同时触发停滞提示（`resource_hard_req_stall_secs`）。
pub(crate) async fn record_local_reject(
    app: &Arc<AppState>,
    candidate: &crbs_core::DispatchCandidate,
    reject: LocalAdmitReject,
) {
    match reject {
        LocalAdmitReject::HardReq(dimension, req) => {
            app.metrics
                .incr_dispatch_admit_reject(planner::hard_req_dimension_metric(dimension));
            app.dispatch_attribution.record_no_fit(
                candidate.id,
                planner::RejectReason::NoFitHardReq { dimension },
            );
            debug!(
                build_id = %candidate.id,
                pkg = %candidate.pkg_name,
                dimension = dimension.as_str(),
                "Local build held by hard-floor gate; trying next candidate"
            );
            planner::notify_hard_req_stall(app, candidate, dimension, &req, "hub local").await;
        }
        LocalAdmitReject::Watermark(dimension, load) => {
            app.metrics
                .incr_dispatch_admit_reject(planner::watermark_dimension_metric(dimension));
            // 本地 build 同样进派发归因表（WatermarkBlocked + 水位首拒时刻 +
            // 生效折算压载）。
            app.dispatch_attribution
                .record_water_reject(candidate.id, dimension, load);
            debug!(
                build_id = %candidate.id,
                pkg = %candidate.pkg_name,
                dimension = ?dimension,
                mem_kb = load.mem_kb,
                cpu_cores = load.cpu_cores,
                "Local build held by watermark gate; trying next candidate"
            );
        }
    }
}
