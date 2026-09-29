// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 构建结果上报与学习闭环。

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;

use crbs_core::types::build_phase_is_terminal;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::resource_learning::{apply_terminal_learning, NodeMemSource};
use crate::server::state::AppState;

use super::require_own_worker;

#[derive(Deserialize)]
pub struct ResultRequest {
    pub(super) phase: String,
    pub(super) result_dir: Option<String>,
    pub(super) error: Option<String>,
    /// 软告警备注：worker 把引擎写进本地 build 行 error_summary
    /// 的软告警随成功上报带回；hub 仅在本上报真正落成 succeeded 时 append
    ///（error_summary 复用通道，UI 以 warnings/notes 渲染）。缺字段 → 无备注。
    #[serde(default)]
    pub(super) notes: Option<String>,
    /// 构建资源采样结果（随脚本进程存续累计）；缺字段 → None；未知键默认忽略。
    #[serde(default)]
    pub(super) resources: Option<ResourceUsagePayload>,
}

/// 资源采样值（`builds` 资源列同构）：缺字段 / null 均按不可得，经
/// [`sanitize_resources`] 越界 / NaN 过滤后落库；字段均可选（能力不可用 /
/// 采样关闭即缺省），未知键默认忽略。
#[derive(Deserialize, Debug, Default)]
pub struct ResourceUsagePayload {
    #[serde(default)]
    pub(super) peak_rss_kb: Option<i64>,
    #[serde(default)]
    pub(super) cpu_secs: Option<f64>,
    #[serde(default)]
    pub(super) cpu_p90_cores: Option<f64>,
    /// cgroup `memory.peak` 高水位（总内存口径，含文件页缓存）。
    #[serde(default)]
    pub(super) peak_total_kb: Option<i64>,
    /// cgroup `io.stat` wbytes 设备求和（字节）。
    #[serde(default)]
    pub(super) disk_wbytes: Option<i64>,
    /// cgroup `memory.events` oom_kill > 0 原值（判定与删失归 OOM 分类）。
    #[serde(default)]
    pub(super) oom_killed: Option<bool>,
    /// 采样口径（"cgroup" / "proc"，非法值降 None）。
    #[serde(default)]
    pub(super) sample_backend: Option<String>,
    /// 执行节点核数（worker 自报，与心跳 ncpu 同源）。
    #[serde(default)]
    pub(super) sample_ncpu: Option<i64>,
    /// 构建自身 tmpfs 占用峰值 KB（build_tmpfs off 恒 None）。
    #[serde(default)]
    pub(super) peak_tmpfs_kb: Option<i64>,
}

/// 资源上报的合理界（口径同 [`sanitize_telemetry`]）：越界 / NaN 按 NULL
/// 落库（不污染容量画像）。上界：peak_rss_kb / peak_total_kb 1e9 KB = 1 TB、
/// cpu_secs 1e7 s（约 115 天）、cpu_p90_cores 1e5 核、disk_wbytes 1e15 B
/// = 1 PB、sample_ncpu 与 ncpu 同界 1..=1024、sample_backend 白名单外降
/// None；全字段 NULL → 返回 `None`（无任何有效观测值）。
pub(super) fn sanitize_resources(
    res: Option<&ResourceUsagePayload>,
) -> Option<crbs_core::engine::ResourceUsage> {
    let r = res?;
    let peak_rss_kb = r.peak_rss_kb.filter(|v| (0..=1_000_000_000).contains(v));
    let cpu_secs = r
        .cpu_secs
        .filter(|v| v.is_finite() && (0.0..=10_000_000.0).contains(v));
    let cpu_p90_cores = r
        .cpu_p90_cores
        .filter(|v| v.is_finite() && (0.0..=100_000.0).contains(v));
    let peak_total_kb = r.peak_total_kb.filter(|v| (0..=1_000_000_000).contains(v));
    let disk_wbytes = r
        .disk_wbytes
        .filter(|v| (0..=1_000_000_000_000_000).contains(v));
    let sample_backend = r.sample_backend.as_deref().and_then(|b| match b {
        crbs_core::engine::SAMPLE_BACKEND_CGROUP => Some(crbs_core::engine::SAMPLE_BACKEND_CGROUP),
        crbs_core::engine::SAMPLE_BACKEND_PROC => Some(crbs_core::engine::SAMPLE_BACKEND_PROC),
        _ => None,
    });
    let sample_ncpu = r.sample_ncpu.filter(|v| (1..=1024).contains(v));
    // tmpfs 实例受物理内存上限约束（tmpfs 默认 size=内存一半），512 GiB
    //（512×1024×1024 KB）远超单机 tmpfs 可达峰值，界外必为脏数据。
    let peak_tmpfs_kb = r
        .peak_tmpfs_kb
        .filter(|v| (0..=512 * 1024 * 1024).contains(v));
    let usage = crbs_core::engine::ResourceUsage {
        peak_rss_kb,
        cpu_secs,
        cpu_p90_cores,
        peak_total_kb,
        disk_wbytes,
        oom_killed: r.oom_killed,
        sample_backend,
        sample_ncpu,
        peak_tmpfs_kb,
    };
    (usage != crbs_core::engine::ResourceUsage::default()).then_some(usage)
}

pub(super) async fn report_result(
    State(app): State<Arc<AppState>>,
    Path((worker_id, assignment_id)): Path<(i64, i64)>,
    auth: Option<axum::extract::Extension<AuthContext>>,
    Json(req): Json<ResultRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _ctx = require_own_worker(&auth, worker_id)?;

    // 一次行查询取归属 / 终态 / kind / build_id：行不存在时 worker_id 为 None → 归属校验 403。
    let (build_id, task_worker_id, task_kind, task_status) = app
        .state_store
        .get_worker_task_meta(assignment_id)
        .await
        .map_err(ApiError::from)?;

    // 校验 assignment 确实属于该 worker，防止通过猜测 assignment_id 越界写入
    if task_worker_id != Some(worker_id) {
        return Err(ApiError::PermissionDenied(
            "assignment does not belong to worker".into(),
        ));
    }

    // 终态截断（幂等）：终态后再收上报一律 409——先到者生效；worker 重试层
    // 把 409 映射为已达终态（防重试烧完预算假失败）。
    if task_status
        .as_deref()
        .is_some_and(|s| matches!(s, "completed" | "failed" | "cancelled"))
    {
        tracing::warn!(
            assignment_id = %assignment_id,
            status = ?task_status,
            "result report rejected for terminal assignment"
        );
        return Err(ApiError::Conflict(
            "assignment already reached terminal state".into(),
        ));
    }

    // init 任务：不更新 builds，只标记 assignment 完成；dispatch gating 查
    // has_active_init(worker, product)，完成后随终态自然解除。
    if task_kind.as_deref() == Some("init") {
        let success = req.phase == "succeeded";
        let error = if success { None } else { req.error.as_deref() };
        app.state_store
            .complete_init_assignment(assignment_id, success, error)
            .await
            .map_err(ApiError::from)?;
        tracing::info!(
            assignment_id = %assignment_id,
            worker_id = %worker_id,
            success = success,
            "Init assignment completed"
        );
        // 响应体与 build 臂统一为 {"accepted":true}（worker 客户端只看状态码）。
        return Ok(Json(serde_json::json!({"accepted": true})));
    }

    // worker_tasks 用纯生命周期词汇（assigned/running/completed/failed/
    // cancelled），与 builds.phase 解耦不做 verbatim 写入；终态分支迁出
    // 'running' 释放调度容量，reclaimer 终态 sweep 兜底崩溃丢失的写入。

    // build_id 已随头部查询取回（init 已分流，此处恒为 build 行）。
    if let Some(id) = build_id {
        // 分布式取消兜底：build 已 cancelled 时忽略 worker 后续上报，防
        // succeeded/failed 覆盖取消状态。
        let current_phase = app
            .state_store
            .get_build(id)
            .await
            .map_err(ApiError::from)?
            .map(|b| b.phase);

        if current_phase.as_deref() == Some("cancelled") {
            tracing::info!(
                build_id = %id,
                assignment_id = %assignment_id,
                // worker 自由文本：转义控制字符，防借日志伪造新行。
                worker_phase = %crbs_core::util::escape_ctrl(&req.phase),
                "Build already cancelled, preserving cancelled state"
            );
            if let Err(e) = app
                .state_store
                .update_worker_task_status(assignment_id, "cancelled")
                .await
            {
                tracing::warn!(
                    assignment_id = %assignment_id,
                    error = %e,
                    "Failed to update worker task status to cancelled"
                );
            }
            // build 已是 cancelled（终态不可变），无需再调 complete_build_guarded；
            // 只写上方 worker_tasks 的 cancelled 收尾（释放调度容量）。
            evict_log_buffer_if_persisted(&app, id).await;
        } else if build_phase_is_terminal(&req.phase) {
            // worker 上报的 result_dir 是不可信输入（真值来自 upload 的
            // update_build_info）：不校验落库会让 regen 在任意可写目录开
            // `.sign.lock`；校验失败不拒上报，仅不采纳（COALESCE 下
            // None = 保留原值）。
            let reported_result_dir = match req.result_dir.as_deref() {
                None => None,
                Some(dir) => {
                    let root = app
                        .result_dir_for(
                            &app.state_store
                                .get_build(id)
                                .await
                                .map_err(ApiError::from)?
                                .map(|b| b.product)
                                .unwrap_or_default(),
                        )
                        .await
                        .map_err(ApiError::from)?;
                    match crbs_core::util::validate_result_dir(dir, &root).await {
                        Ok(_) => Some(dir),
                        Err(e) => {
                            tracing::warn!(
                                build_id = %id,
                                // worker 自由文本：转义控制字符，防借日志伪造新行。
                                worker_result_dir = %crbs_core::util::escape_ctrl(dir),
                                error = %e,
                                "Worker-reported result_dir rejected (outside result root); keeping existing"
                            );
                            None
                        }
                    }
                }
            };
            // 资源列随终态写入（经 sanitize 过滤）；取消臂不传——取消上报
            // 进本分支时守卫也必拒绝（终态先到者），资源无落账意义。
            let resources = if req.phase == "cancelled" {
                None
            } else {
                sanitize_resources(req.resources.as_ref())
            };
            // 终态写入带 assignment 归属 CAS（complete_build_guarded）。
            let affected = app
                .state_store
                .complete_build_guarded_resources(
                    id,
                    worker_id,
                    &req.phase,
                    reported_result_dir,
                    req.error.as_deref(),
                    resources.as_ref(),
                )
                .await
                .map_err(ApiError::from)?;

            // 0 行 = 终态/归属守卫拒绝：读取与 UPDATE 之间被并发取消/完成，
            // 或 assignment 被 reclaim 删行重派（归属复查在事务外，迟到上报
            // 被提交点拒绝）。终态先到者生效，迟到报告留痕丢弃（非 500）；
            // worker_task 收尾与 repo regen 交给赢者路径。
            let build_completed_here = affected > 0;
            if !build_completed_here {
                tracing::warn!(
                    build_id = %id,
                    assignment_id = %assignment_id,
                    // worker 自由文本：转义控制字符，防借日志伪造新行。
                    worker_phase = %crbs_core::util::escape_ctrl(&req.phase),
                    "Terminal-state/ownership guard rejected worker report (concurrently terminal, cancelled or reclaimed); late report dropped"
                );
            }

            // 软告警备注：notes append 进 error_summary，仅在本上报真正落成
            // succeeded 时执行（守卫拒绝的重复上报由首次成功方负责）；失败仅
            // warn（软信息不让终态翻错），文本经 substr 上限截断。
            if build_completed_here && req.phase == "succeeded" {
                if let Some(notes) = req.notes.as_deref().filter(|n| !n.is_empty()) {
                    if let Err(e) = app.state_store.append_build_note(id, notes).await {
                        tracing::warn!(
                            build_id = id,
                            assignment_id = assignment_id,
                            error = %e,
                            "Failed to append worker notes to error_summary"
                        );
                    }
                }
            }

            // 终态学习（只挂终态上报，reclaimer 重置 pending 的重试
            // 路径不触发）：画像更新与同包权重缓存失效在共享入口内按"先学习
            // 后失效"收敛，否则新 EMA 样本要等 5min TTL 才对派发可见。
            // best-effort，失败不阻塞终态；读身份失败仅 debug（TTL 兜底）。
            if build_completed_here {
                match app.state_store.get_build(id).await {
                    Ok(Some(rec)) => {
                        apply_terminal_learning(
                            &app,
                            &rec,
                            &req.phase,
                            resources.as_ref(),
                            NodeMemSource::Worker(worker_id),
                        )
                        .await;
                    }
                    Ok(None) => {
                        tracing::debug!(
                            build_id = %id,
                            "terminal learning skipped: build record vanished"
                        );
                    }
                    Err(e) => {
                        tracing::debug!(
                            build_id = %id,
                            error = %e,
                            "Failed to load build for terminal learning"
                        );
                    }
                }
            }

            evict_log_buffer_if_persisted(&app, id).await;

            // 终态后把 worker_tasks 迁出 'running'（纯生命周期词汇）释放调度
            // 容量；写入失败由 reclaimer 终态 sweep 兜底。仅在本次上报真正翻终态
            // 时写——守卫拒绝（0 行）时并发路径已收尾 worker_task，再写会把取消
            // 路径刚落的 cancelled 覆写成 completed/failed；残行同由 sweep 兜底。
            if build_completed_here {
                let wt_status = match req.phase.as_str() {
                    "succeeded" => "completed",
                    "cancelled" => "cancelled",
                    _ => "failed", // failed / timeout
                };
                if let Err(e) = app
                    .state_store
                    .update_worker_task_status(assignment_id, wt_status)
                    .await
                {
                    tracing::warn!(
                        assignment_id = %assignment_id,
                        build_id = %id,
                        error = %e,
                        "Failed to release worker_task after build completion"
                    );
                }
            }

            // succeeded 终态同步触发该 product 的发布 repo 重建；仅在本上报
            // 真正翻成 succeeded 时（守卫拒绝的重复 / 取消跳过，首次写入方已负责）。
            //
            // 触发点必须在 phase 翻 succeeded 之后（候选 SQL 以 phase='succeeded'
            // 为门，放 sign 出口恒 0 条）；gate 用 `record.result_dir`（DB 真值，
            // upload 的 update_build_info 写入），不能用 `req.result_dir`——
            // worker 成功上报恒带 null。
            //
            // regen 须在签名后：同步拿 `.sign.lock`（`Signer::sign_rpms` 唯一
            // 锁点），30s 短超时防阻塞 worker（sign 正常 < 5s；5min 默认给手动
            // `crbs sign`）。regen 为 fire-and-forget，drop 与任务体先后无保
            // 证，但锁已拿到 = 签名完成，快照必含已签名字节；失败 / 超时仅 warn。
            if build_completed_here && req.phase == "succeeded" {
                // 一次读 build record 取 product 与 result_dir；缺失/失败按
                // "无 regen 目标"处理（debug + 跳过）。
                let (product, record_result_dir) = match app.state_store.get_build(id).await {
                    Ok(Some(rec)) => (rec.product, rec.result_dir),
                    Ok(None) => {
                        tracing::debug!(
                            build_id = %id,
                            "R1b regen skipped: build record vanished"
                        );
                        (String::new(), None)
                    }
                    Err(e) => {
                        tracing::debug!(
                            build_id = %id,
                            error = %e,
                            "R1b regen skipped: failed to load build record"
                        );
                        (String::new(), None)
                    }
                };
                if let Some(result_dir_str) = record_result_dir.as_deref() {
                    let result_dir = std::path::PathBuf::from(result_dir_str);
                    if product.is_empty() {
                        tracing::debug!(
                            build_id = %id,
                            "R1b regen skipped: empty product on build record"
                        );
                    } else {
                        match crbs_core::sign::acquire_result_dir_sign_lock_with_timeout(
                            &result_dir,
                            Duration::from_secs(30),
                        )
                        .await
                        {
                            Ok(_sign_lock) => {
                                // 锁已拿到 = 签名任务已结束；必须在锁后重读
                                // signed（锁前快照可能还是 0）。产品有 key 且
                                // 未显式关闭签名时，未签名产物不得进发布 repo。
                                let signed_now = match app.state_store.get_build(id).await {
                                    Ok(Some(rec)) => rec.signed,
                                    Ok(None) => false,
                                    Err(e) => {
                                        tracing::warn!(
                                            build_id = %id,
                                            error = %e,
                                            "Failed to re-read build signature state; treating as unsigned"
                                        );
                                        false
                                    }
                                };
                                let requires_signed = match app
                                    .state_store
                                    .load_merged_config_for_any_product_by_name(&product)
                                    .await
                                {
                                    Ok(config) => {
                                        crbs_core::sign::SignConfig::signing_required(&config)
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            build_id = %id,
                                            product = %product,
                                            error = %e,
                                            "Failed to resolve signing policy; skipping repo regen"
                                        );
                                        true
                                    }
                                };
                                if requires_signed && !signed_now {
                                    tracing::warn!(
                                        build_id = %id,
                                        product = %product,
                                        "Signed publish required but artifact is unsigned; \
                                         repo regeneration skipped (sign and re-run publish to converge)"
                                    );
                                    if let Err(e) = app
                                        .state_store
                                        .append_build_note(
                                            id,
                                            "signed publish required but artifact signature is \
                                             missing; repo regeneration skipped",
                                        )
                                        .await
                                    {
                                        tracing::warn!(
                                            build_id = %id,
                                            error = %e,
                                            "Failed to append unsigned-publish note"
                                        );
                                    }
                                } else {
                                    // drop 后 regen 与后续手动签名可并发，regen
                                    // 自持 `.repodata.lock` 串行化同 arch 重入。
                                    crate::server::repo_regen::regenerate_product_repo(
                                        &app, &product,
                                    )
                                    .await;
                                }
                                drop(_sign_lock);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    build_id = %id,
                                    product = %product,
                                    result_dir = %result_dir.display(),
                                    error = %e,
                                    "R1b regen skipped: failed to acquire .sign.lock within 30s; \
                                     next successful build or manual `rebuild-repo` will converge"
                                );
                            }
                        }
                    }
                } else {
                    tracing::debug!(
                        build_id = %id,
                        "R1b regen skipped: build record has no result_dir (DB schema invariant \
                         violated — succeeded build should always have result_dir set by \
                         update_build_info during upload)"
                    );
                }
            }

            // 终态异步跟跑钩子（自动重放 / 重放比对 / cross-arch noarch 互比）：
            // 仅本次上报真正翻终态时触发；spawn 不阻塞 worker 响应。
            if build_completed_here {
                crate::server::replay::spawn_on_build_terminal(app.clone(), id);
            }
        } else {
            // 中间态写入带 assignment 归属 CAS：归属复查在事务外一次行读，
            // reclaim 删行重派恰落行读与写入之间时，迟到中间态上报会把重派
            // 间隙的行翻 building（新 assignment 楔死容量）；谓词让其在提交点
            // 被拒，debug 留痕（预期恢复路径噪声，不按错误处理）。
            let affected = app
                .state_store
                .update_build_phase_guarded(id, worker_id, &req.phase)
                .await
                .map_err(ApiError::from)?;
            if affected == 0 {
                tracing::debug!(
                    build_id = %id,
                    assignment_id = %assignment_id,
                    // worker 自由文本：转义控制字符，防借日志伪造新行。
                    worker_phase = %crbs_core::util::escape_ctrl(&req.phase),
                    "Intermediate report dropped (assignment reclaimed or concurrently terminal); late report ignored"
                );
            }
        }

        // err 是 worker 自由文本：进日志前转义控制字符（\n 可伪造日志行）；
        // DB/UI 落库保持原文，渲染端转义。
        if let Some(ref err) = req.error {
            tracing::warn!(
                build_id = %id,
                error = %crbs_core::util::escape_ctrl(err),
                "Worker reported build error"
            );
        }
    }

    app.worker_notify.notify_one();

    Ok(Json(serde_json::json!({"accepted": true})))
}

/// 构建终态后释放 LogBuffer 实时缓冲，读取端回落落盘 build.log。
///
/// 仅在落盘日志可解析（`resolve_log_path` 命中）时驱逐：正常时序 upload →
/// report 必然命中；上传失败的 succeeded、早期取消等边缘无落盘回退，保留
/// 缓冲（10MB 上限）比降级 404 安全。
pub(crate) async fn evict_log_buffer_if_persisted(app: &Arc<AppState>, build_id: i64) {
    if crate::server::routes::logs::resolve_log_path(app, build_id)
        .await
        .is_some()
    {
        app.log_buffer.evict(build_id);
    } else {
        tracing::debug!(build_id = %build_id, "LogBuffer eviction skipped: no persisted build.log to fall back to");
    }
}

// ======== 上报日志 ========
