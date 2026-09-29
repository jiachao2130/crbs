// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 构建执行与归属守卫。

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::WorkerConfig;
use crate::executor::{report_phase, run_build, INIT_ENGINE_TIMEOUT_SECS};

use super::probes::{probe_assignment_ownership, probe_terminal_result, ProbeAction, ProbedBuild};
use super::*;

/// execute_task 总预算的富余（秒）：覆盖引擎超时之后的采集、产物上传与终态
/// 上报重试。
pub(super) const ASSIGNMENT_BUDGET_MARGIN_SECS: u64 = 30 * 60;

/// 预算超时 abort 后等待任务体收尾的界：future Drop 触发的 cleanup_guard 自
/// 带 30s 有界预算，外加少量调度余量。
pub(super) const ASSIGNMENT_ABORT_JOIN: Duration = Duration::from_secs(35);

/// 单个 assignment 的执行总预算（纯函数）：引擎超时 + 30min 富余，加法饱和
///（hub 下发的 timeout 无上限校验，巨值预算封顶 u64::MAX，实际不限时）；
/// build 的引擎超时与 run_build 同口径（effective_build_timeout 合成请求值
/// 与 worker.toml 默认），init 取 [`INIT_ENGINE_TIMEOUT_SECS`]。显式不限时
///（timeout=0 / 配置 0 关闭）→ None，与引擎口径一致不设任务级预算。
pub(crate) fn assignment_budget(task: &AssignedTask, cfg: &WorkerConfig) -> Option<Duration> {
    let engine_timeout_secs = if task.kind == "init" {
        Some(INIT_ENGINE_TIMEOUT_SECS)
    } else {
        let requested = task.build_options.get("timeout").and_then(|v| v.as_u64());
        crbs_core::effective_build_timeout(requested, cfg.build_timeout_secs)
    };
    engine_timeout_secs
        .map(|t| Duration::from_secs(t.saturating_add(ASSIGNMENT_BUDGET_MARGIN_SECS)))
}

/// 把 [`run_build`] 包进归属探针循环：按 `probe_every` 探测归属，据
/// [`ProbeAction`] 处置（生产传 [`ownership_probe_interval_secs`]，测试注
/// 短节拍）。构建持外层 token 的子 token——探针只取消本构建，不波及同
/// worker 其它任务；外层取消级联到子 token。
async fn run_build_with_ownership_probe(
    cfg: &WorkerConfig,
    worker_id: i64,
    task: &AssignedTask,
    cancel_token: &CancellationToken,
    probe_every: Duration,
    resource_slot: crbs_core::engine::ResourceSnapshotSlot,
) -> ProbedBuild {
    let build_token = cancel_token.child_token();
    let build_fut = run_build(cfg, worker_id, task, build_token.clone(), resource_slot);
    tokio::pin!(build_fut);
    let mut next_probe = tokio::time::Instant::now() + probe_every;
    loop {
        tokio::select! {
            biased;
            result = &mut build_fut => return ProbedBuild::Finished(result),
            _ = tokio::time::sleep_until(next_probe) => {
                // 探针在途时构建完成不得被拖住（以构建返回作并列出口）。
                let probe_fut = probe_assignment_ownership(cfg, worker_id, task, cancel_token);
                tokio::pin!(probe_fut);
                let action = tokio::select! {
                    result = &mut build_fut => return ProbedBuild::Finished(result),
                    action = &mut probe_fut => action,
                };
                match action {
                    ProbeAction::Continue => {
                        next_probe = tokio::time::Instant::now() + probe_every;
                    }
                    ProbeAction::FinishTerminal => {
                        info!(
                            assignment_id = %task.assignment_id,
                            build_id = %task.build_id,
                            "Ownership probe got 409: assignment already terminal on hub; \
                             cancelling local build and reporting via post-cancel path"
                        );
                        build_token.cancel();
                        let result = build_fut.await;
                        return ProbedBuild::HubTerminal(probe_terminal_result(result));
                    }
                    ProbeAction::AbortLocal => {
                        warn!(
                            assignment_id = %task.assignment_id,
                            build_id = %task.build_id,
                            "Ownership probe got 403: assignment reclaimed by hub; cancelling \
                             local build, keeping artifacts, skipping terminal report"
                        );
                        build_token.cancel();
                        // 等引擎收尾（teardown 均在 run_build 内部）；产物保留
                        // ——取消不删 result_dir，跳过上报即无双成功删除路径。
                        let _ = build_fut.await;
                        return ProbedBuild::Reclaimed;
                    }
                }
            }
        }
    }
}

/// 执行分配到的任务；`probe_interval` 为归属探针节拍（生产传
/// [`ownership_probe_interval_secs`]，测试注短节拍）。
pub(super) async fn execute_task(
    worker_id: i64,
    cfg: &WorkerConfig,
    task: &AssignedTask,
    cancel_token: CancellationToken,
    executed_assignments: &ExecutedAssignments,
    probe_interval: Duration,
    resource_slot: crbs_core::engine::ResourceSnapshotSlot,
) -> crbs_core::Result<()> {
    // init 走独立路径（不上报 building，无 build 行）；终态上报在 run_init
    // 内部，被接受后同样登记去重集合。
    if task.kind == "init" {
        return crate::executor::run_init(cfg, worker_id, task, cancel_token, executed_assignments)
            .await;
    }

    if let Err(e) = report_phase(cfg, worker_id, task, "building", Some(&cancel_token)).await {
        // 可重试错误耗尽 → 大概率网络分区：不能继续构建（双执行风险），
        // 但也不能发终态 failed——构建尚未开工，失败上报会把本可重派的
        // 任务永久判死。返回 Ok、不发终态，让 hub reclaimer 超时回收重派。
        if e.is_transient() {
            warn!(
                assignment_id = %task.assignment_id,
                task_id = ?task.task_id,
                error = %e,
                "Failed to report building phase (transient); leaving assignment for reclaimer"
            );
            return Ok(());
        }
        warn!(
            assignment_id = %task.assignment_id,
            task_id = ?task.task_id,
            error = %e,
            "Failed to report building phase; hub reachable (definitive 4xx), continuing"
        );
    }

    // 构建期间周期归属探针（处置见 run_build_with_ownership_probe）。
    match run_build_with_ownership_probe(
        cfg,
        worker_id,
        task,
        &cancel_token,
        probe_interval,
        resource_slot,
    )
    .await
    {
        ProbedBuild::Finished(Ok(result)) => {
            report_build_result(
                cfg,
                worker_id,
                task,
                &result,
                &cancel_token,
                executed_assignments,
            )
            .await
        }
        // 原样透传：上层臂分别补报 cancelled / failed。
        ProbedBuild::Finished(Err(e)) => Err(e),
        ProbedBuild::HubTerminal(result) => {
            // 409：走取消后补报（独立 token + 短超时）；hub 对已终态
            // assignment 的二次上报 409 幂等吸收，不翻已落终态。
            let reported = report_terminal_after_cancel(cfg, worker_id, task, &result).await;
            if reported && result.phase == "succeeded" {
                executed_assignments.record(task.assignment_id);
            }
            Ok(())
        }
        ProbedBuild::Reclaimed => {
            // 403：已归新执行者——产物保留供人工恢复，上报会被归属校验拒，跳过。
            Ok(())
        }
    }
}

/// 保护 `active_tasks` 计数在 panic 时也能正确释放。
pub(super) struct ActiveTaskGuard {
    counter: Arc<AtomicI32>,
}

impl ActiveTaskGuard {
    pub(super) fn new(counter: Arc<AtomicI32>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self { counter }
    }
}

impl Drop for ActiveTaskGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}
