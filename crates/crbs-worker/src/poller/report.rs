// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 阶段/终态结果上报。

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::WorkerConfig;
use crate::executor::{report_result, report_result_with_timeout, BuildResult};
use crbs_core::error::CrbsError;

use super::*;

/// execute_task 返回 Err 后的终态补报：build 补 failed（否则 Hub 卡
/// building）；init 终态已由 run_init 上报，跳过防双重上报。panic 路径
/// 未经任何上报（init 也须补报），不走本函数。
pub(super) async fn report_task_failure(
    cfg: &WorkerConfig,
    worker_id: i64,
    task: &AssignedTask,
    error: String,
) {
    if task.kind == "init" {
        warn!(
            assignment_id = %task.assignment_id,
            task_id = ?task.task_id,
            "Init task already reported its terminal state; skipping duplicate failed report"
        );
        return;
    }
    report_terminal_failure(cfg, worker_id, task, error).await;
}

/// 向 Hub 回报终态 `failed`（Err 与 panic 路径共用）：不回报则 Hub 永久卡
/// `building`、worker 槽泄漏；上报失败仅告警。用独立 token——复用主 token
/// 时补报在 `report_result` 入口即被 Cancelled 吞掉。走
/// [`CANCEL_REPORT_PER_ATTEMPT`] 短超时：3 次 + 退避最坏 ~20s，在 30s drain
/// 窗口内必达；代价是慢 hub（单请求 >5s）下放弃，240s reclaimer 兜底。
pub(super) async fn report_terminal_failure(
    cfg: &WorkerConfig,
    worker_id: i64,
    task: &AssignedTask,
    error: String,
) {
    report_terminal_failure_with_resources(cfg, worker_id, task, error, None).await;
}

/// [`report_terminal_failure`] 的带资源版本（poller 总预算 abort 路径）：
/// 引擎已被 abort、常规结果通道丢失，尽力携带共享快照读到的已采值落 hub
/// 资源列（None = 未进采样阶段 / 双口径关闭 / 全空）。
pub(super) async fn report_terminal_failure_with_resources(
    cfg: &WorkerConfig,
    worker_id: i64,
    task: &AssignedTask,
    error: String,
    resources: Option<crbs_core::engine::ResourceUsage>,
) {
    let result = BuildResult::terminal("failed", Some(error), resources);
    let report_token = CancellationToken::new();
    if let Err(e) = report_result_with_timeout(
        cfg,
        worker_id,
        task,
        &result,
        Some(&report_token),
        CANCEL_REPORT_PER_ATTEMPT,
    )
    .await
    {
        warn!(
            assignment_id = %task.assignment_id,
            task_id = ?task.task_id,
            error = %e,
            "Failed to report terminal failure result"
        );
    }
}

/// 终态补报共用的 per-attempt 超时：3 次 × 5s + 退避最坏 ~20s，在 30s
/// drain 窗口内可完成；完不成即放弃，hub 240s reclaimer 兜底。
const CANCEL_REPORT_PER_ATTEMPT: Duration = Duration::from_secs(5);

/// 取消导致的终态补报：已取消令牌在 report_result 入口即返 Cancelled，
/// 真实终态到不了 hub——用独立 token + [`CANCEL_REPORT_PER_ATTEMPT`] 补报
/// `result` 的真实 phase（引擎取消报 cancelled；上报中途被取消的成功构建
/// 报 succeeded，防 hub 重派双跑）。hub 幂等：worker_tasks 已终态 → 409 被
/// 重试层映射为送达；hub 发起的取消不会被本补报翻掉。返回是否被接受——
/// accepted 的 succeeded 由调用方记入 executed 去重集合。pub(crate)：
/// executor `report_init_result` 的取消臂共用本机制。
pub(crate) async fn report_terminal_after_cancel(
    cfg: &WorkerConfig,
    worker_id: i64,
    task: &AssignedTask,
    result: &BuildResult,
) -> bool {
    let report_token = CancellationToken::new();
    if let Err(e) = report_result_with_timeout(
        cfg,
        worker_id,
        task,
        result,
        Some(&report_token),
        CANCEL_REPORT_PER_ATTEMPT,
    )
    .await
    {
        warn!(
            assignment_id = %task.assignment_id,
            task_id = ?task.task_id,
            phase = %result.phase,
            error = %e,
            "Failed to report terminal state after cancellation; hub reclaimer is the fallback"
        );
        return false;
    }
    true
}

/// 从 JoinError 提取失败描述：panic payload（&str/String）带出，否则回退
/// 通用描述；截断 500 字符。
pub(crate) fn join_failure_message(join_err: tokio::task::JoinError) -> String {
    const MAX_PAYLOAD_CHARS: usize = 500;
    if !join_err.is_panic() {
        return format!("worker task join error: {join_err}");
    }
    let payload = join_err.into_panic();
    let detail = if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        String::new()
    };
    if detail.is_empty() {
        "worker task panicked".to_string()
    } else {
        let truncated: String = detail.chars().take(MAX_PAYLOAD_CHARS).collect();
        format!("worker task panicked: {truncated}")
    }
}

/// 构建完成后的结果上报与失败处置：
/// - 上报被取消 → Ok。
/// - succeeded 上报耗尽重试 → Ok + 告警，不走 Err——Err 会把真实成功补报成
///   failed；收敛靠心跳 reclaimer（上报与心跳同 Hub，长期失败 → 120s 超时
///   重置 pending 重派），本地产物保留供人工恢复。
/// - 失败/取消的上报失败 → 维持 Err（上层补报 failed）。
/// - 双成功（succeeded 且无上传错误标记）→ 删本地结果目录；任何失败路径都
///   保留（本地副本是重试/人工恢复唯一来源），删除见
///   `sweep::delete_build_result_dir`。
pub(crate) async fn report_build_result(
    cfg: &WorkerConfig,
    worker_id: i64,
    task: &AssignedTask,
    result: &BuildResult,
    cancel_token: &CancellationToken,
    executed_assignments: &ExecutedAssignments,
) -> crbs_core::Result<()> {
    let report_outcome = report_result(cfg, worker_id, task, result, Some(cancel_token)).await;
    match report_outcome {
        Ok(()) => {
            // 双成功判定：succeeded 且 error=None（上传失败时 run_build 置
            // error=Some）。
            if result.phase == "succeeded" && result.error.is_none() {
                // 上报被接受 → 登记去重（封 guard 移除后的重投递窗口）。
                executed_assignments.record(task.assignment_id);
                if let (Some(dir), Some(engine_build_id), Some(root)) = (
                    result.local_result_dir.as_deref(),
                    result.engine_build_id,
                    result.engine_result_root.as_deref(),
                ) {
                    crate::sweep::delete_build_result_dir(dir, engine_build_id, root).await;
                }
            }
            Ok(())
        }
        Err(CrbsError::Cancelled) => {
            info!(
                assignment_id = %task.assignment_id,
                task_id = ?task.task_id,
                "Result reporting skipped because task was cancelled"
            );
            // 取消 ≠ 无终态：result 可能是真实 succeeded/failed/timeout（引擎
            // 取消已归 cancelled）。独立 token 补报真实 phase，重复上报被 hub
            // 幂等吸收；accepted 且 succeeded 时登记去重（否则重投递会重执行）。
            let reported = report_terminal_after_cancel(cfg, worker_id, task, result).await;
            if reported && result.phase == "succeeded" {
                executed_assignments.record(task.assignment_id);
            }
            Ok(())
        }
        Err(e) if result.phase == "succeeded" => {
            warn!(
                assignment_id = %task.assignment_id,
                task_id = ?task.task_id,
                build_id = %task.build_id,
                error = %e,
                local_result_dir = ?result.local_result_dir,
                "Build succeeded locally but success report failed after exhausting retries; \
                 NOT reporting failed; hub reclaimer will requeue this build once heartbeats \
                 time out; artifacts preserved locally for manual recovery"
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}
