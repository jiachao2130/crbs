// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 任务取消路由：权限、状态机与子构建联动。

use super::*;

pub(crate) async fn cancel_task(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<(StatusCode, Json<TaskCancelResponse>), ApiError> {
    let outcome = cancel_task_for_user(&app, id, auth.as_ref().map(|ext| &ext.0)).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(TaskCancelResponse {
            task_id: id,
            cancelled_build_ids: outcome.cancelled_build_ids,
            skipped_build_ids: outcome.skipped_build_ids,
            failed_build_ids: outcome.failed_build_ids,
            message: outcome.message,
        }),
    ))
}

/// 取消指定 Task：权限检查、子构建取消/标记、父 Task phase 同步、审计日志。
pub(crate) async fn cancel_task_for_user(
    app: &Arc<AppState>,
    task_id: i64,
    auth: Option<&AuthContext>,
) -> Result<CancelTaskOutcome, ApiError> {
    let ctx = auth.ok_or(ApiError::Unauthorized(
        "authentication required to cancel".into(),
    ))?;
    let task = app
        .state_store
        .get_task(task_id)
        .await?
        .ok_or_else(|| ApiError::not_found("task", task_id))?;

    if !ctx.can_cancel(&task.user) {
        return Err(ApiError::PermissionDenied(
            "you do not have permission to cancel this task".into(),
        ));
    }

    if crbs_core::types::build_phase_is_terminal(&task.phase) {
        return Err(ApiError::Conflict("task_already_terminal".into()));
    }

    let children = app
        .state_store
        .get_builds_by_task_id(task_id)
        .await
        .map_err(|e| {
            tracing::warn!(task_id = %task_id, error = %e, "Failed to get child builds for cancel");
            ApiError::Internal("failed to get child builds".into())
        })?;

    if children.is_empty() {
        // finalize 带终态守卫 + completed_at/duration：并发完成/失败先到者生效，不把
        // succeeded 翻 cancelled。Superseded = 竞态拒写，取消未生效、task 仍会被派发
        // → 409 让客户端重试，不静默 202。
        match app.state_store.finalize_cancelled_task(task_id).await {
            Err(e) => {
                tracing::warn!(task_id = %task_id, error = %e, "Failed to mark empty task as cancelled");
                return Err(ApiError::Internal(
                    "failed to cancel task without child builds".into(),
                ));
            }
            Ok(crbs_core::FinalizeOutcome::Superseded) => {
                return Err(ApiError::Conflict(
                    "task state changed during cancel; retry".into(),
                ));
            }
            // Finalized = 0-build task 落 cancelled；ChildrenActive 空子路径不会返回。
            Ok(_) => {}
        }

        let detail = serde_json::json!({
            "cancelled_build_ids": Vec::<i64>::new(),
            "skipped_build_ids": Vec::<i64>::new(),
            "failed_build_ids": Vec::<i64>::new(),
        })
        .to_string();
        audit_cancel(app, &ctx.user, &ctx.role, task_id, &detail).await;

        return Ok(CancelTaskOutcome {
            cancelled_build_ids: Vec::new(),
            skipped_build_ids: Vec::new(),
            failed_build_ids: Vec::new(),
            message: "task cancelled".into(),
        });
    }

    let mut cancelled_build_ids = Vec::new();
    let mut skipped_build_ids = Vec::new();
    let mut failed_build_ids = Vec::new();

    for build in &children {
        let phase = build.phase.as_str();
        if crbs_core::types::build_phase_is_terminal(phase) {
            skipped_build_ids.push(build.id);
            continue;
        }

        let token = {
            let map = app.active_builds.lock().await;
            map.get(&build.id).cloned()
        };

        if let Some(ref cancel) = token {
            cancel.cancel();
            cancelled_build_ids.push(build.id);
        } else if matches!(phase, "pending" | "assigned" | "building") {
            // 本地未在跑（含已分发 Worker）→ 分布式取消；building 为软取消，
            // Worker 上报时按 DB 中 cancelled 状态处置。
            match cancel_distributed_build(app, build.id).await {
                Ok(_) => cancelled_build_ids.push(build.id),
                Err(e) => {
                    // 取消失败（DB 错误 / 终态守卫 409 竞态）单独归 failed_build_ids，
                    // 与"已终态跳过"区分，防误导客户端认为无需取消。
                    tracing::warn!(
                        build_id = %build.id,
                        task_id = %task_id,
                        error = ?e,
                        "Failed to cancel child build"
                    );
                    failed_build_ids.push(build.id);
                }
            }
        } else {
            skipped_build_ids.push(build.id);
        }
    }

    let detail = serde_json::json!({
        "cancelled_build_ids": cancelled_build_ids,
        "skipped_build_ids": skipped_build_ids,
        "failed_build_ids": failed_build_ids,
    })
    .to_string();
    audit_cancel(app, &ctx.user, &ctx.role, task_id, &detail).await;

    // 父 Task phase 同步：与 complete_build 同用 aggregate_child_phases（全部终态
    // 才收口，failed > cancelled > timeout > succeeded），写入带 completed_at/duration
    // + 终态守卫。非空子路径只出 Finalized/ChildrenActive（均软收敛，202 已受理）。
    if let Err(e) = app.state_store.finalize_cancelled_task(task_id).await {
        tracing::warn!(
            task_id = %task_id,
            error = %e,
            "Failed to update parent task phase after cancel"
        );
    }

    let message = if !failed_build_ids.is_empty() {
        // 部分成功语义（202 不变）：提示客户端检查 failed_build_ids 重试或排查。
        format!(
            "cancel partially applied: {} cancelled, {} failed",
            cancelled_build_ids.len(),
            failed_build_ids.len()
        )
    } else if cancelled_build_ids.is_empty() && !skipped_build_ids.is_empty() {
        "no cancellable child builds".into()
    } else {
        "cancel request accepted; child builds are being cancelled".into()
    };

    Ok(CancelTaskOutcome {
        cancelled_build_ids,
        skipped_build_ids,
        failed_build_ids,
        message,
    })
}

/// 写取消审计日志；失败只 warn 不中断取消流程（审计缺失不应让已生效的取消回滚）。
async fn audit_cancel(app: &Arc<AppState>, user: &str, role: &str, task_id: i64, detail: &str) {
    if let Err(e) = app
        .state_store
        .audit_log(
            user,
            role,
            "cancel_task",
            Some(&task_id.to_string()),
            Some(detail),
        )
        .await
    {
        tracing::warn!(task_id = %task_id, error = %e, "Failed to write cancel audit log");
    }
}
