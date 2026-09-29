// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 任务详情 SSE：子构建阶段聚合推送。

use std::sync::Arc;

use axum::extract::{Extension, Path, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::logs::build_phase_is_terminal;
use crate::server::state::AppState;

use super::common::*;

/// Task 状态 SSE：通知即时推送 `get_task` + 子构建摘要，phase 或任一子构建
/// 的 (phase, duration) 变化时推送；5s 兜底防遗漏。
pub(crate) async fn task_sse(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    headers: axum::http::HeaderMap,
    auth: Option<Extension<AuthContext>>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    task_sse_with_poll(State(app), Path(id), headers, auth, SSE_POLL_DEFAULT).await
}

/// [`task_sse`] 的可注入参数版本（测试注入小间隔驱动循环）。
pub(super) async fn task_sse_with_poll(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    headers: axum::http::HeaderMap,
    auth: Option<Extension<AuthContext>>,
    poll: SsePollConfig,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    check_view_access(&app, auth.as_ref().map(|ext| &ext.0))?;
    let _record = fetch_task_checked(&app, id, auth.as_ref().map(|ext| &ext.0)).await?;
    let mut sse_auth = auth.as_ref().map(|ext| ext.0.clone());
    let auth_state = Arc::new(crate::server::auth::AuthMiddlewareState {
        app_state: app.clone(),
    });
    let (tx, rx) = mpsc::channel::<Result<Event, std::convert::Infallible>>(4);

    tokio::spawn(async move {
        send_connect_retry_hint(&tx);
        let deadline = tokio::time::Instant::now() + MAX_SSE_LIFETIME;
        // 推送签名：task phase + 各子构建 (id, phase, duration)。只盯 task phase
        // 会漏子构建变化（building 的子构建相继完成时 task 不变）。
        let mut last_sig = String::new();
        let mut last_visibility_check = tokio::time::Instant::now();
        let mut queries: u64 = 0;
        let mut pushes: u64 = 0;
        let mut consecutive_errors: u32 = 0;
        loop {
            if tx.is_closed() || tokio::time::Instant::now() >= deadline {
                break;
            }
            queries += 1;
            sse_reauth_on_due!(
                app,
                id,
                &auth_state,
                &headers,
                sse_auth,
                poll.visibility_recheck_interval,
                last_visibility_check,
                consecutive_errors,
                fetch_task_checked,
                task_id,
                "Task SSE re-auth keeps failing; closing stream",
                "Transient DB error in task SSE re-auth; retrying"
            );
            match app.state_store.get_task(id).await {
                Ok(Some(record)) => {
                    // 子构建摘要查询失败不得降级为空列表推送（聚合摘要行会
                    // 闪刷成 "0 架构 · 成功 0 · 失败 0"）——走与 get_task Err
                    // 相同的容忍路径（下方 select 等待，下轮重查）；计数只在
                    // 两次查询全成功时重置。
                    match app.state_store.get_child_build_summaries(id).await {
                        Ok(children) => {
                            consecutive_errors = 0;
                            let sig = format!(
                                "{}|{}",
                                record.phase,
                                children
                                    .iter()
                                    .map(|c| format!("{}:{}:{:?}", c.id, c.phase, c.duration))
                                    .collect::<Vec<_>>()
                                    .join(",")
                            );
                            if sig != last_sig {
                                let payload = serde_json::json!({
                                    "phase": record.phase,
                                    "children": children
                                        .iter()
                                        .map(|c| serde_json::json!({
                                            "id": c.id,
                                            "phase": c.phase,
                                            "duration": c.duration,
                                        }))
                                        .collect::<Vec<_>>(),
                                })
                                .to_string();
                                let event = Event::default().event("task").data(payload);
                                if tx.send(Ok(event)).await.is_err() {
                                    break;
                                }
                                pushes += 1;
                                last_sig = sig;
                            }
                            if build_phase_is_terminal(&record.phase) {
                                break;
                            }
                        }
                        Err(e) => {
                            consecutive_errors += 1;
                            if consecutive_errors >= MAX_CONSECUTIVE_QUERY_ERRORS {
                                tracing::warn!(
                                    task_id = %id,
                                    error = %e,
                                    consecutive = consecutive_errors,
                                    "Task SSE child summary queries keep failing; closing stream"
                                );
                                break;
                            }
                            log_transient_retry!(
                                consecutive_errors,
                                task_id = %id,
                                error = %e,
                                consecutive = consecutive_errors,
                                "Transient DB error loading child build summaries in task SSE; retrying"
                            );
                        }
                    }
                }
                // 行不存在（被清理）与 DB 错误分流：前者仍立即断流。
                Ok(None) => break,
                Err(e) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_CONSECUTIVE_QUERY_ERRORS {
                        tracing::warn!(
                            task_id = %id,
                            error = %e,
                            consecutive = consecutive_errors,
                            "Task SSE queries keep failing; closing stream"
                        );
                        break;
                    }
                    log_transient_retry!(
                        consecutive_errors,
                        task_id = %id,
                        error = %e,
                        consecutive = consecutive_errors,
                        "Transient DB error in task SSE loop; retrying"
                    );
                }
            }
            tokio::select! {
                _ = app.state_store.changed() => {}
                _ = tokio::time::sleep(
                    poll.poll_interval * sse_db_retry_backoff_multiplier(consecutive_errors),
                ) => {}
                _ = app.shutdown_cancel.cancelled() => break,
            }
        }
        tracing::debug!(task_id = %id, queries, pushes, "task sse loop stats");
    });

    Ok(sse_no_buffering(
        Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::default()),
    ))
}
