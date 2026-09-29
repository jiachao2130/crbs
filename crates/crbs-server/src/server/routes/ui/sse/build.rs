// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 构建详情 SSE：阶段与时间线推送。

use std::sync::Arc;

use axum::extract::{Extension, Path, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::logs::build_phase_is_terminal;
use crate::server::routes::ui::service::phase_timeline_spans;
use crate::server::state::AppState;

use super::common::*;
use super::dashboard::{timeline_event_payload, timeline_signature};

/// Build 状态 SSE：通知即时推送 `get_build`，phase 变化时推送；5s 兜底防
/// 遗漏。live 构建附带 `event: timeline`（签名变化才推）；终态不推（详情页
/// 全量 SSR）。
pub(crate) async fn build_sse(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    headers: axum::http::HeaderMap,
    auth: Option<Extension<AuthContext>>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    build_sse_with_poll(State(app), Path(id), headers, auth, SSE_POLL_DEFAULT).await
}

/// [`build_sse`] 的可注入参数版本（测试注入小间隔驱动循环）。
pub(super) async fn build_sse_with_poll(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    headers: axum::http::HeaderMap,
    auth: Option<Extension<AuthContext>>,
    poll: SsePollConfig,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    check_view_access(&app, auth.as_ref().map(|ext| &ext.0))?;
    // 先校验记录存在且用户有查看权限，避免无权限时仍创建一个长时间运行的 SSE 流。
    let _record = fetch_build_checked(&app, id, auth.as_ref().map(|ext| &ext.0)).await?;
    let mut sse_auth = auth.as_ref().map(|ext| ext.0.clone());
    let auth_state = Arc::new(crate::server::auth::AuthMiddlewareState {
        app_state: app.clone(),
    });
    let (tx, rx) = mpsc::channel::<Result<Event, std::convert::Infallible>>(4);

    tokio::spawn(async move {
        send_connect_retry_hint(&tx);
        let deadline = tokio::time::Instant::now() + MAX_SSE_LIFETIME;
        let mut last_phase = String::new();
        // 初始空串与"尚无标记"同值：连接时 spans 非空即首推一次。
        let mut last_timeline_sig = String::new();
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
                fetch_build_checked,
                build_id,
                "Build SSE re-auth keeps failing; closing stream",
                "Transient DB error in build SSE re-auth; retrying"
            );
            match app.state_store.get_build(id).await {
                Ok(Some(record)) => {
                    consecutive_errors = 0;
                    if record.phase != last_phase {
                        let data = serde_json::json!({"phase": record.phase}).to_string();
                        let event = Event::default().event("build").data(data);
                        if tx.send(Ok(event)).await.is_err() {
                            break;
                        }
                        pushes += 1;
                        last_phase = record.phase.clone();
                    }
                    // record 已在手，按 phase 纯函数判终态（与 is_build_terminal
                    // 同一终态集合），省一次 get_build。
                    let terminal = build_phase_is_terminal(&record.phase);
                    // live 构建附带时间线——签名变化才推 event: timeline；
                    // spans 计算失败在 phase_timeline_spans 内降级为空列表
                    //（warn 留痕），空签名不推空负载、不杀流。
                    if !terminal {
                        let spans = phase_timeline_spans(&app, &record).await;
                        let sig = timeline_signature(&spans);
                        if sig != last_timeline_sig {
                            let event = Event::default()
                                .event("timeline")
                                .data(timeline_event_payload(&spans));
                            if tx.send(Ok(event)).await.is_err() {
                                break;
                            }
                            pushes += 1;
                            last_timeline_sig = sig;
                        }
                    }
                    if terminal {
                        break;
                    }
                }
                // 行不存在（被清理）与 DB 错误分流：前者仍立即断流。
                Ok(None) => break,
                Err(e) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_CONSECUTIVE_QUERY_ERRORS {
                        tracing::warn!(
                            build_id = %id,
                            error = %e,
                            consecutive = consecutive_errors,
                            "Build SSE queries keep failing; closing stream"
                        );
                        break;
                    }
                    log_transient_retry!(
                        consecutive_errors,
                        build_id = %id,
                        error = %e,
                        consecutive = consecutive_errors,
                        "Transient DB error in build SSE loop; retrying"
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
        tracing::debug!(build_id = %id, queries, pushes, "build sse loop stats");
    });

    Ok(sse_no_buffering(
        Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::default()),
    ))
}
