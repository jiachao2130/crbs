// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 仪表盘 SSE：状态计数与任务时间线。

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::health::compute_public_status;
use crate::server::state::AppState;

use super::common::*;

/// Dashboard 兜底轮询间隔（30s）：状态变更由通知推送，兜底仅覆盖遗漏。
const DASHBOARD_FALLBACK_INTERVAL: Duration = Duration::from_secs(30);

/// Dashboard 状态 SSE：状态写入通知即时推送 `compute_public_status`，变化
/// 才推送；30s 兜底防遗漏 + 30s 墙钟复鉴权。
pub(crate) async fn dashboard_sse(
    State(app): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    auth: Option<Extension<AuthContext>>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    dashboard_sse_with_poll(
        State(app),
        headers,
        auth,
        SsePollConfig {
            poll_interval: DASHBOARD_FALLBACK_INTERVAL,
            visibility_recheck_interval: SSE_POLL_DEFAULT.visibility_recheck_interval,
        },
    )
    .await
}

/// [`dashboard_sse`] 的可注入参数版本（测试注入小间隔驱动循环）。
pub(super) async fn dashboard_sse_with_poll(
    State(app): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    auth: Option<Extension<AuthContext>>,
    poll: SsePollConfig,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    check_view_access(&app, auth.as_ref().map(|ext| &ext.0))?;
    let mut auth = auth.map(|ext| ext.0);
    let auth_state = Arc::new(crate::server::auth::AuthMiddlewareState {
        app_state: app.clone(),
    });
    let (tx, rx) = mpsc::channel::<Result<Event, std::convert::Infallible>>(4);

    tokio::spawn(async move {
        send_connect_retry_hint(&tx);
        let deadline = tokio::time::Instant::now() + MAX_SSE_LIFETIME;
        let mut last: Option<String> = None;
        let mut queries: u64 = 0;
        let mut pushes: u64 = 0;
        let mut consecutive_errors: u32 = 0;
        let mut last_visibility_check = tokio::time::Instant::now();
        loop {
            if tx.is_closed() || tokio::time::Instant::now() >= deadline {
                break;
            }
            queries += 1;
            // 握手快照可能在流内撤销/过期/降级：按握手同一条 resolve_token
            // 链周期重解析，凭据失效或不再满足查看门槛即断流；成功顺带刷新
            // 身份快照。匿名连接无权限可收回，跳过。
            if auth.is_some() && last_visibility_check.elapsed() >= poll.visibility_recheck_interval
            {
                last_visibility_check = tokio::time::Instant::now();
                match crate::server::auth::resolve_token(&auth_state, &headers).await {
                    Ok(ctx) => {
                        if check_view_access(&app, ctx.as_ref()).is_err() {
                            break;
                        }
                        auth = ctx;
                    }
                    Err(e) => {
                        if !sse_reauth_error_is_transient(&e) {
                            break;
                        }
                        consecutive_errors += 1;
                        if consecutive_errors >= MAX_CONSECUTIVE_QUERY_ERRORS {
                            tracing::warn!(
                                error = ?e,
                                consecutive = consecutive_errors,
                                "Dashboard SSE re-auth keeps failing; closing stream"
                            );
                            break;
                        }
                        log_transient_retry!(
                            consecutive_errors,
                            error = ?e,
                            consecutive = consecutive_errors,
                            "Transient backend error in dashboard SSE re-auth; retrying"
                        );
                    }
                }
            }
            match compute_public_status(&app, auth.as_ref()).await {
                Ok(status) => {
                    consecutive_errors = 0;
                    // 去重签名剔除 timestamp（每次调用新生成，纳入则恒不等、
                    // 恒推），只取 tasks/workers 子结构；payload 仍发完整 status。
                    let sig = match serde_json::to_string(&(&status.tasks, &status.workers)) {
                        Ok(sig) => sig,
                        Err(e) => {
                            tracing::error!(error = %e, "Failed to serialize dashboard status signature");
                            break;
                        }
                    };
                    if last.as_ref() != Some(&sig) {
                        let data = match serde_json::to_string(&status) {
                            Ok(data) => data,
                            Err(e) => {
                                tracing::error!(error = %e, "Failed to serialize dashboard status");
                                break;
                            }
                        };
                        let event = Event::default().event("status").data(data);
                        if tx.send(Ok(event)).await.is_err() {
                            break;
                        }
                        pushes += 1;
                        last = Some(sig);
                    }
                }
                Err(e) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_CONSECUTIVE_QUERY_ERRORS {
                        tracing::warn!(
                            error = ?e,
                            consecutive = consecutive_errors,
                            "Dashboard SSE queries keep failing; closing stream"
                        );
                        break;
                    }
                    log_transient_retry!(
                        consecutive_errors,
                        error = ?e,
                        consecutive = consecutive_errors,
                        "Transient DB error in dashboard SSE loop; retrying"
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
        tracing::debug!(queries, pushes, "dashboard sse loop stats");
    });

    Ok(sse_no_buffering(
        Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::default()),
    ))
}

/// 与 SSR phase_timeline 同口径的可见 spans：工具步骤（ccache-init /
/// ccache-summary）按名隐藏、配置性 SKIP（ccache_disabled）聚合为 skip-chip，
/// 签名与负载一致排除。名单唯一真源：
/// [`crate::server::routes::ui::components::HIDDEN_TOOL_PHASES`]。
pub(super) fn visible_timeline_spans(
    spans: &[crbs_core::engine::profile::PhaseSpan],
) -> Vec<&crbs_core::engine::profile::PhaseSpan> {
    spans
        .iter()
        .filter(|s| {
            !crate::server::routes::ui::components::HIDDEN_TOOL_PHASES.contains(&s.name.as_str())
        })
        .filter(|s| !(s.skipped && s.reason.as_deref() == Some("ccache_disabled")))
        .collect()
}

/// timeline 推送签名：`<条数>/name:state,name:state,…`——只有可见 spans 的
/// 名称/状态集合变化才算变化，running 步骤的已流逝时长不入签名（兜底 tick
/// 不因时长增长重复推送）；空集签名为空串（与循环初始值同值，不推空负载）。
pub(super) fn timeline_signature(spans: &[crbs_core::engine::profile::PhaseSpan]) -> String {
    let parts: Vec<String> = visible_timeline_spans(spans)
        .into_iter()
        .map(|s| format!("{}:{}", s.name, s.state()))
        .collect();
    if parts.is_empty() {
        return String::new();
    }
    format!("{}/{}", parts.len(), parts.join(","))
}

/// timeline 事件负载：对齐 phase_timeline SSR 的紧凑 JSON 数组——
/// `duration_seconds` 仅 END 已知时有值（running 由客户端画 "…"），`reason`
/// 透传 SKIP 原因。已知边界（非缺陷）：live 期间子阶段不随 timeline 事件
/// 推进（签名只含顶层 `name:state`），终态 reload 后由 SSR 全量呈现。
pub(super) fn timeline_event_payload(spans: &[crbs_core::engine::profile::PhaseSpan]) -> String {
    serde_json::json!(visible_timeline_spans(spans)
        .into_iter()
        .map(|s| serde_json::json!({
            "name": s.name,
            "state": s.state(),
            "duration_seconds": s.end.is_some().then(|| s.elapsed_seconds(0.0)),
            "reason": s.reason,
        }))
        .collect::<Vec<_>>())
    .to_string()
}
