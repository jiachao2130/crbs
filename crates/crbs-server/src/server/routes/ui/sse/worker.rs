// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! Worker SSE：在线状态与负载快照。

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, Path, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::server::auth::visibility::compute_product_visibility;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

use super::common::*;

/// 获取 worker 并检查查看权限（worker 无产品可见性维度，view 门槛即全部）；
/// 行不存在 → 404（EventSource 对 404 不重连）。
/// Worker 详情页 SSE 兜底 tick（10s）：worker 无 hub 侧事件源（心跳/状态由
/// worker 直写 DB），走服务端 interval tick 快照模式——`state_store.changed()`
/// 唤醒只是省电加速，不变更"周期快照 + 签名去重"的推送语义。
const WORKER_SSE_TICK: Duration = Duration::from_secs(10);

async fn fetch_worker_checked(
    app: &Arc<AppState>,
    worker_id: i64,
    auth: Option<&AuthContext>,
) -> Result<crbs_core::WorkerStatus, ApiError> {
    check_view_access(app, auth)?;
    app.state_store
        .get_worker(worker_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("worker", worker_id))
}

/// worker 快照（UI SSE payload）：None = worker 已删除（调用方断流）。
/// 返回 `(payload 文本, 去重签名, 是否 offline 终态)`——签名即 payload 原文
/// （字段集固定、无 dashboard 的时间戳漂移字段）；offline 时仍先推终态事件
/// 再由调用方关流，页面 JS 收到后 reload 落回 SSR 离线态。
async fn worker_snapshot(
    app: &Arc<AppState>,
    worker_id: i64,
    auth: Option<&AuthContext>,
) -> Result<Option<(String, String, bool)>, ApiError> {
    let Some(w) = app
        .state_store
        .get_worker(worker_id)
        .await
        .map_err(ApiError::from)?
    else {
        return Ok(None);
    };
    // SSE 与详情页同口径：私有产品的包名不得进入匿名 payload。
    let visibility = compute_product_visibility(app, auth).await?;
    let active: Vec<_> = app
        .state_store
        .list_worker_active_builds(worker_id)
        .await
        .map_err(ApiError::from)?
        .into_iter()
        .filter(|b| visibility.allows(&b.product))
        .collect();
    let recent: Vec<_> = app
        .state_store
        .list_worker_recent_builds(worker_id)
        .await
        .map_err(ApiError::from)?
        .into_iter()
        .filter(|b| visibility.allows(&b.product))
        .collect();
    // stale 判定同详情页 SSR（scheduler 判离线阈值 120s）；徽章 stale 词由
    // JS 按 lang 注入表渲染，payload 只带布尔。
    let stale = crate::server::routes::ui::components::worker_heartbeat_older_than(
        w.last_heartbeat.as_deref(),
        crate::server::scheduler::WORKER_HEARTBEAT_TIMEOUT_SECS as i64,
    );
    let value = serde_json::json!({
        "status": w.status,
        "stale": stale,
        "capacity": w.capacity,
        "cpu_util_pct": w.cpu_util_pct,
        "load1": w.load1,
        "ncpu": w.ncpu,
        "mem_used_pct": w.mem_used_pct,
        "mem_total_kb": w.mem_total_kb,
        "disk_free_kb": w.disk_free_kb,
        "resource_caps": w.resource_caps,
        "last_heartbeat": w.last_heartbeat,
        "active_builds": active
            .iter()
            .map(|b| serde_json::json!({
                "id": b.id,
                "pkg_name": b.pkg_name,
                "phase": b.phase,
                "started_at": b.started_at,
            }))
            .collect::<Vec<_>>(),
        "recent_builds": recent
            .iter()
            .map(|b| serde_json::json!({
                "id": b.id,
                // 整表重建需要包名列（applyRecentBuilds 与 SSR 行同构）。
                "pkg_name": b.pkg_name,
                "phase": b.phase,
                "started_at": b.started_at,
                "completed_at": b.completed_at,
            }))
            .collect::<Vec<_>>(),
    });
    let payload = value.to_string();
    let offline = w.status == "offline";
    Ok(Some((payload.clone(), payload, offline)))
}

/// Worker 详情页状态 SSE：interval tick 快照推送 `event: worker`（签名变化才
/// 推，10s 兜底 + changed() 加速）；offline 快照推完终态即关流，worker 删除
/// 静默断流（重连握手 404 收口）。权限/复鉴权姿态与 build SSE 同款（view 门
/// 槛 + 30s 墙钟复鉴权），页面 JS 契约见 worker_sse_script。
pub(crate) async fn worker_sse(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    headers: axum::http::HeaderMap,
    auth: Option<Extension<AuthContext>>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    worker_sse_with_poll(State(app), Path(id), headers, auth, WORKER_SSE_TICK).await
}

/// [`worker_sse`] 的可注入参数版本（测试注入小 tick 驱动循环）。
async fn worker_sse_with_poll(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    headers: axum::http::HeaderMap,
    auth: Option<Extension<AuthContext>>,
    tick: Duration,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let _worker = fetch_worker_checked(&app, id, auth.as_ref().map(|ext| &ext.0)).await?;
    let mut sse_auth = auth.as_ref().map(|ext| ext.0.clone());
    let auth_state = Arc::new(crate::server::auth::AuthMiddlewareState {
        app_state: app.clone(),
    });
    let (tx, rx) = mpsc::channel::<Result<Event, std::convert::Infallible>>(4);

    tokio::spawn(async move {
        send_connect_retry_hint(&tx);
        let deadline = tokio::time::Instant::now() + MAX_SSE_LIFETIME;
        // 初始空串：连接后首个快照恒推送一次（与 build SSE 的 last_phase 同形态）。
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
                SSE_POLL_DEFAULT.visibility_recheck_interval,
                last_visibility_check,
                consecutive_errors,
                fetch_worker_checked,
                worker_id,
                "Worker SSE re-auth keeps failing; closing stream",
                "Transient backend error in worker SSE re-auth; retrying"
            );
            match worker_snapshot(&app, id, sse_auth.as_ref()).await {
                Ok(Some((payload, sig, offline))) => {
                    consecutive_errors = 0;
                    if sig != last_sig {
                        let event = Event::default().event("worker").data(payload);
                        if tx.send(Ok(event)).await.is_err() {
                            break;
                        }
                        pushes += 1;
                        last_sig = sig;
                    }
                    // offline 终态：事件已在上方按签名推出（首连恒推），关流。
                    if offline {
                        break;
                    }
                }
                // 行不存在（worker 被移除）与 DB 错误分流：前者立即断流，
                // 无终态可推——重连握手按 404 收口。
                Ok(None) => break,
                Err(e) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_CONSECUTIVE_QUERY_ERRORS {
                        tracing::warn!(
                            worker_id = %id,
                            error = ?e,
                            consecutive = consecutive_errors,
                            "Worker SSE queries keep failing; closing stream"
                        );
                        break;
                    }
                    log_transient_retry!(
                        consecutive_errors,
                        worker_id = %id,
                        error = ?e,
                        consecutive = consecutive_errors,
                        "Transient DB error in worker SSE loop; retrying"
                    );
                }
            }
            tokio::select! {
                _ = app.state_store.changed() => {}
                _ = tokio::time::sleep(tick) => {}
                _ = app.shutdown_cancel.cancelled() => break,
            }
        }
        tracing::debug!(worker_id = %id, queries, pushes, "worker sse loop stats");
    });

    Ok(sse_no_buffering(
        Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::default()),
    ))
}
