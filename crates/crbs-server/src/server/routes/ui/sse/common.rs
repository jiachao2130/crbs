// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! SSE 端点共享件：无缓冲响应、重连/退避、访问与加载校验。

use std::sync::Arc;
use std::time::Duration;

use axum::response::sse::{Event, Sse};
use tokio::sync::mpsc;

use crate::server::auth::visibility::ensure_product_visible_for_record;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

/// SSE 响应统一附加 `x-accel-buffering: no`（nginx 等反代默认缓冲会攒住
/// 事件）与 `Cache-Control: no-cache`（自有契约，不依赖框架默认）。
pub(super) fn sse_no_buffering<S>(sse: Sse<S>) -> axum::response::Response
where
    Sse<S>: axum::response::IntoResponse,
{
    use axum::response::IntoResponse as _;
    let mut res = sse.into_response();
    res.headers_mut().insert(
        "x-accel-buffering",
        axum::http::HeaderValue::from_static("no"),
    );
    res.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-cache"),
    );
    res
}

/// SSE 连接最大存活时间（1 小时），防止客户端断开后后台任务无限运行。
pub(super) const MAX_SSE_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// SSE 循环参数（生产默认与单测注入共用一个循环实现）：循环由 StateStore
/// 变更通知即时驱动，`poll_interval` 只在通知遗漏或 DB 长时间无写入时兜底
/// 复查，空闲查询量由此决定。
pub(super) struct SsePollConfig {
    /// 兜底轮询间隔。
    pub(super) poll_interval: Duration,
    /// 可见性复鉴权间隔（墙钟）：超时即在下轮查询前复查；墙钟制使权限收回
    /// 的检测窗有固定上界，不随查询频次漂移。
    pub(super) visibility_recheck_interval: Duration,
}

/// 生产默认：5s 兜底轮询（通知驱动下空闲查询 ≤12 条/分钟/连接），每 30s
/// 墙钟复鉴权一次（握手后权限可能被收回）。
pub(super) const SSE_POLL_DEFAULT: SsePollConfig = SsePollConfig {
    poll_interval: Duration::from_secs(5),
    visibility_recheck_interval: Duration::from_secs(30),
};

/// SSE 断线重连提示值：连接建立即下发一次 `retry:` 行（通道容量 ≥4 且起始
/// 为空，try_send 必成功；无 event 名，不干扰按 `event:` 前缀的断言）。基准
/// 5s ±20% 抖动（值域 [4s, 6s]）——同拍断连固定 5s 会密集重连，抖动错开拍。
/// 连接建立后即发一次重连提示事件（四个 SSE 端点共用）：抖动取自墙钟亚秒。
pub(super) fn send_connect_retry_hint(tx: &mpsc::Sender<Result<Event, std::convert::Infallible>>) {
    let _ = tx.try_send(Ok(Event::default().retry(sse_reconnect_hint(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos(),
    ))));
}

pub(super) fn sse_reconnect_hint(nanos: u32) -> Duration {
    Duration::from_millis(4000 + (nanos % 2001) as u64)
}

/// SSE 循环对 DB 查询错误的容忍阈值：连续错误达到该次数才断流（任一次
/// `Ok` 即重置）。瞬时抖动直接 break 会使重连握手仍错 → EventSource
/// CLOSED 永久失活；总上界仍是 [`MAX_SSE_LIFETIME`]。
pub(super) const MAX_CONSECUTIVE_QUERY_ERRORS: u32 = 10;

/// 瞬态重试日志：首败 warn，后续降 debug（同根因无增量信息）；关流时的
/// 收口 warn 由调用方单独保留（不经本宏）。
macro_rules! log_transient_retry {
    ($consecutive:expr, $($fields:tt)*) => {
        if $consecutive == 1 {
            tracing::warn!($($fields)*);
        } else {
            tracing::debug!($($fields)*);
        }
    };
}

/// build/task/worker SSE 周期复鉴权共用块：墙钟到期先用与握手同一条
/// `resolve_token` 链重解析凭据（会话吊销/过期/用户禁用即刻生效），再跑
/// `$fetch` 复查记录可见性。非瞬态错误或连续瞬态达阈值即 break 断流。
/// 宏而非小函数：tracing 字段名与关流/重试文案按端点不同，需编译期展开。
macro_rules! sse_reauth_on_due {
    ($app:expr, $id:expr, $auth_state:expr, $headers:expr, $auth:ident, $interval:expr,
     $last_check:expr, $errors:expr,
     $fetch:path, $id_field:ident, $close_msg:literal, $retry_msg:literal) => {
        if $last_check.elapsed() >= $interval {
            $last_check = tokio::time::Instant::now();
            if $auth.is_some() {
                match crate::server::auth::resolve_token($auth_state, $headers).await {
                    Ok(ctx) => $auth = ctx,
                    Err(e) => {
                        if !sse_reauth_error_is_transient(&e) {
                            break;
                        }
                        $errors += 1;
                        if $errors >= MAX_CONSECUTIVE_QUERY_ERRORS {
                            tracing::warn!(
                                $id_field = %$id,
                                error = ?e,
                                consecutive = $errors,
                                $close_msg
                            );
                            break;
                        }
                        log_transient_retry!(
                            $errors,
                            $id_field = %$id,
                            error = ?e,
                            consecutive = $errors,
                            $retry_msg
                        );
                        continue;
                    }
                }
            }
            if let Err(e) = $fetch(&$app, $id, $auth.as_ref()).await {
                if !sse_reauth_error_is_transient(&e) {
                    break;
                }
                $errors += 1;
                if $errors >= MAX_CONSECUTIVE_QUERY_ERRORS {
                    tracing::warn!(
                        $id_field = %$id,
                        error = ?e,
                        consecutive = $errors,
                        $close_msg
                    );
                    break;
                }
                log_transient_retry!(
                    $errors,
                    $id_field = %$id,
                    error = ?e,
                    consecutive = $errors,
                    $retry_msg
                );
            }
        }
    };
}

/// DB 故障期兜底 sleep 的退避乘数（移位钳 4，对齐 scheduler.rs
/// `tick_backoff_secs`）：连续错误乘数 1→2→4→8→16 封顶，首错不放大（保留
/// 快速恢复），任一成功归 1。只放大兜底 sleep 臂——通知唤醒不受退避，DB
/// 恢复不拖慢。log 流计数器只由 30s 复鉴权墙喂入，退避最迟故障后 30s 生效。
pub(crate) fn sse_db_retry_backoff_multiplier(consecutive_errors: u32) -> u32 {
    1u32 << consecutive_errors.saturating_sub(1).min(4)
}

/// SSE 复鉴权失败的分流：鉴权/权限类是终局判定立即断流；服务不可用类
///（含 auth 层 DB 故障映射）是瞬态，计入 `consecutive_errors` 容忍——直接
/// break 会使 EventSource CLOSED 永久失活。
pub(super) fn sse_reauth_error_is_transient(err: &ApiError) -> bool {
    matches!(
        err,
        ApiError::ServiceUnavailable(_) | ApiError::Internal(_) | ApiError::GatewayTimeout(_)
    )
}

/// 检查是否满足查看类 SSE 的公开访问配置。
pub(super) fn check_view_access(
    app: &AppState,
    auth: Option<&AuthContext>,
) -> Result<(), ApiError> {
    super::super::check_public_access(app, app.server_config.public_access.view, auth)
}

/// 检查是否满足日志类 SSE 的公开访问配置。
pub(super) fn check_log_access(app: &AppState, auth: Option<&AuthContext>) -> Result<(), ApiError> {
    super::super::check_public_access(app, app.server_config.public_access.logs, auth)
}

/// 获取构建记录并检查查看权限。
pub(super) async fn fetch_build_checked(
    app: &Arc<AppState>,
    build_id: i64,
    auth: Option<&AuthContext>,
) -> Result<crbs_core::BuildRecord, ApiError> {
    let record = app
        .state_store
        .get_build(build_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("build", build_id))?;
    // 产品级可见性（与 get_task 同口径）：private 产品对无权限用户 403；
    // 匿名走 public/孤儿产品语义。
    ensure_product_visible_for_record(app, &record.product, auth).await?;
    Ok(record)
}

/// 获取任务记录并检查查看权限。
pub(super) async fn fetch_task_checked(
    app: &Arc<AppState>,
    task_id: i64,
    auth: Option<&AuthContext>,
) -> Result<crbs_core::TaskRecord, ApiError> {
    let record = app
        .state_store
        .get_task(task_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("task", task_id))?;
    // 产品级可见性：与 get_task / fetch_build_checked 同口径，SSE 不做例外。
    ensure_product_visible_for_record(app, &record.product, auth).await?;
    Ok(record)
}
