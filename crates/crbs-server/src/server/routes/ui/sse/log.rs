// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建日志 SSE：缓冲/文件两种来源与断点续传。

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, Path, Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::logs::{build_phase_is_terminal, is_build_terminal, LogsQuery};
use crate::server::state::AppState;

use super::common::*;

const LOG_SSE_FALLBACK_INTERVAL: Duration = Duration::from_secs(5);

/// ponytail: id 复用当前 Source 的文件字节偏移空间，不引入全局序列号——
/// 依赖 report_logs 双写使两空间一致；仅来源中途切换时旧 id 可能指向新空间
/// 的错误字节（重连后漏读/重读少量行）。
pub(super) fn log_event(offset: u64, text: &str) -> Event {
    Event::default()
        .event("log")
        .id(offset.to_string())
        .data(text.replace('\r', "\n"))
}

async fn log_end_event(app: &Arc<AppState>, id: i64) -> Event {
    let phase = app
        .state_store
        .get_build(id)
        .await
        .ok()
        .flatten()
        .map(|r| r.phase)
        .unwrap_or_default();
    Event::default()
        .event("end")
        .data(serde_json::json!({"phase": phase}).to_string())
}

async fn send_log_end(
    app: &Arc<AppState>,
    id: i64,
    tx: &mpsc::Sender<Result<Event, std::convert::Infallible>>,
) {
    let end = log_end_event(app, id).await;
    let _ = tx.send(Ok(end)).await;
}

async fn backfill_log_hole(
    app: &Arc<AppState>,
    id: i64,
    start: usize,
    end: usize,
    tx: &mpsc::Sender<Result<Event, std::convert::Infallible>>,
) -> bool {
    const HOLE_CHUNK_BYTES: u64 = 4096;

    let (start, end) = match (u64::try_from(start).ok(), u64::try_from(end).ok()) {
        (Some(start), Some(end)) => (start, end),
        _ => return true,
    };
    if start >= end {
        return true;
    }
    let artifact_log = app.artifact_dir().join(id.to_string()).join("build.log");
    let mut file = match tokio::fs::File::open(&artifact_log).await {
        Ok(file) => file,
        Err(_) => {
            let record = app.state_store.get_build(id).await.ok().flatten();
            let Some(record) = record else {
                return false;
            };
            let Some(log_path) =
                crate::server::routes::logs::resolve_log_path_for_record(app, &record).await
            else {
                return false;
            };
            match tokio::fs::File::open(&log_path).await {
                Ok(file) => file,
                Err(_) => return false,
            }
        }
    };
    if tokio::io::AsyncSeekExt::seek(&mut file, std::io::SeekFrom::Start(start))
        .await
        .is_err()
    {
        return false;
    }
    let mut buf = bytes::BytesMut::with_capacity(HOLE_CHUNK_BYTES as usize);
    let mut pos = start;
    loop {
        if pos >= end {
            return true;
        }
        let want = (end - pos).min(HOLE_CHUNK_BYTES) as usize;
        buf.resize(want, 0);
        match tokio::io::AsyncReadExt::read(&mut file, &mut buf).await {
            Ok(0) => {
                if pos < end {
                    tracing::debug!(
                        build_id = %id,
                        start = %start,
                        end = %end,
                        reached = %pos,
                        "hole backfill hit EOF short of range (file flush lags buffer append)"
                    );
                }
                return true;
            }
            Ok(n) => {
                let chunk = buf.split_to(n).freeze();
                pos += n as u64;
                let text = String::from_utf8_lossy(&chunk);
                if tx.send(Ok(log_event(pos, text.as_ref()))).await.is_err() {
                    return true;
                }
            }
            Err(_) => {
                if pos < end {
                    tracing::debug!(
                        build_id = %id,
                        start = %start,
                        end = %end,
                        reached = %pos,
                        "hole backfill read error short of range"
                    );
                }
                return true;
            }
        }
    }
}

pub(crate) async fn log_sse(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(q): Query<LogsQuery>,
    headers: axum::http::HeaderMap,
    auth: Option<Extension<AuthContext>>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    log_sse_with_poll(
        State(app),
        Path(id),
        Query(q),
        headers,
        auth,
        SsePollConfig {
            poll_interval: LOG_SSE_FALLBACK_INTERVAL,
            visibility_recheck_interval: SSE_POLL_DEFAULT.visibility_recheck_interval,
        },
    )
    .await
}

pub(super) async fn log_sse_with_poll(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(q): Query<LogsQuery>,
    headers: axum::http::HeaderMap,
    auth: Option<Extension<AuthContext>>,
    poll: SsePollConfig,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    use crate::server::routes::logs::resolve_log_path_for_record;

    check_log_access(&app, auth.as_ref().map(|ext| &ext.0))?;

    let _ = fetch_build_checked(&app, id, auth.as_ref().map(|ext| &ext.0)).await?;
    let mut sse_auth = auth.as_ref().map(|ext| ext.0.clone());
    let auth_state = Arc::new(crate::server::auth::AuthMiddlewareState {
        app_state: app.clone(),
    });
    let auth_headers = headers.clone();
    let (tx, rx) = mpsc::channel::<Result<Event, std::convert::Infallible>>(16);

    let requested_offset = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .or(q.offset);

    if !app.log_buffer.has(id) {
        if let Some(record) = app.state_store.get_build(id).await.ok().flatten() {
            if build_phase_is_terminal(&record.phase)
                && resolve_log_path_for_record(&app, &record).await.is_none()
            {
                return Err(ApiError::not_found("log", id));
            }
        }
    }

    tokio::spawn(async move {
        send_connect_retry_hint(&tx);

        enum Source {
            Waiting,

            Buffer(usize),

            File(std::path::PathBuf, tokio::fs::File, u64),
        }

        let deadline = tokio::time::Instant::now() + MAX_SSE_LIFETIME;
        let mut buf = bytes::BytesMut::with_capacity(4096);
        let mut source = Source::Waiting;

        let mut queries: u64 = 0;
        let mut pushes: u64 = 0;
        let mut last_visibility_check = tokio::time::Instant::now();

        let mut consecutive_errors: u32 = 0;

        let mut consecutive_stat_errors: u32 = 0;

        let mut consecutive_read_errors: u32 = 0;

        let mut data_wake = false;

        loop {
            if tx.is_closed() || tokio::time::Instant::now() >= deadline {
                break;
            }
            queries += 1;

            if last_visibility_check.elapsed() >= poll.visibility_recheck_interval {
                last_visibility_check = tokio::time::Instant::now();
                let mut reauth_ok = true;
                if sse_auth.is_some() {
                    match crate::server::auth::resolve_token(&auth_state, &auth_headers).await {
                        Ok(ctx) => sse_auth = ctx,
                        Err(e) => {
                            if !sse_reauth_error_is_transient(&e) {
                                break;
                            }
                            consecutive_errors += 1;
                            if consecutive_errors >= MAX_CONSECUTIVE_QUERY_ERRORS {
                                tracing::warn!(
                                    build_id = %id,
                                    error = ?e,
                                    consecutive = consecutive_errors,
                                    "Log SSE re-auth keeps failing; closing stream"
                                );
                                break;
                            }
                            log_transient_retry!(
                                consecutive_errors,
                                build_id = %id,
                                error = ?e,
                                consecutive = consecutive_errors,
                                "Transient DB error in log SSE re-auth; retrying"
                            );
                            reauth_ok = false;
                        }
                    }
                }
                if reauth_ok {
                    match fetch_build_checked(&app, id, sse_auth.as_ref()).await {
                        Ok(_) => {
                            consecutive_errors = 0;
                        }
                        Err(e) => {
                            if !sse_reauth_error_is_transient(&e) {
                                break;
                            }
                            consecutive_errors += 1;
                            if consecutive_errors >= MAX_CONSECUTIVE_QUERY_ERRORS {
                                tracing::warn!(
                                    build_id = %id,
                                    error = ?e,
                                    consecutive = consecutive_errors,
                                    "Log SSE re-auth keeps failing; closing stream"
                                );
                                break;
                            }
                            log_transient_retry!(
                                consecutive_errors,
                                build_id = %id,
                                error = ?e,
                                consecutive = consecutive_errors,
                                "Transient DB error in log SSE re-auth; retrying"
                            );
                        }
                    }
                }
            }

            match &mut source {
                Source::Waiting => {
                    if app.log_buffer.has(id) {
                        let total = app.log_buffer.total_size(id).unwrap_or(0);
                        let offset = requested_offset
                            .map(|o| o.min(total as u64) as usize)
                            .unwrap_or(total);
                        source = Source::Buffer(offset);
                        continue;
                    }

                    let record = match app.state_store.get_build(id).await {
                        Ok(Some(record)) => Some(record),
                        Ok(None) => {
                            send_log_end(&app, id, &tx).await;
                            break;
                        }
                        Err(_) => None,
                    };
                    let resolved_log_path = match record.as_ref() {
                        Some(record) => resolve_log_path_for_record(&app, record).await,
                        None => None,
                    };
                    if let Some(log_path) = resolved_log_path {
                        let opened = async {
                            let mut file = tokio::fs::File::open(&log_path).await.ok()?;
                            let file_size = tokio::fs::metadata(&log_path).await.ok()?.len();
                            let position = requested_offset
                                .map(|o| o.min(file_size))
                                .unwrap_or(file_size);
                            tokio::io::AsyncSeekExt::seek(
                                &mut file,
                                std::io::SeekFrom::Start(position),
                            )
                            .await
                            .ok()?;
                            Some((file, position))
                        }
                        .await;
                        match opened {
                            Some((file, position)) => {
                                source = Source::File(log_path, file, position);
                                continue;
                            }
                            None => {
                                tracing::debug!(build_id = %id, "build.log disappeared before open; retrying");
                            }
                        }
                    } else if record
                        .as_ref()
                        .is_some_and(|r| build_phase_is_terminal(&r.phase))
                    {
                        send_log_end(&app, id, &tx).await;
                        break;
                    }
                    tokio::select! {
                        _ = app.log_buffer.wait_change(id) => {}
                        _ = app.state_store.changed() => {}
                        _ = tokio::time::sleep(
                            poll.poll_interval * sse_db_retry_backoff_multiplier(consecutive_errors),
                        ) => {}
                        _ = app.shutdown_cancel.cancelled() => break,
                    }
                }
                Source::Buffer(offset) => {
                    let start_offset = *offset;
                    let (chunks, new_offset, front_offset) =
                        app.log_buffer.read_since_with_offsets(id, *offset);

                    *offset = (*offset).max(new_offset);

                    let first_chunk_offset = chunks.first().map(|(o, _)| *o);
                    if start_offset < front_offset
                        || first_chunk_offset.is_some_and(|first| first > start_offset)
                    {
                        let hole_end = first_chunk_offset.unwrap_or(front_offset);
                        if !backfill_log_hole(&app, id, start_offset, hole_end, &tx).await {
                            tracing::debug!(
                                build_id = %id,
                                start = start_offset,
                                end = hole_end,
                                "log buffer hole has no persisted source; skipping evicted range"
                            );
                        }
                        *offset = hole_end;
                        continue;
                    }
                    let mut disconnected = false;

                    let chunks_empty = chunks.is_empty();

                    for (chunk_start, chunk) in chunks {
                        let text = String::from_utf8_lossy(&chunk);
                        let event = log_event((chunk_start + chunk.len()) as u64, text.as_ref());
                        if tx.send(Ok(event)).await.is_err() {
                            disconnected = true;
                            break;
                        }
                        pushes += 1;
                    }
                    if disconnected {
                        break;
                    }

                    if (!data_wake || chunks_empty) && is_build_terminal(&app.state_store, id).await
                    {
                        crate::server::routes::logs::read_persisted_log_tail(
                            &app,
                            id,
                            *offset,
                            None,
                            &tx,
                            |chunk, pos| {
                                let text = String::from_utf8_lossy(&chunk);
                                Ok(log_event(pos, text.as_ref()))
                            },
                        )
                        .await;
                        send_log_end(&app, id, &tx).await;
                        break;
                    }
                    data_wake = false;
                    tokio::select! {
                        _ = app.log_buffer.wait_change(id) => { data_wake = true; }
                        _ = app.state_store.changed() => {}
                        _ = tokio::time::sleep(
                            poll.poll_interval * sse_db_retry_backoff_multiplier(consecutive_errors),
                        ) => {}
                        _ = app.shutdown_cancel.cancelled() => break,
                    }
                }
                Source::File(log_path, file, position) => {
                    buf.resize(4096, 0);
                    match tokio::io::AsyncReadExt::read(file, &mut buf).await {
                        Ok(0) => {
                            consecutive_read_errors = 0;

                            let current_size = match tokio::fs::metadata(&*log_path).await {
                                Ok(m) => {
                                    consecutive_stat_errors = 0;
                                    m.len()
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                    tracing::debug!(
                                        build_id = %id,
                                        path = %log_path.display(),
                                        "log file removed; closing stream"
                                    );
                                    break;
                                }
                                Err(e) => {
                                    consecutive_stat_errors += 1;
                                    if consecutive_stat_errors >= MAX_CONSECUTIVE_QUERY_ERRORS {
                                        tracing::warn!(
                                            build_id = %id,
                                            path = %log_path.display(),
                                            error = %e,
                                            consecutive = consecutive_stat_errors,
                                            "Log SSE file stat keeps failing; closing stream"
                                        );
                                        break;
                                    }
                                    log_transient_retry!(
                                        consecutive_stat_errors,
                                        build_id = %id,
                                        path = %log_path.display(),
                                        error = %e,
                                        consecutive = consecutive_stat_errors,
                                        "Transient stat error in log SSE file tail; retrying"
                                    );
                                    tokio::select! {
                                        _ = app.state_store.changed() => {}
                                        _ = tokio::time::sleep(poll.poll_interval) => {}
                                        _ = app.shutdown_cancel.cancelled() => break,
                                    }
                                    continue;
                                }
                            };
                            if current_size < *position {
                                let reopened = async {
                                    let mut f = tokio::fs::File::open(&*log_path).await.ok()?;
                                    let pos = (*position).min(current_size);
                                    tokio::io::AsyncSeekExt::seek(
                                        &mut f,
                                        std::io::SeekFrom::Start(pos),
                                    )
                                    .await
                                    .ok()?;
                                    Some((f, pos))
                                }
                                .await;
                                match reopened {
                                    Some((f, pos)) => {
                                        *file = f;
                                        *position = pos;
                                        continue;
                                    }
                                    None => {
                                        break;
                                    }
                                }
                            }
                            if is_build_terminal(&app.state_store, id).await {
                                send_log_end(&app, id, &tx).await;
                                break;
                            }
                            tokio::select! {
                                _ = app.state_store.changed() => {}
                                _ = tokio::time::sleep(
                                    poll.poll_interval * sse_db_retry_backoff_multiplier(consecutive_errors),
                                ) => {}
                                _ = app.shutdown_cancel.cancelled() => break,
                            }
                        }
                        Ok(n) => {
                            consecutive_read_errors = 0;
                            *position += n as u64;
                            let chunk = buf.split_to(n).freeze();
                            let text = String::from_utf8_lossy(&chunk);
                            let event = log_event(*position, text.as_ref());
                            if tx.send(Ok(event)).await.is_err() {
                                break;
                            }
                            pushes += 1;
                        }
                        Err(e) => {
                            consecutive_read_errors += 1;
                            if consecutive_read_errors >= MAX_CONSECUTIVE_QUERY_ERRORS {
                                tracing::warn!(
                                    build_id = %id,
                                    path = %log_path.display(),
                                    error = %e,
                                    consecutive = consecutive_read_errors,
                                    "Log SSE file read keeps failing; closing stream"
                                );
                                break;
                            }
                            log_transient_retry!(
                                consecutive_read_errors,
                                build_id = %id,
                                path = %log_path.display(),
                                error = %e,
                                consecutive = consecutive_read_errors,
                                "Transient read error in log SSE file tail; retrying"
                            );
                            tokio::select! {
                                _ = app.state_store.changed() => {}
                                _ = tokio::time::sleep(poll.poll_interval) => {}
                                _ = app.shutdown_cancel.cancelled() => break,
                            }
                        }
                    }
                }
            }
        }
        tracing::debug!(build_id = %id, queries, pushes, "log sse loop stats");
    });

    Ok(sse_no_buffering(
        Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::default()),
    ))
}
