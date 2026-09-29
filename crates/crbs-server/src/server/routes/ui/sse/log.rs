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

/// 日志流兜底轮询间隔（5s）：日志到达与终态/result_dir 落定均有通知源，
/// 兜底只覆盖无通知源的遗漏——引擎时间戳目录扫描与文件截断复查。
const LOG_SSE_FALLBACK_INTERVAL: Duration = Duration::from_secs(5);

/// 日志事件：`id` 为本 chunk 末尾的累计字节偏移（续传游标）。
///
/// data 显式把 `\r` 归一为 `\n`：axum `Event::data` 双切分逐段补 `data: `
/// 前缀，归一使 wire 形态与浏览器重组结果一致、可测试；落盘与 CLI chunked
/// 流不归一（终端 rpm 进度条依赖 `\r`）。1:1 替换，id 偏移与续传语义不变。
///
/// ponytail: id 复用当前 Source 的文件字节偏移空间，不引入全局序列号——
/// 依赖 report_logs 双写使两空间一致；仅来源中途切换时旧 id 可能指向新空间
/// 的错误字节（重连后漏读/重读少量行）。
pub(super) fn log_event(offset: u64, text: &str) -> Event {
    Event::default()
        .event("log")
        .id(offset.to_string())
        .data(text.replace('\r', "\n"))
}

/// 终态收尾事件：data 与 build SSE 同风格（{"phase":"<终态>"}）。客户端收到
/// end 后主动关流；未收到则浏览器原生重连带 Last-Event-ID 续传。终态且无
/// 任何日志来源的 404 在握手阶段收口，不进入本函数所在流。
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

/// 日志流终局收尾（Waiting/Buffer/File 三分支共用）：发 end 后由调用方
/// break。行已删时 [`log_end_event`] 解析不到 phase、发空串——log_sse_script
/// 对 end 的 phase 有 `|| ''` 回退，空串即"行不在"的准确语义。
async fn send_log_end(
    app: &Arc<AppState>,
    id: i64,
    tx: &mpsc::Sender<Result<Event, std::convert::Infallible>>,
) {
    let end = log_end_event(app, id).await;
    let _ = tx.send(Ok(end)).await;
}

/// 慢客户端空洞补读——offset 落在 FIFO 淘汰区（front 洞）或全局上限拒收
/// 窗口的中途洞时，从持久化 build.log 读 `[start, end)` 逐块经 `tx` 推送，
/// 事件 id 用块末文件累计偏移（read_persisted_log_tail 同款 pos 语义）；字节
/// 对齐依据 report_logs 双写缓冲与落盘、同一偏移空间。
///
/// 路径先直开 `artifact_dir/{build_id}/build.log`（活构建期唯一落盘副本；
/// resolve 前两候选 result_dir/引擎目录此时均未落定），miss 再回落
/// resolve_log_path_for_record（终态驱逐后 artifact 副本可能已被 GC 清理）。
///
/// 返回 `false` = 补读源完全不可得（一字节未推），调用方 debug 留痕后跳过
/// 缺口；EOF 不足额（512MB cap 长度分歧）、读错误、客户端断开均返回 `true`。
async fn backfill_log_hole(
    app: &Arc<AppState>,
    id: i64,
    start: usize,
    end: usize,
    tx: &mpsc::Sender<Result<Event, std::convert::Infallible>>,
) -> bool {
    /// 补读分块大小：与 read_persisted_log_tail 的 TAIL_CHUNK_BYTES 一致。
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
                // 洞补读不足额（debug 留痕）：文件短于 end——512MB cap 长度
                // 分歧形态，[pos, end) 本次缺失。
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

/// 日志 SSE：实时日志 chunk 推送，默认从连接建立时的日志末尾开始（tail
/// -f，避免 live 页面重复展示已渲染的 preview 内容），`?offset=0` 从头读。
/// 起始偏移优先级：`Last-Event-ID`（浏览器重连自动携带）> `?offset` > tail。
/// 每 log 事件带 `id: <累计偏移>`，终态先发 `event: end` 再关流。
///
/// 日志来源在流内动态确定：等待态同时监听 LogBuffer 注册通知、状态变更
/// 通知（`result_dir` 可能中段才写入）与兜底轮询（时间戳目录扫描无通知源），
/// 哪条先就绪进哪个流态。文件态一旦开始输出不再切换——file/buffer 两套字节
/// 偏移不一致会重复输出。
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

/// [`log_sse`] 的可注入参数版本（测试注入小间隔驱动循环）。
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
    // 仅做鉴权与 build 存在性校验（404/403）；日志路径在流内动态解析。
    let _ = fetch_build_checked(&app, id, auth.as_ref().map(|ext| &ext.0)).await?;
    let mut sse_auth = auth.as_ref().map(|ext| ext.0.clone());
    let auth_state = Arc::new(crate::server::auth::AuthMiddlewareState {
        app_state: app.clone(),
    });
    let auth_headers = headers.clone();
    let (tx, rx) = mpsc::channel::<Result<Event, std::convert::Infallible>>(16);
    // 续传优先级：Last-Event-ID > ?offset > 默认 tail；非法头（非数字/非
    // ASCII）静默降级到下一级，不拒绝连接。
    let requested_offset = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .or(q.offset);

    // 终态且无任何日志来源 → 404（EventSource 对 404 不重连，不能挂死连接）。
    // 一次 get_build 同喂终态判定与路径解析；读取失败按非终态处理（DB 瞬态
    // 不杀连接）。
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
        /// 日志流来源状态机。
        enum Source {
            /// 尚未输出任何内容：等待 buffer 注册或本地文件出现。
            Waiting,
            /// LogBuffer 实时流（Worker 构建），值为已读字节偏移。
            Buffer(usize),
            /// 本地文件 tail（hub-local 构建）：路径（截断重开用）、文件句柄、当前读位置。
            File(std::path::PathBuf, tokio::fs::File, u64),
        }

        let deadline = tokio::time::Instant::now() + MAX_SSE_LIFETIME;
        let mut buf = bytes::BytesMut::with_capacity(4096);
        let mut source = Source::Waiting;
        // queries = 循环轮次数（非 DB 查询数），pushes = 日志事件数。
        let mut queries: u64 = 0;
        let mut pushes: u64 = 0;
        let mut last_visibility_check = tokio::time::Instant::now();
        // 复鉴权连续错误计数：本循环无常规 DB 查询作重置点，复鉴权成功即重置。
        let mut consecutive_errors: u32 = 0;
        // File 态 EOF 的 stat 连续错误计数：独立于复鉴权计数（后者以复鉴权
        // 成功为重置点，DB 健康时每 30s 清零，stat 持续失败到不了阈值）；
        // stat 成功即重置。
        let mut consecutive_stat_errors: u32 = 0;
        // File 态 read 连续错误计数（同款预算）：read 走已持有的 fd，路径侧
        // 删除/轮转不影响 fd（unlink 后 read 照常出数据/EOF），Err 几乎只有
        // EIO/ESTALE 类瞬态、无墓碑信号需分流；read 成功即重置本计数。
        let mut consecutive_read_errors: u32 = 0;
        // 上一轮唤醒是否为"纯数据"（wait_change）：纯数据唤醒跳过终态查询
        //（省一次 get_build）；false 或空 chunks 时照查（见 Buffer 分支）。
        let mut data_wake = false;

        loop {
            if tx.is_closed() || tokio::time::Instant::now() >= deadline {
                break;
            }
            queries += 1;
            // 可见性复鉴权（墙钟 30s，对齐 build/task SSE）：先用与握手同源
            // 的 resolve_token 链重解析凭据（会话吊销/过期立即生效），再经
            // fetch_build_checked 复查记录可见性。
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
                        // u64 域 clamp 到当前 total：Last-Event-ID / ?offset 远大于
                        // 当前 total（编号空间重置、服务端重启后重连）时，窄平台
                        // 裸转 usize 可能回绕成小偏移造成全量重放；SSE 无法像
                        // CLI logs 那样对非法 offset 回 400，取 clamp 语义。
                        let total = app.log_buffer.total_size(id).unwrap_or(0);
                        let offset = requested_offset
                            .map(|o| o.min(total as u64) as usize)
                            .unwrap_or(total);
                        source = Source::Buffer(offset);
                        continue;
                    }
                    // 一次 get_build 同喂路径解析与终态判定。三分流：行在→
                    // 解析路径；行删→发 end 断流（JS es.close() 停自动重连，意外
                    // 重连由握手 404 兜底）；DB 错→继续等（复鉴权计数已覆盖）。
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
                        // 期间翻终态且始终无日志来源：发 end 关流（新连接才走 404）。
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
                    // 不变量保险：行不存在（被 prune）时 read_since 返回
                    // new_offset=0，回写会让续传事件 id 回拨——用 max 保持单调。
                    *offset = (*offset).max(new_offset);
                    // 空洞检测（front 洞：start < front；中途洞：拒收窗口使
                    // 首个存活 chunk 偏移 > start）：洞区间均有落盘副本（被拒/
                    // 被淘汰 chunk 照常落盘），补读后对齐洞尾并丢弃本轮 chunks
                    //（下轮从洞尾重读，避免双推）；补读不可得则 debug 留痕跳过。
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
                    // 空 chunks 守卫的输入：先取快照，chunks 随后按值消费。
                    let chunks_empty = chunks.is_empty();
                    // 事件 id 恒等于真实文件偏移（chunk 真实起始偏移 + len）：
                    // 重连带 Last-Event-ID=N 时从 N 继续读。
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
                    // 纯数据唤醒跳过终态查询——终态翻转由
                    // state_store.changed() 或兜底 tick 补查，end 最坏延迟 ≤ 兜底
                    // 间隔。空 chunks 守卫必须保留：evict 唤醒无新数据且 Notify
                    // 句柄已移除，误判会挂到兜底 tick。行删经 is_build_terminal
                    // 同样为真，同路收尾断流。
                    if (!data_wake || chunks_empty) && is_build_terminal(&app.state_store, id).await
                    {
                        // 驱逐竞争窗口补尾：终态驱逐清出缓冲的行从落盘
                        // build.log 分块补读再结束（与 CLI 日志流共用
                        // read_persisted_log_tail）；闭包的 pos 即文件累计偏移，
                        // 续传 id 语义与 File 态一致。
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
                            // EOF：检查文件是否被截断或删除。
                            //
                            // stat 分流：NotFound = "文件被删"墓碑信号，立即断流
                            //（裸 break；重连握手按 404/等待态收口）；其余瞬态
                            //（ESTALE 等）计入 consecutive_stat_errors 重试，
                            // 连续超阈值才与被删同收口。
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
                                // 文件截断：重开定位用本连接已推进位置而非
                                // 握手期 requested_offset 快照——回退会在重写
                                // 增长过该值时重放已推内容、id 回退。分支条件
                                // 下恒等于 current_size，`.min` 是防御形态。
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
                                        // 保 break（不发 end，同墓碑臂）：
                                        // stat 刚证实截断（current_size <
                                        // *position）后 open 失败 = 文件在
                                        // stat→open 窗口内被删/挪走，立即断流。
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
                            // read 瞬态（EIO/ESTALE）同 stat 臂容忍预算：
                            // 计数重试，连续超阈值才断流（裸 break、无 end）。
                            // fd 持有使路径删除不影响 read，无墓碑分流需求。
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
