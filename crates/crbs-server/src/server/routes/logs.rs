// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 日志获取端点：`/api/v1/builds/{id}/logs` 返回 chunked stream（tail -f
//! 语义）——默认从文件末尾推送新增日志直到构建终态；`?offset=N` 显式指定
//! 起始字节偏移。

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use bytes::Bytes;
use crbs_core::StateStore;

use crate::server::auth::visibility::ensure_product_visible_for_record;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::ui::sse_db_retry_backoff_multiplier;
use crate::server::state::AppState;

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/v1/builds/{id}/logs", get(get_logs))
}

#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct LogsQuery {
    pub offset: Option<u64>,
}

const MAX_LOG_STREAM_LIFETIME_SECS: u64 = 3600;

const LOG_STREAM_FALLBACK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

fn log_stream_fallback_sleep(consecutive_db_errors: u32) -> std::time::Duration {
    LOG_STREAM_FALLBACK_INTERVAL * sse_db_retry_backoff_multiplier(consecutive_db_errors)
}

const OFFSET_EXCEEDS_MSG: &str = "offset exceeds current log size";

/// 读取构建日志流：优先 LogBuffer（分布式构建进行中），否则回退本地文件
/// （本地构建 / 已完成分布式构建）。API 与 Web UI 共用入口；自行获取
/// BuildRecord 并做产品可见性权限检查。
pub(crate) async fn get_logs(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    Query(q): Query<LogsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let record = app
        .state_store
        .get_build(id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("build", id))?;

    ensure_product_visible_for_record(&app, &record.product, auth.as_ref().map(|e| &e.0)).await?;

    fetch_log_stream(&app, &record, q.offset).await
}

/// 日志流读取的共用实现：调用方预先取得 BuildRecord 并完成权限检查；
/// 按 LogBuffer 在位与否分流到缓冲流或文件流。
async fn fetch_log_stream(
    app: &Arc<AppState>,
    record: &crbs_core::BuildRecord,
    offset: Option<u64>,
) -> Result<Response, ApiError> {
    let id = record.id;

    if app.log_buffer.has(id) {
        return stream_logs_from_buffer(
            app.clone(),
            id,
            offset,
            std::time::Duration::from_secs(MAX_LOG_STREAM_LIFETIME_SECS),
        )
        .await;
    }

    let log_path = resolve_log_path_for_record(app, record).await;

    let Some(log_path) = log_path else {
        if offset.is_some() || is_build_terminal(&app.state_store, id).await {
            return Err(ApiError::not_found("log", id));
        }
        return stream_logs_when_file_appears(app.clone(), id).await;
    };

    let file_size = current_file_size(&log_path).await?;
    let start_offset = match offset {
        Some(o) => {
            if o > file_size {
                return Err(ApiError::Validation(OFFSET_EXCEEDS_MSG.into()));
            }
            o
        }
        None => file_size,
    };

    stream_logs_from_file(
        log_path,
        id,
        app.state_store.clone(),
        app.shutdown_cancel.clone(),
        start_offset,
        std::time::Duration::from_secs(MAX_LOG_STREAM_LIFETIME_SECS),
    )
    .await
}

pub(crate) async fn resolve_log_path(app: &Arc<AppState>, build_id: i64) -> Option<PathBuf> {
    let record = app.state_store.get_build(build_id).await.ok()??;
    resolve_log_path_for_record(app, &record).await
}

/// build.log 本地路径解析，按序三候选：1. record.result_dir/build.log（终态落点）；2.
/// {result_root}/{product}/{pkg_name}/{timestamp}-{build_id}/build.log（id 后缀精确匹配，覆盖 result_dir
/// 尚未写入的阶段）；3. {artifact_dir}/{build_id}/build.log（report_logs 的持久副本，上传失败构建的日志唯一来源）。前两个校验不越出
/// result_root。
pub(crate) async fn resolve_log_path_for_record(
    app: &Arc<AppState>,
    record: &crbs_core::BuildRecord,
) -> Option<PathBuf> {
    let build_id = record.id;
    let result_root = app.result_dir_for_or_default(&record.product).await;

    if let Some(ref result_dir) = record.result_dir {
        match crbs_core::util::validate_result_dir(result_dir, &result_root).await {
            Ok(base) => {
                let candidate = base.join("build.log");
                if crbs_core::util::is_regular_file_no_symlink(&candidate).await {
                    return Some(candidate);
                }
            }
            Err(e) => {
                tracing::warn!(build_id = %build_id, error = %e, "Invalid result_dir while resolving log path");
            }
        }
    }

    if let Some(path) = find_engine_log(
        &result_root,
        &record.product,
        &record.pkg_name,
        build_id,
        "build.log",
    )
    .await
    {
        return Some(path);
    }

    let artifact_log = app
        .artifact_dir()
        .join(build_id.to_string())
        .join("build.log");
    if crbs_core::util::is_regular_file_no_symlink(&artifact_log).await {
        return Some(artifact_log);
    }

    None
}

async fn find_engine_log(
    result_root: &std::path::Path,
    product: &str,
    pkg_name: &str,
    build_id: i64,
    file_name: &str,
) -> Option<PathBuf> {
    let pkg_root = crbs_core::util::canonicalize_within(
        &result_root.join(product).join(pkg_name),
        result_root,
    )
    .await
    .ok()?;
    let suffix = format!("-{}", build_id);
    let mut entries = tokio::fs::read_dir(&pkg_root).await.ok()?;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.ends_with(&suffix) {
            continue;
        }
        let candidate = entry.path().join(file_name);
        if crbs_core::util::is_regular_file_no_symlink(&candidate).await {
            return Some(candidate);
        }
    }
    None
}

async fn stream_logs_when_file_appears(
    app: Arc<AppState>,
    build_id: i64,
) -> Result<Response, ApiError> {
    enum LogSource {
        Buffer,

        File(PathBuf),
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(16);

    tokio::spawn(async move {
        let stream_deadline = tokio::time::Instant::now()
            + std::time::Duration::from_secs(MAX_LOG_STREAM_LIFETIME_SECS);

        let mut consecutive_db_errors: u32 = 0;

        let source = loop {
            if tokio::time::Instant::now() >= stream_deadline {
                let _ = tx
                    .send(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "log stream reached maximum lifetime",
                    )))
                    .await;
                return;
            }
            if tx.is_closed() {
                return;
            }
            if app.log_buffer.has(build_id) {
                break LogSource::Buffer;
            }

            let record = match app.state_store.get_build(build_id).await {
                Ok(Some(record)) => {
                    consecutive_db_errors = 0;
                    Some(record)
                }
                Ok(None) => return,
                Err(_) => {
                    consecutive_db_errors = consecutive_db_errors.saturating_add(1);
                    None
                }
            };
            let resolved = match record.as_ref() {
                Some(record) => resolve_log_path_for_record(&app, record).await,
                None => None,
            };
            if let Some(path) = resolved {
                break LogSource::File(path);
            }
            if record
                .as_ref()
                .is_some_and(|r| build_phase_is_terminal(&r.phase))
            {
                return;
            }

            tokio::select! {
                _ = app.log_buffer.wait_change(build_id) => {}
                _ = app.state_store.changed() => {}
                _ = tokio::time::sleep(log_stream_fallback_sleep(consecutive_db_errors)) => {}
                _ = app.shutdown_cancel.cancelled() => return,
            }
        };

        let log_path = match source {
            LogSource::Buffer => {
                drain_log_buffer(app.clone(), build_id, 0, stream_deadline, tx).await;
                return;
            }
            LogSource::File(path) => path,
        };

        let mut file = match crbs_core::util::open_read_no_follow().open(&log_path).await {
            Ok(f) => f,
            Err(_) => return,
        };

        let mut buf = bytes::BytesMut::with_capacity(4096);
        loop {
            if tokio::time::Instant::now() >= stream_deadline {
                let _ = tx
                    .send(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "log stream reached maximum lifetime",
                    )))
                    .await;
                break;
            }

            buf.resize(4096, 0);
            match tokio::io::AsyncReadExt::read(&mut file, &mut buf).await {
                Ok(0) => {
                    match probe_build_terminal(&app.state_store, build_id).await {
                        Ok(true) => break,
                        Ok(false) => consecutive_db_errors = 0,
                        Err(_) => consecutive_db_errors = consecutive_db_errors.saturating_add(1),
                    }

                    tokio::select! {
                        _ = app.state_store.changed() => {}
                        _ = tokio::time::sleep(log_stream_fallback_sleep(consecutive_db_errors)) => {}
                        _ = app.shutdown_cancel.cancelled() => break,
                    }
                }
                Ok(n) => {
                    let chunk = buf.split_to(n).freeze();
                    if tx.send(Ok(chunk)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });

    build_stream_response(rx)
}

async fn current_file_size(path: &PathBuf) -> Result<u64, ApiError> {
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("stat build.log", e))?;
    Ok(meta.len())
}

async fn stream_logs_from_file(
    log_path: PathBuf,
    build_id: i64,
    state_store: Arc<StateStore>,
    shutdown: tokio_util::sync::CancellationToken,
    start_offset: u64,
    max_lifetime: std::time::Duration,
) -> Result<Response, ApiError> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(16);

    tokio::spawn(async move {
        let path = log_path;
        let mut file = match crbs_core::util::open_read_no_follow().open(&path).await {
            Ok(f) => f,
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return;
            }
        };

        if let Err(e) =
            tokio::io::AsyncSeekExt::seek(&mut file, std::io::SeekFrom::Start(start_offset)).await
        {
            let _ = tx.send(Err(e)).await;
            return;
        }

        let mut buf = bytes::BytesMut::with_capacity(4096);
        let stream_deadline = tokio::time::Instant::now() + max_lifetime;

        let mut consecutive_db_errors: u32 = 0;

        loop {
            if tokio::time::Instant::now() >= stream_deadline {
                let _ = tx
                    .send(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "log stream reached maximum lifetime",
                    )))
                    .await;
                break;
            }

            buf.resize(4096, 0);
            match tokio::io::AsyncReadExt::read(&mut file, &mut buf).await {
                Ok(0) => {
                    match probe_build_terminal(&state_store, build_id).await {
                        Ok(true) => break,
                        Ok(false) => consecutive_db_errors = 0,
                        Err(_) => consecutive_db_errors = consecutive_db_errors.saturating_add(1),
                    }

                    tokio::select! {
                        _ = state_store.changed() => {}
                        _ = tokio::time::sleep(log_stream_fallback_sleep(consecutive_db_errors)) => {}
                        _ = shutdown.cancelled() => break,
                    }
                }
                Ok(n) => {
                    let chunk = buf.split_to(n).freeze();
                    if tx.send(Ok(chunk)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });

    build_stream_response(rx)
}

/// 从 LogBuffer 流式推送：数据到达或终态变化经逐 build 通知即时唤醒，5s 兜底间隔只兜通知遗漏。
pub(crate) async fn stream_logs_from_buffer(
    app: Arc<AppState>,
    build_id: i64,
    requested_offset: Option<u64>,
    max_lifetime: std::time::Duration,
) -> Result<Response, ApiError> {
    let start_offset = match requested_offset {
        Some(o) => {
            let requested =
                usize::try_from(o).map_err(|_| ApiError::Validation(OFFSET_EXCEEDS_MSG.into()))?;
            if requested > app.log_buffer.total_size(build_id).unwrap_or(0) {
                return Err(ApiError::Validation(OFFSET_EXCEEDS_MSG.into()));
            }
            requested
        }
        None => 0,
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(16);

    tokio::spawn(async move {
        let stream_deadline = tokio::time::Instant::now() + max_lifetime;
        drain_log_buffer(app, build_id, start_offset, stream_deadline, tx).await;
    });

    build_stream_response(rx)
}

async fn drain_log_buffer(
    app: Arc<AppState>,
    build_id: i64,
    start_offset: usize,
    stream_deadline: tokio::time::Instant,
    tx: tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
) {
    let mut offset = start_offset;

    let mut consecutive_db_errors: u32 = 0;

    loop {
        if tx.is_closed() {
            return;
        }
        if tokio::time::Instant::now() >= stream_deadline {
            let _ = tx
                .send(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "log stream reached maximum lifetime",
                )))
                .await;
            break;
        }

        let start_offset = offset;
        let (chunks, new_offset, front_offset) =
            app.log_buffer.read_since_with_offsets(build_id, offset);

        offset = offset.max(new_offset);
        let first_chunk_offset = chunks.first().map(|(o, _)| *o);
        if start_offset < front_offset
            || first_chunk_offset.is_some_and(|first| first > start_offset)
        {
            let hole_end = first_chunk_offset.unwrap_or(front_offset);
            let end = hole_end as u64;
            let reached = read_persisted_log_tail(
                &app,
                build_id,
                start_offset,
                Some(end),
                &tx,
                |chunk, _pos| Ok(chunk),
            )
            .await;
            if reached < end {
                tracing::debug!(
                    build_id = %build_id,
                    start = start_offset,
                    end = end,
                    reached = reached,
                    "hole backfill read short of range (file flush lags buffer append)"
                );
            }
            offset = hole_end;
            continue;
        }
        if chunks.is_empty() {
            match probe_build_terminal(&app.state_store, build_id).await {
                Ok(true) => {
                    read_persisted_log_tail(&app, build_id, offset, None, &tx, |chunk, _pos| {
                        Ok(chunk)
                    })
                    .await;
                    break;
                }
                Ok(false) => consecutive_db_errors = 0,
                Err(_) => consecutive_db_errors = consecutive_db_errors.saturating_add(1),
            }

            tokio::select! {
                _ = app.log_buffer.wait_change(build_id) => {}
                _ = app.state_store.changed() => {}
                _ = tokio::time::sleep(log_stream_fallback_sleep(consecutive_db_errors)) => {}
                _ = app.shutdown_cancel.cancelled() => return,
            }
            continue;
        }

        for (_chunk_start, chunk) in chunks {
            if tx.send(Ok(chunk)).await.is_err() {
                return;
            }
        }

        tokio::select! {
            _ = app.log_buffer.wait_change(build_id) => {}
            _ = app.state_store.changed() => {}
            _ = tokio::time::sleep(log_stream_fallback_sleep(consecutive_db_errors)) => {}
            _ = app.shutdown_cancel.cancelled() => break,
        }
    }
}

/// 终态补尾：构建终态且 LogBuffer 无新 chunk（通常已被终态驱逐清空）时，
/// 从落盘 build.log 按客户端当前偏移补读剩余内容，逐块经 `tx` 推送
/// （`to_message` 负责包装为调用方的消息类型）。
///
/// 字节对齐依据：report_logs 对每个 chunk 先落盘再追加进 LogBuffer（持久
/// 层先行），缓冲流 offset 即文件偏移。文件缺失、不可读或长度不超过
/// offset 时直接返回。按 4KB 分块而非整读：可覆盖整个 build.log
/// （`?offset=0` 的终态场景），避免无界读入造成瞬时大额内存分配且随多连
/// 接叠加。
///
/// `end` 为 `None` 时读到 EOF；为 `Some(e)` 时只补
/// [offset, min(e, EOF))，不越过 e——越界字节仍存活于 LogBuffer，多发会在
/// 后续轮次重复推送。`to_message` 收到 (chunk, chunk 末尾累计偏移)（SSE
/// 据此构造 Last-Event-ID，CLI 忽略）。返回实际读到的偏移（提前返回即为
/// 起始 offset），调用方与 `end` 对比判断是否读满，不足额即 cap 分歧形态，
/// debug 留痕。
pub(crate) async fn read_persisted_log_tail<E>(
    app: &Arc<AppState>,
    build_id: i64,
    offset: usize,
    end: Option<u64>,
    tx: &tokio::sync::mpsc::Sender<E>,
    to_message: impl Fn(Bytes, u64) -> E,
) -> u64 {
    const TAIL_CHUNK_BYTES: usize = 4096;

    let Ok(offset) = u64::try_from(offset) else {
        return 0;
    };
    let Some(log_path) = resolve_log_path(app, build_id).await else {
        return offset;
    };
    let Ok(mut file) = crbs_core::util::open_read_no_follow().open(&log_path).await else {
        return offset;
    };
    if !matches!(file.metadata().await, Ok(meta) if meta.len() > offset) {
        return offset;
    }
    if tokio::io::AsyncSeekExt::seek(&mut file, std::io::SeekFrom::Start(offset))
        .await
        .is_err()
    {
        return offset;
    }
    let mut buf = bytes::BytesMut::with_capacity(TAIL_CHUNK_BYTES);
    let mut pos = offset;
    loop {
        let want = match end {
            None => TAIL_CHUNK_BYTES,
            Some(end) => {
                if pos >= end {
                    return pos;
                }
                (end - pos).min(TAIL_CHUNK_BYTES as u64) as usize
            }
        };
        buf.resize(want, 0);
        match tokio::io::AsyncReadExt::read(&mut file, &mut buf).await {
            Ok(0) => return pos,
            Ok(n) => {
                let chunk = buf.split_to(n).freeze();
                pos += n as u64;
                if tx.send(to_message(chunk, pos)).await.is_err() {
                    return pos;
                }
            }
            Err(_) => return pos,
        }
    }
}

fn build_stream_response(
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
) -> Result<Response, ApiError> {
    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx));
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert("X-Log-Stream", HeaderValue::from_static("1"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
    Ok((StatusCode::OK, headers, body).into_response())
}

/// 构建终态 phase 判定（纯函数）：crbs-core 单源，server 内既有的
/// `routes::logs::build_phase_is_terminal` import 路径经此重导出保持不变。
pub(crate) use crbs_core::types::build_phase_is_terminal;

/// 检查构建是否处于终态；构建行不存在（管理员已删除）按终态处理——对流
/// 生命周期而言，行删除与终态同义（不再产出新日志）。DB 错误按非终态处
/// 理（瞬态错误不中断流）。
pub(crate) async fn is_build_terminal(state_store: &StateStore, build_id: i64) -> bool {
    probe_build_terminal(state_store, build_id)
        .await
        .unwrap_or(false)
}

async fn probe_build_terminal(
    state_store: &StateStore,
    build_id: i64,
) -> Result<bool, crbs_core::error::CrbsError> {
    match state_store.get_build(build_id).await {
        Ok(Some(r)) => Ok(build_phase_is_terminal(&r.phase)),

        Ok(None) => Ok(true),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crbs_core::config::ServerConfig;
    use tokio_stream::StreamExt;

    async fn app_with_result_root() -> (Arc<AppState>, tempfile::TempDir, std::path::PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store,
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let result_root = tmp.path().join("results");
        (app, tmp, result_root)
    }

    async fn insert_task_build(
        app: &Arc<AppState>,
        phase: &str,
        result_dir: Option<&str>,
    ) -> (i64, i64) {
        let task_id = app
            .state_store
            .insert_task(crbs_core::TaskInsert {
                product: "fedora",
                pkg_name: "pkg",
                user: "alice",
                user_id: None,
                phase,
                priority: 0,
                srpm_path: None,
                result_dir: None,
                ..Default::default()
            })
            .await
            .unwrap();
        let build_id = app
            .state_store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "pkg",
                phase,
                result_dir,
                backend: "chroot",
                user: "alice",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        (task_id, build_id)
    }

    async fn collect_body_text(body: axum::body::Body) -> String {
        let frames = collect_body_frames(body).await;
        frames.iter().map(|b| String::from_utf8_lossy(b)).collect()
    }

    async fn collect_body_frames(body: axum::body::Body) -> Vec<Bytes> {
        let mut stream = body.into_data_stream();
        let mut out = Vec::new();
        while let Ok(result) =
            tokio::time::timeout(std::time::Duration::from_secs(5), stream.next()).await
        {
            match result {
                Some(Ok(bytes)) => out.push(bytes),
                Some(Err(_)) | None => break,
            }
        }
        out
    }

    #[tokio::test]
    async fn resolve_log_path_hits_result_dir_candidate() {
        let (app, _tmp, result_root) = app_with_result_root().await;
        let (task_id, id) = insert_task_build(&app, "building", None).await;

        let arch_dir = result_root.join(task_id.to_string()).join("x86_64");
        tokio::fs::create_dir_all(&arch_dir).await.unwrap();
        tokio::fs::write(arch_dir.join("build.log"), b"log")
            .await
            .unwrap();
        app.state_store
            .update_build_info(id, Some(arch_dir.to_str().unwrap()), None, "chroot")
            .await
            .unwrap();

        let resolved = resolve_log_path(&app, id).await;
        let expected = tokio::fs::canonicalize(arch_dir.join("build.log"))
            .await
            .unwrap();
        assert_eq!(resolved, Some(expected.clone()));

        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        assert_eq!(
            resolve_log_path_for_record(&app, &record).await,
            Some(expected)
        );
    }

    #[tokio::test]
    async fn build_stream_response_sets_no_store_and_no_proxy_buffering() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let response = build_stream_response(rx).unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let headers = response.headers();
        assert_eq!(
            headers
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            headers
                .get("x-accel-buffering")
                .and_then(|v| v.to_str().ok()),
            Some("no")
        );
        drop(tx);
        let text = collect_body_text(response.into_body()).await;
        assert!(text.is_empty());
    }

    #[tokio::test]
    async fn is_build_terminal_covers_three_match_arms() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "building", None).await;

        assert!(
            !is_build_terminal(&app.state_store, id).await,
            "building row must not be terminal"
        );

        app.state_store
            .complete_build(id, "succeeded", None)
            .await
            .unwrap();
        assert!(
            is_build_terminal(&app.state_store, id).await,
            "succeeded row must be terminal"
        );

        sqlx::query("DELETE FROM builds WHERE id = ?")
            .bind(id)
            .execute(app.state_store.pool())
            .await
            .unwrap();
        assert!(
            is_build_terminal(&app.state_store, id).await,
            "missing row must be treated as terminal"
        );

        sqlx::query("ALTER TABLE builds RENAME TO builds_test_backup")
            .execute(app.state_store.pool())
            .await
            .unwrap();
        assert!(
            !is_build_terminal(&app.state_store, id).await,
            "DB error must be treated as non-terminal"
        );
        sqlx::query("ALTER TABLE builds_test_backup RENAME TO builds")
            .execute(app.state_store.pool())
            .await
            .unwrap();
    }

    #[test]
    fn log_stream_fallback_sleep_backs_off_on_consecutive_db_errors() {
        assert_eq!(log_stream_fallback_sleep(0), LOG_STREAM_FALLBACK_INTERVAL);
        assert_eq!(log_stream_fallback_sleep(1), LOG_STREAM_FALLBACK_INTERVAL);
        assert_eq!(
            log_stream_fallback_sleep(2),
            LOG_STREAM_FALLBACK_INTERVAL * 2
        );
        assert_eq!(
            log_stream_fallback_sleep(4),
            LOG_STREAM_FALLBACK_INTERVAL * 8
        );

        assert_eq!(
            log_stream_fallback_sleep(50),
            LOG_STREAM_FALLBACK_INTERVAL * 16
        );
    }

    #[tokio::test]
    async fn probe_build_terminal_exposes_db_error_for_backoff_counter() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "building", None).await;

        sqlx::query("ALTER TABLE builds RENAME TO builds_test_backup")
            .execute(app.state_store.pool())
            .await
            .unwrap();
        let probed = probe_build_terminal(&app.state_store, id).await;
        assert!(
            probed.is_err(),
            "DB error must surface as Err for the backoff counter, got: {probed:?}"
        );
        sqlx::query("ALTER TABLE builds_test_backup RENAME TO builds")
            .execute(app.state_store.pool())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn resolve_log_path_hits_engine_timestamp_dir() {
        let (app, _tmp, result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "building", None).await;

        let pkg_root = result_root.join("fedora").join("pkg");
        let build_dir = pkg_root.join(format!("20260717-120000-{}", id));

        let decoy_dir = pkg_root.join(format!("20260717-120001-{}0", id));
        tokio::fs::create_dir_all(&build_dir).await.unwrap();
        tokio::fs::create_dir_all(&decoy_dir).await.unwrap();
        tokio::fs::write(build_dir.join("build.log"), b"log")
            .await
            .unwrap();
        tokio::fs::write(decoy_dir.join("build.log"), b"decoy")
            .await
            .unwrap();

        let resolved = resolve_log_path(&app, id).await;
        let expected = tokio::fs::canonicalize(build_dir.join("build.log"))
            .await
            .unwrap();
        assert_eq!(resolved, Some(expected.clone()));

        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        assert_eq!(
            resolve_log_path_for_record(&app, &record).await,
            Some(expected)
        );
    }

    #[tokio::test]
    async fn resolve_log_path_returns_none_when_nothing_exists() {
        let (app, _tmp, result_root) = app_with_result_root().await;
        tokio::fs::create_dir_all(&result_root).await.unwrap();
        let (_task_id, id) = insert_task_build(&app, "building", None).await;
        assert_eq!(resolve_log_path(&app, id).await, None);

        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        assert_eq!(resolve_log_path_for_record(&app, &record).await, None);
    }

    #[tokio::test]
    async fn resolve_log_path_falls_back_to_artifact_dir_copy() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "failed", None).await;

        let artifact_log = app.artifact_dir().join(id.to_string()).join("build.log");
        tokio::fs::create_dir_all(artifact_log.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&artifact_log, b"durable copy")
            .await
            .unwrap();

        assert_eq!(resolve_log_path(&app, id).await, Some(artifact_log.clone()));
        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        assert_eq!(
            resolve_log_path_for_record(&app, &record).await,
            Some(artifact_log)
        );
    }

    #[tokio::test]
    async fn fetch_log_stream_buffer_delivers_chunk_via_notify_without_fallback_wait() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "building", None).await;

        app.log_buffer.register(id);

        let app_clone = app.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            app_clone
                .log_buffer
                .append(id, Bytes::from("notify-driven\n"));
        });

        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        let response = fetch_log_stream(&app, &record, None).await.unwrap();
        let mut stream = response.into_body().into_data_stream();
        let started = std::time::Instant::now();
        let mut text = String::new();
        let delivered = loop {
            match tokio::time::timeout(std::time::Duration::from_secs(2), stream.next()).await {
                Ok(Some(Ok(bytes))) => {
                    text.push_str(&String::from_utf8_lossy(&bytes));
                    if text.contains("notify-driven") {
                        break true;
                    }
                }
                Ok(Some(Err(_))) | Ok(None) => break false,
                Err(_) => break false,
            }
        };
        assert!(
            delivered,
            "chunk must arrive via notify well under the 5s fallback, got: {text:?}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[tokio::test]
    async fn fetch_log_stream_buffer_ends_when_build_row_deleted() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "building", None).await;
        app.log_buffer.append(id, Bytes::from("hello\n"));

        let app_clone = app.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            sqlx::query("DELETE FROM builds WHERE id = ?")
                .bind(id)
                .execute(app_clone.state_store.pool())
                .await
                .unwrap();
            app_clone
                .state_store
                .insert_task(crbs_core::TaskInsert {
                    product: "fedora",
                    pkg_name: "noise",
                    user: "alice",
                    ..Default::default()
                })
                .await
                .unwrap();
        });

        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        let response = fetch_log_stream(&app, &record, None).await.unwrap();
        let mut stream = response.into_body().into_data_stream();
        let started = std::time::Instant::now();
        let mut text = String::new();

        let ended = loop {
            match tokio::time::timeout(std::time::Duration::from_secs(2), stream.next()).await {
                Ok(Some(Ok(bytes))) => text.push_str(&String::from_utf8_lossy(&bytes)),
                Ok(Some(Err(_))) | Ok(None) => break true,
                Err(_) => break false,
            }
        };
        assert!(ended, "stream must end after row deletion, got: {text:?}");
        assert!(text.contains("hello"), "buffered chunk missing: {text:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[tokio::test]
    async fn fetch_log_stream_wait_for_file_ends_when_build_row_deleted() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "building", None).await;

        let app_clone = app.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            sqlx::query("DELETE FROM builds WHERE id = ?")
                .bind(id)
                .execute(app_clone.state_store.pool())
                .await
                .unwrap();
            app_clone
                .state_store
                .insert_task(crbs_core::TaskInsert {
                    product: "fedora",
                    pkg_name: "noise",
                    user: "alice",
                    ..Default::default()
                })
                .await
                .unwrap();
        });

        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        let response = fetch_log_stream(&app, &record, None).await.unwrap();
        let mut stream = response.into_body().into_data_stream();
        let started = std::time::Instant::now();
        let mut text = String::new();

        let ended = loop {
            match tokio::time::timeout(std::time::Duration::from_secs(2), stream.next()).await {
                Ok(Some(Ok(bytes))) => text.push_str(&String::from_utf8_lossy(&bytes)),
                Ok(Some(Err(_))) | Ok(None) => break true,
                Err(_) => break false,
            }
        };
        assert!(ended, "stream must end after row deletion, got: {text:?}");
        assert!(
            text.is_empty(),
            "waiting stream must deliver no bytes, got: {text:?}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[tokio::test]
    async fn fetch_log_stream_follow_waits_for_file_to_appear() {
        let (app, _tmp, result_root) = app_with_result_root().await;
        let (task_id, id) = insert_task_build(&app, "building", None).await;

        let arch_dir = result_root.join(task_id.to_string()).join("x86_64");
        tokio::fs::create_dir_all(&arch_dir).await.unwrap();
        let log_file = arch_dir.join("build.log");

        let app_clone = app.clone();
        let writer_dir = arch_dir.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            tokio::fs::write(&log_file, b"").await.unwrap();
            app_clone
                .state_store
                .update_build_info(id, Some(writer_dir.to_str().unwrap()), None, "chroot")
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            tokio::fs::write(&log_file, b"follow-data\n").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            app_clone
                .state_store
                .complete_build(id, "succeeded", None)
                .await
                .unwrap();
        });

        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        let response = fetch_log_stream(&app, &record, None).await.unwrap();
        let text = collect_body_text(response.into_body()).await;
        assert!(
            text.contains("follow-data"),
            "expected streamed log, got: {}",
            text
        );
    }

    #[tokio::test]
    async fn fetch_log_stream_snapshot_returns_404_when_file_missing() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_a, building_id) = insert_task_build(&app, "building", None).await;
        let building = app
            .state_store
            .get_build(building_id)
            .await
            .unwrap()
            .unwrap();
        let result = fetch_log_stream(&app, &building, Some(0)).await;
        assert!(matches!(result, Err(ApiError::NotFound(_))));

        let (_task_b, terminal_id) = insert_task_build(&app, "failed", None).await;
        let terminal = app
            .state_store
            .get_build(terminal_id)
            .await
            .unwrap()
            .unwrap();
        let result = fetch_log_stream(&app, &terminal, Some(0)).await;
        assert!(matches!(result, Err(ApiError::NotFound(_))));
    }

    #[tokio::test]
    async fn fetch_log_stream_follow_returns_404_for_terminal_without_file() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "failed", None).await;
        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        let result = fetch_log_stream(&app, &record, None).await;
        assert!(matches!(result, Err(ApiError::NotFound(_))));
    }

    #[tokio::test]
    async fn fetch_log_stream_follow_switches_to_buffer_when_registered() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "building", None).await;

        let app_clone = app.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            app_clone.log_buffer.register(id);
            app_clone
                .log_buffer
                .append(id, Bytes::from("buffer-data\n"));
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            app_clone
                .state_store
                .complete_build(id, "succeeded", None)
                .await
                .unwrap();
        });

        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        let response = fetch_log_stream(&app, &record, None).await.unwrap();
        let text = collect_body_text(response.into_body()).await;
        assert!(
            text.contains("buffer-data"),
            "expected streamed buffer content, got: {}",
            text
        );
    }

    #[tokio::test]
    async fn fetch_log_stream_buffer_tail_reads_persisted_log_after_evict() {
        let (app, _tmp, result_root) = app_with_result_root().await;
        let (task_id, id) = insert_task_build(&app, "building", None).await;

        let arch_dir = result_root.join(task_id.to_string()).join("x86_64");
        tokio::fs::create_dir_all(&arch_dir).await.unwrap();
        let log_file = arch_dir.join("build.log");

        tokio::fs::write(&log_file, "early-line\n").await.unwrap();
        app.state_store
            .update_build_info(id, Some(arch_dir.to_str().unwrap()), None, "chroot")
            .await
            .unwrap();
        app.log_buffer.register(id);
        app.log_buffer.append(id, Bytes::from("early-line\n"));

        let app_clone = app.clone();
        let writer_log = log_file.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            tokio::fs::write(&writer_log, b"early-line\ntail-line\n")
                .await
                .unwrap();
            app_clone
                .state_store
                .complete_build(id, "succeeded", None)
                .await
                .unwrap();
            app_clone.log_buffer.evict(id);
        });

        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        let response = fetch_log_stream(&app, &record, None).await.unwrap();
        let text = collect_body_text(response.into_body()).await;
        assert!(
            text.contains("early-line"),
            "expected buffered log, got: {}",
            text
        );
        assert!(
            text.contains("tail-line"),
            "expected persisted tail after evict, got: {}",
            text
        );
    }

    #[tokio::test]
    async fn fetch_log_stream_backfills_fifo_hole_from_persisted_file() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "building", None).await;

        let artifact_log = app.artifact_dir().join(id.to_string()).join("build.log");
        tokio::fs::create_dir_all(app.artifact_dir().join(id.to_string()))
            .await
            .unwrap();
        tokio::fs::write(&artifact_log, b"old-data ").await.unwrap();
        app.log_buffer.register(id);
        app.log_buffer.append(id, Bytes::from("old-data "));

        for _ in 0..11 {
            assert!(app.log_buffer.append(
                id,
                Bytes::from(vec![b'x'; crate::server::log_buffer::MAX_LOG_CHUNK_BYTES])
            ));
        }

        let app_clone = app.clone();
        let writer_log = artifact_log.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            assert!(app_clone.log_buffer.append(id, Bytes::from("tail")));
            let mut f = tokio::fs::OpenOptions::new()
                .append(true)
                .open(&writer_log)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut f, b"tail")
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            app_clone
                .state_store
                .complete_build(id, "succeeded", None)
                .await
                .unwrap();
        });

        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        let response = fetch_log_stream(&app, &record, Some(0)).await.unwrap();
        let text = collect_body_text(response.into_body()).await;
        assert!(
            text.contains("old-data"),
            "evicted range must be backfilled from the persisted file: {text}"
        );
        assert!(text.contains("tail"), "live tail missing: {text}");
    }

    #[tokio::test]
    async fn fetch_log_stream_backfills_mid_rejection_hole_from_persisted_file() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "building", None).await;

        let artifact_dir = app.artifact_dir().join(id.to_string());
        let artifact_log = artifact_dir.join("build.log");
        tokio::fs::create_dir_all(&artifact_dir).await.unwrap();
        tokio::fs::write(&artifact_log, b"old-data ").await.unwrap();
        app.log_buffer.register(id);
        app.log_buffer.append(id, Bytes::from("old-data "));

        let app_clone = app.clone();
        let writer_log = artifact_log.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;

            for _ in 0..10 {
                assert!(app_clone.log_buffer.append(
                    id + 1,
                    Bytes::from(vec![b'x'; crate::server::log_buffer::MAX_LOG_CHUNK_BYTES])
                ));
            }
            assert!(app_clone.log_buffer.append(
                id + 2,
                Bytes::from(vec![b'y'; crate::server::log_buffer::MAX_LOG_CHUNK_BYTES])
            ));

            let mut f = tokio::fs::OpenOptions::new()
                .append(true)
                .open(&writer_log)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(
                &mut f,
                &[b'z'; crate::server::log_buffer::MAX_LOG_CHUNK_BYTES],
            )
            .await
            .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut f, b"tail")
                .await
                .unwrap();

            assert!(!app_clone.log_buffer.append(
                id,
                Bytes::from(vec![b'z'; crate::server::log_buffer::MAX_LOG_CHUNK_BYTES])
            ));
            app_clone.log_buffer.evict(id + 1);
            app_clone.log_buffer.evict(id + 2);
            assert!(app_clone.log_buffer.append(id, Bytes::from("tail")));
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            app_clone
                .state_store
                .complete_build(id, "succeeded", None)
                .await
                .unwrap();
        });

        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        let response = fetch_log_stream(&app, &record, Some(0)).await.unwrap();
        let text = collect_body_text(response.into_body()).await;
        assert!(text.contains("old-data"), "pre-hole chunk missing: {text}");
        assert!(
            text.contains("zzzz"),
            "mid-rejection hole must be backfilled from the persisted file: {text}"
        );
        assert!(
            text.contains("tail"),
            "post-hole live chunk missing: {text}"
        );

        let old_pos = text.find("old-data").unwrap();
        let z_pos = text.find("zzzz").unwrap();
        let tail_pos = text.rfind("tail").unwrap();
        assert!(
            old_pos < z_pos && z_pos < tail_pos,
            "backfilled hole must sit between pre-hole chunk and live tail: {old_pos} < {z_pos} < {tail_pos}"
        );
    }

    #[tokio::test]
    async fn get_logs_checks_product_visibility() {
        use tower::ServiceExt;

        use crate::server::{create_test_app_with_auth, seed_user_token_for_test};

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let app_state = Arc::new(AppState::for_test(
            store.clone(),
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let viewer_tok = seed_user_token_for_test(&store, "eve", "viewer")
            .await
            .unwrap();
        let app = create_test_app_with_auth(app_state);

        let owner_id = store.create_user("owner", "builder").await.unwrap();
        for (name, owner_id, visibility) in [
            ("secret", Some(owner_id), crbs_core::VISIBILITY_PRIVATE),
            ("openfed", None, crbs_core::VISIBILITY_PUBLIC),
        ] {
            store
                .create_product(crbs_core::CreateProductInput {
                    name,
                    display_name: None,
                    owner_id,
                    parent_id: None,
                    visibility,
                    config: &crbs_core::config::ProductConfig::default(),
                    changed_by_user_id: None,
                    reason: Some("test seed"),
                })
                .await
                .unwrap();
        }
        let insert_build = |product: &'static str| {
            let store = store.clone();
            async move {
                let task_id = crate::test_support::seed_task(&store, product, "pkg").await;
                store
                    .insert_build(crbs_core::BuildInsert {
                        product,
                        pkg_name: "pkg",
                        phase: "building",
                        backend: "chroot",
                        user: "eve",
                        user_id: None,
                        task_id: Some(task_id),
                        ..Default::default()
                    })
                    .await
                    .unwrap()
            }
        };
        let secret_build = insert_build("secret").await;
        let public_build = insert_build("openfed").await;

        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/builds/{}/logs", secret_build))
                    .header("Authorization", format!("Bearer {}", viewer_tok))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);

        let result_root = tmp.path().join("results");
        let dir = result_root.join(public_build.to_string());
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("build.log"), b"pub\n")
            .await
            .unwrap();
        store
            .update_build_info(public_build, Some(dir.to_str().unwrap()), None, "chroot")
            .await
            .unwrap();
        store
            .complete_build(public_build, "succeeded", None)
            .await
            .unwrap();
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/builds/{}/logs", public_build))
                    .header("Authorization", format!("Bearer {}", viewer_tok))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn get_logs_allows_other_builder_on_orphan_product() {
        use tower::ServiceExt;

        use crate::server::{create_test_app_with_auth, seed_user_token_for_test};

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let app_state = Arc::new(AppState::for_test(
            store.clone(),
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let alice_tok = seed_user_token_for_test(&store, "alice", "builder")
            .await
            .unwrap();
        let bob_tok = seed_user_token_for_test(&store, "bob", "builder")
            .await
            .unwrap();
        let app = create_test_app_with_auth(app_state);

        let task_id = crate::test_support::seed_task(&store, "orphan-prod", "pkg").await;
        let build_id = store
            .insert_build(crbs_core::BuildInsert {
                product: "orphan-prod",
                pkg_name: "pkg",
                phase: "building",
                backend: "chroot",
                user: "alice",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        let dir = tmp.path().join("results").join(build_id.to_string());
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("build.log"), b"alice-log\n")
            .await
            .unwrap();
        store
            .update_build_info(build_id, Some(dir.to_str().unwrap()), None, "chroot")
            .await
            .unwrap();
        store
            .complete_build(build_id, "succeeded", None)
            .await
            .unwrap();

        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/builds/{}/logs", build_id))
                    .header("Authorization", format!("Bearer {}", bob_tok))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/builds/{}/logs", build_id))
                    .header("Authorization", format!("Bearer {}", alice_tok))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn fetch_log_stream_buffer_honors_requested_offset() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "succeeded", None).await;

        app.log_buffer.register(id);
        app.log_buffer.append(id, Bytes::from("hello "));
        app.log_buffer.append(id, Bytes::from("world"));

        let record = app.state_store.get_build(id).await.unwrap().unwrap();

        let response = fetch_log_stream(&app, &record, Some(6)).await.unwrap();
        let text = collect_body_text(response.into_body()).await;
        assert_eq!(text, "world");

        let response = fetch_log_stream(&app, &record, None).await.unwrap();
        let text = collect_body_text(response.into_body()).await;
        assert_eq!(text, "hello world");
    }

    #[tokio::test]
    async fn fetch_log_stream_buffer_rejects_offset_beyond_size() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "building", None).await;

        app.log_buffer.register(id);
        app.log_buffer.append(id, Bytes::from("hello world"));

        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        let err = fetch_log_stream(&app, &record, Some(12)).await.unwrap_err();
        assert!(
            matches!(err, ApiError::Validation(ref msg) if msg == "offset exceeds current log size"),
            "unexpected error: {:?}",
            err
        );
    }

    #[tokio::test]
    async fn fetch_log_stream_file_offset_out_of_range_message_hides_size() {
        let (app, _tmp, result_root) = app_with_result_root().await;
        let (task_id, id) = insert_task_build(&app, "succeeded", None).await;

        let arch_dir = result_root.join(task_id.to_string()).join("x86_64");
        tokio::fs::create_dir_all(&arch_dir).await.unwrap();
        tokio::fs::write(arch_dir.join("build.log"), b"abc")
            .await
            .unwrap();
        app.state_store
            .update_build_info(id, Some(arch_dir.to_str().unwrap()), None, "chroot")
            .await
            .unwrap();

        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        let err = fetch_log_stream(&app, &record, Some(10)).await.unwrap_err();
        assert!(
            matches!(err, ApiError::Validation(ref msg) if msg == "offset exceeds current log size"),
            "unexpected error: {:?}",
            err
        );
    }

    #[tokio::test]
    async fn fetch_log_stream_buffer_tail_chunks_large_persisted_tail() {
        let (app, _tmp, result_root) = app_with_result_root().await;
        let (task_id, id) = insert_task_build(&app, "building", None).await;

        let arch_dir = result_root.join(task_id.to_string()).join("x86_64");
        tokio::fs::create_dir_all(&arch_dir).await.unwrap();
        let log_file = arch_dir.join("build.log");

        let early = "early-line\n";

        let tail = format!("tail-start\n{}tail-end\n", "x".repeat(10 * 1024));
        let expected = format!("{}{}", early, tail);
        tokio::fs::write(&log_file, early).await.unwrap();
        app.state_store
            .update_build_info(id, Some(arch_dir.to_str().unwrap()), None, "chroot")
            .await
            .unwrap();
        app.log_buffer.register(id);
        app.log_buffer.append(id, Bytes::from(early));

        let app_clone = app.clone();
        let writer_log = log_file.clone();
        let writer_full = expected.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            tokio::fs::write(&writer_log, writer_full.as_bytes())
                .await
                .unwrap();
            app_clone
                .state_store
                .complete_build(id, "succeeded", None)
                .await
                .unwrap();
            app_clone.log_buffer.evict(id);
        });

        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        let response = fetch_log_stream(&app, &record, None).await.unwrap();
        let frames = collect_body_frames(response.into_body()).await;
        let text: String = frames.iter().map(|b| String::from_utf8_lossy(b)).collect();
        assert_eq!(text, expected, "tail content must be complete");

        assert!(
            frames.len() >= 3,
            "large tail must arrive in multiple chunks, got {} frames",
            frames.len()
        );
    }
}
