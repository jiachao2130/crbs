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
    /// 从指定字节偏移开始推送；默认从当前文件末尾开始（tail -f 语义）。
    pub offset: Option<u64>,
    // 历史 `?which=` 参数已随 root.log 移除；axum Query 静默忽略未知参数，
    // 旧客户端带 which=root 仍按 build.log 处理。
}

/// 单条日志流最大允许存活时间，防止客户端断开后或超大 offset 导致连接长期挂起。
const MAX_LOG_STREAM_LIFETIME_SECS: u64 = 3600;

/// CLI 日志流兜底间隔（5s）：数据到达/终态翻转走 LogBuffer 与 StateStore
/// 通知即时唤醒，本间隔只兜 Notify 无 permit 语义的遗漏（错过退化为一个间隔的延迟）。
const LOG_STREAM_FALLBACK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// 兜底 sleep 随连续 DB 错误按乘数（1→2→4→8→16 封顶）放大，摊薄故障期注定
/// 失败的池排队查询；健康与首错恒基准——只放大兜底臂，DB 恢复后首个状态写入即唤醒。
fn log_stream_fallback_sleep(consecutive_db_errors: u32) -> std::time::Duration {
    LOG_STREAM_FALLBACK_INTERVAL * sse_db_retry_backoff_multiplier(consecutive_db_errors)
}

/// `?offset` 越界错误文案：固定文案，不回传服务端文件/缓冲大小数值（防泄露）。
const OFFSET_EXCEEDS_MSG: &str = "offset exceeds current log size";

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

    // 产品级可见性（与 get_task 同口径）：private 产品对无权限用户 403；
    // 匿名（公开访问）走 public/孤儿产品语义。
    ensure_product_visible_for_record(&app, &record.product, auth.as_ref().map(|e| &e.0)).await?;

    fetch_log_stream(&app, &record, q.offset).await
}

/// 获取构建的日志流，优先从 LogBuffer 读取，否则回退到本地文件。
///
/// 该函数对 API 和 Web UI 共享：调用方负责获取 `BuildRecord` 和权限检查。
async fn fetch_log_stream(
    app: &Arc<AppState>,
    record: &crbs_core::BuildRecord,
    offset: Option<u64>,
) -> Result<Response, ApiError> {
    let id = record.id;

    // 优先检查 LogBuffer（分布式构建进行中）；仅 build.log 有缓冲流。
    if app.log_buffer.has(id) {
        return stream_logs_from_buffer(
            app.clone(),
            id,
            offset,
            std::time::Duration::from_secs(MAX_LOG_STREAM_LIFETIME_SECS),
        )
        .await;
    }

    // 回退本地文件（本地构建 / 已完成分布式构建）；record 直传核心版本，
    // 省一次重复 get_build。
    let log_path = resolve_log_path_for_record(app, record).await;

    let Some(log_path) = log_path else {
        // 日志文件尚未生成：快照（显式 offset）快速失败；follow 在未终态时转入流内等待。
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

/// 解析 build.log 本地路径：get_build 后委托 [`resolve_log_path_for_record`]；
/// 已持有 record 的调用方（SSE 等）直传该版本，省重复 get_build。
pub(crate) async fn resolve_log_path(app: &Arc<AppState>, build_id: i64) -> Option<PathBuf> {
    let record = app.state_store.get_build(build_id).await.ok()??;
    resolve_log_path_for_record(app, &record).await
}

/// [`resolve_log_path`] 的核心：三候选（前两个校验不越出 result_root）：
/// 1. `record.result_dir/build.log`（引擎 `set_info` / worker 终态上传落点）；
/// 2. 引擎目录 `{result_root}/{product}/{pkg_name}/{timestamp}-{build_id}/
///    build.log`：`-{build_id}` 后缀精确匹配，覆盖 result_dir 未写入的窗口；
/// 3. `{artifact_dir}/{build_id}/build.log`：report_logs 双写 durable 副本，
///    双上传失败构建的日志唯一来源（miss 则滞留至强驱逐后 404；i64 join 无路径遍历面）。
///
/// 返回 None 由调用方决定等待或 404；`try_exists` 与 open 间无原子性，并发
/// 删除/轮转可致 ENOENT——调用方按只读降级（等待重试 / 快照 404 / 收尾静默），
/// 不得视为持久故障。
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

    // 候选 3：report_logs 双写的 durable 副本，见函数 doc。
    // artifact_dir 来自 server 配置（AppState::artifact_dir）。
    let artifact_log = app
        .artifact_dir()
        .join(build_id.to_string())
        .join("build.log");
    if crbs_core::util::is_regular_file_no_symlink(&artifact_log).await {
        return Some(artifact_log);
    }

    None
}

/// 在 `{result_root}/{product}/{pkg_name}/` 下查找 `{YYYYMMDD-HHMMSS}-{build_id}/
/// {file_name}`：`-{build_id}` 后缀精确匹配本构建（build_id 纯数字居末段，
/// 不误拾同前缀目录）。
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

/// follow 模式等待流：日志文件与 LogBuffer 均未出现时等待，任一来源出现后
/// 切换到对应推送循环，直到构建终态或流达最大存活时间；两来源都从起始位置
/// 推送（等待期未发数据，来源既有内容全是新数据）。
async fn stream_logs_when_file_appears(
    app: Arc<AppState>,
    build_id: i64,
) -> Result<Response, ApiError> {
    enum LogSource {
        /// Worker 实时日志缓冲已注册。
        Buffer,
        /// 本地日志文件已出现。
        File(PathBuf),
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(16);

    tokio::spawn(async move {
        let stream_deadline = tokio::time::Instant::now()
            + std::time::Duration::from_secs(MAX_LOG_STREAM_LIFETIME_SECS);

        // get_build 连续错误计数——Ok 重置、Err 递增，放大兜底 sleep。
        let mut consecutive_db_errors: u32 = 0;

        // 等任一来源出现；终态仍无来源则结束流。buffer 检查先于终态检查（终态时 buffer 可能还有未读数据）。
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
            // 一次 get_build 同时喂路径解析与终态判定：行在→解析；行已删→
            // 断流（同 is_build_terminal）；DB 错误→继续等（瞬态）。
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
            // buffer/终态/result_dir 变更走通知唤醒；5s 只做兜底（见
            // LOG_STREAM_FALLBACK_INTERVAL），fs 探测留在兜底支路。停机即 return。
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
                    // 终态翻转走 StateStore.changed() 即时唤醒；5s 兜底（DB
                    // 错误期按乘数放大）。停机即 break（drop tx 关闭流）。
                    tokio::select! {
                        _ = app.state_store.changed() => {}
                        _ = tokio::time::sleep(log_stream_fallback_sleep(consecutive_db_errors)) => {}
                        _ = app.shutdown_cancel.cancelled() => break,
                    }
                }
                Ok(n) => {
                    let chunk = buf.split_to(n).freeze();
                    if tx.send(Ok(chunk)).await.is_err() {
                        break; // 客户端已断开
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

/// 获取文件当前大小，作为默认流式起始偏移。
async fn current_file_size(path: &PathBuf) -> Result<u64, ApiError> {
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("stat build.log", e))?;
    Ok(meta.len())
}

/// 返回 chunked stream：推送本地 build.log 自 `start_offset` 起的新增内容；
/// 停机时跳出循环 drop tx 关闭流，不阻塞 HTTP 优雅退出。
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
        // 终态探针连续错误计数——Ok 重置、Err 递增，放大兜底 sleep。
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
                    // 终态翻转走 StateStore.changed() 即时唤醒；5s 兜底——本地
                    // 构建文件增长无 DB 通知源，新数据只能靠兜底间隔覆盖；DB
                    // 错误期按乘数放大。停机即 break（drop tx 关闭流）。
                    tokio::select! {
                        _ = state_store.changed() => {}
                        _ = tokio::time::sleep(log_stream_fallback_sleep(consecutive_db_errors)) => {}
                        _ = shutdown.cancelled() => break,
                    }
                }
                Ok(n) => {
                    let chunk = buf.split_to(n).freeze();
                    if tx.send(Ok(chunk)).await.is_err() {
                        break; // 客户端已断开
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

/// 返回 chunked stream：从 LogBuffer 推送实时日志（[`drain_log_buffer`]，
/// 不清空缓冲、多读者并发）。`requested_offset`：`Some` 从 N 起流（断线
/// 续传），`None` 从 0 重放；N 超过 `total_size`（含已 FIFO 淘汰部分）与
/// 文件路径同语义 400，不让客户端静默等待永不到达的偏移。
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

/// LogBuffer 推送循环：从 `start_offset` 起推新 chunk 入 tx，直到构建终态、
/// 客户端断开或 `stream_deadline`；buffer 直挂与等待流切换两入口共用。
async fn drain_log_buffer(
    app: Arc<AppState>,
    build_id: i64,
    start_offset: usize,
    stream_deadline: tokio::time::Instant,
    tx: tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
) {
    let mut offset = start_offset;
    // 终态探针连续错误计数——Ok 重置、Err 递增，放大两处兜底 sleep。
    let mut consecutive_db_errors: u32 = 0;

    loop {
        // 断连响应性：5s 兜底间隔下须循环顶显式检查 tx.is_closed()，否则
        // 断开的客户端要挂满一个兜底间隔才被 send 失败发现。
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

        // read_since_with_offsets 检测两种洞：FIFO 淘汰洞（start < front）、
        // 全局上限拒收的中途洞（拒收推进 next_offset 但不留 chunk，start ≥
        // front 不触发前一条件，按首个存活 chunk 偏移 > start 识别）。洞区间
        // [start, 洞尾) 均有落盘副本（被拒/被淘汰 chunk 照常落盘），从文件
        // 补读后对齐洞尾、丢弃本轮 chunks（continue 下轮从洞尾重读，防双推）。
        let start_offset = offset;
        let (chunks, new_offset, front_offset) =
            app.log_buffer.read_since_with_offsets(build_id, offset);
        // 行/条目不存在（prune / 墓碑清扫）时返回 new_offset=0，直接回写会
        // 回拨 offset 重复推送——用 max 保持单调。
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
                // 洞补读不足额：仅剩 512MB cap 分歧形态（拒收仍落盘、缓冲
                // 继续前进，见 report_logs over_cap）——[reached, end) 本次丢失
                // （内存副本已淘汰/拒收，文件侧从未收过）。debug 留痕不噪音化。
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
                    // 驱逐竞争窗口补尾：末次间隔内落盘的行已被终态驱逐清出缓冲，按当前 offset 从落盘补读再结束。
                    read_persisted_log_tail(&app, build_id, offset, None, &tx, |chunk, _pos| {
                        Ok(chunk)
                    })
                    .await;
                    break;
                }
                Ok(false) => consecutive_db_errors = 0,
                Err(_) => consecutive_db_errors = consecutive_db_errors.saturating_add(1),
            }
            // 四路等待：通知为主，兜底复查 Notify 遗漏（DB 错误期按乘数放大）；停机即收尾。
            tokio::select! {
                _ = app.log_buffer.wait_change(build_id) => {}
                _ = app.state_store.changed() => {}
                _ = tokio::time::sleep(log_stream_fallback_sleep(consecutive_db_errors)) => {}
                _ = app.shutdown_cancel.cancelled() => return,
            }
            continue;
        }

        // offset 已经 max 推进，此处只推数据（CLI 明文流无 per-chunk 偏移）。
        for (_chunk_start, chunk) in chunks {
            if tx.send(Ok(chunk)).await.is_err() {
                return; // 客户端已断开
            }
        }

        // 同上四路等待。计数器只在空轮探针时更新：数据仍在到达时兜底 sleep
        // 沿用最近一次探针的乘数。停机即 break（drop tx 关闭流）。
        tokio::select! {
            _ = app.log_buffer.wait_change(build_id) => {}
            _ = app.state_store.changed() => {}
            _ = tokio::time::sleep(log_stream_fallback_sleep(consecutive_db_errors)) => {}
            _ = app.shutdown_cancel.cancelled() => break,
        }
    }
}

/// 终态补尾：build 终态且 LogBuffer 无新 chunk（通常已被终态驱逐清空）时，
/// 从落盘 build.log 自客户端当前偏移补读剩余内容，逐块经 `tx` 推送（`to_message`
/// 包装为调用方消息类型）。
///
/// 字节对齐依据：report_logs 对每 chunk 先落盘再 append 进 LogBuffer（durable
/// 先行），缓冲流 offset 即文件偏移。文件缺失/不可读/长度不超过 offset 直接
/// 返回。4KB 分块而非 read_to_end：可覆盖整个 build.log（`?offset=0` 终态），
/// 无界读入瞬时 GB 级分配且多连接叠加。
///
/// `end`：`None` 读到 EOF；`Some(e)` 只补 [offset, min(e, EOF))，不越过 e——
/// 越界字节仍存活于 LogBuffer，多发会在后续轮次重发造成流重复。`to_message`
/// 收到 (chunk, chunk 末尾累计偏移)（SSE 构造 Last-Event-ID，CLI 忽略）。
/// 返回实际读到的偏移（提前返回 = 起始 offset），调用方对比 `end` 判断是否
/// 读满，不足额即 cap 分歧形态，debug 留痕。
pub(crate) async fn read_persisted_log_tail<E>(
    app: &Arc<AppState>,
    build_id: i64,
    offset: usize,
    end: Option<u64>,
    tx: &tokio::sync::mpsc::Sender<E>,
    to_message: impl Fn(Bytes, u64) -> E,
) -> u64 {
    /// 补尾分块大小：与文件推送循环的读取块一致。
    const TAIL_CHUNK_BYTES: usize = 4096;

    // 64 位平台 try_from 不可能失败；失败记 0（= 一个字节未读到）。
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
        // Some(end) 按剩余区间截短读取块、到位即收；None 读到 EOF。
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
                    return pos; // 客户端已断开
                }
            }
            Err(_) => return pos,
        }
    }
}

/// 构造流式响应（共用 headers）：no-store + x-accel-buffering: no，禁缓存留存与反代缓冲（攒 chunk 会把 tail -f 变延迟批放）。
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

/// 构建终态 phase 判定（纯函数）：crbs-core 单源，server 内既有
/// `routes::logs::build_phase_is_terminal` import 路径经此 re-export 不变。
pub(crate) use crbs_core::types::build_phase_is_terminal;

/// 检查构建是否终态；行不存在（管理员删除）按已终态——对日志流生命周期
/// 判定而言行删除与终态同义（不再产出新日志）。DB 错误按非终态（瞬态不断流）。
pub(crate) async fn is_build_terminal(state_store: &StateStore, build_id: i64) -> bool {
    probe_build_terminal(state_store, build_id)
        .await
        .unwrap_or(false)
}

/// [`is_build_terminal`] 的 Err 可见变体：DB 错误以 `Err` 透传（喂连续错误
/// 计数驱动 [`log_stream_fallback_sleep`] 退避），其余两臂同上。
async fn probe_build_terminal(
    state_store: &StateStore,
    build_id: i64,
) -> Result<bool, crbs_core::error::CrbsError> {
    match state_store.get_build(build_id).await {
        Ok(Some(r)) => Ok(build_phase_is_terminal(&r.phase)),
        // 行已删：按已终态处理（见 is_build_terminal 注释）。
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

    /// 构造 AppState 并保持结果根目录存活；result_root 为 `{crbs_root}/results`。
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

    /// 插入一个 task 及其指定状态的 x86_64 子构建记录。
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

    /// 逐帧收集响应体（保留分块边界，供"分块送达"类断言使用）。
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

    /// 响应头契约：no-store + x-accel-buffering: no；发送端 drop 后流自然结束。
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

    /// is_build_terminal 三 match 臂直测：building 继续等；终态与行已删同
    /// 断流；DB Err 按非终态（挪表造真 Err，现场恢复）。
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

    /// 兜底 sleep 接线回归：健康与首错恒基准 5s，连续错误按乘数放大（乘数曲线在 sse.rs）。
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
        // 封顶 ×16：再多的连续错误也不放大（5s × 16 = 80s）。
        assert_eq!(
            log_stream_fallback_sleep(50),
            LOG_STREAM_FALLBACK_INTERVAL * 16
        );
    }

    /// probe_build_terminal 的 Err 臂：退避计数需要 Err 可见性；挪表造真 Err（现场恢复），Ok 臂见上测。
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
        // 干扰目录：不同 build_id 的后缀不应被误拾。
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

    /// 候选 3：双上传失败构建的 durable 副本在 `{artifact_dir}/{build_id}/
    /// build.log`——resolve 必须命中，不再 404。
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

    /// 机制门：buffer 流通知驱动——挂接后追加的 chunk 经 wait_change 即时推送（2s 预算内），只等 5s 兜底即回归。
    #[tokio::test]
    async fn fetch_log_stream_buffer_delivers_chunk_via_notify_without_fallback_wait() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "building", None).await;

        // 只注册空缓冲：首轮 read_since 为空进入等待，追加 chunk 若错过通知只能等 5s 兜底。
        app.log_buffer.register(id);

        let app_clone = app.clone();
        tokio::spawn(async move {
            // 等流挂接并挂上等待（notify_waiters 只唤醒已挂起的等待方）。
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
                Err(_) => break false, // 2s 超时 = 只剩 5s 兜底（通知机制回归）
            }
        };
        assert!(
            delivered,
            "chunk must arrive via notify well under the 5s fallback, got: {text:?}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    /// Buffer 态行删除收尾：空轮询终态检查经 is_build_terminal（行缺失视为终态），
    /// 删行后下一轮唤醒即补尾结束流；裸 SQL 不广播，靠 insert_task 通知驱动。
    #[tokio::test]
    async fn fetch_log_stream_buffer_ends_when_build_row_deleted() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "building", None).await;
        app.log_buffer.append(id, Bytes::from("hello\n"));

        let app_clone = app.clone();
        tokio::spawn(async move {
            // 等流挂接并推出缓冲内容（notify_waiters 只唤醒已挂起的等待方）。
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
        // 2s 预算：通知驱动下 ~300ms 即收尾；超时 = 行删除仍在空转（回归）。
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

    /// 行删除收尾（Waiting 态）：`Ok(None) => return` 分支——文件与 buffer
    /// 均未出现期间行被删，下一轮唤醒即静默空 EOF。夹具：building +
    /// result_dir NULL + 三候选不落盘 + buffer 未注册；靠 insert_task 通知驱动。
    #[tokio::test]
    async fn fetch_log_stream_wait_for_file_ends_when_build_row_deleted() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "building", None).await;

        let app_clone = app.clone();
        tokio::spawn(async move {
            // 等流挂接并进入等待循环（select 已挂起后才注入行删除）。
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
        // 2s 预算：通知驱动下 ~300ms 即收尾；超时 = 行删除仍在空转（回归）。
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

    /// follow 模式（无 offset）：build.log 尚未生成时流内等待，文件出现后开始推送。
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

    /// 快照模式（显式 offset）：文件不存在时保持快速 404，不进入等待。
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

    /// follow 模式：构建已终态且无日志文件时仍返回 404（不挂起连接）。
    #[tokio::test]
    async fn fetch_log_stream_follow_returns_404_for_terminal_without_file() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "failed", None).await;
        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        let result = fetch_log_stream(&app, &record, None).await;
        assert!(matches!(result, Err(ApiError::NotFound(_))));
    }

    /// follow 等待中 buffer 注册则切换并从 0 推送已有 chunk（等待期未发数据，全是新数据）。
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

    /// 驱逐竞争窗口回归：buffer 流挂接后翻终态并驱逐 LogBuffer，末次轮询
    /// 间隔内落盘的行（缓冲已清空、墓碑拦截 append）仍按当前 offset 从落盘补读，不截尾。
    #[tokio::test]
    async fn fetch_log_stream_buffer_tail_reads_persisted_log_after_evict() {
        let (app, _tmp, result_root) = app_with_result_root().await;
        let (task_id, id) = insert_task_build(&app, "building", None).await;

        let arch_dir = result_root.join(task_id.to_string()).join("x86_64");
        tokio::fs::create_dir_all(&arch_dir).await.unwrap();
        let log_file = arch_dir.join("build.log");
        // report_logs 双写语义：同一 chunk 同时进缓冲和落盘文件。
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
            // 等首次轮询吐出 early-line 后制造竞争窗口：新行只落盘（缓冲被
            // 终态驱逐清空），翻终态并驱逐。
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

    /// FIFO 空洞补读：`?offset=0` 连接时 "old-data " 已被 FIFO 淘汰（11 条
    /// 满 1MB chunk 触发，front 前跳），缺口 [0, front) 从 `artifact_dir/{id}/
    /// build.log`（双写副本，同偏移空间）补读，存活内容与增量续流。
    #[tokio::test]
    async fn fetch_log_stream_backfills_fifo_hole_from_persisted_file() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "building", None).await;

        // 模拟 worker report_logs 双写：缓冲 + artifact_dir 落盘同偏移。
        let artifact_log = app.artifact_dir().join(id.to_string()).join("build.log");
        tokio::fs::create_dir_all(app.artifact_dir().join(id.to_string()))
            .await
            .unwrap();
        tokio::fs::write(&artifact_log, b"old-data ").await.unwrap();
        app.log_buffer.register(id);
        app.log_buffer.append(id, Bytes::from("old-data "));
        // 11 条满 1MB chunk：FIFO 淘汰把 "old-data " 清出缓冲，front 前跳。
        for _ in 0..11 {
            assert!(app.log_buffer.append(
                id,
                Bytes::from(vec![b'x'; crate::server::log_buffer::MAX_LOG_CHUNK_BYTES])
            ));
        }

        let app_clone = app.clone();
        let writer_log = artifact_log.clone();
        tokio::spawn(async move {
            // 流已补读缺口并消费缓冲存活内容后追加增量（双写同步）。
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

    /// 中途洞变体：全局上限拒收窗口夹在更旧存活 chunk 与新 chunk 之间
    /// （start >= front 不触发 FIFO 洞分支），按首个存活 chunk 偏移识别，
    /// 从落盘 build.log 补读 [start, 洞尾) 再续流。
    #[tokio::test]
    async fn fetch_log_stream_backfills_mid_rejection_hole_from_persisted_file() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "building", None).await;

        // 更旧存活 chunk：缓冲 + artifact_dir 双写（worker report_logs 语义）。
        let artifact_dir = app.artifact_dir().join(id.to_string());
        let artifact_log = artifact_dir.join("build.log");
        tokio::fs::create_dir_all(&artifact_dir).await.unwrap();
        tokio::fs::write(&artifact_log, b"old-data ").await.unwrap();
        app.log_buffer.register(id);
        app.log_buffer.append(id, Bytes::from("old-data "));

        let app_clone = app.clone();
        let writer_log = artifact_log.clone();
        tokio::spawn(async move {
            // 先让 CLI 流消费 "old-data "（读者 offset 停在 9）。
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            // 触顶（全局上限测试值 12MB）：filler 11MB + 已缓冲 9 字节，随后
            // 的整 1MB chunk 越限被拒（11MB + 9 + 1MB > 12MB，确定性拒收）。
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
            // 先落盘、后 append+notify：补读由缓冲通知触发，落盘先于通知消除
            // 读者唤醒时文件尚缺 z 块、补读撞 EOF 的交错。
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
            // 拒收窗口 [9, 9 + 1MB)：chunk 不入缓冲、next_offset 仍推进，新
            // chunk 从洞后起编；两次 append 间无 await，一次唤醒同时看到洞与洞后 chunk。
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
        // 顺序：pre-hole → 洞补读（z 块）→ 洞后存活 chunk（tail）。
        let old_pos = text.find("old-data").unwrap();
        let z_pos = text.find("zzzz").unwrap();
        let tail_pos = text.rfind("tail").unwrap();
        assert!(
            old_pos < z_pos && z_pos < tail_pos,
            "backfilled hole must sit between pre-hole chunk and live tail: {old_pos} < {z_pos} < {tail_pos}"
        );
    }

    /// 详情产品可见性（与 tasks get_task 同口径）：viewer token 对 private 产品
    /// 构建的日志 403（产品级检查独立把门）；public 产品 200。
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

        // private 产品 + 其上的构建（提交者 = viewer 本人：产品级判定与提交者无关，
        // 用本人提交可单独钉住"不做提交者收窄"）。
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

    /// 产品级唯一读边界：孤儿产品（孤儿豁免）上他人 builder 与提交者本人
    /// 同权可读日志，纯提交者维度不再隔离（与产品级测试互补）。
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

        // 落盘 build.log + 翻终态，让流有内容且自然结束。
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

        // 他人 builder → 200（产品可见即可读，与提交者无关）。
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

    /// LogBuffer 路径尊重 `?offset=N`（断线续传不整段重放）；无 offset 从 0 重放。
    #[tokio::test]
    async fn fetch_log_stream_buffer_honors_requested_offset() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "succeeded", None).await;

        app.log_buffer.register(id);
        app.log_buffer.append(id, Bytes::from("hello "));
        app.log_buffer.append(id, Bytes::from("world"));

        let record = app.state_store.get_build(id).await.unwrap().unwrap();

        // offset=6（"hello " 之后）：只推 "world"，不重放 "hello "。
        let response = fetch_log_stream(&app, &record, Some(6)).await.unwrap();
        let text = collect_body_text(response.into_body()).await;
        assert_eq!(text, "world");

        let response = fetch_log_stream(&app, &record, None).await.unwrap();
        let text = collect_body_text(response.into_body()).await;
        assert_eq!(text, "hello world");
    }

    /// 显式 offset 超过 LogBuffer 总大小：与文件路径同语义 400，文案固定不回传大小。
    #[tokio::test]
    async fn fetch_log_stream_buffer_rejects_offset_beyond_size() {
        let (app, _tmp, _result_root) = app_with_result_root().await;
        let (_task_id, id) = insert_task_build(&app, "building", None).await;

        app.log_buffer.register(id);
        app.log_buffer.append(id, Bytes::from("hello world")); // total = 11

        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        let err = fetch_log_stream(&app, &record, Some(12)).await.unwrap_err();
        assert!(
            matches!(err, ApiError::Validation(ref msg) if msg == "offset exceeds current log size"),
            "unexpected error: {:?}",
            err
        );
    }

    /// 文件路径 offset 越界文案：固定文案，不泄露服务端文件大小。
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

    /// 终态补尾分块送达：>4KB 的落盘 tail 以多 chunk 推送（有界内存），完整不截尾。
    #[tokio::test]
    async fn fetch_log_stream_buffer_tail_chunks_large_persisted_tail() {
        let (app, _tmp, result_root) = app_with_result_root().await;
        let (task_id, id) = insert_task_build(&app, "building", None).await;

        let arch_dir = result_root.join(task_id.to_string()).join("x86_64");
        tokio::fs::create_dir_all(&arch_dir).await.unwrap();
        let log_file = arch_dir.join("build.log");
        // report_logs 双写语义：同一 chunk 同时进缓冲和落盘文件。
        let early = "early-line\n";
        // 10KB+ 的 tail：超过单块 4096 字节，必须分成多块送达。
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
            // 等首次轮询吐出 early-line 后制造竞争窗口：大 tail 只落盘，翻终态并驱逐。
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
        // 多帧即证明分块推送（而非 read_to_end 拼单块）。
        assert!(
            frames.len() >= 3,
            "large tail must arrive in multiple chunks, got {} frames",
            frames.len()
        );
    }
}
