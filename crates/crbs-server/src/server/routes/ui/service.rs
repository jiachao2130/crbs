// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Web UI 共享服务与数据访问。

use std::collections::HashMap;
use std::io::BufRead;
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};

use axum::http::HeaderMap;
use bytes::Bytes;

use crate::server::auth::AuthContext;
use crate::server::csrf::{csrf_token_for, validate_csrf_token};
use crate::server::error::ApiError;
use crate::server::routes::warn_audit_log_failure;
use crate::server::state::AppState;

pub(crate) const UI_PAGE_SIZE: usize = 50;

/// 产品 ACL 可授予角色（value=机器串，展示名走 role_label）：授予校验与
/// 下拉构造共用单源；顺序即下拉展示序（输出字节稳定）。
pub(crate) const PRODUCT_ACL_ROLES: [&str; 3] = ["viewer", "builder", "admin"];

/// UI 页审计写（admin/me 各写路径共用）：写入失败仅 warn——主操作已提交，
/// 审计缺口不阻断主流程；warn 标签取 action 便于定位缺口来源。
pub(crate) async fn audit_ui_event(
    app: &AppState,
    ctx: &AuthContext,
    action: &str,
    target: &str,
    detail: Option<&str>,
) {
    if let Err(e) = app
        .state_store
        .audit_log(&ctx.user, &ctx.role, action, Some(target), detail)
        .await
    {
        warn_audit_log_failure(&e, action);
    }
}

/// 列表页每页条数上限：`?limit=` 与 cookie 的 clamp 上界（cookie 档位白名单见 pages::page_size）。
pub(crate) const UI_PAGE_SIZE_MAX: usize = 200;

/// 检查公开访问配置：仅认证启用且对应开关关闭时要求 `AuthContext`。
pub(crate) fn check_public_access(
    app: &AppState,
    access: bool,
    auth: Option<&AuthContext>,
) -> Result<(), ApiError> {
    if app.server_config.auth_enabled && !access {
        auth.ok_or(ApiError::Unauthorized(
            "this page requires authentication".into(),
        ))?;
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub(crate) struct QueryParams<'a> {
    pub product: Option<&'a str>,
    pub name: Option<&'a str>,
    /// 任务标签精确过滤原文（`KEY=VALUE`）。
    pub label: Option<&'a str>,
    pub nvr: Option<&'a str>,
    pub phase: Option<&'a str>,
    pub arch: Option<&'a str>,
    /// 优先级过滤（DB 序列化值 "0"/"1"/"2"，见 `BuildPriority`）。
    pub priority: Option<&'a str>,
    pub task_id: Option<i64>,
    pub sort: Option<&'a str>,
}

impl<'a> QueryParams<'a> {
    /// 构造列表页 URL：非空参数 URL 编码拼接为 query；offset 为 None 或 0 不带参。
    pub(crate) fn url(&self, base_path: &str, offset: Option<usize>) -> String {
        // 键序钉死（渲染的 URL/HTML 字节稳定）：字符串过滤参数 → task_id → sort →
        // offset；task_id（i64）转字符串入表，空滤对其恒不触发。
        let task_id = self.task_id.map(|id| id.to_string());
        let mut qs = build_filter_qs(&[
            ("product", self.product),
            ("name", self.name),
            ("label", self.label),
            ("nvr", self.nvr),
            ("phase", self.phase),
            ("arch", self.arch),
            ("priority", self.priority),
            ("task_id", task_id.as_deref()),
            ("sort", self.sort),
        ]);
        if let Some(o) = offset.filter(|o| *o > 0) {
            qs = if qs.is_empty() {
                format!("offset={o}")
            } else {
                format!("{qs}&offset={o}")
            };
        }
        if qs.is_empty() {
            base_path.to_string()
        } else {
            format!("{base_path}?{qs}")
        }
    }
}

/// 详情页 `?back=`（及 login `?next=`）回跳目标白名单，防 open redirect：
/// 仅放行 `/ui/` 前缀站内路径（`//`、`://` 显式拒绝），超长（>512）非法。
/// 通过返回原字符串（输出由 maud 自动转义），否则 `None`，调用方回退默认目标。
pub(crate) fn safe_back_path(raw: Option<&str>) -> Option<&str> {
    let s = raw?.trim();
    if s.len() > 512 || !s.starts_with("/ui/") || s.starts_with("//") || s.contains("://") {
        return None;
    }
    Some(s)
}

/// 给详情页链接追加 `back` 参数（URL 编码后的当前列表页 path+query）。
pub(crate) fn with_back_param(href: &str, back: &str) -> String {
    let sep = if href.contains('?') { '&' } else { '?' };
    format!("{}{}back={}", href, sep, urlencoding::encode(back))
}

/// 构造"当前列表页"URL（path + 过滤参数 + offset），作详情页 `back` 目标
///（offset=0 不带参）；filter_qs 型列表页用，QueryParams 型走其 `url`。
pub(crate) fn current_list_url(base_path: &str, filter_qs: &str, offset: usize) -> String {
    let mut parts = Vec::new();
    if !filter_qs.is_empty() {
        parts.push(filter_qs.to_string());
    }
    if offset > 0 {
        parts.push(format!("offset={offset}"));
    }
    if parts.is_empty() {
        base_path.to_string()
    } else {
        format!("{}?{}", base_path, parts.join("&"))
    }
}

/// phase 过滤白名单 = store 层 phase 取值集合（展示序与
/// `pages::COUNT_BADGE_PHASE_ORDER` / filter_form 下拉一致）。
/// 仅本文件使用（降私有）：外部统一经 `normalize_phase_filter` 入口。
const PHASE_FILTER_WHITELIST: &[&str] = &[
    "pending",
    "assigned",
    "building",
    "succeeded",
    "failed",
    "timeout",
    "cancelled",
];

/// 归一 phase 过滤参数：白名单内原样放行，未知值（含空串）按未过滤处理。
pub(crate) fn normalize_phase_filter(raw: Option<&str>) -> Option<&str> {
    raw.filter(|v| PHASE_FILTER_WHITELIST.contains(v))
}

/// 管理列表页共享的过滤器查询串：跳过 `None`/空串，按传入顺序拼
/// `k=URL编码(v)`（`&` 连接）；不含 offset——由 `pagination_links` 的
/// `raw_filter_qs` 分支追加。
pub(crate) fn build_filter_qs(params: &[(&str, Option<&str>)]) -> String {
    params
        .iter()
        .filter_map(|(k, v)| {
            v.filter(|s| !s.is_empty())
                .map(|v| format!("{}={}", k, urlencoding::encode(v)))
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// 每页条数：None → 默认 50，clamp 1..=200（query 与 cookie 都过这里收口）；
/// 调用方接线 `q.limit.or(page_size_from_headers(&headers))` 实现 query > cookie > 默认。
pub(crate) fn page_size_or_default(limit: Option<usize>) -> usize {
    limit.unwrap_or(UI_PAGE_SIZE).clamp(1, UI_PAGE_SIZE_MAX)
}

pub(crate) fn download_url(build_id: i64, file: &str) -> String {
    format!(
        "/api/v1/builds/{}/artifacts/download?file={}",
        build_id,
        urlencoding::encode(file)
    )
}

/// 从 `build_artifacts` 加载 UI 展示产物行：`list_artifacts` 已过滤
/// `on_disk=1`，再剔除 `Metadata` / `Script` 内部产物；查询错误向上传播。
pub(crate) async fn load_artifacts_from_db(
    app: &AppState,
    build_id: i64,
) -> Result<Vec<crbs_core::Artifact>, ApiError> {
    use crbs_core::ArtifactKind;

    let rows = app
        .state_store
        .list_artifacts(build_id)
        .await
        .map_err(ApiError::from)?;
    Ok(rows
        .into_iter()
        .filter(|a| !matches!(a.kind, ArtifactKind::Metadata | ArtifactKind::Script))
        .collect())
}

#[derive(serde::Deserialize)]
pub(crate) struct CancelForm {
    pub csrf_token: String,
}

/// Web UI 内联展示的最大日志字节数。
pub(crate) const UI_LOG_INLINE_MAX_BYTES: usize = 256 * 1024;

#[derive(Debug, Default)]
pub(crate) struct LogViewContent {
    /// 实际展示文本（已做 UTF-8 lossy 转换）。
    pub text: String,
    /// 是否因为超过大小限制而截断。
    pub truncated: bool,
    /// 原始日志总字节数。
    pub total_size: u64,
}

/// LogBuffer chunks → 最多 `max_bytes` 字节的尾部字节串：总量 ≤ max 全拼，
/// 否则扣前缀 total-max 正序拼接（`usize::MAX` 即全拼，scan_phase_spans 用）。
/// 尾部扣前缀避免物化全量中间缓冲（LogBuffer 可达 10MB）。
fn concat_chunks_tail(chunks: &[Bytes], max_bytes: usize) -> Vec<u8> {
    let total: usize = chunks.iter().map(|b| b.len()).sum();
    let mut out = Vec::with_capacity(total.min(max_bytes));
    if total <= max_bytes {
        for chunk in chunks {
            out.extend_from_slice(chunk);
        }
        return out;
    }
    let mut skip = total - max_bytes;
    for chunk in chunks {
        if skip >= chunk.len() {
            skip -= chunk.len();
            continue;
        }
        out.extend_from_slice(&chunk[skip..]);
        skip = 0;
    }
    out
}

/// 读取构建日志最近 `max_bytes` 作页面初始展示，返回 `(文本, 末尾累计字节
/// 偏移)`——end_offset 作 SSE `?offset` 起播点（消除 SSR 预览与 SSE 建连间
/// 的跳行/重放窗口），无内容返回 0；LogBuffer 优先，否则回退落盘文件。
pub(crate) async fn read_log_preview(
    app: &Arc<AppState>,
    record: &crbs_core::BuildRecord,
    max_bytes: usize,
) -> (String, u64) {
    if app.log_buffer.has(record.id) {
        // end_offset 与 chunks 须同锁原子取（read_since 同锁返回 next_offset）
        //——分锁另取 total_size 会把快照后 append 的内容既不进预览又被 SSE
        // 跳过；也不能对 chunks 求和（FIFO 淘汰后存活总和 < 真实末尾）。
        // 尾部截断只砍前缀，末尾恒等于 next_offset。
        let (chunks, end_offset, _) = app.log_buffer.read_since(record.id, 0);
        let data = concat_chunks_tail(&chunks, max_bytes);
        return (
            String::from_utf8_lossy(&data).to_string(),
            end_offset as u64,
        );
    }

    if let Some(log_path) =
        crate::server::routes::logs::resolve_log_path_for_record(app, record).await
    {
        match read_tail_bytes(&log_path, max_bytes).await {
            Ok((bytes, end_offset)) => {
                return (String::from_utf8_lossy(&bytes).to_string(), end_offset);
            }
            Err(e) => {
                tracing::warn!(path = %log_path.display(), error = %e, "Failed to read log preview for UI");
            }
        }
    }

    (String::new(), 0)
}

/// 读取完整日志用于终态内联展示：超 `max_bytes` 只返回尾部并标记
/// `truncated`（完整日志经 `/api/v1/builds/{id}/logs?offset=0` 下载）；文件优先、Buffer 兜底。
pub(crate) async fn read_log_full_or_truncated(
    app: &Arc<AppState>,
    record: &crbs_core::BuildRecord,
    max_bytes: usize,
) -> LogViewContent {
    if let Some(log_path) =
        crate::server::routes::logs::resolve_log_path_for_record(app, record).await
    {
        match read_log_file_full_or_truncated(&log_path, max_bytes).await {
            Ok(content) => return content,
            Err(e) => {
                tracing::warn!(path = %log_path.display(), error = %e, "Failed to read full log for UI");
            }
        }
    }

    if app.log_buffer.has(record.id) {
        // truncated / total_size 以显式 total 计算：直传
        // [`truncate_bytes_to_log_content`] 会按尾部 data.len() 失真
        //（truncated 恒 false、total_size 被压进上限内）。
        let chunks = app.log_buffer.read(record.id);
        let total_size: u64 = chunks.iter().map(|b| b.len() as u64).sum();
        let data = concat_chunks_tail(&chunks, max_bytes);
        return LogViewContent {
            text: String::from_utf8_lossy(&data).to_string(),
            truncated: total_size > max_bytes as u64,
            total_size,
        };
    }

    LogViewContent::default()
}

/// 阶段标记行收集上限：行数/累计字节双上限（真实每构建 ~10 行，只拦异常膨胀）。
const PHASE_MARKER_MAX_LINES: usize = 10_000;
const PHASE_MARKER_MAX_BYTES: usize = 1024 * 1024;

/// phase_timeline_spans 的日志来源（指纹阶段一次定源，避免二次 resolve）。
enum LogSource {
    Buffer,
    File(std::path::PathBuf),
}

/// phase_timeline_spans 结果指纹：枚举天然区分日志来源——Buffer→File 切换
/// （终态驱逐后回落落盘日志）即指纹变化 ⇒ 未命中重扫，语义安全。
#[derive(Debug, Clone, PartialEq, Eq)]
enum PhaseSpanFingerprint {
    /// LogBuffer 路径：单调累计偏移（`LogBuffer::total_size`，O(1)）。
    /// 同偏移 ⇒ 无 append ⇒ 无 FIFO 淘汰 ⇒ 缓冲不变 ⇒ spans 不变。
    Buffer(usize),
    /// 落盘文件路径：(len, mtime)——size 跟住追加，mtime 防同尺寸重写。
    File(u64, std::time::SystemTime),
    /// 指纹不可得（resolve 与 metadata 间删除竞态）：不读不写缓存，退化为直扫。
    Unknown,
}

type PhaseSpanCacheMap = HashMap<
    i64,
    (
        PhaseSpanFingerprint,
        Arc<Vec<crbs_core::engine::profile::PhaseSpan>>,
    ),
>;

/// phase spans 进程内指纹缓存：build SSE 每 tick 调 phase_timeline_spans，
/// 任何状态写会唤醒全部观众连接各扫一次（Buffer 克隆 ≤10MB 缓冲 / File
/// 逐行扫 GB 级日志），指纹未变即回缓存克隆。锁不跨 await（短锁读写、
/// 扫描在锁外）；容量超限整表清空（防无界增长，代价是下次重扫一次）。
static PHASE_SPAN_CACHE: LazyLock<Mutex<PhaseSpanCacheMap>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// [`PHASE_SPAN_CACHE`] 容量上限（build 数）：活跃构建数量级。
const PHASE_SPAN_CACHE_MAX_BUILDS: usize = 128;

/// 解析 build.log 的 `CRBS_PHASE_*` 标记为时间线区间（阶段时间线）。
/// 全文件流式扫描（收集行集合见 [`collect_timeline_lines`]），内存
/// O(标记数)——tail 窗口会漏掉早期步骤的 START/END 标记、时间线退化。
/// LogBuffer 命中读全量缓冲；File 路径 `spawn_blocking` 逐行扫盘（build.log
/// 可达 GB，不能在异步线程整读）；无标记返回空列表。指纹缓存见
/// [`PHASE_SPAN_CACHE`]；返回 Arc 与缓存写回共享同一份，需独立可变副本
/// 自行 `(*spans).clone()`。
pub(crate) async fn phase_timeline_spans(
    app: &Arc<AppState>,
    record: &crbs_core::BuildRecord,
) -> Arc<Vec<crbs_core::engine::profile::PhaseSpan>> {
    // 定源 + 指纹：Buffer 用 has/total_size（O(1)，has 为真时 total_size 必为
    // Some）；File 用 resolve_log_path 后的 metadata。
    let (fingerprint, source) = if app.log_buffer.has(record.id) {
        (
            PhaseSpanFingerprint::Buffer(app.log_buffer.total_size(record.id).unwrap_or(0)),
            LogSource::Buffer,
        )
    } else {
        match crate::server::routes::logs::resolve_log_path_for_record(app, record).await {
            Some(log_path) => match tokio::fs::metadata(&log_path).await {
                Ok(meta) => (
                    PhaseSpanFingerprint::File(
                        meta.len(),
                        meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH),
                    ),
                    LogSource::File(log_path),
                ),
                // ponytail: Unknown（resolve 与 metadata 间删除竞态）不写行为
                // 测试——精确时序无法确定性构造；行为上限是读写都跳过缓存，
                // 无错误固化路径。需覆盖时引入可注入的 metadata 失败点再补。
                Err(_) => (PhaseSpanFingerprint::Unknown, LogSource::File(log_path)),
            },
            // 无任何日志来源：返回空列表，不缓存——来源出现后指纹即变，
            // 天然转为重扫。
            None => return Arc::new(Vec::new()),
        }
    };
    // 短锁读：命中即免整缓冲克隆 / GB 级文件重扫。
    if let Ok(cache) = PHASE_SPAN_CACHE.lock() {
        if let Some((fp, spans)) = cache.get(&record.id) {
            if *fp == fingerprint {
                return Arc::clone(spans);
            }
        }
    }
    // 锁外扫描、短锁写回（Arc 与缓存共享同一份）。扫描失败（None）不写
    // 缓存：瞬态 IO 失败不得按有效指纹固化空时间线——File 态终态构建指纹
    // 不再变，命中会让时间线空到进程重启；留待下次重扫。
    let spans = match scan_phase_spans(app, record, source).await {
        Some(spans) => Arc::new(spans),
        None => return Arc::new(Vec::new()),
    };
    if fingerprint != PhaseSpanFingerprint::Unknown {
        let mut cache = PHASE_SPAN_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() > PHASE_SPAN_CACHE_MAX_BUILDS {
            cache.clear();
        }
        cache.insert(record.id, (fingerprint, Arc::clone(&spans)));
    }
    spans
}

/// [`phase_timeline_spans`] 的扫描主体（缓存未命中路径，不二次 resolve）：
/// `None` = 扫描失败（IO / join 失败），不得写缓存；`Some` 内的空列表是
/// "扫描成功但无标记"的合法结果。
async fn scan_phase_spans(
    app: &Arc<AppState>,
    record: &crbs_core::BuildRecord,
    source: LogSource,
) -> Option<Vec<crbs_core::engine::profile::PhaseSpan>> {
    match source {
        LogSource::Buffer => {
            // 全拼形态（max 传 usize::MAX）；行号由 parse_phase_markers 内部
            // lines() 枚举，无需二次物化 Vec<(u64, &str)>。
            let chunks = app.log_buffer.read(record.id);
            let data = concat_chunks_tail(&chunks, usize::MAX);
            let text = String::from_utf8_lossy(&data);
            Some(crbs_core::engine::profile::parse_phase_markers(&text))
        }
        LogSource::File(log_path) => {
            let path_for_log = log_path.clone();
            match tokio::task::spawn_blocking(move || collect_timeline_lines(&log_path)).await {
                Ok(Ok(lines)) => {
                    let numbered: Vec<(u64, &str)> = lines
                        .iter()
                        .map(|(no, line)| (*no, line.as_str()))
                        .collect();
                    Some(crbs_core::engine::profile::parse_phase_markers_numbered(
                        &numbered,
                    ))
                }
                Ok(Err(e)) => {
                    tracing::warn!(
                        path = %path_for_log.display(),
                        error = %e,
                        "Failed to scan build log for phase timeline"
                    );
                    None
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path_for_log.display(),
                        error = %e,
                        "Phase timeline marker scan task failed to join"
                    );
                    None
                }
            }
        }
    }
}

/// 流式逐行扫描日志文件，只收集时间线消费的行（带 1 起行号）：`#
/// CRBS_PHASE_` 标记行、rpmbuild 子阶段边界（`Executing(%xxx)`）与失败归属
///（`error: Bad exit status from`，后两类供 [`PhaseSpan::sub`] 定位）。
/// 双上限超限即停止收集——缺失标记表现为对应 phase 不出现，解析器容忍。
fn collect_timeline_lines(path: &Path) -> std::io::Result<Vec<(u64, String)>> {
    let file = std::fs::File::open(path)?;
    let mut lines = Vec::new();
    let mut total_bytes = 0usize;
    for (i, line) in std::io::BufReader::new(file).lines().enumerate() {
        let line = line?;
        let is_marker = line.starts_with("# CRBS_PHASE_");
        // 插桩标记带时间戳（时间线分段条的数据源），与边界/归属行同收。
        let is_subphase_marker = line.starts_with("# CRBS_SUBPHASE ");
        let is_subphase_boundary = line.starts_with("Executing(%");
        let is_subphase_error = line.starts_with("error: Bad exit status from ");
        if !is_marker && !is_subphase_marker && !is_subphase_boundary && !is_subphase_error {
            continue;
        }
        if lines.len() >= PHASE_MARKER_MAX_LINES || total_bytes >= PHASE_MARKER_MAX_BYTES {
            tracing::warn!(
                path = %path.display(),
                "Phase marker lines exceed defensive cap, collection truncated"
            );
            break;
        }
        total_bytes += line.len() + 1;
        lines.push((i as u64 + 1, line));
    }
    Ok(lines)
}

async fn read_log_file_full_or_truncated(
    path: &Path,
    max_bytes: usize,
) -> Result<LogViewContent, std::io::Error> {
    let metadata = tokio::fs::metadata(path).await?;
    let file_size = metadata.len();
    if file_size <= max_bytes as u64 {
        let bytes = tokio::fs::read(path).await?;
        // metadata 之后日志可能继续增长（构建进行中），读取结果仍可能超过 max_bytes：
        // 复用截尾逻辑，保证返回内容不超过上限（total_size 以实际读取长度为准）。
        Ok(truncate_bytes_to_log_content(bytes, max_bytes))
    } else {
        let (bytes, tail_end) = read_tail_bytes(path, max_bytes).await?;
        Ok(LogViewContent {
            text: String::from_utf8_lossy(&bytes).to_string(),
            truncated: true,
            total_size: tail_end,
        })
    }
}

fn truncate_bytes_to_log_content(data: Vec<u8>, max_bytes: usize) -> LogViewContent {
    let total_size = data.len() as u64;
    if data.len() > max_bytes {
        let text = String::from_utf8_lossy(&data[data.len() - max_bytes..]).to_string();
        LogViewContent {
            text,
            truncated: true,
            total_size,
        }
    } else {
        let text = String::from_utf8_lossy(&data).to_string();
        LogViewContent {
            text,
            truncated: false,
            total_size,
        }
    }
}

/// 读取文件末尾 `max_bytes` 字节，返回 `(字节, 末尾偏移)`（如 SSE `?offset`
/// 起播点）。不变量：bytes ⇔ `[offset - len, offset)` 严格对应——错位会让
/// SSE 起播重复推送 preview 已含的交界字节。读循环以 metadata 快照为上界：
/// 快照后增长的字节留给 SSE 续推；收缩按 EOF 实读为准，`offset` = 实读末位。
async fn read_tail_bytes(
    path: &std::path::Path,
    max_bytes: usize,
) -> Result<(Vec<u8>, u64), std::io::Error> {
    let metadata = tokio::fs::metadata(path).await?;
    let file_size = metadata.len();
    let start = file_size.saturating_sub(max_bytes as u64);
    let mut file = tokio::fs::File::open(path).await?;
    tokio::io::AsyncSeekExt::seek(&mut file, std::io::SeekFrom::Start(start)).await?;
    // want = [start, file_size) 的长度，恒 ≤ max_bytes：每次 read 也夹在剩余
    // 目标量内（增长部分不进 read），读后无需再截尾。
    let want = (file_size - start) as usize;
    let mut buf = vec![0u8; want];
    let mut read = Vec::new();
    loop {
        let filled = read.len();
        let n = tokio::io::AsyncReadExt::read(&mut file, &mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        read.extend_from_slice(&buf[filled..filled + n]);
    }
    let offset = start + read.len() as u64;
    Ok((read, offset))
}

/// 从请求头会话凭据 cookie 派生 CSRF token（双模式：`crbs_session` 优先，
/// 回落 `crbs_token`）；渲染侧与校验侧须共用同一派生链，否则表单 CSRF 失配。
pub(crate) fn csrf_token_for_request(headers: &HeaderMap, csrf_key: &[u8; 32]) -> Option<String> {
    crate::server::csrf::csrf_base_from_headers(headers)
        .and_then(|t| csrf_token_for(&t, csrf_key).ok())
}

/// 校验 UI 写操作 CSRF：会话凭据存在 + token 匹配，返回派生基值；不取认证
/// 上下文、不做角色检查。错误口径：无凭据 → `Unauthorized("missing session
/// token")`，不匹配 → `PermissionDenied("invalid CSRF token")`。
pub(crate) fn require_csrf(
    headers: &HeaderMap,
    provided_token: &str,
    csrf_key: &[u8; 32],
) -> Result<String, ApiError> {
    let session = crate::server::csrf::csrf_base_from_headers(headers)
        .ok_or_else(|| ApiError::Unauthorized("missing session token".into()))?;
    if !validate_csrf_token(&session, csrf_key, provided_token)? {
        return Err(ApiError::PermissionDenied("invalid CSRF token".into()));
    }
    Ok(session)
}

/// 校验取消表单：`AuthContext` 存在（取消需认证）+ session/token 双模式
/// cookie + CSRF 匹配。
pub(crate) fn require_cancel_session(
    auth: Option<&AuthContext>,
    headers: &HeaderMap,
    form: &CancelForm,
    csrf_key: &[u8; 32],
) -> Result<String, ApiError> {
    if auth.is_none() {
        return Err(ApiError::Unauthorized(
            "authentication required to cancel".into(),
        ));
    }
    require_csrf(headers, &form.csrf_token, csrf_key)
}

/// 校验 Admin 表单是否具备有效的 session cookie、CSRF token，且当前用户为 admin 角色。
pub(crate) fn require_admin_session(
    auth: Option<&AuthContext>,
    headers: &HeaderMap,
    csrf_token: &str,
    csrf_key: &[u8; 32],
) -> Result<AuthContext, ApiError> {
    let ctx = auth
        .ok_or_else(|| ApiError::Unauthorized("admin authentication required".into()))?
        .clone();
    if !ctx.is_admin() {
        return Err(ApiError::PermissionDenied(
            "only admin can perform this action".into(),
        ));
    }
    validate_session_csrf(&ctx, headers, csrf_token, csrf_key)
}

/// 校验已登录用户表单（/ui/me 自管）：session/token 双模式 cookie + CSRF，
/// 角色无关——viewer 也能改自己的密码、管理 token。
pub(crate) fn require_session(
    auth: Option<&AuthContext>,
    headers: &HeaderMap,
    csrf_token: &str,
    csrf_key: &[u8; 32],
) -> Result<AuthContext, ApiError> {
    let ctx = auth
        .ok_or_else(|| ApiError::Unauthorized("authentication required".into()))?
        .clone();
    validate_session_csrf(&ctx, headers, csrf_token, csrf_key)
}

/// 双模式 cookie 存在性 + CSRF token 匹配（require_*_session 共用尾段）。
fn validate_session_csrf(
    ctx: &AuthContext,
    headers: &HeaderMap,
    csrf_token: &str,
    csrf_key: &[u8; 32],
) -> Result<AuthContext, ApiError> {
    require_csrf(headers, csrf_token, csrf_key)?;
    Ok(ctx.clone())
}

#[cfg(test)]
mod tests {
    use super::{
        build_filter_qs, concat_chunks_tail, csrf_token_for, current_list_url,
        normalize_phase_filter, page_size_or_default, phase_timeline_spans, read_tail_bytes,
        require_csrf, safe_back_path, with_back_param, PhaseSpanFingerprint,
        PHASE_FILTER_WHITELIST, PHASE_SPAN_CACHE, PHASE_SPAN_CACHE_MAX_BUILDS, UI_PAGE_SIZE,
    };
    use crate::server::error::ApiError;
    use crate::server::state::AppState;
    use axum::http::{header, HeaderMap};
    use bytes::Bytes;
    use std::sync::Arc;

    #[test]
    fn page_size_or_default_defaults_and_clamps_to_200() {
        assert_eq!(page_size_or_default(None), UI_PAGE_SIZE);
        assert_eq!(page_size_or_default(Some(1)), 1);
        assert_eq!(page_size_or_default(Some(100)), 100);
        assert_eq!(page_size_or_default(Some(200)), 200);
        assert_eq!(page_size_or_default(Some(201)), 200);
        assert_eq!(page_size_or_default(Some(usize::MAX)), 200);
        assert_eq!(page_size_or_default(Some(0)), 1);
    }

    #[test]
    fn build_filter_qs_skips_none_and_empty_and_keeps_order() {
        assert_eq!(build_filter_qs(&[]), "");
        assert_eq!(
            build_filter_qs(&[
                ("name", Some("batch")),
                ("arch", None),
                ("status", Some("")),
            ]),
            "name=batch"
        );
        assert_eq!(
            build_filter_qs(&[
                ("name", Some("batch")),
                ("arch", Some("x86_64")),
                ("status", Some("online")),
            ]),
            "name=batch&arch=x86_64&status=online"
        );
    }

    #[test]
    fn build_filter_qs_urlencodes_values() {
        assert_eq!(
            build_filter_qs(&[("name", Some("a b&c")), ("status", Some("online"))]),
            "name=a%20b%26c&status=online"
        );
    }

    #[test]
    fn safe_back_path_accepts_only_ui_relative_paths() {
        assert_eq!(safe_back_path(Some("/ui/builds")), Some("/ui/builds"));
        assert_eq!(
            safe_back_path(Some("/ui/builds?phase=failed&offset=50")),
            Some("/ui/builds?phase=failed&offset=50")
        );
        assert_eq!(
            safe_back_path(Some("/ui/admin/users/7")),
            Some("/ui/admin/users/7")
        );
        assert_eq!(safe_back_path(None), None);

        for bad in [
            "https://evil.example/ui/builds",
            "//evil.example/ui/builds",
            "/api/v1/builds",
            "ui/builds",
            "/ui",
            "",
        ] {
            assert_eq!(safe_back_path(Some(bad)), None, "must reject {bad:?}");
        }
    }

    #[test]
    fn safe_back_path_rejects_overlong_values() {
        let long = format!("/ui/builds?x={}", "a".repeat(600));
        assert_eq!(safe_back_path(Some(&long)), None);
        let ok = format!("/ui/builds?x={}", "a".repeat(64));
        assert_eq!(safe_back_path(Some(&ok)), Some(ok.as_str()));
    }

    #[test]
    fn with_back_param_urlencodes_and_picks_separator() {
        assert_eq!(
            with_back_param("/ui/builds/1", "/ui/builds?phase=failed&offset=50"),
            "/ui/builds/1?back=%2Fui%2Fbuilds%3Fphase%3Dfailed%26offset%3D50"
        );
        assert_eq!(
            with_back_param("/ui/packages/hello?nvr=hello-1.0-1", "/ui/packages"),
            "/ui/packages/hello?nvr=hello-1.0-1&back=%2Fui%2Fpackages"
        );
    }

    #[test]
    fn current_list_url_appends_filters_and_offset() {
        assert_eq!(current_list_url("/ui/workers", "", 0), "/ui/workers");
        assert_eq!(
            current_list_url("/ui/workers", "", 50),
            "/ui/workers?offset=50"
        );
        assert_eq!(
            current_list_url("/ui/workers", "name=w1&status=online", 0),
            "/ui/workers?name=w1&status=online"
        );
        assert_eq!(
            current_list_url("/ui/workers", "name=w1&status=online", 50),
            "/ui/workers?name=w1&status=online&offset=50"
        );
    }

    #[test]
    fn normalize_phase_filter_passes_whitelist_and_drops_unknown() {
        for phase in PHASE_FILTER_WHITELIST {
            assert_eq!(normalize_phase_filter(Some(phase)), Some(*phase));
        }
        assert_eq!(normalize_phase_filter(None), None);
        // 未知 / 空 / 大小写不一致：按未过滤处理。
        for bad in ["", "bogus", "Succeeded", "running"] {
            assert_eq!(normalize_phase_filter(Some(bad)), None, "must drop {bad:?}");
        }
    }

    #[test]
    fn require_csrf_rejects_missing_credentials() {
        let err = require_csrf(&HeaderMap::new(), "tok", &[7u8; 32]).unwrap_err();
        assert!(matches!(err, ApiError::Unauthorized(ref m) if m == "missing session token"));
    }

    #[test]
    fn require_csrf_rejects_wrong_token() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "crbs_token=crbs_tok_abc".parse().unwrap());
        let err = require_csrf(&headers, "bogus", &[7u8; 32]).unwrap_err();
        assert!(matches!(err, ApiError::PermissionDenied(ref m) if m == "invalid CSRF token"));
    }

    #[test]
    fn require_csrf_accepts_derived_token_and_returns_session_base() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "crbs_token=crbs_tok_abc".parse().unwrap());
        let key = [7u8; 32];
        let token = csrf_token_for("crbs_tok_abc", &key).unwrap();
        let session = require_csrf(&headers, &token, &key).unwrap();
        assert_eq!(session, "crbs_tok_abc");
    }

    // ===== phase_timeline_spans 指纹缓存直调测试 =====
    //
    // PHASE_SPAN_CACHE 是进程级 static：直调测试经此互斥串行、起始清空；隔离
    // 靠 id——Buffer 用远超自增范围的合成 id，File 需真实 DB 行、以垫位把
    // build id 顶到其他测试不可达高位。SSE 路由测试不持锁（残余后台任务仍会
    // 并发写缓存），容量测试分支①自带抗污染重试。
    static PHASE_SPAN_CACHE_TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Buffer 路径直调用的合成记录（File 路径不可用——它要查 DB 行）。
    fn synthetic_record(id: i64) -> crbs_core::BuildRecord {
        crbs_core::BuildRecord {
            id,
            product: "fedora".into(),
            pkg_name: "pkg".into(),
            name: "pkg".into(),
            version: "1".into(),
            release: "1".into(),
            phase: "building".into(),
            result_dir: None,
            srpm_path: None,
            started_at: None,
            completed_at: None,
            duration: None,
            layer_digest: None,
            base_os_digest: None,
            backend: Some("chroot".into()),
            user: "alice".into(),
            user_id: None,
            crbs_pid: None,
            arch: None,
            task_id: None,
            rpms: Vec::new(),
            signed: false,
            priority: 0,
            error_summary: None,
            deterministic: false,
            repo_publish: true,
            repo_consume: true,
            canonical_srpm_sha256: None,
            peak_rss_kb: None,
            peak_total_kb: None,
            cpu_secs: None,
            cpu_p90_cores: None,
            disk_wbytes: None,
            oom_killed: None,
            sample_backend: None,
            sample_ncpu: None,
            peak_tmpfs_kb: None,
            req_min_mem_kb: None,
            req_min_ncpu: None,
            req_min_disk_kb: None,
        }
    }

    /// 读缓存中某 build 的当前指纹（直调测试的断言通道）。
    fn cached_fingerprint(id: i64) -> Option<PhaseSpanFingerprint> {
        PHASE_SPAN_CACHE
            .lock()
            .unwrap()
            .get(&id)
            .map(|(fp, _)| fp.clone())
    }

    async fn cache_test_app() -> (Arc<AppState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        (app, tmp)
    }

    /// 容量整清两分支：len == 上限（128）写入不整清（新旧共存）；len > 上限
    /// 的下一次写入整表清空（只剩新条目，旧条目多付一次重扫）。
    ///
    /// 抗并发污染：不持锁的 SSE 路由测试可能在垫位与写回间并发写缓存、把
    /// len 顶过上限（那是生产正确整清，非分支①验证对象）。分支①以"干净
    /// 观测"判定：键集合恰为 垫位 ∪ {新 id} 才有效，不符换指纹重试（污染
    /// 窗口毫秒级）；真回归 K 次全败照常判红。分支②免疫污染（9_000_000 不得存活）。
    #[tokio::test]
    async fn phase_span_cache_capacity_clears_whole_table_both_branches() {
        let _guard = PHASE_SPAN_CACHE_TEST_MUTEX.lock().await;
        let (app, _tmp) = cache_test_app().await;
        let id = 8_000_001;
        let record = synthetic_record(id);
        app.log_buffer.append(
            id,
            bytes::Bytes::from_static(b"# CRBS_PHASE_START build 1.0\n"),
        );

        // 分支①：len(128) == 上限，不整清——新条目入缓存、垫位旧条目保留。
        const CLEAN_ATTEMPTS: usize = 8;
        let mut clean_observation = false;
        for attempt in 0..CLEAN_ATTEMPTS {
            {
                let mut cache = PHASE_SPAN_CACHE.lock().unwrap();
                cache.clear();
                for i in 0..PHASE_SPAN_CACHE_MAX_BUILDS {
                    cache.insert(
                        9_000_000 + i as i64,
                        (PhaseSpanFingerprint::Buffer(0), Arc::new(Vec::new())),
                    );
                }
            }
            // 每次尝试换指纹（追加非标记行只推 total_size），重试才走 miss → 写回而非命中短路。
            app.log_buffer
                .append(id, bytes::Bytes::from(format!("attempt {attempt}\n")));

            let spans = phase_timeline_spans(&app, &record).await;
            assert_eq!(spans.len(), 1, "{spans:?}");
            let snapshot: std::collections::HashSet<i64> =
                PHASE_SPAN_CACHE.lock().unwrap().keys().copied().collect();
            let expected: std::collections::HashSet<i64> = (9_000_000
                ..9_000_000 + PHASE_SPAN_CACHE_MAX_BUILDS as i64)
                .chain(std::iter::once(id))
                .collect();
            if snapshot == expected {
                clean_observation = true;
                break;
            }
        }
        assert!(
            clean_observation,
            "no pollution-free observation in {CLEAN_ATTEMPTS} attempts: \
             len == MAX write must NOT clear old entries (or unlocked \
             concurrent writers kept interfering)"
        );

        // 分支②：再垫一条（len > 上限）并换指纹逼出重扫——写入整表清空，只剩新条目。
        {
            let mut cache = PHASE_SPAN_CACHE.lock().unwrap();
            cache.insert(
                9_000_128,
                (PhaseSpanFingerprint::Buffer(0), Arc::new(Vec::new())),
            );
        }
        app.log_buffer.append(
            id,
            bytes::Bytes::from_static(b"# CRBS_PHASE_END build 0 2.0\n"),
        );
        let spans = phase_timeline_spans(&app, &record).await;
        assert_eq!(spans.len(), 1, "{spans:?}");
        {
            let cache = PHASE_SPAN_CACHE.lock().unwrap();
            assert!(
                !cache.contains_key(&9_000_000),
                "len > MAX write must clear the whole table"
            );
            assert!(
                cache.contains_key(&id),
                "the writing entry survives the clear"
            );
        }
    }

    /// Buffer→File 指纹切换（终态驱逐后回落落盘）：指纹变化 ⇒ 未命中重扫，
    /// spans 来自文件内容（非缓冲旧值），缓存回写 File 指纹。
    #[tokio::test]
    async fn phase_span_cache_buffer_to_file_switch_rescans() {
        let _guard = PHASE_SPAN_CACHE_TEST_MUTEX.lock().await;
        PHASE_SPAN_CACHE.lock().unwrap().clear();

        let (app, tmp) = cache_test_app().await;
        // 垫位把 build id 顶到高位（避免与并行测试共享小 id 键）；task_id
        // 非空，垫位行共用一个 task。
        let pad_task = crate::test_support::seed_task(&app.state_store, "fedora", "pkg").await;
        for _ in 0..120 {
            app.state_store
                .insert_build(crbs_core::BuildInsert {
                    product: "fedora",
                    pkg_name: "pkg",
                    phase: "failed",
                    backend: "chroot",
                    user: "alice",
                    task_id: Some(pad_task),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        let task_id = crate::test_support::seed_task(&app.state_store, "fedora", "pkg").await;
        let id = app
            .state_store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "pkg",
                phase: "building",
                backend: "chroot",
                user: "alice",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            id > 120,
            "padding must push the target id beyond other tests' reach"
        );

        // Buffer 态：缓冲一条 START 标记 → 扫描入缓存（Buffer 指纹）。
        let record = app.state_store.get_build(id).await.unwrap().unwrap();
        app.log_buffer.append(
            id,
            bytes::Bytes::from_static(b"# CRBS_PHASE_START build 1.0\n"),
        );
        let spans = phase_timeline_spans(&app, &record).await;
        assert_eq!(
            spans.iter().filter(|s| s.name == "build").count(),
            1,
            "{spans:?}"
        );
        assert!(matches!(
            cached_fingerprint(id),
            Some(PhaseSpanFingerprint::Buffer(_))
        ));

        // 切换：驱逐缓冲 + result_dir 落盘另一份标记集（只有 prepare-layer）。
        app.log_buffer.evict(id);
        let arch_dir = tmp
            .path()
            .join("results")
            .join(task_id.to_string())
            .join("x86_64");
        tokio::fs::create_dir_all(&arch_dir).await.unwrap();
        tokio::fs::write(
            arch_dir.join("build.log"),
            b"# CRBS_PHASE_START prepare-layer 1.0\n# CRBS_PHASE_END prepare-layer 0 2.0\n",
        )
        .await
        .unwrap();
        app.state_store
            .update_build_info(id, Some(arch_dir.to_str().unwrap()), None, "chroot")
            .await
            .unwrap();
        let record = app.state_store.get_build(id).await.unwrap().unwrap();

        let spans = phase_timeline_spans(&app, &record).await;
        assert!(
            spans.iter().all(|s| s.name != "build"),
            "stale Buffer cache must not survive the source switch: {spans:?}"
        );
        assert_eq!(
            spans.iter().filter(|s| s.name == "prepare-layer").count(),
            1,
            "{spans:?}"
        );
        assert!(matches!(
            cached_fingerprint(id),
            Some(PhaseSpanFingerprint::File(_, _))
        ));
    }

    // ===== concat_chunks_tail=====

    fn bytes_of(parts: &[&[u8]]) -> Vec<Bytes> {
        parts.iter().map(|p| Bytes::copy_from_slice(p)).collect()
    }

    /// 三档边界（不足 / 恰等 `>` 不截 / 超限恰取尾部 max）× 切点位置（chunk 中段 / 边界）。
    #[test]
    fn concat_chunks_tail_under_equal_over() {
        let chunks = bytes_of(&[b"abc", b"de"]);
        assert_eq!(concat_chunks_tail(&chunks, 10), b"abcde");

        let chunks = bytes_of(&[b"abc", b"de"]);
        assert_eq!(concat_chunks_tail(&chunks, 5), b"abcde");

        // 超限、切点在 chunk 中段：扣掉前缀 total-max 后正序拼接剩余。
        let chunks = bytes_of(&[b"abc", b"de", b"fgh"]);
        assert_eq!(concat_chunks_tail(&chunks, 5), b"defgh");

        // 超限、切点恰在 chunk 边界：整块跳过。
        let chunks = bytes_of(&[b"abc", b"de", b"fgh"]);
        assert_eq!(concat_chunks_tail(&chunks, 4), b"efgh");

        // 超限且 max=0：扣掉全部前缀，产出空串。
        let chunks = bytes_of(&[b"abc"]);
        assert!(concat_chunks_tail(&chunks, 0).is_empty());

        assert!(concat_chunks_tail(&[], 8).is_empty());
    }

    /// 切点切中多字节字符：孤立续字节经 lossy 产出 U+FFFD（替换符），后续字符不受影响。
    #[test]
    fn concat_chunks_tail_mid_char_cut_yields_replacement_char() {
        // "你" = E4 BD A0，"好" = E5 A5 BD；max=5 → 尾部从"你"的第 2 字节起。
        let chunks = bytes_of(&["你好".as_bytes()]);
        let tail = concat_chunks_tail(&chunks, 5);
        assert_eq!(tail, [0xBD, 0xA0, 0xE5, 0xA5, 0xBD]);
        let text = String::from_utf8_lossy(&tail);
        assert!(text.starts_with('\u{FFFD}'), "got: {text:?}");
        assert!(text.ends_with("好"));

        // 切点跨 chunk（"你" 完整落在被丢弃前缀里）：同样以替换符开头。
        let chunks = bytes_of(&["x你".as_bytes(), "好".as_bytes()]);
        let tail = concat_chunks_tail(&chunks, 4);
        let text = String::from_utf8_lossy(&tail);
        assert!(text.starts_with('\u{FFFD}'), "got: {text:?}");
        assert!(text.ends_with("好"));
    }

    /// 一致性不变量：`(bytes, offset)` 满足 bytes ⇔ `[offset - len, offset)`
    ///（preview 与 SSE `?offset` 起播点交界不重不漏）；增长竞态无法确定性
    /// 构造，只钉常态路径。
    #[tokio::test]
    async fn read_tail_bytes_offset_matches_returned_tail() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("build.log");
        let body: Vec<u8> = (0..100u8).collect();
        tokio::fs::write(&path, &body).await.unwrap();

        let (bytes, offset) = read_tail_bytes(&path, 50).await.unwrap();
        assert_eq!((bytes.len(), offset), (50, 100));
        assert_eq!(bytes, &body[50..]);

        let (bytes, offset) = read_tail_bytes(&path, 200).await.unwrap();
        assert_eq!((bytes.len(), offset), (100, 100));
        assert_eq!(bytes, body);

        tokio::fs::write(&path, b"").await.unwrap();
        let (bytes, offset) = read_tail_bytes(&path, 50).await.unwrap();
        assert!(bytes.is_empty());
        assert_eq!(offset, 0);
    }
}
