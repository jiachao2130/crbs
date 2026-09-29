// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use crate::cli::{CommandOutput, OutputFormat};
use crbs_core::error::CrbsError;
use crbs_core::StateStore;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// logs 命令参数。lines：None = 未传 -n（退回 DEFAULT_LOG_LINES），Some(0) = 全量；远程 -f 只拒绝显式非零 -n。
pub(crate) struct LogsArgs {
    pub task: String,
    pub arch: Option<String>,
    pub follow: bool,

    pub lines: Option<usize>,
    pub editor: bool,
    pub grep: Vec<String>,
    pub format: OutputFormat,
    pub remote: Option<String>,
    pub token: Option<String>,
    pub local: bool,
}

pub(crate) const DEFAULT_LOG_LINES: usize = 50;

#[derive(serde::Serialize)]
/// 日志行统一输出（本地/远程共享 JSON 结构）。键恒存在（schema 稳定性）：远程为 null，本地为日志文件路径。
struct LogLinesOutput {
    command: &'static str,
    task_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    build_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    arch: Option<String>,

    log_file: Option<String>,
    lines: Vec<String>,
}

impl CommandOutput for LogLinesOutput {
    fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    fn print_text(&self) {
        for line in &self.lines {
            println!("{}", line);
        }
    }
}

pub(crate) fn grep_print_line(line: &str, grep: &[String]) {
    if matches_grep(line, grep) {
        println!("{}", line);
    }
}

/// 打开日志文件：NotFound 返回 None（容忍日志尚未生成），其他错误上抛。
async fn open_log_file(log_file: &Path) -> anyhow::Result<Option<tokio::fs::File>> {
    match tokio::fs::File::open(log_file).await {
        Ok(f) => Ok(Some(f)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_error(format!("Failed to open {}", log_file.display()), e).into()),
    }
}

fn io_error(context: String, e: std::io::Error) -> CrbsError {
    CrbsError::Io {
        context,
        kind: e.kind(),
        detail: e.to_string(),
    }
}

/// 预分配上限：无上界的巨值 -n 直接进 VecDeque::with_capacity 会一次性巨额分配（自我 DoS）；环形缓冲仍按真实 lines 语义滚动。
const MAX_TAIL_CAPACITY_LINES: usize = 1_000_000;

fn new_tail_ring(lines: usize) -> std::collections::VecDeque<String> {
    if lines > 0 {
        std::collections::VecDeque::with_capacity(lines.min(MAX_TAIL_CAPACITY_LINES))
    } else {
        std::collections::VecDeque::new()
    }
}

fn print_tail_truncation_note(lines: usize, total_lines: usize) {
    if total_lines > lines {
        eprintln!(
            "... (showing last {} of {} lines, use -n 0 for complete log)\n",
            lines, total_lines
        );
    }
}

/// follow 轮询的连续 DB 读失败上限：超限视为日志源持续不可用，中止 follow 上抛 DatabaseUnavailable。
const FOLLOW_DB_FAIL_LIMIT: u32 = 3;

pub(crate) async fn collect_log_lines(
    log_file: &Path,
    lines: usize,
    grep: &[String],
) -> anyhow::Result<Vec<String>> {
    use tokio::io::AsyncBufReadExt;

    let Some(file) = open_log_file(log_file).await? else {
        return Ok(Vec::new());
    };

    let reader = tokio::io::BufReader::new(file);
    let mut ring = new_tail_ring(lines);

    let mut lines_stream = reader.lines();
    loop {
        match lines_stream.next_line().await {
            Ok(Some(line)) => {
                if lines == 0 {
                    if matches_grep(&line, grep) {
                        ring.push_back(line);
                    }
                } else {
                    ring.push_back(line);
                    if ring.len() > lines {
                        ring.pop_front();
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                return Err(io_error(format!("Failed to read {}", log_file.display()), e).into());
            }
        }
    }

    let mut result: Vec<String> = ring.into_iter().collect();
    if lines > 0 {
        result.retain(|l| matches_grep(l, grep));
    }

    Ok(result)
}

fn matches_grep(line: &str, grep: &[String]) -> bool {
    grep.is_empty() || grep.iter().any(|pat| line.contains(pat))
}

/// 把新读到的字节并入行缓冲，逐个回调完整行（\n 已剥离）。缓冲是字节级的：chunk 边界不保证对齐行/UTF-8 边界，半行（含被拆开的多字节字符）驻留到下一轮拼接，只对完整行做一次
/// lossy 转换——逐 chunk 先 from_utf8_lossy 会把跨 chunk 多字节字符拆成两个 U+FFFD（中文日志必中）。行尾 \r 剥除与 tokio lines()
/// 口径一致。
fn emit_complete_lines(byte_buf: &mut Vec<u8>, chunk: &[u8], mut emit: impl FnMut(&str)) {
    byte_buf.extend_from_slice(chunk);
    while let Some(p) = byte_buf.iter().position(|&b| b == b'\n') {
        let line = String::from_utf8_lossy(&byte_buf[..p]);
        let line = line.strip_suffix('\r').unwrap_or(&line);
        emit(line);
        byte_buf.drain(..=p);
    }
}

pub(crate) async fn print_log(
    log_file: &Path,
    lines: usize,
    grep: &[String],
) -> anyhow::Result<()> {
    use tokio::io::AsyncBufReadExt;

    let Some(file) = open_log_file(log_file).await? else {
        return Ok(());
    };

    let reader = tokio::io::BufReader::new(file);
    let mut ring = new_tail_ring(lines);
    let mut total_lines = 0usize;

    let mut lines_stream = reader.lines();
    loop {
        match lines_stream.next_line().await {
            Ok(Some(line)) => {
                total_lines += 1;
                if lines == 0 {
                    grep_print_line(&line, grep);
                } else {
                    ring.push_back(line);
                    if ring.len() > lines {
                        ring.pop_front();
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                return Err(io_error(format!("Failed to read {}", log_file.display()), e).into());
            }
        }
    }

    if lines > 0 {
        print_tail_truncation_note(lines, total_lines);
        for line in &ring {
            grep_print_line(line, grep);
        }
    }

    Ok(())
}

/// follow 模式：实时跟踪日志。首轮与 follow 共用 chunked read + 行缓冲，消费位置记账 pos：首轮读完从 Start(pos) 严格连续续读（直接从 End(0)
/// 起读会让两步之间新追加的内容重复或丢失），并周期探测 metadata().len() < pos 的截断（日志轮转/重建）。DB 读取连续失败达 FOLLOW_DB_FAIL_LIMIT
/// 即中止（状态库持续不可读时 warn-continue 会退化成高频空转）。
pub(crate) async fn follow_log(
    log_file: &Path,
    state: &StateStore,
    build_id: i64,
    lines: usize,
    grep: &[String],
    cancel_token: Option<&CancellationToken>,
) -> anyhow::Result<()> {
    follow_log_with_probe(log_file, build_id, lines, grep, cancel_token, || {
        state.get_build(build_id)
    })
    .await
}

/// follow_log 的可注入探针版：终态探测由 probe 提供（生产走 StateStore::get_build；测试注入确定性序列）。探针返回语义与 get_build 一致：
/// Ok(Some) 带 phase、Ok(None) 记录消失、Err 计连续失败。
async fn follow_log_with_probe<P, F>(
    log_file: &Path,
    build_id: i64,
    lines: usize,
    grep: &[String],
    cancel_token: Option<&CancellationToken>,
    mut probe: P,
) -> anyhow::Result<()>
where
    P: FnMut() -> F,
    F: std::future::Future<Output = crbs_core::Result<Option<crbs_core::BuildRecord>>>,
{
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let mut file = match tokio::fs::OpenOptions::new()
        .read(true)
        .open(log_file)
        .await
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = log_file.parent() {
                if !tokio::fs::try_exists(parent).await? {
                    return Err(CrbsError::NotFound {
                        message: format!("Log directory does not exist: {}", parent.display()),
                    }
                    .into());
                }
            }
            let file = tokio::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o660)
                .open(log_file)
                .await
                .map_err(|e| {
                    io_error(
                        format!("Failed to open {} for following", log_file.display()),
                        e,
                    )
                })?;

            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(e) = file
                    .set_permissions(std::fs::Permissions::from_mode(0o660))
                    .await
                {
                    tracing::warn!(
                        path = %log_file.display(),
                        error = %e,
                        "failed to chmod build log to 0660 (perms may not be effective)"
                    );
                }
            }
            crbs_core::privilege::chown_to_crbs_group_async(log_file, false, "build log").await;
            file
        }
        Err(e) => {
            return Err(io_error(
                format!("Failed to open {} for following", log_file.display()),
                e,
            )
            .into());
        }
    };

    let mut line_buf: Vec<u8> = Vec::new();
    let mut pos: u64 = 0;

    let mut ring = new_tail_ring(lines);
    let mut total_lines = 0usize;

    let mut chunk = vec![0u8; 4096];
    loop {
        match file.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                pos += n as u64;
                emit_complete_lines(&mut line_buf, &chunk[..n], |line| {
                    total_lines += 1;
                    if lines == 0 {
                        grep_print_line(line, grep);
                    } else {
                        ring.push_back(line.to_string());
                        if ring.len() > lines {
                            ring.pop_front();
                        }
                    }
                });
            }
            Err(e) => {
                return Err(
                    io_error(format!("log follow read failed: {}", log_file.display()), e).into(),
                );
            }
        }
    }
    if lines > 0 {
        print_tail_truncation_note(lines, total_lines);
        for line in &ring {
            grep_print_line(line, grep);
        }
    }

    file.seek(std::io::SeekFrom::Start(pos))
        .await
        .map_err(|e| io_error(format!("Failed to seek in {}", log_file.display()), e))?;

    let mut poll_count = 0u32;

    let mut db_fail_streak = 0u32;
    loop {
        if cancel_token.map(|t| t.is_cancelled()).unwrap_or(false) {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        match file.read(&mut chunk).await {
            Ok(0) => {}
            Ok(n) => {
                pos += n as u64;
                emit_complete_lines(&mut line_buf, &chunk[..n], |line| {
                    grep_print_line(line, grep)
                });
            }
            Err(e) => {
                return Err(
                    io_error(format!("log follow read failed: {}", log_file.display()), e).into(),
                );
            }
        }

        poll_count += 1;
        if poll_count >= 25 {
            poll_count = 0;

            match file.metadata().await {
                Ok(meta) if meta.len() < pos => {
                    tracing::warn!(
                        path = %log_file.display(),
                        consumed = pos,
                        current_len = meta.len(),
                        "log file truncated during follow; resuming from new end"
                    );
                    line_buf.clear();
                    pos = file.seek(std::io::SeekFrom::End(0)).await.map_err(|e| {
                        io_error(
                            format!("Failed to seek to end of {}", log_file.display()),
                            e,
                        )
                    })?;
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        path = %log_file.display(),
                        error = %e,
                        "Failed to stat log file during follow"
                    );
                }
            }

            match probe().await {
                Ok(Some(r)) => {
                    db_fail_streak = 0;
                    if !matches!(
                        r.phase.as_str(),
                        "pending" | "assigned" | "building" | "running"
                    ) {
                        match file.read(&mut chunk).await {
                            Ok(0) => {}
                            Ok(n) => {
                                emit_complete_lines(&mut line_buf, &chunk[..n], |line| {
                                    grep_print_line(line, grep)
                                });
                            }
                            Err(e) => {
                                tracing::warn!(
                                    path = %log_file.display(),
                                    error = %e,
                                    "Failed to drain remaining log on terminal phase"
                                );
                            }
                        }

                        if !line_buf.is_empty() {
                            let rest = String::from_utf8_lossy(&line_buf);
                            grep_print_line(&rest, grep);
                        }
                        break;
                    }
                }
                Ok(None) => {
                    tracing::warn!(build_id = %build_id, "build record vanished during log follow");
                    break;
                }
                Err(e) => {
                    db_fail_streak += 1;
                    if db_fail_streak >= FOLLOW_DB_FAIL_LIMIT {
                        return Err(CrbsError::DatabaseUnavailable {
                            context: format!(
                                "log follow for build {build_id}: {FOLLOW_DB_FAIL_LIMIT} \
                                 consecutive DB read failures; log source unavailable, \
                                 the build itself may still be running"
                            ),
                            error: e.to_string(),
                        }
                        .into());
                    }
                    tracing::warn!(build_id = %build_id, error = %e, "DB read failed during log follow");
                }
            }
        }
    }

    Ok(())
}

/// 编辑器环境变量值（$CRBS_LOG_VIEWER / $EDITOR）按空白拆 (cmd, args)：首词为命令、余词为参数。
fn split_env_command(value: String) -> (String, Vec<String>) {
    let mut parts = value.split_whitespace();
    let cmd = parts.next().unwrap_or(&value).to_string();
    let args: Vec<String> = parts.map(|s| s.to_string()).collect();
    (cmd, args)
}

/// 用编辑器只读打开日志。解析顺序：$CRBS_LOG_VIEWER > $EDITOR > vim -R > vi -R。
pub(crate) async fn open_log_in_editor(log_file: &Path) -> anyhow::Result<()> {
    let join_io = |context: &'static str, e: tokio::task::JoinError| CrbsError::Io {
        context: context.to_string(),
        kind: std::io::ErrorKind::Other,
        detail: e.to_string(),
    };
    let (cmd, args) = if let Ok(viewer) = std::env::var("CRBS_LOG_VIEWER") {
        split_env_command(viewer)
    } else if let Ok(editor) = std::env::var("EDITOR") {
        split_env_command(editor)
    } else {
        let found = tokio::task::spawn_blocking(|| {
            if which::which("vim").is_ok() {
                Some(("vim".to_string(), vec!["-R".to_string()]))
            } else if which::which("vi").is_ok() {
                Some(("vi".to_string(), vec!["-R".to_string()]))
            } else {
                None
            }
        })
        .await
        .map_err(|e| join_io("editor lookup task failed", e))?;
        match found {
            Some((cmd, args)) => (cmd, args),

            None => {
                return Err(CrbsError::ValidationFailed {
                    message: "No editor found. Set $CRBS_LOG_VIEWER or $EDITOR, or install vim/vi."
                        .into(),
                }
                .into())
            }
        }
    };

    let mut tmp = tokio::task::spawn_blocking(tempfile::NamedTempFile::new)
        .await
        .map_err(|e| join_io("spawn_blocking temp log file", e))?
        .map_err(|e| io_error("create temp log file".to_string(), e))?;
    let content = tokio::fs::read_to_string(log_file)
        .await
        .map_err(|e| io_error(format!("Failed to read {}", log_file.display()), e))?;
    let tmp_path = tokio::task::spawn_blocking(move || {
        std::io::Write::write_all(&mut tmp, content.as_bytes()).map(|_| tmp.into_temp_path())
    })
    .await
    .map_err(|e| join_io("spawn_blocking write temp log", e))?
    .map_err(|e| io_error("write temp log".to_string(), e))?;

    let mut command = tokio::process::Command::new(&cmd);
    for arg in &args {
        command.arg(arg);
    }
    command.arg(&tmp_path);

    let status = command
        .status()
        .await
        .map_err(|e| io_error(format!("Failed to spawn editor '{}'", cmd), e))?;

    if !status.success() {
        return Err(
            CrbsError::Internal(format!("Editor exited with code: {:?}", status.code())).into(),
        );
    }

    Ok(())
}

pub(crate) async fn handle_logs(
    args: LogsArgs,
    ctx: &crbs_core::privilege::CallerContext,
    state: Option<&StateStore>,
) -> anyhow::Result<()> {
    if args.format == OutputFormat::Json && (args.follow || args.editor) {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: "--format json cannot be used with --follow or --editor; \
                      use --format text for live tailing or editor view"
                .into(),
        }
        .into());
    }

    if let Some(target) =
        crate::remote::resolve(args.remote.clone(), args.token.clone(), None, args.local).await?
    {
        if args.editor {
            return Err(crbs_core::error::CrbsError::ValidationFailed {
                message: "--editor is not supported for remote logs".into(),
            }
            .into());
        }

        if args.follow && (args.lines.is_some_and(|l| l > 0) || !args.grep.is_empty()) {
            return Err(crbs_core::error::CrbsError::ValidationFailed {
                message: "remote logs --follow does not support -n/--lines or --grep \
                          (the server streams from the current end of the log; drop these \
                          flags or use a local follow)"
                    .to_string(),
            }
            .into());
        }
        return fetch_remote_logs(&target.url, target.token, target.ca_cert, &args).await;
    }

    let LogsArgs {
        task,
        arch,
        follow,
        lines,
        editor,
        grep,
        format,
        ..
    } = args;

    let lines = lines.unwrap_or(DEFAULT_LOG_LINES);

    let state = crate::cmd::require_state_store(
        state,
        "local state store not initialized; did you mean --remote?",
    )?;

    let user_filter = crate::cmd::visible_user_filter(ctx);

    let task_id = state.resolve_task_id(&task, user_filter).await?;
    let children = state.get_builds_by_task_id(task_id).await?;
    let record = select_log_build(task_id, &children, arch.as_deref())?;
    let build_id = record.id;

    let result_dir = match record.result_dir {
        Some(ref d) => std::path::PathBuf::from(d),
        None => {
            if record.phase == "pending" || record.phase == "building" {
                return Err(CrbsError::Conflict {
                    message: format!(
                        "Build {} (task {}) is still {} and has no result directory yet",
                        build_id, task_id, record.phase
                    ),
                }
                .into());
            }
            return Err(CrbsError::NotFound {
                message: format!(
                    "Build {} (task {}) has no result directory (may have been cleaned by GC or never created)",
                    build_id, task_id
                ),
            }
            .into());
        }
    };

    let log_file = result_dir.join("build.log");

    if editor {
        open_log_in_editor(&log_file).await?;
    } else if follow {
        follow_log(&log_file, state, build_id, lines, &grep, None).await?;
    } else if format == OutputFormat::Json {
        let log_lines = collect_log_lines(&log_file, lines, &grep).await?;
        let output = LogLinesOutput {
            command: "logs",
            task_id,
            build_id: Some(build_id),
            arch: record.arch.clone(),
            log_file: Some(log_file.display().to_string()),
            lines: log_lines,
        };
        format.print(&output)?;
    } else {
        if !tokio::fs::try_exists(&log_file).await.unwrap_or(false) {
            eprintln!(
                "(build.log not found in {}; the build may not have started writing a log)",
                result_dir.display()
            );
        }
        print_log(&log_file, lines, &grep).await?;
    }

    Ok(())
}

fn select_build_by_arch<'a, T>(
    task_id: i64,
    builds: &'a [T],
    arch: Option<&str>,
    arch_of: impl Fn(&T) -> &str,
) -> anyhow::Result<&'a T> {
    match builds.len() {
        0 => Err(CrbsError::NotFound {
            message: format!("Task {task_id} has no child builds"),
        }
        .into()),
        1 => Ok(&builds[0]),
        _ => {
            let requested = arch.unwrap_or("");
            builds
                .iter()
                .find(|b| arch_of(b) == requested)
                .ok_or_else(|| {
                    let arches: Vec<&str> = builds.iter().map(arch_of).collect();
                    CrbsError::ValidationFailed {
                        message: format!(
                            "Task {} has multiple architectures; specify one of: {}",
                            task_id,
                            arches.join(", ")
                        ),
                    }
                })
                .map_err(Into::into)
        }
    }
}

fn select_log_build<'a>(
    task_id: i64,
    children: &'a [crbs_core::BuildRecord],
    arch: Option<&str>,
) -> anyhow::Result<&'a crbs_core::BuildRecord> {
    select_build_by_arch(task_id, children, arch, |b| b.arch.as_deref().unwrap_or(""))
}

async fn remote_logs_status_error(
    resp: reqwest::Response,
    status: reqwest::StatusCode,
) -> anyhow::Error {
    let body = resp
        .text()
        .await
        .unwrap_or_else(|e| format!("<failed to read body: {}>", e));
    crate::remote::http_status_error("remote logs request", status, &body).into()
}

async fn fetch_remote_logs(
    server_url: &str,
    token: Option<String>,
    ca_cert: Option<PathBuf>,
    args: &LogsArgs,
) -> anyhow::Result<()> {
    let base_url = crate::remote::normalize_base_url(server_url)?;
    let target = crate::remote::RemoteTarget::new(base_url.clone(), token, ca_cert);
    let client = target.client().await?;

    let task_id = crate::cmd::parse_task_id(&args.task)?;
    let detail = crate::remote::fetch_task_record(&target, task_id, None).await?;

    let build = select_build_by_arch(task_id, &detail.builds, args.arch.as_deref(), |b| {
        b.arch.as_str()
    })?;

    let url = format!("{}/api/v1/builds/{}/logs", base_url, build.id);

    if args.follow {
        for _ in 0..60 {
            let resp = client
                .get(&url)
                .timeout(crate::remote::LONG_BODY_TIMEOUT)
                .send()
                .await
                .map_err(|e| CrbsError::Network {
                    message: format!("request build log stream: {e}"),
                })?;
            match resp.status() {
                reqwest::StatusCode::NOT_FOUND => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                status if !status.is_success() => {
                    return Err(remote_logs_status_error(resp, status).await);
                }
                _ => {
                    crate::remote::stream_response_to_stdout(resp, None).await?;
                    return Ok(());
                }
            }
        }

        return Err(crbs_core::error::CrbsError::NotFound {
            message: "Remote build log not available after 60s".to_string(),
        }
        .into());
    }

    let resp = client
        .get(&url)
        .query(&[("offset", "0")])
        .send()
        .await
        .map_err(|e| CrbsError::Network {
            message: format!("request build log: {e}"),
        })?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(crbs_core::error::CrbsError::NotFound {
            message: "Remote build log not found".to_string(),
        }
        .into());
    }
    if !status.is_success() {
        return Err(remote_logs_status_error(resp, status).await);
    }

    let text = resp.text().await.map_err(|e| CrbsError::Network {
        message: format!("read build log body: {e}"),
    })?;

    let lines = args.lines.unwrap_or(DEFAULT_LOG_LINES);
    let mut log_lines: Vec<&str> = text.lines().collect();
    if lines > 0 && log_lines.len() > lines {
        let skip = log_lines.len() - lines;
        log_lines = log_lines.into_iter().skip(skip).collect();
    }
    let filtered: Vec<String> = log_lines
        .into_iter()
        .filter(|l| args.grep.is_empty() || args.grep.iter().any(|pat| l.contains(pat)))
        .map(|l| l.to_string())
        .collect();

    if args.format == OutputFormat::Json {
        let output = LogLinesOutput {
            command: "logs",
            task_id,
            build_id: Some(build.id),
            arch: Some(build.arch.clone()),
            log_file: None,
            lines: filtered,
        };
        args.format.print(&output)?;
    } else {
        for line in filtered {
            println!("{}", line);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_record(id: i64, arch: Option<&str>) -> crbs_core::BuildRecord {
        crbs_core::BuildRecord {
            id,
            product: "fedora".into(),
            pkg_name: "hello".into(),
            name: "hello".into(),
            version: "1.0".into(),
            release: "1".into(),
            phase: "succeeded".into(),
            result_dir: None,
            srpm_path: None,
            started_at: None,
            completed_at: None,
            duration: None,
            layer_digest: None,
            base_os_digest: None,
            backend: Some("chroot".into()),
            user: "tester".into(),
            user_id: None,
            crbs_pid: None,
            rpms: Vec::new(),
            signed: false,
            priority: crbs_core::types::PRIORITY_DEFAULT,
            arch: arch.map(String::from),
            task_id: Some(1),
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

    #[test]
    fn select_log_build_empty_children_bails() {
        let err = select_log_build(7, &[], None).unwrap_err();
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::NotFound { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::USAGE
        );
        assert!(
            format!("{ce}").contains("Task 7 has no child builds"),
            "msg must be preserved verbatim: {ce}"
        );
    }

    #[test]
    fn select_log_build_single_child_ignores_arch() {
        let children = vec![build_record(11, Some("x86_64"))];

        let selected = select_log_build(7, &children, Some("aarch64")).unwrap();
        assert_eq!(selected.id, 11);
    }

    #[test]
    fn select_log_build_multi_requires_arch() {
        let children = vec![
            build_record(11, Some("x86_64")),
            build_record(12, Some("aarch64")),
        ];
        let err = select_log_build(7, &children, None).unwrap_err();
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::ValidationFailed { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::USAGE
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("multiple architectures") && msg.contains("x86_64"),
            "unexpected: {msg}"
        );

        let selected = select_log_build(7, &children, Some("aarch64")).unwrap();
        assert_eq!(selected.id, 12);

        let err = select_log_build(7, &children, Some("riscv64")).unwrap_err();
        assert!(format!("{err}").contains("multiple architectures"));
    }

    async fn tmp_store() -> (tempfile::TempDir, StateStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();
        (tmp, store)
    }

    async fn seed_task_with_build(
        store: &StateStore,
        arch: Option<&str>,
        result_dir: Option<String>,
    ) -> (i64, i64) {
        let task_id = store
            .insert_task(crbs_core::TaskInsert {
                product: "fedora",
                pkg_name: "hello",
                user: "tester",
                phase: "succeeded",
                ..Default::default()
            })
            .await
            .unwrap();
        let build_id = store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "succeeded",
                result_dir: result_dir.as_deref(),
                backend: "chroot",
                user: "tester",
                arch,
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        (task_id, build_id)
    }

    fn tester_ctx() -> crbs_core::privilege::CallerContext {
        crbs_core::privilege::CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: "tester".to_string(),
            },
            false,
        )
    }

    fn logs_args(task: String, format: OutputFormat) -> LogsArgs {
        LogsArgs {
            task,
            arch: None,
            follow: false,
            lines: Some(0),
            editor: false,
            grep: Vec::new(),
            format,
            remote: None,
            token: None,
            local: true,
        }
    }

    #[tokio::test]
    async fn handle_logs_local_resolves_task_id() {
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());

        store
            .insert_task(crbs_core::TaskInsert {
                product: "fedora",
                pkg_name: "pad",
                user: "tester",
                ..Default::default()
            })
            .await
            .unwrap();
        let result_dir = _tmp.path().join("result");
        tokio::fs::create_dir_all(&result_dir).await.unwrap();
        tokio::fs::write(result_dir.join("build.log"), "line1\nline2\n")
            .await
            .unwrap();
        let (task_id, build_id) = seed_task_with_build(
            &store,
            Some("x86_64"),
            Some(result_dir.display().to_string()),
        )
        .await;
        assert_ne!(task_id, build_id, "fixture requires disjoint ids");

        handle_logs(
            logs_args(task_id.to_string(), OutputFormat::Text),
            &tester_ctx(),
            Some(&store),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn handle_logs_local_not_found_shape() {
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        let err = handle_logs(
            logs_args("424242".to_string(), OutputFormat::Text),
            &tester_ctx(),
            Some(&store),
        )
        .await
        .expect_err("missing task must fail");
        assert!(
            err.to_string().contains("task 424242 not found"),
            "unexpected message: {err}"
        );
    }

    #[tokio::test]
    async fn collect_log_lines_returns_all_when_lines_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("build.log");
        tokio::fs::write(&path, "one\ntwo\nthree\n").await.unwrap();

        let lines = collect_log_lines(&path, 0, &[]).await.unwrap();
        assert_eq!(lines, vec!["one", "two", "three"]);
    }

    #[tokio::test]
    async fn collect_log_lines_tails_last_n() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("build.log");
        tokio::fs::write(&path, "1\n2\n3\n4\n5\n").await.unwrap();

        let lines = collect_log_lines(&path, 2, &[]).await.unwrap();
        assert_eq!(lines, vec!["4", "5"]);
    }

    #[tokio::test]
    async fn collect_log_lines_grep_filter() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("build.log");
        tokio::fs::write(&path, "alpha\nbeta\ngamma\n")
            .await
            .unwrap();

        let lines = collect_log_lines(&path, 0, &["b".into(), "g".into()])
            .await
            .unwrap();
        assert_eq!(lines, vec!["beta", "gamma"]);
    }

    #[tokio::test]
    async fn collect_log_lines_missing_file_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("not-exist.log");

        let lines = collect_log_lines(&path, 10, &[]).await.unwrap();
        assert!(lines.is_empty());
    }

    #[test]
    fn matches_grep_empty_patterns_returns_true() {
        assert!(matches_grep("anything", &[]));
    }

    #[test]
    fn matches_grep_any_pattern_matches() {
        assert!(matches_grep(
            "error: failed",
            &["error".into(), "warn".into()]
        ));
        assert!(!matches_grep("info: ok", &["error".into(), "warn".into()]));
    }

    #[test]
    fn emit_complete_lines_handles_chunk_boundaries() {
        let mut buf: Vec<u8> = Vec::new();
        let mut out = Vec::new();
        for chunk in ["par".as_bytes(), b"tial\nli", b"ne2\nno-eol-yet"] {
            emit_complete_lines(&mut buf, chunk, |l| out.push(l.to_string()));
        }
        assert_eq!(out, vec!["partial", "line2"]);
        assert_eq!(buf, b"no-eol-yet");
    }

    #[test]
    fn emit_complete_lines_multibyte_across_chunk_boundaries() {
        let text = "开始构建 hello-1.0\n构建失败：依赖缺失\nno-eol";
        let mut buf: Vec<u8> = Vec::new();
        let mut out = Vec::new();
        for b in text.as_bytes() {
            emit_complete_lines(&mut buf, &[*b], |l| out.push(l.to_string()));
        }
        assert_eq!(out, vec!["开始构建 hello-1.0", "构建失败：依赖缺失"]);
        assert_eq!(buf, b"no-eol");
        assert!(
            !out.iter().any(|l| l.contains('\u{FFFD}')),
            "no replacement char allowed: {out:?}"
        );

        let prefix = "x".repeat(4095);
        let line = format!("{prefix}开始\n");
        let bytes = line.as_bytes();
        let mut buf: Vec<u8> = Vec::new();
        let mut out = Vec::new();
        emit_complete_lines(&mut buf, &bytes[..4096], |l| out.push(l.to_string()));
        emit_complete_lines(&mut buf, &bytes[4096..], |l| out.push(l.to_string()));
        assert_eq!(out.len(), 1);
        assert!(out[0].ends_with("开始"), "unexpected: {}", out[0]);
        assert!(!out[0].contains('\u{FFFD}'), "unexpected: {}", out[0]);
    }

    #[test]
    fn emit_complete_lines_strips_trailing_cr_like_tokio_lines() {
        let mut buf: Vec<u8> = Vec::new();
        let mut out = Vec::new();
        emit_complete_lines(&mut buf, b"crlf line\r\nlf line\ntrailing\r", |l| {
            out.push(l.to_string())
        });
        assert_eq!(out, vec!["crlf line", "lf line"]);

        assert_eq!(buf, b"trailing\r");
    }

    #[tokio::test]
    async fn follow_log_resumes_after_truncation_and_exits_on_terminal() {
        let (tmp, store) = tmp_store().await;
        let result_dir = tmp.path().join("result");
        tokio::fs::create_dir_all(&result_dir).await.unwrap();
        let log = result_dir.join("build.log");
        tokio::fs::write(&log, "old-line-1\nold-line-2\n")
            .await
            .unwrap();
        let (_task_id, build_id) = seed_task_with_build(
            &store,
            Some("x86_64"),
            Some(result_dir.display().to_string()),
        )
        .await;

        store.get_build(build_id).await.unwrap();
        tokio::time::pause();

        let log_for_task = log.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1000)).await;
            tokio::fs::write(&log_for_task, "new-content\n")
                .await
                .unwrap();
        });

        follow_log(&log, &store, build_id, 0, &[], None)
            .await
            .unwrap();
        let content = tokio::fs::read_to_string(&log).await.unwrap();
        assert_eq!(content, "new-content\n");
    }

    #[tokio::test]
    async fn follow_log_reads_readonly_file() {
        if unsafe { nix::libc::geteuid() } == 0 {
            eprintln!("skipped: running as root, 0444 file is still writable-readable");
            return;
        }
        let (tmp, store) = tmp_store().await;
        let result_dir = tmp.path().join("result");
        tokio::fs::create_dir_all(&result_dir).await.unwrap();
        let log = result_dir.join("build.log");
        tokio::fs::write(&log, "readonly-line\n").await.unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o444))
                .await
                .unwrap();
        }
        let (_task_id, build_id) = seed_task_with_build(
            &store,
            Some("x86_64"),
            Some(result_dir.display().to_string()),
        )
        .await;

        let record = store.get_build(build_id).await.unwrap().unwrap();
        tokio::time::pause();
        // 探针注入确定性终态记录：暂停时钟下 sqlx 池 acquire 的超时定时器会被
        // 自动推进秒触，真实池探测存在偶发超时；本测试只覆盖文件打开路径。
        follow_log_with_probe(&log, build_id, 0, &[], None, || {
            let record = record.clone();
            async move { Ok(Some(record)) }
        })
        .await
        .expect("read-only existing log must be followable");
    }

    #[tokio::test]
    async fn follow_log_aborts_after_consecutive_db_failures() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("db-fail.log");
        tokio::fs::write(&log, "seed\n").await.unwrap();

        tokio::time::pause();
        let err = follow_log_with_probe(&log, 7, 0, &[], None, || async {
            Err(crbs_core::error::CrbsError::Io {
                context: "injected probe failure".into(),
                kind: std::io::ErrorKind::Other,
                detail: String::new(),
            })
        })
        .await
        .expect_err("consecutive DB failures must abort the follow");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        match ce {
            crbs_core::error::CrbsError::DatabaseUnavailable { context, .. } => {
                assert!(
                    context.contains("log source unavailable")
                        && context.contains("may still be running"),
                    "message must not imply build failure: {context}"
                );
            }
            other => panic!("unexpected variant: {other:?}"),
        }

        let attempts = std::cell::Cell::new(0u32);
        follow_log_with_probe(&log, 7, 0, &[], None, || {
            let n = attempts.get();
            attempts.set(n + 1);
            async move {
                if n % 3 != 2 {
                    Err(crbs_core::error::CrbsError::Io {
                        context: "transient".into(),
                        kind: std::io::ErrorKind::Other,
                        detail: String::new(),
                    })
                } else {
                    Ok(None::<crbs_core::BuildRecord>)
                }
            }
        })
        .await
        .expect("alternating failures must not accumulate to the limit");
    }

    #[tokio::test]
    async fn follow_log_creates_missing_log_with_owner_rw_and_no_world_access() {
        let (tmp, store) = tmp_store().await;
        let result_dir = tmp.path().join("result");
        tokio::fs::create_dir_all(&result_dir).await.unwrap();
        let log = result_dir.join("not-yet.log");
        let (_task_id, build_id) = seed_task_with_build(
            &store,
            Some("x86_64"),
            Some(result_dir.display().to_string()),
        )
        .await;

        tokio::time::pause();
        follow_log(&log, &store, build_id, 0, &[], None)
            .await
            .expect("missing log with existing parent must be created");

        use std::os::unix::fs::PermissionsExt;
        let mode = tokio::fs::metadata(&log)
            .await
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o007, 0, "no world access allowed: {mode:o}");
        assert_ne!(mode & 0o400, 0, "owner must be able to read: {mode:o}");
    }

    #[tokio::test]
    async fn follow_log_missing_parent_dir_keeps_error_message() {
        let (tmp, store) = tmp_store().await;
        let log = tmp.path().join("no-such-dir").join("build.log");
        let (_task_id, build_id) = seed_task_with_build(&store, Some("x86_64"), None).await;

        let err = follow_log(&log, &store, build_id, 0, &[], None)
            .await
            .expect_err("missing parent dir must fail");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::NotFound { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::USAGE
        );
        assert!(
            format!("{err:#}").contains("Log directory does not exist"),
            "unexpected message: {err:#}"
        );
    }

    #[tokio::test]
    async fn collect_log_lines_read_failure_maps_to_io_environment_6() {
        let tmp = tempfile::tempdir().unwrap();
        let err = collect_log_lines(tmp.path(), 0, &[])
            .await
            .expect_err("directory read must fail");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::Io { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::ENVIRONMENT
        );
        assert!(
            format!("{ce}").contains("Failed to read"),
            "msg must be preserved verbatim: {ce}"
        );
    }

    #[tokio::test]
    async fn handle_logs_missing_state_store_is_validation_failed_exit_4() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = crate::test_support::EnvGuard::new(tmp.path());
        let err = handle_logs(
            logs_args("1".to_string(), OutputFormat::Text),
            &tester_ctx(),
            None,
        )
        .await
        .expect_err("missing state store must fail");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::ValidationFailed { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::USAGE
        );
        assert!(
            format!("{ce}").contains("local state store not initialized; did you mean --remote?"),
            "msg must be preserved verbatim: {ce}"
        );
    }

    #[tokio::test]
    async fn handle_logs_result_dir_missing_maps_by_phase() {
        let (tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(tmp.path());

        let pending_task = store
            .insert_task(crbs_core::TaskInsert {
                product: "fedora",
                pkg_name: "hello",
                user: "tester",
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                backend: "chroot",
                user: "tester",
                arch: Some("x86_64"),
                task_id: Some(pending_task),
                ..Default::default()
            })
            .await
            .unwrap();
        let err = handle_logs(
            logs_args(pending_task.to_string(), OutputFormat::Text),
            &tester_ctx(),
            Some(&store),
        )
        .await
        .expect_err("pending build without result dir must fail");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::Conflict { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::USAGE
        );
        assert!(
            format!("{ce}").contains("has no result directory yet"),
            "msg must be preserved verbatim: {ce}"
        );

        let (done_task, _) = seed_task_with_build(&store, Some("x86_64"), None).await;
        let err = handle_logs(
            logs_args(done_task.to_string(), OutputFormat::Text),
            &tester_ctx(),
            Some(&store),
        )
        .await
        .expect_err("terminal build without result dir must fail");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::NotFound { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::USAGE
        );
        assert!(
            format!("{ce}").contains("may have been cleaned by GC or never created"),
            "msg must be preserved verbatim: {ce}"
        );
    }

    #[tokio::test]
    async fn remote_follow_with_tail_or_grep_is_rejected() {
        let (tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(tmp.path());
        let mut args = logs_args("1".to_string(), OutputFormat::Text);
        args.remote = Some("http://127.0.0.1:1".to_string());
        args.local = false;
        args.follow = true;
        args.lines = Some(10);
        let err = handle_logs(args, &tester_ctx(), Some(&store))
            .await
            .expect_err("remote follow with -n must be rejected");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("should be a CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::ValidationFailed { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_core::exit_code::crbs_error_exit_code(ce), 4);
    }

    #[tokio::test]
    async fn remote_follow_without_explicit_lines_is_not_rejected() {
        let (tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(tmp.path());
        let mut args = logs_args("1".to_string(), OutputFormat::Text);
        args.remote = Some("http://127.0.0.1:1".to_string());
        args.local = false;
        args.follow = true;
        args.lines = None;
        let err = handle_logs(args, &tester_ctx(), Some(&store))
            .await
            .expect_err("unreachable remote must fail");
        assert!(
            err.downcast_ref::<crbs_core::error::CrbsError>()
                .is_none_or(|ce| {
                    !matches!(ce, crbs_core::error::CrbsError::ValidationFailed { .. })
                }),
            "must not be rejected as ValidationFailed, got: {err:#}"
        );
    }

    #[tokio::test]
    async fn remote_follow_with_explicit_zero_lines_is_not_rejected() {
        let (tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(tmp.path());
        let mut args = logs_args("1".to_string(), OutputFormat::Text);
        args.remote = Some("http://127.0.0.1:1".to_string());
        args.local = false;
        args.follow = true;
        args.lines = Some(0);
        let err = handle_logs(args, &tester_ctx(), Some(&store))
            .await
            .expect_err("unreachable remote must fail");
        assert!(
            err.downcast_ref::<crbs_core::error::CrbsError>()
                .is_none_or(|ce| {
                    !matches!(ce, crbs_core::error::CrbsError::ValidationFailed { .. })
                }),
            "must not be rejected as ValidationFailed, got: {err:#}"
        );
    }

    #[tokio::test]
    async fn json_format_with_follow_is_validation_failed_exit_4() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = crate::test_support::EnvGuard::new(tmp.path());
        let mut args = logs_args("1".to_string(), OutputFormat::Json);
        args.follow = true;

        let err = handle_logs(args, &tester_ctx(), None)
            .await
            .expect_err("json + follow must be rejected");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::ValidationFailed { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_core::exit_code::crbs_error_exit_code(ce), 4);
        assert!(
            format!("{ce}").contains("--format json cannot be used with"),
            "msg: {ce}"
        );
    }

    #[tokio::test]
    async fn remote_editor_is_validation_failed_exit_4() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = crate::test_support::EnvGuard::new(tmp.path());
        let mut args = logs_args("1".to_string(), OutputFormat::Text);
        args.editor = true;
        args.remote = Some("http://127.0.0.1:1".to_string());
        args.local = false;
        let err = handle_logs(args, &tester_ctx(), None)
            .await
            .expect_err("remote --editor must be rejected");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::ValidationFailed { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_core::exit_code::crbs_error_exit_code(ce), 4);
        assert!(
            format!("{ce}").contains("--editor is not supported for remote logs"),
            "msg: {ce}"
        );
    }

    #[tokio::test]
    async fn fetch_remote_logs_maps_transport_error_to_network_exit_6() {
        for follow in [false, true] {
            let server = wiremock::MockServer::start().await;
            let detail = crate::remote::TaskDetailResponse {
                task: crbs_core::TaskRecord {
                    id: 1,
                    product: "mydist".into(),
                    pkg_name: "hello".into(),
                    name: "hello".into(),
                    version: "1.0".into(),
                    release: "1".into(),
                    user: "tester".into(),
                    phase: "succeeded".into(),
                    priority: Default::default(),
                    srpm_path: None,
                    result_dir: None,
                    submitted_at: None,
                    completed_at: None,
                    duration: None,
                    pkg_names: Vec::new(),
                },
                builds: vec![crbs_core::types::ChildBuildSummary {
                    id: 7,
                    arch: "x86_64".into(),
                    phase: "succeeded".into(),
                    result_dir: None,
                    started_at: None,
                    duration: None,
                    worker: None,
                }],
                lineage: None,
                labels: Vec::new(),
            };
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/api/v1/tasks/1"))
                .respond_with(
                    wiremock::ResponseTemplate::new(200)
                        .set_body_string(serde_json::to_string(&detail).unwrap()),
                )
                .mount(&server)
                .await;
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/api/v1/builds/7/logs"))
                .respond_with(
                    wiremock::ResponseTemplate::new(302)
                        .insert_header("Location", "http://127.0.0.1:1"),
                )
                .mount(&server)
                .await;

            let mut args = logs_args("1".to_string(), OutputFormat::Text);
            args.follow = follow;
            let err = fetch_remote_logs(&server.uri(), None, None, &args)
                .await
                .expect_err("redirect to dead port must fail");
            let ce = err
                .downcast_ref::<crbs_core::error::CrbsError>()
                .expect("must surface as CrbsError");
            assert!(
                matches!(ce, crbs_core::error::CrbsError::Network { .. }),
                "follow={follow}, unexpected variant: {ce:?}"
            );
            assert_eq!(
                crbs_core::exit_code::crbs_error_exit_code(ce),
                6,
                "follow={follow}"
            );

            assert_eq!(ce.code(), "network_error", "follow={follow}");
        }
    }
}
