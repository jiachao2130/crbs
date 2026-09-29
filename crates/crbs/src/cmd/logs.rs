// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! logs 子命令：日志读取、过滤、跟随与编辑器查看。

use crate::cli::{CommandOutput, OutputFormat};
use crbs_core::error::CrbsError;
use crbs_core::StateStore;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// logs 命令参数（由 CLI 解析后传入）。
pub(crate) struct LogsArgs {
    pub task: String,
    pub arch: Option<String>,
    pub follow: bool,
    /// `None` = 未传 `-n`（回落 [`DEFAULT_LOG_LINES`]），`Some(0)` = 全量；远程 `-f` 只拒绝显式 `-n`。
    pub lines: Option<usize>,
    pub editor: bool,
    pub grep: Vec<String>,
    pub format: OutputFormat,
    pub remote: Option<String>,
    pub token: Option<String>,
    pub local: bool,
}

/// `-n` 未传时的 tail 行数。
pub(crate) const DEFAULT_LOG_LINES: usize = 50;

/// 日志行统一输出（本地 / 远程共享 JSON 结构）。
#[derive(serde::Serialize)]
struct LogLinesOutput {
    command: &'static str,
    task_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    build_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    arch: Option<String>,
    /// 键恒存在（schema 稳定性）：远程为 null，本地为日志文件路径。
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

/// 打印一行，若 grep 非空则只打印匹配的行。
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

/// 本地日志文件 IO 失败统一产出 `CrbsError::Io`（kind 保真，ENVIRONMENT=6）。
fn io_error(context: String, e: std::io::Error) -> CrbsError {
    CrbsError::Io {
        context,
        kind: e.kind(),
        detail: e.to_string(),
    }
}

/// 预分配上限：无上界的巨值 `-n` 直接进 `VecDeque::with_capacity` 会一次性巨额分配（自我 DoS）；
/// 环形缓冲仍按真实 `lines` 语义滚动。
const MAX_TAIL_CAPACITY_LINES: usize = 1_000_000;

/// tail 环形缓冲初始化（collect / print / follow 首轮共用）：lines > 0 按其
/// 预分配（上限 [`MAX_TAIL_CAPACITY_LINES`]），0 = 全量模式无需环形。
fn new_tail_ring(lines: usize) -> std::collections::VecDeque<String> {
    if lines > 0 {
        std::collections::VecDeque::with_capacity(lines.min(MAX_TAIL_CAPACITY_LINES))
    } else {
        std::collections::VecDeque::new()
    }
}

/// tail 截断提示（print_log 与 follow 首轮共用，文案钉死）。
fn print_tail_truncation_note(lines: usize, total_lines: usize) {
    if total_lines > lines {
        eprintln!(
            "... (showing last {} of {} lines, use -n 0 for complete log)\n",
            lines, total_lines
        );
    }
}

/// follow 轮询的连续 DB 读失败上限（与 http_retry 常规重试预算同量级）：
/// 超限视为日志源持续不可用，中止 follow 上抛 DatabaseUnavailable。
const FOLLOW_DB_FAIL_LIMIT: u32 = 3;

/// 收集日志行：tail（lines > 0）或全量（lines = 0）+ grep 过滤，返回过滤后的行列表。
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
        // 读错误不静默当 EOF（对齐 open_log_file 口径）：IO 故障吞掉会让 tail/grep 结果"正常但少了内容"。
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

/// 把新读到的字节并入行缓冲，逐个回调已完整的行（`\n` 已剥离）。缓冲是**字节级**的：
/// chunk 边界不保证对齐行/UTF-8 边界，半行（含被拆开的多字节字符）驻留到下一轮拼接，只对完整行
/// 做一次 lossy 转换——逐 chunk 先 `from_utf8_lossy` 会把跨 chunk 多字节字符拆成两个 U+FFFD
/// （中文日志必中）。行尾 `\r` 剥除与 tokio `lines()` 口径一致；follow 首轮 / poll 增量 / 终态补尾共用。
fn emit_complete_lines(byte_buf: &mut Vec<u8>, chunk: &[u8], mut emit: impl FnMut(&str)) {
    byte_buf.extend_from_slice(chunk);
    while let Some(p) = byte_buf.iter().position(|&b| b == b'\n') {
        let line = String::from_utf8_lossy(&byte_buf[..p]);
        let line = line.strip_suffix('\r').unwrap_or(&line);
        emit(line);
        byte_buf.drain(..=p);
    }
}

/// 打印日志：tail（lines > 0）或全量（lines = 0）+ grep 过滤，环形缓冲只保留最后 N 行。
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

/// follow 模式：实时跟踪日志，支持 tail 截取已有内容 + grep 过滤。
/// 首轮与 follow 共用 chunked read + 行缓冲，消费位置记账 `pos`：首轮读完从 `Start(pos)` 严格
/// 连续续读（直接从 `End(0)` 起读会让两步之间新追加的内容重复或丢失），并周期探测
/// `metadata().len() < pos` 的截断（日志轮转/重建）。
/// `build_id` 是日志属主的子构建 id（日志归属 build；CLI 入参为 task id，
/// 由调用方解析到具体子构建后传入）。
/// DB 读取连续失败达 [`FOLLOW_DB_FAIL_LIMIT`] 即中止（状态库持续不可读时
/// warn-continue 会退化成高频空转）。
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

/// [`follow_log`] 的可注入探针版：终态探测由 `probe` 提供（生产走
/// `StateStore::get_build`；测试注入确定性序列，回归钉 DB 连续失败中止——
/// crbs 无 sqlx 直连依赖，造不出真 DB 故障）。探针返回语义与 get_build 一致：
/// `Ok(Some)` 带 phase、`Ok(None)` 记录消失、`Err` 计连续失败。
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

    // 只读优先：文件已存在时直接读打开（follow 全程只读 + seek，0444 只读日志也能跟）；
    // 只有文件尚不存在才落创建分支，其余打开错误如实上抛。
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
            // 本分支只在文件缺失后进入，属本进程新建（owner 必为自己）；NotFound→create
            // 竞态下可能打开他者文件，set_permissions 届时 EPERM 仅 warn。`.mode(0o660)` 受
            // umask 削减，创建后显式 set_permissions 收口（对齐 server/mod.rs open_pidfile_new）；失败 warn。
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

    // 首轮流式输出已有内容：tail 模式用环形缓冲只保留最后 N 行（文案与 print_log 一致），
    // 全量模式逐行输出；pos += n 记账消费位置。
    let mut ring = new_tail_ring(lines);
    let mut total_lines = 0usize;
    // 读缓冲提出循环外复用（首轮 / poll / 终态 drain 共用）；read 只消费本次写入的前 n 字节，残留不影响行为。
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

    // follow 从首轮消费位置继续（而非 End(0)）：首轮读到此处之间新追加的内容由后续 poll 读出，严格连续不重不漏。
    file.seek(std::io::SeekFrom::Start(pos))
        .await
        .map_err(|e| io_error(format!("Failed to seek in {}", log_file.display()), e))?;

    let mut poll_count = 0u32;
    // 连续 DB 读失败计数：达到上限即中止 follow（[`FOLLOW_DB_FAIL_LIMIT`]）。
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

        // 每 25 次 poll（约 5 秒）查一次 DB，避免频繁查询
        poll_count += 1;
        if poll_count >= 25 {
            poll_count = 0;
            // 截断检测：日志被轮转/重建时 `len < pos`，继续按旧 offset 读只会永远 EOF——
            // 跳到当前末尾重新跟随；不回退重放旧 offset（被截断的历史已不可恢复）。
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
            // pending/assigned 也算进行中：排队阶段的 `crbs logs -f` 不能在 5s 后静默退出；DB 读失败 warn 后继续。
            // 白名单 = crbs_core::types::build_phase_is_terminal 的补集（工作区唯一终态谓词），running 为历史兼容冗余；
            // 新增 phase 必须两处同步，见 crbs-core types.rs 的穷举护栏测试。
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
                        // 输出未完成的最后一行（无换行符结尾；字节缓冲做一次整体 lossy 转换）
                        if !line_buf.is_empty() {
                            let rest = String::from_utf8_lossy(&line_buf);
                            grep_print_line(&rest, grep);
                        }
                        break;
                    }
                }
                Ok(None) => {
                    // 记录消失（被清理）：终止跟随，避免无限轮询。
                    tracing::warn!(build_id = %build_id, "build record vanished during log follow");
                    break;
                }
                Err(e) => {
                    db_fail_streak += 1;
                    if db_fail_streak >= FOLLOW_DB_FAIL_LIMIT {
                        // 连续失败达上限即中止：状态库持续不可读时 warn-continue 会退化成
                        // 高频空转（暂停时钟下 sleep 零成本，直接 100% CPU）。文案明确
                        // 日志源不可用而非构建失败——构建可能仍在跑。
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

/// 编辑器环境变量值（$CRBS_LOG_VIEWER / $EDITOR）按空白拆 (cmd, args)：首词
/// 为命令、余词为参数；无词（空串/纯空白）回退整串作命令名。
fn split_env_command(value: String) -> (String, Vec<String>) {
    let mut parts = value.split_whitespace();
    let cmd = parts.next().unwrap_or(&value).to_string();
    let args: Vec<String> = parts.map(|s| s.to_string()).collect();
    (cmd, args)
}

/// 用编辑器只读打开日志。
/// 解析顺序：$CRBS_LOG_VIEWER > $EDITOR > vim -R > vi -R
pub(crate) async fn open_log_in_editor(log_file: &Path) -> anyhow::Result<()> {
    // spawn_blocking join 失败（panic/取消）属运行时故障，与文件 IO 同归 `CrbsError::Io`（ENVIRONMENT=6）。
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
        // which 是同步 PATH 扫描（逐目录 stat），包进 spawn_blocking。
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
            // 编辑器缺失属用户环境配置问题——ValidationFailed（USAGE=4），不落 INTERNAL(1)。
            None => {
                return Err(CrbsError::ValidationFailed {
                    message: "No editor found. Set $CRBS_LOG_VIEWER or $EDITOR, or install vim/vi."
                        .into(),
                }
                .into())
            }
        }
    };

    // 拷贝到临时文件（tempfile 默认 0600），避免编辑器修改原日志
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

    // 权限保持 tempfile 默认 0600：共享 /tmp 下放开 0644 会让所有本地用户可读构建日志。

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
        // 外部编辑器自身退出非零：无干净归属族，显式 Internal(1)（裁定而非遗漏）。
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
        // 参数互斥属 USAGE=4（裸 bail 会落 INTERNAL(1)），消息附出路：实时跟踪须退回 text 格式。
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: "--format json cannot be used with --follow or --editor; \
                      use --format text for live tailing or editor view"
                .into(),
        }
        .into());
    }

    // 远程日志：--local 优先强制本地；否则按 --remote 或 remote.default 解析。
    if let Some(target) =
        crate::remote::resolve(args.remote.clone(), args.token.clone(), None, args.local).await?
    {
        if args.editor {
            return Err(crbs_core::error::CrbsError::ValidationFailed {
                message: "--editor is not supported for remote logs".into(),
            }
            .into());
        }
        // 服务端 follow 端点只有"从当前 EOF 起流式推送"一种语义（无 tail-lines 参数），客户端无法
        // 可靠补齐 -n/--grep 的首轮语义，显式拒绝而非静默忽略；只认用户显式传参（clap 不注入
        // 默认 50），裸 `--remote <task> -f` 不受影响，-n 0 = 全量也放行（同本地 follow 的 lines=0）。
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
    // 本地展示路径在此回落默认 tail 行数（远程 follow 的显式 -n 判定已在上面用 Option 完成）。
    let lines = lines.unwrap_or(DEFAULT_LOG_LINES);

    // 本地模式需要 StateStore：调用方式误用——ValidationFailed（USAGE=4）。
    let state = crate::cmd::require_state_store(
        state,
        "local state store not initialized; did you mean --remote?",
    )?;

    let user_filter = crate::cmd::visible_user_filter(ctx);
    // 本地路径与远程同语义——按 task id 解析再选定子构建读 build.log；多 arch 须用 --arch。
    let task_id = state.resolve_task_id(&task, user_filter).await?;
    let children = state.get_builds_by_task_id(task_id).await?;
    let record = select_log_build(task_id, &children, arch.as_deref())?;
    let build_id = record.id;

    let result_dir = match record.result_dir {
        Some(ref d) => std::path::PathBuf::from(d),
        None => {
            // result_dir 为空分两种：pending/building = 日志尚不可读的状态机冲突 → Conflict
            //（稍后重试有意义）；终态 = 记录被 GC 清理或目录从未创建 → NotFound。两者退出码
            // 同为 4，变体区分供未来 JSON 错误信封分辨可重试性（现错误输出纯文本，无 code() 消费方）。
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
        // text 模式 build.log 缺失给一行 stderr 提示（stdout 日志流不污染）；json 模式结构化
        // 消费端自行判 lines 空，不加提示。
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

/// 0/1/N 子构建选择（本地子构建与远程 builds 列表同口径）：无子构建报错
/// （NotFound）；单子构建直取（忽略 --arch）；多子构建必须 --arch 命中，
/// 未命中 ValidationFailed 并列出可选 arch。`arch_of` 适配两种记录形态的
/// arch 字段（本地 `Option<String>` 缺失按空串、远程 `String`）。
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

/// 从任务的子构建中选出要读日志的那一个，口径见 [`select_build_by_arch`]。
fn select_log_build<'a>(
    task_id: i64,
    children: &'a [crbs_core::BuildRecord],
    arch: Option<&str>,
) -> anyhow::Result<&'a crbs_core::BuildRecord> {
    select_build_by_arch(task_id, children, arch, |b| b.arch.as_deref().unwrap_or(""))
}

/// 从远程 crbs-server 拉取构建日志：`--follow` 从当前 EOF 流式推送直到响应结束（构建终态）；
/// 非 follow 从 `?offset=0` 拉取完整日志，本地做 tail/grep/JSON 格式化。
/// 远程日志请求的非 2xx 收口（follow 与非 follow 共用）：body 供错误回显，
/// 读取失败给占位串不掩盖状态码。
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

    // task id 解析失败属参数误用——ValidationFailed（USAGE=4）。
    let task_id = crate::cmd::parse_task_id(&args.task)?;
    let detail = crate::remote::fetch_task_record(&target, task_id, None).await?;

    let build = select_build_by_arch(task_id, &detail.builds, args.arch.as_deref(), |b| {
        b.arch.as_str()
    })?;

    let url = format!("{}/api/v1/builds/{}/logs", base_url, build.id);

    if args.follow {
        // 日志文件可能尚未生成，404 时短暂重试。
        for _ in 0..60 {
            // 跟随流按 LONG_BODY_TIMEOUT 放宽总超时：client 级 300s 会在长构建
            // 中途掐断 --follow；流的终止由 EOF/上层取消决定。
            let resp = client
                .get(&url)
                .timeout(crate::remote::LONG_BODY_TIMEOUT)
                .send()
                .await
                // 传输层失败属环境域 → Network(6)；裸 ? 会落 INTERNAL(1)+"this is a bug"。
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
        // 404 重试耗尽：与非 follow 的 404 分支同映射 NotFound，退出码契约一致（裸 bail 会退 1）。
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
        // 传输层失败属环境域 → Network(6)；裸 ? 会落 INTERNAL(1)+"this is a bug"。
        .map_err(|e| CrbsError::Network {
            message: format!("request build log: {e}"),
        })?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        // 与"任务不存在"（fetch_task_record 的 404）区分：命中的是"任务存在但 build.log 尚未生成/已被清理"。
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
    // 远程展示路径同样回落默认 tail 行数（follow 分支不走到这里）。
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

    /// 无子构建属"未找到"语义——NotFound（USAGE=4）；文案逐字保留。
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
        // 单子构建直取，即使 --arch 不匹配（与远程路径同口径）。
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

    /// 同数字两义回归钉：task id 与子构建 id 不同值，传 task id 必须命中。
    #[tokio::test]
    async fn handle_logs_local_resolves_task_id() {
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        // 先垫一条无子构建的任务，让后续 task id 与 build id 错开。
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

    /// 行缓冲核心：chunk 边界不对齐行边界时半行跨 chunk 拼接，未完成行留在缓冲。
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

    /// follow 读缓冲多字节安全：半字符驻留字节缓冲到下一轮拼接，输出绝不出现 U+FFFD；
    /// 逐字节喂入是最苛刻的切法——每个多字节字符都被拆过。
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

        // 复现原 bug 形态：4096 chunk 边界正落在多字节字符中间
        let prefix = "x".repeat(4095); // 4096 字节 chunk 的最后一字节是 '开' 的首字节
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

    /// 行尾 `\r` 剥除与 tokio `lines()` 口径一致（CRLF 日志不残留 `\r`）。
    #[test]
    fn emit_complete_lines_strips_trailing_cr_like_tokio_lines() {
        let mut buf: Vec<u8> = Vec::new();
        let mut out = Vec::new();
        emit_complete_lines(&mut buf, b"crlf line\r\nlf line\ntrailing\r", |l| {
            out.push(l.to_string())
        });
        assert_eq!(out, vec!["crlf line", "lf line"]);
        // 无 `\n` 跟随的 `\r` 不是行终结符的一部分，留在缓冲（同 std/tokio lines）。
        assert_eq!(buf, b"trailing\r");
    }

    /// follow 首轮 + 截断探测 + 终态退出的端到端最小检查：首轮读 old-line-1/2（pos=22）→
    /// t=1s 日志被截断重写为更短内容（len < pos）→ t=5s（poll 25）先走截断分支（seek 到
    /// 新末尾），同轮 DB 检查见终态补尾退出——而非卡在旧 offset EOF 空转或读错误静默 break。
    ///
    /// 时钟：连接池预热（seed 走真实时钟，sqlx pool acquire 超时依赖定时器，start_paused 下
    /// 会被 auto-advance 立即点燃）之后 `tokio::time::pause()`；后续 DB 查询走已建立连接，不依赖定时器。
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

        // 预热：pause 前显式做一次与探针同型的真实查询——seed 只保证此刻有
        // idle，探针时刻 idle 可能被虚拟时钟跳变触发的回收腾空，届时 acquire
        // 需新开连接，"开连接的真实 I/O"与 auto-advance 点燃的 acquire_timeout
        //（10s 定时器）赛跑即 PoolTimedOut（flaky 根因）。预热把新开路径挡在
        // 真实时钟内，探针必命中 idle。
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

    /// 已存在的 0444 只读日志也能 follow（follow 全程只读 + seek）；root 无视 0444，守护跳过。
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

        // 同 truncation 测试：pause 前预热探针同型查询（见该处注释）。
        store.get_build(build_id).await.unwrap();
        tokio::time::pause();
        follow_log(&log, &store, build_id, 0, &[], None)
            .await
            .expect("read-only existing log must be followable");
    }

    /// DB 连续读失败达上限 → follow 以 DatabaseUnavailable 中止，文案明确
    /// "日志源不可用/构建可能仍在跑"（不误导为构建失败）。注入确定性 Err 探针
    /// ——生产探针走 StateStore，测试无 sqlx 直连手段；暂停时钟让 25-poll 间隔
    /// 的探针周期零成本推进。同时钉 Ok(Some(非终态)) 不中止、探针恢复 Ok 时
    /// 连续计数归零。
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

        // 计数归零路径：Err,Err 后探针恢复 Ok(None)（记录消失 break 收尾），
        // streak 在 Ok 臂归零——两次连续失败不会累积到上限误中止。
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

    /// 创建分支：文件缺失 + 父目录存在 → 按权限不变量创建；open(2) mode 受 umask 掩码不能钉死
    /// 0660 字面值，跨 umask 稳定的不变量是"对 other 零权限 + 属主可读"。
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

    /// 创建分支：父目录也不存在 → 保留既有错误文案，目录缺失走 NotFound（USAGE=4）。
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

    /// 对目录 read → EISDIR 稳定读失败注入点：走 `CrbsError::Io`（ENVIRONMENT=6）；文案逐字保留。
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

    /// 本地 logs 缺 StateStore 属调用方式误用——ValidationFailed（USAGE=4）。
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

    /// result_dir 缺失按阶段分流——pending/building = 日志尚不可读的状态机冲突（Conflict），
    /// 终态 = 目录已不存在（NotFound）；两者退出码同为 4，变体区分供未来 JSON 错误信封分辨可重试性。
    #[tokio::test]
    async fn handle_logs_result_dir_missing_maps_by_phase() {
        let (tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(tmp.path());

        // pending：Conflict。
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

        // 终态（succeeded）无 result_dir：NotFound。
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

    /// 远程 follow × -n/--grep 显式拒绝（ValidationFailed → USAGE=4），
    /// 在触网之前就失败。
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

    /// 裸远程 follow（未传 -n）不得命中"-n × 远程 -f 互斥"——
    /// clap 不注入默认 50，互斥只认用户显式传参。断言错误不是
    /// ValidationFailed（守卫已过，失败来自不可达地址的传输错误）。
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

    /// -n 0 显式传入 × 远程 follow 同样放行（全量，对齐本地 lines=0，与上方 Some(10) 被拒对照）：
    /// 守卫过后失败只来自不可达地址的传输错误，而非 ValidationFailed。
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

    /// --format json × --follow/--editor 互斥是参数误用，走 ValidationFailed（USAGE=4）。
    #[tokio::test]
    async fn json_format_with_follow_is_validation_failed_exit_4() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = crate::test_support::EnvGuard::new(tmp.path());
        let mut args = logs_args("1".to_string(), OutputFormat::Json);
        args.follow = true;
        // 互斥检查先于 remote 解析与本地 state 消费，state 传 None 即可。
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

    /// --editor × 远程日志同为参数误用，同走 ValidationFailed（USAGE=4）。
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

    /// 退出码契约：任务详情可达后的传输层失败 → Network（ENVIRONMENT=6），
    /// 不得经裸 ? 落 INTERNAL(1)。经 302 → 127.0.0.1:1（特权端口必拒）在
    /// fetch_task_record 成功之后注入 connect 失败。
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
            // JSON 信封 code 串同钉（--format json 走 network_error 而非 internal_error）。
            assert_eq!(ce.code(), "network_error", "follow={follow}");
        }
    }
}
