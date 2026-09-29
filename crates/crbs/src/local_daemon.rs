// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 本地 TCP daemon 的发现与自启动封装。
//!
//! `--daemon` 或 `[local].daemon_auto = true` 时优先连接本地 daemon，未运行
//! 则 `crbs-server local start` 拉起，失败回退本地直建；默认（无 `--remote`
//! /auto）直接本地构建。

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use crbs_core::config::{CrbsConfig, ServerConfig};
use crbs_core::error::CrbsError;
use tracing::{debug, info, warn};

use crate::cli::{BuildArgs, OutputFormat};
use tokio_util::sync::CancellationToken;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const STARTUP_POLL: Duration = Duration::from_millis(200);
/// `crbs-server local start` 子进程自身完成上限（daemon 就绪轮询另计 STARTUP_TIMEOUT）。
const START_PROCESS_TIMEOUT: Duration = Duration::from_secs(60);

/// 返回本地 daemon 的 HTTP base URL。
pub(crate) fn base_url(port: u16) -> String {
    format!("http://127.0.0.1:{}", port)
}

/// 构造访问本地 daemon 的 HTTP client（无 token、无 CA）。
pub(crate) async fn build_client() -> Result<reqwest::Client> {
    crate::remote::build_http_client(&None, &None).await
}

pub(crate) async fn load_server_config() -> Result<ServerConfig> {
    let path = crbs_core::config::config_path("server.toml")?;
    // 错误原样透传：CrbsError 经 From 保留变体 downcast（Io→6 / ValidationFailed→4）。
    Ok(ServerConfig::load_async(&path).await?)
}

/// 判断配置是否默认走本地 daemon；读取失败保守返回 false（无 server 配置不强走）。
pub(crate) async fn daemon_auto_enabled() -> bool {
    match load_server_config().await {
        Ok(cfg) => cfg.local.daemon_auto,
        Err(_) => false,
    }
}

fn effective_run_dir(server_config: &ServerConfig, crbs_config: &CrbsConfig) -> PathBuf {
    server_config
        .local
        .run_dir
        .clone()
        .unwrap_or_else(|| default_run_dir(&crbs_config.crbs_root))
}

/// 确保本地 daemon 在运行，返回其监听端口：已在跑直接复用，否则
/// `crbs-server local start` 拉起。`cancel` 触发**绝不杀已派生 daemon**
///（留活，由 idle watcher 收尾），见拉起/轮询两处取消分支。
pub(crate) async fn ensure_running(cancel: Option<&CancellationToken>) -> Result<u16> {
    let server_config = load_server_config().await?;
    if !server_config.local.enable {
        // daemon 被配置禁用属配置误用——ValidationFailed（USAGE=4）。
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: "local daemon is disabled by config (server.local.enable=false)".into(),
        }
        .into());
    }

    let crbs_config = CrbsConfig::load_async().await?;
    let run_dir = effective_run_dir(&server_config, &crbs_config);
    if let Some(port) = discover(&run_dir).await? {
        debug!(port = %port, "Reusing existing local daemon");
        return Ok(port);
    }

    let bin = find_server_binary_named("crbs-server").await?;
    info!(bin = %bin.display(), "Starting local daemon via crbs-server");

    // 子进程限时启动；timeout 只丢 future 不杀子进程，超时分支显式补杀防孤儿。
    let child = tokio::process::Command::new(&bin)
        .arg("local")
        .arg("start")
        .arg("--run-dir")
        .arg(&run_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        // 独立进程组：kill(-pid) 补杀要求子进程自成组长，否则 ESRCH 被吞、
        // start 派生的 daemon 成孤儿。
        .process_group(0)
        // spawn 失败（二进制缺失/不可执行等）——Io（kind 保真，ENVIRONMENT=6）。
        .spawn()
        .map_err(|e| CrbsError::Io {
            context: format!("spawn crbs-server local start ({})", bin.display()),
            kind: e.kind(),
            detail: e.to_string(),
        })?;
    let child_pid = child.id();
    let wait_result = tokio::select! {
        r = tokio::time::timeout(START_PROCESS_TIMEOUT, child.wait_with_output()) => r,
        _ = crbs_core::http_retry::wait_for_cancel(cancel) => {
            // 取消分支绝不走下方进程组 kill（会连已派生 daemon 一起杀）：
            // 直接 return，wait future drop → kill_on_drop 只杀直接子进程，
            // daemon 是独立孙进程，由 idle watcher（默认 300s）收尾。
            report_cancelled_daemon_keeps_running();
            return Err(CrbsError::Cancelled.into());
        }
    };
    // wait_with_output 失败（子进程 IO 断裂等）——Io（kind 保真，ENVIRONMENT=6）。
    let output = match wait_result {
        Ok(r) => r,
        Err(_) => {
            // wait_with_output 消费 child（kill_on_drop 随之失效）：按 pid
            // 补杀进程组——`crbs-server local start` 自身还会派生 daemon。
            if let Some(pid) = child_pid {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(-(pid as i32)),
                    nix::sys::signal::Signal::SIGKILL,
                );
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            // start 子进程挂死超时——Io（kind=TimedOut，ENVIRONMENT=6）。
            return Err(CrbsError::Io {
                context: "start local daemon".into(),
                kind: std::io::ErrorKind::TimedOut,
                detail: format!(
                    "crbs-server local start timed out after {}s ({})",
                    START_PROCESS_TIMEOUT.as_secs(),
                    bin.display()
                ),
            }
            .into());
        }
    }
    .map_err(|e| CrbsError::Io {
        context: format!("run crbs-server local start ({})", bin.display()),
        kind: e.kind(),
        detail: e.to_string(),
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // start 失败不立即 bail：最常见是并发首启（DB 迁移+seed 可能超其
        // LOCK_TIMEOUT 10s）自退而首启 daemon 仍在收敛，复用就绪轮询再等
        // 一轮，真超时才上报原始失败。
        // 取舍：任何失败都白等一轮 STARTUP_TIMEOUT；有反馈再按失败原因分流。
        warn!(
            stderr = %stderr.trim(),
            "crbs-server local start failed; polling for a concurrently starting daemon before giving up"
        );
        if let Some(port) = poll_daemon_ready(&run_dir, cancel).await? {
            return Ok(port);
        }
        // start 子进程非零退出——Io（kind=Other，ENVIRONMENT=6），detail 含 stderr。
        return Err(CrbsError::Io {
            context: "start local daemon".into(),
            kind: std::io::ErrorKind::Other,
            detail: format!("crbs-server local start failed: {stderr}"),
        }
        .into());
    }

    match poll_daemon_ready(&run_dir, cancel).await? {
        Some(port) => Ok(port),
        // 就绪轮询窗口耗尽——Io（kind=TimedOut，ENVIRONMENT=6）。
        None => Err(CrbsError::Io {
            context: "start local daemon".into(),
            kind: std::io::ErrorKind::TimedOut,
            detail: format!(
                "local daemon did not become ready within {:?} (run_dir: {})",
                STARTUP_TIMEOUT,
                run_dir.display()
            ),
        }
        .into()),
    }
}

/// STARTUP_TIMEOUT 窗口内轮询 discover 直到就绪（正常路径与 start 失败
/// 重试共用）。Ok(None) = 窗口耗尽；轮询期取消按"daemon 留活"返回 Cancelled。
async fn poll_daemon_ready(
    run_dir: &Path,
    cancel: Option<&CancellationToken>,
) -> Result<Option<u16>> {
    let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
    loop {
        if cancel.is_some_and(|t| t.is_cancelled()) {
            report_cancelled_daemon_keeps_running();
            return Err(CrbsError::Cancelled.into());
        }
        if let Some(port) = discover(run_dir).await? {
            return Ok(Some(port));
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(STARTUP_POLL).await;
    }
}

/// 拉起/轮询取消的统一提示：daemon 留活由 idle watcher 收尾。走 eprintln
/// 而非塞进 Cancelled 的 Display——该变体文案被多处复用，不能改语义。
fn report_cancelled_daemon_keeps_running() {
    eprintln!(
        "Cancelled while waiting for the local daemon; the daemon (if spawned) keeps running and exits after its idle timeout."
    );
}

/// 本地 daemon 任务级取消响应（`/api/v1/tasks/{id}/cancel` 的 202 体），与
/// 服务端 `TaskCancelResponse` 对齐；部分失败语义由 `message` 承载（与远程
/// 同口径）。daemon 未运行/任务 404 时 [`cancel_task`] 返回 `Ok(None)`。
#[derive(Debug, serde::Deserialize)]
pub(crate) struct LocalDaemonTaskCancel {
    #[serde(default)]
    pub cancelled_build_ids: Vec<i64>,
    #[serde(default)]
    pub skipped_build_ids: Vec<i64>,
    #[serde(default)]
    pub message: String,
}

/// 通过本地 daemon 取消整个任务（task 级联子构建）：Some = 取消
/// 已受理；Ok(None) = daemon 未运行或任务 404，调用方回退本地直连路径。
pub(crate) async fn cancel_task(task_id: i64) -> Result<Option<LocalDaemonTaskCancel>> {
    let server_config = load_server_config().await?;
    if !server_config.local.enable {
        return Ok(None);
    }
    let crbs_config = CrbsConfig::load_async().await?;
    let run_dir = effective_run_dir(&server_config, &crbs_config);

    let port = match discover(&run_dir).await? {
        Some(p) => p,
        None => return Ok(None),
    };

    let client = build_client().await?;
    let url = format!("{}/api/v1/tasks/{}/cancel", base_url(port), task_id);
    // 传输失败（连接拒绝/超时）——Network（ENVIRONMENT=6），message 含 URL 与底层错误。
    let resp = client
        .post(&url)
        .send()
        .await
        .map_err(|e| CrbsError::Network {
            message: format!("POST cancel to local daemon {url}: {e}"),
        })?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        let body = resp
            .text()
            .await
            .unwrap_or_else(|e| format!("<failed to read body: {}>", e));
        // 退出码契约与远端对齐（401/403→5、其余 4xx→4、5xx→6）：daemon 即
        // crbs-server，同款 ApiError 信封。
        return Err(
            crate::remote::http_status_error("local daemon task cancel", status, &body).into(),
        );
    }
    // 应答不可解（非 JSON/字段缺失）——Network（ENVIRONMENT=6）。
    let parsed: LocalDaemonTaskCancel = resp.json().await.map_err(|e| CrbsError::Network {
        message: format!("parse local daemon task cancel response: {e}"),
    })?;
    Ok(Some(parsed))
}

/// 提交一批 SRPM 到本地 daemon：`wait = true` 阻塞到全部终态并输出摘要，
/// `false` 立即返回所有 build_id。
pub(crate) async fn submit_builds(
    base_url: &str,
    args: &BuildArgs,
    inputs: &[PathBuf],
    wait: bool,
    cancel_token: Option<&CancellationToken>,
) -> Result<()> {
    let (client, batch) = post_batch(base_url, args, inputs).await?;
    // 回显契约：请求维未在 daemon 响应中确认（缺键降 None）→ stderr 一行
    // 告警，不失败；与 remote 通道同口径（req_min_unconfirmed）。
    if crate::cmd::build::remote::req_min_unconfirmed(
        &args.behavior,
        (
            batch.req_min_mem_kb,
            batch.req_min_ncpu,
            batch.req_min_disk_kb,
        ),
    ) {
        eprintln!(
            "Warning: server did not confirm the requested placement requirements \
             (req_min_* missing from response) — an older hub may have dropped \
             them, so scheduling will not honor these floors"
        );
    }

    if !wait {
        let product = args.input.product.clone().unwrap_or_default();
        return print_detach_output(
            base_url,
            batch.task_id,
            &product,
            &batch.ids,
            inputs,
            args.output.format,
        )
        .await;
    }

    let id_input_pairs: Vec<(i64, PathBuf)> =
        batch.ids.into_iter().zip(inputs.iter().cloned()).collect();
    crate::cmd::build::batch::follow_builds(&client, base_url, id_input_pairs, args, cancel_token)
        .await
}

/// 向 daemon 提交一批 SRPM，返回 HTTP client 与 batch 响应。
async fn post_batch(
    base_url: &str,
    args: &BuildArgs,
    inputs: &[PathBuf],
) -> Result<(reqwest::Client, BatchBuildResponse)> {
    if inputs.is_empty() {
        // 本地侧参数预检——ValidationFailed（USAGE=4）。
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: "No SRPM inputs".into(),
        }
        .into());
    }

    let client = build_client().await?;
    let req = build_request(args, inputs)?;
    let url = format!("{}/api/v1/builds", base_url);
    // 传输失败（连接拒绝/超时）——Network（ENVIRONMENT=6），message 含 URL 与底层错误。
    let resp = client
        .post(&url)
        .json(&req)
        .send()
        .await
        .map_err(|e| CrbsError::Network {
            message: format!("POST {url}: {e}"),
        })?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp
            .text()
            .await
            .unwrap_or_else(|e| format!("<failed to read body: {}>", e));
        // 退出码契约与远端同口径（http_status_error）：daemon 即 crbs-server，同款信封。
        return Err(
            crate::remote::http_status_error("local daemon batch submit", status, &body).into(),
        );
    }

    // 应答不可解（非 JSON/字段缺失）——Network（ENVIRONMENT=6）。
    let batch: BatchBuildResponse = resp.json().await.map_err(|e| CrbsError::Network {
        message: format!("parse local daemon batch build response: {e}"),
    })?;

    if batch.ids.len() != inputs.len() {
        // ids 条数与输入不一致（数据源是 daemon 非用户参数，部署一致性
        // 故障）——Io（kind=Other，ENVIRONMENT=6）。
        return Err(CrbsError::Io {
            context: "local daemon batch submit".into(),
            kind: std::io::ErrorKind::Other,
            detail: format!(
                "daemon returned {} build ids for {} inputs",
                batch.ids.len(),
                inputs.len()
            ),
        }
        .into());
    }

    Ok((client, batch))
}

/// 构造 JSON BuildRequest（语义与 server multipart 字段一致）：仅显式
/// true 的布尔选项上送，默认行为由产品配置决定。
fn build_request(args: &BuildArgs, inputs: &[PathBuf]) -> Result<crbs_core::types::BuildRequest> {
    // dist 走 normalize_dist 归一（含字符集校验，非法字符会拼进
    // rpmbuild define 构建期晚失败）；ValidationFailed 上抛（USAGE=4）。
    let dist = crbs_core::build_options::normalize_dist(args.behavior.dist.clone())?;
    // 标签解析 + 上限/重复键校验在本地先做：参数误用（USAGE=4）不必等 daemon 回 4xx。
    let labels: Vec<crbs_core::types::TaskLabel> =
        crate::cmd::build::parse_task_labels(&args.behavior.label)?
            .into_iter()
            .map(|(key, value)| crbs_core::types::TaskLabel { key, value })
            .collect();

    Ok(crbs_core::types::BuildRequest {
        product: args.input.product.clone().unwrap_or_default(),
        srpms: inputs.iter().map(|p| p.display().to_string()).collect(),
        arch_list: if args.behavior.arch.is_empty() {
            None
        } else {
            Some(args.behavior.arch.clone())
        },
        labels,
        options: crbs_core::BuildOptions {
            stage: args.behavior.stage.clone(),
            shared_layer: args.behavior.shared_layer.then_some(true),
            tmpfs: args.behavior.tmpfs.then_some(true),
            ccache: args.behavior.ccache.then_some(true),
            timeout: args.behavior.timeout,
            nocheck: args.behavior.nocheck.then_some(true),
            noclean: args.behavior.noclean.then_some(true),
            nodebuginfo: args.behavior.nodebuginfo.then_some(true),
            target: args.behavior.target.clone(),
            dist,
            backend: args.container.backend.clone(),
            no_network: args.container.no_network.then_some(true),
            no_publish: args.behavior.no_publish.then_some(true),
            no_consume: args.behavior.no_consume,
            memory_max: args.container.memory_max.clone(),
            cpu_quota: args.container.cpu_quota.clone(),
            // 放置契约下限：daemon = 本地 hub 调度路径（--local/--chain/--attach
            // 已在路由层硬化拒绝），语法与上界由 server 侧 validate_options 收口。
            min_mem: args.behavior.min_mem.clone(),
            min_ncpu: args.behavior.min_ncpu,
            min_disk: args.behavior.min_disk.clone(),
            define: args.behavior.define.clone(),
            with_features: args.behavior.with_features.clone(),
            without_features: args.behavior.without_features.clone(),
            retry: args.behavior.retry,
            no_reproduce: args.reproduce.no_reproduce.then_some(true),
            // 值（replay_build_*）恒 None：daemon 提交只传旗标，BUILDHOST/BUILDTIME
            // 由 server fan-out 对每份 SRPM 探测后写进 build 级 options。
            repro_from_srpm: args.reproduce.repro_from_srpm,
            replay_build_host: None,
            replay_build_time: None,
            reproduce_from_build_id: None,
            priority: Some(args.behavior.priority),
            arch: None,
            arch_list: vec![],
            skip_unsupported_arches: args.behavior.skip_unsupported_arches,
        },
    })
}
/// daemon 路由的 detach envelope 构造：与 direct/remote 同构，整批共享一个
/// task（schema 护栏测试见本文件）。
fn detach_output(
    task_id: i64,
    product: &str,
    ids: &[i64],
    pkg_names: &[String],
) -> crate::cmd::build::DetachOutput {
    let builds: Vec<crate::cmd::build::DetachBuildEntry> = ids
        .iter()
        .zip(pkg_names.iter())
        .map(|(id, pkg_name)| crate::cmd::build::DetachBuildEntry {
            build_id: *id,
            task_id,
            pkg_name: pkg_name.clone(),
        })
        .collect();
    crate::cmd::build::DetachOutput {
        command: "build",
        mode: "detach",
        transport: "daemon",
        product: product.to_string(),
        task_id,
        builds,
    }
}

async fn print_detach_output(
    base_url: &str,
    task_id: i64,
    product: &str,
    ids: &[i64],
    inputs: &[PathBuf],
    format: OutputFormat,
) -> Result<()> {
    // 展示名与 direct/remote 路由同源：NEVR 探测优先，失败回落文件名派生。
    let pkg_names = crate::cmd::build::remote::output::resolve_srpm_pkg_names(None, inputs).await;
    match format {
        OutputFormat::Json => {
            let out = detach_output(task_id, product, ids, &pkg_names);
            crate::cmd::build::print_json(&out)?;
        }
        OutputFormat::Text => {
            println!("Detached local build(s) via {}", base_url);
            for (id, pkg_name) in ids.iter().zip(pkg_names.iter()) {
                println!("  {}  {}", id, pkg_name);
            }
            // crbs logs/status 的 ID 参数是 task 域：打印 task_id，build_id 查无此任务。
            println!("  task_id:    {}", task_id);
            println!("Use 'crbs status' or 'crbs logs {}'", task_id);
        }
    }
    Ok(())
}

/// 返回默认 run_dir：root 用 `/run/crbs`，否则 `{crbs_root}/run`。
fn default_run_dir(crbs_root: &Path) -> PathBuf {
    if nix::unistd::getuid().is_root() {
        PathBuf::from("/run/crbs")
    } else {
        crbs_root.join("run")
    }
}

/// 在相邻目录或 PATH 中查找指定名字的可执行文件（生产固定 "crbs-server"）；
/// 测试用绝不存在的名字直测错误路径，不误拉真 daemon。
async fn find_server_binary_named(binary_name: &str) -> Result<PathBuf> {
    let sibling = match std::env::current_exe() {
        Ok(exe) => exe.parent().map(|p| p.join(binary_name)),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to get current exe, falling back to PATH");
            None
        }
    };

    if let Some(p) = sibling {
        if tokio::fs::try_exists(&p).await.unwrap_or(false) {
            return Ok(p);
        }
    }

    // JoinError 仅在 which 闭包 panic 时出现（真 bug）——Internal 保留 bug hint。
    let name = binary_name.to_string();
    tokio::task::spawn_blocking(move || which::which(&name))
        .await
        .map_err(|e| CrbsError::Internal(format!("search crbs-server binary: {e}")))?
        // 相邻目录与 PATH 均无 crbs-server——Io（kind=NotFound，ENVIRONMENT=6）。
        .map_err(|e| CrbsError::Io {
            context: "search crbs-server binary".into(),
            kind: std::io::ErrorKind::NotFound,
            detail: format!("crbs-server binary not found next to crbs or in PATH: {e}"),
        })
        .map_err(Into::into)
}

/// 读取 pidfile/portfile 并校验进程存活。
async fn discover(run_dir: &Path) -> Result<Option<u16>> {
    let pid_path = run_dir.join("crbs-server.pid");
    let port_path = run_dir.join("crbs-server.port");

    let pid_exists = tokio::fs::try_exists(&pid_path).await.unwrap_or(false);
    let port_exists = tokio::fs::try_exists(&port_path).await.unwrap_or(false);

    if !pid_exists || !port_exists {
        // 文件不完整 ≠ 残留：daemon 先原子建 pidfile（单活锁），全部就绪才写
        // portfile（窗口秒级）。删启动中 daemon 的 pidfile 会被 idle watcher 当
        // 外部停止请求退出并击穿单活锁拉起第二实例（多实例破坏 recovery/
        // zombie repair 正确性）；仅 pid 读不出/已死/垃圾才清理，空内容保留。
        let pid_text = if pid_exists {
            tokio::fs::read_to_string(&pid_path).await.ok()
        } else {
            None
        };
        // 判活用 getpgid 语义工具：kill(pid, None) 对无权信号进程返回 EPERM
        //（root daemon + 普通 CLI 是设计内场景），误判死会删活 pidfile。
        let probe = parse_pidfile_probe(pid_text.as_deref());
        let pid_alive = match probe {
            PidfileProbe::Pid(pid) => crbs_core::util::is_process_alive(i64::from(pid)).await,
            _ => false,
        };
        if preserve_starting_daemon_files(probe, pid_alive) {
            warn!(
                run_dir = %run_dir.display(),
                "daemon pidfile present without portfile but daemon is likely starting up \
                 (empty pidfile write window or live pid); keeping files"
            );
            return Ok(None);
        }
        for path in [&pid_path, &port_path] {
            if tokio::fs::try_exists(path).await.unwrap_or(false) {
                if let Err(e) = tokio::fs::remove_file(path).await {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to remove stale daemon file"
                    );
                }
            }
        }
        return Ok(None);
    }

    let pid_text = match tokio::fs::read_to_string(&pid_path).await {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    // 空内容 = create_new 与 write_all 之间的写入窗口：保守保留，撞上窗口
    // unlink 会击穿单活锁（交 ensure_running 轮询）。
    if pid_text.trim().is_empty() {
        warn!(
            run_dir = %run_dir.display(),
            "daemon pidfile is empty (write window), keeping files"
        );
        return Ok(None);
    }
    let pid: i32 = match pid_text.trim().parse() {
        Ok(p) => p,
        Err(_) => {
            // 内容损坏：清理 pid/port 按不存在处理；lock 不清理（常驻、
            // start truncate-open 复用，删掉削弱并发互斥）。
            for path in [&pid_path, &port_path] {
                if let Err(e) = tokio::fs::remove_file(path).await {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to remove corrupted daemon file"
                    );
                }
            }
            return Ok(None);
        }
    };

    // getpgid 判活（含 /proc 身份校验、读失败保守按活）；pid<=0 按死自愈。
    if !crbs_core::util::is_process_alive(i64::from(pid)).await {
        warn!(
            pid = %pid,
            run_dir = %run_dir.display(),
            "Local daemon pidfile points to a dead process, cleaning up stale files"
        );
        // 判死→unlink TOCTOU 守卫：判死与清理间 pidfile 可能被并发新 daemon
        // 重写，清理前重读，不再是判死 pid（含被删/写入窗口）即放弃本轮。
        let re_read = tokio::fs::read_to_string(&pid_path).await.ok();
        if !stale_cleanup_safe(pid, re_read.as_deref()) {
            warn!(
                pid = %pid,
                run_dir = %run_dir.display(),
                "pidfile changed between liveness judgement and cleanup; skipping stale cleanup for this round"
            );
            return Ok(None);
        }
        // lock 不清理：常驻、start 侧 truncate-open 复用，删掉削弱并发互斥。
        for path in [&pid_path, &port_path] {
            if let Err(e) = tokio::fs::remove_file(path).await {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to remove stale daemon file for dead process"
                );
            }
        }
        return Ok(None);
    }

    let port_text = match tokio::fs::read_to_string(&port_path).await {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let port: u16 = match port_text.trim().parse() {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };

    // 身份探针：pid 存活只证明"某进程占着该 pid"——pid 复用会让陈旧 portfile
    // 指向无关本地服务（submit_builds 会把 SRPM 路径 + 构建选项 POST 过去）。
    // GET /api/v1/nihao（无需认证）应答含 "nihao" 才认定。探针失败按未发现
    // 处理但不删文件：区分不了 pid 复用残留与 daemon 启动中监听未就绪。
    let client = build_client().await?;
    let probe_url = format!("{}/api/v1/nihao", base_url(port));
    let probe = client
        .get(&probe_url)
        .timeout(Duration::from_secs(3))
        .send()
        .await;
    let is_crbs_server = match probe {
        Ok(resp) if resp.status().is_success() => {
            matches!(resp.text().await, Ok(body) if body.contains("nihao"))
        }
        _ => false,
    };
    if !is_crbs_server {
        warn!(
            pid = %pid,
            port = %port,
            run_dir = %run_dir.display(),
            "Local daemon pid/port files exist but the port does not answer as crbs-server; ignoring them"
        );
        return Ok(None);
    }

    Ok(Some(port))
}

#[derive(Debug, serde::Deserialize)]
struct BatchBuildResponse {
    ids: Vec<i64>,
    /// daemon 的 BuildResponse 恒带 task_id（detach schema 需要）；同仓同
    /// 版本部署，不设缺省。
    task_id: i64,
    /// 放置契约下限回显（KB/核）；`#[serde(default)]` 容忍响应缺键
    ///（回显告警判定按 None 走）。
    #[serde(default)]
    req_min_mem_kb: Option<i64>,
    #[serde(default)]
    req_min_ncpu: Option<i64>,
    #[serde(default)]
    req_min_disk_kb: Option<i64>,
}

/// "pidfile/portfile 不完整"分支的判定输入（纯逻辑，便于单测）。
#[derive(Debug, Clone, Copy, PartialEq)]
enum PidfileProbe {
    /// 内容为空/纯空白：daemon create_new 与 write_all 之间的写入窗口。
    Empty,
    /// 内容解析出正 pid（判活结果由调用方注入，core 工具是 async 不能进闭包）。
    Pid(i32),
    /// 内容缺失（pidfile 不存在/读不出）、非法或 pid 非正：陈旧残留。
    Garbage,
}

fn parse_pidfile_probe(pid_text: Option<&str>) -> PidfileProbe {
    match pid_text {
        None => PidfileProbe::Garbage,
        Some(t) if t.trim().is_empty() => PidfileProbe::Empty,
        Some(t) => match t.trim().parse::<i32>() {
            Ok(pid) if pid > 0 => PidfileProbe::Pid(pid),
            _ => PidfileProbe::Garbage,
        },
    }
}

/// "不完整"分支判定核心（纯逻辑）：空内容/正 pid 存活 → 保留；其余按残留清理。
fn preserve_starting_daemon_files(probe: PidfileProbe, pid_alive: bool) -> bool {
    match probe {
        PidfileProbe::Empty => true,
        PidfileProbe::Pid(_) => pid_alive,
        PidfileProbe::Garbage => false,
    }
}

/// 判死→unlink TOCTOU 守卫（纯逻辑）：重读 pidfile 仅当仍是判死同一 pid 才
/// 清理；不同 pid/缺失/解析失败 → false，交下一轮 discover 重判。
fn stale_cleanup_safe(judged_pid: i32, re_read: Option<&str>) -> bool {
    match re_read.map(|t| t.trim().parse::<i32>()) {
        Some(Ok(p)) => p == judged_pid,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        detach_output, parse_pidfile_probe, preserve_starting_daemon_files, stale_cleanup_safe,
        PidfileProbe,
    };

    #[test]
    fn starting_daemon_pid_alive_preserves_files() {
        assert!(matches!(
            parse_pidfile_probe(Some("  1234\n")),
            PidfileProbe::Pid(1234)
        ));
        assert!(preserve_starting_daemon_files(
            parse_pidfile_probe(Some("  1234\n")),
            true
        ));
    }

    #[test]
    fn dead_or_unparseable_pid_cleans_up() {
        assert!(!preserve_starting_daemon_files(
            parse_pidfile_probe(Some("1234")),
            false
        ));
        assert!(!preserve_starting_daemon_files(
            parse_pidfile_probe(Some("not-a-pid")),
            true
        ));
        assert!(!preserve_starting_daemon_files(
            parse_pidfile_probe(None),
            true
        ));
        // 非 pidfile 内容（如 "0"）即便判活函数误报也必须清理：kill(0) 语义
        // 是"调用者所在进程组"，不能当作"daemon 存活"。
        assert!(matches!(
            parse_pidfile_probe(Some("0")),
            PidfileProbe::Garbage
        ));
        assert!(matches!(
            parse_pidfile_probe(Some("-5")),
            PidfileProbe::Garbage
        ));
        assert!(!preserve_starting_daemon_files(
            parse_pidfile_probe(Some("0")),
            true
        ));
    }

    /// 空/纯空白 = 写入窗口：保守保留（撞窗口 unlink 击穿单活锁、idle watcher 误杀）。
    #[test]
    fn empty_pidfile_is_write_window_and_preserved() {
        for text in ["", " ", "\n", " \t "] {
            assert!(
                matches!(parse_pidfile_probe(Some(text)), PidfileProbe::Empty),
                "{text:?} must parse as write-window empty"
            );
            assert!(
                preserve_starting_daemon_files(parse_pidfile_probe(Some(text)), false),
                "{text:?} must be preserved"
            );
        }
    }

    /// 判死→unlink TOCTOU 守卫矩阵：仍是判死 pid → 可清理；不同 pid/缺失/
    /// 空或垃圾 → 一律放弃本轮清理。
    #[test]
    fn stale_cleanup_only_when_pidfile_content_unchanged() {
        assert!(stale_cleanup_safe(1234, Some("1234")));
        assert!(stale_cleanup_safe(1234, Some(" 1234\n")));
        assert!(!stale_cleanup_safe(1234, Some("5678")));
        assert!(!stale_cleanup_safe(1234, None));
        assert!(!stale_cleanup_safe(1234, Some("")));
        assert!(!stale_cleanup_safe(1234, Some("  \n")));
        assert!(!stale_cleanup_safe(1234, Some("junk")));
    }

    /// daemon 路由的 detach JSON schema 钉：三路由统一 envelope，`server` 与
    /// `mode: "local-detach"` 键不得出现；daemon 整批共享一个 task。
    #[test]
    fn detach_output_daemon_envelope_schema() {
        let out = detach_output(
            9,
            "fedora",
            &[41, 42],
            &["hello-1.0-1".to_string(), "world-2.0-1".to_string()],
        );
        let value = serde_json::to_value(&out).expect("serialize detach output");
        crate::cmd::build::output::assert_detach_envelope(&value, "daemon");
        assert_eq!(value["task_id"], 9);
        let builds = value["builds"].as_array().expect("builds array");
        assert_eq!(builds.len(), 2);
        assert_eq!(builds[0]["build_id"], 41);
        assert_eq!(builds[0]["task_id"], 9);
        assert_eq!(builds[1]["build_id"], 42);
        assert_eq!(builds[1]["pkg_name"], "world-2.0-1");
    }

    /// ids 条数与输入不一致 → Io（ENVIRONMENT=6）；变体 + 退出码 + 原文案三形态钉住（wiremock）。
    #[tokio::test]
    async fn post_batch_ids_count_mismatch_maps_to_io_exit_6() {
        use clap::Parser;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(wm_path("/api/v1/builds"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ids": [41, 42],
                "task_id": 9,
            })))
            .mount(&server)
            .await;

        let args = crate::cli::BuildArgs::parse_from([
            "crbs",
            "--product",
            "test-product",
            "a.src.rpm",
            "b.src.rpm",
            "c.src.rpm",
        ]);
        let inputs = vec![
            std::path::PathBuf::from("a.src.rpm"),
            std::path::PathBuf::from("b.src.rpm"),
            std::path::PathBuf::from("c.src.rpm"),
        ];

        let err = super::post_batch(&server.uri(), &args, &inputs)
            .await
            .expect_err("2 ids for 3 inputs must fail");
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
        assert_eq!(
            format!("{ce}"),
            "local daemon batch submit: daemon returned 2 build ids for 3 inputs",
            "original bail text must be preserved verbatim after the op prefix"
        );
    }

    /// 传输失败（连接拒绝）→ Network（ENVIRONMENT=6）；三形态钉住（借用后
    /// 即弃端口制造 ECONNREFUSED，无需真实 daemon）。
    #[tokio::test]
    async fn post_batch_transport_error_maps_to_network_exit_6() {
        use clap::Parser;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        drop(listener); // 端口释放 → 后续连接被拒绝。

        let args =
            crate::cli::BuildArgs::parse_from(["crbs", "--product", "test-product", "a.src.rpm"]);
        let inputs = vec![std::path::PathBuf::from("a.src.rpm")];

        let err = super::post_batch(&format!("http://{addr}"), &args, &inputs)
            .await
            .expect_err("connection refused must fail");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::Network { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::ENVIRONMENT
        );
        let msg = format!("{ce}");
        assert!(
            msg.starts_with("network error: POST http://"),
            "original context text (op + URL) must be preserved after the variant prefix: {msg}"
        );
        assert!(
            msg.contains("/api/v1/builds"),
            "request URL must remain visible: {msg}"
        );
    }

    /// 应答不可解（200 + 非 JSON）→ Network（ENVIRONMENT=6）；三形态钉住（wiremock）。
    #[tokio::test]
    async fn post_batch_unparseable_response_maps_to_network_exit_6() {
        use clap::Parser;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(wm_path("/api/v1/builds"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>not json</html>"))
            .mount(&server)
            .await;

        let args =
            crate::cli::BuildArgs::parse_from(["crbs", "--product", "test-product", "a.src.rpm"]);
        let inputs = vec![std::path::PathBuf::from("a.src.rpm")];

        let err = super::post_batch(&server.uri(), &args, &inputs)
            .await
            .expect_err("non-JSON body must fail parsing");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::Network { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::ENVIRONMENT
        );
        assert!(
            format!("{ce}").starts_with("network error: parse local daemon batch build response"),
            "original context text must be preserved after the variant prefix: {ce}"
        );
    }

    /// 相邻目录与 PATH 均无 crbs-server → Io（kind=NotFound，ENVIRONMENT=6）；
    /// 三形态钉住（uuid 名保证不存在，不误拉真 daemon）。
    #[tokio::test]
    async fn find_server_binary_not_found_maps_to_io_exit_6() {
        let absent = format!("crbs-server-absent-{}", uuid::Uuid::new_v4());
        let err = super::find_server_binary_named(&absent)
            .await
            .expect_err("uuid-suffixed name must not exist next to the test exe nor in PATH");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        let crbs_core::error::CrbsError::Io {
            context,
            kind,
            detail,
        } = ce
        else {
            panic!("expected Io, got: {ce}");
        };
        assert_eq!(context, "search crbs-server binary");
        assert_eq!(*kind, std::io::ErrorKind::NotFound);
        assert!(
            detail.starts_with("crbs-server binary not found next to crbs or in PATH"),
            "original context text must be preserved: {detail}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::ENVIRONMENT
        );
    }

    /// daemon 被配置禁用属配置误用 → ValidationFailed（USAGE=4；exit 1 会
    /// 误报 "this is a bug" hint）。
    #[tokio::test]
    async fn ensure_running_disabled_config_maps_to_validation_failed_exit_4() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = crate::test_support::EnvGuard::new(tmp.path());
        tokio::fs::write(tmp.path().join("server.toml"), "[local]\nenable = false\n")
            .await
            .unwrap();

        let err = super::ensure_running(None)
            .await
            .expect_err("disabled config must fail");
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
            format!("{ce}").contains("local daemon is disabled by config"),
            "msg must be preserved verbatim: {ce}"
        );
    }
}
