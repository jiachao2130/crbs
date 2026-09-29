// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

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

const START_PROCESS_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) fn base_url(port: u16) -> String {
    format!("http://127.0.0.1:{}", port)
}

pub(crate) async fn build_client() -> Result<reqwest::Client> {
    crate::remote::build_http_client(&None, &None).await
}

pub(crate) async fn load_server_config() -> Result<ServerConfig> {
    let path = crbs_core::config::config_path("server.toml")?;

    Ok(ServerConfig::load_async(&path).await?)
}

/// 判断配置是否默认走本地 daemon；读取失败保守返回 false。
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

/// 确保本地 daemon 在运行，返回其监听端口：已在跑直接复用，否则 `crbs-server local start` 拉起。cancel 触发**绝不杀已派生 daemon**（交由
/// idle watcher 收尾）。子进程限时启动；timeout 只丢 future 不杀子进程，超时分支显式补杀，防止子进程被抛弃后无人回收。
pub(crate) async fn ensure_running(cancel: Option<&CancellationToken>) -> Result<u16> {
    let server_config = load_server_config().await?;
    if !server_config.local.enable {
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

    let child = tokio::process::Command::new(&bin)
        .arg("local")
        .arg("start")
        .arg("--run-dir")
        .arg(&run_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        // 独立进程组：kill(-pid) 补杀要求子进程自成组长，否则 ESRCH 被吞、
        // start 派生的 daemon 成无主进程。
        .process_group(0)
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

    let output = match wait_result {
        Ok(r) => r,
        Err(_) => {
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

        warn!(
            stderr = %stderr.trim(),
            "crbs-server local start failed; polling for a concurrently starting daemon before giving up"
        );
        if let Some(port) = poll_daemon_ready(&run_dir, cancel).await? {
            return Ok(port);
        }

        return Err(CrbsError::Io {
            context: "start local daemon".into(),
            kind: std::io::ErrorKind::Other,
            detail: format!("crbs-server local start failed: {stderr}"),
        }
        .into());
    }

    match poll_daemon_ready(&run_dir, cancel).await? {
        Some(port) => Ok(port),

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

/// STARTUP_TIMEOUT 窗口内轮询 discover 直到就绪（正常路径与 start 失败重试共用）。Ok(None) = 窗口耗尽；轮询期取消按"daemon 交由 idle
/// watcher 收尾"返回 Cancelled。
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

fn report_cancelled_daemon_keeps_running() {
    eprintln!(
        "Cancelled while waiting for the local daemon; the daemon (if spawned) keeps running and exits after its idle timeout."
    );
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct LocalDaemonTaskCancel {
    #[serde(default)]
    pub cancelled_build_ids: Vec<i64>,
    #[serde(default)]
    pub skipped_build_ids: Vec<i64>,
    #[serde(default)]
    pub message: String,
}

/// 通过本地 daemon 取消整个任务（task 级联子构建）：Some = 取消已受理；Ok(None) = daemon 未运行或任务 404，调用方回退本地直连路径。
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

        return Err(
            crate::remote::http_status_error("local daemon task cancel", status, &body).into(),
        );
    }

    let parsed: LocalDaemonTaskCancel = resp.json().await.map_err(|e| CrbsError::Network {
        message: format!("parse local daemon task cancel response: {e}"),
    })?;
    Ok(Some(parsed))
}

pub(crate) async fn submit_builds(
    base_url: &str,
    args: &BuildArgs,
    inputs: &[PathBuf],
    wait: bool,
    cancel_token: Option<&CancellationToken>,
) -> Result<()> {
    let (client, batch) = post_batch(base_url, args, inputs).await?;

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

async fn post_batch(
    base_url: &str,
    args: &BuildArgs,
    inputs: &[PathBuf],
) -> Result<(reqwest::Client, BatchBuildResponse)> {
    if inputs.is_empty() {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: "No SRPM inputs".into(),
        }
        .into());
    }

    let client = build_client().await?;
    let req = build_request(args, inputs)?;
    let url = format!("{}/api/v1/builds", base_url);

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

        return Err(
            crate::remote::http_status_error("local daemon batch submit", status, &body).into(),
        );
    }

    let batch: BatchBuildResponse = resp.json().await.map_err(|e| CrbsError::Network {
        message: format!("parse local daemon batch build response: {e}"),
    })?;

    if batch.ids.len() != inputs.len() {
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

fn build_request(args: &BuildArgs, inputs: &[PathBuf]) -> Result<crbs_core::types::BuildRequest> {
    let dist = crbs_core::build_options::normalize_dist(args.behavior.dist.clone())?;

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

            min_mem: args.behavior.min_mem.clone(),
            min_ncpu: args.behavior.min_ncpu,
            min_disk: args.behavior.min_disk.clone(),
            define: args.behavior.define.clone(),
            with_features: args.behavior.with_features.clone(),
            without_features: args.behavior.without_features.clone(),
            retry: args.behavior.retry,
            no_reproduce: args.reproduce.no_reproduce.then_some(true),

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

            println!("  task_id:    {}", task_id);
            println!("Use 'crbs status' or 'crbs logs {}'", task_id);
        }
    }
    Ok(())
}

fn default_run_dir(crbs_root: &Path) -> PathBuf {
    if nix::unistd::getuid().is_root() {
        PathBuf::from("/run/crbs")
    } else {
        crbs_root.join("run")
    }
}

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

    let name = binary_name.to_string();
    tokio::task::spawn_blocking(move || which::which(&name))
        .await
        .map_err(|e| CrbsError::Internal(format!("search crbs-server binary: {e}")))?
        .map_err(|e| CrbsError::Io {
            context: "search crbs-server binary".into(),
            kind: std::io::ErrorKind::NotFound,
            detail: format!("crbs-server binary not found next to crbs or in PATH: {e}"),
        })
        .map_err(Into::into)
}

async fn discover(run_dir: &Path) -> Result<Option<u16>> {
    let pid_path = run_dir.join("crbs-server.pid");
    let port_path = run_dir.join("crbs-server.port");

    let pid_exists = tokio::fs::try_exists(&pid_path).await.unwrap_or(false);
    let port_exists = tokio::fs::try_exists(&port_path).await.unwrap_or(false);

    if !pid_exists || !port_exists {
        let pid_text = if pid_exists {
            tokio::fs::read_to_string(&pid_path).await.ok()
        } else {
            None
        };

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

    if !crbs_core::util::is_process_alive(i64::from(pid)).await {
        warn!(
            pid = %pid,
            run_dir = %run_dir.display(),
            "Local daemon pidfile points to a dead process, cleaning up stale files"
        );

        let re_read = tokio::fs::read_to_string(&pid_path).await.ok();
        if !stale_cleanup_safe(pid, re_read.as_deref()) {
            warn!(
                pid = %pid,
                run_dir = %run_dir.display(),
                "pidfile changed between liveness judgement and cleanup; skipping stale cleanup for this round"
            );
            return Ok(None);
        }

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

    task_id: i64,

    #[serde(default)]
    req_min_mem_kb: Option<i64>,
    #[serde(default)]
    req_min_ncpu: Option<i64>,
    #[serde(default)]
    req_min_disk_kb: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PidfileProbe {
    Empty,

    Pid(i32),

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

fn preserve_starting_daemon_files(probe: PidfileProbe, pid_alive: bool) -> bool {
    match probe {
        PidfileProbe::Empty => true,
        PidfileProbe::Pid(_) => pid_alive,
        PidfileProbe::Garbage => false,
    }
}

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

    #[tokio::test]
    async fn post_batch_transport_error_maps_to_network_exit_6() {
        use clap::Parser;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);

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
