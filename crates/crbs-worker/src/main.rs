// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! crbs-worker：分布式构建 worker 二进制。启动时向 Hub 注册，随后运行心跳 + 任务轮询循环（本地 BuildEngine）。

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use clap::{CommandFactory, Parser, Subcommand};
use crbs_core::error::CrbsError;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

mod caps;
mod config;
mod error;
mod executor;
mod heartbeat;
mod poller;
mod retry;
mod sweep;
#[cfg(test)]
mod test_util;

use config::{should_run_startup_gc, WorkerConfig};
use sweep::ActiveBuildIds;

/// crbs-worker — distributed build worker
#[derive(Parser)]
#[command(name = "crbs-worker")]
#[command(version)]
struct Cli {
    /// Path to the worker.toml configuration file
    #[arg(short, long, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the worker and enter the service loop
    Run,
    /// Register once with the Hub (for testing)
    ///
    /// WARNING: if a `run` process using the same token is online, running
    /// `register` recycles that worker and its running builds get reassigned
    /// to (re-)executing workers — i.e. double execution. Only run this while
    /// no live worker shares this token.
    Register,
    /// Show current worker status (for testing)
    Status,
    /// Generate shell completion scripts (bash/zsh/fish/powershell)
    Completions {
        /// Target shell
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

/// 需加载 worker.toml 的子命令：补全生成在配置加载前短路，不进入此枚举。
enum ConfiguredCommand {
    Run,
    Register,
    Status,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    if let Commands::Completions { shell } = cli.command {
        let mut cmd = Cli::command();
        clap_complete::generate(shell, &mut cmd, "crbs-worker", &mut std::io::stdout());
        return std::process::ExitCode::SUCCESS;
    }

    crbs_core::logging::init_tracing_stdout("info");

    let command = match cli.command {
        Commands::Completions { .. } => unreachable!("handled above, before logging init"),
        Commands::Run => ConfiguredCommand::Run,
        Commands::Register => ConfiguredCommand::Register,
        Commands::Status => ConfiguredCommand::Status,
    };

    let config_path = match cli.config.clone().or_else(find_config_file) {
        Some(p) => p,
        None => match crbs_core::config::config_path("worker.toml") {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "Invalid CRBS_CONFIG_DIR");
                return std::process::ExitCode::from(crbs_core::exit_code::USAGE as u8);
            }
        },
    };

    let cfg = match WorkerConfig::load(&config_path).await {
        Ok(c) => c,
        Err(e) => {
            error!(path = %config_path.display(), error = %e, "Failed to load config");
            return std::process::ExitCode::from(crbs_core::exit_code::USAGE as u8);
        }
    };

    match command {
        ConfiguredCommand::Run => {
            if let Err(e) = run_worker(cfg).await {
                error!(error = %e, "Worker exited with error");
                return std::process::ExitCode::from(
                    crbs_core::exit_code::crbs_error_exit_code(&e) as u8,
                );
            }
        }
        ConfiguredCommand::Register => {
            let resource_caps =
                match tokio::task::spawn_blocking(caps::probe_resource_caps_default).await {
                    Ok(caps) => caps,
                    Err(e) => {
                        warn!(error = ?e, "Capability probe task failed; reporting none");
                        0
                    }
                };
            if let Err(e) = register_once(&cfg, resource_caps).await {
                error!(error = %e, "Registration failed");
                return std::process::ExitCode::from(
                    crbs_core::exit_code::crbs_error_exit_code(&e) as u8,
                );
            }
        }
        ConfiguredCommand::Status => {
            info!(
                name = %cfg.name,
                hub_url = %cfg.hub_url,
                arch = %cfg.arch(),
                capacity = cfg.capacity,
                "Worker status (not yet implemented)"
            );
            return std::process::ExitCode::from(crbs_core::exit_code::USAGE as u8);
        }
    }

    std::process::ExitCode::SUCCESS
}

/// 按优先级查找默认配置文件路径。
fn find_config_file() -> Option<PathBuf> {
    let local = PathBuf::from("./worker.toml");
    if local.exists() {
        return Some(local);
    }
    match crbs_core::config::config_path("worker.toml") {
        Ok(p) if p.exists() => Some(p),
        _ => None,
    }
}

/// worker 关闭原因，仅用于日志。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownReason {
    Signal,
    Heartbeat,
    Poller,
}

/// 启动 worker 主循环。
async fn run_worker(cfg: WorkerConfig) -> crbs_core::Result<()> {
    info!(name = %cfg.name, hub = %cfg.hub_url, "Starting crbs-worker");
    let _ = crbs_core::privilege::init_privilege_backend(
        crbs_core::privilege::PrivilegedHelperMode::Auto,
        None,
        std::path::Path::new(&cfg.crbs_root),
    );
    info!(
        name = %cfg.name,
        "Worker identity derives from name+token; if another live process runs with this same \
         worker.toml, both receive the same assignments and builds execute twice writing the \
         same directories — ensure exactly one process per worker identity"
    );

    let resource_caps = match tokio::task::spawn_blocking(caps::probe_resource_caps_default).await {
        Ok(caps) => caps,
        Err(e) => {
            warn!(error = ?e, "Capability probe task failed; reporting no resource capabilities");
            0
        }
    };
    let registration = register_with_retry(&cfg, resource_caps).await?;
    info!(worker_id = %registration.worker_id, "Registered with Hub");

    match crbs_core::StateStore::new(std::path::Path::new(&cfg.build_dir)).await {
        Ok(store) => match store.gc_stale_local_builds().await {
            Ok(ids) if ids.is_empty() => {}
            Ok(ids) => info!(
                build_ids = ?ids,
                "Startup stale local build GC completed"
            ),
            Err(e) => {
                error!(error = %e, "Failed to GC stale local builds on startup");
            }
        },
        Err(e) => error!(error = %e, "Failed to open local state DB for stale build GC"),
    }

    if should_run_startup_gc(cfg.startup_mount_gc, registration.has_active_local_builds) {
        let crbs_root = cfg.crbs_root.clone();
        let tmp_dirs = vec![cfg.tmp_dir.clone().into(), cfg.tmpfs_dir.clone().into()];
        match tokio::task::spawn_blocking(move || {
            crbs_core::privilege::gc_orphan_mounts(std::path::Path::new(&crbs_root), &tmp_dirs)
        })
        .await
        {
            Ok(Ok(())) => {
                info!(
                    crbs_root = %cfg.crbs_root,
                    tmp_dirs = %format!("{}, {}", cfg.tmp_dir, cfg.tmpfs_dir),
                    "Startup orphan mount GC completed (scan domain: crbs_root subtree plus .tmp* container mounts under tmp dirs)"
                );
            }
            Ok(Err(e)) => {
                error!(crbs_root = %cfg.crbs_root, error = %e, "Failed to clean orphan mounts on startup");
            }
            Err(e) => {
                error!(crbs_root = %cfg.crbs_root, error = %e, "gc_orphan_mounts blocking task panicked");
            }
        }
    } else {
        let reason = if cfg.startup_mount_gc == config::StartupMountGc::Never {
            "startup_mount_gc = never (config)"
        } else {
            match registration.has_active_local_builds {
                Some(true) => "hub reports active builds (has_active_local_builds = true)",
                _ => "hub did not send has_active_local_builds (old hub); conservative skip",
            }
        };
        info!(
            crbs_root = %cfg.crbs_root,
            reason,
            "Skipping startup orphan mount GC; guarded cleanup remains available via `crbs gc --orphan-mounts`"
        );
    }

    let worker_id = registration.worker_id;

    let active_tasks = Arc::new(std::sync::atomic::AtomicI32::new(0));
    let active_build_ids: ActiveBuildIds =
        Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    let cancel_registry = poller::CancelRegistry::default();
    let cancel_token = CancellationToken::new();
    let mut hb_handle = heartbeat::spawn_heartbeat(
        worker_id,
        cfg.clone(),
        active_tasks.clone(),
        cancel_registry.clone(),
        cancel_token.clone(),
        resource_caps,
    );

    let mut poller_handle = poller::spawn_poller(
        worker_id,
        cfg.clone(),
        active_tasks.clone(),
        active_build_ids.clone(),
        cancel_registry.clone(),
        cancel_token.clone(),
    );

    let mut sweeper_handle =
        sweep::spawn_sweeper(cfg.clone(), active_build_ids.clone(), cancel_token.clone());

    #[cfg(unix)]
    let shutdown_reason = {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|e| CrbsError::io_message(format!("register SIGTERM handler: {}", e)))?;
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT, shutting down...");
                ShutdownReason::Signal
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down...");
                ShutdownReason::Signal
            }
            r = &mut hb_handle => {
                if let Err(e) = r {
                    error!(error = %e, "Heartbeat task exited");
                }
                ShutdownReason::Heartbeat
            }
            r = &mut poller_handle => {
                if let Err(e) = r {
                    error!(error = %e, "Poller task exited");
                }
                ShutdownReason::Poller
            }
        }
    };

    #[cfg(not(unix))]
    let shutdown_reason = tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => {
            info!("Received SIGINT, shutting down...");
            ShutdownReason::Signal
        }
        r = &mut hb_handle => {
            if let Err(e) = r {
                error!(error = %e, "Heartbeat task exited");
            }
            ShutdownReason::Heartbeat
        }
        r = &mut poller_handle => {
            if let Err(e) = r {
                error!(error = %e, "Poller task exited");
            }
            ShutdownReason::Poller
        }
    };

    cancel_token.cancel();

    if shutdown_reason != ShutdownReason::Heartbeat
        && tokio::time::timeout(Duration::from_secs(10), &mut hb_handle)
            .await
            .is_err()
    {
        warn!("Heartbeat task did not exit within 10s, proceeding with shutdown");
    }

    info!(reason = ?shutdown_reason, "Waiting for active tasks to finish...");
    if tokio::time::timeout(Duration::from_secs(30), async {
        while active_tasks.load(Ordering::Relaxed) > 0 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .is_err()
    {
        warn!(
            active_tasks = %active_tasks.load(Ordering::Relaxed),
            "Shutdown timeout: active tasks still running"
        );
    }

    if shutdown_reason != ShutdownReason::Poller
        && tokio::time::timeout(Duration::from_secs(10), &mut poller_handle)
            .await
            .is_err()
    {
        warn!("Poller task did not exit within 10s, proceeding with shutdown");
    }

    if tokio::time::timeout(Duration::from_secs(10), &mut sweeper_handle)
        .await
        .is_err()
    {
        warn!("Disk sweeper task did not exit within 10s, proceeding with shutdown");
    }

    let offline_outcome = tokio::time::timeout(Duration::from_secs(10), async {
        let mut last_err = None;
        for attempt in 1..=3u32 {
            match send_offline_heartbeat(
                worker_id,
                &cfg,
                active_tasks.load(Ordering::Relaxed) as usize,
            )
            .await
            {
                Ok(()) => {
                    last_err = None;
                    break;
                }
                Err(e) => {
                    if crate::error::is_auth_rejected(&e) {
                        debug!(error = %e, "Offline heartbeat rejected by auth, skipping retries");
                        last_err = Some(e);
                        break;
                    }
                    if attempt < 3 {
                        debug!(error = %e, attempt, "Offline heartbeat failed, retrying in 1s");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    last_err = Some(e);
                }
            }
        }
        last_err
    })
    .await;

    match offline_outcome {
        Ok(None) => {}
        Ok(Some(e)) => warn!(error = %e, "Failed to send offline heartbeat after retries"),
        Err(_) => warn!("Offline heartbeat timed out after 10s, continuing shutdown"),
    }

    info!("Worker shutdown complete");
    Ok(())
}

/// 发送 offline 心跳到 Hub（Worker 优雅退出时调用）。
async fn send_offline_heartbeat(
    worker_id: i64,
    cfg: &WorkerConfig,
    active_tasks: usize,
) -> crbs_core::Result<()> {
    let active = active_tasks;
    let client = cfg.build_http_client().await?;
    let url = format!("{}/api/v1/workers/{}/heartbeat", cfg.hub_url, worker_id);

    let payload = serde_json::json!({
        "status": "offline",
        "active_tasks": active,
    });

    let resp = client
        .post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| crate::error::reqwest("send offline heartbeat", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(crate::error::http_response_error(
            "offline heartbeat",
            status,
            text,
        ));
    }

    info!(worker_id = %worker_id, "Offline heartbeat sent");
    Ok(())
}

/// 注册结果：worker id + hub 下发的启动 GC 检查字段。
#[derive(Debug, Clone, Copy)]
struct Registration {
    worker_id: i64,
    /// hub DB 是否有活跃（building）构建；不下发 → None（保守跳过 GC）。
    has_active_local_builds: Option<bool>,
}

/// 启动注册的重试预算（独立于运行期 retry 家族——注册失败即退出服务，需覆盖
/// hub 滚动重启/网络抖动的分钟级窗口）：10 次尝试、指数退避（1s 起）封顶 30s
///（总跨度约 2-3 分钟）；4xx（如 secret 错误）不可自愈，立即失败不烧预算。
const REGISTER_MAX_ATTEMPTS: u32 = 10;
/// 启动注册退避上限。
const REGISTER_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(30);

/// 服务循环入口的注册：仅 transient 错误有界重试（判定与 retry 家族同一谓词，指数退避
/// 封顶 30s，见 [`REGISTER_MAX_ATTEMPTS`]）；启动档无 jitter（单进程一次性流程，无惊群面）。
async fn register_with_retry(
    cfg: &WorkerConfig,
    resource_caps: i64,
) -> crbs_core::Result<Registration> {
    let mut attempt = 1u32;
    loop {
        match register_once(cfg, resource_caps).await {
            Ok(registration) => return Ok(registration),
            Err(e) if attempt < REGISTER_MAX_ATTEMPTS && e.is_transient() => {
                let delay = std::time::Duration::from_secs(1u64 << (attempt - 1).min(9))
                    .min(REGISTER_BACKOFF_MAX);
                warn!(
                    attempt,
                    max_attempts = REGISTER_MAX_ATTEMPTS,
                    delay_secs = delay.as_secs(),
                    error = %e,
                    "Worker registration failed; retrying"
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// 向 Hub 注册一次，返回 Worker ID 与启动 GC 检查字段。`resource_caps` 为
/// 启动探测的能力位图（wire 可选字段，缺失按能力不可用降级）。
async fn register_once(cfg: &WorkerConfig, resource_caps: i64) -> crbs_core::Result<Registration> {
    let client = cfg.build_http_client().await?;
    let url = format!("{}/api/v1/workers/register", cfg.hub_url);

    let payload = serde_json::json!({
        "name": cfg.name,
        "arch": cfg.arch(),
        "capacity": cfg.capacity,
        "version": env!("CARGO_PKG_VERSION"),
        "resource_caps": resource_caps,
    });

    let resp = client
        .post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| crate::error::reqwest("register worker", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(crate::error::http_response_error(
            "registration",
            status,
            text,
        ));
    }

    let body: RegisterResponse = resp
        .json()
        .await
        .map_err(|e| crate::error::reqwest("decode registration response", e))?;

    Ok(Registration {
        worker_id: body.worker_id,
        has_active_local_builds: body.has_active_local_builds,
    })
}

/// 注册响应体（hub 侧 `RegisterResponse` 的 worker 本地镜像）：`has_active_local_builds`
/// 带 `#[serde(default)]` 容忍缺字段响应（None → 保守跳过启动 GC）；未知键
/// serde 默认忽略，禁用 `deny_unknown_fields`（与 AssignedTask/HeartbeatNotices 扩展约定一致）。
#[derive(serde::Deserialize)]
struct RegisterResponse {
    #[serde(rename = "id")]
    worker_id: i64,
    #[serde(default)]
    has_active_local_builds: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{read_request, test_cfg};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// 极简 mock hub：按序对每个请求返回预置状态码（200 带 {"id":42} body），返回实际收到的请求数。
    async fn serve_statuses(listener: TcpListener, statuses: Vec<u16>) -> usize {
        let mut count = 0;
        for status in statuses {
            let (mut sock, _) = listener.accept().await.unwrap();
            count += 1;
            read_request(&mut sock).await;
            let (line, body) = match status {
                200 => ("200 OK", r#"{"id":42}"#.to_string()),
                400 => ("400 Bad Request", "bad".to_string()),
                _ => ("503 Service Unavailable", "busy".to_string()),
            };
            let resp = format!(
                "HTTP/1.1 {line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
        }
        count
    }

    #[tokio::test]
    async fn register_with_retry_recovers_from_transient_503() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_statuses(listener, vec![503, 503, 200]));

        let cfg = test_cfg(format!("http://{addr}"), None).await;
        let reg = register_with_retry(&cfg, 0).await.unwrap();

        assert_eq!(reg.worker_id, 42);
        assert_eq!(server.await.unwrap(), 3, "两次 503 后第三次成功");
    }

    #[tokio::test]
    async fn register_with_retry_fails_immediately_on_4xx() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_statuses(listener, vec![400]));

        let cfg = test_cfg(format!("http://{addr}"), None).await;
        let err = register_with_retry(&cfg, 0).await.unwrap_err();

        assert!(
            matches!(err, CrbsError::ValidationFailed { .. }),
            "err: {err}"
        );
        assert_eq!(server.await.unwrap(), 1, "4xx 不得重试");
    }

    /// 响应仅 id → has_active_local_builds 为 None（保守跳过 GC）；带检查字段原样解析。
    #[test]
    fn register_response_guard_field_is_wire_compatible() {
        let old_hub: RegisterResponse =
            serde_json::from_str(r#"{"id":42,"status":"registered"}"#).unwrap();
        assert_eq!(old_hub.worker_id, 42);
        assert_eq!(
            old_hub.has_active_local_builds, None,
            "absent field must default to None"
        );

        let new_hub: RegisterResponse = serde_json::from_str(
            r#"{"id":42,"status":"registered","has_active_local_builds":true}"#,
        )
        .unwrap();
        assert_eq!(new_hub.has_active_local_builds, Some(true));
    }
}
