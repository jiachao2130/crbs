// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! crbs server：HTTP API 层。作为 CLI 的薄 wrapper，复用 BuildEngine/StateStore
//! 提供 RESTful API 供 CI/CD 集成。

pub(crate) mod artifacts_gc;
pub(crate) mod auth;
// batches 已接线（路由走快速段同步 + 慢段 spawn 的拆分形态）；allow 压制的是
// 仅测试读取的项：PrepareOutcome/PlanOutcome 汇总字段与测试注入缝。
#[allow(dead_code)]
pub(crate) mod batches;
pub(crate) mod bootstrap;
pub(crate) mod csrf;
pub(crate) mod error;
pub(crate) mod lifecycle;
pub(crate) mod log_buffer;
pub(crate) mod metrics;
pub(crate) mod rate_limit;
pub(crate) mod replay;
pub mod repo_regen;
pub(crate) mod resource_learning;
pub(crate) mod routes;

/// `_repo` 发布命名空间的目录名（repo_regen 与 routes::repo 共用；真源在
/// `engine::repo_publish`，跨 crate 同步义务见 engine 侧注释）。
pub(crate) const REPO_ROOT_DIR: &str = "_repo";
pub(crate) mod scheduler;
pub(crate) mod signing;
pub(crate) mod staging;
pub mod state;
pub(crate) mod tasks_gc;
#[cfg(feature = "tls")]
pub(crate) mod tls;
pub(crate) mod validation;
pub(crate) mod worker;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crbs_core::config::ServerConfig;
use crbs_core::error::CrbsError;
use crbs_core::StateStore;

use crate::server::state::AppState;

/// 启动 HTTP API server。listen/allow_product_management/shutdown_timeout_secs 为 CLI 覆盖值，默认读
/// /etc/crbs/server.toml；传入 state_store 避免重复建池。
pub async fn run(
    listen: Option<&str>,
    config_dir: Option<&std::path::Path>,
    allow_product_management: Option<bool>,
    shutdown_timeout_secs: Option<u64>,
    run_dir: Option<&std::path::Path>,
    state_store: Option<Arc<StateStore>>,
    web_ui_enabled: Option<bool>,
) -> crbs_core::Result<()> {
    let (server_config, app_state, app) = bootstrap::prepare_server(
        config_dir,
        allow_product_management,
        shutdown_timeout_secs,
        state_store,
        run_dir.map(|p| p.to_path_buf()),
        web_ui_enabled,
    )
    .await?;

    let addr = listen.unwrap_or(&server_config.listen);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| CrbsError::from_io_context("bind", e))?;

    tracing::info!(addr = %addr, "crbs server listening");
    lifecycle::serve_forever(
        listener,
        app_state,
        app,
        server_config.shutdown_timeout_secs,
        None,
    )
    .await
}

/// 启动本地 daemon：绑定随机端口，写入 pid/port 文件，空闲时自动退出。
pub async fn run_local_daemon(
    run_dir: Option<&std::path::Path>,
    config_dir: Option<&std::path::Path>,
) -> crbs_core::Result<()> {
    bootstrap::set_config_dir(config_dir);

    let server_config = ServerConfig::load_async(
        &config_dir
            .map(|d| d.join("server.toml"))
            .unwrap_or_else(|| PathBuf::from("/etc/crbs/server.toml")),
    )
    .await?;
    let run_dir = run_dir
        .map(|p| p.to_path_buf())
        .or_else(|| server_config.local.run_dir.clone())
        .unwrap_or_else(|| default_run_dir(&server_config.server_crbs_root()));

    let (server_config, app_state, app) =
        bootstrap::prepare_server(config_dir, None, None, None, Some(run_dir.clone()), None)
            .await?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| CrbsError::from_io_context("bind", e))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| CrbsError::from_io_context("get local addr", e))?;
    let port = local_addr.port();

    write_port_file(&run_dir, port).await?;

    tracing::info!(
        run_dir = %run_dir.display(),
        port = %port,
        "crbs local daemon listening"
    );

    let idle_timeout = server_config.local.idle_timeout_secs;
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
    let mut cancel_tx = Some(cancel_tx);

    if idle_timeout > 0 {
        let state = app_state.clone();
        let run_dir_clone = run_dir.clone();
        tokio::spawn(async move {
            if lifecycle::idle_shutdown_watcher(state, idle_timeout, &run_dir_clone)
                .await
                .is_ok()
            {
                let _ = cancel_tx.take().map(|tx| tx.send(()));
            }
        });
    }

    let result = lifecycle::serve_forever(
        listener,
        app_state.clone(),
        app,
        server_config.shutdown_timeout_secs,
        Some(cancel_rx),
    )
    .await;

    let _ = remove_own_pid_port_files(&run_dir).await;
    result
}

/// 默认 run_dir：root 身份使用 `/run/crbs`，其余用户使用
/// `{crbs_root}/run`。
pub fn default_run_dir(crbs_root: &Path) -> PathBuf {
    if nix::unistd::getuid().is_root() {
        PathBuf::from("/run/crbs")
    } else {
        crbs_root.join("run")
    }
}

#[derive(Debug)]
/// 单活锁 guard：持有期间保证 pidfile 存在，Drop 时清理；阻止同一 crbs_root 下多实例并发，是 pending recovery / zombie repair
/// 正确的前提。创建锁的进程 pid：Drop 时只删除仍归属本进程的 pidfile。
pub struct ServerLockGuard {
    path: PathBuf,

    pid: u32,
}

impl ServerLockGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            pid: std::process::id(),
        }
    }
}

impl Drop for ServerLockGuard {
    fn drop(&mut self) {
        let owned = std::fs::read_to_string(&self.path)
            .map(|t| t.trim().parse::<u32>().ok() == Some(self.pid))
            .unwrap_or(false);
        if !owned {
            tracing::debug!(
                path = %self.path.display(),
                "pidfile no longer owned by this process; skip cleanup"
            );
            return;
        }
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %self.path.display(), err = ?e, "failed to remove server pidfile");
            }
        }
    }
}

/// 获取 server 单活锁：create_new 原子创建 run_dir/crbs-server.pid，消除"读 pidfile → 判活 → 覆盖写"的 TOCTOU 竞态。成功 →
/// 写 PID 返回 guard；已存在且 PID 存活（含刚创建未写 PID 的启动窗口）→ 失败即拒绝；PID 已死/内容非法（陈旧）→ 删除后重试一次原子创建。
async fn acquire_server_lock(run_dir: &Path) -> crbs_core::Result<ServerLockGuard> {
    tokio::fs::create_dir_all(run_dir)
        .await
        .map_err(|e| CrbsError::from_io_context("create run_dir", e))?;

    let perms = std::fs::Permissions::from_mode(0o2770);
    if let Err(e) = tokio::fs::set_permissions(run_dir, perms).await {
        tracing::warn!(run_dir = %run_dir.display(), error = %e, "failed to chmod run_dir to 2770");
    }

    crbs_core::privilege::chown_to_crbs_group_async(run_dir, false, "run_dir").await;
    let path = run_dir.join("crbs-server.pid");

    let file = match open_pidfile_new(&path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            reject_live_or_remove_stale(&path).await?;

            open_pidfile_new(&path).await.map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => CrbsError::ValidationFailed {
                    message:
                        "another crbs-server won the pidfile race while cleaning a stale lock; retry start"
                            .into(),
                },
                _ => CrbsError::from_io_context("create pidfile", e),
            })?
        }
        Err(e) => return Err(CrbsError::from_io_context("create pidfile", e)),
    };

    let mut file = file;
    tokio::io::AsyncWriteExt::write_all(&mut file, format!("{}\n", std::process::id()).as_bytes())
        .await
        .map_err(|e| CrbsError::from_io_context("write pidfile", e))?;

    tokio::io::AsyncWriteExt::flush(&mut file)
        .await
        .map_err(|e| CrbsError::from_io_context("flush pidfile", e))?;

    Ok(ServerLockGuard::new(path))
}

/// 以 create_new 原子创建 pidfile。权限不变量：0660 + crbs 组（.mode 受 umask 削减，创建后显式 set_permissions，失败 warn；
/// chown 失败仅 debug）。create_new 与写 PID 间的空窗口：并发方读到空文件会按"另一实例在启动"拒绝，不误判陈旧；flush 把窗口收口到函数返回前。
async fn open_pidfile_new(path: &Path) -> std::io::Result<tokio::fs::File> {
    let file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o660)
        .open(path)
        .await?;
    if let Err(e) = file
        .set_permissions(std::fs::Permissions::from_mode(0o660))
        .await
    {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "failed to chmod pidfile to 0660 (perms may not be effective)"
        );
    }
    crbs_core::privilege::chown_to_crbs_group_async(path, false, "server pidfile").await;
    Ok(file)
}

/// pidfile 已存在时判定归属：PID 存活 → Err（拒绝启动）；文件为空 → 另一实例处于"已创建未写入"启动窗口 → Err（失败即拒绝）；PID 已死/内容非法（陈旧）→
/// 删除文件返回 Ok，调用方重试创建。
async fn reject_live_or_remove_stale(path: &Path) -> crbs_core::Result<()> {
    let text = match tokio::fs::read_to_string(path).await {
        Ok(t) => t,

        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(CrbsError::from_io_context("read pidfile", e)),
    };

    match text.trim().parse::<i64>() {
        Ok(pid) if pid > 0 && crbs_core::util::is_process_alive(pid).await => Err(
            CrbsError::ValidationFailed {
                message: format!(
                    "another crbs-server appears to be running (pid {pid}); \
                     running multiple server instances against the same crbs_root is not supported"
                ),
            },
        ),
        Ok(_) => {
            tracing::info!(path = %path.display(), "Found stale pidfile, taking over");
            remove_stale_pidfile(path).await
        }
        Err(_) if text.trim().is_empty() => Err(CrbsError::ValidationFailed {
            message:
                "another crbs-server appears to be starting (pidfile exists but has no PID yet); retry shortly"
                    .into(),
        }),
        Err(_) => {
            tracing::info!(path = %path.display(), "Pidfile has invalid content, taking over");
            remove_stale_pidfile(path).await
        }
    }
}

async fn remove_stale_pidfile(path: &Path) -> crbs_core::Result<()> {
    if let Err(e) = tokio::fs::remove_file(path).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(CrbsError::from_io_context("remove stale pidfile", e));
        }
    }
    Ok(())
}

async fn write_port_file(run_dir: &Path, port: u16) -> crbs_core::Result<()> {
    let path = run_dir.join("crbs-server.port");
    tokio::fs::write(&path, format!("{}\n", port))
        .await
        .map_err(|e| CrbsError::from_io_context("write portfile", e))?;
    if let Err(e) = tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).await
    {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "failed to chmod portfile to 0660 (perms may not be effective)"
        );
    }
    crbs_core::privilege::chown_to_crbs_group_async(&path, false, "server portfile").await;
    Ok(())
}

async fn remove_own_pid_port_files(run_dir: &Path) -> crbs_core::Result<()> {
    let pid_file = run_dir.join("crbs-server.pid");
    match tokio::fs::read_to_string(&pid_file).await {
        Ok(text) if text.trim().parse::<u32>().ok() == Some(std::process::id()) => {
            remove_pid_port_files(run_dir).await
        }

        Ok(_) => {
            tracing::debug!("pidfile no longer owned by this process; skip cleanup");
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(CrbsError::from_io_context(
            "read pidfile for ownership check",
            e,
        )),
    }
}

pub async fn remove_pid_port_files(run_dir: &Path) -> crbs_core::Result<()> {
    for name in &["crbs-server.pid", "crbs-server.port"] {
        let path = run_dir.join(name);
        if let Err(e) = tokio::fs::remove_file(&path).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(CrbsError::from_io_context(format!("remove {}", name), e));
            }
        }
    }
    Ok(())
}

/// 写入 crbs-server root 归属标记文件。mode 0640（owner 读写、crbs 组只
/// 读）；chown 失败仅记 debug（非 root 进程 chown 必然 EPERM，属预期路径，
/// 组读权限已足够）。幂等：每次启动覆盖写。
pub(super) async fn write_server_root_marker(crbs_root: &std::path::Path) -> crbs_core::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let marker_path = crbs_root.join(crbs_core::SERVER_ROOT_MARKER);
    let content = format!(
        "crbs-server root: engine CLI must use its own crbs_root (default /var/lib/crbs-engine)\nv{}\n",
        env!("CARGO_PKG_VERSION")
    );
    tokio::fs::write(&marker_path, content)
        .await
        .map_err(|e| CrbsError::from_io_context("write server root marker", e))?;
    if let Err(e) =
        tokio::fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o640)).await
    {
        tracing::warn!(
            path = %marker_path.display(),
            error = %e,
            "Failed to set server root marker mode 0640"
        );
    }
    crbs_core::privilege::chown_to_crbs_group_async(&marker_path, false, "server root marker")
        .await;
    tracing::debug!(path = %marker_path.display(), "server root marker written");
    Ok(())
}

async fn ensure_crbs_root(crbs_root: &std::path::Path) -> crbs_core::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if !tokio::fs::try_exists(crbs_root).await.unwrap_or(false) {
        tokio::fs::create_dir_all(crbs_root)
            .await
            .map_err(|e| CrbsError::from_io_context("create crbs_root", e))?;
        let perms = std::fs::Permissions::from_mode(0o2770);
        tokio::fs::set_permissions(crbs_root, perms)
            .await
            .map_err(|e| CrbsError::from_io_context("set crbs_root permissions", e))?;
        tracing::info!(path = %crbs_root.display(), "created crbs_root");
    }

    #[cfg(unix)]
    {
        if nix::unistd::getuid().is_root() {
            const SERVER_USER: &str = "crbs-server";
            const SERVER_GROUP: &str = "crbs";

            let path = crbs_root.to_path_buf();
            let user = SERVER_USER.to_string();
            let group = SERVER_GROUP.to_string();
            tokio::task::spawn_blocking(move || {
                crbs_core::privilege::mkdir_chown(&path, &user, &group, 0o2770)
            })
            .await
            .map_err(|e| CrbsError::Internal(e.to_string()))??;
            tracing::info!(
                path = %crbs_root.display(),
                user = %SERVER_USER,
                group = %SERVER_GROUP,
                "fixed crbs_root ownership"
            );
        } else {
            let meta = tokio::fs::metadata(crbs_root)
                .await
                .map_err(|e| CrbsError::from_io_context("stat crbs_root", e))?;
            let perms = meta.permissions().mode();
            if perms & 0o200 == 0 {
                return Err(CrbsError::PermissionDenied {
                    message: format!(
                        "crbs_root {} is not writable by current user (mode={:04o})",
                        crbs_root.display(),
                        perms & 0o7777
                    ),
                });
            }
        }
    }

    Ok(())
}

/// 测试辅助：组装 public + protected 全量路由（无鉴权中间件）；与生产装配
/// （bootstrap prepare_server）的 merge 顺序一致性由
/// integration_route_inventory 测试守卫。
pub fn create_test_app(app_state: Arc<AppState>) -> axum::Router {
    let (public, protected) = assemble_test_routers(&app_state);

    axum::Router::new()
        .merge(public)
        .merge(protected)
        .with_state(app_state)
}

/// 测试辅助：[`create_test_app`] 的带鉴权版本——protected 路由套完整鉴权
/// 中间件（route_layer，未匹配路由返回 404 而非 401），public 路由套可选
/// 鉴权。
pub fn create_test_app_with_auth(app_state: Arc<AppState>) -> axum::Router {
    let (public, protected) = assemble_test_routers(&app_state);

    let auth_state = Arc::new(crate::server::auth::AuthMiddlewareState {
        app_state: app_state.clone(),
    });
    let protected = protected.route_layer(axum::middleware::from_fn_with_state(
        auth_state.clone(),
        crate::server::auth::auth_middleware,
    ));
    let public = public.layer(axum::middleware::from_fn_with_state(
        auth_state,
        crate::server::auth::optional_auth_middleware,
    ));

    axum::Router::new()
        .merge(public)
        .merge(protected)
        .with_state(app_state)
}

fn assemble_test_routers(
    app_state: &Arc<AppState>,
) -> (axum::Router<Arc<AppState>>, axum::Router<Arc<AppState>>) {
    let protected = axum::Router::new()
        .merge(routes::admin::router())
        .merge(routes::artifacts::protected_router())
        .merge(routes::batches::router())
        .merge(routes::builds::router(50 * 1024 * 1024))
        .merge(routes::health::protected_router())
        .merge(routes::logs::router())
        .merge(routes::profile::router())
        .merge(routes::gc::router())
        .merge(routes::product::router())
        .merge(routes::resource_profiles::router())
        .merge(routes::tasks::router())
        .merge(crate::server::worker::routes::router());

    let public = axum::Router::new()
        .merge(routes::health::public_router())
        .merge(routes::artifacts::public_router())
        .merge(routes::reproducibility::public_router())
        .merge(routes::tasks::public_router())
        .merge(routes::nihao::router())
        .merge(routes::repo::router());

    let public = if app_state.server_config.web_ui_enabled {
        public.merge(routes::ui::public_router(app_state))
    } else {
        public
    };

    (public, protected)
}

/// 测试辅助：创建指定角色 DB 用户并签发 user token，返回原始 `crbs_tok_…` 字符串；
/// 仅供测试使用，不参与生产认证路径。
#[doc(hidden)]
pub async fn seed_user_token_for_test(
    state_store: &crbs_core::StateStore,
    name: &str,
    role: &str,
) -> crbs_core::Result<String> {
    use crbs_core::auth::secret::{Secret, SecretHash, SecretKind};
    let user_id = state_store.create_user(name, role).await?;
    let secret = Secret::generate(SecretKind::UserToken)
        .map_err(|e| crbs_core::error::CrbsError::Internal(format!("generate secret: {e}")))?;
    state_store
        .create_user_token(
            user_id,
            Some("test"),
            SecretHash::from_plain(secret.as_str()).as_str(),
            None,
        )
        .await?;
    Ok(secret.as_str().to_string())
}

/// 仅供测试使用。
#[doc(hidden)]
pub async fn seed_worker_secret_for_test(
    state_store: &crbs_core::StateStore,
    name: &str,
    arch: &str,
) -> crbs_core::Result<(i64, String)> {
    use crbs_core::auth::secret::{Secret, SecretKind};
    let worker_id = state_store
        .upsert_worker(name, arch, 1, "test", "online", None)
        .await?;
    let secret = Secret::generate(SecretKind::WorkerSecret)
        .map_err(|e| crbs_core::error::CrbsError::Internal(format!("generate secret: {e}")))?;
    state_store
        .set_worker_secret(worker_id, secret.hash().as_str())
        .await?;
    Ok((worker_id, secret.as_str().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crbs_core::BuildInsert;
    use crbs_core::StateStore;

    #[tokio::test]
    async fn server_lock_rejects_concurrent_instance() {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path();

        let lock = acquire_server_lock(run_dir).await.unwrap();

        let err = acquire_server_lock(run_dir).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("another crbs-server"),
            "expected concurrent lock rejection, got: {msg}"
        );

        drop(lock);

        let _lock2 = acquire_server_lock(run_dir).await.unwrap();
    }

    #[tokio::test]
    async fn server_lock_takes_over_stale_pidfile() {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path();
        let path = run_dir.join("crbs-server.pid");

        tokio::fs::write(&path, "99999999\n").await.unwrap();

        let _lock = acquire_server_lock(run_dir).await.unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content.trim(), std::process::id().to_string());
    }

    #[tokio::test]
    async fn pidfile_is_created_0660() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path();

        let _lock = acquire_server_lock(run_dir).await.unwrap();

        let mode = std::fs::metadata(run_dir.join("crbs-server.pid"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o660, "pidfile must be 0660, got {:04o}", mode);
    }

    #[tokio::test]
    async fn portfile_is_written_0660() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path();

        write_port_file(run_dir, 4242).await.unwrap();

        let mode = std::fs::metadata(run_dir.join("crbs-server.port"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o660, "portfile must be 0660, got {:04o}", mode);
    }

    #[tokio::test]
    async fn server_lock_rejects_empty_pidfile_and_preserves_it() {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path();
        let path = run_dir.join("crbs-server.pid");
        tokio::fs::write(&path, "").await.unwrap();

        let err = acquire_server_lock(run_dir).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("another crbs-server"),
            "expected fail-closed rejection, got: {msg}"
        );
        assert!(
            path.exists(),
            "empty pidfile must be preserved for the starting instance"
        );
    }

    #[tokio::test]
    async fn server_lock_allows_exactly_one_concurrent_starter() {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path().to_path_buf();

        let mut handles = Vec::new();
        for _ in 0..2 {
            let dir = run_dir.clone();
            handles.push(tokio::spawn(async move { acquire_server_lock(&dir).await }));
        }

        let mut winners = 0;
        let mut _guards = Vec::new();
        for h in handles {
            if let Ok(g) = h.await.unwrap() {
                winners += 1;
                _guards.push(g);
            }
        }
        assert_eq!(
            winners, 1,
            "exactly one concurrent starter should win the pidfile lock"
        );
    }

    use crate::test_support::lock_config_env;

    async fn write_test_server_config(dir: &std::path::Path, content: &str) -> std::path::PathBuf {
        let config_dir = dir.join("crbs-config");
        tokio::fs::create_dir_all(&config_dir).await.unwrap();
        tokio::fs::write(config_dir.join("server.toml"), content)
            .await
            .unwrap();
        config_dir
    }

    #[tokio::test]
    async fn prepare_server_rejects_zero_shutdown_timeout() {
        crate::test_support::pin_setuid_privilege_backend();
        let _env = lock_config_env();
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = write_test_server_config(
            tmp.path(),
            "listen = \"127.0.0.1:0\"\nshutdown_timeout_secs = 0\nauth_enabled = false\n",
        )
        .await;

        let result =
            super::bootstrap::prepare_server(Some(&config_dir), None, None, None, None, None).await;
        let msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected shutdown_timeout_secs error, got Ok"),
        };
        assert!(
            msg.contains("shutdown_timeout_secs"),
            "expected shutdown_timeout_secs error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn prepare_server_rejects_product_management_without_auth() {
        crate::test_support::pin_setuid_privilege_backend();
        let _env = lock_config_env();
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = write_test_server_config(
            tmp.path(),
            "listen = \"127.0.0.1:0\"\nshutdown_timeout_secs = 60\nauth_enabled = false\nallow_product_management = true\n",
        )
        .await;

        let result =
            super::bootstrap::prepare_server(Some(&config_dir), None, None, None, None, None).await;
        let msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected allow_product_management error, got Ok"),
        };
        assert!(
            msg.contains("allow_product_management"),
            "expected allow_product_management error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn prepare_server_fails_on_unwritable_result_dir() {
        crate::test_support::pin_setuid_privilege_backend();
        use std::os::unix::fs::PermissionsExt;

        if nix::unistd::geteuid().is_root() {
            return;
        }
        let _env = lock_config_env();
        let tmp = tempfile::tempdir().unwrap();
        let crbs_root = tmp.path().join("crbs");
        let result_dir = tmp.path().join("ro-results");
        std::fs::create_dir_all(&result_dir).unwrap();
        std::fs::set_permissions(&result_dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let config_dir = write_test_server_config(
            tmp.path(),
            &format!(
                "listen = \"127.0.0.1:0\"\nshutdown_timeout_secs = 60\nauth_enabled = false\ncrbs_root = \"{}\"\nresult_dir = \"{}\"\n",
                crbs_root.display(),
                result_dir.display()
            ),
        )
        .await;

        let result =
            super::bootstrap::prepare_server(Some(&config_dir), None, None, None, None, None).await;

        let _ = std::fs::set_permissions(&result_dir, std::fs::Permissions::from_mode(0o700));
        let msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected unwritable result_dir error, got Ok"),
        };
        assert!(
            msg.contains("not writable"),
            "expected not-writable error, got: {msg}"
        );
        assert!(
            msg.contains(&result_dir.display().to_string()),
            "error should name the offending path, got: {msg}"
        );
    }

    #[tokio::test]
    async fn prepare_server_does_not_preoccupy_permits_for_assigned_builds() {
        crate::test_support::pin_setuid_privilege_backend();
        let _env = lock_config_env();
        let tmp = tempfile::tempdir().unwrap();
        let crbs_root = tmp.path().join("crbs");
        let config_dir = tmp.path().join("crbs-config");
        tokio::fs::create_dir_all(&config_dir).await.unwrap();

        tokio::fs::write(
            config_dir.join("server.toml"),
            format!(
                "listen = \"127.0.0.1:0\"\nshutdown_timeout_secs = 60\nauth_enabled = false\nmax_local_builds = 2\ncrbs_root = \"{}\"\n",
                crbs_root.display()
            ),
        )
        .await
        .unwrap();

        tokio::fs::create_dir_all(&crbs_root).await.unwrap();
        let store = Arc::new(StateStore::new(&crbs_root).await.unwrap());
        let task_id = crate::test_support::seed_task(&store, "test", "pkg").await;
        let _build_id = store
            .insert_build(BuildInsert {
                product: "test",
                pkg_name: "pkg",
                phase: "assigned",
                backend: "chroot",
                user: "tester",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        let (_cfg, app_state, _router) = super::bootstrap::prepare_server(
            Some(&config_dir),
            None,
            None,
            Some(store),
            Some(crbs_root.clone()),
            None,
        )
        .await
        .expect("prepare_server should succeed");

        assert_eq!(
            app_state.build_semaphore.available_permits(),
            2,
            "assigned (distributed) build must not pre-occupy local semaphore permits"
        );

        app_state.shutdown_cancel.cancel();
    }

    #[tokio::test]
    async fn submit_rate_limit_counts_per_user_after_auth() {
        crate::test_support::pin_setuid_privilege_backend();
        use tower::ServiceExt;

        let _env = lock_config_env();
        let tmp = tempfile::tempdir().unwrap();
        let crbs_root = tmp.path().join("crbs");
        let config_dir = tmp.path().join("crbs-config");
        tokio::fs::create_dir_all(&config_dir).await.unwrap();
        tokio::fs::write(
            config_dir.join("server.toml"),
            format!(
                "listen = \"127.0.0.1:0\"\nshutdown_timeout_secs = 60\nauth_enabled = true\ncrbs_root = \"{}\"\n\n[submit_rate_limit]\nenabled = true\nrequests = 2\nper_secs = 60\n",
                crbs_root.display()
            ),
        )
        .await
        .unwrap();

        let (_cfg, app_state, app) = super::bootstrap::prepare_server(
            Some(&config_dir),
            None,
            None,
            None,
            Some(crbs_root.clone()),
            None,
        )
        .await
        .expect("prepare_server should succeed");
        app_state.shutdown_cancel.cancel();

        let alice = seed_user_token_for_test(&app_state.state_store, "rl-alice", "builder")
            .await
            .unwrap();
        let bob = seed_user_token_for_test(&app_state.state_store, "rl-bob", "builder")
            .await
            .unwrap();

        let post_builds = |token: Option<String>| {
            let mut builder = axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/builds")
                .header("Content-Type", "application/json");
            if let Some(t) = token {
                builder = builder.header("Authorization", format!("Bearer {t}"));
            }
            builder
                .body(axum::body::Body::from(r#"{"product":"test","srpms":[]}"#))
                .unwrap()
        };

        for _ in 0..3 {
            let resp = app.clone().oneshot(post_builds(None)).await.unwrap();
            assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
        }

        for i in 0..2 {
            let resp = app
                .clone()
                .oneshot(post_builds(Some(alice.clone())))
                .await
                .unwrap();
            assert_ne!(
                resp.status(),
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "alice request {} should pass the limiter",
                i + 1
            );
        }
        let resp = app
            .clone()
            .oneshot(post_builds(Some(alice.clone())))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);

        let resp = app
            .clone()
            .oneshot(post_builds(Some(bob.clone())))
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "bob's quota must be independent of alice's"
        );
    }

    #[tokio::test]
    async fn ui_task_submit_counts_into_submit_rate_limit() {
        crate::test_support::pin_setuid_privilege_backend();
        use tower::ServiceExt;

        let _env = lock_config_env();
        let tmp = tempfile::tempdir().unwrap();
        let crbs_root = tmp.path().join("crbs");
        let config_dir = tmp.path().join("crbs-config");
        tokio::fs::create_dir_all(&config_dir).await.unwrap();
        tokio::fs::write(
            config_dir.join("server.toml"),
            format!(
                "listen = \"127.0.0.1:0\"\nshutdown_timeout_secs = 60\nauth_enabled = true\ncrbs_root = \"{}\"\n\n[submit_rate_limit]\nenabled = true\nrequests = 1\nper_secs = 60\n",
                crbs_root.display()
            ),
        )
        .await
        .unwrap();

        let (_cfg, app_state, app) = super::bootstrap::prepare_server(
            Some(&config_dir),
            None,
            None,
            None,
            Some(crbs_root.clone()),
            None,
        )
        .await
        .expect("prepare_server should succeed");
        app_state.shutdown_cancel.cancel();

        let bob = seed_user_token_for_test(&app_state.state_store, "rl-ui-bob", "builder")
            .await
            .unwrap();
        let carol = seed_user_token_for_test(&app_state.state_store, "rl-ui-carol", "builder")
            .await
            .unwrap();

        let multipart_body =
            b"--b\r\nContent-Disposition: form-data; name=\"product\"\r\n\r\np\r\n\
             --b\r\nContent-Disposition: form-data; name=\"srpm\"; filename=\"x-1.0-1.src.rpm\"\r\n\
             Content-Type: application/octet-stream\r\n\r\nxx\r\n--b--\r\n";
        let post_ui = |token: &str| {
            axum::http::Request::builder()
                .method("POST")
                .uri("/ui/tasks/new")
                .header("Cookie", format!("crbs_token={token}"))
                .header("Content-Type", "multipart/form-data; boundary=b")
                .body(axum::body::Body::from(multipart_body.to_vec()))
                .unwrap()
        };

        let resp = app.clone().oneshot(post_ui(&bob)).await.unwrap();
        assert_ne!(
            resp.status(),
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "first UI submit must pass the limiter"
        );

        let resp = app.clone().oneshot(post_ui(&bob)).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);

        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v1/builds")
                    .header("Authorization", format!("Bearer {bob}"))
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(r#"{"product":"p","srpms":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "API submit must share the UI-consumed quota"
        );

        let resp = app.oneshot(post_ui(&carol)).await.unwrap();
        assert_ne!(
            resp.status(),
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "carol's quota must be independent of bob's"
        );
    }
}

#[cfg(test)]
mod marker_tests {
    use super::*;

    #[tokio::test]
    async fn write_server_root_marker_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("server-root");
        std::fs::create_dir_all(&root).unwrap();

        write_server_root_marker(&root).await.unwrap();
        let marker_path = root.join(crbs_core::SERVER_ROOT_MARKER);
        let first = std::fs::read_to_string(&marker_path).unwrap();
        assert!(
            first.contains("crbs-server root"),
            "marker content: {first}"
        );

        write_server_root_marker(&root).await.unwrap();
        let second = std::fs::read_to_string(&marker_path).unwrap();
        assert_eq!(first, second);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&marker_path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o640,
                "marker must be 0640 (group readable), got {:04o}",
                mode & 0o777
            );
        }
    }

    #[tokio::test]
    async fn engine_open_rejected_after_server_marker_write() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("server-root");
        std::fs::create_dir_all(&root).unwrap();

        write_server_root_marker(&root).await.unwrap();
        let err = match crbs_core::StateStore::open_for_engine(&root).await {
            Ok(_) => panic!("open_for_engine must reject a server marker root"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("crbs-server root"));
    }
}
