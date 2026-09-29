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
// 仅测试读取的项：PrepareOutcome/PlanOutcome 汇总字段（断言消费）与测试注入缝。
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

/// `_repo` 发布命名空间目录名（repo_regen 与 routes::repo 共用；真源在
/// `engine::repo_publish`，跨 crate 手抄同步义务见 engine 侧注释）。
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

/// 启动 HTTP API server。
///
/// `listen`/`allow_product_management`/`shutdown_timeout_secs` 为 CLI 覆盖值，缺省
/// 读 `/etc/crbs/server.toml`（缺文件用硬编码默认）；传入 `state_store` 避免重复建池。
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
    // 先设 CRBS_CONFIG_DIR：load_async 依赖它定位 server.toml，否则 --config-dir
    // 下 crbs_root 取默认值，pidfile/portfile 写错位置。
    bootstrap::set_config_dir(config_dir);
    // run_dir 须在 prepare_server 前确定（据此取单活锁并写 pidfile）；默认值随 server root（缺省 /var/lib/crbs）。
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

/// 默认 run_dir：root 用 /run/crbs，否则 {crbs_root}/run。
pub fn default_run_dir(crbs_root: &Path) -> PathBuf {
    if nix::unistd::getuid().is_root() {
        PathBuf::from("/run/crbs")
    } else {
        crbs_root.join("run")
    }
}

/// 单活锁 guard：持有期间保证 pidfile 存在，Drop 时清理；阻止同一 `crbs_root`
/// 下多实例并发，是 pending recovery / zombie repair 正确的前提。
#[derive(Debug)]
pub struct ServerLockGuard {
    path: PathBuf,
    /// 创建锁的进程 pid：Drop 时只删除仍归属本进程的 pidfile。
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
        // 归属校验后再删：stop→start 快速轮换下新实例可能已重建 pidfile，无条件
        // 删会删掉新实例的锁文件；内容不匹配（含读失败）即放弃清理。
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

/// 获取 server 单活锁：`create_new` 原子创建 `run_dir/crbs-server.pid`，消除
/// "读 pidfile → 判活 → 覆盖写" 的 TOCTOU 竞态（锁是 recovery/repair 正确前提）。
/// 成功 → 写 PID 返回 guard，server 退出自动删；已存在且 PID 存活（含刚创建
/// 未写 PID 的启动窗口）→ fail-closed 拒绝；PID 已死/内容非法（陈旧）→ 删除后
/// 重试一次原子创建。
async fn acquire_server_lock(run_dir: &Path) -> crbs_core::Result<ServerLockGuard> {
    tokio::fs::create_dir_all(run_dir)
        .await
        .map_err(|e| CrbsError::from_io_context("create run_dir", e))?;
    // create_dir_all 受 umask 影响可能缺组写位，显式 2770 保 crbs 组可写。
    let perms = std::fs::Permissions::from_mode(0o2770);
    if let Err(e) = tokio::fs::set_permissions(run_dir, perms).await {
        tracing::warn!(run_dir = %run_dir.display(), error = %e, "failed to chmod run_dir to 2770");
    }
    // chown 到 crbs 组（保留 SGID）：root 创建后 group=root，组成员读不到内部文件。
    crbs_core::privilege::chown_to_crbs_group_async(run_dir, false, "run_dir").await;
    let path = run_dir.join("crbs-server.pid");

    let file = match open_pidfile_new(&path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // 已存在：判活后要么拒绝，要么删陈旧文件重试一次。
            reject_live_or_remove_stale(&path).await?;
            // 重试再撞 AlreadyExists = 另一实例恰在窗口内抢先创建，按并发冲突拒绝。
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

    // create_new 与写 PID 间的空窗口：并发方读到空文件会 fail-closed，不误判陈旧。
    let mut file = file;
    tokio::io::AsyncWriteExt::write_all(&mut file, format!("{}\n", std::process::id()).as_bytes())
        .await
        .map_err(|e| CrbsError::from_io_context("write pidfile", e))?;
    // 契约收口：write_all 返回不保证内容已落内核（tokio File 写在途），外部读者
    // 可能读到空 pidfile；flush 把窗口收口到函数返回前（并发启动方本就 fail-closed）。
    tokio::io::AsyncWriteExt::flush(&mut file)
        .await
        .map_err(|e| CrbsError::from_io_context("flush pidfile", e))?;

    Ok(ServerLockGuard::new(path))
}

/// 以 `create_new` 原子创建 pidfile（仅文件不存在时成功）。权限不变量：
/// 0660 + crbs 组；`.mode(0o660)` 受 umask 削减，创建后显式 set_permissions
/// 收口（失败 warn）；chown 失败仅 debug（非 root 必然 EPERM，预期路径）。
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

/// pidfile 已存在时判定归属：PID 存活 → Err（拒绝启动）；文件为空 → 另一实例
/// 处于"已创建未写入"启动窗口 → Err（fail-closed）；PID 已死/内容非法（陈旧）→
/// 删除文件返回 Ok，调用方重试创建。
async fn reject_live_or_remove_stale(path: &Path) -> crbs_core::Result<()> {
    let text = match tokio::fs::read_to_string(path).await {
        Ok(t) => t,
        // 读取期间文件被并发方删除：让调用方直接重试创建。
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

/// 删除陈旧 pidfile；NotFound（并发方已删）视为成功。
async fn remove_stale_pidfile(path: &Path) -> crbs_core::Result<()> {
    if let Err(e) = tokio::fs::remove_file(path).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(CrbsError::from_io_context("remove stale pidfile", e));
        }
    }
    Ok(())
}

/// 写 portfile。权限不变量：0660 + crbs 组；`tokio::fs::write` 落 umask 缺省
/// （022 下 0644），写后显式 set_permissions(0o660) 收口（失败 warn）；
/// chown 失败仅 debug（非 root 必然 EPERM，预期路径）。
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

/// 删除 pid/port 文件：仅当 pidfile 记录**本进程** pid 时才删（stop→start 快速
/// 轮换下，旧 daemon 按共享名无条件删会删掉新 daemon 刚写的文件）。
async fn remove_own_pid_port_files(run_dir: &Path) -> crbs_core::Result<()> {
    let pid_file = run_dir.join("crbs-server.pid");
    match tokio::fs::read_to_string(&pid_file).await {
        Ok(text) if text.trim().parse::<u32>().ok() == Some(std::process::id()) => {
            remove_pid_port_files(run_dir).await
        }
        // 不存在 / 已被新实例接管：无需（或不应）清理。
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

/// 删除 run_dir 下的 pid/port 文件；文件不存在视为已清理，不报错。
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

/// 写入 crbs-server root 归属标记（marker 护栏）。mode 0640（owner rw、crbs 组 r）；
/// chown 失败仅 debug（非 root 必然 EPERM，group rw 已足够）。幂等：每次启动覆盖写。
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

/// 确保 crbs_root 存在并修复权限：不存在 → 建 02770（含 SGID）；root 运行 →
/// 递归 chown 为 crbs-server:crbs（crbs 组成员经 group 权限访问产物）；非 root
/// → 仅校验目录可写。目录 2770 + root:crbs 是仓库权限不变量（root /
/// crbs-server / crbs 组三身份可读写）；历史 0755 存量由 mkdir_chown 无条件
/// 收敛到 2770（对目录只剥 SUID、保留 SGID）。
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
///（bootstrap prepare_server）的 merge 序列一致性由 integration_route_inventory 守卫。
pub fn create_test_app(app_state: Arc<AppState>) -> axum::Router {
    let (public, protected) = assemble_test_routers(&app_state);

    axum::Router::new()
        .merge(public)
        .merge(protected)
        .with_state(app_state)
}

/// 测试辅助：`create_test_app` 的带鉴权版——protected 路由套 auth 中间件
///（route_layer，未匹配路由 404 而非 401），public 路由套 optional auth。
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

/// 测试路由装配共用段（create_test_app / create_test_app_with_auth）：
/// 返回（public, protected）双路由，鉴权中间件由调用方自行叠加。
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
        // pre-auth 探针（见 bootstrap.rs 同注）：CLI daemon 发现无 token 调用。
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

/// 测试辅助：注册 worker 并设置 secret，返回 `(worker_id, 原始 crbs_wkr_… secret)`；
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

    /// pidfile 权限不变量——创建后 0660（显式 set_permissions 收口，断言不受 umask 影响）。
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

    /// portfile 权限不变量——写后 0660（同 pidfile 口径）。
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

    /// 空 pidfile fail-closed：另一实例"已 create_new 未写入 PID"的启动窗口
    /// 表现为空文件——按"正在启动"拒绝，**不得**当陈旧 pidfile 删除。
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

    /// TOCTOU 回归：双实例并发启动时 create_new 的原子性保证恰好一个赢家。
    #[tokio::test]
    async fn server_lock_allows_exactly_one_concurrent_starter() {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path().to_path_buf();

        let mut handles = Vec::new();
        for _ in 0..2 {
            let dir = run_dir.clone();
            handles.push(tokio::spawn(async move { acquire_server_lock(&dir).await }));
        }

        // 赢家 guard 须存活到两个 contender 都结束：await 后立即丢弃会让 drop
        // 删 pidfile，慢者在"文件已删"窗口重新 create_new → 双赢家假失败 flake。
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

    // 环境变量锁上收为 crate::test_support::lock_config_env（裸 set_var/remove_var
    // 与本组测试竞态：共享进程级锁 + drop 恢复原值）。
    use crate::test_support::lock_config_env;

    /// 写一个最小 server.toml 到 tempdir，返回 config_dir 路径。
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
        // 特权后端钉死非 Helper 模式（进程级一次）：prepare_server 会加载 config，须先钉防 Helper 激活。
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
        // 特权后端钉死非 Helper 模式（进程级一次）：prepare_server 会加载 config，须先钉防 Helper 激活。
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

    /// result_dir 指向预建 0500 目录时 prepare_server 启动期 fail-closed，
    /// 消息含完整路径与人话指引，而非等首次构建落盘才爆。
    #[tokio::test]
    async fn prepare_server_fails_on_unwritable_result_dir() {
        // 特权后端钉死非 Helper 模式（进程级一次）：prepare_server 会加载 config，须先钉防 Helper 激活。
        crate::test_support::pin_setuid_privilege_backend();
        use std::os::unix::fs::PermissionsExt;

        // root 不受 DAC 约束，造不出 EACCES，跳过。
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
        // 恢复目录权限，TempDir 清理才能删除。
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
        // 特权后端钉死非 Helper 模式（进程级一次）：prepare_server 会加载 config，须先钉防 Helper 激活。
        crate::test_support::pin_setuid_privilege_backend();
        let _env = lock_config_env();
        let tmp = tempfile::tempdir().unwrap();
        let crbs_root = tmp.path().join("crbs");
        let config_dir = tmp.path().join("crbs-config");
        tokio::fs::create_dir_all(&config_dir).await.unwrap();
        // prepare_server 的 root 只来自 server.toml 的 crbs_root。
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

        // assigned（distributed）构建由 per-worker capacity 约束，不预占本地 semaphore 槽。
        assert_eq!(
            app_state.build_semaphore.available_permits(),
            2,
            "assigned (distributed) build must not pre-occupy local semaphore permits"
        );

        app_state.shutdown_cancel.cancel();
    }

    /// 缺陷回归：auth 中间件必须先于限流器（auth 在最外层）；顺序颠倒时
    /// AuthContext 未注入、限流 key 恒为 "(anonymous)"——用户配额失去独立，
    /// 匿名 401 请求也消耗认证用户配额。走真实 prepare_server 路径。
    #[tokio::test]
    async fn submit_rate_limit_counts_per_user_after_auth() {
        // 特权后端钉死非 Helper 模式（进程级一次）：prepare_server 会加载 config，须先钉防 Helper 激活。
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

        // 匿名请求：auth（最外层）直接 401，限流器看不到、不耗配额（否则打满 "(anonymous)" 共享配额）。
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

    /// UI 提交端点 POST /ui/tasks/new 与 API 共用同一提交限流器：bob 首次 UI
    /// POST 消耗配额（缺 CSRF 在限流之后 → 非 429）、二次 429，随后的 API 提交
    /// 同样 429（同限流器同 key）；carol 不受牵连（per-user 隔离）。限流层须挂
    /// optional_auth 内侧才能按用户计数——同时钉住 bootstrap public 段挂载顺序。
    #[tokio::test]
    async fn ui_task_submit_counts_into_submit_rate_limit() {
        // 特权后端钉死非 Helper 模式（进程级一次）：prepare_server 会加载 config，须先钉防 Helper 激活。
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

        // 最小 multipart：product + srpm（无 csrf_token → 过限流后在 CSRF 校验失败，证明确已穿过限流器）。
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

        // bob 首次：穿过限流器（非 429；预期因缺 CSRF 403）。
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

    /// server 启动在其 root 写归属标记；重复写幂等（覆盖成功），mode 0640。
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

    /// marker 护栏闭环——server 写过 marker 的 root，open_for_engine 拒绝打开。
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
