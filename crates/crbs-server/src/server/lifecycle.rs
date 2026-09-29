// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Server 生命周期管理：启动 axum serve、优雅退出、空闲 watcher、活跃构建等待。

use std::path::Path;
use std::sync::Arc;

use axum::Router;
use crbs_core::error::CrbsError;
use crbs_core::types::build_phase_is_terminal;

use crate::server::state::AppState;

/// 启动 axum serve，支持 OS 信号或外部取消触发优雅退出。
pub(super) async fn serve_forever(
    listener: tokio::net::TcpListener,
    app_state: Arc<AppState>,
    app: Router,
    shutdown_timeout_secs: u64,
    external_cancel: Option<tokio::sync::oneshot::Receiver<()>>,
) -> crbs_core::Result<()> {
    let app_state_for_shutdown = app_state.clone();
    let shutdown = async move {
        if let Err(e) = shutdown_signal(external_cancel).await {
            tracing::error!(err = %e, "Failed to install shutdown signal handler");
        }
        tracing::info!("Received shutdown signal, stopping listener...");
        spawn_force_exit_on_second_ctrl_c();
        app_state_for_shutdown.shutdown_cancel.cancel();
    };

    #[cfg(feature = "tls")]
    {
        if let Some(tls_cfg) = &app_state.server_config.tls {
            let acceptor = crate::server::tls::build_tls_acceptor(tls_cfg).await?;
            crate::server::tls::serve_tls(listener, app, acceptor, shutdown, shutdown_timeout_secs)
                .await?;
        } else {
            serve_http(listener, app, shutdown, shutdown_timeout_secs).await?;
        }
    }
    #[cfg(not(feature = "tls"))]
    {
        if app_state.server_config.tls.is_some() {
            return Err(CrbsError::ValidationFailed {
                message:
                    "server.toml configures [tls] but crbs-server was built without --features tls"
                        .into(),
            });
        }
        serve_http(listener, app, shutdown, shutdown_timeout_secs).await?;
    }

    wait_for_active_builds(&app_state, shutdown_timeout_secs).await;
    tracing::info!("Server stopped");
    Ok(())
}

/// 用 axum serve 承接 HTTP，shutdown 信号触发优雅退出。`drain_timeout_secs` 只限信号后
/// 的排空阶段：axum 无限期等在途连接（SSE/日志流最长可挂 1h），超时放弃排空、返回 Ok
/// 断开在途连接继续停机（与 `wait_for_active_builds` 共用 shutdown_timeout_secs）；
/// 计时不可从 serve 启动起算——否则长运行部署定时自杀。
async fn serve_http(
    listener: tokio::net::TcpListener,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    drain_timeout_secs: u64,
) -> crbs_core::Result<()> {
    // axum graceful shutdown future 与 select! 须等同一信号而 Future 不可 clone，用 watch channel 把一次性信号转多路观察。
    let (signal_tx, mut signal_rx) = tokio::sync::watch::channel(());
    tokio::spawn(async move {
        shutdown.await;
        // 发送失败 = 所有接收端已 drop（serve 已先行结束），无需处理。
        let _ = signal_tx.send(());
    });

    let mut drain_signal = signal_rx.clone();
    // WithGracefulShutdown 只实现 IntoFuture 非 Future，不能直接 Box::pin：包一层 async block 得可 select / 可入 timeout 的 Future。
    // into_make_service_with_connect_info 注入对端地址（ConnectInfo<SocketAddr>）：登录/注册限流取真连 IP + 访问日志 remote_addr。
    let mut serve = Box::pin(async {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            // changed() Err 仅当 sender 未 send 即 drop；spawned task 保证先 send 再 drop，Err 非收到信号。
            let _ = signal_rx.changed().await;
        })
        .await
    });

    tokio::select! {
        res = &mut serve => {
            return res.map_err(|e| CrbsError::from_io_context("serve http", e));
        }
        _ = drain_signal.changed() => {}
    }

    // 排空阶段：drain 计时从信号之后（此处）起算。
    match tokio::time::timeout(std::time::Duration::from_secs(drain_timeout_secs), serve).await {
        Ok(res) => res.map_err(|e| CrbsError::from_io_context("serve http", e)),
        Err(_) => {
            tracing::warn!(
                drain_timeout_secs,
                "HTTP drain timeout reached, in-flight connections will be dropped; continuing shutdown"
            );
            Ok(())
        }
    }
}

/// 停机信号收到后武装"二次 Ctrl-C 立即退出"：排空等待最长两个 timeout 周期，再按 Ctrl-C = 不等了立刻退出；130 是 SIGINT 惯例退出码。
fn spawn_force_exit_on_second_ctrl_c() {
    tokio::spawn(async {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::warn!("Second Ctrl-C received during shutdown drain, forcing immediate exit");
            std::process::exit(130);
        }
    });
}

/// 空闲自动退出 watcher：active_builds 为空且无 pending 任务，持续空闲超过 `idle_timeout_secs` 即触发取消。
pub(super) async fn idle_shutdown_watcher(
    app_state: Arc<AppState>,
    idle_timeout_secs: u64,
    run_dir: &Path,
) -> crbs_core::Result<()> {
    let threshold = std::time::Duration::from_secs(idle_timeout_secs);
    let mut idle_since: Option<tokio::time::Instant> = None;

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        // pidfile 已被外部删除 = 用户要停止 daemon，直接退出。
        let pid_path = run_dir.join("crbs-server.pid");
        if !tokio::fs::try_exists(&pid_path).await.unwrap_or(false) {
            tracing::debug!("pidfile removed externally, shutting down idle watcher");
            return Ok(());
        }

        let active = app_state.active_builds.lock().await.len();
        // fail-closed：pending 查询失败视为"忙"——fail-open 会让 DB 抖动期累积的空闲时长带着 pending 任务误判退出。
        let pending_idle = match app_state.state_store.count_pending_by_priority().await {
            Ok(m) => m.values().map(|v| *v as usize).sum::<usize>() == 0,
            Err(e) => {
                tracing::warn!(err = %e, "count pending builds failed, treating daemon as busy");
                false
            }
        };

        if active == 0 && pending_idle {
            let now = tokio::time::Instant::now();
            match idle_since {
                Some(start) if now.duration_since(start) >= threshold => {
                    tracing::info!(
                        idle_secs = %idle_timeout_secs,
                        "Idle timeout reached, shutting down local daemon"
                    );
                    return Ok(());
                }
                Some(_) => {}
                None => idle_since = Some(now),
            }
        } else {
            idle_since = None;
        }
    }
}

/// 等待 shutdown 信号：SIGINT、SIGTERM（Unix）或外部取消。
async fn shutdown_signal(
    external_cancel: Option<tokio::sync::oneshot::Receiver<()>>,
) -> crbs_core::Result<()> {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|e| CrbsError::from_io_context("install signal handler", e))?;
        let ctrl_c = tokio::signal::ctrl_c();

        tokio::select! {
            res = ctrl_c => {
                res.map_err(|e| CrbsError::from_io_context("install signal handler", e))?;
                tracing::info!("Received SIGINT");
            }
            _ = sigterm.recv() => tracing::info!("Received SIGTERM"),
            _ = async {
                if let Some(rx) = external_cancel {
                    let _ = rx.await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => tracing::info!("Received external shutdown request"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| CrbsError::from_io_context("install signal handler", e))?;
    }
    Ok(())
}

/// 等待活跃构建完成，超时后取消；取消后留一段清理宽限，宽限期后仍活跃的
/// 强制标 `cancelled`，不留 pending/building 僵尸记录。
pub(super) async fn wait_for_active_builds(app_state: &Arc<AppState>, timeout_secs: u64) {
    if timeout_secs == 0 {
        return;
    }

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        let count = app_state.active_builds.lock().await.len();
        if count == 0 {
            tracing::info!("All active builds finished");
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tracing::debug!(
            active_builds = count,
            "Waiting for active builds to finish..."
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    tracing::warn!("Shutdown timeout reached, cancelling active builds");
    let map = app_state.active_builds.lock().await;
    for token in map.values() {
        token.cancel();
    }
    drop(map);

    let grace = std::time::Duration::from_secs(std::cmp::min(timeout_secs, 10));
    let grace_deadline = tokio::time::Instant::now() + grace;
    loop {
        let count = app_state.active_builds.lock().await.len();
        if count == 0 || tokio::time::Instant::now() >= grace_deadline {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    let still_remaining = app_state.active_builds.lock().await;
    if !still_remaining.is_empty() {
        let ids: Vec<i64> = still_remaining.keys().cloned().collect();
        tracing::warn!(
            remaining = ids.len(),
            "Active builds did not finish in grace period, marking as cancelled"
        );
        drop(still_remaining);
        for id in ids {
            // 双重检查：取 id 与写 DB 之间构建可能刚好完成，已终态不覆盖为 cancelled。
            match app_state.state_store.get_build(id).await {
                Ok(Some(record)) if build_phase_is_terminal(&record.phase) => {
                    tracing::debug!(build_id = %id, phase = %record.phase, "Build already terminal, skipping cancellation overwrite");
                    continue;
                }
                Ok(None) => {
                    tracing::warn!(build_id = %id, "Build record missing during shutdown cancellation");
                    continue;
                }
                Err(e) => {
                    tracing::error!(build_id = %id, err = %e, "Failed to query build phase during shutdown");
                    continue;
                }
                _ => {}
            }
            if let Err(e) = app_state
                .state_store
                .complete_build(id, "cancelled", None)
                .await
            {
                tracing::error!(build_id = %id, err = %e, "Failed to mark build as cancelled during shutdown");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crbs_core::config::ServerConfig;
    use crbs_core::StateStore;
    use tokio_util::sync::CancellationToken;

    async fn make_app() -> (Arc<AppState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let app_state = Arc::new(AppState::for_test(
            store,
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        (app_state, tmp)
    }

    /// pkg 由调用方传入：insert_build 拒同 product+pkg+arch 活跃重复，同产品多种子须错开 pkg。
    async fn insert_build(state_store: &StateStore, pkg: &str) -> i64 {
        state_store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: pkg,
                phase: "building",
                backend: "chroot",
                user: "test",
                task_id: Some(crate::test_support::seed_task(state_store, "fedora", pkg).await),
                ..Default::default()
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn wait_for_active_builds_does_not_overwrite_completed_builds() {
        let (app, _tmp) = make_app().await;
        let active_id = insert_build(&app.state_store, "pkg").await;
        let token = CancellationToken::new();
        app.active_builds
            .lock()
            .await
            .insert(active_id, token.clone());

        let app_clone = app.clone();
        tokio::spawn(async move {
            token.cancelled().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            app_clone
                .state_store
                .complete_build(active_id, "succeeded", None)
                .await
                .unwrap();
            app_clone.active_builds.lock().await.remove(&active_id);
        });

        wait_for_active_builds(&app, 1).await;

        let record = app.state_store.get_build(active_id).await.unwrap().unwrap();
        assert_eq!(record.phase, "succeeded");
    }

    #[tokio::test]
    async fn wait_for_active_builds_only_cancels_still_remaining_builds() {
        let (app, _tmp) = make_app().await;
        let id1 = insert_build(&app.state_store, "pkg").await;
        let id2 = insert_build(&app.state_store, "pkg2").await;

        let token1 = CancellationToken::new();
        let token2 = CancellationToken::new();
        app.active_builds.lock().await.insert(id1, token1.clone());
        app.active_builds.lock().await.insert(id2, token2.clone());

        let app_clone = app.clone();
        tokio::spawn(async move {
            token1.cancelled().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            app_clone
                .state_store
                .complete_build(id1, "succeeded", None)
                .await
                .unwrap();
            app_clone.active_builds.lock().await.remove(&id1);
        });

        wait_for_active_builds(&app, 1).await;

        let r1 = app.state_store.get_build(id1).await.unwrap().unwrap();
        let r2 = app.state_store.get_build(id2).await.unwrap().unwrap();
        assert_eq!(r1.phase, "succeeded");
        assert_eq!(r2.phase, "cancelled");
    }

    #[tokio::test]
    async fn cleanup_guard_remove_clears_active_builds() {
        let (app, _tmp) = make_app().await;
        let build_id = insert_build(&app.state_store, "pkg").await;
        let token = CancellationToken::new();
        app.active_builds
            .lock()
            .await
            .insert(build_id, token.clone());

        let guard = crate::server::state::CleanupGuard {
            active_builds: app.active_builds.clone(),
            build_id,
            consumed: false,
        };
        guard.remove(&app).await;

        assert!(
            app.active_builds.lock().await.is_empty(),
            "CleanupGuard::remove should clear active_builds"
        );
    }

    /// 排空超时兜底：停机信号触发后，在途连接（模拟 SSE/日志流）永不完成时 serve_http 应在 drain 超时后返回 Ok 让停机继续。
    #[tokio::test]
    async fn serve_http_drain_timeout_continues_shutdown_with_hanging_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let app = axum::Router::new().route(
            "/hang",
            axum::routing::get(|| async { std::future::pending::<()>().await }),
        );

        // 在停机信号触发前建立已路由的在途请求，确保连接被 axum 跟踪并等待。
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut client,
            b"GET /hang HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await
        .unwrap();

        let shutdown = async {
            tokio::time::sleep(Duration::from_millis(300)).await;
        };
        let start = std::time::Instant::now();
        let res = serve_http(listener, app, shutdown, 1).await;

        assert!(
            res.is_ok(),
            "drain timeout should return Ok to continue shutdown"
        );
        assert!(
            start.elapsed() >= Duration::from_secs(1),
            "serve_http should have waited for the drain timeout before giving up"
        );
    }

    /// 回归：drain 计时须从停机信号起算而非 serve 启动——否则长运行 server 在 drain_timeout 后无条件自杀；无信号+短超时 ⇒ 越过该时长仍在正常服务。
    #[tokio::test]
    async fn serve_http_keeps_serving_without_signal_beyond_drain_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let app = axum::Router::new().route("/ping", axum::routing::get(|| async { "pong" }));

        let serve = tokio::spawn(serve_http(listener, app, std::future::pending::<()>(), 1));

        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(
            !serve.is_finished(),
            "serve must not exit on drain timeout without a shutdown signal"
        );

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut client,
            b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut client, &mut buf)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.starts_with("HTTP/1.1 200 OK"),
            "server should still serve after drain timeout elapsed, got: {text}"
        );
        assert!(text.ends_with("pong"));
    }
}
