// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Server 启动流程：配置加载、AppState 构造、路由注册、CORS、访问日志。

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use crbs_core::config::{CrbsConfig, ServerConfig};
use crbs_core::error::CrbsError;
use crbs_core::logging::sanitize_query;
use crbs_core::StateStore;
use tower_http::trace::TraceLayer;

use crate::server::state::AppState;

/// 构造 AppState 与 Router，供 run 和 run_local_daemon 复用。root 分流：crbs_root 只由 server.toml 决定；
/// 产品管理端点（init/clean）具有破坏性，必须启用认证；auth 禁用时只允许 loopback 监听。
pub(super) async fn prepare_server(
    config_dir: Option<&std::path::Path>,
    allow_product_management: Option<bool>,
    shutdown_timeout_secs: Option<u64>,
    state_store: Option<Arc<StateStore>>,
    run_dir: Option<PathBuf>,
    web_ui_enabled: Option<bool>,
) -> crbs_core::Result<(ServerConfig, Arc<AppState>, Router)> {
    set_config_dir(config_dir);

    let server_config_path = config_dir
        .map(|d| d.join("server.toml"))
        .unwrap_or_else(|| std::path::PathBuf::from("/etc/crbs/server.toml"));
    let mut server_config = ServerConfig::load_async(&server_config_path).await?;

    if let Some(v) = allow_product_management {
        server_config.allow_product_management = v;
    }
    if let Some(v) = shutdown_timeout_secs {
        server_config.shutdown_timeout_secs = v;
    }
    if let Some(v) = web_ui_enabled {
        server_config.web_ui_enabled = v;
    }
    if server_config.shutdown_timeout_secs == 0 {
        return Err(CrbsError::ValidationFailed {
            message: "shutdown_timeout_secs must be at least 1".into(),
        });
    }

    if server_config.allow_product_management && !server_config.auth_enabled {
        return Err(CrbsError::ValidationFailed {
            message: "allow_product_management requires auth_enabled to be true; \
             refusing to start with unauthenticated destructive product endpoints"
                .into(),
        });
    }

    if !server_config.auth_enabled {
        let listen = server_config.listen.clone();
        let is_loopback = tokio::task::spawn_blocking(move || {
            std::net::ToSocketAddrs::to_socket_addrs(&listen)
                .map(|mut addrs| addrs.all(|a| a.ip().is_loopback()))
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false);
        if !is_loopback {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "auth_enabled=false requires listen address to be loopback only, got: {}",
                    server_config.listen
                ),
            });
        }
    }

    let crbs_config = CrbsConfig::load_async().await?;

    if let Some(notice) =
        risky_backend_notice(crbs_config.backend.as_deref(), server_config.auth_enabled)
    {
        tracing::warn!(
            backend = %crbs_config.backend.as_deref().unwrap_or("nspawn"),
            auth_enabled = server_config.auth_enabled,
            "{notice}"
        );
    }

    if let Some(notice) = insecure_cookie_risk_notice(
        server_config.auth_enabled,
        server_config.tls.is_some(),
        server_config.force_secure_cookies,
        &server_config.listen,
    ) {
        tracing::warn!(
            listen = %server_config.listen,
            auth_enabled = server_config.auth_enabled,
            "{notice}"
        );
    }

    let server_root = server_config.server_crbs_root();

    let run_dir = run_dir.unwrap_or_else(|| super::default_run_dir(&server_root));

    super::ensure_crbs_root(&server_root).await?;

    super::write_server_root_marker(&server_root).await?;

    {
        let uploads = server_config.upload_dir(&server_root);
        let artifacts = server_config.artifact_dir(&server_root);
        tokio::task::spawn_blocking(move || {
            crbs_core::privilege::ensure_directory(&uploads, "uploads")?;
            crbs_core::privilege::ensure_directory(&artifacts, "artifacts")
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("ensure upload/artifact dirs: {e}")))??;
    }

    let result_root = server_config
        .result_dir
        .clone()
        .or_else(|| crbs_config.result_dir.clone())
        .unwrap_or_else(|| server_root.join("results"));
    tokio::task::spawn_blocking(move || ensure_result_root_writable(&result_root))
        .await
        .map_err(|e| CrbsError::io_message(format!("precheck result dir: {e}")))??;

    let server_lock = super::acquire_server_lock(&run_dir).await?;

    let state_store = match state_store {
        Some(s) => s,
        None => match &crbs_config.database_url {
            Some(url) => Arc::new(
                StateStore::new_with_url_and_pool(
                    url,
                    &server_root,
                    server_config.db_max_connections,
                )
                .await?,
            ),
            None => {
                let db_path = server_config.state_db_path(&server_root);
                Arc::new(
                    StateStore::new_with_db_path_and_pool(
                        &db_path,
                        &server_root,
                        server_config.db_max_connections,
                    )
                    .await?,
                )
            }
        },
    };

    let products_dir = crbs_core::config::config_path("products")?;
    state_store.seed_products_from_dir(&products_dir).await?;

    let resume_count = super::routes::builds::recover_pending_builds(&state_store).await?;
    if resume_count > 0 {
        tracing::info!(count = resume_count, "Found pending builds to resume");
    }

    let mut zombie_repaired_ids: Vec<i64> = Vec::new();
    match state_store.repair_all_zombie_active_builds().await {
        Ok((ids, live)) => {
            if !ids.is_empty() {
                tracing::warn!(
                    repaired = ids.len(),
                    live,
                    "Repaired zombie active builds on server startup"
                );
            } else {
                tracing::debug!(live, "No zombie active builds found on startup");
            }
            zombie_repaired_ids = ids;
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "Failed to repair zombie active builds on startup, continuing"
            );
        }
    }

    let max_local = if server_config.max_local_builds > 0 {
        server_config.max_local_builds
    } else {
        num_cpus()
    };

    let shutdown_cancel = tokio_util::sync::CancellationToken::new();

    let srpm_token_key = crate::server::state::load_or_generate_srpm_token_key(&server_root)
        .await
        .map_err(|e| {
            crbs_core::error::CrbsError::io_message(format!(
                "failed to initialize SRPM download token key: {}",
                e
            ))
        })?;

    let csrf_key = crate::server::state::load_or_generate_csrf_key(&server_root)
        .await
        .map_err(|e| {
            crbs_core::error::CrbsError::io_message(format!("failed to initialize CSRF key: {}", e))
        })?;

    let app_state = Arc::new(AppState {
        state_store,
        build_semaphore: Arc::new(tokio::sync::Semaphore::new(max_local)),
        max_local_builds: max_local,
        started_at: chrono::Utc::now(),
        active_builds: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        allow_product_management: server_config.allow_product_management,
        config_dir: config_dir.map(|p| p.to_path_buf()),
        server_config: server_config.clone(),
        crbs_root: server_root,
        crbs_config,
        gc_tasks: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        product_tasks: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        worker_notify: Arc::new(tokio::sync::Notify::new()),
        worker_waiters: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        server_lock: Some(server_lock),
        shutdown_cancel: shutdown_cancel.clone(),
        log_buffer: crate::server::log_buffer::LogBuffer::new(),
        hub_log_cap_warned: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        hub_log_dir_prepared: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        hub_log_chmod_warned: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        hub_log_chunk_seq: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        srpm_token_signer: crbs_core::srpm_token::SrpmTokenSigner::new(srpm_token_key),
        csrf_key,
        login_limiter: crate::server::rate_limit::LoginRateLimiter::new(),
        gc_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
        auth_cache: crate::server::auth::AuthCache::new(),
        repo_visibility_cache: crate::server::routes::repo::RepoVisibilityCache::new(),
        resource_weight_cache: crate::server::scheduler::ResourceWeightCache::new(),
        dispatch_attribution: crate::server::scheduler::planner::DispatchAttribution::new(),
        metrics: crate::server::metrics::MetricsCounters::default(),
        regen_inflight: std::sync::Mutex::new(std::collections::HashSet::new()),
        regen_dirty: std::sync::Mutex::new(std::collections::HashSet::new()),
        auto_replay_inflight: std::sync::Mutex::new(std::collections::HashSet::new()),
        batch_barrier_passed: std::sync::Mutex::new(std::collections::HashSet::new()),
    });

    for id in zombie_repaired_ids {
        crate::server::replay::spawn_on_build_terminal(app_state.clone(), id);
    }

    match app_state
        .state_store
        .list_builds_missing_replay_comparison()
        .await
    {
        Ok(ids) if !ids.is_empty() => {
            tracing::info!(
                count = ids.len(),
                "Reconciling terminal replay builds missing comparison rows"
            );
            for id in ids {
                crate::server::replay::spawn_on_build_terminal(app_state.clone(), id);
            }
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!(
                error = %e,
                "Failed to list builds missing replay comparison on startup, continuing"
            );
        }
    }

    match app_state.state_store.list_tasks_missing_auto_replay().await {
        Ok(candidates) if !candidates.is_empty() => {
            tracing::info!(
                count = candidates.len(),
                "Reconciling fully-succeeded deterministic tasks without any replay task"
            );
            for (_task_id, trigger_build_id) in candidates {
                crate::server::replay::spawn_on_build_terminal(app_state.clone(), trigger_build_id);
            }
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!(
                error = %e,
                "Failed to list tasks missing auto replay on startup, continuing"
            );
        }
    }

    super::scheduler::spawn_profile_backfill_then_scheduler(
        app_state.clone(),
        shutdown_cancel.clone(),
    );

    super::scheduler::spawn_reclaimer(app_state.clone(), shutdown_cancel.clone());

    super::scheduler::spawn_db_retention(app_state.clone(), shutdown_cancel.clone());

    super::scheduler::spawn_session_cleanup(app_state.clone(), shutdown_cancel.clone());

    super::scheduler::spawn_orphan_sweeper(app_state.clone(), shutdown_cancel.clone());

    super::batches::spawn_batch_driver(app_state.clone(), shutdown_cancel.clone());

    let protected = Router::new()
        .merge(super::routes::admin::router())
        .merge(super::routes::artifacts::protected_router())
        .merge(super::routes::batches::router())
        .merge(super::routes::builds::router(
            server_config.upload_max_size_bytes(),
        ))
        .merge(super::routes::health::protected_router())
        .merge(super::routes::logs::router())
        .merge(super::routes::profile::router())
        .merge(super::routes::gc::router())
        .merge(super::routes::product::router())
        .merge(super::routes::resource_profiles::router())
        .merge(super::routes::tasks::router())
        .merge(super::worker::routes::router());

    let public = Router::new()
        .merge(super::routes::health::public_router())
        .merge(super::routes::artifacts::public_router())
        .merge(super::routes::reproducibility::public_router())
        .merge(super::routes::tasks::public_router())
        .merge(super::routes::nihao::router())
        .merge(super::routes::repo::router());

    let public = if server_config.web_ui_enabled {
        public.merge(super::routes::ui::public_router(&app_state))
    } else {
        tracing::info!("Web UI disabled; /ui/* routes will not be mounted");
        public
    };

    // per-user 提交限流：axum 后加 layer 在外层先执行，限流（内层）先加、
    // auth（外层）后加，AuthContext 先注入、限流器才能按用户计数。颠倒则
    // 恒按 "(anonymous)" 计数，匿名流量可打满配额令全部用户 429。
    let submit_limiter =
        crate::server::rate_limit::SubmitRateLimiter::new(server_config.submit_rate_limit.clone());

    // 提交限流：protected/public 两段同挂（UI 提交与 API 端点共用限流器与
    // 配额），先于 auth 挂载 ⇒ 内层，auth 外层先注入身份、限流按用户计数。
    let protected = protected.route_layer(axum::middleware::from_fn_with_state(
        submit_limiter.clone(),
        crate::server::rate_limit::submit_rate_limit_middleware,
    ));
    let public = public.route_layer(axum::middleware::from_fn_with_state(
        submit_limiter,
        crate::server::rate_limit::submit_rate_limit_middleware,
    ));
    let app = if server_config.auth_enabled {
        tracing::info!("API token authentication enabled");
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
        Router::new().merge(public).merge(protected)
    } else {
        tracing::warn!(
            "API token authentication disabled; this should only be used in local development"
        );
        Router::new().merge(public).merge(protected)
    };

    let app = app.with_state(app_state.clone());

    let app = app.layer(tower_http::catch_panic::CatchPanicLayer::custom(
        panic_response,
    ));

    let app = app.layer(axum::middleware::from_fn(request_timeout_middleware));

    let app = if server_config.cors_allowed_origins.is_empty() {
        app
    } else {
        app.layer(cors_layer(&server_config.cors_allowed_origins)?)
    };

    let log_sanitization = server_config.log_sanitization.clone();
    let app = app.layer(
        TraceLayer::new_for_http().make_span_with(move |request: &axum::extract::Request| {
            let uri = request.uri();
            let query = sanitize_query(uri.query().unwrap_or(""), &log_sanitization);
            tracing::info_span!(
                "request",
                method = %request.method(),
                path = %uri.path(),
                query = %query,
                remote_addr = ?request.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>(),
            )
        }),
    );

    Ok((server_config, app_state, app))
}

/// result root 启动预检：坏路径失败即拒绝，而非等首次构建才报错；仅预检全局 root，产品级覆盖保持惰性。
fn ensure_result_root_writable(root: &std::path::Path) -> crbs_core::Result<()> {
    if !root.is_dir() {
        std::fs::create_dir_all(root)
            .map_err(|e| CrbsError::from_io_context("create result dir", e))?;

        if let Err(e) = crbs_core::privilege::chmod(root, 0o2770, false) {
            tracing::warn!(
                path = %root.display(),
                error = %e,
                "result root: chmod 0o2770 failed"
            );
        }
    }

    let probe_err = |e: std::io::Error| CrbsError::PermissionDenied {
        message: format!(
            "result dir {} is not writable (probe failed: {}); check read-only mounts or \
             ownership, or override result_dir in server.toml",
            root.display(),
            e
        ),
    };
    let mut probe = tempfile::NamedTempFile::new_in(root).map_err(probe_err)?;
    std::io::Write::write_all(&mut probe, b"crbs result root writability probe")
        .map_err(probe_err)?;
    drop(probe);
    Ok(())
}

/// 设置配置目录环境变量，供 Config::load 系列函数读取；`run_local_daemon`
/// 首次加载配置前也须调用，否则 pidfile 与 portfile 会落在错误位置。
pub(super) fn set_config_dir(config_dir: Option<&std::path::Path>) {
    if let Some(dir) = config_dir {
        if let Some(s) = dir.to_str() {
            std::env::set_var("CRBS_CONFIG_DIR", s);
        }
    }
}

pub(super) fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

fn risky_backend_notice(backend: Option<&str>, auth_enabled: bool) -> Option<&'static str> {
    let resolved = backend.unwrap_or("nspawn");
    if auth_enabled && resolved == "chroot" {
        Some(
            "backend=chroot provides no PID/mount namespace isolation: build scripts run as \
             host root with host /dev bind-mounted, so any user permitted to submit builds \
             effectively gains host root. Use backend=nspawn for multi-tenant deployments",
        )
    } else {
        None
    }
}

fn insecure_cookie_risk_notice(
    auth_enabled: bool,
    tls_is_some: bool,
    force_secure_cookies: bool,
    listen: &str,
) -> Option<&'static str> {
    if auth_enabled && !tls_is_some && !force_secure_cookies && !listen_host_is_loopback(listen) {
        Some(
            "auth cookies lack the Secure attribute: crbs-server is serving plain HTTP on a \
             non-loopback listener without built-in TLS and without force_secure_cookies, so \
             browsers will send the session cookie in cleartext. Terminate TLS in front of \
             crbs-server (reverse proxy) and set force_secure_cookies=true in server.toml",
        )
    } else {
        None
    }
}

fn listen_host_is_loopback(listen: &str) -> bool {
    let host = listen.rsplit_once(':').map_or(listen, |(h, _)| h);
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    matches!(host, "127.0.0.1" | "::1" | "localhost")
}

fn cors_layer(origins: &[String]) -> Result<tower_http::cors::CorsLayer, CrbsError> {
    use axum::http::{header, Method};

    let mut values = Vec::with_capacity(origins.len());
    for origin in origins {
        if origin == "*" {
            return Err(CrbsError::ValidationFailed {
                message: "wildcard origin not supported: list explicit origins in \
                          cors_allowed_origins (tower-http AllowOrigin::list panics on \"*\")"
                    .into(),
            });
        }
        let value =
            origin
                .parse::<axum::http::HeaderValue>()
                .map_err(|e| CrbsError::ValidationFailed {
                    message: format!("invalid CORS origin {}: {}", origin, e),
                })?;
        values.push(value);
    }
    Ok(tower_http::cors::CorsLayer::new()
        .allow_origin(values)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::HEAD,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]))
}

const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

async fn request_timeout_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    request_timeout_middleware_with(REQUEST_TIMEOUT, req, next).await
}

async fn request_timeout_middleware_with(
    timeout: std::time::Duration,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let content_type = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if request_timeout_exempt(&method, &path, content_type) {
        return next.run(req).await;
    }
    match tokio::time::timeout(timeout, next.run(req)).await {
        Ok(response) => response,
        Err(_elapsed) => {
            tracing::warn!(method = %method, path = %path, "request timed out");
            crate::server::error::ApiError::GatewayTimeout("request timed out".into())
                .into_response()
        }
    }
}

fn request_timeout_exempt(method: &axum::http::Method, path: &str, content_type: &str) -> bool {
    let is_worker_assignments = path
        .strip_prefix("/api/v1/workers/")
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(id, tail)| !id.is_empty() && tail == "assignments");
    if method == axum::http::Method::GET && is_worker_assignments {
        return true;
    }

    let is_artifact_upload = path
        .strip_prefix("/api/v1/builds/")
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(id, tail)| !id.is_empty() && tail == "artifacts/upload");
    if method == axum::http::Method::POST && is_artifact_upload {
        return true;
    }
    method == axum::http::Method::POST
        && matches!(path, "/api/v1/builds" | "/api/v1/tasks" | "/ui/tasks/new")
        && content_type.starts_with("multipart/form-data")
}

fn panic_response(err: Box<dyn std::any::Any + Send + 'static>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let detail = err
        .downcast_ref::<String>()
        .map(|s| s.as_str())
        .or_else(|| err.downcast_ref::<&str>().copied())
        .unwrap_or("non-string panic payload");
    tracing::error!(panic = %detail, "request handler panicked");
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({
            "error": "internal_error",
            "message": "internal error",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{
        cors_layer, ensure_result_root_writable, insecure_cookie_risk_notice, panic_response,
        request_timeout_exempt, request_timeout_middleware, request_timeout_middleware_with,
        risky_backend_notice,
    };
    use axum::routing::{get, post};
    use axum::Router;
    use tower::ServiceExt;

    #[tokio::test]
    async fn panic_response_returns_500_with_internal_error_json() {
        let response = panic_response(Box::new("boom: secret path /etc/crbs".to_string()));
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap_or_default();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "internal_error");
        assert_eq!(v["message"], "internal error");

        assert!(
            !body
                .windows(b"secret path".len())
                .any(|w| w == b"secret path"),
            "panic payload must not leak into the response body"
        );
    }

    #[tokio::test]
    async fn panic_response_handles_str_payload_and_non_string() {
        let response = panic_response(Box::new("plain literal"));
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        let response = panic_response(Box::new(42usize));
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn risky_backend_notice_only_for_chroot_with_auth() {
        assert!(risky_backend_notice(Some("chroot"), true).is_some());

        assert!(risky_backend_notice(Some("chroot"), false).is_none());
        assert!(risky_backend_notice(Some("nspawn"), true).is_none());
        assert!(risky_backend_notice(None, true).is_none());
        assert!(risky_backend_notice(Some("CHROOT"), true).is_none());
    }

    #[test]
    fn insecure_cookie_notice_only_for_auth_plain_http_non_loopback() {
        assert!(insecure_cookie_risk_notice(true, false, false, "0.0.0.0:9090").is_some());
        assert!(insecure_cookie_risk_notice(true, false, false, "192.168.1.10:9090").is_some());
        assert!(insecure_cookie_risk_notice(true, false, false, "hub.example.com:9090").is_some());

        assert!(insecure_cookie_risk_notice(true, false, false, "127.0.0.1:9090").is_none());
        assert!(insecure_cookie_risk_notice(true, false, false, "[::1]:9090").is_none());
        assert!(insecure_cookie_risk_notice(true, false, false, "localhost:9090").is_none());
        assert!(insecure_cookie_risk_notice(true, true, false, "0.0.0.0:9090").is_none());
        assert!(insecure_cookie_risk_notice(true, false, true, "0.0.0.0:9090").is_none());

        assert!(insecure_cookie_risk_notice(false, false, false, "0.0.0.0:9090").is_none());

        assert!(insecure_cookie_risk_notice(true, false, false, "not an addr").is_some());
    }

    #[tokio::test]
    async fn cors_layer_preflight_answers_configured_methods_headers_and_origin() {
        let app = Router::new()
            .route("/api/v1/x", get(|| async { "ok" }))
            .layer(cors_layer(&["https://a.example".into()]).unwrap());

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::OPTIONS)
                    .uri("/api/v1/x")
                    .header("origin", "https://a.example")
                    .header("access-control-request-method", "POST")
                    .header("access-control-request-headers", "authorization")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-methods")
                .and_then(|v| v.to_str().ok()),
            Some("GET,POST,HEAD,PUT,DELETE,PATCH"),
            "methods must be exactly GET/POST/HEAD/PUT/DELETE/PATCH (the route set: \
              admin/product PUT+DELETE, builds PATCH priority)"
        );
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-headers")
                .and_then(|v| v.to_str().ok()),
            Some("authorization,content-type"),
            "headers must be exactly authorization/content-type"
        );
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("https://a.example"),
            "allowed origin must be echoed back"
        );
    }

    #[tokio::test]
    async fn cors_layer_multi_origin_allows_every_listed_origin() {
        let app = Router::new()
            .route("/api/v1/x", get(|| async { "ok" }))
            .layer(cors_layer(&["https://a.example".into(), "https://b.example".into()]).unwrap());

        for origin in ["https://a.example", "https://b.example"] {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(axum::http::Method::OPTIONS)
                        .uri("/api/v1/x")
                        .header("origin", origin)
                        .header("access-control-request-method", "GET")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response
                    .headers()
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok()),
                Some(origin),
                "every listed origin must be allowed (regression: chained allow_origin \
                  replaced the whole list, only the last one took effect)"
            );
        }

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::OPTIONS)
                    .uri("/api/v1/x")
                    .header("origin", "https://evil.example")
                    .header("access-control-request-method", "GET")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_none(),
            "unlisted origin must not be echoed"
        );
    }

    #[test]
    fn cors_layer_rejects_wildcard_origin_without_panicking() {
        let err = cors_layer(&["*".into()]).expect_err("wildcard must be rejected");
        assert!(
            err.to_string().contains("wildcard"),
            "error must explain the wildcard rejection, got: {err}"
        );
    }

    #[test]
    fn cors_layer_rejects_invalid_origin_with_context() {
        let err = cors_layer(&["bad\norigin".into()]).expect_err("invalid origin must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("bad"),
            "error must name the origin, got: {msg}"
        );
    }

    #[test]
    fn request_timeout_exempt_matches_only_whitelisted_paths() {
        let get = axum::http::Method::GET;
        let post = axum::http::Method::POST;
        let multipart_ct = "multipart/form-data; boundary=----crbs";
        let json_ct = "application/json";

        assert!(request_timeout_exempt(
            &get,
            "/api/v1/workers/7/assignments",
            ""
        ));
        assert!(request_timeout_exempt(
            &get,
            "/api/v1/workers/42/assignments",
            ""
        ));

        assert!(!request_timeout_exempt(
            &get,
            "/api/v1/workers/7/assignments/9/result",
            ""
        ));
        assert!(!request_timeout_exempt(
            &get,
            "/api/v1/workers//assignments",
            ""
        ));
        assert!(!request_timeout_exempt(
            &get,
            "/api/v1/workers/7/register",
            ""
        ));

        assert!(!request_timeout_exempt(
            &post,
            "/api/v1/workers/7/assignments",
            multipart_ct
        ));

        for path in ["/api/v1/builds", "/api/v1/tasks", "/ui/tasks/new"] {
            assert!(
                request_timeout_exempt(&post, path, multipart_ct),
                "multipart {path}"
            );
            assert!(
                !request_timeout_exempt(&post, path, json_ct),
                "JSON {path} must not be exempt"
            );
            assert!(
                !request_timeout_exempt(&post, path, ""),
                "no content-type {path} must not be exempt"
            );
        }

        assert!(request_timeout_exempt(
            &post,
            "/api/v1/builds/42/artifacts/upload",
            multipart_ct
        ));

        assert!(!request_timeout_exempt(
            &post,
            "/api/v1/builds//artifacts/upload",
            multipart_ct
        ));
        assert!(!request_timeout_exempt(
            &post,
            "/api/v1/builds/42/artifacts/upload/extra",
            multipart_ct
        ));
        assert!(!request_timeout_exempt(
            &post,
            "/api/v1/builds/42/artifacts",
            multipart_ct
        ));
        assert!(!request_timeout_exempt(
            &post,
            "/api/v1/builds/artifacts/by-sha256/abc",
            multipart_ct
        ));
        assert!(!request_timeout_exempt(
            &post,
            "/api/v1/tasks/5/reproduce",
            json_ct
        ));
    }

    #[tokio::test]
    async fn request_timeout_returns_504_envelope_for_pending_handler() {
        let app = Router::new()
            .route(
                "/slow",
                get(|| async { std::future::pending::<()>().await }),
            )
            .layer(axum::middleware::from_fn(move |req, next| {
                request_timeout_middleware_with(std::time::Duration::from_millis(50), req, next)
            }));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/slow")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::GATEWAY_TIMEOUT);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap_or_default();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "gateway_timeout");
        assert_eq!(v["message"], "request timed out");
    }

    #[tokio::test]
    async fn request_timeout_exempt_path_keeps_pending_handler_alive() {
        let timeout = std::time::Duration::from_millis(50);
        let build_app = || {
            Router::new()
                .route(
                    "/api/v1/builds",
                    post(|| async { std::future::pending::<()>().await }),
                )
                .route(
                    "/api/v1/workers/{id}/assignments",
                    get(|| async { std::future::pending::<()>().await }),
                )
                .layer(axum::middleware::from_fn(move |req, next| {
                    request_timeout_middleware_with(timeout, req, next)
                }))
        };

        for (method, uri, content_type) in [
            (
                axum::http::Method::POST,
                "/api/v1/builds",
                "multipart/form-data; boundary=----crbs",
            ),
            (axum::http::Method::GET, "/api/v1/workers/7/assignments", ""),
        ] {
            let outcome = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                build_app().oneshot(
                    axum::http::Request::builder()
                        .method(method.clone())
                        .uri(uri)
                        .header("content-type", content_type)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                ),
            )
            .await;
            assert!(
                outcome.is_err(),
                "{method} {uri} ({content_type}) must stay pending (exempt from the request timeout)"
            );
        }

        let response = build_app()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/api/v1/builds")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::GATEWAY_TIMEOUT,
            "JSON submit must remain subject to the request timeout"
        );
    }

    #[tokio::test]
    async fn catch_panic_500_envelope_keeps_cors_headers_through_full_layer_stack() {
        async fn boom() -> &'static str {
            panic!("boom: secret path")
        }
        let app = Router::new()
            .route("/api/v1/boom", get(boom))
            .layer(tower_http::catch_panic::CatchPanicLayer::custom(
                panic_response,
            ))
            .layer(axum::middleware::from_fn(request_timeout_middleware))
            .layer(cors_layer(&["https://a.example".into()]).unwrap());

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/boom")
                    .header("origin", "https://a.example")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );

        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("https://a.example"),
            "panic-derived 500 must still carry CORS headers (layer order regression)"
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap_or_default();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "internal_error");
        assert_eq!(v["message"], "internal error");
    }

    #[test]
    fn result_root_precheck_creates_missing_dir_and_cleans_probe() {
        let tmp = tempfile::tempdir().unwrap();

        let root = tmp.path().join("nested").join("results");
        ensure_result_root_writable(&root).expect("precheck on missing dir");
        assert!(root.is_dir(), "missing result root should be created");
        assert_eq!(
            std::fs::read_dir(&root).unwrap().count(),
            0,
            "probe file must be cleaned up"
        );
    }

    #[test]
    fn result_root_precheck_accepts_existing_dir_and_cleans_probe() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("results");
        std::fs::create_dir_all(&root).unwrap();
        ensure_result_root_writable(&root).expect("precheck on existing dir");
        assert_eq!(
            std::fs::read_dir(&root).unwrap().count(),
            0,
            "probe file must be cleaned up"
        );
    }

    #[test]
    fn result_root_precheck_fails_on_unwritable_dir() {
        use std::os::unix::fs::PermissionsExt;

        if nix::unistd::geteuid().is_root() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("results");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();

        let err = ensure_result_root_writable(&root)
            .expect_err("0500 dir must fail the writability probe")
            .to_string();

        let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
        assert!(
            err.contains("not writable"),
            "expected not-writable error, got: {err}"
        );
        assert!(
            err.contains(&root.display().to_string()),
            "error should name the full path, got: {err}"
        );
    }
}
