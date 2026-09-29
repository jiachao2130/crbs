// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 健康检查、版本与监控指标端点。

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

/// 公开路由：health + version + 脱敏状态摘要。
pub(crate) fn public_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/version", get(version))
        .route("/api/v1/status", get(public_status))
}

/// 受保护路由：metrics（磁盘/队列等运维信息，默认不公开）。两路径同源同门控、
/// 不做 Accept 协商：`/api/v1/metrics` JSON 快照、`/metrics` Prometheus text。
pub(crate) fn protected_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/metrics", get(metrics))
        .route("/metrics", get(metrics_prometheus))
}

#[derive(Serialize)]
pub(crate) struct StatusResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub timestamp: String,
    pub tasks: TaskStatusCounts,
    pub workers: WorkerStatusCounts,
}

/// Task 级状态计数（对 tasks.phase 聚合，口径为用户提交的构建任务）。
#[derive(Serialize)]
pub(crate) struct TaskStatusCounts {
    pub pending: i64,
    pub building: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub cancelled: i64,
    pub timeout: i64,
    pub total: i64,
}

#[derive(Serialize)]
pub(crate) struct WorkerStatusCounts {
    pub online: usize,
}

pub(crate) async fn public_status(
    State(state): State<Arc<AppState>>,
) -> Result<axum::response::Response, ApiError> {
    let summary = compute_public_status(&state, None).await?;
    Ok(no_store(Json(summary)))
}

/// 探针端点统一补 `Cache-Control: no-store`：version 随部署变化、status 含实时
/// 计数，禁止中间层/浏览器缓存探针响应。
fn no_store(response: impl IntoResponse) -> axum::response::Response {
    let mut resp = response.into_response();
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    resp
}

/// 计算公开状态摘要（供 JSON 端点和 UI 仪表盘复用）；不暴露磁盘容量、
/// crbs_root、max_local_builds 等敏感运维信息。
pub(crate) async fn compute_public_status(
    state: &AppState,
    auth: Option<&AuthContext>,
) -> Result<StatusResponse, ApiError> {
    // 计数与任务列表同口径按可见性过滤：admin/operator 不过滤，其余用户/
    // 匿名只统计可见产品（含孤儿豁免）——否则私有产品的活动量从公开摘要泄出。
    let visible = crate::server::auth::visibility::compute_visible_products(state, auth).await?;
    let counts = state
        .state_store
        .count_tasks_by_phase_visible(visible.as_deref())
        .await
        .map_err(ApiError::from)?;
    let get = |phase: &str| counts.get(phase).copied().unwrap_or(0);

    let online_workers = state
        .state_store
        .count_online_workers(None)
        .await
        .map_err(ApiError::from)?;

    let total = get("pending")
        + get("building")
        + get("succeeded")
        + get("failed")
        + get("cancelled")
        + get("timeout");

    Ok(StatusResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        timestamp: chrono::Utc::now().to_rfc3339(),
        tasks: TaskStatusCounts {
            pending: get("pending"),
            building: get("building"),
            succeeded: get("succeeded"),
            failed: get("failed"),
            cancelled: get("cancelled"),
            timeout: get("timeout"),
            total,
        },
        workers: WorkerStatusCounts {
            online: online_workers,
        },
    })
}

#[derive(Serialize)]
pub(crate) struct HealthResponse {
    pub status: &'static str,
    /// 深度检查（?deep=1）时才出现的数据库可达性；缺省不序列化（liveness 响应字节不变）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db: Option<&'static str>,
}

#[derive(Serialize)]
pub(crate) struct VersionResponse {
    pub version: &'static str,
}

#[derive(Serialize)]
pub(crate) struct MetricsResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub timestamp: String,
    pub uptime_seconds: u64,
    pub concurrency: ConcurrencyMetrics,
    pub queue: QueueMetrics,
    pub disk: DiskMetrics,
    /// OOM 分类计数镜像（`crbs_build_oom_total{kind}`；label 全集补零）。
    pub build_oom_total: BTreeMap<String, u64>,
    /// 画像更新计数镜像（`crbs_profile_updates_total{outcome}`；label 全集补零）。
    pub profile_updates_total: BTreeMap<String, u64>,
    /// 画像行总数镜像（`crbs_profiles_total` gauge）。
    pub profiles_total: i64,
    /// 派发准入拒绝计数镜像（`crbs_dispatch_admit_rejects_total{dimension}`；
    /// label 全集补零）。
    pub dispatch_admit_rejects_total: BTreeMap<String, u64>,
    /// 有空槽有 pending 但零派发的 tick 数镜像。
    pub dispatch_no_candidate_ticks_total: u64,
    /// 实际派发成功数镜像。
    pub dispatch_assigned_total: u64,
    /// censored 超龄兜底派发数镜像。
    pub dispatch_soft_fallbacks_total: u64,
    /// 最近/最大调度 tick 耗时（毫秒；planner tick 口径）。
    pub dispatch_tick_last_ms: u64,
    pub dispatch_tick_max_ms: u64,
}

/// 集群口径并发指标：`max`/`current`/`available` 为集群合计（分母只计启用
/// 车道）；`local_*` / `worker_*` 为构成分解（本地槽 vs 在线 worker 容量），
/// 纯新增字段、对旧客户端无破坏。
#[derive(Serialize)]
pub(crate) struct ConcurrencyMetrics {
    pub max: usize,
    pub current: usize,
    pub available: usize,
    /// Hub 本机活跃（分子本地分量）。
    pub local_active: usize,
    /// 在线 worker 活跃合计（分子分布式分量）。
    pub distributed_active: usize,
    /// Hub 本地槽（LocalOnly/auto 计入 max）。
    pub local_slots: usize,
    /// 在线 worker capacity 合计（DistributedOnly/auto 计入 max）。
    pub worker_capacity_online: usize,
}

impl From<crate::server::state::ConcurrencySnapshot> for ConcurrencyMetrics {
    fn from(s: crate::server::state::ConcurrencySnapshot) -> Self {
        Self {
            max: s.total_capacity,
            current: s.total_active,
            available: s.total_capacity.saturating_sub(s.total_active),
            local_active: s.local_active,
            distributed_active: s.distributed_active,
            local_slots: s.local_slots,
            worker_capacity_online: s.worker_capacity_online,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct QueueMetrics {
    pub pending: i64,
    pub building: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub cancelled: i64,
    pub total: i64,
}

#[derive(Serialize)]
pub(crate) struct DiskMetrics {
    pub crbs_root: String,
    pub available_bytes: u64,
    pub available_gb: f64,
}

/// 深度检查开关：`?deep=1`/`true`/`yes`。缺省 `/health` 纯 liveness（DB 瞬断不
/// 影响，负载均衡器探活用）；`?deep` 追加 DB ping，失败 503 + degraded（readiness）。
#[derive(serde::Deserialize, Default)]
pub(crate) struct HealthQuery {
    pub deep: Option<String>,
}

pub(crate) async fn health(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<HealthQuery>,
) -> axum::response::Response {
    let deep = matches!(
        query.deep.as_deref(),
        Some("1") | Some("true") | Some("yes")
    );
    if !deep {
        return no_store(Json(HealthResponse {
            status: "ok",
            db: None,
        }));
    }
    match state.state_store.ping().await {
        Ok(()) => no_store(Json(HealthResponse {
            status: "ok",
            db: Some("ok"),
        })),
        Err(e) => {
            tracing::warn!(error = ?e, "health deep check: database unreachable");
            no_store((
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(HealthResponse {
                    status: "degraded",
                    db: Some("error"),
                }),
            ))
        }
    }
}

pub(crate) async fn version() -> axum::response::Response {
    no_store(Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
    }))
}

pub(crate) async fn metrics(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<MetricsResponse>, ApiError> {
    ensure_metrics_viewer(&auth)?;
    let snapshot = collect_metrics_snapshot(&state).await?;
    let queue = build_queue_metrics(&snapshot.counts);

    Ok(Json(MetricsResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        timestamp: chrono::Utc::now().to_rfc3339(),
        uptime_seconds: snapshot.uptime_seconds,
        concurrency: snapshot.concurrency.into(),
        queue,
        disk: DiskMetrics {
            crbs_root: state.crbs_root.to_string_lossy().into_owned(),
            available_bytes: snapshot.available_bytes,
            available_gb: bytes_to_gb(snapshot.available_bytes),
        },
        build_oom_total: snapshot
            .build_oom
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        profile_updates_total: snapshot
            .profile_updates
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        profiles_total: snapshot.profiles_total,
        dispatch_admit_rejects_total: snapshot
            .dispatch_admit_rejects
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect(),
        dispatch_no_candidate_ticks_total: snapshot.dispatch_no_candidate_ticks_total,
        dispatch_assigned_total: snapshot.dispatch_assigned_total,
        dispatch_soft_fallbacks_total: snapshot.dispatch_soft_fallbacks_total,
        dispatch_tick_last_ms: snapshot.dispatch_tick_ms.0,
        dispatch_tick_max_ms: snapshot.dispatch_tick_ms.1,
    }))
}

/// Prometheus 抓取端点：`GET /metrics` 输出 text exposition（format 0.0.4），
/// 与 JSON `/api/v1/metrics` 同源同门控。
pub(crate) async fn metrics_prometheus(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
) -> Result<axum::response::Response, ApiError> {
    ensure_metrics_viewer(&auth)?;
    let snapshot = collect_metrics_snapshot(&state).await?;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        render_prometheus_exposition(&snapshot),
    )
        .into_response())
}

/// metrics 门控：仅 operator/admin 可读；auth 关闭（无 AuthContext）时放行。
fn ensure_metrics_viewer(auth: &Option<Extension<AuthContext>>) -> Result<(), ApiError> {
    if let Some(ctx) = auth.as_ref() {
        if !ctx.is_operator() {
            return Err(ApiError::PermissionDenied(
                "only operator/admin can view metrics".into(),
            ));
        }
    }
    Ok(())
}

/// JSON 与 Prometheus 两个 metrics 端点共享的采集快照（保证同源）。
struct MetricsSnapshot {
    counts: HashMap<String, i64>,
    /// 集群并发快照（state.rs）：JSON 端点取 total_* 集群口径；Prometheus
    /// 指标名含 `local`，只取 local_* 字段保持本机口径不变。
    concurrency: crate::server::state::ConcurrencySnapshot,
    available_bytes: u64,
    uptime_seconds: u64,
    /// 复现率 verdict 计数（全部时间；查询为 replay 口径——cross_arch_noarch
    /// 观测行不入指标，口径见 state `reproducibility_stats` 模块头）；查询失败置空
    /// map、渲染按 `ALL_VERDICTS` 补零——统计故障不放大成端点 500（见
    /// [`collect_metrics_snapshot`]）。
    repro_verdicts: BTreeMap<String, i64>,
    /// 进程内 counter 快照（label 全集由渲染按
    /// `ALL_OOM_KINDS` / `ALL_PROFILE_UPDATES` 补零，map 缺键不收缩 label 集）。
    build_oom: BTreeMap<&'static str, u64>,
    profile_updates: BTreeMap<&'static str, u64>,
    /// 画像行总数（`crbs_profiles_total` gauge）；查询失败置 0——统计故障
    /// 不放大成端点 500（同 [`Self::repro_verdicts`] 降级口径）。
    profiles_total: i64,
    /// dispatch 系计数（admit_rejects 的 label 全集
    /// 由渲染按 `ALL_DISPATCH_REJECTS` 补零）。
    dispatch_admit_rejects: BTreeMap<&'static str, u64>,
    dispatch_no_candidate_ticks_total: u64,
    dispatch_assigned_total: u64,
    dispatch_soft_fallbacks_total: u64,
    /// (last_ms, max_ms)。
    dispatch_tick_ms: (u64, u64),
}

async fn collect_metrics_snapshot(state: &AppState) -> Result<MetricsSnapshot, ApiError> {
    let counts = state
        .state_store
        .count_builds_by_phase()
        .await
        .map_err(ApiError::from)?;

    let concurrency = state.concurrency_snapshot().await.map_err(ApiError::from)?;

    let crbs_root = state.crbs_root.clone();
    let available_bytes = tokio::task::spawn_blocking(move || fs4::available_space(&crbs_root))
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("spawn blocking disk check", e))?
        .map_err(|e| ApiError::log_and_internal_with_context("available_space", e))?;

    let now = chrono::Utc::now();
    let uptime_seconds = (now - state.started_at).num_seconds().max(0) as u64;

    // metrics 端点为 operator+ 门控，全量口径不做可见性过滤。
    let repro_verdicts = match state
        .state_store
        .reproducibility_verdict_counts(None, None)
        .await
    {
        Ok(rows) => crbs_core::fold_verdict_totals(&rows),
        Err(e) => {
            tracing::warn!(error = ?e, "metrics: reproducibility verdict query failed; emitting zeros");
            BTreeMap::new()
        }
    };

    let profiles_total = match state.state_store.count_profiles().await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = ?e, "metrics: profile count query failed; emitting zero");
            0
        }
    };

    Ok(MetricsSnapshot {
        counts,
        concurrency,
        available_bytes,
        uptime_seconds,
        repro_verdicts,
        build_oom: state.metrics.build_oom_snapshot(),
        profile_updates: state.metrics.profile_updates_snapshot(),
        profiles_total,
        dispatch_admit_rejects: state.metrics.dispatch_admit_rejects_snapshot(),
        dispatch_no_candidate_ticks_total: state.metrics.no_candidate_ticks_total(),
        dispatch_assigned_total: state.metrics.dispatch_assigned_total(),
        dispatch_soft_fallbacks_total: state.metrics.soft_fallbacks_total(),
        dispatch_tick_ms: state.metrics.dispatch_tick_ms(),
    })
}

/// 渲染 Prometheus text exposition（零依赖手写输出）。label 值均为编译期枚举名
///（无用户输入、无转义面），数值均为整数 gauge；`crbs_root` 等敏感/非数值不暴露。
fn render_prometheus_exposition(s: &MetricsSnapshot) -> String {
    use std::fmt::Write as _;
    let queue = build_queue_metrics(&s.counts);
    let mut out = String::with_capacity(1024);

    let _ = writeln!(out, "# HELP crbs_builds_phase Build count by phase.");
    let _ = writeln!(out, "# TYPE crbs_builds_phase gauge");
    for (phase, value) in [
        ("pending", queue.pending),
        ("building", queue.building),
        ("succeeded", queue.succeeded),
        ("failed", queue.failed),
        ("cancelled", queue.cancelled),
    ] {
        let _ = writeln!(out, "crbs_builds_phase{{phase=\"{phase}\"}} {value}");
    }

    let _ = writeln!(
        out,
        "# HELP crbs_builds_total Total builds across the phases exposed above."
    );
    let _ = writeln!(out, "# TYPE crbs_builds_total gauge");
    let _ = writeln!(out, "crbs_builds_total {}", queue.total);

    let _ = writeln!(
        out,
        "# HELP crbs_profiles_total Package resource profile rows (declared and learned)."
    );
    let _ = writeln!(out, "# TYPE crbs_profiles_total gauge");
    let _ = writeln!(out, "crbs_profiles_total {}", s.profiles_total);

    let _ = writeln!(
        out,
        "# HELP crbs_local_builds_max Configured max concurrent local builds."
    );
    let _ = writeln!(out, "# TYPE crbs_local_builds_max gauge");
    let _ = writeln!(out, "crbs_local_builds_max {}", s.concurrency.local_slots);

    let _ = writeln!(
        out,
        "# HELP crbs_local_builds_running Currently running local builds."
    );
    let _ = writeln!(out, "# TYPE crbs_local_builds_running gauge");
    let _ = writeln!(
        out,
        "crbs_local_builds_running {}",
        s.concurrency.local_active
    );

    let _ = writeln!(
        out,
        "# HELP crbs_local_builds_available Idle local build slots."
    );
    let _ = writeln!(out, "# TYPE crbs_local_builds_available gauge");
    let _ = writeln!(
        out,
        "crbs_local_builds_available {}",
        s.concurrency
            .local_slots
            .saturating_sub(s.concurrency.local_active)
    );

    let _ = writeln!(
        out,
        "# HELP crbs_disk_available_bytes Free bytes on the filesystem backing crbs_root."
    );
    let _ = writeln!(out, "# TYPE crbs_disk_available_bytes gauge");
    let _ = writeln!(out, "crbs_disk_available_bytes {}", s.available_bytes);

    // 单一 verdict label 指标覆盖五类 verdict，label 集恒定、缺数据补零
    //（抓取端按 label 做率值才有稳定向量）；全部时间口径、不分 kind，ratio 由看板计算。
    let _ = writeln!(
        out,
        "# HELP crbs_reproducibility_verdict_total Replay comparison count by verdict (all time)."
    );
    let _ = writeln!(out, "# TYPE crbs_reproducibility_verdict_total gauge");
    for verdict in crbs_core::ALL_VERDICTS {
        let count = s.repro_verdicts.get(verdict.as_str()).copied().unwrap_or(0);
        let _ = writeln!(
            out,
            "crbs_reproducibility_verdict_total{{verdict=\"{}\"}} {count}",
            verdict.as_str()
        );
    }

    let _ = writeln!(
        out,
        "# HELP crbs_uptime_seconds Server process uptime in seconds."
    );
    let _ = writeln!(out, "# TYPE crbs_uptime_seconds gauge");
    let _ = writeln!(out, "crbs_uptime_seconds {}", s.uptime_seconds);

    // 进程内 counter 组：进程内 AtomicU64，label 全集补零；重启
    // 清零由抓取端 rate() 容忍。
    let _ = writeln!(
        out,
        "# HELP crbs_build_oom_total Terminal builds classified as OOM by kind (all time)."
    );
    let _ = writeln!(out, "# TYPE crbs_build_oom_total counter");
    for kind in crate::server::metrics::ALL_OOM_KINDS {
        let count = s.build_oom.get(kind.as_str()).copied().unwrap_or(0);
        let _ = writeln!(
            out,
            "crbs_build_oom_total{{kind=\"{}\"}} {count}",
            kind.as_str()
        );
    }

    let _ = writeln!(
        out,
        "# HELP crbs_profile_updates_total Package resource profile learning outcomes (all time)."
    );
    let _ = writeln!(out, "# TYPE crbs_profile_updates_total counter");
    for outcome in crate::server::metrics::ALL_PROFILE_UPDATES {
        let count = s
            .profile_updates
            .get(outcome.as_str())
            .copied()
            .unwrap_or(0);
        let _ = writeln!(
            out,
            "crbs_profile_updates_total{{outcome=\"{}\"}} {count}",
            outcome.as_str()
        );
    }

    // dispatch 系计数：计数器 + tick 耗时 gauge（last/
    // max 两个指标名承载单值 gauge）。assigned/soft_fallbacks 只计实际派发。
    let _ = writeln!(
        out,
        "# HELP crbs_dispatch_admit_rejects_total Dispatch admission rejections by dimension (all time)."
    );
    let _ = writeln!(out, "# TYPE crbs_dispatch_admit_rejects_total counter");
    for dimension in crate::server::metrics::ALL_DISPATCH_REJECTS {
        let count = s
            .dispatch_admit_rejects
            .get(dimension.as_str())
            .copied()
            .unwrap_or(0);
        let _ = writeln!(
            out,
            "crbs_dispatch_admit_rejects_total{{dimension=\"{}\"}} {count}",
            dimension.as_str()
        );
    }

    let _ = writeln!(
        out,
        "# HELP crbs_dispatch_no_candidate_ticks_total Scheduler ticks with free slots, pending builds, and zero dispatches (all time)."
    );
    let _ = writeln!(out, "# TYPE crbs_dispatch_no_candidate_ticks_total counter");
    let _ = writeln!(
        out,
        "crbs_dispatch_no_candidate_ticks_total {}",
        s.dispatch_no_candidate_ticks_total
    );

    let _ = writeln!(
        out,
        "# HELP crbs_dispatch_assigned_total Builds actually dispatched to workers (all time)."
    );
    let _ = writeln!(out, "# TYPE crbs_dispatch_assigned_total counter");
    let _ = writeln!(
        out,
        "crbs_dispatch_assigned_total {}",
        s.dispatch_assigned_total
    );

    let _ = writeln!(
        out,
        "# HELP crbs_dispatch_soft_fallbacks_total Censored past-age builds dispatched to the max-headroom worker (all time)."
    );
    let _ = writeln!(out, "# TYPE crbs_dispatch_soft_fallbacks_total counter");
    let _ = writeln!(
        out,
        "crbs_dispatch_soft_fallbacks_total {}",
        s.dispatch_soft_fallbacks_total
    );

    let _ = writeln!(
        out,
        "# HELP crbs_dispatch_tick_seconds Scheduler tick cost in seconds (planner tick; last and max since process start)."
    );
    let _ = writeln!(out, "# TYPE crbs_dispatch_tick_seconds gauge");
    let _ = writeln!(
        out,
        "crbs_dispatch_tick_seconds{{age=\"last\"}} {:.6}",
        s.dispatch_tick_ms.0 as f64 / 1000.0
    );
    let _ = writeln!(
        out,
        "crbs_dispatch_tick_seconds{{age=\"max\"}} {:.6}",
        s.dispatch_tick_ms.1 as f64 / 1000.0
    );

    out
}

fn build_queue_metrics(counts: &HashMap<String, i64>) -> QueueMetrics {
    let get = |phase: &str| counts.get(phase).copied().unwrap_or(0);
    let pending = get("pending");
    let building = get("building");
    let succeeded = get("succeeded");
    let failed = get("failed");
    let cancelled = get("cancelled");
    let total = pending + building + succeeded + failed + cancelled;
    QueueMetrics {
        pending,
        building,
        succeeded,
        failed,
        cancelled,
        total,
    }
}

fn bytes_to_gb(bytes: u64) -> f64 {
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    (bytes as f64 / GB * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::metrics;
    use crate::server::auth::AuthContext;
    use crate::server::error::ApiError;
    use crate::server::state::AppState;
    use axum::extract::{Extension, State};
    use std::sync::Arc;

    fn ctx(role: &str) -> AuthContext {
        AuthContext {
            user: format!("u-{role}"),
            role: role.into(),
            ..Default::default()
        }
    }

    async fn test_app() -> (Arc<AppState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        (app, tmp)
    }

    #[tokio::test]
    async fn metrics_rejects_viewer_with_forbidden() {
        let (app, _tmp) = test_app().await;
        let result = metrics(State(app), Some(Extension(ctx("viewer")))).await;
        assert!(
            matches!(result, Err(ApiError::PermissionDenied(_))),
            "viewer must be denied, got: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn metrics_allows_operator_and_admin() {
        let (app, _tmp) = test_app().await;
        assert!(
            metrics(State(app.clone()), Some(Extension(ctx("operator"))))
                .await
                .is_ok()
        );
        assert!(metrics(State(app), Some(Extension(ctx("admin"))))
            .await
            .is_ok());
    }

    /// 并发指标为集群口径（state.rs 快照共源）：max = 本地槽 + 在线 worker
    /// 容量，分布式活跃计入 current；离线 worker 容量不计入。
    #[tokio::test]
    async fn metrics_concurrency_is_cluster_wide() {
        use crbs_core::BuildInsert;

        let (app, _tmp) = test_app().await;
        let w_online = app
            .state_store
            .upsert_worker("w-online", "x86_64", 3, "1.0", "online", None)
            .await
            .unwrap();
        let w_offline = app
            .state_store
            .upsert_worker("w-offline", "x86_64", 5, "1.0", "offline", None)
            .await
            .unwrap();
        for (pkg, worker_id) in [("pkg-a", w_online), ("pkg-b", w_offline)] {
            let task_id = crate::test_support::seed_task(&app.state_store, "test", pkg).await;
            let build_id = app
                .state_store
                .insert_build(BuildInsert {
                    product: "test",
                    pkg_name: pkg,
                    backend: "chroot",
                    user: "tester",
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
                .unwrap();
            app.state_store
                .assign_build_to_worker(build_id, worker_id)
                .await
                .unwrap();
        }

        let response = metrics(State(app.clone()), Some(Extension(ctx("operator"))))
            .await
            .unwrap();
        let c = response.0.concurrency;
        assert_eq!(c.local_slots, app.max_local_builds);
        assert_eq!(c.worker_capacity_online, 3);
        assert_eq!(c.distributed_active, 1);
        assert_eq!(c.local_active, 0);
        assert_eq!(c.max, app.max_local_builds + 3);
        assert_eq!(c.current, 1);
        assert_eq!(c.available, app.max_local_builds + 2);
    }

    // ---------- GET /metrics Prometheus 文本暴露格式 ----------

    use super::metrics_prometheus;
    use axum::body::to_bytes;
    use axum::response::IntoResponse;

    #[tokio::test]
    async fn metrics_prometheus_rejects_viewer_with_forbidden() {
        let (app, _tmp) = test_app().await;
        let result = metrics_prometheus(State(app), Some(Extension(ctx("viewer")))).await;
        assert!(
            matches!(result, Err(ApiError::PermissionDenied(_))),
            "viewer must be denied, got: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn metrics_prometheus_allows_operator_admin_and_anonymous() {
        let (app, _tmp) = test_app().await;
        assert!(
            metrics_prometheus(State(app.clone()), Some(Extension(ctx("operator"))))
                .await
                .is_ok()
        );
        assert!(
            metrics_prometheus(State(app.clone()), Some(Extension(ctx("admin"))))
                .await
                .is_ok()
        );
        assert!(metrics_prometheus(State(app), None).await.is_ok());
    }

    #[tokio::test]
    async fn metrics_prometheus_renders_exposition_with_phase_labels() {
        use crbs_core::BuildInsert;

        let (app, _tmp) = test_app().await;
        let task_id = crate::test_support::seed_task(&app.state_store, "test", "pkg").await;
        app.state_store
            .insert_build(BuildInsert {
                product: "test",
                pkg_name: "pkg",
                phase: "pending",
                backend: "chroot",
                user: "tester",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        let response = metrics_prometheus(State(app.clone()), Some(Extension(ctx("operator"))))
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let text = String::from_utf8(body).unwrap();

        for metric in [
            "crbs_builds_phase",
            "crbs_builds_total",
            "crbs_profiles_total",
            "crbs_local_builds_max",
            "crbs_local_builds_running",
            "crbs_local_builds_available",
            "crbs_disk_available_bytes",
            "crbs_reproducibility_verdict_total",
            "crbs_uptime_seconds",
        ] {
            assert!(
                text.contains(&format!("# TYPE {metric} gauge\n")),
                "missing TYPE line for {metric} in:\n{text}"
            );
            assert!(text.contains(&format!("# HELP {metric} ")));
        }

        // 相位 label 数值与 DB 计数同源（预置 1 条 pending）。
        assert!(text.contains("crbs_builds_phase{phase=\"pending\"} 1\n"));
        assert!(text.contains("crbs_builds_phase{phase=\"building\"} 0\n"));
        assert!(text.contains("crbs_builds_phase{phase=\"succeeded\"} 0\n"));
        assert!(text.contains("crbs_builds_phase{phase=\"failed\"} 0\n"));
        assert!(text.contains("crbs_builds_phase{phase=\"cancelled\"} 0\n"));
        assert!(text.contains("crbs_builds_total 1\n"));

        let disk_line = text
            .lines()
            .find(|l| l.starts_with("crbs_disk_available_bytes "))
            .expect("disk line");
        let disk_bytes: u64 = disk_line
            .split(' ')
            .next_back()
            .and_then(|v| v.parse().ok())
            .expect("disk value is an integer");
        assert!(disk_bytes > 0);
        let uptime_line = text
            .lines()
            .find(|l| l.starts_with("crbs_uptime_seconds "))
            .expect("uptime line");
        let uptime: u64 = uptime_line
            .split(' ')
            .next_back()
            .and_then(|v| v.parse().ok())
            .expect("uptime value is an integer");
        assert!(uptime < 3600, "fresh server uptime should be small");

        let gauge = |name: &str| -> u64 {
            text.lines()
                .find(|l| l.starts_with(&format!("{name} ")))
                .unwrap_or_else(|| panic!("line for {name}"))
                .split(' ')
                .next_back()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("integer value for {name}"))
        };
        assert_eq!(
            gauge("crbs_local_builds_max"),
            gauge("crbs_local_builds_running") + gauge("crbs_local_builds_available")
        );

        // 敏感/非数值字段不进 exposition（磁盘路径不外泄）。
        assert!(!text.contains(app.crbs_root.to_string_lossy().as_ref()));
    }

    /// seed 一条比对行（task + 双 build + build_reproducibility，verdict 直写）。
    async fn seed_repro_row(app: &AppState, verdict: &str) {
        let task_id = crate::test_support::seed_task(&app.state_store, "test", "pkg").await;
        use crbs_core::BuildInsert;
        for pkg in ["pkg-1.0-1", "pkg-1.0-2"] {
            app.state_store
                .insert_build(BuildInsert {
                    product: "test",
                    pkg_name: pkg,
                    phase: "succeeded",
                    backend: "chroot",
                    user: "tester",
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        sqlx::query(
            "INSERT INTO build_reproducibility (kind, source_build_id, replay_build_id, verdict) \
             VALUES ('replay', 1, 2, $1)",
        )
        .bind(verdict)
        .execute(app.state_store.pool())
        .await
        .unwrap();
    }

    /// exposition 的 verdict 指标行取值表（label → 计数）。
    fn verdict_lines(text: &str) -> std::collections::HashMap<String, i64> {
        text.lines()
            .filter_map(|l| l.strip_prefix("crbs_reproducibility_verdict_total{verdict=\""))
            .map(|l| {
                let (label, value) = l.split_once("\"} ").expect("verdict line shape");
                (
                    label.to_string(),
                    value.parse::<i64>().expect("integer gauge"),
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn metrics_prometheus_renders_reproducibility_verdicts_from_db() {
        let (app, _tmp) = test_app().await;
        seed_repro_row(&app, "same").await;
        seed_repro_row(&app, "same").await;
        seed_repro_row(&app, "diff").await;

        let response = metrics_prometheus(State(app), Some(Extension(ctx("operator"))))
            .await
            .unwrap()
            .into_response();
        let text = String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        let lines = verdict_lines(&text);
        let expected = [
            ("same", 2),
            ("diff", 1),
            ("build_failed", 0),
            ("dep_unavailable", 0),
            ("infra_error", 0),
        ];
        assert_eq!(lines.len(), 5, "exactly five verdict labels: {text}");
        for (label, count) in expected {
            assert_eq!(lines.get(label), Some(&count), "verdict={label}: {text}");
        }
    }

    /// 降级路径：collect 查询失败置空 map 后，渲染仍输出恒定五类 label 全 0
    ///（label 集不随 DB 故障收缩）；渲染器直测——端点级故障由 phase 计数查询先行 503。
    /// counter 组同模式：快照 map 为空仍按 ALL 全集补零、TYPE 标 counter。
    #[test]
    fn prometheus_exposition_zero_fills_verdicts_when_query_failed() {
        use super::{render_prometheus_exposition, MetricsSnapshot};
        use crate::server::state::ConcurrencySnapshot;
        use std::collections::{BTreeMap, HashMap};
        let snapshot = MetricsSnapshot {
            counts: HashMap::new(),
            concurrency: ConcurrencySnapshot {
                local_active: 0,
                distributed_active: 0,
                local_slots: 0,
                worker_capacity_online: 0,
                total_active: 0,
                total_capacity: 0,
            },
            available_bytes: 0,
            uptime_seconds: 0,
            repro_verdicts: BTreeMap::new(),
            build_oom: BTreeMap::new(),
            profile_updates: BTreeMap::new(),
            profiles_total: 0,
            dispatch_admit_rejects: BTreeMap::new(),
            dispatch_no_candidate_ticks_total: 0,
            dispatch_assigned_total: 0,
            dispatch_soft_fallbacks_total: 0,
            dispatch_tick_ms: (0, 0),
        };
        let text = render_prometheus_exposition(&snapshot);
        let lines = verdict_lines(&text);
        assert_eq!(lines.len(), 5, "label set stays stable: {text}");
        assert!(lines.values().all(|v| *v == 0), "all zeros: {text}");
        assert!(text.contains("# TYPE crbs_reproducibility_verdict_total gauge\n"));

        for (metric, label_key, labels) in [
            (
                "crbs_build_oom_total",
                "kind",
                &["cap", "node", "unknown"][..],
            ),
            (
                "crbs_profile_updates_total",
                "outcome",
                &["learned", "censored", "cap_hit_excluded", "reset"][..],
            ),
        ] {
            assert!(
                text.contains(&format!("# TYPE {metric} counter\n")),
                "counter TYPE line missing for {metric}: {text}"
            );
            for label in labels {
                assert!(
                    text.contains(&format!("{metric}{{{label_key}=\"{label}\"}} 0\n")),
                    "zero-filled line missing for {metric}{{{label_key}={label}}}: {text}"
                );
            }
        }
    }

    /// counter 与 AppState 计数组同源：自增后 Prometheus 文本与 JSON 镜像都
    /// 反映新值（collect → render / response 一条链）。
    #[tokio::test]
    async fn metrics_endpoints_mirror_in_memory_counters() {
        use crate::server::metrics::DispatchRejectDimension;
        use crate::server::metrics::{BuildOomKind, ProfileUpdateKind};

        let (app, _tmp) = test_app().await;
        app.metrics.incr_build_oom(BuildOomKind::Cap);
        app.metrics.incr_profile_update(ProfileUpdateKind::Censored);
        app.metrics
            .incr_dispatch_admit_reject(DispatchRejectDimension::WatermarkMem);
        app.metrics.incr_no_candidate_ticks();
        app.metrics.incr_dispatch_assigned();
        app.metrics.incr_soft_fallbacks();
        app.metrics.record_dispatch_tick_ms(12);

        let response = metrics_prometheus(State(app.clone()), Some(Extension(ctx("admin"))))
            .await
            .unwrap()
            .into_response();
        let text = String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            text.contains("crbs_build_oom_total{kind=\"cap\"} 1\n"),
            "{text}"
        );
        assert!(
            text.contains("crbs_build_oom_total{kind=\"node\"} 0\n"),
            "{text}"
        );
        assert!(
            text.contains("crbs_profile_updates_total{outcome=\"censored\"} 1\n"),
            "{text}"
        );
        assert!(
            text.contains("crbs_profile_updates_total{outcome=\"learned\"} 0\n"),
            "{text}"
        );
        // dispatch 系计数：counter 全集补零 + 标量计数 + tick gauge；
        // 维度全集与 ALL_DISPATCH_REJECTS 同序。
        for (dimension, value) in [
            ("mem", 0),
            ("ncpu", 0),
            ("disk", 0),
            ("watermark_mem", 1),
            ("watermark_cpu", 0),
            ("watermark_tmpfs", 0),
            ("no_fit", 0),
        ] {
            assert!(
                text.contains(&format!(
                    "crbs_dispatch_admit_rejects_total{{dimension=\"{dimension}\"}} {value}\n"
                )),
                "dispatch reject line missing for {dimension}: {text}"
            );
        }
        assert!(
            text.contains("crbs_dispatch_no_candidate_ticks_total 1\n"),
            "{text}"
        );
        assert!(text.contains("crbs_dispatch_assigned_total 1\n"), "{text}");
        assert!(
            text.contains("crbs_dispatch_soft_fallbacks_total 1\n"),
            "{text}"
        );
        assert!(
            text.contains("# TYPE crbs_dispatch_tick_seconds gauge\n"),
            "{text}"
        );
        assert!(
            text.contains("crbs_dispatch_tick_seconds{age=\"last\"} 0.012000\n"),
            "{text}"
        );
        assert!(
            text.contains("crbs_dispatch_tick_seconds{age=\"max\"} 0.012000\n"),
            "{text}"
        );

        let response = metrics(State(app), Some(Extension(ctx("admin"))))
            .await
            .unwrap();
        assert_eq!(response.0.build_oom_total.get("cap"), Some(&1));
        assert_eq!(response.0.build_oom_total.get("unknown"), Some(&0));
        assert_eq!(response.0.profile_updates_total.get("censored"), Some(&1));
        assert_eq!(response.0.profile_updates_total.len(), 4);
        assert_eq!(response.0.build_oom_total.len(), 3);
        assert_eq!(
            response.0.dispatch_admit_rejects_total.get("watermark_mem"),
            Some(&1)
        );
        assert_eq!(response.0.dispatch_admit_rejects_total.len(), 7);
        assert_eq!(response.0.dispatch_no_candidate_ticks_total, 1);
        assert_eq!(response.0.dispatch_assigned_total, 1);
        assert_eq!(response.0.dispatch_soft_fallbacks_total, 1);
        assert_eq!(response.0.dispatch_tick_last_ms, 12);
        assert_eq!(response.0.dispatch_tick_max_ms, 12);
    }

    /// crbs_profiles_total 与 DB 画像行数同源：声明写入建行后，Prometheus
    /// 文本与 JSON 镜像都反映行数（gauge 快照、非进程内 counter）。
    #[tokio::test]
    async fn metrics_endpoints_mirror_profile_rows() {
        let (app, _tmp) = test_app().await;
        app.state_store
            .set_declared_requirements("test", "pkg-a", "x86_64", Some(2048), None, None)
            .await
            .unwrap();
        app.state_store
            .set_declared_requirements("test", "pkg-b", "any", None, Some(2), None)
            .await
            .unwrap();

        let response = metrics_prometheus(State(app.clone()), Some(Extension(ctx("operator"))))
            .await
            .unwrap()
            .into_response();
        let text = String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            text.contains("# TYPE crbs_profiles_total gauge\n"),
            "{text}"
        );
        assert!(text.contains("crbs_profiles_total 2\n"), "{text}");

        let response = metrics(State(app), Some(Extension(ctx("admin"))))
            .await
            .unwrap();
        assert_eq!(response.0.profiles_total, 2);
    }

    use super::{health, HealthQuery};

    async fn health_test_app() -> (Arc<AppState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        (app, tmp)
    }

    #[tokio::test]
    async fn health_default_is_liveness_only() {
        let (app, _tmp) = health_test_app().await;
        let response = health(State(app.clone()), axum::extract::Query(Default::default()))
            .await
            .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], br#"{"status":"ok"}"#);
    }

    #[tokio::test]
    async fn health_deep_ok_with_live_database() {
        let (app, _tmp) = health_test_app().await;
        let response = health(
            State(app.clone()),
            axum::extract::Query(HealthQuery {
                deep: Some("1".into()),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], br#"{"status":"ok","db":"ok"}"#);
    }

    #[tokio::test]
    async fn health_deep_returns_503_when_database_unreachable() {
        let (app, _tmp) = health_test_app().await;
        // 关闭连接池：ping 需新连接即失败，模拟 DB 瞬断（readiness 目标场景，liveness 不受影响）。
        app.state_store.pool().close().await;
        let response = health(
            State(app.clone()),
            axum::extract::Query(HealthQuery {
                deep: Some("1".into()),
            }),
        )
        .await
        .into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], br#"{"status":"degraded","db":"error"}"#);
    }
}
