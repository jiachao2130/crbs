// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! GC 端点（异步执行）。

use std::sync::Arc;

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::warn_audit_log_failure;
use crate::server::state::{AppState, GcTask, GcTaskStatus};
use crbs_core::config::CrbsConfig;
use crbs_core::gc::{handle_gc, GcArgs};

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/gc", post(trigger_gc))
        .route("/api/v1/gc/{id}", get(get_gc_status))
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct GcRequest {
    pub dry_run: bool,
    pub results: bool,
    pub product: Option<String>,
    pub orphan_mounts: bool,
    pub cache: bool,
    pub all: bool,
    pub policy: bool,
}

#[derive(Serialize)]
pub(crate) struct GcResponse {
    pub task_id: String,
    pub status: &'static str,
}

#[derive(Serialize)]
pub(crate) struct GcStatusResponse {
    pub task_id: String,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<crbs_core::types::GcSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn validate_gc_request(req: &GcRequest) -> Result<(), ApiError> {
    if req.dry_run && !req.results && !req.orphan_mounts && !req.cache && !req.policy {
        return Err(ApiError::Validation(
            "dry_run must be used with results, orphan_mounts, cache, or policy".into(),
        ));
    }
    if req.product.is_some() && !req.results && !req.policy {
        return Err(ApiError::Validation(
            "product must be used with results or policy".into(),
        ));
    }
    if req.all && !req.cache {
        return Err(ApiError::Validation("all must be used with cache".into()));
    }
    if let Some(ref p) = req.product {
        crbs_core::validation::validate_product(p)?;
    }
    Ok(())
}

pub(crate) async fn trigger_gc(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<GcRequest>,
) -> Result<(StatusCode, Json<GcResponse>), ApiError> {
    if let Some(ctx) = auth.as_ref() {
        if !ctx.can_gc() {
            return Err(ApiError::PermissionDenied(
                "only admin and operator can trigger GC".into(),
            ));
        }
    }

    let task_id = start_gc_task(&app, auth.as_ref().map(|ext| &ext.0), req).await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(GcResponse {
            task_id,
            status: "running",
        }),
    ))
}

/// GC 触发共享入口（API `trigger_gc` 与 UI `POST /ui/admin/gc` 复用）：入队即返回
/// task_id、结果落 `gc_tasks`；权限门槛调用方先做（API `can_gc()`，UI operator+ + CSRF）。
pub(crate) async fn start_gc_task(
    app: &Arc<AppState>,
    auth: Option<&AuthContext>,
    req: GcRequest,
) -> Result<String, ApiError> {
    validate_gc_request(&req)?;

    let product = req.product.clone();
    let args = GcArgs {
        results: req.results,
        product: req.product,
        dry_run: req.dry_run,
        orphan_mounts: req.orphan_mounts,
        cache: req.cache,
        all: req.all,
        policy: req.policy,
        // artifact_dir 用 server.toml 覆盖值（含 server root 派生默认）：结果 GC 按此根删 worker 日志副本。
        artifact_dir: Some(app.artifact_dir()),
    };

    let permit = app
        .gc_semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Conflict("gc already running".into()))?;

    let task_id = uuid::Uuid::new_v4().to_string();
    let started_at = chrono::Utc::now();

    {
        let mut tasks = app.gc_tasks.lock().await;
        tasks.insert(
            task_id.clone(),
            GcTask {
                status: GcTaskStatus::Running,
                started_at,
                finished_at: None,
            },
        );
    }

    let app_task = app.clone();
    let gc_tasks = app.gc_tasks.clone();
    let task_id_clone = task_id.clone();
    let retention = app.server_config.gc_result_retention;

    tokio::spawn(async move {
        let _permit = permit;
        // 内层 spawn + 外层 await 监督：内层 panic 经 JoinError 上浮而非静默死亡
        //（否则 gc_tasks 条目永卡 Running）；permit 在外层持有，不受内层 panic 影响。
        let app_exec = app_task.clone();
        let exec = tokio::spawn(async move {
            // crbs_root 显式 pin 成 server root（server.toml 决定），不随 crbs.toml 引擎 root 漂移。
            let mut cfg = CrbsConfig::load_async()
                .await?
                .pinned_to_root(&app_exec.crbs_root);
            // pin 清空显式 result_dir，按 AppState 回填（server.toml 优先、crbs.toml 兜底、
            // None 随 server root 派生）：显式部署下回填使 GC 根与 worker 落库实际位置一致。
            // override 优先级与读路径 result_dir_for 分叉（此处 merge 产品层最高，读 server.toml 最高）。
            cfg.result_dir = app_exec.explicit_result_dir();
            handle_gc(args, &cfg, &app_exec.state_store).await
        });
        let result = flatten_gc_join(task_id_clone.clone(), exec).await;

        // 结果 GC 实删产品目录后重建其发布 repo（受影响产品全 arch 对账）；
        // affected_products 仅实删时非空（dry-run 为空），失败仅 warn。
        if let Ok(ref summary) = result {
            if let Some(ref results) = summary.results {
                for product in &results.affected_products {
                    crate::server::repo_regen::regenerate_product_repo(&app_task, product).await;
                }
            }
        }

        let mut tasks = gc_tasks.lock().await;
        if let Some(task) = tasks.get_mut(&task_id_clone) {
            task.status = match result {
                Ok(summary) => GcTaskStatus::Succeeded(summary),
                Err(e) => {
                    // 错误串可能带内部路径：状态接口只回 safe_message，完整错误进 tracing。
                    tracing::warn!(task_id = %task_id_clone, error = %e, "GC task failed");
                    GcTaskStatus::Failed(e.safe_message())
                }
            };
            // 终态时间同一锁内打点（UI 历史 Duration 列消费）。
            task.finished_at = Some(chrono::Utc::now());
        }

        prune_gc_tasks(&mut tasks, retention);
    });

    if let Some(ctx) = auth {
        let detail = serde_json::json!({
            "dry_run": req.dry_run,
            "results": req.results,
            "product": product,
            "orphan_mounts": req.orphan_mounts,
            "cache": req.cache,
            "policy": req.policy,
        })
        .to_string();
        if let Err(e) = app
            .state_store
            .audit_log(&ctx.user, &ctx.role, "gc", Some(&task_id), Some(&detail))
            .await
        {
            warn_audit_log_failure(&e, "audit_log");
        }
    }

    Ok(task_id)
}

/// GC 任务 join 收口：正常结束透传结果；panic / abort 折算 `Failed`
///（safe_message 脱敏为 "internal error"，panic 载荷细节只进 error 日志）。
async fn flatten_gc_join(
    task_id: String,
    exec: tokio::task::JoinHandle<crbs_core::Result<crbs_core::types::GcSummary>>,
) -> crbs_core::Result<crbs_core::types::GcSummary> {
    match exec.await {
        Ok(r) => r,
        Err(join_err) => {
            tracing::error!(
                task_id = %task_id,
                error = %join_err,
                "GC task panicked; marking task failed"
            );
            Err(crbs_core::error::CrbsError::Internal(
                "gc task panicked; see server logs".into(),
            ))
        }
    }
}

pub(crate) async fn get_gc_status(
    State(app): State<Arc<AppState>>,
    Path(id): Path<String>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<GcStatusResponse>, ApiError> {
    if let Some(ctx) = auth.as_ref() {
        if !ctx.is_operator() {
            return Err(ApiError::PermissionDenied(
                "only operator/admin can view GC status".into(),
            ));
        }
    }

    let tasks = app.gc_tasks.lock().await;
    let task = tasks
        .get(&id)
        .ok_or_else(|| ApiError::not_found("gc task", &id))?;

    let (status, summary, error) = match &task.status {
        GcTaskStatus::Running => ("running", None, None),
        GcTaskStatus::Succeeded(s) => ("succeeded", Some(s.clone()), None),
        GcTaskStatus::Failed(e) => ("failed", None, Some(e.clone())),
    };

    Ok(Json(GcStatusResponse {
        task_id: id,
        status,
        summary,
        error,
    }))
}

fn prune_gc_tasks(tasks: &mut std::collections::HashMap<String, GcTask>, retention: usize) {
    if retention == 0 || tasks.len() <= retention {
        return;
    }

    let mut ids: Vec<_> = tasks.iter().collect();
    ids.sort_by_key(|item| std::cmp::Reverse(item.1.started_at));
    let to_remove: Vec<_> = ids
        .into_iter()
        .skip(retention)
        .map(|(k, _)| k.clone())
        .collect();
    for id in to_remove {
        tasks.remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_gc_request_dry_run_requires_scope() {
        let req = GcRequest {
            dry_run: true,
            ..Default::default()
        };
        assert!(validate_gc_request(&req).is_err());

        let req = GcRequest {
            dry_run: true,
            results: true,
            ..Default::default()
        };
        assert!(validate_gc_request(&req).is_ok());
    }

    #[test]
    fn validate_gc_request_product_requires_results_or_policy() {
        let req = GcRequest {
            product: Some("fedora".into()),
            orphan_mounts: true,
            ..Default::default()
        };
        assert!(validate_gc_request(&req).is_err());

        let req = GcRequest {
            product: Some("fedora".into()),
            results: true,
            ..Default::default()
        };
        assert!(validate_gc_request(&req).is_ok());
    }

    #[test]
    fn validate_gc_request_all_requires_cache() {
        let req = GcRequest {
            all: true,
            ..Default::default()
        };
        assert!(validate_gc_request(&req).is_err());

        let req = GcRequest {
            all: true,
            cache: true,
            ..Default::default()
        };
        assert!(validate_gc_request(&req).is_ok());
    }

    #[test]
    fn validate_gc_request_rejects_invalid_product_name() {
        let req = GcRequest {
            product: Some("fed ora".into()),
            results: true,
            ..Default::default()
        };
        assert!(validate_gc_request(&req).is_err());
    }

    /// panic 经 flatten_gc_join 折算 Err（safe_message 脱敏、载荷不外泄），正常完成透传。
    #[tokio::test]
    async fn flatten_gc_join_maps_panic_to_error_and_passes_through_ok() {
        async fn always_panics() -> crbs_core::Result<crbs_core::types::GcSummary> {
            panic!("boom: /etc/crbs secret")
        }
        let panicked = tokio::spawn(always_panics());
        let err = flatten_gc_join("t-panic".into(), panicked)
            .await
            .expect_err("panic must flatten to Err");
        assert_eq!(err.safe_message(), "internal error", "{err}");

        let ok = tokio::spawn(async move { Ok(crbs_core::types::GcSummary::default()) });
        assert!(
            flatten_gc_join("t-ok".into(), ok).await.is_ok(),
            "normal completion must pass through"
        );
    }
}
