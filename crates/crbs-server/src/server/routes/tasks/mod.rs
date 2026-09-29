// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 用户可见的 Task 查询端点。

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Extension, Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::server::auth::visibility::{
    compute_visible_products, ensure_product_visible_for_record,
};
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::builds::service::cancel_distributed_build;
use crate::server::state::AppState;

/// 注册 tasks 相关路由。
pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/tasks", get(list_tasks))
        .route("/api/v1/tasks/{id}", get(get_task))
        .route("/api/v1/tasks/{id}/cancel", post(cancel_task))
        .route("/api/v1/tasks/{id}/rebuild", post(rebuild_task))
        .route("/api/v1/tasks/{id}/reproduce", post(reproduce_task))
        .merge(recipe::router())
}

/// 公开路由：匿名受限任务摘要（`crbs download` 无 token profile 的编排元数据）。
pub(crate) fn public_router() -> Router<Arc<AppState>> {
    Router::new().route("/api/v1/public/tasks/{id}", get(public_download_info))
}

/// 匿名下载编排元数据：仅下载链路所需字段（id/product/pkg_name/phase +
/// 子构建 id/arch/phase）。TaskRecord 的 result_dir/user/error_summary 等
/// 服务端字段不透出；builds 复用 ChildBuildSummary 但敏感字段置 None
///（result_dir/started_at/duration/worker——worker 为内部主机名）。
#[derive(serde::Serialize)]
pub(crate) struct PublicDownloadInfoResponse {
    pub id: i64,
    pub product: String,
    pub pkg_name: String,
    pub phase: String,
    pub builds: Vec<crbs_core::types::ChildBuildSummary>,
}

pub(crate) async fn public_download_info(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<PublicDownloadInfoResponse>, ApiError> {
    let task = app
        .state_store
        .get_task(id)
        .await?
        .ok_or_else(|| ApiError::not_found("task", id))?;

    // 门控与产物下载端点同款：public_access.download 关闭时匿名 401（认证
    // 用户不受此限）；产品可见性匿名仅公开产品。
    if app.server_config.auth_enabled && !app.server_config.public_access.download {
        auth.as_ref().ok_or(ApiError::Unauthorized(
            "task download info requires authentication".into(),
        ))?;
    }
    if auth.as_ref().is_none_or(|ctx| ctx.0.role != "worker") {
        ensure_product_visible_for_record(&app, &task.product, auth.as_ref().map(|ext| &ext.0))
            .await?;
    }

    let mut builds = app
        .state_store
        .get_child_build_summaries(id)
        .await
        .map_err(|e| {
            tracing::warn!(task_id = %id, error = %e, "Failed to get child build summaries");
            ApiError::Internal("failed to get child build summaries".into())
        })?;
    for build in &mut builds {
        build.result_dir = None;
        build.started_at = None;
        build.duration = None;
        // worker 名是内部主机名（拓扑信息），匿名面不透出。
        build.worker = None;
    }

    Ok(Json(PublicDownloadInfoResponse {
        id: task.id,
        product: task.product.clone(),
        pkg_name: task.pkg_name.clone(),
        phase: task.phase.clone(),
        builds,
    }))
}

/// Task 详情响应：包含任务记录、子构建摘要、复现血缘（双向）与任务标签。
#[derive(serde::Serialize)]
pub(crate) struct TaskDetailResponse {
    #[serde(flatten)]
    pub task: crbs_core::TaskRecord,
    pub builds: Vec<crbs_core::types::ChildBuildSummary>,
    pub lineage: crbs_core::types::TaskLineage,
    /// 任务标签（按键排序）；无标签为空数组。
    pub labels: Vec<crbs_core::types::TaskLabel>,
}

/// Task 列表查询参数。
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct ListQuery {
    pub product: Option<String>,
    pub phase: Option<String>,
    pub name: Option<String>,
    /// 标签精确过滤（`KEY=VALUE`，首个 `=` 切分）。
    pub label: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort: Option<String>,
}

/// Task 列表响应。
#[derive(serde::Serialize)]
pub(crate) struct TaskListResponse {
    pub total: usize,
    pub tasks: Vec<crbs_core::TaskRecord>,
}

/// 任务及其子构建按 phase 的计数。
#[derive(serde::Serialize)]
pub(crate) struct TaskWithCounts {
    #[serde(flatten)]
    pub task: crbs_core::TaskRecord,
    pub build_counts: HashMap<String, i64>,
}

/// 带子构建计数的 Task 列表响应。
#[derive(serde::Serialize)]
pub(crate) struct TaskListWithCountsResponse {
    pub total: usize,
    pub tasks: Vec<TaskWithCounts>,
}

/// NVR 分组列表响应。
#[derive(serde::Serialize)]
pub(crate) struct NvrGroupListResponse {
    pub total: usize,
    pub groups: Vec<crbs_core::NvrGroupSummary>,
}

/// Task 取消的内部结果。
pub(crate) struct CancelTaskOutcome {
    pub cancelled_build_ids: Vec<i64>,
    /// 因已终态跳过（无需取消）的子构建。
    pub skipped_build_ids: Vec<i64>,
    /// 想取消但没取消掉的子构建（DB 错误、终态守卫 409 竞态）。
    pub failed_build_ids: Vec<i64>,
    pub message: String,
}

/// Task 取消响应。
#[derive(serde::Serialize)]
pub(crate) struct TaskCancelResponse {
    pub task_id: i64,
    pub cancelled_build_ids: Vec<i64>,
    pub skipped_build_ids: Vec<i64>,
    pub failed_build_ids: Vec<i64>,
    pub message: String,
}

pub(crate) async fn get_task(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<TaskDetailResponse>, ApiError> {
    let task = app
        .state_store
        .get_task(id)
        .await?
        .ok_or_else(|| ApiError::not_found("task", id))?;

    // 产品可见性，与列表路径同口径；孤儿产品（已删）按公开处理。
    ensure_product_visible_for_record(&app, &task.product, auth.as_ref().map(|ext| &ext.0)).await?;

    let mut builds = app
        .state_store
        .get_child_build_summaries(id)
        .await
        .map_err(|e| {
            tracing::warn!(task_id = %id, error = %e, "Failed to get child build summaries");
            ApiError::Internal("failed to get child build summaries".into())
        })?;

    // result_dir 是服务端文件系统绝对路径，不回显（与 build detail/list 的
    // sanitize_build_record 同口径）。置 None（null）而非删键：响应键集稳定，
    // 便于 CLI 侧诊断；ChildBuildSummary 对应 Option 字段，null/缺键均落 None。
    for build in &mut builds {
        build.result_dir = None;
    }

    let lineage = app
        .state_store
        .task_lineage(id)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("query task lineage", e))?;

    let labels: Vec<crbs_core::types::TaskLabel> = app
        .state_store
        .get_task_labels(id)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("query task labels", e))?
        .into_iter()
        .map(|(key, value)| crbs_core::types::TaskLabel { key, value })
        .collect();

    Ok(Json(TaskDetailResponse {
        task: sanitize_task_record(task),
        builds,
        lineage,
        labels,
    }))
}

/// 任务记录响应脱敏：`result_dir` / `srpm_path` 是服务端绝对路径，与
/// `sanitize_build_record` 同口径不回显（取文件走 task/build id 端点）。
pub(crate) fn sanitize_task_record(mut task: crbs_core::TaskRecord) -> crbs_core::TaskRecord {
    task.result_dir = None;
    task.srpm_path = None;
    task
}

mod cancel;
mod list;
mod rebuild;
mod recipe;
#[cfg(test)]
mod tests;

pub(crate) use cancel::{cancel_task, cancel_task_for_user};
pub(crate) use list::{
    list_name_groups_for_user, list_nvr_groups_for_user, list_tasks, list_tasks_for_user,
    list_tasks_with_counts_for_user, list_tasks_with_counts_for_user_with_visible,
};
pub(crate) use rebuild::{
    collect_reproduce_entries, rebuild_task, rebuild_task_for_user, reproduce_task,
    reproduce_task_for_user,
};
