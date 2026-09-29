// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 任务取件与派发响应组装。

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

use super::require_own_worker;
use crate::server::worker::dispatch::WorkerDispatch;

#[derive(Deserialize)]
pub struct PollQuery {
    #[serde(default = "default_wait")]
    wait: u64,
}

fn default_wait() -> u64 {
    30
}

/// 长轮询等待上限：巨值 `?wait` 会让连接与 waiter 永挂，钳 120s
///（下一轮 poll 自然衔接，语义无损）。
const MAX_POLL_WAIT_SECS: u64 = 120;

/// 长轮询响应：无任务时字段全部缺席；有任务时为派发给 worker 的 assignment。
#[derive(Serialize)]
pub struct TaskResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    assignment_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    build_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    srpm_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    build_options: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    product_config: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reproduce_packages_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<crate::server::worker::dispatch::AssignmentKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    init_product: Option<String>,
    /// 产品是否对外可注入；worker 侧 `#[serde(default)]`，旧 hub 不下发
    /// → `false`（保守）。
    #[serde(skip_serializing_if = "Option::is_none")]
    product_repo_enabled: Option<bool>,
    /// 本响应是否为重投递（未确认 running 行的重发）：仅重投递路径携带
    /// true。worker 据此对未在执行的重投递打 warn（同身份双进程可见）；
    /// worker 侧缺省按 false 处理。
    #[serde(skip_serializing_if = "Option::is_none")]
    redelivered: Option<bool>,
}

/// Worker 长轮询取任务。
///
/// 契约（GET 语义 = claim，非只读）：成功返回即 assignment 置 running、
/// build 置 building（事务内 CAS 防双领）。坏 assignment 在派发路径终结：
/// JSON 损坏 / 产品配置永久错误 → fail_assignment；arch 不匹配 / 瞬时错误
/// → 重置 pending 待重派。无任务 204。
///
/// 重投递：wait 到期仍无任务时复查本 worker 名下 "running 且 build
/// building" 的行（事务提交在响应前，响应丢失则恒 204、capacity 永久
/// 占用），命中按正常领取同款映射重发、worker 侧去重；仅挂 wait 到期
/// 路径（首查由 check_assigned_task 覆盖，双挂会热循环）。
pub(super) async fn poll_tasks(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<axum::extract::Extension<AuthContext>>,
    axum::extract::Query(q): axum::extract::Query<PollQuery>,
) -> Result<Response, ApiError> {
    let _ctx = require_own_worker(&auth, id)?;

    let worker = app
        .state_store
        .get_worker(id)
        .await
        .map_err(ApiError::from)?;

    let worker = match worker {
        Some(w) => w,
        None => return Err(ApiError::not_found("worker", id)),
    };

    // init gating 已下沉到派发领取 SQL 的 NOT EXISTS 子句（(worker, product) 粒度），无需对整个 worker 做门禁。

    let dispatch = WorkerDispatch::new(app.clone());
    let wait = q.wait.min(MAX_POLL_WAIT_SECS);
    let task = dispatch.wait_for_task(id, &worker.arch, wait).await;

    match task {
        Some(t) => Ok(Json(task_response_from(t, false)).into_response()),
        None => {
            // 响应丢失重投递（见函数 doc）；查询失败 warn 后维持 204
            //（兜底路径不许把 poll 打死），下一轮重试。
            let redelivered = match dispatch.redeliver_running_task(id, &worker.arch).await {
                Ok(task) => task,
                Err(e) => {
                    tracing::warn!(worker_id = %id, error = %e, "poll: running-assignment redelivery check failed");
                    None
                }
            };
            match redelivered {
                Some(t) => Ok(Json(task_response_from(t, true)).into_response()),
                None => Ok((StatusCode::NO_CONTENT, ()).into_response()),
            }
        }
    }
}

/// [`AssignedTask`] → [`TaskResponse`] 统一映射：正常领取与重投递共用
///（防两处字段集漂移），仅 `redelivered` 一处差异。
fn task_response_from(
    t: crate::server::worker::dispatch::AssignedTask,
    redelivered: bool,
) -> TaskResponse {
    TaskResponse {
        assignment_id: Some(t.assignment_id),
        task_id: t.task_id,
        build_id: Some(t.build_id),
        product: Some(t.product),
        srpm_url: if t.srpm_url.is_empty() {
            None
        } else {
            Some(t.srpm_url)
        },
        build_options: if t.build_options.is_null() {
            None
        } else {
            Some(t.build_options)
        },
        product_config: if t.product_config.is_empty() {
            None
        } else {
            Some(t.product_config)
        },
        reproduce_packages_url: t.reproduce_packages_url,
        kind: Some(t.kind),
        init_product: t.init_product,
        product_repo_enabled: Some(t.product_repo_enabled),
        redelivered: if redelivered { Some(true) } else { None },
    }
}

// ======== 上报结果 ========
