// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建管理端点：提交、查询、取消、diff。

mod enqueue;
mod multipart;
mod query;
mod recover;
pub(crate) mod service;
mod sign;
mod types;
mod validation;

pub(crate) use crbs_core::BuildOptions;
pub(crate) use enqueue::{
    check_build_chain_visibility, ensure_can_submit_to_product, ensure_no_active_duplicate,
    ensure_shared_result_dir, execute_build, fan_out_builds, map_noarch_to_concrete,
    mark_build_failed, reconcile_artifact_registration, reproduce_fan_out, resolve_arches,
    submit_multipart_builds_common, validate_replay_caps, validate_replay_caps_by_len, FanOutArgs,
    FanOutOutcome, ReproduceArchEntry, ReproduceFanOutArgs,
};
pub(crate) use multipart::{
    drain_multipart_for_error, extract_multipart_build, request_incoming_dir_of,
    upload_body_limit_bytes,
};
pub use recover::recover_pending_builds;
pub(crate) use types::{BuildResponse, ListQuery};
/// 入口磁盘预检，upload/task_new 等 builds 树外调用方经此 re-export 使用。
pub(crate) use validation::ensure_disk_space;

use std::sync::Arc;

use crate::server::state::AppState;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, patch, post};
use axum::Router;
use tower_http::limit::RequestBodyLimitLayer;

/// 注册 builds 相关路由；`max_upload_size_bytes` 限制 SRPM multipart 提交请求体大小。
pub(crate) fn router(max_upload_size_bytes: usize) -> Router<Arc<AppState>> {
    // 提交端点单独设请求体上限：multipart 提取器默认读 DefaultBodyLimit（2MB），
    // 须同时覆盖两个限制层，否则 >2MB SRPM 解析失败。取 2×upload_max + 余量：
    // 返回 4xx 前要吸干剩余请求体（drain_multipart_for_error），余量即读取空间。
    let body_limit = upload_body_limit_bytes(max_upload_size_bytes);
    // `POST /api/v1/tasks` 为提交域别名端点，与 `/api/v1/builds` 同 handler 同上限。
    let submit = Router::new()
        .route("/api/v1/builds", post(enqueue::submit_build))
        .route("/api/v1/tasks", post(enqueue::submit_build))
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(RequestBodyLimitLayer::new(body_limit));

    Router::new()
        .route("/api/v1/builds", get(query::list_builds))
        .merge(submit)
        .route("/api/v1/builds/{id}", get(query::get_build))
        .route("/api/v1/builds/{id}/cancel", post(query::cancel_build))
        .route("/api/v1/builds/{id}/publish", post(query::publish_build))
        .route(
            "/api/v1/builds/{id}/unpublish",
            post(query::unpublish_build),
        )
        .route("/api/v1/builds/{id}/diff", get(query::diff_build))
        .route(
            "/api/v1/builds/{id}/priority",
            patch(query::update_priority),
        )
        .route(
            "/api/v1/builds/{id}/srpm-download",
            get(query::download_srpm),
        )
        .route(
            "/api/v1/builds/{id}/build-packages",
            get(query::download_build_packages),
        )
        .route("/api/v1/builds/{id}/sign", post(sign::sign_build))
        .route(
            "/api/v1/builds/{id}/reproducibility",
            get(query::get_build_reproducibility),
        )
}
