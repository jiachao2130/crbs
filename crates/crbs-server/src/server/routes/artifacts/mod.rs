// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建产物列表、下载与上传端点。

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;

use crate::server::state::AppState;

pub(crate) mod by_sha256;
pub(crate) mod changelog;
pub(crate) mod download;
pub(crate) mod list;
pub(crate) mod upload;

pub(crate) use by_sha256::by_sha256;
// API handler 与 UI changelog 页共用 core 函数（changelog_for_build / changelog_for_task）。
pub(crate) use changelog::changelog;
pub(crate) use download::download_artifact;
pub(crate) use list::{collect_rpm_file_names, list_artifacts};
pub(crate) use upload::upload_artifacts;

/// 单次任务产物总大小上限（字节）：10GB + 1GB 余量；余量兼作校验失败返回 4xx 前吸干
/// 剩余请求体的读取上限（见 `builds::multipart::drain_multipart_for_error`）。
pub(crate) const ARTIFACT_UPLOAD_BODY_LIMIT: usize = 11 * 1024 * 1024 * 1024;

/// 公开路由：产物下载 + 匿名受限清单（匿名/认证取决于 `server.public_access.download`，
/// 套 `optional_auth_middleware`）。
pub(crate) fn public_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/builds/{id}/artifacts/download",
            get(download_artifact),
        )
        .route(
            "/api/v1/public/builds/{id}/artifacts",
            get(list::list_artifacts_public),
        )
}

/// 受保护路由：产物列表 + 上传。
pub(crate) fn protected_router() -> Router<Arc<AppState>> {
    // Multipart 提取器限流只认 DefaultBodyLimit 扩展（默认 2MB），RequestBodyLimitLayer 不解除该限制，上传必须用 DefaultBodyLimit（单层即足）。
    let upload = Router::new()
        .route(
            "/api/v1/builds/{id}/artifacts/upload",
            post(upload_artifacts),
        )
        .layer(DefaultBodyLimit::max(ARTIFACT_UPLOAD_BODY_LIMIT));

    Router::new()
        .route("/api/v1/builds/{id}/artifacts", get(list_artifacts))
        .route(
            "/api/v1/builds/artifacts/by-sha256/{sha256}",
            get(by_sha256),
        )
        // changelog 走 build 作用域（无 by-sha256 变体）。
        .route("/api/v1/builds/{id}/changelog", get(changelog))
        .merge(upload)
}

#[derive(serde::Deserialize)]
pub(crate) struct DownloadQuery {
    pub file: String,
}
