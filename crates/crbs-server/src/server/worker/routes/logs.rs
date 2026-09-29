// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 构建日志上报。

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

use super::require_own_worker;

/// report_logs 落盘 build.log 的单 build 容量上限（512MB）。
///
/// 终态截断之上的 pre-terminal 上限：认证 worker 可在构建期无限追加撑爆
/// 磁盘；超限拒绝追加（不截断现场），实时读取走 10MB FIFO 缓冲不受影响。
pub(super) const MAX_HUB_BUILD_LOG_BYTES: u64 = 512 * 1024 * 1024;

/// report_logs 路由 body limit 在单 chunk 语义上限之上的余量（64KiB）。
///
/// worker 发裸字节 chunk（无 JSON 信封，LogBatcher 单批 ≤ 64KiB + 4KiB - 1），
/// 端点语义上限即 [`crate::server::log_buffer::MAX_LOG_CHUNK_BYTES`]（1MB）。
/// 余量让"刚好超限"（≤ 上限 + 余量）仍到 handler 预检（400 带确切上限，
/// worker 4xx → ValidationFailed 不重试），明显超出才由 layer 直接 413——
/// 否则 `body: Bytes` 先整包缓冲才拒，失控 worker 每请求放大内存。
pub(super) const REPORT_LOGS_BODY_HEADROOM: usize = 64 * 1024;

pub(super) async fn report_logs(
    State(app): State<Arc<AppState>>,
    Path((worker_id, assignment_id)): Path<(i64, i64)>,
    auth: Option<axum::extract::Extension<AuthContext>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _ctx = require_own_worker(&auth, worker_id)?;

    let log_seq = match headers.get("x-crbs-log-seq") {
        None => None,
        Some(v) => Some(
            v.to_str()
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .ok_or_else(|| ApiError::Validation("invalid X-Crbs-Log-Seq header".into()))?,
        ),
    };

    let (build_id, task_worker_id, _task_kind, task_status) = app
        .state_store
        .get_worker_task_meta(assignment_id)
        .await
        .map_err(ApiError::from)?;

    if task_worker_id != Some(worker_id) {
        return Err(ApiError::PermissionDenied(
            "assignment does not belong to worker".into(),
        ));
    }

    if task_status
        .as_deref()
        .is_some_and(|s| matches!(s, "completed" | "failed" | "cancelled"))
    {
        tracing::warn!(
            assignment_id = %assignment_id,
            status = ?task_status,
            "log chunk rejected for terminal assignment"
        );
        return Err(ApiError::Conflict(
            "assignment already reached terminal state; log upload closed".into(),
        ));
    }

    if let Some(seq) = log_seq {
        let accepted = app
            .hub_log_chunk_seq
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&assignment_id)
            .copied()
            .unwrap_or(0);
        if seq <= accepted {
            tracing::debug!(
                assignment_id = %assignment_id,
                seq,
                accepted,
                "Duplicate log chunk ignored (idempotent retry)"
            );
            return Ok(Json(serde_json::json!({"accepted": true})));
        }
    }

    if let Some(id) = build_id {
        if app.log_buffer.has(id) {
            app.log_buffer.register(id);
        } else {
            let seed_log_path = app.artifact_dir().join(id.to_string()).join("build.log");
            match tokio::fs::metadata(&seed_log_path).await {
                Ok(meta) => app.log_buffer.register_with_base(id, meta.len()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => app.log_buffer.register(id),
                Err(e) => {
                    tracing::warn!(
                        build_id = %id,
                        path = %seed_log_path.display(),
                        error = %e,
                        "Log seed stat failed; retrying synchronously before 0-base fallback"
                    );
                    let retry_path = seed_log_path.clone();
                    match tokio::task::spawn_blocking(move || std::fs::metadata(retry_path)).await {
                        Ok(Ok(meta)) => app.log_buffer.register_with_base(id, meta.len()),
                        _ => app.log_buffer.register(id),
                    }
                }
            }
        }
        if !body.is_empty() {
            if body.len() > crate::server::log_buffer::MAX_LOG_CHUNK_BYTES {
                return Err(ApiError::Validation(format!(
                    "log chunk exceeds single-chunk limit of {} bytes",
                    crate::server::log_buffer::MAX_LOG_CHUNK_BYTES
                )));
            }

            // 双写不变量：durable 先行、缓冲后进——按文件实际推进的字节数
            //（durable_len）决定进 LogBuffer 的内容，两侧 offset 一字节对齐；
            // 失败不进缓冲，否则缓冲编号超前文件，offset seek 的消费端
            //（补读 / 补尾 / SSE / 重播种）全读错位。写前失败回 503：chunk
            // 未落盘，worker 5xx → Network 重试重放同 chunk（零错位）。
            let mut durable_len = 0usize;

            let artifact_dir = app.artifact_dir().join(id.to_string());
            let mut dir_ready = {
                let prepared = app
                    .hub_log_dir_prepared
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                prepared.contains(&id)
            };
            if !dir_ready {
                if let Err(e) = tokio::fs::create_dir_all(&artifact_dir).await {
                    tracing::warn!(build_id = %id, error = %e, "Failed to create artifact dir for log persistence");
                    return Err(ApiError::ServiceUnavailable(
                        "log persistence unavailable".into(),
                    ));
                } else {
                    {
                        let mut prepared = app
                            .hub_log_dir_prepared
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        if prepared.len() >= 4096 {
                            prepared.clear();
                        }
                        prepared.insert(id);
                    }
                    crbs_core::privilege::chown_to_crbs_group_async(
                        &artifact_dir,
                        true,
                        "artifact_dir",
                    )
                    .await;
                    if let Err(e) =
                        crbs_core::privilege::chmod_async(&artifact_dir, 0o2770, true).await
                    {
                        tracing::warn!(build_id = %id, error = %e, "chmod 2770 artifact_dir recursive failed; permission invariant not enforced");
                    }
                    dir_ready = true;
                }
            }
            if dir_ready {
                let log_path = artifact_dir.join("build.log");

                let over_cap = match tokio::fs::metadata(&log_path).await {
                    Ok(meta) => meta.len() >= MAX_HUB_BUILD_LOG_BYTES,
                    Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => false,
                    Err(_) => false, // 元数据不可读时放行：open 阶段会给出真实错误
                };
                if over_cap {
                    let mut warned = app
                        .hub_log_cap_warned
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    if warned.len() >= 4096 {
                        warned.clear();
                    }
                    let first = warned.insert(id);
                    if first {
                        tracing::warn!(
                            build_id = %id,
                            limit_bytes = MAX_HUB_BUILD_LOG_BYTES,
                            "build.log exceeds hub persistence cap; refusing further appends"
                        );
                    }
                    durable_len = body.len();
                } else {
                    match tokio::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .mode(0o660)
                        .open(&log_path)
                        .await
                    {
                        Ok(mut file) => {
                            use std::os::unix::fs::PermissionsExt;
                            if let Err(e) = file
                                .set_permissions(std::fs::Permissions::from_mode(0o660))
                                .await
                            {
                                let first = {
                                    let mut warned = app
                                        .hub_log_chmod_warned
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner());
                                    if warned.len() >= 4096 {
                                        warned.clear();
                                    }
                                    warned.insert(id)
                                };
                                if first {
                                    tracing::warn!(
                                        build_id = %id,
                                        path = %log_path.display(),
                                        error = %e,
                                        "failed to chmod build.log to 0660 (perms may not be effective)"
                                    );
                                }
                            }
                            use tokio::io::AsyncWriteExt;
                            let mut write_res = file.write_all(&body).await;
                            if write_res.is_ok() {
                                write_res = file.flush().await;
                            }
                            match write_res {
                                Ok(()) => durable_len = body.len(),
                                Err(e) => {
                                    tracing::warn!(build_id = %id, error = %e, "Failed to append to build.log");
                                    durable_len = match file.metadata().await {
                                        Ok(meta) => {
                                            let buffered =
                                                app.log_buffer.total_size(id).unwrap_or(0) as u64;
                                            let prefix = (meta.len().saturating_sub(buffered)
                                                as usize)
                                                .min(body.len());
                                            if prefix == 0 {
                                                return Err(ApiError::ServiceUnavailable(
                                                    "log persistence unavailable".into(),
                                                ));
                                            }
                                            prefix
                                        }
                                        Err(_) => 0,
                                    };
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(build_id = %id, error = %e, "Failed to open build.log for append");
                            return Err(ApiError::ServiceUnavailable(
                                "log persistence unavailable".into(),
                            ));
                        }
                    }
                }
            }
            if durable_len > 0 {
                app.log_buffer.append(id, body.slice(..durable_len));
            }

            if let Some(seq) = log_seq {
                let mut seqs = app
                    .hub_log_chunk_seq
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if seqs.len() >= 4096 {
                    seqs.clear();
                }
                seqs.insert(assignment_id, seq);
            }
        }
    }

    Ok(Json(serde_json::json!({"accepted": true})))
}
