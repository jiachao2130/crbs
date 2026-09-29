// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产物上传路由：multipart/流式接收、校验与失败清理。

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Extension, Path as AxumPath, State};
use axum::Json;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::builds::{drain_multipart_for_error, ensure_disk_space};
use crate::server::routes::logs::build_phase_is_terminal;
use crate::server::state::AppState;

/// 单文件大小上限：2GB。
const MAX_ARTIFACT_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// 判定 write/flush 的 IO 错误是否为 ENOSPC（hub 盘满）。只按 raw_os_error 单通道
/// 判定：`ErrorKind::StorageFull` 1.83 才稳定，MSRV 1.82 写不了该变体名，Linux 上
/// ENOSPC 必带 raw_os_error = 28。盘满 → 400 不可重试、产物滞留供人工恢复——5xx
/// 会被 worker 映射 Network 整批重传 3 次，满盘下注定再失败。
fn is_disk_full(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENOSPC)
}

/// 盘满 4xx 信封：文案同入口预检 [`ensure_disk_space`]（不回显服务端路径），调用方先 drain。
fn disk_full_api_error() -> ApiError {
    ApiError::Validation("insufficient disk space on server; free up space and retry".into())
}

const fn max_artifact_total_size() -> u64 {
    if cfg!(test) {
        1024 * 1024
    } else {
        10 * 1024 * 1024 * 1024
    }
}

/// 接收 Worker 上传的构建产物（SHA256 manifest 校验）：流式 multipart 边读 chunk 边写盘，请求体不驻留内存。
pub(crate) async fn upload_artifacts(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: axum::http::HeaderMap,
    mut multipart: axum::extract::Multipart,
) -> Result<Json<serde_json::Value>, ApiError> {
    tracing::info!(build_id = %id, "upload_artifacts handler called");

    // 权限检查：只允许 role=worker token（未认证也拒绝），且须持有该 build 的分配行
    //（worker_tasks）——上传触发服务端 GPG 签名与 repo 重建，无归属约束即可越界上传/覆盖、注入伪造 RPM。
    let worker_id = match auth.as_ref() {
        Some(ctx) if ctx.role == "worker" => ctx
            .worker_id
            .ok_or_else(|| ApiError::Internal("worker token missing worker_id".into()))?,
        _ => {
            tracing::warn!(
                role = ?auth.as_ref().map(|ext| ext.role.clone()),
                "Non-worker or unauthenticated artifact upload"
            );
            return Err(ApiError::PermissionDenied(
                "only worker can upload artifacts".into(),
            ));
        }
    };
    let assignment_id = match headers.get("x-crbs-assignment-id") {
        None => None,
        Some(v) => Some(
            v.to_str()
                .ok()
                .and_then(|s| s.trim().parse::<i64>().ok())
                .ok_or_else(|| {
                    ApiError::Validation("invalid X-Crbs-Assignment-Id header".into())
                })?,
        ),
    };

    let assigned = app
        .state_store
        .worker_assigned_to_build(worker_id, id, assignment_id)
        .await
        .map_err(ApiError::from)?;
    if !assigned {
        tracing::warn!(
            worker_id = %worker_id,
            build_id = %id,
            assignment_id = ?assignment_id,
            "Worker not assigned to build (or stale attempt)"
        );
        return Err(ApiError::PermissionDenied(
            "worker is not assigned to this build".into(),
        ));
    }

    let record = app
        .state_store
        .get_build(id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("build", id))?;

    let attempt = if assignment_id.is_none() {
        app.state_store
            .get_build_attempt(id)
            .await
            .map_err(ApiError::from)?
            .unwrap_or(0)
    } else {
        0
    };
    if assignment_id.is_none() && attempt > 0 {
        tracing::warn!(
            worker_id = %worker_id,
            build_id = %id,
            attempt = attempt,
            "Artifact upload without assignment id on a retried build"
        );
        drain_multipart_for_error(&mut multipart).await;
        return Err(ApiError::Conflict(
            "artifact upload on a retried build requires X-Crbs-Assignment-Id; \
             upgrade the worker"
                .into(),
        ));
    }

    if build_phase_is_terminal(&record.phase) {
        tracing::warn!(
            build_id = %id,
            phase = %record.phase,
            "Artifact upload rejected: build already reached terminal state"
        );
        drain_multipart_for_error(&mut multipart).await;
        return Err(ApiError::Conflict(
            "build already reached terminal state; artifact upload rejected".into(),
        ));
    }

    let result_dir = app.result_dir_for_or_default(&record.product).await;
    let upload_dir = if let (Some(task_id), Some(ref arch)) = (record.task_id, &record.arch) {
        result_dir
            .join(task_id.to_string())
            .join(arch)
            .join(id.to_string())
    } else {
        result_dir.join("builds").join(id.to_string())
    };
    tokio::fs::create_dir_all(&upload_dir)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("create upload dir", e))?;
    crate::server::staging::enforce_result_tree_invariant(&upload_dir, &result_dir).await;

    if let Err(e) = ensure_disk_space(&upload_dir, app.server_config.min_free_disk_bytes()).await {
        drain_multipart_for_error(&mut multipart).await;
        return Err(e);
    }

    let upload_guard = crbs_core::sign::acquire_result_dir_upload_lock(&upload_dir)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("acquire upload lock", e))?;

    let staging_dir = upload_dir.join(format!(".upload-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&staging_dir)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("create upload staging dir", e))?;
    let _staging_guard = StagingDirGuard::new(staging_dir.clone());

    let mut manifest_json: Option<String> = None;
    let mut written_files: Vec<(String, PathBuf, String)> = Vec::new();
    let mut total_uploaded: u64 = 0;

    while let Some(mut field) = match multipart.next_field().await {
        Ok(f) => f,
        Err(e) => {
            cleanup_written_files(&written_files).await;
            return Err(ApiError::log_and_internal_with_context(
                "read multipart field",
                e,
            ));
        }
    } {
        let name = field.name().unwrap_or("unknown").to_string();
        match name.as_str() {
            "manifest" => {
                let text = match field.text().await {
                    Ok(t) => t,
                    Err(e) => {
                        cleanup_written_files(&written_files).await;
                        return Err(ApiError::log_and_internal_with_context(
                            "read manifest field",
                            e,
                        ));
                    }
                };
                manifest_json = Some(text);
            }
            "file" => {
                let file_name = field
                    .file_name()
                    .unwrap_or("unknown")
                    .to_string()
                    .replace('\\', "/");
                if file_name.is_empty() || file_name.ends_with('/') {
                    cleanup_written_files(&written_files).await;
                    drop(field);
                    drain_multipart_for_error(&mut multipart).await;
                    return Err(ApiError::Validation(format!(
                        "invalid artifact file name: {}",
                        file_name
                    )));
                }
                let file_path = std::path::Path::new(&file_name);
                if file_path.is_absolute()
                    || file_path
                        .components()
                        .any(|c| !matches!(c, std::path::Component::Normal(_)))
                {
                    cleanup_written_files(&written_files).await;
                    drop(field);
                    drain_multipart_for_error(&mut multipart).await;
                    return Err(ApiError::Validation(format!(
                        "invalid artifact file name: {}",
                        file_name
                    )));
                }

                let dest = staging_dir.join(&file_name);
                if let Some(parent) = dest.parent() {
                    if let Err(e) = tokio::fs::create_dir_all(parent).await {
                        cleanup_written_files(&written_files).await;
                        return Err(ApiError::log_and_internal_with_context(
                            "create parent dir",
                            e,
                        ));
                    }
                }

                let mut file = match tokio::fs::File::create(&dest).await {
                    Ok(f) => f,
                    Err(e) => {
                        cleanup_written_files(&written_files).await;
                        return Err(ApiError::log_and_internal_with_context(
                            "create uploaded file",
                            e,
                        ));
                    }
                };
                let mut hasher = Sha256::new();
                let mut size: u64 = 0;

                while let Some(chunk) = match field.chunk().await {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = tokio::fs::remove_file(&dest).await;
                        cleanup_written_files(&written_files).await;
                        return Err(ApiError::log_and_internal_with_context(
                            "read file chunk",
                            e,
                        ));
                    }
                } {
                    size += chunk.len() as u64;
                    if size > MAX_ARTIFACT_FILE_SIZE {
                        let _ = tokio::fs::remove_file(&dest).await;
                        cleanup_written_files(&written_files).await;
                        drop(field);
                        drain_multipart_for_error(&mut multipart).await;
                        return Err(ApiError::PayloadTooLarge(format!(
                            "artifact '{}' exceeds max file size ({} bytes)",
                            file_name, MAX_ARTIFACT_FILE_SIZE
                        )));
                    }
                    total_uploaded += chunk.len() as u64;
                    if total_uploaded > max_artifact_total_size() {
                        let _ = tokio::fs::remove_file(&dest).await;
                        cleanup_written_files(&written_files).await;
                        drop(field);
                        drain_multipart_for_error(&mut multipart).await;
                        return Err(ApiError::PayloadTooLarge(format!(
                            "artifact upload exceeds total max size ({} bytes)",
                            max_artifact_total_size()
                        )));
                    }
                    hasher.update(&chunk);
                    if let Err(e) = file.write_all(&chunk).await {
                        let _ = tokio::fs::remove_file(&dest).await;
                        cleanup_written_files(&written_files).await;
                        if is_disk_full(&e) {
                            drop(field);
                            drain_multipart_for_error(&mut multipart).await;
                            tracing::warn!(
                                error = %e,
                                file = %file_name,
                                "hub disk full during artifact write"
                            );
                            return Err(disk_full_api_error());
                        }
                        return Err(ApiError::log_and_internal_with_context(
                            "write uploaded file",
                            e,
                        ));
                    }
                }

                if let Err(e) = file.flush().await {
                    let _ = tokio::fs::remove_file(&dest).await;
                    cleanup_written_files(&written_files).await;
                    if is_disk_full(&e) {
                        drop(field);
                        drain_multipart_for_error(&mut multipart).await;
                        tracing::warn!(
                            error = %e,
                            file = %file_name,
                            "hub disk full during artifact flush"
                        );
                        return Err(disk_full_api_error());
                    }
                    return Err(ApiError::log_and_internal_with_context(
                        "flush uploaded file",
                        e,
                    ));
                }

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(e) =
                        tokio::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o660))
                            .await
                    {
                        tracing::warn!(path = %dest.display(), error = %e,
                            "Failed to chmod uploaded artifact to 0660; group rw may not be in effect");
                    }
                    crbs_core::privilege::chown_to_crbs_group_async(
                        &dest,
                        false,
                        "uploaded artifact",
                    )
                    .await;
                }

                let actual_sha256 = format!("{:x}", hasher.finalize());
                tracing::debug!(file_name = %file_name, size = %size, sha256 = %actual_sha256, "File received");
                written_files.push((file_name, dest, actual_sha256));
            }
            _ => {
                tracing::warn!(field_name = %name, "Unknown multipart field, skipping");
            }
        }
    }

    let manifest: std::collections::HashMap<String, String> = match manifest_json {
        Some(json) => {
            match serde_json::from_str::<std::collections::HashMap<String, String>>(&json) {
                Ok(m) => m
                    .into_iter()
                    .map(|(k, v)| (k.replace('\\', "/"), v))
                    .collect(),
                Err(e) => {
                    cleanup_written_files(&written_files).await;
                    return Err(ApiError::Validation(format!("parse manifest: {}", e)));
                }
            }
        }
        None => {
            cleanup_written_files(&written_files).await;
            return Err(ApiError::Validation(
                "missing manifest field in upload".into(),
            ));
        }
    };
    tracing::info!(
        manifest_entries = manifest.len(),
        file_count = written_files.len(),
        "Multipart parsing complete"
    );

    let mut uploaded = Vec::new();
    for (file_name, _, actual_sha256) in &written_files {
        let expected_sha256 = match manifest.get(file_name.as_str()) {
            Some(h) => h,
            None => {
                cleanup_written_files(&written_files).await;
                return Err(ApiError::Validation(format!(
                    "file '{}' not found in manifest",
                    file_name
                )));
            }
        };

        if actual_sha256 != expected_sha256 {
            cleanup_written_files(&written_files).await;
            return Err(ApiError::Validation(format!(
                "SHA256 mismatch for '{}': expected={}, actual={}",
                file_name, expected_sha256, actual_sha256
            )));
        }

        uploaded.push(file_name.clone());
    }

    // 处理 crbs-artifacts.json（零信任模型）：Server 绝不信任 Worker 算的值，
    // 校验失败 → 400 + 回滚已上传文件；旧 Worker（无 JSON）→ 降级：Server 侧从头采集。
    let artifacts_json_entry = written_files
        .iter()
        .find(|(name, _, _)| name == "crbs-artifacts.json");

    let artifacts_to_insert = if let Some((_, json_path, _)) = artifacts_json_entry {
        let json_content = match tokio::fs::read_to_string(json_path).await {
            Ok(c) => c,
            Err(e) => {
                cleanup_written_files(&written_files).await;
                return Err(ApiError::Validation(format!(
                    "read crbs-artifacts.json: {}",
                    e
                )));
            }
        };

        let artifacts_json = match serde_json::from_str::<crbs_core::ArtifactsJson>(&json_content) {
            Ok(v) => v,
            Err(e) => {
                cleanup_written_files(&written_files).await;
                return Err(ApiError::Validation(format!(
                    "parse crbs-artifacts.json: {}",
                    e
                )));
            }
        };

        tracing::info!(
            build_id = %id,
            artifact_count = artifacts_json.artifacts.len(),
            version = artifacts_json.version,
            "crbs-artifacts.json parsed"
        );

        if artifacts_json.version != 1 {
            tracing::warn!(
                version = artifacts_json.version,
                "unknown crbs-artifacts.json version; falling back to server-side harvest"
            );
            match build_fallback_artifacts(&written_files).await {
                Ok(v) => v,
                Err(e) => {
                    cleanup_written_files(&written_files).await;
                    return Err(e);
                }
            }
        } else {
            let mut server_files: std::collections::HashMap<_, _> = written_files
                .iter()
                .filter(|(name, _, _)| name != "crbs-artifacts.json")
                .map(|(name, dest, sha)| (name.clone(), (sha.clone(), dest)))
                .collect();

            for entry in &artifacts_json.artifacts {
                if !server_files.contains_key(&entry.path) {
                    cleanup_written_files(&written_files).await;
                    return Err(ApiError::Validation(format!(
                        "artifact '{}' in JSON but not in uploaded files",
                        entry.path
                    )));
                }
            }

            let mut new_artifacts = Vec::new();
            for entry in artifacts_json.artifacts {
                let (server_sha, abs_path) = match server_files.remove(&entry.path) {
                    Some(v) => v,
                    None => {
                        cleanup_written_files(&written_files).await;
                        return Err(ApiError::Validation(format!(
                            "artifact '{}' missing from server files map",
                            entry.path
                        )));
                    }
                };

                if entry.sha256 != *server_sha {
                    cleanup_written_files(&written_files).await;
                    return Err(ApiError::Validation(format!(
                        "SHA256 mismatch for '{}': worker={}, server={}",
                        entry.path, entry.sha256, server_sha
                    )));
                }

                let actual_size = match tokio::fs::metadata(abs_path).await {
                    Ok(m) => m.len(),
                    Err(e) => {
                        cleanup_written_files(&written_files).await;
                        return Err(ApiError::Validation(format!(
                            "stat '{}' for size validation: {}",
                            entry.path, e
                        )));
                    }
                };

                if entry.size != actual_size {
                    cleanup_written_files(&written_files).await;
                    return Err(ApiError::Validation(format!(
                        "size mismatch for '{}': worker={}, server={}",
                        entry.path, entry.size, actual_size
                    )));
                }

                new_artifacts.push(crbs_core::NewArtifact {
                    relative_path: entry.path,
                    kind: crbs_core::ArtifactKind::from(entry.kind.as_str()),
                    size_bytes: entry.size,
                    sha256: entry.sha256.clone(),
                    unsigned_sha256: Some(entry.sha256),
                    arch: entry.arch,
                    name: entry.name,
                    version: entry.version,
                    release: entry.release,
                    epoch: entry.epoch,
                    metadata_json: None,
                    signed: false,
                });
            }

            for name in server_files.keys() {
                if name.ends_with(".rpm") {
                    cleanup_written_files(&written_files).await;
                    return Err(ApiError::Validation(format!(
                        "RPM '{}' uploaded but missing from crbs-artifacts.json",
                        name
                    )));
                }
            }

            new_artifacts
        }
    } else {
        tracing::info!(
            build_id = %id,
            "crbs-artifacts.json not present; falling back to server-side harvest"
        );

        match build_fallback_artifacts(&written_files).await {
            Ok(v) => v,
            Err(e) => {
                cleanup_written_files(&written_files).await;
                return Err(e);
            }
        }
    };

    match app.state_store.get_build(id).await {
        Ok(Some(rec)) if build_phase_is_terminal(&rec.phase) => {
            tracing::warn!(
                build_id = %id,
                phase = %rec.phase,
                "Artifact upload rejected at commit: build reached terminal state during upload"
            );
            cleanup_written_files(&written_files).await;
            return Err(ApiError::Conflict(
                "build already reached terminal state; artifact upload rejected".into(),
            ));
        }
        Ok(_) => {}
        Err(e) => {
            cleanup_written_files(&written_files).await;
            return Err(ApiError::log_and_internal_with_context(
                "re-check build phase before artifacts insert",
                e,
            ));
        }
    }

    let mut finalized: Vec<(String, bool)> = Vec::with_capacity(written_files.len());
    for (rel, staged, _) in &written_files {
        let final_path = upload_dir.join(rel);
        if let Some(parent) = final_path.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                cleanup_finalized_files(&upload_dir, &finalized).await;
                return Err(ApiError::log_and_internal_with_context(
                    "create artifact parent dir",
                    e,
                ));
            }
        }
        let preexisted = tokio::fs::symlink_metadata(&final_path).await.is_ok();
        if let Err(e) = tokio::fs::rename(staged, &final_path).await {
            cleanup_finalized_files(&upload_dir, &finalized).await;
            return Err(ApiError::log_and_internal_with_context(
                "install uploaded artifact",
                e,
            ));
        }
        finalized.push((rel.clone(), preexisted));
    }

    let result_dir = upload_dir.to_string_lossy().to_string();
    match app
        .state_store
        .commit_uploaded_artifacts(
            id,
            &artifacts_to_insert,
            &result_dir,
            record.backend.as_deref().unwrap_or(""),
            worker_id,
            assignment_id,
        )
        .await
    {
        Ok(crbs_core::UploadedArtifactsCommit::Committed(ids)) => {
            tracing::info!(
                build_id = %id,
                inserted = ids.len(),
                "Artifacts inserted into DB"
            );
        }
        Ok(crbs_core::UploadedArtifactsCommit::GuardRejected) => {
            cleanup_finalized_files(&upload_dir, &finalized).await;
            tracing::warn!(
                build_id = %id,
                worker_id = %worker_id,
                "build phase flipped terminal or assignment revoked during artifacts commit; upload rejected"
            );
            return Err(ApiError::Conflict(
                "build no longer accepts this upload (terminal state or assignment revoked)".into(),
            ));
        }
        Err(crbs_core::UploadedArtifactsCommitError::RolledBack(e)) => {
            cleanup_finalized_files(&upload_dir, &finalized).await;
            return Err(ApiError::log_and_internal_with_context(
                "commit uploaded artifacts tx",
                e,
            ));
        }
        Err(crbs_core::UploadedArtifactsCommitError::CommitUncertain(e)) => {
            return Err(ApiError::log_and_internal_with_context(
                "commit artifacts insert tx",
                e,
            ));
        }
    }

    let app_for_sign = app.clone();
    let product = record.product.clone();
    let pkg_name = record.pkg_name.clone();
    let sign_dir = upload_dir.clone();
    let sign_paths: Vec<(std::path::PathBuf, String)> = finalized
        .iter()
        .map(|(rel, _)| (upload_dir.join(rel), rel.clone()))
        .collect();
    tokio::spawn(async move {
        let _upload_guard = upload_guard;
        crate::server::signing::sign_uploaded_artifacts(
            &app_for_sign,
            &product,
            id,
            &pkg_name,
            &sign_dir,
            &sign_paths,
        )
        .await;
    });

    Ok(Json(serde_json::json!({
        "build_id": id,
        "uploaded": uploaded,
    })))
}

/// 降级模式采集 artifacts（legacy worker / 未知版本 JSON 通用）：从文件名猜 NEVRA，epoch NULL，kind=other。
async fn build_fallback_artifacts(
    written_files: &[(String, PathBuf, String)],
) -> Result<Vec<crbs_core::NewArtifact>, crate::server::error::ApiError> {
    let mut fallback_artifacts = Vec::new();
    for (rel_path, abs_path, sha) in written_files {
        if rel_path == "crbs-artifacts.json" {
            continue;
        }

        let size = tokio::fs::metadata(abs_path)
            .await
            .map_err(|e| {
                crate::server::error::ApiError::log_and_internal_with_context(
                    "stat for fallback artifact insert",
                    e,
                )
            })?
            .len();

        let file_name = std::path::Path::new(rel_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(rel_path);
        let (name, version, release) = crbs_core::engine::artifact_harvest::parse_nevra(file_name);
        let (kind, arch) = crbs_core::engine::artifact_harvest::classify(rel_path);

        fallback_artifacts.push(crbs_core::NewArtifact {
            relative_path: rel_path.clone(),
            kind,
            size_bytes: size,
            sha256: sha.clone(),
            unsigned_sha256: Some(sha.clone()),
            arch,
            name,
            version,
            release,
            epoch: None,
            metadata_json: None,
            signed: false,
        });
    }
    Ok(fallback_artifacts)
}

/// 清理已写入的临时产物文件，用于上传失败时回滚。
pub(crate) async fn cleanup_written_files(files: &[(String, PathBuf, String)]) {
    for (_, path, _) in files {
        if let Err(e) = tokio::fs::remove_file(path).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %path.display(), error = %e, "Failed to cleanup uploaded artifact");
            }
        }
    }
}

/// 提交失败清理：只删本次 rename 新建的文件；覆盖了既有文件的路径保留新
/// 内容（DB 行可能仍指旧哈希，等 worker 重试覆盖收敛——删掉会直接 404）。
async fn cleanup_finalized_files(upload_dir: &std::path::Path, finalized: &[(String, bool)]) {
    for (rel, preexisted) in finalized {
        if *preexisted {
            continue;
        }
        let path = upload_dir.join(rel);
        if let Err(e) = tokio::fs::remove_file(&path).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %path.display(), error = %e, "Failed to cleanup finalized artifact");
            }
        }
    }
}

/// 请求级 staging 目录 guard：无论成功/失败/panic 都异步删除目录（Drop 不能
/// await，交给运行时后台清理）。
struct StagingDirGuard {
    path: PathBuf,
    armed: bool,
}

impl StagingDirGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }
}

impl Drop for StagingDirGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let path = std::mem::take(&mut self.path);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = tokio::fs::remove_dir_all(&path).await;
            });
        }
    }
}

#[cfg(test)]
mod tests;
