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
    // 携带本次 assignment id 时精确匹配：同 worker 被重派同一 build 后，旧
    // attempt 的迟到上传不得命中新分配。无此头时仅在首轮 attempt（attempt
    // == 0）放行，重派后（attempt > 0）强制要求。
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

    // 终态守卫：拒终态集，不要求 building（pending/assigned 均可上传）——重派后旧
    // worker 迟到上传会污染新构建产物目录、触发伪造签名/repo 重建，409 让 worker
    // 重试层停止重试。尚未读任何字段：先吸干请求体再返回，否则 worker 读不到错误响应。
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

    // 产物按 build 独立目录存放：{result_dir}/{task_id}/{arch}/{build_id}/，
    // 非 Task 构建退 {result_dir}/builds/{build_id}/；与 hub-local 写路径
    //（execute.rs）一致，同 task 同 arch 的多个 sidecar（build.log 等）互不覆盖。
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
    // 权限不变量：create_dir_all 各级目录受 umask 削减，逐级补
    // chmod 2770 + crbs 组——本 build 结果子树（含中间层）须三身份可读写。
    crate::server::staging::enforce_result_tree_invariant(&upload_dir, &result_dir).await;

    // 入口磁盘预检：低于 min_free_disk_bytes（默认 1GiB）即 400，避免流式写盘
    // 半途 ENOSPC——半截回滚 + worker 全量重传的代价远高于一次 statvfs。请求体
    // 尚未消费：先吸干再返回，否则 worker 因连接早断读不到 400 响应（同 drain 模式）。
    if let Err(e) = ensure_disk_space(&upload_dir, app.server_config.min_free_disk_bytes()).await {
        drain_multipart_for_error(&mut multipart).await;
        return Err(e);
    }

    // 同一 build 的上传串行化：重试不得与上一请求的落盘/后台签名交错。
    // guard 一路移交给签名任务，签名结束才释放（worker 重试层超时足够覆盖）。
    let upload_guard = crbs_core::sign::acquire_result_dir_upload_lock(&upload_dir)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("acquire upload lock", e))?;

    // 每请求独立 staging 目录：全部文件校验通过后才 rename 到最终路径。
    // 失败清理只动 staging，绝不删上一请求已提交的文件。
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
            // multipart 中断（连接切断/解析错误）：整体上传失败，已写完的文件统一回滚。
            cleanup_written_files(&written_files).await;
            // 500 而非 400：worker 分类下非 401/403/429 的 4xx 不重试，瞬断落
            // 400 会让 worker 放弃整批重传（代价：恶意畸形请求也 500 重试 3 次）。
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
                    // 先吸干请求体再返回 4xx，否则 worker 因连接早断读不到错误
                    // 响应；先 drop(field)：multer 字段独占锁要求上一字段释放后
                    // next_field 才能推进，否则吸干立刻 LockFailure 返回。
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
                        // 整体上传失败统一回滚（当前文件尚未创建，无自清理项）。
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
                        // 半截 dest 与已写文件统一回滚：半截产物会被当成有效文件残留、进入签名/发布流程。
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
                        // 413 而非 400：超限是请求体过大，非字段语义错误。
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
                        // ENOSPC → 4xx 不可重试（见 is_disk_full 文档）；先吸干请求体，否则 worker 读不到 400。
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
                    // flush 同样可能 ENOSPC（延迟分配/配额结算），同 write 的 4xx 语义。
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

                // 权限不变量：文件 0660 + chown 到 crbs 组——root 接收时
                // umask 缺省 0644（world-read、无组写），crbs 侧后续读取或 regen 会 EACCES。
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

    // manifest key 反斜杠统一为正斜杠，与 multipart 文件名口径一致。
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
        // 两个校验失败分支都整体回滚（cleanup 已覆盖当前文件——它已在 written_files 中）。
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
        // === 有 JSON：零信任校验模式 ===
        // 本段所有 `?` 出口都必须回滚已写盘文件：行未落库，无人再走回收链路认领。
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

        // 版本 1 是唯一已知有效版本；更高版本（新 Worker 遇旧 Hub）前向兼容
        // 走降级路径不报错，未来 JSON schema 升级不会炸掉旧 Hub 的上传通道。
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
            // 版本 1：零信任校验——Server 侧 sha256/size 边写边算，已是真值。
            let mut server_files: std::collections::HashMap<_, _> = written_files
                .iter()
                .filter(|(name, _, _)| name != "crbs-artifacts.json")
                .map(|(name, dest, sha)| (name.clone(), (sha.clone(), dest)))
                .collect();

            // 校验 1: 集合相等 — JSON 声明的文件必须与上传文件集完全一致。
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
                        // JSON 重复 path 等：校验 1 保证首查命中，二次落空 = 声明集与上传集不一致。
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

                // Size 零信任校验：用文件系统实际 size（stat）核对 JSON——
                // multipart 期累加的是 HTTP chunk size，不是 metadata size。
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
                    // 签名前哈希留档：首插哈希即未签名字节（worker 上传一律
                    // 未签名），签名后 refresh_signed_files 只改 sha256/size/signed，本列保持。
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

            // 校验 2: 反向集合相等——上传的 RPM/SRPM 必须在 JSON 中（debug 文件可不在）。
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
        // === 无 JSON：旧 Worker 降级模式 ===
        // Server 侧从零采集，确保 DB 至少有路径/大小/SHA256；NEVRA 从文件名猜，epoch NULL。
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

    // TOCTOU 加固：multipart 传输期间构建可能被并发取消/超时/重派完成——
    // 落库前复查 phase，终态则回滚已写盘文件并 409（迟到 artifacts 行会触发
    // 签名与发布 repo 重建）；请求体已读完，无需 drain。
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

    // 全部校验通过：staging 原子 rename 到最终路径（rename 替换目录项本身，
    // 不跟随预植 symlink）。记录每个路径是否早已存在——提交失败时只删本次
    // 新建的文件，绝不删上一请求已提交的内容。
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

    // 落库单事务（相位 + assignment 双 CAS；0 行回滚 / commit 不确定等语义见
    // StateStore::commit_uploaded_artifacts），server 侧只保留失败后的盘上清理。
    // backend 传 record 原值：UPDATE_BUILD_INFO 无条件 SET，传 "" 会把引擎写入的真实 backend 覆写为空串。
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
        // CAS 守卫拒绝（终态翻转/归属剥夺）：rollback 确定未提交，清掉已写盘
        // 文件后 409；残留竞态（剥夺窗口内新旧执行同写同名文件）见 state 层方法注释。
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
        // rollback 确定未提交：行未设 result_dir，无人再走回收链路认领，留着
        // 才是泄漏；worker 重试全量重传，删未落库文件不损收敛语义。
        Err(crbs_core::UploadedArtifactsCommitError::RolledBack(e)) => {
            cleanup_finalized_files(&upload_dir, &finalized).await;
            return Err(ApiError::log_and_internal_with_context(
                "commit uploaded artifacts tx",
                e,
            ));
        }
        // COMMIT 失败：提交结果不确定（可能已持久化、仅响应丢失），不清盘——
        // 删文件会造出"行已设 result_dir 而文件被删"的毒化态（下载/日志定位
        // 失效），由 worker 重试上传收敛兜底。
        Err(crbs_core::UploadedArtifactsCommitError::CommitUncertain(e)) => {
            return Err(ApiError::log_and_internal_with_context(
                "commit artifacts insert tx",
                e,
            ));
        }
    }

    // 服务端 GPG 签名（worker 不持私钥）：后台任务执行避免阻塞上传响应，
    // 签名后刷新 DB 哈希，并在同一后台任务内触发 repo 重建。
    let app_for_sign = app.clone();
    let product = record.product.clone();
    let pkg_name = record.pkg_name.clone();
    let sign_dir = upload_dir.clone();
    let sign_paths: Vec<(std::path::PathBuf, String)> = finalized
        .iter()
        .map(|(rel, _)| (upload_dir.join(rel), rel.clone()))
        .collect();
    tokio::spawn(async move {
        // 上传锁随签名任务持有到签名/刷新完成：重试请求会等待，不会在签名
        // 原地改写字节时截断文件或清理已提交产物。
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

    // 响应不回显服务端绝对 result_dir（脱敏口径）；worker 只看状态码、不消费响应体。
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
        // JSON 自身不入行
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

        // parse_nevra 只吃裸文件名：直接喂 rel_path 会把 "RPMS/x86_64" 目录前缀
        // 混进 DB name 列；classify(rel_path) 不动——以 Path 语义设计，吃目录布局。
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
            // 降级采集同样一律未签名（留档口径同上）。
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
