// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 共享层创建：依赖安装、复用判定与创建锁。

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use tracing::{info, warn};

use crate::engine::layer::{bind_mount_dnf_cache, mount_build_layer};
use crate::engine::mount_guard::MountGuard;
use crate::engine::shared_layer::chroot_output_with_cancel;
use crate::engine::shared_layer::cleanup::cleanup_layer_dir;
use crate::engine::shared_layer::inc_layer_ref_on_reuse;
use crate::engine::shared_layer::lock::acquire_layer_lock;
use crate::engine::shared_layer::persist::{
    restore_from_packages, save_packages_list, write_layer_lockfile,
};
use crate::engine::shared_layer::ttl::{
    is_layer_stale, timestamp_marker, write_layer_timestamp, STALE_UPPER_TS_FORMAT,
};
use crate::engine::shared_layer::SharedLayerParams;
use crate::error::CrbsError;
use crate::util::extract_spec_from_srpm;

const REGISTER_LAYER_RETRIES: usize = 3;
const REGISTER_LAYER_RETRY_DELAY: Duration = Duration::from_millis(100);

/// 收尾拆除 overlay：显式 await umount 后再删 workdir/merged——顺序不可倒置
///（挂载点未摘即删，rm 永久 ENOTEMPTY/EACCES 滞留）；两处删除失败只 warn
///（诊断性，不阻断返回路径）。
async fn teardown_merged(guard: &mut MountGuard, workdir: &Path, merged: &Path) {
    guard.umount().await;
    if let Err(e) = tokio::fs::remove_dir_all(workdir).await {
        warn!(path = %workdir.display(), error = %e, "Failed to remove shared layer workdir");
    }
    if let Err(e) = tokio::fs::remove_dir_all(merged).await {
        warn!(path = %merged.display(), error = %e, "Failed to remove shared layer merged dir");
    }
}

/// SharedLayer 的 `dnf builddep` 参数序列（纯函数便于单测）；`--refresh` 强制
/// 回源校验 repomd——dnf 默认 metadata_expire 48h 内不回源，陈旧元数据会在层
/// TTL 内被长期复用（无层路径同款）。`--setopt=install_weak_deps=False`：弱
/// 依赖非 BR 硬要求，关掉收窄装包集、降低构建环境方差（同 Koji
/// install_weak_deps=False）。
pub(crate) fn builddep_args(spec_path_in_rootfs: &str) -> Vec<String> {
    vec![
        "builddep".to_string(),
        "-y".to_string(),
        "--refresh".to_string(),
        "--setopt=tsflags=nodocs".to_string(),
        "--setopt=install_weak_deps=False".to_string(),
        "--setopt=keepcache=1".to_string(),
        spec_path_in_rootfs.to_string(),
    ]
}

/// 单次 SharedLayer 创建尝试。失败后的目录清理必须在 `_held_lock` 仍持有时执行：
/// 锁随 guard drop 释放后另一进程可能已在重建，无锁 cleanup 会删掉其正在写入的文件。
pub(crate) async fn try_create_shared_layer(
    params: &SharedLayerParams<'_>,
    digest: &str,
    layer_dir: &Path,
    upperdir: &Path,
    complete_marker: &Path,
    lock_path: &Path,
) -> crate::Result<(PathBuf, String)> {
    crate::engine::shared_dir::ensure_shared_dir(layer_dir).await?;

    let _held_lock: std::fs::File =
        acquire_layer_lock(params.poll_interval, params.timeout, lock_path, digest).await?;

    // dir_touched：本次尝试是否已改动目录内容（摘标志 / rename-aside / 半成品
    // upper）。已改动 → 失败必须锁内清理，残留会污染下一次重建；未改动（复用
    // 路径的 DB 错误）→ upper 可能仍被并发构建引用，清理会删在用层，原样返回错误。
    let mut dir_touched = false;
    match create_shared_layer_locked(
        params,
        digest,
        layer_dir,
        upperdir,
        complete_marker,
        &mut dir_touched,
    )
    .await
    {
        Ok(result) => Ok(result),
        Err(e) => {
            if dir_touched {
                if let Err(cleanup_err) = cleanup_layer_dir(layer_dir).await {
                    warn!(
                        digest = %digest,
                        path = %layer_dir.display(),
                        error = %cleanup_err,
                        "Failed to cleanup layer dir after failed creation"
                    );
                }
            }
            Err(e)
        }
    }
}

/// 复用既有层：inc 引用计数后返回。inc 报 `LayerNotFound`（.complete 在盘但 DB 行缺失：
/// 注册前崩溃或 GC 删行成功删目录失败）时自愈——重注册后复用（缺行按初始 ref_count upsert）。
pub(crate) async fn reuse_existing_layer(
    params: &SharedLayerParams<'_>,
    digest: &str,
    upperdir: &Path,
) -> crate::Result<(PathBuf, String)> {
    match inc_layer_ref_on_reuse(params.state, digest).await {
        Ok(()) => {}
        Err(CrbsError::LayerNotFound { .. }) => {
            warn!(
                digest = %digest,
                "SharedLayer complete on disk but DB row missing; re-registering"
            );
            let layer_path = upperdir.to_string_lossy().to_string();
            params
                .state
                .insert_layer(digest, &layer_path, params.product, 1)
                .await
                .map_err(|e| {
                    CrbsError::io_message(format!("re-register missing SharedLayer row: {}", e))
                })?;
        }
        Err(e) => return Err(e),
    }
    Ok((upperdir.to_path_buf(), digest.to_string()))
}

/// 锁内创建尝试（`_held_lock` 由 [`try_create_shared_layer`] 持有）；
/// `dir_touched` 见调用方注释。`pub(crate)` 供 tests 直构崩溃残局固定分支。
pub(crate) async fn create_shared_layer_locked(
    params: &SharedLayerParams<'_>,
    digest: &str,
    layer_dir: &Path,
    upperdir: &Path,
    complete_marker: &Path,
    dir_touched: &mut bool,
) -> crate::Result<(PathBuf, String)> {
    let complete_exists = tokio::fs::try_exists(complete_marker).await?;
    if !complete_exists {
        *dir_touched = true;
    }
    if complete_exists {
        let stale = match is_layer_stale(layer_dir, params.staleness).await {
            Ok(stale) => stale,
            Err(e) => {
                warn!(
                    digest = %digest,
                    error = %e,
                    "Failed to recheck SharedLayer staleness under lock; treating as stale and rebuilding"
                );
                true
            }
        };
        if !stale {
            info!(digest = %digest, "SharedLayer cache hit (recheck under lock)");
            return reuse_existing_layer(params, digest, upperdir).await;
        }

        match params.state.get_layer_ref_count(digest).await {
            Ok(Some(0)) | Ok(None) => {}
            Ok(Some(ref_count)) => {
                info!(
                    digest = %digest,
                    ref_count,
                    "Stale SharedLayer still referenced; reusing instead of rebuilding"
                );
                return reuse_existing_layer(params, digest, upperdir).await;
            }
            Err(e) => {
                return Err(CrbsError::io_message(format!(
                    "check ref_count before stale rebuild: {}",
                    e
                )));
            }
        }

        if let Err(e) = tokio::fs::remove_file(complete_marker).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(CrbsError::from_io_context(
                    "remove stale .complete marker",
                    e,
                ));
            }
        }
        let stale_upper = format!(
            "{}.stale.{}",
            upperdir.display(),
            Utc::now().format(STALE_UPPER_TS_FORMAT)
        );
        match tokio::fs::rename(&upperdir, &stale_upper).await {
            Ok(()) => {
                *dir_touched = true;
                info!(digest = %digest, stale_upper = %stale_upper, "Moved stale SharedLayer upperdir aside");
                if let Err(e) = tokio::fs::remove_file(&timestamp_marker(layer_dir)).await {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        warn!(path = %timestamp_marker(layer_dir).display(), error = %e, "Failed to remove stale timestamp marker");
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                *dir_touched = true;
                warn!(
                    digest = %digest,
                    "Stale SharedLayer upperdir already gone (crash residue); rebuilding"
                );
                if let Err(e) = tokio::fs::remove_file(&timestamp_marker(layer_dir)).await {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        warn!(path = %timestamp_marker(layer_dir).display(), error = %e, "Failed to remove stale timestamp marker");
                    }
                }
            }
            Err(e) => {
                warn!(
                    digest = %digest,
                    error = %e,
                    "Failed to move stale SharedLayer upperdir aside (likely in use); restoring marker to reuse"
                );
                if let Err(e2) = tokio::fs::write(complete_marker, "").await {
                    warn!(
                        path = %complete_marker.display(),
                        error = %e2,
                        "Failed to restore .complete marker after rename failure; failing closed"
                    );
                    return Err(CrbsError::from_io_context(
                        "restore .complete marker after rename failure",
                        e2,
                    ));
                }
                return reuse_existing_layer(params, digest, upperdir).await;
            }
        }
    }

    info!(digest = %digest, "Creating SharedLayer");

    let dirty_marker = layer_dir.join(".dirty");
    if tokio::fs::try_exists(&dirty_marker).await.unwrap_or(false)
        || tokio::fs::try_exists(upperdir).await.unwrap_or(false)
    {
        match params.state.get_layer_ref_count(digest).await {
            Ok(Some(0)) | Ok(None) => {}
            Ok(_) => {
                *dir_touched = false;
                return Err(CrbsError::io_message(format!(
                    "SharedLayer leftover present but still referenced (digest {digest}); failing closed, cleanup deferred until refs drop"
                )));
            }
            Err(e) => {
                *dir_touched = false;
                return Err(CrbsError::io_message(format!(
                    "check ref_count before leftover cleanup: {e}"
                )));
            }
        }
        info!(digest = %digest, "Cleaning up leftover layer state");
        cleanup_layer_dir(layer_dir).await?;
    }

    let workdir = layer_dir.join("work");
    let merged = layer_dir.join("merged");
    tokio::fs::create_dir_all(&upperdir)
        .await
        .map_err(|e| CrbsError::from_io_context("create upperdir", e))?;
    tokio::fs::create_dir_all(&workdir)
        .await
        .map_err(|e| CrbsError::from_io_context("create workdir", e))?;
    tokio::fs::create_dir_all(&merged)
        .await
        .map_err(|e| CrbsError::from_io_context("create merged dir", e))?;

    let lowerdir = params.base_os.display().to_string();
    let mut guard = MountGuard::new();
    if let Err(e) = mount_build_layer(
        &merged, upperdir, &workdir, &lowerdir, false, false, &mut guard,
    )
    .await
    {
        guard.umount().await;
        return Err(CrbsError::io_message(format!("mount shared layer: {}", e)));
    }

    if params.dnf_cache_enabled {
        if let Err(e) = bind_mount_dnf_cache(&merged, params.dnf_cache_path, &mut guard).await {
            guard.umount().await;
            return Err(e);
        }
    }

    let saved_packages = match params.state.get_layer_packages(digest).await {
        Ok(pkgs) => pkgs,
        Err(e) => {
            warn!(
                digest = %digest,
                error = %e,
                "Failed to load saved layer packages, falling back to create from scratch"
            );
            None
        }
    };

    let build_result: crate::Result<()> = async {
        if let Some(ref packages_text) = saved_packages {
            info!(digest = %digest, "Attempting restore from saved package list");
            match restore_from_packages(
                layer_dir,
                &merged,
                packages_text,
                digest,
                params.cancel_token,
                params.operation_timeout,
            )
            .await
            {
                Ok(()) => {
                    if let Err(e) = save_packages_list(
                        &merged,
                        layer_dir,
                        params.state,
                        digest,
                        params.product,
                        params.cancel_token,
                        params.operation_timeout,
                    )
                    .await
                    {
                        warn!(digest = %digest, error = %e, "Failed to re-persist saved package list");
                    }

                    if params.record_provenance {
                        if let Err(e) = write_layer_lockfile(
                            &merged,
                            layer_dir,
                            params.package_cache_path,
                            digest,
                            "shared layer restore",
                        )
                        .await
                        {
                            warn!(digest = %digest, error = %e, "Failed to write layer lockfile after restore");
                        }
                    }

                    teardown_merged(&mut guard, &workdir, &merged).await;
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        digest = %digest,
                        error = %e,
                        "Restore failed, falling back to create from scratch"
                    );
                    guard.umount().await;
                    cleanup_layer_dir(layer_dir).await?;
                    tokio::fs::create_dir_all(&upperdir)
                        .await
                        .map_err(|e| CrbsError::from_io_context("recreate upperdir", e))?;
                    tokio::fs::create_dir_all(&workdir)
                        .await
                        .map_err(|e| CrbsError::from_io_context("recreate workdir", e))?;
                    tokio::fs::create_dir_all(&merged)
                        .await
                        .map_err(|e| CrbsError::from_io_context("recreate merged dir", e))?;
                    if let Err(e) = mount_build_layer(
                        &merged,
                        upperdir,
                        &workdir,
                        &lowerdir,
                        false,
                        false,
                        &mut guard,
                    )
                    .await
                    {
                        guard.umount().await;
                        return Err(CrbsError::io_message(format!(
                            "remount shared layer: {}",
                            e
                        )));
                    }
                    if params.dnf_cache_enabled {
                        if let Err(e) =
                            bind_mount_dnf_cache(&merged, params.dnf_cache_path, &mut guard).await
                        {
                            guard.umount().await;
                            return Err(e);
                        }
                    }
                }
            }
        }

        let spec_extract_dir = {
            let tmp_dir = params.tmp_dir.to_path_buf();
            tokio::task::spawn_blocking(move || tempfile::TempDir::new_in(&tmp_dir))
        }
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking spec extract tempdir: {}", e)))?
        .map_err(|e| CrbsError::from_io_context("create spec extract tempdir", e))?;
        let spec_path = extract_spec_from_srpm(
            params.srpm,
            spec_extract_dir.path(),
            params.cancel_token,
            params.operation_timeout,
        )
        .await?;
        let spec_name = spec_path
            .file_name()
            .ok_or_else(|| {
                CrbsError::io_message(format!("extracted spec path has no file name: {}", spec_path.display()))
            })?
            .to_string_lossy();

        let specs_dir = merged.join("builddir").join("SPECS");
        tokio::fs::create_dir_all(&specs_dir)
            .await
            .map_err(|e| CrbsError::from_io_context("create SPECS dir", e))?;
        let dest_spec = specs_dir.join(&*spec_name);
        tokio::fs::copy(&spec_path, &dest_spec)
            .await
            .map_err(|e| CrbsError::from_io_context("copy spec", e))?;

        info!(digest = %digest, "Installing dependencies into SharedLayer");
        let log_path = layer_dir.join("builddep.log");
        let spec_path_in_rootfs = format!("/builddir/SPECS/{}", spec_name);
        let builddep_args = builddep_args(&spec_path_in_rootfs);
        let arg_refs: Vec<&str> = builddep_args.iter().map(String::as_str).collect();
        let output = chroot_output_with_cancel(
            &merged,
            "dnf",
            &arg_refs,
            params.cancel_token,
            params.operation_timeout,
        )
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn dnf builddep: {}", e)))?;

        let mut log = match tokio::fs::File::create(&log_path).await {
            Ok(f) => {
                super::fix_layer_file_perms(&log_path).await;
                Some(f)
            }
            Err(e) => {
                warn!(path = %log_path.display(), error = %e, "Failed to create builddep log; continuing without it");
                None
            }
        };
        use tokio::io::AsyncWriteExt;
        if let Some(log) = log.as_mut() {
            if let Err(e) = log.write_all(&output.stdout).await {
                warn!(path = %log_path.display(), error = %e, "Failed to write builddep stdout to log");
            }
            if let Err(e) = log.write_all(&output.stderr).await {
                warn!(path = %log_path.display(), error = %e, "Failed to write builddep stderr to log");
            }
        }

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let message = format!(
                "dnf builddep failed: exit_code={:?}, see {}",
                output.status.code(),
                log_path.display()
            );
            return Err(if crate::error::looks_like_network_failure(&stderr) {
                CrbsError::Network { message }
            } else {
                CrbsError::io_message(message)
            });
        }

        if let Err(e) = save_packages_list(
            &merged,
            layer_dir,
            params.state,
            digest,
            params.product,
            params.cancel_token,
            params.operation_timeout,
        )
        .await
        {
            warn!(digest = %digest, error = %e, "Failed to persist installed package list; continuing");
        }

        if params.record_provenance {
            if let Err(e) = write_layer_lockfile(
                &merged,
                layer_dir,
                params.package_cache_path,
                digest,
                "shared layer create",
            )
            .await
            {
                warn!(digest = %digest, error = %e, "Failed to write layer lockfile; continuing");
            }
        }

        teardown_merged(&mut guard, &workdir, &merged).await;

        Ok(())
    }
    .await;

    match build_result {
        Ok(()) => {
            tokio::fs::write(&complete_marker, "")
                .await
                .map_err(|e| CrbsError::from_io_context("write .complete", e))?;
            write_layer_timestamp(&timestamp_marker(layer_dir)).await?;
            info!(digest = %digest, "SharedLayer created");

            let layer_path_str = upperdir.to_string_lossy().to_string();
            let mut last_err = None;
            for attempt in 0..REGISTER_LAYER_RETRIES {
                match params
                    .state
                    .insert_layer(digest, &layer_path_str, params.product, 1)
                    .await
                {
                    Ok(()) => {
                        info!(digest = %digest, "Registered SharedLayer in state DB");
                        return Ok((upperdir.to_path_buf(), digest.to_string()));
                    }
                    Err(e) if attempt + 1 < REGISTER_LAYER_RETRIES => {
                        warn!(
                            digest = %digest,
                            attempt = attempt + 1,
                            error = %e,
                            "Failed to register SharedLayer in state DB, retrying"
                        );
                        tokio::time::sleep(REGISTER_LAYER_RETRY_DELAY).await;
                        last_err = Some(e);
                    }
                    Err(e) => {
                        last_err = Some(e);
                        break;
                    }
                }
            }

            let e = last_err
                .unwrap_or_else(|| CrbsError::io_message("register SharedLayer in state DB"));
            warn!(
                digest = %digest,
                error = %e,
                "Failed to register SharedLayer in state DB after retries; removing .complete/.timestamp"
            );
            if let Err(e2) = tokio::fs::remove_file(&complete_marker).await {
                if e2.kind() != std::io::ErrorKind::NotFound {
                    warn!(path = %complete_marker.display(), error = %e2, "Failed to remove .complete after registration failure");
                }
            }
            let ts_marker = timestamp_marker(layer_dir);
            if let Err(e2) = tokio::fs::remove_file(&ts_marker).await {
                if e2.kind() != std::io::ErrorKind::NotFound {
                    warn!(path = %ts_marker.display(), error = %e2, "Failed to remove .timestamp after registration failure");
                }
            }
            Err(CrbsError::io_message(format!(
                "register SharedLayer in state DB after {} retries: {}",
                REGISTER_LAYER_RETRIES, e
            )))
        }
        Err(e) => {
            guard.umount().await;
            Err(e)
        }
    }
}
