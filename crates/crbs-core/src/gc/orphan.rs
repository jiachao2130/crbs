// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 本地孤儿挂载 GC 与锁文件权限修复。

use crate::config::CrbsConfig;
use crate::engine::orphan;
use crate::state::StateStore;
use crate::types::GcOrphanMountsSummary;
use std::path::{Path, PathBuf};

pub(crate) async fn gc_orphan_mounts(
    dry_run: bool,
    crbs_cfg: &CrbsConfig,
    state: &StateStore,
) -> crate::Result<GcOrphanMountsSummary> {
    // 全局活跃构建守卫：先 pid 修复僵尸记录，仍有真实活跃 build 即跳过——本入口
    // 扫描/umount 范围全局（crbs_root + tmp），无守卫会误卸他产品构建中的挂载。
    if crate::engine::gc::should_skip_orphan_cleanup(state).await {
        return Ok(GcOrphanMountsSummary {
            found: 0,
            cleaned: 0,
            removed_dirs: 0,
            dry_run,
        });
    }

    // 合并两种扫描：产品 base_os 目录挂载 + /proc/mounts 中 crbs 相关挂载；只扫
    // {crbs_root} 直接子目录（产品目录），crbs_root 本身不入扫描根——否则其自身
    // 挂载会被误判孤儿卸载。read_dir/迭代错误必须传播，吞掉 = 静默截断伪装"扫描完成"。
    let mut product_roots = Vec::new();
    let mut entries = tokio::fs::read_dir(&crbs_cfg.crbs_root)
        .await
        .map_err(|e| crate::error::CrbsError::from_io_context("read crbs_root", e))?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| crate::error::CrbsError::from_io_context("iterate crbs_root", e))?
    {
        // 单条 file_type 失败按条跳过（目录恰被移走等瞬时态），不截断整轮扫描。
        if let Ok(ft) = entry.file_type().await {
            if ft.is_dir() {
                product_roots.push(entry.path());
            }
        }
    }

    let tmp_dir = crbs_cfg.tmp_dir_or_derived();
    let tmp_dirs: Vec<&std::path::Path> = vec![&crbs_cfg.tmpfs_dir, &tmp_dir];
    let product_root_refs: Vec<&Path> = product_roots.iter().map(|p| p.as_path()).collect();
    let mounts =
        orphan::scan_all_orphan_mounts(&product_root_refs, &crbs_cfg.crbs_root, &tmp_dirs).await;

    let mounts = orphan::filter_active_builds(mounts, state).await?;

    let (other_mounts, shared_found, shared_cleaned, shared_removed_dirs) =
        partition_and_cleanup_shared_layer_mounts(mounts, crbs_cfg, state, dry_run).await?;

    let other_found = other_mounts.len();
    let cleaned = if dry_run {
        0
    } else {
        orphan::umount_all(other_mounts).await.len() + shared_cleaned
    };

    Ok(GcOrphanMountsSummary {
        found: other_found + shared_found,
        cleaned,
        removed_dirs: shared_removed_dirs,
        dry_run,
    })
}

/// 分离普通挂载与 shared_layers_dir 下挂载，并对后者做安全清理。
/// 返回：普通挂载列表（调用方 umount）、shared 下安全可清落数（found 统计）、
/// 实际已 umount 数（dry_run 为 0）、已删不完整 layer 目录数（dry_run 为 0）。
async fn partition_and_cleanup_shared_layer_mounts(
    mounts: Vec<orphan::OrphanMount>,
    crbs_cfg: &CrbsConfig,
    state: &StateStore,
    dry_run: bool,
) -> crate::Result<(Vec<orphan::OrphanMount>, usize, usize, usize)> {
    let shared_layers_dir = crbs_cfg.shared_layers_dir_or_derived();
    let shared_dir = match tokio::fs::canonicalize(&shared_layers_dir).await {
        Ok(d) => d,
        Err(e) => {
            tracing::debug!(
                dir = %shared_layers_dir.display(),
                error = %e,
                "shared_layers_dir not found, skipping shared layer orphan scan"
            );
            return Ok((mounts, 0, 0, 0));
        }
    };

    let (shared_mounts, other_mounts): (Vec<_>, Vec<_>) = mounts
        .into_iter()
        .partition(|m| m.path.starts_with(&shared_dir));

    // 对 shared_layers_dir 再完整扫一次：补前两种扫描未捕获的挂载点，合并统一安全检查。
    let scanned_shared = orphan::scan_mounts_under(&[&shared_dir])
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                dir = %shared_dir.display(),
                error = %e,
                "Failed to scan shared_layers_dir mounts"
            );
            Vec::new()
        });

    // 去重保真值：路径 → fstype（umount_all 按 fstype 把伪 fs 失败降 debug，硬编码
    // "overlay" 会让 proc/sysfs 失败误升 warn 且日志失真）。
    let mut candidate_paths: std::collections::HashMap<PathBuf, String> = shared_mounts
        .into_iter()
        .map(|m| (m.path, m.fstype))
        .collect();
    for m in scanned_shared {
        candidate_paths.insert(m.path, m.fstype);
    }

    // 按路径深度倒序排序，保证子挂载点先卸载
    let mut candidates: Vec<_> = candidate_paths.into_iter().collect();
    candidates.sort_by(|a, b| {
        let depth_a = a.0.components().count();
        let depth_b = b.0.components().count();
        depth_b
            .cmp(&depth_a)
            .then_with(|| b.0.as_os_str().len().cmp(&a.0.as_os_str().len()))
    });

    let mut safe_mounts = Vec::new();
    let mut _locks = Vec::new();

    for (path, fstype) in candidates {
        match is_shared_layer_mount_safe(&path, &shared_dir, state, dry_run).await {
            Ok(Safety::Safe) => {
                safe_mounts.push(orphan::OrphanMount { path, fstype });
            }
            Ok(Safety::SafeWithLock(lock)) => {
                if dry_run {
                    // dry-run 不持锁：锁对象在此 drop 释放
                    drop(lock);
                } else {
                    _locks.push(lock);
                }
                safe_mounts.push(orphan::OrphanMount { path, fstype });
            }
            Ok(Safety::Skipped { reason }) => {
                tracing::debug!(path = %path.display(), reason, "Skipping shared layer orphan mount");
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "Failed to check shared layer mount safety"
                );
            }
        }
    }

    let found = safe_mounts.len();
    let (cleaned, removed_dirs) = if dry_run {
        (0, 0)
    } else {
        // 只把成功 umount 的挂载点交目录回收：失败 = 挂载仍活跃，rm 会穿过挂载点删掉挂载源内容。
        let unmounted = orphan::umount_all(safe_mounts).await;
        let cleaned = unmounted.len();
        let removed_dirs = remove_incomplete_shared_layer_dirs(&unmounted, &shared_dir).await;
        (cleaned, removed_dirs)
    };

    Ok((other_mounts, found, cleaned, removed_dirs))
}

#[derive(Debug)]
enum Safety {
    Safe,
    SafeWithLock(std::fs::File),
    Skipped { reason: &'static str },
}

/// 判断 shared_layers_dir 下挂载点能否安全卸载：路径在其下且能推断 layer digest、
/// `ref_count == 0`，且 `.complete` 存在（层完成，挂载 stale），或 `.lock` 不存在/
/// 可非阻塞获取独占锁（无活跃创建进程）。获锁的不完整层返回持有 `File` 须持至 umount 完成。
async fn is_shared_layer_mount_safe(
    mount_path: &Path,
    shared_dir: &Path,
    state: &StateStore,
    dry_run: bool,
) -> crate::Result<Safety> {
    let digest = match resolve_layer_digest(mount_path, shared_dir) {
        Some(d) => d,
        None => {
            return Ok(Safety::Skipped {
                reason: "cannot resolve layer digest",
            });
        }
    };

    // `?` 不加 db_ctx：内层已带查询语义与 Database/DatabaseUnavailable 分类，二次包装
    // 会把不可用错误降级成普通 Database（丢 503/is_transient）且 Display 双重嵌套。
    let ref_count = state.get_layer_ref_count(&digest).await?;
    match ref_count {
        Some(0) | None => {}
        Some(_n) => {
            return Ok(Safety::Skipped {
                reason: "layer still referenced",
            });
        }
    }

    let layer_dir = shared_dir.join(&digest);
    let complete_marker = layer_dir.join(".complete");
    if tokio::fs::try_exists(&complete_marker)
        .await
        .unwrap_or(false)
    {
        return Ok(Safety::Safe);
    }

    let lock_path = layer_dir.join(".lock");
    let lock_path_c = lock_path.clone();
    let dry_run_c = dry_run;
    let can_lock =
        tokio::task::spawn_blocking(move || try_acquire_exclusive_lock(&lock_path_c, !dry_run_c))
            .await
            .map_err(|e| {
                crate::error::CrbsError::io_message(format!("spawn_blocking lock check: {e}"))
            })?;

    match can_lock {
        LockCheck::Held(lock) => Ok(Safety::SafeWithLock(lock)),
        LockCheck::AcquiredNoHold => Ok(Safety::Safe),
        LockCheck::Busy => Ok(Safety::Skipped {
            reason: "layer creation in progress",
        }),
        LockCheck::Error(e) => Err(crate::error::CrbsError::io_message(format!(
            "check lock {}: {e}",
            lock_path.display()
        ))),
    }
}

/// 从挂载点路径推断 layer digest：取相对 shared_dir 首段，支持 `{shared_dir}/
/// {digest}/merged` 或其任意子目录（如 merged 内额外挂载的 proc/sysfs）；
/// 首段须为合法 blake3 hex（64 位小写十六进制），否则 None。
fn resolve_layer_digest(mount_path: &Path, shared_dir: &Path) -> Option<String> {
    let rel = mount_path.strip_prefix(shared_dir).ok()?;
    let first = rel.components().next()?;
    let digest = first.as_os_str().to_str()?;
    if !super::is_layer_digest(digest) {
        return None;
    }
    Some(digest.to_string())
}

/// umount 后删除不完整 SharedLayer 目录（无 `.complete` 标记）。只删确实 umount
/// 成功的目录（`unmounted` 为成功集合）；有 `.complete` 的层归 SharedLayer GC
/// 管理，避免与 `ref_count`/`scheduled_gc_at` 策略冲突。
async fn remove_incomplete_shared_layer_dirs(unmounted: &[PathBuf], shared_dir: &Path) -> usize {
    use std::collections::HashSet;

    let mut layer_dirs: HashSet<PathBuf> = HashSet::new();
    for path in unmounted {
        if let Some(digest) = resolve_layer_digest(path, shared_dir) {
            layer_dirs.insert(shared_dir.join(digest));
        }
    }

    let mut removed = 0usize;
    for dir in layer_dirs {
        let complete = dir.join(".complete");
        if tokio::fs::try_exists(&complete).await.unwrap_or(false) {
            continue;
        }
        if let Err(e) = super::assert_delete_under_root(shared_dir, &dir) {
            tracing::warn!(
                path = %dir.display(),
                error = %e,
                "Refusing to remove incomplete SharedLayer dir"
            );
            continue;
        }
        // 特权 rm_rf：层树可能含 root/builder 属主文件，非 root 进程 remove_dir_all 会 EACCES。
        match crate::privilege::rm_rf_async(&[dir.as_path()]).await {
            Ok(_) => {
                tracing::debug!(path = %dir.display(), "Removed incomplete SharedLayer dir");
                removed += 1;
            }
            Err(e) => {
                tracing::warn!(
                    path = %dir.display(),
                    error = %e,
                    "Failed to remove incomplete SharedLayer dir"
                );
            }
        }
    }
    removed
}

#[derive(Debug)]
enum LockCheck {
    Held(std::fs::File),
    AcquiredNoHold,
    Busy,
    Error(String),
}

/// 非阻塞获取 `.lock` 独占锁。`create = true`（实际清理）：文件不存在则创建，
/// 获锁后保持打开返回 `Held(File)`，调用方在 umount 期间持锁；`create = false`
///（dry-run）：不建文件，不存在或可获锁均视为可清理，返回 `AcquiredNoHold`（获锁即释放）。
fn try_acquire_exclusive_lock(lock_path: &Path, create: bool) -> LockCheck {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true);
    if create {
        opts.create(true).truncate(false);
    }

    let file = match opts.open(lock_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !create => {
            return LockCheck::AcquiredNoHold;
        }
        Err(e) => return LockCheck::Error(format!("open {}: {e}", lock_path.display())),
    };
    if create {
        fix_created_lock_perms(lock_path);
    }

    match fs4::fs_std::FileExt::try_lock_exclusive(&file) {
        Ok(()) => {
            if create {
                LockCheck::Held(file)
            } else {
                // dry-run：获锁即释放
                let _ = fs4::fs_std::FileExt::unlock(&file);
                LockCheck::AcquiredNoHold
            }
        }
        Err(_) => LockCheck::Busy,
    }
}

/// create=true 建锁文件后的权限修正：setuid root umask(022) 下仅 0644，补 chmod
/// 0660 并 chown 到 crbs 组（root / crbs-server / crbs 组三身份可锁）；chmod 失败
/// warn、chown 失败仅 debug（非 root 必 EPERM）。运行在 spawn_blocking 内，用同步等价 chown 实现。
pub(crate) fn fix_created_lock_perms(lock_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let need_fix = match std::fs::metadata(lock_path) {
            Ok(m) => m.permissions().mode() & 0o777 != 0o660,
            Err(_) => true,
        };
        if need_fix {
            if let Err(e) =
                std::fs::set_permissions(lock_path, std::fs::Permissions::from_mode(0o660))
            {
                if e.kind() == std::io::ErrorKind::NotFound {
                    // 并发 GC 删目录竞态：锁文件已随目录回收，无需收敛。
                    tracing::debug!(
                        path = %lock_path.display(),
                        error = %e,
                        "lock file vanished before perms fix; already reclaimed"
                    );
                } else {
                    tracing::warn!(
                        path = %lock_path.display(),
                        error = %e,
                        "Failed to set lock file mode 0660; group members may not be able to lock"
                    );
                }
            }
        }
        match crate::privilege::crbs_group_gid() {
            Ok(gid) => {
                if let Err(e) =
                    crate::privilege::chown(lock_path, nix::unistd::getuid().as_raw(), gid, false)
                {
                    tracing::debug!(
                        path = %lock_path.display(),
                        error = %e,
                        "lock file: chown to crbs group failed; skip"
                    );
                }
            }
            Err(e) => tracing::debug!(
                path = %lock_path.display(),
                error = %e,
                "lock file: lookup crbs group gid failed; skip chown"
            ),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = lock_path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_layer_digest() {
        let shared = PathBuf::from("/var/lib/crbs/shared_layers");
        let digest = "a".repeat(64);
        assert_eq!(
            resolve_layer_digest(&shared.join(&digest).join("merged"), &shared),
            Some(digest.clone())
        );
        assert_eq!(
            resolve_layer_digest(&shared.join(&digest).join("merged/proc"), &shared),
            Some(digest)
        );
        // shared_dir 自身无 digest 组件
        assert_eq!(resolve_layer_digest(&shared, &shared), None);
        // 目录名不是合法 blake3 hex（64 位小写十六进制）
        assert_eq!(
            resolve_layer_digest(&shared.join("abc123/merged"), &shared),
            None
        );
        assert_eq!(
            resolve_layer_digest(
                &shared
                    .join(format!("{}.upper", "b".repeat(64)))
                    .join("merged"),
                &shared
            ),
            None
        );
    }

    #[tokio::test]
    async fn test_shared_layer_safety_complete_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let shared = tmp.path().join("shared_layers");
        let digest = "1".repeat(64);
        let layer_dir = shared.join(&digest);
        tokio::fs::create_dir_all(&layer_dir).await.unwrap();
        tokio::fs::write(layer_dir.join(".complete"), b"")
            .await
            .unwrap();

        let state = StateStore::new(tmp.path()).await.unwrap();
        state
            .insert_layer(&digest, "fedora", "sha256:xxx", 0)
            .await
            .unwrap();
        let mount = layer_dir.join("merged");

        let result = is_shared_layer_mount_safe(&mount, &shared, &state, false).await;
        match result.unwrap() {
            Safety::Safe => {}
            other => panic!("expected Safe, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_shared_layer_safety_ref_count() {
        let tmp = tempfile::tempdir().unwrap();
        let shared = tmp.path().join("shared_layers");
        let digest = "2".repeat(64);
        let layer_dir = shared.join(&digest);
        tokio::fs::create_dir_all(&layer_dir).await.unwrap();

        let state = StateStore::new(tmp.path()).await.unwrap();
        state
            .insert_layer(&digest, "fedora", "sha256:xxx", 1)
            .await
            .unwrap();

        let mount = layer_dir.join("merged");
        let result = is_shared_layer_mount_safe(&mount, &shared, &state, false).await;
        match result.unwrap() {
            Safety::Skipped { reason } => assert!(reason.contains("referenced")),
            other => panic!("expected Skipped, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_shared_layer_safety_lock_busy() {
        let tmp = tempfile::tempdir().unwrap();
        let shared = tmp.path().join("shared_layers");
        let digest = "3".repeat(64);
        let layer_dir = shared.join(&digest);
        tokio::fs::create_dir_all(&layer_dir).await.unwrap();

        let state = StateStore::new(tmp.path()).await.unwrap();
        state
            .insert_layer(&digest, "fedora", "sha256:xxx", 0)
            .await
            .unwrap();
        let lock_path = layer_dir.join(".lock");

        let holder = tokio::task::spawn_blocking({
            let lock_path = lock_path.clone();
            move || {
                let f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&lock_path)
                    .unwrap();
                fs4::fs_std::FileExt::lock_exclusive(&f).unwrap();
                f
            }
        })
        .await
        .unwrap();

        let mount = layer_dir.join("merged");
        let result = is_shared_layer_mount_safe(&mount, &shared, &state, false).await;
        match result.unwrap() {
            Safety::Skipped { reason } => assert!(reason.contains("creation")),
            other => panic!("expected Skipped, got {:?}", other),
        }

        drop(holder);

        let result = is_shared_layer_mount_safe(&mount, &shared, &state, false).await;
        match result.unwrap() {
            Safety::SafeWithLock(_) | Safety::Safe => {}
            other => panic!("expected safe after lock release, got {:?}", other),
        }
    }
}
