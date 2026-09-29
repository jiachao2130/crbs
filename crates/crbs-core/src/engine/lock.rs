// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 文件锁原语：排他/共享锁、超时与可取消等待。

use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::error::CrbsError;

const DEFAULT_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// 默认文件锁等待超时。
pub(crate) const DEFAULT_FILE_LOCK_TIMEOUT: Duration = Duration::from_secs(300);

/// 文件锁模式：共享锁多个持有者并发兼容，独占锁与其他任何锁互斥。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockMode {
    Shared,
    Exclusive,
}

/// 异步获取文件锁（不可取消）；语义同 [`lock_file_async_cancellable`]，等价于传 `None` token。
pub(crate) async fn lock_file_async(
    path: PathBuf,
    mode: LockMode,
    timeout: Duration,
) -> crate::Result<std::fs::File> {
    lock_file_async_cancellable(path, mode, timeout, None).await
}

/// 异步获取文件锁（可取消，唯一规范入口）。flock 无 async API，实际获取在
/// `spawn_blocking` 中按固定间隔轮询至超时，避免阻塞 tokio worker；`cancel`
/// 触发即退出返回 [`CrbsError::Cancelled`]，否则 drop future 后阻塞任务仍
/// sleep-poll 到超时。调用方持返回的 `File` 期间锁有效，drop 即自动释放。
pub(crate) async fn lock_file_async_cancellable(
    path: PathBuf,
    mode: LockMode,
    timeout: Duration,
    cancel: Option<CancellationToken>,
) -> crate::Result<std::fs::File> {
    let lock_file = open_lock_file(&path).await?;
    // 文件权限不变量：group=crbs、mode≥0660；chown 失败仅 debug（非 root 必 EPERM）。
    crate::privilege::chown_to_crbs_group_async(&path, false, "lock file").await;

    let mode_str = format!("{:?}", mode);
    let cancel = cancel.unwrap_or_default();
    tokio::task::spawn_blocking(move || {
        let start = Instant::now();
        loop {
            // 每次 try_lock 前检查取消，最多延迟一个 poll interval 即退出。
            if cancel.is_cancelled() {
                debug!(path = %path.display(), mode = %mode_str, "Lock wait cancelled");
                return Err(CrbsError::Cancelled);
            }
            let result = match mode {
                LockMode::Shared => fs4::fs_std::FileExt::try_lock_shared(&lock_file),
                LockMode::Exclusive => fs4::fs_std::FileExt::try_lock_exclusive(&lock_file),
            };

            match result {
                Ok(()) => {
                    debug!(path = %path.display(), mode = %mode_str, "Acquired file lock");
                    return Ok(lock_file);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock && start.elapsed() < timeout => {
                    std::thread::sleep(DEFAULT_LOCK_POLL_INTERVAL);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    return Err(CrbsError::io_message(format!(
                        "timeout waiting for {:?} lock {}",
                        mode,
                        path.display()
                    )));
                }
                Err(e) => {
                    return Err(CrbsError::from_io_context("flock", e));
                }
            }
        }
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("lock task panicked: {}", e)))?
}

/// 打开（必要时创建）锁文件，权限修正 0660。group 须可写（crbs 组用户的
/// server 也要能 lock）；setuid root 的 umask(022) 创建出 0644，mode 不符时
/// 补 chmod（非属主必 EPERM）。存量 root:root 锁文件（父目录无 setgid，组
/// 不继承）组身份 write-open 即 EACCES、chmod/chown 均到不了、repo regen
/// 永久卡死——先经 [`converge_legacy_lock_group`] 收敛再重试一次。
async fn open_lock_file(path: &Path) -> crate::Result<std::fs::File> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let lock_file = match OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                converge_legacy_lock_group(&path);
                match OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .read(true)
                    .write(true)
                    .open(&path)
                {
                    Ok(f) => f,
                    Err(_) => {
                        tracing::warn!(
                            path = %path.display(),
                            "Legacy lock file not convergable in this environment; \
                             remove the root-owned lock manually (or run one privileged \
                             repo regen) to unblock this path"
                        );
                        return Err(CrbsError::from_io_context("open lock file", e));
                    }
                }
            }
            Err(e) => return Err(CrbsError::from_io_context("open lock file", e)),
        };

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let need_fix = match std::fs::metadata(&path) {
                Ok(m) => m.permissions().mode() & 0o777 != 0o660,
                Err(_) => true,
            };
            if need_fix {
                if let Err(e) =
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))
                {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "Failed to set lock file mode 0660; group members may not be able to lock"
                    );
                }
            }
        }

        Ok(lock_file)
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("lock task panicked: {}", e)))?
}

/// 存量锁文件的属主/权限收敛（尽力而为）：Linux 下 stat 属主 group 非 crbs
/// 时经特权 backend 补 chown（owner=当前 uid、group=crbs；失败仅 debug，非
/// root 必 EPERM），随后 chmod 0660——chown 成功后本进程即属主、必然生效，
/// 属主自身 mode-broken（0644 等）亦由此修复。非 Linux 跳过 chown 仅 chmod，
/// 组身份由部署侧保证。
#[cfg(unix)]
fn converge_legacy_lock_group(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(m), Ok(gid)) = (std::fs::metadata(path), crate::privilege::crbs_group_gid()) {
            if m.gid() != gid {
                let uid = nix::unistd::getuid().as_raw();
                if let Err(e) = crate::privilege::chown(path, uid, gid, false) {
                    tracing::debug!(
                        path = %path.display(),
                        error = %e,
                        "lock file: legacy owner chown to crbs group failed; skip"
                    );
                }
            }
        }
        // stat 失败或查不到 crbs 组（环境无该组）：无目标组可收敛，跳过 chown。
    }

    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)) {
        tracing::debug!(
            path = %path.display(),
            error = %e,
            "lock file: legacy mode converge chmod 0660 failed; skip"
        );
    }
}

#[cfg(not(unix))]
fn converge_legacy_lock_group(_path: &Path) {}

/// 异步获取共享锁的便捷函数。
pub(crate) async fn lock_shared_async(
    path: PathBuf,
    timeout: Duration,
) -> crate::Result<std::fs::File> {
    lock_file_async(path, LockMode::Shared, timeout).await
}

/// 异步获取独占锁的便捷函数。
pub(crate) async fn lock_exclusive_async(
    path: PathBuf,
    timeout: Duration,
) -> crate::Result<std::fs::File> {
    lock_file_async(path, LockMode::Exclusive, timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;

    fn temp_lock_path() -> (tempfile::NamedTempFile, PathBuf) {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        (tmp, path)
    }

    #[tokio::test]
    async fn test_lock_shared_no_contention() {
        let (_tmp, path) = temp_lock_path();
        let _lock = lock_shared_async(path.clone(), Duration::from_secs(5))
            .await
            .expect("shared lock should succeed without contention");

        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(
            fs4::fs_std::FileExt::try_lock_exclusive(&probe).is_err(),
            "shared lock should block exclusive lock"
        );
    }

    #[tokio::test]
    async fn test_lock_exclusive_no_contention() {
        let (_tmp, path) = temp_lock_path();
        let _lock = lock_exclusive_async(path.clone(), Duration::from_secs(5))
            .await
            .expect("exclusive lock should succeed without contention");

        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(
            fs4::fs_std::FileExt::try_lock_shared(&probe).is_err(),
            "exclusive lock should block shared lock"
        );
        assert!(
            fs4::fs_std::FileExt::try_lock_exclusive(&probe).is_err(),
            "exclusive lock should block another exclusive lock"
        );
    }

    #[tokio::test]
    async fn test_shared_and_exclusive_are_mutually_exclusive() {
        let (_tmp, path) = temp_lock_path();

        let shared = lock_shared_async(path.clone(), Duration::from_secs(5))
            .await
            .expect("shared lock should succeed");

        let result = lock_exclusive_async(path.clone(), Duration::from_millis(50)).await;
        assert!(
            result.is_err(),
            "exclusive lock should fail while shared lock is held"
        );

        drop(shared);
        let _exclusive = lock_exclusive_async(path.clone(), Duration::from_secs(5))
            .await
            .expect("exclusive lock should succeed after shared lock released");
    }

    #[tokio::test]
    async fn test_lock_exclusive_timeout() {
        let (_tmp, path) = temp_lock_path();

        let holder = lock_exclusive_async(path.clone(), Duration::from_secs(5))
            .await
            .expect("exclusive lock should succeed");

        let timeout = Duration::from_millis(100);
        let start = std::time::Instant::now();
        let result = lock_shared_async(path.clone(), timeout).await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "shared lock should timeout");
        assert!(
            elapsed >= timeout,
            "should wait at least the timeout duration"
        );
        assert!(
            elapsed < timeout + Duration::from_millis(200),
            "should return promptly after timeout"
        );

        drop(holder);
    }

    /// 取消令牌触发后等锁循环立即退出并返回 `CrbsError::Cancelled`，而非 sleep-poll 到超时。
    #[tokio::test]
    async fn test_lock_cancel_bails_promptly() {
        use tokio_util::sync::CancellationToken;

        let (_tmp, path) = temp_lock_path();

        // 持有者一直占住独占锁，迫使被测 future 进入轮询等待。
        let _holder = lock_exclusive_async(path.clone(), Duration::from_secs(30))
            .await
            .expect("holder lock should succeed");

        let token = CancellationToken::new();
        let task = tokio::spawn(lock_file_async_cancellable(
            path.clone(),
            LockMode::Shared,
            // 远超断言上限：只有 cancel 能让它提前返回（区分于超时路径）。
            Duration::from_secs(60),
            Some(token.clone()),
        ));

        // 等轮询循环转起来后再取消。
        tokio::time::sleep(Duration::from_millis(200)).await;
        let start = std::time::Instant::now();
        token.cancel();

        let result = task.await.expect("lock task join");
        assert!(
            matches!(result, Err(CrbsError::Cancelled)),
            "expected CrbsError::Cancelled, got {:?}",
            result.map(|_| ())
        );
        // poll interval 100ms，取消后应在一个 interval 内返回。
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "cancel should bail promptly, took {:?}",
            start.elapsed()
        );
    }

    /// 锁文件权限应为 0660（文件权限不变量：group rw）。
    #[cfg(unix)]
    #[tokio::test]
    async fn test_lock_file_mode_is_0660() {
        use std::os::unix::fs::PermissionsExt;

        let (_tmp, path) = temp_lock_path();
        let _lock = lock_shared_async(path.clone(), Duration::from_secs(5))
            .await
            .expect("shared lock should succeed");

        let mode = std::fs::metadata(&path)
            .expect("lock file metadata")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o660,
            "lock file should be group-writable 0660"
        );
    }

    /// mode-broken 存量锁（组写缺失，如 root 建的 0444）write-open 遭 EACCES →
    /// chown + chmod 0660 收敛 → 重试 open 成功、mode 收敛 0660。
    #[cfg(unix)]
    #[tokio::test]
    async fn test_lock_file_self_heals_mode_broken_legacy_file() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".repodata.lock");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();

        let _lock = lock_shared_async(path.clone(), Duration::from_secs(5))
            .await
            .expect("mode-broken legacy lock must self-heal via chmod and open");

        let mode = std::fs::metadata(&path)
            .expect("lock file metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o660, "converged lock mode must be 0660");
    }

    /// 收敛降级路径：父目录不可写 → open create 即 EACCES、chown/chmod 无从
    /// 生效 → 重试仍失败返回原 open 错误（不吞错），warn 披露存量迁移法。
    #[cfg(unix)]
    #[tokio::test]
    async fn test_lock_file_unconvergable_eacces_returns_original_error() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".repodata.lock");
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o555)).unwrap();

        let result = lock_shared_async(path.clone(), Duration::from_millis(50)).await;
        // 恢复目录权限，保证 TempDir 清理可删。
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        let err = result.expect_err("unconvergable EACCES must surface the open error");
        assert!(
            err.to_string().contains("open lock file"),
            "error should carry the original open context: {err}"
        );
    }
}
