// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 挂载护栏：登记已建挂载，异常路径按逆序卸载。

use std::path::PathBuf;
use std::sync::Mutex;

use crate::engine::mount::MsFlags;
#[cfg(target_os = "linux")]
use crate::engine::mount::{umount2, MntFlags};
use crate::error::CrbsError;

/// 全局 stale umount 列表：async umount 失败时记录，cleanup 时重试。
pub static STALE_UMOUNTS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// RAII mount 守卫：mount 成功后立即 `push()` 注册；正常路径必须显式 `umount()`
/// 后再丢弃，Drop 仅 panic/abort 兜底（detached 线程 lazy umount，不保证完成）。
pub(crate) struct MountGuard {
    mounts: Vec<PathBuf>,
}

impl MountGuard {
    pub fn new() -> Self {
        Self { mounts: Vec::new() }
    }

    pub fn push(&mut self, path: PathBuf) {
        self.mounts.push(path);
    }

    /// 取出挂载点列表（供 `PreparedEnv::drop` 兜底线程）；取走后本 guard 的 Drop 不 umount。
    pub(crate) fn take_mounts(&mut self) -> Vec<PathBuf> {
        std::mem::take(&mut self.mounts)
    }

    /// Bind-mount `source`→`target` 并置 private；bind 成功即注册 target，private 步失败时已注册、cleanup 必 umount（防泄漏）。
    pub async fn bind_mount_private(
        &mut self,
        source: Option<&std::path::Path>,
        target: &std::path::Path,
        context: &str,
    ) -> crate::Result<()> {
        let target_bind = target.to_path_buf();
        let source_bind = source.map(|p| p.to_path_buf());
        tokio::task::spawn_blocking(move || {
            crate::engine::mount::mount(
                source_bind.as_deref(),
                &target_bind,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking bind mount {context}: {e}")))?
        .map_err(|e| CrbsError::io_message(format!("bind mount {context}: {e}")))?;

        self.push(target.to_path_buf());

        let target_private = target.to_path_buf();
        tokio::task::spawn_blocking(move || {
            crate::engine::mount::mount(
                None::<&std::path::Path>,
                &target_private,
                None::<&str>,
                MsFlags::MS_PRIVATE,
                None::<&str>,
            )
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking private mount {context}: {e}")))?
        .map_err(|e| CrbsError::io_message(format!("private mount {context}: {e}")))?;

        Ok(())
    }

    /// 显式逆序 lazy umount：取空列表（Drop 不重复执行），失败记入 STALE_UMOUNTS 供 cleanup 重试。
    #[cfg(target_os = "linux")]
    pub async fn umount(&mut self) {
        let to_umount = std::mem::take(&mut self.mounts)
            .into_iter()
            .rev()
            .collect::<Vec<_>>();
        // 副本：spawn_blocking panic（JoinError）时 move 进闭包的列表取不回，用副本记入 STALE_UMOUNTS 交 orphan 清理兜底。
        let pending = to_umount.clone();
        let joined = tokio::task::spawn_blocking(move || {
            for m in to_umount {
                if let Err(e) = umount2(&m, MntFlags::MNT_DETACH) {
                    tracing::warn!(path = %m.display(), error = %e, "umount failed, recording for retry");
                    match STALE_UMOUNTS.lock() {
                        Ok(mut stale) => stale.push(m),
                        // 中毒时记录丢失：显式 warn（orphan 清理将看不到该挂载）。
                        Err(e) => tracing::warn!(
                            error = ?e,
                            path = %m.display(),
                            "STALE_UMOUNTS poisoned; stale mount record lost"
                        ),
                    }
                }
            }
        })
        .await;
        if let Err(e) = joined {
            tracing::warn!(error = %e, "spawn_blocking umount task failed");
            match STALE_UMOUNTS.lock() {
                Ok(mut stale) => stale.extend(pending),
                Err(e) => tracing::warn!(
                    error = ?e,
                    count = pending.len(),
                    "STALE_UMOUNTS poisoned; pending umount records lost"
                ),
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn umount(&mut self) {
        let _ = std::mem::take(&mut self.mounts);
    }
}

pub fn take_stale_umounts() -> Vec<PathBuf> {
    STALE_UMOUNTS
        .lock()
        .map(|mut v| std::mem::take(&mut *v))
        .unwrap_or_else(|e| {
            tracing::warn!(error = ?e, "STALE_UMOUNTS lock poisoned, returning empty");
            Vec::new()
        })
}

/// 同步逆序 lazy umount，失败记入 STALE_UMOUNTS 供重试（Drop detached 兜底线程共用）。
#[cfg(target_os = "linux")]
pub(crate) fn sync_lazy_umount_all(mounts: Vec<PathBuf>) {
    for m in mounts.into_iter().rev() {
        if let Err(e) = umount2(&m, MntFlags::MNT_DETACH) {
            tracing::warn!(path = %m.display(), error = %e, "lazy umount failed, recording for retry");
            match STALE_UMOUNTS.lock() {
                Ok(mut stale) => stale.push(m),
                Err(e) => tracing::warn!(
                    error = ?e,
                    path = %m.display(),
                    "STALE_UMOUNTS poisoned; stale mount record lost"
                ),
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn sync_lazy_umount_all(mounts: Vec<PathBuf>) {
    // 非 Linux 开发环境无真实挂载（mount 为桩实现），无需 umount。
    let _ = mounts;
}

#[cfg(target_os = "linux")]
impl Drop for MountGuard {
    fn drop(&mut self) {
        if !self.mounts.is_empty() {
            let to_umount = std::mem::take(&mut self.mounts);
            // 不在 Drop 中 join：会阻塞 async worker 事件循环，detached 线程尽力清理。
            std::thread::spawn(move || sync_lazy_umount_all(to_umount));
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for MountGuard {
    fn drop(&mut self) {
        let _ = std::mem::take(&mut self.mounts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_accumulates_mounts() {
        let mut guard = MountGuard::new();
        assert!(guard.mounts.is_empty());
        guard.push(PathBuf::from("/mnt/a"));
        guard.push(PathBuf::from("/mnt/b"));
        assert_eq!(guard.mounts.len(), 2);
        assert_eq!(guard.mounts[0], PathBuf::from("/mnt/a"));
        assert_eq!(guard.mounts[1], PathBuf::from("/mnt/b"));
    }

    #[test]
    fn test_take_then_reverse_order() {
        let mut guard = MountGuard::new();
        guard.push(PathBuf::from("/mnt/a"));
        guard.push(PathBuf::from("/mnt/b"));
        let taken = std::mem::take(&mut guard.mounts);
        assert!(guard.mounts.is_empty());
        assert_eq!(taken.len(), 2);
        let reversed: Vec<_> = taken.into_iter().rev().collect();
        assert_eq!(reversed[0], PathBuf::from("/mnt/b"));
        assert_eq!(reversed[1], PathBuf::from("/mnt/a"));
    }
}
