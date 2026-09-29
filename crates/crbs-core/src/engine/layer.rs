// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建层挂载与目录准备：overlay 层、dnf 缓存、属主与权限。

use crate::engine::mount::MsFlags;
use crate::engine::mount_guard::MountGuard;
use crate::error::CrbsError;
use crate::privilege::{get_privilege_backend, MountOverlayRequest};
// 属主/权限变更统一走 crate::privilege，不直接用 nix chown。
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
use tracing::warn;

/// 挂载基础构建层（overlayfs + 伪文件系统 + resolv.conf），挂载点注册进调用方
/// 持有的 `guard`；`lowerdir` 支持单个或多个（`:` 分隔，如 `base_os:shared_layer`）。
/// 显式 teardown 契约（构建管线路径遵守）：Err 后先 `guard.umount().await` 再清理
/// 临时目录，不能让 guard 随 Err 直接 Drop——Drop 只派分离线程 lazy umount，与同
/// tick 的 temp 删除竞争（竞态纪律见 `PreparedEnv::drop` / `base_os_install`）。
/// `skip_dev_mounts` 兼容 nspawn 等自管理 /dev 的 backend：为 true 跳过 /dev 与
/// devpts 的 bind mount（nspawn 内部自建 /dev，外部预挂载导致启动失败）。
/// `skip_pseudo_mounts` 为 true 跳过宿主侧 proc/sys 预挂载：宿主 procfs 随
/// pivot_root 进入 nspawn 容器后，容器内 /proc 是宿主 PID namespace 实例，
/// /proc 探测随宿主 pid 状态翻转（产物不可复现），由 nspawn 自挂全新 procfs。
/// 跳过的挂载不进 guard，无需卸载。
pub(crate) async fn mount_build_layer(
    root: &std::path::Path,
    upperdir: &std::path::Path,
    workdir: &std::path::Path,
    lowerdir: &str,
    skip_dev_mounts: bool,
    skip_pseudo_mounts: bool,
    guard: &mut MountGuard,
) -> crate::Result<()> {
    let root_for_overlay = root.to_path_buf();
    let root_c = root.to_path_buf();
    let upperdir_c = upperdir.to_path_buf();
    let workdir_c = workdir.to_path_buf();
    let lower_dirs: Vec<std::path::PathBuf> =
        lowerdir.split(':').map(std::path::PathBuf::from).collect();
    tokio::task::spawn_blocking(move || {
        get_privilege_backend()
            .mount_overlay(MountOverlayRequest {
                lower: lower_dirs,
                upper: upperdir_c,
                work: workdir_c,
                target: root_for_overlay,
            })
            .map_err(|e| CrbsError::io_message(format!("mount overlay: {e}")))
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("spawn_blocking mount: {}", e)))??;
    // overlay 挂载成功立即 push（对齐 bind_mount_private）：private remount 失败返回
    // Err 时挂载点已在 guard、调用方显式 umount 逆序摘除；等 remount 成功才 push 则
    // 失败路径 guard 为空、overlay 泄漏（TempDir 删不掉含挂载点的目录）。
    guard.push(root.to_path_buf());
    tokio::task::spawn_blocking(move || {
        crate::engine::mount::mount(
            None::<&std::path::Path>,
            &root_c,
            None::<&str>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&str>,
        )
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("spawn_blocking private mount: {}", e)))?
    .map_err(|e| CrbsError::io_message(format!("make mount private: {e}")))?;

    if !skip_pseudo_mounts {
        let proc = root.join("proc");
        if let Err(e) = tokio::fs::create_dir_all(&proc).await {
            return Err(CrbsError::from_io_context("create proc", e));
        }
        // 伪文件系统同款"即挂即 push"（对齐 overlay）：mount 成功立即注册，再做
        // MS_PRIVATE remount——等 remount 成功才 push 会泄漏；下方 sys/dev/devpts 同款。
        let proc_c = proc.clone();
        tokio::task::spawn_blocking(move || {
            crate::engine::mount::mount(
                Some(std::path::Path::new("proc")),
                &proc_c,
                Some("proc"),
                MsFlags::empty(),
                None::<&str>,
            )
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking mount proc: {}", e)))?
        .map_err(|e| CrbsError::io_message(format!("mount proc: {}", e)))?;
        guard.push(proc.clone());
        tokio::task::spawn_blocking(move || {
            crate::engine::mount::mount(
                None::<&std::path::Path>,
                &proc,
                None::<&str>,
                MsFlags::MS_PRIVATE,
                None::<&str>,
            )
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking mount proc: {}", e)))?
        .map_err(|e| CrbsError::io_message(format!("mount proc: {}", e)))?;

        let sys = root.join("sys");
        if let Err(e) = tokio::fs::create_dir_all(&sys).await {
            return Err(CrbsError::from_io_context("create sys", e));
        }
        let sys_c = sys.clone();
        tokio::task::spawn_blocking(move || {
            crate::engine::mount::mount(
                Some(std::path::Path::new("sysfs")),
                &sys_c,
                Some("sysfs"),
                MsFlags::empty(),
                None::<&str>,
            )
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking mount sys: {}", e)))?
        .map_err(|e| CrbsError::io_message(format!("mount sys: {}", e)))?;
        guard.push(sys.clone());
        tokio::task::spawn_blocking(move || {
            crate::engine::mount::mount(
                None::<&std::path::Path>,
                &sys,
                None::<&str>,
                MsFlags::MS_PRIVATE,
                None::<&str>,
            )
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking mount sys: {}", e)))?
        .map_err(|e| CrbsError::io_message(format!("mount sys: {}", e)))?;
    }

    if !skip_dev_mounts {
        let dev = root.join("dev");
        let devpts = dev.join("pts");
        if let Err(e) = tokio::fs::create_dir_all(&dev).await {
            return Err(CrbsError::from_io_context("create dev", e));
        }
        let dev_c = dev.clone();
        tokio::task::spawn_blocking(move || {
            crate::engine::mount::mount(
                Some(std::path::Path::new("/dev")),
                &dev_c,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            )
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking mount dev: {}", e)))?
        .map_err(|e| CrbsError::io_message(format!("mount dev: {}", e)))?;
        guard.push(dev.clone());
        tokio::task::spawn_blocking(move || {
            crate::engine::mount::mount(
                None::<&std::path::Path>,
                &dev,
                None::<&str>,
                MsFlags::MS_PRIVATE | MsFlags::MS_REC,
                None::<&str>,
            )
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking mount dev: {}", e)))?
        .map_err(|e| CrbsError::io_message(format!("mount dev: {}", e)))?;

        if let Err(e) = tokio::fs::create_dir_all(&devpts).await {
            return Err(CrbsError::from_io_context("create devpts", e));
        }
        let devpts_c = devpts.clone();
        tokio::task::spawn_blocking(move || {
            crate::engine::mount::mount(
                Some(std::path::Path::new("devpts")),
                &devpts_c,
                Some("devpts"),
                MsFlags::empty(),
                Some("newinstance,ptmxmode=0666,mode=0620,gid=5"),
            )
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking mount devpts: {}", e)))?
        .map_err(|e| CrbsError::io_message(format!("mount devpts: {}", e)))?;
        guard.push(devpts.clone());
        tokio::task::spawn_blocking(move || {
            crate::engine::mount::mount(
                None::<&std::path::Path>,
                &devpts,
                None::<&str>,
                MsFlags::MS_PRIVATE,
                None::<&str>,
            )
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking mount devpts: {}", e)))?
        .map_err(|e| CrbsError::io_message(format!("mount devpts: {}", e)))?;
    }

    // 错误分级：NotFound = 合法缺失（最小环境无 DNS 配置）静默跳过；其他读失败
    // warn 留排障线索；任何失败都不阻断构建层挂载。
    let resolv_content = match tokio::fs::read_to_string("/etc/resolv.conf").await {
        Ok(content) => Some(content),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!(
                error = %e,
                "Failed to read host /etc/resolv.conf; skipping copy (DNS inside chroot may fail)"
            );
            None
        }
    };
    if let Some(content) = resolv_content {
        let resolv = root.join("etc/resolv.conf");
        // /etc 可能来自 lowerdir 且为 root 所有，普通用户无法直接写入，
        // 通过 helper 写入，helper 会先删除可能存在的 dangling symlink。
        tokio::task::spawn_blocking(move || {
            crate::privilege::write_file(&resolv, content.as_bytes(), Some(0o644), Some(0), Some(0))
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking write resolv.conf: {}", e)))?
        .map_err(|e| CrbsError::io_message(format!("write resolv.conf: {}", e)))?;
    }

    Ok(())
}

/// bind mount 宿主机缓存目录到 chroot 的 dnf4/dnf5 缓存路径（宿主目录不存在则自动创建）。
pub(crate) async fn bind_mount_dnf_cache(
    root: &std::path::Path,
    host_cache: &std::path::Path,
    guard: &mut MountGuard,
) -> crate::Result<()> {
    tokio::fs::create_dir_all(host_cache)
        .await
        .map_err(|e| CrbsError::from_io_context("create dnf cache dir", e))?;

    let dnf4 = root.join("var/cache/dnf");
    let dnf5 = root.join("var/cache/libdnf5");

    for path in [&dnf4, &dnf5] {
        tokio::fs::create_dir_all(path)
            .await
            .map_err(|e| CrbsError::from_io_context("create dnf cache dir", e))?;
        guard
            .bind_mount_private(Some(host_cache), path, "dnf cache")
            .await?;
    }
    Ok(())
}

/// 递归修改目录及其内容的属主；统一走特权后端（setuid/helper），主进程无 CAP_CHOWN。
pub(crate) async fn chown_recursive(
    path: &std::path::Path,
    uid: u32,
    gid: u32,
) -> crate::Result<()> {
    let path = path.to_path_buf();
    let path_for_err = path.clone();
    tokio::task::spawn_blocking(move || crate::privilege::chown(&path, uid, gid, true))
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking chown: {}", e)))?
        .map_err(|e| {
            CrbsError::io_message(format!(
                "chown recursive {} to {uid}:{gid}: {e}",
                path_for_err.display()
            ))
        })
}

/// 递归修改目录及其内容的权限；统一走 PrivilegeBackend，非 root 的 crbs 主进程
/// 也能修改不属于自己的目录（如 ccache 目录在容器内被 builder 用户写入后）。
pub(crate) async fn chmod_recursive(path: &std::path::Path, mode: u32) -> crate::Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::privilege::chmod(&path, mode, true))
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking chmod: {}", e)))?
}

/// 准备宿主机 ccache 目录：属主 builder（容器内写入）、属组 `crbs`（普通用户主进程
/// 管理），setgid 0o2770 让新文件继承 `crbs` 组；最后写探针验证实际可写性。
pub(crate) async fn setup_ccache_dir(
    host_cache: &std::path::Path,
    builder_uid: u32,
) -> crate::Result<()> {
    tokio::fs::create_dir_all(host_cache)
        .await
        .map_err(|e| CrbsError::from_io_context("create ccache dir", e))?;

    // 快路径：目录已就绪（mode 2770 + builder 属主 + crbs 组）则跳过全树 chown/chmod。
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = tokio::fs::metadata(host_cache).await {
            let mode_ok = meta.mode() & 0o7777 == 0o2770;
            let owner_ok = meta.uid() == builder_uid;
            let group_ok = crate::privilege::crbs_group_gid_async()
                .await
                .map(|g| meta.gid() == g)
                .unwrap_or(false);
            if mode_ok && owner_ok && group_ok {
                return write_probe(host_cache).await;
            }
        }
    }

    let crbs_gid = crate::privilege::crbs_group_gid_async()
        .await
        .map_err(|e| CrbsError::io_message(format!("lookup crbs group gid for ccache dir: {e}")))?;

    let chown_ok = chown_recursive(host_cache, builder_uid, crbs_gid)
        .await
        .is_ok();

    if !chown_ok {
        tracing::warn!(
            dir = %host_cache.display(),
            "chown ccache dir failed; falling back to chmod 0770 (not world-writable)"
        );
    }

    // 无论 chown 是否成功都保证组可写 + setgid：crbs 主进程与容器内 builder 均可写。
    if let Err(e) = chmod_recursive(host_cache, 0o2770).await {
        warn!(
            dir = %host_cache.display(),
            error = %e,
            "chmod ccache dir to 2770 failed; write probe may still fail"
        );
    }

    write_probe(host_cache).await?;
    Ok(())
}

/// 写探针验证 ccache 目录可写。
async fn write_probe(host_cache: &std::path::Path) -> crate::Result<()> {
    let probe = host_cache.join(".crbs-write-test");
    tokio::fs::write(&probe, b"ok")
        .await
        .map_err(|e| CrbsError::from_io_context("ccache dir not writable", e))?;
    if let Err(e) = tokio::fs::remove_file(&probe).await {
        warn!(path = %probe.display(), error = %e, "Failed to remove ccache write probe");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[tokio::test]
    async fn test_chmod_recursive_sets_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("file"), b"x").unwrap();

        chmod_recursive(tmp.path(), 0o700).await.unwrap();

        let top = tmp.path().metadata().unwrap().permissions().mode() & 0o777;
        let sub_dir = sub.metadata().unwrap().permissions().mode() & 0o777;
        let sub_file = sub.join("file").metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(top, 0o700);
        assert_eq!(sub_dir, 0o700);
        assert_eq!(sub_file, 0o600); // 文件不设置 execute/setgid
    }

    #[tokio::test]
    async fn test_chown_recursive_changes_owner() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("file"), b"x").unwrap();

        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        chown_recursive(tmp.path(), uid, gid).await.unwrap();

        let top = tmp.path().metadata().unwrap();
        assert_eq!(top.uid(), uid);
        assert_eq!(top.gid(), gid);
        let file = sub.join("file").metadata().unwrap();
        assert_eq!(file.uid(), uid);
        assert_eq!(file.gid(), gid);
    }
}
