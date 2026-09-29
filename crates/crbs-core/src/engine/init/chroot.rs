// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Chroot 命令执行基础设施：构造 chroot Command、执行并等待/捕获输出、为
//! base_os 安装挂载伪文件系统；与 `BuildEngine` 无关的通用特权后端封装。

use std::path::Path;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::engine::cache::TempDirGuard;
use crate::engine::mount::MsFlags;
use crate::engine::mount_guard::MountGuard;
use crate::error::CrbsError;

/// 为 base_os 安装挂载 /proc、/sys、/dev 伪文件系统（dnf --installroot 的 RPM 脚本
/// 片段可能依赖，如 selinux-policy-targeted %post）；由调用者显式调用 MountGuard::umount() 卸载。
pub(super) async fn mount_base_os_pseudo_fs(base_os: &Path) -> crate::Result<MountGuard> {
    let mut guard = MountGuard::new();
    let proc = base_os.join("proc");
    let sys = base_os.join("sys");
    let dev = base_os.join("dev");

    for d in [&proc, &sys, &dev] {
        tokio::fs::create_dir_all(d)
            .await
            .map_err(|e| CrbsError::from_io_context("create pseudo fs dir", e))?;
    }

    let mount_blocking = |source: Option<&'static Path>,
                          target: std::path::PathBuf,
                          fstype: Option<&'static str>,
                          flags: MsFlags,
                          what: &'static str| async move {
        tokio::task::spawn_blocking(move || {
            crate::engine::mount::mount(source, &target, fstype, flags, None::<&str>)
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn mount {what}: {}", e)))?
        .map_err(|e| CrbsError::io_message(format!("mount {what}: {}", e)))
    };

    mount_blocking(
        Some(Path::new("proc")),
        proc.clone(),
        Some("proc"),
        MsFlags::empty(),
        "proc",
    )
    .await?;
    guard.push(proc);

    mount_blocking(
        Some(Path::new("sysfs")),
        sys.clone(),
        Some("sysfs"),
        MsFlags::empty(),
        "sys",
    )
    .await?;
    guard.push(sys);

    mount_blocking(
        Some(Path::new("/dev")),
        dev.clone(),
        None,
        MsFlags::MS_BIND,
        "dev",
    )
    .await?;
    guard.push(dev.clone());

    // dev bind mount 置 private：installroot 内 mount/unmount 事件不向 host 传播。
    mount_blocking(
        None::<&Path>,
        dev,
        None::<&str>,
        MsFlags::MS_PRIVATE,
        "dev-private",
    )
    .await?;

    Ok(guard)
}

/// 构造进入 base_os 的 chroot Command，统一走 PrivilegeBackend；helper 模式经
/// setuid-root 的 crbs-priv-helper，主进程无需 CAP_SYS_CHROOT。
fn chroot_command(
    base_os: &Path,
    program: &str,
    args: &[&str],
) -> crate::Result<tokio::process::Command> {
    let backend = crate::privilege::get_privilege_backend();
    let std_cmd = backend
        .spawn_chroot(base_os, program, args, true)
        .map_err(|e| CrbsError::io_message(format!("setup chroot command {program}: {e}")))?;
    Ok(tokio::process::Command::from(std_cmd))
}

/// 在 base_os 内执行命令并等待退出。
pub(super) async fn chroot_status(
    base_os: &Path,
    argv: &[&str],
    cancel_token: Option<&CancellationToken>,
    timeout: Option<Duration>,
) -> crate::Result<std::process::ExitStatus> {
    let mut cmd = chroot_command(base_os, argv[0], &argv[1..])?;
    crate::engine::command::run_child_status_with_cancel_timeout(
        &mut cmd,
        cancel_token,
        timeout,
        "spawn chroot",
    )
    .await
}

/// 在 base_os 内执行命令并捕获输出。
pub(super) async fn chroot_output(
    base_os: &Path,
    argv: &[&str],
    cancel_token: Option<&CancellationToken>,
    timeout: Option<Duration>,
) -> crate::Result<std::process::Output> {
    let mut cmd = chroot_command(base_os, argv[0], &argv[1..])?;
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    crate::engine::command::run_child_output_with_cancel_timeout(
        &mut cmd,
        cancel_token,
        timeout,
        "spawn chroot",
    )
    .await
}

/// post_init 命令执行所需的审计上下文。
pub(super) struct PostInitAuditContext<'a> {
    pub state: &'a crate::StateStore,
    pub actor: &'a str,
    pub role: &'a str,
    pub product: &'a str,
}

/// 把 post_init 命令写入 rootfs 内临时脚本，经 `bash <script>` 执行——避免拼进
/// `bash -c` 参数被外部 shell 解析元字符；脚本放 `{base_os}/tmp`，执行后清理。
pub(super) async fn run_post_init_command(
    base_os: &Path,
    command: &str,
    audit: PostInitAuditContext<'_>,
    cancel_token: Option<&CancellationToken>,
    timeout: Option<Duration>,
) -> crate::Result<std::process::ExitStatus> {
    // post_init 以 root 执行，审计必须留痕。
    let detail = serde_json::json!({ "command": command }).to_string();
    if let Err(e) = audit
        .state
        .audit_log(
            audit.actor,
            audit.role,
            "post_init",
            Some(audit.product),
            Some(&detail),
        )
        .await
    {
        warn!(product = %audit.product, error = %e, "Failed to write post_init audit log");
    }

    let base_os = base_os.to_path_buf();
    let command = command.to_string();

    let (script_path, tmp_dir) = tokio::task::spawn_blocking({
        let base_os = base_os.clone();
        move || {
            let parent = base_os.join("tmp");
            std::fs::create_dir_all(&parent)
                .map_err(|e| CrbsError::from_io_context("create base_os tmp", e))?;

            // 独立 0700 临时目录：脚本直接放 1777 的 /tmp 再 chmod 有 TOCTOU 窗口。
            let tmp_dir = tempfile::Builder::new()
                .prefix("crbs-post-init-")
                .suffix(".d")
                .tempdir_in(&parent)
                .map_err(|e| CrbsError::from_io_context("create post_init temp dir", e))?;

            let mut f = tempfile::Builder::new()
                .prefix("crbs-post-init-")
                .suffix(".sh")
                .tempfile_in(&tmp_dir)
                .map_err(|e| CrbsError::from_io_context("create post_init temp script", e))?;
            use std::io::Write;
            writeln!(f, "#!/bin/bash")
                .and_then(|()| writeln!(f, "set -e"))
                .and_then(|()| f.write_all(command.as_bytes()))
                .and_then(|()| f.write_all(b"\n"))
                .map_err(|e| CrbsError::from_io_context("write post_init script", e))?;
            let path = f
                .into_temp_path()
                .keep()
                .map_err(|e| CrbsError::from_io_context("keep post_init script path", e.into()))?;
            Ok::<_, CrbsError>((path, tmp_dir))
        }
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("spawn_blocking post_init script: {}", e)))??;

    // TempDir 的 Drop 是同步 remove_dir_all，不得落在 tokio worker 线程——交
    // TempDirGuard（engine::cache）fire-and-forget spawn_blocking 清理，兜住任一
    // 早退臂。删除 best-effort：runtime 关停竞态下可能永不执行，tmp_sweep 只覆盖
    // .tmpXXXX 挂载域、本目录残留无兜底（量级小，init 取消路径通常连 base_os 一起清）。
    let tmp_dir_guard = TempDirGuard::new(tmp_dir);

    let rel_path = script_path
        .strip_prefix(&base_os)
        .map_err(|_| CrbsError::io_message("post_init script path is not under base_os"))?;
    let in_root_path = format!("/{}", rel_path.display());

    let status = chroot_status(&base_os, &["bash", &in_root_path], cancel_token, timeout).await;

    if let Err(e) = tokio::fs::remove_file(&script_path).await {
        warn!(path = %script_path.display(), error = %e, "Failed to remove post_init temp script");
    }
    drop(tmp_dir_guard);

    status
}
