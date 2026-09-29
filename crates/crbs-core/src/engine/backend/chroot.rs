// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! chroot 后端：直接 chroot 进 base_os rootfs 执行命令（无 systemd 容器）。

use std::path::Path;

use crate::engine::backend::{ContainerBackend, SpawnOptions, SpawnedChild};
use crate::error::CrbsError;

/// Chroot 后端：Linux 经 `Command::pre_exec` 直接调用 `unshare`/`chroot`/`chdir`
///（无外部二进制依赖）；非 Linux 保留外部 `chroot` 便于开发机编译测试。
#[derive(Debug)]
pub struct ChrootBackend;

impl Default for ChrootBackend {
    fn default() -> Self {
        Self
    }
}

impl ChrootBackend {
    /// 创建 chroot 后端实例。
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ContainerBackend for ChrootBackend {
    fn name(&self) -> &str {
        "chroot"
    }

    fn available(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            // 直接 syscall 路径需要 euid=0；helper 路径只需要 helper 可执行。
            nix::unistd::geteuid().is_root()
                || crate::privilege::get_privilege_backend().is_helper()
        }
        #[cfg(not(target_os = "linux"))]
        {
            which::which("chroot").is_ok()
        }
    }

    async fn spawn(
        &self,
        rootfs: &Path,
        command: &[&str],
        opts: &SpawnOptions,
    ) -> crate::Result<SpawnedChild> {
        if opts.user.is_some() {
            return Err(CrbsError::ValidationFailed {
                message: "ChrootBackend::spawn() contract violated: opts.user must be None; \
                         user switching is handled by the caller's build script"
                    .to_string(),
            });
        }

        let Some(program) = command.first() else {
            return Err(CrbsError::ValidationFailed {
                message: "ChrootBackend::spawn() contract violated: command must not be empty"
                    .to_string(),
            });
        };

        let mut cmd = build_command(rootfs, program, &command[1..], opts.network)?;

        for (k, v) in &opts.env {
            cmd.env(k, v);
        }

        crate::engine::backend::apply_spawn_opts(&mut cmd, opts);

        let child = cmd
            .spawn()
            .map_err(|e| CrbsError::io_message(format!("spawn chroot: {}", e)))?;

        Ok(SpawnedChild {
            child,
            cgroup_kill_paths: Vec::new(),
            machine_name: None,
        })
    }

    async fn shell(
        &self,
        rootfs: &Path,
        command: Option<&str>,
        opts: &SpawnOptions,
    ) -> crate::Result<std::process::ExitStatus> {
        let bash_cmd: Vec<&str> = if let Some(ref user) = opts.user {
            // chroot 默认以 root 运行，需通过 sudo -u 切换到构建用户
            if let Some(cmd_str) = command {
                vec![
                    "/usr/bin/sudo",
                    "-u",
                    user,
                    "--",
                    "/bin/bash",
                    "-c",
                    cmd_str,
                ]
            } else {
                vec!["/usr/bin/sudo", "-u", user, "--", "/bin/bash"]
            }
        } else if let Some(cmd_str) = command {
            vec!["/bin/bash", "-c", cmd_str]
        } else {
            vec!["/bin/bash"]
        };

        let mut cmd = build_command(rootfs, bash_cmd[0], &bash_cmd[1..], opts.network)?;

        for (k, v) in &opts.env {
            cmd.env(k, v);
        }

        crate::engine::backend::apply_spawn_opts(&mut cmd, opts);

        cmd.status()
            .await
            .map_err(|e| CrbsError::io_message(format!("spawn chroot shell: {}", e)))
    }
}

/// 构造进入 rootfs 的 tokio Command；特权操作经 `PrivilegeBackend`——setuid
/// 路径直接 syscall，helper 路径调用 `crbs-priv-helper spawn-chroot`。
fn build_command(
    rootfs: &Path,
    program: &str,
    args: &[&str],
    network: bool,
) -> crate::Result<tokio::process::Command> {
    let std_cmd =
        crate::privilege::get_privilege_backend().spawn_chroot(rootfs, program, args, network)?;
    Ok(tokio::process::Command::from(std_cmd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chroot_backend_available() {
        let backend = ChrootBackend::new();
        #[cfg(target_os = "linux")]
        {
            // 断言镜像 [`ChrootBackend::available`] 谓词：root 直接 syscall，或 helper 后端可用。
            assert_eq!(
                backend.available(),
                nix::unistd::geteuid().is_root()
                    || crate::privilege::get_privilege_backend().is_helper()
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(backend.available());
        }
    }

    #[test]
    fn test_chroot_backend_name() {
        let backend = ChrootBackend::new();
        assert_eq!(backend.name(), "chroot");
    }

    /// 空 command 不得 panic（曾因 command[0] 越界），必须在 trait 边界拒绝。
    #[tokio::test]
    async fn test_chroot_spawn_rejects_empty_command() {
        let backend = ChrootBackend::new();
        let err = backend
            .spawn(
                Path::new("/tmp/rootfs"),
                &[],
                &crate::engine::backend::SpawnOptions::default(),
            )
            .await
            .err()
            .expect("empty command must be rejected");
        assert!(matches!(err, CrbsError::ValidationFailed { .. }));
    }
}
