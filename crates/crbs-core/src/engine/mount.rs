// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 挂载操作的跨平台封装：crbs 仅在 Linux 实际运行（需 OverlayFS / mount 命名空间），
//! Linux 透传 `nix::mount`，非 Linux（macOS 开发/编译环境）提供同名桩保证可编译；
//! 实际 mount/umount 一律经 [`crate::privilege::PrivilegeBackend`] 执行（setuid / privileged helper 两模式）。

use std::path::Path;

#[cfg(target_os = "linux")]
pub use nix::mount::MsFlags;

#[cfg(not(target_os = "linux"))]
pub use fallback::MsFlags;

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
mod fallback {
    use nix::errno::Errno;
    use nix::NixPath;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MsFlags(u64);

    impl MsFlags {
        pub const fn empty() -> Self {
            MsFlags(0)
        }
    }

    impl MsFlags {
        pub const MS_RDONLY: Self = MsFlags(1);
        pub const MS_REMOUNT: Self = MsFlags(1 << 5);
        pub const MS_BIND: Self = MsFlags(1 << 12);
        pub const MS_REC: Self = MsFlags(1 << 14);
        pub const MS_PRIVATE: Self = MsFlags(1 << 18);
    }

    impl std::ops::BitOr for MsFlags {
        type Output = Self;

        fn bitor(self, rhs: Self) -> Self::Output {
            MsFlags(self.0 | rhs.0)
        }
    }

    impl MsFlags {
        pub const fn bits(&self) -> u64 {
            self.0
        }
    }

    fn unsupported<T>() -> nix::Result<T> {
        Err(nix::Error::from(Errno::EINVAL))
    }

    pub fn mount<
        P1: ?Sized + NixPath,
        P2: ?Sized + NixPath,
        P3: ?Sized + NixPath,
        P4: ?Sized + NixPath,
    >(
        _source: Option<&P1>,
        _target: &P2,
        _fstype: Option<&P3>,
        _flags: MsFlags,
        _data: Option<&P4>,
    ) -> nix::Result<()> {
        unsupported()
    }
}

#[cfg(target_os = "linux")]
pub use nix::mount::MntFlags;

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MntFlags(u64);

#[cfg(not(target_os = "linux"))]
impl MntFlags {
    pub const MNT_DETACH: Self = MntFlags(1);

    pub const fn bits(&self) -> u64 {
        self.0
    }
}

/// 挂载文件系统：[`PrivilegeBackend::mount`] 的便捷封装，自动选用当前初始化的后端。
pub fn mount(
    source: Option<&Path>,
    target: &Path,
    fstype: Option<&str>,
    flags: MsFlags,
    data: Option<&str>,
) -> crate::Result<()> {
    crate::privilege::get_privilege_backend().mount(source, target, fstype, flags.bits(), data)
}

/// 卸载文件系统。
pub fn umount2(target: &Path, flags: MntFlags) -> crate::Result<()> {
    // Linux 上 MntFlags::bits() 已是 i32；跨平台保留 as i32。
    #[allow(clippy::unnecessary_cast)]
    let flags = flags.bits() as i32;
    crate::privilege::get_privilege_backend().umount2(target, flags)
}
