// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Linux capability 裁剪与调用者身份校验。helper 以 setuid-root 运行：先验证调用者
//! 身份，再把能力集裁剪到最小，并为 exec 出的子进程保留必需的能力。

#[cfg(target_os = "linux")]
use nix::unistd::{geteuid, getgroups, getuid, Gid};

use crate::Error;

/// crbs 服务组名，调用者身份校验的依据。
pub const CRBS_GROUP: &str = "crbs";

#[cfg(target_os = "linux")]
/// setuid-root 启动时设置 KEEP_CAPS + NO_SETUID_FIXUP。不设置的话，后续裁剪
/// effective 集时内核会把 euid 重置回 ruid 并清空能力集，exec 出的子进程将失去特权。
pub fn keep_caps_if_setuid() -> Result<(), Error> {
    let euid = geteuid();
    let ruid = getuid();
    if euid.is_root() && !ruid.is_root() {
        let bits = libc::SECBIT_KEEP_CAPS | libc::SECBIT_NO_SETUID_FIXUP;
        let ret = unsafe { libc::prctl(libc::PR_SET_SECUREBITS, bits) };
        if ret != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        tracing::debug!(bits = %format!("{:08x}", bits), "set securebits for setuid-root helper");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn keep_caps_if_setuid() -> Result<(), Error> {
    Ok(())
}

#[cfg(target_os = "linux")]
/// 校验调用者为 root 或 crbs 组成员。
pub fn verify_caller() -> Result<(), Error> {
    let uid = getuid();
    if uid.is_root() {
        return Ok(());
    }

    let crbs_gid = resolve_crbs_group_gid()?;
    if nix::unistd::getgid() == crbs_gid {
        return Ok(());
    }

    let groups = getgroups().map_err(|e| Error::PermissionDenied(format!("getgroups: {e}")))?;
    if groups.contains(&crbs_gid) {
        return Ok(());
    }

    Err(Error::PermissionDenied(format!(
        "user {} is not root and not in '{}' group",
        uid, CRBS_GROUP
    )))
}

#[cfg(not(target_os = "linux"))]

/// 非 Linux 平台无 crbs 组语义，恒通过。
pub fn verify_caller() -> Result<(), Error> {
    Ok(())
}

/// 从 `/etc/group` 解析 `crbs` 组的 gid；组缺失或行格式非法均报错。
#[cfg(target_os = "linux")]
pub fn resolve_crbs_group_gid() -> Result<Gid, Error> {
    let content = std::fs::read_to_string("/etc/group").map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("read /etc/group: {e}"),
        ))
    })?;
    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 && parts[0] == CRBS_GROUP {
            let gid: u32 = parts[2]
                .parse()
                .map_err(|e| Error::Validation(format!("parse gid in /etc/group: {e}")))?;
            return Ok(Gid::from_raw(gid));
        }
    }
    Err(Error::PermissionDenied(format!(
        "group '{}' not found in /etc/group",
        CRBS_GROUP
    )))
}

#[cfg(target_os = "linux")]
/// 把 bounding / effective / permitted 三个集合同步裁剪到 keep；helper 自身的特权
/// 操作同样受该集合限制。
pub fn drop_bounding_set_to(keep: &[Capability]) -> Result<(), Error> {
    let keep: std::collections::HashSet<caps::Capability> =
        keep.iter().copied().map(Into::into).collect();

    for set in [
        caps::CapSet::Bounding,
        caps::CapSet::Effective,
        caps::CapSet::Permitted,
    ] {
        let current =
            caps::read(None, set).map_err(|e| Error::Capability(format!("read {set:?}: {e}")))?;
        for cap in &current - &keep {
            caps::drop(None, set, cap)
                .map_err(|e| Error::Capability(format!("drop {set:?} {cap:?}: {e}")))?;
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn drop_bounding_set_to(_keep: &[Capability]) -> Result<(), Error> {
    Ok(())
}

#[cfg(target_os = "linux")]
/// 为 exec 的子进程保留能力：提升 inheritable，再尽可能提升 ambient。exec 后仍需
/// 特权时必须调用（dnf 安装含 %caps 的包时 SETFCAP 仅经 ambient 存活，缺失会 EPERM）。
pub fn set_ambient_caps_for_exec(keep: &[Capability]) -> Result<(), Error> {
    let keep: std::collections::HashSet<caps::Capability> =
        keep.iter().copied().map(Into::into).collect();

    for cap in &keep {
        caps::raise(None, caps::CapSet::Inheritable, *cap)
            .map_err(|e| Error::Capability(format!("raise inheritable {cap:?}: {e}")))?;
        if *cap != caps::Capability::CAP_SETPCAP {
            // CAP_SETPCAP 不能加入 ambient 集，跳过。
            caps::raise(None, caps::CapSet::Ambient, *cap)
                .map_err(|e| Error::Capability(format!("raise ambient {cap:?}: {e}")))?;
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_ambient_caps_for_exec(_keep: &[Capability]) -> Result<(), Error> {
    Ok(())
}

#[cfg(target_os = "linux")]
/// SELinux 启用（enforcing 或 permissive）时内核挂载 selinuxfs，该节点即存在；
/// `selinux=0` 禁用时不挂载。
pub fn selinux_enabled() -> bool {
    std::path::Path::new("/sys/fs/selinux/enforce").exists()
}

#[cfg(not(target_os = "linux"))]
pub fn selinux_enabled() -> bool {
    false
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// helper 内部的 capability 枚举；非 Linux 平台上仅作占位，保持调用方代码跨平台一致。
pub enum Capability {
    CAP_SYS_ADMIN,

    CAP_SYS_CHROOT,

    CAP_CHOWN,

    CAP_FOWNER,

    CAP_SETUID,

    CAP_SETGID,

    CAP_SETPCAP,

    CAP_AUDIT_CONTROL,

    CAP_AUDIT_WRITE,

    CAP_SETFCAP,

    CAP_DAC_OVERRIDE,

    CAP_MAC_ADMIN,
}

#[cfg(target_os = "linux")]
impl From<Capability> for caps::Capability {
    fn from(c: Capability) -> Self {
        match c {
            Capability::CAP_SYS_ADMIN => caps::Capability::CAP_SYS_ADMIN,
            Capability::CAP_SYS_CHROOT => caps::Capability::CAP_SYS_CHROOT,
            Capability::CAP_CHOWN => caps::Capability::CAP_CHOWN,
            Capability::CAP_FOWNER => caps::Capability::CAP_FOWNER,
            Capability::CAP_SETUID => caps::Capability::CAP_SETUID,
            Capability::CAP_SETGID => caps::Capability::CAP_SETGID,
            Capability::CAP_SETPCAP => caps::Capability::CAP_SETPCAP,
            Capability::CAP_AUDIT_CONTROL => caps::Capability::CAP_AUDIT_CONTROL,
            Capability::CAP_AUDIT_WRITE => caps::Capability::CAP_AUDIT_WRITE,
            Capability::CAP_SETFCAP => caps::Capability::CAP_SETFCAP,
            Capability::CAP_DAC_OVERRIDE => caps::Capability::CAP_DAC_OVERRIDE,
            Capability::CAP_MAC_ADMIN => caps::Capability::CAP_MAC_ADMIN,
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn capability_from_maps_each_variant_to_correct_caps_value() {
        let cases: [(Capability, caps::Capability); 12] = [
            (Capability::CAP_SYS_ADMIN, caps::Capability::CAP_SYS_ADMIN),
            (Capability::CAP_SYS_CHROOT, caps::Capability::CAP_SYS_CHROOT),
            (Capability::CAP_CHOWN, caps::Capability::CAP_CHOWN),
            (Capability::CAP_FOWNER, caps::Capability::CAP_FOWNER),
            (Capability::CAP_SETUID, caps::Capability::CAP_SETUID),
            (Capability::CAP_SETGID, caps::Capability::CAP_SETGID),
            (Capability::CAP_SETPCAP, caps::Capability::CAP_SETPCAP),
            (
                Capability::CAP_AUDIT_CONTROL,
                caps::Capability::CAP_AUDIT_CONTROL,
            ),
            (
                Capability::CAP_AUDIT_WRITE,
                caps::Capability::CAP_AUDIT_WRITE,
            ),
            (Capability::CAP_SETFCAP, caps::Capability::CAP_SETFCAP),
            (
                Capability::CAP_DAC_OVERRIDE,
                caps::Capability::CAP_DAC_OVERRIDE,
            ),
            (Capability::CAP_MAC_ADMIN, caps::Capability::CAP_MAC_ADMIN),
        ];
        for (ours, expected) in cases {
            assert_eq!(
                caps::Capability::from(ours),
                expected,
                "capability {:?} mapped incorrectly",
                ours
            );
        }
    }
}
