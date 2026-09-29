// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Linux capability 裁剪与身份校验——setuid-root helper 安全核心：校验调用者身份（root 或
//! crbs 组）、设 securebits 防 capability 泄露、裁剪 bounding/effective/permitted 到最小集、
//! 为 exec 后需特权的子进程设 ambient caps。

#[cfg(target_os = "linux")]
use nix::unistd::{geteuid, getgroups, getuid, Gid};

use crate::Error;

/// crbs 服务专用系统组名（helper 身份校验依据）。
pub const CRBS_GROUP: &str = "crbs";

/// setuid-root 启动时先设 securebits（KEEP_CAPS + NO_SETUID_FIXUP）：否则后续裁剪
/// effective caps 时内核把 euid 重置回 ruid 并清空能力集，子进程（如 dnf）失去特权。
#[cfg(target_os = "linux")]
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

/// 校验调用者身份：root 或 crbs 组成员。
#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
/// 从 `/etc/group` 解析 `crbs` 组的 gid；组缺失或行格式非法均报错。
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

/// 裁剪当前进程能力集到指定集合——bounding/effective/permitted 同步收，helper 自身特权操作同样受限。
#[cfg(target_os = "linux")]
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

/// 为 exec 的子进程保留能力：提升 inheritable + ambient。子进程 exec 后仍需特权
/// 即须调用（dnf 全集；nspawn/chroot 亦然——其 SETFCAP 在 NOROOT 下 exec 后仅
/// ambient 存活，沙箱内 dnf/rpm 装含 %caps 包缺它即 EPERM）。
#[cfg(target_os = "linux")]
pub fn set_ambient_caps_for_exec(keep: &[Capability]) -> Result<(), Error> {
    let keep: std::collections::HashSet<caps::Capability> =
        keep.iter().copied().map(Into::into).collect();

    for cap in &keep {
        caps::raise(None, caps::CapSet::Inheritable, *cap)
            .map_err(|e| Error::Capability(format!("raise inheritable {cap:?}: {e}")))?;
        // CAP_SETPCAP 不能加入 ambient set，跳过。
        if *cap != caps::Capability::CAP_SETPCAP {
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

/// SELinux 是否启用（enforcing 或 permissive）：启用时内核挂载 selinuxfs 并暴露
/// `/sys/fs/selinux/enforce` 节点；`selinux=0` 禁用时不挂载、节点不存在。
#[cfg(target_os = "linux")]
pub fn selinux_enabled() -> bool {
    std::path::Path::new("/sys/fs/selinux/enforce").exists()
}

#[cfg(not(target_os = "linux"))]
pub fn selinux_enabled() -> bool {
    false
}

/// helper 内部 capability 枚举，桥接 `caps` crate 类型；非 Linux 上仅作占位类型，保持调用方代码与 Linux 一致。
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Capability {
    /// 挂载、命名空间等管理操作。
    CAP_SYS_ADMIN,
    /// chroot 切换根目录。
    CAP_SYS_CHROOT,
    /// 修改文件属主。
    CAP_CHOWN,
    /// 绕过文件属主权限检查。
    CAP_FOWNER,
    /// 切换进程 UID。
    CAP_SETUID,
    /// 切换进程 GID。
    CAP_SETGID,
    /// 调整进程 capability 集合。
    CAP_SETPCAP,
    /// 配置内核审计。
    CAP_AUDIT_CONTROL,
    /// 写审计日志。
    CAP_AUDIT_WRITE,
    /// 设置文件 capability。
    CAP_SETFCAP,
    /// 绕过文件读写权限检查。
    CAP_DAC_OVERRIDE,
    /// 配置 MAC（SELinux）策略。
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
