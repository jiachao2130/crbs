// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You can obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Chroot 进入 rootfs 的底层 helper：Linux 经 `Command::pre_exec` 调 `unshare`/`chroot`/`chdir`；
//! 非 Linux 平台不提供 syscall 版本，由调用方保留外部二进制 fallback。

#[cfg(target_os = "linux")]
use {
    nix::libc,
    nix::sched::{unshare, CloneFlags},
    nix::unistd::{chdir, chroot},
    std::ffi::OsStr,
    std::io,
    std::os::unix::process::CommandExt,
    std::path::Path,
    std::process::Command,
};

/// `nix::Error` → `io::Error`，不分配不格式化（`pre_exec` 专用须 async-signal-safe；nix 0.29 `Error` 即 `Errno`）。
#[cfg(target_os = "linux")]
fn nix_err_to_io(e: nix::Error) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

// ── exec 前收口：Linux capability ABI 数值常量（include/uapi/linux/capability.h）──
// 不复用 caps crate（pre_exec 须 async-signal-safe，caps 集合类型有分配）；数值与 crbs-priv-helper chroot_command 手抄对齐。
#[cfg(target_os = "linux")]
mod caps_abi {
    // 父模块 use 不进子模块作用域；走 nix 重导出，不给 crbs-core 直接新增 libc 依赖。
    use nix::libc;

    pub const CAP_CHOWN: libc::c_ulong = 0;
    pub const CAP_DAC_OVERRIDE: libc::c_ulong = 1;
    pub const CAP_FOWNER: libc::c_ulong = 3;
    pub const CAP_SETGID: libc::c_ulong = 6;
    pub const CAP_SETUID: libc::c_ulong = 7;
    pub const CAP_AUDIT_WRITE: libc::c_ulong = 29;
}

/// exec 后构建负载仍需的能力集（inheritable + ambient）：rpm chown/scriptlet→
/// CHOWN/DAC_OVERRIDE/FOWNER、sudo 切用户→SETUID/SETGID、audit 写→AUDIT_WRITE。
/// NOROOT 后 exec 的 permitted = ambient，缺任何一项对应构建操作即 EPERM。
#[cfg(target_os = "linux")]
const BUILD_AMBIENT_CAPS: [libc::c_ulong; 6] = [
    caps_abi::CAP_CHOWN,
    caps_abi::CAP_DAC_OVERRIDE,
    caps_abi::CAP_FOWNER,
    caps_abi::CAP_SETGID,
    caps_abi::CAP_SETUID,
    caps_abi::CAP_AUDIT_WRITE,
];

/// `_LINUX_CAPABILITY_VERSION_3`（include/uapi/linux/capability.h）。
#[cfg(target_os = "linux")]
const CAP_VERSION_3: libc::c_uint = 0x2008_0522;

/// prctl(2) PR_CAP_AMBIENT 操作码（include/uapi/linux/prctl.h = 47；libc 对部分 gnu
/// 目标未导出，按 ABI 数值定义；勿混 38 = PR_SET_NO_NEW_PRIVS，错值给 RAISE 恒 EINVAL）。
#[cfg(target_os = "linux")]
const PR_CAP_AMBIENT: libc::c_int = 47;
#[cfg(target_os = "linux")]
const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;

#[cfg(target_os = "linux")]
#[repr(C)]
struct CapUserHeader {
    version: libc::c_uint,
    pid: libc::c_int,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserData {
    effective: libc::c_uint,
    permitted: libc::c_uint,
    inheritable: libc::c_uint,
}

/// 把 [`BUILD_AMBIENT_CAPS`] 放进 inheritable 并 raise ambient；raw capget/capset/
/// prctl 全栈数据无分配（async-signal-safe）。ambient raise 要求 cap 同在 permitted
/// 与 inheritable（permitted 由 root 身份保证，capset 补齐；目标集 ⊆ permitted ⊆ bounding，
/// 满足 capset(2) 继承约束）；任一步失败即返回——收口失败必须让 spawn 失败，不得无能力 exec。
#[cfg(target_os = "linux")]
fn set_ambient_caps_for_build() -> io::Result<()> {
    let hdr = CapUserHeader {
        version: CAP_VERSION_3,
        pid: 0,
    };
    let mut data = [CapUserData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capget 只写入调用方提供的定长栈缓冲。
    if unsafe { libc::syscall(libc::SYS_capget, &hdr, data.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    for cap in BUILD_AMBIENT_CAPS {
        let (word, bit) = ((cap / 32) as usize, 1u32 << (cap % 32));
        data[word].inheritable |= bit;
    }
    // SAFETY: capset 读取调用方提供的定长栈缓冲。
    if unsafe { libc::syscall(libc::SYS_capset, &hdr, data.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    for cap in BUILD_AMBIENT_CAPS {
        // SAFETY: prctl 常量参数，无内存访问。
        if unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Linux：构造 Command，子进程 exec 前进入新 network namespace（可选）、chroot 到
/// rootfs，做与 crbs-priv-helper `chroot_command` 同款的 exec 前收口。闭包在 fork/exec
/// 间执行须 async-signal-safe：只用 nix 包装 syscall 与 raw prctl/capset，无分配、不日志、不 panic。
#[cfg(target_os = "linux")]
pub(crate) fn command_in_rootfs<S, I>(
    rootfs: &Path,
    program: S,
    args: I,
    network: bool,
) -> io::Result<Command>
where
    S: AsRef<OsStr>,
    I: IntoIterator,
    I::Item: AsRef<OsStr>,
{
    let rootfs = rootfs.to_path_buf();
    let program = program.as_ref().to_os_string();
    let args: Vec<_> = args
        .into_iter()
        .map(|a| a.as_ref().to_os_string())
        .collect();

    unsafe {
        let mut cmd = Command::new(program);
        cmd.args(args);
        // 与 helper 路径同款环境卫生：exec 的 PATH 搜索跟随子进程环境，继承守护进程 PATH
        // （不含 sbin）则 sbin-only 二进制 ENOENT；HOME/proxy/token 等守护环境不应带入 chroot 内以 root 运行的进程。
        cmd.env_clear();
        cmd.env("PATH", crate::engine::backend::SAFE_PATH);
        cmd.pre_exec(move || {
            if !network {
                if let Err(e) = unshare(CloneFlags::CLONE_NEWNET) {
                    return Err(nix_err_to_io(e));
                }
            }
            if let Err(e) = chroot(&rootfs) {
                return Err(nix_err_to_io(e));
            }
            if let Err(e) = chdir("/") {
                return Err(nix_err_to_io(e));
            }
            // ── exec 前封死 root 特例能力回灌（主机逃逸收口）────────────
            // 与 crbs-priv-helper chroot_command 的 pre_exec 收口对齐：exec 时 euid=0 且 bounding 仍含
            // SYS_ADMIN/SYS_CHROOT，无 SECBIT_NOROOT 时 capabilities(7) root 特例把 permitted/effective
            // 从 bounding 重新灌满——chroot 内负载即可经典双 chroot 逃逸。四步封死：
            // 1) 构建能力先进 inheritable+ambient（set_ambient_caps_for_build）：NOROOT 后
            //    exec 的 permitted = ambient，缺集则 rpm chown/scriptlet、sudo 切用户 EPERM；
            // 2) SECBIT_NOROOT(+LOCKED)：exec 不再走 root 特例；
            // 3) bounding 收敛到 BUILD_AMBIENT_CAPS（同 helper 终态）：bounding 留额外 cap 则
            //    chroot 内带 file caps 的二进制 exec 后可取回；LOCKED 后 SETPCAP 无法翻回；
            // 4) 集合 = helper spawn-chroot 分支 ambient 集，setuid 直连 / priv-helper 两条部署路径行为一致。
            set_ambient_caps_for_build()?;
            let cur = libc::prctl(libc::PR_GET_SECUREBITS);
            if cur < 0 {
                return Err(io::Error::last_os_error());
            }
            let bits = cur as libc::c_ulong
                | libc::SECBIT_NOROOT as libc::c_ulong
                | libc::SECBIT_NOROOT_LOCKED as libc::c_ulong;
            if libc::prctl(libc::PR_SET_SECUREBITS, bits) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut cap: libc::c_ulong = 0;
            loop {
                // SAFETY: prctl 常量参数，无内存访问；PR_CAPBSET_READ 超 CAP_LAST_CAP 即 EINVAL，作遍历终止条件。
                let in_bounding = libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0);
                if in_bounding < 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINVAL) {
                        break;
                    }
                    return Err(err);
                }
                if in_bounding == 1 && !BUILD_AMBIENT_CAPS.contains(&cap) {
                    // SAFETY: prctl 常量参数，无内存访问。
                    if libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                cap += 1;
            }
            Ok(())
        });
        Ok(cmd)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// 验证 chroot 到不存在的目录时，spawn 返回 NotFound 错误。
    #[tokio::test]
    #[ignore = "requires root privileges to run chroot syscalls"]
    async fn test_command_in_rootfs_bad_rootfs_returns_not_found() {
        if !nix::unistd::geteuid().is_root() {
            return;
        }
        let bad_root = std::path::Path::new("/crbs_nonexistent_rootfs_for_test");
        let mut cmd = command_in_rootfs(bad_root, "true", Vec::<&str>::new(), true)
            .expect("command construction should succeed");
        let err = cmd.spawn().expect_err("spawn should fail for bad rootfs");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    /// 收口后 exec 的子进程不得再持有 SYS_CHROOT/SYS_ADMIN/SETPCAP，ambient/CapBnd 集恰为 BUILD_AMBIENT_CAPS。
    #[tokio::test]
    #[ignore = "requires root privileges to run chroot syscalls"]
    async fn test_command_in_rootfs_caps_locked_after_exec() {
        if !nix::unistd::geteuid().is_root() {
            return;
        }
        // /bin/sh 普通文件无 file caps；NOROOT 后 permitted=ambient。
        let mut cmd = command_in_rootfs(Path::new("/"), "/bin/sh", vec!["-c", "sleep 5"], true)
            .expect("command construction should succeed");
        let mut child = cmd.spawn().expect("spawn");
        // spawn 返回时 exec 可能未完成（pre_exec 刚跑完，caps 仍是父进程全集），等 exec 后再采样。
        std::thread::sleep(std::time::Duration::from_millis(300));
        let pid = child.id();
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let cap = |name: &str| -> u64 {
            let line = status
                .lines()
                .find(|l| l.starts_with(name))
                .unwrap_or_else(|| panic!("{name} missing"));
            u64::from_str_radix(line.split_whitespace().nth(1).unwrap(), 16).unwrap()
        };
        let expected_ambient: u64 = BUILD_AMBIENT_CAPS.iter().map(|c| 1u64 << *c).sum();
        assert_eq!(cap("CapAmb"), expected_ambient);
        // bounding/permitted 收敛到构建能力集（同 helper 终态）：不含 SYS_CHROOT(18)/SYS_ADMIN(21)/SETPCAP(8)。
        assert_eq!(cap("CapBnd"), expected_ambient);
        assert_eq!(
            cap("CapPrm") & ((1 << 18) | (1 << 21) | (1 << 8)),
            0,
            "CapPrm"
        );
        let _ = child.kill();
        let _ = child.wait();
    }
}
