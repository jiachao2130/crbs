// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 特权系统调用封装：mount、chown、chmod、write_file、gc_orphan_mounts。
//!
//! 所有操作在 Linux only 下实现，非 Linux 平台返回 `Error::Unsupported`。

use std::path::{Path, PathBuf};

use crate::Error;

#[cfg(target_os = "linux")]
use std::fs;

/// 文件类目标：剥 S_ISUID|S_ISGID（0o6000），保留其余位（0o755 脚本、0o1777
/// sticky 合法）。调用方（crbs 组成员）不可信，可铸 suid-root 文件提权（漏洞 3），
/// 类型感知剥离统一在 ops 层施加；递归 chmod 对文件另有 0o666 掩码。
pub fn strip_file_setid_bits(mode: u32) -> u32 {
    mode & !0o6000
}

/// 目录类目标：剥 S_ISUID（0o4000）**保留 SGID**——目录 SGID（0o2770）是 crbs 权限不变量（新文件继承组），不能剥。
pub fn strip_dir_setid_bits(mode: u32) -> u32 {
    mode & !0o4000
}

/// 挂载点边界（漏洞 4 修复）：st_dev 不同 ⇒ 中隔挂载点（bind/overlay/tmpfs…）；
/// 递归 chown/chmod/rm-rf 穿透会作用到 bind 进来的宿主子树（/dev、dnf 缓存等），必须跳过。
pub fn crosses_mount(root_dev: u64, child_dev: u64) -> bool {
    root_dev != child_dev
}

/// 拒绝会破坏 overlayfs 选项结构的字符：`,` 是选项分隔符（可注入 `upperdir=` 等新选项），
/// `\n` 同样禁止；lowerdir 额外禁止 `:`（多 lower 的分隔符）。
#[cfg(target_os = "linux")]
fn check_overlay_path_chars(p: &Path, role: &str, is_lower: bool) -> Result<(), Error> {
    let s = p.as_os_str().to_string_lossy();
    let bad = if is_lower { ",:\n" } else { ",\n" };
    if let Some(c) = s.chars().find(|c| bad.contains(*c)) {
        return Err(Error::Validation(format!(
            "mount-overlay {role} path contains forbidden character '{c}': {}",
            p.display()
        )));
    }
    Ok(())
}

// 取舍：mount(2) 无超时参数，NFS/CIFS 可无限挂起；调用链无上界
//（helper wait_with_output 无超时，build_timeout 是协作式检查点回不去）——
// 挂起即任务永久挂起。升级路径：privilege backend 外包 tokio::time::timeout 并 kill。
/// 挂载 overlayfs：多层 lower + upper/work 叠加到 target。
pub fn mount_overlay(
    lower: &[PathBuf],
    upper: &Path,
    work: &Path,
    target: &Path,
) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        if lower.is_empty() {
            return Err(Error::Validation(
                "mount-overlay requires at least one --lower".into(),
            ));
        }

        for p in lower {
            check_overlay_path_chars(p, "lower", true)?;
        }
        check_overlay_path_chars(upper, "upper", false)?;
        check_overlay_path_chars(work, "work", false)?;

        fs::create_dir_all(upper)?;
        fs::create_dir_all(work)?;
        fs::create_dir_all(target)?;

        let lower_opt = lower
            .iter()
            .map(|p| p.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(":");
        let options = format!(
            "lowerdir={lower},upperdir={upper},workdir={work},index=off,metacopy=off",
            lower = lower_opt,
            upper = upper.display(),
            work = work.display()
        );

        nix::mount::mount(
            Some("overlay"),
            target,
            Some("overlay"),
            nix::mount::MsFlags::empty(),
            Some(options.as_str()),
        )
        .map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "mount overlay {}: {e}",
                target.display()
            )))
        })?;

        tracing::debug!(
            target = %target.display(),
            lower = %lower_opt,
            "mounted overlayfs"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (lower, upper, work, target);
        Err(Error::Unsupported("mount-overlay is Linux only".into()))
    }
}

/// 卸载 target：flags 透传 umount2(2)（如懒卸载 MNT_DETACH）。
pub fn umount(target: &Path, flags: u32) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        let nix_flags = nix::mount::MntFlags::from_bits_truncate(flags as i32);
        nix::mount::umount2(target, nix_flags).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "umount {}: {e}",
                target.display()
            )))
        })?;
        tracing::debug!(target = %target.display(), "unmounted");
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (target, flags);
        Err(Error::Unsupported("umount is Linux only".into()))
    }
}

/// 杀构建进程组（负 pgid = kill(2) 按组语义）：无需额外能力（kill 只受
/// DAC 属主约束，root 恒可）。实现走 nix（Linux only 链接），非 Linux 桩
/// 与 mount/umount 同模式。
pub fn kill_process_group(pgid: i32) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        // pgid 负值约定与 core 侧 nix::sys::signal::kill 一致。
        let target = nix::unistd::Pid::from_raw(-pgid);
        nix::sys::signal::kill(target, nix::sys::signal::SIGKILL).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "kill process group {pgid}: {e}"
            )))
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pgid;
        Err(Error::Unsupported(
            "kill-process-group is Linux only".into(),
        ))
    }
}

/// 受控终止本系统自建的 nspawn machine（信任锚见
/// [`crate::validate::validate_machine_name`]）：探测 scope 目录写
/// `cgroup.kill`（原子杀整棵子树；v2 统一根与 v1 legacy systemd 根下都实测
/// 存在此文件）；kill 文件不可写再按 /proc cgroup 成员 SIGKILL 兜底，杀伤
/// 边界 = kernel 报告的 scope 从属。machine 已不存在（scope 与成员皆空）按
/// 幂等成功。
pub fn terminate_machine(machine_name: &str) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        let mut scope_seen = false;
        for scope in machine_scope_cgroup_dirs(machine_name) {
            scope_seen |= scope.is_dir();
            let kill_file = scope.join("cgroup.kill");
            if kill_file.exists() {
                // 目录在且 kill 文件在但写失败 → 报错（fail-closed）：部分杀伤
                // 后继续跑会让调用方把失败当收敛，绝不落 /proc 兜底假成功。
                return write_cgroup_file(&kill_file, "1\n");
            }
        }
        let killed = terminate_scope_members(machine_name)?;
        // 幂等复核：killed == 0 且 scope 目录从未出现 = machine 已不在（未注册
        // /自然退出）；scope 在但无可见成员 = 构建已自然退出、scope 待 machined
        // 回收——两者都按成功，scope_seen 仅区分观测面供审计。
        tracing::debug!(
            machine = %machine_name,
            killed = killed,
            scope_seen = scope_seen,
            "terminate-machine done"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = machine_name;
        Err(Error::Unsupported("terminate-machine is Linux only".into()))
    }
}

/// scope 目录的 cgroup 路径候选（写探测顺序）：cgroup v2 统一根 + v1 legacy
/// 的 systemd 层级根（v1 宿主层级挂 /sys/fs/cgroup/systemd，无 v2 前缀）×
/// 双命名形态（`{name}.scope` / `machine-{name}.scope`）× 原样/转义——
/// machined 注册的 scope 目录名即转义形态（`machine-crbs\x2d…`），两栈都存
/// 在，漏任一形态则 terminate 落空。转义见
/// [`crate::validate::systemd_escape_dash`]。顺序与 crbs-core nspawn cgroup.rs
/// 的 `scope_path_candidates` 手抄同步。machine_name 已过
/// validate_machine_name，拼接不可能逃逸出 machine.slice。
#[cfg(target_os = "linux")]
fn machine_scope_cgroup_dirs(machine_name: &str) -> Vec<PathBuf> {
    const SLICE_ROOTS: [&str; 2] = [
        "/sys/fs/cgroup/machine.slice",
        "/sys/fs/cgroup/systemd/machine.slice",
    ];
    let escaped = crate::validate::systemd_escape_dash(machine_name);
    let names = [
        format!("{machine_name}.scope"),
        format!("{escaped}.scope"),
        format!("machine-{machine_name}.scope"),
        format!("machine-{escaped}.scope"),
    ];
    let mut dirs = Vec::with_capacity(SLICE_ROOTS.len() * names.len());
    for root in SLICE_ROOTS {
        for name in &names {
            dirs.push(PathBuf::from(format!("{root}/{name}")));
        }
    }
    dirs
}

/// SIGKILL scope 内全部 /proc 成员（cgroup 任一行落在 scope 之下即成员），
/// 返回 SIGKILL 成功数；cgroup 不可读/ESRCH 按扫描间隙消失跳过，尽力终止，
/// 收敛复核由调用方（crbs-core kill 升级链）负责。
#[cfg(target_os = "linux")]
fn terminate_scope_members(machine_name: &str) -> Result<usize, Error> {
    let mut killed = 0usize;
    let entries = std::fs::read_dir("/proc").map_err(|e| {
        Error::Io(std::io::Error::other(format!(
            "terminate-machine scan /proc: {e}"
        )))
    })?;
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(content) = std::fs::read_to_string(entry.path().join("cgroup")) else {
            continue;
        };
        if crate::validate::cgroup_in_machine_scope(&content, machine_name)
            && nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::SIGKILL)
                .is_ok()
        {
            killed += 1;
        }
    }
    Ok(killed)
}

// 取舍：mount(2) 无超时参数，NFS/CIFS 可无限挂起；调用链无上界
//（helper wait_with_output 无超时，build_timeout 是协作式检查点回不去）——
// 挂起即任务永久挂起。升级路径：privilege backend 外包 tokio::time::timeout 并 kill。
/// 通用挂载：source / fstype / flags / data 透传 mount(2)（bind、proc 等用）。
pub fn mount(
    source: Option<&str>,
    target: &Path,
    fstype: Option<&str>,
    flags: u64,
    data: Option<&str>,
) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        let nix_flags = nix::mount::MsFlags::from_bits_truncate(flags);
        nix::mount::mount(source, target, fstype, nix_flags, data).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "mount {}: {e}",
                target.display()
            )))
        })?;
        tracing::debug!(target = %target.display(), fstype = ?fstype, "mounted");
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (source, target, fstype, flags, data);
        Err(Error::Unsupported("mount is Linux only".into()))
    }
}

/// 创建目录（含缺失父级）并 chown 到 user:group、chmod 指定 mode（应用前剥
/// setid 位，见 [`strip_dir_setid_bits`]）。fd 锚定（与 write/chown/chmod/rm-rf
/// 同级 TOCTOU 防护，见 `fs_walk::create_dir_anchored`）：父链逐组件
/// O_DIRECTORY|O_NOFOLLOW 解析补建，chown/chmod 锚定已验证 fd 不经名字解析。
pub fn mkdir_chown(path: &Path, user: &str, group: &str, mode: u32) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::stat::{fchmod, Mode};
        use nix::unistd::{fchown, Gid, Uid};
        use std::os::unix::io::AsRawFd;

        let dir = fs_walk::create_dir_anchored(path)?;
        let dirfd = dir.as_raw_fd();

        let uid = nix::unistd::User::from_name(user)
            .map_err(|e| Error::Io(std::io::Error::other(format!("lookup user {user}: {e}"))))?
            .map(|u| u.uid.as_raw())
            .ok_or_else(|| Error::Validation(format!("user {user} not found")))?;
        let gid = nix::unistd::Group::from_name(group)
            .map_err(|e| Error::Io(std::io::Error::other(format!("lookup group {group}: {e}"))))?
            .map(|g| g.gid.as_raw())
            .ok_or_else(|| Error::Validation(format!("group {group} not found")))?;

        fchown(dirfd, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "fchown {}: {e}",
                path.display()
            )))
        })?;

        // 剥 SUID 保 SGID（0o2770 权限不变量；SUID 目录无合法调用方，漏洞 3）。
        let mode = crate::ops::strip_dir_setid_bits(mode);
        let mode = Mode::from_bits_truncate(mode as nix::libc::mode_t);
        fchmod(dirfd, mode).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "fchmod {}: {e}",
                path.display()
            )))
        })?;

        tracing::debug!(
            path = %path.display(),
            user = %user,
            group = %group,
            mode = %format!("{:04o}", mode),
            "mkdir-chown done"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, user, group, mode);
        Err(Error::Unsupported("mkdir-chown is Linux only".into()))
    }
}

/// fd 相对的递归遍历：每级目录以 `O_DIRECTORY | O_NOFOLLOW` 打开，操作经
/// `fchown`/`fchmod`/`f*at(dirfd, …)` 施加，全程不依赖路径字符串。根/父路径
/// 由 `resolve_leaf` 从受信锚点逐组件解析，write_file / chown / chmod / rm-rf /
/// mkdir_chown 五操作共用此"受信打开根"原语。read_dir 递归在"判定是目录"与
/// "进入"间有窗口，目录被换成 symlink 即以 root 改写攻击者指定文件；fd 遍历
/// openat 遇 symlink/非目录直接失败，置换只能失败或跳过。
#[cfg(target_os = "linux")]
mod fs_walk {
    use std::ffi::OsStr;
    use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
    use std::path::{Component, Path};

    use nix::dir::{Dir, Type};
    use nix::errno::Errno;
    use nix::fcntl::{openat, AtFlags, OFlag};
    use nix::sys::stat::{fchmod, fchmodat, fstat, fstatat, mkdirat, FchmodatFlags, Mode};
    use nix::unistd::{fchown, fchownat, unlinkat, Gid, Uid, UnlinkatFlags};

    use crate::Error;

    #[derive(Clone, Copy)]
    enum WalkOp {
        Chown { uid: u32, gid: u32 },
        Chmod { mode: u32 },
    }

    enum EntryKind {
        Dir,
        Symlink,
        File,
    }

    /// 逐组件解析途中遇到组件缺失（ENOENT）的处置策略。
    #[derive(Clone, Copy, PartialEq)]
    enum Missing {
        /// 视为路径不存在，解析返回 `None`（rm -rf 的 no-op 语义）。
        Ignore,
        /// 报错：操作对象必须已经存在（chown / chmod）。
        Fail,
        /// `mkdirat` 逐级补建后重开（write-file 的 create_dir_all 语义）。
        Create,
    }

    const OPEN_FLAGS: OFlag = OFlag::O_RDONLY
        .union(OFlag::O_CLOEXEC)
        .union(OFlag::O_DIRECTORY)
        .union(OFlag::O_NOFOLLOW);

    /// 组件打开失败（非缺失）的统一错误映射：symlink/非目录明确点名 fail-closed。
    fn open_err(e: Errno, name: &OsStr, path: &Path, op: &str) -> Error {
        match e {
            Errno::ELOOP | Errno::ENOTDIR => Error::Io(std::io::Error::other(format!(
                "{op}: component {name:?} of {} is or was replaced by a symlink/non-directory: {e}",
                path.display()
            ))),
            _ => Error::Io(std::io::Error::other(format!(
                "open component {name:?} of {}: {e}",
                path.display()
            ))),
        }
    }

    /// 经 `dir` 打开单个中间组件（原子校验）；仅 `Ignore` 缺失返回 `Ok(None)`。
    fn open_component(
        dir: &OwnedFd,
        name: &OsStr,
        path: &Path,
        missing: Missing,
        op: &str,
    ) -> Result<Option<OwnedFd>, Error> {
        let dirfd = dir.as_raw_fd();
        let opened = match openat(Some(dirfd), name, OPEN_FLAGS, Mode::empty()) {
            Ok(fd) => Some(fd),
            Err(Errno::ENOENT) => match missing {
                Missing::Ignore => return Ok(None),
                Missing::Fail => {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!(
                            "{op}: component {name:?} of {} does not exist",
                            path.display()
                        ),
                    )));
                }
                Missing::Create => {
                    // create_dir_all 等价：mkdir(0777) 受 umask；EEXIST 并发补建回落重开。
                    if let Err(e) = mkdirat(Some(dirfd), name, Mode::from_bits_truncate(0o777)) {
                        if !matches!(e, Errno::EEXIST) {
                            return Err(Error::Io(std::io::Error::other(format!(
                                "mkdir component {name:?} of {}: {e}",
                                path.display()
                            ))));
                        }
                    }
                    match openat(Some(dirfd), name, OPEN_FLAGS, Mode::empty()) {
                        Ok(fd) => Some(fd),
                        Err(e) => return Err(open_err(e, name, path, op)),
                    }
                }
            },
            Err(e) => return Err(open_err(e, name, path, op)),
        };
        Ok(opened.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// 递归 chown：根经 `resolve_leaf` 逐组件解析且必须是真实目录（symlink 拒绝）。
    pub fn chown_recursive(path: &Path, uid: u32, gid: u32) -> Result<(), Error> {
        let (parent, leaf) = resolve_leaf_required(path, Missing::Fail, "chown -r")?;
        let root = match openat(Some(parent.as_raw_fd()), leaf, OPEN_FLAGS, Mode::empty()) {
            Ok(fd) => unsafe { OwnedFd::from_raw_fd(fd) },
            Err(e @ (Errno::ELOOP | Errno::ENOTDIR)) => {
                return Err(Error::Io(std::io::Error::other(format!(
                    "chown -r: {} is or was replaced by a symlink/non-directory: {e}",
                    path.display()
                ))));
            }
            Err(e) => {
                return Err(Error::Io(std::io::Error::other(format!(
                    "chown -r: open {}: {e}",
                    path.display()
                ))));
            }
        };
        let op = WalkOp::Chown { uid, gid };
        let root_dev = fd_dev(root.as_raw_fd())?;
        apply_fd(root.as_raw_fd(), op)?;
        walk(dir_from(root)?, op, root_dev)
    }

    /// 递归 chmod：根路径逐组件解析（`resolve_leaf`）；根为普通文件/symlink 时
    /// 退化为单文件 chmod（保持旧语义；symlink 经 fchmodat NoFollow 报 EOPNOTSUPP）。
    pub fn chmod_recursive(path: &Path, mode: u32) -> Result<(), Error> {
        let (parent, leaf) = resolve_leaf_required(path, Missing::Fail, "chmod -r")?;
        let dirfd = parent.as_raw_fd();
        match openat(Some(dirfd), leaf, OPEN_FLAGS, Mode::empty()) {
            Ok(fd) => {
                let root = unsafe { OwnedFd::from_raw_fd(fd) };
                let op = WalkOp::Chmod { mode };
                let root_dev = fd_dev(root.as_raw_fd())?;
                apply_fd(root.as_raw_fd(), op)?;
                walk(dir_from(root)?, op, root_dev)
            }
            Err(Errno::ELOOP | Errno::ENOTDIR) => {
                // 根是文件/symlink：单文件语义；剥 setid（漏洞 3）。
                fchmodat(
                    Some(dirfd),
                    leaf,
                    Mode::from_bits_truncate(
                        crate::ops::strip_file_setid_bits(mode) as nix::libc::mode_t
                    ),
                    FchmodatFlags::NoFollowSymlink,
                )
                .map_err(|e| {
                    Error::Io(std::io::Error::other(format!(
                        "fchmodat {}: {e}",
                        path.display()
                    )))
                })
            }
            Err(e) => Err(Error::Io(std::io::Error::other(format!(
                "chmod -r: open {}: {e}",
                path.display()
            )))),
        }
    }

    /// 单路径 chown（lchown 语义不跟随）：父目录经 `resolve_leaf` 逐组件锚定，中间组件无 TOCTOU 窗口。
    pub fn chown_leaf(path: &Path, uid: u32, gid: u32) -> Result<(), Error> {
        let (parent, leaf) = resolve_leaf_required(path, Missing::Fail, "chown")?;
        fchownat(
            Some(parent.as_raw_fd()),
            leaf,
            Some(Uid::from_raw(uid)),
            Some(Gid::from_raw(gid)),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "lchown {}: {e}",
                path.display()
            )))
        })
    }

    /// 单路径 chmod（fchmodat NoFollow）：类型感知剥 setid 位（漏洞 3）——目录剥 SUID 保 SGID，文件剥 SUID+SGID。
    pub fn chmod_leaf(path: &Path, mode: u32) -> Result<(), Error> {
        let (parent, leaf) = resolve_leaf_required(path, Missing::Fail, "chmod")?;
        let st =
            fstatat(Some(parent.as_raw_fd()), leaf, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|e| {
                Error::Io(std::io::Error::other(format!(
                    "stat {:?} for chmod {}: {e}",
                    leaf,
                    path.display()
                )))
            })?;
        let mode = if st.st_mode & nix::libc::S_IFMT == nix::libc::S_IFDIR {
            crate::ops::strip_dir_setid_bits(mode)
        } else {
            crate::ops::strip_file_setid_bits(mode)
        };
        fchmodat(
            Some(parent.as_raw_fd()),
            leaf,
            Mode::from_bits_truncate(mode as nix::libc::mode_t),
            FchmodatFlags::NoFollowSymlink,
        )
        .map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "fchmodat {}: {e}",
                path.display()
            )))
        })
    }

    /// 递归删除：fd 相对遍历 + `unlinkat`，全程不跟随 symlink。根路径逐组件
    /// 解析（`resolve_leaf`）而非整路径 `openat(None, path)`——整路径
    /// O_NOFOLLOW 只护最后一级（open(2)：earlier components will still be
    /// followed），validate 后中间组件换 symlink 会被跟随；逐组件每级原子
    /// 校验 fail-closed。根为文件/symlink 经父 fd unlink；目录后序清空后
    /// rmdir；路径不存在（含中间组件缺失）按 no-op。
    pub fn remove_recursive(path: &Path) -> Result<(), Error> {
        let Some((parent, leaf)) = resolve_leaf(path, Missing::Ignore, "rm -rf")? else {
            return Ok(());
        };
        let dirfd = parent.as_raw_fd();
        let st = match fstatat(Some(dirfd), leaf, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(Errno::ENOENT) => return Ok(()),
            Err(e) => {
                return Err(Error::Io(std::io::Error::other(format!(
                    "stat {:?} in {}: {e}",
                    leaf,
                    path.display()
                ))))
            }
        };
        if st.st_mode & nix::libc::S_IFMT != nix::libc::S_IFDIR {
            return unlinkat(Some(dirfd), leaf, UnlinkatFlags::NoRemoveDir).map_err(|e| {
                Error::Io(std::io::Error::other(format!(
                    "unlink {:?} in {}: {e}",
                    leaf,
                    path.display()
                )))
            });
        }
        let root = match openat(Some(dirfd), leaf, OPEN_FLAGS, Mode::empty()) {
            Ok(fd) => unsafe { OwnedFd::from_raw_fd(fd) },
            // stat 到 open 之间叶子被换成 symlink/文件：fail-closed 报错。
            Err(e @ (Errno::ELOOP | Errno::ENOTDIR)) => {
                return Err(Error::Io(std::io::Error::other(format!(
                    "rm -rf: {} was replaced by non-directory during removal: {e}",
                    path.display()
                ))));
            }
            Err(e) => {
                return Err(Error::Io(std::io::Error::other(format!(
                    "open dir {:?} in {}: {e}",
                    leaf,
                    path.display()
                ))))
            }
        };
        let root_dev = fd_dev(root.as_raw_fd())?;
        walk_remove(dir_from(root)?, root_dev, 0)?;
        // 删根本身：经父 fd rmdir 叶子名，换成 symlink/文件则 ENOTDIR fail-closed。
        unlinkat(Some(dirfd), leaf, UnlinkatFlags::RemoveDir).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "rmdir {:?} in {}: {e}",
                leaf,
                path.display()
            )))
        })
    }

    /// 逐组件解析 `path`，返回 (叶子所在目录 fd, 叶子名)。从受信锚点出发
    ///（绝对路径 `/`、相对路径 `.`——内核保留名不可能被换成 symlink），每个
    /// 中间组件单独 `openat(dirfd, comp, O_DIRECTORY | O_NOFOLLOW)` 原子校验：
    /// symlink（ELOOP）/非目录（ENOTDIR）fail-closed，缺失（ENOENT）按
    /// `missing` 策略（no-op/报错/mkdirat 补建）。write_file / chown / chmod /
    /// rm-rf / mkdir_chown 共用此原语，关闭 validate 后整路径解析被置换的
    /// TOCTOU 窗口。`.`/`..` 中间组件经内核解析（保留名无 TOCTOU）；叶子为
    /// `..`/`.`（含整体 `/`、`.`）直接拒绝——rm -rf 会先清空所指目录再失败，
    /// write/chown/chmod 会作用到祖先目录，必须 fail-closed。
    fn resolve_leaf<'a>(
        path: &'a Path,
        missing: Missing,
        op: &str,
    ) -> Result<Option<(OwnedFd, &'a OsStr)>, Error> {
        // 头部的 RootDir / CurDir 由锚点 fd 覆盖（CurDir 仅可能出现在头部）。
        let mut comps: Vec<Component<'_>> = path
            .components()
            .filter(|c| !matches!(c, Component::RootDir | Component::CurDir))
            .collect();
        let leaf = match comps.pop() {
            Some(Component::Normal(name)) => name,
            Some(Component::ParentDir) => {
                return Err(Error::Validation(format!(
                    "{op}: refusing '..' leaf: {}",
                    path.display()
                )));
            }
            None => {
                // 空路径、"/"、"."：无可操作叶子名。
                return Err(Error::Validation(format!(
                    "{op}: refusing filesystem root, cwd or empty path: {}",
                    path.display()
                )));
            }
            _ => {
                return Err(Error::Validation(format!(
                    "unsupported path component: {}",
                    path.display()
                )));
            }
        };

        let anchor = if path.is_absolute() { "/" } else { "." };
        let mut fd = match openat(None, anchor, OPEN_FLAGS, Mode::empty()) {
            Ok(fd) => unsafe { OwnedFd::from_raw_fd(fd) },
            Err(Errno::ENOENT) if missing == Missing::Ignore => return Ok(None),
            Err(e) => {
                return Err(Error::Io(std::io::Error::other(format!(
                    "open anchor {anchor}: {e}"
                ))));
            }
        };
        for comp in &comps {
            let name = match comp {
                Component::Normal(name) => *name,
                Component::ParentDir => OsStr::new(".."),
                Component::RootDir | Component::CurDir => continue,
                Component::Prefix(_) => {
                    return Err(Error::Validation(format!(
                        "unsupported path prefix: {}",
                        path.display()
                    )));
                }
            };
            fd = match open_component(&fd, name, path, missing, op)? {
                Some(fd) => fd,
                None => return Ok(None),
            };
        }
        Ok(Some((fd, leaf)))
    }

    /// `Fail`/`Create` 策略入口：不因组件缺失返回 `None`（缺失报错/已补建），
    /// None 仅剩防御式不可达臂；调用方直接拿到 (父目录 fd, 叶子名)。
    fn resolve_leaf_required<'a>(
        path: &'a Path,
        missing: Missing,
        op: &str,
    ) -> Result<(OwnedFd, &'a OsStr), Error> {
        match resolve_leaf(path, missing, op)? {
            Some(resolved) => Ok(resolved),
            None => Err(Error::Io(std::io::Error::other(format!(
                "{op}: anchor of {} vanished during resolution",
                path.display()
            )))),
        }
    }

    /// write-file 父目录解析：缺失组件 mkdirat 逐级补建，symlink/非目录
    /// fail-closed；返回 fd 是 tempfile 与 rename 必须锚定的已验证父目录。
    pub fn parent_for_write(path: &Path) -> Result<(OwnedFd, &OsStr), Error> {
        resolve_leaf_required(path, Missing::Create, "write-file")
    }

    /// mkdir-chown 的 fd 锚定实现：确保 `path` 指向真实目录并返回已打开的
    /// 目录 fd（`O_DIRECTORY | O_NOFOLLOW`；中间组件缺失按 Create 策略补建，
    /// 见 [`resolve_leaf`]）。叶子 mkdirat（EEXIST 容忍 = mkdir -p 幂等）后以
    /// OPEN_FLAGS 打开，symlink/普通文件/被置换都在此步原子 fail-closed 无
    /// 副作用（该形态本被 validate 挡在门外）；调用方对 fd 直接 fchown/fchmod 不经名字解析，与 write/chown/chmod/rm-rf 同级消除 TOCTOU。
    pub fn create_dir_anchored(path: &Path) -> Result<OwnedFd, Error> {
        let (parent, leaf) = resolve_leaf_required(path, Missing::Create, "mkdir-chown")?;
        let dirfd = parent.as_raw_fd();
        if let Err(e) = mkdirat(Some(dirfd), leaf, Mode::from_bits_truncate(0o777)) {
            if !matches!(e, Errno::EEXIST) {
                return Err(Error::Io(std::io::Error::other(format!(
                    "mkdir component {leaf:?} of {}: {e}",
                    path.display()
                ))));
            }
        }
        match openat(Some(dirfd), leaf, OPEN_FLAGS, Mode::empty()) {
            Ok(fd) => Ok(unsafe { OwnedFd::from_raw_fd(fd) }),
            // EEXIST 后打开失败 = 叶子非目录：对齐 create_dir_all AlreadyExists 分类。
            Err(e @ (Errno::ELOOP | Errno::ENOTDIR)) => Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "mkdir-chown: {leaf:?} of {} exists and is not a directory: {e}",
                    path.display()
                ),
            ))),
            Err(e) => Err(Error::Io(std::io::Error::other(format!(
                "mkdir-chown: open {}: {e}",
                path.display()
            )))),
        }
    }

    fn dir_from(fd: OwnedFd) -> Result<Dir, Error> {
        // from_fd 在 fdopendir 失败时自行关闭 fd。
        Dir::from_fd(fd.into_raw_fd())
            .map_err(|e| Error::Io(std::io::Error::other(format!("fdopendir: {e}"))))
    }

    /// fd 的 st_dev，供 [`crate::ops::crosses_mount`] 判定挂载点边界。
    // dev_t 宽度平台相关（Linux u64/macOS u32）：macOS 需宽化，allow unnecessary_cast。
    #[allow(clippy::unnecessary_cast)]
    fn fd_dev(fd: RawFd) -> Result<u64, Error> {
        fstat(fd)
            .map(|st| st.st_dev)
            .map_err(|e| Error::Io(std::io::Error::other(format!("fstat walk fd: {e}"))))
    }

    fn apply_fd(fd: RawFd, op: WalkOp) -> Result<(), Error> {
        match op {
            WalkOp::Chown { uid, gid } => {
                fchown(fd, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
            }
            WalkOp::Chmod { mode } => {
                // 只用于目录 fd：剥 SUID 保 SGID（0o2770 不变量）；文件见 walk File 分支。
                let mode = crate::ops::strip_dir_setid_bits(mode);
                fchmod(fd, Mode::from_bits_truncate(mode as nix::libc::mode_t))
            }
        }
        .map_err(|e| Error::Io(std::io::Error::other(format!("apply on dir fd: {e}"))))
    }

    fn classify(dirfd: RawFd, entry: &nix::dir::Entry) -> Result<EntryKind, Error> {
        match entry.file_type() {
            Some(Type::Directory) => Ok(EntryKind::Dir),
            Some(Type::Symlink) => Ok(EntryKind::Symlink),
            Some(Type::File) => Ok(EntryKind::File),
            _ => {
                // d_type 未知（DT_UNKNOWN 或其它类型）：fstatat 兜底，不跟随 symlink。
                let st = fstatat(Some(dirfd), entry.file_name(), AtFlags::AT_SYMLINK_NOFOLLOW)
                    .map_err(|e| {
                        Error::Io(std::io::Error::other(format!(
                            "stat dir entry {:?}: {e}",
                            entry.file_name()
                        )))
                    })?;
                Ok(match st.st_mode & nix::libc::S_IFMT {
                    nix::libc::S_IFDIR => EntryKind::Dir,
                    nix::libc::S_IFLNK => EntryKind::Symlink,
                    _ => EntryKind::File,
                })
            }
        }
    }

    fn walk(dir: Dir, op: WalkOp, root_dev: u64) -> Result<(), Error> {
        let mut dir = dir;
        let dirfd = dir.as_raw_fd();
        for entry in dir.iter() {
            let entry = entry
                .map_err(|e| Error::Io(std::io::Error::other(format!("read dir entry: {e}"))))?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            match classify(dirfd, &entry)? {
                EntryKind::Dir => {
                    let child = match openat(Some(dirfd), name, OPEN_FLAGS, Mode::empty()) {
                        Ok(fd) => unsafe { OwnedFd::from_raw_fd(fd) },
                        Err(e @ (Errno::ELOOP | Errno::ENOTDIR)) => {
                            // 判定到打开间被换成 symlink/非目录：跳过，遍历继续（fail safe）。
                            tracing::warn!(entry = ?name, errno = %e, "skip entry replaced during recursive walk");
                            continue;
                        }
                        Err(e) => {
                            return Err(Error::Io(std::io::Error::other(format!(
                                "open dir entry {:?}: {e}",
                                name
                            ))))
                        }
                    };
                    // 挂载点边界：st_dev 不同 ⇒ 中隔 bind/overlay/tmpfs（宿主 /dev、
                    // dnf 缓存等 bind 进构建树），递归不得穿透宿主子树。
                    if crate::ops::crosses_mount(root_dev, fd_dev(child.as_raw_fd())?) {
                        tracing::warn!(entry = ?name, "skip mountpoint during recursive walk");
                        continue;
                    }
                    apply_fd(child.as_raw_fd(), op)?;
                    walk(dir_from(child)?, op, root_dev)?;
                }
                EntryKind::Symlink => {
                    if let WalkOp::Chown { uid, gid } = op {
                        fchownat(
                            Some(dirfd),
                            name,
                            Some(Uid::from_raw(uid)),
                            Some(Gid::from_raw(gid)),
                            AtFlags::AT_SYMLINK_NOFOLLOW,
                        )
                        .map_err(|e| {
                            Error::Io(std::io::Error::other(format!(
                                "lchown dir entry {:?}: {e}",
                                name
                            )))
                        })?;
                    }
                    // chmod 不触碰 symlink（kernel 也不支持改 symlink 本身的 mode）。
                }
                EntryKind::File => match op {
                    WalkOp::Chown { uid, gid } => fchownat(
                        Some(dirfd),
                        name,
                        Some(Uid::from_raw(uid)),
                        Some(Gid::from_raw(gid)),
                        AtFlags::AT_SYMLINK_NOFOLLOW,
                    )
                    .map_err(|e| {
                        Error::Io(std::io::Error::other(format!(
                            "lchown dir entry {:?}: {e}",
                            name
                        )))
                    })?,
                    WalkOp::Chmod { mode } => {
                        // 文件只保留 owner/group rw，不设 setgid/execute。
                        fchmodat(
                            Some(dirfd),
                            name,
                            Mode::from_bits_truncate((mode & 0o666) as nix::libc::mode_t),
                            FchmodatFlags::NoFollowSymlink,
                        )
                        .map_err(|e| {
                            Error::Io(std::io::Error::other(format!(
                                "fchmodat dir entry {:?}: {e}",
                                name
                            )))
                        })?;
                    }
                },
            }
        }
        Ok(())
    }

    /// `walk_remove` 递归深度上限（相对 rm-rf 根层数，根为 0）。64 ≈ 最深合法
    /// 布局（dnf installroot ~15 层、rpmbuild BUILD/BUILDROOT vendored 源码树
    /// ~30 层）× 2 余量；兼约束递归资源（每层 1 目录 fd，64 << RLIMIT_NOFILE
    /// 1024；1 小栈帧远低于栈溢出阈）。超限视为对抗性超深树，fail-closed 拒绝并审计。
    pub(super) const WALK_REMOVE_MAX_DEPTH: u32 = 64;

    /// 后序遍历删除：子目录先递归清空再 rmdir，文件/symlink 直接 unlink；
    /// 条目消失（ENOENT）容错跳过，其余错误 fail-closed。`depth` 相对根层数
    ///（根为 0），超 [`WALK_REMOVE_MAX_DEPTH`] 的下降被拒绝（见其文档）。
    fn walk_remove(dir: Dir, root_dev: u64, depth: u32) -> Result<(), Error> {
        let mut dir = dir;
        let dirfd = dir.as_raw_fd();
        for entry in dir.iter() {
            let entry = entry
                .map_err(|e| Error::Io(std::io::Error::other(format!("read dir entry: {e}"))))?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            let kind = match classify(dirfd, &entry) {
                Ok(k) => k,
                Err(e) => {
                    // classify 仅在 fstatat 兜底路径报错；区分条目消失与真实错误。
                    match fstatat(Some(dirfd), name, AtFlags::AT_SYMLINK_NOFOLLOW) {
                        Err(Errno::ENOENT) => {
                            tracing::warn!(entry = ?name, "skip entry vanished during recursive remove");
                            continue;
                        }
                        _ => return Err(e),
                    }
                }
            };
            match kind {
                EntryKind::Dir => match openat(Some(dirfd), name, OPEN_FLAGS, Mode::empty()) {
                    Ok(fd) => {
                        let child = unsafe { OwnedFd::from_raw_fd(fd) };
                        // 挂载点边界：st_dev 不同不得穿透（会删到 bind 进来的宿主子树）；
                        // 挂载点拆卸留给 umount / gc-orphan-mounts。
                        if crate::ops::crosses_mount(root_dev, fd_dev(child.as_raw_fd())?) {
                            tracing::warn!(entry = ?name, "skip mountpoint during recursive remove");
                            continue;
                        }
                        // 深度熔断：对抗性超深树（栈溢出/EMFILE DoS），fail-closed
                        // 拒绝整次删除并审计；挂载点跳过在前，不影响深度判定。
                        if depth >= WALK_REMOVE_MAX_DEPTH {
                            tracing::error!(
                                entry = ?name,
                                depth,
                                limit = WALK_REMOVE_MAX_DEPTH,
                                "refusing descent: directory tree exceeds depth limit during recursive remove"
                            );
                            return Err(Error::Validation(format!(
                                "rm -rf: directory {name:?} exceeds max depth {WALK_REMOVE_MAX_DEPTH}"
                            )));
                        }
                        walk_remove(dir_from(child)?, root_dev, depth + 1)?;
                        remove_entry(dirfd, name, UnlinkatFlags::RemoveDir)?;
                    }
                    Err(Errno::ENOENT) => continue,
                    Err(e @ (Errno::ELOOP | Errno::ENOTDIR)) => {
                        // 判定到打开之间被换成 symlink/文件：按非目录删除（不跟随）。
                        tracing::warn!(entry = ?name, errno = %e, "entry replaced by non-directory during recursive remove");
                        remove_entry(dirfd, name, UnlinkatFlags::NoRemoveDir)?;
                    }
                    Err(e) => {
                        return Err(Error::Io(std::io::Error::other(format!(
                            "open dir entry {name:?}: {e}"
                        ))))
                    }
                },
                EntryKind::Symlink | EntryKind::File => {
                    remove_entry(dirfd, name, UnlinkatFlags::NoRemoveDir)?;
                }
            }
        }
        Ok(())
    }

    /// 删除单个条目；条目已消失（ENOENT）视为成功（幂等，与 rm -rf 语义一致）。
    fn remove_entry(
        dirfd: RawFd,
        name: &std::ffi::CStr,
        flags: UnlinkatFlags,
    ) -> Result<(), Error> {
        match unlinkat(Some(dirfd), name, flags) {
            Ok(()) | Err(Errno::ENOENT) => Ok(()),
            Err(e) => Err(Error::Io(std::io::Error::other(format!(
                "unlink dir entry {name:?}: {e}"
            )))),
        }
    }
}

/// 修改属主为 uid:gid；recursive 时遍历目录树，否则仅叶子（lchown 语义）。
pub fn chown(path: &Path, uid: u32, gid: u32, recursive: bool) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        if recursive {
            fs_walk::chown_recursive(path, uid, gid)?;
        } else {
            fs_walk::chown_leaf(path, uid, gid)?;
        }
        tracing::debug!(path = %path.display(), uid = %uid, gid = %gid, recursive = %recursive, "chown done");
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, uid, gid, recursive);
        Err(Error::Unsupported("chown is Linux only".into()))
    }
}

/// 修改权限为 mode；recursive 时遍历目录树，否则仅叶子。
pub fn chmod(path: &Path, mode: u32, recursive: bool) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        if recursive {
            fs_walk::chmod_recursive(path, mode)?;
        } else {
            fs_walk::chmod_leaf(path, mode)?;
        }
        tracing::debug!(path = %path.display(), mode = %format!("{:04o}", mode), recursive = %recursive, "chmod done");
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, mode, recursive);
        Err(Error::Unsupported("chmod is Linux only".into()))
    }
}

/// 原子写文件：锚定父目录 fd 建临时文件，写内容、设属主权限后 rename 到位
/// （mode 缺省 0660，应用前剥 setid 位，见 [`strip_file_setid_bits`]）。
pub fn write_file(
    path: &Path,
    content: &[u8],
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        use std::io::Write;
        use std::os::unix::io::AsRawFd;

        use nix::sys::stat::{fchmod, Mode};
        use nix::unistd::{fchown, Gid, Uid};

        // 父目录受信锚点逐组件解析（缺失补建、symlink fail-closed），tempfile 与
        // rename 只锚定该 fd（/proc/self/fd/<fd>/），不经原始路径重解析（否则 TOCTOU 重开）。
        let (parent, leaf) = fs_walk::parent_for_write(path)?;
        let dir = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd()));

        let tmp = tempfile::NamedTempFile::new_in(&dir).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "create temp file for {}: {e}",
                path.display()
            )))
        })?;

        tmp.as_file().write_all(content).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "write temp file {}: {e}",
                tmp.path().display()
            )))
        })?;

        // mode 缺省 0660 而非 tempfile 0600：三身份可读写不变量；显式 mode 下方剥 setid。
        let mode = mode.unwrap_or(0o660);
        // 漏洞 3：剥 suid/sgid——不可信调用方（crbs 组）铸 setid-root 文件即提权。
        let stripped = strip_file_setid_bits(mode);
        let file_mode = Mode::from_bits_truncate(stripped as nix::libc::mode_t);
        fchmod(tmp.as_file().as_raw_fd(), file_mode).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "fchmod temp file {}: {e}",
                tmp.path().display()
            )))
        })?;

        if uid.is_some() || gid.is_some() {
            fchown(
                tmp.as_file().as_raw_fd(),
                uid.map(Uid::from_raw),
                gid.map(Gid::from_raw),
            )
            .map_err(|e| {
                Error::Io(std::io::Error::other(format!(
                    "fchown temp file {}: {e}",
                    tmp.path().display()
                )))
            })?;
        }

        // rename 原子替换目标（文件/symlink 均替换本身），禁先删——remove 成功
        // 而 rename 失败即丢原文件；非空目录报错；目标锚定父 fd（procfs fd symlink 不可置换）。
        let target = dir.join(leaf);
        tmp.persist(&target).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "rename temp file to {}: {e}",
                path.display()
            )))
        })?;

        tracing::debug!(
            path = %path.display(),
            size = content.len(),
            mode = ?Some(format!("{:04o}", mode)),
            uid = ?uid,
            gid = ?gid,
            "write file done"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, content, mode, uid, gid);
        Err(Error::Unsupported("write-file is Linux only".into()))
    }
}

/// 写入 cgroup v2 控制文件（memory.max / cpu.max / cgroup.kill 等）。不走
/// temp+rename（cgroupfs 不支持 rename，EINVAL），直接 write(2)；调用方
///（main.rs）已断言严格位于 /sys/fs/cgroup/machine.slice 之下 + 文件名白名单；kernfs 组件不可被普通用户替换，无 symlink 面。
pub fn write_cgroup_file(path: &Path, content: &str) -> Result<(), Error> {
    std::fs::write(path, content.as_bytes()).map_err(|e| {
        Error::Io(std::io::Error::other(format!(
            "write {}: {e}",
            path.display()
        )))
    })
}

/// 解码 mountinfo 字段的八进制转义（`\040` 空格、`\011`、`\012`、`\134` 反斜杠）；不合法 `\` 序列原样保留。
#[cfg(target_os = "linux")]
fn decode_mountinfo_field(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..=i + 3].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 容器伪文件系统白名单（tmp 扫描域判定用）：与 crbs-core `engine::orphan`
/// 集合一致，只命中构建环境挂载类型，不殃及同机第三方在共享 tmp 的挂载。
pub const GC_TMP_CONTAINER_FSTYPES: &[&str] = &["overlay", "proc", "sysfs", "tmpfs", "devpts"];

/// gc-orphan-mounts 扫描域判定（纯函数，跨平台可测）：规范化挂载点 `canon`
/// 是否在扫描域内。crbs_root 域：严格在其之下（本身不算），整域私有数据全量
/// 扫描。tmp 域：tmp 目录下首级子目录以 `.tmp` 开头（tempfile 形态）且 fstype
/// 属容器伪 fs——tmp（/var/tmp、/dev/shm）是共享系统目录，不收紧会懒卸载同机
/// 第三方挂载（对齐 engine::orphan::mount_line_is_crbs_related 规则 3，含误判面）。
pub fn mount_in_gc_scan_domain(
    canon: &Path,
    fstype: &str,
    crbs_root: &Path,
    tmp_roots: &[PathBuf],
) -> bool {
    if canon != crbs_root && canon.starts_with(crbs_root) {
        return true;
    }
    tmp_roots.iter().any(|tmp| {
        // strip_prefix 按组件剥 tmp 根：canon == tmp 时 rest 空 → 不命中（GC 永不作用于 tmp 根）；首级组件 .tmp 前缀即 tempfile 形态。
        let under_tmp_dot = canon.strip_prefix(tmp).is_ok_and(|rest| {
            rest.components()
                .next()
                .is_some_and(|c| c.as_os_str().to_string_lossy().starts_with(".tmp"))
        });
        under_tmp_dot && GC_TMP_CONTAINER_FSTYPES.contains(&fstype)
    })
}

/// 清扫 crbs_root 与可选临时目录扫描域下崩溃残留的孤儿挂载点（扫描
/// /proc/self/mountinfo），全部 MNT_DETACH 懒卸载，不删目录体。`tmp_dirs`
/// 是 engine 的 tmp_dir/tmpfs_dir——overlay 目标在 `{tmp_dir}/.tmpXXXX/root`，
/// 全内存构建另在 `.tmpXXXX/memroot/root`，崩溃残留最常见于此而非 crbs_root 下；
/// tmp 域命中规则见 [`mount_in_gc_scan_domain`]。
pub fn gc_orphan_mounts(crbs_root: &Path, tmp_dirs: &[PathBuf]) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        // mountinfo 格式：id parent maj:min root mount_point options ... - fs_type source options；
        // mount_point = 字段 5（索引 4），fs_type 在 "-" 分隔符之后。
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("read mountinfo: {e}"),
            ))
        })?;

        // canonicalize 解析 symlink 后比较；MNT_DETACH 懒卸载避免 busy（对齐 core setuid 后端）。
        let canonical_root = fs::canonicalize(crbs_root).map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("canonicalize {}: {e}", crbs_root.display()),
            ))
        })?;
        // tmp 扫描根逐个规范化；不存在的目录 warn 跳过——漏扫不是错误。
        let mut canonical_tmps = Vec::with_capacity(tmp_dirs.len());
        for tmp in tmp_dirs {
            match fs::canonicalize(tmp) {
                Ok(p) => canonical_tmps.push(p),
                Err(e) => {
                    tracing::warn!(
                        tmp_dir = %tmp.display(),
                        error = %e,
                        "gc tmp scan dir not canonicalizable, skipping"
                    );
                }
            }
        }
        let mut to_umount = Vec::new();

        for line in mountinfo.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }
            let mp = decode_mountinfo_field(parts[4]);
            // 畸形行（缺 "-" 分隔符）跳过：tmp 域判定依赖 fstype，不能当空串放行。
            let Some(sep) = parts.iter().position(|p| *p == "-") else {
                continue;
            };
            let Some(fstype) = parts.get(sep + 1) else {
                continue;
            };
            if let Ok(canon) = fs::canonicalize(&mp) {
                if mount_in_gc_scan_domain(&canon, fstype, &canonical_root, &canonical_tmps) {
                    to_umount.push(canon);
                }
            }
        }

        // 深层优先卸载（与 setuid 后端一致）。
        to_umount.sort_by_key(|p| p.components().count());
        to_umount.reverse();
        to_umount.dedup();

        let total = to_umount.len();
        let mut failed = 0usize;
        for mp in &to_umount {
            if let Err(e) = nix::mount::umount2(mp, nix::mount::MntFlags::MNT_DETACH) {
                tracing::warn!(mountpoint = %mp.display(), error = %e, "failed to umount orphan");
                failed += 1;
            } else {
                tracing::debug!(mountpoint = %mp.display(), "unmounted orphan");
            }
        }

        tracing::info!(
            removed = %total.saturating_sub(failed),
            failed = %failed,
            crbs_root = %canonical_root.display(),
            tmp_dirs = %canonical_tmps.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(","),
            "gc orphan mounts done"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (crbs_root, tmp_dirs);
        Err(Error::Unsupported("gc-orphan-mounts is Linux only".into()))
    }
}

/// 递归删除一个或多个路径（文件或目录）：走 `fs_walk` fd 相对遍历（根逐组件
/// 解析、TOCTOU 防护与删除语义见 `fs_walk::remove_recursive`）；路径不存在
/// no-op，遍历期间条目消失（ENOENT）容错跳过。
pub fn rm_rf(paths: &[PathBuf]) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        for p in paths {
            fs_walk::remove_recursive(p)?;
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = paths;
        Err(Error::Unsupported("rm-rf is Linux only".into()))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &Path) -> std::io::Result<u32> {
        Ok(std::fs::metadata(path)?.permissions().mode() & 0o777)
    }

    #[test]
    fn write_file_creates_parent_and_writes_content() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sub/dir/file.txt");
        write_file(&path, b"hello", None, None, None).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello");
    }

    #[test]
    fn write_file_applies_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("file.txt");
        write_file(&path, b"x", Some(0o640), None, None).unwrap();
        assert_eq!(mode_of(&path).unwrap(), 0o640);
    }

    #[test]
    fn write_file_replaces_existing_symlink_without_touching_target() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        std::fs::write(&target, "old").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        write_file(&link, b"new", None, None, None).unwrap();

        assert_eq!(std::fs::read_to_string(&link).unwrap(), "new");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "old");
        assert!(!std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn write_file_replaces_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("file");
        std::fs::write(&target, "old-content").unwrap();

        write_file(&target, b"new-content", Some(0o600), None, None).unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new-content");
        assert_eq!(mode_of(&target).unwrap(), 0o600);
    }

    #[test]
    fn write_file_onto_directory_fails_and_keeps_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("dir");
        std::fs::create_dir_all(dir.join("sub")).unwrap();

        // rename 无法替换非空目录：必须报错且原目录原样保留。
        let res = write_file(&dir, b"x", None, None, None);
        assert!(res.is_err());
        assert!(dir.join("sub").exists());
    }

    #[test]
    fn write_file_rejects_path_without_parent() {
        let res = write_file(Path::new("/"), b"x", None, None, None);
        assert!(matches!(res, Err(Error::Validation(_))));
    }

    #[test]
    fn write_file_intermediate_symlink_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        // 树外受害目录：若跟随中间 symlink，受害文件会被替换。
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("f");
        fs::write(&victim, b"secret").unwrap();

        let parent = tmp.path().join("parent");
        fs::create_dir_all(&parent).unwrap();
        std::os::unix::fs::symlink(&outside, parent.join("link")).unwrap();
        let target = parent.join("link").join("f");

        assert!(write_file(&target, b"evil", None, None, None).is_err());
        // 树外受害内容原样保留，报错发生在解析中间组件时，symlink 也不被动。
        assert_eq!(fs::read_to_string(&victim).unwrap(), "secret");
        assert!(parent.join("link").symlink_metadata().is_ok());
    }

    #[test]
    fn write_file_dotdot_leaf_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let keep = tmp.path().join("keep");
        fs::create_dir_all(&keep).unwrap();

        // 叶子 ".."（validate 归一化后可放行）：必须拒绝，不得落到祖先目录。
        let res = write_file(&keep.join(".."), b"x", None, None, None);
        assert!(matches!(res, Err(Error::Validation(_))));
    }

    #[test]
    fn chmod_sets_file_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("f");
        std::fs::write(&path, "x").unwrap();
        chmod(&path, 0o600, false).unwrap();
        assert_eq!(mode_of(&path).unwrap(), 0o600);
    }

    #[test]
    fn chmod_intermediate_symlink_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        // 树外受害文件：若 chmod 跟随中间 symlink，其 mode 会被改写。
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("f");
        fs::write(&victim, b"x").unwrap();
        fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();

        let parent = tmp.path().join("parent");
        fs::create_dir_all(&parent).unwrap();
        std::os::unix::fs::symlink(&outside, parent.join("link")).unwrap();
        let target = parent.join("link").join("f");

        assert!(chmod(&target, 0o777, false).is_err());
        assert_eq!(mode_of(&victim).unwrap(), 0o600);
        assert!(parent.join("link").symlink_metadata().is_ok());
    }

    #[test]
    fn chmod_recursive_intermediate_symlink_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("f");
        fs::write(&victim, b"x").unwrap();
        fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();

        let parent = tmp.path().join("parent");
        fs::create_dir_all(&parent).unwrap();
        std::os::unix::fs::symlink(&outside, parent.join("link")).unwrap();
        let target = parent.join("link").join("f");

        // 递归变体同样在解析中间组件时 fail-closed，不进入树外目录。
        assert!(chmod(&target, 0o777, true).is_err());
        assert_eq!(mode_of(&victim).unwrap(), 0o600);
        assert!(parent.join("link").symlink_metadata().is_ok());
    }

    #[test]
    fn chmod_recursive_masks_files_but_preserves_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("f");
        std::fs::write(&file, "x").unwrap();

        chmod(&dir, 0o777, true).unwrap();

        assert_eq!(mode_of(&file).unwrap(), 0o666);
        assert_eq!(mode_of(&dir).unwrap(), 0o777);
    }

    #[test]
    fn chmod_recursive_skips_symlink_target() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        std::fs::write(&target, "x").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();

        let dir = tmp.path().join("d");
        std::fs::create_dir(&dir).unwrap();
        std::os::unix::fs::symlink(&target, dir.join("link")).unwrap();

        chmod(&dir, 0o777, true).unwrap();

        assert_eq!(mode_of(&target).unwrap(), 0o600);
    }

    #[test]
    fn chmod_recursive_does_not_descend_into_symlinked_subdir() {
        let tmp = tempfile::tempdir().unwrap();
        // 树外目录：若递归跟随 symlink 子目录，其中文件会被改 mode。
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let outside_file = outside.join("f");
        std::fs::write(&outside_file, "x").unwrap();
        std::fs::set_permissions(&outside_file, std::fs::Permissions::from_mode(0o600)).unwrap();

        let dir = tmp.path().join("d");
        std::fs::create_dir(&dir).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("sub")).unwrap();

        chmod(&dir, 0o777, true).unwrap();

        assert_eq!(mode_of(&outside_file).unwrap(), 0o600);
        assert_eq!(mode_of(&dir).unwrap(), 0o777);
    }

    #[test]
    fn chmod_recursive_on_regular_file_still_applies_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("f");
        std::fs::write(&file, "x").unwrap();

        // 递归 chmod 作用于普通文件：退化为单文件 chmod。
        chmod(&file, 0o640, true).unwrap();
        assert_eq!(mode_of(&file).unwrap(), 0o640);
    }

    #[test]
    fn chown_recursive_happy_path_to_current_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/f"), "x").unwrap();
        std::os::unix::fs::symlink("sub/f", dir.join("link")).unwrap();

        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        chown(&dir, uid, gid, true).unwrap();
    }

    #[test]
    fn chown_recursive_rejects_symlink_path() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("d");
        std::fs::create_dir(&target).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        // 根是 symlink：递归拒绝。
        assert!(chown(&link, uid, gid, true).is_err());
        // 非递归作用于 link 本身（lchown 语义）。
        chown(&link, uid, gid, false).unwrap();
    }

    #[test]
    fn chown_intermediate_symlink_rejected() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();
        // 树外受害文件：若 chown 跟随中间 symlink，其属主会被改写。
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("f");
        fs::write(&victim, b"x").unwrap();
        let before = fs::metadata(&victim).unwrap();

        let parent = tmp.path().join("parent");
        fs::create_dir_all(&parent).unwrap();
        std::os::unix::fs::symlink(&outside, parent.join("link")).unwrap();
        let target = parent.join("link").join("f");

        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        assert!(chown(&target, uid, gid, false).is_err());
        let after = fs::metadata(&victim).unwrap();
        assert_eq!((before.uid(), before.gid()), (after.uid(), after.gid()));
        assert!(parent.join("link").symlink_metadata().is_ok());
    }

    #[test]
    fn chown_recursive_intermediate_symlink_rejected() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("f");
        fs::write(&victim, b"x").unwrap();
        let before = fs::metadata(&victim).unwrap();

        let parent = tmp.path().join("parent");
        fs::create_dir_all(&parent).unwrap();
        std::os::unix::fs::symlink(&outside, parent.join("link")).unwrap();
        let target = parent.join("link").join("f");

        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        assert!(chown(&target, uid, gid, true).is_err());
        let after = fs::metadata(&victim).unwrap();
        assert_eq!((before.uid(), before.gid()), (after.uid(), after.gid()));
        assert!(parent.join("link").symlink_metadata().is_ok());
    }

    #[test]
    fn chown_chmod_missing_intermediate_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let ghost = tmp.path().join("no-such-dir").join("f");
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        // 对象必须已存在：中间组件缺失报错（rm -rf 的 no-op 语义不适用）。
        assert!(chown(&ghost, uid, gid, false).is_err());
        assert!(chown(&ghost, uid, gid, true).is_err());
        assert!(chmod(&ghost, 0o600, false).is_err());
        assert!(chmod(&ghost, 0o600, true).is_err());
    }

    /// 当前进程的 user/group 名（chown 到自身，非 root 环境可行）。
    // 辅助函数不在 allow-unwrap-in-tests 豁免范围，就地放行（见根 clippy.toml）。
    #[allow(clippy::unwrap_used)]
    fn current_user_and_group() -> (String, String) {
        let user = nix::unistd::User::from_uid(nix::unistd::getuid())
            .unwrap()
            .unwrap()
            .name;
        let group = nix::unistd::Group::from_gid(nix::unistd::getgid())
            .unwrap()
            .unwrap()
            .name;
        (user, group)
    }

    #[test]
    fn mkdir_chown_creates_nested_dirs_with_owner_and_mode() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("a").join("b").join("c");
        let (user, group) = current_user_and_group();

        mkdir_chown(&target, &user, &group, 0o2770).unwrap();

        assert!(tmp.path().join("a").join("b").is_dir());
        let meta = fs::metadata(&target).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o2770, "0o2770 must land as-is");
        assert_eq!(meta.uid(), nix::unistd::getuid().as_raw());
        assert_eq!(meta.gid(), nix::unistd::getgid().as_raw());
    }

    #[test]
    fn mkdir_chown_idempotent_on_existing_dir_and_strips_suid() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("existing");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"data").unwrap();
        let (user, group) = current_user_and_group();

        // mkdir -p 幂等：已有目录内容保留；0o6770 剥 SUID 保 SGID → 0o2770。
        mkdir_chown(&target, &user, &group, 0o6770).unwrap();

        assert_eq!(fs::read_to_string(target.join("keep")).unwrap(), "data");
        let meta = fs::metadata(&target).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o2770);
    }

    #[test]
    fn mkdir_chown_intermediate_symlink_rejected() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();
        // 树外受害目录：若跟随中间 symlink，属主/权限会被改写。
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("f");
        fs::write(&victim, b"secret").unwrap();
        let before = fs::metadata(&victim).unwrap();

        let parent = tmp.path().join("parent");
        fs::create_dir_all(&parent).unwrap();
        std::os::unix::fs::symlink(&outside, parent.join("link")).unwrap();
        let target = parent.join("link").join("newdir");
        let (user, group) = current_user_and_group();

        let res = mkdir_chown(&target, &user, &group, 0o2770);
        assert!(res.is_err());
        // 树外受害目录原样保留（无新建、无属主/权限变化），symlink 不被动。
        assert!(!outside.join("newdir").exists());
        let after = fs::metadata(&victim).unwrap();
        assert_eq!((before.uid(), before.gid()), (after.uid(), after.gid()));
        assert_eq!(before.mode(), after.mode());
        assert!(parent.join("link").symlink_metadata().is_ok());
    }

    #[test]
    fn mkdir_chown_symlink_leaf_rejected_without_side_effect() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real-dir");
        fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let (user, group) = current_user_and_group();
        let real_meta_before = fs::metadata(&real).unwrap();

        // 叶子是 symlink：无副作用 fail-closed 拒绝（该形态本被 validate 挡在门外）。
        assert!(mkdir_chown(&link, &user, &group, 0o2770).is_err());
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        let real_meta_after = fs::metadata(&real).unwrap();
        assert_eq!(real_meta_before.mode(), real_meta_after.mode());
        assert_eq!(real_meta_before.uid(), real_meta_after.uid());
        assert_eq!(real_meta_before.gid(), real_meta_after.gid());
    }

    #[test]
    fn mkdir_chown_existing_file_leaf_rejected_as_already_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("a-file");
        fs::write(&target, b"content").unwrap();
        let (user, group) = current_user_and_group();

        // 叶子是普通文件：对齐 create_dir_all AlreadyExists 分类，内容保留。
        let res = mkdir_chown(&target, &user, &group, 0o2770);
        assert!(
            matches!(res, Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::AlreadyExists),
            "unexpected: {res:?}"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "content");
    }

    #[test]
    fn mkdir_chown_refuses_filesystem_root() {
        let (user, group) = current_user_and_group();
        // "/" 没有可操作的叶子名字：直接拒绝（不得退化为对根目录 chown/chmod）。
        let res = mkdir_chown(Path::new("/"), &user, &group, 0o2770);
        assert!(
            matches!(res, Err(Error::Validation(_))),
            "unexpected: {res:?}"
        );
    }

    #[test]
    fn decode_mountinfo_field_unescapes_octal_sequences() {
        assert_eq!(decode_mountinfo_field("/var/lib/crbs"), "/var/lib/crbs");
        assert_eq!(
            decode_mountinfo_field("/var/lib/crbs/with\\040space"),
            "/var/lib/crbs/with space"
        );
        assert_eq!(decode_mountinfo_field("/x\\011\\012\\134y"), "/x\t\n\\y");
        // 不完整的转义序列原样保留
        assert_eq!(decode_mountinfo_field("/x\\04y"), "/x\\04y");
        assert_eq!(decode_mountinfo_field("/x\\"), "/x\\");
    }

    #[test]
    fn mount_overlay_rejects_empty_lower() {
        let tmp = tempfile::tempdir().unwrap();
        let upper = tmp.path().join("upper");
        let work = tmp.path().join("work");
        let target = tmp.path().join("target");
        let res = mount_overlay(&[], &upper, &work, &target);
        assert!(matches!(res, Err(Error::Validation(_))));
    }

    #[test]
    fn mount_overlay_rejects_option_injection_chars() {
        let tmp = tempfile::tempdir().unwrap();
        let upper = tmp.path().join("upper");
        let work = tmp.path().join("work");
        let target = tmp.path().join("target");

        // lower 含逗号：可注入 upperdir= 等新选项
        let evil_lower = tmp.path().join("lo,upperdir=/etc");
        let res = mount_overlay(&[evil_lower], &upper, &work, &target);
        assert!(matches!(res, Err(Error::Validation(_))));

        // lower 含冒号：会被拆成两个 lower
        let colon_lower = tmp.path().join("lo:win");
        let res = mount_overlay(&[colon_lower], &upper, &work, &target);
        assert!(matches!(res, Err(Error::Validation(_))));

        let evil_upper = tmp.path().join("up,metacopy=on");
        let res = mount_overlay(&[tmp.path().join("lo")], &evil_upper, &work, &target);
        assert!(matches!(res, Err(Error::Validation(_))));
    }

    #[test]
    fn rm_rf_nonexistent_path_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let ghost = tmp.path().join("does-not-exist");
        assert!(rm_rf(&[ghost]).is_ok());
    }

    #[test]
    fn rm_rf_removes_dir_and_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("victim-dir");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("inside"), b"data").unwrap();
        let file = tmp.path().join("victim-file");
        fs::write(&file, b"x").unwrap();

        assert!(rm_rf(&[dir.clone(), file.clone()]).is_ok());
        assert!(!dir.exists());
        assert!(!file.exists());
    }

    #[test]
    fn rm_rf_empty_path_list_is_ok() {
        let res: Result<(), Error> = rm_rf(&[]);
        assert!(res.is_ok());
    }

    #[test]
    fn rm_rf_root_symlink_removes_link_not_target() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target-dir");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("keep"), b"data").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(rm_rf(std::slice::from_ref(&link)).is_ok());
        assert!(link.symlink_metadata().is_err());
        assert!(target.join("keep").exists());
    }

    #[test]
    fn rm_rf_symlink_inside_tree_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep"), b"data").unwrap();
        let tree = tmp.path().join("tree");
        fs::create_dir_all(tree.join("sub")).unwrap();
        fs::write(tree.join("sub").join("f"), b"x").unwrap();
        // 指向树外目录与树外文件的 symlink：必须删 link 本身，不得跟随。
        std::os::unix::fs::symlink(&outside, tree.join("sub").join("escape-dir")).unwrap();
        std::os::unix::fs::symlink(outside.join("keep"), tree.join("escape-file")).unwrap();

        assert!(rm_rf(std::slice::from_ref(&tree)).is_ok());
        assert!(!tree.exists());
        assert!(outside.join("keep").exists());
    }

    #[test]
    fn rm_rf_deep_nesting() {
        let tmp = tempfile::tempdir().unwrap();
        let deep = tmp.path().join("a").join("b").join("c").join("d");
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("leaf"), b"x").unwrap();
        let root = tmp.path().join("a");

        assert!(rm_rf(std::slice::from_ref(&root)).is_ok());
        assert!(!root.exists());
    }

    /// 计算 root 下 n 层嵌套目录链路径（纯计算；建链 IO 在 #[test] 体内做——辅助函数不在 allow-unwrap-in-tests 豁免）。
    fn nested_chain_path(root: &Path, levels: usize) -> PathBuf {
        let mut chain = root.to_path_buf();
        for i in 0..levels {
            chain.push(format!("d{i}"));
        }
        chain
    }

    #[test]
    fn rm_rf_tree_exceeding_depth_limit_refused_and_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        // 超深链：对抗性超深树 fail-closed 拒绝（Validation），不得半途删上层。
        let chain = nested_chain_path(&root, (fs_walk::WALK_REMOVE_MAX_DEPTH + 6) as usize);
        fs::create_dir_all(&chain).unwrap();
        fs::write(chain.join("leaf"), b"x").unwrap();

        let res = rm_rf(std::slice::from_ref(&root));
        assert!(
            matches!(res, Err(Error::Validation(ref msg))
                if msg.contains("max depth")),
            "unexpected: {res:?}"
        );
        // 后序删除在下降阶段即被熔断：根与整条链（含叶子）原样保留。
        assert!(root.exists());
        assert!(chain.join("leaf").exists());
    }

    #[test]
    fn rm_rf_tree_at_depth_limit_fully_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        // 恰好上限层：完整删除不熔断（上限为合法布局 ~30 层的 2 倍余量）。
        let chain = nested_chain_path(&root, fs_walk::WALK_REMOVE_MAX_DEPTH as usize);
        fs::create_dir_all(&chain).unwrap();
        fs::write(chain.join("leaf"), b"x").unwrap();

        assert!(rm_rf(std::slice::from_ref(&root)).is_ok());
        assert!(!root.exists());
    }

    #[test]
    fn rm_rf_dangling_symlink_is_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let link = tmp.path().join("dangling");
        std::os::unix::fs::symlink(tmp.path().join("no-such-target"), &link).unwrap();

        assert!(rm_rf(std::slice::from_ref(&link)).is_ok());
        assert!(link.symlink_metadata().is_err());
    }

    #[test]
    fn rm_rf_intermediate_symlink_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        // 树外目录经中间 symlink 真实存在：若跟随中间组件，其内容会被清空。
        let outside = tmp.path().join("outside");
        fs::create_dir_all(outside.join("victim")).unwrap();
        fs::write(outside.join("victim").join("f"), b"x").unwrap();
        fs::write(outside.join("keep"), b"data").unwrap();

        let parent = tmp.path().join("parent");
        fs::create_dir_all(&parent).unwrap();
        std::os::unix::fs::symlink(&outside, parent.join("link")).unwrap();
        let victim = parent.join("link").join("victim");

        assert!(rm_rf(std::slice::from_ref(&victim)).is_err());
        assert!(outside.join("victim").join("f").exists());
        assert!(outside.join("keep").exists());
        // 报错发生在打开中间组件时，symlink 本身也不被误删。
        assert!(parent.join("link").symlink_metadata().is_ok());
    }

    #[test]
    fn rm_rf_missing_intermediate_dir_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let ghost = tmp.path().join("no-such-dir").join("child");
        assert!(rm_rf(&[ghost]).is_ok());
    }

    #[test]
    fn rm_rf_dotdot_leaf_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let keep = tmp.path().join("keep");
        fs::create_dir_all(&keep).unwrap();
        fs::write(keep.join("f"), b"x").unwrap();
        let x = tmp.path().join("x");
        fs::create_dir_all(&x).unwrap();

        // 叶子 ".."（validate 归一化后可放行）：直接拒绝，不删任何东西。
        assert!(rm_rf(std::slice::from_ref(&x.join(".."))).is_err());
        assert!(keep.join("f").exists());
    }

    // ── terminate-machine 的 scope 目录候选 ──────────────────────

    /// 候选表 = v2 统一根 + v1 legacy systemd 根 × 双命名 × 原样/转义，共 8 条、
    /// 顺序与 crbs-core nspawn cgroup.rs 的 `scope_path_candidates` 手抄同步。
    /// v1 宿主层级挂 /sys/fs/cgroup/systemd，缺该前缀探测必落空。
    #[test]
    fn machine_scope_cgroup_dirs_cover_roots_namings_and_escaping() {
        let name = "crbs-1b033e1a-27";
        let dirs = machine_scope_cgroup_dirs(name);
        let expect: Vec<String> = [
            "/sys/fs/cgroup/machine.slice",
            "/sys/fs/cgroup/systemd/machine.slice",
        ]
        .iter()
        .flat_map(|root| {
            [
                format!("{root}/{name}.scope"),
                format!("{root}/crbs\\x2d1b033e1a\\x2d27.scope"),
                format!("{root}/machine-{name}.scope"),
                format!("{root}/machine-crbs\\x2d1b033e1a\\x2d27.scope"),
            ]
        })
        .collect();
        assert_eq!(dirs.len(), 8);
        for (got, want) in dirs.iter().zip(expect.iter()) {
            assert_eq!(got, Path::new(want), "candidate order/content mismatch");
        }
    }

    /// 纯数字段名与 uuid 形态（多 `-`）同样双形态齐全，转义逐 `-` 替换。
    #[test]
    fn machine_scope_cgroup_dirs_escaping_for_digit_and_uuid_names() {
        for name in ["crbs-01234567", "crbs-9c714595-1b03-4e5f-8d2a-abcdef012345"] {
            let dirs = machine_scope_cgroup_dirs(name);
            assert_eq!(dirs.len(), 8);
            let escaped = name.replace('-', "\\x2d");
            // 任一根下四种命名形态齐备（原样 + 转义 × 有无 machine- 前缀）。
            for root in [
                "/sys/fs/cgroup/machine.slice",
                "/sys/fs/cgroup/systemd/machine.slice",
            ] {
                for want in [
                    format!("{name}.scope"),
                    format!("{escaped}.scope"),
                    format!("machine-{name}.scope"),
                    format!("machine-{escaped}.scope"),
                ] {
                    assert!(
                        dirs.contains(&PathBuf::from(format!("{root}/{want}"))),
                        "missing candidate {root}/{want}"
                    );
                }
            }
        }
    }
}

/// gc 扫描域判定单测（纯函数跨平台）：ops 既有测试模组 Linux-only，单开全平台模组使 macOS 也能跑。
#[cfg(test)]
mod gc_scan_domain_tests {
    use super::mount_in_gc_scan_domain;

    fn domain(crbs_root: &str, tmps: &[&str]) -> (std::path::PathBuf, Vec<std::path::PathBuf>) {
        (
            std::path::PathBuf::from(crbs_root),
            tmps.iter().map(std::path::PathBuf::from).collect(),
        )
    }

    #[test]
    fn crbs_root_domain_keeps_full_scan() {
        let (root, tmps) = domain("/var/lib/crbs", &[]);
        // 严格之下命中（含深路径）；crbs_root 本身不算（既有口径）。
        assert!(mount_in_gc_scan_domain(
            "/var/lib/crbs/products/x/root".as_ref(),
            "overlay",
            &root,
            &tmps
        ));
        assert!(!mount_in_gc_scan_domain(
            "/var/lib/crbs".as_ref(),
            "overlay",
            &root,
            &tmps
        ));
        // 兄弟目录不误伤（组件级前缀，/var/lib/crbs-other 不命中）。
        assert!(!mount_in_gc_scan_domain(
            "/var/lib/crbs-other/x".as_ref(),
            "overlay",
            &root,
            &tmps
        ));
    }

    #[test]
    fn tmp_domain_hits_dot_tmp_container_mounts_only() {
        let (root, tmps) = domain("/var/lib/crbs", &["/var/tmp", "/dev/shm"]);
        // overlay 目标 {tmp}/.tmpXXXX/root：tmp 域核心命中。
        assert!(mount_in_gc_scan_domain(
            "/var/tmp/.tmpABC123/root".as_ref(),
            "overlay",
            &root,
            &tmps
        ));
        assert!(mount_in_gc_scan_domain(
            "/dev/shm/.tmpABC123/root/proc".as_ref(),
            "proc",
            &root,
            &tmps
        ));
        // .tmpXXX 自身是挂载点（卸载目标含临时目录本体）也命中。
        assert!(mount_in_gc_scan_domain(
            "/var/tmp/.tmpABC123".as_ref(),
            "tmpfs",
            &root,
            &tmps
        ));
        // 非 .tmp 命名的共享 tmp 挂载不命中（不殃及同机第三方）。
        assert!(!mount_in_gc_scan_domain(
            "/var/tmp/my-mount".as_ref(),
            "overlay",
            &root,
            &tmps
        ));
        // .tmp 命名但非容器伪 fs（如第三方 ext4 bind）不命中。
        assert!(!mount_in_gc_scan_domain(
            "/var/tmp/.tmpXYZ/data".as_ref(),
            "ext4",
            &root,
            &tmps
        ));
        // 兄弟前缀不误伤：/dev/shmfoo 不在任何扫描 tmp 根之下。
        assert!(!mount_in_gc_scan_domain(
            "/dev/shmfoo/.tmpA".as_ref(),
            "overlay",
            &root,
            &tmps
        ));
    }

    #[test]
    fn tmp_domain_root_itself_never_hits() {
        // tmp 根本身不在 .tmp 前缀下永不命中——GC 不可能懒卸载共享临时区全体。
        let (root, tmps) = domain("/var/lib/crbs", &["/var/tmp"]);
        assert!(!mount_in_gc_scan_domain(
            "/var/tmp".as_ref(),
            "tmpfs",
            &root,
            &tmps
        ));
        assert!(!mount_in_gc_scan_domain(
            "/".as_ref(),
            "overlay",
            &root,
            &tmps
        ));
    }
}
