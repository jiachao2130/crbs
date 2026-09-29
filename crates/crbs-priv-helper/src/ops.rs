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
//! 所有操作仅 Linux 实现，其它平台返回 Error::Unsupported。

use std::path::{Path, PathBuf};

use crate::Error;

#[cfg(target_os = "linux")]
use std::fs;

/// 文件类目标：剥 S_ISUID|S_ISGID。调用方（crbs 组成员）不可信，能铸 setid-root
/// 文件即提权；类型感知剥离统一在 ops 层施加，递归 chmod 对文件另有 0o666 掩码。
pub fn strip_file_setid_bits(mode: u32) -> u32 {
    mode & !0o6000
}

/// 目录类目标：只剥 S_ISUID，保留 SGID——目录 SGID（0o2770）是 crbs 权限不变量
/// （新文件继承 crbs 组），不能剥。
pub fn strip_dir_setid_bits(mode: u32) -> u32 {
    mode & !0o4000
}

/// 挂载点边界判定（漏洞 4 修复）：st_dev 不同即中间隔着挂载点（bind、
/// overlay、tmpfs 等）；递归 chown/chmod/rm-rf 穿透会作用到 bind 进来的宿
/// 主子树（/dev、dnf 缓存等），遍历必须跳过。
pub fn crosses_mount(root_dev: u64, child_dev: u64) -> bool {
    root_dev != child_dev
}

#[cfg(target_os = "linux")]
/// 拒绝会破坏 overlayfs 选项结构的字符：`,` 是选项分隔符（可注入 `upperdir=` 等
/// 新选项），`\n` 同样禁止；lowerdir 额外禁止 `:`（多 lower 的分隔符）。
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

/// 挂载 overlayfs：多层 lower + upper/work 叠加到 target。
/// mount(2) 无超时参数，NFS/CIFS 可无限挂起，而调用链无上界——挂起即任务永久
/// 挂起。升级路径：privilege backend 外包 tokio::time::timeout 并 kill。
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

pub fn kill_process_group(pgid: i32) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
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

/// 受控终止本系统自建的 nspawn machine：优先向 scope 的 cgroup.kill 写入（原子杀
/// 整棵子树），kill 文件不可写再退而按 /proc 成员 SIGKILL。machine 已不存在
/// （scope 与成员皆空）按幂等成功。
pub fn terminate_machine(machine_name: &str) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        let mut scope_seen = false;
        for scope in machine_scope_cgroup_dirs(machine_name) {
            scope_seen |= scope.is_dir();
            let kill_file = scope.join("cgroup.kill");
            if kill_file.exists() {
                // kill 文件在但写失败必须报错（失败即拒绝）：部分杀伤后继续跑会让
                // 调用方把失败当成已处置，绝不用 /proc 补查制造假成功。
                return write_cgroup_file(&kill_file, "1\n");
            }
        }
        let killed = terminate_scope_members(machine_name)?;

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

#[cfg(target_os = "linux")]
/// scope 目录的 cgroup 路径候选：cgroup v2 统一根与 v1 legacy systemd 根 × 双命名
/// 形态（{name}.scope / machine-{name}.scope）× 原样/转义。 machined 注册的目录名
/// 是转义形态，两种栈都存在，漏任一形态则 terminate 落空。顺序与 crbs-core nspawn
/// cgroup.rs 的 scope_path_candidates 手工保持同步。
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

/// 通用挂载：source / fstype / flags / data 透传 mount(2)。
/// mount(2) 无超时参数，NFS/CIFS 可无限挂起，而调用链无上界——挂起即任务永久
/// 挂起。升级路径：privilege backend 外包 tokio::time::timeout 并 kill。
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

/// 创建目录（含缺失父级）并 chown 到 user:group、chmod 指定 mode。父链逐组件
/// O_DIRECTORY|O_NOFOLLOW 解析补建，chown/chmod 作用于已验证的 fd，不经名字解析
/// （与 write/chown/chmod/rm-rf 同级的 TOCTOU 防护）。
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

        let mode = crate::ops::strip_dir_setid_bits(mode);
        // 剥 SUID 保 SGID（0o2770 权限不变量；SUID 目录无合法调用方）。
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

#[cfg(target_os = "linux")]
/// fd 相对遍历：每级目录以 O_DIRECTORY|O_NOFOLLOW 打开，操作经 fchown/fchmod/
/// f*at(dirfd,…) 施加，全程不依赖路径字符串。根路径由 resolve_leaf 从可信起点逐
/// 组件解析——整路径 openat 只护最后一级（open(2)：earlier components will still be
/// followed），校验后中间组件被换成 symlink 会被跟随；逐组件每级原子校验，遇
/// symlink/非目录直接失败，消除 validate 之后的 TOCTOU 窗口。
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

    #[derive(Clone, Copy, PartialEq)]
    enum Missing {
        Ignore,

        Fail,

        Create,
    }

    const OPEN_FLAGS: OFlag = OFlag::O_RDONLY
        .union(OFlag::O_CLOEXEC)
        .union(OFlag::O_DIRECTORY)
        .union(OFlag::O_NOFOLLOW);

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

    /// 递归 chown：根经 `resolve_leaf` 逐组件解析且必须是真实目录（symlink
    /// 拒绝）。
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

    /// 递归 chmod：根路径逐组件解析（`resolve_leaf`）；根为普通文件或
    /// symlink 时退化为单文件 chmod（symlink 经 fchmodat NoFollow 报
    /// EOPNOTSUPP）。
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
            Err(Errno::ELOOP | Errno::ENOTDIR) => fchmodat(
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
            }),
            Err(e) => Err(Error::Io(std::io::Error::other(format!(
                "chmod -r: open {}: {e}",
                path.display()
            )))),
        }
    }

    /// 单路径 chown（lchown 语义不跟随）：父目录经 `resolve_leaf` 逐组件解
    /// 析到已验证 fd，中间组件无 TOCTOU 窗口。
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

    /// 单路径 chmod（fchmodat NoFollow）：类型感知剥 setid 位（漏洞 3）——
    /// 目录剥 SUID 保 SGID，文件剥 SUID 与 SGID。
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

    /// 递归删除：fd 相对遍历加 `unlinkat`，全程不跟随 symlink。根路径逐组
    /// 件解析（`resolve_leaf`）而非整路径 `openat(None, path)`——整路径
    /// O_NOFOLLOW 只保护最后一级（open(2) 的 earlier components 仍会被跟
    /// 随），validate 之后中间组件被换成 symlink 会被跟随；逐组件每级原子
    /// 校验即拒绝。根为文件或 symlink 时经父 fd unlink；目录后序清空后
    /// rmdir；路径不存在（含中间组件缺失）按 no-op 处理。
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

        unlinkat(Some(dirfd), leaf, UnlinkatFlags::RemoveDir).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "rmdir {:?} in {}: {e}",
                leaf,
                path.display()
            )))
        })
    }

    /// 逐组件解析 path，返回（叶子所在目录 fd, 叶子名）。从可信起点出发（绝对路径
    /// `/`、相对路径 `.`——内核保留名不可能被换成 symlink），每个中间组件单独
    /// `openat(O_DIRECTORY | O_NOFOLLOW)` 原子校验：symlink（ELOOP）/非目录（ENOTDIR）
    /// 失败即拒绝，缺失按 missing 策略处理。叶子为 `..` 或 `.` 直接拒绝——rm -rf
    /// 会先清空所指目录再失败，write/chown/chmod 会作用到祖先目录。
    fn resolve_leaf<'a>(
        path: &'a Path,
        missing: Missing,
        op: &str,
    ) -> Result<Option<(OwnedFd, &'a OsStr)>, Error> {
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

    /// write-file 的父目录解析：缺失组件 mkdirat 逐级补建，symlink/非目录失败即
    /// 拒绝；返回的 fd 是 tempfile 与 rename 必须使用的已验证父目录（经 /proc/self/fd/ 访问，不经原路径重解析）。
    pub fn parent_for_write(path: &Path) -> Result<(OwnedFd, &OsStr), Error> {
        resolve_leaf_required(path, Missing::Create, "write-file")
    }

    /// mkdir-chown 的实现：叶子 mkdirat（EEXIST 容忍 = mkdir -p 幂等）后
    /// 重新打开，symlink/普通文件在此步原子失败、无副作用。调用方对 fd 直接
    /// fchown/fchmod，不经名字解析。
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
        Dir::from_fd(fd.into_raw_fd())
            .map_err(|e| Error::Io(std::io::Error::other(format!("fdopendir: {e}"))))
    }

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

                    if crate::ops::crosses_mount(root_dev, fd_dev(child.as_raw_fd())?) {
                        tracing::warn!(entry = ?name, "skip mountpoint during recursive walk");
                        continue;
                    }
                    apply_fd(child.as_raw_fd(), op)?;
                    walk(dir_from(child)?, op, root_dev)?;
                }
                EntryKind::Symlink => {
                    // chmod 不触碰 symlink（内核也不支持改 symlink 本身的 mode）。
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

    /// 递归删除的深度上限（相对根层数，根为 0）：约为最深合法布局（dnf installroot
    /// ~15 层、vendored 源码树 ~30 层）的 2 倍，兼约束递归资源。超限视为对抗性超深
    /// 树，拒绝并审计。
    pub(super) const WALK_REMOVE_MAX_DEPTH: u32 = 64;

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
                Err(e) => match fstatat(Some(dirfd), name, AtFlags::AT_SYMLINK_NOFOLLOW) {
                    Err(Errno::ENOENT) => {
                        tracing::warn!(entry = ?name, "skip entry vanished during recursive remove");
                        continue;
                    }
                    _ => return Err(e),
                },
            };
            match kind {
                EntryKind::Dir => match openat(Some(dirfd), name, OPEN_FLAGS, Mode::empty()) {
                    Ok(fd) => {
                        let child = unsafe { OwnedFd::from_raw_fd(fd) };

                        if crate::ops::crosses_mount(root_dev, fd_dev(child.as_raw_fd())?) {
                            tracing::warn!(entry = ?name, "skip mountpoint during recursive remove");
                            continue;
                        }

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

/// 修改属主为 uid:gid；`recursive` 时遍历目录树，否则仅叶子（lchown 语义）。
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

/// 修改权限为 mode；`recursive` 时遍历目录树，否则仅叶子。
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

/// 原子写文件：在已验证的父目录 fd 下建临时文件，写内容、设属主权限后 rename 到位
/// （mode 默认 0660，应用前剥 setid 位）。rename 原子替换目标本身（文件与 symlink
/// 都替换），禁止先删——remove 成功而 rename 失败会丢原文件。
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

        // mode 默认 0660 而非 tempfile 的 0600：三身份可读写是不变量。
        let mode = mode.unwrap_or(0o660);

        // 剥 suid/sgid：不可信调用方（crbs 组）铸 setid-root 文件即提权。
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

/// 写入 cgroup v2 控制文件。不走 temp+rename（cgroupfs 不支持 rename，EINVAL），
/// 直接 write(2)；调用方已断言路径严格位于 /sys/fs/cgroup/machine.slice 之下且
/// 文件名在白名单内。
pub fn write_cgroup_file(path: &Path, content: &str) -> Result<(), Error> {
    std::fs::write(path, content.as_bytes()).map_err(|e| {
        Error::Io(std::io::Error::other(format!(
            "write {}: {e}",
            path.display()
        )))
    })
}

#[cfg(target_os = "linux")]
/// 解码 mountinfo 字段的八进制转义（`\040` 空格、`\011`、`\012`、`\134` 反斜杠）；
/// 不合法的 `\` 序列原样保留。
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

/// GC 扫描域认定的容器伪文件系统（与 crbs-core engine::orphan 集合一致）：只命中
/// 构建环境的挂载类型，不殃及同机在共享 tmp 的第三方挂载。
pub const GC_TMP_CONTAINER_FSTYPES: &[&str] = &["overlay", "proc", "sysfs", "tmpfs", "devpts"];

/// GC 扫描域判定：crbs_root 域 = 严格位于 crbs_root 之下（本身不算）；tmp 域 =
/// tmp 目录下首级子目录以 .tmp 开头（tempfile 命名形态）且 fstype 属容器伪文件
/// 系统。tmp 是共享系统目录，不收紧会懒卸载同机第三方挂载。
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
        let under_tmp_dot = canon.strip_prefix(tmp).is_ok_and(|rest| {
            rest.components()
                .next()
                .is_some_and(|c| c.as_os_str().to_string_lossy().starts_with(".tmp"))
        });
        under_tmp_dot && GC_TMP_CONTAINER_FSTYPES.contains(&fstype)
    })
}

/// 清扫 crbs_root 与可选临时目录扫描范围内的无主挂载（扫描 /proc/self/mountinfo），
/// 全部 MNT_DETACH 懒卸载，不删目录体。tmp_dirs 覆盖 overlay 目标
/// （{tmp_dir}/.tmpXXXX/root）与全内存构建（.tmpXXXX/memroot/root）的崩溃残留——
/// 这类残留最常见于此而非 crbs_root 下。
pub fn gc_orphan_mounts(crbs_root: &Path, tmp_dirs: &[PathBuf]) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("read mountinfo: {e}"),
            ))
        })?;

        let canonical_root = fs::canonicalize(crbs_root).map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("canonicalize {}: {e}", crbs_root.display()),
            ))
        })?;

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

        to_umount.sort_by_key(|p| p.components().count());
        to_umount.reverse();
        to_umount.dedup();
        // 深层优先卸载。

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

/// 递归删除一个或多个路径（文件或目录）：走 `fs_walk` 的 fd 相对遍历（根
/// 逐组件解析、TOCTOU 防护与删除语义见 `fs_walk::remove_recursive`）；路
/// 径不存在视为 no-op，遍历期间条目消失（ENOENT）容错跳过。
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

        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("f");
        fs::write(&victim, b"secret").unwrap();

        let parent = tmp.path().join("parent");
        fs::create_dir_all(&parent).unwrap();
        std::os::unix::fs::symlink(&outside, parent.join("link")).unwrap();
        let target = parent.join("link").join("f");

        assert!(write_file(&target, b"evil", None, None, None).is_err());

        assert_eq!(fs::read_to_string(&victim).unwrap(), "secret");
        assert!(parent.join("link").symlink_metadata().is_ok());
    }

    #[test]
    fn write_file_dotdot_leaf_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let keep = tmp.path().join("keep");
        fs::create_dir_all(&keep).unwrap();

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

        assert!(chown(&link, uid, gid, true).is_err());

        chown(&link, uid, gid, false).unwrap();
    }

    #[test]
    fn chown_intermediate_symlink_rejected() {
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

        assert!(chown(&ghost, uid, gid, false).is_err());
        assert!(chown(&ghost, uid, gid, true).is_err());
        assert!(chmod(&ghost, 0o600, false).is_err());
        assert!(chmod(&ghost, 0o600, true).is_err());
    }

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

        mkdir_chown(&target, &user, &group, 0o6770).unwrap();

        assert_eq!(fs::read_to_string(target.join("keep")).unwrap(), "data");
        let meta = fs::metadata(&target).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o2770);
    }

    #[test]
    fn mkdir_chown_intermediate_symlink_rejected() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();

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

        let evil_lower = tmp.path().join("lo,upperdir=/etc");
        let res = mount_overlay(&[evil_lower], &upper, &work, &target);
        assert!(matches!(res, Err(Error::Validation(_))));

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

        let chain = nested_chain_path(&root, (fs_walk::WALK_REMOVE_MAX_DEPTH + 6) as usize);
        fs::create_dir_all(&chain).unwrap();
        fs::write(chain.join("leaf"), b"x").unwrap();

        let res = rm_rf(std::slice::from_ref(&root));
        assert!(
            matches!(res, Err(Error::Validation(ref msg))
                if msg.contains("max depth")),
            "unexpected: {res:?}"
        );

        assert!(root.exists());
        assert!(chain.join("leaf").exists());
    }

    #[test]
    fn rm_rf_tree_at_depth_limit_fully_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");

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

        assert!(rm_rf(std::slice::from_ref(&x.join(".."))).is_err());
        assert!(keep.join("f").exists());
    }

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

    #[test]
    fn machine_scope_cgroup_dirs_escaping_for_digit_and_uuid_names() {
        for name in ["crbs-01234567", "crbs-9c714595-1b03-4e5f-8d2a-abcdef012345"] {
            let dirs = machine_scope_cgroup_dirs(name);
            assert_eq!(dirs.len(), 8);
            let escaped = name.replace('-', "\\x2d");

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

        assert!(mount_in_gc_scan_domain(
            "/var/tmp/.tmpABC123".as_ref(),
            "tmpfs",
            &root,
            &tmps
        ));

        assert!(!mount_in_gc_scan_domain(
            "/var/tmp/my-mount".as_ref(),
            "overlay",
            &root,
            &tmps
        ));

        assert!(!mount_in_gc_scan_domain(
            "/var/tmp/.tmpXYZ/data".as_ref(),
            "ext4",
            &root,
            &tmps
        ));

        assert!(!mount_in_gc_scan_domain(
            "/dev/shmfoo/.tmpA".as_ref(),
            "overlay",
            &root,
            &tmps
        ));
    }

    #[test]
    fn tmp_domain_root_itself_never_hits() {
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
