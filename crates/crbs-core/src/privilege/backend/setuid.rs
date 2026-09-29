// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! setuid 特权后端：按操作切换身份并执行特权系统调用。

use std::path::{Path, PathBuf};

use super::PrivilegeBackend;

/// 默认 setuid 后端：直接执行系统调用。
pub struct SetuidBackend;

// ── setid 位剥离：与 helper 侧 ops::strip_*_setid_bits 手抄同步——两条特权
// 路径的约束必须一致，否则 setuid 路径成为绕过面。root 后端不得铸造
// setid 文件（write-file/chmod 4755 → suid-root）；类型感知剥离：目录剥
// S_ISUID、保留 S_ISGID（0o2770 是仓库权限不变量）。

/// 文件类目标：剥 S_ISUID|S_ISGID（0o6000），保留其余位。
fn strip_file_setid_bits(mode: u32) -> u32 {
    mode & !0o6000
}

/// 目录类目标：剥 S_ISUID（0o4000），保留 S_ISGID。
fn strip_dir_setid_bits(mode: u32) -> u32 {
    mode & !0o4000
}

impl PrivilegeBackend for SetuidBackend {
    #[cfg(target_os = "linux")]
    fn mount(
        &self,
        source: Option<&Path>,
        target: &Path,
        fstype: Option<&str>,
        flags: u64,
        data: Option<&str>,
    ) -> crate::Result<()> {
        use nix::mount::{mount, MsFlags};

        let flags = MsFlags::from_bits_truncate(flags);
        mount(source, target, fstype, flags, data).map_err(|e| {
            crate::error::CrbsError::io_message(format!(
                "mount {} ({:?}): {e}",
                target.display(),
                fstype
            ))
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn mount(
        &self,
        _source: Option<&Path>,
        target: &Path,
        _fstype: Option<&str>,
        _flags: u64,
        _data: Option<&str>,
    ) -> crate::Result<()> {
        Err(crate::error::CrbsError::io_message(format!(
            "mount {} requires Linux",
            target.display()
        )))
    }

    #[cfg(target_os = "linux")]
    fn umount2(&self, target: &Path, flags: i32) -> crate::Result<()> {
        use nix::mount::{umount2, MntFlags};

        let flags = MntFlags::from_bits_truncate(flags);
        umount2(target, flags).map_err(|e| {
            crate::error::CrbsError::io_message(format!("umount2 {}: {e}", target.display()))
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn umount2(&self, target: &Path, _flags: i32) -> crate::Result<()> {
        Err(crate::error::CrbsError::io_message(format!(
            "umount2 {} requires Linux",
            target.display()
        )))
    }

    #[cfg(target_os = "linux")]
    fn mkdir_chown(&self, path: &Path, user: &str, group: &str, mode: u32) -> crate::Result<()> {
        use nix::sys::stat::{fchmodat, FchmodatFlags, Mode};
        use std::fs;
        use std::os::unix::fs::lchown;

        fs::create_dir_all(path).map_err(|e| {
            crate::error::CrbsError::io_message(format!("create dir {}: {e}", path.display()))
        })?;

        let uid = nix::unistd::User::from_name(user)
            .map_err(|e| crate::error::CrbsError::io_message(format!("lookup user {user}: {e}")))?
            .map(|u| u.uid.as_raw())
            .ok_or_else(|| crate::error::CrbsError::io_message(format!("user {user} not found")))?;
        let gid = nix::unistd::Group::from_name(group)
            .map_err(|e| crate::error::CrbsError::io_message(format!("lookup group {group}: {e}")))?
            .map(|g| g.gid.as_raw())
            .ok_or_else(|| {
                crate::error::CrbsError::io_message(format!("group {group} not found"))
            })?;

        lchown(path, Some(uid), Some(gid)).map_err(|e| {
            crate::error::CrbsError::io_message(format!("lchown {}: {e}", path.display()))
        })?;

        // 目录剥 SUID 保 SGID（对齐 helper 侧 mkdir-chown；SUID 目录无合法调用方）。
        let mode = Mode::from_bits_truncate(strip_dir_setid_bits(mode) as nix::libc::mode_t);
        fchmodat(None, path, mode, FchmodatFlags::NoFollowSymlink).map_err(|e| {
            crate::error::CrbsError::io_message(format!("fchmodat {}: {e}", path.display()))
        })?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn mkdir_chown(
        &self,
        _path: &Path,
        _user: &str,
        _group: &str,
        _mode: u32,
    ) -> crate::Result<()> {
        Err(crate::error::CrbsError::io_message(
            "mkdir-chown requires Linux",
        ))
    }

    #[cfg(unix)]
    fn chown(&self, path: &Path, uid: u32, gid: u32, recursive: bool) -> crate::Result<()> {
        use std::os::unix::fs::lchown;

        fn walk(dir: &Path, uid: u32, gid: u32) -> crate::Result<()> {
            // 使用 lchown，避免跟随符号链接，同时不改变链接目标。
            lchown(dir, Some(uid), Some(gid)).map_err(|e| {
                crate::error::CrbsError::io_message(format!("lchown {}: {e}", dir.display()))
            })?;
            let entries = std::fs::read_dir(dir).map_err(|e| {
                crate::error::CrbsError::io_message(format!("read dir {}: {e}", dir.display()))
            })?;
            for entry in entries {
                let entry = entry.map_err(|e| {
                    crate::error::CrbsError::io_message(format!("read dir entry: {e}"))
                })?;
                let p = entry.path();
                lchown(&p, Some(uid), Some(gid)).map_err(|e| {
                    crate::error::CrbsError::io_message(format!("lchown {}: {e}", p.display()))
                })?;
                if entry
                    .file_type()
                    .map_err(|e| {
                        crate::error::CrbsError::io_message(format!(
                            "file type {}: {e}",
                            p.display()
                        ))
                    })?
                    .is_dir()
                {
                    walk(&p, uid, gid)?;
                }
            }
            Ok(())
        }

        lchown(path, Some(uid), Some(gid)).map_err(|e| {
            crate::error::CrbsError::io_message(format!("lchown {}: {e}", path.display()))
        })?;
        if recursive {
            walk(path, uid, gid)?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn chown(&self, path: &Path, _uid: u32, _gid: u32, _recursive: bool) -> crate::Result<()> {
        Err(crate::error::CrbsError::io_message(format!(
            "chown {} requires Unix",
            path.display()
        )))
    }

    #[cfg(unix)]
    fn chmod(&self, path: &Path, mode: u32, recursive: bool) -> crate::Result<()> {
        use nix::sys::stat::{fchmodat, FchmodatFlags, Mode};

        fn chmod_one(p: &Path, mode: u32) -> crate::Result<()> {
            fchmodat(
                None,
                p,
                Mode::from_bits_truncate(mode as nix::libc::mode_t),
                FchmodatFlags::NoFollowSymlink,
            )
            .map_err(|e| {
                crate::error::CrbsError::io_message(format!("fchmodat {}: {e}", p.display()))
            })
        }

        // 类型感知剥 setid 位（对齐 helper 侧 ops/fs_walk）：顶层目标也按型剥，
        // 否则 `chmod 4755 <file>` 经 setuid 路径仍可铸造 suid-root 文件。
        fn chmod_one_stripped(p: &Path, mode: u32) -> crate::Result<()> {
            let meta = std::fs::symlink_metadata(p).map_err(|e| {
                crate::error::CrbsError::io_message(format!("metadata {}: {e}", p.display()))
            })?;
            let effective = if meta.file_type().is_dir() {
                strip_dir_setid_bits(mode)
            } else {
                strip_file_setid_bits(mode)
            };
            chmod_one(p, effective)
        }

        fn walk(dir: &Path, mode: u32) -> crate::Result<()> {
            chmod_one_stripped(dir, mode)?;
            let entries = std::fs::read_dir(dir).map_err(|e| {
                crate::error::CrbsError::io_message(format!("read dir {}: {e}", dir.display()))
            })?;
            for entry in entries {
                let entry = entry.map_err(|e| {
                    crate::error::CrbsError::io_message(format!("read dir entry: {e}"))
                })?;
                let p = entry.path();
                let ft = entry.file_type().map_err(|e| {
                    crate::error::CrbsError::io_message(format!("file type {}: {e}", p.display()))
                })?;
                // 跳过符号链接：fchmodat 应不跟随链接，但这里显式跳过避免修改链接目标。
                if ft.is_symlink() {
                    continue;
                }
                // 文件掩 0o666（无 execute/setgid，天然无 setid 位）；目录保完整
                // mode 保证可再建子项，setid 由 chmod_one_stripped 按型剥。
                let effective = if ft.is_dir() { mode } else { mode & 0o0666 };
                if ft.is_dir() {
                    chmod_one_stripped(&p, effective)?;
                    walk(&p, mode)?;
                } else {
                    chmod_one(&p, effective)?;
                }
            }
            Ok(())
        }

        chmod_one_stripped(path, mode)?;
        if recursive {
            let meta = std::fs::symlink_metadata(path).map_err(|e| {
                crate::error::CrbsError::io_message(format!("metadata {}: {e}", path.display()))
            })?;
            if meta.file_type().is_dir() {
                walk(path, mode)?;
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn chmod(&self, path: &Path, _mode: u32, _recursive: bool) -> crate::Result<()> {
        Err(crate::error::CrbsError::io_message(format!(
            "chmod {} requires Unix",
            path.display()
        )))
    }

    fn write_file(
        &self,
        path: &Path,
        content: &[u8],
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> crate::Result<()> {
        use std::io::Write;
        use std::os::unix::io::AsRawFd;

        use nix::sys::stat::{fchmod, Mode};
        use nix::unistd::{fchown, Gid, Uid};

        let parent = path.parent().ok_or_else(|| {
            crate::error::CrbsError::io_message(format!("path has no parent: {}", path.display()))
        })?;
        std::fs::create_dir_all(parent).map_err(|e| {
            crate::error::CrbsError::io_message(format!(
                "create parent dir {}: {e}",
                parent.display()
            ))
        })?;

        // 临时文件上写内容、设权限/属主后原子 rename（规避 symlink 跟随目标路径）。
        let tmp = tempfile::NamedTempFile::new_in(parent).map_err(|e| {
            crate::error::CrbsError::io_message(format!(
                "create temp file in {}: {e}",
                parent.display()
            ))
        })?;

        tmp.as_file().write_all(content).map_err(|e| {
            crate::error::CrbsError::io_message(format!(
                "write temp file {}: {e}",
                tmp.path().display()
            ))
        })?;

        // 缺省 0660（非 tempfile 0600）：三身份可读写不变量；应用前剥
        // suid/sgid（对齐 helper 侧 write-file：不铸造 setid-root 文件）。
        let mode = Mode::from_bits_truncate(
            strip_file_setid_bits(mode.unwrap_or(0o660)) as nix::libc::mode_t
        );
        fchmod(tmp.as_file().as_raw_fd(), mode).map_err(|e| {
            crate::error::CrbsError::io_message(format!(
                "fchmod temp file {}: {e}",
                tmp.path().display()
            ))
        })?;

        #[cfg(unix)]
        if uid.is_some() || gid.is_some() {
            fchown(
                tmp.as_file().as_raw_fd(),
                uid.map(Uid::from_raw),
                gid.map(Gid::from_raw),
            )
            .map_err(|e| {
                crate::error::CrbsError::io_message(format!(
                    "fchown temp file {}: {e}",
                    tmp.path().display()
                ))
            })?;
        }

        // rename(2) 原子替换已有目标（文件/symlink 均被替换本身），不先删——
        // 先删会在 remove 成功而 rename 失败时丢原文件；目标为非空目录时报错。
        tmp.persist(path).map_err(|e| {
            crate::error::CrbsError::io_message(format!(
                "rename temp file to {}: {e}",
                path.display()
            ))
        })?;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn gc_orphan_mounts(&self, crbs_root: &Path, tmp_dirs: &[PathBuf]) -> crate::Result<()> {
        // 同步读 /proc/mounts，深层优先卸载扫描域内挂载点；扫描域谓词见
        // mount_in_gc_scan_domain（与 helper 侧同口径，域定义见其 doc）。
        use nix::mount::{umount2, MntFlags};
        use std::fs;

        let canonical_root = fs::canonicalize(crbs_root)
            .map_err(|e| crate::error::CrbsError::io_message(format!("canonicalize: {e}")))?;
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
        let content = fs::read_to_string("/proc/mounts")
            .map_err(|e| crate::error::CrbsError::io_message(format!("read /proc/mounts: {e}")))?;

        let mut to_umount = Vec::new();
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            // 挂载点字段解码内核八进制转义（\040 空格等；split_whitespace
            // 作用在原始行上安全）：不解码则含空白路径 canonicalize 必失败、漏挂载。
            let mp = crate::engine::orphan::decode_proc_mounts_field(parts[1]);
            let fstype = parts[2];
            if let Ok(canon) = fs::canonicalize(&mp) {
                if mount_in_gc_scan_domain(&canon, fstype, &canonical_root, &canonical_tmps) {
                    to_umount.push(canon);
                }
            }
        }
        to_umount.sort_by_key(|p| p.components().count());
        to_umount.reverse();
        to_umount.dedup();
        for mp in &to_umount {
            if let Err(e) = umount2(mp, MntFlags::MNT_DETACH) {
                tracing::warn!(path = %mp.display(), error = %e, "failed to umount orphan mount");
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn gc_orphan_mounts(&self, _crbs_root: &Path, _tmp_dirs: &[PathBuf]) -> crate::Result<()> {
        Err(crate::error::CrbsError::io_message(
            "gc-orphan-mounts requires Linux",
        ))
    }

    // 纯 std::fs，无 Linux 专属 syscall；限成 Linux-only 会让非 Linux 的 GC/清理路径全报错。
    #[cfg(unix)]
    fn rm_rf(&self, paths: &[&Path]) -> crate::Result<()> {
        use std::fs;
        for p in paths {
            let meta = match fs::symlink_metadata(p) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(crate::error::CrbsError::io_message(format!(
                        "rm_rf stat {}: {e}",
                        p.display()
                    )));
                }
            };
            if meta.is_dir() {
                fs::remove_dir_all(p).map_err(|e| {
                    crate::error::CrbsError::io_message(format!("rm_rf dir {}: {e}", p.display()))
                })?;
            } else {
                fs::remove_file(p).map_err(|e| {
                    crate::error::CrbsError::io_message(format!("rm_rf file {}: {e}", p.display()))
                })?;
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn rm_rf(&self, _paths: &[&Path]) -> crate::Result<()> {
        Err(crate::error::CrbsError::io_message("rm_rf requires Unix"))
    }

    #[cfg(target_os = "linux")]
    fn spawn_chroot(
        &self,
        rootfs: &Path,
        program: &str,
        args: &[&str],
        network: bool,
    ) -> crate::Result<std::process::Command> {
        crate::engine::backend::chroot_impl::command_in_rootfs(rootfs, program, args, network)
            .map_err(|e| crate::error::CrbsError::io_message(format!("setup chroot pre_exec: {e}")))
    }

    #[cfg(not(target_os = "linux"))]
    fn spawn_chroot(
        &self,
        rootfs: &Path,
        program: &str,
        args: &[&str],
        network: bool,
    ) -> crate::Result<std::process::Command> {
        let mut cmd = if !network {
            let mut c = std::process::Command::new("unshare");
            c.arg("--net").arg("--").arg("chroot");
            c
        } else {
            std::process::Command::new("chroot")
        };
        cmd.arg(rootfs).arg(program).args(args);
        Ok(cmd)
    }

    fn spawn_nspawn(&self, nspawn_argv: &[String]) -> crate::Result<std::process::Command> {
        if nspawn_argv.is_empty() {
            return Err(crate::error::CrbsError::io_message(
                "spawn_nspawn: empty argv",
            ));
        }
        let mut cmd = std::process::Command::new(&nspawn_argv[0]);
        cmd.args(&nspawn_argv[1..]);
        // 与 helper 路径同款环境卫生：不把守护进程环境（PATH/HOME/proxy/token）
        // 带给宿主侧 nspawn；容器内环境只经 argv 的 --setenv 显式注入。
        cmd.env_clear();
        cmd.env("PATH", crate::engine::backend::SAFE_PATH);
        Ok(cmd)
    }
    fn kill_process_group(&self, pgid: i32) -> crate::Result<()> {
        let target = nix::unistd::Pid::from_raw(-pgid);
        nix::sys::signal::kill(target, nix::sys::signal::SIGKILL).map_err(|e| {
            crate::error::CrbsError::io_message(format!("SIGKILL process group {pgid}: {e}"))
        })
    }

    fn terminate_machine(&self, machine_name: &str) -> crate::Result<()> {
        // 与 crbs-priv-helper ops::terminate_machine 同语义（跨 crate 手抄同步，
        // kill_process_group 同先例）：探测 scope 目录写 cgroup.kill（v2 统一根
        // 与 v1 legacy systemd 根 × 双命名 × 原样/转义全候选），kill 文件不可写
        // 按 /proc cgroup 成员 SIGKILL 兜底；machine 已不存在按幂等成功。信任
        // 边界在引擎侧：machine_name 来自 spawn 侧 machine_name_for（crbs- 命名
        // 空间生成器），不经外部输入。
        let mut scope_seen = false;
        for scope in machine_scope_cgroup_dirs(machine_name) {
            let kill_file = format!("{scope}/cgroup.kill");
            scope_seen |= Path::new(&scope).is_dir();
            if Path::new(&kill_file).exists() {
                // 目录在且 kill 文件在但写失败 → 报错（fail-closed），不落 /proc
                // 兜底造成部分杀伤后的假成功（与 helper 侧同款）。
                return self.write_cgroup_file(&kill_file, "1");
            }
        }
        let killed = terminate_machine_members(machine_name)?;
        // 幂等复核：killed == 0 且 scope 目录从未出现 = machine 已不在；scope
        // 在但无可见成员 = 构建已自然退出——两者都按成功，scope_seen 供审计。
        tracing::debug!(
            machine = %machine_name,
            killed = killed,
            scope_seen = scope_seen,
            "terminate-machine done"
        );
        Ok(())
    }

    fn write_cgroup_file(&self, path: &str, value: &str) -> crate::Result<()> {
        // 与 HelperBackend 语义对齐：统一追加换行（cgroupfs 忽略尾随空白）。
        let data = format!("{value}\n");
        std::fs::write(path, data.as_bytes()).map_err(|e| {
            crate::error::CrbsError::io_message(format!("write cgroup file {path}: {e}"))
        })
    }

    fn spawn_dnf(
        &self,
        installroot: &Path,
        releasever: &str,
        trusted_repos_dir: &Path,
        args: &[String],
    ) -> crate::Result<std::process::Command> {
        // setuid 直连路径以 root 跑 dnf：参数白名单见 validate_setuid_dnf_args。
        validate_setuid_dnf_args(args)?;
        // fail-closed（与 helper 同款）：受信目录/配置缺失即拒绝，不静默回退 installroot。
        let dnf_conf = require_trusted_dnf_repos_dir(trusted_repos_dir)?;
        // 环境卫生（同 helper）：不继承调用方环境（防 PATH 劫持/token 泄漏）。
        let mut cmd = std::process::Command::new("/usr/bin/dnf");
        cmd.env_clear();
        cmd.env("PATH", crate::engine::backend::SAFE_PATH);
        // 这两个参数按 host 绝对路径消费（不与 --installroot 拼接；dnf4/dnf5 实测把关）。
        cmd.arg("--installroot")
            .arg(installroot)
            .arg("--releasever")
            .arg(releasever)
            .args(trusted_dnf_injected_args(&dnf_conf, trusted_repos_dir))
            .args(args);
        Ok(cmd)
    }
}

/// machine scope 的 cgroup 路径候选（写探测顺序，绝对路径）：cgroup v2 统一根
/// 与 v1 legacy 的 systemd 层级根（v1 宿主层级挂 /sys/fs/cgroup/systemd，无 v2
/// 前缀）为二探测根，乘双命名形态（`{name}.scope` / `machine-{name}.scope`）
/// 与原样/转义双形态——machined 注册的 scope 目录名即转义形态
///（`machine-crbs\x2d…`），两栈都存在，漏任一形态则 terminate 落空。转义复用
/// nspawn::systemd_escape_dash（同 crate 单一实现）。与 crbs-priv-helper
/// ops::machine_scope_cgroup_dirs 手抄同步；machine 名经 machine_name_for 生成，
/// 拼接不可能逃逸出 machine.slice。
fn machine_scope_cgroup_dirs(machine_name: &str) -> Vec<String> {
    const SLICE_ROOTS: [&str; 2] = [
        "/sys/fs/cgroup/machine.slice",
        "/sys/fs/cgroup/systemd/machine.slice",
    ];
    let escaped = crate::engine::backend::nspawn::systemd_escape_dash(machine_name);
    let names = [
        format!("{machine_name}.scope"),
        format!("{escaped}.scope"),
        format!("machine-{machine_name}.scope"),
        format!("machine-{escaped}.scope"),
    ];
    let mut dirs = Vec::with_capacity(SLICE_ROOTS.len() * names.len());
    for root in SLICE_ROOTS {
        for name in &names {
            dirs.push(format!("{root}/{name}"));
        }
    }
    dirs
}

/// /proc/{pid}/cgroup 内容是否把进程置于 machine_name 的 machine.slice scope
/// 之内（v2 `0::` 行与 v1 `hierarchy:controllers:path` 行同判；scope 组件整段
/// 比较防兄弟前缀误匹配；machined 注册的组件名是转义形态
/// `machine-crbs\x2d…`，v2 宿主 `0::` 行同此形态，原样/转义双形态都收）。
/// 与 crbs-priv-helper validate::cgroup_in_machine_scope
/// 手抄同步，双侧单测钉死同语义。
fn cgroup_in_machine_scope(cgroup_content: &str, machine_name: &str) -> bool {
    let escaped = crate::engine::backend::nspawn::systemd_escape_dash(machine_name);
    let scope_names = [
        format!("{machine_name}.scope"),
        format!("{escaped}.scope"),
        format!("machine-{machine_name}.scope"),
        format!("machine-{escaped}.scope"),
    ];
    cgroup_content.lines().any(|line| {
        // 路径取最后一个 ':' 之后：v2 两段（0::path）与 v1 三段（h:ctl:path）同构。
        let Some((_, path)) = line.rsplit_once(':') else {
            return false;
        };
        let mut components = Path::new(path).components();
        match (components.next(), components.next(), components.next()) {
            (Some(std::path::Component::RootDir), Some(slice), Some(scope)) => {
                slice.as_os_str() == "machine.slice"
                    && scope_names.iter().any(|n| scope.as_os_str() == n.as_str())
            }
            _ => false,
        }
    })
}

/// SIGKILL machine scope 内全部 /proc 成员（cgroup 任一行落在 scope 之下即
/// 成员），返回 SIGKILL 成功数；cgroup 不可读/ESRCH 按扫描间隙消失跳过，尽力
/// 终止——收敛复核由调用方（kill 升级链）负责。
fn terminate_machine_members(machine_name: &str) -> crate::Result<usize> {
    let mut killed = 0usize;
    let entries = std::fs::read_dir("/proc").map_err(|e| {
        crate::error::CrbsError::io_message(format!("terminate-machine scan /proc: {e}"))
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
        if cgroup_in_machine_scope(&content, machine_name)
            && nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::SIGKILL)
                .is_ok()
        {
            killed += 1;
        }
    }
    Ok(killed)
}

/// 受信 repo 目录内 dnf 主配置文件名（与 helper 侧 spawn.rs 手抄同步，双侧同改）。
const TRUSTED_DNF_CONF_NAME: &str = "dnf.conf";

/// spawn-dnf 前 fail-closed 检查（与 helper 侧 spawn.rs 同语义）：受信目录/
/// 配置缺失即拒绝。调用方是受信 engine 代码，只查存在性；属主/写位信任锚
/// 由写入侧（write_file 以 root 落盘）保证，helper CLI 边界另有全量属主校验。
fn require_trusted_dnf_repos_dir(repos_dir: &Path) -> crate::Result<PathBuf> {
    let conf = repos_dir.join(TRUSTED_DNF_CONF_NAME);
    let missing = |what: &str, p: &Path| crate::error::CrbsError::ValidationFailed {
        message: format!(
            "spawn_dnf trusted {what} {} is missing; refusing to fall back to \
                 installroot-side repo files",
            p.display()
        ),
    };
    if !repos_dir.is_dir() {
        return Err(missing("repos dir", repos_dir));
    }
    if !conf.is_file() {
        return Err(missing("config", &conf));
    }
    Ok(conf)
}

/// 固定注入的受信参数形态（与 helper 侧 main.rs 同步；纯函数供测试钉死）。
fn trusted_dnf_injected_args(conf: &Path, repos_dir: &Path) -> [String; 2] {
    [
        format!("--config={}", conf.display()),
        format!("--setopt=reposdir={}", repos_dir.display()),
    ]
}

/// setuid 直连 spawn_dnf 的参数白名单（与 helper validate_dnf_args 同语义，
/// 两特权路径约束必须一致，否则成绕过面）。engine 发这些形态：
/// `install -y [--downloadonly] [--setopt=keepcache=1] <pkg>...`（resolve 的
/// `--downloadonly` 只跳过 rpm 事务执行，不改 repo/路径语义）、
/// `clean metadata|all`；包名不得以 `-` 开头（选项注入）；受信
/// --config/--setopt 由 spawn_dnf 固定注入。
fn validate_setuid_dnf_args(args: &[String]) -> crate::Result<()> {
    let bad = |msg: String| crate::error::CrbsError::ValidationFailed { message: msg };
    let Some(verb) = args.first() else {
        return Err(bad("spawn_dnf: empty args".to_string()));
    };
    match verb.as_str() {
        "install" => {
            if args.len() < 2 || args[1] != "-y" {
                return Err(bad("spawn_dnf install requires -y".to_string()));
            }
            let mut i = 2;
            while matches!(
                args.get(i).map(String::as_str),
                Some("--setopt=keepcache=1") | Some("--downloadonly")
            ) {
                i += 1;
            }
            if i >= args.len() {
                return Err(bad(
                    "spawn_dnf install requires at least one package".to_string()
                ));
            }
            for a in &args[i..] {
                if a.starts_with('-') || a.chars().any(|c| c.is_whitespace()) {
                    return Err(bad(format!("spawn_dnf: invalid package arg {a:?}")));
                }
            }
        }
        "clean" => {
            let sub = args.get(1).map(String::as_str);
            if !matches!(sub, Some("metadata") | Some("all")) || args.len() != 2 {
                return Err(bad(
                    "spawn_dnf clean only accepts 'metadata' or 'all'".to_string()
                ));
            }
        }
        other => {
            return Err(bad(format!("spawn_dnf: verb {other:?} not allowed")));
        }
    }
    Ok(())
}

/// 容器伪文件系统白名单（tmp 扫描域判定）：与 helper 侧 ops 及 engine::orphan
/// 集合同集，只命中构建环境产生的挂载类型；生产调用点 Linux-only、非 Linux 仅为单测。
#[cfg(any(target_os = "linux", test))]
const GC_TMP_CONTAINER_FSTYPES: &[&str] = &["overlay", "proc", "sysfs", "tmpfs", "devpts"];

/// gc-orphan-mounts 扫描域判定（纯函数，跨平台可测）：规范化挂载点 `canon`
/// 是否在扫描域内；谓词与 helper 侧 ops::mount_in_gc_scan_domain 同语义
///（helper 独立成包，两处实现须同步）。crbs_root 域 = 严格在其下（本身不算）；
/// tmp 域 = tmp 下第一级子目录 `.tmp` 开头（tempfile 形态）且 fstype 属容器
/// 伪 fs。不可用 `starts_with(tmp.join(".tmp"))`：整组件比较 `.tmpABC123`
/// ≠ `.tmp`，tempfile 形态挂载一个都扫不到。
#[cfg(any(target_os = "linux", test))]
fn mount_in_gc_scan_domain(
    canon: &Path,
    fstype: &str,
    crbs_root: &Path,
    tmp_roots: &[PathBuf],
) -> bool {
    if canon != crbs_root && canon.starts_with(crbs_root) {
        return true;
    }
    tmp_roots.iter().any(|tmp| {
        // strip_prefix 按组件剥根：canon == tmp 时 rest 为空 → 不命中（GC 不作用 tmp 根）。
        let under_tmp_dot = canon.strip_prefix(tmp).is_ok_and(|rest| {
            rest.components()
                .next()
                .is_some_and(|c| c.as_os_str().to_string_lossy().starts_with(".tmp"))
        });
        under_tmp_dot && GC_TMP_CONTAINER_FSTYPES.contains(&fstype)
    })
}

/// gc 扫描域判定单测（与 helper 侧 ops.rs gc_scan_domain_tests 同款，钉两路同口径）。
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
        // 非 .tmp 命名（不殃及第三方）、.tmp 命名但非容器伪 fs（ext4 bind）均不命中。
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
        // tmp 根乃至 / 永不命中——GC 不会卸载共享临时区全体的挂载。
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

#[cfg(test)]
mod tests {
    use super::*;

    /// setuid 后端直接 std::fs::write，统一追加换行（与 helper 子命令行为对齐，见 trait 文档）。
    #[test]
    fn setuid_write_cgroup_file_appends_newline() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("memory.max");
        SetuidBackend
            .write_cgroup_file(target.to_str().unwrap(), "1073741824")
            .expect("write temp cgroup file");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"1073741824\n",
            "must append exactly one trailing newline"
        );
    }

    /// scope 成员判定（与 helper 侧 validate::cgroup_in_machine_scope 同语义）：
    /// v2/v1 双方言命中（含转义组件——machined 注册目录名的实际形态）、
    /// 他方 scope 与兄弟前缀拒绝。
    #[test]
    fn cgroup_in_machine_scope_matches_both_dialects_and_rejects_outside() {
        let name = "crbs-9c714595-22";
        for content in [
            "0::/machine.slice/crbs-9c714595-22.scope/payload\n",
            "0::/machine.slice/machine-crbs-9c714595-22.scope\n",
            "10:cpu,cpuacct:/machine.slice/machine-crbs-9c714595-22.scope/payload\n",
            // 转义组件：v2 `0::` 行与 v1 多控制器行（实测注册形态）。
            "0::/machine.slice/crbs\\x2d9c714595\\x2d22.scope/payload\n",
            "0::/machine.slice/machine-crbs\\x2d9c714595\\x2d22.scope\n",
            "10:cpu,cpuacct:/machine.slice/machine-crbs\\x2d9c714595\\x2d22.scope/payload\n",
        ] {
            assert!(
                cgroup_in_machine_scope(content, name),
                "must hit: {content:?}"
            );
        }
        for content in [
            "0::/machine.slice/crbs-deadbeef.scope/payload\n",
            // 转义名不同（他方 machine）与转义组件的兄弟前缀。
            "0::/machine.slice/machine-crbs\\x2ddeadbeef.scope\n",
            "0::/machine.slice/machine-crbs\\x2d9c714595\\x2d2.scope\n",
            "0::/machine.slice/machine-crbs\\x2d9c714595\\x2d22.scope.evil/x\n",
            "0::/machine.slice\n",
            "",
            "0::/machine.slice/machine-crbs-9c714595-22.scope.evil/x\n",
            "0::/machine.slice/crbs-9c714595-2.scope\n",
            "0::/system.slice/crbs-worker.service\n",
        ] {
            assert!(
                !cgroup_in_machine_scope(content, name),
                "must reject: {content:?}"
            );
        }
    }

    /// scope 候选路径形态：探测根（v2 统一根 + v1 legacy systemd 根）× 双命名
    /// × 原样/转义共 8 条（与 helper 侧 ops::machine_scope_cgroup_dirs 成对），
    /// kill 升级终局错误的操作提示与 cgroup.kill 探测共用。
    #[test]
    fn machine_scope_cgroup_dirs_cover_both_naming_forms() {
        let dirs = machine_scope_cgroup_dirs("crbs-9c714595-22");
        let expect: Vec<String> = [
            "/sys/fs/cgroup/machine.slice",
            "/sys/fs/cgroup/systemd/machine.slice",
        ]
        .iter()
        .flat_map(|root| {
            [
                format!("{root}/crbs-9c714595-22.scope"),
                format!("{root}/crbs\\x2d9c714595\\x2d22.scope"),
                format!("{root}/machine-crbs-9c714595-22.scope"),
                format!("{root}/machine-crbs\\x2d9c714595\\x2d22.scope"),
            ]
        })
        .collect();
        assert_eq!(dirs, expect);
    }

    /// 与 helper 侧 ops::strip_* 同步的剥离语义（两处约束必须一致）。
    #[test]
    fn setid_masks_strip_correctly_for_setuid_backend() {
        assert_eq!(strip_file_setid_bits(0o4755), 0o755);
        assert_eq!(strip_file_setid_bits(0o6755), 0o755);
        assert_eq!(strip_file_setid_bits(0o644), 0o644);
        assert_eq!(strip_file_setid_bits(0o1777), 0o1777);
        assert_eq!(strip_dir_setid_bits(0o2770), 0o2770);
        assert_eq!(strip_dir_setid_bits(0o4770), 0o770);
        assert_eq!(strip_dir_setid_bits(0o3770), 0o3770);
        assert_eq!(strip_dir_setid_bits(0o755), 0o755);
    }

    /// chmod 类型感知剥离：文件 4755 落盘 755、目录 4770 落盘 2770（铸造原语闭合）。
    #[test]
    fn chmod_strips_setid_bits_by_target_type() {
        use std::os::unix::fs::PermissionsExt;

        let backend = SetuidBackend;
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        backend.chmod(&file, 0o4755, false).unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o755, "file setid bits must be stripped");

        let dir = tmp.path().join("d");
        std::fs::create_dir(&dir).unwrap();
        backend.chmod(&dir, 0o4770, false).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        // SUID 剥离、rwx 收敛 770；SGID 允许被内核再清（非 root 对组不匹配
        // 目录 chmod 时 BSD 内核清 SGID——保留语义由纯函数测试钉死）。
        assert_eq!(mode & 0o777, 0o770, "dir rwx bits");
        assert_eq!(mode & 0o4000, 0, "dir SUID must be dropped");
        assert!(
            mode & 0o6000 == 0o2000 || mode & 0o6000 == 0,
            "unexpected: {:o}",
            mode
        );

        let sub = dir.join("s");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("f2"), b"x").unwrap();
        backend.chmod(&dir, 0o2770, true).unwrap();
        let mode = std::fs::metadata(&sub).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o770, "subdir rwx bits");
        assert_eq!(mode & 0o4000, 0, "subdir SUID must be dropped");
        let mode = std::fs::metadata(sub.join("f2"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o660);
    }

    /// write_file 剥 setid + 直接 persist：4755 落盘 755，已存在目标原子替换。
    #[test]
    fn write_file_strips_setid_and_replaces_atomically() {
        use std::os::unix::fs::PermissionsExt;

        let backend = SetuidBackend;
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("cfg");
        backend
            .write_file(&target, b"old", Some(0o4755), None, None)
            .unwrap();
        let meta = std::fs::metadata(&target).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o755, "setid stripped");
        assert_eq!(std::fs::read(&target).unwrap(), b"old");

        backend
            .write_file(&target, b"new", Some(0o640), None, None)
            .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o640
        );
    }

    #[test]
    fn validate_setuid_dnf_args_accepts_engine_forms_and_rejects_redirection() {
        let s = |v: &[&str]| -> Vec<String> { v.iter().map(|x| x.to_string()).collect() };
        assert!(
            validate_setuid_dnf_args(&s(&["install", "-y", "--setopt=keepcache=1", "bash"]))
                .is_ok()
        );
        assert!(validate_setuid_dnf_args(&s(&["clean", "metadata"])).is_ok());
        assert!(validate_setuid_dnf_args(&s(&["install", "-y", "dnf-plugins-core"])).is_ok());
        // 快照 resolve 形态（--downloadonly 跳过 rpm 事务执行）
        assert!(validate_setuid_dnf_args(&s(&[
            "install",
            "-y",
            "--downloadonly",
            "--setopt=keepcache=1",
            "bash"
        ]))
        .is_ok());
        // 配置/仓库源重定向：含与 helper 固定注入同形的透传也拒绝。
        let dir = "/var/lib/crbs-engine/dnf-repos/mydist";
        for evil in [
            s(&["install", "-y", &format!("--config={dir}/dnf.conf")]),
            s(&["install", "-y", &format!("--setopt=reposdir={dir}")]),
            s(&["install", "-y", "--config"]),
            s(&["install", "-y", "--setopt", "reposdir=/x"]),
            s(&["install", "-y", "--repofrompath=r,/tmp/r"]),
            s(&["install", "-y", "--installroot=/etc"]),
            s(&["install", "-y", "-x"]),
            s(&["install", "-y"]),
            s(&["repoquery", "bash"]),
            s(&[]),
        ] {
            assert!(
                validate_setuid_dnf_args(&evil).is_err(),
                "must be rejected: {evil:?}"
            );
        }
    }

    /// 受信参数注入形态（与 helper 侧同步）：恰好两个内联形态参数。
    #[test]
    fn spawn_dnf_injects_trusted_config_and_reposdir() {
        let backend = SetuidBackend;
        let tmp = tempfile::tempdir().unwrap();
        let repos_dir = tmp.path().join("dnf-repos/mydist");
        std::fs::create_dir_all(&repos_dir).unwrap();
        std::fs::write(repos_dir.join(TRUSTED_DNF_CONF_NAME), b"[main]\n").unwrap();

        let cmd = backend
            .spawn_dnf(
                Path::new("/var/lib/crbs-engine/products/mydist/base"),
                "9",
                &repos_dir,
                &["install".to_string(), "-y".to_string(), "bash".to_string()],
            )
            .unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&format!("--config={}/dnf.conf", repos_dir.display())));
        assert!(args.contains(&format!("--setopt=reposdir={}", repos_dir.display())));
        let ir = args
            .iter()
            .position(|a| a == "/var/lib/crbs-engine/products/mydist/base")
            .unwrap();
        let cfg = args
            .iter()
            .position(|a| a.starts_with("--config="))
            .unwrap();
        let pkg = args.iter().position(|a| a == "bash").unwrap();
        assert!(ir < cfg && cfg < pkg, "args: {args:?}");

        let injected =
            trusted_dnf_injected_args(&repos_dir.join(TRUSTED_DNF_CONF_NAME), &repos_dir);
        assert_eq!(
            injected[0],
            format!("--config={}/dnf.conf", repos_dir.display())
        );
        assert_eq!(
            injected[1],
            format!("--setopt=reposdir={}", repos_dir.display())
        );
    }

    #[test]
    fn spawn_dnf_fails_closed_when_trusted_repos_missing() {
        let backend = SetuidBackend;
        let tmp = tempfile::tempdir().unwrap();
        let repos_dir = tmp.path().join("dnf-repos/mydist");
        let args = vec!["clean".to_string(), "metadata".to_string()];

        let err = backend
            .spawn_dnf(Path::new("/i"), "9", &repos_dir, &args)
            .unwrap_err()
            .to_string();
        assert!(err.contains("refusing to fall back"), "unexpected: {err}");

        std::fs::create_dir_all(&repos_dir).unwrap();
        let err = backend
            .spawn_dnf(Path::new("/i"), "9", &repos_dir, &args)
            .unwrap_err()
            .to_string();
        assert!(err.contains("dnf.conf"), "unexpected: {err}");
        assert!(err.contains("refusing to fall back"), "unexpected: {err}");
    }
}
