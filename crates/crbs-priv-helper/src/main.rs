// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! crbs-priv-helper：CRBS 特权 one-shot helper。命令行接收参数，每次
//! 执行一个特权操作后立即退出，stdout 最后一行输出 JSON 结果。

use std::io::Read;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
#[cfg(target_os = "linux")]
use nix::unistd::{Gid, Uid};
use serde::Serialize;

use crbs_priv_helper::allowed_paths;
use crbs_priv_helper::capability::{self, Capability};
use crbs_priv_helper::ops;
use crbs_priv_helper::spawn;
use crbs_priv_helper::validate;
use crbs_priv_helper::{success, Error, Outcome};

#[derive(Parser)]
#[command(
    name = "crbs-priv-helper",
    about = "Privileged one-shot helper for CRBS"
)]
struct Cli {
    /// CRBS 数据根目录，所有传入路径必须位于其下。
    #[arg(long, global = true, default_value = "/var/lib/crbs")]
    crbs_root: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 通用 mount。
    Mount {
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        fstype: Option<String>,
        #[arg(long)]
        flags: Option<u64>,
        #[arg(long)]
        data: Option<String>,
    },
    /// 挂载 overlayfs。
    MountOverlay {
        #[arg(long, required = true)]
        lower: Vec<PathBuf>,
        #[arg(long)]
        upper: PathBuf,
        #[arg(long)]
        work: PathBuf,
        #[arg(long)]
        target: PathBuf,
    },
    /// 卸载路径。
    Umount {
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        flags: Option<u32>,
    },
    /// 创建目录并设置属主/权限。
    MkdirChown {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        user: String,
        #[arg(long)]
        group: String,
        /// 权限，八进制字符串，例如 755、2770。
        #[arg(long)]
        mode: String,
    },
    /// 修改文件或目录的属主（支持递归）。
    Chown {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        uid: u32,
        #[arg(long)]
        gid: u32,
        #[arg(long)]
        recursive: bool,
    },
    /// 修改文件或目录的权限（支持递归）。
    Chmod {
        #[arg(long)]
        path: PathBuf,
        /// 权限，八进制字符串，例如 755、2770。
        #[arg(long)]
        mode: String,
        #[arg(long)]
        recursive: bool,
    },
    /// 写入文件（父目录不存在时自动创建）；`--content` / `--content-stdin`
    /// 二选一，互斥。
    WriteFile {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        content: Option<String>,
        /// 从标准输入读取文件内容，避免命令行参数暴露数据且支持二进制。
        #[arg(long)]
        content_stdin: bool,
        /// 权限，八进制字符串，例如 644、440。
        #[arg(long)]
        mode: Option<String>,
        #[arg(long)]
        uid: Option<u32>,
        #[arg(long)]
        gid: Option<u32>,
    },
    /// 清理 crbs_root 下的孤儿挂载点（可选扩展扫描域到构建临时目录）。
    /// 版本耦合：旧版 helper 不识别 `--tmp-dir`——worker GC 只记错误不阻断启动。
    GcOrphanMounts {
        #[arg(long)]
        crbs_root: PathBuf,
        /// 额外扫描域：构建临时目录，可重复传入。每个值过
        /// `validate_path_normalized`（与 umount 同一信任域：绝对、无 `..`/
        /// symlink 组件，位于标准临时目录或 allowed_paths 下）；扫描只命中
        /// `{tmp}/.tmp*` 下容器伪 fs 挂载，绝不作用于 tmp 目录根本身。
        #[arg(long)]
        tmp_dir: Vec<PathBuf>,
    },
    /// 递归删除一个或多个路径（文件或目录）。先过 `validate_path` +
    /// `allowed_paths` 校验，调用时收窄至 `CAP_DAC_OVERRIDE`；fs_walk fd
    /// 相对遍历（TOCTOU 防护），symlink 删本身不跟随。
    RmRf {
        #[arg(long, required = true)]
        path: Vec<PathBuf>,
    },
    /// 在 chroot 环境中执行命令（exec 目标进程，不返回 JSON）。
    SpawnChroot {
        #[arg(long)]
        rootfs: PathBuf,
        #[arg(long)]
        program: String,
        #[arg(long, allow_hyphen_values = true)]
        arg: Vec<String>,
        #[arg(long)]
        no_network: bool,
    },
    /// 执行 systemd-nspawn（exec 目标进程，不返回 JSON）。
    SpawnNspawn {
        /// nspawn 完整命令行，第一个元素必须是 systemd-nspawn 可执行文件路径。
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
    /// 以 root 执行 dnf（exec 目标进程，不返回 JSON）。版本耦合：旧版
    /// helper 不识别 `--repos-dir`——helper 与 crbs-core 需同版本部署。
    SpawnDnf {
        #[arg(long)]
        installroot: PathBuf,
        #[arg(long)]
        releasever: String,
        /// host 受信 repo 目录（`{crbs_root}/dnf-repos/{product}`）。dnf 的
        /// repo 来源被钉死到该目录，installroot 内 repo 文件不再被读取。
        #[arg(long)]
        repos_dir: PathBuf,
        #[arg(long, allow_hyphen_values = true)]
        arg: Vec<String>,
    },
    /// 写入 cgroup v2 控制文件（资源限制 / cgroup.kill 通道；消费方 crbs-core
    /// nspawn 后端）。路径须严格位于 /sys/fs/cgroup/ 之下且文件名在白名单内，
    /// 值仅数字/空格/小写字母（自动追加换行）；版本耦合：旧版 helper 不识别。
    WriteCgroupFile {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        value: String,
    },
    /// 取消时杀构建进程组（pgid 为负 pid 约定；helper 以 root 身份 SIGKILL，
    /// worker 不持 root）。
    KillProcessGroup {
        #[arg(long)]
        pgid: i32,
    },
    /// Terminates a crbs-owned nspawn machine (kill escalation last resort).
    /// `--name` must match `crbs-[0-9a-fA-F-]{8,64}` (crbs machine namespace
    /// only); on cgroup v2 writes the scope `cgroup.kill`, otherwise SIGKILLs
    /// scope members resolved via /proc. Idempotent when already gone.
    /// Version coupling: older helpers reject this subcommand.
    TerminateMachine {
        #[arg(long)]
        name: String,
    },
}

#[derive(Serialize)]
struct ResultBody<T: Serialize> {
    ok: Option<T>,
    err: Option<String>,
}

/// 结果 JSON 落 stdout 最后一行；序列化失败静默跳过（one-shot 协议尽力输出）。
fn emit_json<T: Serialize>(body: &ResultBody<T>) {
    if let Ok(json) = serde_json::to_string(body) {
        println!("{}", json);
    }
}

fn main() {
    let cli = Cli::parse();
    init_tracing();

    match run(cli) {
        Ok(Outcome::Success) => {
            emit_json(&ResultBody::<()> {
                ok: Some(()),
                err: None,
            });
        }
        Ok(Outcome::Exec(mut cmd)) => {
            use std::os::unix::process::CommandExt;
            let err = cmd.exec();
            tracing::error!(error = %err, "helper exec failed");
            std::process::exit(126);
        }
        Err(e) => {
            // M-8：错误串可含调用方控制的路径/参数，进 tracing 与 stdout JSON
            // err 前都过 escape_ctrl——控制字符不得穿过日志/协议边界。
            let err = escape_ctrl(&e.to_string());
            tracing::error!(error = %err, "helper operation failed");
            emit_json(&ResultBody::<()> {
                ok: None,
                err: Some(err),
            });
            std::process::exit(1);
        }
    }
}

/// setuid-root 不读调用方环境：filter 固定 "info"（审计行即 info 级；
/// debug 不在 setuid 场景开放）；调试改这里重编译，不留 env 后门。
fn log_filter() -> &'static str {
    "info"
}

fn init_tracing() {
    // stderr 恒为父进程 pipe：彩色无意义，且 ANSI 会被父进程日志层转义成 \x1b 字面量。
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(log_filter())
        .with_ansi(false)
        .try_init();
}

/// 解析八进制权限字符串（如 "755"、"2770"）为 mode_t。
fn parse_mode(s: &str) -> Result<u32, Error> {
    u32::from_str_radix(s, 8).map_err(|e| Error::Validation(format!("invalid mode '{s}': {e}")))
}

// ── mount 参数白名单（漏洞 1 修复）──────────────────────────────────
// source/fstype/flags/data 全走白名单：bind 任意宿主路径（如 /）进允许根，
// 再经 chown/rm-rf 递归穿透 = 全盘提权原语；白名单 = crbs-core 实际调用形态。

/// mount(2) flag 常量（Linux ABI；纯数值比较，与编译目标平台无关）。
mod mount_flags {
    pub const MS_RDONLY: u64 = 1;
    pub const MS_REMOUNT: u64 = 1 << 5;
    pub const MS_BIND: u64 = 1 << 12;
    pub const MS_REC: u64 = 1 << 14;
    pub const MS_PRIVATE: u64 = 1 << 18;
    /// 允许的位集：任何其他位置位即拒绝。
    pub const ALLOWED_MASK: u64 = MS_BIND | MS_REC | MS_PRIVATE | MS_RDONLY | MS_REMOUNT;
}

/// fstype 白名单：{None} ∪ {proc, sysfs, devpts, tmpfs}（crbs-core 实际
/// 调用面；其余 fstype 无调用方）。
const MOUNT_ALLOWED_FSTYPES: &[&str] = &["proc", "sysfs", "devpts", "tmpfs"];

/// MS_BIND 场景下硬编码的宿主设备树白名单：在用仅 /dev，/dev/pts、/proc、
/// /sys 同权；其余 bind source 须位于允许根/临时目录下——bind 任意宿主路径
/// = 以 root 暴露给调用方可控容器，`crbs shell --bind` 因此被收紧。
const MOUNT_ALLOWED_BIND_DEVICES: &[&str] = &["/dev", "/dev/pts", "/proc", "/sys"];

/// mount data 选项键白名单（仅 devpts/tmpfs 携带 data）：devpts 用
/// newinstance/ptmxmode/mode/gid，余为 tmpfs 限额/属主键；其他键（suid/dev/exec…）拒绝。
const MOUNT_ALLOWED_DATA_KEYS: &[&str] = &[
    "newinstance",
    "ptmxmode",
    "mode",
    "gid",
    "uid",
    "size",
    "nr_inodes",
];

/// mount 子命令参数校验（target 的路径校验在调用处另行执行）。
fn validate_mount_request(
    source: Option<&str>,
    fstype: Option<&str>,
    flags: u64,
    data: Option<&str>,
    allowed_paths: &[PathBuf],
) -> Result<(), Error> {
    if let Some(fs) = fstype {
        if !MOUNT_ALLOWED_FSTYPES.contains(&fs) {
            return Err(Error::Validation(format!(
                "mount fstype '{fs}' is not allowed (allowed: none or {})",
                MOUNT_ALLOWED_FSTYPES.join(", ")
            )));
        }
    }

    let unknown = flags & !mount_flags::ALLOWED_MASK;
    if unknown != 0 {
        return Err(Error::Validation(format!(
            "mount flags {flags} contain disallowed bits {unknown:#x} \
             (allowed bits: MS_RDONLY|MS_REMOUNT|MS_BIND|MS_REC|MS_PRIVATE)"
        )));
    }

    if let Some(src) = source {
        if flags & mount_flags::MS_BIND != 0 {
            // bind：source 须绝对路径（相对路径按调用方 cwd 解析，不可控），
            // 且位于允许根/临时目录下，或属设备树白名单。
            if !src.starts_with('/') {
                return Err(Error::Validation(format!(
                    "mount bind source '{src}' must be an absolute path"
                )));
            }
            let dev_tree_ok = MOUNT_ALLOWED_BIND_DEVICES.contains(&src);
            if !dev_tree_ok && validate::validate_path(Path::new(src), allowed_paths).is_err() {
                return Err(Error::Validation(format!(
                    "mount bind source '{src}' escapes allowed roots and is not one of {}; \
                     to bind additional host paths, ask the admin to add them to \
                     allowed_paths in /etc/crbs/priv-helper.toml",
                    MOUNT_ALLOWED_BIND_DEVICES.join(", ")
                )));
            }
        } else {
            // 非 bind：source 只能是与 fstype 同名的伪文件系统名。
            let ok = MOUNT_ALLOWED_FSTYPES.contains(&src) && fstype == Some(src);
            if !ok {
                return Err(Error::Validation(format!(
                    "mount source '{src}' is not allowed for non-bind mount \
                     (must equal one of {} and match --fstype)",
                    MOUNT_ALLOWED_FSTYPES.join(", ")
                )));
            }
        }
    }

    // data 选项键白名单（值域校验见 validate::validate_mount_data_value）。
    if let Some(d) = data {
        if !matches!(fstype, Some("devpts") | Some("tmpfs")) {
            return Err(Error::Validation(format!(
                "mount data is only allowed for fstype devpts/tmpfs, got fstype {fstype:?}"
            )));
        }
        for opt in d.split(',') {
            // split_once 只切首个 '='：值里再出现 '=' 落入值域校验被拒绝。
            let (key, value) = match opt.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (opt, None),
            };
            if key.is_empty() || !MOUNT_ALLOWED_DATA_KEYS.contains(&key) {
                return Err(Error::Validation(format!(
                    "mount data option '{opt}' is not allowed \
                     (allowed keys: {})",
                    MOUNT_ALLOWED_DATA_KEYS.join(", ")
                )));
            }
            validate::validate_mount_data_value(key, value)?;
        }
    }

    Ok(())
}

/// SpawnNspawn 的 exec 能力集：drop_bounding_set_to 与 set_ambient_caps_for_exec
/// 共用同集（nspawn 自行沙箱，SYS_ADMIN/SYS_CHROOT 随 exec 保留，与 chroot 腿
/// 防双 chroot 逃逸的 ambient 剔除不同）。
const NSPAWN_EXEC_CAPS: &[Capability] = &[
    Capability::CAP_SYS_ADMIN,
    Capability::CAP_SYS_CHROOT,
    Capability::CAP_SETUID,
    Capability::CAP_SETGID,
    Capability::CAP_SETPCAP,
    Capability::CAP_AUDIT_CONTROL,
    Capability::CAP_AUDIT_WRITE,
    Capability::CAP_SETFCAP,
    Capability::CAP_DAC_OVERRIDE,
    Capability::CAP_CHOWN,
    Capability::CAP_FOWNER,
];

/// exec 特权子进程前把 real/effective/saved uid 与 gid 恢复到 0 并清空补充组
///（目标程序查 geteuid()==0 且以 root 写 installroot；CAP_SETUID/SETGID 使本步可行）。
#[cfg(target_os = "linux")]
fn restore_root_identity() -> Result<(), Error> {
    // setgroups 须先于 setuid/setgid（丢 CAP_SETGID 后不可再调用）：setgid(0)
    // 只改主组，补充组会原样跟随 exec——组身份是独立 DAC 原语，不得保留。
    nix::unistd::setgroups(&[])
        .map_err(|e| Error::Io(std::io::Error::other(format!("setgroups(): {e}"))))?;
    nix::unistd::setuid(Uid::from_raw(0))
        .map_err(|e| Error::Io(std::io::Error::other(format!("setuid(0): {e}"))))?;
    nix::unistd::setgid(Gid::from_raw(0))
        .map_err(|e| Error::Io(std::io::Error::other(format!("setgid(0): {e}"))))?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn restore_root_identity() -> Result<(), Error> {
    Ok(())
}

/// 控制字符转义：`\t`/`\r`/`\n` 短转义，其余 ASCII 控制字符（C0/DEL）统一
/// `\xHH`——调用方可控字段含 `\n` 可伪造下一行记录，出口统一转义保单行。
fn escape_ctrl(s: &str) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '\x00'..='\x1f' | '\x7f' => {
                // match 范围保证 c <= 0x7f，`as u8` 截断无损。
                let _ = write!(out, "\\x{:02x}", c as u8);
            }
            _ => out.push(c),
        }
    }
    out
}

/// 生成特权操作审计行：op 名 + 关键参数 + caller uid；可能含 secret 的字段
/// （content/data）只记长度不落内容，出口经 escape_ctrl 转义保单行。
fn audit_line(cmd: &Command, caller_uid: u32) -> String {
    use std::fmt::Write as _;

    fn join_paths(paths: &[PathBuf], sep: &str) -> String {
        paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(sep)
    }

    let mut s = "audit op=".to_string();
    match cmd {
        Command::Mount {
            source,
            target,
            fstype,
            flags,
            data,
        } => {
            // data 可携带凭据（cifs password=…）且随审计行落构建日志，
            // 只记长度（与 content 同规则）。
            let data_len = data.as_ref().map(|d| d.len());
            let _ = write!(
                s,
                "mount source={source:?} target={} fstype={fstype:?} flags={flags:?} data_len={data_len:?}",
                target.display()
            );
        }
        Command::MountOverlay {
            lower,
            upper,
            work,
            target,
        } => {
            let _ = write!(
                s,
                "mount-overlay lower={} upper={} work={} target={}",
                join_paths(lower, ":"),
                upper.display(),
                work.display(),
                target.display()
            );
        }
        Command::Umount { target, flags } => {
            let _ = write!(s, "umount target={} flags={flags:?}", target.display());
        }
        Command::MkdirChown {
            path,
            user,
            group,
            mode,
        } => {
            let _ = write!(
                s,
                "mkdir-chown path={} user={user} group={group} mode={mode}",
                path.display()
            );
        }
        Command::Chown {
            path,
            uid,
            gid,
            recursive,
        } => {
            let _ = write!(
                s,
                "chown path={} uid={uid} gid={gid} recursive={recursive}",
                path.display()
            );
        }
        Command::Chmod {
            path,
            mode,
            recursive,
        } => {
            let _ = write!(
                s,
                "chmod path={} mode={mode} recursive={recursive}",
                path.display()
            );
        }
        Command::WriteFile {
            path,
            content,
            content_stdin,
            mode,
            uid,
            gid,
        } => {
            // content 只记长度，绝不落内容（可能含 secret）。
            let content_len = content.as_ref().map(|c| c.len());
            let _ = write!(
                s,
                "write-file path={} content_len={content_len:?} content_stdin={content_stdin} mode={mode:?} uid={uid:?} gid={gid:?}",
                path.display()
            );
        }
        Command::GcOrphanMounts { crbs_root, tmp_dir } => {
            let _ = write!(
                s,
                "gc-orphan-mounts crbs_root={} tmp_dirs={}",
                crbs_root.display(),
                join_paths(tmp_dir, ",")
            );
        }
        Command::RmRf { path } => {
            let _ = write!(s, "rm-rf path={}", join_paths(path, ","));
        }
        Command::SpawnChroot {
            rootfs,
            program,
            arg,
            no_network,
        } => {
            let _ = write!(
                s,
                "spawn-chroot rootfs={} program={program} arg={arg:?} no_network={no_network}",
                rootfs.display()
            );
        }
        Command::SpawnNspawn { argv } => {
            // --setenv 值可能携带凭证（当前仅注入 LC_ALL，防漂移）：只记 KEY=，内联/分离形态同规则脱敏。
            let mut redacted: Vec<String> = Vec::with_capacity(argv.len());
            let mut i = 0;
            while i < argv.len() {
                let a = &argv[i];
                if let Some(v) = a.strip_prefix("--setenv=") {
                    let key = v.split('=').next().unwrap_or("?");
                    redacted.push(format!("--setenv={key}="));
                } else if a == "--setenv" {
                    redacted.push(a.clone());
                    if let Some(next) = argv.get(i + 1) {
                        let key = next.split('=').next().unwrap_or("?");
                        redacted.push(format!("{key}="));
                        i += 1;
                    }
                } else {
                    redacted.push(a.clone());
                }
                i += 1;
            }
            let _ = write!(s, "spawn-nspawn argv={redacted:?}");
        }
        Command::SpawnDnf {
            installroot,
            releasever,
            repos_dir,
            arg,
        } => {
            let _ = write!(
                s,
                "spawn-dnf installroot={} releasever={releasever} repos_dir={} arg={arg:?}",
                installroot.display(),
                repos_dir.display()
            );
        }
        Command::WriteCgroupFile { path, value } => {
            // value 已过字符集白名单（数字/空格/小写字母），无 secret 面。
            let _ = write!(s, "write-cgroup-file path={} value={value}", path.display());
        }
        Command::KillProcessGroup { pgid } => {
            let _ = write!(s, "kill-process-group pgid={pgid}");
        }
        Command::TerminateMachine { name } => {
            let _ = write!(s, "terminate-machine name={name}");
        }
    }
    let _ = write!(s, " caller_uid={caller_uid}");
    escape_ctrl(&s)
}

/// 调用者 real uid（审计用，与 `verify_caller` 判定同源）；非 Linux 仅开发编译占位。
#[cfg(target_os = "linux")]
fn caller_uid() -> u32 {
    nix::unistd::getuid().as_raw()
}

#[cfg(not(target_os = "linux"))]
fn caller_uid() -> u32 {
    0
}

/// gc-orphan-mounts 的 `--crbs-root` 必须 normalize 后与配置 root 等值（∈
/// 允许根集合：server root ∪ 引擎 root）；只过前缀校验则 crbs 组成员可对
/// /tmp 下任意路径的挂载 MNT_DETACH（DoS）。返回规范化路径供 ops 消费。
fn check_gc_root(cli_root: &Path, allowed_roots: &[PathBuf]) -> Result<PathBuf, Error> {
    let normalized = validate::normalize_path(cli_root)?;
    if !allowed_roots.contains(&normalized) {
        return Err(Error::Validation(format!(
            "gc-orphan-mounts --crbs-root {} is not one of the configured crbs roots: {}",
            normalized.display(),
            allowed_roots
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(normalized)
}

fn run(cli: Cli) -> Result<Outcome, Error> {
    // 防御纵深：禁止 ptrace 附加（即使 YAMA ptrace_scope=0）；失败只降级
    // 本层、warn 继续（PR_SET_SECUREBITS 则失败即退）。
    #[cfg(target_os = "linux")]
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) 仅设置进程标志，无内存安全影响。
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
            tracing::warn!(
                error = %std::io::Error::last_os_error(),
                "prctl(PR_SET_DUMPABLE, 0) failed; ptrace hardening not applied"
            );
        }
    }

    capability::verify_caller()?;
    capability::keep_caps_if_setuid()?;

    // 审计：所有特权操作先落 info 级审计行（含被校验拒绝的尝试）。
    let caller_uid = caller_uid();
    tracing::info!("{}", audit_line(&cli.command, caller_uid));

    // 配置以 root-owned /etc/crbs 为准（priv-helper.toml 自举检查不可放宽）：
    // --crbs-root 仅一致性校验，不得扩大允许路径集合。
    let config_dir = Path::new("/etc/crbs");
    // A-1：目录权限检查先于 priv-helper.toml 读取——group/other 可写目录可在
    // 文件检查通过与读取之间 rename-swap 该文件（可对 root 属主文件 unlink/
    // rename）；失败仅 relax_config_permissions=true（配置不受信，限开发机）放行。
    let config_dir_check = allowed_paths::verify_config_dir_strict(config_dir);
    let helper_cfg = allowed_paths::load_helper_config(config_dir)?;
    if let Err(e) = config_dir_check {
        if !helper_cfg.relax_config_permissions {
            return Err(e);
        }
        tracing::warn!(
            dir = %config_dir.display(),
            "config dir permission check relaxed by priv-helper.toml"
        );
    }
    // 允许集 = server root ∪ 引擎 root ∪ worker root（server 本地构建、引擎 CLI
    // 与 worker 共用本 helper；worker.toml 配置了 crbs_root 即采信，未配置时
    // worker 进程缺省回落 server root）；集合外一律 fail-closed。root 快照随
    // 集合单次读盘返回，勿为取 root 再读一遍配置（两读间文件可被换出）。
    let allowed_paths::AllowedPaths {
        paths: mut allowed_paths,
        server_root,
        engine_root,
        worker_root,
    } = allowed_paths::load_allowed_paths(config_dir, &helper_cfg)?;
    let cli_root = validate::normalize_path(&cli.crbs_root)?;
    if cli_root != server_root && cli_root != engine_root && worker_root.as_ref() != Some(&cli_root)
    {
        let mut configured = format!(
            "{} (server.toml) or {} (crbs.toml)",
            server_root.display(),
            engine_root.display()
        );
        if let Some(worker_root) = &worker_root {
            configured.push_str(&format!(" or {} (worker.toml)", worker_root.display()));
        }
        return Err(Error::Validation(format!(
            "--crbs-root {} is not one of the configured crbs roots: {}",
            cli_root.display(),
            configured
        )));
    }
    if !allowed_paths.contains(&server_root) {
        allowed_paths.push(server_root.clone());
    }
    if !allowed_paths.contains(&engine_root) {
        allowed_paths.push(engine_root.clone());
    }
    if let Some(worker_root) = &worker_root {
        if !allowed_paths.contains(worker_root) {
            allowed_paths.push(worker_root.clone());
        }
    }

    match cli.command {
        Command::Mount {
            source,
            target,
            fstype,
            flags,
            data,
        } => {
            // 漏洞 1：source/fstype/flags/data 白名单（见上方常量）。
            validate_mount_request(
                source.as_deref(),
                fstype.as_deref(),
                flags.unwrap_or(0),
                data.as_deref(),
                &allowed_paths,
            )?;
            // 漏洞 2：消费规范化路径（校验与作用路径严格一致）；目标须严格在
            // 允许根/临时目录之下——等于根会覆盖数据根或共享临时区。
            let target = validate::validate_mount_target(&target, &allowed_paths)?;
            capability::drop_bounding_set_to(&[
                // creator_cred：overlayfs 记录挂载者凭据，copy-up（ovl_set_attr）
                // 同以该凭据执行，须保留 CHOWN/FOWNER；DAC_OVERRIDE 穿 0770 临时目录。
                Capability::CAP_SYS_ADMIN,
                Capability::CAP_DAC_OVERRIDE,
                Capability::CAP_CHOWN,
                Capability::CAP_FOWNER,
            ])?;
            success(ops::mount(
                source.as_deref(),
                &target,
                fstype.as_deref(),
                flags.unwrap_or(0),
                data.as_deref(),
            ))
        }
        Command::MountOverlay {
            lower,
            upper,
            work,
            target,
        } => {
            // 漏洞 2：全部路径规范化后交给 ops（overlay 选项串按路径文本拼接，必须与校验同形态）。
            let lower = lower
                .iter()
                .map(|p| validate::validate_path_normalized(p, &allowed_paths))
                .collect::<Result<Vec<_>, _>>()?;
            let upper = validate::validate_path_normalized(&upper, &allowed_paths)?;
            let work = validate::validate_path_normalized(&work, &allowed_paths)?;
            let target = validate::validate_mount_target(&target, &allowed_paths)?;
            capability::drop_bounding_set_to(&[
                // creator_cred 同 mount 分支；DAC_OVERRIDE 穿过调用方 0770 临时目录。
                // creator_cred 主导 overlay 上层全部 xattr 操作（含 security.capability
                // 的 setxattr 鉴权）——缺 SETFCAP 时容器内装 %caps 包必 EPERM。
                Capability::CAP_SYS_ADMIN,
                Capability::CAP_DAC_OVERRIDE,
                Capability::CAP_CHOWN,
                Capability::CAP_FOWNER,
                Capability::CAP_SETFCAP,
            ])?;
            success(ops::mount_overlay(&lower, &upper, &work, &target))
        }
        Command::Umount { target, flags } => {
            let target = validate::validate_path_normalized(&target, &allowed_paths)?;
            // 域收紧：合法卸载域 = 严格位于某 allowed root 之下（根本身拒绝），
            // 或位于 /tmp、/var/tmp、/dev/shm 下且首级组件 ".tmp*"——与 GC 扫描
            // 域对齐，否则共享临时区任意挂载点可被 MNT_DETACH（同机第三方 DoS）。
            // 临时域不过滤 fstype：bind 的 mountinfo 报源宿主 fs，引擎 bind 目标
            // 均形如 {tmp_dir}/.tmpXXXX/root/…，过滤会让 teardown umount 必败、
            // 挂载泄漏、temp EBUSY；命名谓词（.tmp* 首级组件）已收口 DoS 面。
            validate::umount_target_domain(&target, &allowed_paths).ok_or_else(|| {
                Error::Validation(format!(
                    "umount target {} is outside the allowed umount domain; \
                     must be strictly below an allowed root, or below a standard \
                     temp dir (/tmp, /var/tmp, /dev/shm) with a '.tmp*' first \
                     path component",
                    target.display()
                ))
            })?;
            // 调用方只用 MNT_DETACH（lazy 卸载）；其他 flag 位无合法用途。
            const MNT_DETACH: u32 = 2; // Linux ABI（include/uapi/linux/mount.h）
            let flags = flags.unwrap_or(0);
            if flags & !MNT_DETACH != 0 {
                return Err(Error::Validation(format!(
                    "umount flags {flags} contain bits other than MNT_DETACH ({MNT_DETACH})"
                )));
            }
            capability::drop_bounding_set_to(&[
                // 同 mount 分支集合：MNT_DETACH 后仍有 in-flight copy-up 以挂载者凭据执行（creator_cred）。
                // overlay 挂载场景下 SETFCAP 属该凭据集（xattr 鉴权同 mount_overlay）。
                Capability::CAP_SYS_ADMIN,
                Capability::CAP_DAC_OVERRIDE,
                Capability::CAP_CHOWN,
                Capability::CAP_FOWNER,
                Capability::CAP_SETFCAP,
            ])?;
            success(ops::umount(&target, flags))
        }
        Command::MkdirChown {
            path,
            user,
            group,
            mode,
        } => {
            let path = validate::validate_path_normalized(&path, &allowed_paths)?;
            let mode = parse_mode(&mode)?;
            // 根等值放行但参数收死到权限不变量值（合法形态仅 root 首启收敛/
            // 显式 product_root init），拦组员夺取数据根。
            if validate::equals_allowed_root(&path, &allowed_paths) {
                validate::validate_root_equal_mkdir_chown(&user, &group, mode, caller_uid == 0)?;
            }
            capability::drop_bounding_set_to(&[
                Capability::CAP_CHOWN,
                Capability::CAP_FOWNER,
                Capability::CAP_DAC_OVERRIDE,
            ])?;
            success(ops::mkdir_chown(&path, &user, &group, mode))
        }
        Command::Chown {
            path,
            uid,
            gid,
            recursive,
        } => {
            let path = validate::validate_path_normalized(&path, &allowed_paths)?;
            // 根等值收死到 root:crbs（同 mkdir-chown 分支；非 Linux 无组解析，chown 走 Unsupported）。
            if validate::equals_allowed_root(&path, &allowed_paths) {
                #[cfg(target_os = "linux")]
                {
                    let crbs_gid = capability::resolve_crbs_group_gid()
                        .map_err(|e| {
                            Error::Validation(format!(
                                "root-equal chown requires the crbs group: {e}"
                            ))
                        })?
                        .as_raw();
                    validate::validate_root_equal_chown(uid, gid, crbs_gid)?;
                }
            }
            capability::drop_bounding_set_to(&[
                Capability::CAP_CHOWN,
                Capability::CAP_FOWNER,
                Capability::CAP_DAC_OVERRIDE,
            ])?;
            success(ops::chown(&path, uid, gid, recursive))
        }
        Command::Chmod {
            path,
            mode,
            recursive,
        } => {
            let path = validate::validate_path_normalized(&path, &allowed_paths)?;
            let mode = parse_mode(&mode)?;
            // 根等值收死到 2770（语义同 mkdir-chown 分支）。
            if validate::equals_allowed_root(&path, &allowed_paths) {
                validate::validate_root_equal_chmod(mode)?;
            }
            capability::drop_bounding_set_to(&[
                Capability::CAP_FOWNER,
                Capability::CAP_DAC_OVERRIDE,
            ])?;
            success(ops::chmod(&path, mode, recursive))
        }
        Command::WriteFile {
            path,
            content,
            content_stdin,
            mode,
            uid,
            gid,
        } => {
            // 叶子 symlink 放行（ops::write_file 的 fd+rename 只替换链接本身
            // 不跟随）；中间组件 symlink 仍 fail-closed。
            let path = validate::validate_path_normalized_leaf_replace(&path, &allowed_paths)?;

            if content.is_some() && content_stdin {
                return Err(Error::Validation(
                    "--content and --content-stdin are mutually exclusive".into(),
                ));
            }
            // M-7：stdin 内容上限 16 MiB——同步管道读无界内容会耗尽内存/管道。
            const MAX_STDIN_CONTENT: usize = 16 * 1024 * 1024;
            let content_bytes: Vec<u8> = if content_stdin {
                // take(上限+1)：读到上限+1 字节即可判定超限，不无界读入。
                let mut buf = Vec::new();
                let mut limited = std::io::stdin().take((MAX_STDIN_CONTENT + 1) as u64);
                limited
                    .read_to_end(&mut buf)
                    .map_err(|e| Error::Io(std::io::Error::other(format!("read stdin: {e}"))))?;
                if buf.len() > MAX_STDIN_CONTENT {
                    return Err(Error::Validation(format!(
                        "--content-stdin content exceeds {} MiB limit",
                        MAX_STDIN_CONTENT / (1024 * 1024)
                    )));
                }
                buf
            } else if let Some(c) = content {
                c.into_bytes()
            } else {
                return Err(Error::Validation(
                    "either --content or --content-stdin must be provided".into(),
                ));
            };

            let mode = mode.map(|m| parse_mode(&m)).transpose()?;

            capability::drop_bounding_set_to(&[
                Capability::CAP_CHOWN,
                Capability::CAP_FOWNER,
                Capability::CAP_DAC_OVERRIDE,
            ])?;
            success(ops::write_file(&path, &content_bytes, mode, uid, gid))
        }
        Command::GcOrphanMounts { crbs_root, tmp_dir } => {
            let normalized_root = check_gc_root(&crbs_root, &allowed_paths)?;
            // 扩展扫描域过与 umount 同源的路径校验，消费规范化路径。
            let mut normalized_tmps: Vec<PathBuf> = Vec::with_capacity(tmp_dir.len());
            for p in &tmp_dir {
                let normalized = validate::validate_path_normalized(p, &allowed_paths)?;
                if !normalized_tmps.contains(&normalized) {
                    normalized_tmps.push(normalized);
                }
            }
            capability::drop_bounding_set_to(&[
                Capability::CAP_SYS_ADMIN,
                Capability::CAP_DAC_OVERRIDE,
            ])?;
            success(ops::gc_orphan_mounts(&normalized_root, &normalized_tmps))
        }
        Command::RmRf { path } => {
            let paths = path
                .iter()
                .map(|p| validate::validate_path_normalized(p, &allowed_paths))
                .collect::<Result<Vec<_>, _>>()?;
            // 允许根本身不可删；清空根下内容由调用方展开为直接子项传入。
            validate::validate_rm_rf_paths(&paths, &allowed_paths)?;
            capability::drop_bounding_set_to(&[Capability::CAP_DAC_OVERRIDE])?;
            success(ops::rm_rf(&paths))
        }
        Command::SpawnChroot {
            rootfs,
            program,
            arg,
            no_network,
        } => {
            let rootfs = validate::validate_path_normalized(&rootfs, &allowed_paths)?;
            // 漏洞 5：pre_exec 在 chroot(2)/chdir 后以 SECBIT_NOROOT(+LOCKED) +
            // PR_CAPBSET_DROP 剥离 SYS_ADMIN/SYS_CHROOT/SETPCAP，故 exec 前须保有：
            // SYS_ADMIN（unshare NEWNET）、SYS_CHROOT（chroot）、SETPCAP（securebits LOCKED）。
            // SETFCAP 须在 ambient：NOROOT 下 exec 后仅 ambient 存活，沙箱内 dnf/rpm
            // 装含 %caps 包（etcd 类）时 cap_set_file 缺它即 EPERM 装包失败。
            // 残余风险：沙箱内可对 rootfs 铸 file-cap xattr 并随文件持久化，宿主侧
            // crbs 组用户执行 rootfs 中被植入的带 cap 二进制可借其提权——与 nspawn
            // 后端（MINIMAL_CAPS 含 SETFCAP）既有暴露水平一致，不单独加固。
            capability::drop_bounding_set_to(&[
                Capability::CAP_SYS_ADMIN,
                Capability::CAP_SYS_CHROOT,
                Capability::CAP_SETPCAP,
                Capability::CAP_SETUID,
                Capability::CAP_SETGID,
                Capability::CAP_CHOWN,
                Capability::CAP_FOWNER,
                Capability::CAP_DAC_OVERRIDE,
                Capability::CAP_AUDIT_WRITE,
                Capability::CAP_SETFCAP,
            ])?;
            restore_root_identity()?;
            // ambient 不含 SYS_ADMIN/SYS_CHROOT——exec 后不得再能 chroot(2)（防双 chroot 逃逸）。
            capability::set_ambient_caps_for_exec(&[
                Capability::CAP_SETUID,
                Capability::CAP_SETGID,
                Capability::CAP_CHOWN,
                Capability::CAP_FOWNER,
                Capability::CAP_DAC_OVERRIDE,
                Capability::CAP_AUDIT_WRITE,
                Capability::CAP_SETFCAP,
            ])?;
            let cmd = spawn::chroot_command(&rootfs, &program, &arg, !no_network)?;
            Ok(Outcome::Exec(cmd))
        }
        Command::SpawnNspawn { argv } => {
            capability::drop_bounding_set_to(NSPAWN_EXEC_CAPS)?;
            restore_root_identity()?;
            capability::set_ambient_caps_for_exec(NSPAWN_EXEC_CAPS)?;
            let cmd = spawn::nspawn_command(&argv, &allowed_paths)?;
            Ok(Outcome::Exec(cmd))
        }
        Command::SpawnDnf {
            installroot,
            releasever,
            repos_dir,
            arg,
        } => {
            // 漏洞 2：消费规范化 installroot（原始串 `..`/中间 symlink 与校验口径分歧）。
            let installroot = validate::validate_path_normalized(&installroot, &allowed_paths)?;
            // releasever 进入 $releasever 路径展开，`../../` 可穿越宿主目录，
            // 按单段安全字符集校验。
            if releasever.is_empty()
                || !releasever
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
            {
                return Err(Error::Validation(format!(
                    "spawn-dnf: invalid releasever {:?}",
                    releasever
                )));
            }
            // 收权：repo 来源钉死到 host 受信 {crbs_root}/dnf-repos/{product}；installroot
            // 内 etc/yum.repos.d 产品/组成员可控，植入 repo 定义会让 %post 以 root
            // 执行；布局对全部已配置 root 判定（--crbs-root 与运行时 pin 可能不同，
            // worker 传入的是 worker.toml 的 root，与 server/引擎 root 允许同机分歧）。
            let repos_dir = validate::validate_path_normalized(&repos_dir, &allowed_paths)?;
            let mut known_roots = vec![server_root.clone(), engine_root.clone()];
            if let Some(worker_root) = &worker_root {
                known_roots.push(worker_root.clone());
            }
            spawn::validate_dnf_repos_dir(&repos_dir, &known_roots)?;
            let dnf_conf = spawn::require_trusted_dnf_repos(&repos_dir)?;
            spawn::validate_dnf_args(&arg)?;

            // CAP_MAC_ADMIN 仅 SELinux 启用时保留（禁用时 raise 会 EPERM）。
            let keep = spawn::dnf_keep_caps(capability::selinux_enabled());
            capability::drop_bounding_set_to(&keep)?;
            capability::set_ambient_caps_for_exec(&keep)?;
            restore_root_identity()?;
            // setuid 进程不经 PATH 解析 dnf：只在固定候选路径中查找。
            let dnf = spawn::resolve_trusted_bin(&["/usr/bin/dnf", "/bin/dnf"]);
            let mut cmd = std::process::Command::new(dnf);
            // 固定注入受信 --config/--setopt=reposdir（透传同名形态仍被拒）；依赖
            // dnf 以 host 绝对路径语义消费（不与 --installroot 拼接，实测把关）。
            cmd.arg("--installroot")
                .arg(&installroot)
                .arg("--releasever")
                .arg(&releasever)
                .arg(format!("--config={}", dnf_conf.display()))
                .arg(format!("--setopt=reposdir={}", repos_dir.display()))
                .args(&arg);
            // 不继承调用方环境，只给 dnf 必需的最小环境。
            cmd.env_clear();
            cmd.env("PATH", spawn::SAFE_PATH);
            cmd.env("HOME", "/root");
            // exec 前置 SECBIT_NOROOT(+LOCKED)：防 scriptlet 内 setuid/file-cap
            // 二进制重灌提权进 permitted 集；SYS_CHROOT 因 rpm scriptlet 依赖保留。
            spawn::harden_dnf_exec(&mut cmd);
            Ok(Outcome::Exec(cmd))
        }
        Command::WriteCgroupFile { path, value } => {
            // 路径：严格位于 /sys/fs/cgroup/machine.slice 之下断言 + `..`/相对拒绝 + 文件名白名单
            //（对齐 validate_path_normalized 语义）。
            let path = validate::validate_cgroup_file_path(&path)?;
            validate::validate_cgroup_value(&value)?;
            // 写 cgroup 文件无需 CAP_SYS_ADMIN（非挂载操作，DAC 即可写 kernfs）；
            // 保守保留 DAC_OVERRIDE 覆盖 DelegatedTree 属主移交非 root 场景。
            capability::drop_bounding_set_to(&[Capability::CAP_DAC_OVERRIDE])?;
            // cgroupfs 解析忽略尾随空白；追加换行与 crbs-core 直写通道口径一致。
            success(ops::write_cgroup_file(&path, &format!("{value}\n")))
        }
        Command::KillProcessGroup { pgid } => {
            // 杀构建进程组：无需额外能力（kill 只受 DAC 属主约束，root 恒可）。
            // pgid 负值约定与 core 侧 nix::sys::signal::kill 一致。
            let pgid = validate::validate_pgid(pgid)?;
            // 信任边界：本操作作用于全局 pid 命名空间（root SIGKILL 任意 pgid），
            // 须先做属主作用域校验——成员为空按组已死幂等放行，任一存活成员
            // 越界或作用域不可判定即拒绝，防组成员借 helper 杀系统服务。
            // 允许根与 spawn 校验同一集合（allowed_paths；标准临时目录谓词内置），
            // helper 能 spawn 的沙箱组必能 kill。
            validate::validate_kill_scope(pgid, caller_uid, &allowed_paths)?;
            success(ops::kill_process_group(pgid))
        }
        Command::TerminateMachine { name } => {
            // 信任锚：名称严格限定 crbs machine 命名空间——scope 路径与 /proc
            // 成员匹配全部由该名称派生，他方容器（machine.slice 其他 scope）与
            // 路径拼接形态在此字符集校验下不可达。
            let name = validate::validate_machine_name(&name)?;
            // cgroupfs 写与 kill 同 write-cgroup-file/kill-process-group 的能力
            // 口径：DAC 覆盖已足（kernfs 非 mount 操作，root kill 无需额外能力）。
            capability::drop_bounding_set_to(&[Capability::CAP_DAC_OVERRIDE])?;
            success(ops::terminate_machine(name))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_filter_is_pinned_constant() {
        // setuid 卫生：filter 必须是常量 "info"，不得派生自 RUST_LOG。
        assert_eq!(log_filter(), "info");
    }

    #[test]
    fn audit_line_contains_op_paths_and_caller_uid() {
        let cmd = Command::RmRf {
            path: vec![
                PathBuf::from("/var/lib/crbs/x"),
                PathBuf::from("/var/lib/crbs/y"),
            ],
        };
        let line = audit_line(&cmd, 1000);
        assert!(line.contains("op=rm-rf"), "line: {line}");
        assert!(line.contains("caller_uid=1000"), "line: {line}");
        assert!(line.contains("/var/lib/crbs/x"), "line: {line}");
        assert!(line.contains("/var/lib/crbs/y"), "line: {line}");
    }

    #[test]
    fn audit_line_write_file_never_logs_content() {
        let secret = "crbs_wkr_SUPERSECRET";
        let cmd = Command::WriteFile {
            path: PathBuf::from("/etc/crbs/worker.toml"),
            content: Some(secret.to_string()),
            content_stdin: false,
            mode: Some("600".to_string()),
            uid: Some(0),
            gid: Some(0),
        };
        let line = audit_line(&cmd, 0);
        assert!(!line.contains(secret), "line: {line}");
        assert!(
            line.contains(&format!("content_len=Some({})", secret.len())),
            "line: {line}"
        );
        assert!(line.contains("op=write-file"), "line: {line}");
    }

    /// 回归：分离形态（--setenv 与值各占一个元素）的值同规则脱敏；内联不回归。
    #[test]
    fn audit_line_nspawn_redacts_separated_setenv_value() {
        let secret = "TOKEN=hunter2";
        let cmd = Command::SpawnNspawn {
            argv: vec![
                "systemd-nspawn".to_string(),
                "--directory=/var/lib/crbs/p/rootfs".to_string(),
                "--setenv".to_string(),
                secret.to_string(),
                "--setenv=LC_ALL=C".to_string(),
                "--quiet".to_string(),
            ],
        };
        let line = audit_line(&cmd, 1000);
        assert!(!line.contains(secret), "line: {line}");
        assert!(!line.contains("hunter2"), "line: {line}");
        assert!(
            !line.contains("LC_ALL=C"),
            "inline form must stay redacted: {line}"
        );
        assert!(line.contains("\"--setenv\", \"TOKEN=\""), "line: {line}");
        assert!(line.contains("--setenv=LC_ALL="), "line: {line}");
        let cmd = Command::SpawnNspawn {
            argv: vec![
                "systemd-nspawn".to_string(),
                "--setenv".to_string(),
                "--quiet".to_string(),
            ],
        };
        let line = audit_line(&cmd, 1000);
        assert!(!line.contains("--setenv --quiet="), "line: {line}");
        assert!(line.contains("--setenv"), "line: {line}");
    }

    #[test]
    fn audit_line_mount_never_logs_data() {
        let secret = "password=hunter2";
        let data = format!("user=build,{secret}");
        let cmd = Command::Mount {
            source: Some("//fs/share".to_string()),
            target: PathBuf::from("/mnt/share"),
            fstype: Some("cifs".to_string()),
            flags: None,
            data: Some(data.clone()),
        };
        let line = audit_line(&cmd, 1000);
        assert!(!line.contains(secret), "line: {line}");
        assert!(!line.contains(&data), "line: {line}");
        assert!(
            line.contains(&format!("data_len=Some({})", data.len())),
            "line: {line}"
        );
        assert!(line.contains("op=mount"), "line: {line}");
    }

    #[test]
    fn audit_line_covers_all_variants() {
        let cmds = vec![
            Command::Mount {
                source: Some("src".to_string()),
                target: PathBuf::from("/t"),
                fstype: None,
                flags: None,
                data: None,
            },
            Command::MountOverlay {
                lower: vec![PathBuf::from("/l")],
                upper: PathBuf::from("/u"),
                work: PathBuf::from("/w"),
                target: PathBuf::from("/t"),
            },
            Command::Umount {
                target: PathBuf::from("/t"),
                flags: None,
            },
            Command::MkdirChown {
                path: PathBuf::from("/p"),
                user: "u".to_string(),
                group: "g".to_string(),
                mode: "755".to_string(),
            },
            Command::Chown {
                path: PathBuf::from("/p"),
                uid: 1,
                gid: 2,
                recursive: true,
            },
            Command::Chmod {
                path: PathBuf::from("/p"),
                mode: "644".to_string(),
                recursive: false,
            },
            Command::WriteFile {
                path: PathBuf::from("/p"),
                content: None,
                content_stdin: true,
                mode: None,
                uid: None,
                gid: None,
            },
            Command::GcOrphanMounts {
                crbs_root: PathBuf::from("/var/lib/crbs"),
                tmp_dir: vec![PathBuf::from("/var/tmp")],
            },
            Command::RmRf {
                path: vec![PathBuf::from("/p")],
            },
            Command::SpawnChroot {
                rootfs: PathBuf::from("/r"),
                program: "bash".to_string(),
                arg: vec![],
                no_network: false,
            },
            Command::SpawnNspawn {
                argv: vec!["systemd-nspawn".to_string()],
            },
            Command::SpawnDnf {
                installroot: PathBuf::from("/i"),
                releasever: "1".to_string(),
                repos_dir: PathBuf::from("/var/lib/crbs-engine/dnf-repos/p"),
                arg: vec!["install".to_string()],
            },
            Command::WriteCgroupFile {
                path: PathBuf::from("/sys/fs/cgroup/machine.slice/x.scope/payload/memory.max"),
                value: "1073741824".to_string(),
            },
            Command::KillProcessGroup { pgid: 4242 },
            Command::TerminateMachine {
                name: "crbs-9c714595-22".to_string(),
            },
        ];
        for cmd in &cmds {
            let line = audit_line(cmd, 42);
            assert!(line.starts_with("audit op="), "line: {line}");
            assert!(line.ends_with(" caller_uid=42"), "line: {line}");
            assert!(!line.chars().any(|c| c.is_control()), "line: {line:?}");
        }
    }

    #[test]
    fn escape_ctrl_maps_common_and_remaining_control_chars() {
        assert_eq!(escape_ctrl("a\tb\rc\nd"), "a\\tb\\rc\\nd");
        assert_eq!(escape_ctrl("\x00\x01\x1f\x7f"), "\\x00\\x01\\x1f\\x7f");
        assert_eq!(escape_ctrl("plain \\ path é"), "plain \\ path é");
        assert_eq!(escape_ctrl(""), "");
    }

    #[test]
    fn audit_line_control_chars_in_fields_cannot_forge_next_record() {
        // 路径/program 含 \n 可伪造下一行记录；转义后须单行、换行点以短转义留原行。
        let cmds = vec![
            Command::MkdirChown {
                path: PathBuf::from("/var/lib/crbs/a\nb\rc\td"),
                user: "u".to_string(),
                group: "g".to_string(),
                mode: "755".to_string(),
            },
            Command::SpawnChroot {
                rootfs: PathBuf::from("/r"),
                program: "ba\nsh\x01".to_string(),
                arg: vec!["--flag\n".to_string()],
                no_network: false,
            },
            Command::RmRf {
                path: vec![
                    PathBuf::from("/var/lib/crbs/x\n"),
                    PathBuf::from("/var/lib/crbs/y"),
                ],
            },
        ];
        for cmd in &cmds {
            let line = audit_line(cmd, 1000);
            assert!(!line.contains('\n'), "line: {line:?}");
            assert!(!line.contains('\r'), "line: {line:?}");
            assert!(!line.chars().any(|c| c.is_control()), "line: {line:?}");
            // 伪造的"下一行"应插在 op 与 caller_uid 之间：转义后仍同行行尾。
            assert!(line.ends_with(" caller_uid=1000"), "line: {line}");
        }
        let mkdir_line = audit_line(&cmds[0], 1000);
        assert!(
            mkdir_line.contains("path=/var/lib/crbs/a\\nb\\rc\\td"),
            "line: {mkdir_line}"
        );
        let chroot_line = audit_line(&cmds[1], 1000);
        assert!(
            chroot_line.contains("program=ba\\nsh\\x01"),
            "line: {chroot_line}"
        );
    }

    #[test]
    fn check_gc_root_accepts_any_configured_root() {
        let configured = vec![
            PathBuf::from("/var/lib/crbs"),
            PathBuf::from("/var/lib/crbs-engine"),
        ];
        assert!(check_gc_root(Path::new("/var/lib/crbs"), &configured).is_ok());
        assert!(check_gc_root(Path::new("/var/lib/crbs-engine"), &configured).is_ok());
        assert!(check_gc_root(Path::new("/var/lib/crbs/"), &configured).is_ok());
        assert!(check_gc_root(Path::new("/var/lib//crbs"), &configured).is_ok());
    }

    #[test]
    fn check_gc_root_rejects_subpath_parent_and_unrelated() {
        let configured = vec![PathBuf::from("/var/lib/crbs")];
        // 关键用例：allowed_paths 前缀校验会放行的子路径，成员判定必须拒绝。
        assert!(check_gc_root(Path::new("/var/lib/crbs/x"), &configured).is_err());
        assert!(check_gc_root(Path::new("/var/lib"), &configured).is_err());
        assert!(check_gc_root(Path::new("/tmp"), &configured).is_err());
    }

    // ── 漏洞 1：mount 参数白名单测试 ─────────────────────────────

    fn mount_allowed_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/var/lib/crbs"),
            PathBuf::from("/data/crbs-cache"),
        ]
    }

    #[test]
    fn mount_policy_accepts_all_core_call_patterns() {
        type MountCase<'a> = (Option<&'a str>, Option<&'a str>, u64, Option<&'a str>);
        let allowed = mount_allowed_paths();
        // crbs-core 全部实际调用形态：
        let cases: [MountCase; 9] = [
            // make private（overlay/伪 fs 挂载点收尾）
            (
                None,
                None,
                mount_flags::MS_REC | mount_flags::MS_PRIVATE,
                None,
            ),
            (None, None, mount_flags::MS_PRIVATE, None),
            (Some("proc"), Some("proc"), 0, None),
            (Some("sysfs"), Some("sysfs"), 0, None),
            // bind 宿主 /dev（递归 + 单独）
            (
                Some("/dev"),
                None,
                mount_flags::MS_BIND | mount_flags::MS_REC,
                None,
            ),
            (Some("/dev"), None, mount_flags::MS_BIND, None),
            // devpts（含 data 选项串）
            (
                Some("devpts"),
                Some("devpts"),
                0,
                Some("newinstance,ptmxmode=0666,mode=0620,gid=5"),
            ),
            (Some("tmpfs"), Some("tmpfs"), 0, None),
            (
                None,
                None,
                mount_flags::MS_BIND | mount_flags::MS_REMOUNT | mount_flags::MS_RDONLY,
                None,
            ),
        ];
        for (source, fstype, flags, data) in cases {
            assert!(
                validate_mount_request(source, fstype, flags, data, &allowed).is_ok(),
                "core call pattern rejected: source={source:?} fstype={fstype:?} \
                 flags={flags} data={data:?}"
            );
        }
        // bind 允许根内的宿主路径（dnf 缓存 / local repo / 允许根内 user bind）。
        assert!(validate_mount_request(
            Some("/data/crbs-cache/dnf"),
            None,
            mount_flags::MS_BIND,
            None,
            &allowed
        )
        .is_ok());
        // 设备树白名单其余成员（/dev 当前在用；/dev/pts、/proc、/sys 预留同权）。
        for dev in ["/dev/pts", "/proc", "/sys"] {
            assert!(
                validate_mount_request(Some(dev), None, mount_flags::MS_BIND, None, &allowed)
                    .is_ok(),
                "device-tree bind rejected: {dev}"
            );
        }
    }

    #[test]
    fn mount_policy_rejects_unknown_fstype() {
        let allowed = mount_allowed_paths();
        for fs in ["cifs", "nfs", "ext4", "overlay", "xfs"] {
            let err = validate_mount_request(Some(fs), Some(fs), 0, None, &allowed)
                .unwrap_err()
                .to_string();
            assert!(err.contains("fstype"), "unexpected: {err}");
            assert!(err.contains(fs), "unexpected: {err}");
        }
    }

    #[test]
    fn mount_policy_rejects_unknown_flag_bits() {
        let allowed = mount_allowed_paths();
        // MS_SHARED（1<<20）、MS_MANDLOCK、MS_POSIXACTS… 任何白名单外的位。
        assert!(validate_mount_request(
            None,
            None,
            mount_flags::MS_PRIVATE | (1 << 20),
            None,
            &allowed
        )
        .is_err());
        assert!(validate_mount_request(None, None, 1 << 40, None, &allowed).is_err());
        // flags 4096（MS_BIND）+ source "/"：由 source 规则拒绝。
        assert!(
            validate_mount_request(Some("/"), None, mount_flags::MS_BIND, None, &allowed).is_err()
        );
    }

    #[test]
    fn mount_policy_rejects_bind_source_outside_allowed_roots() {
        let allowed = mount_allowed_paths();
        // bind 根文件系统 / 敏感目录进白名单路径 = 提权原语，必须拒绝。
        for src in ["/", "/etc", "/home", "/usr", "/root"] {
            let err = validate_mount_request(Some(src), None, mount_flags::MS_BIND, None, &allowed)
                .unwrap_err()
                .to_string();
            assert!(err.contains("bind source"), "unexpected: {err}");
        }
        // 相对路径 bind source（按调用方 cwd 解析，不可控）拒绝。
        assert!(validate_mount_request(
            Some("var/lib"),
            None,
            mount_flags::MS_BIND,
            None,
            &allowed
        )
        .is_err());
        // 设备树白名单成员的"子路径"不在白名单内（只允许精确成员）。
        assert!(validate_mount_request(
            Some("/dev/../etc"),
            None,
            mount_flags::MS_BIND,
            None,
            &allowed
        )
        .is_err());
    }

    #[test]
    fn mount_policy_non_bind_source_must_match_fstype() {
        let allowed = mount_allowed_paths();
        assert!(validate_mount_request(Some("proc"), Some("proc"), 0, None, &allowed).is_ok());
        assert!(validate_mount_request(Some("proc"), Some("devpts"), 0, None, &allowed).is_err());
        // source 是任意路径但非 bind → 拒绝（mount(2) 会把它当设备/源串）。
        assert!(validate_mount_request(Some("/etc/passwd"), None, 0, None, &allowed).is_err());
        // fstype 缺失的伪名 source → 拒绝。
        assert!(validate_mount_request(Some("proc"), None, 0, None, &allowed).is_err());
    }

    #[test]
    fn mount_policy_data_keys_whitelisted() {
        let allowed = mount_allowed_paths();
        // 实际使用的 devpts 选项串 + tmpfs 资源限额键。
        assert!(validate_mount_request(
            Some("devpts"),
            Some("devpts"),
            0,
            Some("newinstance,ptmxmode=0666,mode=0620,gid=5"),
            &allowed
        )
        .is_ok());
        for key in [
            "size=1g",
            "nr_inodes=1024",
            "mode=700",
            "uid=1000",
            "gid=1000",
        ] {
            assert!(
                validate_mount_request(Some("tmpfs"), Some("tmpfs"), 0, Some(key), &allowed)
                    .is_ok(),
                "tmpfs data key rejected: {key}"
            );
        }
        // suid/dev/exec 注入（tmpfs 上铸造 suid 文件）必须拒绝。
        for evil in ["suid", "dev", "exec", "mode=1777,suid"] {
            let err = validate_mount_request(Some("tmpfs"), Some("tmpfs"), 0, Some(evil), &allowed)
                .unwrap_err()
                .to_string();
            assert!(err.contains("data option"), "unexpected: {err}");
        }
        // data 只允许 devpts/tmpfs；proc/sysfs 带 data 拒绝（无调用点）。
        for fs in ["proc", "sysfs"] {
            assert!(
                validate_mount_request(Some(fs), Some(fs), 0, Some("mode=0666"), &allowed).is_err()
            );
        }
        assert!(validate_mount_request(
            Some("tmpfs"),
            Some("tmpfs"),
            0,
            Some("size=1,,mode=700"),
            &allowed
        )
        .is_err());
    }

    #[test]
    fn mount_policy_data_values_validated_per_key() {
        let allowed = mount_allowed_paths();
        // 键合法但值越域：一律拒绝。
        for evil in [
            "mode=9999",
            "mode=12345",
            "ptmxmode=0620=1",
            "uid=+1000",
            "gid=0x10",
            "uid=10000000000",
            "size=10x",
            "nr_inodes=1kk",
            "size=abc",
            "mode=0620\n",
        ] {
            assert!(
                validate_mount_request(Some("devpts"), Some("devpts"), 0, Some(evil), &allowed)
                    .is_err(),
                "evil data value must be rejected: {evil:?}"
            );
        }
        assert!(
            validate_mount_request(Some("tmpfs"), Some("tmpfs"), 0, Some("size=1G"), &allowed)
                .is_ok()
        );
        assert!(validate_mount_request(
            Some("tmpfs"),
            Some("tmpfs"),
            0,
            Some("nr_inodes=max,mode=755"),
            &allowed
        )
        .is_ok());
        // 无值键携带 '='：newinstance=1 拒绝（newinstance 不接受值形态）。
        assert!(validate_mount_request(
            Some("devpts"),
            Some("devpts"),
            0,
            Some("newinstance=1"),
            &allowed
        )
        .is_err());
        // 值里再出现 '=' 不得被键解析吞掉。
        assert!(validate_mount_request(
            Some("tmpfs"),
            Some("tmpfs"),
            0,
            Some("mode=755,suid=1"),
            &allowed
        )
        .is_err());
    }

    // ── 漏洞 3：suid/sgid 剥离掩码测试（ops::strip_* 的纯逻辑）────────

    #[test]
    fn setid_masks_strip_correctly() {
        use crbs_priv_helper::ops::{strip_dir_setid_bits, strip_file_setid_bits};
        // 文件：剥 suid+sgid，保留其余位（0o755 脚本合法）。
        assert_eq!(strip_file_setid_bits(0o4755), 0o755);
        assert_eq!(strip_file_setid_bits(0o6755), 0o755);
        assert_eq!(strip_file_setid_bits(0o2770), 0o770);
        assert_eq!(strip_file_setid_bits(0o644), 0o644);
        // sticky 位保留（0o1777 临时目录合法）。
        assert_eq!(strip_file_setid_bits(0o1777), 0o1777);
        // 目录：剥 suid，保留 sgid（0o2770 是仓库权限不变量）与 sticky。
        assert_eq!(strip_dir_setid_bits(0o2770), 0o2770);
        assert_eq!(strip_dir_setid_bits(0o4770), 0o770);
        assert_eq!(strip_dir_setid_bits(0o3770), 0o3770);
        assert_eq!(strip_dir_setid_bits(0o755), 0o755);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prctl_sets_nondumpable() {
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0);
        }
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        assert_eq!(
            dumpable, 0,
            "PR_GET_DUMPABLE should be 0 after PR_SET_DUMPABLE(0)"
        );
    }
}
