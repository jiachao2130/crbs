// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 特权 helper 的进程派生：可信二进制解析、chroot/nspawn 命令与安全 PATH。

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::capability::Capability;
use crate::validate::validate_path;
use crate::Error;

/// nspawn 可执行文件的固定候选路径（按优先级）。setuid-root 下不得按调用方
/// PATH 解析（伪造的 `systemd-nspawn` 会以 root 执行）；argv[0] 仅确认意图。
const NSPAWN_BIN_CANDIDATES: &[&str] = &["/usr/bin/systemd-nspawn", "/bin/systemd-nspawn"];

/// setuid 进程执行外部程序时注入的最小 PATH（不继承调用方环境）。
pub const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// 在固定候选路径中解析可信可执行文件（不依赖环境 PATH）；都不存在时返回首个候选（exec 时 ENOENT，错误信息清晰）。
pub fn resolve_trusted_bin(candidates: &[&str]) -> PathBuf {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from(candidates[0]))
}

/// 校验 argv[0] 指向 systemd-nspawn（仅认 basename）并解析执行路径：执行固定为 [`NSPAWN_BIN_CANDIDATES`] 而非 argv[0] 本身。
fn resolve_nspawn_bin(requested: &str) -> Result<PathBuf, Error> {
    let is_nspawn = Path::new(requested)
        .file_name()
        .map(|n| n == "systemd-nspawn")
        .unwrap_or(false);
    if !is_nspawn {
        return Err(Error::Validation(format!(
            "spawn-nspawn: untrusted executable '{}'",
            requested
        )));
    }
    Ok(resolve_trusted_bin(NSPAWN_BIN_CANDIDATES))
}

/// 允许在 chroot 环境中执行的程序名（basename 白名单）：均来自 engine
/// 硬编码调用、不接收用户输入；dnf 供 SharedLayer 层内 builddep/restore 用。
const ALLOWED_CHROOT_PROGRAMS: &[&str] = &[
    "bash",
    "sh",
    "sudo",
    "rpmbuild",
    "rpm",
    "dnf",
    "getent",
    "groupadd",
    "useradd",
    "crbs-build",
    "crbs-build.sh",
    "crbs-reproduce-deps.sh",
    "crbs-reproduce-build.sh",
];

/// 构造 chroot 容器内构建命令：白名单校验程序，exec 前按需隔离网络、chroot 并封死 root 特例能力回灌。
#[cfg(target_os = "linux")]
pub fn chroot_command(
    rootfs: &Path,
    program: &str,
    args: &[String],
    network: bool,
) -> Result<Command, Error> {
    validate_chroot_program(program)?;

    use nix::sched::{unshare, CloneFlags};
    use nix::unistd::{chdir, chroot};
    use std::io;
    use std::os::unix::process::CommandExt;

    let rootfs = rootfs.to_path_buf();
    let program = program.to_string();
    let args = args.to_vec();

    let mut cmd = Command::new(program);
    cmd.args(args);
    // PATH 搜索跟随子进程环境：继承调用方 PATH 不含 sbin 时，sbin-only
    // 二进制（groupadd/useradd）ENOENT；调用方环境也不得整体带进 chroot 内 root 进程。
    cmd.env_clear();
    cmd.env("PATH", SAFE_PATH);
    unsafe {
        cmd.pre_exec(move || {
            if !network {
                unshare(CloneFlags::CLONE_NEWNET)
                    .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            }
            chroot(&rootfs).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            chdir("/").map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            // ── exec 前封死 root 特例能力回灌（主机逃逸收口）────────────
            // euid=0 且 bounding 含 SYS_ADMIN/SYS_CHROOT 时，无 SECBIT_NOROOT 则
            // capabilities(7) root 特例会把 permitted/effective 从 bounding 重灌满
            //——chroot 内负载即可双 chroot 逃逸。三步封死：NOROOT(+LOCKED)——exec
            // 按 ambient 规则算 permitted（main.rs 最小集）；bounding 剥 SYS_ADMIN/
            // SYS_CHROOT/SETPCAP（防 file caps / 后续 exec 取回，LOCKED 后 SETPCAP
            // 无法翻回）；inheritable∩F=0（无 file caps）+ ambient 不含这两个 cap
            //（main.rs set_ambient_caps_for_exec）。raw prctl 无堆分配（async-signal-safe）。
            let cur = libc::prctl(libc::PR_GET_SECUREBITS);
            if cur < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(
                libc::PR_SET_SECUREBITS,
                noroot_securebits(cur as libc::c_long),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // Linux ABI 数值（include/uapi/linux/capability.h），与编译目标平台无关。
            const CAP_SETPCAP: libc::c_ulong = 8;
            const CAP_SYS_CHROOT: libc::c_ulong = 18;
            const CAP_SYS_ADMIN: libc::c_ulong = 21;
            for cap in [CAP_SYS_CHROOT, CAP_SETPCAP, CAP_SYS_ADMIN] {
                if libc::prctl(libc::PR_CAPBSET_DROP, cap) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(cmd)
}

/// 非 Linux 平台桩：chroot 构建不受支持，仅做白名单校验后返回 Unsupported。
#[cfg(not(target_os = "linux"))]
pub fn chroot_command(
    _rootfs: &Path,
    program: &str,
    _args: &[String],
    _network: bool,
) -> Result<Command, Error> {
    validate_chroot_program(program)?;
    Err(Error::Unsupported("spawn-chroot is Linux only".into()))
}

/// 构造 systemd-nspawn 容器命令：校验 argv，清零环境仅注入最小 PATH。
pub fn nspawn_command(argv: &[String], allowed_paths: &[PathBuf]) -> Result<Command, Error> {
    if argv.is_empty() {
        return Err(Error::Validation("spawn-nspawn: empty argv".into()));
    }
    validate_nspawn_argv(argv, allowed_paths)?;
    let mut cmd = Command::new(resolve_nspawn_bin(&argv[0])?);
    cmd.args(&argv[1..]);
    // 环境清零只注入最小 PATH：调用方环境不得进以裁剪 caps 运行的 nspawn；容器内环境由 engine --setenv 注入。
    cmd.env_clear();
    cmd.env("PATH", SAFE_PATH);
    Ok(cmd)
}

fn validate_nspawn_argv(argv: &[String], allowed_paths: &[PathBuf]) -> Result<(), Error> {
    // argv[0] 的身份与执行路径由 resolve_nspawn_bin 把关，此处只校验选项。

    let mut i = 1;
    while i < argv.len() {
        let arg = argv[i].as_str();
        if arg == "--" {
            break;
        }

        // 拆分 --opt=value；不带内联值时从下一个 argv 元素取值。
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) if n.starts_with('-') => (n, Some(v)),
            _ => (arg, None),
        };

        if let Some(kind) = path_value_kind(name) {
            let value = match inline {
                Some(v) => v,
                None => {
                    i += 1;
                    if i >= argv.len() {
                        return Err(Error::Validation(format!(
                            "spawn-nspawn: '{}' requires a value",
                            name
                        )));
                    }
                    argv[i].as_str()
                }
            };
            validate_path_value(kind, value, allowed_paths)?;
        }
        // 非 path 选项也须白名单化（argv.rs 是唯一合法调用方）：未知选项透传即
        // 攻击面——`--settings=` 采信 rootfs 旁 .nspawn、`--share-system` 共享
        // 宿主命名空间，组成员可借 4755 helper 拿宿主 root shell；新增选项须同步本表与 argv.rs。
        if !NSPAWN_ALLOWED_OPTIONS.contains(&name) {
            return Err(Error::Validation(format!(
                "spawn-nspawn: option '{}' is not allowed",
                name
            )));
        }
        // 值形态约束（inline 或下一 argv 元素的值在上面 path 分支已处理）。
        if let Some(v) = inline {
            validate_nspawn_option_value(name, v)?;
        } else if option_takes_value(name) {
            i += 1;
            if i >= argv.len() {
                return Err(Error::Validation(format!(
                    "spawn-nspawn: '{}' requires a value",
                    name
                )));
            }
            validate_nspawn_option_value(name, argv[i].as_str())?;
        }

        i += 1;
    }

    Ok(())
}

/// nspawn 选项白名单（与 crbs-core argv.rs 实际发送的选项集同步——一致性由
/// tests::nspawn_allowed_options_cover_engine_argv_options 以源码扫描锁定）。
const NSPAWN_ALLOWED_OPTIONS: &[&str] = &[
    "--directory",
    "-D",
    "--machine",
    "--as-pid2",
    "--register",
    "--quiet",
    "--capability",
    "--console",
    "--private-network",
    "--property",
    "--setenv",
    "--keep-unit",
    "--user",
    "--bind",
    "--bind-ro",
    // engine 决策的容器 hostname（det 固定 "crbs-build" / worker 主机名 / 回放
    // BUILDHOST，见 phase::decide_container_hostname）：非路径语义，值按
    // --machine 同款字符集校验。
    "--hostname",
    // 携带宿主路径的选项（值经 path_value_kind 校验）：engine 未发送，预留扩展；无 --settings 类语义逃逸面。
    "--image",
    "--template",
    "--overlay",
    "--overlay-ro",
    "--load-credential",
    "--certificate",
    "--private-key",
];

/// 需要消耗一个值的选项（path 类的值已在 path 分支处理，这里只列非 path 类）。
fn option_takes_value(name: &str) -> bool {
    matches!(
        name,
        "--machine"
            | "--register"
            | "--capability"
            | "--console"
            | "--setenv"
            | "--user"
            | "--hostname"
    )
}

/// --capability 允许的 capability 名（= engine MINIMAL_CAPS 集合，允许子集）。
const NSPAWN_ALLOWED_CAPS: &[&str] = &[
    "cap_chown",
    "cap_dac_override",
    "cap_fowner",
    "cap_setuid",
    "cap_setgid",
    "cap_sys_admin",
    "cap_sys_chroot",
    "cap_setpcap",
    "cap_audit_control",
    "cap_audit_write",
    "cap_setfcap",
];

/// --property 允许的属性前缀（engine 只发资源限制三类；属性可改容器安全语义）。
const NSPAWN_ALLOWED_PROPERTIES: &[&str] = &["MemoryMax=", "MemoryLimit=", "CPUQuota="];

fn validate_nspawn_option_value(name: &str, value: &str) -> Result<(), Error> {
    match name {
        "--capability" => {
            for cap in value.split(',') {
                let c = cap.trim().to_ascii_lowercase();
                if !NSPAWN_ALLOWED_CAPS.contains(&c.as_str()) {
                    return Err(Error::Validation(format!(
                        "spawn-nspawn: capability '{}' is not allowed",
                        cap
                    )));
                }
            }
            Ok(())
        }
        "--property" => {
            if NSPAWN_ALLOWED_PROPERTIES
                .iter()
                .any(|p| value.starts_with(p))
            {
                Ok(())
            } else {
                Err(Error::Validation(format!(
                    "spawn-nspawn: property '{}' is not allowed",
                    value
                )))
            }
        }
        // --machine 进 cgroup 路径拼接、--user/--setenv 的 KEY 进容器配置：
        // 拒路径分隔符/空白/控制字符防注入。--hostname 进 UTS namespace，
        // 值来自 engine 固定字面量，非路径但按同字符集收口（纵深防御），
        // 另限内核主机名上限 HOST_NAME_MAX = 64 字节（engine 侧
        // hostname_value_valid 同口径前置过滤，此处兜底超长值）。
        "--machine" | "--user" | "--hostname" => {
            if name == "--hostname" && value.len() > 64 {
                return Err(Error::Validation(
                    "spawn-nspawn: '--hostname' value exceeds HOST_NAME_MAX (64)".into(),
                ));
            }
            if value.is_empty()
                || value.contains('/')
                || value.contains("..")
                || value.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(Error::Validation(format!(
                    "spawn-nspawn: invalid '{}' value",
                    name
                )));
            }
            Ok(())
        }
        "--setenv" => match value.split_once('=') {
            Some((k, _))
                if !k.is_empty() && !k.chars().any(|c| c.is_whitespace() || c.is_control()) =>
            {
                Ok(())
            }
            _ => Err(Error::Validation(
                "spawn-nspawn: invalid --setenv value".into(),
            )),
        },
        // --register/--console 的值域窄，engine 固定发送 no/pipe；白名单化。
        "--register" if value != "no" => Err(Error::Validation(
            "spawn-nspawn: --register only accepts 'no'".into(),
        )),
        "--console" if value != "pipe" => Err(Error::Validation(
            "spawn-nspawn: --console only accepts 'pipe'".into(),
        )),
        _ => Ok(()),
    }
}

/// 携带宿主机路径值的 nspawn 选项的值形态。
#[derive(Clone, Copy)]
enum PathValue {
    /// 整个值即宿主机路径。
    Whole,
    /// `HOST[:CONTAINER[:opts]]`：冒号首段是宿主机路径。
    BindHost,
    /// `LOWER:UPPER:WORK[:DEST]`：前三段是宿主机路径，可选的 DEST 在容器内。
    Overlay,
    /// `NAME:HOST_PATH`：冒号第二段是宿主机路径。
    Credential,
}

/// 识别携带宿主机路径的 nspawn 选项；未列出 = 不携带宿主路径（非路径选项
/// 白名单见 NSPAWN_ALLOWED_OPTIONS）。覆盖与 systemd-nspawn 文档对齐。
fn path_value_kind(name: &str) -> Option<PathValue> {
    Some(match name {
        "--directory" | "-D" | "--image" | "--template" | "--certificate" | "--private-key" => {
            PathValue::Whole
        }
        "--bind" | "--bind-ro" => PathValue::BindHost,
        "--overlay" | "--overlay-ro" => PathValue::Overlay,
        "--load-credential" => PathValue::Credential,
        _ => return None,
    })
}

fn validate_path_value(
    kind: PathValue,
    value: &str,
    allowed_paths: &[PathBuf],
) -> Result<(), Error> {
    match kind {
        PathValue::Whole => validate_path(Path::new(value), allowed_paths),
        PathValue::BindHost => validate_host_of_bind(value, allowed_paths),
        PathValue::Overlay => {
            let parts: Vec<&str> = value.split(':').collect();
            match parts.len() {
                // LOWER:UPPER:WORK 三段均在宿主机；可选的第四段是容器内目标。
                3 | 4 => {
                    for host in &parts[..3] {
                        validate_path(Path::new(host), allowed_paths)?;
                    }
                    Ok(())
                }
                _ => Err(Error::Validation(format!(
                    "spawn-nspawn: invalid overlay spec '{}'",
                    value
                ))),
            }
        }
        PathValue::Credential => match value.split_once(':') {
            Some((_, host)) => validate_path(Path::new(host), allowed_paths),
            None => Err(Error::Validation(format!(
                "spawn-nspawn: invalid credential spec '{}'",
                value
            ))),
        },
    }
}

fn validate_host_of_bind(spec: &str, allowed_paths: &[PathBuf]) -> Result<(), Error> {
    let host = spec
        .split(':')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(spec);
    validate_path(Path::new(host), allowed_paths)
}

/// host 侧受信 repo 集合内 dnf 主配置文件名（engine 写入、helper 消费，两侧字面量手抄同步——helper 独立成包不依赖 crbs-core）。
pub const TRUSTED_DNF_CONF_NAME: &str = "dnf.conf";

/// 受信 repo 目录的固定布局：`{root}/dnf-repos/{product}/`——恰一层产品名，
/// 调用方可选维度只有产品名，不能指向允许根内其它可写位置（installroot 等）。
/// 目录由 engine 经 write-file 写入（root:root、目录 0755 / 文件 0644），engine
/// 自身无写权限，随 root 派生天然位于 allowed_paths 内。须对全部已配置 root
///（server ∪ 引擎）判定（backend `--crbs-root` 与运行时 pin 的 root 可能不同），
/// 单一 root 判定会误拒另一世界的合法布局。
pub fn validate_dnf_repos_dir(repos_dir: &Path, known_roots: &[PathBuf]) -> Result<(), Error> {
    let layout_ok = |root: &Path| {
        let rest = match repos_dir.strip_prefix(root.join("dnf-repos")) {
            Ok(r) => r,
            Err(_) => return false,
        };
        // 恰一层产品名：更深层（嵌套子目录）不是 engine 写入的布局。
        let mut components = rest.components();
        components.next().is_some() && components.next().is_none()
    };
    if !known_roots.iter().any(|r| layout_ok(r)) {
        return Err(Error::Validation(format!(
            "spawn-dnf --repos-dir {} is not a product directory under the trusted layout \
             {{root}}/dnf-repos/{{product}} of a configured crbs root ({}); installroot-side \
             repo dirs are not accepted",
            repos_dir.display(),
            known_roots
                .iter()
                .map(|r| r.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(())
}

/// 受信 repo 目录内 dnf 主配置文件路径（固定文件名 [`TRUSTED_DNF_CONF_NAME`]）。
pub fn trusted_dnf_conf_path(repos_dir: &Path) -> PathBuf {
    repos_dir.join(TRUSTED_DNF_CONF_NAME)
}

/// 信任锚类资产的 (uid, mode) 判定（纯函数）：root 属主且组/其他不可写（0o022 任一位 = 可能被非 root 改写，不可信）。
fn trusted_asset_ok(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

/// spawn-dnf 执行前的 fail-closed 检查（返回配置文件路径）：受信 reposdir/配置
/// 缺失或属主/写位不符信任锚即拒绝，绝不静默退回 dnf 默认的 installroot 内
/// repo 读取（正是要收权的抢占植入面）；symlink_metadata 不跟随叶子（换包 symlink 按不可信拒）。
pub fn require_trusted_dnf_repos(repos_dir: &Path) -> Result<PathBuf, Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let dir_meta = std::fs::symlink_metadata(repos_dir).map_err(|e| {
            Error::Validation(format!(
                "spawn-dnf trusted repos dir {} is missing ({e}); refusing to fall back to \
                 installroot-side repo files",
                repos_dir.display()
            ))
        })?;
        if !dir_meta.is_dir() || !trusted_asset_ok(dir_meta.uid(), dir_meta.mode()) {
            return Err(Error::Validation(format!(
                "spawn-dnf trusted repos dir {} must be a root-owned directory without \
                 group/other write bits",
                repos_dir.display()
            )));
        }
        let conf = trusted_dnf_conf_path(repos_dir);
        let conf_meta = std::fs::symlink_metadata(&conf).map_err(|e| {
            Error::Validation(format!(
                "spawn-dnf trusted config {} is missing ({e}); refusing to fall back to \
                 installroot-side repo files",
                conf.display()
            ))
        })?;
        if !conf_meta.is_file() || !trusted_asset_ok(conf_meta.uid(), conf_meta.mode()) {
            return Err(Error::Validation(format!(
                "spawn-dnf trusted config {} must be a root-owned regular file without \
                 group/other write bits",
                conf.display()
            )));
        }
        Ok(conf)
    }
    #[cfg(not(unix))]
    {
        let _ = repos_dir;
        Err(Error::Unsupported("spawn-dnf is Unix only".into()))
    }
}

/// 校验 spawn-dnf 透传的 dnf 参数（白名单）。dnf 以 root + caps 运行：
/// `--config`/`--repofrompath`/`--setopt=reposdir` 可加载攻击者仓库（%post 以
/// root 执行），`--installroot`/`--downloaddir` 可写允许路径之外。受信
/// `--config`/`--setopt=reposdir` 由 helper 注入（main.rs），透传同形态一律拒。
pub fn validate_dnf_args(args: &[String]) -> Result<(), Error> {
    // engine 发四种形态（base_os_install.rs + engine/init/snapshot.rs）：
    // install -y [--downloadonly] --setopt=keepcache=1 <pkgs...> / clean metadata /
    // install -y --setopt=keepcache=1 dnf-plugins-core / clean all。`--downloadonly`
    // 只跳过 rpm 事务执行（快照 resolve 用），不改 repo/路径语义。
    let rejected = |a: &str| {
        Err(Error::Validation(format!(
            "spawn-dnf: argument '{a}' is not allowed (dnf args are allowlisted)"
        )))
    };
    match args.first().map(String::as_str) {
        Some("install") => {
            let mut pkgs = 0usize;
            for a in &args[1..] {
                match a.as_str() {
                    "-y" | "--setopt=keepcache=1" | "--downloadonly" => {}
                    // 包名/NEVRA 不得以 "-" 开头：防止把选项 smuggle 进包位。
                    pkg if !pkg.starts_with('-') => pkgs += 1,
                    other => return rejected(other),
                }
            }
            if pkgs == 0 {
                return Err(Error::Validation(
                    "spawn-dnf: install requires at least one package".into(),
                ));
            }
        }
        Some("clean") => {
            // engine 只发 `clean metadata`；`clean all` 同为纯缓存清理，一并放行。
            if args.len() != 2 || !matches!(args[1].as_str(), "metadata" | "all") {
                return Err(Error::Validation(
                    "spawn-dnf: only 'clean metadata'/'clean all' is allowed".into(),
                ));
            }
        }
        _ => return rejected(args.first().map(String::as_str).unwrap_or("")),
    }
    Ok(())
}

/// 构造 dnf installroot 子进程需保留的能力集。`CAP_MAC_ADMIN` 仅 SELinux
/// 启用时保留（selinux-policy 包 %post 加载策略）：禁用时无必要，且 crbs
/// 侧 Restricted 模式 bounding set 不含它，raise 必 EPERM 阻断 base_os 安装。
pub fn dnf_keep_caps(selinux_enabled: bool) -> Vec<Capability> {
    // 不保留 CAP_SYS_ADMIN：文件操作不需要，%post 里的 mount()/unshare() 恰是
    // 恶意 RPM 逃逸向量（repo 来源钉死 host 受信目录，见 require_trusted_dnf_repos）。
    // 残余风险：CAP_SYS_CHROOT 为 scriptlet 进 chroot 必需、无法剥离；
    // NOROOT(+LOCKED)（[`harden_dnf_exec`]）挡提权重灌，但双 chroot 逃逸面仍在。
    let mut keep = vec![
        Capability::CAP_SYS_CHROOT,
        Capability::CAP_SETUID,
        Capability::CAP_SETGID,
        Capability::CAP_CHOWN,
        Capability::CAP_FOWNER,
        Capability::CAP_DAC_OVERRIDE,
        Capability::CAP_SETFCAP,
        Capability::CAP_AUDIT_WRITE,
        Capability::CAP_SETPCAP,
    ];
    if selinux_enabled {
        keep.push(Capability::CAP_MAC_ADMIN);
    }
    keep
}

/// 在现有 securebits 之上置 NOROOT(+LOCKED) 的目标位组合（纯算术、无分配/系统
/// 调用——async-signal-safe，pre_exec 闭包内可直接调用；单测锁定幂等与位保留）。
#[cfg(target_os = "linux")]
fn noroot_securebits(current: libc::c_long) -> libc::c_ulong {
    current as libc::c_ulong
        | libc::SECBIT_NOROOT as libc::c_ulong
        | libc::SECBIT_NOROOT_LOCKED as libc::c_ulong
}

/// spawn-dnf 子进程 exec 前的 securebits 加固：置 SECBIT_NOROOT(+LOCKED)。
/// 与 [`chroot_command`] 策略不同：capability 集一律不动（rpm scriptlet 在
/// --installroot 内自行 chroot(2)，剥掉即断 scriptlet）——故 NOROOT 关不掉
/// 经典双 chroot 逃逸（ambient=keep=bounding，exec 后 scriptlet 仍持
/// SYS_CHROOT），是保留 scriptlet 的已知残余风险。NOROOT 实际作用：关
/// capabilities(7) 的 exec root 特例——否则 scriptlet 内任何 exec（含
/// setuid-root / file-cap 二进制）都把 bounding 全集重灌进 permitted/
/// effective、覆盖 ambient 最小集并复活 ambient 容不下的 CAP_SETPCAP；
/// LOCKED 防持 SETPCAP 的代码翻回。raw prctl 无堆分配（async-signal-safe）；pre_exec 失败即 exec 失败。
#[cfg(target_os = "linux")]
pub fn harden_dnf_exec(cmd: &mut Command) {
    use std::io;
    use std::os::unix::process::CommandExt;

    unsafe {
        cmd.pre_exec(|| {
            let cur = libc::prctl(libc::PR_GET_SECUREBITS);
            if cur < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(
                libc::PR_SET_SECUREBITS,
                noroot_securebits(cur as libc::c_long),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// 非 Linux 平台桩：无 securebits 语义，空操作。
#[cfg(not(target_os = "linux"))]
pub fn harden_dnf_exec(_cmd: &mut Command) {}

fn validate_chroot_program(program: &str) -> Result<(), Error> {
    if program.is_empty() {
        return Err(Error::Validation(
            "spawn-chroot: program must not be empty".into(),
        ));
    }
    if program.contains("\0") || program.contains("..") {
        return Err(Error::Validation(format!(
            "spawn-chroot: invalid program '{}'",
            program
        )));
    }
    let basename = Path::new(program)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(program);
    if !ALLOWED_CHROOT_PROGRAMS.contains(&basename) {
        return Err(Error::Validation(format!(
            "spawn-chroot: program '{}' not allowed",
            program
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/var/lib/crbs"),
            PathBuf::from("/data/crbs-results"),
        ]
    }

    #[test]
    fn dnf_keep_caps_excludes_mac_admin_when_selinux_disabled() {
        let keep = dnf_keep_caps(false);
        assert!(!keep.contains(&Capability::CAP_MAC_ADMIN));
        assert!(!keep.contains(&Capability::CAP_SYS_ADMIN));
        assert!(keep.contains(&Capability::CAP_SYS_CHROOT));
        assert!(keep.contains(&Capability::CAP_SETFCAP));
        assert_eq!(keep.len(), 9);
    }

    #[test]
    fn dnf_keep_caps_includes_mac_admin_when_selinux_enabled() {
        let keep = dnf_keep_caps(true);
        assert!(keep.contains(&Capability::CAP_MAC_ADMIN));
        assert_eq!(keep.len(), 10);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn noroot_securebits_preserves_existing_and_sets_locked_pair() {
        // 在启动期 KEEP_CAPS|NO_SETUID_FIXUP（capability.rs）之上 OR 入 NOROOT(+LOCKED)：既有位保留，两位必置。
        let keep_caps = (libc::SECBIT_KEEP_CAPS | libc::SECBIT_NO_SETUID_FIXUP) as libc::c_long;
        let bits = noroot_securebits(keep_caps);
        assert_eq!(
            bits & libc::SECBIT_KEEP_CAPS as libc::c_ulong,
            libc::SECBIT_KEEP_CAPS as libc::c_ulong
        );
        assert_eq!(
            bits & libc::SECBIT_NO_SETUID_FIXUP as libc::c_ulong,
            libc::SECBIT_NO_SETUID_FIXUP as libc::c_ulong
        );
        assert_eq!(
            bits & libc::SECBIT_NOROOT as libc::c_ulong,
            libc::SECBIT_NOROOT as libc::c_ulong
        );
        assert_eq!(
            bits & libc::SECBIT_NOROOT_LOCKED as libc::c_ulong,
            libc::SECBIT_NOROOT_LOCKED as libc::c_ulong
        );
        // 幂等（chroot 路径与 dnf 路径叠加时不丢位）。
        assert_eq!(noroot_securebits(bits as libc::c_long), bits);
    }

    #[test]
    fn nspawn_command_accepts_trusted_bin_and_allowed_directory() {
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--directory=/var/lib/crbs/products/mydist/rootfs".to_string(),
            "--as-pid2".to_string(),
            "--".to_string(),
            "/bin/bash".to_string(),
        ];
        let cmd = nspawn_command(&argv, &allowed()).unwrap();
        let program = cmd.get_program().to_string_lossy().into_owned();
        assert!(
            NSPAWN_BIN_CANDIDATES.contains(&program.as_str()),
            "unexpected nspawn program: {program}"
        );
    }

    #[test]
    fn nspawn_command_scrubs_environment() {
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--directory=/var/lib/crbs/products/mydist/rootfs".to_string(),
        ];
        let cmd = nspawn_command(&argv, &allowed()).unwrap();
        let envs: Vec<_> = cmd.get_envs().collect();
        assert_eq!(envs.len(), 1);
        assert_eq!(envs[0].0, "PATH");
        assert!(envs[0].1.is_some());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn chroot_command_scrubs_environment() {
        // 回归：继承调用方 PATH 不含 sbin 时 groupadd 等以 ENOENT 失败。
        let cmd = chroot_command(
            Path::new("/var/lib/crbs/mydist/base"),
            "groupadd",
            &[
                "-g".to_string(),
                "10010".to_string(),
                "ccbuilder".to_string(),
            ],
            true,
        )
        .unwrap();
        let envs: Vec<_> = cmd.get_envs().collect();
        assert_eq!(envs.len(), 1);
        assert_eq!(envs[0].0, "PATH");
        assert_eq!(
            envs[0].1.map(|v| v.to_string_lossy().into_owned()),
            Some(SAFE_PATH.to_string())
        );
    }

    #[test]
    fn nspawn_command_rejects_untrusted_executable() {
        let argv = vec!["/bin/bash".to_string(), "-c".to_string(), "id".to_string()];
        assert!(nspawn_command(&argv, &allowed()).is_err());
        let argv = vec!["/opt/evil/nspawn".to_string()];
        assert!(nspawn_command(&argv, &allowed()).is_err());
    }

    #[test]
    fn nspawn_command_rejects_directory_outside_allowed() {
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--directory=/etc".to_string(),
            "--".to_string(),
            "/bin/bash".to_string(),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_err());
    }

    #[test]
    fn nspawn_command_rejects_bind_host_outside_allowed() {
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--directory=/var/lib/crbs/products/mydist/rootfs".to_string(),
            "--bind=/etc/passwd:/tmp/passwd".to_string(),
            "--".to_string(),
            "/bin/bash".to_string(),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_err());
    }

    #[test]
    fn nspawn_command_accepts_bind_host_inside_allowed() {
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--directory=/var/lib/crbs/products/mydist/rootfs".to_string(),
            "--bind=/data/crbs-results:/results".to_string(),
            "--".to_string(),
            "/bin/bash".to_string(),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_ok());
    }

    #[test]
    fn nspawn_command_validates_overlay_host_paths() {
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--overlay=/var/lib/crbs/lower:/var/lib/crbs/upper:/var/lib/crbs/work:/rootfs"
                .to_string(),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_ok());
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--overlay-ro".to_string(),
            "/var/lib/crbs/lower:/var/lib/crbs/upper:/var/lib/crbs/work".to_string(),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_ok());

        let argv = vec![
            "systemd-nspawn".to_string(),
            "--overlay=/etc:/var/lib/crbs/upper:/var/lib/crbs/work".to_string(),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_err());
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--overlay=/var/lib/crbs/lower:/var/lib/crbs/upper:/srv/work".to_string(),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_err());

        let argv = vec![
            "systemd-nspawn".to_string(),
            "--overlay=/var/lib/crbs/lower:/var/lib/crbs/upper".to_string(),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_err());
    }

    #[test]
    fn nspawn_command_validates_template_and_credential_paths() {
        let argv = vec!["systemd-nspawn".to_string(), "--template=/etc".to_string()];
        assert!(nspawn_command(&argv, &allowed()).is_err());
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--template".to_string(),
            "/var/lib/crbs/products/mydist/rootfs".to_string(),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_ok());

        let argv = vec![
            "systemd-nspawn".to_string(),
            "--load-credential=secret:/etc/shadow".to_string(),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_err());
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--load-credential=secret:/var/lib/crbs/secret".to_string(),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_ok());
    }

    #[test]
    fn nspawn_command_accepts_engine_option_set() {
        // argv.rs 发送/曾发送的非 path 选项集全部放行（含 --hostname 决策值，
        // det 固定 "crbs-build" / worker 主机名 / 回放 BUILDHOST）；
        // --register=no / --keep-unit 仅 shell 路径仍发（保留放行以兼容）。
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--directory=/var/lib/crbs/products/mydist/rootfs".to_string(),
            "--as-pid2".to_string(),
            "--register=no".to_string(),
            "--quiet".to_string(),
            "--console=pipe".to_string(),
            "--capability=cap_chown,cap_dac_override".to_string(),
            "--setenv=HOME=/root".to_string(),
            "--machine=crbs-test".to_string(),
            "--property=MemoryMax=512M".to_string(),
            "--keep-unit".to_string(),
            "--hostname=crbs-build".to_string(),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_ok());
        // 非内联形态（--hostname 单独成元素）也放行且取值合法。
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--directory=/var/lib/crbs/products/mydist/rootfs".to_string(),
            "--hostname".to_string(),
            "crbs-build".to_string(),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_ok());
        // 值含路径分隔符/空白：拒绝（--machine 同款字符集）；超 HOST_NAME_MAX
        //（64 字节）的 hostname 拒绝（engine 前置过滤同口径，helper 纵深防御）。
        let over_max = format!("--hostname={}", "a".repeat(65));
        for bad in [
            "--hostname=/e/t/c",
            "--hostname=bad host",
            over_max.as_str(),
        ] {
            let argv = vec![
                "systemd-nspawn".to_string(),
                "--directory=/var/lib/crbs/products/mydist/rootfs".to_string(),
                bad.to_string(),
            ];
            assert!(
                nspawn_command(&argv, &allowed()).is_err(),
                "hostname value must be charset/length-checked: {bad}"
            );
        }
        // 64 字节恰在上限内（engine det 钉值 / worker 主机名的合法形态）。
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--directory=/var/lib/crbs/products/mydist/rootfs".to_string(),
            format!("--hostname={}", "a".repeat(64)),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_ok());
        // 长度上限只作用 --hostname：同长度的 --machine 值不受限。
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--directory=/var/lib/crbs/products/mydist/rootfs".to_string(),
            format!("--machine={}", "a".repeat(65)),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_ok());
    }

    /// 同步性契约测试：argv.rs 实际发送的每个 nspawn 选项都必须在本白名单内
    ///（helper 与 crbs-core 互不依赖、常量手抄，漏登在此变红而非运行期拒绝
    /// 整个 nspawn 后端）。提取：剥行注释后扫描 argv.rs 的 `--` 字面量取 `=`
    /// 前选项名；反向不查（白名单刻意预留 path 类扩展项 --image 等）。
    #[test]
    fn nspawn_allowed_options_cover_engine_argv_options() {
        let src = include_str!("../../crbs-core/src/engine/backend/nspawn/argv.rs");
        let mut sent: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for line in src.lines() {
            // 剥 // 行注释（argv.rs 字符串字面量不含 //）
            let line = match line.find("//") {
                Some(i) => &line[..i],
                None => line,
            };
            for lit in line.split('"').skip(1).step_by(2) {
                if let Some(name) = lit.strip_prefix("--") {
                    let name = name.split('=').next().unwrap_or_default();
                    if !name.is_empty() {
                        sent.insert(format!("--{name}"));
                    }
                }
            }
        }
        assert!(
            sent.contains("--hostname"),
            "source scan must see the hostname option (scanner regression?)"
        );
        let missing: Vec<_> = sent
            .iter()
            .filter(|o| !NSPAWN_ALLOWED_OPTIONS.contains(&o.as_str()))
            .cloned()
            .collect();
        assert!(
            missing.is_empty(),
            "argv.rs sends options absent from NSPAWN_ALLOWED_OPTIONS: {missing:?} — \
             the setuid helper would reject them at runtime; sync the whitelist"
        );
    }

    #[test]
    fn nspawn_command_rejects_semantic_escape_options() {
        // 回归：语义逃逸选项（--settings/--share-system/--volatile/--pivot-root）必须拒绝。
        for opt in [
            "--settings=trusted",
            "--share-system",
            "--volatile=yes",
            "--pivot-root=/x",
        ] {
            let argv = vec![
                "systemd-nspawn".to_string(),
                "--directory=/var/lib/crbs/products/mydist/rootfs".to_string(),
                opt.to_string(),
            ];
            assert!(
                nspawn_command(&argv, &allowed()).is_err(),
                "{opt} must be rejected"
            );
        }
    }

    #[test]
    fn nspawn_command_constrains_capability_and_property_values() {
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--directory=/var/lib/crbs/products/mydist/rootfs".to_string(),
            "--capability=cap_sys_boot".to_string(),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_err());
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--directory=/var/lib/crbs/products/mydist/rootfs".to_string(),
            "--property=DeviceAllow=/dev/sda".to_string(),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_err());
        let argv = vec![
            "systemd-nspawn".to_string(),
            "--directory=/var/lib/crbs/products/mydist/rootfs".to_string(),
            "--machine=../escape".to_string(),
        ];
        assert!(nspawn_command(&argv, &allowed()).is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn chroot_command_accepts_allowed_program() {
        let res = chroot_command(Path::new("/var/lib/crbs/rootfs"), "bash", &[], true);
        assert!(res.is_ok());
        // SharedLayer 层内 dnf builddep / restore install / rpm -qa 使用的程序名。
        for program in ["dnf", "rpm"] {
            assert!(
                chroot_command(Path::new("/var/lib/crbs/rootfs"), program, &[], true).is_ok(),
                "{program} must be allowlisted"
            );
        }
    }

    #[test]
    fn chroot_command_rejects_disallowed_program() {
        let res = chroot_command(Path::new("/var/lib/crbs/rootfs"), "/bin/evil", &[], true);
        assert!(res.is_err());
    }

    #[test]
    fn chroot_command_rejects_program_with_dotdot() {
        let res = chroot_command(
            Path::new("/var/lib/crbs/rootfs"),
            "/tmp/../bin/bash",
            &[],
            true,
        );
        assert!(res.is_err());
    }

    #[test]
    fn validate_dnf_args_accepts_engine_invocations() {
        // engine 实际构造的调用形态（install 常规 / install 快照 resolve / clean）
        assert!(validate_dnf_args(&[
            "install".into(),
            "-y".into(),
            "--setopt=keepcache=1".into(),
            "bash".into(),
            "rpm-build".into(),
        ])
        .is_ok());
        assert!(validate_dnf_args(&["clean".into(), "all".into()]).is_ok());
        assert!(
            validate_dnf_args(&["install".into(), "-y".into(), "dnf-plugins-core".into()]).is_ok()
        );
        assert!(validate_dnf_args(&[
            "install".into(),
            "-y".into(),
            "--downloadonly".into(),
            "--setopt=keepcache=1".into(),
            "bash".into(),
        ])
        .is_ok());
    }

    #[test]
    fn validate_dnf_args_rejects_config_and_repo_redirection() {
        // 配置文件/仓库源重定向（含合并形式与短选项）
        assert!(validate_dnf_args(&["install".into(), "--config=/tmp/x.conf".into()]).is_err());
        assert!(validate_dnf_args(&["install".into(), "--config".into()]).is_err());
        assert!(validate_dnf_args(&["install".into(), "-c".into()]).is_err());
        assert!(validate_dnf_args(&["install".into(), "-c/tmp/x.conf".into()]).is_err());
        assert!(validate_dnf_args(&["install".into(), "--repofrompath=r,/tmp/r".into()]).is_err());
        // --setopt 内联与空格两种形式
        assert!(validate_dnf_args(&["install".into(), "--setopt=reposdir=/tmp/r".into()]).is_err());
        assert!(validate_dnf_args(&[
            "install".into(),
            "--setopt".into(),
            "reposdir=/tmp/r".into()
        ])
        .is_err());
        assert!(
            validate_dnf_args(&["install".into(), "--setopt".into(), "installroot=/x".into()])
                .is_err()
        );
        // installroot/releasever 由 helper 固定设置，不允许覆盖
        assert!(validate_dnf_args(&["install".into(), "--installroot=/etc".into()]).is_err());
        assert!(validate_dnf_args(&["install".into(), "--releasever=9".into()]).is_err());
        assert!(
            validate_dnf_args(&["install".into(), "--downloaddir=/etc/cron.d".into()]).is_err()
        );
        // denylist 会静默放行的重定向类选项
        for evil in [
            "--setopt=cachedir=/etc/cron.d",
            "--setopt=persistdir=/etc/cron.d",
            "--setopt=logdir=/tmp/x",
            "--setopt=pluginconfpath=/tmp/x",
            "--setopt=varsdir=/tmp/x",
            "--forcearch=x86_64",
            "--enableplugin=nasty",
            "--disableplugin=security",
        ] {
            assert!(
                validate_dnf_args(&["install".into(), "-y".into(), evil.into()]).is_err(),
                "must reject {evil}"
            );
        }
        // 包位 smuggle 选项
        assert!(validate_dnf_args(&["install".into(), "-y".into(), "-x".into()]).is_err());
        // 动词白名单外
        assert!(validate_dnf_args(&["repoquery".into(), "bash".into()]).is_err());
        assert!(validate_dnf_args(&[]).is_err());
        assert!(validate_dnf_args(&["install".into(), "-y".into()]).is_err());
    }

    // ── host 受信 repo 目录（spawn-dnf 收权）────────────────────

    #[test]
    fn dnf_repos_dir_accepts_only_product_layout_under_root() {
        let roots = vec![
            PathBuf::from("/var/lib/crbs"),
            PathBuf::from("/var/lib/crbs-engine"),
        ];
        assert!(
            validate_dnf_repos_dir(Path::new("/var/lib/crbs-engine/dnf-repos/mydist"), &roots)
                .is_ok()
        );
        assert!(
            validate_dnf_repos_dir(Path::new("/var/lib/crbs/dnf-repos/mydist"), &roots).is_ok()
        );
        assert!(
            validate_dnf_repos_dir(Path::new("/var/lib/crbs-engine/dnf-repos"), &roots).is_err()
        );
        assert!(validate_dnf_repos_dir(Path::new("/var/lib/crbs-engine"), &roots).is_err());
        assert!(validate_dnf_repos_dir(
            Path::new("/var/lib/crbs-engine/dnf-repos/mydist/sub"),
            &roots
        )
        .is_err());
        // 布局外路径：installroot 侧 repo 目录、未配置的根、越界路径。
        assert!(validate_dnf_repos_dir(
            Path::new("/var/lib/crbs-engine/products/mydist/base/etc/yum.repos.d"),
            &roots
        )
        .is_err());
        assert!(validate_dnf_repos_dir(Path::new("/var/data/dnf-repos/mydist"), &roots).is_err());
        assert!(validate_dnf_repos_dir(Path::new("/etc/dnf-repos/mydist"), &roots).is_err());
    }

    #[test]
    fn trusted_dnf_conf_path_uses_fixed_name() {
        assert_eq!(
            trusted_dnf_conf_path(Path::new("/var/lib/crbs-engine/dnf-repos/mydist")),
            PathBuf::from("/var/lib/crbs-engine/dnf-repos/mydist/dnf.conf")
        );
    }

    #[test]
    fn trusted_asset_requires_root_owner_without_write_bits() {
        assert!(trusted_asset_ok(0, 0o755));
        assert!(trusted_asset_ok(0, 0o644));
        assert!(trusted_asset_ok(0, 0o2750));
        assert!(!trusted_asset_ok(1000, 0o755));
        assert!(!trusted_asset_ok(0, 0o775));
        assert!(!trusted_asset_ok(0, 0o757));
        assert!(!trusted_asset_ok(0, 0o666));
    }

    /// fail-closed：受信目录/配置缺失即拒绝，错误信息说明不回退 installroot 内
    /// 读取；属主断言按运行身份分流（非 root 属主拒，root 环境放行）。
    #[test]
    fn require_trusted_dnf_repos_fails_closed_when_missing() {
        use std::os::unix::fs::MetadataExt;

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("dnf-repos/mydist");
        // 经临时目录属主探测运行身份（libc/nix 是 Linux-only，测试需跨平台）。
        let running_as_root = std::fs::metadata(tmp.path())
            .map(|m| m.uid() == 0)
            .unwrap_or(false);

        let err = require_trusted_dnf_repos(&dir).unwrap_err().to_string();
        assert!(err.contains("missing"), "unexpected: {err}");
        assert!(
            err.contains("installroot"),
            "must state the no-fallback rule: {err}"
        );

        // 目录存在但配置缺失：拒绝（非 root 属主校验先行拒，都不得放行）。
        std::fs::create_dir_all(&dir).unwrap();
        assert!(require_trusted_dnf_repos(&dir).is_err());

        // 配置补齐：root 环境放行，非 root 属主不满足信任锚仍拒。
        std::fs::write(trusted_dnf_conf_path(&dir), b"[main]\n").unwrap();
        let res = require_trusted_dnf_repos(&dir);
        if running_as_root {
            assert!(res.is_ok(), "root-owned complete layout must pass: {res:?}");
        } else {
            assert!(res.is_err(), "non-root owner must fail the trust anchor");
        }
    }

    /// 白名单与注入的分工：调用方透传的 --config/--setopt=reposdir 即便与 helper 注入同形也拒（注入只在 argv 构造点）。
    #[test]
    fn validate_dnf_args_rejects_injected_lookalike_from_caller() {
        let dir = "/var/lib/crbs-engine/dnf-repos/mydist";
        for evil in [
            format!("--config={dir}/dnf.conf"),
            format!("--setopt=reposdir={dir}"),
            "--config".to_string(),
            "--setopt".to_string(),
        ] {
            assert!(
                validate_dnf_args(&["install".into(), "-y".into(), evil.clone()]).is_err(),
                "caller-supplied {evil:?} must be rejected"
            );
        }
    }
}
