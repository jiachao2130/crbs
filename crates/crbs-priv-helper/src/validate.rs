// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 路径安全校验。helper 以 setuid-root 运行，所有传入路径必须位于允许根或标准临时
//! 目录之内。

use std::path::{Path, PathBuf};

use crate::Error;

/// 校验通过时返回规范化后的路径，调用方必须使用该返回值。任何含 `..` 的输入直接
/// 拒绝：词法规范化会把它"弹出"，内核却按原路径解析、可能穿过中间 symlink 作用到
/// 别处，校验路径与实际作用的路径必须严格一致。
pub fn validate_path_normalized(path: &Path, allowed_roots: &[PathBuf]) -> Result<PathBuf, Error> {
    validate_path_normalized_with(path, allowed_roots, LeafSymlinkPolicy::Reject)
}

#[derive(Clone, Copy)]
/// 叶子组件为 symlink 时的策略。Reject 一律拒绝；AllowReplace 仅 WriteFile 使用——
/// 它的 tempfile+rename 流程原子替换的正是叶子本身。
pub enum LeafSymlinkPolicy {
    Reject,

    AllowReplace,
}

/// [`validate_path_normalized`] 的叶子 symlink 放行变体：仅 WriteFile 使用。
/// `ops::write_file` 的 tempfile 加 rename 流程原子替换的正是叶子本身
/// （rename(2) 不跟随目标、不触达链接指向处），中间组件 symlink 仍被
/// `validate_path_components` 拒绝。典型场景：base_os 的 `etc/resolv.conf`
/// 是指向 `../run/systemd/resolve/stub-resolv.conf` 的 symlink（nspawn 首启
/// 由 systemd-resolved 生成），构建层需用普通文件原子替换。
pub fn validate_path_normalized_leaf_replace(
    path: &Path,
    allowed_roots: &[PathBuf],
) -> Result<PathBuf, Error> {
    validate_path_normalized_with(path, allowed_roots, LeafSymlinkPolicy::AllowReplace)
}

/// mount 目标必须是允许根或临时根的严格后代：目标等于根本身时，卸载会把整个
/// crbs 数据区或临时根拆掉。
pub fn validate_mount_target(path: &Path, allowed_roots: &[PathBuf]) -> Result<PathBuf, Error> {
    let normalized = validate_path_normalized(path, allowed_roots)?;
    let hits_root = allowed_roots.contains(&normalized);
    let hits_temp_root = ["/dev/shm", "/var/tmp", "/tmp"]
        .iter()
        .any(|p| normalized == Path::new(p));
    if hits_root || hits_temp_root {
        return Err(Error::Validation(format!(
            "mount target must be a strict descendant, not the root itself: {}",
            path.display()
        )));
    }
    Ok(normalized)
}

fn validate_path_normalized_with(
    path: &Path,
    allowed_roots: &[PathBuf],
    leaf_policy: LeafSymlinkPolicy,
) -> Result<PathBuf, Error> {
    if !path.is_absolute() {
        return Err(Error::Validation(format!(
            "path is not absolute: {}",
            path.display()
        )));
    }

    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Error::Validation(format!(
            "path contains '..' component: {}",
            path.display()
        )));
    }

    let normalized = normalize_path(path)?;

    let Some(prefix) = allowed_roots
        .iter()
        .find(|root| normalized == **root || normalized.starts_with(root))
        .map(|p| p.as_path())
        .or_else(|| temp_dir_prefix(&normalized))
    else {
        return Err(Error::Validation(format!(
            "path escapes allowed roots: {}",
            path.display()
        )));
    };

    validate_path_components(&normalized, prefix)?;

    if let Ok(meta) = std::fs::symlink_metadata(&normalized) {
        if meta.file_type().is_symlink() {
            match leaf_policy {
                LeafSymlinkPolicy::Reject => {
                    return Err(Error::Validation(format!(
                        "path is a symlink: {}",
                        path.display()
                    )));
                }
                LeafSymlinkPolicy::AllowReplace => {}
            }
        }
    }

    Ok(normalized)
}

/// 校验路径安全：绝对路径、位于允许根目录集合或标准临时目录之下、不含
/// `..`、不是 symlink。任何含 `..` 的输入直接拒绝（词法规范化与内核解析存
/// 在分歧：`..` 在词法规范化时被消去，内核却按原路径解析并可能穿过中间
/// symlink 作用到别处，如 `/tmp/s/../etc/x`），使"校验的路径"与"作用的路
/// 径"严格一致。允许 /dev/shm、/var/tmp、/tmp：CRBS 在这些目录创建
/// upperdir/workdir/target，lowerdir 仍必须在 crbs_root 或额外允许路径下。
///
/// 残余 TOCTOU 窗口（已知、可接受）：校验之后攻击者可把某个中间目录换成
/// symlink。缓解：one-shot 进程窗口微秒级、每次调用重新校验；write、
/// chown、chmod、rm-rf、mkdir-chown 走 fs_walk 逐组件
/// `openat(O_NOFOLLOW)`，在内核级消除该窗口；mount/umount 仍按路径解析
/// （挂载点没有自然的 dirfd 形态），彻底消除需 fd 定位（逐组件 open 后以
/// /proc/self/fd/N 作为路径参数），留待后续升级。
pub fn validate_path(path: &Path, allowed_roots: &[PathBuf]) -> Result<(), Error> {
    validate_path_normalized(path, allowed_roots).map(|_| ())
}

fn validate_path_components(normalized: &Path, prefix: &Path) -> Result<(), Error> {
    let mut parent = normalized.parent();
    while let Some(p) = parent {
        if p == prefix || p == Path::new("/") {
            break;
        }
        if let Ok(meta) = std::fs::symlink_metadata(p) {
            if meta.file_type().is_symlink() {
                return Err(Error::Validation(format!(
                    "path component is a symlink: {}",
                    p.display()
                )));
            }
        }
        parent = p.parent();
    }
    Ok(())
}

pub fn is_under_temp_dir(normalized: &Path) -> bool {
    temp_dir_prefix(normalized).is_some()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
/// umount 目标所属的合法卸载域，调用方按域采取不同的防护。
pub enum UmountDomain {
    AllowedRoot,

    TempDotTmp,
}

/// 判定已规范化的 umount 目标落在哪个合法卸载域，域外返回 None。allowed root 域 =
/// 严格位于某 root 之下（等于根本身不算）；临时域 = /tmp、/var/tmp、/dev/shm 之下
/// 且第一级组件以 ".tmp" 开头。共享临时区里任意命名的挂载点都可被 MNT_DETACH，等于
/// 对同机第三方挂载点开放拒绝服务面，因此非 .tmp 命名与临时根本身都拒绝。规则与
/// ops::mount_in_gc_scan_domain 的 tmp 分支一致。
pub fn umount_target_domain(normalized: &Path, allowed_roots: &[PathBuf]) -> Option<UmountDomain> {
    if allowed_roots
        .iter()
        .any(|root| normalized.as_os_str() != root.as_os_str() && normalized.starts_with(root))
    {
        return Some(UmountDomain::AllowedRoot);
    }
    let under_tmp_dot = temp_dir_prefix(normalized).is_some_and(|prefix| {
        normalized.strip_prefix(prefix).is_ok_and(|rest| {
            rest.components()
                .next()
                .is_some_and(|c| c.as_os_str().to_string_lossy().starts_with(".tmp"))
        })
    });
    under_tmp_dot.then_some(UmountDomain::TempDotTmp)
}

/// 允许根本身的唯一合法 mode：2770 = setgid + 属主/组可读写，
/// root、crbs-server、crbs 组三个身份可读写，新文件继承 crbs 组。
pub const ROOT_EQUAL_DIR_MODE: u32 = 0o2770;

pub fn equals_allowed_root(normalized: &Path, allowed_roots: &[PathBuf]) -> bool {
    allowed_roots
        .iter()
        .any(|root| normalized.as_os_str() == root.as_os_str())
}

/// rm-rf 的根等值拒绝：任一目标等于允许根本身即整体拒绝，不部分执行。删根等于
/// 一条命令清除全部产品数据与共享层，没有合法调用方；"清空根下内容"由调用方展开为
/// 根的直接子项逐个传入。
pub fn validate_rm_rf_paths(paths: &[PathBuf], allowed_roots: &[PathBuf]) -> Result<(), Error> {
    if let Some(p) = paths.iter().find(|p| equals_allowed_root(p, allowed_roots)) {
        return Err(Error::Validation(format!(
            "rm-rf refuses to remove an allowed root itself (delete its children instead): {}",
            p.display()
        )));
    }
    Ok(())
}

/// 对允许根本身的 mkdir-chown 做参数收死：属主仅 root（root 调用方时还允许
/// crbs-server），组必须 crbs，mode 必须恰为 2770。放宽任一维度都等于把数据根交给
/// 调用方（属主可自行再 chmod，组权限不变量失守）。
pub fn validate_root_equal_mkdir_chown(
    user: &str,
    group: &str,
    mode: u32,
    caller_is_root: bool,
) -> Result<(), Error> {
    let owner_ok = user == "root" || (caller_is_root && user == "crbs-server");
    if !owner_ok {
        return Err(Error::Validation(format!(
            "mkdir-chown on an allowed root itself only accepts owner 'root'{} (got {user:?}); \
             chowning the data root to anything else hands the whole crbs data tree to that user",
            if caller_is_root {
                " or 'crbs-server'"
            } else {
                ""
            },
        )));
    }
    if group != "crbs" {
        return Err(Error::Validation(format!(
            "mkdir-chown on an allowed root itself requires group 'crbs' (got {group:?})"
        )));
    }
    if mode != ROOT_EQUAL_DIR_MODE {
        return Err(Error::Validation(format!(
            "mkdir-chown on an allowed root itself only accepts mode 2770 (got {:04o}); \
             the data root must keep the group-inheritance invariant and never be \
             world-writable",
            mode
        )));
    }
    Ok(())
}

/// 根等值 chown 的参数收死：属主必须仍是 root，组必须是 crbs 组。
pub fn validate_root_equal_chown(uid: u32, gid: u32, crbs_gid: u32) -> Result<(), Error> {
    if uid != 0 {
        return Err(Error::Validation(format!(
            "chown on an allowed root itself only accepts uid 0 (got {uid}); \
             the data root must stay root-owned"
        )));
    }
    if gid != crbs_gid {
        return Err(Error::Validation(format!(
            "chown on an allowed root itself requires the crbs group gid {crbs_gid} (got {gid})"
        )));
    }
    Ok(())
}

/// 根等值 chmod 的参数收死：mode 必须恰为 2770，放宽会破坏共享访问不变量。
pub fn validate_root_equal_chmod(mode: u32) -> Result<(), Error> {
    if mode != ROOT_EQUAL_DIR_MODE {
        return Err(Error::Validation(format!(
            "chmod on an allowed root itself only accepts mode 2770 (got {:04o}); \
             loosening the data root mode breaks the shared-access invariant",
            mode
        )));
    }
    Ok(())
}

/// 返回路径所在的标准临时目录前缀（仅 /dev/shm、/var/tmp、/tmp，否则 None）。
/// 比较要求 / 分隔，避免 /dev/shmfoo 之类被误匹配。
fn temp_dir_prefix(normalized: &Path) -> Option<&'static Path> {
    let prefixes = ["/dev/shm", "/var/tmp", "/tmp"];
    for prefix in prefixes {
        let p = Path::new(prefix);
        if normalized.as_os_str() == prefix || normalized.starts_with(format!("{}/", prefix)) {
            return Some(p);
        }
    }
    None
}

/// 规范化绝对路径，不解析 symlink。
pub fn normalize_path(path: &Path) -> Result<PathBuf, Error> {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::RootDir => out.push("/"),
            std::path::Component::Normal(c) => out.push(c),
            std::path::Component::ParentDir => {
                if !out.pop() {
                    return Err(Error::Validation(format!(
                        "path has too many '..' components: {}",
                        path.display()
                    )));
                }
            }
            std::path::Component::CurDir => {}
            std::path::Component::Prefix(_) => {
                return Err(Error::Validation(format!(
                    "unsupported path prefix: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(out)
}

/// write-cgroup-file 允许写入的子树：crbs-core nspawn 后端只写 payload scope
/// （machine.slice/machine-*.scope/ 之下）的控制文件，组成员不能借 helper 改写宿主
/// 其它 cgroup 的状态。
pub const CGROUP_WRITABLE_ROOT: &str = "/sys/fs/cgroup/machine.slice";

/// 允许写入的控制文件名：payload cgroup 的资源限制文件与终止通道。其余文件一律
/// 拒绝——cgroup.procs 可迁移任意进程进任意 cgroup，尤其不能放行。
pub const CGROUP_WRITABLE_FILES: &[&str] =
    &["memory.max", "memory.swap.max", "cpu.max", "cgroup.kill"];

/// pgid 校验：kill-process-group 用负 pid 约定，拒绝 0（自身组）与 1（init 组），
/// 误杀这两者属于逻辑错误。
pub fn validate_pgid(pgid: i32) -> Result<i32, Error> {
    if pgid <= 1 {
        return Err(Error::Validation(format!(
            "kill-process-group pgid {pgid} is invalid (must be > 1)"
        )));
    }
    Ok(pgid)
}

/// crbs 构建容器的 cgroup 子树根。构建容器 scope 由 machined 建在 machine.slice
/// 之下；本 crate 不依赖 crbs-core，硬编码同值。
pub const KILL_SCOPE_CGROUP_SUBTREE: &str = "/machine.slice";

/// 从 /proc/{pid}/stat 内容解析 pgrp（第 5 字段）：comm 可含空格/括号，取最后一个
/// `)` 之后第 3 个空白分隔字段（state、ppid 之后），后段字段不含括号，取位无歧义。
pub fn parse_stat_pgrp(stat: &str) -> Option<u32> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(2)?
        .parse()
        .ok()
}

pub fn parse_status_uid(status: &str) -> Option<u32> {
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    line.strip_prefix("Uid:")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

pub fn parse_cgroup_v2_path(content: &str) -> Option<&str> {
    content.lines().find_map(|l| l.strip_prefix("0::"))
}

/// kill 作用域的属主谓词，任一成立即放行：
/// a) 容器化构建成员：/proc/{pid}/root 位于配置允许根或标准临时目录之下（与 spawn
///    校验同一套允许根推导——helper 能 spawn 的沙箱根，取消、超时、清扫时必能 kill）；
/// b) machined 为 crbs 容器注册的 scope 成员（cgroup 路径位于 crbs 命名空间）；
/// c) 调用者本人：成员 real uid 等于 caller_uid。
/// 信息缺失（None）的谓词视为不成立，逐成员失败即拒绝。
pub fn scope_allows(
    proc_root: Option<&Path>,
    cgroup_path: Option<&str>,
    member_uid: Option<u32>,
    caller_uid: u32,
    allowed_roots: &[PathBuf],
) -> bool {
    if let Some(root) = proc_root {
        if kill_scope_root_allowed(root, allowed_roots) {
            return true;
        }
    }
    if let Some(cg) = cgroup_path {
        if crbs_machine_scope(cg) {
            return true;
        }
    }
    member_uid == Some(caller_uid)
}

/// a 谓词的允许根判定：组件级前缀比较，防止兄弟前缀误匹配（/var/lib/crbs2 不等于
/// /var/lib/crbs 之下）。
fn kill_scope_root_allowed(root: &Path, allowed_roots: &[PathBuf]) -> bool {
    allowed_roots
        .iter()
        .any(|r| root == r || root.starts_with(r))
        || is_under_temp_dir(root)
}

fn crbs_machine_scope(cg: &str) -> bool {
    let subtree = Path::new(KILL_SCOPE_CGROUP_SUBTREE);
    let p = Path::new(cg);
    if p == subtree || !p.starts_with(subtree) {
        return false;
    }
    let Some(scope) = p
        .strip_prefix(subtree)
        .ok()
        .and_then(|rest| rest.components().next())
    else {
        return false;
    };
    let name = scope.as_os_str().to_string_lossy();

    let decoded = name.replace("\\x2d", "-");
    // systemd 转义的组件名先解码再判定命名空间；解码不放宽边界——命中仍需 crbs-
    // 前缀 + .scope 后缀的 machine 命名空间形态。
    (decoded.starts_with("crbs-") || decoded.starts_with("machine-crbs-"))
        && decoded.ends_with(".scope")
}

/// kill-process-group 的属主作用域校验：root 可杀任意 pgid，组成员可能借此杀系统
/// 服务，因此组内每个存活成员都必须满足 scope_allows 的至少一条谓词，任一越界即
/// 整体拒绝；成员为空 = 组已死，幂等成功。必须扫描 /proc 成员：/proc/{pgid} 缺失
/// 不能当作组已死——组长退出而组仍存活时会留下无人收割的进程组。
pub fn validate_kill_scope(
    pgid: i32,
    caller_uid: u32,
    allowed_roots: &[PathBuf],
) -> Result<(), Error> {
    let Ok(target_pgrp) = u32::try_from(pgid) else {
        // 非正 pgid 不可能有组成员（上游 validate_pgid 已拒绝），按空组幂等成功。
        return Ok(());
    };
    let proc_fs = Path::new("/proc");
    let entries = std::fs::read_dir(proc_fs).map_err(|e| {
        Error::Io(std::io::Error::other(format!(
            "kill-process-group scan {}/: {e}",
            proc_fs.display()
        )))
    })?;
    let mut members: Vec<u32> = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };

        let stat = match std::fs::read_to_string(proc_fs.join(entry.file_name()).join("stat")) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                // stat 不可读时分流：ENOENT = 进程已退出（扫描间隙消失），跳过；
                // 其余错误 = 组成员关系不可判定，整体拒绝（静默跳过等于放行越界成员）。
                return Err(Error::Io(std::io::Error::other(format!(
                    "kill-process-group scan /proc/{pid}/stat: {e}"
                ))));
            }
        };
        if parse_stat_pgrp(&stat) == Some(target_pgrp) {
            members.push(pid);
        }
    }
    for pid in members {
        let dir = proc_fs.join(pid.to_string());

        let proc_root = match std::fs::read_link(dir.join("root")) {
            Ok(p) => normalize_path(&p).ok(),
            // ENOENT = 成员已退出（SIGKILL 对其无意义），跳过；其余失败置 None，
            // 由谓词判定（能判定的谓词仍然生效）。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => None,
        };
        let cgroup_path = match std::fs::read_to_string(dir.join("cgroup")) {
            Ok(c) => parse_cgroup_v2_path(&c).map(str::to_owned),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => None,
        };
        let member_uid = match std::fs::read_to_string(dir.join("status")) {
            Ok(s) => parse_status_uid(&s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => None,
        };
        if !scope_allows(
            proc_root.as_deref(),
            cgroup_path.as_deref(),
            member_uid,
            caller_uid,
            allowed_roots,
        ) {
            return Err(Error::Validation(format!(
                "kill-process-group pgid {pgid} has a member outside the allowed scope"
            )));
        }
    }
    Ok(())
}

/// 校验 `write-cgroup-file` 的目标路径（语义与 validate_path_normalized 对
/// 齐：绝对路径、拒绝 `..`、词法规范化），并要求严格位于
/// [`CGROUP_WRITABLE_ROOT`] 之下（等于根本身拒绝——作用于 slice 根会改写
/// 整个层级的容器状态）、叶子文件名在 [`CGROUP_WRITABLE_FILES`] 白名单内。
/// cgroupfs（kernfs）不由调用方可写介质支撑、目录组件也无法被普通用户替
/// 换成 symlink，故不做 allowed_roots 与 symlink 检查，前缀加文件名白名单
/// 已覆盖全部攻击面。
pub fn validate_cgroup_file_path(path: &Path) -> Result<PathBuf, Error> {
    if !path.is_absolute() {
        return Err(Error::Validation(format!(
            "write-cgroup-file path is not absolute: {}",
            path.display()
        )));
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Error::Validation(format!(
            "write-cgroup-file path contains '..' component: {}",
            path.display()
        )));
    }
    let normalized = normalize_path(path)?;
    let root = Path::new(CGROUP_WRITABLE_ROOT);

    if normalized == root || !normalized.starts_with(root) {
        return Err(Error::Validation(format!(
            "write-cgroup-file path must be strictly under {CGROUP_WRITABLE_ROOT}/: {}",
            path.display()
        )));
    }
    let file_name = normalized
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            Error::Validation(format!(
                "write-cgroup-file path has no file name: {}",
                path.display()
            ))
        })?;
    if !CGROUP_WRITABLE_FILES.contains(&file_name) {
        return Err(Error::Validation(format!(
            "write-cgroup-file file name '{file_name}' is not allowed (allowed: {})",
            CGROUP_WRITABLE_FILES.join(", ")
        )));
    }
    Ok(normalized)
}

/// terminate-machine 的 machine 名是唯一信任依据：仅接受 crbs 自建命名空间——
/// `crbs-` 前缀加 `^[0-9a-fA-F-]{8,64}$`（crbs-core nspawn `machine_name_for`
/// 的生成形态 `crbs-{8hex}[-{build_id}]`）。分隔符、`..` 与路径组件在该字
/// 符集下不可能成立，名称直接拼接 scope 路径即安全。
pub fn validate_machine_name(name: &str) -> Result<&str, Error> {
    let Some(rest) = name.strip_prefix("crbs-") else {
        return Err(Error::Validation(format!(
            "terminate-machine name {name:?} is outside the crbs machine namespace \
             (must match crbs-[0-9a-fA-F-]{{8,64}})"
        )));
    };
    let charset_ok = rest.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
    if !(8..=64).contains(&rest.len()) || !charset_ok {
        return Err(Error::Validation(format!(
            "terminate-machine name {name:?} is outside the crbs machine namespace \
             (must match crbs-[0-9a-fA-F-]{{8,64}})"
        )));
    }
    Ok(name)
}

pub(crate) fn systemd_escape_dash(name: &str) -> String {
    name.replace('-', "\\x2d")
}

/// /proc/{pid}/cgroup 内容是否把进程置于 machine_name 的 machine.slice scope
/// 之内：任一行路径严格位于 /machine.slice 之下、且下一级组件为
/// `{name}.scope` / `machine-{name}.scope` 的原样或转义形态（组件级整段比较，
/// 兄弟前缀不误匹配）。v2 `0::` 行与 v1 行同判——cgroup v1 宿主无 `0::` 行，
/// 只认 v2 会让成员判定落空；machined 注册的 scope 目录名即转义形态，只认
/// 原样名两栈都会漏杀。
pub fn cgroup_in_machine_scope(cgroup_content: &str, machine_name: &str) -> bool {
    let escaped = systemd_escape_dash(machine_name);
    let scope_names = [
        format!("{machine_name}.scope"),
        format!("{escaped}.scope"),
        format!("machine-{machine_name}.scope"),
        format!("machine-{escaped}.scope"),
    ];
    cgroup_content.lines().any(|line| {
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

/// 校验 `write-cgroup-file` 的写入值：非空，且仅允许数字、空格、小写字母
///（"max" / "1" / "200000 100000" 均合法）。值直接进 cgroupfs 控制文件，
/// 其它字符（大写、符号、换行注入等）没有合法调用方，失败即拒绝。
pub fn validate_cgroup_value(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b' ' || b.is_ascii_lowercase())
    {
        return Err(Error::Validation(format!(
            "write-cgroup-file value must be non-empty digits/spaces/lowercase letters: {value:?}"
        )));
    }
    Ok(())
}

/// 校验 mount data 携值键的值域（键到值域按 devpts/tmpfs 的合法取值形态收窄）：
/// mode/ptmxmode 3~4 位八进制；uid/gid 1~10 位十进制；size/nr_inodes 十进制 +
/// 可选 k/K/m/M/g/G 后缀或字面量 "max"；所有值非空且不含空白/控制字符（data
/// 整串原样进 mount(2) 的 data 参数，白名单字符集兜底防注入）。无值键（如
/// newinstance）以 `None` 放行；携值不在值域表内的键拒绝。
pub fn validate_mount_data_value(key: &str, value: Option<&str>) -> Result<(), Error> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_empty() || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Error::Validation(format!(
            "mount data value for '{key}' must be non-empty without whitespace/control \
             characters: {value:?}"
        )));
    }
    let ok = match key {
        "mode" | "ptmxmode" => {
            (3..=4).contains(&value.len()) && value.bytes().all(|b| (b'0'..=b'7').contains(&b))
        }
        "uid" | "gid" => {
            (1..=10).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit())
        }
        "size" | "nr_inodes" => {
            if value == "max" {
                true
            } else {
                let digits = match value.as_bytes() {
                    [d @ .., b'k' | b'K' | b'm' | b'M' | b'g' | b'G'] => d,
                    d => d,
                };
                !digits.is_empty() && digits.iter().all(|b| b.is_ascii_digit())
            }
        }
        _ => false,
    };
    if !ok {
        return Err(Error::Validation(format!(
            "mount data option '{key}={value}' has an invalid value format"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_absolute_path() {
        assert_eq!(
            normalize_path(Path::new("/a/b/c")).unwrap(),
            PathBuf::from("/a/b/c")
        );
    }

    #[test]
    fn normalize_resolves_dotdot() {
        assert_eq!(
            normalize_path(Path::new("/a/../b/c")).unwrap(),
            PathBuf::from("/b/c")
        );
    }

    #[test]
    fn normalize_rejects_too_many_dotdot() {
        assert!(normalize_path(Path::new("/a/../../c")).is_err());
    }

    #[test]
    fn validate_path_under_allowed_root() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];
        assert!(validate_path(Path::new("/var/lib/crbs/layers/foo"), &allowed).is_ok());
    }

    #[test]
    fn validate_path_under_custom_allowed_root() {
        let allowed = vec![
            PathBuf::from("/var/lib/crbs"),
            PathBuf::from("/data/crbs-results"),
        ];
        assert!(validate_path(Path::new("/data/crbs-results/mydist/123"), &allowed).is_ok());
    }

    #[test]
    fn validate_path_under_tmp() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];
        assert!(validate_path(Path::new("/tmp/crbs-build-123"), &allowed).is_ok());
    }

    #[test]
    fn validate_path_under_dev_shm() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];
        assert!(validate_path(Path::new("/dev/shm/crbs-build-123"), &allowed).is_ok());
    }

    #[test]
    fn validate_path_rejects_escape() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];
        assert!(validate_path(Path::new("/etc/passwd"), &allowed).is_err());
    }

    #[test]
    fn validate_path_rejects_relative() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];
        assert!(validate_path(Path::new("foo/bar"), &allowed).is_err());
    }

    #[test]
    fn validate_path_rejects_dotdot_escape() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];
        assert!(validate_path(Path::new("/var/lib/crbs/../../etc/passwd"), &allowed).is_err());
    }

    #[test]
    fn validate_path_rejects_any_dotdot_component_even_in_bounds() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];
        assert!(validate_path(Path::new("/tmp/s/../etc/x"), &allowed).is_err());
        assert!(validate_path(Path::new("/var/lib/crbs/a/../x"), &allowed).is_err());
        let err = validate_path(Path::new("/tmp/s/../etc/x"), &allowed)
            .unwrap_err()
            .to_string();
        assert!(err.contains("'..'"), "unexpected: {err}");
    }

    #[test]
    fn validate_path_normalized_returns_normalized_path() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let allowed = vec![base.clone()];
        assert_eq!(
            validate_path_normalized(&base.join("a/./b"), &allowed).unwrap(),
            base.join("a/b")
        );
        assert_eq!(validate_path_normalized(&base, &allowed).unwrap(), base);
    }

    #[test]
    fn validate_path_normalized_rejects_dotdot_input() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];
        assert!(validate_path_normalized(Path::new("/var/lib/crbs/x/.."), &allowed).is_err());
    }

    #[test]
    fn mount_target_rejects_root_and_temp_root_equality() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let allowed = vec![base.clone()];

        assert!(validate_mount_target(&base, &allowed).is_err());
        assert!(validate_mount_target(&base.join("a/b"), &allowed).is_ok());
        assert!(validate_mount_target(Path::new("/tmp"), &allowed).is_err());
        assert!(validate_mount_target(Path::new("/var/tmp"), &allowed).is_err());
        assert!(validate_mount_target(Path::new("/dev/shm"), &allowed).is_err());
        assert!(validate_mount_target(Path::new("/tmp/.tmpabc/root"), &allowed).is_ok());
    }

    #[test]
    fn validate_path_normalized_leaf_symlink_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let allowed = vec![base.clone()];
        let target = base.join("real-file");
        std::fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, base.join("link")).unwrap();

        assert!(validate_path_normalized(&base.join("link"), &allowed).is_err());
        assert!(validate_path_normalized(&target, &allowed).is_ok());
    }

    #[test]
    fn validate_path_normalized_leaf_replace_allows_leaf_symlink_only() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let allowed = vec![base.clone()];
        let target = base.join("real-file");
        std::fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, base.join("link")).unwrap();

        assert!(
            validate_path_normalized_leaf_replace(&base.join("link"), &allowed).is_ok(),
            "leaf symlink must be allowed for write-file"
        );

        std::fs::create_dir(base.join("dir")).unwrap();
        std::os::unix::fs::symlink(&target, base.join("dir/sub")).unwrap();
        assert!(
            validate_path_normalized_leaf_replace(&base.join("dir/sub/file"), &allowed).is_err(),
            "intermediate symlink component must stay rejected"
        );
    }

    #[test]
    fn umount_target_domain_allowed_root_arm() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];
        assert_eq!(
            umount_target_domain(Path::new("/var/lib/crbs/layers/x/root"), &allowed),
            Some(UmountDomain::AllowedRoot)
        );
        assert_eq!(
            umount_target_domain(Path::new("/var/lib/crbs"), &allowed),
            None
        );

        assert_eq!(umount_target_domain(Path::new("/etc"), &allowed), None);
    }

    #[test]
    fn umount_target_domain_tmp_arm_requires_dot_tmp_first_component() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];
        assert_eq!(
            umount_target_domain(Path::new("/var/tmp/.tmpabc/root"), &allowed),
            Some(UmountDomain::TempDotTmp)
        );
        assert_eq!(
            umount_target_domain(Path::new("/dev/shm/.tmpX1/root/proc"), &allowed),
            Some(UmountDomain::TempDotTmp)
        );
        assert_eq!(
            umount_target_domain(Path::new("/var/tmp/.tmpabc"), &allowed),
            Some(UmountDomain::TempDotTmp)
        );
        assert_eq!(
            umount_target_domain(Path::new("/var/tmp/foo"), &allowed),
            None
        );
        assert_eq!(
            umount_target_domain(Path::new("/var/tmp/my-mount/sub"), &allowed),
            None
        );

        assert_eq!(
            umount_target_domain(Path::new("/var/tmpfoo/.tmpA"), &allowed),
            None
        );
    }

    #[test]
    fn umount_target_domain_rejects_roots_themselves() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];
        assert_eq!(umount_target_domain(Path::new("/tmp"), &allowed), None);
        assert_eq!(umount_target_domain(Path::new("/var/tmp"), &allowed), None);
        assert_eq!(umount_target_domain(Path::new("/dev/shm"), &allowed), None);

        let allowed_under_tmp = vec![PathBuf::from("/var/tmp/crbs")];
        assert_eq!(
            umount_target_domain(Path::new("/var/tmp/crbs"), &allowed_under_tmp),
            None
        );

        let dot_tmp_root = vec![PathBuf::from("/var/tmp/.tmpabc")];
        assert_eq!(
            umount_target_domain(Path::new("/var/tmp/.tmpabc/root"), &dot_tmp_root),
            Some(UmountDomain::AllowedRoot)
        );
    }

    #[test]
    fn validate_path_rejects_intermediate_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let allowed = vec![base.clone()];

        let real_dir = base.join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let link_dir = base.join("link");
        std::os::unix::fs::symlink(tmp.path(), &link_dir).unwrap();

        assert!(validate_path(&real_dir.join("file"), &allowed).is_ok());
        assert!(validate_path(&link_dir.join("file"), &allowed).is_err());
    }

    #[test]
    fn validate_path_accepts_deep_allowed_path() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let allowed = vec![base.clone()];
        let deep = base.join("a").join("b").join("c");
        std::fs::create_dir_all(&deep).unwrap();
        assert!(validate_path(&deep.join("file"), &allowed).is_ok());
    }

    #[test]
    fn is_under_temp_dir_shm() {
        assert!(is_under_temp_dir(Path::new("/dev/shm/foo")));
        assert!(!is_under_temp_dir(Path::new("/dev/shmfoo")));
    }

    #[test]
    fn validate_cgroup_file_path_accepts_whitelisted_files() {
        for file in ["memory.max", "memory.swap.max", "cpu.max", "cgroup.kill"] {
            let p = validate_cgroup_file_path(Path::new(&format!(
                "/sys/fs/cgroup/machine.slice/machine-crbs-1.scope/payload/{file}"
            )))
            .unwrap_or_else(|e| panic!("{file} must be allowed: {e}"));
            assert!(p.starts_with("/sys/fs/cgroup/machine.slice/"));
        }
    }

    #[test]
    fn validate_cgroup_file_path_rejects_root_and_outside() {
        assert!(validate_cgroup_file_path(Path::new("/sys/fs/cgroup/machine.slice")).is_err());

        assert!(validate_cgroup_file_path(Path::new("/sys/fs/cgroupfoo/memory.max")).is_err());
        assert!(validate_cgroup_file_path(Path::new("/etc/passwd")).is_err());
        assert!(validate_cgroup_file_path(Path::new("/sys/fs/cgroup/../../etc/passwd")).is_err());

        assert!(validate_cgroup_file_path(Path::new(
            "/sys/fs/cgroup/system.slice/sshd.service/cgroup.kill"
        ))
        .is_err());
        assert!(
            validate_cgroup_file_path(Path::new("/sys/fs/cgroup/init.scope/cgroup.procs")).is_err()
        );
        assert!(validate_cgroup_file_path(Path::new("/sys/fs/cgroup/memory.max")).is_err());
        assert!(validate_cgroup_file_path(Path::new("sys/fs/cgroup/memory.max")).is_err());
        assert!(validate_cgroup_file_path(Path::new(
            "/sys/fs/cgroup/machine.slice/../machine.slice/x/memory.max"
        ))
        .is_err());
    }

    #[test]
    fn validate_cgroup_file_path_rejects_non_whitelisted_file() {
        for file in [
            "cgroup.subtree_control",
            "cgroup.procs",
            "tasks",
            "memory.high",
            "cgroup.type",
            "pids.max",
            "notify_on_release",
        ] {
            assert!(
                validate_cgroup_file_path(Path::new(&format!(
                    "/sys/fs/cgroup/machine.slice/x.scope/payload/{file}"
                )))
                .is_err(),
                "{file} must be rejected"
            );
        }
    }

    #[test]
    fn validate_cgroup_value_charset() {
        assert!(validate_cgroup_value("1").is_ok());
        assert!(validate_cgroup_value("max").is_ok());
        assert!(validate_cgroup_value("200000 100000").is_ok());
        assert!(validate_cgroup_value("").is_err());
        assert!(validate_cgroup_value("MAX").is_err());
        assert!(validate_cgroup_value("1\n").is_err());
        assert!(validate_cgroup_value("1;reboot").is_err());
        assert!(validate_cgroup_value("1 2\t3").is_err());
        assert!(validate_cgroup_value("+1").is_err());
    }

    #[test]
    fn mount_data_value_accepts_legal_forms() {
        assert!(validate_mount_data_value("newinstance", None).is_ok());
        assert!(validate_mount_data_value("mode", Some("0620")).is_ok());
        assert!(validate_mount_data_value("ptmxmode", Some("666")).is_ok());
        assert!(validate_mount_data_value("mode", Some("0777")).is_ok());
        assert!(validate_mount_data_value("uid", Some("0")).is_ok());
        assert!(validate_mount_data_value("gid", Some("4294967295")).is_ok());
        assert!(validate_mount_data_value("size", Some("1073741824")).is_ok());
        assert!(validate_mount_data_value("size", Some("1g")).is_ok());
        assert!(validate_mount_data_value("size", Some("512M")).is_ok());
        assert!(validate_mount_data_value("nr_inodes", Some("1024k")).is_ok());
        assert!(validate_mount_data_value("size", Some("max")).is_ok());
    }

    #[test]
    fn mount_data_value_rejects_illegal_forms() {
        for bad in ["9999", "12345", "62", "0620=1", "O620", "+620", "06 20"] {
            assert!(
                validate_mount_data_value("mode", Some(bad)).is_err(),
                "mode value {bad:?} must be rejected"
            );
        }
        for bad in ["+1000", "-1", "0x10", "10000000000", "1 2", "abc"] {
            assert!(
                validate_mount_data_value("uid", Some(bad)).is_err(),
                "uid value {bad:?} must be rejected"
            );
        }
        for bad in ["10x", "1kk", "k", "mAx", "1M2", ""] {
            assert!(
                validate_mount_data_value("size", Some(bad)).is_err(),
                "size value {bad:?} must be rejected"
            );
        }
        for key in ["mode", "uid", "size", "nr_inodes"] {
            assert!(validate_mount_data_value(key, Some("")).is_err());
            assert!(validate_mount_data_value(key, Some("1\n")).is_err());
            assert!(validate_mount_data_value(key, Some("1\t2")).is_err());
        }

        assert!(validate_mount_data_value("newinstance", Some("1")).is_err());
        assert!(validate_mount_data_value("unknown-key", Some("1")).is_err());
    }

    fn roots() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/var/lib/crbs"),
            PathBuf::from("/var/lib/crbs-engine"),
        ]
    }

    #[test]
    fn equals_allowed_root_is_exact_match_only() {
        assert!(equals_allowed_root(Path::new("/var/lib/crbs"), &roots()));
        assert!(equals_allowed_root(
            Path::new("/var/lib/crbs-engine"),
            &roots()
        ));

        assert!(!equals_allowed_root(Path::new("/var/lib/crbs/x"), &roots()));
        assert!(!equals_allowed_root(
            Path::new("/var/lib/crbs-other"),
            &roots()
        ));
        assert!(!equals_allowed_root(Path::new("/var/lib"), &roots()));
    }

    #[test]
    fn rm_rf_rejects_root_itself() {
        for root in ["/var/lib/crbs", "/var/lib/crbs-engine"] {
            let err = validate_rm_rf_paths(&[PathBuf::from(root)], &roots())
                .unwrap_err()
                .to_string();
            assert!(err.contains("allowed root"), "unexpected: {err}");
        }
        assert!(validate_rm_rf_paths(
            &[
                PathBuf::from("/var/lib/crbs/products/x"),
                PathBuf::from("/var/lib/crbs")
            ],
            &roots()
        )
        .is_err());
        assert!(validate_rm_rf_paths(
            &[
                PathBuf::from("/var/lib/crbs/products/x"),
                PathBuf::from("/var/lib/crbs-engine/results/y"),
            ],
            &roots()
        )
        .is_ok());
    }

    #[test]
    fn root_equal_mkdir_chown_pins_owner_group_mode() {
        assert!(
            validate_root_equal_mkdir_chown("root", "crbs", 0o2770, false).is_ok(),
            "init-style root:crbs 2770 must pass for group-member callers"
        );

        assert!(
            validate_root_equal_mkdir_chown("crbs-server", "crbs", 0o2770, true).is_ok(),
            "server first-boot convergence must pass for root callers"
        );
        assert!(validate_root_equal_mkdir_chown("builder", "crbs", 0o2770, false).is_err());
        assert!(
            validate_root_equal_mkdir_chown("crbs-server", "crbs", 0o2770, false).is_err(),
            "service-account owner is root-caller-only"
        );
        assert!(validate_root_equal_mkdir_chown("root", "wheel", 0o2770, false).is_err());
        assert!(validate_root_equal_mkdir_chown("root", "root", 0o2770, false).is_err());
        for bad_mode in [0o777, 0o2777, 0o770, 0o0770, 0o755, 0o4770, 0o2700] {
            assert!(
                validate_root_equal_chmod(bad_mode).is_err(),
                "mode {:04o} must be rejected for the root itself",
                bad_mode
            );
            assert!(
                validate_root_equal_mkdir_chown("root", "crbs", bad_mode, false).is_err(),
                "mkdir-chown mode {:04o} must be rejected for the root itself",
                bad_mode
            );
        }
    }

    #[test]
    fn root_equal_chown_pins_root_owner_and_crbs_group() {
        assert!(validate_root_equal_chown(0, 1000, 1000).is_ok());
        assert!(validate_root_equal_chown(1000, 1000, 1000).is_err());
        assert!(validate_root_equal_chown(1, 1000, 1000).is_err());
        assert!(validate_root_equal_chown(0, 0, 1000).is_err());
        assert!(validate_root_equal_chown(0, 10, 1000).is_err());
    }

    #[test]
    fn root_equal_chmod_pins_2770() {
        assert!(validate_root_equal_chmod(0o2770).is_ok());
        assert!(validate_root_equal_chmod(0o755).is_err());
        assert!(validate_root_equal_chmod(0o777).is_err());
        assert!(validate_root_equal_chmod(0o770).is_err());
        assert!(validate_root_equal_chmod(0o4770).is_err());
        assert!(validate_root_equal_chmod(0o1777).is_err());
    }

    #[test]
    fn validate_pgid_rejects_non_positive_and_accepts_normal() {
        for bad in [0, 1, -1, -1000, i32::MIN] {
            assert!(validate_pgid(bad).is_err(), "pgid {bad} must be rejected");
        }
        assert_eq!(validate_pgid(2).unwrap(), 2);
        assert_eq!(validate_pgid(4194304).unwrap(), 4194304);
    }

    #[test]
    fn parse_stat_pgrp_handles_comm_with_spaces_and_parens() {
        let stat = "123 (my (weird) proc name)S 1 456 789 0";
        assert_eq!(parse_stat_pgrp(stat), Some(456));

        assert_eq!(parse_stat_pgrp("999 (bash)S 1 999 999 0"), Some(999));
        assert_eq!(parse_stat_pgrp("999 (bash)"), None);
        assert_eq!(parse_stat_pgrp("999 bash S 1 999 999"), None);
        assert_eq!(parse_stat_pgrp(""), None);
    }

    #[test]
    fn parse_status_uid_takes_real_uid_field() {
        let status = "Name:\tbash\nUid:\t1000\t1000\t1000\t5\nGid:\t1000\n";
        assert_eq!(parse_status_uid(status), Some(1000));
        assert_eq!(parse_status_uid("Uid:\t0\t0\t0\t0\n"), Some(0));
        assert!(parse_status_uid("Name:\tbash\n").is_none());
        assert!(parse_status_uid("Uid:\t\n").is_none());
    }

    #[test]
    fn parse_cgroup_v2_path_reads_unified_line() {
        assert_eq!(
            parse_cgroup_v2_path("0::/machine.slice/crbs-x.scope/payload\n"),
            Some("/machine.slice/crbs-x.scope/payload")
        );

        assert_eq!(parse_cgroup_v2_path("12:cpu:/build\n11:cpuset:/\n"), None);
        assert_eq!(parse_cgroup_v2_path(""), None);
    }

    #[test]
    fn scope_allows_container_root_under_allowed_root() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];

        assert!(scope_allows(
            Some(Path::new("/var/lib/crbs/products/p/rootfs")),
            None,
            None,
            1000,
            &allowed
        ));

        assert!(scope_allows(
            Some(Path::new("/var/lib/crbs")),
            None,
            None,
            1000,
            &allowed
        ));

        assert!(!scope_allows(
            Some(Path::new("/var/lib/crbs2/rootfs")),
            None,
            None,
            1000,
            &allowed
        ));
        assert!(!scope_allows(
            Some(Path::new("/etc")),
            None,
            None,
            1000,
            &allowed
        ));
    }

    #[test]
    fn scope_allows_tmp_sandbox_root_passes_random_path_rejected() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];
        for root in [
            "/var/tmp/.tmpABC123/root",
            "/tmp/.tmpXYZ/root",
            "/dev/shm/.tmpQ/root",
        ] {
            assert!(
                scope_allows(Some(Path::new(root)), None, None, 1000, &allowed),
                "tmp sandbox root must pass predicate a: {root}"
            );
        }
        for root in ["/home/alice/sandbox", "/srv/evil", "/opt/unknown"] {
            assert!(
                !scope_allows(Some(Path::new(root)), None, None, 1000, &allowed),
                "random root must be rejected: {root}"
            );
        }
    }

    #[test]
    fn scope_allows_cgroup_requires_crbs_scoped_scope_name() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];

        for cg in [
            "/machine.slice/crbs-1a2b3c4d.scope/payload",
            "/machine.slice/crbs-1a2b3c4d-build1.scope",
            "/machine.slice/machine-crbs-1a2b3c4d.scope/payload",
        ] {
            assert!(
                scope_allows(None, Some(cg), None, 1000, &allowed),
                "crbs scope must pass predicate b: {cg}"
            );
        }

        for cg in [
            "/machine.slice/machine-foo.scope/payload",
            "/machine.slice/docker-abc.scope",
            "/machine.slice/machine-crab-x.scope/payload",
            "/machine.slice2/x.scope",
            "/machine.slice",
            "/system.slice/sshd.service",
        ] {
            assert!(
                !scope_allows(None, Some(cg), None, 1000, &allowed),
                "non-crbs scope must be rejected: {cg}"
            );
        }
    }

    #[test]
    fn scope_allows_accepts_escaped_crbs_scope_component() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];
        for cg in [
            "/machine.slice/machine-crbs\\x2d1b033e1a\\x2d27.scope/payload",
            "/machine.slice/crbs\\x2d1b033e1a\\x2d27.scope",
            "/machine.slice/machine-crbs\\x2d1b033e1a\\x2d27.scope/payload/init",
        ] {
            assert!(
                scope_allows(None, Some(cg), None, 1000, &allowed),
                "escaped crbs scope must pass predicate b: {cg}"
            );
        }

        for cg in [
            "/machine.slice/machine-foo\\x2dbar.scope",
            "/machine.slice/docker\\x2dabc.scope",
            "/machine.slice/machine-crab\\x2dx.scope",
        ] {
            assert!(
                !scope_allows(None, Some(cg), None, 1000, &allowed),
                "escaped non-crbs scope must be rejected: {cg}"
            );
        }
    }

    #[test]
    fn scope_allows_caller_owned_member_and_fails_closed() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];

        assert!(scope_allows(None, None, Some(1000), 1000, &allowed));
        assert!(!scope_allows(None, None, Some(0), 1000, &allowed));
        assert!(!scope_allows(None, None, Some(1001), 1000, &allowed));

        assert!(!scope_allows(None, None, None, 1000, &allowed));
        assert!(!scope_allows(None, None, None, 0, &allowed));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn validate_kill_scope_self_group_and_empty_group() {
        let my_uid = unsafe { libc::getuid() } as u32;
        let my_pgid = unsafe { libc::getpgid(0) };
        let allowed = vec![PathBuf::from("/nonexistent")];
        assert!(validate_kill_scope(my_pgid, my_uid, &allowed).is_ok());

        assert!(validate_kill_scope(i32::MAX, my_uid, &allowed).is_ok());
    }

    #[test]
    fn validate_machine_name_accepts_generated_forms() {
        assert_eq!(
            validate_machine_name("crbs-9c714595").unwrap(),
            "crbs-9c714595"
        );
        assert_eq!(
            validate_machine_name("crbs-9c714595-22").unwrap(),
            "crbs-9c714595-22"
        );

        assert_eq!(
            validate_machine_name("crbs-0A1B2C3D-4e5f-6789").unwrap(),
            "crbs-0A1B2C3D-4e5f-6789"
        );

        let min = format!("crbs-{}", "a".repeat(8));
        let max = format!("crbs-{}", "a".repeat(64));
        assert_eq!(validate_machine_name(&min).unwrap(), min);
        assert_eq!(validate_machine_name(&max).unwrap(), max);
    }

    #[test]
    fn validate_machine_name_rejects_outside_namespace() {
        let too_long = format!("crbs-{}", "a".repeat(65));
        for bad in [
            "",
            "crbs-",
            "machine-crbs-9c714595",
            "CRBS-9c714595",
            "crbs-1234567",
            &too_long,
            "crbs-9c7145_95",
            "crbs-9c71.4595",
            "crbs-9c71/4595",
            "crbs-../etc",
            "crbs-9c714595-22/machine.slice",
            "crbs-9c714595 ",
            "/etc/passwd",
        ] {
            assert!(validate_machine_name(bad).is_err(), "must reject: {bad:?}");
        }
    }

    #[test]
    fn cgroup_in_machine_scope_matches_both_dialects() {
        let name = "crbs-9c714595-22";

        assert!(cgroup_in_machine_scope(
            "0::/machine.slice/crbs-9c714595-22.scope/payload\n",
            name
        ));
        assert!(cgroup_in_machine_scope(
            "0::/machine.slice/machine-crbs-9c714595-22.scope\n",
            name
        ));

        assert!(cgroup_in_machine_scope(
            "10:cpu,cpuacct:/machine.slice/machine-crbs-9c714595-22.scope/payload\n\
             11:memory:/machine.slice/machine-crbs-9c714595-22.scope\n",
            name
        ));
    }

    #[test]
    fn systemd_escape_dash_translates_dashes_only() {
        assert_eq!(systemd_escape_dash("crbs-9c714595"), "crbs\\x2d9c714595");
        assert_eq!(
            systemd_escape_dash("crbs-1b033e1a-27"),
            "crbs\\x2d1b033e1a\\x2d27"
        );

        assert_eq!(systemd_escape_dash("crbs-01234567"), "crbs\\x2d01234567");
        assert_eq!(
            systemd_escape_dash("crbs-9c714595-1b03-4e5f-8d2a-abcdef012345"),
            "crbs\\x2d9c714595\\x2d1b03\\x2d4e5f\\x2d8d2a\\x2dabcdef012345"
        );
    }

    #[test]
    fn cgroup_in_machine_scope_matches_escaped_components_both_dialects() {
        let name = "crbs-1b033e1a-27";

        assert!(cgroup_in_machine_scope(
            "0::/machine.slice/crbs\\x2d1b033e1a\\x2d27.scope/payload\n",
            name
        ));

        assert!(cgroup_in_machine_scope(
            "0::/machine.slice/machine-crbs\\x2d1b033e1a\\x2d27.scope\n",
            name
        ));

        assert!(cgroup_in_machine_scope(
            "10:cpu,cpuacct:/machine.slice/machine-crbs\\x2d1b033e1a\\x2d27.scope/payload\n\
             11:memory:/machine.slice/machine-crbs\\x2d1b033e1a\\x2d27.scope\n",
            name
        ));

        assert!(cgroup_in_machine_scope(
            "0::/machine.slice/machine-crbs\\x2d1b033e1a\\x2d27.scope/payload/init\n",
            name
        ));
    }

    #[test]
    fn cgroup_in_machine_scope_rejects_escaped_outside() {
        let name = "crbs-1b033e1a-27";
        for content in [
            "0::/machine.slice/machine-crbs\\x2ddeadbeef.scope\n",
            "0::/machine.slice/crbs\\x2d1b033e1a\\x2d2.scope\n",
            "0::/machine.slice/machine-crbs\\x2d1b033e1a\\x2d27.scope.evil/x\n",
        ] {
            assert!(
                !cgroup_in_machine_scope(content, name),
                "must reject: {content:?}"
            );
        }
    }

    #[test]
    fn cgroup_in_machine_scope_rejects_outside_and_siblings() {
        let name = "crbs-9c714595-22";
        for content in [
            "0::/machine.slice/crbs-deadbeef.scope/payload\n",
            "0::/machine.slice\n",
            "",
            "0::/machine.slice/machine-crbs-9c714595-22.scope.evil/x\n",
            "0::/machine.slice/crbs-9c714595-2.scope\n",
            "0::/system.slice/crbs-worker.service\n",
            "12:cpu:/\n",
        ] {
            assert!(
                !cgroup_in_machine_scope(content, name),
                "must reject: {content:?}"
            );
        }
    }
}
