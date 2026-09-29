// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 路径安全校验：防止路径穿越、symlink 攻击。crbs-priv-helper 作为
//! setuid-root 进程，所有传入路径必须校验在允许根目录或标准临时目录之内。

use std::path::{Path, PathBuf};

use crate::Error;

/// 校验路径安全：绝对路径、在允许根目录集合或标准临时目录下、不含 `..`、
/// 不是 symlink；通过时返回**规范化后的路径**，调用方必须把返回值交给后续
/// 系统调用。允许 /dev/shm（tmpfs 构建层）、/var/tmp、/tmp：CRBS 在这些目录
/// 创建 upperdir/workdir/target，lowerdir 仍必须在 crbs_root 或额外允许路径下。
///
/// 任何含 `..` 的输入直接拒绝（词法规范化与内核解析的分歧）：`..` 在词法
/// 规范化时被“弹出”，内核却按原路径解析、穿过中间 symlink 作用到别处
///（`/tmp/s/../etc/x` 词法上是 `/tmp/etc/x`，内核解析穿过 symlink `s` 到
/// `/etc/x`），使“校验的路径”与“作用的路径”严格一致。
///
/// 残余 TOCTOU 窗口（已知、可接受）：校验后攻击者可把某个中间目录换成 symlink。
/// 缓解：one-shot 进程窗口微秒级、每次调用重新校验；中间组件检查时须存在且非
/// symlink、需精确竞速 rename；write/chown/chmod/rm-rf/mkdir-chown 走 fs_walk
/// 逐组件 `openat(O_NOFOLLOW)` 内核级消除该窗口；mount/umount 仍按路径解析
///（挂载点没有自然的 dirfd 形态，umount 目标域已按 .tmp* 收紧），彻底消除需
/// fd 锚定（逐组件 open 后以 /proc/self/fd/N 作为路径参数），留待后续升级。
pub fn validate_path_normalized(path: &Path, allowed_roots: &[PathBuf]) -> Result<PathBuf, Error> {
    validate_path_normalized_with(path, allowed_roots, LeafSymlinkPolicy::Reject)
}

/// 叶子组件 symlink 策略：[`LeafSymlinkPolicy::Reject`] 一律拒绝（mount/
/// chmod/mkdir 等操作的既有语义）；[`LeafSymlinkPolicy::AllowReplace`] 仅
/// WriteFile 用：`ops::write_file` 的 tempfile+rename 流程原子替换叶子本身
///（rename(2) 不跟随目标，不触达链接指向处），中间组件 symlink 仍被
/// `validate_path_components` fail-closed 拒绝。典型场景：base_os 的
/// `etc/resolv.conf` 是指向 `../run/systemd/resolve/stub-resolv.conf` 的
/// symlink（nspawn 首启由 systemd-resolved 生成），构建层需用普通文件原子替换。
#[derive(Clone, Copy)]
pub enum LeafSymlinkPolicy {
    /// 拒绝叶子 symlink（默认，适用于所有非 WriteFile 操作）。
    Reject,
    /// 允许原子替换叶子 symlink 本身，不跟随其目标。
    AllowReplace,
}

/// WriteFile 专用：叶子 symlink 视为可原子替换的既有目标（见 [`LeafSymlinkPolicy::AllowReplace`]）。
pub fn validate_path_normalized_leaf_replace(
    path: &Path,
    allowed_roots: &[PathBuf],
) -> Result<PathBuf, Error> {
    validate_path_normalized_with(path, allowed_roots, LeafSymlinkPolicy::AllowReplace)
}

/// mount/mount-overlay 目标域：必须**严格**位于允许根或标准临时目录之下。
/// 目标等于允许根会把数据根整体覆盖（状态库/结果目录被隐藏，且 umount 侧
/// 本就拒绝根等值，非 root 无法恢复）；等于 `/tmp`/`/var/tmp`/`/dev/shm`
/// 则覆盖共享临时区，属同机 DoS。source/lower/upper/work 不在此收紧。
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

    // 拒绝任何含 `..` 组件的输入（见函数文档）；normalize_path 的弹出语义留给配置加载等调用方。
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

    // 受信前缀 = 允许根目录或标准临时目录。
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

    // 防御父目录 symlink：检查受信前缀以下所有中间目录组件。
    validate_path_components(&normalized, prefix)?;

    // 叶子 symlink：默认拒绝；WriteFile（AllowReplace）放行（rename 只替换叶子本身，见 policy 文档）。
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

/// [`validate_path_normalized`] 的单位返回版本（路径值无需留用，如 nspawn 选项值校验）。
pub fn validate_path(path: &Path, allowed_roots: &[PathBuf]) -> Result<(), Error> {
    validate_path_normalized(path, allowed_roots).map(|_| ())
}

/// 检查规范化路径从 `prefix` 下一层到父目录的每个中间组件是否为 symlink（防御
/// `/var/lib/crbs/products/malicious -> /etc` 攻击）；`prefix` 视为受信不检查，叶子由调用方单独检查。
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

/// 判断路径是否位于标准临时目录下（要求 / 分隔，避免 /dev/shmfoo 误匹配）。
pub fn is_under_temp_dir(normalized: &Path) -> bool {
    temp_dir_prefix(normalized).is_some()
}

/// umount 目标所在的合法域（判定依据），供调用方按域施加差异化加固。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UmountDomain {
    /// 严格位于某个 allowed root 之下。
    AllowedRoot,
    /// 标准临时目录下且第一级组件以 ".tmp" 开头（tempfile 的 `.tmpXXXXXX` 命名）。
    TempDotTmp,
}

/// umount 目标域判定（纯函数，跨平台可测）：已规范化的目标落在哪个合法卸载域，
/// 域外返回 `None`。allowed root 域 = 严格位于某 root 之下（等于根本身不算，
/// 卸载根本身会拆掉整个 crbs 数据区）；临时域 = /tmp、/var/tmp、/dev/shm 之下
/// 且第一级组件以 ".tmp" 开头，临时根本身（rest 为空）与非 .tmp 命名都拒绝：
/// 共享系统临时区任意命名挂载点可 MNT_DETACH，等于对同机第三方挂载点开放 DoS 面。
/// 口径与 gc-orphan-mounts 扫描域 tmp 分支（`ops::mount_in_gc_scan_domain`）一致。
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

// ── allowed root 本身的操作边界 ──────────────────────────────────────
//
// 允许根（server root / 引擎 root / priv-helper.toml 额外路径）承载整个 crbs
// 数据区：rm-rf 不可删根本身（删根 = 组成员单命令清除全部产品数据与共享层，
// 无合法调用方，"清空根下内容"由调用方展开为逐个子项）；mkdir-chown/chown/
// chmod 对根本身的幂等收敛合法（root 首启建 server root、显式 product_root 的
// init），但参数必须收死到权限不变量值——否则 `--user <自己> --mode 0777` 等于把数据根交给调用方（属主可自行再 chmod，组权限不变量失守）。

/// allowed root 本身（目录）的唯一合法 mode：2770 = setgid + owner/group
/// rwx，root / crbs-server / crbs 组三身份可读写、新文件继承 crbs 组。
pub const ROOT_EQUAL_DIR_MODE: u32 = 0o2770;

/// 判定（已规范化的）路径是否等于某个允许根本身（与 [`umount_target_domain`]
/// 同一比较口径）；结果用于触发参数收死而非直接拒绝，根本身的幂等收敛合法。
pub fn equals_allowed_root(normalized: &Path, allowed_roots: &[PathBuf]) -> bool {
    allowed_roots
        .iter()
        .any(|root| normalized.as_os_str() == root.as_os_str())
}

/// rm-rf 的根等值拒绝（纯函数，paths 须已过 `validate_path_normalized`）：
/// 任一目标等于允许根本身即整体拒绝（不部分执行），删根没有合法调用方；"清空根下内容"由调用方展开为根的直接子项逐个传入。
pub fn validate_rm_rf_paths(paths: &[PathBuf], allowed_roots: &[PathBuf]) -> Result<(), Error> {
    if let Some(p) = paths.iter().find(|p| equals_allowed_root(p, allowed_roots)) {
        return Err(Error::Validation(format!(
            "rm-rf refuses to remove an allowed root itself (delete its children instead): {}",
            p.display()
        )));
    }
    Ok(())
}

/// 根等值 mkdir-chown 的参数收死（纯函数）：属主 `root` 恒合法，`crbs-server`
/// 仅 root 调用方（server 首启收敛是只有 root 能做的不变量修复，root 本可绕过
/// helper；拦的是组员把数据根 chown 给自己/服务账户）；组必须 `crbs`（三身份
/// 不变量的组维度）；mode 必须恰为 2770（world 可写、组权限缺失、setuid 位均拒绝）。
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

/// 根等值 chown 的参数收死（纯函数，uid/gid 为调用方传入的目标值）：属主必须
/// 仍是 root、组必须是 crbs 组（gid 相等比较）；现有调用面没有"根本身 chown
/// 给非 root 属主"的合法形态（服务侧收敛走 mkdir-chown 的名字形态）。
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

/// 根等值 chmod 的参数收死（纯函数）：允许根必为目录，mode 必须恰为 2770。
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

/// 返回路径所在的标准临时目录前缀（仅 `/dev/shm`、`/var/tmp`、`/tmp`，否则 `None`）。
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

/// 规范化绝对路径（不解析 symlink）。
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

/// `write-cgroup-file` 允许写入的 cgroup 子树前缀：crbs-core nspawn 后端只写
/// payload scope（`machine.slice/machine-*.scope/` 之下）的控制文件，组成员
/// 不能借 helper 改写宿主其它 cgroup（system.slice/init.scope 等）的状态。
pub const CGROUP_WRITABLE_ROOT: &str = "/sys/fs/cgroup/machine.slice";

/// `write-cgroup-file` 允许写入的控制文件名白名单：payload cgroup 的资源限制
/// 文件与终止通道（cgroup.rs / SpawnedChild::cgroup_kill）；其余 cgroup 文件
/// 无调用方一律拒绝（cgroup.procs 可迁移任意进程进任意 cgroup，尤其不能放行）。
pub const CGROUP_WRITABLE_FILES: &[&str] =
    &["memory.max", "memory.swap.max", "cpu.max", "cgroup.kill"];

/// pgid 校验：取消时杀的构建进程组（负 pid 约定，`-pid` 对应 nspawn 容器 pid2）。
/// 拒绝 0（自身组）与 1（init 组）——非本进程组误杀属逻辑错误。
pub fn validate_pgid(pgid: i32) -> Result<i32, Error> {
    if pgid <= 1 {
        return Err(Error::Validation(format!(
            "kill-process-group pgid {pgid} is invalid (must be > 1)"
        )));
    }
    Ok(pgid)
}

// ── kill-process-group 的属主作用域 ──────────────────────────────────
//
// kill 是 helper 第一个作用于全局 pid 命名空间的操作：root SIGKILL 任意
// pgid，组成员可借此杀系统服务。作用域 = 组内每个存活成员至少满足一条
// 属主谓词（[`scope_allows`]），任一越界或作用域不可判定即整体拒绝
//（fail-closed）；成员为空 = 进程组已死，幂等成功。

/// crbs 的 cgroup 子树根（`/proc/{pid}/cgroup` 报告的相对路径）：构建容器
/// scope 由 machined 建于 machine.slice 之下。取值来源：crbs-core
/// engine/backend/nspawn/cgroup.rs 的 `CGROUP_FS_ROOT` + machine.slice 候选
///（本 crate 的 `CGROUP_WRITABLE_ROOT` 去 /sys/fs/cgroup 前缀同值）；本 crate
/// 不依赖 crbs-core，硬编码同值。
pub const KILL_SCOPE_CGROUP_SUBTREE: &str = "/machine.slice";

/// 从 `/proc/{pid}/stat` 内容解析 pgrp（第 5 字段）：comm 可含空格/括号，
/// 取最后一个 `)` 之后第 3 个空白分隔字段（state、ppid 之后），后段字段
/// 不含括号故取位无歧义。
pub fn parse_stat_pgrp(stat: &str) -> Option<u32> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(2)?
        .parse()
        .ok()
}

/// 从 `/proc/{pid}/status` 内容解析 real uid（`Uid:` 行首字段）；helper 为
/// root，可读任意成员。
pub fn parse_status_uid(status: &str) -> Option<u32> {
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    line.strip_prefix("Uid:")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// 从 `/proc/{pid}/cgroup` 内容解析 v2 unified 层级路径（`0::/...` 行）；
/// v1 无该行返回 None（b 谓词不可判定，a/c 谓词仍可放行）。
pub fn parse_cgroup_v2_path(content: &str) -> Option<&str> {
    content.lines().find_map(|l| l.strip_prefix("0::"))
}

/// 属主作用域谓词（纯函数，输入为成员 /proc 信息的已解析形态）：任一谓词
/// 成立即放行——a) 容器化构建成员：`/proc/{pid}/root` 位于任一配置允许根或
/// 标准临时目录之下（与 spawn-chroot/spawn-nspawn 的 rootfs 校验同一允许根
/// 推导：凡 helper 能 spawn 的沙箱根，取消/超时/清扫时必能 kill）；b)
/// machined 为 crbs 容器注册的 scope 成员：cgroup 路径位于
/// [`KILL_SCOPE_CGROUP_SUBTREE`] 之下且 scope 组件带 crbs 命名空间前缀
///（`crbs_machine_scope`）；c) 调用者本人：成员 real uid == `caller_uid`。
/// 信息缺失（None）的谓词不成立，逐成员 fail-closed。
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

/// a 谓词的允许根判定（纯函数）：任一配置允许根（等值或严格之下），或标准
/// 临时目录（/dev/shm、/var/tmp、/tmp——tempfile 沙箱与 chroot 回放 rootfs
/// 所在）。口径与 [`validate_path_normalized`] 的受信前缀推导一致，组件级
/// 前缀比较防兄弟前缀误匹配（/var/lib/crbs2 ≠ /var/lib/crbs）。
fn kill_scope_root_allowed(root: &Path, allowed_roots: &[PathBuf]) -> bool {
    allowed_roots
        .iter()
        .any(|r| root == r || root.starts_with(r))
        || is_under_temp_dir(root)
}

/// b 谓词的 scope 命名判定（纯函数）：cgroup 路径严格位于
/// [`KILL_SCOPE_CGROUP_SUBTREE`] 之下，且 /machine.slice 下一级组件是 machined
/// 为 crbs 容器建的 scope——`crbs-{hash}[-{suffix}].scope` 或旧 systemd 的
/// `machine-crbs-{hash}[-{suffix}].scope`（crbs-core nspawn 后端两种候选形态），
/// 原样/转义（`-` → `\x2d`）双形态都收。
/// /machine.slice 收宿主任意来源的容器，scope 组件不带 crbs- 前缀即拒绝。
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
    // machined 注册的 scope 目录名是转义形态（machine-crbs\x2d…），组件先按
    // systemd_escape_dash 的逆变换解码再做命名空间判定；解码不放宽边界——
    // 命中仍是 crbs- 前缀 + .scope 后缀的 machine 命名空间形态。
    let decoded = name.replace("\\x2d", "-");
    (decoded.starts_with("crbs-") || decoded.starts_with("machine-crbs-"))
        && decoded.ends_with(".scope")
}

/// kill-process-group 属主作用域校验：扫描 /proc 找出 pgid 等于目标的组成员
///（`/proc/{pgid}` 缺失不能当组已死——组长退出而组仍存活时误判会留孤儿，
/// 必须成员扫描），任一存活成员不满足 [`scope_allows`] 即拒绝；成员在校验
/// 间隙退出（ENOENT）按已消失跳过，字段不可读置 None 交谓词 fail-closed。
/// `allowed_roots` = 调用方传来的配置允许根集合（与 spawn 校验同源）。
pub fn validate_kill_scope(
    pgid: i32,
    caller_uid: u32,
    allowed_roots: &[PathBuf],
) -> Result<(), Error> {
    // 非正 pgid 不可能有组成员（上游 validate_pgid 已拒绝，此处兜底），按空组幂等成功。
    let Ok(target_pgrp) = u32::try_from(pgid) else {
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
        // stat 不可读按错误类别分流：ENOENT = 进程已退出（扫描间隙消失），
        // 不可能再是组成员；其余错误（EACCES 等）= 组成员关系不可判定，整体
        // 拒绝——静默跳过会让该成员游离于作用域校验之外（fail-open）。
        let stat = match std::fs::read_to_string(proc_fs.join(entry.file_name()).join("stat")) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
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
        // ENOENT = 成员已退出（SIGKILL 对其 no-op），跳过；其余失败置 None，
        // 由谓词判定 fail-closed（残留谓词仍可放行，如 uid 可判而 root 不可读）。
        // readlink 结果已是内核解析的规范路径，词法规范化兜底，失败置 None。
        let proc_root = match std::fs::read_link(dir.join("root")) {
            Ok(p) => normalize_path(&p).ok(),
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

/// 校验 `write-cgroup-file` 的目标路径（语义与 validate_path_normalized 对齐：
/// 绝对路径、拒绝 `..`、词法规范化），并要求严格位于 [`CGROUP_WRITABLE_ROOT`]
/// **之下**（等于根本身拒绝，断言风格同 umount 的根拒绝——作用于 slice 根会
/// 改写整个层级的容器状态）、叶子文件名在 [`CGROUP_WRITABLE_FILES`] 白名单内。
/// cgroupfs（kernfs）不由调用方可写介质支撑、目录组件也无法被普通用户替换成
/// symlink，故不做 allowed_roots/symlink 检查，前缀 + 文件名白名单已覆盖全部攻击面。
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
    // Path::starts_with 按组件比较：/sys/fs/cgroupfoo 不会误匹配。
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

// ── terminate-machine 的 machine 命名空间 ────────────────────────────
//
// machine.slice 收宿主任意来源的容器，terminate-machine 的信任锚只有名称
// 本身：scope 路径与 /proc 成员匹配全部由校验过的名称派生，命名空间外的
// machine（他方容器）在该字符集下不可达。

/// terminate-machine 的 machine 名信任锚：仅接受 crbs 自建命名空间——`crbs-`
/// 前缀 + `^[0-9a-fA-F-]{8,64}$`（crbs-core nspawn `machine_name_for` 的生成
/// 形态 `crbs-{8hex}[-{build_id}]`）。分隔符/`..`/路径组件在该字符集下不可
/// 能成立，名称直接拼接 scope 路径即安全。
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

/// systemd unit 名转义（machined 注册 scope 的确定性变换）：`-` → `\x2d`。
/// machine 名已过 [`validate_machine_name`]（字符集 `crbs-[0-9a-fA-F-]{8,64}`），
/// systemd unit 转义仅替换 - 为 \x2d，命名空间字符集下无损；完整 unit 转义
/// 规则（其余非字母数字字符）对本命名空间不可达，不实现。
pub(crate) fn systemd_escape_dash(name: &str) -> String {
    name.replace('-', "\\x2d")
}

/// /proc/{pid}/cgroup 内容是否把进程置于 machine_name 的 machine.slice scope
/// 之内：任一行路径严格位于 /machine.slice 之下、且下一级组件为
/// `{name}.scope` / `machine-{name}.scope` 的原样或转义形态（组件级整段比较，
/// 兄弟前缀不误匹配）。v2 `0::` 行与 v1 `hierarchy:controllers:path` 行同判
/// ——cgroup v1 宿主无 `0::` 行，只认 v2 会让成员判定落空；转义形态必收：
/// machined 注册的 scope 目录名即 `machine-crbs\x2d…\x2d….scope`，v2 宿主的
/// `0::` 行目录名同样是转义形态，只认原样名两栈都会漏杀。
pub fn cgroup_in_machine_scope(cgroup_content: &str, machine_name: &str) -> bool {
    let escaped = systemd_escape_dash(machine_name);
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

/// 校验 `write-cgroup-file` 的写入值：非空，且仅允许数字、空格、小写字母
///（"max" / "1" / "200000 100000" 均合法）。值直接进 cgroupfs 控制文件，
/// 其它字符（大写、符号、换行注入等）没有合法调用方，fail-closed。
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

/// 校验 mount data 选项的值（键白名单在 main.rs 的 MOUNT_ALLOWED_DATA_KEYS，
/// 本函数只管值域，键到值域按 devpts/tmpfs 的合法取值形态收窄）：mode/ptmxmode
/// 3~4 位八进制（`0620`、`0666`）；uid/gid 1~10 位十进制；
/// size/nr_inodes 十进制 + 可选单个 k/K/m/M/g/G 后缀或字面量 "max"；所有值非空
/// 且不含空白/控制字符（data 整串原样进 mount(2) 的 data 参数，白名单字符集
/// 兜底防注入）。无值键（如 newinstance）以 `None` 放行；携值不在值域表内的键拒绝。
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
                // 恰好一个可选后缀字符；剩余部分必须全为数字。
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

    /// 词法规范化与内核解析分歧（漏洞 2）：`/tmp/s/../etc/x` 词法上过校验，
    /// 内核解析却穿过 symlink `s` 作用到 `/etc/x`，任何含 `..` 输入必须直接拒绝。
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
        // 允许根用真实存在的临时目录：macOS 上 /var 本身是 symlink，组件检查会因环境而非逻辑失败。
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

    /// mount 目标不得等于允许根 / 标准临时目录根（覆盖数据根或共享临时区）；
    /// 严格后代放行。
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
        // 中间组件 symlink 仍然 fail-closed。
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
        // 域外路径（validate_path_normalized 之前的粗筛，这里兜底）。
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
        // 兄弟前缀不误伤（组件级比较）。
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
        // allowed root 恰为临时根之下的目录：不算"严格之下"、也不满足 .tmp 形态，拒绝。
        let allowed_under_tmp = vec![PathBuf::from("/var/tmp/crbs")];
        assert_eq!(
            umount_target_domain(Path::new("/var/tmp/crbs"), &allowed_under_tmp),
            None
        );
        // 反之：allowed root 本身在临时根下且首级 .tmp 形态，其下路径按 allowed root 域优先放行。
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
        // 前缀恰好重叠但不在其下（组件级比较，cgroupfoo 不匹配）。
        assert!(validate_cgroup_file_path(Path::new("/sys/fs/cgroupfoo/memory.max")).is_err());
        assert!(validate_cgroup_file_path(Path::new("/etc/passwd")).is_err());
        assert!(validate_cgroup_file_path(Path::new("/sys/fs/cgroup/../../etc/passwd")).is_err());
        // machine.slice 之外的 cgroup 子树（宿主服务）：即使文件名在白名单内也拒绝。
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
        // 携值的未知键 fail-closed（值域表兜底拒绝）；缺值形态与键白名单由调用方把关。
        assert!(validate_mount_data_value("newinstance", Some("1")).is_err());
        assert!(validate_mount_data_value("unknown-key", Some("1")).is_err());
    }

    // ── allowed root 本身的操作边界 ──────────────────────────────

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
        // 严格之下的子路径不算根等值（走正常参数语义）；前缀重叠但组件不同也不算。
        assert!(!equals_allowed_root(Path::new("/var/lib/crbs/x"), &roots()));
        assert!(!equals_allowed_root(
            Path::new("/var/lib/crbs-other"),
            &roots()
        ));
        assert!(!equals_allowed_root(Path::new("/var/lib"), &roots()));
    }

    /// rm-rf 拒绝删除允许根本身（组成员单命令即可清除/夺取整个 crbs 数据区）；合法清理 = 调用方展开为根的直接子项。
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
        // 合法形态一：init 显式 product_root 收敛（root:crbs 2770，组成员调用）。
        assert!(
            validate_root_equal_mkdir_chown("root", "crbs", 0o2770, false).is_ok(),
            "init-style root:crbs 2770 must pass for group-member callers"
        );
        // 合法形态二：server 首启收敛（crbs-server:crbs 2770，仅 root 调用方）。
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

    // ── kill-process-group 的属主作用域 ──────────────────────────

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
        // comm 含空格与括号：取最后一个 ')' 之后的字段（state/ppid/pgrp…）。
        let stat = "123 (my (weird) proc name)S 1 456 789 0";
        assert_eq!(parse_stat_pgrp(stat), Some(456));
        // 组长：pid == pgrp。
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
        // cgroup v1 多控制器文件无 0:: 行。
        assert_eq!(parse_cgroup_v2_path("12:cpu:/build\n11:cpuset:/\n"), None);
        assert_eq!(parse_cgroup_v2_path(""), None);
    }

    #[test]
    fn scope_allows_container_root_under_allowed_root() {
        let allowed = vec![PathBuf::from("/var/lib/crbs")];
        // a 谓词：构建 rootfs 内的成员（chroot/nspawn 均此形态）。
        assert!(scope_allows(
            Some(Path::new("/var/lib/crbs/products/p/rootfs")),
            None,
            None,
            1000,
            &allowed
        ));
        // 等值放行：spawn 校验对 rootfs == 允许根本身同样放行，kill 口径一致。
        assert!(scope_allows(
            Some(Path::new("/var/lib/crbs")),
            None,
            None,
            1000,
            &allowed
        ));
        // 兄弟前缀、域外路径不满足 a 谓词（组件级比较，/var/lib/crbs2 不误匹配）。
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

    /// 回放沙箱根在标准临时目录下（chroot 后端 rootfs 位于 config.tmp_dir，
    /// 默认 /var/tmp）：a 谓词按 spawn 校验同一临时目录推导放行；临时目录外
    /// 的随机路径拒绝。
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
        // b 谓词：machined 为 crbs 容器建的 scope——新式 crbs-*.scope 与
        // 旧式 machine-crbs-*.scope 两种形态。
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
        // /machine.slice 收宿主任意来源的容器：scope 组件非 crbs- 前缀一律
        // 拒绝；前缀须按完整命名空间匹配（machine-crab ≠ machine-crbs）。
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

    /// b 谓词收转义 scope 组件：machined 注册的目录名形态
    /// （machine-crbs\x2d…）按命名空间匹配——v2 宿主 kill-process-group
    /// 的成员判定依赖此谓词。
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
        // 解码不放宽边界：非 crbs 命名空间的转义组件照拒。
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
        // c 谓词：调用者本人的成员。
        assert!(scope_allows(None, None, Some(1000), 1000, &allowed));
        assert!(!scope_allows(None, None, Some(0), 1000, &allowed));
        assert!(!scope_allows(None, None, Some(1001), 1000, &allowed));
        // 信息缺失不构成放行：fail-closed。
        assert!(!scope_allows(None, None, None, 1000, &allowed));
        assert!(!scope_allows(None, None, None, 0, &allowed));
    }

    /// 端到端（仅 Linux，读真实 /proc）：本测试进程组经 c 谓词放行（允许根
    /// 集合不存在时其余谓词均不成立）；不存在的 pgid = 空成员集，幂等成功。
    #[cfg(target_os = "linux")]
    #[test]
    fn validate_kill_scope_self_group_and_empty_group() {
        // SAFETY: 无参 pid 查询调用，无内存安全影响。
        let my_uid = unsafe { libc::getuid() } as u32;
        let my_pgid = unsafe { libc::getpgid(0) };
        let allowed = vec![PathBuf::from("/nonexistent")];
        assert!(validate_kill_scope(my_pgid, my_uid, &allowed).is_ok());
        // pid_max ≤ i32::MAX，不可能存在该 pgid 的成员。
        assert!(validate_kill_scope(i32::MAX, my_uid, &allowed).is_ok());
    }

    // ── terminate-machine 的 machine 命名空间 ──────────────────────

    #[test]
    fn validate_machine_name_accepts_generated_forms() {
        // machine_name_for 生成形态：crbs-{8hex} 与 crbs-{8hex}-{build_id}。
        assert_eq!(
            validate_machine_name("crbs-9c714595").unwrap(),
            "crbs-9c714595"
        );
        assert_eq!(
            validate_machine_name("crbs-9c714595-22").unwrap(),
            "crbs-9c714595-22"
        );
        // 大写 hex 与多段连字符都在字符集 [0-9a-fA-F-] 内。
        assert_eq!(
            validate_machine_name("crbs-0A1B2C3D-4e5f-6789").unwrap(),
            "crbs-0A1B2C3D-4e5f-6789"
        );
        // 边界长度：前缀后段恰 8 与 64 字节。
        let min = format!("crbs-{}", "a".repeat(8));
        let max = format!("crbs-{}", "a".repeat(64));
        assert_eq!(validate_machine_name(&min).unwrap(), min);
        assert_eq!(validate_machine_name(&max).unwrap(), max);
    }

    #[test]
    fn validate_machine_name_rejects_outside_namespace() {
        // 前缀缺失、空 hex 段、过短/过长、字符集外（下划线/点/斜杠/空白/
        // 大写前缀）、`..` 与绝对路径逃逸形态——全拒。
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
        // v2 unified 行：新式与旧式 scope 命名形态。
        assert!(cgroup_in_machine_scope(
            "0::/machine.slice/crbs-9c714595-22.scope/payload\n",
            name
        ));
        assert!(cgroup_in_machine_scope(
            "0::/machine.slice/machine-crbs-9c714595-22.scope\n",
            name
        ));
        // cgroup v1 多控制器行（无 unified 层级宿主的实际形态）：同样命中。
        assert!(cgroup_in_machine_scope(
            "10:cpu,cpuacct:/machine.slice/machine-crbs-9c714595-22.scope/payload\n\
             11:memory:/machine.slice/machine-crbs-9c714595-22.scope\n",
            name
        ));
    }

    /// systemd unit 转义仅替换 - 为 \x2d（命名空间字符集下无损）。
    #[test]
    fn systemd_escape_dash_translates_dashes_only() {
        assert_eq!(systemd_escape_dash("crbs-9c714595"), "crbs\\x2d9c714595");
        assert_eq!(
            systemd_escape_dash("crbs-1b033e1a-27"),
            "crbs\\x2d1b033e1a\\x2d27"
        );
        // 纯数字段、uuid 形态（多 `-`）全量转义。
        assert_eq!(systemd_escape_dash("crbs-01234567"), "crbs\\x2d01234567");
        assert_eq!(
            systemd_escape_dash("crbs-9c714595-1b03-4e5f-8d2a-abcdef012345"),
            "crbs\\x2d9c714595\\x2d1b03\\x2d4e5f\\x2d8d2a\\x2dabcdef012345"
        );
    }

    /// machined 注册的 scope 目录名是转义形态（v1 宿主 systemd 层级与 v2 宿主
    /// `0::` 行实测同此形态）：原样名判定必漏，转义/原义双形态都必须命中。
    #[test]
    fn cgroup_in_machine_scope_matches_escaped_components_both_dialects() {
        let name = "crbs-1b033e1a-27";
        // v2 `0::` 行 + 新式命名的转义形态。
        assert!(cgroup_in_machine_scope(
            "0::/machine.slice/crbs\\x2d1b033e1a\\x2d27.scope/payload\n",
            name
        ));
        // v2 `0::` 行 + 旧式命名的转义形态（现代 systemd 实际注册形态）。
        assert!(cgroup_in_machine_scope(
            "0::/machine.slice/machine-crbs\\x2d1b033e1a\\x2d27.scope\n",
            name
        ));
        // v1 多控制器行的转义形态。
        assert!(cgroup_in_machine_scope(
            "10:cpu,cpuacct:/machine.slice/machine-crbs\\x2d1b033e1a\\x2d27.scope/payload\n\
             11:memory:/machine.slice/machine-crbs\\x2d1b033e1a\\x2d27.scope\n",
            name
        ));
        // 转义组件在 payload 子 cgroup 之下同样命中。
        assert!(cgroup_in_machine_scope(
            "0::/machine.slice/machine-crbs\\x2d1b033e1a\\x2d27.scope/payload/init\n",
            name
        ));
    }

    /// 转义形态的兄弟前缀 / 他方 scope 仍拒绝（组件整段比较不被解码破坏）。
    #[test]
    fn cgroup_in_machine_scope_rejects_escaped_outside() {
        let name = "crbs-1b033e1a-27";
        for content in [
            // 转义名不同（他方 machine）。
            "0::/machine.slice/machine-crbs\\x2ddeadbeef.scope\n",
            // 转义组件之外的前缀（crbs 段不同）。
            "0::/machine.slice/crbs\\x2d1b033e1a\\x2d2.scope\n",
            // 组件后缀整段不同（.scope.evil）。
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
            // 他方 machine（不同名 scope）。
            "0::/machine.slice/crbs-deadbeef.scope/payload\n",
            // machine.slice 本身（不严格位于其下）与空内容。
            "0::/machine.slice\n",
            "",
            // 兄弟前缀组件（scope 组件整段比较）。
            "0::/machine.slice/machine-crbs-9c714595-22.scope.evil/x\n",
            // 名称仅子串匹配（crbs-9c714595-2 ≠ crbs-9c714595-22）。
            "0::/machine.slice/crbs-9c714595-2.scope\n",
            // scope 之外的系统 cgroup。
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
