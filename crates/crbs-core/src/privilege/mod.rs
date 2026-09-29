// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 特权与权限：setuid 提权 / 降权、调用者身份管理与文件属组不变量（crbs 组 + 0660/2770）。

use crate::error::CrbsError;
#[cfg(target_os = "linux")]
use nix::unistd::geteuid;
use nix::unistd::{getgid, getuid, Uid};

#[cfg(target_os = "linux")]
use {
    nix::unistd::{getgroups, Gid},
    std::collections::HashSet,
    std::fs,
    std::sync::LazyLock,
    tracing::{debug, info},
};

pub mod backend;

pub use backend::{HelperBackend, MountOverlayRequest, PrivilegeBackend, SetuidBackend};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Once, OnceLock};

static BACKEND: OnceLock<Box<dyn PrivilegeBackend>> = OnceLock::new();

/// 最近一次 [`setup_privileges`] 是否请求了需特权的档位（Full/Restricted）。
/// CLI 时序是先设权限后加载配置（main.rs setup_privileges → dispatch 内 CrbsConfig::load
/// 才触发 init_privilege_backend），档位先落此静态、由后端解析处合流判定告警。
static PRIVILEGED_TIER_REQUESTED: AtomicBool = AtomicBool::new(false);

/// 特权 helper 使用策略。
// Serialize 仅供配置 schema 完备性测试快照默认值（crbs.toml use_privileged_helper 字段）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivilegedHelperMode {
    /// 自动探测：helper 路径通过最小安全基线（普通文件/非 symlink/root 属主/
    /// 无组他写位，见 [`backend::helper::passes_helper_file_baseline`]——不校验执行位，缺失
    /// 时到 spawn 才 EACCES）则使用，否则回退 setuid。
    #[default]
    Auto,
    /// 强制使用 helper，不存在则报错。
    Always,
    /// 强制使用 setuid 行为。
    Never,
}

/// 初始化全局特权后端；进程启动早期调用一次，`Auto` 优先探测 helper、回退 setuid。
pub fn init_privilege_backend(
    mode: PrivilegedHelperMode,
    helper_path: Option<&std::path::Path>,
    crbs_root: &std::path::Path,
) -> crate::Result<()> {
    let backend: Box<dyn PrivilegeBackend> = match mode {
        PrivilegedHelperMode::Auto => {
            if let Some(path) = helper_path {
                if backend::passes_helper_file_baseline(path) {
                    Box::new(HelperBackend::new(
                        path.to_path_buf(),
                        crbs_root.to_path_buf(),
                    ))
                } else {
                    tracing::debug!(path = %path.display(), "privileged helper not executable, falling back to setuid");
                    Box::new(SetuidBackend)
                }
            } else if let Some(helper) = HelperBackend::detect(crbs_root.to_path_buf()) {
                Box::new(helper)
            } else {
                tracing::debug!("no privileged helper found, using setuid backend");
                Box::new(SetuidBackend)
            }
        }
        PrivilegedHelperMode::Always => {
            let path = helper_path
                .map(|p| p.to_path_buf())
                .or_else(|| {
                    HelperBackend::detect(crbs_root.to_path_buf())
                        .map(|h| h.helper_path().to_path_buf())
                })
                .ok_or_else(|| CrbsError::io_message("privileged helper required but not found"))?;
            if !backend::passes_helper_file_baseline(&path) {
                return Err(CrbsError::io_message(format!(
                    "privileged helper is not executable: {}",
                    path.display()
                )));
            }
            Box::new(HelperBackend::new(path, crbs_root.to_path_buf()))
        }
        PrivilegedHelperMode::Never => Box::new(SetuidBackend),
    };

    // Auto 探测失败回退 setuid 的单点告警评估；Always 失败已报错、Never 是显式选择，均不告警。
    if mode == PrivilegedHelperMode::Auto && !backend.is_helper() {
        maybe_warn_auto_fallback();
    }

    // 幂等：Auto 已初始化则跳过；显式模式请求与已初始化后端类型不一致则报错，防静默用错后端。
    if let Some(current) = BACKEND.get() {
        if mode == PrivilegedHelperMode::Auto {
            return Ok(());
        }
        let current_is_helper = current.as_ref().is_helper();
        let requested_is_helper = mode == PrivilegedHelperMode::Always;
        if current_is_helper != requested_is_helper {
            return Err(CrbsError::Internal(format!(
                "privilege backend already initialized as {}, but mode {:?} requested",
                if current_is_helper {
                    "helper"
                } else {
                    "setuid"
                },
                mode
            )));
        }
        return Ok(());
    }
    let _ = BACKEND.set(backend);
    Ok(())
}

static AUTO_FALLBACK_WARN: Once = Once::new();

/// Auto 回退 setuid 后的一次性可行动告警：仅当本次请求了需特权的档位（Full/Restricted）
/// 且进程自身无特权才发——root/setuid 形态不受影响，避免 root 机器与只读命令被噪音打扰。
fn maybe_warn_auto_fallback() {
    if !PRIVILEGED_TIER_REQUESTED.load(Ordering::Relaxed) || !process_has_no_privilege() {
        return;
    }
    AUTO_FALLBACK_WARN.call_once(|| {
        tracing::warn!(
            backend = "setuid",
            "privileged helper not found and this command requires privileges; \
             mount/chown operations will fail with EPERM - install the crbs-priv-helper \
             package or run as root"
        );
    });
}

/// 进程自身无特权可用：ruid 与 euid 均非 0（root 直跑与 setuid-root 提权都不可行）。
#[cfg(target_os = "linux")]
fn process_has_no_privilege() -> bool {
    !getuid().is_root() && !geteuid().is_root()
}

/// 非 Linux 桩：无 setuid 提权模型，视为无特权可用。
#[cfg(not(target_os = "linux"))]
fn process_has_no_privilege() -> bool {
    true
}

static FALLBACK_WARN: Once = Once::new();

/// 获取当前特权后端；未初始化时返回 `SetuidBackend` 安全默认并一次性告警。
pub fn get_privilege_backend() -> &'static dyn PrivilegeBackend {
    BACKEND.get().map(|b| b.as_ref()).unwrap_or_else(|| {
        FALLBACK_WARN.call_once(|| {
            tracing::warn!("Privilege backend not initialized; using SetuidBackend as fallback");
        });
        static FALLBACK: SetuidBackend = SetuidBackend;
        &FALLBACK
    })
}

/// 便捷函数：创建目录并设置属主/权限。
pub fn mkdir_chown(
    path: &std::path::Path,
    user: &str,
    group: &str,
    mode: u32,
) -> crate::Result<()> {
    get_privilege_backend().mkdir_chown(path, user, group, mode)
}

/// 便捷函数：修改文件或目录的属主（支持递归）。
pub fn chown(path: &std::path::Path, uid: u32, gid: u32, recursive: bool) -> crate::Result<()> {
    get_privilege_backend().chown(path, uid, gid, recursive)
}

/// 便捷函数：修改文件或目录的权限（支持递归）。
pub fn chmod(path: &std::path::Path, mode: u32, recursive: bool) -> crate::Result<()> {
    get_privilege_backend().chmod(path, mode, recursive)
}

/// 便捷函数：写入文件（父目录不存在时自动创建），可选设置权限与属主。
pub fn write_file(
    path: &std::path::Path,
    content: &[u8],
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> crate::Result<()> {
    get_privilege_backend().write_file(path, content, mode, uid, gid)
}

/// 便捷函数：清理 crbs_root 及可选临时目录扫描域下的孤儿挂载点（`tmp_dirs` = engine 的 `tmp_dir`/`tmpfs_dir`；扫描域语义见 [`backend::PrivilegeBackend::gc_orphan_mounts`]）。
pub fn gc_orphan_mounts(
    crbs_root: &std::path::Path,
    tmp_dirs: &[std::path::PathBuf],
) -> crate::Result<()> {
    get_privilege_backend().gc_orphan_mounts(crbs_root, tmp_dirs)
}

/// 异步惰性卸载（MNT_DETACH）：spawn_blocking 包裹 backend `umount2`，结果由调用方处理。
/// pub：worker 周期清扫的孤儿挂载回收（tmp_sweep）作为 umounter 注入复用同一特权通路。
pub async fn umount_detach(path: std::path::PathBuf) -> crate::Result<()> {
    tokio::task::spawn_blocking(move || {
        #[cfg(target_os = "linux")]
        let flags = nix::mount::MntFlags::MNT_DETACH.bits();
        #[cfg(not(target_os = "linux"))]
        let flags = 0;
        // Linux 上 MntFlags::bits() 已是 i32；跨平台保留 as i32。
        #[allow(clippy::unnecessary_cast)]
        let flags = flags as i32;
        get_privilege_backend().umount2(&path, flags)
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("umount join error: {e}")))?
}

/// 同步创建目录并设置 `crbs` 组 + setgid 模式（0o2770）；chmod/chown 失败仅记录日志不阻断（group rw 已足够本进程访问）。
pub fn ensure_directory(path: &std::path::Path, label: &'static str) -> crate::Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|e| CrbsError::from_io_context(format!("create {label} directory"), e))?;

    // 快路径：目录已就绪（mode 2770 + crbs 组）则跳过 chmod/chown——热路径应零 syscall。
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            let mode_ok = meta.mode() & 0o7777 == 0o2770;
            // 只看 group==crbs 不看属主：root 建的目录同样满足权限不变量，要求属主会误伤并触发无谓 chmod/chown。
            let group_ok = crbs_group_gid()
                .map(|gid| meta.gid() == gid)
                .unwrap_or(false);
            if mode_ok && group_ok {
                return Ok(());
            }
        }
    }

    if let Err(e) = chmod(path, 0o2770, false) {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "{label}: chmod 0o2770 failed"
        );
    }

    #[cfg(target_os = "linux")]
    {
        let gid = match crbs_group_gid() {
            Ok(g) => g,
            Err(e) => {
                tracing::debug!(
                    path = %path.display(),
                    error = %e,
                    "{label}: lookup crbs group gid failed; skip chown"
                );
                return Ok(());
            }
        };
        let uid = getuid().as_raw();
        if let Err(e) = chown(path, uid, gid, false) {
            tracing::debug!(
                path = %path.display(),
                error = %e,
                "{label}: chown to crbs group failed; skip"
            );
        }
    }

    Ok(())
}

/// 路径不存在时按 backend 语义视为 no-op 返回 Ok。
pub fn rm_rf(paths: &[&std::path::Path]) -> crate::Result<()> {
    get_privilege_backend().rm_rf(paths)
}

/// 异步版本：递归删除一个或多个路径。
pub async fn rm_rf_async(paths: &[&std::path::Path]) -> crate::Result<()> {
    let owned: Vec<std::path::PathBuf> = paths.iter().map(|p| p.to_path_buf()).collect();
    tokio::task::spawn_blocking(move || {
        let refs: Vec<&std::path::Path> = owned.iter().map(|p| p.as_path()).collect();
        rm_rf(&refs)
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("spawn_blocking rm_rf: {}", e)))?
}

/// 异步版本：修改文件或目录的属主（支持递归）。
pub async fn chown_async(
    path: &std::path::Path,
    uid: u32,
    gid: u32,
    recursive: bool,
) -> crate::Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || chown(&path, uid, gid, recursive))
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking chown: {}", e)))?
}

/// 异步版本：修改文件或目录的权限（支持递归）。
pub async fn chmod_async(path: &std::path::Path, mode: u32, recursive: bool) -> crate::Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || chmod(&path, mode, recursive))
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking chmod: {}", e)))?
}

/// 把 `path` 的 group 改为 `crbs`，owner 设为当前进程 uid（`getuid()`）。
/// gid 查不到或 chown EPERM（非 root 不能 chown 别人）时仅 debug 日志不阻断——调用者本就在
/// crbs 组时 mode 0660/2770 的 group rw 仍足够访问。`recursive=true` 走安全 walker，`label` 仅用于日志。
pub async fn chown_to_crbs_group_async(
    path: &std::path::Path,
    recursive: bool,
    label: &'static str,
) {
    let gid = match crbs_group_gid_async().await {
        Ok(g) => g,
        Err(e) => {
            tracing::debug!(
                path = %path.display(),
                error = %e,
                "{label}: lookup crbs group gid failed; skip chown"
            );
            return;
        }
    };
    let uid = nix::unistd::getuid().as_raw();
    let path_owned = path.to_path_buf();
    if let Err(e) = chown_async(&path_owned, uid, gid, recursive).await {
        tracing::debug!(
            path = %path_owned.display(),
            error = %e,
            "{label}: chown to crbs group failed; skip"
        );
    }
}

/// 异步版本：写入文件（父目录不存在时自动创建），可选设置权限与属主。
pub async fn write_file_async(
    path: &std::path::Path,
    content: &[u8],
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> crate::Result<()> {
    let path = path.to_path_buf();
    let content = content.to_vec();
    tokio::task::spawn_blocking(move || write_file(&path, &content, mode, uid, gid))
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking write_file: {}", e)))?
}

/// 进程原始调用者身份快照：setup 在任何 setuid(0) 之前写入（setuid(0) 会把 ruid/euid/suid
/// 全部清零，此后 `getuid()` 拿到 0 而非调用者）；未经过 setup 的常驻进程保持为空。
static ORIGINAL_CALLER: OnceLock<CallerInfo> = OnceLock::new();

/// 调用者身份信息（进程的原始 real uid/gid）。
#[derive(Clone)]
pub struct CallerInfo {
    pub uid: u32,
    pub gid: u32,
    pub username: String,
}

/// 获取当前调用者信息：优先返回 setup 快照（见 `ORIGINAL_CALLER`，setuid(0) 后实时查询不再是调用者）；未过 setup 的常驻进程走实时查询。
pub fn get_caller_info() -> CallerInfo {
    if let Some(caller) = ORIGINAL_CALLER.get() {
        return caller.clone();
    }
    let ruid = getuid();
    let rgid = getgid();
    CallerInfo {
        uid: ruid.as_raw(),
        gid: rgid.as_raw(),
        username: get_username(ruid),
    }
}

/// 异步版本：获取当前调用者信息（spawn_blocking，不阻塞 Tokio worker 线程）。
pub async fn get_caller_info_async() -> CallerInfo {
    tokio::task::spawn_blocking(get_caller_info)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "get_caller_info spawn_blocking failed; falling back to sync");
            get_caller_info()
        })
}

/// 通过 getpwuid_r（线程安全）获取用户名，失败时 fallback 到 uid=<数字> 格式。
fn get_username(uid: Uid) -> String {
    match nix::unistd::User::from_uid(uid) {
        Ok(Some(user)) => user.name,
        _ => format!("uid={}", uid.as_raw()),
    }
}

/// 返回 `crbs` 系统组的 gid（宿主机目录如 ccache 的权限设置用）。
#[cfg(target_os = "linux")]
pub fn crbs_group_gid() -> crate::Result<u32> {
    // /etc/group 进程生命周期内不变，LazyLock 缓存（含失败结果）免热路径重复读文件+解析。
    static CACHED: LazyLock<crate::Result<u32>> =
        LazyLock::new(|| linux_privs::get_crbs_group_gid().map(|g| g.as_raw()));
    CACHED.clone()
}

/// 异步版本：返回 `crbs` 系统组的 gid（spawn_blocking，不阻塞 Tokio worker 线程）。
pub async fn crbs_group_gid_async() -> crate::Result<u32> {
    tokio::task::spawn_blocking(crbs_group_gid)
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking crbs_group_gid: {e}")))?
}

/// 非 Linux 桩：`crbs` 组查找仅在 Linux 有实现，其余平台直接报错。
#[cfg(not(target_os = "linux"))]
pub fn crbs_group_gid() -> crate::Result<u32> {
    Err(crate::error::CrbsError::io_message(
        "crbs group lookup requires Linux",
    ))
}

#[cfg(target_os = "linux")]
mod linux_privs {
    const CRBS_GROUP: &str = "crbs";
    use super::*;
    use caps::Capability;
    use nix::unistd::setuid;

    static ALLOWED_CAPS: LazyLock<HashSet<Capability>> = LazyLock::new(|| {
        let mut set = HashSet::new();
        set.insert(Capability::CAP_SYS_ADMIN);
        set.insert(Capability::CAP_SYS_CHROOT);
        set.insert(Capability::CAP_CHOWN);
        set.insert(Capability::CAP_DAC_OVERRIDE);
        set.insert(Capability::CAP_FOWNER);
        set.insert(Capability::CAP_SETUID);
        set.insert(Capability::CAP_SETGID);
        // nspawn --as-pid2 + --bind 需要设置/删除容器 capabilities 和 audit login uid
        set.insert(Capability::CAP_SETPCAP);
        set.insert(Capability::CAP_AUDIT_CONTROL);
        // chroot backend 内 sudo -u builder 需要写 audit 记录，避免 "unable to send audit message"
        set.insert(Capability::CAP_AUDIT_WRITE);
        // dnf installroot 中 RPM 安装会设置文件 capabilities（如 shadow 的 newgidmap）
        set.insert(Capability::CAP_SETFCAP);
        // dnf installroot 中 SELinux 策略包 %post 需要加载策略（仅 SELinux 启用时被
        // priv-helper 实际使用）；base_os 安装（init / build --reproduce，Restricted 模式）
        // 必须保留——否则 setuid-root 的 priv-helper 继承到缺它的 bounding set，无法 raise（EPERM）。
        set.insert(Capability::CAP_MAC_ADMIN);
        set
    });

    /// 特权命令入口（Restricted 模式）：uid=0，裁剪 bounding set 到 ALLOWED_CAPS。
    pub fn setup_privileged() -> crate::Result<()> {
        setup_privileged_impl(true)
    }

    /// 特权命令入口（Full 模式）：uid=0，不裁剪 bounding set（gc 等需完整特权的命令用）。
    pub fn setup_privileged_init() -> crate::Result<()> {
        setup_privileged_impl(false)
    }

    fn setup_privileged_impl(drop_caps: bool) -> crate::Result<()> {
        let ruid = getuid();
        let euid = geteuid();
        // setuid(0) 会连 ruid 一起清零，先快照原始调用者（重复 setup 时首个快照获胜）。
        let _ = ORIGINAL_CALLER.set(CallerInfo {
            uid: ruid.as_raw(),
            gid: getgid().as_raw(),
            username: get_username(ruid),
        });
        if ruid.is_root() {
            debug!(
                caller = "root/sudo",
                mode = if drop_caps { "restricted" } else { "full" }
            );
        } else if euid.is_root() {
            // setuid root 二进制：提权后运行，随后按模式裁剪能力集。
            verify_crbs_group(ruid)?;
            setuid(Uid::from_raw(0)).map_err(|e| CrbsError::Internal(format!("setuid(0): {e}")))?;
            debug!(
                caller_uid = ruid.as_raw(),
                mode = if drop_caps { "restricted" } else { "full" }
            );
        } else {
            // 权限模型：CLI 不 setuid，仅验证组成员身份；无需也不能裁剪 bounding set。
            verify_crbs_group(ruid)?;
            debug!(
                caller_uid = ruid.as_raw(),
                mode = if drop_caps { "restricted" } else { "full" },
                "privileged helper model (no setuid)"
            );
            clear_ambient_and_inheritable_caps()?;
            return Ok(());
        }
        if drop_caps {
            drop_bounding_set()?;
        }
        Ok(())
    }

    /// 只读命令入口：验证 crbs 组，setuid 二进制再降到调用者 uid。
    pub fn setup_unprivileged() -> crate::Result<()> {
        let ruid = getuid();
        let euid = geteuid();
        if ruid.is_root() {
            return Ok(());
        }
        verify_crbs_group(ruid)?;
        debug!(
            caller_uid = ruid.as_raw(),
            "unprivileged mode (dropped uid 0)"
        );
        if euid.is_root() {
            setuid(ruid).map_err(|e| CrbsError::Internal(format!("setuid: {e}")))?;
        }
        Ok(())
    }

    fn verify_crbs_group(ruid: Uid) -> crate::Result<()> {
        let crbs_gid = get_crbs_group_gid()?;

        if getgid() == crbs_gid {
            return Ok(());
        }

        let groups = getgroups().map_err(|e| CrbsError::Internal(format!("getgroups: {e}")))?;
        if groups.contains(&crbs_gid) {
            return Ok(());
        }

        Err(CrbsError::PermissionDenied {
            message: format!(
                "User {} is not in the '{}' group. Run: sudo usermod -aG {} <username>",
                ruid, CRBS_GROUP, CRBS_GROUP
            ),
        })
    }

    pub(crate) fn get_crbs_group_gid() -> crate::Result<Gid> {
        let content = fs::read_to_string("/etc/group")
            .map_err(|e| CrbsError::from_io_context("read /etc/group", e))?;

        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && parts[0] == CRBS_GROUP {
                let gid: u32 = parts[2].parse().map_err(|e: std::num::ParseIntError| {
                    CrbsError::Internal(format!("parse gid in /etc/group: {e}"))
                })?;
                return Ok(Gid::from_raw(gid));
            }
        }

        Err(CrbsError::PermissionDenied {
            message: format!(
                "Group '{}' not found. Run: groupadd -r {}",
                CRBS_GROUP, CRBS_GROUP
            ),
        })
    }

    fn drop_bounding_set() -> crate::Result<()> {
        let current = caps::read(None, caps::CapSet::Bounding)
            .map_err(|e| CrbsError::Internal(format!("read bounding set: {e}")))?;

        for cap in &current - &ALLOWED_CAPS {
            caps::drop(None, caps::CapSet::Bounding, cap)
                .map_err(|e| CrbsError::Internal(format!("drop bounding set: {e}")))?;
        }
        Ok(())
    }

    /// 清空 ambient 与 inheritable 能力集：helper 模型下主进程非特权运行，不留环境继承能力。
    fn clear_ambient_and_inheritable_caps() -> crate::Result<()> {
        caps::clear(None, caps::CapSet::Ambient)
            .map_err(|e| CrbsError::Internal(format!("clear ambient caps: {e}")))?;
        caps::clear(None, caps::CapSet::Inheritable)
            .map_err(|e| CrbsError::Internal(format!("clear inheritable caps: {e}")))?;
        Ok(())
    }

    /// crbs-server 入口：root 启动时仅裁剪 bounding set 作纵深防御，非 root 直接通过；特权操作委托 crbs-priv-helper。
    pub fn setup_server() -> crate::Result<()> {
        let ruid = getuid();
        if ruid.is_root() {
            info!("crbs-server running as root; dropping bounding set to allowed capabilities");
            drop_bounding_set()?;
        } else {
            info!(
                uid = ruid.as_raw(),
                "crbs-server running as unprivileged user (privileged helper model)"
            );
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn allowed_caps_matches_expected_set() {
            // nspawn MINIMAL_CAPS + CAP_AUDIT_WRITE（chroot backend 内 sudo）+ CAP_MAC_ADMIN（SELinux %post）。
            let expected_names = [
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
                "cap_mac_admin",
            ];
            assert_eq!(
                ALLOWED_CAPS.len(),
                expected_names.len(),
                "ALLOWED_CAPS size mismatch"
            );
            for name in &expected_names {
                assert!(
                    ALLOWED_CAPS
                        .iter()
                        .any(|c| format!("{:?}", c).to_lowercase() == *name),
                    "ALLOWED_CAPS missing {} (from expected set)",
                    name
                );
            }
        }

        #[test]
        fn get_crbs_group_gid_parses_format() {
            if !std::path::Path::new("/etc/group").exists() {
                eprintln!("skipping: /etc/group not available");
                return;
            }
            match get_crbs_group_gid() {
                Ok(gid) => assert!(gid.as_raw() > 0, "gid should be positive"),
                Err(CrbsError::PermissionDenied { .. }) => {}
                Err(e) => panic!("unexpected error: {}", e),
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod linux_privs {
    /// 非 Linux 桩：特权入口（Linux 侧 = Restricted 模式，uid=0 并裁剪 bounding 集）在本平台为 no-op。
    pub fn setup_privileged() -> crate::Result<()> {
        Ok(())
    }

    /// 非 Linux 桩：特权入口（Linux 侧 = Full 模式，uid=0 且不裁剪 bounding 集）在本平台为 no-op。
    pub fn setup_privileged_init() -> crate::Result<()> {
        Ok(())
    }

    /// 非 Linux 桩：只读入口（Linux 侧验证 crbs 组，setuid 二进制再降回调用者 uid）在本平台为 no-op。
    pub fn setup_unprivileged() -> crate::Result<()> {
        Ok(())
    }

    /// 非 Linux 桩：server 入口（Linux 侧 root 启动时裁剪 bounding 集）在本平台为 no-op。
    pub fn setup_server() -> crate::Result<()> {
        Ok(())
    }
}

pub use linux_privs::{setup_privileged, setup_privileged_init, setup_server, setup_unprivileged};

/// 权限模式：特权命令需 euid=0。Full：不裁剪 bounding 集（gc 等需完整特权）；
/// Restricted：裁剪 bounding 集到 ALLOWED_CAPS（含 base_os 重建所需的 CAP_MAC_ADMIN）；
/// Unprivileged：降权到调用者 uid；Server：systemd 以非 root + ambient caps 运行，
/// root 启动时仅裁剪 bounding 集。
#[derive(Clone, Copy)]
pub enum PrivMode {
    /// Full：特权命令不裁剪 bounding 集（gc 等需完整特权），入口 [`setup_privileged_init`]。
    Full,
    /// Restricted：特权命令裁剪 bounding 集到白名单（含 base_os 重建所需 CAP_MAC_ADMIN），入口 [`setup_privileged`]。
    Restricted,
    /// Unprivileged：只读命令，验证 crbs 组后 setuid 二进制降回调用者 uid，入口 [`setup_unprivileged`]。
    Unprivileged,
    /// Server：crbs-server 常驻，特权操作委托 priv-helper，root 启动仅裁剪 bounding 集，入口 [`setup_server`]。
    Server,
}

/// 根据模式设置进程权限。
pub fn setup_privileges(mode: PrivMode) -> crate::Result<()> {
    // 记录档位特权需求供 init_privilege_backend 的 Auto 回退告警合流；Unprivileged/Server
    // 档不需要特权，remote 命令不进本函数，均不触发告警。
    if matches!(mode, PrivMode::Full | PrivMode::Restricted) {
        PRIVILEGED_TIER_REQUESTED.store(true, Ordering::Relaxed);
    }
    match mode {
        PrivMode::Full => setup_privileged_init()?,
        PrivMode::Restricted => setup_privileged()?,
        PrivMode::Unprivileged => setup_unprivileged()?,
        PrivMode::Server => setup_server()?,
    }
    Ok(())
}

/// 调用者上下文：封装 caller 信息和 root 判断。
///
/// `is_root` = 启动时 real uid 是否为 0（setup_privileges 前捕获），操作者语义而非进程特权语义：
/// setuid-root 二进制被普通用户调用时 euid=0 但 is_root 仍 false（用 getuid 而非 geteuid，防越权）。
#[derive(Clone)]
pub struct CallerContext {
    pub caller: CallerInfo,
    pub is_root: bool,
}

impl CallerContext {
    /// 以 caller 信息与启动时捕获的 root 判定（见结构体文档）构造上下文。
    pub fn new(caller: CallerInfo, is_root: bool) -> Self {
        Self { caller, is_root }
    }
}
