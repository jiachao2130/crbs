// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! PrivilegeBackend：把必须 root/capability 的操作抽象为可插拔后端。
//! - `SetuidBackend`：主进程已 euid=0，直接执行 syscall；`HelperBackend`：调用
//!   独立 `crbs-priv-helper` one-shot 二进制。
//!
//! 默认 `SetuidBackend`；`Config::use_privileged_helper` 启用且 helper 可执行时切换。

use std::path::{Path, PathBuf};

/// Helper 后端子模块：把特权操作编码为 `crbs-priv-helper` one-shot 子命令执行，
/// 含 helper 探测与安全基线校验（`passes_helper_file_baseline`）。
pub mod helper;
/// Setuid 后端子模块：主进程已持 root 时进程内直接 syscall，承载与 helper 侧
/// 手抄同步的 setid 位剥离等安全约束。
pub mod setuid;

pub use helper::{passes_helper_file_baseline, HelperBackend};
pub use setuid::SetuidBackend;

/// overlayfs 挂载请求：`lower` 为只读下层（按序叠加），`upper`/`work` 为可写
/// 上层与 overlay 工作目录，`target` 为挂载点。
#[derive(Debug, Clone)]
pub struct MountOverlayRequest {
    pub lower: Vec<PathBuf>,
    pub upper: PathBuf,
    pub work: PathBuf,
    pub target: PathBuf,
}

/// 特权操作抽象：engine 侧只面向本 trait，由 Setuid（进程内直接 syscall）与
/// Helper（one-shot `crbs-priv-helper` 子进程）双实现承载。
///
/// 契约：同名方法两路结果语义一致；安全口径（setid 位剥离、spawn_dnf 参数
/// 白名单、受信 repo 固定注入）两侧须同步收紧，单侧收窄即成绕过面。
///
/// 边界差异（有意保留）：路径域校验（mount 目标须严格位于允许根/临时目录
/// 之下、umount 域、rm-rf 根等值拒绝等）只存在于 Helper 实现——那是 setuid
/// 边界对**调用者参数**的防御。Setuid 后端跑在已获 root 的进程内，调用方与
/// 被调用方同源，无边界可防，只直连 syscall；生产部署（server 非特权 +
/// helper）走 Helper 校验。
pub trait PrivilegeBackend: Send + Sync {
    /// 执行 mount(2)：`source`/`fstype`/`data` 可空，`flags` 传 `MsFlags` 原始位。
    /// setuid 直接 syscall（未知 flag 位被 `from_bits_truncate` 静默丢弃）；helper
    /// 转发 `mount` 子命令，flags 以十进制串透传。
    fn mount(
        &self,
        source: Option<&Path>,
        target: &Path,
        fstype: Option<&str>,
        flags: u64,
        data: Option<&str>,
    ) -> crate::Result<()>;

    /// 执行 umount2(2)：`flags` 传 `MntFlags` 原始位，0 = 无标志。
    /// setuid 直接 syscall；helper 转发 `umount` 子命令。非 Linux 的 setuid
    /// 实现一律报错（mount/umount2 均 Linux-only）。
    fn umount2(&self, target: &Path, flags: i32) -> crate::Result<()>;

    /// 挂载 overlayfs。默认实现把 `req` 拼成 `lowerdir=`/`upperdir=`/`workdir=`
    /// 选项串交 [`Self::mount`]（fstype = overlay）；helper 实现改走专用
    /// `mount-overlay` 子命令逐层传参，不经选项串拼装。
    fn mount_overlay(&self, req: MountOverlayRequest) -> crate::Result<()> {
        let lower_opt = req
            .lower
            .iter()
            .map(|p| p.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(":");
        let options = format!(
            "lowerdir={lower},upperdir={upper},workdir={work}",
            lower = lower_opt,
            upper = req.upper.display(),
            work = req.work.display()
        );
        self.mount(
            Some(Path::new("overlay")),
            &req.target,
            Some("overlay"),
            0,
            Some(&options),
        )
    }

    /// 创建目录（含父目录）并设属主与权限：`user`/`group` 按名解析，不存在即报错；
    /// `mode` 为八进制位。两实现均剥目录 SUID、保 SGID（0o2770 组协作不变量不被
    /// 特权路径破坏），且 chmod 不跟随符号链接。
    fn mkdir_chown(&self, path: &Path, user: &str, group: &str, mode: u32) -> crate::Result<()>;

    /// 变更属主：`uid`/`gid` 为原始数字 id；`recursive` 时遍历整棵子树。
    /// 两实现均不跟随符号链接（lchown，改链接自身属主而非目标）。
    fn chown(&self, path: &Path, uid: u32, gid: u32, recursive: bool) -> crate::Result<()>;

    /// 变更权限位（八进制）；`recursive` 时遍历整棵子树。两实现均类型感知剥
    /// setid 位（文件剥 S_ISUID|S_ISGID、目录剥 S_ISUID）——特权路径不得铸造
    /// setid-root 文件；递归时文件另掩 `0o666`，符号链接不跟随。
    fn chmod(&self, path: &Path, mode: u32, recursive: bool) -> crate::Result<()>;

    /// 写入文件（父目录不存在时自动创建），可选设置权限与属主。
    fn write_file(
        &self,
        path: &Path,
        content: &[u8],
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> crate::Result<()>;

    /// 清理指定 crbs_root 下的孤儿挂载点。`tmp_dirs` = 可选扩展扫描域（engine
    /// `tmp_dir`/`tmpfs_dir`；overlay 目标在 `{tmp_dir}/.tmpXXXX/root`，全内存
    /// 构建另在 `.tmpXXXX/memroot/root`，崩溃残留多在 crbs_root 之外）。tmp 域
    /// 命中须收紧到 `.tmp*` 命名 + 容器伪文件系统（对齐 helper
    /// `mount_in_gc_scan_domain`），不得全量扫描共享 tmp；一律 MNT_DETACH 懒卸载，不删目录体。
    fn gc_orphan_mounts(&self, crbs_root: &Path, tmp_dirs: &[PathBuf]) -> crate::Result<()>;

    /// 递归删除一个或多个路径（文件或目录）；路径不存在按 `remove_dir_all`/
    /// `remove_file` 语义 no-op。不带默认实现：所有 backend 必须显式实现，防 mock 静默走错路径。
    fn rm_rf(&self, paths: &[&Path]) -> crate::Result<()>;

    /// 构造进入 chroot rootfs 的 Command（Linux 直接 syscall；helper 模式调用 helper）。
    fn spawn_chroot(
        &self,
        rootfs: &Path,
        program: &str,
        args: &[&str],
        network: bool,
    ) -> crate::Result<std::process::Command>;

    /// 构造执行 `systemd-nspawn` 的 Command（helper 模式下由 helper exec nspawn）。
    fn spawn_nspawn(&self, nspawn_argv: &[String]) -> crate::Result<std::process::Command>;

    /// 写入 cgroup v2 控制文件（如 memory.max / cpu.max / cgroup.kill）。值统一
    /// 追加单个换行（cgroupfs 解析忽略尾随空白，调用方无需自带）；路径须由调用
    /// 方保证指向 cgroupfs（nspawn 后端只传 /sys/fs/cgroup/machine.slice/ 固定
    /// 文件名）。setuid 直接 `std::fs::write`；helper spawn `crbs-priv-helper
    /// write-cgroup-file`（旧版以"未知子命令"失败）。同步可阻塞至内部超时，async 须经 `spawn_blocking`。
    fn write_cgroup_file(&self, path: &str, value: &str) -> crate::Result<()>;

    /// 构造执行 `dnf` 的 Command（普通用户经 helper 以 root 执行；setuid 直接执行）。
    /// `args` 不含 `--installroot`/`--releasever`（后端统一注入）；`trusted_repos_dir`
    /// = host 受信 repo 目录（`{crbs_root}/dnf-repos/{product}`，engine 经 write_file
    /// 预写 repo 集与 dnf.conf），后端固定注入 `--config=<dir>/dnf.conf`、
    /// `--setopt=reposdir=<dir>` 钉死 repo 来源——installroot 内 repo（产品/组成员
    /// 可控）不再被读；调用方透传的 `--config`/`--setopt` 仍被参数白名单拒绝。
    fn spawn_dnf(
        &self,
        installroot: &Path,
        releasever: &str,
        trusted_repos_dir: &Path,
        args: &[String],
    ) -> crate::Result<std::process::Command>;

    /// 当前后端是否为 helper（用于后端可用性判断）。
    fn is_helper(&self) -> bool {
        false
    }

    /// 取消时杀构建进程组（pgid 负 pid 约定）：helper 以 root 身份 SIGKILL，
    /// worker 不持 root。`pgid` 为 spawn 时捕获的子进程 pid（= pgid）。
    fn kill_process_group(&self, pgid: i32) -> crate::Result<()>;

    /// 受控终止本系统自建的 nspawn machine（kill 升级链的 machine 级兜底）：
    /// cgroup v2 写 scope 的 `cgroup.kill`（`/sys/fs/cgroup/machine.slice/` 下
    /// 双命名形态探测），v1（无统一层级）按 /proc cgroup 的 scope 成员 SIGKILL；
    /// machine 已不存在按幂等成功。信任边界：`machine_name` 只接受 crbs 自建
    /// 命名空间，helper 路径以 `crbs-[0-9a-fA-F-]{8,64}` 再校验。同步可阻塞，
    /// async 须经 `spawn_blocking`。
    fn terminate_machine(&self, machine_name: &str) -> crate::Result<()>;
}
