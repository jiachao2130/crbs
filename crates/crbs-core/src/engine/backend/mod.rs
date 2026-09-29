// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 容器后端抽象：`ContainerBackend` trait、spawn 公共类型（选项 / stdio /
//! 子进程包装）与 chroot / nspawn 两个实现模块。

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;

/// setuid 直连 spawn 的最小 PATH（env_clear 后仅保留）；与 crbs-priv-helper `spawn::SAFE_PATH` 手抄同步。
pub(crate) const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// nspawn `--bind` / `--bind-ro` 规格：host 路径 → 容器内路径；chroot 忽略（host mount ns 已可见）。
#[derive(Debug, Clone)]
pub struct BindMount {
    /// 宿主机路径。
    pub host: String,
    /// 容器内路径。
    pub container: String,
    /// 是否只读（nspawn `--bind-ro`）。
    pub read_only: bool,
}

/// 容器资源限制（目前仅 nspawn backend 支持）。
#[derive(Debug, Clone, Default)]
pub struct ResourceLimits {
    /// systemd MemoryMax= 格式，如 "512M" / "2G" / "0"。
    pub memory_max: Option<String>,
    /// systemd CPUQuota= 格式，如 "200%"（2 核）/ "50%"（半核）。
    pub cpu_quota: Option<String>,
}

/// 容器后端执行选项（Stdio 字段用枚举包装：`std::process::Stdio` 不实现 Clone）。
#[derive(Debug, Clone)]
pub struct SpawnOptions {
    /// 运行命令的用户（仅 shell 场景；spawn 必须为 None，否则被 chroot/nspawn
    /// 以 ValidationFailed 拒绝）。
    pub user: Option<String>,
    /// 环境变量（BTreeMap：nspawn 按迭代顺序生成 `--setenv`，argv 确定可复现）。
    pub env: BTreeMap<String, String>,
    /// 是否创建新进程组（process_group(0)）。
    pub process_group: bool,
    /// 网络模式：true = 共享宿主网络（默认），false = 隔离（--private-network / unshare --net）。
    pub network: bool,
    /// stdin 配置。
    pub stdin: StdioKind,
    /// stdout 配置。
    pub stdout: StdioKind,
    /// stderr 配置。
    pub stderr: StdioKind,
    /// nspawn 专用：bind mount 列表（映射规格见 `BindMount`）。
    pub binds: Vec<BindMount>,
    /// nspawn 专用：machine name 后缀（通常传 build_id），避免并发构建共享 rootfs 时 cgroup 冲突。
    pub machine_name_suffix: Option<String>,
    /// 容器 hostname 钉死（确定性模式）：nspawn `--hostname=<值>` 消除宿主机名环境变量；chroot 当前忽略。
    pub hostname: Option<String>,
}

/// Stdio 配置的克隆友好枚举。
#[derive(Debug, Clone, Copy)]
pub enum StdioKind {
    /// 丢弃输出（/dev/null）。
    Null,
    /// 管道输出，由父进程读取。
    Piped,
    /// 继承父进程 stdio。
    Inherit,
}

impl From<StdioKind> for Stdio {
    fn from(kind: StdioKind) -> Self {
        match kind {
            StdioKind::Null => Stdio::null(),
            StdioKind::Piped => Stdio::piped(),
            StdioKind::Inherit => Stdio::inherit(),
        }
    }
}

impl SpawnOptions {
    /// 交互式 shell 的默认配置（stdin/stdout/stderr 均为 inherit）。
    pub fn interactive() -> Self {
        Self {
            stdin: StdioKind::Inherit,
            stdout: StdioKind::Inherit,
            stderr: StdioKind::Inherit,
            ..Self::default()
        }
    }
}

impl Default for SpawnOptions {
    fn default() -> Self {
        Self {
            user: None,
            env: BTreeMap::new(),
            process_group: false,
            network: true,
            stdin: StdioKind::Null,
            stdout: StdioKind::Piped,
            stderr: StdioKind::Piped,
            binds: Vec::new(),
            machine_name_suffix: None,
            hostname: None,
        }
    }
}

/// 将 `SpawnOptions` 的 stdio 与 process_group 应用到 tokio Command；`opts.env`
/// 不在此处理——chroot 直接 `cmd.env`，nspawn 经 argv `--setenv` 注入。
pub(crate) fn apply_spawn_opts(cmd: &mut tokio::process::Command, opts: &SpawnOptions) {
    cmd.stdin(Stdio::from(opts.stdin))
        .stdout(Stdio::from(opts.stdout))
        .stderr(Stdio::from(opts.stderr))
        .kill_on_drop(true);
    if opts.process_group {
        cmd.process_group(0);
    }
}

/// 包装 `tokio::process::Child` 附带 cgroup payload kill 候选路径；`Deref`/`DerefMut`
/// 直接当 `Child` 用，取消/超时路径经 `cgroup_kill()` 原子 kill 整棵 cgroup 子树。
pub struct SpawnedChild {
    /// 子进程句柄。
    pub child: tokio::process::Child,
    /// cgroup payload 子 cgroup kill 候选路径（探测根 × scope 命名形态组合 +
    /// 解析命中优先，nspawn 即填充，与 limits 无关）；写入走特权后端
    ///（直写 /sys/fs/cgroup 会 EACCES）。首个 = 解析命中的主路径（资源采样口径）。
    cgroup_kill_paths: Vec<String>,
    /// nspawn machine 名（kill 复核失败日志的操作提示用）；chroot 恒 None。
    machine_name: Option<String>,
}

impl SpawnedChild {
    /// 构造无 cgroup payload 的包装（测试 mock 用；chroot backend 在子模块内可直接构造字面量）。
    #[cfg(test)]
    pub(crate) fn new(child: tokio::process::Child) -> Self {
        Self {
            child,
            cgroup_kill_paths: Vec::new(),
            machine_name: None,
        }
    }

    /// payload 主 cgroup 路径（解析命中的首个候选）；`None` = 无 cgroup 口径，
    /// 资源采样分派 /proc 模式。
    pub(crate) fn cgroup_payload_path(&self) -> Option<&str> {
        self.cgroup_kill_paths.first().map(String::as_str)
    }

    /// nspawn machine 名（kill 复核失败日志的操作提示用）；chroot 恒 None。
    pub(crate) fn machine_name(&self) -> Option<&str> {
        self.machine_name.as_deref()
    }

    /// nspawn + cgroup v1 宿主的采样归属 machine 名：payload 缺席而 machine 名
    /// 在场即 v1（v2 宿主 `setup_payload_cgroup` 无条件产出 payload 主路径，
    /// machine 名非法时两者同为 None）。v1 容器 init 开新会话/进程组，资源采样
    /// 据此按 machine scope 子树归属而非 pgid 匹配（pgid 抓不到容器进程）。
    pub(crate) fn v1_scope_machine_name(&self) -> Option<&str> {
        if self.cgroup_kill_paths.is_empty() {
            self.machine_name.as_deref()
        } else {
            None
        }
    }

    /// machine scope 的 cgroup 候选路径（探测根 × 双命名 × 原样/转义组合，
    /// 绝对路径）；machine 名缺失（chroot / 注册降级）为空。kill 升级终局
    /// "人工清理"错误的操作提示用——v2 宿主即精确 scope 路径，v1 宿主给出
    /// systemd 层级前缀下的 machined 命名形态。
    pub(crate) fn machine_scope_hints(&self) -> Vec<String> {
        match self.machine_name.as_deref() {
            Some(name) => nspawn::scope_path_candidates(name),
            None => Vec::new(),
        }
    }

    /// 原子 kill 整棵 cgroup 子树，返回是否成功发起：遍历全部 scope 命名候选
    ///（随 systemd 版本两种并存，单形态写失败会漏杀整棵子树），任一写成功即
    /// true；全部失败（cgroup 已被 systemd 回收等）false，调用方回退 SIGKILL 进程组。
    pub async fn cgroup_kill(&self) -> bool {
        for path in &self.cgroup_kill_paths {
            let kill_path = format!("{path}/cgroup.kill");
            let backend = crate::privilege::get_privilege_backend();
            let result =
                tokio::task::spawn_blocking(move || backend.write_cgroup_file(&kill_path, "1"))
                    .await;
            match result {
                Ok(Ok(())) => return true,
                Ok(Err(e)) => {
                    tracing::debug!(path = %path, error = %e, "cgroup.kill write failed");
                }
                Err(e) => {
                    tracing::debug!(path = %path, error = %e, "cgroup.kill spawn_blocking failed");
                }
            }
        }
        false
    }
}

impl std::ops::Deref for SpawnedChild {
    type Target = tokio::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.child
    }
}

impl std::ops::DerefMut for SpawnedChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}

/// 在已 mount 好的 rootfs 内执行命令。责任边界：BuildEngine 负责 overlay /
/// bind mount、tmpfs、脚本生成、日志流式、取消/超时；backend 只负责 spawn 进程。
// double_must_use 白名单：async_trait 展开叠加 Box<dyn Future + MustUse> 与
// 本 trait 自身 must_use 语义（spawn 出的 Child 不可弃置），双标记属派生形态。
#[async_trait::async_trait]
#[allow(clippy::double_must_use)]
pub trait ContainerBackend: Send + Sync + std::fmt::Debug {
    /// 后端名称。
    fn name(&self) -> &str;

    /// 检测后端是否可用。
    fn available(&self) -> bool;

    /// 在 rootfs 内执行命令，返回已 spawn 的 Child。chroot 要求 `opts.user` 为
    /// None：用户切换由调用方脚本内部处理（避免与脚本内 sudo 双重切换）。
    async fn spawn(
        &self,
        rootfs: &Path,
        command: &[&str],
        opts: &SpawnOptions,
    ) -> crate::Result<SpawnedChild>;

    /// 交互式 shell，尊重 `opts` 全部字段。⚠️ 交互式慎用 `process_group: true`
    ///（断开终端 job control，Ctrl+Z 等失效），主要用于后台/非交互场景。
    async fn shell(
        &self,
        rootfs: &Path,
        command: Option<&str>,
        opts: &SpawnOptions,
    ) -> crate::Result<std::process::ExitStatus>;
}

pub mod chroot;
pub use chroot::ChrootBackend;

pub(crate) mod chroot_impl;

pub mod nspawn;
pub use nspawn::NspawnBackend;

/// 按名称创建后端（"chroot" / "nspawn"）并校验可用性，不可用返回配置错误。
pub async fn create_backend(
    name: &str,
    limits: &ResourceLimits,
) -> crate::Result<Box<dyn ContainerBackend>> {
    let backend: Box<dyn ContainerBackend> = match name {
        "chroot" => Box::new(ChrootBackend::new()),
        "nspawn" => Box::new(NspawnBackend::new().with_limits(limits.clone())),
        other => {
            return Err(crate::error::CrbsError::ValidationFailed {
                message: format!("Unknown backend: {}; supported: chroot, nspawn", other),
            });
        }
    };
    if !backend.available() {
        return Err(crate::error::CrbsError::ValidationFailed {
            message: format!(
                "Backend '{}' not available on this host; \
                 install required packages (systemd-container for nspawn) \
                 or choose a different backend",
                name
            ),
        });
    }
    Ok(backend)
}

#[cfg(test)]
mod tests {
    /// 锁定 SAFE_PATH 与 helper 手抄常量相等（crbs-core 不依赖 helper crate，include_str 比对源码字面量）。
    #[test]
    fn safe_path_matches_priv_helper_constant() {
        let helper_src = include_str!("../../../../crbs-priv-helper/src/spawn.rs");
        let line = helper_src
            .lines()
            .find(|l| l.contains("pub const SAFE_PATH"))
            .expect("crbs-priv-helper spawn.rs must define pub const SAFE_PATH");
        let start = line.find('"').expect("SAFE_PATH literal start") + 1;
        let end = line[start..].find('"').expect("SAFE_PATH literal end") + start;
        assert_eq!(
            &line[start..end],
            super::SAFE_PATH,
            "SAFE_PATH in crbs-core and crbs-priv-helper must stay in sync"
        );
    }

    /// machine scope 候选提示：探测根 × 命名形态组合齐全（v2 + v1 legacy 根、
    /// 原样 + 转义）、绝对路径；machine 名缺失（chroot / 注册降级）为空——
    /// 升级终局错误不得给 chroot 报 nspawn 提示。
    #[tokio::test]
    async fn machine_scope_hints_derived_from_machine_name() {
        let child = tokio::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let spawned = super::SpawnedChild {
            child,
            cgroup_kill_paths: Vec::new(),
            machine_name: Some("crbs-9c714595-22".to_string()),
        };
        let hints = spawned.machine_scope_hints();
        assert_eq!(hints.len(), 8);
        for h in &hints {
            assert!(
                h.starts_with("/sys/fs/cgroup/machine.slice/")
                    || h.starts_with("/sys/fs/cgroup/systemd/machine.slice/"),
                "hint root unexpected: {h}"
            );
        }
        assert!(hints.contains(&"/sys/fs/cgroup/machine.slice/crbs-9c714595-22.scope".to_string()));
        assert!(hints.contains(
            &"/sys/fs/cgroup/machine.slice/machine-crbs\\x2d9c714595\\x2d22.scope".to_string()
        ));
        assert!(hints.contains(
            &"/sys/fs/cgroup/systemd/machine.slice/machine-crbs-9c714595-22.scope".to_string()
        ));

        let child = tokio::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let spawned = super::SpawnedChild::new(child);
        assert!(spawned.machine_scope_hints().is_empty());
    }

    /// v1 scope 归属 machine 名矩阵：payload 缺席 + machine 名在场（nspawn v1）
    /// → Some(machine 名)；v2（payload 在）与 chroot（machine 名缺）→ None。
    #[tokio::test]
    async fn v1_scope_machine_name_matrix() {
        let spawn_true = || {
            tokio::process::Command::new("true")
                .spawn()
                .expect("spawn true")
        };
        let payload_path = "/sys/fs/cgroup/machine.slice/machine-test.scope/payload".to_string();

        let nspawn_v1 = super::SpawnedChild {
            child: spawn_true(),
            cgroup_kill_paths: Vec::new(),
            machine_name: Some("crbs-9c714595".to_string()),
        };
        assert_eq!(nspawn_v1.v1_scope_machine_name(), Some("crbs-9c714595"));

        let nspawn_v2 = super::SpawnedChild {
            child: spawn_true(),
            cgroup_kill_paths: vec![payload_path],
            machine_name: Some("crbs-9c714595".to_string()),
        };
        assert_eq!(nspawn_v2.v1_scope_machine_name(), None);

        let chroot = super::SpawnedChild::new(spawn_true());
        assert_eq!(chroot.v1_scope_machine_name(), None);
    }

    /// 契约：chroot 与 nspawn 消费**同一份** `SpawnOptions.env`——nspawn 经 `--setenv`
    /// argv、chroot 经 `Command::env` 逐键注入。chroot spawn 需 root/chroot（macOS
    /// 不可跑），故以源码护栏锁定 env 注入循环，删掉即丢 deterministic env 基线。
    #[test]
    fn chroot_spawn_applies_spawn_options_env_loop() {
        let src = include_str!("chroot.rs");
        assert!(
            src.contains("for (k, v) in &opts.env {"),
            "chroot.rs must keep applying SpawnOptions.env via `for (k, v) in &opts.env {{ cmd.env(k, v); }}` \
             (spawn + shell 两条路径) — the deterministic env baseline relies on it"
        );
        assert_eq!(
            src.matches("for (k, v) in &opts.env {").count(),
            2,
            "chroot.rs must apply opts.env on BOTH spawn and shell paths"
        );
    }
}
