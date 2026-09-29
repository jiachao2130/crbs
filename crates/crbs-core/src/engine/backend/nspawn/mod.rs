// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! nspawn 后端：systemd-nspawn 容器执行命令，支持 cgroup v2 资源限制与整棵 cgroup 子树原子 kill。

use std::path::Path;

use crate::engine::backend::{ContainerBackend, ResourceLimits, SpawnOptions, SpawnedChild};
use crate::error::CrbsError;

mod argv;
mod cgroup;
/// cgroup 资源限制值解析（`parse_memory_max` / `parse_cpu_quota`）；pub(crate) 供
/// config::validation 复用同一解析器，保证配置校验与运行时写入判定一致。
pub(crate) mod parse;

/// machine scope 候选路径（探测根 × 命名形态组合）：backend 层
/// `SpawnedChild::machine_scope_hints` 组装 kill 升级终局错误的操作提示用；
/// systemd unit 转义（`-` → `\x2d`）同源供 privilege setuid 后端的 scope
/// 探测复用（helper 侧为无依赖边的手抄镜像）。
pub(crate) use cgroup::{scope_path_candidates, systemd_escape_dash};

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use argv::{build_shell_argv, build_spawn_argv};

/// systemd-nspawn 后端（PID namespace + cgroup 隔离）。backend 只负责容器启动（永远 root 进入），用户切换由构建脚本内部 sudo 处理。
/// 资源限制：`build_spawn_argv()` 注册 machined（`--register` 默认 auto）为容器建 transient scope——
/// `--register=no` 实测证伪：scope 不创建，进程落回 crbs 自身 session cgroup；scope 命名双形态由
/// `cgroup::scope_path_candidates()` 依序探测，不按版本猜。cgroup v1：`--property=MemoryLimit=`/`CPUQuota=` scope
/// 级生效；v2 payload 不继承 `--property=`，由 `cgroup::setup_payload_cgroup()` 从 host 侧写入；
/// `build_spawn_argv()` 恒生成 `--property=`（v1 需要，v2 忽略）。
/// 就绪等待：构建脚本永不 sd_notify，禁用 `--notify-ready`（必然 30s 超时）；轮询 payload cgroup `cgroup.procs`
///（上限 `cgroup::PAYLOAD_CGROUP_WAIT`）并监听子进程退出，nspawn 启动即失败时立即返回不空等。
#[derive(Debug, Default)]
pub struct NspawnBackend {
    limits: ResourceLimits,
}

impl NspawnBackend {
    /// 创建使用默认（无限）资源限制的后端。
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置容器资源限制（builder 风格）。
    pub fn with_limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }
}

#[async_trait::async_trait]
impl ContainerBackend for NspawnBackend {
    fn name(&self) -> &str {
        "nspawn"
    }

    fn available(&self) -> bool {
        which::which("systemd-nspawn").is_ok()
    }

    async fn spawn(
        &self,
        rootfs: &Path,
        command: &[&str],
        opts: &SpawnOptions,
    ) -> crate::Result<SpawnedChild> {
        if opts.user.is_some() {
            return Err(CrbsError::ValidationFailed {
                message: "NspawnBackend::spawn() contract violated: opts.user must be None; \
                         user switching is handled by the caller's build script"
                    .to_string(),
            });
        }
        if command.is_empty() {
            return Err(CrbsError::ValidationFailed {
                message: "NspawnBackend::spawn() contract violated: command must not be empty"
                    .to_string(),
            });
        }

        let argv = argv::build_spawn_argv(rootfs, command, opts, &self.limits)?;

        let std_cmd = crate::privilege::get_privilege_backend()
            .spawn_nspawn(&argv)
            .map_err(|e| CrbsError::io_message(format!("setup nspawn command: {e}")))?;
        let mut cmd = tokio::process::Command::from(std_cmd);

        crate::engine::backend::apply_spawn_opts(&mut cmd, opts);

        let mut child = cmd
            .spawn()
            .map_err(|e| CrbsError::io_message(format!("spawn nspawn: {}", e)))?;

        // cgroup v2：等 payload cgroup 就绪后写入 limits；kill 候选（双 scope
        // 命名形态）无条件携带，取消路径 cgroup_kill 不依赖 limits 配置。v1 由
        // --property= scope 级生效。
        let payload_cgroup = if cgroup::is_cgroup_v2() {
            cgroup::setup_payload_cgroup(
                &mut child,
                rootfs,
                &self.limits,
                opts.machine_name_suffix.as_deref(),
            )
            .await
        } else {
            None
        };

        // machine 名与 v2 payload 门控脱钩：spawn 恒注册 machined（build_spawn_argv
        // 不传 --register=no，该开关仅存于交互 shell 路径），v1/v2 双栈都建 scope，
        // kill 升级层的 terminate-machine 依赖它——machine 名缺失时取消链路在
        // v1 宿主（cgroup.kill 与 scope 校验谓词全废）再无任何可指向的终止目标。
        // ponytail: build_spawn_argv 已用同参成功过，此处 Err 属不可能路径；
        // 若将来引入不注册 machine 的 spawn 形态，降级 None 后升级链直落人工
        // 清理 error（现有出口），terminate-machine 静默跳过。
        let (cgroup_kill_paths, machine_name) = match payload_cgroup {
            Some(p) => (p.kill_paths, Some(p.machine_name)),
            None => (
                Vec::new(),
                argv::machine_name_for(rootfs, opts.machine_name_suffix.as_deref()).ok(),
            ),
        };

        Ok(SpawnedChild {
            child,
            cgroup_kill_paths,
            machine_name,
        })
    }

    async fn shell(
        &self,
        rootfs: &Path,
        command: Option<&str>,
        opts: &SpawnOptions,
    ) -> crate::Result<std::process::ExitStatus> {
        let argv = argv::build_shell_argv(rootfs, command, opts)?;
        let std_cmd = crate::privilege::get_privilege_backend()
            .spawn_nspawn(&argv)
            .map_err(|e| CrbsError::io_message(format!("setup nspawn shell command: {e}")))?;
        let mut cmd = tokio::process::Command::from(std_cmd);

        crate::engine::backend::apply_spawn_opts(&mut cmd, opts);

        cmd.status()
            .await
            .map_err(|e| CrbsError::io_message(format!("spawn nspawn shell: {}", e)))
    }
}
