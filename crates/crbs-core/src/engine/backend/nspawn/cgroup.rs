// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! nspawn 的 cgroup 约束：v2 判定、scope 路径候选与 payload 回收。

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use tokio::time::timeout;
use tracing::{debug, error, warn};

use crate::engine::backend::nspawn::argv::machine_name_for;
use crate::engine::backend::nspawn::parse::{parse_cpu_quota, parse_memory_max};
use crate::engine::backend::ResourceLimits;

/// 等待 payload cgroup `cgroup.procs` 出现的上限（构建脚本不发 READY=1，
/// 就绪只能轮询 cgroupfs；正常 machined 注册后毫秒级建 scope）。
pub(crate) const PAYLOAD_CGROUP_WAIT: Duration = Duration::from_secs(10);

const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// cgroup 文件系统挂载根（scope 探测专用）：v2 统一根在前，v1 legacy 的
/// systemd 层级根在后——v1 宿主层级挂 /sys/fs/cgroup/systemd，machine scope
/// 只在该前缀下可见。两根都进候选，存在哪个用哪个。
const CGROUP_FS_ROOTS: [&str; 2] = ["/sys/fs/cgroup", "/sys/fs/cgroup/systemd"];

/// v2 统一根（payload 就绪等待的探测根；`setup_payload_cgroup` 仅经
/// `is_cgroup_v2()` 判定的 v2 宿主调用，v1 前缀无需参与该探测）。
const CGROUP_FS_ROOT: &str = CGROUP_FS_ROOTS[0];

static IS_CGROUP_V2: LazyLock<bool> =
    LazyLock::new(|| Path::new("/sys/fs/cgroup/cgroup.controllers").exists());

pub(crate) fn is_cgroup_v2() -> bool {
    *IS_CGROUP_V2
}

/// machined 注册 scope 的 unit 名转义：`-` → `\x2d`（systemd unit_name_escape
/// 的确定性变换）。与 crbs-priv-helper validate::systemd_escape_dash 手抄同步
///（本 crate 与 helper 无依赖边）；machine 命名空间字符集
///（crbs-[0-9a-fA-F-]{8,64}）下仅 `-` 需转义，变换无损，完整 unit 转义规则
///（其余非字母数字字符）不适用不实现。
pub(crate) fn systemd_escape_dash(name: &str) -> String {
    name.replace('-', "\\x2d")
}

/// scope 目录命名形态（machine.slice 下的相对组件，按探测优先级）：
/// `{name}.scope` / `machine-{name}.scope` 双命名 × 原样/转义——machined
/// 注册的 scope 目录名即转义形态（`machine-crbs\x2d…`），v1/v2 宿主一致，
/// 漏转义形态则探测/kill/limits 全部落空。
fn scope_dir_names(machine_name: &str) -> [String; 4] {
    let escaped = systemd_escape_dash(machine_name);
    [
        format!("{machine_name}.scope"),
        format!("{escaped}.scope"),
        format!("machine-{machine_name}.scope"),
        format!("machine-{escaped}.scope"),
    ]
}

/// `--machine=<name>` 容器 transient scope 的候选路径（按探测优先级）：
/// 探测根 × 命名形态全组合（见 [`CGROUP_FS_ROOTS`] / [`scope_dir_names`]）。
/// scope 由 machined 注册容器时创建；存在哪个用哪个，不按版本猜。
pub(crate) fn scope_path_candidates(machine_name: &str) -> Vec<String> {
    let names = scope_dir_names(machine_name);
    let mut out = Vec::with_capacity(CGROUP_FS_ROOTS.len() * names.len());
    for root in CGROUP_FS_ROOTS {
        for name in &names {
            out.push(format!("{root}/machine.slice/{name}"));
        }
    }
    out
}

/// cgroup_kill 的 payload 候选路径序列（纯函数）：探测根 × 命名形态全组合
/// 列入、解析命中的主路径（存在或兜底推导）提到首位且不重复——kill 不赌单形态。
pub(crate) fn payload_kill_candidates(machine_name: &str, primary: &str) -> Vec<String> {
    let mut paths: Vec<String> = scope_path_candidates(machine_name)
        .into_iter()
        .map(|s| format!("{s}/payload"))
        .collect();
    paths.retain(|c| c != primary);
    paths.insert(0, primary.to_string());
    paths
}

/// 以主路径构造 [`PayloadCgroup`]（kill 候选派生见 [`payload_kill_candidates`]）。
fn payload_result(machine_name: &str, primary: &str) -> PayloadCgroup {
    PayloadCgroup {
        kill_paths: payload_kill_candidates(machine_name, primary),
        machine_name: machine_name.to_string(),
    }
}

/// 在 `root` 下按序探测各命名形态的 scope 目录；都不存在返回 `None`，
/// 调用方自行降级（等待/兜底推导），本函数不放大失败。
pub(crate) async fn resolve_scope_path_in(root: &Path, machine_name: &str) -> Option<String> {
    for rel in scope_dir_names(machine_name) {
        let candidate = root.join("machine.slice").join(&rel);
        if tokio::fs::try_exists(&candidate).await.unwrap_or(false) {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

/// 等待候选 payload `cgroup.procs` 之一出现，同时监听子进程退出：候选出现
/// 返回 Some(路径)；子进程先退出（nspawn 启动即败，如坏 rootfs）立即返回
/// None 不空等到 deadline；超时同 None。`Child::wait` 幂等——返回后子进程
/// 已 reap，调用方再次 wait 立即拿到缓存退出状态。
pub(crate) async fn wait_for_cgroup_procs_or_child_exit(
    procs_paths: &[String],
    deadline: Duration,
    child: &mut tokio::process::Child,
) -> Option<String> {
    let candidates: Vec<PathBuf> = procs_paths.iter().map(PathBuf::from).collect();
    timeout(deadline, async {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(POLL_INTERVAL) => {
                    for p in &candidates {
                        if tokio::fs::try_exists(p).await.unwrap_or(false) {
                            return Some(p.to_string_lossy().into_owned());
                        }
                    }
                }
                status = child.wait() => {
                    debug!(status = ?status, "nspawn exited before payload cgroup appeared");
                    return None;
                }
            }
        }
    })
    .await
    .unwrap_or(None)
}

/// `setup_payload_cgroup` 的产出：kill 候选 + machine 名（主路径 = 候选首位）。
pub(crate) struct PayloadCgroup {
    /// cgroup_kill 遍历的全部候选 payload 路径（解析命中的主路径在首，见
    /// [`payload_kill_candidates`]；资源采样同样取首位）。
    pub(crate) kill_paths: Vec<String>,
    /// machine 名（kill 复核失败日志的操作提示用）。
    pub(crate) machine_name: String,
}

/// cgroup v2 专用：等待 payload cgroup 就绪并写入资源限制，返回 payload 路径
///（v1 由 `--property=` 直接生效）。`--property=` 仅作用于 scope，payload 不
/// 继承限制——host 侧经特权后端直写 payload 控制文件（helper 模式 crbs-core
/// 非特权，直写 /sys/fs/cgroup 会 EACCES，通道见 PrivilegeBackend::write_cgroup_file）。
/// 路径无条件 Some：cgroup_kill 不依赖 limits 配置；等待失败/子进程早退跳过
/// limits 仍返回兜底路径，kill 写失败调用方回退 SIGKILL 进程组。
pub(crate) async fn setup_payload_cgroup(
    child: &mut tokio::process::Child,
    rootfs: &Path,
    limits: &ResourceLimits,
    machine_name_suffix: Option<&str>,
) -> Option<PayloadCgroup> {
    let machine_name = match machine_name_for(rootfs, machine_name_suffix) {
        Ok(name) => name,
        Err(e) => {
            warn!(error = %e, "invalid machine_name_suffix, skipping payload cgroup setup");
            return None;
        }
    };
    let candidates = scope_path_candidates(&machine_name);
    // 已存在 scope 优先；都不存在（容器启动中/systemd-less 宿主）时兜底推导
    // 新式命名路径——kill/limits 写失败均有降级路径，不放大失败。
    let scope_path = resolve_scope_path_in(Path::new(CGROUP_FS_ROOT), &machine_name)
        .await
        .unwrap_or_else(|| candidates[0].clone());
    let mut payload_path = format!("{scope_path}/payload");
    let procs_paths: Vec<String> = candidates
        .iter()
        .map(|s| format!("{s}/payload/cgroup.procs"))
        .collect();

    // 无 limits 时跳过就绪等待：路径仅用于 cgroup_kill 尝试，systemd-less
    // 宿主上 scope 永不出现，等待只会每构建空耗 PAYLOAD_CGROUP_WAIT。
    if limits.memory_max.is_none() && limits.cpu_quota.is_none() {
        return Some(payload_result(&machine_name, &payload_path));
    }

    match wait_for_cgroup_procs_or_child_exit(&procs_paths, PAYLOAD_CGROUP_WAIT, child).await {
        Some(procs) => {
            // 命中候选即实际创建的 scope：以它为准（两次探测间无竞态窗口）。
            if let Some(scope) = procs.strip_suffix("/payload/cgroup.procs") {
                payload_path = format!("{scope}/payload");
            }
        }
        None => {
            warn!(
                machine = machine_name,
                payload_path = %payload_path,
                "nspawn payload cgroup not observed (container exited early or startup failed), \
                 skipping limits"
            );
            return Some(payload_result(&machine_name, &payload_path));
        }
    }

    if let Some(ref mem) = limits.memory_max {
        match parse_memory_max(mem) {
            Ok(bytes) => {
                // cgroupfs 写 "0" = 0 字节硬限（立即 OOM），产品口径 "0" = 不限制：
                // 直写把 0 翻译为 "max"，--property 路径在 argv.rs 同步译为 infinity。
                let value = if bytes == 0 {
                    "max".to_string()
                } else {
                    bytes.to_string()
                };
                // memory.max 失败不得静默跳过 swap.max 的尝试与告警。
                if let Err(e) =
                    write_cgroup_file(&format!("{}/memory.max", payload_path), &value).await
                {
                    log_limit_write_failure("memory.max", &payload_path, &e);
                }
                // swap.max=0 有意禁用 swap：内存压力应触发 OOM kill 而非拖慢宿主。
                if let Err(e) =
                    write_cgroup_file(&format!("{}/memory.swap.max", payload_path), "0").await
                {
                    log_limit_write_failure("memory.swap.max", &payload_path, &e);
                }
            }
            Err(e) => warn!(error = %e, "Failed to parse memory_max, skipping memory limit"),
        }
    }
    if let Some(ref cpu) = limits.cpu_quota {
        match parse_cpu_quota(cpu) {
            Ok((quota, period)) => {
                if let Err(e) = write_cgroup_file(
                    &format!("{}/cpu.max", payload_path),
                    &format!("{} {}", quota, period),
                )
                .await
                {
                    log_limit_write_failure("cpu.max", &payload_path, &e);
                }
            }
            Err(e) => warn!(error = %e, "Failed to parse cpu_quota, skipping CPU limit"),
        }
    }
    Some(payload_result(&machine_name, &payload_path))
}

/// limits 写失败日志：helper 模式常见根因是 priv-helper 过旧不支持
/// write-cgroup-file，静默失效无人察觉故升 error 带升级指引。
fn log_limit_write_failure(file: &'static str, payload_path: &str, e: &crate::error::CrbsError) {
    if crate::privilege::get_privilege_backend().is_helper() {
        error!(
            file = file,
            payload_path = payload_path,
            error = %e,
            "Failed to write cgroup limit via priv-helper; \
             resource limit NOT enforced. The deployed crbs-priv-helper may be too old \
             to support the 'write-cgroup-file' subcommand — upgrade crbs-priv-helper \
             to the matching version, or check helper deployment"
        );
    } else {
        warn!(
            file = file,
            payload_path = payload_path,
            error = %e,
            "Failed to write cgroup limit; resource limit NOT enforced"
        );
    }
}

/// 经特权后端写 cgroup 控制文件（自动追加换行，见 trait 文档）；helper 调用
/// 为 one-shot 子进程（可阻塞至 10s 超时），spawn_blocking 防阻塞 runtime。
async fn write_cgroup_file(path: &str, value: &str) -> crate::Result<()> {
    let backend = crate::privilege::get_privilege_backend();
    let owned_path = path.to_string();
    let owned_value = value.to_string();
    tokio::task::spawn_blocking(move || backend.write_cgroup_file(&owned_path, &owned_value))
        .await
        .map_err(|e| {
            crate::error::CrbsError::io_message(format!("spawn_blocking write_cgroup_file: {e}"))
        })?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 转义变换：`-` → \x2d 全量替换（与 helper validate::systemd_escape_dash
    /// 手抄同步的钉子，两测保持成对）。
    #[test]
    fn systemd_escape_dash_translates_dashes_only() {
        assert_eq!(systemd_escape_dash("crbs-9c714595"), "crbs\\x2d9c714595");
        assert_eq!(
            systemd_escape_dash("crbs-9c714595-1b03-4e5f-8d2a-abcdef012345"),
            "crbs\\x2d9c714595\\x2d1b03\\x2d4e5f\\x2d8d2a\\x2dabcdef012345"
        );
        assert_eq!(systemd_escape_dash("crbs-01234567"), "crbs\\x2d01234567");
    }

    /// 候选序列契约：探测根（v2 + v1 legacy）× 双命名 × 原样/转义全列入；
    /// 解析命中的主路径提到首位、其余候选不丢不重。
    #[test]
    fn payload_kill_candidates_primary_first_all_roots_and_namings_present() {
        let name = "crbs-00010203-42";
        let candidates = scope_path_candidates(name);
        assert_eq!(candidates.len(), 8, "2 roots x 4 naming forms");

        // v2 统一根在前，v1 legacy systemd 根在后；每根内新式原样/转义、
        // 旧式原样/转义四形态齐备（machined 实际注册名 = 旧式转义形态）。
        let escaped = systemd_escape_dash(name);
        let expect: Vec<String> = CGROUP_FS_ROOTS
            .iter()
            .flat_map(|root| {
                [
                    format!("{root}/machine.slice/{name}.scope"),
                    format!("{root}/machine.slice/{escaped}.scope"),
                    format!("{root}/machine.slice/machine-{name}.scope"),
                    format!("{root}/machine.slice/machine-{escaped}.scope"),
                ]
            })
            .collect();
        assert_eq!(candidates, expect);

        // 主路径 = v2 新式形态：提到首位，其余候选按序保留在后。
        let primary_new = format!("{}/payload", candidates[0]);
        let kill = payload_kill_candidates(name, &primary_new);
        assert_eq!(kill.first().unwrap(), &primary_new);
        assert_eq!(kill.len(), candidates.len(), "kill 不赌单形态，全候选保留");
        for c in &candidates {
            assert!(kill.contains(&format!("{c}/payload")), "missing {c}");
        }

        // 主路径 = v1 根下的旧式转义形态（v1 宿主实测形态，候选 [6]）：
        // 同样首位不重复。
        let primary_v1 = format!("{}/payload", candidates[6]);
        let kill = payload_kill_candidates(name, &primary_v1);
        assert_eq!(kill.first().unwrap(), &primary_v1);
        assert_eq!(kill.len(), candidates.len());
    }
}
