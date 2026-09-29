// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You can obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! nspawn 命令行组装：机器名、容器参数与 shell/执行两种形态。

use std::path::Path;

use crate::engine::backend::{BindMount, ResourceLimits, SpawnOptions};
use crate::error::CrbsError;

/// RPM 构建与 nspawn 管理的最小 capability 集（收敛自 `--capability=all`）。
/// 逐项：chown 构建目录；dac_override/fowner 写改非 root 属主文件、dnf 绕过
/// 文件权限；setuid/setgid sudo 切用户；sys_admin mount/umount（overlayfs）；
/// sys_chroot 构建脚本 chroot；setpcap 供 --as-pid2 调容器进程 caps；
/// audit_control nspawn reset audit login UID；audit_write 容器内 sudo 写
/// audit 日志；setfcap 供 dnf installroot 设文件 caps（如 shadow 的 newgidmap）。
const MINIMAL_CAPS: &str =
    "cap_chown,cap_dac_override,cap_fowner,cap_setuid,cap_setgid,cap_sys_admin,cap_sys_chroot,\
     cap_setpcap,cap_audit_control,cap_audit_write,cap_setfcap";

/// 构造 `--machine=` 名称：rootfs 路径哈希前缀 + 可选后缀（build_id）。
/// 后缀白名单 `[A-Za-z0-9_.-]` 且拒绝任何 `..`（含单独出现）：该值直接拼进
/// machine 名与 cgroup 路径，分隔符/穿越片段必须 fail-fast。
pub fn machine_name_for(rootfs: &Path, suffix: Option<&str>) -> crate::Result<String> {
    let hash = blake3::hash(rootfs.to_string_lossy().as_bytes());
    let prefix = u32::from_be_bytes(hash.as_bytes()[..4].try_into().unwrap_or([0; 4]));
    match suffix {
        Some(s) if !s.is_empty() => {
            if s.contains("..")
                || !s
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
            {
                return Err(CrbsError::ValidationFailed {
                    message: format!(
                        "invalid machine_name_suffix {:?}: only [A-Za-z0-9_.-] allowed, \
                         '..' rejected (path separators and traversal must not reach the \
                         machine name / cgroup path)",
                        s
                    ),
                });
            }
            Ok(format!("crbs-{:08x}-{}", prefix, s))
        }
        _ => Ok(format!("crbs-{:08x}", prefix)),
    }
}

/// 构造 nspawn spawn() 的 argv（纯函数，便于单元测试）。
///
/// 不含 `--keep-unit`；**不传 `--register=no`**：注册 machined（`--register`
/// 默认 `auto`）才会为容器建独立 transient scope（`machine.slice/{name}.scope`，
/// 旧 systemd 为 `machine-{name}.scope`），实测新 systemd 下 `--register=no`
/// scope 根本不创建，容器进程落回 crbs 自身 session cgroup，资源采样与 cgroup
/// 限制/kill 全部失效。三种特权模式均以 root 运行 nspawn，注册必成功；`auto`
/// 下注册失败被 systemd 忽略（如 systemd-less 宿主），降级为无 scope，等待
/// 逻辑按超时降级不放大失败。
///
/// cgroup 差异：v1 `--property=` 直接在 scope 级别生效；v2 仅作用于 scope、
/// payload 不继承，另由 `cgroup::setup_payload_cgroup()` 从 host 侧写 payload cgroup。
///
/// bind 路径含 `:` 返回错误（`--bind=HOST:CONTAINER` 无转义，见 `push_bind_args`）。
pub fn build_spawn_argv(
    rootfs: &Path,
    command: &[&str],
    opts: &SpawnOptions,
    limits: &ResourceLimits,
) -> crate::Result<Vec<String>> {
    let machine_name = machine_name_for(rootfs, opts.machine_name_suffix.as_deref())?;
    let mut argv = vec![
        "systemd-nspawn".to_string(),
        format!("--directory={}", rootfs.display()),
        format!("--machine={}", machine_name),
        "--as-pid2".to_string(),
        "--quiet".to_string(),
        format!("--capability={}", MINIMAL_CAPS),
        "--console=pipe".to_string(),
    ];

    if !opts.network {
        argv.push("--private-network".to_string());
    }

    // hostname 钉死：`--hostname` 消除容器内 `uname -n` 落 nspawn 默认（machine
    // name = rootfs 随机 tempdir 路径哈希）。值由 phase::decide_container_hostname
    // 决策（det 钉 crbs-build；非 det 源构建钉 worker 主机名；非 det 回放钉源
    // 构建内核主机名），合法性由 phase::hostname_value_valid 前置（priv-helper
    // 侧同口径再校验）。
    if let Some(ref hostname) = opts.hostname {
        argv.push(format!("--hostname={}", hostname));
    }

    if let Some(ref mem) = limits.memory_max {
        // "0" 产品口径 = 不限制；systemd 对 MemoryMax=0 解释随版本/层级有分歧
        //（cgroupfs 语义 0 字节硬限），统一译为 infinity（cgroup.rs 直写路径译 "max"）。
        let value = if mem == "0" { "infinity" } else { mem.as_str() };
        argv.push(format!("--property=MemoryMax={value}"));
        // MemoryLimit= 用于 cgroup v1 兼容（systemd 自动翻译）
        argv.push(format!("--property=MemoryLimit={value}"));
    }
    if let Some(ref cpu) = limits.cpu_quota {
        // cgroup v1 需要百分比格式；"2" → "200%"，"200%" 保持不变
        let normalized = if cpu.ends_with('%') {
            cpu.clone()
        } else if let Ok(cores) = cpu.parse::<u64>() {
            let pct = cores
                .checked_mul(100)
                .ok_or_else(|| CrbsError::ValidationFailed {
                    message: format!("cpu_quota '{}' overflows when normalized to percent", cpu),
                })?;
            format!("{}%", pct)
        } else {
            // 未识别格式入口 fail-fast：透传会把坏值交给 systemd 运行期才失败或被静默接受。
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "unrecognized cpu_quota format '{}': expected '<cores>' or '<percent>%%'",
                    cpu
                ),
            });
        };
        argv.push(format!("--property=CPUQuota={}", normalized));
    }

    for (k, v) in &opts.env {
        argv.push(format!("--setenv={}={}", k, v));
    }
    push_bind_args(&mut argv, &opts.binds)?;
    argv.push("--".to_string());
    argv.extend(command.iter().map(|s| s.to_string()));
    Ok(argv)
}

/// 构造 nspawn shell() 的 argv（纯函数，便于单元测试）。
///
/// 保留 `--keep-unit`（无需 scope，资源限制不适用于交互式 shell）；`--register=no`
/// 仅在此保留：配合 --keep-unit 明确不做 machined 注册、不动 unit 分配
///（spawn 路径已去掉该开关，见 `build_spawn_argv`）。
pub fn build_shell_argv(
    rootfs: &Path,
    command: Option<&str>,
    opts: &SpawnOptions,
) -> crate::Result<Vec<String>> {
    // --console=interactive + --as-pid2 + --user 在 systemd 255 上触发 SIGKILL。
    // 需要 --user 时降级到 --console=pipe 规避。
    let console_flag = if opts.user.is_some() {
        "--console=pipe"
    } else {
        "--console=interactive"
    };

    let machine_name = machine_name_for(rootfs, opts.machine_name_suffix.as_deref())?;

    let mut argv = vec![
        "systemd-nspawn".to_string(),
        format!("--directory={}", rootfs.display()),
        format!("--machine={}", machine_name),
        "--as-pid2".to_string(),
        "--register=no".to_string(),
        "--keep-unit".to_string(),
        "--quiet".to_string(),
        format!("--capability={}", MINIMAL_CAPS),
        console_flag.to_string(),
    ];

    if !opts.network {
        argv.push("--private-network".to_string());
    }

    if let Some(ref user) = opts.user {
        argv.push(format!("--user={}", user));
    }

    for (k, v) in &opts.env {
        argv.push(format!("--setenv={}={}", k, v));
    }
    // host 侧挂载对 nspawn 独立 mount namespace 不可见，bind 必须走参数（与 spawn 共用校验）。
    push_bind_args(&mut argv, &opts.binds)?;

    argv.push("--".to_string());

    if let Some(cmd_str) = command {
        argv.push("/bin/bash".to_string());
        argv.push("-c".to_string());
        argv.push(cmd_str.to_string());
    } else {
        argv.push("/bin/bash".to_string());
    }

    Ok(argv)
}

/// 追加 `--bind=` / `--bind-ro=` 参数（spawn 与 shell 共用）。路径含 `:` 报错：
/// 按 `:` 分隔无转义，错切分段导致 misbind；与 CLI `--bind` 规格一致（见 `bind.rs`）。
fn push_bind_args(argv: &mut Vec<String>, binds: &[BindMount]) -> crate::Result<()> {
    for b in binds {
        if b.host.contains(':') || b.container.contains(':') {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "nspawn --bind path must not contain ':' (no escaping): {}:{}",
                    b.host, b.container
                ),
            });
        }
        let flag = if b.read_only { "--bind-ro" } else { "--bind" };
        argv.push(format!("{}={}:{}", flag, b.host, b.container));
    }
    Ok(())
}
