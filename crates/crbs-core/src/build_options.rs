// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建运行时选项（BuildOptions）与 BuildEngine 选项应用：请求选项的反序列化、
//! 校验与逐项应用（本地 Server 与分布式 Worker 共用）。

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::config::BoolOrPackages;
use crate::engine::backend::ResourceLimits;
use crate::engine::BuildEngine;
use crate::error::CrbsError;
use crate::types::BuildPriority;

/// 从请求解析出的构建运行时选项（本地 Server enqueue / Worker 任务下发接收）。
/// 所有字段可选，逐项覆盖默认值。
#[derive(Clone, Default, serde::Serialize, serde::Deserialize, Debug)]
pub struct BuildOptions {
    pub stage: Option<String>,
    pub shared_layer: Option<bool>,
    pub tmpfs: Option<bool>,
    pub ccache: Option<bool>,
    pub timeout: Option<u64>,
    pub nocheck: Option<bool>,
    pub noclean: Option<bool>,
    pub nodebuginfo: Option<bool>,
    pub target: Option<String>,
    pub dist: Option<String>,
    pub backend: Option<String>,
    pub no_network: Option<bool>,
    /// 发布轴逐构建收紧：`true` = 本次构建产物不发布进产品 repo（Koji
    /// `--scratch` 式）。省略/`false` = 发布（默认）。无放宽形态；server 侧
    /// 在提交时把生效值快照进 `builds.repo_publish`。
    pub no_publish: Option<bool>,
    /// 消费轴逐构建收紧：`true` = 本次构建不消费产品 repo（派发不注入
    /// crbs-product.repo）。省略/`false` = 跟随产品配置（默认消费）。无放宽
    /// 形态；生效值在提交时与产品可见性、产品 `repo-consume` 合流快照进
    /// `builds.repo_consume`。
    #[serde(default)]
    pub no_consume: bool,
    pub memory_max: Option<String>,
    pub cpu_quota: Option<String>,
    /// 放置契约下限——最低内存（人类单位：`K/M/G/T` 1024 基，`'4G'` = 4 GiB；
    /// 纯数字 = KB），fan_out 物化进 `builds.req_min_mem_kb`，扇出子构建继承。
    /// 声明期望节点档位（鼓励按满并行峰值声明），不改变本机构建行为；
    /// 上界 1 TiB。
    pub min_mem: Option<String>,
    /// 放置契约下限——最低磁盘（单位语法同 `min_mem`），物化进
    /// `builds.req_min_disk_kb`；上界 64 TiB。
    pub min_disk: Option<String>,
    /// 放置契约下限——最低 CPU 核数（裸数字），物化进 `builds.req_min_ncpu`；
    /// 上界 1024。不做 memory_max → min_mem 自动换算（cap 是"最多许用"
    /// 不是"需要"）。
    pub min_ncpu: Option<u32>,
    #[serde(default)]
    pub define: Vec<String>,
    #[serde(default)]
    pub with_features: Vec<String>,
    #[serde(default)]
    pub without_features: Vec<String>,
    pub retry: Option<u32>,
    pub no_reproduce: Option<bool>,
    /// reproduce 模式标记：指定要复现的来源构建 ID。仅 reproduce 路径设置
    ///（普通构建 `None`），随 `request_json` 流转；worker 据此进入 reproduce 模式，
    /// 并经 `AssignedTask.reproduce_packages_url` 下载来源 build 的 `build_packages.json`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reproduce_from_build_id: Option<i64>,
    /// repro-from-srpm 模式标记：从 SRPM 头探测 `BUILDHOST`/`BUILDTIME` 注入构建。
    /// 旗标只驱动提交侧（探测 + 模式 note + canonical sha256 锚），引擎执行语义只认
    /// `replay_build_host`/`replay_build_time` 两值——"值而无旗标"= 显式参数注入，
    /// 合法；旗标走 task 级 request_json（先于探测序列化）、值只走 build 级（rebuild
    /// 复用旗标重新探测，值幂等）。
    #[serde(default)]
    pub repro_from_srpm: bool,
    /// SRPM 头 `BUILDHOST` 原样回放值；`None` = 头缺失（`(none)`）或未探测，不注入。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_build_host: Option<String>,
    /// SRPM 头 `BUILDTIME`（epoch 秒）回放值，作为容器内 `SOURCE_DATE_EPOCH`
    /// 与宏组 epoch 来源；`0` 照注（不降级不拒绝）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_build_time: Option<i64>,
    pub priority: Option<BuildPriority>,
    pub arch: Option<String>,
    /// 多架构构建时的架构列表（仅用于解析阶段，写入 DB 时拆分）。
    #[serde(skip)]
    pub arch_list: Vec<String>,
    /// 显式 `arch_list` 提交遇 spec 架构约束（SRPM 头 ExclusiveArch/ExcludeArch
    /// 评估值）不兼容时，跳过不兼容架构而非拒绝整个提交。默认 false（拒绝）。
    /// 仅影响显式架构请求；产品默认 fan-out 与批次路径本就按跳过处理。
    /// JSON 入口经 BuildRequest 的 serde flatten 从顶层键读入；multipart 表单
    /// 有同名字段臂（multipart.rs）。
    #[serde(default, skip_serializing_if = "crate::types::is_false")]
    pub skip_unsupported_arches: bool,
}

/// 校验后端名称。
pub fn validate_backend_name(name: &str) -> crate::Result<()> {
    if !matches!(name, "chroot" | "nspawn") {
        return Err(CrbsError::ValidationFailed {
            message: format!("backend must be 'chroot' or 'nspawn', got: {}", name),
        });
    }
    Ok(())
}

/// `--define` 拒绝的保留宏键：布局强制 `_topdir=/builddir`（CLI 宏最后叠加会盖掉
/// 强制值），覆盖只会把产物写出布局外、收成零产物的 succeeded 构建。
const RESERVED_MACRO_KEYS: [&str; 1] = ["_topdir"];

/// 解析 `KEY=VALUE` 格式的 RPM 宏列表（全部 define 入口单过本函数）。键名过
/// `validate_rpm_macro_key`（[a-zA-Z0-9_]+）：宏键拼进 `rpmbuild --define`，
/// 空格/`%` 等字符会破坏 define 解析或注入宏语言；保留键 `_topdir` 与空 VALUE
/// 均拒绝（fail-closed）。条目过 [`validate_rpm_macro_entry`] 共享咽喉——`dist`
/// 键值与 `--dist` 同白名单（防 cli_macros 最高优先级覆盖已过白名单的 `--dist`）；
/// 其余键 VALUE 不过滤。
pub fn parse_macros(define: &[String]) -> crate::Result<BTreeMap<String, String>> {
    let mut macros = BTreeMap::new();
    for d in define {
        let pos = d.find('=').ok_or_else(|| CrbsError::ValidationFailed {
            message: format!("define must be in KEY=VALUE format, got: {}", d),
        })?;
        if pos == 0 {
            return Err(CrbsError::ValidationFailed {
                message: format!("define KEY must not be empty, got: {}", d),
            });
        }
        let key = &d[..pos];
        crate::validation::validate_rpm_macro_key(key)?;
        if RESERVED_MACRO_KEYS.contains(&key) {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "define KEY {} is reserved (forced to /builddir by the build layout), got: {}",
                    key, d
                ),
            });
        }
        let value = &d[pos + 1..];
        if value.is_empty() {
            return Err(CrbsError::ValidationFailed {
                message: format!("define VALUE for '{}' must not be empty, got: {}", key, d),
            });
        }
        validate_rpm_macro_entry(key, value)?;
        macros.insert(key.to_string(), value.to_string());
    }
    Ok(macros)
}

/// 校验条件构建特性：feature 名拼成宏键（`with_<feature>`/`without_<feature>`）进
/// `--define`，过 `[a-zA-Z0-9_]` 白名单（`a.b`、含空格等在此拒绝而非执行期破坏
/// define 解析）；同一特性不得同时出现在 with/without。返回去重后的 `(with, without)` 列表。
pub fn validate_features(
    with: &[String],
    without: &[String],
) -> crate::Result<(Vec<String>, Vec<String>)> {
    for feature in with.iter().chain(without.iter()) {
        if let Err(e) = crate::validation::validate_rpm_macro_key(feature) {
            return Err(CrbsError::ValidationFailed {
                message: format!("invalid build feature '{}': {}", feature, e),
            });
        }
    }
    let with_set: BTreeSet<_> = with.iter().collect();
    let without_set: BTreeSet<_> = without.iter().collect();
    if let Some(conflict) = with_set.intersection(&without_set).next() {
        return Err(CrbsError::ValidationFailed {
            message: format!("conflicting with/without for feature: {}", conflict),
        });
    }
    Ok((
        with_set.into_iter().cloned().collect(),
        without_set.into_iter().cloned().collect(),
    ))
}

/// 校验 rpmbuild 构建阶段（bb=二进制包, bs=源码包, ba=两者）；
/// 与 `BuildEngine::with_build_stage` 共用同一校验。
pub fn validate_build_stage(stage: &str) -> crate::Result<()> {
    if !matches!(stage, "bb" | "bs" | "ba") {
        return Err(CrbsError::ValidationFailed {
            message: format!("build_stage must be bb, bs or ba, got: {}", stage),
        });
    }
    Ok(())
}

/// 提交入口允许的最大 `retry` 值：multipart 按 u32 解析（可到 42 亿），无界值
/// 会让引擎近乎无限重试，提交阶段统一封顶。
pub const MAX_SUBMIT_RETRIES: u32 = 10;

/// 放置契约下限上界：mem ≤ 1 TiB、disk ≤ 64 TiB、ncpu ≤ 1024。
/// 防 KB/单位笔误把调度硬下限抬到集群无人可满足；真实需求高于上界属集群
/// 档位问题，不该靠声明绕过。KB 常量 = TiB × 1024³。
pub const MAX_REQ_MIN_MEM_KB: i64 = 1024 * 1024 * 1024;
/// 磁盘下限上界（64 TiB），与内存上界同受单位笔误防线约束。
pub const MAX_REQ_MIN_DISK_KB: i64 = 64 * 1024 * 1024 * 1024;
/// CPU 下限上界（1024 核）。
pub const MAX_REQ_MIN_NCPU: u32 = 1024;

/// 放置契约下限的 KB 物化值（fan_out 落 `builds.req_min_*` 与 submit 响应
/// 回显共用同一解析结果，两端不分叉）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReqMinKb {
    pub mem: Option<i64>,
    pub ncpu: Option<i64>,
    pub disk: Option<i64>,
}

impl ReqMinKb {
    /// 解析 BuildOptions 三下限 → KB（ncpu 原样）。无声明 → 全 None。
    /// 解析/上界校验与 `validate_options` 同规则（重放路径 request_json 反
    /// 序列化不经过提交期 validate_options，此处兜同一口径）。
    pub fn from_options(opts: &BuildOptions) -> crate::Result<Self> {
        validate_req_min_mins(opts)?;
        Ok(Self {
            mem: opts
                .min_mem
                .as_deref()
                .map(|s| crate::config::parse_resource_min_kb("min_mem", s))
                .transpose()?,
            ncpu: opts.min_ncpu.map(i64::from),
            disk: opts
                .min_disk
                .as_deref()
                .map(|s| crate::config::parse_resource_min_kb("min_disk", s))
                .transpose()?,
        })
    }

    /// 三维全空（任务未声明任何下限）。
    pub fn is_none(&self) -> bool {
        self.mem.is_none() && self.ncpu.is_none() && self.disk.is_none()
    }
}

/// 放置契约下限的提交期校验：单位语法与正值在 [`crate::config::parse_resource_min_kb`]，
/// 字段级上界在此收口（mem/disk 各自上限、ncpu 1..=1024）。
fn validate_req_min_mins(opts: &BuildOptions) -> crate::Result<()> {
    if let Some(ref s) = opts.min_mem {
        let kb = crate::config::parse_resource_min_kb("min_mem", s)?;
        if kb > MAX_REQ_MIN_MEM_KB {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "min_mem '{s}' exceeds the {} TiB upper limit",
                    MAX_REQ_MIN_MEM_KB / (1024 * 1024 * 1024)
                ),
            });
        }
    }
    if let Some(ref s) = opts.min_disk {
        let kb = crate::config::parse_resource_min_kb("min_disk", s)?;
        if kb > MAX_REQ_MIN_DISK_KB {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "min_disk '{s}' exceeds the {} TiB upper limit",
                    MAX_REQ_MIN_DISK_KB / (1024 * 1024 * 1024)
                ),
            });
        }
    }
    if let Some(n) = opts.min_ncpu {
        if n == 0 || n > MAX_REQ_MIN_NCPU {
            return Err(CrbsError::ValidationFailed {
                message: format!("min_ncpu must be 1..={MAX_REQ_MIN_NCPU}, got: {n}"),
            });
        }
    }
    Ok(())
}

/// 提交入口的早期选项校验：把执行期才失败的错误提前到 HTTP 请求阶段
///（backend/memory/cpu/stage/dist 字符集/features/define/retry 上限）；执行期
///（`build_engine_from_options` / `apply_options_to_engine`）仍各自校验，不取代。
pub fn validate_options(opts: &BuildOptions) -> crate::Result<()> {
    if let Some(b) = &opts.backend {
        validate_backend_name(b)?;
    }
    if let Some(ref m) = opts.memory_max {
        crate::config::validate_memory_max(m)?;
    }
    if let Some(ref c) = opts.cpu_quota {
        crate::config::validate_cpu_quota(c)?;
    }
    validate_req_min_mins(opts)?;
    if let Some(s) = &opts.stage {
        validate_build_stage(s)?;
    }
    if let Some(d) = &opts.dist {
        validate_dist_tag(d)?;
    }
    validate_features(&opts.with_features, &opts.without_features)?;
    parse_macros(&opts.define)?;
    if let Some(r) = opts.retry {
        if r > MAX_SUBMIT_RETRIES {
            return Err(CrbsError::ValidationFailed {
                message: format!("retry must be at most {}, got: {}", MAX_SUBMIT_RETRIES, r),
            });
        }
    }
    Ok(())
}

/// 校验 dist 标签：非空，字符集只允许 [a-zA-Z0-9._-]。dist 提交者可控，拼进
/// `rpmbuild --define 'dist .fc44'` 并参与 release 后缀比对——`/` 产非法
/// release 文件名（构建期才失败）、`%` 属宏注入同族面、空白/控制符破坏
/// define 解析，故提交期收口；常见 dist tag（`.fc44`、`.el9`…）均在字符集内。
pub fn validate_dist_tag(tag: &str) -> crate::Result<()> {
    if tag.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: "dist tag cannot be empty".to_string(),
        });
    }
    if !tag
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "dist tag '{}' contains invalid characters. Only [a-zA-Z0-9._-] are allowed",
                tag
            ),
        });
    }
    Ok(())
}

/// 规范化 dist 标签：先过 [`validate_dist_tag`] 字符集校验（非法值
/// `ValidationFailed`），再确保以 `.` 开头。
pub fn normalize_dist(dist: Option<String>) -> crate::Result<Option<String>> {
    dist.map(|tag| {
        validate_dist_tag(&tag)?;
        Ok(if tag.starts_with('.') {
            tag
        } else {
            format!(".{tag}")
        })
    })
    .transpose()
}

/// `rpm_macros` 配置与 `--define` 条目的单条 `(key, value)` 共享校验咽喉：键名过
/// [`crate::validation::validate_rpm_macro_key`]；`dist` 键值过 [`validate_dist_tag`]
/// 同白名单——config 侧 `dist` 与 CLI `--dist` 在 `merge_build_macros` 中同格合并
/// 进 `--define 'dist ...'`，提交期字符集校验面不得被 config 定义绕过；其余键
/// VALUE 不过滤（渲染经 shell_quote 单引号包裹）。
pub fn validate_rpm_macro_entry(key: &str, value: &str) -> crate::Result<()> {
    crate::validation::validate_rpm_macro_key(key)?;
    if key == "dist" {
        validate_dist_tag(value)?;
    }
    Ok(())
}

/// reproduce 引擎构造的选项收口：`backend` / `memory_max` / `cpu_quota` 置空——
/// 复现不读请求级执行环境，容器 backend 与资源限制走与正常构建相同的解析链
///（`create_backend` ← `config.backend` 全局→产品→默认），/proc 挂载语义与源
/// 构建同态。`no_network` 保留（沙箱网络密闭语义仍随请求）；其余选项由
/// `apply_options_to_engine` 照常消费。
pub fn engine_options_for_reproduce_construction(opts: &BuildOptions) -> BuildOptions {
    BuildOptions {
        backend: None,
        memory_max: None,
        cpu_quota: None,
        ..opts.clone()
    }
}

/// 根据 `BuildOptions` 创建 `BuildEngine`：校验并应用 backend、memory_max、
/// cpu_quota、no_network 等构造参数。`product_config` 为产品配置 TOML（hub 下发
/// 或 server 从 DB chain-resolve）；`None` = 读本地配置文件（仅 CLI 引擎世界合法），
/// server/worker 路径禁止磁盘回退，worker 空 config 必须 fail-closed 拒绝。
/// `crbs_root` 为引擎 root pin（server/worker 各传自身 root）；`None` = 不 pin
///（CLI 引擎世界，crbs.toml 的 crbs_root 即引擎 root）。
pub async fn build_engine_from_options(
    product: &str,
    opts: &BuildOptions,
    state_store: Arc<crate::state::StateStore>,
    product_config: Option<&str>,
    crbs_root: Option<&std::path::Path>,
) -> crate::Result<BuildEngine> {
    if let Some(b) = &opts.backend {
        validate_backend_name(b)?;
    }
    if let Some(ref m) = opts.memory_max {
        crate::config::validate_memory_max(m)?;
    }
    if let Some(ref c) = opts.cpu_quota {
        crate::config::validate_cpu_quota(c)?;
    }

    let limits = ResourceLimits {
        memory_max: opts.memory_max.clone(),
        cpu_quota: opts.cpu_quota.clone(),
    };
    let network = opts.no_network.map(|n| !n);

    BuildEngine::new_with_state_and_config_root(
        product,
        opts.backend.as_deref(),
        Some(limits),
        network,
        state_store,
        product_config,
        crbs_root,
    )
    .await
}

/// 构建超时兜底（纯函数）：`None` → `Some(default_secs)`（`default_secs=0` 配置
/// 关兜底 → `None` 不限时）；`Some(0)` → `None` 显式无限（"--timeout 0 =
/// unlimited" 已钉语义，不得被兜底覆盖）；`Some(t)` → 透传。`default_secs` 取
/// 调用方配置键（worker.toml / server.toml 的 `build_timeout_secs`）：timeout=None
/// 时引擎无超时，hang 构建永久占 building 行 + 并发槽（进程存活使回收机制全部跳过）。
pub fn effective_build_timeout(requested: Option<u64>, default_secs: u64) -> Option<u64> {
    match requested {
        None => (default_secs > 0).then_some(default_secs),
        Some(0) => None,
        Some(t) => Some(t),
    }
}

/// 将 `BuildOptions` 中除构造参数外的选项逐项应用到已创建的 `BuildEngine`。
pub fn apply_options_to_engine(
    mut engine: BuildEngine,
    opts: &BuildOptions,
) -> crate::Result<BuildEngine> {
    if let Some(true) = opts.shared_layer {
        engine = engine.enable_shared_layer();
    } else if let Some(false) = opts.shared_layer {
        engine = engine.with_shared_layer_disabled();
    }

    if let Some(enabled) = opts.tmpfs {
        engine = engine.with_tmpfs(enabled);
    }

    if let Some(true) = opts.ccache {
        engine = engine.enable_ccache();
    } else if let Some(false) = opts.ccache {
        engine = engine.with_ccache_disabled();
    }

    if let Some(t) = opts.timeout {
        let duration = if t > 0 {
            Some(std::time::Duration::from_secs(t))
        } else {
            None
        };
        engine = engine.with_timeout(duration);
    }

    if let Some(enabled) = opts.nocheck {
        engine = engine.with_nocheck(enabled);
    }
    if let Some(enabled) = opts.noclean {
        engine = engine.with_noclean(enabled);
    }
    if let Some(enabled) = opts.nodebuginfo {
        engine = engine.with_nodebuginfo(enabled);
    }

    if let Some(priority) = opts.priority {
        engine = engine.with_priority(priority);
    }

    engine = engine
        .with_target_arch(opts.target.clone())
        .with_dist(normalize_dist(opts.dist.clone())?)
        .with_terminal_tx(None);

    let (with_features, without_features) =
        validate_features(&opts.with_features, &opts.without_features)?;
    engine = engine
        .with_with_features(with_features)
        .with_without_features(without_features);

    if !opts.define.is_empty() {
        engine = engine.with_cli_macros(parse_macros(&opts.define)?);
    }

    if let Some(retry) = opts.retry {
        engine = engine.with_build_max_retries(retry);
    }

    if let Some(true) = opts.no_reproduce {
        engine = engine.with_reproduce_enabled(BoolOrPackages::Bool(false));
    }

    if let Some(ref host) = opts.replay_build_host {
        engine = engine.with_replay_build_host(host.clone());
    }
    if let Some(t) = opts.replay_build_time {
        engine = engine.with_replay_build_time(t);
    }

    if let Some(ref s) = opts.stage {
        engine = engine.with_build_stage(s.clone())?;
    }

    Ok(engine)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_backend_name_accepts_known_backends() {
        assert!(validate_backend_name("chroot").is_ok());
        assert!(validate_backend_name("nspawn").is_ok());
        assert!(validate_backend_name("docker").is_err());
    }

    /// reproduce 引擎构造收口：backend / memory_max / cpu_quota 剥离（解析链归
    /// config.backend），no_network 与其余选项原样保留。
    #[test]
    fn engine_options_for_reproduce_construction_strips_execution_env() {
        let opts: BuildOptions = serde_json::from_str(
            r#"{"backend": "nspawn", "memory_max": "1G", "cpu_quota": "200%",
                "no_network": true, "nocheck": true, "dist": "fc44"}"#,
        )
        .unwrap();
        let stripped = engine_options_for_reproduce_construction(&opts);
        assert!(
            stripped.backend.is_none(),
            "backend must resolve via config chain"
        );
        assert!(stripped.memory_max.is_none() && stripped.cpu_quota.is_none());
        assert_eq!(stripped.no_network, Some(true), "no_network must survive");
        assert_eq!(stripped.nocheck, Some(true));
        assert_eq!(stripped.dist.as_deref(), Some("fc44"));
    }

    #[test]
    fn parse_macros_accepts_valid_key_value() {
        let macros = parse_macros(&["A=1".into(), "_smp_mflags=-j8".into()]).unwrap();
        assert_eq!(macros.get("A"), Some(&"1".to_string()));
        assert_eq!(macros.get("_smp_mflags"), Some(&"-j8".to_string()));
    }

    #[test]
    fn parse_macros_rejects_missing_equals() {
        assert!(parse_macros(&["NOEQUALS".into()]).is_err());
    }

    #[test]
    fn parse_macros_rejects_empty_key() {
        let err = parse_macros(&["=VALUE".into()]).unwrap_err();
        match err {
            CrbsError::ValidationFailed { message } => {
                assert!(message.contains("empty"), "got: {}", message)
            }
            other => panic!("expected ValidationFailed, got: {:?}", other),
        }
    }

    /// `_topdir` 布局强制 /builddir，CLI 覆盖只会收零产物 succeeded 构建——提交期拒绝。
    #[test]
    fn parse_macros_rejects_reserved_topdir() {
        let err = parse_macros(&["_topdir=/x".into()]).unwrap_err();
        match err {
            CrbsError::ValidationFailed { message } => {
                assert!(message.contains("_topdir is reserved"), "got: {}", message);
            }
            other => panic!("expected ValidationFailed, got: {:?}", other),
        }
    }

    /// `k=` 空宏体拒绝：rpm 侧报 "empty body" 族错误，提交期给可读信息。
    #[test]
    fn parse_macros_rejects_empty_value() {
        let err = parse_macros(&["k=".into()]).unwrap_err();
        match err {
            CrbsError::ValidationFailed { message } => {
                assert!(message.contains("must not be empty"), "got: {}", message);
            }
            other => panic!("expected ValidationFailed, got: {:?}", other),
        }
    }

    /// 含空格/`%`/`-`/`.` 的 KEY 拒绝；`_smp_mflags=-j8` 下划线键仍过。
    #[test]
    fn parse_macros_rejects_invalid_key_chars() {
        for bad in ["BAD KEY=1", "%_topdir=/x", "foo-bar=1", "a.b=1"] {
            let err = parse_macros(&[bad.into()]).unwrap_err();
            assert!(
                matches!(err, CrbsError::ValidationFailed { ref message } if message
                    .contains("invalid characters")),
                "key {:?} should be rejected: {:?}",
                bad,
                err
            );
        }
    }

    #[test]
    fn validate_features_detects_conflict() {
        assert!(validate_features(&["foo".into()], &["foo".into()]).is_err());
    }

    #[test]
    fn validate_features_allows_disjoint() {
        let (with, without) = validate_features(&["foo".into()], &["bar".into()]).unwrap();
        assert_eq!(with, vec!["foo"]);
        assert_eq!(without, vec!["bar"]);
    }

    #[test]
    fn validate_features_returns_deduped_lists() {
        let (with, without) =
            validate_features(&["foo".into(), "bar".into(), "foo".into()], &["baz".into()])
                .unwrap();
        assert_eq!(with, vec!["bar".to_string(), "foo".to_string()]);
        assert_eq!(without, vec!["baz".to_string()]);
    }

    /// feature 名拼成宏键进 `--define`，非 `[a-zA-Z0-9_]` 字符会破坏 define
    /// 解析——validate 阶段拒绝，错误文案点名 feature。
    #[test]
    fn validate_features_rejects_non_macro_key_charset() {
        let err = validate_features(&["a.b".into()], &[]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("a.b"), "error must name the feature: {msg}");
        assert!(
            msg.contains("invalid characters") || msg.contains("macro key"),
            "error must point at charset: {msg}"
        );
        assert!(validate_features(&[], &["with space".into()]).is_err());
    }

    /// 常规 feature 名（含下划线）不受字符集收口影响。
    #[test]
    fn validate_features_accepts_macro_safe_names() {
        validate_features(&["debug".into()], &["_underscore_name".into()]).unwrap();
    }

    #[test]
    fn validate_options_rejects_bad_backend_memory_quota_and_stage() {
        for field_json in [
            r#"{"backend": "docker"}"#,
            r#"{"memory_max": "4X"}"#,
            r#"{"cpu_quota": "abc"}"#,
            r#"{"stage": "xx"}"#,
        ] {
            let opts: BuildOptions = serde_json::from_str(field_json).unwrap();
            assert!(
                validate_options(&opts).is_err(),
                "should reject {}",
                field_json
            );
        }
        let ok: BuildOptions = serde_json::from_str(
            r#"{"backend": "nspawn", "memory_max": "4G", "cpu_quota": "200%", "stage": "bb"}"#,
        )
        .unwrap();
        assert!(validate_options(&ok).is_ok());
    }

    #[test]
    fn validate_options_rejects_retry_above_cap() {
        let ok: BuildOptions =
            serde_json::from_str(&format!(r#"{{"retry": {}}}"#, MAX_SUBMIT_RETRIES)).unwrap();
        assert!(validate_options(&ok).is_ok());

        let bad: BuildOptions =
            serde_json::from_str(&format!(r#"{{"retry": {}}}"#, MAX_SUBMIT_RETRIES + 1)).unwrap();
        let err = validate_options(&bad).unwrap_err();
        match err {
            CrbsError::ValidationFailed { message } => {
                assert!(
                    message.contains(&format!("at most {}", MAX_SUBMIT_RETRIES)),
                    "got: {}",
                    message
                )
            }
            other => panic!("expected ValidationFailed, got: {:?}", other),
        }
    }

    #[test]
    fn validate_options_rejects_bad_define_and_conflicting_features() {
        let bad_define: BuildOptions = serde_json::from_str(r#"{"define": ["=V"]}"#).unwrap();
        assert!(validate_options(&bad_define).is_err());

        let bad_features: BuildOptions =
            serde_json::from_str(r#"{"with_features": ["foo"], "without_features": ["foo"]}"#)
                .unwrap();
        assert!(validate_options(&bad_features).is_err());
    }

    #[test]
    fn normalize_dist_adds_leading_dot() {
        assert_eq!(
            normalize_dist(Some("fc44".into())).unwrap(),
            Some(".fc44".into())
        );
        assert_eq!(
            normalize_dist(Some(".fc44".into())).unwrap(),
            Some(".fc44".into())
        );
        assert_eq!(normalize_dist(None).unwrap(), None);
    }

    /// dist 字符集收紧：`/` 产非法 release 文件名、`%` 属宏注入同族面，提交期拒绝。
    #[test]
    fn normalize_dist_rejects_invalid_charset_and_empty() {
        for bad in ["fc/44", "%{dist}", "fc 44", "fc\n44", "", "标签"] {
            let err = normalize_dist(Some(bad.into())).unwrap_err();
            assert!(
                matches!(&err, CrbsError::ValidationFailed { message } if message.contains(bad)),
                "dist {bad:?} must be rejected with the tag named: {err:?}"
            );
        }
        assert_eq!(normalize_dist(None).unwrap(), None);
    }

    /// 常见发行版 dist tag 均在白名单内，前导点归一语义保留。
    #[test]
    fn normalize_dist_accepts_common_dist_tags() {
        for (raw, want) in [
            ("fc44", ".fc44"),
            (".el9", ".el9"),
            (".oe2203sp4", ".oe2203sp4"),
            ("el9_aarch64", ".el9_aarch64"),
        ] {
            assert_eq!(
                normalize_dist(Some(raw.into())).unwrap(),
                Some(want.to_string())
            );
        }
    }

    /// validate_options 覆盖 dist——提交入口（HTTP 阶段）拒绝，不等构建期。
    #[test]
    fn validate_options_rejects_invalid_dist() {
        let bad: BuildOptions = serde_json::from_str(r#"{"dist": "fc/44"}"#).unwrap();
        let err = validate_options(&bad).unwrap_err();
        assert!(
            matches!(&err, CrbsError::ValidationFailed { message } if message.contains("fc/44")),
            "got: {err:?}"
        );

        let ok: BuildOptions = serde_json::from_str(r#"{"dist": ".fc44"}"#).unwrap();
        assert!(validate_options(&ok).is_ok());
    }

    /// 放置契约下限：合法组合过校验，上界逐字段收口（mem 1TiB / disk 64TiB /
    /// ncpu 1024），坏单位与 0 值拒绝且错误点名字段。
    #[test]
    fn validate_options_rejects_bad_req_mins_and_bounds() {
        let ok: BuildOptions =
            serde_json::from_str(r#"{"min_mem": "4G", "min_disk": "2T", "min_ncpu": 8}"#).unwrap();
        assert!(validate_options(&ok).is_ok());

        let mem_over: BuildOptions =
            serde_json::from_str(r#"{"min_mem": "1T", "min_ncpu": 1}"#).unwrap();
        assert_eq!(
            ReqMinKb::from_options(&mem_over).unwrap().mem,
            Some(MAX_REQ_MIN_MEM_KB)
        );
        let mem_too_big: BuildOptions =
            serde_json::from_str(&format!(r#"{{"min_mem": "{}"}}"#, MAX_REQ_MIN_MEM_KB + 1))
                .unwrap();
        let err = validate_options(&mem_too_big).unwrap_err();
        assert!(
            matches!(&err, CrbsError::ValidationFailed { message } if message.contains("min_mem")),
            "got: {err:?}"
        );

        let disk_too_big: BuildOptions =
            serde_json::from_str(&format!(r#"{{"min_disk": "{}"}}"#, MAX_REQ_MIN_DISK_KB + 1))
                .unwrap();
        let err = validate_options(&disk_too_big).unwrap_err();
        assert!(
            matches!(&err, CrbsError::ValidationFailed { message } if message.contains("min_disk")),
            "got: {err:?}"
        );

        for bad_ncpu in [0u32, MAX_REQ_MIN_NCPU + 1] {
            let bad: BuildOptions =
                serde_json::from_str(&format!(r#"{{"min_ncpu": {bad_ncpu}}}"#)).unwrap();
            let err = validate_options(&bad).unwrap_err();
            assert!(
                matches!(&err, CrbsError::ValidationFailed { message } if message.contains("min_ncpu")),
                "got: {err:?}"
            );
        }

        let bad_unit: BuildOptions = serde_json::from_str(r#"{"min_mem": "4Gi"}"#).unwrap();
        let err = validate_options(&bad_unit).unwrap_err();
        assert!(
            matches!(&err, CrbsError::ValidationFailed { message } if message.contains("min_mem")),
            "got: {err:?}"
        );
    }

    /// ReqMinKb 物化解析：KB 落列口径、全 None 形态、is_none 判定；
    /// 上界合法值（=上界）通过。
    #[test]
    fn req_min_kb_from_options_matrix() {
        let none = ReqMinKb::from_options(&BuildOptions::default()).unwrap();
        assert!(none.is_none());
        assert_eq!(none, ReqMinKb::default());

        let some = ReqMinKb::from_options(
            &serde_json::from_str::<BuildOptions>(
                r#"{"min_mem": "512M", "min_disk": "1048576", "min_ncpu": 4}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(some.mem, Some(512 * 1024));
        assert_eq!(some.disk, Some(1024 * 1024));
        assert_eq!(some.ncpu, Some(4));
        assert!(!some.is_none());
    }

    /// serde 往返：三字段随 request_json 流转（rebuild/reproduce 反序列化
    /// 重放免费），缺键落 None（旧 request_json 兼容）。
    #[test]
    fn build_options_req_mins_serde_roundtrip() {
        let opts: BuildOptions =
            serde_json::from_str(r#"{"min_mem": "4G", "min_disk": "2T", "min_ncpu": 16}"#).unwrap();
        assert_eq!(opts.min_mem.as_deref(), Some("4G"));
        assert_eq!(opts.min_disk.as_deref(), Some("2T"));
        assert_eq!(opts.min_ncpu, Some(16));
        let json = serde_json::to_string(&opts).unwrap();
        let back: BuildOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(back.min_mem, opts.min_mem);
        assert_eq!(back.min_disk, opts.min_disk);
        assert_eq!(back.min_ncpu, opts.min_ncpu);

        let legacy: BuildOptions = serde_json::from_str("{}").unwrap();
        assert!(legacy.min_mem.is_none());
        assert!(legacy.min_disk.is_none());
        assert!(legacy.min_ncpu.is_none());
    }

    /// rpm_macros 的 dist 值纳入 validate_dist_tag 同白名单——config
    /// 定义 `%dist` 不得绕过 CLI --dist 的提交期校验面；其余键值维持透传。
    #[test]
    fn validate_rpm_macro_entry_dist_value_shares_dist_whitelist() {
        assert!(validate_rpm_macro_entry("dist", ".fc44").is_ok());
        assert!(validate_rpm_macro_entry("_smp_mflags", "-j8").is_ok());
        for bad in ["fc/44", "%{dist}", "fc 44", ""] {
            let err = validate_rpm_macro_entry("dist", bad).unwrap_err();
            assert!(
                matches!(&err, CrbsError::ValidationFailed { message } if message.contains("dist tag")),
                "dist={bad:?} must be rejected by the shared whitelist: {err:?}"
            );
        }
        assert!(validate_rpm_macro_entry("bad key", "1").is_err());
        // 非 dist 键不受 dist 白名单约束。
        assert!(validate_rpm_macro_entry("vendor", "%{dist}").is_ok());
    }

    /// `--define 'dist=...'` 值过 dist 白名单（与 `--dist` 同口径）——防
    /// cli_macros 最高优先级覆盖已过白名单的 --dist。
    #[test]
    fn parse_macros_rejects_invalid_dist_value() {
        // 合法 dist 值照常通过（charset 校验不要求前导点）。
        assert!(parse_macros(&["dist=.fc44".to_string()]).is_ok());
        assert!(parse_macros(&["dist=el9_awesome".to_string()]).is_ok());
        for bad in ["fc 44", ".fc/44", ".fc%41", ".fc${x}"] {
            let err = parse_macros(&[format!("dist={bad}")]).unwrap_err();
            assert!(
                matches!(&err, CrbsError::ValidationFailed { message } if message.contains("dist tag")),
                "define dist={bad:?} must be rejected by the shared whitelist: {err:?}"
            );
        }
        assert!(parse_macros(&["vendor=Fedora Project".to_string()]).is_ok());
    }

    /// 决策表：None→配置默认（0=关兜底→不限时）、Some(0)→显式无限、Some(t)→透传。
    #[test]
    fn effective_build_timeout_decision_table() {
        assert_eq!(effective_build_timeout(None, 86_400), Some(86_400));
        assert_eq!(effective_build_timeout(None, 3600), Some(3600));
        assert_eq!(effective_build_timeout(None, 0), None);
        assert_eq!(effective_build_timeout(Some(0), 86_400), None);
        assert_eq!(effective_build_timeout(Some(0), 0), None);
        assert_eq!(effective_build_timeout(Some(60), 86_400), Some(60));
        assert_eq!(effective_build_timeout(Some(1), 0), Some(1));
    }

    #[test]
    fn build_options_defaults_to_empty() {
        let opts: BuildOptions = serde_json::from_str("{}").unwrap();
        assert!(opts.backend.is_none());
        assert!(opts.memory_max.is_none());
        assert!(opts.define.is_empty());
        // repro-from-srpm：旧 request_json 缺字段兼容（flag=false、值=None）。
        assert!(!opts.repro_from_srpm);
        assert_eq!(opts.replay_build_host, None);
        assert_eq!(opts.replay_build_time, None);
    }

    /// repro-from-srpm 字段反序列化：旗标 + 值齐备、BUILDTIME=0 照收（不降级）。
    #[test]
    fn build_options_deserializes_replay_fields() {
        let opts: BuildOptions = serde_json::from_str(
            r#"{"repro_from_srpm": true, "replay_build_host": "probehost",
                "replay_build_time": 0}"#,
        )
        .unwrap();
        assert!(opts.repro_from_srpm);
        assert_eq!(opts.replay_build_host.as_deref(), Some("probehost"));
        assert_eq!(opts.replay_build_time, Some(0));
    }

    #[test]
    fn build_options_deserializes_all_fields() {
        let json = r#"{
            "stage": "bb",
            "backend": "nspawn",
            "no_network": true,
            "memory_max": "2G",
            "cpu_quota": "50%",
            "nocheck": true,
            "define": ["A=1"],
            "with_features": ["foo"],
            "retry": 3,
            "priority": 1,
            "no_publish": true
        }"#;
        let opts: BuildOptions = serde_json::from_str(json).unwrap();
        assert_eq!(opts.stage, Some("bb".to_string()));
        assert_eq!(opts.backend, Some("nspawn".to_string()));
        assert_eq!(opts.no_network, Some(true));
        assert_eq!(opts.memory_max, Some("2G".to_string()));
        assert_eq!(opts.cpu_quota, Some("50%".to_string()));
        assert_eq!(opts.nocheck, Some(true));
        assert_eq!(opts.define, vec!["A=1"]);
        assert_eq!(opts.with_features, vec!["foo"]);
        assert_eq!(opts.retry, Some(3));
        assert_eq!(opts.priority, Some(1));
        assert_eq!(opts.no_publish, Some(true));
        assert!(!opts.no_consume);
    }

    /// 双轴收紧旗标反序列化：`no_consume` 缺省 false（旧 request_json 兼容）、
    /// 显式 true 如实接收；旧键 `no_repo` 不再识别（静默忽略，生效值以
    /// `builds.repo_publish` 列快照为准）。
    #[test]
    fn build_options_deserializes_consume_flag_with_default() {
        let opts: BuildOptions = serde_json::from_str(r#"{"no_consume": true}"#).unwrap();
        assert!(opts.no_consume);
        assert_eq!(opts.no_publish, None);

        let legacy: BuildOptions = serde_json::from_str(r#"{"no_repo": true}"#).unwrap();
        assert_eq!(legacy.no_publish, None, "legacy key must be ignored");
    }
}
