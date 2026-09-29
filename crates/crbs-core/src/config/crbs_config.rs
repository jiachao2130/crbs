// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 顶层引擎配置：crbs.toml 的字段、默认值与根路径派生。

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::config_path;
use crate::config::BoolOrPackages;
use crate::config::HooksConfig;
use crate::config::RemoteConfig;
use crate::error::CrbsError;

/// 全局配置（`/etc/crbs/crbs.toml`）：路径、构建用户、GC、tmpfs、运行时行为；
/// 所有产品共享，产品 TOML 可经 `Option` 字段覆盖任意项。
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrbsConfig {
    // root 分离：crbs_root 属引擎世界，默认 /var/lib/crbs-engine；
    // server 的 root 由 server.toml `ServerConfig::crbs_root` 决定（缺省 /var/lib/crbs）。
    #[serde(default = "crate::config::defaults::default_engine_crbs_root")]
    pub crbs_root: PathBuf,
    /// 构建结果目录；None 时由使用处按 `{crbs_root}/results` 派生（`result_dir_or_derived()`）。
    #[serde(default)]
    pub result_dir: Option<PathBuf>,
    /// 共享层存储目录；None 时按 `{crbs_root}/shared_layers` 派生（`shared_layers_dir_or_derived()`）。
    #[serde(default)]
    pub shared_layers_dir: Option<PathBuf>,

    /// 数据库连接 URL：SQLite `sqlite:///path/to/crbs.db`（默认 `{crbs_root}/crbs.db`）、
    /// PostgreSQL `postgres://user:pass@host/dbname`。含明文口令：Debug 经手写 impl 脱敏
    /// （密码段 → `***`）；`Serialize` 逐字不脱敏（落盘持久化走 `crbs remote add` 的 toml_edit）。
    #[serde(default)]
    pub database_url: Option<String>,
    #[serde(default)]
    pub product_root: Option<PathBuf>,
    #[serde(default)]
    pub base_os_path: Option<PathBuf>,
    #[serde(default)]
    pub dnf_cache_path: Option<PathBuf>,

    #[serde(default = "crate::config::defaults::default_builder_user")]
    pub builder_user: String,
    #[serde(default = "crate::config::defaults::default_builder_uid")]
    pub builder_uid: u32,
    #[serde(default = "crate::config::defaults::default_builder_group")]
    pub builder_group: String,
    #[serde(default = "crate::config::defaults::default_builder_gid")]
    pub builder_gid: u32,

    #[serde(default = "crate::config::defaults::default_shared_layer_gc_grace_hours")]
    pub shared_layer_gc_grace_hours: u64,
    #[serde(default = "crate::config::defaults::default_result_gc_grace_hours")]
    pub result_gc_grace_hours: u64,

    #[serde(default)]
    pub shared_layer: BoolOrPackages,

    #[serde(default)]
    pub build_tmpfs: bool,
    #[serde(default = "crate::config::defaults::default_tmpfs_dir")]
    pub tmpfs_dir: PathBuf,
    /// 构建临时目录；None 时由 merge_configs 按 `{crbs_root}/tmp` 派生。
    #[serde(default)]
    pub tmp_dir: Option<PathBuf>,

    /// CLI 本地构建并发上限（仅 `crbs build` 本地引擎生效，0 = num_cpus）；
    /// server 本地构建并发由 server.toml `max_local_builds` 控制，互不影响。
    #[serde(default)]
    pub max_concurrent_builds: usize,
    #[serde(default = "crate::config::defaults::default_shared_layer_poll_interval_ms")]
    pub shared_layer_poll_interval_ms: u64,
    #[serde(default = "crate::config::defaults::default_shared_layer_timeout_secs")]
    pub shared_layer_timeout_secs: u64,
    #[serde(default = "crate::config::defaults::default_shared_layer_max_retries")]
    pub shared_layer_max_retries: u32,
    #[serde(default)]
    pub shared_layer_staleness: Option<String>,
    #[serde(default = "crate::config::defaults::default_chain_parallelism")]
    pub chain_parallelism: usize,
    #[serde(default = "crate::config::defaults::default_chain_max_recovery_rounds")]
    pub chain_max_recovery_rounds: usize,

    #[serde(default = "crate::config::defaults::default_build_max_retries")]
    pub build_max_retries: u32,
    #[serde(default = "crate::config::defaults::default_build_retry_backoff_ms")]
    pub build_retry_backoff_ms: u64,

    #[serde(default)]
    pub package_cache_max_size_gb: Option<u64>,
    #[serde(default)]
    pub package_cache_evict_referenced: bool,
    #[serde(default)]
    pub result_max_count_per_pkg: Option<usize>,
    #[serde(default)]
    pub result_retention_days: Option<u64>,

    // URL 解析缓存 TTL（天），0 表示不清理
    #[serde(default = "crate::config::defaults::default_package_url_cache_ttl_days")]
    pub package_url_cache_ttl_days: u64,

    /// base 快照保留代数（按产品隔离，init 发布后代内裁剪），0 = 不清理。
    #[serde(default = "crate::config::defaults::default_base_snapshot_keep_generations")]
    pub base_snapshot_keep_generations: u32,

    // 是否为构建记录 provenance（URL、SHA256、build_packages.json），用于 reproduce
    // true = 全部记录，false = 不记录，["pkg1"] = 仅指定包记录
    #[serde(default = "crate::config::defaults::default_reproduce_enabled")]
    pub reproduce_enabled: BoolOrPackages,

    // RPM 宏。BTreeMap：key 排序迭代，序列化跨进程确定（同 ProductConfig.rpm_macros）。
    #[serde(default)]
    pub rpm_macros: BTreeMap<String, String>,

    #[serde(default)]
    pub ccache_enabled: BoolOrPackages,
    #[serde(default = "crate::config::defaults::default_ccache_dir")]
    pub ccache_dir: PathBuf,
    #[serde(default = "crate::config::defaults::default_ccache_max_size")]
    pub ccache_max_size: String,

    #[serde(default)]
    pub dnf_cache_enabled: bool,

    // dnf --releasever，未配置时尝试从宿主 /etc/os-release 推断
    #[serde(default)]
    pub releasever: Option<String>,

    // 包缓存（构建幂等性）
    #[serde(default)]
    pub package_cache_path: Option<PathBuf>,

    #[serde(default = "crate::config::defaults::default_build_target")]
    pub build_target: String,

    // 是否跳过 %check 阶段（全局默认值，产品可覆盖）
    #[serde(default)]
    pub nocheck: bool,

    // 是否跳过 distro 收尾清理段（%clean 与 rmbuild；全局默认值，产品可覆盖）
    #[serde(default)]
    pub noclean: bool,

    // 是否不生成 debuginfo 包（全局默认值，产品可覆盖）
    #[serde(default)]
    pub nodebuginfo: bool,

    #[serde(default)]
    pub gpg_signing_key_id: Option<String>,
    #[serde(default)]
    pub gpg_home: Option<String>,
    #[serde(default)]
    pub gpg_signing_enabled: Option<bool>,

    #[serde(default)]
    pub backend: Option<String>,

    // 资源限制（仅 nspawn backend 生效）
    #[serde(default)]
    pub memory_max: Option<String>,
    #[serde(default)]
    pub cpu_quota: Option<String>,

    // 网络控制（true = 共享宿主网络，false = 隔离）
    #[serde(default = "crate::config::defaults::default_network")]
    pub network: bool,

    // 构建资源采样间隔（秒），0 = 关闭；采样宿主侧只读，失败不影响构建（engine::resource_sample）。
    #[serde(default = "crate::config::defaults::default_resource_sample_interval_secs")]
    pub resource_sample_interval_secs: u64,

    // cgroup 口径采样间隔（秒，采样分级）：None = 5s 引擎常量、Some(0) = 关闭
    // cgroup 口径、Some(n) = n 秒。resource_sample_interval_secs 管 /proc 口径，
    // 任一键为 0 只关对应口径、互不牵连。
    #[serde(default)]
    pub resource_sample_interval_cgroup_secs: Option<u32>,

    // 构建脚本 hook 点（全局默认值，产品可覆盖）
    #[serde(default)]
    pub hooks: Option<HooksConfig>,

    // 客户端远程 server profiles（仅被 crbs CLI 读取，server 忽略）
    #[serde(default)]
    pub remote: RemoteConfig,

    #[serde(default)]
    pub use_privileged_helper: crate::privilege::PrivilegedHelperMode,
    #[serde(default)]
    pub privileged_helper_path: Option<PathBuf>,
}

/// Debug 展示用：DB 连接 URL userinfo 密码段替换为 `***`；无 userinfo 或无
/// 密码分量（`sqlite:///path`、`postgres://user@host`）原样返回。
fn redact_database_url_for_debug(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let auth_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(auth_len);
    // 口令可能含未编码 `@`：按最后一个 `@` 切分（宽解析，宁可多脱不可漏脱）。
    let Some((userinfo, host)) = authority.rsplit_once('@') else {
        return url.to_string();
    };
    let Some((user, _password)) = userinfo.split_once(':') else {
        return url.to_string();
    };
    format!("{scheme}://{user}:***@{host}{tail}")
}

/// `database_url` 含明文口令，Debug 一律脱敏密码段为 `***`（姿态同
/// `RemoteProfile::token`）：`{:?}` 进日志/panic 不得带出口令；remote token 自行脱敏。
impl fmt::Debug for CrbsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrbsConfig")
            .field("crbs_root", &self.crbs_root)
            .field("result_dir", &self.result_dir)
            .field("shared_layers_dir", &self.shared_layers_dir)
            .field(
                "database_url",
                &self
                    .database_url
                    .as_deref()
                    .map(redact_database_url_for_debug),
            )
            .field("product_root", &self.product_root)
            .field("base_os_path", &self.base_os_path)
            .field("dnf_cache_path", &self.dnf_cache_path)
            .field("builder_user", &self.builder_user)
            .field("builder_uid", &self.builder_uid)
            .field("builder_group", &self.builder_group)
            .field("builder_gid", &self.builder_gid)
            .field(
                "shared_layer_gc_grace_hours",
                &self.shared_layer_gc_grace_hours,
            )
            .field("result_gc_grace_hours", &self.result_gc_grace_hours)
            .field("shared_layer", &self.shared_layer)
            .field("build_tmpfs", &self.build_tmpfs)
            .field("tmpfs_dir", &self.tmpfs_dir)
            .field("tmp_dir", &self.tmp_dir)
            .field("max_concurrent_builds", &self.max_concurrent_builds)
            .field(
                "shared_layer_poll_interval_ms",
                &self.shared_layer_poll_interval_ms,
            )
            .field("shared_layer_timeout_secs", &self.shared_layer_timeout_secs)
            .field("shared_layer_max_retries", &self.shared_layer_max_retries)
            .field("shared_layer_staleness", &self.shared_layer_staleness)
            .field("chain_parallelism", &self.chain_parallelism)
            .field(
                "resource_sample_interval_secs",
                &self.resource_sample_interval_secs,
            )
            .field(
                "resource_sample_interval_cgroup_secs",
                &self.resource_sample_interval_cgroup_secs,
            )
            .field("chain_max_recovery_rounds", &self.chain_max_recovery_rounds)
            .field("build_max_retries", &self.build_max_retries)
            .field("build_retry_backoff_ms", &self.build_retry_backoff_ms)
            .field("package_cache_max_size_gb", &self.package_cache_max_size_gb)
            .field(
                "package_cache_evict_referenced",
                &self.package_cache_evict_referenced,
            )
            .field("result_max_count_per_pkg", &self.result_max_count_per_pkg)
            .field("result_retention_days", &self.result_retention_days)
            .field(
                "package_url_cache_ttl_days",
                &self.package_url_cache_ttl_days,
            )
            .field(
                "base_snapshot_keep_generations",
                &self.base_snapshot_keep_generations,
            )
            .field("reproduce_enabled", &self.reproduce_enabled)
            .field("rpm_macros", &self.rpm_macros)
            .field("ccache_enabled", &self.ccache_enabled)
            .field("ccache_dir", &self.ccache_dir)
            .field("ccache_max_size", &self.ccache_max_size)
            .field("dnf_cache_enabled", &self.dnf_cache_enabled)
            .field("releasever", &self.releasever)
            .field("package_cache_path", &self.package_cache_path)
            .field("build_target", &self.build_target)
            .field("nocheck", &self.nocheck)
            .field("noclean", &self.noclean)
            .field("nodebuginfo", &self.nodebuginfo)
            .field("gpg_signing_key_id", &self.gpg_signing_key_id)
            .field("gpg_home", &self.gpg_home)
            .field("gpg_signing_enabled", &self.gpg_signing_enabled)
            .field("backend", &self.backend)
            .field("memory_max", &self.memory_max)
            .field("cpu_quota", &self.cpu_quota)
            .field("network", &self.network)
            .field("hooks", &self.hooks)
            .field("remote", &self.remote)
            .field("use_privileged_helper", &self.use_privileged_helper)
            .field("privileged_helper_path", &self.privileged_helper_path)
            .finish()
    }
}

impl CrbsConfig {
    /// 结果目录：显式配置优先，未配置时按 `{crbs_root}/results` 派生。
    pub fn result_dir_or_derived(&self) -> PathBuf {
        self.result_dir
            .clone()
            .unwrap_or_else(|| self.crbs_root.join("results"))
    }

    /// 共享层目录：显式配置优先，未配置时按 `{crbs_root}/shared_layers` 派生。
    pub fn shared_layers_dir_or_derived(&self) -> PathBuf {
        self.shared_layers_dir
            .clone()
            .unwrap_or_else(|| self.crbs_root.join("shared_layers"))
    }

    /// 构建临时目录：显式配置优先，未配置时按 `{crbs_root}/tmp` 派生。
    pub fn tmp_dir_or_derived(&self) -> PathBuf {
        self.tmp_dir
            .clone()
            .unwrap_or_else(|| self.crbs_root.join("tmp"))
    }

    /// 固定 crbs_root（server / worker 构造引擎配置用），并清空显式
    /// result_dir / shared_layers_dir 使其随 pin 后的 root 派生——crbs.toml 的
    /// crbs_root 属引擎世界，不 pin 则状态/结果路径漂到引擎 root。
    /// note：privilege backend 在 `CrbsConfig::load` 内初始化（早于 pin），
    /// --crbs-root 可能取引擎 root；priv-helper 允许集「∈ server ∪ 引擎 root」均合法。
    pub fn pinned_to_root(mut self, root: &std::path::Path) -> Self {
        self.crbs_root = root.to_path_buf();
        self.result_dir = None;
        self.shared_layers_dir = None;
        self
    }

    /// 读取全局配置：优先 `CRBS_CONFIG_DIR` 目录下的 `crbs.toml`，未设置用
    /// `/etc/crbs/crbs.toml`；文件不存在返回默认值。
    pub fn load() -> crate::Result<Self> {
        Self::load_blocking()
    }

    /// 异步版本：在 `spawn_blocking` 中完成文件 IO 与解析。
    pub async fn load_async() -> crate::Result<Self> {
        tokio::task::spawn_blocking(Self::load_blocking)
            .await
            .map_err(|e| CrbsError::io_message(format!("load crbs config: {}", e)))?
    }

    /// 读取系统配置并合并用户级 `~/.config/crbs/crbs.toml`（存在时）：仅 `remote`
    /// 段合并（系统 profile 为底，同名被用户覆盖）；`remote.default` 未配置或为
    /// `"local"` 时本地直接构建。server 端用 `load_async()`，勿读个人 home 配置。
    pub async fn load_merged_async() -> crate::Result<Self> {
        tokio::task::spawn_blocking(Self::load_merged_blocking)
            .await
            .map_err(|e| CrbsError::io_message(format!("load merged crbs config: {}", e)))?
    }

    fn load_merged_blocking() -> crate::Result<Self> {
        let mut cfg = Self::load_from(&config_path("crbs.toml")?)?;
        if let Some(user_path) = Self::user_config_path() {
            if user_path.exists() {
                let user_cfg = Self::load_from(&user_path)?;
                warn_ignored_user_keys(&user_path);
                cfg.remote.merge(user_cfg.remote);
            }
        }
        Ok(cfg)
    }

    fn load_blocking() -> crate::Result<Self> {
        Self::load_from(&config_path("crbs.toml")?)
    }

    /// 从指定路径读取全局配置，文件不存在时返回默认值。
    pub(crate) fn load_from(path: &Path) -> crate::Result<Self> {
        // 仅 NotFound 走默认值；exists() 预检会吞掉 stat 错误（父目录 EACCES 等）、静默降级。
        let mut cfg = match std::fs::read_to_string(path) {
            Ok(content) => {
                let cfg: CrbsConfig =
                    toml::from_str(&content).map_err(|e| CrbsError::ValidationFailed {
                        message: format!("parse crbs config {}: {}", path.display(), e),
                    })?;
                cfg
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(CrbsError::from_io_context("read crbs config", e)),
        };

        cfg.crbs_root =
            crate::config::validation::validate_config_path(&cfg.crbs_root, "crbs_root")?;

        // u64 时间参数上界：gc 路径直接用全局 CrbsConfig（不走 merge_configs 校验），
        // ≥ 2^63 经 SQL `as i64` 回绕成负数，"N 天前"变未来时刻，retention/ttl GC 匹配所有行。
        crate::config::validation::require_i64_representable_u64(
            "shared_layer_gc_grace_hours",
            cfg.shared_layer_gc_grace_hours,
        )?;
        crate::config::validation::require_i64_representable_u64(
            "result_gc_grace_hours",
            cfg.result_gc_grace_hours,
        )?;
        if let Some(v) = cfg.result_retention_days {
            crate::config::validation::require_i64_representable_u64("result_retention_days", v)?;
        }
        crate::config::validation::require_i64_representable_u64(
            "package_url_cache_ttl_days",
            cfg.package_url_cache_ttl_days,
        )?;

        // 全局 rpm_macros（键名 / dist 值白名单）与产品宏同一校验
        // （chain_resolve 出口）；坏条目在文件加载期即拒（经 merge_configs 注入构建）。
        for (key, value) in &cfg.rpm_macros {
            if let Err(e) = crate::build_options::validate_rpm_macro_entry(key, value) {
                return Err(CrbsError::ValidationFailed {
                    message: format!("crbs config {} rpm_macros: {}", path.display(), e),
                });
            }
        }

        // 初始化特权后端。幂等：若已初始化则跳过。
        crate::privilege::init_privilege_backend(
            cfg.use_privileged_helper,
            cfg.privileged_helper_path.as_deref(),
            &cfg.crbs_root,
        )?;

        Ok(cfg)
    }

    fn user_config_path() -> Option<PathBuf> {
        home::home_dir().map(|home| home.join(".config").join("crbs").join("crbs.toml"))
    }
}

/// 用户级配置只合并 `[remote]` 段，其余顶层键静默不生效——此处 warn 列出键名
/// （这些键只在全局 crbs.toml / 产品 TOML 生效）。"已设值" = 文件中出现的顶层键
/// （键集差集 remote 段，不逐字段聚合 Option；deny_unknown_fields 已保证合法）。
/// 二次读取仅作诊断：读/解析失败 debug! 后跳过，不影响合并主路径。
fn warn_ignored_user_keys(path: &Path) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(
                path = %path.display(),
                error = %e,
                "user config re-read for ignored-key diagnostic failed"
            );
            return;
        }
    };
    let table = match content.parse::<toml::Value>() {
        Ok(toml::Value::Table(t)) => t,
        Err(e) => {
            tracing::debug!(
                path = %path.display(),
                error = %e,
                "user config re-read parse failed; skipping ignored-key diagnostic"
            );
            return;
        }
        Ok(_) => {
            tracing::debug!(
                path = %path.display(),
                "user config re-read is not a table; skipping ignored-key diagnostic"
            );
            return;
        }
    };
    let ignored: Vec<&str> = table
        .keys()
        .filter(|k| k.as_str() != "remote")
        .map(|k| k.as_str())
        .collect();
    if !ignored.is_empty() {
        tracing::warn!(
            path = %path.display(),
            keys = ?ignored,
            "user config only merges [remote]; these keys are ignored here — \
             set them in the global crbs.toml or the product TOML"
        );
    }
}

impl Default for CrbsConfig {
    fn default() -> Self {
        // 空 TOML 反序列化即默认值：所有字段都有 `#[serde(default)]`（单一事实源
        // 在 defaults:: 模块），避免手工实现双份漂移。LazyLock 缓存解析：Default
        // 无法返回 Err，漏标必填字段时 panic 仅首次取默认值触发一次、指向此处。
        static DEFAULTS: std::sync::LazyLock<CrbsConfig> = std::sync::LazyLock::new(|| {
            // expect 白名单：空 TOML 必为全默认值（见上）——文档化不变量断言，非运行时风险。
            #[allow(clippy::expect_used)]
            toml::from_str("").expect(
                "empty toml deserializes to CrbsConfig defaults; \
                 if this panics, a new required field is missing #[serde(default)]",
            )
        });
        DEFAULTS.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::with_capture;
    use tempfile::TempDir;

    /// 非 remote 顶层键（builder_user）→ warn 列键名与路径；仅 [remote] 不告警。
    #[test]
    fn warn_ignored_user_keys_lists_non_remote_keys() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("crbs.toml");

        std::fs::write(
            &path,
            "builder_user = \"someone\"\n\n[remote]\ndefault = \"hub\"\n",
        )
        .unwrap();
        let out = with_capture(|| warn_ignored_user_keys(&path));
        assert!(out.contains("builder_user"), "captured: {out}");
        let path_display = path.display().to_string();
        assert!(out.contains(&path_display), "captured: {out}");
        assert!(out.contains("WARN"), "captured: {out}");

        std::fs::write(&path, "[remote]\ndefault = \"hub\"\n").unwrap();
        let out = with_capture(|| warn_ignored_user_keys(&path));
        assert!(
            out.is_empty(),
            "remote-only user config must not warn: {out}"
        );
    }

    /// database_url 明文口令不进 Debug 输出（密码段 → `***`）；无密码 / 无
    /// userinfo / sqlite 原样保留，未编码 `@` 按最后一个切分（宁可多脱不可漏脱）。
    #[test]
    fn crbs_config_debug_redacts_database_url_password() {
        let cfg = CrbsConfig {
            database_url: Some("postgres://crbs:s3cret@db.example.com:5432/crbs".to_string()),
            ..CrbsConfig::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(
            dbg.contains("postgres://crbs:***@db.example.com:5432/crbs"),
            "redacted form missing: {dbg}"
        );
        assert!(!dbg.contains("s3cret"), "password must not leak: {dbg}");

        assert_eq!(
            redact_database_url_for_debug("postgres://crbs@db.example.com/crbs"),
            "postgres://crbs@db.example.com/crbs",
            "no password component: nothing to redact"
        );
        assert_eq!(
            redact_database_url_for_debug("sqlite:///var/lib/crbs/crbs.db"),
            "sqlite:///var/lib/crbs/crbs.db",
            "sqlite path has no userinfo: unchanged"
        );
        assert_eq!(
            redact_database_url_for_debug("postgres://u:p@ss@host/db"),
            "postgres://u:***@host/db",
            "unencoded @ in password: split authority at the last @"
        );
    }

    /// 手写 Debug 字段漂移守护：serde 序列化的每个顶层字段名必须出现在 Debug
    /// 输出；顶层无 `skip_serializing_if`（键集即字段全集），漏更手写 impl 在此失败。
    #[test]
    fn crbs_config_debug_covers_all_serialized_fields() {
        let cfg = CrbsConfig::default();
        let json = serde_json::to_value(&cfg).expect("serialize default");
        let field_names: Vec<&str> = json
            .as_object()
            .expect("CrbsConfig serializes to a JSON object")
            .keys()
            .map(|k| k.as_str())
            .collect();
        assert!(!field_names.is_empty());
        let dbg = format!("{cfg:?}");
        for name in field_names {
            assert!(
                dbg.contains(name),
                "field {name} missing from Debug output: {dbg}"
            );
        }
    }
}
