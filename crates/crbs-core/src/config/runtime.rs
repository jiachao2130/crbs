// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 引擎运行时配置：由全局配置与产品配置合并后的路径与构建参数。

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::BoolOrPackages;
use crate::config::Hooks;
use crate::config::PostInitCommand;
use crate::config::RepoConfig;

/// 合并后的运行时配置（BuildEngine 使用）：`CrbsConfig` + `ProductConfig` 合并而成。
/// 运行时控制字段（`max_concurrent_builds` 等）由 BuildEngine 内部管理，不在此处。
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub product: String,

    pub crbs_root: PathBuf,
    pub result_dir: PathBuf,
    pub shared_layers_dir: PathBuf,
    pub product_root: PathBuf,
    pub base_os_path: PathBuf,
    pub dnf_cache_path: PathBuf,
    pub builder_user: String,
    pub builder_uid: u32,
    pub builder_group: String,
    pub builder_gid: u32,
    pub shared_layer_gc_grace_hours: u64,
    pub result_gc_grace_hours: u64,
    pub shared_layer: BoolOrPackages,
    pub shared_layer_staleness: Option<std::time::Duration>,
    pub build_tmpfs: bool,
    pub tmpfs_dir: PathBuf,
    pub tmp_dir: PathBuf,
    pub gpg_signing_key_id: Option<String>,
    pub gpg_home: Option<String>,
    pub gpg_signing_enabled: Option<bool>,

    // 产品特有
    pub base_packages: Vec<String>,
    pub repos: Vec<RepoConfig>,
    /// 产品声明的架构列表（可选）；CLI `resolve_local_arch` 无 `--arches` 时据此提示，免再读盘。
    pub arches: Vec<String>,
    pub releasever: Option<String>,
    pub overlay_dir: Option<PathBuf>,
    pub post_init: Vec<PostInitCommand>,

    /// BTreeMap：key 排序迭代，JSON 输出与宏注入跨进程确定。
    pub rpm_macros: BTreeMap<String, String>,

    pub ccache_enabled: BoolOrPackages,
    pub ccache_dir: PathBuf,
    pub ccache_max_size: String,

    pub dnf_cache_enabled: bool,

    /// `dnf builddep` weak deps 开关（产品级，无全局字段）：None = dnf 默认（装 weak deps）；
    /// Some(false) 追加 `--setopt=install_weak_deps=False`，仅作用 builddep 装包路径，base_os init 不读。
    pub builddep_install_weak_deps: Option<bool>,

    // 包缓存（构建幂等性）
    pub package_cache_path: PathBuf,

    // rpmbuild 目标阶段
    pub build_target: String,

    // 是否跳过 %check 阶段
    pub nocheck: bool,

    // 是否跳过 distro 收尾清理段（%clean 与 rmbuild）
    pub noclean: bool,

    // 是否不生成 debuginfo 包
    pub nodebuginfo: bool,

    pub backend: String,

    // 资源限制（仅 nspawn backend 生效；chroot 下被忽略）
    pub memory_max: Option<String>,
    pub cpu_quota: Option<String>,

    // 网络控制（true = 共享宿主网络，false = 隔离）
    pub network: bool,

    // chain 构建
    pub local_repo: Option<PathBuf>,
    pub chain_parallelism: usize,
    /// chain 恢复轮上限（0 = 禁用恢复）。
    pub chain_max_recovery_rounds: usize,

    // 构建资源采样间隔（秒），0 = 关闭（全局默认 15）
    pub resource_sample_interval_secs: u64,

    /// cgroup 口径采样间隔（秒，采样分级）：None = 5s 引擎常量、Some(0) = 关闭
    /// cgroup 口径、Some(n) = n 秒。与 `resource_sample_interval_secs` 互不牵连。
    pub resource_sample_interval_cgroup_secs: Option<u32>,

    // 构建 transient 失败自动重试
    pub build_max_retries: u32,
    pub build_retry_backoff_ms: u64,

    pub package_cache_max_size_gb: Option<u64>,
    pub package_cache_evict_referenced: bool,
    pub result_max_count_per_pkg: Option<usize>,
    pub result_retention_days: Option<u64>,

    // URL 解析缓存 TTL（天），0 表示不清理
    pub package_url_cache_ttl_days: u64,

    /// base 快照保留代数（{crbs_root}/base-snapshots/{product}/，init 发布后代内
    /// 裁剪），0 = 不清理。
    pub base_snapshot_keep_generations: u32,

    // 是否记录 provenance 用于 reproduce
    pub reproduce_enabled: BoolOrPackages,

    /// 确定性构建模式（产品级开关）：true 时注入确定性宏组 / env 基线 /
    /// hostname 钉死 / ccache 守卫，并强制溯源落盘 + 完整性硬门。
    pub deterministic: bool,
    pub mtime_normalize: bool,

    /// `_buildhost` 宏的生效值：产品级 `_buildhost` 配置 > 固定 "crbs"。
    pub buildhost: String,

    pub hooks: Hooks,
}

impl Config {
    /// base OS 层路径（merge_configs 已解析的最终值：配置 > 默认 `{product_root}/base`）。
    pub fn base_os_path(&self) -> PathBuf {
        self.base_os_path.clone()
    }

    /// 产品根目录（merge_configs 已解析的最终值：配置 > 默认 `{crbs_root}/{product}`）。
    pub fn product_root(&self) -> PathBuf {
        self.product_root.clone()
    }

    /// local repo 路径：配置 > 默认 `{crbs_root}/repo/{product}/`。
    pub fn local_repo_path(&self) -> PathBuf {
        self.local_repo
            .clone()
            .unwrap_or_else(|| self.crbs_root.join("repo").join(&self.product))
    }

    /// dnf 缓存目录（merge_configs 已解析的最终值：配置 > 默认 `{product_root}/dnf-cache`）。
    pub fn dnf_cache_path(&self) -> PathBuf {
        self.dnf_cache_path.clone()
    }

    /// 实际用于 `dnf --releasever` 的值：配置 > 宿主 `/etc/os-release` 推断。
    pub fn effective_releasever(&self) -> crate::Result<String> {
        if let Some(ref v) = self.releasever {
            return Ok(v.clone());
        }
        detect_host_releasever().ok_or_else(|| crate::error::CrbsError::ValidationFailed {
            message: "releasever is not configured and could not be detected from /etc/os-release"
                .into(),
        })
    }
}

/// 从宿主 `/etc/os-release` 读取 `VERSION_ID` 作为 releasever 回退。
pub(crate) fn detect_host_releasever() -> Option<String> {
    let content = std::fs::read_to_string("/etc/os-release").ok()?;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("VERSION_ID=") {
            let v = v.trim().trim_matches('"').trim_matches('\'');
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// 产品配置详情（`crbs products show` 与 server API 响应）：只暴露合并后的有效
/// 配置，不区分全局默认与产品覆盖。`id` / `parent_id` / `parent_name` 是产品图
/// 元数据，来自 `ProductRecord` 而非 `Config`，`From<Config>` 无法填充，由
/// server handler 经 `with_graph_meta(...)` 附加；离线 CLI（TOML 构造）为 `None`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductDetail {
    pub product: String,
    pub crbs_root: PathBuf,
    pub result_dir: PathBuf,
    pub base_packages: Vec<String>,
    pub repos: Vec<RepoConfig>,
    /// BTreeMap：key 排序迭代，API JSON / CLI show / UI 渲染顺序跨进程确定。
    pub rpm_macros: BTreeMap<String, String>,
    pub backend: String,
    pub network: bool,
    pub build_target: String,
    pub shared_layer: BoolOrPackages,
    pub build_tmpfs: bool,
    pub ccache_enabled: BoolOrPackages,
    pub memory_max: Option<String>,
    pub cpu_quota: Option<String>,
    pub hooks: Hooks,
    /// 产品在 hub DB 的 numeric id；`None` = 离线/未知，server handler 从 `ProductRecord` 拉出。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    /// 产品继承 parent 的 id；`None` = 根产品或未知（离线上下文）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<i64>,
    /// parent 的 `name`（CLI/UI 直接展示，免回查 hub）；`None` = 根产品或 parent 已删（FK 下不该发生）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_name: Option<String>,
    /// 当前产品配置 revision（hub DB 字段）。离线上下文为 0。
    #[serde(default)]
    pub revision: i64,
}

impl ProductDetail {
    /// 链式写入产品图元数据（hub DB numeric id / parent id / parent 名称）；
    /// 离线或未知场景传 `None`。
    pub fn with_graph_meta(
        mut self,
        id: Option<i64>,
        parent_id: Option<i64>,
        parent_name: Option<String>,
    ) -> Self {
        self.id = id;
        self.parent_id = parent_id;
        self.parent_name = parent_name;
        self
    }

    /// 链式写入产品配置 revision（hub DB 字段）；离线上下文传 0。
    pub fn with_revision(mut self, revision: i64) -> Self {
        self.revision = revision;
        self
    }
}

impl From<Config> for ProductDetail {
    fn from(cfg: Config) -> Self {
        Self {
            product: cfg.product,
            crbs_root: cfg.crbs_root,
            result_dir: cfg.result_dir,
            base_packages: cfg.base_packages,
            repos: cfg.repos,
            rpm_macros: cfg.rpm_macros,
            backend: cfg.backend,
            network: cfg.network,
            build_target: cfg.build_target,
            shared_layer: cfg.shared_layer,
            build_tmpfs: cfg.build_tmpfs,
            ccache_enabled: cfg.ccache_enabled,
            memory_max: cfg.memory_max,
            cpu_quota: cfg.cpu_quota,
            hooks: cfg.hooks,
            id: None,
            parent_id: None,
            parent_name: None,
            revision: 0,
        }
    }
}
