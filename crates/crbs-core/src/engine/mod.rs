// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建引擎：`BuildEngine` 持有合并配置、状态库与容器后端，驱动
//! prepare → init → build → report 的产品构建全生命周期。

#![warn(missing_docs)]

use std::path::{Path, PathBuf};

use crate::config::{Config, CrbsConfig, LogSanitizationConfig};
use crate::engine::backend::ResourceLimits;

pub mod artifact_harvest;
pub mod backend;
pub(crate) mod br_cache;
pub mod chain;
pub mod depsolve;
pub(crate) mod init;
pub(crate) mod layer;
pub(crate) mod mount;
pub(crate) mod mount_guard;
pub mod orphan;
pub(crate) mod pipeline;
pub mod product_repo;
pub mod profile;
pub mod repo;
pub mod repo_publish;
pub mod reproduce;
pub mod resource_sample;
pub(crate) mod shared_layer;

pub(crate) mod shared_dir;

pub(crate) mod build;
pub(crate) mod build_lifecycle;
pub mod cache;
pub(crate) mod clean;
pub(crate) mod command;
pub mod gc;
pub(crate) mod lock;
pub(crate) mod prepare;
pub mod retry;
pub(crate) mod shell;
pub mod tmp_sweep;

pub use build::srpm_pkg_name;
pub use build::{enumerate_repo_src_rpms, SrcRpmEntry, ENUMERATE_SRC_RPMS_TIMEOUT};
pub use build_lifecycle::{BuildContext, BuildIdentity, BuildLifecycle, BuildOutcome};
pub use resource_sample::{
    new_resource_snapshot_slot, snapshot_slot_resources, ResourceSnapshot, ResourceSnapshotSlot,
    ResourceUsage, SAMPLE_BACKEND_CGROUP, SAMPLE_BACKEND_PROC,
};
// command / prepare 模块均 pub(crate)：外部 crate 与集成测试只能经此处
// re-export 取用。
pub use command::{
    run_command_capped_output_with_cancel, run_command_capped_output_with_cancel_and_timeout,
    run_command_capped_output_with_timeout,
};
pub use prepare::{validate_product_repo_inject, write_product_repo_to_root};

/// 终端实时日志通道（CLI `--follow-logs`）的容量上限。通道必须 bounded：
/// phase 读循环 try_send，消费停滞时丢行（计数 + warn）而非堆积内存——
/// build.log 才是持久 sink。
pub const TERMINAL_LOG_CHANNEL_CAPACITY: usize = 256;

/// 构建引擎：封装合并配置、状态库与容器后端，提供 build / init / clean /
/// shell 等产品级操作的统一入口。
pub struct BuildEngine {
    config: Config,
    state: std::sync::Arc<crate::state::StateStore>,
    backend: Box<dyn crate::engine::backend::ContainerBackend>,

    /// 运行时控制（来自 CrbsConfig，CLI 通过 builder 覆盖）。
    max_concurrent_builds: usize,
    /// 单包构建时 rpmbuild 输出的 bounded sender，实时回传上层打印；多包构建
    /// 或 server 模式不设置（避免输出交错）。丢行语义见 `TERMINAL_LOG_CHANNEL_CAPACITY`。
    terminal_tx: Option<tokio::sync::mpsc::Sender<String>>,
    /// 单包构建超时（从 build() 入口开始计算）。
    build_timeout: Option<std::time::Duration>,
    /// SharedLayer 创建时 flock 轮询间隔。
    shared_layer_poll_interval: std::time::Duration,
    /// SharedLayer 创建时 flock 等待超时。
    shared_layer_timeout: std::time::Duration,
    /// SharedLayer 创建失败后的重试次数。
    shared_layer_max_retries: u32,
    /// SharedLayer TTL：超过该时间后触发重建。
    shared_layer_staleness: Option<std::time::Duration>,

    /// CLI 传入的 RPM 宏（覆盖配置文件）。
    cli_macros: std::collections::BTreeMap<String, String>,
    nocheck: bool,
    noclean: bool,
    nodebuginfo: bool,
    target_arch: Option<String>,
    dist: Option<String>,
    with_features: Vec<String>,
    without_features: Vec<String>,
    /// 是否在构建脚本中将 build.log 内容同时输出到 stdout（--follow-logs）。
    follow_logs: bool,

    /// 日志脱敏配置（默认关闭 URL/路径脱敏，开启 token 脱敏）。
    log_sanitization: LogSanitizationConfig,

    /// 调用者身份信息（用于结果目录 chown 和权限控制）。
    caller: Option<crate::privilege::CallerInfo>,

    /// Chain 模式的 local repo 路径（设置后 build() 会 bind mount 到容器内）。
    local_repo_dir: Option<PathBuf>,

    /// Hub 远端产品 repo baseurl（worker 设置）：build() 在 chroot 内写
    /// `crbs-product.repo`（http 源，无 bind 挂载）；与 `local_repo_dir` 互斥。
    product_repo_url: Option<String>,

    /// 复现解析域旗标（apply_reproduce_engine 置位）：置位后 base 安装解析域 =
    /// 复现快照仓（local_repo，记录全集，受信 reposdir 唯一源），install-deps
    /// 的 builddep 亦 disablerepo=* 只看该仓（prepare.rs 据此跳过产品 repo
    /// 注入）——重放解析域钉在源构建记录上。
    replay_snapshot_domain: bool,

    /// --reproduce 模式的预期包列表（NEVRA → SHA256），设置后启用两阶段执行 + fail-fast 校验。
    reproduce_expected: Option<std::collections::HashMap<String, String>>,

    /// --reproduce 模式下原始构建的包信息（NEVRA → BuildPackage），用于继承原始 URL 等 provenance。
    reproduce_source_packages:
        Option<std::collections::HashMap<String, crate::state::BuildPackage>>,

    /// 是否为构建记录 provenance（URL、SHA256、build_packages.json）。实际记录
    /// 与否经 should_record_provenance 门控：deterministic 强制；reproduce 重放
    /// 不重录（复用源记录）。
    reproduce_enabled: crate::config::BoolOrPackages,

    /// repro-from-srpm 回放值：SRPM 头 `BUILDHOST`（`None` = 未探测/头缺失）。
    replay_build_host: Option<String>,

    /// repro-from-srpm 回放值：SRPM 头 `BUILDTIME`（epoch 秒），注入容器
    /// `SOURCE_DATE_EPOCH` 并驱动时间宏组。
    replay_build_time: Option<i64>,

    /// 普通构建时间自锚定（mtime_normalize，非 det）：构建入口取墙钟 S，
    /// BUILDTIME 头与 payload mtime 统一为 S——回放锚（源构建 BUILDTIME）
    /// 因此与源构建逐字节对齐。入口 set-once，相位期只读。
    time_anchor_epoch: std::sync::atomic::AtomicI64,

    /// 构建优先级（0=默认, 1=高优, 2=紧急）。
    priority: i32,

    /// 资源采样快照槽位（worker 设置）：引擎每次建采样器时把句柄写入，任务体
    /// 被 abort 后调用方仍可从槽位读到已累计值（poller 总预算路径兜底取值）。
    resource_snapshot_slot: Option<crate::engine::resource_sample::ResourceSnapshotSlot>,

    /// 构建创建时的产品配置原文快照（chain-resolved 或磁盘产品 TOML）：
    /// CLI 本地构建锚定，随 build 行写入 `product_config_toml`，供
    /// `crbs debug` 复现当时的配置。
    product_config_toml: Option<String>,

    /// 任务级标签：本地任务创建时随任务行落库。
    task_labels: Vec<(String, String)>,
}

impl BuildEngine {
    /// 创建 BuildEngine 实例（加载合并配置 + CrbsConfig + 打开状态库）。
    /// `backend_name` 为 `Some("chroot" | "nspawn")` 时显式指定后端，`None`
    /// 时用配置默认值（全局 → 产品 → "chroot"）。
    pub async fn new(
        product: &str,
        backend_name: Option<&str>,
        cli_limits: Option<ResourceLimits>,
        cli_network: Option<bool>,
    ) -> crate::Result<Self> {
        let config = Config::load_async(product).await?;
        // marker 护栏：CLI 世界开库一律经 open_for_engine——目标 root
        // 含 crbs-server 归属标记时拒绝并给出分流指引。
        let state = std::sync::Arc::new(
            crate::state::StateStore::open_for_engine(&config.crbs_root).await?,
        );
        Self::build_from_parts(
            product,
            backend_name,
            cli_limits,
            cli_network,
            state,
            config,
        )
        .await
    }

    /// 同 `new()`，但接受外部 `StateStore`（共享连接池）与 Hub 下发的产品
    /// 配置 TOML，并可 pin crbs_root：server / worker 传自己的 root，CLI 传
    /// None 保持 crbs.toml 语义。pin 在合并前生效，派生路径随之。
    pub async fn new_with_state_and_config_root(
        product: &str,
        backend_name: Option<&str>,
        cli_limits: Option<ResourceLimits>,
        cli_network: Option<bool>,
        state: std::sync::Arc<crate::state::StateStore>,
        product_config: Option<&str>,
        crbs_root: Option<&std::path::Path>,
    ) -> crate::Result<Self> {
        let config = match (product_config, crbs_root) {
            (Some(toml), Some(root)) => {
                Config::load_with_product_config_and_root_async(product, toml, root).await?
            }
            (Some(toml), None) => Config::load_with_product_config_async(product, toml).await?,
            // fail-closed 拒绝（磁盘 fallback 仅 CLI 的 (None, None) 臂），
            // 勿复活此臂。编程错误守卫走 Internal：server 语境 ValidationFailed
            // 映射 400"用户可修正"会误导（非用户输入问题）。
            (None, Some(_)) => {
                return Err(crate::error::CrbsError::Internal(
                    "new_with_state_and_config_root: crbs_root pin requires \
                     product_config (disk fallback is CLI-only, see the \
                     (None, None) arm) — programming error"
                        .to_string(),
                ));
            }
            (None, None) => Config::load_async(product).await?,
        };
        Self::build_from_parts(
            product,
            backend_name,
            cli_limits,
            cli_network,
            state,
            config,
        )
        .await
    }

    /// CLI 专用：接受 CLI 层已加载好的 `Config`，不从磁盘 / TOML 重新
    /// parse；`Config` 可能来自 hub 的 chain-resolved TOML 而非磁盘。
    pub async fn new_from_config(
        product: &str,
        backend_name: Option<&str>,
        cli_limits: Option<ResourceLimits>,
        cli_network: Option<bool>,
        config: Config,
    ) -> crate::Result<Self> {
        // marker 护栏：同 `new()`，CLI 传入的 config 同样可能来自
        // /etc/crbs/crbs.toml，开库前检查 server root 标记。
        let state = std::sync::Arc::new(
            crate::state::StateStore::open_for_engine(&config.crbs_root).await?,
        );
        Self::build_from_parts(
            product,
            backend_name,
            cli_limits,
            cli_network,
            state,
            config,
        )
        .await
    }

    /// server 世界专用：crbs_root 显式 pin 成 server root，StateStore 复用
    /// server 已打开的共享连接池。server 必须显式 pin，否则引擎配置漂到
    /// 引擎 root；pin 经 `Config::load_with_root_async` 在合并前生效，
    /// product_root / ccache / package_cache 等派生路径随 server root。
    /// 不做 marker 检查（server 打开自己的 root）。
    pub async fn new_with_state_pinned_root(
        product: &str,
        backend_name: Option<&str>,
        cli_limits: Option<ResourceLimits>,
        cli_network: Option<bool>,
        state: std::sync::Arc<crate::state::StateStore>,
        crbs_root: &std::path::Path,
    ) -> crate::Result<Self> {
        let config = Config::load_with_root_async(product, crbs_root).await?;
        Self::build_from_parts(
            product,
            backend_name,
            cli_limits,
            cli_network,
            state,
            config,
        )
        .await
    }

    /// 私有辅助：从**已加载好**的 `Config` + `StateStore` 组装 engine（CLI
    /// 覆盖 → backend 构造 → 结构体组装）。**不做** config 加载与 StateStore
    /// 打开——那两件事由 `new*` 系公开构造函数负责。
    async fn build_from_parts(
        product: &str,
        backend_name: Option<&str>,
        cli_limits: Option<ResourceLimits>,
        cli_network: Option<bool>,
        state: std::sync::Arc<crate::state::StateStore>,
        mut config: Config,
    ) -> crate::Result<Self> {
        // 上游 bug 守卫：product 参数与 config 不匹配时拒绝，避免静默按错的
        // 产品名建目录、写状态。
        if config.product != product {
            return Err(crate::error::CrbsError::ValidationFailed {
                message: format!(
                    "BuildEngine: product mismatch between argument '{}' and config '{}'",
                    product, config.product
                ),
            });
        }

        // merge_configs 不建目录；各 `new*` 构造汇入本函数，在此显式
        // 确保运行时目录存在。
        config.ensure_runtime_dirs()?;

        let crbs = CrbsConfig::load_async().await?;
        let backend_name = backend_name.unwrap_or(&config.backend);

        // CLI 覆盖配置（CLI > product TOML > global TOML）
        if let Some(l) = cli_limits {
            if l.memory_max.is_some() {
                config.memory_max = l.memory_max;
            }
            if l.cpu_quota.is_some() {
                config.cpu_quota = l.cpu_quota;
            }
        }
        if let Some(n) = cli_network {
            config.network = n;
        }

        let limits = ResourceLimits {
            memory_max: config.memory_max.clone(),
            cpu_quota: config.cpu_quota.clone(),
        };

        if backend_name == "chroot" && (limits.memory_max.is_some() || limits.cpu_quota.is_some()) {
            tracing::warn!(
                backend = %backend_name,
                "resource limits (memory_max/cpu_quota) are ignored for chroot backend; \
                 use --backend nspawn to apply them"
            );
        }

        let backend = crate::engine::backend::create_backend(backend_name, &limits).await?;
        let shared_layer_staleness = config.shared_layer_staleness;
        let reproduce_enabled = config.reproduce_enabled.clone();
        let nocheck = config.nocheck;
        let noclean = config.noclean;
        let nodebuginfo = config.nodebuginfo;
        Ok(Self {
            config,
            state,
            backend,
            max_concurrent_builds: crbs.max_concurrent_builds,
            terminal_tx: None,
            build_timeout: None,
            shared_layer_poll_interval: std::time::Duration::from_millis(
                crbs.shared_layer_poll_interval_ms,
            ),
            shared_layer_timeout: std::time::Duration::from_secs(crbs.shared_layer_timeout_secs),
            shared_layer_max_retries: crbs.shared_layer_max_retries,
            shared_layer_staleness,
            cli_macros: std::collections::BTreeMap::new(),
            nocheck,
            noclean,
            nodebuginfo,
            target_arch: None,
            dist: None,
            with_features: Vec::new(),
            without_features: Vec::new(),
            follow_logs: false,
            log_sanitization: LogSanitizationConfig::default(),
            caller: None,
            local_repo_dir: None,
            product_repo_url: None,
            reproduce_expected: None,
            replay_snapshot_domain: false,
            reproduce_source_packages: None,
            reproduce_enabled,
            replay_build_host: None,
            replay_build_time: None,
            time_anchor_epoch: std::sync::atomic::AtomicI64::new(0),
            priority: 0,
            resource_snapshot_slot: None,
            product_config_toml: None,
            task_labels: Vec::new(),
        })
    }

    /// 暴露运行时控制字段（供 main.rs 调度使用）。
    pub fn max_concurrent_builds(&self) -> usize {
        self.max_concurrent_builds
    }

    /// 暴露 product 名称（供 main.rs 插入 pending 记录）。
    pub fn product(&self) -> &str {
        &self.config.product
    }

    /// 暴露 caller 信息（供 main.rs 插入 pending 记录时写入 user）。
    pub fn caller(&self) -> Option<&crate::privilege::CallerInfo> {
        self.caller.as_ref()
    }

    /// 暴露 config（供 main.rs chain 构建读取 local_repo 等配置）。
    pub fn config(&self) -> &crate::config::Config {
        &self.config
    }

    /// 暴露内部 StateStore（供 detach 等场景复用同一连接池）。
    pub fn state_store(&self) -> &std::sync::Arc<crate::state::StateStore> {
        &self.state
    }

    /// 返回 Chain 模式 local repo 路径覆盖（未设置时为 `None`）。
    pub fn local_repo_dir(&self) -> Option<&Path> {
        self.local_repo_dir.as_deref()
    }

    /// hub 远端产品 repo baseurl。
    pub fn product_repo_url(&self) -> Option<&str> {
        self.product_repo_url.as_deref()
    }

    /// 覆盖 tmpfs 配置（CLI 选项优先于配置文件）。
    pub fn with_tmpfs(mut self, enabled: bool) -> Self {
        self.config.build_tmpfs = enabled;
        self
    }

    /// 强制开启 shared_layer（覆盖配置文件）；关闭侧见
    /// [`Self::with_shared_layer_disabled`]。
    pub fn enable_shared_layer(mut self) -> Self {
        self.config.shared_layer = crate::config::BoolOrPackages::Bool(true);
        self
    }

    /// 无视配置强制停用 shared_layer（供 --reproduce）。
    pub fn with_shared_layer_disabled(mut self) -> Self {
        self.config.shared_layer = crate::config::BoolOrPackages::Bool(false);
        self
    }

    /// 强制开启 ccache（覆盖配置文件）；关闭侧见 [`Self::with_ccache_disabled`]。
    pub fn enable_ccache(mut self) -> Self {
        self.config.ccache_enabled = crate::config::BoolOrPackages::Bool(true);
        self
    }

    /// 强制关闭 ccache，无论配置文件是否启用（server 可选参数传 false 时使用）。
    pub fn with_ccache_disabled(mut self) -> Self {
        self.config.ccache_enabled = crate::config::BoolOrPackages::Bool(false);
        self
    }

    /// 设置 rpmbuild 输出的实时回传 sender（上层消费并打印）。通道须以
    /// [`TERMINAL_LOG_CHANNEL_CAPACITY`] 为容量创建（bounded，丢行语义见彼处）。
    pub fn with_terminal_tx(mut self, tx: Option<tokio::sync::mpsc::Sender<String>>) -> Self {
        self.terminal_tx = tx;
        self
    }

    /// 设置单包构建超时（CLI 覆盖 CrbsConfig 默认值）。
    pub fn with_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.build_timeout = timeout;
        self
    }

    /// 设置最大并行构建数（CLI 覆盖 CrbsConfig 默认值）。
    pub fn with_max_concurrent_builds(mut self, jobs: usize) -> Self {
        self.max_concurrent_builds = jobs;
        self
    }

    /// 设置 rpmbuild 构建阶段（CLI 覆盖 CrbsConfig 默认值）。运行时断言：
    /// deterministic 产品拒绝 `ba`——提交入口校验后 CLI `--stage` 仍可在配置
    /// 加载后经本方法覆盖生效值，这里是构建启动路径最后一道收口（断言在
    /// `ensure_stage_allowed_for_deterministic`，纯函数，单测锚点）。
    pub fn with_build_stage(mut self, stage: String) -> crate::Result<Self> {
        crate::build_options::validate_build_stage(&stage)?;
        ensure_stage_allowed_for_deterministic(
            self.config.deterministic,
            &self.config.product,
            &stage,
        )?;
        self.config.build_target = stage;
        Ok(self)
    }

    /// 设置 CLI 传入的 RPM 宏（覆盖配置文件同名宏）。
    pub fn with_cli_macros(mut self, macros: std::collections::BTreeMap<String, String>) -> Self {
        self.cli_macros = macros;
        self
    }

    /// 设置是否跳过 %check 阶段。
    pub fn with_nocheck(mut self, v: bool) -> Self {
        self.nocheck = v;
        self
    }

    /// 设置是否不生成 debuginfo 包。
    pub fn with_nodebuginfo(mut self, v: bool) -> Self {
        self.nodebuginfo = v;
        self
    }

    /// 设置是否跳过 distro 收尾清理段（%clean 与 rmbuild）。
    pub fn with_noclean(mut self, v: bool) -> Self {
        self.noclean = v;
        self
    }

    /// 设置目标架构。
    pub fn with_target_arch(mut self, arch: Option<String>) -> Self {
        self.target_arch = arch;
        self
    }

    /// 设置 dist 标签。
    pub fn with_dist(mut self, dist: Option<String>) -> Self {
        self.dist = dist;
        self
    }

    /// 设置条件构建：启用。
    pub fn with_with_features(mut self, features: Vec<String>) -> Self {
        self.with_features = features;
        self
    }

    /// 设置条件构建：禁用。
    pub fn with_without_features(mut self, features: Vec<String>) -> Self {
        self.without_features = features;
        self
    }

    /// 设置是否将 build.log / phase 标记同时输出到 stdout（--follow-logs）。
    pub fn with_follow_logs(mut self, v: bool) -> Self {
        self.follow_logs = v;
        self
    }

    /// 设置日志脱敏配置（server 传入 `ServerConfig.log_sanitization`）。
    pub fn with_log_sanitization(mut self, cfg: LogSanitizationConfig) -> Self {
        self.log_sanitization = cfg;
        self
    }

    /// 设置单包构建遇到 transient 错误时的最大重试次数（CLI 覆盖产品配置）。
    pub fn with_build_max_retries(mut self, retries: u32) -> Self {
        self.config.build_max_retries = retries;
        self
    }

    /// 设置调用者身份信息（用于结果目录 chown 和权限控制）。
    pub fn with_caller(mut self, caller: crate::privilege::CallerInfo) -> Self {
        self.caller = Some(caller);
        self
    }

    /// 设置构建创建时的产品配置原文快照，随 build 行写入。
    pub fn with_product_config_toml(mut self, toml: Option<String>) -> Self {
        self.product_config_toml = toml;
        self
    }

    /// 设置任务级标签，随本地任务行写入（调用方已校验）。
    pub fn with_task_labels(mut self, labels: Vec<(String, String)>) -> Self {
        self.task_labels = labels;
        self
    }

    /// 设置 Chain 模式 local repo 路径（build() 时 bind mount 进容器）。
    pub fn with_local_repo(mut self, repo_dir: PathBuf) -> Self {
        self.local_repo_dir = Some(repo_dir);
        self
    }

    /// 设置 hub 远端产品 repo baseurl。调用方须保证 `local_repo_dir` 为
    /// `None`（互斥，build 期 `validate_product_repo_inject` 校验）与
    /// `config.network == true`（网络关闭时注入被静默跳过）。
    pub fn with_product_repo_url(mut self, url: String) -> Self {
        self.product_repo_url = Some(url);
        self
    }

    /// 清除 hub 远端产品 repo baseurl。reproduce 确定性：worker 主路径
    /// 每个 assignment 先注入 hub 产品仓，而 reproduce 重放的依赖源是
    /// build_packages.json 记录的包（`with_local_repo` 临时仓）；产品仓随时间
    /// 漂移，与 `local_repo` 互斥（fail-fast），reproduce 分支必须先清除。
    pub fn without_product_repo_url(mut self) -> Self {
        self.product_repo_url = None;
        self
    }

    /// 置复现解析域旗标（replay）：base 安装解析域 = 复现快照仓（local_repo），
    /// install-deps 的 builddep disablerepo=* 只看该仓（见字段 doc）。
    pub fn with_replay_snapshot_domain(mut self) -> Self {
        self.replay_snapshot_domain = true;
        self
    }

    /// 复现解析域旗标读取（prepare.rs 密闭判别器与 init 快照域分流共用）。
    pub(crate) fn replay_snapshot_domain(&self) -> bool {
        self.replay_snapshot_domain
    }

    /// base OS 层路径。
    pub fn base_os_path(&self) -> PathBuf {
        self.config.base_os_path()
    }

    /// 设置 --reproduce 预期包列表（NEVRA → SHA256），启用两阶段执行 + fail-fast 校验。
    pub fn with_reproduce_expected(
        mut self,
        packages: std::collections::HashMap<String, String>,
    ) -> Self {
        self.reproduce_expected = Some(packages);
        self
    }

    /// 设置 --reproduce 原始构建包信息（NEVRA → BuildPackage），继承原始 URL 等 provenance。
    pub fn with_reproduce_source_packages(
        mut self,
        packages: std::collections::HashMap<String, crate::state::BuildPackage>,
    ) -> Self {
        self.reproduce_source_packages = Some(packages);
        self
    }

    /// 设置是否记录构建 provenance（URL / SHA256 / build_packages.json）；实际
    /// 记录与否经 should_record_provenance 门（--reproduce 重放不重录）。
    pub fn with_reproduce_enabled(mut self, enabled: crate::config::BoolOrPackages) -> Self {
        self.reproduce_enabled = enabled;
        self
    }

    /// 设置 repro-from-srpm 回放主机名（SRPM 头 `BUILDHOST` 原样）：驱动
    /// `_buildhost` 宏（merge_build_macros 静默层）与非 det 回放的容器
    /// hostname 钉值（decide_container_hostname，钉回源构建内核主机名）。
    pub fn with_replay_build_host(mut self, host: String) -> Self {
        self.replay_build_host = Some(host);
        self
    }

    /// 设置 repro-from-srpm 回放构建时间（SRPM 头 `BUILDTIME`，epoch 秒）：
    /// 注入容器 `SOURCE_DATE_EPOCH`（spawn env + rpmbuild sudo env 前缀——
    /// sudo env_reset 会剥掉脚本 shell 的环境）。`0` 照注。
    pub fn with_replay_build_time(mut self, epoch: i64) -> Self {
        self.replay_build_time = Some(epoch);
        self
    }

    /// replay 模式判定：任一回放值存在即真（引擎只认值，不读旗标）。
    pub(crate) fn replay_mode(&self) -> bool {
        self.replay_build_host.is_some() || self.replay_build_time.is_some()
    }

    /// 设置构建优先级（0=默认, 1=高优, 2=紧急）。
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// 注入资源采样快照槽位：引擎每次建采样器（`build` / `build_into`）时把
    /// 句柄写入槽位，构建 future 被 abort（poller 总预算超时）后，调用方仍可
    /// 经 [`snapshot_slot_resources`] 读到
    /// 已累计值。未注入 = 无兜底（CLI 本地路径不需要）。
    pub fn with_resource_snapshot_slot(
        mut self,
        slot: crate::engine::ResourceSnapshotSlot,
    ) -> Self {
        self.resource_snapshot_slot = Some(slot);
        self
    }
}

/// 终止构建进程树：cgroup.kill 优先（nspawn + cgroup v2 payload cgroup，
/// 与 limits 配置无关），否则 SIGKILL 进程组。
///
/// `pid` 须为 spawn 后、wait 前捕获的子进程 pid（= pgid）：`Child::id()`
/// 在子进程被 reap 后返回 `None`，而 reap 后仍需 kill 持有管道写端的幸存
/// 孙进程；传 `None` 回退 `child.id()`（仅对未 reap 子进程有效）。
async fn kill_process_tree(spawned: &crate::engine::backend::SpawnedChild, pid: Option<u32>) {
    if spawned.cgroup_kill().await {
        return;
    }
    kill_process_group_via_privilege(spawned, pid).await;
}

/// 复核升级路径：cgroup 候选与进程组 SIGKILL 全部施加——首轮 cgroup.kill
/// 写成功≠子树死透（形态猜错时写的是空 scope），不因写成功跳过进程组 kill。
async fn kill_process_tree_exhaustive(
    spawned: &crate::engine::backend::SpawnedChild,
    pid: Option<u32>,
) {
    spawned.cgroup_kill().await;
    kill_process_group_via_privilege(spawned, pid).await;
}

/// 经特权层 SIGKILL 进程组（kill_process_group 是同步方法：helper spawn +
/// 50ms 轮询 + 10s 截止，须离开运行时线程执行，防阻塞 async）。
async fn kill_process_group_via_privilege(
    spawned: &crate::engine::backend::SpawnedChild,
    pid: Option<u32>,
) {
    if let Some(pid) = pid.or_else(|| spawned.child.id()) {
        let pgid = pid as i32;
        let backend = crate::privilege::get_privilege_backend();
        let result =
            match tokio::task::spawn_blocking(move || backend.kill_process_group(pgid)).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(crate::error::CrbsError::io_message(format!(
                    "spawn_blocking kill_process_group: {e}"
                ))),
            };
        if let Err(e) = result {
            tracing::warn!(
                pid = %pid,
                error = %e,
                "failed to kill build process group via privilege layer"
            );
        }
    }
}

/// 经特权层终止 nspawn machine（kill 升级链的 machine 级兜底；terminate_machine
/// 同步——helper one-shot 与 /proc 扫描可阻塞，spawn_blocking 防 async 阻塞）。
/// 失败仅 warn 不放大：升级链终局是"人工清理"error，此处失败不影响其触达。
async fn terminate_machine_via_privilege(machine_name: &str) {
    let backend = crate::privilege::get_privilege_backend();
    let owned = machine_name.to_string();
    let result = match tokio::task::spawn_blocking(move || backend.terminate_machine(&owned)).await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(crate::error::CrbsError::io_message(format!(
            "spawn_blocking terminate_machine: {e}"
        ))),
    };
    if let Err(e) = result {
        tracing::warn!(
            machine = %machine_name,
            error = %e,
            "failed to terminate nspawn machine via privilege layer"
        );
    }
}

/// 构建阶段断言核心逻辑（纯函数，供 [`BuildEngine::with_build_stage`] 收口与单测
/// 锚定）：deterministic 产品拒绝 `ba`——每架构 `-ba` 重造 SRPM 引入
/// "哪个 SRPM 算数"的字节歧义。
pub(crate) fn ensure_stage_allowed_for_deterministic(
    deterministic: bool,
    product: &str,
    stage: &str,
) -> crate::Result<()> {
    if deterministic && stage == "ba" {
        return Err(crate::error::CrbsError::ValidationFailed {
            message: format!(
                "deterministic product '{}' cannot use build_target 'ba': per-arch SRPM \
                 rebuilding breaks byte-identical output; use 'bb'",
                product
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod new_from_config_tests {
    //! 锁住 `new_from_config` 经 `build_from_parts` 的 product 一致性检查；
    //! 不覆盖 happy path 组装（`create_backend` / `StateStore::new` 需真实
    //! 运行环境）。

    use super::ensure_stage_allowed_for_deterministic;
    use super::BuildEngine;
    use crate::config::{Config, CrbsConfig, ProductConfig};
    use tempfile::TempDir;

    #[tokio::test]
    async fn new_from_config_rejects_product_mismatch() {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path().join("root");
        tokio::fs::create_dir_all(&root).await.expect("mkdir root");

        // global config 的 crbs_root 指到 tempdir：产品级 crbs_root 已被
        // ignore（见 merge.rs），须走 merge_configs 直接传 global，避免撞
        // 默认 /var/lib/crbs 拿不到权限。
        let global = CrbsConfig {
            crbs_root: root.clone(),
            result_dir: Some(root.join("results")),
            shared_layers_dir: Some(root.join("shared_layers")),
            tmpfs_dir: tmp.path().join("tmpfs"),
            tmp_dir: Some(tmp.path().join("tmp")),
            ccache_dir: root.join("ccache"),
            ..CrbsConfig::default()
        };
        let product = ProductConfig {
            product: Some("prod_a".into()),
            base_packages: vec!["bash".into()],
            repos: vec![],
            ..ProductConfig::default()
        };
        let config = Config::merge_configs("prod_a", global, product).expect("merge_configs");

        let result = BuildEngine::new_from_config("prod_b", None, None, None, config).await;
        // 不用 expect_err：BuildEngine 无 Debug 实现（内部持有 backend trait 对象等）。
        let err = match result {
            Ok(_) => panic!("mismatched product should fail"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("product mismatch"), "unexpected error: {msg}");
        assert!(
            msg.contains("prod_a") && msg.contains("prod_b"),
            "err should name both products: {msg}"
        );
    }

    /// 构建阶段断言单测（完整 BuildEngine 组装需 root/真实后端，故测纯函数）：
    /// deterministic 拒 ba（错误点名产品与修复方向），bb/bs 放行；
    /// 非 deterministic 的 ba 不受限。
    #[test]
    fn stage_ba_rejected_for_deterministic_products() {
        let err = ensure_stage_allowed_for_deterministic(true, "det-prod", "ba").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("det-prod"), "must name the product: {msg}");
        assert!(msg.contains("'bb'"), "must point at the fix: {msg}");

        assert!(ensure_stage_allowed_for_deterministic(true, "det-prod", "bb").is_ok());
        assert!(ensure_stage_allowed_for_deterministic(true, "det-prod", "bs").is_ok());
        // 非 deterministic：ba 照常（由 validate_build_stage 管字符集）
        assert!(ensure_stage_allowed_for_deterministic(false, "plain", "ba").is_ok());
    }
}

/// 测试专用最小 BuildEngine 构造（cfg(test)，engine 子模块测试共用）：
/// 真实 Config + StateStore（sqlite 默认 feature，临时根）+ ChrootBackend
/// 直构——create_backend 的 available() 检查在 Linux 非 root / macOS 必失败。
#[cfg(test)]
async fn minimal_engine(tmp_root: &Path) -> BuildEngine {
    let global = CrbsConfig {
        crbs_root: tmp_root.to_path_buf(),
        ..CrbsConfig::default()
    };
    let product = crate::config::ProductConfig {
        product: Some("prod_a".into()),
        base_packages: vec!["bash".into()],
        ..crate::config::ProductConfig::default()
    };
    let config = Config::merge_configs("prod_a", global, product).expect("merge_configs");
    let state = std::sync::Arc::new(
        crate::state::StateStore::open_for_engine(tmp_root)
            .await
            .expect("state"),
    );
    let reproduce_enabled = config.reproduce_enabled.clone();
    BuildEngine {
        config,
        state,
        backend: Box::new(crate::engine::backend::ChrootBackend::new()),
        max_concurrent_builds: 1,
        terminal_tx: None,
        build_timeout: None,
        shared_layer_poll_interval: std::time::Duration::from_secs(1),
        shared_layer_timeout: std::time::Duration::from_secs(1),
        shared_layer_max_retries: 0,
        shared_layer_staleness: None,
        cli_macros: Default::default(),
        nocheck: false,
        noclean: false,
        nodebuginfo: false,
        target_arch: None,
        dist: None,
        with_features: Vec::new(),
        without_features: Vec::new(),
        follow_logs: false,
        log_sanitization: LogSanitizationConfig::default(),
        caller: None,
        local_repo_dir: None,
        product_repo_url: None,
        reproduce_expected: None,
        replay_snapshot_domain: false,
        reproduce_source_packages: None,
        reproduce_enabled,
        replay_build_host: None,
        replay_build_time: None,
        time_anchor_epoch: std::sync::atomic::AtomicI64::new(0),
        priority: 0,
        resource_snapshot_slot: None,
        product_config_toml: None,
        task_labels: Vec::new(),
    }
}

#[cfg(test)]
mod product_repo_builder_tests {
    //! reproduce 链回归：worker 主路径先注入 hub 产品仓，reproduce 分支用
    //! `with_local_repo` 恢复记录包来源——两源互斥
    //!（`validate_product_repo_inject`），reproduce 链必须
    //! `without_product_repo_url` 清除产品仓、保留 local_repo。公共组装经
    //! `create_backend` 做 available() 检查（Linux 非 root 必失败），故用
    //! `minimal_engine` 直构锁 builder 链语义。

    use super::*;
    /// reproduce 链语义：注入产品仓 → without_product_repo_url +
    /// with_local_repo——产品仓被清除、local_repo 保留，互斥校验不触发。
    #[tokio::test]
    async fn reproduce_chain_clears_product_repo_and_keeps_local_repo() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let engine = minimal_engine(tmp.path())
            .await
            .with_product_repo_url("http://hub.example.com/repo/prod/x86_64".into())
            .without_product_repo_url()
            .with_local_repo(PathBuf::from("/tmp/fake-temp-repo"));

        assert_eq!(
            engine.product_repo_url(),
            None,
            "product repo must be cleared"
        );
        assert_eq!(
            engine.local_repo_dir(),
            Some(Path::new("/tmp/fake-temp-repo")),
            "local repo must be kept"
        );
    }

    /// 既有行为不回退：非 reproduce 且 product_repo_enabled 时产品仓注入保留、无 local_repo。
    #[tokio::test]
    async fn product_repo_url_injection_survives_without_reproduce_clear() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let engine = minimal_engine(tmp.path())
            .await
            .with_product_repo_url("http://hub.example.com/repo/prod/x86_64".into());

        assert_eq!(
            engine.product_repo_url(),
            Some("http://hub.example.com/repo/prod/x86_64")
        );
        assert_eq!(engine.local_repo_dir(), None);
    }

    /// 幂等：干净的 engine 上 without_product_repo_url 是 no-op（None 保持 None）。
    #[tokio::test]
    async fn without_product_repo_url_is_noop_when_unset() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let engine = minimal_engine(tmp.path()).await.without_product_repo_url();
        assert_eq!(engine.product_repo_url(), None);
        assert_eq!(engine.local_repo_dir(), None);
    }

    /// 复现解析域旗标置位后，`mount_common_features` 的产品 repo 动态注入与
    /// crbs-product.repo belt 守卫输入成立（`replay_snapshot_domain` → 注入
    /// 关闭）；挂载路径需真实 overlayfs / root，此处只锁 builder 链到判定的
    /// 衔接语义。
    #[tokio::test]
    async fn replay_snapshot_domain_disables_dynamic_repo_injection() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let engine = minimal_engine(tmp.path())
            .await
            .with_replay_snapshot_domain();

        assert!(
            engine.replay_snapshot_domain(),
            "premise: replay flag must be set"
        );
        assert!(
            !crate::engine::prepare::dynamic_repo_injection_enabled(
                engine.replay_snapshot_domain()
            ),
            "replay engine must disable product repo injection"
        );
    }

    /// 非 replay 形态动态注入保持开启（normal 路径不受影响）。
    #[tokio::test]
    async fn normal_build_keeps_dynamic_repo_injection() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let engine = minimal_engine(tmp.path()).await;

        assert!(
            crate::engine::prepare::dynamic_repo_injection_enabled(engine.replay_snapshot_domain()),
            "normal build engine must keep product repo injection"
        );
    }

    /// repro-from-srpm builder 链：两个 with_replay_* 落值、`replay_mode` 任一存在即真；干净 engine 恒非 replay。
    #[tokio::test]
    async fn replay_builder_methods_set_values() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(!minimal_engine(tmp.path()).await.replay_mode());

        let engine = minimal_engine(tmp.path())
            .await
            .with_replay_build_host("probehost".into())
            .with_replay_build_time(0);
        assert!(engine.replay_mode());
        assert_eq!(engine.replay_build_host.as_deref(), Some("probehost"));
        assert_eq!(engine.replay_build_time, Some(0));
    }
}

#[cfg(test)]
mod apply_options_tmpfs_tests {
    //! CLI tmpfs 三态收口语义：`None`（未传旗标）跟随配置，`Some` 显式覆写。
    //! CLI 侧把 bool false 压成 `Some(false)` 会强制关闭配置（历史缺陷），
    //! 此测试钉住 `apply_options_to_engine` 的三态行为。`minimal_engine` 直构，
    //! 默认配置 build_tmpfs=false，true 侧直接改 config 字段模拟配置开启。

    use super::minimal_engine;
    use crate::build_options::{apply_options_to_engine, BuildOptions};
    use tempfile::TempDir;

    fn opts_with(tmpfs: Option<bool>) -> BuildOptions {
        BuildOptions {
            tmpfs,
            ..BuildOptions::default()
        }
    }

    #[tokio::test]
    async fn tmpfs_none_follows_config() {
        let tmp = TempDir::new().expect("tempdir");

        // 配置 false：None 保持关。
        let engine = minimal_engine(tmp.path()).await;
        assert!(!engine.config.build_tmpfs, "premise: default config is off");
        let engine = apply_options_to_engine(engine, &opts_with(None)).expect("apply");
        assert!(!engine.config.build_tmpfs, "None must follow config (off)");

        // 配置 true：None 保持开——不得压成 Some(false) 强制关。
        let mut engine = minimal_engine(tmp.path()).await;
        engine.config.build_tmpfs = true;
        let engine = apply_options_to_engine(engine, &opts_with(None)).expect("apply");
        assert!(engine.config.build_tmpfs, "None must follow config (on)");
    }

    #[tokio::test]
    async fn tmpfs_some_overrides_config() {
        let tmp = TempDir::new().expect("tempdir");

        // Some(true)：配置关也强制开。
        let engine = minimal_engine(tmp.path()).await;
        let engine = apply_options_to_engine(engine, &opts_with(Some(true))).expect("apply");
        assert!(engine.config.build_tmpfs, "Some(true) must force on");

        // Some(false)：配置开也强制关。
        let mut engine = minimal_engine(tmp.path()).await;
        engine.config.build_tmpfs = true;
        let engine = apply_options_to_engine(engine, &opts_with(Some(false))).expect("apply");
        assert!(!engine.config.build_tmpfs, "Some(false) must force off");
    }
}
