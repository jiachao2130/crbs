// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Server 专属配置（`/etc/crbs/server.toml`）。
//!
//! 优先级：CLI 参数 > 配置文件 > 硬编码默认值。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::CrbsError;

/// Web 只读面（UI/日志/产物下载）匿名访问控制，默认全开；写操作始终需要认证。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicAccessConfig {
    /// Web UI 查看产品/构建/任务是否公开。
    #[serde(default = "default_public_access")]
    pub view: bool,

    /// 构建日志是否公开查看。
    #[serde(default = "default_public_access")]
    pub logs: bool,

    /// 产物下载是否公开。
    #[serde(default = "default_public_access")]
    pub download: bool,
}

impl Default for PublicAccessConfig {
    fn default() -> Self {
        Self {
            view: default_public_access(),
            logs: default_public_access(),
            download: default_public_access(),
        }
    }
}

/// 日志脱敏配置：访问/错误/诊断日志敏感字段（token、URL 凭证、路径）；默认开 token 脱敏（防 SRPM 下载 token 泄露），URL/路径默认关。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSanitizationConfig {
    /// 是否在访问日志查询字符串中脱敏 `token` 参数（例如 SRPM 下载签名 token）。
    #[serde(default = "default_log_sanitization_redact_tokens")]
    pub redact_tokens: bool,

    /// 是否脱敏 URL 中的用户认证信息（如 `http://user:pass@host/`）。
    #[serde(default)]
    pub redact_urls: bool,

    /// 是否将日志中 repo `baseurl` 的路径脱敏为 basename。
    #[serde(default)]
    pub redact_paths: bool,
}

impl Default for LogSanitizationConfig {
    fn default() -> Self {
        Self {
            redact_tokens: default_log_sanitization_redact_tokens(),
            redact_urls: false,
            redact_paths: false,
        }
    }
}

pub(crate) fn default_log_sanitization_redact_tokens() -> bool {
    true
}
/// 构建调度模式：Hub 在本地执行与 Worker 分发之间如何取舍。
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerMode {
    /// 自动模式：优先分发到 Worker，无可用 Worker 时回退本地。
    #[default]
    Auto,
    /// 仅本地执行：即使有可用 Worker 也不分发，构建一律 Hub 本机执行。
    LocalOnly,
    /// 仅分发：本地不执行构建，只派给 Worker；无可用 Worker 时任务滞留 pending，
    /// 不回退本地。
    DistributedOnly,
}

/// 本地 daemon 配置：自动发现、`crbs build` 默认是否走 daemon、pid/port 目录
/// 与空闲自动退出。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    /// 是否启用本地 daemon 自动发现。
    #[serde(default = "default_local_enable")]
    pub enable: bool,

    /// `crbs build` 默认路径是否优先走 daemon；false（默认）= 直接本地构建，显式 `--daemon` 才走 daemon。
    #[serde(default = "default_local_daemon_auto")]
    pub daemon_auto: bool,

    /// pid/port 文件目录；None 时按运行身份选择默认值。
    #[serde(default)]
    pub run_dir: Option<PathBuf>,

    /// 空闲自动退出超时（秒）；0 表示不自动退出。
    #[serde(default = "default_local_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            enable: default_local_enable(),
            daemon_auto: default_local_daemon_auto(),
            run_dir: None,
            idle_timeout_secs: default_local_idle_timeout_secs(),
        }
    }
}

/// TLS 服务端配置（可选）：配置后走内置 tokio-rustls HTTPS；
/// 不配置保持 HTTP，由外部反代终止 TLS。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ServerTlsConfig {
    /// PEM 格式的服务端证书路径。
    pub cert: PathBuf,
    /// PEM 格式的服务端私钥路径。
    pub key: PathBuf,
}

/// server（Hub）配置根：监听与 TLS、认证与限流、构建超时与调度、结果保留，
/// 以及由 crbs_root 派生的各路径。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// server 世界的 crbs_root（root 分离）：只由本字段或缺省 /var/lib/crbs 决定，
    /// 不读 crbs.toml（其 crbs_root 收归引擎世界，缺省 /var/lib/crbs-engine，勿混）。
    /// state DB / uploads / artifacts / srpm token key / csrf key / run_dir 均由此派生。
    #[serde(default)]
    pub crbs_root: Option<PathBuf>,

    #[serde(default = "default_listen")]
    pub listen: String,

    /// Hub 本地构建并发上限，0 = 用 CPU 数；只限 Hub 本机执行，
    /// 分布式构建不受此限（各 Worker 由其 `capacity` 独立约束）。
    #[serde(default)]
    pub max_local_builds: usize,

    /// 构建超时兜底（秒）：请求未显式指定 timeout 时 hub 本地构建的默认值；
    /// 不兜底则 hang 构建永久占 building 行 + build_semaphore（zombie 修复因
    /// crbs_pid = server pid 存活而跳过，直到 server 重启）。
    /// 0 = 关闭兜底；默认 86_400（24h）；请求显式 timeout 优先（0 = 显式无限）。
    #[serde(default = "default_build_timeout_secs")]
    pub build_timeout_secs: u64,

    /// 优雅退出超时（秒）：约束停机两段等待——HTTP 连接排空（超时断开在途连接）与等待活跃构建（超时取消未完成构建）。
    #[serde(default = "default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,

    /// 是否允许产品管理端点。
    #[serde(default)]
    pub allow_product_management: bool,

    /// 是否启用 API Bearer Token 认证；false 时除 health/version 外全端点关认证（仅本地开发/反代后用）。
    #[serde(default = "default_auth_enabled")]
    pub auth_enabled: bool,

    /// Deprecated 兼容键：仅接受旧 server.toml 中的该键使旧配置可启动，
    /// 值不参与任何判定（读写边界统一收敛到产品可见性）。
    #[serde(default, skip_serializing)]
    pub strict_ownership: bool,

    /// 提交限流：per-user 固定窗口，作用于 POST /api/v1/builds 与
    /// /api/v1/tasks/{id}/rebuild|reproduce；进程内存态（多实例各独立计数），
    /// worker 认证路径豁免。默认关：批量重建工作流会触发 429，窗口按负载定，见 SECURITY.md。
    #[serde(default)]
    pub submit_rate_limit: SubmitRateLimitConfig,

    /// SRPM 上传大小上限（MB）；`0` 会拒绝所有上传（并非“不限制”），关闭上传需移除相关路由或前端入口。
    #[serde(default = "default_upload_max_size_mb")]
    pub upload_max_size_mb: usize,

    /// 接受构建前要求 crbs_root 上保留的最小剩余磁盘空间（GB）；0 = 禁用磁盘水位检查。
    #[serde(default = "default_min_free_disk_gb")]
    pub min_free_disk_gb: usize,

    /// 内存中保留的 GC task 结果数量：`0` = 不裁剪、全部保留（`prune_gc_tasks`
    /// 直接返回，并非"全不留"），取 1 = 只留最近一条。默认 100。
    #[serde(default = "default_gc_result_retention")]
    pub gc_result_retention: usize,

    /// 内存中保留的 product task 结果数量。未设置时复用 gc_result_retention。
    #[serde(default)]
    pub product_result_retention: Option<usize>,

    /// DB 历史行保留天数：audit_logs/worker_tasks/builds/tasks 超龄行后台删除（builds 仅删
    /// 已磁盘 GC、result_dir 已置 NULL 的行，不产生孤儿目录；磁盘产物归 result GC）。0 = 禁用，默认 90。
    #[serde(default = "default_db_retention_days")]
    pub db_retention_days: u64,

    /// CORS 允许的 Origin 列表。空表示不启用 CORS。
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,

    /// 低优（Default 优先级）任务预留的并发槽比例（0.0 ~ 1.0）；Default running 数不足该比例时优先分配 Default。
    #[serde(default = "default_low_priority_reserve_ratio")]
    pub low_priority_reserve_ratio: f64,

    /// 调度器模式：auto / local_only / distributed_only。
    #[serde(default)]
    pub scheduler_mode: SchedulerMode,

    /// 硬下限消费总闸：true 时 planner 的
    /// eligible 过滤与 hub 本地取件预检按 builds.req_min_*（缺维回退画像表
    /// declared 声明）判 worker 可承载性，要求维遥测缺失按 fail-closed 拒；
    /// false（默认）时整段跳过。不管采集、写入与展示。
    #[serde(default)]
    pub resource_requirements_enabled: bool,

    /// 学习面权重消费开关：true（默认）时 Σ
    /// 水位权重源 = 画像表有效权重（censored 期 mem 取 max(ema, max)，缺维
    /// 回退 resource_overrides）；false 时 Σ 只剩 resource_overrides。画像
    /// 写入无条件，不受本键影响。
    #[serde(default = "default_resource_profile_weights_enabled")]
    pub resource_profile_weights_enabled: bool,

    /// hub 本地构建水位门（独立开关）：
    /// true 时本地取件前按伪 worker 遥测（/proc 自采）+ 在跑权重 Σ + 队首
    /// 候选权重判水位，超限跳过本 tick 本地取件（不阻塞远端派发，归因照记）；
    /// false（默认）时本地路径不加水位门——hub 兼任 API/UI 服务，默认不给
    /// 本地构建加门。本地硬下限随 resource_requirements_enabled，不在本开关
    /// 范围。
    #[serde(default)]
    pub resource_local_watermark_enabled: bool,

    /// 分布式派发水位门总闸：true（默认）时 planner 按目标 worker 实时遥测 +
    /// 在跑权重 Σ + 候选权重判水位；false 时放置序选中即派发（硬下限过滤不受
    /// 影响）。遥测缺失恒 fail-open，不因缺数据阻塞。运维退路：CPU 权重在
    /// 异构核数集群上偏保守时先关本闸，不影响本地门（独立开关）。
    #[serde(default = "default_resource_dispatch_watermark_enabled")]
    pub resource_dispatch_watermark_enabled: bool,

    /// 硬下限停滞提示阈值（秒）：构建首次因硬下限（无任一在线 worker 满足
    /// 声明）被拒后持续该时长，追加一条构建 note 说明原因与解绑方式。
    /// 0 = 关闭提示。
    #[serde(default = "default_resource_hard_req_stall_secs")]
    pub resource_hard_req_stall_secs: u64,

    /// heavy steering 总闸：true 时 heavy
    /// 候选（req 声明存在 / 有效权重达阈值 / SRPM ≥ resource_heavy_srpm_bytes）
    /// 在 eligible 存活节点中选 headroom 最大者；false（默认）时全部候选走
    /// least-loaded 序首个（未启用 steering 的路径）。
    #[serde(default)]
    pub resource_steering_enabled: bool,

    /// 学习门影子记录开关：true 时派发落点对已学习键
    ///（画像 learned_samples ≥ 1）逐门评估并落结构化决策日志——内存门
    ///（节点可用内存 ≥ learned_max_mem_kb × 1.2）与 tmpfs 门（节点 tmpfs 余量
    /// ≥ learned_max_tmpfs_kb，容量按 mem_total/2、已用按 0）；影子只记录不
    /// 实际拒绝，未学习键与遥测缺失节点不受影响。false（默认）时无额外回源、
    /// 无记录，派发行为零变化。
    #[serde(default)]
    pub resource_learned_gates_enabled: bool,

    /// 学习 tmpfs 门转正开关：true 时 planner 遍历中把 tmpfs 门升级为真实
    /// 拒绝——节点 tmpfs 容量（mem_total/2，与影子门同口径）< 该键学习 tmpfs
    /// 峰值的已学习候选在该节点拒绝、顺延下一节点，全组拒绝归因记
    /// `watermark_tmpfs` 维。fail-open 同向：未学习键 / 学习值缺失 / 节点
    /// mem_total 缺失一律放行。false（默认）时门只随
    /// `resource_learned_gates_enabled` 影子记录，派发行为与既有基线逐位一致。
    /// 门输入回源随本开关或影子开关任一开启。
    #[serde(default)]
    pub resource_tmpfs_gate_enforced: bool,

    /// 派发准入门内存水位系数：`used + Σ权重 ≥ mem_total × 该值` 即拒。
    /// 默认 0.90（余 10% 给抖动）；调低收紧、调高放宽（>1 = 事实关内存门，
    /// 属实验语义）。加载期校验 >0（NaN 拒），越界 fail-fast 拒启。
    #[serde(default = "default_resource_mem_watermark")]
    pub resource_mem_watermark: f64,

    /// 派发准入门 CPU 水位系数：`load1 + Σp90 ≥ ncpu × 该值` 即拒。默认
    /// 1.00；load1 可超 ncpu，>1 的放宽（如 1.05 容忍 5% 过载）属实验语义。
    /// 加载期校验 >0（NaN 拒），越界 fail-fast 拒启。
    #[serde(default = "default_resource_cpu_watermark")]
    pub resource_cpu_watermark: f64,

    /// heavy 判定的 SRPM 体积阈值（字节）：srpm_size_bytes ≥
    /// 本值的构建按 heavy steering（未画像重包的补洞，如 llvm/chromium 源包；
    /// 画像包走权重阈值臂）。0 = 本臂禁用。
    #[serde(default = "default_resource_heavy_srpm_bytes")]
    pub resource_heavy_srpm_bytes: i64,

    #[serde(default)]
    pub local: LocalConfig,

    #[serde(default)]
    pub public_access: PublicAccessConfig,

    /// 是否启用 Web UI。关闭后 `/ui/*` 与 `/` 仪表盘路由不再挂载。
    #[serde(default = "default_web_ui_enabled")]
    pub web_ui_enabled: bool,

    /// 强制给会话/登录 cookie 加 `Secure`。默认 `false`；**反代（nginx 等）终止 TLS、
    /// server 只监听 loopback HTTP 时必须设 `true`**，否则 cookie 缺 `Secure` 可被中间
    /// 设备明文读取。开启内置 `tls` 时自动带 `Secure`，无需此项。
    #[serde(default = "default_force_secure_cookies")]
    pub force_secure_cookies: bool,

    #[serde(default)]
    pub log_sanitization: LogSanitizationConfig,

    /// Hub 产物根覆盖。
    #[serde(default)]
    pub result_dir: Option<PathBuf>,

    /// SRPM 上传暂存区目录。
    #[serde(default)]
    pub upload_dir: Option<PathBuf>,

    /// SQLite 数据库文件路径。
    #[serde(default)]
    pub state_db_path: Option<PathBuf>,

    /// Worker 日志持久化目录。
    #[serde(default)]
    pub artifact_dir: Option<PathBuf>,

    #[serde(default)]
    pub tls: Option<ServerTlsConfig>,

    /// 是否允许下载源码包（.src.rpm）。
    /// false 时，只有 operator/admin 角色可下载 SRPM，builder/viewer 被拒绝。
    #[serde(default = "default_allow_srpm_download")]
    pub allow_srpm_download: bool,

    /// DB 连接池上限。优先级：`CRBS_DB_MAX_CONNECTIONS` 环境变量 > 本键 > 默认 8；
    /// 各级非法值（<1 等）warn 后回退下一级不 fail-fast；仅 server 进程消费本键，
    /// CLI / worker 侧只认 env。
    #[serde(default)]
    pub db_max_connections: Option<u32>,

    /// 轻包门槛（KB）：succeeded 样本 peak_rss_kb 低于该值不写画像行（builds
    /// 行资源列照记）；0 = 不过滤。
    #[serde(default = "default_resource_profile_min_peak_rss_kb")]
    pub resource_profile_min_peak_rss_kb: i64,

    /// OOM 删失抬升系数：node-OOM 样本的真实需求下界 = 观测峰值 × 本系数
    ///（画像 max 只抬不降不变量要求 ≥1.0；加载期 fail-fast 校验）。
    #[serde(default = "default_resource_censor_headroom")]
    pub resource_censor_headroom: f64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        // 空 TOML 反序列化即默认值：所有字段都有 `#[serde(default)]`（单一事实源
        // 在 defaults:: 模块），避免手工实现双份漂移（同 CrbsConfig::default 惯
        // 用法）。LazyLock 缓存解析：漏标必填字段时 panic 仅首次触发、指向此处。
        static DEFAULTS: std::sync::LazyLock<ServerConfig> = std::sync::LazyLock::new(|| {
            // expect 白名单：空 TOML 必为全默认值（见上）——文档化不变量断言，非运行时风险。
            #[allow(clippy::expect_used)]
            toml::from_str("").expect(
                "empty toml deserializes to ServerConfig defaults; \
                 if this panics, a new required field is missing #[serde(default)]",
            )
        });
        DEFAULTS.clone()
    }
}

/// 提交限流配置（固定窗口、进程内存态）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SubmitRateLimitConfig {
    /// 是否启用；默认 false（批量重建工作流低阈值下会误触发 429）。
    pub enabled: bool,
    /// 窗口内允许的请求数。
    pub requests: u64,
    /// 窗口时长（秒）。
    pub per_secs: u64,
}

impl Default for SubmitRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            requests: 30,
            per_secs: 60,
        }
    }
}

impl ServerConfig {
    /// 返回 server 世界的 crbs_root：显式配置优先，缺省 /var/lib/crbs。
    /// crbs-server 全部子命令与 bootstrap 的 root 解析统一走本助手。
    pub fn server_crbs_root(&self) -> PathBuf {
        self.crbs_root
            .clone()
            .unwrap_or_else(super::defaults::default_crbs_root)
    }

    /// 异步版本：在 `spawn_blocking` 中完成文件 IO 与解析。
    pub async fn load_async(path: &Path) -> crate::Result<Self> {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || Self::load_blocking(&path))
            .await
            .map_err(|e| CrbsError::io_message(format!("load server config: {}", e)))?
    }

    fn load_blocking(path: &Path) -> crate::Result<Self> {
        // 仅 NotFound 视为"未配置走默认"；EACCES/IO 错误必须上抛——exists()
        // 在这些情况下同样返回 false，静默 default 会让服务以错误配置启动。
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(CrbsError::from_io_context("read server config", e)),
        };
        let mut cfg: ServerConfig =
            toml::from_str(&content).map_err(|e| CrbsError::ValidationFailed {
                message: format!("parse server config {}: {}", path.display(), e),
            })?;
        if !(0.0..=1.0).contains(&cfg.low_priority_reserve_ratio) {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "low_priority_reserve_ratio must be between 0.0 and 1.0, got: {}",
                    cfg.low_priority_reserve_ratio
                ),
            });
        }
        // 准入水位系数须为有限正数（NaN/inf 拒）；上界不设——>1 是放宽该维
        // 门的实验语义（cpu 的 load1 可超 ncpu），非法值拒启而非静默回退。
        for (key, value) in [
            ("resource_mem_watermark", cfg.resource_mem_watermark),
            ("resource_cpu_watermark", cfg.resource_cpu_watermark),
        ] {
            if !value.is_finite() || value <= 0.0 {
                return Err(CrbsError::ValidationFailed {
                    message: format!("{key} must be a finite value > 0.0, got: {value}"),
                });
            }
        }
        // 启用时窗口参数必须有效：per_secs = 0 → 窗口永不过期（限流 fail-open）、requests = 0 → 429 所有请求。
        if cfg.submit_rate_limit.enabled {
            if cfg.submit_rate_limit.requests < 1 {
                return Err(CrbsError::ValidationFailed {
                    message: format!(
                        "submit_rate_limit.requests must be >= 1 when submit_rate_limit.enabled, got: {}",
                        cfg.submit_rate_limit.requests
                    ),
                });
            }
            if cfg.submit_rate_limit.per_secs < 1 {
                return Err(CrbsError::ValidationFailed {
                    message: format!(
                        "submit_rate_limit.per_secs must be >= 1 when submit_rate_limit.enabled, got: {}",
                        cfg.submit_rate_limit.per_secs
                    ),
                });
            }
        }
        // 巨值字节换算 saturating_mul 静默饱和到 usize::MAX（上传上限事实上无限 /
        // 调度器永远拒绝派发），加载期 fail-fast；上界 1<<20 MiB/GiB 低于饱和区间。
        const MAX_UPLOAD_MAX_SIZE_MB: usize = 1 << 20;
        const MAX_MIN_FREE_DISK_GB: usize = 1 << 20;
        if cfg.upload_max_size_mb > MAX_UPLOAD_MAX_SIZE_MB {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "upload_max_size_mb must be at most {} MiB, got: {}",
                    MAX_UPLOAD_MAX_SIZE_MB, cfg.upload_max_size_mb
                ),
            });
        }
        if cfg.min_free_disk_gb > MAX_MIN_FREE_DISK_GB {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "min_free_disk_gb must be at most {} GiB, got: {}",
                    MAX_MIN_FREE_DISK_GB, cfg.min_free_disk_gb
                ),
            });
        }
        // db_retention_days 以 i64 进入 prune 的 SQL "N 天前" 时间运算：≥ 2^63
        // 回绕成负数会把 cutoff 推到未来、一次清空全部历史行（0 = 禁用，合法）。
        super::validation::require_i64_representable_u64(
            "db_retention_days",
            cfg.db_retention_days,
        )?;
        // 删失抬升系数：<1 或非有限让 max 不抬甚至倒降（画像 max 只抬不降不变量），加载期 fail-fast。
        if !cfg.resource_censor_headroom.is_finite() || cfg.resource_censor_headroom < 1.0 {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "resource_censor_headroom must be a finite value >= 1.0, got: {}",
                    cfg.resource_censor_headroom
                ),
            });
        }
        // 轻包门槛为负会把样本比较逻辑倒置（语义上不存在"负内存"），拒绝。
        if cfg.resource_profile_min_peak_rss_kb < 0 {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "resource_profile_min_peak_rss_kb must be >= 0, got: {}",
                    cfg.resource_profile_min_peak_rss_kb
                ),
            });
        }
        // heavy 判定的 SRPM 阈值为负同理倒置（0 = 禁用该臂，合法）。
        if cfg.resource_heavy_srpm_bytes < 0 {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "resource_heavy_srpm_bytes must be >= 0, got: {}",
                    cfg.resource_heavy_srpm_bytes
                ),
            });
        }
        super::validation::validate_opt_path(&mut cfg.crbs_root, "server.crbs_root")?;
        super::validation::validate_opt_path(&mut cfg.result_dir, "server.result_dir")?;
        super::validation::validate_opt_path(&mut cfg.upload_dir, "server.upload_dir")?;
        super::validation::validate_opt_path(&mut cfg.state_db_path, "server.state_db_path")?;
        super::validation::validate_opt_path(&mut cfg.artifact_dir, "server.artifact_dir")?;
        // 三大目录两两不得重合，按 resolve 后的**有效目录**比较：显式配置优先，
        // 未配置按 server root 派生（{root}/uploads、{root}/artifacts、{root}/results，
        // 复用下方三个访问器）。互斥原因：upload/artifact 的 `{build_id}/` 与 result
        // 的 `{task_id}/` 分属不同 id 命名空间，重合后对账清扫（staging /
        // artifacts_gc / tasks_gc）把对方目录当孤儿清掉（task 清扫删掉 staging 的
        // build_id 目录 → worker 拉源码 404）。
        // 边界：crbs.toml 全局 result_dir 的跨文件覆盖链（server 侧
        // `AppState::result_dir_for`）bootstrap 才收口、加载期不可见——指到
        // {server_root}/results 的病态配置被误拒，反向指到 uploads/artifacts 的
        // 真实重合则漏检（收口在 bootstrap.rs 启动预检，目前只预检可写）。
        // 比较用 validate_config_path 词法规范化形式（加载期目录未必存在，不能
        // canonicalize；派生值由规范化 root + 字面后缀拼出）。
        let server_root = cfg.server_crbs_root();
        let dir_fields = [
            (
                "server.result_dir",
                cfg.result_dir(&server_root.join("results")),
            ),
            ("server.upload_dir", cfg.upload_dir(&server_root)),
            ("server.artifact_dir", cfg.artifact_dir(&server_root)),
        ];
        for i in 0..dir_fields.len() {
            let (name_a, dir_a) = &dir_fields[i];
            for (name_b, dir_b) in dir_fields.iter().skip(i + 1) {
                if dir_a == dir_b {
                    return Err(CrbsError::ValidationFailed {
                        message: format!(
                            "{name_a} and {name_b} must not be the same directory: {} \
                             (effective value: explicitly configured or derived from crbs_root)",
                            dir_a.display()
                        ),
                    });
                }
            }
        }
        if let Some(ref tls) = cfg.tls {
            let cert = super::validation::validate_config_path(&tls.cert, "server.tls.cert")?;
            let key = super::validation::validate_config_path(&tls.key, "server.tls.key")?;
            cfg.tls = Some(ServerTlsConfig { cert, key });
        }
        Ok(cfg)
    }

    /// 返回上传大小上限（字节）。
    pub fn upload_max_size_bytes(&self) -> usize {
        self.upload_max_size_mb.saturating_mul(1024 * 1024)
    }

    /// 返回要求保留的最小剩余磁盘空间（字节）。
    pub fn min_free_disk_bytes(&self) -> u64 {
        self.min_free_disk_gb.saturating_mul(1024 * 1024 * 1024) as u64
    }

    /// 返回产物根目录；未配置时用调用方给定的 `fallback`。
    pub fn result_dir(&self, fallback: &Path) -> PathBuf {
        self.result_dir
            .clone()
            .unwrap_or_else(|| fallback.to_path_buf())
    }

    /// 返回上传暂存目录；未配置时落在 `{crbs_root}/uploads`。
    pub fn upload_dir(&self, crbs_root: &Path) -> PathBuf {
        self.upload_dir
            .clone()
            .unwrap_or_else(|| crbs_root.join("uploads"))
    }

    /// 返回 state DB 文件路径；未配置时落在 `{crbs_root}/crbs.db`。
    pub fn state_db_path(&self, crbs_root: &Path) -> PathBuf {
        self.state_db_path
            .clone()
            .unwrap_or_else(|| crbs_root.join("crbs.db"))
    }

    /// 返回 Worker 日志持久化目录；未配置时落在 `{crbs_root}/artifacts`。
    pub fn artifact_dir(&self, crbs_root: &Path) -> PathBuf {
        self.artifact_dir
            .clone()
            .unwrap_or_else(|| crbs_root.join("artifacts"))
    }
}

// 本组 default_* 与 default_log_sanitization_redact_tokens 均 pub(crate)：
// schema_tests 直接调用其格式化期望值，钉住 schema 文档与 serde 默认值 parity。
pub(crate) fn default_listen() -> String {
    "127.0.0.1:9090".into()
}

pub(crate) fn default_shutdown_timeout_secs() -> u64 {
    60
}

pub(crate) fn default_build_timeout_secs() -> u64 {
    86_400
}

pub(crate) fn default_upload_max_size_mb() -> usize {
    500
}

pub(crate) fn default_min_free_disk_gb() -> usize {
    1
}

pub(crate) fn default_gc_result_retention() -> usize {
    100
}

pub(crate) fn default_db_retention_days() -> u64 {
    90
}

pub(crate) fn default_local_enable() -> bool {
    true
}

pub(crate) fn default_local_daemon_auto() -> bool {
    false
}

pub(crate) fn default_local_idle_timeout_secs() -> u64 {
    300
}

pub(crate) fn default_low_priority_reserve_ratio() -> f64 {
    0.25
}

pub(crate) fn default_auth_enabled() -> bool {
    true
}

pub(crate) fn default_public_access() -> bool {
    true
}

pub(crate) fn default_web_ui_enabled() -> bool {
    true
}

pub(crate) fn default_force_secure_cookies() -> bool {
    false
}

pub(crate) fn default_allow_srpm_download() -> bool {
    true
}

pub(crate) fn default_resource_profile_min_peak_rss_kb() -> i64 {
    1_048_576
}

// 学习面权重消费默认开（回填保证权重源切换时连续）。
pub(crate) fn default_resource_profile_weights_enabled() -> bool {
    true
}

// 删失默认系数单一事实源 = profiles 模块（state 层学习决策与 config 文档不双写）。
pub(crate) fn default_resource_censor_headroom() -> f64 {
    crate::state::DEFAULT_CENSOR_HEADROOM
}

pub(crate) fn default_resource_heavy_srpm_bytes() -> i64 {
    104_857_600
}

// 分布式水位门默认开（特性既有的行为基线；开关是运维退路，不改变灰度语义）。
pub(crate) fn default_resource_dispatch_watermark_enabled() -> bool {
    true
}

pub(crate) fn default_resource_hard_req_stall_secs() -> u64 {
    3600
}

// 准入水位系数默认值单一事实源 = server.rs（profiles.rs 的 AdmitWatermarks
// 默认经此处 serde 默认链对齐，不双写常量）。
pub(crate) fn default_resource_mem_watermark() -> f64 {
    0.90
}

pub(crate) fn default_resource_cpu_watermark() -> f64 {
    1.00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.listen, "127.0.0.1:9090");
        assert_eq!(cfg.shutdown_timeout_secs, 60);
        assert_eq!(cfg.upload_max_size_mb, 500);
        assert_eq!(cfg.gc_result_retention, 100);
        assert!(!cfg.allow_product_management);
        assert_eq!(cfg.low_priority_reserve_ratio, 0.25);
        assert_eq!(cfg.build_timeout_secs, 86_400);
        // 资源画像两键：轻包门槛 1GiB、删失抬升 1.25。
        assert_eq!(cfg.resource_profile_min_peak_rss_kb, 1_048_576);
        assert_eq!(cfg.resource_censor_headroom, 1.25);
        // 消费两键：硬下限默认关、学习权重默认开。
        assert!(!cfg.resource_requirements_enabled);
        assert!(cfg.resource_profile_weights_enabled);
        // 分布式水位门默认开（既有行为）；硬下限停滞提示默认 1h。
        assert!(cfg.resource_dispatch_watermark_enabled);
        assert_eq!(cfg.resource_hard_req_stall_secs, 3600);
        assert!(!cfg.resource_tmpfs_gate_enforced);
        assert_eq!(cfg.resource_mem_watermark, 0.90);
        assert_eq!(cfg.resource_cpu_watermark, 1.00);
    }

    /// 准入水位系数：默认 = 既有常量基线（行为不变）；显式值解析生效；
    /// ≤0 / NaN 加载期 fail-fast 拒启（NaN 不满足 >0 同拒），>1 放宽属实验
    /// 语义不拒绝。
    #[test]
    fn test_admit_watermark_keys_defaults_parse_and_validation() {
        let tmp = tempfile::tempdir().unwrap();

        // 默认 + 显式值。
        let path = write_server_toml(
            tmp.path(),
            "resource_mem_watermark = 0.8\nresource_cpu_watermark = 1.05\n",
        );
        let cfg = ServerConfig::load_blocking(&path).unwrap();
        assert_eq!(cfg.resource_mem_watermark, 0.8);
        assert_eq!(cfg.resource_cpu_watermark, 1.05);

        // 非法值（含 NaN）拒启，错误点名键。
        for (key, bad) in [
            ("resource_mem_watermark", "0"),
            ("resource_mem_watermark", "-0.5"),
            ("resource_mem_watermark", "nan"),
            ("resource_cpu_watermark", "0"),
            ("resource_cpu_watermark", "nan"),
        ] {
            let path = write_server_toml(tmp.path(), &format!("{key} = {bad}\n"));
            let err = ServerConfig::load_blocking(&path).unwrap_err();
            assert!(
                err.to_string().contains(key),
                "{key} = {bad} must be rejected naming the key, got: {err}"
            );
        }

        // >1 放宽（实验语义）合法。
        let path = write_server_toml(tmp.path(), "resource_cpu_watermark = 1.2\n");
        let cfg = ServerConfig::load_blocking(&path).unwrap();
        assert_eq!(cfg.resource_cpu_watermark, 1.2);
    }

    /// resource_censor_headroom 加载期校验：非有限 / <1.0 拒绝（画像 max 只抬
    /// 不降不变量），>=1.0 合法；resource_profile_min_peak_rss_kb 负值拒绝、0 合法。
    #[test]
    fn test_load_config_rejects_invalid_resource_profile_keys() {
        let tmp = tempfile::tempdir().unwrap();
        for bad in ["0.5", "0.99", "nan", "inf", "-inf"] {
            let path =
                write_server_toml(tmp.path(), &format!("resource_censor_headroom = {bad}\n"));
            let err = ServerConfig::load_blocking(&path).unwrap_err();
            assert!(
                err.to_string().contains("resource_censor_headroom"),
                "headroom {bad} must be rejected, got: {err}"
            );
        }
        for (ok, expect) in [("1.0", 1.0), ("1.25", 1.25), ("2.5", 2.5)] {
            let path = write_server_toml(tmp.path(), &format!("resource_censor_headroom = {ok}\n"));
            let cfg = ServerConfig::load_blocking(&path).unwrap();
            assert_eq!(cfg.resource_censor_headroom, expect);
        }
        let path = write_server_toml(tmp.path(), "resource_profile_min_peak_rss_kb = -1\n");
        let err = ServerConfig::load_blocking(&path).unwrap_err();
        assert!(err.to_string().contains("resource_profile_min_peak_rss_kb"));
        let path = write_server_toml(
            tmp.path(),
            "resource_profile_min_peak_rss_kb = 0\nresource_censor_headroom = 1.25\n",
        );
        let cfg = ServerConfig::load_blocking(&path).unwrap();
        assert_eq!(cfg.resource_profile_min_peak_rss_kb, 0);
    }

    /// build_timeout_secs 显式 0（关闭兜底）与正数均合法：全 u64 取值有语义，无 load 期拒绝。
    #[test]
    fn test_build_timeout_secs_zero_and_positive_accepted() {
        for (value, expect) in [(0, 0u64), (3600, 3600)] {
            let cfg: ServerConfig =
                toml::from_str(&format!("build_timeout_secs = {value}\n")).unwrap();
            assert_eq!(cfg.build_timeout_secs, expect, "value {value} must parse");
        }
    }

    /// server root 缺省 = /var/lib/crbs（非引擎 root）；显式配置生效，非法值被路径校验拒绝。
    #[test]
    fn test_server_crbs_root_default_and_explicit() {
        let cfg = ServerConfig::default();
        assert!(cfg.crbs_root.is_none());
        assert_eq!(
            cfg.server_crbs_root(),
            PathBuf::from("/var/lib/crbs"),
            "server root must default to /var/lib/crbs, not the engine root"
        );

        let cfg: ServerConfig = toml::from_str("crbs_root = \"/data/server-root\"\n").unwrap();
        assert_eq!(cfg.server_crbs_root(), PathBuf::from("/data/server-root"));
    }

    #[test]
    fn test_server_crbs_root_rejects_relative_path() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_server_toml(tmp.path(), "crbs_root = \"relative/root\"\n");
        let err = ServerConfig::load_blocking(&path).unwrap_err();
        assert!(
            err.to_string().contains("server.crbs_root"),
            "error should name the field, got: {err}"
        );
    }

    #[test]
    fn test_upload_max_size_bytes() {
        let cfg = ServerConfig {
            upload_max_size_mb: 1,
            ..Default::default()
        };
        assert_eq!(cfg.upload_max_size_bytes(), 1024 * 1024);
    }

    #[test]
    fn test_min_free_disk_bytes() {
        let cfg = ServerConfig {
            min_free_disk_gb: 2,
            ..Default::default()
        };
        assert_eq!(cfg.min_free_disk_bytes(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_default_config_has_no_tls() {
        let cfg = ServerConfig::default();
        assert!(cfg.tls.is_none());
    }

    #[test]
    fn test_default_force_secure_cookies_off() {
        let cfg = ServerConfig::default();
        assert!(
            !cfg.force_secure_cookies,
            "force_secure_cookies must default to false to keep loopback dev working"
        );
    }

    #[test]
    fn test_load_config_with_tls() {
        let tmp = tempfile::tempdir().unwrap();
        let cert_path = tmp.path().join("server.crt");
        let key_path = tmp.path().join("server.key");
        std::fs::write(&cert_path, "test cert").unwrap();
        std::fs::write(&key_path, "test key").unwrap();

        let config_path = tmp.path().join("server.toml");
        let content = format!(
            "listen = \"127.0.0.1:9090\"\n[tls]\ncert = \"{}\"\nkey = \"{}\"\n",
            cert_path.display(),
            key_path.display()
        );
        std::fs::write(&config_path, content).unwrap();

        let cfg = ServerConfig::load_blocking(&config_path).unwrap();
        assert!(cfg.tls.is_some());
        let tls = cfg.tls.unwrap();
        assert_eq!(tls.cert, cert_path);
        assert_eq!(tls.key, key_path);
    }

    fn write_server_toml(dir: &std::path::Path, content: &str) -> std::path::PathBuf {
        let path = dir.join("server.toml");
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_load_config_rejects_out_of_range_low_priority_reserve_ratio() {
        let tmp = tempfile::tempdir().unwrap();
        for bad in ["1.5", "-0.1"] {
            let path =
                write_server_toml(tmp.path(), &format!("low_priority_reserve_ratio = {bad}\n"));
            let err = ServerConfig::load_blocking(&path).unwrap_err();
            assert!(err.to_string().contains("low_priority_reserve_ratio"));
        }
        for ok in ["0.0", "1.0"] {
            let path =
                write_server_toml(tmp.path(), &format!("low_priority_reserve_ratio = {ok}\n"));
            assert!(ServerConfig::load_blocking(&path).is_ok());
        }
    }

    #[test]
    fn test_submit_rate_limit_defaults_parsing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_server_toml(tmp.path(), "[submit_rate_limit]\nenabled = true\n");
        let cfg = ServerConfig::load_blocking(&path).unwrap();
        assert!(cfg.submit_rate_limit.enabled);
        assert_eq!(cfg.submit_rate_limit.requests, 30);
        assert_eq!(cfg.submit_rate_limit.per_secs, 60);
    }

    /// db_max_connections 可选键：未设置 None（env/默认 8 生效）；0 走运行期
    /// warn 回退不 fail-fast；负数/超 u32 在反序列化期直接报错。
    #[test]
    fn test_db_max_connections_parsing() {
        assert_eq!(ServerConfig::default().db_max_connections, None);

        let cfg: ServerConfig = toml::from_str("db_max_connections = 16\n").unwrap();
        assert_eq!(cfg.db_max_connections, Some(16));

        let cfg: ServerConfig = toml::from_str("db_max_connections = 0\n").unwrap();
        assert_eq!(cfg.db_max_connections, Some(0));

        assert!(toml::from_str::<ServerConfig>("db_max_connections = -1\n").is_err());
        assert!(toml::from_str::<ServerConfig>("db_max_connections = 5000000000\n").is_err());
    }

    /// 两两重合加载期拒绝（对账清扫按各自 id 命名空间删目录，重合互删对方）；
    /// 词法规范化（`..` 折叠）后相同同样拒绝；只配其一时正常加载。
    #[test]
    fn test_load_config_rejects_overlapping_result_upload_artifact_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let cases = [
            "result_dir = \"/data/x\"\nupload_dir = \"/data/x\"\n",
            "result_dir = \"/data/x\"\nartifact_dir = \"/data/x\"\n",
            "upload_dir = \"/data/x\"\nartifact_dir = \"/data/x\"\n",
            "result_dir = \"/data/../data/x\"\nupload_dir = \"/data/x\"\n",
        ];
        for content in cases {
            let path = write_server_toml(tmp.path(), content);
            let err = ServerConfig::load_blocking(&path).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("must not be the same directory"),
                "overlap must be rejected, got: {msg}"
            );
            assert!(
                msg.contains("server.result_dir")
                    || msg.contains("server.upload_dir")
                    || msg.contains("server.artifact_dir"),
                "error should name the conflicting fields, got: {msg}"
            );
        }

        let path = write_server_toml(tmp.path(), "upload_dir = \"/data/x\"\n");
        assert!(ServerConfig::load_blocking(&path).is_ok());
    }

    /// 显式值恰等于对方派生默认值（如 result_dir = {root}/uploads 而未配
    /// upload_dir）同样拒绝：按 resolve 后的有效目录比较。
    #[test]
    fn test_load_config_rejects_explicit_dir_equal_to_derived_default() {
        let tmp = tempfile::tempdir().unwrap();
        // 显式 crbs_root 让派生默认可预测；三对各验一个方向。
        let cases = [
            "crbs_root = \"/data/root\"\nresult_dir = \"/data/root/uploads\"\n",
            "crbs_root = \"/data/root\"\nupload_dir = \"/data/root/results\"\n",
            "crbs_root = \"/data/root\"\nartifact_dir = \"/data/root/uploads\"\n",
        ];
        for content in cases {
            let path = write_server_toml(tmp.path(), content);
            let err = ServerConfig::load_blocking(&path).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("must not be the same directory"),
                "explicit-vs-derived overlap must be rejected, got: {msg}"
            );
        }

        // 正常不重合：三个显式目录互异（且不同于任何派生默认）→ 放行。
        let path = write_server_toml(
            tmp.path(),
            "crbs_root = \"/data/root\"\nresult_dir = \"/data/r\"\nupload_dir = \"/data/u\"\nartifact_dir = \"/data/a\"\n",
        );
        assert!(ServerConfig::load_blocking(&path).is_ok());
    }

    #[test]
    fn test_submit_rate_limit_enabled_rejects_zero_window() {
        let tmp = tempfile::tempdir().unwrap();

        let path = write_server_toml(
            tmp.path(),
            "[submit_rate_limit]\nenabled = true\nrequests = 0\n",
        );
        let err = ServerConfig::load_blocking(&path).unwrap_err();
        assert!(err.to_string().contains("submit_rate_limit.requests"));

        let path = write_server_toml(
            tmp.path(),
            "[submit_rate_limit]\nenabled = true\nper_secs = 0\n",
        );
        let err = ServerConfig::load_blocking(&path).unwrap_err();
        assert!(err.to_string().contains("submit_rate_limit.per_secs"));

        let path = write_server_toml(
            tmp.path(),
            "[submit_rate_limit]\nenabled = true\nrequests = 1\nper_secs = 1\n",
        );
        assert!(ServerConfig::load_blocking(&path).is_ok());
    }

    #[test]
    fn test_submit_rate_limit_disabled_allows_zero_values() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_server_toml(
            tmp.path(),
            "[submit_rate_limit]\nenabled = false\nrequests = 0\nper_secs = 0\n",
        );
        let cfg = ServerConfig::load_blocking(&path).unwrap();
        assert!(!cfg.submit_rate_limit.enabled);
    }

    /// 巨值字节换算 saturating_mul 静默饱和到 usize::MAX（上限事实上无限 /
    /// 调度器永远拒绝），加载期拒绝；边界值 1<<20 合法。
    #[test]
    fn test_load_config_rejects_oversized_upload_and_disk_caps() {
        let tmp = tempfile::tempdir().unwrap();

        let path = write_server_toml(
            tmp.path(),
            &format!("upload_max_size_mb = {}\n", (1 << 20) + 1),
        );
        let err = ServerConfig::load_blocking(&path).unwrap_err();
        assert!(err.to_string().contains("upload_max_size_mb"));

        let path = write_server_toml(
            tmp.path(),
            &format!("min_free_disk_gb = {}\n", (1 << 20) + 1),
        );
        let err = ServerConfig::load_blocking(&path).unwrap_err();
        assert!(err.to_string().contains("min_free_disk_gb"));

        let path = write_server_toml(
            tmp.path(),
            &format!(
                "upload_max_size_mb = {}\nmin_free_disk_gb = {}\n",
                1 << 20,
                1 << 20
            ),
        );
        let cfg = ServerConfig::load_blocking(&path).unwrap();
        assert_eq!(cfg.upload_max_size_mb, 1 << 20);
        assert_eq!(cfg.min_free_disk_gb, 1 << 20);
    }

    /// db_retention_days ≥ 2^63 在 prune 的 SQL "N 天前" 运算中回绕成负数，
    /// cutoff 推到未来会一次清空全部历史行；0 = 禁用是合法哨兵值。
    #[test]
    fn test_load_config_rejects_db_retention_days_beyond_i64() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_server_toml(
            tmp.path(),
            &format!("db_retention_days = {}\n", i64::MAX as u64 + 1),
        );
        let err = ServerConfig::load_blocking(&path).unwrap_err();
        assert!(err.to_string().contains("db_retention_days"));

        let path = write_server_toml(tmp.path(), "db_retention_days = 0\n");
        assert!(ServerConfig::load_blocking(&path).is_ok());
        let path = write_server_toml(
            tmp.path(),
            &format!("db_retention_days = {}\n", i64::MAX as u64),
        );
        assert!(ServerConfig::load_blocking(&path).is_ok());
    }

    #[test]
    fn test_local_and_log_sanitization_defaults_from_empty_toml() {
        let cfg: ServerConfig = toml::from_str("").unwrap();
        assert!(cfg.local.enable);
        assert!(!cfg.local.daemon_auto);
        assert_eq!(cfg.local.run_dir, None);
        assert_eq!(cfg.local.idle_timeout_secs, 300);
        assert!(cfg.log_sanitization.redact_tokens);
        assert!(!cfg.log_sanitization.redact_urls);
        assert!(!cfg.log_sanitization.redact_paths);
    }

    #[test]
    fn test_unknown_fields_rejected() {
        use crate::config::types::{HooksConfig, RemoteConfig, RemoteProfile, SpecHooksConfig};

        assert!(toml::from_str::<LocalConfig>("enable = true\nbogus = 1\n").is_err());
        assert!(
            toml::from_str::<ServerTlsConfig>("cert = \"/a\"\nkey = \"/b\"\nbogus = 1\n").is_err()
        );
        assert!(toml::from_str::<RemoteConfig>("default = \"x\"\nbogus = 1\n").is_err());
        assert!(
            toml::from_str::<RemoteProfile>("name = \"x\"\nurl = \"http://x\"\nbogus = 1\n")
                .is_err(),
            "unknown key inside remote profile must be rejected"
        );
        // HooksConfig / SpecHooksConfig：pre/post/spec 是结构字段，
        // hook step 名是 map key 不受 deny_unknown_fields 影响
        assert!(toml::from_str::<HooksConfig>("[pre]\nstep = \"echo\"\nbogus = 1\n").is_err());
        assert!(toml::from_str::<SpecHooksConfig>("[pre]\nstep = \"echo\"\nbogus = 1\n").is_err());
        let hooks: HooksConfig = toml::from_str("[pre]\nany-step-name = \"echo ok\"\n").unwrap();
        assert_eq!(
            hooks.pre.get("any-step-name").map(String::as_str),
            Some("echo ok")
        );
    }
}
