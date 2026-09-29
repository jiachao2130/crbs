// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Worker 配置解析。

use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::Deserialize;

/// HTTP 客户端全局兜底超时（秒）：单文件产物上限 2GB，慢链路上传可远超 30s。
/// 产物上传每次重试尝试的超时（`executor/upload.rs`）必须与之对齐，否则重试层会先于客户端掐断上传。
pub(crate) const HTTP_FALLBACK_TIMEOUT_SECS: u64 = 600;

/// 心跳间隔下限（秒）：低于此值请求级超时 `min(间隔, 10s)` 失去保护意义，且高频心跳放大 Hub 压力——load 时 fail-fast。
const MIN_HEARTBEAT_INTERVAL_SECS: u64 = 5;

/// 心跳间隔上限（秒）：hub 心跳新鲜度阈值 120s（crbs-core state workers SQL 的 2min 窗口），
/// 间隔贴近/超过则 worker 永远不可调度、assignment 被周期回收重派（静默瘫痪）——load 时 fail-fast 而非静默接受。
const MAX_HEARTBEAT_INTERVAL_SECS: u64 = 110;

/// 长轮询超时下限（秒）：下限 5 保证 wait ≥ 1（减 5 的余量后不滑落 0/忙轮询），
/// 也留出请求级超时的保护意义。poll 请求显式携带 `?wait=<poll_timeout-5（钳 1..=115）>`。
const MIN_POLL_TIMEOUT_SECS: u64 = 5;

/// 长轮询超时上限（秒）：客户端整体超时须显著低于 hub 心跳新鲜度阈值的双倍回收窗口，过大让 poll
/// 长期占用连接、心跳在长轮询 shadow 下失真——上限 125 保证 wait ≤ 115（服务端 clamp 120s 内、
/// 客户端超时恒大于服务端 wait）；超出范围 fail-fast，不静默钳制。
const MAX_POLL_TIMEOUT_SECS: u64 = 125;

/// capacity 合法上限：与 server 注册端点（`MAX_WORKER_CAPACITY`）同口径。幽灵 capacity（如 i64::MAX）
/// 会被派发又因心跳超时回收，形成派发-回收-再派发的队列 DoS——超出范围 fail-fast，不静默钳制。
const MAX_WORKER_CAPACITY: i64 = 1024;

/// 启动期孤儿挂载 GC 模式（小写字符串反序列化，非法值如 `"sometimes"` 在 load 期 fail-fast 报错）。
/// - `Auto`（默认）：由 hub 注册响应的 `has_active_local_builds` 守卫决定（语义见 [`should_run_startup_gc`]）。
/// - `Always`：无条件执行（worker 独占整机的部署可显式开阀）。
/// - `Never`：从不执行（孤儿挂载交 `crbs gc --orphan-mounts` 等带守卫入口）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum StartupMountGc {
    Auto,
    Always,
    Never,
}

/// worker 启动期孤儿挂载 GC 是否执行（纯函数，决策表见测试）。`has_active` 为 hub 注册响应守卫字段：
/// `Some(false)` = hub 确认无活跃构建；`Some(true)` = 有活跃构建（或查询失败时 hub 保守上报）；`None` = 老 hub 不下发。
/// 保守方向是**跳过**——启动 GC 杀错活跃挂载（构建假失败/产物损坏）的代价远高于孤儿多留一轮（hub 侧带守卫 `crbs gc --orphan-mounts` 兜底）。
pub(crate) fn should_run_startup_gc(mode: StartupMountGc, has_active: Option<bool>) -> bool {
    match mode {
        StartupMountGc::Always => true,
        StartupMountGc::Never => false,
        StartupMountGc::Auto => has_active == Some(false),
    }
}

/// Worker 配置。
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerConfig {
    /// Worker 显示名称。
    pub name: String,

    /// Hub 地址（生产建议 `https://hub.example.com:18443`；`http://` 仅用于 loopback dev）。
    pub hub_url: String,

    /// Worker 架构（如 x86_64, aarch64）；未指定时自动探测本地架构（`std::env::consts::ARCH`）。
    #[serde(default)]
    pub arch: Option<String>,

    /// 最大并发构建数。
    #[serde(default = "default_capacity")]
    pub capacity: i64,

    /// API Token（用于认证）。
    pub token: String,

    /// 可选的 Hub CA 证书路径（自签/内网 CA 场景）；未配置时使用系统默认信任库。
    #[serde(default)]
    pub hub_ca_cert: Option<std::path::PathBuf>,

    /// 心跳间隔（秒）。
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,

    /// 长轮询超时（秒）——客户端整体请求超时。poll 请求显式携带 `?wait=<该值-5（≤115）>`：
    /// 服务端长轮询窗口与之对齐（留 5s 余量给服务端 wait 到期后的兜底重查与响应组装；服务端 clamp 120s）。
    #[serde(default = "default_poll_timeout_secs")]
    pub poll_timeout_secs: u64,

    /// 构建临时目录。
    #[serde(default = "default_build_dir")]
    pub build_dir: String,

    /// 本地结果目录保留天数：mtime 超过该天数的构建结果目录
    /// （`{result_dir}/{product}/{pkg}/{ts}-{build_id}/`）由周期 sweeper 删除；0 = 永久保留，默认 3。
    #[serde(default = "default_result_retention_days")]
    pub result_retention_days: u64,

    /// crbs_root 路径（用于启动时清理残留挂载）。
    #[serde(default = "default_crbs_root")]
    pub crbs_root: String,

    /// 构建临时目录（engine 配置的 `tmp_dir`）：启动期孤儿挂载 GC 的扩展扫描域——
    /// overlay 挂载目标在 `{tmp_dir}/.tmpXXXX/root`。引擎默认 tmp_dir 已归一到
    /// `{crbs_root}/tmp`（落在启动 GC 的 crbs_root 子树扫描覆盖内），本默认
    /// /var/tmp 兜住显式自定义引擎 tmp_dir 的部署。**须与部署的 crbs.toml 引擎
    /// 配置 `tmp_dir` 保持一致**：分叉时启动 GC 只覆盖这里声明的目录，
    /// 未覆盖的孤儿由每构建 init 的清理与带守卫的 `crbs gc --orphan-mounts` 兜底。
    #[serde(default = "default_tmp_dir")]
    pub tmp_dir: String,

    /// tmpfs 构建目录（engine 配置的 `tmpfs_dir`，默认 /dev/shm）：语义同
    /// [`WorkerConfig::tmp_dir`]。当前全内存构建（build_tmpfs）已在 `tmp_dir`
    /// 的 tempdir 内挂独立 memroot tmpfs，本域只剩历史残留的清扫职责；仍须与
    /// 部署的 crbs.toml 引擎配置保持一致的 `tmpfs_dir`。
    #[serde(default = "default_tmpfs_dir")]
    pub tmpfs_dir: String,

    /// 启动期孤儿挂载 GC 模式：auto | always | never，默认 auto（hub 注册响应守卫决定，见 [`StartupMountGc`]）。
    #[serde(default = "default_startup_mount_gc")]
    pub startup_mount_gc: StartupMountGc,

    /// 构建超时兜底（秒）：远程构建请求未显式指定 timeout 时的默认值——hang 构建会永久占用
    /// hub running 行 + worker permit（心跳活着 reclaimer 永不回收）。0 = 关闭兜底（不限时），
    /// 默认 86_400（24h）；请求显式 `--timeout` 优先级更高（含 `--timeout 0` = 显式无限）。
    #[serde(default = "default_build_timeout_secs")]
    pub build_timeout_secs: u64,

    /// 领任务前的磁盘水位门（GB）：`build_dir` 所在盘剩余空间低于该值时本轮跳过领任务（满盘继续
    /// 领任务会形成"领取→失败→释放→再领"的失败泵；hub 侧 `min_free_disk_gb` 三处入口拦截，此处为
    /// worker 侧对应闸门）。只拦新领取：心跳照常发送（保持 online 让在跑任务收尾），在跑构建不受影响。
    /// 0 = 关闭水位门（对齐 hub 侧 0 = 禁用语义），默认 1。
    #[serde(default = "default_min_free_disk_gb")]
    pub min_free_disk_gb: u64,

    /// 领任务前的内存水位门（MB）：/proc/meminfo MemAvailable 低于该值时本轮跳过领任务（继续领
    /// 任务会把 OOM 从"构建失败"恶化为"拖垮同机其他构建/系统服务"）。与磁盘水位门同款语义——只拦
    /// 新领取，在跑构建与心跳不受影响；读取 /proc/meminfo 失败放行（fail-open，非 Linux 恒放行）。
    /// 0 = 关闭水位门。默认 512。
    #[serde(default = "default_min_free_mem_mb")]
    pub min_free_mem_mb: u64,

    /// 缓存的 reqwest HTTP client，避免每次请求重建连接池。
    #[serde(skip)]
    client: Arc<Mutex<Option<reqwest::Client>>>,
}

impl fmt::Debug for WorkerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkerConfig")
            .field("name", &self.name)
            .field("hub_url", &self.hub_url)
            .field("arch", &self.arch)
            .field("capacity", &self.capacity)
            .field("token", &"<redacted>")
            .field("heartbeat_interval_secs", &self.heartbeat_interval_secs)
            .field("poll_timeout_secs", &self.poll_timeout_secs)
            .field("build_dir", &self.build_dir)
            .field("result_retention_days", &self.result_retention_days)
            .field("crbs_root", &self.crbs_root)
            .field("tmp_dir", &self.tmp_dir)
            .field("tmpfs_dir", &self.tmpfs_dir)
            .field("startup_mount_gc", &self.startup_mount_gc)
            .field("build_timeout_secs", &self.build_timeout_secs)
            .field("min_free_disk_gb", &self.min_free_disk_gb)
            .field("min_free_mem_mb", &self.min_free_mem_mb)
            .finish()
    }
}

impl WorkerConfig {
    /// 从指定路径加载配置。文件不存在则报错。
    pub async fn load(path: &Path) -> crbs_core::Result<Self> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| crbs_core::error::CrbsError::from_io_context("read worker config", e))?;
        let cfg: WorkerConfig = toml::from_str(&content).map_err(|e| {
            crbs_core::error::CrbsError::ValidationFailed {
                message: format!("parse config {}: {}", path.display(), e),
            }
        })?;
        if !(1..=MAX_WORKER_CAPACITY).contains(&cfg.capacity) {
            return Err(crbs_core::error::CrbsError::ValidationFailed {
                message: format!(
                    "capacity must be in 1..={MAX_WORKER_CAPACITY}, got {}",
                    cfg.capacity
                ),
            });
        }
        ensure_range(
            "heartbeat_interval_secs",
            cfg.heartbeat_interval_secs,
            MIN_HEARTBEAT_INTERVAL_SECS,
            MAX_HEARTBEAT_INTERVAL_SECS,
            // 上限触发的追加说明：贴近 hub 120s 心跳新鲜度阈值 → 永不可调度（语义见常量 doc）。
            "it must stay significantly below the hub-side 120s heartbeat freshness threshold or the worker is never schedulable",
        )?;
        ensure_range(
            "poll_timeout_secs",
            cfg.poll_timeout_secs,
            MIN_POLL_TIMEOUT_SECS,
            MAX_POLL_TIMEOUT_SECS,
            // 上限触发的追加说明：wait = value - 5 须落在服务端 120s 长轮询 clamp 内（语义见常量 doc）。
            "the client request timeout must stay within the hub's 120s long-poll clamp (wait = value - 5, clamped to 1..=115)",
        )?;
        Ok(cfg)
    }

    /// 返回 Worker 架构，未配置时取本地架构。
    pub fn arch(&self) -> &str {
        self.arch.as_deref().unwrap_or(std::env::consts::ARCH)
    }

    /// 水位门字节数：`min_free_disk_gb` 换算为字节（0 保持 0 = 关闭）；saturating 防巨值溢出，与 hub 侧同式。
    pub fn min_free_disk_bytes(&self) -> u64 {
        self.min_free_disk_gb.saturating_mul(1024 * 1024 * 1024)
    }

    /// 内存水位门字节数：`min_free_mem_mb` 换算为字节（0 保持 0 = 关闭）；saturating 防巨值溢出，同 [`Self::min_free_disk_bytes`]。
    pub fn min_free_mem_bytes(&self) -> u64 {
        self.min_free_mem_mb.saturating_mul(1024 * 1024)
    }

    /// 构造信任的 reqwest HTTP client：首次调用构建并缓存，后续调用返回缓存复用连接池；
    /// 配置了 `hub_ca_cert` 则将其加入根证书信任列表，否则使用系统默认信任库。
    pub async fn build_http_client(&self) -> crbs_core::Result<reqwest::Client> {
        {
            // 锁中毒即恢复：临界区只做 clone/replace，无不变量可破坏；不恢复则一次 panic 后到重启前所有请求失败。
            let cached = self.client.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(client) = cached.clone() {
                return Ok(client);
            }
        }

        // 全局兜底超时避免 Hub 无响应时请求永久挂起；长轮询在请求级设置了更短的 timeout，会覆盖此默认值。
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(HTTP_FALLBACK_TIMEOUT_SECS))
            // worker 全站使用同一 token，注入默认头；个别请求级 header 可覆盖。
            .default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                let val = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", self.token))
                    .map_err(|e| crbs_core::error::CrbsError::ValidationFailed {
                        message: format!("invalid worker token header: {e}"),
                    })?;
                h.insert(reqwest::header::AUTHORIZATION, val);
                h
            });
        if let Some(ca_path) = &self.hub_ca_cert {
            let ca_pem = tokio::fs::read(ca_path)
                .await
                .map_err(|e| crbs_core::error::CrbsError::from_io_context("read hub ca cert", e))?;
            let cert = reqwest::Certificate::from_pem(&ca_pem).map_err(|e| {
                crbs_core::error::CrbsError::ValidationFailed {
                    message: format!("parse hub ca cert {}: {}", ca_path.display(), e),
                }
            })?;
            builder = builder.add_root_certificate(cert);
        }
        let client = builder.build().map_err(|e| {
            crbs_core::error::CrbsError::io_message(format!("build http client: {}", e))
        })?;

        self.client
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .replace(client.clone());
        Ok(client)
    }
}

/// 数值范围守护（load 期 fail-fast，不静默钳制）：低/越界句式 ``"<field> must be >= / <= N, got V"``，
/// 上限触发的追加说明由调用方传入（各字段语义不同）；capacity 为 i64 且句式是区间包含形，不共用此处。
fn ensure_range(field: &str, v: u64, min: u64, max: u64, high_hint: &str) -> crbs_core::Result<()> {
    if v < min {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: format!("{field} must be >= {min}, got {v}"),
        });
    }
    if v > max {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: format!("{field} must be <= {max}, got {v}; {high_hint}"),
        });
    }
    Ok(())
}

/// 校验并创建安全的 build_dir：拒绝路径中的 `..`（路径穿越）；目标已存在时必须是目录且非符号链接，
/// 并补齐权限不变量（2770 + group=crbs——部署工具预建的 0755 目录不修正会让 root / crbs-server /
/// crbs 组用户三身份互访永久失败）；创建目录后设置权限 2770 并 chown 到 crbs 组。防 `/tmp` 等可被
/// 其他本地用户写入的目录中预创建符号链接导致的目录劫持或信息泄露。
pub(crate) async fn ensure_safe_build_dir(path: &std::path::Path) -> crbs_core::Result<()> {
    use std::path::Component;

    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: format!(
                "build_dir must not contain '..' components: {}",
                path.display()
            ),
        });
    }

    if tokio::fs::try_exists(path).await.unwrap_or(false) {
        let meta = tokio::fs::symlink_metadata(path)
            .await
            .map_err(|e| crbs_core::error::CrbsError::from_io_context("stat build_dir", e))?;
        if meta.file_type().is_symlink() {
            return Err(crbs_core::error::CrbsError::ValidationFailed {
                message: format!("build_dir is a symlink: {}", path.display()),
            });
        }
        if !meta.is_dir() {
            return Err(crbs_core::error::CrbsError::ValidationFailed {
                message: format!(
                    "build_dir exists but is not a directory: {}",
                    path.display()
                ),
            });
        }
        // 已存在目录同样要满足权限不变量（目录 2770 + group=crbs）；chmod 失败仅 warn（权限未生效，
        // 不阻断本 build），chown 失败仅 debug（非 root chown 必然 EPERM，见 chown_to_crbs_group_async）。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o2770)).await
            {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "Failed to enforce 2770 on existing build_dir"
                );
            }
            crbs_core::privilege::chown_to_crbs_group_async(path, false, "build_dir").await;
        }
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            crbs_core::error::CrbsError::from_io_context("create build_dir parent", e)
        })?;
    }
    tokio::fs::create_dir(path).await.or_else(|e| {
        // 全新 worker 首批任务并发抢建 build_dir 时只有一个 create_dir 成功，其余拿到 AlreadyExists：
        // 此时目录已存在，视为成功并继续走下方安全复检，绝不能裸 return Ok——否则被抢建为符号链接的攻击面重开。
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            Ok(())
        } else {
            Err(crbs_core::error::CrbsError::from_io_context(
                "create build_dir",
                e,
            ))
        }
    })?;

    // 创建后再检查一次，确保没有被抢建为符号链接。
    let meta = tokio::fs::symlink_metadata(path).await.map_err(|e| {
        crbs_core::error::CrbsError::from_io_context("stat build_dir after create", e)
    })?;
    if meta.file_type().is_symlink() {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: format!("build_dir was created as a symlink: {}", path.display()),
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 2770（setgid）：权限不变量——group=crbs 组内 rwx，子目录/文件
        // 继承 crbs 组，root / crbs-server / crbs 组用户三身份可读写。
        let perms = std::fs::Permissions::from_mode(0o2770);
        tokio::fs::set_permissions(path, perms).await.map_err(|e| {
            crbs_core::error::CrbsError::from_io_context("set build_dir permissions", e)
        })?;
        crbs_core::privilege::chown_to_crbs_group_async(path, false, "build_dir").await;
    }

    Ok(())
}

fn default_capacity() -> i64 {
    1
}

fn default_heartbeat_interval_secs() -> u64 {
    30
}

fn default_poll_timeout_secs() -> u64 {
    60
}

fn default_build_dir() -> String {
    "/var/lib/crbs/worker/builds".to_string()
}

fn default_result_retention_days() -> u64 {
    3
}

fn default_crbs_root() -> String {
    "/var/lib/crbs".to_string()
}

/// 引擎默认 tmp_dir 已归一到 {crbs_root}/tmp（crbs_root 子树扫描覆盖）；保留
/// /var/tmp 兜住显式自定义引擎 tmp_dir 的部署——此类部署须在此镜像配置。
fn default_tmp_dir() -> String {
    "/var/tmp".to_string()
}

/// 与 crbs-core 引擎默认 `tmpfs_dir`（/dev/shm）对齐（见 `default_tmp_dir`）。
fn default_tmpfs_dir() -> String {
    "/dev/shm".to_string()
}

fn default_startup_mount_gc() -> StartupMountGc {
    StartupMountGc::Auto
}

/// 构建超时兜底默认 24h（0 = 关闭兜底，语义见字段文档）。
fn default_build_timeout_secs() -> u64 {
    86_400
}

/// 磁盘水位门默认 1GB（对齐 hub 侧 `default_min_free_disk_gb`）。
fn default_min_free_disk_gb() -> u64 {
    1
}

/// 内存水位门默认 512MB：容纳 rpmbuild 尾段 + dnf 元数据的余量下限，又不至于把低配节点（2-4GB）关到常态跳过。
fn default_min_free_mem_mb() -> u64 {
    512
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_load_valid_config() {
        let content = r#"
name = "worker-01"
hub_url = "http://localhost:8080"
arch = "x86_64"
capacity = 2
token = "test-token"
"#;
        let temp = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(temp.path(), content).await.unwrap();

        let cfg = WorkerConfig::load(temp.path()).await.unwrap();
        assert_eq!(cfg.name, "worker-01");
        assert_eq!(cfg.hub_url, "http://localhost:8080");
        assert_eq!(cfg.arch(), "x86_64");
        assert_eq!(cfg.capacity, 2);
        assert_eq!(cfg.token, "test-token");
        assert_eq!(cfg.heartbeat_interval_secs, 30);
        assert_eq!(cfg.poll_timeout_secs, 60);
    }

    #[tokio::test]
    async fn test_load_missing_file() {
        let result = WorkerConfig::load(Path::new("/nonexistent/worker.toml")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_load_rejects_too_small_heartbeat_interval() {
        let content = r#"
name = "w"
hub_url = "http://h"
token = "t"
heartbeat_interval_secs = 4
"#;
        let temp = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(temp.path(), content).await.unwrap();
        let result = WorkerConfig::load(temp.path()).await;
        assert!(
            result.is_err(),
            "heartbeat_interval_secs=4 must be rejected"
        );
    }

    #[tokio::test]
    async fn test_load_rejects_too_large_heartbeat_interval() {
        for interval in ["111", "120", "3600"] {
            let content = format!(
                "name = \"w\"\nhub_url = \"http://h\"\ntoken = \"t\"\nheartbeat_interval_secs = {interval}\n"
            );
            let temp = tempfile::NamedTempFile::new().unwrap();
            tokio::fs::write(temp.path(), &content).await.unwrap();
            let result = WorkerConfig::load(temp.path()).await;
            assert!(
                result.is_err(),
                "heartbeat_interval_secs={interval} must be rejected (above hub 120s freshness threshold)"
            );
        }
        let content =
            "name = \"w\"\nhub_url = \"http://h\"\ntoken = \"t\"\nheartbeat_interval_secs = 110\n";
        let temp = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(temp.path(), &content).await.unwrap();
        let result = WorkerConfig::load(temp.path()).await;
        assert!(
            result.is_ok(),
            "heartbeat_interval_secs=110 must be accepted"
        );
    }

    #[tokio::test]
    async fn test_load_rejects_too_small_poll_timeout() {
        for value in ["0", "1", "4"] {
            let content = format!(
                "name = \"w\"\nhub_url = \"http://h\"\ntoken = \"t\"\npoll_timeout_secs = {value}\n"
            );
            let temp = tempfile::NamedTempFile::new().unwrap();
            tokio::fs::write(temp.path(), &content).await.unwrap();
            let result = WorkerConfig::load(temp.path()).await;
            assert!(
                result.is_err(),
                "poll_timeout_secs={value} must be rejected"
            );
        }
        let content =
            "name = \"w\"\nhub_url = \"http://h\"\ntoken = \"t\"\npoll_timeout_secs = 5\n";
        let temp = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(temp.path(), content).await.unwrap();
        assert!(WorkerConfig::load(temp.path()).await.is_ok());
    }

    #[tokio::test]
    async fn test_load_rejects_too_large_poll_timeout() {
        for value in ["126", "300", "18446744073709551615"] {
            let content = format!(
                "name = \"w\"\nhub_url = \"http://h\"\ntoken = \"t\"\npoll_timeout_secs = {value}\n"
            );
            let temp = tempfile::NamedTempFile::new().unwrap();
            tokio::fs::write(temp.path(), &content).await.unwrap();
            let result = WorkerConfig::load(temp.path()).await;
            assert!(
                result.is_err(),
                "poll_timeout_secs={value} must be rejected"
            );
        }
        let content =
            "name = \"w\"\nhub_url = \"http://h\"\ntoken = \"t\"\npoll_timeout_secs = 125\n";
        let temp = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(temp.path(), content).await.unwrap();
        assert!(WorkerConfig::load(temp.path()).await.is_ok());
    }

    #[tokio::test]
    async fn test_load_rejects_capacity_out_of_range() {
        for capacity in ["0", "-1", "1025", "9223372036854775807"] {
            let content = format!(
                "name = \"w\"\nhub_url = \"http://h\"\ntoken = \"t\"\ncapacity = {capacity}\n"
            );
            let temp = tempfile::NamedTempFile::new().unwrap();
            tokio::fs::write(temp.path(), content).await.unwrap();
            let result = WorkerConfig::load(temp.path()).await;
            assert!(
                result.is_err(),
                "capacity={capacity} must be rejected (fail-fast, no silent clamp)"
            );
        }
        for capacity in ["1", "1024"] {
            let content = format!(
                "name = \"w\"\nhub_url = \"http://h\"\ntoken = \"t\"\ncapacity = {capacity}\n"
            );
            let temp = tempfile::NamedTempFile::new().unwrap();
            tokio::fs::write(temp.path(), content).await.unwrap();
            let result = WorkerConfig::load(temp.path()).await;
            assert!(result.is_ok(), "capacity={capacity} must be accepted");
        }
    }

    /// ensure_range 消息句式钉死（低/高界与高界追加说明），防共享后文案漂移。
    #[test]
    fn ensure_range_messages_are_verbatim() {
        match ensure_range("heartbeat_interval_secs", 4, 5, 110, "high hint") {
            Err(crbs_core::error::CrbsError::ValidationFailed { message }) => {
                assert_eq!(message, "heartbeat_interval_secs must be >= 5, got 4");
            }
            other => panic!("expected low-bound ValidationFailed, got {other:?}"),
        }
        match ensure_range("poll_timeout_secs", 126, 5, 125, "high hint") {
            Err(crbs_core::error::CrbsError::ValidationFailed { message }) => {
                assert_eq!(
                    message,
                    "poll_timeout_secs must be <= 125, got 126; high hint"
                );
            }
            other => panic!("expected high-bound ValidationFailed, got {other:?}"),
        }
        assert!(ensure_range("poll_timeout_secs", 5, 5, 125, "high hint").is_ok());
        assert!(ensure_range("poll_timeout_secs", 125, 5, 125, "high hint").is_ok());
    }

    #[tokio::test]
    async fn test_defaults() {
        let content = r#"
name = "w"
hub_url = "http://h"
token = "t"
"#;
        let temp = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(temp.path(), content).await.unwrap();

        let cfg = WorkerConfig::load(temp.path()).await.unwrap();
        assert_eq!(cfg.capacity, 1);
        assert_eq!(cfg.heartbeat_interval_secs, 30);
        assert_eq!(cfg.poll_timeout_secs, 60);
        assert_eq!(cfg.build_dir, "/var/lib/crbs/worker/builds");
        assert_eq!(cfg.result_retention_days, 3);
        assert_eq!(cfg.crbs_root, "/var/lib/crbs");
        assert_eq!(cfg.tmp_dir, "/var/tmp");
        assert_eq!(cfg.tmpfs_dir, "/dev/shm");
        assert_eq!(cfg.build_timeout_secs, 86_400);
        assert_eq!(cfg.min_free_disk_gb, 1);
        assert_eq!(cfg.min_free_disk_bytes(), 1024 * 1024 * 1024);
        assert_eq!(cfg.min_free_mem_mb, 512);
        assert_eq!(cfg.min_free_mem_bytes(), 512 * 1024 * 1024);
        assert_eq!(cfg.arch(), std::env::consts::ARCH);
    }

    #[tokio::test]
    async fn test_min_free_disk_gb_zero_and_positive_accepted() {
        for (value, expect) in [("0", 0u64), ("5", 5)] {
            let content = format!(
                "name = \"w\"\nhub_url = \"http://h\"\ntoken = \"t\"\nmin_free_disk_gb = {value}\n"
            );
            let temp = tempfile::NamedTempFile::new().unwrap();
            tokio::fs::write(temp.path(), &content).await.unwrap();
            let cfg = WorkerConfig::load(temp.path()).await.unwrap();
            assert_eq!(cfg.min_free_disk_gb, expect, "value {value} must parse");
        }
    }

    #[tokio::test]
    async fn test_build_timeout_secs_zero_and_positive_accepted() {
        for (value, expect) in [("0", 0u64), ("3600", 3600)] {
            let content = format!(
                "name = \"w\"\nhub_url = \"http://h\"\ntoken = \"t\"\nbuild_timeout_secs = {value}\n"
            );
            let temp = tempfile::NamedTempFile::new().unwrap();
            tokio::fs::write(temp.path(), &content).await.unwrap();
            let cfg = WorkerConfig::load(temp.path()).await.unwrap();
            assert_eq!(cfg.build_timeout_secs, expect, "value {value} must parse");
        }
    }

    #[tokio::test]
    async fn test_min_free_mem_mb_zero_and_positive_accepted() {
        for (value, expect) in [("0", 0u64), ("256", 256)] {
            let content = format!(
                "name = \"w\"\nhub_url = \"http://h\"\ntoken = \"t\"\nmin_free_mem_mb = {value}\n"
            );
            let temp = tempfile::NamedTempFile::new().unwrap();
            tokio::fs::write(temp.path(), &content).await.unwrap();
            let cfg = WorkerConfig::load(temp.path()).await.unwrap();
            assert_eq!(cfg.min_free_mem_mb, expect, "value {value} must parse");
        }
    }

    #[tokio::test]
    async fn test_result_retention_days_zero_and_positive_accepted() {
        for days in ["0", "30"] {
            let content = format!(
                "name = \"w\"\nhub_url = \"http://h\"\ntoken = \"t\"\nresult_retention_days = {days}\n"
            );
            let temp = tempfile::NamedTempFile::new().unwrap();
            tokio::fs::write(temp.path(), &content).await.unwrap();
            let cfg = WorkerConfig::load(temp.path()).await.unwrap();
            assert_eq!(cfg.result_retention_days.to_string(), days);
        }
    }

    #[tokio::test]
    async fn test_startup_mount_gc_values_and_default() {
        for (value, expect) in [
            ("auto", StartupMountGc::Auto),
            ("always", StartupMountGc::Always),
            ("never", StartupMountGc::Never),
        ] {
            let content = format!(
                "name = \"w\"\nhub_url = \"http://h\"\ntoken = \"t\"\nstartup_mount_gc = \"{value}\"\n"
            );
            let temp = tempfile::NamedTempFile::new().unwrap();
            tokio::fs::write(temp.path(), &content).await.unwrap();
            let cfg = WorkerConfig::load(temp.path()).await.unwrap();
            assert_eq!(cfg.startup_mount_gc, expect, "value {value} must parse");
        }

        let temp = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(
            temp.path(),
            "name = \"w\"\nhub_url = \"http://h\"\ntoken = \"t\"\n",
        )
        .await
        .unwrap();
        let cfg = WorkerConfig::load(temp.path()).await.unwrap();
        assert_eq!(cfg.startup_mount_gc, StartupMountGc::Auto);

        for bad in ["sometimes", "Auto", "true", "1"] {
            let content = format!(
                "name = \"w\"\nhub_url = \"http://h\"\ntoken = \"t\"\nstartup_mount_gc = \"{bad}\"\n"
            );
            let temp = tempfile::NamedTempFile::new().unwrap();
            tokio::fs::write(temp.path(), &content).await.unwrap();
            let result = WorkerConfig::load(temp.path()).await;
            assert!(
                result.is_err(),
                "startup_mount_gc={bad:?} must be rejected at load time"
            );
        }
    }

    /// 启动 GC 决策表（纯函数直测）：always 恒执行 / never 恒跳过 /
    /// auto 仅在 hub 明确报告无活跃构建（Some(false)）时执行，Some(true) 与 None 保守跳过。
    #[test]
    fn test_should_run_startup_gc_decision_table() {
        use StartupMountGc as Mode;
        // auto × 三态
        assert!(should_run_startup_gc(Mode::Auto, Some(false)));
        assert!(!should_run_startup_gc(Mode::Auto, Some(true)));
        assert!(!should_run_startup_gc(Mode::Auto, None));
        assert!(should_run_startup_gc(Mode::Always, Some(true)));
        assert!(should_run_startup_gc(Mode::Always, Some(false)));
        assert!(should_run_startup_gc(Mode::Always, None));
        assert!(!should_run_startup_gc(Mode::Never, Some(true)));
        assert!(!should_run_startup_gc(Mode::Never, Some(false)));
        assert!(!should_run_startup_gc(Mode::Never, None));
    }

    /// deny_unknown_fields：拼错键（数据丢失类 typo）必须在 load 期报错——静默吞掉会让结果目录按默认 3 天被清理。
    #[tokio::test]
    async fn test_load_rejects_unknown_field_typo() {
        let content = r#"
name = "w"
hub_url = "http://h"
token = "t"
result_retention_day = 30
"#;
        let temp = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(temp.path(), content).await.unwrap();
        let err = WorkerConfig::load(temp.path()).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "msg: {msg}");
        assert!(msg.contains("result_retention_day"), "msg: {msg}");
    }

    #[tokio::test]
    async fn ensure_safe_build_dir_creates_and_sets_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("safe-build-dir");
        ensure_safe_build_dir(&dir).await.unwrap();
        assert!(dir.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&dir).unwrap().permissions();
            // 2770（setgid，权限不变量）：组内 rwx + 子目录继承 crbs 组。
            assert_eq!(perms.mode() & 0o7777, 0o2770);
        }
    }

    /// 已存在目录（如部署工具预建的 0755）也必须被修正为 2770——否则 crbs 组三身份互访永久失败。
    #[tokio::test]
    async fn ensure_safe_build_dir_fixes_permissions_of_existing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("pre-made-build-dir");
        tokio::fs::create_dir(&dir).await.unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
                .await
                .unwrap();
        }

        ensure_safe_build_dir(&dir).await.unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode, 0o2770, "预建 0755 目录必须被修正为 2770");
        }
    }

    #[tokio::test]
    async fn ensure_safe_build_dir_rejects_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real");
        let symlink = tmp.path().join("link");
        tokio::fs::create_dir(&real_dir).await.unwrap();
        tokio::fs::symlink(&real_dir, &symlink).await.unwrap();
        let err = ensure_safe_build_dir(&symlink).await.unwrap_err();
        assert!(
            matches!(err, crbs_core::error::CrbsError::ValidationFailed { .. }),
            "expected validation error for symlink, got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn ensure_safe_build_dir_rejects_parent_dir_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let bad = tmp.path().join("good").join("..").join("bad");
        let err = ensure_safe_build_dir(&bad).await.unwrap_err();
        assert!(matches!(
            err,
            crbs_core::error::CrbsError::ValidationFailed { .. }
        ));
    }

    #[tokio::test]
    async fn ensure_safe_build_dir_tolerates_concurrent_creation() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("concurrent-build-dir");

        let results = tokio::join!(
            ensure_safe_build_dir(&dir),
            ensure_safe_build_dir(&dir),
            ensure_safe_build_dir(&dir),
            ensure_safe_build_dir(&dir),
        );
        for (i, r) in [results.0, results.1, results.2, results.3]
            .iter()
            .enumerate()
        {
            assert!(r.is_ok(), "concurrent create #{} failed: {:?}", i, r);
        }
        assert!(dir.is_dir());
    }
}

#[cfg(test)]
mod example_tests {
    use super::*;

    /// examples/config/worker.toml 必须始终可被 WorkerConfig 解析（示例与结构体漂移时在此失败，而非用户机器上）。
    #[tokio::test]
    async fn shipped_example_config_parses() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let path = std::path::Path::new(manifest)
            .join("../..")
            .join("examples/config/worker.toml");
        let cfg = WorkerConfig::load(&path).await.unwrap();
        assert_eq!(cfg.name, "worker-01");
        assert_eq!(cfg.capacity, 2);
        assert!(cfg.hub_url.starts_with("https://"));
    }
}
