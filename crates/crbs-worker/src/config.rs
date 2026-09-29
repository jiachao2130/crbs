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

/// HTTP 客户端全局的兜底超时（秒）：单文件产物上限 2GB，慢链路上传可远超 30s。
/// 产物上传每次重试尝试的超时（executor/upload.rs）必须与之对齐，否则重试层会先于
/// 客户端掐断上传。
pub(crate) const HTTP_FALLBACK_TIMEOUT_SECS: u64 = 600;

/// 心跳间隔下限：低于此值，请求级超时 min(间隔, 10s) 失去保护意义，且高频心跳
/// 放大 Hub 压力。
const MIN_HEARTBEAT_INTERVAL_SECS: u64 = 5;

/// 心跳间隔上限：hub 侧 120s 未收到心跳即判失联，间隔贴近/超过则 worker 永远不可调度、
/// assignment 被周期回收重派。
const MAX_HEARTBEAT_INTERVAL_SECS: u64 = 110;

/// 长轮询超时下限：下限 5 保证减 5 余量后 wait 不滑落成 0（忙轮询）。
const MIN_POLL_TIMEOUT_SECS: u64 = 5;

/// 长轮询超时上限：客户端整体超时须显著低于 hub 失联判定时长的双倍回收窗口；
/// 上限 125 保证 wait ≤ 115（服务端 clamp 120s 内、客户端超时恒大于服务端 wait）。
const MAX_POLL_TIMEOUT_SECS: u64 = 125;

/// capacity 合法上限，与 server 注册端点的 MAX_WORKER_CAPACITY 同一套规则。
/// 异常 capacity（如 i64::MAX）会被派发又因心跳超时回收，形成派发-回收-再派发的
/// 循环压力。
const MAX_WORKER_CAPACITY: i64 = 1024;

/// 启动期无主挂载 GC 模式：auto（默认，由 hub 注册响应的 has_active_local_builds
/// 检查决定）| always | never（交 crbs gc --orphan-mounts 等带检查入口）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum StartupMountGc {
    Auto,
    Always,
    Never,
}

/// 启动 GC 是否执行的决策。保守方向是跳过：启动 GC 杀错活跃挂载（构建假失败/产物
/// 损坏）的代价，远高于无主挂载多留一轮（hub 侧还有 crbs gc --orphan-mounts）。
pub(crate) fn should_run_startup_gc(mode: StartupMountGc, has_active: Option<bool>) -> bool {
    match mode {
        StartupMountGc::Always => true,
        StartupMountGc::Never => false,
        StartupMountGc::Auto => has_active == Some(false),
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
/// Worker 配置。数值越界在 load 期直接报错，不静默接受越界值。
pub struct WorkerConfig {
    pub name: String,

    pub hub_url: String,

    #[serde(default)]
    pub arch: Option<String>,

    #[serde(default = "default_capacity")]
    pub capacity: i64,

    pub token: String,

    #[serde(default)]
    pub hub_ca_cert: Option<std::path::PathBuf>,

    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,

    #[serde(default = "default_poll_timeout_secs")]
    /// 客户端整体请求超时；poll 请求显式携带 ?wait=<该值-5（≤115）>，服务端长轮询
    /// 窗口与之对齐（留 5s 余量给服务端 wait 到期后的补查与响应组装）。
    pub poll_timeout_secs: u64,

    #[serde(default = "default_build_dir")]
    pub build_dir: String,

    #[serde(default = "default_result_retention_days")]
    pub result_retention_days: u64,

    #[serde(default = "default_crbs_root")]
    pub crbs_root: String,

    #[serde(default = "default_tmp_dir")]
    /// 构建临时目录（engine 配置的 tmp_dir）：启动期无主挂载 GC 的扩展扫描范围，overlay
    /// 挂载目标在 {tmp_dir}/.tmpXXXX/root。须与部署的 crbs.toml 引擎配置 tmp_dir
    /// 保持一致：分叉时启动 GC 只覆盖这里声明的目录，未覆盖的无主挂载由每构建 init 的
    /// 清理与带检查的 crbs gc --orphan-mounts 收尾。
    pub tmp_dir: String,

    #[serde(default = "default_tmpfs_dir")]
    /// tmpfs 构建目录（engine 配置的 tmpfs_dir），语义同 tmp_dir，也须与部署的
    /// crbs.toml 保持一致。
    pub tmpfs_dir: String,

    #[serde(default = "default_startup_mount_gc")]
    pub startup_mount_gc: StartupMountGc,

    #[serde(default = "default_build_timeout_secs")]
    /// 远程构建请求未显式指定 timeout 时的默认值：hang 构建会永久占用 hub running
    /// 行 + worker permit（只要心跳还在 reclaimer 就不会回收）。0 = 不限时。
    pub build_timeout_secs: u64,

    #[serde(default = "default_min_free_disk_gb")]
    /// 领任务前的磁盘余量门槛：build_dir 所在盘剩余空间低于该值时本轮跳过领任务
    /// （满盘继续领会形成"领取→失败→释放→再领"的空转）。只拦新任务的领取：心跳
    /// 照常发送，在跑构建不受影响。0 = 关闭。
    pub min_free_disk_gb: u64,

    #[serde(default = "default_min_free_mem_mb")]
    /// 领任务前的内存余量门槛：/proc/meminfo MemAvailable 低于该值时本轮跳过领任务
    /// （继续领会把 OOM 从"构建失败"升级为"拖垮同机其他构建/系统服务"）。只拦新任务
    /// 的领取；读取失败放行（非 Linux 恒放行）。0 = 关闭。
    pub min_free_mem_mb: u64,

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

            "it must stay significantly below the hub-side 120s heartbeat freshness threshold or the worker is never schedulable",
        )?;
        ensure_range(
            "poll_timeout_secs",
            cfg.poll_timeout_secs,
            MIN_POLL_TIMEOUT_SECS,
            MAX_POLL_TIMEOUT_SECS,

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

    /// 构造并缓存 reqwest client：首次调用构建、后续复用连接池；配置 hub_ca_cert
    /// 则加入根证书信任列表，否则用系统默认信任库。
    pub async fn build_http_client(&self) -> crbs_core::Result<reqwest::Client> {
        {
            let cached = self.client.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(client) = cached.clone() {
                return Ok(client);
            }
        }

        let mut builder = reqwest::Client::builder()
            // 全局超时避免 Hub 无响应时请求永久挂起；长轮询在请求级设置了更短的
            // timeout，会覆盖此默认值。
            .timeout(std::time::Duration::from_secs(HTTP_FALLBACK_TIMEOUT_SECS))
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

/// 数值范围守护（load 期直接报错，不静默接受越界值）：低/越界句式固定，上限触发的追加
/// 说明由调用方传入（各字段语义不同）。
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

/// 校验并创建安全的 build_dir：拒绝 `..`（路径穿越）；目标已存在时必须是目录且非
/// 符号链接，并补齐权限不变量（2770 + group=crbs——部署工具预建的 0755 目录不
/// 修正，会让 root / crbs-server / crbs 组用户三身份互访永久失败）；创建目录后设
/// 置权限 2770 并 chown 到 crbs 组。防 /tmp 等可被其他本地用户写入的目录中预建
/// 符号链接导致的目录劫持或信息泄露。
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

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // 已存在目录同样要满足权限不变量（2770 + group=crbs）；chmod 失败仅
            // warn（权限未生效，不阻断本 build），chown 失败仅 debug（非 root chown
            // 必然 EPERM）。
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
        // 首批任务并发抢建 build_dir 时只有一个 create_dir 成功，其余拿到
        // AlreadyExists：此时目录已存在，视为成功并继续走下方安全复检——绝不能
        // 直接 return Ok，否则被抢建为符号链接的风险重新引入。
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

fn default_tmp_dir() -> String {
    "/var/tmp".to_string()
}

fn default_tmpfs_dir() -> String {
    "/dev/shm".to_string()
}

fn default_startup_mount_gc() -> StartupMountGc {
    StartupMountGc::Auto
}

fn default_build_timeout_secs() -> u64 {
    86_400
}

fn default_min_free_disk_gb() -> u64 {
    1
}

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

    #[test]
    fn test_should_run_startup_gc_decision_table() {
        use StartupMountGc as Mode;

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

            assert_eq!(perms.mode() & 0o7777, 0o2770);
        }
    }

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
