// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! RPM 签名模块（Host 侧执行，私钥不进入构建容器）。签名与构建生命周期解耦：
//! 引擎只产出不签名；CLI 本地构建后可选调 `Signer`，远程构建由客户端自行签或启用服务端签名。

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tracing::{info, warn};

use crate::error::CrbsError;

/// 单次 gpg / rpmsign 子进程硬超时；超出视为挂死（典型 pinentry 无 TTY 阻塞等输入），
/// 进程组 SIGKILL 后映射 `CrbsError::Timeout`（无消息载荷，上下文由调用点 warn 补充）。
const SIGN_CMD_TIMEOUT: Duration = Duration::from_secs(600);

/// `SignFailed` 消息携带的 stderr 尾部上限，截尾防异常巨大输出撑爆错误与日志。
const SIGN_STDERR_TAIL_BYTES: usize = 4 * 1024;

/// 返回当前进程有效 UID。非 Unix 平台返回 0（root 语义）。
fn current_euid() -> u32 {
    #[cfg(unix)]
    {
        nix::unistd::geteuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// 获取结果目录的签名排他锁 `{result_dir}/.sign.lock`。GPG **原地改写** RPM，
/// 并发签同一结果目录会交错改写、悄悄产出损坏包——按结果目录串行化，防
/// "并发改写损坏"而非"重复签名"（幂等无害），不同结果目录可并行；`File` 即
/// 锁 guard，drop 释放；签名路径锁已收敛 [`Signer::sign_rpms`]（唯一锁点），外部 regen 协调用 with_timeout 变体。
pub async fn acquire_result_dir_sign_lock(result_dir: &Path) -> crate::Result<std::fs::File> {
    let lock_path = result_dir.join(".sign.lock");
    crate::engine::lock::lock_exclusive_async(
        lock_path,
        crate::engine::lock::DEFAULT_FILE_LOCK_TIMEOUT,
    )
    .await
}

/// 结果目录上传互斥锁 `{result_dir}/.upload.lock`：上传重试与上一请求的
/// 落盘/后台签名不得交错（重试截断签名中的字节、失败清理删已提交文件）。
/// 上传 handler 持有到签名任务结束；不同 build 的结果目录互不影响。
pub async fn acquire_result_dir_upload_lock(result_dir: &Path) -> crate::Result<std::fs::File> {
    crate::engine::lock::lock_exclusive_async(
        result_dir.join(".upload.lock"),
        crate::engine::lock::DEFAULT_FILE_LOCK_TIMEOUT,
    )
    .await
}

/// 同 [`acquire_result_dir_sign_lock`]，但可指定超时：`report_result` 是 worker
/// 同步 HTTP 调用，不能等 `DEFAULT_FILE_LOCK_TIMEOUT`（5 分钟，撞锁最坏时长）。
/// 超时后调用方应仅 warn 不 regen，由下一次成功 build 或手动 `rebuild-repo` 对账。
pub async fn acquire_result_dir_sign_lock_with_timeout(
    result_dir: &Path,
    timeout: std::time::Duration,
) -> crate::Result<std::fs::File> {
    let lock_path = result_dir.join(".sign.lock");
    crate::engine::lock::lock_exclusive_async(lock_path, timeout).await
}

/// GPG 签名配置。
#[derive(Debug, Clone)]
pub struct SignConfig {
    /// GPG key ID 或邮箱。
    pub key_id: String,
    /// GPG home 目录（可选，默认使用当前用户 keyring）。
    pub gpg_home: Option<String>,
}

impl SignConfig {
    /// 校验 `gpg_home` 路径安全可用：存在且为目录；非符号链接（防 TOCTOU 替换）；
    /// owner 与 euid 一致或 euid == 0；权限 owner-only（mode & 0o077 == 0，禁 group/other 读写执行）。
    #[cfg(unix)]
    pub fn validate_gpg_home<P: AsRef<Path>>(home: P, euid: u32) -> crate::Result<String> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let path = home.as_ref();
        let meta = std::fs::symlink_metadata(path).map_err(|e| CrbsError::ValidationFailed {
            message: format!("gpg_home {} is not accessible: {}", path.display(), e),
        })?;

        if meta.is_symlink() {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "gpg_home {} is a symlink; refusing to use it",
                    path.display()
                ),
            });
        }
        if !meta.is_dir() {
            return Err(CrbsError::ValidationFailed {
                message: format!("gpg_home {} is not a directory", path.display()),
            });
        }

        let owner = meta.uid();
        if euid != 0 && owner != euid {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "gpg_home {} is owned by {} but current euid is {}; refusing to use it",
                    path.display(),
                    owner,
                    euid
                ),
            });
        }

        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "gpg_home {} has unsafe permissions {:04o}; expected owner-only (0o700)",
                    path.display(),
                    mode
                ),
            });
        }

        let abs = path
            .canonicalize()
            .map_err(|e| CrbsError::ValidationFailed {
                message: format!("gpg_home {} cannot be canonicalized: {}", path.display(), e),
            })?;
        Ok(abs.to_string_lossy().to_string())
    }

    /// 非 Unix 桩：仅做 canonicalize，不带属主/权限安全校验（生产签名只在 Linux）。
    #[cfg(not(unix))]
    pub fn validate_gpg_home<P: AsRef<Path>>(home: P, _euid: u32) -> crate::Result<String> {
        // map_err 闭包引用自身初始化器在非 Unix 目标上是 E0425：先绑定外层 path 再 shadow。
        let path = home.as_ref();
        let abs = path
            .canonicalize()
            .map_err(|e| CrbsError::ValidationFailed {
                message: format!("gpg_home {} cannot be canonicalized: {}", path.display(), e),
            })?;
        Ok(abs.to_string_lossy().to_string())
    }

    /// `validate_gpg_home` 的异步包装，避免在 async 中直接同步访问文件系统。
    pub async fn validate_gpg_home_async<P: AsRef<Path> + Send>(
        home: P,
        euid: u32,
    ) -> crate::Result<String> {
        let path = home.as_ref().to_path_buf();
        tokio::task::spawn_blocking(move || Self::validate_gpg_home(path, euid))
            .await
            .map_err(|e| CrbsError::Internal(format!("validate_gpg_home panicked: {e}")))?
    }

    /// 从 Config 中提取签名配置（非 Unix 变体）：key 未配置返回 `None`；
    /// `gpg_home` 原样透传不校验（生产签名只在 Linux，校验与回退语义见 Unix 侧变体）。
    #[cfg(not(unix))]
    pub fn from_config(config: &crate::config::Config) -> Option<Self> {
        // 显式关闭（gpg_signing_enabled = false）优先于 key 配置：签名许可不随继承/全局缺省扩散。
        if config.gpg_signing_enabled == Some(false) {
            return None;
        }
        let key_id = config.gpg_signing_key_id.clone()?;
        let gpg_home = config.gpg_home.clone();
        Some(Self { key_id, gpg_home })
    }

    /// 从 Config 中提取签名配置：显式关闭（`gpg_signing_enabled = false`）或 key
    /// 未配置返回 `None`；`gpg_home` 经 `validate_gpg_home` 校验，失败 warn 回退默认 keyring。
    #[cfg(unix)]
    pub fn from_config(config: &crate::config::Config) -> Option<Self> {
        if config.gpg_signing_enabled == Some(false) {
            return None;
        }
        let key_id = config.gpg_signing_key_id.clone()?;
        let euid = current_euid();
        let gpg_home =
            config
                .gpg_home
                .clone()
                .and_then(|home| match Self::validate_gpg_home(&home, euid) {
                    Ok(abs) => Some(abs),
                    Err(e) => {
                        warn!(path = %home, error = %e, "gpg_home rejected, using default keyring");
                        None
                    }
                });
        Some(Self { key_id, gpg_home })
    }

    /// `from_config` 的 spawn_blocking 包装；平台差异由 `from_config` 内部处理。
    pub async fn from_config_async(config: &crate::config::Config) -> Option<Self> {
        let config = config.clone();
        match tokio::task::spawn_blocking(move || Self::from_config(&config)).await {
            Ok(inner) => inner,
            // join 错误（panic/取消）如实记录：静默当"未配置"会误导排障。
            Err(e) => {
                tracing::warn!(error = %e, "signing from_config task failed");
                None
            }
        }
    }

    /// 产品是否声明了签名策略（`gpg_signing_enabled != false` 且 key 非空白）。
    /// 纯配置判断、不触碰文件系统（`from_config` 会校验 `gpg_home`，不能用于
    /// 纯判断）：供"未签名产物不得进发布 repo"等策略门控。
    pub fn signing_required(config: &crate::config::Config) -> bool {
        config.gpg_signing_enabled != Some(false)
            && config
                .gpg_signing_key_id
                .as_deref()
                .is_some_and(|key| !key.trim().is_empty())
    }
}

/// RPM 签名执行器：在调用者进程上下文执行 `rpmsign --addsign`，使用调用者的 GPG keyring（私钥不进构建容器）。
pub struct Signer;

impl Default for Signer {
    fn default() -> Self {
        Self::new()
    }
}

impl Signer {
    /// 构造签名执行器。
    pub fn new() -> Self {
        Self
    }

    /// 检查指定 key_id 的私钥是否存在于 keyring 中。
    pub async fn key_available(&self, config: &SignConfig) -> crate::Result<bool> {
        let mut cmd = tokio::process::Command::new("gpg");
        if let Some(ref home) = config.gpg_home {
            cmd.arg("--homedir").arg(home);
        }
        // key_id 是配置自由文本且落位置参数槽：`-`/空白会被 gpg 解析为选项（rpmsign 路径按值槽处理，口径必须一致）。
        if config.key_id.starts_with('-')
            || config
                .key_id
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(crate::error::CrbsError::ValidationFailed {
                message: format!(
                    "gpg_signing_key_id contains invalid characters: {:?}",
                    config.key_id
                ),
            });
        }
        cmd.args(["--list-secret-keys", &config.key_id])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let status = crate::engine::command::run_child_status_with_cancel_timeout(
            &mut cmd,
            None,
            Some(SIGN_CMD_TIMEOUT),
            "spawn gpg --list-secret-keys",
        )
        .await;
        match status {
            Ok(s) => Ok(s.success()),
            Err(CrbsError::Io { .. }) => {
                // gpg 命令不存在/无法执行时视为 key 不可用（常见于非 Linux 环境）。
                warn!(
                    key = %config.key_id,
                    "gpg command not available; treating key as unavailable"
                );
                Ok(false)
            }
            // 超时等其他错误上告，不误判为"key 不存在"。
            Err(e) => Err(e),
        }
    }

    /// 对指定结果目录下的 RPM/SRPM 文件执行 `rpmsign --addsign`。
    ///
    /// # 并发互斥（唯一锁点）
    /// 所有签名路径汇聚到本方法统一持有 `{result_dir}/.sign.lock`，串行化对同一
    /// 结果目录 RPM 的原地改写。调用方**不得**再在外部获取该锁：flock 按 fd 计，
    /// 同进程新 fd 二次获取会等到超时（等效自死锁）。锁只覆盖 rpmsign 执行；哈希
    /// 刷新/DB 更新留锁外——并发重签最坏哈希短暂陈旧，重跑 `crbs sign` 幂等收敛。
    ///
    /// 前置条件：`paths` 非空、已检查 `key_available()`。失败 `SignFailed`（含
    /// exit status 与 stderr 尾部），超时 `Timeout`（子进程已被 SIGKILL）。
    pub async fn sign_rpms(
        &self,
        config: &SignConfig,
        result_dir: &Path,
        paths: &[&Path],
    ) -> crate::Result<()> {
        if paths.is_empty() {
            info!("sign_rpms called with empty paths; skipping");
            return Ok(());
        }

        let _sign_lock = acquire_result_dir_sign_lock(result_dir).await?;

        let mut cmd = tokio::process::Command::new("rpmsign");
        cmd.arg("--addsign");
        // RPM 4.18 中 #%_gpg_name/#%_gpg_path 被定义为空 body，--define '_gpg_name ...'
        // 会报 "Macro %_gpg_name has empty body"；--key-id 等价设置且不依赖覆盖系统宏。
        cmd.arg("--key-id").arg(&config.key_id);
        // GPG_TTY 继承既有值否则置空：避免 sudo 无 TTY 下 rpmsign 报 "Could not set GPG_TTY to stdin"。
        cmd.env("GPG_TTY", std::env::var("GPG_TTY").unwrap_or_default());
        if let Some(ref home) = config.gpg_home {
            // 显式设 GNUPGHOME：防 systemd PrivateTmp/环境继承回退到不安全默认路径。
            cmd.env("GNUPGHOME", home.as_str());
        }
        for path in paths {
            cmd.arg(path);
        }
        // stderr 管道化：失败把 exit status + stderr 尾部带进 SignFailed；capped 读取（32MB 上限、超限续读防死锁，engine::command）。
        cmd.stderr(Stdio::piped());

        info!(
            key = %config.key_id,
            count = paths.len(),
            "Signing RPMs"
        );

        let output = match crate::engine::command::run_child_output_with_cancel_timeout(
            &mut cmd,
            None,
            Some(SIGN_CMD_TIMEOUT),
            "spawn rpmsign --addsign",
        )
        .await
        {
            Ok(o) => o,
            Err(CrbsError::Timeout) => {
                warn!(
                    key = %config.key_id,
                    count = paths.len(),
                    timeout_secs = SIGN_CMD_TIMEOUT.as_secs(),
                    "rpmsign --addsign timed out; child process group killed"
                );
                return Err(CrbsError::Timeout);
            }
            Err(e) => return Err(e),
        };

        if !output.status.success() {
            return Err(CrbsError::SignFailed {
                message: format!(
                    "rpmsign --addsign failed for key '{}' (exit={:?}): {}",
                    config.key_id,
                    output.status.code(),
                    stderr_tail(&output.stderr)
                ),
            });
        }

        info!(count = paths.len(), "RPM sign succeeded");
        Ok(())
    }
}

/// 取 stderr 尾部（最多 [`SIGN_STDERR_TAIL_BYTES`] 字节）用于 `SignFailed` 消息。
fn stderr_tail(stderr: &[u8]) -> String {
    let start = stderr.len().saturating_sub(SIGN_STDERR_TAIL_BYTES);
    String::from_utf8_lossy(&stderr[start..]).trim().to_string()
}

/// 从构建产物中提取所有待签名的 RPM 路径。
fn collect_sign_paths(outputs: &crate::types::BuildOutputs) -> Vec<&Path> {
    outputs
        .rpms
        .iter()
        .chain(outputs.srpms.iter())
        .map(|p| p.as_path())
        .collect()
}

/// PrivilegeBackend 批量调整产物及其父目录权限（best-effort 失败仅 warn）：
/// 签名前放宽到 group 可写，签名后恢复最终权限。
async fn chmod_outputs(
    paths: Vec<std::path::PathBuf>,
    file_mode: u32,
    dir_mode: u32,
    op: &'static str,
) {
    let _ = tokio::task::spawn_blocking(move || {
        let backend = crate::privilege::get_privilege_backend();
        for path in &paths {
            if let Err(e) = backend.chmod(path, file_mode, false) {
                warn!(path = %path.display(), error = ?e, "{} chmod {:o} on rpm failed", op, file_mode);
            }
            if let Some(parent) = path.parent() {
                if let Err(e) = backend.chmod(parent, dir_mode, false) {
                    warn!(path = %parent.display(), error = ?e, "{} chmod {:o} on parent dir failed", op, dir_mode);
                }
            }
        }
    })
    .await;
}

/// 构建成功后统一签名入口（**只做物理签名**，不写数据库）：配置有 key 时对产物
/// 执行 rpmsign 并把 `outputs.signed` 翻 true，签名失败仅 warn 不中断构建。
///
/// **`builds.signed=1` 的置位不在本函数**——不变量 `signed=1 ⇒ build_artifacts
/// 行哈希新鲜` 要求哈希刷新成功后才置位，本函数无法感知产物行：已登记行路径由
/// 调用方刷新/落库后置位（server 侧共享 helper `crbs_server::server::signing`）；
/// 无产物行的 CLI 本地路径用 [`mark_build_signed_best_effort`]（无行级哈希可 stale）。
pub async fn sign_build_outputs(
    outputs: &mut crate::types::BuildOutputs,
    config: &crate::config::Config,
) {
    let Some(sign_config) = SignConfig::from_config_async(config).await else {
        return;
    };
    let paths = collect_sign_paths(outputs);
    if paths.is_empty() {
        return;
    }

    let signer = Signer::new();
    // key 检查先于 pre-sign chmod：早退路径没有 restore chmod，先 chmod 会把产物留在 group-widened 状态。
    match signer.key_available(&sign_config).await {
        Ok(false) => {
            warn!(
                build_id = %outputs.build_id,
                key = %sign_config.key_id,
                "GPG key not available; skipping sign"
            );
            return;
        }
        Ok(true) => {}
        Err(e) => {
            warn!(
                build_id = %outputs.build_id,
                key = %sign_config.key_id,
                error = %e,
                "failed to check GPG key availability; skipping sign"
            );
            return;
        }
    }

    // 签名前后把产物和父目录权限收敛到不变量终态（文件 0o660、目录 0o2770，
    // crbs 组）：rpmsign 需重写 RPM（owner/group 写即可），GPG 需在目录建临时文件。
    let chmod_paths: Vec<std::path::PathBuf> = paths.iter().map(|p| p.to_path_buf()).collect();
    chmod_outputs(chmod_paths.clone(), 0o660, 0o2770, "pre-sign").await;

    let sign_result = signer
        .sign_rpms(&sign_config, &outputs.result_dir, &paths)
        .await;

    chmod_outputs(chmod_paths, 0o660, 0o2770, "restore").await;

    match sign_result {
        Ok(()) => {
            // 物理签名完成标记；builds.signed 置位见函数文档的不变量说明。
            outputs.signed = true;
        }
        Err(e) => {
            warn!(build_id = %outputs.build_id, error = %e, "failed to sign RPMs");
        }
    }
}

/// 物理签名成功后置位 `builds.signed=1`（best-effort，失败仅 warn）。仅供**无
/// build_artifacts 行**的 CLI 本地路径（登记行路径须先刷新哈希，见 [`sign_build_outputs`]）。
pub async fn mark_build_signed_best_effort(state: &crate::state::StateStore, build_id: i64) {
    if let Err(e) = state.update_build_signed(build_id, true).await {
        warn!(
            build_id = %build_id,
            error = %e,
            "failed to update signed status in database"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::*;

    fn test_euid() -> u32 {
        current_euid()
    }

    fn make_test_gpg_home(dir: &std::path::Path) -> PathBuf {
        let home = dir.join("gnupg");
        std::fs::create_dir_all(&home).unwrap();
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(&home, perms).unwrap();
        home
    }

    #[test]
    fn validate_gpg_home_accepts_owner_only_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let home = make_test_gpg_home(tmp.path());
        let result = SignConfig::validate_gpg_home(&home, test_euid());
        assert!(
            result.is_ok(),
            "expected valid gpg_home, got {:?}",
            result.err()
        );
        assert_eq!(
            result.unwrap(),
            home.canonicalize().unwrap().to_string_lossy()
        );
    }

    #[test]
    fn validate_gpg_home_rejects_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let real = make_test_gpg_home(tmp.path());
        let link = tmp.path().join("gnupg-link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        #[cfg(not(unix))]
        {
            // symlink 创建是平台相关的；非 unix 跳过
            return;
        }
        let result = SignConfig::validate_gpg_home(&link, test_euid());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symlink"));
    }

    #[test]
    fn validate_gpg_home_rejects_too_permissive() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("gnupg");
        std::fs::create_dir_all(&home).unwrap();
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&home, perms).unwrap();

        let result = SignConfig::validate_gpg_home(&home, test_euid());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsafe permissions"));
    }

    #[test]
    fn validate_gpg_home_rejects_owner_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let home = make_test_gpg_home(tmp.path());
        let result = SignConfig::validate_gpg_home(&home, 99999);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("owned by"));
    }

    #[test]
    fn from_config_ignores_invalid_gpg_home() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("gnupg");
        std::fs::create_dir_all(&home).unwrap();
        let perms = std::fs::Permissions::from_mode(0o777);
        std::fs::set_permissions(&home, perms).unwrap();

        let config = crate::config::Config {
            product: "test".to_string(),
            gpg_signing_key_id: Some("key@example.com".to_string()),
            gpg_home: Some(home.to_str().unwrap().to_string()),
            ..Default::default()
        };
        let sc = SignConfig::from_config(&config).expect("should be Some");
        assert_eq!(sc.key_id, "key@example.com");
        assert_eq!(sc.gpg_home, None);
    }

    /// 显式关闭（gpg_signing_enabled = false）压制 key 配置：SignConfig 恒 None。
    #[test]
    fn from_config_disabled_by_gpg_signing_enabled_false() {
        let config = crate::config::Config {
            product: "test".to_string(),
            gpg_signing_key_id: Some("key@example.com".to_string()),
            gpg_signing_enabled: Some(false),
            ..Default::default()
        };
        assert!(SignConfig::from_config(&config).is_none());

        let mut enabled = config.clone();
        enabled.gpg_signing_enabled = Some(true);
        assert!(SignConfig::from_config(&enabled).is_some());
        let mut unset = config;
        unset.gpg_signing_enabled = None;
        assert!(SignConfig::from_config(&unset).is_some());
    }

    /// 发布门控谓词：key 非空白且未显式关闭才要求签名；key 缺失/空白/关闭均不要求。
    #[test]
    fn signing_required_matrix() {
        let base = crate::config::Config {
            product: "test".to_string(),
            ..Default::default()
        };
        assert!(
            !SignConfig::signing_required(&base),
            "no key = not required"
        );

        let key = crate::config::Config {
            gpg_signing_key_id: Some("key@example.com".to_string()),
            ..base.clone()
        };
        assert!(
            SignConfig::signing_required(&key),
            "key configured = required"
        );

        let disabled = crate::config::Config {
            gpg_signing_enabled: Some(false),
            ..key.clone()
        };
        assert!(
            !SignConfig::signing_required(&disabled),
            "explicit disable wins over key"
        );

        let blank = crate::config::Config {
            gpg_signing_key_id: Some("   ".to_string()),
            ..base
        };
        assert!(
            !SignConfig::signing_required(&blank),
            "blank key is not a signing policy"
        );
    }

    #[tokio::test]
    async fn validate_gpg_home_async_rejects_invalid() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("gnupg");
        std::fs::create_dir_all(&home).unwrap();
        let perms = std::fs::Permissions::from_mode(0o777);
        std::fs::set_permissions(&home, perms).unwrap();

        let result = SignConfig::validate_gpg_home_async(home, test_euid()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn sign_rpms_empty_paths_returns_ok() {
        let signer = Signer::new();
        let config = SignConfig {
            key_id: "dummy@example.com".to_string(),
            gpg_home: None,
        };
        // 空 paths 在拿锁之前早退，result_dir 不会被访问。
        let result = signer
            .sign_rpms(&config, Path::new("/nonexistent-result-dir"), &[])
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn sign_rpms_acquires_and_releases_sign_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let rpm = tmp.path().join("a.rpm");
        std::fs::write(&rpm, b"stub").unwrap();
        let signer = Signer::new();
        let config = SignConfig {
            key_id: "dummy@example.com".to_string(),
            gpg_home: None,
        };
        let paths = [rpm.as_path()];

        // rpmsign 缺失（非 Linux CI）或拒绝伪 RPM 都发生在拿锁后：结果必 Err 且锁文件已创建。
        let result = signer.sign_rpms(&config, tmp.path(), &paths).await;
        assert!(result.is_err());
        assert!(tmp.path().join(".sign.lock").exists());

        // 锁随函数返回释放：同进程新 fd 应能立即重新获取（不等到超时）。
        let guard = acquire_result_dir_sign_lock(tmp.path()).await;
        assert!(
            guard.is_ok(),
            "sign lock should be re-acquirable after sign_rpms returns"
        );
    }

    #[test]
    fn stderr_tail_truncates_to_cap() {
        let stderr = vec![b'x'; SIGN_STDERR_TAIL_BYTES + 10];
        let tail = stderr_tail(&stderr);
        assert_eq!(tail.len(), SIGN_STDERR_TAIL_BYTES);
        assert!(stderr_tail(b"boom").contains("boom"));
    }

    #[tokio::test]
    async fn key_available_with_missing_key_returns_false() {
        let signer = Signer::new();
        let config = SignConfig {
            key_id: "nonexistent-key-id-12345678".to_string(),
            gpg_home: None,
        };
        let result = signer.key_available(&config).await;
        // gpg 命令可能不存在于 macOS 测试环境，但 spawn 应成功，gpg 本身返回失败。
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn sign_config_from_config_returns_none_when_key_missing() {
        let config = crate::config::Config {
            product: "test".to_string(),
            gpg_signing_key_id: None,
            gpg_home: None,
            ..Default::default()
        };
        assert!(SignConfig::from_config(&config).is_none());
    }

    #[test]
    fn sign_config_from_config_returns_some_when_key_present() {
        let tmp = tempfile::tempdir().unwrap();
        let gpg_home = make_test_gpg_home(tmp.path());

        let config = crate::config::Config {
            product: "test".to_string(),
            gpg_signing_key_id: Some("key@example.com".to_string()),
            gpg_home: Some(gpg_home.to_str().unwrap().to_string()),
            ..Default::default()
        };
        let sc = SignConfig::from_config(&config).expect("should be Some");
        assert_eq!(sc.key_id, "key@example.com");
        assert_eq!(
            sc.gpg_home,
            Some(
                gpg_home
                    .canonicalize()
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            )
        );
    }

    #[test]
    fn collect_sign_paths_empty() {
        let outputs = crate::types::BuildOutputs {
            build_id: 1,
            pkg_name: "pkg".to_string(),
            rpms: vec![],
            srpms: vec![],
            logs: vec![],
            result_dir: PathBuf::from("/tmp"),
            retries: 0,
            signed: false,
        };
        let paths = collect_sign_paths(&outputs);
        assert!(paths.is_empty());
    }

    #[test]
    fn collect_sign_paths_with_rpms_and_srpms() {
        let outputs = crate::types::BuildOutputs {
            build_id: 1,
            pkg_name: "pkg".to_string(),
            rpms: vec![PathBuf::from("/tmp/RPMS/a.rpm")],
            srpms: vec![PathBuf::from("/tmp/SRPMS/b.src.rpm")],
            logs: vec![],
            result_dir: PathBuf::from("/tmp"),
            retries: 0,
            signed: false,
        };
        let paths = collect_sign_paths(&outputs);
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], std::path::Path::new("/tmp/RPMS/a.rpm"));
        assert_eq!(paths[1], std::path::Path::new("/tmp/SRPMS/b.src.rpm"));
    }

    #[tokio::test]
    async fn sign_build_outputs_no_config_returns_early() {
        let temp_dir = tempfile::tempdir().unwrap();

        let mut outputs = crate::types::BuildOutputs {
            build_id: 1,
            pkg_name: "pkg".to_string(),
            rpms: vec![PathBuf::from("/tmp/test.rpm")],
            srpms: vec![],
            logs: vec![],
            result_dir: temp_dir.path().to_path_buf(),
            retries: 0,
            signed: false,
        };

        let config = crate::config::Config {
            product: "test".to_string(),
            gpg_signing_key_id: None,
            gpg_home: None,
            ..Default::default()
        };

        sign_build_outputs(&mut outputs, &config).await;
        assert!(!outputs.signed);
    }

    #[tokio::test]
    async fn sign_build_outputs_no_paths_returns_early() {
        let temp_dir = tempfile::tempdir().unwrap();

        let mut outputs = crate::types::BuildOutputs {
            build_id: 1,
            pkg_name: "pkg".to_string(),
            rpms: vec![],
            srpms: vec![],
            logs: vec![],
            result_dir: temp_dir.path().to_path_buf(),
            retries: 0,
            signed: false,
        };

        let config = crate::config::Config {
            product: "test".to_string(),
            gpg_signing_key_id: Some("key@example.com".to_string()),
            gpg_home: None,
            ..Default::default()
        };

        sign_build_outputs(&mut outputs, &config).await;
        assert!(!outputs.signed);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sign_build_outputs_key_unavailable_leaves_permissions_untouched() {
        let temp_dir = tempfile::tempdir().unwrap();

        let rpm_dir = temp_dir.path().join("RPMS");
        std::fs::create_dir_all(&rpm_dir).unwrap();
        let rpm = rpm_dir.join("a.rpm");
        std::fs::write(&rpm, b"stub").unwrap();
        std::fs::set_permissions(&rpm, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&rpm_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mut outputs = crate::types::BuildOutputs {
            build_id: 1,
            pkg_name: "pkg".to_string(),
            rpms: vec![rpm.clone()],
            srpms: vec![],
            logs: vec![],
            result_dir: rpm_dir.clone(),
            retries: 0,
            signed: false,
        };

        // key 不存在必须在 pre-sign chmod 前早退（早退无 restore chmod），权限不得停留放宽态。
        let config = crate::config::Config {
            product: "test".to_string(),
            gpg_signing_key_id: Some("nonexistent-key-id-12345678".to_string()),
            gpg_home: None,
            ..Default::default()
        };

        sign_build_outputs(&mut outputs, &config).await;
        assert!(!outputs.signed);

        let file_mode = std::fs::metadata(&rpm).unwrap().permissions().mode() & 0o777;
        let dir_mode = std::fs::metadata(&rpm_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            file_mode, 0o644,
            "rpm mode must not be widened when sign is skipped"
        );
        assert_eq!(
            dir_mode, 0o755,
            "parent dir mode must not be widened when sign is skipped"
        );
    }

    /// chmod_outputs 恢复终态 = 权限不变量（文件 0660、目录 2770），不回落 world-read。
    #[tokio::test]
    async fn chmod_outputs_converges_to_invariant_modes() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rpm_dir = temp_dir.path().join("RPMS");
        std::fs::create_dir_all(&rpm_dir).unwrap();
        let rpm = rpm_dir.join("a.rpm");
        std::fs::write(&rpm, b"stub").unwrap();
        std::fs::set_permissions(&rpm, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&rpm_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        chmod_outputs(vec![rpm.clone()], 0o660, 0o2770, "restore").await;

        let file_mode = std::fs::metadata(&rpm).unwrap().permissions().mode() & 0o7777;
        let dir_mode = std::fs::metadata(&rpm_dir).unwrap().permissions().mode() & 0o7777;
        assert_eq!(file_mode, 0o660, "rpm must converge to group-writable 0660");
        assert_eq!(dir_mode, 0o2770, "parent dir must converge to setgid 2770");
    }
}
