// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 远程 server 解析与 HTTP client 共享逻辑，供各 `--remote` 命令复用。

use std::path::{Path, PathBuf};

use anyhow::Result;
use crbs_core::error::CrbsError;
use tokio::sync::OnceCell;

use super::http::build_http_client;

/// 解析后的远程 server 目标。
pub struct RemoteTarget {
    pub url: String,
    pub token: Option<String>,
    pub ca_cert: Option<PathBuf>,
    cached_client: OnceCell<reqwest::Client>,
}

impl Clone for RemoteTarget {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            token: self.token.clone(),
            ca_cert: self.ca_cert.clone(),
            cached_client: OnceCell::new(),
        }
    }
}

impl RemoteTarget {
    /// 构造 `RemoteTarget`，内部 client 首次调用 `client()` 时懒初始化。
    pub fn new(url: String, token: Option<String>, ca_cert: Option<PathBuf>) -> Self {
        Self {
            url,
            token,
            ca_cert,
            cached_client: OnceCell::new(),
        }
    }

    /// 获取缓存的 HTTP client（首次调用构建，后续复用）。
    pub async fn client(&self) -> Result<&reqwest::Client> {
        self.cached_client
            .get_or_try_init(|| build_http_client(&self.token, &self.ca_cert))
            .await
    }
}

impl std::fmt::Debug for RemoteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteTarget")
            .field("url", &self.url)
            .field("token", &self.token.as_deref().map(|_| "<redacted>"))
            .field("ca_cert", &self.ca_cert)
            .field("client_cached", &self.cached_client.initialized())
            .finish()
    }
}

/// 根据 CLI 参数、配置文件与本地强制标志解析远程 server。优先级：
/// `local_override` → `None`（强制本地）；`remote_arg` 显式指定 → 按 URL /
/// profile 名解析；`remote.default` → 按该 profile；否则 `None`（本地）。
pub async fn resolve(
    remote_arg: Option<String>,
    token_arg: Option<String>,
    ca_cert_arg: Option<PathBuf>,
    local_override: bool,
) -> Result<Option<RemoteTarget>> {
    let cfg = crbs_core::config::CrbsConfig::load_merged_async().await?;

    if local_override {
        return Ok(None);
    }

    let input = match remote_arg {
        Some(v) => v,
        None => match cfg.remote.default_profile() {
            Some(d) => d.to_string(),
            None => return Ok(None),
        },
    };

    let (url, token, ca_cert) = resolve_input(&input, &cfg.remote, token_arg, ca_cert_arg).await?;
    // ca_cert 无论来源（profile/env/CLI）统一展开前导 `~`，与文档声明一致。
    let ca_cert = ca_cert.map(|p| expand_tilde(&p));
    enforce_plaintext_token_policy(&url, token.as_deref())?;
    Ok(Some(RemoteTarget::new(url, token, ca_cert)))
}

/// 解析**配置源** target，专供 `api::product::load_product_config`，不得与
/// 执行 target 混用。不接受 `local_override`：`--local` 只影响执行位置，
/// 配置来源由 `--offline` 独立控制；语义等同 `resolve(.., local_override = false)`。
pub async fn resolve_config_target(
    remote_arg: Option<String>,
    token_arg: Option<String>,
    ca_cert_arg: Option<PathBuf>,
) -> Result<Option<RemoteTarget>> {
    resolve(remote_arg, token_arg, ca_cert_arg, false).await
}

async fn resolve_input(
    input: &str,
    remote_cfg: &crbs_core::config::RemoteConfig,
    cli_token: Option<String>,
    cli_ca_cert: Option<PathBuf>,
) -> Result<(String, Option<String>, Option<PathBuf>)> {
    if is_remote_url(input) {
        let token = cli_token.or_else(|| std::env::var("CRBS_TOKEN").ok());
        // raw URL 匹配某 profile 的 URL 时继承其 ca_cert（--remote 直接给 URL 也用配置证书）。
        let normalized_input = normalize_base_url(input)?;
        let ca_cert = cli_ca_cert
            .or_else(|| {
                remote_cfg
                    .profiles
                    .iter()
                    .find(|p| {
                        normalize_base_url(&p.url).ok().as_deref()
                            == Some(normalized_input.as_str())
                    })
                    .and_then(|p| p.ca_cert.clone())
            })
            .or_else(env_ca_cert);
        return Ok((normalized_input, token, ca_cert));
    }

    let profile = remote_cfg
        .profiles
        .iter()
        .find(|p| p.name == input)
        .ok_or_else(|| {
            // 客户端配置类错误（USAGE=4）：消息文案保持不变。
            let names: Vec<_> = remote_cfg
                .profiles
                .iter()
                .map(|p| p.name.as_str())
                .collect();
            CrbsError::ValidationFailed {
                message: format!(
                    "remote profile '{}' not found; configured profiles: {}",
                    input,
                    if names.is_empty() {
                        "(none)".to_string()
                    } else {
                        names.join(", ")
                    }
                ),
            }
        })?;

    let url = normalize_base_url(&profile.url)?;

    if let Some(t) = cli_token {
        let ca_cert = cli_ca_cert
            .or_else(|| profile.ca_cert.clone())
            .or_else(env_ca_cert);
        return Ok((url, Some(t), ca_cert));
    }

    let token = resolve_profile_token(profile).await?;
    let ca_cert = cli_ca_cert
        .or_else(|| profile.ca_cert.clone())
        .or_else(env_ca_cert);
    Ok((url, token, ca_cert))
}

fn env_ca_cert() -> Option<PathBuf> {
    std::env::var("CRBS_CA_CERT").ok().map(PathBuf::from)
}

/// 按优先级解析 profile token：token > token_env > token_file > CRBS_TOKEN。
/// `token_env` 未设/为空时 warn 后落穿（不报错）——拼错 env 名属配置错误，
/// 落穿给用户的是"最终 401 + warn 日志"而非直接失败。
async fn resolve_profile_token(
    profile: &crbs_core::config::RemoteProfile,
) -> Result<Option<String>> {
    if let Some(t) = &profile.token {
        return Ok(Some(t.clone()));
    }
    if let Some(env_name) = &profile.token_env {
        match std::env::var(env_name) {
            // 空串视同未设：与拼错 env 名同族故障，同样落穿。
            Ok(t) if !t.is_empty() => return Ok(Some(t)),
            _ => tracing::warn!(
                env = %env_name,
                profile = %profile.name,
                "token_env points to an unset or empty environment variable; falling back to token_file/CRBS_TOKEN"
            ),
        }
    }
    if let Some(path) = &profile.token_file {
        let path = expand_tilde(path);
        // 防御性权限检查：group/other 可写仅 warn——权限语义随 OS/环境（如容器）而异，不拒绝。
        if let Ok(meta) = tokio::fs::metadata(&path).await {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode();
                if mode & 0o022 != 0 {
                    tracing::warn!(
                        path = %path.display(),
                        mode = format!("{:04o}", mode),
                        "token file is writable by group or other; consider chmod 0600"
                    );
                }
            }
            let _ = meta; // suppress unused variable on non-unix
        }
        // 读不出（缺失/权限等 io 错误）属本地环境故障：Io（kind 保真，
        // ENVIRONMENT=6），不经 anyhow context 落 INTERNAL(1)；与 malformed →
        // ValidationFailed、token_env 落穿三分边界；message 保留 context 串并内联 io 文本。
        let content = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| CrbsError::Io {
                context: format!("read token file {}", path.display()),
                kind: e.kind(),
                detail: e.to_string(),
            })?;
        let token = content.trim();
        // 格式校验 fail-fast：垃圾串直接报错，而非当 token 发出去换难排查的 401。
        // 客户端配置类错误（USAGE=4）：消息文案保持不变。
        crbs_core::auth::secret::Secret::parse(token).map_err(|e| CrbsError::ValidationFailed {
            message: format!(
                "token file {} is malformed (expected a crbs_tok_/crbs_wkr_ \
                     prefixed token): {e}",
                path.display()
            ),
        })?;
        return Ok(Some(token.to_string()));
    }
    Ok(std::env::var("CRBS_TOKEN").ok())
}

/// 判断输入是 URL 还是 profile 名：显式 scheme（任何含 `://`）或裸
/// `host:port`（如 crbs.example.com:9090）按 URL；非 http/https scheme 也按
/// URL，交 [`normalize_base_url`] 报"仅支持 http/https"而非误报 profile not found。
/// pub(crate)：`crbs remote add` 复用同一判定拒绝"长得像 URL"的 profile 名
///（URL 形态名字在 `--remote` 永远按 ad-hoc URL 解析，profile 不可达）。
pub(crate) fn is_remote_url(input: &str) -> bool {
    if input.starts_with("http://") || input.starts_with("https://") {
        return true;
    }
    if input.contains("://") {
        return true;
    }
    if let Some((host, port)) = input.rsplit_once(':') {
        return !host.is_empty() && port.parse::<u16>().is_ok();
    }
    false
}

/// 规范化 base URL：trim 尾部 `/`，校验 scheme 仅 http/https，无 scheme 补 `http://`。
pub fn normalize_base_url(url: &str) -> Result<String> {
    let url = url.trim_end_matches('/');
    if let Some(colon) = url.find("://") {
        let scheme = &url[..colon];
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            // 客户端配置类错误（USAGE=4）：消息文案保持不变。
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "unsupported URL scheme '{scheme}://'; only http:// and https:// are supported"
                ),
            }
            .into());
        }
        return Ok(url.to_string());
    }
    Ok(format!("http://{}", url))
}

/// 环境变量：设为 `1` / `true` / `yes` 时允许明文 HTTP 向**非** loopback 主机
/// 发送 Bearer token；仅受控内网诊断用，生产请改用 `https://`。
const ENV_ALLOW_PLAINTEXT_TOKEN: &str = "CRBS_ALLOW_PLAINTEXT_TOKEN";

/// 从规范化后的 base URL 中抽出 host（不含端口）。
fn extract_host(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let host_port = rest.split('/').next().unwrap_or("");
    // IPv6 字面量：`[::1]:8080`
    if let Some(stripped) = host_port.strip_prefix('[') {
        return stripped.split(']').next();
    }
    Some(host_port.rsplitn(2, ':').last().unwrap_or(host_port))
}

/// 判断 host 是否属于 loopback（本机回环，明文 HTTP 携带 token 可接受）。
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if host.eq_ignore_ascii_case("localhost") || host == "::1" {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return ip.is_loopback();
    }
    if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        return ip.is_loopback();
    }
    false
}

fn env_flag_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let normalized = v.trim().to_ascii_lowercase();
            if matches!(normalized.as_str(), "1" | "true" | "yes" | "on") {
                true
            } else {
                // 非空非真值静默按 disabled 会坑排障——warn 可见化；空串/纯空白视为未设。
                if !normalized.is_empty() {
                    tracing::warn!(
                        env = name,
                        value = %v,
                        "not recognized as truthy; treating as disabled"
                    );
                }
                false
            }
        }
        Err(_) => false,
    }
}

/// 拒绝明文 HTTP + 非 loopback 主机携带 Bearer token（防 token 明文流出）。
/// - `https://` 或无 token：放行；`http://` + loopback：允许（本地 dev / daemon）。
/// - `http://` + 非 loopback + 有 token：默认拒绝（`ValidationFailed`）；临时
///   容忍需显式设 `CRBS_ALLOW_PLAINTEXT_TOKEN=1`（不推荐）。
fn enforce_plaintext_token_policy(url: &str, token: Option<&str>) -> Result<()> {
    enforce_plaintext_token_policy_inner(url, token, env_flag_truthy(ENV_ALLOW_PLAINTEXT_TOKEN))
}

fn enforce_plaintext_token_policy_inner(
    url: &str,
    token: Option<&str>,
    allow_override: bool,
) -> Result<()> {
    if token.is_none() {
        return Ok(());
    }
    if url.starts_with("https://") {
        return Ok(());
    }
    let host = extract_host(url).unwrap_or("");
    if is_loopback_host(host) {
        return Ok(());
    }
    if allow_override {
        tracing::warn!(
            host = %host,
            "sending bearer token over plaintext http:// per {} override",
            ENV_ALLOW_PLAINTEXT_TOKEN,
        );
        return Ok(());
    }
    // 用户可自行修正的配置问题 → ValidationFailed（USAGE=4），不落 INTERNAL(1)
    //（exit 1 会误报 "this is a bug" hint）；文案逐字保留、仅加变体前缀（测试钉住）。
    Err(CrbsError::ValidationFailed {
        message: format!(
            "refusing to send bearer token over plaintext http:// to non-loopback host `{}`; \
             use `https://{}` (recommended) or set `{}=1` to override (not recommended)",
            host, host, ENV_ALLOW_PLAINTEXT_TOKEN
        ),
    }
    .into())
}

pub fn expand_tilde(path: &Path) -> PathBuf {
    if let Some(std::path::Component::Normal(os)) = path.components().next() {
        if os == "~" {
            if let Some(home) = home::home_dir() {
                return home.join(path.strip_prefix("~").unwrap_or(path));
            }
        }
    }
    path.to_path_buf()
}

#[cfg(test)]
mod plaintext_token_tests {
    use super::{
        enforce_plaintext_token_policy_inner, extract_host, is_loopback_host, normalize_base_url,
    };

    #[test]
    fn normalize_still_defaults_to_http() {
        assert_eq!(
            normalize_base_url("hub.example.com").unwrap(),
            "http://hub.example.com"
        );
        assert_eq!(
            normalize_base_url("https://hub.example.com/").unwrap(),
            "https://hub.example.com"
        );
    }

    #[test]
    fn normalize_rejects_non_http_scheme() {
        assert!(normalize_base_url("ftp://example.com").is_err());
        assert!(normalize_base_url("ssh://example.com").is_err());
        assert!(normalize_base_url("file:///tmp/x").is_err());
        assert!(normalize_base_url("http://example.com").is_ok());
        assert!(normalize_base_url("https://example.com").is_ok());
    }

    #[test]
    fn extract_host_variants() {
        assert_eq!(
            extract_host("http://hub.example.com"),
            Some("hub.example.com")
        );
        assert_eq!(
            extract_host("http://hub.example.com:9090"),
            Some("hub.example.com")
        );
        assert_eq!(
            extract_host("https://192.168.1.1:18443/api/v1"),
            Some("192.168.1.1")
        );
        assert_eq!(extract_host("http://[::1]:9090"), Some("::1"));
        assert_eq!(extract_host("ftp://weird"), None);
    }

    #[test]
    fn loopback_recognition() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LOCALHOST"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.5.6.7"));
        assert!(is_loopback_host("::1"));
        assert!(!is_loopback_host("192.168.1.1"));
        assert!(!is_loopback_host("hub.example.com"));
        assert!(!is_loopback_host(""));
    }

    #[test]
    fn no_token_always_ok() {
        assert!(
            enforce_plaintext_token_policy_inner("http://hub.example.com", None, false).is_ok()
        );
    }

    #[test]
    fn https_always_ok_with_token() {
        assert!(
            enforce_plaintext_token_policy_inner("https://hub.example.com", Some("t"), false)
                .is_ok()
        );
    }

    #[test]
    fn loopback_http_with_token_ok() {
        assert!(
            enforce_plaintext_token_policy_inner("http://127.0.0.1:9090", Some("t"), false).is_ok()
        );
        assert!(
            enforce_plaintext_token_policy_inner("http://localhost:9090", Some("t"), false).is_ok()
        );
    }

    /// 拒绝属用户可修正配置问题：ValidationFailed（USAGE=4）不落 INTERNAL(1)；
    /// 变体 + 退出码 + 原文案（含变体前缀）三形态钉住。
    #[test]
    fn plain_http_non_loopback_with_token_maps_to_validation_failed_exit_4() {
        use crbs_core::error::CrbsError;
        use crbs_core::exit_code::{crbs_error_exit_code, USAGE};

        let err = enforce_plaintext_token_policy_inner("http://192.168.1.1:9090", Some("t"), false)
            .unwrap_err();
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::ValidationFailed { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_error_exit_code(ce), USAGE);
        let msg = format!("{ce}");
        assert!(
            msg.starts_with(
                "validation failed: refusing to send bearer token over plaintext http://"
            ),
            "original bail text must be preserved after the variant prefix: {msg}"
        );
        assert!(msg.contains("192.168.1.1"), "unexpected message: {msg}");
        assert!(
            msg.contains("CRBS_ALLOW_PLAINTEXT_TOKEN"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn allow_override_lets_it_through() {
        assert!(
            enforce_plaintext_token_policy_inner("http://192.168.1.1:9090", Some("t"), true)
                .is_ok()
        );
    }
}

#[cfg(test)]
mod env_flag_truthy_tests {
    //! 非空非真值垃圾值 warn 可见化但返回值不变（false）。EnvGuard 以 crate 级
    //! env 锁序列化并发测试的进程环境访问；warn 输出不在此捕获。

    use super::env_flag_truthy;
    use super::ENV_ALLOW_PLAINTEXT_TOKEN;
    use crate::test_support::EnvGuard;
    use tempfile::TempDir;

    #[test]
    fn garbage_value_is_false_truthy_values_are_true() {
        let tmp = TempDir::new().expect("tempdir");
        let _guard = EnvGuard::new(tmp.path());

        std::env::set_var(ENV_ALLOW_PLAINTEXT_TOKEN, "yes please");
        assert!(!env_flag_truthy(ENV_ALLOW_PLAINTEXT_TOKEN));

        for v in ["true", "1", "yes", "on", "  TRUE  "] {
            std::env::set_var(ENV_ALLOW_PLAINTEXT_TOKEN, v);
            assert!(env_flag_truthy(ENV_ALLOW_PLAINTEXT_TOKEN), "v = {v:?}");
        }

        std::env::set_var(ENV_ALLOW_PLAINTEXT_TOKEN, "   ");
        assert!(!env_flag_truthy(ENV_ALLOW_PLAINTEXT_TOKEN));

        std::env::remove_var(ENV_ALLOW_PLAINTEXT_TOKEN);
    }
}

#[cfg(test)]
mod resolve_orthogonality_tests {
    //! 验证 `--local`（执行位置）与 config target（配置来源）正交：同一显式 URL，
    //! `resolve(.., local_override = true)` 返回 None，`resolve_config_target`
    //! 仍返回 Some。显式 URL 绕开 `remote.default` 解析，无需构造 crbs.toml；
    //! tempdir 隔离 `CRBS_CONFIG_DIR` 防读 CI 主机 /etc/crbs。

    use super::resolve;
    use super::resolve_config_target;
    use crate::test_support::EnvGuard;
    use tempfile::TempDir;

    #[tokio::test]
    async fn local_override_kills_execution_target_but_not_config_target() {
        let tmp = TempDir::new().expect("tempdir");
        let _env = EnvGuard::new(tmp.path());

        // 显式 URL，用 loopback + 无 token，规避 plaintext-token 策略。
        let url = Some("http://127.0.0.1:1".to_string());

        let exec = resolve(url.clone(), None, None, true)
            .await
            .expect("resolve should succeed");
        assert!(
            exec.is_none(),
            "--local should force execution to local, got {:?}",
            exec
        );

        let cfg = resolve_config_target(url, None, None)
            .await
            .expect("resolve_config_target should succeed");
        let cfg = cfg.expect("explicit URL should produce a config target");
        assert_eq!(cfg.url, "http://127.0.0.1:1");
    }
}

#[cfg(test)]
mod url_detection_tests {
    use super::is_remote_url;

    #[test]
    fn http_and_bare_host_port_are_urls() {
        assert!(is_remote_url("http://example.com"));
        assert!(is_remote_url("https://example.com:9090/base"));
        assert!(is_remote_url("crbs.example.com:9090"));
    }

    /// 非 http/https scheme 必须按 URL 处理，进 normalize_base_url 报 scheme
    /// 拒绝错误而非误报 profile not found（否则 scheme 校验变死代码）。
    #[test]
    fn any_explicit_scheme_is_url() {
        assert!(is_remote_url("ftp://example.com"));
        assert!(is_remote_url("ssh://user@host"));
        assert!(is_remote_url("unix:///tmp/crbs.sock"));
    }

    #[test]
    fn plain_names_are_profiles() {
        assert!(!is_remote_url("my-profile"));
        assert!(!is_remote_url("prod"));
        // 冒号后非端口 → 仍是 profile 名。
        assert!(!is_remote_url("a:b"));
    }
}

#[cfg(test)]
mod token_file_tests {
    //! `token_file` 内容必须通过 `Secret::parse` 格式校验：
    //! 合法 token 原样返回（trim 尾随换行），垃圾内容 fail-fast 报错。

    use super::resolve_profile_token;
    use crbs_core::auth::secret::{Secret, SecretKind};
    use crbs_core::config::RemoteProfile;
    use tempfile::TempDir;

    fn profile_with_token_file(path: std::path::PathBuf) -> RemoteProfile {
        RemoteProfile {
            name: "hub".into(),
            url: "https://hub.example.com".into(),
            token: None,
            token_env: None,
            token_file: Some(path),
            ca_cert: None,
        }
    }

    #[tokio::test]
    async fn token_file_with_valid_token_is_returned() {
        let tmp = TempDir::new().expect("tempdir");
        let secret = Secret::generate(SecretKind::UserToken).expect("secret");
        let file = tmp.path().join("token");
        std::fs::write(&file, format!("{}\n", secret.as_str())).expect("write");

        let token = resolve_profile_token(&profile_with_token_file(file))
            .await
            .expect("resolve");
        assert_eq!(token.as_deref(), Some(secret.as_str()));
    }

    /// 垃圾内容 fail-fast，错误信息点明期望的 crbs_tok_/crbs_wkr_ 前缀。
    #[tokio::test]
    async fn token_file_with_malformed_content_fails_fast() {
        let tmp = TempDir::new().expect("tempdir");
        let file = tmp.path().join("token");
        std::fs::write(&file, "not-a-valid-token").expect("write");

        let err = resolve_profile_token(&profile_with_token_file(file))
            .await
            .expect_err("malformed token file must fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("malformed"), "got: {msg}");
        assert!(msg.contains("crbs_tok_"), "got: {msg}");
    }

    /// 读不出（缺失/权限等 io 错误）属本地环境故障：Io（kind 保真，
    /// ENVIRONMENT=6），不落 INTERNAL(1)；变体 + 退出码 + 原 context 串三形态钉住。
    #[tokio::test]
    async fn token_file_unreadable_maps_to_io_exit_6() {
        use crbs_core::exit_code::{crbs_error_exit_code, ENVIRONMENT};

        let tmp = TempDir::new().expect("tempdir");
        let file = tmp.path().join("absent-token-file");

        let err = resolve_profile_token(&profile_with_token_file(file.clone()))
            .await
            .expect_err("missing token file must fail");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        let crbs_core::error::CrbsError::Io {
            context,
            kind,
            detail,
        } = ce
        else {
            panic!("expected Io, got: {ce}");
        };
        assert_eq!(context, &format!("read token file {}", file.display()));
        assert_eq!(*kind, std::io::ErrorKind::NotFound);
        assert!(!detail.is_empty(), "underlying io text must be kept");
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
    }
}

#[cfg(test)]
mod token_env_tests {
    //! `token_env` 指向未设置（或为空）的环境变量时不能静默落穿——
    //! warn 后落穿 token_file / CRBS_TOKEN；全无 → None。

    use super::resolve_profile_token;
    use crbs_core::auth::secret::{Secret, SecretKind};
    use crbs_core::config::RemoteProfile;
    use tempfile::TempDir;

    fn profile_with_token_env_and_file(
        env_name: &str,
        token_file: std::path::PathBuf,
    ) -> RemoteProfile {
        RemoteProfile {
            name: "hub".into(),
            url: "https://hub.example.com".into(),
            token: None,
            token_env: Some(env_name.into()),
            token_file: Some(token_file),
            ca_cert: None,
        }
    }

    /// env 名带进程 id 后缀防宿主恰好设置；断言落穿到 token_file 而非 None
    ///（后者依赖宿主未导出 CRBS_TOKEN，开发机导出时测试必红）。
    #[tokio::test]
    async fn token_env_unset_falls_through_to_token_file() {
        let tmp = TempDir::new().expect("tempdir");
        let secret = Secret::generate(SecretKind::UserToken).expect("secret");
        let file = tmp.path().join("token");
        std::fs::write(&file, format!("{}\n", secret.as_str())).expect("write");

        let env_name = format!("CRBS_TEST_TOKEN_ENV_UNSET_{}", std::process::id());
        let token = resolve_profile_token(&profile_with_token_env_and_file(&env_name, file))
            .await
            .expect("unset token_env must not error");
        assert_eq!(token.as_deref(), Some(secret.as_str()));
    }
}
