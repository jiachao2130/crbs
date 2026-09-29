// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 日志辅助：tracing subscriber 统一初始化（各二进制 main 收口到此）+ 日志脱敏
//! （开关见 `LogSanitizationConfig`）。例外：crbs-priv-helper 刻意不依赖
//! crbs-core（setuid 最小审计面），filter 钉死 "info"、不读 RUST_LOG 的初始化留其 main.rs。

use std::path::Path;

use crate::config::LogSanitizationConfig;

/// 统一 tracing 初始化（crbs-server / crbs CLI main）：`RUST_LOG` 优先（宽松解析：
/// 无效指令丢弃、其余生效），缺省 `default_filter`，重复 `.init()` panic；差异见 [`init_tracing_stdout`]。
pub fn init_tracing(default_filter: &str) {
    let env_filter = if let Ok(rust_log) = std::env::var("RUST_LOG") {
        tracing_subscriber::EnvFilter::new(rust_log)
    } else {
        tracing_subscriber::EnvFilter::new(default_filter)
    };
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .init();
}

/// crbs-worker 专用变体，与 [`init_tracing`] 两处刻意差异（勿顺手统一）：writer 为 stdout
/// （worker 历史行为，非 stderr）；`RUST_LOG` 严格解析，无效指令整体回退 `default_filter`（后者宽松）。
pub fn init_tracing_stdout(default_filter: &str) {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
}

/// 脱敏查询字符串中的 `token` 参数。
pub fn sanitize_query(query: &str, cfg: &LogSanitizationConfig) -> String {
    if !cfg.redact_tokens || query.is_empty() {
        return query.to_string();
    }
    query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, _)) if key.eq_ignore_ascii_case("token") => format!("{}=<redacted>", key),
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// 无条件剥离 URL userinfo（`user:pass@host` → `host`），供错误/警告日志：
/// 仓库凭证是泄露红线，不随 `redact_urls` 开关（该开关只管访问日志展示噪音）。
pub fn redact_userinfo(url: &str) -> String {
    let cfg = LogSanitizationConfig {
        redact_urls: true,
        ..LogSanitizationConfig::default()
    };
    sanitize_url(url, &cfg)
}

/// 按 `redact_urls` 剥离 URL user:pass 凭证（'@' 边界语义见函数内注释）；关闭或无凭证时原样返回。
pub fn sanitize_url(url: &str, cfg: &LogSanitizationConfig) -> String {
    if !cfg.redact_urls {
        return url.to_string();
    }
    let Some((scheme, after_scheme)) = url.split_once("://") else {
        return url.to_string();
    };
    // authority 至首个 '/'/'?'；userinfo 取其中最后一个 '@'（RFC 3986），防 path/query 的 '@' 误判
    let auth_end = after_scheme.find(['/', '?']).unwrap_or(after_scheme.len());
    let Some(cred_end) = after_scheme[..auth_end].rfind('@') else {
        return url.to_string();
    };
    format!("{}://{}", scheme, &after_scheme[cred_end + 1..])
}

/// 脱敏 repo `extra` 行中的敏感 key（proxy、proxy_password、sslclientcert 等）。
pub fn sanitize_repo_extra_line(line: &str, cfg: &LogSanitizationConfig) -> String {
    if !cfg.redact_urls && !cfg.redact_paths {
        return line.to_string();
    }
    let Some((key, value)) = line.split_once('=') else {
        return line.to_string();
    };
    let key_trimmed = key.trim();
    match key_trimmed {
        "proxy" | "proxy_username" | "proxy_password" | "sslclientcert" | "sslclientkey"
            if cfg.redact_urls =>
        {
            format!("{}=<redacted>", key_trimmed)
        }
        "baseurl" => {
            // baseurl 先剥凭证（redact_urls）再取 basename（redact_paths）
            let mut v = value.to_string();
            if cfg.redact_urls {
                v = sanitize_url(&v, cfg);
            }
            if cfg.redact_paths {
                v = Path::new(&v)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "<redacted>".to_string());
            }
            format!("{}={}", key_trimmed, v)
        }
        _ => line.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(tokens: bool, urls: bool, paths: bool) -> LogSanitizationConfig {
        LogSanitizationConfig {
            redact_tokens: tokens,
            redact_urls: urls,
            redact_paths: paths,
        }
    }

    #[test]
    fn sanitize_query_redacts_token() {
        assert_eq!(
            sanitize_query("token=secret&foo=bar", &cfg(true, false, false)),
            "token=<redacted>&foo=bar"
        );
    }

    #[test]
    fn sanitize_query_preserves_other_params() {
        assert_eq!(
            sanitize_query("build=1&phase=running", &cfg(true, false, false)),
            "build=1&phase=running"
        );
    }

    #[test]
    fn sanitize_query_case_insensitive_token() {
        assert_eq!(
            sanitize_query("TOKEN=secret&foo=bar", &cfg(true, false, false)),
            "TOKEN=<redacted>&foo=bar"
        );
    }

    #[test]
    fn sanitize_query_disabled_returns_unchanged() {
        assert_eq!(
            sanitize_query("token=secret&foo=bar", &cfg(false, false, false)),
            "token=secret&foo=bar"
        );
    }

    #[test]
    fn sanitize_url_strips_user_pass() {
        assert_eq!(
            sanitize_url(
                "http://user:pass@repo.example.com/path",
                &cfg(false, true, false)
            ),
            "http://repo.example.com/path"
        );
    }

    #[test]
    fn sanitize_url_strips_only_user() {
        assert_eq!(
            sanitize_url(
                "http://user@repo.example.com/path",
                &cfg(false, true, false)
            ),
            "http://repo.example.com/path"
        );
    }

    #[test]
    fn sanitize_url_leaves_plain_url_unchanged() {
        assert_eq!(
            sanitize_url("http://repo.example.com/path", &cfg(false, true, false)),
            "http://repo.example.com/path"
        );
    }

    #[test]
    fn sanitize_url_strips_password_containing_at() {
        assert_eq!(
            sanitize_url(
                "http://user:p@ss@repo.example.com/path",
                &cfg(false, true, false)
            ),
            "http://repo.example.com/path"
        );
    }

    #[test]
    fn sanitize_url_leaves_path_with_at_unchanged() {
        assert_eq!(
            sanitize_url("http://repo.example.com/a@b", &cfg(false, true, false)),
            "http://repo.example.com/a@b"
        );
    }

    #[test]
    fn sanitize_url_leaves_query_with_at_unchanged() {
        assert_eq!(
            sanitize_url("http://repo.example.com/p?x=a@b", &cfg(false, true, false)),
            "http://repo.example.com/p?x=a@b"
        );
    }

    #[test]
    fn sanitize_url_disabled_returns_unchanged() {
        assert_eq!(
            sanitize_url(
                "http://user:pass@repo.example.com/path",
                &cfg(false, false, false)
            ),
            "http://user:pass@repo.example.com/path"
        );
    }

    #[test]
    fn sanitize_repo_extra_line_redacts_sensitive_keys() {
        let cfg = cfg(false, true, false);
        assert_eq!(
            sanitize_repo_extra_line("proxy_password=secret", &cfg),
            "proxy_password=<redacted>"
        );
        assert_eq!(
            sanitize_repo_extra_line("proxy=http://user:pass@host:8080", &cfg),
            "proxy=<redacted>"
        );
    }

    #[test]
    fn sanitize_repo_extra_line_preserves_normal_keys() {
        assert_eq!(
            sanitize_repo_extra_line("sslverify=0", &cfg(false, true, false)),
            "sslverify=0"
        );
    }

    #[test]
    fn sanitize_repo_extra_line_baseurl_basename_when_redact_paths() {
        assert_eq!(
            sanitize_repo_extra_line(
                "baseurl=file:///srv/repos/prod/rpms",
                &cfg(false, false, true)
            ),
            "baseurl=rpms"
        );
    }

    #[test]
    fn sanitize_repo_extra_line_baseurl_strips_creds_when_redact_urls() {
        assert_eq!(
            sanitize_repo_extra_line("baseurl=http://u:p@host/repo", &cfg(false, true, false)),
            "baseurl=http://host/repo"
        );
    }

    #[test]
    fn sanitize_repo_extra_line_baseurl_creds_then_basename_when_both() {
        assert_eq!(
            sanitize_repo_extra_line("baseurl=http://u:p@host/srv/rpms", &cfg(false, true, true)),
            "baseurl=rpms"
        );
    }

    #[test]
    fn sanitize_repo_extra_line_baseurl_unchanged_when_disabled() {
        assert_eq!(
            sanitize_repo_extra_line(
                "baseurl=file:///srv/repos/prod/rpms",
                &cfg(false, false, false)
            ),
            "baseurl=file:///srv/repos/prod/rpms"
        );
    }
}
