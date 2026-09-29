// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use anyhow::{Context, Result};
use crbs_core::config::Config;
use crbs_core::error::CrbsError;
use tracing::debug;

use crate::remote::RemoteTarget;

pub(crate) fn config_source_label(config_target: Option<&RemoteTarget>, offline: bool) -> String {
    match (offline, config_target) {
        (true, _) => "disk (--offline)".to_string(),
        (false, Some(t)) => format!("hub ({})", t.url),
        (false, None) => "disk".to_string(),
    }
}

pub(crate) fn log_config_source(
    product: &str,
    config_target: Option<&RemoteTarget>,
    offline: bool,
) {
    let source = config_source_label(config_target, offline);
    eprintln!("config: {} for product '{}'", source, product);
}

/// 从 hub 拉取 chain-resolved 产品 TOML 字符串；GET 幂等，瞬时 5xx/传输错误经 retry_http 自动重试。404 → NotFound（USAGE=4），
/// 文案双出口（--offline 存量磁盘快照 / crbs products create --config-file）；4xx → ValidationFailed、429/5xx →
/// Network。body 不 log（可能含私有仓库地址）。
pub(crate) async fn fetch_resolved_toml(target: &RemoteTarget, product: &str) -> Result<String> {
    let client = target.client().await?;
    let url = format!(
        "{}/api/v1/products/{}/resolved",
        target.url,
        urlencoding::encode(product)
    );
    debug!(url = %url, product = %product, "fetching chain-resolved product TOML");

    let resp = crate::remote::retry_http("fetch_resolved_toml", reqwest::Method::GET, None, || {
        client.get(&url)
    })
    .await
    .map_err(|e| CrbsError::Network {
        message: format!(
            "hub unreachable at {}. Use --offline to fall back to local disk (may be stale). ({e})",
            url
        ),
    })?;

    let status = resp.status;
    let body = resp.body;

    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(CrbsError::NotFound {
            message: format!(
                "product '{p}' not found on hub ({url}). \
                 If this is a new product, run: \
                 `crbs products create {p} --config-file <path>`; \
                 if you want to use the local snapshot, add --offline.",
                p = product,
                url = url,
            ),
        }
        .into());
    }
    if !status.is_success() {
        let message = format!(
            "hub returned {} for {}: {}. Use --offline to fall back to local disk (may be stale).",
            status,
            url,
            crate::remote::truncate_body_for_error(&body)
        );
        return Err(match status.as_u16() {
            401 | 403 => CrbsError::PermissionDenied { message },
            s if (400..500).contains(&s) && s != 429 => CrbsError::ValidationFailed { message },
            _ => CrbsError::Network { message },
        }
        .into());
    }
    Ok(body)
}

/// CLI 各命令加载产品配置的唯一入口。offline → 读磁盘；config_target = Some → 拉 hub /resolved 解析，hub 不可达/4xx/5xx 报错，不
/// silent fallback；config_target = None → 读磁盘。config_target 是配置源 target，与调用方另行解析的执行 target 语义正交。
pub(crate) async fn load_product_config(
    product: &str,
    config_target: Option<&RemoteTarget>,
    offline: bool,
) -> Result<Config> {
    load_product_config_with_snapshot(product, config_target, offline)
        .await
        .map(|(config, _)| config)
}

pub(crate) async fn load_product_config_with_snapshot(
    product: &str,
    config_target: Option<&RemoteTarget>,
    offline: bool,
) -> Result<(Config, Option<String>)> {
    if offline {
        let (config, toml) = load_disk_with_snapshot(product).await.with_context(|| {
            format!(
                "load product config from disk (--offline). If missing, run: \
                 `crbs products export {p} --remote <hub> > /etc/crbs/products/{p}.toml` first.",
                p = product
            )
        })?;
        ensure_cli_runtime_dirs(&config)?;
        return Ok((config, Some(toml)));
    }

    let (config, toml) = match config_target {
        Some(t) => {
            let toml = fetch_resolved_toml(t, product).await?;
            let config = Config::load_with_product_config_async(product, &toml)
                .await
                .context("parse chain-resolved TOML from hub")?;
            (config, toml)
        }
        None => load_disk_with_snapshot(product)
            .await
            .context("load product config from disk")?,
    };
    ensure_cli_runtime_dirs(&config)?;
    Ok((config, Some(toml)))
}

pub(crate) async fn load_product_config_from_snapshot(product: &str, toml: &str) -> Result<Config> {
    let config = Config::load_with_product_config_async(product, toml)
        .await
        .context("parse recorded product config snapshot")?;
    ensure_cli_runtime_dirs(&config)?;
    Ok(config)
}

async fn load_disk_with_snapshot(product: &str) -> Result<(Config, String)> {
    crbs_core::validation::validate_product(product)?;
    let path = crbs_core::config::config_path(format!("products/{product}.toml"))?;
    let toml = tokio::fs::read_to_string(&path).await.map_err(|e| {
        CrbsError::from_io_context(format!("read product config {}", path.display()), e)
    })?;
    let config = Config::load_with_product_config_async(product, &toml).await?;
    Ok((config, toml))
}

fn ensure_cli_runtime_dirs(config: &Config) -> Result<()> {
    config
        .ensure_runtime_dirs()
        .context("ensure runtime directories")
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct ProductCleanResponse {
    pub task_id: String,
    pub status: String,
    pub product: String,
    pub op: String,
}

pub(crate) async fn clean_product(
    target: &RemoteTarget,
    product: &str,
) -> Result<ProductCleanResponse> {
    let url = format!(
        "{}/api/v1/products/{}/clean",
        target.url,
        urlencoding::encode(product)
    );
    let not_found = format!("product '{}' not found", product);
    crate::remote::remote_send_json(
        target,
        reqwest::Method::POST,
        |client| client.post(&url),
        Some(&not_found),
        None,
    )
    .await
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::test_support::EnvGuard;
    use std::path::Path;
    use tempfile::TempDir;
    use wiremock::matchers::{method, path as wm_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const MINIMAL_TOML: &str = "\
product = \"mydist\"
base_packages = [\"bash\"]
repos = []
";

    fn make_target(url: String) -> RemoteTarget {
        RemoteTarget::new(url, None, None)
    }

    fn write_min_global_config(dir: &Path) -> anyhow::Result<()> {
        let root = dir.join("crbs_root");
        let content = format!(
            "crbs_root = \"{}\"\n\
            result_dir = \"{}\"\n\
            shared_layers_dir = \"{}\"\n\
            tmp_dir = \"{}\"\n\
            tmpfs_dir = \"{}\"\n",
            root.display(),
            root.join("results").display(),
            root.join("shared_layers").display(),
            dir.join("tmp").display(),
            dir.join("tmpfs").display(),
        );
        std::fs::write(dir.join("crbs.toml"), content)?;
        Ok(())
    }

    fn write_min_product(dir: &Path, name: &str) -> anyhow::Result<()> {
        write_min_global_config(dir)?;
        std::fs::create_dir_all(dir.join("products"))?;
        std::fs::write(dir.join(format!("products/{}.toml", name)), MINIMAL_TOML)?;
        Ok(())
    }

    #[tokio::test]
    async fn fetch_resolved_toml_returns_body_on_200() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/mydist/resolved"))
            .respond_with(ResponseTemplate::new(200).set_body_string(MINIMAL_TOML))
            .mount(&server)
            .await;

        let toml = fetch_resolved_toml(&make_target(server.uri()), "mydist")
            .await
            .expect("200 should return body");
        assert!(toml.contains("base_packages"), "unexpected body: {toml}");
    }

    #[tokio::test]
    async fn fetch_resolved_toml_bails_with_dual_exit_on_404() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/mydist/resolved"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;

        let err = fetch_resolved_toml(&make_target(server.uri()), "mydist")
            .await
            .expect_err("404 should bail");
        let crbs_err = err
            .downcast_ref::<CrbsError>()
            .expect("404 must surface as CrbsError");
        assert!(
            matches!(crbs_err, CrbsError::NotFound { .. }),
            "unexpected variant: {crbs_err:?}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(crbs_err),
            crbs_core::exit_code::USAGE
        );
        let msg = format!("{:#}", err);
        assert!(msg.contains("not found on hub"), "msg: {msg}");
        assert!(msg.contains("--offline"), "missing --offline hint: {msg}");
        assert!(
            msg.contains("products create"),
            "missing products create hint: {msg}"
        );
    }

    #[tokio::test]
    async fn fetch_resolved_toml_bails_on_5xx_with_offline_hint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/mydist/resolved"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let err = fetch_resolved_toml(&make_target(server.uri()), "mydist")
            .await
            .expect_err("500 should bail");
        let crbs_err = err
            .downcast_ref::<CrbsError>()
            .expect("5xx must surface as CrbsError");
        assert!(
            matches!(crbs_err, CrbsError::Network { .. }),
            "unexpected variant: {crbs_err:?}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(crbs_err),
            crbs_core::exit_code::ENVIRONMENT
        );
        let msg = format!("{:#}", err);

        assert!(msg.contains("hub returned"), "msg: {msg}");
        assert!(msg.contains("500"), "msg missing status: {msg}");
        assert!(msg.contains("--offline"), "msg: {msg}");
    }

    #[tokio::test]
    async fn fetch_resolved_toml_maps_401_to_permission_denied() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/mydist/resolved"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .mount(&server)
            .await;

        let err = fetch_resolved_toml(&make_target(server.uri()), "mydist")
            .await
            .expect_err("401 should bail");
        let crbs_err = err
            .downcast_ref::<CrbsError>()
            .expect("401 must surface as CrbsError");
        assert!(
            matches!(crbs_err, CrbsError::PermissionDenied { .. }),
            "unexpected variant: {crbs_err:?}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(crbs_err),
            crbs_core::exit_code::PERMISSION
        );
        let msg = format!("{:#}", err);
        assert!(msg.contains("hub returned 401"), "msg: {msg}");
        assert!(msg.contains("--offline"), "msg: {msg}");
    }

    #[tokio::test]
    async fn fetch_resolved_toml_bails_hub_unreachable_on_transport_error() {
        let err = fetch_resolved_toml(&make_target("http://127.0.0.1:1".to_string()), "mydist")
            .await
            .expect_err("transport error should bail");
        let crbs_err = err
            .downcast_ref::<CrbsError>()
            .expect("transport error must surface as CrbsError");
        assert!(
            matches!(crbs_err, CrbsError::Network { .. }),
            "unexpected variant: {crbs_err:?}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(crbs_err),
            crbs_core::exit_code::ENVIRONMENT
        );
        let msg = format!("{:#}", err);
        assert!(msg.contains("hub unreachable"), "msg: {msg}");
        assert!(msg.contains("--offline"), "msg: {msg}");
    }

    #[tokio::test]
    async fn fetch_resolved_toml_error_body_sanitized_and_truncated() {
        let server = MockServer::start().await;

        let body = format!("\x1b[2J<html>{}</html>", "x".repeat(4096));
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/mydist/resolved"))
            .respond_with(ResponseTemplate::new(500).set_body_string(body))
            .mount(&server)
            .await;

        let err = fetch_resolved_toml(&make_target(server.uri()), "mydist")
            .await
            .expect_err("500 should bail after retry budget");
        let crbs_err = err
            .downcast_ref::<CrbsError>()
            .expect("5xx must surface as CrbsError");
        let CrbsError::Network { message } = crbs_err else {
            panic!("unexpected variant: {crbs_err:?}")
        };
        assert!(
            !message.contains('\x1b'),
            "terminal control sequences must be stripped: {message:?}"
        );
        assert!(
            message.len() < 1024,
            "body contribution must be bounded (prefix + URL + ≤512 body chars): {} bytes",
            message.len()
        );
    }

    #[tokio::test]
    async fn fetch_resolved_toml_retries_transient_5xx_then_succeeds() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/mydist/resolved"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/mydist/resolved"))
            .respond_with(ResponseTemplate::new(200).set_body_string(MINIMAL_TOML))
            .mount(&server)
            .await;

        let toml = fetch_resolved_toml(&make_target(server.uri()), "mydist")
            .await
            .expect("transient 5xx must be retried, then succeed");
        assert!(toml.contains("base_packages"), "unexpected body: {toml}");
        assert_eq!(
            server.received_requests().await.expect("requests").len(),
            3,
            "two 503 attempts + one final 200"
        );
    }

    #[tokio::test]
    async fn clean_product_parses_accepted_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(wm_path("/api/v1/products/mydist/clean"))
            .respond_with(ResponseTemplate::new(202).set_body_string(
                r#"{"task_id":"abc","status":"running","product":"mydist","op":"clean"}"#,
            ))
            .mount(&server)
            .await;

        let resp = clean_product(&make_target(server.uri()), "mydist")
            .await
            .expect("202 should return the clean task");
        assert_eq!(resp.task_id, "abc");
        assert_eq!(resp.status, "running");
        assert_eq!(resp.product, "mydist");
        assert_eq!(resp.op, "clean");
    }

    #[tokio::test]
    async fn clean_product_maps_404_to_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(wm_path("/api/v1/products/mydist/clean"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;

        let err = clean_product(&make_target(server.uri()), "mydist")
            .await
            .expect_err("404 should bail");
        let crbs_err = err
            .downcast_ref::<CrbsError>()
            .expect("404 must surface as CrbsError");
        assert!(
            matches!(crbs_err, CrbsError::NotFound { .. }),
            "unexpected variant: {crbs_err:?}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(crbs_err),
            crbs_core::exit_code::USAGE
        );
        let msg = format!("{err:#}");
        assert!(msg.contains("product 'mydist' not found"), "msg: {msg}");
    }

    #[tokio::test]
    async fn load_product_config_offline_reads_disk() {
        let tmp = TempDir::new().expect("tempdir");
        write_min_product(tmp.path(), "mydist").expect("write toml");
        let _env = EnvGuard::new(tmp.path());

        let cfg = load_product_config("mydist", None, true)
            .await
            .expect("disk load should succeed");
        assert_eq!(cfg.product, "mydist");
        assert!(cfg.base_packages.contains(&"bash".to_string()));
    }

    #[tokio::test]
    async fn load_product_config_offline_bails_when_disk_missing() {
        let tmp = TempDir::new().expect("tempdir");
        write_min_global_config(tmp.path()).expect("write global toml");
        let _env = EnvGuard::new(tmp.path());

        let err = load_product_config("mydist", None, true)
            .await
            .expect_err("missing disk toml should bail");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("products export"),
            "missing export hint: {msg}"
        );
    }

    #[tokio::test]
    async fn load_product_config_from_hub_parses_toml() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/mydist/resolved"))
            .respond_with(ResponseTemplate::new(200).set_body_string(MINIMAL_TOML))
            .mount(&server)
            .await;

        let tmp = TempDir::new().expect("tempdir");
        write_min_global_config(tmp.path()).expect("write global toml");
        let _env = EnvGuard::new(tmp.path());

        let target = make_target(server.uri());
        let cfg = load_product_config("mydist", Some(&target), false)
            .await
            .expect("hub load should succeed");
        assert_eq!(cfg.product, "mydist");
        assert!(cfg.base_packages.contains(&"bash".to_string()));
    }

    #[tokio::test]
    async fn load_product_config_falls_back_to_disk_when_no_target() {
        crate::test_support::pin_setuid_privilege_backend();
        let tmp = TempDir::new().expect("tempdir");
        write_min_product(tmp.path(), "mydist").expect("write toml");
        let _env = EnvGuard::new(tmp.path());

        let cfg = load_product_config("mydist", None, false)
            .await
            .expect("no target + not offline should read disk");
        assert_eq!(cfg.product, "mydist");
    }

    #[tokio::test]
    async fn load_product_config_with_snapshot_matches_disk_bytes() {
        crate::test_support::pin_setuid_privilege_backend();
        let tmp = TempDir::new().expect("tempdir");
        write_min_product(tmp.path(), "mydist").expect("write toml");
        let _env = EnvGuard::new(tmp.path());

        let (cfg, toml) = load_product_config_with_snapshot("mydist", None, true)
            .await
            .expect("disk load should succeed");
        assert_eq!(cfg.product, "mydist");
        assert_eq!(toml.as_deref(), Some(MINIMAL_TOML));
    }

    #[tokio::test]
    async fn load_product_config_with_snapshot_returns_hub_body() {
        crate::test_support::pin_setuid_privilege_backend();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/mydist/resolved"))
            .respond_with(ResponseTemplate::new(200).set_body_string(MINIMAL_TOML))
            .mount(&server)
            .await;

        let tmp = TempDir::new().expect("tempdir");
        write_min_global_config(tmp.path()).expect("write global toml");
        let _env = EnvGuard::new(tmp.path());

        let target = make_target(server.uri());
        let (cfg, toml) = load_product_config_with_snapshot("mydist", Some(&target), false)
            .await
            .expect("hub load should succeed");
        assert_eq!(cfg.product, "mydist");
        assert_eq!(toml.as_deref(), Some(MINIMAL_TOML));
    }

    #[tokio::test]
    async fn load_product_config_from_snapshot_ignores_disk_state() {
        crate::test_support::pin_setuid_privilege_backend();
        let tmp = TempDir::new().expect("tempdir");
        write_min_product(tmp.path(), "mydist").expect("write toml");
        let _env = EnvGuard::new(tmp.path());

        let snapshot = "\
product = \"mydist\"
base_packages = [\"zsh\"]
repos = []
";
        let cfg = load_product_config_from_snapshot("mydist", snapshot)
            .await
            .expect("snapshot load should succeed");
        assert!(cfg.base_packages.contains(&"zsh".to_string()));
        assert!(!cfg.base_packages.contains(&"bash".to_string()));
    }

    #[tokio::test]
    async fn load_product_config_from_snapshot_bails_on_invalid_toml() {
        crate::test_support::pin_setuid_privilege_backend();
        let tmp = TempDir::new().expect("tempdir");
        write_min_global_config(tmp.path()).expect("write global toml");
        let _env = EnvGuard::new(tmp.path());

        let err = load_product_config_from_snapshot("mydist", "not = [valid toml")
            .await
            .expect_err("invalid snapshot should bail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("parse recorded product config snapshot"),
            "msg: {msg}"
        );
    }
}
