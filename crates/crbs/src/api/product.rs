// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 拉取 hub 上的 chain-resolved 产品配置 + 决策磁盘/hub/offline。
//!
//! - `fetch_resolved_toml`：HTTP 层，拉 `/api/v1/products/{name}/resolved`
//!   返回原始 TOML，网络/4xx/5xx 分别报不同消息。
//! - `load_product_config`：决策器，CLI 各命令唯一入口，offline 与
//!   config_target 两正交维度收敛为一个 `Config`。
//!
//! 错误分层：CLI-only 模块，全部用 `anyhow::Result` + `anyhow::Context`，
//! 不引 `thiserror`。

use anyhow::{Context, Result};
use crbs_core::config::Config;
use crbs_core::error::CrbsError;
use tracing::debug;

use crate::remote::RemoteTarget;

/// 三态配置来源标签，`log_config_source`（stderr 提示）与
/// `crbs init --format json` 的 `config_source` 字段共用，避免口径漂移。
pub(crate) fn config_source_label(config_target: Option<&RemoteTarget>, offline: bool) -> String {
    match (offline, config_target) {
        (true, _) => "disk (--offline)".to_string(),
        (false, Some(t)) => format!("hub ({})", t.url),
        (false, None) => "disk".to_string(),
    }
}

/// 构建启动时把"配置来源"打到 stderr 一行；`eprintln!` 属 CLI 交互输出
/// 例外（非日志），勿改 tracing。
pub(crate) fn log_config_source(
    product: &str,
    config_target: Option<&RemoteTarget>,
    offline: bool,
) {
    let source = config_source_label(config_target, offline);
    eprintln!("config: {} for product '{}'", source, product);
}

/// 从 hub 拉取 chain-resolved 产品 TOML 字符串；GET 幂等，瞬时 5xx/传输错误
/// 经 [`crate::remote::retry_http`] 自动重试，耗尽后走终态分支。
/// 200 → body（server 保证 `application/toml`，此处不解析）；404 →
/// [`CrbsError::NotFound`]（USAGE=4），文案双出口（`--offline` 存量磁盘快照 /
/// `crbs products create --config-file <path>` 新产品）；其他非成功 status →
/// "hub returned {status}"，4xx → [`CrbsError::ValidationFailed`]（USAGE=4）、
/// 429/5xx → [`CrbsError::Network`]（ENVIRONMENT=6），仅传输层错误叫
/// "unreachable"。body 不 log（可能含私有仓库地址），token 走
/// `RemoteTarget::client()` 内部 header。
pub(crate) async fn fetch_resolved_toml(target: &RemoteTarget, product: &str) -> Result<String> {
    let client = target.client().await?;
    let url = format!(
        "{}/api/v1/products/{}/resolved",
        target.url,
        urlencoding::encode(product)
    );
    debug!(url = %url, product = %product, "fetching chain-resolved product TOML");

    // 退出码契约：传输层错误属环境类 → Network（ENVIRONMENT=6），不经 anyhow
    // context 落 INTERNAL(1)；"hub unreachable" 与 HTTP 层 "hub returned" 有意区分。
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
        // 退出码契约（remote.rs http_status_error 同口径）：401/403 →
        // PermissionDenied（PERMISSION=5）、其余非 429 的 4xx → ValidationFailed
        //（USAGE=4）、429/5xx → Network（ENVIRONMENT=6）。body 经
        // truncate_body_for_error 净化截断（512 上限 + 剥控制序列）才进消息。
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

/// CLI 各命令加载产品配置的唯一入口。
/// offline → 读磁盘（缺失时以 "products export" 为 fix-it）；config_target =
/// Some → 拉 hub `/resolved` 解析，hub 不可达/4xx/5xx 报错，不 silent fallback；
/// config_target = None → 读磁盘。`product` 由调用方保证已过 `validate_product`。
/// `config_target` 是配置源 target（`remote::resolve_config_target` 产出，不吃
/// `--local`），与调用方另行解析的执行 target（`remote::resolve(.., local)`）
/// 语义正交。
pub(crate) async fn load_product_config(
    product: &str,
    config_target: Option<&RemoteTarget>,
    offline: bool,
) -> Result<Config> {
    load_product_config_with_snapshot(product, config_target, offline)
        .await
        .map(|(config, _)| config)
}

/// 同 [`load_product_config`]，并返回配置原文快照（供构建行
/// `builds.product_config_toml` 锚定）：hub 分支为 `/resolved` 响应体
///（chain-resolved TOML），磁盘分支为 `products/{product}.toml` 原文。两者
/// 与解析所用字节同源，快照不随磁盘/hub 后续变更漂移。
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

/// 按构建记录的产品配置快照原文加载 `Config`（`crbs debug` 专用）：与构建
/// 时解析出的配置同源，不受 hub `/resolved` 或磁盘配置后续变更影响。
pub(crate) async fn load_product_config_from_snapshot(product: &str, toml: &str) -> Result<Config> {
    let config = Config::load_with_product_config_async(product, toml)
        .await
        .context("parse recorded product config snapshot")?;
    ensure_cli_runtime_dirs(&config)?;
    Ok(config)
}

/// 读磁盘产品 TOML 原文并按同源字节解析：先读文件再经
/// `load_with_product_config_async` 合并，保证返回的配置与快照逐字节同源。
async fn load_disk_with_snapshot(product: &str) -> Result<(Config, String)> {
    // 产品名拼进文件路径：独立于调用方校验再拦一次路径穿越。
    crbs_core::validation::validate_product(product)?;
    let path = crbs_core::config::config_path(format!("products/{product}.toml"))?;
    let toml = tokio::fs::read_to_string(&path).await.map_err(|e| {
        CrbsError::from_io_context(format!("read product config {}", path.display()), e)
    })?;
    let config = Config::load_with_product_config_async(product, &toml).await?;
    Ok((config, toml))
}

/// CLI 执行命令 funnel 的运行时目录确保：`Config::load*` 不隐式 mkdir，
/// CLI 侧经 [`load_product_config`] 拿配置的路径在此补齐；engine
/// `build_from_parts` 会再确保一次（幂等）。
fn ensure_cli_runtime_dirs(config: &Config) -> Result<()> {
    config
        .ensure_runtime_dirs()
        .context("ensure runtime directories")
}

/// `POST /api/v1/products/{name}/clean` 的服务端响应（202，clean 任务 hub 侧异步执行）。
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ProductCleanResponse {
    pub task_id: String,
    pub status: String,
    pub product: String,
    pub op: String,
}

/// 请求 hub 清理产品的发布仓库与磁盘产物（薄客户端）：202 → 响应体（task
/// 异步执行，此处不轮询）；404 → [`CrbsError::NotFound`]（USAGE=4，文案对齐
/// products 家族 `product '<name>' not found`）；401/403 → PermissionDenied
///（PERMISSION=5，clean 需 admin 角色），其余走 [`crate::remote::http_status_error`]。
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
    //! hub API 客户端单元测试。
    //!
    //! 磁盘 fallback 经 `CRBS_CONFIG_DIR` 注入 tempdir；env 进程全局，用
    //! `crate::test_support::EnvGuard` 跨线程/跨 mod 串行，避免与 remote 测试互踩。

    use super::*;
    use crate::test_support::EnvGuard;
    use std::path::Path;
    use tempfile::TempDir;
    use wiremock::matchers::{method, path as wm_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// 最小合法 product TOML（`base_packages`/`repos` 是仅有的必填字段）。
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
        // crbs_root 须指向 tempdir：funnel 会 ensure 运行时目录，默认 /var/lib/crbs 非 root 会 Permission denied。
        write_min_global_config(dir)?;
        std::fs::create_dir_all(dir.join("products"))?;
        std::fs::write(dir.join(format!("products/{}.toml", name)), MINIMAL_TOML)?;
        Ok(())
    }

    // --- fetch_resolved_toml ----------------------------------------------

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
        // hub 有回应就不是 "unreachable"：HTTP 层措辞 "hub returned" 与传输层有意区分。
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
        // 127.0.0.1:1（privileged 端口）基本必拒，模拟传输层不通。
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

    /// 错误消息 body 净化截断（剥终端控制序列 + 512 上限）：恶意 hub 的 body
    /// 不得原样进 stderr/日志；5xx 走重试耗尽终态分支，覆盖该构造路径。
    #[tokio::test]
    async fn fetch_resolved_toml_error_body_sanitized_and_truncated() {
        let server = MockServer::start().await;
        // \x1b[2J（清屏序列）+ 超长填充（>512 字符）迫使净化与截断双双生效。
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
        // wiremock 按挂载顺序取首个 in-scope 匹配：503 两次（up_to_n_times(2) 用尽后 OutOfScope）后落 200 兜底。
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

    // --- clean_product ------------------------------------------------------

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

    /// 退出码契约：404 → NotFound（USAGE=4），文案对齐 products 家族。
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

    // --- load_product_config：offline 分支 -----------------------------

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

    // --- load_product_config：hub 分支 ---------------------------------

    #[tokio::test]
    async fn load_product_config_from_hub_parses_toml() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/mydist/resolved"))
            .respond_with(ResponseTemplate::new(200).set_body_string(MINIMAL_TOML))
            .mount(&server)
            .await;

        // `Config::load_with_product_config_async` 内部仍调 `CrbsConfig::load()`，
        // 缺文件走 default；CRBS_CONFIG_DIR 设 tempdir 为不误读 CI 主机 /etc/crbs。
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

    // --- load_product_config：纯本地分支 --------------------------

    #[tokio::test]
    async fn load_product_config_falls_back_to_disk_when_no_target() {
        // 钉非 Helper 特权后端：本测试读宿主机磁盘配置触发后端 Auto 初始化，
        // 有 setuid helper 的宿主机会把整个测试进程楔死成 Helper（gc 等 rm-rf 测试连坐失败）。
        crate::test_support::pin_setuid_privilege_backend();
        let tmp = TempDir::new().expect("tempdir");
        write_min_product(tmp.path(), "mydist").expect("write toml");
        let _env = EnvGuard::new(tmp.path());

        let cfg = load_product_config("mydist", None, false)
            .await
            .expect("no target + not offline should read disk");
        assert_eq!(cfg.product, "mydist");
    }

    // --- load_product_config_with_snapshot -----------------------------

    /// 磁盘分支快照与解析所用文件逐字节同源。
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

    /// hub 分支快照即 `/resolved` 响应体（chain-resolved TOML 原文）。
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

    // --- load_product_config_from_snapshot -----------------------------

    /// 快照加载不读磁盘产品配置：结果必须来自传入的 TOML 原文。
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

    /// 损坏快照以 context 报错（调用方据此降级回落当前配置）。
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
