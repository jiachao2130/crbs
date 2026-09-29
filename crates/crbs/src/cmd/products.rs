// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs products` 命令：列出/查看/创建/更新/删除 产品配置。

use std::path::{Path, PathBuf};

use crate::cli::{CommandOutput, OutputFormat, ProductsCommand};
use crate::remote::remote_send_json;
use anyhow::{Context, Result};

pub(crate) async fn handle_products(
    command: Option<ProductsCommand>,
    remote: Option<String>,
    token: Option<String>,
    local: bool,
    format: OutputFormat,
) -> Result<()> {
    let target = crate::remote::resolve(remote, token, None, local).await?;

    match command {
        Some(ProductsCommand::Show { product }) => show_product(&product, target, format).await,
        Some(ProductsCommand::Create {
            product,
            config_file,
            display_name,
            parent_id,
            reason,
        }) => {
            let t = require_remote(target, "products create")?;
            create_product(
                &t,
                &product,
                &config_file,
                display_name,
                parent_id,
                reason,
                format,
            )
            .await
        }
        Some(ProductsCommand::Update {
            product,
            config_file,
            expected_revision,
            reason,
            parent_id,
            detach_parent,
        }) => {
            let t = require_remote(target, "products update")?;
            // 三态映射：都没给 → None（不改）；--detach-parent → Some(None) 脱钩；--parent-id N → Some(Some(N)) 挂新 parent。
            let reparent: Option<Option<i64>> = match (parent_id, detach_parent) {
                // clap conflicts_with 拦截了组合；漂移仍显式报错——ValidationFailed（USAGE=4）。
                (Some(_), true) => {
                    return Err(crbs_core::error::CrbsError::ValidationFailed {
                        message: "--parent-id and --detach-parent are mutually exclusive".into(),
                    }
                    .into())
                }
                (Some(p), false) => Some(Some(p)),
                (None, true) => Some(None),
                (None, false) => None,
            };
            update_product(
                &t,
                &product,
                &config_file,
                expected_revision,
                reason,
                reparent,
                format,
            )
            .await
        }
        Some(ProductsCommand::Fork {
            parent,
            new_name,
            display_name,
            detached,
            reason,
        }) => {
            let t = require_remote(target, "products fork")?;
            fork_product(
                &t,
                &parent,
                &new_name,
                display_name,
                detached,
                reason,
                format,
            )
            .await
        }
        Some(ProductsCommand::Delete { product, yes }) => {
            let t = require_remote(target, "products delete")?;
            delete_product(&t, &product, yes, format).await
        }
        Some(ProductsCommand::Clean { product, yes }) => {
            let t = require_remote(target, "products clean")?;
            clean_product(&t, &product, yes, format).await
        }
        Some(ProductsCommand::History { product, revision }) => {
            let t = require_remote(target, "products history")?;
            product_history(&t, &product, revision, format).await
        }
        Some(ProductsCommand::Export { product, file }) => {
            let t = require_remote(target, "products export")?;
            export_product(&t, &product, file.as_deref()).await
        }
        Some(ProductsCommand::Publish { product, reason }) => {
            let t = require_remote(target, "products publish")?;
            update_product_visibility(&t, &product, "public", reason.as_deref(), format).await
        }
        Some(ProductsCommand::Unpublish { product, reason }) => {
            let t = require_remote(target, "products unpublish")?;
            update_product_visibility(&t, &product, "private", reason.as_deref(), format).await
        }
        Some(ProductsCommand::Transfer {
            product,
            new_owner,
            reason,
        }) => {
            let t = require_remote(target, "products transfer")?;
            transfer_product(&t, &product, &new_owner, reason.as_deref(), format).await
        }
        Some(ProductsCommand::Acl(acl_cmd)) => {
            let t = require_remote(target, "products acl")?;
            crate::cmd::products_acl::handle_products_acl(acl_cmd, t, format).await
        }
        None => list_products(target, format).await,
    }
}

/// 写路径权威在 server DB，本地磁盘仅开发环境 seed：create/update/delete/history 一律要求远程 target。
fn require_remote(
    target: Option<crate::remote::RemoteTarget>,
    op: &str,
) -> Result<crate::remote::RemoteTarget> {
    // 缺远程目标属调用方式误用——ValidationFailed（USAGE=4）。
    target.ok_or_else(|| crbs_core::error::CrbsError::ValidationFailed {
        message: format!(
            "`crbs products {op}` requires a remote server: pass --remote or set remote.default in crbs.toml"
        ),
    }
    .into())
}

async fn list_products(
    target: Option<crate::remote::RemoteTarget>,
    format: OutputFormat,
) -> Result<()> {
    let names = if let Some(t) = target {
        list_remote_products(&t).await?
    } else {
        list_local_products().await?
    };

    format.print(&ProductListOutput(&names))?;
    Ok(())
}

async fn show_product(
    product: &str,
    target: Option<crate::remote::RemoteTarget>,
    format: OutputFormat,
) -> Result<()> {
    let detail = if let Some(t) = target {
        get_remote_product(product, &t).await?
    } else {
        get_local_product(product).await?
    };

    format.print(&ProductDetailOutput(&detail))?;
    Ok(())
}

struct ProductListOutput<'a>(&'a [String]);

impl CommandOutput for ProductListOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        // 裸数组包 {command, products} 信封（资源复数键 products，全族与 json_error_contract 同源）；空数组同包装。
        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "command": "products",
            "products": self.0,
        }))?)
    }

    fn print_text(&self) {
        if self.0.is_empty() {
            println!("No products configured.");
        } else {
            for name in self.0 {
                println!("{}", name);
            }
        }
    }
}

struct ProductDetailOutput<'a>(&'a crbs_core::config::ProductDetail);

impl CommandOutput for ProductDetailOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        // 透传对象本体平铺加 command，detail schema 原样保留。
        Ok(serde_json::to_string_pretty(
            &crate::cmd::json_success_envelope("products", serde_json::to_value(self.0)?),
        )?)
    }

    fn print_text(&self) {
        print_product_detail(self.0);
    }
}

async fn list_local_products() -> Result<Vec<String>> {
    let products_dir = crbs_core::config::config_path("products")?;
    let mut names = Vec::new();
    if !products_dir.exists() {
        return Ok(names);
    }
    // 目录读取 io 错误 → Io（kind 保真，ENVIRONMENT=6），context 保留原串（含路径）。
    let mut entries =
        tokio::fs::read_dir(&products_dir)
            .await
            .map_err(|e| crbs_core::error::CrbsError::Io {
                context: format!("read products dir {}", products_dir.display()),
                kind: e.kind(),
                detail: e.to_string(),
            })?;
    // 迭代错误必须传播（断言式形态）：`while let Ok(Some(..))` 会把 io 错误当迭代结束，截断列表以 exit 0 呈现。
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| crbs_core::error::CrbsError::from_io_context("iterate products dir", e))?
    {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".toml") {
            names.push(name.trim_end_matches(".toml").to_string());
        }
    }
    names.sort();
    Ok(names)
}

async fn get_local_product(product: &str) -> Result<crbs_core::config::ProductDetail> {
    let cfg = crbs_core::config::Config::load_async(product)
        .await
        .with_context(|| format!("load product config {}", product))?;
    Ok(crbs_core::config::ProductDetail::from(cfg))
}

async fn list_remote_products(target: &crate::remote::RemoteTarget) -> Result<Vec<String>> {
    let url = format!("{}/api/v1/products", target.url);
    remote_send_json(
        target,
        reqwest::Method::GET,
        |client| client.get(&url),
        None,
        None,
    )
    .await
}

async fn get_remote_product(
    product: &str,
    target: &crate::remote::RemoteTarget,
) -> Result<crbs_core::config::ProductDetail> {
    let url = format!(
        "{}/api/v1/products/{}",
        target.url,
        urlencoding::encode(product)
    );
    remote_send_json(
        target,
        reqwest::Method::GET,
        |client| client.get(&url),
        None,
        None,
    )
    .await
}

fn print_product_detail(detail: &crbs_core::config::ProductDetail) {
    println!("Product:        {}", detail.product);
    if let Some(id) = detail.id {
        println!("id:             {}", id);
    }
    match (&detail.parent_name, detail.parent_id) {
        (Some(name), Some(id)) => println!("parent:         {} (id={})", name, id),
        (None, Some(id)) => println!("parent:         id={} (name unavailable)", id),
        _ => println!("parent:         --"),
    }
    println!("crbs_root:      {}", detail.crbs_root.display());
    println!("result_dir:     {}", detail.result_dir.display());
    println!("backend:        {}", detail.backend);
    println!("build_target:   {}", detail.build_target);
    println!("network:        {}", detail.network);
    println!("build_tmpfs:    {}", detail.build_tmpfs);
    println!(
        "shared_layer:   {}",
        bool_or_packages_summary(&detail.shared_layer)
    );
    println!(
        "ccache_enabled: {}",
        bool_or_packages_summary(&detail.ccache_enabled)
    );
    if let Some(m) = &detail.memory_max {
        println!("memory_max:     {}", m);
    }
    if let Some(c) = &detail.cpu_quota {
        println!("cpu_quota:      {}", c);
    }

    println!("\nBase packages:");
    for pkg in &detail.base_packages {
        println!("  - {}", pkg);
    }

    println!("\nRepos:");
    for repo in &detail.repos {
        let status = if repo.enabled { "" } else { " (disabled)" };
        println!(
            "  - {} => {}{} (priority={}, cost={})",
            repo.name, repo.baseurl, status, repo.priority, repo.cost
        );
        if repo.module_hotfixes {
            println!("      module_hotfixes=true");
        }
        if !repo.exclude.is_empty() {
            println!("      exclude: {}", repo.exclude.join(", "));
        }
        if !repo.includepkgs.is_empty() {
            println!("      includepkgs: {}", repo.includepkgs.join(", "));
        }
    }

    if !detail.rpm_macros.is_empty() {
        println!("\nRPM macros:");
        for (k, v) in &detail.rpm_macros {
            println!("  {} = {}", k, v);
        }
    }

    if !detail.hooks.pre.is_empty() || !detail.hooks.post.is_empty() {
        println!("\nHooks:");
        for (step, script) in &detail.hooks.pre {
            println!("  [pre:{}] {}", step, script);
        }
        for (step, script) in &detail.hooks.post {
            println!("  [post:{}] {}", step, script);
        }
    }
}

fn bool_or_packages_summary(bp: &crbs_core::config::BoolOrPackages) -> String {
    match bp {
        crbs_core::config::BoolOrPackages::Bool(true) => "true".to_string(),
        crbs_core::config::BoolOrPackages::Bool(false) => "false".to_string(),
        crbs_core::config::BoolOrPackages::Packages(pkgs) => pkgs.join(", "),
    }
}

// -------- 写路径与 history 只走远程 --------

/// 从磁盘读入 TOML → `ProductConfig`；转成 JSON `Value` 给 HTTP body。
async fn read_config_file(path: &Path) -> Result<serde_json::Value> {
    // 配置文件读 io 错误 → Io（kind 保真，ENVIRONMENT=6），context 保留原串（含路径）。
    let text =
        tokio::fs::read_to_string(path)
            .await
            .map_err(|e| crbs_core::error::CrbsError::Io {
                context: format!("read product config file {}", path.display()),
                kind: e.kind(),
                detail: e.to_string(),
            })?;
    let cfg = crbs_core::config::ProductConfig::from_str(&text)
        .with_context(|| format!("parse product config {}", path.display()))?;
    serde_json::to_value(&cfg).context("serialize product config to json")
}

async fn create_product(
    target: &crate::remote::RemoteTarget,
    product: &str,
    config_file: &Path,
    display_name: Option<String>,
    parent_id: Option<i64>,
    reason: Option<String>,
    format: OutputFormat,
) -> Result<()> {
    let config = read_config_file(config_file).await?;
    let body = serde_json::json!({
        "name": product,
        "display_name": display_name,
        "parent_id": parent_id,
        "config": config,
        "reason": reason,
    });
    let url = format!("{}/api/v1/products", target.url);
    let parsed: serde_json::Value = remote_send_json(
        target,
        reqwest::Method::POST,
        |client| client.post(&url).json(&body),
        None,
        None,
    )
    .await?;
    format.print(&CreateOutput(&parsed))?;
    Ok(())
}

async fn update_product(
    target: &crate::remote::RemoteTarget,
    product: &str,
    config_file: &Path,
    expected_revision: i64,
    reason: Option<String>,
    // 三态；None = 不改，Some(None) = detach, Some(Some(n)) = set。
    reparent: Option<Option<i64>>,
    format: OutputFormat,
) -> Result<()> {
    let config = read_config_file(config_file).await?;
    // 只在明确要动 parent 时才把 parent_id 键写进 body：缺键 = 不改（server 侧
    // #[serde(default)] 给 None），null = detach，int = set。
    let mut body = serde_json::json!({
        "expected_revision": expected_revision,
        "config": config,
        "reason": reason,
    });
    if let Some(target_parent) = reparent {
        body["parent_id"] = match target_parent {
            None => serde_json::Value::Null,
            Some(id) => serde_json::Value::Number(id.into()),
        };
    }
    let url = format!(
        "{}/api/v1/products/{}",
        target.url,
        urlencoding::encode(product)
    );
    let client = target.client().await?;
    let resp = crate::remote::retry_http("update_product", reqwest::Method::PUT, None, || {
        client.put(&url).json(&body)
    })
    .await?;
    let status = resp.status;
    let body_text = resp.body;
    if !status.is_success() {
        // 含 409 revision conflict → Conflict（USAGE=4），server 错误消息（expected/current revision）随 body 透传，脚本按退出码 4 拉新 revision 重试。
        return Err(crate::remote::http_status_error("update_product", status, &body_text).into());
    }
    // 响应 serde 解析失败属环境域——Network（ENVIRONMENT=6），message 保留原串并内联底层错误文本；
    // body 经共享 truncate_body_for_error 截断/剥终端控制序列。
    let parsed: serde_json::Value =
        serde_json::from_str(&body_text).map_err(|e| crbs_core::error::CrbsError::Network {
            message: format!(
                "parse update response: {}: {e}",
                crate::remote::truncate_body_for_error(&body_text)
            ),
        })?;
    format.print(&UpdateOutput(&parsed))?;
    Ok(())
}

/// `crbs products fork PARENT NEW_NAME [--detached]`.
///
/// Two modes: activelink（默认）POST /api/v1/products 空 own config（`ProductConfig::default()`）+ `parent_id` 指向 parent；
/// `--detached` GET {parent}/resolved（chain-merged TOML）原样 POST 回，`parent_id = null`。
async fn fork_product(
    target: &crate::remote::RemoteTarget,
    parent: &str,
    new_name: &str,
    display_name: Option<String>,
    detached: bool,
    reason: Option<String>,
    format: OutputFormat,
) -> Result<()> {
    // Resolve parent's numeric id：activelink 必需；detached 仅进 audit reason。
    let parent_id = lookup_product_id(target, parent).await?;

    let (parent_id_field, config): (Option<i64>, serde_json::Value) = if detached {
        let resolved_toml = fetch_resolved_toml(target, parent).await?;
        let mut cfg = crbs_core::config::ProductConfig::from_str(&resolved_toml)
            .with_context(|| format!("parse resolved TOML from parent {}", parent))?;
        // fork 派生的签名许可不随派生扩散：显式关闭，签与不签由 operator/admin 构建完成后决定。
        cfg.gpg_signing_enabled = Some(false);
        let json = serde_json::to_value(&cfg).context("serialize snapshot config to json")?;
        (None, json)
    } else {
        // activelink: 空 config 继承 parent chain 全部，唯签名许可显式关闭（理由同 detached）。
        let cfg = crbs_core::config::ProductConfig {
            gpg_signing_enabled: Some(false),
            ..crbs_core::config::ProductConfig::default()
        };
        let json = serde_json::to_value(&cfg).context("serialize default config to json")?;
        (Some(parent_id), json)
    };

    let body = serde_json::json!({
        "name": new_name,
        "display_name": display_name,
        "parent_id": parent_id_field,
        "config": config,
        "reason": reason.or_else(|| Some(format!(
            "fork from {}{}",
            parent,
            if detached { " (detached snapshot)" } else { " (activelink)" }
        ))),
    });
    let url = format!("{}/api/v1/products", target.url);
    let parsed: serde_json::Value = remote_send_json(
        target,
        reqwest::Method::POST,
        |client| client.post(&url).json(&body),
        None,
        None,
    )
    .await?;
    format.print(&CreateOutput(&parsed))?;
    Ok(())
}

/// 经 `remote_send_json` 按名称查产品数字 id。
async fn lookup_product_id(target: &crate::remote::RemoteTarget, name: &str) -> Result<i64> {
    let url = format!(
        "{}/api/v1/products/{}",
        target.url,
        urlencoding::encode(name)
    );
    let msg = format!("product '{}' not found", name);
    let v: serde_json::Value = remote_send_json(
        target,
        reqwest::Method::GET,
        |client| client.get(&url),
        Some(&msg),
        None,
    )
    .await?;
    // 2xx 可解但缺 `id` 字段——异常/被攻破 server（环境域）→ Network（ENVIRONMENT=6），文案逐字保留。
    v.get("id").and_then(|x| x.as_i64()).ok_or_else(|| {
        crbs_core::error::CrbsError::Network {
            message: format!("server response for product '{}' lacks `id` field", name),
        }
        .into()
    })
}

/// 拉取产品的 chain-resolved TOML 原文（fork 与 export 共用底层拉取；GET
/// 幂等，走 retry_http 对瞬时传输失败重试）。返回 (status, body)，非 2xx 的
/// 错误文案由调用方按子命令语义收口。
async fn fetch_resolved_toml_raw(
    target: &crate::remote::RemoteTarget,
    name: &str,
) -> Result<(reqwest::StatusCode, String)> {
    let client = target.client().await?;
    let url = format!(
        "{}/api/v1/products/{}/resolved",
        target.url,
        urlencoding::encode(name)
    );
    let resp = crate::remote::retry_http("fetch resolved TOML", reqwest::Method::GET, None, || {
        client.get(&url)
    })
    .await?;
    Ok((resp.status, resp.body))
}

/// fork 侧收口：非 2xx → `fetch resolved TOML` 语义的 http_status_error。
/// admin init 的 --all arch 预检共用（产品未声明 arches 时 TOML 仍可解析，
/// 空列表由调用方按"无约束"处理）。
pub(crate) async fn fetch_resolved_toml(
    target: &crate::remote::RemoteTarget,
    name: &str,
) -> Result<String> {
    let (status, body) = fetch_resolved_toml_raw(target, name).await?;
    if !status.is_success() {
        return Err(crate::remote::http_status_error("fetch resolved TOML", status, &body).into());
    }
    Ok(body)
}

/// `products delete` 的 JSON 输出（与其他子命令的 command 键风格对齐）。
struct DeleteOutput<'a> {
    product: &'a str,
}

impl CommandOutput for DeleteOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        // command 与错误信封同源：format 是父命令级 global 旗标，json_error_contract 全族共用 "products"。
        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "command": "products",
            "product": self.product,
            "deleted": true,
        }))?)
    }

    fn print_text(&self) {
        println!("deleted");
    }
}

async fn delete_product(
    target: &crate::remote::RemoteTarget,
    product: &str,
    yes: bool,
    format: OutputFormat,
) -> Result<()> {
    if !yes {
        eprintln!(
            "About to delete product row '{}' on {} (this does NOT clean disk artifacts).",
            product, target.url
        );
        eprintln!("Re-run with --yes to confirm.");
        // 本路径从不弹 y/N 交互确认：缺 --yes 属缺旗标用法错误（同 confirm_or_bail
        // 非交互拒绝口径）——ValidationFailed（USAGE=4）；交互确认被拒才是 Cancelled(3)。
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: "refusing to delete product without --yes".into(),
        }
        .into());
    }
    let url = format!(
        "{}/api/v1/products/{}",
        target.url,
        urlencoding::encode(product)
    );
    let client = target.client().await?;
    let resp = crate::remote::retry_http("delete_product", reqwest::Method::DELETE, None, || {
        client.delete(&url)
    })
    .await?;
    let status = resp.status;
    if status == reqwest::StatusCode::NO_CONTENT {
        format.print(&DeleteOutput { product })?;
        return Ok(());
    }
    let body_text = resp.body;
    Err(crate::remote::http_status_error("products delete", status, &body_text).into())
}

/// `products clean` 的 JSON 输出（与 delete 同族：command 键共用 "products"）。
struct CleanOutput<'a> {
    resp: &'a crate::api::product::ProductCleanResponse,
}

impl CommandOutput for CleanOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        // command 与错误信封同源——products 全族共用父命令级 "products"。
        Ok(serde_json::to_string_pretty(
            &crate::cmd::json_success_envelope(
                "products",
                serde_json::json!({
                    "task_id": self.resp.task_id,
                    "status": self.resp.status,
                    "product": self.resp.product,
                    "op": self.resp.op,
                }),
            ),
        )?)
    }

    fn print_text(&self) {
        println!(
            "clean task {} accepted for product '{}' (status: {})",
            self.resp.task_id, self.resp.product, self.resp.status
        );
    }
}

async fn clean_product(
    target: &crate::remote::RemoteTarget,
    product: &str,
    yes: bool,
    format: OutputFormat,
) -> Result<()> {
    // clean 清掉产品发布仓库与磁盘产物，破坏性整批操作统一走 confirm_or_bail：--yes 跳过，否则交互确认（非 TTY 拒绝）。
    crate::cmd::confirm::confirm_or_bail(
        &format!(
            "Clean ALL published repo artifacts for product '{product}' on {}?",
            target.url
        ),
        yes,
    )?;
    let resp = crate::api::product::clean_product(target, product).await?;
    format.print(&CleanOutput { resp: &resp })?;
    Ok(())
}

async fn product_history(
    target: &crate::remote::RemoteTarget,
    product: &str,
    revision: Option<i64>,
    format: OutputFormat,
) -> Result<()> {
    let url = match revision {
        Some(rev) => format!(
            "{}/api/v1/products/{}/history/{}",
            target.url,
            urlencoding::encode(product),
            rev
        ),
        None => format!(
            "{}/api/v1/products/{}/history",
            target.url,
            urlencoding::encode(product)
        ),
    };
    let parsed: serde_json::Value = remote_send_json(
        target,
        reqwest::Method::GET,
        |client| client.get(&url),
        None,
        None,
    )
    .await?;
    format.print(&HistoryOutput {
        value: &parsed,
        // 按响应本体形态判定而非请求参数：revision Some 但 server 返回列表时，请求形态判定会错位信封分支。
        single: parsed.is_object(),
    })?;
    Ok(())
}

/// publish / unpublish 产品可见性。先拉取当前 revision 做乐观锁。
async fn update_product_visibility(
    target: &crate::remote::RemoteTarget,
    product: &str,
    visibility: &str,
    reason: Option<&str>,
    format: OutputFormat,
) -> Result<()> {
    let detail = get_remote_product(product, target).await?;
    let body = serde_json::json!({
        "visibility": visibility,
        "reason": reason,
        "expected_revision": detail.revision,
    });
    let url = format!(
        "{}/api/v1/products/{}/visibility",
        target.url,
        urlencoding::encode(product)
    );
    let parsed: serde_json::Value = remote_send_json(
        target,
        reqwest::Method::POST,
        |client| client.post(&url).json(&body),
        None,
        None,
    )
    .await?;
    format.print(&UpdateOutput(&parsed))?;
    Ok(())
}

/// 将产品所有权转让给其他用户。先拉取当前 revision 做乐观锁。
async fn transfer_product(
    target: &crate::remote::RemoteTarget,
    product: &str,
    new_owner: &str,
    reason: Option<&str>,
    format: OutputFormat,
) -> Result<()> {
    let detail = get_remote_product(product, target).await?;
    let body = serde_json::json!({
        "new_owner_username": new_owner,
        "reason": reason,
        "expected_revision": detail.revision,
    });
    let url = format!(
        "{}/api/v1/products/{}/transfer",
        target.url,
        urlencoding::encode(product)
    );
    let parsed: serde_json::Value = remote_send_json(
        target,
        reqwest::Method::POST,
        |client| client.post(&url).json(&body),
        None,
        None,
    )
    .await?;
    format.print(&UpdateOutput(&parsed))?;
    Ok(())
}

/// export 的同目录临时名：固定临时名并发导出同一目标会互相踩踏（各写同一临时文件后
/// 各自 rename，后者可能发布前者半截内容），加 uuid 隔离并发写者。
fn export_tmp_path(path: &Path) -> PathBuf {
    path.with_extension(format!("toml.export-{}", uuid::Uuid::new_v4()))
}

/// 过渡桥：从 hub 拉取 chain-resolved TOML 并写到 stdout 或 `--file`。
///
/// 输出未经解析的原始 TOML（server 把 DB `config_json` 序列化回 TOML 返回），可直接重定向到
/// /etc/crbs/products/{name}.toml 供本地 CLI 读到；format flag 对本子命令不生效（固定输出 TOML）。
async fn export_product(
    target: &crate::remote::RemoteTarget,
    product: &str,
    file: Option<&Path>,
) -> Result<()> {
    let (status, body_text) = fetch_resolved_toml_raw(target, product).await?;
    if !status.is_success() {
        return Err(crate::remote::http_status_error("export_product", status, &body_text).into());
    }
    match file {
        Some(path) => {
            // 原子写 + 0660 权限不变量：导出文件常直接放进 /etc/crbs/products，半截 TOML、0644 均不合要求。
            use tokio::io::AsyncWriteExt;
            let tmp_path = export_tmp_path(path);
            // 错误路径 best-effort 删 uuid 临时文件不留半截残留；Ctrl-C（SIGINT 直接杀进程、
            // 进程内清理不可达）残留靠 `toml.export-` 前缀辨识，不按前缀扫目录删。
            let result: Result<()> = async {
                // 临时文件创建/写入/rename 的 io 错误 → Io（kind 保真，ENVIRONMENT=6），context 保留原串（含路径）。
                let mut f = tokio::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o660)
                    .open(&tmp_path)
                    .await
                    .map_err(|e| crbs_core::error::CrbsError::Io {
                        context: format!("create temp export {}", tmp_path.display()),
                        kind: e.kind(),
                        detail: e.to_string(),
                    })?;
                // tmp 为本进程 uuid 新建，`.mode(0o660)` 受 umask 削减，创建后显式
                // set_permissions 收口（rename 保 mode，最终文件继承）；失败 warn 即权限未生效。
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(e) = f
                        .set_permissions(std::fs::Permissions::from_mode(0o660))
                        .await
                    {
                        tracing::warn!(
                            path = %tmp_path.display(),
                            error = %e,
                            "failed to chmod export temp file to 0660 (perms may not be effective)"
                        );
                    }
                }
                f.write_all(body_text.as_bytes()).await.map_err(|e| {
                    crbs_core::error::CrbsError::Io {
                        context: format!("write TOML to {}", tmp_path.display()),
                        kind: e.kind(),
                        detail: e.to_string(),
                    }
                })?;
                f.sync_all().await.ok();
                drop(f);
                tokio::fs::rename(&tmp_path, path).await.map_err(|e| {
                    crbs_core::error::CrbsError::Io {
                        context: format!("finalize export {}", path.display()),
                        kind: e.kind(),
                        detail: e.to_string(),
                    }
                })?;
                Ok(())
            }
            .await;
            if let Err(e) = result {
                // tmp 可能尚不存在（open 失败），remove NotFound 一并吞掉。
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(e);
            }
            eprintln!("wrote {} bytes to {}", body_text.len(), path.display());
        }
        None => {
            // 直接 stdout，方便 `> /etc/crbs/products/foo.toml` 重定向。
            print!("{}", body_text);
        }
    }
    Ok(())
}

struct CreateOutput<'a>(&'a serde_json::Value);

impl CommandOutput for CreateOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        // 透传服务端响应体平铺加 command（create/fork 共用，全族 "products"），响应 schema 原样。
        Ok(serde_json::to_string_pretty(
            &crate::cmd::json_success_envelope("products", self.0.clone()),
        )?)
    }
    fn print_text(&self) {
        let id = self.0.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
        let name = self.0.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let rev = self.0.get("revision").and_then(|v| v.as_i64()).unwrap_or(0);
        let bos = self
            .0
            .get("base_os_revision")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        println!(
            "created id={} name={} revision={} base_os_revision={}",
            id, name, rev, bos
        );
    }
}

struct UpdateOutput<'a>(&'a serde_json::Value);

impl CommandOutput for UpdateOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        // 透传服务端响应体平铺加 command（update/publish/unpublish/transfer 共用，全族 "products"），schema 原样。
        Ok(serde_json::to_string_pretty(
            &crate::cmd::json_success_envelope("products", self.0.clone()),
        )?)
    }
    fn print_text(&self) {
        let rev = self.0.get("revision").and_then(|v| v.as_i64()).unwrap_or(0);
        let bos = self
            .0
            .get("base_os_revision")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let bumped = self
            .0
            .get("base_os_bumped")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        println!(
            "updated revision={} base_os_revision={} base_os_bumped={}",
            rev, bos, bumped
        );
    }
}

struct HistoryOutput<'a> {
    value: &'a serde_json::Value,
    single: bool,
}

impl CommandOutput for HistoryOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        // 单条（对象）平铺加 command；列表（裸数组）包 {command, history} 信封，条目 schema 原样。
        let body = if self.single {
            self.value.clone()
        } else {
            serde_json::json!({ "history": self.value })
        };
        Ok(serde_json::to_string_pretty(
            &crate::cmd::json_success_envelope("products", body),
        )?)
    }
    fn print_text(&self) {
        if self.single {
            print_history_entry(self.value);
            return;
        }
        let arr = self.value.as_array();
        match arr {
            Some(entries) if entries.is_empty() => println!("(no history)"),
            Some(entries) => {
                for e in entries {
                    print_history_summary(e);
                }
            }
            None => println!("{}", self.value),
        }
    }
}

fn print_history_summary(entry: &serde_json::Value) {
    let rev = entry.get("revision").and_then(|v| v.as_i64()).unwrap_or(0);
    let bos = entry
        .get("base_os_revision")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let by = entry
        .get("changed_by_user_id")
        .and_then(|v| v.as_i64())
        .map(|i| i.to_string())
        .unwrap_or_else(|| "-".to_string());
    let reason = entry.get("reason").and_then(|v| v.as_str()).unwrap_or("");
    // changed_at 是 DB 存储的 UTC 串，human 输出走本地时区显示（解析失败原样降级）；JSON 保持原串。
    let at = crbs_core::util::format_local_time(
        entry
            .get("changed_at")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    );
    println!(
        "revision={:<4} base_os_revision={:<4} by=user#{:<4} at={} reason={}",
        rev, bos, by, at, reason
    );
}

fn print_history_entry(entry: &serde_json::Value) {
    print_history_summary(entry);
    if let Some(cfg) = entry.get("config") {
        println!("\nconfig:");
        println!(
            "{}",
            serde_json::to_string_pretty(cfg).unwrap_or_else(|_| cfg.to_string())
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// export 临时名带 uuid（并发导出同一目标不互相踩踏），保留原父目录与 `toml.export-` 前缀
    /// （错误路径仅单文件 best-effort 清理，Ctrl-C 残留靠前缀辨识）。
    #[test]
    fn export_tmp_path_is_uuid_suffixed_and_keeps_parent() {
        let p = Path::new("/etc/crbs/products/foo.toml");
        let a = export_tmp_path(p);
        let b = export_tmp_path(p);

        assert_ne!(a, b, "two calls must not collide");
        assert_eq!(a.parent(), p.parent(), "parent dir must be preserved");
        let name = a.file_name().unwrap().to_string_lossy();
        assert!(
            name.contains("toml.export-"),
            "tmp name must keep the toml.export- marker: {name}"
        );
        assert!(
            name.starts_with("foo.toml.export-"),
            "tmp name must stay in the same-file family: {name}"
        );
    }

    /// 2xx 可解但缺 `id` 字段——异常/被攻破 server（环境域）→ Network（ENVIRONMENT=6），文案逐字保留。
    #[tokio::test]
    async fn product_id_missing_field_maps_to_network_exit_6() {
        use crbs_core::exit_code::{crbs_error_exit_code, ENVIRONMENT};
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/fedora"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"name":"fedora"}"#))
            .mount(&server)
            .await;
        let target = crate::remote::RemoteTarget::new(server.uri(), None, None);

        let err = lookup_product_id(&target, "fedora")
            .await
            .expect_err("missing `id` field must fail");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::Network { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
        assert!(
            format!("{ce}").contains("server response for product 'fedora' lacks `id` field"),
            "msg must be preserved verbatim: {ce}"
        );
    }

    /// 配置文件读 NotFound → Io（kind 保真，ENVIRONMENT=6），context 保留原串 "read product config file"（含路径）。
    #[tokio::test]
    async fn read_config_file_missing_maps_to_io_not_found() {
        use crbs_core::exit_code::{crbs_error_exit_code, ENVIRONMENT};

        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("no-such-product.toml");

        let err = read_config_file(&missing)
            .await
            .expect_err("missing config file must fail read");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        match ce {
            crbs_core::error::CrbsError::Io {
                context,
                kind: std::io::ErrorKind::NotFound,
                ..
            } => {
                assert!(
                    context.contains(&format!("read product config file {}", missing.display())),
                    "original context string must be preserved verbatim: {context}"
                );
            }
            other => panic!("expected Io/NotFound, got {other:?}"),
        }
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
    }
}
