// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

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

            let reparent: Option<Option<i64>> = match (parent_id, detach_parent) {
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

    let mut entries =
        tokio::fs::read_dir(&products_dir)
            .await
            .map_err(|e| crbs_core::error::CrbsError::Io {
                context: format!("read products dir {}", products_dir.display()),
                kind: e.kind(),
                detail: e.to_string(),
            })?;

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

async fn read_config_file(path: &Path) -> Result<serde_json::Value> {
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

    reparent: Option<Option<i64>>,
    format: OutputFormat,
) -> Result<()> {
    let config = read_config_file(config_file).await?;

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
        return Err(crate::remote::http_status_error("update_product", status, &body_text).into());
    }

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

/// fork 两形态：默认 activelink POST 空 own config + `parent_id` 指向 parent；
/// `--detached` 取 parent chain-merged TOML 原文回 POST（`parent_id` = null）。
async fn fork_product(
    target: &crate::remote::RemoteTarget,
    parent: &str,
    new_name: &str,
    display_name: Option<String>,
    detached: bool,
    reason: Option<String>,
    format: OutputFormat,
) -> Result<()> {
    let parent_id = lookup_product_id(target, parent).await?;

    let (parent_id_field, config): (Option<i64>, serde_json::Value) = if detached {
        let resolved_toml = fetch_resolved_toml(target, parent).await?;
        let mut cfg = crbs_core::config::ProductConfig::from_str(&resolved_toml)
            .with_context(|| format!("parse resolved TOML from parent {}", parent))?;

        cfg.gpg_signing_enabled = Some(false);
        let json = serde_json::to_value(&cfg).context("serialize snapshot config to json")?;
        (None, json)
    } else {
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

    v.get("id").and_then(|x| x.as_i64()).ok_or_else(|| {
        crbs_core::error::CrbsError::Network {
            message: format!("server response for product '{}' lacks `id` field", name),
        }
        .into()
    })
}

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

struct DeleteOutput<'a> {
    product: &'a str,
}

impl CommandOutput for DeleteOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
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

struct CleanOutput<'a> {
    resp: &'a crate::api::product::ProductCleanResponse,
}

impl CommandOutput for CleanOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
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

        single: parsed.is_object(),
    })?;
    Ok(())
}

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

fn export_tmp_path(path: &Path) -> PathBuf {
    path.with_extension(format!("toml.export-{}", uuid::Uuid::new_v4()))
}

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
            use tokio::io::AsyncWriteExt;
            let tmp_path = export_tmp_path(path);

            let result: Result<()> = async {
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
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(e);
            }
            eprintln!("wrote {} bytes to {}", body_text.len(), path.display());
        }
        None => {
            print!("{}", body_text);
        }
    }
    Ok(())
}

struct CreateOutput<'a>(&'a serde_json::Value);

impl CommandOutput for CreateOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
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
