// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs init` 命令实现。

use crate::cli::{CommandOutput, GlobalArgs};
use crbs_core::privilege::CallerContext;
use tracing::info;

pub(crate) struct InitArgs {
    pub product: String,
    pub force: bool,
    pub remote: Option<String>,
    pub token: Option<String>,
    pub ca_cert: Option<std::path::PathBuf>,
    pub format: crate::cli::OutputFormat,
}

/// `crbs init` 统一输出（json 摘要；text 模式 stdout 保持静默）。
#[derive(serde::Serialize)]
struct InitOutput {
    command: &'static str,
    product: String,
    config_source: String,
    /// engine 实际使用的 crbs root（base_os/product_root 均在其下派生）。
    root: String,
}

impl CommandOutput for InitOutput {
    fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    fn print_text(&self) {
        // 刻意空实现：脚本依赖 init 成功后 stdout 无输出，人读提示走 info!/stderr 的 `config:` 行。
    }
}

pub(crate) async fn handle_init(
    args: InitArgs,
    _ctx: CallerContext,
    global: GlobalArgs,
) -> anyhow::Result<()> {
    let InitArgs {
        product,
        force,
        remote,
        token,
        ca_cert,
        format,
    } = args;
    crate::cli::validate_product(&product)?;
    info!("Initializing product: {}", product);

    // config target 解析 hub 优先；`--local` 不参与（init 是本地操作，与配置源正交）。
    // hub 404 沿用 `fetch_resolved_toml` 双出口消息（"products create" / `--offline`）。
    let config_target = crate::remote::resolve_config_target(remote, token, ca_cert).await?;

    if global.offline && config_target.is_none() {
        // Legacy 首启 bootstrap：写模板并以 bail 提示编辑（单一 stderr 出口，不 eprintln + Err 双写）。
        crate::cli::ensure_product_config_ready(&product).await?;
    }

    let config =
        crate::api::product::load_product_config(&product, config_target.as_ref(), global.offline)
            .await?;
    crate::api::product::log_config_source(&product, config_target.as_ref(), global.offline);
    let config_source =
        crate::api::product::config_source_label(config_target.as_ref(), global.offline);
    // config 随 engine 构造被 move，root 须在其前取出（engine 开 StateStore 的实际 crbs root）。
    let root = config.crbs_root.display().to_string();

    let engine =
        crbs_core::engine::BuildEngine::new_from_config(&product, None, None, None, config).await?;
    let base_os = engine.base_os_path();
    if tokio::fs::try_exists(&base_os).await? && !force {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: format!(
                "base_os already exists: {}. Use --force to overwrite",
                base_os.display()
            ),
        }
        .into());
    }
    // bypass_guard=false（CLI 路径）：保留 active build 守卫。
    engine.init(force, None, None, false).await?;
    let output = InitOutput {
        command: "init",
        product,
        config_source,
        root,
    };
    format.print(&output)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_output_json_roundtrip() {
        let out = InitOutput {
            command: "init",
            product: "cc9".to_string(),
            config_source: "hub (https://hub.example.com)".to_string(),
            root: "/var/lib/crbs".to_string(),
        };
        let parsed: serde_json::Value = serde_json::from_str(&out.to_json().unwrap()).unwrap();
        assert_eq!(parsed["command"], "init");
        assert_eq!(parsed["product"], "cc9");
        assert_eq!(parsed["config_source"], "hub (https://hub.example.com)");
        assert_eq!(parsed["root"], "/var/lib/crbs");
    }
}
