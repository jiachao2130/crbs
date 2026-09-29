// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs clean` 命令实现。

use crate::cli::{CommandOutput, GlobalArgs};
use crbs_core::privilege::CallerContext;
use tracing::info;

pub(crate) struct CleanArgs {
    pub product: String,
    pub remote: Option<String>,
    pub token: Option<String>,
    pub ca_cert: Option<std::path::PathBuf>,
    pub yes: bool,
    pub format: crate::cli::OutputFormat,
}

/// `crbs clean` 统一输出：engine clean 返回 `Result<()>` 无清理统计，摘要只含 product + ok。
#[derive(serde::Serialize)]
struct CleanOutput {
    command: &'static str,
    product: String,
    ok: bool,
}

impl CommandOutput for CleanOutput {
    fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    fn print_text(&self) {
        // 同 InitOutput：成功后 stdout 刻意静默。
    }
}

pub(crate) async fn handle_clean(
    args: CleanArgs,
    ctx: CallerContext,
    global: GlobalArgs,
) -> anyhow::Result<()> {
    let CleanArgs {
        product,
        remote,
        token,
        ca_cert,
        yes,
        format,
    } = args;
    crate::cli::validate_product(&product)?;
    // 破坏性整批操作（拆掉产品全部构建状态：chroot base / 共享层引用 / 结果目录），统一走 confirm_or_bail（与 admin init 同口径）。
    crate::cmd::confirm::confirm_or_bail(
        &format!("Remove ALL build state for product '{product}'?"),
        yes,
    )?;
    info!("Cleaning product: {}", product);

    // 与 init 同一套解析路径；hub 报产品已删除（404）时 `--offline` 仍可读磁盘快照完成清理（404 消息双出口已含该提示）。
    let config_target = crate::remote::resolve_config_target(remote, token, ca_cert).await?;
    let config =
        crate::api::product::load_product_config(&product, config_target.as_ref(), global.offline)
            .await?;
    crate::api::product::log_config_source(&product, config_target.as_ref(), global.offline);

    let engine =
        crbs_core::engine::BuildEngine::new_from_config(&product, None, None, None, config)
            .await?
            .with_caller(ctx.caller.clone());
    // crbs clean CLI：保留 active build 守卫
    engine.clean(false).await?;
    let output = CleanOutput {
        command: "clean",
        product,
        ok: true,
    };
    format.print(&output)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_output_json_roundtrip() {
        let out = CleanOutput {
            command: "clean",
            product: "cc9".to_string(),
            ok: true,
        };
        let parsed: serde_json::Value = serde_json::from_str(&out.to_json().unwrap()).unwrap();
        assert_eq!(parsed["command"], "clean");
        assert_eq!(parsed["product"], "cc9");
        assert_eq!(parsed["ok"], true);
    }

    /// 非 TTY 且无 --yes 必须在任何工作前拒绝（gate 在产品名校验后、配置加载前）。
    #[tokio::test]
    async fn clean_without_yes_bails_in_non_tty() {
        let ctx = CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: "tester".to_string(),
            },
            false,
        );
        let err = handle_clean(
            CleanArgs {
                product: "fedora".to_string(),
                remote: None,
                token: None,
                ca_cert: None,
                yes: false,
                format: crate::cli::OutputFormat::Text,
            },
            ctx,
            crate::cli::GlobalArgs { offline: false },
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("stdin is not a TTY"),
            "expected non-TTY refusal, got: {err:#}"
        );
    }
}
