// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs-server product`：产品 ACL 管理子命令（acl grant / revoke / list）。

use std::path::PathBuf;

use clap::{Args, Subcommand};

use super::common::{find_user_by_name, load_state_store};

/// Product ACL management command entry.
#[derive(Args, Debug)]
pub struct ProductCli {
    #[command(subcommand)]
    pub command: ProductCommand,
}

/// Product ACL management subcommands.
#[derive(Subcommand, Debug)]
pub enum ProductCommand {
    /// Grant a user access to a product
    Acl(AclCli),
}

/// Product ACL subcommand entry.
#[derive(Args, Debug)]
pub struct AclCli {
    #[command(subcommand)]
    pub command: AclCommand,
}

/// Product ACL operations (grant / revoke / list).
#[derive(Subcommand, Debug, Clone)]
pub enum AclCommand {
    /// Grant a user access to a product
    Grant {
        /// Product name
        product: String,
        /// User name
        user: String,
        /// Role to grant. Defaults to `viewer` (least-privilege).
        #[arg(long, value_parser = ["viewer", "builder", "admin"], default_value = "viewer")]
        role: String,
    },
    /// Revoke a user's access to a product
    Revoke {
        /// Product name
        product: String,
        /// User name
        user: String,
    },
    /// List users authorized for a product
    List {
        /// Product name
        product: String,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = crate::cli::common::OutputFormat::Text)]
        format: crate::cli::common::OutputFormat,
    },
}

/// Handle `crbs-server product acl ...` commands.
pub async fn handle_product(
    config_dir: Option<PathBuf>,
    product_cli: ProductCli,
) -> anyhow::Result<()> {
    let store = load_state_store(config_dir.as_deref()).await?;

    let ProductCommand::Acl(AclCli { command }) = product_cli.command;

    match command {
        AclCommand::Grant {
            product,
            user,
            role,
        } => {
            // handler 层防御复验：与 clap value_parser / HTTP API 同一角色集合。
            if !is_valid_acl_role(&role) {
                anyhow::bail!(
                    "invalid role '{}'; must be one of: viewer, builder, admin",
                    role
                );
            }
            crbs_core::validation::validate_product(&product)
                .map_err(|e| anyhow::anyhow!("invalid product name: {e}"))?;
            let u = find_user_by_name(&store, &user).await?;
            store
                .grant_product_acl_with_role(u.id, &product, &role)
                .await
                .map_err(|e| anyhow::anyhow!("grant product acl: {e}"))?;
            let detail = serde_json::json!({ "user": user, "role": role }).to_string();
            store
                .audit_log(
                    "cli",
                    "cli",
                    "grant_product_acl",
                    Some(&product),
                    Some(&detail),
                )
                .await
                .map_err(|e| anyhow::anyhow!("audit grant_product_acl: {e}"))?;
            println!(
                "Granted user '{}' role '{}' to product '{}'.",
                user, role, product
            );
            Ok(())
        }
        AclCommand::Revoke { product, user } => {
            crbs_core::validation::validate_product(&product)
                .map_err(|e| anyhow::anyhow!("invalid product name: {e}"))?;
            let u = find_user_by_name(&store, &user).await?;
            store
                .revoke_product_acl(u.id, &product)
                .await
                .map_err(|e| anyhow::anyhow!("revoke product acl: {e}"))?;
            let detail = serde_json::json!({ "user": user }).to_string();
            store
                .audit_log(
                    "cli",
                    "cli",
                    "revoke_product_acl",
                    Some(&product),
                    Some(&detail),
                )
                .await
                .map_err(|e| anyhow::anyhow!("audit revoke_product_acl: {e}"))?;
            println!("Revoked user '{}' access to product '{}'.", user, product);
            Ok(())
        }
        AclCommand::List { product, format } => {
            crbs_core::validation::validate_product(&product)
                .map_err(|e| anyhow::anyhow!("invalid product name: {e}"))?;
            let users = store
                .list_users_by_product(&product)
                .await
                .map_err(|e| anyhow::anyhow!("list users by product: {e}"))?;
            if format == crate::cli::common::OutputFormat::Json {
                let items: Vec<serde_json::Value> = users
                    .iter()
                    .map(|u| {
                        serde_json::json!({
                            "id": u.id, "name": u.name, "role": u.role,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "command": "product acl list",
                        "product": product,
                        "users": items,
                    }))
                    .map_err(|e| anyhow::anyhow!("serialize product acl list: {e}"))?
                );
                return Ok(());
            }
            if users.is_empty() {
                println!("No users have access to product '{}'.", product);
                return Ok(());
            }
            println!("{:<5} {:<20} {:<12}", "id", "name", "role");
            for u in users {
                println!("{:<5} {:<20} {:<12}", u.id, u.name, u.role);
            }
            Ok(())
        }
    }
}

/// 校验 product ACL role 是否合法；与 HTTP API routes/product.rs 的
/// `["viewer", "builder", "admin"]` 单一真值集合，扩集合需双侧同步。
fn is_valid_acl_role(role: &str) -> bool {
    matches!(role, "viewer" | "builder" | "admin")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{App, Command};
    use clap::Parser;

    // -------- `AclCommand::Grant` --role 解析与 validator 测试 --------

    /// `AclCommand::Grant` `--role` 行为的端到端 clap 解析测试。
    fn parse_acl_grant(args: &[&str]) -> Result<App, clap::Error> {
        let mut full = vec!["crbs-server", "product", "acl", "grant", "mydist", "alice"];
        full.extend_from_slice(args);
        App::try_parse_from(full)
    }

    #[test]
    fn acl_role_validator_accepts_three_canonical_values() {
        // 单真值：与 HTTP 路由 product.rs:1028 同一集合；扩展集合需双侧同步。
        assert!(is_valid_acl_role("viewer"));
        assert!(is_valid_acl_role("builder"));
        assert!(is_valid_acl_role("admin"));
    }

    #[test]
    fn acl_role_validator_rejects_anything_else() {
        for bad in [
            "",
            "VIEWER",
            "Viewer",
            " owner",
            "root",
            "operator",
            "v",
            "viewer-admin",
            "viewer,builder",
        ] {
            assert!(
                !is_valid_acl_role(bad),
                "role {bad:?} should be rejected (case/whitespace/aliases forbidden)"
            );
        }
    }

    #[test]
    fn acl_grant_parses_explicit_role_per_value() {
        for role in ["viewer", "builder", "admin"] {
            let app = parse_acl_grant(&["--role", role]).expect("parse should succeed");
            let AclCommand::Grant { role: parsed, .. } = match_command_product(&app, "acl grant")
            else {
                panic!("unexpected subcommand shape for --role {role}");
            };
            assert_eq!(parsed, role, "explicit --role={role} should round-trip");
        }
    }

    #[test]
    fn acl_grant_defaults_role_to_viewer_when_flag_absent() {
        let app = parse_acl_grant(&[]).expect("parse should succeed");
        let AclCommand::Grant { role, .. } = match_command_product(&app, "acl grant") else {
            panic!("unexpected subcommand shape for default role");
        };
        assert_eq!(role, "viewer");
    }

    #[test]
    fn acl_grant_rejects_invalid_role_at_clap_level() {
        for bad in ["owner", "operator", "root", ""] {
            let err = parse_acl_grant(&["--role", bad])
                .expect_err(&format!("role {bad:?} should be rejected at clap layer"));
            let msg = err.to_string();
            // clap 的 value_parser 失败会包含 "invalid value" 或具体取值
            assert!(
                msg.contains("invalid value")
                    || msg.contains("--role")
                    || msg.contains("possible values"),
                "expected clap rejection message, got: {msg}"
            );
        }
    }

    /// 抽出 `App → AclCommand` 链的 match 逻辑，让多个解析测试共享。
    fn match_command_product(app: &App, sub: &str) -> AclCommand {
        let product_cli = match &app.command {
            Command::Product(p) => p,
            _ => panic!("expected Product subcommand, got something else (case: {sub})"),
        };
        let ProductCommand::Acl(acl_cli) = &product_cli.command;
        match &acl_cli.command {
            AclCommand::Grant { .. } => acl_cli.command.clone(),
            other => panic!("expected AclCommand::Grant, got {other:?}"),
        }
    }
}
