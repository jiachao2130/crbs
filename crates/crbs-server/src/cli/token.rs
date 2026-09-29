// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs-server token`：用户 token 管理子命令（create / list / revoke）。

use std::path::PathBuf;

use clap::{Args, Subcommand};
use crbs_core::auth::secret::{Secret, SecretHash, SecretKind};

use super::common::{find_user_by_name, load_state_store};

/// Token management command entry.
#[derive(Args, Debug)]
pub struct TokenCli {
    #[command(subcommand)]
    pub command: TokenCommand,
}

/// Token management subcommands.
#[derive(Subcommand, Debug)]
pub enum TokenCommand {
    /// Issue a new token for a user
    Create {
        /// User name
        user: String,
        /// Token note (optional)
        #[arg(short, long)]
        name: Option<String>,
        /// Expiration in days (optional, default: no expiration)
        #[arg(short, long)]
        expires: Option<u32>,
    },
    /// List tokens for a user
    List {
        /// User name
        user: String,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = crate::cli::common::OutputFormat::Text)]
        format: crate::cli::common::OutputFormat,
    },
    /// Revoke a user's token
    Revoke {
        /// User name
        user: String,
        /// Token ID
        #[arg(long)]
        id: i64,
    },
}

/// token create `--expires` 上限，与 HTTP 路由 routes/admin.rs 的同名常量保持一致：
/// 巨值令 `Utc::now() + Duration::days(...)` 溢出 panic，近乎永不过期的 token 也无合理用途。
const MAX_TOKEN_EXPIRES_IN_DAYS: u32 = 3650;

fn validate_token_expires_days(days: u32) -> anyhow::Result<()> {
    if days > MAX_TOKEN_EXPIRES_IN_DAYS {
        anyhow::bail!(
            "--expires must be at most {} days",
            MAX_TOKEN_EXPIRES_IN_DAYS
        );
    }
    Ok(())
}

/// Handle `crbs-server token ...` commands.
pub async fn handle_token(config_dir: Option<PathBuf>, token_cli: TokenCli) -> anyhow::Result<()> {
    let store = load_state_store(config_dir.as_deref()).await?;

    match token_cli.command {
        TokenCommand::Create {
            user,
            name,
            expires,
        } => {
            if let Some(days) = expires {
                validate_token_expires_days(days)?;
            }
            let u = find_user_by_name(&store, &user).await?;
            if u.status != "active" {
                anyhow::bail!("user '{}' is disabled; cannot create token", user);
            }
            let secret = Secret::generate(SecretKind::UserToken)
                .map_err(|e| anyhow::anyhow!("generate token: {e}"))?;
            let hash = SecretHash::from_plain(secret.as_str());
            let expires_at = expires.map(|days| {
                (chrono::Utc::now() + chrono::Duration::days(days as i64)).to_rfc3339()
            });
            let id = store
                .create_user_token(u.id, name.as_deref(), hash.as_str(), expires_at.as_deref())
                .await
                .map_err(|e| anyhow::anyhow!("create user token: {e}"))?;
            // secret 明文只 stdout 一次性展示，绝不进审计日志。
            let detail = serde_json::json!({
                "token_id": id,
                "name": name,
                "expires_at": expires_at,
            })
            .to_string();
            store
                .audit_log(
                    "cli",
                    "cli",
                    "create_user_token",
                    Some(&user),
                    Some(&detail),
                )
                .await
                .map_err(|e| anyhow::anyhow!("audit create_user_token: {e}"))?;
            println!("Token created for {} (id={}) name={:?}", user, id, name);
            println!("Token: {}", secret.as_str());
            println!("\nKeep it secret; it will not be shown again.");
            if let Some(days) = expires {
                println!("Expires in {} days.", days);
            }
            Ok(())
        }
        TokenCommand::List { user, format } => {
            let u = find_user_by_name(&store, &user).await?;
            let tokens = store
                .list_user_tokens(u.id)
                .await
                .map_err(|e| anyhow::anyhow!("list user tokens: {e}"))?;
            if format == crate::cli::common::OutputFormat::Json {
                // 手动选列：hash（凭证哈希）绝不进任何输出形态。
                let items: Vec<serde_json::Value> = tokens
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "id": t.id,
                            "name": t.name,
                            "created_at": t.created_at,
                            "expires_at": t.expires_at,
                            "revoked_at": t.revoked_at,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "command": "token list",
                        "user": u.name,
                        "tokens": items,
                    }))
                    .map_err(|e| anyhow::anyhow!("serialize token list: {e}"))?
                );
                return Ok(());
            }
            if tokens.is_empty() {
                println!("No tokens for user '{}'.", user);
                return Ok(());
            }
            println!(
                "{:<5} {:<15} {:<25} {:<25} {:<25}",
                "id", "name", "created_at", "expires_at", "revoked_at"
            );
            for t in tokens {
                println!(
                    "{:<5} {:<15} {:<25} {:<25} {:<25}",
                    t.id,
                    t.name.as_deref().unwrap_or("-"),
                    t.created_at,
                    t.expires_at.as_deref().unwrap_or("-"),
                    t.revoked_at.as_deref().unwrap_or("-"),
                );
            }
            Ok(())
        }
        TokenCommand::Revoke { user, id } => {
            let u = find_user_by_name(&store, &user).await?;
            let token = store
                .list_user_tokens(u.id)
                .await
                .map_err(|e| anyhow::anyhow!("list user tokens: {e}"))?
                .into_iter()
                .find(|t| t.id == id)
                .ok_or_else(|| anyhow::anyhow!("token id {} not found for user '{}'", id, user))?;
            store
                .revoke_user_token(token.id)
                .await
                .map_err(|e| anyhow::anyhow!("revoke token: {e}"))?;
            let detail = serde_json::json!({ "token_id": id }).to_string();
            store
                .audit_log(
                    "cli",
                    "cli",
                    "revoke_user_token",
                    Some(&user),
                    Some(&detail),
                )
                .await
                .map_err(|e| anyhow::anyhow!("audit revoke_user_token: {e}"))?;
            println!("Token {} for user {} revoked.", id, user);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_token_expires_days_caps_at_3650() {
        assert!(validate_token_expires_days(3650).is_ok());
        assert!(validate_token_expires_days(0).is_ok());
        let err = validate_token_expires_days(3651).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("at most 3650"), "got: {msg}");
        assert!(validate_token_expires_days(u32::MAX).is_err());
    }
}
