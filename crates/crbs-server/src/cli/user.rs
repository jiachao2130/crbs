// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs-server user`：用户管理子命令（add / list / set-role / disable / set-password）。

use std::path::PathBuf;

use clap::{Args, Subcommand};

use super::common::{find_user_by_name, load_state_store};

/// User management command entry.
#[derive(Args, Debug)]
pub struct UserCli {
    #[command(subcommand)]
    pub command: UserCommand,
}

/// User management subcommands.
#[derive(Subcommand, Debug)]
pub enum UserCommand {
    /// Create a user
    Add {
        /// User name
        name: String,
        /// Role: admin / operator / builder / viewer (default: builder)
        #[arg(short, long, default_value = "builder")]
        role: String,
    },
    /// List all users
    List {
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = crate::cli::common::OutputFormat::Text)]
        format: crate::cli::common::OutputFormat,
    },
    /// Change a user's role
    SetRole {
        /// User name
        name: String,
        /// New role
        role: String,
    },
    /// Disable a user
    Disable {
        /// User name
        name: String,
    },
    /// Set a user's password (reads the password from stdin)
    SetPassword {
        /// User name
        name: String,
        /// Require the user to change the password at next sign-in
        #[arg(long)]
        must_change: bool,
    },
}

const VALID_ROLES: &[&str] = &["admin", "operator", "builder", "viewer"];

fn validate_role(role: &str) -> anyhow::Result<()> {
    if VALID_ROLES.contains(&role) {
        Ok(())
    } else {
        anyhow::bail!(
            "invalid role '{}'; expected one of: admin, operator, builder, viewer",
            role
        )
    }
}

/// Handle `crbs-server user ...` commands.
pub async fn handle_user(config_dir: Option<PathBuf>, user_cli: UserCli) -> anyhow::Result<()> {
    let store = load_state_store(config_dir.as_deref()).await?;

    match user_cli.command {
        UserCommand::Add { name, role } => {
            validate_user_name(&name)?;
            validate_role(&role)?;
            let id = store
                .create_user(&name, &role)
                .await
                .map_err(|e| anyhow::anyhow!("create user: {e}"))?;
            println!("User created: {} (id={}) role={}", name, id, role);
            Ok(())
        }
        UserCommand::List { format } => {
            let users = store
                .list_users()
                .await
                .map_err(|e| anyhow::anyhow!("list users: {e}"))?;
            if format == crate::cli::common::OutputFormat::Json {
                let items: Vec<serde_json::Value> = users
                    .iter()
                    .map(|u| {
                        serde_json::json!({
                            "id": u.id, "name": u.name, "role": u.role, "status": u.status,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "command": "user list",
                        "users": items,
                    }))
                    .map_err(|e| anyhow::anyhow!("serialize user list: {e}"))?
                );
                return Ok(());
            }
            if users.is_empty() {
                println!("No users found.");
                return Ok(());
            }
            println!("{:<5} {:<20} {:<12} {:<12}", "id", "name", "role", "status");
            for u in users {
                println!("{:<5} {:<20} {:<12} {:<12}", u.id, u.name, u.role, u.status);
            }
            Ok(())
        }
        UserCommand::SetRole { name, role } => {
            validate_role(&role)?;
            let user = find_user_by_name(&store, &name).await?;
            store
                .set_user_role(user.id, &role)
                .await
                .map_err(|e| anyhow::anyhow!("set user role: {e}"))?;
            // 审计走 store 层直写（CLI 不走 HTTP，避免 CLI 需要凭据的悖论）。
            let detail = serde_json::json!({ "role": role }).to_string();
            store
                .audit_log("cli", "cli", "role_set", Some(&name), Some(&detail))
                .await
                .map_err(|e| anyhow::anyhow!("audit role_set: {e}"))?;
            println!("User {} role updated to {}.", name, role);
            Ok(())
        }
        UserCommand::Disable { name } => {
            let user = find_user_by_name(&store, &name).await?;
            store
                .set_user_status(user.id, "disabled")
                .await
                .map_err(|e| anyhow::anyhow!("disable user: {e}"))?;
            let detail = serde_json::json!({ "status": "disabled" }).to_string();
            store
                .audit_log("cli", "cli", "user_disabled", Some(&name), Some(&detail))
                .await
                .map_err(|e| anyhow::anyhow!("audit user_disabled: {e}"))?;
            println!("User {} disabled.", name);
            Ok(())
        }
        UserCommand::SetPassword { name, must_change } => {
            let user = find_user_by_name(&store, &name).await?;
            let password = read_password_from_stdin()?;
            set_password_with_revocation(&store, &user, &name, &password, must_change).await?;
            println!("Password set for {}.", name);
            if must_change {
                println!("The user must change it at next sign-in.");
            }
            Ok(())
        }
    }
}

/// 改密落库 + 连锁撤销 + 审计（stdin 读取之外的完整流程，便于单测）。与 HTTP 两条
/// 改密路径同语义：改密后该用户全部既有会话立即失效——CLI 没有可保留的“当前会话”
///（管理员代改），故走全撤销；凭证失效由 `set_user_password` bump 收口，调用方无需重复。
async fn set_password_with_revocation(
    store: &crbs_core::StateStore,
    user: &crbs_core::User,
    name: &str,
    password: &str,
    must_change: bool,
) -> anyhow::Result<()> {
    // 策略收口：长度 10–1024 字符（不 trim、允许 unicode）
    crbs_core::auth::password::validate_password_policy(password)
        .map_err(|e| anyhow::anyhow!("invalid password: {e}"))?;
    let hash = crbs_core::auth::password::hash_password(password)
        .map_err(|e| anyhow::anyhow!("hash password: {e}"))?;
    store
        .set_user_password(user.id, &hash, must_change)
        .await
        .map_err(|e| anyhow::anyhow!("set user password: {e}"))?;
    // 连锁撤销：撤销失败必须报错可见（密码已换而旧会话仍活是安全缺陷），不做 warn-and-continue。
    store
        .revoke_all_user_sessions(user.id)
        .await
        .map_err(|e| anyhow::anyhow!("revoke user sessions: {e}"))?;
    // 审计走 store 层直写；只记事件名与目标用户，密码材料不进审计。
    let detail = must_change.then_some(r#"{"must_change":true}"#);
    store
        .audit_log("cli", "cli", "password_set", Some(name), detail)
        .await
        .map_err(|e| anyhow::anyhow!("audit password_set: {e}"))?;
    Ok(())
}

/// 从 stdin 读取一行作为密码（单遍，支持管道/重定向；无终端回显抑制，交互式场景配合
/// `read -s` 使用）。只去除行尾 `\n` / `\r\n`（传输介质换行），不 trim：密码前后空白是字面语义。
fn read_password_from_stdin() -> anyhow::Result<String> {
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)
        .map_err(|e| anyhow::anyhow!("read password from stdin: {e}"))?;
    if line.ends_with('\n') {
        line.pop();
    }
    if line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

/// 用户名预检：规则本体在 `crbs_core::validation::validate_user_name`
/// （`StateStore::create_user` 收口同一真值），此处仅做 anyhow 适配。
fn validate_user_name(name: &str) -> anyhow::Result<()> {
    crbs_core::validation::validate_user_name(name)
        .map_err(|e| anyhow::anyhow!("invalid user name: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{App, Command};

    /// `user set-password --must-change`：flag 解析与缺省 false。
    #[test]
    fn set_password_parses_must_change_flag() {
        use clap::Parser;
        let app = App::try_parse_from([
            "crbs-server",
            "--config-dir",
            "/etc/crbs",
            "user",
            "set-password",
            "alice",
            "--must-change",
        ])
        .expect("parse with --must-change");
        assert!(matches!(
            app.command,
            Command::User(UserCli {
                command: UserCommand::SetPassword {
                    ref name,
                    must_change: true
                }
            }) if name == "alice"
        ));

        let app = App::try_parse_from([
            "crbs-server",
            "--config-dir",
            "/etc/crbs",
            "user",
            "set-password",
            "alice",
        ])
        .expect("parse without flag");
        assert!(matches!(
            app.command,
            Command::User(UserCli {
                command: UserCommand::SetPassword {
                    must_change: false,
                    ..
                }
            })
        ));
    }

    /// 改密连锁撤销：`user set-password` 落库后该用户既有会话必须全部失效，他人会话不受牵连。
    #[tokio::test]
    async fn set_password_revokes_user_sessions() {
        use crbs_core::auth::secret::{Secret, SecretKind};

        let tmp = tempfile::tempdir().unwrap();
        let store = crbs_core::StateStore::new(tmp.path()).await.unwrap();

        // bob 两个会话 + carol 一个会话（对照组：不应被牵连）。
        let bob_id = store.create_user("bob", "builder").await.unwrap();
        let carol_id = store.create_user("carol", "builder").await.unwrap();
        let expires = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let mk_session = |user_id: i64| {
            let store = &store;
            let expires = expires.clone();
            async move {
                let secret = Secret::generate(SecretKind::Session).unwrap();
                store
                    .create_session(user_id, secret.hash().as_str(), &expires, None)
                    .await
                    .unwrap();
                secret.hash().as_str().to_string()
            }
        };
        let bob_a = mk_session(bob_id).await;
        let bob_b = mk_session(bob_id).await;
        let carol = mk_session(carol_id).await;

        let now = chrono::Utc::now();
        for hash in [&bob_a, &bob_b, &carol] {
            assert!(
                store
                    .find_session_by_hash(hash)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_active(now),
                "seeded sessions must be active before password change"
            );
        }

        let bob = store.find_user_by_name("bob").await.unwrap().unwrap();
        set_password_with_revocation(&store, &bob, "bob", "correct horse battery staple", false)
            .await
            .expect("cli set-password flow");

        let now = chrono::Utc::now();
        for hash in [&bob_a, &bob_b] {
            assert!(
                !store
                    .find_session_by_hash(hash)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_active(now),
                "bob's old sessions must be revoked after password change"
            );
        }
        assert!(
            store
                .find_session_by_hash(&carol)
                .await
                .unwrap()
                .unwrap()
                .is_active(now),
            "carol's session must survive bob's password change"
        );
    }
}
