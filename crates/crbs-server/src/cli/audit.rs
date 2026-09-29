// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs-server audit`：审计日志查询子命令（list）。

use std::path::PathBuf;

use clap::{Args, Subcommand};

use super::common::load_state_store;

/// Audit log query command entry.
#[derive(Args, Debug)]
pub struct AuditCli {
    #[command(subcommand)]
    pub command: AuditCommand,
}

/// Audit log management subcommands.
#[derive(Subcommand, Debug)]
pub enum AuditCommand {
    /// List audit logs
    List {
        /// Operator user name
        #[arg(short, long)]
        user: Option<String>,
        /// Operator role
        #[arg(short, long)]
        role: Option<String>,
        /// Action type
        #[arg(short, long)]
        action: Option<String>,
        /// Target object
        #[arg(short, long)]
        target: Option<String>,
        /// Start time (RFC3339)
        #[arg(long)]
        since: Option<String>,
        /// End time (RFC3339)
        #[arg(long)]
        until: Option<String>,
        /// Page size
        #[arg(short, long, default_value = "100")]
        limit: i64,
        /// Offset
        #[arg(short, long, default_value = "0")]
        offset: i64,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = crate::cli::common::OutputFormat::Text)]
        format: crate::cli::common::OutputFormat,
    },
}

/// Handle `crbs-server audit ...` commands.
pub async fn handle_audit(config_dir: Option<PathBuf>, audit_cli: AuditCli) -> anyhow::Result<()> {
    use crbs_core::AuditLogFilter;

    let store = load_state_store(config_dir.as_deref()).await?;

    match audit_cli.command {
        AuditCommand::List {
            user,
            role,
            action,
            target,
            since,
            until,
            limit,
            offset,
            format,
        } => {
            let filter = AuditLogFilter {
                user: user.as_deref(),
                role: role.as_deref(),
                action: action.as_deref(),
                target: target.as_deref(),
                since: since.as_deref(),
                until: until.as_deref(),
                limit,
                offset,
            };

            let total = store
                .count_audit_logs(AuditLogFilter {
                    user: filter.user,
                    role: filter.role,
                    action: filter.action,
                    target: filter.target,
                    since: filter.since,
                    until: filter.until,
                    limit: 0,
                    offset: 0,
                })
                .await
                .map_err(|e| anyhow::anyhow!("count audit logs: {e}"))?;
            let logs = store
                .list_audit_logs(filter)
                .await
                .map_err(|e| anyhow::anyhow!("list audit logs: {e}"))?;

            if format == crate::cli::common::OutputFormat::Json {
                let items: Vec<serde_json::Value> = logs
                    .iter()
                    .map(|l| {
                        serde_json::json!({
                            "id": l.id,
                            "user": l.user,
                            "role": l.role,
                            "action": l.action,
                            "target": l.target,
                            "detail": l.detail,
                            "created_at": l.created_at,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "command": "audit list",
                        "total": total,
                        "limit": limit,
                        "offset": offset,
                        "logs": items,
                    }))
                    .map_err(|e| anyhow::anyhow!("serialize audit list: {e}"))?
                );
                return Ok(());
            }

            if logs.is_empty() {
                println!("No audit logs found.");
                return Ok(());
            }

            println!(
                "Total: {}, limit: {}, offset: {}",
                total,
                logs.len(),
                offset
            );
            println!(
                "{:<5} {:<20} {:<12} {:<25} {:<20} {:<20}",
                "id", "user", "role", "action", "target", "created_at"
            );
            for l in logs {
                println!(
                    "{:<5} {:<20} {:<12} {:<25} {:<20} {:<20}",
                    l.id,
                    l.user,
                    l.role,
                    l.action,
                    l.target.as_deref().unwrap_or("-"),
                    l.created_at
                );
            }
            Ok(())
        }
    }
}
