// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs products acl` 命令：产品 ACL 管理（list 列表；grant/revoke 授予/撤销 viewer/builder/admin 角色）。

use crate::cli::OutputFormat;
use crate::remote::RemoteTarget;
use anyhow::Result;
use clap::Subcommand;

/// ACL 子命令参数。
#[derive(Subcommand, Clone, Debug)]
pub(crate) enum ProductsAclCommand {
    /// List ACL entries for a product
    List {
        /// Product slug
        product: String,
    },
    /// Grant ACL access to a user
    Grant {
        /// Product slug
        product: String,
        /// Username to grant access to
        username: String,
        /// Role to grant
        #[arg(long, value_parser = ["viewer", "builder", "admin"], default_value = "viewer")]
        role: String,
    },
    /// Revoke ACL access from a user
    Revoke {
        /// Product slug
        product: String,
        /// Username to revoke access from
        username: String,
    },
}

pub(crate) async fn handle_products_acl(
    command: ProductsAclCommand,
    target: RemoteTarget,
    format: OutputFormat,
) -> Result<()> {
    match command {
        ProductsAclCommand::List { product } => list_acl(&target, &product, format).await,
        ProductsAclCommand::Grant {
            product,
            username,
            role,
        } => grant_acl(&target, &product, &username, &role, format).await,
        ProductsAclCommand::Revoke { product, username } => {
            revoke_acl(&target, &product, &username, format).await
        }
    }
}

async fn list_acl(target: &RemoteTarget, product: &str, format: OutputFormat) -> Result<()> {
    let url = format!(
        "{}/api/v1/products/{}/acl",
        target.url,
        urlencoding::encode(product)
    );
    let parsed: serde_json::Value = crate::remote::remote_send_json(
        target,
        reqwest::Method::GET,
        |client| client.get(&url),
        None,
        None,
    )
    .await?;
    format.print(&AclListOutput { value: &parsed })?;
    Ok(())
}

async fn grant_acl(
    target: &RemoteTarget,
    product: &str,
    username: &str,
    role: &str,
    format: OutputFormat,
) -> Result<()> {
    let body = serde_json::json!({
        "username": username,
        "role": role,
    });
    let url = format!(
        "{}/api/v1/products/{}/acl",
        target.url,
        urlencoding::encode(product)
    );
    let client = target.client().await?;
    let resp = crate::remote::retry_http("grant_acl", reqwest::Method::POST, None, || {
        client.post(&url).json(&body)
    })
    .await?;
    let status = resp.status;
    if status.is_success() {
        format.print(&AclGrantOutput {
            product,
            username,
            role,
        })?;
        return Ok(());
    }
    let body_text = resp.body;
    Err(crate::remote::http_status_error("grant_acl", status, &body_text).into())
}

async fn revoke_acl(
    target: &RemoteTarget,
    product: &str,
    username: &str,
    format: OutputFormat,
) -> Result<()> {
    let body = serde_json::json!({
        "username": username,
    });
    let url = format!(
        "{}/api/v1/products/{}/acl",
        target.url,
        urlencoding::encode(product)
    );
    let client = target.client().await?;
    let resp = crate::remote::retry_http("revoke_acl", reqwest::Method::DELETE, None, || {
        client.delete(&url).json(&body)
    })
    .await?;
    let status = resp.status;
    if status.is_success() {
        // 服务端 revoke 只删 ACL 行，不级联取消该用户在该产品的 pending/building 构建，输出只报告真实变更。
        format.print(&AclRevokeOutput { product, username })?;
        return Ok(());
    }
    let body_text = resp.body;
    Err(crate::remote::http_status_error("revoke_acl", status, &body_text).into())
}

/// grant 结果信封（`--format json` 生效，Text 分支保持既有文案）。
struct AclGrantOutput<'a> {
    product: &'a str,
    username: &'a str,
    role: &'a str,
}

impl crate::cli::CommandOutput for AclGrantOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        // command 与错误信封同源（products 全族共用 "products"）。
        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "command": "products",
            "product": self.product,
            "username": self.username,
            "role": self.role,
            "granted": true,
        }))?)
    }

    fn print_text(&self) {
        println!(
            "Granted {} access to '{}' for user '{}'",
            self.role, self.product, self.username
        );
    }
}

/// revoke 结果信封（同上）。
struct AclRevokeOutput<'a> {
    product: &'a str,
    username: &'a str,
}

impl crate::cli::CommandOutput for AclRevokeOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        // command 与错误信封同源（products 全族共用 "products"）。
        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "command": "products",
            "product": self.product,
            "username": self.username,
            "revoked": true,
        }))?)
    }

    fn print_text(&self) {
        println!(
            "Revoked access to '{}' from user '{}'",
            self.product, self.username
        );
    }
}

struct AclListOutput<'a> {
    value: &'a serde_json::Value,
}

impl crate::cli::CommandOutput for AclListOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        // 服务端返回裸数组，包 {command, acl} 信封（复数键 acl；command 与
        // json_error_contract 同源，全族 "products"），条目 schema 原样。
        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "command": "products",
            "acl": self.value,
        }))?)
    }

    fn print_text(&self) {
        let entries = self
            .value
            .as_array()
            .map(|a| a.as_slice())
            .unwrap_or_default();
        if entries.is_empty() {
            println!("No ACL entries.");
            return;
        }
        println!("{:<20} {:<10} Granted At", "User", "Role");
        for entry in entries {
            let username = entry
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            let role = entry.get("role").and_then(|v| v.as_str()).unwrap_or("-");
            // created_at 为 DB 存储的 UTC 串：human 输出转本地时区（解析失败原样降级），JSON 保持原串不包。
            let granted = crbs_core::util::format_local_time(
                entry
                    .get("created_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-"),
            );
            println!("{:<20} {:<10} {}", username, role, granted);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AclGrantOutput, AclRevokeOutput};
    use crate::cli::CommandOutput;

    /// grant 的 JSON 信封——`{command,product,username,role,granted}`，Text 文案不变。
    #[test]
    fn acl_grant_output_json_envelope() {
        let out = AclGrantOutput {
            product: "fedora",
            username: "alice",
            role: "viewer",
        };
        let v: serde_json::Value = serde_json::from_str(&out.to_json().unwrap()).unwrap();
        assert_eq!(v["command"], "products");
        assert_eq!(v["product"], "fedora");
        assert_eq!(v["username"], "alice");
        assert_eq!(v["role"], "viewer");
        assert_eq!(v["granted"], true);
        assert_eq!(
            v.as_object().map(|m| m.len()),
            Some(5),
            "no extra keys: {v}"
        );
    }

    /// revoke 的 JSON 信封——`{command,product,username,revoked}`。
    #[test]
    fn acl_revoke_output_json_envelope() {
        let out = AclRevokeOutput {
            product: "fedora",
            username: "alice",
        };
        let v: serde_json::Value = serde_json::from_str(&out.to_json().unwrap()).unwrap();
        assert_eq!(v["command"], "products");
        assert_eq!(v["product"], "fedora");
        assert_eq!(v["username"], "alice");
        assert_eq!(v["revoked"], true);
        assert_eq!(
            v.as_object().map(|m| m.len()),
            Some(4),
            "no extra keys: {v}"
        );
    }
}
