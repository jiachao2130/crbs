// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs nihao` 命令：连通性与认证自检。

use anyhow::Result;
use serde::Deserialize;

use crate::cli::OutputFormat;

/// `GET /api/v1/nihao` 的响应体。
#[derive(Debug, Deserialize)]
pub(crate) struct NihaoResponse {
    pub message: String,
    pub server_version: String,
    pub server_time: String,
    pub auth: String,
    pub user: String,
    pub role: String,
}

pub(crate) struct NihaoArgs {
    /// 成功信封 command：nihao/ping/whoami 三别名共用本 handler，随实际入口变体走。
    pub command: &'static str,
    pub remote: Option<String>,
    pub token: Option<String>,
    pub ca_cert: Option<std::path::PathBuf>,
    pub daemon: bool,
    pub format: OutputFormat,
}

pub(crate) async fn handle_nihao(args: NihaoArgs) -> Result<()> {
    let resolved = resolve_target(args.remote, args.token, args.ca_cert, args.daemon).await?;

    let rt = crate::remote::RemoteTarget::new(resolved.url, resolved.token, resolved.ca_cert);
    let url = format!("{}/api/v1/nihao", rt.url);
    let parsed: NihaoResponse = crate::remote::remote_send_json(
        &rt,
        reqwest::Method::GET,
        |client| client.get(&url),
        None,
        None,
    )
    .await?;

    let output = NihaoOutput {
        command: args.command,
        server: rt.url,
        message: parsed.message,
        server_version: parsed.server_version,
        server_time: parsed.server_time,
        auth: parsed.auth,
        user: parsed.user,
        role: parsed.role,
    };
    args.format.print(&output)?;

    Ok(())
}

#[derive(serde::Serialize)]
struct NihaoOutput {
    command: &'static str,
    server: String,
    message: String,
    server_version: String,
    server_time: String,
    auth: String,
    user: String,
    role: String,
}

impl crate::cli::CommandOutput for NihaoOutput {
    fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    fn print_text(&self) {
        println!("Server at {} says \"{}\"", self.server, self.message);
        println!("  version: {}", self.server_version);
        println!("  auth: {}", self.auth);
        // 匿名（profile 无 token 或服务端关闭认证）：服务端回空串，显示可读占位。
        if self.auth == "disabled" {
            println!("  user: (anonymous)");
        } else {
            println!("  user: {} (role: {})", self.user, self.role);
        }
        // server_time 是 DB 存的 UTC 串：human 输出转本地时区（解析失败原样降级），JSON 保持原串。
        println!(
            "  server_time: {}",
            crbs_core::util::format_local_time(&self.server_time)
        );
    }
}

struct ResolvedTarget {
    url: String,
    token: Option<String>,
    ca_cert: Option<std::path::PathBuf>,
}

async fn resolve_target(
    remote: Option<String>,
    token: Option<String>,
    ca_cert: Option<std::path::PathBuf>,
    daemon: bool,
) -> Result<ResolvedTarget> {
    if daemon {
        // 短探测命令无取消令牌，传 None。
        let port = crate::local_daemon::ensure_running(None).await?;
        return Ok(ResolvedTarget {
            url: crate::local_daemon::base_url(port),
            token: None,
            ca_cert: None,
        });
    }

    if let Some(target) = crate::remote::resolve(remote, token, ca_cert, false).await? {
        return Ok(ResolvedTarget {
            url: target.url,
            token: target.token,
            ca_cert: target.ca_cert,
        });
    }

    Err(crbs_core::error::CrbsError::ValidationFailed {
        message:
            "nihao requires a server target. Use --remote, --daemon, or configure remote.default"
                .into(),
    }
    .into())
}
