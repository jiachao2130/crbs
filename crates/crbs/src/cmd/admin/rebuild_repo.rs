// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs admin rebuild-repo <product>`：经 hub 触发产品发布 repo 的对账式重建。
//! 兜底收敛入口：自动触发点因撞锁超时等短暂失守时手动补位。

use anyhow::Result;

use crate::cli::{AdminRebuildRepoArgs, OutputFormat};

pub(crate) async fn handle_rebuild_repo(args: AdminRebuildRepoArgs) -> Result<()> {
    // 含 `/`、`?` 的产品名会打到错误端点：先校验，发送时 URL 编码。
    crbs_core::validation::validate_product(&args.product)?;
    // 仅远程执行（对账重建在 hub 侧）；缺远程目标 = ValidationFailed（USAGE=4）非 INTERNAL(1)，文案钉死。
    let target = crate::remote::resolve(
        args.remote_args.remote,
        args.remote_args.token,
        args.remote_args.ca_cert,
        false,
    )
        .await?
        .ok_or_else(|| crbs_core::error::CrbsError::ValidationFailed {
            message:
                "crbs admin rebuild-repo requires a remote server. Use --remote or configure remote.default"
                    .to_string(),
        })?;

    let client = target.client().await?;
    let url = format!(
        "{}/api/v1/admin/products/{}/rebuild-repo",
        target.url,
        urlencoding::encode(&args.product)
    );

    // 撞 .repodata.lock 时 hub 侧 regen 最坏阻塞数分钟（DEFAULT_FILE_LOCK_TIMEOUT=300s）；传输失败 = Network（ENVIRONMENT=6）非 INTERNAL(1)。
    let resp =
        client
            .post(&url)
            .send()
            .await
            .map_err(|e| crbs_core::error::CrbsError::Network {
                message: format!("POST {url}: {e}"),
            })?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| crbs_core::error::CrbsError::Network {
            message: format!("read rebuild-repo response body: {e}"),
        })?;

    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
        // 退出码契约：PERMISSION(5)，文案钉死。
        return Err(crbs_core::error::CrbsError::PermissionDenied {
            message: "permission denied: admin role required".to_string(),
        }
        .into());
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        // 退出码契约：USAGE(4)，文案钉死。
        return Err(crbs_core::error::CrbsError::NotFound {
            message: format!("product {} not found", args.product),
        }
        .into());
    }
    if !status.is_success() {
        return Err(crate::remote::http_status_error("admin rebuild-repo", status, &body).into());
    }

    // 错误文本中的 body 先经共享 truncate_body_for_error 截断/剥终端控制序列。
    let parsed: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| crbs_core::error::CrbsError::Network {
            message: format!(
                "parse rebuild-repo response: {}: {e}",
                crate::remote::truncate_body_for_error(&body)
            ),
        })?;

    match args.remote_args.format {
        // 成功包络：服务端响应体平铺透传并加 command 字段，schema 原样。
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&crate::cmd::json_success_envelope(
                "admin rebuild-repo",
                parsed,
            ))?
        ),
        OutputFormat::Text => {
            let arches = parsed
                .get("arches")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let linked = parsed.get("linked").and_then(|v| v.as_u64()).unwrap_or(0);
            let unlinked = parsed.get("unlinked").and_then(|v| v.as_u64()).unwrap_or(0);
            println!(
                "Rebuilt repo for product '{}': arches=[{}] linked={} unlinked={}",
                args.product, arches, linked, unlinked
            );
        }
    }

    Ok(())
}
