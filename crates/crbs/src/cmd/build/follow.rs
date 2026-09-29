// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 本地/远程构建 follow 共用逻辑：轮询到终态、取消、超时、阶段输出。

use std::time::Duration;

use anyhow::{Context, Result};
use crbs_core::error::CrbsError;
use tokio_util::sync::CancellationToken;

use crate::cli::OutputFormat;

/// 通用轮询循环：每隔 `interval` 拉取一次构建记录，直到进入终态或超时/取消。
/// `timeout = None` = 无限轮询（attach 等用户主动等待场景）。
pub(crate) async fn poll_until_terminal<F, Fut>(
    pkg_name: &str,
    format: OutputFormat,
    interval: Duration,
    timeout: Option<Duration>,
    cancel_token: Option<&CancellationToken>,
    mut fetch: F,
) -> Result<crbs_core::BuildRecord>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Option<crbs_core::BuildRecord>>>,
{
    let mut last_phase = String::new();
    let start = std::time::Instant::now();

    loop {
        if cancel_token.map(|t| t.is_cancelled()).unwrap_or(false) {
            return Err(CrbsError::Cancelled.into());
        }
        if timeout.map(|t| start.elapsed() >= t).unwrap_or(false) {
            return Err(CrbsError::Timeout.into());
        }

        let maybe_record = fetch()
            .await
            .with_context(|| format!("poll build status for {}", pkg_name))?;

        if let Some(record) = maybe_record {
            if format == OutputFormat::Text && record.phase.as_str() != last_phase {
                // DB 中 arch 列默认为空字符串；空串视为未设置，避免打印空白对齐。
                if let Some(arch) = record.arch.as_deref().filter(|a| !a.is_empty()) {
                    println!(
                        "{}  arch={:<10} phase={:<12} elapsed={:>4}s",
                        pkg_name,
                        arch,
                        record.phase,
                        start.elapsed().as_secs()
                    );
                } else {
                    println!(
                        "{}  phase={:<12} elapsed={:>4}s",
                        pkg_name,
                        record.phase,
                        start.elapsed().as_secs()
                    );
                }
                last_phase = record.phase.clone();
            }

            if crbs_core::types::build_phase_is_terminal(&record.phase) {
                return Ok(record);
            }
        }

        // 与取消竞争：Ctrl-C 后立即以 Cancelled 返回，不被一个 interval 拖住。
        match cancel_token {
            Some(token) => {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = token.cancelled() => return Err(CrbsError::Cancelled.into()),
                }
            }
            None => tokio::time::sleep(interval).await,
        }
    }
}
