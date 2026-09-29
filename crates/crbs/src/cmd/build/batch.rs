// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 本地/远程批量构建共用逻辑：提交后并发 follow 多个 build_id 并聚合摘要。

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use crbs_core::error::CrbsError;
use tracing::warn;

use crate::cli::OutputFormat;
use crate::cmd::build::follow::{self};
use crate::cmd::build::output;
use crate::cmd::build::workers;
use crate::cmd::build::{
    follow_abandon_reason, follow_abandoned, follow_should_cancel_remote,
    print_follow_abandon_notice, term_trigger, BuildArgs, BuildOutputs, BuildResult, BuildSummary,
    FollowAbandoned, FollowTrigger,
};
use tokio_util::sync::CancellationToken;

/// follow 超时策略（daemon 与 remote/follow.rs 路径同族共用）：`Some(0)`
/// 不限时构建 → 24h 兜底（复用 LONG_BODY_TIMEOUT，防连接僵死后永久挂死）；
/// `Some(t)` → t + 600s 轮询余量；`None` → 默认 1h。
pub(crate) fn follow_timeout(timeout: Option<u64>) -> Duration {
    match timeout {
        Some(0) => crate::remote::LONG_BODY_TIMEOUT,
        Some(t) => Duration::from_secs(t.saturating_add(600)),
        None => Duration::from_secs(3600),
    }
}

/// 并发 follow 多个构建直到终态，返回聚合摘要（不输出）。
pub(crate) async fn follow_builds_raw(
    client: &reqwest::Client,
    base_url: &str,
    id_input_pairs: Vec<(i64, PathBuf)>,
    args: &BuildArgs,
    cancel_token: Option<&CancellationToken>,
) -> Result<BuildSummary> {
    let timeout_cancel = args.behavior.timeout_cancel;
    if cancel_token.map(|t| t.is_cancelled()).unwrap_or(false) {
        // 首信号即 SIGTERM/SIGHUP 时按 detach 处理：不补发取消（follow 出口
        // 决策共用），打印提示后由调用方按 3 收口；SIGINT/程序化取消仍全量
        // 补发取消（Ctrl-C 放弃即取消）。
        let trigger = term_trigger();
        if follow_should_cancel_remote(trigger, timeout_cancel) {
            for (id, _) in &id_input_pairs {
                request_server_cancel(client, base_url, *id).await;
            }
        } else {
            let ids: Vec<i64> = id_input_pairs.iter().map(|(id, _)| *id).collect();
            print_follow_abandon_notice(
                &follow_abandon_reason(crate::cmd::build::first_term_signal(), false),
                &ids,
            );
            return Err(FollowAbandoned.into());
        }
        return Err(CrbsError::Cancelled.into());
    }

    let jobs = args.behavior.jobs.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(jobs));

    let mut handles: Vec<(tokio::task::JoinHandle<Result<BuildResult>>, PathBuf)> =
        Vec::with_capacity(id_input_pairs.len());
    for (build_id, srpm) in id_input_pairs {
        // 私有 Semaphore 从不 close，acquire 无失败路径，INTERNAL(1) 语义恰确。
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .context("acquire follow semaphore")?;
        let client = client.clone();
        let base_url = base_url.to_string();
        let follow_logs = args.output.follow_logs;
        let format = args.output.format;
        let cancel = cancel_token.cloned();
        let srpm_for_task = srpm.clone();
        let follow_timeout = follow_timeout(args.behavior.timeout);
        let timeout_cancel = args.behavior.timeout_cancel;
        let handle = tokio::spawn(async move {
            let _permit = permit;
            follow_one_build(FollowOneParams {
                client: &client,
                base_url: &base_url,
                build_id,
                srpm: &srpm_for_task,
                follow_logs,
                format,
                cancel_token: cancel.as_ref(),
                follow_timeout,
                timeout_cancel,
            })
            .await
        });
        handles.push((handle, srpm));
    }

    let mut succeeded = Vec::new();
    let mut failed = Vec::new();
    let mut cancelled = Vec::new();
    let mut timeout_list = Vec::new();

    for (handle, srpm) in handles {
        // JoinError 仅在 follow 子任务 panic 时出现（真 bug 防御臂），归 Internal。
        let result = match handle.await {
            Ok(r) => r,
            Err(e) => Err(anyhow::anyhow!("follow build task panicked: {e}")),
        };
        match result {
            Ok(BuildResult::Succeeded(path, outputs, duration)) => {
                succeeded.push((path, outputs, duration))
            }
            Ok(BuildResult::Failed(path, e, duration)) => {
                if matches!(e, CrbsError::Cancelled) {
                    cancelled.push((path, e, duration));
                } else if matches!(e, CrbsError::Timeout) {
                    timeout_list.push((path, e, duration));
                } else {
                    failed.push((path, e, duration));
                }
            }
            Err(e) => failed.push((srpm, CrbsError::Internal(e.to_string()), 0)),
        }
    }

    Ok(BuildSummary {
        succeeded,
        failed,
        cancelled,
        timeout: timeout_list,
    })
}

/// 并发 follow 多个构建直到终态，输出统一摘要。
pub(crate) async fn follow_builds(
    client: &reqwest::Client,
    base_url: &str,
    id_input_pairs: Vec<(i64, PathBuf)>,
    args: &BuildArgs,
    cancel_token: Option<&CancellationToken>,
) -> Result<()> {
    // 放弃提示需 build id：raw 消费 pairs，先留一份 id/路径映射。
    let pairs: Vec<(i64, PathBuf)> = id_input_pairs.clone();
    let timeout_cancel = args.behavior.timeout_cancel;
    let summary =
        match follow_builds_raw(client, base_url, id_input_pairs, args, cancel_token).await {
            Ok(s) => s,
            // daemon 路径无 submit 级联收口（补发取消已在 raw 内决策），此处直接
            // 映射 SilentExit{INTERRUPTED(3)}；提示已在 raw 打印。
            Err(e) if e.downcast_ref::<FollowAbandoned>().is_some() => {
                return Err(CrbsError::SilentExit {
                    code: crbs_core::exit_code::INTERRUPTED,
                }
                .into());
            }
            Err(e) => return Err(e),
        };

    match args.output.format {
        OutputFormat::Json => {
            // batch 不是 chain，chain-only 元数据全部 None。
            output::print_json_summary(output::SummaryOutputParams::plain(
                args.input.product.as_deref().unwrap_or(""),
                &summary,
            ))
            .await?
        }
        OutputFormat::Text => workers::print_summary(&summary),
    }

    // 三桶判定 + 代表错误抽取共用 super::batch_failure_exit（与本地 batch 单一事实源）。
    if let Some(representative) = super::batch_failure_exit(&summary) {
        let sig = crate::cmd::build::first_term_signal();
        if follow_abandoned(
            sig,
            summary.failed.len(),
            summary.cancelled.len(),
            summary.timeout.len(),
            timeout_cancel,
        ) {
            print_follow_abandon_notice(
                &follow_abandon_reason(sig, !timeout_cancel && !summary.timeout.is_empty()),
                &abandoned_ids(&pairs, &summary),
            );
            return Err(CrbsError::SilentExit {
                code: crbs_core::exit_code::INTERRUPTED,
            }
            .into());
        }
        return Err(super::exit_from_representative(
            args.output.format,
            representative,
        ));
    }

    Ok(())
}

/// 放弃提示的 build id 列表：按取消/超时桶里的 SRPM 路径回查 pairs。
fn abandoned_ids(pairs: &[(i64, PathBuf)], summary: &BuildSummary) -> Vec<i64> {
    summary
        .cancelled
        .iter()
        .chain(summary.timeout.iter())
        .filter_map(|(path, _, _)| {
            pairs
                .iter()
                .find(|(_, srpm)| srpm == path)
                .map(|(id, _)| *id)
        })
        .collect()
}

/// [`follow_one_build`] 的参数包：并发 batch 中单个构建的跟随上下文。
struct FollowOneParams<'a> {
    client: &'a reqwest::Client,
    base_url: &'a str,
    build_id: i64,
    srpm: &'a std::path::Path,
    follow_logs: bool,
    format: OutputFormat,
    cancel_token: Option<&'a CancellationToken>,
    follow_timeout: Duration,
    /// `--timeout-cancel`：超时臂是否补发服务端取消（默认仅放弃等待）。
    timeout_cancel: bool,
}

async fn follow_one_build(params: FollowOneParams<'_>) -> Result<BuildResult> {
    let FollowOneParams {
        client,
        base_url,
        build_id,
        srpm,
        follow_logs,
        format,
        cancel_token,
        follow_timeout,
        timeout_cancel,
    } = params;
    let pkg_name = crbs_core::util::srpm_display_name(srpm).to_string();

    let logs_handle = if follow_logs {
        let client = client.clone();
        let base_url = base_url.to_string();
        let cancel = cancel_token.cloned();
        Some(tokio::spawn(async move {
            if let Err(e) = stream_logs(&client, &base_url, build_id, cancel.as_ref()).await {
                warn!(error = %e, "Log streaming failed");
            }
        }))
    } else {
        None
    };

    let client = client.clone();
    let base_url = base_url.to_string();
    let build_id_owned = build_id;
    let client_for_cancel = client.clone();
    let base_url_for_cancel = base_url.clone();
    let start = std::time::Instant::now();
    let record = follow::poll_until_terminal(
        &pkg_name,
        format,
        Duration::from_secs(5),
        Some(follow_timeout),
        cancel_token,
        move || {
            let client = client.clone();
            let base_url = base_url.clone();
            let build_id = build_id_owned;
            async move {
                match fetch_build_record(&client, &base_url, build_id).await {
                    Ok(r) => Ok(Some(r)),
                    Err(e) => {
                        warn!(error = %e, "Failed to poll build status");
                        Ok(None)
                    }
                }
            }
        },
    )
    .await;

    if let Some(handle) = logs_handle {
        handle.abort();
        let _ = handle.await;
    }

    let record = match record {
        Ok(r) => r,
        Err(e) => {
            let duration = start.elapsed().as_secs();
            if e.downcast_ref::<CrbsError>()
                .is_some_and(|ce| matches!(ce, CrbsError::Cancelled))
            {
                // SIGTERM/SIGHUP detach 不补发取消（决策纯函数共用）；SIGINT/
                // 程序化取消仍通知 server 停止（客户端放弃即取消语义）。
                if follow_should_cancel_remote(crate::cmd::build::term_trigger(), timeout_cancel) {
                    request_server_cancel(&client_for_cancel, &base_url_for_cancel, build_id).await;
                }
                return Ok(BuildResult::Failed(
                    srpm.to_path_buf(),
                    CrbsError::Cancelled,
                    duration,
                ));
            }
            if e.downcast_ref::<CrbsError>()
                .is_some_and(|ce| matches!(ce, CrbsError::Timeout))
            {
                // 客户端等待超时（跟 --timeout 对齐后仍到点）：--timeout-cancel
                // 才补发取消；默认放弃等待、构建在 server 继续跑完。
                if follow_should_cancel_remote(FollowTrigger::Timeout, timeout_cancel) {
                    request_server_cancel(&client_for_cancel, &base_url_for_cancel, build_id).await;
                }
                return Ok(BuildResult::Failed(
                    srpm.to_path_buf(),
                    CrbsError::Timeout,
                    duration,
                ));
            }
            return Err(e);
        }
    };
    let duration = record.duration.unwrap_or(0) as u64;

    match record.phase.as_str() {
        "succeeded" => {
            let result_dir = record
                .result_dir
                .as_ref()
                .map(PathBuf::from)
                // result_dir 缺失属"未找到"语义——NotFound（USAGE=4）。
                .ok_or_else(|| CrbsError::NotFound {
                    message: format!("build {build_id} has no result_dir"),
                })?;
            let outputs = BuildOutputs {
                build_id,
                pkg_name: record.pkg_name,
                rpms: record.rpms.into_iter().map(PathBuf::from).collect(),
                srpms: vec![],
                logs: vec![],
                result_dir,
                retries: 0,
                signed: record.signed,
            };
            Ok(BuildResult::Succeeded(
                srpm.to_path_buf(),
                outputs,
                duration,
            ))
        }
        // 服务端非 succeeded 终态统一经 remote_phase_error 归桶（与 remote follow
        // 同一构造器）：cancelled/timeout 保持纯变体；failed 与未知 phase 落
        // ContainerExecFailed（build_failed 桶、退出码 2）——不用 Internal（误导排障），
        // 未知 phase 只在服务端白名单外新状态出现时发生，按构建失败处理进重试语义。
        other => Ok(BuildResult::Failed(
            srpm.to_path_buf(),
            super::remote::output::remote_phase_error(
                other,
                format!("remote build {build_id} ended with phase '{other}'"),
            ),
            duration,
        )),
    }
}

/// 客户端取消时通知 server/daemon 终止后台构建；404/409（已结束/不可取消）仅 debug 记录，不阻断流程（同目的信封复用 remote 取消实现，日志动词随其文案）。
async fn request_server_cancel(client: &reqwest::Client, base_url: &str, build_id: i64) {
    super::remote::request_remote_cancel(client, base_url, build_id).await;
}

async fn fetch_build_record(
    client: &reqwest::Client,
    base_url: &str,
    id: i64,
) -> Result<crbs_core::BuildRecord> {
    let url = format!("{}/api/v1/builds/{}", base_url, id);
    // reqwest 传输失败属环境域——Network（ENVIRONMENT=6），message 保留 context 串（含 URL）。
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| CrbsError::Network {
            message: format!("GET {url}: {e}"),
        })?;
    let status = resp.status();
    // body 读取失败（reqwest 错误）同属环境域，归 Network（ENVIRONMENT=6）。
    let body = resp.text().await.map_err(|e| CrbsError::Network {
        message: format!("read response body: {e}"),
    })?;
    if !status.is_success() {
        // 统一退出码契约映射：404 → NotFound、401/403 → PermissionDenied、5xx → Network。
        return Err(crate::remote::http_status_error("fetch build record", status, &body).into());
    }
    // serde 解析失败同归 Network（ENVIRONMENT=6）；body 经 truncate_body_for_error 净化后入错误文本。
    serde_json::from_str(&body)
        .map_err(|e| CrbsError::Network {
            message: format!(
                "parse build record: {}: {e}",
                crate::remote::truncate_body_for_error(&body)
            ),
        })
        .map_err(Into::into)
}

async fn stream_logs(
    client: &reqwest::Client,
    base_url: &str,
    build_id: i64,
    cancel_token: Option<&CancellationToken>,
) -> Result<()> {
    let url = format!("{}/api/v1/builds/{}/logs", base_url, build_id);
    // 跟随流放宽总超时（client 级 300s 会掐断 >5min 构建的日志尾），接入取消
    // 令牌随 Ctrl-C 终止；传输失败归 Network（ENVIRONMENT=6），message 含 URL。
    let resp = client
        .get(&url)
        .timeout(crate::remote::LONG_BODY_TIMEOUT)
        .send()
        .await
        .map_err(|e| CrbsError::Network {
            message: format!("GET {url}: {e}"),
        })?;
    crate::remote::stream_response_to_stdout(resp, cancel_token).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 钉死 follow 超时策略：Some(0)=24h 兜底、Some(t)=t+600s、None=1h。
    #[test]
    fn follow_timeout_covers_zero_explicit_and_default() {
        assert_eq!(follow_timeout(Some(0)), Duration::from_secs(86400));
        assert_eq!(follow_timeout(Some(14400)), Duration::from_secs(15000));
        assert_eq!(follow_timeout(None), Duration::from_secs(3600));
    }
}
