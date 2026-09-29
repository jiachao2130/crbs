// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use crbs_core::error::CrbsError;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::cli::OutputFormat;
use crate::cmd::build::follow;
use crate::cmd::build::output;
use crate::cmd::build::workers;
use crate::cmd::build::{
    batch_failure_exit, exit_from_representative, follow_abandon_reason, follow_abandoned,
    follow_should_cancel_remote, print_follow_abandon_notice, BuildArgs, BuildOutputs, BuildResult,
    BuildSummary, FollowAbandoned, FollowTrigger,
};

use super::make_local_result_dir;
use super::output::{
    handle_terminal_record, print_status_line, remote_failure_message, TerminalRecordParams,
};

/// [`follow_remote_build`] 参数包：attach/watch 单个远端构建的连接凭据、构建标识、展示与轮询上下文。
pub(crate) struct FollowRemoteParams<'a> {
    pub(crate) client: &'a reqwest::Client,
    pub(crate) base_url: &'a str,
    pub(crate) build_id: i64,
    pub(crate) pkg_name: &'a str,
    pub(crate) follow_logs: bool,
    pub(crate) format: OutputFormat,
    pub(crate) cancel_token: Option<&'a CancellationToken>,
    pub(crate) token: Option<String>,
    pub(crate) ca_cert: Option<PathBuf>,
    pub(crate) poll_timeout: Duration,
}

/// 跟随单个远端构建：状态轮询任务后台静默运行（状态变化才更新状态行），日志经 chunked streaming 实时推送；永久错误（401/403/404）终止轮询，瞬时错误容忍继续。
/// JSON 模式下不输出状态行也不跟日志，只等终态后输出 JSON 摘要。
pub(crate) async fn follow_remote_build(params: FollowRemoteParams<'_>) -> Result<()> {
    let FollowRemoteParams {
        client,
        base_url,
        build_id,
        pkg_name,
        follow_logs,
        format,
        cancel_token,
        token,
        ca_cert,
        poll_timeout,
    } = params;
    if cancel_token.map(|t| t.is_cancelled()).unwrap_or(false) {
        return Err(CrbsError::Cancelled.into());
    }

    if format == OutputFormat::Json {
        let client_for_poll = client.clone();
        let base_url_for_poll = base_url.to_string();
        let build_id_owned = build_id;
        let record = follow::poll_until_terminal(
            pkg_name,
            OutputFormat::Json,
            Duration::from_secs(5),
            Some(poll_timeout),
            cancel_token,
            move || {
                let client = client_for_poll.clone();
                let base_url = base_url_for_poll.clone();
                let build_id = build_id_owned;

                async move {
                    match fetch_build_record(&client, &base_url, build_id).await {
                        Ok(record) => Ok(Some(record)),
                        Err(e) if !is_permanent_remote_error(&e) => {
                            warn!(error = %e, "Failed to poll remote build status");
                            Ok(None)
                        }
                        Err(e) => Err(e),
                    }
                }
            },
        )
        .await?;
        return handle_terminal_record(TerminalRecordParams {
            base_url,
            build_id,
            pkg_name,
            record: &record,
            format,
            token: token.clone(),
            ca_cert,
            cancel_token,
        })
        .await;
    }

    let cancel = cancel_token.cloned();
    let status_handle: tokio::task::JoinHandle<Result<crbs_core::BuildRecord>> = {
        let client = client.clone();
        let base_url = base_url.to_string();
        let pkg_name = pkg_name.to_string();
        tokio::spawn(async move {
            let mut last_phase = String::new();
            let start = std::time::Instant::now();
            let timeout = poll_timeout;
            loop {
                if cancel.as_ref().map(|t| t.is_cancelled()).unwrap_or(false) {
                    return Err(CrbsError::Cancelled.into());
                }
                if start.elapsed() >= timeout {
                    return Err(CrbsError::Timeout.into());
                }
                match fetch_build_record(&client, &base_url, build_id).await {
                    Ok(record) => {
                        if record.phase != last_phase {
                            print_status_line(
                                &pkg_name,
                                record.arch.as_deref(),
                                &record.phase,
                                start.elapsed().as_secs(),
                            );
                            last_phase = record.phase.clone();
                        }
                        if crbs_core::types::build_phase_is_terminal(&record.phase) {
                            return Ok(record);
                        }
                    }

                    Err(e) if is_permanent_remote_error(&e) => return Err(e),

                    Err(e) => {
                        warn!(error = %e, "Failed to poll remote build status");
                    }
                }

                match cancel.as_ref() {
                    Some(token) => {
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                            _ = token.cancelled() => return Err(CrbsError::Cancelled.into()),
                        }
                    }
                    None => tokio::time::sleep(Duration::from_secs(5)).await,
                }
            }
        })
    };

    let logs_handle = if follow_logs {
        let client = client.clone();
        let base_url = base_url.to_string();
        let cancel = cancel_token.cloned();
        Some(tokio::spawn(async move {
            if cancel.as_ref().map(|t| t.is_cancelled()).unwrap_or(false) {
                return;
            }
            if let Err(e) = stream_remote_logs(&client, &base_url, build_id, cancel.as_ref()).await
            {
                warn!(error = %e, "Remote log streaming failed");
            }
        }))
    } else {
        None
    };

    let status_result = status_handle.await;

    if let Some(mut handle) = logs_handle {
        tokio::select! {
            r = &mut handle => {
                if let Err(e) = r {
                    warn!(error = %e, "Remote log streaming task panicked");
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                warn!("Remote log streaming did not stop within timeout, aborting");
                handle.abort();
            }
        }
    }

    let record = status_result.context("status poll task")??;

    if !follow_logs {
        println!();
    }

    handle_terminal_record(TerminalRecordParams {
        base_url,
        build_id,
        pkg_name,
        record: &record,
        format,
        token: token.clone(),
        ca_cert,
        cancel_token,
    })
    .await
}
/// 并发跟随一批远端构建至终态并聚合结果。
pub(crate) async fn follow_remote_builds(
    client: &reqwest::Client,
    base_url: &str,
    id_input_pairs: Vec<(i64, PathBuf)>,
    args: &BuildArgs,
    cancel_token: Option<&CancellationToken>,
    token: Option<String>,
    ca_cert: Option<PathBuf>,
) -> Result<()> {
    let jobs = args.behavior.jobs.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(jobs));
    let timeout_cancel = args.behavior.timeout_cancel;

    let pairs: Vec<(i64, PathBuf)> = id_input_pairs.clone();

    let mut handles: Vec<(tokio::task::JoinHandle<Result<BuildResult>>, PathBuf)> =
        Vec::with_capacity(id_input_pairs.len());
    for (build_id, srpm) in id_input_pairs {
        let follow_timeout: Duration =
            crate::cmd::build::batch::follow_timeout(args.behavior.timeout);

        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .context("acquire follow semaphore")?;
        let client = client.clone();
        let base_url = base_url.to_string();
        let follow_logs = args.output.follow_logs;
        let format = args.output.format;
        let download = args.runtime.download;
        let cancel = cancel_token.cloned();
        let srpm_for_task = srpm.clone();
        let token_for_task = token.clone();
        let ca_cert_for_task = ca_cert.clone();
        let handle = tokio::spawn(async move {
            let _permit = permit;
            follow_remote_build_to_outputs(FollowToOutputsParams {
                client: &client,
                base_url: &base_url,
                build_id,
                srpm: &srpm_for_task,
                follow_logs,
                format,
                download,
                cancel_token: cancel.as_ref(),
                token: token_for_task,
                ca_cert: ca_cert_for_task,
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
        let result = match handle.await {
            Ok(r) => r,
            Err(e) => Err(anyhow::anyhow!("follow remote build task panicked: {e}")),
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

    let summary = BuildSummary {
        succeeded,
        failed,
        cancelled,
        timeout: timeout_list,
    };

    match args.output.format {
        OutputFormat::Json => {
            output::print_json_summary(output::SummaryOutputParams::plain(
                args.input.product.as_deref().unwrap_or(""),
                &summary,
            ))
            .await?
        }
        OutputFormat::Text => workers::print_summary(&summary),
    }

    if let Some(representative) = batch_failure_exit(&summary) {
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
            return Err(FollowAbandoned.into());
        }
        return Err(exit_from_representative(args.output.format, representative));
    }

    Ok(())
}

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

/// [`follow_remote_build_to_outputs`] 参数包：并发跟随一批构建中单个构建的
/// 上下文（凭据、构建标识与 SRPM、下载与展示选项、轮询上限）。
pub(crate) struct FollowToOutputsParams<'a> {
    pub(crate) client: &'a reqwest::Client,
    pub(crate) base_url: &'a str,
    pub(crate) build_id: i64,
    pub(crate) srpm: &'a Path,
    pub(crate) follow_logs: bool,
    pub(crate) format: OutputFormat,
    pub(crate) download: bool,
    pub(crate) cancel_token: Option<&'a CancellationToken>,
    pub(crate) token: Option<String>,
    pub(crate) ca_cert: Option<PathBuf>,
    pub(crate) follow_timeout: Duration,

    pub(crate) timeout_cancel: bool,
}

pub(crate) async fn follow_remote_build_to_outputs(
    params: FollowToOutputsParams<'_>,
) -> Result<BuildResult> {
    use crbs_core::error::CrbsError;

    let FollowToOutputsParams {
        client,
        base_url,
        build_id,
        srpm,
        follow_logs,
        format,
        download,
        cancel_token,
        token,
        ca_cert,
        follow_timeout,
        timeout_cancel,
    } = params;

    if cancel_token.map(|t| t.is_cancelled()).unwrap_or(false) {
        return Ok(BuildResult::Failed(
            srpm.to_path_buf(),
            CrbsError::Cancelled,
            0,
        ));
    }

    let pkg_name = crbs_core::util::srpm_display_name(srpm).to_string();

    let logs_handle = if follow_logs {
        let client = client.clone();
        let base_url = base_url.to_string();
        let cancel = cancel_token.cloned();
        Some(tokio::spawn(async move {
            if cancel.as_ref().map(|t| t.is_cancelled()).unwrap_or(false) {
                return;
            }
            if let Err(e) = stream_remote_logs(&client, &base_url, build_id, cancel.as_ref()).await
            {
                warn!(error = %e, "Remote log streaming failed");
            }
        }))
    } else {
        None
    };

    let client_for_poll = client.clone();
    let base_url_for_poll = base_url.to_string();
    let build_id_owned = build_id;
    let start = std::time::Instant::now();
    let record = follow::poll_until_terminal(
        &pkg_name,
        format,
        Duration::from_secs(5),
        Some(follow_timeout),
        cancel_token,
        move || {
            let client = client_for_poll.clone();
            let base_url = base_url_for_poll.clone();
            let build_id = build_id_owned;
            async move {
                match fetch_build_record(&client, &base_url, build_id).await {
                    Ok(r) => Ok(Some(r)),

                    Err(e) if is_permanent_remote_error(&e) => Err(e),
                    Err(e) => {
                        warn!(error = %e, "Failed to poll remote build status");
                        Ok(None)
                    }
                }
            }
        },
    )
    .await;

    if let Some(mut handle) = logs_handle {
        tokio::select! {
            r = &mut handle => {
                if let Err(e) = r {
                    warn!(error = %e, "Remote log streaming task panicked");
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                warn!("Remote log streaming did not stop within timeout, aborting");
                handle.abort();
            }
        }
    }

    let record = match record {
        Ok(r) => r,
        Err(e) => {
            let duration = start.elapsed().as_secs();
            if e.downcast_ref::<CrbsError>()
                .is_some_and(|ce| matches!(ce, CrbsError::Cancelled))
            {
                return Ok(BuildResult::Failed(
                    srpm.to_path_buf(),
                    CrbsError::Cancelled,
                    duration,
                ));
            }
            if e.downcast_ref::<CrbsError>()
                .is_some_and(|ce| matches!(ce, CrbsError::Timeout))
            {
                if follow_should_cancel_remote(FollowTrigger::Timeout, timeout_cancel) {
                    super::request_remote_cancel(client, base_url, build_id).await;
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

    let pkg_name = if record.pkg_name.is_empty() {
        pkg_name
    } else {
        record.pkg_name.clone()
    };

    let duration = record.duration.unwrap_or(0) as u64;

    match record.phase.as_str() {
        "succeeded" => {
            let local_result_dir = make_local_result_dir(&record.product, &pkg_name, build_id)?;

            if !download {
                tracing::info!(
                    build_id,
                    "Build succeeded on server; artifacts not downloaded (use --download to fetch)"
                );
                return Ok(BuildResult::Succeeded(
                    srpm.to_path_buf(),
                    BuildOutputs {
                        build_id,
                        pkg_name: pkg_name.clone(),
                        rpms: vec![],
                        srpms: vec![],
                        logs: vec![],
                        result_dir: local_result_dir,
                        retries: 0,
                        signed: record.signed,
                    },
                    duration,
                ));
            }

            tokio::fs::create_dir_all(&local_result_dir)
                .await
                .map_err(|e| CrbsError::Io {
                    context: format!("create local result dir {}", local_result_dir.display()),
                    kind: e.kind(),
                    detail: e.to_string(),
                })?;
            let target = crate::remote::RemoteTarget::new(
                base_url.to_string(),
                token.clone(),
                ca_cert.clone(),
            );

            let (rpm_files, srpm_files) = {
                let mut attempt = 0u32;
                let max_attempts = 3u32;
                let base_delay = Duration::from_millis(500);
                loop {
                    let fetch = async {
                        let a =
                            crate::remote::list_artifacts(&target, build_id, cancel_token).await?;
                        crate::remote::download_artifacts(
                            &target,
                            build_id,
                            &a,
                            &local_result_dir,
                            cancel_token,
                        )
                        .await?;
                        Ok::<_, anyhow::Error>(a)
                    };
                    match fetch.await {
                        Ok(a) => break (a.rpms, a.srpms),
                        Err(e) => {
                            attempt += 1;
                            if attempt >= max_attempts {
                                warn!(
                                    build_id,
                                    error = %e,
                                    result_dir = %local_result_dir.display(),
                                    "artifact download failed after retries; build succeeded on server, retry with: crbs build --remote {} --attach {}",
                                    base_url, build_id,
                                );
                                break (Vec::new(), Vec::new());
                            }
                            let delay = base_delay.saturating_mul(1u32 << (attempt - 1));
                            tracing::debug!(
                                build_id, attempt, error = %e,
                                "artifact fetch failed; retrying"
                            );
                            tokio::time::sleep(delay).await;
                        }
                    }
                }
            };

            let outputs = BuildOutputs {
                build_id,
                pkg_name: pkg_name.clone(),
                rpms: rpm_files.iter().map(|r| local_result_dir.join(r)).collect(),
                srpms: srpm_files
                    .iter()
                    .map(|r| local_result_dir.join(r))
                    .collect(),
                logs: vec![],
                result_dir: local_result_dir,
                retries: 0,
                signed: record.signed,
            };
            Ok(BuildResult::Succeeded(
                srpm.to_path_buf(),
                outputs,
                duration,
            ))
        }
        "cancelled" => Ok(BuildResult::Failed(
            srpm.to_path_buf(),
            CrbsError::Cancelled,
            duration,
        )),
        "timeout" => Ok(BuildResult::Failed(
            srpm.to_path_buf(),
            CrbsError::Timeout,
            duration,
        )),

        _ => Ok(BuildResult::Failed(
            srpm.to_path_buf(),
            CrbsError::ContainerExecFailed {
                exit_code: None,
                signal: None,
                stderr: remote_failure_message(build_id, &record.phase, record.task_id),
            },
            duration,
        )),
    }
}
pub(crate) async fn fetch_build_record(
    client: &reqwest::Client,
    base_url: &str,
    id: i64,
) -> Result<crbs_core::BuildRecord> {
    let url = format!("{}/api/v1/builds/{}", base_url, id);
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| CrbsError::Network {
            message: format!("GET {url}: {e}"),
        })?;
    let status = resp.status();
    let body = read_body_capped(resp).await?;
    if !status.is_success() {
        let body = crate::remote::truncate_body_for_error(&body);

        return Err(crate::remote::http_status_error("fetch build record", status, &body).into());
    }
    serde_json::from_str(&body)
        .map_err(|e| CrbsError::Network {
            message: format!(
                "parse build record: {}: {e}",
                crate::remote::truncate_body_for_error(&body)
            ),
        })
        .map_err(Into::into)
}

async fn read_body_capped(resp: reqwest::Response) -> Result<String> {
    const MAX_BODY: usize = 1024 * 1024;
    let mut resp = resp;
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| CrbsError::Network {
        message: format!("read response body: {e}"),
    })? {
        if buf.len() + chunk.len() > MAX_BODY {
            return Err(CrbsError::Network {
                message: format!("response body exceeds {MAX_BODY} bytes"),
            }
            .into());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// 永久错误判定：401/403/404 终止轮询，否则空转到超时上限。
pub(crate) fn is_permanent_remote_error(e: &anyhow::Error) -> bool {
    e.downcast_ref::<CrbsError>().is_some_and(|ce| {
        matches!(
            ce,
            CrbsError::NotFound { .. } | CrbsError::PermissionDenied { .. }
        )
    })
}
pub(crate) async fn stream_remote_logs(
    client: &reqwest::Client,
    base_url: &str,
    build_id: i64,
    cancel_token: Option<&CancellationToken>,
) -> Result<()> {
    let url = format!("{}/api/v1/builds/{}/logs?offset=0", base_url, build_id);

    let mut attempts = 0;
    let resp = loop {
        if cancel_token.map(|t| t.is_cancelled()).unwrap_or(false) {
            return Ok(());
        }

        let resp = client
            .get(&url)
            .timeout(crate::remote::LONG_BODY_TIMEOUT)
            .send()
            .await
            .map_err(|e| CrbsError::Network {
                message: format!("GET {url}: {e}"),
            })?;
        if resp.status() != reqwest::StatusCode::NOT_FOUND || attempts >= 30 {
            break resp;
        }
        attempts += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    crate::remote::stream_response_to_stdout(resp, cancel_token).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crbs_core::exit_code::{crbs_error_exit_code, ENVIRONMENT};
    use wiremock::matchers::{method, path as wm_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn oversized_response_body_maps_to_network() {
        let server = MockServer::start().await;

        let huge = "A".repeat(1024 * 1024 + 1);
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/builds/7"))
            .respond_with(ResponseTemplate::new(200).set_body_string(huge))
            .mount(&server)
            .await;
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/api/v1/builds/7", server.uri()))
            .send()
            .await
            .expect("mock server reachable");

        let err = read_body_capped(resp).await.unwrap_err();
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::Network { .. }),
            "unexpected variant: {ce:?}"
        );
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
        assert!(
            format!("{ce}").contains("response body exceeds 1048576 bytes"),
            "msg must be preserved verbatim: {ce}"
        );
    }

    #[tokio::test]
    async fn body_within_cap_reads_through() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/builds/7"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"id":7,"phase":"running"}"#),
            )
            .mount(&server)
            .await;
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/api/v1/builds/7", server.uri()))
            .send()
            .await
            .expect("mock server reachable");

        let body = read_body_capped(resp).await.expect("within cap must pass");
        assert!(body.contains("\"phase\":\"running\""), "body: {body}");
    }

    #[tokio::test]
    async fn fetch_build_record_non_json_maps_to_network_sanitized() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/builds/7"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json \u{1b}[2J body"))
            .mount(&server)
            .await;
        let client = reqwest::Client::new();

        let err = fetch_build_record(&client, &server.uri(), 7)
            .await
            .expect_err("non-JSON 2xx body must fail parse");
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::Network { .. }),
            "unexpected variant: {ce:?}"
        );
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
        let msg = format!("{ce}");
        assert!(
            msg.contains("parse build record:"),
            "original context string must be preserved verbatim: {msg}"
        );
        assert!(
            msg.contains("expected ident at line 1 column"),
            "underlying serde error text must be inlined: {msg}"
        );
        assert!(
            !msg.contains('\u{1b}'),
            "terminal control sequence must be stripped from error text: {msg:?}"
        );
    }

    #[tokio::test]
    async fn fetch_build_record_transport_failure_maps_to_network() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        let base_url = format!("http://{addr}");
        let client = reqwest::Client::new();

        let err = fetch_build_record(&client, &base_url, 7)
            .await
            .expect_err("dropped listener must refuse connection");
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::Network { .. }),
            "unexpected variant: {ce:?}"
        );
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
        let msg = format!("{ce}");
        assert!(
            msg.contains(&format!("GET {base_url}/api/v1/builds/7")),
            "original context string (with URL) must be preserved: {msg}"
        );
    }

    #[tokio::test]
    async fn follow_remote_build_text_mode_short_circuits_on_permanent_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/builds/404"))
            .respond_with(ResponseTemplate::new(404).set_body_string("gone"))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let started = std::time::Instant::now();
        let err = follow_remote_build(FollowRemoteParams {
            client: &client,
            base_url: &server.uri(),
            build_id: 404,
            pkg_name: "gone",
            follow_logs: false,
            format: OutputFormat::Text,
            cancel_token: None,
            token: None,
            ca_cert: None,

            poll_timeout: Duration::from_secs(30),
        })
        .await
        .expect_err("404 must terminate text-mode polling");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "permanent error must short-circuit instead of spinning, took {:?}",
            started.elapsed()
        );
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::NotFound { .. }),
            "unexpected variant: {ce:?}"
        );
    }
}
