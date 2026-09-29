// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::path::PathBuf;

use anyhow::{Context, Result};
use crbs_core::error::CrbsError;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::cmd::build::BuildArgs;
use crate::cmd::build::FollowAbandoned;

use super::follow::follow_remote_builds;
use super::output::print_detach_results;
use super::warn_req_min_unconfirmed;
use super::BuildResponse;
use super::{is_cancelled_result, request_remote_cancel};

/// 远端响应守护（submit/rebuild/reproduce 三入口共享）：HTTP 2xx 已达但内容不满足配对前提，属环境域 → Network(6) 不落 INTERNAL(1)。
/// server 少回 ids 时 zip+cycle 会静默丢掉部分构建（无人 follow、无人取消）；inputs 为空时取模除零，先单独拒绝。
fn ensure_build_ids_returned(ids: &[i64]) -> Result<()> {
    if ids.is_empty() {
        return Err(CrbsError::Network {
            message: "Server did not return any build ids".into(),
        }
        .into());
    }
    Ok(())
}

fn ensure_pairable_counts(build_ids: usize, inputs: usize) -> Result<()> {
    if inputs == 0 {
        return Err(CrbsError::Network {
            message: "Task record has no package names; cannot pair build ids".into(),
        }
        .into());
    }
    if build_ids % inputs != 0 {
        return Err(CrbsError::Network {
            message: format!(
                "Server returned {} build ids for {} SRPMs (not a multiple)",
                build_ids, inputs
            ),
        }
        .into());
    }
    Ok(())
}

fn print_skipped_arches_warning(skipped_arches: &[String]) {
    for entry in skipped_arches {
        eprintln!("Warning: skipped {entry}");
    }
}

#[derive(Clone, Copy)]
enum ResubmitKind {
    Rebuild,
    Reproduce,
}

impl ResubmitKind {
    fn flag(self) -> &'static str {
        match self {
            ResubmitKind::Rebuild => "--rebuild",
            ResubmitKind::Reproduce => "--reproduce",
        }
    }

    fn verb(self) -> &'static str {
        match self {
            ResubmitKind::Rebuild => "rebuilt",
            ResubmitKind::Reproduce => "reproduced",
        }
    }
}

pub(crate) async fn submit_rebuild(
    target: &crate::remote::RemoteTarget,
    task_id: &str,
    args: &BuildArgs,
    cancel_token: Option<&CancellationToken>,
) -> Result<()> {
    submit_resubmit(ResubmitKind::Rebuild, target, task_id, args, cancel_token).await
}

pub(crate) async fn submit_reproduce(
    target: &crate::remote::RemoteTarget,
    task_id: &str,
    args: &BuildArgs,
    cancel_token: Option<&CancellationToken>,
) -> Result<()> {
    submit_resubmit(ResubmitKind::Reproduce, target, task_id, args, cancel_token).await
}

async fn submit_resubmit(
    kind: ResubmitKind,
    target: &crate::remote::RemoteTarget,
    task_id: &str,
    args: &BuildArgs,
    cancel_token: Option<&CancellationToken>,
) -> Result<()> {
    let id: i64 = task_id.parse().map_err(|e| CrbsError::ValidationFailed {
        message: format!("invalid task id for {}: {task_id}: {e}", kind.flag()),
    })?;
    let client = target.client().await?;
    let base_url = crate::remote::normalize_base_url(&target.url)?;

    let response = match kind {
        ResubmitKind::Rebuild => crate::remote::rebuild_task(target, id, cancel_token).await?,
        ResubmitKind::Reproduce => crate::remote::reproduce_task(target, id, cancel_token).await?,
    };
    ensure_build_ids_returned(&response.ids)?;
    print_skipped_arches_warning(&response.skipped_arches);

    let detail = crate::remote::fetch_task_record(target, response.task_id, cancel_token).await?;
    let product = detail.task.product.clone();
    let inputs: Vec<PathBuf> = detail
        .task
        .pkg_names
        .iter()
        .map(|n| PathBuf::from(format!("{}.src.rpm", n)))
        .collect();

    info!(
        from_task_id = id,
        task_id = response.task_id,
        count = response.ids.len(),
        "Task {}",
        kind.verb()
    );

    if args.runtime.detach {
        return print_detach_results(
            &base_url,
            response.task_id,
            &response.ids,
            &product,
            &inputs,
            response.pkg_name.as_deref(),
            args.output.format,
        )
        .await;
    }

    ensure_pairable_counts(response.ids.len(), inputs.len())?;
    let pairs: Vec<(i64, PathBuf)> = response
        .ids
        .iter()
        .copied()
        .zip(inputs.iter().cycle().cloned())
        .collect();
    let result = follow_remote_builds(
        client,
        &base_url,
        pairs,
        args,
        cancel_token,
        target.token.clone(),
        target.ca_cert.clone(),
    )
    .await;
    if is_cancelled_result(&result) {
        for id in &response.ids {
            request_remote_cancel(client, &base_url, *id).await;
        }
    }
    follow_abandoned_to_silent_exit(result)
}

/// 常规远程提交：参数预检 → 组装请求 → 提交 → detach 或 zip cycle 配对跟随。回显契约先于解构：响应缺 req_min_* 键 → serde default 落
/// None → 告警。
pub(crate) async fn submit_build(
    server_url: &str,
    token: Option<String>,
    ca_cert: Option<PathBuf>,
    args: BuildArgs,
    wait: bool,
    cancel_token: Option<&CancellationToken>,
) -> Result<()> {
    let inputs =
        crate::cmd::build::resolve_srpm_inputs(args.input.srpm.clone(), args.input.list.clone())
            .await
            .context("resolve SRPM inputs")?;
    if inputs.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: "No SRPM inputs".into(),
        }
        .into());
    }
    for srpm_path in &inputs {
        let metadata = tokio::fs::metadata(srpm_path).await.map_err(|e| {
            let message = format!("SRPM not found: {}", srpm_path.display());
            if e.kind() == std::io::ErrorKind::NotFound {
                CrbsError::NotFound { message }
            } else {
                CrbsError::Io {
                    context: message,
                    kind: e.kind(),
                    detail: e.to_string(),
                }
            }
        })?;
        if !metadata.is_file() {
            return Err(CrbsError::NotFound {
                message: format!("SRPM not found: {}", srpm_path.display()),
            }
            .into());
        }
    }

    let product = args
        .input
        .product
        .clone()
        .ok_or_else(|| CrbsError::ValidationFailed {
            message: "--product is required for remote build".to_string(),
        })?;
    let task_labels = crate::cmd::build::parse_task_labels(&args.behavior.label)?;

    let base_url = crate::remote::normalize_base_url(server_url)?;
    let target = crate::remote::RemoteTarget::new(base_url.clone(), token.clone(), ca_cert.clone());
    let client = target.client().await?;

    info!(
        server = %base_url,
        product = %product,
        count = inputs.len(),
        "Submitting remote builds"
    );

    let response = upload_srpm_batch(
        client,
        &base_url,
        &args,
        &inputs,
        &task_labels,
        cancel_token,
    )
    .await?;

    warn_req_min_unconfirmed(&args.behavior, &response);
    let build_ids = response.ids;
    ensure_build_ids_returned(&build_ids)?;
    print_skipped_arches_warning(&response.skipped_arches);
    if wait && !args.runtime.detach {
        ensure_pairable_counts(build_ids.len(), inputs.len())?;
    }
    info!(count = build_ids.len(), "Remote builds accepted");

    if !wait || args.runtime.detach {
        return print_detach_results(
            &base_url,
            response.task_id,
            &build_ids,
            &product,
            &inputs,
            response.pkg_name.as_deref(),
            args.output.format,
        )
        .await;
    }

    let pairs: Vec<(i64, PathBuf)> = build_ids
        .iter()
        .copied()
        .zip(inputs.iter().cycle().cloned())
        .collect();
    let result = follow_remote_builds(
        client,
        &base_url,
        pairs,
        &args,
        cancel_token,
        token,
        ca_cert,
    )
    .await;
    if is_cancelled_result(&result) {
        for id in &build_ids {
            request_remote_cancel(client, &base_url, *id).await;
        }
    }
    follow_abandoned_to_silent_exit(result)
}

fn follow_abandoned_to_silent_exit(result: Result<()>) -> Result<()> {
    match result {
        Err(e) if e.downcast_ref::<FollowAbandoned>().is_some() => Err(CrbsError::SilentExit {
            code: crbs_core::exit_code::INTERRUPTED,
        }
        .into()),
        other => other,
    }
}
async fn upload_srpm_batch(
    client: &reqwest::Client,
    base_url: &str,
    args: &BuildArgs,
    inputs: &[PathBuf],
    task_labels: &[(String, String)],
    cancel_token: Option<&CancellationToken>,
) -> Result<BuildResponse> {
    let product = args
        .input
        .product
        .clone()
        .ok_or_else(|| CrbsError::ValidationFailed {
            message: "--product is required for remote build".to_string(),
        })?;
    let mut form = reqwest::multipart::Form::new().text("product", product);

    for srpm_path in inputs {
        let file_name = srpm_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("package.src.rpm")
            .to_string();

        let file = tokio::fs::File::open(srpm_path)
            .await
            .map_err(|e| CrbsError::Io {
                context: format!("open SRPM {}", srpm_path.display()),
                kind: e.kind(),
                detail: e.to_string(),
            })?;
        let file_len = file
            .metadata()
            .await
            .map_err(|e| CrbsError::Io {
                context: format!("metadata of SRPM {}", srpm_path.display()),
                kind: e.kind(),
                detail: e.to_string(),
            })?
            .len();
        let part = reqwest::multipart::Part::stream_with_length(file, file_len)
            .file_name(file_name)
            .mime_str("application/x-rpm")
            .context("set srpm mime type")?;
        form = form.part("srpm", part);
    }

    fn add_opt<T: std::fmt::Display>(
        form: reqwest::multipart::Form,
        name: &str,
        value: Option<T>,
    ) -> reqwest::multipart::Form {
        match value {
            Some(v) => form.text(name.to_string(), v.to_string()),
            None => form,
        }
    }
    form = add_opt(form, "stage", args.behavior.stage.clone());
    form = add_opt(form, "backend", args.container.backend.clone());
    form = add_opt(form, "target", args.behavior.target.clone());
    form = add_opt(form, "dist", args.behavior.dist.clone());
    form = add_opt(form, "timeout", args.behavior.timeout);
    form = add_opt(form, "memory_max", args.container.memory_max.clone());
    form = add_opt(form, "cpu_quota", args.container.cpu_quota.clone());
    form = add_opt(form, "retry", args.behavior.retry);
    form = add_opt(
        form,
        "shared_layer",
        args.behavior.shared_layer.then_some(true),
    );
    form = add_opt(form, "tmpfs", args.behavior.tmpfs.then_some(true));
    form = add_opt(form, "ccache", args.behavior.ccache.then_some(true));
    form = add_opt(form, "nocheck", args.behavior.nocheck.then_some(true));
    form = add_opt(form, "noclean", args.behavior.noclean.then_some(true));
    form = add_opt(
        form,
        "nodebuginfo",
        args.behavior.nodebuginfo.then_some(true),
    );
    form = add_opt(
        form,
        "no_network",
        args.container.no_network.then_some(true),
    );
    form = add_opt(form, "no_publish", args.behavior.no_publish.then_some(true));
    form = add_opt(form, "no_consume", args.behavior.no_consume.then_some(true));
    form = add_opt(
        form,
        "no_reproduce",
        args.reproduce.no_reproduce.then_some(true),
    );
    form = add_opt(
        form,
        "repro_from_srpm",
        args.reproduce.repro_from_srpm.then_some(true),
    );
    form = add_opt(form, "priority", Some(args.behavior.priority));

    form = add_opt(form, "min_mem", args.behavior.min_mem.clone());
    form = add_opt(form, "min_disk", args.behavior.min_disk.clone());
    form = add_opt(form, "min_ncpu", args.behavior.min_ncpu);
    form = add_opt(
        form,
        "skip_unsupported_arches",
        args.behavior.skip_unsupported_arches.then_some(true),
    );
    for (key, value) in task_labels {
        form = form.text("label", format!("{key}={value}"));
    }
    for arch in &args.behavior.arch {
        form = form.text("arch", arch.clone());
    }
    for d in &args.behavior.define {
        form = form.text("define", d.clone());
    }
    for f in &args.behavior.with_features {
        form = form.text("with_features", f.clone());
    }
    for f in &args.behavior.without_features {
        form = form.text("without_features", f.clone());
    }

    let url = format!("{}/api/v1/builds", base_url);

    let resp = tokio::select! {
        _ = crbs_core::http_retry::wait_for_cancel(cancel_token) => {
            return Err(CrbsError::Cancelled.into());
        }
        result = client
            .post(&url)
            .multipart(form)

            .timeout(crate::remote::DOWNLOAD_TIMEOUT)
            .send() => {

            result.map_err(|e| {
                CrbsError::Network {
                    message: format!("POST {url}: {e}"),
                }
            })?
        }
    };

    let status = resp.status();
    if !status.is_success() {
        if matches!(status.as_u16(), 401 | 403) {
            return Err(CrbsError::PermissionDenied {
                message: format!(
                    "unauthorized ({}) — the server rejected the request before the upload \
                     finished. this is almost always an expired or unregistered token, not a \
                     network problem. check `crbs-server token list <user>` on the hub or pass \
                     --token explicitly. (any 'IncompleteMessage' / 'Connection reset' above is \
                     a side effect of the server closing the connection mid-upload, not the \
                     root cause.)",
                    status
                ),
            }
            .into());
        }

        let body = resp.text().await.map_err(|e| CrbsError::Network {
            message: format!("read response body: {e}"),
        })?;
        return Err(crate::remote::http_status_error("submit build", status, &body).into());
    }
    let body = resp.text().await.map_err(|e| CrbsError::Network {
        message: format!("read response body: {e}"),
    })?;

    serde_json::from_str(&body)
        .map_err(|e| CrbsError::Network {
            message: format!(
                "parse build response: {}: {e}",
                crate::remote::truncate_body_for_error(&body)
            ),
        })
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crbs_core::exit_code::{crbs_error_exit_code, ENVIRONMENT};

    #[test]
    fn follow_abandoned_to_silent_exit_maps_interrupted_and_passes_through() {
        let err = follow_abandoned_to_silent_exit(Err(FollowAbandoned.into()))
            .expect_err("marker must convert");
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::SilentExit { code } if *code == crbs_core::exit_code::INTERRUPTED),
            "unexpected variant: {ce:?}"
        );

        let err = follow_abandoned_to_silent_exit(Err(CrbsError::ValidationFailed {
            message: "x".into(),
        }
        .into()))
        .expect_err("must err");
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::ValidationFailed { .. }),
            "non-marker must pass through: {ce:?}"
        );
        assert_eq!(crbs_error_exit_code(ce), crbs_core::exit_code::USAGE);
    }

    #[test]
    fn empty_build_ids_response_maps_to_network() {
        let err = ensure_build_ids_returned(&[]).unwrap_err();
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::Network { .. }),
            "unexpected variant: {ce:?}"
        );
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
        assert!(
            format!("{ce}").contains("Server did not return any build ids"),
            "msg must be preserved verbatim: {ce}"
        );
        assert!(ensure_build_ids_returned(&[1, 2]).is_ok());
    }

    #[test]
    fn non_pairable_counts_map_to_network_with_verbatim_message() {
        let err = ensure_pairable_counts(3, 0).unwrap_err();
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::Network { .. }),
            "unexpected variant: {ce:?}"
        );
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
        assert!(
            format!("{ce}").contains("Task record has no package names; cannot pair build ids"),
            "msg must be preserved verbatim: {ce}"
        );

        let err = ensure_pairable_counts(3, 2).unwrap_err();
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(matches!(ce, CrbsError::Network { .. }));
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
        assert!(
            format!("{ce}").contains("Server returned 3 build ids for 2 SRPMs (not a multiple)"),
            "msg must be preserved verbatim: {ce}"
        );

        assert!(ensure_pairable_counts(4, 2).is_ok());
        assert!(ensure_pairable_counts(2, 1).is_ok());
    }

    fn build_args(argv: &[&str]) -> BuildArgs {
        use crate::cli::Cli;
        use clap::Parser as _;
        let mut full: Vec<&str> = vec!["crbs", "build"];
        full.extend(argv);
        match Cli::try_parse_from(full).expect("valid build argv") {
            Cli::Build(args) => args,
            other => panic!(
                "expected Cli::Build variant, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[tokio::test]
    async fn upload_srpm_batch_non_json_response_maps_to_network_sanitized() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(wm_path("/api/v1/builds"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json \u{1b}[2J at all"))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let srpm = tmp.path().join("hello-1.0-1.src.rpm");
        std::fs::write(&srpm, b"rpm-ish bytes").unwrap();
        let args = build_args(&["-p", "cc9", srpm.to_str().unwrap()]);

        let err = upload_srpm_batch(
            &reqwest::Client::new(),
            &server.uri(),
            &args,
            &[srpm],
            &[],
            None,
        )
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
            msg.contains("parse build response:"),
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
    async fn upload_srpm_batch_missing_srpm_maps_to_io_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing-1.0-1.src.rpm");
        let args = build_args(&["-p", "cc9"]);

        let err = upload_srpm_batch(
            &reqwest::Client::new(),
            "http://127.0.0.1:1",
            &args,
            std::slice::from_ref(&missing),
            &[],
            None,
        )
        .await
        .expect_err("missing SRPM file must fail open");
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        match ce {
            CrbsError::Io {
                context,
                kind: std::io::ErrorKind::NotFound,
                ..
            } => {
                assert!(
                    context.contains(&format!("open SRPM {}", missing.display())),
                    "original context string must be preserved verbatim: {context}"
                );
            }
            other => panic!("expected Io/NotFound, got {other:?}"),
        }
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
    }
}
