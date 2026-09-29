// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use nix::libc;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::Result;
use crbs_core::config::CrbsConfig;
use crbs_core::engine::BuildLifecycle;
use crbs_core::privilege::CallerContext;
use tracing::{info, warn};

use crate::cli::OutputFormat;
use crate::cmd::build::workers::{self, WorkerPoolParams};

use super::BuildArgs;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
/// 派生子进程执行的构建请求。敏感边界：`--token` 不落盘（凭据不依赖文件权限），经 CRBS_TOKEN env 转发子进程（仅父/子进程链可见）。
pub(crate) struct DetachedBuildRequest {
    pub build_ids: Vec<i64>,
    pub srpms: Vec<PathBuf>,
    pub product: String,
    pub backend: Option<String>,
    pub no_network: bool,
    pub memory_max: Option<String>,
    pub cpu_quota: Option<String>,
    pub jobs: Option<usize>,
    pub shared_layer: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmpfs: Option<bool>,
    pub ccache: bool,
    pub fail_fast: bool,
    pub timeout: Option<u64>,
    pub stage: Option<String>,
    pub define: Vec<String>,
    pub with_features: Vec<String>,
    pub without_features: Vec<String>,
    pub nocheck: bool,
    pub noclean: bool,
    pub nodebuginfo: bool,
    pub target: Option<String>,
    pub dist: Option<String>,
    pub retry: Option<u32>,
    pub no_reproduce: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_build_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_build_time: Option<i64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub offline: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl DetachedBuildRequest {
    pub fn from_args(args: &BuildArgs, build_ids: Vec<i64>, offline: bool) -> Self {
        let container = &args.container;
        Self {
            build_ids,
            srpms: args.input.srpm.clone(),
            product: args.input.product.clone().unwrap_or_default(),
            backend: container.backend.clone(),
            no_network: container.no_network,
            memory_max: container.memory_max.clone(),
            cpu_quota: container.cpu_quota.clone(),
            jobs: args.behavior.jobs,
            shared_layer: args.behavior.shared_layer,
            tmpfs: args.behavior.tmpfs.then_some(true),
            ccache: args.behavior.ccache,
            fail_fast: args.behavior.fail_fast,
            timeout: args.behavior.timeout,
            stage: args.behavior.stage.clone(),
            define: args.behavior.define.clone(),
            with_features: args.behavior.with_features.clone(),
            without_features: args.behavior.without_features.clone(),
            nocheck: args.behavior.nocheck,
            noclean: args.behavior.noclean,
            nodebuginfo: args.behavior.nodebuginfo,
            target: args.behavior.target.clone(),
            dist: args.behavior.dist.clone(),
            retry: args.behavior.retry,
            no_reproduce: args.reproduce.no_reproduce,

            replay_build_host: None,
            replay_build_time: None,
            remote: args.runtime.remote.clone(),
            ca_cert: args.runtime.ca_cert.clone(),
            offline,
        }
    }
}

/// 本地 detach 入口（父进程逻辑）：预创建 pending 记录、派生子进程并立即返回 build_id。pending 记录创建后任何一步失败都必须转终态并清理——无 crbs_pid
/// 的行被 zombie repair 刻意跳过，不收口即永久悬挂甚至被 daemon recover 复活重跑。
pub(crate) async fn submit_local_detach(
    args: BuildArgs,
    ctx: &CallerContext,
    global: crate::cli::GlobalArgs,
) -> Result<()> {
    if args.behavior.chain {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: "--detach is not yet supported with --chain".into(),
        }
        .into());
    }

    let product = args.input.product.clone().ok_or_else(|| {
        crbs_core::error::CrbsError::ValidationFailed {
            message: "--product is required".into(),
        }
    })?;
    let task_labels = super::parse_task_labels(&args.behavior.label)?;

    let inputs =
        super::resolve_srpm_inputs(args.input.srpm.clone(), args.input.list.clone()).await?;
    if inputs.is_empty() {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: "No SRPM files found".into(),
        }
        .into());
    }

    let replay_params = if args.reproduce.repro_from_srpm {
        let p = super::probe_uniform_replay_params(&inputs).await?;
        super::print_repro_from_srpm_hint(&p);
        Some(p)
    } else {
        None
    };

    let crbs_config = CrbsConfig::load_async().await?;

    let state =
        std::sync::Arc::new(crbs_core::StateStore::open_for_engine(&crbs_config.crbs_root).await?);

    let config_target = crate::remote::resolve_config_target(
        args.runtime.remote.clone(),
        args.runtime.token.clone(),
        args.runtime.ca_cert.clone(),
    )
    .await?;
    crate::api::product::log_config_source(&product, config_target.as_ref(), global.offline);

    let mut build_ids = Vec::with_capacity(inputs.len());
    let mut task_ids = Vec::with_capacity(inputs.len());
    let pkg_names = crate::cmd::build::remote::output::resolve_srpm_pkg_names(None, &inputs).await;
    for (srpm, pkg_name) in inputs.iter().zip(&pkg_names) {
        let identity = crbs_core::engine::BuildIdentity::new(&product, pkg_name);
        let context = crbs_core::engine::BuildContext::new(0)
            .with_user(&ctx.caller.username, None)
            .with_srpm_path(srpm.to_str())
            .with_task_labels(&task_labels);
        let lifecycle = BuildLifecycle::new_with_task(state.clone(), &identity, &context).await?;
        build_ids.push(lifecycle.build_id());
        task_ids.push(lifecycle.task_id());
    }

    let mut request = DetachedBuildRequest::from_args(&args, build_ids.clone(), global.offline);

    request.srpms = inputs.clone();
    if let Some((host, time)) = replay_params {
        request.replay_build_host = host;
        request.replay_build_time = time;
    }

    let request_path =
        std::env::temp_dir().join(format!("crbs-detach-{}.json", uuid::Uuid::new_v4()));
    let spawn_result: anyhow::Result<tokio::process::Child> = async {
        use tokio::io::AsyncWriteExt;
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&request_path)
            .await
            .map_err(|e| crbs_core::error::CrbsError::Io {
                context: format!("create detach request {}", request_path.display()),
                kind: e.kind(),
                detail: e.to_string(),
            })?;
        let request_json = serde_json::to_string_pretty(&request)?;
        f.write_all(request_json.as_bytes()).await.map_err(|e| {
            crbs_core::error::CrbsError::Io {
                context: format!("write detach request {}", request_path.display()),
                kind: e.kind(),
                detail: e.to_string(),
            }
        })?;
        f.sync_all()
            .await
            .map_err(|e| crbs_core::error::CrbsError::Io {
                context: format!("sync detach request {}", request_path.display()),
                kind: e.kind(),
                detail: e.to_string(),
            })?;

        info!(
            request_path = %request_path.display(),
            build_ids = ?build_ids,
            "Spawning detached build worker"
        );

        let exe = std::env::current_exe().map_err(|e| crbs_core::error::CrbsError::Io {
            context: "locate current crbs executable".to_string(),
            kind: e.kind(),
            detail: e.to_string(),
        })?;
        let mut cmd = tokio::process::Command::new(exe);
        cmd.arg("detached-run")
            .arg(&request_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .open(request_path.with_extension("log"))
                    .map_err(|e| crbs_core::error::CrbsError::Io {
                        context: format!("create detach worker log {}", request_path.display()),
                        kind: e.kind(),
                        detail: e.to_string(),
                    })?,
            ))
            .kill_on_drop(false);

        if let Some(ref t) = args.runtime.token {
            cmd.env("CRBS_TOKEN", t);
        }

        unsafe {
            cmd.pre_exec(|| {
                libc::signal(libc::SIGHUP, libc::SIG_IGN);
                libc::setsid();
                Ok(())
            });
        }

        cmd.spawn()
            .map_err(|e| crbs_core::error::CrbsError::Io {
                context: "spawn detached build worker".to_string(),
                kind: e.kind(),
                detail: e.to_string(),
            })
            .map_err(Into::into)
    }
    .await;

    let child = match spawn_result {
        Ok(c) => c,
        Err(e) => {
            mark_pending_failed(&state, &build_ids, "detach spawn failed").await;
            let _ = tokio::fs::remove_file(&request_path).await;
            let _ = tokio::fs::remove_file(request_path.with_extension("log")).await;
            return Err(e);
        }
    };
    let child_pid = child
        .id()
        .ok_or_else(|| crbs_core::error::CrbsError::NotFound {
            message: "detached worker pid not available".to_string(),
        })?;

    for id in &build_ids {
        if let Err(e) = state.update_build_crbs_pid(*id, i64::from(child_pid)).await {
            warn!(
                build_id = %id,
                error = %e,
                "Failed to update crbs_pid for detached build"
            );
        }
    }

    let _ = child;

    print_detach_output(
        &build_ids,
        &task_ids,
        &pkg_names,
        &product,
        args.output.format,
    )?;

    Ok(())
}

/// detach spawn 失败后把预创建 pending 记录统一转终态：无 crbs_pid 的行被 zombie repair 刻意跳过，不收口即永久悬挂或被 recover 复活；逐条
/// warn 尽力补偿，不遮蔽 spawn 错误。
async fn mark_pending_failed(
    state: &std::sync::Arc<crbs_core::StateStore>,
    build_ids: &[i64],
    reason: &str,
) {
    for id in build_ids {
        match state.complete_build(*id, "failed", None).await {
            Ok(0) => {}
            Ok(_) => warn!(build_id = %id, reason = %reason, "Marked pending detach build failed"),
            Err(e) => {
                warn!(build_id = %id, error = %e, reason = %reason, "Failed to mark pending detach build failed")
            }
        }
    }
}

fn detach_output(
    build_ids: &[i64],
    task_ids: &[i64],
    pkg_names: &[String],
    product: &str,
) -> super::output::DetachOutput {
    let first_task_id = task_ids.first().copied().unwrap_or_default();
    let builds: Vec<super::output::DetachBuildEntry> = build_ids
        .iter()
        .zip(task_ids.iter())
        .zip(pkg_names.iter())
        .map(|((id, task_id), pkg)| super::output::DetachBuildEntry {
            build_id: *id,
            task_id: *task_id,
            pkg_name: pkg.clone(),
        })
        .collect();
    super::output::DetachOutput {
        command: "build",
        mode: "detach",
        transport: "direct",
        product: product.to_string(),
        task_id: first_task_id,
        builds,
    }
}

fn print_detach_output(
    build_ids: &[i64],
    task_ids: &[i64],
    pkg_names: &[String],
    product: &str,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let out = detach_output(build_ids, task_ids, pkg_names, product);
            super::output::print_json(&out)?;
        }
        OutputFormat::Text => {
            print!("{}", render_detach_text(build_ids, task_ids, pkg_names));
        }
    }
    Ok(())
}

fn render_detach_text(build_ids: &[i64], task_ids: &[i64], pkg_names: &[String]) -> String {
    let mut out = String::from("Builds submitted:\n");
    out.push_str("  mode:       detach\n");
    out.push_str("  transport:  direct\n");
    out.push_str("  location:   local\n");
    out.push_str(&format!(
        "  task_id:    {}\n",
        task_ids.first().copied().unwrap_or_default()
    ));
    out.push_str("  builds:\n");
    for ((id, task_id), pkg) in build_ids.iter().zip(task_ids.iter()).zip(pkg_names.iter()) {
        out.push_str(&format!("    - build_id:  {}\n", id));
        out.push_str(&format!("      task_id:   {}\n", task_id));
        out.push_str(&format!("      pkg_name:  {}\n", pkg));
    }
    out.push('\n');
    if let Some(id) = build_ids.first() {
        out.push_str(&format!("Attach later: crbs build --attach {}\n", id));
    }
    out
}

/// detached-run 子命令入口（子进程）：读取父进程写入的请求文件执行构建。
pub(crate) async fn run_detached_build(request_path: &Path) -> Result<()> {
    let request_json = tokio::fs::read_to_string(request_path).await.map_err(|e| {
        crbs_core::error::CrbsError::Io {
            context: format!("read detach request {}", request_path.display()),
            kind: e.kind(),
            detail: e.to_string(),
        }
    })?;
    let _ = tokio::fs::remove_file(request_path).await;

    let request: DetachedBuildRequest = serde_json::from_str(&request_json).map_err(|e| {
        crbs_core::error::CrbsError::ValidationFailed {
            message: format!("parse detach request: {e}"),
        }
    })?;

    if request.srpms.len() != request.build_ids.len() {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: "detached request: srpms and build_ids length mismatch".into(),
        }
        .into());
    }

    info!(
        product = %request.product,
        count = request.srpms.len(),
        "Starting detached build worker"
    );

    let cli_limits = crbs_core::ResourceLimits {
        memory_max: request.memory_max,
        cpu_quota: request.cpu_quota,
    };
    let network = if request.no_network {
        Some(false)
    } else {
        None
    };

    let config_target =
        crate::remote::resolve_config_target(request.remote.clone(), None, request.ca_cert.clone())
            .await?;
    let (config, product_config_toml) = crate::api::product::load_product_config_with_snapshot(
        &request.product,
        config_target.as_ref(),
        request.offline,
    )
    .await?;

    let engine_builder = crbs_core::engine::BuildEngine::new_from_config(
        &request.product,
        request.backend.as_deref(),
        Some(cli_limits),
        network,
        config,
    )
    .await?;

    let jobs = request.jobs.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });

    let config_nocheck = engine_builder.config().nocheck;
    let config_noclean = engine_builder.config().noclean;
    let config_nodebuginfo = engine_builder.config().nodebuginfo;

    let opts = crbs_core::build_options::BuildOptions {
        shared_layer: request.shared_layer.then_some(true),
        tmpfs: request.tmpfs,
        ccache: request.ccache.then_some(true),
        timeout: request.timeout,
        nocheck: Some(request.nocheck || config_nocheck),
        noclean: Some(request.noclean || config_noclean),
        nodebuginfo: Some(request.nodebuginfo || config_nodebuginfo),
        target: request.target.clone(),
        dist: request.dist.clone(),
        define: request.define.clone(),
        with_features: request.with_features.clone(),
        without_features: request.without_features.clone(),
        retry: request.retry,
        no_reproduce: request.no_reproduce.then_some(true),
        repro_from_srpm: false,
        replay_build_host: request.replay_build_host.clone(),
        replay_build_time: request.replay_build_time,
        stage: request.stage.clone(),
        ..Default::default()
    };
    let engine = crbs_core::build_options::apply_options_to_engine(engine_builder, &opts)?
        .with_max_concurrent_builds(jobs);

    if let Some(toml) = product_config_toml.as_deref() {
        for build_id in &request.build_ids {
            if let Err(e) = engine
                .state_store()
                .set_build_product_config_toml(*build_id, toml)
                .await
            {
                warn!(
                    build_id = %build_id,
                    error = %e,
                    "Failed to persist detached build product config snapshot"
                );
            }
        }
    }

    let engine = std::sync::Arc::new(engine);
    let cancel_token = tokio_util::sync::CancellationToken::new();

    let cancel_for_signal = cancel_token.clone();
    tokio::spawn(async move {
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Failed to setup SIGTERM handler: {}", e);
                    return;
                }
            };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Detached worker received Ctrl+C, cancelling builds...");
            }
            _ = sigterm.recv() => {
                tracing::info!("Detached worker received SIGTERM, cancelling builds...");
            }
        }
        cancel_for_signal.cancel();
    });

    let state = engine.state_store().clone();
    let pid = std::process::id() as i64;
    let mut lifecycle_map = std::collections::HashMap::new();
    for (srpm, build_id) in request.srpms.iter().zip(request.build_ids.iter()) {
        match BuildLifecycle::attach(state.clone(), *build_id, pid).await {
            Ok(lifecycle) => {
                lifecycle_map.insert(srpm.clone(), Some(lifecycle));
            }
            Err(e) => {
                warn!(
                    build_id = %build_id,
                    error = %e,
                    "Failed to attach detached build lifecycle; child will create a new record"
                );
            }
        }
    }

    let srpms_with_targets = super::attach_targets_to_inputs(request.srpms).await?;
    let total = srpms_with_targets.len();
    let lifecycle_map = std::sync::Arc::new(tokio::sync::Mutex::new(lifecycle_map));

    let mut summary = match workers::run_build_workers_with_lifecycle_map(WorkerPoolParams {
        engine: &engine,
        srpms: srpms_with_targets,
        total,
        jobs,
        cancel_token: &cancel_token,
        fail_fast: request.fail_fast,
        format: OutputFormat::Text,
        lifecycle_map: Some(lifecycle_map),
    })
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "Detached build workers failed");
            return Err(e);
        }
    };

    for (_, outputs, _) in &mut summary.succeeded {
        crbs_core::sign::sign_build_outputs(outputs, engine.config()).await;
        if outputs.signed {
            crbs_core::sign::mark_build_signed_best_effort(engine.state_store(), outputs.build_id)
                .await;
        }
    }

    if let Some(err) = detached_failure_silent_exit(&summary) {
        return Err(err.into());
    }

    Ok(())
}

fn detached_failure_silent_exit(
    summary: &super::BuildSummary,
) -> Option<crbs_core::error::CrbsError> {
    super::batch_failure_exit(summary).map(|representative| {
        crbs_core::error::CrbsError::SilentExit {
            code: crbs_core::exit_code::crbs_error_exit_code(&representative),
        }
    })
}

pub(crate) async fn cleanup_stale_detach_requests(max_age: Duration) -> Result<(usize, usize)> {
    let tmp = std::env::temp_dir();
    let mut entries = match tokio::fs::read_dir(&tmp).await {
        Ok(e) => e,
        Err(e) => {
            warn!(path = %tmp.display(), error = %e, "Failed to read temp dir for detach cleanup");
            return Ok((0, 0));
        }
    };

    let mut removed = 0usize;
    let mut skipped = 0usize;
    let now = std::time::SystemTime::now();

    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(n) => n,
            None => continue,
        };

        let is_json = name.starts_with("crbs-detach-") && name.ends_with(".json");
        let is_log = name.starts_with("crbs-detach-") && name.ends_with(".log");
        if !is_json && !is_log {
            continue;
        }

        let path = entry.path();
        let meta = match tokio::fs::metadata(&path).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to stat detach request file");
                skipped += 1;
                continue;
            }
        };

        let modified = match meta.modified() {
            Ok(t) => t,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };

        match now.duration_since(modified) {
            Ok(age) if age > max_age => match tokio::fs::remove_file(&path).await {
                Ok(()) => {
                    info!(path = %path.display(), age_secs = %age.as_secs(), "Removed stale detach request file");
                    removed += 1;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,

                Err(_) => {
                    skipped += 1;
                }
            },
            _ => skipped += 1,
        }
    }

    Ok((removed, skipped))
}

#[cfg(test)]
mod tests {
    use super::{detach_output, render_detach_text};
    use crate::cmd::build::output::assert_detach_envelope;

    use super::{run_detached_build, submit_local_detach, BuildArgs, DetachedBuildRequest};
    use crate::cli::{Cli, GlobalArgs};
    use clap::Parser as _;
    use crbs_core::exit_code::crbs_error_exit_code;
    use crbs_core::privilege::CallerContext;

    fn detach_args(argv: &[&str]) -> BuildArgs {
        let mut full: Vec<&str> = vec!["crbs", "build"];
        full.extend_from_slice(argv);
        match Cli::try_parse_from(full).expect("valid detach argv") {
            Cli::Build(args) => args,
            other => panic!(
                "expected Cli::Build variant, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    fn tester_ctx() -> CallerContext {
        CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: "tester".to_string(),
            },
            false,
        )
    }

    fn assert_validation_failed_exit_4(err: anyhow::Error) {
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::ValidationFailed { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_error_exit_code(ce), 4);
    }

    #[tokio::test]
    async fn detach_with_chain_is_validation_failed_exit_4() {
        let args = detach_args(&["-p", "cc9", "--chain", "--detach", "x.src.rpm"]);
        let err = submit_local_detach(args, &tester_ctx(), GlobalArgs::default())
            .await
            .expect_err("--detach with --chain must be rejected");
        assert_validation_failed_exit_4(err);
    }

    #[tokio::test]
    async fn detach_without_srpm_inputs_is_validation_failed_exit_4() {
        let args = detach_args(&["-p", "cc9", "--detach"]);
        let err = submit_local_detach(args, &tester_ctx(), GlobalArgs::default())
            .await
            .expect_err("empty inputs must be rejected");
        assert_validation_failed_exit_4(err);
    }

    #[tokio::test]
    async fn detached_run_length_mismatch_is_validation_failed_exit_4() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("request.json");
        let mut request = DetachedBuildRequest::from_args(
            &detach_args(&["-p", "cc9", "--detach"]),
            vec![1, 2],
            false,
        );

        request.srpms = vec![std::path::PathBuf::from("hello-1.0-1.src.rpm")];
        std::fs::write(&path, serde_json::to_string(&request).unwrap()).unwrap();

        let err = run_detached_build(&path)
            .await
            .expect_err("length mismatch must be rejected");
        assert_validation_failed_exit_4(err);
    }

    #[test]
    fn detach_request_tmpfs_tri_state_roundtrip() {
        let plain = DetachedBuildRequest::from_args(
            &detach_args(&["-p", "cc9", "--detach"]),
            vec![1],
            false,
        );
        assert_eq!(plain.tmpfs, None);
        let plain_json = serde_json::to_string(&plain).unwrap();
        assert!(
            !plain_json.contains("tmpfs"),
            "None must omit field: {plain_json}"
        );
        let back: DetachedBuildRequest = serde_json::from_str(&plain_json).unwrap();
        assert_eq!(back.tmpfs, None);

        let explicit = DetachedBuildRequest::from_args(
            &detach_args(&["-p", "cc9", "--detach", "--tmpfs"]),
            vec![1],
            false,
        );
        assert_eq!(explicit.tmpfs, Some(true));
        let explicit_json = serde_json::to_string(&explicit).unwrap();
        let back: DetachedBuildRequest = serde_json::from_str(&explicit_json).unwrap();
        assert_eq!(back.tmpfs, Some(true));

        let legacy_json = explicit_json.replace("\"tmpfs\":true", "\"tmpfs\":false");
        let back: DetachedBuildRequest = serde_json::from_str(&legacy_json).unwrap();
        assert_eq!(back.tmpfs, Some(false));
    }

    #[tokio::test]
    async fn detached_run_garbage_request_is_validation_failed_exit_4() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("request.json");
        std::fs::write(&path, "this is not json").unwrap();

        let err = run_detached_build(&path)
            .await
            .expect_err("garbage request file must fail parse");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::ValidationFailed { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_error_exit_code(ce), 4);
        let msg = format!("{ce}");
        assert!(
            msg.contains("parse detach request:"),
            "original context string must be preserved verbatim: {msg}"
        );

        assert!(!path.exists(), "request file must be removed after read");
    }

    #[test]
    fn detached_failure_silent_exit_maps_failed_bucket_to_build_failed() {
        let summary = crate::cmd::build::BuildSummary {
            succeeded: vec![],
            failed: vec![(
                std::path::PathBuf::from("f-1.0-1.src.rpm"),
                crbs_core::error::CrbsError::DepsolveFailed {
                    message: "x".into(),
                },
                0,
            )],
            cancelled: vec![],
            timeout: vec![],
        };
        let err = super::detached_failure_silent_exit(&summary)
            .expect("failed bucket must produce SilentExit");
        match err {
            crbs_core::error::CrbsError::SilentExit { code } => {
                assert_eq!(code, crbs_core::exit_code::BUILD_FAILED);
            }
            other => panic!("expected SilentExit, got {other:?}"),
        }

        let all_clear = crate::cmd::build::BuildSummary {
            succeeded: vec![],
            failed: vec![],
            cancelled: vec![],
            timeout: vec![],
        };
        assert!(
            super::detached_failure_silent_exit(&all_clear).is_none(),
            "all-clear summary must exit 0"
        );
    }

    #[test]
    fn detach_output_direct_envelope_schema() {
        let out = detach_output(
            &[11, 12],
            &[7, 8],
            &["hello".to_string(), "world".to_string()],
            "fedora",
        );
        let value = serde_json::to_value(&out).expect("serialize detach output");
        assert_detach_envelope(&value, "direct");
        assert_eq!(value["task_id"], 7);
        let builds = value["builds"].as_array().expect("builds array");
        assert_eq!(builds.len(), 2);
        assert_eq!(builds[0]["build_id"], 11);
        assert_eq!(builds[0]["task_id"], 7);
        assert_eq!(builds[0]["pkg_name"], "hello");
        assert_eq!(builds[1]["build_id"], 12);
        assert_eq!(builds[1]["task_id"], 8);
    }

    #[test]
    fn render_detach_text_has_top_level_task_id_line() {
        let text = render_detach_text(
            &[11, 12],
            &[7, 8],
            &["hello".to_string(), "world".to_string()],
        );
        let expected_prefix = "\
Builds submitted:
  mode:       detach
  transport:  direct
  location:   local
  task_id:    7
  builds:
";
        assert!(
            text.starts_with(expected_prefix),
            "missing top-level task_id line; got:\n{text}"
        );
        assert!(
            text.contains("    - build_id:  11\n      task_id:   7"),
            "{text}"
        );
        assert!(
            text.contains("    - build_id:  12\n      task_id:   8"),
            "{text}"
        );
    }
}
