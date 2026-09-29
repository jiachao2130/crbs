// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 本地 `--attach`：接入一个已有的本地 detached 构建。

use crate::cli::OutputFormat;
use crate::cmd::build::follow;
use crbs_core::config::CrbsConfig;
use crbs_core::error::CrbsError;
use crbs_core::privilege::CallerContext;
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::info;

const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// 本地 attach 入口。
pub(crate) async fn attach_local_build(
    task: &str,
    follow_logs: bool,
    format: OutputFormat,
    ctx: &CallerContext,
    cancel_token: Option<&CancellationToken>,
) -> anyhow::Result<()> {
    let crbs_config = CrbsConfig::load_async().await?;
    // marker 护栏，见 StateStore::open_for_engine。
    let state =
        std::sync::Arc::new(crbs_core::StateStore::open_for_engine(&crbs_config.crbs_root).await?);

    let user_filter = crate::cmd::visible_user_filter(ctx);

    let task_id = crate::cmd::resolve_short_id(task, &state, user_filter).await?;

    let record = state
        .get_build(task_id)
        .await?
        // attach 的 ID 是 build id（见任务详情 child builds）；未找到 → NotFound（USAGE=4）。
        .ok_or_else(|| CrbsError::NotFound {
            message: format!("Build task {task_id} not found. Run 'crbs status' to list builds."),
        })?;

    crate::cmd::ensure_record_owner("build", task_id, &record.user, ctx)?;

    info!(build_id = %task_id, "Attaching to local build");

    if cancel_token.map(|t| t.is_cancelled()).unwrap_or(false) {
        return Err(CrbsError::Cancelled.into());
    }

    if format == OutputFormat::Json {
        let record = wait_for_terminal(&state, task_id, follow_logs, cancel_token).await?;
        // 成功信封与错误信封同源（command = "build"）；信封层资源命名：build_id、duration_seconds。
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "command": "build",
                "build_id": record.id,
                "product": record.product,
                "pkg_name": record.pkg_name,
                "user": record.user,
                "phase": record.phase,
                "backend": record.backend.as_deref().unwrap_or("chroot"),
                "result_dir": record.result_dir,
                "started_at": record.started_at,
                "completed_at": record.completed_at,
                "duration_seconds": record.duration,
                "layer_digest": record.layer_digest,
                "base_os_digest": record.base_os_digest,
            }))?
        );
        return exit_with_outcome(&record.phase);
    }

    let mut last_phase = record.phase.clone();
    println!(
        "Attaching to build {} ({} / {}) - phase: {}",
        task_id, record.product, record.pkg_name, record.phase
    );

    if follow_logs {
        let log_path = wait_for_log_path(&state, task_id, cancel_token).await?;
        if let Some(path) = log_path {
            crate::cmd::logs::follow_log(&path, &state, task_id, 0, &[], cancel_token).await?;
        }
        let final_record = get_final_record(&state, task_id, cancel_token).await?;
        print_terminal_line(&final_record);
        return exit_with_outcome(&final_record.phase);
    }

    loop {
        if cancel_token.map(|t| t.is_cancelled()).unwrap_or(false) {
            return Err(CrbsError::Cancelled.into());
        }
        let record = state
            .get_build(task_id)
            .await?
            // 记录中途消失属"未找到"语义——NotFound（USAGE=4）。
            .ok_or_else(|| CrbsError::NotFound {
                message: format!("Build task {task_id} disappeared"),
            })?;

        if record.phase != last_phase {
            println!(
                "Build {} phase: {} -> {}",
                task_id, last_phase, record.phase
            );
            last_phase = record.phase.clone();
        }

        if crbs_core::types::build_phase_is_terminal(&record.phase) {
            print_terminal_line(&record);
            return exit_with_outcome(&record.phase);
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn exit_with_outcome(phase: &str) -> anyhow::Result<()> {
    let code = match phase {
        "succeeded" => return Ok(()),
        // 对齐 crbs_error_exit_code：timeout/cancelled 均映射 INTERRUPTED（超时可重试、取消不重试）。
        "cancelled" | "timeout" => crbs_core::exit_code::INTERRUPTED,
        _ => crbs_core::exit_code::BUILD_FAILED,
    };
    Err(CrbsError::SilentExit { code }.into())
}

fn print_terminal_line(record: &crbs_core::BuildRecord) {
    // 秒数经 format_seconds 人性化（3661s → 61m1s，同 status detail）；单位已含，勿再补 "s"（防 "12ss"/"-s"）。
    let duration_str = record
        .duration
        .map(crate::cmd::status::format_seconds)
        .unwrap_or_else(|| "-".to_string());
    println!(
        "Build {} {} / {} finished: {} ({})",
        record.id, record.product, record.pkg_name, record.phase, duration_str
    );
    if let Some(ref dir) = record.result_dir {
        println!("  result_dir: {}", dir);
    }
}

async fn wait_for_terminal(
    state: &crbs_core::StateStore,
    task_id: i64,
    follow_logs: bool,
    cancel_token: Option<&CancellationToken>,
) -> anyhow::Result<crbs_core::BuildRecord> {
    if follow_logs {
        let log_path = wait_for_log_path(state, task_id, cancel_token).await?;
        if let Some(path) = log_path {
            crate::cmd::logs::follow_log(&path, state, task_id, 0, &[], cancel_token).await?;
        }
    }
    get_final_record(state, task_id, cancel_token).await
}

async fn wait_for_log_path(
    state: &crbs_core::StateStore,
    task_id: i64,
    cancel_token: Option<&CancellationToken>,
) -> anyhow::Result<Option<PathBuf>> {
    loop {
        if cancel_token.map(|t| t.is_cancelled()).unwrap_or(false) {
            return Err(CrbsError::Cancelled.into());
        }
        let record = state
            .get_build(task_id)
            .await?
            // 记录中途消失属"未找到"语义——NotFound（USAGE=4）。
            .ok_or_else(|| CrbsError::NotFound {
                message: format!("Build task {task_id} disappeared"),
            })?;

        if let Some(dir) = record.result_dir {
            let log_path = std::path::Path::new(&dir).join("build.log");
            if tokio::fs::try_exists(&log_path).await.unwrap_or(false) {
                return Ok(Some(log_path));
            }
        }

        if crbs_core::types::build_phase_is_terminal(&record.phase) {
            return Ok(None);
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn get_final_record(
    state: &crbs_core::StateStore,
    task_id: i64,
    cancel_token: Option<&CancellationToken>,
) -> anyhow::Result<crbs_core::BuildRecord> {
    let state = state.clone();
    let task_id_for_poll = task_id.to_string();
    follow::poll_until_terminal(
        &task_id_for_poll,
        OutputFormat::Json,
        POLL_INTERVAL,
        None,
        cancel_token,
        move || {
            let state = state.clone();
            let task_id = task_id;
            async move {
                match state.get_build(task_id).await {
                    Ok(Some(record)) => Ok(Some(record)),
                    // 记录中途消失属"未找到"语义——NotFound（USAGE=4）。
                    Ok(None) => Err(CrbsError::NotFound {
                        message: format!("Build task {task_id} disappeared"),
                    }
                    .into()),
                    Err(e) => {
                        tracing::warn!(error = %e, task_id = %task_id, "Failed to poll local build status");
                        Ok(None)
                    }
                }
            }
        },
    )
    .await
}
