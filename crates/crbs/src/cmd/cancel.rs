// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use anyhow::Context;
use crbs_core::privilege::CallerContext;
use crbs_core::types::build_phase_is_terminal;
use crbs_core::StateStore;
use tracing::{info, warn};

use crate::cli::{CommandOutput, OutputFormat};

pub(crate) struct CancelArgs {
    pub task: String,
    pub format: OutputFormat,
    pub remote: Option<String>,
    pub token: Option<String>,
    pub local: bool,
}

#[derive(serde::Serialize)]
struct CancelOutput {
    command: &'static str,
    task_id: i64,
    cancelled: bool,
    cancelled_ids: Vec<i64>,
    skipped_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<i64>,
    via: String,
    message: String,
}

impl CommandOutput for CancelOutput {
    fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    fn print_text(&self) {
        if self.cancelled {
            println!("Cancelled task {} via {}", self.task_id, self.via);
        } else {
            println!("Task {} was not cancelled", self.task_id);
        }
        if let Some(pid) = self.pid {
            println!("  pid: {}", pid);
        }
        if !self.cancelled_ids.is_empty() {
            println!(
                "  cancelled: {}",
                self.cancelled_ids
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !self.skipped_ids.is_empty() {
            println!(
                "  skipped: {}",
                self.skipped_ids
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        if !self.message.is_empty() {
            println!("  message: {}", self.message);
        }
    }
}

/// cancel 命令实现（远程 / daemon / 本地 SIGTERM 三路径）：任务由本地 daemon 管理时优先走 daemon cancel（级联子构建），避免 SIGTERM
/// 误杀 daemon 进程。
pub(crate) async fn handle_cancel(
    args: CancelArgs,
    ctx: CallerContext,
    state: Option<&StateStore>,
) -> anyhow::Result<()> {
    let remote_target = crate::remote::resolve(args.remote, args.token, None, args.local).await?;
    if let Some(target) = remote_target {
        let task_id = crate::cmd::parse_task_id(&args.task)?;
        let resp = crate::remote::cancel_task(&target, task_id).await?;

        let output = CancelOutput {
            command: "cancel",
            task_id: resp.task_id,
            cancelled: !resp.cancelled_build_ids.is_empty(),
            cancelled_ids: resp.cancelled_build_ids,
            skipped_ids: resp.skipped_build_ids,
            pid: None,
            via: format!("remote ({})", target.url),
            message: resp.message,
        };
        args.format.print(&output)?;
        return Ok(());
    }

    let state = crate::cmd::require_state_store(
        state,
        "local cancel requires a state store; use --remote for remote builds",
    )?;

    let user_filter = crate::cmd::visible_user_filter(&ctx);

    let task_id = state.resolve_task_id(&args.task, user_filter).await?;
    let task = state
        .get_task(task_id)
        .await?
        .ok_or_else(|| crate::cmd::task_not_found(task_id))?;

    validate_cancel_task(&task, &ctx)?;

    let children = state.get_builds_by_task_id(task_id).await?;

    match crate::local_daemon::cancel_task(task_id).await {
        Ok(Some(resp)) => {
            let output = CancelOutput {
                command: "cancel",
                task_id,
                cancelled: !resp.cancelled_build_ids.is_empty(),
                cancelled_ids: resp.cancelled_build_ids,
                skipped_ids: resp.skipped_build_ids,
                pid: None,
                via: "local_daemon".to_string(),
                message: resp.message,
            };
            args.format.print(&output)?;
            return Ok(());
        }

        Ok(None) => {}
        Err(e) => {
            warn!(task_id = %task_id, error = %e, "Local daemon cancel failed, falling back to local SIGTERM")
        }
    }

    let active: Vec<crbs_core::BuildRecord> = children
        .iter()
        .filter(|b| !build_phase_is_terminal(&b.phase))
        .cloned()
        .collect();

    if active.is_empty() {
        match state.finalize_cancelled_task(task_id).await {
            Err(e) => {
                warn!(task_id = %task_id, error = %e, "Failed to finalize task without cancellable builds");
            }

            Ok(crbs_core::FinalizeOutcome::Superseded) => {
                return Err(crbs_core::error::CrbsError::Conflict {
                    message: format!("task {task_id} state changed during cancel; retry"),
                }
                .into());
            }

            Ok(_) => {}
        }
        let (cancelled, message) = if children.is_empty() {
            (true, "task cancelled (no child builds)".to_string())
        } else {
            (false, "no cancellable child builds".to_string())
        };
        let output = CancelOutput {
            command: "cancel",
            task_id,
            cancelled,
            cancelled_ids: Vec::new(),
            skipped_ids: children.iter().map(|b| b.id).collect(),
            pid: None,
            via: "local".to_string(),
            message,
        };
        args.format.print(&output)?;
        return Ok(());
    }

    let mut cancelled_ids: Vec<i64> = Vec::new();
    let mut stale_pids: Vec<i64> = Vec::new();
    let mut sigterm_groups: std::collections::BTreeMap<i64, Vec<&crbs_core::BuildRecord>> =
        std::collections::BTreeMap::new();
    for build in &active {
        let pid = build
            .crbs_pid
            .ok_or_else(|| crbs_core::error::CrbsError::NotFound {
                message: format!(
                    "task {task_id} child build {} has no PID recorded (too old?)",
                    build.id
                ),
            })?;
        if crbs_core::util::is_process_alive(pid).await {
            sigterm_groups.entry(pid).or_default().push(build);
        } else {
            info!(
                task_id = %task_id,
                build_id = %build.id,
                pid = pid,
                "Executor not alive; marking stale build cancelled"
            );

            let won = state
                .complete_build(build.id, "cancelled", build.result_dir.as_deref())
                .await?;
            if won > 0 && build.phase == "building" {
                if let Some(ref digest) = build.layer_digest {
                    if let Err(e) = state.layer_ref_dec(digest, 0).await {
                        warn!(
                            build_id = %build.id,
                            digest = %digest,
                            error = %e,
                            "layer_ref_dec failed while cancelling stale build"
                        );
                    }
                }
            }
            cancelled_ids.push(build.id);
            if !stale_pids.contains(&pid) {
                stale_pids.push(pid);
            }
        }
    }

    let mut sigterm_pid: Option<i64> = None;
    for (pid, builds) in &sigterm_groups {
        let in_progress = state.list_in_progress_by_pid(*pid).await?;
        let foreign: Vec<&crbs_core::BuildRecord> = in_progress
            .iter()
            .filter(|r| !children.iter().any(|c| c.id == r.id))
            .collect();
        if !foreign.is_empty() {
            return Err(crbs_core::error::CrbsError::Conflict {
                message: format!(
                    "PID {} has {} active build(s) outside task {} (including build {}). \
                     Use 'crbs daemon' for per-build cancellation, or terminate the whole process.",
                    pid,
                    foreign.len(),
                    task_id,
                    foreign[0].id
                ),
            }
            .into());
        }
        info!(pid = pid, "PID identity check passed");

        let pid_i32 = i32::try_from(*pid)
            .with_context(|| format!("PID {} is out of range for process signaling", pid))?;
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid_i32),
            nix::sys::signal::Signal::SIGTERM,
        )
        .map_err(|e| crbs_core::error::CrbsError::Io {
            context: format!("Failed to send SIGTERM to PID {pid}"),
            kind: std::io::ErrorKind::Other,
            detail: e.to_string(),
        })?;

        for build in builds {
            match state.mark_build_cancelled(build.id).await {
                Ok(0) => warn!(
                    build_id = %build.id,
                    "Build already reached a terminal phase; cancel not applied (SIGTERM already sent)"
                ),
                Ok(_) => cancelled_ids.push(build.id),
                Err(e) => {
                    warn!(build_id = %build.id, err = %e, "Failed to mark build as cancelled")
                }
            }
        }
        sigterm_pid = Some(*pid);
    }

    let (via, pid, message) = if !sigterm_groups.is_empty() {
        let pid = sigterm_pid;
        ("sigterm".to_string(), pid, String::new())
    } else {
        (
            "stale-pid".to_string(),
            stale_pids.first().copied(),
            format!(
                "executor PID(s) {} not alive; stale build(s) marked cancelled",
                stale_pids
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    };

    let output = CancelOutput {
        command: "cancel",
        task_id,
        cancelled: !cancelled_ids.is_empty(),
        cancelled_ids,
        skipped_ids: children
            .iter()
            .filter(|b| build_phase_is_terminal(&b.phase))
            .map(|b| b.id)
            .collect(),
        pid,
        via,
        message,
    };
    args.format.print(&output)?;

    Ok(())
}

pub(crate) fn validate_cancel_task(
    task: &crbs_core::TaskRecord,
    ctx: &CallerContext,
) -> anyhow::Result<()> {
    crate::cmd::ensure_record_owner("task", task.id, &task.user, ctx)?;

    if build_phase_is_terminal(&task.phase) {
        return Err(crbs_core::error::CrbsError::Conflict {
            message: format!("task {} is already {} (cannot cancel)", task.id, task.phase),
        }
        .into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn tmp_store() -> (tempfile::TempDir, crbs_core::StateStore) {
        crate::test_support::pin_setuid_privilege_backend();
        let tmp = tempfile::tempdir().unwrap();
        let store = crbs_core::StateStore::new(tmp.path()).await.unwrap();
        (tmp, store)
    }

    async fn seed_task(store: &crbs_core::StateStore, product: &str, pkg_name: &str) -> i64 {
        store
            .insert_task(crbs_core::TaskInsert {
                product,
                pkg_name,
                user: "",
                ..Default::default()
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn handle_cancel_dead_pid_marks_stale_build_cancelled() {
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        let task_id = seed_task(&store, "fedora", "hello").await;
        let id = store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "building",
                backend: "chroot",
                user: "tester",
                crbs_pid: Some(2_000_000_000),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        let ctx = CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: "tester".to_string(),
            },
            false,
        );
        let args = CancelArgs {
            task: task_id.to_string(),
            format: OutputFormat::Text,
            remote: None,
            token: None,
            local: true,
        };
        handle_cancel(args, ctx, Some(&store)).await.unwrap();

        let rec = store.get_build(id).await.unwrap().unwrap();
        assert_eq!(rec.phase, "cancelled");
        assert!(
            rec.completed_at.is_some(),
            "completed_at must be backfilled"
        );
    }

    #[tokio::test]
    async fn handle_cancel_dead_pid_releases_shared_layer_ref() {
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        let digest = "sha256:deadbeef";
        store
            .insert_layer(digest, "/tmp/layers/deadbeef", "fedora", 1)
            .await
            .unwrap();
        let task_id = seed_task(&store, "fedora", "hello").await;
        let id = store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "building",
                layer_digest: Some(digest),
                backend: "chroot",
                user: "tester",
                crbs_pid: Some(2_000_000_000),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        let ctx = CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: "tester".to_string(),
            },
            false,
        );
        let args = CancelArgs {
            task: task_id.to_string(),
            format: OutputFormat::Text,
            remote: None,
            token: None,
            local: true,
        };
        handle_cancel(args, ctx, Some(&store)).await.unwrap();

        let rec = store.get_build(id).await.unwrap().unwrap();
        assert_eq!(rec.phase, "cancelled");
        assert_eq!(
            store.get_layer_ref_count(digest).await.unwrap(),
            Some(0),
            "stale-pid cancel must dec layer ref held by the dead build"
        );
    }

    #[tokio::test]
    async fn handle_cancel_build_without_pid_is_not_found_exit_4() {
        use crbs_core::exit_code::{crbs_error_exit_code, USAGE};

        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        let task_id = seed_task(&store, "fedora", "hello").await;
        let build_id = store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "building",
                backend: "chroot",
                user: "tester",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        let ctx = CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: "tester".to_string(),
            },
            false,
        );
        let args = CancelArgs {
            task: task_id.to_string(),
            format: OutputFormat::Text,
            remote: None,
            token: None,
            local: true,
        };
        let err = handle_cancel(args, ctx, Some(&store))
            .await
            .expect_err("active build without PID must fail");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::NotFound { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_error_exit_code(ce), USAGE);
        assert!(
            format!("{ce}").contains(&format!(
                "task {task_id} child build {build_id} has no PID recorded (too old?)"
            )),
            "msg must be preserved verbatim: {ce}"
        );
    }

    #[tokio::test]
    async fn handle_cancel_task_cascades_all_child_builds() {
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        let task_id = seed_task(&store, "fedora", "hello").await;
        let mut build_ids = Vec::new();
        for arch in ["x86_64", "aarch64"] {
            build_ids.push(
                store
                    .insert_build(crbs_core::BuildInsert {
                        product: "fedora",
                        pkg_name: "hello",
                        phase: "building",
                        backend: "chroot",
                        user: "tester",
                        crbs_pid: Some(2_000_000_000),
                        arch: Some(arch),
                        task_id: Some(task_id),
                        ..Default::default()
                    })
                    .await
                    .unwrap(),
            );
        }

        let ctx = CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: "tester".to_string(),
            },
            false,
        );
        let args = CancelArgs {
            task: task_id.to_string(),
            format: OutputFormat::Text,
            remote: None,
            token: None,
            local: true,
        };
        handle_cancel(args, ctx, Some(&store)).await.unwrap();

        for id in &build_ids {
            let rec = store.get_build(*id).await.unwrap().unwrap();
            assert_eq!(rec.phase, "cancelled", "child build {id} must be cancelled");
            assert!(rec.completed_at.is_some());
        }
        let task = store.get_task(task_id).await.unwrap().unwrap();
        assert_eq!(task.phase, "cancelled", "task phase must aggregate");
    }

    #[tokio::test]
    async fn handle_cancel_denies_other_users_task() {
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());

        let task_id = store
            .insert_task(crbs_core::TaskInsert {
                product: "fedora",
                pkg_name: "hello",
                user: "alice",
                ..Default::default()
            })
            .await
            .unwrap();

        let ctx = CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: "mallory".to_string(),
            },
            false,
        );
        let args = CancelArgs {
            task: task_id.to_string(),
            format: OutputFormat::Text,
            remote: None,
            token: None,
            local: true,
        };
        let err = match handle_cancel(args, ctx, Some(&store)).await {
            Ok(_) => panic!("cancel of another user's task must fail"),
            Err(e) => e,
        };
        assert!(
            matches!(
                err.downcast_ref::<crbs_core::error::CrbsError>(),
                Some(crbs_core::error::CrbsError::NotFound { .. })
            ),
            "must be NotFound (existence concealed): {err}"
        );
    }

    #[tokio::test]
    async fn handle_cancel_local_task_not_found_message() {
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        let ctx = CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: "tester".to_string(),
            },
            false,
        );
        let args = CancelArgs {
            task: "424242".to_string(),
            format: OutputFormat::Text,
            remote: None,
            token: None,
            local: true,
        };
        let err = handle_cancel(args, ctx, Some(&store))
            .await
            .expect_err("missing task must fail");
        assert!(
            err.to_string().contains("task 424242 not found"),
            "unexpected message: {err}"
        );
    }

    fn task_record(id: i64, user: &str, phase: &str) -> crbs_core::TaskRecord {
        crbs_core::TaskRecord {
            id,
            product: "fedora".into(),
            pkg_name: "hello".into(),
            name: "hello".into(),
            version: "1.0".into(),
            release: "1".into(),
            user: user.into(),
            phase: phase.into(),
            priority: 0,
            srpm_path: None,
            result_dir: None,
            submitted_at: None,
            completed_at: None,
            duration: None,
            pkg_names: Vec::new(),
        }
    }

    fn ctx_for(username: &str) -> CallerContext {
        CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: username.into(),
            },
            false,
        )
    }

    #[test]
    fn validate_cancel_allows_owner() {
        let task = task_record(1, "alice", "building");
        assert!(validate_cancel_task(&task, &ctx_for("alice")).is_ok());
    }

    #[test]
    fn validate_cancel_denies_other_user() {
        let task = task_record(1, "bob", "building");
        let err = validate_cancel_task(&task, &ctx_for("alice")).unwrap_err();

        let e_str = format!("{err}");
        assert!(e_str.contains("belongs to"), "unexpected: {e_str}");
        assert!(
            matches!(
                err.downcast_ref::<crbs_core::error::CrbsError>(),
                Some(crbs_core::error::CrbsError::PermissionDenied { .. })
            ),
            "must be CrbsError::PermissionDenied: {e_str}"
        );
    }

    #[test]
    fn validate_cancel_denies_completed_phase() {
        let task = task_record(1, "alice", "succeeded");
        let err = validate_cancel_task(&task, &ctx_for("alice")).unwrap_err();
        assert!(format!("{}", err).contains("already succeeded"));
    }
}
