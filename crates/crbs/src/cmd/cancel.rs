// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs cancel` 命令实现（远程 / daemon / 本地 SIGTERM 三路径）。

use anyhow::Context;
use crbs_core::privilege::CallerContext;
use crbs_core::types::build_phase_is_terminal;
use crbs_core::StateStore;
use tracing::{info, warn};

use crate::cli::{CommandOutput, OutputFormat};

/// cancel 命令参数（由 CLI 解析后传入）。
pub(crate) struct CancelArgs {
    pub task: String,
    pub format: OutputFormat,
    pub remote: Option<String>,
    pub token: Option<String>,
    pub local: bool,
}

/// cancel 命令统一输出（远程 / daemon / SIGTERM 三种路径均构造此类型）。
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
        // 服务器 message（如全 skipped 原因）始终展示，不以 cancelled 旗标抑制：部分取消下两者都要可见。
        if !self.message.is_empty() {
            println!("  message: {}", self.message);
        }
    }
}

pub(crate) async fn handle_cancel(
    args: CancelArgs,
    ctx: CallerContext,
    state: Option<&StateStore>,
) -> anyhow::Result<()> {
    let remote_target = crate::remote::resolve(args.remote, args.token, None, args.local).await?;
    if let Some(target) = remote_target {
        // 退出码契约：参数格式错误 = USAGE(4)，见 cmd::parse_task_id。
        let task_id = crate::cmd::parse_task_id(&args.task)?;
        let resp = crate::remote::cancel_task(&target, task_id).await?;
        // 响应无显式 cancelled 旗标：按 cancelled_build_ids 非空推导，否则全 skipped（已终态）也谎报 Cancelled。
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

    // 缺 StateStore 属调用方式误用——ValidationFailed（USAGE=4）。
    let state = crate::cmd::require_state_store(
        state,
        "local cancel requires a state store; use --remote for remote builds",
    )?;

    let user_filter = crate::cmd::visible_user_filter(&ctx);

    let task_id = state.resolve_task_id(&args.task, user_filter).await?;
    let task = state
        .get_task(task_id)
        .await?
        // 任务不存在属"未找到"语义。
        .ok_or_else(|| crate::cmd::task_not_found(task_id))?;

    validate_cancel_task(&task, &ctx)?;

    let children = state.get_builds_by_task_id(task_id).await?;

    // 任务由本地 daemon 管理时优先走 daemon cancel（级联子构建），避免 SIGTERM 误杀 daemon 进程。
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
        // daemon 未运行或任务不在其上：回退本地直连。
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
        // 镜像服务端语义：无活跃子构建也补 finalize 收口（终态守卫先到者生效）。
        match state.finalize_cancelled_task(task_id).await {
            Err(e) => {
                warn!(task_id = %task_id, error = %e, "Failed to finalize task without cancellable builds");
            }
            // 竞态：快照读空后 fan-out 又提交子构建（或 task 被并发写终态），取消未生效——
            // 镜像服务端 409 → Conflict（USAGE=4），不输出 cancelled:true。
            Ok(crbs_core::FinalizeOutcome::Superseded) => {
                return Err(crbs_core::error::CrbsError::Conflict {
                    message: format!("task {task_id} state changed during cancel; retry"),
                }
                .into());
            }
            // Finalized / ChildrenActive：软收敛语义，继续输出。
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

    // 按 PID 分流：已死 = 僵尸记录（崩溃/OOM 残留）补终态，存活进 SIGTERM 组；SIGTERM 收尾由
    // 执行者侧 BuildCleanupGuard 负责，执行者已死无 guard，须在此 complete_build 补全 completed_at/duration。
    let mut cancelled_ids: Vec<i64> = Vec::new();
    let mut stale_pids: Vec<i64> = Vec::new();
    let mut sigterm_groups: std::collections::BTreeMap<i64, Vec<&crbs_core::BuildRecord>> =
        std::collections::BTreeMap::new();
    for build in &active {
        // 活跃子构建无 PID = 记录残缺"未找到"——NotFound（USAGE=4），不落 INTERNAL(1)。
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
            // 先抢终态守卫再 dec：complete_build 0 行 = guard/并发修复已先转终态（已 dec 过），
            // 绝不能再 dec——双重扣减把仍被引用的共享层提前 GC，其他构建随即 LayerNotFound。
            let won = state
                .complete_build(build.id, "cancelled", build.result_dir.as_deref())
                .await?;
            if won > 0 && build.phase == "building" {
                if let Some(ref digest) = build.layer_digest {
                    // grace=0（全图第三类口径，见 state/gc.rs 漂移全图）：执行者确认死亡，无人会
                    // 在宽限期内重持引用，立即进 GC 候选；引擎 dec=operator 配置值，修复/回滚释放恒 168h。
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
        // 共享 PID 守卫：SIGTERM 杀整个进程，同 PID 上本任务之外的 in-progress 构建会被误伤，故先查后拒。
        let in_progress = state.list_in_progress_by_pid(*pid).await?;
        let foreign: Vec<&crbs_core::BuildRecord> = in_progress
            .iter()
            .filter(|r| !children.iter().any(|c| c.id == r.id))
            .collect();
        if !foreign.is_empty() {
            // 拒发 SIGTERM 属运行态冲突——Conflict（USAGE=4）；message 文案逐字保留。
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

        // pid 为内核 PID（Linux pid_max ≤ 2^22，远小于 i32::MAX）：try_from 失败理论不可达，
        // INTERNAL(1) 语义恰确。
        let pid_i32 = i32::try_from(*pid)
            .with_context(|| format!("PID {} is out of range for process signaling", pid))?;
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid_i32),
            nix::sys::signal::Signal::SIGTERM,
        )
        // 信号发送失败属环境/进程问题——Io（ENVIRONMENT=6），不落 INTERNAL(1)。
        .map_err(|e| crbs_core::error::CrbsError::Io {
            context: format!("Failed to send SIGTERM to PID {pid}"),
            kind: std::io::ErrorKind::Other,
            detail: e.to_string(),
        })?;

        // 逐个标记取消：终态守卫先到者生效；失败/0 行不阻断——SIGTERM 已发出，BuildCleanupGuard 进程退出后兜底。
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

/// 校验任务级取消的权限与状态前提（不发信号、不触 /proc，便于单测）。
/// 权限与服务端 `cancel_task_for_user` 同口径：普通用户仅能取消自己的任务
///（root 除外，旧记录 user='' 视为无主放行）；终态任务拒绝重复取消。
pub(crate) fn validate_cancel_task(
    task: &crbs_core::TaskRecord,
    ctx: &CallerContext,
) -> anyhow::Result<()> {
    crate::cmd::ensure_record_owner("task", task.id, &task.user, ctx)?;

    // 终态任务 Conflict（USAGE=4）；本地"无不可取消子构建 → Ok"幂等分支不受影响。
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
        // 钉非 Helper 特权后端：防有 setuid helper 的宿主机上 config 加载把进程楔死成 Helper。
        crate::test_support::pin_setuid_privilege_backend();
        let tmp = tempfile::tempdir().unwrap();
        let store = crbs_core::StateStore::new(tmp.path()).await.unwrap();
        (tmp, store)
    }

    /// `builds.task_id` NOT NULL：测试造 build 前先插一条本地任务行。
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
        // 死 PID 的 building 记录：cancel 须补全终态（cancelled + completed_at）而非报错留僵尸。
        // cancel 按 task id 解析（传 task id）；EnvGuard 使 CRBS_CONFIG_DIR 指向 store tempdir
        //（无 crbs.toml → 默认值），避免读到部署机 /etc/crbs root 属主配置（EACCES）。
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
        // 死 PID 的 building 构建持有 SharedLayer：补终态须同时 dec 层引用（镜像 zombie.rs repair），
        // 否则计数永不清零、层无法 GC。
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

    /// 活跃子构建无 PID（记录残缺/过旧）：NotFound（USAGE=4）不落 INTERNAL(1)，文案逐字钉死。
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

    /// 行为矩阵 cancel 行：多 arch 取消级联覆盖全部子构建，task phase 经聚合落 cancelled。
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

    /// 解析他人任务按 NotFound 隐蔽（不泄露存在性）；归属校验本体见 validate_cancel_denies_other_user。
    #[tokio::test]
    async fn handle_cancel_denies_other_users_task() {
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        // seed_task 以 user='' 落库（无主豁免口径）；此处需有主任务。
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

    /// NotFound 消息与服务端 `ApiError::not_found("task", id)` 同形（`task {id} not found`）。
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
        // 必须是 PermissionDenied（PERMISSION=5），消息点名归属。
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
