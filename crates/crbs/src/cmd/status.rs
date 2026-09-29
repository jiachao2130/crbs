// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

mod format;
mod remote;

use crate::cli::{validate_product, CommandOutput, OutputFormat};
use crate::cmd::status::format::{print_profile, print_task_detail, print_task_table};

use crate::cmd::status::remote::handle_remote_status;
use crbs_core::privilege::CallerContext;
use crbs_core::types::TaskListFilter;
use crbs_core::StateStore;
pub(crate) use format::ansi_allowed;
pub(crate) use format::format_seconds;
pub(crate) use format::new_table_with_style;
use std::collections::HashSet;
use std::io::IsTerminal;

const VALID_PHASES: &[&str] = &[
    "succeeded",
    "failed",
    "building",
    "pending",
    "timeout",
    "cancelled",
];

const JSON_TIME_KEYS: &[&str] = &["submitted_at", "completed_at", "started_at"];

/// status JSON 呈现约定（本地/远程、列表/详情共用）：builds 数组 → 按 arch 索引的 dict（同 arch 多 SRPM 与 NULL arch 均不丢；
/// unknown 收纳无 arch 的构建）；项内 result_dir 为 null 时省略键；时间值转 RFC3339 UTC（朴素串无时区标记，脚本按本地时间误读是真实痛点）。
pub(crate) fn shape_task_json(value: &mut serde_json::Value) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    normalize_json_times(obj);
    if let Some(builds) = obj.get_mut("builds") {
        if let Some(arr) = builds.as_array_mut() {
            let mut map = serde_json::Map::new();
            for item in arr.iter_mut() {
                let Some(item_obj) = item.as_object_mut() else {
                    continue;
                };
                let arch = item_obj
                    .remove("arch")
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default();
                let key = if arch.is_empty() {
                    "unknown".to_string()
                } else {
                    arch
                };
                if item_obj
                    .get("result_dir")
                    .is_some_and(serde_json::Value::is_null)
                {
                    item_obj.remove("result_dir");
                }
                normalize_json_times(item_obj);
                let entry = map
                    .entry(key)
                    .or_insert_with(|| serde_json::Value::Array(Vec::new()));
                if let Some(items) = entry.as_array_mut() {
                    items.push(item.take());
                }
            }
            *builds = serde_json::Value::Object(map);
        }
    }
    if let Some(tasks) = obj.get_mut("tasks") {
        if let Some(arr) = tasks.as_array_mut() {
            for item in arr.iter_mut() {
                if let Some(item_obj) = item.as_object_mut() {
                    normalize_json_times(item_obj);
                }
            }
        }
    }
}

fn normalize_json_times(obj: &mut serde_json::Map<String, serde_json::Value>) {
    for key in JSON_TIME_KEYS {
        if let Some(v) = obj.get_mut(*key) {
            if let Some(s) = v.as_str() {
                *v = serde_json::Value::String(naive_utc_to_rfc3339(s));
            }
        }
    }
}

/// "2026-10-23 13:40:39" → "2026-10-23T13:40:39Z"；非该形态（含已是 ISO 串、"-" 占位）原样返回。
pub(crate) fn naive_utc_to_rfc3339(s: &str) -> String {
    let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") else {
        return s.to_string();
    };
    naive
        .and_utc()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// status 命令参数（由 CLI 解析后传入）。
pub(crate) struct StatusArgs {
    pub task: Option<String>,
    pub product: Option<String>,
    pub limit: usize,
    pub format: OutputFormat,
    pub all: bool,
    pub filter: Vec<String>,
    pub label: Option<String>,
    pub watch: bool,
    pub profile: bool,
    pub repair: bool,
    pub remote: Option<String>,
    pub token: Option<String>,
    pub local: bool,
}

pub(crate) fn normalize_phase(raw: &str) -> String {
    let s = raw.trim().to_lowercase();
    match s.as_str() {
        "running" => "building".to_string(),
        "success" | "completed" | "done" => "succeeded".to_string(),
        "fail" | "failure" => "failed".to_string(),
        "canceled" => "cancelled".to_string(),
        _ => s,
    }
}

pub(crate) fn validate_status_values(values: &[String]) -> anyhow::Result<HashSet<String>> {
    let mut set = HashSet::with_capacity(values.len());
    for v in values {
        let normalized = normalize_phase(v);
        if !VALID_PHASES.contains(&normalized.as_str()) {
            return Err(crbs_core::error::CrbsError::ValidationFailed {
                message: format!(
                    "Invalid status value: '{}'. Valid: {}",
                    v,
                    VALID_PHASES.join(", ")
                ),
            }
            .into());
        }
        set.insert(normalized);
    }
    Ok(set)
}

/// 按状态过滤任务记录（本地与远程列表共用）。
pub(crate) fn filter_tasks(
    tasks: Vec<crbs_core::TaskRecord>,
    filter: &HashSet<String>,
) -> Vec<crbs_core::TaskRecord> {
    if filter.is_empty() {
        tasks
    } else {
        tasks
            .into_iter()
            .filter(|t| filter.contains(&t.phase))
            .collect()
    }
}

/// watch 轮询循环（本地/远程共用）：fetch 取数 → filter_tasks 过滤 → 渲染 → 2s 休眠，Ctrl+C 经 cancel 退出。
/// max_consecutive_failures 为取数连续失败上限——本地 1（首错即上抛）、远程 10（单次网络抖动不终结长驻视图）。
pub(crate) async fn watch_loop<F, Fut>(
    cancel: &tokio_util::sync::CancellationToken,
    mut fetch: F,
    filter_set: &HashSet<String>,
    limit: usize,
    max_consecutive_failures: u32,
) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Vec<crbs_core::TaskRecord>>>,
{
    let is_tty = std::io::stdout().is_terminal();
    let mut was_empty = false;
    let mut consecutive_failures = 0u32;
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let tasks = match fetch().await {
            Ok(tasks) => {
                consecutive_failures = 0;
                tasks
            }
            Err(e) => {
                consecutive_failures += 1;
                if consecutive_failures >= max_consecutive_failures {
                    return Err(e);
                }
                tracing::warn!(error = %e, "fetch tasks for watch failed; retrying");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };
        let filtered = filter_tasks(tasks, filter_set);
        let now_empty = filtered.is_empty();

        if now_empty {
            if !was_empty {
                if is_tty {
                    print!("\x1B[2J\x1B[1;1H");
                }
                println!("No tasks found. (watching every 2s, Ctrl+C to quit)");
                was_empty = true;
            }
        } else {
            was_empty = false;
            if is_tty {
                print!("\x1B[2J\x1B[1;1H");
            }
            let now = crbs_core::util::format_local_now();
            println!("Last updated: {} (every 2s, Ctrl+C to quit)\n", now);

            print_task_table(&filtered, limit);
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    Ok(())
}

struct RepairOutput {
    repaired: usize,
    live: usize,
    stale_detach_requests_removed: usize,
    stale_detach_requests_skipped: usize,
}

impl CommandOutput for RepairOutput {
    fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "command": "status",
            "repaired": self.repaired,
            "live": self.live,
            "stale_detach_requests_removed": self.stale_detach_requests_removed,
            "stale_detach_requests_skipped": self.stale_detach_requests_skipped,
        }))?)
    }

    fn print_text(&self) {
        println!(
            "Repaired {} zombie active build(s), {} still live.",
            self.repaired, self.live
        );
        println!(
            "Removed {} stale detach request file(s), skipped {}.",
            self.stale_detach_requests_removed, self.stale_detach_requests_skipped
        );

        if self.repaired > 0 {
            println!(
                "Replay comparison rows for flipped builds are backfilled by the next crbs-server startup reconcile."
            );
        }
    }
}

pub(crate) async fn handle_status(
    args: StatusArgs,
    ctx: &CallerContext,
    state: Option<&StateStore>,
) -> anyhow::Result<()> {
    if args.watch && args.format == OutputFormat::Json {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: "--watch and --format json are mutually exclusive".into(),
        }
        .into());
    }
    if args.profile && args.watch {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: "--profile and --watch are mutually exclusive".into(),
        }
        .into());
    }
    if args.profile && args.task.is_none() {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: "--profile requires a build ID".into(),
        }
        .into());
    }
    if let Some(ref p) = args.product {
        validate_product(p)?;
    }

    let filter_set = validate_status_values(&args.filter)?;
    let label_filter = match args.label.as_deref() {
        Some(raw) => Some(crbs_core::validation::parse_task_label_arg(raw)?),
        None => None,
    };

    let remote_target =
        crate::remote::resolve(args.remote.clone(), args.token.clone(), None, args.local).await?;
    if let Some(target) = remote_target {
        if args.repair {
            return Err(crbs_core::error::CrbsError::ValidationFailed {
                message: "--repair is only supported for local status".to_string(),
            }
            .into());
        }
        return handle_remote_status(target, &args, filter_set, label_filter).await;
    }

    let state = crate::cmd::require_state_store(
        state,
        "local state store not initialized; did you mean --remote?",
    )?;

    let StatusArgs {
        task,
        product,
        limit,
        format,
        all,
        filter: _,
        label: _,
        watch: local_watch,
        profile,
        repair,
        remote: _,
        token: _,
        local: _,
    } = args;

    let user_filter = if all {
        None
    } else {
        Some(ctx.caller.username.as_str())
    };

    if repair {
        if !ctx.is_root {
            return Err(crbs_core::error::CrbsError::PermissionDenied {
                message: "status --repair rewrites records across all users; requires root"
                    .to_string(),
            }
            .into());
        }

        let (repaired_ids, live) = state.repair_all_zombie_active_builds().await?;
        let (removed, skipped) = crate::cmd::build::detach::cleanup_stale_detach_requests(
            std::time::Duration::from_secs(24 * 3600),
        )
        .await?;
        format.print(&RepairOutput {
            repaired: repaired_ids.len(),
            live,
            stale_detach_requests_removed: removed,
            stale_detach_requests_skipped: skipped,
        })?;

        return Ok(());
    }

    if let Some(task) = task {
        if profile {
            let build_id = crate::cmd::resolve_short_id(&task, state, user_filter).await?;
            let record = state.get_build(build_id).await?.ok_or_else(|| {
                crbs_core::error::CrbsError::NotFound {
                    message: format!(
                        "build {build_id} not found. Run 'crbs status' to list builds."
                    ),
                }
            })?;

            crate::cmd::ensure_record_owner("build", build_id, &record.user, ctx)?;

            let result_dir = record.result_dir.as_ref().ok_or_else(|| {
                crbs_core::error::CrbsError::NotFound {
                    message: format!("Build {build_id} result directory has been cleaned"),
                }
            })?;
            let profile =
                crbs_core::engine::profile::read_profile(std::path::Path::new(result_dir))
                    .await?
                    .ok_or_else(|| crbs_core::error::CrbsError::NotFound {
                        message: format!("Build {build_id} has no profile.json"),
                    })?;
            if format == OutputFormat::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "command": "status",
                        "profile": profile,
                    }))?
                );
            } else {
                print_profile(&profile);
            }
            return Ok(());
        }

        let task_id = state.resolve_task_id(&task, user_filter).await?;
        let record = state
            .get_task(task_id)
            .await?
            .ok_or_else(|| crate::cmd::task_not_found(task_id))?;

        crate::cmd::ensure_record_owner("task", task_id, &record.user, ctx)?;

        let builds = state.get_child_build_summaries(task_id).await?;
        let lineage = Some(state.task_lineage(task_id).await?);
        let labels: Vec<crbs_core::types::TaskLabel> = state
            .get_task_labels(task_id)
            .await?
            .into_iter()
            .map(|(key, value)| crbs_core::types::TaskLabel { key, value })
            .collect();
        if format == OutputFormat::Json {
            let detail = crate::remote::TaskDetailResponse {
                task: record,
                builds,
                lineage,
                labels,
            };
            let mut body = serde_json::to_value(&detail)?;
            shape_task_json(&mut body);
            println!(
                "{}",
                serde_json::to_string_pretty(&crate::cmd::json_success_envelope("status", body,))?
            );
        } else {
            print_task_detail(&record, &builds, lineage.as_ref(), &labels);
        }
        return Ok(());
    }

    if local_watch {
        let cancel = crate::cmd::ctrl_c_cancel_token();

        let product = product.as_deref();
        let label_filter = label_filter.clone();
        let fetch = move || {
            let label = label_filter.clone();
            async move {
                let (_, tasks) = state
                    .list_tasks(&TaskListFilter {
                        product,
                        user: user_filter,
                        label,
                        ..Default::default()
                    })
                    .await?;
                anyhow::Ok(tasks)
            }
        };
        return watch_loop(&cancel, fetch, &filter_set, limit, 1).await;
    }

    let (_, tasks) = state
        .list_tasks(&TaskListFilter {
            product: product.as_deref(),
            user: user_filter,
            label: label_filter,
            ..Default::default()
        })
        .await?;
    let filtered = filter_tasks(tasks, &filter_set);

    if filtered.is_empty() && format != OutputFormat::Json {
        println!("No tasks found.");
        return Ok(());
    }

    if format == OutputFormat::Json {
        let display_limit = if limit == 0 { filtered.len() } else { limit };
        let mut body = serde_json::json!({
            "command": "status",
            "tasks": filtered.iter().take(display_limit).collect::<Vec<_>>(),
        });
        shape_task_json(&mut body);
        println!("{}", serde_json::to_string_pretty(&body)?);
        return Ok(());
    }

    let (shown, total) = print_task_table(&filtered, limit);
    if shown < total {
        println!("\nshowing {shown} of {total} (use --limit 0 for all)");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::status::format::{format_seconds, phase_color, truncate};
    use std::collections::HashSet;

    #[test]
    fn shape_task_json_rebuilds_dict_and_normalizes_times() {
        let mut v = serde_json::json!({
            "id": 7,
            "submitted_at": "2026-10-23 13:40:39",
            "builds": [
                {"id": 28, "arch": "x86_64", "phase": "succeeded",
                 "result_dir": null, "started_at": "2026-10-23 13:40:40",
                 "duration_seconds": 4903},
                {"id": 29, "arch": "x86_64", "phase": "succeeded",
                 "result_dir": null, "started_at": "2026-10-23 13:40:41",
                 "duration_seconds": 4904},
                {"id": 25, "arch": "aarch64", "phase": "succeeded",
                 "result_dir": "/data/crbs/hub/results/7/aarch64/25",
                 "started_at": "2026-10-23T13:40:40Z", "duration_seconds": 1074},
                {"id": 30, "arch": null, "phase": "failed",
                 "result_dir": null, "started_at": null, "duration_seconds": 1}
            ]
        });
        shape_task_json(&mut v);

        assert_eq!(v["submitted_at"], "2026-10-23T13:40:39Z");
        let builds = v["builds"].as_object().expect("builds must be an object");
        assert_eq!(builds.len(), 3);
        let x86 = builds["x86_64"].as_array().expect("arch values are arrays");
        assert_eq!(x86.len(), 2, "same-arch multi-SRPM builds must survive");
        assert!(
            x86[0].get("arch").is_none() && x86[1].get("arch").is_none(),
            "arch key is the index, not repeated"
        );
        assert!(
            x86[0].get("result_dir").is_none(),
            "null result_dir omits the key"
        );
        assert_eq!(x86[0]["started_at"], "2026-10-23T13:40:40Z");
        let aarch = builds["aarch64"]
            .as_array()
            .expect("arch values are arrays");
        assert_eq!(aarch.len(), 1);
        assert!(aarch[0].get("result_dir").is_some(), "real value kept");
        assert_eq!(
            aarch[0]["started_at"], "2026-10-23T13:40:40Z",
            "already-ISO value passes through unchanged"
        );
        assert_eq!(
            builds["unknown"]
                .as_array()
                .expect("NULL arch builds are retained under unknown")
                .len(),
            1
        );

        let mut list = serde_json::json!({
            "command": "status",
            "tasks": [{"id": 1, "submitted_at": "2026-10-23 10:02:11", "completed_at": null}]
        });
        shape_task_json(&mut list);
        assert_eq!(list["tasks"][0]["submitted_at"], "2026-10-23T10:02:11Z");
        assert!(
            list["tasks"][0]["completed_at"].is_null(),
            "null time stays null"
        );
    }

    #[test]
    fn normalize_phase_maps_aliases() {
        assert_eq!(normalize_phase("running"), "building");
        assert_eq!(normalize_phase("RUNNING"), "building");
        assert_eq!(normalize_phase("success"), "succeeded");
        assert_eq!(normalize_phase("completed"), "succeeded");
        assert_eq!(normalize_phase("canceled"), "cancelled");
        assert_eq!(normalize_phase("building"), "building");
    }

    #[test]
    fn validate_status_values_accepts_aliases() {
        let set = validate_status_values(&["running".to_string(), "success".to_string()]).unwrap();
        assert!(set.contains("building"));
        assert!(set.contains("succeeded"));
    }

    #[test]
    fn validate_status_values_rejects_invalid() {
        let err = validate_status_values(&["unknown".to_string()]).unwrap_err();
        let ce = err.downcast_ref::<crbs_core::error::CrbsError>().unwrap();
        assert!(
            matches!(ce, crbs_core::error::CrbsError::ValidationFailed { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::USAGE
        );
        assert!(
            format!("{ce}").contains("Invalid status value: 'unknown'. Valid: "),
            "msg must be preserved verbatim: {ce}"
        );
    }

    #[test]
    fn format_seconds_handles_various_durations() {
        assert_eq!(format_seconds(45), "45s");
        assert_eq!(format_seconds(60), "1m");
        assert_eq!(format_seconds(125), "2m5s");
        assert_eq!(format_seconds(-1), "-1s");
    }

    #[test]
    fn filter_tasks_empty_filter_returns_all() {
        let tasks = vec![sample_task(1, "succeeded"), sample_task(2, "building")];
        let filtered = filter_tasks(tasks, &HashSet::new());
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn filter_tasks_keeps_matching_phase() {
        let tasks = vec![
            sample_task(1, "succeeded"),
            sample_task(2, "building"),
            sample_task(3, "failed"),
        ];
        let mut filter = HashSet::new();
        filter.insert("building".to_string());
        let filtered = filter_tasks(tasks, &filter);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, 2);
    }

    fn sample_task(id: i64, phase: &str) -> crbs_core::TaskRecord {
        crbs_core::TaskRecord {
            id,
            product: "fedora".into(),
            pkg_name: "hello".into(),
            name: "hello".into(),
            version: "1.0".into(),
            release: "1".into(),
            user: "alice".into(),
            phase: phase.into(),
            priority: crbs_core::types::PRIORITY_DEFAULT,
            srpm_path: None,
            result_dir: None,
            submitted_at: None,
            completed_at: None,
            duration: None,
            pkg_names: Vec::new(),
        }
    }

    #[test]
    fn phase_color_maps_known_phases() {
        assert!(!phase_color("succeeded").is_empty());
        assert!(!phase_color("failed").is_empty());
        assert!(!phase_color("building").is_empty());
        assert!(phase_color("unknown").is_empty());
    }

    #[test]
    fn ansi_allowed_respects_tty_and_no_color() {
        use crate::cmd::status::format::ansi_allowed;
        use std::ffi::OsStr;
        assert!(ansi_allowed(true, None));

        assert!(ansi_allowed(true, Some(OsStr::new(""))));

        assert!(!ansi_allowed(true, Some(OsStr::new("1"))));
        assert!(!ansi_allowed(true, Some(OsStr::new("false"))));
        assert!(!ansi_allowed(false, None));
        assert!(!ansi_allowed(false, Some(OsStr::new(""))));
    }

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_string_adds_ellipsis() {
        let s = "this is a very long string";
        let out = truncate(s, 10);
        assert!(out.len() <= 10);
        assert!(out.ends_with("..."));
    }

    async fn tmp_store() -> (tempfile::TempDir, StateStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();
        (tmp, store)
    }

    async fn insert_task(store: &StateStore, pkg_name: &str) -> i64 {
        store
            .insert_task(crbs_core::TaskInsert {
                product: "fedora",
                pkg_name,
                user: "tester",
                phase: "succeeded",
                ..Default::default()
            })
            .await
            .unwrap()
    }

    async fn insert_build(store: &StateStore, task_id: i64, arch: &str) -> i64 {
        store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "succeeded",
                backend: "chroot",
                user: "tester",
                arch: Some(arch),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap()
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

    fn status_args(task: Option<String>) -> StatusArgs {
        StatusArgs {
            task,
            product: None,
            limit: 20,
            format: OutputFormat::Text,
            all: false,
            filter: Vec::new(),
            watch: false,
            profile: false,
            repair: false,
            remote: None,
            token: None,
            local: true,
            label: None,
        }
    }

    #[tokio::test]
    async fn handle_status_local_detail_resolves_task_id() {
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        insert_task(&store, "pad").await;
        let task_id = insert_task(&store, "hello").await;
        let build_id = insert_build(&store, task_id, "x86_64").await;
        assert_ne!(task_id, build_id, "fixture requires disjoint ids");

        handle_status(
            status_args(Some(task_id.to_string())),
            &tester_ctx(),
            Some(&store),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn handle_status_local_detail_not_found_shape() {
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        let err = handle_status(
            status_args(Some("424242".to_string())),
            &tester_ctx(),
            Some(&store),
        )
        .await
        .expect_err("missing task must fail");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::NotFound { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::USAGE
        );
        assert!(
            err.to_string().contains("task 424242 not found"),
            "unexpected message: {err}"
        );
    }

    #[tokio::test]
    async fn handle_status_local_list_is_task_scoped() {
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        let task_id = insert_task(&store, "hello").await;
        insert_build(&store, task_id, "x86_64").await;
        insert_build(&store, task_id, "aarch64").await;

        handle_status(status_args(None), &tester_ctx(), Some(&store))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn handle_status_local_profile_stays_build_scoped() {
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        let task_id = insert_task(&store, "hello").await;
        let build_id = insert_build(&store, task_id, "x86_64").await;

        let mut args = status_args(Some(build_id.to_string()));
        args.profile = true;
        let err = handle_status(args, &tester_ctx(), Some(&store))
            .await
            .expect_err("build without result_dir cannot serve a profile");

        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::NotFound { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::USAGE
        );
        assert!(
            err.to_string()
                .contains("result directory has been cleaned"),
            "unexpected message: {err}"
        );
    }
}
