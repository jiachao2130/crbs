// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! builds 子命令（产物列表展示 + publish/unpublish repo 发布控制）。

use anyhow::Result;
use comfy_table::{Cell, Color, Table};
use std::io::IsTerminal;

use crate::cli::{BuildsCommand, OutputFormat};
use crate::cmd::status::new_table_with_style;
use crbs_core::StateStore;

/// 运行 builds 子命令：`Show` 走本地 StateStore，`Publish`/`Unpublish` 走远程 HTTP。
pub(crate) async fn handle_builds(
    cmd: BuildsCommand,
    remote: Option<String>,
    token: Option<String>,
    local: bool,
    state: Option<&StateStore>,
    ctx: &crbs_core::privilege::CallerContext,
) -> Result<()> {
    match cmd {
        BuildsCommand::Show { id, format } => {
            // 缺本地 StateStore 属调用方式误用——ValidationFailed（USAGE=4）。
            let state = crate::cmd::require_state_store(
                state,
                "builds show requires a local state store; pass --local \
                 (a remote target is configured via --remote or remote.default)",
            )?;
            handle_show(id, format, ctx, state).await
        }
        BuildsCommand::Publish { id, format } => {
            handle_set_publish(id, true, remote, token, local, format).await
        }
        BuildsCommand::Unpublish { id, format } => {
            handle_set_publish(id, false, remote, token, local, format).await
        }
    }
}

/// `crbs builds publish/unpublish <id>`：远程翻发布轴 `repo_publish` + hub 同步重建 repo。
async fn handle_set_publish(
    id: i64,
    publish: bool,
    remote: Option<String>,
    token: Option<String>,
    local: bool,
    format: OutputFormat,
) -> Result<()> {
    let verb = if publish { "publish" } else { "unpublish" };

    // 只能远程（repo 重建在 hub 侧）；--local 强制本地 = 误用：ValidationFailed（USAGE=4）。
    let target = crate::remote::resolve(remote, token, None, local)
        .await?
        .ok_or_else(|| crbs_core::error::CrbsError::ValidationFailed {
            message: format!(
                "crbs builds {} requires a remote server. Use --remote or configure remote.default",
                verb
            ),
        })?;

    let url = format!("{}/api/v1/builds/{}/{}", target.url, id, verb);

    // 撞 .repodata-{arch}.lock 时 regen 最坏可阻塞数分钟。
    let client = target.client().await?;
    let resp = crate::remote::retry_http("set_publish", reqwest::Method::POST, None, || {
        client.post(&url)
    })
    .await?;
    let status = resp.status;
    let body = resp.body;

    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
        // 退出码契约：PERMISSION(5)。
        return Err(crbs_core::error::CrbsError::PermissionDenied {
            message: "permission denied: admin/operator or the original submitter required"
                .to_string(),
        }
        .into());
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        // 退出码契约：USAGE(4)；404 文案与 builds show 同口径（id 同为 build id）。
        return Err(crbs_core::error::CrbsError::NotFound {
            message: format!("Build {id} not found. Run 'crbs status' to list builds."),
        }
        .into());
    }
    if !status.is_success() {
        return Err(
            crate::remote::http_status_error(&format!("builds {verb}"), status, &body).into(),
        );
    }

    // serde 解析失败 = Network（ENVIRONMENT=6），不经 anyhow context 落 INTERNAL；
    // message 内联经 truncate_body_for_error 截断/剥控制序列的 body。
    let parsed: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| crbs_core::error::CrbsError::Network {
            message: format!(
                "parse publish response: {}: {e}",
                crate::remote::truncate_body_for_error(&body)
            ),
        })?;

    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&crate::cmd::json_success_envelope(
                if publish {
                    "builds publish"
                } else {
                    "builds unpublish"
                },
                parsed,
            ))?
        ),
        OutputFormat::Text => {
            let product = parsed
                .get("product")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let state_str = if publish { "published" } else { "unpublished" };
            println!("Build #{} {} in product '{}' repo", id, state_str, product);
        }
    }

    Ok(())
}

/// `crbs builds show <id>` 的产物表格构造。comfy-table 自带 tty 探测但不读 `NO_COLOR`
///（与 `ansi_allowed` 口径相悖）；复用同一判定与 `new_table_with_style`，`style=false`
/// 时 `should_style()` 恒 false（单测不依赖真实 stdout），NO_COLOR=1/重定向输出纯文本。
fn new_artifact_table() -> Table {
    new_table_with_style(crate::cmd::status::ansi_allowed(
        std::io::stdout().is_terminal(),
        std::env::var_os("NO_COLOR").as_deref(),
    ))
}

/// `builds show` 的 JSON 输出体（双轴标注随 BuildRecord 透出）。
fn build_show_json(
    id: i64,
    build: &crbs_core::BuildRecord,
    artifacts: &[crbs_core::Artifact],
    reproducibility: &Option<crbs_core::ReproducibilityRecord>,
) -> serde_json::Value {
    serde_json::json!({
        "command": "builds show",
        "build_id": id,
        "product": build.product,
        "pkg_name": build.pkg_name,
        "phase": build.phase,
        "deterministic": build.deterministic,
        "repo_publish": build.repo_publish,
        "repo_consume": build.repo_consume,
        "canonical_srpm_sha256": build.canonical_srpm_sha256,
        "artifacts": artifacts,
        "reproducibility": reproducibility,
    })
}

/// `crbs builds show <id>`：本地展示产物列表。
async fn handle_show(
    id: i64,
    format: OutputFormat,
    ctx: &crbs_core::privilege::CallerContext,
    state: &StateStore,
) -> Result<()> {
    let build = state
        .get_build(id)
        .await?
        // 不存在 = NotFound（USAGE=4）；id 是 build id（文案对齐 resolve_short_id）。
        .ok_or_else(|| crbs_core::error::CrbsError::NotFound {
            message: format!("Build {id} not found. Run 'crbs status' to list builds."),
        })?;

    // 权限校验（PERMISSION(5)）：本地入口不经 resolve_short_id 的 user_filter，归属显式判定。
    crate::cmd::ensure_record_owner("build", id, &build.user, ctx)?;

    let artifacts = state.list_artifacts(id).await?;

    // 最新比对行可能来自 source 或 replay 侧。
    let reproducibility = state.latest_reproducibility_for_build(id).await?;

    match format {
        OutputFormat::Json => {
            let output = build_show_json(id, &build, &artifacts, &reproducibility);
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Text => {
            println!("Build #{}: {} ({})", id, build.pkg_name, build.phase);
            println!("Product: {}", build.product);
            // 双轴生效值标注（提交时快照）：发布侧产物进不进 repo、消费侧
            // builddep 吃不吃 repo；unpublish 会翻 publish 臂。
            let mark = |on: bool| if on { "✓" } else { "✗" };
            println!(
                "Repo: publish{} consume{}",
                mark(build.repo_publish),
                mark(build.repo_consume)
            );
            if build.deterministic {
                println!("Deterministic: yes");
            }
            if let Some(r) = &reproducibility {
                let replay_label = r
                    .replay_build_id
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "Reproducibility: {} (kind={}, source={}, replay={}, compared_at={})",
                    r.verdict, r.kind, r.source_build_id, replay_label, r.compared_at
                );
            }
            println!();

            if artifacts.is_empty() {
                println!("(no artifacts found)");
                return Ok(());
            }

            let mut table = new_artifact_table();
            table.set_header(vec![
                Cell::new("Type"),
                Cell::new("Size"),
                Cell::new("Signed"),
                Cell::new("Path"),
            ]);

            for a in &artifacts {
                let kind_color = match a.kind.as_str() {
                    "rpm" => Color::Green,
                    "srpm" => Color::Magenta,
                    "log" => Color::Blue,
                    _ => Color::DarkGrey,
                };
                let signed = if a.signed { "✓" } else { "" };
                let signed_color = if a.signed {
                    Color::Green
                } else {
                    Color::DarkGrey
                };

                table.add_row(vec![
                    Cell::new(a.kind.as_str()).fg(kind_color),
                    Cell::new(humansize::format_size(a.size_bytes, humansize::BINARY)),
                    Cell::new(signed).fg(signed_color),
                    Cell::new(&a.relative_path),
                ]);
            }

            println!("{}", table);
            println!();
            println!("Total: {} artifact(s)", artifacts.len());

            let rpm_count = artifacts
                .iter()
                .filter(|a| a.kind.as_str() == "rpm")
                .count();
            let srpm_count = artifacts
                .iter()
                .filter(|a| a.kind.as_str() == "srpm")
                .count();
            let log_count = artifacts
                .iter()
                .filter(|a| a.kind.as_str() == "log")
                .count();
            let other_count = artifacts.len() - rpm_count - srpm_count - log_count;

            let mut summary = Vec::new();
            if rpm_count > 0 {
                summary.push(format!("{} RPM(s)", rpm_count));
            }
            if srpm_count > 0 {
                summary.push(format!("{} SRPM(s)", srpm_count));
            }
            if log_count > 0 {
                summary.push(format!("{} log(s)", log_count));
            }
            if other_count > 0 {
                summary.push(format!("{} other(s)", other_count));
            }
            println!("({})", summary.join(", "));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NO_COLOR 判定矩阵（照 status.rs 同款测试形态）：builds 与 status 共用同一
    /// `ansi_allowed` 口径，禁用分支经 force_no_tty 落 `should_style() == false`
    ///（确定性，不依赖真实 stdout），启用分支纯判定一并钉住。
    #[test]
    fn artifact_table_disables_styling_per_ansi_allowed_matrix() {
        use std::ffi::OsStr;
        for (is_tty, no_color) in [
            (true, Some(OsStr::new("1"))),
            (true, Some(OsStr::new("false"))),
            (false, None),
            (false, Some(OsStr::new(""))),
        ] {
            let style = crate::cmd::status::ansi_allowed(is_tty, no_color);
            assert!(
                !style,
                "matrix must disable: is_tty={is_tty} no_color={no_color:?}"
            );
            let table = new_table_with_style(style);
            assert!(
                !table.should_style(),
                "force_no_tty must win for is_tty={is_tty} no_color={no_color:?}"
            );
        }
        assert!(crate::cmd::status::ansi_allowed(true, None));
        assert!(crate::cmd::status::ansi_allowed(true, Some(OsStr::new(""))));
    }

    fn tester_ctx(username: &str, is_root: bool) -> crbs_core::privilege::CallerContext {
        crbs_core::privilege::CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: username.to_string(),
            },
            is_root,
        )
    }

    async fn insert_build_as(store: &StateStore, user: &str) -> i64 {
        // builds.task_id 非空约束：先垫任务行再挂子构建。
        let task_id = store
            .insert_task(crbs_core::TaskInsert {
                product: "fedora",
                pkg_name: "hello",
                user,
                phase: "succeeded",
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "succeeded",
                backend: "chroot",
                user,
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap()
    }

    /// `builds show` 保持 build id 执行域语义——task id 与 build id
    /// 错开时，按 build id 命中、按 task id 查无。
    #[tokio::test]
    async fn builds_show_stays_build_id_domain() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();

        for pkg in ["pad", "hello"] {
            store
                .insert_task(crbs_core::TaskInsert {
                    product: "fedora",
                    pkg_name: pkg,
                    user: "tester",
                    phase: "succeeded",
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        let task_id = 2; // 第二条任务（第一条仅垫号）
        let build_id = store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "succeeded",
                backend: "chroot",
                user: "tester",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(build_id, 1, "first build id");
        assert_ne!(task_id, build_id, "fixture requires disjoint ids");

        let ctx = tester_ctx("tester", false);
        handle_show(build_id, OutputFormat::Json, &ctx, &store)
            .await
            .unwrap();
        let err = handle_show(task_id, OutputFormat::Json, &ctx, &store)
            .await
            .expect_err("task id must not resolve in the build domain");
        assert!(
            err.to_string()
                .contains(&format!("Build {task_id} not found")),
            "unexpected message: {err}"
        );
    }

    /// 双轴标注透出：show JSON 体含 repo_publish / repo_consume 两键；
    /// 旧记录 JSON（缺列）反序列化按默认——publish 收紧侧 false、consume 默认 true。
    #[test]
    fn builds_show_json_exposes_repo_axes() {
        let build = crbs_core::BuildRecord {
            id: 1,
            product: "fedora".into(),
            pkg_name: "hello".into(),
            name: "hello".into(),
            version: "1.0".into(),
            release: "1".into(),
            phase: "succeeded".into(),
            result_dir: None,
            srpm_path: None,
            started_at: None,
            completed_at: None,
            duration: None,
            layer_digest: None,
            base_os_digest: None,
            backend: Some("chroot".into()),
            user: "tester".into(),
            user_id: None,
            crbs_pid: None,
            rpms: Vec::new(),
            signed: false,
            priority: 0,
            arch: Some("x86_64".into()),
            task_id: Some(1),
            error_summary: None,
            deterministic: false,
            repo_publish: false,
            repo_consume: false,
            canonical_srpm_sha256: None,
            peak_rss_kb: None,
            peak_total_kb: None,
            cpu_secs: None,
            cpu_p90_cores: None,
            disk_wbytes: None,
            oom_killed: None,
            sample_backend: None,
            sample_ncpu: None,
            peak_tmpfs_kb: None,
            req_min_mem_kb: None,
            req_min_ncpu: None,
            req_min_disk_kb: None,
        };
        let json = build_show_json(1, &build, &[], &None);
        assert_eq!(json["repo_publish"], serde_json::json!(false));
        assert_eq!(json["repo_consume"], serde_json::json!(false));

        let legacy = r#"{"id": 1, "product": "fedora", "pkg_name": "hello", "name": "hello",
            "version": "1.0", "release": "1", "phase": "succeeded", "user": "",
            "signed": false, "priority": 0, "deterministic": false}"#;
        let old: crbs_core::BuildRecord = serde_json::from_str(legacy).unwrap();
        assert!(
            !old.repo_publish,
            "missing publish flag defaults to tightened"
        );
        assert!(
            old.repo_consume,
            "missing consume flag defaults to consuming"
        );
    }

    /// 归属校验：非 root 查他人 build → PermissionDenied（PERMISSION=5）。
    #[tokio::test]
    async fn builds_show_rejects_other_users_build_for_non_root() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();
        let build_id = insert_build_as(&store, "alice").await;

        let err = handle_show(
            build_id,
            OutputFormat::Json,
            &tester_ctx("tester", false),
            &store,
        )
        .await
        .expect_err("non-root must not read another user's build");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::PermissionDenied { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_core::exit_code::crbs_error_exit_code(ce), 5);
    }

    /// root 不受归属限制（与 logs/diff/download 同口径）。
    #[tokio::test]
    async fn builds_show_allows_root_to_read_any_users_build() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();
        let build_id = insert_build_as(&store, "alice").await;

        handle_show(
            build_id,
            OutputFormat::Json,
            &tester_ctx("tester", true),
            &store,
        )
        .await
        .expect("root must bypass the ownership check");
    }

    /// 历史遗留记录 user 为空串（无属主）时放行，不误伤存量数据。
    #[tokio::test]
    async fn builds_show_allows_empty_owner_build() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();
        let build_id = insert_build_as(&store, "").await;

        handle_show(
            build_id,
            OutputFormat::Json,
            &tester_ctx("tester", false),
            &store,
        )
        .await
        .expect("legacy owner-less records must stay readable");
    }
}
