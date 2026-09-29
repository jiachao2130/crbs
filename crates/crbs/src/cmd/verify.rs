// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use anyhow::Result;
use std::collections::BTreeMap;

use crate::cli::OutputFormat;
use crbs_core::privilege::CallerContext;
use crbs_core::StateStore;

#[derive(serde::Serialize, Debug)]
struct RpmEntry {
    file: String,
    task_a_sha256: Option<String>,
    task_b_sha256: Option<String>,
}

#[derive(serde::Serialize)]
struct VerifyOutput {
    command: &'static str,
    task_a: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    task_b: Option<i64>,
    verdict: &'static str,
    same: Vec<String>,
    diff: Vec<RpmEntry>,

    internal_conflicts: Vec<String>,
}

#[derive(Debug)]
struct CompareResult {
    same: Vec<String>,
    diff: Vec<RpmEntry>,
    internal_conflicts: Vec<String>,
    verdict: &'static str,

    no_succeeded: bool,
}

pub(crate) async fn handle_verify(
    task_a: i64,
    task_b: Option<i64>,
    format: OutputFormat,
    ctx: &CallerContext,
    state: &StateStore,
) -> Result<()> {
    let core = verify_tasks(task_a, task_b, ctx, state).await?;

    let out = VerifyOutput {
        command: "verify",
        task_a,
        task_b,
        verdict: core.verdict,
        same: core.same,
        diff: core.diff,
        internal_conflicts: core.internal_conflicts,
    };
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&out)?),
        OutputFormat::Text => {
            let b_label = task_b
                .map(|t| t.to_string())
                .unwrap_or_else(|| format!("{task_a} (internal consistency)"));
            println!("verify: task {} vs {}", task_a, b_label);
            println!("verdict: {}", out.verdict);
            println!("  same: {} file(s)", out.same.len());
            if !out.diff.is_empty() {
                println!("  diff:");
                for e in &out.diff {
                    println!("    {}", e.file);
                    if let Some(a) = &e.task_a_sha256 {
                        println!("      task {}: {}", out.task_a, a);
                    } else {
                        println!("      task {}: <missing>", out.task_a);
                    }
                    if let Some(b) = &e.task_b_sha256 {
                        println!("      task {b_label}: {b}");
                    } else {
                        println!("      task {b_label}: <missing>");
                    }
                }
            }
            if !out.internal_conflicts.is_empty() {
                println!("  internal conflicts (same file, different hashes within a task):");
                for c in &out.internal_conflicts {
                    println!("    {c}");
                }
            }
        }
    }
    if core.no_succeeded {
        return Err(crbs_core::error::CrbsError::SilentExit {
            code: crbs_core::exit_code::USAGE,
        }
        .into());
    }
    Ok(())
}

async fn verify_tasks(
    task_a: i64,
    task_b: Option<i64>,
    ctx: &CallerContext,
    state: &StateStore,
) -> Result<CompareResult> {
    for tid in std::iter::once(task_a).chain(task_b) {
        let task = state
            .get_task(tid)
            .await?
            .ok_or_else(|| crate::cmd::task_not_found(tid))?;
        crate::cmd::ensure_record_owner("task", tid, &task.user, ctx)?;
    }

    let (map_a, conflicts_a, succeeded_a) = task_rpm_map(state, task_a).await?;
    let (map_b, conflicts_b, succeeded_b) = match task_b {
        Some(tb) => task_rpm_map(state, tb).await?,

        None => (BTreeMap::new(), Vec::new(), 0),
    };

    let no_succeeded = succeeded_a == 0 || (task_b.is_some() && succeeded_b == 0);

    let mut same = Vec::new();
    let mut diff = Vec::new();
    if task_b.is_some() && !no_succeeded {
        let mut files: Vec<&String> = map_a.keys().collect();
        files.extend(map_b.keys());
        files.sort_unstable();
        files.dedup();
        for file in files {
            let a = map_a.get(file);
            let b = map_b.get(file);
            match (a, b) {
                (Some(x), Some(y)) if x == y => same.push(file.clone()),
                _ => diff.push(RpmEntry {
                    file: file.clone(),
                    task_a_sha256: a.cloned(),
                    task_b_sha256: b.cloned(),
                }),
            }
        }
    }
    let mut internal_conflicts = conflicts_a;
    internal_conflicts.extend(conflicts_b);

    if !no_succeeded {
        let comparable = if task_b.is_some() {
            !same.is_empty() || !diff.is_empty()
        } else {
            !map_a.is_empty()
        };
        if !comparable {
            return Err(crbs_core::error::CrbsError::NotFound {
                message: match task_b {
                    Some(b) => format!(
                        "no comparable artifacts found between task {task_a} and task {b} \
                         (no RPM artifacts in either task's results)"
                    ),
                    None => {
                        format!("no comparable artifacts found in task {task_a} (no RPM artifacts)")
                    }
                },
            }
            .into());
        }
    }

    let verdict = if no_succeeded {
        "no succeeded builds"
    } else if task_b.is_none() {
        if internal_conflicts.is_empty() {
            "same"
        } else {
            "diff"
        }
    } else if diff.is_empty() && internal_conflicts.is_empty() {
        "same"
    } else {
        "diff"
    };

    Ok(CompareResult {
        same,
        diff,
        internal_conflicts,
        verdict,
        no_succeeded,
    })
}

async fn task_rpm_map(
    state: &StateStore,
    task_id: i64,
) -> Result<(BTreeMap<String, String>, Vec<String>, usize)> {
    let children = state.get_builds_by_task_id(task_id).await?;
    let mut succeeded: Vec<crbs_core::BuildRecord> = children
        .iter()
        .filter(|c| c.phase == "succeeded")
        .cloned()
        .collect();

    succeeded.sort_by_key(|c| c.id);
    if succeeded.is_empty() {
        return Ok((BTreeMap::new(), Vec::new(), 0));
    }
    let ids: Vec<i64> = succeeded.iter().map(|c| c.id).collect();
    let artifacts = state.list_artifacts_for_builds(&ids).await?;
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let mut conflicts: Vec<String> = Vec::new();

    for child in &succeeded {
        let rows: Vec<(String, String)> = artifacts
            .iter()
            .filter(|a| a.build_id == child.id && a.kind.as_str() == "rpm")
            .map(|a| {
                (
                    artifact_file_name(&a.relative_path),
                    a.unsigned_sha256
                        .clone()
                        .unwrap_or_else(|| a.sha256.clone()),
                )
            })
            .collect();
        let rows = if rows.is_empty() {
            disk_rpm_hashes(child).await?
        } else {
            rows
        };
        for (file, sha) in rows {
            match map.get(file.as_str()) {
                Some(existing) if *existing != sha => {
                    conflicts.push(format!("{file}: {existing} vs {sha} (build {})", child.id));
                }
                Some(_) => {}
                None => {
                    map.insert(file, sha);
                }
            }
        }
    }
    Ok((map, conflicts, succeeded.len()))
}

fn artifact_file_name(relative_path: &str) -> String {
    std::path::Path::new(relative_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| relative_path.to_string())
}

/// DB 无 rpm artifact 行的构建回退：扫 `{result_dir}/RPMS`（一层下钻）取在盘
/// 二进制 RPM 实算 sha256（as-built 字节，与 unsigned_sha256 同口径；`.src.rpm`
/// 不参与比对，同 DB 侧 kind 过滤）。结果目录缺失（已 GC）返回空集，交由零
/// 可比对判定如实报错。
async fn disk_rpm_hashes(child: &crbs_core::BuildRecord) -> Result<Vec<(String, String)>> {
    let Some(result_dir) = child.result_dir.as_deref() else {
        return Ok(Vec::new());
    };
    let rpms_dir = std::path::Path::new(result_dir).join("RPMS");
    let mut out = Vec::new();
    for rpm in crbs_core::engine::artifact_harvest::rpms_under(&rpms_dir).await {
        let Some(file) = rpm.file_name().map(|s| s.to_string_lossy().to_string()) else {
            continue;
        };
        if file.ends_with(".src.rpm") {
            continue;
        }
        let sha = crbs_core::engine::artifact_harvest::sha256_file(&rpm).await?;
        out.push((file, sha));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crbs_core::privilege::CallerInfo;

    fn tester_ctx(username: &str, is_root: bool) -> CallerContext {
        CallerContext::new(
            CallerInfo {
                uid: 1000,
                gid: 1000,
                username: username.to_string(),
            },
            is_root,
        )
    }

    async fn seed_task(store: &StateStore, pkg: &str, phase: &str, user: &str) -> i64 {
        store
            .insert_task(crbs_core::TaskInsert {
                product: "fedora",
                pkg_name: pkg,
                user,
                phase,
                ..Default::default()
            })
            .await
            .unwrap()
    }

    async fn seed_succeeded_build(store: &StateStore, task_id: i64, pkg: &str) -> i64 {
        store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: pkg,
                phase: "succeeded",
                backend: "chroot",
                user: "tester",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap()
    }

    async fn seed_rpm_artifact(
        store: &StateStore,
        build_id: i64,
        file_name: &str,
        unsigned_sha256: &str,
        sha256: &str,
    ) {
        let a = crbs_core::NewArtifact {
            relative_path: format!("RPMS/x86_64/{file_name}"),
            kind: crbs_core::ArtifactKind::Rpm,
            size_bytes: 10,
            sha256: sha256.to_string(),
            unsigned_sha256: Some(unsigned_sha256.to_string()),
            arch: Some("x86_64".to_string()),
            name: None,
            version: None,
            release: None,
            epoch: None,
            metadata_json: None,
            signed: false,
        };
        let mut tx = store.pool().begin().await.unwrap();
        store
            .insert_artifacts_tx(
                &mut tx,
                build_id,
                std::slice::from_ref(&a),
                "2026-01-01 00:00:00",
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn single_task_without_succeeded_builds_exits_usage() {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateStore::new(tmp.path()).await.unwrap();
        let task_id = seed_task(&state, "failed-pkg-1.0-1", "failed", "tester").await;

        let err = handle_verify(
            task_id,
            None,
            OutputFormat::Text,
            &tester_ctx("tester", false),
            &state,
        )
        .await
        .expect_err("zero succeeded builds must exit non-zero");
        match err.downcast_ref::<crbs_core::error::CrbsError>() {
            Some(crbs_core::error::CrbsError::SilentExit { code }) => {
                assert_eq!(*code, crbs_core::exit_code::USAGE);
            }
            other => panic!("expected SilentExit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn single_task_with_succeeded_build_reports_same_and_empty_diff() {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateStore::new(tmp.path()).await.unwrap();
        let task_id = seed_task(&state, "ok-pkg-1.0-1", "succeeded", "tester").await;
        let build_id = seed_succeeded_build(&state, task_id, "ok-pkg-1.0-1").await;
        seed_rpm_artifact(
            &state,
            build_id,
            "ok-pkg-1.0-1.x86_64.rpm",
            "hash-a",
            "hash-a",
        )
        .await;

        let core = verify_tasks(task_id, None, &tester_ctx("tester", false), &state)
            .await
            .expect("internally consistent single task must verify");
        assert_eq!(core.verdict, "same");
        assert!(
            core.diff.is_empty(),
            "single-task form must not fill diff: {:?}",
            core.diff
        );

        assert!(core.same.is_empty());
        assert!(core.internal_conflicts.is_empty());
    }

    #[tokio::test]
    async fn dual_task_anchor_unsigned_sha256_ignores_signed_drift() {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateStore::new(tmp.path()).await.unwrap();
        let task_a = seed_task(&state, "signed-1.0-1", "succeeded", "tester").await;
        let task_b = seed_task(&state, "signed-1.0-1", "succeeded", "tester").await;
        let file = "signed-1.0-1.x86_64.rpm";
        seed_rpm_artifact(
            &state,
            seed_succeeded_build(&state, task_a, "signed-1.0-1").await,
            file,
            "unsigned-1",
            "signed-1",
        )
        .await;
        seed_rpm_artifact(
            &state,
            seed_succeeded_build(&state, task_b, "signed-1.0-1").await,
            file,
            "unsigned-1",
            "signed-2",
        )
        .await;

        let core = verify_tasks(task_a, Some(task_b), &tester_ctx("tester", false), &state)
            .await
            .unwrap();
        assert_eq!(core.verdict, "same");
        assert_eq!(core.same, vec![file.to_string()]);
        assert!(core.diff.is_empty());
    }

    #[tokio::test]
    async fn single_task_same_file_different_hashes_reports_internal_conflict() {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateStore::new(tmp.path()).await.unwrap();
        let task_id = seed_task(&state, "conflict-1.0-1", "succeeded", "tester").await;
        let file = "conflict-1.0-1.x86_64.rpm";
        seed_rpm_artifact(
            &state,
            seed_succeeded_build(&state, task_id, "conflict-1.0-1").await,
            file,
            "hash-1",
            "hash-1",
        )
        .await;
        seed_rpm_artifact(
            &state,
            seed_succeeded_build(&state, task_id, "conflict-1.0-1").await,
            file,
            "hash-2",
            "hash-2",
        )
        .await;

        let core = verify_tasks(task_id, None, &tester_ctx("tester", false), &state)
            .await
            .unwrap();
        assert_eq!(core.verdict, "diff");
        assert_eq!(core.internal_conflicts.len(), 1);
        let conflict = &core.internal_conflicts[0];
        assert!(
            conflict.contains(file),
            "conflict names the file: {conflict}"
        );
        assert!(conflict.contains("hash-1") && conflict.contains("hash-2"));
        assert!(core.diff.is_empty());
    }

    #[tokio::test]
    async fn verify_foreign_task_as_non_root_is_permission_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateStore::new(tmp.path()).await.unwrap();
        let task_id = seed_task(&state, "foreign-1.0-1", "succeeded", "someone-else").await;

        let err = verify_tasks(task_id, None, &tester_ctx("tester", false), &state)
            .await
            .expect_err("foreign task must be denied for non-root");
        match err.downcast_ref::<crbs_core::error::CrbsError>() {
            Some(crbs_core::error::CrbsError::PermissionDenied { .. }) => {}
            other => panic!("expected PermissionDenied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dual_task_partial_diff_lists_and_exit_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateStore::new(tmp.path()).await.unwrap();
        let task_a = seed_task(&state, "pair-1.0-1", "succeeded", "tester").await;
        let task_b = seed_task(&state, "pair-1.0-1", "succeeded", "tester").await;
        let (f1, f2) = ("pair-1.0-1.x86_64.rpm", "pair-1.0-1.noarch.rpm");
        let build_a = seed_succeeded_build(&state, task_a, "pair-1.0-1").await;
        let build_b = seed_succeeded_build(&state, task_b, "pair-1.0-1").await;
        seed_rpm_artifact(&state, build_a, f1, "h1", "h1").await;
        seed_rpm_artifact(&state, build_a, f2, "h2", "h2").await;
        seed_rpm_artifact(&state, build_b, f1, "h1", "h1").await;
        seed_rpm_artifact(&state, build_b, f2, "h3", "h3").await;

        let core = verify_tasks(task_a, Some(task_b), &tester_ctx("tester", false), &state)
            .await
            .unwrap();
        assert_eq!(core.verdict, "diff");
        assert_eq!(core.same, vec![f1.to_string()]);
        assert_eq!(core.diff.len(), 1);
        assert_eq!(core.diff[0].file, f2);
        assert_eq!(core.diff[0].task_a_sha256.as_deref(), Some("h2"));
        assert_eq!(core.diff[0].task_b_sha256.as_deref(), Some("h3"));

        handle_verify(
            task_a,
            Some(task_b),
            OutputFormat::Text,
            &tester_ctx("tester", false),
            &state,
        )
        .await
        .expect("diff verdict must exit 0 (data command)");
    }

    #[tokio::test]
    async fn dual_task_one_side_zero_succeeded_exits_usage() {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateStore::new(tmp.path()).await.unwrap();
        let task_a = seed_task(&state, "empty-1.0-1", "succeeded", "tester").await;
        let task_b = seed_task(&state, "empty-1.0-1", "failed", "tester").await;
        seed_rpm_artifact(
            &state,
            seed_succeeded_build(&state, task_a, "empty-1.0-1").await,
            "empty-1.0-1.x86_64.rpm",
            "hash-a",
            "hash-a",
        )
        .await;

        let core = verify_tasks(task_a, Some(task_b), &tester_ctx("tester", false), &state)
            .await
            .unwrap();
        assert_eq!(core.verdict, "no succeeded builds");
        assert!(
            core.diff.is_empty(),
            "missing data must not be reported as real diff: {:?}",
            core.diff
        );

        let err = handle_verify(
            task_a,
            Some(task_b),
            OutputFormat::Text,
            &tester_ctx("tester", false),
            &state,
        )
        .await
        .expect_err("one side without succeeded builds must exit non-zero");
        match err.downcast_ref::<crbs_core::error::CrbsError>() {
            Some(crbs_core::error::CrbsError::SilentExit { code }) => {
                assert_eq!(*code, crbs_core::exit_code::USAGE);
            }
            other => panic!("expected SilentExit, got {other:?}"),
        }
    }

    async fn seed_local_succeeded_build(
        store: &StateStore,
        task_id: i64,
        pkg: &str,
        result_dir: &std::path::Path,
    ) -> i64 {
        store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: pkg,
                phase: "succeeded",
                result_dir: result_dir.to_str(),
                backend: "chroot",
                user: "tester",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap()
    }

    async fn write_local_rpm(result_dir: &std::path::Path, file: &str, body: &[u8]) {
        let arch = result_dir.join("RPMS").join("noarch");
        tokio::fs::create_dir_all(&arch).await.unwrap();
        tokio::fs::write(arch.join(file), body).await.unwrap();
    }

    #[tokio::test]
    async fn dual_task_disk_fallback_compares_local_result_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateStore::new(tmp.path()).await.unwrap();
        let task_a = seed_task(&state, "local-1.0-1", "succeeded", "tester").await;
        let task_b = seed_task(&state, "local-1.0-1", "succeeded", "tester").await;
        let file = "local-1.0-1.noarch.rpm";
        let dir_a = tmp.path().join("results-a");
        let dir_b = tmp.path().join("results-b");
        write_local_rpm(&dir_a, file, b"identical-bytes").await;
        write_local_rpm(&dir_b, file, b"identical-bytes").await;
        seed_local_succeeded_build(&state, task_a, "local-1.0-1", &dir_a).await;
        seed_local_succeeded_build(&state, task_b, "local-1.0-1", &dir_b).await;

        let core = verify_tasks(task_a, Some(task_b), &tester_ctx("tester", false), &state)
            .await
            .unwrap();
        assert_eq!(core.verdict, "same");
        assert_eq!(core.same, vec![file.to_string()]);
        assert!(core.diff.is_empty());
    }

    #[tokio::test]
    async fn dual_task_disk_fallback_reports_byte_diff() {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateStore::new(tmp.path()).await.unwrap();
        let task_a = seed_task(&state, "drift-1.0-1", "succeeded", "tester").await;
        let task_b = seed_task(&state, "drift-1.0-1", "succeeded", "tester").await;
        let file = "drift-1.0-1.noarch.rpm";
        let dir_a = tmp.path().join("results-a");
        let dir_b = tmp.path().join("results-b");
        write_local_rpm(&dir_a, file, b"build-time-1791792817").await;
        write_local_rpm(&dir_b, file, b"build-time-1791792899").await;
        seed_local_succeeded_build(&state, task_a, "drift-1.0-1", &dir_a).await;
        seed_local_succeeded_build(&state, task_b, "drift-1.0-1", &dir_b).await;

        let core = verify_tasks(task_a, Some(task_b), &tester_ctx("tester", false), &state)
            .await
            .unwrap();
        assert_eq!(core.verdict, "diff");
        assert_eq!(core.diff.len(), 1);
        assert_eq!(core.diff[0].file, file);
        assert!(core.diff[0].task_a_sha256.is_some());
        assert!(core.diff[0].task_b_sha256.is_some());
        assert_ne!(core.diff[0].task_a_sha256, core.diff[0].task_b_sha256);
    }

    #[tokio::test]
    async fn dual_task_zero_comparable_artifacts_is_error() {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateStore::new(tmp.path()).await.unwrap();
        let task_a = seed_task(&state, "empty-1.0-1", "succeeded", "tester").await;
        let task_b = seed_task(&state, "empty-1.0-1", "succeeded", "tester").await;
        seed_succeeded_build(&state, task_a, "empty-1.0-1").await;
        seed_succeeded_build(&state, task_b, "empty-1.0-1").await;

        let err = verify_tasks(task_a, Some(task_b), &tester_ctx("tester", false), &state)
            .await
            .expect_err("zero comparable artifacts must be an error, not 'same'");
        match err.downcast_ref::<crbs_core::error::CrbsError>() {
            Some(crbs_core::error::CrbsError::NotFound { message }) => {
                assert!(
                    message.contains("no comparable artifacts found"),
                    "message must name the condition: {message}"
                );
                assert!(message.contains(&task_a.to_string()));
                assert!(message.contains(&task_b.to_string()));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn single_task_zero_comparable_artifacts_is_error() {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateStore::new(tmp.path()).await.unwrap();
        let task_id = seed_task(&state, "bare-1.0-1", "succeeded", "tester").await;
        seed_succeeded_build(&state, task_id, "bare-1.0-1").await;

        let err = verify_tasks(task_id, None, &tester_ctx("tester", false), &state)
            .await
            .expect_err("zero comparable artifacts must be an error, not 'same'");
        match err.downcast_ref::<crbs_core::error::CrbsError>() {
            Some(crbs_core::error::CrbsError::NotFound { message }) => {
                assert!(
                    message.contains("no comparable artifacts found"),
                    "message must name the condition: {message}"
                );
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dual_task_gc_result_dirs_fall_into_zero_comparable_error() {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateStore::new(tmp.path()).await.unwrap();
        let task_a = seed_task(&state, "gc-1.0-1", "succeeded", "tester").await;
        let task_b = seed_task(&state, "gc-1.0-1", "succeeded", "tester").await;
        let gone_a = tmp.path().join("gc'd-a");
        let gone_b = tmp.path().join("gc'd-b");
        seed_local_succeeded_build(&state, task_a, "gc-1.0-1", &gone_a).await;
        seed_local_succeeded_build(&state, task_b, "gc-1.0-1", &gone_b).await;

        let err = verify_tasks(task_a, Some(task_b), &tester_ctx("tester", false), &state)
            .await
            .expect_err("missing result dirs must yield zero comparable artifacts");
        assert!(matches!(
            err.downcast_ref::<crbs_core::error::CrbsError>(),
            Some(crbs_core::error::CrbsError::NotFound { .. })
        ));
    }
}
