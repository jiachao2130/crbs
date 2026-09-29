// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crbs_core::error::CrbsError;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SrpmStagingDecision {
    Keep {
        path: PathBuf,
        rpm_error: Option<String>,
    },

    Stage {
        nevr: String,
        source: PathBuf,
    },
}

fn srpm_name_stem(path: &std::path::Path) -> Option<&str> {
    path.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix(".src.rpm"))
}

/// 落名 planner（纯函数）：逐文件决定直通 / 落名，批内 nevr 唯一——不同文件同 nevr 拒绝（pkg_name 直接决定结果目录，同 nevr 双输入会互写同一目录）；
/// 同一路径重复出现按同一落名复用。header 探测失败回退 srpm_pkg_name 结构校验：结构合法则直通（附 rpm 失败原因供调用方 warn）；结构也非法则拒绝。
pub(crate) fn plan_srpm_staging(
    entries: Vec<(PathBuf, crbs_core::Result<String>)>,
) -> anyhow::Result<Vec<SrpmStagingDecision>> {
    let mut by_nevr: HashMap<String, PathBuf> = HashMap::new();
    let mut decisions = Vec::with_capacity(entries.len());
    for (path, meta) in entries {
        let decision = match meta {
            Ok(nevr) => {
                match by_nevr.get(&nevr) {
                    Some(prev) if prev != &path => {
                        return Err(CrbsError::ValidationFailed {
                            message: format!(
                                "two input SRPMs resolve to the same N-V-R {nevr}: {} and {}; \
                                 remove the duplicate input",
                                prev.display(),
                                path.display()
                            ),
                        }
                        .into());
                    }
                    None => {
                        by_nevr.insert(nevr.clone(), path.clone());
                    }
                    Some(_) => {}
                }
                match srpm_name_stem(&path) {
                    Some(stem) if stem == nevr => SrpmStagingDecision::Keep {
                        path,
                        rpm_error: None,
                    },
                    _ => SrpmStagingDecision::Stage { nevr, source: path },
                }
            }
            Err(rpm_error) => match crbs_core::engine::srpm_pkg_name(&path) {
                Ok(_) => SrpmStagingDecision::Keep {
                    path,
                    rpm_error: Some(rpm_error.to_string()),
                },
                Err(name_err) => {
                    return Err(anyhow::Error::new(name_err).context(format!(
                        "cannot determine the real N-V-R of {}: rpm -qp failed ({rpm_error}); \
                         the file name must be N-V-R.src.rpm and match the SRPM header",
                        path.display()
                    )));
                }
            },
        };
        decisions.push(decision);
    }
    Ok(decisions)
}

/// 批量落名暂存：header N-V-R 批量探测 + planner 决策 + 符号链接落名。返回与输入严格同序同长的新 inputs；仅存在需落名文件时才建 TempDir，
/// 随机唯一名即满足并发命名空间隔离。TempDir 须由调用方绑定活过整个构建 await，drop 自动清理且只删自己命名空间。
pub(crate) async fn stage_srpm_inputs(
    inputs: Vec<PathBuf>,
    cancel_token: Option<&CancellationToken>,
) -> anyhow::Result<(Vec<PathBuf>, Option<tempfile::TempDir>)> {
    let metas = crbs_core::engine::depsolve::parse_nevr_from_srpms(&inputs, cancel_token).await;
    let entries: Vec<(PathBuf, crbs_core::Result<String>)> =
        inputs.into_iter().zip(metas).collect();
    let plan = plan_srpm_staging(entries)?;

    let mut staging_dir: Option<tempfile::TempDir> = None;

    let mut created: HashSet<String> = HashSet::new();
    let mut staged = Vec::with_capacity(plan.len());
    for decision in plan {
        match decision {
            SrpmStagingDecision::Keep { path, rpm_error } => {
                if let Some(reason) = rpm_error {
                    warn!(
                        srpm = %path.display(),
                        reason = %reason,
                        "SRPM header N-V-R probe failed; trusting the file name structure"
                    );
                }
                staged.push(path);
            }
            SrpmStagingDecision::Stage { nevr, source } => {
                let dir = match &staging_dir {
                    Some(d) => d.path().to_path_buf(),
                    None => {
                        let d = tempfile::TempDir::new().map_err(|e| {
                            CrbsError::from_io_context("create SRPM staging tempdir", e)
                        })?;
                        let path = d.path().to_path_buf();
                        staging_dir = Some(d);
                        path
                    }
                };
                if created.insert(nevr.clone()) {
                    let target = tokio::fs::canonicalize(&source).await.map_err(|e| {
                        CrbsError::from_io_context(
                            format!("canonicalize SRPM {}", source.display()),
                            e,
                        )
                    })?;
                    let link = dir.join(format!("{}.src.rpm", nevr));
                    tokio::fs::symlink(&target, &link)
                        .await
                        .map_err(|e| CrbsError::from_io_context("create staged SRPM symlink", e))?;
                    info!(
                        srpm = %source.display(),
                        nevr = %nevr,
                        staged = %link.display(),
                        "SRPM staged under header N-V-R name"
                    );
                }
                staged.push(dir.join(format!("{}.src.rpm", nevr)));
            }
        }
    }
    Ok((staged, staging_dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn planner_keeps_path_when_name_matches_header() {
        let path = PathBuf::from("/srv/SRPMS/hello-1.0-1.src.rpm");
        let plan = plan_srpm_staging(vec![(path.clone(), Ok("hello-1.0-1".into()))]).unwrap();
        assert_eq!(
            plan,
            vec![SrpmStagingDecision::Keep {
                path,
                rpm_error: None,
            }]
        );
    }

    #[test]
    fn planner_stages_when_name_differs_from_header() {
        let path = PathBuf::from("/srv/SRPMS/81971ed44391c39ddf0b65abc41505d5c290ebc3.src.rpm");
        let plan = plan_srpm_staging(vec![(path.clone(), Ok("hello-1.0-1".into()))]).unwrap();
        assert_eq!(
            plan,
            vec![SrpmStagingDecision::Stage {
                nevr: "hello-1.0-1".into(),
                source: path,
            }]
        );
    }

    #[test]
    fn planner_falls_back_to_filename_when_probe_fails() {
        let path = PathBuf::from("/srv/SRPMS/hello-1.0-1.src.rpm");
        let rpm_err = crbs_core::error::CrbsError::DepsolveFailed {
            message: "rpm -qp NEVR for ...: exit 1".into(),
        };
        let plan = plan_srpm_staging(vec![(path.clone(), Err(rpm_err))]).unwrap();
        match &plan[..] {
            [SrpmStagingDecision::Keep {
                path: p,
                rpm_error: Some(reason),
            }] => {
                assert_eq!(p, &path);
                assert!(reason.contains("exit 1"), "reason must carry rpm detail");
            }
            other => panic!("unexpected plan: {other:?}"),
        }
    }

    #[test]
    fn planner_rejects_when_probe_and_filename_both_fail() {
        let path = PathBuf::from("/srv/SRPMS/81971ed4.src.rpm");
        let rpm_err = crbs_core::error::CrbsError::DepsolveFailed {
            message: "rpm -qp NEVR: not an rpm package".into(),
        };
        let err = plan_srpm_staging(vec![(path, Err(rpm_err))]).unwrap_err();
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("context chain must keep CrbsError for exit-code mapping");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::ValidationFailed { message }
                if message.contains("malformed SRPM file name")),
            "core文案 must be preserved verbatim, got: {ce}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("not an rpm package") && msg.contains("N-V-R.src.rpm"),
            "context must add rpm reason and naming hint, got: {msg}"
        );
    }

    #[test]
    fn planner_rejects_two_files_with_same_nevr() {
        let keep = PathBuf::from("/srv/SRPMS/a-1.0-1.src.rpm");
        let stage = PathBuf::from("/srv/SRPMS/aaaa.src.rpm");
        let err = plan_srpm_staging(vec![
            (keep, Ok("a-1.0-1".into())),
            (stage, Ok("a-1.0-1".into())),
        ])
        .unwrap_err();
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must be CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::ValidationFailed { message }
                if message.contains("a-1.0-1") && message.contains("same N-V-R")),
            "got: {ce}"
        );

        let err = plan_srpm_staging(vec![
            (
                PathBuf::from("/srv/SRPMS/bbbb.src.rpm"),
                Ok("a-1.0-1".into()),
            ),
            (
                PathBuf::from("/srv/SRPMS/cccc.src.rpm"),
                Ok("a-1.0-1".into()),
            ),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("same N-V-R"), "got: {err}");
    }

    #[test]
    fn planner_reuses_staging_for_duplicate_path() {
        let path = PathBuf::from("/srv/SRPMS/81971ed4.src.rpm");
        let plan = plan_srpm_staging(vec![
            (path.clone(), Ok("a-1.0-1".into())),
            (path.clone(), Ok("a-1.0-1".into())),
        ])
        .expect("duplicate path must not be a nevr collision");
        assert_eq!(plan.len(), 2, "决策数须与输入数一致");
        for d in &plan {
            assert_eq!(
                *d,
                SrpmStagingDecision::Stage {
                    nevr: "a-1.0-1".into(),
                    source: path.clone(),
                }
            );
        }
    }

    fn rpm_spawnable() -> bool {
        std::process::Command::new("rpm")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn hello_fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crbs-server/tests/fixtures/hello-1.0-1.src.rpm")
    }

    #[tokio::test]
    async fn stage_srpm_inputs_renames_hash_named_srpm_to_header_nvr() {
        if !rpm_spawnable() {
            eprintln!("skipping: rpm not available");
            return;
        }
        let fixture = hello_fixture();
        let work = tempfile::tempdir().unwrap();
        let hash_named = work
            .path()
            .join("81971ed44391c39ddf0b65abc41505d5c290ebc3.src.rpm");
        std::fs::copy(&fixture, &hash_named).unwrap();

        let (staged, staging) = stage_srpm_inputs(vec![hash_named.clone()], None)
            .await
            .unwrap();

        let staging_dir = staging.expect("有落名需求必须建 staging 目录");
        assert_eq!(staged.len(), 1, "长度须与输入一致");
        assert_eq!(
            staged[0].file_name().and_then(|n| n.to_str()),
            Some("hello-1.0-1.src.rpm")
        );
        assert_eq!(
            staged[0].parent(),
            Some(staging_dir.path()),
            "落名文件须位于 staging 目录"
        );

        let link_meta = std::fs::symlink_metadata(&staged[0]).unwrap();
        assert!(link_meta.file_type().is_symlink(), "staged 须是符号链接");
        let via_link = std::fs::read(&staged[0]).unwrap();
        let direct = std::fs::read(&hash_named).unwrap();
        assert_eq!(via_link, direct, "链接解出的内容须等同源文件");

        assert!(staging_dir.path().starts_with(std::env::temp_dir()));
    }

    #[tokio::test]
    async fn stage_srpm_inputs_is_noop_for_canonical_names() {
        if !rpm_spawnable() {
            eprintln!("skipping: rpm not available");
            return;
        }
        let fixture = hello_fixture();
        let work = tempfile::tempdir().unwrap();
        let a = work.path().join("hello-1.0-1.src.rpm");
        std::fs::copy(&fixture, &a).unwrap();

        let (staged, staging) = stage_srpm_inputs(vec![a.clone()], None).await.unwrap();
        assert!(staging.is_none(), "无落名需求不得建 staging 目录");
        assert_eq!(staged, vec![a]);
    }
}
