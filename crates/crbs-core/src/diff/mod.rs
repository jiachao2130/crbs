// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs diff` 核心逻辑：对比两次构建的产物、依赖与 profile 差异。
//!
//! CLI 和 server API 共用此模块，CLI 负责输出格式化，server 负责 JSON 序列化。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::config::CrbsConfig;
use crate::engine::profile::BuildProfile;
use crate::error::CrbsError;
use crate::state::BuildPackage;
use crate::StateStore;

/// 两次构建的对比结果（可直接 JSON 序列化）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiffResult {
    pub left: BuildSummary,
    pub right: BuildSummary,
    pub rpms: RpmDiffSummary,
    pub srpms: RpmDiffSummary,
    pub packages: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileDiff>,
}

/// 单次构建的摘要信息。
///
/// `short_id` 为完整 ID 的字符串形式（如 `"1"`），保留此字段以兼容 API 输出。
#[derive(Debug, Clone, serde::Serialize)]
pub struct BuildSummary {
    pub id: i64,
    #[serde(rename = "short_id")]
    pub short_id: String,
    pub product: String,
    pub pkg_name: String,
    pub backend: Option<String>,
    pub duration: Option<i64>,
    pub phase: String,
}

/// RPM/SRPM 文件的增删改统计。
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct RpmDiffSummary {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
    pub unchanged: usize,
}

/// Profile 阶段耗时差异。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProfileDiff {
    pub left_total: f64,
    pub right_total: f64,
    pub delta: f64,
    pub phases: Vec<String>,
}

/// 计算两次构建的差异。
///
/// `left` 和 `right` 为 build ID 数字字符串（builds.id 精确匹配；与
/// task id 自增序列独立，同数字两义）。
/// `user_filter` 为 Some 时只允许查看该用户名自己的构建（旧记录 user
/// 为空视为无主放行）；`None` 不限制，由调用方按身份裁定（CLI root、
/// server 特权角色传 `None`，受限用户传用户名）。
/// `global` 为调用方世界的全局配置（server 传 pin 到 server root 的
/// `CrbsConfig`，CLI 传引擎配置）：diff 不自己重读 `/etc/crbs/crbs.toml`，
/// 否则 server 侧 pin 的 root 被架空。
pub async fn compute_diff(
    state: &StateStore,
    global: &CrbsConfig,
    left: &str,
    right: &str,
    user_filter: Option<&str>,
) -> crate::Result<DiffResult> {
    let left_id = state.resolve_short_id(left, user_filter).await?;
    let right_id = state.resolve_short_id(right, user_filter).await?;

    let left_record =
        state
            .get_build(left_id)
            .await?
            .ok_or_else(|| CrbsError::ValidationFailed {
                message: format!("Build task {} not found", left_id),
            })?;
    let right_record =
        state
            .get_build(right_id)
            .await?
            .ok_or_else(|| CrbsError::ValidationFailed {
                message: format!("Build task {} not found", right_id),
            })?;

    // 归属复核（resolve_short_id 已查一次，此处纵深防御并映射
    // PermissionDenied）；user 为空的旧记录视为无主放行。
    if let Some(user) = user_filter {
        for record in [&left_record, &right_record] {
            if !record.user.is_empty() && record.user != user {
                return Err(CrbsError::PermissionDenied {
                    message: format!(
                        "Build task {} belongs to '{}', not '{}'",
                        record.id, record.user, user
                    ),
                });
            }
        }
    }

    let left_dir = record_result_dir(&left_record, state, global).await?;
    let right_dir = record_result_dir(&right_record, state, global).await?;

    let left_packages = load_build_packages(&left_dir).await?;
    let right_packages = load_build_packages(&right_dir).await?;
    let left_profile = crate::engine::profile::read_profile(&left_dir).await?;
    let right_profile = crate::engine::profile::read_profile(&right_dir).await?;

    let left_rpms = collect_rpm_dump(&left_dir.join("RPMS")).await?;
    let right_rpms = collect_rpm_dump(&right_dir.join("RPMS")).await?;
    let left_srpms = collect_rpm_dump(&left_dir.join("SRPMS")).await?;
    let right_srpms = collect_rpm_dump(&right_dir.join("SRPMS")).await?;

    let rpms = rpm_summary(&left_rpms, &right_rpms);
    let srpms = rpm_summary(&left_srpms, &right_srpms);
    let packages = package_diff(&left_packages, &right_packages);
    let profile = match (left_profile.as_ref(), right_profile.as_ref()) {
        (Some(left), Some(right)) => {
            let phases = profile_phase_diff(left, right);
            Some(ProfileDiff {
                left_total: left.total_seconds,
                right_total: right.total_seconds,
                delta: right.total_seconds - left.total_seconds,
                phases,
            })
        }
        _ => None,
    };

    Ok(DiffResult {
        left: build_summary(&left_record),
        right: build_summary(&right_record),
        rpms,
        srpms,
        packages,
        profile,
    })
}

fn build_summary(record: &crate::BuildRecord) -> BuildSummary {
    BuildSummary {
        id: record.id,
        short_id: record.id.to_string(),
        product: record.product.clone(),
        pkg_name: record.pkg_name.clone(),
        backend: record.backend.clone(),
        duration: record.duration,
        phase: record.phase.clone(),
    }
}

async fn record_result_dir(
    record: &crate::BuildRecord,
    state: &StateStore,
    global: &CrbsConfig,
) -> crate::Result<PathBuf> {
    match record.result_dir.as_ref() {
        Some(d) => {
            // 产品配置不读磁盘 `products/*.toml`：由注入的 StateStore 从 DB
            // chain-resolve 出合并 Config，取 `result_dir` 做安全根校验。
            // 全局层用调用方注入的世界配置（与结果 GC with_root 同口径）：
            // 重读 /etc/crbs/crbs.toml 会把 server 侧 pin 的 root 架空——
            // server-only / root 不一致部署下 diff 对合法 result_dir 全部拒绝。
            let cfg = state
                .load_merged_config_for_product_with_root(&record.product, global)
                .await?;
            crate::util::validate_result_dir(d, &cfg.result_dir).await
        }
        None => Err(CrbsError::io_message(format!(
            "Build task {} result directory has been cleaned",
            record.id
        ))),
    }
}

async fn load_build_packages(result_dir: &Path) -> crate::Result<Vec<BuildPackage>> {
    let path = result_dir.join("build_packages.json");
    let content = match tokio::fs::read_to_string(&path).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(CrbsError::from_io_context(
                format!("read {}", path.display()),
                e,
            ))
        }
    };
    serde_json::from_str::<Vec<BuildPackage>>(&content).map_err(|e| {
        CrbsError::Internal(format!("parse build packages at {}: {}", path.display(), e))
    })
}

#[derive(Debug)]
struct RpmDump {
    file_name: String,
    dump: Vec<String>,
}

/// 递归扫描目录下所有 RPM/SRPM，并对每个包执行 `rpm -qlp --dump`；
/// 根目录不存在按空结果处理（缺 RPMS/ 子目录仅跳过）。
async fn collect_rpm_dump(dir: &Path) -> crate::Result<Vec<RpmDump>> {
    let mut dumps = Vec::new();
    let mut dirs: Vec<PathBuf> = vec![dir.to_path_buf()];

    while let Some(current) = dirs.pop() {
        let mut entries = match tokio::fs::read_dir(&current).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if current == dir {
                    return Ok(dumps);
                }
                continue;
            }
            Err(e) => {
                return Err(CrbsError::from_io_context(
                    format!("read_dir {}", current.display()),
                    e,
                ))
            }
        };

        while let Some(entry) = match entries.next_entry().await {
            Ok(entry) => entry,
            Err(e) => {
                return Err(CrbsError::from_io_context(
                    format!("read_dir {}", current.display()),
                    e,
                ))
            }
        } {
            let path = entry.path();
            let file_type = match entry.file_type().await {
                Ok(t) => t,
                Err(e) => {
                    return Err(CrbsError::from_io_context(
                        format!("stat {}", path.display()),
                        e,
                    ))
                }
            };

            if file_type.is_dir() {
                dirs.push(path);
                continue;
            }

            if path.extension().map(|e| e == "rpm").unwrap_or(false) {
                let file_name = path
                    .file_name()
                    .ok_or_else(|| {
                        CrbsError::io_message(format!(
                            "diff rpm path has no file name: {}",
                            path.display()
                        ))
                    })?
                    .to_string_lossy()
                    .to_string();
                let mut cmd = tokio::process::Command::new("rpm");
                cmd.args(["-qlp", "--dump"]).arg(&path);
                // 60s 单包预算：停滞存储上挂死的 rpm 不得无限占用 diff future
                //（对齐 repo.rs rpm_query_release 的单包查询预算）。
                let output = crate::engine::command::run_command_capped_output_with_timeout(
                    cmd,
                    "spawn rpm -qlp --dump",
                    std::time::Duration::from_secs(60),
                )
                .await?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(CrbsError::io_message(format!(
                        "rpm -qlp --dump failed for {}: {}",
                        path.display(),
                        stderr
                    )));
                }
                // dump 输出按行 1:1 进 diff 结果：大 -debuginfo 包（数十万文件）
                // 超 32MB 截断时静默继续会把"缺文件"当 diff 结论——fail-closed。
                if crate::engine::command::output_hit_capture_cap(&output) {
                    return Err(CrbsError::io_message(format!(
                        "rpm -qlp --dump output exceeded capture cap for {}",
                        path.display()
                    )));
                }
                let dump = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .map(|s| s.to_string())
                    .collect();
                dumps.push(RpmDump { file_name, dump });
            }
        }
    }

    Ok(dumps)
}

fn rpm_summary(left: &[RpmDump], right: &[RpmDump]) -> RpmDiffSummary {
    let left_names: HashSet<String> = left.iter().map(|r| r.file_name.clone()).collect();
    let right_names: HashSet<String> = right.iter().map(|r| r.file_name.clone()).collect();
    let mut added: Vec<_> = right_names.difference(&left_names).cloned().collect();
    let mut removed: Vec<_> = left_names.difference(&right_names).cloned().collect();
    let left_index: HashMap<&str, &RpmDump> =
        left.iter().map(|r| (r.file_name.as_str(), r)).collect();
    let right_index: HashMap<&str, &RpmDump> =
        right.iter().map(|r| (r.file_name.as_str(), r)).collect();
    let mut changed = Vec::new();
    for name in left_names.intersection(&right_names) {
        if let (Some(left_dump), Some(right_dump)) = (
            left_index.get(name.as_str()),
            right_index.get(name.as_str()),
        ) {
            if left_dump.dump != right_dump.dump {
                changed.push(name.clone());
            }
        }
    }
    added.sort();
    removed.sort();
    changed.sort();
    let unchanged = left_names
        .intersection(&right_names)
        .count()
        .saturating_sub(changed.len());
    RpmDiffSummary {
        added,
        removed,
        changed,
        unchanged,
    }
}

fn package_diff(left: &[BuildPackage], right: &[BuildPackage]) -> Vec<String> {
    let left_map: HashMap<&str, &str> = left
        .iter()
        .map(|p| (p.nevra.as_str(), p.sha256.as_str()))
        .collect();
    let right_map: HashMap<&str, &str> = right
        .iter()
        .map(|p| (p.nevra.as_str(), p.sha256.as_str()))
        .collect();

    let mut lines = Vec::new();
    for (nevra, sha) in &left_map {
        match right_map.get(nevra) {
            Some(rsha) if **rsha != **sha => {
                lines.push(format!("~ {} (sha256 changed)", nevra));
            }
            None => lines.push(format!("- {}", nevra)),
            _ => {}
        }
    }
    for nevra in right_map.keys() {
        if !left_map.contains_key(nevra) {
            lines.push(format!("+ {}", nevra));
        }
    }
    lines.sort();
    lines
}

fn profile_phase_diff(left: &BuildProfile, right: &BuildProfile) -> Vec<String> {
    let left_map: HashMap<&str, f64> = left
        .phases
        .iter()
        .map(|p| (p.name.as_str(), p.duration_seconds))
        .collect();
    let right_map: HashMap<&str, f64> = right
        .phases
        .iter()
        .map(|p| (p.name.as_str(), p.duration_seconds))
        .collect();

    let mut lines = Vec::new();
    for (name, left_sec) in &left_map {
        match right_map.get(name) {
            Some(right_sec) if *right_sec > 0.0 || *left_sec > 0.0 => {
                let delta = right_sec - *left_sec;
                // left 为 0 时百分比无意义（0s → Ns），标记为 new。
                if *left_sec > 0.0 {
                    lines.push(format!(
                        "{}: {:.1}s → {:.1}s ({:+.1}s, {:+.0}%)",
                        name,
                        left_sec,
                        right_sec,
                        delta,
                        delta / *left_sec * 100.0
                    ));
                } else {
                    lines.push(format!(
                        "{}: {:.1}s → {:.1}s ({:+.1}s, new)",
                        name, left_sec, right_sec, delta
                    ));
                }
            }
            None => lines.push(format!("{}: removed", name)),
            _ => {}
        }
    }
    for name in right_map.keys() {
        if !left_map.contains_key(name) {
            lines.push(format!("{}: added", name));
        }
    }
    lines.sort();
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(nevra: &str, sha256: &str) -> BuildPackage {
        BuildPackage {
            build_id: 1,
            nevra: nevra.into(),
            sha256: sha256.into(),
            repo: None,
            url: None,
        }
    }

    fn profile_with_phases(phases: Vec<(&str, f64)>) -> crate::engine::profile::BuildProfile {
        crate::engine::profile::BuildProfile {
            build_id: 1,
            srpm: "x.src.rpm".into(),
            total_seconds: phases.iter().map(|(_, s)| s).sum(),
            shared_layer_hit: false,
            ccache: None,
            phases: phases
                .into_iter()
                .map(
                    |(name, duration_seconds)| crate::engine::profile::BuildPhase {
                        name: name.into(),
                        duration_seconds,
                        skipped: None,
                        reason: None,
                        exit_code: None,
                    },
                )
                .collect(),
        }
    }

    #[test]
    fn package_diff_detects_added_removed_changed() {
        let left = vec![pkg("a-1", "aaa"), pkg("b-1", "bbb"), pkg("d-1", "ddd")];
        let right = vec![pkg("b-1", "bbb"), pkg("c-1", "ccc"), pkg("a-1", "zzz")];
        let diff = package_diff(&left, &right);
        assert!(diff.contains(&"- d-1".to_string()));
        assert!(diff.contains(&"+ c-1".to_string()));
        assert!(diff.iter().any(|s| s.starts_with("~ a-1")));
        assert!(!diff.iter().any(|s| s.contains("b-1")));
    }

    #[test]
    fn package_diff_output_is_sorted() {
        let left = vec![pkg("b-1", "bbb"), pkg("d-1", "ddd"), pkg("a-1", "aaa")];
        let right = vec![pkg("c-1", "ccc"), pkg("a-1", "zzz"), pkg("b-1", "bbb")];
        let diff = package_diff(&left, &right);
        assert_eq!(
            diff,
            vec![
                "+ c-1".to_string(),
                "- d-1".to_string(),
                "~ a-1 (sha256 changed)".to_string(),
            ]
        );
    }

    #[test]
    fn rpm_summary_classifies_added_removed_changed_unchanged() {
        let dump = |file_name: &str, line: &str| RpmDump {
            file_name: file_name.into(),
            dump: vec![line.to_string()],
        };
        let left = vec![
            dump("same-1.rpm", "a"),
            dump("diff-1.rpm", "a"),
            dump("gone-1.rpm", "a"),
        ];
        let right = vec![
            dump("same-1.rpm", "a"),
            dump("diff-1.rpm", "b"),
            dump("new-1.rpm", "a"),
        ];
        let summary = rpm_summary(&left, &right);
        assert_eq!(summary.added, vec!["new-1.rpm".to_string()]);
        assert_eq!(summary.removed, vec!["gone-1.rpm".to_string()]);
        assert_eq!(summary.changed, vec!["diff-1.rpm".to_string()]);
        assert_eq!(summary.unchanged, 1);
    }

    #[test]
    fn profile_phase_diff_computes_delta() {
        let left = profile_with_phases(vec![("build", 8.0), ("setup", 2.0)]);
        let right = profile_with_phases(vec![("build", 12.0), ("setup", 2.0)]);
        let diff = profile_phase_diff(&left, &right);
        assert_eq!(
            diff,
            vec![
                "build: 8.0s → 12.0s (+4.0s, +50%)".to_string(),
                "setup: 2.0s → 2.0s (+0.0s, +0%)".to_string(),
            ]
        );
    }

    #[test]
    fn profile_phase_diff_marks_new_when_left_duration_zero() {
        let left = profile_with_phases(vec![("build", 0.0)]);
        let right = profile_with_phases(vec![("build", 3.5)]);
        let diff = profile_phase_diff(&left, &right);
        assert_eq!(diff, vec!["build: 0.0s → 3.5s (+3.5s, new)".to_string()]);
    }

    #[tokio::test]
    async fn load_build_packages_loads_valid_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("build_packages.json");
        let packages = vec![pkg("a-1", "aaa"), pkg("b-1", "bbb")];
        tokio::fs::write(
            &path,
            serde_json::to_string(&packages).unwrap().into_bytes(),
        )
        .await
        .unwrap();

        let loaded = load_build_packages(tmp.path()).await.unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.iter().any(|p| p.nevra == "a-1"));
        assert!(loaded.iter().any(|p| p.nevra == "b-1"));
    }

    #[tokio::test]
    async fn load_build_packages_errors_on_invalid_json() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("build_packages.json");
        tokio::fs::write(&path, b"not json").await.unwrap();

        let err = load_build_packages(tmp.path()).await.unwrap_err();
        assert!(matches!(err, CrbsError::Internal(_)));
    }

    #[tokio::test]
    async fn load_build_packages_returns_empty_on_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = load_build_packages(tmp.path()).await.unwrap();
        assert!(loaded.is_empty());
    }
}
