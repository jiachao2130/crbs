// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 最小比对闭环的 hub 侧执行体。单一入口
//! [`spawn_on_build_terminal`]：构建终态首次写入处 spawn 执行，不阻塞构建
//! 路径。三个 per-build 动作：
//! 1. 复现比对：终态构建自身是 replay（request_json 带
//!    `reproduce_from_build_id`）→ 按 unsigned_sha256 集合比对 source vs
//!    replay，verdict 落 `build_reproducibility`（失败按
//!    [`crbs_core::classify_replay_failure`] 分类）。
//! 2. 自动跟跑：succeeded + deterministic + 任务全部子构建 succeeded +
//!    `auto_replay` + `replay_sampling` 抽中 → 经 `reproduce_fan_out` 建后台
//!    档复现任务（隔离四规则见 [`maybe_auto_replay`] 注）。
//! 3. cross-arch noarch 互比：任务 ≥2 架构且全部子构建终态 → 同 NVR noarch
//!    子包 unsigned_sha256 跨架构互比，不一致记 cross_arch_noarch/diff。
//!
//! 复现构建不触发 2/3（单代血缘，规则②）。

use std::sync::Arc;

use crbs_core::types::build_phase_is_terminal;
use crbs_core::types::PRIORITY_BACKGROUND;
use crbs_core::{
    classify_replay_failure, compare_unsigned_sets, sampling_hit, CompareDetail,
    NewReproducibility, ReplayVerdict, KIND_CROSS_ARCH_NOARCH, KIND_REPLAY,
};
use tracing::{debug, info, warn};

use crate::server::state::AppState;

/// 构建终态钩子入口（spawn 版）：终态首次写入处 spawn 执行，不阻塞构建路径。内部失败只记日志，不影响已达成的构建状态；外层任务监管内层 JoinHandle——钩子 panic
/// 不再随裸 tokio::spawn 静默丢失，同样落 auto_replay_failure 审计。
pub(crate) fn spawn_on_build_terminal(app: Arc<AppState>, build_id: i64) {
    tokio::spawn(async move {
        let hook_app = app.clone();
        let hook = tokio::spawn(async move { on_build_terminal(&hook_app, build_id).await });
        let failure = match hook.await {
            Ok(Ok(())) => return,
            Ok(Err(e)) => format!("{e:?}"),
            Err(join) => format!("panic: {join}"),
        };
        warn!(build_id = build_id, error = %failure, "auto-replay hook failed (build state untouched)");

        if let Err(audit_err) = app
            .state_store
            .audit_log(
                "system",
                "system",
                "auto_replay_failure",
                Some(&build_id.to_string()),
                Some(
                    &serde_json::json!({
                        "stage": "on_build_terminal",
                        "error": failure,
                    })
                    .to_string(),
                ),
            )
            .await
        {
            crate::server::routes::warn_audit_log_failure(&audit_err, "audit_log");
        }
    });
}

/// 终态钩子主体（可直接 await 的版本，测试用）。三个 per-build 动作：① 复现比对（自身是 replay → unsigned_sha256 集合比对 source vs
/// replay，verdict 落 build_reproducibility）；② 自动跟跑（succeeded + deterministic + 任务全部子构建 succeeded +
/// auto_replay + 抽样命中 → reproduce_fan_out 建后台复现任务）；③ cross-arch noarch 互比（任务 ≥2 架构且全部终态 → 同 NVR
/// noarch 子包跨架构互比）。复现构建不触发 ②③（单代血缘）。
pub(crate) async fn on_build_terminal(
    app: &Arc<AppState>,
    build_id: i64,
) -> Result<(), crate::server::error::ApiError> {
    let store = &app.state_store;
    let Some(record) = store.get_build(build_id).await? else {
        return Ok(());
    };
    if !build_phase_is_terminal(&record.phase) {
        return Ok(());
    }

    if let Some(source_id) = store.get_build_reproduce_source(build_id).await? {
        compare_replay_build(app, &record, source_id).await?;
        return Ok(());
    }

    if let Some(json) = store.get_build_request_json(build_id).await? {
        let lineage_present = match serde_json::from_str::<serde_json::Value>(&json) {
            Ok(v) => v.get("reproduce_from_build_id").is_some(),
            Err(_) => json.contains("reproduce_from_build_id"),
        };
        if lineage_present {
            debug!(
                build_id = build_id,
                "Replay lineage key present but value unparseable; \
                 treating as replay (no auto replay / cross-arch)"
            );
            return Ok(());
        }
    }

    if record.phase == "succeeded" && record.deterministic {
        if let Err(e) = maybe_auto_replay(app, &record).await {
            warn!(
                build_id = build_id,
                error = ?e,
                "Auto replay trigger failed; skipping replay creation"
            );
        }
    }

    maybe_cross_arch_compare(app, &record).await?;
    Ok(())
}

struct AutoReplayInflightGuard {
    app: Arc<AppState>,
    task_id: i64,
}

impl Drop for AutoReplayInflightGuard {
    fn drop(&mut self) {
        self.app
            .auto_replay_inflight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.task_id);
    }
}

/// 自动跟跑触发 + 创建复现任务。
///
/// 重放隔离四规则（硬性）：
/// - ①repo_publish=0：no_publish 在 `reproduce_fan_out` 入口统一强制 → 快照
///   builds.repo_publish=0（发布端 MAX(build_id) newest-wins，重放可发布会
///   静默发布错误字节）；
/// - ②单代血缘：只从非 replay 构建触达，重放不再触发下一代；
/// - ③后台档 priority=-1：不继承原 task 优先级（aging 权重下积压重放会
///   插队用户构建）；负值仅本系统路径可设（校验层只放行 0-2）；
/// - ④空闲派发：调度谓词 `priority >= 0 OR NOT EXISTS(...)`，存在用户
///   pending 构建时不派发重放。
///
/// 重放跳过 GPG 签名、走冷 ccache（隔离＝reproduce 临时 base_os）。
async fn maybe_auto_replay(
    app: &Arc<AppState>,
    record: &crbs_core::BuildRecord,
) -> Result<(), crate::server::error::ApiError> {
    let store = &app.state_store;
    let Some(task_id) = record.task_id else {
        return Ok(());
    };

    // 任务级在途去重：check-and-insert 必须在函数第一个 await 之前，防双
    // fan-out 竞态重复建任务。
    if !app
        .auto_replay_inflight
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(task_id)
    {
        info!(task_id = task_id, "Auto replay already in flight for task");
        return Ok(());
    }
    let _inflight = AutoReplayInflightGuard {
        app: app.clone(),
        task_id,
    };

    let task = store
        .get_task(task_id)
        .await?
        .ok_or_else(|| crate::server::error::ApiError::not_found("task", task_id))?;
    let children = store.get_builds_by_task_id(task_id).await?;
    if children.is_empty() || !children.iter().all(|c| c.phase == "succeeded") {
        debug!(
            task_id = task_id,
            "Auto replay: task not fully succeeded; no replay this round"
        );
        return Ok(());
    }

    let resolved = match store.resolve_any_product_by_name(&record.product).await {
        Ok(r) => r,
        Err(e) => {
            warn!(
                product = %record.product,
                error = %e,
                "Auto replay: product config unavailable; skipping"
            );
            return Ok(());
        }
    };
    let auto_replay = resolved.config.auto_replay.unwrap_or(true);
    if !auto_replay {
        info!(task_id = task_id, product = %record.product, "Auto replay disabled by product config");
        return Ok(());
    }
    let sampling_pct = match resolved.config.replay_sampling {
        Some(p) if p > 100 => {
            warn!(
                product = %record.product,
                value = p,
                "Auto replay: replay_sampling out of range (0-100); clamping to 100"
            );
            100
        }
        Some(p) => p,
        None => 100,
    };

    if !sampling_hit(task_id, sampling_pct) {
        info!(
            task_id = task_id,
            sampling_pct = sampling_pct,
            "Auto replay: task not selected by replay_sampling (sha256(task_id) % 100 >= pct)"
        );
        return Ok(());
    }
    info!(
        task_id = task_id,
        sampling_pct = sampling_pct,
        "Auto replay: task selected, creating background replay task"
    );

    let info = store
        .get_task_rebuild_info(task_id)
        .await?
        .ok_or_else(|| crate::server::error::ApiError::not_found("task rebuild info", task_id))?;
    let request_json = info.request_json.clone().ok_or_else(|| {
        crate::server::error::ApiError::Conflict(
            "task has no recorded build options; cannot auto replay".into(),
        )
    })?;
    let mut opts: crbs_core::BuildOptions = serde_json::from_str(&request_json).map_err(|e| {
        crate::server::error::ApiError::log_and_internal_with_context(
            "parse recorded build options for auto replay",
            e,
        )
    })?;
    opts.arch = None;
    opts.arch_list.clear();
    opts.priority = Some(PRIORITY_BACKGROUND);
    opts.reproduce_from_build_id = None;

    let entries =
        crate::server::routes::tasks::collect_reproduce_entries(app, task_id, &info, children)
            .await?;
    if entries.is_empty() {
        warn!(
            task_id = task_id,
            "Auto replay: no reproducible child builds (missing build_packages.json); skipping"
        );
        return Ok(());
    }
    let mut entry_arches: Vec<String> = entries.iter().map(|e| e.arch.clone()).collect();
    entry_arches.sort();
    entry_arches.dedup();
    crate::server::routes::builds::validate_replay_caps_by_len(entries.len(), &entry_arches)?;

    let result_dir = app.result_dir_for(&record.product).await?;
    tokio::fs::create_dir_all(&result_dir).await.map_err(|e| {
        crate::server::error::ApiError::log_and_internal_with_context(
            "create result_dir for auto replay",
            e,
        )
    })?;
    crate::server::routes::builds::ensure_shared_result_dir(&result_dir).await;

    let (replay_task_id, ids) = crate::server::routes::builds::reproduce_fan_out(
        app.clone(),
        crate::server::routes::builds::ReproduceFanOutArgs {
            product: record.product.clone(),
            result_dir,
            opts,
            entries,
            submit_user: task.user.clone(),
            submit_user_id: None,
            source_pkg_name: info.pkg_name.clone(),
        },
    )
    .await?;

    let role = match store.find_user_by_name(&task.user).await {
        Ok(Some(u)) => u.role,
        Ok(None) => {
            warn!(
                user = %task.user,
                "Auto replay audit: user not found; falling back to role 'operator'"
            );
            "operator".to_string()
        }
        Err(e) => {
            warn!(
                user = %task.user,
                error = %e,
                "Auto replay audit: role lookup failed; falling back to role 'operator'"
            );
            "operator".to_string()
        }
    };
    if let Err(e) = store
        .audit_log(
            &task.user,
            &role,
            "auto_replay",
            Some(&task_id.to_string()),
            Some(
                &serde_json::json!({
                    "from_task_id": task_id,
                    "replay_task_id": replay_task_id,
                    "build_ids": ids,
                })
                .to_string(),
            ),
        )
        .await
    {
        crate::server::routes::warn_audit_log_failure(&e, "audit_log");
    }
    info!(
        task_id = task_id,
        replay_task_id = replay_task_id,
        build_ids = ?ids,
        "Auto replay task created (background priority, repo_publish=0)"
    );

    app.worker_notify.notify_one();
    Ok(())
}

/// 复现比对：按 unsigned_sha256 集合比对 source vs replay。
async fn compare_replay_build(
    app: &Arc<AppState>,
    replay: &crbs_core::BuildRecord,
    source_id: i64,
) -> Result<(), crate::server::error::ApiError> {
    let store = &app.state_store;
    let Some(source) = store.get_build(source_id).await? else {
        warn!(
            replay_build_id = replay.id,
            source_build_id = source_id,
            "Replay comparison: source build record missing; skipping"
        );
        return Ok(());
    };
    let (verdict, detail) = if replay.phase == "succeeded" {
        let src_artifacts = store.list_artifacts(source_id).await?;
        let rpl_artifacts = store.list_artifacts(replay.id).await?;
        compare_unsigned_sets(&src_artifacts, &rpl_artifacts)
    } else {
        match classify_replay_failure(&replay.phase, replay.error_summary.as_deref()) {
            None => {
                info!(
                    replay_build_id = replay.id,
                    "Replay comparison: replay cancelled; no comparison row"
                );
                return Ok(());
            }
            Some(v) => (
                v,
                CompareDetail {
                    missing_unsigned: vec![format!(
                        "replay build terminal phase '{}': no artifacts compared",
                        replay.phase
                    )],
                    ..Default::default()
                },
            ),
        }
    };

    let mut detail_json = serde_json::to_value(&detail).unwrap_or(serde_json::Value::Null);
    if let Some(obj) = detail_json.as_object_mut() {
        obj.insert(
            "classification".to_string(),
            serde_json::json!(verdict.as_str()),
        );
        if let Some(ccache) = source_ccache_stats(&source).await {
            obj.insert("source_ccache".to_string(), ccache);
        }
        if replay.phase != "succeeded" {
            obj.insert("replay_phase".to_string(), serde_json::json!(replay.phase));
            if let Some(err) = replay.error_summary.as_deref() {
                obj.insert(
                    "replay_error".to_string(),
                    serde_json::json!(truncate_chars(err, 400)),
                );
            }
        }
    }

    let inserted = store
        .insert_replay_if_absent(&NewReproducibility {
            kind: KIND_REPLAY,
            source_build_id: source_id,
            replay_build_id: Some(replay.id),
            verdict,
            detail_json: Some(detail_json.to_string()),
        })
        .await?;
    if inserted {
        info!(
            replay_build_id = replay.id,
            source_build_id = source_id,
            verdict = verdict.as_str(),
            "Replay comparison recorded"
        );
    } else {
        debug!(
            replay_build_id = replay.id,
            source_build_id = source_id,
            "Replay comparison row already present; duplicate terminal hook absorbed"
        );
    }
    Ok(())
}

async fn source_ccache_stats(source: &crbs_core::BuildRecord) -> Option<serde_json::Value> {
    let result_dir = source.result_dir.as_deref()?;
    let log_path = std::path::Path::new(result_dir).join("build.log");
    match crbs_core::engine::profile::parse_profile_from_log_file(
        &log_path, source.id, "", 0.0, false, true,
    )
    .await
    {
        Ok(profile) => profile
            .ccache
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        Err(e) => {
            debug!(
                build_id = source.id,
                error = %e,
                "Replay comparison: source ccache stats unavailable"
            );
            None
        }
    }
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

async fn maybe_cross_arch_compare(
    app: &Arc<AppState>,
    record: &crbs_core::BuildRecord,
) -> Result<(), crate::server::error::ApiError> {
    let store = &app.state_store;
    let Some(task_id) = record.task_id else {
        return Ok(());
    };
    let children = store.get_builds_by_task_id(task_id).await?;

    if children.len() < 2 || !children.iter().all(|c| build_phase_is_terminal(&c.phase)) {
        return Ok(());
    }

    for c in &children {
        if let Some(source_id) = store.get_build_reproduce_source(c.id).await? {
            debug!(
                task_id = task_id,
                replay_build_id = c.id,
                source_build_id = source_id,
                "Cross-arch compare: task has reproduce lineage; skipping (per-build comparison already covers it)"
            );
            return Ok(());
        }
    }

    if !record.deterministic {
        debug!(
            task_id = task_id,
            build_id = record.id,
            "Cross-arch compare: non-deterministic build; skipping"
        );
        return Ok(());
    }
    let succeeded: Vec<&crbs_core::BuildRecord> =
        children.iter().filter(|c| c.phase == "succeeded").collect();
    let arch_count = {
        let mut arches: Vec<&str> = succeeded.iter().filter_map(|c| c.arch.as_deref()).collect();
        arches.sort_unstable();
        arches.dedup();
        arches.len()
    };
    if arch_count < 2 {
        return Ok(());
    }

    let build_ids: Vec<i64> = succeeded.iter().map(|c| c.id).collect();
    let artifacts = store.list_artifacts_for_builds(&build_ids).await?;

    let mut by_file: std::collections::BTreeMap<String, Vec<(i64, Option<String>)>> =
        std::collections::BTreeMap::new();
    for a in artifacts.iter().filter(|a| a.kind.as_str() == "rpm") {
        if a.arch.as_deref() != Some("noarch") {
            continue;
        }
        let file = std::path::Path::new(&a.relative_path)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| a.relative_path.clone());
        by_file
            .entry(file)
            .or_default()
            .push((a.build_id, a.unsigned_sha256.clone()));
    }

    let mut mismatched = serde_json::Map::new();

    let mut only_in = serde_json::Map::new();
    let mut involved_min_build_id: Option<i64> = None;
    for (file, entries) in &by_file {
        let distinct: std::collections::BTreeSet<&str> = entries
            .iter()
            .filter_map(|(_, sha)| sha.as_deref())
            .collect();
        if distinct.len() < 2 {
            let mut build_ids = entries.iter().map(|(bid, _)| *bid);
            if let Some(first) = build_ids.next() {
                if build_ids.all(|b| b == first) {
                    let arch = children
                        .iter()
                        .find(|c| c.id == first)
                        .and_then(|c| c.arch.clone())
                        .unwrap_or_default();
                    only_in.insert(
                        file.clone(),
                        serde_json::json!({ "build_id": first, "arch": arch }),
                    );
                }
            }
            continue;
        }
        mismatched.insert(
            file.clone(),
            serde_json::Value::Array(
                entries
                    .iter()
                    .map(|(bid, sha)| {
                        let arch = children
                            .iter()
                            .find(|c| c.id == *bid)
                            .and_then(|c| c.arch.clone())
                            .unwrap_or_default();
                        serde_json::json!({
                            "build_id": bid,
                            "arch": arch,
                            "unsigned_sha256": sha,
                        })
                    })
                    .collect(),
            ),
        );
        for (bid, _) in entries {
            involved_min_build_id = Some(match involved_min_build_id {
                Some(m) if m <= *bid => m,
                _ => *bid,
            });
        }
    }
    let Some(source_build_id) = involved_min_build_id else {
        return Ok(());
    };

    let missing_unsigned_anchor: Vec<String> = by_file
        .iter()
        .filter(|(_, entries)| entries.iter().any(|(_, sha)| sha.is_none()))
        .map(|(file, _)| file.clone())
        .collect();

    let mut detail = serde_json::json!({
        "mismatched_noarch": mismatched,
        "task_id": task_id,
        "attribution": "cross-arch noarch subpackage byte drift; publish side picks newest-wins silently",
    });

    if !missing_unsigned_anchor.is_empty() {
        detail["missing_unsigned_anchor"] = serde_json::Value::Array(
            missing_unsigned_anchor
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );
    }
    if !only_in.is_empty() {
        detail["only_in"] = serde_json::Value::Object(only_in);
    }
    let detail = detail.to_string();
    let inserted = store
        .insert_cross_arch_if_absent(&NewReproducibility {
            kind: KIND_CROSS_ARCH_NOARCH,
            source_build_id,
            replay_build_id: None,
            verdict: ReplayVerdict::Diff,
            detail_json: Some(detail),
        })
        .await?;
    if inserted {
        warn!(
            task_id = task_id,
            source_build_id = source_build_id,
            "Cross-arch noarch mismatch recorded (verdict=diff, kind=cross_arch_noarch)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::state::AppState;
    use crbs_core::{ArtifactKind, NewArtifact};

    async fn setup_app(
        auto_replay: Option<bool>,
        replay_sampling: Option<u8>,
    ) -> (Arc<AppState>, tempfile::TempDir) {
        let (store, tmp) = crate::test_support::create_test_store().await;
        let cfg = crbs_core::config::ProductConfig::from_str(&format!(
            "base_packages = [\"bash\"]\ndeterministic = true\ndnf_cache_enabled = true\n{}\n{}\n\n[[repos]]\n\
             name = \"base\"\nbaseurl = \"http://example.com/base/$basearch\"\ngpgcheck = false\n",
            auto_replay
                .map(|v| format!("auto_replay = {v}"))
                .unwrap_or_default(),
            replay_sampling
                .map(|v| format!("replay_sampling = {v}"))
                .unwrap_or_default(),
        ))
        .unwrap();
        store
            .create_product(crbs_core::CreateProductInput {
                name: "det",
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: crbs_core::VISIBILITY_PUBLIC,
                config: &cfg,
                changed_by_user_id: None,
                reason: Some("auto-replay test seed"),
            })
            .await
            .unwrap();
        let app = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        (app, tmp)
    }

    async fn seed_succeeded_det_task(app: &Arc<AppState>, pkg: &str, arch: &str) -> (i64, i64) {
        let store = &app.state_store;
        let task_id = crate::test_support::seed_task(store, "det", pkg).await;
        let build_id = store
            .insert_build(crbs_core::BuildInsert {
                product: "det",
                pkg_name: pkg,
                phase: "pending",
                backend: "chroot",
                user: "test",
                priority: 0,
                arch: Some(arch),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store.set_build_deterministic(build_id, true).await.unwrap();
        store
            .set_build_request_info(build_id, "/tmp/x.src.rpm", "{}")
            .await
            .unwrap();
        store
            .complete_build(build_id, "succeeded", None)
            .await
            .unwrap();

        let result_root = app.result_dir_for_or_default("det").await;
        let build_dir = result_root
            .join(task_id.to_string())
            .join(arch)
            .join(build_id.to_string());
        tokio::fs::create_dir_all(&build_dir).await.unwrap();

        tokio::fs::write(build_dir.join("build_packages.json"), b"[]")
            .await
            .unwrap();

        tokio::fs::create_dir_all(build_dir.join("RPMS"))
            .await
            .unwrap();
        tokio::fs::write(
            build_dir.join("RPMS").join("anchor.rpm"),
            include_bytes!("replay/fixtures/replay_anchor.rpm"),
        )
        .await
        .unwrap();
        let source_dir = result_root.join(task_id.to_string()).join("source");
        tokio::fs::create_dir_all(&source_dir).await.unwrap();
        tokio::fs::write(source_dir.join(format!("{pkg}.src.rpm")), b"srpm-bytes")
            .await
            .unwrap();

        sqlx::query("UPDATE tasks SET request_json = $1, result_dir = $2 WHERE id = $3")
            .bind(r#"{"target":"x86_64"}"#)
            .bind(result_root.join(task_id.to_string()).display().to_string())
            .bind(task_id)
            .execute(store.pool())
            .await
            .unwrap();
        (task_id, build_id)
    }

    fn rpm_artifact(rel: &str, unsigned: &str) -> NewArtifact {
        NewArtifact {
            relative_path: rel.to_string(),
            kind: ArtifactKind::Rpm,
            size_bytes: 10,
            sha256: "signed-ignored".to_string(),
            unsigned_sha256: Some(unsigned.to_string()),
            arch: Some("x86_64".to_string()),
            name: None,
            version: None,
            release: None,
            epoch: None,
            metadata_json: None,
            signed: true,
        }
    }

    async fn insert_artifacts(app: &Arc<AppState>, build_id: i64, artifacts: &[NewArtifact]) {
        let now = crbs_core::util::db_now_utc();
        let mut tx = app.state_store.pool().begin().await.unwrap();
        app.state_store
            .insert_artifacts_tx(&mut tx, build_id, artifacts, &now)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    async fn second_arch_child(
        app: &Arc<AppState>,
        task_id: i64,
        pkg: &str,
        request_json: &str,
    ) -> i64 {
        let store = &app.state_store;
        let build_id = store
            .insert_build(crbs_core::BuildInsert {
                product: "det",
                pkg_name: pkg,
                phase: "succeeded",
                backend: "chroot",
                user: "test",
                arch: Some("aarch64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store.set_build_deterministic(build_id, true).await.unwrap();
        store
            .set_build_request_info(build_id, "/tmp/x.src.rpm", request_json)
            .await
            .unwrap();
        let dir = app
            .result_dir_for_or_default("det")
            .await
            .join(task_id.to_string())
            .join("aarch64")
            .join(build_id.to_string());
        tokio::fs::create_dir_all(&dir).await.unwrap();

        tokio::fs::write(dir.join("build_packages.json"), b"[]")
            .await
            .unwrap();

        tokio::fs::create_dir_all(dir.join("RPMS")).await.unwrap();
        tokio::fs::write(
            dir.join("RPMS").join("anchor.rpm"),
            include_bytes!("replay/fixtures/replay_anchor.rpm"),
        )
        .await
        .unwrap();
        build_id
    }

    #[tokio::test]
    async fn auto_replay_creates_background_replay_task() {
        let (app, _tmp) = setup_app(None, None).await;
        let (_task_id, build_id) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;

        on_build_terminal(&app, build_id).await.unwrap();

        let rows: Vec<(i64, i64)> =
            sqlx::query_as("SELECT id, priority FROM builds WHERE id > $1 ORDER BY id")
                .bind(build_id)
                .fetch_all(app.state_store.pool())
                .await
                .unwrap();
        assert_eq!(rows.len(), 1, "exactly one replay build per source child");
        let (replay_build_id, priority) = rows[0];
        assert_eq!(
            priority, -1,
            "replay build must carry PRIORITY_BACKGROUND (-1)"
        );

        let repo_publish: i64 = sqlx::query_scalar("SELECT repo_publish FROM builds WHERE id = $1")
            .bind(replay_build_id)
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();
        assert_eq!(repo_publish, 0, "replay build must not publish (rule 1)");

        let det: i64 = sqlx::query_scalar("SELECT deterministic FROM builds WHERE id = $1")
            .bind(replay_build_id)
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();
        assert_eq!(det, 1, "replay build inherits deterministic tagging");

        assert_eq!(
            app.state_store
                .get_build_reproduce_source(replay_build_id)
                .await
                .unwrap(),
            Some(build_id)
        );

        let signed: i64 = sqlx::query_scalar("SELECT signed FROM builds WHERE id = $1")
            .bind(replay_build_id)
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();
        assert_eq!(signed, 0);
    }

    #[tokio::test]
    async fn manual_reproduce_children_do_not_publish() {
        let (app, _tmp) = setup_app(None, Some(0)).await;
        let (task_id, _build_id) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        let store = &app.state_store;
        let info = store
            .get_task_rebuild_info(task_id)
            .await
            .unwrap()
            .expect("task rebuild info must exist");
        let children = store.get_builds_by_task_id(task_id).await.unwrap();
        let mut opts: crbs_core::BuildOptions =
            serde_json::from_str(info.request_json.as_deref().unwrap_or("{}")).unwrap();
        opts.arch = None;
        opts.arch_list.clear();
        opts.reproduce_from_build_id = None;
        assert_ne!(
            opts.no_publish,
            Some(true),
            "test premise: caller does not set no_publish (manual path shape)"
        );

        let entries =
            crate::server::routes::tasks::collect_reproduce_entries(&app, task_id, &info, children)
                .await
                .unwrap();
        assert!(!entries.is_empty(), "seeded task must be reproducible");

        let result_dir = app.result_dir_for_or_default("det").await;
        let (_replay_task_id, ids) = crate::server::routes::builds::reproduce_fan_out(
            app.clone(),
            crate::server::routes::builds::ReproduceFanOutArgs {
                product: "det".into(),
                result_dir,
                opts,
                entries,
                submit_user: "test".into(),
                submit_user_id: None,
                source_pkg_name: info.pkg_name.clone(),
            },
        )
        .await
        .unwrap();
        assert!(!ids.is_empty(), "manual reproduce must create child builds");
        for id in &ids {
            let repo_publish: i64 =
                sqlx::query_scalar("SELECT repo_publish FROM builds WHERE id = $1")
                    .bind(id)
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            assert_eq!(
                repo_publish, 0,
                "manual reproduce child build {id} must not publish (rule 1)"
            );
        }
    }

    #[tokio::test]
    async fn replay_terminal_compares_and_does_not_chain() {
        let (app, _tmp) = setup_app(None, None).await;
        let (_task_id, source_build) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        insert_artifacts(
            &app,
            source_build,
            &[rpm_artifact("RPMS/x86_64/hello-1.0-1.x86_64.rpm", "aaa")],
        )
        .await;

        on_build_terminal(&app, source_build).await.unwrap();
        let replay_build_id: i64 = sqlx::query_scalar("SELECT MAX(id) FROM builds")
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();
        let task_count_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();

        insert_artifacts(
            &app,
            replay_build_id,
            &[rpm_artifact("RPMS/x86_64/hello-1.0-1.x86_64.rpm", "aaa")],
        )
        .await;
        app.state_store
            .complete_build(replay_build_id, "succeeded", None)
            .await
            .unwrap();

        on_build_terminal(&app, replay_build_id).await.unwrap();

        let rows = app
            .state_store
            .list_reproducibility_for_build(source_build)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "one comparison row");
        assert_eq!(rows[0].verdict, "same");
        assert_eq!(rows[0].kind, "replay");
        assert_eq!(rows[0].replay_build_id, Some(replay_build_id));
        assert!(rows[0]
            .detail_json
            .as_deref()
            .unwrap_or("")
            .contains("hello-1.0-1.x86_64.rpm"));

        let task_count_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();
        assert_eq!(
            task_count_before, task_count_after,
            "replay must not chain (rule 2)"
        );
    }

    #[tokio::test]
    async fn replay_with_different_hash_records_diff() {
        let (app, _tmp) = setup_app(None, None).await;
        let (_task_id, source_build) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        insert_artifacts(
            &app,
            source_build,
            &[rpm_artifact("RPMS/x86_64/hello-1.0-1.x86_64.rpm", "aaa")],
        )
        .await;
        on_build_terminal(&app, source_build).await.unwrap();
        let replay_build_id: i64 = sqlx::query_scalar("SELECT MAX(id) FROM builds")
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();

        insert_artifacts(
            &app,
            replay_build_id,
            &[
                rpm_artifact("RPMS/x86_64/hello-1.0-1.x86_64.rpm", "bbb"),
                rpm_artifact("RPMS/x86_64/hello-extra-1.0-1.x86_64.rpm", "ccc"),
            ],
        )
        .await;
        app.state_store
            .complete_build(replay_build_id, "succeeded", None)
            .await
            .unwrap();
        on_build_terminal(&app, replay_build_id).await.unwrap();

        let rows = app
            .state_store
            .list_reproducibility_for_build(source_build)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].verdict, "diff");
        let detail = rows[0].detail_json.as_deref().unwrap_or("");
        assert!(
            detail.contains("hello-1.0-1.x86_64.rpm"),
            "detail must name the mismatched file"
        );
        assert!(
            detail.contains("hello-extra-1.0-1.x86_64.rpm"),
            "detail must name the replay-only file"
        );
        assert!(
            detail.contains("aaa") && detail.contains("bbb"),
            "detail must carry both hashes"
        );
    }

    #[tokio::test]
    async fn replay_failure_classification_rows() {
        let (app, _tmp) = setup_app(None, None).await;
        let (_task_id, source_build) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        on_build_terminal(&app, source_build).await.unwrap();

        let mk_replay_failed = |pkg: &'static str, error: &'static str| {
            let app = app.clone();
            async move {
                let (_t, src) = seed_succeeded_det_task(&app, pkg, "x86_64").await;
                on_build_terminal(&app, src).await.unwrap();
                let replay_build_id: i64 = sqlx::query_scalar("SELECT MAX(id) FROM builds")
                    .fetch_one(app.state_store.pool())
                    .await
                    .unwrap();
                app.state_store
                    .complete_build_with_error(replay_build_id, "failed", None, Some(error))
                    .await
                    .unwrap();
                on_build_terminal(&app, replay_build_id).await.unwrap();
                app.state_store
                    .latest_reproducibility_for_build(src)
                    .await
                    .unwrap()
                    .expect("comparison row must exist")
                    .verdict
            }
        };

        let v = mk_replay_failed(
            "dep-case",
            "validation failed: Reproduce fail-fast: 2 builddep package(s) missing from Phase 1 dnf cache, snapshot repo Packages, and base_os manifest:\n  gcc-12.3.1-1.x86_64 (sha256)",
        )
        .await;
        assert_eq!(v, "dep_unavailable");

        let v = mk_replay_failed(
            "build-case",
            "script /crbs-build.sh failed: exit_code=Some(1); phase=build; subphase=%install",
        )
        .await;
        assert_eq!(v, "build_failed");

        let (_t, src) = seed_succeeded_det_task(&app, "cancel-case", "x86_64").await;
        on_build_terminal(&app, src).await.unwrap();
        let replay_build_id: i64 = sqlx::query_scalar("SELECT MAX(id) FROM builds")
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();
        app.state_store
            .complete_build(replay_build_id, "cancelled", None)
            .await
            .unwrap();
        on_build_terminal(&app, replay_build_id).await.unwrap();
        let rows = app
            .state_store
            .list_reproducibility_for_build(src)
            .await
            .unwrap();
        assert!(rows.is_empty(), "cancelled replay adds no comparison row");
    }

    #[tokio::test]
    async fn zombie_repair_terminal_ids_feed_replay_comparison() {
        let (app, _tmp) = setup_app(None, None).await;
        let (_task_id, source_build) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        insert_artifacts(
            &app,
            source_build,
            &[rpm_artifact("RPMS/x86_64/hello-1.0-1.x86_64.rpm", "aaa")],
        )
        .await;
        on_build_terminal(&app, source_build).await.unwrap();
        let replay_build_id: i64 = sqlx::query_scalar("SELECT MAX(id) FROM builds")
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();

        sqlx::query("UPDATE builds SET phase = 'building', crbs_pid = $1 WHERE id = $2")
            .bind(999_999_i64)
            .bind(replay_build_id)
            .execute(app.state_store.pool())
            .await
            .unwrap();

        let (repaired_ids, live) = app
            .state_store
            .repair_all_zombie_active_builds()
            .await
            .unwrap();
        assert_eq!(
            repaired_ids,
            vec![replay_build_id],
            "修复 id 集恰为翻终态的重放构建行"
        );
        assert_eq!(live, 0);
        assert_eq!(
            app.state_store
                .get_build(replay_build_id)
                .await
                .unwrap()
                .expect("replay build record")
                .phase,
            "failed"
        );

        for id in repaired_ids {
            on_build_terminal(&app, id).await.unwrap();
        }

        let rows = app
            .state_store
            .list_reproducibility_for_build(source_build)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "zombie 修复翻终态后比对行必须落库");
        assert_eq!(rows[0].verdict, "build_failed");
        assert_eq!(rows[0].replay_build_id, Some(replay_build_id));
    }

    #[tokio::test]
    async fn startup_reconcile_backfills_missing_replay_comparison_rows() {
        let (app, _tmp) = setup_app(None, None).await;
        let store = &app.state_store;
        let (_task_id, source_build) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        insert_artifacts(
            &app,
            source_build,
            &[rpm_artifact("RPMS/x86_64/hello-1.0-1.x86_64.rpm", "aaa")],
        )
        .await;
        on_build_terminal(&app, source_build).await.unwrap();
        let replay_build_id: i64 = sqlx::query_scalar("SELECT MAX(id) FROM builds")
            .fetch_one(store.pool())
            .await
            .unwrap();

        insert_artifacts(
            &app,
            replay_build_id,
            &[rpm_artifact("RPMS/x86_64/hello-1.0-1.x86_64.rpm", "aaa")],
        )
        .await;
        store
            .complete_build(replay_build_id, "succeeded", None)
            .await
            .unwrap();

        let (_t2, _plain_build) = seed_succeeded_det_task(&app, "plain-2.0-1", "x86_64").await;

        let ids = store.list_builds_missing_replay_comparison().await.unwrap();
        assert_eq!(
            ids,
            vec![replay_build_id],
            "对账必须恰查出崩溃窗口中的重放构建（血缘反例排除）"
        );

        for id in &ids {
            on_build_terminal(&app, *id).await.unwrap();
        }
        let rows = store
            .list_reproducibility_for_build(source_build)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "对账补发钩子后比对行必须落库");
        assert_eq!(rows[0].kind, "replay");
        assert_eq!(rows[0].verdict, "same");
        assert_eq!(rows[0].replay_build_id, Some(replay_build_id));

        let ids2 = store.list_builds_missing_replay_comparison().await.unwrap();
        assert!(ids2.is_empty(), "已落行的重放构建不得再入集");

        let (_t3, src3) = seed_succeeded_det_task(&app, "cancel-3.0-1", "x86_64").await;
        on_build_terminal(&app, src3).await.unwrap();
        let cancelled_replay: i64 = sqlx::query_scalar("SELECT MAX(id) FROM builds")
            .fetch_one(store.pool())
            .await
            .unwrap();
        store
            .complete_build(cancelled_replay, "cancelled", None)
            .await
            .unwrap();
        let ids3 = store.list_builds_missing_replay_comparison().await.unwrap();
        assert!(
            ids3.is_empty(),
            "cancelled 重放不得入集（无比对行是设计语义），其余终态行均已收口"
        );
    }

    #[tokio::test]
    async fn startup_reconcile_backfills_missing_auto_replay_task() {
        let (app, _tmp) = setup_app(None, None).await;
        let store = &app.state_store;
        let (task_id, build_id) =
            seed_succeeded_det_task(&app, "crash-replay-1.0-1", "x86_64").await;

        let (_t_partial, partial_build) =
            seed_succeeded_det_task(&app, "partial-replay-2.0-1", "x86_64").await;
        let partial_task: i64 = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(partial_build)
            .fetch_one(store.pool())
            .await
            .unwrap();
        store
            .insert_build(crbs_core::BuildInsert {
                product: "det",
                pkg_name: "partial-replay-2.0-1",
                phase: "failed",
                backend: "chroot",
                user: "test",
                arch: Some("aarch64"),
                task_id: Some(partial_task),
                ..Default::default()
            })
            .await
            .unwrap();

        let candidates = store.list_tasks_missing_auto_replay().await.unwrap();
        assert_eq!(
            candidates,
            vec![(task_id, build_id)],
            "对账必须恰查出崩溃窗口中的源任务（部分成功任务排除）"
        );

        let max_id_before: i64 = sqlx::query_scalar("SELECT MAX(id) FROM builds")
            .fetch_one(store.pool())
            .await
            .unwrap();
        for (_t, trigger) in &candidates {
            on_build_terminal(&app, *trigger).await.unwrap();
        }
        let replay_builds: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds WHERE id > $1")
            .bind(max_id_before)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(replay_builds, 1, "对账补发钩子后重放子构建必须建立");
        assert_eq!(
            store
                .get_build_reproduce_source(max_id_before + 1)
                .await
                .unwrap(),
            Some(build_id),
            "新子构建的 replay 血缘指回源构建"
        );

        let candidates2 = store.list_tasks_missing_auto_replay().await.unwrap();
        assert!(candidates2.is_empty(), "已有 replay 的源任务不得再入对账集");
    }

    #[tokio::test]
    async fn startup_reconcile_skips_task_with_existing_replay() {
        let (app, _tmp) = setup_app(None, None).await;
        let store = &app.state_store;
        let (_task_id, build_id) =
            seed_succeeded_det_task(&app, "has-replay-3.0-1", "x86_64").await;
        on_build_terminal(&app, build_id).await.unwrap();

        let replay_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds WHERE id > $1")
            .bind(build_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(replay_count, 1, "前置：正常路径已建恰一个重放子构建");

        let candidates = store.list_tasks_missing_auto_replay().await.unwrap();
        assert!(candidates.is_empty(), "已有 replay 的源任务不得再入对账集");
        for (_t, trigger) in &candidates {
            on_build_terminal(&app, *trigger).await.unwrap();
        }
        let replay_count2: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds WHERE id > $1")
            .bind(build_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            replay_count2, 1,
            "重启对账不得给已有 replay 的源任务重复建重放"
        );
    }

    async fn seed_lineage_terminal_build(
        app: &Arc<AppState>,
        pkg: &str,
        request_json: &str,
        deterministic: bool,
    ) -> i64 {
        let store = &app.state_store;
        let task_id = crate::test_support::seed_task(store, "det", pkg).await;
        let build_id = store
            .insert_build(crbs_core::BuildInsert {
                product: "det",
                pkg_name: pkg,
                phase: "pending",
                backend: "chroot",
                user: "test",
                priority: 0,
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        if deterministic {
            store.set_build_deterministic(build_id, true).await.unwrap();
        }
        store
            .set_build_request_info(build_id, "/tmp/x.src.rpm", request_json)
            .await
            .unwrap();
        store
            .complete_build(build_id, "succeeded", None)
            .await
            .unwrap();
        build_id
    }

    #[tokio::test]
    async fn reconcile_excludes_non_deterministic_lineage_builds() {
        let (app, _tmp) = setup_app(None, None).await;
        let store = &app.state_store;
        let (_t, source_build) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        let lineage_json = format!(r#"{{"reproduce_from_build_id":{source_build}}}"#);
        let tagged =
            seed_lineage_terminal_build(&app, "manual-tagged-1.0-1", &lineage_json, true).await;
        let untagged =
            seed_lineage_terminal_build(&app, "manual-untagged-1.0-1", &lineage_json, false).await;

        let ids = store.list_builds_missing_replay_comparison().await.unwrap();
        assert_eq!(
            ids,
            vec![tagged, untagged],
            "det 标记不再参与对账粗筛：两种血缘终态构建都入集"
        );
    }

    #[tokio::test]
    async fn reconcile_excludes_non_id_lineage_value() {
        let (app, _tmp) = setup_app(None, None).await;
        let store = &app.state_store;
        let null_valued = seed_lineage_terminal_build(
            &app,
            "null-lineage-1.0-1",
            r#"{"reproduce_from_build_id":null}"#,
            true,
        )
        .await;

        assert_eq!(
            store.get_build_reproduce_source(null_valued).await.unwrap(),
            None,
            "血缘键值为 null 不得解析出 source id"
        );
        let ids = store.list_builds_missing_replay_comparison().await.unwrap();
        assert!(ids.is_empty(), "血缘键值非 id（null）的构建不得入对账集");
    }

    #[tokio::test]
    async fn corrupted_lineage_replay_skips_auto_replay_and_cross_arch() {
        let (app, _tmp) = setup_app(None, None).await;
        let store = &app.state_store;

        let (_t, b1) = seed_succeeded_det_task(&app, "corrupt-lineage-1.0-1", "x86_64").await;
        let task_id: i64 = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(b1)
            .fetch_one(store.pool())
            .await
            .unwrap();
        let b2 = second_arch_child(
            &app,
            task_id,
            "corrupt-lineage-1.0-1",
            r#"{"reproduce_from_build_id":null}"#,
        )
        .await;
        let mut n1 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "aaa");
        n1.arch = Some("noarch".into());
        insert_artifacts(&app, b1, &[n1]).await;
        let mut n2 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "bbb");
        n2.arch = Some("noarch".into());
        insert_artifacts(&app, b2, &[n2]).await;

        on_build_terminal(&app, b2).await.unwrap();

        let new_builds: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds WHERE id > $1")
            .bind(b2)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            new_builds, 0,
            "血缘损坏的 replay 终态不得跌落②（再触发一代 auto replay）"
        );
        let cross_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM build_reproducibility WHERE kind = 'cross_arch_noarch'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            cross_rows, 0,
            "血缘损坏的 replay 终态不得跌落③（cross-arch 比对行）"
        );

        let (_t, c1) = seed_succeeded_det_task(&app, "plain-contrast-2.0-1", "x86_64").await;
        let c_task: i64 = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(c1)
            .fetch_one(store.pool())
            .await
            .unwrap();
        let c2 = second_arch_child(&app, c_task, "plain-contrast-2.0-1", "{}").await;
        let mut n3 = rpm_artifact("RPMS/noarch/plain-doc-2.0-1.noarch.rpm", "aaa");
        n3.arch = Some("noarch".into());
        insert_artifacts(&app, c1, &[n3]).await;
        let mut n4 = rpm_artifact("RPMS/noarch/plain-doc-2.0-1.noarch.rpm", "bbb");
        n4.arch = Some("noarch".into());
        insert_artifacts(&app, c2, &[n4]).await;

        on_build_terminal(&app, c2).await.unwrap();

        let contrast_replays: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds WHERE id > $1")
            .bind(c2)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            contrast_replays, 2,
            "对照臂：普通终态构建照旧触发 auto replay（每子构建一个重放）"
        );
        let contrast_cross: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM build_reproducibility WHERE kind = 'cross_arch_noarch'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            contrast_cross, 1,
            "对照臂：普通任务照旧落 cross-arch 比对行"
        );
    }

    #[tokio::test]
    async fn define_value_containing_lineage_substring_still_auto_replays() {
        let (app, _tmp) = setup_app(None, None).await;
        let store = &app.state_store;

        let (_t, f1) = seed_succeeded_det_task(&app, "substr-1.0-1", "x86_64").await;
        let task_id: i64 = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(f1)
            .fetch_one(store.pool())
            .await
            .unwrap();
        let f2 = second_arch_child(
            &app,
            task_id,
            "substr-1.0-1",
            r#"{"define":{"foo":"reproduce_from_build_id"}}"#,
        )
        .await;
        let mut n1 = rpm_artifact("RPMS/noarch/substr-doc-1.0-1.noarch.rpm", "aaa");
        n1.arch = Some("noarch".into());
        insert_artifacts(&app, f1, &[n1]).await;
        let mut n2 = rpm_artifact("RPMS/noarch/substr-doc-1.0-1.noarch.rpm", "bbb");
        n2.arch = Some("noarch".into());
        insert_artifacts(&app, f2, &[n2]).await;

        on_build_terminal(&app, f2).await.unwrap();

        let replays: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds WHERE id > $1")
            .bind(f2)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            replays, 2,
            "define 值含血缘子串的普通构建必须照旧触发 auto replay（每子构建一个）"
        );
        let cross: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM build_reproducibility WHERE kind = 'cross_arch_noarch'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            cross, 1,
            "define 值含血缘子串的普通构建必须照旧落 cross-arch 比对行"
        );
    }

    #[tokio::test]
    async fn auto_replay_product_gates() {
        let (app, _tmp) = setup_app(Some(false), None).await;
        let (_t, build_id) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        on_build_terminal(&app, build_id).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds WHERE id > $1")
            .bind(build_id)
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();
        assert_eq!(n, 0, "auto_replay=false must not create a replay task");

        let (app, _tmp) = setup_app(None, Some(0)).await;
        let (_t, build_id) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        on_build_terminal(&app, build_id).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds WHERE id > $1")
            .bind(build_id)
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();
        assert_eq!(n, 0, "replay_sampling=0 must not create a replay task");
    }

    #[tokio::test]
    async fn taskless_build_terminal_hooks_are_noop() {
        let (app, _tmp) = setup_app(None, None).await;
        let (_task_id, build_id) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        let store = &app.state_store;
        let mut record = store
            .get_build(build_id)
            .await
            .unwrap()
            .expect("seeded build record");
        record.task_id = None;
        let task_count_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
            .fetch_one(store.pool())
            .await
            .unwrap();

        maybe_auto_replay(&app, &record).await.unwrap();
        maybe_cross_arch_compare(&app, &record).await.unwrap();

        let new_builds: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds WHERE id > $1")
            .bind(build_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            new_builds, 0,
            "taskless build must not trigger auto replay (maybe_auto_replay early return)"
        );
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM build_reproducibility")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            rows, 0,
            "taskless build must not produce comparison rows (maybe_cross_arch_compare early return)"
        );
        let task_count_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(task_count_before, task_count_after, "no task churn");
    }

    #[tokio::test]
    async fn concurrent_terminal_hooks_trigger_single_auto_replay() {
        let (app, _tmp) = setup_app(None, None).await;
        let (_task_id, b1) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        let store = &app.state_store;
        let task_id: i64 = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(b1)
            .fetch_one(store.pool())
            .await
            .unwrap();

        let b2 = second_arch_child(&app, task_id, "hello-1.0-1", "{}").await;

        let task_count_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
            .fetch_one(store.pool())
            .await
            .unwrap();

        let start = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let s1 = start.clone();
        let s2 = start.clone();
        let app1 = app.clone();
        let app2 = app.clone();
        let (r1, r2) = tokio::join!(
            async move {
                s1.wait().await;
                on_build_terminal(&app1, b1).await
            },
            async move {
                s2.wait().await;
                on_build_terminal(&app2, b2).await
            }
        );
        r1.unwrap();
        r2.unwrap();

        let replay_builds: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds WHERE id > $1")
            .bind(b2)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            replay_builds, 2,
            "exactly one fan-out (one replay child per source child)"
        );
        let task_count_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            task_count_after - task_count_before,
            1,
            "exactly one replay task; double trigger would create two"
        );

        assert!(
            app.auto_replay_inflight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "inflight slot must be released after completion"
        );
    }

    #[tokio::test]
    async fn partially_failed_task_does_not_auto_replay() {
        let (app, _tmp) = setup_app(None, None).await;
        let (_task_id, b1) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        let store = &app.state_store;
        let task_id: i64 = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(b1)
            .fetch_one(store.pool())
            .await
            .unwrap();

        let b2 = store
            .insert_build(crbs_core::BuildInsert {
                product: "det",
                pkg_name: "hello-1.0-1",
                phase: "failed",
                backend: "chroot",
                user: "test",
                arch: Some("aarch64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        on_build_terminal(&app, b1).await.unwrap();

        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds WHERE id > $1")
            .bind(b2)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(n, 0, "partially failed task must not trigger auto replay");
    }

    #[tokio::test]
    async fn cross_arch_noarch_mismatch_recorded_once() {
        let (app, _tmp) = setup_app(None, Some(0)).await;
        let (_task_id, b1) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        let store = &app.state_store;
        let task_id: i64 = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(b1)
            .fetch_one(store.pool())
            .await
            .unwrap();

        let b2 = store
            .insert_build(crbs_core::BuildInsert {
                product: "det",
                pkg_name: "hello-1.0-1",
                phase: "succeeded",
                backend: "chroot",
                user: "test",
                arch: Some("aarch64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store.set_build_deterministic(b2, true).await.unwrap();

        let mut noarch1 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "aaa");
        noarch1.arch = Some("noarch".into());
        insert_artifacts(&app, b1, &[noarch1]).await;
        let mut noarch2 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "bbb");
        noarch2.arch = Some("noarch".into());
        insert_artifacts(&app, b2, &[noarch2]).await;

        on_build_terminal(&app, b2).await.unwrap();

        let rows = store
            .list_reproducibility_for_build(b1)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.kind == "cross_arch_noarch")
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].verdict, "diff");
        assert_eq!(rows[0].replay_build_id, None);
        let detail = rows[0].detail_json.as_deref().unwrap_or("");
        assert!(detail.contains("hello-doc-1.0-1.noarch.rpm"));
        assert!(detail.contains("aaa") && detail.contains("bbb"));

        on_build_terminal(&app, b1).await.unwrap();
        let rows2 = store
            .list_reproducibility_for_build(b1)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.kind == "cross_arch_noarch")
            .count();
        assert_eq!(
            rows2, 1,
            "cross-arch comparison must be recorded once per task"
        );
    }

    #[tokio::test]
    async fn cross_arch_compare_skips_replay_lineage_task() {
        let (app, _tmp) = setup_app(None, Some(0)).await;
        let (_task_id, b1) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        let store = &app.state_store;
        let task_id: i64 = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(b1)
            .fetch_one(store.pool())
            .await
            .unwrap();
        let b2 = store
            .insert_build(crbs_core::BuildInsert {
                product: "det",
                pkg_name: "hello-1.0-1",
                phase: "succeeded",
                backend: "chroot",
                user: "test",
                arch: Some("aarch64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        store.set_build_deterministic(b2, true).await.unwrap();

        for b in [b1, b2] {
            store
                .set_build_request_info(
                    b,
                    "/tmp/x.src.rpm",
                    &serde_json::json!({"reproduce_from_build_id": 900}).to_string(),
                )
                .await
                .unwrap();
        }

        let mut noarch1 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "aaa");
        noarch1.arch = Some("noarch".into());
        insert_artifacts(&app, b1, &[noarch1]).await;
        let mut noarch2 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "bbb");
        noarch2.arch = Some("noarch".into());
        insert_artifacts(&app, b2, &[noarch2]).await;

        let record = store.get_build(b2).await.unwrap().expect("build record");
        maybe_cross_arch_compare(&app, &record).await.unwrap();

        let rows = store
            .list_reproducibility_for_build(b1)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.kind == "cross_arch_noarch")
            .count();
        assert_eq!(
            rows, 0,
            "replay-lineage task must not get cross-arch comparison rows"
        );
    }

    #[tokio::test]
    async fn cross_arch_compare_gated_on_deterministic_tag() {
        async fn seed_two_arch_noarch_mismatch(
            app: &Arc<AppState>,
            pkg: &str,
            deterministic: bool,
        ) -> (i64, i64) {
            let store = &app.state_store;
            let task_id = crate::test_support::seed_task(store, "det", pkg).await;
            let b1 = store
                .insert_build(crbs_core::BuildInsert {
                    product: "det",
                    pkg_name: pkg,
                    phase: "succeeded",
                    backend: "chroot",
                    user: "test",
                    arch: Some("x86_64"),
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
                .unwrap();
            let b2 = store
                .insert_build(crbs_core::BuildInsert {
                    product: "det",
                    pkg_name: pkg,
                    phase: "succeeded",
                    backend: "chroot",
                    user: "test",
                    arch: Some("aarch64"),
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
                .unwrap();
            if deterministic {
                store.set_build_deterministic(b1, true).await.unwrap();
                store.set_build_deterministic(b2, true).await.unwrap();
            }
            let mut n1 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "aaa");
            n1.arch = Some("noarch".into());
            insert_artifacts(app, b1, &[n1]).await;
            let mut n2 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "bbb");
            n2.arch = Some("noarch".into());
            insert_artifacts(app, b2, &[n2]).await;
            (b1, b2)
        }

        let (app, _tmp) = setup_app(None, Some(0)).await;
        let (_b1, b2) = seed_two_arch_noarch_mismatch(&app, "non-det-1.0-1", false).await;
        on_build_terminal(&app, b2).await.unwrap();
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM build_reproducibility WHERE kind = 'cross_arch_noarch'",
        )
        .fetch_one(app.state_store.pool())
        .await
        .unwrap();
        assert_eq!(
            n, 0,
            "non-deterministic task must not produce cross-arch rows"
        );

        let (app, _tmp) = setup_app(None, Some(0)).await;
        let (b1, b2) = seed_two_arch_noarch_mismatch(&app, "det-tagged-1.0-1", true).await;
        on_build_terminal(&app, b2).await.unwrap();
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM build_reproducibility WHERE kind = 'cross_arch_noarch'",
        )
        .fetch_one(app.state_store.pool())
        .await
        .unwrap();
        assert_eq!(
            n, 1,
            "deterministic-tagged task still records cross-arch mismatch"
        );
        let rows = app
            .state_store
            .list_reproducibility_for_build(b1)
            .await
            .unwrap();
        assert_eq!(rows[0].verdict, "diff");
    }

    #[tokio::test]
    async fn non_deterministic_source_replay_records_diff() {
        let (app, _tmp) = setup_app(None, None).await;
        let store = &app.state_store;
        let task_id = crate::test_support::seed_task(store, "det", "hello-1.0-1").await;
        let src = store
            .insert_build(crbs_core::BuildInsert {
                product: "det",
                pkg_name: "hello-1.0-1",
                phase: "succeeded",
                backend: "chroot",
                user: "test",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let replay = store
            .insert_build(crbs_core::BuildInsert {
                product: "det",
                pkg_name: "hello-1.0-1",
                phase: "succeeded",
                backend: "chroot",
                user: "test",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        store
            .set_build_request_info(
                replay,
                "/tmp/x.src.rpm",
                &serde_json::json!({"reproduce_from_build_id": src}).to_string(),
            )
            .await
            .unwrap();
        insert_artifacts(
            &app,
            src,
            &[rpm_artifact("RPMS/x86_64/hello-1.0-1.x86_64.rpm", "aaa")],
        )
        .await;
        insert_artifacts(
            &app,
            replay,
            &[rpm_artifact("RPMS/x86_64/hello-1.0-1.x86_64.rpm", "zzz")],
        )
        .await;

        on_build_terminal(&app, replay).await.unwrap();
        let row = store
            .list_reproducibility_for_build(src)
            .await
            .unwrap()
            .into_iter()
            .next()
            .expect("non-deterministic source replay must produce comparison rows");
        assert_eq!(row.verdict, "diff");
    }

    #[tokio::test]
    async fn replay_comparison_skips_when_source_build_missing() {
        let (app, _tmp) = setup_app(None, None).await;
        let (_task_id, source_build) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        on_build_terminal(&app, source_build).await.unwrap();
        let replay_build_id: i64 = sqlx::query_scalar("SELECT MAX(id) FROM builds")
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();

        sqlx::query("DELETE FROM builds WHERE id = $1")
            .bind(source_build)
            .execute(app.state_store.pool())
            .await
            .unwrap();

        app.state_store
            .complete_build(replay_build_id, "succeeded", None)
            .await
            .unwrap();
        on_build_terminal(&app, replay_build_id).await.unwrap();

        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM build_reproducibility")
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();
        assert_eq!(
            n, 0,
            "missing source build record must not produce a comparison row"
        );
    }

    #[tokio::test]
    async fn cross_arch_noarch_all_identical_records_no_row() {
        let (app, _tmp) = setup_app(None, Some(0)).await;
        let (_task_id, b1) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        let store = &app.state_store;
        let task_id: i64 = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(b1)
            .fetch_one(store.pool())
            .await
            .unwrap();

        let b2 = store
            .insert_build(crbs_core::BuildInsert {
                product: "det",
                pkg_name: "hello-1.0-1",
                phase: "succeeded",
                backend: "chroot",
                user: "test",
                arch: Some("aarch64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store.set_build_deterministic(b2, true).await.unwrap();

        let mut noarch1 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "aaa");
        noarch1.arch = Some("noarch".into());
        insert_artifacts(&app, b1, &[noarch1]).await;
        let mut noarch2 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "aaa");
        noarch2.arch = Some("noarch".into());
        insert_artifacts(&app, b2, &[noarch2]).await;

        on_build_terminal(&app, b2).await.unwrap();
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM build_reproducibility WHERE kind = 'cross_arch_noarch'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            n, 0,
            "identical noarch hashes across arches must not produce a comparison row"
        );
    }

    #[tokio::test]
    async fn non_terminal_build_hook_returns_early_no_side_effects() {
        let (app, _tmp) = setup_app(None, Some(0)).await;
        let store = &app.state_store;

        let task_id = crate::test_support::seed_task(store, "det", "hello-1.0-1").await;
        let src = store
            .insert_build(crbs_core::BuildInsert {
                product: "det",
                pkg_name: "hello-1.0-1",
                phase: "succeeded",
                backend: "chroot",
                user: "test",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store.set_build_deterministic(src, true).await.unwrap();
        insert_artifacts(
            &app,
            src,
            &[rpm_artifact("RPMS/x86_64/hello-1.0-1.x86_64.rpm", "aaa")],
        )
        .await;
        let building = store
            .insert_build(crbs_core::BuildInsert {
                product: "det",
                pkg_name: "hello-1.0-1",
                phase: "building",
                backend: "chroot",
                user: "test",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .set_build_request_info(
                building,
                "/tmp/x.src.rpm",
                &serde_json::json!({"reproduce_from_build_id": src}).to_string(),
            )
            .await
            .unwrap();
        insert_artifacts(
            &app,
            building,
            &[rpm_artifact("RPMS/x86_64/hello-1.0-1.x86_64.rpm", "zzz")],
        )
        .await;
        let task_count_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
            .fetch_one(store.pool())
            .await
            .unwrap();

        on_build_terminal(&app, building).await.unwrap();

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM build_reproducibility")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            rows, 0,
            "non-terminal build must not produce comparison rows"
        );
        let builds: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            builds, 2,
            "no replay build may be created for non-terminal hook"
        );
        let task_count_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(task_count_before, task_count_after, "no task churn allowed");
    }

    #[tokio::test]
    async fn auto_replay_skips_when_product_unresolvable() {
        let (app, _tmp) = setup_app(None, None).await;
        let store = &app.state_store;

        let task_id = crate::test_support::seed_task(store, "ghost", "hello-1.0-1").await;
        let build_id = store
            .insert_build(crbs_core::BuildInsert {
                product: "ghost",
                pkg_name: "hello-1.0-1",
                phase: "succeeded",
                backend: "chroot",
                user: "test",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store.set_build_deterministic(build_id, true).await.unwrap();

        on_build_terminal(&app, build_id).await.unwrap();

        let new_builds: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds WHERE id > $1")
            .bind(build_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            new_builds, 0,
            "unresolvable product must not create a replay task"
        );
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM build_reproducibility")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            rows, 0,
            "unresolvable product must not produce comparison rows"
        );
    }

    #[tokio::test]
    async fn cross_arch_compare_skips_single_arch_and_failed_children() {
        let (app, _tmp) = setup_app(None, Some(0)).await;
        let (_task_id, b1) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        let store = &app.state_store;
        let task_id: i64 = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(b1)
            .fetch_one(store.pool())
            .await
            .unwrap();
        let b2 = store
            .insert_build(crbs_core::BuildInsert {
                product: "det",
                pkg_name: "hello-1.0-1",
                phase: "succeeded",
                backend: "chroot",
                user: "test",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store.set_build_deterministic(b2, true).await.unwrap();
        let mut noarch1 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "aaa");
        noarch1.arch = Some("noarch".into());
        insert_artifacts(&app, b1, &[noarch1]).await;
        let mut noarch2 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "bbb");
        noarch2.arch = Some("noarch".into());
        insert_artifacts(&app, b2, &[noarch2]).await;

        on_build_terminal(&app, b2).await.unwrap();
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM build_reproducibility WHERE kind = 'cross_arch_noarch'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            n, 0,
            "single-arch task has no cross-arch comparison surface (no row)"
        );

        let (app, _tmp) = setup_app(None, Some(0)).await;
        let (_task_id, b1) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        let store = &app.state_store;
        let task_id: i64 = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(b1)
            .fetch_one(store.pool())
            .await
            .unwrap();
        let b2 = store
            .insert_build(crbs_core::BuildInsert {
                product: "det",
                pkg_name: "hello-1.0-1",
                phase: "failed",
                backend: "chroot",
                user: "test",
                arch: Some("aarch64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let mut noarch1 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "aaa");
        noarch1.arch = Some("noarch".into());
        insert_artifacts(&app, b1, &[noarch1]).await;
        let mut noarch2 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "bbb");
        noarch2.arch = Some("noarch".into());
        insert_artifacts(&app, b2, &[noarch2]).await;

        on_build_terminal(&app, b1).await.unwrap();
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM build_reproducibility WHERE kind = 'cross_arch_noarch'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            n, 0,
            "failed child build must not participate in cross-arch comparison"
        );
    }

    #[tokio::test]
    async fn cross_arch_null_anchor_noarch_disclosed_in_detail() {
        let (app, _tmp) = setup_app(None, Some(0)).await;
        let (_task_id, b1) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        let store = &app.state_store;
        let task_id: i64 = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(b1)
            .fetch_one(store.pool())
            .await
            .unwrap();
        let b2 = store
            .insert_build(crbs_core::BuildInsert {
                product: "det",
                pkg_name: "hello-1.0-1",
                phase: "succeeded",
                backend: "chroot",
                user: "test",
                arch: Some("aarch64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store.set_build_deterministic(b2, true).await.unwrap();

        let mut diff1 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "aaa");
        diff1.arch = Some("noarch".into());
        insert_artifacts(&app, b1, &[diff1]).await;
        let mut diff2 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "bbb");
        diff2.arch = Some("noarch".into());
        insert_artifacts(&app, b2, &[diff2]).await;

        let mut anchorless = rpm_artifact("RPMS/noarch/anchorless-doc-1.0-1.noarch.rpm", "ignored");
        anchorless.arch = Some("noarch".into());
        anchorless.unsigned_sha256 = None;
        insert_artifacts(&app, b1, &[anchorless]).await;
        let mut anchored_other_side =
            rpm_artifact("RPMS/noarch/anchorless-doc-1.0-1.noarch.rpm", "ddd");
        anchored_other_side.arch = Some("noarch".into());
        insert_artifacts(&app, b2, &[anchored_other_side]).await;

        on_build_terminal(&app, b2).await.unwrap();

        let rows = store
            .list_reproducibility_for_build(b1)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.kind == "cross_arch_noarch")
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].verdict, "diff");
        let detail: serde_json::Value =
            serde_json::from_str(rows[0].detail_json.as_deref().unwrap_or("")).unwrap();
        let missing = detail["missing_unsigned_anchor"].as_array().unwrap();
        assert_eq!(
            missing,
            &vec![serde_json::Value::String(
                "anchorless-doc-1.0-1.noarch.rpm".into()
            )],
            "NULL-anchor noarch filename must be disclosed in detail"
        );
        let mismatched = detail["mismatched_noarch"].as_object().unwrap();
        assert_eq!(
            mismatched.len(),
            1,
            "anchorless row must not fabricate a mismatch: {mismatched:?}"
        );
        assert!(mismatched.contains_key("hello-doc-1.0-1.noarch.rpm"));

        assert!(detail.get("only_in").is_none());
    }

    #[tokio::test]
    async fn cross_arch_single_sided_file_noted_in_detail() {
        let (app, _tmp) = setup_app(None, Some(0)).await;
        let (_task_id, b1) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        let store = &app.state_store;
        let task_id: i64 = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(b1)
            .fetch_one(store.pool())
            .await
            .unwrap();
        let b2 = store
            .insert_build(crbs_core::BuildInsert {
                product: "det",
                pkg_name: "hello-1.0-1",
                phase: "succeeded",
                backend: "chroot",
                user: "test",
                arch: Some("aarch64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store.set_build_deterministic(b2, true).await.unwrap();

        let mut diff1 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "aaa");
        diff1.arch = Some("noarch".into());
        insert_artifacts(&app, b1, &[diff1]).await;
        let mut diff2 = rpm_artifact("RPMS/noarch/hello-doc-1.0-1.noarch.rpm", "bbb");
        diff2.arch = Some("noarch".into());
        insert_artifacts(&app, b2, &[diff2]).await;
        let mut solo = rpm_artifact("RPMS/noarch/solo-doc-1.0-1.noarch.rpm", "ccc");
        solo.arch = Some("noarch".into());
        insert_artifacts(&app, b1, &[solo]).await;

        on_build_terminal(&app, b2).await.unwrap();

        let rows = store
            .list_reproducibility_for_build(b1)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.kind == "cross_arch_noarch")
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].verdict, "diff");
        let detail: serde_json::Value =
            serde_json::from_str(rows[0].detail_json.as_deref().unwrap_or("")).unwrap();
        let only_in = detail["only_in"].as_object().unwrap();
        assert_eq!(
            only_in.len(),
            1,
            "only the single-sided file is annotated: {only_in:?}"
        );
        let note = &only_in["solo-doc-1.0-1.noarch.rpm"];
        assert_eq!(note["build_id"], b1);
        assert_eq!(note["arch"], "x86_64");
        let mismatched = detail["mismatched_noarch"].as_object().unwrap();
        assert_eq!(
            mismatched.len(),
            1,
            "single-sided file must not fabricate a mismatch: {mismatched:?}"
        );
        assert!(mismatched.contains_key("hello-doc-1.0-1.noarch.rpm"));

        assert!(detail.get("missing_unsigned_anchor").is_none());
    }
}
