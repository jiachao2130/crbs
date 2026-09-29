// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 入队构建的服务端执行：状态推进、产物登记与失败收口。

use std::path::PathBuf;
use std::sync::Arc;

use crbs_core::types::build_phase_is_terminal;
use crbs_core::BuildOptions;
use tokio_util::sync::CancellationToken;

use crate::server::resource_learning::{apply_terminal_learning, record_resources, NodeMemSource};
use crate::server::state::{AppState, CleanupGuard};

/// ArtifactJsonEntry → Vec<NewArtifact> 纯转换：仅 RPM/SRPM 行随 build_signed 置 signed。
/// unsigned_by_file（签名前哈希，key = 文件 basename）由调用方在签名前预计算传入；未签名路径传空 map，回退 sha256 本身作比对基准。
pub(crate) fn artifacts_json_to_new_artifacts(
    artifacts: crbs_core::ArtifactsJson,
    build_signed: bool,
    unsigned_by_file: &std::collections::HashMap<String, String>,
) -> Vec<crbs_core::NewArtifact> {
    artifacts
        .artifacts
        .into_iter()
        .map(|entry| {
            let kind = crbs_core::ArtifactKind::from(entry.kind.as_str());
            let row_signed = build_signed
                && matches!(
                    kind,
                    crbs_core::ArtifactKind::Rpm | crbs_core::ArtifactKind::Srpm
                );

            let unsigned_sha256 = if matches!(
                kind,
                crbs_core::ArtifactKind::Rpm | crbs_core::ArtifactKind::Srpm
            ) {
                unsigned_by_file
                    .get(
                        std::path::Path::new(&entry.path)
                            .file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_else(|| entry.path.clone())
                            .as_str(),
                    )
                    .cloned()
                    .or_else(|| {
                        if build_signed {
                            None
                        } else {
                            Some(entry.sha256.clone())
                        }
                    })
            } else {
                None
            };
            crbs_core::NewArtifact {
                relative_path: entry.path,
                kind,
                size_bytes: entry.size,
                sha256: entry.sha256,
                unsigned_sha256,
                arch: entry.arch,
                name: entry.name,
                version: entry.version,
                release: entry.release,
                epoch: entry.epoch,
                metadata_json: None,
                signed: row_signed,
            }
        })
        .collect()
}

/// 提交与恢复共用的后台构建执行体。CleanupGuard：无论成功/失败/panic 都清理 active_builds；清理 upload_dir 中本 build 独有的暂存副本，
/// 绝不清理 srpm_path 指向的共享 source SRPM（同 task 各 arch 共用、worker 下载源，误删即 404）。hub-local 超时兜底：
/// apply_options_to_engine 只透传显式 timeout，默认落 server.toml 的 build_timeout_secs。
pub(crate) async fn execute_build(
    app: Arc<AppState>,
    build_id: i64,
    product: String,
    srpm_path: PathBuf,
    opts: BuildOptions,
    permit: tokio::sync::OwnedSemaphorePermit,
    cancel: CancellationToken,
) {
    let _permit = permit;

    let cleanup = CleanupGuard {
        active_builds: app.active_builds.clone(),
        build_id,
        consumed: false,
    };

    let _srpm_cleanup =
        crate::server::staging::staged_srpm_copy_path(&app.upload_dir(), build_id, &srpm_path)
            .map(|path| crate::server::staging::StagedSrpmGuard { path });

    let lifecycle = match crbs_core::engine::BuildLifecycle::attach(
        app.state_store.clone(),
        build_id,
        std::process::id() as i64,
    )
    .await
    {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(build_id = %build_id, error = %e, "Failed to attach build lifecycle");
            fail_local(&app, build_id, Some(&e.to_string())).await;
            return;
        }
    };

    if let Err(e) = lifecycle.start_building().await {
        tracing::error!(build_id = %build_id, error = %e, "Failed to update build phase to building");
        fail_local(&app, build_id, Some(&e.to_string())).await;
        return;
    }

    let product_toml = match async {
        let record = app
            .state_store
            .get_product_by_name(&product)
            .await?
            .ok_or_else(|| crbs_core::error::CrbsError::NotFound {
                message: format!("product '{product}' not found in database"),
            })?;
        app.state_store.chain_resolve_to_toml(record.id).await
    }
    .await
    {
        Ok(toml) => toml,
        Err(e) => {
            tracing::error!(
                build_id = %build_id,
                product = %product,
                error = %e,
                "Failed to chain-resolve product config for local build"
            );
            fail_local(&app, build_id, Some(&e.to_string())).await;
            return;
        }
    };

    if let Err(e) = app
        .state_store
        .set_build_product_config_toml(build_id, &product_toml)
        .await
    {
        tracing::warn!(
            build_id = %build_id,
            error = %e,
            "Failed to persist product config snapshot for local build"
        );
    }

    let engine_construction_opts = if opts.reproduce_from_build_id.is_some() {
        crbs_core::engine_options_for_reproduce_construction(&opts)
    } else {
        opts.clone()
    };
    let engine = match crbs_core::build_engine_from_options(
        &product,
        &engine_construction_opts,
        app.state_store.clone(),
        Some(product_toml.as_str()),
        Some(&app.crbs_root),
    )
    .await
    {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(build_id = %build_id, error = ?e, "Failed to create engine");
            fail_local(&app, build_id, Some(&e.to_string())).await;
            return;
        }
    };

    let engine = match crbs_core::apply_options_to_engine(engine, &opts) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(build_id = %build_id, error = ?e, "Failed to apply build options");
            fail_local(&app, build_id, Some(&e.to_string())).await;
            return;
        }
    };

    let engine = engine.with_timeout(
        crbs_core::effective_build_timeout(opts.timeout, app.server_config.build_timeout_secs)
            .map(std::time::Duration::from_secs),
    );

    let build_record = match app.state_store.get_build(build_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            tracing::error!(build_id = %build_id, "Build record disappeared after start_building");
            fail_local(&app, build_id, None).await;
            return;
        }
        Err(e) => {
            tracing::error!(build_id = %build_id, error = %e, "Failed to query build record");
            fail_local(&app, build_id, Some(&e.to_string())).await;
            return;
        }
    };

    let result_dir = app.result_dir_for_or_default(&product).await;

    let (mut reproduce_env, engine) = if let Some(src_id) = opts.reproduce_from_build_id {
        match prepare_reproduce_for_build(&app, src_id, &product, engine, &cancel).await {
            Ok((env, re_engine)) => {
                tracing::info!(
                    build_id = %build_id,
                    source_build_id = %src_id,
                    restored = env.restored_count,
                    "Reproduce environment prepared"
                );
                (Some(env), re_engine)
            }
            Err(e) => {
                tracing::error!(
                    build_id = %build_id,
                    source_build_id = %src_id,
                    error = %e,
                    "Failed to prepare reproduce environment"
                );
                fail_local(&app, build_id, Some(&e.to_string())).await;
                return;
            }
        }
    } else {
        (None, engine)
    };

    let task_arch_dir =
        if let (Some(task_id), Some(ref arch)) = (build_record.task_id, &build_record.arch) {
            Some(
                result_dir
                    .join(task_id.to_string())
                    .join(arch)
                    .join(build_id.to_string()),
            )
        } else {
            None
        };

    let result = if let Some(ref arch_dir) = task_arch_dir {
        if let Err(e) = tokio::fs::create_dir_all(arch_dir).await {
            tracing::error!(
                build_id = %build_id,
                path = %arch_dir.display(),
                error = %e,
                "Failed to create task arch result dir"
            );
            fail_local(&app, build_id, Some(&e.to_string())).await;
            if let Some(env) = reproduce_env.take() {
                env.teardown().await;
            }
            return;
        }

        crate::server::staging::enforce_result_tree_invariant(arch_dir, &result_dir).await;
        engine
            .build_into(arch_dir, &srpm_path, &cancel, Some(lifecycle))
            .await
    } else {
        engine.build(&srpm_path, &cancel, Some(lifecycle)).await
    };
    match result {
        Ok(mut outputs) => {
            tracing::info!(build_id = %build_id, "Build succeeded");

            let unsigned_by_file = if engine.config().deterministic {
                compute_unsigned_hashes(&outputs).await
            } else {
                std::collections::HashMap::new()
            };

            let is_replay = opts.reproduce_from_build_id.is_some();
            if is_replay {
                tracing::info!(
                    build_id = %build_id,
                    source_build_id = ?opts.reproduce_from_build_id,
                    "Replay build: skipping GPG signing (repo_publish=0, no publish value)"
                );
            } else {
                let mut sign_config = engine.config().clone();
                crate::server::signing::apply_server_gpg_home_default(&mut sign_config).await;
                crbs_core::sign::sign_build_outputs(&mut outputs, &sign_config).await;
            }

            let build_signed = outputs.signed;
            match crbs_core::engine::artifact_harvest::collect_artifacts(
                &outputs.result_dir,
                Some(&cancel),
            )
            .await
            {
                Ok(artifacts) => {
                    let new_artifacts =
                        artifacts_json_to_new_artifacts(artifacts, build_signed, &unsigned_by_file);

                    if !new_artifacts.is_empty() {
                        match app
                            .state_store
                            .commit_local_build_artifacts(build_id, &new_artifacts)
                            .await
                        {
                            Ok(ids) => {
                                tracing::info!(
                                    build_id = %build_id,
                                    inserted = ids.len(),
                                    signed = build_signed,
                                    "Hub-local artifacts inserted into DB"
                                );

                                if build_signed {
                                    if let Err(e) =
                                        app.state_store.update_build_signed(build_id, true).await
                                    {
                                        tracing::warn!(
                                            build_id = %build_id,
                                            error = %e,
                                            "Failed to mark hub-local build signed after artifact insert"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(build_id = %build_id, error = %e, "Failed to commit hub-local artifacts");
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(build_id = %build_id, error = %e, "collect_artifacts failed for hub-local build");
                }
            }

            crate::server::repo_regen::regenerate_product_repo(&app, &product).await;

            crate::server::replay::spawn_on_build_terminal(app.clone(), build_id);
        }
        Err(ref e) => {
            tracing::warn!(build_id = %build_id, error = %e, "Build failed");

            let record = app.state_store.get_build(build_id).await;
            if let Ok(Some(r)) = record {
                if !build_phase_is_terminal(&r.phase) {
                    if let Err(e2) =
                        mark_build_failed(&app.state_store, build_id, Some(&e.to_string())).await
                    {
                        warn_mark_build_failed(&e2, "engine error");
                    }
                }
            }

            if let Some(ref artifact_dir) = task_arch_dir {
                match crbs_core::engine::artifact_harvest::collect_artifacts(
                    artifact_dir,
                    Some(&cancel),
                )
                .await
                {
                    Ok(artifacts) => {
                        let new_artifacts = artifacts_json_to_new_artifacts(
                            artifacts,
                            false,
                            &std::collections::HashMap::new(),
                        );

                        if !new_artifacts.is_empty() {
                            if let Err(e) = app
                                .state_store
                                .commit_local_build_artifacts(build_id, &new_artifacts)
                                .await
                            {
                                tracing::warn!(build_id = %build_id, error = %e, "Failed to commit failed-build artifacts");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            build_id = %build_id,
                            dir = %artifact_dir.display(),
                            error = %e,
                            "collect_artifacts failed for failed build"
                        );
                    }
                }
            } else {
                tracing::debug!(
                    build_id = %build_id,
                    "Skipping artifact collection for non-task failed build (result dir unknown)"
                );
            }

            crate::server::replay::spawn_on_build_terminal(app.clone(), build_id);
        }
    }

    apply_local_terminal_learning(&app, build_id).await;

    if let Some(env) = reproduce_env.take() {
        env.teardown().await;
    }

    cleanup.remove(&app).await;
}

async fn fail_local(app: &Arc<AppState>, build_id: i64, error: Option<&str>) {
    if let Err(e) = mark_build_failed(&app.state_store, build_id, error).await {
        tracing::warn!(error = %e, "Failed to mark build as failed");
    }
    crate::server::replay::spawn_on_build_terminal(app.clone(), build_id);
}

/// 标记构建为 failed：`error` 写入 error_summary（截断由 store 层负责），
/// 传 `None` 保留库中已有值；影响 0 行（终态守卫拒绝）按成功处理。
pub(crate) async fn mark_build_failed(
    state_store: &Arc<crbs_core::StateStore>,
    build_id: i64,
    error: Option<&str>,
) -> Result<(), String> {
    state_store
        .complete_build_with_error(build_id, "failed", None, error)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// `mark_build_failed` 补偿失败的统一告警出口：主失败已留痕，此处仅降级
/// 为 warn；`cause` 标明失败发生的环节。
pub(crate) fn warn_mark_build_failed(error: &str, cause: &str) {
    tracing::warn!(error = %error, "Failed to mark build as failed after {cause}");
}

async fn apply_local_terminal_learning(app: &Arc<AppState>, build_id: i64) {
    let rec = match app.state_store.get_build(build_id).await {
        Ok(Some(rec)) => rec,
        Ok(None) => return,
        Err(e) => {
            tracing::debug!(
                build_id = %build_id,
                error = %e,
                "Local terminal learning skipped: failed to load build record"
            );
            return;
        }
    };
    let resources = record_resources(&rec);
    apply_terminal_learning(
        app,
        &rec,
        &rec.phase,
        resources.as_ref(),
        NodeMemSource::HubLocal,
    )
    .await;
}

/// 产物登记对账：终态时核对 DB 产物行与磁盘，漏登记补登。
pub(crate) async fn reconcile_artifact_registration(app: &Arc<AppState>) {
    let candidates = match app
        .state_store
        .list_succeeded_builds_without_artifacts()
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "Artifact registration reconcile: candidate query failed");
            return;
        }
    };

    let mut regen_products = std::collections::HashSet::new();

    for rec in candidates {
        let build_id = rec.id;
        let Some(result_dir_str) = rec.result_dir.as_deref() else {
            continue;
        };

        if !tokio::fs::try_exists(result_dir_str).await.unwrap_or(false) {
            tracing::debug!(
                build_id = %build_id,
                "Artifact registration reconcile: result_dir missing; skipping"
            );
            continue;
        }

        let result_root = app.result_dir_for_or_default(&rec.product).await;
        let result_dir =
            match crbs_core::util::validate_result_dir(result_dir_str, &result_root).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::debug!(
                        build_id = %build_id,
                        result_dir = %result_dir_str,
                        error = %e,
                        "Artifact registration reconcile: invalid result_dir; skipping"
                    );
                    continue;
                }
            };

        let artifacts = match crbs_core::engine::artifact_harvest::collect_artifacts(
            &result_dir,
            None,
        )
        .await
        {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(
                    build_id = %build_id,
                    error = %e,
                    "Artifact registration reconcile: collect_artifacts failed; skipping this round"
                );
                continue;
            }
        };
        let new_artifacts = artifacts_json_to_new_artifacts(
            artifacts,
            rec.signed,
            &std::collections::HashMap::new(),
        );
        if new_artifacts.is_empty() {
            tracing::debug!(
                build_id = %build_id,
                "Artifact registration reconcile: nothing to collect; skipping"
            );
            continue;
        }

        let insert = app
            .state_store
            .commit_local_build_artifacts(build_id, &new_artifacts)
            .await
            .map(|ids| ids.len());

        match insert {
            Ok(count) => {
                tracing::warn!(
                    build_id = %build_id,
                    inserted = count,
                    "Artifact registration reconcile: re-registered artifacts after crash window"
                );
                regen_products.insert(rec.product.clone());
            }
            Err(e) => {
                tracing::warn!(
                    build_id = %build_id,
                    error = %e,
                    "Artifact registration reconcile: artifact insert failed; retrying next sweep"
                );
            }
        }
    }

    for product in regen_products {
        crate::server::repo_regen::regenerate_product_repo(app, &product).await;
    }
}

async fn compute_unsigned_hashes(
    outputs: &crbs_core::types::BuildOutputs,
) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for path in outputs.rpms.iter().chain(outputs.srpms.iter()) {
        let Some(name) = path.file_name().map(|s| s.to_string_lossy().to_string()) else {
            continue;
        };
        match crbs_core::engine::artifact_harvest::sha256_file(path).await {
            Ok(sha) => {
                map.insert(name, sha);
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "Failed to hash artifact before signing; unsigned_sha256 will be NULL for it"
                );
            }
        }
    }
    map
}

async fn prepare_reproduce_for_build(
    app: &Arc<AppState>,
    source_build_id: i64,
    product: &str,
    engine: crbs_core::engine::BuildEngine,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<
    (
        crbs_core::engine::reproduce::ReproduceEnv,
        crbs_core::engine::BuildEngine,
    ),
    crbs_core::error::CrbsError,
> {
    use crbs_core::engine::reproduce;

    let src = app
        .state_store
        .get_build(source_build_id)
        .await?
        .ok_or_else(|| crbs_core::error::CrbsError::NotFound {
            message: format!("reproduce source build {} not found", source_build_id),
        })?;

    let result_root = app.result_dir_for_or_default(product).await;
    let src_dir = match (src.task_id, src.arch.as_deref()) {
        (Some(tid), Some(a)) => crate::server::routes::builds::service::resolve_build_packages_dir(
            &result_root,
            tid,
            a,
            source_build_id,
        )
        .await
        .ok_or_else(|| crbs_core::error::CrbsError::NotFound {
            message: format!(
                "reproduce source build {} has no build_packages.json (task/arch/build_id layout)",
                source_build_id
            ),
        })?,
        _ => {
            return Err(crbs_core::error::CrbsError::NotFound {
                message: format!(
                    "reproduce source build {} has no task_id/arch; cannot locate build_packages.json",
                    source_build_id
                ),
            });
        }
    };

    let env = reproduce::prepare_reproduce_env(&src_dir, engine.config(), Some(cancel)).await?;

    let engine = reproduce::apply_reproduce_engine(engine, &env);

    Ok((env, engine))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crbs_core::config::ServerConfig;

    async fn setup_app() -> (Arc<crate::server::state::AppState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        store
            .create_product(crbs_core::CreateProductInput {
                name: "test",
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: crbs_core::VISIBILITY_PUBLIC,
                config: &crbs_core::config::ProductConfig::default(),
                changed_by_user_id: None,
                reason: Some("reconcile test seed"),
            })
            .await
            .unwrap();
        let app = Arc::new(crate::server::state::AppState::for_test(
            store,
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        (app, tmp)
    }

    async fn seed_succeeded_build(
        app: &Arc<crate::server::state::AppState>,
        signed: bool,
    ) -> (i64, PathBuf) {
        let task_id = crate::test_support::seed_task(&app.state_store, "test", "pkg").await;
        let build_id = app
            .state_store
            .insert_build(crbs_core::BuildInsert {
                product: "test",
                pkg_name: "pkg",
                phase: "succeeded",
                backend: "chroot",
                user: "tester",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let result_dir = app
            .result_dir_for_or_default("test")
            .await
            .join("1")
            .join("x86_64")
            .join(build_id.to_string());
        tokio::fs::create_dir_all(result_dir.join("RPMS/x86_64"))
            .await
            .unwrap();
        tokio::fs::write(
            result_dir.join("RPMS/x86_64/hello-1.0-1.x86_64.rpm"),
            b"rpm-bytes",
        )
        .await
        .unwrap();
        tokio::fs::write(result_dir.join("build.log"), b"log-bytes")
            .await
            .unwrap();
        app.state_store
            .update_build_info(build_id, Some(result_dir.to_str().unwrap()), None, "chroot")
            .await
            .unwrap();
        if signed {
            app.state_store
                .update_build_signed(build_id, true)
                .await
                .unwrap();
        }
        (build_id, result_dir)
    }

    async fn artifact_row(
        app: &Arc<crate::server::state::AppState>,
        build_id: i64,
        rel: &str,
    ) -> Option<crbs_core::Artifact> {
        app.state_store
            .list_artifacts(build_id)
            .await
            .unwrap()
            .into_iter()
            .find(|a| a.relative_path == rel)
    }

    #[tokio::test]
    async fn reconcile_registers_rowless_succeeded_build_and_is_idempotent() {
        let (app, _tmp) = setup_app().await;
        let (build_id, _dir) = seed_succeeded_build(&app, true).await;

        reconcile_artifact_registration(&app).await;

        let rpm_rel = "RPMS/x86_64/hello-1.0-1.x86_64.rpm";
        let rpm = artifact_row(&app, build_id, rpm_rel).await;
        let rpm = rpm.expect("rpm row must be registered");
        assert!(rpm.signed, "builds.signed=1 ⇒ reconciled rpm row signed=1");
        let (expect_sha, expect_size) =
            crbs_core::engine::artifact_harvest::sha256_file_with_size(&_dir.join(rpm_rel))
                .await
                .unwrap();
        assert_eq!(rpm.sha256, expect_sha);
        assert_eq!(rpm.size_bytes, expect_size);

        let log = artifact_row(&app, build_id, "build.log")
            .await
            .expect("log row must be registered");
        assert!(!log.signed, "log row must stay signed=0");

        reconcile_artifact_registration(&app).await;
        let rows = app.state_store.list_artifacts(build_id).await.unwrap();
        assert_eq!(rows.len(), 2, "reconcile re-run must not duplicate rows");
    }

    #[tokio::test]
    async fn reconcile_leaves_builds_with_existing_rows_untouched() {
        let (app, _tmp) = setup_app().await;
        let (build_id, dir) = seed_succeeded_build(&app, false).await;

        let now = crbs_core::util::db_now_utc();
        let mut tx = app.state_store.pool().begin().await.unwrap();
        app.state_store
            .insert_artifacts_tx(
                &mut tx,
                build_id,
                &[crbs_core::NewArtifact {
                    relative_path: "RPMS/x86_64/hello-1.0-1.x86_64.rpm".to_string(),
                    kind: crbs_core::ArtifactKind::Rpm,
                    size_bytes: 1,
                    sha256: "stale-hash".to_string(),
                    unsigned_sha256: None,
                    arch: Some("x86_64".to_string()),
                    name: Some("hello".to_string()),
                    version: Some("1.0".to_string()),
                    release: Some("1".to_string()),
                    epoch: None,
                    metadata_json: None,
                    signed: false,
                }],
                &now,
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
        tokio::fs::write(dir.join("RPMS/x86_64/hello-1.0-1.x86_64.rpm"), b"new-bytes")
            .await
            .unwrap();

        reconcile_artifact_registration(&app).await;

        let rpm = artifact_row(&app, build_id, "RPMS/x86_64/hello-1.0-1.x86_64.rpm")
            .await
            .expect("existing row must survive");
        assert_eq!(
            rpm.sha256, "stale-hash",
            "non-zero-row build must not be re-collected"
        );
        assert!(!rpm.signed);
    }

    #[tokio::test]
    async fn reconcile_skips_when_result_dir_missing() {
        let (app, _tmp) = setup_app().await;
        let (build_id, dir) = seed_succeeded_build(&app, false).await;
        tokio::fs::remove_dir_all(&dir).await.unwrap();

        reconcile_artifact_registration(&app).await;

        assert!(
            app.state_store
                .list_artifacts(build_id)
                .await
                .unwrap()
                .is_empty(),
            "missing result_dir must not produce artifact rows"
        );
    }

    #[tokio::test]
    async fn stage_srpm_copies_file_and_guard_cleans_up() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("hello.src.rpm");
        tokio::fs::write(&src, b"dummy srpm").await.unwrap();

        let staged =
            crate::server::staging::stage_srpm(tmp.path(), "123", &src, "hello.src.rpm", false)
                .await
                .unwrap();

        assert!(staged.exists());
        let content = tokio::fs::read_to_string(&staged).await.unwrap();
        assert_eq!(content, "dummy srpm");

        let guard = crate::server::staging::StagedSrpmGuard {
            path: staged.clone(),
        };
        drop(guard);
        for _ in 0..100 {
            if !staged.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(!staged.exists());
        assert!(!staged.parent().unwrap().exists());
    }

    #[tokio::test]
    async fn execute_build_uses_db_chain_resolved_config_for_db_only_product() {
        let (app, tmp) = setup_app().await;

        let record = app
            .state_store
            .get_product_by_name("test")
            .await
            .unwrap()
            .expect("seeded product must exist");
        let bad_cfg = crbs_core::config::ProductConfig {
            builder_user: Some("bad name".into()),
            base_packages: vec!["bash".into()],
            repos: vec![crbs_core::config::RepoConfig {
                name: "base".into(),
                baseurl: "http://example/repo".into(),
                enabled: true,
                gpgcheck: false,
                gpgkey: None,
                priority: 99,
                cost: 1000,
                module_hotfixes: false,
                exclude: Vec::new(),
                includepkgs: Vec::new(),
                extra: Default::default(),
            }],
            ..Default::default()
        };
        app.state_store
            .update_product_config(
                record.id,
                &bad_cfg,
                None,
                Some("test: invalid builder_user in DB config"),
                None,
            )
            .await
            .unwrap();

        let task_id = crate::test_support::seed_task(&app.state_store, "test", "pkg").await;
        let build_id = app
            .state_store
            .insert_build(crbs_core::BuildInsert {
                product: "test",
                pkg_name: "pkg",
                phase: "pending",
                backend: "chroot",
                user: "tester",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let srpm_path = tmp.path().join("fake.src.rpm");
        tokio::fs::write(&srpm_path, b"fake srpm").await.unwrap();

        let permit = app.build_semaphore.clone().acquire_owned().await.unwrap();
        execute_build(
            app.clone(),
            build_id,
            "test".to_string(),
            srpm_path,
            crbs_core::BuildOptions::default(),
            permit,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;

        let rec = app
            .state_store
            .get_build(build_id)
            .await
            .unwrap()
            .expect("build record must exist");
        assert_eq!(rec.phase, "failed");
        let summary = rec.error_summary.as_deref().unwrap_or("");
        assert!(
            summary.contains("builder_user"),
            "failure must come from chain-resolved DB config validation \
             (not disk fallback), got: {summary}"
        );
    }

    #[tokio::test]
    async fn execute_build_rejects_srpm_name_without_nvr_structure() {
        let (app, tmp) = setup_app().await;

        let record = app
            .state_store
            .get_product_by_name("test")
            .await
            .unwrap()
            .expect("seeded product must exist");
        let legal_cfg = crbs_core::config::ProductConfig {
            backend: Some("chroot".into()),
            base_packages: vec!["bash".into()],
            repos: vec![crbs_core::config::RepoConfig {
                name: "base".into(),
                baseurl: "http://example/repo".into(),
                enabled: true,
                gpgcheck: false,
                gpgkey: None,
                priority: 99,
                cost: 1000,
                module_hotfixes: false,
                exclude: Vec::new(),
                includepkgs: Vec::new(),
                extra: Default::default(),
            }],
            ..Default::default()
        };
        app.state_store
            .update_product_config(
                record.id,
                &legal_cfg,
                None,
                Some("test: legal DB config"),
                None,
            )
            .await
            .unwrap();

        let task_id = crate::test_support::seed_task(&app.state_store, "test", "pkg").await;
        let build_id = app
            .state_store
            .insert_build(crbs_core::BuildInsert {
                product: "test",
                pkg_name: "pkg",
                phase: "pending",
                backend: "chroot",
                user: "tester",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let srpm_path = tmp.path().join("malformed.src.rpm");
        tokio::fs::write(&srpm_path, b"fake srpm").await.unwrap();

        let permit = app.build_semaphore.clone().acquire_owned().await.unwrap();
        let srpm_path_for_boundary = srpm_path.clone();
        execute_build(
            app.clone(),
            build_id,
            "test".to_string(),
            srpm_path,
            crbs_core::BuildOptions::default(),
            permit,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;

        let rec = app
            .state_store
            .get_build(build_id)
            .await
            .unwrap()
            .expect("build record must exist");
        assert_eq!(rec.phase, "failed");
        let summary = rec.error_summary.as_deref().unwrap_or("");

        if summary.contains("malformed SRPM") {
            return;
        }
        assert!(
            summary.contains("not available on this host"),
            "expected either srpm_pkg_name N-V-R rejection or the engine \
             construction backend-availability failure, got: {summary}"
        );
        let err = crbs_core::engine::srpm_pkg_name(&srpm_path_for_boundary).unwrap_err();
        assert!(
            err.to_string().contains("malformed SRPM"),
            "pure N-V-R boundary must reject the same name with the shared \
             message, got: {err}"
        );
    }

    #[tokio::test]
    async fn local_terminal_learning_folds_profile_and_invalidates_weight_cache() {
        let (app, _tmp) = setup_app().await;
        let task_id = crate::test_support::seed_task(&app.state_store, "test", "heavy").await;
        let build_id = app
            .state_store
            .insert_build(crbs_core::BuildInsert {
                product: "test",
                pkg_name: "heavy",
                phase: "pending",
                backend: "nspawn",
                user: "tester",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        let key = (
            "test".to_string(),
            "heavy".to_string(),
            "x86_64".to_string(),
        );
        app.resource_weight_cache.fill(&key, Default::default());
        assert!(
            app.resource_weight_cache
                .lookup("test", "heavy", "x86_64")
                .is_some(),
            "precondition: stale cache entry must exist"
        );

        app.state_store
            .complete_build_with_resources(
                build_id,
                "succeeded",
                None,
                Some(crbs_core::engine::ResourceUsage {
                    peak_rss_kb: Some(2_000_000),
                    cpu_p90_cores: Some(2.5),
                    sample_ncpu: Some(8),
                    ..Default::default()
                }),
            )
            .await
            .unwrap();

        apply_local_terminal_learning(&app, build_id).await;

        let row = app
            .state_store
            .get_profile("test", "heavy", "x86_64")
            .await
            .unwrap()
            .expect("hub-local succeeded sample must create the profile row");
        assert_eq!(row.learned_ema_mem_kb, Some(2_000_000));
        assert_eq!(row.learned_backend.as_deref(), Some("cgroup"));
        assert_eq!(row.learned_sample_ncpu, Some(8));
        assert_eq!(
            app.metrics
                .profile_updates_total(crate::server::metrics::ProfileUpdateKind::Learned),
            1
        );

        let profiles =
            crate::server::scheduler::load_resource_profiles(&app, vec![key.clone()]).await;
        let profile = profiles.get(&key).expect("key must resolve");
        assert_eq!(profile.weight.peak_rss_kb, Some(2_000_000.0));
        assert_eq!(profile.weight.cpu_p90_cores, Some(2.5));
    }

    #[tokio::test]
    async fn local_terminal_learning_censors_node_oom() {
        let (app, _tmp) = setup_app().await;
        let task_id = crate::test_support::seed_task(&app.state_store, "test", "big").await;
        let build_id = app
            .state_store
            .insert_build(crbs_core::BuildInsert {
                product: "test",
                pkg_name: "big",
                phase: "pending",
                backend: "nspawn",
                user: "tester",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        app.state_store
            .complete_build_with_resources(
                build_id,
                "failed",
                None,
                Some(crbs_core::engine::ResourceUsage {
                    peak_rss_kb: Some(3_000_000),
                    oom_killed: Some(true),
                    sample_backend: Some(crbs_core::engine::SAMPLE_BACKEND_CGROUP),
                    sample_ncpu: Some(4),
                    ..Default::default()
                }),
            )
            .await
            .unwrap();

        apply_local_terminal_learning(&app, build_id).await;

        let row = app
            .state_store
            .get_profile("test", "big", "x86_64")
            .await
            .unwrap()
            .expect("hub-local node-OOM must censor-create the profile row");
        assert_eq!(row.learned_max_mem_kb, Some(3_750_000));
        assert_eq!(row.learned_ema_mem_kb, None);
        assert!(row.learned_censored);
        assert_eq!(
            app.metrics
                .build_oom_total(crate::server::metrics::BuildOomKind::Node),
            1
        );
    }

    #[tokio::test]
    async fn deviation_warning_uses_task_level_floor() {
        const GIB: i64 = 1024 * 1024;
        let (app, _tmp) = setup_app().await;

        async fn seed_succeeded(
            store: &crbs_core::StateStore,
            pkg: &str,
            req_min: i64,
            peak: i64,
        ) -> i64 {
            let task_id = crate::test_support::seed_task(store, "test", pkg).await;
            let build_id = store
                .insert_build(crbs_core::BuildInsert {
                    product: "test",
                    pkg_name: pkg,
                    phase: "pending",
                    backend: "nspawn",
                    user: "tester",
                    arch: Some("x86_64"),
                    req_min_mem_kb: Some(req_min),
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
                .unwrap();
            store
                .complete_build_with_resources(
                    build_id,
                    "succeeded",
                    None,
                    Some(crbs_core::engine::ResourceUsage {
                        peak_rss_kb: Some(peak),
                        sample_backend: Some(crbs_core::engine::SAMPLE_BACKEND_CGROUP),
                        ..Default::default()
                    }),
                )
                .await
                .unwrap();
            build_id
        }

        app.state_store
            .set_declared_requirements("test", "dev-a", "x86_64", Some(10 * GIB), None, None)
            .await
            .unwrap();
        let build_a = seed_succeeded(&app.state_store, "dev-a", 2 * GIB, 4 * GIB).await;
        apply_local_terminal_learning(&app, build_a).await;
        let summary_a = app
            .state_store
            .get_build(build_a)
            .await
            .unwrap()
            .unwrap()
            .error_summary
            .unwrap_or_default();
        assert!(
            summary_a.contains("effective placement min_mem 2097152 KB"),
            "task-level floor (2 GiB) must drive the warning, got: {summary_a}"
        );

        app.state_store
            .set_declared_requirements("test", "dev-b", "x86_64", Some(GIB), None, None)
            .await
            .unwrap();
        let build_b = seed_succeeded(&app.state_store, "dev-b", 4 * GIB, 5 * GIB).await;
        apply_local_terminal_learning(&app, build_b).await;
        let summary_b = app
            .state_store
            .get_build(build_b)
            .await
            .unwrap()
            .unwrap()
            .error_summary;
        assert!(
            summary_b.is_none(),
            "task-level floor (4 GiB) admits a 5 GiB peak; declaration must not override it, got: {summary_b:?}"
        );
    }

    #[test]
    fn test_artifacts_json_signed_per_row() {
        use crbs_core::{ArtifactJsonEntry, ArtifactsJson};

        let json = ArtifactsJson {
            version: 1,
            build_id: Some(1),
            artifacts: vec![
                ArtifactJsonEntry {
                    path: "RPMS/x86_64/hello-1.0-1.x86_64.rpm".to_string(),
                    kind: "rpm".to_string(),
                    size: 1024,
                    sha256: "hash1".to_string(),
                    arch: Some("x86_64".to_string()),
                    name: Some("hello".to_string()),
                    version: Some("1.0".to_string()),
                    release: Some("1".to_string()),
                    epoch: None,
                },
                ArtifactJsonEntry {
                    path: "SRPMS/hello-1.0-1.src.rpm".to_string(),
                    kind: "srpm".to_string(),
                    size: 512,
                    sha256: "hash2".to_string(),
                    arch: None,
                    name: Some("hello".to_string()),
                    version: Some("1.0".to_string()),
                    release: Some("1".to_string()),
                    epoch: None,
                },
                ArtifactJsonEntry {
                    path: "data/build.log".to_string(),
                    kind: "log".to_string(),
                    size: 256,
                    sha256: "hash3".to_string(),
                    arch: None,
                    name: None,
                    version: None,
                    release: None,
                    epoch: None,
                },
            ],
        };

        let signed_true =
            artifacts_json_to_new_artifacts(json.clone(), true, &std::collections::HashMap::new());
        assert_eq!(signed_true.len(), 3);
        assert!(signed_true[0].signed, "RPM should be signed");
        assert!(signed_true[1].signed, "SRPM should be signed");
        assert!(!signed_true[2].signed, "log should NOT be signed");

        let signed_false =
            artifacts_json_to_new_artifacts(json, false, &std::collections::HashMap::new());
        assert_eq!(signed_false.len(), 3);
        assert!(!signed_false[0].signed, "RPM should NOT be signed");
        assert!(!signed_false[1].signed, "SRPM should NOT be signed");
        assert!(!signed_false[2].signed, "log should NOT be signed");
    }

    #[test]
    fn test_unsigned_sha256_from_presize_map() {
        use crbs_core::{ArtifactJsonEntry, ArtifactsJson};
        use std::collections::HashMap;

        let json = ArtifactsJson {
            version: 1,
            build_id: Some(1),
            artifacts: vec![
                ArtifactJsonEntry {
                    path: "RPMS/x86_64/hello-1.0-1.x86_64.rpm".to_string(),
                    kind: "rpm".to_string(),
                    size: 1024,
                    sha256: "signed-hash".to_string(),
                    arch: Some("x86_64".to_string()),
                    name: None,
                    version: None,
                    release: None,
                    epoch: None,
                },
                ArtifactJsonEntry {
                    path: "build.log".to_string(),
                    kind: "log".to_string(),
                    size: 5,
                    sha256: "log-hash".to_string(),
                    arch: None,
                    name: None,
                    version: None,
                    release: None,
                    epoch: None,
                },
            ],
        };

        let mut map = HashMap::new();
        map.insert(
            "hello-1.0-1.x86_64.rpm".to_string(),
            "pre-sign-hash".to_string(),
        );

        let rows = artifacts_json_to_new_artifacts(json.clone(), true, &map);
        assert_eq!(rows[0].sha256, "signed-hash");
        assert_eq!(
            rows[0].unsigned_sha256.as_deref(),
            Some("pre-sign-hash"),
            "signed path must archive the pre-sign hash, not the signed one"
        );
        assert_eq!(rows[1].unsigned_sha256, None);

        let rows = artifacts_json_to_new_artifacts(json, false, &HashMap::new());
        assert_eq!(rows[0].unsigned_sha256.as_deref(), Some("signed-hash"));

        let rows = artifacts_json_to_new_artifacts(single_rpm_json(), true, &HashMap::new());
        assert_eq!(rows[0].unsigned_sha256, None);
    }

    fn single_rpm_json() -> crbs_core::ArtifactsJson {
        crbs_core::ArtifactsJson {
            version: 1,
            build_id: Some(1),
            artifacts: vec![crbs_core::ArtifactJsonEntry {
                path: "RPMS/x86_64/hello-1.0-1.x86_64.rpm".to_string(),
                kind: "rpm".to_string(),
                size: 1024,
                sha256: "signed-hash".to_string(),
                arch: Some("x86_64".to_string()),
                name: None,
                version: None,
                release: None,
                epoch: None,
            }],
        }
    }

    #[test]
    fn test_failed_build_all_unsigned() {
        use crbs_core::{ArtifactJsonEntry, ArtifactsJson};

        let json = ArtifactsJson {
            version: 1,
            build_id: Some(1),
            artifacts: vec![
                ArtifactJsonEntry {
                    path: "RPMS/x86_64/partial.rpm".to_string(),
                    kind: "rpm".to_string(),
                    size: 999,
                    sha256: "partial".to_string(),
                    arch: Some("x86_64".to_string()),
                    name: Some("partial".to_string()),
                    version: Some("1.0".to_string()),
                    release: Some("1".to_string()),
                    epoch: None,
                },
                ArtifactJsonEntry {
                    path: "build.log".to_string(),
                    kind: "log".to_string(),
                    size: 100,
                    sha256: "log".to_string(),
                    arch: None,
                    name: None,
                    version: None,
                    release: None,
                    epoch: None,
                },
            ],
        };

        let artifacts =
            artifacts_json_to_new_artifacts(json, false, &std::collections::HashMap::new());
        assert_eq!(artifacts.len(), 2);
        assert!(
            !artifacts[0].signed,
            "partial RPM in failed build should NOT be signed"
        );
        assert!(
            !artifacts[1].signed,
            "log in failed build should NOT be signed"
        );
    }
}
