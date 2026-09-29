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

/// ArtifactJsonEntry → Vec<NewArtifact> 纯转换：仅 RPM/SRPM 行随 build_signed
/// 置 signed。`unsigned_by_file`（签名前哈希，key = 文件 basename）由调用方
/// 在签名前预计算传入；未签名路径传空 map，回退 `sha256` 本身作比对锚。
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
            // 留档：签名前哈希（map 命中 > 未签名回退 > None）。
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

/// 提交与恢复共用的后台构建执行体。
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

    // CleanupGuard：无论成功/失败/panic 都清理 active_builds
    let cleanup = CleanupGuard {
        active_builds: app.active_builds.clone(),
        build_id,
        consumed: false,
    };

    // 清理 upload_dir 中本 build 独有的暂存副本；绝不清理 srpm_path 指向的
    // 共享 source SRPM（同 task 各 arch 共用、worker 下载源，误删即 404）。
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

    // 立即翻 building，防调度器在 engine 创建/准备期重复选取；幂等，
    // 引擎内部会再次调用。
    if let Err(e) = lifecycle.start_building().await {
        tracing::error!(build_id = %build_id, error = %e, "Failed to update build phase to building");
        fail_local(&app, build_id, Some(&e.to_string())).await;
        return;
    }

    // 创建 engine：crbs_root 显式 pin 为 server root（result_dir /
    // shared_layers 等派生路径随之）；产品配置统一 DB chain-resolve（与
    // enqueue 校验 / worker 下发同源），不走磁盘 toml fallback（残留旧
    // toml 会与 worker 配置漂移）。
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

    // 构建时配置锚（审计/debug）：与 engine 消费的 chain-resolved TOML 同源；
    // 写失败只降级（debug 回落当前配置），不阻断构建。
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

    // reproduce：backend / 资源限制不读复现请求——走与正常构建相同的解析链
    //（create_backend ← config.backend 全局→产品→默认），容器 /proc 挂载语义
    // 与源构建同态；no_network 与其余选项仍随请求。
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

    // hub-local 超时兜底：apply_options_to_engine 只透传显式 timeout（None =
    // 引擎默认无超时），hang 构建会永久占 building 行 + build_semaphore（pid
    // 存活，无回收路径）直至重启；缺省落 server.toml 的 build_timeout_secs。
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

    // reproduce：读来源 build 的 build_packages.json 恢复环境。env 的
    // TempDir guard 持有到构建结束，函数尾显式 teardown（同步
    // remove_dir_all 可达 GB 级，不能在 async 线程 Drop）；prepare 之后的
    // 各早退分支 return 前先 take + teardown。
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

    // 每 build 独立子目录：{result_root}/{task_id}/{arch}/{build_id}/。
    // 同 task 同 arch 的多个 SRPM 必须隔离 sidecar 文件（build.log /
    // crbs-artifacts.json / build_packages.json），否则互相覆盖。
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
        // 权限不变量：create_dir_all 级联目录受 umask 削减（root 下 0755/2755），
        // 逐级补 2770 + crbs 组；叶子目录随后由 engine 归 builder:crbs。
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

            // 签名前哈希（deterministic 构建）：签名原地改写产物字节，须先
            // 存档 sha256；非 deterministic 跳过（省全量哈希成本）。
            let unsigned_by_file = if engine.config().deterministic {
                compute_unsigned_hashes(&outputs).await
            } else {
                std::collections::HashMap::new()
            };

            // 自动签名：先应用服务端默认 keyring；sign_build_outputs 只做物理
            // 签名，builds.signed 置位在产物落库成功后。重放构建跳签
            //（repo_publish=0 无发布价值，.sign.lock 是串行热点）。
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

            // lifecycle.complete 已在 engine.build_into 内部调用，result_dir 已落库。
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
                                // builds.signed 在产物行落库成功后置位
                                //（signed=1 ⇒ 行内哈希新鲜）；置位失败仅
                                // warn，滞后只影响展示、重签幂等收敛。
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

            // 上方签名是同步的且产物已落库，此处 regen 天然在签名之后；失败仅 warn。
            crate::server::repo_regen::regenerate_product_repo(&app, &product).await;

            // 终态后的异步跟跑钩子（自动重放 / 比对 / cross-arch 互比），spawn 不阻塞。
            crate::server::replay::spawn_on_build_terminal(app.clone(), build_id);
        }
        Err(ref e) => {
            tracing::warn!(build_id = %build_id, error = %e, "Build failed");
            // 兜底：engine 早期失败路径可能未调 lifecycle.complete，phase 卡
            // building 成 ghost slot，此处补标 failed（终态守卫见下）。
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

            // 失败路径采集仅限 task 构建（目录已知）；非 task 目录名含内部
            // 时间戳，无法可靠重建。
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

            // 失败臂同样补终态钩子（重放失败的比对行由此落库）。
            crate::server::replay::spawn_on_build_terminal(app.clone(), build_id);
        }
    }

    // hub 本地构建是终态上报之外的第二学习来源：资源列已由 lifecycle.complete
    // 随终态落库（取消 / 无采样 → NULL，学习面自会跳过），重读终态行取真值。
    apply_local_terminal_learning(&app, build_id).await;

    // 显式 teardown reproduce 临时环境（Drop 是同步 remove_dir_all，见上方）。
    if let Some(env) = reproduce_env.take() {
        env.teardown().await;
    }

    // 正常路径：显式从 active_builds 移除，避免依赖 Drop 中的 try_lock
    cleanup.remove(&app).await;
}

/// execute_build 早退失败臂共用收口：标 failed（补偿失败仅 warn）+ 补终态
/// 钩子——重放构建翻 failed 时比对行需要钩子落库；非重放构建钩子内部判
/// 血缘/终态，no-op。`error` 传 None 保留库中已有 error_summary。
async fn fail_local(app: &Arc<AppState>, build_id: i64, error: Option<&str>) {
    if let Err(e) = mark_build_failed(&app.state_store, build_id, error).await {
        tracing::warn!(error = %e, "Failed to mark build as failed");
    }
    crate::server::replay::spawn_on_build_terminal(app.clone(), build_id);
}

/// 标记构建为 failed：`error` 落 error_summary（截断由 store 层负责），
/// `None` 保留库中已有值；返回 0 行（已终态守卫拒绝）按成功处理。
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

/// `mark_build_failed` 补偿失败的统一 warn：主失败已留痕，只降级告警；
/// `cause` 点名失败环节。
pub(crate) fn warn_mark_build_failed(error: &str, cause: &str) {
    tracing::warn!(error = %error, "Failed to mark build as failed after {cause}");
}

/// hub 本地构建终态学习：从终态行回读资源列交共享学习面（画像写 + 权重
/// 缓存失效），node-OOM 无 peak 时以本机 mem_total 为保守下界。读行失败仅
/// debug（学习面自身 best-effort，不阻塞收尾）。
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

/// hub-local 产物登记崩溃窗口的兜底 reconcile：对 "succeeded + result_dir
/// 非空 + 零产物行" 的构建重采集并幂等 upsert（窗口 = engine 翻 succeeded
/// 与产物行落库之间崩溃；UNIQUE(build_id, relative_path) upsert 天然幂等）。
/// 只碰该精确谓词：活跃构建、已有产物行（含结果 GC 翻 on_disk=0）、
/// result_dir 为空的 succeeded 均不碰；采集为空跳过。挂 scheduler 清扫循环。
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
    // 同产品只触发一次 repo 重建。
    let mut regen_products = std::collections::HashSet::new();

    for rec in candidates {
        let build_id = rec.id;
        let Some(result_dir_str) = rec.result_dir.as_deref() else {
            continue;
        };
        // 目录已删（手工清理/挂载消失）：无可修复，安静跳过防 60s 刷屏。
        if !tokio::fs::try_exists(result_dir_str).await.unwrap_or(false) {
            tracing::debug!(
                build_id = %build_id,
                "Artifact registration reconcile: result_dir missing; skipping"
            );
            continue;
        }
        // 路径防穿越：result_dir 必须严格位于该产品 result root 之下；不合法
        // 存量值只 debug 跳过（防 60s 刷屏），采集/入库失败仍 WARN 及以上。
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

        // signed 按 builds.signed 逐行设置，哈希对签名后字节重算即新鲜
        //（signed=1 ⇒ 哈希新鲜）；崩溃窗口补采拿不到签名前哈希，
        // unsigned_sha256 留 NULL（比对侧按 missing_unsigned 明示），
        // upsert COALESCE 保旧值。
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
            // 目录存在但无可采集文件：无内容可补，跳过（不误造空行）。
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

    // 补登记后发布候选集已变，重建受影响产品 repo（构建时点 regen 漏掉了
    // 这批产物）；失败仅 warn，可由下次构建 / rebuild-repo 兜底。
    for product in regen_products {
        crate::server::repo_regen::regenerate_product_repo(app, &product).await;
    }
}

/// 签名前逐产物 sha256（key = 文件 basename，与落库口径对齐）；单个文件
/// 失败仅跳过（留 None = 比对锚缺口），不阻断签名/落库主路径。
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

/// 为 hub 本地 reproduce 准备环境并重配 engine：读来源 build 的
/// build_packages.json，按回放仓库模式二态分派（Snapshot = 恢复包建复现
/// 快照仓、隔离域 = 记录全集；BaseOnly = 记录集无 sha 条目、正常解析域）。
/// env 的 TempDir guard 须由调用方持有到构建结束。
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

    // 来源 build_packages.json 目录：{task_id}/{arch}/{build_id}/ 布局。
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

    // 密闭链按回放仓库模式分派（Snapshot 隔离域 / BaseOnly 正常解析域），
    // 单点在 crbs-core apply_reproduce_engine。
    let engine = reproduce::apply_reproduce_engine(engine, &env);

    Ok((env, engine))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crbs_core::config::ServerConfig;

    /// 构造测试 AppState（crbs_root=tmp）。种子 build 的 product="test" 需有
    /// products 行——reconcile 候选按产品存在性过滤，缺行则候选为空。
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

    /// 插入 succeeded build（result_dir 落在产品 result root 下）。
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

    /// 崩溃窗口态（succeeded + 零产物行 + 磁盘有文件）→ reconcile 重采集
    /// 入库：哈希正确、RPM 行 signed 随 builds.signed、log 行恒 0；幂等
    /// 不重复造行。
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

        // 幂等：重跑后仍各一行（UNIQUE(build_id, relative_path) upsert）。
        reconcile_artifact_registration(&app).await;
        let rows = app.state_store.list_artifacts(build_id).await.unwrap();
        assert_eq!(rows.len(), 2, "reconcile re-run must not duplicate rows");
    }

    /// 非零产物行的构建不被 reconcile 触碰（行保留原哈希，即使磁盘文件已变）。
    #[tokio::test]
    async fn reconcile_leaves_builds_with_existing_rows_untouched() {
        let (app, _tmp) = setup_app().await;
        let (build_id, dir) = seed_succeeded_build(&app, false).await;

        // 先插入一行（旧哈希），磁盘文件随后被改写，模拟"已有行"状态。
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

    /// result_dir 已删除（手工清理）→ 安静跳过，不造行、不报错。
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

        // guard drop 清理为异步 spawn，轮询等待删除落地（文件与目录均消失）。
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

    /// DB-only 产品（无磁盘 toml）的 hub 本地构建走 DB chain-resolved 配置：
    /// DB 配置带非法 builder_user，构建失败且 error_summary 含
    /// "builder_user" = chain 配置确实被引擎读取合并。
    #[tokio::test]
    async fn execute_build_uses_db_chain_resolved_config_for_db_only_product() {
        let (app, tmp) = setup_app().await;

        // 非法 builder_user（含空格）+ 合法 base_packages/repos：过 chain 出口
        // shape 校验，让非法值留到引擎构造期 merge_configs 命中；配置提交后
        // resolve 缓存递归失效，chain_resolve_to_toml 必读到新配置。
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

        // pending build + 假 SRPM（引擎构造期即失败，不会消费 SRPM）。
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

    /// SRPM 命名契约钉：hub 本地对无 '-' 的暂存 SRPM 名必须在 `srpm_pkg_name`
    /// 拒绝（build failed 且 error_summary 含 "malformed SRPM"）——回退
    /// "unknown" 会让畸形 SRPM 共享 `{product}/unknown/` 目录、chain 增量
    /// 误判已构建。落点工程：写合法 DB 产品配置（含显式 chroot backend，缺省
    /// nspawn 在测试主机不可用会让失败提前落在引擎构造期），让失败精确落在
    /// 命名校验。可达性分档见断言处：无 helper 且非 root 宿主引擎构造先
    /// fail-fast，退钉 crbs-core 纯边界（同源文案），契约至少一层钉死。
    #[tokio::test]
    async fn execute_build_rejects_srpm_name_without_nvr_structure() {
        let (app, tmp) = setup_app().await;

        // 合法配置保证 chain-resolve 与引擎构造成功，失败落点后移到
        // srpm_pkg_name；缓存递归失效，必读到新配置。
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

        // pending build + 无 '-' 的畸形 SRPM 名（无 N-V-R → srpm_pkg_name 拒绝）。
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

        // N-V-R 校验可达前提是引擎构造成功；ChrootBackend::available() 在
        // Linux 上要求 euid=0 或 helper，无可用后端的宿主上引擎 fail-fast
        // 先于命名校验触发。分档：可达则钉完整 executor 契约；否则退钉
        // crbs-core 纯边界（同文件名以同源文案拒绝），"unknown" 回归在
        // 任何宿主都钉得住。
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

    /// 本地构建学习闭环（succeeded）：终态行资源列回读 → 画像 EMA 折叠 +
    /// 权重缓存失效（预填旧值必须回源到新样本）。
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

        // 预填缓存（模拟本进程已回源过该键的旧值）：收尾后必须失效回源。
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

        // engine 在 lifecycle.complete 中随终态写资源列（此处直写同一写路径）。
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

        // 学习后缓存已失效：查询回源拿到刚折叠的权重（而非预填的未知值）。
        let profiles =
            crate::server::scheduler::load_resource_profiles(&app, vec![key.clone()]).await;
        let profile = profiles.get(&key).expect("key must resolve");
        assert_eq!(profile.weight.peak_rss_kb, Some(2_000_000.0));
        assert_eq!(profile.weight.cpu_p90_cores, Some(2.5));
    }

    /// 本地构建学习闭环（failed + OOM）：走与 worker 上报同源的删失通道
    /// （node-OOM → learned max = peak × headroom、censored、ema 不写）。
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

    /// 偏差告警对照本构建**生效的**放置下限（任务级 `req_min_mem_kb` 优先于
    /// 包声明，与调度硬下限解析链同源）：
    /// A) 任务 2 GiB / 声明 10 GiB / 峰值 4 GiB（> 2×1.5、< 10×1.5）→ 必须
    ///    告警（只看声明的实现会漏报）；
    /// B) 任务 4 GiB / 声明 1 GiB / 峰值 5 GiB（< 4×1.5、> 1×1.5）→ 不告警
    ///    （只看声明的实现会误报）。
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

    /// 逐行 signed：build_signed=true 时 RPM/SRPM 行 signed=1，log 行 0。
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

    /// 签名前哈希留档时序：build_signed=true 时 unsigned_sha256 取预计算 map
    ///（签名后 sha256 不再等于锚）；未签名路径回退 sha256 本身。
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

        // 签名路径：unsigned 取预计算 map 值（与签名后 sha256 不同）。
        let rows = artifacts_json_to_new_artifacts(json.clone(), true, &map);
        assert_eq!(rows[0].sha256, "signed-hash");
        assert_eq!(
            rows[0].unsigned_sha256.as_deref(),
            Some("pre-sign-hash"),
            "signed path must archive the pre-sign hash, not the signed one"
        );
        assert_eq!(rows[1].unsigned_sha256, None);

        // 未签名路径（签名未发生/失败）：磁盘字节即未签名 → 锚 = sha256。
        let rows = artifacts_json_to_new_artifacts(json, false, &HashMap::new());
        assert_eq!(rows[0].unsigned_sha256.as_deref(), Some("signed-hash"));

        // 签名路径但 map 缺文件（reconcile 补采等缺口）：None，不用签名后哈希冒充锚。
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

    /// 失败构建（build_signed=false）所有产物 signed=0（含 RPM 残留）。
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
