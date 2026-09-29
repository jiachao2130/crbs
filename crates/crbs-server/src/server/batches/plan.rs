// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 整仓重建批次规划服务：前置校验 → hub 工具检查 → 仓库集组装 → SRPM 批量
//! BR 提取 → 建图分轮 → 计划重写（幂等重入）→ running 交棒。
//!
//! 失败路径不变量：任何失败路径必须收口批次 failed（不允许悬空 planning），
//! 收口前先计数归零 + 清计划：`finish_batch` 对账要求 `sum(n_*) == total_items`，
//! failed 项 `n_failed` 不还原会拒绝收口。
//!
//! 计划重写与计数器镜像：重写 = 清旧计划再按轮重插。state 层口径：pending
//! 重插不动计数器；failed/skipped 直插走对应 insert（逐行 bump）；清旧计划必须
//! 走 `clear_batch_items_rollback_counters`（删行与 `n_*` 回退同事务），否则
//! 重插翻倍计数、`finish_batch` 对账必炸。
//!
//! 并发约定：每批次至多一个 planner（路由层单飞）。重写由多个独立事务组成，
//! 崩溃残留的 planning 批次由启动对账重入：重读项 → 重建轮次，无 pending 项按
//! "无事可做"收口；UNIQUE(batch_id, pkg_name) + 先清后插保证无重复 items。

use std::collections::HashMap;
use std::path::PathBuf;

use crbs_core::config::RepoConfig;
use crbs_core::engine::depsolve::{
    build_dep_graph, parse_br_and_arch_from_srpms, topo_sort, SrpmInfo,
};
use crbs_core::error::CrbsError;
use crbs_core::SkippedBatchItem;
use crbs_core::{BatchItemRecord, BatchRecord, FailedBatchItem, NewBatchItem, ProductRecord};
use tracing::{debug, info, warn};

use crate::server::error::ApiError;
use crate::server::state::AppState;

/// 批次规划结果。
#[derive(Debug, Clone)]
pub struct PlanOutcome {
    pub batch_id: i64,
    /// (round, 该轮 item 数)，round 升序；round 0 含环/未解析节点。
    pub rounds: Vec<(i64, usize)>,
    /// 全部 item 数（pending + failed + plan 期 arch 跳过）。
    pub total: usize,
    /// 准备期已 failed 的 item 数（暂存路径 NULL，不参与建图）。
    pub failed_pre_prepare: usize,
    /// plan 期因 spec 架构约束与批次 arch 目标不兼容而跳过的 item 数。
    pub arch_skipped: usize,
}

/// 规划一个整仓重建批次（流程见模块头注）：批次必须存在且处于 planning 态
///（否则 NotFound / Conflict）；出错时批次收口 failed（见失败路径不变量）。
pub(crate) async fn plan_batch(app: &AppState, batch_id: i64) -> Result<PlanOutcome, ApiError> {
    let store = &app.state_store;

    let batch = store
        .get_batch(batch_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::NotFound(format!("batch {batch_id} not found")))?;
    if batch.status != "planning" {
        return Err(ApiError::Conflict(format!(
            "batch {batch_id} is in status '{}' (expected 'planning'); refusing to plan",
            batch.status
        )));
    }
    // 整仓量级规划可达 10min+（rpm -qp / dnf repoquery 长等待）：伴生心跳
    // 协程防 sweep 按"心跳停更"误收口活批次（prepare 下载段同款防护）。
    super::touch_batch_heartbeat(&app.state_store, batch_id).await;
    // Drop-abort 句柄（BatchHeartbeatGuard）：正常结束与 panic unwind 均收掉心跳协程。
    let _heartbeat = super::spawn_batch_heartbeat(app.state_store.clone(), batch_id);
    // 仓库集来源：prepare 建批恒写 product_id，None 属异常数据。
    let product_id = batch.product_id.ok_or_else(|| {
        ApiError::Internal(format!(
            "batch {batch_id} has no product; cannot resolve the repo set for planning"
        ))
    })?;
    let product = store
        .get_product_by_id(product_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "product id={product_id} (batch {batch_id}) not found"
            ))
        })?;

    let planned = plan_planning_batch(app, &batch, &product).await;

    match planned {
        Ok(outcome) => Ok(outcome),
        Err(err) => {
            // 失败收口：批次仍 planning 才动，共享信封见 close_batch_failed。
            close_batch_failed(store, batch_id, "planning", &err).await;
            Err(err)
        }
    }
}

/// 批次确认 planning 后的全部规划工作。任何 Err 都由调用方收口批次。
async fn plan_planning_batch(
    app: &AppState,
    batch: &BatchRecord,
    product: &ProductRecord,
) -> Result<PlanOutcome, ApiError> {
    let store = &app.state_store;
    let batch_id = batch.id;

    // 1. 计划项：pending 进依赖图（有暂存路径）；failed（暂存 NULL）不进图，重写原样保留账本。
    let pending_items = store
        .items_in_state(batch_id, "pending")
        .await
        .map_err(ApiError::from)?;
    let failed_items = store
        .items_in_state(batch_id, "failed")
        .await
        .map_err(ApiError::from)?;
    let failed_pre_prepare = failed_items.len();

    // 2. 无事可做：无 pending 项则不查工具、不解析仓库，直接 completed 收口。
    //    子形态：全增量跳过（零 item）或全准备期失败（防御臂），保住 failed 账本与计数。
    if pending_items.is_empty() {
        return finish_nothing_to_build(store, batch_id, &failed_items).await;
    }

    // 3. 防御：pending 项必须有暂存路径（prepare 契约），NULL 属数据异常。
    let staging_paths: Vec<PathBuf> = pending_items
        .iter()
        .map(|item| {
            item.srpm_staging_path
                .clone()
                .map(PathBuf::from)
                .ok_or_else(|| {
                    ApiError::Internal(format!(
                        "pending item '{}' in batch {batch_id} has no srpm staging path",
                        item.pkg_name
                    ))
                })
        })
        .collect::<Result<Vec<PathBuf>, ApiError>>()?;

    // 4. hub 工具检查（阻塞 PATH 查询放 spawn_blocking）：dnf 供 capability
    //    索引，rpm 供 BR 批量提取；rpmspec 不需要（BR 走 `rpm -qp` 批量原语）。
    check_plan_tools().await?;

    // 5. 仓库集 = 产品配置仓库 + hub 自己的发布仓。
    let config = store
        .load_merged_config_for_product_by_id(product.id, &product.name)
        .await
        .map_err(ApiError::from)?;
    let archs =
        parse_arch_targets(batch_id, batch.arch_targets.as_deref()).map_err(ApiError::from)?;
    let result_root = app.result_dir_for_or_default(&product.name).await;
    let mut repos = config.repos.clone();
    repos.extend(publish_repos(&result_root, &product.name, &archs)?);

    // 6. BR + ARCH 批量提取（`rpm -qp` 512/批，批量失败退单包）；返回序与输入
    //    一致，zip 长度守护防解析器少吐致尾部项静默消失。
    let parsed = parse_br_and_arch_from_srpms(&staging_paths, None).await;
    if parsed.len() != staging_paths.len() {
        return Err(ApiError::Internal(format!(
            "rpm metadata parser returned {} results for {} SRPMs in batch {batch_id}",
            parsed.len(),
            staging_paths.len()
        )));
    }
    // 图节点名复用 batch_items.pkg_name 列值（NEVRA 推导，UNIQUE(batch_id,
    // pkg_name) 权威键），与重插行天然对齐，无需从暂存文件名二次推导。
    //
    // 架构约束裁决（仅全部目标 arch 不兼容才整项跳过）：不兼容项整项记
    // arch_skipped（带原因落账，n_skipped 计数），不进依赖图——item 状态机
    // 按整项收口，部分 arch 构建会打破 item→task 一对一聚合假设；部分不兼容
    // 的项保留，release 期 fan-out 按架构跳过、可构建子集照常重建。
    let mut infos: Vec<SrpmInfo> = Vec::with_capacity(pending_items.len());
    let mut arch_skipped: Vec<(&BatchItemRecord, String)> = Vec::new();
    for ((item, path), res) in pending_items.iter().zip(&staging_paths).zip(parsed) {
        let meta = res.map_err(ApiError::from)?;
        if let Some(reason) = arch_skip_reason(&meta.arch, &meta.arch_constraints, &archs) {
            arch_skipped.push((item, reason));
            continue;
        }
        infos.push(SrpmInfo {
            name: item.pkg_name.clone(),
            path: path.clone(),
            arch: meta.arch,
            build_requires: meta.build_requires,
        });
    }
    if !arch_skipped.is_empty() {
        info!(
            batch_id = batch_id,
            skipped = arch_skipped.len(),
            names = ?arch_skipped.iter().map(|(i, _)| i.pkg_name.as_str()).collect::<Vec<_>>(),
            "Batch plan: items skipped by spec arch constraints"
        );
    }
    debug!(
        batch_id = batch_id,
        items = infos.len(),
        repos = repos.len(),
        "Batch plan inputs ready"
    );

    // 7. 建图 + 拓扑分轮（仓库集 = 构建环境，无 chain 本地收集仓）；环/未解析
    //    节点由 topo_sort 并入 round 0 先试构建。
    let graph = build_dep_graph(&infos, &repos, None, None)
        .await
        .map_err(ApiError::from)?;
    let (rounds, cycle_attempted) = topo_sort(&graph);
    if !cycle_attempted.is_empty() {
        warn!(
            batch_id = batch_id,
            nodes = ?cycle_attempted,
            "topo sort left unresolvable nodes; they are attempted in round 0"
        );
    }

    let round_of: HashMap<&str, i64> = rounds
        .iter()
        .enumerate()
        .flat_map(|(round, nodes)| nodes.iter().map(move |n| (n.name.as_str(), round as i64)))
        .collect();
    // 被 plan 期跳过的项不进轮次表（也不在依赖图里），重插时改落 arch_skipped 账。
    let skipped_names: std::collections::HashSet<&str> = arch_skipped
        .iter()
        .map(|(item, _)| item.pkg_name.as_str())
        .collect();
    let new_items: Vec<NewBatchItem<'_>> = pending_items
        .iter()
        .filter(|item| !skipped_names.contains(item.pkg_name.as_str()))
        .map(|item| {
            let round = round_of
                .get(item.pkg_name.as_str())
                .copied()
                .ok_or_else(|| {
                    ApiError::Internal(format!(
                        "package '{}' is missing from the dependency graph of batch {batch_id}",
                        item.pkg_name
                    ))
                })?;
            Ok(NewBatchItem {
                pkg_name: &item.pkg_name,
                srpm_nevra: item.srpm_nevra.as_deref(),
                srpm_staging_path: item.srpm_staging_path.as_deref(),
                round,
            })
        })
        .collect::<Result<Vec<NewBatchItem<'_>>, ApiError>>()?;

    // 8. 计划重写（幂等重入）：failed 计数归零 + 清旧计划 → pending 按轮重插
    //    → failed 原样重插（`n_failed` 随 bump 还原）；计数器镜像见模块头注。
    let failed_snapshot = take_failed_and_clear_items(store, batch_id)
        .await
        .map_err(ApiError::from)?;
    if failed_snapshot.len() != failed_pre_prepare {
        return Err(ApiError::Internal(format!(
            "batch {batch_id} failed item count changed during planning \
             ({} -> {}); concurrent plan write?",
            failed_pre_prepare,
            failed_snapshot.len()
        )));
    }
    store
        .insert_batch_items(batch_id, &new_items)
        .await
        .map_err(ApiError::from)?;
    let failed_rows: Vec<FailedBatchItem<'_>> = failed_snapshot
        .iter()
        .map(|item| FailedBatchItem {
            pkg_name: &item.pkg_name,
            srpm_nevra: item.srpm_nevra.as_deref(),
            // 占位兜数据异常：账本残缺不得中断重写。
            error_code: item.error_code.as_deref().unwrap_or("prepare_failed"),
            error_message: item.error_message.as_deref().unwrap_or(""),
        })
        .collect();
    store
        .insert_failed_batch_items(batch_id, &failed_rows)
        .await
        .map_err(ApiError::from)?;
    // plan 期架构跳过项落账：直插终态 arch_skipped（n_skipped 随 bump），
    // 与 failed 账本同一重写事务序后、交棒前落齐。
    let skipped_rows: Vec<SkippedBatchItem<'_>> = arch_skipped
        .iter()
        .map(|(item, reason)| SkippedBatchItem {
            pkg_name: &item.pkg_name,
            srpm_nevra: item.srpm_nevra.as_deref(),
            srpm_staging_path: item.srpm_staging_path.as_deref(),
            error_code: "arch_unsupported",
            error_message: reason,
        })
        .collect();
    store
        .insert_arch_skipped_batch_items(batch_id, &skipped_rows)
        .await
        .map_err(ApiError::from)?;

    // 9. 交棒 running：total_items = 全 item 数（finish 总数对账的基准）。
    let total = pending_items.len() + failed_pre_prepare;
    store
        .set_batch_running(batch_id, total as i64)
        .await
        .map_err(ApiError::from)?;

    info!(
        batch_id = batch_id,
        rounds = rounds.len(),
        total = total,
        failed_pre_prepare = failed_pre_prepare,
        arch_skipped = arch_skipped.len(),
        "Batch planned and handed to running"
    );
    Ok(PlanOutcome {
        batch_id,
        rounds: rounds
            .iter()
            .enumerate()
            .map(|(round, nodes)| (round as i64, nodes.len()))
            .collect(),
        total,
        failed_pre_prepare,
        arch_skipped: arch_skipped.len(),
    })
}

/// 单 item 的批次架构兼容性裁决（纯函数，可单测）：返回 Some(原因) = 该项应
/// 整项记 arch_skipped。规则同 plan_srpm_arches（rpm 6.0.2 实测口径），但整项
/// 跳过仅当**全部**目标 arch 不兼容：部分不兼容的项保留进依赖图，release 期
/// fan-out 按架构跳过（skip_unsupported_arches 兜底），可构建子集照常重建——
/// 整项跳过会静默丢掉部分兼容包（如 ExclusiveArch 单架构遇上多架构批次）的
/// 成功构建。
///
/// 不裁决（→ None，预检是优化不是安全裁决）：探测失败（空 arch）、无约束、
/// 空目标集（产品默认批次 arch_targets 省略/[]，release 期 driver 回退产品
/// arches，plan 期无从预判）。
///
/// 已知漂移边缘：arch_targets 含 "noarch" 时 plan 期以 "noarch" 作宿主代理
/// 裁决，release 期 driver 把 noarch 映射为产品 concrete arch，两侧检查面
/// 不严格一致。
fn arch_skip_reason(
    arch: &str,
    constraints: &crbs_core::engine::depsolve::ArchConstraints,
    batch_arches: &[String],
) -> Option<String> {
    // 空目标集不裁决：全不兼容谓词在空集上 0==0 恒真；预检是优化不是安全裁决。
    if arch.is_empty()
        || batch_arches.is_empty()
        || (constraints.exclusive.is_empty() && constraints.exclude.is_empty())
    {
        return None;
    }
    let bad: Vec<String> = batch_arches
        .iter()
        .filter_map(|a| {
            constraints
                .incompatible_for(arch, a)
                .map(|r| format!("{a}: {r}"))
        })
        .collect();
    if bad.len() == batch_arches.len() {
        Some(bad.join("; "))
    } else {
        None
    }
}

/// "无事可做"收口：pending 为空时直接 completed。零 item（全增量跳过）计数器
/// 全 0 对账通过；全准备期失败先置 total 再 completed——对账要求
/// `total_items == n_failed`（planning→running 唯一写入口；窗口内无 pending 项故无副作用）。
async fn finish_nothing_to_build(
    store: &crbs_core::StateStore,
    batch_id: i64,
    failed_items: &[BatchItemRecord],
) -> Result<PlanOutcome, ApiError> {
    if failed_items.is_empty() {
        store
            .finish_batch(
                batch_id,
                "completed",
                Some("nothing to build: all source packages were skipped (already built)"),
            )
            .await
            .map_err(ApiError::from)?;
        info!(batch_id = batch_id, "Batch completed without items");
        return Ok(PlanOutcome {
            batch_id,
            rounds: Vec::new(),
            total: 0,
            failed_pre_prepare: 0,
            arch_skipped: 0,
        });
    }

    let total = failed_items.len();
    store
        .set_batch_running(batch_id, total as i64)
        .await
        .map_err(ApiError::from)?;
    store
        .finish_batch(
            batch_id,
            "completed",
            Some(&format!(
                "nothing to build: all {total} item(s) failed during prepare \
                 (srpm download / disk watermark)"
            )),
        )
        .await
        .map_err(ApiError::from)?;
    info!(
        batch_id = batch_id,
        failed = total,
        "Batch completed with prepare-time failures only"
    );
    Ok(PlanOutcome {
        batch_id,
        rounds: Vec::new(),
        total,
        failed_pre_prepare: total,
        arch_skipped: 0,
    })
}

/// 清空计划项并回退全部终态计数（failed/arch_skipped/dep_skipped/skipped_conflict），
/// 返回清理前的 failed 快照供重写路径重插。计数回退与删行在同一事务内完成——
/// 只减 `n_failed` 的旧做法会让 plan 期 `arch_skipped` 计数遗留，`finish_batch`
/// 对账永久拒绝、批次占配额；重写路径由调用方对快照长度做并发断言。
pub(super) async fn take_failed_and_clear_items(
    store: &crbs_core::StateStore,
    batch_id: i64,
) -> crbs_core::Result<Vec<BatchItemRecord>> {
    let items = store.clear_batch_items_rollback_counters(batch_id).await?;
    Ok(items.into_iter().filter(|i| i.state == "failed").collect())
}

/// 失败收口共享信封（prepare 与 plan 的 Err 路径）：批次仍在 `expected_status`
/// 才动——并发迁移先到者胜，不得践踏并发方状态。清理走
/// [`take_failed_and_clear_items`]（先减回 `n_failed` 再清行：准备期失败项已
/// bump 计数器，裸删行会让 `finish_batch` 总数对账拒绝、批次永久滞留原状态）。
/// 各步尽力而为仅 warn、不掩盖原始错误；收口失败的悬空批次由启动对账兜底扫出。
pub(super) async fn close_batch_failed(
    store: &crbs_core::StateStore,
    batch_id: i64,
    expected_status: &str,
    err: &ApiError,
) {
    match store.get_batch(batch_id).await {
        Ok(Some(b)) if b.status == expected_status => {
            if let Err(e) = take_failed_and_clear_items(store, batch_id).await {
                warn!(
                    batch_id = batch_id,
                    error = %e,
                    "cleanup: normalize batch items failed"
                );
            }
            if let Err(e) = store
                .finish_batch(batch_id, "failed", Some(err.message()))
                .await
            {
                warn!(
                    batch_id = batch_id,
                    error = %e,
                    "cleanup: finish batch as failed failed"
                );
            }
        }
        Ok(_) => warn!(
            batch_id = batch_id,
            "batch left {expected_status} before failure cleanup; skipping (concurrent transition won)"
        ),
        Err(e) => warn!(
            batch_id = batch_id,
            error = %e,
            "cleanup: read batch status failed"
        ),
    }
}

/// 解析批次 `arch_targets` JSON + 白名单校验（prepare 原样落库，按信任边界
/// 校验拒穿越/注入；plan/driver 共用同一契约）。空/缺失 = 未声明目标架构
/// （无发布仓可注入）。
pub(crate) fn parse_arch_targets(
    batch_id: i64,
    raw: Option<&str>,
) -> crbs_core::Result<Vec<String>> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let parsed: Vec<String> =
        serde_json::from_str(raw).map_err(|e| CrbsError::ValidationFailed {
            message: format!("batch {batch_id} arch_targets is not a JSON string array: {e}"),
        })?;
    for arch in &parsed {
        crbs_core::validation::validate_arch(arch).map_err(|e| CrbsError::ValidationFailed {
            message: format!("invalid arch in batch {batch_id} arch_targets: {e}"),
        })?;
    }
    Ok(parsed)
}

/// hub 自己的发布仓集：每个目标架构一个 `file://{result_root}/_repo/{product}/
/// {arch}/` 仓库。repo 名 `crbs-pub-{arch}` 避免与产品配置 repo 撞名
///（`--repofrompath` 的 repo id 再加 `crbs-` 前缀）；目录缺失则跳过（首建
/// 发布仓为空属正常，依赖只能来自产品配置仓库）；arch 先过 `validate_arch`
/// 白名单再拼路径（arch_targets 来自请求 JSON 原样落库，`/`、`..` 可路径穿越）。
fn publish_repos(
    result_root: &std::path::Path,
    product: &str,
    archs: &[String],
) -> Result<Vec<RepoConfig>, ApiError> {
    let mut repos = Vec::with_capacity(archs.len());
    for arch in archs {
        crbs_core::validation::validate_arch(arch).map_err(|e| {
            ApiError::Validation(format!("invalid arch in batch arch_targets: {e}"))
        })?;
        let dir = result_root.join("_repo").join(product).join(arch);
        if !dir.is_dir() {
            debug!(
                dir = %dir.display(),
                "Publish repo dir missing; skipping file:// repo (first build for product)"
            );
            continue;
        }
        repos.push(RepoConfig {
            name: format!("crbs-pub-{arch}"),
            baseurl: format!("file://{}", dir.display()),
            ..Default::default()
        });
    }
    Ok(repos)
}

/// hub 侧规划工具检查：缺失返回 ServiceUnavailable（环境问题，非请求可
/// 修正）；阻塞 PATH 查询放 spawn_blocking，最小集只有 dnf 与 rpm。
async fn check_plan_tools() -> Result<(), ApiError> {
    let missing = tokio::task::spawn_blocking(|| {
        for tool in &["dnf", "rpm"] {
            if which::which(tool).is_err() {
                return Some(*tool);
            }
        }
        None
    })
    .await
    .map_err(|e| ApiError::Internal(format!("check plan tools: {e}")))?;
    match missing {
        Some(tool) => Err(ApiError::ServiceUnavailable(format!(
            "required tool '{tool}' not found on hub host; batch planning needs dnf \
             (dependency capability index) and rpm (BuildRequires extraction)"
        ))),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::setup_app;
    use crbs_core::test_support::SrpmFixture;
    use crbs_core::{BatchInsert, StateStore};

    /// 建产品行（config 带 base_packages/repos：chain-resolve 校验要求非空）。
    async fn seed_product(store: &StateStore, id: i64, name: &str) {
        let config = serde_json::json!({
            "base_packages": ["filesystem"],
            "repos": [{"name": "test-os", "baseurl": "file:///dev/null/no-such-repo"}]
        });
        sqlx::query(
            "INSERT INTO products (id, name, visibility, config_json, revision, \
             base_os_revision) VALUES ($1, $2, 'public', $3, 1, 1)",
        )
        .bind(id)
        .bind(name)
        .bind(config.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    }

    /// 建一个 planning 批次（模拟 prepare 交棒后的状态），返回批次 id。
    async fn seed_planning_batch(
        store: &StateStore,
        product_id: i64,
        arch_targets: Option<&str>,
    ) -> i64 {
        let id = store
            .insert_batch(BatchInsert {
                product_id: Some(product_id),
                created_by: None,
                source_repo_url: "https://example.com/repo",
                dist: None,
                arch_targets_json: arch_targets,
                on_failure: "continue",
                force_all: false,
                request_json: None,
            })
            .await
            .unwrap();
        store.set_batch_planning(id).await.unwrap();
        id
    }

    async fn batch_counters(store: &StateStore, batch_id: i64) -> (i64, i64, i64, i64, i64) {
        sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(
            "SELECT total_items, n_succeeded, n_failed, n_skipped, n_cancelled \
             FROM build_batches WHERE id = $1",
        )
        .bind(batch_id)
        .fetch_one(store.pool())
        .await
        .unwrap()
    }

    /// arch_skip_reason 矩阵：仅全部目标 arch 不兼容才整项跳过——部分不兼容
    /// 放行（release 期 fan-out 按架构跳过，可构建子集照常重建）；noarch
    /// ExclusiveArch 豁免、ExcludeArch 命中全部派发 arch 才整项跳过；
    /// 无约束/探测失败/空目标集放行（空目标集不裁决，产品默认批次）。
    #[test]
    fn arch_skip_reason_matrix() {
        use crbs_core::engine::depsolve::ArchConstraints;
        let targets = || vec!["x86_64".to_string(), "aarch64".to_string()];

        // 无约束 / 探测失败：放行。
        assert!(arch_skip_reason("x86_64", &ArchConstraints::default(), &targets()).is_none());
        assert!(arch_skip_reason("", &ArchConstraints::default(), &targets()).is_none());

        // ExclusiveArch 只含 aarch64：x86_64 不兼容但 aarch64 可构建 → 放行，
        // 整项跳过会静默丢掉 aarch64 侧的成功构建。
        let exc = ArchConstraints {
            exclusive: vec!["aarch64".to_string()],
            exclude: vec![],
        };
        assert!(arch_skip_reason("x86_64", &exc, &targets()).is_none());

        // ExclusiveArch 不含任一目标：全部不兼容 → 整项跳过，原因逐 arch 点名。
        let exc_none = ArchConstraints {
            exclusive: vec!["ppc64le".to_string()],
            exclude: vec![],
        };
        let r = arch_skip_reason("x86_64", &exc_none, &targets()).unwrap();
        assert!(
            r.contains("x86_64: not in ExclusiveArch [ppc64le]"),
            "got: {r}"
        );
        assert!(
            r.contains("aarch64: not in ExclusiveArch [ppc64le]"),
            "got: {r}"
        );

        // ExcludeArch 含全部目标：整项跳过，原因逐 arch 点名。
        let excl_all = ArchConstraints {
            exclusive: vec![],
            exclude: vec!["x86_64".to_string(), "aarch64".to_string()],
        };
        let r = arch_skip_reason("x86_64", &excl_all, &targets()).unwrap();
        assert!(r.contains("x86_64: excluded by ExcludeArch"), "got: {r}");
        assert!(r.contains("aarch64: excluded by ExcludeArch"), "got: {r}");

        // ExcludeArch 只命中部分目标：放行（剩余 arch 照常重建）。
        let excl_part = ArchConstraints {
            exclusive: vec![],
            exclude: vec!["x86_64".to_string()],
        };
        assert!(arch_skip_reason("x86_64", &excl_part, &targets()).is_none());

        // noarch + ExclusiveArch（矛盾 spec）：豁免 → 放行。
        let contradict = ArchConstraints {
            exclusive: vec!["x86_64".to_string()],
            exclude: vec![],
        };
        assert!(arch_skip_reason("noarch", &contradict, &targets()).is_none());

        // noarch + ExcludeArch 命中全部派发 arch：整项跳过，原因带宿主代理语义。
        let noarch_excl_all = ArchConstraints {
            exclusive: vec![],
            exclude: vec!["x86_64".to_string(), "aarch64".to_string()],
        };
        let r = arch_skip_reason("noarch", &noarch_excl_all, &targets()).unwrap();
        assert!(
            r.contains("x86_64: excluded by ExcludeArch [x86_64 aarch64] (noarch build host)"),
            "got: {r}"
        );

        // noarch + ExcludeArch 只命中部分派发 arch：放行（剩余派发面可构建）。
        let noarch_excl_part = ArchConstraints {
            exclusive: vec![],
            exclude: vec!["x86_64".to_string()],
        };
        assert!(arch_skip_reason("noarch", &noarch_excl_part, &targets()).is_none());

        // 空目标集（产品默认批次，driver 回退产品 arches）：不裁决。全不兼容
        // 谓词在空集上 0==0 恒真，ExclusiveArch 非空与 ExcludeArch 命中两种
        // 形态都要放行而非整项跳过。
        assert!(arch_skip_reason("x86_64", &exc_none, &[]).is_none());
        assert!(arch_skip_reason("x86_64", &excl_all, &[]).is_none());
    }

    #[tokio::test]
    async fn plan_rejects_missing_or_non_planning_batch() {
        let (app, _tmp) = setup_app().await;
        seed_product(&app.state_store, 1, "p1").await;

        let err = plan_batch(&app, 1234).await.unwrap_err();
        assert!(matches!(err, ApiError::NotFound(_)), "{err:?}");

        let id = app
            .state_store
            .insert_batch(BatchInsert {
                product_id: Some(1),
                created_by: None,
                source_repo_url: "https://r",
                dist: None,
                arch_targets_json: None,
                on_failure: "continue",
                force_all: false,
                request_json: None,
            })
            .await
            .unwrap();
        let err = plan_batch(&app, id).await.unwrap_err();
        assert!(
            matches!(err, ApiError::Conflict(ref m) if m.contains("preparing")),
            "{err:?}"
        );
        assert_eq!(
            app.state_store.get_batch(id).await.unwrap().unwrap().status,
            "preparing",
            "rejected plan must not touch the batch"
        );

        app.state_store.set_batch_planning(id).await.unwrap();
        app.state_store
            .finish_batch(id, "cancelled", None)
            .await
            .unwrap();
        let err = plan_batch(&app, id).await.unwrap_err();
        assert!(matches!(err, ApiError::Conflict(_)), "{err:?}");
    }

    #[test]
    fn publish_repos_included_only_when_dir_exists_and_arch_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let x86 = root.join("_repo").join("p1").join("x86_64");
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            tokio::fs::create_dir_all(&x86).await.unwrap();
        });

        let archs = vec![
            "x86_64".to_string(),
            "aarch64".to_string(), // 目录缺失 → 跳过
        ];
        let repos = publish_repos(root, "p1", &archs).unwrap();
        assert_eq!(repos.len(), 1, "missing dir is skipped");
        assert_eq!(repos[0].name, "crbs-pub-x86_64");
        assert_eq!(repos[0].baseurl, format!("file://{}", x86.display()));
        assert!(repos[0].enabled);

        assert!(publish_repos(root, "p1", &[]).unwrap().is_empty());

        for evil in ["../evil", "x86 64", "", "x86_64\ngpgcheck=0"] {
            let err = publish_repos(root, "p1", &[evil.to_string()]).unwrap_err();
            assert!(matches!(err, ApiError::Validation(_)), "{evil}: {err:?}");
        }
    }

    #[test]
    fn parse_arch_targets_accepts_json_array_and_rejects_malformed() {
        assert_eq!(parse_arch_targets(1, None).unwrap(), Vec::<String>::new());
        assert_eq!(
            parse_arch_targets(1, Some(r#"["x86_64","aarch64"]"#)).unwrap(),
            vec!["x86_64".to_string(), "aarch64".to_string()]
        );
        let err = parse_arch_targets(1, Some("not-json")).unwrap_err();
        assert!(matches!(err, CrbsError::ValidationFailed { .. }), "{err:?}");
        // 白名单即校验：穿越形态在解析点即拒（driver 侧同契约）。
        let err = parse_arch_targets(1, Some(r#"["../../etc"]"#)).unwrap_err();
        assert!(matches!(err, CrbsError::ValidationFailed { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn plan_completes_immediately_when_all_packages_were_skipped() {
        let (app, _tmp) = setup_app().await;
        seed_product(&app.state_store, 1, "p1").await;

        // 全部包增量跳过：prepare 不建 item，批次 planning 且零 item。
        let id = seed_planning_batch(&app.state_store, 1, None).await;

        let outcome = plan_batch(&app, id).await.unwrap();
        assert!(outcome.rounds.is_empty());
        assert_eq!(outcome.total, 0);
        assert_eq!(outcome.failed_pre_prepare, 0);

        let rec = app.state_store.get_batch(id).await.unwrap().unwrap();
        assert_eq!(
            rec.status, "completed",
            "zero-item batch completes directly"
        );
        assert!(rec.notes.unwrap().contains("skipped"));
    }

    #[tokio::test]
    async fn plan_completes_when_only_prepare_time_failures_remain() {
        let (app, _tmp) = setup_app().await;
        seed_product(&app.state_store, 1, "p1").await;

        // 全部准备期失败（防御臂）：planning 批次只有 failed item。
        let id = seed_planning_batch(&app.state_store, 1, Some(r#"["x86_64"]"#)).await;
        app.state_store
            .insert_failed_batch_items(
                id,
                &[FailedBatchItem {
                    pkg_name: "bad",
                    srpm_nevra: Some("bad-1.0-1.el9.src"),
                    error_code: "srpm_download_failed",
                    error_message: "HTTP 503",
                }],
            )
            .await
            .unwrap();

        let outcome = plan_batch(&app, id).await.unwrap();
        assert_eq!(outcome.total, 1);
        assert_eq!(outcome.failed_pre_prepare, 1);

        let rec = app.state_store.get_batch(id).await.unwrap().unwrap();
        assert_eq!(rec.status, "completed");
        assert_eq!(
            rec.total_items, 1,
            "total mirrors failed count for reconciliation"
        );
        assert_eq!(rec.n_failed, 1, "failed ledger preserved");
        // 对账口径成立：sum(n_*) == total_items（1 == 1）。
        assert_eq!(batch_counters(&app.state_store, id).await, (1, 0, 1, 0, 0));
        let failed = app.state_store.items_in_state(id, "failed").await.unwrap();
        assert_eq!(failed.len(), 1, "failed item ledger intact");
    }

    #[tokio::test]
    async fn plan_failure_finishes_batch_failed_with_counter_reset() {
        let (app, _tmp) = setup_app().await;
        seed_product(&app.state_store, 1, "p1").await;

        // pending 项缺暂存路径 = 确定性规划失败（防御臂）；另置 prepare 期
        // failed 项制造非零 n_failed，钉住收口前计数归零（否则对账拒绝）。
        let id = seed_planning_batch(&app.state_store, 1, Some(r#"["x86_64"]"#)).await;
        app.state_store
            .insert_batch_items(
                id,
                &[NewBatchItem {
                    pkg_name: "ghost",
                    srpm_nevra: Some("ghost-1.0-1.src"),
                    srpm_staging_path: None,
                    round: 0,
                }],
            )
            .await
            .unwrap();
        app.state_store
            .insert_failed_batch_items(
                id,
                &[FailedBatchItem {
                    pkg_name: "bad",
                    srpm_nevra: None,
                    error_code: "srpm_download_failed",
                    error_message: "HTTP 503",
                }],
            )
            .await
            .unwrap();
        assert_eq!(batch_counters(&app.state_store, id).await, (0, 0, 1, 0, 0));

        let err = plan_batch(&app, id).await.unwrap_err();
        assert!(
            matches!(err, ApiError::Internal(ref m) if m.contains("staging path")),
            "{err:?}"
        );

        let rec = app.state_store.get_batch(id).await.unwrap().unwrap();
        assert_eq!(rec.status, "failed", "plan failure must close the batch");
        assert!(
            rec.notes.unwrap().contains("staging path"),
            "notes carry the reason"
        );
        assert_eq!(
            batch_counters(&app.state_store, id).await,
            (0, 0, 0, 0, 0),
            "items cleared and counters normalized"
        );
        assert_eq!(
            app.state_store
                .batch_item_summary(id)
                .await
                .unwrap()
                .total(),
            0,
            "no dangling items after failure cleanup"
        );
    }

    /// 探测外部工具可用性（一次 spawn，结果跨调用稳定）。
    fn tool_available(tool: &str) -> bool {
        std::process::Command::new(tool)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// 本集成组的全部前置（fixture 构造 + BR 提取 + capability 索引）。
    fn integration_tools_ready() -> bool {
        ["rpmbuild", "rpm", "dnf", "createrepo_c"]
            .iter()
            .all(|t| tool_available(t))
    }

    /// 用 `rpmbuild -bs` 构造最小 fixture SRPM 落盘 dest_dir（批次暂存语义：
    /// topdir 用 dest_dir 内临时子目录，产物拷回 dest_dir 返回）；`build_requires`
    /// 逐条写入 spec 的 BuildRequires。构造本体在共享
    /// `crbs_core::test_support::build_srpm`。
    #[cfg(target_os = "linux")]
    fn build_fixture_srpm(
        dest_dir: &std::path::Path,
        name: &str,
        version: &str,
        release: &str,
        build_requires: &[&str],
        exclusive: &[&str],
        exclude: &[&str],
    ) -> PathBuf {
        let top = tempfile::tempdir_in(dest_dir).unwrap();
        let produced = crbs_core::test_support::build_srpm(SrpmFixture {
            topdir: top.path(),
            name,
            version,
            release,
            buildarch: None,
            build_requires,
            exclusive,
            exclude,
        });
        let dest = dest_dir.join(produced.file_name().unwrap());
        std::fs::copy(&produced, &dest).unwrap();
        dest
    }

    /// createrepo_c 建空 file:// 仓（合法 repodata，capability 索引可查询，离线可达）。
    #[cfg(target_os = "linux")]
    fn createrepo(dir: &std::path::Path) {
        let status = std::process::Command::new("createrepo_c")
            .arg(dir)
            .status()
            .expect("spawn createrepo_c");
        assert!(
            status.success(),
            "createrepo_c failed for {}",
            dir.display()
        );
    }

    /// 集成路径：beta BuildRequires alpha 两 fixture 规划出两轮并落库、running
    /// 交棒、total/failed 计数镜像一致；二次 plan（重入）无重复 items。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn plan_builds_two_dependency_rounds_and_is_idempotent_on_reentry() {
        if !integration_tools_ready() {
            eprintln!("skipping: rpmbuild/rpm/dnf/createrepo_c not all available");
            return;
        }

        let (app, tmp) = setup_app().await;
        let store = &app.state_store;
        seed_product(store, 1, "p1").await;

        let staging = tmp.path().join("results").join("batches").join("srpms");
        tokio::fs::create_dir_all(&staging).await.unwrap();
        let alpha = build_fixture_srpm(&staging, "alpha", "1.0", "1", &[], &[], &[]);
        let beta = build_fixture_srpm(&staging, "beta", "1.0", "1", &["alpha"], &[], &[]);

        let product_repo = tmp.path().join("product-repo");
        tokio::fs::create_dir_all(&product_repo).await.unwrap();
        createrepo(&product_repo);
        let pub_repo = tmp
            .path()
            .join("results")
            .join("_repo")
            .join("p1")
            .join("x86_64");
        tokio::fs::create_dir_all(&pub_repo).await.unwrap();
        createrepo(&pub_repo);
        // 产品配置 repo 指向可达本地仓（chain-resolve 校验 + capability 索引查询都需要）。
        let product_repo_config = serde_json::json!({
            "base_packages": ["filesystem"],
            "repos": [{"name": "test-os", "baseurl": format!("file://{}", product_repo.display())}]
        })
        .to_string();
        sqlx::query("UPDATE products SET config_json = $1 WHERE id = 1")
            .bind(product_repo_config)
            .execute(store.pool())
            .await
            .unwrap();

        // 模拟 prepare 交棒：round 0 占位 pending 项 + 准备期 failed 项（n_failed=1 钉计数镜像）。
        let batch_id = seed_planning_batch(store, 1, Some(r#"["x86_64"]"#)).await;
        store
            .insert_batch_items(
                batch_id,
                &[
                    NewBatchItem {
                        pkg_name: "alpha",
                        srpm_nevra: Some("alpha-1.0-1.src"),
                        srpm_staging_path: Some(alpha.to_str().unwrap()),
                        round: 0,
                    },
                    NewBatchItem {
                        pkg_name: "beta",
                        srpm_nevra: Some("beta-1.0-1.src"),
                        srpm_staging_path: Some(beta.to_str().unwrap()),
                        round: 0,
                    },
                ],
            )
            .await
            .unwrap();
        store
            .insert_failed_batch_items(
                batch_id,
                &[FailedBatchItem {
                    pkg_name: "wet",
                    srpm_nevra: Some("wet-1.0-1.el9.src"),
                    error_code: "disk_below_watermark",
                    error_message: "free space below watermark",
                }],
            )
            .await
            .unwrap();

        let outcome = plan_batch(&app, batch_id).await.unwrap();

        // 依赖边 beta → alpha：round 0 = alpha、round 1 = beta；failed 项留 round 0 不进轮次。
        assert_eq!(outcome.rounds, vec![(0, 1), (1, 1)], "{outcome:?}");
        assert_eq!(outcome.total, 3);
        assert_eq!(outcome.failed_pre_prepare, 1);

        let rec = store.get_batch(batch_id).await.unwrap().unwrap();
        assert_eq!(rec.status, "running", "handed to running");
        assert_eq!(rec.total_items, 3, "total = pending + failed");
        assert_eq!(
            rec.n_failed, 1,
            "failed counter survives the rewrite unmoved"
        );

        let round0: Vec<String> = store
            .items_in_round(batch_id, 0)
            .await
            .unwrap()
            .into_iter()
            .map(|i| i.pkg_name)
            .collect();
        let round1: Vec<String> = store
            .items_in_round(batch_id, 1)
            .await
            .unwrap()
            .into_iter()
            .map(|i| i.pkg_name)
            .collect();
        assert!(round0.contains(&"alpha".to_string()), "round 0: {round0:?}");
        assert!(
            round0.contains(&"wet".to_string()),
            "failed item stays round 0: {round0:?}"
        );
        assert_eq!(
            round1,
            vec!["beta".to_string()],
            "dependent package in round 1"
        );
        assert_eq!(store.batch_item_summary(batch_id).await.unwrap().total(), 3);

        // ── 幂等重入：批次回 planning（模拟崩溃残留对账重入）再 plan，无重复 items、计数轮次不变。
        sqlx::query("UPDATE build_batches SET status = 'planning' WHERE id = $1")
            .bind(batch_id)
            .execute(store.pool())
            .await
            .unwrap();
        let outcome2 = plan_batch(&app, batch_id).await.unwrap();
        assert_eq!(outcome2.rounds, outcome.rounds, "rounds are deterministic");
        assert_eq!(outcome2.total, 3);
        let rec = store.get_batch(batch_id).await.unwrap().unwrap();
        assert_eq!(rec.status, "running");
        assert_eq!(rec.total_items, 3);
        assert_eq!(rec.n_failed, 1, "no double bump on re-entry");
        assert_eq!(
            store.batch_item_summary(batch_id).await.unwrap().total(),
            3,
            "no duplicate items after re-plan"
        );
        assert_eq!(
            store
                .items_in_state(batch_id, "failed")
                .await
                .unwrap()
                .len(),
            1
        );
    }

    /// 端到端：批次内约束 SRPM（ExclusiveArch 与全部批次目标 arch 不兼容）经
    /// plan 落账 arch_skipped（带原因、n_skipped 计数），不进轮次表；无约束
    /// 包照常建图分轮、running 交棒。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn plan_lands_arch_skipped_item_and_excludes_it_from_rounds() {
        if !integration_tools_ready() {
            eprintln!("skipping: rpmbuild/rpm/dnf/createrepo_c not all available");
            return;
        }

        let (app, tmp) = setup_app().await;
        let store = &app.state_store;
        seed_product(store, 1, "p1").await;

        let staging = tmp.path().join("results").join("batches").join("srpms");
        tokio::fs::create_dir_all(&staging).await.unwrap();
        let plain = build_fixture_srpm(&staging, "plainpkg", "1.0", "1", &[], &[], &[]);
        // ExclusiveArch 不含批次唯一目标 x86_64 → 整项跳过。
        let constrained =
            build_fixture_srpm(&staging, "excconly", "1.0", "1", &[], &["aarch64"], &[]);

        // 产品配置 repo 指向可达本地仓（chain-resolve 校验 + capability 索引都需要）。
        let product_repo = tmp.path().join("product-repo");
        tokio::fs::create_dir_all(&product_repo).await.unwrap();
        createrepo(&product_repo);
        let pub_repo = tmp
            .path()
            .join("results")
            .join("_repo")
            .join("p1")
            .join("x86_64");
        tokio::fs::create_dir_all(&pub_repo).await.unwrap();
        createrepo(&pub_repo);
        let product_repo_config = serde_json::json!({
            "base_packages": ["filesystem"],
            "repos": [{"name": "test-os", "baseurl": format!("file://{}", product_repo.display())}]
        })
        .to_string();
        sqlx::query("UPDATE products SET config_json = $1 WHERE id = 1")
            .bind(product_repo_config)
            .execute(store.pool())
            .await
            .unwrap();

        // 模拟 prepare 交棒：两个 pending 项各带暂存路径。
        let batch_id = seed_planning_batch(store, 1, Some(r#"["x86_64"]"#)).await;
        store
            .insert_batch_items(
                batch_id,
                &[
                    NewBatchItem {
                        pkg_name: "plainpkg",
                        srpm_nevra: Some("plainpkg-1.0-1.src"),
                        srpm_staging_path: Some(plain.to_str().unwrap()),
                        round: 0,
                    },
                    NewBatchItem {
                        pkg_name: "excconly",
                        srpm_nevra: Some("excconly-1.0-1.src"),
                        srpm_staging_path: Some(constrained.to_str().unwrap()),
                        round: 0,
                    },
                ],
            )
            .await
            .unwrap();

        let outcome = plan_batch(&app, batch_id).await.unwrap();
        assert_eq!(outcome.arch_skipped, 1, "{outcome:?}");
        assert_eq!(outcome.total, 2, "total = pending + failed_pre_prepare");
        assert_eq!(outcome.rounds, vec![(0, 1)], "仅无约束包进轮次");

        let rec = store.get_batch(batch_id).await.unwrap().unwrap();
        assert_eq!(rec.status, "running");
        assert_eq!(rec.total_items, 2);
        assert_eq!(rec.n_skipped, 1, "arch_skipped 项随落账 bump n_skipped");

        // 落账行：终态 arch_skipped + 原因点名约束来源。
        let skipped = store
            .items_in_state(batch_id, "arch_skipped")
            .await
            .unwrap();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].pkg_name, "excconly");
        assert_eq!(skipped[0].error_code.as_deref(), Some("arch_unsupported"));
        assert!(
            skipped[0]
                .error_message
                .as_deref()
                .unwrap()
                .contains("not in ExclusiveArch [aarch64]"),
            "got: {:?}",
            skipped[0].error_message
        );

        // 跳过项不回 pending（不再派发）；无约束包保持待构建。
        // （arch_skipped 行直插 round 0 行位但终态，items_in_round 不过滤状态，
        // 派发面由 pending/unfinished 刻画。）
        let pending: Vec<String> = store
            .items_in_state(batch_id, "pending")
            .await
            .unwrap()
            .into_iter()
            .map(|i| i.pkg_name)
            .collect();
        assert_eq!(pending, vec!["plainpkg".to_string()], "{pending:?}");
        let unfinished: Vec<String> = store
            .unfinished_items(batch_id)
            .await
            .unwrap()
            .into_iter()
            .map(|i| i.pkg_name)
            .collect();
        assert_eq!(unfinished, vec!["plainpkg".to_string()], "{unfinished:?}");
        assert_eq!(
            store
                .batch_item_summary(batch_id)
                .await
                .unwrap()
                .arch_skipped,
            1
        );
    }
}
