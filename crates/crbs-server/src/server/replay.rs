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
//! 1. 重放比对：终态构建自身是 replay（request_json 带
//!    `reproduce_from_build_id`）→ 按 unsigned_sha256 集合比对 source vs
//!    replay，verdict 落 `build_reproducibility`（失败按
//!    [`crbs_core::classify_replay_failure`] 分类）。
//! 2. 自动跟跑：succeeded + deterministic + 任务全部子构建 succeeded +
//!    `auto_replay` + `replay_sampling` 抽中 → 经 `reproduce_fan_out` 建后台
//!    档重放任务（隔离四规则见 [`maybe_auto_replay`] 注）。
//! 3. cross-arch noarch 互比：任务 ≥2 架构且全部子构建终态 → 同 NVR noarch
//!    子包 unsigned_sha256 跨架构互比，不一致记 cross_arch_noarch/diff。
//!
//! 重放构建不触发 2/3（单代血缘，规则②）。

use std::sync::Arc;

use crbs_core::types::build_phase_is_terminal;
use crbs_core::types::PRIORITY_BACKGROUND;
use crbs_core::{
    classify_replay_failure, compare_unsigned_sets, sampling_hit, CompareDetail,
    NewReproducibility, ReplayVerdict, KIND_CROSS_ARCH_NOARCH, KIND_REPLAY,
};
use tracing::{debug, info, warn};

use crate::server::state::AppState;

/// 构建终态钩子入口（spawn 版）：内部失败只记日志，不影响已达成的构建状态。
/// 外层任务监管内层 JoinHandle：钩子 panic 不再随裸 `tokio::spawn` 静默丢失，
/// 同样落 `auto_replay_failure` 审计（构建状态已终态，不受影响）。
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
        // 失败审计留痕（`auto_replay_failure`，重启后仍有观测面）；
        // 审计本身失败仅 warn（事后记账不放大故障）。
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

/// 终态钩子主体（可直接 `await` 的版本，测试用）。
pub(crate) async fn on_build_terminal(
    app: &Arc<AppState>,
    build_id: i64,
) -> Result<(), crate::server::error::ApiError> {
    let store = &app.state_store;
    let Some(record) = store.get_build(build_id).await? else {
        // 记录消失（GC 竞态）：无事可做。
        return Ok(());
    };
    if !build_phase_is_terminal(&record.phase) {
        return Ok(());
    }

    // ① 终态构建自身是 replay → 比对后早退（规则②不再触发②③）。
    if let Some(source_id) = store.get_build_reproduce_source(build_id).await? {
        compare_replay_build(app, &record, source_id).await?;
        return Ok(());
    }

    // 血缘复核跌落判别：上方 `None` 混杂"普通构建"与"血缘键在但值不可
    // 解析"——后者按普通构建落②③会多跟跑一代（违反规则②）。判定取
    // **顶层键存在性**而非子串粗筛：`define` 等用户可控值原样序列化进
    // JSON 文本，子串粗筛会让普通构建误中早退、静默丢失 auto-replay /
    // cross-arch。解析失败退 contains 兜底（保守视为血缘：漏跟跑只损失
    // 观测面）。读 Err 按钩子 `?` 上抛。
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

    // ② 自动跟跑（succeeded + deterministic 的 source 构建，任务收口时）。
    if record.phase == "succeeded" && record.deterministic {
        if let Err(e) = maybe_auto_replay(app, &record).await {
            // 跟跑失败不影响其余钩子（cross-arch 仍执行）。
            warn!(
                build_id = build_id,
                error = ?e,
                "Auto replay trigger failed; skipping replay creation"
            );
        }
    }

    // ③ cross-arch noarch 互比（任务级收口）。
    maybe_cross_arch_compare(app, &record).await?;
    Ok(())
}

/// auto replay 在途占位 guard：Drop 移除 task id，Err/panic 路径也释放。
/// 锁中毒走 `into_inner`——残留条目只会让该 task 跟跑在重启前静默，
/// 移除是收敛方向。
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

/// 自动跟跑触发 + 创建重放任务。触发（全部满足）：本构建 succeeded 且
/// deterministic=1；任务全部子构建 succeeded（任务级收口，部分成功交操作员
/// 手动 reproduce）；产品 `auto_replay`（默认 true）；`replay_sampling`
///（默认 100）按 task 哈希抽中。
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

    // 任务级在途去重：check-and-insert 必须在函数**第一个 await 之前**——
    // 多架构任务末两子构建并发终态时，占位晚了会落进先到钩子收尾释放后的
    // 空窗 → 双 replay task。单次 std::sync::Mutex 锁内 check-and-claim
    //（短锁不跨 await）；insert_build 任务关联守卫是第二道防线；占位先于
    // 快照的残留交错由 `list_tasks_missing_auto_replay` 启动补发兜底。
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
    // 抽样判据 sha256(task_id) 首 u64 % 100 < pct：确定性哈希，重复触发判定一致。
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
    opts.priority = Some(PRIORITY_BACKGROUND); // 规则③后台档
    opts.reproduce_from_build_id = None; // 逐子构建由 reproduce_fan_out 设置

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

    // 审计 role 查用户真实值（固定档位会出"builder 执行 operator 档动作"
    // 假象）；查询失败与用户不存在降级回退 "operator"，不阻塞跟跑（审计是
    // 事后记账，重放任务已落库）。
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
    // 唤醒调度器（空闲闸会按需压制派发）。
    app.worker_notify.notify_one();
    Ok(())
}

/// 重放构建终态 → 比对 source vs replay 并落 `build_reproducibility` 行。
/// 输入 = 双方 `build_artifacts.unsigned_sha256` 集合（按 RPM 文件名对齐，
/// [`compare_unsigned_sets`]）；重放失败按 [`classify_replay_failure`] 映射
/// verdict；detail_json 附 source ccache 命中统计（归因辅助）。
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
                // cancelled：操作员干预，比对无意义，不落行。
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

    // 判据写进 detail_json：分类依据 + ccache 统计 + 失败摘要（截断防膨胀）。
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

    // 双保险：同 (kind='replay', replay_build_id) 已有行即跳过——钩子
    // double-fire 不产生重复比对行。
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

/// source ccache 命中统计：best-effort（缺失/失败返回 None），纯归因辅助，
/// 不参与 verdict 判定。
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

/// 按字符截断（UTF-8 边界安全；错误摘录进 detail_json 前的防膨胀）。
fn truncate_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// cross-arch noarch 互比（任务级收口）：同 task 不同架构的同 NVR noarch
/// 子包 unsigned_sha256 互比，不一致记 kind=cross_arch_noarch / verdict=diff
///（发布端 newest-wins 静默选一个、发布哈希随时序漂移——本互比即观测面）。
/// 幂等：partial UNIQUE `idx_build_repro_cross_arch`（source = 涉及构建的
/// 最小 build_id）同 task 只记一行。只对非 replay 任务执行（replay 已逐
/// build 与 source 比对）。detail 附注仅随真实 diff 行落盘（全一致不落行）：
/// NULL 锚文件名进 `missing_unsigned_anchor`、单侧产出进 `only_in`
///（file → {build_id, arch}），都是 newest-wins 静默选择观测面。
async fn maybe_cross_arch_compare(
    app: &Arc<AppState>,
    record: &crbs_core::BuildRecord,
) -> Result<(), crate::server::error::ApiError> {
    let store = &app.state_store;
    let Some(task_id) = record.task_id else {
        return Ok(());
    };
    let children = store.get_builds_by_task_id(task_id).await?;
    // 多架构任务全架构终态后才收口（避免每架构重复比）。
    if children.len() < 2 || !children.iter().all(|c| build_phase_is_terminal(&c.phase)) {
        return Ok(());
    }
    // 非 replay 任务强制：任一子构建带 reproduce 血缘（全体同源）即跳过；
    // 检查在收口点执行（每任务至多一次）。读错上抛不猜测血缘。
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
    // deterministic 门：非 det 产品的 noarch 字节漂移属预期，不产观测行。
    // 判据取构建自带的 builds.deterministic 标：标取提交时产品配置落列（免
    // 额外产品查询），配置事后翻转不追溯已建构建；执行帧的 unsigned 锚计算
    // 由引擎侧另有权威门。打标失败（仅 warn 留痕）按非 det 保守跳过。
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
        return Ok(()); // 单架构（或多包单架构）任务无跨架构互比面
    }

    let build_ids: Vec<i64> = succeeded.iter().map(|c| c.id).collect();
    let artifacts = store.list_artifacts_for_builds(&build_ids).await?;
    // 按文件名聚合 noarch unsigned 哈希（跨构建）。NULL 锚行也进聚合（披露
    // 观测缺口），distinct 仍只对有锚行——缺锚行不可能制造 false mismatch。
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
    // 单侧产出附注（file → {build_id, arch}）：newest-wins 的静默选择面之一。
    let mut only_in = serde_json::Map::new();
    let mut involved_min_build_id: Option<i64> = None;
    for (file, entries) in &by_file {
        let distinct: std::collections::BTreeSet<&str> = entries
            .iter()
            .filter_map(|(_, sha)| sha.as_deref())
            .collect();
        if distinct.len() < 2 {
            // 单侧产出判定：全部 entries 同一 build（非空）；仅记附注，无真实 diff 仍不落行。
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
        return Ok(()); // 全一致：不落行（仅记录不一致）
    };

    // NULL 锚 noarch 文件名（任一行缺锚即列；与比对侧 missing_unsigned 同义）。
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
    // 附注仅挂在已落行的 diff detail 上；纯缺锚/纯单侧无真实 diff 不落行。
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

    /// 构造 deterministic 产品的测试 AppState（auto_replay / replay_sampling
    /// 可覆盖）；create_test_store 双方言建库，CI 的 PG 腿真跑钩子链。
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

    /// 种子 deterministic succeeded 任务（task 行 + 单 arch 子构建 +
    /// reproduce fixture）；返回 (task_id, build_id)。
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

        // 复现机制 fixture：result_root/{task}/{arch}/{build}/build_packages.json
        // + {task}/source/{pkg}.src.rpm + task 行的 request_json/result_dir。
        let result_root = app.result_dir_for_or_default("det").await;
        let build_dir = result_root
            .join(task_id.to_string())
            .join(arch)
            .join(build_id.to_string());
        tokio::fs::create_dir_all(&build_dir).await.unwrap();
        // manifest 恒为数组形态（worker 按 Vec<BuildPackage> 解析）。
        tokio::fs::write(build_dir.join("build_packages.json"), b"[]")
            .await
            .unwrap();
        // 锚夹具：resolve_replay_anchors 探该产物头取 BUILDTIME/BUILDHOST。
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
        // request_json 带 target：种子 SRPM 是假字节，target 为空时
        // reproduce_fan_out 会因 arch 探针失败拒绝重放（生产行为）；显式
        // target 跳过探针，测试不被探针结果劫持。
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

    /// 第二架构（aarch64）终态子构建：直插终态行（任务聚合已 succeeded 时
    /// pending 会被 task 守卫拒）+ det 标 + request_info + manifest。
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
        // manifest 恒为数组形态（worker 按 Vec<BuildPackage> 解析）。
        tokio::fs::write(dir.join("build_packages.json"), b"[]")
            .await
            .unwrap();
        // 锚夹具：同 seed_succeeded_det_task。
        tokio::fs::create_dir_all(dir.join("RPMS")).await.unwrap();
        tokio::fs::write(
            dir.join("RPMS").join("anchor.rpm"),
            include_bytes!("replay/fixtures/replay_anchor.rpm"),
        )
        .await
        .unwrap();
        build_id
    }

    /// 自动跟跑：全子构建 succeeded → 创建后台档重放任务（规则①③：
    /// repo_publish=0 + PRIORITY_BACKGROUND）。
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

        // signed=0（初始态；重放路径三处签名都会跳过）。
        let signed: i64 = sqlx::query_scalar("SELECT signed FROM builds WHERE id = $1")
            .bind(replay_build_id)
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();
        assert_eq!(signed, 0);
    }

    /// 手动 reproduce 对称用例（规则①收口）：opts 不带 no_publish 直走
    /// `reproduce_fan_out`，子构建 repo_publish 仍须 0——收口点在入口，
    /// 不依赖调用方自觉。
    #[tokio::test]
    async fn manual_reproduce_children_do_not_publish() {
        let (app, _tmp) = setup_app(None, Some(0)).await; // sampling=0：隔离自动跟跑
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

    /// 规则②：重放终态不再触发下一代（任务数不增），比对行落库（全等 → same）。
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

    /// 人为注入差异（改宏重放的等价模拟）→ verdict=diff，detail 指出差异文件。
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

    /// 重放失败按错误文本分类：restore fail-fast → dep_unavailable；
    /// rpmbuild 退出 → build_failed；cancelled → 不落行。
    #[tokio::test]
    async fn replay_failure_classification_rows() {
        let (app, _tmp) = setup_app(None, None).await;
        let (_task_id, source_build) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        on_build_terminal(&app, source_build).await.unwrap();

        // 每用例一对独立 (source, replay)：终态不可重写，复用会读到旧 error_summary。
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

    /// zombie 修复路径的比对闭环：重放构建卡 building 后进程死，
    /// `repair_all_zombie_active_builds` 翻 failed 回报修复 id 集，逐 id 触发
    /// 终态钩子后比对行落库（verdict=build_failed，翻的是 failed 非 timeout）。
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

        // 置 building + 死 pid（口径同 test_state 的 999_999）。
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

    /// 终态钩子崩溃窗口的启动对账：重放翻终态但钩子未执行（COMMIT 与 spawn
    /// 间崩溃的等价模拟）→ 对账查出、补发后行落回。非血缘终态构建、已落行
    /// 重跑、cancelled 重放均不入集（防启动空转）。
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

        // 崩溃窗口模拟：重放构建带一致产物并翻终态，钩子未执行（无比对行）。
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

        // 补发钩子（启动对账逐 id spawn 的可等待等价形态）→ 行落回。
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

    /// auto-replay 创建侧崩溃窗口的启动对账：源任务全子构建 succeeded 落
    /// 终态但钩子未执行 → 对账恰查出，补发后重放任务建立；部分成功任务不
    /// 入集；重跑空集（幂等，不重复建）。
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

    /// 反例：已建 replay 的源任务二次启动不补发、不重复建（lineage 剔除对
    /// 存活/终态 replay 一视同仁，pending 存活形态即覆盖"活跃 replay"面）。
    #[tokio::test]
    async fn startup_reconcile_skips_task_with_existing_replay() {
        let (app, _tmp) = setup_app(None, None).await;
        let store = &app.state_store;
        let (_task_id, build_id) =
            seed_succeeded_det_task(&app, "has-replay-3.0-1", "x86_64").await;
        on_build_terminal(&app, build_id).await.unwrap(); // 正常路径：钩子创建 replay

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

    /// 种子"血缘形态"终态构建：血缘键直书 request_json、可选打 det 标、
    /// 翻 succeeded（无产物、无比对行）。返回 build id。
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

    /// 对账不按 det 标记筛（比对对所有回放开放）：det 标记与否的
    /// 血缘终态构建都入集，判别力移交比对落行侧。
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

    /// 对账反例②：血缘键值非 id（JSON null）不入集——LIKE 粗筛按键名放行，
    /// 键值合法性由 `get_build_reproduce_source` 复核剔除；det 标打上证明
    /// 剔除发生在血缘复核段而非 det 谓词。
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

    /// 血缘复核跌落判别（三态）：`get_build_reproduce_source` 返回 None 后
    /// 按原文是否含血缘键区分——(a) 普通构建照旧落②③（对照臂）；(b) 血缘
    /// 键损坏（值 null/字符串，as_i64 失败）按规则②早退：不建 auto replay、
    /// 不落 cross-arch；(c) 有效血缘已由 `replay_terminal_compares_and_
    /// does_not_chain` 钉死。(b) 与 (a) 夹具同构、唯一差异血缘键值损坏，
    /// 回退即两条断言必红；对照臂防空转绿。
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

    /// 假阳性回归：request_json 含血缘子串但无顶层血缘键的普通构建
    ///（`--define 'foo=reproduce_from_build_id'` 形态）不得被子串粗筛误判，
    /// 照旧落②③。夹具同三态 (a) 对照臂、唯一差异 define 值子串，回退即
    /// replay 数与 cross-arch 行两条断言必红。
    #[tokio::test]
    async fn define_value_containing_lineage_substring_still_auto_replays() {
        let (app, _tmp) = setup_app(None, None).await;
        let store = &app.state_store;

        // 末子构建 request_json 的 define 值含键名子串（顶层无血缘键）。
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

    /// 产品闸：auto_replay=false 或 replay_sampling=0 → 不创建重放。
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

    /// L-4 残余：task_id=None 的构建记录两入口同形态早退（任务收口机制对
    /// 无任务构建无观测面）。直调内部函数：builds.task_id NOT NULL，None
    /// 无法经 DB 落行，取真实记录置 None 直调锁住入口守卫本身。
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
        record.task_id = None; // 无任务形态（succeeded + deterministic 前置保持）
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

    /// 多架构任务末两子构建并发终态 → 两钩子都读到 all-succeeded 快照
    ///（check-then-act 无互斥），在途去重保证只 fan-out 一次；无守卫时
    /// 2/1 断言必红。屏障让两钩子确定性同时进入（不靠调度偶然）。
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
        // 第二架构子构建：直插终态行（规避 pending 守卫）+ reproduce fixture。
        let b2 = second_arch_child(&app, task_id, "hello-1.0-1", "{}").await;

        let task_count_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
            .fetch_one(store.pool())
            .await
            .unwrap();

        // 并发两钩子（末两子构建近同时终态的等价模拟），屏障保证同时进入。
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
        // 收尾释放：占位不残留（否则同 task 后续触发会被误吞）。
        assert!(
            app.auto_replay_inflight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "inflight slot must be released after completion"
        );
    }

    /// 部分成功任务不触发跟跑：一 succeeded 一 failed → 不创建任何重放
    ///（all-succeeded 判定）。
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
        // 第二架构子构建 failed（直插终态行；failed 侧无需 det 标）。
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

        // succeeded 侧钩子（failed 侧不满足 maybe_auto_replay 的 phase 前置）。
        on_build_terminal(&app, b1).await.unwrap();

        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds WHERE id > $1")
            .bind(b2)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(n, 0, "partially failed task must not trigger auto replay");
    }

    /// cross-arch 互比：双架构全终态后 noarch 哈希不一致 → cross_arch_noarch
    /// / diff；重跑幂等（partial UNIQUE 去重）。
    #[tokio::test]
    async fn cross_arch_noarch_mismatch_recorded_once() {
        let (app, _tmp) = setup_app(None, Some(0)).await; // sampling=0：隔离自动跟跑
        let (_task_id, b1) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        let store = &app.state_store;
        let task_id: i64 = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(b1)
            .fetch_one(store.pool())
            .await
            .unwrap();
        // 任务聚合已 succeeded：pending 会被 task 守卫拒，直插终态行。
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

    /// "只对非 replay 任务执行"的强制面：子构建带血缘即使双架构全终态 +
    /// noarch 不一致也不做任务级互比（已逐 build 与 source 比对）；① 分支
    /// 已提前返回，此处直调钉住入口守卫。
    #[tokio::test]
    async fn cross_arch_compare_skips_replay_lineage_task() {
        let (app, _tmp) = setup_app(None, Some(0)).await; // sampling=0：隔离自动跟跑
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
        // b2 补打 det 标：夹具须只被血缘守卫拦截——裸插入默认非 det，deterministic
        // 门同样会拦，删守卫后断言仍绿（无判别力）。
        store.set_build_deterministic(b2, true).await.unwrap();

        // 两子构建都带血缘标记（来源 id 任意，判定只解析 request_json，无 FK）。
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

    /// deterministic 门：构建未打 det 标的双架构任务 noarch 不一致也不落行
    ///（非 det 漂移属预期，不入观测面）；同构夹具打标后照常落行——门只看
    /// builds.deterministic 标，钩子内不读产品配置。
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

        // 非 det：双架构全终态 + noarch 哈希不一致 → 门拦截，零行。
        let (app, _tmp) = setup_app(None, Some(0)).await; // sampling=0：隔离自动跟跑
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

        // det：同构夹具 + 打标 → 照常落行。
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

    /// 非 deterministic source 的手动 reproduce：比对照常落行，verdict 如实
    /// 记 diff（源未时间归一化，mtime 漂移属真实差异）。
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
        // 手动 replay：血缘指向非 deterministic source。
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

    /// GC 竞态：source 行已被删除 → 比对钩子 warn + Ok，不落行。
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

    /// cross-arch 全一致 → 零行（只记不一致；正向测试均用不一致样本，本例补判别锚）。
    #[tokio::test]
    async fn cross_arch_noarch_all_identical_records_no_row() {
        let (app, _tmp) = setup_app(None, Some(0)).await; // sampling=0：隔离自动跟跑
        let (_task_id, b1) = seed_succeeded_det_task(&app, "hello-1.0-1", "x86_64").await;
        let store = &app.state_store;
        let task_id: i64 = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(b1)
            .fetch_one(store.pool())
            .await
            .unwrap();
        // 第二架构子构建（同 task，纯历史记账形态直插终态行）。
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

    /// 非终态早退：building 期触发的钩子（时序竞态）零副作用。判别力前提：
    /// 带血缘 + source 带产物，守卫缺失会走进 compare 落行。
    #[tokio::test]
    async fn non_terminal_build_hook_returns_early_no_side_effects() {
        let (app, _tmp) = setup_app(None, Some(0)).await;
        let store = &app.state_store;
        // deterministic source（带产物）+ 尚在 building 的 replay 构建。
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

    /// 产品解析失败（产品已删）→ warn + skip：不建重放、不落比对行。
    #[tokio::test]
    async fn auto_replay_skips_when_product_unresolvable() {
        let (app, _tmp) = setup_app(None, None).await;
        let store = &app.state_store;
        // 产品 "ghost" 无行（builds/tasks.product 无 FK，可直插）。
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

    /// 单架构跳过 + succeeded-only 口径：(a) 同架构哈希不一致 → arch_count<2
    /// 不互比；(b) 双架构一 failed——failed 子构建不参与比对，哈希不同也不
    /// 落行。
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

        // (b) 双架构一 failed：failed 子构建被 succeeded 过滤口径排除。
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

        // succeeded 侧收口（failed 侧不满足 maybe_auto_replay 前置）。
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

    /// ①：NULL 锚 noarch 文件名进 detail 的 `missing_unsigned_anchor`（缺锚
    /// 行不参与 mismatch 判定，仅披露）；纯缺锚无真实 diff 仍不落行。
    #[tokio::test]
    async fn cross_arch_null_anchor_noarch_disclosed_in_detail() {
        let (app, _tmp) = setup_app(None, Some(0)).await; // sampling=0：隔离自动跟跑
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
        // NULL 锚行：双架构都产出该文件，b1 侧 unsigned_sha256 缺失。
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
        // 本例无单侧产出文件：only_in 不出现。
        assert!(detail.get("only_in").is_none());
    }

    /// ②：单侧产出文件随真实 diff 行在 detail 的 `only_in` 附注（file →
    /// {build_id, arch}）；纯单侧无真实 diff 仍不落行。
    #[tokio::test]
    async fn cross_arch_single_sided_file_noted_in_detail() {
        let (app, _tmp) = setup_app(None, Some(0)).await; // sampling=0：隔离自动跟跑
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
        // 本例无缺锚文件：missing_unsigned_anchor 不出现。
        assert!(detail.get("missing_unsigned_anchor").is_none());
    }
}
