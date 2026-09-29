// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Hub 侧 Worker 日志目录（`{artifact_dir}/{build_id}/`）的孤儿清扫。
//!
//! `report_logs` 在构建期间把日志 chunk 落盘到该目录（失败构建的 durable
//! 日志）。正常回收链路是结果 GC 联动删除（crbs-core `remove_gc_artifact_dir`）；
//! 但 DB 行已被 `prune_old_records` 清掉的构建走不到 GC 候选（候选按行选），
//! 日志副本因此永久残留。本 sweep 兜底该场景：**行不存在且目录 mtime 超过
//! 宽限期**才删——行存在的一律保留（无论终态与否，交给结果 GC 联动）。
//! 与 `sweep_stale_staging` 的分工：staging 额外删"行不存在 + 超宽限"目录
//! 之外的终态行目录（构建在途生命周期资源，终态即废）；artifacts 目录在
//! 行消失后已无任何潜在读取方，宽限期只防 prune 与 sweep 之间的窗口。

use std::sync::Arc;
use std::time::Duration;

/// 目录项 mtime 过期判定（artifacts/tasks GC 与 staging 行消失目录三个 sweep
/// 点共用，均为 `>=` 严格超宽限口径）：metadata 失败或时钟不可得按新鲜保留
///（fail-safe 不删，防 prune/sweep 竞态误删）。staging 孤儿目录的 `>` 边界
/// 语义不同，保持内联。
pub(crate) async fn dir_entry_stale(entry: &tokio::fs::DirEntry, grace: Duration) -> bool {
    entry
        .metadata()
        .await
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok())
        .map(|age| age >= grace)
        .unwrap_or(false)
}

use tracing::{info, warn};

use crate::server::state::AppState;

/// 孤儿判定宽限：目录 mtime 超过该时长且 DB 行不存在才删。
/// 行在 submit 时先于任何日志写入创建，正常路径不存在"目录先于行"的窗口；
/// 宽限仅防 prune 事务与 sweep 读取之间的竞态。
const ORPHAN_ARTIFACT_GRACE: Duration = Duration::from_secs(24 * 3600);

/// 清扫 `{artifact_dir}` 下 DB 行已不存在的孤儿日志目录。
///
/// 挂载在 scheduler 孤儿清扫循环内（与 `sweep_stale_staging` 同档，60s 一轮）。
pub(crate) async fn sweep_orphan_artifact_dirs(app: &Arc<AppState>) {
    sweep_orphan_artifact_dirs_with_grace(app, ORPHAN_ARTIFACT_GRACE).await;
}

/// 实际实现（grace 可注入，测试用 `ZERO` 直接触发删除分支）。
async fn sweep_orphan_artifact_dirs_with_grace(app: &Arc<AppState>, grace: Duration) {
    let artifact_root = app.artifact_dir();
    let mut rd = match tokio::fs::read_dir(&artifact_root).await {
        Ok(rd) => rd,
        // artifact_dir 尚未创建：无日志可扫。
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            warn!(
                path = %artifact_root.display(),
                error = %e,
                "Failed to read artifact_dir for orphan sweep"
            );
            return;
        }
    };

    loop {
        let entry = match rd.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(e) => {
                warn!(
                    path = %artifact_root.display(),
                    error = %e,
                    "Failed to iterate artifact_dir during orphan sweep"
                );
                return;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // 只认纯数字一级目录（{build_id}）；非数字条目跳过。
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(build_id) = name.parse::<i64>() else {
            continue;
        };

        // mtime 宽限先于 DB 点查（判定顺序调优，照 tasks_gc 的同款顺序）：
        // 目录仍新鲜时恒保留（无论行是否存在——四个组合语义与"先查行后看
        // mtime"完全一致：行在+新鲜/行在+超限均保留，行不在+新鲜保留，
        // 行不在+超限删），stat 失败按新鲜口径保留，防 prune/sweep 竞态。
        // 行存在是常态，先查 mtime 让 fresh 目录不再每轮各付一次点查。
        let stale = crate::server::artifacts_gc::dir_entry_stale(&entry, grace).await;
        if !stale {
            continue;
        }

        // stale 才查行：行仍存在 → 保留（终态构建的结果 GC 联动负责，与
        // tasks_gc"行在即 rebuild source 在"的保留理由不同，见模块文档）；
        // 读取失败 → 跳过本轮（DB 瞬时故障不应当成"行不存在"删数据）。
        match app.state_store.get_build(build_id).await {
            Ok(Some(_)) => continue,
            Ok(None) => {}
            Err(e) => {
                warn!(
                    build_id = build_id,
                    error = %e,
                    "Failed to look up build for artifact orphan sweep; skipping this round"
                );
                continue;
            }
        }

        // 隔离断言：目标严格位于 artifact_dir 之下、不等于共享根本身
        //（name 为纯数字，join 产物必为根下一级子目录）。
        let target = artifact_root.join(name);
        if !target.starts_with(&artifact_root) || target == artifact_root {
            warn!(
                target = %target.display(),
                "Artifact orphan sweep target failed isolation assertion; refusing to remove"
            );
            continue;
        }
        match tokio::fs::remove_dir_all(&target).await {
            Ok(()) => info!(
                build_id = build_id,
                path = %target.display(),
                "Swept orphan artifact dir of pruned build"
            ),
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(
                build_id = build_id,
                path = %target.display(),
                error = %e,
                "Failed to remove orphan artifact dir"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crbs_core::config::ServerConfig;
    use crbs_core::{BuildInsert, StateStore};

    async fn setup_app() -> (Arc<AppState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store,
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        (app, tmp)
    }

    /// 行不存在的孤儿目录（宽限 ZERO）被删；行存在（终态/活跃）与非数字目录保留。
    #[tokio::test]
    async fn sweep_removes_rowless_dirs_and_keeps_rows_present() {
        let (app, _tmp) = setup_app().await;
        let artifact_root = app.artifact_dir();

        let done = app
            .state_store
            .insert_build(BuildInsert {
                product: "p",
                pkg_name: "pkg",
                phase: "succeeded",
                backend: "chroot",
                user: "t",
                task_id: Some(crate::test_support::seed_task(&app.state_store, "p", "pkg").await),
                ..Default::default()
            })
            .await
            .unwrap();
        let building = app
            .state_store
            .insert_build(BuildInsert {
                product: "p",
                pkg_name: "pkg",
                phase: "building",
                backend: "chroot",
                user: "t",
                task_id: Some(crate::test_support::seed_task(&app.state_store, "p", "pkg").await),
                ..Default::default()
            })
            .await
            .unwrap();

        for id in [done, building, 999999] {
            tokio::fs::create_dir_all(artifact_root.join(id.to_string()))
                .await
                .unwrap();
        }
        tokio::fs::create_dir_all(artifact_root.join("junk"))
            .await
            .unwrap();

        sweep_orphan_artifact_dirs_with_grace(&app, Duration::ZERO).await;

        assert!(
            !artifact_root.join("999999").exists(),
            "rowless dir must be swept"
        );
        assert!(
            artifact_root.join(done.to_string()).exists(),
            "terminal build dir must stay (results-GC linkage owns it)"
        );
        assert!(
            artifact_root.join(building.to_string()).exists(),
            "active build dir must stay"
        );
        assert!(artifact_root.join("junk").exists());
    }

    /// 默认宽限：新鲜目录即使行不存在也保留（prune/sweep 竞态窗口）。
    #[tokio::test]
    async fn sweep_keeps_fresh_rowless_dirs_within_grace() {
        let (app, _tmp) = setup_app().await;
        let artifact_root = app.artifact_dir();
        tokio::fs::create_dir_all(artifact_root.join("123456"))
            .await
            .unwrap();

        sweep_orphan_artifact_dirs(&app).await;

        assert!(
            artifact_root.join("123456").exists(),
            "fresh rowless dir must survive the grace window"
        );
    }

    /// mtime-first 重排后"行存在+新鲜"成为独立早退路径
    /// （先 mtime 后点查），补一回归测试防"漏保留/误删"——行存在 + 默认宽限（目录
    /// 新鲜）→ 目录保留。（注：查询顺序回归[行先序 vs mtime 先序]在存活结果
    /// 上不可观测，本测试只锁保留结果。）
    #[tokio::test]
    async fn sweep_keeps_fresh_dirs_with_existing_build_row() {
        let (app, _tmp) = setup_app().await;
        let artifact_root = app.artifact_dir();
        let build_id = app
            .state_store
            .insert_build(BuildInsert {
                product: "p",
                pkg_name: "pkg",
                phase: "succeeded",
                backend: "chroot",
                user: "t",
                task_id: Some(crate::test_support::seed_task(&app.state_store, "p", "pkg").await),
                ..Default::default()
            })
            .await
            .unwrap();
        tokio::fs::create_dir_all(artifact_root.join(build_id.to_string()))
            .await
            .unwrap();

        sweep_orphan_artifact_dirs(&app).await;

        assert!(
            artifact_root.join(build_id.to_string()).exists(),
            "fresh dir with an existing build row must survive (mtime-first path)"
        );
    }

    /// artifact_dir 不存在时 no-op，不报错。
    #[tokio::test]
    async fn sweep_noop_when_artifact_dir_missing() {
        let (app, _tmp) = setup_app().await;
        sweep_orphan_artifact_dirs(&app).await;
        assert!(!app.artifact_dir().exists());
    }
}
