// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Hub 侧 task 源码目录（`{result_root}/{task_id}/`）的孤儿对账清扫：submit
//! 留存全部 source SRPM（单份 1~100MB 级）落库 `tasks.result_dir`，而结果
//! GC 只删 builds.result_dir 叶子，一级 task 目录被"至少二级子目录"安全
//! 边界跳过，tasks 行被 retention prune 清掉后无回收方、无界泄漏。sweep
//! 谓词：**行不存在且 mtime 超过宽限期**才删——行在即 source 在（rebuild
//! 依赖），无行任务 rebuild 本就 404、无读取方。互引：纯数字一级目录过滤
//! （跳过 {product}/{pkg} 等布局）是结果 GC（`engine/gc/results.rs::run_result_gc_standalone`）
//! "builds 行不以 result_dir 非 NULL 被删"前提的组成之一。

use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use crate::server::state::AppState;

/// 孤儿判定宽限：目录 mtime 超过该时长且 DB 行不存在才删（行先于目录写入
/// 创建，宽限仅防 prune/sweep 竞态）；取值对齐 `artifacts_gc::ORPHAN_ARTIFACT_GRACE`。
const ORPHAN_TASK_DIR_GRACE: Duration = Duration::from_secs(24 * 3600);

/// 清扫 task 结果根下 DB 行已不存在的孤儿 task 目录（scheduler 孤儿清扫
/// 循环挂载，与 `sweep_stale_staging` 同档，60s 一轮）。
pub(crate) async fn sweep_orphan_task_dirs(app: &Arc<AppState>) {
    sweep_orphan_task_dirs_with_grace(app, ORPHAN_TASK_DIR_GRACE).await;
}

/// 实际实现（grace 可注入，测试用 `ZERO` 直接触发删除分支）。
async fn sweep_orphan_task_dirs_with_grace(app: &Arc<AppState>, grace: Duration) {
    let result_root = app.default_task_result_root();
    let mut rd = match tokio::fs::read_dir(&result_root).await {
        Ok(rd) => rd,
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            warn!(
                path = %result_root.display(),
                error = %e,
                "Failed to read result root for orphan task dir sweep"
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
                    path = %result_root.display(),
                    error = %e,
                    "Failed to iterate result root during orphan task dir sweep"
                );
                return;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(task_id) = name.parse::<i64>() else {
            // 宁漏删不误删：解析失败仅跳过，绝不删。
            warn!(
                entry = %name,
                "Numeric task dir name out of i64 range; skipping orphan task dir sweep entry"
            );
            continue;
        };

        // mtime 宽限先于 DB 点查（行存在是常态，省每轮点查）；stat 失败按新鲜口径保留。
        let stale = crate::server::artifacts_gc::dir_entry_stale(&entry, grace).await;
        if !stale {
            continue;
        }

        // stale 才查行：行在→保留（rebuild 依赖）；查行失败→跳过（防瞬时故障误删）。
        match app.state_store.get_task(task_id).await {
            Ok(Some(_)) => continue,
            Ok(None) => {}
            Err(e) => {
                warn!(
                    task_id = task_id,
                    error = %e,
                    "Failed to look up task for orphan task dir sweep; skipping this round"
                );
                continue;
            }
        }

        // 隔离断言：目标严格位于 result root 之下、不等于根本身（join 产物必为一级子目录）。
        let target = result_root.join(name);
        if !target.starts_with(&result_root) || target == result_root {
            warn!(
                target = %target.display(),
                "Task dir sweep target failed isolation assertion; refusing to remove"
            );
            continue;
        }
        match tokio::fs::remove_dir_all(&target).await {
            Ok(()) => info!(
                task_id = task_id,
                path = %target.display(),
                "Swept orphan task dir of pruned task"
            ),
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(
                task_id = task_id,
                path = %target.display(),
                error = %e,
                "Failed to remove orphan task dir"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crbs_core::config::ServerConfig;
    use crbs_core::StateStore;

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

    /// 行在目录（含 source 树）保留；行不存在 + grace ZERO 连树删除；非数字目录不碰。
    #[tokio::test]
    async fn sweep_removes_rowless_dirs_and_keeps_rows_present() {
        let (app, _tmp) = setup_app().await;
        let result_root = app.default_task_result_root();

        let live = crate::test_support::seed_task(&app.state_store, "p", "pkg").await;

        for id in [live, 999999] {
            let source = result_root.join(id.to_string()).join("source");
            tokio::fs::create_dir_all(&source).await.unwrap();
            tokio::fs::write(source.join("hello-1.0-1.src.rpm"), b"srpm")
                .await
                .unwrap();
        }
        tokio::fs::create_dir_all(result_root.join("junk"))
            .await
            .unwrap();

        sweep_orphan_task_dirs_with_grace(&app, Duration::ZERO).await;

        assert!(
            !result_root.join("999999").exists(),
            "rowless task dir must be swept with its source tree"
        );
        assert!(
            result_root
                .join(live.to_string())
                .join("source")
                .join("hello-1.0-1.src.rpm")
                .exists(),
            "task row present → source dir must stay (rebuild semantics)"
        );
        assert!(result_root.join("junk").exists());
    }

    /// 默认宽限：新鲜目录即使行不存在也保留（prune/sweep 竞态窗口）。
    #[tokio::test]
    async fn sweep_keeps_fresh_rowless_dirs_within_grace() {
        let (app, _tmp) = setup_app().await;
        let result_root = app.default_task_result_root();
        tokio::fs::create_dir_all(result_root.join("123456").join("source"))
            .await
            .unwrap();

        sweep_orphan_task_dirs(&app).await;

        assert!(
            result_root.join("123456").exists(),
            "fresh rowless dir must survive the grace window"
        );
    }

    /// result root 不存在时 no-op，不报错。
    #[tokio::test]
    async fn sweep_noop_when_result_root_missing() {
        let (app, _tmp) = setup_app().await;
        sweep_orphan_task_dirs(&app).await;
        assert!(!app.default_task_result_root().exists());
    }
}
