// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `--rebuild --local`：无 daemon 的本地任务重建。镜像 `crbs-server::rebuild_task_for_user`
//! 业务逻辑但去掉 HTTP / audit_log / 新 task 行记账：本进程读 StateStore、复用原任务
//! SRPM 与 request_json 走 `handle_batch_build`；与 `reproduce.rs` 的 `--local` 直连模式一致。

use std::path::PathBuf;
use std::sync::Arc;

use crbs_core::config::CrbsConfig;
use crbs_core::error::CrbsError;
use crbs_core::privilege::CallerContext;
use crbs_core::StateStore;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::cli::BuildArgs;

use super::handle_batch_build;

/// 处理 `crbs build --rebuild <id> --local`（arch 约束见 `resolve_rebuild_local_arch`）。
pub(crate) async fn handle_rebuild_local(
    rebuild_id: &str,
    args: &BuildArgs,
    ctx: &CallerContext,
    cancel_token: &CancellationToken,
) -> anyhow::Result<()> {
    let crbs_config = CrbsConfig::load_async().await?;
    let state = StateStore::open_for_engine(&crbs_config.crbs_root).await?;

    let user_filter = crate::cmd::visible_user_filter(ctx);
    // --rebuild ID 是 task 语义；两表序列独立同数字，不得用 build 域 resolve_short_id。
    let task_id = state.resolve_task_id(rebuild_id, user_filter).await?;

    let task = state
        .get_task(task_id)
        .await?
        .ok_or_else(|| CrbsError::ValidationFailed {
            message: format!(
                "task {} not found. Run 'crbs status' to list tasks.",
                task_id
            ),
        })?;

    crate::cmd::ensure_record_owner("task", task_id, &task.user, ctx)?;

    let info =
        state
            .get_task_rebuild_info(task_id)
            .await?
            .ok_or_else(|| CrbsError::ValidationFailed {
                // task 行存在、id 源没错：缺的是 rebuild info，故不给 id 来源提示。
                message: format!(
                    "task {} has no recorded rebuild info (cannot rebuild)",
                    task_id
                ),
            })?;

    let task_dir = info
        .result_dir
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| CrbsError::ValidationFailed {
            message: format!(
                "task {} has no recorded result_dir; cannot rebuild locally",
                task_id
            ),
        })?;
    let source_dir = task_dir.join("source");

    let mut srpms = read_source_srpms(&source_dir).await?;
    if srpms.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "source srpms no longer available at {} (results may have been GC'd); \
                 cannot rebuild",
                source_dir.display()
            ),
        }
        .into());
    }

    // 多包任务按记录的提交序（pkg_names）重排 SRPM；单包保持文件名序。
    if task.pkg_names.len() > 1 {
        let mut ordered = Vec::with_capacity(srpms.len());
        for name in &task.pkg_names {
            if let Some(pos) = srpms
                .iter()
                .position(|p| crbs_core::util::srpm_display_name(p) == name)
            {
                ordered.push(srpms.remove(pos));
            }
        }
        ordered.extend(srpms);
        srpms = ordered;
    }

    // 构建选项：task 级 request_json（v1 schema 起必有；缺失则无法重建）。
    let request_json = info
        .request_json
        .as_deref()
        .ok_or_else(|| CrbsError::ValidationFailed {
            message: format!(
                "task {} has no recorded build options; cannot rebuild",
                task_id
            ),
        })?;
    let mut opts: crbs_core::BuildOptions =
        serde_json::from_str(request_json).map_err(|e| CrbsError::ValidationFailed {
            message: format!("parse recorded build options for task {}: {}", task_id, e),
        })?;
    opts.arch = None;
    opts.arch_list.clear();
    opts.priority = Some(info.priority);

    let db_arches = state.get_task_arches(task_id).await?;
    if let Some(target) = resolve_rebuild_local_arch(&db_arches, task_id)? {
        opts.target = Some(target);
    }

    let store = Arc::new(state);
    // CLI 引擎世界不 pin root（crbs.toml 的 crbs_root 即引擎 root）。
    let engine =
        crbs_core::build_engine_from_options(&info.product, &opts, store.clone(), None, None)
            .await?;
    let mut engine = crbs_core::apply_options_to_engine(engine, &opts)?;
    engine = engine.with_caller(ctx.caller.clone());

    // 并发度：CLI > engine config > available_parallelism。与 prepare_local_engine 对齐。
    let jobs = args.behavior.jobs.unwrap_or_else(|| {
        let cfg_jobs = engine.max_concurrent_builds();
        if cfg_jobs > 0 {
            cfg_jobs
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        }
    });
    engine = engine.with_max_concurrent_builds(jobs);

    info!(
        task_id,
        product = %info.product,
        srpms = srpms.len(),
        jobs,
        "Rebuilding task locally (no daemon)"
    );

    let engine = Arc::new(engine);
    handle_batch_build(
        &engine,
        srpms,
        jobs,
        cancel_token,
        args.behavior.fail_fast,
        args.output.format,
    )
    .await
}

async fn read_source_srpms(source_dir: &std::path::Path) -> crbs_core::Result<Vec<PathBuf>> {
    let mut srpms = Vec::new();
    let mut entries =
        tokio::fs::read_dir(source_dir)
            .await
            .map_err(|_| CrbsError::ValidationFailed {
                message: format!(
                    "source srpms no longer available at {} (results may have been GC'd); \
                 cannot rebuild",
                    source_dir.display()
                ),
            })?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| CrbsError::from_io_context("read task source dir", e))?
    {
        if entry.file_name().to_string_lossy().ends_with(".src.rpm") {
            srpms.push(entry.path());
        }
    }
    srpms.sort();
    Ok(srpms)
}

/// 本地重建只产宿主 arch（诚实语义）；arch 来自数据库（原任务去重子构建）而非用户本次
/// 显式指定，故不做 conflict-with-`--target` 检查。三种情况：空 → BuildEngine 默认（host）；
/// 含 host → host（多 arch 时 warn 丢弃项）；不含 host → 拒绝（跨 arch 须 `--remote`）。
fn resolve_rebuild_local_arch(
    arches: &[String],
    task_id: i64,
) -> crbs_core::Result<Option<String>> {
    let host = std::env::consts::ARCH;
    if arches.is_empty() {
        return Ok(None);
    }
    if arches.iter().any(|a| a == host) {
        if arches.len() > 1 {
            let dropped: Vec<&String> = arches.iter().filter(|a| *a != host).collect();
            warn!(
                task_id,
                host = %host,
                dropped = ?dropped,
                "local rebuild only produces the host arch; other arches will need --remote for fan-out."
            );
        }
        Ok(Some(host.to_string()))
    } else {
        Err(CrbsError::ValidationFailed {
            message: format!(
                "task {} targets {:?}, host arch is {}; local rebuild cannot cross-compile. \
                 Use --remote for cross-arch fan-out.",
                task_id, arches, host
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_rebuild_arch_empty_returns_none() {
        let out = resolve_rebuild_local_arch(&[], 1).unwrap();
        assert_eq!(out, None);
    }

    #[test]
    fn resolve_rebuild_arch_host_only_uses_host() {
        let host = std::env::consts::ARCH.to_string();
        let out = resolve_rebuild_local_arch(std::slice::from_ref(&host), 1).unwrap();
        assert_eq!(out, Some(host));
    }

    #[test]
    fn resolve_rebuild_arch_multi_with_host_warns_and_uses_host() {
        let host = std::env::consts::ARCH.to_string();
        let other = if host == "x86_64" {
            "aarch64"
        } else {
            "x86_64"
        }
        .to_string();
        let out = resolve_rebuild_local_arch(&[host.clone(), other], 42).unwrap();
        assert_eq!(out, Some(host));
    }

    #[test]
    fn resolve_rebuild_arch_cross_arch_bails() {
        let host = std::env::consts::ARCH;
        let other = if host == "x86_64" {
            "aarch64"
        } else {
            "x86_64"
        }
        .to_string();
        let err = resolve_rebuild_local_arch(&[other], 7).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("cannot cross-compile"), "err was: {}", msg);
        assert!(msg.contains("--remote"), "err was: {}", msg);
    }

    #[tokio::test]
    async fn read_source_srpms_missing_dir_maps_to_validation_error() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        let err = read_source_srpms(&missing).await.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("no longer available"), "err was: {}", msg);
    }

    #[tokio::test]
    async fn read_source_srpms_returns_sorted_srpms() {
        let tmp = tempfile::tempdir().unwrap();
        let src_dir = tmp.path().join("source");
        tokio::fs::create_dir_all(&src_dir).await.unwrap();
        for name in ["b-1-1.src.rpm", "a-1-1.src.rpm", "not-an-rpm.txt"] {
            tokio::fs::write(src_dir.join(name), b"").await.unwrap();
        }
        let out = read_source_srpms(&src_dir).await.unwrap();
        assert_eq!(out.len(), 2);
        assert!(out[0].ends_with("a-1-1.src.rpm"));
        assert!(out[1].ends_with("b-1-1.src.rpm"));
    }
}
