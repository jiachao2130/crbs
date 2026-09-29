// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 待处理构建恢复：僵尸记录重排与派发修复入口。

use std::sync::Arc;

/// Server 启动时收集可恢复的 pending 任务；必须先于 zombie repair 调用——
/// `BuildLifecycle::attach` 把待恢复记录的 `crbs_pid` 刷成当前 PID，避免被 zombie
/// repair 误判孤儿。首查失败上抛拒启（fail-closed：静默跳过会让待恢复构建滞留 pending）。
pub async fn recover_pending_builds(
    state_store: &Arc<crbs_core::StateStore>,
) -> crbs_core::Result<usize> {
    let infos = state_store
        .list_pending_with_request_info()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to list pending builds for resume");
            crbs_core::error::CrbsError::Database(format!("recover pending builds: {e}"))
        })?;

    let current_pid = std::process::id() as i64;
    let mut count = 0;

    for info in infos {
        // 若原进程仍存活，可能是另一个 server 实例在负责该任务，跳过避免重复执行。
        if let Some(pid) = info.crbs_pid {
            if crbs_core::util::is_process_alive(pid).await {
                continue;
            }
        }

        if !tokio::fs::try_exists(&info.srpm_path)
            .await
            .unwrap_or(false)
        {
            tracing::warn!(build_id = %info.id, path = %info.srpm_path, "Staged SRPM missing, skipping resume");
            continue;
        }

        if let Err(e) =
            crbs_core::engine::BuildLifecycle::attach(state_store.clone(), info.id, current_pid)
                .await
        {
            tracing::warn!(build_id = %info.id, error = %e, "Failed to attach lifecycle for resume");
            continue;
        }

        // 重置 started_at 避免旧任务因等待时间累积获得不公平调度优势
        if let Err(e) = state_store.reset_pending_build_timestamp(info.id).await {
            tracing::warn!(build_id = %info.id, error = %e, "Failed to reset pending build timestamp");
        }

        count += 1;
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 断言恢复首查失败上抛（关池注入 PoolClosed），错误 Display 含 recover 语义供 bootstrap 拒启分流。
    #[tokio::test]
    async fn recover_pending_builds_propagates_list_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        store.pool().close().await;

        let err = recover_pending_builds(&store).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("recover pending builds"),
            "error must carry recover semantics for bootstrap triage: {msg}"
        );
    }
}
