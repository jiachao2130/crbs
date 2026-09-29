// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 多包本地并发构建：worker 池、生命周期映射与结果汇总。

use crate::cli::OutputFormat;
use crbs_core::engine::retry::RetryPolicy;
use crbs_core::engine::BuildLifecycle;
use crbs_core::error::CrbsError;
use std::collections::HashMap;
use std::path::PathBuf;

use super::BuildResult;
use super::BuildSummary;

type LifecycleMap = HashMap<PathBuf, Option<BuildLifecycle>>;
type SharedLifecycleMap = std::sync::Arc<tokio::sync::Mutex<LifecycleMap>>;

pub(crate) async fn run_build_workers(
    engine: &std::sync::Arc<crbs_core::engine::BuildEngine>,
    srpms: Vec<(std::path::PathBuf, Option<String>)>,
    jobs: usize,
    cancel_token: &tokio_util::sync::CancellationToken,
    fail_fast: bool,
    format: OutputFormat,
) -> anyhow::Result<BuildSummary> {
    let total = srpms.len();
    run_build_workers_with_lifecycle_map(WorkerPoolParams {
        engine,
        srpms,
        total,
        jobs,
        cancel_token,
        fail_fast,
        format,
        lifecycle_map: None,
    })
    .await
}

/// [`run_build_workers_with_lifecycle_map`] 的参数包：worker 池的输入与
/// 运行选项（SRPM 队列、并发度、取消/失败策略、展示格式、预创建 lifecycle）。
///
/// `lifecycle_map` 的 key 为 SRPM 路径，value 为可选的预创建 lifecycle；
/// worker 处理每个 SRPM 时从 map 取出（remove，一次性）传给
/// `engine.build_with_target`，用于本地 detach 等需要先拿到 build_id 的场景。
pub(crate) struct WorkerPoolParams<'a> {
    pub(crate) engine: &'a std::sync::Arc<crbs_core::engine::BuildEngine>,
    pub(crate) srpms: Vec<(std::path::PathBuf, Option<String>)>,
    pub(crate) total: usize,
    pub(crate) jobs: usize,
    pub(crate) cancel_token: &'a tokio_util::sync::CancellationToken,
    pub(crate) fail_fast: bool,
    pub(crate) format: OutputFormat,
    pub(crate) lifecycle_map: Option<SharedLifecycleMap>,
}

pub(crate) async fn run_build_workers_with_lifecycle_map(
    params: WorkerPoolParams<'_>,
) -> anyhow::Result<BuildSummary> {
    let WorkerPoolParams {
        engine,
        srpms,
        total,
        jobs,
        cancel_token,
        fail_fast,
        format,
        lifecycle_map,
    } = params;
    let tasks = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::VecDeque::from(
        srpms.into_iter().enumerate().collect::<Vec<_>>(),
    )));
    let results: std::sync::Arc<tokio::sync::Mutex<Vec<BuildResult>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let json_mode = format == OutputFormat::Json;
    let mut handles = Vec::new();
    for _ in 0..jobs {
        let engine = std::sync::Arc::clone(engine);
        let cancel = cancel_token.clone();
        let tasks = std::sync::Arc::clone(&tasks);
        let results = std::sync::Arc::clone(&results);
        let lifecycle_map = lifecycle_map.clone();
        let handle = tokio::spawn(async move {
            loop {
                let task = {
                    let mut t = tasks.lock().await;
                    t.pop_front()
                };
                match task {
                    Some((seq, (srpm, target))) => {
                        if cancel.is_cancelled() {
                            // fail_fast/取消触发后，队列中剩余包不能凭空消失
                            //（summary 少计、--list-failed 无从展示）：登记为
                            // Cancelled 并继续排空队列，而不是 break 丢弃。
                            if !json_mode {
                                let pkg_name =
                                    crbs_core::util::srpm_display_name(&srpm).to_string();
                                println!(
                                    "[{}/{}] {:<20} CANCELLED  (  0s)",
                                    seq + 1,
                                    total,
                                    pkg_name
                                );
                            }
                            results.lock().await.push(BuildResult::Failed(
                                srpm,
                                CrbsError::Cancelled,
                                0,
                            ));
                            continue;
                        }
                        let pkg_name = crbs_core::util::srpm_display_name(&srpm).to_string();
                        if !json_mode {
                            println!("[{}/{}] {:<20} STARTED", seq + 1, total, pkg_name);
                        }

                        let start = std::time::Instant::now();
                        let policy = RetryPolicy::from_config(engine.config());

                        match policy
                            .run(&pkg_name, &cancel, || {
                                let engine = std::sync::Arc::clone(&engine);
                                let srpm = srpm.clone();
                                let target = target.clone();
                                let task_cancel = cancel.clone();
                                let lifecycle_map = lifecycle_map.clone();
                                async move {
                                    let lifecycle = if let Some(ref map) = lifecycle_map {
                                        map.lock().await.remove(&srpm).flatten()
                                    } else {
                                        None
                                    };
                                    let child_token = task_cancel.child_token();
                                    engine
                                        .build_with_target(
                                            &srpm,
                                            &child_token,
                                            lifecycle,
                                            None,
                                            target.as_deref(),
                                        )
                                        .await
                                        .outputs
                                }
                            })
                            .await
                        {
                            Ok((mut outputs, retries)) => {
                                outputs.retries = retries;
                                let duration = start.elapsed().as_secs();
                                if !json_mode {
                                    let retry_tag = if retries > 0 {
                                        format!(" (retried {})", retries)
                                    } else {
                                        String::new()
                                    };
                                    println!(
                                        "[{}/{}] {:<20} SUCCEEDED  ({:>3}s){}  → {}",
                                        seq + 1,
                                        total,
                                        pkg_name,
                                        duration,
                                        retry_tag,
                                        outputs.result_dir.display()
                                    );
                                }
                                results
                                    .lock()
                                    .await
                                    .push(BuildResult::Succeeded(srpm, outputs, duration));
                            }
                            Err(e) => {
                                let duration = start.elapsed().as_secs();
                                if matches!(e, CrbsError::Cancelled) {
                                    if !json_mode {
                                        println!(
                                            "[{}/{}] {:<20} CANCELLED  ({:>3}s)",
                                            seq + 1,
                                            total,
                                            pkg_name,
                                            duration
                                        );
                                    }
                                } else if matches!(e, CrbsError::Timeout) {
                                    if !json_mode {
                                        println!(
                                            "[{}/{}] {:<20} TIMEOUT    ({:>3}s)",
                                            seq + 1,
                                            total,
                                            pkg_name,
                                            duration
                                        );
                                    }
                                } else {
                                    if !json_mode {
                                        println!(
                                            "[{}/{}] {:<20} FAILED     ({:>3}s)  {}",
                                            seq + 1,
                                            total,
                                            pkg_name,
                                            duration,
                                            e
                                        );
                                    }
                                    if fail_fast {
                                        cancel.cancel();
                                    }
                                }
                                results
                                    .lock()
                                    .await
                                    .push(BuildResult::Failed(srpm, e, duration));
                            }
                        }
                    }
                    None => break,
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        // JoinError 仅在 worker 任务 panic 时出现（构建失败经
        // results 通道回传，不靠 JoinHandle 传播），真 bug 防御臂：
        // 归 INTERNAL(1)（batch.rs::follow_builds_raw 同族裁定），不走
        // io_message（会误归 Io(6)，误导指向网络/磁盘排查）。
        if let Err(e) = handle.await {
            tracing::error!(error = %e, "worker task panicked or was cancelled");
            return Err(crbs_core::error::CrbsError::Internal(format!(
                "worker task panicked or was cancelled: {}",
                e
            ))
            .into());
        }
    }

    let results_vec = {
        let mut guard = results.lock().await;
        std::mem::take(&mut *guard)
    };

    let mut succeeded = Vec::new();
    let mut failed = Vec::new();
    let mut cancelled = Vec::new();
    let mut timeout_list = Vec::new();
    for result in results_vec {
        match result {
            BuildResult::Succeeded(srpm, outputs, duration) => {
                succeeded.push((srpm, outputs, duration))
            }
            BuildResult::Failed(srpm, e, duration) => {
                if matches!(e, CrbsError::Cancelled) {
                    cancelled.push((srpm, e, duration));
                } else if matches!(e, CrbsError::Timeout) {
                    timeout_list.push((srpm, e, duration));
                } else {
                    failed.push((srpm, e, duration));
                }
            }
        }
    }

    Ok(BuildSummary {
        succeeded,
        failed,
        cancelled,
        timeout: timeout_list,
    })
}

pub(crate) fn display_names(items: &[(std::path::PathBuf, CrbsError, u64)]) -> String {
    let mut names: Vec<_> = items
        .iter()
        .map(|(s, _, _)| crbs_core::util::srpm_display_name(s).to_string())
        .collect();
    names.sort();
    names.dedup();
    names.join("  ")
}

pub(crate) fn print_summary(summary: &BuildSummary) {
    println!("\n═══ Summary ═══");
    if !summary.succeeded.is_empty() {
        let signed_count = summary
            .succeeded
            .iter()
            .filter(|(_, o, _)| o.signed)
            .count();
        println!(
            "SUCCEEDED  {:<3} {} (signed: {})",
            summary.succeeded.len(),
            {
                let mut names: Vec<&str> = summary
                    .succeeded
                    .iter()
                    .map(|(_, o, _)| o.pkg_name.as_str())
                    .collect();
                names.sort();
                names.dedup();
                names.join("  ")
            },
            signed_count
        );
    }
    if !summary.failed.is_empty() {
        println!(
            "FAILED     {:<3} {}",
            summary.failed.len(),
            display_names(&summary.failed)
        );
    }
    if !summary.cancelled.is_empty() {
        println!(
            "CANCELLED  {:<3} {}",
            summary.cancelled.len(),
            display_names(&summary.cancelled)
        );
    }
    if !summary.timeout.is_empty() {
        println!(
            "TIMEOUT    {:<3} {}",
            summary.timeout.len(),
            display_names(&summary.timeout)
        );
    }
}
