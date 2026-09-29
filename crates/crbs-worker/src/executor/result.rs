// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Worker 结果上报与辅助工具。

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::info;

use crbs_core::error::CrbsError;

use crate::config::WorkerConfig;
use crate::poller::AssignedTask;
use crate::retry::{retry_with_backoff, retry_with_timeout, wait_for_cancel, REQUEST_TIMEOUT};

use super::ensure_not_cancelled;

/// 构建结果。
#[derive(Debug)]
pub struct BuildResult {
    pub phase: String,
    pub result_dir: Option<String>,
    pub error: Option<String>,
    /// 软告警备注（确定性 SDE 卫生等；**进 JSON payload**，下方三字段不进）：
    /// worker 本地 StateStore 的 build 行 error_summary hub 不可见，此处随成功
    /// 上报带回原文，hub append 进自己 build 行；仅成功填充（失败走 error 通道）。
    pub notes: Option<String>,
    /// 资源采样结果（**进 JSON payload**）：脚本执行期间引擎采样器累计的内存
    /// 峰值 / CPU 总量 / p90 核数 + cgroup 终态包络（peak_total / disk_wbytes /
    /// oom_killed / 口径），随终态上报落 hub 资源列（可空）。失败/取消尽力取
    /// 已采值，前置早退/采样关闭为 `None`（→ null，落库为 NULL）。
    pub resources: Option<crbs_core::engine::ResourceUsage>,
    /// 本地产物目录（仅成功非 None）：上报失败时告警定位产物、供人工恢复。
    pub local_result_dir: Option<std::path::PathBuf>,
    /// 引擎本地 build_id（StateStore 自增 id，结果目录叶子 `{ts}-{build_id}` 后缀，
    /// 与 hub task.build_id 两个 id 空间）；仅成功非 None，上报成功后用于 result_dir 删除断言。
    pub engine_build_id: Option<i64>,
    /// 引擎本地结果根（`engine.config().result_dir`，仅成功非 None）：与
    /// engine_build_id 构成上报成功后删除 local_result_dir 的命名空间断言
    ///（叶子须恰为 root 下第三级 `{product}/{pkg}/{ts}-{id}`）。
    pub engine_result_root: Option<std::path::PathBuf>,
}

impl BuildResult {
    /// 终态载荷构造器：失败/取消路径的 result_dir、notes 与本地产物定位三字段
    /// 恒 `None`（仅成功路径填充）；resources 按"尽力取已采值"传入。
    pub(crate) fn terminal(
        phase: &str,
        error: Option<String>,
        resources: Option<crbs_core::engine::ResourceUsage>,
    ) -> Self {
        Self {
            phase: phase.to_string(),
            result_dir: None,
            error,
            notes: None,
            resources,
            local_result_dir: None,
            engine_build_id: None,
            engine_result_root: None,
        }
    }
}

/// 向 Hub 上报任务中间状态。
pub async fn report_phase(
    cfg: &WorkerConfig,
    worker_id: i64,
    task: &AssignedTask,
    phase: &str,
    cancel_token: Option<&CancellationToken>,
) -> crbs_core::Result<()> {
    ensure_not_cancelled(cancel_token)?;

    let phase = phase.to_string();
    retry_with_backoff("report_phase", cancel_token, || async {
        let client = cfg.build_http_client().await?;
        let url = format!(
            "{}/api/v1/workers/{}/assignments/{}/result",
            cfg.hub_url, worker_id, task.assignment_id
        );

        let payload = serde_json::json!({
            "phase": phase,
        });

        let request = client.post(&url).json(&payload).send();

        let resp = tokio::select! {
            _ = wait_for_cancel(cancel_token) => {
                return Err(CrbsError::Cancelled);
            }
            result = request => {
                result.map_err(|e| crate::error::reqwest("send phase report", e))?
            }
        };

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(crate::error::http_response_error(
                "report phase",
                status,
                text,
            ));
        }

        info!(
            assignment_id = %task.assignment_id,
            task_id = ?task.task_id,
            phase = %phase,
            "Phase reported"
        );
        Ok(())
    })
    .await
}

/// 向 Hub 上报任务结果。契约：入口对已取消令牌直接返回 `Cancelled`，终态上报
/// 必须传未取消令牌（shutdown 取消后终态仍须送达，poller 补报持独立 report_token）。
pub async fn report_result(
    cfg: &WorkerConfig,
    worker_id: i64,
    task: &AssignedTask,
    result: &BuildResult,
    cancel_token: Option<&CancellationToken>,
) -> crbs_core::Result<()> {
    report_result_with_timeout(cfg, worker_id, task, result, cancel_token, REQUEST_TIMEOUT).await
}

/// [`report_result`] 的可注入 per-attempt 超时版：取消路径与失败补报传短
/// 超时，drain 窗口内完不成即放弃（hub 240s reclaimer 仍兜底），不吃默认
/// 30s×3≈93s 的最坏重试链（会被进程退出截断）。其余契约同 [`report_result`]。
pub async fn report_result_with_timeout(
    cfg: &WorkerConfig,
    worker_id: i64,
    task: &AssignedTask,
    result: &BuildResult,
    cancel_token: Option<&CancellationToken>,
    per_attempt: Duration,
) -> crbs_core::Result<()> {
    ensure_not_cancelled(cancel_token)?;

    let payload = serde_json::json!({
        "phase": result.phase,
        "result_dir": result.result_dir,
        "error": result.error,
        // 软告警通道：None → null。
        "notes": result.notes,
        "resources": result.resources,
    });

    retry_with_timeout("report_result", cancel_token, per_attempt, || async {
        let client = cfg.build_http_client().await?;
        let url = format!(
            "{}/api/v1/workers/{}/assignments/{}/result",
            cfg.hub_url, worker_id, task.assignment_id
        );

        let request = client.post(&url).json(&payload).send();

        let resp = tokio::select! {
            _ = wait_for_cancel(cancel_token) => {
                return Err(CrbsError::Cancelled);
            }
            result = request => {
                result.map_err(|e| crate::error::reqwest("send result report", e))?
            }
        };

        if !resp.status().is_success() {
            let status = resp.status();
            // 幂等 409：assignment 已在 hub 落终态（重试重放或 hub 并发写终态）
            // ——按"已达终态"成功处理，否则重试层烧完预算把已完成构建记成假失败。
            if status == reqwest::StatusCode::CONFLICT {
                info!(
                    assignment_id = %task.assignment_id,
                    task_id = ?task.task_id,
                    phase = %result.phase,
                    "Assignment already terminal on hub; result report treated as delivered"
                );
                return Ok(());
            }
            let text = resp.text().await.unwrap_or_default();
            return Err(crate::error::http_response_error(
                "report result",
                status,
                text,
            ));
        }

        info!(
            assignment_id = %task.assignment_id,
            task_id = ?task.task_id,
            phase = %result.phase,
            "Result reported"
        );
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_task() -> AssignedTask {
        AssignedTask {
            assignment_id: 42,
            task_id: Some(7),
            build_id: 1,
            product: "fedora".into(),
            srpm_url: String::new(),
            build_options: serde_json::Value::Null,
            product_config: String::new(),
            reproduce_packages_url: None,
            kind: "build".into(),
            init_product: None,
            product_repo_enabled: false,
            redelivered: false,
        }
    }

    /// 起一个单请求 HTTP 服务器，回给定状态码 + 空 body，返回监听地址。
    async fn spawn_status_server(status: u16) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            if let Ok((mut sock, _)) = listener.accept().await {
                // 读掉请求头 + body（不等对端关闭）。
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body = format!(
                    "HTTP/1.1 {status} x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = sock.write_all(body.as_bytes()).await;
            }
        });
        addr
    }

    fn config_for(hub_url: String) -> WorkerConfig {
        toml::from_str(&format!(
            "name = \"w-test\"\nhub_url = \"{hub_url}\"\ntoken = \"t\""
        ))
        .unwrap()
    }

    /// hub 已终态回 409 须映射为成功，不得烧重试预算记假失败。
    #[tokio::test]
    async fn report_result_treats_409_conflict_as_delivered() {
        let addr = spawn_status_server(409).await;
        let cfg = config_for(format!("http://{}", addr));
        let task = test_task();
        let result = BuildResult {
            phase: "succeeded".into(),
            result_dir: None,
            error: None,
            notes: None,
            resources: None,
            local_result_dir: None,
            engine_build_id: None,
            engine_result_root: None,
        };
        let outcome = report_result(&cfg, 1, &task, &result, None).await;
        assert!(outcome.is_ok(), "409 must map to success, got {outcome:?}");
    }

    /// 其余 4xx（如 404）仍是错误：只有终态语义的 409 被幂等吸收。
    #[tokio::test]
    async fn report_result_propagates_other_4xx() {
        let addr = spawn_status_server(404).await;
        let cfg = config_for(format!("http://{}", addr));
        let task = test_task();
        let result = BuildResult {
            phase: "failed".into(),
            result_dir: None,
            error: Some("boom".into()),
            notes: None,
            resources: None,
            local_result_dir: None,
            engine_build_id: None,
            engine_result_root: None,
        };
        let outcome = report_result(&cfg, 1, &task, &result, None).await;
        assert!(outcome.is_err(), "404 must stay an error, got {outcome:?}");
    }
}
