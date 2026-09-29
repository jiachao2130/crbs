// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建结果上报。

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::info;

use crbs_core::error::CrbsError;

use crate::config::WorkerConfig;
use crate::poller::AssignedTask;
use crate::retry::{retry_with_backoff, retry_with_timeout, wait_for_cancel, REQUEST_TIMEOUT};

use super::ensure_not_cancelled;

#[derive(Debug)]
/// 构建结果终态载荷。notes 与 resources 进 JSON payload；local_result_dir /
/// engine_build_id / engine_result_root 仅 worker 本地使用（上报失败时定位产物、
/// 上报成功后删除本地产物的命名空间断言），不进 payload。
pub struct BuildResult {
    pub phase: String,
    pub result_dir: Option<String>,
    pub error: Option<String>,

    pub notes: Option<String>,

    pub resources: Option<crbs_core::engine::ResourceUsage>,

    pub local_result_dir: Option<std::path::PathBuf>,

    pub engine_build_id: Option<i64>,

    pub engine_result_root: Option<std::path::PathBuf>,
}

impl BuildResult {
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

/// 向 Hub 上报任务结果。契约：入口对已取消令牌直接返回 Cancelled；终态上报必须
/// 传未取消令牌——shutdown 取消后终态仍须送达，poller 补报持独立 report_token。
pub async fn report_result(
    cfg: &WorkerConfig,
    worker_id: i64,
    task: &AssignedTask,
    result: &BuildResult,
    cancel_token: Option<&CancellationToken>,
) -> crbs_core::Result<()> {
    report_result_with_timeout(cfg, worker_id, task, result, cancel_token, REQUEST_TIMEOUT).await
}

/// report_result 的可注入单次尝试超时版本：取消路径与失败补报传短超时，drain
/// 窗口内完不成即放弃（hub 240s reclaimer 仍会回收），不吃默认 30s×3≈93s 的最坏
/// 重试链（会被进程退出截断）。其余契约同 report_result。
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

            if status == reqwest::StatusCode::CONFLICT {
                // 幂等 409：assignment 已在 hub 落终态（重试重放或 hub 并发写终态），
                // 按"已达终态"成功处理——否则重试层烧完预算会把已完成构建记成假失败。
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

    async fn spawn_status_server(status: u16) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            if let Ok((mut sock, _)) = listener.accept().await {
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
