// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::path::PathBuf;

use anyhow::Result;
use crbs_core::error::CrbsError;
use reqwest::header;
use tokio_util::sync::CancellationToken;

use super::target::RemoteTarget;

/// 远程 server 返回的构建 profile 响应。
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RemoteProfileResponse {
    pub id: i64,
    pub pkg_name: String,
    pub product: String,
    pub phase: String,
    pub elapsed_secs: i64,
    pub rpms: Vec<String>,

    /// 完整 profile 本体：低版本 server 无该字段时为 `None`，CLI 降级保留
    /// 六字段布局；`skip_serializing_if` 使降级输出不出现 `"profile": null`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<crbs_core::engine::profile::BuildProfile>,
}

/// 远程 server 返回的任务取消响应。
#[derive(Debug, serde::Deserialize)]
pub struct RemoteTaskCancelResponse {
    pub task_id: i64,
    pub cancelled_build_ids: Vec<i64>,
    pub skipped_build_ids: Vec<i64>,
    pub message: String,
}

/// 远程 server 返回的任务列表响应。
#[derive(Debug, serde::Deserialize)]
struct TaskListResponse {
    tasks: Vec<crbs_core::TaskRecord>,
}

/// 远程 server 返回的任务详情响应。
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TaskDetailResponse {
    #[serde(flatten)]
    pub task: crbs_core::TaskRecord,
    pub builds: Vec<crbs_core::types::ChildBuildSummary>,

    /// 复现血缘：仅达到该功能版本的 hub 回传；低版本缺键时落 `None`（版本
    /// 偏斜防线）。
    #[serde(default)]
    pub lineage: Option<crbs_core::types::TaskLineage>,

    /// 任务标签（按键排序）；低版本 hub 缺键时落空列表。
    #[serde(default)]
    pub labels: Vec<crbs_core::types::TaskLabel>,
}

/// 清除服务器可控字符串中的终端控制序列（ESC/C0/DEL），保留 \n、\t：这些值直接打进终端，恶意 hub 可用 `\r\x1b[2K\x1b[32msucceeded` 伪造状态行。
pub(crate) fn strip_terminal_control(s: &str) -> String {
    s.chars()
        .filter(|c| matches!(*c, '\n' | '\t') || (!c.is_control() && *c != '\u{7f}'))
        .collect()
}

/// 错误回显用的 body 截断（并剥终端控制序列——错误文本直接进 stderr/日志）。
pub(crate) fn truncate_body_for_error(body: &str) -> String {
    strip_terminal_control(&body.chars().take(512).collect::<String>())
}

/// server JSON 错误信封 `{"error","message"}` 的 CLI 解析视图：`message`
/// 用于展示、`error` 用于 500 细分；解析失败或缺字段时调用方回退裸 body。
#[derive(Debug, serde::Deserialize)]
struct ServerErrorEnvelope {
    error: Option<String>,
    message: Option<String>,
}

/// 判断 500 信封是否标识数据库语义错误：首选判据为 error 串
/// "database_error"（server 对 Database 变体发送的串）；回退判据为 message
/// 精确串 "database error"（该形态下 error 串恒为 "internal_error"，只能凭
/// message 判断）。文案变更须同步两侧测试。
fn is_database_error_envelope(envelope: Option<&ServerErrorEnvelope>) -> bool {
    match envelope {
        Some(env) => {
            env.error.as_deref() == Some("database_error")
                || env.message.as_deref() == Some("database error")
        }
        None => false,
    }
}

/// 远程 HTTP 非成功状态码 → CrbsError（决定 CLI 退出码，远程与本地同条件一致：USAGE=4 / PERMISSION=5 / ENVIRONMENT=6）。
/// 401/403 → PermissionDenied、409 → Conflict、404 → NotFound、504 → Timeout、500 且信封标识数据库错误 →
/// Database（可重试）、429/其余 5xx → Network。body 进 message 前剥终端控制序列并截断（服务器数据不可信）。
pub(crate) fn http_status_error(op: &str, status: reqwest::StatusCode, body: &str) -> CrbsError {
    let envelope = serde_json::from_str::<ServerErrorEnvelope>(body).ok();
    let inner = envelope
        .as_ref()
        .and_then(|env| env.message.as_deref())
        .unwrap_or(body);
    let message = format!(
        "{}: remote server returned {}: {}",
        op,
        status,
        truncate_body_for_error(inner)
    );
    match status.as_u16() {
        401 | 403 => CrbsError::PermissionDenied { message },
        404 => CrbsError::NotFound { message },
        409 => CrbsError::Conflict { message },

        s if (400..500).contains(&s) && s != 429 => CrbsError::ValidationFailed { message },
        504 => CrbsError::Timeout,
        500 if is_database_error_envelope(envelope.as_ref()) => CrbsError::Database(message),
        _ => CrbsError::Network { message },
    }
}

/// 构建带 Bearer Token 与可选 CA 证书的 reqwest HTTP client。token
/// 非法字符属用户可修正的配置问题——ValidationFailed（USAGE=4）；总超时覆盖"连接→响应 body 读毕"全程，连接阶段单独收紧（TCP 黑洞 10s 即失败）。
pub async fn build_http_client(
    token: &Option<String>,
    ca_cert: &Option<PathBuf>,
) -> Result<reqwest::Client> {
    let mut headers = header::HeaderMap::new();
    if let Some(t) = token {
        let value = header::HeaderValue::from_str(&format!("Bearer {}", t)).map_err(|e| {
            CrbsError::ValidationFailed {
                message: format!("invalid API token: {e}"),
            }
        })?;
        headers.insert(header::AUTHORIZATION, value);
    }
    let mut builder = reqwest::Client::builder()
        .default_headers(headers)
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(300));
    if let Some(ca_path) = ca_cert {
        let ca_pem = tokio::fs::read(ca_path).await.map_err(|e| CrbsError::Io {
            context: format!("read ca cert {}", ca_path.display()),
            kind: e.kind(),
            detail: e.to_string(),
        })?;

        let cert =
            reqwest::Certificate::from_pem(&ca_pem).map_err(|e| CrbsError::ValidationFailed {
                message: format!("parse ca cert {}: {e}", ca_path.display()),
            })?;
        builder = builder.add_root_certificate(cert);
    }

    builder
        .build()
        .map_err(|e| CrbsError::ValidationFailed {
            message: format!("build HTTP client: {e}"),
        })
        .map_err(Into::into)
}

/// 最大重试次数（含首次尝试）。
const HTTP_RETRY_MAX_ATTEMPTS: u32 = 3;

/// 重试的基础退避间隔。
const HTTP_RETRY_BASE_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

/// 判断 HTTP 状态码是否可重试（方法感知）：GET/HEAD（幂等）任何 5xx；其他
/// 方法仅 500/503——502/504 是"后端可能已处理但响应丢失"的未知结局，重
/// POST 会造成重复任务/误导性 409；500 显式失败、503 未处理即拒，重试安全。
fn is_http_retryable_status(method: &reqwest::Method, status: reqwest::StatusCode) -> bool {
    if method == reqwest::Method::GET || method == reqwest::Method::HEAD {
        return status.is_server_error();
    }
    status == reqwest::StatusCode::INTERNAL_SERVER_ERROR
        || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
}

/// 传输类错误（发送失败或 body 读取失败）是否可安全重试：GET/HEAD 对任何
/// 传输错误重试；其他方法仅在连接失败（`is_connect`，请求必然未达服务端）
/// 时重试——超时或中断可能发生在"服务端已处理但响应丢失"之后，重试会造
/// 成重复任务或误导性 409。
fn should_retry_transport(method: &reqwest::Method, is_connect: bool) -> bool {
    if method == reqwest::Method::GET || method == reqwest::Method::HEAD {
        return true;
    }
    is_connect
}

/// 已读取完整 body 的 HTTP 响应：[`retry_http`] 内部完成 body 读取，读取
/// 失败也可作为传输类错误参与重试决策。
#[derive(Debug)]
pub(crate) struct HttpTextResponse {
    pub(crate) status: reqwest::StatusCode,
    pub(crate) body: String,
}

/// 通用 HTTP 重试骨架：发送 + 读 body + 重试（最多 [`HTTP_RETRY_MAX_ATTEMPTS`]
/// 次，half jitter 退避），返回状态码与 body 文本。仅 5xx 与按
/// [`should_retry_transport`] 判定的传输错误可重试，2xx/4xx 立即返回；循环
/// 骨架（计数/退避/取消/耗尽）委托 `crbs_core::http_retry::retry_with_policy`，
/// 本函数保留 CLI 策略谓词与错误上下文包装。`make_request` 每次调用产生新
/// `RequestBuilder`。取消令牌让重试发送、退避睡眠、body 读取立即让路——否则
/// CLI 装了信号处理器后 Ctrl-C 仍会跑满 3×300s。
pub(crate) async fn retry_http(
    op_name: &str,
    method: reqwest::Method,
    cancel: Option<&CancellationToken>,
    mut make_request: impl FnMut() -> reqwest::RequestBuilder,
) -> Result<HttpTextResponse> {
    use crbs_core::http_retry::{retry_with_policy, RetryBreak, RetryCause};

    enum Attempt {
        Done(HttpTextResponse),
        RetryableStatus {
            status: reqwest::StatusCode,
            body: String,
        },
    }

    enum AttemptError {
        Send { err: reqwest::Error, ctx: String },
        BodyRead { err: reqwest::Error, ctx: String },
    }

    impl AttemptError {
        fn is_connect(&self) -> bool {
            match self {
                Self::Send { err, .. } | Self::BodyRead { err, .. } => err.is_connect(),
            }
        }

        fn into_contextualized(self, op_name: &str) -> anyhow::Error {
            let message = match self {
                Self::Send { err, ctx } => format!("{op_name}: {ctx} request failed: {err}"),
                Self::BodyRead { err, ctx } => {
                    format!("{op_name}: {ctx} read response body: {err}")
                }
            };
            CrbsError::Network { message }.into()
        }
    }

    let outcome = retry_with_policy(
        HTTP_RETRY_MAX_ATTEMPTS,
        HTTP_RETRY_BASE_DELAY,
        cancel,
        |e: &AttemptError| should_retry_transport(&method, e.is_connect()),
        |v: &Attempt| matches!(v, Attempt::RetryableStatus { .. }),
        |cause, attempt, delay| match cause {
            RetryCause::Error(AttemptError::Send { err, .. }) => tracing::warn!(
                op = op_name,
                attempt,
                error = %err,
                delay_ms = delay.as_millis() as u64,
                "HTTP request failed (retryable transport error), retrying"
            ),
            RetryCause::Error(AttemptError::BodyRead { err, .. }) => tracing::warn!(
                op = op_name,
                attempt,
                error = %err,
                delay_ms = delay.as_millis() as u64,
                "HTTP response body read failed (retryable), retrying"
            ),
            RetryCause::Value(Attempt::RetryableStatus { status, body }) => tracing::warn!(
                op = op_name,
                attempt,
                status = %status,
                body = %body,
                delay_ms = delay.as_millis() as u64,
                "HTTP request failed (retryable status), retrying"
            ),
            RetryCause::Value(Attempt::Done(_)) => {}
        },
        |attempt| {
            let builder = make_request();

            let request_ctx = builder
                .try_clone()
                .and_then(|b| b.build().ok())
                .map(|r| format!("{} {}", r.method(), r.url()))
                .unwrap_or_else(|| method.to_string());
            let method = &method;
            async move {
                let resp = match builder.send().await {
                    Ok(resp) => resp,
                    Err(err) => {
                        return Err(AttemptError::Send {
                            err,
                            ctx: request_ctx,
                        })
                    }
                };
                let status = resp.status();
                if is_http_retryable_status(method, status) && attempt < HTTP_RETRY_MAX_ATTEMPTS {
                    let body = resp
                        .text()
                        .await
                        .unwrap_or_else(|e| format!("<failed to read body: {e}>"));
                    Ok(Attempt::RetryableStatus { status, body })
                } else {
                    match resp.text().await {
                        Ok(body) => Ok(Attempt::Done(HttpTextResponse { status, body })),
                        Err(err) => Err(AttemptError::BodyRead {
                            err,
                            ctx: request_ctx,
                        }),
                    }
                }
            }
        },
    )
    .await;

    match outcome {
        Ok(Attempt::Done(resp)) => Ok(resp),

        Ok(Attempt::RetryableStatus { status, .. }) => Err(CrbsError::Network {
            message: format!("{op_name}: retry budget exhausted with retryable status {status}"),
        }
        .into()),
        Err(RetryBreak::Cancelled) => Err(CrbsError::Cancelled.into()),
        Err(RetryBreak::Inner(e)) => Err(e.into_contextualized(op_name)),
    }
}

/// 通用远程 JSON API 调用骨架：经 [`retry_http`] 完成发送与重试，再做状
/// 态检查与 JSON 解析。`request_fn` 接收已带 Authorization 与 CA 证书的
/// client，每次调用产生新的 `RequestBuilder`；`not_found_msg` 为 404 特判
/// 消息（`None` 时走通用错误路径）；`cancel` 供长流程传入进程级取消令牌，
/// 短命令传 `None`。
pub(crate) async fn remote_send_json<T: serde::de::DeserializeOwned>(
    target: &RemoteTarget,
    method: reqwest::Method,
    request_fn: impl FnMut(&reqwest::Client) -> reqwest::RequestBuilder,
    not_found_msg: Option<&str>,
    cancel: Option<&CancellationToken>,
) -> Result<T> {
    let client = target.client().await?;
    let mut request_fn = request_fn;
    let resp = retry_http("remote_api", method, cancel, || request_fn(client)).await?;

    if resp.status == reqwest::StatusCode::NOT_FOUND {
        if let Some(msg) = not_found_msg {
            return Err(CrbsError::NotFound {
                message: msg.to_string(),
            }
            .into());
        }
    }
    if !resp.status.is_success() {
        return Err(http_status_error("remote_api", resp.status, &resp.body).into());
    }

    serde_json::from_str(&resp.body)
        .map_err(|e| CrbsError::Network {
            message: format!(
                "parse response: {}: {e}",
                truncate_body_for_error(&resp.body)
            ),
        })
        .map_err(Into::into)
}

/// 从远程 server 拉取任务列表；`limit` 为 `None` 时拉取全部。
pub async fn fetch_task_records(
    target: &RemoteTarget,
    product: Option<&str>,
    phase: Option<&str>,
    label: Option<(&str, &str)>,
    limit: Option<usize>,
    cancel: Option<&CancellationToken>,
) -> Result<Vec<crbs_core::TaskRecord>> {
    let url = format!("{}/api/v1/tasks", target.url);
    let p = product.map(|s| s.to_string());
    let ph = phase.map(|s| s.to_string());
    let l = label.map(|(k, v)| format!("{k}={v}"));

    let list: TaskListResponse = remote_send_json(
        target,
        reqwest::Method::GET,
        |client| {
            let mut req = client.get(&url);
            if let Some(ref prod) = p {
                req = req.query(&[("product", prod.as_str())]);
            }
            if let Some(ref phase_val) = ph {
                req = req.query(&[("phase", phase_val.as_str())]);
            }
            if let Some(ref label_val) = l {
                req = req.query(&[("label", label_val.as_str())]);
            }
            if let Some(lim) = limit {
                req = req.query(&[("limit", lim.to_string().as_str())]);
            }
            req
        },
        None,
        cancel,
    )
    .await?;
    Ok(list.tasks)
}

/// 从远程 server 拉取单条任务详情（含子构建摘要）。
pub async fn fetch_task_record(
    target: &RemoteTarget,
    id: i64,
    cancel: Option<&CancellationToken>,
) -> Result<TaskDetailResponse> {
    let url = format!("{}/api/v1/tasks/{}", target.url, id);
    let msg = format!("Task {} not found", id);
    remote_send_json(
        target,
        reqwest::Method::GET,
        |client| client.get(&url),
        Some(&msg),
        cancel,
    )
    .await
}

/// 匿名下载编排元数据（`/api/v1/public/tasks/{id}`）：仅取下载链路消费的
/// `pkg_name` 与 `builds`（serde 默认忽略多余 JSON 键），服务端已脱敏（无
/// result_dir/user/error_summary，builds 的敏感字段为 null）。
#[derive(Debug, serde::Deserialize)]
pub struct PublicDownloadInfo {
    pub pkg_name: String,
    pub builds: Vec<crbs_core::types::ChildBuildSummary>,
}

/// 获取无 token profile 的下载元数据（匿名受限端点，限公开产品；门控在
/// 服务端）。
pub async fn fetch_public_download_info(
    target: &RemoteTarget,
    id: i64,
    cancel: Option<&CancellationToken>,
) -> Result<PublicDownloadInfo> {
    let url = format!("{}/api/v1/public/tasks/{}", target.url, id);
    let msg = format!("Task {} not found", id);
    remote_send_json(
        target,
        reqwest::Method::GET,
        |client| client.get(&url),
        Some(&msg),
        cancel,
    )
    .await
}

/// 匿名受限制品清单（`/api/v1/public/builds/{id}/artifacts`），响应结构
/// 与受保护版本相同。
pub async fn list_artifacts_public(
    target: &RemoteTarget,
    id: i64,
    cancel: Option<&CancellationToken>,
) -> Result<ArtifactsResponse> {
    let url = format!("{}/api/v1/public/builds/{}/artifacts", target.url, id);
    remote_send_json(
        target,
        reqwest::Method::GET,
        |client| client.get(&url),
        None,
        cancel,
    )
    .await
}

/// 从远程 server 拉取构建 profile。
pub async fn fetch_build_profile(target: &RemoteTarget, id: i64) -> Result<RemoteProfileResponse> {
    let url = format!("{}/api/v1/builds/{}/profile", target.url, id);
    let msg = format!("Build task {} profile not found", id);
    remote_send_json(
        target,
        reqwest::Method::GET,
        |client| client.get(&url),
        Some(&msg),
        None,
    )
    .await
}

/// 向远程 server 发送任务取消请求。
pub async fn cancel_task(target: &RemoteTarget, id: i64) -> Result<RemoteTaskCancelResponse> {
    let url = format!("{}/api/v1/tasks/{}/cancel", target.url, id);
    let msg = format!("Task {} not found", id);
    remote_send_json(
        target,
        reqwest::Method::POST,
        |client| client.post(&url),
        Some(&msg),
        None,
    )
    .await
}

/// 重建已提交的任务：服务端以留存的源码与记录选项重新入队，返回新任务。
pub async fn rebuild_task(
    target: &RemoteTarget,
    id: i64,
    cancel: Option<&CancellationToken>,
) -> Result<crate::cmd::build::remote::BuildResponse> {
    let url = format!("{}/api/v1/tasks/{}/rebuild", target.url, id);
    let msg = format!("Task {} not found", id);
    remote_send_json(
        target,
        reqwest::Method::POST,
        |client| client.post(&url),
        Some(&msg),
        cancel,
    )
    .await
}

/// 产物清单响应。
#[derive(Debug, serde::Deserialize)]
pub struct ArtifactsResponse {
    pub rpms: Vec<String>,
    pub srpms: Vec<String>,
    pub other: Vec<String>,
}

/// 复现已提交的任务：服务端在锁定的依赖快照下重建各 arch 子构建，返回新
/// 任务。
pub async fn reproduce_task(
    target: &RemoteTarget,
    id: i64,
    cancel: Option<&CancellationToken>,
) -> Result<crate::cmd::build::remote::BuildResponse> {
    let url = format!("{}/api/v1/tasks/{}/reproduce", target.url, id);
    let msg = format!("Task {} not found", id);
    remote_send_json(
        target,
        reqwest::Method::POST,
        |client| client.post(&url),
        Some(&msg),
        cancel,
    )
    .await
}

/// 从远程 server 拉取构建产物清单。
pub async fn list_artifacts(
    target: &RemoteTarget,
    id: i64,
    cancel: Option<&CancellationToken>,
) -> Result<ArtifactsResponse> {
    let url = format!("{}/api/v1/builds/{}/artifacts", target.url, id);
    remote_send_json(
        target,
        reqwest::Method::GET,
        |client| client.get(&url),
        None,
        cancel,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetch_public_download_info_hits_public_path() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/public/tasks/7"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 7,
                "product": "mydist",
                "pkg_name": "pkg",
                "phase": "succeeded",
                "builds": [
                    {"id": 8, "arch": "x86_64", "phase": "succeeded",
                     "result_dir": null, "started_at": null, "duration": null}
                ]
            })))
            .mount(&server)
            .await;

        let target = RemoteTarget::new(server.uri(), None, None);
        assert!(target.token.is_none(), "precondition: tokenless profile");
        let info = fetch_public_download_info(&target, 7, None)
            .await
            .expect("public info should parse");
        assert_eq!(info.pkg_name, "pkg");
        assert_eq!(info.builds.len(), 1);
        assert_eq!(info.builds[0].arch, "x86_64");
    }

    #[tokio::test]
    async fn invalid_api_token_maps_to_validation_failed_exit_4() {
        use crbs_core::exit_code::{crbs_error_exit_code, USAGE};

        let err = build_http_client(&Some("tok\nen".to_string()), &None)
            .await
            .expect_err("control char in token must fail header parse");
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::ValidationFailed { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_error_exit_code(ce), USAGE);
        assert!(
            format!("{ce}").starts_with("validation failed: invalid API token: "),
            "context-chain text must be preserved after the variant prefix: {ce}"
        );
    }

    #[tokio::test]
    async fn unparseable_ca_cert_maps_to_validation_failed_exit_4() {
        use crbs_core::exit_code::{crbs_error_exit_code, USAGE};

        let tmp = tempfile::tempdir().expect("tempdir");
        let ca_path = tmp.path().join("ca.pem");
        std::fs::write(
            &ca_path,
            b"-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
        )
        .expect("write malformed ca pem");

        let err = build_http_client(&None, &Some(ca_path))
            .await
            .expect_err("malformed PEM body must fail client build");
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::ValidationFailed { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_error_exit_code(ce), USAGE);
        assert!(
            format!("{ce}").starts_with("validation failed: build HTTP client: "),
            "original context text must be preserved after the variant prefix: {ce}"
        );
    }

    #[tokio::test]
    async fn remote_send_json_unparseable_response_maps_to_network_exit_6() {
        use crbs_core::exit_code::{crbs_error_exit_code, ENVIRONMENT};
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/tasks"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>not json</html>"))
            .mount(&server)
            .await;

        let target = RemoteTarget::new(server.uri(), None, None);
        let err: anyhow::Error = remote_send_json::<TaskListResponse>(
            &target,
            reqwest::Method::GET,
            |client| client.get(format!("{}/api/v1/tasks", target.url)),
            None,
            None,
        )
        .await
        .expect_err("non-JSON body must fail parsing");
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::Network { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
        assert!(
            format!("{ce}").starts_with("network error: parse response: "),
            "original context text must be preserved after the variant prefix: {ce}"
        );
    }

    #[tokio::test]
    async fn remote_send_json_parse_error_body_sanitized_and_truncated() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        let body = format!("\x1b[2J<html>{}</html>", "x".repeat(4096));
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/tasks"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let target = RemoteTarget::new(server.uri(), None, None);
        let err: anyhow::Error = remote_send_json::<TaskListResponse>(
            &target,
            reqwest::Method::GET,
            |client| client.get(format!("{}/api/v1/tasks", target.url)),
            None,
            None,
        )
        .await
        .expect_err("non-JSON body must fail parsing");
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        let CrbsError::Network { message } = ce else {
            panic!("unexpected variant: {ce}")
        };
        assert!(
            !message.contains('\x1b'),
            "terminal control sequences must be stripped: {message:?}"
        );
        assert!(
            message.len() < 1024,
            "body contribution must be bounded (prefix + serde error + ≤512 body chars): {} bytes",
            message.len()
        );
    }
}

#[cfg(test)]
mod retry_tests {
    use super::{retry_http, should_retry_transport};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[test]
    fn transport_retry_matrix() {
        let get = reqwest::Method::GET;
        let head = reqwest::Method::HEAD;
        let post = reqwest::Method::POST;
        let put = reqwest::Method::PUT;
        let delete = reqwest::Method::DELETE;

        assert!(should_retry_transport(&get, false));
        assert!(should_retry_transport(&get, true));
        assert!(should_retry_transport(&head, false));
        assert!(should_retry_transport(&post, true));
        assert!(!should_retry_transport(&post, false));
        assert!(should_retry_transport(&put, true));
        assert!(!should_retry_transport(&put, false));
        assert!(should_retry_transport(&delete, true));
        assert!(!should_retry_transport(&delete, false));
    }

    #[tokio::test]
    async fn retry_http_post_timeout_fails_without_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connects = Arc::new(AtomicU32::new(0));
        let counter = connects.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                counter.fetch_add(1, Ordering::Relaxed);

                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf).await;
            }
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        let url = format!("http://{addr}/api/v1/tasks/1/rebuild");

        let started = Instant::now();
        let result = retry_http("test_rebuild", reqwest::Method::POST, None, || {
            client.post(&url)
        })
        .await;
        assert!(result.is_err(), "POST timeout should fail, got {result:?}");

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "should fail fast, took {:?}",
            started.elapsed()
        );

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            connects.load(Ordering::Relaxed),
            1,
            "POST timeout must not be retried"
        );
        server.abort();
    }

    #[tokio::test]
    async fn retry_http_transport_error_maps_to_network_exit_6() {
        use crbs_core::exit_code::{crbs_error_exit_code, ENVIRONMENT};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf).await;
            }
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        let url = format!("http://{addr}/api/v1/tasks/1/rebuild");

        let err = retry_http("test_rebuild", reqwest::Method::POST, None, || {
            client.post(&url)
        })
        .await
        .expect_err("black-holed POST must fail");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::Network { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
        let msg = format!("{ce}");
        assert!(
            msg.starts_with("network error: test_rebuild: POST http://"),
            "original context format (op + METHOD url + request failed) must be preserved \
             after the variant prefix: {msg}"
        );
        assert!(
            msg.contains("request failed"),
            "transport failure phrase must remain: {msg}"
        );
        server.abort();
    }

    #[test]
    fn status_retry_matrix() {
        use super::is_http_retryable_status;
        let get = reqwest::Method::GET;
        let post = reqwest::Method::POST;
        let s = |code: u16| reqwest::StatusCode::from_u16(code).unwrap();

        for code in [500, 502, 503, 504] {
            assert!(is_http_retryable_status(&get, s(code)), "GET {code}");
        }
        assert!(!is_http_retryable_status(&get, s(404)));
        assert!(!is_http_retryable_status(&get, s(429)));

        assert!(is_http_retryable_status(&post, s(500)));
        assert!(is_http_retryable_status(&post, s(503)));
        assert!(!is_http_retryable_status(&post, s(502)), "502 = 未知结局");
        assert!(!is_http_retryable_status(&post, s(504)), "504 = 未知结局");
    }
}

#[cfg(test)]
mod http_status_error_tests {

    use super::http_status_error;
    use crbs_core::error::CrbsError;
    use crbs_core::exit_code::{crbs_error_exit_code, ENVIRONMENT, INTERRUPTED, PERMISSION, USAGE};

    fn status(code: u16) -> reqwest::StatusCode {
        reqwest::StatusCode::from_u16(code).unwrap()
    }

    fn variant_of(code: u16) -> CrbsError {
        http_status_error("test_op", status(code), "boom")
    }

    #[test]
    fn maps_4xx_5xx_to_contract_variants() {
        for code in [400, 405, 422] {
            assert!(
                matches!(variant_of(code), CrbsError::ValidationFailed { .. }),
                "{code}"
            );
            assert_eq!(crbs_error_exit_code(&variant_of(code)), USAGE, "{code}");
        }
        for code in [401, 403] {
            assert!(
                matches!(variant_of(code), CrbsError::PermissionDenied { .. }),
                "{code}"
            );
            assert_eq!(
                crbs_error_exit_code(&variant_of(code)),
                PERMISSION,
                "{code}"
            );
        }
        assert!(matches!(variant_of(404), CrbsError::NotFound { .. }));
        assert_eq!(crbs_error_exit_code(&variant_of(404)), USAGE);
        assert!(matches!(variant_of(409), CrbsError::Conflict { .. }));
        assert_eq!(crbs_error_exit_code(&variant_of(409)), USAGE);
        for code in [429, 500, 502, 503] {
            assert!(
                matches!(variant_of(code), CrbsError::Network { .. }),
                "{code}"
            );
            assert_eq!(
                crbs_error_exit_code(&variant_of(code)),
                ENVIRONMENT,
                "{code}"
            );
        }
    }

    #[test]
    fn sanitizes_and_truncates_body() {
        let hostile = format!("{}\r\x1b[2K\x1b[32mfake-ok", "A".repeat(600));
        let err = http_status_error("test_op", status(500), &hostile);
        let CrbsError::Network { message } = err else {
            panic!("expected Network");
        };
        assert!(
            !message.contains('\x1b'),
            "ESC must be stripped: {message:?}"
        );
        assert!(!message.contains('\r'), "CR must be stripped: {message:?}");

        assert!(message.chars().count() < 600, "expected truncation");
        assert!(message.contains("test_op"), "op context missing: {message}");
        assert!(message.contains("500"), "status missing: {message}");
    }

    #[test]
    fn parses_server_envelope_message_and_falls_back_to_raw_body() {
        let err = http_status_error(
            "test_op",
            status(404),
            r#"{"error":"not_found","message":"build 42 not found"}"#,
        );
        let CrbsError::NotFound { message } = err else {
            panic!("expected NotFound");
        };
        assert!(message.contains("build 42 not found"), "{message}");
        assert!(
            !message.contains("{\"error\""),
            "envelope noise must not leak: {message}"
        );

        let err = http_status_error("test_op", status(502), "<html>bad gateway</html>");
        let CrbsError::Network { message } = err else {
            panic!("expected Network");
        };
        assert!(message.contains("<html>bad gateway</html>"), "{message}");
    }

    #[test]
    fn maps_500_database_envelope_to_database() {
        let err = http_status_error(
            "test_op",
            status(500),
            r#"{"error":"internal_error","message":"database error"}"#,
        );
        assert!(matches!(err, CrbsError::Database(_)));
        assert_eq!(crbs_error_exit_code(&err), ENVIRONMENT);

        let err = http_status_error(
            "test_op",
            status(500),
            r#"{"error":"database_error","message":"whatever"}"#,
        );
        assert!(matches!(err, CrbsError::Database(_)));

        let err = http_status_error(
            "test_op",
            status(500),
            r#"{"error":"internal_error","message":"internal error"}"#,
        );
        assert!(matches!(err, CrbsError::Network { .. }));
        let err = http_status_error("test_op", status(500), "database error plain text");
        assert!(matches!(err, CrbsError::Network { .. }));
    }

    #[test]
    fn maps_504_to_timeout() {
        let err = variant_of(504);
        assert!(matches!(err, CrbsError::Timeout));
        assert_eq!(crbs_error_exit_code(&err), INTERRUPTED);
        for code in [502, 503] {
            assert!(
                matches!(variant_of(code), CrbsError::Network { .. }),
                "{code}"
            );
        }
    }
}
