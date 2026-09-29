// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! HTTP client 构造、重试骨架、状态码 → 错误映射与远程 JSON API 包装。

use std::path::PathBuf;

use anyhow::Result;
use crbs_core::error::CrbsError;
use reqwest::header;
use tokio_util::sync::CancellationToken;

use super::target::RemoteTarget;

/// 远程 server 返回的 profile 响应。
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RemoteProfileResponse {
    pub id: i64,
    pub pkg_name: String,
    pub product: String,
    pub phase: String,
    pub elapsed_secs: i64,
    pub rpms: Vec<String>,
    /// 完整 profile 本体：旧 server 无该字段 → None，CLI 降级保留六字段
    /// 布局；`skip_serializing_if` 让降级输出不冒出 `"profile": null`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<crbs_core::engine::profile::BuildProfile>,
}

/// 远程 server 返回的任务 cancel 响应。
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
    /// hub ≥ 此版本回传复现血缘；旧 hub 缺键落 None（版本偏斜防线）。
    #[serde(default)]
    pub lineage: Option<crbs_core::types::TaskLineage>,
    /// 任务标签（按键排序）；旧 hub 缺键落空列表。
    #[serde(default)]
    pub labels: Vec<crbs_core::types::TaskLabel>,
}

/// 清除服务器可控字符串中的终端控制序列（ESC/C0/DEL），保留 \n、\t：这些值
/// 直接打进终端，恶意 hub 可用 `\r\x1b[2K\x1b[32msucceeded` 伪造状态行。
pub(crate) fn strip_terminal_control(s: &str) -> String {
    s.chars()
        .filter(|c| matches!(*c, '\n' | '\t') || (!c.is_control() && *c != '\u{7f}'))
        .collect()
}

/// 错误回显用的 body 截断（并剥终端控制序列——错误文本直接进 stderr/日志）；
/// pub(crate) 供 CLI 各处 parse 错误回显 body 前统一净化。
pub(crate) fn truncate_body_for_error(body: &str) -> String {
    strip_terminal_control(&body.chars().take(512).collect::<String>())
}

/// server JSON 错误信封 `{"error","message"}` 的 CLI 解析视图：读 `message`
/// 供展示、`error` 供 500 细分；解析失败或缺字段时调用方回退裸 body。
#[derive(Debug, serde::Deserialize)]
struct ServerErrorEnvelope {
    error: Option<String>,
    message: Option<String>,
}

/// 500 信封是否标识数据库语义错误：首选判据 error 串 "database_error"
///（当前 server 对 Database 变体发的串）；回退判据 message 精确串
/// "database error"（兼容形态：error 串恒 "internal_error"，
/// 只能判 message）。文案变更须同步两侧测试。
fn is_database_error_envelope(envelope: Option<&ServerErrorEnvelope>) -> bool {
    match envelope {
        Some(env) => {
            env.error.as_deref() == Some("database_error")
                || env.message.as_deref() == Some("database error")
        }
        None => false,
    }
}

/// 远程 HTTP 非成功状态码 → [`CrbsError`]（决定 CLI 退出码，远程与本地同条件
/// 一致：USAGE=4 / PERMISSION=5 / ENVIRONMENT=6）。401/403 → PermissionDenied、
/// 409 → Conflict、其余 4xx → ValidationFailed；非显然臂：404 → NotFound（不
/// 照抄 worker 侧 404→ValidationFailed，`--format json` 信封 `code()` 随变体
/// 变化）；504 → Timeout（INTERRUPTED=3，sign API 以网关超时表签名超时；变体
/// 无 message 字段，内层 message 丢弃）；500 且信封标识数据库错误 → Database
///（可重试）；429 / 其余 5xx / 异常状态 → Network（远程 5xx 先按环境类，不归
/// Internal=1）。`body` 进 message 前剥终端控制序列并截断 512 字符（服务器
/// 数据不可信）；先解信封内层 `message` 展示，非信封 body 回退裸 body。
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
        // 429 是限流（瞬时、可重试），归 Network 而非用户可修正的 ValidationFailed。
        s if (400..500).contains(&s) && s != 429 => CrbsError::ValidationFailed { message },
        504 => CrbsError::Timeout,
        500 if is_database_error_envelope(envelope.as_ref()) => CrbsError::Database(message),
        _ => CrbsError::Network { message },
    }
}

/// 构建带 Bearer Token 与可选 CA 证书的 reqwest HTTP client。
pub async fn build_http_client(
    token: &Option<String>,
    ca_cert: &Option<PathBuf>,
) -> Result<reqwest::Client> {
    let mut headers = header::HeaderMap::new();
    if let Some(t) = token {
        // token 来自用户配置，非法字符致 HeaderValue 解析失败属用户可修正的
        // 配置值问题——ValidationFailed（USAGE=4）；消息保留原 context 链文本。
        let value = header::HeaderValue::from_str(&format!("Bearer {}", t)).map_err(|e| {
            CrbsError::ValidationFailed {
                message: format!("invalid API token: {e}"),
            }
        })?;
        headers.insert(header::AUTHORIZATION, value);
    }
    let mut builder = reqwest::Client::builder()
        .default_headers(headers)
        // 总超时覆盖"连接→响应 body 读毕"全程；连接阶段单独收紧，TCP 黑洞
        // （对端不 RST 不回包）时 10s 即失败而不是吃满总超时。
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(300));
    if let Some(ca_path) = ca_cert {
        // CA 证书文件读不出属本地环境故障——Io（kind 保真，ENVIRONMENT=6）。
        let ca_pem = tokio::fs::read(ca_path).await.map_err(|e| CrbsError::Io {
            context: format!("read ca cert {}", ca_path.display()),
            kind: e.kind(),
            detail: e.to_string(),
        })?;
        // 证书内容非 PEM 属用户配置值问题——ValidationFailed（USAGE=4），同
        // invalid API token 臂口径（归 Network 会误导"检查网络"排障方向）。
        // 取舍：rustls 把 PEM 解析失败推迟到 build() 才报，本臂当前后端
        // 近乎不可达（防御严格后端），测试以 build() 失败为触发点。
        let cert =
            reqwest::Certificate::from_pem(&ca_pem).map_err(|e| CrbsError::ValidationFailed {
                message: format!("parse ca cert {}: {e}", ca_path.display()),
            })?;
        builder = builder.add_root_certificate(cert);
    }
    // build() 失败源几乎只有刚加入的 CA 证书内容（rustls 把 PEM 解析失败
    // 推迟到此处才报）——用户可修正的配置值问题，ValidationFailed（USAGE=4），
    // 同上两臂口径。
    builder
        .build()
        .map_err(|e| CrbsError::ValidationFailed {
            message: format!("build HTTP client: {e}"),
        })
        .map_err(Into::into)
}

/// 最大重试次数（含首次尝试）。
const HTTP_RETRY_MAX_ATTEMPTS: u32 = 3;
/// 重试基础退避间隔。
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

/// 传输类错误（发送失败 / body 读取失败）是否可安全重试：GET/HEAD 任何传输
/// 错误；其他方法仅连接失败（`is_connect`，请求必然未达服务端）——超时/中断
/// 可能发生在"服务端已处理但响应丢失"之后，重试造成重复任务或误导性 409。
fn should_retry_transport(method: &reqwest::Method, is_connect: bool) -> bool {
    if method == reqwest::Method::GET || method == reqwest::Method::HEAD {
        return true;
    }
    is_connect
}

/// 已读取完整 body 的 HTTP 响应：[`retry_http`] 内部完成 body 读取，读取
/// 失败也能作为传输类错误参与重试决策。
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

    /// 单次尝试产物：终态响应，或可重试状态码（5xx）藏在成功值里的重试信号
    ///（core 值谓词路径；耗尽时工厂走终态分支返回 `Done`）。
    enum Attempt {
        Done(HttpTextResponse),
        RetryableStatus {
            status: reqwest::StatusCode,
            body: String,
        },
    }

    /// 单次尝试的传输类错误：send 失败或终态 body 读取失败，
    /// 携带错误上下文 "METHOD url" 供终态包装。
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

        /// 终态错误包装：传输失败属环境域——Network（ENVIRONMENT=6）；
        /// message 格式 "{op}: {ctx} request failed/read response body" 钉死。
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
        // 尝试工厂入参为 attempt 序号（1 起）：最后一次尝试对可重试状态码走
        // 终态分支（body 读取失败按传输错误处理）。
        |attempt| {
            let builder = make_request();
            // 错误上下文 "METHOD url"；不可克隆请求（multipart 流 body）退化为仅 method。
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
                    // 5xx 重试；body 读取失败只降级日志文本（状态码已决定重试）。
                    let body = resp
                        .text()
                        .await
                        .unwrap_or_else(|e| format!("<failed to read body: {e}>"));
                    Ok(Attempt::RetryableStatus { status, body })
                } else {
                    // 终态（2xx / 4xx / 耗尽的 5xx）：body 读取失败按传输错误参与重试。
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
        // 理论不可达（值重试仅在 attempt < MAX 时产生），兜底报错而非 panic：
        // 预算耗尽 = 远端持续不可用——Network（ENVIRONMENT=6）。
        Ok(Attempt::RetryableStatus { status, .. }) => Err(CrbsError::Network {
            message: format!("{op_name}: retry budget exhausted with retryable status {status}"),
        }
        .into()),
        Err(RetryBreak::Cancelled) => Err(CrbsError::Cancelled.into()),
        Err(RetryBreak::Inner(e)) => Err(e.into_contextualized(op_name)),
    }
}

/// 通用远程 JSON API 骨架：[`retry_http`] 发送重试 + 状态检查 + JSON 解析。
/// `request_fn` 接收已带 Authorization / CA 证书的 client，每次调用产生新
/// `RequestBuilder`；`not_found_msg` 为 404 特判消息（`None` 走通用错误）；
/// `cancel`：长流程传进程级信号令牌，短命令传 `None`。
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
            // 404 特判消息保持原文案，仅换 NotFound 变体承载（USAGE=4）。
            return Err(CrbsError::NotFound {
                message: msg.to_string(),
            }
            .into());
        }
    }
    if !resp.status.is_success() {
        return Err(http_status_error("remote_api", resp.status, &resp.body).into());
    }
    // 对端响应不可解（serde 错误）属环境域——Network（ENVIRONMENT=6）；
    // message 含净化截断后的 body（同 http_status_error 口径）。
    serde_json::from_str(&resp.body)
        .map_err(|e| CrbsError::Network {
            message: format!(
                "parse response: {}: {e}",
                truncate_body_for_error(&resp.body)
            ),
        })
        .map_err(Into::into)
}

/// 从远程 server 拉取任务列表（`limit` 为 `None` 时拉取全部）。
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
/// pkg_name 与 builds（serde 默认忽略多余 JSON 键），服务端已脱敏（无
/// result_dir/user/error_summary，builds 的敏感字段为 null）。
#[derive(Debug, serde::Deserialize)]
pub struct PublicDownloadInfo {
    pub pkg_name: String,
    pub builds: Vec<crbs_core::types::ChildBuildSummary>,
}

/// 无 token profile 的下载元数据获取（匿名受限端点，公开产品；门控在服务端）。
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

/// 匿名受限制品清单（`/api/v1/public/builds/{id}/artifacts`），响应同 protected 版。
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

/// 重建已提交的任务：服务端用留存源码与记录选项重新入队，返回新 task。
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

/// 产物列表响应。
#[derive(Debug, serde::Deserialize)]
pub struct ArtifactsResponse {
    pub rpms: Vec<String>,
    pub srpms: Vec<String>,
    pub other: Vec<String>,
}

/// 复现已提交的任务：服务端在锁定的依赖快照下重建各 arch 子构建，返回新 task。
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

/// 从远程 server 拉取构建产物列表。
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

    /// 无 token profile 的匿名下载元数据：命中 public 路径且响应可解析
    /// （端点选择分支的路径契约钉住）。
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

    /// API token 含非法字符（用户配置）→ ValidationFailed（USAGE=4）；变体 +
    /// 退出码 + 原文案三形态钉住。
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

    /// CA 证书内容损坏 → ValidationFailed（USAGE=4）；变体 + 退出码 + 原
    /// context 串三形态钉住。触发点：rustls 把 PEM 解析失败推迟到 build()
    /// 才报（from_pem 对垃圾输入返回 Ok），故用合法 PEM 结构 + 非法 DER
    /// body（Zm9v = "foo"）让 build() 确定性失败。
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

    /// 200 + 非 JSON body（serde 错误）→ Network（ENVIRONMENT=6）；变体 +
    /// 退出码 + 原 context 串三形态钉住（wiremock）。
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

    /// parse 错误 message 的 body 经净化截断（剥终端控制序列 + 512 上限，对齐
    /// http_status_error 口径）——恶意 hub 响应不原样进 stderr/日志。变体与
    /// 退出码由既有短 body 用例钉住，本变体钉净化与截断。
    #[tokio::test]
    async fn remote_send_json_parse_error_body_sanitized_and_truncated() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // \x1b[2J（清屏序列）+ 超长填充（>512 字符）迫使净化与截断双双生效：
        // 不截断时 message 会超过 4K，截断后 body 侧贡献 ≤512 字符。
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

    /// 传输错误重试决策矩阵。回归：非幂等方法在超时/中断（is_connect ==
    /// false，请求可能已达服务端）时不得重试，否则会造成重复任务或误导性 409。
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

    /// 行为测试：POST 在非连接失败的传输错误时不得重试。mock 服务端 accept
    /// 后立即关闭连接，客户端收到连接关闭错误（即时返回，非 200ms 超时臂）；
    /// 断言只发起 1 个连接且快速失败（若重试则 3 次尝试 + 秒级退避）。
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
                // accept 后即弃：sock 迭代尾 drop 即关连接（非 connect 失败，Send 臂）。
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

        // 不可重试 → 单次尝试即返回，不会出现 3 次尝试 + 退避的秒级耗时。
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "should fail fast, took {:?}",
            started.elapsed()
        );

        // 给可能（不该出现的）重试连接一点时间后断言只连过一次。
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            connects.load(Ordering::Relaxed),
            1,
            "POST timeout must not be retried"
        );
        server.abort();
    }

    /// 终态传输错误 → Network（ENVIRONMENT=6）；变体 + 退出码 + 原上下文格式
    /// 三形态钉住（mock 同上：accept 后立即关连接，POST 非连接失败单次即败）。
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
                // accept 后即弃：sock 迭代尾 drop 即关连接（非 connect 失败，Send 臂，非超时）。
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

    /// 状态码重试决策矩阵（方法感知）。回归：非幂等方法对 502/504（网关丢失
    /// 响应，服务端可能已处理）不得按状态码重试——重 POST 造成重复任务。
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
    //! 远程 HTTP 错误状态 → CrbsError 变体 → 退出码契约（4/5/6）。
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

    /// body 进 message 前剥终端控制序列并截断 512 字符（服务器数据不可信）。
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
        // 512 截断 + op/status 前缀：消息不会无限放大服务器响应体。
        assert!(message.chars().count() < 600, "expected truncation");
        assert!(message.contains("test_op"), "op context missing: {message}");
        assert!(message.contains("500"), "status missing: {message}");
    }

    /// server JSON 信封解出内层 message 展示（避免双层 JSON 噪声）；
    /// 非信封 body（反代等）回退裸 body。
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

    /// 500 + 数据库信封 → Database（ENVIRONMENT=6 可重试），与
    /// 服务端 bug 区分；非数据库信封 / 裸 body 的 500 保持 Network。
    #[test]
    fn maps_500_database_envelope_to_database() {
        // 兼容形态：error 串恒 "internal_error"，只能判 message 精确串；
        // 另一形态直接发 "database_error"（下一断言覆盖）。
        let err = http_status_error(
            "test_op",
            status(500),
            r#"{"error":"internal_error","message":"database error"}"#,
        );
        assert!(matches!(err, CrbsError::Database(_)));
        assert_eq!(crbs_error_exit_code(&err), ENVIRONMENT);

        // 当前 server 形态：独立 error 串 "database_error"（首选判据）。
        let err = http_status_error(
            "test_op",
            status(500),
            r#"{"error":"database_error","message":"whatever"}"#,
        );
        assert!(matches!(err, CrbsError::Database(_)));

        // 负例：普通 server bug 信封与裸 body 的 500 仍 Network。
        let err = http_status_error(
            "test_op",
            status(500),
            r#"{"error":"internal_error","message":"internal error"}"#,
        );
        assert!(matches!(err, CrbsError::Network { .. }));
        let err = http_status_error("test_op", status(500), "database error plain text");
        assert!(matches!(err, CrbsError::Network { .. }));
    }

    /// 504（sign API 有意以网关超时表签名超时）→ Timeout
    /// （INTERRUPTED=3）而非 Network（6）；502/503 维持 Network。
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
