// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! API 错误类型与 HTTP 状态码映射。
//!
//! 契约：axum extractor 拒绝（Query/Path/Json 反序列化失败）保持原生
//! text/plain 不套 JSON 信封，仅 handler 内部错误走 JSON 信封。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use crbs_core::error::CrbsError;
use serde::Serialize;

#[derive(Debug)]
pub(crate) enum ApiError {
    Validation(String),
    NotFound(String),
    Conflict(String),
    PermissionDenied(String),
    Unauthorized(String),
    TooManyRequests(String),
    ServiceUnavailable(String),
    GatewayTimeout(String),
    PayloadTooLarge(String),
    Internal(String),
    Database(String),
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match self {
            ApiError::Validation(msg) => (StatusCode::BAD_REQUEST, "validation_failed", msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg),
            ApiError::PermissionDenied(msg) => (StatusCode::FORBIDDEN, "permission_denied", msg),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "unauthorized", msg),
            ApiError::TooManyRequests(msg) => {
                (StatusCode::TOO_MANY_REQUESTS, "too_many_requests", msg)
            }
            ApiError::ServiceUnavailable(msg) => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable", msg)
            }
            ApiError::GatewayTimeout(msg) => (StatusCode::GATEWAY_TIMEOUT, "gateway_timeout", msg),
            ApiError::PayloadTooLarge(msg) => {
                (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", msg)
            }
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", msg),
            ApiError::Database(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "database_error", msg),
        };
        (
            status,
            Json(ErrorResponse {
                error: error_code.into(),
                message,
            }),
        )
            .into_response()
    }
}

impl From<CrbsError> for ApiError {
    fn from(e: CrbsError) -> Self {
        // 信封粒度契约：25 个 core `code()` 有意坍缩为 11 个信封 error 串，不回传
        // core code；CLI `http_status_error` 按状态码 + 信封 error/message 还原
        // 语义。坍缩即契约，调整需评审（逐臂映射见下）。
        match e {
            CrbsError::ValidationFailed { message }
            | CrbsError::ReproduceVerificationFailed { message }
            | CrbsError::DepsolveFailed { message } => ApiError::Validation(message),
            CrbsError::ProductChainInvalid { product, reason } => {
                ApiError::Validation(format!("product chain invalid: {}: {}", product, reason))
            }
            CrbsError::ProductChainCycle { chain } => {
                ApiError::Validation(format!("product chain cycle: {:?}", chain))
            }
            CrbsError::ProductChainTooDeep { max } => {
                ApiError::Validation(format!("product chain too deep: max {}", max))
            }
            CrbsError::PermissionDenied { message } => ApiError::PermissionDenied(message),
            // 防御臂：Timeout / Cancelled 由 worker 产出，server 无构造点
            //（hub-local Err 臂只 warn 不经 HTTP），仅对假想泄漏兜底。
            CrbsError::Cancelled => ApiError::Conflict("build cancelled".into()),
            CrbsError::Timeout => ApiError::GatewayTimeout("build timed out".into()),
            CrbsError::Network { .. } => ApiError::ServiceUnavailable(e.safe_message()),
            // 池不可用（acquire 超时 / DB 不可达）是服务端依赖问题而非请求
            // 错误：503 固定文案促退避重试，不当 500 泄露内部细节。
            CrbsError::DatabaseUnavailable { .. } => {
                ApiError::ServiceUnavailable("database unavailable".into())
            }
            CrbsError::NotFound { message } => ApiError::NotFound(message),
            CrbsError::LayerNotFound { digest } => {
                ApiError::NotFound(format!("shared layer {digest} not found"))
            }
            CrbsError::RevisionConflict { expected, current } => ApiError::Conflict(format!(
                "revision conflict: expected {}, current {}",
                expected, current
            )),
            CrbsError::AlreadyExists { message } => ApiError::Conflict(message),
            CrbsError::Conflict { message } => ApiError::Conflict(message),
            CrbsError::DeleteRestricted { message } => ApiError::Conflict(message),
            // Database 与 Internal 同为 500 但 CLI 语义不同：Database →
            // ENVIRONMENT=6 可重试，Internal → exit 1 "this is a bug"。信封
            // error 串即机器码（CLI `is_database_error_envelope` 首选判据），
            // message 固定 "database error"（脱敏）供旧版 CLI 精确串回退匹配，
            // 文案变更须两侧同步（两侧测试钉死）。
            CrbsError::Database(_) => ApiError::Database("database error".into()),
            // 防御臂：这些变体可能含内部路径 / 系统调用细节，统一 safe_message
            // 避免泄露；ContainerExecFailed / SignFailed 等五者 server 无构造点，
            // 本臂仅对假想泄漏兜底。
            other => ApiError::Internal(other.safe_message()),
        }
    }
}

impl ApiError {
    /// 返回该错误对外展示的安全消息。
    pub fn message(&self) -> &str {
        match self {
            ApiError::Validation(msg) => msg,
            ApiError::NotFound(msg) => msg,
            ApiError::Conflict(msg) => msg,
            ApiError::PermissionDenied(msg) => msg,
            ApiError::Unauthorized(msg) => msg,
            ApiError::TooManyRequests(msg) => msg,
            ApiError::ServiceUnavailable(msg) => msg,
            ApiError::GatewayTimeout(msg) => msg,
            ApiError::PayloadTooLarge(msg) => msg,
            ApiError::Internal(msg) => msg,
            ApiError::Database(msg) => msg,
        }
    }

    /// 404：消息含资源名与 id，如 "build 42 not found"。
    pub(crate) fn not_found(resource: &str, id: impl std::fmt::Display) -> Self {
        ApiError::NotFound(format!("{resource} {id} not found"))
    }

    /// 内部详细错误进 tracing 日志，HTTP 响应只回固定安全消息（防泄露，保留排障上下文）。
    pub fn log_and_internal<E>(err: E) -> Self
    where
        E: std::fmt::Display,
    {
        tracing::error!(error = %err, "internal request error");
        ApiError::Internal("internal error".into())
    }

    /// 带上下文变体：context 与错误均进日志，HTTP 响应仍只回通用安全消息。
    pub fn log_and_internal_with_context<E>(context: impl Into<String>, err: E) -> Self
    where
        E: std::fmt::Display,
    {
        let context = context.into();
        tracing::error!(context, error = %err, "internal request error");
        ApiError::Internal("internal error".into())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::log_and_internal(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_error_maps_to_bad_request() {
        let api: ApiError = CrbsError::ValidationFailed {
            message: "bad input".into(),
        }
        .into();
        assert!(matches!(api, ApiError::Validation(ref msg) if msg == "bad input"));
        let response = api.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn product_chain_invalid_maps_to_bad_request_with_product_and_reason() {
        let api: ApiError = CrbsError::ProductChainInvalid {
            product: "child".into(),
            reason: "leaf 'child' has empty base_packages".into(),
        }
        .into();
        assert!(matches!(
            api,
            ApiError::Validation(ref msg)
                if msg.contains("child") && msg.contains("empty base_packages")
        ));
        let response = api.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn layer_not_found_maps_to_not_found() {
        let api: ApiError = CrbsError::LayerNotFound {
            digest: "sha256:abc".into(),
        }
        .into();
        assert!(
            matches!(api, ApiError::NotFound(ref msg) if msg == "shared layer sha256:abc not found")
        );
        let response = api.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn not_found_constructor_renders_resource_and_id() {
        let api = ApiError::not_found("task", 42);
        assert!(matches!(api, ApiError::NotFound(ref msg) if msg == "task 42 not found"));
        let response = api.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn io_error_redacted_to_internal() {
        let api: ApiError = CrbsError::Io {
            context: "open /secret/key.pem".into(),
            kind: std::io::ErrorKind::NotFound,
            detail: "no such file".into(),
        }
        .into();
        assert!(matches!(api, ApiError::Internal(msg) if msg == "internal I/O error"));
    }

    #[test]
    fn database_unavailable_maps_to_service_unavailable() {
        // error 字段底层形态（PoolTimedOut 等）仅供日志 / CLI Display，HTTP 走固定文案不随 Display 泄露。
        let api: ApiError = CrbsError::DatabaseUnavailable {
            context: "acquire conn".into(),
            error: "pool timed out while waiting for an open connection".into(),
        }
        .into();
        assert!(matches!(
            api,
            ApiError::ServiceUnavailable(ref msg) if msg == "database unavailable"
        ));
        let response = api.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// 钉死信封机器码 "database_error" 与固定 message "database error"（契约见 From Database 臂注释）。
    #[tokio::test]
    async fn database_error_maps_to_500_with_distinct_envelope_message() {
        let api: ApiError =
            CrbsError::Database("create user: UNIQUE constraint failed".into()).into();
        let response = api.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"], "database_error");
        assert_eq!(json["message"], "database error");
    }

    #[test]
    fn payload_too_large_maps_to_413() {
        let api = ApiError::PayloadTooLarge("JSON request body exceeds 2097152 bytes".into());
        assert!(matches!(api, ApiError::PayloadTooLarge(ref msg) if msg.contains("exceeds")));
        let response = api.into_response();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn log_and_internal_returns_safe_message() {
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "secret path");
        let api = ApiError::log_and_internal(err);
        assert!(matches!(api, ApiError::Internal(msg) if msg == "internal error"));
    }

    #[test]
    fn log_and_internal_with_context_returns_safe_message() {
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "secret path");
        let api = ApiError::log_and_internal_with_context("do something sensitive", err);
        assert!(matches!(api, ApiError::Internal(msg) if msg == "internal error"));
    }
}
