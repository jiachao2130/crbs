// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! worker 内部错误转换：reqwest、serde_json 等外部错误统一转为 CrbsError，
//! 避免每个调用点重复 map_err。

use crbs_core::error::CrbsError;

/// without_url() 剥离 Display 内嵌的 URL：SRPM 下载 URL 带签名 token，错误文本
/// 会进日志、随终态上报落库、展示到 UI。
pub(crate) fn reqwest(context: impl Into<String>, err: reqwest::Error) -> CrbsError {
    CrbsError::Network {
        message: format!("{}: {}", context.into(), err.without_url()),
    }
}

/// 按 HTTP 状态码分类 Hub 非 2xx 响应：401/403 = 凭据失效或被撤销，重试无意义，
/// poller/heartbeat 据此退出进程；429 = 限流暂态，归 Network 走退避重试；其余 4xx =
/// 客户端错误不进退避，但按暂态处理（如 404 资源未就绪）；5xx 归 Network 可重试。
pub(crate) fn http_response_error(
    context: impl Into<String>,
    status: reqwest::StatusCode,
    text: String,
) -> CrbsError {
    let message = format!("{}: {} {}", context.into(), status, text);
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        CrbsError::PermissionDenied { message }
    } else if status.is_client_error() && status != reqwest::StatusCode::TOO_MANY_REQUESTS {
        CrbsError::ValidationFailed { message }
    } else {
        CrbsError::Network { message }
    }
}

pub(crate) fn is_auth_rejected(e: &CrbsError) -> bool {
    matches!(e, CrbsError::PermissionDenied { .. })
}

pub(crate) fn serde(context: impl Into<String>, err: serde_json::Error) -> CrbsError {
    CrbsError::Internal(format!("{}: {}", context.into(), err))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(code: u16) -> reqwest::StatusCode {
        reqwest::StatusCode::from_u16(code).unwrap()
    }

    #[test]
    fn http_response_error_maps_401_403_to_permission_denied() {
        for code in [401, 403] {
            let e = http_response_error("ctx", status(code), "denied".into());
            assert!(
                matches!(e, CrbsError::PermissionDenied { .. }),
                "{} should map to PermissionDenied: {e}",
                code
            );
            assert!(is_auth_rejected(&e), "{} should be auth-rejected", code);
        }
    }

    #[test]
    fn http_response_error_maps_other_4xx_to_validation_failed() {
        for code in [400, 404, 422] {
            let e = http_response_error("ctx", status(code), "client error".into());
            assert!(
                matches!(e, CrbsError::ValidationFailed { .. }),
                "{} should map to ValidationFailed: {e}",
                code
            );
            assert!(!is_auth_rejected(&e), "{} must not be auth-rejected", code);
        }
    }

    #[test]
    fn http_response_error_maps_429_to_retryable_network() {
        let e = http_response_error("ctx", status(429), "rate limited".into());
        assert!(
            matches!(e, CrbsError::Network { .. }),
            "429 must map to Network: {e}"
        );
        assert!(e.is_transient(), "429 must be retryable via is_transient");
        assert!(!is_auth_rejected(&e));
    }

    #[test]
    fn http_response_error_maps_5xx_to_network() {
        for code in [500, 502, 503, 504] {
            let e = http_response_error("ctx", status(code), "server error".into());
            assert!(
                matches!(e, CrbsError::Network { .. }),
                "{} should map to Network: {e}",
                code
            );
            assert!(!is_auth_rejected(&e));
        }
    }

    #[test]
    fn is_auth_rejected_is_exclusive_to_permission_denied() {
        assert!(is_auth_rejected(&CrbsError::PermissionDenied {
            message: "denied".into()
        }));
        assert!(!is_auth_rejected(&CrbsError::ValidationFailed {
            message: "bad".into()
        }));
        assert!(!is_auth_rejected(&CrbsError::Network {
            message: "down".into()
        }));
        assert!(!is_auth_rejected(&CrbsError::Timeout));
        assert!(!is_auth_rejected(&CrbsError::Cancelled));
    }
}
