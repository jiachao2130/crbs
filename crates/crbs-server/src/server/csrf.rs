// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! CSRF token 生成与校验：Web 表单认证凭 cookie session token，防御 = 内嵌派生 token + POST 校验。
//!
//! 派生：HMAC-SHA256(csrf_key, purpose || session_token) 的 hex，purpose 前缀隔离
//! 登录/注册 nonce 与登录后写操作两个命名空间；key 仅服务端持有、token 定长不可伪造；
//! token 同 session 跨页面/tab 稳定，多 tab 表单不因逐页刷新失效。

use axum::http::{header, HeaderMap};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::server::error::ApiError;

/// 从请求头 `Cookie` 提取指定名称的 cookie 值（认证/偏好 cookie 共用入口；同名多个取首个）。
pub(crate) fn cookie_value_from_headers(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some((cookie_name, value)) = cookie.split_once('=') {
            if cookie_name.trim() == name {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// 从请求头中的 `Cookie` 提取 `crbs_token` 值。
pub(crate) fn token_cookie_from_headers(headers: &HeaderMap) -> Option<String> {
    cookie_value_from_headers(headers, "crbs_token")
}

/// CSRF 派生基值：`crbs_session` 优先、回落 `crbs_token`，与 [`crate::server::auth::resolve_token`] 请求级优先链对齐。
/// session cookie 存在即作基值、不要求通过认证——校验侧走同一条链，两侧对称。
pub(crate) fn csrf_base_from_headers(headers: &HeaderMap) -> Option<String> {
    session_cookie_from_headers(headers).or_else(|| token_cookie_from_headers(headers))
}

/// 提取 `crbs_session` cookie（密码登录 UI 会话）：与 `crbs_token` 独立凭据，只走会话查表路径、永不被 API Bearer 接受。
pub(crate) fn session_cookie_from_headers(headers: &HeaderMap) -> Option<String> {
    cookie_value_from_headers(headers, "crbs_session")
}

type HmacSha256 = Hmac<Sha256>;

/// 登录后写操作 CSRF 的用途标签：HMAC 输入前缀（"ui" purpose）。
const CSRF_PURPOSE_UI: &[u8] = b"csrf-ui:";

/// 登录/注册 nonce CSRF 的用途标签（"login" purpose）。
/// 与写操作 CSRF 命名空间隔离：cookie tossing 下诱导的登录页 nonce 不能充当写操作 CSRF 基值（反之亦然）。
const CSRF_PURPOSE_LOGIN: &[u8] = b"csrf-login:";

/// 为指定 session token 生成写操作 CSRF token（"ui" purpose）。
pub(crate) fn csrf_token_for(session_token: &str, csrf_key: &[u8; 32]) -> Result<String, ApiError> {
    csrf_token_with_purpose(CSRF_PURPOSE_UI, session_token, csrf_key)
}

/// 校验表单提交的写操作 CSRF token（"ui" purpose）是否与 session token 派生结果一致。
pub(crate) fn validate_csrf_token(
    session_token: &str,
    csrf_key: &[u8; 32],
    provided: &str,
) -> Result<bool, ApiError> {
    let expected = csrf_token_for(session_token, csrf_key)?;
    Ok(provided.as_bytes().ct_eq(expected.as_bytes()).into())
}

/// 为登录/注册 nonce 生成 CSRF token（"login" purpose，与写操作命名空间隔离）。
pub(crate) fn csrf_token_for_login(nonce: &str, csrf_key: &[u8; 32]) -> Result<String, ApiError> {
    csrf_token_with_purpose(CSRF_PURPOSE_LOGIN, nonce, csrf_key)
}

/// 校验登录/注册表单的 CSRF token（"login" purpose）。
pub(crate) fn validate_login_csrf(
    nonce: &str,
    csrf_key: &[u8; 32],
    provided: &str,
) -> Result<bool, ApiError> {
    let expected = csrf_token_for_login(nonce, csrf_key)?;
    Ok(provided.as_bytes().ct_eq(expected.as_bytes()).into())
}

fn csrf_token_with_purpose(
    purpose: &[u8],
    value: &str,
    csrf_key: &[u8; 32],
) -> Result<String, ApiError> {
    let mut mac = HmacSha256::new_from_slice(csrf_key)
        .map_err(|_| ApiError::Internal("invalid CSRF key length".into()))?;
    mac.update(purpose);
    mac.update(value.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// UI error flash 签名的用途标签：HMAC 输入前缀，与 CSRF token 派生隔离，防不同用途签名互相重放。
const UI_ERROR_FLASH_PURPOSE: &[u8] = b"ui-error-flash:";

/// 为 UI 重定向 flash 的 error 文本生成签名（hex HMAC-SHA256）。
/// `Location` 形如 `<path>?error=<urlencoded text>&es=<sig>`；渲染端（`status_message`）
/// 校验失败退回固定文案，防攻击者构造任意 URL 在受信错误横幅反射内容（content spoofing）。
pub(crate) fn sign_ui_error_flash(text: &str, csrf_key: &[u8; 32]) -> Result<String, ApiError> {
    csrf_token_with_purpose(UI_ERROR_FLASH_PURPOSE, text, csrf_key)
}

/// 常数时间校验 UI error flash 签名（`es` 参数）是否与文本匹配。
pub(crate) fn verify_ui_error_flash(
    text: &str,
    csrf_key: &[u8; 32],
    provided: &str,
) -> Result<bool, ApiError> {
    let expected = sign_ui_error_flash(text, csrf_key)?;
    Ok(provided.as_bytes().ct_eq(expected.as_bytes()).into())
}

/// 从请求头中的 `Cookie` 提取 `crbs_login_nonce` 值。
pub(crate) fn login_nonce_from_headers(headers: &HeaderMap) -> Option<String> {
    cookie_value_from_headers(headers, "crbs_login_nonce")
}

/// 从请求头 `Cookie` 提取 `crbs_register_nonce` 值（注册表单，与登录 nonce 同机制）。
pub(crate) fn register_nonce_from_headers(headers: &HeaderMap) -> Option<String> {
    cookie_value_from_headers(headers, "crbs_register_nonce")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_token_is_stable_for_same_session() {
        let key = [1u8; 32];
        let token = "crbs_tok_abc123";
        let a = csrf_token_for(token, &key).unwrap();
        let b = csrf_token_for(token, &key).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn csrf_token_differs_for_different_keys() {
        let token = "crbs_tok_abc123";
        let a = csrf_token_for(token, &[1u8; 32]).unwrap();
        let b = csrf_token_for(token, &[2u8; 32]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn validate_csrf_token_accepts_correct_token() {
        let key = [1u8; 32];
        let session = "crbs_tok_abc123";
        let token = csrf_token_for(session, &key).unwrap();
        assert!(validate_csrf_token(session, &key, &token).unwrap());
    }

    #[test]
    fn validate_csrf_token_rejects_wrong_token() {
        let key = [1u8; 32];
        let session = "crbs_tok_abc123";
        assert!(!validate_csrf_token(session, &key, "wrong").unwrap());
    }

    #[test]
    fn token_cookie_from_headers_parses_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "crbs_token=abc123; other=xyz".parse().unwrap(),
        );
        assert_eq!(
            token_cookie_from_headers(&headers),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn token_cookie_from_headers_missing() {
        let headers = HeaderMap::new();
        assert_eq!(token_cookie_from_headers(&headers), None);
    }

    /// crbs_session 解析：命中、缺失、与 crbs_token 并存互不干扰。
    #[test]
    fn session_cookie_from_headers_parses() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "crbs_session=crbs_sess_abc; crbs_token=crbs_tok_xyz"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            session_cookie_from_headers(&headers),
            Some("crbs_sess_abc".to_string())
        );
        assert_eq!(
            token_cookie_from_headers(&headers),
            Some("crbs_tok_xyz".to_string())
        );

        let headers = HeaderMap::new();
        assert_eq!(session_cookie_from_headers(&headers), None);

        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "crbs_token=crbs_tok_xyz".parse().unwrap());
        assert_eq!(session_cookie_from_headers(&headers), None);
    }

    /// 基值链：session cookie 优先，无 session 回落 token，皆无 → None。
    #[test]
    fn csrf_base_prefers_session_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "crbs_session=crbs_sess_abc; crbs_token=crbs_tok_xyz"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            csrf_base_from_headers(&headers),
            Some("crbs_sess_abc".to_string()),
            "session cookie must win for CSRF derivation"
        );

        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "crbs_token=crbs_tok_xyz".parse().unwrap());
        assert_eq!(
            csrf_base_from_headers(&headers),
            Some("crbs_tok_xyz".to_string())
        );

        assert_eq!(csrf_base_from_headers(&HeaderMap::new()), None);
    }

    #[test]
    fn ui_error_flash_verify_roundtrip() {
        let key = [1u8; 32];
        let sig = sign_ui_error_flash("Build 42 failed", &key).unwrap();
        assert!(verify_ui_error_flash("Build 42 failed", &key, &sig).unwrap());
        assert!(!verify_ui_error_flash("Build 43 failed", &key, &sig).unwrap());
    }

    #[test]
    fn ui_error_flash_signature_is_purpose_tagged() {
        // CSRF token 与 error flash 签名使用同一 key 但不同用途标签，不可互相冒用。
        let key = [1u8; 32];
        let text = "some text";
        let csrf_sig = csrf_token_for(text, &key).unwrap();
        assert!(!verify_ui_error_flash(text, &key, &csrf_sig).unwrap());
    }

    /// CSRF purpose 隔离：登录/注册 nonce 派生的 CSRF 与写操作 CSRF 互不可冒用（cookie tossing）。
    #[test]
    fn login_csrf_and_ui_csrf_namespaces_are_isolated() {
        let key = [1u8; 32];
        let nonce = "login_nonce_value";

        let login_token = csrf_token_for_login(nonce, &key).unwrap();
        assert!(!validate_csrf_token(nonce, &key, &login_token).unwrap());
        assert!(validate_login_csrf(nonce, &key, &login_token).unwrap());

        let ui_token = csrf_token_for(nonce, &key).unwrap();
        assert!(!validate_login_csrf(nonce, &key, &ui_token).unwrap());
        assert_ne!(login_token, ui_token);
    }

    #[test]
    fn validate_login_csrf_rejects_wrong_token() {
        let key = [1u8; 32];
        assert!(!validate_login_csrf("nonce", &key, "wrong").unwrap());
    }
}
