// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 将 UI 路由的 JSON 错误响应重写为带导航的 HTML 错误页：仅拦截 `ui::public_router()`
//! 内层的 4xx/5xx JSON 响应（`ApiError::into_response` 默认一律回 JSON），状态码不变；
//! 非 JSON（如 HTML 登录页 401）与非错误响应放行，SSE 握手前的 401/403 也会变成 HTML。

use axum::body::{to_bytes, Body};
use axum::extract::{Extension, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::server::auth::AuthContext;
use crate::server::routes::ui::components::{
    error_content, error_title, generate_nonce, page_with_csp_status, PageCspParams,
};
use crate::server::routes::ui::i18n::{lang_from_headers, t, TextKey};
use crate::server::routes::ui::service::safe_back_path;
use crate::server::state::AppState;

/// 错误体缓冲上限：错误 JSON 通常 < 1KB，64KB 超配；超限走 fallback。
const MAX_ERROR_BODY: usize = 64 * 1024;

/// 拦截 UI 路由的 JSON 错误响应并重写为 HTML 错误页。
pub(crate) async fn error_page_middleware(
    State(app): State<std::sync::Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let auth = request.extensions().get::<AuthContext>().cloned();
    let req_headers = request.headers().clone();
    // 语言提取与正常页同源：?lang= 覆盖头（外层 lang_query_middleware 注入）> cookie > Accept-Language。
    // req_headers 兼供错误页导航栏 logout 表单的 CSRF 派生（与正常页同链）。
    let lang = lang_from_headers(&req_headers);
    // 先记原始 path+query（request 会被 next.run 消费）：401 login CTA 的 next 参数要用。
    let req_uri = request.uri().clone();

    let res = next.run(request).await;
    let status = res.status();

    if !(status.is_client_error() || status.is_server_error()) {
        return res;
    }

    let is_json = res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/json"));
    if !is_json {
        return res;
    }

    // 缓冲失败（超限/流错误）时 body 已消费、无法原样返回：退回仅保留状态码的响应（不把 4xx 变 5xx）。
    let (parts, body) = res.into_parts();
    let bytes = match to_bytes(body, MAX_ERROR_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return status.into_response(),
    };

    let message = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(str::to_owned))
        .unwrap_or_else(|| t(lang, TextKey::ErrRequestFailed).to_string());

    // nonce 生成失败：退回原始 JSON 响应，不因美化错误页把 4xx 变 5xx。
    let nonce = match generate_nonce() {
        Ok(nonce) => nonce,
        Err(_) => return Response::from_parts(parts, Body::from(bytes)),
    };

    // login CTA next 仅放行 /ui/ 站内路径（safe_back_path 白名单，防开放重定向），其余渲染不带 next 的链接。
    let login_next = (status == StatusCode::UNAUTHORIZED)
        .then(|| {
            req_uri
                .path_and_query()
                .map(|pq| pq.as_str().to_string())
                .and_then(|pq| safe_back_path(Some(&pq)).map(str::to_owned))
        })
        .flatten();

    let content = error_content(status, &message, login_next.as_deref(), lang);
    match page_with_csp_status(PageCspParams {
        title: &error_title(status, lang),
        nonce: &nonce,
        auth: auth.as_ref(),
        active: "",
        headers: &req_headers,
        csrf_key: &app.csrf_key,
        content,
        status,
    }) {
        Ok((_status, security_headers, markup)) => {
            // 以原始 JSON 响应头为基底（保留 Set-Cookie / WWW-Authenticate 等）；跳过
            // Content-Type / Content-Length / Transfer-Encoding——body 已换成 HTML，沿用 JSON 表述头会坏响应。
            let mut res = markup.into_response();
            *res.status_mut() = status;
            for (name, value) in &parts.headers {
                if name != header::CONTENT_TYPE
                    && name != header::CONTENT_LENGTH
                    && name != header::TRANSFER_ENCODING
                {
                    // append 保住多值头（如多条 Set-Cookie）不被折叠。
                    res.headers_mut().append(name.clone(), value.clone());
                }
            }
            for (name, value) in &security_headers {
                res.headers_mut().insert(name.clone(), value.clone());
            }
            res
        }
        // 渲染失败同样退回原始 JSON，保持状态码。
        Err(_) => Response::from_parts(parts, Body::from(bytes)),
    }
}

/// 渲染标准 HTML 错误页（导航 + CSP 安全头），供 UI 的 404/405 fallback 使用；与
/// `error_page_middleware` 同一管线但不消费已有响应、无 JSON 可回退——nonce/渲染失败退回仅含状态码的空响应。
fn render_fallback_error_page(
    app: &AppState,
    auth: Option<&AuthContext>,
    headers: &HeaderMap,
    status: StatusCode,
    message: &str,
) -> Response {
    let nonce = match generate_nonce() {
        Ok(nonce) => nonce,
        Err(_) => return status.into_response(),
    };
    let lang = lang_from_headers(headers);
    match page_with_csp_status(PageCspParams {
        title: &error_title(status, lang),
        nonce: &nonce,
        auth,
        active: "",
        headers,
        csrf_key: &app.csrf_key,
        content: error_content(status, message, None, lang),
        status,
    }) {
        Ok((status, security_headers, markup)) => {
            let mut res = markup.into_response();
            *res.status_mut() = status;
            for (name, value) in &security_headers {
                res.headers_mut().insert(name.clone(), value.clone());
            }
            res
        }
        Err(_) => status.into_response(),
    }
}

/// UI 路由的 404 fallback。`Router::merge` 会把自定义 fallback 传播到整个 app router，
/// 必须按路径分流：`/ui` 前缀渲染带导航的 HTML 404；其余（如未匹配的 `/api/v1/*`）
/// 保持 axum 默认空 404，不改 API 契约。
pub(crate) async fn ui_not_found_fallback(
    State(app): State<std::sync::Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let path = request.uri().path();
    if path != "/ui" && !path.starts_with("/ui/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    render_fallback_error_page(
        &app,
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        StatusCode::NOT_FOUND,
        t(lang_from_headers(&headers), TextKey::Err404Message),
    )
}

/// UI 路由的 405 fallback：路径匹配但方法不符时渲染 HTML 错误页。axum 的 router-level
/// fallback 不拦截 405，由 `method_not_allowed_fallback` 逐路由注入本 handler，不经 merge 泄漏到非 UI 路由。
pub(crate) async fn ui_method_not_allowed_fallback(
    State(app): State<std::sync::Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
) -> Response {
    render_fallback_error_page(
        &app,
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        StatusCode::METHOD_NOT_ALLOWED,
        t(lang_from_headers(&headers), TextKey::Err405Message),
    )
}
