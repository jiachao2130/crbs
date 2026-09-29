// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL v2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 注册页：管理员开关控制的自助注册。
//! 关闭时页面仍可达（200 提示页非 404），POST 关闭态 403 返回同一提示页。
//! 开放态：username 复用 `validate_user_name`，密码策略 ≥10 字符，confirm 后端
//! 独立复核，重名统一"已被占用"（枚举面靠限流兜底）；新用户 viewer/active，
//! 注册成功即登录（与密码登录同一签发路径）。POST 与 login 共享 nonce cookie +
//! CSRF + LoginRateLimiter（IP/用户名双轴）。审计 register（actor=新用户名，target=user id）。

use super::auth::{client_ip, issue_session_response, rate_limited_page};
use super::cookie_secure_suffix;
use crate::server::csrf;
use crate::server::error::ApiError;
use crate::server::routes::ui::components::{generate_nonce, page_bare_with_csp_status};
use crate::server::routes::ui::i18n::{lang_from_headers, t, t_fmt, FmtKey, Lang, TextKey};
use crate::server::state::AppState;
use axum::extract::{ConnectInfo, Extension, Form, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use crbs_core::auth::password::{self, PasswordPolicyError};
use maud::{html, Markup, PreEscaped};
use std::sync::Arc;

/// 注册 nonce cookie（与登录 nonce 同机制、不同名字与 Path，互不复用）。
const REGISTER_NONCE_COOKIE: &str = "crbs_register_nonce";

const REGISTRATION_ENABLED_KEY: &str = "registration_enabled";

/// 读注册开关：值恰为 "true" 才开放；缺失/读失败按关闭（fail-closed）。
pub(crate) async fn registration_enabled(app: &AppState) -> bool {
    match app.state_store.get_app_meta(REGISTRATION_ENABLED_KEY).await {
        Ok(Some(v)) => v == "true",
        Ok(None) => false,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to read registration switch; treating as closed");
            false
        }
    }
}

/// aria-invalid 属性值：仅失败字段渲染 "true"（空值属性对 ARIA 无效）。
fn invalid_attr(invalid: bool) -> Option<&'static str> {
    invalid.then_some("true")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RegisterField {
    Username,
    Password,
    Confirm,
}

struct RegisterFormView<'a> {
    lang: Lang,
    csrf_token: &'a str,
    nonce: &'a str,
    error: Option<String>,
    invalid_field: Option<RegisterField>,
    /// 失败后保留的用户名（密码/确认框永不回填）。
    username: &'a str,
    auth_disabled: bool,
}

/// confirm 一致性前端脚本：mismatch 时 setCustomValidity 阻止提交，文案按页面语言注入（js_str 转义）。
fn confirm_match_script(nonce: &str, mismatch_msg: &str) -> Markup {
    let msg = crate::server::routes::ui::components::js_str(mismatch_msg);
    let script = format!(
        r#"(function() {{
    var form = document.getElementById('register-form');
    if (!form) {{ return; }}
    var pw = form.elements['password'];
    var cf = form.elements['confirm_password'];
    var msg = '{msg}';
    function check() {{
        cf.setCustomValidity(pw.value !== cf.value ? msg : '');
    }}
    pw.addEventListener('input', check);
    cf.addEventListener('input', check);
    form.addEventListener('submit', check);
}})();"#
    );
    html! {
        script nonce=(nonce) { (PreEscaped(script)) }
    }
}

/// 注册表单正文（开放态）：与登录页同一 .login-page / .login-card 品牌卡。
fn register_form_body(v: &RegisterFormView<'_>) -> Markup {
    let lang = v.lang;
    html! {
        div class="login-page" {
            div class="login-card" {
                div class="login-logo" {
                    img class="login-mark" src="/ui/favicon.svg" alt="";
                    h1 { (t(lang, TextKey::RegisterTitle)) }
                    p class="login-logo-sub" { (t(lang, TextKey::RegisterSubtitle)) }
                }
                @if v.auth_disabled {
                    div class="message warning" role="note" { (t(lang, TextKey::AuthDisabledNote)) }
                }
                form id="register-form" method="post" action="/ui/register" {
                    input type="hidden" name="csrf_token" value=(v.csrf_token);
                    @if let Some(err) = &v.error {
                        div class="message failure" role="alert" { (err) }
                    }
                    label for="register-username" { (t(lang, TextKey::LoginUsernameLabel)) }
                    input type="text" id="register-username" name="username"
                        value=(v.username) autocomplete="username" autofocus
                        aria-invalid=[invalid_attr(v.invalid_field == Some(RegisterField::Username))] {}
                    p class="field-hint" { (t(lang, TextKey::RegisterUsernameHint)) }
                    label for="register-password" { (t(lang, TextKey::LoginPasswordLabel)) }
                    input type="password" id="register-password" name="password"
                        autocomplete="new-password"
                        aria-invalid=[invalid_attr(v.invalid_field == Some(RegisterField::Password))] {}
                    // 静态 3 档刻度（实时填充需 JS，不在本站无 JS 基线内）；分档口径见 title，策略由后端收口。
                    div class="pw-strength" role="img"
                        aria-label=(t(lang, TextKey::RegisterStrengthLabel))
                        title=(t(lang, TextKey::RegisterStrengthTitle)) {
                        span class="pw-strength-seg" {}
                        span class="pw-strength-seg" {}
                        span class="pw-strength-seg" {}
                    }
                    p class="field-hint" { (t(lang, TextKey::RegisterPasswordHint)) }
                    label for="register-confirm" { (t(lang, TextKey::RegisterConfirmLabel)) }
                    input type="password" id="register-confirm" name="confirm_password"
                        autocomplete="new-password"
                        aria-invalid=[invalid_attr(v.invalid_field == Some(RegisterField::Confirm))] {}
                    button type="submit" class="wide" { (t(lang, TextKey::RegisterSubmitButton)) }
                }
                p class="login-foot" {
                    (t(lang, TextKey::RegisterHasAccount)) " "
                    a href="/ui/login" { (t(lang, TextKey::RegisterGoLogin)) }
                }
            }
        }
        (confirm_match_script(v.nonce, t(lang, TextKey::RegisterPasswordMismatch)))
    }
}

fn register_closed_body(lang: Lang, auth_disabled: bool) -> Markup {
    html! {
        div class="login-page" {
            div class="login-card" {
                h1 { (t(lang, TextKey::RegisterTitle)) }
                @if auth_disabled {
                    div class="message warning" role="note" { (t(lang, TextKey::AuthDisabledNote)) }
                }
                div class="message warning" role="note" { (t(lang, TextKey::RegisterClosedMessage)) }
                p class="login-foot" { a href="/ui/login" { (t(lang, TextKey::RegisterBackToLogin)) } }
            }
        }
    }
}

/// GET /ui/register：开关开放 → 注册表单（种 nonce cookie）；关闭 → 提示页。
pub(crate) async fn register_page(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let lang = lang_from_headers(&headers);
    if !registration_enabled(&app).await {
        let nonce = generate_nonce()?;
        return page_bare_with_csp_status(
            t(lang, TextKey::RegisterTitle),
            &nonce,
            &headers,
            register_closed_body(lang, !app.server_config.auth_enabled),
            StatusCode::OK,
        );
    }
    let nonce = generate_nonce()?;
    let csrf_token = csrf::csrf_token_for_login(&nonce, &app.csrf_key)
        .map_err(|_| ApiError::Internal("failed to generate register CSRF token".into()))?;
    let view = RegisterFormView {
        lang,
        csrf_token: &csrf_token,
        nonce: &nonce,
        error: None,
        invalid_field: None,
        username: "",
        auth_disabled: !app.server_config.auth_enabled,
    };
    let mut response = page_bare_with_csp_status(
        t(lang, TextKey::RegisterTitle),
        &nonce,
        &headers,
        register_form_body(&view),
        StatusCode::OK,
    )?;
    let cookie = format!(
        "{REGISTER_NONCE_COOKIE}={}; HttpOnly; SameSite=Lax; Path=/ui/register{}",
        nonce,
        cookie_secure_suffix(&app),
    );
    response.1.insert(
        header::SET_COOKIE,
        cookie
            .parse()
            .map_err(|_| ApiError::Internal("failed to build Set-Cookie header".into()))?,
    );
    Ok(response)
}

#[derive(serde::Deserialize)]
pub(crate) struct RegisterForm {
    username: String,
    password: String,
    confirm_password: String,
    csrf_token: Option<String>,
}

/// 校验失败重渲染（200 保留输入 + 具体提示 + 对应字段红框）。
async fn register_failure_page(
    app: &AppState,
    headers: &HeaderMap,
    username: &str,
    error: String,
    invalid_field: RegisterField,
) -> Result<(StatusCode, HeaderMap, Markup), ApiError> {
    let nonce = generate_nonce()?;
    let lang = lang_from_headers(headers);
    let csrf_token = csrf::csrf_token_for_login(&nonce, &app.csrf_key)
        .map_err(|_| ApiError::Internal("failed to generate register CSRF token".into()))?;
    let view = RegisterFormView {
        lang,
        csrf_token: &csrf_token,
        nonce: &nonce,
        error: Some(error),
        invalid_field: Some(invalid_field),
        username,
        auth_disabled: !app.server_config.auth_enabled,
    };
    let mut response = page_bare_with_csp_status(
        t(lang, TextKey::RegisterTitle),
        &nonce,
        headers,
        register_form_body(&view),
        StatusCode::OK,
    )?;
    let cookie = format!(
        "{REGISTER_NONCE_COOKIE}={}; HttpOnly; SameSite=Lax; Path=/ui/register{}",
        nonce,
        cookie_secure_suffix(app),
    );
    response.1.insert(
        header::SET_COOKIE,
        cookie
            .parse()
            .map_err(|_| ApiError::Internal("failed to build Set-Cookie header".into()))?,
    );
    Ok(response)
}

pub(crate) async fn register_submit(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    connect_info: Option<Extension<ConnectInfo<std::net::SocketAddr>>>,
    Form(form): Form<RegisterForm>,
) -> Result<impl IntoResponse, ApiError> {
    let register_nonce = csrf::register_nonce_from_headers(&headers)
        .ok_or(ApiError::Unauthorized("missing register session".into()))?;
    let csrf_token = form
        .csrf_token
        .ok_or(ApiError::Unauthorized("missing CSRF token".into()))?;
    if !csrf::validate_login_csrf(&register_nonce, &app.csrf_key, &csrf_token)? {
        return Err(ApiError::PermissionDenied("invalid CSRF token".into()));
    }

    let lang = lang_from_headers(&headers);
    let username = form.username.trim().to_string();
    let ip = client_ip(connect_info.as_ref().map(|ext| &ext.0));

    // 开关关闭：POST 403 + 同一提示页（GET 为 200 可达提示）。先于限流——开关
    // 检查只是一次 KV 读，不烧与登录共享的限流配额。
    if !registration_enabled(&app).await {
        let nonce = generate_nonce()?;
        return page_bare_with_csp_status(
            t(lang, TextKey::RegisterTitle),
            &nonce,
            &headers,
            register_closed_body(lang, !app.server_config.auth_enabled),
            StatusCode::FORBIDDEN,
        );
    }

    // 限流（与登录共享 limiter 与 key 空间）：先于一切用户查询。
    if let Some(remaining) = app.login_limiter.check(
        &format!("ip:{ip}"),
        &crate::server::rate_limit::login_user_key(&username),
    ) {
        if let Err(e) = app
            .state_store
            .audit_log(
                &username,
                "",
                "login_failure",
                None,
                Some(&format!(
                    r#"{{"reason":"rate_limited","mode":"register","ip":"{ip}"}}"#
                )),
            )
            .await
        {
            tracing::warn!(error = %e, "audit log write failed (rate limit already enforced)");
        }
        return rate_limited_page(
            &headers,
            remaining,
            t(lang, TextKey::RegisterTitle),
            "/ui/register",
            t(lang, TextKey::RegisterBackToLogin),
        )
        .await;
    }

    // 用户名：复用核心校验（slug 字符集 + ≤128），提示本地化（机器错误文本不反射进页面）。
    if crbs_core::validation::validate_user_name(&username).is_err() {
        return register_failure_page(
            &app,
            &headers,
            &username,
            t(lang, TextKey::RegisterInvalidUsername).to_string(),
            RegisterField::Username,
        )
        .await;
    }

    if let Err(e) = password::validate_password_policy(&form.password) {
        let msg = match e {
            PasswordPolicyError::TooShort { min } => {
                t_fmt(lang, FmtKey::RegisterPasswordTooShort, &[&min.to_string()])
            }
            PasswordPolicyError::TooLong { max } => {
                t_fmt(lang, FmtKey::RegisterPasswordTooLong, &[&max.to_string()])
            }
        };
        return register_failure_page(&app, &headers, &username, msg, RegisterField::Password)
            .await;
    }

    // confirm 一致（后端独立校验；前端 setCustomValidity 只是快速反馈）。
    if form.password != form.confirm_password {
        return register_failure_page(
            &app,
            &headers,
            &username,
            t(lang, TextKey::RegisterPasswordMismatch).to_string(),
            RegisterField::Confirm,
        )
        .await;
    }

    let exists = app
        .state_store
        .find_user_by_name(&username)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Register duplicate check failed");
            ApiError::Internal("registration failed".into())
        })?
        .is_some();
    if exists {
        return register_failure_page(
            &app,
            &headers,
            &username,
            t(lang, TextKey::RegisterUsernameTaken).to_string(),
            RegisterField::Username,
        )
        .await;
    }

    // 建用户（viewer / active，最小权限）：先 hash 再单条 INSERT 原子落库，
    // 消除两步中间失败留下的无密码半成品行；与查重间竞态由 UNIQUE 兜底。
    let hash = password::hash_password(&form.password).map_err(|e| {
        tracing::warn!(error = %e, "Register hash password failed");
        // 500 body 的 message 原样回传客户端（error.rs 口径），固定文案防内部串泄漏。
        ApiError::Internal("registration failed".into())
    })?;
    let user_id = match app
        .state_store
        .create_user_with_password(&username, "viewer", &hash, false)
        .await
    {
        Ok(id) => id,
        // 查重后并发竞态撞 UNIQUE：按已被占用重渲染（不 warn）。
        Err(e) if crbs_core::is_unique_violation(&e) => {
            return register_failure_page(
                &app,
                &headers,
                &username,
                t(lang, TextKey::RegisterUsernameTaken).to_string(),
                RegisterField::Username,
            )
            .await;
        }
        Err(e) => {
            tracing::warn!(error = %e, username = %username, "Register create user failed");
            return Err(ApiError::Internal("registration failed".into()));
        }
    };

    if let Err(e) = app
        .state_store
        .audit_log(
            &username,
            "viewer",
            "register",
            Some(&user_id.to_string()),
            Some(&format!(r#"{{"mode":"self-service","ip":"{ip}"}}"#)),
        )
        .await
    {
        tracing::warn!(error = %e, "audit register write failed (user already created)");
    }

    let user = app
        .state_store
        .get_user(user_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, user_id = user_id, "Register reload user failed");
            ApiError::Internal("registration failed".into())
        })?
        .ok_or_else(|| ApiError::Internal("registration failed".into()))?;

    let (status, mut resp_headers, body) =
        issue_session_response(&app, &user, &headers, "/ui/").await?;
    // 注册 nonce 是一次性 CSRF 因素，成功即清；clear Path/secure 后缀须与种植
    // 侧精确同源（/ui/register）。issue_session_response 只清 login nonce，不覆盖此处。
    let clear_nonce = format!(
        "{REGISTER_NONCE_COOKIE}=; HttpOnly; SameSite=Lax; Path=/ui/register{}; Max-Age=0",
        cookie_secure_suffix(&app),
    );
    resp_headers.append(
        header::SET_COOKIE,
        clear_nonce
            .parse()
            .map_err(|_| ApiError::Internal("failed to build Set-Cookie header".into()))?,
    );
    Ok((status, resp_headers, body))
}
