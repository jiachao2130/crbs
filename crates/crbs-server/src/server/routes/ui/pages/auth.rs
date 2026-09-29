// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Web UI 认证页 handler：登录双模式 + 登出。
//!
//! - GET `/ui/login`：双模式 segmented control（纯 CSS radio，无 JS，Password 为主）；
//!   POST `/ui/login/password`、`/ui/login/token` 登录，`/ui/logout` 登出（见各 handler doc）。
//! - 限流：per-IP + per-username 固定窗口 10 次/5 分钟，IP 取 ConnectInfo 真连地址，文案
//!   不带剩余次数；审计 login_success / login_failure / logout（密码与失败原因不进日志/审计）。

use super::cookie_secure_suffix;
use crate::server::auth::{self, AuthContext};
use crate::server::csrf;
use crate::server::error::ApiError;
use crate::server::routes::ui::components::{
    ascii_location_value, generate_nonce, page_bare_with_csp_status, redirect_body,
};
use crate::server::routes::ui::i18n::{lang_from_headers, t, t_fmt, FmtKey, Lang, TextKey};
use crate::server::routes::ui::service::safe_back_path;
use crate::server::state::AppState;
use axum::extract::{ConnectInfo, Extension, Form, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use crbs_core::auth::password;
use crbs_core::auth::secret::{Secret, SecretKind};
use crbs_core::{User, UserAuthRow};
use maud::{html, Markup};
use std::sync::Arc;
use std::time::Duration;

/// 登录会话有效期（7 天）：cookie Max-Age 与 sessions 表绝对过期共用此值。
const SESSION_MAX_AGE_SECS: i64 = 604_800;

/// token 粘贴模式限流用户轴：token 无用户名（认证前不可知），按 SHA-256 前 8 字节分桶
/// ——同 token 共享一桶（保住单 token 撞解限制），不同 token 各自落桶，杜绝固定全局桶
/// 被 10 次垃圾请求封禁全部 token 登录 5 分钟且可无限重复；与 per-IP 轴叠加兜底。
fn token_mode_user_key(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(token.trim().as_bytes());
    let prefix: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("user:tok:{prefix}")
}

/// 登录 nonce cookie：Path=/ui/login 前缀匹配同时覆盖 password / token 两个 POST 目标。
const LOGIN_NONCE_COOKIE: &str = "crbs_login_nonce";

/// login 页 GET 参数：`?next=` 回跳目标（`safe_back_path` 白名单，非法/缺失回退 `/ui/`）。
#[derive(serde::Deserialize, Default)]
pub(crate) struct LoginQuery {
    pub next: Option<String>,
}

/// aria-invalid 属性值：仅失败态渲染 "true"（空值属性对 ARIA 无效）。
fn invalid_attr(invalid: bool) -> Option<&'static str> {
    invalid.then_some("true")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LoginMode {
    Password,
    Token,
}

/// 双模式登录页渲染参数（GET 与失败重渲染共用一套骨架）。
struct LoginPageView<'a> {
    mode: LoginMode,
    lang: Lang,
    csrf_token: &'a str,
    /// 失败提示（已本地化的完整文案）；None 不渲染 message 行。
    error: Option<String>,
    /// 密码模式失败后保留的用户名（密码永不回填）。
    username: &'a str,
    invalid: bool,
    next: Option<&'a str>,
    registration_open: bool,
    /// auth_enabled=false：显示"认证已禁用"说明（安全清单）。
    auth_disabled: bool,
}

/// 渲染双模式登录页正文（骨架由 page_bare_with_csp_status 包装）；版式：.login-page 渐变光晕 + .login-card 居中 384px 品牌卡。
fn login_page_body(v: &LoginPageView<'_>) -> Markup {
    let lang = v.lang;
    html! {
        div class="login-page" {
            div class="login-card" {
                div class="login-logo" {
                    img class="login-mark" src="/ui/favicon.svg" alt="";
                    h1 { (t(lang, TextKey::LoginTitle)) }
                    p class="login-logo-sub" { (t(lang, TextKey::LoginSubtitle)) }
                }
                @if v.auth_disabled {
                    div class="message warning" role="note" { (t(lang, TextKey::AuthDisabledNote)) }
                }
                // 纯 CSS radio 切换（无 JS）：不支持 :has() 的浏览器降级为两表单都可见
                // 可用；radio 不在任何 form 内，纯展示开关，两表单 action 各自固定。
                div class="login-modes" {
                    div class="seg" {
                        input type="radio" class="mode-radio" name="login_mode"
                            id="login-mode-password" value="password"
                            checked[v.mode == LoginMode::Password] {}
                        label class="mode-label" for="login-mode-password" { (t(lang, TextKey::LoginModePassword)) }
                        input type="radio" class="mode-radio" name="login_mode"
                            id="login-mode-token" value="token"
                            checked[v.mode == LoginMode::Token] {}
                        label class="mode-label" for="login-mode-token" { (t(lang, TextKey::LoginModeToken)) }
                    }

                    @if let Some(err) = &v.error {
                        div class="message failure" role="alert" { (err) }
                    }

                    form class="mode-panel mode-panel-password"
                        method="post" action="/ui/login/password" {
                        input type="hidden" name="csrf_token" value=(v.csrf_token);
                        @if let Some(next) = v.next {
                            input type="hidden" name="next" value=(next);
                        }
                        label for="login-username" { (t(lang, TextKey::LoginUsernameLabel)) }
                        input type="text" id="login-username" name="username"
                            value=(v.username) autocomplete="username" autofocus
                            aria-invalid=[invalid_attr(v.invalid)] {}
                        p class="field-hint" { (t(lang, TextKey::LoginUsernameHint)) }
                        label for="login-password" { (t(lang, TextKey::LoginPasswordLabel)) }
                        input type="password" id="login-password" name="password"
                            autocomplete="current-password" aria-invalid=[invalid_attr(v.invalid)] {}
                        button type="submit" class="wide" { (t(lang, TextKey::LoginSubmitButton)) }
                        p class="auth-alt" {
                            (t(lang, TextKey::LoginRateLimitHint))
                        }
                    }

                    form class="mode-panel mode-panel-token"
                        method="post" action="/ui/login/token" {
                        input type="hidden" name="csrf_token" value=(v.csrf_token);
                        @if let Some(next) = v.next {
                            input type="hidden" name="next" value=(next);
                        }
                        label for="login-token" { (t(lang, TextKey::LoginTokenLabel)) }
                        input type="password" id="login-token" name="token"
                            autocomplete="off" autofocus {}
                        p class="field-hint" { (t(lang, TextKey::LoginTokenHint)) }
                        button type="submit" class="wide" { (t(lang, TextKey::LoginSubmitButton)) }
                        p class="auth-alt" { (t(lang, TextKey::LoginNoTokenHint)) }
                    }
                }
                @if v.registration_open {
                    p class="login-foot" {
                        (t(lang, TextKey::LoginNoAccount)) " "
                        a href="/ui/register" { (t(lang, TextKey::LoginRegisterLink)) } " "
                        (t(lang, TextKey::LoginRegisterAdminNote))
                    }
                }
            }
        }
    }
}

async fn login_page_response(
    app: &AppState,
    headers: &HeaderMap,
    view: LoginPageView<'_>,
) -> Result<(StatusCode, HeaderMap, Markup), ApiError> {
    let nonce = generate_nonce()?;
    let csrf_token = csrf::csrf_token_for_login(&nonce, &app.csrf_key)
        .map_err(|_| ApiError::Internal("failed to generate login CSRF token".into()))?;
    let lang = view.lang;
    let view = LoginPageView {
        csrf_token: &csrf_token,
        ..view
    };
    let body = login_page_body(&view);
    let mut response = page_bare_with_csp_status(
        t(lang, TextKey::LoginTitle),
        &nonce,
        headers,
        body,
        StatusCode::OK,
    )?;
    let cookie = format!(
        "{LOGIN_NONCE_COOKIE}={}; HttpOnly; SameSite=Lax; Path=/ui/login{}",
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

pub(crate) async fn login_page(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<LoginQuery>,
) -> Result<impl IntoResponse, ApiError> {
    // next 白名单校验在渲染前完成：非法值不进 hidden input（POST 端会再校验）。
    let next = safe_back_path(q.next.as_deref()).map(str::to_string);
    let view = LoginPageView {
        mode: LoginMode::Password,
        lang: lang_from_headers(&headers),
        csrf_token: "",
        error: None,
        username: "",
        invalid: false,
        next: next.as_deref(),
        registration_open: super::register::registration_enabled(&app).await,
        auth_disabled: !app.server_config.auth_enabled,
    };
    login_page_response(&app, &headers, view).await
}

/// 登录失败重渲染：200 + 保留用户名 + 统一文案 + aria-invalid（不泄露哪个字段错）。
async fn login_failure_page(
    app: &AppState,
    headers: &HeaderMap,
    mode: LoginMode,
    username: &str,
    next: Option<&str>,
    error: String,
) -> Result<(StatusCode, HeaderMap, Markup), ApiError> {
    let view = LoginPageView {
        mode,
        lang: lang_from_headers(headers),
        csrf_token: "",
        error: Some(error),
        username,
        invalid: true,
        next: safe_back_path(next),
        registration_open: super::register::registration_enabled(app).await,
        auth_disabled: !app.server_config.auth_enabled,
    };
    login_page_response(app, headers, view).await
}

/// 限流触发页（429），登录与注册共用：文案只给保守的"N 分钟后重试"（不带剩余次数），
/// `back_href`/`back_label` 提供回入口，同走裸品牌卡版式。
pub(crate) async fn rate_limited_page(
    headers: &HeaderMap,
    remaining: Duration,
    title: &str,
    back_href: &str,
    back_label: &str,
) -> Result<(StatusCode, HeaderMap, Markup), ApiError> {
    let nonce = generate_nonce()?;
    let lang = lang_from_headers(headers);
    // 保守上取整：宁可提示更长也不让用户掐点重试撞墙。
    let minutes = remaining.as_secs().div_ceil(60).max(1).to_string();
    let body = html! {
        div class="login-page" {
            div class="login-card" {
                h1 { (title) }
                div class="message failure" role="alert" {
                    (t_fmt(lang, FmtKey::RateLimitedMinutes, &[&minutes]))
                }
                p { a class="action-button secondary" href=(back_href) { (back_label) } }
            }
        }
    };
    page_bare_with_csp_status(title, &nonce, headers, body, StatusCode::TOO_MANY_REQUESTS)
}

/// 请求真连 IP（ConnectInfo）；缺失（如测试 oneshot）记 "unknown"——限流退化为共享桶 + 用户名轴。
pub(crate) fn client_ip(connect_info: Option<&ConnectInfo<std::net::SocketAddr>>) -> String {
    connect_info
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// User-Agent 摘要：截断到 256 字节（char boundary 对齐），供 sessions.agent 展示。
fn user_agent_truncated(headers: &HeaderMap) -> Option<String> {
    let ua = headers.get(header::USER_AGENT)?.to_str().ok()?;
    let mut end = ua.len().min(256);
    while end > 0 && !ua.is_char_boundary(end) {
        end -= 1;
    }
    Some(ua[..end].to_string())
}

/// 审计写失败只 warn：认证主流程已提交，审计缺口不阻断登录/登出。
async fn audit_auth_event(
    app: &AppState,
    actor: &str,
    role: &str,
    action: &str,
    target: Option<&str>,
    detail: &str,
) {
    if let Err(e) = app
        .state_store
        .audit_log(actor, role, action, target, Some(detail))
        .await
    {
        tracing::warn!(error = %e, action = action, "audit log write failed (auth flow already committed)");
    }
}

/// detail JSON 组装（值域受控：mode/reason 枚举 + IP 的安全字符集，无注入面）。
fn auth_detail(mode: &str, ip: &str) -> String {
    format!(r#"{{"mode":"{mode}","ip":"{ip}"}}"#)
}

fn auth_failure_detail(reason: &str, mode: &str, ip: &str) -> String {
    format!(r#"{{"reason":"{reason}","mode":"{mode}","ip":"{ip}"}}"#)
}

#[derive(serde::Deserialize)]
pub(crate) struct LoginPasswordForm {
    username: String,
    password: String,
    csrf_token: Option<String>,
    /// hidden input 透传的回跳目标；GET 已校验，POST 再校验（表单可被外部构造）。
    next: Option<String>,
}

/// POST /ui/login/password：密码登录。校验序：nonce + CSRF → 限流（先于任何 DB 查询）
/// → 查用户 → argon2（每条路径恰好执行一次真实或 dummy 验证，防时序枚举）→ 账号状态
/// → 签发 session。
pub(crate) async fn login_password_submit(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    connect_info: Option<Extension<ConnectInfo<std::net::SocketAddr>>>,
    Form(form): Form<LoginPasswordForm>,
) -> Result<impl IntoResponse, ApiError> {
    let login_nonce = csrf::login_nonce_from_headers(&headers)
        .ok_or(ApiError::Unauthorized("missing login session".into()))?;
    let csrf_token = form
        .csrf_token
        .ok_or(ApiError::Unauthorized("missing CSRF token".into()))?;
    if !csrf::validate_login_csrf(&login_nonce, &app.csrf_key, &csrf_token)? {
        return Err(ApiError::PermissionDenied("invalid CSRF token".into()));
    }

    let username = form.username.trim().to_string();
    let ip = client_ip(connect_info.as_ref().map(|ext| &ext.0));
    let ip_key = format!("ip:{ip}");
    let user_key = crate::server::rate_limit::login_user_key(&username);

    // 限流先于一切用户查询：触发即 429，对所有用户名行为一致（无枚举面）。
    if let Some(remaining) = app.login_limiter.check(&ip_key, &user_key) {
        audit_auth_event(
            &app,
            &username,
            "",
            "login_failure",
            None,
            &auth_failure_detail("rate_limited", "password", &ip),
        )
        .await;
        let lang = lang_from_headers(&headers);
        return rate_limited_page(
            &headers,
            remaining,
            t(lang, TextKey::LoginTitle),
            "/ui/login",
            t(lang, TextKey::RegisterBackToLogin),
        )
        .await;
    }

    // 查用户 + 认证行；任一步"未命中"都补一次 dummy argon2，抹平时序差。
    let outcome = match fetch_login_user(&app, &username).await? {
        Some((user, auth_row)) => match auth_row.password_hash.as_deref() {
            // 未设密码（token-only 用户）：统一失败文案，不泄露"该用户存在"。
            None => {
                password::dummy_verify(&form.password);
                None
            }
            Some(phc) if password::verify_password(&form.password, phc) => {
                Some((user, auth_row.must_change_password))
            }
            // 密码错：argon2 已执行，无需 dummy。
            Some(_) => None,
        },
        None => {
            password::dummy_verify(&form.password);
            None
        }
    };

    let Some((user, must_change)) = outcome else {
        audit_auth_event(
            &app,
            &username,
            "",
            "login_failure",
            None,
            &auth_failure_detail("invalid_credentials", "password", &ip),
        )
        .await;
        let lang = lang_from_headers(&headers);
        return login_failure_page(
            &app,
            &headers,
            LoginMode::Password,
            &username,
            form.next.as_deref(),
            t(lang, TextKey::LoginInvalidCredentials).to_string(),
        )
        .await;
    };

    // 账号状态在密码验证之后检查：argon2 在所有失败路径上都已执行过一次。
    if user.status != "active" {
        audit_auth_event(
            &app,
            &username,
            "",
            "login_failure",
            None,
            &auth_failure_detail("user_disabled", "password", &ip),
        )
        .await;
        let lang = lang_from_headers(&headers);
        return login_failure_page(
            &app,
            &headers,
            LoginMode::Password,
            &username,
            form.next.as_deref(),
            t(lang, TextKey::LoginInvalidCredentials).to_string(),
        )
        .await;
    }

    audit_auth_event(
        &app,
        &user.name,
        &user.role,
        "login_success",
        None,
        &auth_detail("password", &ip),
    )
    .await;

    // must_change → 密码登录改跳 /ui/me?must_change=1（替代 next；横幅常驻 /ui/me，
    // 参数只作一次性 flash）；token 登录不重定向——看不到横幅，admin 撤 token 逼改。
    let next = if must_change {
        "/ui/me?must_change=1".to_string()
    } else {
        safe_back_path(form.next.as_deref())
            .map(str::to_string)
            .unwrap_or_else(|| "/ui/".to_string())
    };

    issue_session_response(&app, &user, &headers, &next).await
}

/// 签发独立 UI 会话并 303 到 `next`（密码登录与注册直登共用）。副作用：懒删该用户
/// 过期 session 行 → 生成 `crbs_sess_` secret → 落 sessions 表（只存 SHA-256）→
/// cookie 三连：种 `crbs_session`，清 `crbs_token`（切模式清对方）+ `crbs_login_nonce`。
pub(crate) async fn issue_session_response(
    app: &AppState,
    user: &User,
    headers: &HeaderMap,
    next: &str,
) -> Result<(StatusCode, HeaderMap, Markup), ApiError> {
    if let Err(e) = app
        .state_store
        .delete_expired_user_sessions(user.id, &chrono::Utc::now().to_rfc3339())
        .await
    {
        tracing::warn!(user_id = user.id, error = %e, "Failed to lazy-clean expired sessions on login");
    }

    // 明文 secret 只在本次响应出现，DB 只存 SHA-256。
    let secret = Secret::generate(SecretKind::Session)
        .map_err(|e| ApiError::log_and_internal_with_context("generate session secret", e))?;
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(SESSION_MAX_AGE_SECS);
    let agent = user_agent_truncated(headers);
    app.state_store
        .create_session(
            user.id,
            secret.hash().as_str(),
            &expires_at.to_rfc3339(),
            agent.as_deref(),
        )
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Failed to create login session");
            ApiError::Internal("failed to create login session".into())
        })?;

    let mut resp_headers = HeaderMap::new();
    let session_cookie = format!(
        "crbs_session={}; HttpOnly; SameSite=Lax; Path=/{}; Max-Age={}",
        secret.as_str(),
        cookie_secure_suffix(app),
        SESSION_MAX_AGE_SECS,
    );
    resp_headers.append(
        header::SET_COOKIE,
        session_cookie
            .parse()
            .map_err(|_| ApiError::Internal("failed to build Set-Cookie header".into()))?,
    );
    let clear_token = format!(
        "crbs_token=; HttpOnly; SameSite=Lax; Path=/{}; Max-Age=0",
        cookie_secure_suffix(app),
    );
    resp_headers.append(
        header::SET_COOKIE,
        clear_token
            .parse()
            .map_err(|_| ApiError::Internal("failed to build Set-Cookie header".into()))?,
    );
    let clear_nonce = format!(
        "{LOGIN_NONCE_COOKIE}=; HttpOnly; SameSite=Lax; Path=/ui/login{}; Max-Age=0",
        cookie_secure_suffix(app),
    );
    resp_headers.append(
        header::SET_COOKIE,
        clear_nonce
            .parse()
            .map_err(|_| ApiError::Internal("failed to build Set-Cookie header".into()))?,
    );
    resp_headers.insert(header::LOCATION, ascii_location_value(next));

    Ok((
        StatusCode::SEE_OTHER,
        resp_headers,
        redirect_body(lang_from_headers(headers)),
    ))
}

/// 查用户 + 认证行（密码列专用独立映射，password_hash 不进任何序列化输出）。
async fn fetch_login_user(
    app: &AppState,
    username: &str,
) -> Result<Option<(User, UserAuthRow)>, ApiError> {
    let user = app
        .state_store
        .find_user_by_name(username)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Login user lookup failed");
            ApiError::Internal("login failed".into())
        })?;
    // auth_row 缺失只可能是并发删用户，与"用户不存在"同路径（调用方补 dummy 验证）。
    let Some(user) = user else {
        return Ok(None);
    };
    let auth_row = app
        .state_store
        .get_user_auth_row(user.id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Login auth row lookup failed");
            ApiError::Internal("login failed".into())
        })?;
    Ok(auth_row.map(|row| (user, row)))
}

#[derive(serde::Deserialize)]
pub(crate) struct LoginTokenForm {
    token: String,
    csrf_token: Option<String>,
    next: Option<String>,
}

/// POST /ui/login/token：token 粘贴兼容模式（CLI/自动化用户）；限流、审计、
/// 登录前清 `crbs_session`（切模式清对方）。
pub(crate) async fn login_token_submit(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    connect_info: Option<Extension<ConnectInfo<std::net::SocketAddr>>>,
    Form(form): Form<LoginTokenForm>,
) -> Result<impl IntoResponse, ApiError> {
    let login_nonce = csrf::login_nonce_from_headers(&headers)
        .ok_or(ApiError::Unauthorized("missing login session".into()))?;
    let csrf_token = form
        .csrf_token
        .ok_or(ApiError::Unauthorized("missing CSRF token".into()))?;
    if !csrf::validate_login_csrf(&login_nonce, &app.csrf_key, &csrf_token)? {
        return Err(ApiError::PermissionDenied("invalid CSRF token".into()));
    }

    let ip = client_ip(connect_info.as_ref().map(|ext| &ext.0));
    if let Some(remaining) = app
        .login_limiter
        .check(&format!("ip:{ip}"), &token_mode_user_key(&form.token))
    {
        audit_auth_event(
            &app,
            "(token)",
            "",
            "login_failure",
            None,
            &auth_failure_detail("rate_limited", "token", &ip),
        )
        .await;
        let lang = lang_from_headers(&headers);
        return rate_limited_page(
            &headers,
            remaining,
            t(lang, TextKey::LoginTitle),
            "/ui/login",
            t(lang, TextKey::RegisterBackToLogin),
        )
        .await;
    }

    // 粘贴的 token 常带尾随换行/空白，认证与 Set-Cookie 必须用同一 trim 后的值。
    let token = form.token.trim().to_string();

    // DB 故障（Err → 503）`?` 上抛全局错误信封；Ok(None) 才是"token 无效"失败路径。
    let Some(ctx) = auth::authenticate_token(&app, &token).await? else {
        audit_auth_event(
            &app,
            "(token)",
            "",
            "login_failure",
            None,
            &auth_failure_detail("invalid_credentials", "token", &ip),
        )
        .await;
        let lang = lang_from_headers(&headers);
        return login_failure_page(
            &app,
            &headers,
            LoginMode::Token,
            "",
            form.next.as_deref(),
            t(lang, TextKey::LoginInvalidToken).to_string(),
        )
        .await;
    };

    // 回跳目标 POST 端再过一次白名单（表单可被外部构造），非法/缺失回退 /ui/。
    let next = safe_back_path(form.next.as_deref())
        .map(str::to_string)
        .unwrap_or_else(|| "/ui/".to_string());

    let max_age = ctx
        .token_expires_at
        .map(|exp| exp.signed_duration_since(chrono::Utc::now()).num_seconds())
        .filter(|&secs| secs > 0)
        .unwrap_or(SESSION_MAX_AGE_SECS);

    audit_auth_event(
        &app,
        &ctx.user,
        &ctx.role,
        "login_success",
        None,
        &auth_detail("token", &ip),
    )
    .await;

    let mut resp_headers = HeaderMap::new();
    let token_cookie = format!(
        "crbs_token={}; HttpOnly; SameSite=Lax; Path=/{}; Max-Age={}",
        token,
        cookie_secure_suffix(&app),
        max_age,
    );
    resp_headers.append(
        header::SET_COOKIE,
        token_cookie
            .parse()
            .map_err(|_| ApiError::Internal("failed to build Set-Cookie header".into()))?,
    );
    // 切模式登录前清对方 cookie（session 模式凭据一并失效的浏览器侧）。
    let clear_session = format!(
        "crbs_session=; HttpOnly; SameSite=Lax; Path=/{}; Max-Age=0",
        cookie_secure_suffix(&app),
    );
    resp_headers.append(
        header::SET_COOKIE,
        clear_session
            .parse()
            .map_err(|_| ApiError::Internal("failed to build Set-Cookie header".into()))?,
    );
    let clear_nonce = format!(
        "{LOGIN_NONCE_COOKIE}=; HttpOnly; SameSite=Lax; Path=/ui/login{}; Max-Age=0",
        cookie_secure_suffix(&app),
    );
    resp_headers.append(
        header::SET_COOKIE,
        clear_nonce
            .parse()
            .map_err(|_| ApiError::Internal("failed to build Set-Cookie header".into()))?,
    );
    resp_headers.insert(header::LOCATION, ascii_location_value(&next));

    Ok((
        StatusCode::SEE_OTHER,
        resp_headers,
        redirect_body(lang_from_headers(&headers)),
    ))
}

#[derive(serde::Deserialize)]
pub(crate) struct LogoutForm {
    csrf_token: Option<String>,
}

/// POST /ui/logout：登出（双模式）。CSRF 基值与渲染侧 `csrf_token_for_request` 同链
///（`crbs_session` 优先，回落 `crbs_token`，否则 nav logout 表单失配）；session 模式
/// 真撤销（revoke_session），token 模式只清浏览器侧（token 撤销走 Admin/token 自管）。
pub(crate) async fn logout_submit(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    auth: Option<Extension<AuthContext>>,
    Form(form): Form<LogoutForm>,
) -> Result<impl IntoResponse, ApiError> {
    let csrf_base = csrf::csrf_base_from_headers(&headers)
        .ok_or(ApiError::Unauthorized("missing session".into()))?;
    let csrf_token = form
        .csrf_token
        .ok_or(ApiError::Unauthorized("missing CSRF token".into()))?;
    if !csrf::validate_csrf_token(&csrf_base, &app.csrf_key, &csrf_token)? {
        return Err(ApiError::PermissionDenied("invalid CSRF token".into()));
    }

    // 查不到/已撤销/过期 → 幂等登出（cookie 仍清）；DB 故障只 warn 不阻断——最坏
    // 情况是会话行残留至绝对过期/周期清理，浏览器侧凭据已清空。
    if let Some(session_value) = csrf::session_cookie_from_headers(&headers) {
        if let Ok(secret) = Secret::parse(&session_value) {
            match app
                .state_store
                .find_session_by_hash(secret.hash().as_str())
                .await
            {
                Ok(Some(row)) if row.is_active(chrono::Utc::now()) => {
                    if let Err(e) = app.state_store.revoke_session(row.id).await {
                        tracing::warn!(session_id = row.id, error = %e, "Failed to revoke session on logout");
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "Session lookup failed on logout; cookie will still be cleared");
                }
            }
        }
    }

    // 审计 actor：optional_auth 中间件已注入的 AuthContext（无凭据时跳过）。
    if let Some(ctx) = auth.as_ref().map(|ext| &ext.0) {
        if !ctx.user.is_empty() {
            audit_auth_event(&app, &ctx.user, &ctx.role, "logout", None, "{}").await;
        }
    }

    let mut resp_headers = HeaderMap::new();
    for name in ["crbs_session", "crbs_token"] {
        let cookie = format!(
            "{name}=; HttpOnly; SameSite=Lax; Path=/{}; Max-Age=0",
            cookie_secure_suffix(&app),
        );
        resp_headers.append(
            header::SET_COOKIE,
            cookie
                .parse()
                .map_err(|_| ApiError::Internal("failed to build Set-Cookie header".into()))?,
        );
    }
    resp_headers.insert(
        header::LOCATION,
        "/ui/login"
            .parse()
            .map_err(|_| ApiError::Internal("failed to build Location header".into()))?,
    );

    Ok((
        StatusCode::SEE_OTHER,
        resp_headers,
        redirect_body(lang_from_headers(&headers)),
    ))
}

#[cfg(test)]
mod tests {
    use super::token_mode_user_key;

    /// token 模式用户轴按哈希前缀分桶：同 token（含 trim 后等值，与认证口径一致）稳定
    /// 同桶，不同 token 不同桶；IP 轴兜底不变（LoginRateLimiter::check 双轴计数）。
    #[test]
    fn token_mode_user_key_buckets_per_token() {
        let a1 = token_mode_user_key("crbs_tok_aaaa");
        let a2 = token_mode_user_key("crbs_tok_aaaa");
        let a3 = token_mode_user_key("  crbs_tok_aaaa\n");
        let b = token_mode_user_key("crbs_tok_bbbb");
        assert_eq!(a1, a2, "same token must share one bucket");
        assert_eq!(a1, a3, "trimmed token is the same credential");
        assert_ne!(a1, b, "different tokens must not share a bucket");
        assert!(a1.starts_with("user:tok:"), "{a1}");
    }
}
