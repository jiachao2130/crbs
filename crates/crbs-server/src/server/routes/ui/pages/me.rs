// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 个人中心 /ui/me：身份条 + 个人总览带 + 四卡（安全 / API tokens / 我的产品 / 最近任务）。
//!
//! - 门控：已认证（匿名 401）；`user_id` 为 None（worker / 特殊凭据）渲染
//!   简短"此凭据无账户页"提示（200），不出四卡。
//! - must_change：admin 置位后常驻顶部横幅（改密成功即消失）；登录侧
//!   `?must_change=1` 只作一次性 flash 提示。
//! - 校验失败 flash 按页面语言本地化，不走 `?error=` 原文通道。

use super::{
    phase_count, phase_counts_from_series, rel_time_lang, success_rate_gauge, BUILD_DURATION_BARS,
    SUCCESS_RATE_WINDOW,
};
use crate::server::auth::AuthContext;
use crate::server::csrf;
use crate::server::error::ApiError;
use crate::server::routes::ui::components::{
    confirm_button, confirm_button_ghost, duration_chart, empty_state, format_local_time,
    gauge_chart, generate_nonce, internal_error_flash, list_page_head, no_store, page_with_csp,
    phase_badge, secret_reveal_box, see_other_error_redirect, see_other_redirect, stat_strip,
    status_message, storage_error_flash, user_status_badge, StatStripItem, StatusQuery,
};
use crate::server::routes::ui::i18n::{lang_from_headers, role_label, t, t_fmt, FmtKey, TextKey};
use crate::server::routes::ui::service::{
    audit_ui_event, csrf_token_for_request, require_session, CancelForm,
};
use crate::server::state::AppState;
use axum::extract::{Extension, Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use crbs_core::auth::password;
use crbs_core::auth::secret::{Secret, SecretHash, SecretKind};
use crbs_core::SessionRecord;
use maud::html;
use std::sync::Arc;

/// Recent tasks 卡行数。
const ME_RECENT_TASKS: usize = 5;

/// 令牌卡展示封顶：活跃 token 新→旧最多列 10 条，超出底部提示计数（总览带活跃计数不受此截断）。
const ME_TOKENS_LIMIT: i64 = 10;

/// /ui/me GET 查询参数：StatusQuery 的 flash 通道 + `?must_change=1`。
#[derive(serde::Deserialize, Default)]
pub(crate) struct MeQuery {
    pub status: Option<String>,
    pub error: Option<String>,
    pub es: Option<String>,
    /// 密码登录且 must_change 置位时的跳转标记：仅作一次性 flash。
    pub must_change: Option<String>,
}

/// 从请求头的 `crbs_session` cookie 值计算会话行匹配用的 SHA-256 hex；与认证路径
/// `resolve_session_value` 同一算法（`Secret::parse().hash()`），无 cookie / 坏格式 → None。
fn current_session_hash(headers: &HeaderMap) -> Option<String> {
    let value = csrf::session_cookie_from_headers(headers)?;
    let secret = Secret::parse(&value).ok()?;
    Some(secret.hash().as_str().to_string())
}

/// 在已取会话行中定位当前会话 id（hash 匹配 + 行仍活跃；否则 None）；
/// 已持有 `list_user_sessions` 结果的调用方直接用本函数，不同参重查。
fn find_current_session_id(sessions: &[SessionRecord], hash: &str) -> Option<i64> {
    sessions
        .iter()
        .find(|s| s.hash == hash && s.is_active(chrono::Utc::now()))
        .map(|s| s.id)
}

/// 查当前会话行 id（session 模式且行仍属于该用户且活跃；否则 None）。
async fn current_session_id(
    app: &AppState,
    headers: &HeaderMap,
    user_id: i64,
) -> Result<Option<i64>, ApiError> {
    let Some(hash) = current_session_hash(headers) else {
        return Ok(None);
    };
    let rows = app
        .state_store
        .list_user_sessions(user_id)
        .await
        .map_err(|e| {
            tracing::warn!(user_id, error = %e, "Failed to list sessions for /ui/me");
            ApiError::Internal("failed to list sessions".into())
        })?;
    Ok(find_current_session_id(&rows, &hash))
}

/// RFC3339 → 本地时间短格式：sessions/tokens.expires_at 是应用写入的 RFC3339 UTC，
/// `format_local_time` 只认 DB 墙钟帧，这里补本地化；解析失败回退原串。
fn fmt_rfc3339_local(s: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| {
            dt.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|| s.to_string())
}

/// 凭据型 AuthContext（token 直达、无账号行）的用户 id：me 页各写路径的
/// 统一门（同一文案 PermissionDenied）。
fn require_user_id(ctx: &AuthContext) -> Result<i64, ApiError> {
    ctx.user_id
        .ok_or_else(|| ApiError::PermissionDenied("this credential has no account".into()))
}

pub(crate) async fn me_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<MeQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = auth
        .as_ref()
        .map(|ext| &ext.0)
        .ok_or_else(|| ApiError::Unauthorized("authentication required".into()))?
        .clone();
    let lang = lang_from_headers(&headers);
    let nonce = generate_nonce()?;

    let Some(user_id) = ctx.user_id else {
        let body = html! {
            h1 { (t(lang, TextKey::MePageTitle)) }
            (empty_state(t(lang, TextKey::MeNoAccountTitle), t(lang, TextKey::MeNoAccountHint)))
        };
        return page_with_csp(
            t(lang, TextKey::MePageTitle),
            &nonce,
            Some(&ctx),
            "",
            &headers,
            &app.csrf_key,
            body,
        );
    };

    let user = app.state_store.get_user(user_id).await.map_err(|e| {
        tracing::warn!(user_id, error = %e, "Failed to get user for /ui/me");
        ApiError::Internal("failed to get user".into())
    })?;
    let auth_row = app
        .state_store
        .get_user_auth_row(user_id)
        .await
        .map_err(|e| {
            tracing::warn!(user_id, error = %e, "Failed to get auth row for /ui/me");
            ApiError::Internal("failed to get auth row".into())
        })?;
    let must_change = auth_row.as_ref().is_some_and(|r| r.must_change_password);
    let has_password = auth_row.as_ref().is_some_and(|r| r.password_hash.is_some());

    let phase_counts = app
        .state_store
        .count_tasks_by_phase_for_user(&ctx.user)
        .await
        .map_err(ApiError::from)?;
    // 窗口只取一次相位序列：gauge 计数由序列 fold 同源同口径。
    let series = app
        .state_store
        .recent_task_phase_series_for_user(&ctx.user, SUCCESS_RATE_WINDOW)
        .await
        .map_err(ApiError::from)?;
    let recent_counts = phase_counts_from_series(&series);
    let durations = app
        .state_store
        .recent_succeeded_build_durations_for_user(&ctx.user, BUILD_DURATION_BARS)
        .await
        .map_err(ApiError::from)?;
    // 令牌卡只列活跃 token，新→旧封顶 ME_TOKENS_LIMIT；总览带计数用不受截断的 COUNT（已撤销不计）。
    let tokens = app
        .state_store
        .list_active_user_tokens(user_id, ME_TOKENS_LIMIT)
        .await
        .map_err(|e| {
            tracing::warn!(user_id, error = %e, "Failed to list tokens for /ui/me");
            ApiError::Internal("failed to list tokens".into())
        })?;
    let active_token_count = app
        .state_store
        .count_active_user_tokens(user_id)
        .await
        .map_err(|e| {
            tracing::warn!(user_id, error = %e, "Failed to count tokens for /ui/me");
            ApiError::Internal("failed to count tokens".into())
        })?;
    let owned_products = app
        .state_store
        .list_products_by_owner(user_id)
        .await
        .map_err(ApiError::from)?;
    let acls = app
        .state_store
        .list_product_acls(user_id)
        .await
        .map_err(|e| {
            tracing::warn!(user_id, error = %e, "Failed to list ACLs for /ui/me");
            ApiError::Internal("failed to list ACLs".into())
        })?;
    let session_mode = csrf::session_cookie_from_headers(&headers).is_some();
    let sessions = if session_mode {
        Some(
            app.state_store
                .list_user_sessions(user_id)
                .await
                .map_err(|e| {
                    tracing::warn!(user_id, error = %e, "Failed to list sessions for /ui/me");
                    ApiError::Internal("failed to list sessions".into())
                })?,
        )
    } else {
        None
    };
    // 当前会话 id 由会话卡已取的全量 sessions 派生，不同参重查；token 模式 sessions 为 None。
    let current_sid = sessions.as_deref().and_then(|rows| {
        current_session_hash(&headers).and_then(|hash| find_current_session_id(rows, &hash))
    });
    let (_recent_total, recent_tasks) = app
        .state_store
        .list_tasks(&crbs_core::types::TaskListFilter {
            user: Some(ctx.user.as_str()),
            limit: Some(ME_RECENT_TASKS),
            offset: Some(0),
            // 自己的任务自己可见：不做产品可见性过滤（宁选 None 的最小口径）。
            visible_products: None,
            ..Default::default()
        })
        .await
        .map_err(ApiError::from)?;

    let csrf_token = csrf_token_for_request(&headers, &app.csrf_key);

    // ── 个人总览带：5 项 strip + 成功率 gauge（口径同 home，走 pages 共享 helper）。
    let my_total: i64 = phase_counts.values().sum();
    let items = [
        StatStripItem {
            label: t(lang, TextKey::MeStatMyTasks),
            value: my_total.to_string(),
            ok: false,
            title: None,
        },
        StatStripItem {
            label: t(lang, TextKey::MeStatBuilding),
            value: phase_count(&phase_counts, "building").to_string(),
            ok: false,
            title: None,
        },
        StatStripItem {
            label: t(lang, TextKey::MeStatQueued),
            value: phase_count(&phase_counts, "pending").to_string(),
            ok: false,
            title: None,
        },
        StatStripItem {
            label: t(lang, TextKey::MeStatTokens),
            value: active_token_count.to_string(),
            ok: false,
            title: None,
        },
        StatStripItem {
            label: t(lang, TextKey::MeStatOwnedProducts),
            value: owned_products.len().to_string(),
            ok: false,
            title: None,
        },
    ];
    let (success_pct, gauge_side) = success_rate_gauge(&recent_counts, lang);

    let avatar_char = user
        .as_ref()
        .map(|u| u.name.clone())
        .unwrap_or_else(|| ctx.user.clone())
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "?".to_string());
    let identity_meta = if let Some(u) = &user {
        t_fmt(
            lang,
            FmtKey::MeUserSince,
            &[&u.id.to_string(), &format_local_time(&u.created_at)],
        )
    } else {
        format!("user #{}", user_id)
    };
    let cred_mode = if session_mode {
        t(lang, TextKey::MeCredModeSession)
    } else {
        t(lang, TextKey::MeCredModeToken)
    };

    let body = html! {
        // 页头条带只上标题不带 meta：身份/徽章/元信息归下方 me-band，避免重复。
        (list_page_head(
            html! { (t(lang, TextKey::MePageTitle)) },
            html! {},
            html! {},
        ))
        @if must_change {
            div class="message warning" role="alert" {
                (t(lang, TextKey::MeMustChangeBanner)) " "
                a href="#security" { (t(lang, TextKey::MePasswordChangeTitle)) " →" }
            }
        }
        @if q.must_change.as_deref() == Some("1") {
            div class="message warning" { (t(lang, TextKey::MeMustChangeFlash)) }
        }
        (status_message(
            &StatusQuery {
                status: q.status.clone(),
                error: q.error.clone(),
                es: q.es.clone(),
                back: None,
                range: None,
            },
            &app.csrf_key,
            lang,
        ))

        div class="me-band" {
            div class="avatar" aria-hidden="true" { (avatar_char) }
            div class="me-id" {
                div class="me-id-row" {
                    b { (ctx.user) }
                    // role 徽章走 role_label 显示名；机器值仍是权限判据，不直出裸枚举。
                    span class="badge accent" { (role_label(lang, &ctx.role)) }
                    @if let Some(u) = &user { (user_status_badge(&u.status, lang)) }
                }
                div class="me-meta" { (identity_meta) " · " (cred_mode) }
            }
        }

        div class="me-overview" {
            (stat_strip(&items, lang))
            (gauge_chart("me", success_pct, gauge_side, lang))
        }

        section class="viz-panel" {
            h3 { (t(lang, TextKey::PanelBuildDurations)) }
            div class="viz-fill" { (duration_chart(&durations, lang)) }
        }

        div class="me-grid" {
            section class="admin-section me-card" id="security" {
                h2 { (t(lang, TextKey::MeCardSecurity)) }
                h3 { @if has_password { (t(lang, TextKey::MePasswordChangeTitle)) } @else { (t(lang, TextKey::MePasswordSetTitle)) } }
                @if let Some(token) = csrf_token.as_ref() {
                    form class="form-card me-form" method="post" action="/ui/me/password" {
                        input type="hidden" name="csrf_token" value=(token);
                        @if has_password {
                            label { (t(lang, TextKey::MePasswordCurrent))
                                input type="password" name="current_password" autocomplete="current-password";
                            }
                        }
                        label { (t(lang, TextKey::MePasswordNew))
                            input type="password" name="new_password" autocomplete="new-password" required="";
                        }
                        p class="field-hint" {
                            @if has_password { (t(lang, TextKey::MePasswordChangeHint)) } @else { (t(lang, TextKey::MePasswordSetHint)) }
                        }
                        label { (t(lang, TextKey::MePasswordConfirm))
                            input type="password" name="confirm_password" autocomplete="new-password" required="";
                        }
                        @if has_password {
                            button class="action-button" type="submit" { (t(lang, TextKey::MePasswordChangeSubmit)) }
                        } @else {
                            button class="action-button" type="submit" { (t(lang, TextKey::MePasswordSetSubmit)) }
                        }
                    }
                } @else {
                    p { (t(lang, TextKey::SettingsSessionExpired)) " "
                        a href="/ui/login" { (t(lang, TextKey::ErrLoginCta)) } }
                }

                @if let Some(sessions) = sessions {
                    @let active: Vec<_> = sessions
                        .iter()
                        .filter(|s| s.is_active(chrono::Utc::now()))
                        .collect();
                    h3 { (t(lang, TextKey::MeCardSessions)) " "
                        span class="me-meta" { (t_fmt(lang, FmtKey::MeSessionsDeviceCount, &[&active.len().to_string()])) }
                    }
                    div class="table-wrap" {
                        table class="fixed" {
                            colgroup {
                                col style="width:38%" {}
                                col style="width:20%" {}
                                col class="col-time" {}
                                col style="width:20%" {}
                            }
                            thead {
                                tr {
                                    th { (t(lang, TextKey::MeSessionsDevice)) }
                                    th { (t(lang, TextKey::MeSessionsSignedIn)) }
                                    th { (t(lang, TextKey::MeSessionsExpires)) }
                                    th { (t(lang, TextKey::ThAction)) }
                                }
                            }
                            tbody {
                                @for s in &active {
                                    tr {
                                        td class="ellipsis" title=(s.agent.as_deref().unwrap_or("—")) {
                                            (s.agent.as_deref().unwrap_or(t(lang, TextKey::MeSessionsUnknownDevice)))
                                            @if Some(s.id) == current_sid {
                                                " " span class="badge success" { (t(lang, TextKey::MeSessionCurrent)) }
                                            }
                                        }
                                        td { (rel_time_lang(Some(s.created_at.as_str()), lang)) }
                                        td { (fmt_rfc3339_local(&s.expires_at)) }
                                        td {
                                            @if let Some(token) = csrf_token.as_ref() {
                                                @if Some(s.id) == current_sid {
                                                    form class="action-form" method="post" action="/ui/logout" {
                                                        input type="hidden" name="csrf_token" value=(token);
                                                        (confirm_button_ghost(t(lang, TextKey::MeSessionLogoutCurrent), t(lang, TextKey::MeSessionRevokeConfirm)))
                                                    }
                                                } @else {
                                                    form class="action-form" method="post" action=(format!("/ui/me/sessions/{}/revoke", s.id)) {
                                                        input type="hidden" name="csrf_token" value=(token);
                                                        (confirm_button_ghost(t(lang, TextKey::MeSessionRevoke), t(lang, TextKey::MeSessionRevokeConfirm)))
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    @if let Some(token) = csrf_token.as_ref() {
                        @if active.len() > 1 {
                            form class="action-form" method="post" action="/ui/me/sessions/revoke-all" {
                                input type="hidden" name="csrf_token" value=(token);
                                (confirm_button(t(lang, TextKey::MeSessionsSignOutAll), t(lang, TextKey::MeSessionsSignOutAllConfirm)))
                            }
                        }
                    }
                } @else {
                    p class="field-hint" { (t(lang, TextKey::MeSessionsTokenModeNote)) }
                }
            }

            section class="admin-section me-card" {
                h2 { (t(lang, TextKey::MeCardTokens)) }
                @if let Some(token) = csrf_token.as_ref() {
                    form class="form-card me-form" method="post" action="/ui/me/tokens" {
                        input type="hidden" name="csrf_token" value=(token);
                        label { (t(lang, TextKey::MeTokenName))
                            input type="text" name="name" required="" placeholder=(t(lang, TextKey::MeTokenNamePlaceholder));
                        }
                        label { (t(lang, TextKey::MeTokenExpiresIn))
                            select name="expires_in_days" {
                                option value="30" { (t_fmt(lang, FmtKey::MeTokenDays, &["30"])) }
                                option value="90" selected { (t_fmt(lang, FmtKey::MeTokenDays, &["90"])) }
                                option value="180" { (t_fmt(lang, FmtKey::MeTokenDays, &["180"])) }
                                option value="365" { (t_fmt(lang, FmtKey::MeTokenDays, &["365"])) }
                                option value="3650" { (t_fmt(lang, FmtKey::MeTokenDays, &["3650"])) }
                            }
                        }
                        button class="action-button" type="submit" { (t(lang, TextKey::MeTokenCreate)) }
                    }
                }
                @if tokens.is_empty() {
                    (empty_state(t(lang, TextKey::MeTokenEmptyTitle), t(lang, TextKey::MeTokenEmptyHint)))
                } @else {
                    div class="table-wrap" {
                        table class="fixed" {
                            colgroup {
                                col style="width:auto" {}
                                col style="width:22%" {}
                                col class="col-time" {}
                                col style="width:16%" {}
                            }
                            thead {
                                tr {
                                    th { (t(lang, TextKey::MeTokenName)) }
                                    th { (t(lang, TextKey::MeSessionsSignedIn)) }
                                    th { (t(lang, TextKey::MeSessionsExpires)) }
                                    th { (t(lang, TextKey::ThAction)) }
                                }
                            }
                            tbody {
                                @for tok in &tokens {
                                    tr {
                                        td class="ellipsis" title=(tok.name.as_deref().unwrap_or("—")) { (tok.name.as_deref().unwrap_or("—")) }
                                        td { (rel_time_lang(Some(tok.created_at.as_str()), lang)) }
                                        td { (tok.expires_at.as_deref().map(fmt_rfc3339_local).unwrap_or_else(|| t(lang, TextKey::MeTokenNever).to_string())) }
                                        td {
                                            @if let Some(token) = csrf_token.as_ref() {
                                                form class="action-form" method="post" action=(format!("/ui/me/tokens/{}/revoke", tok.id)) {
                                                    input type="hidden" name="csrf_token" value=(token);
                                                    (confirm_button_ghost(t(lang, TextKey::MeTokenDelete), t(lang, TextKey::MeTokenRevokeConfirm)))
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    @let hidden = active_token_count - tokens.len() as i64;
                    @if hidden > 0 {
                        p class="field-hint" { (t_fmt(lang, FmtKey::MeTokensMoreHidden, &[&hidden.to_string()])) }
                    }
                }
            }

            section class="admin-section me-card" {
                div class="section-heading" {
                    h2 { (t(lang, TextKey::MeCardProducts)) }
                    span class="spacer" { }
                    a href="/ui/products" { (t(lang, TextKey::MeAllProducts)) }
                }
                @if owned_products.is_empty() && acls.is_empty() {
                    (empty_state(t(lang, TextKey::MeProductsEmptyTitle), t(lang, TextKey::MeProductsEmptyHint)))
                } @else {
                    div class="table-wrap" {
                        table class="fixed" {
                            colgroup {
                                col style="width:auto" {}
                                col style="width:32%" {}
                                col style="width:16%" {}
                            }
                            thead {
                                tr {
                                    th { (t(lang, TextKey::ThProduct)) }
                                    th { (t(lang, TextKey::MeProductRelation)) }
                                    th class="num" { (t(lang, TextKey::MeRevision)) }
                                }
                            }
                            tbody {
                                @for p in &owned_products {
                                    tr {
                                        td class="ellipsis" title=(p.name) { a href=(format!("/ui/products/{}", urlencoding::encode(&p.name))) { (p.name) } }
                                        td { span class="badge accent" { (t(lang, TextKey::MeRelationOwner)) } }
                                        td class="num" { "r" (p.revision) }
                                    }
                                }
                                @for a in &acls {
                                    // owner 已覆盖的产品不重复列（owner 关系更强）。
                                    @if !owned_products.iter().any(|p| p.name == a.product) {
                                        tr {
                                            td class="ellipsis" title=(a.product) { a href=(format!("/ui/products/{}", urlencoding::encode(&a.product))) { (a.product) } }
                                            td { span class="badge" { (role_label(lang, &a.role)) } " " span class="via-acl" { (t(lang, TextKey::MeViaAcl)) } }
                                            td class="num" { "—" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            section class="admin-section me-card" {
                div class="section-heading" {
                    h2 { (t(lang, TextKey::SectionRecentTasks)) }
                    span class="spacer" { }
                    a href="/ui/tasks" { (t(lang, TextKey::ViewAllTasks)) }
                }
                @if recent_tasks.is_empty() {
                    (empty_state(t(lang, TextKey::EmptyRecentTitle), t(lang, TextKey::EmptyRecentHint)))
                } @else {
                    div class="table-wrap" {
                        table class="fixed" {
                            colgroup {
                                col style="width:14%" {}
                                col style="width:auto" {}
                                col style="width:20%" {}
                                col style="width:20%" {}
                            }
                            thead {
                                tr {
                                    th class="num" { (t(lang, TextKey::ThId)) }
                                    th { (t(lang, TextKey::ThPackage)) }
                                    th { (t(lang, TextKey::ThPhase)) }
                                    th class="num" { (t(lang, TextKey::ThSubmitted)) }
                                }
                            }
                            tbody {
                                @for task in &recent_tasks {
                                    tr {
                                        td class="num" { a href=(format!("/ui/tasks/{}", task.id)) { (task.id) } }
                                        td class="ellipsis" title=(task.pkg_name) { (task.pkg_name) }
                                        td { (phase_badge(&task.phase, lang)) }
                                        td class="num" { (rel_time_lang(task.submitted_at.as_deref(), lang)) }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    page_with_csp(
        t(lang, TextKey::MePageTitle),
        &nonce,
        Some(&ctx),
        "",
        &headers,
        &app.csrf_key,
        body,
    )
}

/// 改密失败分类：校验类在渲染处按页面语言取双语 flash 文案；策略错误映射注册页 RegisterPasswordToo* 双语模板。
enum MePasswordError {
    CurrentPasswordIncorrect,
    NewPasswordMismatch,
    Policy(password::PasswordPolicyError),
    /// 会话指向的用户无 auth 行（异常态）：复用通用失败文案，不泄露细节。
    UserNotFound,
    /// 已是 `?status=` 机器码的存储/内部错误（storage_error_flash / internal_error_flash 产物）：
    /// 原样透传，see_other_error_redirect 自行改道 `?status=` 双语 flash。
    Status(String),
}

/// 改密表单（token-only 用户无 Current password 字段）。
#[derive(serde::Deserialize)]
pub(crate) struct MePasswordForm {
    pub csrf_token: String,
    pub current_password: Option<String>,
    pub new_password: String,
    pub confirm_password: String,
}

/// POST /ui/me/password：改密 + 连锁撤销其它会话 + must_change 清零；
/// 校验失败 flash 按页面语言本地化（[`MePasswordError`] → 双语表）。
pub(crate) async fn me_password_submit(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<MePasswordForm>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = require_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form.csrf_token,
        &app.csrf_key,
    )?;
    let user_id = require_user_id(&ctx)?;
    let lang = lang_from_headers(&headers);
    let result: Result<(), MePasswordError> = async {
        let auth_row = app
            .state_store
            .get_user_auth_row(user_id)
            .await
            .map_err(|e| MePasswordError::Status(storage_error_flash("get auth row", &e)))?
            .ok_or(MePasswordError::UserNotFound)?;
        // 有旧密码才校验 Current password（token-only 无此字段）；缺失按空串 → 同一失败文案（不泄露哪个错）。
        if let Some(phc) = auth_row.password_hash.as_deref() {
            if !password::verify_password(form.current_password.as_deref().unwrap_or(""), phc) {
                return Err(MePasswordError::CurrentPasswordIncorrect);
            }
        }
        if form.new_password != form.confirm_password {
            return Err(MePasswordError::NewPasswordMismatch);
        }
        password::validate_password_policy(&form.new_password).map_err(MePasswordError::Policy)?;
        let hash = password::hash_password(&form.new_password)
            .map_err(|e| MePasswordError::Status(internal_error_flash("hash password", &e)))?;
        // must_change 传 false：自改即清零重置标志。
        app.state_store
            .set_user_password(user_id, &hash, false)
            .await
            .map_err(|e| MePasswordError::Status(storage_error_flash("set password", &e)))?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => {
            // 连锁撤销：session 模式保留本机；token 模式（无当前会话）全部撤销。
            // 定位本机失败时 fail-closed 全部撤销（宁可过度撤销，flash 才属实）。
            let revoke = match current_session_id(&app, &headers, user_id).await {
                Ok(Some(keep)) => {
                    app.state_store
                        .revoke_all_user_sessions_except(user_id, keep)
                        .await
                }
                Ok(None) => app.state_store.revoke_all_user_sessions(user_id).await,
                Err(e) => {
                    tracing::warn!(user_id, error = ?e, "Failed to locate current session; revoking all sessions");
                    app.state_store.revoke_all_user_sessions(user_id).await
                }
            };
            if let Err(e) = revoke {
                tracing::warn!(user_id, error = %e, "Failed to revoke other sessions on password change");
            }
            audit_ui_event(
                &app,
                &ctx,
                "password_change",
                &user_id.to_string(),
                Some("{}"),
            )
            .await;
            see_other_redirect("/ui/me?status=password_changed")
        }
        Err(e) => {
            let msg = match e {
                // 机器码直通，改道 ?status= 双语 flash。
                MePasswordError::Status(code) => code,
                MePasswordError::CurrentPasswordIncorrect => {
                    t(lang, TextKey::MePasswordCurrentIncorrect).to_string()
                }
                // 复用注册页同文案（两次输入不一致）。
                MePasswordError::NewPasswordMismatch => {
                    t(lang, TextKey::RegisterPasswordMismatch).to_string()
                }
                MePasswordError::Policy(e) => match e {
                    password::PasswordPolicyError::TooShort { min } => {
                        t_fmt(lang, FmtKey::RegisterPasswordTooShort, &[&min.to_string()])
                    }
                    password::PasswordPolicyError::TooLong { max } => {
                        t_fmt(lang, FmtKey::RegisterPasswordTooLong, &[&max.to_string()])
                    }
                },
                MePasswordError::UserNotFound => t(lang, TextKey::FlashOperationFailed).to_string(),
            };
            see_other_error_redirect("/ui/me", &msg, &app.csrf_key)
        }
    }
}

/// POST /ui/me/sessions/{sid}/revoke：撤销自己的一台设备。行查找限定在
/// `list_user_sessions(自己)` 内——sid 属于他人时不在结果里 → 404，绝不按 id 直删。
pub(crate) async fn me_session_revoke(
    State(app): State<Arc<AppState>>,
    Path(sid): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<CancelForm>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = require_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form.csrf_token,
        &app.csrf_key,
    )?;
    let user_id = require_user_id(&ctx)?;
    let sessions = app
        .state_store
        .list_user_sessions(user_id)
        .await
        .map_err(|e| {
            tracing::warn!(user_id, error = %e, "Failed to list sessions for revoke");
            ApiError::Internal("failed to list sessions".into())
        })?;
    let row = sessions
        .into_iter()
        .find(|s| s.id == sid)
        .ok_or_else(|| ApiError::not_found("session", sid))?;
    app.state_store.revoke_session(row.id).await.map_err(|e| {
        tracing::warn!(session_id = sid, error = %e, "Failed to revoke session");
        ApiError::Internal("failed to revoke session".into())
    })?;
    audit_ui_event(&app, &ctx, "session_revoke", &sid.to_string(), Some("{}")).await;
    see_other_redirect("/ui/me?status=sessions_revoked")
}

/// POST /ui/me/sessions/revoke-all：除本机外全部登出。
pub(crate) async fn me_sessions_revoke_all(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<CancelForm>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = require_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form.csrf_token,
        &app.csrf_key,
    )?;
    let user_id = require_user_id(&ctx)?;
    // 撤销是安全操作，两段 DB 失败均 fail-closed：绝不跳过撤销仍报成功
    // （password 路径同前置口径）。
    let revoke = match current_session_id(&app, &headers, user_id).await {
        Ok(Some(keep)) => {
            app.state_store
                .revoke_all_user_sessions_except(user_id, keep)
                .await
        }
        Ok(None) => app.state_store.revoke_all_user_sessions(user_id).await,
        Err(e) => {
            return see_other_error_redirect(
                "/ui/me",
                &storage_error_flash("locate current session for revoke-all", e.message()),
                &app.csrf_key,
            );
        }
    };
    if let Err(e) = revoke {
        return see_other_error_redirect(
            "/ui/me",
            &storage_error_flash("revoke all sessions", &e),
            &app.csrf_key,
        );
    }
    audit_ui_event(
        &app,
        &ctx,
        "session_revoke",
        &user_id.to_string(),
        Some(r#"{"all":true}"#),
    )
    .await;
    see_other_redirect("/ui/me?status=sessions_revoked")
}

/// 创建 token 表单（Name 必填 + 有效期下拉）。
#[derive(serde::Deserialize)]
pub(crate) struct MeTokenForm {
    pub csrf_token: String,
    pub name: String,
    pub expires_in_days: Option<u32>,
}

/// POST /ui/me/tokens：创建 token → 一次性 secret_reveal_box 页面（no-store）。
pub(crate) async fn me_token_create(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<MeTokenForm>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = require_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form.csrf_token,
        &app.csrf_key,
    )?;
    let user_id = require_user_id(&ctx)?;
    let lang = lang_from_headers(&headers);
    let name = form.name.trim().to_string();
    if name.is_empty() {
        return see_other_error_redirect(
            "/ui/me",
            t(lang, TextKey::MeTokenNameEmpty),
            &app.csrf_key,
        );
    }
    // clamp：与 admin_token_create 同口径（防超大天数让 chrono 越界）；
    // 实际过期与审计 detail 共用同一值，防双源漂移。
    let expires_days = form.expires_in_days.unwrap_or(90).min(3650);
    let result: Result<(String, i64), String> = async {
        // 重名预检必须查全量（含 revoked 同名行）——UNIQUE(user_id, name) 部分索引把
        // 已撤销行也算进名字空间，active-only 视图会漏判（提交后撞 UNIQUE）。
        let name_taken = app
            .state_store
            .list_user_tokens(user_id)
            .await
            .map_err(|e| storage_error_flash("list user tokens", &e))?
            .iter()
            .any(|t| t.name.as_deref() == Some(name.as_str()));
        if name_taken {
            return Err(t(lang, TextKey::MeTokenNameInUse).to_string());
        }
        let secret = Secret::generate(SecretKind::UserToken)
            .map_err(|e| internal_error_flash("generate token", &e))?;
        let hash = SecretHash::from_plain(secret.as_str());
        let days = expires_days as i64;
        let expires_at = (chrono::Utc::now() + chrono::Duration::days(days)).to_rfc3339();
        let id = app
            .state_store
            .create_user_token(user_id, Some(&name), hash.as_str(), Some(&expires_at))
            .await
            .map_err(|e| {
                // 预检后的并发撞库（UNIQUE 冲突）与预检同文案直显；其余 storage_error_flash。
                if crbs_core::is_unique_violation(&e) {
                    t(lang, TextKey::MeTokenNameInUse).to_string()
                } else {
                    storage_error_flash("create user token", &e)
                }
            })?;
        Ok((secret.as_str().to_string(), id))
    }
    .await;
    let (secret, id) = match result {
        Ok(v) => v,
        Err(msg) => return see_other_error_redirect("/ui/me", &msg, &app.csrf_key),
    };
    let detail = serde_json::json!({
        "user_id": user_id,
        "name": name,
        "expires_in_days": expires_days,
    })
    .to_string();
    audit_ui_event(
        &app,
        &ctx,
        "create_user_token",
        &id.to_string(),
        Some(&detail),
    )
    .await;
    // 一次性展示页：明文 token 只出现一次，禁止任何缓存存储。
    let nonce = generate_nonce()?;
    let body = html! {
        h1 { (t(lang, TextKey::MeTokenCreatedTitle)) }
        p { (t(lang, TextKey::MeTokenName)) ": " b { (name) } " · ID " (id) }
        (secret_reveal_box(&secret, &nonce, lang))
        p { a href="/ui/me" { (t(lang, TextKey::MeTokenCreatedBack)) } }
    };
    let page = page_with_csp(
        t(lang, TextKey::MeTokenCreatedTitle),
        &nonce,
        Some(&ctx),
        "",
        &headers,
        &app.csrf_key,
        body,
    )?;
    Ok(no_store(page))
}

/// POST /ui/me/tokens/{tid}/revoke：撤销自己的 token——列表内查找（他人 id → 404），绝不按 id 直删。
pub(crate) async fn me_token_revoke(
    State(app): State<Arc<AppState>>,
    Path(tid): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<CancelForm>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = require_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form.csrf_token,
        &app.csrf_key,
    )?;
    let user_id = require_user_id(&ctx)?;
    let tokens = app
        .state_store
        .list_user_tokens(user_id)
        .await
        .map_err(|e| {
            tracing::warn!(user_id, error = %e, "Failed to list tokens for revoke");
            ApiError::Internal("failed to list tokens".into())
        })?;
    let token = tokens
        .into_iter()
        .find(|t| t.id == tid)
        .ok_or_else(|| ApiError::not_found("token", tid))?;
    app.state_store
        .revoke_user_token(token.id)
        .await
        .map_err(|e| {
            tracing::warn!(token_id = tid, error = %e, "Failed to revoke token");
            ApiError::Internal("failed to revoke token".into())
        })?;
    audit_ui_event(
        &app,
        &ctx,
        "revoke_user_token",
        &tid.to_string(),
        Some(&user_id.to_string()),
    )
    .await;
    see_other_redirect("/ui/me?status=token_revoked")
}
