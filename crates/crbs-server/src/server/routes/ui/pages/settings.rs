// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL v2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Admin 设置页：注册开关卡片。
//! GET `/ui/admin/settings`（admin 门控）展示开关当前态 + 切换表单；POST 经
//! `require_admin_session`（CSRF + admin）写 app_meta KV（运行时生效）→ 审计
//! → 303 回 `?status=saved`；CSRF 走 `csrf_token_for_request`（session/token 双模式派生链）。

use super::register::registration_enabled;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::ui::components::{
    generate_nonce, list_page_head, page_with_csp, redirect_body,
};
use crate::server::routes::ui::i18n::{lang_from_headers, t, TextKey};
use crate::server::routes::ui::service::{csrf_token_for_request, require_admin_session};
use crate::server::state::AppState;
use axum::extract::{Extension, Form, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use maud::html;
use std::sync::Arc;

/// 注册开关 app_meta key（与 register.rs 共用值域；只写，读走 registration_enabled fail-closed）。
const REGISTRATION_ENABLED_KEY: &str = "registration_enabled";

use super::require_admin_page;

#[derive(serde::Deserialize, Default)]
pub(crate) struct SettingsQuery {
    pub status: Option<String>,
}

/// GET /ui/admin/settings。
pub(crate) async fn settings_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<SettingsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin_page(auth.as_ref().map(|ext| &ext.0))?;
    let lang = lang_from_headers(&headers);
    let registration_open = registration_enabled(&app).await;
    let csrf_token = csrf_token_for_request(&headers, &app.csrf_key);
    let nonce = generate_nonce()?;

    let body = html! {
        // 页头条带：标题 + 开关态 badge meta；设置页无主操作，actions 留空。
        (list_page_head(
            html! { (t(lang, TextKey::SettingsTitle)) },
            html! {
                (t(lang, TextKey::SettingsRegistrationCardTitle))
                span class="sep" { "·" }
                span class=(if registration_open { "badge success" } else { "badge" }) {
                    (t(lang, if registration_open {
                        TextKey::SettingsRegistrationStateOpen
                    } else {
                        TextKey::SettingsRegistrationStateClosed
                    }))
                }
            },
            html! {},
        ))
        @if q.status.as_deref() == Some("saved") {
            div class="message success" { (t(lang, TextKey::SettingsSavedMessage)) }
        }
        div class="admin-section" {
            h2 { (t(lang, TextKey::SettingsRegistrationCardTitle)) }
            p class="settings-desc" { (t(lang, TextKey::SettingsRegistrationCardDesc)) }
            @if let Some(token) = csrf_token.as_ref() {
                // 不走 .inline-filter 过滤条皮肤（本表单非过滤器），控件用全局 label/button + .radio-label。
                form method="post" action="/ui/admin/settings" {
                    input type="hidden" name="csrf_token" value=(token);
                    label class="radio-label" {
                        input type="checkbox" name="registration_enabled"
                            checked[registration_open] {}
                        " " (t(lang, TextKey::SettingsRegistrationToggleLabel))
                    }
                    button type="submit" { (t(lang, TextKey::SettingsSaveButton)) }
                }
            } @else {
                p {
                    (t(lang, TextKey::SettingsSessionExpired)) " "
                    a href="/ui/login" { (t(lang, TextKey::ErrLoginCta)) }
                }
            }
        }
    };
    page_with_csp(
        t(lang, TextKey::SettingsTitle),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "admin",
        &headers,
        &app.csrf_key,
        body,
    )
}

#[derive(serde::Deserialize)]
pub(crate) struct SettingsForm {
    csrf_token: String,
    /// checkbox：勾选="on"，未勾选不出现在表单里 → Option。
    registration_enabled: Option<String>,
}

/// POST /ui/admin/settings：切换注册开关 + 审计。
pub(crate) async fn settings_submit(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<SettingsForm>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = require_admin_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form.csrf_token,
        &app.csrf_key,
    )?;
    let enabled = form.registration_enabled.as_deref() == Some("on");
    app.state_store
        .set_app_meta(
            REGISTRATION_ENABLED_KEY,
            if enabled { "true" } else { "false" },
        )
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Failed to persist registration switch");
            ApiError::Internal("failed to save settings".into())
        })?;

    // 审计 detail 记开关值，机器面不翻译。
    if let Err(e) = app
        .state_store
        .audit_log(
            &ctx.user,
            &ctx.role,
            "update_registration_setting",
            None,
            Some(&format!(r#"{{"registration_enabled":{enabled}}}"#)),
        )
        .await
    {
        tracing::warn!(error = %e, "audit update_registration_setting write failed (setting already saved)");
    }

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        header::LOCATION,
        "/ui/admin/settings?status=saved"
            .parse()
            .map_err(|_| ApiError::Internal("failed to build Location header".into()))?,
    );
    Ok((
        StatusCode::SEE_OTHER,
        resp_headers,
        redirect_body(lang_from_headers(&headers)),
    ))
}
