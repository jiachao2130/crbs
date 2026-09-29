// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Web UI 页面 handler。

use super::{abs_time_or_dash, default_acl_role, rel_time_lang};
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::ui::components::{
    admin_card_grid, admin_inline_form, admin_select, back_link, clickable_rows_script,
    confirm_button, count_chip, danger_row, detail_grid, empty_state, filter_apply, filter_chips,
    format_local_time, generate_nonce, id_link, internal_error_flash, list_page_head, no_store,
    page_with_csp, pagination_links, secret_reveal_box, see_other_error_redirect,
    see_other_redirect, side_card, side_kv, status_message, storage_error_flash, user_cell,
    user_status_badge, PaginationParams, StatusQuery, AUDIT_ACTIONS,
};
use crate::server::routes::ui::i18n::{
    lang_from_headers, role_label, t, t_fmt, user_status_label, FmtKey, Lang, TextKey,
};
use crate::server::routes::ui::pages::page_size::list_limit_offset;
use crate::server::routes::ui::service::{
    audit_ui_event, build_filter_qs, csrf_token_for_request, current_list_url,
    require_admin_session, with_back_param, CancelForm, QueryParams, PRODUCT_ACL_ROLES,
};
use crate::server::state::AppState;
use crate::server::validation::validate_product_name;
use axum::extract::{Extension, Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use maud::{html, Markup};

use crbs_core::auth::secret::{Secret, SecretHash, SecretKind};
use crbs_core::error::CrbsError;
use crbs_core::{AuditLogFilter, UserFilter};
use std::sync::Arc;

const VALID_ADMIN_ROLES: &[&str] = &["admin", "operator", "builder", "viewer"];

use super::require_admin_page;

fn validate_admin_role(role: &str) -> Result<(), ApiError> {
    if VALID_ADMIN_ROLES.contains(&role) {
        Ok(())
    } else {
        Err(ApiError::Validation(format!(
            "invalid role '{}'; expected one of: {}",
            role,
            VALID_ADMIN_ROLES.join(", ")
        )))
    }
}

async fn list_product_names_for_admin(app: &AppState) -> Vec<String> {
    match app.state_store.list_products().await {
        Ok(stubs) => {
            let mut names: Vec<String> = stubs.into_iter().map(|s| s.name).collect();
            names.sort();
            names
        }
        Err(e) => {
            tracing::warn!(err = %e, "Failed to list products for admin");
            Vec::new()
        }
    }
}

/// 用户列表 Role 列徽章：admin 用 running 蓝，其余中性
/// badge；显示名走 [`role_label`]（机器值仍作 class/比较判据，仅文本本地化）。
fn user_role_badge(role: &str, lang: Lang) -> Markup {
    let class = if role == "admin" {
        "badge running"
    } else {
        "badge"
    };
    html! { span class=(class) { (role_label(lang, role)) } }
}

#[derive(serde::Deserialize)]
pub(crate) struct AdminUserForm {
    pub csrf_token: String,
    pub name: String,
    pub role: String,
}

#[derive(serde::Deserialize)]
pub(crate) struct AdminUserRoleForm {
    pub csrf_token: String,
    pub role: String,
}

#[derive(serde::Deserialize)]
pub(crate) struct AdminUserStatusForm {
    pub csrf_token: String,
    pub status: String,
}

#[derive(serde::Deserialize)]
pub(crate) struct AdminTokenForm {
    pub csrf_token: String,
    pub name: Option<String>,
    pub expires_in_days: Option<u32>,
}

#[derive(serde::Deserialize)]
pub(crate) struct AdminAclForm {
    pub csrf_token: String,
    pub product: String,
    /// ACL 角色，默认 viewer
    #[serde(default = "default_acl_role")]
    pub role: String,
}

#[derive(serde::Deserialize, Default)]
pub(crate) struct AdminAuditQuery {
    pub user: Option<String>,
    pub role: Option<String>,
    pub action: Option<String>,
    pub target: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    #[serde(default)]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

/// 用户列表页查询参数。`status` 兼任 [`StatusQuery`] 的 flash 消息通道：
/// 仅 `active` / `disabled` 视为过滤器，`created` 等消息值不参与过滤。
#[derive(serde::Deserialize, Default)]
pub(crate) struct AdminUsersQuery {
    pub name: Option<String>,
    pub role: Option<String>,
    pub status: Option<String>,
    pub error: Option<String>,
    /// `error` 文本的 HMAC 签名（flash 通道，透传给 [`StatusQuery::es`]）。
    pub es: Option<String>,
    #[serde(default)]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

pub(crate) async fn admin_dashboard_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    require_admin_page(auth.as_ref().map(|ext| &ext.0))?;
    let nonce = generate_nonce()?;
    let lang = lang_from_headers(&headers);
    let body = html! {
        h1 { (t(lang, TextKey::NavAdmin)) }
        (admin_card_grid(&nonce, lang))
    };
    page_with_csp(
        t(lang, TextKey::NavAdmin),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "admin",
        &headers,
        &app.csrf_key,
        body,
    )
}

pub(crate) async fn admin_users_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<AdminUsersQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin_page(auth.as_ref().map(|ext| &ext.0))?;
    let name_filter = q.name.as_deref().filter(|v| !v.is_empty());
    let role_filter = q.role.as_deref().filter(|v| !v.is_empty());
    let status_filter = q
        .status
        .as_deref()
        .filter(|v| *v == "active" || *v == "disabled");
    let (limit, offset) = list_limit_offset(q.limit, q.offset, &headers);
    let filter = UserFilter {
        name: name_filter,
        role: role_filter,
        status: status_filter,
        limit,
        offset,
    };
    let count_filter = UserFilter {
        name: filter.name,
        role: filter.role,
        status: filter.status,
        limit: 0,
        offset: 0,
    };
    let (total, users) = tokio::try_join!(
        app.state_store.count_users_filtered(&count_filter),
        app.state_store.list_users_filtered(&filter)
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "Failed to list users for admin UI");
        ApiError::Internal("failed to list users".into())
    })?;
    let csrf_token = csrf_token_for_request(&headers, &app.csrf_key);
    let nonce = generate_nonce()?;
    let flash = StatusQuery {
        status: q.status.clone(),
        error: q.error.clone(),
        es: q.es.clone(),
        back: None,
        range: None,
    };
    // 构建保留过滤器参数的查询后缀（用于分页链接），offset 由调用方覆盖。
    let filter_qs = build_filter_qs(&[
        ("name", name_filter),
        ("role", role_filter),
        ("status", status_filter),
    ]);
    let page_size = limit as usize;
    let offset_val = offset as usize;
    // 当前列表页 URL：详情链接 back 参数的目标（过滤参数 + 当前页码）。
    let current_list = current_list_url("/ui/admin/users", &filter_qs, offset_val);
    let lang = lang_from_headers(&headers);
    // 激活过滤 chips：name/role 原值、status 走显示名；remove URL 去掉该参数、其余保留、offset 归零。
    let mut active_chips: Vec<(String, String, String)> = Vec::new();
    if let Some(name) = name_filter {
        let remove = current_list_url(
            "/ui/admin/users",
            &build_filter_qs(&[
                ("name", None),
                ("role", role_filter),
                ("status", status_filter),
            ]),
            0,
        );
        active_chips.push((
            t(lang, TextKey::ThName).to_string(),
            name.to_string(),
            remove,
        ));
    }
    if let Some(role) = role_filter {
        let remove = current_list_url(
            "/ui/admin/users",
            &build_filter_qs(&[
                ("name", name_filter),
                ("role", None),
                ("status", status_filter),
            ]),
            0,
        );
        active_chips.push((
            t(lang, TextKey::ThRole).to_string(),
            role.to_string(),
            remove,
        ));
    }
    if let Some(status) = status_filter {
        let remove = current_list_url(
            "/ui/admin/users",
            &build_filter_qs(&[
                ("name", name_filter),
                ("role", role_filter),
                ("status", None),
            ]),
            0,
        );
        active_chips.push((
            t(lang, TextKey::ThStatus).to_string(),
            user_status_label(lang, status).to_string(),
            remove,
        ));
    }
    let active_chips = filter_chips(&active_chips, lang);
    // filter_form 组件无 role/status 字段，手写同构标记（过滤条并入卡头首子
    // 元素、chips 尾置其内）。
    let toolbar = html! {
        form class="filter-bar" method="get" action="/ui/admin/users" {
            label {
                (t(lang, TextKey::ThName))
                input type="text" name="name" value=(q.name.as_deref().unwrap_or(""));
            }
            label {
                (t(lang, TextKey::ThRole))
                // role 过滤：value = 机器串，label 走 role_label。
                (admin_select("role", &[
                    ("", t(lang, TextKey::FilterAll)),
                    ("admin", role_label(lang, "admin")),
                    ("operator", role_label(lang, "operator")),
                    ("builder", role_label(lang, "builder")),
                    ("viewer", role_label(lang, "viewer")),
                ], role_filter))
            }
            label {
                (t(lang, TextKey::ThStatus))
                (admin_select("status", &[
                    ("", t(lang, TextKey::FilterAll)),
                    ("active", user_status_label(lang, "active")),
                    ("disabled", user_status_label(lang, "disabled")),
                ], status_filter))
            }
            (filter_apply("/ui/admin/users", lang))
            (active_chips)
        }
    };
    let body = html! {
        // 页头 actions/meta 留空：Create user 多字段表单卡走下方独立 admin-section。
        (list_page_head(
            html! { (t(lang, TextKey::AdminUsersTitle)) " " (count_chip(total.max(0) as usize)) },
            html! {},
            html! {},
        ))
        (status_message(&flash, &app.csrf_key, lang))
        div class="admin-section" {
            h2 { (t(lang, TextKey::CreateUser)) }
            @if let Some(token) = csrf_token.as_ref() {
                (admin_inline_form("/ui/admin/users", token, html! {
                    label {
                        (t(lang, TextKey::ThName))
                        input type="text" name="name" required="";
                    }
                    label {
                        (t(lang, TextKey::ThRole))
                        // value 顺序 = 提交默认（builder），label 本地化不改值域。
                        (admin_select("role", &[
                            ("builder", role_label(lang, "builder")),
                            ("operator", role_label(lang, "operator")),
                            ("admin", role_label(lang, "admin")),
                            ("viewer", role_label(lang, "viewer")),
                        ], None))
                    }
                }, t(lang, TextKey::ButtonCreate)))
            } @else {
                p { (t(lang, TextKey::SettingsSessionExpired)) " " a href="/ui/login" { (t(lang, TextKey::ErrLoginCta)) } }
            }
        }
        // 空态判据用 total 而非页切片：offset 越过末页仍渲染表卡 + 分页（prev 可回第一页）。
        @if total == 0 {
            // 过滤条仍需可操作（调整/清除过滤）：空结果时卡内只留卡头。
            div class="table-card" { (toolbar) }
            (empty_state(t(lang, TextKey::EmptyUsersTitle), t(lang, TextKey::EmptyUsersHint)))
        } @else {
            // 表格卡：高密度表 + 分页并入卡脚（pagination_links 对 total=0 返回空标记）。
            div class="table-card" {
                (toolbar)
                table class="fixed" {
                    // 列宽：9/auto/16/16/18。
                    colgroup {
                        col style="width:9%" {}
                        col style="width:auto" {}
                        col style="width:16%" {}
                        col style="width:16%" {}
                        col style="width:18%" {}
                    }
                    thead {
                        tr {
                            th { (t(lang, TextKey::ThId)) }
                            th { (t(lang, TextKey::ThName)) }
                            th { (t(lang, TextKey::ThRole)) }
                            th { (t(lang, TextKey::ThStatus)) }
                            th class="num" { (t(lang, TextKey::ThCreated)) }
                        }
                    }
                    tbody {
                        @for u in &users {
                            tr class="clickable-row" {
                                // #123 形态 mono 链接（row-target 契约保留）。
                                td { (id_link(with_back_param(&format!("/ui/admin/users/{}", u.id), &current_list), u.id)) }
                                td class="ellipsis" title=(u.name) { (user_cell(&u.name)) }
                                td { (user_role_badge(&u.role, lang)) }
                                td { (user_status_badge(&u.status, lang)) }
                                td class="num" { (rel_time_lang(Some(u.created_at.as_str()), lang)) }
                            }
                        }
                    }
                }
                (pagination_links(&PaginationParams {
                    base_path: "/ui/admin/users",
                        lang,
                    total: total as usize,
                    limit: page_size,
                    offset: offset_val,
                    query: QueryParams::default(),
                    raw_filter_qs: Some(&filter_qs),

                    csrf_token: csrf_token_for_request(&headers, &app.csrf_key).as_deref(),                }))
            }
        }
        (clickable_rows_script(&nonce))
    };
    page_with_csp(
        t(lang, TextKey::AdminUsersPageTitle),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "admin",
        &headers,
        &app.csrf_key,
        body,
    )
}

pub(crate) async fn admin_user_create(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<AdminUserForm>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = require_admin_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form.csrf_token,
        &app.csrf_key,
    )?;
    let lang = lang_from_headers(&headers);
    let name = form.name.trim().to_string();
    let role = form.role.clone();
    let result: Result<i64, String> = async {
        // 唯一失败文案是非法角色（带角色名）：按变体映射双语 key，不透传 e.message()。
        validate_admin_role(&role)
            .map_err(|_| t_fmt(lang, FmtKey::FlashAdminRoleExpected, &[&role]))?;
        if name.is_empty() {
            return Err(t(lang, TextKey::FlashUserNameEmpty).to_string());
        }
        if name.chars().any(|c| c.is_whitespace()) {
            return Err(t(lang, TextKey::FlashUserNameWhitespace).to_string());
        }
        if app
            .state_store
            .find_user_by_name(&name)
            .await
            .map_err(|e| storage_error_flash("check existing user", &e))?
            .is_some()
        {
            return Err(t_fmt(lang, FmtKey::FlashUserExists, &[&name]));
        }
        let id = app
            .state_store
            .create_user(&name, &role)
            .await
            .map_err(|e| storage_error_flash("create user", &e))?;
        Ok(id)
    }
    .await;
    match result {
        Ok(id) => {
            audit_ui_event(&app, &ctx, "create_user", &id.to_string(), None).await;
            see_other_redirect(&format!("/ui/admin/users/{}?status=created", id))
        }
        Err(msg) => see_other_error_redirect("/ui/admin/users", &msg, &app.csrf_key),
    }
}

pub(crate) async fn admin_user_detail_page(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<StatusQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin_page(auth.as_ref().map(|ext| &ext.0))?;
    let user = app
        .state_store
        .get_user(id)
        .await
        .map_err(|e| {
            tracing::warn!(user_id = %id, error = %e, "Failed to get user for admin UI");
            ApiError::Internal("failed to get user".into())
        })?
        .ok_or_else(|| ApiError::not_found("user", id))?;
    let tokens = app.state_store.list_user_tokens(id).await.map_err(|e| {
        tracing::warn!(user_id = %id, error = %e, "Failed to list tokens for admin UI");
        ApiError::Internal("failed to list tokens".into())
    })?;
    let acls = app.state_store.list_product_acls(id).await.map_err(|e| {
        tracing::warn!(user_id = %id, error = %e, "Failed to list ACLs for admin UI");
        ApiError::Internal("failed to list ACLs".into())
    })?;
    let products = list_product_names_for_admin(&app).await;
    let csrf_token = csrf_token_for_request(&headers, &app.csrf_key);
    let lang = lang_from_headers(&headers);
    let nonce = generate_nonce()?;
    let status_action = if user.status == "active" {
        "disabled"
    } else {
        "active"
    };
    let status_label = if user.status == "active" {
        t(lang, TextKey::ButtonDisable)
    } else {
        t(lang, TextKey::ButtonEnable)
    };
    let details_rows: Vec<(Markup, Markup)> = vec![
        (
            html! { (t(lang, TextKey::ThStatus)) },
            html! { (user_status_badge(&user.status, lang)) },
        ),
        (
            html! { (t(lang, TextKey::ThCreated)) },
            html! { code { (format_local_time(&user.created_at)) } },
        ),
    ];
    let product_options: Vec<(&str, &str)> =
        products.iter().map(|p| (p.as_str(), p.as_str())).collect();

    let body = html! {
        // 页头条带：crumb + h1 + meta 身份行；管理动作集中在下方分区卡，band 不设 header-actions。
        div class="crumb" {
            (back_link(t(lang, TextKey::BackToUsers), "/ui/admin/users", q.back.as_deref()))
        }
        div class="page-head" {
            div class="title-block" {
                h1 { (t(lang, TextKey::ThUser)) " #" (id) }
                div class="page-meta" {
                    (user.name)
                    span class="sep" { "·" }
                    // 身份行同走 role_label：改角色下拉已本地化，直出裸枚举会致 zh 页内分裂。
                    (role_label(lang, &user.role))
                }
            }
        }
        (status_message(&q, &app.csrf_key, lang))

        // 双栏：主列 Role / 重置密码 / Tokens / Product ACL；侧栏 Details + Danger zone（禁用红按钮带后果文案、固定沉底）。
        (detail_grid(
            html! {
                div class="admin-section" {
                    h2 { (t(lang, TextKey::ThRole)) }
                    @if let Some(token) = csrf_token.as_ref() {
                        (admin_inline_form(&format!("/ui/admin/users/{}/role", id), token, html! {
                            label {
                                (t(lang, TextKey::ThRole))
                                // 预选当前角色（机器串匹配 value），label 本地化不改提交值域。
                                (admin_select("role", &[
                                    ("builder", role_label(lang, "builder")),
                                    ("operator", role_label(lang, "operator")),
                                    ("admin", role_label(lang, "admin")),
                                    ("viewer", role_label(lang, "viewer")),
                                ], Some(&user.role)))
                            }
                        }, t(lang, TextKey::ButtonUpdate)))
                    }
                }

                // 临时密码一次性展示 + 全会话撤销 + 下次登录强制改密；API token 不受影响（另行撤销 token 逼改）。
                div class="admin-section" {
                    h2 { (t(lang, TextKey::AdminResetCardTitle)) }
                    p class="settings-desc" { (t(lang, TextKey::AdminResetCardDesc)) }
                    p class="field-hint" { (t(lang, TextKey::AdminResetTokenNote)) }
                    @if let Some(token) = csrf_token.as_ref() {
                        form class="admin-inline-form" method="post" action=(format!("/ui/admin/users/{}/password", id)) {
                            input type="hidden" name="csrf_token" value=(token);
                            (confirm_button(
                                t(lang, TextKey::AdminResetButton),
                                &t_fmt(lang, FmtKey::AdminResetConfirm, &[&user.name]),
                            ))
                        }
                    }
                }

            div class="admin-section" {
                h2 { (t(lang, TextKey::SectionTokens)) }
                @if let Some(token) = csrf_token.as_ref() {
                    (admin_inline_form(&format!("/ui/admin/users/{}/tokens", id), token, html! {
                        label {
                            (t(lang, TextKey::LabelNameOptional))
                            input type="text" name="name";
                        }
                        label {
                            (t(lang, TextKey::LabelExpiresDays))
                            input type="number" name="expires_in_days" min="1";
                        }
                    }, t(lang, TextKey::MeTokenCreate)))
                }
                @if tokens.is_empty() {
                    (empty_state(t(lang, TextKey::EmptyTokensTitle), t(lang, TextKey::EmptyTokensHint)))
                } @else {
                    div class="table-wrap" {
                        // table-wrap 横滚保护：nowrap 时间戳（来自 .admin-section
                        // td.num 规则）在 % 弹性列装不下时溢出盖住撤销按钮，col-time
                        // 定宽 + 表级 min-width 横滚（见 style.css tokens-table 注释）。
                        table class="fixed tokens-table" {
                            colgroup {
                                col style="width:8%" {}
                                col style="width:auto" {}
                                col style="width:14%" {}
                                col class="col-time" {}
                                col class="col-time" {}
                                col style="width:18%" {}
                            }
                            thead {
                                tr {
                                    th class="num" { (t(lang, TextKey::ThId)) }
                                    th { (t(lang, TextKey::ThName)) }
                                    th class="num" { (t(lang, TextKey::ThCreated)) }
                                    th class="num" { (t(lang, TextKey::ThExpires)) }
                                    th class="num" { (t(lang, TextKey::ThRevoked)) }
                                    th { (t(lang, TextKey::ThAction)) }
                                }
                            }
                            tbody {
                                // 循环变量 tok：避免遮蔽 i18n 的 t() 函数。
                                @for tok in &tokens {
                                    tr {
                                        td class="num" { (tok.id) }
                                        td class="ellipsis" title=(tok.name.as_deref().unwrap_or("—")) { (tok.name.as_deref().unwrap_or("—")) }
                                        td class="num" { (rel_time_lang(Some(tok.created_at.as_str()), lang)) }
                                        td class="num" { (abs_time_or_dash(tok.expires_at.as_deref())) }
                                        td class="num" { (abs_time_or_dash(tok.revoked_at.as_deref())) }
                                        td {
                                            @if tok.revoked_at.is_none() {
                                                @if let Some(token) = csrf_token.as_ref() {
                                                    form class="action-form" method="post" action=(format!("/ui/admin/users/{}/tokens/{}/revoke", id, tok.id)) {
                                                        input type="hidden" name="csrf_token" value=(token);
                                                        (confirm_button(t(lang, TextKey::ButtonRevoke), &t_fmt(lang, FmtKey::ConfirmRevokeToken, &[tok.name.as_deref().unwrap_or("(unnamed)")])))
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            div class="admin-section" {
                h2 { (t(lang, TextKey::SectionProductAcl)) }
                @if let Some(token) = csrf_token.as_ref() {
                    @if products.is_empty() {
                        (empty_state(t(lang, TextKey::EmptyProductsTitle), t(lang, TextKey::EmptyAclNoProductsHint)))
                    } @else {
                        (admin_inline_form(&format!("/ui/admin/users/{}/acl", id), token, html! {
                            label {
                                (t(lang, TextKey::ThProduct))
                                (admin_select("product", &product_options, None))
                            }
                            label {
                                (t(lang, TextKey::ThRole))
                                // ACL 授予：value=机器串、label 本地化（缺省 viewer）。
                                (admin_select(
                                    "role",
                                    &PRODUCT_ACL_ROLES.map(|r| (r, role_label(lang, r))),
                                    Some("viewer")
                                ))
                            }
                        }, t(lang, TextKey::ButtonGrant)))
                    }
                }
                @if acls.is_empty() {
                    (empty_state(t(lang, TextKey::EmptyUserAclsTitle), t(lang, TextKey::EmptyUserAclsHint)))
                } @else {
                    div class="table-wrap" {
                        // table-wrap 横滚保护：nowrap Granted 时间戳（来自
                        // .admin-section td.num 规则）在 % 弹性列装不下时溢出盖住撤销按钮，
                        // col-granted 定宽 + 表级 min-width 横滚（见 style.css acl-table 注释）。
                        table class="fixed acl-table" {
                            colgroup {
                                col style="width:auto" {}
                                col style="width:16%" {}
                                col class="col-granted" {}
                                col style="width:20%" {}
                            }
                            thead {
                                tr {
                                    th { (t(lang, TextKey::ThProduct)) }
                                    th { (t(lang, TextKey::ThRole)) }
                                    th class="num" { (t(lang, TextKey::ThGranted)) }
                                    th { (t(lang, TextKey::ThAction)) }
                                }
                            }
                            tbody {
                                @for a in &acls {
                                    tr {
                                        td class="ellipsis" title=(a.product) { (a.product) }
                                        // role 徽章同走 role_label；机器值仍是校验/表单 value。
                                        td { (role_label(lang, &a.role)) }
                                        td class="num" { (format_local_time(&a.created_at)) }
                                        td {
                                            @if let Some(token) = csrf_token.as_ref() {
                                                form class="action-form" method="post" action=(format!("/ui/admin/users/{}/acl/{}/revoke", id, urlencoding::encode(&a.product))) {
                                                    input type="hidden" name="csrf_token" value=(token);
                                                    (confirm_button(t(lang, TextKey::ButtonRevoke), &t_fmt(lang, FmtKey::ConfirmRevokeUserAcl, &[&a.product])))
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            },
            html! {
                (side_card("", t(lang, TextKey::SideDetailsTitle), side_kv(&details_rows)))
                // Danger zone：禁用是危险方向（红 confirm + 后果文案）；启用非破坏，无描述行。
                @if let Some(token) = csrf_token.as_ref() {
                    (side_card(
                        "danger-zone",
                        t(lang, TextKey::DangerZoneTitle),
                        html! {
                            @if status_action == "disabled" {
                                (danger_row(
                                    status_label,
                                    t(lang, TextKey::DangerDisableUserDesc),
                                    html! {
                                        form class="action-form" method="post" action=(format!("/ui/admin/users/{}/status", id)) {
                                            input type="hidden" name="csrf_token" value=(token);
                                            input type="hidden" name="status" value=(status_action);
                                            (confirm_button(status_label, t(lang, TextKey::ConfirmDisableUser)))
                                        }
                                    },
                                ))
                            } @else {
                                (danger_row(
                                    status_label,
                                    "",
                                    html! {
                                        form class="action-form" method="post" action=(format!("/ui/admin/users/{}/status", id)) {
                                            input type="hidden" name="csrf_token" value=(token);
                                            input type="hidden" name="status" value=(status_action);
                                            button class="action-button" type="submit" { (status_label) }
                                        }
                                    },
                                ))
                            }
                        },
                    ))
                }
            },
        ))
    };
    page_with_csp(
        &t_fmt(
            lang,
            FmtKey::AdminUserPageTitle,
            &[&id.to_string(), &user.name],
        ),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "admin",
        &headers,
        &app.csrf_key,
        body,
    )
}

pub(crate) async fn admin_user_set_role(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<AdminUserRoleForm>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = require_admin_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form.csrf_token,
        &app.csrf_key,
    )?;
    let lang = lang_from_headers(&headers);
    let result: Result<(), String> = async {
        // 唯一失败文案是非法角色（带角色名）：按变体映射双语 key。
        validate_admin_role(&form.role)
            .map_err(|_| t_fmt(lang, FmtKey::FlashAdminRoleExpected, &[&form.role]))?;
        // 存在性预检：set_user_role 对缺失行是 no-op，走 ?error= flash 而非静默成功。
        app.state_store
            .get_user(id)
            .await
            .map_err(|e| storage_error_flash("get user for role update", &e))?
            .ok_or_else(|| t_fmt(lang, FmtKey::FlashUserNotFoundById, &[&id.to_string()]))?;
        // Conflict 唯一来源是最后活跃管理员守卫（文案源 crbs-core state/users.rs），映射双语 key。
        match app.state_store.set_user_role(id, &form.role).await {
            Ok(()) => {}
            Err(CrbsError::Conflict { .. }) => {
                return Err(t(lang, TextKey::FlashLastAdminGuard).to_string())
            }
            Err(e) => return Err(storage_error_flash("set user role", &e)),
        }
        Ok(())
    }
    .await;
    match result {
        Ok(()) => {
            let detail = serde_json::json!({ "role": form.role }).to_string();
            audit_ui_event(&app, &ctx, "update_user", &id.to_string(), Some(&detail)).await;
            see_other_redirect(&format!("/ui/admin/users/{}?status=role_updated", id))
        }
        Err(msg) => {
            see_other_error_redirect(&format!("/ui/admin/users/{}", id), &msg, &app.csrf_key)
        }
    }
}

pub(crate) async fn admin_user_set_status(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<AdminUserStatusForm>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = require_admin_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form.csrf_token,
        &app.csrf_key,
    )?;
    let lang = lang_from_headers(&headers);
    let result: Result<String, String> = async {
        if form.status != "active" && form.status != "disabled" {
            return Err(t(lang, TextKey::FlashInvalidUserStatus).to_string());
        }
        // 存在性预检：no-op UPDATE 不得静默成功。
        app.state_store
            .get_user(id)
            .await
            .map_err(|e| storage_error_flash("get user for status update", &e))?
            .ok_or_else(|| t_fmt(lang, FmtKey::FlashUserNotFoundById, &[&id.to_string()]))?;
        // Conflict 映射双语 key：该调用链唯一来源是最后活跃管理员守卫。
        match app.state_store.set_user_status(id, &form.status).await {
            Ok(()) => {}
            Err(CrbsError::Conflict { .. }) => {
                return Err(t(lang, TextKey::FlashLastAdminGuard).to_string())
            }
            Err(e) => return Err(storage_error_flash("set user status", &e)),
        }
        Ok(if form.status == "active" {
            "enable_user".to_string()
        } else {
            "disable_user".to_string()
        })
    }
    .await;
    match result {
        Ok(action) => {
            audit_ui_event(&app, &ctx, &action, &id.to_string(), None).await;
            see_other_redirect(&format!("/ui/admin/users/{}?status=status_updated", id))
        }
        Err(msg) => {
            see_other_error_redirect(&format!("/ui/admin/users/{}", id), &msg, &app.csrf_key)
        }
    }
}

/// POST /ui/admin/users/{id}/password：admin 重置密码——生成 16 字符临时密码
/// → `set_user_password(must_change=true)`（下次登录强制改密）→ 撤销全部会话
///（admin 重置自己时本机会话同撤销）→ 一次性展示页（secret_reveal_box + no-store）。
pub(crate) async fn admin_user_reset_password(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<CancelForm>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = require_admin_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form.csrf_token,
        &app.csrf_key,
    )?;
    let lang = lang_from_headers(&headers);
    let result: Result<(crbs_core::User, String), String> = async {
        let user = app
            .state_store
            .get_user(id)
            .await
            .map_err(|e| storage_error_flash("get user for reset", &e))?
            .ok_or_else(|| t_fmt(lang, FmtKey::FlashUserNotFoundById, &[&id.to_string()]))?;
        let temp = crbs_core::auth::password::generate_temp_password()
            .map_err(|e| internal_error_flash("generate temporary password", &e))?;
        // temp 为 16 字符字母数字，恒满足策略（10..1024）；校验仅断言该不变量。
        crbs_core::auth::password::validate_password_policy(&temp).map_err(|e| e.to_string())?;
        let hash = crbs_core::auth::password::hash_password(&temp)
            .map_err(|e| internal_error_flash("hash password", &e))?;
        // must_change=true：该用户下次密码登录即被导向 /ui/me 强制改密。
        app.state_store
            .set_user_password(id, &hash, true)
            .await
            .map_err(|e| storage_error_flash("set user password", &e))?;
        app.state_store
            .revoke_all_user_sessions(id)
            .await
            .map_err(|e| storage_error_flash("revoke user sessions", &e))?;
        Ok((user, temp))
    }
    .await;
    let (user, temp) = match result {
        Ok(v) => v,
        Err(msg) => {
            return see_other_error_redirect(&format!("/ui/admin/users/{id}"), &msg, &app.csrf_key)
        }
    };
    let detail = serde_json::json!({ "user_id": id, "user_name": user.name }).to_string();
    audit_ui_event(&app, &ctx, "password_reset", &id.to_string(), Some(&detail)).await;
    let nonce = generate_nonce()?;
    let body = html! {
        h1 { (t(lang, TextKey::AdminResetDoneTitle)) }
        p { b { (user.name) } }
        p { (t_fmt(lang, FmtKey::AdminResetTempLabel, &[&user.name])) }
        (secret_reveal_box(&temp, &nonce, lang))
        p { (t(lang, TextKey::AdminResetMustChangeNote)) }
        p { a href=(format!("/ui/admin/users/{id}")) { (t(lang, TextKey::AdminResetBackToUser)) } }
    };
    let page = page_with_csp(
        t(lang, TextKey::AdminResetDoneTitle),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "admin",
        &headers,
        &app.csrf_key,
        body,
    )?;
    Ok(no_store(page))
}

pub(crate) async fn admin_token_create(
    State(app): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<AdminTokenForm>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = require_admin_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form.csrf_token,
        &app.csrf_key,
    )?;
    let lang = lang_from_headers(&headers);
    let result: Result<(String, i64), String> = async {
        let user = app
            .state_store
            .get_user(user_id)
            .await
            .map_err(|e| storage_error_flash("get user for token", &e))?
            .ok_or_else(|| t_fmt(lang, FmtKey::FlashUserNotFoundById, &[&user_id.to_string()]))?;
        if user.status != "active" {
            return Err(t_fmt(lang, FmtKey::FlashTokenDisabledUser, &[&user.name]));
        }
        let secret = Secret::generate(SecretKind::UserToken)
            .map_err(|e| internal_error_flash("generate token", &e))?;
        let hash = SecretHash::from_plain(secret.as_str());
        let expires_at = form.expires_in_days.map(|days| {
            // clamp：超大 u32 天数会让 chrono Duration 加法越界 panic（请求被丢）。
            let days = days.min(3650) as i64;
            (chrono::Utc::now() + chrono::Duration::days(days)).to_rfc3339()
        });
        let id = app
            .state_store
            .create_user_token(
                user_id,
                form.name.as_deref(),
                hash.as_str(),
                expires_at.as_deref(),
            )
            .await
            .map_err(|e| storage_error_flash("create user token", &e))?;
        Ok((secret.as_str().to_string(), id))
    }
    .await;
    let (secret, id) = match result {
        Ok(v) => v,
        Err(msg) => {
            return see_other_error_redirect(
                &format!("/ui/admin/users/{}", user_id),
                &msg,
                &app.csrf_key,
            )
        }
    };
    let detail = serde_json::json!({
        "user_id": user_id,
        "name": form.name,
        "expires_in_days": form.expires_in_days,
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
    let nonce = generate_nonce()?;
    let body = html! {
        h1 { (t(lang, TextKey::MeTokenCreatedTitle)) }
        p { (t_fmt(lang, FmtKey::TokenIdLabel, &[&id.to_string()])) }
        (secret_reveal_box(&secret, &nonce, lang))
        p { a href=(format!("/ui/admin/users/{}", user_id)) { "← " (t(lang, TextKey::AdminResetBackToUser)) } }
    };
    let page = page_with_csp(
        t(lang, TextKey::AdminTokenCreatedTitle),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "admin",
        &headers,
        &app.csrf_key,
        body,
    )?;
    // 明文 token 只展示一次，禁止任何缓存存储。
    Ok(no_store(page))
}

pub(crate) async fn admin_token_revoke(
    State(app): State<Arc<AppState>>,
    Path((user_id, token_id)): Path<(i64, i64)>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<CancelForm>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = require_admin_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form.csrf_token,
        &app.csrf_key,
    )?;
    let lang = lang_from_headers(&headers);
    let result: Result<(), String> = async {
        let token = app
            .state_store
            .list_user_tokens(user_id)
            .await
            .map_err(|e| storage_error_flash("list user tokens", &e))?
            .into_iter()
            .find(|t| t.id == token_id)
            .ok_or_else(|| {
                t_fmt(
                    lang,
                    FmtKey::FlashTokenNotFoundForUser,
                    &[&token_id.to_string(), &user_id.to_string()],
                )
            })?;
        app.state_store
            .revoke_user_token(token.id)
            .await
            .map_err(|e| storage_error_flash("revoke user token", &e))?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => {
            audit_ui_event(
                &app,
                &ctx,
                "revoke_user_token",
                &token_id.to_string(),
                Some(&user_id.to_string()),
            )
            .await;
            see_other_redirect(&format!("/ui/admin/users/{}?status=token_revoked", user_id))
        }
        Err(msg) => {
            see_other_error_redirect(&format!("/ui/admin/users/{}", user_id), &msg, &app.csrf_key)
        }
    }
}

pub(crate) async fn admin_acl_grant(
    State(app): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<AdminAclForm>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = require_admin_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form.csrf_token,
        &app.csrf_key,
    )?;
    let lang = lang_from_headers(&headers);
    let product = form.product.clone();
    let role = form.role.clone();
    let result: Result<String, String> = async {
        // 校验 fn 的两条文案按输入分类映射（空名/非法字符），不透传原文。
        validate_product_name(&product).map_err(|_| {
            if product.is_empty() {
                t(lang, TextKey::FlashProductNameEmpty).to_string()
            } else {
                t_fmt(lang, FmtKey::FlashProductNameInvalidChars, &[&product])
            }
        })?;
        if !PRODUCT_ACL_ROLES.contains(&role.as_str()) {
            return Err(t_fmt(lang, FmtKey::FlashAdminAclInvalidRole, &[&role]));
        }
        let target_user = app
            .state_store
            .get_user(user_id)
            .await
            .map_err(|e| storage_error_flash("get user for ACL", &e))?
            .ok_or_else(|| t_fmt(lang, FmtKey::FlashUserNotFoundById, &[&user_id.to_string()]))?;
        if target_user.status != "active" {
            return Err(t_fmt(
                lang,
                FmtKey::FlashUserNotActive,
                &[&target_user.name, &target_user.status],
            ));
        }
        app.state_store
            .grant_product_acl_with_role(user_id, &product, &role)
            .await
            .map_err(|e| storage_error_flash("grant product ACL", &e))?;
        Ok(target_user.name)
    }
    .await;
    match result {
        Ok(user_name) => {
            let detail =
                serde_json::json!({ "user_id": user_id, "user_name": user_name }).to_string();
            audit_ui_event(&app, &ctx, "grant_product_acl", &product, Some(&detail)).await;
            see_other_redirect(&format!("/ui/admin/users/{}?status=acl_granted", user_id))
        }
        Err(msg) => {
            see_other_error_redirect(&format!("/ui/admin/users/{}", user_id), &msg, &app.csrf_key)
        }
    }
}

pub(crate) async fn admin_acl_revoke(
    State(app): State<Arc<AppState>>,
    Path((user_id, product)): Path<(i64, String)>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<CancelForm>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = require_admin_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form.csrf_token,
        &app.csrf_key,
    )?;
    let lang = lang_from_headers(&headers);
    let result: Result<u64, String> = async {
        // 同 admin_acl_grant：按输入分类映射校验 fn 的两条文案。
        validate_product_name(&product).map_err(|_| {
            if product.is_empty() {
                t(lang, TextKey::FlashProductNameEmpty).to_string()
            } else {
                t_fmt(lang, FmtKey::FlashProductNameInvalidChars, &[&product])
            }
        })?;
        let granted = app
            .state_store
            .is_product_acl_granted(user_id, &product)
            .await
            .map_err(|e| storage_error_flash("check product ACL", &e))?;
        if !granted {
            return Err(t_fmt(
                lang,
                FmtKey::FlashAclNotGranted,
                &[&user_id.to_string(), &product],
            ));
        }
        let builds_cancelled = app
            .state_store
            .revoke_product_acl(user_id, &product)
            .await
            .map_err(|e| storage_error_flash("revoke product ACL", &e))?;
        Ok(builds_cancelled)
    }
    .await;
    match result {
        Ok(builds_cancelled) => {
            let detail =
                serde_json::json!({ "user_id": user_id, "builds_cancelled": builds_cancelled })
                    .to_string();
            audit_ui_event(&app, &ctx, "revoke_product_acl", &product, Some(&detail)).await;
            see_other_redirect(&format!("/ui/admin/users/{}?status=acl_revoked", user_id))
        }
        Err(msg) => {
            see_other_error_redirect(&format!("/ui/admin/users/{}", user_id), &msg, &app.csrf_key)
        }
    }
}

pub(crate) async fn admin_audit_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<AdminAuditQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin_page(auth.as_ref().map(|ext| &ext.0))?;
    let (limit, offset) = list_limit_offset(q.limit, q.offset, &headers);
    let filter = AuditLogFilter {
        user: q.user.as_deref(),
        role: q.role.as_deref(),
        action: q.action.as_deref(),
        target: q.target.as_deref(),
        since: q.since.as_deref(),
        until: q.until.as_deref(),
        limit,
        offset,
    };
    let (total, logs) = tokio::try_join!(
        app.state_store.count_audit_logs(AuditLogFilter {
            user: filter.user,
            role: filter.role,
            action: filter.action,
            target: filter.target,
            since: filter.since,
            until: filter.until,
            limit: 0,
            offset: 0,
        }),
        app.state_store.list_audit_logs(filter)
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "Failed to list audit logs for admin UI");
        ApiError::Internal("failed to list audit logs".into())
    })?;
    let nonce = generate_nonce()?;
    let lang = lang_from_headers(&headers);
    let action_options: Vec<(&str, &str)> = std::iter::once(("", t(lang, TextKey::FilterAll)))
        .chain(AUDIT_ACTIONS.iter().map(|a| (*a, *a)))
        .collect();
    // 构建保留过滤器参数的查询后缀（用于分页链接），offset 由调用方覆盖。
    let filter_qs = build_filter_qs(&[
        ("user", q.user.as_deref()),
        ("role", q.role.as_deref()),
        ("action", q.action.as_deref()),
        ("target", q.target.as_deref()),
        ("since", q.since.as_deref()),
        ("until", q.until.as_deref()),
    ]);
    let page_size = limit as usize;
    let offset_val = offset as usize;
    // 激活过滤 chips：6 字段全量（label 同表单字段标签；since/until 原样日期串）；remove URL 去掉该参数、其余保留、offset 归零。
    let user_filter = q.user.as_deref().filter(|v| !v.is_empty());
    let role_filter = q.role.as_deref().filter(|v| !v.is_empty());
    let action_filter = q.action.as_deref().filter(|v| !v.is_empty());
    let target_filter = q.target.as_deref().filter(|v| !v.is_empty());
    let since_filter = q.since.as_deref().filter(|v| !v.is_empty());
    let until_filter = q.until.as_deref().filter(|v| !v.is_empty());
    // 以当前过滤集构造查询串，`drop` 指定的参数置 None（chip 的 remove URL 用）。
    let filter_qs_without = |drop: &str| {
        build_filter_qs(&[
            ("user", (drop != "user").then_some(user_filter).flatten()),
            ("role", (drop != "role").then_some(role_filter).flatten()),
            (
                "action",
                (drop != "action").then_some(action_filter).flatten(),
            ),
            (
                "target",
                (drop != "target").then_some(target_filter).flatten(),
            ),
            ("since", (drop != "since").then_some(since_filter).flatten()),
            ("until", (drop != "until").then_some(until_filter).flatten()),
        ])
    };
    let active_chips: Vec<(String, String, String)> = [
        ("user", TextKey::ThUser, user_filter),
        ("role", TextKey::ThRole, role_filter),
        ("action", TextKey::ThAction, action_filter),
        ("target", TextKey::ThTarget, target_filter),
        ("since", TextKey::ThSince, since_filter),
        ("until", TextKey::ThUntil, until_filter),
    ]
    .into_iter()
    .filter_map(|(param, key, value)| {
        value.map(|v| {
            (
                t(lang, key).to_string(),
                v.to_string(),
                current_list_url("/ui/admin/audit", &filter_qs_without(param), 0),
            )
        })
    })
    .collect();
    let active_chips = filter_chips(&active_chips, lang);
    // 过滤条并入卡头、chips 尾置其内；6 字段在 1024 宽单行放不下，卡头 flex-wrap 按条目整洁换行。
    let toolbar = html! {
        form class="filter-bar" method="get" action="/ui/admin/audit" {
            label {
                (t(lang, TextKey::ThUser))
                input type="text" name="user" value=(q.user.as_deref().unwrap_or(""));
            }
            label {
                (t(lang, TextKey::ThRole))
                // 审计 role 过滤：value=机器串（匹配审计 detail 的 role 值），label 本地化。
                (admin_select("role", &[
                    ("", t(lang, TextKey::FilterAll)),
                    ("admin", role_label(lang, "admin")),
                    ("operator", role_label(lang, "operator")),
                    ("builder", role_label(lang, "builder")),
                    ("viewer", role_label(lang, "viewer")),
                ], q.role.as_deref()))
            }
            label {
                (t(lang, TextKey::ThAction))
                (admin_select("action", &action_options, q.action.as_deref()))
            }
            label {
                (t(lang, TextKey::ThTarget))
                input type="text" name="target" value=(q.target.as_deref().unwrap_or(""));
            }
            label {
                (t(lang, TextKey::ThSince))
                input type="datetime-local" name="since" value=(q.since.as_deref().unwrap_or(""));
            }
            label {
                (t(lang, TextKey::ThUntil))
                input type="datetime-local" name="until" value=(q.until.as_deref().unwrap_or(""));
            }
            (filter_apply("/ui/admin/audit", lang))
            (active_chips)
        }
    };
    let body = html! {
        // 页头：h1 = 页名 + 总数 chip；audit 无主操作，actions/meta 留空。
        (list_page_head(
            html! { (t(lang, TextKey::AuditLogsTitle)) " " (count_chip(total.max(0) as usize)) },
            html! {},
            html! {},
        ))
        // 空态判据用 total 而非页切片：offset 越过末页仍渲染表卡 + 分页。
        @if total == 0 {
            // 过滤条仍需可操作（调整/清除过滤）：空结果时卡内只留卡头。
            div class="table-card" { (toolbar) }
            (empty_state(t(lang, TextKey::EmptyAuditTitle), t(lang, TextKey::EmptyAuditHint)))
        } @else {
            div class="table-card" {
                (toolbar)
                // table-wrap 横滚保护：五定宽列合计 49rem，卡宽不足时 Detail 列被静默挤没——
                // 表级 min-width 59rem 横滚（见 style.css audit-table 注释）；toolbar 与卡脚分页留 wrap 外。
                div class="table-wrap" {
                    table class="audit-table" {
                        // 列宽定值在 style.css（.audit-table col.*），与 .audit-time 等列类集中一处。
                        colgroup {
                            col class="col-time" {}
                            col class="col-user" {}
                            col class="col-role" {}
                            col class="col-action" {}
                            col class="col-target" {}
                        }
                        thead {
                            tr {
                                th { (t(lang, TextKey::ThTime)) }
                                th { (t(lang, TextKey::ThUser)) }
                                th { (t(lang, TextKey::ThRole)) }
                                th { (t(lang, TextKey::ThAction)) }
                                th { (t(lang, TextKey::ThTarget)) }
                                th { (t(lang, TextKey::ThDetail)) }
                            }
                        }
                        tbody {
                            @for log in &logs {
                                tr {
                                    td class="audit-time" { (rel_time_lang(Some(log.created_at.as_str()), lang)) }
                                    td { (user_cell(&log.user)) }
                                    td { (log.role) }
                                    td { (log.action) }
                                    td { (audit_target_cell(&log.action, log.target.as_deref())) }
                                    td class="audit-detail" {
                                        @if let Some(detail) = log.detail.as_deref().filter(|d| !d.is_empty()) {
                                            details {
                                                summary class="detail-summary" { (detail) }
                                                pre class="code-block" { (pretty_audit_detail(detail)) }
                                            }
                                        } @else {
                                            "—"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                (pagination_links(&PaginationParams {
                    base_path: "/ui/admin/audit",
                        lang,
                    total: total as usize,
                    limit: page_size,
                    offset: offset_val,
                    query: QueryParams::default(),
                    raw_filter_qs: Some(&filter_qs),

                    csrf_token: csrf_token_for_request(&headers, &app.csrf_key).as_deref(),                }))
            }
        }
    };
    page_with_csp(
        t(lang, TextKey::AdminAuditPageTitle),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "admin",
        &headers,
        &app.csrf_key,
        body,
    )
}

/// 审计 Target 列 → 详情页链接：仅无歧义的 action→实体映射做链接，数字型
/// target 需能解析为 i64（脏行不链接）。保持纯文本：`gc`（uuid 无详情页）、
/// token 类（target 是 token id，链用户页语义错位）、未知 action / 非数字 id。
fn audit_target_cell(action: &str, target: Option<&str>) -> Markup {
    let Some(t) = target.filter(|t| !t.is_empty()) else {
        return html! { "—" };
    };
    let int_id = |t: &str| t.parse::<i64>().ok();
    let href = match action {
        // 用户：target = user id（自改的 password_change target 是本人 id，同链）。
        "create_user" | "update_user" | "enable_user" | "disable_user" | "password_reset"
        | "password_change" => int_id(t).map(|id| format!("/ui/admin/users/{id}")),
        // 构建：target = build id。
        "cancel_build" | "publish_build" | "unpublish_build" | "change_priority" => {
            int_id(t).map(|id| format!("/ui/builds/{id}"))
        }
        // 任务：target = task id。
        "submit_build" | "cancel_task" | "rebuild_task" | "reproduce_task" => {
            int_id(t).map(|id| format!("/ui/tasks/{id}"))
        }
        // worker：target = worker id。
        "rotate_worker_secret" | "revoke_worker_secret" | "delete_worker" | "init_base_os" => {
            int_id(t).map(|id| format!("/ui/workers/{id}"))
        }
        // 产品：target = 产品名。
        "create_product"
        | "update_product"
        | "delete_product_row"
        | "init_product"
        | "clean_product"
        | "rebuild_repo"
        | "update_product_visibility"
        | "transfer_product_ownership"
        | "grant_product_acl"
        | "revoke_product_acl"
        | "post_init" => Some(format!("/ui/products/{}", urlencoding::encode(t))),
        // gc（uuid）/ token 类（token id）/ 未知 action：纯文本。
        _ => None,
    };
    match href {
        Some(href) => html! { a href=(href) { (t) } },
        None => html! { (t) },
    }
}

/// 审计 Detail 列展示用：有效 JSON 则 pretty-print，否则原样返回。
fn pretty_audit_detail(detail: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(detail) {
        Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_else(|_| detail.to_string()),
        Err(_) => detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_audit_detail_formats_valid_json_with_newlines() {
        let detail = r#"{"user_id":"u-1","builds_cancelled":[1,2,3,4,5]}"#;
        let out = pretty_audit_detail(detail);
        assert!(
            out.contains('\n'),
            "pretty JSON should contain newlines: {out}"
        );
        assert!(
            out.contains("\"user_id\": \"u-1\""),
            "should keep field values: {out}"
        );
        assert!(
            out.contains("\"builds_cancelled\""),
            "should keep long array field: {out}"
        );
    }

    #[test]
    fn pretty_audit_detail_returns_non_json_untouched() {
        let detail = "cancelled 3 builds for product demo";
        assert_eq!(pretty_audit_detail(detail), detail);
    }

    #[test]
    fn pretty_audit_detail_empty_object_stays_single_braces() {
        // serde_json 对空对象 pretty 输出仍是 `{}`（无换行）。
        assert_eq!(pretty_audit_detail("{}"), "{}");
    }

    /// Target 列链接映射：无歧义 action → 详情页；歧义/未知 → 纯文本。
    #[test]
    fn audit_target_cell_links_unambiguous_actions_only() {
        let cell =
            |action: &str, target: Option<&str>| audit_target_cell(action, target).into_string();

        assert_eq!(
            cell("create_user", Some("7")),
            r#"<a href="/ui/admin/users/7">7</a>"#
        );
        assert_eq!(
            cell("disable_user", Some("7")),
            r#"<a href="/ui/admin/users/7">7</a>"#
        );
        assert_eq!(
            cell("cancel_build", Some("42")),
            r#"<a href="/ui/builds/42">42</a>"#
        );
        assert_eq!(
            cell("submit_build", Some("9")),
            r#"<a href="/ui/tasks/9">9</a>"#
        );
        assert_eq!(
            cell("rotate_worker_secret", Some("3")),
            r#"<a href="/ui/workers/3">3</a>"#
        );
        assert_eq!(
            cell("grant_product_acl", Some("mydist")),
            r#"<a href="/ui/products/mydist">mydist</a>"#
        );
        assert_eq!(
            cell("post_init", Some("a b")),
            r#"<a href="/ui/products/a%20b">a b</a>"#
        );

        assert_eq!(cell("gc", Some("01234567-89ab")), "01234567-89ab");
        assert_eq!(cell("create_user_token", Some("5")), "5");
        assert_eq!(cell("revoke_user_token", Some("5")), "5");
        assert_eq!(cell("mystery", Some("1")), "1");
        assert_eq!(cell("cancel_build", Some("not-a-number")), "not-a-number");
        assert_eq!(cell("create_user", None), "—");
        assert_eq!(cell("create_user", Some("")), "—");
    }

    /// 页面守卫语义锁定：匿名一律 401、非 admin 403、admin 放行。
    #[test]
    fn admin_page_guard_rejects_anonymous_and_underprivileged() {
        assert!(matches!(
            require_admin_page(None),
            Err(ApiError::Unauthorized(_))
        ));
        let operator = AuthContext {
            role: "operator".into(),
            ..Default::default()
        };
        assert!(matches!(
            require_admin_page(Some(&operator)),
            Err(ApiError::PermissionDenied(_))
        ));
        let admin = AuthContext {
            role: "admin".into(),
            ..Default::default()
        };
        assert!(require_admin_page(Some(&admin)).is_ok());
    }
}
