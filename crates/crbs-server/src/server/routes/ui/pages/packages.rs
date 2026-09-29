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

use super::{child_build_counts, rel_time_lang};
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::tasks::{
    list_name_groups_for_user, list_nvr_groups_for_user, list_tasks_with_counts_for_user,
};
use crate::server::routes::ui::components::{
    back_link, clickable_rows_script, count_chip, empty_state, filter_chips, filter_form,
    generate_nonce, list_page_head, page_with_csp, pagination_links, phase_status,
    FilterFormParams, PaginationParams,
};
use crate::server::routes::ui::i18n::{lang_from_headers, t, t_fmt, FmtKey, TextKey};
use crate::server::routes::ui::pages::page_size::page_size_from_headers;
use crate::server::routes::ui::service::{
    check_public_access, csrf_token_for_request, page_size_or_default, with_back_param, QueryParams,
};
use crate::server::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use maud::html;
use std::sync::Arc;

/// Package 列表页查询参数。
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct PackageListQuery {
    pub product: Option<String>,
    /// 包名子串过滤（Package 输入框，name 列 LIKE contains）。
    pub name: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

/// Package 详情页查询参数。
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct PackageDetailQuery {
    pub product: Option<String>,
    /// 精确主 NVR：有值时切换到"同 NVR 尝试列表"视图。
    pub nvr: Option<String>,
    /// 返回目标（`?back=`，来源列表页 path+query，经 [`safe_back_path`] 校验）。
    pub back: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

/// Package 历史页（列表）：按基础包名分组，用户可见性由 service 层收口（与任务列表同口径）。
pub(crate) async fn package_list_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<PackageListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    check_public_access(
        &app,
        app.server_config.public_access.view,
        auth.as_ref().map(|ext| &ext.0),
    )?;

    // ?limit= query > crbs_page_size cookie > 默认 50。
    let limit = page_size_or_default(q.limit.or(page_size_from_headers(&headers)));
    let offset = q
        .offset
        .unwrap_or(0)
        .min(crate::server::validation::MAX_LIST_OFFSET);
    // 空串/纯空白视为未过滤（filter_form 未填字段以空串回传）。
    let name = q.name.as_deref().map(str::trim).filter(|v| !v.is_empty());
    let filter = crbs_core::NvrGroupFilter {
        product: q.product.as_deref(),
        name,
        limit: Some(limit),
        offset: Some(offset),
        ..Default::default()
    };
    let resp = list_name_groups_for_user(&app, filter, auth.as_ref().map(|ext| &ext.0)).await?;

    let nonce = generate_nonce()?;
    let product = q.product.as_deref();
    let page_query = QueryParams {
        product,
        name,
        ..Default::default()
    };
    let current_list = page_query.url("/ui/packages", Some(offset));
    let lang = lang_from_headers(&headers);
    // 激活 chips 仅 product/name（包列表无相位过滤）；remove URL 去该参数、offset 归零。
    let mut active_chips: Vec<(String, String, String)> = Vec::new();
    if let Some(product) = product {
        let remove = QueryParams {
            product: None,
            name,
            ..Default::default()
        }
        .url("/ui/packages", None);
        active_chips.push((
            t(lang, TextKey::ThProduct).to_string(),
            product.to_string(),
            remove,
        ));
    }
    if let Some(name) = name {
        let remove = QueryParams {
            product,
            name: None,
            ..Default::default()
        }
        .url("/ui/packages", None);
        active_chips.push((
            t(lang, TextKey::ThPackage).to_string(),
            name.to_string(),
            remove,
        ));
    }
    let active_chips = filter_chips(&active_chips, lang);
    let toolbar = filter_form(FilterFormParams {
        base_path: "/ui/packages",
        product,
        name,
        label: None,
        phase: None,
        arch: None,
        priority: None,
        sort: None,
        chips: active_chips,
        lang,
    });
    let body = html! {
        // 页头：h1 = 导航名 + 总数 chip；meta/actions 留空（页无主操作）。
        (list_page_head(
            html! { (t(lang, TextKey::NavPackages)) " " (count_chip(resp.total)) },
            html! {},
            html! {},
        ))
        @if resp.groups.is_empty() {
            // 过滤条仍需可操作（调整/清除过滤）：空结果时卡内只留卡头。
            div class="table-card" { (toolbar) }
            (empty_state(t(lang, TextKey::EmptyPackagesTitle), t(lang, TextKey::EmptyPackagesHint)))
        } @else {
            div class="table-card" {
                (toolbar)
                table class="fixed" {
                    colgroup {
                        col style="width:auto" {}
                        col style="width:14%" {}
                        col style="width:11%" {}
                        col style="width:14%" {}
                    }
                    thead { tr { th { (t(lang, TextKey::ThName)) } th { (t(lang, TextKey::ThLatestPhase)) } th class="num" { (t(lang, TextKey::ThAttempts)) } th class="num" { (t(lang, TextKey::ThLastBuild)) } } }
                    tbody {
                        @for g in &resp.groups {
                            tr class="clickable-row" {
                                td class="ellipsis" title=(g.pkg_name) {
                                    a class="row-target" href=(with_back_param(&format!("/ui/packages/{}", urlencoding::encode(&g.pkg_name)), &current_list)) { (g.pkg_name) }
                                }
                                // Latest phase 落回包维度（与 Attempts 同目标），不直链 task。
                                td { a href=(format!("/ui/packages/{}", urlencoding::encode(&g.pkg_name))) { (phase_status(&g.phase, lang)) } }
                                td class="num" { a href=(format!("/ui/packages/{}", urlencoding::encode(&g.pkg_name))) { (g.attempts) } }
                                td class="num" { (rel_time_lang(g.submitted_at.as_deref(), lang)) }
                            }
                        }
                    }
                }
                (pagination_links(&PaginationParams {
                    base_path: "/ui/packages",
                        lang,
                    total: resp.total,
                    limit,
                    offset,
                    query: page_query,
                    raw_filter_qs: None,

                    csrf_token: csrf_token_for_request(&headers, &app.csrf_key).as_deref(),
                }))
            }
            (clickable_rows_script(&nonce))
        }
    };
    page_with_csp(
        t(lang, TextKey::NavPackages),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "packages",
        &headers,
        &app.csrf_key,
        body,
    )
}

/// Package 历史页（详情）：无 `nvr`（默认）= 按主 NVR 分组；有 `nvr` = 该 NVR 全部尝试任务列表（精确匹配 pkg_name）。
pub(crate) async fn package_detail_page(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<PackageDetailQuery>,
) -> Result<impl IntoResponse, ApiError> {
    check_public_access(
        &app,
        app.server_config.public_access.view,
        auth.as_ref().map(|ext| &ext.0),
    )?;
    if name.is_empty() {
        return Err(ApiError::Validation("package name is empty".into()));
    }

    // ?limit= query > crbs_page_size cookie > 默认 50。
    let limit = page_size_or_default(q.limit.or(page_size_from_headers(&headers)));
    // 与 API validate_list_pagination 同上限：usize::MAX 经 `offset as i64` 变
    // -1（SQLite 视作 0 / PG 直接 500），pagination_links 的 offset+limit 也会回绕。
    let offset = q
        .offset
        .unwrap_or(0)
        .min(crate::server::validation::MAX_LIST_OFFSET);
    let product = q.product.as_deref();
    // 空串规范化：空 nvr 视为无参数（回到分组视图）。
    let nvr = q.nvr.as_deref().filter(|v| !v.is_empty());
    let auth_ctx = auth.as_ref().map(|ext| &ext.0);
    let base_path = format!("/ui/packages/{}", urlencoding::encode(&name));
    let nonce = generate_nonce()?;
    let lang = lang_from_headers(&headers);

    // -------- 视图 B：同 NVR 尝试列表（有 nvr 参数）--------
    if let Some(nvr) = nvr {
        let filter = crbs_core::types::TaskListFilter {
            product,
            name: Some(&name),
            nvr: Some(nvr),
            limit: Some(limit),
            offset: Some(offset),
            ..Default::default()
        };
        let tasks = list_tasks_with_counts_for_user(&app, filter, auth_ctx).await?;

        let body = html! {
            // 页头条带：crumb 回分组视图（URL 带 product 过滤，非 ?back=/back_link）。
            div class="crumb" {
                p {
                    a href=(QueryParams { product, ..Default::default() }.url(&base_path, None)) { "← " (t(lang, TextKey::AllVersions)) }
                }
            }
            div class="page-head" {
                div class="title-block" {
                    h1 { (t_fmt(lang, FmtKey::PackageNvrTitle, &[&name, nvr])) }
                    @if let Some(p) = product {
                        div class="page-meta" {
                            (t(lang, TextKey::ThProduct)) ": "
                            a href=(QueryParams { product: Some(p), ..Default::default() }.url("/ui/builds", None)) { (p) }
                        }
                    }
                }
            }
            div class="admin-section" {
                h2 { (t_fmt(lang, FmtKey::AttemptsCount, &[&tasks.total.to_string()])) }
                @if tasks.tasks.is_empty() {
                    (empty_state(t(lang, TextKey::EmptyAttemptsTitle), t(lang, TextKey::EmptyAttemptsHint)))
                } @else {
                    div class="table-card" {
                        table class="fixed" {
                            colgroup {
                                col style="width:8%" {}
                                col style="width:auto" {}
                                col style="width:12%" {}
                                col style="width:14%" {}
                                col style="width:12%" {}
                                col style="width:14%" {}
                            }
                            thead { tr { th class="num" { (t(lang, TextKey::ThId)) } th { (t(lang, TextKey::ThProduct)) } th { (t(lang, TextKey::ThPhase)) } th { (t(lang, TextKey::NavBuilds)) } th { (t(lang, TextKey::ThUser)) } th class="num" { (t(lang, TextKey::ThSubmitted)) } } }
                            tbody {
                                @for t in &tasks.tasks {
                                    tr class="clickable-row" {
                                        td class="num" { a class="row-target" href=(format!("/ui/tasks/{}", t.task.id)) { (t.task.id) } }
                                        td class="ellipsis" title=(t.task.product) { (t.task.product) }
                                        td { (phase_status(&t.task.phase, lang)) }
                                        td { (child_build_counts(t.task.id, &t.build_counts, lang)) }
                                        td { (t.task.user) }
                                        td class="num" { (rel_time_lang(t.task.submitted_at.as_deref(), lang)) }
                                    }
                                }
                            }
                        }
                        (pagination_links(&PaginationParams {
                            base_path: &base_path,
                                lang,
                            total: tasks.total,
                            limit,
                            offset,
                            query: QueryParams {
                                product,
                                name: Some(&name),
                                nvr: Some(nvr),
                                ..Default::default()
                            },
                            raw_filter_qs: None,

                            csrf_token: csrf_token_for_request(&headers, &app.csrf_key).as_deref(),
                        }))
                    }
                }
            }
            (clickable_rows_script(&nonce))
        };
        return page_with_csp(
            &t_fmt(lang, FmtKey::PackageNvrTitle, &[&name, nvr]),
            &nonce,
            auth.as_ref().map(|ext| &ext.0),
            "packages",
            &headers,
            &app.csrf_key,
            body,
        );
    }

    // -------- 视图 A：按 NVR 分组（默认）--------
    let filter = crbs_core::NvrGroupFilter {
        product,
        name: Some(&name),
        limit: Some(limit),
        offset: Some(offset),
        ..Default::default()
    };
    let groups = list_nvr_groups_for_user(&app, filter, auth_ctx).await?;

    let body = html! {
        // 页头条带：crumb 走 back_link（safe_back_path）；Total 计数并入 h1 chip（不做双栏）。
        div class="crumb" {
            (back_link(t(lang, TextKey::BackToPackages), "/ui/packages", q.back.as_deref()))
        }
        div class="page-head" {
            div class="title-block" {
                h1 {
                    (t_fmt(lang, FmtKey::PackageTitle, &[&name]))
                    span class="count-chip" { (groups.total) }
                }
                div class="page-meta" {
                    @if let Some(p) = product {
                        (t(lang, TextKey::ThProduct)) ": "
                        a href=(QueryParams { product: Some(p), ..Default::default() }.url("/ui/builds", None)) { (p) }
                    }
                }
            }
        }
        div class="admin-section" {
            h2 { (t(lang, TextKey::Versions)) }
            @if groups.groups.is_empty() {
                (empty_state(t(lang, TextKey::EmptyVersionsTitle), t(lang, TextKey::EmptyVersionsHint)))
            } @else {
                div class="table-card" {
                    table class="fixed" {
                        colgroup {
                            col style="width:auto" {}
                            col style="width:14%" {}
                            col style="width:12%" {}
                            col style="width:12%" {}
                            col style="width:14%" {}
                        }
                        thead { tr { th { (t(lang, TextKey::ThNvr)) } th { (t(lang, TextKey::ThLatest)) } th class="num" { (t(lang, TextKey::ThAttempts)) } th { (t(lang, TextKey::ThUser)) } th class="num" { (t(lang, TextKey::ThSubmitted)) } } }
                        tbody {
                            @for g in &groups.groups {
                                tr class="clickable-row" {
                                    td class="ellipsis" title=(g.pkg_name) { a class="row-target" href=(QueryParams { product, nvr: Some(&g.pkg_name), ..Default::default() }.url(&base_path, None)) { (g.pkg_name) } }
                                    // Latest phase → 视图 B（URL 与同行 NVR 名链接一致）；task 下钻在视图 B。
                                    td { a href=(QueryParams { product, nvr: Some(&g.pkg_name), ..Default::default() }.url(&base_path, None)) { (phase_status(&g.phase, lang)) } }
                                    td class="num" { span class="count-badge" { (g.attempts) } }
                                    td { (g.user) }
                                    td class="num" { (rel_time_lang(g.submitted_at.as_deref(), lang)) }
                                }
                            }
                        }
                    }
                    (pagination_links(&PaginationParams {
                        base_path: &base_path,
                            lang,
                        total: groups.total,
                        limit,
                        offset,
                        query: QueryParams {
                            product,
                            ..Default::default()
                        },
                        raw_filter_qs: None,

                        csrf_token: csrf_token_for_request(&headers, &app.csrf_key).as_deref(),
                    }))
                }
            }
        }
        (clickable_rows_script(&nonce))
    };
    page_with_csp(
        &t_fmt(lang, FmtKey::PackageTitle, &[&name]),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "packages",
        &headers,
        &app.csrf_key,
        body,
    )
}
