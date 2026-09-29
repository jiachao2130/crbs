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

use super::{
    default_acl_role, phase_count, phase_counts_from_series, rel_time_lang, rel_time_text_lang,
    success_rate_gauge, BUILD_DURATION_BARS, SUCCESS_RATE_WINDOW,
};
use crate::server::auth::visibility::{
    check_chain_visibility, is_owner_or_admin, is_product_content_visible_to,
};
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::product::load_record_for_owner_or_admin;
use crate::server::routes::ui::components::{
    admin_inline_form, admin_select, back_link, clickable_rows_script, confirm_button, count_chip,
    danger_row, detail_grid, duration_chart, empty_state, filter_apply, filter_chips,
    format_local_time, gauge_chart, generate_nonce, list_page_head, page_with_csp,
    pagination_links, see_other_error_redirect, see_other_redirect, side_card, side_kv, stat_strip,
    status_message, storage_error_flash, user_cell, PaginationParams, StatStripItem, StatusQuery,
};
use crate::server::routes::ui::i18n::{
    lang_from_headers, role_label, t, t_fmt, visibility_label, FmtKey, Lang, TextKey,
};
use crate::server::routes::ui::pages::page_size::page_size_from_headers;
use crate::server::routes::ui::service::{
    build_filter_qs, check_public_access, csrf_token_for_request, current_list_url, require_csrf,
    with_back_param, CancelForm, QueryParams, PRODUCT_ACL_ROLES, UI_PAGE_SIZE,
};
use crate::server::state::AppState;
use crate::server::validation::validate_product_name;
use axum::extract::{Extension, Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use crbs_core::ProductRecord;
use maud::{html, Markup};
use std::sync::Arc;

/// 读取合并后的 product 配置（product-layer + CrbsConfig + server override）：
/// DB 不存在视为 404，权限过滤由调用方结合 `is_product_content_visible_to` 完成。
async fn load_product_detail(
    app: &AppState,
    name: &str,
) -> Result<crbs_core::config::ProductDetail, ApiError> {
    match app
        .state_store
        .load_merged_config_for_any_product_by_name(name)
        .await
    {
        Ok(cfg) => {
            let mut detail = crbs_core::config::ProductDetail::from(cfg);
            app.apply_display_paths(&mut detail, name).await;
            Ok(detail)
        }
        Err(e) if e.is_not_found() => Err(ApiError::not_found("product", name)),
        Err(e) => Err(ApiError::log_and_internal_with_context(
            "load product config",
            e,
        )),
    }
}

/// user_id → 展示名：优先 username，行缺失 / 查询失败回退 `user#N`
/// （批量版见 [`resolve_user_names`]）。
async fn user_display_name(app: &AppState, id: i64) -> String {
    match app.state_store.get_user(id).await {
        Ok(Some(u)) => u.name,
        Ok(None) => {
            tracing::warn!(
                user_id = id,
                "user row missing while rendering product page"
            );
            format!("user#{id}")
        }
        Err(e) => {
            tracing::warn!(user_id = id, error = %e, "get_user failed while rendering product page");
            format!("user#{id}")
        }
    }
}

/// 批量解析 user_id → username：同 id 只查一次，解析失败落 `user#N` 不挡页面。
async fn resolve_user_names(
    app: &AppState,
    ids: impl Iterator<Item = i64>,
) -> std::collections::HashMap<i64, String> {
    let mut names = std::collections::HashMap::new();
    for id in ids {
        if names.contains_key(&id) {
            continue;
        }
        names.insert(id, user_display_name(app, id).await);
    }
    names
}

/// products 列表页查询参数：`name` 模糊匹配（大小写不敏感 contains）、
/// `visibility` 精确匹配（public/private，其余值视为不过滤）+ 分页 offset。
#[derive(serde::Deserialize, Default)]
pub(crate) struct ProductsListQuery {
    pub name: Option<String>,
    pub visibility: Option<String>,
    #[serde(default)]
    pub offset: i64,
}

pub(crate) async fn list_products_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<ProductsListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    check_public_access(
        &app,
        app.server_config.public_access.view,
        auth.as_ref().map(|ext| &ext.0),
    )?;

    let auth_ref = auth.as_ref().map(|ext| &ext.0);
    let summaries = app
        .state_store
        .load_product_summaries()
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("load product summaries", e))?;

    // build_target 链合并值未设置时回退全局（product-override-or-global 语义）。
    let global = crbs_core::config::CrbsConfig::load_async().await.unwrap_or_else(|e| {
        tracing::warn!(error = %e, "Failed to load global config for products list; using defaults");
        crbs_core::config::CrbsConfig::default()
    });

    let name_filter = q.name.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let name_lower = name_filter.map(|s| s.to_lowercase());
    let visibility_filter = q
        .visibility
        .as_deref()
        .filter(|v| *v == crbs_core::VISIBILITY_PUBLIC || *v == crbs_core::VISIBILITY_PRIVATE);

    let mut rows: Vec<&crbs_core::ProductSummary> = summaries
        .iter()
        .filter(|s| is_product_content_visible_to(s.owner_id, &s.visibility, &s.name, auth_ref))
        .filter(|s| {
            name_lower
                .as_ref()
                .is_none_or(|n| s.name.to_lowercase().contains(n))
        })
        .filter(|s| visibility_filter.is_none_or(|v| s.visibility == v))
        .collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));

    let total = rows.len();
    let offset_val = (q
        .offset
        .clamp(0, crate::server::validation::MAX_LIST_OFFSET as i64)) as usize;
    let page_size = page_size_from_headers(&headers).unwrap_or(UI_PAGE_SIZE);
    let page: &[&crbs_core::ProductSummary] =
        &rows[offset_val.min(total)..(offset_val + page_size).min(total)];
    let owner_names = resolve_user_names(&app, page.iter().filter_map(|s| s.owner_id)).await;
    // 活动列：页内产品名一次批量聚合（Tasks 总数 + 最近构建时间）；
    // 零任务产品不在 map（渲染 0 / "—"）。
    let page_products: Vec<String> = page.iter().map(|s| s.name.clone()).collect();
    let activity = app
        .state_store
        .product_activity_for_products(&page_products)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("load product activity", e))?;
    // 当前列表页 URL：详情链接 back 参数的目标（过滤参数 + 当前页码）。
    let filter_qs = build_filter_qs(&[("name", name_filter), ("visibility", visibility_filter)]);
    let current_list = current_list_url("/ui/products", &filter_qs, offset_val);
    let nonce = generate_nonce()?;
    let can_create = auth_ref.is_some_and(|c| c.is_builder());
    // 空串（DB Some("") / 全局配置）视为未设置：显示 "—"（UI 层统一空值标记，见 pages/mod.rs）。
    let global_build_target = if global.build_target.is_empty() {
        "—"
    } else {
        global.build_target.as_str()
    };
    let lang = lang_from_headers(&headers);
    // 激活过滤 chips：name 原值、visibility 显示名（与过滤选项 label 同源）。
    let mut active_chips: Vec<(String, String, String)> = Vec::new();
    if let Some(name) = name_filter {
        let remove = current_list_url(
            "/ui/products",
            &build_filter_qs(&[("name", None), ("visibility", visibility_filter)]),
            0,
        );
        active_chips.push((
            t(lang, TextKey::ThName).to_string(),
            name.to_string(),
            remove,
        ));
    }
    if let Some(visibility) = visibility_filter {
        let remove = current_list_url(
            "/ui/products",
            &build_filter_qs(&[("name", name_filter), ("visibility", None)]),
            0,
        );
        active_chips.push((
            t(lang, TextKey::ThVisibility).to_string(),
            visibility_label(lang, visibility).to_string(),
            remove,
        ));
    }
    let active_chips = filter_chips(&active_chips, lang);
    // 过滤条并入卡头：filter_form 组件无 visibility 字段，手写同构标记，chips 尾置。
    let toolbar = html! {
        form class="filter-bar" method="get" action="/ui/products" {
            label {
                (t(lang, TextKey::ThName))
                input type="text" name="name" value=(name_filter.unwrap_or("")) placeholder=(t(lang, TextKey::PlaceholderProduct));
            }
            label {
                (t(lang, TextKey::ThVisibility))
                (admin_select("visibility", &[
                    ("", t(lang, TextKey::FilterAll)),
                    (crbs_core::VISIBILITY_PUBLIC, visibility_label(lang, crbs_core::VISIBILITY_PUBLIC)),
                    (crbs_core::VISIBILITY_PRIVATE, visibility_label(lang, crbs_core::VISIBILITY_PRIVATE)),
                ], visibility_filter))
            }
            (filter_apply("/ui/products", lang))
            (active_chips)
        }
    };
    let body = html! {
        (list_page_head(
            html! { (t(lang, TextKey::NavProducts)) " " (count_chip(total)) },
            html! {},
            html! {
                @if can_create {
                    a class="action-button" href="/ui/products/new" { (t(lang, TextKey::NewProduct)) }
                }
            },
        ))
        @if total == 0 {
            // 过滤条仍需可操作（调整/清除过滤）：空结果时卡内只留卡头。
            div class="table-card" { (toolbar) }
            @if summaries.is_empty() {
                (empty_state(t(lang, TextKey::EmptyProductsTitle), t(lang, TextKey::EmptyProductsHint)))
            } @else {
                (empty_state(t(lang, TextKey::EmptyProductsMatchTitle), t(lang, TextKey::EmptyProductsMatchHint)))
            }
        } @else {
            div class="table-card" {
                (toolbar)
                table class="fixed" {
                    // 定宽列合计 73%，Build target 吃剩余 auto 宽度。
                    colgroup {
                        col style="width:14%" {}
                        col style="width:10%" {}
                        col style="width:9%" {}
                        col style="width:10%" {}
                        col style="width:8%" {}
                        col style="width:8%" {}
                        col style="width:14%" {}
                        col style="width:auto" {}
                    }
                    thead {
                        tr {
                            th { (t(lang, TextKey::ThName)) }
                            th { (t(lang, TextKey::ThParent)) }
                            th { (t(lang, TextKey::ThVisibility)) }
                            th { (t(lang, TextKey::ThOwner)) }
                            th class="num" { (t(lang, TextKey::MeRevision)) }
                            th class="num" { (t(lang, TextKey::ThTasks)) }
                            th class="num" { (t(lang, TextKey::ThLastBuild)) }
                            th { (t(lang, TextKey::ThBuildTarget)) }
                        }
                    }
                    tbody {
                        @for s in page {
                            tr class="clickable-row" {
                                td class="ellipsis" title=(s.name) { a class="row-target" href=(with_back_param(&format!("/ui/products/{}", urlencoding::encode(&s.name)), &current_list)) { (s.name) } }
                                td {
                                    @match &s.parent_name {
                                        Some(pn) => a href=(format!("/ui/products/{}", urlencoding::encode(pn))) { (pn) },
                                        None => "—",
                                    }
                                }
                                td {
                                    // private 用 warn 族徽章（受限语义），public 中性灰。
                                    @if s.visibility == crbs_core::VISIBILITY_PRIVATE {
                                        span class="badge warn" { (visibility_label(lang, &s.visibility)) }
                                    } @else {
                                        span class="badge" { (visibility_label(lang, &s.visibility)) }
                                    }
                                }
                                td {
                                    @match s.owner_id.and_then(|id| owner_names.get(&id)) {
                                        Some(name) => (user_cell(name)),
                                        None => "—",
                                    }
                                }
                                td class="num" { (s.revision) }
                                // Tasks 无活动显示 0，Last build 无任务为 "—"（口径同详情页）。
                                td class="num" { (activity.get(&s.name).map_or(0, |a| a.total_tasks)) }
                                td class="num" { (rel_time_lang(activity.get(&s.name).and_then(|a| a.last_task_at.as_deref()), lang)) }
                                td { (s.build_target.as_deref().filter(|t| !t.is_empty()).unwrap_or(global_build_target)) }
                            }
                        }
                    }
                }
                (pagination_links(&PaginationParams {
                    base_path: "/ui/products",
                        lang,
                    total,
                    limit: page_size,
                    offset: offset_val,
                    query: QueryParams::default(),
                    raw_filter_qs: Some(&filter_qs),

                    csrf_token: csrf_token_for_request(&headers, &app.csrf_key).as_deref(),                }))
            }
            (clickable_rows_script(&nonce))
        }
    };
    page_with_csp(
        t(lang, TextKey::NavProducts),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "products",
        &headers,
        &app.csrf_key,
        body,
    )
}

/// GET 侧可见产品加载（产品三页共用）：按名查行 + 内容可见性判 404（同名
/// 同因，不泄露存在性）；详情页的链上可见性检查由调用方追加。
pub(super) async fn load_visible_product(
    app: &AppState,
    auth: Option<&AuthContext>,
    name: &str,
) -> Result<ProductRecord, ApiError> {
    let Some(record) = app.state_store.get_product_by_name(name).await? else {
        return Err(ApiError::not_found("product", name));
    };
    if !is_product_content_visible_to(record.owner_id, &record.visibility, &record.name, auth) {
        return Err(ApiError::not_found("product", name));
    }
    Ok(record)
}

/// 产品详情页（查看走产品可见性；声明下限编辑在源码包详情页，仅 hub admin）。
pub(crate) async fn product_detail_page(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<StatusQuery>,
    Query(profile_q): Query<super::product_profiles::ProfileListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    check_public_access(
        &app,
        app.server_config.public_access.view,
        auth.as_ref().map(|ext| &ext.0),
    )?;
    validate_product_name(&name)?;

    let record = load_visible_product(&app, auth.as_ref().map(|ext| &ext.0), &name).await?;
    let auth_ref = auth.as_ref().map(|ext| &ext.0);
    // 链上所有节点必须可见（私有祖先不可泄露）
    check_chain_visibility(&app, record.id, auth_ref).await?;
    let detail = load_product_detail(&app, &name).await?;

    // 产品总览带数据：页面加载时一次计算（同 /ui/me 模式）。
    let phase_counts = app
        .state_store
        .count_tasks_by_phase_for_product(&name)
        .await
        .map_err(ApiError::from)?;
    let series = app
        .state_store
        .recent_task_phase_series_for_product(&name, SUCCESS_RATE_WINDOW)
        .await
        .map_err(ApiError::from)?;
    let recent_counts = phase_counts_from_series(&series);
    let durations = app
        .state_store
        .recent_succeeded_build_durations_for_product(&name, BUILD_DURATION_BARS)
        .await
        .map_err(ApiError::from)?;
    // 最近构建时间：该产品最新一条 task（默认 id DESC）的 completed_at，
    // 进行中（未完成）回退 submitted_at；无任务 → None 渲染 "—"。
    let (_latest_total, latest_tasks) = app
        .state_store
        .list_tasks(&crbs_core::types::TaskListFilter {
            product: Some(name.as_str()),
            limit: Some(1),
            ..Default::default()
        })
        .await
        .map_err(ApiError::from)?;
    let last_build_at = latest_tasks
        .first()
        .and_then(|t| t.completed_at.as_deref().or(t.submitted_at.as_deref()));
    // 包数：/ui/packages 同口径（list_name_groups 按基础包名分组 total）。
    // ponytail: 复用 (total, Vec) 查询 limit=1 只取 total；包量数百开销可忽略，
    // 不为 count-only 加变体，包列表页改分组口径时此处自动跟随。
    let (package_total, _groups) = app
        .state_store
        .list_name_groups(&crbs_core::NvrGroupFilter {
            product: Some(name.as_str()),
            limit: Some(1),
            ..Default::default()
        })
        .await
        .map_err(ApiError::from)?;

    // 资源画像：源码包级分组（画像键 = builds.name，版本只作历史维度）。
    // 展示面失败不 500 整页，降级空卡。
    let profiles_all = match app.state_store.list_profiles_by_product(&name).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(product = %name, error = %e, "Failed to list resource profiles");
            Vec::new()
        }
    };
    let profile_filter = super::product_profiles::ProfileFilter::from_query(&profile_q);
    let profile_groups =
        super::product_profiles::build_profile_groups(&profiles_all, &profile_filter);
    let profile_total = profile_groups.len();
    let profile_limit = page_size_from_headers(&headers).unwrap_or(UI_PAGE_SIZE);
    let profile_offset = profile_q.offset.min(profile_total.saturating_sub(1));
    let profile_end = (profile_offset + profile_limit).min(profile_total);
    let profile_page = &profile_groups[profile_offset..profile_end];
    let page_sources: Vec<&str> = profile_page.iter().map(|g| g.source_name).collect();
    let latest_builds =
        super::product_profiles::load_latest_builds(&app, &name, &page_sources).await;

    let csrf_token = csrf_token_for_request(&headers, &app.csrf_key);

    // chain-resolve 出口 effective TOML（worker 实际看到的合并结果）。resolve 校验
    // 失败不 `?` 整页 500：详情页即诊断工具，错误文本渲染进 `<pre>` 其余照常。
    let resolved_toml = app.state_store.chain_resolve_to_toml(record.id).await;

    // parent 展示——按 id 回查 name。FK 语义下 parent_id 存在则 name 必存在。
    let parent_info: Option<(i64, String)> = match record.parent_id {
        Some(pid) => app
            .state_store
            .get_product_by_id(pid)
            .await?
            .map(|p| (pid, p.name)),
        None => None,
    };

    let shared_layer_text = match &detail.shared_layer {
        crbs_core::config::BoolOrPackages::Bool(b) => b.to_string(),
        crbs_core::config::BoolOrPackages::Packages(pkgs) => pkgs.join(", "),
    };
    let ccache_text = match &detail.ccache_enabled {
        crbs_core::config::BoolOrPackages::Bool(b) => b.to_string(),
        crbs_core::config::BoolOrPackages::Packages(pkgs) => pkgs.join(", "),
    };

    let is_owner_or_admin = is_owner_or_admin(record.owner_id, auth_ref);
    let acls: Vec<(String, String, String)> = if is_owner_or_admin {
        match app.state_store.list_users_by_product(&name).await {
            Ok(users) => users
                .into_iter()
                .map(|u| (u.name, u.role, u.created_at))
                .collect(),
            Err(e) => {
                tracing::warn!(product = %name, error = %e, "Failed to list ACLs for product");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    let owner_name: Option<String> = match record.owner_id {
        Some(id) => Some(user_display_name(&app, id).await),
        None => None,
    };

    let nonce = generate_nonce()?;
    let lang = lang_from_headers(&headers);

    // SRPM 下载策略三态（Ownership 卡只读展示，普通访问者可见）：产品显式覆盖
    // 优先，省略跟随全局。链解析失败回退全局——展示位不因产品配置损坏而 500。
    let srpm_override = app
        .state_store
        .resolve_any_product_by_name(&name)
        .await
        .ok()
        .and_then(|resolved| resolved.config.allow_srpm_download);
    let srpm_effective = srpm_override.unwrap_or(app.server_config.allow_srpm_download);
    let srpm_policy_text = match (srpm_override, srpm_effective) {
        (Some(true), _) | (None, true) => t(lang, TextKey::SrpmPolicyPublic).to_string(),
        (Some(false), _) | (None, false) => t(lang, TextKey::SrpmPolicyOperator).to_string(),
    };
    let srpm_policy_text = if srpm_override.is_none() {
        format!(
            "{} · {}",
            t(lang, TextKey::SrpmPolicyFollowGlobal),
            srpm_policy_text
        )
    } else {
        srpm_policy_text
    };

    // 总览带：Running/Queued 沿用 home donut 相位映射（running→building、
    // queued→pending），gauge 走 pages 共享 helper（与 /ui/me 同口径）。
    let task_total: i64 = phase_counts.values().sum();
    let items = [
        StatStripItem {
            label: t(lang, TextKey::ProductStatTasks),
            value: task_total.to_string(),
            ok: false,
            title: None,
        },
        StatStripItem {
            label: t(lang, TextKey::LegendRunning),
            value: phase_count(&phase_counts, "building").to_string(),
            ok: false,
            title: None,
        },
        StatStripItem {
            label: t(lang, TextKey::LegendQueued),
            value: phase_count(&phase_counts, "pending").to_string(),
            ok: false,
            title: None,
        },
        StatStripItem {
            label: t(lang, TextKey::ProductStatLastBuild),
            value: rel_time_text_lang(last_build_at, lang),
            ok: false,
            title: last_build_at.map(format_local_time),
        },
        StatStripItem {
            label: t(lang, TextKey::ProductStatPackages),
            value: package_total.to_string(),
            ok: false,
            title: None,
        },
        StatStripItem {
            label: t(lang, TextKey::MeRevision),
            value: format!("r{}", record.revision),
            ok: false,
            title: None,
        },
    ];
    let (success_pct, gauge_side) = success_rate_gauge(&recent_counts, lang);

    // Details 卡：服务器绝对路径行仅 owner/admin 展示（防基础设施侦察）。
    let mut details_rows: Vec<(Markup, Markup)> = vec![
        (html! { (t(lang, TextKey::ThId)) }, html! { (record.id) }),
        (
            html! { (t(lang, TextKey::ThParent)) },
            html! {
                @match &parent_info {
                    Some((pid, pname)) => {
                        // ParentWithId 模板双占位符：传 (pname, pid) 双参，整句作链接文本。
                        a href=(format!("/ui/products/{}", urlencoding::encode(pname))) {
                            (t_fmt(
                                lang,
                                FmtKey::ParentWithId,
                                &[pname.as_str(), pid.to_string().as_str()],
                            ))
                        }
                    },
                    None => (t(lang, TextKey::RootProductPlaceholder)),
                }
            },
        ),
        (
            html! { "base_os_revision" },
            html! { (record.base_os_revision) },
        ),
        (
            html! { (t(lang, TextKey::LabelBackend)) },
            html! { (if detail.backend.is_empty() { "—" } else { detail.backend.as_str() }) },
        ),
        (
            html! { (t(lang, TextKey::ThBuildTarget)) },
            html! { (if detail.build_target.is_empty() { "—" } else { detail.build_target.as_str() }) },
        ),
        (
            html! { (t(lang, TextKey::LabelNetwork)) },
            html! { (if detail.network { t(lang, TextKey::Yes) } else { t(lang, TextKey::No) }) },
        ),
        (
            html! { (t(lang, TextKey::LabelBuildTmpfs)) },
            html! { (if detail.build_tmpfs { t(lang, TextKey::Yes) } else { t(lang, TextKey::No) }) },
        ),
        (
            html! { (t(lang, TextKey::LabelSharedLayer)) },
            html! { (shared_layer_text) },
        ),
        (html! { "ccache" }, html! { (ccache_text) }),
    ];
    if let Some(v) = &detail.memory_max {
        details_rows.push((html! { (t(lang, TextKey::LabelMemoryMax)) }, html! { (v) }));
    }
    if let Some(v) = &detail.cpu_quota {
        details_rows.push((html! { (t(lang, TextKey::LabelCpuQuota)) }, html! { (v) }));
    }
    if is_owner_or_admin {
        details_rows.push((
            html! { (t(lang, TextKey::LabelResultDir)) },
            html! { code { (detail.result_dir.display().to_string()) } },
        ));
        details_rows.push((
            html! { (t(lang, TextKey::LabelCrbsRoot)) },
            html! { code { (detail.crbs_root.display().to_string()) } },
        ));
    }
    let ownership_rows: Vec<(Markup, Markup)> = vec![
        (
            html! { (t(lang, TextKey::ThVisibility)) },
            html! { (visibility_label(lang, &record.visibility)) },
        ),
        (
            html! { (t(lang, TextKey::ThOwner)) },
            html! {
                @match &owner_name {
                    Some(owner) => (owner),
                    None => (t(lang, TextKey::OfficialProductNote)),
                }
            },
        ),
        (
            html! { (t(lang, TextKey::LabelSrpmDownload)) },
            html! { (srpm_policy_text) },
        ),
    ];

    let body = html! {
        div class="crumb" {
            (back_link(t(lang, TextKey::BackToProducts), "/ui/products", q.back.as_deref()))
        }
        div class="page-head" {
            div class="title-block" {
                h1 {
                    (t_fmt(lang, FmtKey::ProductTitle, &[&detail.product]))
                    span class="count-chip" { "r" (record.revision) }
                }
                div class="page-meta" {
                    a href=(QueryParams { product: Some(&detail.product), ..Default::default() }.url("/ui/tasks", None)) { (t(lang, TextKey::NavTasks)) }
                    span class="sep" { "·" }
                    a href=(QueryParams { product: Some(&detail.product), ..Default::default() }.url("/ui/builds", None)) { (t(lang, TextKey::NavBuilds)) }
                    span class="sep" { "·" }
                    a href=(format!("/ui/products/{}/history", urlencoding::encode(&record.name))) { (t(lang, TextKey::HistoryLabel)) }
                }
            }
            @if is_owner_or_admin {
                div class="header-actions" {
                    a class="action-button" href=(format!("/ui/products/{}/edit", urlencoding::encode(&record.name))) { (t(lang, TextKey::EditConfig)) }
                }
            }
        }
        (status_message(&q, &app.csrf_key, lang))
        (detail_grid(
            html! {
                // 复用 /ui/me 的 .me-overview 布局类（strip + gauge 同行，窄屏折行）。
                div class="me-overview" {
                    (stat_strip(&items, lang))
                    (gauge_chart("product", success_pct, gauge_side, lang))
                }
                section class="viz-panel" {
                    h3 { (t(lang, TextKey::PanelBuildDurations)) }
                    div class="viz-fill" { (duration_chart(&durations, lang)) }
                }
                div class="admin-section" {
                    h2 { (t(lang, TextKey::SectionBasePackages)) }
                    @if detail.base_packages.is_empty() {
                        (empty_state(t(lang, TextKey::EmptyBasePackagesTitle), t(lang, TextKey::EmptyBasePackagesHint)))
                    } @else {
                        ul {
                            @for p in &detail.base_packages {
                                li { (p) }
                            }
                        }
                    }
                }
                div class="admin-section" {
                    h2 { (t(lang, TextKey::SectionRepos)) }
                    @if detail.repos.is_empty() {
                        p { (t(lang, TextKey::NoRepos)) }
                    } @else {
                        table class="fixed" {
                            colgroup {
                                col style="width:16%" {}
                                col style="width:auto" {}
                                col style="width:10%" {}
                                col style="width:12%" {}
                                col style="width:11%" {}
                                col style="width:9%" {}
                            }
                            thead {
                                tr {
                                    th { (t(lang, TextKey::ThName)) }
                                    th { (t(lang, TextKey::ThBaseUrl)) }
                                    th { (t(lang, TextKey::ThEnabled)) }
                                    th { (t(lang, TextKey::ThGpgCheck)) }
                                    th class="num" { (t(lang, TextKey::FilterPriority)) }
                                    th class="num" { (t(lang, TextKey::ThCost)) }
                                }
                            }
                            tbody {
                                @for repo in &detail.repos {
                                    tr {
                                        td class="ellipsis" title=(repo.name) { (repo.name) }
                                        td class="ellipsis" title=(repo.baseurl) { code { (repo.baseurl) } }
                                        td { (if repo.enabled { t(lang, TextKey::Yes) } else { t(lang, TextKey::No) }) }
                                        td { (if repo.gpgcheck { t(lang, TextKey::Yes) } else { t(lang, TextKey::No) }) }
                                        td class="num" { (repo.priority) }
                                        td class="num" { (repo.cost) }
                                    }
                                }
                            }
                        }
                    }
                }
                div class="admin-section" {
                    h2 { (t(lang, TextKey::SectionRpmMacros)) }
                    @if detail.rpm_macros.is_empty() {
                        p { (t(lang, TextKey::NoMacros)) }
                    } @else {
                        table class="fixed" {
                            colgroup {
                                col style="width:20%" {}
                                col style="width:auto" {}
                            }
                            thead { tr { th { (t(lang, TextKey::ThName)) } th { (t(lang, TextKey::ThValue)) } } }
                            tbody {
                                @for (k, v) in &detail.rpm_macros {
                                    tr { td class="ellipsis" title=(k) { (k) } td class="ellipsis" title=(v) { code { (v) } } }
                                }
                            }
                        }
                    }
                }
                div class="admin-section" {
                    h2 { (t(lang, TextKey::SectionHooks)) }
                    @if detail.hooks.pre.is_empty() && detail.hooks.post.is_empty() && detail.hooks.spec_pre.is_empty() && detail.hooks.spec_post.is_empty() {
                        p { (t(lang, TextKey::NoHooks)) }
                    } @else {
                        // h3 是 TOML 槽位标识符（机器面非用户文案）：不进 i18n，zh 原样显示。
                        @if !detail.hooks.pre.is_empty() {
                            h3 { "pre" }
                            ul { @for hook in detail.hooks.pre.keys() { li { (hook) } } }
                        }
                        @if !detail.hooks.post.is_empty() {
                            h3 { "post" }
                            ul { @for hook in detail.hooks.post.keys() { li { (hook) } } }
                        }
                        @if !detail.hooks.spec_pre.is_empty() {
                            h3 { "spec pre" }
                            ul { @for hook in detail.hooks.spec_pre.keys() { li { (hook) } } }
                        }
                        @if !detail.hooks.spec_post.is_empty() {
                            h3 { "spec post" }
                            ul { @for hook in detail.hooks.spec_post.keys() { li { (hook) } } }
                        }
                    }
                }
                (super::product_profiles::resource_profiles_section(
                    super::product_profiles::ProfileSectionParams {
                        lang,
                        product: &name,
                        groups: profile_page,
                        total: profile_total,
                        offset: profile_offset,
                        limit: profile_limit,
                        filter: &profile_filter,
                        latest: &latest_builds,
                        csrf_token: csrf_token.as_deref(),
                    },
                ))
                @if is_owner_or_admin {
                    div class="admin-section" {
                        h2 { (t(lang, TextKey::SectionAcl)) }
                        @if let Some(token) = csrf_token.as_ref() {
                            (admin_inline_form(&format!("/ui/products/{}/acl", urlencoding::encode(&record.name)), token, html! {
                                label {
                                    (t(lang, TextKey::ThUser))
                                    input type="text" name="username" placeholder=(t(lang, TextKey::PlaceholderUsername)) required;
                                }
                                label {
                                    (t(lang, TextKey::ThRole))
                                    // role value=机器串，label 走 role_label 本地化。
                                    (admin_select(
                                        "role",
                                        &PRODUCT_ACL_ROLES.map(|r| (r, role_label(lang, r))),
                                        Some("viewer")
                                    ))
                                }
                            }, t(lang, TextKey::GrantAccess)))
                        }
                        @if acls.is_empty() {
                            p { (t(lang, TextKey::NoAclEntries)) }
                        } @else {
                            // table-wrap 横滚保护：Granted 列装不下时溢出盖住撤销
                            // 按钮，col-granted 定宽 + 表级 min-width（机制见 style.css）。
                            div class="table-wrap" {
                                table class="fixed acl-table" {
                                    colgroup {
                                        col style="width:22%" {}
                                        col style="width:16%" {}
                                        col class="col-granted" {}
                                        col style="width:auto" {}
                                    }
                                    thead {
                                        tr {
                                            th { (t(lang, TextKey::ThUser)) }
                                            th { (t(lang, TextKey::ThRole)) }
                                            th class="num" { (t(lang, TextKey::ThGranted)) }
                                            th { (t(lang, TextKey::ThAction)) }
                                        }
                                    }
                                    tbody {
                                        @for (username, role, created_at) in &acls {
                                            tr {
                                                td class="ellipsis" title=(username) { (username) }
                                                td { (role) }
                                                td class="num" { (format_local_time(created_at)) }
                                                td {
                                                    @if let Some(token) = csrf_token.as_ref() {
                                                        form class="admin-inline-form" method="post" action=(format!("/ui/products/{}/acl/{}/revoke", urlencoding::encode(&record.name), urlencoding::encode(username))) {
                                                            input type="hidden" name="csrf_token" value=(token);
                                                            (confirm_button(t(lang, TextKey::ButtonRevoke), &t_fmt(lang, FmtKey::ConfirmRevokeAclUser, &[username])))
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
                    // 解析后的完整 TOML 同样含路径等内部配置，与侧栏路径行同一门槛。
                    div class="admin-section" {
                        h2 { (t(lang, TextKey::SectionEffectiveToml)) }
                        p { (t(lang, TextKey::EffectiveTomlDesc)) }
                        @match &resolved_toml {
                            Ok(toml) => pre class="code-block" { code { (toml.as_str()) } },
                            Err(e) => pre class="code-block" { code { (t_fmt(lang, FmtKey::ChainResolveFailed, &[&e.to_string()])) } },
                        }
                    }
                }
            },
            html! {
                (side_card("", t(lang, TextKey::SideDetailsTitle), side_kv(&details_rows)))
                // Ownership 信息卡：展示行 + 公开/私有说明，操作面在下方 Danger zone。
                (side_card(
                    "",
                    t(lang, TextKey::SectionOwnership),
                    html! {
                        (side_kv(&ownership_rows))
                        @if record.visibility == "public" {
                            p class="admin-card-desc" { (t(lang, TextKey::ProductPublicNote)) }
                        } @else {
                            p class="admin-card-desc" { (t(lang, TextKey::ProductPrivateNote)) }
                        }
                    },
                ))
                @if let Some(token) = csrf_token.as_ref() {
                    (side_card(
                        "danger-zone",
                        t(lang, TextKey::DangerZoneTitle),
                        html! {
                            @if record.visibility == "public" {
                                // 危险方向（收窄可见性）：红色 confirm_button + 后果文案。
                                (danger_row(
                                    t(lang, TextKey::MakePrivate),
                                    t(lang, TextKey::DangerMakePrivateDesc),
                                    html! {
                                        form class="admin-inline-form" method="post" action=(format!("/ui/products/{}/visibility", urlencoding::encode(&record.name))) {
                                            input type="hidden" name="csrf_token" value=(token);
                                            input type="hidden" name="visibility" value="private";
                                            input type="hidden" name="expected_revision" value=(record.revision);
                                            (confirm_button(t(lang, TextKey::MakePrivate), t(lang, TextKey::ConfirmMakePrivate)))
                                        }
                                    },
                                ))
                            } @else {
                                // 放宽方向同样弹确认（对所有人可见），次要描边样式非红。
                                (danger_row(
                                    t(lang, TextKey::MakePublic),
                                    t(lang, TextKey::DangerMakePublicDesc),
                                    html! {
                                        form class="admin-inline-form" method="post" action=(format!("/ui/products/{}/visibility", urlencoding::encode(&record.name))) {
                                            input type="hidden" name="csrf_token" value=(token);
                                            input type="hidden" name="visibility" value="public";
                                            input type="hidden" name="expected_revision" value=(record.revision);
                                            button class="action-button secondary" type="submit"
                                                data-confirm=(t(lang, TextKey::ConfirmMakePublic)) { (t(lang, TextKey::MakePublic)) }
                                        }
                                    },
                                ))
                            }
                            // 转让：官方产品连带变 private + 取消进行中构建/任务
                            // （transfer_product_ownership 事务语义）。
                            (danger_row(
                                t(lang, TextKey::TransferOwnership),
                                t(lang, TextKey::DangerTransferDesc),
                                html! {
                                    form class="admin-inline-form" method="post" action=(format!("/ui/products/{}/transfer", urlencoding::encode(&record.name))) {
                                        input type="hidden" name="csrf_token" value=(token);
                                        label {
                                            (t(lang, TextKey::NewOwnerUsername))
                                            input type="text" name="new_owner_username" placeholder=(t(lang, TextKey::PlaceholderUsername)) required;
                                        }
                                        input type="hidden" name="expected_revision" value=(record.revision);
                                        @if record.owner_id.is_none() {
                                            (confirm_button(t(lang, TextKey::TransferOwnership), t(lang, TextKey::ConfirmTransferOfficial)))
                                        } @else {
                                            (confirm_button(t(lang, TextKey::TransferOwnership), t(lang, TextKey::ConfirmTransferOwnership)))
                                        }
                                    }
                                },
                            ))
                            // 重建 repo（admin-only）：权限独立于 owner/admin 偏序判断。
                            @if auth_ref.is_some_and(|ctx| ctx.is_admin()) {
                                (danger_row(
                                    t(lang, TextKey::RebuildRepo),
                                    t(lang, TextKey::MaintenanceDesc),
                                    html! {
                                        form class="admin-inline-form" method="post" action=(format!("/ui/products/{}/rebuild-repo", urlencoding::encode(&record.name))) {
                                            input type="hidden" name="csrf_token" value=(token);
                                            (confirm_button(t(lang, TextKey::RebuildRepo), t(lang, TextKey::ConfirmRebuildRepo)))
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
        &t_fmt(lang, FmtKey::ProductTitle, &[&detail.product]),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "products",
        &headers,
        &app.csrf_key,
        body,
    )
}

/// 产品详情页路径（产品页 POST 的 redirect / error-flash 目标）。
fn product_detail_path(name: &str) -> String {
    format!("/ui/products/{}", urlencoding::encode(name))
}

/// 产品页 POST 的取行前奏：复用 API 侧 `load_record_for_owner_or_admin`
/// （缺失/越权同名 404 防探测，表单渲染后被删重定向无增益），存储错改道
/// 303 签名 flash 回详情页。外层 Err 即调用方原样返回的响应。
// Err 即重定向前置信封（家法嵌套 Result 形态），装箱会伤五处调用方 ? 形态。
#[allow(clippy::result_large_err)]
async fn load_record_for_page_post(
    app: &AppState,
    name: &str,
    auth: Option<&AuthContext>,
    csrf_key: &[u8; 32],
) -> Result<ProductRecord, Result<(StatusCode, HeaderMap, Markup), ApiError>> {
    match load_record_for_owner_or_admin(app, name, auth).await {
        Ok(record) => Ok(record),
        Err(e @ ApiError::NotFound(_)) => Err(Err(e)),
        Err(e) => Err(see_other_error_redirect(
            &product_detail_path(name),
            &storage_error_flash("load product", e.message()),
            csrf_key,
        )),
    }
}

/// 更新产品可见性（publish/unpublish），权限：仅 owner/admin。可达失败路径
/// （并发修订/链泄漏/非法值/存储错误）一律 303 回详情页带签名 error flash。
pub(crate) async fn product_visibility_post(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<ProductVisibilityForm>,
) -> Result<impl IntoResponse, ApiError> {
    let auth_ref = auth.as_ref().map(|ext| &ext.0);
    let lang = lang_from_headers(&headers);

    require_csrf(&headers, &form.csrf_token, &app.csrf_key)?;

    validate_product_name(&name)?;

    let record = match load_record_for_page_post(&app, &name, auth_ref, &app.csrf_key).await {
        Ok(r) => r,
        Err(exit) => return exit,
    };

    // 乐观并发：expected_revision 必须匹配当前 DB revision。
    if form.expected_revision != record.revision {
        let expected = form.expected_revision.to_string();
        let current = record.revision.to_string();
        return see_other_error_redirect(
            &product_detail_path(&name),
            &t_fmt(lang, FmtKey::FlashRevisionConflict, &[&expected, &current]),
            &app.csrf_key,
        );
    }

    if form.visibility != crbs_core::VISIBILITY_PUBLIC
        && form.visibility != crbs_core::VISIBILITY_PRIVATE
    {
        return see_other_error_redirect(
            &product_detail_path(&name),
            &t_fmt(lang, FmtKey::FlashInvalidVisibility, &[&form.visibility]),
            &app.csrf_key,
        );
    }

    // 官方产品（owner_id=None）不能 unpublish（SCHEMA 约束）
    if record.owner_id.is_none() && form.visibility == crbs_core::VISIBILITY_PRIVATE {
        return see_other_error_redirect(
            &product_detail_path(&name),
            t(lang, TextKey::FlashOfficialProductPrivate),
            &app.csrf_key,
        );
    }

    // unpublish（private）前检查是否有 public 后代（避免泄漏私有祖先链）
    if form.visibility == crbs_core::VISIBILITY_PRIVATE {
        let has_public_descendants = match app.state_store.has_public_descendants(record.id).await {
            Ok(v) => v,
            Err(e) => {
                return see_other_error_redirect(
                    &product_detail_path(&name),
                    &storage_error_flash("check public descendants", &e),
                    &app.csrf_key,
                );
            }
        };
        if has_public_descendants {
            return see_other_error_redirect(
                &product_detail_path(&name),
                t(lang, TextKey::FlashUnpublishPublicDescendants),
                &app.csrf_key,
            );
        }
    }

    // publish（public）前检查整条祖先链是否全 public
    if form.visibility == crbs_core::VISIBILITY_PUBLIC {
        let mut cursor = record.parent_id;
        while let Some(pid) = cursor {
            let parent = match app.state_store.get_product_by_id(pid).await {
                Ok(Some(p)) => p,
                // FK 语义下 parent_id 存在则行必存在；并发删除属异常路径。
                Ok(None) => {
                    return see_other_error_redirect(
                        &product_detail_path(&name),
                        &t_fmt(lang, FmtKey::FlashParentDisappeared, &[&pid.to_string()]),
                        &app.csrf_key,
                    )
                }
                Err(e) => {
                    return see_other_error_redirect(
                        &product_detail_path(&name),
                        &storage_error_flash("load parent product", &e),
                        &app.csrf_key,
                    );
                }
            };
            if parent.visibility != crbs_core::VISIBILITY_PUBLIC {
                return see_other_error_redirect(
                    &product_detail_path(&name),
                    &t_fmt(lang, FmtKey::FlashPublishPrivateAncestor, &[&parent.name]),
                    &app.csrf_key,
                );
            }
            cursor = parent.parent_id;
        }
    }

    if let Err(e) = app
        .state_store
        .update_product_visibility(
            record.id,
            &form.visibility,
            auth_ref.and_then(|c| c.user_id),
            None,
            Some(form.expected_revision),
        )
        .await
    {
        return see_other_error_redirect(
            &product_detail_path(&name),
            &storage_error_flash("update visibility", &e),
            &app.csrf_key,
        );
    }

    see_other_redirect(&format!(
        "{}?status=visibility_updated",
        product_detail_path(&name)
    ))
}

/// 产品可见性更新表单。
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ProductVisibilityForm {
    pub visibility: String,
    pub expected_revision: i64,
    pub csrf_token: String,
}

/// 授予产品 ACL（admin 或 owner；区别于 admin 专属的 admin_acl_grant）。可达失败
/// 路径（角色非法/用户不存在/owner 冗余授权/存储错误）→ 303 签名 error flash 回详情页。
pub(crate) async fn product_acl_grant(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<ProductAclGrantForm>,
) -> Result<impl IntoResponse, ApiError> {
    let auth_ref = auth.as_ref().map(|ext| &ext.0);
    let lang = lang_from_headers(&headers);

    require_csrf(&headers, &form.csrf_token, &app.csrf_key)?;

    validate_product_name(&name)?;

    let record = match load_record_for_page_post(&app, &name, auth_ref, &app.csrf_key).await {
        Ok(r) => r,
        Err(exit) => return exit,
    };

    if !PRODUCT_ACL_ROLES.contains(&form.role.as_str()) {
        return see_other_error_redirect(
            &product_detail_path(&name),
            &t_fmt(lang, FmtKey::FlashProductAclInvalidRole, &[&form.role]),
            &app.csrf_key,
        );
    }

    let target_user = match app.state_store.find_user_by_name(&form.username).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return see_other_error_redirect(
                &product_detail_path(&name),
                &t_fmt(lang, FmtKey::FlashUserNotFoundByName, &[&form.username]),
                &app.csrf_key,
            )
        }
        Err(e) => {
            return see_other_error_redirect(
                &product_detail_path(&name),
                &storage_error_flash("find user", &e),
                &app.csrf_key,
            );
        }
    };

    // 不能给 owner 授予 ACL（owner 本身已有全部权限）
    if Some(target_user.id) == record.owner_id {
        return see_other_error_redirect(
            &product_detail_path(&name),
            t(lang, TextKey::FlashOwnerFullAccess),
            &app.csrf_key,
        );
    }

    if let Err(e) = app
        .state_store
        .grant_product_acl_with_role(target_user.id, &record.name, &form.role)
        .await
    {
        return see_other_error_redirect(
            &product_detail_path(&name),
            &storage_error_flash("grant ACL", &e),
            &app.csrf_key,
        );
    }

    see_other_redirect(&format!(
        "{}?status=acl_granted",
        product_detail_path(&name)
    ))
}

/// 产品 ACL 授予表单。
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ProductAclGrantForm {
    pub username: String,
    #[serde(default = "default_acl_role")]
    pub role: String,
    pub csrf_token: String,
}

/// 撤销产品 ACL（admin 或 owner）。可达失败路径（用户不存在/存储错误）→
/// 303 签名 error flash 回详情页。
pub(crate) async fn product_acl_revoke(
    State(app): State<Arc<AppState>>,
    Path((name, acl_username)): Path<(String, String)>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<ProductAclRevokeForm>,
) -> Result<impl IntoResponse, ApiError> {
    let auth_ref = auth.as_ref().map(|ext| &ext.0);
    let lang = lang_from_headers(&headers);

    require_csrf(&headers, &form.csrf_token, &app.csrf_key)?;

    validate_product_name(&name)?;

    let record = match load_record_for_page_post(&app, &name, auth_ref, &app.csrf_key).await {
        Ok(r) => r,
        Err(exit) => return exit,
    };

    let target_user = match app.state_store.find_user_by_name(&acl_username).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return see_other_error_redirect(
                &product_detail_path(&name),
                &t_fmt(lang, FmtKey::FlashUserNotFoundByName, &[&acl_username]),
                &app.csrf_key,
            )
        }
        Err(e) => {
            return see_other_error_redirect(
                &product_detail_path(&name),
                &storage_error_flash("find user", &e),
                &app.csrf_key,
            );
        }
    };

    if let Err(e) = app
        .state_store
        .revoke_product_acl(target_user.id, &record.name)
        .await
    {
        return see_other_error_redirect(
            &product_detail_path(&name),
            &storage_error_flash("revoke ACL", &e),
            &app.csrf_key,
        );
    }

    see_other_redirect(&format!(
        "{}?status=acl_revoked",
        product_detail_path(&name)
    ))
}

/// 产品 ACL 撤销表单。
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ProductAclRevokeForm {
    pub csrf_token: String,
}

/// 转让产品所有权（admin 或 owner）。可达失败路径（public 后代保护/新 owner
/// 不存在/转让给自己/存储错误）→ 303 签名 error flash 回详情页。
pub(crate) async fn product_transfer_post(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<ProductTransferForm>,
) -> Result<impl IntoResponse, ApiError> {
    let auth_ref = auth.as_ref().map(|ext| &ext.0);
    let lang = lang_from_headers(&headers);

    require_csrf(&headers, &form.csrf_token, &app.csrf_key)?;

    validate_product_name(&name)?;

    let record = match load_record_for_page_post(&app, &name, auth_ref, &app.csrf_key).await {
        Ok(r) => r,
        Err(exit) => return exit,
    };

    // 官方产品转让会连带变 private，须先确保无 public 后代（leak 保护）；
    // 私人产品转让 keep visibility 且为 private，后代必为 private，无需检查。
    if record.owner_id.is_none() {
        let has_public_descendants = match app.state_store.has_public_descendants(record.id).await {
            Ok(v) => v,
            Err(e) => {
                return see_other_error_redirect(
                    &product_detail_path(&name),
                    &storage_error_flash("check public descendants", &e),
                    &app.csrf_key,
                );
            }
        };
        if has_public_descendants {
            return see_other_error_redirect(
                &product_detail_path(&name),
                t(lang, TextKey::FlashTransferOfficialPublicDescendants),
                &app.csrf_key,
            );
        }
    }

    let new_owner = match app
        .state_store
        .find_user_by_name(&form.new_owner_username)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return see_other_error_redirect(
                &product_detail_path(&name),
                &t_fmt(
                    lang,
                    FmtKey::FlashUserNotFoundByName,
                    &[&form.new_owner_username],
                ),
                &app.csrf_key,
            )
        }
        Err(e) => {
            return see_other_error_redirect(
                &product_detail_path(&name),
                &storage_error_flash("find user", &e),
                &app.csrf_key,
            );
        }
    };

    if Some(new_owner.id) == record.owner_id {
        return see_other_error_redirect(
            &product_detail_path(&name),
            t(lang, TextKey::FlashTransferToCurrentOwner),
            &app.csrf_key,
        );
    }

    if let Err(e) = app
        .state_store
        .transfer_product_ownership(
            record.id,
            new_owner.id,
            auth_ref.and_then(|c| c.user_id),
            None,
            Some(form.expected_revision),
        )
        .await
    {
        return see_other_error_redirect(
            &product_detail_path(&name),
            &storage_error_flash("transfer ownership", &e),
            &app.csrf_key,
        );
    }

    see_other_redirect(&format!(
        "{}?status=ownership_transferred",
        product_detail_path(&name)
    ))
}

/// 产品所有权转让表单。
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ProductTransferForm {
    pub new_owner_username: String,
    pub expected_revision: i64,
    pub csrf_token: String,
}

/// 触发产品发布 repo 对账式全量重建（admin-only UI 版，与 API
/// `POST /api/v1/admin/products/{product}/rebuild-repo` 同源）：同步执行
/// `assemble_for_product`，失败 303 回详情页带签名 error flash（可重试）；
/// 非 admin 或产品不存在 → 404 防探测。
pub(crate) async fn product_rebuild_repo_post(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<CancelForm>,
) -> Result<impl IntoResponse, ApiError> {
    let auth_ref = auth.as_ref().map(|ext| &ext.0);

    require_csrf(&headers, &form.csrf_token, &app.csrf_key)?;

    validate_product_name(&name)?;

    let record = match load_record_for_page_post(&app, &name, auth_ref, &app.csrf_key).await {
        Ok(r) => r,
        Err(exit) => return exit,
    };

    // admin-only：与详情页 Maintenance 区块的显示条件一致。
    let Some(ctx) = auth_ref.filter(|c| c.is_admin()) else {
        return Err(ApiError::not_found("product", &name));
    };

    let report = match crate::server::repo_regen::assemble_for_product(&app, &record.name).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(product = %record.name, error = %e, "Rebuild product repo failed via admin UI");
            // storage_error_flash 内部还会 warn 一次，与上行 error! 双写留痕。
            return see_other_error_redirect(
                &product_detail_path(&record.name),
                &storage_error_flash("rebuild product repo", &e),
                &app.csrf_key,
            );
        }
    };

    let detail = serde_json::json!({
        "product": record.name,
        "arches": report.arches,
        "linked": report.linked,
        "unlinked": report.unlinked,
    })
    .to_string();
    let _ = app
        .state_store
        .audit_log(
            &ctx.user,
            &ctx.role,
            "rebuild_repo",
            Some(&record.name),
            Some(&detail),
        )
        .await;

    tracing::info!(
        product = %record.name,
        arches = ?report.arches,
        linked = report.linked,
        unlinked = report.unlinked,
        user = %ctx.user,
        "Product repo rebuilt via admin UI"
    );

    see_other_redirect(&format!(
        "{}?status=repo_rebuilt",
        product_detail_path(&record.name)
    ))
}

/// 产品配置历史页（只读）：revision DESC；显示的 config 仅本层（不含继承合并结果）。
/// ≥2 个 revision 时提供 From/To 单选 + 提交跳转服务端 diff 页（只读对比）；
/// 回滚仍走 CLI（`crbs products update --expected-revision …`）显式操作，避免误点。
pub(crate) async fn product_history_page(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    check_public_access(
        &app,
        app.server_config.public_access.view,
        auth.as_ref().map(|ext| &ext.0),
    )?;
    validate_product_name(&name)?;

    let record = load_visible_product(&app, auth.as_ref().map(|ext| &ext.0), &name).await?;
    let auth_ref = auth.as_ref().map(|ext| &ext.0);

    let entries = app.state_store.list_product_history(record.id).await?;
    let changer_names =
        resolve_user_names(&app, entries.iter().filter_map(|e| e.changed_by_user_id)).await;
    let nonce = generate_nonce()?;
    let lang = lang_from_headers(&headers);
    // 默认对比 from=次新、to=最新（entries DESC，[0] 为最新）；单 revision 不渲染单选列。
    let radio = (entries.len() >= 2).then(|| (entries[1].revision, entries[0].revision));
    let body = html! {
        div class="crumb" {
            (back_link(
                t(lang, TextKey::BackToProduct),
                &format!("/ui/products/{}", urlencoding::encode(&record.name)),
                None,
            ))
        }
        div class="page-head" {
            div class="title-block" {
                h1 { (t_fmt(lang, FmtKey::ProductHistoryTitle, &[&record.name])) }
            }
        }
        @if entries.is_empty() {
            p { (t(lang, TextKey::NoHistoryEntries)) }
        } @else if let Some((default_from, default_to)) = radio {
            // GET 提交到 diff 页（只读对比，无需 CSRF）。
            form method="get" action=(format!("/ui/products/{}/history/diff", urlencoding::encode(&record.name))) {
                (product_history_table(&entries, &changer_names, lang, default_from, default_to))
                button class="action-button" type="submit" { (t(lang, TextKey::CompareRevisions)) }
            }
        } @else {
            (product_history_table(&entries, &changer_names, lang, 0, 0))
        }
    };
    page_with_csp(
        &t_fmt(lang, FmtKey::HistoryTitle, &[&record.name]),
        &nonce,
        auth_ref,
        "products",
        &headers,
        &app.csrf_key,
        body,
    )
}

/// history 页表格：`default_from`/`default_to` > 0 渲染 From/To 单选列（值 = revision），
/// 否则五列纯展示（0/0 即"无单选列"哨兵，revision 恒正所以安全）。
fn product_history_table(
    entries: &[crbs_core::ProductConfigHistoryEntry],
    changer_names: &std::collections::HashMap<i64, String>,
    lang: Lang,
    default_from: i64,
    default_to: i64,
) -> Markup {
    let selectable = default_from > 0 && default_to > 0;
    html! {
        // history 全量展示，无分页。
        div class="table-card" {
            table class="fixed" {
                // Reason 是自由文本：auto 列换行显示（不截断）。
                colgroup {
                    @if selectable {
                        col style="width:6%" {}
                        col style="width:6%" {}
                    }
                    col style="width:10%" {}
                    col style="width:14%" {}
                    col style="width:13%" {}
                    col style="width:13%" {}
                    col style="width:auto" {}
                }
                thead {
                    tr {
                        @if selectable {
                            th { (t(lang, TextKey::ThDiffFrom)) }
                            th { (t(lang, TextKey::ThDiffTo)) }
                        }
                        th class="num" { (t(lang, TextKey::MeRevision)) }
                        th class="num" { "base_os_revision" }
                        th class="num" { (t(lang, TextKey::ThChangedAt)) }
                        th { (t(lang, TextKey::ThChangedBy)) }
                        th { (t(lang, TextKey::ThReason)) }
                    }
                }
                tbody {
                    @for e in entries {
                        tr {
                            @if selectable {
                                td { input type="radio" name="from" value=(e.revision) checked[e.revision == default_from]; }
                                td { input type="radio" name="to" value=(e.revision) checked[e.revision == default_to]; }
                            }
                            td class="num" { (e.revision) }
                            td class="num" { (e.base_os_revision) }
                            td class="num" { (rel_time_lang(Some(e.changed_at.as_str()), lang)) }
                            td {
                                @match e.changed_by_user_id.and_then(|id| changer_names.get(&id)) {
                                    Some(name) => (name),
                                    None => "—",
                                }
                            }
                            td { (e.reason.as_deref().filter(|r| !r.is_empty()).unwrap_or("—")) }
                        }
                    }
                }
            }
        }
    }
}

/// 产品配置历史 diff 页查询参数：`from` / `to` 为 revision 号。
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ProductHistoryDiffQuery {
    pub from: Option<i64>,
    pub to: Option<i64>,
}

/// history 快照 → 归一 TOML（fail-soft）：与详情页 Effective TOML 同口径，两个
/// revision 各自归一后对比，同内容不同 JSON 序列化细节不产生假 diff。快照损坏
/// 不让 diff 页 500：该侧回退原始 `config_json`，bool = 是否回退（调用方渲染
/// [`FmtKey::HistoryDiffRawFallback`] notice）；错误细节只进日志。
fn history_snapshot_toml(entry: &crbs_core::ProductConfigHistoryEntry) -> (String, bool) {
    // 两阶段错误类型不同，统一成带阶段上下文的字符串只进日志，页面不透出细节。
    let normalized = serde_json::from_str::<crbs_core::config::ProductConfig>(&entry.config_json)
        .map_err(|e| format!("parse config_json: {e}"))
        .and_then(|cfg| {
            cfg.to_toml_string()
                .map_err(|e| format!("serialize config to toml: {e}"))
        });
    match normalized {
        Ok(toml) => (toml, false),
        Err(e) => {
            tracing::warn!(
                revision = entry.revision,
                error = %e,
                "History snapshot config unusable; diff falls back to raw content"
            );
            (entry.config_json.clone(), true)
        }
    }
}

/// diff 渲染行数上限：防巨型配置撑爆页面。ponytail: 全文件渲染不分组 hunk
/// （产品配置通常几十行）；规模显著增长（数千行）换 `similar` `grouped_ops(3)`。
const DIFF_MAX_LINES: usize = 2000;

/// 渲染 unified 风格行级 diff（similar）：ctx 灰 / removed 红 / added 绿，
/// 老/新双侧行号 + `-`/`+` 前缀；超过 [`DIFF_MAX_LINES`] 行截断并提示。
fn render_config_diff(lang: Lang, from_toml: &str, to_toml: &str) -> Markup {
    let diff = similar::TextDiff::from_lines(from_toml, to_toml);

    struct DiffRow<'a> {
        class: &'static str,
        sign: char,
        old: Option<usize>,
        new: Option<usize>,
        text: std::borrow::Cow<'a, str>,
    }
    let mut rows: Vec<DiffRow> = Vec::new();
    let mut truncated = false;
    for change in diff.iter_all_changes() {
        if rows.len() >= DIFF_MAX_LINES {
            truncated = true;
            break;
        }
        let (class, sign) = match change.tag() {
            similar::ChangeTag::Equal => ("diff-ctx", ' '),
            similar::ChangeTag::Delete => ("diff-del", '-'),
            similar::ChangeTag::Insert => ("diff-ins", '+'),
        };
        rows.push(DiffRow {
            class,
            sign,
            // similar 行号 0-based：Equal 双侧、Delete 仅老、Insert 仅新（None 列留空）。
            old: change.old_index().map(|i| i + 1),
            new: change.new_index().map(|i| i + 1),
            // from_lines 的行值带尾随换行（除末行），HTML 渲染前去掉。
            text: match change.to_string_lossy() {
                std::borrow::Cow::Borrowed(s) => {
                    std::borrow::Cow::Borrowed(s.strip_suffix('\n').unwrap_or(s))
                }
                std::borrow::Cow::Owned(s) => {
                    std::borrow::Cow::Owned(s.strip_suffix('\n').map(str::to_owned).unwrap_or(s))
                }
            },
        });
    }

    html! {
        @if truncated {
            p class="diff-truncated" { (t_fmt(lang, FmtKey::DiffTruncatedNote, &[&DIFF_MAX_LINES.to_string()])) }
        }
        div class="diff-block" {
            @for r in &rows {
                div class={ "diff-line " (r.class) } {
                    span class="diff-ln" { @if let Some(n) = r.old { (n) } }
                    span class="diff-ln" { @if let Some(n) = r.new { (n) } }
                    span class="diff-sign" { (r.sign) }
                    span class="diff-text" { (r.text) }
                }
            }
        }
    }
}

/// 产品配置历史 diff 页（只读）：`GET /ui/products/{name}/history/diff?from=N&to=M`，
/// 取两 revision 快照归一 TOML 后 similar 行级 diff，可见性门禁同 history 页。
/// 参数缺失/非正/revision 不在该产品历史中 → 404 防探测；非数字参数先于产品
/// 查询被 Query rejection 拒 → 400，无探测面。from == to 或归一后相同 → 空态。
pub(crate) async fn product_history_diff_page(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<ProductHistoryDiffQuery>,
) -> Result<impl IntoResponse, ApiError> {
    check_public_access(
        &app,
        app.server_config.public_access.view,
        auth.as_ref().map(|ext| &ext.0),
    )?;
    validate_product_name(&name)?;

    let record = load_visible_product(&app, auth.as_ref().map(|ext| &ext.0), &name).await?;
    let auth_ref = auth.as_ref().map(|ext| &ext.0);
    // diff 渲染完整 ProductConfig（含 result_dir/crbs_root/base_os_path 与
    // repos[].extra 可能的凭据行）——详情页刻意只对 owner/admin 展示这些
    // 路径，diff 必须同门禁；对其他人按不存在处理，避免绕过。
    if !is_owner_or_admin(record.owner_id, auth_ref) {
        return Err(ApiError::not_found("product", name));
    }

    let (from_rev, to_rev) = match (q.from, q.to) {
        (Some(f), Some(t)) if f > 0 && t > 0 => (f, t),
        _ => {
            return Err(ApiError::not_found(
                "revision range",
                format!("{}..{}", q.from.unwrap_or(0), q.to.unwrap_or(0)),
            ))
        }
    };
    let from_entry = match app
        .state_store
        .get_product_history_revision(record.id, from_rev)
        .await?
    {
        Some(e) => e,
        None => {
            return Err(ApiError::not_found(
                "product history revision",
                format!("{name}#{from_rev}"),
            ))
        }
    };
    let to_entry = match app
        .state_store
        .get_product_history_revision(record.id, to_rev)
        .await?
    {
        Some(e) => e,
        None => {
            return Err(ApiError::not_found(
                "product history revision",
                format!("{name}#{to_rev}"),
            ))
        }
    };

    let (from_toml, from_raw) = history_snapshot_toml(&from_entry);
    let (to_toml, to_raw) = history_snapshot_toml(&to_entry);

    let names = resolve_user_names(
        &app,
        [from_entry.changed_by_user_id, to_entry.changed_by_user_id]
            .into_iter()
            .flatten(),
    )
    .await;
    let nonce = generate_nonce()?;
    let lang = lang_from_headers(&headers);
    // 页头 revision 摘要行："rN by user, 相对时间"（与 history 表格同信息口径）。
    let rev_meta = |e: &crbs_core::ProductConfigHistoryEntry| {
        let user = e
            .changed_by_user_id
            .and_then(|id| names.get(&id).cloned())
            .unwrap_or_else(|| "—".to_string());
        t_fmt(
            lang,
            FmtKey::DiffRevMeta,
            &[
                &e.revision.to_string(),
                &user,
                &rel_time_text_lang(Some(e.changed_at.as_str()), lang),
            ],
        )
    };
    let body = html! {
        div class="crumb" {
            (back_link(
                t(lang, TextKey::BackToProductHistory),
                &format!("/ui/products/{}/history", urlencoding::encode(&record.name)),
                None,
            ))
        }
        div class="page-head" {
            div class="title-block" {
                h1 { (t_fmt(lang, FmtKey::ProductHistoryDiffTitle, &[&record.name])) }
                div class="page-meta" {
                    (t(lang, TextKey::ThDiffFrom)) ": " (rev_meta(&from_entry))
                    span class="sep" { "→" }
                    (t(lang, TextKey::ThDiffTo)) ": " (rev_meta(&to_entry))
                }
            }
        }
        @if from_raw {
            div class="message warning" role="note" {
                (t_fmt(lang, FmtKey::HistoryDiffRawFallback, &[&from_entry.revision.to_string()]))
            }
        }
        @if to_raw {
            div class="message warning" role="note" {
                (t_fmt(lang, FmtKey::HistoryDiffRawFallback, &[&to_entry.revision.to_string()]))
            }
        }
        @if from_toml == to_toml {
            (empty_state(
                t(lang, TextKey::DiffNoChangesTitle),
                t(lang, TextKey::DiffNoChangesHint),
            ))
        } @else {
            (render_config_diff(lang, &from_toml, &to_toml))
        }
    };
    page_with_csp(
        &t_fmt(lang, FmtKey::HistoryDiffTitle, &[&record.name]),
        &nonce,
        auth_ref,
        "products",
        &headers,
        &app.csrf_key,
        body,
    )
}
