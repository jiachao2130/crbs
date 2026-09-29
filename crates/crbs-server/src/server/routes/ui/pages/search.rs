// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2/
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 全局搜索页：task#/build# 直达 + 产品/包名前缀跳转列表；纯服务端，nav 搜索框 GET 表单提交 `?q=`。
//! 各区全部无命中则整区不渲染；不可见/不存在的直达目标同样不渲染（不泄露存在性）。

use crate::server::auth::visibility::{
    compute_visible_products, ensure_product_visible_for_record, is_product_content_visible_to,
};
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::ui::components::{empty_state, generate_nonce, page_with_csp};
use crate::server::routes::ui::i18n::{lang_from_headers, t, t_fmt, FmtKey, TextKey};
use crate::server::routes::ui::service::check_public_access;
use crate::server::state::AppState;
use axum::extract::{Extension, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use maud::html;
use std::sync::Arc;

const PREFIX_RESULT_LIMIT: usize = 8;

/// 查询词长度上限（信任边界：URL 查询参数截断，防滥用）。
const MAX_QUERY_CHARS: usize = 200;

#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct SearchQuery {
    pub q: Option<String>,
}

/// q → 直达 ID：解析为正整数才有效（"007"/"+7" 按 i64 解析语义收为 7）。
fn parse_direct_id(q: &str) -> Option<i64> {
    q.parse::<i64>().ok().filter(|v| *v > 0)
}

/// 直达条目可见性判定，与详情页谓词同口径（task_detail_page / fetch_build_with_rpms）：
/// `ensure_product_visible_for_record` 产品级检查（孤儿按公开）；
/// 不可见 `Ok(false)`（不渲染、不泄露存在性），DB 故障照传（同详情页 5xx）。
async fn record_visible(
    app: &AppState,
    product: &str,
    auth: Option<&AuthContext>,
) -> Result<bool, ApiError> {
    match ensure_product_visible_for_record(app, product, auth).await {
        Ok(()) => Ok(true),
        Err(ApiError::PermissionDenied(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

pub(crate) async fn search_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<SearchQuery>,
) -> Result<impl IntoResponse, ApiError> {
    check_public_access(
        &app,
        app.server_config.public_access.view,
        auth.as_ref().map(|ext| &ext.0),
    )?;
    let auth_ref = auth.as_ref().map(|ext| &ext.0);
    let lang = lang_from_headers(&headers);

    // 信任边界：trim + 空串归一为未查询 + 截断到 MAX_QUERY_CHARS。
    let query: Option<String> =
        q.q.as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| v.chars().take(MAX_QUERY_CHARS).collect());

    // -------- 直达区：q 为正整数时按 task/build 两套 ID 空间各查一次 --------
    let direct_id = query.as_deref().and_then(parse_direct_id);
    let direct_task = match direct_id {
        Some(id) => match app.state_store.get_task(id).await.map_err(ApiError::from)? {
            Some(task) if record_visible(&app, &task.product, auth_ref).await? => Some(task),
            _ => None,
        },
        None => None,
    };
    let direct_build = match direct_id {
        Some(id) => match app
            .state_store
            .get_build(id)
            .await
            .map_err(ApiError::from)?
        {
            Some(build) if record_visible(&app, &build.product, auth_ref).await? => Some(build),
            _ => None,
        },
        None => None,
    };

    let mut products: Vec<crbs_core::ProductSummary> = Vec::new();
    let mut packages: Vec<String> = Vec::new();
    if let Some(q_lower) = query.as_ref().map(|s| s.to_lowercase()) {
        let summaries = app
            .state_store
            .load_product_summaries()
            .await
            .map_err(|e| ApiError::log_and_internal_with_context("load product summaries", e))?;
        let mut matched: Vec<crbs_core::ProductSummary> = summaries
            .into_iter()
            .filter(|s| {
                is_product_content_visible_to(s.owner_id, &s.visibility, &s.name, auth_ref)
                    && s.name.to_lowercase().starts_with(&q_lower)
            })
            .collect();
        matched.sort_by(|a, b| a.name.cmp(&b.name));
        products = matched.into_iter().take(PREFIX_RESULT_LIMIT).collect();

        let visible_products = compute_visible_products(&app, auth_ref).await?;
        // ponytail: store 层 LIKE 是子串匹配，PG 端对 ASCII 大小写敏感（SQLite 不敏感）——
        // 大小写不同的行在 SQL 预取阶段就丢，下方 Rust to_lowercase 前缀过滤只能再收窄、补不回来，
        // PG 全链路大小写敏感为已知限制；升级路径：store 层改 LIKE 'q%' 前缀 + SQL lower()。
        // limit=None 全量取回子串命中（数百包名可接受，>1k 同走该路径）；可见性白名单 + 孤儿豁免同 /ui/packages。
        let (_, names) = app
            .state_store
            .list_package_names(
                None,
                None,
                query.as_deref(),
                visible_products.as_deref(),
                None,
                0,
            )
            .await
            .map_err(ApiError::from)?;
        packages = names
            .into_iter()
            .filter(|n| n.to_lowercase().starts_with(&q_lower))
            .take(PREFIX_RESULT_LIMIT)
            .collect();
    }

    let has_direct = direct_task.is_some() || direct_build.is_some();
    let any_hit = has_direct || !products.is_empty() || !packages.is_empty();

    let nonce = generate_nonce()?;
    let body = html! {
        h1 {
            @match query.as_deref() {
                Some(qv) => (t_fmt(lang, FmtKey::SearchTitle, &[qv])),
                None => (t(lang, TextKey::SearchPageTitle)),
            }
        }
        form class="search-box" method="get" action="/ui/search" {
            input type="search" name="q" value=(query.as_deref().unwrap_or(""))
                aria-label=(t(lang, TextKey::SearchPlaceholder))
                placeholder=(t(lang, TextKey::SearchPlaceholder))
                autofocus[query.is_none()];
        }
        @if has_direct {
            h2 { (t(lang, TextKey::SearchDirectTitle)) }
            ul {
                @if let Some(task) = &direct_task {
                    li {
                        a href=(format!("/ui/tasks/{}", task.id)) {
                            (t_fmt(lang, FmtKey::TaskTitle, &[&task.id.to_string()]))
                        }
                        " — " (task.pkg_label())
                    }
                }
                @if let Some(build) = &direct_build {
                    li {
                        a href=(format!("/ui/builds/{}", build.id)) {
                            (t_fmt(lang, FmtKey::BuildTitle, &[&build.id.to_string()]))
                        }
                        " — " (build.pkg_name)
                    }
                }
            }
        }
        @if !products.is_empty() {
            h2 { (t(lang, TextKey::NavProducts)) }
            ul {
                @for s in &products {
                    li { a href=(format!("/ui/products/{}", urlencoding::encode(&s.name))) { (s.name) } }
                }
            }
        }
        @if !packages.is_empty() {
            h2 { (t(lang, TextKey::NavPackages)) }
            ul {
                @for name in &packages {
                    li { a href=(format!("/ui/packages?name={}", urlencoding::encode(name))) { (name) } }
                }
            }
        }
        // 空 q 空态不走 empty_state：h1 已是 "Search"，再带标题会双标题；聚焦中的输入框即号召，仅留弱色提示行（.search-hint）。
        @if query.is_none() {
            p class="search-hint" { (t(lang, TextKey::SearchEmptyQueryHint)) }
        } @else if !any_hit {
            (empty_state(t(lang, TextKey::SearchEmptyTitle), t(lang, TextKey::SearchEmptyHint)))
        }
    };
    let title = match query.as_deref() {
        Some(qv) => t_fmt(lang, FmtKey::SearchTitle, &[qv]),
        None => t(lang, TextKey::SearchPageTitle).to_string(),
    };
    // active 用独立 "search" 键：nav 无搜索项，任何导航链接都不高亮。
    page_with_csp(
        &title,
        &nonce,
        auth_ref,
        "search",
        &headers,
        &app.csrf_key,
        body,
    )
}
