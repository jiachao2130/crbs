// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产品页资源画像（源码包维度）与源码包画像详情页：包级列表（筛选/排序/分页/
//! CSV 导出）、按架构的画像明细、最近构建历史，以及 hub admin 的声明下限编辑。
//! 画像键是 `(product, source_name, arch)`：同一源码包的版本只作为历史样本维度。

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::extract::{Extension, Form, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use maud::{html, Markup};

use crbs_core::config::validation::parse_resource_min_kb;
use crbs_core::types::BuildListFilter;
use crbs_core::{LatestSourceBuild, PackageResourceProfile};

use crate::server::auth::visibility::check_chain_visibility;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::audit_event;
use crate::server::routes::ui::components::{
    back_link, empty_state, filter_apply, format_kb_human, generate_nonce, page_with_csp,
    pagination_links, phase_badge, see_other_error_redirect, see_other_redirect, status_message,
    storage_error_flash, PaginationParams, StatusQuery,
};
use crate::server::routes::ui::i18n::{lang_from_headers, t, t_fmt, FmtKey, Lang, TextKey};
use crate::server::routes::ui::pages::page_size::page_size_from_headers;
use crate::server::routes::ui::service::{
    build_filter_qs, check_public_access, csrf_token_for_request, require_csrf, UI_PAGE_SIZE,
};
use crate::server::state::AppState;
use crate::server::validation::validate_product_name;

use super::rel_time_text_lang;

/// 画像包列表的过滤/排序/分页参数（产品详情页 `?profile_*` + `offset`）。
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct ProfileListQuery {
    pub profile_q: Option<String>,
    pub profile_arch: Option<String>,
    pub profile_status: Option<String>,
    pub profile_sort: Option<String>,
    #[serde(default)]
    pub offset: usize,
}

/// 学习状态过滤（declared/learned 可叠加于同一行，按任一命中语义过滤）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProfileStatusFilter {
    Declared,
    Learned,
    Censored,
}

/// 包级列表排序；默认有效内存降序（重的包在前，便于先看调度大头）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProfileSort {
    MemDesc,
    NameAsc,
    NameDesc,
    SamplesDesc,
    UpdatedDesc,
}

impl ProfileSort {
    fn as_str(self) -> &'static str {
        match self {
            ProfileSort::MemDesc => "mem_desc",
            ProfileSort::NameAsc => "name_asc",
            ProfileSort::NameDesc => "name_desc",
            ProfileSort::SamplesDesc => "samples_desc",
            ProfileSort::UpdatedDesc => "updated_desc",
        }
    }
}

/// 归一化后的画像列表过滤条件（query 白名单解析；raw_qs 供分页/CSV 链接）。
#[derive(Debug, Clone)]
pub(crate) struct ProfileFilter {
    q: Option<String>,
    arch: Option<String>,
    status: Option<ProfileStatusFilter>,
    status_raw: Option<&'static str>,
    sort: ProfileSort,
}

impl ProfileFilter {
    pub(crate) fn from_query(q: &ProfileListQuery) -> Self {
        let status_raw = match q.profile_status.as_deref() {
            Some("declared") => Some("declared"),
            Some("learned") => Some("learned"),
            Some("censored") => Some("censored"),
            _ => None,
        };
        let status = match status_raw {
            Some("declared") => Some(ProfileStatusFilter::Declared),
            Some("learned") => Some(ProfileStatusFilter::Learned),
            Some("censored") => Some(ProfileStatusFilter::Censored),
            _ => None,
        };
        let sort = match q.profile_sort.as_deref() {
            Some("name_asc") => ProfileSort::NameAsc,
            Some("name_desc") => ProfileSort::NameDesc,
            Some("samples_desc") => ProfileSort::SamplesDesc,
            Some("updated_desc") => ProfileSort::UpdatedDesc,
            _ => ProfileSort::MemDesc,
        };
        Self {
            q: q.profile_q
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            arch: q
                .profile_arch
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            status,
            status_raw,
            sort,
        }
    }

    /// 分页/CSV 链接携带的过滤串（默认排序不进 URL，保持链接字节稳定）。
    fn raw_qs(&self) -> String {
        build_filter_qs(&[
            ("profile_q", self.q.as_deref()),
            ("profile_arch", self.arch.as_deref()),
            ("profile_status", self.status_raw),
            (
                "profile_sort",
                (self.sort != ProfileSort::MemDesc).then(|| self.sort.as_str()),
            ),
        ])
    }
}

/// 单个源码包的画像行集合（行数 = 该包的架构数）。
pub(crate) struct PackageProfileGroup<'a> {
    pub source_name: &'a str,
    pub rows: Vec<&'a PackageResourceProfile>,
}

impl PackageProfileGroup<'_> {
    fn total_samples(&self) -> i64 {
        self.rows.iter().map(|p| p.learned_samples).sum()
    }

    fn any_declared(&self) -> bool {
        self.rows.iter().any(|p| has_declared(p))
    }

    fn any_censored(&self) -> bool {
        self.rows.iter().any(|p| p.learned_censored)
    }

    fn any_learned(&self) -> bool {
        self.rows.iter().any(|p| p.learned_samples > 0)
    }

    fn max_effective_mem_kb(&self) -> Option<i64> {
        self.rows.iter().filter_map(|p| effective_mem_kb(p)).max()
    }

    fn latest_learned_at(&self) -> Option<&str> {
        self.rows
            .iter()
            .filter_map(|p| p.learned_updated_at.as_deref())
            .max()
    }
}

fn has_declared(p: &PackageResourceProfile) -> bool {
    p.declared_min_mem_kb.is_some()
        || p.declared_min_ncpu.is_some()
        || p.declared_min_disk_kb.is_some()
}

/// 消费侧有效内存权重：删失期取 max(EMA, max)，否则取 EMA（与调度器同口径）。
fn effective_mem_kb(p: &PackageResourceProfile) -> Option<i64> {
    if p.learned_censored {
        p.learned_max_mem_kb.or(p.learned_ema_mem_kb)
    } else {
        p.learned_ema_mem_kb
    }
}

/// 过滤 + 按源码包分组 + 排序（组内按架构，`any` 回退行置底）。
pub(crate) fn build_profile_groups<'a>(
    profiles: &'a [PackageResourceProfile],
    filter: &ProfileFilter,
) -> Vec<PackageProfileGroup<'a>> {
    let q_lower = filter.q.as_deref().map(str::to_lowercase);
    let mut map: BTreeMap<&'a str, Vec<&'a PackageResourceProfile>> = BTreeMap::new();
    for p in profiles {
        if let Some(q) = q_lower.as_deref() {
            if !p.source_name.to_lowercase().contains(q) {
                continue;
            }
        }
        if let Some(arch) = filter.arch.as_deref() {
            if p.arch != arch {
                continue;
            }
        }
        if let Some(status) = filter.status {
            let hit = match status {
                ProfileStatusFilter::Declared => has_declared(p),
                ProfileStatusFilter::Learned => p.learned_samples > 0,
                ProfileStatusFilter::Censored => p.learned_censored,
            };
            if !hit {
                continue;
            }
        }
        map.entry(p.source_name.as_str()).or_default().push(p);
    }
    let mut groups: Vec<PackageProfileGroup<'a>> = map
        .into_iter()
        .map(|(source_name, rows)| PackageProfileGroup { source_name, rows })
        .collect();
    for g in &mut groups {
        g.rows.sort_by(|a, b| {
            let rank = |arch: &str| u8::from(arch == "any");
            rank(&a.arch)
                .cmp(&rank(&b.arch))
                .then_with(|| a.arch.cmp(&b.arch))
        });
    }
    groups.sort_by(|a, b| match filter.sort {
        ProfileSort::MemDesc => b
            .max_effective_mem_kb()
            .cmp(&a.max_effective_mem_kb())
            .then_with(|| a.source_name.cmp(b.source_name)),
        ProfileSort::NameAsc => a.source_name.cmp(b.source_name),
        ProfileSort::NameDesc => b.source_name.cmp(a.source_name),
        ProfileSort::SamplesDesc => b
            .total_samples()
            .cmp(&a.total_samples())
            .then_with(|| a.source_name.cmp(b.source_name)),
        ProfileSort::UpdatedDesc => b
            .latest_learned_at()
            .cmp(&a.latest_learned_at())
            .then_with(|| a.source_name.cmp(b.source_name)),
    });
    groups
}

/// KB → 编辑框可回读的整数字面（`4G` / `512M` / 纯 KB），保证 parse 往返。
fn format_kb_input(kb: i64) -> String {
    const M: i64 = 1024;
    const G: i64 = 1024 * 1024;
    const T: i64 = G * 1024;
    if kb % T == 0 {
        format!("{}T", kb / T)
    } else if kb % G == 0 {
        format!("{}G", kb / G)
    } else if kb % M == 0 {
        format!("{}M", kb / M)
    } else {
        format!("{kb}K")
    }
}

/// declared 三维组合（"4.0G / 4 / 20.0G"，未声明维 "—"）。
fn declared_composite(p: &PackageResourceProfile) -> String {
    let mem = p
        .declared_min_mem_kb
        .map(format_kb_human)
        .unwrap_or_else(|| "—".into());
    let ncpu = p
        .declared_min_ncpu
        .map(|v| v.to_string())
        .unwrap_or_else(|| "—".into());
    let disk = p
        .declared_min_disk_kb
        .map(format_kb_human)
        .unwrap_or_else(|| "—".into());
    format!("{mem} / {ncpu} / {disk}")
}

/// CPU p90 @nC（"2.5 @8C"；核数上下文缺失只出 p90 值）。
fn cpu_p90_text(p: &PackageResourceProfile) -> String {
    match (p.learned_ema_ncpu, p.learned_sample_ncpu) {
        (Some(v), Some(n)) => format!("{v:.1} @{n}C"),
        (Some(v), None) => format!("{v:.1}"),
        (None, _) => "—".into(),
    }
}

/// 内存 EMA/max @采样节点核数（"2.1G / 2.4G @128C"）；无学习值或缺采样
/// 核数上下文时只出基础文本（与 CPU 列 `2.5 @8C` 形态同源）。弹性行（与
/// [`is_elastic`] 徽章同谓词）追加单核值 `· 0.4G/核`（EMA / 采样核数）；
/// 固定行不追加——单核值对依赖图封顶、并行度不随核数伸缩的包是误导。
fn learned_mem_text(p: &PackageResourceProfile, lang: Lang) -> String {
    let base = match (p.learned_ema_mem_kb, p.learned_max_mem_kb) {
        (Some(ema), Some(max)) => format!("{} / {}", format_kb_human(ema), format_kb_human(max)),
        (Some(ema), None) => format!("{} / —", format_kb_human(ema)),
        (None, Some(max)) => format!("— / {}", format_kb_human(max)),
        (None, None) => return "—".into(),
    };
    let annotated = match p.learned_sample_ncpu {
        Some(n) => format!("{base} @{n}C"),
        None => base,
    };
    match (is_elastic(p), p.learned_ema_mem_kb, p.learned_sample_ncpu) {
        (true, Some(ema), Some(n)) if n > 0 => format!(
            "{annotated} · {}/{}",
            format_kb_human(ema / n),
            t(lang, TextKey::ProfileMemPerCoreUnit)
        ),
        _ => annotated,
    }
}

/// 弹性判定：`cpu_p90 ≥ 0.5 × 采样核数` = 并行度随节点伸缩的饱和包；
/// p90 / 采样核数缺任一（旧样本、静态覆盖）按固定处理，与调度器
/// `ELASTIC_MIN_SATURATION` 护栏同口径。
fn is_elastic(p: &PackageResourceProfile) -> bool {
    match (p.learned_ema_ncpu, p.learned_sample_ncpu) {
        (Some(p90), Some(n)) => n > 0 && p90 >= n as f64 * 0.5,
        _ => false,
    }
}

/// 弹性/固定徽章：elastic 主色底（折算生效），fixed 中性底；title 带
/// 折算语义提示。
fn elastic_badge(p: &PackageResourceProfile, lang: Lang) -> Markup {
    let (class, text_key, title_key) = if is_elastic(p) {
        (
            "badge accent",
            TextKey::ProfileElastic,
            TextKey::ProfileElasticTitle,
        )
    } else {
        ("badge", TextKey::ProfileFixed, TextKey::ProfileFixedTitle)
    };
    html! { span class=(class) title=(t(lang, title_key)) { (t(lang, text_key)) } }
}

fn tmpfs_text(p: &PackageResourceProfile) -> String {
    match (p.learned_ema_tmpfs_kb, p.learned_max_tmpfs_kb) {
        (Some(ema), Some(max)) => format!("{} / {}", format_kb_human(ema), format_kb_human(max)),
        (Some(ema), None) => format!("{} / —", format_kb_human(ema)),
        (None, Some(max)) => format!("— / {}", format_kb_human(max)),
        (None, None) => "—".into(),
    }
}

fn product_path(product: &str) -> String {
    format!("/ui/products/{}", urlencoding::encode(product))
}

fn package_path(product: &str, source: &str) -> String {
    format!(
        "/ui/products/{}/packages/{}",
        urlencoding::encode(product),
        urlencoding::encode(source)
    )
}

fn profiles_csv_path(product: &str) -> String {
    format!("{}/profiles.csv", product_path(product))
}

/// 产品页画像区参数包（避开 too_many_arguments）。
pub(crate) struct ProfileSectionParams<'a> {
    pub lang: Lang,
    pub product: &'a str,
    pub groups: &'a [PackageProfileGroup<'a>],
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub filter: &'a ProfileFilter,
    pub latest: &'a HashMap<String, LatestSourceBuild>,
    pub csrf_token: Option<&'a str>,
}

/// 产品页画像区块：源码包级列表 + 过滤/排序 + 分页 + CSV 导出。
pub(crate) fn resource_profiles_section(params: ProfileSectionParams<'_>) -> Markup {
    let ProfileSectionParams {
        lang,
        product,
        groups,
        total,
        offset,
        limit,
        filter,
        latest,
        csrf_token,
    } = params;
    let base = product_path(product);
    let raw_qs = filter.raw_qs();
    let csv_href = if raw_qs.is_empty() {
        profiles_csv_path(product)
    } else {
        format!("{}?{}", profiles_csv_path(product), raw_qs)
    };
    html! {
        div class="admin-section" {
            h2 { (t(lang, TextKey::SectionResourceProfiles)) }
            p class="admin-card-desc" { (t(lang, TextKey::ProfileHelp)) }
            form class="filter-bar" method="get" action=(base) {
                label {
                    (t(lang, TextKey::ThSourcePackage))
                    input type="text" name="profile_q"
                        value=(filter.q.as_deref().unwrap_or(""))
                        placeholder=(t(lang, TextKey::ProfileSourcePlaceholder));
                }
                label {
                    (t(lang, TextKey::ThArch))
                    input type="text" name="profile_arch"
                        value=(filter.arch.as_deref().unwrap_or(""))
                        placeholder=(t(lang, TextKey::PlaceholderArch));
                }
                label {
                    (t(lang, TextKey::ProfileFilterState))
                    select name="profile_status" {
                        option value="" selected[filter.status.is_none()] { (t(lang, TextKey::FilterAll)) }
                        option value="declared" selected[filter.status == Some(ProfileStatusFilter::Declared)] {
                            (t(lang, TextKey::ProfileStateDeclared))
                        }
                        option value="learned" selected[filter.status == Some(ProfileStatusFilter::Learned)] {
                            (t(lang, TextKey::ProfileStateLearned))
                        }
                        option value="censored" selected[filter.status == Some(ProfileStatusFilter::Censored)] {
                            (t(lang, TextKey::ProfileCensored))
                        }
                    }
                }
                label {
                    (t(lang, TextKey::FilterSort))
                    select name="profile_sort" {
                        option value="mem_desc" selected[filter.sort == ProfileSort::MemDesc] {
                            (t(lang, TextKey::SortProfileMemDesc))
                        }
                        option value="name_asc" selected[filter.sort == ProfileSort::NameAsc] {
                            (t(lang, TextKey::SortProfileNameAsc))
                        }
                        option value="name_desc" selected[filter.sort == ProfileSort::NameDesc] {
                            (t(lang, TextKey::SortProfileNameDesc))
                        }
                        option value="samples_desc" selected[filter.sort == ProfileSort::SamplesDesc] {
                            (t(lang, TextKey::SortProfileSamplesDesc))
                        }
                        option value="updated_desc" selected[filter.sort == ProfileSort::UpdatedDesc] {
                            (t(lang, TextKey::SortProfileUpdatedDesc))
                        }
                    }
                }
                (filter_apply(&base, lang))
                a class="action-button secondary" href=(csv_href) { (t(lang, TextKey::ProfileCsvExport)) }
            }
            @if groups.is_empty() {
                @if filter.q.is_some() || filter.arch.is_some() || filter.status.is_some() {
                    (empty_state(
                        t(lang, TextKey::EmptyProductsMatchTitle),
                        t(lang, TextKey::EmptyProductsMatchHint),
                    ))
                } @else {
                    (empty_state(
                        t(lang, TextKey::ProfileNoData),
                        t(lang, TextKey::ProfileNoDataHint),
                    ))
                }
            } @else {
                div class="table-wrap" {
                    table class="fixed" {
                        colgroup {
                            col style="width:16%" {}
                            col style="width:18%" {}
                            col style="width:10%" {}
                            col style="width:22%" {}
                            col style="width:10%" {}
                            col style="width:7%" {}
                            col style="width:9%" {}
                            col style="width:8%" {}
                        }
                        thead {
                            tr {
                                th { (t(lang, TextKey::ThSourcePackage)) }
                                th { (t(lang, TextKey::ThLatestBuild)) }
                                th { (t(lang, TextKey::ThArches)) }
                                th { (t(lang, TextKey::ThDeclared)) }
                                th { (t(lang, TextKey::ThEffectiveMem)) }
                                th class="num" { (t(lang, TextKey::ThSamples)) }
                                th { (t(lang, TextKey::ThStatus)) }
                                th { (t(lang, TextKey::ThUpdated)) }
                            }
                        }
                        tbody {
                            @for g in groups {
                                tr {
                                    td class="ellipsis" title=(g.source_name) {
                                        a href=(package_path(product, g.source_name)) { (g.source_name) }
                                    }
                                    td class="ellipsis" {
                                        @match latest.get(g.source_name) {
                                            Some(b) => {
                                                a href=(format!("/ui/builds/{}", b.id)) title=(b.pkg_name) {
                                                    (b.pkg_name)
                                                }
                                            }
                                            None => "—",
                                        }
                                    }
                                    td {
                                        @for p in &g.rows {
                                            span class="badge arch-badge" title=(arch_title(lang, &p.arch)) {
                                                (p.arch)
                                            }
                                            " "
                                        }
                                    }
                                    td {
                                        @if g.any_declared() {
                                            @for p in g.rows.iter().filter(|p| has_declared(p)) {
                                                div class="admin-card-desc" {
                                                    (p.arch) ": " (declared_composite(p))
                                                }
                                            }
                                        } @else {
                                            "—"
                                        }
                                    }
                                    td class="num" {
                                        @match g.max_effective_mem_kb() {
                                            Some(kb) => (format_kb_human(kb)),
                                            None => "—",
                                        }
                                    }
                                    td class="num" { (g.total_samples()) }
                                    td {
                                        @if g.any_declared() {
                                            span class="badge" { (t(lang, TextKey::ProfileStateDeclared)) }
                                            " "
                                        }
                                        @if g.any_learned() {
                                            span class="badge success" { (t(lang, TextKey::ProfileStateLearned)) }
                                            " "
                                        }
                                        @if g.any_censored() {
                                            span class="badge failure" title=(t(lang, TextKey::ProfileCensoredTitle)) {
                                                (t(lang, TextKey::ProfileCensored))
                                            }
                                        }
                                    }
                                    td { (rel_time_text_lang(g.latest_learned_at(), lang)) }
                                }
                            }
                        }
                    }
                }
                (pagination_links(&PaginationParams {
                    base_path: &base,
                    total,
                    limit,
                    offset,
                    lang,
                    query: Default::default(),
                    raw_filter_qs: Some(raw_qs.as_str()),
                    csrf_token,
                }))
            }
        }
    }
}

fn arch_title(lang: Lang, arch: &str) -> String {
    if arch == "any" {
        t(lang, TextKey::ProfileArchAnyTitle).to_string()
    } else {
        arch.to_string()
    }
}

/// 产品页数据：画像当前页 source 集合 → 最新构建摘要（失败降级为空，不挡整页）。
pub(crate) async fn load_latest_builds(
    app: &AppState,
    product: &str,
    sources: &[&str],
) -> HashMap<String, LatestSourceBuild> {
    match app
        .state_store
        .latest_builds_by_source(product, sources)
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|b| (b.source_name.clone(), b))
            .collect(),
        Err(e) => {
            tracing::warn!(product = %product, error = %e, "Failed to load latest builds by source");
            HashMap::new()
        }
    }
}

/// 源码包画像详情页：按架构的完整画像 + 该源码包最近构建历史。
pub(crate) async fn package_profile_page(
    State(app): State<Arc<AppState>>,
    Path((name, source)): Path<(String, String)>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(status_q): Query<StatusQuery>,
    Query(hist_q): Query<PackageHistoryQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let auth_ref = auth.as_ref().map(|ext| &ext.0);
    check_public_access(&app, app.server_config.public_access.view, auth_ref)?;
    validate_product_name(&name)?;
    validate_profile_source(&source)?;

    // 产品可见性 + 链上可见性：与产品详情页同口径（私有产品不泄露画像存在性）。
    let record = super::products::load_visible_product(&app, auth_ref, &name).await?;
    check_chain_visibility(&app, record.id, auth_ref).await?;

    let all = app
        .state_store
        .list_profiles_by_product(&name)
        .await
        .map_err(ApiError::from)?;
    let mut rows: Vec<PackageResourceProfile> = all
        .into_iter()
        .filter(|p| p.source_name == source)
        .collect();
    if rows.is_empty() {
        return Err(ApiError::not_found("package profile", &source));
    }
    rows.sort_by(|a, b| {
        let rank = |arch: &str| u8::from(arch == "any");
        rank(&a.arch)
            .cmp(&rank(&b.arch))
            .then_with(|| a.arch.cmp(&b.arch))
    });

    let lang = lang_from_headers(&headers);
    let arch_filter = hist_q
        .arch
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let hist_limit = page_size_from_headers(&headers).unwrap_or(UI_PAGE_SIZE);
    let (hist_total, builds) = app
        .state_store
        .list_builds(&BuildListFilter {
            product: Some(&name),
            source_name: Some(&source),
            arch: arch_filter.as_deref(),
            limit: Some(hist_limit),
            offset: Some(hist_q.offset),
            ..Default::default()
        })
        .await
        .map_err(ApiError::from)?;
    let hist_offset = hist_q.offset.min(hist_total.saturating_sub(1));
    let hist_qs = build_filter_qs(&[("arch", arch_filter.as_deref())]);

    let is_admin = auth_ref.is_some_and(|ctx| ctx.is_admin());
    let csrf_token = csrf_token_for_request(&headers, &app.csrf_key);
    let nonce = generate_nonce()?;
    let title = format!("{source} · {name}");
    let pkg_path = package_path(&name, &source);
    let base = product_path(&name);

    let body = html! {
        (status_message(&status_q, &app.csrf_key, lang))
        (back_link(t(lang, TextKey::BackToProduct), &base, Some(&base)))
        div class="page-head" {
            div class="title-block" {
                h1 { (source) }
                div class="page-meta" {
                    span class="badge" { (name) }
                }
            }
        }
        div class="admin-section" {
            h2 { (t(lang, TextKey::ProfileDetailHeading)) }
            p class="admin-card-desc" { (t(lang, TextKey::ProfileHelp)) }
            div class="table-wrap" {
                table class="fixed" {
                    colgroup {
                        col style="width:8%" {}
                        col style="width:17%" {}
                        col style="width:13%" {}
                        col style="width:11%" {}
                        col style="width:10%" {}
                        col style="width:6%" {}
                        col style="width:7%" {}
                        col style="width:9%" {}
                        col style="width:9%" {}
                        @if is_admin {
                            col style="width:10%" {}
                        }
                    }
                    thead {
                        tr {
                            th { (t(lang, TextKey::ThArch)) }
                            th { (t(lang, TextKey::ThDeclared)) }
                            th { (t(lang, TextKey::ThLearnedMem)) }
                            th { (t(lang, TextKey::ThTmpfsMem)) }
                            th { (t(lang, TextKey::ThCpuP90)) }
                            th class="num" { (t(lang, TextKey::ThSamples)) }
                            th { (t(lang, TextKey::ThBackend)) }
                            th { (t(lang, TextKey::ThStatus)) }
                            th { (t(lang, TextKey::ThUpdated)) }
                            @if is_admin {
                                th { (t(lang, TextKey::ThAction)) }
                            }
                        }
                    }
                    tbody {
                        @for p in &rows {
                            tr {
                                td title=(arch_title(lang, &p.arch)) { (p.arch) }
                                td { (declared_composite(p)) }
                                td { (learned_mem_text(p, lang)) }
                                td { (tmpfs_text(p)) }
                                td {
                                    (cpu_p90_text(p))
                                    @if p.learned_ema_ncpu.is_some() {
                                        " "
                                        (elastic_badge(p, lang))
                                    }
                                }
                                td class="num" { (p.learned_samples) }
                                td { (p.learned_backend.as_deref().unwrap_or("—")) }
                                td {
                                    @if p.learned_censored {
                                        span class="badge failure" title=(t(lang, TextKey::ProfileCensoredTitle)) {
                                            (t(lang, TextKey::ProfileCensored))
                                        }
                                    } @else {
                                        "—"
                                    }
                                }
                                td { (rel_time_text_lang(p.learned_updated_at.as_deref(), lang)) }
                                @if is_admin {
                                    td {
                                        @if let Some(token) = csrf_token.as_deref() {
                                            details {
                                                summary { (t(lang, TextKey::ProfileEditTitle)) }
                                                form class="admin-inline-form" method="post"
                                                    action=(format!("{}/floors", pkg_path)) {
                                                    input type="hidden" name="csrf_token" value=(token);
                                                    input type="hidden" name="arch" value=(p.arch);
                                                    label {
                                                        (t(lang, TextKey::TaskNewResMemLabel))
                                                        input type="text" name="min_mem"
                                                            value=(p.declared_min_mem_kb.map(format_kb_input).unwrap_or_default())
                                                            placeholder="4G";
                                                    }
                                                    label {
                                                        (t(lang, TextKey::TaskNewResNcpuLabel))
                                                        input type="text" name="min_ncpu"
                                                            value=(p.declared_min_ncpu.map(|v| v.to_string()).unwrap_or_default())
                                                            placeholder="4";
                                                    }
                                                    label {
                                                        (t(lang, TextKey::TaskNewResDiskLabel))
                                                        input type="text" name="min_disk"
                                                            value=(p.declared_min_disk_kb.map(format_kb_input).unwrap_or_default())
                                                            placeholder="20G";
                                                    }
                                                    p class="admin-card-desc" { (t(lang, TextKey::ProfileEditHint)) }
                                                    button type="submit" name="action" value="set" {
                                                        (t(lang, TextKey::SettingsSaveButton))
                                                    }
                                                    button class="action-button secondary" type="submit"
                                                        name="action" value="unset" {
                                                        (t(lang, TextKey::ProfileEditClear))
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
            @if is_admin {
                @if let Some(token) = csrf_token.as_deref() {
                    details class="admin-card" {
                        summary { (t(lang, TextKey::ProfileAddArchTitle)) }
                        form class="admin-inline-form" method="post"
                            action=(format!("{}/floors", pkg_path)) {
                            input type="hidden" name="csrf_token" value=(token);
                            label {
                                (t(lang, TextKey::ThArch))
                                input type="text" name="arch" required
                                    placeholder=(t(lang, TextKey::ProfileArchPlaceholder));
                            }
                            label {
                                (t(lang, TextKey::TaskNewResMemLabel))
                                input type="text" name="min_mem" placeholder="4G";
                            }
                            label {
                                (t(lang, TextKey::TaskNewResNcpuLabel))
                                input type="text" name="min_ncpu" placeholder="4";
                            }
                            label {
                                (t(lang, TextKey::TaskNewResDiskLabel))
                                input type="text" name="min_disk" placeholder="20G";
                            }
                            p class="admin-card-desc" { (t(lang, TextKey::ProfileAddArchHint)) }
                            button type="submit" name="action" value="set" {
                                (t(lang, TextKey::SettingsSaveButton))
                            }
                        }
                    }
                }
            }
        }
        div class="admin-section" {
            h2 { (t(lang, TextKey::ProfileHistoryTitle)) }
            p class="admin-card-desc" { (t(lang, TextKey::ProfileHistoryHint)) }
            div class="filter-bar" {
                span class="filter-chips" {
                    @if arch_filter.is_none() {
                        span class="chip active" { (t(lang, TextKey::FilterAll)) }
                    } @else {
                        a class="chip" href=(pkg_path) { (t(lang, TextKey::FilterAll)) }
                    }
                    @for p in &rows {
                        @if arch_filter.as_deref() == Some(p.arch.as_str()) {
                            span class="chip active" { (p.arch) }
                        } @else {
                            a class="chip" href=(format!("{}?arch={}", pkg_path, urlencoding::encode(&p.arch))) {
                                (p.arch)
                            }
                        }
                    }
                }
            }
            @if builds.is_empty() {
                (empty_state(
                    t(lang, TextKey::ProfileHistoryEmpty),
                    t(lang, TextKey::ProfileHistoryHint),
                ))
            } @else {
                div class="table-wrap" {
                    table class="fixed" {
                        colgroup {
                            col style="width:auto" {}
                            col style="width:9%" {}
                            col style="width:9%" {}
                            col style="width:12%" {}
                            col style="width:12%" {}
                            col style="width:9%" {}
                            col style="width:9%" {}
                            col style="width:12%" {}
                        }
                        thead {
                            tr {
                                th { (t(lang, TextKey::ThNvr)) }
                                th { (t(lang, TextKey::ThArch)) }
                                th { (t(lang, TextKey::ThPhase)) }
                                th { (t(lang, TextKey::ResPeakMem)) }
                                th { (t(lang, TextKey::ResCpuP90)) }
                                th { (t(lang, TextKey::ThBackend)) }
                                th class="num" { (t(lang, TextKey::ResOomBadge)) }
                                th { (t(lang, TextKey::LabelCompleted)) }
                            }
                        }
                        tbody {
                            @for b in &builds {
                                tr {
                                    td class="ellipsis" title=(b.pkg_name) {
                                        a href=(format!("/ui/builds/{}", b.id)) { (b.pkg_name) }
                                    }
                                    td { (b.arch.as_deref().unwrap_or("—")) }
                                    td { (phase_badge(&b.phase, lang)) }
                                    td class="num" {
                                        @match b.peak_rss_kb {
                                            Some(kb) => (format_kb_human(kb)),
                                            None => "—",
                                        }
                                    }
                                    td class="num" {
                                        @match (b.cpu_p90_cores, b.sample_ncpu) {
                                            (Some(v), Some(n)) => (format!("{v:.1} @{n}C")),
                                            (Some(v), None) => (format!("{v:.1}")),
                                            _ => "—",
                                        }
                                    }
                                    td { (b.sample_backend.as_deref().unwrap_or("—")) }
                                    td class="num" {
                                        @if b.oom_killed == Some(true) {
                                            span class="badge failure" { (t(lang, TextKey::ResOomBadge)) }
                                        } @else {
                                            "—"
                                        }
                                    }
                                    td { (rel_time_text_lang(b.completed_at.as_deref(), lang)) }
                                }
                            }
                        }
                    }
                }
                (pagination_links(&PaginationParams {
                    base_path: &pkg_path,
                    total: hist_total,
                    limit: hist_limit,
                    offset: hist_offset,
                    lang,
                    query: Default::default(),
                    raw_filter_qs: Some(hist_qs.as_str()),
                    csrf_token: csrf_token.as_deref(),
                }))
            }
        }
    };

    page_with_csp(
        &title,
        &nonce,
        auth_ref,
        "products",
        &headers,
        &app.csrf_key,
        body,
    )
}

/// 源码包页历史列表的查询参数（与 `StatusQuery` 独立提取）。
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct PackageHistoryQuery {
    pub arch: Option<String>,
    #[serde(default)]
    pub offset: usize,
}

/// 声明下限编辑表单（hub admin）：空值 = 该维未声明。
#[derive(serde::Deserialize)]
pub(crate) struct FloorsForm {
    pub csrf_token: String,
    pub arch: String,
    pub min_mem: String,
    pub min_ncpu: String,
    pub min_disk: String,
    pub action: String,
}

/// `POST /ui/products/{name}/packages/{source}/floors`：仅 hub admin。
/// action=set 全量写 declared 组（空值即未声明；架构无画像行时创建仅声明行，
/// 支持 `any` 兜底键）；action=unset 或三维全空清声明。
pub(crate) async fn package_floors_post(
    State(app): State<Arc<AppState>>,
    Path((name, source)): Path<(String, String)>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<FloorsForm>,
) -> Result<impl IntoResponse, ApiError> {
    require_csrf(&headers, &form.csrf_token, &app.csrf_key)?;
    let Some(ctx) = auth.as_ref().map(|ext| &ext.0) else {
        return Err(ApiError::Unauthorized(
            "admin authentication required".into(),
        ));
    };
    if !ctx.is_admin() {
        return Err(ApiError::PermissionDenied(
            "only hub admin can edit declared floors".into(),
        ));
    }
    validate_product_name(&name)?;
    validate_profile_source(&source)?;
    let lang = lang_from_headers(&headers);
    let back = package_path(&name, &source);
    let arch = match normalize_floor_arch(&form.arch) {
        Ok(arch) => arch,
        Err(message) => {
            return see_other_error_redirect(&back, &message, &app.csrf_key);
        }
    };

    let is_unset = form.action == "unset";
    if !is_unset && form.action != "set" {
        return see_other_error_redirect(
            &back,
            &t_fmt(lang, FmtKey::ProfileInvalidAction, &[&form.action]),
            &app.csrf_key,
        );
    }

    let parsed = if is_unset {
        Ok(FloorValues {
            min_mem_kb: None,
            min_ncpu: None,
            min_disk_kb: None,
        })
    } else {
        parse_floor_fields(&form)
    };
    let FloorValues {
        min_mem_kb: min_mem,
        min_ncpu,
        min_disk_kb: min_disk,
    } = match parsed {
        Ok(v) => v,
        Err(message) => {
            return see_other_error_redirect(&back, &message, &app.csrf_key);
        }
    };
    let all_empty = min_mem.is_none() && min_ncpu.is_none() && min_disk.is_none();

    let result = if is_unset || all_empty {
        app.state_store
            .unset_declared_requirements(&name, &source, &arch)
            .await
    } else {
        app.state_store
            .set_declared_requirements(&name, &source, &arch, min_mem, min_ncpu, min_disk)
            .await
    };
    if let Err(e) = result {
        return see_other_error_redirect(
            &back,
            &storage_error_flash("edit declared floors", e),
            &app.csrf_key,
        );
    }

    let target = format!("{name}/{source}/{arch}");
    if is_unset || all_empty {
        audit_event(&app, ctx, "unset_resource_profile", Some(&target), None).await;
    } else {
        let detail = serde_json::json!({
            "min_mem_kb": min_mem,
            "min_ncpu": min_ncpu,
            "min_disk_kb": min_disk,
        });
        audit_event(
            &app,
            ctx,
            "set_resource_profile",
            Some(&target),
            Some(&detail.to_string()),
        )
        .await;
    }
    app.resource_weight_cache.invalidate_pkg(&name, &source);
    see_other_redirect(&format!(
        "{}?status=profile_floors_updated",
        package_path(&name, &source)
    ))
}

/// 声明三维表单解析结果（`None` = 该维未声明）。
struct FloorValues {
    min_mem_kb: Option<i64>,
    min_ncpu: Option<i64>,
    min_disk_kb: Option<i64>,
}

fn parse_floor_fields(form: &FloorsForm) -> Result<FloorValues, String> {
    use crbs_core::build_options::{MAX_REQ_MIN_DISK_KB, MAX_REQ_MIN_MEM_KB, MAX_REQ_MIN_NCPU};

    let parse_kb = |field: &str, raw: &str| -> Result<Option<i64>, String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok(None);
        }
        parse_resource_min_kb(field, raw)
            .map(Some)
            .map_err(|e| e.to_string())
    };
    let min_mem = parse_kb("min_mem", &form.min_mem)?;
    if min_mem.is_some_and(|v| v > MAX_REQ_MIN_MEM_KB) {
        return Err(format!("min_mem must be <= {MAX_REQ_MIN_MEM_KB} KB"));
    }
    let min_disk = parse_kb("min_disk", &form.min_disk)?;
    if min_disk.is_some_and(|v| v > MAX_REQ_MIN_DISK_KB) {
        return Err(format!("min_disk must be <= {MAX_REQ_MIN_DISK_KB} KB"));
    }
    let raw_ncpu = form.min_ncpu.trim();
    let min_ncpu = if raw_ncpu.is_empty() {
        None
    } else {
        let n: i64 = raw_ncpu
            .parse()
            .map_err(|_| format!("invalid min_ncpu '{raw_ncpu}'; expected a positive integer"))?;
        if !(1..=i64::from(MAX_REQ_MIN_NCPU)).contains(&n) {
            return Err(format!("min_ncpu must be 1..={MAX_REQ_MIN_NCPU}"));
        }
        Some(n)
    };
    Ok(FloorValues {
        min_mem_kb: min_mem,
        min_ncpu,
        min_disk_kb: min_disk,
    })
}

fn normalize_floor_arch(raw: &str) -> Result<String, String> {
    let arch = raw.trim();
    if arch.is_empty() || arch.len() > 64 {
        return Err("arch must be 1..=64 bytes".to_string());
    }
    if arch
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '/' || c == '\\')
    {
        return Err(format!("invalid arch '{arch}'"));
    }
    Ok(arch.to_string())
}

fn validate_profile_source(source: &str) -> Result<(), ApiError> {
    if source.is_empty() || source.len() > 255 {
        return Err(ApiError::Validation(
            "source package name must be 1..=255 bytes".into(),
        ));
    }
    if source.chars().any(|c| c == '/' || c.is_control()) {
        return Err(ApiError::Validation(
            "source package name contains invalid characters".into(),
        ));
    }
    Ok(())
}

/// `GET /ui/products/{name}/profiles.csv`：产品页可见性门内的画像明细导出
/// （每源码包每架构一行；过滤/排序与页面一致，不受分页限制）。
pub(crate) async fn product_profiles_csv(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    Query(q): Query<ProfileListQuery>,
) -> Result<Response, ApiError> {
    let auth_ref = auth.as_ref().map(|ext| &ext.0);
    check_public_access(&app, app.server_config.public_access.view, auth_ref)?;
    validate_product_name(&name)?;
    let record = super::products::load_visible_product(&app, auth_ref, &name).await?;
    check_chain_visibility(&app, record.id, auth_ref).await?;

    let profiles = app
        .state_store
        .list_profiles_by_product(&name)
        .await
        .map_err(ApiError::from)?;
    let filter = ProfileFilter::from_query(&q);
    let groups = build_profile_groups(&profiles, &filter);

    let mut out = String::from(
        "product,source_name,arch,declared_min_mem_kb,declared_min_ncpu,declared_min_disk_kb,\
         learned_ema_mem_kb,learned_max_mem_kb,learned_ema_tmpfs_kb,learned_max_tmpfs_kb,\
         learned_ema_ncpu,learned_max_ncpu,learned_sample_ncpu,learned_samples,\
         learned_backend,learned_censored,declared_updated_at,learned_updated_at\n",
    );
    for g in &groups {
        for p in &g.rows {
            let cells: Vec<String> = vec![
                csv_field(&p.product),
                csv_field(&p.source_name),
                csv_field(&p.arch),
                csv_opt(p.declared_min_mem_kb),
                csv_opt(p.declared_min_ncpu),
                csv_opt(p.declared_min_disk_kb),
                csv_opt(p.learned_ema_mem_kb),
                csv_opt(p.learned_max_mem_kb),
                csv_opt(p.learned_ema_tmpfs_kb),
                csv_opt(p.learned_max_tmpfs_kb),
                p.learned_ema_ncpu
                    .map(|v| v.to_string())
                    .unwrap_or_default(),
                p.learned_max_ncpu
                    .map(|v| v.to_string())
                    .unwrap_or_default(),
                csv_opt(p.learned_sample_ncpu),
                p.learned_samples.to_string(),
                csv_field(p.learned_backend.as_deref().unwrap_or("")),
                p.learned_censored.to_string(),
                csv_field(p.declared_updated_at.as_deref().unwrap_or("")),
                csv_field(p.learned_updated_at.as_deref().unwrap_or("")),
            ];
            out.push_str(&cells.join(","));
            out.push('\n');
        }
    }

    let mut response = Response::new(axum::body::Body::from(out));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    let disposition = format!("attachment; filename=\"resource-profiles-{name}.csv\"");
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition)
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    Ok(response)
}

fn csv_opt(v: Option<i64>) -> String {
    v.map(|v| v.to_string()).unwrap_or_default()
}

/// CSV 单元格：公式注入前缀防护 + RFC 4180 引号转义。
fn csv_field(value: &str) -> String {
    let guarded = if matches!(
        value.chars().next(),
        Some('=' | '+' | '-' | '@' | '\t' | '\r')
    ) {
        format!("'{value}")
    } else {
        value.to_string()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crbs_core::PackageResourceProfile;

    fn profile(source: &str, arch: &str) -> PackageResourceProfile {
        PackageResourceProfile {
            product: "p".into(),
            source_name: source.into(),
            arch: arch.into(),
            declared_min_mem_kb: None,
            declared_min_ncpu: None,
            declared_min_disk_kb: None,
            declared_updated_at: None,
            learned_ema_mem_kb: None,
            learned_max_mem_kb: None,
            learned_ema_tmpfs_kb: None,
            learned_max_tmpfs_kb: None,
            learned_ema_ncpu: None,
            learned_max_ncpu: None,
            learned_samples: 0,
            learned_sample_ncpu: None,
            learned_backend: None,
            learned_censored: false,
            learned_updated_at: None,
            created_at: "2026-01-01 00:00:00".into(),
            updated_at: "2026-01-01 00:00:00".into(),
        }
    }

    fn empty_filter() -> ProfileFilter {
        ProfileFilter::from_query(&ProfileListQuery::default())
    }

    #[test]
    fn format_kb_input_roundtrips_through_parser() {
        for kb in [
            1,
            1023,
            1024,
            4096 * 1024,
            4 * 1024 * 1024,
            20 * 1024 * 1024,
        ] {
            let text = format_kb_input(kb);
            let parsed = parse_resource_min_kb("test", &text).unwrap();
            assert_eq!(parsed, kb, "{text}");
        }
    }

    #[test]
    fn declared_composite_and_units() {
        let mut p = profile("gcc", "x86_64");
        assert_eq!(declared_composite(&p), "— / — / —");
        p.declared_min_mem_kb = Some(4 * 1024 * 1024);
        p.declared_min_ncpu = Some(4);
        assert_eq!(declared_composite(&p), "4.0G / 4 / —");
        assert_eq!(format_kb_human(2 * 1024 * 1024), "2.0G");
        assert_eq!(format_kb_human(2048), "2.0M");
        assert_eq!(format_kb_human(512), "512K");
    }

    #[test]
    fn groups_collapse_versions_and_filter_by_source() {
        let mut a1 = profile("gcc", "x86_64");
        a1.learned_ema_mem_kb = Some(1000);
        a1.learned_samples = 2;
        let mut a2 = profile("gcc", "aarch64");
        a2.learned_ema_mem_kb = Some(500);
        a2.learned_samples = 1;
        let mut b = profile("gcc-devel", "x86_64");
        b.learned_ema_mem_kb = Some(9000);
        b.learned_samples = 5;
        let profiles = vec![a1, a2, b];

        let groups = build_profile_groups(&profiles, &empty_filter());
        assert_eq!(groups.len(), 2, "one row per source package");
        assert_eq!(groups[0].source_name, "gcc-devel", "memory desc");
        assert_eq!(groups[1].rows.len(), 2, "gcc keeps one row per arch");
        assert_eq!(groups[1].total_samples(), 3);

        let q = ProfileListQuery {
            profile_q: Some("GCC-DEV".into()),
            ..Default::default()
        };
        let filtered = build_profile_groups(&profiles, &ProfileFilter::from_query(&q));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].source_name, "gcc-devel");

        let q = ProfileListQuery {
            profile_arch: Some("aarch64".into()),
            ..Default::default()
        };
        let filtered = build_profile_groups(&profiles, &ProfileFilter::from_query(&q));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].source_name, "gcc");
        assert_eq!(filtered[0].rows[0].arch, "aarch64");
    }

    #[test]
    fn groups_sort_any_arch_last_and_censored_uses_max() {
        let mut any = profile("gcc", "any");
        any.learned_censored = true;
        any.learned_ema_mem_kb = Some(100);
        any.learned_max_mem_kb = Some(500);
        let real = profile("gcc", "x86_64");
        let mut profiles = vec![any, real];
        profiles[0].learned_ema_mem_kb = Some(100);
        profiles[0].learned_max_mem_kb = Some(500);
        profiles[0].learned_censored = true;
        profiles[1].learned_ema_mem_kb = Some(200);

        let groups = build_profile_groups(&profiles, &empty_filter());
        assert_eq!(
            groups[0].max_effective_mem_kb(),
            Some(500),
            "censored weight uses max(ema, max)"
        );
        assert_eq!(groups[0].rows[0].arch, "x86_64", "any renders last");
        assert_eq!(groups[0].rows[1].arch, "any");
    }

    #[test]
    fn filter_whitelist_and_raw_qs_stability() {
        let q = ProfileListQuery {
            profile_q: Some(" gcc ".into()),
            profile_arch: Some("x86_64".into()),
            profile_status: Some("bogus".into()),
            profile_sort: Some("bogus".into()),
            ..Default::default()
        };
        let f = ProfileFilter::from_query(&q);
        assert_eq!(f.q.as_deref(), Some("gcc"));
        assert!(f.status.is_none());
        assert_eq!(f.sort, ProfileSort::MemDesc);
        assert_eq!(
            f.raw_qs(),
            "profile_q=gcc&profile_arch=x86_64",
            "default sort is omitted from links"
        );

        let q = ProfileListQuery {
            profile_status: Some("censored".into()),
            profile_sort: Some("name_asc".into()),
            ..Default::default()
        };
        let f = ProfileFilter::from_query(&q);
        assert_eq!(f.raw_qs(), "profile_status=censored&profile_sort=name_asc");
    }

    #[test]
    fn csv_field_guards_formulas_and_quotes() {
        assert_eq!(csv_field("gcc"), "gcc");
        assert_eq!(csv_field("=1+1"), "'=1+1");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn learned_mem_text_appends_sample_node_when_value_present() {
        let mut p = profile("gcc", "x86_64");
        assert_eq!(
            learned_mem_text(&p, Lang::En),
            "—",
            "no values, no annotation"
        );
        p.learned_ema_mem_kb = Some(2 * 1024 * 1024);
        p.learned_max_mem_kb = Some(3 * 1024 * 1024);
        assert_eq!(
            learned_mem_text(&p, Lang::En),
            "2.0G / 3.0G",
            "no sample ncpu context"
        );
        p.learned_sample_ncpu = Some(128);
        assert_eq!(learned_mem_text(&p, Lang::En), "2.0G / 3.0G @128C");
        p.learned_ema_mem_kb = None;
        assert_eq!(
            learned_mem_text(&p, Lang::En),
            "— / 3.0G @128C",
            "max-only keeps annotation"
        );
    }

    #[test]
    fn learned_mem_text_appends_per_core_only_for_elastic() {
        let mut p = profile("gcc", "x86_64");
        p.learned_ema_mem_kb = Some(2 * 1024 * 1024);
        p.learned_max_mem_kb = Some(3 * 1024 * 1024);
        p.learned_sample_ncpu = Some(4);
        // 饱和线：p90 4.0 ≥ 0.5 × 4 = 2.0，与徽章同谓词。
        p.learned_ema_ncpu = Some(4.0);
        assert!(is_elastic(&p));
        // 2G / 4 核 = 512K KB → 人读 512.0M。
        assert_eq!(
            learned_mem_text(&p, Lang::En),
            "2.0G / 3.0G @4C · 512.0M/core"
        );
        assert_eq!(
            learned_mem_text(&p, Lang::Zh),
            "2.0G / 3.0G @4C · 512.0M/核"
        );

        // 固定行不追加单核值：并行度受依赖图封顶的包，单核值是误导。
        p.learned_ema_ncpu = Some(1.9);
        assert!(!is_elastic(&p));
        assert_eq!(learned_mem_text(&p, Lang::En), "2.0G / 3.0G @4C");

        // 弹性但 EMA 缺失（max-only）：无被除数，不追加。
        let mut max_only = profile("gcc", "x86_64");
        max_only.learned_max_mem_kb = Some(3 * 1024 * 1024);
        max_only.learned_sample_ncpu = Some(4);
        max_only.learned_ema_ncpu = Some(4.0);
        assert_eq!(learned_mem_text(&max_only, Lang::En), "— / 3.0G @4C");
    }

    #[test]
    fn is_elastic_threshold_matches_scheduler_guard() {
        let mut p = profile("gcc", "x86_64");
        // 任一输入缺失 = 固定。
        assert!(!is_elastic(&p));
        p.learned_sample_ncpu = Some(8);
        assert!(!is_elastic(&p), "p90 missing = fixed");
        // 饱和线：p90 ≥ 0.5 × 8 = 4.0。
        p.learned_ema_ncpu = Some(4.0);
        assert!(is_elastic(&p), "exactly at 0.5 saturation is elastic");
        p.learned_ema_ncpu = Some(3.9);
        assert!(!is_elastic(&p));
        // 采样核数 0 无意义（调度器同判固定）。
        p.learned_sample_ncpu = Some(0);
        p.learned_ema_ncpu = Some(4.0);
        assert!(!is_elastic(&p));
    }
}
