// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! RPM changelog 整页（build/task 卡头入口：实时解析 + 服务端限量分页）。
//! 与 API 端点共用 [`changelog_for_build`] / [`changelog_for_task`]（实时
//! 解析、fail-soft、零持久化）：最新在前，服务端按 [`CHANGELOG_PAGE_SIZE`]
//! 切片；`?offset=` 零 JS 翻页（非数字/越界宽容回落首页），不可用时空态。

use std::sync::Arc;

use axum::extract::{Extension, Path as AxumPath, Query, State};
use axum::http::HeaderMap;
use maud::{html, Markup};

use crbs_core::util::rpm_changelog::ChangelogEntry;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::artifacts::changelog::{
    changelog_for_build, changelog_for_task, ChangelogResponse,
};
use crate::server::routes::ui::components::{
    back_link, empty_state, generate_nonce, page_with_csp,
};
use crate::server::routes::ui::i18n::{lang_from_headers, t, t_fmt, FmtKey, Lang, TextKey};
use crate::server::routes::ui::service::check_public_access;
use crate::server::state::AppState;

/// 每页渲染的 entry 上限（服务端切片）。
const CHANGELOG_PAGE_SIZE: usize = 50;

/// `?offset=` 查询参数；`None` = 未传（首页）。
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct ChangelogPageQuery {
    offset: Option<String>,
}

/// 宽容解析：非数字 → 0；越界（>= total）由 [`slice_changelog_page`] 收敛回首页。
fn parse_offset(raw: Option<&str>) -> usize {
    raw.and_then(|s| s.parse::<usize>().ok()).unwrap_or(0)
}

/// 服务端切片（纯函数）：倒序结果按 offset 取 [`CHANGELOG_PAGE_SIZE`] 条，
/// 返回 `(本页 entries, 总条数)`；offset 越界（>= total）宽容回落首页。
fn slice_changelog_page(entries: &[ChangelogEntry], offset: usize) -> (Vec<ChangelogEntry>, usize) {
    let total = entries.len();
    let start = if offset >= total { 0 } else { offset };
    let end = (start + CHANGELOG_PAGE_SIZE).min(total);
    (entries[start..end].to_vec(), total)
}

/// 单条 entry 渲染：date/author 元信息行 + 正文块；pre 保留换行，挂既有
/// .code-block 复用 mono 卡壳/滚动/白空规则。
fn changelog_entry(date: &str, author: &str, text: &str) -> Markup {
    html! {
        // .changelog-entry 无 CSS：仅语义分组 + 测试锚（slice 测试按 class 计数）。
        div class="changelog-entry" {
            div class="page-meta" {
                span { (date) }
                span class="sep" { "·" }
                span { (author) }
            }
            pre class="code-block" { (text) }
        }
    }
}

/// entries 区块渲染（纯函数，可直测）：限量摘要行 + 本页 entries + 页尾
/// Older/Newer 导航（纯链接）；`base` 是作用域 changelog 页 URL。
fn changelog_entries_section(
    lang: Lang,
    page: &[ChangelogEntry],
    total: usize,
    base: &str,
    offset: usize,
) -> Markup {
    let next_offset = offset + CHANGELOG_PAGE_SIZE;
    let prev_offset = offset.saturating_sub(CHANGELOG_PAGE_SIZE);
    html! {
        section class="admin-section" {
            p class="page-meta" {
                (t_fmt(
                    lang,
                    FmtKey::ChangelogPageSummary,
                    &[&page.len().to_string(), &total.to_string()],
                ))
            }
            @for entry in page {
                (changelog_entry(&entry.date, &entry.author, &entry.text))
            }
        }
        div class="table-foot" {
            @if offset > 0 {
                a href=(format!("{base}?offset={prev_offset}")) {
                    "← " (t(lang, TextKey::ChangelogNewer))
                }
            } @else {
                span class="disabled" { "← " (t(lang, TextKey::ChangelogNewer)) }
            }
            @if next_offset < total {
                a href=(format!("{base}?offset={next_offset}")) {
                    (t(lang, TextKey::ChangelogOlder)) " →"
                }
            } @else {
                span class="disabled" { (t(lang, TextKey::ChangelogOlder)) " →" }
            }
        }
    }
}

/// [`render_changelog_page`] 的参数包（build/task 作用域同构公共渲染）。
/// `base` 是本页 URL（分页 `?offset=` 的作用域基准，task 页留在 task URL、
/// 不跳去胜出子构建）；`crumb` 回来源卡渲染结果；`nav_active` 导航高亮项。
struct ChangelogPageParams<'a> {
    lang: Lang,
    nonce: &'a str,
    auth: Option<&'a AuthContext>,
    headers: &'a HeaderMap,
    app: &'a AppState,
    data: &'a ChangelogResponse,
    offset: usize,
    base: &'a str,
    crumb: Markup,
    nav_active: &'static str,
}

fn render_changelog_page(
    params: ChangelogPageParams<'_>,
) -> Result<(axum::http::StatusCode, HeaderMap, Markup), ApiError> {
    let ChangelogPageParams {
        lang,
        nonce,
        auth,
        headers,
        app,
        data,
        offset,
        base,
        crumb,
        nav_active,
    } = params;
    let (page, total) = slice_changelog_page(&data.entries, offset);
    let title = t(lang, TextKey::ChangelogPageTitle);
    let body = html! {
        div class="crumb" { (crumb) }
        div class="page-head" {
            div class="title-block" {
                h1 { (title) }
                div class="page-meta" {
                    // 解析源文件名（NEVRA 兜底）+ 来源构建号（task=胜出子构建，build=自身）。
                    @if !data.file_name.is_empty() || data.nevra.is_some() {
                        (data.nevra.as_deref().filter(|s| !s.is_empty()).unwrap_or(&data.file_name))
                    }
                    @if let Some(build_id) = data.build_id {
                        span class="sep" { "·" }
                        (t_fmt(lang, FmtKey::BuildTitle, &[&build_id.to_string()]))
                    }
                }
            }
        }
        @if !data.available {
            // fail-soft 空态：不阻塞产物主链路（rpm 缺失 / 解析空 / 文件不可达）。
            (empty_state(
                t(lang, TextKey::ChangelogEmptyTitle),
                t(lang, TextKey::ChangelogEmptyHint),
            ))
        } @else {
            (changelog_entries_section(lang, &page, total, base, offset))
        }
    };
    page_with_csp(title, nonce, auth, nav_active, headers, &app.csrf_key, body)
}

/// `GET /ui/builds/{id}/changelog`：build 作用域产物卡头下钻入口。
pub(crate) async fn build_changelog_page(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    query: Query<ChangelogPageQuery>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
) -> Result<(axum::http::StatusCode, HeaderMap, Markup), ApiError> {
    check_public_access(
        &app,
        app.server_config.public_access.view,
        auth.as_ref().map(|e| &e.0),
    )?;
    let lang = lang_from_headers(&headers);
    let data = changelog_for_build(&app, id, auth.as_ref().map(|e| &e.0)).await?;
    let offset = parse_offset(query.offset.as_deref());
    let nonce = generate_nonce()?;
    let crumb = back_link(
        &t_fmt(lang, FmtKey::BuildTitle, &[&id.to_string()]),
        &format!("/ui/builds/{id}"),
        None,
    );
    render_changelog_page(ChangelogPageParams {
        lang,
        nonce: &nonce,
        auth: auth.as_ref().map(|e| &e.0),
        headers: &headers,
        app: &app,
        data: &data,
        offset,
        base: &format!("/ui/builds/{id}/changelog"),
        crumb,
        nav_active: "builds",
    })
}

/// `GET /ui/tasks/{id}/changelog`：task 作用域，解析胜出子构建的 SRPM/rpm。
pub(crate) async fn task_changelog_page(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    query: Query<ChangelogPageQuery>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
) -> Result<(axum::http::StatusCode, HeaderMap, Markup), ApiError> {
    check_public_access(
        &app,
        app.server_config.public_access.view,
        auth.as_ref().map(|e| &e.0),
    )?;
    let lang = lang_from_headers(&headers);
    let data = changelog_for_task(&app, id, auth.as_ref().map(|e| &e.0)).await?;
    let offset = parse_offset(query.offset.as_deref());
    let nonce = generate_nonce()?;
    let crumb = back_link(
        &t_fmt(lang, FmtKey::TaskTitle, &[&id.to_string()]),
        &format!("/ui/tasks/{id}"),
        None,
    );
    render_changelog_page(ChangelogPageParams {
        lang,
        nonce: &nonce,
        auth: auth.as_ref().map(|e| &e.0),
        headers: &headers,
        app: &app,
        data: &data,
        offset,
        base: &format!("/ui/tasks/{id}/changelog"),
        crumb,
        nav_active: "tasks",
    })
}

#[cfg(test)]
mod tests {
    use super::{
        build_changelog_page, changelog_entries_section, changelog_entry, parse_offset,
        slice_changelog_page, task_changelog_page, ChangelogPageQuery, CHANGELOG_PAGE_SIZE,
    };
    use crate::server::auth::AuthContext;
    use crate::server::routes::ui::i18n::Lang;
    use crate::server::state::AppState;
    use crate::test_support::seed_task;
    use axum::extract::{Extension, Path as AxumPath, Query, State};
    use axum::http::HeaderMap;
    use crbs_core::util::rpm_changelog::ChangelogEntry;
    use std::sync::Arc;

    const SHA: &str = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    fn entry(n: usize) -> ChangelogEntry {
        ChangelogEntry {
            date: format!("Mon Aug 25 2026 #{n}"),
            author: format!("A <a@h> - 1.0-{n}"),
            text: format!("change {n}"),
        }
    }

    /// 公共 seed：openfed 公开产品 + hello task + succeeded 子构建 + 单 rpm
    /// 产物。差异参数化：result_dir（Some 时同步落盘假 rpm；None → 定位失败
    /// → available=false 走 fail-soft）、build arch（get_child_build_summaries
    /// 的映射不容 NULL）与产物 arch。返回 (app, task_id, build_id)；tmp 由
    /// 调用方持有。
    async fn seed_openfed_build(
        tmp: &tempfile::TempDir,
        result_dir: Option<&std::path::Path>,
        build_arch: Option<&str>,
        artifact_arch: Option<&str>,
    ) -> (Arc<AppState>, i64, i64) {
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        store
            .create_product(crbs_core::CreateProductInput {
                name: "openfed",
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: crbs_core::VISIBILITY_PUBLIC,
                config: &crbs_core::config::ProductConfig::default(),
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();
        let task_id = seed_task(&store, "openfed", "hello").await;
        let result_dir_str = result_dir.map(|p| p.to_string_lossy().into_owned());
        let build_id = store
            .insert_build(crbs_core::BuildInsert {
                product: "openfed",
                pkg_name: "hello",
                phase: "succeeded",
                backend: "chroot",
                arch: build_arch,
                result_dir: result_dir_str.as_deref(),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        if let Some(dir) = result_dir {
            std::fs::create_dir_all(dir.join("RPMS")).unwrap();
            std::fs::write(dir.join("RPMS/hello-1.0-1.x86_64.rpm"), b"not a real rpm").unwrap();
        }
        let mut tx = store.pool().begin().await.unwrap();
        store
            .insert_artifacts_tx(
                &mut tx,
                build_id,
                &[crbs_core::NewArtifact {
                    relative_path: "RPMS/hello-1.0-1.x86_64.rpm".to_string(),
                    kind: crbs_core::ArtifactKind::Rpm,
                    size_bytes: 1024,
                    sha256: SHA.to_string(),
                    unsigned_sha256: None,
                    arch: artifact_arch.map(str::to_string),
                    name: Some("hello".to_string()),
                    version: Some("1.0".to_string()),
                    release: Some("1".to_string()),
                    epoch: None,
                    metadata_json: None,
                    signed: false,
                }],
                "2026-08-31 00:00:00",
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
        (app, task_id, build_id)
    }

    /// slice_changelog_page：锁每页 50 与 offset 行为（首页/中段/尾页/越界/空集）。
    #[test]
    fn slice_changelog_page_locks_page_size_and_offset() {
        let entries: Vec<ChangelogEntry> = (0..120).map(entry).collect();

        let (page, total) = slice_changelog_page(&entries, 0);
        assert_eq!(total, 120);
        assert_eq!(page.len(), CHANGELOG_PAGE_SIZE);
        assert_eq!(page[0], entry(0));

        let (page, _) = slice_changelog_page(&entries, 50);
        assert_eq!(page.len(), 50);
        assert_eq!(page[0], entry(50));

        let (page, _) = slice_changelog_page(&entries, 100);
        assert_eq!(page.len(), 20);
        assert_eq!(page[0], entry(100));

        let (page, total) = slice_changelog_page(&entries, 999);
        assert_eq!(total, 120);
        assert_eq!(page.len(), 50);
        assert_eq!(page[0], entry(0));

        // 空集：available=false 本走不到切片，此处锁宽容不 panic。
        let (page, total) = slice_changelog_page(&[], 0);
        assert_eq!((page.len(), total), (0, 0));
    }

    /// 非数字/负数形态/空串 → 0；正常数字透传。
    #[test]
    fn parse_offset_is_lenient() {
        assert_eq!(parse_offset(None), 0);
        assert_eq!(parse_offset(Some("abc")), 0);
        assert_eq!(parse_offset(Some("-1")), 0);
        assert_eq!(parse_offset(Some("")), 0);
        assert_eq!(parse_offset(Some("50")), 50);
    }

    /// entries 区块（纯 markup）：切片渲染 + 导航方向（base=build 作用域页）。
    #[test]
    fn entries_section_renders_page_slice_and_nav() {
        let entries: Vec<ChangelogEntry> = (0..120).map(entry).collect();
        let base = "/ui/builds/42/changelog";

        let (page, _) = slice_changelog_page(&entries, 0);
        let html = changelog_entries_section(Lang::En, &page, 120, base, 0).into_string();
        assert!(html.contains("showing 50 of 120 entries"), "{html}");
        assert_eq!(html.matches("changelog-entry\"").count(), 50, "{html}");
        assert!(
            html.contains("/ui/builds/42/changelog?offset=50"),
            "older link missing: {html}"
        );
        assert!(
            !html.contains("Newer entries</a>"),
            "no newer link on first page: {html}"
        );

        let html =
            changelog_entries_section(Lang::En, &entries[50..100], 120, base, 50).into_string();
        assert!(html.contains("/ui/builds/42/changelog?offset=0"));
        assert!(html.contains("/ui/builds/42/changelog?offset=100"));
        assert!(html.contains("Newer entries"));
        assert!(html.contains("Older entries"));

        let html =
            changelog_entries_section(Lang::En, &entries[100..], 120, base, 100).into_string();
        assert!(html.contains("showing 20 of 120 entries"), "{html}");
        assert!(html.contains("/ui/builds/42/changelog?offset=50"));
        assert!(
            !html.contains("changelog?offset=150"),
            "no older link past end: {html}"
        );
    }

    /// 公开产品 + 假 rpm 文件在盘 → 渲染上下文与 fail-soft 空态（macOS/Linux 同断言）。
    #[tokio::test]
    async fn build_changelog_page_renders_context_and_empty_state() {
        let tmp = tempfile::tempdir().unwrap();
        let (app, _task_id, build_id) = seed_openfed_build(
            &tmp,
            Some(&tmp.path().join("results/build-1")),
            None,
            Some("x86_64"),
        )
        .await;

        let (status, _headers, markup) = build_changelog_page(
            State(app),
            AxumPath(build_id),
            Query(ChangelogPageQuery::default()),
            Some(Extension(AuthContext {
                user: "op".into(),
                role: "operator".into(),
                ..Default::default()
            })),
            HeaderMap::new(),
        )
        .await
        .unwrap();
        assert_eq!(status, axum::http::StatusCode::OK);
        let html = markup.into_string();
        assert!(
            html.contains(&format!("/ui/builds/{build_id}")),
            "crumb must link back to build: {html}"
        );
        assert!(
            html.contains("Changelog unavailable"),
            "fail-soft must render empty state: {html}"
        );
    }

    /// task 作用域：rpm 子构建胜出 → fail-soft 空态 + 面包屑回 task（macOS/Linux 同断言）。
    #[tokio::test]
    async fn task_changelog_page_failsoft_renders_empty_state() {
        let tmp = tempfile::tempdir().unwrap();
        // build 无 result_dir → 定位失败 → available=false；build arch 必填
        //（get_child_build_summaries 的 ChildBuildSummary 映射不容 NULL）。
        let (app, task_id, _build_id) = seed_openfed_build(&tmp, None, Some("x86_64"), None).await;

        let (status, _headers, markup) = task_changelog_page(
            State(app),
            AxumPath(task_id),
            Query(ChangelogPageQuery::default()),
            None,
            HeaderMap::new(),
        )
        .await
        .unwrap();
        assert_eq!(status, axum::http::StatusCode::OK);
        let html = markup.into_string();
        assert!(
            html.contains(&format!("/ui/tasks/{task_id}")),
            "crumb must link back to task: {html}"
        );
        assert!(
            html.contains("Changelog unavailable"),
            "fail-soft must render empty state: {html}"
        );
        assert!(
            !html.contains("Mon Aug"),
            "no entries must render on fail-soft: {html}"
        );
    }

    /// entry 组件：元信息行 + pre 换行保留（.code-block）。
    #[test]
    fn changelog_entry_markup() {
        let html = changelog_entry("Mon Aug 25 2026", "A <a@h> - 1-1", "line1\nline2");
        let s = html.into_string();
        assert!(s.contains("Mon Aug 25 2026"));
        assert!(s.contains("A &lt;a@h&gt; - 1-1"));
        assert!(s.contains("<pre class=\"code-block\">line1\nline2</pre>"));
    }
}
