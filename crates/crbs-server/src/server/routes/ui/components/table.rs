// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 表格与列表页共享组件：artifact_table、artifact_tree_script、arch_matrix、
//! 列表页 chips 族、clickable_rows_script。

use std::collections::BTreeMap;

use maud::{html, Markup, PreEscaped};

use crate::server::routes::ui::i18n::{t, t_fmt, FmtKey, Lang, TextKey};
use crate::server::routes::ui::pages::format_duration_secs;
use crate::server::routes::ui::service::{download_url, with_back_param};
use crbs_core::engine::artifact_harvest::CRBS_LOGS_DIR;
use crbs_core::types::ChildBuildSummary;
use crbs_core::Artifact;

use super::{empty_state, format_local_time, phase_badge_with_class, phase_status};

// ===== 列表页共享组件 =====

/// h1 总数 chip：纯数字（tabular-nums），无文案故不进 i18n。
pub(crate) fn count_chip(n: usize) -> Markup {
    html! { span class="count-chip" { (n) } }
}

/// 相位摘要 chips（页头下、表格卡上）：每 chip 是该相位的过滤链接，兼做
/// 概览与过滤（count 进 `b`、label 随后）。
/// - `current_phase`：当前 phase 过滤（`None` = All）→ active chip 判定；
/// - `total`：All chip 计数 = 去掉 phase 过滤后其余过滤下的总数（`counts`
///   求和，非含 phase 过滤的列表 total）；
/// - `counts`：`count_*_by_phase_scoped` 同过滤口径分组；count=0 不出
///   chip，未知相位不入 chips（点色修饰类映射不到）；`url_for`：生成保留
///   其余过滤、去掉 offset 的列表 URL（`None` = 移除 phase 过滤）。
///
/// 展示序固定（见 CHIP_ORDER）：活跃在前；点色只是装饰，走 CSS 修饰类
/// （building→running、pending/assigned→queued），不经对比度门禁。
pub(crate) fn phase_chips(
    lang: Lang,
    current_phase: Option<&str>,
    total: usize,
    counts: &[(String, i64)],
    url_for: &dyn Fn(Option<&str>) -> String,
) -> Markup {
    use crate::server::routes::ui::i18n::phase_option_label;

    /// DB 相位 → chip 点色修饰类（--dot 色族）；未知相位 `None`：不入 chips。
    fn chip_modifier(phase: &str) -> Option<&'static str> {
        match phase {
            "succeeded" => Some("succeeded"),
            "failed" => Some("failed"),
            "timeout" => Some("timeout"),
            "cancelled" => Some("cancelled"),
            "building" => Some("running"),
            "pending" | "assigned" => Some("queued"),
            _ => None,
        }
    }

    /// 固定展示序：执行段 → 排队段 → 终态段；未知排最后（保险，正常不入 chips）。
    const CHIP_ORDER: [&str; 7] = [
        "building",
        "pending",
        "assigned",
        "succeeded",
        "failed",
        "timeout",
        "cancelled",
    ];
    let rank = |p: &str| {
        CHIP_ORDER
            .iter()
            .position(|c| *c == p)
            .unwrap_or(CHIP_ORDER.len())
    };
    let mut items: Vec<&(String, i64)> = counts.iter().filter(|(_, c)| *c > 0).collect();
    items.sort_by_key(|(p, _)| rank(p));

    html! {
        div class="phase-chips" {
            a class=(if current_phase.is_none() { "phase-chip active" } else { "phase-chip" })
                href=(url_for(None)) {
                b { (total) } " " (t(lang, TextKey::FilterAll))
            }
            @for (phase, count) in items {
                @if let Some(modifier) = chip_modifier(phase) {
                    a class=(format!("phase-chip {modifier}{}", if current_phase == Some(phase.as_str()) { " active" } else { "" }))
                        href=(url_for(Some(phase))) {
                        b { (count) } " " (phase_option_label(lang, phase))
                    }
                }
            }
        }
    }
}

/// 激活过滤条件 chips（卡头过滤条尾部）：每项 `label: value` + 移除链接
/// （✕ = 去掉该参数、保留其余过滤的 URL，纯 `<a>` 无 JS）。label/value 由
/// 调用方本地化 / 展示化后传入。空列表返回空 Markup（不渲染容器）。
pub(crate) fn filter_chips(chips: &[(String, String, String)], lang: Lang) -> Markup {
    if chips.is_empty() {
        return html! {};
    }
    html! {
        div class="filter-chips" {
            @for (label, value, remove_url) in chips {
                span class="f-chip" {
                    (label) ": " (value) " "
                    a href=(remove_url) title=(t(lang, TextKey::FilterRemove)) { "✕" }
                }
            }
        }
    }
}

/// 列表 ID 列链接（#123 形态，mono）；`row-target` 类 = clickable_rows_script 整行点击契约。
pub(crate) fn id_link(href: String, id: i64) -> Markup {
    html! { a class="row-target id-link" href=(href) { "#" (id) } }
}

/// 列表 User 列：首字母 avatar（aria-hidden 装饰）+ 用户名；空用户名显示 "?" avatar + 空串文本（诚实降级）。
pub(crate) fn user_cell(name: &str) -> Markup {
    let initial = name
        .chars()
        .next()
        .and_then(|c| c.to_uppercase().next())
        .unwrap_or('?');
    html! {
        span class="user-cell" {
            span class="avatar" aria-hidden="true" { (initial) }
            (name)
        }
    }
}

/// 产物相对路径 → 展示用文件名（basename）。
fn artifact_file_name(rel: &str) -> String {
    std::path::Path::new(rel)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| rel.to_string())
}

/// 产物卡头的 changelog 下钻链接（每构建/每任务恰一个入口）；`url` 是作用
/// 域页（`/ui/builds/{id}/changelog` 或 `/ui/tasks/{id}/changelog`）；渲染
/// 条件由调用方判定（产物行含 rpm/srpm）。
pub(crate) fn changelog_header_link(url: &str, lang: Lang) -> Markup {
    html! {
        a class="changelog-link" href=(url) { (t(lang, TextKey::ChangelogLink)) }
    }
}

/// 渲染 `build_artifacts` 表格（build/task 详情页共用），`crbs-logs/` 子树
/// 压缩为表格内可展开行。`rows` 由调用方（`service::load_artifacts_from_db`）
/// 过滤掉 Metadata/Script 后传入。列刻意精简：NEVRA 即文件名、Signed 在
/// Details 侧栏、SHA256 反查走 API `by-sha256` 端点、changelog 入口在产物
/// 卡头（[`changelog_header_link`]）。`crbs-logs/` 前缀行不进普通行，改列为
/// 树行（见 [`logs_tree_rows`]）：根行默认折叠，点击 File 单元格原地展开直接
/// 子行（[`artifact_tree_script`]）；SSE 终态整页 reload 会丢用户展开态——
/// 不持久化。
pub(crate) fn artifact_table(build_id: i64, rows: &[Artifact], lang: Lang) -> Markup {
    // 分区：`crbs-logs/` 前缀行（classify 强制 kind=log、arch=None，树行不
    // 需要 Kind/Arch 列）进目录树，其余进表格；前缀判定与 classify 同口径
    // （strip_prefix CRBS_LOGS_DIR + 后随 '/'）。
    let mut tree = LogsTree::default();
    let mut table_rows: Vec<&Artifact> = Vec::new();
    for row in rows {
        match row
            .relative_path
            .strip_prefix(CRBS_LOGS_DIR)
            .and_then(|rest| rest.strip_prefix('/'))
        {
            Some(rel) => tree.insert(rel, row),
            None => table_rows.push(row),
        }
    }
    html! {
        @if !table_rows.is_empty() || !tree.is_empty() {
            table class="fixed" {
                // 列宽：File 长内容 auto 吃剩余宽度，Kind/Arch/Size 短定值。
                colgroup {
                    col style="width:auto" {}
                    col style="width:11%" {}
                    col style="width:11%" {}
                    col style="width:13%" {}
                }
                thead {
                    tr {
                        th { (t(lang, TextKey::ThFile)) }
                        th { (t(lang, TextKey::ThKind)) }
                        th { (t(lang, TextKey::FilterArch)) }
                        th class="num" { (t(lang, TextKey::ThSize)) }
                    }
                }
                tbody {
                    @for row in table_rows {
                        tr {
                            td class="ellipsis" title=(artifact_file_name(&row.relative_path)) {
                                a href=(download_url(build_id, &row.relative_path)) {
                                    (artifact_file_name(&row.relative_path))
                                }
                            }
                            td { code { (row.kind.as_str()) } }
                            td { (row.arch.as_deref().unwrap_or("—")) }
                            td class="num" { (humansize::format_size(row.size_bytes, humansize::DECIMAL)) }
                        }
                    }
                    @if !tree.is_empty() {
                        (logs_tree_rows(build_id, &tree, lang))
                    }
                }
            }
        }
    }
}

/// crbs-logs/ 子树节点：BTreeMap 迭代序即按名排序（渲染时目录先、文件后），
/// files 键 = 文件 basename（同目录内唯一）。
#[derive(Default)]
struct LogsTree<'a> {
    dirs: BTreeMap<String, LogsTree<'a>>,
    files: BTreeMap<String, &'a Artifact>,
}

impl<'a> LogsTree<'a> {
    fn is_empty(&self) -> bool {
        self.dirs.is_empty() && self.files.is_empty()
    }

    /// 插入一条 crbs-logs 文件行：`rel` 为去掉 `crbs-logs/` 前缀后的相对
    /// 路径，逐段下钻建目录、末段作文件；空段跳过（脏数据不建匿名目录）。
    fn insert(&mut self, rel: &str, row: &'a Artifact) {
        let mut segs = rel.split('/').filter(|s| !s.is_empty());
        let Some(name) = segs.next_back() else { return };
        let mut node = self;
        for seg in segs {
            node = node.dirs.entry(seg.to_string()).or_default();
        }
        node.files.insert(name.to_string(), row);
    }

    /// 递归文件数与总字节数（根 summary 计数 + 总大小、子目录 summary 计数口径）。
    fn stats(&self) -> (usize, u64) {
        let mut count = self.files.len();
        let mut size: u64 = self.files.values().map(|r| r.size_bytes).sum();
        for sub in self.dirs.values() {
            let (c, s) = sub.stats();
            count += c;
            size += s;
        }
        (count, size)
    }
}

/// 树行 File 列缩进：td 基础左内边距 0.875rem（th,td 规则）之上每深一级
/// 加 14px，inline calc 承担。
fn at_indent(depth: usize) -> String {
    format!("padding-left:calc(0.875rem + {}px)", depth * 14)
}

/// crbs-logs/ 树行：根行（可见）+ 递归全部后代行（hidden，随父目录展开
/// 逐级显示）。行契约：目录行 `at-dir-row` + `data-at-node`（crbs-logs/
/// 起完整相对路径，根即 "crbs-logs"），所有子行 `data-at-parent` = 父目录
/// 路径；task 详情页每架构一张表、node 路径跨表重复，JS 侧必须以
/// closest('table') 圈定作用域。根 summary：目录名 + 递归文件数 + 递归总
/// 大小，Kind=log、Arch=—。
fn logs_tree_rows(build_id: i64, tree: &LogsTree<'_>, lang: Lang) -> Markup {
    let (count, total) = tree.stats();
    html! {
        tr class="at-dir-row" data-at-node=(CRBS_LOGS_DIR) {
            td class="ellipsis" data-at-toggle {
                span class="at-caret" aria-hidden="true" { "▸" }
                code class="at-dirname" { (CRBS_LOGS_DIR) "/" }
                span class="at-count" { (t_fmt(lang, FmtKey::LogsDirFiles, &[&count.to_string()])) }
            }
            td { code { (crbs_core::ArtifactKind::Log.as_str()) } }
            td { "—" }
            td class="num" { (humansize::format_size(total, humansize::DECIMAL)) }
        }
        (logs_tree_children_rows(build_id, tree, CRBS_LOGS_DIR, 1, lang))
    }
}

/// 后代行：子目录先、文件后各按名排序（BTreeMap 迭代序保证确定性）；
/// 目录行 File = 展开标记 + `名/` + 递归文件数、Kind/Arch/Size 留空，
/// 文件行 basename 做链接文本、title 放完整 relative_path（补普通行只有
/// 文件名的缺口）、Size 为文件大小。
fn logs_tree_children_rows(
    build_id: i64,
    node: &LogsTree<'_>,
    parent: &str,
    depth: usize,
    lang: Lang,
) -> Markup {
    html! {
        @for (name, sub) in &node.dirs {
            @let (count, _) = sub.stats();
            @let path = format!("{parent}/{name}");
            tr class="at-dir-row" hidden data-at-node=(path) data-at-parent=(parent) {
                td class="ellipsis" data-at-toggle style=(at_indent(depth)) {
                    span class="at-caret" aria-hidden="true" { "▸" }
                    code class="at-dirname" { (name) "/" }
                    span class="at-count" { (t_fmt(lang, FmtKey::LogsDirFiles, &[&count.to_string()])) }
                }
                td {}
                td {}
                td {}
            }
            (logs_tree_children_rows(build_id, sub, &path, depth + 1, lang))
        }
        @for row in node.files.values() {
            tr hidden data-at-parent=(parent) {
                td class="ellipsis" style=(at_indent(depth)) title=(row.relative_path) {
                    a href=(download_url(build_id, &row.relative_path)) {
                        (artifact_file_name(&row.relative_path))
                    }
                }
                td {}
                td {}
                td class="num" { (humansize::format_size(row.size_bytes, humansize::DECIMAL)) }
            }
        }
    }
}

/// 子构建时长展示：duration>0 才渲染（None/0 不占位）；task SSE 子构建更新按 `.arch-duration` 定位刷新。
fn arch_duration(duration: Option<i64>, lang: Lang) -> Markup {
    match duration.filter(|d| *d > 0) {
        Some(secs) => {
            html! { span class="arch-duration" title=(t(lang, TextKey::TitleDuration)) { (format_duration_secs(secs)) } }
        }
        None => html! {},
    }
}

/// task 详情子构建矩阵。`back`：携带当前 task 详情 URL 作为子构建详情页的
/// 返回目标（task→build→back 回来源 task）。`a.arch-cell` 带 `aria-live="polite"`，
/// task SSE 脚本（updateChildren）会原地改写 cell 内 phase 徽章文本与时长。
pub(crate) fn arch_matrix(builds: &[ChildBuildSummary], back: Option<&str>, lang: Lang) -> Markup {
    if builds.is_empty() {
        return html! { (empty_state(
            t(lang, TextKey::EmptyChildBuildsTitle),
            t(lang, TextKey::EmptyChildBuildsHint),
        )) };
    }
    let cell_href = |id: i64| -> String {
        let href = format!("/ui/builds/{id}");
        match back {
            Some(b) => with_back_param(&href, b),
            None => href,
        }
    };
    html! {
        div class="arch-matrix" {
            @for b in builds {
                // data-build-id 是 task SSE 子构建增量更新的定位锚点。
                @if let Some(started) = b.started_at.as_deref() {
                    a class="arch-cell" data-build-id=(b.id) href=(cell_href(b.id))
                        aria-live="polite"
                        title=(t_fmt(lang, FmtKey::StartedAtTitle, &[&format_local_time(started)])) {
                        span class="arch-name" { (b.arch) }
                        (phase_badge_with_class(&b.phase, "", lang))
                        time class="arch-time" { (format_local_time(started)) }
                        (arch_duration(b.duration, lang))
                        @if let Some(w) = b.worker.as_deref() {
                            span class="arch-worker" { (w) }
                        }
                    }
                } @else {
                    // 未 started 子构建不含 time.arch-time 格且**不随 SSE 补建**
                    // （裁定）：children payload 只带 id/phase/duration（sse.rs
                    // task 事件），JS 无开始时间可填；徽章与 .arch-duration 仍由
                    // updateChildren 刷新，start 时间列待终态 reload 由本 SSR 分支补齐。
                    a class="arch-cell" data-build-id=(b.id) href=(cell_href(b.id))
                        aria-live="polite" {
                        span class="arch-name" { (b.arch) }
                        (phase_badge_with_class(&b.phase, "", lang))
                        (arch_duration(b.duration, lang))
                        @if let Some(w) = b.worker.as_deref() {
                            span class="arch-worker" { (w) }
                        }
                    }
                }
            }
        }
    }
}

/// Danger zone 单行：左侧标题 + 后果描述（`desc` 为空串时不渲染描述行），
/// 右侧操作（form / button 由调用方构造，保持各自 confirm 语义与样式）。
pub(crate) fn danger_row(title: &str, desc: &str, action: Markup) -> Markup {
    html! {
        div class="danger-row" {
            div class="danger-txt" {
                b { (title) }
                @if !desc.is_empty() {
                    span { (desc) }
                }
            }
            (action)
        }
    }
}

/// build 详情侧栏「所属任务」块：Task #N 链接 + 该任务各架构 mini 列表
/// （phase 色点 `.status` 无 data-phase——本块无 JS/SSE 消费；当前构建
/// `li.current` 高亮且保持纯文本不自指，其余行整行链接到各自详情页）。
/// 数据源 get_child_build_summaries（task_id 恒非空，调用方保证 Option
/// 已解包）；仅输出块内层，由调用方嵌进 Details side_card。
pub(crate) fn parent_task_block(
    task_id: i64,
    current_build_id: i64,
    builds: &[ChildBuildSummary],
    lang: Lang,
) -> Markup {
    html! {
        div class="parent-task-block" {
            h3 class="side-sub" { (t(lang, TextKey::ParentTaskTitle)) }
            a class="parent-task-link" href=(format!("/ui/tasks/{task_id}")) {
                (t_fmt(lang, FmtKey::TaskTitle, &[&task_id.to_string()]))
            }
            ul class="sibling-builds" {
                @for b in builds {
                    @let is_current = b.id == current_build_id;
                    @let row = html! {
                        span class="sib-arch" { (b.arch) }
                        (phase_status(&b.phase, lang))
                        @if let Some(secs) = b.duration.filter(|d| *d > 0) {
                            span class="sib-dur" { (format_duration_secs(secs)) }
                        }
                    };
                    @if is_current {
                        li class="current" { (row) }
                    } @else {
                        li { a href=(format!("/ui/builds/{}", b.id)) { (row) } }
                    }
                }
            }
        }
    }
}

/// 详情侧栏的 SRPM 一键下载链接（产物行含 srpm 才有；无则 None 不渲染）。
pub(crate) fn srpm_download_href(build_id: i64, rows: &[Artifact]) -> Option<String> {
    rows.iter()
        .find(|r| r.kind.as_str() == "srpm")
        .map(|r| download_url(build_id, &r.relative_path))
}

pub(crate) fn clickable_rows_script(nonce: &str) -> Markup {
    html! {
        script nonce=(nonce) { (PreEscaped(r#"
            (function() {
                // 幂等全局绑定器（window.__crbsBindClickableRows）：SSE 片段换新
                // 后由 dashboard 脚本重调；data 标记防同页重绑叠加 listener。
                function bind() {
                    document.querySelectorAll('table tbody tr.clickable-row').forEach(function(row) {
                        if (row.dataset.crbsClickable) return;
                        row.dataset.crbsClickable = '1';
                        row.style.cursor = 'pointer';
                        row.addEventListener('click', function(ev) {
                            if (ev.target.closest('a, button, input, select, textarea')) return;
                            var link = row.querySelector('a.row-target');
                            if (link) {
                                window.location.href = link.href;
                            }
                        });
                    });
                }
                window.__crbsBindClickableRows = bind;
                bind();
            })();
        "#)) }
    }
}

/// 产物表 crbs-logs/ 树行展开脚本（build/task 详情页各一条，页面多张产物
/// 表共用）：事件委托绑 document + window 标志位只绑一次；点击 File 单元格
/// `td[data-at-toggle]` 在 closest('table') 作用域内展开/收起该
/// `data-at-node`——展开只显示 `data-at-parent` 等于该节点的直接子行；收
/// 起递归隐藏 parent 等于该节点或以其为前缀的全部后代行并复位展开态（跨
/// 表 node 路径重复，不圈 table 会误伤他表）。
pub(crate) fn artifact_tree_script(nonce: &str) -> Markup {
    html! {
        script nonce=(nonce) { (PreEscaped(r#"
            (function() {
                if (window.__atTreeBound) return;
                window.__atTreeBound = true;
                document.addEventListener('click', function(ev) {
                    var cell = ev.target.closest('[data-at-toggle]');
                    if (!cell) return;
                    var row = cell.closest('tr');
                    var table = cell.closest('table');
                    var node = row && row.getAttribute('data-at-node');
                    if (!table || !node) return;
                    var expand = !row.classList.contains('expanded');
                    row.classList.toggle('expanded', expand);
                    table.querySelectorAll('tr[data-at-parent]').forEach(function(r) {
                        var parent = r.getAttribute('data-at-parent');
                        if (expand) {
                            if (parent === node) r.removeAttribute('hidden');
                        } else if (parent === node || parent.indexOf(node + '/') === 0) {
                            r.setAttribute('hidden', '');
                            r.classList.remove('expanded');
                        }
                    });
                });
            })();
        "#)) }
    }
}

/// 审计页 action 下拉已知动作列表。
pub(crate) const AUDIT_ACTIONS: &[&str] = &[
    "cancel_build",
    "cancel_task",
    "change_priority",
    "clean_product",
    "create_product",
    "create_user",
    "create_user_token",
    "delete_product_row",
    "delete_worker",
    "disable_user",
    "enable_user",
    "gc",
    "grant_product_acl",
    "init_base_os",
    "init_product",
    "login_failure",
    "login_success",
    "logout",
    "password_change",
    "password_reset",
    "post_init",
    "register",
    "publish_build",
    "rebuild_repo",
    "rebuild_task",
    "reproduce_task",
    "revoke_product_acl",
    "revoke_user_token",
    "session_revoke",
    "revoke_worker_secret",
    "rotate_worker_secret",
    "submit_build",
    "transfer_product_ownership",
    "unpublish_build",
    "update_product",
    "update_product_visibility",
    "update_registration_setting",
    "update_user",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试产物行构造（arch 默认 x86_64、1 KiB、on_disk=true）。
    fn artifact(kind: crbs_core::ArtifactKind, sha: &str, rel: &str) -> Artifact {
        Artifact {
            id: 1,
            build_id: 1,
            relative_path: rel.to_string(),
            kind,
            size_bytes: 1024,
            sha256: sha.to_string(),
            unsigned_sha256: None,
            arch: Some("x86_64".into()),
            name: Some("hello".into()),
            version: Some("1.0".to_string()),
            release: Some("1".to_string()),
            epoch: None,
            signed: false,
            on_disk: true,
            metadata_json: None,
            created_at: "2026-08-31 00:00:00".into(),
        }
    }

    /// artifact_table 对 rpm/srpm/log 行零输出 sha 值、SHA256 表头、
    /// changelog-link 类与 /ui/artifacts/ 下钻 href（入口见 changelog_header_link 测试）。
    #[test]
    fn artifact_table_has_no_sha256_column_or_inline_changelog() {
        let rpm_sha = "a".repeat(64);
        let log_sha = "b".repeat(64);
        let rows = vec![
            artifact(
                crbs_core::ArtifactKind::Rpm,
                &rpm_sha,
                "RPMS/hello-1.0-1.x86_64.rpm",
            ),
            artifact(crbs_core::ArtifactKind::Log, &log_sha, "build.log"),
        ];
        let html = artifact_table(1, &rows, Lang::En).into_string();

        // SHA256 列零输出（表头 + 单元格值；文件名已与 sha 解耦，命中即泄漏）。
        assert!(!html.contains("SHA256"), "no SHA256 header: {html}");
        assert!(!html.contains(&rpm_sha), "no sha value: {html}");
        assert!(!html.contains(&rpm_sha[..12]), "no sha prefix: {html}");
        assert!(
            !html.contains("changelog-link"),
            "no inline changelog link: {html}"
        );
        assert!(
            !html.contains("/ui/artifacts/"),
            "no sha-scoped changelog href: {html}"
        );
        // 四列表头仍在（走 DB 表格路径的断言锚点）。
        assert!(
            html.contains("<th>Kind</th>"),
            "kind header remains: {html}"
        );
    }

    /// crbs-logs/ 子树表格内可展开行：根行可见且含递归文件数/总大小、
    /// Kind=log；全部子行默认 hidden 且带 data-at-parent，嵌套目录行带
    /// data-at-node；文件行链接 href/title 携带 urlencode 完整相对路径；
    /// 缩进随深度递增；其余行仍全部留在表格（分区不漏行、目录先文件后）。
    #[test]
    fn artifact_table_renders_crbs_logs_as_expandable_rows() {
        let rows = vec![
            artifact(
                crbs_core::ArtifactKind::Rpm,
                &"a".repeat(64),
                "RPMS/hello-1.0-1.x86_64.rpm",
            ),
            artifact(crbs_core::ArtifactKind::Log, &"b".repeat(64), "build.log"),
            artifact(
                crbs_core::ArtifactKind::Log,
                &"c".repeat(64),
                "crbs-logs/dmesg.txt",
            ),
            artifact(
                crbs_core::ArtifactKind::Log,
                &"d".repeat(64),
                "crbs-logs/effective_code_rate/hook-debug/err",
            ),
        ];
        let html = artifact_table(1, &rows, Lang::En).into_string();

        // 根行：可见（无 hidden）、data-at-node 为根目录名，File 列含展开
        // 标记 + 目录名 + 递归文件总数，Kind=log、Arch=—、Size=递归总大小。
        assert!(
            html.contains(r#"<tr class="at-dir-row" data-at-node="crbs-logs">"#),
            "{html}"
        );
        assert!(html.contains(r#"data-at-toggle"#), "{html}");
        assert!(html.contains("crbs-logs/"), "{html}");
        assert!(html.contains("(2 files)"), "{html}");
        assert!(html.contains("<td><code>log</code></td>"), "{html}");
        assert!(html.contains("<td>—</td>"), "{html}");
        assert!(html.contains(r#"<td class="num">2.05 kB</td>"#), "{html}");

        // 子目录行（两级）与文件行均默认 hidden；子行带 data-at-parent，
        // 目录行另带 data-at-node（crbs-logs/ 起完整相对路径）。
        assert!(
            html.contains(
                r#"<tr class="at-dir-row" hidden data-at-node="crbs-logs/effective_code_rate" data-at-parent="crbs-logs">"#
            ),
            "{html}"
        );
        assert!(
            html.contains(
                r#"<tr class="at-dir-row" hidden data-at-node="crbs-logs/effective_code_rate/hook-debug" data-at-parent="crbs-logs/effective_code_rate">"#
            ),
            "{html}"
        );
        assert!(
            html.contains(r#"<tr hidden data-at-parent="crbs-logs">"#),
            "{html}"
        );

        // 子目录 summary：目录名/ + 各自递归计数。
        assert!(html.contains("effective_code_rate/"), "{html}");
        assert!(html.contains("hook-debug/"), "{html}");
        assert!(html.contains("(1 files)"), "{html}");

        // 文件行：href 携带 urlencode 完整相对路径，title 放全路径，basename
        // 做文本，Size 为文件大小。
        assert!(
            html.contains(
                r#"href="/api/v1/builds/1/artifacts/download?file=crbs-logs%2Feffective_code_rate%2Fhook-debug%2Ferr""#
            ),
            "{html}"
        );
        assert!(
            html.contains(r#"title="crbs-logs/effective_code_rate/hook-debug/err""#),
            "{html}"
        );

        // 缩进随深度递增：depth 1 = 14px、depth 2 = 28px（叠在 td 基础内边距上）。
        assert!(
            html.contains("padding-left:calc(0.875rem + 14px)"),
            "{html}"
        );
        assert!(
            html.contains("padding-left:calc(0.875rem + 28px)"),
            "{html}"
        );

        // 分区：td.ellipsis = 普通行 2（rpm + 顶层 build.log）+ 树行 5
        //（目录 3 含根 + 文件 2），树入口一个不漏。
        assert_eq!(html.matches(r#"<td class="ellipsis""#).count(), 7, "{html}");
        // 确定性排序：子目录行先于同层文件行渲染（目录先、文件后）。
        let dir_at = html
            .find(r#"data-at-node="crbs-logs/effective_code_rate""#)
            .unwrap();
        let file_at = html.find(r#"title="crbs-logs/dmesg.txt""#).unwrap();
        assert!(dir_at < file_at, "dirs render before files: {html}");
    }

    /// 无 crbs-logs 行时输出与引入目录树前逐字节一致（回归钉住整段表格 HTML）。
    #[test]
    fn artifact_table_without_crbs_logs_rows_is_unchanged() {
        let rows = vec![
            artifact(
                crbs_core::ArtifactKind::Rpm,
                &"a".repeat(64),
                "RPMS/hello-1.0-1.x86_64.rpm",
            ),
            artifact(crbs_core::ArtifactKind::Log, &"b".repeat(64), "build.log"),
        ];
        let html = artifact_table(1, &rows, Lang::En).into_string();
        assert_eq!(
            html,
            concat!(
                r#"<table class="fixed"><colgroup><col style="width:auto"></col>"#,
                r#"<col style="width:11%"></col><col style="width:11%"></col>"#,
                r#"<col style="width:13%"></col></colgroup><thead><tr><th>File</th>"#,
                r#"<th>Kind</th><th>Arch</th><th class="num">Size</th></tr></thead><tbody>"#,
                r#"<tr><td class="ellipsis" title="hello-1.0-1.x86_64.rpm">"#,
                r#"<a href="/api/v1/builds/1/artifacts/download?file=RPMS%2Fhello-1.0-1.x86_64.rpm">"#,
                r#"hello-1.0-1.x86_64.rpm</a></td><td><code>rpm</code></td><td>x86_64</td>"#,
                r#"<td class="num">1.02 kB</td></tr>"#,
                r#"<tr><td class="ellipsis" title="build.log">"#,
                r#"<a href="/api/v1/builds/1/artifacts/download?file=build.log">build.log</a></td>"#,
                r#"<td><code>log</code></td><td>x86_64</td><td class="num">1.02 kB</td></tr>"#,
                r#"</tbody></table>"#,
            ),
            "{html}"
        );
    }

    /// 产物卡头 changelog 入口 helper：渲染 a.changelog-link + 作用域 href，文案复用 ChangelogLink 键。
    #[test]
    fn changelog_header_link_renders_scope_url() {
        let html = changelog_header_link("/ui/builds/7/changelog", Lang::En).into_string();
        assert!(
            html.contains("href=\"/ui/builds/7/changelog\""),
            "header link uses build-scoped url: {html}"
        );
        assert!(
            html.contains(">changelog</a>"),
            "link text must be the localized label: {html}"
        );

        let html = changelog_header_link("/ui/tasks/9/changelog", Lang::En).into_string();
        assert!(
            html.contains("href=\"/ui/tasks/9/changelog\""),
            "header link uses task-scoped url: {html}"
        );
    }

    #[test]
    fn arch_matrix_renders_build_id_anchor_and_duration() {
        // data-build-id = task SSE 增量更新定位锚；duration>0 渲染 .arch-duration
        // （与 format_duration_secs 同口径，None/0 不占位）；cell 带 aria-live + back 参数。
        let builds = [
            ChildBuildSummary {
                id: 11,
                arch: "x86_64".into(),
                phase: "succeeded".into(),
                result_dir: None,
                started_at: Some("2026-08-26T10:00:00".into()),
                duration: Some(222),
                worker: None,
            },
            ChildBuildSummary {
                id: 12,
                arch: "aarch64".into(),
                phase: "building".into(),
                result_dir: None,
                started_at: Some("2026-08-26T10:00:00".into()),
                duration: None,
                worker: None,
            },
            ChildBuildSummary {
                id: 13,
                arch: "riscv64".into(),
                phase: "pending".into(),
                result_dir: None,
                started_at: None,
                duration: Some(0),
                worker: None,
            },
        ];
        let s = arch_matrix(&builds, Some("/ui/tasks/9"), Lang::En).into_string();
        for id in [11, 12, 13] {
            assert_eq!(
                s.matches(&format!(r#"data-build-id="{id}""#)).count(),
                1,
                "{s}"
            );
        }
        assert_eq!(
            s.matches(r#"aria-live="polite""#).count(),
            3,
            "every arch cell must be a live region: {s}"
        );
        assert!(
            s.contains(r#"href="/ui/builds/11?back=%2Fui%2Ftasks%2F9""#),
            "{s}"
        );
        assert!(
            s.contains(r#"<span class="arch-duration" title="duration">3m 42s</span>"#),
            "{s}"
        );
        // building（duration=None）与 pending（duration=0）不渲染时长节点。
        assert_eq!(s.matches("arch-duration").count(), 1, "{s}");
    }

    #[test]
    fn arch_matrix_empty_renders_empty_state_and_without_back_is_plain_link() {
        let s = arch_matrix(&[], None, Lang::En).into_string();
        assert!(s.contains("empty-state"), "{s}");
        assert!(s.contains("No child builds yet"), "{s}");

        let builds = [ChildBuildSummary {
            id: 21,
            arch: "x86_64".into(),
            phase: "succeeded".into(),
            result_dir: None,
            started_at: Some("2026-08-26T10:00:00".into()),
            duration: None,
            worker: None,
        }];
        let s = arch_matrix(&builds, None, Lang::En).into_string();
        assert!(s.contains(r#"href="/ui/builds/21""#), "{s}");
        assert!(!s.contains("back="), "{s}");
    }

    /// 「所属任务」块：非当前构建行整行链接到各自详情页（build id 进 href），
    /// 当前构建行保持纯文本不自指；Task #N 链接与 arch/状态/时长内容不变。
    #[test]
    fn parent_task_block_links_siblings_but_keeps_current_plain() {
        let builds = [
            ChildBuildSummary {
                id: 31,
                arch: "x86_64".into(),
                phase: "succeeded".into(),
                result_dir: None,
                started_at: None,
                duration: Some(416),
                worker: None,
            },
            ChildBuildSummary {
                id: 32,
                arch: "aarch64".into(),
                phase: "building".into(),
                result_dir: None,
                started_at: None,
                duration: None,
                worker: None,
            },
        ];
        let html = parent_task_block(9, 31, &builds, Lang::En).into_string();

        // 兄弟构建：build id 进 href，arch 文案保留在链接内。
        assert!(
            html.contains(r#"<li><a href="/ui/builds/32"><span class="sib-arch">aarch64</span>"#),
            "{html}"
        );
        // 当前构建：li.current 高亮且无自指链接。
        assert!(html.contains(r#"<li class="current">"#), "{html}");
        assert!(!html.contains(r#"href="/ui/builds/31""#), "{html}");
        // Task #N 链接仍在；时长文案不变（416s = 6m 56s）。
        assert!(html.contains(r#"href="/ui/tasks/9""#), "{html}");
        assert!(
            html.contains(r#"<span class="sib-dur">6m 56s</span>"#),
            "{html}"
        );
    }
}
