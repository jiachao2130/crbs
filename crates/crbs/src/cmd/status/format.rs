// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 状态输出格式化：颜色、表格、profile 展示。

use std::io::IsTerminal;

use comfy_table::{Cell, Color, ColumnConstraint, ContentArrangement, Table, Width};

pub(crate) fn phase_color(phase: &str) -> &'static str {
    match phase {
        "succeeded" => "\x1b[32m", // green
        "failed" => "\x1b[31m",    // red
        "building" => "\x1b[33m",  // yellow
        "pending" => "\x1b[34m",   // blue
        "timeout" => "\x1b[35m",   // magenta
        "cancelled" => "\x1b[90m", // gray
        _ => "",
    }
}

/// ANSI 启用判定（纯函数便于单测）：stdout 是 tty 且未设非空 `NO_COLOR`（与值无关）。
/// 非 tty（管道/重定向）下不发音任何转义序列——含未知 phase 的裸 reset。
pub(crate) fn ansi_allowed(is_tty: bool, no_color: Option<&std::ffi::OsStr>) -> bool {
    is_tty && no_color.is_none_or(|v| v.is_empty())
}

/// 是否向 stdout 发 ANSI 颜色序列（OnceLock 缓存：tty 属性与环境变量进程内不变）。
fn ansi_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        ansi_allowed(
            std::io::stdout().is_terminal(),
            std::env::var_os("NO_COLOR").as_deref(),
        )
    })
}

fn colorize_phase(phase: &str, text: &str) -> String {
    if ansi_enabled() {
        format!("{}{}\x1b[0m", phase_color(phase), text)
    } else {
        text.to_string()
    }
}

/// 把秒数格式化为人类可读短串：仅分钟粒度（3661s → "61m1s"，无小时档），负数原样带 s。
pub(crate) fn format_seconds(s: i64) -> String {
    if s < 0 {
        return format!("{}s", s);
    }
    if s < 60 {
        format!("{}s", s)
    } else {
        let m = s / 60;
        let rem = s % 60;
        if rem == 0 {
            format!("{}m", m)
        } else {
            format!("{}m{}s", m, rem)
        }
    }
}

/// 截断字符串，超过宽度时加省略号（UTF-8 安全）。
pub(crate) fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_string()
    } else {
        let end = s
            .char_indices()
            .nth(width.saturating_sub(3))
            .map(|(i, _)| i)
            .unwrap_or(0);
        format!("{}...", &s[..end])
    }
}

/// phase → comfy-table 前景色；与 [`phase_color`] 的 ANSI 映射同义需同步维护，未着色返回 None。
fn phase_cell_color(phase: &str) -> Option<Color> {
    match phase {
        "succeeded" => Some(Color::Green),
        "failed" => Some(Color::Red),
        "building" => Some(Color::Yellow),
        "pending" => Some(Color::Blue),
        "timeout" => Some(Color::Magenta),
        "cancelled" => Some(Color::DarkGrey),
        _ => None,
    }
}

/// 统一新建基础表格（status 列表/详情与 builds show 产物表共用）：Dynamic 排布；
/// style=false 落到 comfy-table `should_style()==false`，重定向 / `NO_COLOR` 下纯文本。
pub(crate) fn new_table_with_style(style: bool) -> Table {
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    if !style {
        table.force_no_tty();
    }
    table
}

/// comfy-table 默认 cell 左右各 1 空格 padding：`Absolute(Fixed(w))` 的 w
/// **含** padding，内容区仅 w-2；钉宽按 内容宽 + padding 换算。
const CELL_PADDING: u16 = 2;

/// 给列钉固定宽度（入参为**内容**宽；内容入表前已 `truncate` 到同宽，几何与终端无关）。
fn pin_widths(table: &mut Table, content_widths: &[u16]) {
    table.set_constraints(
        content_widths
            .iter()
            .map(|w| ColumnConstraint::Absolute(Width::Fixed(w + CELL_PADDING))),
    );
}

pub(crate) fn print_profile(profile: &crbs_core::engine::profile::BuildProfile) {
    print!("{}", format_profile(profile));
}

/// 构建 profile 的人类可读多行文本（本地 `status --profile` 与远程同款渲染
/// 共用；远程路径拼在 record 摘要头行之后）。
pub(crate) fn format_profile(profile: &crbs_core::engine::profile::BuildProfile) -> String {
    let mut out = format!(
        "Build {}  {}  {:.1}s\n",
        profile.build_id, profile.srpm, profile.total_seconds
    );
    if profile.shared_layer_hit {
        out.push_str("SharedLayer: hit\n");
    }
    if let Some(ref ccache) = profile.ccache {
        out.push_str(&format!(
            "ccache: {:.0}% hit rate ({}/{} cacheable)\n",
            ccache.hit_rate * 100.0,
            ccache.cache_hits,
            ccache.cacheable_calls
        ));
    }
    out.push_str("\nPhase breakdown:\n");

    let total: f64 = profile.phases.iter().map(|p| p.duration_seconds).sum();
    for phase in &profile.phases {
        let pct = if total > 0.0 {
            phase.duration_seconds / total * 100.0
        } else {
            0.0
        };
        let bar_len = ((pct / 100.0) * 32.0).round() as usize;
        let bar = "█".repeat(bar_len);
        if phase.skipped == Some(true) {
            let reason = phase.reason.as_deref().unwrap_or("skipped");
            out.push_str(&format!("  {:<18} skipped ({})\n", phase.name, reason));
        } else {
            out.push_str(&format!(
                "  {:<18} {:>6.1}s {:>3.0}% {}\n",
                phase.name, phase.duration_seconds, pct, bar
            ));
        }
    }
    out
}

/// 任务列表表格的列宽（cell 内容先 `truncate` 到同宽再入表，列宽钉死）。
const TASK_TABLE_WIDTHS: [u16; 6] = [8, 16, 24, 12, 10, 20];

/// 构造任务列表表格（本地 / 远程 status 共用；style=false 即重定向 / NO_COLOR 下不发音任何样式序列）。
fn build_task_table(tasks: &[crbs_core::TaskRecord], limit: usize, style: bool) -> Table {
    let mut table = new_table_with_style(style);
    table.set_header(vec![
        Cell::new("ID"),
        Cell::new("Product"),
        Cell::new("Package"),
        Cell::new("Phase"),
        Cell::new("Priority"),
        Cell::new("Submitted"),
    ]);
    pin_widths(&mut table, &TASK_TABLE_WIDTHS);

    let display = if limit == 0 {
        tasks
    } else {
        &tasks[..tasks.len().min(limit)]
    };
    for t in display {
        // product/pkg_name/phase 可能来自服务器：先剥终端控制序列（防伪造状态
        // 行/破坏终端）；本地数据走同一函数，保本地/远程输出逐字节一致。
        let product = crate::remote::strip_terminal_control(&t.product);
        let pkg_name = crate::remote::strip_terminal_control(&t.pkg_name);
        let phase_src = crate::remote::strip_terminal_control(&t.phase);
        let [w_id, w_product, w_pkg, w_phase, w_priority, w_submitted] = TASK_TABLE_WIDTHS;
        let mut phase = Cell::new(truncate(&phase_src, w_phase as usize));
        if let Some(color) = phase_cell_color(&phase_src) {
            phase = phase.fg(color);
        }
        table.add_row(vec![
            Cell::new(truncate(&t.id.to_string(), w_id as usize)),
            Cell::new(truncate(&product, w_product as usize)),
            Cell::new(truncate(&pkg_name, w_pkg as usize)),
            phase,
            Cell::new(truncate(&t.priority.to_string(), w_priority as usize)),
            Cell::new(truncate(
                &crbs_core::util::format_local_time(t.submitted_at.as_deref().unwrap_or("-")),
                w_submitted as usize,
            )),
        ]);
    }
    table
}

/// 打印任务列表表格，返回 `(shown, total)`：shown = `limit` 截断后实际打印行数，
/// total = 列表真实长度（非 watch 调用方据此附截断提示；watch 轮询忽略返回值）。
pub(crate) fn print_task_table(tasks: &[crbs_core::TaskRecord], limit: usize) -> (usize, usize) {
    let display_len = if limit == 0 {
        tasks.len()
    } else {
        tasks.len().min(limit)
    };
    println!("{}", build_task_table(tasks, limit, ansi_enabled()));
    (display_len, tasks.len())
}

/// 打印任务详情：task 字段 + 子构建表（本地 / 远程 status 共用）。
pub(crate) fn print_task_detail(
    task: &crbs_core::TaskRecord,
    builds: &[crbs_core::types::ChildBuildSummary],
    lineage: Option<&crbs_core::types::TaskLineage>,
    labels: &[crbs_core::types::TaskLabel],
) {
    let t = task;
    // 详情字段同样可能来自服务器（远程 status）：与列表路径同口径剥终端控制
    // 序列，防 ANSI/CR 伪造状态行。
    let product = crate::remote::strip_terminal_control(&t.product);
    let pkg_name = crate::remote::strip_terminal_control(&t.pkg_name);
    let user = crate::remote::strip_terminal_control(&t.user);
    let phase_src = crate::remote::strip_terminal_control(&t.phase);
    println!("Task {}:", t.id);
    println!("  product:     {product}");
    println!("  package:     {pkg_name}");
    println!("  user:        {user}");
    println!("  phase:       {}", colorize_phase(&phase_src, &phase_src));
    println!("  priority:    {}", t.priority);
    println!(
        "  submitted:   {}",
        crbs_core::util::format_local_time(t.submitted_at.as_deref().unwrap_or("-"))
    );
    if let Some(ref completed) = t.completed_at {
        println!(
            "  completed:   {}",
            crbs_core::util::format_local_time(completed)
        );
    }
    if let Some(duration) = t.duration {
        println!("  duration:    {}", format_seconds(duration));
    }
    if let Some(ref result_dir) = t.result_dir {
        println!(
            "  result_dir:  {}",
            crate::remote::strip_terminal_control(result_dir)
        );
    }
    for label in labels {
        // 标签值来自服务器/用户输入，与其余详情字段同口径剥终端控制序列。
        println!(
            "  label:       {}={}",
            crate::remote::strip_terminal_control(&label.key),
            crate::remote::strip_terminal_control(&label.value)
        );
    }
    if let Some(l) = lineage {
        if let Some(src) = l.replay_source.as_ref() {
            println!(
                "  replay source: task {} (build {})",
                src.task_id, src.build_id
            );
        }
        if !l.replays.is_empty() {
            let list = l
                .replays
                .iter()
                .map(|r| {
                    format!(
                        "task {} ({})",
                        r.task_id,
                        crate::remote::strip_terminal_control(&r.phase)
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            println!("  replays:       {list}");
        }
    }

    if !builds.is_empty() {
        println!("\n  child builds:");
        const W_BUILD_ID: u16 = 10;
        const W_ARCH: u16 = 12;
        const W_PHASE: u16 = 12;
        const W_WORKER: u16 = 12;
        const W_RESULT: u16 = 40;
        let mut table = new_table_with_style(ansi_enabled());
        table.set_header(vec![
            Cell::new("Build ID"),
            Cell::new("Arch"),
            Cell::new("Phase"),
            Cell::new("Worker"),
            Cell::new("Result Dir"),
        ]);
        pin_widths(
            &mut table,
            &[W_BUILD_ID, W_ARCH, W_PHASE, W_WORKER, W_RESULT],
        );
        for b in builds {
            let arch = crate::remote::strip_terminal_control(&b.arch);
            let phase_src = crate::remote::strip_terminal_control(&b.phase);
            let worker = crate::remote::strip_terminal_control(b.worker.as_deref().unwrap_or("-"));
            let result_dir =
                crate::remote::strip_terminal_control(b.result_dir.as_deref().unwrap_or("-"));
            let mut phase = Cell::new(truncate(&phase_src, W_PHASE as usize));
            if let Some(color) = phase_cell_color(&phase_src) {
                phase = phase.fg(color);
            }
            table.add_row(vec![
                Cell::new(truncate(&b.id.to_string(), W_BUILD_ID as usize)),
                Cell::new(truncate(&arch, W_ARCH as usize)),
                phase,
                Cell::new(truncate(&worker, W_WORKER as usize)),
                Cell::new(truncate(&result_dir, W_RESULT as usize)),
            ]);
        }
        for line in table.to_string().lines() {
            println!("    {line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{build_task_table, format_seconds, print_task_detail};
    use crbs_core::types::ChildBuildSummary;
    use crbs_core::TaskRecord;

    /// 边界护栏：分钟进位与大值形态，防实现与文档示例漂移。
    #[test]
    fn format_seconds_minute_boundaries() {
        assert_eq!(format_seconds(0), "0s");
        assert_eq!(format_seconds(59), "59s");
        assert_eq!(format_seconds(61), "1m1s");
        assert_eq!(format_seconds(120), "2m");
        assert_eq!(format_seconds(3661), "61m1s");
    }

    fn sample_task(id: i64, phase: &str) -> TaskRecord {
        TaskRecord {
            id,
            product: "fedora".into(),
            pkg_name: "hello".into(),
            name: "hello".into(),
            version: "1.0".into(),
            release: "1".into(),
            user: "alice".into(),
            phase: phase.into(),
            priority: crbs_core::types::PRIORITY_DEFAULT,
            srpm_path: None,
            result_dir: None,
            submitted_at: None,
            completed_at: None,
            duration: None,
            pkg_names: Vec::new(),
        }
    }

    /// 关样式渲染必须无任何转义序列（含已知 phase 的着色 cell）；列头/行内容齐备，列宽钉死。
    #[test]
    fn task_table_renders_plain_and_pinned_when_styling_disabled() {
        let tasks = vec![
            sample_task(1, "succeeded"),
            sample_task(2, "cancelled"),
            sample_task(3, "mystery-phase"),
        ];
        let rendered = build_task_table(&tasks, 0, false).to_string();
        assert!(
            !rendered.contains('\x1b'),
            "style=false must not emit any escape sequence: {rendered}"
        );
        for header in ["ID", "Product", "Package", "Phase", "Priority", "Submitted"] {
            assert!(rendered.contains(&format!("| {header} ")), "{rendered}");
        }
        for (id, phase) in [(1, "succeeded"), (2, "cancelled"), (3, "mystery-p...")] {
            assert!(rendered.contains(&format!("| {id} ")), "{rendered}");
            assert!(rendered.contains(&format!("| {phase} ")), "{rendered}");
        }
        // limit=0 全行保留；行数 = 顶边+表头+表头分隔+n 行+(n-1) 分隔+底边 = 2n+3。
        assert_eq!(rendered.lines().count(), 3 * 2 + 3, "{rendered}");
    }

    #[test]
    fn task_table_limit_truncates_rows() {
        let tasks: Vec<_> = (1..=5).map(|i| sample_task(i, "succeeded")).collect();
        let rendered = build_task_table(&tasks, 2, false).to_string();
        assert!(rendered.contains("| 1 "), "{rendered}");
        assert!(rendered.contains("| 2 "), "{rendered}");
        assert!(!rendered.contains("| 3 "), "{rendered}");
    }

    #[test]
    fn child_builds_table_is_indented_plain_text() {
        let mut task = sample_task(7, "succeeded");
        task.result_dir = Some("/srv/result/7".into());
        let builds = vec![ChildBuildSummary {
            id: 11,
            arch: "x86_64".into(),
            phase: "failed".into(),
            result_dir: Some("/srv/result/11".into()),
            started_at: None,
            duration: None,
            worker: None,
        }];
        // stdout 重定向（测试捕获）下 ansi_enabled() 为 false，渲染即纯文本。
        print_task_detail(&task, &builds, None, &[]);
    }
}
