// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs diff <left> <right>`：对比两次构建的产物、依赖与 profile 差异。

use crate::cli::OutputFormat;
use crbs_core::config::CrbsConfig;
use crbs_core::privilege::CallerContext;
use crbs_core::StateStore;

/// Diff 命令入口；result_dir 安全根按调用方世界解析（server 侧 pin 到 server root）。
pub(crate) async fn handle_diff(
    left: String,
    right: String,
    format: OutputFormat,
    ctx: &CallerContext,
    global: &CrbsConfig,
    state: &StateStore,
) -> anyhow::Result<()> {
    let user_filter = crate::cmd::visible_user_filter(ctx);

    let diff = crbs_core::diff::compute_diff(state, global, &left, &right, user_filter).await?;
    format.print(&DiffOutput(&diff))?;
    Ok(())
}

struct DiffOutput<'a>(&'a crbs_core::diff::DiffResult);

impl crate::cli::CommandOutput for DiffOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        let diff = self.0;
        let output = serde_json::json!({
            "command": "diff",
            "left": diff.left.short_id,
            "right": diff.right.short_id,
            "metadata": {
                "left_backend": diff.left.backend,
                "right_backend": diff.right.backend,
                "left_duration": diff.left.duration,
                "right_duration": diff.right.duration,
                "left_phase": diff.left.phase,
                "right_phase": diff.right.phase,
            },
            "rpms": {
                "added": diff.rpms.added,
                "removed": diff.rpms.removed,
                "changed": diff.rpms.changed,
                "unchanged": diff.rpms.unchanged,
            },
            "srpms": {
                "added": diff.srpms.added,
                "removed": diff.srpms.removed,
                "changed": diff.srpms.changed,
                "unchanged": diff.srpms.unchanged,
            },
            "packages": diff.packages,
            "profile": diff.profile.as_ref().map(|p| serde_json::json!({
                "left_total": p.left_total,
                "right_total": p.right_total,
                "delta": p.delta,
                "phases": p.phases,
            })).unwrap_or(serde_json::Value::Null),
        });
        Ok(serde_json::to_string_pretty(&output)?)
    }

    fn print_text(&self) {
        print_diff_text(self.0);
    }
}

fn print_diff_text(diff: &crbs_core::diff::DiffResult) {
    println!(
        "Diff: {} ({}) → {} ({})",
        diff.left.short_id, diff.left.pkg_name, diff.right.short_id, diff.right.pkg_name
    );

    println!("\nMetadata:");
    if diff.left.backend != diff.right.backend {
        println!(
            "  backend:  {} → {}",
            fmt_opt(&diff.left.backend),
            fmt_opt(&diff.right.backend)
        );
    }
    println!(
        "  duration: {} → {}",
        fmt_duration(diff.left.duration),
        fmt_duration(diff.right.duration)
    );
    println!("  phase:    {} → {}", diff.left.phase, diff.right.phase);

    println!("\nRPM files:");
    print_rpm_diff_summary(&diff.rpms, "RPMS");
    print_rpm_diff_summary(&diff.srpms, "SRPMS");

    if !diff.packages.is_empty() {
        println!("\nPackage dependencies:");
        for d in &diff.packages {
            println!("  {}", d);
        }
    }

    if let Some(profile) = &diff.profile {
        if !profile.phases.is_empty() {
            println!("\nProfile:");
            for d in &profile.phases {
                println!("  {}", d);
            }
        }
    }
}

fn print_rpm_diff_summary(summary: &crbs_core::diff::RpmDiffSummary, label: &str) {
    println!(
        "  {}: added={}, removed={}, changed={}, unchanged={}",
        label,
        summary.added.len(),
        summary.removed.len(),
        summary.changed.len(),
        summary.unchanged
    );
}

fn fmt_opt(o: &Option<String>) -> String {
    o.as_deref().unwrap_or("-").to_string()
}

/// 秒数格式化：`Some(n)` → `"{n}s"`、`None` → `"-"`（缺失值渲染 "-" 而非 "-s"）。
fn fmt_duration(d: Option<i64>) -> String {
    match d {
        Some(s) => format!("{s}s"),
        None => "-".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_duration_handles_some_and_none() {
        assert_eq!(fmt_duration(Some(42)), "42s");
        assert_eq!(fmt_duration(None), "-");
    }

    #[test]
    fn fmt_opt_handles_some_and_none() {
        assert_eq!(fmt_opt(&Some("x".to_string())), "x");
        assert_eq!(fmt_opt(&None), "-");
    }
}
