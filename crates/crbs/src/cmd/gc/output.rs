// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! gc 子命令输出：文本摘要与 JSON 成功信封。

use crate::cli::CommandOutput;
use crbs_core::types::GcSummary;

pub(crate) struct GcOutput<'a>(pub &'a GcSummary);

impl CommandOutput for GcOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        // GcSummary 全为标量/Option 字段，serde 序列化实际不可失败，map_err
        // 仅防御；本体平铺合并 command:"gc"（与 json_error_contract 同源），
        // schema 原样保留。
        let body = serde_json::to_value(self.0)
            .map_err(|e| anyhow::anyhow!("serialize GC summary: {}", e))?;
        serde_json::to_string_pretty(&crate::cmd::json_success_envelope("gc", body))
            .map_err(|e| anyhow::anyhow!("serialize GC envelope: {}", e))
    }

    fn print_text(&self) {
        print_text_summary(self.0);
    }
}

fn print_text_summary(summary: &GcSummary) {
    if let Some(o) = &summary.orphan_mounts {
        if o.found == 0 {
            println!("No orphan mounts found.");
        } else if o.dry_run {
            println!("Orphan mounts: {} would be umounted", o.found);
        } else {
            let dirs = if o.removed_dirs > 0 {
                format!(
                    ", {} incomplete layer dir{} removed",
                    o.removed_dirs,
                    if o.removed_dirs == 1 { "" } else { "s" }
                )
            } else {
                String::new()
            };
            println!("Orphan mounts: {} umounted{}", o.cleaned, dirs);
        }
    }

    if let Some(r) = &summary.results {
        let size_str = format_size(r.bytes);
        // failed>0 = 有候选删除/落库失败，留待下一轮 GC 重试
        let failed_tag = if r.failed > 0 {
            format!(", {} failed", r.failed)
        } else {
            String::new()
        };
        if r.would_remove > 0 {
            println!(
                "Result dirs: {} would be removed ({}){}",
                r.would_remove, size_str, failed_tag
            );
        } else {
            let policy_tag = if r.policy_removed > 0 {
                format!(", {} policy removed", r.policy_removed)
            } else {
                String::new()
            };
            println!(
                "Result dirs: {} removed{}{} ({} freed)",
                r.removed, policy_tag, failed_tag, size_str
            );
        }
    }

    if let Some(c) = &summary.package_cache {
        let size_str = format_size(c.bytes);
        let lru_size_str = format_size(c.lru_bytes);
        if c.dry_run {
            println!(
                "Package cache: {} would be removed, {} referenced ({} freed)",
                c.removed, c.kept, size_str
            );
        } else if c.removed == 0 && c.kept == 0 && c.bytes == 0 && c.lru_evicted == 0 {
            println!("Package cache: directory not found, nothing to clean");
        } else {
            println!(
                "Package cache: {} unreferenced removed, {} LRU evicted ({} freed)",
                c.removed, c.lru_evicted, lru_size_str
            );
        }
    }

    if let Some(s) = &summary.shared_layers {
        let stale_size = format_size(s.stale_upper_bytes);
        if s.stale_uppers > 0 {
            println!(
                "Shared layers: {} removed, {} stale upper dirs cleaned ({} freed)",
                s.removed, s.stale_uppers, stale_size
            );
        } else {
            println!("Shared layers: {} removed", s.removed);
        }
    }
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{} B", bytes)
    }
}
