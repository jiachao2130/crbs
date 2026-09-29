// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Chain build 摘要的分组与打印。
//!
//! ScriptPhase 粒度受限：脚本失败的 stderr 只落在 build.log、不在
//! `CrbsError` 内，分类只能依据 `Io.detail` 的 script 路径与 phase.rs
//! 注入的受控 `phase=` 段。常规 chain（`/crbs-build.sh`）全部归
//! `Unknown`，`--reproduce` 脚本可分 install-deps / build；按 code
//! 分桶仍能区分 `io_error` 与 `timeout`。更细分类需改 `phase.rs`
//! 把 build.log tail 注入 `Io.detail`，属已知 follow-up。

use std::collections::HashMap;
use std::time::Duration;

use crbs_core::error::CrbsError;

/// 脚本阶段分类。详见模块级文档。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptPhase {
    /// `--reproduce` 路径的 deps 阶段（含 install-srpm + install-deps）
    InstallDeps,
    /// `--reproduce` 路径的 build 阶段
    Build,
    /// `/crbs-sign.sh` 失败（`code = "sign_failed"`）
    Sign,
    /// `code = "network_error"`
    NetworkSetup,
    /// ccache 步骤失败（`phase=ccache-init` / `ccache-summary`；典型根因：base_os 未装 ccache）
    Ccache,
    /// 占位：常规 chain build（绝大多数情况）
    Unknown,
}

impl ScriptPhase {
    /// 从 `CrbsError` 启发式分类 phase，优先级：`code`（sign_failed /
    /// network_error）→ `Io.detail` 受控 `phase=` 段（phase.rs 注入）→
    /// script 路径（reproduce-deps → InstallDeps、reproduce-build →
    /// Build、sign → Sign）→ 其余 `Unknown`。
    pub fn from_error(err: &CrbsError) -> Self {
        match err.code() {
            "sign_failed" => return Self::Sign,
            "network_error" => return Self::NetworkSetup,
            _ => {}
        }
        if let CrbsError::Io { detail, .. } = err {
            if let Some(phase) = Self::parse_detail_phase(detail) {
                return phase;
            }
        }
        let detail = err.to_string();
        if detail.contains("crbs-reproduce-deps.sh") {
            return Self::InstallDeps;
        }
        if detail.contains("crbs-reproduce-build.sh") {
            return Self::Build;
        }
        if detail.contains("crbs-sign.sh") {
            return Self::Sign;
        }
        Self::Unknown
    }

    /// 解析 `Io.detail` 中 phase.rs 注入的受控 `phase=` 段（PR-C）。
    fn parse_detail_phase(detail: &str) -> Option<Self> {
        for seg in detail.split(';') {
            let seg = seg.trim();
            if let Some(name) = seg.strip_prefix("phase=") {
                return match name {
                    "install-deps" => Some(Self::InstallDeps),
                    "build" => Some(Self::Build),
                    "install-srpm" => Some(Self::InstallDeps),
                    "ccache-init" | "ccache-summary" => Some(Self::Ccache),
                    _ => Some(Self::Unknown),
                };
            }
        }
        None
    }

    /// 稳定的小写 snake_case 标签，用于人类可读输出和 JSON `phase` 字段。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InstallDeps => "install-deps",
            Self::Build => "build",
            Self::Sign => "sign",
            Self::NetworkSetup => "network-setup",
            Self::Ccache => "ccache",
            Self::Unknown => "unknown",
        }
    }
}

/// 一个 (code, phase) 桶，聚合同类型失败；`code` 引用
/// `CrbsError::code()`，`sample_message` 取桶内出现次数最多的
/// message（mode 而非 first）。
#[derive(Debug, Clone)]
pub struct FailureBucket {
    pub code: &'static str,
    pub phase: ScriptPhase,
    pub count: usize,
    /// 截断到 200 字符的典型 message（mode 而非 first）。
    pub sample_message: String,
    /// 前 3 个包名（按 `summary.failed` 出现顺序）。
    pub sample_packages: Vec<String>,
    /// 内部统计 message mode，输出前清空。
    pub(crate) message_counts: HashMap<String, usize>,
}

/// 把 failed / cancelled / timeout 三类合并按 (code, phase) 分桶；
/// sample_message 取 mode（语义见 [`FailureBucket`]）。
pub fn group_failures(
    failed: &[(std::path::PathBuf, CrbsError, u64)],
    cancelled: &[(std::path::PathBuf, CrbsError, u64)],
    timeout: &[(std::path::PathBuf, CrbsError, u64)],
) -> Vec<FailureBucket> {
    let mut buckets: HashMap<(&'static str, ScriptPhase), FailureBucket> = HashMap::new();
    for (path, err, _dur) in failed.iter().chain(cancelled.iter()).chain(timeout.iter()) {
        let code = err.code();
        let phase = ScriptPhase::from_error(err);
        let key = (code, phase);
        let entry = buckets.entry(key).or_insert_with(|| FailureBucket {
            code,
            phase,
            count: 0,
            sample_message: String::new(),
            sample_packages: Vec::new(),
            message_counts: HashMap::new(),
        });
        entry.count += 1;
        if entry.sample_packages.len() < 3 {
            entry.sample_packages.push(extract_pkg_name(path));
        }
        let msg = truncate(&err.to_string(), 200);
        *entry.message_counts.entry(msg).or_insert(0) += 1;
    }

    for bucket in buckets.values_mut() {
        bucket.sample_message = bucket
            .message_counts
            .iter()
            .max_by_key(|(_, count)| **count)
            .map(|(msg, _)| msg.clone())
            .unwrap_or_default();
    }

    // 丢弃内部 message_counts，只对外暴露 sample_message
    let mut out: Vec<FailureBucket> = buckets
        .into_values()
        .map(|mut b| {
            b.message_counts.clear();
            b
        })
        .collect();
    out.sort_by_key(|b| std::cmp::Reverse(b.count));
    out
}

/// 从 SRPM 路径提取 NVRA（如 `/path/to/foo-1.0-1.src.rpm` → `foo-1.0-1`）。
/// 委托 `crbs_core::util::srpm_display_name`，失败时返回原始 path string。
pub fn extract_pkg_name(path: &std::path::Path) -> String {
    crbs_core::util::srpm_display_name(path).to_string()
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n).collect();
        out.push('…');
        out
    }
}

/// 摘要类目截断判定（纯函数，可单测）：返回 `(显示行数, full)`。
/// `force_full`（--list-* 强制全量）或 `limit == 0`（CLI 承诺
/// "0 = no truncation"）返回全量；否则取 `limit.min(total)` 行，
/// `full == false` 且超出时调用方补 "(N more)" 尾注。
fn summary_truncation(total: usize, limit: usize, force_full: bool) -> (usize, bool) {
    if force_full || limit == 0 {
        (total, true)
    } else {
        (limit.min(total), false)
    }
}

/// 打印截断的包名列表：空列表不打印；`full = false` 按 `limit` 截断、
/// 末尾打 `(N more, {hint})`（`hint` 空串退化为中性 `(N more)`）；
/// `limit == 0` 视同 full（CLI 承诺 "0 = no truncation"）；
/// `full = true` 打印全部，`hint` 不使用。
pub fn print_truncated_list(label: &str, pkgs: &[String], limit: usize, full: bool, hint: &str) {
    if pkgs.is_empty() {
        return;
    }
    let (show_count, full) = summary_truncation(pkgs.len(), limit, full);
    println!("{}{}", label, pkgs.len());
    for p in &pkgs[..show_count] {
        println!("  {}", p);
    }
    if !full && pkgs.len() > limit {
        if hint.is_empty() {
            println!("  ... ({} more)", pkgs.len() - limit);
        } else {
            println!("  ... ({} more, {})", pkgs.len() - limit, hint);
        }
    }
}

/// 打印 by-reason 桶列表；`limit`（默认 20）同时截断每桶包数与桶的
/// 显示数量（`limit.min(buckets.len())`；典型 2-3 桶远小于 limit，实际无感）。
pub fn print_failures_by_phase(buckets: &[FailureBucket], limit: usize) {
    if buckets.is_empty() {
        return;
    }
    // "0 = no truncation"：0 视同全量，避免 "(top 0)" 空表 + 尾注。
    let limit = if limit == 0 { buckets.len() } else { limit };
    println!("\nFailed by phase (top {}):", limit.min(buckets.len()));
    for b in buckets.iter().take(limit) {
        println!(
            "  {:>5}  {:<14}  {:<14}  {}",
            b.count,
            b.phase.as_str(),
            b.code,
            b.sample_message
        );
        if b.phase == ScriptPhase::Ccache {
            // ccache 失败几乎总是 base_os 未装 ccache（exit 127），hint 指向修复动作。
            println!(
                "  hint: ccache binary missing or failed — add ccache to base_packages so base_os provides it"
            );
        }
    }
    if buckets.len() > limit {
        println!(
            "  ... ({} more categories, use --list-failed for full breakdown)",
            buckets.len() - limit
        );
    }
}

/// [`print_summary_header`] 的参数包：摘要头部数字行。不变量：
/// `total == succeeded + failed + cancelled + timeout + cached + dep_skipped`；
/// `failed_total = failed + cancelled + timeout`。
pub struct SummaryHeaderParams {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub cancelled: usize,
    pub timeout: usize,
    pub dep_skipped: usize,
    pub recovered: usize,
    pub wall_time: Duration,
    pub rounds: usize,
    pub parallelism: usize,
}

/// 打印摘要头部数字行。
pub fn print_summary_header(params: SummaryHeaderParams) {
    let SummaryHeaderParams {
        total,
        succeeded,
        failed,
        cancelled,
        timeout,
        dep_skipped,
        recovered,
        wall_time,
        rounds,
        parallelism,
    } = params;
    let failed_total = failed + cancelled + timeout;
    let pct = |n: usize| {
        if total == 0 {
            0.0
        } else {
            n as f32 * 100.0 / total as f32
        }
    };
    println!(
        "Total: {}    Succeeded: {} ({:.1}%)    Failed: {} ({:.1}%)    Skipped: {} ({:.1}%)",
        total,
        succeeded,
        pct(succeeded),
        failed_total,
        pct(failed_total),
        dep_skipped,
        pct(dep_skipped)
    );
    let secs = wall_time.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    println!(
        "Wall time: {}h {}m {}s    Rounds: {}    Parallelism: {}    Recovered: {}",
        h, m, s, rounds, parallelism, recovered
    );
}

/// 标记桶内 `count` 总和等于输入大小（用于 invariant 单测）。
#[cfg(test)]
pub(crate) fn total_count(buckets: &[FailureBucket]) -> usize {
    buckets.iter().map(|b| b.count).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// 构造一个走 `Io` 变体的错误（`code = "io_error"`），detail 透传。
    /// 对应 `phase.rs:140` `CrbsError::io_message(...)` 的实际形态。
    fn make_io_err(detail: &str) -> CrbsError {
        CrbsError::io_message(detail.to_string())
    }

    fn make_timeout_err() -> CrbsError {
        CrbsError::Timeout
    }

    fn make_sign_err() -> CrbsError {
        CrbsError::SignFailed {
            message: "GPG signing failed".to_string(),
        }
    }

    fn make_network_err() -> CrbsError {
        CrbsError::Network {
            message: "connection timeout".to_string(),
        }
    }

    fn srpm_path(name: &str) -> PathBuf {
        PathBuf::from(format!("/path/to/{}.src.rpm", name))
    }

    // --- ScriptPhase::from_error -----------------------------------------

    #[test]
    fn script_phase_classifies_install_deps() {
        let err = make_io_err("io error: script /crbs-reproduce-deps.sh failed: exit_code=Some(1)");
        assert_eq!(ScriptPhase::from_error(&err), ScriptPhase::InstallDeps);
    }

    #[test]
    fn script_phase_classifies_build_phase() {
        let err =
            make_io_err("io error: script /crbs-reproduce-build.sh failed: exit_code=Some(2)");
        assert_eq!(ScriptPhase::from_error(&err), ScriptPhase::Build);
    }

    #[test]
    fn script_phase_classifies_sign_via_code() {
        // code 优先于 detail 路径
        let err = make_sign_err();
        assert_eq!(ScriptPhase::from_error(&err), ScriptPhase::Sign);
    }

    #[test]
    fn script_phase_classifies_sign_via_path() {
        let err = make_io_err("io error: script /crbs-sign.sh failed: exit_code=Some(1)");
        assert_eq!(ScriptPhase::from_error(&err), ScriptPhase::Sign);
    }

    #[test]
    fn script_phase_classifies_network_via_code() {
        let err = make_network_err();
        assert_eq!(ScriptPhase::from_error(&err), ScriptPhase::NetworkSetup);
    }

    #[test]
    fn script_phase_classifies_timeout_as_unknown() {
        // Timeout 不带 phase 信息，归 Unknown
        let err = make_timeout_err();
        assert_eq!(ScriptPhase::from_error(&err), ScriptPhase::Unknown);
    }

    #[test]
    fn script_phase_classifies_regular_chain_as_unknown() {
        let err = make_io_err("io error: script /crbs-build.sh failed: exit_code=Some(1)");
        assert_eq!(ScriptPhase::from_error(&err), ScriptPhase::Unknown);
    }

    #[test]
    fn script_phase_classifies_install_deps_via_phase_segment() {
        let err = make_io_err(
            "io error: script /crbs-build.sh failed: exit_code=Some(1); phase=install-deps; reason=No match for argument: python3-devel",
        );
        assert_eq!(ScriptPhase::from_error(&err), ScriptPhase::InstallDeps);
    }

    #[test]
    fn script_phase_classifies_build_via_phase_segment() {
        let err = make_io_err(
            "io error: script /crbs-build.sh failed: exit_code=Some(1); phase=build; reason=RPM build errors",
        );
        assert_eq!(ScriptPhase::from_error(&err), ScriptPhase::Build);
    }

    #[test]
    fn script_phase_classifies_ccache_via_phase_segment() {
        let err = make_io_err(
            "io error: script /crbs-build.sh failed: exit_code=Some(127); phase=ccache-summary; reason=env: 'ccache': No such file or directory",
        );
        assert_eq!(ScriptPhase::from_error(&err), ScriptPhase::Ccache);

        let err = make_io_err(
            "io error: script /crbs-build.sh failed: exit_code=Some(127); phase=ccache-init; reason=env: 'ccache': No such file or directory",
        );
        assert_eq!(ScriptPhase::from_error(&err), ScriptPhase::Ccache);
    }

    #[test]
    fn script_phase_unknown_phase_segment_stays_unknown() {
        // phase 段无法映射 → Unknown
        let err = make_io_err(
            "io error: script /crbs-build.sh failed: exit_code=Some(1); phase=what-ever",
        );
        assert_eq!(ScriptPhase::from_error(&err), ScriptPhase::Unknown);
    }

    #[test]
    fn script_phase_as_str_is_stable() {
        // 锁定对外标签（JSON phase 字段值）；改字符串是 breaking change
        assert_eq!(ScriptPhase::InstallDeps.as_str(), "install-deps");
        assert_eq!(ScriptPhase::Build.as_str(), "build");
        assert_eq!(ScriptPhase::Sign.as_str(), "sign");
        assert_eq!(ScriptPhase::NetworkSetup.as_str(), "network-setup");
        assert_eq!(ScriptPhase::Ccache.as_str(), "ccache");
        assert_eq!(ScriptPhase::Unknown.as_str(), "unknown");
    }

    // --- group_failures --------------------------------------------------

    #[test]
    fn group_failures_buckets_by_code_and_phase() {
        let failed = vec![
            (
                srpm_path("foo-1.0-1"),
                make_io_err("io error: script /crbs-reproduce-deps.sh failed: exit_code=Some(1)"),
                10,
            ),
            (
                srpm_path("bar-2.0-1"),
                make_io_err("io error: script /crbs-reproduce-deps.sh failed: exit_code=Some(1)"),
                11,
            ),
            (
                srpm_path("baz-3.0-1"),
                make_io_err("io error: script /crbs-reproduce-build.sh failed: exit_code=Some(2)"),
                12,
            ),
            (srpm_path("qux-4.0-1"), make_timeout_err(), 1800),
        ];
        let buckets = group_failures(&failed, &[], &[]);
        assert_eq!(
            buckets.len(),
            3,
            "expected (io_error+InstallDeps), (io_error+Build), (timeout+Unknown)"
        );

        // HashMap 顺序不定，只断言 count=2 桶排第一
        assert_eq!(buckets[0].count, 2);
        assert_eq!(buckets[0].code, "io_error");
        assert_eq!(buckets[0].phase, ScriptPhase::InstallDeps);
        assert!(buckets[0].sample_message.contains("crbs-reproduce-deps.sh"));
    }

    #[test]
    fn group_failures_buckets_ccache_phase_for_hint() {
        // print_failures_by_phase 为 println! 直出无法断言，只验分类并冒烟调用。
        let failed = vec![(
            srpm_path("glucose-5.0-1"),
            make_io_err(
                "io error: script /crbs-build.sh failed: exit_code=Some(127); phase=ccache-summary; reason=env: 'ccache': No such file or directory",
            ),
            1,
        )];
        let buckets = group_failures(&failed, &[], &[]);
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].phase, ScriptPhase::Ccache);
        assert_eq!(buckets[0].code, "io_error");
        print_failures_by_phase(&buckets, 20);
    }

    #[test]
    fn group_failures_merges_failed_cancelled_timeout() {
        let failed = vec![(srpm_path("f"), make_io_err("io error: a"), 1)];
        let cancelled = vec![(srpm_path("c"), make_io_err("io error: a"), 1)];
        let timeout = vec![(srpm_path("t"), make_io_err("io error: a"), 1)];
        let buckets = group_failures(&failed, &cancelled, &timeout);
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].count, 3, "failed+cancelled+timeout 合并到同一桶");
        assert_eq!(total_count(&buckets), 3);
    }

    #[test]
    fn group_failures_mode_picks_most_frequent_message() {
        let mut failed = Vec::new();
        for name in ["a", "b", "c"] {
            failed.push((
                srpm_path(name),
                make_io_err("io error: message A — dominant"),
                1,
            ));
        }
        for name in ["d", "e"] {
            failed.push((
                srpm_path(name),
                make_io_err("io error: message B — minority"),
                1,
            ));
        }
        let buckets = group_failures(&failed, &[], &[]);
        assert_eq!(buckets.len(), 1);
        assert!(buckets[0].sample_message.contains("message A"));
        assert!(!buckets[0].sample_message.contains("message B"));
    }

    #[test]
    fn group_failures_caps_sample_packages_at_three() {
        let failed: Vec<_> = (0..5)
            .map(|i| {
                (
                    srpm_path(&format!("pkg-{}-1", i)),
                    make_io_err("io error: same"),
                    1,
                )
            })
            .collect();
        let buckets = group_failures(&failed, &[], &[]);
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].sample_packages.len(), 3);
    }

    #[test]
    fn group_failures_sorts_by_count_desc() {
        let mut failed = Vec::new();
        for i in 0..3 {
            failed.push((
                srpm_path(&format!("a-{}", i)),
                make_io_err("io error: same A"),
                1,
            ));
        }
        failed.push((srpm_path("b-1"), make_timeout_err(), 1));
        let buckets = group_failures(&failed, &[], &[]);
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].count, 3);
        assert_eq!(buckets[1].count, 1);
    }

    #[test]
    fn group_failures_empty_inputs_yield_empty_buckets() {
        let buckets = group_failures(&[], &[], &[]);
        assert!(buckets.is_empty());
    }

    // --- extract_pkg_name ------------------------------------------------

    #[test]
    fn extract_pkg_name_strips_src_rpm_suffix() {
        assert_eq!(
            extract_pkg_name(Path::new("/a/foo-1.0-1.src.rpm")),
            "foo-1.0-1"
        );
        assert_eq!(extract_pkg_name(Path::new("bar-2.0.src.rpm")), "bar-2.0");
    }

    // --- truncate --------------------------------------------------------

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_string_adds_ellipsis() {
        let s = "x".repeat(200);
        let out = truncate(&s, 80);
        // 80 个 'x' + '…' = 81 字符
        assert_eq!(out.chars().count(), 81);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn truncate_exact_boundary_keeps_all() {
        let s = "x".repeat(80);
        let out = truncate(&s, 80);
        assert_eq!(out.chars().count(), 80);
        assert!(!out.ends_with('…'));
    }

    // --- summary_truncation / --summary-limit 0 ---------------------------

    #[test]
    fn summary_truncation_limit_zero_means_full() {
        // CLI 承诺 "0 = no truncation"：0 不得当截断值透传。
        assert_eq!(summary_truncation(30, 0, false), (30, true));
        assert_eq!(summary_truncation(1, 0, false), (1, true));
    }

    #[test]
    fn summary_truncation_nonzero_limit_and_full_flag() {
        assert_eq!(summary_truncation(30, 20, false), (20, false));
        // total < limit：full=false 但无 more 尾注。
        assert_eq!(summary_truncation(5, 20, false), (5, false));
        assert_eq!(summary_truncation(30, 20, true), (30, true));
    }
}
