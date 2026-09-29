// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 提交期架构预裁决：spec 约束与 noarch 收敛的纯函数矩阵。

use super::*;

use crbs_core::engine::depsolve::ArchConstraints;

fn exc(list: &[&str]) -> ArchConstraints {
    ArchConstraints {
        exclusive: list.iter().map(|s| s.to_string()).collect(),
        exclude: Vec::new(),
    }
}

fn excl(list: &[&str]) -> ArchConstraints {
    ArchConstraints {
        exclusive: Vec::new(),
        exclude: list.iter().map(|s| s.to_string()).collect(),
    }
}

const NOARCH: &str = "noarch";

#[test]
fn plan_no_constraints_keeps_everything_and_collapse() {
    let p = plan_srpm_arches(
        "pkg",
        NOARCH,
        &ArchConstraints::default(),
        &["x86_64".into()],
        true,
        true,
        false,
    )
    .unwrap();
    assert_eq!(p.arches, vec!["x86_64"]);
    assert!(p.collapse);
    assert!(p.skipped.is_empty());
    // 探测失败（空 arch）同样保守放行、不收敛。
    let p = plan_srpm_arches(
        "pkg",
        "",
        &exc(&["x86_64"]),
        &["aarch64".into()],
        true,
        true,
        false,
    )
    .unwrap();
    assert_eq!(p.arches, vec!["aarch64"]);
    assert!(!p.collapse);
}

#[test]
fn plan_concrete_partial_explicit_rejects_without_flag() {
    // ExcludeArch: x86_64；显式请求 [x86_64, aarch64] → 拒绝并点名。
    let err = plan_srpm_arches(
        "hello-excl",
        "x86_64",
        &excl(&["x86_64"]),
        &["x86_64".into(), "aarch64".into()],
        false,
        true,
        false,
    )
    .unwrap_err();
    assert!(err.contains("hello-excl"), "must name pkg: {err}");
    assert!(err.contains("x86_64"), "must name arch: {err}");
    assert!(err.contains("ExcludeArch"), "must name constraint: {err}");
    assert!(
        err.contains("--skip-unsupported-arches"),
        "must hint flag: {err}"
    );
}

#[test]
fn plan_concrete_partial_explicit_skip_flag_skips() {
    let p = plan_srpm_arches(
        "hello-excl",
        "x86_64",
        &excl(&["x86_64"]),
        &["x86_64".into(), "aarch64".into()],
        false,
        true,
        true,
    )
    .unwrap();
    assert_eq!(p.arches, vec!["aarch64"]);
    assert_eq!(p.skipped.len(), 1);
    assert!(p.skipped[0].1.contains("ExcludeArch"));
}

#[test]
fn plan_concrete_partial_product_default_skips_silently_authorized() {
    // 产品默认 fan-out（非显式）：部分不兼容 → 跳过，不拒绝。
    let p = plan_srpm_arches(
        "hello-dual",
        "x86_64",
        &exc(&["x86_64", "aarch64"]),
        &["x86_64".into(), "aarch64".into(), "riscv64".into()],
        false,
        false,
        false,
    )
    .unwrap();
    assert_eq!(p.arches, vec!["x86_64", "aarch64"]);
    assert_eq!(p.skipped[0].0, "riscv64");
    assert!(p.skipped[0].1.contains("ExclusiveArch"));
}

#[test]
fn plan_concrete_all_incompatible_rejects_even_product_default() {
    // 剔除后无事可做：显式/默认都拒绝（不产空任务）。
    let err = plan_srpm_arches(
        "hello-exc",
        "x86_64",
        &exc(&["aarch64"]),
        &["x86_64".into()],
        false,
        false,
        true,
    )
    .unwrap_err();
    assert!(
        err.contains("no requested architecture is buildable"),
        "{err}"
    );
}

#[test]
fn plan_concrete_excludearch_exact_match_keeps_variant() {
    // ExcludeArch: x86_64 对 target x86_64_v3 放行（逐字精确匹配，
    // rpm 4.18.2 实测：未被字面排除，产物 arch 字面 x86_64_v3）。
    let p = plan_srpm_arches(
        "hello-excl-var",
        "x86_64_v3",
        &excl(&["x86_64"]),
        &["x86_64_v3".into()],
        false,
        true,
        true,
    )
    .unwrap();
    assert_eq!(p.arches, vec!["x86_64_v3"]);
    assert!(p.skipped.is_empty());
}

#[test]
fn plan_noarch_excludearch_disables_collapse_and_skips_host() {
    // noarch + ExcludeArch: [x86_64]：收敛宿主不可预知 → 关闭收敛，
    // 跳过 x86_64（宿主代理），其余架构每架构 noarch-target 子构建。
    let p = plan_srpm_arches(
        "hello-no-excl",
        NOARCH,
        &excl(&["x86_64"]),
        &["x86_64".into(), "aarch64".into()],
        true,
        false,
        false,
    )
    .unwrap();
    assert!(
        !p.collapse,
        "collapse must be disabled when a candidate host is excluded"
    );
    assert_eq!(p.arches, vec!["aarch64"]);
    assert_eq!(p.skipped.len(), 1);
}

#[test]
fn plan_noarch_excludearch_unmatched_still_disables_collapse() {
    // ExcludeArch 非空但未命中任何候选宿主：无跳过，收敛仍关闭（谓词是
    // "非空"而非"命中"——收敛构建可被任意 worker 领取、宿主不可预知）。
    let p = plan_srpm_arches(
        "hello-no-excl",
        NOARCH,
        &excl(&["ppc64le"]),
        &["x86_64".into(), "aarch64".into()],
        true,
        false,
        false,
    )
    .unwrap();
    assert!(
        !p.collapse,
        "collapse must be disabled when ExcludeArch is non-empty"
    );
    assert_eq!(p.arches, vec!["x86_64", "aarch64"]);
    assert!(p.skipped.is_empty());
}

#[test]
fn plan_noarch_exclusive_arch_is_exempt() {
    // ExclusiveArch 对 noarch target 豁免（含矛盾 spec，rpm 6.0.2 实测）。
    let p = plan_srpm_arches(
        "hello-contradict",
        NOARCH,
        &exc(&["x86_64"]),
        &["x86_64".into(), "aarch64".into()],
        true,
        false,
        false,
    )
    .unwrap();
    assert_eq!(p.arches, vec!["x86_64", "aarch64"]);
    assert!(p.collapse, "exempt noarch keeps collapse");
    assert!(p.skipped.is_empty());
}

#[test]
fn plan_concrete_exclusive_and_exclude_precedence() {
    // ExclusiveArch 非空且不含目标 → not included（即使 ExcludeArch 为空）。
    let p = plan_srpm_arches(
        "hello-exc",
        "x86_64",
        &exc(&["aarch64"]),
        &["x86_64".into(), "aarch64".into()],
        false,
        false,
        false,
    )
    .unwrap();
    assert_eq!(p.arches, vec!["aarch64"]);
    assert!(p.skipped[0].1.contains("not in ExclusiveArch"));
}
