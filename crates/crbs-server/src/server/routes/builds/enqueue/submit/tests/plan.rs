// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 提交期架构预判定：spec 约束与 noarch 收敛的纯函数矩阵。

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
