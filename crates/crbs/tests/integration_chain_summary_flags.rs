// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INDUSTRY,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! PR-B: `crbs build --chain` 摘要重构 5 旗标的集成测试，聚焦 flag 的 help 可见性
//! 与解析共存；语义细节（默认 20、--list-failed 强制全量）由 `cli/mod.rs` 单测覆盖。

use assert_cmd::Command;
use predicates::prelude::*;

/// `--summary-limit` 必须出现在 `crbs build -h`，且默认 20。
#[test]
fn help_build_shows_summary_limit() {
    Command::cargo_bin("crbs")
        .unwrap()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--summary-limit"))
        .stdout(predicate::str::contains("20"));
}

/// `--list-failed` 必须出现。
#[test]
fn help_build_shows_list_failed() {
    Command::cargo_bin("crbs")
        .unwrap()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--list-failed"));
}

/// `--list-succeeded` 必须出现。
#[test]
fn help_build_shows_list_succeeded() {
    Command::cargo_bin("crbs")
        .unwrap()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--list-succeeded"));
}

/// `--concise` 必须出现；命名避开全局 `--quiet`（控 tracing 级别）。
#[test]
fn help_build_shows_concise() {
    Command::cargo_bin("crbs")
        .unwrap()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--concise"));
}

/// `--verbose-summary` 必须出现；命名避开全局 `--verbose`。
#[test]
fn help_build_shows_verbose_summary() {
    Command::cargo_bin("crbs")
        .unwrap()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--verbose-summary"));
}

/// `--concise` 与 `--verbose-summary` 功能互斥（单行 vs 全量列表），解析层允许共存。
/// 借 `--chain --local` product 已给、缺 SRPM 的 validation 失败路径验证解析成功（不实际执行）。
#[test]
fn chain_concise_and_verbose_summary_parsed() {
    Command::cargo_bin("crbs")
        .unwrap()
        .args([
            "build",
            "-p",
            "cc9",
            "--chain",
            "--local",
            "--concise",
            "--verbose-summary",
            "--summary-limit",
            "50",
            "--list-failed",
        ])
        .assert()
        // 非零退出必须来自域内失败（缺 SRPM / 建库路径），不是 clap 拒参——
        // clap 拒参同样非零退出且其错误码也是 4（与 USAGE 撞码），只能按 stderr 形态判别。
        .failure()
        .stderr(predicate::str::contains("unexpected argument").not());
}
