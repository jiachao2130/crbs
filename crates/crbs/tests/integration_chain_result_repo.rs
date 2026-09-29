// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INDUSTRY,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs build --chain` 的 `--result-repo` / `--no-result-repo` 集成测试：
//! 只做 help 可见性回归。旗标语义：注入默认开启（`--result-repo` default
//! true），`--no-result-repo` 显式关闭，`overrides_with` 互覆盖、命令行后传
//! 者赢，解析语义由 `crates/crbs/src/cli/mod.rs` 的 `cli::tests` 单测覆盖。
//!
//! 注入有两道防冲突闸门：精准注入只灌批次内被其他包 BuildRequires 的成功
//! RPM（防全量注入引发 EVR 冲突）；dist 校验（chain 提交前抽样比对标签）
//! 跳过错标签包，防本地产物覆盖上游同名包。
//! 关闭注入时仍维护 `/var/lib/crbs/repo/{product}/`（成功 RPM 软链接 +
//! repodata），只是不写 chroot 的 crbs-local.repo。真实注入链路
//! （`MountOptions.local_repo` 决定是否写 crbs-local.repo）由单测与部署
//! 环境 E2E 覆盖，本文件不 fork `crbs build` 实测（需 root + base_os + 容器）。

use assert_cmd::Command;
use predicates::prelude::*;

/// `crbs build -h` 必须列出 `--result-repo` 与 `--no-result-repo`（用户发现"关闭本地仓库"开关的唯一渠道）。
#[test]
fn help_build_shows_result_repo() {
    Command::cargo_bin("crbs")
        .unwrap()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("--result-repo")
                .and(predicate::str::contains("--no-result-repo")),
        );
}

/// help 文本里必须显式说"default ON"——精准注入后默认安全开启。
#[test]
fn help_text_documents_default_on() {
    Command::cargo_bin("crbs")
        .unwrap()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("default ON").or(predicate::str::contains("default on")));
}

/// help 文本里必须提到精准注入（只灌被依赖的包）。
#[test]
fn chain_help_documents_precise_injection() {
    Command::cargo_bin("crbs")
        .unwrap()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("BuildRequires")
                .or(predicate::str::contains("precise"))
                .or(predicate::str::contains("injected")),
        );
}
