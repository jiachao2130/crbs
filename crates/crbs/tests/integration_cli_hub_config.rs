// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! CLI ↔ hub `/api/v1/products/{name}/resolved` 端到端集成测试。
//!
//! 常跑档 = CLI 解析 / `--help` 旗标可见性（任何平台任何权限都必须过的回归门）；
//! `#[ignore]` 档 = 真 fork `crbs` 二进制 + hub-mock。Linux 非 root 且非 setuid
//! 且不在 `crbs` 组时 `setup_privileges` 在 dispatch 前 bail、拿不到
//! `config: ...` stderr 行；macOS 为 no-op（crbs-core/src/privilege 非 linux
//! 分支），本地 `cargo test -- --ignored` 直跑；Linux CI 需授 `crbs` 组或 setuid。
//!
//! init 与 clean 执行流同构（共享 `load_product_config` + `log_config_source`），
//! hub-mock 用例只在 clean 侧铺 5 条，等价覆盖 init 侧。

// 辅助函数（write_disk_product 等）不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;

// -- always-run：CLI 解析 / --help ----------------------------------------

/// 顶层 `--help` 可见全局 `--offline`（用户借此绕过 hub、用磁盘快照）。
#[test]
fn help_shows_global_offline_flag() {
    Command::cargo_bin("crbs")
        .unwrap()
        .args(["--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--offline"));
}

/// build `--help` 可见 `--ca-cert`（复用作 hub /resolved TLS）。
#[test]
fn help_build_shows_ca_cert() {
    Command::cargo_bin("crbs")
        .unwrap()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--ca-cert"));
}

/// init `--help` 可见 `--remote`/`--token`/`--ca-cert`。
#[test]
fn help_init_shows_hub_flags() {
    Command::cargo_bin("crbs")
        .unwrap()
        .args(["init", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("--remote")
                .and(predicate::str::contains("--token"))
                .and(predicate::str::contains("--ca-cert")),
        );
}

/// clean 同 init：hub 三件套。
#[test]
fn help_clean_shows_hub_flags() {
    Command::cargo_bin("crbs")
        .unwrap()
        .args(["clean", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("--remote")
                .and(predicate::str::contains("--token"))
                .and(predicate::str::contains("--ca-cert")),
        );
}

/// sign `--help` 可见 `--ca-cert`。
#[test]
fn help_sign_shows_ca_cert() {
    Command::cargo_bin("crbs")
        .unwrap()
        .args(["sign", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--ca-cert"));
}

/// `--offline` 须在子命令之前生效：锁死 clap `global = true` 不被误改成 per-subcommand。
#[test]
fn parse_offline_global_before_subcommand() {
    // 只验证解析不驱动执行：`completions` 子命令与 PrivMode 无关，打印 completions 即退出。
    Command::cargo_bin("crbs")
        .unwrap()
        .args(["--offline", "completions", "bash"])
        .assert()
        .success();
}

// -- #[ignore] 子进程 + wiremock ----------------------------------------

mod ignored {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use wiremock::matchers::{method, path as wm_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// 最小合法 product TOML：`base_packages`/`repos` 为 ProductConfig 必填，其余可选。
    const MIN_TOML: &str = "\
product = \"mydist\"
base_packages = [\"bash\"]
repos = []
";

    fn write_disk_product(config_dir: &std::path::Path, name: &str) {
        fs::create_dir_all(config_dir.join("products")).unwrap();
        fs::write(config_dir.join(format!("products/{}.toml", name)), MIN_TOML).unwrap();
    }

    #[test]
    #[ignore = "requires crbs group membership on Linux; run with --ignored"]
    fn clean_offline_logs_disk_source() {
        let tmp = TempDir::new().unwrap();
        write_disk_product(tmp.path(), "mydist");
        Command::cargo_bin("crbs")
            .unwrap()
            .env("CRBS_CONFIG_DIR", tmp.path())
            .args(["--offline", "clean", "mydist", "--yes"])
            .assert()
            // config 日志行先打、clean 随后才因 base_os 缺失/权限失败退出——允许非零退出，只断言 stderr。
            .stderr(predicate::str::contains(
                "config: disk (--offline) for product 'mydist'",
            ));
    }

    #[tokio::test]
    #[ignore = "requires crbs group membership on Linux; run with --ignored"]
    async fn clean_hub_200_logs_hub_source() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/mydist/resolved"))
            .respond_with(ResponseTemplate::new(200).set_body_string(MIN_TOML))
            .mount(&server)
            .await;

        let tmp = TempDir::new().unwrap();
        let url = server.uri();
        Command::cargo_bin("crbs")
            .unwrap()
            .env("CRBS_CONFIG_DIR", tmp.path())
            .args(["clean", "mydist", "--yes", "--remote", &url])
            .assert()
            .stderr(
                predicate::str::contains("config: hub (")
                    .and(predicate::str::contains("for product 'mydist'")),
            );
    }

    #[tokio::test]
    #[ignore = "requires crbs group membership on Linux; run with --ignored"]
    async fn clean_hub_404_dual_exit_message() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/mydist/resolved"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;

        let tmp = TempDir::new().unwrap();
        let url = server.uri();
        Command::cargo_bin("crbs")
            .unwrap()
            .env("CRBS_CONFIG_DIR", tmp.path())
            .args(["clean", "mydist", "--yes", "--remote", &url])
            .assert()
            .failure()
            .stderr(
                predicate::str::contains("crbs products create")
                    .and(predicate::str::contains("--offline")),
            );
    }

    #[tokio::test]
    #[ignore = "requires crbs group membership on Linux; run with --ignored"]
    async fn clean_hub_5xx_offline_hint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/mydist/resolved"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let tmp = TempDir::new().unwrap();
        let url = server.uri();
        Command::cargo_bin("crbs")
            .unwrap()
            .env("CRBS_CONFIG_DIR", tmp.path())
            .args(["clean", "mydist", "--yes", "--remote", &url])
            .assert()
            .failure()
            .stderr(predicate::str::contains("500").and(predicate::str::contains("Use --offline")));
    }

    /// hub 不可达 → `hub unreachable ... Use --offline`；fail-closed，不静默降级到磁盘。
    #[test]
    #[ignore = "requires crbs group membership on Linux; run with --ignored"]
    fn clean_hub_unreachable_bails_fail_closed() {
        let tmp = TempDir::new().unwrap();
        Command::cargo_bin("crbs")
            .unwrap()
            .env("CRBS_CONFIG_DIR", tmp.path())
            // 127.0.0.1:1 端口 1 保留，无法监听，reqwest 立刻 send() 失败。
            .args(["clean", "mydist", "--yes", "--remote", "http://127.0.0.1:1"])
            .assert()
            .failure()
            .stderr(
                predicate::str::contains("hub unreachable")
                    .and(predicate::str::contains("Use --offline")),
            );
    }
}
