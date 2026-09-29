// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! JSON 错误信封族契约：所有支持 `--format json` 的命令失败时 stdout 恰好一个 JSON 信封、
//! stderr 无 Error/hint 行。断言与 integration_verify_json_error.rs 同款；信封由
//! dispatch::run 单一收口点按 `Cli::json_error_contract` 的 (命令名, format) 补齐，
//! 全族矩阵由 cli/mod.rs `json_error_contract_covers_every_format_json_command`
//! 单测覆盖；`CRBS_CONFIG_DIR`+`HOME` 指向临时目录，用户级 `remote.default` 不影响失败路径。

// 测试辅助函数不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Output;

use assert_cmd::Command;
use tempfile::TempDir;

mod common;

use common::sandbox;

fn crbs_command(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("crbs").unwrap();
    cmd.env("CRBS_CONFIG_DIR", tmp.path())
        // 沙箱化 HOME：配置合并会读 ~/.config/crbs/crbs.toml 的 remote 段。
        .env("HOME", tmp.path());
    cmd
}

/// 信封族共用断言：非零退出 + 退出码语义 + stdout 单信封（command/outcome/error.code/error.message）+ stderr 干净。
fn assert_single_error_envelope(
    output: &Output,
    expected_command: &str,
    expected_code: &str,
    expected_exit: i32,
) {
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();

    assert!(
        !output.status.success(),
        "must exit non-zero (stderr: {stderr})"
    );
    assert_eq!(
        output.status.code(),
        Some(expected_exit),
        "unexpected exit code (stderr: {stderr})"
    );

    // serde_json::from_str 对多文档/尾随垃圾整体解析失败——解析成功即 stdout 恰好一个 JSON 文档。
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be exactly one JSON document: {e}\n{stdout}"));
    assert_eq!(
        envelope["command"].as_str(),
        Some(expected_command),
        "envelope must carry the actual command name: {stdout}"
    );
    assert_eq!(
        envelope["outcome"].as_str(),
        Some("error"),
        "error envelope outcome must be \"error\": {stdout}"
    );
    assert_eq!(
        envelope["error"]["code"].as_str(),
        Some(expected_code),
        "unexpected error.code: {stdout}"
    );
    assert!(
        envelope["error"]["message"].as_str().is_some(),
        "envelope must carry error.message: {stdout}"
    );

    assert!(
        !stderr.contains("Error:") && !stderr.contains("hint:"),
        "SilentExit must suppress main's Error/hint lines: {stderr}"
    );
}

/// 本地只读族代表：status 的 task NotFound → USAGE=4 信封。
#[test]
fn status_json_task_not_found_prints_exactly_one_envelope() {
    let tmp = sandbox();
    let output = crbs_command(&tmp)
        .args(["status", "999999", "--format", "json", "--local"])
        .output()
        .unwrap();
    assert_single_error_envelope(&output, "status", "not_found", crbs_core::exit_code::USAGE);
}

/// logs：本地路径 task NotFound → USAGE=4 信封。
#[test]
fn logs_json_task_not_found_prints_exactly_one_envelope() {
    let tmp = sandbox();
    let output = crbs_command(&tmp)
        .args(["logs", "999999", "--format", "json", "--local"])
        .output()
        .unwrap();
    assert_single_error_envelope(&output, "logs", "not_found", crbs_core::exit_code::USAGE);
}

/// cancel：本地 task NotFound（破坏性子命令同样入信封族）。
#[test]
fn cancel_json_task_not_found_prints_exactly_one_envelope() {
    let tmp = sandbox();
    let output = crbs_command(&tmp)
        .args(["cancel", "999999", "--format", "json", "--local"])
        .output()
        .unwrap();
    assert_single_error_envelope(&output, "cancel", "not_found", crbs_core::exit_code::USAGE);
}

/// builds show：build 域 NotFound；`--local`/`--remote` 挂父命令，须置于子命令之前。
#[test]
fn builds_show_json_not_found_prints_exactly_one_envelope() {
    let tmp = sandbox();
    let output = crbs_command(&tmp)
        .args(["builds", "--local", "show", "999999", "--format", "json"])
        .output()
        .unwrap();
    assert_single_error_envelope(
        &output,
        "builds show",
        "not_found",
        crbs_core::exit_code::USAGE,
    );
}

/// debug：StateStore 在 handler 内打开（不经 dispatch 建库块）仍被收口点罩住；ID 为 build 域。
#[test]
fn debug_json_not_found_prints_exactly_one_envelope() {
    let tmp = sandbox();
    let output = crbs_command(&tmp)
        .args(["debug", "999999", "--format", "json"])
        .output()
        .unwrap();
    assert_single_error_envelope(&output, "debug", "not_found", crbs_core::exit_code::USAGE);
}

/// builds publish 远程不可达：关死端口重试耗尽 → Network（ENVIRONMENT=6），command 带全路径。
#[test]
fn builds_publish_json_remote_unreachable_prints_exactly_one_envelope() {
    let tmp = sandbox();
    let output = crbs_command(&tmp)
        .args([
            "builds",
            "--remote",
            "http://127.0.0.1:1",
            "publish",
            "999999",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_single_error_envelope(
        &output,
        "builds publish",
        "network_error",
        crbs_core::exit_code::ENVIRONMENT,
    );
}

/// products delete 无远程目标：ValidationFailed → USAGE=4；全族共用父级 ("products", format) 契约。
#[test]
fn products_delete_json_without_remote_prints_exactly_one_envelope() {
    let tmp = sandbox();
    let output = crbs_command(&tmp)
        .args(["products", "delete", "no-such-product", "--format", "json"])
        .output()
        .unwrap();
    assert_single_error_envelope(
        &output,
        "products",
        "validation_failed",
        crbs_core::exit_code::USAGE,
    );
}

/// nihao（连通性探测族代表；ping/whoami 同 handler 同契约）：缺目标 → ValidationFailed。
#[test]
fn nihao_json_without_target_prints_exactly_one_envelope() {
    let tmp = sandbox();
    let output = crbs_command(&tmp)
        .args(["nihao", "--format", "json"])
        .output()
        .unwrap();
    assert_single_error_envelope(
        &output,
        "nihao",
        "validation_failed",
        crbs_core::exit_code::USAGE,
    );
}

/// admin 子命令组：admin init 缺远程目标 → ValidationFailed。
#[test]
fn admin_init_json_without_remote_prints_exactly_one_envelope() {
    let tmp = sandbox();
    let output = crbs_command(&tmp)
        .args(["admin", "init", "cc9", "--all", "--yes", "--format", "json"])
        .output()
        .unwrap();
    assert_single_error_envelope(
        &output,
        "admin init",
        "validation_failed",
        crbs_core::exit_code::USAGE,
    );
}

/// admin resource-profile 组：缺远程目标 → ValidationFailed（信封命令名带子命令）。
#[test]
fn admin_resource_profile_json_without_remote_prints_exactly_one_envelope() {
    let tmp = sandbox();
    let output = crbs_command(&tmp)
        .args([
            "admin",
            "resource-profile",
            "list",
            "--product",
            "cc9",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_single_error_envelope(
        &output,
        "admin resource-profile list",
        "validation_failed",
        crbs_core::exit_code::USAGE,
    );
}
