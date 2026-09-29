// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 回退面集成断言：chain JSON 模式必失败路径的真实进程契约——stdout 恰好一个
//! 非空 JSON 文档。沙箱化 `crbs_root`（临时目录，无需 root/容器/base_os）跑真实
//! `crbs build --chain --local` / `crbs init`，用确定性失败点（不存在的 SRPM、
//! 不可用的 crbs_root）验证非零退出、stdout 恰好一个 JSON 信封、stderr 无
//! `Error:`/`hint:` 泄漏；引擎前置全落临时目录，与机器全局状态无关。

use std::fs;

use assert_cmd::Command;
use tempfile::TempDir;

mod common;

use common::sandbox;

#[test]
fn chain_json_prepare_failure_prints_exactly_one_envelope() {
    let tmp = sandbox();

    let output = Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args([
            "build",
            "--chain",
            "--local",
            "/nonexistent-does-not-exist.src.rpm",
            "--format",
            "json",
            "--product",
            "json-envelope-test",
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "prepare failure must exit non-zero"
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.trim().is_empty(), "stdout must not be empty");

    // from_str 对尾随垃圾/多文档整体解析失败：成功 = 恰好一个 JSON 文档。
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be exactly one JSON document: {e}\n{stdout}"));

    assert_eq!(
        envelope["command"].as_str(),
        Some("build"),
        "envelope must carry the command field: {stdout}"
    );
    let code = envelope["error"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("envelope must carry error.code: {stdout}"));
    assert!(!code.is_empty(), "error.code must be non-empty: {stdout}");
    assert!(
        envelope["error"]["message"].as_str().is_some(),
        "envelope must carry error.message: {stdout}"
    );

    // 回退失效信号：错误裸透传 main 时 stdout 变空、stderr 出现 Error/hint 行。
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains("Error:") && !stderr.contains("hint:"),
        "SilentExit must suppress main's Error/hint lines: {stderr}"
    );
}

/// 引擎 init 阶段（dispatch 层加载全局配置 / open_for_engine 建库，早于
/// handle_build 信封兜底）失败的 JSON 契约：`crbs_root` 指向普通文件使建库
/// 确定性失败。断言非零退出（Io 变体码 ENVIRONMENT=6）、stdout 恰好一个
/// 文档（error.code=io_error）、stderr 无 Error/hint 行。
#[test]
fn chain_json_engine_init_failure_prints_exactly_one_envelope() {
    let tmp = TempDir::new().unwrap();
    let crbs_root = tmp.path().join("crbs-root-is-a-file");
    fs::write(&crbs_root, b"not a directory").unwrap();
    fs::write(
        tmp.path().join("crbs.toml"),
        format!("crbs_root = \"{}\"\n", crbs_root.display()),
    )
    .unwrap();

    let output = Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args([
            "build",
            "--chain",
            "--local",
            "/nonexistent-does-not-exist.src.rpm",
            "--format",
            "json",
            "--product",
            "json-envelope-test",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success(), "init failure must exit non-zero");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be exactly one JSON document: {e}\n{stdout}"));

    assert_eq!(envelope["command"].as_str(), Some("build"));
    let code = envelope["error"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("envelope must carry error.code: {stdout}"));
    assert_eq!(
        code, "io_error",
        "init-stage Io failure must map like the prepare-stage precedent: {stdout}"
    );

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains("Error:") && !stderr.contains("hint:"),
        "init failure must not leak to main's stderr Error/hint lines: {stderr}"
    );
}

/// `crbs init --format json` 的 engine/state 打开失败同契约：init 不在
/// `requires_state_store` 集，engine 打开发生在 handle_init 内部（new_from_config
/// 建库、ensure_cli_runtime_dirs 均先触 crbs_root），dispatch 命令臂的
/// maybe_json_error_exit 信封必须罩住它；`crbs_root` 指向普通文件使运行时
/// 目录创建确定性失败。
#[test]
fn init_json_engine_init_failure_prints_exactly_one_envelope() {
    let tmp = TempDir::new().unwrap();
    let crbs_root = tmp.path().join("crbs-root-is-a-file");
    fs::write(&crbs_root, b"not a directory").unwrap();
    fs::write(
        tmp.path().join("crbs.toml"),
        format!("crbs_root = \"{}\"\n", crbs_root.display()),
    )
    .unwrap();
    // 最小产品配置：让配置加载成功，失败点收敛在 crbs_root 不可用上。
    fs::create_dir_all(tmp.path().join("products")).unwrap();
    fs::write(
        tmp.path().join("products/json-envelope-test.toml"),
        "product = \"json-envelope-test\"\nbase_packages = [\"bash\"]\nrepos = []\n",
    )
    .unwrap();

    let output = Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        // 沙箱化 HOME：否则开发机 ~/.config/crbs/crbs.toml 的 remote 段
        //（load_merged_blocking）会让 init 转向 hub，失败点漂移。
        .env("HOME", tmp.path())
        .args(["init", "json-envelope-test", "--format", "json"])
        .output()
        .unwrap();

    assert!(!output.status.success(), "init failure must exit non-zero");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be exactly one JSON document: {e}\n{stdout}"));

    // 信封 schema：判别字段是 command（实际命令名），outcome 恒 "error"。
    assert_eq!(
        envelope["command"].as_str(),
        Some("init"),
        "envelope must carry the actual command name: {stdout}"
    );
    assert_eq!(
        envelope["outcome"].as_str(),
        Some("error"),
        "error envelope outcome must be \"error\": {stdout}"
    );
    let code = envelope["error"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("envelope must carry error.code: {stdout}"));
    assert_eq!(
        code, "io_error",
        "crbs_root unusable must map to the Io variant code: {stdout}"
    );

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains("Error:") && !stderr.contains("hint:"),
        "init failure must not leak to main's stderr Error/hint lines: {stderr}"
    );
}
