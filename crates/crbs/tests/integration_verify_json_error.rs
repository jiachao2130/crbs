// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs verify --format json` 失败路径进程契约：stdout 恰好一个 JSON 文档——
//! dispatch 命令臂对 handle_verify 逃逸的错误补 maybe_json_error_exit 信封。
//! 触发：沙箱化 crbs_root + 不存在 task id → NotFound；断言同 integration_chain_json_error.rs。

use assert_cmd::Command;

mod common;

use common::sandbox;

#[test]
fn verify_json_task_not_found_prints_exactly_one_envelope() {
    let tmp = sandbox();

    let output = Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args(["verify", "999999", "--format", "json"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "task-not-found must exit non-zero"
    );
    assert_eq!(
        output.status.code(),
        Some(crbs_core::exit_code::USAGE),
        "NotFound must map to USAGE=4"
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    // from_str 对"多个文档 / 尾随垃圾"整体解析失败，解析成功即恰好一个 JSON 文档。
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be exactly one JSON document: {e}\n{stdout}"));

    assert_eq!(
        envelope["command"].as_str(),
        Some("verify"),
        "envelope must carry the actual command name: {stdout}"
    );
    assert_eq!(
        envelope["outcome"].as_str(),
        Some("error"),
        "error envelope outcome must be \"error\": {stdout}"
    );
    assert_eq!(
        envelope["error"]["code"].as_str(),
        Some("not_found"),
        "task-not-found must map to the NotFound variant code: {stdout}"
    );
    assert!(
        envelope["error"]["message"].as_str().is_some(),
        "envelope must carry error.message: {stdout}"
    );

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains("Error:") && !stderr.contains("hint:"),
        "SilentExit must suppress main's Error/hint lines: {stderr}"
    );
}
