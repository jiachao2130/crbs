// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs status` 人类路径的 `--limit` 截断提示：表尾附 `showing N of M (use --limit 0 for all)`。

// 测试辅助函数（sandbox / seed_tasks）不带 #[test]，clippy.toml 的 tests 豁免覆盖不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use crbs_core::{StateStore, TaskInsert};

mod common;

use common::sandbox;

const TOTAL_TASKS: usize = 25;

/// 预插 25 条任务（limit 默认 20 → 必截断）。
async fn seed_tasks(crbs_root: &std::path::Path) {
    let store = StateStore::new(crbs_root).await.unwrap();
    for i in 0..TOTAL_TASKS {
        store
            .insert_task(TaskInsert {
                product: "fedora",
                pkg_name: &format!("pkg{i}"),
                user: "tester",
                phase: "succeeded",
                ..Default::default()
            })
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn status_human_truncation_hint_shows_counts() {
    let tmp = sandbox();
    seed_tasks(&tmp.path().join("engine-root")).await;

    let output = Command::cargo_bin("crbs")
        .unwrap()
        .args(["status", "--all"])
        .env("CRBS_CONFIG_DIR", tmp.path())
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("showing 20 of 25 (use --limit 0 for all)"),
        "stdout must carry the truncation hint: {stdout}"
    );

    let output = Command::cargo_bin("crbs")
        .unwrap()
        .args(["status", "--all", "--limit", "5"])
        .env("CRBS_CONFIG_DIR", tmp.path())
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("showing 5 of 25 (use --limit 0 for all)"),
        "stdout must carry the truncation hint: {stdout}"
    );

    let output = Command::cargo_bin("crbs")
        .unwrap()
        .args(["status", "--all", "--limit", "0"])
        .env("CRBS_CONFIG_DIR", tmp.path())
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        !stdout.contains("showing "),
        "full listing must not carry a truncation hint: {stdout}"
    );

    // JSON 路径 schema 不动：裸数组包成功信封 {command, tasks}（与错误信封同源），静默默认 limit=20。
    let output = Command::cargo_bin("crbs")
        .unwrap()
        .args(["status", "--all", "--format", "json"])
        .env("CRBS_CONFIG_DIR", tmp.path())
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        !stdout.contains("showing "),
        "JSON output must stay hint-free: {stdout}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be exactly one JSON document: {e}\n{stdout}"));
    assert_eq!(
        parsed["command"], "status",
        "success envelope must carry command: {stdout}"
    );
    let arr = parsed["tasks"]
        .as_array()
        .expect("status list JSON must wrap tasks in an array");
    assert_eq!(
        arr.len(),
        20,
        "JSON path keeps the silent default limit=20 behavior: {}",
        arr.len()
    );
}
