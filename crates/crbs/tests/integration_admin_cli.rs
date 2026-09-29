// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! CLI `admin` 子命令端到端集成测试：wiremock 模拟 hub，无需本地特权。

use assert_cmd::Command;
use tempfile::TempDir;
use wiremock::matchers::{body_json, method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// `admin init --format json` 的 stdout 必须是单一 JSON 文档，目标列表与确认提示全走 stderr。
#[tokio::test]
async fn admin_init_json_stdout_is_single_json_document() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(wm_path("/api/v1/admin/workers/1/init"))
        .and(body_json(serde_json::json!({ "product": "cc9" })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "assignment_id": 7 })),
        )
        .mount(&server)
        .await;

    let tmp = TempDir::new().unwrap();
    let output = Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args([
            "admin",
            "init",
            "cc9",
            "-w",
            "1",
            "--yes",
            "--format",
            "json",
            "--remote",
            &server.uri(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "admin init should succeed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be a single JSON document ({e}): {stdout:?}"));
    assert_eq!(
        parsed["command"], "admin init",
        "envelope command: {stdout}"
    );
    assert_eq!(parsed["ok"], 1, "one dispatch should succeed: {stdout}");
    assert_eq!(parsed["err"], 0);
    assert_eq!(parsed["results"][0]["assignment_id"], 7);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("About to dispatch init"),
        "target list hint must go to stderr, got stderr: {stderr:?}"
    );
}

/// `admin resource-profile set`：PUT 请求体三维齐全（人类单位 CLI 侧换算 KB）。
#[tokio::test]
async fn admin_resource_profile_set_sends_declared_body() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(wm_path("/api/v1/resource-profiles/cc9/gcc/x86_64"))
        .and(body_json(serde_json::json!({
            "min_mem_kb": 4194304,
            "min_ncpu": 4,
            "min_disk_kb": null,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "product": "cc9",
            "source_name": "gcc",
            "arch": "x86_64",
            "declared_min_mem_kb": 4194304,
            "declared_min_ncpu": 4,
            "declared_min_disk_kb": null,
        })))
        .mount(&server)
        .await;

    let tmp = TempDir::new().unwrap();
    let output = Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args([
            "admin",
            "resource-profile",
            "set",
            "cc9",
            "gcc",
            "x86_64",
            "--min-mem",
            "4G",
            "--min-ncpu",
            "4",
            "--format",
            "json",
            "--remote",
            &server.uri(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "resource-profile set should succeed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be a single JSON document ({e}): {stdout:?}"));
    assert_eq!(parsed["command"], "admin resource-profile set");
    assert_eq!(parsed["min_mem"], "4G");
    assert_eq!(parsed["set"], true);
}

/// `admin resource-profile list`：服务端响应键是 `profiles`（行数组），CLI text
/// 逐行渲染、json 信封用 `resource_profiles` 与 export 文档键保持同构。
#[tokio::test]
async fn admin_resource_profile_list_reads_server_profiles_key() {
    let server = MockServer::start().await;
    let row = serde_json::json!({
        "product": "cc9",
        "source_name": "gcc",
        "arch": "x86_64",
        "declared_min_mem_kb": 4194304,
        "declared_min_ncpu": 4,
        "declared_min_disk_kb": null,
        "learned_samples": 3,
        "learned_ema_mem_kb": 2097152,
        "learned_max_mem_kb": 3145728,
        "learned_ema_tmpfs_kb": 1048576,
        "learned_max_tmpfs_kb": 2097152,
        "learned_ema_ncpu": 2.5,
        "learned_sample_ncpu": 8,
        "learned_censored": false,
    });
    Mock::given(method("GET"))
        .and(wm_path("/api/v1/resource-profiles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "product": "cc9",
            "total": 1,
            "profiles": [row],
        })))
        .mount(&server)
        .await;

    let tmp = TempDir::new().unwrap();
    let uri = server.uri();
    let run = |format: Option<&str>| {
        let mut args = vec![
            "admin",
            "resource-profile",
            "list",
            "--product",
            "cc9",
            "--remote",
            uri.as_str(),
        ];
        if let Some(f) = format {
            args.extend(["--format", f]);
        }
        Command::cargo_bin("crbs")
            .unwrap()
            .env("CRBS_CONFIG_DIR", tmp.path())
            .args(args)
            .output()
            .unwrap()
    };

    let text = run(None);
    assert!(
        text.status.success(),
        "list should succeed: {:?}",
        String::from_utf8_lossy(&text.stderr)
    );
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(
        stdout.contains("gcc") && stdout.contains("4194304K/4/-"),
        "text output must render the server row: {stdout:?}"
    );
    assert!(
        stdout.contains("2.5@8C"),
        "learned EMA with sample ncpu must render: {stdout:?}"
    );
    assert!(
        stdout.contains("1048576/2097152"),
        "tmpfs EMA/max column must render: {stdout:?}"
    );

    let json = run(Some("json"));
    assert!(
        json.status.success(),
        "list --format json should succeed: {:?}",
        String::from_utf8_lossy(&json.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&json.stdout)).unwrap();
    assert_eq!(parsed["command"], "admin resource-profile list");
    assert_eq!(parsed["total"], 1);
    assert_eq!(parsed["resource_profiles"][0]["source_name"], "gcc");
}

/// `admin resource-profile set` 缺全部三维 → USAGE 校验错误，不发请求。
#[tokio::test]
async fn admin_resource_profile_set_requires_at_least_one_dimension() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let output = Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args([
            "admin",
            "resource-profile",
            "set",
            "cc9",
            "gcc",
            "x86_64",
            "--remote",
            &server.uri(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success(), "set without floors must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("at least one of --min-mem"),
        "validation message must point at the flags: {stderr:?}"
    );
}

/// export → import 往返：import 按行逐条 PUT declared 三维（含 NULL 维）。
#[tokio::test]
async fn admin_resource_profile_export_import_roundtrip() {
    let server = MockServer::start().await;
    let row = serde_json::json!({
        "product": "cc9",
        "source_name": "gcc",
        "arch": "x86_64",
        "declared_min_mem_kb": 4194304,
        "declared_min_ncpu": null,
        "declared_min_disk_kb": null,
        "learned_samples": 5,
        "learned_sample_ncpu": 8,
    });
    Mock::given(method("GET"))
        .and(wm_path("/api/v1/resource-profiles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "product": "cc9",
            "total": 1,
            "profiles": [row],
        })))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(wm_path("/api/v1/resource-profiles/cc9/gcc/x86_64"))
        .and(body_json(serde_json::json!({
            "min_mem_kb": 8388608,
            "min_ncpu": null,
            "min_disk_kb": null,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(row))
        .mount(&server)
        .await;

    let tmp = TempDir::new().unwrap();
    let export_path = tmp.path().join("profiles.json");
    let output = Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args([
            "admin",
            "resource-profile",
            "export",
            "--product",
            "cc9",
            "--file",
            export_path.to_str().unwrap(),
            "--remote",
            &server.uri(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "export should succeed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    // export 文档携带样本数与末次样本核数上下文（@nC 归一依据）。
    let mut doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&export_path).unwrap()).unwrap();
    assert_eq!(doc["version"], 2);
    assert_eq!(doc["resource_profiles"][0]["learned_samples"], 5);
    assert_eq!(doc["resource_profiles"][0]["learned_sample_ncpu"], 8);

    // 修改导出文档后回灌（export → 修改 → import 往返一致）。
    doc["resource_profiles"][0]["declared_min_mem_kb"] = serde_json::json!(8388608);
    std::fs::write(
        &export_path,
        serde_json::to_string_pretty(&doc).unwrap() + "\n",
    )
    .unwrap();

    let output = Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args([
            "admin",
            "resource-profile",
            "import",
            "--file",
            export_path.to_str().unwrap(),
            "--format",
            "json",
            "--remote",
            &server.uri(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "import should succeed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be a single JSON document ({e}): {stdout:?}"));
    assert_eq!(parsed["command"], "admin resource-profile import");
    assert_eq!(parsed["imported"], 1);
}
