// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! CLI `products` 子命令（publish / unpublish / transfer / acl / clean）端到端集成测试。
//!
//! 这些测试用 wiremock 模拟 hub，只验证 CLI 发出的 HTTP 请求体/路径/方法以及
//! 对响应的解析。无需 Linux 特权或本地 crbs 组，不标 `#[ignore]`。

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;
use wiremock::matchers::{body_json, method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// 构造一个最小合法的 `ProductDetail` JSON，供 `GET /api/v1/products/{name}` 模拟返回。
fn product_detail_json(revision: i64) -> serde_json::Value {
    serde_json::json!({
        "product": "foo",
        "crbs_root": "/tmp/crbs",
        "result_dir": "/tmp/results",
        "base_packages": ["bash"],
        "repos": [],
        "rpm_macros": {},
        "backend": "mock",
        "network": false,
        "build_target": "x86_64",
        "shared_layer": false,
        "build_tmpfs": false,
        "ccache_enabled": false,
        "memory_max": null,
        "cpu_quota": null,
        "hooks": {
            "pre": {},
            "post": {},
            "spec_pre": {},
            "spec_post": {},
        },
        "id": 1,
        "revision": revision,
    })
}

/// 构造 `UpdateProductResponse` JSON，publish/unpublish/transfer 都返回此形状。
fn update_response_json() -> serde_json::Value {
    serde_json::json!({
        "revision": 6,
        "base_os_revision": 4,
        "base_os_bumped": false,
    })
}

// -- always-run: CLI 参数解析 / --help ----------------------------------------

#[test]
fn help_products_shows_p3_commands() {
    Command::cargo_bin("crbs")
        .unwrap()
        .args(["products", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("publish")
                .and(predicate::str::contains("unpublish"))
                .and(predicate::str::contains("transfer"))
                .and(predicate::str::contains("acl")),
        );
}

// -- publish / unpublish / transfer -----------------------------------------

#[tokio::test]
async fn publish_sends_visibility_and_expected_revision() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wm_path("/api/v1/products/foo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(product_detail_json(5)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(wm_path("/api/v1/products/foo/visibility"))
        .and(body_json(serde_json::json!({
            "visibility": "public",
            "reason": null,
            "expected_revision": 5,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(update_response_json()))
        .mount(&server)
        .await;

    let tmp = TempDir::new().unwrap();
    Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args(["products", "publish", "foo", "--remote", &server.uri()])
        .assert()
        .success()
        .stdout(predicate::str::contains("updated revision=6"));
}

#[tokio::test]
async fn unpublish_sends_private_and_reason() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wm_path("/api/v1/products/foo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(product_detail_json(5)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(wm_path("/api/v1/products/foo/visibility"))
        .and(body_json(serde_json::json!({
            "visibility": "private",
            "reason": "going private",
            "expected_revision": 5,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(update_response_json()))
        .mount(&server)
        .await;

    let tmp = TempDir::new().unwrap();
    Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args([
            "products",
            "unpublish",
            "foo",
            "--reason",
            "going private",
            "--remote",
            &server.uri(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("updated revision=6"));
}

#[tokio::test]
async fn transfer_sends_new_owner_and_expected_revision() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wm_path("/api/v1/products/foo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(product_detail_json(5)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(wm_path("/api/v1/products/foo/transfer"))
        .and(body_json(serde_json::json!({
            "new_owner_username": "bar",
            "reason": null,
            "expected_revision": 5,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(update_response_json()))
        .mount(&server)
        .await;

    let tmp = TempDir::new().unwrap();
    Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args([
            "products",
            "transfer",
            "foo",
            "bar",
            "--remote",
            &server.uri(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("updated revision=6"));
}

// -- ACL ---------------------------------------------------------------------

/// `products publish --format json` 的成功信封——透传服务端
/// UpdateProductResponse 平铺加 `command:"products"`（与 json_error_contract
/// 同源），响应 schema（revision 等）原样保留。
#[tokio::test]
async fn publish_json_envelope_merges_command_into_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wm_path("/api/v1/products/foo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(product_detail_json(5)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(wm_path("/api/v1/products/foo/visibility"))
        .respond_with(ResponseTemplate::new(200).set_body_json(update_response_json()))
        .mount(&server)
        .await;

    let tmp = TempDir::new().unwrap();
    let output = Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args([
            "products",
            "publish",
            "foo",
            "--format",
            "json",
            "--remote",
            &server.uri(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be a single JSON document ({e}): {stdout:?}"));
    assert_eq!(parsed["command"], "products", "envelope command: {stdout}");
    assert_eq!(parsed["revision"], 6);
    assert_eq!(parsed["base_os_revision"], 4);
    assert_eq!(parsed["base_os_bumped"], false);

    // 空列表同包装：无远程 target 时本地 products 目录为空 → {command, products: []}。
    let output = Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args(["products", "--format", "json", "--local"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be a single JSON document ({e}): {stdout:?}"));
    assert_eq!(parsed["command"], "products", "envelope command: {stdout}");
    assert_eq!(
        parsed["products"].as_array().map(|a| a.len()),
        Some(0),
        "empty list stays wrapped: {stdout}"
    );
}

#[tokio::test]
async fn acl_list_gets_acl_entries() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wm_path("/api/v1/products/foo/acl"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                "user_id": 2,
                "username": "bar",
                "role": "builder",
                "created_at": "2026-01-01T00:00:00Z",
            }])),
        )
        .mount(&server)
        .await;

    let tmp = TempDir::new().unwrap();
    Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args(["products", "acl", "list", "foo", "--remote", &server.uri()])
        .assert()
        .success()
        .stdout(predicate::str::contains("bar").and(predicate::str::contains("builder")));
}

#[tokio::test]
async fn acl_grant_posts_role() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(wm_path("/api/v1/products/foo/acl"))
        .and(body_json(serde_json::json!({
            "username": "bar",
            "role": "builder",
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let tmp = TempDir::new().unwrap();
    Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args([
            "products",
            "acl",
            "grant",
            "foo",
            "bar",
            "--role",
            "builder",
            "--remote",
            &server.uri(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Granted builder access to 'foo' for user 'bar'",
        ));
}

#[tokio::test]
async fn acl_revoke_deletes_with_username() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(wm_path("/api/v1/products/foo/acl"))
        .and(body_json(serde_json::json!({
            "username": "bar",
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let tmp = TempDir::new().unwrap();
    Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args([
            "products",
            "acl",
            "revoke",
            "foo",
            "bar",
            "--remote",
            &server.uri(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Revoked access to 'foo' from user 'bar'",
        ));
}

// -- clean --------------------------------------------------------------------

/// 服务端 `POST /api/v1/products/{name}/clean` 的 202 响应形状。
fn clean_response_json() -> serde_json::Value {
    serde_json::json!({
        "task_id": "6f1e2b3a-0000-4000-8000-000000000001",
        "status": "running",
        "product": "foo",
        "op": "clean",
    })
}

/// `products clean --yes`：POST 到 clean 端点，text 输出回显接受的 clean 任务。
#[tokio::test]
async fn clean_posts_to_clean_endpoint_with_yes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(wm_path("/api/v1/products/foo/clean"))
        .respond_with(ResponseTemplate::new(202).set_body_json(clean_response_json()))
        .mount(&server)
        .await;

    let tmp = TempDir::new().unwrap();
    Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args([
            "products",
            "clean",
            "foo",
            "--yes",
            "--remote",
            &server.uri(),
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("clean task")
                .and(predicate::str::contains("accepted"))
                .and(predicate::str::contains("status: running")),
        );
}

/// `products clean --format json` 成功信封：响应体平铺加 `command:"products"`
/// （与 json_error_contract 同源），task_id 等字段原样保留。
#[tokio::test]
async fn clean_json_envelope_merges_command_into_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(wm_path("/api/v1/products/foo/clean"))
        .respond_with(ResponseTemplate::new(202).set_body_json(clean_response_json()))
        .mount(&server)
        .await;

    let tmp = TempDir::new().unwrap();
    let output = Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args([
            "products",
            "clean",
            "foo",
            "--yes",
            "--format",
            "json",
            "--remote",
            &server.uri(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be a single JSON document ({e}): {stdout:?}"));
    assert_eq!(parsed["command"], "products", "envelope command: {stdout}");
    assert_eq!(parsed["task_id"], clean_response_json()["task_id"]);
    assert_eq!(parsed["status"], "running");
    assert_eq!(parsed["op"], "clean");
}

/// 确认门对齐 `crbs clean`：非 TTY 且无 --yes 必须在任何 HTTP 请求前拒绝
/// （USAGE=4）。mock 不挂 clean 端点：若误发请求会得 404 → "not found"
/// 文案，退出码同为 4——以 stderr 含 TTY 拒绝文案排除该假阳性。
#[tokio::test]
async fn clean_without_yes_refuses_in_non_tty() {
    let server = MockServer::start().await;

    let tmp = TempDir::new().unwrap();
    let output = Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args(["products", "clean", "foo", "--remote", &server.uri()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4), "USAGE=4 expected");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("stdin is not a TTY"),
        "expected non-TTY refusal: {stderr}"
    );
}

/// 404 对齐 products 家族其他子命令：`product '<name>' not found`（USAGE=4）。
#[tokio::test]
async fn clean_maps_404_to_not_found_message() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(wm_path("/api/v1/products/no-such/clean"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;

    let tmp = TempDir::new().unwrap();
    Command::cargo_bin("crbs")
        .unwrap()
        .env("CRBS_CONFIG_DIR", tmp.path())
        .args([
            "products",
            "clean",
            "no-such",
            "--yes",
            "--remote",
            &server.uri(),
        ])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("product 'no-such' not found"));
}
