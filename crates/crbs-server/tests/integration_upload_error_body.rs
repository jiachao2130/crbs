// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2/
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 上传校验失败的错误响应完整性（curl 56 / 错误页截断回归）。
//!
//! 机制：multipart 校验失败若未吸干请求体即回 4xx，close 时 socket 仍有未读
//! 请求数据 → TCP RST 打断客户端写/读：curl 56、错误体截断（线上 content-length
//! 100676 实收 65035）。oneshot 进程内测试看不到该连接层行为，故起真实 TCP
//! 监听器 + 手写 HTTP/1.1 客户端，断言完整写出请求体、按 content-length 读回。

// 文件级放行：辅助函数不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::Body;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crbs_core::auth::secret::{Secret, SecretKind};
use crbs_core::config::ServerConfig;
use crbs_core::BuildInsert;
use crbs_server::server::state::AppState;
use tower::ServiceExt;

mod common;

use common::TEST_CONFIG_DIR;

/// 测试用上传上限 upload_max_size_mb=1（extract per-file 校验在 1 MiB 处触发）。
const LIMIT_MB: usize = 1;
const LIMIT_BYTES: usize = LIMIT_MB * 1024 * 1024;

/// 超限文件 1.9 MiB：超出上限的 ~0.9 MiB 须小于服务端吸干预算（上限+余量），
/// 保证客户端能在预算内发完、读到完整错误响应。以真 SRPM 打头（尾部 x 填充）：
/// 提交入口按 header N-V-R 解析任务真名，非 RPM 字节会被 400 拒。
fn oversize_srpm() -> Vec<u8> {
    let mut v = fixture_srpm_prefix();
    v.resize(LIMIT_BYTES + LIMIT_BYTES / 2 + 1024 * 400, b'x');
    v
}

/// 真 SRPM 的头部前缀，供 NEVR 解析与大小测试拼接。
fn fixture_srpm_prefix() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/hello-1.0-1.src.rpm"
    );
    std::fs::read(path).expect("test fixture SRPM missing")
}

const BOUNDARY: &str = "crbsdraintest";

async fn serve_app(app: axum::Router) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("test server");
    });
    port
}

/// 返回 (端口, TempDir)；TempDir 必须存活到测试结束（否则中途删库）。
async fn spawn_server_with_upload_limit(limit_mb: usize) -> (u16, tempfile::TempDir) {
    let _ = TEST_CONFIG_DIR.path();
    crbs_server::test_support::init_test_logging();
    let (store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        store,
        ServerConfig {
            min_free_disk_gb: 0,
            upload_max_size_mb: limit_mb,
            ..Default::default()
        },
        tmp_dir.path().to_path_buf(),
    ));
    let port = serve_app(crbs_server::server::create_test_app(app_state)).await;
    (port, tmp_dir)
}

async fn spawn_server() -> (u16, tempfile::TempDir) {
    spawn_server_with_upload_limit(LIMIT_MB).await
}

/// 真实 TCP 上的 HTTP/1.1 POST：完整写出 head+body（服务端中途 RST → write
/// Err = curl 56 "实送 < content-length"）；`Connection: close` 下 read_to_end
///（响应未读完被 RST → read Err 或体短缺）；成功时校验体长 == content-length。
async fn tcp_post_multipart(
    port: u16,
    path: &str,
    bearer: Option<&str>,
    body: Vec<u8>,
) -> Result<(u16, Vec<u8>), String> {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let mut head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        body.len(),
    );
    if let Some(token) = bearer {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|e| format!("write request head: {e}"))?;
    // 分块 + 间隔发送：服务端未吸干请求体即关闭连接（RST）时，客户端仍在
    // 发送途中，下一次 write 必然失败——确定性复现 curl 56，不依赖缓冲耗尽时序。
    const CHUNK: usize = 128 * 1024;
    for (i, piece) in body.chunks(CHUNK).enumerate() {
        if i > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        stream
            .write_all(piece)
            .await
            .map_err(|e| format!("write request body (chunk {i}): {e}"))?;
    }
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .map_err(|e| format!("read response (connection reset / truncated): {e}"))?;
    drop(stream);

    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("response has no header terminator")?;
    let head_text = String::from_utf8_lossy(&raw[..header_end]).into_owned();
    let status: u16 = head_text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            format!(
                "bad status line: {}",
                head_text.lines().next().unwrap_or("")
            )
        })?;
    let content_length: usize = head_text
        .lines()
        .skip(1)
        .find_map(|l| {
            l.split_once(':').and_then(|(k, v)| {
                k.eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse().ok())
                    .flatten()
            })
        })
        .ok_or("response missing content-length")?;
    let resp_body = raw[header_end + 4..].to_vec();
    if resp_body.len() != content_length {
        return Err(format!(
            "response body truncated: content-length {content_length}, received {}",
            resp_body.len()
        ));
    }
    Ok((status, resp_body))
}

fn builds_submit_body(product: &str, srpm: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"product\"\r\n\r\n");
    body.extend_from_slice(product.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"srpm\"; filename=\"big.src.rpm\"\r\n\
          Content-Type: application/octet-stream\r\n\r\n",
    );
    body.extend_from_slice(srpm);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

fn artifacts_upload_body(manifest: &str, file_name: &str, content: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"manifest\"\r\n\r\n");
    body.extend_from_slice(manifest.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"file\"; filename=\"{file_name}\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

fn assert_error_envelope(
    status: u16,
    body: &[u8],
    expected_status: u16,
    expected_error: &str,
    message_contains: &str,
) {
    assert_eq!(
        status,
        expected_status,
        "expected {expected_status}, body: {}",
        String::from_utf8_lossy(body)
    );
    let json: serde_json::Value = serde_json::from_slice(body).unwrap_or_else(|e| {
        panic!(
            "error body is JSON: {e}; body: {}",
            String::from_utf8_lossy(body)
        )
    });
    assert_eq!(json["error"], expected_error, "body: {json}");
    let msg = json["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains(message_contains),
        "message should contain '{message_contains}', got: {msg}"
    );
}

fn assert_validation_error(status: u16, body: &[u8], message_contains: &str) {
    assert_error_envelope(status, body, 400, "validation_failed", message_contains);
}

fn assert_payload_too_large(status: u16, body: &[u8], message_contains: &str) {
    assert_error_envelope(status, body, 413, "payload_too_large", message_contains);
}

// ======== builds 提交（API multipart 入口） ========

/// 超限上传：服务端须吸干剩余请求体再返回 4xx，客户端（真实 TCP）完整
/// 写出、完整读回错误体。per-file 超限 = 413 payload_too_large（非字段语义错误）。
#[tokio::test]
async fn over_limit_submit_error_body_fully_delivered() {
    let (port, _tmp) = spawn_server().await;
    let body = builds_submit_body("drainprod", &oversize_srpm());

    let (status, resp_body) = tcp_post_multipart(port, "/api/v1/builds", None, body)
        .await
        .expect("client must be able to finish sending and read the full error response");
    assert_payload_too_large(status, &resp_body, "size limit");
}

#[tokio::test]
async fn within_limit_submit_succeeds_over_tcp() {
    let (port, _tmp) = spawn_server().await;
    let mut srpm = fixture_srpm_prefix();
    srpm.extend_from_slice(&[b'x'; 96]);
    let body = builds_submit_body("drainprod", &srpm);

    let (status, resp_body) = tcp_post_multipart(port, "/api/v1/builds", None, body)
        .await
        .expect("client must finish sending and read the full response");
    assert_eq!(status, 202, "body: {}", String::from_utf8_lossy(&resp_body));
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(
        json["task_id"].as_i64().is_some(),
        "202 body should carry task_id: {json}"
    );
}

/// 回归钉：axum `DefaultBodyLimit` 框架默认 2MB，multipart 提交靠 route 级
/// `max(upload_max×2+余量)` 抬高、JSON 的 2MB 覆盖只在分支内 `apply`——
/// 覆盖挪到分支前或删掉路由级抬高，multipart 即被掐断；断言 202。
#[tokio::test]
async fn over_two_mb_multipart_submit_succeeds_with_raised_limit() {
    let (port, _tmp) = spawn_server_with_upload_limit(3).await;
    // 2.5 MiB：> 2MB 框架默认、< 3 MiB per-file 上限，总量 << 路由级 2×3MiB+余量。
    let mut srpm = fixture_srpm_prefix();
    srpm.extend_from_slice(&[b'x'; 5 * 512 * 1024]);
    assert!(
        srpm.len() > 2 * 1024 * 1024,
        "fixture must exceed the 2MB default"
    );
    let body = builds_submit_body("drainprod", &srpm);

    let (status, resp_body) = tcp_post_multipart(port, "/api/v1/builds", None, body)
        .await
        .expect("client must finish sending and read the full response");
    assert_eq!(status, 202, "body: {}", String::from_utf8_lossy(&resp_body));
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(
        json["task_id"].as_i64().is_some(),
        "202 body should carry task_id: {json}"
    );
}

// ======== artifacts 上传（worker multipart 入口） ========

async fn register_worker(
    app: &axum::Router,
    app_state: &Arc<AppState>,
    name: &str,
    op_token: &str,
) -> (i64, String) {
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/workers/register")
                .header("Authorization", format!("Bearer {}", op_token))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "name": name, "arch": "x86_64", "capacity": 1 })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let worker_id = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["id"]
        .as_i64()
        .unwrap();
    let secret = Secret::generate(SecretKind::WorkerSecret).unwrap();
    app_state
        .state_store
        .set_worker_secret(worker_id, secret.hash().as_str())
        .await
        .unwrap();
    (worker_id, secret.as_str().to_string())
}

/// 非法文件名（路径穿越）在校验期被 400 拒绝；其后还有 ~1.9 MiB 未读数据，
/// 服务端须吸干后返回，worker 才能读到完整 400。
#[tokio::test]
async fn artifact_bad_filename_error_body_fully_delivered() {
    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let _ = TEST_CONFIG_DIR.path();
    crbs_server::test_support::init_test_logging();
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig {
            min_free_disk_gb: 0,
            upload_max_size_mb: LIMIT_MB,
            ..Default::default()
        },
        tmp.path().to_path_buf(),
    ));
    let app = crbs_server::server::create_test_app_with_auth(app_state.clone());
    let op_token = crbs_server::server::seed_user_token_for_test(
        &app_state.state_store,
        "drain-op",
        "operator",
    )
    .await
    .unwrap();
    let (worker_id, worker_token) =
        register_worker(&app, &app_state, "drain-worker", &op_token).await;

    // 造一个已分配给该 worker 的 build（上传归属校验的前置）。
    let toml_body = "\
base_packages = [\"bash\", \"rpm-build\"]\n\
arches = [\"x86_64\"]\n\
\n\
[[repos]]\n\
name = \"base\"\n\
baseurl = \"http://example.com/base/$basearch\"\n\
gpgcheck = false\n";
    let config = crbs_core::config::ProductConfig::from_str(toml_body).unwrap();
    store
        .create_product(crbs_core::CreateProductInput {
            name: "drainprod",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &config,
            changed_by_user_id: None,
            reason: Some("drain test"),
        })
        .await
        .unwrap();
    let task_id = crbs_server::test_support::seed_task(&store, "drainprod", "hello").await;
    let build_id = store
        .insert_build(BuildInsert {
            product: "drainprod",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    let port = serve_app(app).await;

    let manifest = serde_json::json!({ "hello.rpm": "0".repeat(64) }).to_string();
    let body = artifacts_upload_body(&manifest, "../evil.rpm", &oversize_srpm());
    let (status, resp_body) = tcp_post_multipart(
        port,
        &format!("/api/v1/builds/{build_id}/artifacts/upload"),
        Some(&worker_token),
        body,
    )
    .await
    .expect("worker client must be able to finish sending and read the full error response");
    assert_validation_error(status, &resp_body, "invalid artifact file name");
}
