// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use crbs_core::config::ServerConfig;
use crbs_core::StateStore;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use crate::server::create_test_app_with_auth;
use crate::server::seed_worker_secret_for_test;
use crate::server::state::AppState;

async fn seed_worker(store: &StateStore) -> (i64, String) {
    seed_worker_secret_for_test(store, "test-worker", "x86_64")
        .await
        .unwrap()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn build_multipart_body(
    boundary: &str,
    manifest: &str,
    file_name: &str,
    content: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"manifest\"\r\n");
    body.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
    body.extend_from_slice(manifest.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n",
            file_name
        )
        .as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(content);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    body
}

fn build_multipart_body_multi(boundary: &str, manifest: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"manifest\"\r\n");
    body.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
    body.extend_from_slice(manifest.as_bytes());
    body.extend_from_slice(b"\r\n");
    for (file_name, content) in files {
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n",
                file_name
            )
            .as_bytes(),
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(content);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    body
}

#[tokio::test]
async fn upload_artifacts_streaming_success() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    // 上传端点要求 worker 持有该 build 的分配行（归属校验）
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);
    let content = b"hello streaming artifact";
    let manifest = serde_json::json!({ "test.txt": sha256_hex(content) }).to_string();
    let boundary = "----stream-test";
    let body = build_multipart_body(boundary, &manifest, "test.txt", content);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", worker_token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["uploaded"], serde_json::json!(["test.txt"]));
    // 响应不得携带服务器绝对 result_dir（与 artifacts/list.rs 的
    // 脱敏口径对齐；DB 侧 builds.result_dir 照常落库，不受影响）。
    assert!(
        json.get("result_dir").is_none(),
        "result_dir must not be echoed in upload response: {json}"
    );

    let expected_path = tmp
        .path()
        .join("results")
        .join(task_id.to_string())
        .join("x86_64")
        .join(build_id.to_string())
        .join("test.txt");
    assert_eq!(tokio::fs::read(&expected_path).await.unwrap(), content);

    // backend 覆写回归：上传落库的 update_build_info 不得把引擎写入的
    // builds.backend 覆写为空串（UPDATE 无条件 SET，须透传 record 原值）。
    let record = store.get_build(build_id).await.unwrap().unwrap();
    assert_eq!(
        record.backend.as_deref(),
        Some("chroot"),
        "upload must not clobber builds.backend"
    );
}

#[tokio::test]
async fn upload_artifacts_streaming_sha256_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    // 上传端点要求 worker 持有该 build 的分配行（归属校验）
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);
    let content = b"hello streaming artifact";
    let manifest = serde_json::json!({ "test.txt": "deadbeef" }).to_string();
    let boundary = "----stream-test-mismatch";
    let body = build_multipart_body(boundary, &manifest, "test.txt", content);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", worker_token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let leftover = tmp
        .path()
        .join("results")
        .join("fedora")
        .join(build_id.to_string())
        .join("test.txt");
    assert!(!leftover.exists());
}

#[tokio::test]
async fn upload_artifacts_accepts_nested_relative_path() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    // 上传端点要求 worker 持有该 build 的分配行（归属校验）
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);
    let content = b"nested rpm content";
    let file_name = "RPMS/x86_64/pkg.rpm";
    let manifest = serde_json::json!({ file_name: sha256_hex(content) }).to_string();
    let boundary = "----stream-test-nested";
    let body = build_multipart_body(boundary, &manifest, file_name, content);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", worker_token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["uploaded"], serde_json::json!([file_name]));

    let expected_path = tmp
        .path()
        .join("results")
        .join(task_id.to_string())
        .join("x86_64")
        .join(build_id.to_string())
        .join(file_name);
    assert_eq!(tokio::fs::read(&expected_path).await.unwrap(), content);
}

#[tokio::test]
async fn upload_artifacts_rejects_parent_dir_in_file_name() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    // 上传端点要求 worker 持有该 build 的分配行（归属校验）
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);
    let content = b"evil content";
    let file_name = "foo/../bar.rpm";
    let manifest = serde_json::json!({ file_name: sha256_hex(content) }).to_string();
    let boundary = "----stream-test-parent";
    let body = build_multipart_body(boundary, &manifest, file_name, content);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", worker_token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn upload_artifacts_rejects_absolute_file_name() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    // 上传端点要求 worker 持有该 build 的分配行（归属校验）
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);
    let content = b"evil content";
    let file_name = "/tmp/evil.rpm";
    let manifest = serde_json::json!({ file_name: sha256_hex(content) }).to_string();
    let boundary = "----stream-test-absolute";
    let body = build_multipart_body(boundary, &manifest, file_name, content);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", worker_token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// 聚合总量超限 → 413（请求体过大，非字段语义错误——与 builds 提交侧
/// multipart per-file 超限同口径），已写文件统一回滚。
#[tokio::test]
async fn upload_artifacts_rejects_aggregate_total_size() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    // 上传端点要求 worker 持有该 build 的分配行（归属校验）
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);
    // 测试环境下聚合上限为 1 MiB，两个 700 KiB 文件合计超过。
    let content1 = vec![0u8; 700 * 1024];
    let content2 = vec![0u8; 700 * 1024];
    let manifest = serde_json::json!({
        "file1.bin": sha256_hex(&content1),
        "file2.bin": sha256_hex(&content2),
    })
    .to_string();
    let boundary = "----aggregate-test";
    let body = build_multipart_body_multi(
        boundary,
        &manifest,
        &[("file1.bin", &content1), ("file2.bin", &content2)],
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", worker_token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let leftover1 = tmp
        .path()
        .join("results")
        .join("builds")
        .join(build_id.to_string())
        .join("file1.bin");
    assert!(!leftover1.exists());
}

/// 回归：上传中断（multipart body 截断）时，已开写的半截 dest 不得残留。
#[tokio::test]
async fn upload_artifacts_truncated_multipart_cleans_partial_file() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

    let content = b"hello streaming artifact that will be truncated mid-flight";
    let manifest = serde_json::json!({ "test.txt": sha256_hex(content) }).to_string();
    let boundary = "----truncated-test";
    let full = build_multipart_body(boundary, &manifest, "test.txt", content);
    // 截断：砍掉尾部（含闭合 boundary 与部分文件内容），保留 manifest part、
    // file part 头与前半段内容——服务端会开写 dest 后遭遇流中断。
    let cut = full.len() - 40;
    let body = full[..cut].to_vec();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", worker_token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // 截断的 multipart 必然失败（4xx/5xx 皆可）；关键是 dest 不残留半截文件。
    assert_ne!(response.status(), StatusCode::OK);

    let leftover = tmp
        .path()
        .join("results")
        .join("builds")
        .join(build_id.to_string())
        .join("test.txt");
    assert!(
        !leftover.exists(),
        "中断上传的半截产物必须被清理: {}",
        leftover.display()
    );
}

/// multipart 在两个字段之间截断（manifest part 完整、下一个 part 的
/// 头只写一半）——顶层 `next_field` 读头时遭遇流中断，须返回 500 internal
/// error 信封：worker 分类（`http_response_error`：非 401/403/429 的 4xx →
/// ValidationFailed 不重试）下瞬断落 4xx 会放弃整批重传，500 → Network
/// 可重试，与 manifest 字段读 / file chunk 读位点同口径。验证边界：真实
/// "连接中途切断"需在传输层断开，oneshot
/// 无法注入，以请求体截断等价模拟读流意外终止。
#[tokio::test]
async fn upload_artifacts_truncated_between_fields_returns_500() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

    // manifest part 完整可读（首次 next_field / field.text() 均成功），随后
    // 下一个 part 的头写到一半截断——第二次 next_field 读头时遭遇 EOF → Err。
    let manifest = serde_json::json!({ "test.txt": sha256_hex(b"never-sent") }).to_string();
    let boundary = "----cut-between-fields";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"manifest\"\r\n");
    body.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
    body.extend_from_slice(manifest.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{}\r\nContent-Disposit", boundary).as_bytes());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", worker_token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "internal_error");
    assert_eq!(json["message"], "internal error");
}

/// 终态 build 的产物上传被拒：cancelled 构建上迟到 / 重派前残留的
/// 上传返回 409，无 artifacts 行、builds.result_dir 未写、磁盘不创建上传目录。
/// 参照 worker/routes.rs report_result_returns_conflict_for_terminal_assignment
/// 的 409 幂等语义（worker 侧重试层把 409 映射为不重试的 ValidationFailed）。
#[tokio::test]
async fn upload_artifacts_rejected_for_terminal_build() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    // 归属校验只看分配行存在（终态后行保留）；assign 要求 pending，故先
    // 分配再经 complete_build 翻 cancelled（模拟 hub 侧取消路径）。
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    store
        .complete_build(build_id, "cancelled", None)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);
    let content = b"late artifact from cancelled build";
    let manifest = serde_json::json!({ "test.txt": sha256_hex(content) }).to_string();
    let boundary = "----terminal-reject";
    let body = build_multipart_body(boundary, &manifest, "test.txt", content);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", worker_token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);

    // DB：无 artifacts 行，result_dir 未被覆写。
    let artifacts = store.list_artifacts(build_id).await.unwrap();
    assert_eq!(artifacts.len(), 0);
    let record = store.get_build(build_id).await.unwrap().unwrap();
    assert_eq!(record.result_dir, None);

    // 磁盘：上传目录未创建（入口守卫在读体之前拒绝）。
    let upload_dir = tmp
        .path()
        .join("results")
        .join(task_id.to_string())
        .join("x86_64")
        .join(build_id.to_string());
    assert!(
        !upload_dir.exists(),
        "terminal build must not get an upload dir: {}",
        upload_dir.display()
    );
}

/// 落库前终态守卫（TOCTOU 加固，handler 内"re-check build phase before
/// artifacts insert"分支）：入口检查通过（pending）、multipart 传输期间构建
/// 翻终态的迟到上传必须在**落库前**被拒——409 + 回滚已写盘文件 + 无
/// artifacts 行 + result_dir 不落库。钉住该分支防被当死代码删除。
/// 落库事务内的 `update_build_info_tx_guarded` CAS 是同一场景的
/// 第二道防线（覆盖复查 SELECT 之后才翻转的窗口），由 crbs-core 侧
/// `update_build_info_tx_guarded_rejects_non_active_phase` 单测钉住。
///
/// 构造方式：multipart 体用流式 body 分两段发送——先发 manifest 字段并等
/// 上传目录出现（目录创建于入口守卫之后、字段解析之前，是"已过入口守卫"
/// 的可观测信号），翻终态后再放行 file 字段；入口守卫路径下目录不会创建
/// （见上一测试），断言目录存在即证明这次命中的是落库前复查分支。
#[tokio::test]
async fn upload_artifacts_rejected_at_commit_when_build_flips_terminal_during_upload() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

    let content = b"artifact uploaded before terminal flip";
    let manifest = serde_json::json!({ "test.txt": sha256_hex(content) }).to_string();
    let boundary = "----commit-guard";
    let full = build_multipart_body(boundary, &manifest, "test.txt", content);
    // 在 file 字段边界切开：前段 = manifest 字段，后段 = file 字段 + 收尾。
    let marker = format!(
        "--{}\r\nContent-Disposition: form-data; name=\"file\"",
        boundary
    );
    let split_at = full
        .windows(marker.len())
        .position(|w| w == marker.as_bytes())
        .expect("file part marker in multipart body");

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(4);
    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx));
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
        .header("Authorization", format!("Bearer {}", worker_token))
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={}", boundary),
        )
        .body(body)
        .unwrap();
    let response = tokio::spawn(async move { app.oneshot(request).await.unwrap() });

    // 第一段（manifest 字段）放行；handler 消费后阻塞等待后续字段。
    tx.send(Ok(bytes::Bytes::from(full[..split_at].to_vec())))
        .await
        .unwrap();

    // 等上传目录出现 = 入口守卫已过（目录创建于守卫后、multipart 解析前）。
    let upload_dir = tmp
        .path()
        .join("results")
        .join(task_id.to_string())
        .join("x86_64")
        .join(build_id.to_string());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !upload_dir.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "upload dir must appear after the entry guard passes"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // multipart 传输期间构建翻终态（并发取消/超时/重派完成的窗口）。
    store
        .complete_build(build_id, "cancelled", None)
        .await
        .unwrap();

    // 第二段（file 字段 + 结束 boundary）放行，请求走完。
    tx.send(Ok(bytes::Bytes::from(full[split_at..].to_vec())))
        .await
        .unwrap();
    drop(tx);

    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // DB：无 artifacts 行（落库前拦截），result_dir 未写。
    let artifacts = store.list_artifacts(build_id).await.unwrap();
    assert_eq!(artifacts.len(), 0);
    let record = store.get_build(build_id).await.unwrap().unwrap();
    assert_eq!(record.result_dir, None);

    // 磁盘：目录已在（证明过的是入口守卫而非它拒绝），但已写盘文件被回滚。
    let written = upload_dir.join("test.txt");
    assert!(
        !written.exists(),
        "committed-then-rejected file must be rolled back: {}",
        written.display()
    );
}

/// 归属 CAS（handler 内 update_build_info_tx_guarded 的 assignment
/// EXISTS 谓词）：入口归属校验通过、multipart 传输期间 assignment 被 reclaim
/// 删行并重派给另一 worker（build 保持活跃态，phase 复查与终态 CAS 均放行）
/// 的迟到上传必须在**落库点**被拒——409 + 回滚已写盘文件 + 无 artifacts 行 +
/// result_dir 不落库，被剥夺执行的产物不得进入重派 build 的命名空间。
///
/// 构造方式同上一测试的流式 multipart 窗口：先发 manifest 字段并等上传目录
/// 出现（= 入口守卫已过），再 reclaim+重派，然后放行 file 字段。若删归属
/// EXISTS 谓词，本测试会在活跃态 build 上成功落库（回归信号）。
#[tokio::test]
async fn upload_artifacts_rejected_at_commit_when_assignment_revoked_during_upload() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

    let content = b"stale artifact from revoked worker";
    let manifest = serde_json::json!({ "test.txt": sha256_hex(content) }).to_string();
    let boundary = "----revoke-guard";
    let full = build_multipart_body(boundary, &manifest, "test.txt", content);
    // 在 file 字段边界切开：前段 = manifest 字段，后段 = file 字段 + 收尾。
    let marker = format!(
        "--{}\r\nContent-Disposition: form-data; name=\"file\"",
        boundary
    );
    let split_at = full
        .windows(marker.len())
        .position(|w| w == marker.as_bytes())
        .expect("file part marker in multipart body");

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(4);
    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx));
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
        .header("Authorization", format!("Bearer {}", worker_token))
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={}", boundary),
        )
        .body(body)
        .unwrap();
    let response = tokio::spawn(async move { app.oneshot(request).await.unwrap() });

    // 第一段（manifest 字段）放行；handler 消费后阻塞等待后续字段。
    tx.send(Ok(bytes::Bytes::from(full[..split_at].to_vec())))
        .await
        .unwrap();

    // 等上传目录出现 = 入口守卫（含归属校验）已过。
    let upload_dir = tmp
        .path()
        .join("results")
        .join(task_id.to_string())
        .join("x86_64")
        .join(build_id.to_string());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !upload_dir.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "upload dir must appear after the entry guard passes"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // 传输期间模拟 reclaimer：删原 worker 的分配行、build 裸翻回 pending
    // （仅 phase，非完整回收重置），重派给新 worker——落库点只剩归属
    // CAS 能拒绝这次迟到上传。
    sqlx::query("DELETE FROM worker_tasks WHERE build_id = $1 AND worker_id = $2")
        .bind(build_id)
        .bind(worker_id)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET phase = 'pending' WHERE id = $1")
        .bind(build_id)
        .execute(store.pool())
        .await
        .unwrap();
    let new_worker = store
        .upsert_worker(
            "reassigned-worker",
            "x86_64",
            2,
            "0.15.0-dev",
            "online",
            None,
        )
        .await
        .unwrap();
    store
        .assign_build_to_worker(build_id, new_worker)
        .await
        .unwrap();

    // 第二段（file 字段 + 结束 boundary）放行，请求走完。
    tx.send(Ok(bytes::Bytes::from(full[split_at..].to_vec())))
        .await
        .unwrap();
    drop(tx);

    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // DB：无 artifacts 行（落库前拦截，重派 build 命名空间不被旧执行污染），
    // result_dir 未写；新 worker 的 assignment 完好。
    let artifacts = store.list_artifacts(build_id).await.unwrap();
    assert_eq!(artifacts.len(), 0);
    let record = store.get_build(build_id).await.unwrap().unwrap();
    assert_eq!(record.result_dir, None);
    assert!(
        store
            .worker_assigned_to_build(new_worker, build_id, None)
            .await
            .unwrap(),
        "new assignee must be unaffected"
    );

    // 磁盘：已写盘文件被回滚。
    let written = upload_dir.join("test.txt");
    assert!(
        !written.exists(),
        "revoked-then-rejected file must be rolled back: {}",
        written.display()
    );
}

/// 落库 insert 真 DB 失败分支（`commit_uploaded_artifacts` 事务内 Err →
/// RolledBack 路径）：入口守卫与落库前终态复查都通过、事务 begin 成功，
/// 但 `insert_artifacts_tx` 撞库错误 → 500 + rollback + 已写盘文件清理 +
/// result_dir 不落库。
///
/// 注入方式沿用上一测试的流式 multipart 窗口：等上传目录出现（= 已过入口
/// 守卫、进入字段解析）后 `DROP TABLE build_artifacts`——get_build 仍成功且
/// 非终态（builds 表未动，复查分支放行）、begin 不触表，insert 撞
/// "no such table" 产生真 DB Err。之所以要 DROP TABLE 而非冲突行：
/// insert_artifacts_tx 是 ON CONFLICT 幂等 upsert，唯一键冲突不产生 Err。
#[tokio::test]
async fn upload_artifacts_db_failure_at_insert_rolls_back_and_cleans_files() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

    let content = b"artifact uploaded before db failure injection";
    let manifest = serde_json::json!({ "test.txt": sha256_hex(content) }).to_string();
    let boundary = "----db-insert-fail";
    let full = build_multipart_body(boundary, &manifest, "test.txt", content);
    let marker = format!(
        "--{}\r\nContent-Disposition: form-data; name=\"file\"",
        boundary
    );
    let split_at = full
        .windows(marker.len())
        .position(|w| w == marker.as_bytes())
        .expect("file part marker in multipart body");

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(4);
    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx));
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
        .header("Authorization", format!("Bearer {}", worker_token))
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={}", boundary),
        )
        .body(body)
        .unwrap();
    let response = tokio::spawn(async move { app.oneshot(request).await.unwrap() });

    // 第一段（manifest 字段）放行；handler 消费后阻塞等待后续字段。
    tx.send(Ok(bytes::Bytes::from(full[..split_at].to_vec())))
        .await
        .unwrap();

    // 等上传目录出现 = 入口守卫已过（目录创建于守卫后、multipart 解析前）。
    let upload_dir = tmp
        .path()
        .join("results")
        .join(task_id.to_string())
        .join("x86_64")
        .join(build_id.to_string());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !upload_dir.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "upload dir must appear after the entry guard passes"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // multipart 传输期间注入库故障：产物表消失。builds 表未动——终态复查
    // 分支放行，失败点被推到事务内的 insert。
    sqlx::query("DROP TABLE build_artifacts")
        .execute(store.pool())
        .await
        .unwrap();

    // 第二段（file 字段 + 结束 boundary）放行，请求走完。
    tx.send(Ok(bytes::Bytes::from(full[split_at..].to_vec())))
        .await
        .unwrap();
    drop(tx);

    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // DB：result_dir 未写（builds 表仍在，get_build 可查；build_artifacts 表
    // 已被本测试 DROP，list_artifacts 必然报错，不做 artifacts 行数断言）。
    let record = store.get_build(build_id).await.unwrap().unwrap();
    assert_eq!(record.result_dir, None);

    // 磁盘：已写盘文件被回滚清理。
    let written = upload_dir.join("test.txt");
    assert!(
        !written.exists(),
        "files written before the DB failure must be cleaned up: {}",
        written.display()
    );
}

// === 集成测试 ===

#[tokio::test]
async fn a2_upload_with_artifacts_json_inserts_into_db() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    // 上传端点要求 worker 持有该 build 的分配行（归属校验）
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

    let rpm_content = b"fake rpm content";
    let log_content = b"build log here";

    // 构造 crbs-artifacts.json（version=1，与 Server 计算的 SHA256 一致）
    let artifacts_json = serde_json::json!({
        "version": 1,
        "build_id": build_id,
        "artifacts": [
            {
                "path": "RPMS/x86_64/hello-1.0-1.x86_64.rpm",
                "kind": "rpm",
                "size": rpm_content.len(),
                "sha256": sha256_hex(rpm_content),
                "arch": "x86_64",
                "name": "hello",
                "version": "1.0",
                "release": "1",
                "epoch": null
            },
            {
                "path": "build.log",
                "kind": "log",
                "size": log_content.len(),
                "sha256": sha256_hex(log_content)
            }
        ]
    })
    .to_string();

    let manifest = serde_json::json!({
        "RPMS/x86_64/hello-1.0-1.x86_64.rpm": sha256_hex(rpm_content),
        "build.log": sha256_hex(log_content),
        "crbs-artifacts.json": sha256_hex(artifacts_json.as_bytes()),
    })
    .to_string();

    let boundary = "----a2-test-valid";
    let body = build_multipart_body_multi(
        boundary,
        &manifest,
        &[
            ("RPMS/x86_64/hello-1.0-1.x86_64.rpm", rpm_content.as_slice()),
            ("build.log", log_content.as_slice()),
            ("crbs-artifacts.json", artifacts_json.as_bytes()),
        ],
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", worker_token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // 验证 DB 中确实插入了 artifacts 记录
    let artifacts = store.list_artifacts(build_id).await.unwrap();
    assert_eq!(artifacts.len(), 2);

    let rpm = artifacts
        .iter()
        .find(|a| a.relative_path == "RPMS/x86_64/hello-1.0-1.x86_64.rpm")
        .unwrap();
    assert!(matches!(rpm.kind, crbs_core::ArtifactKind::Rpm));
    assert_eq!(rpm.arch, Some("x86_64".to_string()));
    assert_eq!(rpm.name, Some("hello".to_string()));
    assert_eq!(rpm.size_bytes, rpm_content.len() as u64);
    assert!(!rpm.signed); // 签名是后台任务，测试环境下可能没执行

    let log = artifacts
        .iter()
        .find(|a| a.relative_path == "build.log")
        .unwrap();
    assert!(matches!(log.kind, crbs_core::ArtifactKind::Log));
}

#[tokio::test]
async fn a2_upload_artifacts_json_sha256_mismatch_returns_400() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    // 上传端点要求 worker 持有该 build 的分配行（归属校验）
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

    let rpm_content = b"fake rpm content";
    let wrong_sha = "0000000000000000000000000000000000000000000000000000000000000000";

    // crbs-artifacts.json 中的 SHA256 是错的（零信任校验应该拦截）
    let artifacts_json = serde_json::json!({
        "version": 1,
        "build_id": build_id,
        "artifacts": [{
            "path": "RPMS/x86_64/hello-1.0-1.x86_64.rpm",
            "kind": "rpm",
            "size": rpm_content.len(),
            "sha256": wrong_sha,
            "arch": "x86_64"
        }]
    })
    .to_string();

    let manifest = serde_json::json!({
        "RPMS/x86_64/hello-1.0-1.x86_64.rpm": sha256_hex(rpm_content),
        "crbs-artifacts.json": sha256_hex(artifacts_json.as_bytes()),
    })
    .to_string();

    let boundary = "----a2-test-mismatch";
    let body = build_multipart_body_multi(
        boundary,
        &manifest,
        &[
            ("RPMS/x86_64/hello-1.0-1.x86_64.rpm", rpm_content.as_slice()),
            ("crbs-artifacts.json", artifacts_json.as_bytes()),
        ],
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", worker_token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // 校验失败 → 400 BAD REQUEST + 回滚已上传文件
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // DB 中没有 artifacts 记录
    let artifacts = store.list_artifacts(build_id).await.unwrap();
    assert_eq!(artifacts.len(), 0);

    // 文件已被清理
    let leftover = tmp
        .path()
        .join("results")
        .join("builds")
        .join(build_id.to_string())
        .join("RPMS/x86_64/hello-1.0-1.x86_64.rpm");
    assert!(!leftover.exists());
}

#[tokio::test]
async fn a2_legacy_worker_no_artifacts_json_fallback_insert() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    // 上传端点要求 worker 持有该 build 的分配行（归属校验）
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

    let rpm_content = b"legacy rpm content";

    // 无清单文件：没有 crbs-artifacts.json
    let manifest = serde_json::json!({
        "RPMS/x86_64/hello-1.0-1.x86_64.rpm": sha256_hex(rpm_content),
    })
    .to_string();

    let boundary = "----a2-test-legacy";
    let body = build_multipart_body(
        boundary,
        &manifest,
        "RPMS/x86_64/hello-1.0-1.x86_64.rpm",
        rpm_content,
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", worker_token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // 向后兼容：上传必须成功
    assert_eq!(response.status(), StatusCode::OK);

    // 降级模式——Server 侧采集，DB 中有记录
    let artifacts = store.list_artifacts(build_id).await.unwrap();
    assert_eq!(artifacts.len(), 1);

    // 降级插入的字段：kind 从 classify() 推断（Rpm），NEVRA 从文件名猜
    let artifact = &artifacts[0];
    assert!(matches!(artifact.kind, crbs_core::ArtifactKind::Rpm));
    assert_eq!(artifact.arch, Some("x86_64".into()));
    assert_eq!(artifact.size_bytes, rpm_content.len() as u64);
    assert_eq!(artifact.sha256, sha256_hex(rpm_content));

    // 回归测试：NEVRA 解析只吃裸文件名，"RPMS/x86_64" 目录前缀不得
    // 混进 name 列。
    assert_eq!(artifact.name, Some("hello".into()));
    assert_eq!(artifact.version, Some("1.0".into()));
    assert_eq!(artifact.release, Some("1".into()));

    // 文件也写入了磁盘
    let expected_path = tmp
        .path()
        .join("results")
        .join(task_id.to_string())
        .join("x86_64")
        .join(build_id.to_string())
        .join("RPMS/x86_64/hello-1.0-1.x86_64.rpm");
    assert_eq!(tokio::fs::read(&expected_path).await.unwrap(), rpm_content);
}

#[tokio::test]
async fn a2_upload_artifacts_json_size_mismatch_returns_400() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    // 上传端点要求 worker 持有该 build 的分配行（归属校验）
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

    let rpm_content = b"fake rpm content";
    let wrong_size = 999999;

    // crbs-artifacts.json 中的 size 是错的
    let artifacts_json = serde_json::json!({
        "version": 1,
        "build_id": build_id,
        "artifacts": [{
            "path": "RPMS/x86_64/hello-1.0-1.x86_64.rpm",
            "kind": "rpm",
            "size": wrong_size,
            "sha256": sha256_hex(rpm_content),
            "arch": "x86_64"
        }]
    })
    .to_string();

    let manifest = serde_json::json!({
        "RPMS/x86_64/hello-1.0-1.x86_64.rpm": sha256_hex(rpm_content),
        "crbs-artifacts.json": sha256_hex(artifacts_json.as_bytes()),
    })
    .to_string();

    let boundary = "----a2-test-size-mismatch";
    let body = build_multipart_body_multi(
        boundary,
        &manifest,
        &[
            ("RPMS/x86_64/hello-1.0-1.x86_64.rpm", rpm_content.as_slice()),
            ("crbs-artifacts.json", artifacts_json.as_bytes()),
        ],
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", worker_token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a2_upload_artifacts_json_unknown_version_falls_back() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    // 上传端点要求 worker 持有该 build 的分配行（归属校验）
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

    let rpm_content = b"fake rpm content";

    // 未知版本号——前向兼容，走降级路径
    let artifacts_json = serde_json::json!({
        "version": 999,
        "build_id": build_id,
        "artifacts": []
    })
    .to_string();

    let manifest = serde_json::json!({
        "RPMS/x86_64/hello-1.0-1.x86_64.rpm": sha256_hex(rpm_content),
        "crbs-artifacts.json": sha256_hex(artifacts_json.as_bytes()),
    })
    .to_string();

    let boundary = "----a2-test-version";
    let body = build_multipart_body_multi(
        boundary,
        &manifest,
        &[
            ("RPMS/x86_64/hello-1.0-1.x86_64.rpm", rpm_content.as_slice()),
            ("crbs-artifacts.json", artifacts_json.as_bytes()),
        ],
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", worker_token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // 未知版本不报错，走降级路径，上传成功
    assert_eq!(response.status(), StatusCode::OK);

    // 验证 DB 中有降级插入的 artifact 行
    let artifacts = store.list_artifacts(build_id).await.unwrap();
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0].size_bytes, rpm_content.len() as u64);
    assert_eq!(artifacts[0].sha256, sha256_hex(rpm_content));
}

#[tokio::test]
async fn a2_refresh_signed_file_updates_hash_and_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    // 先插入一个 artifact（模拟上传流程）
    let now = chrono::Utc::now()
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string();
    let mut tx = store.pool().begin().await.unwrap();
    store
        .insert_artifacts_tx(
            &mut tx,
            build_id,
            &[crbs_core::NewArtifact {
                relative_path: "RPMS/x86_64/hello-1.0-1.x86_64.rpm".to_string(),
                kind: crbs_core::ArtifactKind::Rpm,
                size_bytes: 100,
                sha256: "original_hash".to_string(),
                unsigned_sha256: None,
                arch: Some("x86_64".to_string()),
                name: Some("hello".to_string()),
                version: Some("1.0".to_string()),
                release: Some("1".to_string()),
                epoch: None,
                metadata_json: None,
                signed: false,
            }],
            &now,
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // 验证初始状态：signed = false，hash = original_hash
    let artifacts = store.list_artifacts(build_id).await.unwrap();
    assert_eq!(artifacts.len(), 1);
    assert!(!artifacts[0].signed);
    assert_eq!(artifacts[0].sha256, "original_hash");
    assert_eq!(artifacts[0].size_bytes, 100);

    // 调用 refresh_signed_files（模拟签名后流程；事务化批量刷新）
    store
        .refresh_signed_files(
            build_id,
            &[(
                "RPMS/x86_64/hello-1.0-1.x86_64.rpm".to_string(),
                "signed_hash".to_string(),
                200,
            )],
        )
        .await
        .unwrap();

    // 验证：signed=true，hash 更新，size 更新，created_at 不变（SQL 层面保证）
    let artifacts = store.list_artifacts(build_id).await.unwrap();
    assert_eq!(artifacts.len(), 1);
    assert!(artifacts[0].signed);
    assert_eq!(artifacts[0].sha256, "signed_hash");
    assert_eq!(artifacts[0].size_bytes, 200);
}

/// 回归：同 task 同 arch 的多个 build（多 SRPM task）上传相同相对路径的
/// sidecar（build.log）必须落到各自的 build_id 子目录，互不覆盖。
#[tokio::test]
async fn upload_sidecars_isolated_per_build_for_same_task_arch() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let (worker_id, worker_token) = seed_worker(&store).await;

    // 同一 task、同一 arch 的两个 build（模拟一个 task 下的两个 SRPM）
    let task_id = store
        .insert_task(crbs_core::TaskInsert {
            product: "fedora",
            pkg_name: "hello",
            user: "test",
            priority: crbs_core::types::PRIORITY_DEFAULT,
            ..Default::default()
        })
        .await
        .unwrap();
    let build_a = insert_task_build(&store, "hello", task_id).await;
    let build_b = insert_task_build(&store, "world", task_id).await;
    store
        .assign_build_to_worker(build_a, worker_id)
        .await
        .unwrap();
    store
        .assign_build_to_worker(build_b, worker_id)
        .await
        .unwrap();

    // 两个 build 上传相同相对路径 build.log，内容不同
    upload_log_file(&app, &worker_token, build_a, "build.log", "log-of-build-a").await;
    upload_log_file(&app, &worker_token, build_b, "build.log", "log-of-build-b").await;

    // 断言：各自落在 {task_id}/{arch}/{build_id}/build.log，内容独立
    let root = tmp.path().join("results");
    for (build_id, expected) in [(build_a, "log-of-build-a"), (build_b, "log-of-build-b")] {
        let p = root
            .join(task_id.to_string())
            .join("x86_64")
            .join(build_id.to_string())
            .join("build.log");
        let actual = tokio::fs::read_to_string(&p)
            .await
            .unwrap_or_else(|e| panic!("expected per-build sidecar at {}: {}", p.display(), e));
        assert_eq!(actual, expected, "sidecar must be isolated per build_id");
    }

    // 旧布局（无 build_id 段）下不应残留 build.log——新写入全部进入 per-build 目录
    let legacy = root
        .join(task_id.to_string())
        .join("x86_64")
        .join("build.log");
    assert!(
        !legacy.exists(),
        "legacy shared-path build.log must not exist"
    );
}

/// 插入一个带 task_id/arch 的 build 行（多 SRPM task 场景辅助）。
async fn insert_task_build(store: &StateStore, pkg_name: &str, task_id: i64) -> i64 {
    store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name,
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap()
}

/// 以 worker 身份向指定 build 上传一个单文件 multipart 请求（sidecar 测试辅助）。
async fn upload_log_file(
    app: &axum::Router,
    worker_token: &str,
    build_id: i64,
    file_name: &str,
    content: &str,
) {
    let manifest = serde_json::json!({ file_name: sha256_hex(content.as_bytes()) }).to_string();
    let boundary = "----sidecar-isolation";
    let body = build_multipart_body(boundary, &manifest, file_name, content.as_bytes());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", worker_token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// 回归：带前序合法 file 字段 + 畸形 crbs-artifacts.json 的上传，
/// 零信任校验段解析失败时必须回滚**全部**已写盘文件（parse 分支的 `?`
/// 出口不得绕过清理，否则前序文件残留在 upload_dir 成为无人认领的孤儿）。
#[tokio::test]
async fn upload_artifacts_malformed_artifacts_json_cleans_written_files() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let server_config = ServerConfig {
        result_dir: Some(tmp.path().join("results")),
        ..Default::default()
    };
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        server_config,
        tmp.path().to_path_buf(),
    ));

    let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
    let build_id = store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (worker_id, worker_token) = seed_worker(&store).await;
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

    let content = b"prior valid file content";
    let malformed_json = b"{ not valid json";
    // manifest 校验覆盖所有 written 文件（含 crbs-artifacts.json 自身），
    // 全部给正确 sha，确保失败点落在零信任校验段的 parse 分支。
    let manifest = serde_json::json!({
        "test.txt": sha256_hex(content),
        "crbs-artifacts.json": sha256_hex(malformed_json.as_slice()),
    })
    .to_string();

    let boundary = "----malformed-json-cleanup";
    let body = build_multipart_body_multi(
        boundary,
        &manifest,
        &[
            ("test.txt", content.as_slice()),
            ("crbs-artifacts.json", malformed_json.as_slice()),
        ],
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/builds/{}/artifacts/upload", build_id))
                .header("Authorization", format!("Bearer {}", worker_token))
                .header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // 前序合法文件与畸形 JSON 都必须被回滚：upload_dir 不剩业务文件。
    // `.upload.lock` 是常驻互斥锁；staging 目录由 Drop 异步删除，轮询等待。
    let upload_dir = tmp
        .path()
        .join("results")
        .join(task_id.to_string())
        .join("x86_64")
        .join(build_id.to_string());
    let poll_leftover = || {
        std::fs::read_dir(&upload_dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name())
                    .filter(|n| n != ".upload.lock" && !n.to_string_lossy().starts_with(".upload-"))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let mut leftover = poll_leftover();
    for _ in 0..50 {
        if leftover.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        leftover = poll_leftover();
    }
    assert!(
        leftover.is_empty(),
        "malformed crbs-artifacts.json must roll back all written files, found: {:?}",
        leftover
    );
}

/// ENOSPC 错误分类直测（route 级注入真实 ENOSPC 需满盘文件系统，
/// 成本过高收口到分类函数）：raw_os_error(28)（真实 ENOSPC syscall 的
/// std 映射形态）必须命中；其余 IO 错误不得误判（否则会把可恢复的瞬时
/// IO 故障变成不可重试的 400）。
#[test]
fn is_disk_full_classifies_enospc_by_raw_os_error() {
    use super::is_disk_full;
    // errno 通道：真实 ENOSPC syscall 在目标平台（Linux）必带 errno 28。
    assert!(is_disk_full(&std::io::Error::from_raw_os_error(28)));
    // 负例：常见非盘满 IO 错误不得误判。
    for kind in [
        std::io::ErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::TimedOut,
        std::io::ErrorKind::Other,
    ] {
        assert!(
            !is_disk_full(&std::io::Error::from(kind)),
            "{kind:?} must not classify as disk full"
        );
    }
    assert!(!is_disk_full(&std::io::Error::from_raw_os_error(5))); // EIO
    assert!(!is_disk_full(&std::io::Error::from_raw_os_error(13))); // EACCES
}

/// 盘满 4xx 信封文案与入口预检（ensure_disk_space）一致且不含
/// 服务端路径（Validation 消息直达客户端）。
#[test]
fn disk_full_api_error_message_is_safe_and_explicit() {
    use super::disk_full_api_error;
    let err = disk_full_api_error();
    assert!(
        matches!(err, crate::server::error::ApiError::Validation(ref msg) if msg == "insufficient disk space on server; free up space and retry")
    );
}
