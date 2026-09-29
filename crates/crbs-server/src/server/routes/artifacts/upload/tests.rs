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

    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

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

    let artifacts = store.list_artifacts(build_id).await.unwrap();
    assert_eq!(artifacts.len(), 0);
    let record = store.get_build(build_id).await.unwrap().unwrap();
    assert_eq!(record.result_dir, None);

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

    tx.send(Ok(bytes::Bytes::from(full[..split_at].to_vec())))
        .await
        .unwrap();

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

    store
        .complete_build(build_id, "cancelled", None)
        .await
        .unwrap();

    tx.send(Ok(bytes::Bytes::from(full[split_at..].to_vec())))
        .await
        .unwrap();
    drop(tx);

    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let artifacts = store.list_artifacts(build_id).await.unwrap();
    assert_eq!(artifacts.len(), 0);
    let record = store.get_build(build_id).await.unwrap().unwrap();
    assert_eq!(record.result_dir, None);

    let written = upload_dir.join("test.txt");
    assert!(
        !written.exists(),
        "committed-then-rejected file must be rolled back: {}",
        written.display()
    );
}

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

    tx.send(Ok(bytes::Bytes::from(full[..split_at].to_vec())))
        .await
        .unwrap();

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

    tx.send(Ok(bytes::Bytes::from(full[split_at..].to_vec())))
        .await
        .unwrap();
    drop(tx);

    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

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

    let written = upload_dir.join("test.txt");
    assert!(
        !written.exists(),
        "revoked-then-rejected file must be rolled back: {}",
        written.display()
    );
}

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

    tx.send(Ok(bytes::Bytes::from(full[..split_at].to_vec())))
        .await
        .unwrap();

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

    sqlx::query("DROP TABLE build_artifacts")
        .execute(store.pool())
        .await
        .unwrap();

    tx.send(Ok(bytes::Bytes::from(full[split_at..].to_vec())))
        .await
        .unwrap();
    drop(tx);

    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let record = store.get_build(build_id).await.unwrap().unwrap();
    assert_eq!(record.result_dir, None);

    let written = upload_dir.join("test.txt");
    assert!(
        !written.exists(),
        "files written before the DB failure must be cleaned up: {}",
        written.display()
    );
}

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

    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

    let rpm_content = b"fake rpm content";
    let log_content = b"build log here";

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
    assert!(!rpm.signed);

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

    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

    let rpm_content = b"fake rpm content";
    let wrong_sha = "0000000000000000000000000000000000000000000000000000000000000000";

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

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let artifacts = store.list_artifacts(build_id).await.unwrap();
    assert_eq!(artifacts.len(), 0);

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

    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

    let rpm_content = b"legacy rpm content";

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

    assert_eq!(response.status(), StatusCode::OK);

    let artifacts = store.list_artifacts(build_id).await.unwrap();
    assert_eq!(artifacts.len(), 1);

    let artifact = &artifacts[0];
    assert!(matches!(artifact.kind, crbs_core::ArtifactKind::Rpm));
    assert_eq!(artifact.arch, Some("x86_64".into()));
    assert_eq!(artifact.size_bytes, rpm_content.len() as u64);
    assert_eq!(artifact.sha256, sha256_hex(rpm_content));

    assert_eq!(artifact.name, Some("hello".into()));
    assert_eq!(artifact.version, Some("1.0".into()));
    assert_eq!(artifact.release, Some("1".into()));

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

    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

    let rpm_content = b"fake rpm content";
    let wrong_size = 999999;

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

    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    let app = create_test_app_with_auth(app_state);

    let rpm_content = b"fake rpm content";

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

    assert_eq!(response.status(), StatusCode::OK);

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

    let artifacts = store.list_artifacts(build_id).await.unwrap();
    assert_eq!(artifacts.len(), 1);
    assert!(!artifacts[0].signed);
    assert_eq!(artifacts[0].sha256, "original_hash");
    assert_eq!(artifacts[0].size_bytes, 100);

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

    let artifacts = store.list_artifacts(build_id).await.unwrap();
    assert_eq!(artifacts.len(), 1);
    assert!(artifacts[0].signed);
    assert_eq!(artifacts[0].sha256, "signed_hash");
    assert_eq!(artifacts[0].size_bytes, 200);
}

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

    upload_log_file(&app, &worker_token, build_a, "build.log", "log-of-build-a").await;
    upload_log_file(&app, &worker_token, build_b, "build.log", "log-of-build-b").await;

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

    let legacy = root
        .join(task_id.to_string())
        .join("x86_64")
        .join("build.log");
    assert!(
        !legacy.exists(),
        "legacy shared-path build.log must not exist"
    );
}

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

#[test]
fn is_disk_full_classifies_enospc_by_raw_os_error() {
    use super::is_disk_full;

    assert!(is_disk_full(&std::io::Error::from_raw_os_error(28)));

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
    assert!(!is_disk_full(&std::io::Error::from_raw_os_error(5)));
    assert!(!is_disk_full(&std::io::Error::from_raw_os_error(13)));
}

#[test]
fn disk_full_api_error_message_is_safe_and_explicit() {
    use super::disk_full_api_error;
    let err = disk_full_api_error();
    assert!(
        matches!(err, crate::server::error::ApiError::Validation(ref msg) if msg == "insufficient disk space on server; free up space and retry")
    );
}
