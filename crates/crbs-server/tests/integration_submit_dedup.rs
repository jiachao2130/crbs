// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 提交去重（应用层存在性短路）集成测试：同产品同 pkg_name 活跃构建存在时 submit / rebuild 返回 409，终态放行，多 arch fan-out 不自误伤。

// 文件级放行 unwrap/expect：seed_* 等测试辅助函数不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::ServerConfig;
use crbs_server::server::state::AppState;
use crbs_server::server::{create_test_app_with_auth, seed_user_token_for_test};

mod common;

async fn setup() -> (Arc<AppState>, axum::Router, String, tempfile::TempDir) {
    let _ = common::TEST_CONFIG_DIR.path();
    crbs_server::test_support::init_test_logging();
    let (state_store, tmp) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        state_store,
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let token = seed_user_token_for_test(&app_state.state_store, "dedop-admin", "admin")
        .await
        .expect("seed admin token");
    let app = create_test_app_with_auth(app_state.clone());
    (app_state, app, token, tmp)
}

async fn post_json(
    app: &axum::Router,
    token: &str,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// 在 upload_dir 下放一个 SRPM 文件并返回其路径（enqueue 路径校验要求）。
async fn make_srpm(tmp: &tempfile::TempDir, file: &str) -> std::path::PathBuf {
    let upload_dir = tmp.path().join("uploads");
    tokio::fs::create_dir_all(&upload_dir).await.unwrap();
    // N-V-R 拆分（rpm 语义：前两段 '-' 定 name，其余为 verrel）；
    // release 段含 '.'（dist）但不含 '-'。
    let stem = file.strip_suffix(".src.rpm").unwrap_or(file);
    let (name, verrel) = stem.split_once('-').unwrap_or((stem, "1.0-1"));
    let (version, release) = verrel.split_once('-').unwrap_or((verrel, "1"));
    let release = release.split('.').next().unwrap_or(release);
    common::make_minimal_srpm(&upload_dir, name, version, release)
}

/// 重复提交同 pkg 活跃构建 → 409（error=conflict，消息含 pkg 名与下一步指引）；build 置终态后 → 202。
#[tokio::test]
async fn duplicate_active_submit_conflicts_until_terminal() {
    let (state, app, token, tmp) = setup().await;
    let srpm = make_srpm(&tmp, "dup-pkg-1.0-1.fc42.src.rpm").await;
    let body = serde_json::json!({
        "product": "dedop",
        "srpms": [srpm.to_str().unwrap()]
    });

    let (status, json) = post_json(&app, &token, "/api/v1/builds", body.clone()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "first submit body: {json}");
    let ids = json["ids"].as_array().unwrap();
    assert_eq!(ids.len(), 1);

    let (status, json) = post_json(&app, &token, "/api/v1/builds", body.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT, "duplicate body: {json}");
    assert_eq!(json["error"], "conflict", "envelope error code: {json}");
    let msg = json["message"].as_str().unwrap();
    assert!(
        msg.contains("dup-pkg-1"),
        "conflict message must name the pkg: {msg}"
    );
    assert!(
        msg.contains("already active"),
        "conflict message must state the conflict: {msg}"
    );
    assert!(
        msg.contains("cancel it before resubmitting"),
        "conflict message must state the next step: {msg}"
    );

    sqlx::query("UPDATE builds SET phase = 'cancelled'")
        .execute(state.state_store.pool())
        .await
        .unwrap();
    let (status, json) = post_json(&app, &token, "/api/v1/builds", body).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "resubmit after terminal phase: {json}"
    );
}

/// 单请求多 arch（同 SRPM 两 arch）不自误伤：去重检查只在 insert 前对 DB 既有活跃集做一次，fan-out 同 pkg 多行不互撞 → 202 且 ids=arch 数；再提交（两 arch 行已活跃）→ 409。
#[tokio::test]
async fn multi_arch_submission_does_not_self_conflict() {
    let (_state, app, token, tmp) = setup().await;
    let srpm = make_srpm(&tmp, "fan-out-2.0-1.fc42.src.rpm").await;
    let body = serde_json::json!({
        "product": "dedop",
        "srpms": [srpm.to_str().unwrap()],
        "arch_list": ["x86_64", "aarch64"]
    });

    let (status, json) = post_json(&app, &token, "/api/v1/builds", body.clone()).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "multi-arch single request must not self-conflict: {json}"
    );
    assert_eq!(
        json["ids"].as_array().unwrap().len(),
        2,
        "ids count must equal arch count: {json}"
    );

    let (status, json) = post_json(&app, &token, "/api/v1/builds", body).await;
    assert_eq!(status, StatusCode::CONFLICT, "second submit: {json}");
    assert!(
        json["message"].as_str().unwrap().contains("fan-out-2"),
        "conflict message: {json}"
    );
}

/// JSON 提交 body 上限 2MB：超限 413 + 标准错误信封（error=payload_too_large）；小 JSON 仍 202。
#[tokio::test]
async fn oversized_json_submit_returns_413_envelope() {
    let (_state, app, token, tmp) = setup().await;
    let srpm = make_srpm(&tmp, "oversize-1.0-1.fc42.src.rpm").await;

    let small = serde_json::json!({
        "product": "dedop",
        "srpms": [srpm.to_str().unwrap()]
    });
    let (status, json) = post_json(&app, &token, "/api/v1/builds", small).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "small JSON submit body: {json}"
    );

    // >2MB body：Json extractor 读体阶段被 per-request DefaultBodyLimit 掐断 → 413 信封（非 400 语法错、非路由级 ~1GB multipart 上限的裸 413 文本）。
    let mut oversized = String::with_capacity(3 * 1024 * 1024 + 64);
    oversized.push_str("{\"product\":\"dedop\",\"srpms\":[\"");
    oversized.push_str(&"a".repeat(3 * 1024 * 1024));
    oversized.push_str("\"]}");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/builds")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(oversized))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "413 body: {json}");
    assert_eq!(
        json["error"], "payload_too_large",
        "envelope error code: {json}"
    );
    let msg = json["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("2097152"),
        "413 message must name the byte limit: {msg}"
    );
}

/// rebuild 重放同 NVR 时该 pkg 活跃 → 409（与 submit 入口同口径）。
#[tokio::test]
async fn rebuild_same_active_nvr_conflicts() {
    let (_state, app, token, tmp) = setup().await;
    let srpm = make_srpm(&tmp, "rebuild-dup-1.0-1.fc42.src.rpm").await;
    let body = serde_json::json!({
        "product": "dedop",
        "srpms": [srpm.to_str().unwrap()]
    });

    let (status, json) = post_json(&app, &token, "/api/v1/builds", body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "submit body: {json}");
    let task_id = json["task_id"].as_i64().unwrap();

    let (status, json) = post_json(
        &app,
        &token,
        &format!("/api/v1/tasks/{task_id}/rebuild"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "rebuild body: {json}");
    assert_eq!(json["error"], "conflict", "envelope error code: {json}");
    assert!(
        json["message"].as_str().unwrap().contains("rebuild-dup-1"),
        "conflict message must name the pkg: {json}"
    );
}

/// 回归钉（N-V-R 真名去重）：同一包换文件名重复提交，JSON 入口两道查重
/// （预检 NEVR + insert 事务内 pkg_name）都必须按 header 真名拦下 409。
#[tokio::test]
async fn json_same_nevr_different_filename_conflicts() {
    let (state, app, token, tmp) = setup().await;
    let _ = &state;
    // 判别形态：两次提交的文件名均不含真名 NEVR（真包为 dup-a-1），
    // 锁死"去重键=header N-V-R 而非文件名"的语义：若落库键回退为文件名
    // 派生，staged-a/staged-b 两键互不相同、二次提交不再 409——本测试将红。
    let srpm_a = make_srpm(&tmp, "dup-a-1.0-1.fc42.src.rpm").await;
    let staged_a = tmp.path().join("uploads").join("staged-a.src.rpm");
    std::fs::copy(&srpm_a, &staged_a).unwrap();
    let body = serde_json::json!({
        "product": "dedop",
        "srpms": [staged_a.to_str().unwrap()]
    });
    let (status, json) = post_json(&app, &token, "/api/v1/builds", body.clone()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "first: {json}");

    // 换个文件名放同一 NEVR 的包
    let staged_b = tmp.path().join("uploads").join("staged-b.src.rpm");
    std::fs::copy(&srpm_a, &staged_b).unwrap();
    let body = serde_json::json!({
        "product": "dedop",
        "srpms": [staged_b.to_str().unwrap()]
    });
    let (status, json) = post_json(&app, &token, "/api/v1/builds", body).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "same-NEVR rename resubmit must 409: {json}"
    );
    assert!(
        json.to_string().contains("dup-a"),
        "conflict message must name the real N-V-R: {json}"
    );
}
