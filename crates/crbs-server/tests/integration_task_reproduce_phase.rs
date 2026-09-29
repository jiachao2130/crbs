// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! reproduce 服务端 phase 校验集成测试：仅全部子构建 succeeded 的
//! task 可复现（与本地 CLI `crbs build --reproduce` 口径对齐）。

// 测试辅助函数不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::ServerConfig;
use crbs_core::{BuildInsert, TaskInsert};
use crbs_server::server::state::AppState;
use crbs_server::server::{create_test_app_with_auth, seed_user_token_for_test};

mod common;

const USER: &str = "repro-admin";

async fn setup() -> (Arc<AppState>, axum::Router, String, tempfile::TempDir) {
    let _ = common::TEST_CONFIG_DIR.path();
    crbs_server::test_support::init_test_logging();
    let (state_store, tmp) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        state_store,
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let token = seed_user_token_for_test(&app_state.state_store, USER, "admin")
        .await
        .expect("seed admin token");
    let app = create_test_app_with_auth(app_state.clone());
    (app_state, app, token, tmp)
}

/// 构造带单子构建的可复现档案：task（request_json + result_dir + source SRPM）
/// 外加指定 phase 子构建，返回 (task_id, build_id)。task phase 随子构建取值：
/// 非终态同值承接、终态一律钉 succeeded（终态子构建挂终态 task，
/// insert_build 守卫只拒非终态子构建）。
async fn seed_task_with_child(
    state: &AppState,
    tmp: &tempfile::TempDir,
    child_phase: &str,
) -> (i64, i64) {
    let task_phase = match child_phase {
        "building" | "assigned" | "pending" => child_phase,
        _ => "succeeded",
    };
    let opts_json = serde_json::to_string(&crbs_core::BuildOptions::default()).unwrap();
    let task_dir = tmp.path().join("results").join("src");

    let task_id = state
        .state_store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "repro-1.0-1",
            user: USER,
            phase: task_phase,
            result_dir: Some(task_dir.to_str().unwrap()),
            request_json: Some(&opts_json),
            ..Default::default()
        })
        .await
        .unwrap();
    let source = task_dir.join("source");
    tokio::fs::create_dir_all(&source).await.unwrap();
    tokio::fs::write(source.join("repro-1.0-1.src.rpm"), b"fake-srpm")
        .await
        .unwrap();

    let build_id = state
        .state_store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "repro-1.0-1",
            phase: child_phase,
            backend: "nspawn",
            user: USER,
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    (task_id, build_id)
}

async fn post_reproduce(
    app: &axum::Router,
    token: &str,
    task_id: i64,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/tasks/{task_id}/reproduce"))
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// 进行中子构建（building/pending/assigned）→ 409，文案含 "still in progress"
/// 与 child build id（pending/assigned 未开跑/未跑完，同属进行中）。每 phase
/// 独立 setup：同 product+pkg+arch 活跃构建去重，同一 store 连插三个会被 409 拒。
#[tokio::test]
async fn reproduce_in_progress_child_conflicts_with_progress_message() {
    for phase in ["building", "pending", "assigned"] {
        let (state, app, token, tmp) = setup().await;
        let (task_id, build_id) = seed_task_with_child(&state, &tmp, phase).await;

        let (status, json) = post_reproduce(&app, &token, task_id).await;
        assert_eq!(status, StatusCode::CONFLICT, "{phase} body: {json}");
        let msg = json["message"].as_str().unwrap();
        assert!(
            msg.contains(&format!(
                "task {task_id} is still in progress (child build {build_id})"
            )),
            "{phase} branch message must name task and child: {msg}"
        );
    }
}

/// 非 succeeded 终态子构建（钉 failed 一例）→ 409，文案含 "has status '<phase>'"。
#[tokio::test]
async fn reproduce_non_succeeded_child_conflicts_with_status_message() {
    let (state, app, token, tmp) = setup().await;
    for phase in ["failed"] {
        let (task_id, build_id) = seed_task_with_child(&state, &tmp, phase).await;
        let (status, json) = post_reproduce(&app, &token, task_id).await;
        assert_eq!(status, StatusCode::CONFLICT, "{phase} body: {json}");
        let msg = json["message"].as_str().unwrap();
        assert!(
            msg.contains(&format!(
                "task {task_id} child build {build_id} has status '{phase}'"
            )),
            "{phase} branch message must quote the status: {msg}"
        );
        assert!(
            msg.contains("only succeeded builds can be reproduced"),
            "{phase} branch message must state the rule: {msg}"
        );
    }
}

/// 无子构建的 task → 409 "has no child builds"。
#[tokio::test]
async fn reproduce_task_without_children_conflicts() {
    let (state, app, token, tmp) = setup().await;
    let opts_json = serde_json::to_string(&crbs_core::BuildOptions::default()).unwrap();
    let task_id = state
        .state_store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "empty-1.0-1",
            user: USER,
            phase: "succeeded",
            result_dir: Some(tmp.path().join("results").join("empty").to_str().unwrap()),
            request_json: Some(&opts_json),
            ..Default::default()
        })
        .await
        .unwrap();

    let (status, json) = post_reproduce(&app, &token, task_id).await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {json}");
    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .contains(&format!("task {task_id} has no child builds")),
        "empty-children message: {json}"
    );
}

/// succeeded 子构建无磁盘 build_packages.json → phase 门放行，落回
/// "no reproducible child builds" 409（错误分层不受影响）。
#[tokio::test]
async fn reproduce_succeeded_child_without_manifest_keeps_layered_error() {
    let (state, app, token, tmp) = setup().await;
    let (task_id, _build_id) = seed_task_with_child(&state, &tmp, "succeeded").await;

    let (status, json) = post_reproduce(&app, &token, task_id).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "missing-manifest path stays a conflict: {json}"
    );
    let msg = json["message"].as_str().unwrap();
    assert!(
        msg.contains("no reproducible child builds"),
        "existing layering must surface manifest-missing message: {msg}"
    );
    assert!(
        !msg.contains("only succeeded builds"),
        "phase gate must not fire for succeeded children: {msg}"
    );
}

/// 混合成败任务 → succeeded-only 扇出：202 建重放任务，子构建只含
/// succeeded 来源（failed 子构建不触发整体 409、也不进重放任务）。
#[tokio::test]
async fn reproduce_mixed_task_fans_out_succeeded_only() {
    let (state, app, token, _tmp) = setup().await;
    let store = &state.state_store;

    // task：request_json 带 target（假字节 SRPM 跳过 arch 探针）+ result_dir
    // 钉在产品 result root 下（manifest / anchor / source 布局与其重合，同
    // replay.rs 种子形态）。
    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "repro-1.0-1",
            user: USER,
            phase: "succeeded",
            request_json: Some(r#"{"target":"x86_64"}"#),
            ..Default::default()
        })
        .await
        .unwrap();
    let result_root = state.result_dir_for_or_default("fedora").await;
    let task_dir = result_root.join(task_id.to_string());
    sqlx::query("UPDATE tasks SET result_dir = $1 WHERE id = $2")
        .bind(task_dir.display().to_string())
        .bind(task_id)
        .execute(store.pool())
        .await
        .unwrap();
    let source_dir = task_dir.join("source");
    tokio::fs::create_dir_all(&source_dir).await.unwrap();
    tokio::fs::write(source_dir.join("repro-1.0-1.src.rpm"), b"fake-srpm")
        .await
        .unwrap();

    let ok_build = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "repro-1.0-1",
            phase: "succeeded",
            backend: "nspawn",
            user: USER,
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    // succeeded 子构建的 manifest + anchor 夹具（resolve_replay_anchors 探头）。
    let ok_dir = task_dir.join("x86_64").join(ok_build.to_string());
    tokio::fs::create_dir_all(&ok_dir).await.unwrap();
    tokio::fs::write(ok_dir.join("build_packages.json"), b"[]")
        .await
        .unwrap();
    tokio::fs::create_dir_all(ok_dir.join("RPMS"))
        .await
        .unwrap();
    tokio::fs::write(
        ok_dir.join("RPMS").join("anchor.rpm"),
        include_bytes!("../src/server/replay/fixtures/replay_anchor.rpm"),
    )
    .await
    .unwrap();

    let failed_build = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "repro-1.0-1",
            phase: "failed",
            backend: "nspawn",
            user: USER,
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    let _ = failed_build;

    let (status, json) = post_reproduce(&app, &token, task_id).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "mixed task must fan out succeeded-only: {json}"
    );
    let ids: Vec<i64> = json["ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_i64().unwrap())
        .collect();
    assert_eq!(ids.len(), 1, "only the succeeded child fans out: {json}");
    let source = store.get_build_reproduce_source(ids[0]).await.unwrap();
    assert_eq!(
        source,
        Some(ok_build),
        "replay build must trace to the succeeded source build"
    );
}

/// reproduce 继承放置契约：源任务 request_json 携带 min_* → 新
/// 复现子构建 req_min_* 落列同值、响应回显物化 KB（重放解析与 reproduce
/// fan-out 物化同源链路）。
#[tokio::test]
async fn reproduce_child_builds_inherit_req_min_from_request_json() {
    let (state, app, token, _tmp) = setup().await;
    let store = &state.state_store;

    // request_json 带 target（假字节 SRPM 跳过 arch 探针）+ 声明三维。
    let task_id = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "repro-1.0-1",
            user: USER,
            phase: "succeeded",
            request_json: Some(
                r#"{"target":"x86_64","min_mem":"4G","min_disk":"2T","min_ncpu":8}"#,
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    let result_root = state.result_dir_for_or_default("fedora").await;
    let task_dir = result_root.join(task_id.to_string());
    sqlx::query("UPDATE tasks SET result_dir = $1 WHERE id = $2")
        .bind(task_dir.display().to_string())
        .bind(task_id)
        .execute(store.pool())
        .await
        .unwrap();
    let source_dir = task_dir.join("source");
    tokio::fs::create_dir_all(&source_dir).await.unwrap();
    tokio::fs::write(source_dir.join("repro-1.0-1.src.rpm"), b"fake-srpm")
        .await
        .unwrap();

    let ok_build = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "repro-1.0-1",
            phase: "succeeded",
            backend: "nspawn",
            user: USER,
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    let ok_dir = task_dir.join("x86_64").join(ok_build.to_string());
    tokio::fs::create_dir_all(&ok_dir).await.unwrap();
    tokio::fs::write(ok_dir.join("build_packages.json"), b"[]")
        .await
        .unwrap();
    tokio::fs::create_dir_all(ok_dir.join("RPMS"))
        .await
        .unwrap();
    tokio::fs::write(
        ok_dir.join("RPMS").join("anchor.rpm"),
        include_bytes!("../src/server/replay/fixtures/replay_anchor.rpm"),
    )
    .await
    .unwrap();

    let (status, json) = post_reproduce(&app, &token, task_id).await;
    assert_eq!(status, StatusCode::ACCEPTED, "body: {json}");
    // 响应回显物化值：min_mem 4G = 4 GiB KB、min_disk 2T = 2 TiB KB、ncpu 原样。
    assert_eq!(
        json["req_min_mem_kb"],
        serde_json::json!(4i64 * 1024 * 1024)
    );
    assert_eq!(
        json["req_min_disk_kb"],
        serde_json::json!(2i64 * 1024 * 1024 * 1024)
    );
    assert_eq!(json["req_min_ncpu"], serde_json::json!(8));

    let ids: Vec<i64> = json["ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_i64().unwrap())
        .collect();
    assert_eq!(ids.len(), 1, "single succeeded child fans out: {json}");
    for id in &ids {
        let (mem, ncpu, disk): (Option<i64>, Option<i64>, Option<i64>) = sqlx::query_as(
            "SELECT req_min_mem_kb, req_min_ncpu, req_min_disk_kb FROM builds WHERE id = $1",
        )
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            (mem, ncpu, disk),
            (
                Some(4i64 * 1024 * 1024),
                Some(8),
                Some(2i64 * 1024 * 1024 * 1024)
            ),
            "reproduced build {id} must inherit the declared placement floors"
        );
    }
}
