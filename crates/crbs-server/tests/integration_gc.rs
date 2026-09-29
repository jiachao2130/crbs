// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 结果 GC 实删集成测试（会删用户数据的路径）：走真实 HTTP 端点触发。GC 后台
//! task 先 `CrbsConfig::load_async()` 再 pin 到 server root（`AppState.crbs_root`），
//! 安全根随其派生，候选目录须布置在 `{server_root}/results` 下。

// 文件级放行：测试辅助函数（seed_* 等）不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::ServerConfig;
use crbs_core::BuildInsert;
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;

mod common;

const PRODUCT: &str = "gcprod";

/// 最小可解析 TOML；根产品必须声明至少一个 repo（chain-resolve 出口校验）。
const SAMPLE_TOML: &str = "\
base_packages = [\"bash\", \"rpm-build\"]\n\
arches = [\"x86_64\"]\n\
\n\
[[repos]]\n\
name = \"base\"\n\
baseurl = \"http://example.com/base/$basearch\"\n\
gpgcheck = false\n\
";

async fn setup() -> (Arc<AppState>, axum::Router, String, tempfile::TempDir) {
    setup_with(|_| {}).await
}

/// [`setup`] 的可定制变体：包 Arc 前修改 AppState（如 result_dir/artifact_dir 覆盖；`Arc<AppState>` 不可外部可变借用，须构造期注入）。
async fn setup_with(
    customize: impl FnOnce(&mut AppState),
) -> (Arc<AppState>, axum::Router, String, tempfile::TempDir) {
    // GC 后台 task 经 CrbsConfig::load_async() 读全局配置：CRBS_CONFIG_DIR 须先落可写 tempdir。
    let _ = common::TEST_CONFIG_DIR.path();
    crbs_server::test_support::init_test_logging();

    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let mut app_state = AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    );
    customize(&mut app_state);
    let app_state = Arc::new(app_state);
    // server 结果根 = {AppState.crbs_root}/results：GC task 把全局配置 pin 到 server root
    //（显式 result_dir 清空、随 root 派生），候选须在其下；crbs.toml 的 result_dir 属引擎世界不参与求根。
    let result_root = tmp.path().join("results");
    tokio::fs::create_dir_all(&result_root).await.unwrap();

    let app = create_test_app_with_auth(app_state.clone());
    let op_token = seed_user_token_for_test(&app_state.state_store, "gc-operator", "operator")
        .await
        .unwrap();

    // 候选要求产品在 products 表中，否则 skipped_invalid 跳过（不删）：seed 官方 public 产品。
    seed_product(&app_state, PRODUCT, None, "public").await;

    (app_state, app, op_token, tmp)
}

/// seed 一个产品（官方：owner None；私人：owner Some + private）。
async fn seed_product(
    state: &AppState,
    name: &str,
    owner_id: Option<i64>,
    visibility: &str,
) -> i64 {
    let config = crbs_core::config::ProductConfig::from_str(SAMPLE_TOML).unwrap();
    state
        .state_store
        .create_product(crbs_core::CreateProductInput {
            name,
            display_name: None,
            owner_id,
            parent_id: None,
            visibility,
            config: &config,
            changed_by_user_id: None,
            reason: Some("gc integration test seed"),
        })
        .await
        .unwrap()
}

/// 40 天前完成的 UTC 时间戳（默认 grace 720h 下必过期）。
fn expired_at() -> String {
    (chrono::Utc::now() - chrono::Duration::days(40))
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string()
}

/// POST /api/v1/gc 实删 results 并轮询到终态，返回 GC 状态 JSON。
async fn trigger_results_gc(app: &axum::Router, op_token: &str) -> serde_json::Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/gc")
                .header("Authorization", format!("Bearer {}", op_token))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({"dry_run": false, "results": true}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let task_id = json["task_id"].as_str().unwrap().to_string();

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/gc/{}", task_id))
                        .header("Authorization", format!("Bearer {}", op_token))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if json["status"] != "running" {
                return json;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("gc task must reach terminal state within 10s")
}

/// 造一个已完成构建：result_dir 在指定 result_root 下（至少二级子目录）、内含一个文件。
async fn seed_finished_build(
    state: &AppState,
    result_root: &std::path::Path,
    pkg: &str,
    completed_at: &str,
) -> (i64, std::path::PathBuf) {
    seed_finished_build_for(state, PRODUCT, result_root, pkg, completed_at).await
}

/// [`seed_finished_build`] 的多产品变体。
async fn seed_finished_build_for(
    state: &AppState,
    product: &str,
    result_root: &std::path::Path,
    pkg: &str,
    completed_at: &str,
) -> (i64, std::path::PathBuf) {
    let build_id = state
        .state_store
        .insert_build(BuildInsert {
            product,
            pkg_name: pkg,
            phase: "succeeded",
            backend: "chroot",
            user: "gc-tester",
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, product, pkg).await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let dir = result_root
        .join(product)
        .join(pkg)
        .join(format!("20260825-000000-{build_id}"));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    tokio::fs::write(dir.join("build.log"), b"stale result payload")
        .await
        .unwrap();

    // result_dir + completed_at 都齐后才是 GC 候选（候选 SQL 的两个 NOT NULL 条件）。
    let dir_str = dir.to_string_lossy().to_string();
    sqlx::query("UPDATE builds SET result_dir = $1, completed_at = $2 WHERE id = $3")
        .bind(&dir_str)
        .bind(completed_at)
        .bind(build_id)
        .execute(state.state_store.pool())
        .await
        .unwrap();

    (build_id, dir)
}

/// 在盘产物行（on_disk=1），供 GC 后断言翻 0。
async fn seed_artifact_row(state: &AppState, build_id: i64) {
    sqlx::query(
        "INSERT INTO build_artifacts \
         (build_id, relative_path, kind, size_bytes, sha256, on_disk, created_at) \
         VALUES ($1, 'hello-1.0-1.x86_64/hello-1.0-1.x86_64.rpm', 'rpm', 123, \
                 '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 1, \
                 '2026-01-01 00:00:00')",
    )
    .bind(build_id)
    .execute(state.state_store.pool())
    .await
    .unwrap();
}

/// POST /api/v1/gc 实删结果目录 → 过期目录被删、不过期保留、summary 正确。
#[tokio::test]
async fn gc_results_deletes_expired_dir_and_keeps_fresh() {
    let (state, app, op_token, _tmp) = setup().await;
    let result_root = state.crbs_root.join("results");

    // 默认 result_gc_grace_hours = 720（30 天）：40 天前过期，现在完成的不动。
    let expired_at = (chrono::Utc::now() - chrono::Duration::days(40))
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string();
    let fresh_at = chrono::Utc::now()
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string();
    let (expired_id, expired_dir) =
        seed_finished_build(&state, &result_root, "old-pkg", &expired_at).await;
    let (fresh_id, fresh_dir) =
        seed_finished_build(&state, &result_root, "new-pkg", &fresh_at).await;

    // 模拟 report_logs 的 hub 日志副本 `{crbs_root}/artifacts/{build_id}/`（pinned 配置的
    // crbs_root = AppState.crbs_root，与 artifact_dir() 同源）：被 GC build 联动删除，未 GC 保留。
    let artifacts_root = state.crbs_root.join("artifacts");
    for id in [expired_id, fresh_id] {
        let dir = artifacts_root.join(id.to_string());
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("build.log"), b"hub-side log copy")
            .await
            .unwrap();
    }

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/gc")
                .header("Authorization", format!("Bearer {}", op_token))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({"dry_run": false, "results": true}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let task_id = json["task_id"].as_str().unwrap().to_string();

    let status_json = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/gc/{}", task_id))
                        .header("Authorization", format!("Bearer {}", op_token))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if json["status"] != "running" {
                return json;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("gc task must reach terminal state within 10s");

    assert_eq!(status_json["status"], "succeeded", "body: {status_json}");
    let results = &status_json["summary"]["results"];
    assert_eq!(results["removed"], 1, "body: {status_json}");
    assert_eq!(results["would_remove"], 0);
    assert!(
        results["bytes"].as_u64().unwrap_or(0) > 0,
        "removed bytes must be positive, body: {status_json}"
    );

    assert!(
        !tokio::fs::try_exists(&expired_dir).await.unwrap(),
        "expired result dir must be deleted: {}",
        expired_dir.display()
    );
    assert!(
        tokio::fs::try_exists(&fresh_dir).await.unwrap(),
        "fresh result dir must survive: {}",
        fresh_dir.display()
    );

    let expired_record = state
        .state_store
        .get_build(expired_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(expired_record.result_dir, None);
    let fresh_record = state
        .state_store
        .get_build(fresh_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        fresh_record.result_dir.as_deref(),
        Some(fresh_dir.to_str().unwrap())
    );

    assert!(
        !tokio::fs::try_exists(artifacts_root.join(expired_id.to_string()))
            .await
            .unwrap(),
        "artifact log dir of GC'd build must be removed"
    );
    assert!(
        tokio::fs::try_exists(artifacts_root.join(fresh_id.to_string()))
            .await
            .unwrap(),
        "artifact log dir of kept build must survive"
    );
}

/// server.toml 显式 result_dir 部署：pin 后按 AppState 回填显式根，过期候选实删
///（不回填则安全根退化 {server_root}/results，全候选 skipped_invalid 静默零回收）。
#[tokio::test]
async fn gc_results_honors_server_config_result_dir() {
    let explicit = tempfile::tempdir().unwrap();
    let explicit_root = explicit.path().join("results");
    let (state, app, op_token, _tmp) = setup_with(|app| {
        app.server_config.result_dir = Some(explicit_root.clone());
    })
    .await;

    let (build_id, dir) =
        seed_finished_build(&state, &explicit_root, "old-pkg", &expired_at()).await;

    let status_json = trigger_results_gc(&app, &op_token).await;
    assert_eq!(status_json["status"], "succeeded", "body: {status_json}");
    let results = &status_json["summary"]["results"];
    assert!(
        results["removed"].as_u64().unwrap_or(0) >= 1,
        "body: {status_json}"
    );

    assert!(
        !tokio::fs::try_exists(&dir).await.unwrap(),
        "显式根下的过期目录必须被删除: {}",
        dir.display()
    );
    let record = state
        .state_store
        .get_build(build_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.result_dir, None);
}

/// 变体：显式 result_dir 配在 crbs.toml 世界（AppState.crbs_config），server.toml 未设时 or_else 兜底。
#[tokio::test]
async fn gc_results_honors_crbs_config_result_dir() {
    let explicit = tempfile::tempdir().unwrap();
    let explicit_root = explicit.path().join("results");
    let (state, app, op_token, _tmp) = setup_with(|app| {
        app.crbs_config.result_dir = Some(explicit_root.clone());
    })
    .await;

    let (build_id, dir) =
        seed_finished_build(&state, &explicit_root, "old-pkg", &expired_at()).await;

    let status_json = trigger_results_gc(&app, &op_token).await;
    assert_eq!(status_json["status"], "succeeded", "body: {status_json}");
    assert!(
        status_json["summary"]["results"]["removed"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "body: {status_json}"
    );

    assert!(
        !tokio::fs::try_exists(&dir).await.unwrap(),
        "crbs.toml 显式根下的过期目录必须被删除: {}",
        dir.display()
    );
    let record = state
        .state_store
        .get_build(build_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.result_dir, None);
}

/// 私人产品（提交链路允许落 result_dir）可被 GC 回收，防 official-only 解析重新拒收致目录与行永不回收。
#[tokio::test]
async fn gc_results_recovers_private_product_result_dir() {
    let (state, app, op_token, _tmp) = setup().await;

    let owner = state
        .state_store
        .create_user("gc-owner", "builder")
        .await
        .unwrap();
    seed_product(&state, "gcpriv", Some(owner), "private").await;

    let result_root = state.crbs_root.join("results");
    let (build_id, dir) =
        seed_finished_build_for(&state, "gcpriv", &result_root, "priv-pkg", &expired_at()).await;
    seed_artifact_row(&state, build_id).await;

    let status_json = trigger_results_gc(&app, &op_token).await;
    assert_eq!(status_json["status"], "succeeded", "body: {status_json}");
    assert_eq!(
        status_json["summary"]["results"]["removed"], 1,
        "body: {status_json}"
    );

    assert!(
        !tokio::fs::try_exists(&dir).await.unwrap(),
        "私人产品的过期目录必须被删除: {}",
        dir.display()
    );
    let record = state
        .state_store
        .get_build(build_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.result_dir, None);
    let on_disk: i64 =
        sqlx::query_scalar("SELECT on_disk FROM build_artifacts WHERE build_id = $1")
            .bind(build_id)
            .fetch_one(state.state_store.pool())
            .await
            .unwrap();
    assert_eq!(on_disk, 0, "私人产品产物行必须翻 on_disk=0");
}

/// 已删产品的遗留目录可 GC 回收：删除段解析失败回退全局安全根（否则目录与行永不回收、package cache 引用集永久 pin）。
#[tokio::test]
async fn gc_results_recovers_deleted_product_result_dir() {
    let (state, app, op_token, _tmp) = setup().await;

    let gone_id = seed_product(&state, "gcgone", None, "public").await;
    let result_root = state.crbs_root.join("results");
    let (build_id, dir) =
        seed_finished_build_for(&state, "gcgone", &result_root, "gone-pkg", &expired_at()).await;

    // 删产品：succeeded 行与 product TEXT 保留（取消只针对活跃 phase）、product_id 置 NULL（FK ON DELETE SET NULL）。
    state.state_store.delete_product(gone_id).await.unwrap();

    let status_json = trigger_results_gc(&app, &op_token).await;
    assert_eq!(status_json["status"], "succeeded", "body: {status_json}");
    assert_eq!(
        status_json["summary"]["results"]["removed"], 1,
        "body: {status_json}"
    );

    assert!(
        !tokio::fs::try_exists(&dir).await.unwrap(),
        "已删产品的遗留目录必须被删除（回退全局根）: {}",
        dir.display()
    );
    let record = state
        .state_store
        .get_build(build_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.result_dir, None);
}

/// 显式 result_root 下私人产品两次构建 POST diff 200（防世界配置不回填 / official-only 解析对合法 result_dir 拒 500）。
#[tokio::test]
async fn diff_build_accepts_dirs_under_explicit_result_root() {
    let explicit = tempfile::tempdir().unwrap();
    let explicit_root = explicit.path().join("results");
    let (state, app, op_token, _tmp) = setup_with(|app| {
        app.server_config.result_dir = Some(explicit_root.clone());
    })
    .await;

    let owner = state
        .state_store
        .create_user("diff-owner", "builder")
        .await
        .unwrap();
    seed_product(&state, "diffpriv", Some(owner), "private").await;

    let (left_id, _left_dir) =
        seed_finished_build_for(&state, "diffpriv", &explicit_root, "pkg", &expired_at()).await;
    let (right_id, _right_dir) =
        seed_finished_build_for(&state, "diffpriv", &explicit_root, "pkg", &expired_at()).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/builds/{}/diff?against={}",
                    left_id, right_id
                ))
                .header("Authorization", format!("Bearer {}", op_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["left"]["id"].as_i64(), Some(left_id));
    assert_eq!(json["right"]["id"].as_i64(), Some(right_id));
}

/// server.toml artifact_dir 覆盖：GC 联动删 worker 日志副本按覆盖根定位（防固定拼 {crbs_root}/artifacts 致副本永不清理）。
#[tokio::test]
async fn gc_artifact_dir_override_directs_log_copy_cleanup() {
    let override_root = tempfile::tempdir().unwrap();
    let (state, app, op_token, _tmp) = setup_with(|app| {
        app.server_config.artifact_dir = Some(override_root.path().to_path_buf());
    })
    .await;

    let result_root = state.crbs_root.join("results");
    let (expired_id, _dir) =
        seed_finished_build(&state, &result_root, "old-pkg", &expired_at()).await;

    // 双副本：覆盖根（report_logs 实际落盘处）+ 默认根（诱饵，必须原样保留）。
    let override_copy = override_root.path().join(expired_id.to_string());
    tokio::fs::create_dir_all(&override_copy).await.unwrap();
    tokio::fs::write(override_copy.join("build.log"), b"override copy")
        .await
        .unwrap();
    let default_copy = state
        .crbs_root
        .join("artifacts")
        .join(expired_id.to_string());
    tokio::fs::create_dir_all(&default_copy).await.unwrap();
    tokio::fs::write(default_copy.join("build.log"), b"default copy")
        .await
        .unwrap();

    let status_json = trigger_results_gc(&app, &op_token).await;
    assert_eq!(status_json["status"], "succeeded", "body: {status_json}");
    assert_eq!(
        status_json["summary"]["results"]["removed"], 1,
        "body: {status_json}"
    );

    assert!(
        !tokio::fs::try_exists(&override_copy).await.unwrap(),
        "覆盖根下的 worker 日志副本必须被联动删除"
    );
    assert!(
        tokio::fs::try_exists(&default_copy).await.unwrap(),
        "默认根 {{crbs_root}}/artifacts 不受覆盖影响"
    );
}
