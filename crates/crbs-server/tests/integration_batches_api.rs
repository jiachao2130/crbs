// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 整仓重建批次 API 集成测试：operator 门禁、提交快速段 202 形态、
//! 详情聚合（轮次 / 失败分桶）、取消幂等、body 上限。
//!
//! 不跑真实枚举 / 下载（dnf 依赖，环境相关）：慢段失败路径由服务层单测
//! 覆盖（batches/prepare.rs、batches/plan.rs），这里只锁 HTTP 面契约。

// 整个文件是测试 crate：测试辅助函数（seed_* 等）不带 #[test] 属性，
// clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::ServerConfig;
use crbs_core::BatchInsert;
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;

mod common;

async fn setup() -> (
    Arc<AppState>,
    axum::Router,
    String,
    String,
    tempfile::TempDir,
) {
    let _ = common::TEST_CONFIG_DIR.path();
    crbs_server::test_support::init_test_logging();

    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let op = seed_user_token_for_test(&app_state.state_store, "batch-op", "operator")
        .await
        .unwrap();
    let viewer = seed_user_token_for_test(&app_state.state_store, "batch-viewer", "viewer")
        .await
        .unwrap();
    (app_state, app, op, viewer, tmp)
}

fn post_batches(token: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/batches")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// 门禁：viewer 对列表 / 提交 / 取消都是 403；匿名 401（protected 网关）。
#[tokio::test]
async fn batches_endpoints_require_operator() {
    let (_state, app, _op, viewer, _tmp) = setup().await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/batches")
                .header("Authorization", format!("Bearer {viewer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .clone()
        .oneshot(post_batches(
            &viewer,
            r#"{"product":"p","source_repo_url":"https://r"}"#.into(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 匿名：protected 网关 401。
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/batches")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/batches/1/cancel")
                .header("Authorization", format!("Bearer {viewer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// 前置校验失败（非法 scheme / 未知产品 / 非法 arch）同步 4xx，无批次落库。
#[tokio::test]
async fn create_batch_rejects_bad_input_without_batch_row() {
    let (state, app, op, _viewer, _tmp) = setup().await;

    // 非法 scheme：400。
    let resp = app
        .clone()
        .oneshot(post_batches(
            &op,
            r#"{"product":"p","source_repo_url":"ftp://h/r"}"#.into(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = json_body(resp).await;
    assert_eq!(v["error"], "validation_failed");

    // 未知产品：404。
    let resp = app
        .clone()
        .oneshot(post_batches(
            &op,
            r#"{"product":"ghost","source_repo_url":"https://r"}"#.into(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 非法 arch（信任边界白名单）：400。
    let resp = app
        .clone()
        .oneshot(post_batches(
            &op,
            r#"{"product":"p","source_repo_url":"https://r","arch_targets":["../evil"]}"#.into(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    assert_eq!(state.state_store.count_active_batches().await.unwrap(), 0);
}

/// 提交的 202 形态：快速段建行拿到 batch_id，慢段后台跑（本测试环境必然
/// 失败收口，不锁状态）；详情端点回完整聚合面。
#[tokio::test]
async fn create_batch_returns_202_with_id_and_detail_aggregates() {
    let (state, app, op, _viewer, _tmp) = setup().await;
    let product_id = state
        .state_store
        .create_product(crbs_core::CreateProductInput {
            name: "batchprod",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &crbs_core::config::ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("batches api test seed"),
        })
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(post_batches(
            &op,
            r#"{"product":"batchprod","source_repo_url":"file:///definitely/not/a/repo","on_failure":"abort","force_all":true}"#.into(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let v = json_body(resp).await;
    let batch_id = v["batch_id"].as_i64().expect("batch_id");
    assert_eq!(v["status"], "preparing");
    assert!(batch_id > 0);

    // 详情：批次面（product 名解析）+ 空轮次 / 空分桶的聚合形状。
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/batches/{batch_id}"))
                .header("Authorization", format!("Bearer {op}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["id"], batch_id);
    assert_eq!(v["product"], "batchprod");
    assert_eq!(v["on_failure"], "abort");
    assert_eq!(v["force_all"], true);
    assert!(v["rounds"].is_array());
    assert!(v["failures"].is_array());
    assert!(v["progress"].is_object());
    assert!(product_id > 0);

    // 列表：含本批次（id DESC 首行）。
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/batches?limit=10")
                .header("Authorization", format!("Bearer {op}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    let first = v["batches"][0].as_object().expect("at least one batch");
    assert_eq!(first["id"].as_i64(), Some(batch_id));
    assert_eq!(first["product"], "batchprod");
}

/// 详情的轮次 / 失败分桶聚合：seed 一个 running 批次带两轮与失败项，
/// 断言轮次计数与分桶排序。
#[tokio::test]
async fn batch_detail_buckets_failures_and_summarizes_rounds() {
    let (state, app, op, _viewer, _tmp) = setup().await;
    let product_id = state
        .state_store
        .create_product(crbs_core::CreateProductInput {
            name: "bucketprod",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &crbs_core::config::ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("buckets test seed"),
        })
        .await
        .unwrap();
    let batch = state
        .state_store
        .insert_batch(BatchInsert {
            product_id: Some(product_id),
            created_by: None,
            source_repo_url: "https://example.com/r",
            dist: None,
            arch_targets_json: None,
            on_failure: "continue",
            force_all: false,
            request_json: None,
        })
        .await
        .unwrap();
    state.state_store.set_batch_planning(batch).await.unwrap();
    state
        .state_store
        .insert_batch_items(
            batch,
            &[
                crbs_core::NewBatchItem {
                    pkg_name: "a",
                    srpm_nevra: None,
                    srpm_staging_path: None,
                    round: 0,
                },
                crbs_core::NewBatchItem {
                    pkg_name: "b",
                    srpm_nevra: None,
                    srpm_staging_path: None,
                    round: 1,
                },
            ],
        )
        .await
        .unwrap();
    state.state_store.set_batch_running(batch, 4).await.unwrap();
    state
        .state_store
        .insert_failed_batch_items(
            batch,
            &[
                crbs_core::FailedBatchItem {
                    pkg_name: "x",
                    srpm_nevra: None,
                    error_code: "srpm_download_failed",
                    error_message: "HTTP 503",
                },
                crbs_core::FailedBatchItem {
                    pkg_name: "y",
                    srpm_nevra: None,
                    error_code: "srpm_download_failed",
                    error_message: "HTTP 504",
                },
                crbs_core::FailedBatchItem {
                    pkg_name: "z",
                    srpm_nevra: None,
                    error_code: "disk_below_watermark",
                    error_message: "free space below watermark",
                },
            ],
        )
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/batches/{batch}"))
                .header("Authorization", format!("Bearer {op}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;

    // 两轮：round 0（1 pending + 3 failed）、round 1（1 pending）。
    let rounds = v["rounds"].as_array().unwrap();
    assert_eq!(rounds.len(), 2);
    assert_eq!(rounds[0]["round"], 0);
    assert_eq!(rounds[0]["pending"], 1);
    assert_eq!(rounds[0]["failed"], 3);
    assert_eq!(rounds[1]["round"], 1);
    assert_eq!(rounds[1]["pending"], 1);

    // 分桶按计数降序：srpm_download_failed(2) 在前。
    let failures = v["failures"].as_array().unwrap();
    assert_eq!(failures.len(), 2);
    assert_eq!(failures[0]["error_code"], "srpm_download_failed");
    assert_eq!(failures[0]["count"], 2);
    assert_eq!(failures[1]["count"], 1);

    // 未知批次：404。
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/batches/99999")
                .header("Authorization", format!("Bearer {op}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// 取消：preparing 批次可取消（200 cancelled）、幂等重取消 409。
#[tokio::test]
async fn cancel_batch_cancels_preparing_and_is_idempotent() {
    let (state, app, op, _viewer, _tmp) = setup().await;
    let product_id = state
        .state_store
        .create_product(crbs_core::CreateProductInput {
            name: "cancelprod",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &crbs_core::config::ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("cancel test seed"),
        })
        .await
        .unwrap();
    let batch = state
        .state_store
        .insert_batch(BatchInsert {
            product_id: Some(product_id),
            created_by: None,
            source_repo_url: "https://example.com/r",
            dist: None,
            arch_targets_json: None,
            on_failure: "continue",
            force_all: false,
            request_json: None,
        })
        .await
        .unwrap();

    let cancel_uri = format!("/api/v1/batches/{batch}/cancel");
    let cancel = |app: axum::Router, token: String| {
        let uri = cancel_uri.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };

    let resp = cancel(app.clone(), op.clone()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["batch_id"], batch);
    assert_eq!(v["status"], "cancelled");

    // 幂等：终态批次重取消 409。
    let resp = cancel(app.clone(), op.clone()).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // 审计：batch_cancel 落一条。
    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'batch_cancel' AND target = $1",
    )
    .bind(batch.to_string())
    .fetch_one(state.state_store.pool())
    .await
    .unwrap();
    assert_eq!(audited, 1, "one batch_cancel audit row");
}

/// body 上限：> 64KB 的提交体 413。
#[tokio::test]
async fn create_batch_body_over_limit_is_413() {
    let (_state, app, op, _viewer, _tmp) = setup().await;
    // 70KB 的合法 JSON 字符串值。
    let big = "x".repeat(70 * 1024);
    let body = format!(r#"{{"product":"p","source_repo_url":"{big}"}}"#);
    let resp = app.oneshot(post_batches(&op, body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
