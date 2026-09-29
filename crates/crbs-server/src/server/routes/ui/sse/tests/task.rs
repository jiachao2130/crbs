// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 任务 SSE 测试：子构建阶段聚合与可见性吊销。

use super::common::*;
use super::*;

#[tokio::test]
async fn task_sse_streams_initial_phase_for_terminal_task() {
    let (app, _tmp) = test_app_state().await;
    let id = app
        .state_store
        .insert_task(crbs_core::TaskInsert {
            product: "fedora",
            pkg_name: "pkg",
            user: "alice",
            user_id: None,
            phase: "failed",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();

    let response = task_sse(State(app), Path(id), axum::http::HeaderMap::new(), None)
        .await
        .unwrap()
        .into_response();
    assert_eq!(
        response
            .headers()
            .get("x-accel-buffering")
            .and_then(|v| v.to_str().ok()),
        Some("no"),
        "task SSE must disable reverse-proxy buffering"
    );
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    let retry_ms: u64 = text
        .lines()
        .find_map(|l| l.strip_prefix("retry: "))
        .expect("connect-time reconnect hint missing")
        .parse()
        .expect("retry hint must be a millisecond integer");
    assert!(
        (4000..=6000).contains(&retry_ms),
        "retry hint {retry_ms} outside jitter window [4000,6000]: {text}"
    );
    assert!(text.contains("event: task"));
    assert!(text.contains(r#""phase":"failed""#));
    // 无子构建时 children 为空数组（payload 契约）。
    assert!(text.contains(r#""children":[]"#));
}

/// children payload 契约：每个子构建带 id/phase/duration，终态后 duration 非空。
#[tokio::test]
async fn task_sse_streams_child_phase_and_duration_payload() {
    let (app, _tmp) = test_app_state().await;
    let (task_id, build_id) = insert_building_task_build(&app).await;
    // 子构建完成 → duration 写入（秒级四舍五入，测试内为 0）。
    app.state_store
        .complete_build(build_id, "succeeded", None)
        .await
        .unwrap();

    let response = task_sse(
        State(app),
        Path(task_id),
        axum::http::HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(text.contains("event: task"));

    let payload = text
        .lines()
        .find_map(|l| l.strip_prefix("data: "))
        .expect("sse data line");
    let value: serde_json::Value = serde_json::from_str(payload).expect("valid json payload");
    assert_eq!(value["phase"], "succeeded");
    let children = value["children"].as_array().expect("children array");
    assert_eq!(children.len(), 1);
    assert_eq!(children[0]["id"].as_i64(), Some(build_id));
    assert_eq!(children[0]["phase"], "succeeded");
    assert!(
        children[0]["duration"].is_number(),
        "completed child should carry a duration"
    );
}

/// children 查询 Err 容忍链：失败轮不降级空 children 推送（摘要行闪刷
/// "0 架构 · 成功 0 · 失败 0"）、不断流；恢复且签名变化后照常推送。注入：
/// RENAME 挪走 builds 表造真 DB Err，恢复即 RENAME 回（现场干净）。
#[tokio::test]
async fn task_sse_tolerates_child_summary_errors_and_resumes() {
    let (app, _tmp) = test_app_state().await;
    let (task_id, build_id) = insert_building_task_build(&app).await;

    let response = task_sse(
        State(app.clone()),
        Path(task_id),
        axum::http::HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();
    let mut rx = spawn_sse_body_reader(response.into_body());

    let first = recv_until(&mut rx, |t| t.contains(r#""children":[{"#), "initial push").await;
    assert!(first.contains("event: task"), "{first}");
    assert!(first.contains(r#""phase":"building""#), "{first}");

    sqlx::query("ALTER TABLE builds RENAME TO builds_test_backup")
        .execute(app.state_store.pool())
        .await
        .unwrap();
    // 写路径通知驱动下一轮（insert_task 广播）：children Err → 计入容忍、本轮不推送。
    app.state_store
        .insert_task(crbs_core::TaskInsert {
            product: "fedora",
            pkg_name: "noise",
            user: "alice",
            ..Default::default()
        })
        .await
        .unwrap();

    // 静默窗：错误轮不得推送（收到块 = 降级推送，失败）；通道关闭 =
    // 循环断流，同样失败；超时 = 无推送且连接仍在，期望形态。
    match tokio::time::timeout(std::time::Duration::from_millis(1500), rx.recv()).await {
        Err(_) => {}
        Ok(Some(chunk)) => {
            panic!("error round must not push a (degraded) payload: {chunk}")
        }
        Ok(None) => panic!("error round must not close the stream"),
    }

    sqlx::query("ALTER TABLE builds_test_backup RENAME TO builds")
        .execute(app.state_store.pool())
        .await
        .unwrap();
    app.state_store
        .mark_build_cancelled(build_id)
        .await
        .unwrap();

    let resumed = recv_until(
        &mut rx,
        |t| t.contains(r#""phase":"cancelled""#),
        "resumed push",
    )
    .await;
    assert!(
        resumed.contains("event: task"),
        "connection must survive the error round and resume: {resumed}"
    );
    assert!(
        resumed.contains(r#""phase":"cancelled""#),
        "children payload must carry the new signature after recovery: {resumed}"
    );
}

/// 同 [`build_sse_terminates_after_visibility_revoked_mid_stream`]，task SSE
/// 的复鉴权路径（独立循环，需各自有门）。
#[tokio::test]
async fn task_sse_terminates_after_visibility_revoked_mid_stream() {
    let (app, _tmp, _root) = app_with_result_root().await;
    let owner_id = app
        .state_store
        .create_user("owner", "builder")
        .await
        .unwrap();
    app.state_store
        .create_product(crbs_core::CreateProductInput {
            name: "flip-task",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: crbs_core::VISIBILITY_PUBLIC,
            config: &crbs_core::config::ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("sse recheck test"),
        })
        .await
        .unwrap();
    let id = app
        .state_store
        .insert_task(crbs_core::TaskInsert {
            product: "flip-task",
            pkg_name: "pkg",
            phase: "building",
            user: "alice",
            ..Default::default()
        })
        .await
        .unwrap();

    let flipper = app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        sqlx::query("UPDATE products SET visibility = 'private' WHERE name = $1")
            .bind("flip-task")
            .execute(flipper.state_store.pool())
            .await
            .unwrap();
    });

    let response = task_sse_with_poll(
        State(app),
        Path(id),
        axum::http::HeaderMap::new(),
        None,
        SsePollConfig {
            poll_interval: std::time::Duration::from_millis(20),
            visibility_recheck_interval: std::time::Duration::from_millis(40),
        },
    )
    .await
    .unwrap()
    .into_response();

    let data = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        collect_body_data(response.into_body()),
    )
    .await
    .expect("task SSE must terminate after product becomes private");
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(
        text.contains("event: task"),
        "should stream initial phase before revoke, got: {text}"
    );
}
