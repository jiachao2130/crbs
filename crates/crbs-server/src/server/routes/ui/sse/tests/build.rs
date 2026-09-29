// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 构建 SSE 测试：阶段推送与可见性吊销。

use super::common::*;
use super::*;

#[tokio::test]
async fn build_sse_streams_initial_phase_for_terminal_build() {
    let (app, _tmp) = test_app_state().await;
    let id = app
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg",
            phase: "succeeded",
            backend: "chroot",
            user: "alice",
            task_id: Some(crate::test_support::seed_task(&app.state_store, "fedora", "pkg").await),
            ..Default::default()
        })
        .await
        .unwrap();

    let response = build_sse(State(app), Path(id), axum::http::HeaderMap::new(), None)
        .await
        .unwrap()
        .into_response();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-accel-buffering")
            .and_then(|v| v.to_str().ok()),
        Some("no")
    );
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-cache")
    );
    assert!(response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/event-stream"));

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
    assert!(text.contains("event: build"));
    assert!(text.contains(r#""phase":"succeeded""#));
}

/// 通知驱动门：phase 变更（complete_build 广播）后 build 事件须在 5s 兜底
/// 之前推出，终态后流结束（同一 end 契约）。
#[tokio::test]
async fn build_sse_pushes_phase_change_promptly_on_notify() {
    let (app, _tmp) = test_app_state().await;
    let (_task_id, id) = insert_building_task_build(&app).await;

    let app_clone = app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        app_clone
            .state_store
            .complete_build(id, "succeeded", None)
            .await
            .unwrap();
    });

    let response = build_sse(State(app), Path(id), axum::http::HeaderMap::new(), None)
        .await
        .unwrap()
        .into_response();
    // 逐读限时 4s：初始与通知驱动事件都须早于 5s 兜底到达。
    let mut stream = response.into_body().into_data_stream();
    let mut text = String::new();
    while let Ok(Some(Ok(bytes))) =
        tokio::time::timeout(std::time::Duration::from_secs(4), stream.next()).await
    {
        text.push_str(&String::from_utf8_lossy(&bytes));
        if text.contains(r#""phase":"succeeded""#) {
            break;
        }
    }
    assert!(
        text.contains("event: build"),
        "initial phase event missing: {text}"
    );
    assert!(
        text.contains(r#""phase":"succeeded""#),
        "phase change must be pushed via notify well before the 5s fallback, got: {text}"
    );
}

/// 通知驱动门：live 构建连接即首推当前时间线，标记推进后签名变化再推
///（payload 为 spans 紧凑 JSON）。日志追加无 DB 写信号，注入 50ms 兜底
/// tick 复查。
#[tokio::test]
async fn build_sse_streams_timeline_and_repushes_on_state_change() {
    let (app, _tmp) = test_app_state().await;
    let (_task_id, id) = insert_building_task_build(&app).await;
    app.log_buffer.register(id);
    app.log_buffer
        .append(id, Bytes::from("# CRBS_PHASE_START prepare-layer 100.0\n"));

    // 流挂接后异步推进标记：prepare-layer 翻 done（耗时 5s），build 开跑。
    let app_clone = app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        app_clone.log_buffer.append(
            id,
            Bytes::from("# CRBS_PHASE_END prepare-layer 0 105.0\n# CRBS_PHASE_START build 105.5\n"),
        );
    });

    let response = build_sse_with_poll(
        State(app),
        Path(id),
        axum::http::HeaderMap::new(),
        None,
        SsePollConfig {
            poll_interval: std::time::Duration::from_millis(50),
            visibility_recheck_interval: std::time::Duration::from_secs(30),
        },
    )
    .await
    .unwrap()
    .into_response();
    let mut stream = response.into_body().into_data_stream();
    let mut text = String::new();
    while text.matches("event: timeline").count() < 2 {
        match tokio::time::timeout(std::time::Duration::from_secs(4), stream.next()).await {
            Ok(Some(Ok(bytes))) => text.push_str(&String::from_utf8_lossy(&bytes)),
            _ => break,
        }
    }
    assert!(
        text.contains("event: build"),
        "initial phase event missing: {text}"
    );
    assert_eq!(
        text.matches("event: timeline").count(),
        2,
        "expected initial + changed timeline pushes, got: {text}"
    );

    let payloads: Vec<serde_json::Value> = text
        .lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|d| serde_json::from_str::<serde_json::Value>(d).ok())
        .filter(|v| v.is_array())
        .collect();
    assert!(payloads.len() >= 2, "timeline payloads missing: {text}");
    // 首推：prepare-layer running（无时长）。
    let first = payloads[0].as_array().unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0]["name"], "prepare-layer");
    assert_eq!(first[0]["state"], "running");
    assert!(first[0]["duration_seconds"].is_null());
    // 变化推：prepare-layer done（END-start=5s），build running。
    let second = payloads[1].as_array().unwrap();
    assert_eq!(second.len(), 2);
    assert_eq!(second[0]["name"], "prepare-layer");
    assert_eq!(second[0]["state"], "done");
    assert_eq!(second[0]["duration_seconds"].as_f64(), Some(5.0));
    assert_eq!(second[1]["name"], "build");
    assert_eq!(second[1]["state"], "running");
}

/// 终态构建不推 timeline（详情页终态全量 SSR）：即使 LogBuffer 带阶段
/// 标记，流里也只有初始 phase 事件。
#[tokio::test]
async fn build_sse_terminal_build_does_not_push_timeline() {
    let (app, _tmp) = test_app_state().await;
    let id = app
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg",
            phase: "succeeded",
            backend: "chroot",
            user: "alice",
            task_id: Some(crate::test_support::seed_task(&app.state_store, "fedora", "pkg").await),
            ..Default::default()
        })
        .await
        .unwrap();
    app.log_buffer.register(id);
    app.log_buffer.append(
        id,
        Bytes::from(
            "# CRBS_PHASE_START prepare-layer 100.0\n# CRBS_PHASE_END prepare-layer 0 102.0\n",
        ),
    );

    let response = build_sse(State(app), Path(id), axum::http::HeaderMap::new(), None)
        .await
        .unwrap()
        .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(
        text.contains("event: build"),
        "terminal phase event missing: {text}"
    );
    assert!(
        !text.contains("event: timeline"),
        "terminal build must not push timeline: {text}"
    );
}

/// 复鉴权回归门：SSE 握手后产品转 private，下一次可见性复查必须失败并
/// 断流——否则失去权限的客户端可无限期继续收实时数据。集成层间隔固定
/// 30s 墙钟，经 `*_with_poll` 注入小间隔覆盖同一循环。
#[tokio::test]
async fn build_sse_terminates_after_visibility_revoked_mid_stream() {
    let (app, _tmp, _root) = app_with_result_root().await;
    let owner_id = app
        .state_store
        .create_user("owner", "builder")
        .await
        .unwrap();
    app.state_store
        .create_product(crbs_core::CreateProductInput {
            name: "flip",
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
    let task_id = crate::test_support::seed_task(&app.state_store, "flip", "pkg").await;
    let id = app
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "flip",
            pkg_name: "pkg",
            phase: "building",
            backend: "chroot",
            user: "alice",
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    // 流启动后把产品转 private（owner 已设置，满足 SCHEMA CHECK）。
    let flipper = app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        sqlx::query("UPDATE products SET visibility = 'private' WHERE name = $1")
            .bind("flip")
            .execute(flipper.state_store.pool())
            .await
            .unwrap();
    });

    let response = build_sse_with_poll(
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

    // 整体超时包住消费：复鉴权生效则流必须结束，而不是挂到 MAX_SSE_LIFETIME。
    let data = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        collect_body_data(response.into_body()),
    )
    .await
    .expect("build SSE must terminate after product becomes private");
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(
        text.contains("event: build"),
        "should stream initial phase before revoke, got: {text}"
    );
}
