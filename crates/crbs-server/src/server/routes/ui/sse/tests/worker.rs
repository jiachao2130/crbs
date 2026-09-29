// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! Worker SSE 测试：在线快照与离线关流。

use super::common::*;
use super::*;

#[tokio::test]
async fn worker_sse_streams_snapshot_and_closes_for_offline() {
    let (app, _tmp) = test_app_state().await;
    let worker_id = app
        .state_store
        .upsert_worker("sse-worker", "x86_64", 2, "test", "online", None)
        .await
        .unwrap();
    app.state_store
        .worker_touch_heartbeat(
            worker_id,
            crbs_core::WorkerTelemetry {
                load1: Some(1.5),
                ncpu: Some(4),
                cpu_util_pct: Some(42.0),
                mem_used_pct: Some(60.0),
                mem_total_kb: Some(8_000_000),
                disk_free_kb: Some(48_832_000),
            },
            Some(
                crbs_core::RESOURCE_CAP_CGROUP_V2
                    | crbs_core::RESOURCE_CAP_MEMORY_PEAK
                    | crbs_core::RESOURCE_CAP_MEMORY_EVENTS,
            ),
        )
        .await
        .unwrap();

    // 在线 worker：首推快照（status/遥测/活跃行），流保持打开（无终态）。
    let response = worker_sse(
        State(app.clone()),
        Path(worker_id),
        axum::http::HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/event-stream"
    );
    let text: String = collect_body_data(response.into_body())
        .await
        .iter()
        .map(|b| String::from_utf8_lossy(b))
        .collect();
    assert!(text.contains("event: worker"), "{text}");
    assert!(text.contains(r#""status":"online""#), "{text}");
    assert!(text.contains(r#""capacity":2"#), "{text}");
    assert!(text.contains(r#""cpu_util_pct":42.0"#), "{text}");
    assert!(text.contains(r#""mem_total_kb":8000000"#), "{text}");
    // 资源可观测增量字段：磁盘与能力位图随快照透出（payload 恒含键、
    // null 值承载缺省）。
    assert!(text.contains(r#""disk_free_kb":48832000"#), "{text}");
    assert!(text.contains(r#""resource_caps":7"#), "{text}");

    // 置 offline 后新连接：推终态快照即关流（collect 以超时收尾，不再有数据）。
    app.state_store
        .worker_mark_offline(worker_id)
        .await
        .unwrap();
    let response = worker_sse(
        State(app),
        Path(worker_id),
        axum::http::HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();
    let text: String = collect_body_data(response.into_body())
        .await
        .iter()
        .map(|b| String::from_utf8_lossy(b))
        .collect();
    assert!(text.contains(r#""status":"offline""#), "{text}");
}

/// worker 不存在：握手 404（EventSource 对 404 不重连，不能挂死连接）。
#[tokio::test]
async fn worker_sse_unknown_worker_is_not_found() {
    let (app, _tmp) = test_app_state().await;
    let err = match worker_sse(State(app), Path(4242), axum::http::HeaderMap::new(), None).await {
        Err(e) => e,
        Ok(_) => panic!("unknown worker must fail the SSE handshake with 404"),
    };
    assert!(
        matches!(err, ApiError::NotFound(ref msg) if msg.contains("4242")),
        "{err:?}"
    );
}
