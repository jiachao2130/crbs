// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! Worker API 测试：心跳与遥测清洗。

use super::*;

use super::super::heartbeat::{sanitize_telemetry, HeartbeatRequest, HeartbeatResponse};
/// 心跳遥测解析矩阵：缺省字段全 None；字段就位照常；未知键
///（active_tasks，hub 从不消费）默认忽略；显式 null 同 None；
/// `cpu_util_pct` / `mem_total_kb` 同模式。
#[test]
fn heartbeat_request_telemetry_serde_matrix() {
    let old: HeartbeatRequest = serde_json::from_str(r#"{"status":"online"}"#).unwrap();
    assert_eq!(old.status, "online");
    assert!(old.load1.is_none());
    assert!(old.ncpu.is_none());
    assert!(old.cpu_util_pct.is_none());
    assert!(old.mem_used_pct.is_none());
    assert!(old.mem_total_kb.is_none());

    let new: HeartbeatRequest = serde_json::from_str(
        r#"{"status":"online","active_tasks":2,"load1":0.52,"ncpu":8,"cpu_util_pct":66.5,"mem_used_pct":37.5,"mem_total_kb":16384000}"#,
    )
    .unwrap();
    assert_eq!(new.load1, Some(0.52));
    assert_eq!(new.ncpu, Some(8));
    assert_eq!(new.cpu_util_pct, Some(66.5));
    assert_eq!(new.mem_used_pct, Some(37.5));
    assert_eq!(new.mem_total_kb, Some(16_384_000));

    // 显式 null + 缺 status（default_online）
    let nulls: HeartbeatRequest = serde_json::from_str(
        r#"{"load1":null,"ncpu":null,"cpu_util_pct":null,"mem_used_pct":null,"mem_total_kb":null}"#,
    )
    .unwrap();
    assert_eq!(nulls.status, "online");
    assert!(nulls.load1.is_none());
    assert!(nulls.ncpu.is_none());
    assert!(nulls.cpu_util_pct.is_none());
    assert!(nulls.mem_used_pct.is_none());
    assert!(nulls.mem_total_kb.is_none());
}

/// 遥测界检查：越界 → None（诚实降级）、边界值保留，钉住 sanitize 区间语义。
#[test]
fn heartbeat_telemetry_bounds_out_of_range_degrades_to_none() {
    fn sanitized(json: &str) -> crbs_core::WorkerTelemetry {
        let req: HeartbeatRequest = serde_json::from_str(json).unwrap();
        sanitize_telemetry(&req)
    }

    assert_eq!(sanitized(r#"{"load1":-0.1}"#).load1, None);
    assert_eq!(sanitized(r#"{"load1":1e308}"#).load1, None);
    assert_eq!(sanitized(r#"{"ncpu":0}"#).ncpu, None);
    assert_eq!(sanitized(r#"{"ncpu":99999}"#).ncpu, None);
    assert_eq!(sanitized(r#"{"cpu_util_pct":-1.0}"#).cpu_util_pct, None);
    assert_eq!(sanitized(r#"{"cpu_util_pct":100.5}"#).cpu_util_pct, None);
    assert_eq!(sanitized(r#"{"mem_used_pct":-1.0}"#).mem_used_pct, None);
    assert_eq!(sanitized(r#"{"mem_used_pct":100.5}"#).mem_used_pct, None);
    assert_eq!(sanitized(r#"{"mem_total_kb":-1}"#).mem_total_kb, None);
    assert_eq!(
        sanitized(r#"{"mem_total_kb":1000000001}"#).mem_total_kb,
        None
    );

    let edges = sanitized(
        r#"{"load1":0.0,"ncpu":1024,"cpu_util_pct":0.0,"mem_used_pct":0.0,"mem_total_kb":1}"#,
    );
    assert_eq!(edges.load1, Some(0.0));
    assert_eq!(edges.ncpu, Some(1024));
    assert_eq!(edges.cpu_util_pct, Some(0.0));
    assert_eq!(edges.mem_used_pct, Some(0.0));
    assert_eq!(edges.mem_total_kb, Some(1));
    let edges = sanitized(
        r#"{"load1":1e6,"ncpu":1,"cpu_util_pct":100.0,"mem_used_pct":100.0,"mem_total_kb":1000000000}"#,
    );
    assert_eq!(edges.load1, Some(1e6));
    assert_eq!(edges.ncpu, Some(1));
    assert_eq!(edges.cpu_util_pct, Some(100.0));
    assert_eq!(edges.mem_used_pct, Some(100.0));
    assert_eq!(edges.mem_total_kb, Some(1_000_000_000));
}

/// 心跳响应体形态钉住：无取消时逐字节 `{"accepted":true}`（字段整体
/// 缺席）；有取消时携带 `cancelled_assignments`。
#[test]
fn heartbeat_response_serde_shape() {
    let empty = HeartbeatResponse {
        accepted: true,
        cancelled_assignments: vec![],
    };
    assert_eq!(
        serde_json::to_string(&empty).unwrap(),
        r#"{"accepted":true}"#
    );

    let with_notices = HeartbeatResponse {
        accepted: true,
        cancelled_assignments: vec![42],
    };
    let json: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&with_notices).unwrap()).unwrap();
    assert_eq!(json["accepted"], true);
    assert_eq!(json["cancelled_assignments"], serde_json::json!([42]));
}

/// 心跳搭车取消通知：assign → cancel → 心跳响应携带该
/// assignment id；取消前的心跳响应体保持旧形态 `{"accepted":true}`。
#[tokio::test]
async fn heartbeat_carries_cancelled_assignment_ids() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let (worker_id, token) = seed_worker_secret_for_test(&store, "w-cancel", "x86_64")
        .await
        .unwrap();

    let build_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(crate::test_support::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();
    let (assignment_id, _) = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    let heartbeat_body = || {
        let app = app.clone();
        let token = token.clone();
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/v1/workers/{worker_id}/heartbeat"))
                        .header("Authorization", format!("Bearer {}", token))
                        .header("Content-Type", "application/json")
                        .body(Body::from(r#"{"status":"online"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            String::from_utf8(bytes.to_vec()).unwrap()
        }
    };

    assert_eq!(heartbeat_body().await, r#"{"accepted":true}"#);

    // 取消（镜像 cancel_distributed_build 的两次写入）。
    store.mark_build_cancelled(build_id).await.unwrap();
    store
        .update_worker_task_status_for_build(build_id, "cancelled")
        .await
        .unwrap();

    let json: serde_json::Value = serde_json::from_str(&heartbeat_body().await).unwrap();
    assert_eq!(json["accepted"], true);
    assert_eq!(
        json["cancelled_assignments"],
        serde_json::json!([assignment_id])
    );
}

// ======== 学习接线端到端（report_result → package_resource_profiles）========
