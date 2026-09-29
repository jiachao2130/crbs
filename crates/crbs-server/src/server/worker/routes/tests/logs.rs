// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! Worker API 测试：构建日志上报。

use super::common::*;
use super::*;

use super::super::logs::MAX_HUB_BUILD_LOG_BYTES;
/// 序号幂等：响应丢失后的同 seq 重试只确认不重复追加（文件 + 缓冲各一次）；
/// 下一个 seq 正常追加；不带 seq 头的请求维持原追加语义。
#[tokio::test]
async fn report_logs_dedupes_retried_chunk_by_seq() {
    let (app, app_state, token, assignment_id, build_id, _tmp) =
        setup_worker_build_with_streamed_log().await;
    let log_path = app_state
        .artifact_dir()
        .join(build_id.to_string())
        .join("build.log");
    let size_before = tokio::fs::metadata(&log_path).await.unwrap().len();
    let buffered_before = app_state.log_buffer.total_size(build_id).unwrap();

    assert_eq!(
        post_log_chunk(&app, &token, assignment_id, Some(1), "retry-me").await,
        StatusCode::OK
    );
    let size_after_first = tokio::fs::metadata(&log_path).await.unwrap().len();
    assert_eq!(size_after_first, size_before + 8);
    assert_eq!(
        app_state.log_buffer.total_size(build_id).unwrap(),
        buffered_before + 8
    );

    // 同 seq 重放（首次响应丢失）：200 确认但零追加。
    assert_eq!(
        post_log_chunk(&app, &token, assignment_id, Some(1), "retry-me").await,
        StatusCode::OK
    );
    assert_eq!(
        tokio::fs::metadata(&log_path).await.unwrap().len(),
        size_after_first
    );
    assert_eq!(
        app_state.log_buffer.total_size(build_id).unwrap(),
        buffered_before + 8
    );

    // 下一个 seq 与不带 seq 头的请求均正常追加。
    assert_eq!(
        post_log_chunk(&app, &token, assignment_id, Some(2), "next!").await,
        StatusCode::OK
    );
    assert_eq!(
        post_log_chunk(&app, &token, assignment_id, None, "legacy").await,
        StatusCode::OK
    );
    assert_eq!(
        tokio::fs::metadata(&log_path).await.unwrap().len(),
        size_after_first + 5 + 6
    );

    let chunks = app_state.log_buffer.read(build_id);
    let text: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    assert!(
        String::from_utf8_lossy(&text).ends_with("retry-menext!legacy"),
        "buffer tail must contain exactly one copy of the retried chunk: {text:?}"
    );
    assert!(
        !String::from_utf8_lossy(&text).contains("retry-meretry-me"),
        "retried chunk must not be appended twice: {text:?}"
    );
}

/// 非法序号头是协议错误：400 显式拒绝（worker 4xx 不重试，走缺口占位）。
#[tokio::test]
async fn report_logs_rejects_malformed_seq_header() {
    let (app, _app_state, token, assignment_id, _build_id, _tmp) =
        setup_worker_build_with_streamed_log().await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/logs"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .header("X-Crbs-Log-Seq", "not-a-number")
                .body(Body::from("x"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// 终态 assignment 的日志 chunk 409——防 build.log 无界增长。
#[tokio::test]
async fn report_logs_returns_conflict_for_terminal_assignment() {
    let (app, _app_state, token, assignment_id, _build_id, _tmp) =
        setup_worker_build_with_streamed_log().await;
    report_terminal(&app, &token, assignment_id).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/logs"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from("late chunk"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

/// 超 512MB 上限后拒绝追加（不截断）：防认证 worker 灌盘；HTTP 仍 200。
/// 稀疏文件（set_len）瞬时构造 512MB。
#[tokio::test]
async fn report_logs_refuses_append_beyond_cap() {
    let (app, app_state, token, assignment_id, build_id, _tmp) =
        setup_worker_build_with_streamed_log().await;
    let buffered_before = app_state.log_buffer.total_size(build_id).unwrap();

    let log_path = app_state
        .artifact_dir()
        .join(build_id.to_string())
        .join("build.log");
    let file = std::fs::File::options()
        .write(true)
        .open(&log_path)
        .unwrap();
    file.set_len(MAX_HUB_BUILD_LOG_BYTES).unwrap();
    drop(file);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/logs"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from("overflow chunk"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        std::fs::metadata(&log_path).unwrap().len(),
        MAX_HUB_BUILD_LOG_BYTES,
        "capped build.log must not grow further"
    );
    // cap 长度分歧按设计保留：缓冲照收、offset 照常推进（见 handler
    // over_cap 注释）。
    assert_eq!(
        app_state.log_buffer.total_size(build_id).unwrap(),
        buffered_before + "overflow chunk".len(),
        "capped build must keep feeding the real-time buffer by design"
    );
    assert!(app_state.log_buffer.has(build_id));
}

/// 单 chunk 超 1MB：入口 400 拒收（不进缓冲不落盘）；worker 4xx → 不
/// 重试，走缺口占位机制。
#[tokio::test]
async fn report_logs_rejects_oversized_chunk() {
    let (app, app_state, token, assignment_id, build_id, _tmp) =
        setup_worker_build_with_streamed_log().await;
    let before = app_state.log_buffer.total_size(build_id).unwrap();

    let oversized = vec![b'x'; crate::server::log_buffer::MAX_LOG_CHUNK_BYTES + 1];
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/logs"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(oversized))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    assert_eq!(
        app_state.log_buffer.total_size(build_id).unwrap(),
        before,
        "oversized chunk must not enter the log buffer"
    );
}

/// 明显超限（> 1MB + 余量）的 body 由 layer 直接 413，handler 不执行
///（缓冲与落盘都不动）；"刚好超限"仍走 handler 400 预检。
#[tokio::test]
async fn report_logs_layer_rejects_body_far_over_chunk_limit() {
    let (app, app_state, token, assignment_id, build_id, _tmp) =
        setup_worker_build_with_streamed_log().await;
    let before = app_state.log_buffer.total_size(build_id).unwrap();
    let artifact_log = app_state
        .artifact_dir()
        .join(build_id.to_string())
        .join("build.log");
    let file_before = std::fs::metadata(&artifact_log)
        .map(|m| m.len())
        .unwrap_or(0);

    // 1MB + 64KiB + 1：刚好越过 layer 上限（1MB + 64KiB 余量）的最小拒收样本。
    let oversized =
        vec![
            b'x';
            crate::server::log_buffer::MAX_LOG_CHUNK_BYTES + super::REPORT_LOGS_BODY_HEADROOM + 1
        ];
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/logs"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(oversized))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    assert_eq!(
        app_state.log_buffer.total_size(build_id).unwrap(),
        before,
        "layer-rejected body must not reach the log buffer"
    );
    assert_eq!(
        std::fs::metadata(&artifact_log).unwrap().len(),
        file_before,
        "layer-rejected body must not reach build.log"
    );
}

/// 恰好 1MB（语义上限边界）照常 200，双写同步推进（钉上限边界）。
#[tokio::test]
async fn report_logs_accepts_full_size_chunk() {
    let (app, app_state, token, assignment_id, build_id, _tmp) =
        setup_worker_build_with_streamed_log().await;
    let before = app_state.log_buffer.total_size(build_id).unwrap();

    let chunk = vec![b'x'; crate::server::log_buffer::MAX_LOG_CHUNK_BYTES];
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/logs"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(chunk))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let advanced = crate::server::log_buffer::MAX_LOG_CHUNK_BYTES as u64;
    assert_eq!(
        app_state.log_buffer.total_size(build_id).unwrap() as u64,
        before as u64 + advanced,
        "full-size chunk must enter the buffer"
    );
    let artifact_log = app_state
        .artifact_dir()
        .join(build_id.to_string())
        .join("build.log");
    assert_eq!(
        std::fs::metadata(&artifact_log).unwrap().len(),
        before as u64 + advanced,
        "full-size chunk must be persisted (buffer offset == file length)"
    );
}

/// 写前失败（open）→ 503：build.log 换成目录构造 EISDIR（与权限无关），
/// worker 5xx → Network 重放同 chunk；末段验证两端同偏移续写、逐位一致。
#[tokio::test]
async fn report_logs_disk_append_failure_skips_buffer_and_realigns() {
    let (app, app_state, token, assignment_id, build_id, _tmp) =
        setup_worker_build_with_streamed_log().await;
    // setup 已落 11 字节、目录已记忆化，两次 POST 直达 open 分支。
    let log_path = app_state
        .artifact_dir()
        .join(build_id.to_string())
        .join("build.log");
    let before = app_state.log_buffer.total_size(build_id).unwrap();

    tokio::fs::remove_file(&log_path).await.unwrap();
    tokio::fs::create_dir(&log_path).await.unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/logs"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from("lost-chunk"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "pre-write open failure must be 503 so the worker replays the chunk"
    );

    // 失败 chunk 未进缓冲：offset 不动。
    assert_eq!(
        app_state.log_buffer.total_size(build_id).unwrap(),
        before,
        "chunk whose durable append failed must not enter the buffer"
    );

    // worker 重放：磁盘恢复后重发同 chunk——两端从同一偏移起，
    // 缓冲与文件逐位一致。
    tokio::fs::remove_dir(&log_path).await.unwrap();
    tokio::fs::write(&log_path, "hello build").await.unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/logs"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from("lost-chunk"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/logs"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from("tail"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let (chunks, next, _) = app_state.log_buffer.read_since(build_id, 0);
    let buffered: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    assert_eq!(
        String::from_utf8_lossy(&buffered),
        "hello buildlost-chunktail",
        "buffer content must be the contiguous surviving stream"
    );
    assert_eq!(next, "hello buildlost-chunktail".len());
    let on_disk = tokio::fs::read(&log_path).await.unwrap();
    assert_eq!(
        on_disk, buffered,
        "buffer offset space and file bytes must stay aligned"
    );
}

/// 稳态子形态：write 失败 + fstat Ok + 零进展（sustained ENOSPC）→ 503
/// 触发 worker 重放（文件端 == 缓冲 offset，零错位）。注入：build.log 换
/// 指向 /dev/full 的符号链接（write 恒 ENOSPC、st_size=0；仅 Linux，缺失跳过）。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn report_logs_write_zero_progress_returns_503_and_replay_recovers() {
    let (app, app_state, token, assignment_id, build_id, _tmp) =
        setup_worker_build_with_streamed_log().await;
    if !std::path::Path::new("/dev/full").exists() {
        return;
    }
    // setup 已落 11 字节、目录已记忆化，直达 write 分支。
    let log_path = app_state
        .artifact_dir()
        .join(build_id.to_string())
        .join("build.log");
    let before = app_state.log_buffer.total_size(build_id).unwrap();
    assert_eq!(before, "hello build".len(), "setup precondition");

    tokio::fs::remove_file(&log_path).await.unwrap();
    tokio::fs::symlink("/dev/full", &log_path).await.unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/logs"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from("lost-chunk"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "write failure with zero durable progress must be 503 so the worker replays the chunk"
    );

    // 失败 chunk 未进缓冲：offset 不动。
    assert_eq!(
        app_state.log_buffer.total_size(build_id).unwrap(),
        before,
        "zero-progress chunk must not enter the buffer"
    );

    // 磁盘恢复后重发同 chunk → 200，两端同偏移续写、逐位一致。
    tokio::fs::remove_file(&log_path).await.unwrap();
    tokio::fs::write(&log_path, b"hello build").await.unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/logs"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from("lost-chunk"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let (chunks, next, _) = app_state.log_buffer.read_since(build_id, 0);
    let buffered: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    assert_eq!(
        String::from_utf8_lossy(&buffered),
        "hello buildlost-chunk",
        "replayed chunk must be the contiguous stream"
    );
    assert_eq!(next, "hello buildlost-chunk".len());
    let on_disk = tokio::fs::read(&log_path).await.unwrap();
    assert_eq!(
        on_disk, buffered,
        "replay after zero-progress failure must keep both sides aligned"
    );
}

/// 写前失败（目录预备，ENOTDIR 与权限无关）→ 503 触发 worker 重放；
/// 目录恢复后重发同 chunk，文件与缓冲零错位续写。
#[tokio::test]
async fn report_logs_dir_prep_failure_returns_503_and_replay_recovers() {
    let (app, app_state, token, assignment_id, build_id, _tmp) =
        setup_worker_build_with_streamed_log().await;
    let artifact_dir = app_state.artifact_dir().join(build_id.to_string());
    let log_path = artifact_dir.join("build.log");
    let before = app_state.log_buffer.total_size(build_id).unwrap();

    app_state
        .hub_log_dir_prepared
        .lock()
        .unwrap()
        .remove(&build_id);
    tokio::fs::remove_dir_all(&artifact_dir).await.unwrap();
    tokio::fs::write(&artifact_dir, b"not a dir").await.unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/logs"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from("lost chunk"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "pre-write dir prep failure must be 503 so the worker replays the chunk"
    );

    // 缓冲未推进；占位文件未被 handler 改写（确无任何写发生）。
    assert_eq!(
        app_state.log_buffer.total_size(build_id).unwrap(),
        before,
        "chunk whose dir prep failed must not enter the buffer"
    );
    assert_eq!(
        tokio::fs::read_to_string(&artifact_dir).await.unwrap(),
        "not a dir",
        "handler must not touch the artifact path on prep failure"
    );

    // worker 重放：目录恢复后重发同一 chunk → 200，文件与缓冲逐位一致。
    tokio::fs::remove_file(&artifact_dir).await.unwrap();
    tokio::fs::create_dir(&artifact_dir).await.unwrap();
    tokio::fs::write(&log_path, "hello build").await.unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/logs"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from("lost chunk"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let (chunks, next, _) = app_state.log_buffer.read_since(build_id, 0);
    let buffered: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    assert_eq!(String::from_utf8_lossy(&buffered), "hello buildlost chunk");
    assert_eq!(next, "hello buildlost chunk".len());
    let on_disk = tokio::fs::read(&log_path).await.unwrap();
    assert_eq!(
        on_disk, buffered,
        "replayed chunk must keep both sides aligned"
    );
}
