// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 日志 SSE 测试：缓冲/文件来源、断点续传与流终止。

use super::common::*;
use super::*;

#[tokio::test]
async fn log_sse_buffer_streams_from_offset_zero_for_terminal_build() {
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

    app.log_buffer.append(id, Bytes::from("hello "));
    app.log_buffer.append(id, Bytes::from("world"));

    let response = log_sse(
        State(app),
        Path(id),
        Query(LogsQuery { offset: Some(0) }),
        HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();
    assert_eq!(
        response
            .headers()
            .get("x-accel-buffering")
            .and_then(|v| v.to_str().ok()),
        Some("no"),
        "log SSE must disable reverse-proxy buffering"
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
    assert!(text.contains("hello"));
    assert!(text.contains("world"));
}

#[tokio::test]
async fn log_sse_buffer_tail_streams_only_new_data() {
    let (app, _tmp) = test_app_state().await;
    let id = app
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg",
            phase: "building",
            backend: "chroot",
            user: "alice",
            task_id: Some(crate::test_support::seed_task(&app.state_store, "fedora", "pkg").await),
            ..Default::default()
        })
        .await
        .unwrap();

    app.log_buffer.append(id, Bytes::from("old-data "));

    let app_clone = app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        app_clone.log_buffer.append(id, Bytes::from("new-data "));
        app_clone
            .state_store
            .complete_build(id, "succeeded", None)
            .await
            .unwrap();
    });

    let response = log_sse(
        State(app),
        Path(id),
        Query(LogsQuery::default()),
        HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(text.contains("new-data"));
    assert!(!text.contains("old-data"));
}

#[tokio::test]
async fn log_sse_buffer_hole_backfills_from_persisted_file() {
    let (app, _tmp) = test_app_state().await;
    let (_task_id, id) = insert_building_task_build(&app).await;

    let artifact_log = app.artifact_dir().join(id.to_string()).join("build.log");
    tokio::fs::create_dir_all(app.artifact_dir().join(id.to_string()))
        .await
        .unwrap();
    tokio::fs::write(&artifact_log, b"old-data ").await.unwrap();
    app.log_buffer.register(id);
    app.log_buffer.append(id, Bytes::from("old-data "));
    for _ in 0..11 {
        assert!(app.log_buffer.append(
            id,
            Bytes::from(vec![b'x'; crate::server::log_buffer::MAX_LOG_CHUNK_BYTES])
        ));
    }

    let app_clone = app.clone();
    let writer_log = artifact_log.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(app_clone.log_buffer.append(id, Bytes::from("tail")));
        let mut f = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&writer_log)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut f, b"tail")
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        app_clone
            .state_store
            .complete_build(id, "succeeded", None)
            .await
            .unwrap();
    });

    let response = log_sse(
        State(app),
        Path(id),
        Query(LogsQuery { offset: Some(0) }),
        HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(
        text.contains("old-data"),
        "evicted range must be backfilled from the persisted file: {text}"
    );
    assert!(text.contains("tail"), "live tail missing: {text}");
    assert!(text.contains("event: end"), "stream must end: {text}");

    let ids: Vec<u64> = text
        .lines()
        .filter_map(|l| l.strip_prefix("id: "))
        .filter_map(|v| v.parse().ok())
        .collect();
    assert!(!ids.is_empty(), "no log events captured: {text}");
    assert!(
        ids.windows(2).all(|w| w[0] < w[1]),
        "event ids must strictly increase across backfill-to-buffer boundary: {ids:?}"
    );
}

#[tokio::test]
async fn log_sse_buffer_mid_hole_backfills_from_persisted_file() {
    let (app, _tmp) = test_app_state().await;
    let (_task_id, id) = insert_building_task_build(&app).await;

    let artifact_dir = app.artifact_dir().join(id.to_string());
    let artifact_log = artifact_dir.join("build.log");
    tokio::fs::create_dir_all(&artifact_dir).await.unwrap();
    tokio::fs::write(&artifact_log, b"old-data ").await.unwrap();
    app.log_buffer.register(id);
    app.log_buffer.append(id, Bytes::from("old-data "));

    let app_clone = app.clone();
    let writer_log = artifact_log.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        for _ in 0..10 {
            assert!(app_clone.log_buffer.append(
                id + 1,
                Bytes::from(vec![b'x'; crate::server::log_buffer::MAX_LOG_CHUNK_BYTES])
            ));
        }
        assert!(app_clone.log_buffer.append(
            id + 2,
            Bytes::from(vec![b'y'; crate::server::log_buffer::MAX_LOG_CHUNK_BYTES])
        ));

        let mut f = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&writer_log)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut f,
            &[b'z'; crate::server::log_buffer::MAX_LOG_CHUNK_BYTES],
        )
        .await
        .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut f, b"tail")
            .await
            .unwrap();

        assert!(!app_clone.log_buffer.append(
            id,
            Bytes::from(vec![b'z'; crate::server::log_buffer::MAX_LOG_CHUNK_BYTES])
        ));
        app_clone.log_buffer.evict(id + 1);
        app_clone.log_buffer.evict(id + 2);
        assert!(app_clone.log_buffer.append(id, Bytes::from("tail")));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        app_clone
            .state_store
            .complete_build(id, "succeeded", None)
            .await
            .unwrap();
    });

    let response = log_sse(
        State(app),
        Path(id),
        Query(LogsQuery { offset: Some(0) }),
        HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(text.contains("old-data"), "pre-hole chunk missing: {text}");
    assert!(text.contains("zzzz"), "mid-hole backfill missing: {text}");
    assert!(
        text.contains("tail"),
        "post-hole live chunk missing: {text}"
    );
    assert!(text.contains("event: end"), "stream must end: {text}");

    let ids: Vec<u64> = text
        .lines()
        .filter_map(|l| l.strip_prefix("id: "))
        .filter_map(|v| v.parse().ok())
        .collect();
    assert_eq!(ids.first(), Some(&9), "first chunk ends at 9: {text}");
    assert_eq!(
        ids.last(),
        Some(&1_048_589),
        "tail chunk id must equal its real file end: {text}"
    );
    assert!(
        ids.contains(&1_048_585),
        "backfill must reach the hole end (real offset): {ids:?}"
    );
    assert_eq!(
        text.matches("event: log").count(),
        2 + crate::server::log_buffer::MAX_LOG_CHUNK_BYTES / 4096,
        "expected old-data + tail + per-4096 backfill events: {text}"
    );
    assert!(
        ids.windows(2).all(|w| w[0] < w[1]),
        "event ids must strictly increase across the mid-hole: {ids:?}"
    );
}

#[tokio::test]
async fn log_sse_waiting_ends_stream_when_build_row_deleted() {
    let (app, _tmp) = test_app_state().await;
    let (_task_id, id) = insert_building_task_build(&app).await;

    let response = log_sse(
        State(app.clone()),
        Path(id),
        Query(LogsQuery::default()),
        HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();
    let mut rx = spawn_sse_body_reader(response.into_body());

    sqlx::query("DELETE FROM builds WHERE id = ?")
        .bind(id)
        .execute(app.state_store.pool())
        .await
        .unwrap();
    app.state_store
        .insert_task(crbs_core::TaskInsert {
            product: "fedora",
            pkg_name: "noise",
            user: "alice",
            ..Default::default()
        })
        .await
        .unwrap();

    let end = recv_until(&mut rx, |t| t.contains("event: end"), "row-deleted end").await;
    assert!(end.contains(r#"data: {"phase":""}"#), "{end}");

    match tokio::time::timeout(std::time::Duration::from_millis(1500), rx.recv()).await {
        Ok(None) => {}
        Ok(Some(chunk)) => panic!("stream must close after row-deleted end: {chunk}"),
        Err(_) => panic!("stream still open after row-deleted end (spinning)"),
    }
}

#[tokio::test]
async fn log_sse_buffer_ends_stream_when_build_row_deleted() {
    let (app, _tmp) = test_app_state().await;
    let (_task_id, id) = insert_building_task_build(&app).await;
    app.log_buffer.append(id, Bytes::from("hello"));

    let response = log_sse(
        State(app.clone()),
        Path(id),
        Query(LogsQuery { offset: Some(0) }),
        HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();
    let mut rx = spawn_sse_body_reader(response.into_body());

    let first = recv_until(&mut rx, |t| t.contains("hello"), "buffered chunk").await;
    assert!(first.contains("event: log"), "{first}");

    sqlx::query("DELETE FROM builds WHERE id = ?")
        .bind(id)
        .execute(app.state_store.pool())
        .await
        .unwrap();
    app.state_store
        .insert_task(crbs_core::TaskInsert {
            product: "fedora",
            pkg_name: "noise",
            user: "alice",
            ..Default::default()
        })
        .await
        .unwrap();

    let end = recv_until(&mut rx, |t| t.contains("event: end"), "row-deleted end").await;
    assert!(end.contains(r#"data: {"phase":""}"#), "{end}");
    match tokio::time::timeout(std::time::Duration::from_millis(1500), rx.recv()).await {
        Ok(None) => {}
        Ok(Some(chunk)) => panic!("stream must close after row-deleted end: {chunk}"),
        Err(_) => panic!("stream still open after row-deleted end (spinning)"),
    }
}

#[test]
fn event_build_data_format() {
    let data = serde_json::json!({"phase": "building"}).to_string();
    assert_eq!(data, r#"{"phase":"building"}"#);
}

#[tokio::test]
async fn log_event_normalizes_cr_to_lf_on_wire() {
    let event = log_event(42, "progress 50%\rprogress 99%\nline\r\ndone");
    let response = sse_no_buffering(Sse::new(tokio_stream::iter(vec![Ok::<
        Event,
        std::convert::Infallible,
    >(event)])))
    .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(!text.contains('\r'), "wire must not carry CR: {text:?}");

    assert_eq!(
        text,
        "event: log\nid: 42\n\
         data: progress 50%\n\
         data: progress 99%\n\
         data: line\n\
         data: \n\
         data: done\n\n"
    );
}

#[tokio::test]
async fn log_sse_waits_and_streams_after_result_dir_set() {
    let (app, _tmp, result_root) = app_with_result_root().await;
    let (task_id, id) = insert_building_task_build(&app).await;

    let arch_dir = result_root.join(task_id.to_string()).join("x86_64");
    tokio::fs::create_dir_all(&arch_dir).await.unwrap();
    let log_file = arch_dir.join("build.log");

    let app_clone = app.clone();
    let writer_dir = arch_dir.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        tokio::fs::write(&log_file, b"").await.unwrap();
        app_clone
            .state_store
            .update_build_info(id, Some(writer_dir.to_str().unwrap()), None, "chroot")
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        tokio::fs::write(&log_file, b"new-data\n").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        app_clone
            .state_store
            .complete_build(id, "succeeded", None)
            .await
            .unwrap();
    });

    let response = log_sse(
        State(app),
        Path(id),
        Query(LogsQuery::default()),
        HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(
        text.contains("new-data"),
        "expected streamed log, got: {}",
        text
    );
}

#[tokio::test]
async fn log_sse_file_truncation_reopen_does_not_replay_consumed_content() {
    let (app, _tmp, result_root) = app_with_result_root().await;
    let (task_id, id) = insert_building_task_build(&app).await;

    let arch_dir = result_root.join(task_id.to_string()).join("x86_64");
    tokio::fs::create_dir_all(&arch_dir).await.unwrap();
    let log_file = arch_dir.join("build.log");
    tokio::fs::write(&log_file, b"v1-aaaaaaaa\n").await.unwrap();
    app.state_store
        .update_build_info(id, Some(arch_dir.to_str().unwrap()), None, "chroot")
        .await
        .unwrap();

    let app_clone = app.clone();
    let writer_file = log_file.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        tokio::fs::write(&writer_file, b"v2-bb\n").await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let mut f = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&writer_file)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut f, b"new-data\n")
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        app_clone
            .state_store
            .complete_build(id, "succeeded", None)
            .await
            .unwrap();
    });

    let response = log_sse_with_poll(
        State(app),
        Path(id),
        Query(LogsQuery { offset: Some(0) }),
        HeaderMap::new(),
        None,
        SsePollConfig {
            poll_interval: std::time::Duration::from_millis(50),
            visibility_recheck_interval: SSE_POLL_DEFAULT.visibility_recheck_interval,
        },
    )
    .await
    .unwrap()
    .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(
        text.contains("v1-aaaaaaaa"),
        "pre-truncation content missing: {text}"
    );
    assert!(
        text.contains("new-data"),
        "post-rewrite tail missing: {text}"
    );
    assert!(
        !text.contains("v2-bb"),
        "truncated-rewrite content must not replay: {text}"
    );

    let ids: Vec<u64> = text
        .lines()
        .filter_map(|l| l.strip_prefix("id: "))
        .filter_map(|v| v.parse().ok())
        .collect();
    assert!(!ids.is_empty(), "no log events captured: {text}");
    assert!(
        ids.windows(2).all(|w| w[0] <= w[1]),
        "event ids must not regress: {ids:?}"
    );
}

#[tokio::test]
async fn log_sse_file_eof_tolerates_transient_stat_errors_and_recovers() {
    let (app, _tmp, result_root) = app_with_result_root().await;
    let (task_id, id) = insert_building_task_build(&app).await;

    let arch_dir = result_root.join(task_id.to_string()).join("x86_64");
    tokio::fs::create_dir_all(&arch_dir).await.unwrap();
    let log_file = arch_dir.join("build.log");
    tokio::fs::write(&log_file, b"v1\n").await.unwrap();
    app.state_store
        .update_build_info(id, Some(arch_dir.to_str().unwrap()), None, "chroot")
        .await
        .unwrap();

    let (inject_tx, mut inject_rx) = tokio::sync::watch::channel(false);
    let app_clone = app.clone();
    let inject_file = log_file.clone();
    let inject_dir = arch_dir.clone();
    tokio::spawn(async move {
        if !*inject_rx.borrow() && inject_rx.changed().await.is_err() {
            return;
        }

        let bak = inject_dir.join("build.log.test_bak");
        let tmp_link = inject_dir.join("build.log.test_tmp");
        std::fs::hard_link(&inject_file, &bak).unwrap();
        std::os::unix::fs::symlink(&inject_file, &tmp_link).unwrap();
        std::fs::rename(&tmp_link, &inject_file).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(350)).await;

        std::fs::rename(&bak, &inject_file).unwrap();
        let mut f = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&inject_file)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut f, b"recovered\n")
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        app_clone
            .state_store
            .complete_build(id, "succeeded", None)
            .await
            .unwrap();
    });

    let response = log_sse_with_poll(
        State(app),
        Path(id),
        Query(LogsQuery { offset: Some(0) }),
        HeaderMap::new(),
        None,
        SsePollConfig {
            poll_interval: std::time::Duration::from_millis(50),
            visibility_recheck_interval: SSE_POLL_DEFAULT.visibility_recheck_interval,
        },
    )
    .await
    .unwrap()
    .into_response();
    let mut rx = spawn_sse_body_reader(response.into_body());

    let first = recv_until(&mut rx, |t| t.contains("v1"), "initial content").await;
    assert!(first.contains("event: log"), "{first}");

    let _ = inject_tx.send(true);

    let recovered = recv_until(&mut rx, |t| t.contains("recovered"), "post-recovery tail").await;
    assert!(recovered.contains("event: log"), "{recovered}");
    let end = recv_until(&mut rx, |t| t.contains("event: end"), "terminal end").await;
    assert!(end.contains(r#""phase":"succeeded""#), "{end}");
}

#[tokio::test]
async fn log_sse_file_eof_breaks_immediately_when_log_file_removed() {
    let (app, _tmp, result_root) = app_with_result_root().await;
    let (task_id, id) = insert_building_task_build(&app).await;

    let arch_dir = result_root.join(task_id.to_string()).join("x86_64");
    tokio::fs::create_dir_all(&arch_dir).await.unwrap();
    let log_file = arch_dir.join("build.log");
    tokio::fs::write(&log_file, b"v1\n").await.unwrap();
    app.state_store
        .update_build_info(id, Some(arch_dir.to_str().unwrap()), None, "chroot")
        .await
        .unwrap();

    let (inject_tx, mut inject_rx) = tokio::sync::watch::channel(false);
    let inject_file = log_file.clone();
    let inject_dir = arch_dir.clone();
    tokio::spawn(async move {
        if !*inject_rx.borrow() && inject_rx.changed().await.is_err() {
            return;
        }

        let bak = inject_dir.join("build.log.test_bak");
        tokio::fs::rename(&inject_file, &bak).await.unwrap();
    });

    let response = log_sse_with_poll(
        State(app),
        Path(id),
        Query(LogsQuery { offset: Some(0) }),
        HeaderMap::new(),
        None,
        SsePollConfig {
            poll_interval: std::time::Duration::from_millis(50),
            visibility_recheck_interval: SSE_POLL_DEFAULT.visibility_recheck_interval,
        },
    )
    .await
    .unwrap()
    .into_response();
    let mut rx = spawn_sse_body_reader(response.into_body());

    let first = recv_until(&mut rx, |t| t.contains("v1"), "initial content").await;
    assert!(first.contains("event: log"), "{first}");

    let _ = inject_tx.send(true);

    match tokio::time::timeout(std::time::Duration::from_millis(1500), rx.recv()).await {
        Ok(None) => {}
        Ok(Some(chunk)) => panic!("stream must close after file removal: {chunk}"),
        Err(_) => panic!("stream still open after log file removal"),
    }
}

#[tokio::test]
async fn log_sse_resolves_engine_timestamp_dir_by_build_id_suffix() {
    let (app, _tmp, result_root) = app_with_result_root().await;
    let (_task_id, id) = insert_building_task_build(&app).await;

    let pkg_root = result_root.join("fedora").join("pkg");
    let build_dir = pkg_root.join(format!("20260717-120000-{}", id));

    let decoy_dir = pkg_root.join(format!("20260717-120001-{}0", id));
    tokio::fs::create_dir_all(&build_dir).await.unwrap();
    tokio::fs::create_dir_all(&decoy_dir).await.unwrap();
    tokio::fs::write(decoy_dir.join("build.log"), b"decoy-data\n")
        .await
        .unwrap();
    let log_file = build_dir.join("build.log");
    tokio::fs::write(&log_file, b"").await.unwrap();

    let app_clone = app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        tokio::fs::write(&log_file, b"engine-data\n").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        app_clone
            .state_store
            .complete_build(id, "succeeded", None)
            .await
            .unwrap();
    });

    let response = log_sse(
        State(app),
        Path(id),
        Query(LogsQuery::default()),
        HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(
        text.contains("engine-data"),
        "expected streamed log, got: {}",
        text
    );
    assert!(!text.contains("decoy-data"), "picked wrong dir: {}", text);
}

#[tokio::test]
async fn log_sse_switches_to_buffer_when_registered_mid_stream() {
    let (app, _tmp, _result_root) = app_with_result_root().await;
    let (_task_id, id) = insert_building_task_build(&app).await;

    let app_clone = app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        app_clone.log_buffer.register(id);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        app_clone.log_buffer.append(id, Bytes::from("live-data\n"));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        app_clone
            .state_store
            .complete_build(id, "succeeded", None)
            .await
            .unwrap();
    });

    let response = log_sse(
        State(app),
        Path(id),
        Query(LogsQuery::default()),
        HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(
        text.contains("live-data"),
        "expected buffered log, got: {}",
        text
    );
}

#[tokio::test]
async fn log_sse_switches_to_buffer_with_far_last_event_id_delivers_once() {
    let (app, _tmp, _result_root) = app_with_result_root().await;
    let (_task_id, id) = insert_building_task_build(&app).await;

    let app_clone = app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        app_clone.log_buffer.register(id);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        app_clone.log_buffer.append(id, Bytes::from("live-data\n"));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        app_clone
            .state_store
            .complete_build(id, "succeeded", None)
            .await
            .unwrap();
    });

    let mut headers = HeaderMap::new();
    headers.insert(
        "last-event-id",
        axum::http::HeaderValue::from_str("999").unwrap(),
    );
    let response = log_sse(
        State(app),
        Path(id),
        Query(LogsQuery::default()),
        headers,
        None,
    )
    .await
    .unwrap()
    .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();

    assert_eq!(
        text.matches("live-data").count(),
        1,
        "subsequent events must arrive exactly once: {}",
        text
    );
    assert_eq!(
        text.matches("event: log").count(),
        1,
        "exactly one log event expected: {}",
        text
    );
}

#[tokio::test]
async fn log_sse_buffer_tail_reads_persisted_log_after_evict() {
    let (app, _tmp, result_root) = app_with_result_root().await;
    let (task_id, id) = insert_building_task_build(&app).await;

    let arch_dir = result_root.join(task_id.to_string()).join("x86_64");
    tokio::fs::create_dir_all(&arch_dir).await.unwrap();
    let log_file = arch_dir.join("build.log");
    tokio::fs::write(&log_file, "sse-early\n").await.unwrap();
    app.state_store
        .update_build_info(id, Some(arch_dir.to_str().unwrap()), None, "chroot")
        .await
        .unwrap();
    app.log_buffer.register(id);
    app.log_buffer.append(id, Bytes::from("sse-early\n"));

    let app_clone = app.clone();
    let writer_log = log_file.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        tokio::fs::write(&writer_log, b"sse-early\nsse-tail\n")
            .await
            .unwrap();
        app_clone
            .state_store
            .complete_build(id, "succeeded", None)
            .await
            .unwrap();
        app_clone.log_buffer.evict(id);
    });

    let response = log_sse(
        State(app),
        Path(id),
        Query(LogsQuery::default()),
        HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(
        text.contains("sse-tail"),
        "expected persisted tail after evict, got: {}",
        text
    );
    assert!(
        !text.contains("sse-early"),
        "tail mode should not replay pre-attach content, got: {}",
        text
    );
}

#[tokio::test]
async fn log_sse_terminal_without_logs_returns_404() {
    let (app, _tmp, _result_root) = app_with_result_root().await;
    let id = app
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg",
            phase: "failed",
            backend: "chroot",
            user: "alice",
            arch: Some("x86_64"),
            task_id: Some(crate::test_support::seed_task(&app.state_store, "fedora", "pkg").await),
            ..Default::default()
        })
        .await
        .unwrap();

    let result = log_sse(
        State(app),
        Path(id),
        Query(LogsQuery::default()),
        HeaderMap::new(),
        None,
    )
    .await;
    assert!(matches!(result, Err(ApiError::NotFound(_))));
}

#[tokio::test]
async fn log_sse_buffer_terminal_stream_ends_with_end_event() {
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

    app.log_buffer.append(id, Bytes::from("hello "));
    app.log_buffer.append(id, Bytes::from("world"));

    let response = log_sse(
        State(app),
        Path(id),
        Query(LogsQuery { offset: Some(0) }),
        HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();

    assert!(
        text.contains("id: 6\n"),
        "expected id line for chunk 1: {text}"
    );
    assert!(
        text.contains("id: 11\n"),
        "expected id line for chunk 2: {text}"
    );
    let end_at = text
        .rfind("event: end")
        .expect("end event must close the stream");
    assert!(
        text[end_at..].contains(r#"{"phase":"succeeded"}"#),
        "end event data must carry terminal phase: {text}"
    );
    assert!(
        !text[end_at..].contains("event: log"),
        "no log events after end: {text}"
    );
}

#[tokio::test]
async fn log_sse_file_terminal_stream_ends_with_end_event() {
    let (app, _tmp, result_root) = app_with_result_root().await;
    let (task_id, id) = insert_building_task_build(&app).await;

    let arch_dir = result_root.join(task_id.to_string()).join("x86_64");
    tokio::fs::create_dir_all(&arch_dir).await.unwrap();
    tokio::fs::write(arch_dir.join("build.log"), b"file-log\n")
        .await
        .unwrap();
    app.state_store
        .update_build_info(id, Some(arch_dir.to_str().unwrap()), None, "chroot")
        .await
        .unwrap();
    app.state_store
        .complete_build(id, "failed", None)
        .await
        .unwrap();

    let response = log_sse(
        State(app),
        Path(id),
        Query(LogsQuery::default()),
        HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(
        text.contains("event: end"),
        "terminal file stream must end with end event: {text}"
    );
    assert!(
        text.contains(r#"{"phase":"failed"}"#),
        "end event data must carry terminal phase: {text}"
    );
}

#[tokio::test]
async fn log_sse_resumes_from_last_event_id_header() {
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

    app.log_buffer.append(id, Bytes::from("hello world"));

    let mut headers = HeaderMap::new();
    headers.insert(
        "last-event-id",
        axum::http::HeaderValue::from_str("6").unwrap(),
    );
    let response = log_sse(
        State(app.clone()),
        Path(id),
        Query(LogsQuery { offset: Some(0) }),
        headers,
        None,
    )
    .await
    .unwrap()
    .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(
        text.contains("world"),
        "must resume from header offset: {text}"
    );
    assert!(
        !text.contains("hello"),
        "content before Last-Event-ID must not replay: {text}"
    );

    let mut bad = HeaderMap::new();
    bad.insert(
        "last-event-id",
        axum::http::HeaderValue::from_str("not-a-number").unwrap(),
    );
    let response = log_sse(
        State(app),
        Path(id),
        Query(LogsQuery { offset: Some(0) }),
        bad,
        None,
    )
    .await
    .unwrap()
    .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(
        text.contains("hello") && text.contains("world"),
        "invalid header must fall back to ?offset: {text}"
    );
}

#[tokio::test]
async fn log_sse_clamps_last_event_id_beyond_buffer_total() {
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

    app.log_buffer.append(id, Bytes::from("hello world"));

    let mut headers = HeaderMap::new();
    headers.insert(
        "last-event-id",
        axum::http::HeaderValue::from_str("999").unwrap(),
    );
    let response = log_sse(
        State(app),
        Path(id),
        Query(LogsQuery::default()),
        headers,
        None,
    )
    .await
    .unwrap()
    .into_response();
    let data = collect_body_data(response.into_body()).await;
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(
        !text.contains("hello") && !text.contains("world"),
        "content beyond current total must not replay: {text}"
    );
    assert_eq!(
        text.matches("event: log").count(),
        0,
        "no log events expected when resumed past the end: {text}"
    );
    assert!(
        text.contains("event: end"),
        "terminal stream must close with end event: {text}"
    );
}

#[tokio::test]
async fn sse_checks_product_visibility() {
    let (app, _tmp, _result_root) = app_with_result_root().await;
    let viewer = AuthContext {
        user: "eve".into(),
        role: "viewer".into(),
        ..Default::default()
    };

    let owner_id = app
        .state_store
        .create_user("owner", "builder")
        .await
        .unwrap();
    for (name, owner_id, visibility) in [
        ("secret", Some(owner_id), crbs_core::VISIBILITY_PRIVATE),
        ("openfed", None, crbs_core::VISIBILITY_PUBLIC),
    ] {
        app.state_store
            .create_product(crbs_core::CreateProductInput {
                name,
                display_name: None,
                owner_id,
                parent_id: None,
                visibility,
                config: &crbs_core::config::ProductConfig::default(),
                changed_by_user_id: None,
                reason: Some("test seed"),
            })
            .await
            .unwrap();
    }

    let insert_build = |product: &'static str, phase: &'static str| {
        let app = app.clone();
        async move {
            let task_id = crate::test_support::seed_task(&app.state_store, product, "pkg").await;
            app.state_store
                .insert_build(crbs_core::BuildInsert {
                    product,
                    pkg_name: "pkg",
                    phase,
                    backend: "chroot",
                    user: "alice",
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };

    let secret_build = insert_build("secret", "succeeded").await;
    let result = build_sse(
        State(app.clone()),
        Path(secret_build),
        axum::http::HeaderMap::new(),
        Some(Extension(viewer.clone())),
    )
    .await;
    assert!(
        matches!(result, Err(ApiError::PermissionDenied(_))),
        "private product build SSE must be denied for viewer"
    );

    let secret_task = app
        .state_store
        .insert_task(crbs_core::TaskInsert {
            product: "secret",
            pkg_name: "pkg",
            phase: "succeeded",
            user: "alice",
            ..Default::default()
        })
        .await
        .unwrap();
    let result = task_sse(
        State(app.clone()),
        Path(secret_task),
        axum::http::HeaderMap::new(),
        Some(Extension(viewer.clone())),
    )
    .await;
    assert!(
        matches!(result, Err(ApiError::PermissionDenied(_))),
        "private product task SSE must be denied for viewer"
    );

    let public_build = insert_build("openfed", "succeeded").await;
    let response = build_sse(
        State(app),
        Path(public_build),
        axum::http::HeaderMap::new(),
        Some(Extension(viewer)),
    )
    .await
    .unwrap()
    .into_response();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn log_sse_pushes_new_chunk_promptly_on_buffer_notify() {
    let (app, _tmp) = test_app_state().await;
    let id = app
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg",
            phase: "building",
            backend: "chroot",
            user: "alice",
            task_id: Some(crate::test_support::seed_task(&app.state_store, "fedora", "pkg").await),
            ..Default::default()
        })
        .await
        .unwrap();

    app.log_buffer.register(id);
    app.log_buffer.append(id, Bytes::from("seed "));

    let app_clone = app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        app_clone.log_buffer.append(id, Bytes::from("notify-data"));
    });

    let response = log_sse(
        State(app),
        Path(id),
        Query(LogsQuery::default()),
        HeaderMap::new(),
        None,
    )
    .await
    .unwrap()
    .into_response();

    let mut stream = response.into_body().into_data_stream();
    let mut text = String::new();
    while !text.contains("notify-data") {
        match tokio::time::timeout(std::time::Duration::from_secs(4), stream.next()).await {
            Ok(Some(Ok(bytes))) => text.push_str(&String::from_utf8_lossy(&bytes)),
            _ => break,
        }
    }
    assert!(
        text.contains("notify-data"),
        "chunk must be pushed via notify well before the 5s fallback, got: {text}"
    );
    assert!(
        !text.contains("seed"),
        "tail mode must not replay pre-attach content, got: {text}"
    );
}

#[tokio::test]
async fn log_sse_terminates_after_visibility_revoked_mid_stream() {
    let (app, _tmp, _root) = app_with_result_root().await;
    let owner_id = app
        .state_store
        .create_user("owner", "builder")
        .await
        .unwrap();
    app.state_store
        .create_product(crbs_core::CreateProductInput {
            name: "flip-log",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: crbs_core::VISIBILITY_PUBLIC,
            config: &crbs_core::config::ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("log sse recheck test"),
        })
        .await
        .unwrap();
    let task_id = crate::test_support::seed_task(&app.state_store, "flip-log", "pkg").await;
    let id = app
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "flip-log",
            pkg_name: "pkg",
            phase: "building",
            backend: "chroot",
            user: "alice",
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    app.log_buffer
        .append(id, Bytes::from_static(b"# CRBS_PHASE_START build 1.0\n"));

    let flipper = app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        sqlx::query("UPDATE products SET visibility = 'private' WHERE name = $1")
            .bind("flip-log")
            .execute(flipper.state_store.pool())
            .await
            .unwrap();
    });

    let response = log_sse_with_poll(
        State(app),
        Path(id),
        Query(LogsQuery { offset: Some(0) }),
        HeaderMap::new(),
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
    .expect("log SSE must terminate after product becomes private");
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(
        text.contains("event: log"),
        "should stream buffered log before revoke, got: {text}"
    );
    assert!(text.contains("CRBS_PHASE_START"), "{text}");
}
