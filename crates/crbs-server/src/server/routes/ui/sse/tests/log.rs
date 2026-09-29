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

/// 慢客户端 front 洞补读：`?offset=0` 时 "old-data " 已被 FIFO 淘汰（11
/// 条满 1MB chunk 触发），缺口 [0, front) 从 artifact_dir build.log（双写
/// 副本，同偏移空间）补读，随后缓冲存活内容与 "tail" 续流；活构建期直开
/// artifact_dir 是唯一可得来源。
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
        // SSE 已补读缺口并消费缓冲存活内容后追加增量（双写同步）。
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
    // 事件 id 严格递增，覆盖补读段→缓冲续流交界（两段偏移空间错位会回退/重号）。
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

/// 中途洞变体：拒收窗口夹在更旧存活 chunk 与新 chunk 之间（推进
/// next_offset 但不留 chunk，不触发 front 洞分支），按首个存活 chunk 真实
/// 偏移识别，从落盘 build.log 补读 [start, 洞尾)；事件 id 恒等于真实文件
/// 偏移。
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
        // 先让 SSE 消费 "old-data "（offset 停在 9）。
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        // 触顶（全局上限测试值 12MB）：filler 11MB 记账 + 已缓冲 9 字节，
        // 随后的整 1MB chunk 越限被拒（差恰为 9 字节，确定性拒收）。
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
        // 双写落盘先行：补读由缓冲通知触发，落盘完成先于通知即消除
        // "唤醒时文件尚缺 z 块、洞补读撞 EOF 不足额"的交错。
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
        // 拒收窗口 [9, 9 + 1MB)：chunk 不入缓冲、next_offset 仍推进。两次
        // append 间无 await，一次唤醒即同时看到洞与洞后 chunk（确定性触发）。
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
    // id 恒等于真实文件偏移：old-data 末尾 9 → 补读各块（4096 步进，
    // 洞长恰为整 1MB → 末补读块 id = 洞尾 1048585）→ tail 末尾 1048589。
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

/// Waiting 态行删除收尾：builds 行被删后下一次唤醒即发 end 断流（空
/// phase，JS 端 `|| ''` 回退），不空转 get_build。注入用真 DELETE
///（RENAME 造的是 DB Err 不覆盖本路径）；DELETE 不广播，insert_task 通知
/// 驱动下一轮。
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

    // 收尾契约：end 事件携带空 phase（行不在的准确语义）。
    let end = recv_until(&mut rx, |t| t.contains("event: end"), "row-deleted end").await;
    assert!(end.contains(r#"data: {"phase":""}"#), "{end}");
    // 断流断言：end 之后循环必须退出（通道关闭 = body 流结束），不再空转。
    match tokio::time::timeout(std::time::Duration::from_millis(1500), rx.recv()).await {
        Ok(None) => {}
        Ok(Some(chunk)) => panic!("stream must close after row-deleted end: {chunk}"),
        Err(_) => panic!("stream still open after row-deleted end (spinning)"),
    }
}

/// Buffer 态行删除收尾——同一收尾路径经 is_build_terminal（行缺失
/// 视为终态）生效：缓冲推送期间行被删，下一轮空查询即补尾 + end 断流
///（File 态 EOF 检查共用 is_build_terminal，同路径覆盖）。
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

/// log_event 的 wire CR 归一契约：序列化后 wire 上不得残留 `\r`（axum
/// `Event::data` 双切分逐段补前缀，浏览器以 \n 重组）；落盘与 CLI
/// chunked 流不归一（终端进度条依赖原始 `\r`），差异由此钉住。
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
    // 归一后输入为 "progress 50%\nprogress 99%\nline\n\ndone"：每个逻辑行
    // 一条 data: 行（空行产生空 data: 行），末尾空行是事件终结符。
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

/// hub-local task 构建：连接时 result_dir 尚未写入（引擎 set_info 前），
/// SSE 应保持连接并在 result_dir 就绪、build.log 出现后开始推送。
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
        // 模拟引擎时序：先创建空 build.log 并写入 result_dir（set_info）。
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        tokio::fs::write(&log_file, b"").await.unwrap();
        app_clone
            .state_store
            .update_build_info(id, Some(writer_dir.to_str().unwrap()), None, "chroot")
            .await
            .unwrap();
        // 文件被打开（tail 定位到末尾）之后才产生新内容。
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

/// File 态截断重开不得回退到握手期偏移快照：`?offset=0` 消费 "v1"
///（position=12）后截断重写（6 字节）再增长，重开须用已推进位置（clamp
/// 到 6）而非 requested_offset=0——否则重放已推内容、id 回退。File 态无
/// 文件变更通知源，注入小兜底间隔压缩截断复查时序；终态 complete_build
/// 冲刷残余内容并结束流。
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
        // SSE 已消费 v1（position=12）后截断重写（6 字节）。
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        tokio::fs::write(&writer_file, b"v2-bb\n").await.unwrap();
        // 重写后的文件继续增长：重开位置正确（=12 clamp 到 6）时只推增量。
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
    // 事件 id 单调不回退。
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

/// File 态 EOF 的 stat 瞬时失败不得断流。注入：文件被持 fd 后把路径替换
/// 成自指符号链接——fd 读照常、stat(路径) 撞 ELOOP（非 NotFound，确定性
/// 复现）。容忍窗内流存活不发 end；恢复后照常推内容、end 收尾。注入时机
/// 经信号驱动：等 v1 已收到（挂接完成、position 停在 EOF）再注入——固定
/// 延时在极慢 CI 下会假阳性。
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
        // 等 File 态挂接并消费完 v1 的信号（见上方文档）。
        if !*inject_rx.borrow() && inject_rx.changed().await.is_err() {
            // 测试主体已退出（断言失败先行）：无需注入。
            return;
        }
        // 注入：自指 symlink → stat 撞 ELOOP。必须原子替换：先 rename 再
        // symlink 会留 NotFound 中间态，满载下窗口可与 50ms 轮询同量级、
        // 撞墓碑臂误杀。三步同步 syscall：硬链接留底 → 备好 symlink →
        // rename(2) 原子替换。
        let bak = inject_dir.join("build.log.test_bak");
        let tmp_link = inject_dir.join("build.log.test_tmp");
        std::fs::hard_link(&inject_file, &bak).unwrap();
        std::os::unix::fs::symlink(&inject_file, &tmp_link).unwrap();
        std::fs::rename(&tmp_link, &inject_file).unwrap();
        // 容忍窗：50ms 轮询下经历约 7 轮 EOF + stat 失败（< 阈值 10），
        // 流不得断、不得发 end。
        tokio::time::sleep(std::time::Duration::from_millis(350)).await;
        // 恢复：单次 rename(2) 直接归位并追加新内容（先 remove 再
        // rename 会复刻注入段同款 NotFound 中间态窗口，且 remove 多余）。
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

    // v1 到手 = 挂接 + 消费完成的实证，放行注入。
    let _ = inject_tx.send(true);

    let recovered = recv_until(&mut rx, |t| t.contains("recovered"), "post-recovery tail").await;
    assert!(recovered.contains("event: log"), "{recovered}");
    let end = recv_until(&mut rx, |t| t.contains("event: end"), "terminal end").await;
    assert!(end.contains(r#""phase":"succeeded""#), "{end}");
}

/// 墓碑臂：File 态日志文件被删（stat NotFound）立即断流——裸 break、
/// 无 end（重连握手按 404/等待态收口）；容错不得把真删除挂到容忍窗。
/// 注入时机经信号驱动（等 v1 已收到再注入，防极慢 CI 假阴性）。
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
        // 等 File 态挂接的信号（见上方文档）。
        if !*inject_rx.borrow() && inject_rx.changed().await.is_err() {
            return;
        }
        // 真身挪走即"文件被删"：stat(路径) NotFound。
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

    // v1 到手 = File 态已挂接的实证，放行注入。
    let _ = inject_tx.send(true);

    // 删除后：下一轮 EOF 检查 stat 撞 NotFound → 立即 break，流关闭。
    match tokio::time::timeout(std::time::Duration::from_millis(1500), rx.recv()).await {
        Ok(None) => {}
        Ok(Some(chunk)) => panic!("stream must close after file removal: {chunk}"),
        Err(_) => panic!("stream still open after log file removal"),
    }
}

/// 独立构建（result_dir 始终为空）：fallback 扫描
/// `{result_root}/{product}/{pkg}/{timestamp}-{build_id}/build.log`，按
/// `-{build_id}` 后缀精确匹配不误拾。时间戳目录出现无通知源（兜底 5s），
/// 连接前先落空 build.log（对齐真实引擎时序），首轮扫描即挂接。
#[tokio::test]
async fn log_sse_resolves_engine_timestamp_dir_by_build_id_suffix() {
    let (app, _tmp, result_root) = app_with_result_root().await;
    let (_task_id, id) = insert_building_task_build(&app).await;

    let pkg_root = result_root.join("fedora").join("pkg");
    let build_dir = pkg_root.join(format!("20260717-120000-{}", id));
    // 干扰目录：不同 build_id 的时间戳目录，含 build.log，不应被拾取。
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
        // 等首轮扫描挂接（tail 定位到空文件末尾）后再追加内容。
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

/// Worker 构建：连接时 log_buffer 未注册，等待态应在注册到达后切到
/// buffer 流并推送后续 chunk。
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

/// 同上场景的远端 Last-Event-ID 变体：id 远大于当前 total（编号空间重置/
/// 重启后重连）时 clamp 到当前末尾——恰好推送一次，不重放、id 不回拨。
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

    // Last-Event-ID=999 远大于本 build 的任何偏移（本用例 total ≤ 10）。
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
    // 后续事件恰好一次（不多：无重复重放；不少：clamp 不吞新事件）。
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

/// 驱逐竞争窗口回归：buffer 流挂接后 build 翻终态并驱逐 LogBuffer，最后
/// 轮询间隔内落盘的行仍应经 read_persisted_log_tail 补读吐出，不截尾。
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
        // 等 SSE 首次轮询（tail 到缓冲末尾）后再制造竞争窗口：新行只
        // 落盘（缓冲被终态驱逐清空），build 翻终态并驱逐。
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

    // tail 模式（无 offset）：从连接时缓冲末尾开始，只期待窗口内的新行。
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

/// 终态 + LogBuffer 有日志：流以 `event: end`（data 含终态 phase）收尾，
/// log 事件带 `id:` 续传游标（块末累计偏移）。
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
    // 两个 chunk 的 id 依次为块末累计偏移 6、11。
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

/// 终态 + 落盘 build.log（File 态，tail 无新内容）：流仍以 `event: end`
/// 收尾，客户端据此关流而非依赖浏览器自动重连。
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

/// Last-Event-ID 头按与 `?offset` 相同路径解析为起始偏移且优先于它；
/// 非法头静默降级。
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

/// [`log_sse_resumes_from_last_event_id_header`] 的远端 id 变体：
/// Last-Event-ID 远大于 total（999 vs 11）时 clamp 到末尾——零 log 事件
/// 不重放，end 收尾，id 不回拨。
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

    // total = 11（"hello world"）。
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

/// 详情产品可见性（与 tasks get_task 同口径）：viewer 对 private 产品的
/// build/task SSE 403（产品级检查独立把门）；public 产品 200。
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

/// 通知驱动门：Buffer 态下 append 后 log 事件须在兜底间隔（5s）
/// 之前即时推出——若实现退化为兜底轮询驱动，本测试将超时失败。
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

    // 流挂接（tail 定位到缓冲末尾）并进入等待后，异步追加新 chunk。
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
    // 逐读限时 4s：通知命中远早于该时限；退化成兜底轮询则首读必在 5s
    // 后，超时失败。
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

/// 同上，log SSE 的复鉴权路径（独立循环：fetch_build_checked 复查转
/// private 即 PermissionDenied——非瞬态，断流）。先注一块日志驱动 Buffer
/// 态，断流前有真实 log 事件。
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

    // 流启动后把产品转 private（owner 已设置，满足 SCHEMA CHECK）。
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
        // offset=0：从头推缓冲内容（默认 tail 语义下预注的 chunk 不会推出，
        // 拿不到断流前的 log 事件）。
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
