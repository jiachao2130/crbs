// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use super::cancel::*;
use super::execute::*;
use super::probes::*;
use super::report::*;
use super::*;

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;

use crate::executor::{report_result, BuildResult};
use crate::test_util::{test_cfg, test_task};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[test]
fn active_task_guard_increments_and_decrements() {
    let counter = Arc::new(AtomicI32::new(0));
    {
        let _guard = ActiveTaskGuard::new(counter.clone());
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[test]
fn poll_retry_delay_exponential_capped_at_60s() {
    assert_eq!(
        poll_retry_delay_secs(0),
        5,
        "defensive: 0 treated as first failure"
    );
    assert_eq!(
        poll_retry_delay_secs(1),
        5,
        "first failure keeps the old fixed 5s"
    );
    assert_eq!(poll_retry_delay_secs(2), 10);
    assert_eq!(poll_retry_delay_secs(3), 20);
    assert_eq!(poll_retry_delay_secs(4), 40);
    assert_eq!(poll_retry_delay_secs(5), 60, "80 capped at 60");
    assert_eq!(poll_retry_delay_secs(6), 60);
    assert_eq!(poll_retry_delay_secs(u64::MAX), 60, "no overflow, capped");
}

#[test]
fn poller_stalled_for_requires_silence_beyond_window() {
    assert_eq!(poller_stalled_for(100, 700), None, "恰达窗口不算失活");
    assert_eq!(poller_stalled_for(100, 100), None);
    assert_eq!(poller_stalled_for(100, 300), None);
    assert_eq!(poller_stalled_for(100, 701), Some(601));
    assert_eq!(
        poller_stalled_for(100, 99),
        None,
        "时钟回拨（now < last）不得误报"
    );
}

#[tokio::test]
async fn assignment_budget_matches_engine_timeout_plus_margin() {
    let mut cfg = test_cfg("http://127.0.0.1:1".to_string(), None).await;
    cfg.build_timeout_secs = 7200;

    let mut task = test_task();
    task.build_options = serde_json::json!({});
    assert_eq!(
        assignment_budget(&task, &cfg),
        Some(Duration::from_secs(7200 + ASSIGNMENT_BUDGET_MARGIN_SECS)),
        "无请求值回落 worker 配置"
    );

    task.build_options = serde_json::json!({ "timeout": 600 });
    assert_eq!(
        assignment_budget(&task, &cfg),
        Some(Duration::from_secs(600 + ASSIGNMENT_BUDGET_MARGIN_SECS)),
        "请求值透传（不读配置默认）"
    );

    task.build_options = serde_json::json!({ "timeout": u64::MAX });
    assert_eq!(
        assignment_budget(&task, &cfg),
        Some(Duration::from_secs(u64::MAX)),
        "巨值请求超时饱和加富余不回绕（预算封顶，实际不限时）"
    );

    task.build_options = serde_json::json!({ "timeout": 0 });
    assert_eq!(assignment_budget(&task, &cfg), None, "0 = 显式不限时");

    task.build_options = serde_json::json!({});
    cfg.build_timeout_secs = 0;
    assert_eq!(assignment_budget(&task, &cfg), None, "配置 0 = 关闭兜底");

    let mut init_task = test_task();
    init_task.kind = "init".to_string();
    init_task.init_product = Some("ule3".to_string());
    assert_eq!(
        assignment_budget(&init_task, &cfg),
        Some(Duration::from_secs(
            crate::executor::INIT_ENGINE_TIMEOUT_SECS + ASSIGNMENT_BUDGET_MARGIN_SECS
        )),
        "init 恒取 3h 引擎上限（与 build 配置无关）"
    );
}

#[test]
fn gate_blocks_decision_table() {
    for (available, watermark) in [
        (1024 * 1024 * 1024u64, 1024 * 1024 * 1024u64),
        (512 * 1024 * 1024u64, 512 * 1024 * 1024u64),
    ] {
        assert!(!gate_blocks(&Ok(available), watermark));
        assert!(gate_blocks(&Ok(available - 1), watermark));
        assert!(!gate_blocks(&Ok(available + 1), watermark));
    }
    assert!(!gate_blocks(&Ok(0), 0));
    assert!(!gate_blocks(&Ok(u64::MAX), 0));
    let stat_err = Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    assert!(!gate_blocks(&stat_err, u64::MAX));
}

#[test]
fn parse_mem_available_kb_reads_proc_meminfo() {
    let meminfo = "MemTotal:       32629856 kB
                   MemFree:         1234567 kB
                   MemAvailable:   24654321 kB
                   Buffers:          234567 kB
";
    assert_eq!(parse_mem_available_kb(meminfo), Some(24_654_321));
    assert_eq!(
        parse_mem_available_kb(
            "MemTotal: 1024 kB
"
        ),
        None
    );
    assert_eq!(parse_mem_available_kb(""), None);
    assert_eq!(
        parse_mem_available_kb(
            "MemAvailable:   garbage kB
"
        ),
        None
    );
}

#[tokio::test]
async fn disk_gate_uses_real_free_space_of_build_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let probe = tmp.path().join("not-created-yet");
    let available = free_disk_bytes(&probe).await.expect("statvfs must succeed");
    assert!(available < u64::MAX);
    assert!(
        gate_blocks(&Ok(available), u64::MAX),
        "u64::MAX watermark must gate any real disk"
    );
    assert!(!gate_blocks(&Ok(available), 0), "0 must disable the gate");
}

#[test]
fn cancel_registry_cancel_hits_live_token_only_once() {
    let registry = CancelRegistry::default();
    let token = CancellationToken::new();
    registry.insert(42, token.clone());

    assert!(registry.cancel(42));
    assert!(token.is_cancelled());
    assert!(!registry.cancel(42));
}

#[test]
fn cancel_registry_unknown_id_returns_false() {
    let registry = CancelRegistry::default();
    assert!(!registry.cancel(999));
}

#[test]
fn cancel_registration_guard_removes_entry_on_drop() {
    let registry = CancelRegistry::default();
    let token = CancellationToken::new();
    {
        let _guard = CancelRegistrationGuard::new(registry.clone(), 7, token.clone());
        assert!(registry.contains(7));
    }
    assert!(!registry.contains(7));
    assert!(!registry.cancel(7));
    assert!(!token.is_cancelled());
}

#[tokio::test]
async fn redelivered_assignment_is_deduped_while_executing() {
    let registry = CancelRegistry::default();
    let task = test_task();

    assert!(!registry.contains(task.assignment_id), "首轮不得误判重复");
    let _guard = CancelRegistrationGuard::new(
        registry.clone(),
        task.assignment_id,
        CancellationToken::new(),
    );
    assert!(
        registry.contains(task.assignment_id),
        "执行中（guard 存活）的重投递必须命中去重"
    );

    drop(_guard);
    assert!(!registry.contains(task.assignment_id));
}

#[test]
fn executed_assignments_fifo_eviction() {
    let executed = ExecutedAssignments::default();
    assert!(!executed.contains(1), "空集合不得命中");
    executed.record(1);
    assert!(executed.contains(1));
    for id in 2..=(EXECUTED_ASSIGNMENTS_CAPACITY as i64 + 1) {
        executed.record(id);
    }
    assert!(!executed.contains(1), "超容量必须驱逐最老条目（FIFO）");
    assert!(executed.contains(EXECUTED_ASSIGNMENTS_CAPACITY as i64 + 1));
    let q = executed.0.lock().unwrap();
    assert_eq!(q.len(), EXECUTED_ASSIGNMENTS_CAPACITY, "条目数恒有上界");
}

#[tokio::test]
async fn report_build_result_records_only_double_success() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));
    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let task = test_task();
    let executed = ExecutedAssignments::default();
    let ok = BuildResult {
        phase: "succeeded".to_string(),
        result_dir: None,
        error: None,
        notes: None,
        resources: None,
        local_result_dir: None,
        engine_build_id: None,
        engine_result_root: None,
    };
    report_build_result(&cfg, 1, &task, &ok, &CancellationToken::new(), &executed)
        .await
        .unwrap();
    let _ = server.await.unwrap();
    assert!(
        executed.contains(task.assignment_id),
        "双成功必须登记去重集合"
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));
    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let mut failed_task = test_task();
    failed_task.assignment_id = 8;
    let failed = BuildResult {
        phase: "failed".to_string(),
        result_dir: None,
        error: Some("build error".to_string()),
        notes: None,
        resources: None,
        local_result_dir: None,
        engine_build_id: None,
        engine_result_root: None,
    };
    report_build_result(
        &cfg,
        1,
        &failed_task,
        &failed,
        &CancellationToken::new(),
        &executed,
    )
    .await
    .unwrap();
    let _ = server.await.unwrap();
    assert!(!executed.contains(8), "失败构建不得登记去重集合");
}

#[tokio::test]
async fn report_build_result_cancelled_arm_records_accepted_success() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));
    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let task = test_task();
    let executed = ExecutedAssignments::default();

    let main_cancel = CancellationToken::new();
    main_cancel.cancel();
    let ok = BuildResult {
        phase: "succeeded".to_string(),
        result_dir: None,
        error: None,
        notes: None,
        resources: None,
        local_result_dir: None,
        engine_build_id: None,
        engine_result_root: None,
    };
    report_build_result(&cfg, 1, &task, &ok, &main_cancel, &executed)
        .await
        .unwrap();
    let _ = server.await.unwrap();
    assert!(
        executed.contains(task.assignment_id),
        "补报 accepted 的 succeeded 必须登记去重集合"
    );
}

#[test]
fn assigned_task_redelivered_field_is_wire_compatible() {
    let old_hub = r#"{"assignment_id":7,"task_id":5,"build_id":14,"product":"ule3"}"#;
    let t: AssignedTask = serde_json::from_str(old_hub).unwrap();
    assert!(!t.redelivered, "absent field must default to false");

    let new_hub =
        r#"{"assignment_id":7,"task_id":5,"build_id":14,"product":"ule3","redelivered":true}"#;
    let t: AssignedTask = serde_json::from_str(new_hub).unwrap();
    assert!(t.redelivered, "redelivery marker must parse");
}

async fn read_one_request(sock: &mut tokio::net::TcpStream) -> (String, String, String) {
    let buf = crate::test_util::read_request(sock).await;
    let header_end =
        crate::test_util::find_subslice(&buf, b"\r\n\r\n").map_or(buf.len(), |p| p + 4);
    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
    let mut request_line = header_text.lines().next().unwrap_or("").split_whitespace();
    let method = request_line.next().unwrap_or("").to_string();
    let path = request_line.next().unwrap_or("").to_string();
    let content_len = header_text
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    (
        method,
        path,
        String::from_utf8_lossy(&buf[header_end..header_end + content_len]).into_owned(),
    )
}

async fn capture_one_request(listener: TcpListener) -> String {
    let (mut sock, _) = listener.accept().await.unwrap();
    let (_, _, body) = read_one_request(&mut sock).await;
    sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
        .await
        .unwrap();
    sock.flush().await.unwrap();
    body
}

async fn serve_n_requests(listener: TcpListener, n: usize, reject_phases: &[&str]) -> Vec<String> {
    let mut bodies = Vec::new();
    for _ in 0..n {
        let (mut sock, _) = listener.accept().await.unwrap();
        let (_, _, body) = read_one_request(&mut sock).await;
        let phase = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["phase"].as_str().map(str::to_string));
        let reject = phase.as_deref().is_some_and(|p| reject_phases.contains(&p));
        let resp: &str = if reject {
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        } else {
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
        };
        sock.write_all(resp.as_bytes()).await.unwrap();
        sock.flush().await.unwrap();
        bodies.push(body);
    }
    bodies
}

async fn serve_all_404(listener: TcpListener, n: usize) -> Vec<(String, String, String)> {
    let mut reqs = Vec::new();
    for _ in 0..n {
        let (mut sock, _) = listener.accept().await.unwrap();
        let req = read_one_request(&mut sock).await;
        sock.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        sock.flush().await.unwrap();
        reqs.push(req);
    }
    reqs
}

#[tokio::test]
async fn join_failure_message_extracts_str_payload() {
    let handle = tokio::spawn(async { panic!("boom-detail") });
    let err = handle.await.unwrap_err();
    let msg = join_failure_message(err);
    assert!(msg.contains("boom-detail"), "msg: {msg}");
    assert!(msg.starts_with("worker task panicked"), "msg: {msg}");
}

#[tokio::test]
async fn join_failure_message_extracts_string_payload() {
    let handle = tokio::spawn(async {
        panic!("{}", "owned-detail".to_string());
    });
    let err = handle.await.unwrap_err();
    let msg = join_failure_message(err);
    assert!(msg.contains("owned-detail"), "msg: {msg}");
}

#[tokio::test]
async fn join_failure_message_truncates_long_payload() {
    let long = "x".repeat(5000);
    let handle = tokio::spawn(async move {
        panic!("{long}");
    });
    let err = handle.await.unwrap_err();
    let msg = join_failure_message(err);
    assert!(msg.len() < 600, "msg len: {}", msg.len());
}

#[tokio::test]
async fn join_failure_message_handles_aborted_task() {
    let handle = tokio::spawn(async {
        std::future::pending::<()>().await;
    });
    handle.abort();
    let err = handle.await.unwrap_err();
    let msg = join_failure_message(err);
    assert!(msg.contains("join error"), "msg: {msg}");
}

#[tokio::test]
async fn report_terminal_failure_posts_failed_phase() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));

    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let task = test_task();

    report_terminal_failure(
        &cfg,
        1,
        &task,
        "network error: download srpm: not_found".to_string(),
    )
    .await;

    let body = server.await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["phase"], "failed", "必须回报 phase=failed");
    assert!(
        json["error"].as_str().unwrap().contains("download srpm"),
        "错误信息应透传到 Hub"
    );
}

#[tokio::test]
async fn report_terminal_failure_carries_snapshot_resources() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));
    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let task = test_task();
    report_terminal_failure_with_resources(&cfg, 1, &task, "budget exceeded".to_string(), None)
        .await;
    let body = server.await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["resources"], serde_json::Value::Null);

    let slot = crbs_core::engine::new_resource_snapshot_slot();
    assert_eq!(crbs_core::engine::snapshot_slot_resources(&slot), None);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));
    let cfg = test_cfg(format!("http://{}", addr), None).await;
    report_terminal_failure_with_resources(
        &cfg,
        1,
        &task,
        "budget exceeded".to_string(),
        Some(crbs_core::engine::ResourceUsage {
            peak_rss_kb: Some(262_144),
            cpu_secs: Some(9.5),
            cpu_p90_cores: Some(1.7),
            peak_total_kb: Some(524_288),
            disk_wbytes: Some(1_236),
            oom_killed: Some(true),
            sample_backend: Some(crbs_core::engine::SAMPLE_BACKEND_CGROUP),
            sample_ncpu: Some(8),
            peak_tmpfs_kb: Some(65_536),
        }),
    )
    .await;
    let body = server.await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let res = &json["resources"];
    assert_eq!(res["peak_rss_kb"], 262_144);
    assert!((res["cpu_secs"].as_f64().unwrap() - 9.5).abs() < 1e-9);
    assert!((res["cpu_p90_cores"].as_f64().unwrap() - 1.7).abs() < 1e-9);
    assert_eq!(res["peak_total_kb"], 524_288);
    assert_eq!(res["disk_wbytes"], 1_236);
    assert_eq!(res["oom_killed"], true);
    assert_eq!(res["sample_backend"], "cgroup");
    assert_eq!(res["sample_ncpu"], 8);
    assert_eq!(res["peak_tmpfs_kb"], 65_536);
}

#[tokio::test]
async fn report_terminal_failure_still_sends_after_shutdown_cancel() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));

    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let task = test_task();

    let main_cancel = CancellationToken::new();
    main_cancel.cancel();

    report_terminal_failure(&cfg, 1, &task, "cancelled by shutdown".to_string()).await;

    let body = server.await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        json["phase"], "failed",
        "shutdown 后仍必须回报 phase=failed"
    );
}

#[tokio::test]
async fn cancelled_terminal_report_survives_main_token_cancel() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));

    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let task = test_task();

    let main_cancel = CancellationToken::new();
    main_cancel.cancel();

    let result = BuildResult {
        phase: "cancelled".to_string(),
        result_dir: None,
        error: None,
        notes: None,
        resources: None,
        local_result_dir: None,
        engine_build_id: None,
        engine_result_root: None,
    };

    let control = BuildResult {
        phase: "cancelled".to_string(),
        result_dir: None,
        error: Some("leaked-control-group".to_string()),
        notes: None,
        resources: None,
        local_result_dir: None,
        engine_build_id: None,
        engine_result_root: None,
    };
    let swallowed = report_result(&cfg, 1, &task, &control, Some(&main_cancel)).await;
    assert!(
        matches!(swallowed, Err(CrbsError::Cancelled)),
        "已取消令牌的常规上报必须入口即返 Cancelled: {swallowed:?}"
    );

    report_terminal_after_cancel(&cfg, 1, &task, &result).await;

    let body = server.await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        json["phase"], "cancelled",
        "取消终态必须在主 token 已取消后仍送达 hub"
    );
}

#[tokio::test]
async fn auth_rejected_poll_cancels_running_tasks_and_drains_within_window() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let assignments_hits = Arc::new(std::sync::atomic::AtomicU32::new(0));
    {
        let seen = seen.clone();
        let assignments_hits = assignments_hits.clone();
        tokio::spawn(async move {
            let task_json = serde_json::json!({
                "assignment_id": 7,
                "task_id": 5,
                "build_id": 14,
                "product": "ule3",
                "srpm_url": "/api/v1/srpm/hello-1.0-1.src.rpm",
                "kind": "build",
            })
            .to_string();
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let seen = seen.clone();
                let assignments_hits = assignments_hits.clone();
                let task_json = task_json.clone();
                tokio::spawn(async move {
                    let (method, path, body) = read_one_request(&mut sock).await;
                    if path.contains("/result") {
                        seen.lock().unwrap().push((method, body));
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\
                                  Connection: close\r\n\r\n{}",
                            )
                            .await;
                    } else if path.contains("/srpm/") {
                        std::future::pending::<()>().await;
                    } else if path.contains("/assignments") {
                        let hit = assignments_hits.fetch_add(1, Ordering::SeqCst);
                        let resp = if hit == 0 {
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                                task_json.len(),
                                task_json
                            )
                        } else {
                            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\
                             Connection: close\r\n\r\n"
                                .to_string()
                        };
                        let _ = sock.write_all(resp.as_bytes()).await;
                    } else {
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\
                                  Connection: close\r\n\r\n",
                            )
                            .await;
                    }
                    let _ = sock.flush().await;
                });
            }
        });
    }

    let tmp = tempfile::tempdir().unwrap();
    let content = format!(
        "name = \"w\"\nhub_url = \"http://{addr}\"\ntoken = \"t\"\n\
         capacity = 4\nmin_free_disk_gb = 0\nbuild_dir = \"{}\"\n",
        tmp.path().display()
    );
    let config_file = tempfile::NamedTempFile::new().unwrap();
    tokio::fs::write(config_file.path(), content).await.unwrap();
    let cfg = WorkerConfig::load(config_file.path()).await.unwrap();

    let cancel_token = CancellationToken::new();
    let poller = spawn_poller(
        1,
        cfg,
        Arc::new(AtomicI32::new(0)),
        Arc::new(Mutex::new(std::collections::HashSet::new())),
        CancelRegistry::default(),
        cancel_token.clone(),
    );

    let started = std::time::Instant::now();
    let _ = tokio::time::timeout(Duration::from_secs(60), poller)
        .await
        .expect("poller must exit after auth rejection");
    let elapsed = started.elapsed();

    assert!(
        cancel_token.is_cancelled(),
        "auth-rejected exit must cancel the main token before draining"
    );

    assert!(
        elapsed < AUTH_EXIT_DRAIN,
        "poller exited at {elapsed:?}, not within the drain window"
    );

    let requests = seen.lock().unwrap().clone();
    let cancelled_reports: Vec<serde_json::Value> = requests
        .iter()
        .filter(|(m, _)| m == "post")
        .filter_map(|(_, b)| serde_json::from_str::<serde_json::Value>(b).ok())
        .filter(|v| v["phase"] == "cancelled")
        .collect();
    assert_eq!(
        cancelled_reports.len(),
        1,
        "exactly one cancelled terminal report expected; got {requests:?}"
    );
    assert!(
        cancelled_reports[0]["error"].is_null(),
        "cancelled 终态不带错误归因: {:?}",
        cancelled_reports[0]
    );
}

#[tokio::test]
async fn succeeded_report_failure_keeps_artifacts_and_skips_failed_report() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(serve_n_requests(listener, 3, &["succeeded"]));

    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let task = test_task();

    let tmp = tempfile::tempdir().unwrap();
    let result_dir = tmp.path().join("result-14");
    tokio::fs::create_dir_all(&result_dir).await.unwrap();
    tokio::fs::write(result_dir.join("hello-1.0-1.rpm"), b"rpm-bytes")
        .await
        .unwrap();

    let result = BuildResult {
        phase: "succeeded".to_string(),
        result_dir: None,
        error: None,
        notes: None,
        resources: None,
        local_result_dir: Some(result_dir.clone()),
        engine_build_id: None,
        engine_result_root: None,
    };

    let outcome = report_build_result(
        &cfg,
        1,
        &task,
        &result,
        &CancellationToken::new(),
        &ExecutedAssignments::default(),
    )
    .await;
    assert!(
        outcome.is_ok(),
        "成功上报失败不得走 Err 路径（会补报 failed）: {outcome:?}"
    );

    let bodies = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("mock hub should serve 3 requests")
        .unwrap();
    assert_eq!(bodies.len(), 3, "恰好 3 次重试后耗尽");
    for body in &bodies {
        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(
            json["phase"], "succeeded",
            "不得出现误导性 failed 上报: {body}"
        );
    }
    assert!(
        result_dir.join("hello-1.0-1.rpm").exists(),
        "本地产物必须保留"
    );
}

#[tokio::test]
async fn double_success_report_deletes_local_result_dir() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));

    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let task = test_task();

    let tmp = tempfile::tempdir().unwrap();
    let result_dir = tmp
        .path()
        .join("results")
        .join("ule3")
        .join("hello")
        .join("20260825-010203-14");
    tokio::fs::create_dir_all(&result_dir).await.unwrap();
    tokio::fs::write(result_dir.join("hello-1.0-1.rpm"), b"rpm-bytes")
        .await
        .unwrap();

    let result = BuildResult {
        phase: "succeeded".to_string(),
        result_dir: None,
        error: None,
        notes: None,
        resources: None,
        local_result_dir: Some(result_dir.clone()),
        engine_build_id: Some(14),
        engine_result_root: Some(tmp.path().join("results")),
    };

    let outcome = report_build_result(
        &cfg,
        1,
        &task,
        &result,
        &CancellationToken::new(),
        &ExecutedAssignments::default(),
    )
    .await;
    assert!(outcome.is_ok(), "double success must be Ok: {outcome:?}");
    let body = server.await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["phase"], "succeeded");

    assert!(
        !result_dir.exists(),
        "上传+上报双成功后本地结果目录应被删除"
    );
}

#[tokio::test]
async fn upload_failure_marker_keeps_local_result_dir_even_when_report_succeeds() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));

    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let task = test_task();

    let tmp = tempfile::tempdir().unwrap();
    let result_dir = tmp
        .path()
        .join("results")
        .join("ule3")
        .join("hello")
        .join("20260825-010203-14");
    tokio::fs::create_dir_all(&result_dir).await.unwrap();
    tokio::fs::write(result_dir.join("hello-1.0-1.rpm"), b"rpm-bytes")
        .await
        .unwrap();

    let result = BuildResult {
        phase: "succeeded".to_string(),
        result_dir: None,
        error: Some("artifact upload failed".into()),
        notes: None,
        resources: None,
        local_result_dir: Some(result_dir.clone()),
        engine_build_id: Some(14),
        engine_result_root: Some(tmp.path().join("results")),
    };

    let outcome = report_build_result(
        &cfg,
        1,
        &task,
        &result,
        &CancellationToken::new(),
        &ExecutedAssignments::default(),
    )
    .await;
    assert!(outcome.is_ok());
    let _ = server.await.unwrap();

    assert!(
        result_dir.exists(),
        "上传失败时本地结果目录必须保留（恢复来源）"
    );
}

#[tokio::test]
async fn failed_build_report_failure_still_propagates_err() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_n_requests(listener, 3, &["failed"]));

    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let task = test_task();

    let result = BuildResult {
        phase: "failed".to_string(),
        result_dir: None,
        error: Some("build error".to_string()),
        notes: None,
        resources: None,
        local_result_dir: None,
        engine_build_id: None,
        engine_result_root: None,
    };

    let outcome = report_build_result(
        &cfg,
        1,
        &task,
        &result,
        &CancellationToken::new(),
        &ExecutedAssignments::default(),
    )
    .await;
    assert!(outcome.is_err(), "失败构建上报失败必须走 Err 补报终态");

    let bodies = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("mock hub should serve 3 requests")
        .unwrap();
    assert_eq!(bodies.len(), 3);
}

#[tokio::test]
async fn building_report_network_exhaustion_leaves_assignment_for_reclaimer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(serve_n_requests(listener, 3, &["building"]));

    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let mut task = test_task();
    task.srpm_url = "/api/v1/srpm/hello-1.0-1.src.rpm".to_string();

    let outcome = tokio::time::timeout(
        Duration::from_secs(60),
        execute_task(
            1,
            &cfg,
            &task,
            CancellationToken::new(),
            &ExecutedAssignments::default(),
            Duration::from_secs(ownership_probe_interval_secs(cfg.heartbeat_interval_secs)),
            crbs_core::engine::new_resource_snapshot_slot(),
        ),
    )
    .await
    .expect("execute_task must not hang after retry exhaustion");

    assert!(
        outcome.is_ok(),
        "网络错误耗尽应静默退出、不发终态（留给 reclaimer）: {outcome:?}"
    );

    let bodies = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("mock hub should serve exactly 3 requests")
        .unwrap();
    assert_eq!(bodies.len(), 3, "不得出现第 4 个请求（SRPM 下载）");
    for body in &bodies {
        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(json["phase"], "building");
    }
}

#[tokio::test]
async fn building_report_4xx_still_continues_to_download() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(serve_all_404(listener, 2));

    let tmp = tempfile::tempdir().unwrap();
    let cfg = test_cfg(format!("http://{}", addr), Some(&tmp.path().join("builds"))).await;
    let mut task = test_task();
    task.srpm_url = "/api/v1/srpm/hello-1.0-1.src.rpm".to_string();

    let outcome = tokio::time::timeout(
        Duration::from_secs(60),
        execute_task(
            1,
            &cfg,
            &task,
            CancellationToken::new(),
            &ExecutedAssignments::default(),
            Duration::from_secs(ownership_probe_interval_secs(cfg.heartbeat_interval_secs)),
            crbs_core::engine::new_resource_snapshot_slot(),
        ),
    )
    .await
    .expect("execute_task must not hang");

    assert!(outcome.is_err());

    let reqs = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("mock hub should serve exactly 2 requests")
        .unwrap();
    assert_eq!(reqs.len(), 2, "building 之后必须继续到 SRPM 下载");

    assert_eq!(reqs[0].0, "post");
    let json: serde_json::Value = serde_json::from_str(&reqs[0].2).unwrap();
    assert_eq!(json["phase"], "building");
    assert_eq!(reqs[1].0, "get", "第二个请求必须是 SRPM 下载");
}

#[tokio::test]
async fn init_task_failure_reported_only_once() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(capture_one_request(listener));

    let tmp = tempfile::tempdir().unwrap();
    let cfg = test_cfg(format!("http://{}", addr), Some(&tmp.path().join("builds"))).await;
    let mut task = test_task();
    task.kind = "init".to_string();
    task.init_product = Some("ule3".to_string());

    task.product_config = "not-valid-toml".to_string();

    let err = crate::executor::run_init(
        &cfg,
        1,
        &task,
        CancellationToken::new(),
        &ExecutedAssignments::default(),
    )
    .await
    .expect_err("invalid product config must fail init");

    tokio::time::timeout(
        Duration::from_secs(10),
        report_task_failure(&cfg, 1, &task, err.to_string()),
    )
    .await
    .expect("init failure must not trigger a duplicate report (would hang on unserved mock)");

    let body = server.await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["phase"], "failed");
}

#[tokio::test]
async fn init_task_empty_product_config_fails_closed_and_reports_once() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));

    let tmp = tempfile::tempdir().unwrap();
    let cfg = test_cfg(format!("http://{}", addr), Some(&tmp.path().join("builds"))).await;
    let mut task = test_task();
    task.kind = "init".to_string();
    task.init_product = Some("ule3".to_string());
    task.product_config = String::new();

    let err = crate::executor::run_init(
        &cfg,
        1,
        &task,
        CancellationToken::new(),
        &ExecutedAssignments::default(),
    )
    .await
    .expect_err("empty product_config must fail closed on the worker");
    assert!(err.to_string().contains("product_config"), "err: {err}");

    let body = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("mock hub should serve exactly one failed report")
        .unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["phase"], "failed");
}

#[tokio::test]
async fn init_result_report_records_accepted_success_only() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));
    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let mut task = test_task();
    task.kind = "init".to_string();
    task.init_product = Some("ule3".to_string());
    let executed = ExecutedAssignments::default();
    crate::executor::report_init_result(
        &cfg,
        1,
        &task,
        &Ok(()),
        &CancellationToken::new(),
        &executed,
    )
    .await;
    let body = server.await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["phase"], "succeeded");
    assert!(
        executed.contains(task.assignment_id),
        "成功 init 上报被接受后必须登记去重集合（重投递据此跳过）"
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_n_requests(listener, 3, &["succeeded"]));
    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let mut retried = task.clone();
    retried.assignment_id = 9;
    let executed_retried = ExecutedAssignments::default();
    crate::executor::report_init_result(
        &cfg,
        1,
        &retried,
        &Ok(()),
        &CancellationToken::new(),
        &executed_retried,
    )
    .await;
    let bodies = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("mock hub should serve 3 requests")
        .unwrap();
    assert_eq!(bodies.len(), 3);
    assert!(
        !executed_retried.contains(9),
        "上报未被 hub 接受不得登记（重投递重执行是合法重试）"
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));
    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let mut failed = task.clone();
    failed.assignment_id = 10;
    let executed_failed = ExecutedAssignments::default();
    crate::executor::report_init_result(
        &cfg,
        1,
        &failed,
        &Err(CrbsError::io_message("init engine failed".to_string())),
        &CancellationToken::new(),
        &executed_failed,
    )
    .await;
    let body = server.await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["phase"], "failed");
    assert!(!executed_failed.contains(10), "失败 init 不得登记去重集合");
}

#[tokio::test]
async fn init_cancelled_result_report_survives_cancelled_task_token() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));
    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let mut task = test_task();
    task.kind = "init".to_string();
    task.init_product = Some("ule3".to_string());
    let executed = ExecutedAssignments::default();
    let token = CancellationToken::new();
    token.cancel();
    crate::executor::report_init_result(
        &cfg,
        1,
        &task,
        &Err(CrbsError::Cancelled),
        &token,
        &executed,
    )
    .await;
    let body = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("cancelled init terminal report must be delivered")
        .unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        json["phase"], "cancelled",
        "被取消的 init 必须以 cancelled 终态送达 hub（修前被已取消 token 吞掉，worker_tasks 滞 running）"
    );
    assert!(
        json["error"].is_null(),
        "取消终态不带 error（与 build 侧取消补报同口径）: {json}"
    );
    assert!(
        !executed.contains(task.assignment_id),
        "取消 init 不得登记去重集合（重投递重执行是唯一收敛路径）"
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));
    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let mut done = task.clone();
    done.assignment_id = 11;
    let executed_ok = ExecutedAssignments::default();
    let token2 = CancellationToken::new();
    token2.cancel();
    crate::executor::report_init_result(&cfg, 1, &done, &Ok(()), &token2, &executed_ok).await;
    let body = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("succeeded init supplementary report must be delivered")
        .unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        json["phase"], "succeeded",
        "被取消吞掉的成功 init 必须补报 succeeded（防 hub 重派双跑）"
    );
    assert!(
        executed_ok.contains(11),
        "补报被 hub 接受的成功 init 必须登记去重集合（与 build 路径同口径）"
    );
}

#[test]
fn ownership_probe_interval_clamps_to_30_60() {
    assert_eq!(ownership_probe_interval_secs(5), 30, "低于下限钳到 30");
    assert_eq!(ownership_probe_interval_secs(30), 30);
    assert_eq!(ownership_probe_interval_secs(45), 45, "区间内原样对齐心跳");
    assert_eq!(ownership_probe_interval_secs(60), 60);
    assert_eq!(ownership_probe_interval_secs(110), 60, "高于上限钳到 60");
}

#[test]
fn probe_decision_acts_on_positive_evidence_only() {
    let s = |code: u16| Some(reqwest::StatusCode::from_u16(code).unwrap());
    assert_eq!(probe_decision(s(200)), ProbeAction::Continue);
    assert_eq!(probe_decision(s(204)), ProbeAction::Continue);
    assert_eq!(probe_decision(s(409)), ProbeAction::FinishTerminal);
    assert_eq!(probe_decision(s(403)), ProbeAction::AbortLocal);
    assert_eq!(probe_decision(None), ProbeAction::Continue, "网络错误不动");
    assert_eq!(probe_decision(s(400)), ProbeAction::Continue);
    assert_eq!(probe_decision(s(401)), ProbeAction::Continue);
    assert_eq!(probe_decision(s(404)), ProbeAction::Continue);
    assert_eq!(probe_decision(s(429)), ProbeAction::Continue);
    assert_eq!(probe_decision(s(500)), ProbeAction::Continue);
    assert_eq!(probe_decision(s(503)), ProbeAction::Continue);
}

#[test]
fn probe_terminal_result_normalizes_err_by_real_phase() {
    let ok = BuildResult {
        phase: "succeeded".to_string(),
        result_dir: None,
        error: None,
        notes: None,
        resources: None,
        local_result_dir: None,
        engine_build_id: None,
        engine_result_root: None,
    };
    let out = probe_terminal_result(Ok(ok));
    assert_eq!(out.phase, "succeeded");

    let out = probe_terminal_result(Err(CrbsError::Cancelled));
    assert_eq!(out.phase, "cancelled");
    assert!(out.error.is_none(), "取消终态不带错误归因: {out:?}");

    let out = probe_terminal_result(Err(CrbsError::Timeout));
    assert_eq!(out.phase, "timeout");
    assert!(out.error.is_some());

    let out = probe_terminal_result(Err(CrbsError::Network {
        message: "download srpm: refused".to_string(),
    }));
    assert_eq!(out.phase, "failed");
    assert!(
        out.error.as_deref().unwrap().contains("download srpm"),
        "错误文本必须透传: {out:?}"
    );
}

enum MockReply {
    Status(u16),

    Close,
}

async fn serve_scripted_hub<F>(
    listener: TcpListener,
    reply_post: F,
) -> Arc<Mutex<Vec<(String, String)>>>
where
    F: Fn(usize) -> MockReply + Send + Sync + 'static,
{
    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let post_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reply_post = Arc::new(reply_post);
    let seen_for_server = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let seen = seen_for_server.clone();
            let post_hits = post_hits.clone();
            let reply_post = reply_post.clone();
            tokio::spawn(async move {
                let (method, path, body) = read_one_request(&mut sock).await;
                if method == "post" && path.contains("/result") {
                    let n = post_hits.fetch_add(1, Ordering::SeqCst);
                    seen.lock().unwrap().push((method, body));
                    match reply_post(n) {
                        MockReply::Status(code) => {
                            let reason = match code {
                                200 => "OK",
                                403 => "Forbidden",
                                409 => "Conflict",
                                _ => "Status",
                            };
                            let resp = format!(
                                "HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\n\
                                 Connection: close\r\n\r\n"
                            );
                            let _ = sock.write_all(resp.as_bytes()).await;
                            let _ = sock.flush().await;
                        }

                        MockReply::Close => drop(sock),
                    }
                } else if path.contains("/srpm/") {
                    std::future::pending::<()>().await;
                } else {
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\
                              Connection: close\r\n\r\n",
                        )
                        .await;
                    let _ = sock.flush().await;
                }
            });
        }
    });
    seen
}

async fn probe_test_setup(
    hub_addr: &std::net::SocketAddr,
) -> (WorkerConfig, AssignedTask, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = test_cfg(
        format!("http://{hub_addr}"),
        Some(&tmp.path().join("builds")),
    )
    .await;
    let mut task = test_task();
    task.srpm_url = "/api/v1/srpm/hello-1.0-1.src.rpm".to_string();
    (cfg, task, tmp)
}

const TEST_PROBE_INTERVAL: Duration = Duration::from_millis(50);

#[tokio::test]
async fn probe_403_aborts_local_build_and_skips_terminal_report() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let seen = serve_scripted_hub(listener, |n| match n {
        0 => MockReply::Status(200),
        _ => MockReply::Status(403),
    })
    .await;
    let (cfg, task, _tmp) = probe_test_setup(&addr).await;
    let executed = ExecutedAssignments::default();

    let outcome = tokio::time::timeout(
        Duration::from_secs(60),
        execute_task(
            1,
            &cfg,
            &task,
            CancellationToken::new(),
            &executed,
            TEST_PROBE_INTERVAL,
            crbs_core::engine::new_resource_snapshot_slot(),
        ),
    )
    .await
    .expect("403 后本地构建必须取消收敛，不得挂起");
    assert!(outcome.is_ok(), "Reclaimed 路径不得向上层抛错: {outcome:?}");
    assert!(
        !executed.contains(task.assignment_id),
        "被回收的构建不得登记去重集合"
    );

    let reqs = seen.lock().unwrap().clone();
    assert_eq!(reqs.len(), 2, "恰好首次上报 + 一次探针: {reqs:?}");
    for (_, body) in &reqs {
        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(json["phase"], "building", "不得出现终态上报: {reqs:?}");
    }
}

#[tokio::test]
async fn probe_409_cancels_local_build_and_reports_terminal() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let seen = serve_scripted_hub(listener, |n| match n {
        0 => MockReply::Status(200),
        1 => MockReply::Status(409),
        _ => MockReply::Status(200),
    })
    .await;
    let (cfg, task, _tmp) = probe_test_setup(&addr).await;
    let executed = ExecutedAssignments::default();

    let outcome = tokio::time::timeout(
        Duration::from_secs(60),
        execute_task(
            1,
            &cfg,
            &task,
            CancellationToken::new(),
            &executed,
            TEST_PROBE_INTERVAL,
            crbs_core::engine::new_resource_snapshot_slot(),
        ),
    )
    .await
    .expect("409 后本地构建必须取消收敛，不得挂起");
    assert!(outcome.is_ok(), "终态补报路径不得向上层抛错: {outcome:?}");
    assert!(
        !executed.contains(task.assignment_id),
        "cancelled 不登记去重"
    );

    let reqs = seen.lock().unwrap().clone();
    assert_eq!(reqs.len(), 3, "首次上报 + 探针 + 终态补报: {reqs:?}");
    let terminal: serde_json::Value = serde_json::from_str(&reqs[2].1).unwrap();
    assert_eq!(terminal["phase"], "cancelled", "补报必须携带真实终态");
    assert!(
        terminal["error"].is_null(),
        "取消终态不带错误归因（与既有取消补报同口径）: {terminal}"
    );
}

#[tokio::test]
async fn probe_network_error_leaves_build_running() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let seen = serve_scripted_hub(listener, |n| match n {
        0 => MockReply::Status(200),
        _ => MockReply::Close,
    })
    .await;
    let (cfg, task, _tmp) = probe_test_setup(&addr).await;
    let executed = ExecutedAssignments::default();
    let cancel = CancellationToken::new();

    let mut running = tokio::spawn({
        let cfg = cfg.clone();
        let task = task.clone();
        let executed = executed.clone();
        let cancel = cancel.clone();
        async move {
            execute_task(
                1,
                &cfg,
                &task,
                cancel,
                &executed,
                TEST_PROBE_INTERVAL,
                crbs_core::engine::new_resource_snapshot_slot(),
            )
            .await
        }
    });

    tokio::time::timeout(Duration::from_secs(10), async {
        while seen.lock().unwrap().len() < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("至少一次探针被尝试过（否则用例没测到探针路径）");
    assert!(
        !running.is_finished(),
        "网络错误的探针（阴性证据）不得中止在跑构建"
    );

    cancel.cancel();
    let outcome = tokio::time::timeout(Duration::from_secs(60), &mut running)
        .await
        .expect("shutdown 取消后构建必须收敛退出")
        .expect("join must succeed");
    assert!(
        matches!(outcome, Err(CrbsError::Cancelled)),
        "shutdown 取消语义不变: {outcome:?}"
    );

    let reqs = seen.lock().unwrap().clone();
    assert!(
        reqs.len() >= 2,
        "至少一次探针被尝试过（否则用例没测到探针路径）: {reqs:?}"
    );
    for (_, body) in &reqs {
        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(json["phase"], "building", "不得出现终态上报: {reqs:?}");
    }
}
