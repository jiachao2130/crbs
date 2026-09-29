// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! poller 测试：探针、取消、归属与执行路径。

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

/// 退避决策表：5s 起 ×2 指数、封顶 60s；0（防御）按首败。
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

/// 失活判定决策表：窗口内（含恰等于 600s）不报；超窗报静默秒数；时钟
/// 回拨不误报。
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

/// 总预算决策表：init = 3h + 30min 富余；build 与 effective_build_timeout
/// 同口径（请求值透传 / 0 显式不限时 → None / 缺省回落 worker 配置 / 配置
/// 0 关闭 → None / 巨值饱和封顶不回绕）。
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

/// 水位门决策表（磁盘/内存同一判定函数）：低于拦、等于放行、0 关闭、
/// Err fail-open。
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

/// MemAvailable 解析：标准形态取值、缺行 None、脏值 None。
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

/// 真实探测路径：未创建路径向上收敛到祖先探测，u64::MAX 必拦、0 放行。
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

/// guard Drop（含 panic）移除条目，迟到通知不再命中。
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

/// 去重生命周期：未注册 → 注册；guard 存活期重投递命中；Drop 后不再
/// 去重（reclaim 重派的新执行合法）。
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

/// 集合生命周期 + FIFO 定容：record 后命中、超容驱逐最老、重复不重登。
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

/// 接线语义：双成功登记去重；失败不登记（hub 落账后的重派是合法重试）。
#[tokio::test]
async fn report_build_result_records_only_double_success() {
    // ① 双成功：登记。
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

    // ② 失败构建：不得登记。
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

/// Cancelled 臂：补报 accepted 的 succeeded 记入去重集合。
#[tokio::test]
async fn report_build_result_cancelled_arm_records_accepted_success() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));
    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let task = test_task();
    let executed = ExecutedAssignments::default();

    // 模拟上报重试中途被取消：主 token 已触发，result 为真实 succeeded。
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

/// wire 兼容：redelivered 缺席（旧 hub）→ false，显式 true → true。
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

/// 读一个 HTTP 请求（headers + Content-Length body），返回 (方法, 路径,
/// body)；header 整体 lowercase。读循环与 test_util::read_request 共用，
/// 此处只做请求行/长度解析与切片。
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

/// 极简 mock hub：接收一次 HTTP 请求，返回 body 文本并回 200。
async fn capture_one_request(listener: TcpListener) -> String {
    let (mut sock, _) = listener.accept().await.unwrap();
    let (_, _, body) = read_one_request(&mut sock).await;
    sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
        .await
        .unwrap();
    sock.flush().await.unwrap();
    body
}

/// mock hub 多请求版：恰好 `n` 个请求，phase 命中 `reject_phases` 回
/// 503、否则 200；`Connection: close` 让 reqwest 每次重试新建连接。
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

/// mock hub：恰好 n 个请求全回 404（确定性 4xx）。
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

/// 回归：execute_task 出错必须补报 failed，否则 Hub 卡 building。
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

/// 预算 abort 保样本：report_terminal_failure_with_resources 把
/// 快照读到的已采值带进终态 payload（含资源字段）；默认臂保持 resources=null。
#[tokio::test]
async fn report_terminal_failure_carries_snapshot_resources() {
    // 无资源臂：resources 序列化为 null（取消/不可得同口径）。
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

    // 携带臂：槽位快照值（三值 + 资源字段）整体进 payload；空槽位仍 null。
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

/// 回归：主 token 取消后终态上报仍须发出（独立 token）。
#[tokio::test]
async fn report_terminal_failure_still_sends_after_shutdown_cancel() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));

    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let task = test_task();

    // 模拟 shutdown：主 token 已触发。
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

/// 回归：主 token 已取消后，独立 token 补报仍须送达 cancelled；对照组
/// 锚定 report_result 入口吞已取消令牌的契约。
#[tokio::test]
async fn cancelled_terminal_report_survives_main_token_cancel() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_one_request(listener));

    let cfg = test_cfg(format!("http://{}", addr), None).await;
    let task = test_task();

    // 模拟 shutdown：主取消 token 已触发。
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

    // 对照组：已取消主 token 的常规上报入口即被吞，mock 不应收到请求；
    // error 打泄漏标记以便与补报（error 恒 null）区分。
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

/// 回归：认证拒绝退出——先取消主 token、drain 在跑任务以 cancelled
/// 补报收尾、drain 窗口内退出，而非直接 break detach 在跑构建。
#[tokio::test]
async fn auth_rejected_poll_cancels_running_tasks_and_drains_within_window() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // 按路径路由的 mock hub（/result 含 /assignments 子串，必须先判）：
    // /result 记录后 200；/srpm/ 挂起（在途下载）；/assignments 第 1 次
    // 回任务、第 2 次回 401。
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
                        // 挂起模拟在途下载；poller 取消后请求 future 被 drop。
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

    // capacity=4：在跑持一槽后第二次 poll 仍能撞 401；min_free_disk_gb=0
    // 关水位门（不依赖测试机磁盘）。
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

    // 断言点 1：退出前已取消主 token。
    assert!(
        cancel_token.is_cancelled(),
        "auth-rejected exit must cancel the main token before draining"
    );
    // 断言点 2：退出发生在 drain 窗口内。
    assert!(
        elapsed < AUTH_EXIT_DRAIN,
        "poller exited at {elapsed:?}, not within the drain window"
    );

    // 断言点 3：cancelled 终态经独立 token 补报送达。
    let requests = seen.lock().unwrap().clone();
    let cancelled_reports: Vec<serde_json::Value> = requests
        .iter()
        // read_one_request 已 lowercase（见其 doc）。
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

/// 回归：本地成功但上报耗尽——不走 Err（会把成功记成 failed）；mock 对
/// succeeded 持续 503、其它 200（hub 半恢复窗口），断言全部请求为
/// succeeded；本地产物保留。
#[tokio::test]
async fn succeeded_report_failure_keeps_artifacts_and_skips_failed_report() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // report_result 对可重试错误（5xx → Network）共 3 次尝试。
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

/// 上传 + 上报双成功 → 本地结果目录即时删除（hub 已持有完整副本）。
/// 目录布局按引擎真实形态 `{result_root}/{product}/{pkg}/{ts}-{build_id}`。
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
        error: None, // 上传成功（上传失败时 run_build 置 Some）
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

/// error=Some（上传失败标记）时即使上报成功也保留本地目录。
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

/// 对照：失败构建上报耗尽仍走 Err（上层补报 failed）。
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

/// 回归：可重试网络错误耗尽后放弃本次执行且不发起 SRPM 下载；但不得
/// 补报终态 failed——构建未开工，交给 hub reclaimer 超时重派。
#[tokio::test]
async fn building_report_network_exhaustion_leaves_assignment_for_reclaimer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // building 持续 503（→ Network 可重试）×3 次耗尽；只服务这 3 个请求。
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

/// 对照：确定性 4xx 时 hub 可达、归属未失联，构建照常继续到 SRPM 下载。
#[tokio::test]
async fn building_report_4xx_still_continues_to_download() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // 全 404：building 上报（不可重试）继续；SRPM GET 404 退出。共 2 请求。
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

    // SRPM 下载 404 → run_build Err；本测试只关心 building 之后流程继续。
    assert!(outcome.is_err());

    let reqs = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("mock hub should serve exactly 2 requests")
        .unwrap();
    assert_eq!(reqs.len(), 2, "building 之后必须继续到 SRPM 下载");
    // read_one_request 返回 lowercase 化的请求行（为 content-length 匹配）。
    assert_eq!(reqs[0].0, "post");
    let json: serde_json::Value = serde_json::from_str(&reqs[0].2).unwrap();
    assert_eq!(json["phase"], "building");
    assert_eq!(reqs[1].0, "get", "第二个请求必须是 SRPM 下载");
}

/// 回归：run_init 失败已自行上报，report_task_failure 不得二次上报。
#[tokio::test]
async fn init_task_failure_reported_only_once() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // mock 只服务 1 个请求；若补报，第二连接无人应答挂起，靠 timeout 暴露。
    let server = tokio::spawn(capture_one_request(listener));

    let tmp = tempfile::tempdir().unwrap();
    let cfg = test_cfg(format!("http://{}", addr), Some(&tmp.path().join("builds"))).await;
    let mut task = test_task();
    task.kind = "init".to_string();
    task.init_product = Some("ule3".to_string());
    // 非法产品 TOML 让引擎构造快速失败，避免测试里真的跑 base_os init。
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

/// product_config 为空 → fail-closed 拒绝（不回退本地 products/*.toml），
/// 恰一次 failed 上报（mock 只服务一个请求）。
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

/// init 登记语义：succeeded 上报被接受 → 登记（重投递跳过）；上报耗尽或
/// 失败上报被接受 → 不登记——hub 未落账 succeeded 时重投递重执行是唯一
/// 收敛路径。经 report_init_result 直驱（真实 init 无法在单测跑完）。
#[tokio::test]
async fn init_result_report_records_accepted_success_only() {
    // ① 成功 init + 上报被接受（mock hub 200）→ 登记。
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

    // ② 成功 init 但上报耗尽重试（succeeded 持续 503 ×3）→ 不登记。
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

    // ③ 失败 init + 上报被接受 → 不登记。
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

/// 回归（init 取消终态补报）：已取消 token 的 report_result 入口返
/// Cancelled，init 终态不上报则 worker_tasks 滞 running、has_active_init
/// 阻断派发。独立 token 补报真实 phase：
/// ① 取消的 init 送达 cancelled（不折 failed），不登记去重；
/// ② 中途被取消的成功 init 补报 succeeded 并登记（防重派双跑）。
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

    // ② 成功 init + 上报中途被取消：补报 succeeded 且登记。
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

// ---- 阳性归属探针 ----

/// 探针周期决策表：对齐心跳钳 [30, 60]。
#[test]
fn ownership_probe_interval_clamps_to_30_60() {
    assert_eq!(ownership_probe_interval_secs(5), 30, "低于下限钳到 30");
    assert_eq!(ownership_probe_interval_secs(30), 30);
    assert_eq!(ownership_probe_interval_secs(45), 45, "区间内原样对齐心跳");
    assert_eq!(ownership_probe_interval_secs(60), 60);
    assert_eq!(ownership_probe_interval_secs(110), 60, "高于上限钳到 60");
}

/// 三分支决策表：2xx/409/403 处置；阴性证据（None 及其余状态码）一律
/// 不动。
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

/// 终态归一：Ok 透传；Cancelled → cancelled 无 error；其余按真实 phase
/// 折叠带文本。
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

/// 探针接线测试的 mock hub 应答脚本。
enum MockReply {
    /// 回给定状态码 + 空 body（Connection: close）。
    Status(u16),
    /// 读掉请求后立即关闭连接（无应答 = 网络错误，不占用 10s 探针超时）。
    Close,
}

/// 探针接线 mock hub：POST /result 按命中序（第 0 个 = 首次 building
/// 上报）经 `reply_post` 脚本应答并捕获；GET /srpm/ 挂起（在途下载）。
/// 返回捕获的 (method, body) 列表。
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
                        // 无应答形态：弃连接让请求端立刻拿到连接错误。
                        MockReply::Close => drop(sock),
                    }
                } else if path.contains("/srpm/") {
                    // 在途下载：挂起，等取消击杀（同 auth-exit 测试形态）。
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

/// 探针接线测试共用：指向 mock hub 的配置 + 携带 SRPM URL 的 build 任务。
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

/// 节拍：短到亚秒驱动探针路径，长到避开首次上报/下载启动竞态。
const TEST_PROBE_INTERVAL: Duration = Duration::from_millis(50);

/// 回归（探针 403）：本地构建取消收敛、无终态补报（hub 只收到
/// building）、不登记去重。
#[tokio::test]
async fn probe_403_aborts_local_build_and_skips_terminal_report() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // 第 0 个 POST（首次 building 上报）200；第 1 个（探针）403。
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

/// 回归（探针 409）：本地取消后走取消后补报（cancelled 送达、error 不带
/// 归因），不登记去重。
#[tokio::test]
async fn probe_409_cancels_local_build_and_reports_terminal() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // 首次 200；探针 409；补报 200（幂等吸收语义在 result.rs 覆盖）。
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

/// 回归（探针无应答）：多个周期后构建仍在跑、无终态上报；外层取消
/// 照常击杀（令牌协同不受探针影响）。
#[tokio::test]
async fn probe_network_error_leaves_build_running() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // 首次 building 200；其后所有 POST（探针）无应答即弃连（网络错误）。
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

    // 等待至少一次探针落表：固定 sleep 在并行测试负载下可能整个错过 50ms
    // 探针周期（探针路径未被覆盖就退出的假阴性），改为条件轮询 + 超时。
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

    // 外层取消照常击杀。
    cancel.cancel();
    let outcome = tokio::time::timeout(Duration::from_secs(60), &mut running)
        .await
        .expect("shutdown 取消后构建必须收敛退出")
        .expect("join must succeed");
    assert!(
        matches!(outcome, Err(CrbsError::Cancelled)),
        "shutdown 取消语义不变: {outcome:?}"
    );

    // 全部 POST 均为 building（无终态上报混入）。
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
