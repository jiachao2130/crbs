// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! SSE 测试共享夹具与应用构造辅助。

use super::*;

/// 重连提示抖动纯函数边界测试——0 → 4s 下沿、2000 → 6s 上沿、
/// 2001 回卷 4s（值域恒在 [4s, 6s]）。
#[test]
fn sse_reconnect_hint_jitter_window() {
    assert_eq!(sse_reconnect_hint(0), Duration::from_millis(4000));
    assert_eq!(sse_reconnect_hint(2000), Duration::from_millis(6000));
    assert_eq!(sse_reconnect_hint(2001), Duration::from_millis(4000));
}

/// 退避乘数决策表：健康与首错恒 ×1（保留快速恢复），2→4→8→16 翻倍，
/// ×16 封顶（移位钳 4，巨计数不溢出）。
#[test]
fn sse_db_retry_backoff_multiplier_first_error_keeps_base_then_doubles_and_caps() {
    assert_eq!(
        sse_db_retry_backoff_multiplier(0),
        1,
        "healthy loop keeps the base interval"
    );
    assert_eq!(
        sse_db_retry_backoff_multiplier(1),
        1,
        "first error keeps base for fast recovery"
    );
    assert_eq!(sse_db_retry_backoff_multiplier(2), 2);
    assert_eq!(sse_db_retry_backoff_multiplier(3), 4);
    assert_eq!(sse_db_retry_backoff_multiplier(4), 8);
    assert_eq!(sse_db_retry_backoff_multiplier(5), 16, "capped at x16");
    assert_eq!(
        sse_db_retry_backoff_multiplier(50),
        16,
        "huge counters stay capped (no overflow)"
    );
    // 组合语义锚点：默认 5s 兜底下满退避一轮等 80s（只放大兜底 sleep 臂）。
    assert_eq!(
        SSE_POLL_DEFAULT.poll_interval * sse_db_retry_backoff_multiplier(5),
        Duration::from_secs(80)
    );
}

/// 返回 (AppState, TempDir)：TempDir 必须存活到测试结束——提前 drop 会删掉
/// crbs.db 所在目录，负载下池新开连接即 SQLITE_CANTOPEN（曾致 SSE 时序
/// 测试全量跑时随机失败）。
pub(super) async fn test_app_state() -> (Arc<AppState>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    (
        Arc::new(AppState::for_test(
            store,
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        )),
        tmp,
    )
}

pub(super) async fn collect_body_data(body: Body) -> Vec<Bytes> {
    let mut stream = body.into_data_stream();
    let mut out = Vec::new();
    while let Ok(result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.next()).await
    {
        match result {
            Some(Ok(bytes)) => out.push(bytes),
            Some(Err(_)) | None => break,
        }
    }
    out
}

/// 构造 AppState 并保持结果根目录存活；result_root 为
/// `{crbs_root}/results`（与 for_test 默认 result_dir 一致）。
pub(super) async fn app_with_result_root() -> (Arc<AppState>, tempfile::TempDir, std::path::PathBuf)
{
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app = Arc::new(AppState::for_test(
        store,
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let result_root = tmp.path().join("results");
    (app, tmp, result_root)
}

/// 插入一个 task 及其 building 状态的 x86_64 子构建记录（无 result_dir）。
pub(super) async fn insert_building_task_build(app: &Arc<AppState>) -> (i64, i64) {
    let task_id = app
        .state_store
        .insert_task(crbs_core::TaskInsert {
            product: "fedora",
            pkg_name: "pkg",
            user: "alice",
            user_id: None,
            phase: "building",
            priority: 0,
            srpm_path: None,
            result_dir: None,
            ..Default::default()
        })
        .await
        .unwrap();
    let build_id = app
        .state_store
        .insert_build(crbs_core::BuildInsert {
            product: "fedora",
            pkg_name: "pkg",
            phase: "building",
            backend: "chroot",
            user: "alice",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    (task_id, build_id)
}

/// SSE 响应体后台读取器：数据块经 mpsc 转交测试线程，支持"静默窗"断言
///（collect_body_data 只在流结束时返回，看不到中途"某段时间没有推送"）。
pub(super) fn spawn_sse_body_reader(body: Body) -> tokio::sync::mpsc::Receiver<String> {
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(16);
    tokio::spawn(async move {
        let mut stream = body.into_data_stream();
        // 单块读兜底只防测试挂死，不是被测行为——满载并发下单块曾被
        // 调度拖过 15s 致流被误判提前结束；60s 保持防挂死且不误杀。
        while let Ok(Some(Ok(bytes))) =
            tokio::time::timeout(std::time::Duration::from_secs(60), stream.next()).await
        {
            let chunk = String::from_utf8_lossy(&bytes).to_string();
            if tx.send(chunk).await.is_err() {
                break;
            }
        }
        // 流结束 / 读超时：关闭通道，recv 侧以 None 收场。
    });
    rx
}

/// 收块直到累积文本命中谓词（单块超时即 panic；流提前结束也 panic）。
pub(super) async fn recv_until(
    rx: &mut tokio::sync::mpsc::Receiver<String>,
    pred: impl Fn(&str) -> bool,
    ctx: &str,
) -> String {
    let mut acc = String::new();
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv()).await {
            Ok(Some(chunk)) => {
                acc.push_str(&chunk);
                if pred(&acc) {
                    return acc;
                }
            }
            Ok(None) => panic!("SSE stream ended while waiting for {ctx}: {acc}"),
            Err(_) => panic!("timed out waiting for {ctx}: {acc}"),
        }
    }
}

/// 复鉴权失败分流表驱动：服务不可用类（含 DB 抖动映射的 5xx）瞬态容忍
/// 重试；凭据/权限/业务类（401/403/404/400/409/429）终局判定立即断流。
#[test]
fn sse_reauth_error_is_transient_classifies_all_variants() {
    let transient = [
        ApiError::ServiceUnavailable("auth backend down".into()),
        ApiError::Internal("auth backend internal".into()),
        ApiError::GatewayTimeout("auth backend timeout".into()),
    ];
    for e in &transient {
        assert!(sse_reauth_error_is_transient(e), "{e:?} must be transient");
    }
    let terminal = [
        ApiError::Unauthorized("session revoked".into()),
        ApiError::PermissionDenied("product is private".into()),
        ApiError::NotFound("build 42 not found".into()),
        ApiError::Validation("bad request".into()),
        ApiError::Conflict("revision conflict".into()),
        ApiError::TooManyRequests("rate limited".into()),
    ];
    for e in &terminal {
        assert!(
            !sse_reauth_error_is_transient(e),
            "{e:?} must be terminal (break the stream)"
        );
    }
}
