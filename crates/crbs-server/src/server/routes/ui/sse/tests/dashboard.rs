// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 仪表盘 SSE 测试：状态计数推送与会话吊销。

use super::common::*;
use super::*;

/// 可见过滤与 SSR 同口径：工具步骤两种标记形态都不进签名与负载；
/// ccache_disabled SKIP 聚合排除（名单真源 components::HIDDEN_TOOL_PHASES）。
#[test]
fn visible_timeline_spans_hides_tool_phases_and_ccache_skips() {
    let spans = crbs_core::engine::profile::parse_phase_markers(
        "# CRBS_PHASE_START ccache-init 1.0\n\
         # CRBS_PHASE_END ccache-init 0 1.1\n\
         # CRBS_PHASE_START build 1.1\n\
         # CRBS_PHASE_SKIP ccache-summary ccache_disabled\n\
         # CRBS_PHASE_SKIP install-deps shared_layer\n",
    );
    let visible = visible_timeline_spans(&spans);
    let names: Vec<&str> = visible.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["build", "install-deps"]);
    // 签名与事件负载同步排除（任一漏网都会把隐藏步骤推给详情页 JS）。
    let sig = timeline_signature(&spans);
    assert!(!sig.contains("ccache"), "{sig}");
    let payload = timeline_event_payload(&spans);
    assert!(!payload.contains("ccache"), "{payload}");
}

/// dashboard SSE 复鉴权路径（独立循环）。驱动手段：查看门槛是静态
/// `public_access.view` 配置，产品翻转驱动不了；"删 session" 经
/// resolve_token 分类为 Ok(None)（降级匿名，非 Err），断流落在 Ok 分支的
/// check_view_access(None)——故用 view=false 配置驱动。Err 侧分流由表
/// 驱动测试覆盖。
#[tokio::test]
async fn dashboard_sse_terminates_after_session_revoked_mid_stream() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let mut config = ServerConfig::default();
    config.public_access.view = false;
    let app = Arc::new(AppState::for_test(store, config, tmp.path().to_path_buf()));

    // 用户 + 会话：握手经 Extension 注入身份快照，流内复鉴权经原始
    // cookie 头重解析（与生产中间件链同一条 resolve_token 路径）。
    let user_id = app
        .state_store
        .create_user("dash-owner", "builder")
        .await
        .unwrap();
    let secret =
        crbs_core::auth::secret::Secret::generate(crbs_core::auth::secret::SecretKind::Session)
            .unwrap();
    let session_id = app
        .state_store
        .create_session(
            user_id,
            secret.hash().as_str(),
            &(chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            Some("sse-recheck-test"),
        )
        .await
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        format!("crbs_session={}", secret.as_str()).parse().unwrap(),
    );
    let auth = Extension(AuthContext {
        user: "dash-owner".into(),
        role: "builder".into(),
        user_id: Some(user_id),
        ..Default::default()
    });

    // 流启动后撤销会话（revoke 会 bump 用户代数，AuthCache 正向缓存随即失配）。
    let revoker = app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        revoker
            .state_store
            .revoke_session(session_id)
            .await
            .unwrap();
    });

    let response = dashboard_sse_with_poll(
        State(app),
        headers,
        Some(auth),
        SsePollConfig {
            poll_interval: std::time::Duration::from_millis(20),
            visibility_recheck_interval: std::time::Duration::from_millis(40),
        },
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
        "dashboard SSE must disable reverse-proxy buffering"
    );

    let data = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        collect_body_data(response.into_body()),
    )
    .await
    .expect("dashboard SSE must terminate after session revocation");
    let text: String = data.iter().map(|b| String::from_utf8_lossy(b)).collect();
    assert!(
        text.contains("event: status"),
        "should stream initial status before revoke, got: {text}"
    );
}

/// 去重门：无状态写入时只推建连首推一次——timestamp 每次新生成，签名
/// 含入则每个兜底 tick 恒推。payload 仍为完整 StatusResponse。
#[tokio::test]
async fn dashboard_sse_pushes_status_only_when_counts_change() {
    let (app, _tmp) = test_app_state().await;
    let response = dashboard_sse_with_poll(
        State(app),
        HeaderMap::new(),
        None,
        SsePollConfig {
            poll_interval: std::time::Duration::from_millis(40),
            visibility_recheck_interval: std::time::Duration::from_secs(30),
        },
    )
    .await
    .unwrap()
    .into_response();

    // 收集 ~600ms（约 15 个兜底 tick）：去重生效则只有首推一次；每读
    // 限时 200ms，超时只表示本 tick 无事件，继续等到总窗满。
    let mut stream = response.into_body().into_data_stream();
    let mut text = String::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(600);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(Ok(bytes))) =
            tokio::time::timeout(std::time::Duration::from_millis(200), stream.next()).await
        {
            text.push_str(&String::from_utf8_lossy(&bytes));
        }
    }
    assert!(
        text.contains("event: status"),
        "initial status push missing: {text}"
    );
    // retry 行无 event 名，不参与下方按 event: 前缀的去重计数；值域
    // [4000,6000]ms 抖动，逐行断言范围。
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
    assert!(
        text.contains("timestamp"),
        "payload must stay the full StatusResponse (with timestamp): {text}"
    );
    assert_eq!(
        text.matches("event: status").count(),
        1,
        "unchanged state must not re-push status (timestamp is not a change): {text}"
    );
}
