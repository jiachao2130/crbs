// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 后台维护：监督循环、心跳回收、日志缓冲清理与 session 清理。

use super::common::*;
use super::*;

#[test]
fn tick_backoff_secs_doubles_and_caps_at_30s() {
    assert_eq!(
        tick_backoff_secs(0),
        2,
        "healthy loop keeps the 2s base tick"
    );
    assert_eq!(
        tick_backoff_secs(1),
        2,
        "first failure keeps base for fast recovery"
    );
    assert_eq!(tick_backoff_secs(2), 4);
    assert_eq!(tick_backoff_secs(3), 8);
    assert_eq!(tick_backoff_secs(4), 16);
    assert_eq!(tick_backoff_secs(5), 30, "capped at 30s");
    assert_eq!(
        tick_backoff_secs(50),
        30,
        "huge counters stay capped (no overflow)"
    );
}

#[test]
fn completed_at_older_than_parses_db_text_and_fails_closed() {
    let day = Duration::from_secs(24 * 3600);
    let stale = (chrono::Utc::now() - chrono::Duration::hours(25))
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string();
    assert!(completed_at_older_than(&stale, day));
    let fresh = (chrono::Utc::now() - chrono::Duration::hours(1))
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string();
    assert!(!completed_at_older_than(&fresh, day));
    assert!(!completed_at_older_than("garbage", day));
    assert!(!completed_at_older_than("2026-01-01T00:00:00Z", day));
}

#[tokio::test]
async fn evict_stale_terminal_log_buffers_respects_phase_and_grace() {
    let (app, _tmp) = setup_app(4).await;
    let store = &app.state_store;

    let stale = seed_pending_build(store, "pkg", Some("x86_64"), 0).await;
    store.complete_build(stale, "failed", None).await.unwrap();
    sqlx::query("UPDATE builds SET completed_at = datetime('now', '-25 hours') WHERE id = ?")
        .bind(stale)
        .execute(store.pool())
        .await
        .unwrap();
    app.log_buffer.register(stale);
    assert!(app.log_buffer.has(stale));

    let fresh_terminal = seed_pending_build(store, "pkg", Some("x86_64"), 0).await;
    store
        .complete_build(fresh_terminal, "failed", None)
        .await
        .unwrap();
    app.log_buffer.register(fresh_terminal);

    let active = seed_building_build(store, "pkg", 0).await;
    app.log_buffer.register(active);

    // 行不存在（被 prune）：注册的孤儿条目。
    let pruned = stale + 100_000;
    app.log_buffer.register(pruned);

    let mut evict_warn = crbs_core::util::WarnThrottle::new(20);
    evict_stale_terminal_log_buffers(&app, &mut evict_warn).await;

    assert!(
        !app.log_buffer.has(stale),
        "stale terminal entry must be evicted"
    );
    assert!(
        !app.log_buffer.notify_tracked_ids().contains(&stale),
        "evict must also clean the notify handle"
    );
    assert!(
        !app.log_buffer.has(pruned),
        "entry for pruned build row must be evicted"
    );
    assert!(
        app.log_buffer.has(fresh_terminal),
        "terminal entry within grace must stay"
    );
    assert!(app.log_buffer.has(active), "active entry must stay");
}

#[tokio::test]
async fn evict_stale_terminal_log_buffers_db_error_fails_closed() {
    let (app, _tmp) = setup_app(4).await;
    let store = &app.state_store;

    // 两个终态超期条目（无故障时都会被驱逐）。
    let mut stale_ids = Vec::new();
    for _ in 0..2 {
        let id = seed_pending_build(store, "pkg", Some("x86_64"), 0).await;
        store.complete_build(id, "failed", None).await.unwrap();
        sqlx::query("UPDATE builds SET completed_at = datetime('now', '-25 hours') WHERE id = ?")
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap();
        app.log_buffer.register(id);
        assert!(app.log_buffer.has(id));
        stale_ids.push(id);
    }

    // 注入 DB 故障：builds 表消失 → 每个 tracked id 的 get_build 都返回 Err。
    sqlx::query("DROP TABLE builds")
        .execute(store.pool())
        .await
        .unwrap();

    let mut evict_warn = crbs_core::util::WarnThrottle::new(20);
    evict_stale_terminal_log_buffers(&app, &mut evict_warn).await;

    for id in stale_ids {
        assert!(
            app.log_buffer.has(id),
            "DB error must fail closed: no eviction this round"
        );
    }
}

#[tokio::test]
async fn reclaim_requeues_stuck_task() {
    let (app, _tmp) = setup_app(4).await;
    let build_id = seed_pending_build(&app.state_store, "pkg", Some("x86_64"), 0).await;
    let worker_id = seed_worker(&app.state_store, "w1", "x86_64", 2).await;

    app.state_store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    // 把 worker 心跳拨到 300s 前（超过 120s 阈值）
    age_worker_heartbeat(&app.state_store, worker_id, 300).await;

    reclaim_offline_workers(&app).await.unwrap();

    assert_eq!(
        build_phase(&app.state_store, build_id).await,
        "pending",
        "reclaimed build should be back to pending"
    );
}

#[tokio::test]
async fn reclaim_does_nothing_when_worker_healthy() {
    let (app, _tmp) = setup_app(4).await;
    let build_id = seed_pending_build(&app.state_store, "pkg", Some("x86_64"), 0).await;
    let worker_id = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    app.state_store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    reclaim_offline_workers(&app).await.unwrap();

    assert_eq!(
        build_phase(&app.state_store, build_id).await,
        "assigned",
        "healthy worker's task should not be reclaimed"
    );
}

#[tokio::test(start_paused = true)]
async fn supervised_loop_restarts_panicking_body() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let cancel = CancellationToken::new();
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_in_body = attempts.clone();
    let supervisor = spawn_supervised_loop("panic_test", cancel, move |_| {
        let attempts = attempts_in_body.clone();
        async move {
            attempts.fetch_add(1, Ordering::SeqCst);
            if attempts.load(Ordering::SeqCst) < 3 {
                panic!("intentional test panic");
            }
        }
    });

    tokio::time::timeout(Duration::from_secs(120), async {
        while attempts.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("loop body must be restarted after panics");

    tokio::time::timeout(Duration::from_secs(5), supervisor)
        .await
        .expect("supervisor exits after clean loop return")
        .expect("supervisor itself must not panic");
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
}

#[tokio::test(start_paused = true)]
async fn supervised_loop_runs_body_once_when_it_returns_on_cancel() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let cancel = CancellationToken::new();
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_in_body = attempts.clone();
    let cancel_in_body = cancel.clone();
    let supervisor = spawn_supervised_loop("cancel_exit_test", cancel.clone(), move |_| {
        let attempts = attempts_in_body.clone();
        let cancel = cancel_in_body.clone();
        async move {
            attempts.fetch_add(1, Ordering::SeqCst);
            // 真实循环体的典型形态：等 cancel 后正常 return。
            cancel.cancelled().await;
        }
    });

    tokio::time::timeout(Duration::from_secs(5), async {
        while attempts.load(Ordering::SeqCst) < 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("loop body should start once");

    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), supervisor)
        .await
        .expect("supervisor exits after cancel-driven clean return")
        .expect("supervisor itself must not panic");
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "clean return must not trigger a restart"
    );
}

#[tokio::test(start_paused = true)]
async fn supervised_loop_skips_body_when_pre_cancelled() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let cancel = CancellationToken::new();
    cancel.cancel();
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_in_body = attempts.clone();
    let supervisor = spawn_supervised_loop("pre_cancelled_test", cancel, move |_| {
        let attempts = attempts_in_body.clone();
        async move {
            attempts.fetch_add(1, Ordering::SeqCst);
        }
    });

    tokio::time::timeout(Duration::from_secs(5), supervisor)
        .await
        .expect("supervisor must exit without running the body")
        .expect("supervisor itself must not panic");
    assert_eq!(attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn terminal_sweep_evicts_log_buffer_of_released_builds() {
    async fn seed_terminal_with_running_task(
        app: &Arc<AppState>,
        with_persisted_log: bool,
        tmp: &std::path::Path,
    ) -> i64 {
        let task_id = crate::test_support::seed_task(&app.state_store, "test", "pkg").await;
        let build_id = app
            .state_store
            .insert_build(crbs_core::BuildInsert {
                product: "test",
                pkg_name: "pkg",
                phase: "pending",
                backend: "chroot",
                user: "tester",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let worker_id = seed_worker(&app.state_store, "w-evict", "x86_64", 2).await;
        app.state_store
            .assign_build_to_worker(build_id, worker_id)
            .await
            .unwrap();
        // 模拟已开跑 + 已终态但 report 丢失（worker_task 停留 running）。
        sqlx::query("UPDATE worker_tasks SET status = 'running' WHERE build_id = ?")
            .bind(build_id)
            .execute(app.state_store.pool())
            .await
            .unwrap();
        app.state_store
            .complete_build(build_id, "succeeded", None)
            .await
            .unwrap();

        if with_persisted_log {
            let log_dir = tmp
                .join("results")
                .join("persist-evict")
                .join(build_id.to_string());
            tokio::fs::create_dir_all(&log_dir).await.unwrap();
            tokio::fs::write(log_dir.join("build.log"), b"log")
                .await
                .unwrap();
            app.state_store
                .update_build_info(build_id, Some(log_dir.to_str().unwrap()), None, "test")
                .await
                .unwrap();
        }

        // LogBuffer 挂上实时条目（模拟构建期间 worker 流式上报）。
        app.log_buffer.register(build_id);
        app.log_buffer
            .append(build_id, bytes::Bytes::from("streaming"));
        assert!(app.log_buffer.has(build_id));
        build_id
    }

    let (app, tmp) = setup_app(4).await;

    let persisted = seed_terminal_with_running_task(&app, true, tmp.path()).await;
    let unpersisted = seed_terminal_with_running_task(&app, false, tmp.path()).await;

    release_terminal_worker_tasks(&app).await.unwrap();

    assert!(
        !app.log_buffer.has(persisted),
        "落盘日志存在时，终态 sweep 必须驱逐 LogBuffer（防内存滞留）"
    );
    assert!(
        app.log_buffer.has(unpersisted),
        "无落盘回退时保留缓冲（保守路径，与 report_result 同语义）"
    );
}

#[tokio::test]
async fn reclaim_spare_running_within_double_threshold() {
    let (app, _tmp) = setup_app(4).await;
    let worker_id = seed_worker(&app.state_store, "w1", "x86_64", 4).await;

    let b_assigned = seed_pending_build(&app.state_store, "pkg", Some("x86_64"), 0).await;
    let b_running = seed_pending_build(&app.state_store, "pkg2", Some("x86_64"), 0).await;
    app.state_store
        .assign_build_to_worker(b_assigned, worker_id)
        .await
        .unwrap();
    app.state_store
        .assign_build_to_worker(b_running, worker_id)
        .await
        .unwrap();
    // 模拟 worker 已拉取 running 任务：worker_tasks→running、builds→building。
    sqlx::query("UPDATE worker_tasks SET status = 'running' WHERE build_id = ?")
        .bind(b_running)
        .execute(app.state_store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET phase = 'building' WHERE id = ?")
        .bind(b_running)
        .execute(app.state_store.pool())
        .await
        .unwrap();

    // 失联 180s（>120 且 <240）：assigned 回 pending，running 保留 building。
    age_worker_heartbeat(&app.state_store, worker_id, 180).await;
    reclaim_offline_workers(&app).await.unwrap();
    assert_eq!(
        build_phase(&app.state_store, b_assigned).await,
        "pending",
        "assigned task must be reclaimed at the standard threshold"
    );
    assert_eq!(
        build_phase(&app.state_store, b_running).await,
        "building",
        "running task must survive until the double threshold"
    );

    // 失联 300s（>240）：running 也回收重派。
    age_worker_heartbeat(&app.state_store, worker_id, 300).await;
    // reclaim 会置 offline，恢复 online 以重新进入离线列表。
    sqlx::query("UPDATE workers SET status = 'online' WHERE id = ?")
        .bind(worker_id)
        .execute(app.state_store.pool())
        .await
        .unwrap();
    reclaim_offline_workers(&app).await.unwrap();
    assert_eq!(
        build_phase(&app.state_store, b_running).await,
        "pending",
        "running task must be reclaimed after the double threshold"
    );
}

#[tokio::test]
async fn reclaim_gone_worker_running_rows_after_grace() {
    let (app, _tmp) = setup_app(4).await;
    let worker_id = seed_worker(&app.state_store, "w-graceful", "x86_64", 4).await;

    let b_running = seed_pending_build(&app.state_store, "pkg", Some("x86_64"), 0).await;
    app.state_store
        .assign_build_to_worker(b_running, worker_id)
        .await
        .unwrap();
    // 模拟已领取（running/building）后优雅停机：mark_offline 刷新心跳并
    // 置 offline——list_offline_workers（只匹配 online）从此看不见它。
    sqlx::query("UPDATE worker_tasks SET status = 'running' WHERE build_id = ?")
        .bind(b_running)
        .execute(app.state_store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET phase = 'building' WHERE id = ?")
        .bind(b_running)
        .execute(app.state_store.pool())
        .await
        .unwrap();
    app.state_store
        .worker_mark_offline(worker_id)
        .await
        .unwrap();

    // 停机后 180s（<240s 双阈值）：running 保留。
    age_worker_heartbeat(&app.state_store, worker_id, 180).await;
    reclaim_offline_workers(&app).await.unwrap();
    assert_eq!(
        build_phase(&app.state_store, b_running).await,
        "building",
        "offline within grace: running task must survive"
    );

    // 停机后 300s（>240s）：running 也回收重派。
    age_worker_heartbeat(&app.state_store, worker_id, 300).await;
    reclaim_offline_workers(&app).await.unwrap();
    assert_eq!(
        build_phase(&app.state_store, b_running).await,
        "pending",
        "offline beyond grace: running task must be reclaimed"
    );
}

#[tokio::test]
async fn reclaim_gone_worker_without_assignments_is_noop() {
    let (app, _tmp) = setup_app(4).await;
    let worker_id = seed_worker(&app.state_store, "w-idle-off", "x86_64", 2).await;
    app.state_store
        .worker_mark_offline(worker_id)
        .await
        .unwrap();
    age_worker_heartbeat(&app.state_store, worker_id, 300).await;

    reclaim_offline_workers(&app).await.unwrap();

    let w = app.state_store.get_worker(worker_id).await.unwrap();
    assert!(w.is_some(), "无 assignment 的 offline worker 行必须保留");
    assert_eq!(w.unwrap().status, "offline");
}

#[tokio::test]
async fn scheduler_loop_exits_promptly_on_cancel() {
    let (app, _tmp) = setup_app(4).await;
    let cancel = CancellationToken::new();
    let app_clone = app.clone();
    let loop_cancel = cancel.clone();
    let handle = tokio::spawn(async move {
        run_scheduler_loop(app_clone, loop_cancel).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    cancel.cancel();

    // 取消后应立刻退出，而不是等待 2 秒 sleep
    tokio::time::timeout(Duration::from_millis(200), handle)
        .await
        .expect("scheduler loop should exit promptly after cancel")
        .expect("scheduler loop panicked");
}

#[tokio::test]
async fn session_cleanup_tick_removes_expired_and_revoked() {
    use crbs_core::auth::secret::{Secret, SecretKind};

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));

    let user_id = store.create_user("alice", "builder").await.unwrap();
    let seed = |expires: chrono::DateTime<chrono::Utc>| {
        let store = store.clone();
        let secret = Secret::generate(SecretKind::Session).unwrap();
        async move {
            store
                .create_session(user_id, secret.hash().as_str(), &expires.to_rfc3339(), None)
                .await
                .unwrap();
            secret
        }
    };
    let _expired_a = seed(chrono::Utc::now() - chrono::Duration::days(1)).await;
    let _expired_b = seed(chrono::Utc::now() - chrono::Duration::hours(1)).await;
    let live_a = seed(chrono::Utc::now() + chrono::Duration::days(1)).await;
    let live_b = seed(chrono::Utc::now() + chrono::Duration::days(30)).await;

    let seed_token = |expires_at: Option<String>| {
        let store = store.clone();
        let secret = Secret::generate(SecretKind::UserToken).unwrap();
        async move {
            let id = store
                .create_user_token(user_id, None, secret.hash().as_str(), expires_at.as_deref())
                .await
                .unwrap();
            (id, secret)
        }
    };
    let _expired_token = seed_token(Some(
        (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339(),
    ))
    .await;
    let (revoked_id, revoked_token) = seed_token(None).await;
    store.revoke_user_token(revoked_id).await.unwrap();
    let active_token = seed_token(Some(
        (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339(),
    ))
    .await;

    let removed = session_cleanup_tick(&app).await.unwrap();
    assert_eq!(removed, (2, 2), "only expired/revoked rows must be removed");

    assert!(
        store
            .find_session_by_hash(live_a.hash().as_str())
            .await
            .unwrap()
            .is_some(),
        "unexpired session (1d) must survive"
    );
    assert!(
        store
            .find_session_by_hash(live_b.hash().as_str())
            .await
            .unwrap()
            .is_some(),
        "unexpired session (30d) must survive"
    );
    assert!(
        store
            .find_user_token_by_hash(active_token.1.hash().as_str())
            .await
            .unwrap()
            .is_some(),
        "active token must survive"
    );
    assert!(
        store
            .find_user_token_by_hash(revoked_token.hash().as_str())
            .await
            .unwrap()
            .is_none(),
        "revoked token must be pruned (frees the UNIQUE(user_id, name) slot)"
    );

    // 幂等：再次 tick 无可删行
    assert_eq!(session_cleanup_tick(&app).await.unwrap(), (0, 0));
}
