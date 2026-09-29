// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 终态收口：完成/取消/相位守卫、资源列与任务相位聚合。

use super::common::*;
use super::*;

/// 资源列随终态写入：with_resources 落值、无资源保持 NULL。读回走裸
/// query（BuildRecord 未透出三列）。
#[tokio::test]
async fn complete_build_writes_resource_columns() {
    let (store, _tmp) = create_test_store().await;
    // 每构建各挂独立 task（否则共享 task 聚合终态后撞 task 守卫）。
    async fn mk_build(store: &StateStore, pkg: &str) -> i64 {
        let task_id = crate::state::test_state::seed_task(store, "fedora", pkg).await;
        store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: pkg,
                phase: "building",
                backend: "chroot",
                user: "alice",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap()
    }
    async fn read_resources(
        store: &StateStore,
        id: i64,
    ) -> (Option<i64>, Option<f64>, Option<f64>) {
        let row =
            sqlx::query("SELECT peak_rss_kb, cpu_secs, cpu_p90_cores FROM builds WHERE id = $1")
                .bind(id)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        use sqlx::Row as _;
        (
            row.get("peak_rss_kb"),
            row.get::<Option<f64>, _>("cpu_secs"),
            row.get::<Option<f64>, _>("cpu_p90_cores"),
        )
    }

    // 带资源写入：三列就位。
    let with_res = mk_build(&store, "res-with-1.0").await;
    store
        .complete_build_with_resources(
            with_res,
            "succeeded",
            None,
            Some(crate::engine::ResourceUsage {
                peak_rss_kb: Some(2_621_440),
                cpu_secs: Some(42.5),
                cpu_p90_cores: Some(3.7),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    let (peak, cpu, p90) = read_resources(&store, with_res).await;
    assert_eq!(peak, Some(2_621_440));
    assert_eq!(cpu, Some(42.5));
    assert_eq!(p90, Some(3.7));

    // 无资源写入（崩溃修复 / zombie / 只写 phase 的路径形态）：三列 NULL。
    let no_res = mk_build(&store, "res-null-1.0").await;
    store.complete_build(no_res, "failed", None).await.unwrap();
    let (peak, cpu, p90) = read_resources(&store, no_res).await;
    assert_eq!(peak, None);
    assert_eq!(cpu, None);
    assert_eq!(p90, None);
}

/// 采集包络五列（peak_total_kb / disk_wbytes / oom_killed / sample_backend /
/// sample_ncpu）与 tmpfs 峰值（peak_tmpfs_kb）随终态写入：全值 payload 各列
/// 就位；全 None payload → 各列 NULL；oom_killed bool 折 0/1。
#[tokio::test]
async fn complete_build_writes_envelope_columns() {
    let (store, _tmp) = create_test_store().await;
    async fn mk_build(store: &StateStore, pkg: &str) -> i64 {
        let task_id = crate::state::test_state::seed_task(store, "fedora", pkg).await;
        store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: pkg,
                phase: "building",
                backend: "nspawn",
                user: "alice",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap()
    }
    async fn read_envelope(
        store: &StateStore,
        id: i64,
    ) -> (
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<String>,
        Option<i64>,
        Option<i64>,
    ) {
        let row = sqlx::query(
            "SELECT peak_total_kb, disk_wbytes, oom_killed, sample_backend, sample_ncpu, \
             peak_tmpfs_kb FROM builds WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
        use sqlx::Row as _;
        (
            row.get("peak_total_kb"),
            row.get("disk_wbytes"),
            row.get("oom_killed"),
            row.get("sample_backend"),
            row.get("sample_ncpu"),
            row.get("peak_tmpfs_kb"),
        )
    }

    // 全值写入：六列就位（oom_killed true → 1；tmpfs 峰值随包络同写）。
    let full = mk_build(&store, "envelope-full-1.0").await;
    store
        .complete_build_with_resources(
            full,
            "succeeded",
            None,
            Some(crate::engine::ResourceUsage {
                peak_total_kb: Some(524_288),
                disk_wbytes: Some(1_236),
                oom_killed: Some(true),
                sample_backend: Some(crate::engine::SAMPLE_BACKEND_CGROUP),
                sample_ncpu: Some(8),
                peak_tmpfs_kb: Some(131_072),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    let (pt, dw, oom, backend, ncpu, tmpfs) = read_envelope(&store, full).await;
    assert_eq!(pt, Some(524_288));
    assert_eq!(dw, Some(1_236));
    assert_eq!(oom, Some(1), "oom_killed true must land as 1");
    assert_eq!(backend.as_deref(), Some("cgroup"));
    assert_eq!(ncpu, Some(8));
    assert_eq!(tmpfs, Some(131_072));

    // oom_killed false → 0（口径可用证据）。
    let no_oom = mk_build(&store, "envelope-nooom-1.0").await;
    store
        .complete_build_with_resources(
            no_oom,
            "failed",
            None,
            Some(crate::engine::ResourceUsage {
                oom_killed: Some(false),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    let (_, _, oom, _, _, _) = read_envelope(&store, no_oom).await;
    assert_eq!(oom, Some(0));

    // 扩展字段全缺的 payload：包络六列 NULL，老三列照常。
    let no_envelope = mk_build(&store, "envelope-noext-1.0").await;
    store
        .complete_build_with_resources(
            no_envelope,
            "failed",
            None,
            Some(crate::engine::ResourceUsage {
                peak_rss_kb: Some(1024),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    let (pt, dw, oom, backend, ncpu, tmpfs) = read_envelope(&store, no_envelope).await;
    assert_eq!(
        pt, None,
        "payload without extension fields must leave envelope columns NULL"
    );
    assert_eq!(dw, None);
    assert_eq!(oom, None);
    assert_eq!(backend, None);
    assert_eq!(ncpu, None);
    assert_eq!(tmpfs, None, "build_tmpfs off / 未采样的 tmpfs 峰值恒 NULL");
}

/// complete_build 成功路径广播状态变更（`changed()` 等待方被唤醒）。
#[tokio::test]
async fn complete_build_notifies_state_change_waiters() {
    let (_tmp, store) = tmp_store().await;
    let task_id = crate::state::test_state::seed_task(&store, "fedora", "notify-1.0").await;
    let id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "notify-1.0",
            phase: "building",
            backend: "chroot",
            user: "alice",
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    // 先 poll 一次 waiter（Notify 首次 poll 即注册，notify_waiters 必达），
    // 替代固定睡眠的启动竞态。
    let store = std::sync::Arc::new(store);
    let mut waiter = std::pin::pin!(store.changed());
    {
        use std::future::Future;
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};
        // Waker::noop() 1.85 才稳定（rust-version=1.82），用 Wake trait 构造等价 noop。
        struct NoopWake;
        impl Wake for NoopWake {
            fn wake(self: Arc<Self>) {}
        }
        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);
        assert!(
            matches!(waiter.as_mut().poll(&mut cx), Poll::Pending),
            "changed() must start pending before the write"
        );
    }

    let writer = store.clone();
    tokio::spawn(async move {
        writer.complete_build(id, "succeeded", None).await.unwrap();
    });
    let woke = tokio::time::timeout(std::time::Duration::from_secs(2), waiter.as_mut()).await;
    assert!(
        woke.is_ok(),
        "complete_build must wake changed() waiters within 2s"
    );
}

/// complete_build_guarded 归属 CAS：reclaim 重派后旧 attempt 迟到终态上报
/// 被拒（0 行，completed_at 不落），新持有者放行；无归属调用方走
/// with_error（None）不受影响。
#[tokio::test]
async fn complete_build_guarded_rejects_revoked_assignment() {
    let (store, _tmp) = create_test_store().await;
    let mk_build = |pkg: &'static str| {
        let store = &store;
        async move {
            let task_id = crate::state::test_state::seed_task(store, "fedora", pkg).await;
            let id = store
                .insert_build(BuildInsert {
                    product: "fedora",
                    pkg_name: pkg,
                    phase: "pending",
                    backend: "chroot",
                    user: "alice",
                    arch: Some("x86_64"),
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
                .unwrap();
            id
        }
    };
    let set_building = |id: i64| {
        let store = &store;
        async move {
            sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
                .bind(id)
                .execute(store.pool())
                .await
                .unwrap();
        }
    };
    let phase_of = |id: i64| {
        let store = &store;
        async move {
            let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
                .bind(id)
                .fetch_one(store.pool())
                .await
                .unwrap();
            phase
        }
    };
    let completed_at_of = |id: i64| {
        let store = &store;
        async move {
            let completed_at: Option<String> =
                sqlx::query_scalar("SELECT completed_at FROM builds WHERE id = $1")
                    .bind(id)
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            completed_at
        }
    };

    let worker_id = store
        .upsert_worker("guard-w", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    // 归属臂（行在）：持有者上报照常落终态。
    let b_owner = mk_build("guard-ok").await;
    store
        .assign_build_to_worker(b_owner, worker_id)
        .await
        .unwrap();
    set_building(b_owner).await;
    let rows = store
        .complete_build_guarded(b_owner, worker_id, "succeeded", None, None)
        .await
        .unwrap();
    assert_eq!(rows, 1, "owner report must pass the ownership CAS");
    assert_eq!(phase_of(b_owner).await, "succeeded");

    // 剥夺臂：reclaim + 重派后，旧 attempt 迟到上报被拒（0 行、
    // completed_at 不落）；新持有者放行。
    let b_revoked = mk_build("guard-revoked").await;
    store
        .assign_build_to_worker(b_revoked, worker_id)
        .await
        .unwrap();
    set_building(b_revoked).await;
    sqlx::query("DELETE FROM worker_tasks WHERE build_id = $1 AND worker_id = $2")
        .bind(b_revoked)
        .bind(worker_id)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET phase = 'pending' WHERE id = $1")
        .bind(b_revoked)
        .execute(store.pool())
        .await
        .unwrap();
    let new_worker = store
        .upsert_worker("guard-w-new", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    store
        .assign_build_to_worker(b_revoked, new_worker)
        .await
        .unwrap();
    set_building(b_revoked).await;

    let rows = store
        .complete_build_guarded(b_revoked, worker_id, "succeeded", None, None)
        .await
        .unwrap();
    assert_eq!(rows, 0, "revoked worker's late report must be rejected");
    assert_eq!(phase_of(b_revoked).await, "building");
    assert!(
        completed_at_of(b_revoked).await.is_none(),
        "rejected write must not stamp completed_at"
    );

    let rows = store
        .complete_build_guarded(b_revoked, new_worker, "succeeded", None, None)
        .await
        .unwrap();
    assert_eq!(rows, 1, "new assignee must pass the ownership CAS");
    assert_eq!(phase_of(b_revoked).await, "succeeded");

    // 无归属臂：with_error 在无 assignment 行的 build 上照常落终态。
    let b_local = mk_build("guard-local").await;
    set_building(b_local).await;
    let rows = store
        .complete_build_with_error(b_local, "failed", None, Some("boom"))
        .await
        .unwrap();
    assert_eq!(rows, 1, "unguarded path must not require assignment rows");
    assert_eq!(phase_of(b_local).await, "failed");
}

/// 终态守卫（1.0 硬化）：cancel 先到后，complete_build 不得覆盖 cancelled。
#[tokio::test]
async fn complete_build_does_not_override_cancelled() {
    let (store, _tmp) = create_test_store().await;
    let id = store
        .insert_build(BuildInsert {
            phase: "building",
            ..sample_insert(&store).await
        })
        .await
        .unwrap();

    store.mark_build_cancelled(id).await.unwrap();
    store.complete_build(id, "succeeded", None).await.unwrap();

    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "cancelled", "terminal phase must not be overridden");

    // 取消即终态：completed_at 必须落值（result-GC 门）。
    let completed_at: Option<String> =
        sqlx::query_scalar("SELECT completed_at FROM builds WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(
        completed_at.is_some(),
        "cancelled build must carry completed_at"
    );

    // duration 同口径落值；间隔毫秒级，只断言非 NULL 非负。
    let duration: Option<i64> = sqlx::query_scalar("SELECT duration FROM builds WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    let duration = duration.expect("cancelled build must carry duration like complete_build");
    assert!(
        duration >= 0,
        "duration must be non-negative, got {duration}"
    );

    // 三值语义：started_at NULL（遗留行）→ duration 亦 NULL（宁 NULL
    // 不伪造 0），completed_at 仍落值；首行已终态，同 identity 再插放行。
    let legacy_id = store
        .insert_build(BuildInsert {
            phase: "building",
            ..sample_insert(&store).await
        })
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET started_at = NULL WHERE id = $1")
        .bind(legacy_id)
        .execute(store.pool())
        .await
        .unwrap();
    store.mark_build_cancelled(legacy_id).await.unwrap();
    let legacy_duration: Option<i64> =
        sqlx::query_scalar("SELECT duration FROM builds WHERE id = $1")
            .bind(legacy_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(
        legacy_duration.is_none(),
        "NULL started_at must yield NULL duration, got {legacy_duration:?}"
    );
    let legacy_completed_at: Option<String> =
        sqlx::query_scalar("SELECT completed_at FROM builds WHERE id = $1")
            .bind(legacy_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(
        legacy_completed_at.is_some(),
        "cancelled build must carry completed_at regardless of duration"
    );
}

/// 终态守卫：complete 先到后，cancel 不得覆盖 succeeded（返回 0 行）。
#[tokio::test]
async fn mark_build_cancelled_rejects_terminal_build() {
    let (_tmp, store) = tmp_store().await;
    let id = store
        .insert_build(BuildInsert {
            phase: "building",
            ..sample_insert(&store).await
        })
        .await
        .unwrap();

    store.complete_build(id, "succeeded", None).await.unwrap();
    let affected = store.mark_build_cancelled(id).await.unwrap();
    assert_eq!(affected, 0, "terminal build must not be cancelled");

    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "succeeded");
}

/// 陈旧行回收：死/未记录 pid 的活跃行置 failed，活 pid 与终态行不动。
#[tokio::test]
async fn gc_stale_local_builds_reclaims_dead_pid_rows_only() {
    let (_tmp, store) = tmp_store().await;
    // 活 pid：测试进程自身。死 pid：spawn 后立即 wait 的短命子进程。
    let live_pid = std::process::id() as i64;
    let mut dead_child = std::process::Command::new("true").spawn().unwrap();
    let dead_pid = dead_child.id() as i64;
    dead_child.wait().unwrap();

    let mk = |pkg: &'static str, task_id: i64| BuildInsert {
        product: "fedora",
        pkg_name: pkg,
        phase: "building",
        backend: "chroot",
        user: "alice",
        task_id: Some(task_id),
        ..Default::default()
    };
    let seed = |pkg: &'static str| crate::state::test_state::seed_task(&store, "fedora", pkg);
    let dead_row = store
        .insert_build(mk("pkg-dead", seed("pkg-dead").await))
        .await
        .unwrap();
    store
        .update_build_crbs_pid(dead_row, dead_pid)
        .await
        .unwrap();
    let null_row = store
        .insert_build(mk("pkg-null", seed("pkg-null").await))
        .await
        .unwrap();
    let live_row = store
        .insert_build(mk("pkg-live", seed("pkg-live").await))
        .await
        .unwrap();
    store
        .update_build_crbs_pid(live_row, live_pid)
        .await
        .unwrap();
    let done_row = store
        .insert_build(mk("pkg-done", seed("pkg-done").await))
        .await
        .unwrap();
    store
        .update_build_crbs_pid(done_row, dead_pid)
        .await
        .unwrap();
    store
        .complete_build(done_row, "succeeded", None)
        .await
        .unwrap();

    let mut reclaimed = store.gc_stale_local_builds().await.unwrap();
    reclaimed.sort();
    assert_eq!(
        reclaimed,
        vec![dead_row, null_row],
        "dead/null-pid rows reclaimed"
    );

    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(live_row)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "building", "live-pid row must be untouched");
    let (phase, summary): (String, Option<String>) =
        sqlx::query_as("SELECT phase, error_summary FROM builds WHERE id = $1")
            .bind(dead_row)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(phase, "failed");
    assert!(summary.unwrap().contains(&dead_pid.to_string()));
    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(done_row)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "succeeded", "terminal row must be untouched");
}

/// 失败原因落库并读回；后续 complete（None）不影响已落库的值。
#[tokio::test]
async fn complete_build_with_error_persists_and_survives_guard() {
    let (_tmp, store) = tmp_store().await;
    let id = store
        .insert_build(BuildInsert {
            phase: "building",
            ..sample_insert(&store).await
        })
        .await
        .unwrap();

    let affected = store
        .complete_build_with_error(id, "failed", None, Some("exit_code=1 phase=build"))
        .await
        .unwrap();
    assert_eq!(affected, 1);

    let record = store.get_build(id).await.unwrap().unwrap();
    assert_eq!(record.phase, "failed");
    assert_eq!(
        record.error_summary.as_deref(),
        Some("exit_code=1 phase=build")
    );

    // 终态守卫：第二次 complete 被拒（0 行），error_summary 保持不变。
    let affected = store.complete_build(id, "failed", None).await.unwrap();
    assert_eq!(affected, 0);
    let record = store.get_build(id).await.unwrap().unwrap();
    assert_eq!(
        record.error_summary.as_deref(),
        Some("exit_code=1 phase=build")
    );
}

/// 截断防御：超长 error 只保留前 1024 字节（UTF-8 边界安全）。
#[tokio::test]
async fn complete_build_with_error_truncates_overlong_text() {
    let (_tmp, store) = tmp_store().await;
    let id = store
        .insert_build(BuildInsert {
            phase: "building",
            ..sample_insert(&store).await
        })
        .await
        .unwrap();

    // 3000 个单字节字符 + 多字节尾巴：截断点落在 1024 处。
    let long = format!("{}你你你", "x".repeat(3000));
    store
        .complete_build_with_error(id, "failed", None, Some(&long))
        .await
        .unwrap();

    let record = store.get_build(id).await.unwrap().unwrap();
    let stored = record.error_summary.unwrap();
    assert_eq!(stored.len(), 1024);
    assert_eq!(stored, "x".repeat(1024), "prefix must be preserved");
}

/// 截断纯函数：UTF-8 字符边界安全（多字节字符不跨界切半）。
#[test]
fn truncate_to_bytes_respects_char_boundary() {
    // "你"占 3 字节：4 字节上限只能容纳 1 个"你"（3 字节），不会切出半个。
    assert_eq!(truncate_to_bytes("你你你", 4), "你");
    assert_eq!(truncate_to_bytes("你你你", 6), "你你");
    assert_eq!(truncate_to_bytes("ab你", 2), "ab");
    // 短输入原样返回；上限落在字符结束点上不丢字符。
    assert_eq!(truncate_to_bytes("abc", 4), "abc");
    assert_eq!(truncate_to_bytes("你你", 6), "你你");
}

/// 终态守卫：活跃态（pending/building/assigned）正常完成与取消不受影响。
#[tokio::test]
async fn terminal_guard_allows_active_phase_transitions() {
    let (_tmp, store) = tmp_store().await;
    for (from, to, expect) in [
        ("pending", "succeeded", "succeeded"),
        ("assigned", "failed", "failed"),
        ("pending", "timeout", "timeout"),
        ("building", "cancelled", "cancelled"),
    ] {
        let id = store
            .insert_build(BuildInsert {
                phase: from,
                ..sample_insert(&store).await
            })
            .await
            .unwrap();
        if to == "cancelled" {
            store.mark_build_cancelled(id).await.unwrap();
        } else {
            store.complete_build(id, to, None).await.unwrap();
        }
        let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(phase, expect, "{} -> {} transition", from, to);
    }
}

#[tokio::test]
async fn complete_build_aggregates_task_phase_end_to_end() {
    let (_tmp, store) = tmp_store().await;
    let task_id = store
        .insert_task(crate::state::TaskInsert {
            product: "fedora",
            pkg_name: "hello-1.0-1.fc42",
            user: "alice",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();
    let mk_build = |arch: &'static str| {
        let store = &store;
        async move {
            store
                .insert_build(BuildInsert {
                    product: "fedora",
                    pkg_name: "hello-1.0-1.fc42",
                    phase: "pending",
                    backend: "chroot",
                    user: "alice",
                    arch: Some(arch),
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };
    let b1 = mk_build("x86_64").await;
    let b2 = mk_build("aarch64").await;

    // 第一个子构建成功：另一个仍 pending → task 进入 building
    store.complete_build(b1, "succeeded", None).await.unwrap();
    assert_eq!(
        store.get_task(task_id).await.unwrap().unwrap().phase,
        "building"
    );

    // 第二个也成功 → task 聚合为 succeeded 并记录完成时间
    store.complete_build(b2, "succeeded", None).await.unwrap();
    let task = store.get_task(task_id).await.unwrap().unwrap();
    assert_eq!(task.phase, "succeeded");
    assert!(task.completed_at.is_some());

    // failed 优先级高于 succeeded：再起一个 task 验证聚合序
    let task2 = store
        .insert_task(crate::state::TaskInsert {
            product: "fedora",
            pkg_name: "hello-1.0-1.fc42",
            user: "alice",
            phase: "pending",
            ..Default::default()
        })
        .await
        .unwrap();
    let b3 = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello-1.0-1.fc42",
            phase: "pending",
            backend: "chroot",
            user: "alice",
            arch: Some("x86_64"),
            task_id: Some(task2),
            ..Default::default()
        })
        .await
        .unwrap();
    store.complete_build(b3, "failed", None).await.unwrap();
    assert_eq!(
        store.get_task(task2).await.unwrap().unwrap().phase,
        "failed"
    );

    // 取消：终态守卫（affected == 0 拒绝重复取消）不回归
    assert_eq!(store.mark_build_cancelled(b3).await.unwrap(), 0);
}

/// 目标 phase 白名单：放行 pending 会导致同一构建执行两次。
#[tokio::test]
async fn update_build_phase_rejects_illegal_target() {
    let (store, _tmp) = create_test_store().await;
    let id = store
        .insert_build(BuildInsert {
            phase: "building",
            ..sample_insert(&store).await
        })
        .await
        .unwrap();

    let err = store.update_build_phase(id, "pending").await.unwrap_err();
    assert!(
        matches!(err,
            crate::error::CrbsError::ValidationFailed { ref message }
                if message.contains("pending")),
        "illegal target must be rejected naming the value, got: {err:?}"
    );

    store.update_build_phase(id, "building").await.unwrap();
    store.update_build_phase(id, "assigned").await.unwrap();
}

/// complete_build 族终态白名单：非法值 fail-closed `ValidationFailed`
///（收口在公共咽喉 complete_build_update，非裸 Database 错误）。
#[tokio::test]
async fn complete_build_rejects_non_terminal_phase() {
    let (store, _tmp) = create_test_store().await;
    let id = store
        .insert_build(BuildInsert {
            phase: "building",
            ..sample_insert(&store).await
        })
        .await
        .unwrap();

    // 活跃词汇（最可能的调用方笔误）必须被拒并点名该值。
    let err = store
        .complete_build(id, "building", None)
        .await
        .unwrap_err();
    assert!(
        matches!(err,
            crate::error::CrbsError::ValidationFailed { ref message }
                if message.contains("building")),
        "non-terminal phase must be rejected naming the value, got: {err:?}"
    );
    let err = store
        .complete_build_with_error(id, "pending", None, Some("boom"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, crate::error::CrbsError::ValidationFailed { .. }),
        "complete_build_with_error must share the whitelist, got: {err:?}"
    );

    // 拒绝不是终态守卫（0 行 silently）：build 行必须原样保持 building。
    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "building");
}

/// 终态源拒绝：已 succeeded 的构建不接受迟到的 building 中间态汇报。
#[tokio::test]
async fn update_build_phase_rejects_terminal_source() {
    let (store, _tmp) = create_test_store().await;
    let id = store
        .insert_build(BuildInsert {
            phase: "building",
            ..sample_insert(&store).await
        })
        .await
        .unwrap();
    store.complete_build(id, "succeeded", None).await.unwrap();

    let err = store.update_build_phase(id, "building").await.unwrap_err();
    assert!(matches!(
        err,
        crate::error::CrbsError::ValidationFailed { .. }
    ));
    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "succeeded", "terminal phase must be preserved");
}

/// 中间态归属 CAS：wt 行已删/已易主时迟到上报 0 行静默（phase 不被翻）；
/// 归属正确照常生效（含幂等重复）。
#[tokio::test]
async fn update_build_phase_guarded_ownership_cas() {
    let (store, _tmp) = create_test_store().await;
    let id = store
        .insert_build(BuildInsert {
            phase: "assigned",
            ..sample_insert(&store).await
        })
        .await
        .unwrap();
    let w_old = store
        .upsert_worker("w-old", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    let w_new = store
        .upsert_worker("w-new", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    // 场景 1：wt 行已删（重派间隙）——迟到上报 0 行，phase 不被翻。
    assert_eq!(
        store
            .update_build_phase_guarded(id, w_old, "building")
            .await
            .unwrap(),
        0,
        "late report from worker whose assignment was reclaimed must be dropped"
    );
    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        phase, "assigned",
        "phase must stay untouched in re-dispatch gap"
    );

    // 场景 2：assignment 已易主——旧 attempt 迟到上报仍 0 行。
    // $n 占位符双方言通用；裸 ? 在 PgPool 是语法错误。
    sqlx::query(
        "INSERT INTO worker_tasks (build_id, worker_id, status) VALUES ($1, $2, 'running')",
    )
    .bind(id)
    .bind(w_new)
    .execute(store.pool())
    .await
    .unwrap();
    assert_eq!(
        store
            .update_build_phase_guarded(id, w_old, "building")
            .await
            .unwrap(),
        0,
        "report from the previous owner must be rejected at commit point"
    );
    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        phase, "assigned",
        "re-assigned phase must not be flipped by the old worker"
    );

    // 对照：归属正确的中间态上报照常生效，幂等重复同样 1 行。
    assert_eq!(
        store
            .update_build_phase_guarded(id, w_new, "building")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .update_build_phase_guarded(id, w_new, "building")
            .await
            .unwrap(),
        1,
        "idempotent re-report from the rightful owner must keep working"
    );
    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "building");
}

/// 终态构建 complete 返回 0，调用方据此跳过 repo regen 等后续动作。
#[tokio::test]
async fn complete_build_returns_zero_for_terminal_build() {
    let (_tmp, store) = tmp_store().await;
    let id = store
        .insert_build(BuildInsert {
            phase: "building",
            ..sample_insert(&store).await
        })
        .await
        .unwrap();

    assert_eq!(
        store.complete_build(id, "succeeded", None).await.unwrap(),
        1
    );
    assert_eq!(store.complete_build(id, "failed", None).await.unwrap(), 0);
}
