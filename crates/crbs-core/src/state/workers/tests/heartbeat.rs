// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 心跳、在线状态与遥测采样。

use super::common::*;
use super::*;

#[tokio::test]
async fn test_worker_secret_set_find_clear() {
    use crate::auth::secret::{Secret, SecretKind};

    let (store, _tmp) = create_test_store().await;

    let worker_id = store
        .upsert_worker("w-secret", "x86_64", 1, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    let w = store.get_worker(worker_id).await.unwrap().unwrap();
    assert!(!w.has_secret);

    let secret = Secret::generate(SecretKind::WorkerSecret).unwrap();
    let hash = secret.hash();
    store
        .set_worker_secret(worker_id, hash.as_str())
        .await
        .unwrap();

    let found = store
        .find_worker_by_secret(hash.as_str())
        .await
        .unwrap()
        .expect("should find worker by secret");
    assert_eq!(found.id, worker_id);
    assert!(found.has_secret);

    let not_found = store
        .find_worker_by_secret(&"deadbeef".repeat(8))
        .await
        .unwrap();
    assert!(not_found.is_none());

    store.clear_worker_secret(worker_id).await.unwrap();
    let cleared = store.find_worker_by_secret(hash.as_str()).await.unwrap();
    assert!(cleared.is_none());

    let w2 = store.get_worker(worker_id).await.unwrap().unwrap();
    assert!(!w2.has_secret);
}

#[tokio::test]
async fn test_worker_secret_rotate_invalidates_old() {
    use crate::auth::secret::{Secret, SecretKind};

    let (store, _tmp) = create_test_store().await;
    let worker_id = store
        .upsert_worker("w-rotate", "x86_64", 1, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    let old_secret = Secret::generate(SecretKind::WorkerSecret).unwrap();
    store
        .set_worker_secret(worker_id, old_secret.hash().as_str())
        .await
        .unwrap();

    let new_secret = Secret::generate(SecretKind::WorkerSecret).unwrap();
    store
        .set_worker_secret(worker_id, new_secret.hash().as_str())
        .await
        .unwrap();

    let old_result = store
        .find_worker_by_secret(old_secret.hash().as_str())
        .await
        .unwrap();
    assert!(old_result.is_none());

    let new_result = store
        .find_worker_by_secret(new_secret.hash().as_str())
        .await
        .unwrap();
    assert!(new_result.is_some());
}

#[tokio::test]
async fn worker_touch_heartbeat_does_not_change_status() {
    let (store, _tmp) = create_test_store().await;
    let id = store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    sqlx::query("UPDATE workers SET status = 'offline' WHERE id = $1")
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();

    store
        .worker_touch_heartbeat(id, WorkerTelemetry::default(), None)
        .await
        .unwrap();

    let status: String = sqlx::query_scalar("SELECT status FROM workers WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(status, "offline");
}

#[tokio::test]
async fn worker_touch_heartbeat_persists_telemetry() {
    let (store, _tmp) = create_test_store().await;
    let id = store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    store
        .worker_touch_heartbeat(
            id,
            WorkerTelemetry {
                load1: Some(0.52),
                ncpu: Some(8),
                cpu_util_pct: Some(12.5),
                mem_used_pct: Some(37.5),
                mem_total_kb: None,
                disk_free_kb: None,
            },
            None,
        )
        .await
        .unwrap();
    let (load1, ncpu, util, mem): (Option<f64>, Option<i64>, Option<f64>, Option<f64>) =
        sqlx::query("SELECT load1, ncpu, cpu_util_pct, mem_used_pct FROM workers WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .map(|r| {
                (
                    r.get("load1"),
                    r.get("ncpu"),
                    r.get("cpu_util_pct"),
                    r.get("mem_used_pct"),
                )
            })
            .unwrap();
    assert_eq!(load1, Some(0.52));
    assert_eq!(ncpu, Some(8));
    assert_eq!(util, Some(12.5));
    assert_eq!(mem, Some(37.5));

    // 无遥测心跳（无采样 / 非 Linux）：遥测列覆写为 NULL（非保留旧值）。
    store
        .worker_touch_heartbeat(id, WorkerTelemetry::default(), None)
        .await
        .unwrap();
    let (load1, ncpu, util, mem): (Option<f64>, Option<i64>, Option<f64>, Option<f64>) =
        sqlx::query("SELECT load1, ncpu, cpu_util_pct, mem_used_pct FROM workers WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .map(|r| {
                (
                    r.get("load1"),
                    r.get("ncpu"),
                    r.get("cpu_util_pct"),
                    r.get("mem_used_pct"),
                )
            })
            .unwrap();
    assert_eq!(load1, None);
    assert_eq!(ncpu, None);
    assert_eq!(util, None);
    assert_eq!(mem, None);
}

#[tokio::test]
async fn worker_recover_online_flips_offline_to_online() {
    let (store, _tmp) = create_test_store().await;
    let id = store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    // 场景：upsert online 后被置 offline，但进程存活、心跳继续上报。
    sqlx::query("UPDATE workers SET status = 'offline' WHERE id = $1")
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();

    let flipped = store.worker_recover_online(id).await.unwrap();
    assert!(flipped, "offline → online 应当被翻转");

    let status: String = sqlx::query_scalar("SELECT status FROM workers WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(status, "online");
}

#[tokio::test]
async fn worker_recover_online_does_not_touch_non_offline_status() {
    // 安全约束：admin 可写 draining/suspended 等状态，心跳路径只翻严格等于 'offline' 的行。
    let (store, _tmp) = create_test_store().await;
    let id = store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    for admin_status in ["draining", "suspended", "online"] {
        sqlx::query("UPDATE workers SET status = $1 WHERE id = $2")
            .bind(admin_status)
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap();

        let flipped = store.worker_recover_online(id).await.unwrap();
        assert!(
            !flipped,
            "admin status={admin_status} 应当原样保留，不被心跳覆盖"
        );

        let status: String = sqlx::query_scalar("SELECT status FROM workers WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(status, admin_status);
    }
}

#[tokio::test]
async fn worker_mark_offline_sets_status_offline() {
    let (store, _tmp) = create_test_store().await;
    let id = store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    // offline 心跳必须同时清空遥测列：它本身会刷新 last_heartbeat，保留旧采样会让
    // UI 在无 stale 标记的窗口展示过期值。
    store
        .worker_touch_heartbeat(
            id,
            WorkerTelemetry {
                load1: Some(0.5),
                ncpu: Some(4),
                cpu_util_pct: Some(30.0),
                mem_used_pct: Some(12.5),
                mem_total_kb: None,
                disk_free_kb: None,
            },
            None,
        )
        .await
        .unwrap();

    store.worker_mark_offline(id).await.unwrap();

    let status: String = sqlx::query_scalar("SELECT status FROM workers WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(status, "offline");
    let (load1, ncpu, util, mem): (Option<f64>, Option<i64>, Option<f64>, Option<f64>) =
        sqlx::query("SELECT load1, ncpu, cpu_util_pct, mem_used_pct FROM workers WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .map(|r| {
                (
                    r.get("load1"),
                    r.get("ncpu"),
                    r.get("cpu_util_pct"),
                    r.get("mem_used_pct"),
                )
            })
            .unwrap();
    assert_eq!(load1, None);
    assert_eq!(ncpu, None);
    assert_eq!(util, None);
    assert_eq!(mem, None);
}

/// `worker_heartbeat_upsert` online 分支行为矩阵：不覆盖非 offline 状态（含
/// 管理员状态）、offline→online 翻转、遥测覆写与 None 清 NULL、缺失行 rows=0。
#[tokio::test]
async fn worker_heartbeat_upsert_online_branch_matrix() {
    let (store, _tmp) = create_test_store().await;
    let id = store
        .upsert_worker("w-hb", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    // 遥测覆写 + None 清 NULL（无采样 / 非 Linux 心跳）。
    store
        .worker_heartbeat_upsert(
            id,
            false,
            WorkerTelemetry {
                load1: Some(0.52),
                ncpu: Some(8),
                cpu_util_pct: Some(66.5),
                mem_used_pct: Some(37.5),
                mem_total_kb: None,
                disk_free_kb: None,
            },
            None,
        )
        .await
        .unwrap();
    let (load1, ncpu, util, mem): (Option<f64>, Option<i64>, Option<f64>, Option<f64>) =
        sqlx::query("SELECT load1, ncpu, cpu_util_pct, mem_used_pct FROM workers WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .map(|r| {
                (
                    r.get("load1"),
                    r.get("ncpu"),
                    r.get("cpu_util_pct"),
                    r.get("mem_used_pct"),
                )
            })
            .unwrap();
    assert_eq!(load1, Some(0.52));
    assert_eq!(ncpu, Some(8));
    assert_eq!(util, Some(66.5));
    assert_eq!(mem, Some(37.5));
    store
        .worker_heartbeat_upsert(id, false, WorkerTelemetry::default(), None)
        .await
        .unwrap();
    let (load1, ncpu, util, mem): (Option<f64>, Option<i64>, Option<f64>, Option<f64>) =
        sqlx::query("SELECT load1, ncpu, cpu_util_pct, mem_used_pct FROM workers WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .map(|r| {
                (
                    r.get("load1"),
                    r.get("ncpu"),
                    r.get("cpu_util_pct"),
                    r.get("mem_used_pct"),
                )
            })
            .unwrap();
    assert_eq!(load1, None);
    assert_eq!(ncpu, None);
    assert_eq!(util, None);
    assert_eq!(mem, None);

    // online 心跳不覆盖管理员状态。
    for admin_status in ["draining", "suspended"] {
        sqlx::query("UPDATE workers SET status = $1 WHERE id = $2")
            .bind(admin_status)
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap();
        store
            .worker_heartbeat_upsert(id, false, WorkerTelemetry::default(), None)
            .await
            .unwrap();
        let status: String = sqlx::query_scalar("SELECT status FROM workers WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(status, admin_status);
    }

    sqlx::query("UPDATE workers SET status = 'offline' WHERE id = $1")
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
    store
        .worker_heartbeat_upsert(id, false, WorkerTelemetry::default(), None)
        .await
        .unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM workers WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(status, "online");

    // 不存在的行：0 rows（路由据此 404，替代 get_worker 预检）。
    let affected = store
        .worker_heartbeat_upsert(9999, false, WorkerTelemetry::default(), None)
        .await
        .unwrap();
    assert_eq!(affected, 0);
}

/// `worker_heartbeat_upsert`——offline 分支：status 置 offline、遥测列
/// 置 NULL、last_heartbeat 刷新（原 mark_offline 语义）。
#[tokio::test]
async fn worker_heartbeat_upsert_offline_branch_matches_mark_offline() {
    let (store, _tmp) = create_test_store().await;
    let id = store
        .upsert_worker("w-hb-off", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();

    store
        .worker_touch_heartbeat(
            id,
            WorkerTelemetry {
                load1: Some(0.5),
                ncpu: Some(4),
                cpu_util_pct: Some(30.0),
                mem_used_pct: Some(12.5),
                mem_total_kb: None,
                disk_free_kb: None,
            },
            None,
        )
        .await
        .unwrap();
    age_worker_heartbeat(&store, id, "-300 seconds").await;
    let aged_hb: Option<String> =
        sqlx::query_scalar("SELECT last_heartbeat FROM workers WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap();

    let affected = store
        .worker_heartbeat_upsert(
            id,
            true,
            WorkerTelemetry {
                load1: Some(9.9),
                ncpu: Some(4),
                cpu_util_pct: Some(80.0),
                mem_used_pct: Some(50.0),
                mem_total_kb: None,
                disk_free_kb: None,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(affected, 1);

    let row = sqlx::query(
        "SELECT status, last_heartbeat, load1, ncpu, cpu_util_pct, mem_used_pct \
         FROM workers WHERE id = $1",
    )
    .bind(id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("status"), "offline");
    assert_eq!(
        row.get::<Option<f64>, _>("load1"),
        None,
        "offline 心跳必须清空遥测（含入参非 None）"
    );
    assert_eq!(row.get::<Option<i64>, _>("ncpu"), None);
    assert_eq!(row.get::<Option<f64>, _>("cpu_util_pct"), None);
    assert_eq!(row.get::<Option<f64>, _>("mem_used_pct"), None);
    let hb: Option<String> = row.get("last_heartbeat");
    assert!(
        hb.as_deref()
            .is_some_and(|v| Some(v.to_string()) != aged_hb),
        "last_heartbeat 必须从 300s 前刷新（got {hb:?}, aged {aged_hb:?}）"
    );
}

/// offline 心跳打不存在的 worker id → Ok(0)（调用方据此 404）、表无变化；
/// 广播 gating（offline && affected > 0）在 Ok(0) 路径不唤醒。
#[tokio::test]
async fn worker_heartbeat_upsert_offline_branch_returns_zero_for_missing_row() {
    let (store, _tmp) = create_test_store().await;

    let affected = store
        .worker_heartbeat_upsert(9999, true, WorkerTelemetry::default(), None)
        .await
        .unwrap();
    assert_eq!(affected, 0, "missing worker row must report 0 rows");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workers")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(count, 0, "no worker row may be created by heartbeat");
}

/// offline 心跳（优雅停机上报）不覆盖管理员保留态——管理员状态只由显式
/// 管理操作改变；`worker_mark_offline`（独立翻 offline 入口）同口径。当前无
/// 生产写入点产生保留态，此处钉住防御语义；online 行照常翻 offline。
#[tokio::test]
async fn offline_heartbeat_preserves_admin_statuses() {
    let (store, _tmp) = create_test_store().await;

    for admin_status in ["suspended", "draining"] {
        let id = store
            .upsert_worker(
                &format!("w-{admin_status}"),
                "x86_64",
                2,
                "0.15.0-dev",
                "online",
                None,
            )
            .await
            .unwrap();
        sqlx::query("UPDATE workers SET status = $1 WHERE id = $2")
            .bind(admin_status)
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap();

        // status 保持；行仍更新（last_heartbeat / 遥测清 NULL 不受 CASE 谓词影响）。
        let affected = store
            .worker_heartbeat_upsert(id, true, WorkerTelemetry::default(), None)
            .await
            .unwrap();
        assert_eq!(affected, 1);
        let status: String = sqlx::query_scalar("SELECT status FROM workers WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(status, admin_status, "offline 心跳不得覆盖管理员保留态");

        store.worker_mark_offline(id).await.unwrap();
        let status: String = sqlx::query_scalar("SELECT status FROM workers WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(status, admin_status, "worker_mark_offline 同口径");
    }

    let online_id = store
        .upsert_worker("w-flip", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    store
        .worker_heartbeat_upsert(online_id, true, WorkerTelemetry::default(), None)
        .await
        .unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM workers WHERE id = $1")
        .bind(online_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(status, "offline");
}

/// 心跳 upsert 落采样行：有效遥测（cpu 或 mem 至少一项）追加一条；NULL 浮点
/// 先行（load1=None、cpu=Some）再 Some 绑定，钉双方言 TEXT+CAST 绑定路径
/// （Any 驱动浮点 NULL 先行钉 FLOAT4 的坑在采样 INSERT 上同样必须绕开）。
#[tokio::test]
async fn heartbeat_upsert_appends_telemetry_sample() {
    let (store, _tmp) = create_test_store().await;
    let wid = store
        .upsert_worker("tel-hb", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();

    store
        .worker_heartbeat_upsert(
            wid,
            false,
            WorkerTelemetry {
                load1: None,
                ncpu: Some(8),
                cpu_util_pct: Some(50.0),
                mem_used_pct: None,
                mem_total_kb: None,
                disk_free_kb: None,
            },
            None,
        )
        .await
        .unwrap();
    store
        .worker_heartbeat_upsert(
            wid,
            false,
            WorkerTelemetry {
                load1: Some(4.0),
                ncpu: Some(8),
                cpu_util_pct: Some(30.0),
                mem_used_pct: Some(60.0),
                mem_total_kb: Some(16_000_000),
                disk_free_kb: None,
            },
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        sample_count(&store, wid).await,
        2,
        "one sample per heartbeat"
    );
    let (cpu, mem, load, total): (Option<f64>, Option<f64>, Option<f64>, Option<i64>) =
        sqlx::query_as(
            "SELECT cpu_util_pct, mem_used_pct, load1, mem_total_kb \
             FROM worker_telemetry_samples ORDER BY id DESC LIMIT 1",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(cpu, Some(30.0));
    assert_eq!(mem, Some(60.0));
    assert_eq!(load, Some(4.0));
    assert_eq!(total, Some(16_000_000));
    // sampled_at 与心跳同帧可解析（DB_TIME_FMT TEXT UTC）。
    let sampled_at: String = sqlx::query_scalar(
        "SELECT sampled_at FROM worker_telemetry_samples ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(
        crate::util::parse_db_time(&sampled_at).is_some(),
        "{sampled_at}"
    );
}

/// 心跳新列（采集侧）：注册/重复注册写 resource_caps（重注册 = 重探测
/// 覆写）；online 心跳覆写 workers.disk_free_kb / resource_caps 并把
/// disk_free_kb 追加进采样行；None 心跳两列清 NULL；offline 心跳清 NULL 且
/// 不落采样行（disk-only 有效观测可落行）。
#[tokio::test]
async fn heartbeat_disk_and_caps_columns_landed_and_offline_cleared() {
    let (store, _tmp) = create_test_store().await;
    let wid = store
        .upsert_worker(
            "caps-hb",
            "x86_64",
            2,
            "1.0",
            "online",
            Some(crate::state::RESOURCE_CAP_CGROUP_V2 | crate::state::RESOURCE_CAP_PSI),
        )
        .await
        .unwrap();
    async fn read_cols(store: &StateStore, id: i64) -> (Option<i64>, Option<i64>) {
        sqlx::query_as("SELECT disk_free_kb, resource_caps FROM workers WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap()
    }
    // 注册位图就位（bit0 | bit4 = 17）。
    let (disk, caps) = read_cols(&store, wid).await;
    assert_eq!(caps, Some(17), "register must land the capability bitmap");
    assert_eq!(disk, None);
    // 重复注册 = 进程重启重探测：位图覆写（cgroup v2 能力位消失）。
    store
        .upsert_worker("caps-hb", "x86_64", 2, "1.0", "online", Some(0))
        .await
        .unwrap();
    let (_, caps) = read_cols(&store, wid).await;
    assert_eq!(caps, Some(0), "re-register must overwrite the bitmap");

    // online 心跳：disk/caps 落列 + 采样行带 disk_free_kb。
    store
        .worker_heartbeat_upsert(
            wid,
            false,
            WorkerTelemetry {
                disk_free_kb: Some(1_234_567),
                mem_used_pct: Some(40.0),
                ..Default::default()
            },
            Some(crate::state::RESOURCE_CAP_MEMORY_PEAK),
        )
        .await
        .unwrap();
    let (disk, caps) = read_cols(&store, wid).await;
    assert_eq!(disk, Some(1_234_567));
    assert_eq!(caps, Some(crate::state::RESOURCE_CAP_MEMORY_PEAK));
    let sample_disk: Option<i64> = sqlx::query_scalar(
        "SELECT disk_free_kb FROM worker_telemetry_samples ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        sample_disk,
        Some(1_234_567),
        "sample row carries disk_free_kb"
    );

    // None 心跳（无采样 / 探测失败）：两列清 NULL；disk-only 不算观测，不落行。
    let before = sample_count(&store, wid).await;
    store
        .worker_heartbeat_upsert(wid, false, WorkerTelemetry::default(), None)
        .await
        .unwrap();
    let (disk, caps) = read_cols(&store, wid).await;
    assert_eq!(disk, None);
    assert_eq!(caps, None);
    assert_eq!(sample_count(&store, wid).await, before);

    // disk-only 心跳：workers 列落值 + 采样行追加（有效观测值语义扩展）。
    store
        .worker_heartbeat_upsert(
            wid,
            false,
            WorkerTelemetry {
                disk_free_kb: Some(9_000),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let (disk, _) = read_cols(&store, wid).await;
    assert_eq!(disk, Some(9_000));
    assert_eq!(
        sample_count(&store, wid).await,
        before + 1,
        "disk-only telemetry is a valid observation"
    );

    // offline 心跳：即便带值也清 NULL、不落采样行（既有 offline 语义延续）。
    store
        .worker_heartbeat_upsert(
            wid,
            true,
            WorkerTelemetry {
                disk_free_kb: Some(1),
                mem_used_pct: Some(1.0),
                ..Default::default()
            },
            Some(crate::state::RESOURCE_CAP_PSI),
        )
        .await
        .unwrap();
    let (disk, caps) = read_cols(&store, wid).await;
    assert_eq!(disk, None, "offline heartbeat must clear disk_free_kb");
    assert_eq!(caps, None, "offline heartbeat must clear resource_caps");
    assert_eq!(sample_count(&store, wid).await, before + 1);
}

/// offline 心跳与双指标全 None 的心跳都不落采样（无有效观测值）。
#[tokio::test]
async fn heartbeat_upsert_skips_sample_for_offline_or_empty_telemetry() {
    let (store, _tmp) = create_test_store().await;
    let wid = store
        .upsert_worker("tel-off", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();

    store
        .worker_heartbeat_upsert(wid, false, WorkerTelemetry::default(), None)
        .await
        .unwrap();
    store
        .worker_heartbeat_upsert(wid, true, WorkerTelemetry::default(), None)
        .await
        .unwrap();
    // offline 且带值：同样不落（下线时段由图表断线表达）。
    store
        .worker_heartbeat_upsert(
            wid,
            true,
            WorkerTelemetry {
                load1: Some(1.0),
                ncpu: Some(8),
                cpu_util_pct: Some(10.0),
                mem_used_pct: Some(20.0),
                mem_total_kb: None,
                disk_free_kb: None,
            },
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        sample_count(&store, wid).await,
        0,
        "offline / all-None heartbeats must not append samples"
    );
}

/// list_telemetry_samples：since 过滤（窗外排除）、返回升序、limit 超限按
/// 最新保留（趋势图"现在"端不缺）；其他 worker 的采样不串。
#[tokio::test]
async fn list_telemetry_samples_filters_orders_and_limits() {
    let (store, _tmp) = create_test_store().await;
    let wid = store
        .upsert_worker("tel-list", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();
    let other = store
        .upsert_worker("tel-other", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();
    seed_telemetry_sample(&store, wid, "-50 minutes", 10.0).await;
    seed_telemetry_sample(&store, wid, "-10 minutes", 30.0).await;
    seed_telemetry_sample(&store, wid, "-30 minutes", 20.0).await;
    seed_telemetry_sample(&store, wid, "-2 hours", 90.0).await;
    seed_telemetry_sample(&store, other, "-15 minutes", 70.0).await;

    let rows = store.list_telemetry_samples(wid, 60, 100).await.unwrap();
    let cpus: Vec<Option<f64>> = rows.iter().map(|r| r.telemetry.cpu_util_pct).collect();
    assert_eq!(
        cpus,
        vec![Some(10.0), Some(20.0), Some(30.0)],
        "window-filtered, ascending, other worker excluded: {rows:?}"
    );

    // 超限轻量钉方向：3 点取 2 留最新两行（升序回显），不造 5 万行。
    let rows = store.list_telemetry_samples(wid, 60, 2).await.unwrap();
    let cpus: Vec<Option<f64>> = rows.iter().map(|r| r.telemetry.cpu_util_pct).collect();
    assert_eq!(rows.len(), 2, "limit caps row count");
    assert_eq!(
        cpus,
        vec![Some(20.0), Some(30.0)],
        "over-limit keeps newest, returned ascending: {rows:?}"
    );
}

/// retention 清理采样：超期删、新留、stats 回传；其他表计数不受影响语义
///（此处只盯采样统计）。
#[tokio::test]
async fn retention_prunes_old_telemetry_samples() {
    let (store, _tmp) = create_test_store().await;
    let wid = store
        .upsert_worker("tel-ret", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();
    seed_telemetry_sample(&store, wid, "-60 days", 10.0).await;
    seed_telemetry_sample(&store, wid, "-20 days", 20.0).await;
    seed_telemetry_sample(&store, wid, "-1 day", 30.0).await;

    let stats = store.prune_old_records(90).await.unwrap();
    // 采样独立 14 天上限：-60d / -20d 删，-1d 留。
    assert_eq!(stats.worker_telemetry_samples, 2, "capped at 14 days");
    assert_eq!(sample_count(&store, wid).await, 1);

    // 全局收紧（2 天 < 14 天上限）按紧者走：-3d 删、-1d 留。
    seed_telemetry_sample(&store, wid, "-3 days", 40.0).await;
    let stats = store.prune_old_records(2).await.unwrap();
    assert_eq!(stats.worker_telemetry_samples, 1, "tighter global wins");
    assert_eq!(sample_count(&store, wid).await, 1);
}

/// worker 删除级联清采样（worker_id ON DELETE CASCADE，与 worker_tasks 同款）。
#[tokio::test]
async fn delete_worker_cascades_telemetry_samples() {
    let (store, _tmp) = create_test_store().await;
    let wid = store
        .upsert_worker("tel-del", "x86_64", 2, "1.0", "online", None)
        .await
        .unwrap();
    seed_telemetry_sample(&store, wid, "-10 minutes", 10.0).await;
    sqlx::query("UPDATE workers SET status = 'offline' WHERE id = $1")
        .bind(wid)
        .execute(store.pool())
        .await
        .unwrap();

    assert_eq!(
        store.delete_worker_if_offline(wid).await.unwrap(),
        DeleteWorkerOutcome::Deleted
    );
    assert_eq!(
        sample_count(&store, wid).await,
        0,
        "samples must cascade with worker delete"
    );
}
