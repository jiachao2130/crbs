// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 读取与列更新：列表、画像/请求字段、发布轴与优先级统计。

use super::common::*;
use super::*;

/// id 批量取 (product, pkg, arch)：命中行返回、缺失 id 静默跳过、空集
/// 返回空（本地取件预检的注册表 → 三维权重键输入契约）。
#[tokio::test]
async fn list_build_pkgs_by_ids_returns_pairs_and_skips_missing() {
    let (store, _tmp) = create_test_store().await;
    let task_id = crate::state::test_state::seed_task(&store, "fedora", "pkg-a").await;
    let b1 = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "pkg-a",
            phase: "building",
            backend: "chroot",
            user: "alice",
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(store
        .list_build_pkgs_by_ids(&[], 90)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .list_build_pkgs_by_ids(&[b1, b1 + 999_999], 90)
            .await
            .unwrap(),
        vec![(b1, "fedora".to_string(), "pkg-a".to_string(), None)],
        "missing ids must be skipped, not error; NULL arch passes through NULLIF"
    );
}

/// `list_build_pkgs_by_ids` 爬坡窗口谓词：started_at NULL（已派未起跑）与
/// 窗口内起跑的行供给；窗口外起跑的行不算在跑压载（本地伪 worker 的 load1
/// 已承载）。
#[tokio::test]
async fn list_build_pkgs_by_ids_respects_ramp_window() {
    let (store, _tmp) = create_test_store().await;
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

    let fresh = mk_build(&store, "rw-fresh").await;
    let stale = mk_build(&store, "rw-stale").await;
    let unstarted = mk_build(&store, "rw-unstarted").await;
    for (id, offset) in [(fresh, "-30 seconds"), (stale, "-900 seconds")] {
        sqlx::query(&format!(
            "UPDATE builds SET started_at = {} WHERE id = $1",
            crate::state::test_state::sql_time_offset(store.dialect, offset)
        ))
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
    }
    sqlx::query("UPDATE builds SET started_at = NULL WHERE id = $1")
        .bind(unstarted)
        .execute(store.pool())
        .await
        .unwrap();

    let mut rows = store
        .list_build_pkgs_by_ids(&[fresh, stale, unstarted], 90)
        .await
        .unwrap();
    rows.sort_by_key(|(id, ..)| *id);
    let mut want = vec![fresh, unstarted];
    want.sort_unstable();
    assert_eq!(
        rows.iter().map(|(id, ..)| *id).collect::<Vec<_>>(),
        want,
        "unstarted (NULL) and in-window rows survive the ramp predicate: {rows:?}"
    );
}

/// BuildRecord 资源字段往返：行解码非 NULL 全值就位
/// （oom_killed 0/1 → bool）、全 NULL 落 None；serde JSON 快照——Some 键在、
/// None 键缺（skip_serializing_if），缺键 wire 反序列化落 None。
#[tokio::test]
async fn build_record_resource_fields_roundtrip() {
    let (store, _tmp) = create_test_store().await;
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

    // 全值写入 → get_build 十一字段全解码（oom true → Some(true)）。
    let full = mk_build(&store, "rr-full-1.0").await;
    store
        .complete_build_with_resources(
            full,
            "succeeded",
            None,
            Some(crate::engine::ResourceUsage {
                peak_rss_kb: Some(2_621_440),
                cpu_secs: Some(42.5),
                cpu_p90_cores: Some(3.7),
                peak_total_kb: Some(524_288),
                disk_wbytes: Some(1_236),
                oom_killed: Some(true),
                sample_backend: Some(crate::engine::SAMPLE_BACKEND_CGROUP),
                sample_ncpu: Some(8),
                peak_tmpfs_kb: None,
            }),
        )
        .await
        .unwrap();
    let rec = store.get_build(full).await.unwrap().unwrap();
    assert_eq!(rec.peak_rss_kb, Some(2_621_440));
    assert_eq!(rec.peak_total_kb, Some(524_288));
    assert_eq!(rec.cpu_secs, Some(42.5));
    assert_eq!(rec.cpu_p90_cores, Some(3.7));
    assert_eq!(rec.disk_wbytes, Some(1_236));
    assert_eq!(rec.oom_killed, Some(true));
    assert_eq!(rec.sample_backend.as_deref(), Some("cgroup"));
    assert_eq!(rec.sample_ncpu, Some(8));
    // 未声明放置下限的插入：req_min_* 读回 None。
    assert_eq!(rec.req_min_mem_kb, None);
    assert_eq!(rec.req_min_ncpu, None);
    assert_eq!(rec.req_min_disk_kb, None);

    // serde 序列化：资源键在场（有值时），oom 布尔直出。
    let json: serde_json::Value = serde_json::to_value(&rec).unwrap();
    assert_eq!(json["peak_rss_kb"], serde_json::json!(2_621_440));
    assert_eq!(json["oom_killed"], serde_json::json!(true));
    assert_eq!(json["cpu_p90_cores"], serde_json::json!(3.7));
    // req 键缺席（skip_serializing_if = None）。
    assert!(json.get("req_min_mem_kb").is_none());

    // 全 NULL 写入（complete_build 无资源路径）→ 行解码十一字段全 None，
    // 序列化资源键全部缺席。
    let bare = mk_build(&store, "rr-null-1.0").await;
    store.complete_build(bare, "failed", None).await.unwrap();
    let rec = store.get_build(bare).await.unwrap().unwrap();
    assert_eq!(rec.peak_rss_kb, None);
    assert_eq!(rec.peak_total_kb, None);
    assert_eq!(rec.cpu_secs, None);
    assert_eq!(rec.cpu_p90_cores, None);
    assert_eq!(rec.disk_wbytes, None);
    assert_eq!(rec.oom_killed, None);
    assert_eq!(rec.sample_backend, None);
    assert_eq!(rec.sample_ncpu, None);
    let json: serde_json::Value = serde_json::to_value(&rec).unwrap();
    for key in [
        "peak_rss_kb",
        "peak_total_kb",
        "cpu_secs",
        "cpu_p90_cores",
        "disk_wbytes",
        "oom_killed",
        "sample_backend",
        "sample_ncpu",
        "req_min_mem_kb",
        "req_min_ncpu",
        "req_min_disk_kb",
    ] {
        assert!(json.get(key).is_none(), "{key} must be skipped when None");
    }

    // 无资源键 wire 反序列化：全部落 None（serde 缺省语义）。
    let sparse: crate::state::BuildRecord = serde_json::from_str(
        r#"{"id": 1, "product": "fedora", "pkg_name": "hello",
            "name": "hello", "version": "1", "release": "1", "phase": "succeeded",
            "user": "alice", "signed": false, "priority": 0, "deterministic": false}"#,
    )
    .unwrap();
    assert_eq!(sparse.peak_rss_kb, None);
    assert_eq!(sparse.oom_killed, None);
    assert_eq!(sparse.req_min_mem_kb, None);
}

/// srpm_size_bytes 落列（heavy steering 输入）：写入读回一致、幂等覆盖，
/// 不存在的 build id 报 NotFound（调用方 best-effort warn 不回滚的输入）。
/// 列不在 BuildRecord 标准列集（wire 未透出），直查 SQL 读回。
#[tokio::test]
async fn set_build_srpm_size_bytes_persists_and_404s_on_missing() {
    let (_tmp, store) = tmp_store().await;
    let task_id = crate::state::test_state::seed_task(&store, "fedora", "rr-srpm-1.0").await;
    let id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "rr-srpm-1.0",
            phase: "pending",
            backend: "chroot",
            user: "alice",
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    store
        .set_build_srpm_size_bytes(id, 1_234_567)
        .await
        .unwrap();
    let size: Option<i64> = sqlx::query_scalar("SELECT srpm_size_bytes FROM builds WHERE id = ?")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(size, Some(1_234_567));

    // 幂等覆盖。
    store.set_build_srpm_size_bytes(id, 42).await.unwrap();
    let size: Option<i64> = sqlx::query_scalar("SELECT srpm_size_bytes FROM builds WHERE id = ?")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(size, Some(42));

    let err = store
        .set_build_srpm_size_bytes(id + 999_999, 1)
        .await
        .unwrap_err();
    assert!(
        matches!(err, crate::error::CrbsError::NotFound { .. }),
        "got: {err:?}"
    );
}

/// 产品配置快照（调试锚）：写入读回一致，缺失构建返回 None；列不在
/// BuildRecord 标准列集（列表查询不带大字段）。
#[tokio::test]
async fn product_config_toml_roundtrips_and_missing_is_none() {
    let (_tmp, store) = tmp_store().await;
    let task_id = crate::state::test_state::seed_task(&store, "fedora", "anchor-1.0").await;
    let id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "anchor-1.0",
            phase: "pending",
            backend: "chroot",
            user: "alice",
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(store.get_build_product_config_toml(id).await.unwrap(), None);
    store
        .set_build_product_config_toml(id, "[product]\nname = \"fedora\"\n")
        .await
        .unwrap();
    assert_eq!(
        store.get_build_product_config_toml(id).await.unwrap(),
        Some("[product]\nname = \"fedora\"\n".to_string())
    );
    assert_eq!(
        store
            .get_build_product_config_toml(id + 999_999)
            .await
            .unwrap(),
        None
    );
}

/// 血缘锚内容过滤：同值命中、异值/NULL 不命中，total 与分页同口径。
#[tokio::test]
async fn list_builds_filters_by_srpm_sha256() {
    use crate::types::BuildListFilter;
    let (_tmp, store) = tmp_store().await;
    let mut ids = Vec::new();
    for (pkg, sha) in [
        ("sha-a", Some("abc123")),
        ("sha-b", Some("def456")),
        ("sha-c", None),
    ] {
        let task_id = crate::state::test_state::seed_task(&store, "fedora", pkg).await;
        let id = store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: pkg,
                phase: "succeeded",
                backend: "chroot",
                user: "alice",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        if let Some(sha) = sha {
            store
                .set_build_canonical_srpm_sha256(id, sha)
                .await
                .unwrap();
        }
        ids.push(id);
    }

    let (total, records) = store
        .list_builds(&BuildListFilter {
            srpm_sha256: Some("abc123"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(records[0].id, ids[0]);

    let (total, _) = store
        .list_builds(&BuildListFilter {
            srpm_sha256: Some("no-such-hash"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 0, "NULL anchors must not match any hash");
}

/// NOT IN 须排除 init 行（build_id NULL）：否则任一活跃 init assignment
/// 令本地计数恒空集（三值逻辑 UNKNOWN）。
#[tokio::test]
async fn count_local_building_survives_active_init_assignment() {
    use crate::types::PRIORITY_DEFAULT;
    let (store, _tmp) = create_test_store().await;
    let worker_id = store
        .upsert_worker("w-init", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    let _build_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "local-1.0",
            phase: "building",
            backend: "chroot",
            user: "alice",
            task_id: Some(crate::state::test_state::seed_task(&store, "fedora", "local-1.0").await),
            ..Default::default()
        })
        .await
        .unwrap();

    let counts = store.count_local_building_by_priority().await.unwrap();
    assert_eq!(
        counts.get(&PRIORITY_DEFAULT),
        Some(&1),
        "baseline: local building build must be counted"
    );

    // 活跃 init assignment（插 build_id NULL 行）：计数不受影响。
    store
        .try_assign_init_to_worker(worker_id, "fedora")
        .await
        .unwrap()
        .expect("init assignment should be created");
    let counts = store.count_local_building_by_priority().await.unwrap();
    assert_eq!(
        counts.get(&PRIORITY_DEFAULT),
        Some(&1),
        "active init assignment (build_id NULL) must not blank the local count"
    );
}

/// phase CAS：building → 1 行放行；并发翻终态 → 0 行，rollback 后
/// result_dir 不泄漏拒写值。
#[tokio::test]
async fn update_build_info_tx_guarded_rejects_non_active_phase() {
    let (store, _tmp) = create_test_store().await;
    // 两条 build 不同 arch：避开 insert_build 活跃去重（与本测试无关）。
    let mut active = sample_insert(&store).await;
    active.phase = "pending";
    active.arch = Some("x86_64");
    let active_id = store.insert_build(active).await.unwrap();
    let mut flipped = sample_insert(&store).await;
    flipped.phase = "pending";
    flipped.arch = Some("aarch64");
    let flipped_id = store.insert_build(flipped).await.unwrap();

    // 两条都补 assignment 行，只考察 phase 维度（归属臂见下方专项）。
    // assign 要求 pending：先分配再推 building。
    let worker_id = store
        .upsert_worker("guard-w", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    store
        .assign_build_to_worker(active_id, worker_id)
        .await
        .unwrap();
    store
        .assign_build_to_worker(flipped_id, worker_id)
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
        .bind(active_id)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
        .bind(flipped_id)
        .execute(store.pool())
        .await
        .unwrap();

    let mut tx = store.pool().begin().await.unwrap();
    let rows = store
        .update_build_info_tx_guarded(
            &mut tx,
            GuardedBuildInfo {
                id: active_id,
                result_dir: Some("/tmp/guard-ok"),
                base_os_digest: None,
                backend: "chroot",
                worker_id,
                assignment_id: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(rows, 1, "active build must accept the write");
    tx.commit().await.unwrap();
    assert_eq!(
        store
            .get_build(active_id)
            .await
            .unwrap()
            .unwrap()
            .result_dir
            .as_deref(),
        Some("/tmp/guard-ok")
    );

    // 直改终态（模拟上传期间并发取消）→ 0 行拒绝，rollback 后仍 NULL。
    sqlx::query("UPDATE builds SET phase = 'cancelled' WHERE id = $1")
        .bind(flipped_id)
        .execute(store.pool())
        .await
        .unwrap();
    let mut tx = store.pool().begin().await.unwrap();
    let rows = store
        .update_build_info_tx_guarded(
            &mut tx,
            GuardedBuildInfo {
                id: flipped_id,
                result_dir: Some("/tmp/guard-rej"),
                base_os_digest: None,
                backend: "chroot",
                worker_id,
                assignment_id: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(rows, 0, "terminal build must reject the write");
    tx.rollback().await.unwrap();
    assert_eq!(
        store
            .get_build(flipped_id)
            .await
            .unwrap()
            .unwrap()
            .result_dir,
        None,
        "rejected write must not leak result_dir"
    );
}

/// assignment 归属 CAS：reclaim 重派后旧 attempt 迟到上传被拒（0 行，即使
/// phase 仍活跃——归属谓词是唯一防线）；新持有者放行。
#[tokio::test]
async fn update_build_info_tx_guarded_rejects_revoked_assignment() {
    let (store, _tmp) = create_test_store().await;
    let mut b = sample_insert(&store).await;
    b.phase = "pending";
    b.arch = Some("x86_64");
    let build_id = store.insert_build(b).await.unwrap();

    let worker_id = store
        .upsert_worker("w-old", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    // assign 要求 pending：先分配再推 building（剥夺窗口的活跃态）。
    sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
        .bind(build_id)
        .execute(store.pool())
        .await
        .unwrap();

    // reclaim 全语义：删分配行 + 回 pending + 重派——归属 CAS 是唯一防线。
    sqlx::query("DELETE FROM worker_tasks WHERE build_id = $1 AND worker_id = $2")
        .bind(build_id)
        .bind(worker_id)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET phase = 'pending' WHERE id = $1")
        .bind(build_id)
        .execute(store.pool())
        .await
        .unwrap();

    // 重派给新 worker 并开跑（剥夺窗口形态）。
    let new_worker = store
        .upsert_worker("w-new", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    store
        .assign_build_to_worker(build_id, new_worker)
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
        .bind(build_id)
        .execute(store.pool())
        .await
        .unwrap();

    // 旧 attempt 迟到提交：phase 复查通过、归属谓词拒 → 0 行。
    let mut tx = store.pool().begin().await.unwrap();
    let rows = store
        .update_build_info_tx_guarded(
            &mut tx,
            GuardedBuildInfo {
                id: build_id,
                result_dir: Some("/tmp/revoked"),
                base_os_digest: None,
                backend: "chroot",
                worker_id,
                assignment_id: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(rows, 0, "revoked worker must be rejected at commit");
    tx.rollback().await.unwrap();
    assert_eq!(
        store.get_build(build_id).await.unwrap().unwrap().result_dir,
        None,
        "rejected write must not leak result_dir"
    );

    let mut tx = store.pool().begin().await.unwrap();
    let rows = store
        .update_build_info_tx_guarded(
            &mut tx,
            GuardedBuildInfo {
                id: build_id,
                result_dir: Some("/tmp/reassigned"),
                base_os_digest: None,
                backend: "chroot",
                worker_id: new_worker,
                assignment_id: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(rows, 1, "new assignee must pass the ownership CAS");
    tx.commit().await.unwrap();
    assert_eq!(
        store
            .get_build(build_id)
            .await
            .unwrap()
            .unwrap()
            .result_dir
            .as_deref(),
        Some("/tmp/reassigned")
    );
}

/// 排序臂：started_desc 双键 (started_at DESC, id DESC)、id_asc 升序、
/// 未知值宽松回落 id DESC（UI 的 id_desc 押在回退臂上，改语义前先补显式臂）。
#[tokio::test]
async fn list_builds_order_by_arms_covered() {
    use crate::types::BuildListFilter;

    let (store, _tmp) = create_test_store().await;

    // 乱序 seed：A(01-02) B(01-03) C(01-02)——C 与 A 同时刻，二级序落在 id。
    let mut ids = Vec::new();
    for (pkg, started) in [
        ("a-1.0-1", "2026-01-02 09:00:00"),
        ("b-1.0-1", "2026-01-03 09:00:00"),
        ("c-1.0-1", "2026-01-02 09:00:00"),
    ] {
        let id = store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: pkg,
                phase: "succeeded",
                backend: "chroot",
                user: "alice",
                task_id: Some(crate::state::test_state::seed_task(&store, "fedora", pkg).await),
                ..Default::default()
            })
            .await
            .unwrap();
        // 显式落 started_at（UTC 墙钟 TEXT，与生产比较帧同帧）。
        sqlx::query("UPDATE builds SET started_at = $1 WHERE id = $2")
            .bind(started)
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap();
        ids.push(id);
    }

    let order = |order_by: &'static str| {
        let store = &store;
        async move {
            let (_, rows) = store
                .list_builds(&BuildListFilter {
                    order_by: Some(order_by),
                    ..Default::default()
                })
                .await
                .unwrap();
            rows.into_iter().map(|b| b.id).collect::<Vec<_>>()
        }
    };

    let cases: &[(&str, Vec<i64>)] = &[
        ("started_desc", vec![ids[1], ids[2], ids[0]]),
        ("id_asc", ids.clone()),
        ("definitely-not-a-sort", vec![ids[2], ids[1], ids[0]]),
    ];
    for (order_by, expected) in cases {
        assert_eq!(&order(order_by).await, expected, "order_by={order_by}");
    }
}

/// set_build_repo_publish 双向翻转 0/1（publish/unpublish 命令复用）。
#[tokio::test]
async fn set_build_repo_publish_flips_flag() {
    let (_tmp, store) = tmp_store().await;
    let id = store
        .insert_build(sample_insert(&store).await)
        .await
        .unwrap();

    store.set_build_repo_publish(id, false).await.unwrap();
    assert_eq!(repo_publish_of(&store, id).await, 0);

    store.set_build_repo_publish(id, true).await.unwrap();
    assert_eq!(repo_publish_of(&store, id).await, 1);
}

/// deterministic 打标读写：插入默认 0，set 后读到 1，未打标行 false。
#[tokio::test]
async fn set_build_deterministic_flags_record() {
    let (store, _tmp) = create_test_store().await;
    let tagged = store
        .insert_build(sample_insert(&store).await)
        .await
        .unwrap();
    let untagged = store
        .insert_build(sample_insert(&store).await)
        .await
        .unwrap();

    assert!(
        !store
            .get_build(tagged)
            .await
            .unwrap()
            .unwrap()
            .deterministic
    );

    store.set_build_deterministic(tagged, true).await.unwrap();
    let record = store.get_build(tagged).await.unwrap().unwrap();
    assert!(record.deterministic);
    assert!(
        !store
            .get_build(untagged)
            .await
            .unwrap()
            .unwrap()
            .deterministic
    );
}

/// canonical_srpm 0 行（build 不存在）报 NotFound；存在行正常写入。
#[tokio::test]
async fn set_build_canonical_srpm_sha256_missing_build_yields_not_found() {
    let (store, _tmp) = create_test_store().await;
    let id = store
        .insert_build(sample_insert(&store).await)
        .await
        .unwrap();

    store
        .set_build_canonical_srpm_sha256(id, "deadbeef")
        .await
        .unwrap();

    let err = store
        .set_build_canonical_srpm_sha256(9999, "deadbeef")
        .await
        .unwrap_err();
    assert!(
        matches!(err, crate::error::CrbsError::NotFound { .. }),
        "missing build must be NotFound, got: {err:?}"
    );
}

/// append_build_note：NULL 起步追加、二次拼接不覆盖；超长截断。
#[tokio::test]
async fn append_build_note_appends_and_truncates() {
    let (store, _tmp) = create_test_store().await;
    let id = store
        .insert_build(sample_insert(&store).await)
        .await
        .unwrap();

    store
        .append_build_note(id, "\nwarning: SOURCE_DATE_EPOCH in the future")
        .await
        .unwrap();
    let record = store.get_build(id).await.unwrap().unwrap();
    assert!(
        record
            .error_summary
            .as_deref()
            .unwrap_or("")
            .contains("SOURCE_DATE_EPOCH in the future"),
        "got: {:?}",
        record.error_summary
    );

    store
        .append_build_note(id, "\nwarning: second note")
        .await
        .unwrap();
    let record = store.get_build(id).await.unwrap().unwrap();
    let summary = record.error_summary.as_deref().unwrap_or("");
    assert!(summary.contains("SOURCE_DATE_EPOCH in the future"));
    assert!(summary.contains("second note"));

    // 超长截断（SQL 侧 1000 字符上限）
    store
        .append_build_note(id, &"\nx".repeat(2000))
        .await
        .unwrap();
    let record = store.get_build(id).await.unwrap().unwrap();
    assert!(
        record
            .error_summary
            .as_deref()
            .unwrap_or("")
            .chars()
            .count()
            <= 1000,
        "note append must be capped"
    );
}

/// priority 精确过滤（typed bind）；total 与分页占位符编号正确。
#[tokio::test]
async fn list_builds_filters_by_priority() {
    use crate::types::{BuildListFilter, PRIORITY_CRITICAL, PRIORITY_DEFAULT};
    let (_tmp, store) = tmp_store().await;
    for priority in [PRIORITY_DEFAULT, 1, 1, PRIORITY_CRITICAL] {
        store
            .insert_build(BuildInsert {
                priority,
                ..sample_insert(&store).await
            })
            .await
            .unwrap();
    }

    let (total, records) = store
        .list_builds(&BuildListFilter {
            priority: Some(1), // 高优
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 2);
    assert!(records.iter().all(|b| b.priority == 1));

    // priority + limit/offset 组合：分页占位符在 priority 之后，编号不错位。
    let (total, page) = store
        .list_builds(&BuildListFilter {
            priority: Some(PRIORITY_DEFAULT),
            limit: Some(10),
            offset: Some(0),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].priority, PRIORITY_DEFAULT);
}

/// 可见性下沉 SQL：private 分页前过滤；空名单仅孤儿豁免；None 不过滤。
#[tokio::test]
async fn list_builds_filters_by_visible_products() {
    use crate::config::ProductConfig;
    use crate::state::products::CreateProductInput;

    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::new(tmp.path()).await.unwrap();

    // "secret" 入 products 表（private）；"ule3" 不入（模拟已删孤儿产品）。
    let owner_id = store.create_user("owner", "builder").await.unwrap();
    store
        .create_product(CreateProductInput {
            name: "secret",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: crate::VISIBILITY_PRIVATE,
            config: &ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("test seed"),
        })
        .await
        .unwrap();

    let mk = |product: &'static str| {
        let store = &store;
        async move {
            let task_id =
                crate::state::test_state::seed_task(store, product, "hello-1.0-1.fc42").await;
            store
                .insert_build(BuildInsert {
                    product,
                    pkg_name: "hello-1.0-1.fc42",
                    phase: "succeeded",
                    backend: "chroot",
                    user: "alice",
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };
    let b1 = mk("ule3").await;
    let _b2 = mk("ule3").await;
    let private = mk("secret").await;

    let (total, records) = store
        .list_builds(&crate::types::BuildListFilter {
            visible_products: Some(vec!["ule3".to_string()]),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 2);
    assert!(records.iter().all(|b| b.id != private));

    let (total, records) = store
        .list_builds(&crate::types::BuildListFilter {
            visible_products: Some(vec![]),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 2, "orphan-product builds stay visible on empty list");
    assert!(records.iter().all(|b| b.id != private));

    let (total, _) = store
        .list_builds(&crate::types::BuildListFilter::default())
        .await
        .unwrap();
    assert_eq!(total, 3);

    // offset 越界的空页：窗口函数无行，COUNT 兜底必须仍返回真实 total（与 tasks 侧同口径）。
    let (total, empty) = store
        .list_builds(&crate::types::BuildListFilter {
            visible_products: Some(vec!["ule3".to_string()]),
            limit: Some(2),
            offset: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 2, "empty page must keep the real total");
    assert!(empty.is_empty());

    // 兜底重查的尾占位符补绑：task_id + priority 过滤 + 越界 offset 空页——
    // 漏绑任一尾部占位符，COUNT 重查即绑定数错位。
    let rec = store.get_build(b1).await.unwrap().expect("b1 record");
    let (total, empty) = store
        .list_builds(&crate::types::BuildListFilter {
            task_id: rec.task_id,
            priority: Some(rec.priority),
            limit: Some(2),
            offset: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 1, "task+priority filtered COUNT fallback");
    assert!(empty.is_empty());
}

/// 超 MAX_BIND_PARAMS 拒绝（守卫先于查询，无需建行）。
#[tokio::test]
async fn get_existing_build_phases_rejects_oversized_in_list() {
    let (store, _tmp) = create_test_store().await;
    let limit = crate::state::db::MAX_BIND_PARAMS;
    let ids: Vec<i64> = (0..=limit as i64).collect();
    let err = store
        .get_existing_build_phases(&ids)
        .await
        .expect_err("oversized IN list must be rejected by in_placeholders guard");
    assert!(
        err.to_string().to_lowercase().contains("in list too long"),
        "unexpected error: {err:?}"
    );
}

/// 批次归属回填：task 下未归属行标到批次、既有归属不动、跨 task 不影响。
#[tokio::test]
async fn attach_task_builds_to_batch_only_claims_unowned_rows() {
    let (store, _tmp) = create_test_store().await;
    let task_id = crate::state::test_state::seed_task(&store, "fedora", "hello-1.0-1.fc42").await;
    // batch_id 是真实外键（builds.batch_id → build_batches.id），先建批次行。
    let batch_id = store
        .insert_batch(BatchInsert {
            product_id: None,
            created_by: None,
            source_repo_url: "https://example.com/repo",
            dist: None,
            arch_targets_json: None,
            on_failure: "continue",
            force_all: false,
            request_json: None,
        })
        .await
        .unwrap();
    let b1 = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello-1.0-1.fc42",
            phase: "pending",
            backend: "chroot",
            user: "batch",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(
        store
            .attach_task_builds_to_batch(task_id, batch_id)
            .await
            .unwrap(),
        1
    );
    let owned: i64 = sqlx::query_scalar("SELECT batch_id FROM builds WHERE id = $1")
        .bind(b1)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(owned, batch_id);

    // 既有归属不被抢占（重放/恢复路径重复调用无害）；无归属行时 0 行。
    assert_eq!(
        store
            .attach_task_builds_to_batch(task_id, batch_id)
            .await
            .unwrap(),
        0
    );
    let owned: i64 = sqlx::query_scalar("SELECT batch_id FROM builds WHERE id = $1")
        .bind(b1)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(owned, batch_id, "existing attribution must not be stolen");
}

/// succeeded 裸源包名（name 列）去重；失败/他产品/他 phase 不混入。
/// 种子带 N-V-R，钉住返回裸名（列用错则与源仓裸名永不相交）。
#[tokio::test]
async fn list_succeeded_source_names_dedups_and_scopes_by_product() {
    use crate::state::test_state::seed_task;
    let (_tmp, store) = tmp_store().await;

    async fn mk_build(store: &StateStore, product: &str, pkg: &str, phase: &str) {
        let task_id = seed_task(store, product, pkg).await;
        store
            .insert_build(BuildInsert {
                product,
                pkg_name: pkg,
                phase,
                backend: "chroot",
                user: "tester",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
    }

    mk_build(&store, "p1", "alpha-1.0-1.fc42", "succeeded").await;
    mk_build(&store, "p1", "beta-2.0-1", "succeeded").await;
    // 同裸包名第二次成功构建（N-V-R 不同、name 相同）→ 按 name 去重。
    mk_build(&store, "p1", "alpha-2.0-1.fc42", "succeeded").await;
    mk_build(&store, "p1", "gamma-1.0-1", "failed").await;
    mk_build(&store, "p1", "delta-1.0-1", "building").await;
    mk_build(&store, "p2", "alpha-1.0-1.fc42", "succeeded").await;

    let mut names = store.list_succeeded_source_names("p1").await.unwrap();
    names.sort();
    assert_eq!(
        names,
        vec!["alpha".to_string(), "beta".to_string()],
        "set must carry bare source names, never N-V-R pkg_name"
    );
    assert_eq!(
        store.list_succeeded_source_names("p2").await.unwrap(),
        vec!["alpha".to_string()]
    );
    assert!(store
        .list_succeeded_source_names("nope")
        .await
        .unwrap()
        .is_empty());
}
