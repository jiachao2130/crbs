// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 共享测试夹具：AppState 构造、构建/worker/画像播种与查询辅助。

use super::*;

pub(super) async fn setup_app(max_concurrent: usize) -> (Arc<AppState>, tempfile::TempDir) {
    setup_app_with_mode(max_concurrent, SchedulerMode::default()).await
}

pub(super) async fn setup_app_with_mode(
    max_concurrent: usize,
    mode: SchedulerMode,
) -> (Arc<AppState>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let cfg = ServerConfig {
        max_local_builds: max_concurrent,
        min_free_disk_gb: 0,
        low_priority_reserve_ratio: 0.25,
        scheduler_mode: mode,
        ..Default::default()
    };
    let app = Arc::new(AppState::for_test(store, cfg, tmp.path().to_path_buf()));
    (app, tmp)
}

pub(super) async fn setup_app_with_config(
    max_concurrent: usize,
    mut cfg: ServerConfig,
) -> (Arc<AppState>, tempfile::TempDir) {
    cfg.max_local_builds = max_concurrent;
    cfg.min_free_disk_gb = 0;
    cfg.low_priority_reserve_ratio = 0.25;
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app = Arc::new(AppState::for_test(store, cfg, tmp.path().to_path_buf()));
    (app, tmp)
}

pub(super) async fn seed_pending_build(
    store: &StateStore,
    pkg: &str,
    arch: Option<&str>,
    priority: i32,
) -> i64 {
    let task_id = crate::test_support::seed_task(store, "test", pkg).await;
    let build_id = store
        .insert_build(BuildInsert {
            product: "test",
            pkg_name: pkg,
            phase: "pending",
            backend: "chroot",
            user: "tester",
            arch,
            priority,
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .set_build_request_info(build_id, "/tmp/test.src.rpm", r#"{"arch":"x86_64"}"#)
        .await
        .unwrap();
    build_id
}

pub(super) async fn seed_building_build(store: &StateStore, pkg: &str, priority: i32) -> i64 {
    let task_id = crate::test_support::seed_task(store, "test", pkg).await;
    store
        .insert_build(BuildInsert {
            product: "test",
            pkg_name: pkg,
            phase: "building",
            backend: "chroot",
            user: "tester",
            priority,
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap()
}

pub(super) async fn seed_assigned_build(store: &StateStore, pkg: &str, priority: i32) -> i64 {
    let task_id = crate::test_support::seed_task(store, "test", pkg).await;
    store
        .insert_build(BuildInsert {
            product: "test",
            pkg_name: pkg,
            phase: "assigned",
            backend: "chroot",
            user: "tester",
            priority,
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap()
}

pub(super) async fn seed_worker(store: &StateStore, name: &str, arch: &str, capacity: i64) -> i64 {
    store
        .upsert_worker(name, arch, capacity, "test", "online", None)
        .await
        .unwrap()
}

pub(super) async fn age_worker_heartbeat(store: &StateStore, worker_id: i64, secs: i64) {
    sqlx::query("UPDATE workers SET last_heartbeat = datetime('now', ?) WHERE id = ?")
        .bind(format!("-{} seconds", secs))
        .bind(worker_id)
        .execute(store.pool())
        .await
        .unwrap();
}

pub(super) async fn build_phase(store: &StateStore, build_id: i64) -> String {
    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = ?")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    phase
}

pub(super) async fn build_assignment_pairs(store: &StateStore) -> Vec<(i64, i64)> {
    let rows: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT build_id, worker_id FROM worker_tasks WHERE kind = 'build' ORDER BY id",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    rows
}

pub(super) async fn seed_succeeded_resource_builds(
    store: &StateStore,
    product: &str,
    pkg: &str,
    peak_rss_kb: i64,
    cpu_p90_cores: f64,
    count: usize,
) {
    for _ in 0..count {
        let task_id = crate::test_support::seed_task(store, product, pkg).await;
        let build_id = store
            .insert_build(BuildInsert {
                product,
                pkg_name: pkg,
                phase: "pending",
                backend: "chroot",
                user: "tester",
                arch: Some("x86_64"),
                priority: 0,
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .complete_build(build_id, "succeeded", None)
            .await
            .unwrap();
        sqlx::query("UPDATE builds SET peak_rss_kb = ?, cpu_p90_cores = ? WHERE id = ?")
            .bind(peak_rss_kb)
            .bind(cpu_p90_cores)
            .bind(build_id)
            .execute(store.pool())
            .await
            .unwrap();
        // 门槛传 Some(0)：种子值低于默认 1GiB 轻包门槛，门槛语义已由
        // core 学习单测覆盖。
        store
            .apply_learning_sample(
                product,
                pkg,
                "x86_64",
                &crbs_core::ResourceSampleOutcome::Succeeded {
                    backend: crbs_core::SampleBackend::Cgroup,
                    peak_rss_kb,
                    peak_tmpfs_kb: None,
                    cpu_p90_cores: Some(cpu_p90_cores),
                    sample_ncpu: None,
                },
                Some(0),
                crbs_core::DEFAULT_CENSOR_HEADROOM,
            )
            .await
            .unwrap();
    }
}

pub(super) async fn seed_product(
    store: &StateStore,
    name: &str,
    overrides: Option<std::collections::BTreeMap<String, crbs_core::config::ResourceOverride>>,
) {
    let cfg = crbs_core::config::ProductConfig {
        base_packages: vec!["bash".into()],
        repos: vec![crbs_core::config::RepoConfig {
            name: "base".into(),
            baseurl: "http://example/repo".into(),
            ..Default::default()
        }],
        resource_overrides: overrides,
        ..Default::default()
    };
    store
        .create_product(crbs_core::CreateProductInput {
            name,
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: "public",
            config: &cfg,
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();
}

pub(super) async fn seed_worker_telemetry(
    store: &StateStore,
    worker_id: i64,
    load1: f64,
    ncpu: i64,
    mem_used_pct: f64,
    mem_total_kb: i64,
) {
    sqlx::query(
        "UPDATE workers SET load1 = ?, ncpu = ?, mem_used_pct = ?, mem_total_kb = ? WHERE id = ?",
    )
    .bind(load1)
    .bind(ncpu)
    .bind(mem_used_pct)
    .bind(mem_total_kb)
    .bind(worker_id)
    .execute(store.pool())
    .await
    .unwrap();
}

pub(super) async fn build_error_summary(store: &StateStore, build_id: i64) -> Option<String> {
    sqlx::query_scalar("SELECT error_summary FROM builds WHERE id = ?")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap()
}

pub(super) async fn seed_censored_profile(store: &StateStore, product: &str, pkg: &str) {
    sqlx::query(
        "INSERT INTO package_resource_profiles (product, source_name, arch, learned_censored, learned_samples, learned_max_mem_kb) VALUES (?, ?, 'x86_64', 1, 1, 1000000000000) \
         ON CONFLICT (product, source_name, arch) DO UPDATE SET learned_censored = 1, learned_samples = 1, learned_max_mem_kb = 1000000000000, learned_ema_mem_kb = NULL",
    )
    .bind(product)
    .bind(pkg)
    .execute(store.pool())
    .await
    .unwrap();
}

pub(super) async fn assignment_map(store: &StateStore) -> HashMap<i64, i64> {
    build_assignment_pairs(store).await.into_iter().collect()
}

pub(super) async fn seed_steering_cluster(app: &Arc<AppState>) -> (i64, i64) {
    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    let w2 = seed_worker(&app.state_store, "w2", "x86_64", 2).await;
    seed_worker_telemetry(&app.state_store, w1, 0.0, 8, 80.0, 2_000_000).await;
    seed_worker_telemetry(&app.state_store, w2, 0.0, 8, 10.0, 2_000_000).await;
    (w1, w2)
}
