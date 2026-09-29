// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 分布式派发 planner 集成：决策、censored 兜底、硬下限、权重/回填与 heavy steering。

use super::common::*;
use super::*;

#[tokio::test]
async fn dispatch_rejects_arch_mismatch_and_requeues() {
    let (app, _tmp) = setup_app(1).await;
    let build_id = seed_pending_build(&app.state_store, "pkg", Some("x86_64"), 0).await;
    let worker_id = seed_worker(&app.state_store, "w1", "aarch64", 2).await;

    sqlx::query("UPDATE builds SET request_json = ? WHERE id = ?")
        .bind(r#"{"arch": "x86_64"}"#)
        .bind(build_id)
        .execute(app.state_store.pool())
        .await
        .unwrap();

    app.state_store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    let dispatch = WorkerDispatch::new(app.clone());
    let task = dispatch.wait_for_task(worker_id, "aarch64", 0).await;

    assert!(task.is_none(), "arch mismatch should return no task");
    assert_eq!(
        build_phase(&app.state_store, build_id).await,
        "pending",
        "rejected build should be back to pending"
    );
}

#[tokio::test]
async fn distributed_only_mode_skips_local_build() {
    let (app, _tmp) = setup_app_with_mode(4, SchedulerMode::DistributedOnly).await;
    seed_pending_build(&app.state_store, "pkg", Some(""), 0).await;

    assert_eq!(
        app.server_config.scheduler_mode,
        SchedulerMode::DistributedOnly
    );

    let cancel = CancellationToken::new();
    let app_clone = app.clone();
    let loop_cancel = cancel.clone();
    let handle = tokio::spawn(async move {
        run_scheduler_loop(app_clone, loop_cancel).await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    cancel.cancel();
    let _ = handle.await;

    let phase = build_phase(&app.state_store, 1).await;
    assert_eq!(
        phase, "pending",
        "DistributedOnly mode should not execute local build"
    );
}

#[tokio::test]
async fn planner_dispatches_pending_and_tracks_counters() {
    let (app, _tmp) = setup_app(4).await;
    let build_id = seed_pending_build(&app.state_store, "pkg", Some("x86_64"), 0).await;
    seed_worker(&app.state_store, "w1", "x86_64", 2).await;

    let dispatched = planner::run_tick(&app).await.unwrap();
    assert!(dispatched);
    assert_eq!(build_phase(&app.state_store, build_id).await, "assigned");
    assert_eq!(app.metrics.dispatch_assigned_total(), 1);
    assert!(
        app.dispatch_attribution.is_empty(),
        "dispatched build must leave attribution"
    );
}

#[tokio::test]
async fn planner_watermark_blocked_head_falls_over_to_next_worker() {
    let (app, _tmp) = setup_app(4).await;
    seed_succeeded_resource_builds(&app.state_store, "test", "heavy", 600_000, 0.0, 2).await;
    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    let w2 = seed_worker(&app.state_store, "w2", "x86_64", 2).await;
    seed_worker_telemetry(&app.state_store, w1, 0.0, 8, 50.0, 1_000_000).await;
    seed_worker_telemetry(&app.state_store, w2, 0.0, 8, 10.0, 1_000_000).await;
    let filler = seed_pending_build(&app.state_store, "filler", Some("x86_64"), 0).await;
    app.state_store
        .assign_build_to_worker(filler, w2)
        .await
        .unwrap();
    let build_id = seed_pending_build(&app.state_store, "heavy", Some("x86_64"), 0).await;

    assert!(planner::run_tick(&app).await.unwrap());
    assert_eq!(
        assignment_map(&app.state_store).await.get(&build_id),
        Some(&w2),
        "head blocked by the watermark must fall over to the feasible next worker"
    );
    assert_eq!(
        app.metrics.dispatch_admit_rejects_total(
            crate::server::metrics::DispatchRejectDimension::WatermarkMem
        ),
        0,
        "fall-through dispatch is a placement, not a rejection"
    );
}

#[tokio::test]
async fn planner_candidate_weight_admits_healthy_worker() {
    let (app, _tmp) = setup_app(4).await;
    seed_succeeded_resource_builds(&app.state_store, "test", "heavy", 600_000, 0.0, 2).await;
    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    let w2 = seed_worker(&app.state_store, "w2", "x86_64", 2).await;

    seed_worker_telemetry(&app.state_store, w1, 0.0, 8, 90.0, 1_000_000).await;
    seed_worker_telemetry(&app.state_store, w2, 0.0, 8, 10.0, 1_000_000).await;
    let blocker = seed_pending_build(&app.state_store, "blocker", Some("x86_64"), 0).await;
    app.state_store
        .assign_build_to_worker(blocker, w1)
        .await
        .unwrap();
    let build_id = seed_pending_build(&app.state_store, "heavy", Some("x86_64"), 0).await;

    assert!(planner::run_tick(&app).await.unwrap());
    assert_eq!(
        assignment_map(&app.state_store).await.get(&build_id),
        Some(&w2),
        "healthy worker must take the heavy build"
    );
}

#[tokio::test]
async fn planner_holds_queue_on_full_watermark_reject() {
    let (app, _tmp) = setup_app(4).await;
    seed_succeeded_resource_builds(&app.state_store, "test", "heavy", 600_000, 0.0, 2).await;
    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    seed_worker_telemetry(&app.state_store, w1, 0.0, 8, 50.0, 1_000_000).await;
    let build_id = seed_pending_build(&app.state_store, "heavy", Some("x86_64"), 0).await;

    assert!(!planner::run_tick(&app).await.unwrap());
    assert_eq!(build_phase(&app.state_store, build_id).await, "pending");
    let attribution = app
        .dispatch_attribution
        .get(build_id)
        .expect("attribution recorded");
    assert_eq!(
        attribution.reason,
        planner::RejectReason::WatermarkBlocked {
            dimension: WatermarkDimension::Mem
        }
    );
    assert!(attribution.first_watermark_reject_at.is_some());

    let load = attribution
        .watermark_effective_load
        .expect("effective load recorded with the watermark reject");
    assert!((load.mem_kb - 600_000.0).abs() < 1e-6, "load: {load:?}");
    assert!((load.cpu_cores - 0.0).abs() < 1e-6, "load: {load:?}");
    assert!(app.metrics.no_candidate_ticks_total() >= 1);
}

#[tokio::test]
async fn planner_watermark_blocked_head_does_not_block_next_candidate() {
    let (app, _tmp) = setup_app(4).await;
    seed_succeeded_resource_builds(&app.state_store, "test", "heavy", 600_000, 0.0, 2).await;
    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    seed_worker_telemetry(&app.state_store, w1, 0.0, 8, 50.0, 1_000_000).await;

    let heavy = seed_pending_build(
        &app.state_store,
        "heavy",
        Some("x86_64"),
        crbs_core::types::PRIORITY_CRITICAL,
    )
    .await;

    let light = seed_pending_build(&app.state_store, "light", Some("x86_64"), 0).await;

    assert!(planner::run_tick(&app).await.unwrap());
    assert_eq!(
        build_phase(&app.state_store, heavy).await,
        "pending",
        "blocked head must stay queued"
    );
    assert_eq!(
        app.dispatch_attribution.get(heavy).unwrap().reason,
        planner::RejectReason::WatermarkBlocked {
            dimension: WatermarkDimension::Mem
        }
    );
    assert_eq!(
        assignment_map(&app.state_store).await.get(&light),
        Some(&w1),
        "the following light candidate must dispatch past the blocked head"
    );
}

#[tokio::test]
async fn planner_records_no_fit_arch() {
    let (app, _tmp) = setup_app(4).await;
    let build_id = seed_pending_build(&app.state_store, "pkg", Some("x86_64"), 0).await;
    seed_worker(&app.state_store, "w1", "aarch64", 2).await;

    assert!(!planner::run_tick(&app).await.unwrap());
    assert_eq!(build_phase(&app.state_store, build_id).await, "pending");
    assert_eq!(
        app.dispatch_attribution.get(build_id).unwrap().reason,
        planner::RejectReason::NoFitArch
    );
    assert_eq!(
        app.metrics
            .dispatch_admit_rejects_total(crate::server::metrics::DispatchRejectDimension::NoFit),
        1
    );
}

#[tokio::test]
async fn planner_init_gate_blocks_and_releases() {
    let (app, _tmp) = setup_app(4).await;
    let build_id = seed_pending_build(&app.state_store, "pkg", Some("x86_64"), 0).await;
    let worker_id = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    let init_id = app
        .state_store
        .try_assign_init_to_worker(worker_id, "test")
        .await
        .unwrap()
        .expect("init fixture");

    assert!(!planner::run_tick(&app).await.unwrap());
    assert_eq!(build_phase(&app.state_store, build_id).await, "pending");
    assert_eq!(
        app.dispatch_attribution.get(build_id).unwrap().reason,
        planner::RejectReason::InitGated
    );

    app.state_store
        .update_worker_task_status(init_id, "completed")
        .await
        .unwrap();
    assert!(planner::run_tick(&app).await.unwrap());
    assert_eq!(build_phase(&app.state_store, build_id).await, "assigned");
}

#[tokio::test]
async fn planner_retries_next_candidate_after_cas_loss() {
    let (app, _tmp) = setup_app(4).await;
    let b1 = seed_pending_build(&app.state_store, "pkg", Some("x86_64"), 0).await;
    let b2 = seed_pending_build(&app.state_store, "pkg2", Some("x86_64"), 0).await;
    let worker_id = seed_worker(&app.state_store, "w1", "x86_64", 2).await;

    app.state_store
        .assign_build_to_worker(b1, worker_id)
        .await
        .unwrap();

    assert!(planner::run_tick(&app).await.unwrap());
    let map = assignment_map(&app.state_store).await;
    assert_eq!(
        map.get(&b2),
        Some(&worker_id),
        "next candidate must proceed"
    );
    assert_eq!(
        map.get(&b1),
        Some(&worker_id),
        "stolen build keeps its assignment"
    );
}

#[tokio::test]
async fn planner_fills_distinct_workers_per_candidate() {
    let (app, _tmp) = setup_app(4).await;
    let b1 = seed_pending_build(&app.state_store, "pkg", Some("x86_64"), 0).await;
    let b2 = seed_pending_build(&app.state_store, "pkg2", Some("x86_64"), 0).await;
    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 1).await;
    let w2 = seed_worker(&app.state_store, "w2", "x86_64", 1).await;

    assert!(planner::run_tick(&app).await.unwrap());
    let map = assignment_map(&app.state_store).await;
    assert_eq!(
        map.get(&b1),
        Some(&w1),
        "first candidate takes the least-loaded worker"
    );
    assert_eq!(
        map.get(&b2),
        Some(&w2),
        "second candidate skips the now-full worker"
    );
}

#[tokio::test]
async fn planner_soft_fallback_only_censored_past_age() {
    let (app, _tmp) = setup_app(4).await;
    seed_succeeded_resource_builds(&app.state_store, "test", "heavy", 600_000, 0.0, 2).await;
    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    let w2 = seed_worker(&app.state_store, "w2", "x86_64", 2).await;

    seed_worker_telemetry(&app.state_store, w1, 0.0, 8, 80.0, 1_000_000).await;
    seed_worker_telemetry(&app.state_store, w2, 0.0, 8, 50.0, 1_000_000).await;
    seed_censored_profile(&app.state_store, "test", "heavy").await;

    sqlx::query(
        "INSERT INTO package_resource_profiles (product, source_name, arch, learned_censored, learned_samples) VALUES ('test', 'heavy2', 'x86_64', 0, 1)",
    )
    .execute(app.state_store.pool())
    .await
    .unwrap();
    seed_succeeded_resource_builds(&app.state_store, "test", "heavy2", 600_000, 0.0, 2).await;
    let censored = seed_pending_build(&app.state_store, "heavy", Some("x86_64"), 0).await;
    let plain = seed_pending_build(&app.state_store, "heavy2", Some("x86_64"), 0).await;

    let aged = std::time::Instant::now()
        - std::time::Duration::from_secs(planner::LAST_RESORT_AFTER_SECS + 60);
    app.dispatch_attribution
        .seed_first_watermark_reject(censored, aged);
    app.dispatch_attribution
        .seed_first_watermark_reject(plain, aged);

    assert!(planner::run_tick(&app).await.unwrap());
    assert_eq!(
        build_phase(&app.state_store, censored).await,
        "assigned",
        "censored past-age build must get the soft fallback"
    );
    assert_eq!(
        assignment_map(&app.state_store).await.get(&censored),
        Some(&w2),
        "fallback targets the max-headroom worker"
    );
    let summary = build_error_summary(&app.state_store, censored)
        .await
        .unwrap_or_default();
    assert!(
        summary.contains("soft watermark fallback"),
        "note must land on the error_summary channel: {summary}"
    );
    assert_eq!(app.metrics.soft_fallbacks_total(), 1);
}

#[tokio::test]
async fn planner_never_falls_back_for_uncensored() {
    let (app, _tmp) = setup_app(4).await;
    seed_succeeded_resource_builds(&app.state_store, "test", "heavy", 600_000, 0.0, 2).await;
    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    seed_worker_telemetry(&app.state_store, w1, 0.0, 8, 50.0, 1_000_000).await;
    let build_id = seed_pending_build(&app.state_store, "heavy", Some("x86_64"), 0).await;
    let aged = std::time::Instant::now()
        - std::time::Duration::from_secs(planner::LAST_RESORT_AFTER_SECS + 60);
    app.dispatch_attribution
        .seed_first_watermark_reject(build_id, aged);

    assert!(!planner::run_tick(&app).await.unwrap());
    assert_eq!(build_phase(&app.state_store, build_id).await, "pending");
    assert_eq!(app.metrics.soft_fallbacks_total(), 0);
}

#[tokio::test]
async fn planner_censored_within_age_keeps_waiting() {
    let (app, _tmp) = setup_app(4).await;
    seed_succeeded_resource_builds(&app.state_store, "test", "heavy", 600_000, 0.0, 2).await;
    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    seed_worker_telemetry(&app.state_store, w1, 0.0, 8, 50.0, 1_000_000).await;
    seed_censored_profile(&app.state_store, "test", "heavy").await;
    let build_id = seed_pending_build(&app.state_store, "heavy", Some("x86_64"), 0).await;
    let fresh = std::time::Instant::now() - std::time::Duration::from_secs(60);
    app.dispatch_attribution
        .seed_first_watermark_reject(build_id, fresh);

    assert!(!planner::run_tick(&app).await.unwrap());
    assert_eq!(build_phase(&app.state_store, build_id).await, "pending");

    assert_eq!(
        app.dispatch_attribution.get(build_id).unwrap().reason,
        planner::RejectReason::WatermarkBlocked {
            dimension: WatermarkDimension::Mem
        },
        "censored effective weight must spill the watermark gate and attribute"
    );
    assert_eq!(app.metrics.soft_fallbacks_total(), 0);
}

#[tokio::test]
async fn planner_hard_floor_lands_only_on_qualifying_worker() {
    let cfg = ServerConfig {
        resource_requirements_enabled: true,
        ..Default::default()
    };
    let (app, _tmp) = setup_app_with_config(4, cfg).await;
    app.state_store
        .set_declared_requirements(
            "test",
            "floorpkg",
            "x86_64",
            Some(16 * 1024 * 1024),
            None,
            None,
        )
        .await
        .unwrap();
    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    let w2 = seed_worker(&app.state_store, "w2", "x86_64", 2).await;
    seed_worker_telemetry(&app.state_store, w1, 0.0, 8, 0.0, 8 * 1024 * 1024).await;
    seed_worker_telemetry(&app.state_store, w2, 0.0, 8, 0.0, 32 * 1024 * 1024).await;
    let build_id = seed_pending_build(&app.state_store, "floorpkg", Some("x86_64"), 0).await;

    assert!(planner::run_tick(&app).await.unwrap());
    assert_eq!(
        assignment_map(&app.state_store).await.get(&build_id),
        Some(&w2),
        "declared min-mem must restrict placement to the qualifying worker"
    );
}

#[tokio::test]
async fn planner_disk_floor_rejects_worker_without_disk_telemetry() {
    let cfg = ServerConfig {
        resource_requirements_enabled: true,
        ..Default::default()
    };
    let (app, _tmp) = setup_app_with_config(4, cfg).await;
    app.state_store
        .set_declared_requirements(
            "test",
            "diskpkg",
            "x86_64",
            None,
            None,
            Some(64 * 1024 * 1024),
        )
        .await
        .unwrap();
    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    seed_worker_telemetry(&app.state_store, w1, 0.0, 8, 0.0, 32 * 1024 * 1024).await;

    let build_id = seed_pending_build(&app.state_store, "diskpkg", Some("x86_64"), 0).await;

    assert!(!planner::run_tick(&app).await.unwrap());
    assert_eq!(build_phase(&app.state_store, build_id).await, "pending");
    assert_eq!(
        app.dispatch_attribution.get(build_id).unwrap().reason,
        planner::RejectReason::NoFitHardReq {
            dimension: planner::HardReqDimension::Disk
        },
        "missing required-dimension telemetry must fail closed with a disk attribution"
    );
    assert_eq!(
        app.metrics
            .dispatch_admit_rejects_total(crate::server::metrics::DispatchRejectDimension::Disk),
        1
    );
}

#[tokio::test]
async fn planner_scales_learned_cpu_weight_to_target_node() {
    let (app, _tmp) = setup_app(4).await;
    seed_succeeded_resource_builds(&app.state_store, "test", "cpuwide", 100_000, 40.0, 2).await;
    sqlx::query(
        "UPDATE package_resource_profiles SET learned_sample_ncpu = 64 \
         WHERE product = 'test' AND source_name = 'cpuwide'",
    )
    .execute(app.state_store.pool())
    .await
    .unwrap();
    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    seed_worker_telemetry(&app.state_store, w1, 0.0, 16, 0.0, 8_000_000).await;
    let build_id = seed_pending_build(&app.state_store, "cpuwide", Some("x86_64"), 0).await;

    assert!(planner::run_tick(&app).await.unwrap());
    assert_eq!(
        assignment_map(&app.state_store).await.get(&build_id),
        Some(&w1),
        "40 cores sampled on 64 cores must normalize to 10 on a 16-core node"
    );
}

#[tokio::test]
async fn planner_scales_learned_mem_weight_to_target_node() {
    let (app, _tmp) = setup_app(4).await;
    seed_succeeded_resource_builds(&app.state_store, "test", "memwide", 57_000_000, 100.0, 2).await;
    sqlx::query(
        "UPDATE package_resource_profiles SET learned_sample_ncpu = 128 \
         WHERE product = 'test' AND source_name = 'memwide'",
    )
    .execute(app.state_store.pool())
    .await
    .unwrap();
    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 2).await;

    seed_worker_telemetry(&app.state_store, w1, 0.0, 64, 10.0, 64_000_000).await;
    let build_id = seed_pending_build(&app.state_store, "memwide", Some("x86_64"), 0).await;

    assert!(planner::run_tick(&app).await.unwrap());
    assert_eq!(
        assignment_map(&app.state_store).await.get(&build_id),
        Some(&w1),
        "57GB sampled on 128 cores must scale to 28.5GB on a 64-core node"
    );
}

#[tokio::test]
async fn planner_hard_floor_stall_emits_one_time_note() {
    let cfg = ServerConfig {
        resource_requirements_enabled: true,
        ..Default::default()
    };
    let (app, _tmp) = setup_app_with_config(4, cfg).await;
    app.state_store
        .set_declared_requirements(
            "test",
            "floorpkg",
            "x86_64",
            Some(64 * 1024 * 1024),
            None,
            None,
        )
        .await
        .unwrap();
    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    seed_worker_telemetry(&app.state_store, w1, 0.0, 8, 0.0, 8 * 1024 * 1024).await;
    let build_id = seed_pending_build(&app.state_store, "floorpkg", Some("x86_64"), 0).await;
    let aged = std::time::Instant::now()
        - Duration::from_secs(app.server_config.resource_hard_req_stall_secs + 60);
    app.dispatch_attribution
        .seed_first_hard_req_reject(build_id, aged);

    assert!(!planner::run_tick(&app).await.unwrap());
    assert_eq!(build_phase(&app.state_store, build_id).await, "pending");
    let summary = build_error_summary(&app.state_store, build_id)
        .await
        .unwrap_or_default();
    assert!(
        summary.contains("resource floor not satisfiable"),
        "stall note must land on the error_summary channel: {summary}"
    );
    assert!(
        summary.contains("dimension=mem"),
        "note must name the blocked dimension: {summary}"
    );
    assert!(
        app.dispatch_attribution
            .get(build_id)
            .unwrap()
            .hard_req_stall_noted
    );

    assert!(!planner::run_tick(&app).await.unwrap());
    let summary2 = build_error_summary(&app.state_store, build_id)
        .await
        .unwrap_or_default();
    assert_eq!(summary, summary2, "stall note must be emitted once");
}

#[tokio::test]
async fn planner_requirements_off_ignores_declared_floors() {
    let (app, _tmp) = setup_app(4).await;
    app.state_store
        .set_declared_requirements(
            "test",
            "floorpkg",
            "x86_64",
            Some(16 * 1024 * 1024),
            None,
            None,
        )
        .await
        .unwrap();
    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    seed_worker_telemetry(&app.state_store, w1, 0.0, 8, 0.0, 8 * 1024 * 1024).await;
    let build_id = seed_pending_build(&app.state_store, "floorpkg", Some("x86_64"), 0).await;

    assert!(planner::run_tick(&app).await.unwrap());
    assert_eq!(
        assignment_map(&app.state_store).await.get(&build_id),
        Some(&w1),
        "requirements off: declared floor must not gate dispatch"
    );
    assert_eq!(
        app.metrics
            .dispatch_admit_rejects_total(crate::server::metrics::DispatchRejectDimension::Mem),
        0
    );
}

#[tokio::test]
async fn weight_source_falls_back_to_overrides_only_when_switch_off() {
    let cfg = ServerConfig {
        resource_profile_weights_enabled: false,
        ..Default::default()
    };
    let (app, _tmp) = setup_app_with_config(4, cfg).await;
    let store = &app.state_store;

    let mut overrides = std::collections::BTreeMap::new();
    overrides.insert(
        "gcc".to_string(),
        crbs_core::config::ResourceOverride {
            mem_gb: 16.0,
            cpu_cores: 8.0,
        },
    );
    seed_product(store, "ovr", Some(overrides)).await;

    seed_succeeded_resource_builds(store, "ovr", "gcc", 1_000_000, 4.0, 2).await;
    seed_censored_profile(store, "ovr", "cens").await;

    let gcc_key = profile_key("ovr", "gcc", Some("x86_64"));
    let resolved = load_resource_profiles(&app, vec![gcc_key.clone()]).await;
    assert_eq!(
        resolved.get(&gcc_key).unwrap().weight,
        PackageResourceWeight {
            peak_rss_kb: Some(16.0 * 1024.0 * 1024.0),
            cpu_p90_cores: Some(8.0),
            cpu_sample_ncpu: None,
        },
        "weights off: override values must be the only weight source"
    );

    let cens_key = profile_key("ovr", "cens", Some("x86_64"));
    let resolved = load_resource_profiles(&app, vec![cens_key.clone()]).await;
    assert_eq!(
        resolved.get(&cens_key).unwrap().weight,
        PackageResourceWeight::default()
    );
}

#[tokio::test]
async fn profile_backfill_feeds_dispatch_weight_identical_to_pre_upgrade() {
    let (app, _tmp) = setup_app_with_config(
        4,
        ServerConfig {
            resource_profile_min_peak_rss_kb: 0,
            ..Default::default()
        },
    )
    .await;
    let store = &app.state_store;

    for peak in [1000, 2000, 3000] {
        let task_id = crate::test_support::seed_task(store, "test", "bf").await;
        let id = store
            .insert_build(BuildInsert {
                product: "test",
                pkg_name: "bf",
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
        store.complete_build(id, "succeeded", None).await.unwrap();
        sqlx::query("UPDATE builds SET peak_rss_kb = ? WHERE id = ?")
            .bind(peak)
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap();
    }

    let key = profile_key("test", "bf", Some("x86_64"));
    let before = load_resource_profiles(&app, vec![key.clone()]).await;
    assert_eq!(
        before.get(&key).unwrap().weight,
        PackageResourceWeight::default(),
        "pre-backfill lookup must cache an unknown weight"
    );

    run_profile_backfill_once(&app).await;

    let row = store
        .get_profile("test", "bf", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_ema_mem_kb, Some(2040));
    let resolved = load_resource_profiles(&app, vec![key.clone()]).await;
    assert_eq!(
        resolved.get(&key).unwrap().weight.peak_rss_kb,
        Some(2040.0),
        "dispatch weight must equal the pre-upgrade EMA bit-for-bit (S6)"
    );

    assert!(store
        .get_app_meta(PROFILE_BACKFILL_MARKER)
        .await
        .unwrap()
        .is_some());
    sqlx::query("DELETE FROM package_resource_profiles")
        .execute(store.pool())
        .await
        .unwrap();
    run_profile_backfill_once(&app).await;
    assert!(
        store
            .get_profile("test", "bf", "x86_64")
            .await
            .unwrap()
            .is_none(),
        "marker short-circuits the second run (idempotent startup)"
    );
}

#[tokio::test]
async fn steering_places_heavy_candidate_on_normalized_roomiest_worker() {
    let cfg = ServerConfig {
        resource_requirements_enabled: true,
        resource_steering_enabled: true,
        ..Default::default()
    };
    let (app, _tmp) = setup_app_with_config(4, cfg).await;
    app.state_store
        .set_declared_requirements("test", "steerpkg", "x86_64", Some(1024), None, None)
        .await
        .unwrap();
    let (_w1, w2) = seed_steering_cluster(&app).await;
    let build_id = seed_pending_build(&app.state_store, "steerpkg", Some("x86_64"), 0).await;

    assert!(planner::run_tick(&app).await.unwrap());
    assert_eq!(
        assignment_map(&app.state_store).await.get(&build_id),
        Some(&w2),
        "heavy candidate must land on the normalized-roomiest worker, not the order head"
    );
}

#[tokio::test]
async fn steering_prefers_proportionally_roomier_node_over_absolutely_bigger() {
    let cfg = ServerConfig {
        resource_requirements_enabled: true,
        resource_steering_enabled: true,
        ..Default::default()
    };
    let (app, _tmp) = setup_app_with_config(4, cfg).await;
    app.state_store
        .set_declared_requirements("test", "steerpkg", "x86_64", Some(1024), None, None)
        .await
        .unwrap();
    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    let w2 = seed_worker(&app.state_store, "w2", "x86_64", 2).await;
    seed_worker_telemetry(&app.state_store, w1, 0.0, 8, 60.0, 10_000_000).await;
    seed_worker_telemetry(&app.state_store, w2, 0.0, 8, 10.0, 1_000_000).await;
    let build_id = seed_pending_build(&app.state_store, "steerpkg", Some("x86_64"), 0).await;

    assert!(planner::run_tick(&app).await.unwrap());
    assert_eq!(
        assignment_map(&app.state_store).await.get(&build_id),
        Some(&w2),
        "proportionally roomier small node must beat the absolutely bigger fuller node"
    );
}

#[tokio::test]
async fn steering_leaves_non_heavy_candidates_on_order_head() {
    let cfg = ServerConfig {
        resource_requirements_enabled: true,
        resource_steering_enabled: true,
        ..Default::default()
    };
    let (app, _tmp) = setup_app_with_config(4, cfg).await;
    let (w1, _w2) = seed_steering_cluster(&app).await;
    let build_id = seed_pending_build(&app.state_store, "plainpkg", Some("x86_64"), 0).await;

    assert!(planner::run_tick(&app).await.unwrap());
    assert_eq!(
        assignment_map(&app.state_store).await.get(&build_id),
        Some(&w1),
        "non-heavy candidates keep the least-loaded placement"
    );
}

#[tokio::test]
async fn steering_off_keeps_m1b_placement_bit_for_bit() {
    let cfg = ServerConfig {
        resource_requirements_enabled: true,
        ..Default::default()
    };
    let (app, _tmp) = setup_app_with_config(4, cfg).await;
    app.state_store
        .set_declared_requirements("test", "steerpkg", "x86_64", Some(1024), None, None)
        .await
        .unwrap();
    let (w1, _w2) = seed_steering_cluster(&app).await;
    let build_id = seed_pending_build(&app.state_store, "steerpkg", Some("x86_64"), 0).await;

    assert!(planner::run_tick(&app).await.unwrap());
    assert_eq!(
        assignment_map(&app.state_store).await.get(&build_id),
        Some(&w1),
        "steering off: placement must be bit-for-bit identical (order head)"
    );
}

#[tokio::test]
async fn planner_refill_cap_bounds_new_assignments_per_worker_per_tick() {
    let (app, _tmp) = setup_app(4).await;
    seed_worker(&app.state_store, "w1", "x86_64", 40).await;
    let mut critical = Vec::new();
    let mut plain = Vec::new();

    for i in 0..7 {
        critical.push(
            seed_pending_build(
                &app.state_store,
                &format!("critpkg{i}"),
                Some("x86_64"),
                crbs_core::types::PRIORITY_CRITICAL,
            )
            .await,
        );
    }
    for i in 0..5 {
        plain.push(
            seed_pending_build(&app.state_store, &format!("plainpkg{i}"), Some("x86_64"), 0).await,
        );
    }

    assert!(planner::run_tick(&app).await.unwrap());
    assert_eq!(
        assignment_map(&app.state_store).await.len(),
        5,
        "capacity-40 worker must take at most 5 new assignments per tick"
    );
    for id in &critical[..5] {
        assert_eq!(
            build_phase(&app.state_store, *id).await,
            "assigned",
            "the tick budget must be consumed in candidate order (priority first)"
        );
    }
    for id in &critical[5..] {
        assert_eq!(
            build_phase(&app.state_store, *id).await,
            "pending",
            "critical candidates beyond the budget stay queued (no drop, no quota split)"
        );
    }
    for id in &plain {
        assert_eq!(
            build_phase(&app.state_store, *id).await,
            "pending",
            "budget exhausted: remaining candidates wait for the next tick"
        );
    }

    assert!(planner::run_tick(&app).await.unwrap());
    let map = assignment_map(&app.state_store).await;
    assert_eq!(
        map.len(),
        10,
        "second tick must refill 2 criticals + 3 plains"
    );
    for id in &critical {
        assert_eq!(build_phase(&app.state_store, *id).await, "assigned");
    }
    for id in &plain[..3] {
        assert_eq!(build_phase(&app.state_store, *id).await, "assigned");
    }
    for id in &plain[3..] {
        assert_eq!(
            build_phase(&app.state_store, *id).await,
            "pending",
            "second tick budget exhausted after 2 criticals + 3 plains"
        );
    }

    assert!(planner::run_tick(&app).await.unwrap());
    let map = assignment_map(&app.state_store).await;
    assert_eq!(map.len(), 12);
    for id in &plain {
        assert_eq!(build_phase(&app.state_store, *id).await, "assigned");
    }
}

#[tokio::test]
async fn planner_refill_cap_is_per_worker_and_does_not_spill_within_tick() {
    let (app, _tmp) = setup_app(4).await;

    let w1 = seed_worker(&app.state_store, "w1", "x86_64", 40).await;
    let w2 = seed_worker(&app.state_store, "w2", "x86_64", 16).await;
    for i in 0..7 {
        seed_pending_build(&app.state_store, &format!("pkg{i}"), Some("x86_64"), 0).await;
    }

    assert!(planner::run_tick(&app).await.unwrap());
    let map = assignment_map(&app.state_store).await;
    assert_eq!(map.len(), 5);
    assert_eq!(
        map.values().filter(|w| **w == w1).count(),
        5,
        "w1 budget = 40/8"
    );
    assert_eq!(
        map.values().filter(|w| **w == w2).count(),
        0,
        "a capped worker must not spill candidates to the next worker within the tick"
    );

    assert!(planner::run_tick(&app).await.unwrap());
    let map = assignment_map(&app.state_store).await;
    assert_eq!(map.len(), 7);
    assert_eq!(
        map.values().filter(|w| **w == w2).count(),
        2,
        "w2 budget = max(2, 16/8)"
    );
}
