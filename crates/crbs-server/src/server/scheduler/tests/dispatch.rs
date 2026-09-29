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

    // 手动写入 request_json，使 check_assigned_task 能解析出架构
    sqlx::query("UPDATE builds SET request_json = ? WHERE id = ?")
        .bind(r#"{"arch": "x86_64"}"#)
        .bind(build_id)
        .execute(app.state_store.pool())
        .await
        .unwrap();

    // 手动分配 x86_64 build 到 aarch64 worker（模拟调度器错误/DB 异常）
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
    // DistributedOnly：有 pending local build（arch=None），但不应本地执行
    let (app, _tmp) = setup_app_with_mode(4, SchedulerMode::DistributedOnly).await;
    seed_pending_build(&app.state_store, "pkg", Some(""), 0).await;
    // 无 worker，所以也不会 dispatch

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

/// 遍历序首节点被水位挡住时顺延次优节点：w1 排序在前（w2 预置活跃拉高
/// 利用率）且 used 50%×1M，候选 600k 进门即溢（500k+600k ≥ 900k）被拒；
/// roomy 的 w2 承接——排队回收语义（被 Σ 挡住的候选由空闲次优节点先行
/// 承接），顺延落位不是拒绝、不计 watermark_mem 指标。
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
    // w1：水位贴线（used 90%×1M）且带活跃构建（利用率排序垫底）；
    // w2：空载健康（used 10%），排序在前被选中。
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
    // 全拒归因随序首节点生效折算压载：唯一候选节点的 Σ 0 + 候选 600k mem / 0 核。
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
    // critical 优先级把 heavy 钉在队首：500k 已用 + 600k 权重 ≥ 900k 水位 → 拒。
    let heavy = seed_pending_build(
        &app.state_store,
        "heavy",
        Some("x86_64"),
        crbs_core::types::PRIORITY_CRITICAL,
    )
    .await;
    // 其后 default 小包（无画像 → 权重 0）：500k + 0 < 900k → 照常派出。
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
    // 首候选被外部（并发路径）先领走。
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
    // 两家都拒（used 80%×1M / 50%×1M，候选 600k 都进门溢出）；headroom
    // 大者 w2（900k−500k=400k vs 900k−800k=100k）承接兜底。
    seed_worker_telemetry(&app.state_store, w1, 0.0, 8, 80.0, 1_000_000).await;
    seed_worker_telemetry(&app.state_store, w2, 0.0, 8, 50.0, 1_000_000).await;
    seed_censored_profile(&app.state_store, "test", "heavy").await;
    // heavy2 的未删失画像与历史先行（pending 与 succeeded 同键活跃去重，
    // 历史必须先种）。
    sqlx::query(
        "INSERT INTO package_resource_profiles (product, source_name, arch, learned_censored, learned_samples) VALUES ('test', 'heavy2', 'x86_64', 0, 1)",
    )
    .execute(app.state_store.pool())
    .await
    .unwrap();
    seed_succeeded_resource_builds(&app.state_store, "test", "heavy2", 600_000, 0.0, 2).await;
    let censored = seed_pending_build(&app.state_store, "heavy", Some("x86_64"), 0).await;
    let plain = seed_pending_build(&app.state_store, "heavy2", Some("x86_64"), 0).await;
    // 两者都预置超龄的水位全拒时刻。
    let aged = std::time::Instant::now()
        - std::time::Duration::from_secs(planner::LAST_RESORT_AFTER_SECS + 60);
    app.dispatch_attribution
        .seed_first_watermark_reject(censored, aged);
    app.dispatch_attribution
        .seed_first_watermark_reject(plain, aged);

    // 先给 censored 一轮 tick（plain 会被同 tick 判拒，但兜底只应救前者）。
    // 同一 tick 内 plain 也超龄且全拒——它非 censored，必须留队列。
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
    // 端到端语义：censored 有效权重（max(ema,max) = 1e12）进 Σ 后被
    // 小节点水位门拒绝——留队列且归因WatermarkBlocked（兜底钟未满不救）。
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
    // disk_free_kb 不种 = NULL（未上报形态）。
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

/// 学习到的 CPU 权重是采样机并行度的函数：64 核机饱和包（p90=40 ≥ 0.5×64）
/// 派到 16 核节点须折算为 10 核才不被 CPU 水位恒拒（端到端走画像批查 → 决策）。
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

/// 学习到的内存权重按目标节点折算（饱和包）：128 核采样机的 57GB 峰值放到
/// 64 核节点折算为 28.5GB（-j 减半、真实需求同步减半），避免小内存节点被
/// 内存水位不必要拒绝（端到端走画像批查 → 决策）。
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
    // 64 核节点：used 10%×64GB → 全额比对 6.4M+57M ≥ 57.6M 必拒；折算后
    // 6.4M+28.5M < 57.6M 放行。
    seed_worker_telemetry(&app.state_store, w1, 0.0, 64, 10.0, 64_000_000).await;
    let build_id = seed_pending_build(&app.state_store, "memwide", Some("x86_64"), 0).await;

    assert!(planner::run_tick(&app).await.unwrap());
    assert_eq!(
        assignment_map(&app.state_store).await.get(&build_id),
        Some(&w1),
        "57GB sampled on 128 cores must scale to 28.5GB on a 64-core node"
    );
}

/// 硬下限全拒且超停滞阈值：一次性 note 落到 error_summary（可发现、可
/// 取消）；二次 tick 不重复追加。build 保持 pending——下限是契约，不自动
/// 破坏。
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
    // 学习画像与删失画像都种上：开关关闭时两者都不得进入权重。
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

    // 删失行同口径：不读 max(ema, max)，overrides 缺失降级未知（零权重）。
    let cens_key = profile_key("ovr", "cens", Some("x86_64"));
    let resolved = load_resource_profiles(&app, vec![cens_key.clone()]).await;
    assert_eq!(
        resolved.get(&cens_key).unwrap().weight,
        PackageResourceWeight::default()
    );
}

#[tokio::test]
async fn profile_backfill_feeds_dispatch_weight_identical_to_pre_upgrade() {
    // 轻包门槛置 0：本测试聚焦权重连续性，种子峰值是任意小值；
    // 门槛的分组语义由 profiles 模块单测覆盖。
    let (app, _tmp) = setup_app_with_config(
        4,
        ServerConfig {
            resource_profile_min_peak_rss_kb: 0,
            ..Default::default()
        },
    )
    .await;
    let store = &app.state_store;

    // builds 历史种子（写入序 = 新→旧，不触在线学习面——occupied 行会被
    // 回填跳过）；峰值经裸 SQL 落列。
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

    // 回填前先查一次：缓存写入"无画像"未知值；回填播种后必须整体清除，
    // 否则 TTL 内调度仍读旧值（启动顺序不变量：回填完成 → 调度器首 tick）。
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

    // 幂等：标记置位后二次执行短路（重跑不重算）。
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

/// steering 归一化评分（压测轮 3 修正）：绝对余量大的高占用大节点不再赢过
/// 比例更空的小节点——heavy 落比例最空的节点。w1（10M 节点 60% 满，绝对
/// 余量 3M、比例分 0.3）排序在前；w2（1M 节点 10% 满，绝对余量 0.8M、比例
/// 分 0.8）。旧绝对口径必选 w1，归一化选 w2；硬下限与水位门两节点都过，
/// 落点差异纯由评分序决定。
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

// ===== 单 worker 单 tick refill 上限 =====

/// 深候选流下一 tick 只派 `max(2, capacity/8)` 个（capacity 40 → 5）：预算按
/// 候选序（优先级在前）消耗、不分优先级配额；预算按 tick 重置，下一 tick
/// 续派剩余候选。censored 等待钟与归因不受超限跳过影响（非拒绝语义）。
#[tokio::test]
async fn planner_refill_cap_bounds_new_assignments_per_worker_per_tick() {
    let (app, _tmp) = setup_app(4).await;
    seed_worker(&app.state_store, "w1", "x86_64", 40).await;
    let mut critical = Vec::new();
    let mut plain = Vec::new();
    // 7 个 critical > 预算 5：超限 critical 必须留队列，且下一 tick 仍先于
    // plain 续派（预算按候选序消耗、不分优先级配额的回归锚）。
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

    // 预算按 tick 重置：第二 tick 先续派剩余 2 个 critical，再按序补 3 个
    // plain（同轮预算内候选序连续消耗）。
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

    // 第三 tick：剩余 plain 续派。
    assert!(planner::run_tick(&app).await.unwrap());
    let map = assignment_map(&app.state_store).await;
    assert_eq!(map.len(), 12);
    for id in &plain {
        assert_eq!(build_phase(&app.state_store, *id).await, "assigned");
    }
}

/// 上限按 worker 独立计且不跨节点摊派：预算用尽的 worker 之后，同 tick 内
/// 候选留队列（与放置序"不暗中换节点"同口径），下一 tick 由排序把空载
/// worker 排前、按其自身容量预算续派。
#[tokio::test]
async fn planner_refill_cap_is_per_worker_and_does_not_spill_within_tick() {
    let (app, _tmp) = setup_app(4).await;
    // w1 先种（id 小、util 并列排前）：cap 40 → 上限 5；w2 cap 16 → 上限 2。
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

    // 下一 tick：w2 空载排前，按自身预算派 2。
    assert!(planner::run_tick(&app).await.unwrap());
    let map = assignment_map(&app.state_store).await;
    assert_eq!(map.len(), 7);
    assert_eq!(
        map.values().filter(|w| **w == w2).count(),
        2,
        "w2 budget = max(2, 16/8)"
    );
}
