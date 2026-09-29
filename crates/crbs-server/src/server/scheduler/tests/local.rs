// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! hub 本地构建：槽位、本地水位/硬下限门、取消语义与伪 worker 遥测。

use super::common::*;
use super::*;

fn default_wm() -> AdmitWatermarks {
    AdmitWatermarks::from_config(&crbs_core::config::ServerConfig::default())
}

#[tokio::test]
async fn local_build_fills_slots_in_one_pass() {
    let (app, tmp) = setup_app(3).await;
    let mut ids = Vec::new();
    for (i, pkg) in ["pkg", "pkg2", "pkg3"].into_iter().enumerate() {
        let id = seed_pending_build(&app.state_store, pkg, Some(""), 0).await;
        let srpm_path = tmp.path().join(format!("fake{}.src.rpm", i));
        tokio::fs::write(&srpm_path, b"fake srpm").await.unwrap();
        let request_json = serde_json::to_string(&BuildOptions::default()).unwrap();
        app.state_store
            .set_build_request_info(id, srpm_path.to_str().unwrap(), &request_json)
            .await
            .unwrap();
        ids.push(id);
    }

    let cancel = CancellationToken::new();
    let built = try_local_build(&app, &cancel).await.unwrap();
    assert!(built);

    tokio::time::sleep(Duration::from_millis(300)).await;
    for id in ids {
        let phase = build_phase(&app.state_store, id).await;
        assert_ne!(
            phase, "pending",
            "build {id} should leave pending in one pass"
        );
    }
}

#[tokio::test]
async fn local_build_returns_false_when_concurrency_full() {
    let (app, _tmp) = setup_app(1).await;

    seed_building_build(&app.state_store, "pkg", 0).await;
    seed_pending_build(&app.state_store, "pkg2", Some(""), 0).await;

    let cancel = CancellationToken::new();
    let built = try_local_build(&app, &cancel).await.unwrap();
    assert!(!built, "should not build when concurrency is full");
}

#[tokio::test]
async fn local_build_returns_false_when_assigned_occupies_slot() {
    let (app, _tmp) = setup_app(1).await;

    seed_assigned_build(&app.state_store, "pkg", 0).await;
    seed_pending_build(&app.state_store, "pkg2", Some(""), 0).await;

    let cancel = CancellationToken::new();
    let built = try_local_build(&app, &cancel).await.unwrap();
    assert!(!built, "assigned build should occupy concurrency slot");
}

#[tokio::test]
async fn local_build_returns_false_when_no_pending() {
    let (app, _tmp) = setup_app(4).await;
    let cancel = CancellationToken::new();
    let built = try_local_build(&app, &cancel).await.unwrap();
    assert!(!built, "should not build when nothing pending");
}

#[tokio::test]
async fn local_build_anti_starvation_fallback_for_high_priority() {
    let (app, tmp) = setup_app(4).await;

    for pkg in ["pkg", "pkg2", "pkg3"] {
        seed_building_build(&app.state_store, pkg, 2).await;
    }
    let high_prio_build = seed_pending_build(&app.state_store, "pkg4", Some(""), 2).await;

    let srpm_path = tmp.path().join("fake.src.rpm");
    tokio::fs::write(&srpm_path, b"fake srpm").await.unwrap();

    let request_json = serde_json::to_string(&BuildOptions::default()).unwrap();
    app.state_store
        .set_build_request_info(high_prio_build, srpm_path.to_str().unwrap(), &request_json)
        .await
        .unwrap();

    let cancel = CancellationToken::new();
    let built = try_local_build(&app, &cancel).await.unwrap();

    assert!(
        built,
        "anti-starvation fallback should dispatch high-priority build"
    );

    tokio::time::sleep(Duration::from_millis(300)).await;
    let phase = build_phase(&app.state_store, high_prio_build).await;
    assert_ne!(
        phase, "pending",
        "build should have transitioned out of pending (got {phase})"
    );
}

#[tokio::test]
async fn concurrent_local_builds_pick_distinct_builds() {
    let (app, tmp) = setup_app(2).await;
    let build1 = seed_pending_build(&app.state_store, "pkg", Some(""), 0).await;
    let build2 = seed_pending_build(&app.state_store, "pkg2", Some(""), 0).await;

    let srpm1 = tmp.path().join("fake1.src.rpm");
    let srpm2 = tmp.path().join("fake2.src.rpm");
    tokio::fs::write(&srpm1, b"fake srpm").await.unwrap();
    tokio::fs::write(&srpm2, b"fake srpm").await.unwrap();

    let request_json = serde_json::to_string(&BuildOptions::default()).unwrap();
    app.state_store
        .set_build_request_info(build1, srpm1.to_str().unwrap(), &request_json)
        .await
        .unwrap();
    app.state_store
        .set_build_request_info(build2, srpm2.to_str().unwrap(), &request_json)
        .await
        .unwrap();

    let cancel = CancellationToken::new();
    let built1 = try_local_build(&app, &cancel);
    let built2 = try_local_build(&app, &cancel);
    let (r1, r2) = tokio::join!(built1, built2);

    let started = r1.unwrap() || r2.unwrap();
    assert!(started, "at least one concurrent call should start builds");

    let phase1 = build_phase(&app.state_store, build1).await;
    let phase2 = build_phase(&app.state_store, build2).await;
    assert_ne!(phase1, "pending", "build1 should be picked");
    assert_ne!(phase2, "pending", "build2 should be picked");
}

#[test]
fn parse_proc_telemetry_fields() {
    assert_eq!(parse_proc_load1("0.52 0.58 0.59 1/367 12345\n"), Some(0.52));
    assert_eq!(parse_proc_load1("garbage 0.58"), None);

    let meminfo = "MemTotal:       16000000 kB\nMemFree:  1234567 kB\nMemAvailable: 8000000 kB\n";
    assert_eq!(parse_proc_mem_used_pct(meminfo), Some(50.0));
    assert_eq!(parse_proc_mem_total_kb(meminfo), Some(16_000_000));

    let old_kernel = "MemTotal: 16000000 kB\nMemFree: 1234567 kB\n";
    assert_eq!(parse_proc_mem_used_pct(old_kernel), None);
    assert_eq!(parse_proc_mem_total_kb("MemFree: 1 kB\n"), None);

    assert_eq!(
        parse_proc_mem_used_pct("MemTotal: 0 kB\nMemAvailable: 0 kB\n"),
        None
    );
    assert_eq!(parse_proc_mem_used_pct(""), None);
}

#[tokio::test]
async fn sample_hub_telemetry_reads_injected_proc_dir() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("loadavg"), "0.52 0.58 0.59 1/367 12345\n")
        .await
        .unwrap();
    tokio::fs::write(
        tmp.path().join("meminfo"),
        "MemTotal:       16000000 kB\nMemAvailable:    8000000 kB\n",
    )
    .await
    .unwrap();
    let t = sample_hub_load_telemetry(tmp.path())
        .await
        .expect("fixture proc parses");
    assert_eq!(t.load1, 0.52);
    assert_eq!(t.mem_used_pct, 50.0);
    assert_eq!(t.mem_total_kb, 16_000_000);
    assert!(t.ncpu > 0);

    assert!(
        sample_hub_load_telemetry(Path::new("/nonexistent-proc-for-tests"))
            .await
            .is_none(),
        "missing /proc must degrade to None, never error"
    );
}

#[test]
fn hub_pseudo_worker_feeds_watermark_gate() {
    let t = HubLoadTelemetry {
        load1: 0.0,
        ncpu: 8,
        mem_used_pct: 50.0,
        mem_total_kb: 1_000_000,
    };
    let w = hub_pseudo_worker(Some(t), "x86_64", 4).expect("telemetry present");
    assert_eq!(w.arch, "x86_64");
    assert_eq!(w.capacity, 4);

    let heavy = PackageResourceWeight {
        peak_rss_kb: Some(600_000.0),
        cpu_p90_cores: Some(0.0),
        cpu_sample_ncpu: None,
    };
    let light = PackageResourceWeight {
        peak_rss_kb: Some(100_000.0),
        cpu_p90_cores: Some(0.0),
        cpu_sample_ncpu: None,
    };
    assert_eq!(
        watermark_reject_dimension(
            &w,
            CommittedLoad::default().plus(&heavy, None),
            default_wm()
        ),
        Some(WatermarkDimension::Mem)
    );
    assert_eq!(
        watermark_reject_dimension(
            &w,
            CommittedLoad::default().plus(&light, None),
            default_wm()
        ),
        None
    );

    let t_cpu = HubLoadTelemetry {
        load1: 7.9,
        ncpu: 8,
        mem_used_pct: 0.0,
        mem_total_kb: 1_000_000,
    };
    let w_cpu = hub_pseudo_worker(Some(t_cpu), "x86_64", 4).unwrap();
    let cpu_heavy = PackageResourceWeight {
        peak_rss_kb: Some(0.0),
        cpu_p90_cores: Some(0.2),
        cpu_sample_ncpu: None,
    };
    assert_eq!(
        watermark_reject_dimension(
            &w_cpu,
            CommittedLoad::default().plus(&cpu_heavy, None),
            default_wm()
        ),
        Some(WatermarkDimension::Cpu)
    );

    assert!(
        hub_pseudo_worker(None, "x86_64", 4).is_none(),
        "missing telemetry must fail open"
    );
}

#[tokio::test]
async fn local_watermark_gate_blocks_head_and_records_attribution() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app = Arc::new(AppState::for_test(
        store,
        ServerConfig {
            max_local_builds: 1,
            min_free_disk_gb: 0,
            low_priority_reserve_ratio: 0.25,
            resource_local_watermark_enabled: true,
            ..Default::default()
        },
        tmp.path().to_path_buf(),
    ));
    seed_succeeded_resource_builds(&app.state_store, "test", "heavy", 1_000_000_000_000, 0.0, 1)
        .await;

    let heavy = seed_pending_build(
        &app.state_store,
        "heavy",
        Some("x86_64"),
        crbs_core::types::PRIORITY_CRITICAL,
    )
    .await;

    let cancel = CancellationToken::new();
    let built = try_local_build(&app, &cancel).await.unwrap();
    assert!(
        !built,
        "watermark gate must hold the local pickup this tick"
    );
    assert_eq!(build_phase(&app.state_store, heavy).await, "pending");
    let attribution = app
        .dispatch_attribution
        .get(heavy)
        .expect("local reject must land in the L3 attribution map");
    assert_eq!(
        attribution.reason,
        planner::RejectReason::WatermarkBlocked {
            dimension: WatermarkDimension::Mem
        }
    );
    assert!(attribution.first_watermark_reject_at.is_some());
    assert!(
        app.metrics.dispatch_admit_rejects_total(
            crate::server::metrics::DispatchRejectDimension::WatermarkMem
        ) >= 1,
        "watermark_mem reject must be counted"
    );
}

#[tokio::test]
async fn local_watermark_gate_disabled_keeps_legacy_local_pickup() {
    let (app, tmp) = setup_app(1).await;
    seed_succeeded_resource_builds(&app.state_store, "test", "heavy", 1_000_000_000_000, 0.0, 1)
        .await;
    let heavy = seed_pending_build(
        &app.state_store,
        "heavy",
        Some(""),
        crbs_core::types::PRIORITY_CRITICAL,
    )
    .await;

    let srpm = tmp.path().join("heavy.src.rpm");
    tokio::fs::write(&srpm, b"fake srpm").await.unwrap();
    let request_json = serde_json::to_string(&BuildOptions::default()).unwrap();
    app.state_store
        .set_build_request_info(heavy, srpm.to_str().unwrap(), &request_json)
        .await
        .unwrap();

    let cancel = CancellationToken::new();
    assert!(
        try_local_build(&app, &cancel).await.unwrap(),
        "gate off must keep the legacy local pickup for a heavy head"
    );
    assert_ne!(
        build_phase(&app.state_store, heavy).await,
        "pending",
        "heavy head must leave pending without the gate"
    );
}

#[tokio::test]
async fn local_watermark_gate_does_not_block_remote_dispatch() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app = Arc::new(AppState::for_test(
        store,
        ServerConfig {
            max_local_builds: 1,
            min_free_disk_gb: 0,
            low_priority_reserve_ratio: 0.25,
            resource_local_watermark_enabled: true,
            ..Default::default()
        },
        tmp.path().to_path_buf(),
    ));
    seed_succeeded_resource_builds(&app.state_store, "test", "heavy", 1_000_000_000_000, 0.0, 1)
        .await;

    let heavy = seed_pending_build(
        &app.state_store,
        "heavy",
        Some("x86_64"),
        crbs_core::types::PRIORITY_CRITICAL,
    )
    .await;
    let light = seed_pending_build(&app.state_store, "light", Some("x86_64"), 0).await;
    let worker_id = seed_worker(&app.state_store, "w1", "x86_64", 2).await;
    seed_worker_telemetry(&app.state_store, worker_id, 0.0, 2, 50.0, 1_000_000).await;

    assert!(
        planner::run_tick(&app).await.unwrap(),
        "remote dispatch must be unaffected by the local gate"
    );
    assert_eq!(build_phase(&app.state_store, light).await, "assigned");
    assert_eq!(
        assignment_map(&app.state_store).await.get(&light),
        Some(&worker_id)
    );

    let cancel = CancellationToken::new();
    assert!(
        !try_local_build(&app, &cancel).await.unwrap(),
        "local pickup stays held by the watermark gate"
    );
    assert_eq!(build_phase(&app.state_store, heavy).await, "pending");
}

#[tokio::test]
async fn local_hard_req_gate_skips_blocked_head_to_next_candidate() {
    let (app, tmp) = setup_app_with_config(
        2,
        ServerConfig {
            resource_requirements_enabled: true,
            ..Default::default()
        },
    )
    .await;

    let blocked = seed_pending_build(
        &app.state_store,
        "blocked",
        Some("x86_64"),
        crbs_core::types::PRIORITY_CRITICAL,
    )
    .await;
    sqlx::query("UPDATE builds SET req_min_disk_kb = ? WHERE id = ?")
        .bind(1024 * 1024)
        .bind(blocked)
        .execute(app.state_store.pool())
        .await
        .unwrap();
    let light = seed_pending_build(&app.state_store, "light", Some("x86_64"), 0).await;

    let srpm = tmp.path().join("light.src.rpm");
    tokio::fs::write(&srpm, b"fake srpm").await.unwrap();
    let request_json = serde_json::to_string(&BuildOptions::default()).unwrap();
    app.state_store
        .set_build_request_info(light, srpm.to_str().unwrap(), &request_json)
        .await
        .unwrap();

    let cancel = CancellationToken::new();
    assert!(
        try_local_build(&app, &cancel).await.unwrap(),
        "the candidate after a blocked head must still start"
    );
    assert_eq!(
        build_phase(&app.state_store, blocked).await,
        "pending",
        "hard-floor gate must hold the declared head"
    );
    let attribution = app
        .dispatch_attribution
        .get(blocked)
        .expect("blocked candidate must carry L3 attribution");
    assert_eq!(
        attribution.reason,
        planner::RejectReason::NoFitHardReq {
            dimension: planner::HardReqDimension::Disk
        }
    );

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_ne!(
        build_phase(&app.state_store, light).await,
        "pending",
        "light candidate must leave pending on the same pass"
    );
}

#[tokio::test]
async fn local_hard_req_gate_holds_background_build_without_exemption() {
    let (app, _tmp) = setup_app_with_config(
        1,
        ServerConfig {
            resource_requirements_enabled: true,
            ..Default::default()
        },
    )
    .await;
    let background = seed_pending_build(
        &app.state_store,
        "bg",
        Some("x86_64"),
        crbs_core::types::PRIORITY_BACKGROUND,
    )
    .await;
    sqlx::query("UPDATE builds SET req_min_disk_kb = ? WHERE id = ?")
        .bind(1024 * 1024)
        .bind(background)
        .execute(app.state_store.pool())
        .await
        .unwrap();

    let cancel = CancellationToken::new();
    assert!(
        !try_local_build(&app, &cancel).await.unwrap(),
        "background build must not bypass the hard-floor gate"
    );
    assert_eq!(build_phase(&app.state_store, background).await, "pending");
    assert_eq!(
        app.dispatch_attribution
            .get(background)
            .expect("background reject must carry L3 attribution")
            .reason,
        planner::RejectReason::NoFitHardReq {
            dimension: planner::HardReqDimension::Disk
        }
    );
}

#[tokio::test]
async fn local_dispatch_clears_prior_reject_attribution() {
    let (app, tmp) = setup_app(1).await;
    let id = seed_pending_build(&app.state_store, "pkg", Some(""), 0).await;
    let srpm = tmp.path().join("pkg.src.rpm");
    tokio::fs::write(&srpm, b"fake srpm").await.unwrap();
    let request_json = serde_json::to_string(&BuildOptions::default()).unwrap();
    app.state_store
        .set_build_request_info(id, srpm.to_str().unwrap(), &request_json)
        .await
        .unwrap();
    app.dispatch_attribution.record_water_reject(
        id,
        WatermarkDimension::Mem,
        CommittedLoad::default(),
    );
    assert!(app
        .dispatch_attribution
        .get(id)
        .unwrap()
        .first_watermark_reject_at
        .is_some());

    let cancel = CancellationToken::new();
    assert!(try_local_build(&app, &cancel).await.unwrap());
    assert!(
        app.dispatch_attribution.get(id).is_none(),
        "locally dispatched build must leave the attribution map"
    );
}

#[tokio::test]
async fn local_only_mode_skips_distributed_dispatch() {
    let (app, _tmp) = setup_app_with_mode(4, SchedulerMode::LocalOnly).await;
    let task_id = crate::test_support::seed_task(&app.state_store, "test", "pkg").await;
    let build_id = app
        .state_store
        .insert_build(BuildInsert {
            product: "test",
            pkg_name: "pkg",
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
    seed_worker(&app.state_store, "w1", "x86_64", 2).await;

    assert_eq!(app.server_config.scheduler_mode, SchedulerMode::LocalOnly);

    let cancel = CancellationToken::new();
    let app_clone = app.clone();
    let loop_cancel = cancel.clone();
    let handle = tokio::spawn(async move {
        run_scheduler_loop(app_clone, loop_cancel).await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    cancel.cancel();
    let _ = handle.await;

    let phase = build_phase(&app.state_store, build_id).await;
    assert_eq!(
        phase, "pending",
        "LocalOnly mode should not dispatch to worker"
    );
}

#[tokio::test]
async fn local_build_stops_draining_once_cancelled() {
    let (app, tmp) = setup_app(4).await;
    let mut ids = Vec::new();
    for (i, pkg) in ["pkg", "pkg2"].into_iter().enumerate() {
        let id = seed_pending_build(&app.state_store, pkg, Some(""), 0).await;
        let srpm_path = tmp.path().join(format!("fake{}.src.rpm", i));
        tokio::fs::write(&srpm_path, b"fake srpm").await.unwrap();
        let request_json = serde_json::to_string(&BuildOptions::default()).unwrap();
        app.state_store
            .set_build_request_info(id, srpm_path.to_str().unwrap(), &request_json)
            .await
            .unwrap();
        ids.push(id);
    }

    let cancel = CancellationToken::new();
    cancel.cancel();
    let built = try_local_build(&app, &cancel).await.unwrap();
    assert!(!built, "cancelled scheduler must not start new builds");
    for id in ids {
        assert_eq!(
            build_phase(&app.state_store, id).await,
            "pending",
            "cancelled scheduler must leave pending queue untouched"
        );
    }
}

#[tokio::test]
async fn local_build_acquire_contends_with_cancel() {
    let (app, tmp) = setup_app(1).await;

    let _held = app.build_semaphore.clone().acquire_owned().await.unwrap();

    let id = seed_pending_build(&app.state_store, "pkg", Some(""), 0).await;
    let srpm_path = tmp.path().join("fake.src.rpm");
    tokio::fs::write(&srpm_path, b"fake srpm").await.unwrap();
    let request_json = serde_json::to_string(&BuildOptions::default()).unwrap();
    app.state_store
        .set_build_request_info(id, srpm_path.to_str().unwrap(), &request_json)
        .await
        .unwrap();

    let cancel = CancellationToken::new();
    let app_for_task = app.clone();
    let cancel_for_task = cancel.clone();
    let task = tokio::spawn(async move { try_local_build(&app_for_task, &cancel_for_task).await });

    tokio::time::sleep(Duration::from_millis(50)).await;
    cancel.cancel();

    let built = tokio::time::timeout(Duration::from_millis(500), task)
        .await
        .expect("try_local_build must return promptly once cancelled")
        .expect("task join")
        .unwrap();
    assert!(!built);
    assert_eq!(build_phase(&app.state_store, id).await, "pending");
}
