// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use crbs_core::{DispatchCandidate, WorkerStatus};

use super::super::{AdmitWatermarks, CommittedLoad, ResolvedResourceProfile, WatermarkDimension};
use super::attribution::ATTRIBUTION_CAPACITY;
use super::decide::{
    candidate_arch_matches, fallback_expired, normalized_headroom_score, steering_order,
};
use super::*;

fn candidate(arch: Option<&str>, host_arches: Option<&str>, product: &str) -> DispatchCandidate {
    DispatchCandidate {
        id: 1,
        task_id: None,
        product: product.to_string(),
        pkg_name: "pkg".to_string(),
        source_name: "pkg".to_string(),
        arch: arch.map(str::to_string),
        host_arches: host_arches.map(str::to_string),
        priority: 0,
        created_at: None,
        started_at: None,
        req_min_mem_kb: None,
        req_min_ncpu: None,
        req_min_disk_kb: None,
        srpm_size_bytes: None,
    }
}

fn worker(id: i64, arch: &str, capacity: i64) -> WorkerStatus {
    WorkerStatus {
        id,
        name: format!("w{id}"),
        arch: arch.to_string(),
        capacity,
        status: "online".into(),
        last_heartbeat: None,
        version: "test".into(),
        has_secret: false,
        load1: None,
        ncpu: None,
        cpu_util_pct: None,
        mem_used_pct: None,
        mem_total_kb: None,
        disk_free_kb: None,
        resource_caps: None,
        created_at: None,
        secret_expires_at: None,
    }
}

fn with_telemetry(
    mut w: WorkerStatus,
    load1: f64,
    ncpu: i64,
    used_pct: f64,
    total_kb: i64,
) -> WorkerStatus {
    w.load1 = Some(load1);
    w.ncpu = Some(ncpu);
    w.mem_used_pct = Some(used_pct);
    w.mem_total_kb = Some(total_kb);
    w
}

fn with_disk_free(mut w: WorkerStatus, free_kb: i64) -> WorkerStatus {
    w.disk_free_kb = Some(free_kb);
    w
}

fn default_wm() -> AdmitWatermarks {
    AdmitWatermarks::from_config(&crbs_core::config::ServerConfig::default())
}

fn base_input<'a>(
    c: &'a DispatchCandidate,
    profile: ResolvedResourceProfile,
    workers: &'a [WorkerStatus],
) -> DecideCandidateInput<'a> {
    static EMPTY_ACTIVE: std::sync::LazyLock<HashMap<i64, i64>> =
        std::sync::LazyLock::new(HashMap::new);
    static EMPTY_COMMITTED: std::sync::LazyLock<HashMap<i64, CommittedLoad>> =
        std::sync::LazyLock::new(HashMap::new);
    static EMPTY_INIT: std::sync::LazyLock<HashMap<i64, HashSet<String>>> =
        std::sync::LazyLock::new(HashMap::new);
    DecideCandidateInput {
        candidate: c,
        profile,
        hard_req: EffectiveHardReq::default(),
        workers,
        active: &EMPTY_ACTIVE,
        committed: &EMPTY_COMMITTED,
        init_by_worker: &EMPTY_INIT,
        first_watermark_reject_age: None,
        steer_heavy: false,
        watermark_enabled: true,
        watermarks: default_wm(),
        tmpfs_gate_enforced: false,
    }
}

#[test]
fn hard_req_matrix_fails_closed_on_missing_telemetry() {
    let mut w = with_telemetry(worker(1, "x86_64", 2), 0.0, 8, 10.0, 32 * 1024 * 1024);
    w = with_disk_free(w, 100 * 1024 * 1024);

    let req = EffectiveHardReq {
        min_mem_kb: Some(16 * 1024 * 1024),
        min_ncpu: Some(8),
        min_disk_kb: Some(64 * 1024 * 1024),
    };
    assert_eq!(worker_satisfies_hard_req(&w, &req), None);

    let req_mem = EffectiveHardReq {
        min_mem_kb: Some(33 * 1024 * 1024),
        ..Default::default()
    };
    assert_eq!(
        worker_satisfies_hard_req(&w, &req_mem),
        Some(HardReqDimension::Mem)
    );
    let req_ncpu = EffectiveHardReq {
        min_ncpu: Some(9),
        ..Default::default()
    };
    assert_eq!(
        worker_satisfies_hard_req(&w, &req_ncpu),
        Some(HardReqDimension::Ncpu)
    );
    let req_disk = EffectiveHardReq {
        min_disk_kb: Some(101 * 1024 * 1024),
        ..Default::default()
    };
    assert_eq!(
        worker_satisfies_hard_req(&w, &req_disk),
        Some(HardReqDimension::Disk)
    );

    let no_disk = with_telemetry(worker(1, "x86_64", 2), 0.0, 8, 10.0, 32 * 1024 * 1024);
    assert_eq!(
        worker_satisfies_hard_req(&no_disk, &req_disk),
        Some(HardReqDimension::Disk)
    );
    let no_mem = with_disk_free(worker(1, "x86_64", 2), 1024);
    let req_mem_only = EffectiveHardReq {
        min_mem_kb: Some(1024),
        ..Default::default()
    };
    assert_eq!(
        worker_satisfies_hard_req(&no_mem, &req_mem_only),
        Some(HardReqDimension::Mem)
    );

    let all = EffectiveHardReq {
        min_mem_kb: Some(33 * 1024 * 1024),
        min_ncpu: Some(9),
        min_disk_kb: Some(101 * 1024 * 1024),
    };
    assert_eq!(
        worker_satisfies_hard_req(&w, &all),
        Some(HardReqDimension::Mem)
    );
}

#[test]
fn decide_hard_req_skips_underprovisioned_and_reports_dimension() {
    let workers = vec![
        with_telemetry(worker(1, "x86_64", 2), 0.0, 8, 0.0, 8 * 1024 * 1024),
        with_telemetry(worker(2, "x86_64", 2), 0.0, 8, 0.0, 32 * 1024 * 1024),
    ];
    let c = candidate(Some("x86_64"), None, "test");
    let req = EffectiveHardReq {
        min_mem_kb: Some(16 * 1024 * 1024),
        ..Default::default()
    };
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            hard_req: req,
            ..base_input(&c, weight(0.0, 0.0), &workers)
        }),
        PlannerDecision::Dispatch { worker_id: 2 }
    );

    let req_all = EffectiveHardReq {
        min_mem_kb: Some(64 * 1024 * 1024),
        ..Default::default()
    };
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            hard_req: req_all,
            ..base_input(&c, weight(0.0, 0.0), &workers)
        }),
        PlannerDecision::NoFit {
            reason: RejectReason::NoFitHardReq {
                dimension: HardReqDimension::Mem
            }
        }
    );

    let old_workers = vec![with_telemetry(
        worker(1, "x86_64", 2),
        0.0,
        8,
        0.0,
        32 * 1024 * 1024,
    )];
    let req_disk = EffectiveHardReq {
        min_disk_kb: Some(1024),
        ..Default::default()
    };
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            hard_req: req_disk,
            ..base_input(&c, weight(0.0, 0.0), &old_workers)
        }),
        PlannerDecision::NoFit {
            reason: RejectReason::NoFitHardReq {
                dimension: HardReqDimension::Disk
            }
        }
    );
}

fn weight(rss_kb: f64, cpu: f64) -> ResolvedResourceProfile {
    ResolvedResourceProfile {
        weight: super::super::PackageResourceWeight {
            peak_rss_kb: Some(rss_kb),
            cpu_p90_cores: Some(cpu),
            cpu_sample_ncpu: None,
        },
        censored: false,
        ..ResolvedResourceProfile::default()
    }
}

fn weight_only(rss_kb: f64) -> super::super::PackageResourceWeight {
    super::super::PackageResourceWeight {
        peak_rss_kb: Some(rss_kb),
        cpu_p90_cores: None,
        cpu_sample_ncpu: None,
    }
}

fn expect_watermark_blocked(
    d: PlannerDecision,
    dimension: crate::server::scheduler::WatermarkDimension,
    mem_kb: f64,
    cpu_cores: f64,
) {
    match d {
        PlannerDecision::WatermarkBlocked {
            dimension: got_dim,
            head_load,
        } => {
            assert_eq!(got_dim, dimension);
            assert!(
                (head_load.mem_kb - mem_kb).abs() < 1e-6,
                "mem_kb {head_load:?} != {mem_kb}"
            );
            assert!(
                (head_load.cpu_cores - cpu_cores).abs() < 1e-6,
                "cpu_cores {head_load:?} != {cpu_cores}"
            );
        }
        other => panic!("expected WatermarkBlocked({dimension:?}), got {other:?}"),
    }
}

#[test]
fn is_heavy_candidate_three_arms_and_boundaries() {
    let no_req = EffectiveHardReq::default();
    let with_req = EffectiveHardReq {
        min_disk_kb: Some(1024),
        ..Default::default()
    };

    assert!(is_heavy_candidate(&with_req, &weight_only(0.0), None, 0));

    let threshold = HEAVY_EFFECTIVE_WEIGHT_MEM_KB as f64;
    assert!(is_heavy_candidate(
        &no_req,
        &weight_only(threshold),
        None,
        0
    ));
    assert!(!is_heavy_candidate(
        &no_req,
        &weight_only(threshold - 1.0),
        None,
        0
    ));

    assert!(!is_heavy_candidate(
        &no_req,
        &super::super::PackageResourceWeight::default(),
        None,
        0
    ));

    let limit = 104_857_600;
    assert!(is_heavy_candidate(
        &no_req,
        &weight_only(0.0),
        Some(limit),
        limit
    ));
    assert!(!is_heavy_candidate(
        &no_req,
        &weight_only(0.0),
        Some(limit - 1),
        limit
    ));
    assert!(!is_heavy_candidate(
        &no_req,
        &weight_only(0.0),
        Some(limit),
        0
    ));
}

#[test]
fn decide_steering_picks_headroom_head_only_for_heavy() {
    let c = candidate(Some("x86_64"), None, "test");

    let mid = weight(600_000.0, 0.0);
    let workers = vec![
        with_telemetry(worker(1, "x86_64", 2), 0.0, 8, 55.0, 2_000_000),
        with_telemetry(worker(2, "x86_64", 2), 0.0, 8, 10.0, 2_000_000),
    ];
    let active: HashMap<i64, i64> = [(2i64, 1i64)].into_iter().collect();

    assert_eq!(
        decide_candidate(DecideCandidateInput {
            steer_heavy: true,
            active: &active,
            ..base_input(&c, mid, &workers)
        }),
        PlannerDecision::Dispatch { worker_id: 2 },
        "heavy candidate must land on the max-headroom worker when it admits"
    );

    assert_eq!(
        decide_candidate(DecideCandidateInput {
            active: &active,
            ..base_input(&c, mid, &workers)
        }),
        PlannerDecision::Dispatch { worker_id: 1 },
        "steering off keeps the order-head placement when the head admits"
    );

    let heavy = weight(1_500_000.0, 0.0);
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            active: &active,
            ..base_input(&c, heavy, &workers)
        }),
        PlannerDecision::Dispatch { worker_id: 2 },
        "blocked order head must fall over to the next feasible worker"
    );

    let twins = vec![
        with_telemetry(worker(1, "x86_64", 2), 0.0, 8, 10.0, 2_000_000),
        with_telemetry(worker(2, "x86_64", 2), 0.0, 8, 10.0, 2_000_000),
    ];
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            steer_heavy: true,
            ..base_input(&c, heavy, &twins)
        }),
        PlannerDecision::Dispatch { worker_id: 1 }
    );
}

#[test]
fn decide_steering_prefers_telemetried_workers_and_degrades_to_order_head() {
    let c = candidate(Some("x86_64"), None, "test");
    let heavy = weight(1_500_000.0, 0.0);

    let mixed = vec![
        worker(1, "x86_64", 2),
        with_telemetry(worker(2, "x86_64", 2), 0.0, 8, 10.0, 2_000_000),
    ];
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            steer_heavy: true,
            ..base_input(&c, heavy, &mixed)
        }),
        PlannerDecision::Dispatch { worker_id: 2 },
        "heavy must prefer the telemetried worker over the nominal +∞ untelemetried one"
    );

    let mut partial = worker(1, "x86_64", 2);
    partial.mem_total_kb = Some(2_000_000);
    let mixed_partial = vec![
        partial,
        with_telemetry(worker(2, "x86_64", 2), 0.0, 8, 10.0, 2_000_000),
    ];
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            steer_heavy: true,
            ..base_input(&c, heavy, &mixed_partial)
        }),
        PlannerDecision::Dispatch { worker_id: 2 },
        "total-only mem telemetry must not join the steered group"
    );

    let blind = vec![worker(1, "x86_64", 2), worker(2, "x86_64", 2)];
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            steer_heavy: true,
            ..base_input(&c, heavy, &blind)
        }),
        PlannerDecision::Dispatch { worker_id: 1 },
        "all-untelemetried eligible must degrade to the order head"
    );

    let mut partial1 = worker(1, "x86_64", 2);
    partial1.mem_total_kb = Some(2_000_000);
    let mut partial2 = worker(2, "x86_64", 2);
    partial2.mem_total_kb = Some(4_000_000);
    let all_partial = vec![partial1, partial2];
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            steer_heavy: true,
            ..base_input(&c, heavy, &all_partial)
        }),
        PlannerDecision::Dispatch { worker_id: 1 },
        "all-partial telemetry must degrade to the order head"
    );
}

#[test]
fn candidate_arch_matches_mirrors_pick_predicate() {
    let c = candidate(Some("x86_64"), None, "test");
    assert!(candidate_arch_matches(&c, "x86_64"));
    assert!(!candidate_arch_matches(&c, "aarch64"));

    let unpinned = candidate(Some("noarch"), None, "test");
    assert!(candidate_arch_matches(&unpinned, "x86_64"));
    assert!(candidate_arch_matches(&unpinned, "aarch64"));

    let pinned = candidate(Some("noarch"), Some("x86_64,aarch64"), "test");
    assert!(candidate_arch_matches(&pinned, "aarch64"));
    assert!(!candidate_arch_matches(&pinned, "ppc64le"));

    let null_arch = candidate(None, None, "test");
    assert!(!candidate_arch_matches(&null_arch, "x86_64"));
}

#[test]
fn decide_dispatches_to_least_loaded_first() {
    let workers = vec![worker(2, "x86_64", 2), worker(1, "x86_64", 2)];
    let c = candidate(Some("x86_64"), None, "test");
    let d = decide_candidate(base_input(&c, weight(0.0, 0.0), &workers));
    assert_eq!(
        d,
        PlannerDecision::Dispatch { worker_id: 2 },
        "输入序即派发序（调用方已排序）"
    );
}

#[test]
fn decide_skips_full_worker_to_next() {
    let workers = vec![worker(1, "x86_64", 1), worker(2, "x86_64", 2)];
    let active: HashMap<i64, i64> = [(1i64, 1i64)].into_iter().collect();
    let c = candidate(Some("x86_64"), None, "test");
    let d = decide_candidate(DecideCandidateInput {
        active: &active,
        ..base_input(&c, weight(0.0, 0.0), &workers)
    });
    assert_eq!(d, PlannerDecision::Dispatch { worker_id: 2 });
}

#[test]
fn decide_no_fit_reasons_are_distinguished() {
    let workers = vec![worker(1, "aarch64", 2)];
    let c = candidate(Some("x86_64"), None, "test");
    assert_eq!(
        decide_candidate(base_input(&c, weight(0.0, 0.0), &workers)),
        PlannerDecision::NoFit {
            reason: RejectReason::NoFitArch
        }
    );

    let workers = vec![worker(1, "x86_64", 1)];
    let active: HashMap<i64, i64> = [(1i64, 1i64)].into_iter().collect();
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            active: &active,
            ..base_input(&c, weight(0.0, 0.0), &workers)
        }),
        PlannerDecision::NoFit {
            reason: RejectReason::NoFitCapacity
        }
    );

    let mut init = HashMap::new();
    init.insert(
        1i64,
        ["test".to_string()].into_iter().collect::<HashSet<_>>(),
    );
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            init_by_worker: &init,
            ..base_input(&c, weight(0.0, 0.0), &workers)
        }),
        PlannerDecision::NoFit {
            reason: RejectReason::InitGated
        }
    );

    let mut init = HashMap::new();
    init.insert(
        1i64,
        ["other".to_string()].into_iter().collect::<HashSet<_>>(),
    );
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            init_by_worker: &init,
            ..base_input(&c, weight(0.0, 0.0), &workers)
        }),
        PlannerDecision::Dispatch { worker_id: 1 }
    );
}

#[test]
fn decide_candidate_weight_enters_the_watermark() {
    let workers = vec![with_telemetry(
        worker(1, "x86_64", 2),
        0.0,
        8,
        30.0,
        1_000_000,
    )];
    let c = candidate(Some("x86_64"), None, "test");
    let committed: HashMap<i64, CommittedLoad> = [(
        1i64,
        CommittedLoad {
            mem_kb: 500_000.0,
            cpu_cores: 0.0,
        },
    )]
    .into_iter()
    .collect();

    let fits = decide_candidate(DecideCandidateInput {
        committed: &committed,
        ..base_input(&c, weight(50_000.0, 0.0), &workers)
    });
    assert_eq!(fits, PlannerDecision::Dispatch { worker_id: 1 });

    let spills = decide_candidate(DecideCandidateInput {
        committed: &committed,
        ..base_input(&c, weight(150_000.0, 0.0), &workers)
    });

    expect_watermark_blocked(
        spills,
        crate::server::scheduler::WatermarkDimension::Mem,
        650_000.0,
        0.0,
    );
}

#[test]
fn decide_water_falls_over_to_next_feasible_worker() {
    let workers = vec![
        with_telemetry(worker(1, "x86_64", 2), 0.0, 8, 95.0, 1_000_000),
        with_telemetry(worker(2, "x86_64", 2), 0.0, 8, 10.0, 1_000_000),
    ];
    let active: HashMap<i64, i64> = [(1i64, 0i64), (2, 1)].into_iter().collect();
    let c = candidate(Some("x86_64"), None, "test");
    let d = decide_candidate(DecideCandidateInput {
        active: &active,
        ..base_input(&c, weight(1_000.0, 0.0), &workers)
    });
    assert_eq!(
        d,
        PlannerDecision::Dispatch { worker_id: 2 },
        "head worker over watermark must fall over to the feasible next worker"
    );
}

#[test]
fn decide_reports_cpu_dimension_reject() {
    let workers = vec![with_telemetry(
        worker(1, "x86_64", 2),
        7.9,
        8,
        0.0,
        1_000_000,
    )];
    let c = candidate(Some("x86_64"), None, "test");
    let d = decide_candidate(base_input(&c, weight(0.0, 0.2), &workers));
    expect_watermark_blocked(
        d,
        crate::server::scheduler::WatermarkDimension::Cpu,
        0.0,
        0.2,
    );
}

#[test]
fn decide_cpu_weight_scales_to_target_node_cores() {
    let workers = vec![with_telemetry(
        worker(1, "x86_64", 2),
        0.0,
        16,
        0.0,
        8_000_000,
    )];
    let c = candidate(Some("x86_64"), None, "test");
    let sampled = ResolvedResourceProfile {
        weight: super::super::PackageResourceWeight {
            peak_rss_kb: Some(0.0),
            cpu_p90_cores: Some(40.0),
            cpu_sample_ncpu: Some(64),
        },
        censored: false,
        ..ResolvedResourceProfile::default()
    };
    assert_eq!(
        decide_candidate(base_input(&c, sampled, &workers)),
        PlannerDecision::Dispatch { worker_id: 1 },
        "p90=40 on a 64-core sampler must scale to 10 cores on a 16-core node"
    );

    let legacy = ResolvedResourceProfile {
        weight: super::super::PackageResourceWeight {
            peak_rss_kb: Some(0.0),
            cpu_p90_cores: Some(40.0),
            cpu_sample_ncpu: None,
        },
        censored: false,
        ..ResolvedResourceProfile::default()
    };
    expect_watermark_blocked(
        decide_candidate(base_input(&c, legacy, &workers)),
        crate::server::scheduler::WatermarkDimension::Cpu,
        0.0,
        40.0,
    );

    let dep_bound = ResolvedResourceProfile {
        weight: super::super::PackageResourceWeight {
            peak_rss_kb: Some(0.0),
            cpu_p90_cores: Some(20.0),
            cpu_sample_ncpu: Some(64),
        },
        censored: false,
        ..ResolvedResourceProfile::default()
    };
    let small = vec![with_telemetry(
        worker(1, "x86_64", 2),
        0.0,
        8,
        0.0,
        8_000_000,
    )];
    expect_watermark_blocked(
        decide_candidate(base_input(&c, dep_bound, &small)),
        crate::server::scheduler::WatermarkDimension::Cpu,
        0.0,
        20.0,
    );
}

#[test]
fn decide_watermark_switch_off_skips_gate_only() {
    let workers = vec![with_telemetry(
        worker(1, "x86_64", 2),
        0.0,
        8,
        99.0,
        1_000_000,
    )];
    let c = candidate(Some("x86_64"), None, "test");
    expect_watermark_blocked(
        decide_candidate(base_input(&c, weight(1_000.0, 0.0), &workers)),
        crate::server::scheduler::WatermarkDimension::Mem,
        1_000.0,
        0.0,
    );
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            watermark_enabled: false,
            ..base_input(&c, weight(1_000.0, 0.0), &workers)
        }),
        PlannerDecision::Dispatch { worker_id: 1 },
        "switch off: placement-order target dispatches regardless of the watermark"
    );

    let req = EffectiveHardReq {
        min_mem_kb: Some(2_000_000),
        ..Default::default()
    };
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            watermark_enabled: false,
            hard_req: req,
            ..base_input(&c, weight(0.0, 0.0), &workers)
        }),
        PlannerDecision::NoFit {
            reason: RejectReason::NoFitHardReq {
                dimension: HardReqDimension::Mem
            }
        },
        "hard floors stay enforced with the watermark switch off"
    );
}

#[test]
fn decide_soft_fallback_only_for_censored_past_age() {
    let workers = vec![with_telemetry(
        worker(1, "x86_64", 2),
        0.0,
        8,
        95.0,
        1_000_000,
    )];
    let c = candidate(Some("x86_64"), None, "test");
    let heavy_censored = ResolvedResourceProfile {
        weight: weight(1_000_000.0, 0.0).weight,
        censored: true,
        ..ResolvedResourceProfile::default()
    };
    let not_aged = decide_candidate(DecideCandidateInput {
        first_watermark_reject_age: Some(Duration::from_secs(LAST_RESORT_AFTER_SECS - 1)),
        ..base_input(&c, heavy_censored, &workers)
    });
    expect_watermark_blocked(
        not_aged,
        crate::server::scheduler::WatermarkDimension::Mem,
        1_000_000.0,
        0.0,
    );

    let aged = decide_candidate(DecideCandidateInput {
        first_watermark_reject_age: Some(Duration::from_secs(LAST_RESORT_AFTER_SECS)),
        ..base_input(&c, heavy_censored, &workers)
    });
    assert_eq!(aged, PlannerDecision::SoftFallback { worker_id: 1 });

    let plain = decide_candidate(DecideCandidateInput {
        first_watermark_reject_age: Some(Duration::from_secs(LAST_RESORT_AFTER_SECS)),
        ..base_input(&c, weight(1_000_000.0, 0.0), &workers)
    });
    expect_watermark_blocked(
        plain,
        crate::server::scheduler::WatermarkDimension::Mem,
        1_000_000.0,
        0.0,
    );

    let no_record = decide_candidate(base_input(&c, heavy_censored, &workers));
    expect_watermark_blocked(
        no_record,
        crate::server::scheduler::WatermarkDimension::Mem,
        1_000_000.0,
        0.0,
    );
}

#[test]
fn soft_fallback_targets_max_headroom_worker() {
    let workers = vec![
        with_telemetry(worker(1, "x86_64", 2), 0.0, 8, 80.0, 1_000_000),
        with_telemetry(worker(2, "x86_64", 2), 0.0, 8, 50.0, 2_000_000),
    ];
    let c = candidate(Some("x86_64"), None, "test");
    let heavy_censored = ResolvedResourceProfile {
        weight: weight(1_000_000.0, 0.0).weight,
        censored: true,
        ..ResolvedResourceProfile::default()
    };
    let d = decide_candidate(DecideCandidateInput {
        first_watermark_reject_age: Some(Duration::from_secs(LAST_RESORT_AFTER_SECS)),
        ..base_input(&c, heavy_censored, &workers)
    });
    assert_eq!(d, PlannerDecision::SoftFallback { worker_id: 2 });
}

#[test]
fn soft_fallback_only_fires_when_every_node_rejects() {
    let c = candidate(Some("x86_64"), None, "test");
    let heavy_censored = ResolvedResourceProfile {
        weight: weight(1_000_000.0, 0.0).weight,
        censored: true,
        ..ResolvedResourceProfile::default()
    };

    let with_blind = vec![
        with_telemetry(worker(1, "x86_64", 2), 0.0, 8, 95.0, 1_000_000),
        worker(2, "x86_64", 2),
        with_telemetry(worker(3, "x86_64", 2), 0.0, 8, 10.0, 1_000_000),
    ];
    let d = decide_candidate(DecideCandidateInput {
        first_watermark_reject_age: Some(Duration::from_secs(LAST_RESORT_AFTER_SECS)),
        ..base_input(&c, heavy_censored, &with_blind)
    });
    assert_eq!(
        d,
        PlannerDecision::Dispatch { worker_id: 2 },
        "blind node fail-opens the gate; dispatch precedes the fallback"
    );

    let cpu_blocked = vec![
        with_telemetry(worker(1, "x86_64", 2), 8.0, 8, 0.0, 1_000_000),
        with_telemetry(worker(2, "x86_64", 2), 8.0, 8, 0.0, 1_000_000),
    ];
    let mut blind_mem = cpu_blocked;
    for w in &mut blind_mem {
        w.mem_total_kb = None;
        w.mem_used_pct = None;
    }
    let cpu_censored = ResolvedResourceProfile {
        weight: weight(0.0, 2.0).weight,
        censored: true,
        ..ResolvedResourceProfile::default()
    };
    let d = decide_candidate(DecideCandidateInput {
        first_watermark_reject_age: Some(Duration::from_secs(LAST_RESORT_AFTER_SECS)),
        ..base_input(&c, cpu_censored, &blind_mem)
    });
    assert_eq!(
        d,
        PlannerDecision::SoftFallback { worker_id: 1 },
        "no observable headroom: degrade to the order head"
    );
}

#[test]
fn fallback_expired_requires_full_age() {
    assert!(!fallback_expired(None), "无记录不超龄");
    assert!(!fallback_expired(Some(Duration::from_secs(
        LAST_RESORT_AFTER_SECS - 1
    ))));
    assert!(fallback_expired(Some(Duration::from_secs(
        LAST_RESORT_AFTER_SECS
    ))));
}

#[test]
fn normalized_headroom_score_formula_and_missing_telemetry() {
    let w = with_telemetry(worker(1, "x86_64", 2), 2.0, 8, 30.0, 1_000_000);
    let load = CommittedLoad {
        mem_kb: 100_000.0,
        cpu_cores: 1.0,
    };

    let score = normalized_headroom_score(&w, load, default_wm()).expect("telemetry present");
    assert!((score - 0.5).abs() < 1e-9, "score: {score}");

    let mut cpu_only = worker(2, "x86_64", 2);
    cpu_only.load1 = Some(2.0);
    cpu_only.ncpu = Some(8);
    let score = normalized_headroom_score(&cpu_only, CommittedLoad::default(), default_wm())
        .expect("cpu dim");
    assert!((score - 0.75).abs() < 1e-9, "score: {score}");

    let blind = worker(3, "x86_64", 2);
    assert_eq!(
        normalized_headroom_score(&blind, CommittedLoad::default(), default_wm()),
        None
    );
}

#[test]
fn steering_order_ranks_normalized_score_over_absolute_headroom() {
    let big = with_telemetry(worker(1, "x86_64", 2), 0.0, 8, 60.0, 10_000_000);
    let small = with_telemetry(worker(2, "x86_64", 2), 0.0, 8, 10.0, 1_000_000);
    let eligible = vec![&big, &small];
    let committed: HashMap<i64, CommittedLoad> = HashMap::new();
    let order = steering_order(&eligible, &committed, default_wm());
    assert_eq!(
        order.iter().map(|w| w.id).collect::<Vec<_>>(),
        vec![2, 1],
        "proportionally roomier small node must outrank the fuller big node"
    );

    let blind = worker(3, "x86_64", 2);
    let mixed = vec![&blind, &small, &big];
    let order = steering_order(&mixed, &committed, default_wm());
    assert_eq!(
        order.iter().map(|w| w.id).collect::<Vec<_>>(),
        vec![2, 1, 3]
    );
}

#[test]
fn per_tick_refill_cap_formula() {
    assert_eq!(per_tick_refill_cap(40), 5);
    assert_eq!(per_tick_refill_cap(80), 10);
    assert_eq!(per_tick_refill_cap(24), 3);
    assert_eq!(per_tick_refill_cap(16), 2);
    assert_eq!(per_tick_refill_cap(8), 2);
    assert_eq!(per_tick_refill_cap(2), 2);
    assert_eq!(per_tick_refill_cap(0), 2);
}

#[test]
fn attribution_records_reasons_and_first_watermark_reject() {
    let a = DispatchAttribution::new();
    assert_eq!(a.get(1), None);

    a.record_no_fit(1, RejectReason::NoFitArch);
    let e = a.get(1).unwrap();
    assert_eq!(e.reason, RejectReason::NoFitArch);
    assert!(e.first_watermark_reject_at.is_none(), "no_fit 不设水位首拒");

    a.record_water_reject(
        1,
        WatermarkDimension::Mem,
        CommittedLoad {
            mem_kb: 600_000.0,
            cpu_cores: 2.0,
        },
    );
    let first = a.get(1).unwrap();
    assert_eq!(
        first.reason,
        RejectReason::WatermarkBlocked {
            dimension: WatermarkDimension::Mem
        }
    );
    assert!(first.first_watermark_reject_at.is_some());
    let load = first
        .watermark_effective_load
        .expect("water reject carries the effective load");
    assert!((load.mem_kb - 600_000.0).abs() < 1e-6);
    assert!((load.cpu_cores - 2.0).abs() < 1e-6);

    a.record_water_reject(1, WatermarkDimension::Cpu, CommittedLoad::default());
    assert_eq!(
        a.get(1).unwrap().first_watermark_reject_at,
        first.first_watermark_reject_at
    );

    a.record_no_fit(1, RejectReason::NoFitCapacity);
    let e = a.get(1).unwrap();
    assert_eq!(e.reason, RejectReason::NoFitCapacity);
    assert_eq!(e.first_watermark_reject_at, first.first_watermark_reject_at);

    a.clear(1);
    assert_eq!(a.get(1), None);
}

#[test]
fn attribution_capacity_evicts_oldest_without_resetting_clocks() {
    let a = DispatchAttribution::new();
    a.record_water_reject(1, WatermarkDimension::Mem, CommittedLoad::default());
    let clock = a.get(1).unwrap().first_watermark_reject_at;
    a.record_no_fit(2, RejectReason::NoFitArch);
    for id in 3..=ATTRIBUTION_CAPACITY as i64 {
        a.record_no_fit(id, RejectReason::NoFitArch);
    }
    assert_eq!(a.len(), ATTRIBUTION_CAPACITY);
    a.record_no_fit(999_999, RejectReason::InitGated);
    assert_eq!(a.len(), ATTRIBUTION_CAPACITY, "只淘汰一条，不整表清空");
    assert_eq!(
        a.get(1).unwrap().first_watermark_reject_at,
        clock,
        "带等待钟的条目不被淘汰"
    );
    assert!(a.get(2).is_none(), "最旧无钟条目被淘汰");
    assert_eq!(a.get(999_999).unwrap().reason, RejectReason::InitGated);
}

#[test]
fn attribution_tracks_hard_req_clock_and_one_time_note() {
    let a = DispatchAttribution::new();
    a.record_no_fit(7, RejectReason::NoFitArch);
    assert!(a.get(7).unwrap().first_hard_req_reject_at.is_none());

    a.record_no_fit(
        7,
        RejectReason::NoFitHardReq {
            dimension: HardReqDimension::Mem,
        },
    );
    let first = a.get(7).unwrap().first_hard_req_reject_at;
    assert!(first.is_some());
    a.record_no_fit(
        7,
        RejectReason::NoFitHardReq {
            dimension: HardReqDimension::Ncpu,
        },
    );
    assert_eq!(
        a.get(7).unwrap().first_hard_req_reject_at,
        first,
        "首拒时刻只进不退"
    );

    assert!(a.mark_hard_req_stall_noted(7));
    assert!(!a.mark_hard_req_stall_noted(7), "只提示一次");
    assert!(!a.mark_hard_req_stall_noted(12345), "无条目不置位");

    a.unmark_hard_req_stall_noted(7);
    assert!(a.mark_hard_req_stall_noted(7), "note 写失败回滚后可重试");
    a.unmark_hard_req_stall_noted(12345);
}

fn learned_tmpfs_profile(max_tmpfs_kb: Option<i64>) -> ResolvedResourceProfile {
    ResolvedResourceProfile {
        gate_learned: true,
        gate_max_tmpfs_kb: max_tmpfs_kb,
        ..ResolvedResourceProfile::default()
    }
}

#[test]
fn tmpfs_gate_off_keeps_baseline_dispatch() {
    let workers = vec![with_telemetry(
        worker(1, "x86_64", 2),
        0.0,
        8,
        0.0,
        1_000_000,
    )];
    let c = candidate(Some("x86_64"), None, "test");
    let d = decide_candidate(DecideCandidateInput {
        profile: learned_tmpfs_profile(Some(500_001)),
        ..base_input(&c, learned_tmpfs_profile(Some(500_001)), &workers)
    });
    assert_eq!(
        d,
        PlannerDecision::Dispatch { worker_id: 1 },
        "gate off (default): first worker dispatches regardless of tmpfs capacity"
    );
}

#[test]
fn tmpfs_gate_enforced_falls_over_to_next_worker() {
    let workers = vec![
        with_telemetry(worker(1, "x86_64", 2), 0.0, 8, 0.0, 1_000_000),
        with_telemetry(worker(2, "x86_64", 2), 0.0, 8, 0.0, 2_000_000),
    ];
    let c = candidate(Some("x86_64"), None, "test");
    let d = decide_candidate(DecideCandidateInput {
        tmpfs_gate_enforced: true,
        profile: learned_tmpfs_profile(Some(500_001)),
        ..base_input(&c, learned_tmpfs_profile(Some(500_001)), &workers)
    });
    assert_eq!(
        d,
        PlannerDecision::Dispatch { worker_id: 2 },
        "enforced: first worker rejected by tmpfs gate, next worker takes the dispatch"
    );
}

#[test]
fn tmpfs_gate_enforced_all_reject_attributes_tmpfs() {
    let workers = vec![with_telemetry(
        worker(1, "x86_64", 2),
        0.0,
        8,
        0.0,
        1_000_000,
    )];
    let c = candidate(Some("x86_64"), None, "test");
    let d = decide_candidate(DecideCandidateInput {
        tmpfs_gate_enforced: true,
        profile: learned_tmpfs_profile(Some(1_000_000)),
        ..base_input(&c, learned_tmpfs_profile(Some(1_000_000)), &workers)
    });
    match d {
        PlannerDecision::WatermarkBlocked {
            dimension,
            head_load,
        } => {
            assert_eq!(
                dimension,
                crate::server::scheduler::WatermarkDimension::Tmpfs
            );
            assert!(
                head_load.mem_kb.abs() < 1e-6 && head_load.cpu_cores.abs() < 1e-6,
                "zero-weight candidate carries empty load, got {head_load:?}"
            );
        }
        other => panic!("expected WatermarkBlocked(Tmpfs), got {other:?}"),
    }
}

#[test]
fn tmpfs_gate_enforced_skip_and_boundary_arms() {
    let mk_w = || with_telemetry(worker(1, "x86_64", 2), 0.0, 8, 0.0, 1_000_000);
    let c = candidate(Some("x86_64"), None, "test");

    let unlearned = ResolvedResourceProfile {
        gate_learned: false,
        gate_max_tmpfs_kb: Some(999_999_999),
        ..ResolvedResourceProfile::default()
    };
    let d = decide_candidate(DecideCandidateInput {
        tmpfs_gate_enforced: true,
        profile: unlearned,
        ..base_input(&c, unlearned, &[mk_w()])
    });
    assert_eq!(d, PlannerDecision::Dispatch { worker_id: 1 });

    let blind = worker(1, "x86_64", 2);
    let learned = learned_tmpfs_profile(Some(999_999_999));
    let d = decide_candidate(DecideCandidateInput {
        tmpfs_gate_enforced: true,
        profile: learned,
        ..base_input(&c, learned, &[blind])
    });
    assert_eq!(d, PlannerDecision::Dispatch { worker_id: 1 });

    let boundary = learned_tmpfs_profile(Some(500_000));
    let d = decide_candidate(DecideCandidateInput {
        tmpfs_gate_enforced: true,
        profile: boundary,
        ..base_input(&c, boundary, &[mk_w()])
    });
    assert_eq!(d, PlannerDecision::Dispatch { worker_id: 1 });

    let w_full = with_telemetry(worker(1, "x86_64", 2), 0.0, 8, 95.0, 1_000_000);
    let profile_with_weight = ResolvedResourceProfile {
        weight: weight_only(900_000.0),
        ..learned_tmpfs_profile(Some(1_000_000))
    };
    let d = decide_candidate(DecideCandidateInput {
        tmpfs_gate_enforced: true,
        profile: profile_with_weight,
        ..base_input(&c, profile_with_weight, &[w_full])
    });
    expect_watermark_blocked(
        d,
        crate::server::scheduler::WatermarkDimension::Mem,
        900_000.0,
        0.0,
    );
}
