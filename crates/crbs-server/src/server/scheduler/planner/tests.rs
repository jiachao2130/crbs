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

/// 测试 worker 构造（id 递增隐含 least-loaded 序兜底；遥测可选）。
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

/// 决策输入基线：空 active/Σ/init、无水位记录、非 steering；各用例用
/// 测试基线水位（= serde 默认 0.90/1.00，经 ServerConfig::default 单一事实源）。
fn default_wm() -> AdmitWatermarks {
    AdmitWatermarks::from_config(&crbs_core::config::ServerConfig::default())
}

/// `..base_input(...)` 只覆盖差异字段。
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

// ===== 硬下限（fail-closed）=====

/// 逐维判定矩阵：满足返回 None；不满足/要求维遥测缺失（未上报）返回
/// 首个不合格维——mem → ncpu → disk 固定序，缺失与不足同判（声明是契约）。
#[test]
fn hard_req_matrix_fails_closed_on_missing_telemetry() {
    let mut w = with_telemetry(worker(1, "x86_64", 2), 0.0, 8, 10.0, 32 * 1024 * 1024);
    w = with_disk_free(w, 100 * 1024 * 1024);

    // 全部满足 → None。
    let req = EffectiveHardReq {
        min_mem_kb: Some(16 * 1024 * 1024),
        min_ncpu: Some(8),
        min_disk_kb: Some(64 * 1024 * 1024),
    };
    assert_eq!(worker_satisfies_hard_req(&w, &req), None);

    // 逐维不足：mem 不足 / ncpu 不足 / disk 不足，各返回该维。
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

    // fail-closed：要求维遥测缺失 = 不可承载（未上报 disk_free）。
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

    // 多维声明按 mem → ncpu → disk 序报首个不合格维。
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

/// 硬下限 eligible 过滤：不达标节点跳过、达标节点承接；全员不达标 →
/// NoFitHardReq{首缺维}（队首不阻塞，归因带维度）。
#[test]
fn decide_hard_req_skips_underprovisioned_and_reports_dimension() {
    // w1(8G) 排前、w2(32G) 排后：min_mem 16G 只留 w2（eligible 保序取首）。
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

    // 全员不达标（min_mem 高于最大节点）→ NoFitHardReq{Mem}。
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

    // 无磁盘遥测（disk_free 缺失）+ 磁盘声明 → fail-closed Disk 维。
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

/// 水位拒断言：维度与序首节点生效折算压载逐字段核对（f64 无 Eq，不走
/// assert_eq 全值比较）。
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

// ===== heavy 判定与 steering 选点 =====

/// heavy 判定三臂 + 边界：req 任一维即 heavy；有效权重达阈值（1 GiB，代码
/// 常量）即 heavy（差 1 KB 不算）；srpm ≥ resource_heavy_srpm_bytes 即
/// heavy（恰好达界算、0 = 臂禁用）。三臂独立 OR。
#[test]
fn is_heavy_candidate_three_arms_and_boundaries() {
    let no_req = EffectiveHardReq::default();
    let with_req = EffectiveHardReq {
        min_disk_kb: Some(1024),
        ..Default::default()
    };

    // req 臂：任一维存在即 heavy（权重/srpm 双缺）。
    assert!(is_heavy_candidate(&with_req, &weight_only(0.0), None, 0));

    // 权重臂：阈值恰好达界算 heavy，差 1 KB 不算。
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
    // 未画像（权重未知）不算。
    assert!(!is_heavy_candidate(
        &no_req,
        &super::super::PackageResourceWeight::default(),
        None,
        0
    ));

    // srpm 臂：恰好达界算 heavy，低于不算；阈值 0 = 臂禁用。
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

/// steering 选点（开关开的 heavy 候选）：eligible 全链过滤后以 headroom 最大
/// 节点为头逐个验门，首个过门者承接；开关关时按传入序逐个验门。水位门拒
/// 顺延后两序只在"多个节点都能过门"时落点不同；并列 headroom 取序首。
#[test]
fn decide_steering_picks_headroom_head_only_for_heavy() {
    let c = candidate(Some("x86_64"), None, "test");
    // heavy 权重 600k：w1（55%×2M → 1.1M+0.6M < 1.8M 过门、余量比 0.35）排序
    // 在前，w2（10%×2M → 过门、余量比 0.8、active 垫底排序在后）。
    let mid = weight(600_000.0, 0.0);
    let workers = vec![
        with_telemetry(worker(1, "x86_64", 2), 0.0, 8, 55.0, 2_000_000),
        with_telemetry(worker(2, "x86_64", 2), 0.0, 8, 10.0, 2_000_000),
    ];
    let active: HashMap<i64, i64> = [(2i64, 1i64)].into_iter().collect();

    // steer 开：steering 序 [w2, w1]，两节点都过门 → 落余量最大的 w2。
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            steer_heavy: true,
            active: &active,
            ..base_input(&c, mid, &workers)
        }),
        PlannerDecision::Dispatch { worker_id: 2 },
        "heavy candidate must land on the max-headroom worker when it admits"
    );

    // steer 关：传入序 [w1, w2]，序首 w1 过门 → 落 w1（顺延只在序首被挡时发生）。
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            active: &active,
            ..base_input(&c, mid, &workers)
        }),
        PlannerDecision::Dispatch { worker_id: 1 },
        "steering off keeps the order-head placement when the head admits"
    );

    // steer 关且序首被挡（1.5M 进 w1 即溢）→ 顺延 w2 承接，不再整体等待。
    let heavy = weight(1_500_000.0, 0.0);
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            active: &active,
            ..base_input(&c, heavy, &workers)
        }),
        PlannerDecision::Dispatch { worker_id: 2 },
        "blocked order head must fall over to the next feasible worker"
    );

    // steer 开并列 headroom → 取序首（eligible 保序 tie-break）。
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

/// steering 选点的遥测分组：eligible 混有无遥测 / 半遥测节点时
/// 只在完整 mem 遥测（total + used%）组内选 headroom 最大——缺任一维节点
/// 名义 headroom +∞ 且水位门 fail-open，直接比 headroom 会把重包导向最
/// 不可观测节点；全组无完整遥测才退化为序首。
#[test]
fn decide_steering_prefers_telemetried_workers_and_degrades_to_order_head() {
    let c = candidate(Some("x86_64"), None, "test");
    let heavy = weight(1_500_000.0, 0.0);

    // 混合：w1 无遥测（名义 +∞，排序在前）、w2 有遥测（10%×2M，余量大且
    // 水位门放行）。heavy 必落 w2——+∞ 不许冒充"最宽裕"。
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

    // 半遥测（只有 total、缺 used%）同样不参与分组：w1 名义 +∞ 排序在前，
    // 正确选点仍是有完整遥测的 w2。
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

    // 全组无遥测（两家都未上报）：无可比余量 → 退化为序首。
    let blind = vec![worker(1, "x86_64", 2), worker(2, "x86_64", 2)];
    assert_eq!(
        decide_candidate(DecideCandidateInput {
            steer_heavy: true,
            ..base_input(&c, heavy, &blind)
        }),
        PlannerDecision::Dispatch { worker_id: 1 },
        "all-untelemetried eligible must degrade to the order head"
    );

    // 全组只有半遥测：同样无完整可比余量 → 序首（而非把 total-only 当 +∞）。
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

// ===== candidate_arch_matches =====

/// 架构匹配矩阵：精确命中、不匹配拒、noarch 三态（未钉收/钉含收/钉其它拒）、
/// NULL-arch 拒（镜像分布式 pick 谓词，仅本地路径领取）。
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

// ===== decide_candidate =====

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
    // 仅 aarch64 worker、x86_64 候选 → NoFitArch。
    let workers = vec![worker(1, "aarch64", 2)];
    let c = candidate(Some("x86_64"), None, "test");
    assert_eq!(
        decide_candidate(base_input(&c, weight(0.0, 0.0), &workers)),
        PlannerDecision::NoFit {
            reason: RejectReason::NoFitArch
        }
    );

    // 架构匹配但容量满 → NoFitCapacity。
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

    // 空槽但 init 门 → InitGated。
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
    // 其它 product 的 init 不拦。
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
    // total=1_000_000KB、used 30%：余量到 90% 水位 = 600_000。
    // Σ 已占 500_000：候选权重 50_000 进门后仍 < 900_000 → 派。
    // 候选权重 150_000 进门后 ≥ 900_000 → 拒（legacy worker-outer 只看
    // Σ=500_000 会开门——候选权重进门是 planner 的行为差异点）。
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
    // 全拒归因随序首节点生效压载：Σ 500k + 候选 150k = 650k。
    expect_watermark_blocked(
        spills,
        crate::server::scheduler::WatermarkDimension::Mem,
        650_000.0,
        0.0,
    );
}

/// 水位门拒顺延次优节点：遍历序首节点超水位即试下一个 eligible——被在跑
/// Σ 挡住的候选由空闲次优节点先行承接（排队回收；pending 无落点锁定、每
/// tick 重评），全拒才整体等待。
#[test]
fn decide_water_falls_over_to_next_feasible_worker() {
    // 放置序 w1（active 0/2）在 w2（active 1/2）前；w1 水位已过 90%
    //（95%），w2 仅 10%：w1 被拒、w2 承接。
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
    // ncpu=8、load1=4：Σp90=3.9 + 候选 0.2 = 4.1 ≥ 8×1.0？不，水位是 ncpu×1.0
    // = 8。改用贴线数据：load1=7.9、Σp90=0 → 候选 0.2 进门后 8.1 ≥ 8 → 拒。
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

/// CPU 权重按目标节点核数折算（饱和护栏约束）：64 核采样机的饱和包
///（p90=40 ≥ 0.5×64）派到 16 核节点折算为 10 核，不再被 40 ≥ 16 恒判超载；
/// 采样核数未知（旧样本/静态覆盖）不猜基准，维持原口径；非饱和包（p90 <
/// 0.5×采样核数）护栏命中按原值比对——缩放会低估依赖图约束下的小节点占用。
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

    // 非饱和包：p90=20 < 0.5×64，护栏命中——若折算（20×8/64=2.5）会误放行，
    // 原值 20 ≥ 16 必拒。
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

/// 分布式水位门总闸：关闭后放置序选中即派（含超水位节点）；硬下限过滤
/// 不受开关影响——开关只管建议性水位，不动契约性下限。
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
    // 水位拒 + 未超龄 → WatermarkBlocked（censored 也一样）。
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

    // 超龄 + censored → 兜底派 headroom 最大节点。
    let aged = decide_candidate(DecideCandidateInput {
        first_watermark_reject_age: Some(Duration::from_secs(LAST_RESORT_AFTER_SECS)),
        ..base_input(&c, heavy_censored, &workers)
    });
    assert_eq!(aged, PlannerDecision::SoftFallback { worker_id: 1 });

    // 超龄 + 非 censored → 永不兜底（继续等待 + 归因可见）。
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

    // 无水位全拒记录（None）= 未超龄，不兜底。
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
    // 两家都拒（水位贴线），headroom 大者承接兜底：
    // w1: used 80%×1M → headroom 100_000；w2: used 50%×2M → headroom 900_000。
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

/// 兜底只在"eligible 全拒"时触发：盲节点（mem 遥测缺失）的水位门 fail-open
/// 直接放行——有节点可派就派，派发优先于兜底；全组可观测且全拒时，兜底落
/// headroom 最大者（盲节点的名义 +∞ 不参与比选，全盲组退化为序首）。
#[test]
fn soft_fallback_only_fires_when_every_node_rejects() {
    let c = candidate(Some("x86_64"), None, "test");
    let heavy_censored = ResolvedResourceProfile {
        weight: weight(1_000_000.0, 0.0).weight,
        censored: true,
        ..ResolvedResourceProfile::default()
    };

    // w1/w3 可观测且被 1M 权重挤爆（950k/100k + 1M ≥ 900k 水位全拒）；
    // w2 无遥测 → 门 fail-open 放行：逐节点验门在 w2 命中首个可行落点，
    // 派发直接发生，兜底（全拒才有资格触发）不参与。
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

    // 全组无完整 mem 遥测但纯 CPU 维被拒（load1 贴线）：所有节点全拒 →
    // 兜底触发，无可比 mem 余量 → 选点退化为序首（fail-open 方向）。
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

// ===== steering 归一化评分与全序 =====

/// 评分公式与遥测缺失语义：mem 维 `(0.9×total − used − Σmem)/total`、cpu 维
/// `(ncpu − load1 − Σcpu)/ncpu`、瓶颈维 min；单维缺失只比另一维，两维全缺
/// = `None`（盲节点不冒充最宽裕）。
#[test]
fn normalized_headroom_score_formula_and_missing_telemetry() {
    let w = with_telemetry(worker(1, "x86_64", 2), 2.0, 8, 30.0, 1_000_000);
    let load = CommittedLoad {
        mem_kb: 100_000.0,
        cpu_cores: 1.0,
    };
    // mem (900k−300k−100k)/1M = 0.5；cpu (8−2−1)/8 = 0.625 → 瓶颈维 0.5。
    let score = normalized_headroom_score(&w, load, default_wm()).expect("telemetry present");
    assert!((score - 0.5).abs() < 1e-9, "score: {score}");

    // mem 遥测缺失：只比 cpu 维。
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

/// 归一化消除绝对偏大：60% 满的大节点绝对余量更大，但比例分低于比例更空的
/// 小节点——steering 全序把小节点排前。
#[test]
fn steering_order_ranks_normalized_score_over_absolute_headroom() {
    // w1：10M 节点 60% 满 → 绝对余量 3M，比例分 0.3；
    // w2：1M 节点 10% 满 → 绝对余量 0.8M，比例分 0.8。
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

    // 盲节点垫底、彼此保序；并列分数保持传入序（stable sort tie-break）。
    let blind = worker(3, "x86_64", 2);
    let mixed = vec![&blind, &small, &big];
    let order = steering_order(&mixed, &committed, default_wm());
    assert_eq!(
        order.iter().map(|w| w.id).collect::<Vec<_>>(),
        vec![2, 1, 3]
    );
}

// ===== per-tick refill cap =====

/// 上限公式边界：`capacity/8` 向下取整、下限 2（capacity 0/2/8/16 同为 2）、
/// 大容量线性放大（40 → 5，80 → 10）。
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

// ===== DispatchAttribution =====

/// 归因语义：no_fit 不设水位首拒、water_reject 首拒只进不退、跨原因
/// 保留、clear 清除、容量封顶清空。
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

    // 首拒时刻只进不退（第二次记录不得重置基准）。
    a.record_water_reject(1, WatermarkDimension::Cpu, CommittedLoad::default());
    assert_eq!(
        a.get(1).unwrap().first_watermark_reject_at,
        first.first_watermark_reject_at
    );

    // 跨原因保留：no_fit 不清水位首拒。
    a.record_no_fit(1, RejectReason::NoFitCapacity);
    let e = a.get(1).unwrap();
    assert_eq!(e.reason, RejectReason::NoFitCapacity);
    assert_eq!(e.first_watermark_reject_at, first.first_watermark_reject_at);

    a.clear(1);
    assert_eq!(a.get(1), None);
}

/// 定容：触满淘汰一条最旧条目（优先无等待钟条目），其它构建的等待钟不被
/// 重置——水位/硬下限首拒是兜底与停滞判定的输入，不是纯诊断字段。
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

/// 硬下限首拒时钟：首次设置后只进不退；停滞提示一次性置位。
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

// ===== 学习 tmpfs 门转正（resource_tmpfs_gate_enforced）=====

/// 已学习且带 tmpfs 需求的画像。
fn learned_tmpfs_profile(max_tmpfs_kb: Option<i64>) -> ResolvedResourceProfile {
    ResolvedResourceProfile {
        gate_learned: true,
        gate_max_tmpfs_kb: max_tmpfs_kb,
        ..ResolvedResourceProfile::default()
    }
}

/// 转正关（默认）行为不变：序首节点 tmpfs 装不下也照派——影子门不参与决策。
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

/// 转正开：序首 tmpfs 容量不足拒、顺延次优节点派发——与水位门同路径。
#[test]
fn tmpfs_gate_enforced_falls_over_to_next_worker() {
    let workers = vec![
        with_telemetry(worker(1, "x86_64", 2), 0.0, 8, 0.0, 1_000_000), // 容量 500_000
        with_telemetry(worker(2, "x86_64", 2), 0.0, 8, 0.0, 2_000_000), // 容量 1_000_000
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

/// 转正开 + 全组拒绝：归因记 Tmpfs 维，head_load 携带生效折算压载。
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

/// 转正开的 fail-open 臂：未学习键 / mem_total 缺失（容量换算不出）放行；
/// 容量恰好压线 = 放行（≥ 同影子门语义）；水位先拒的节点归因仍是水位维。
#[test]
fn tmpfs_gate_enforced_skip_and_boundary_arms() {
    let mk_w = || with_telemetry(worker(1, "x86_64", 2), 0.0, 8, 0.0, 1_000_000);
    let c = candidate(Some("x86_64"), None, "test");

    // 未学习键：gate_learned=false，学习值齐备也放行。
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

    // mem_total 缺失 = 容量换算不出 → 门跳过放行。
    let blind = worker(1, "x86_64", 2);
    let learned = learned_tmpfs_profile(Some(999_999_999));
    let d = decide_candidate(DecideCandidateInput {
        tmpfs_gate_enforced: true,
        profile: learned,
        ..base_input(&c, learned, &[blind])
    });
    assert_eq!(d, PlannerDecision::Dispatch { worker_id: 1 });

    // 压线：容量 500_000 = 需求 → 放行（≥）。
    let boundary = learned_tmpfs_profile(Some(500_000));
    let d = decide_candidate(DecideCandidateInput {
        tmpfs_gate_enforced: true,
        profile: boundary,
        ..base_input(&c, boundary, &[mk_w()])
    });
    assert_eq!(d, PlannerDecision::Dispatch { worker_id: 1 });

    // 水位先拒的节点归因保持水位维（tmpfs 门只在水位通过后评估）。
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
