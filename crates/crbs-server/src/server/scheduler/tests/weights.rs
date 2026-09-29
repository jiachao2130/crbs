// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 派发序、水位门与画像权重回源纯函数。

use super::common::*;
use super::*;

/// 测试基线水位（= serde 默认 0.90/1.00）下的准入门判定。
fn wm_reject(
    w: &crbs_core::WorkerStatus,
    load: CommittedLoad,
) -> Option<crate::server::scheduler::WatermarkDimension> {
    let wm = AdmitWatermarks::from_config(&crbs_core::config::ServerConfig::default());
    watermark_reject_dimension(w, load, wm)
}

#[test]
fn sort_workers_for_dispatch_orders_by_utilization_load_then_id() {
    let mk = |id: i64, capacity: i64, load1: Option<f64>, ncpu: Option<i64>| WorkerStatus {
        id,
        name: format!("w{id}"),
        arch: "x86_64".into(),
        capacity,
        status: "online".into(),
        last_heartbeat: None,
        version: "test".into(),
        has_secret: false,
        load1,
        ncpu,
        cpu_util_pct: None,
        mem_used_pct: None,
        mem_total_kb: None,
        disk_free_kb: None,
        resource_caps: None,
        created_at: None,
        secret_expires_at: None,
    };
    let mut workers = vec![
        mk(1, 2, None, None),          // util 2/2 = 1.0
        mk(2, 4, Some(3.0), Some(4)),  // util 0, load 0.75
        mk(3, 2, Some(0.25), Some(2)), // util 0, load 0.125
        mk(4, 4, None, None),          // util 0, 遥测缺失 → +∞ 排同档末尾
        mk(5, 2, Some(0.25), Some(2)), // 与 3 同档同负载 → id 兜底
    ];
    let active: HashMap<i64, i64> = [(1i64, 2i64)].into_iter().collect();
    sort_workers_for_dispatch(&mut workers, &active);
    let order: Vec<i64> = workers.iter().map(|w| w.id).collect();
    assert_eq!(order, vec![3, 5, 2, 4, 1]);
}

#[test]
fn watermark_gate_checks_memory_and_cpu_dimensions() {
    let mk =
        |load1: Option<f64>, ncpu: Option<i64>, used_pct: Option<f64>, total_kb: Option<i64>| {
            WorkerStatus {
                id: 1,
                name: "w".into(),
                arch: "x86_64".into(),
                capacity: 4,
                status: "online".into(),
                last_heartbeat: None,
                version: "test".into(),
                has_secret: false,
                load1,
                ncpu,
                cpu_util_pct: None,
                mem_used_pct: used_pct,
                mem_total_kb: total_kb,
                disk_free_kb: None,
                resource_caps: None,
                created_at: None,
                secret_expires_at: None,
            }
        };
    // 内存：total=1_000_000KB、used 50% → 余量 400_000，Σ 权重贴线上/下各验一边。
    let mem_worker = mk(Some(0.0), Some(64), Some(50.0), Some(1_000_000));
    assert_eq!(
        wm_reject(
            &mem_worker,
            CommittedLoad {
                mem_kb: 399_999.0,
                cpu_cores: 0.0
            }
        ),
        None
    );
    assert_eq!(
        wm_reject(
            &mem_worker,
            CommittedLoad {
                mem_kb: 400_000.0,
                cpu_cores: 0.0
            }
        ),
        Some(WatermarkDimension::Mem)
    );
    // CPU：ncpu=8，load1=4；余量 4 核，边界取等拒绝。
    let cpu_worker = mk(Some(4.0), Some(8), None, None);
    assert_eq!(
        wm_reject(
            &cpu_worker,
            CommittedLoad {
                mem_kb: 0.0,
                cpu_cores: 3.999
            }
        ),
        None
    );
    assert_eq!(
        wm_reject(
            &cpu_worker,
            CommittedLoad {
                mem_kb: 0.0,
                cpu_cores: 4.0
            }
        ),
        Some(WatermarkDimension::Cpu)
    );
    // 遥测缺失（无采样 / 非 Linux）：两维度均 NULL → 直接放行（降级语义）。
    assert_eq!(
        wm_reject(
            &mk(None, None, None, None),
            CommittedLoad {
                mem_kb: 1e18,
                cpu_cores: 1e9
            }
        ),
        None
    );
    // 遥测齐全且 Σ=0：空载 worker 开门。
    assert_eq!(wm_reject(&mem_worker, CommittedLoad::default()), None);
}

#[test]
fn cpu_weight_scales_by_target_node_cores() {
    // 64 核采样机饱和包（p90=40 ≥ 0.5×64）：16 核折算 10，64 核原值，128 核
    // 只降不升不放大。
    let learned = PackageResourceWeight {
        peak_rss_kb: None,
        cpu_p90_cores: Some(40.0),
        cpu_sample_ncpu: Some(64),
    };
    assert_eq!(learned.cpu_cores_on(Some(16)), 10.0);
    assert_eq!(learned.cpu_cores_on(Some(64)), 40.0);
    assert_eq!(learned.cpu_cores_on(Some(128)), 40.0);
    // 目标核数未知（未上报 ncpu 遥测）：无基准，不缩放。
    assert_eq!(learned.cpu_cores_on(None), 40.0);

    // 采样核数未知（样本缺 ncpu / 静态覆盖）：不猜基准，维持原值。
    let legacy = PackageResourceWeight {
        peak_rss_kb: None,
        cpu_p90_cores: Some(40.0),
        cpu_sample_ncpu: None,
    };
    assert_eq!(legacy.cpu_cores_on(Some(16)), 40.0);

    // 非饱和包（p90=4 < 0.5×64）：并发受依赖图上限约束，护栏命中不折算。
    let dep_bound = PackageResourceWeight {
        peak_rss_kb: None,
        cpu_p90_cores: Some(4.0),
        cpu_sample_ncpu: Some(64),
    };
    assert_eq!(dep_bound.cpu_cores_on(Some(16)), 4.0);

    // 退化值不做除零：sample=0 / target=0 都按不缩放处理。
    let zero_sample = PackageResourceWeight {
        peak_rss_kb: None,
        cpu_p90_cores: Some(1.0),
        cpu_sample_ncpu: Some(0),
    };
    assert_eq!(zero_sample.cpu_cores_on(Some(8)), 1.0);
    assert_eq!(learned.cpu_cores_on(Some(0)), 40.0);

    // Σ 折算与候选进门共用同一口径：同节点全部构建按该节点核数折算。
    let mut load = CommittedLoad::default();
    load.add(&learned, Some(16));
    assert_eq!(load.cpu_cores, 10.0);
    assert_eq!(load.plus(&learned, Some(16)).cpu_cores, 20.0);
}

/// 内存权重按目标节点折算，与 cpu 维同系数同护栏：饱和包（峰值随 -j$(nproc)
/// 伸缩）按 `peak_rss × target/sample` 折算、只降不升；非饱和包 / 无采样基准
/// / cpu 权重缺失（无饱和度判据）一律原值。
#[test]
fn mem_weight_scales_by_target_node_cores_with_saturation_guard() {
    // 饱和包：128 核采样机的 20GB 峰值放 64 核节点折 10GB（-j 减半）、
    // 16 核折 2.5GB；128 核目标只降不升维持原值。
    let elastic = PackageResourceWeight {
        peak_rss_kb: Some(20_000_000.0),
        cpu_p90_cores: Some(40.0),
        cpu_sample_ncpu: Some(64),
    };
    assert_eq!(elastic.mem_kb_on(Some(32)), 10_000_000.0);
    assert_eq!(elastic.mem_kb_on(Some(16)), 5_000_000.0);
    assert_eq!(elastic.mem_kb_on(Some(64)), 20_000_000.0);
    assert_eq!(elastic.mem_kb_on(Some(128)), 20_000_000.0);
    assert_eq!(elastic.mem_kb_on(None), 20_000_000.0);

    // 非饱和包：护栏命中，cpu/mem 都按原值比对。
    let dep_bound = PackageResourceWeight {
        peak_rss_kb: Some(20_000_000.0),
        cpu_p90_cores: Some(4.0),
        cpu_sample_ncpu: Some(64),
    };
    assert_eq!(dep_bound.mem_kb_on(Some(16)), 20_000_000.0);
    assert_eq!(dep_bound.cpu_cores_on(Some(16)), 4.0);

    // cpu 权重缺失（mem-only 形态）：无饱和度判据，不折算。
    let mem_only = PackageResourceWeight {
        peak_rss_kb: Some(20_000_000.0),
        cpu_p90_cores: None,
        cpu_sample_ncpu: Some(64),
    };
    assert_eq!(mem_only.mem_kb_on(Some(16)), 20_000_000.0);

    // Σ 折算与候选进门共用同一口径（add/plus 走 mem_kb_on）。
    let mut load = CommittedLoad::default();
    load.add(&elastic, Some(16));
    assert_eq!(load.mem_kb, 5_000_000.0);
    assert_eq!(load.plus(&elastic, Some(16)).mem_kb, 10_000_000.0);
}

/// Σ 折算按各构建所在节点分别归一：同一画像（40 核 @ 64 核采样，饱和包）在
/// 16 核节点计 10、在 64 核节点计 40——Σ 不是全局常量，而是 per-worker 量。
#[test]
fn committed_load_normalizes_per_worker_cores() {
    let profile = ResolvedResourceProfile {
        weight: PackageResourceWeight {
            peak_rss_kb: Some(100.0),
            cpu_p90_cores: Some(40.0),
            cpu_sample_ncpu: Some(64),
        },
        censored: false,
        ..ResolvedResourceProfile::default()
    };
    let key = profile_key("p", "pkg", Some("x86_64"));
    let profiles: ResourceProfileMap = [(key, profile)].into_iter().collect();
    let rows = vec![
        (
            1i64,
            "p".to_string(),
            "pkg".to_string(),
            Some("x86_64".to_string()),
        ),
        (
            2i64,
            "p".to_string(),
            "pkg".to_string(),
            Some("x86_64".to_string()),
        ),
    ];
    let worker_ncpu: HashMap<i64, i64> = [(1i64, 16i64), (2, 64)].into_iter().collect();
    let committed = committed_from_active(&rows, &profiles, &worker_ncpu);
    assert_eq!(committed.get(&1).unwrap().cpu_cores, 10.0);
    assert_eq!(committed.get(&2).unwrap().cpu_cores, 40.0);
    // 缺 ncpu 的 worker 退化为不缩放。
    let committed = committed_from_active(&rows, &profiles, &HashMap::new());
    assert_eq!(committed.get(&1).unwrap().cpu_cores, 40.0);
}

#[test]
fn resource_weight_cache_lookup_fill_invalidate_and_ttl() {
    let cache = ResourceWeightCache::with_ttl(Duration::from_millis(60));
    let profile = ResolvedResourceProfile {
        weight: PackageResourceWeight {
            peak_rss_kb: Some(1024.0),
            cpu_p90_cores: Some(2.0),
            cpu_sample_ncpu: None,
        },
        censored: true,
        ..ResolvedResourceProfile::default()
    };
    assert_eq!(
        cache.lookup("p", "gcc", "x86_64"),
        None,
        "empty cache misses"
    );

    cache.fill(&("p".into(), "gcc".into(), "x86_64".into()), profile);
    assert_eq!(cache.lookup("p", "gcc", "x86_64"), Some(profile));

    cache.invalidate("p", "gcc", "x86_64");
    assert_eq!(
        cache.lookup("p", "gcc", "x86_64"),
        None,
        "invalidated key misses"
    );

    cache.fill(&("p".into(), "gcc".into(), "x86_64".into()), profile);
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        cache.lookup("p", "gcc", "x86_64"),
        None,
        "expired entry misses"
    );

    // 同 (product, pkg) 异 arch 是独立键：写入不复活另一 arch 的过期条目。
    cache.fill(&("p".into(), "gcc".into(), "aarch64".into()), profile);
    assert_eq!(cache.lookup("p", "gcc", "aarch64"), Some(profile));
    assert_eq!(cache.lookup("p", "gcc", "x86_64"), None);

    // 批量形态：部分命中部分 miss，回填后全命中。
    let cache2 = ResourceWeightCache::with_ttl(Duration::from_secs(60));
    let keys = vec![
        ("p".to_string(), "gcc".to_string(), "x86_64".to_string()),
        ("p".to_string(), "llvm".to_string(), "x86_64".to_string()),
    ];
    cache2.fill(&(keys[0].clone()), profile);
    let (hits, misses) = cache2.lookup_many(&keys);
    assert_eq!(hits.len(), 1);
    assert_eq!(misses, vec![keys[1].clone()]);
    let mut backfill = std::collections::HashMap::new();
    backfill.insert(keys[1].clone(), ResolvedResourceProfile::default());
    cache2.fill_many(&backfill);
    let (hits, misses) = cache2.lookup_many(&keys);
    assert_eq!(hits.len(), 2);
    assert!(misses.is_empty());
}

#[tokio::test]
async fn package_weight_prefers_ema_then_static_then_unknown() {
    let (app, _tmp) = setup_app(4).await;
    let store = &app.state_store;

    // 未知：无产品行、无历史 → 全 None。
    let ghost_key = profile_key("ghost-product", "gcc", None);
    let unknown = load_resource_profiles(&app, vec![ghost_key.clone()]).await;
    assert_eq!(
        unknown.get(&ghost_key).unwrap().weight,
        PackageResourceWeight::default()
    );

    seed_product(store, "static-product", None).await;
    let mut static_cfg = std::collections::BTreeMap::new();
    static_cfg.insert(
        "gcc".to_string(),
        crbs_core::config::ResourceOverride {
            mem_gb: 16.0,
            cpu_cores: 8.0,
        },
    );
    seed_product(store, "with-overrides", Some(static_cfg)).await;

    // 静态覆盖：无历史时回退 overrides（GiB → KB，16GiB = 16×1024×1024KB）。
    let static_key = profile_key("with-overrides", "gcc", None);
    let static_w = load_resource_profiles(&app, vec![static_key.clone()]).await;
    assert_eq!(
        static_w.get(&static_key).unwrap().weight,
        PackageResourceWeight {
            peak_rss_kb: Some(16.0 * 1024.0 * 1024.0),
            cpu_p90_cores: Some(8.0),
            cpu_sample_ncpu: None,
        }
    );

    // 无覆盖且无历史 → 未知。
    let plain_key = profile_key("static-product", "gcc", None);
    let plain = load_resource_profiles(&app, vec![plain_key.clone()]).await;
    assert_eq!(
        plain.get(&plain_key).unwrap().weight,
        PackageResourceWeight::default()
    );

    // EMA 优先：有历史 + 有静态覆盖时历史样本胜出（key 含构建 arch）。
    seed_succeeded_resource_builds(store, "with-overrides", "gcc", 1_000_000, 4.0, 2).await;
    app.resource_weight_cache
        .invalidate("with-overrides", "gcc", "x86_64");
    let ema_key = profile_key("with-overrides", "gcc", Some("x86_64"));
    let ema_w = load_resource_profiles(&app, vec![ema_key.clone()]).await;
    let resolved = ema_w.get(&ema_key).unwrap();
    assert_eq!(
        resolved.weight,
        PackageResourceWeight {
            peak_rss_kb: Some(1_000_000.0),
            cpu_p90_cores: Some(4.0),
            cpu_sample_ncpu: None,
        }
    );
    assert!(!resolved.censored);
}

#[test]
fn effective_weight_consumes_censored_max_then_reverts_to_ema() {
    // 删失期：ema 低于 max 取 max。
    let w = effective_weight_from_learned(
        &crbs_core::LearnedWeightSnapshot {
            ema_mem_kb: Some(400_000),
            max_mem_kb: Some(1_200_000),
            ema_ncpu: Some(2.0),
            sample_ncpu: None,
            censored: true,
        },
        (None, None),
    );
    assert_eq!(w.peak_rss_kb, Some(1_200_000.0));
    assert_eq!(w.cpu_p90_cores, Some(2.0));

    // 解锁：回 ema。
    let w = effective_weight_from_learned(
        &crbs_core::LearnedWeightSnapshot {
            ema_mem_kb: Some(400_000),
            max_mem_kb: Some(1_200_000),
            ema_ncpu: Some(2.0),
            sample_ncpu: None,
            censored: false,
        },
        (None, None),
    );
    assert_eq!(w.peak_rss_kb, Some(400_000.0));

    // 冷启动删失（ema NULL 只有 max）：靠 max 进 Σ。
    let w = effective_weight_from_learned(
        &crbs_core::LearnedWeightSnapshot {
            ema_mem_kb: None,
            max_mem_kb: Some(1_200_000),
            ema_ncpu: None,
            sample_ncpu: None,
            censored: true,
        },
        (None, None),
    );
    assert_eq!(w.peak_rss_kb, Some(1_200_000.0));
    assert_eq!(w.cpu_p90_cores, None);

    // 缺维回退静态覆盖。
    let w = effective_weight_from_learned(
        &crbs_core::LearnedWeightSnapshot {
            ema_mem_kb: None,
            max_mem_kb: None,
            ema_ncpu: None,
            sample_ncpu: None,
            censored: false,
        },
        (Some(4.0 * 1024.0 * 1024.0), Some(2.0)),
    );
    assert_eq!(w.peak_rss_kb, Some(4.0 * 1024.0 * 1024.0));
    assert_eq!(w.cpu_p90_cores, Some(2.0));
}
