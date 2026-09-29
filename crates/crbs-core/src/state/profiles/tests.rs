// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use super::*;
use crate::state::test_state::create_test_store;
use crate::state::StateStore;

fn succeeded(
    backend: SampleBackend,
    peak_rss_kb: i64,
    cpu_p90: Option<f64>,
    ncpu: Option<i64>,
) -> ResourceSampleOutcome {
    ResourceSampleOutcome::Succeeded {
        backend,
        peak_rss_kb,
        peak_tmpfs_kb: None,
        cpu_p90_cores: cpu_p90,
        sample_ncpu: ncpu,
    }
}

fn node_oom(backend: SampleBackend, peak_rss_kb: i64) -> ResourceSampleOutcome {
    ResourceSampleOutcome::NodeOom {
        backend,
        peak_rss_kb,
        peak_tmpfs_kb: None,
        cpu_p90_cores: None,
        sample_ncpu: None,
    }
}

/// 带 tmpfs 峰值观测的样本（tmpfs 维折叠/删失测试专用；cpu/ncpu 无观测）。
fn succeeded_tmpfs(
    backend: SampleBackend,
    peak_rss_kb: i64,
    peak_tmpfs_kb: i64,
) -> ResourceSampleOutcome {
    ResourceSampleOutcome::Succeeded {
        backend,
        peak_rss_kb,
        peak_tmpfs_kb: Some(peak_tmpfs_kb),
        cpu_p90_cores: None,
        sample_ncpu: None,
    }
}

fn node_oom_tmpfs(
    backend: SampleBackend,
    peak_rss_kb: i64,
    peak_tmpfs_kb: i64,
) -> ResourceSampleOutcome {
    ResourceSampleOutcome::NodeOom {
        backend,
        peak_rss_kb,
        peak_tmpfs_kb: Some(peak_tmpfs_kb),
        cpu_p90_cores: None,
        sample_ncpu: None,
    }
}

/// 纯函数调用的键占位（sticky warn 字段；断言不依赖键值）。
const KEY: (&str, &str, &str) = ("p", "pkg", "x86_64");

// ---------- 纯函数单测（无 IO） ----------

#[test]
fn pure_cap_oom_and_light_package_produce_no_write() {
    let cur = LearnedState {
        ema_mem_kb: Some(1000),
        max_mem_kb: Some(1200),
        ema_tmpfs_kb: None,
        max_tmpfs_kb: None,
        ema_ncpu: None,
        max_ncpu: None,
        samples: 5,
        sample_ncpu: None,
        backend: Some(SampleBackend::Cgroup),
        censored: false,
    };
    let (state, decision) = next_learned_state(
        Some(&cur),
        &ResourceSampleOutcome::CapOom,
        None,
        1.25,
        KEY.0,
        KEY.1,
        KEY.2,
    );
    assert!(
        state.is_none() && decision == ProfileUpdateDecision::CapHitExcluded,
        "cap-OOM must not write and must report the exclusion: {decision:?}"
    );
    let (state, decision) = next_learned_state(
        None,
        &succeeded(SampleBackend::Cgroup, 100, None, None),
        Some(1000),
        1.25,
        KEY.0,
        KEY.1,
        KEY.2,
    );
    assert!(
        state.is_none() && decision == ProfileUpdateDecision::Skipped,
        "below-threshold sample must not create a row: {decision:?}"
    );
    let (state, decision) = next_learned_state(
        Some(&cur),
        &succeeded(SampleBackend::Cgroup, 100, None, None),
        Some(1000),
        1.25,
        KEY.0,
        KEY.1,
        KEY.2,
    );
    assert!(
        state.is_none() && decision == ProfileUpdateDecision::Skipped,
        "below-threshold sample must not touch an existing row: {decision:?}"
    );
}

/// 决策枚举覆盖 learned/censored/reset 三写通道：折叠、删失首行、升级重置。
#[test]
fn pure_decision_covers_learned_censored_and_reset() {
    let proc_row = LearnedState {
        ema_mem_kb: Some(1000),
        max_mem_kb: Some(1200),
        ema_tmpfs_kb: None,
        max_tmpfs_kb: None,
        ema_ncpu: None,
        max_ncpu: None,
        samples: 5,
        sample_ncpu: None,
        backend: Some(SampleBackend::Proc),
        censored: false,
    };
    // 折叠 → Learned。
    let (_, decision) = next_learned_state(
        Some(&proc_row),
        &succeeded(SampleBackend::Proc, 2000, None, None),
        None,
        1.25,
        KEY.0,
        KEY.1,
        KEY.2,
    );
    assert_eq!(decision, ProfileUpdateDecision::Learned);
    // 无前行删失 → Censored。
    let (_, decision) = next_learned_state(
        None,
        &node_oom(SampleBackend::Cgroup, 2000),
        None,
        1.25,
        KEY.0,
        KEY.1,
        KEY.2,
    );
    assert_eq!(decision, ProfileUpdateDecision::Censored);
    // proc → cgroup 升级 → Reset。
    let (_, decision) = next_learned_state(
        Some(&proc_row),
        &succeeded(SampleBackend::Cgroup, 500, None, None),
        None,
        1.25,
        KEY.0,
        KEY.1,
        KEY.2,
    );
    assert_eq!(decision, ProfileUpdateDecision::Reset);
}

#[test]
fn pure_null_backend_row_folds_without_reset() {
    // 回填行：backend NULL + 播种值；首个真实样本按本样本口径折叠、
    // 保留播种（重置只发生在 proc→cgroup 升级）。
    let cur = LearnedState {
        ema_mem_kb: Some(1000),
        max_mem_kb: Some(1200),
        ema_tmpfs_kb: None,
        max_tmpfs_kb: None,
        ema_ncpu: None,
        max_ncpu: None,
        samples: 5,
        sample_ncpu: None,
        backend: None,
        censored: false,
    };
    let (state, decision) = next_learned_state(
        Some(&cur),
        &succeeded(SampleBackend::Cgroup, 2000, None, None),
        None,
        1.25,
        KEY.0,
        KEY.1,
        KEY.2,
    );
    let next = state.expect("backend-NULL row must fold");
    assert_eq!(decision, ProfileUpdateDecision::Learned);
    assert_eq!(next.ema_mem_kb, Some(1400));
    assert_eq!(next.samples, 6);
    assert_eq!(next.backend, Some(SampleBackend::Cgroup));
}

/// tmpfs 双分量折叠：与 mem 同语义但独立折叠——样本带观测时 α 折叠、max
/// 只抬不降；缺观测（None 穿透）时 tmpfs 两列维持前值，mem 照常折叠。
#[test]
fn pure_tmpfs_dimension_folds_independently_of_mem() {
    // 前值：mem 有历史、tmpfs 无观测历史（回填行形态）。
    let cur = LearnedState {
        ema_mem_kb: Some(1000),
        max_mem_kb: Some(1200),
        ema_tmpfs_kb: None,
        max_tmpfs_kb: None,
        ema_ncpu: None,
        max_ncpu: None,
        samples: 5,
        sample_ncpu: None,
        backend: Some(SampleBackend::Cgroup),
        censored: false,
    };
    // 带 tmpfs 观测的样本：mem 折叠、tmpfs 首项直落（None 前值 init 形态）。
    let (state, decision) = next_learned_state(
        Some(&cur),
        &succeeded_tmpfs(SampleBackend::Cgroup, 2000, 800),
        None,
        1.25,
        KEY.0,
        KEY.1,
        KEY.2,
    );
    let next = state.expect("sample above threshold must fold");
    assert_eq!(decision, ProfileUpdateDecision::Learned);
    assert_eq!(next.ema_mem_kb, Some(1400));
    assert_eq!(next.max_mem_kb, Some(2000));
    assert_eq!(next.ema_tmpfs_kb, Some(800));
    assert_eq!(next.max_tmpfs_kb, Some(800));

    // 缺 tmpfs 观测的样本：mem 照常折叠，tmpfs 两列维持前值。
    let (state, _) = next_learned_state(
        Some(&next),
        &succeeded(SampleBackend::Cgroup, 3000, None, None),
        None,
        1.25,
        KEY.0,
        KEY.1,
        KEY.2,
    );
    let next = state.expect("sample above threshold must fold");
    assert_eq!(next.ema_mem_kb, Some(2040));
    assert_eq!(
        next.ema_tmpfs_kb,
        Some(800),
        "无 tmpfs 观测的样本不得折叠 tmpfs 维"
    );
    assert_eq!(next.max_tmpfs_kb, Some(800));

    // 带 tmpfs 观测：α 折叠 round(0.4×1200+0.6×800)=960、max 只抬不降。
    let (state, _) = next_learned_state(
        Some(&next),
        &succeeded_tmpfs(SampleBackend::Cgroup, 4000, 1200),
        None,
        1.25,
        KEY.0,
        KEY.1,
        KEY.2,
    );
    let next = state.expect("sample above threshold must fold");
    assert_eq!(next.ema_tmpfs_kb, Some(960));
    assert_eq!(next.max_tmpfs_kb, Some(1200));
    assert_eq!(next.max_mem_kb, Some(4000));
}

/// 删失通道 tmpfs 维：带观测的删失样本只抬 max（×headroom、只抬不降）；
/// 缺观测不动；ema 恒不动。
#[test]
fn pure_tmpfs_censoring_only_raises_max() {
    let cur = LearnedState {
        ema_mem_kb: Some(1000),
        max_mem_kb: Some(1200),
        ema_tmpfs_kb: Some(800),
        max_tmpfs_kb: Some(1000),
        ema_ncpu: None,
        max_ncpu: None,
        samples: 5,
        sample_ncpu: None,
        backend: Some(SampleBackend::Cgroup),
        censored: false,
    };
    // 带 tmpfs=800 的删失样本：floor=1000 与前 max 持平，不抬；ema 不动。
    let (state, decision) = next_learned_state(
        Some(&cur),
        &node_oom_tmpfs(SampleBackend::Cgroup, 2000, 800),
        None,
        1.25,
        KEY.0,
        KEY.1,
        KEY.2,
    );
    let next = state.expect("censored sample must write");
    assert_eq!(decision, ProfileUpdateDecision::Censored);
    assert_eq!(next.max_tmpfs_kb, Some(1000), "floor 未超前 max 不得回降");
    assert_eq!(next.ema_tmpfs_kb, Some(800), "删失样本不动 ema");
    assert!(next.censored);

    // 带 tmpfs=5000 的删失样本：floor=6250，抬升。
    let (state, _) = next_learned_state(
        Some(&next),
        &node_oom_tmpfs(SampleBackend::Cgroup, 2000, 5000),
        None,
        1.25,
        KEY.0,
        KEY.1,
        KEY.2,
    );
    let next = state.expect("censored sample must write");
    assert_eq!(next.max_tmpfs_kb, Some(6250));

    // 缺 tmpfs 观测的删失样本：tmpfs 维全不动。
    let (state, _) = next_learned_state(
        Some(&next),
        &node_oom(SampleBackend::Cgroup, 2000),
        None,
        1.25,
        KEY.0,
        KEY.1,
        KEY.2,
    );
    let next = state.expect("censored sample must write");
    assert_eq!(next.max_tmpfs_kb, Some(6250));
    assert_eq!(next.ema_tmpfs_kb, Some(800));
}

/// 首样本 init 形态（tmpfs 维）：succeeded 建行 ema=max=样本；删失首行
/// ema NULL、max=floor；样本缺 tmpfs 观测则两列全 NULL。
#[test]
fn pure_tmpfs_first_sample_init_shapes() {
    // succeeded 带 tmpfs。
    let (state, decision) = next_learned_state(
        None,
        &succeeded_tmpfs(SampleBackend::Cgroup, 2000, 512),
        None,
        1.25,
        KEY.0,
        KEY.1,
        KEY.2,
    );
    let next = state.expect("first sample must create the row");
    assert_eq!(decision, ProfileUpdateDecision::Learned);
    assert_eq!(next.ema_tmpfs_kb, Some(512));
    assert_eq!(next.max_tmpfs_kb, Some(512));

    // 删失带 tmpfs：ema NULL、max = 512×1.25 = 640。
    let (state, decision) = next_learned_state(
        None,
        &node_oom_tmpfs(SampleBackend::Cgroup, 2000, 512),
        None,
        1.25,
        KEY.0,
        KEY.1,
        KEY.2,
    );
    let next = state.expect("first sample must create the row");
    assert_eq!(decision, ProfileUpdateDecision::Censored);
    assert_eq!(next.ema_tmpfs_kb, None);
    assert_eq!(next.max_tmpfs_kb, Some(640));

    // succeeded 缺 tmpfs：两列全 NULL。
    let (state, _) = next_learned_state(
        None,
        &succeeded(SampleBackend::Cgroup, 2000, None, None),
        None,
        1.25,
        KEY.0,
        KEY.1,
        KEY.2,
    );
    let next = state.expect("first sample must create the row");
    assert_eq!(next.ema_tmpfs_kb, None);
    assert_eq!(next.max_tmpfs_kb, None);
}

/// sticky-cgroup 可观测性：cgroup 画像遇 proc 样本的静默 skip 显式 warn
///（带 product/pkg/arch 与两端口径）；同口径样本不告警。
#[test]
fn sticky_proc_sample_under_cgroup_profile_warns() {
    let cur = LearnedState {
        ema_mem_kb: Some(1000),
        max_mem_kb: Some(1200),
        ema_tmpfs_kb: None,
        max_tmpfs_kb: None,
        ema_ncpu: None,
        max_ncpu: None,
        samples: 5,
        sample_ncpu: None,
        backend: Some(SampleBackend::Cgroup),
        censored: false,
    };
    let out = crate::test_util::with_capture(|| {
        let (_, decision) = next_learned_state(
            Some(&cur),
            &succeeded(SampleBackend::Proc, 9000, None, None),
            None,
            1.25,
            "myprod",
            "mypkg",
            "x86_64",
        );
        assert_eq!(decision, ProfileUpdateDecision::Skipped);
    });
    assert!(out.contains("WARN"), "captured: {out}");
    assert!(out.contains("myprod"), "captured: {out}");
    assert!(out.contains("mypkg"), "captured: {out}");
    assert!(out.contains("x86_64"), "captured: {out}");
    assert!(out.contains("cgroup"), "captured: {out}");
    assert!(out.contains("proc"), "captured: {out}");

    // 同口径（cgroup）样本照常折叠，不告警。
    let out = crate::test_util::with_capture(|| {
        next_learned_state(
            Some(&cur),
            &succeeded(SampleBackend::Cgroup, 9000, None, None),
            None,
            1.25,
            KEY.0,
            KEY.1,
            KEY.2,
        );
    });
    assert!(out.is_empty(), "same-backend sample must not warn: {out}");
}

// ---------- DB 行为测试（双方言，create_test_store） ----------

/// upsert learned 行为：建行/EMA 折叠/max 同批最大/轻包门槛/列组不越界
///（学习与声明两写方互不吞写）/ CapOom 不变更。
#[tokio::test]
async fn upsert_learned_folds_threshold_and_column_group_isolation() {
    let (store, _tmp) = create_test_store().await;

    // 门槛以下的样本不建行。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded(SampleBackend::Cgroup, 100, None, None),
            Some(1000),
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    assert!(store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .is_none());

    // 首个样本建行：ema=max=样本、samples=1、口径与核数上下文落列。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded(SampleBackend::Cgroup, 2000, Some(2.0), Some(8)),
            Some(1000),
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .expect("sample above threshold must create the row");
    assert_eq!(row.learned_ema_mem_kb, Some(2000));
    assert_eq!(row.learned_max_mem_kb, Some(2000));
    assert_eq!(row.learned_samples, 1);
    assert_eq!(row.learned_backend.as_deref(), Some("cgroup"));
    assert!(!row.learned_censored);
    assert_eq!(row.learned_sample_ncpu, Some(8));
    assert_eq!(row.learned_ema_ncpu, Some(2.0));

    // 折叠：ema = round(0.4×3000 + 0.6×2000) = 2400；max 取同批最大。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded(SampleBackend::Cgroup, 3000, Some(3.0), Some(8)),
            Some(1000),
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_ema_mem_kb, Some(2400));
    assert_eq!(row.learned_max_mem_kb, Some(3000));
    assert_eq!(row.learned_samples, 2);
    assert!((row.learned_ema_ncpu.unwrap() - 2.4).abs() < 1e-9);

    // 列组隔离（学习方视角）：声明写入后学习更新不动 declared 组。
    store
        .set_declared_requirements("p", "pkg", "x86_64", Some(4096), Some(4), Some(8_000_000))
        .await
        .unwrap();
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded(SampleBackend::Cgroup, 5000, None, Some(8)),
            Some(1000),
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.declared_min_mem_kb, Some(4096));
    assert_eq!(row.declared_min_ncpu, Some(4));
    assert_eq!(row.declared_min_disk_kb, Some(8_000_000));
    assert_eq!(row.learned_ema_mem_kb, Some(3440));
    assert_eq!(row.learned_samples, 3);

    // 列组隔离（声明方视角）：set_declared 不吞学习组。
    store
        .set_declared_requirements("p", "pkg", "x86_64", Some(1), None, None)
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.declared_min_mem_kb, Some(1));
    assert!(row.declared_min_ncpu.is_none());
    assert_eq!(row.learned_ema_mem_kb, Some(3440));
    assert_eq!(row.learned_samples, 3);

    // CapOom：不进学习、不变更（防御臂）。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &ResourceSampleOutcome::CapOom,
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_samples, 3);
}

/// 删失只抬不降：NodeOom max=样本×headroom 只增不减、ema 不动、samples
/// 计入；任意 Succeeded 解锁 censored 且 max 不回降。
#[tokio::test]
async fn node_oom_censors_only_raise_and_succeeded_unlocks() {
    let (store, _tmp) = create_test_store().await;

    // 首个删失样本：max = 1000×1.25，ema NULL，samples=1，censored=1。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &node_oom(SampleBackend::Cgroup, 1000),
            None,
            1.25,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_max_mem_kb, Some(1250));
    assert_eq!(row.learned_ema_mem_kb, None);
    assert_eq!(row.learned_samples, 1);
    assert!(row.learned_censored);

    // 更小的删失样本只计样本数，max 不回降（625 < 1250）。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &node_oom(SampleBackend::Cgroup, 500),
            None,
            1.25,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_max_mem_kb, Some(1250));
    assert_eq!(row.learned_samples, 2);

    // 更大的删失样本抬 max（2000×1.25 = 2500）。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &node_oom(SampleBackend::Cgroup, 2000),
            None,
            1.25,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_max_mem_kb, Some(2500));
    assert_eq!(row.learned_samples, 3);

    // Succeeded 解锁：censored=0、ema 起算、max 不回降（800 < 2500）。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded(SampleBackend::Cgroup, 800, None, None),
            None,
            1.25,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert!(!row.learned_censored);
    assert_eq!(row.learned_ema_mem_kb, Some(800));
    assert_eq!(row.learned_max_mem_kb, Some(2500));
    assert_eq!(row.learned_samples, 4);
}

/// tmpfs 维端到端：apply_learning_sample → upsert 双列落库 → get_profile 回读；
/// α 折叠、None 穿透、删失抬升与解锁保持的 DB 形态。
#[tokio::test]
async fn apply_learning_sample_roundtrips_tmpfs_columns() {
    let (store, _tmp) = create_test_store().await;

    // 首样本带 tmpfs：ema=max=样本。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded_tmpfs(SampleBackend::Cgroup, 2000, 1000),
            Some(1000),
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_ema_tmpfs_kb, Some(1000));
    assert_eq!(row.learned_max_tmpfs_kb, Some(1000));

    // 带 tmpfs 折叠：round(0.4×2000+0.6×1000)=1400、max 同批最大。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded_tmpfs(SampleBackend::Cgroup, 3000, 2000),
            Some(1000),
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_ema_tmpfs_kb, Some(1400));
    assert_eq!(row.learned_max_tmpfs_kb, Some(2000));

    // 缺 tmpfs 观测的样本：mem 折叠（2400→3040），tmpfs 两列维持前值。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded(SampleBackend::Cgroup, 4000, None, None),
            Some(1000),
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_ema_mem_kb, Some(3040));
    assert_eq!(row.learned_ema_tmpfs_kb, Some(1400));
    assert_eq!(row.learned_max_tmpfs_kb, Some(2000));

    // 删失抬升：tmpfs=5000 → floor=6250；ema 不动、censored=1。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &node_oom_tmpfs(SampleBackend::Cgroup, 2000, 5000),
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert!(row.learned_censored);
    assert_eq!(row.learned_max_tmpfs_kb, Some(6250));
    assert_eq!(row.learned_ema_tmpfs_kb, Some(1400));

    // Succeeded 解锁：censored=0，tmpfs max 保持不回降。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded(SampleBackend::Cgroup, 1000, None, None),
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert!(!row.learned_censored);
    assert_eq!(row.learned_max_tmpfs_kb, Some(6250));
}

/// 口径 sticky + 升级重置：proc 起算折叠；cgroup 样本到达清零重算；
/// cgroup 粘滞后 proc 样本忽略、计数不计。
#[tokio::test]
async fn backend_sticky_resets_on_proc_to_cgroup_upgrade() {
    let (store, _tmp) = create_test_store().await;

    // proc 口径起算：ema 1000 → round(0.4×2000+0.6×1000)=1400、samples=2。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded(SampleBackend::Proc, 1000, None, None),
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded(SampleBackend::Proc, 2000, None, None),
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_ema_mem_kb, Some(1400));
    assert_eq!(row.learned_samples, 2);
    assert_eq!(row.learned_backend.as_deref(), Some("proc"));

    // cgroup 样本到达：清零 EMA/max/samples 按本样本重起算。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded(SampleBackend::Cgroup, 500, None, None),
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_ema_mem_kb, Some(500));
    assert_eq!(row.learned_max_mem_kb, Some(500));
    assert_eq!(row.learned_samples, 1);
    assert_eq!(row.learned_backend.as_deref(), Some("cgroup"));

    // cgroup 粘滞：proc 样本直接忽略，ema/max/samples 全不动。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded(SampleBackend::Proc, 9000, None, None),
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_ema_mem_kb, Some(500));
    assert_eq!(row.learned_max_mem_kb, Some(500));
    assert_eq!(row.learned_samples, 1);
}

/// 升级重置只清 mem/ncpu 口径：tmpfs 是 statfs 绝对值，历史 EMA/max 保留并
/// 继续按样本折叠；重置样本无 tmpfs 观测时两列原样保留；删失只抬 max。
#[tokio::test]
async fn backend_upgrade_preserves_tmpfs_history() {
    let (store, _tmp) = create_test_store().await;

    // proc 起算：tmpfs ema 300 → round(0.4×400+0.6×300)=340、max=400。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded_tmpfs(SampleBackend::Proc, 1000, 300),
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded_tmpfs(SampleBackend::Proc, 2000, 400),
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_ema_tmpfs_kb, Some(340));
    assert_eq!(row.learned_max_tmpfs_kb, Some(400));

    // cgroup 升级样本不带 tmpfs：mem 清零重算，tmpfs 两列原值保留。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded(SampleBackend::Cgroup, 500, None, None),
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_ema_mem_kb, Some(500));
    assert_eq!(row.learned_max_mem_kb, Some(500));
    assert_eq!(row.learned_samples, 1);
    assert_eq!(row.learned_backend.as_deref(), Some("cgroup"));
    assert_eq!(row.learned_ema_tmpfs_kb, Some(340));
    assert_eq!(row.learned_max_tmpfs_kb, Some(400));

    // cgroup 后续带 tmpfs 样本：ema = round(0.4×100+0.6×340)=244、max 不回降。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded_tmpfs(SampleBackend::Cgroup, 600, 100),
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_ema_tmpfs_kb, Some(244));
    assert_eq!(row.learned_max_tmpfs_kb, Some(400));
    assert_eq!(row.learned_samples, 2);

    // 删失只抬 max：1000×1.25 抬到 1250，EMA 不动。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &node_oom_tmpfs(SampleBackend::Cgroup, 1000, 1000),
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_ema_tmpfs_kb, Some(244));
    assert_eq!(row.learned_max_tmpfs_kb, Some(1250));
    assert!(row.learned_censored);
    assert_eq!(row.learned_samples, 3);
}

/// 声明面查找：精确 arch 优先、未命中回退 'any'；unset 只清 declared
/// 不删行（learned 资产保留、'any' 回退重新生效）；list 列举产品全行。
#[tokio::test]
async fn declared_lookup_falls_back_to_any_and_unset_keeps_row() {
    let (store, _tmp) = create_test_store().await;

    // 未声明：None。
    assert!(store
        .find_declared_requirements("p", "pkg", "x86_64")
        .await
        .unwrap()
        .is_none());

    // 'any' 哨兵：精确 arch 未命中回退命中。
    store
        .set_declared_requirements("p", "pkg", "any", Some(2048), None, Some(1_000_000))
        .await
        .unwrap();
    let hit = store
        .find_declared_requirements("p", "pkg", "x86_64")
        .await
        .unwrap()
        .expect("any-sentinel must serve undeclared arches");
    assert_eq!(hit.arch, "any");
    assert_eq!(hit.min_mem_kb, Some(2048));
    assert_eq!(hit.min_ncpu, None);
    assert_eq!(hit.min_disk_kb, Some(1_000_000));

    // 精确 arch 优先。
    store
        .set_declared_requirements("p", "pkg", "x86_64", Some(4096), Some(2), None)
        .await
        .unwrap();
    let hit = store
        .find_declared_requirements("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(hit.arch, "x86_64");
    assert_eq!(hit.min_mem_kb, Some(4096));
    assert_eq!(hit.min_ncpu, Some(2));

    // 学习通道写入后 unset：行保留、learned 完好、declared 清空、
    // 'any' 回退重新生效。
    store
        .apply_learning_sample(
            "p",
            "pkg",
            "x86_64",
            &succeeded(SampleBackend::Cgroup, 2000, None, None),
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    store
        .unset_declared_requirements("p", "pkg", "x86_64")
        .await
        .unwrap();
    let hit = store
        .find_declared_requirements("p", "pkg", "x86_64")
        .await
        .unwrap()
        .expect("'any' fallback must re-apply after exact-arch unset");
    assert_eq!(hit.arch, "any");
    let row = store
        .get_profile("p", "pkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.learned_ema_mem_kb,
        Some(2000),
        "learned asset survives declared unset"
    );
    assert!(row.declared_min_mem_kb.is_none());
    assert!(row.declared_min_ncpu.is_none());

    // 行未删：产品列举命中两条（'any' + 'x86_64'）。
    let all = store.list_profiles_by_product("p").await.unwrap();
    assert_eq!(all.len(), 2);
}

/// 批量权重快照：三维键精确命中、缺键缺席、空键集不发 SQL。
#[tokio::test]
async fn learned_weights_batch_fetches_exact_3d_keys() {
    let (store, _tmp) = create_test_store().await;
    store
        .apply_learning_sample(
            "p",
            "multi",
            "x86_64",
            &succeeded(SampleBackend::Cgroup, 2000, Some(2.0), Some(8)),
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    store
        .apply_learning_sample(
            "p",
            "multi",
            "aarch64",
            &node_oom(SampleBackend::Cgroup, 1000),
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();

    let keys = [
        ("p".to_string(), "multi".to_string(), "x86_64".to_string()),
        ("p".to_string(), "multi".to_string(), "aarch64".to_string()),
        ("p".to_string(), "ghost".to_string(), "x86_64".to_string()),
    ];
    let out = store.learned_weights_batch(&keys).await.unwrap();
    assert_eq!(out.len(), 2, "missing keys must be absent");
    let x86 = &out[&keys[0]];
    assert_eq!(x86.ema_mem_kb, Some(2000));
    assert!(!x86.censored);
    let arm = &out[&keys[1]];
    assert_eq!(arm.ema_mem_kb, None, "删失样本不进 EMA");
    assert_eq!(arm.max_mem_kb, Some(1250));
    assert!(arm.censored);

    assert!(
        store.learned_weights_batch(&[]).await.unwrap().is_empty(),
        "empty key set must skip the query"
    );
}

/// 批量声明解析：精确 arch 优先、'any' 回退、全空声明不挡回退、缺键缺席。
#[tokio::test]
async fn declared_requirements_batch_resolves_exact_then_any() {
    let (store, _tmp) = create_test_store().await;
    store
        .set_declared_requirements("p", "pkg", "any", Some(2048), None, None)
        .await
        .unwrap();
    store
        .set_declared_requirements("p", "pkg", "x86_64", Some(4096), None, Some(1_000_000))
        .await
        .unwrap();
    // 学习通道创建的行（声明全空）：不挡 'any' 回退。
    store
        .apply_learning_sample(
            "p",
            "learned-only",
            "x86_64",
            &succeeded(SampleBackend::Cgroup, 2000, None, None),
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();

    let keys = [
        ("p".to_string(), "pkg".to_string(), "x86_64".to_string()),
        ("p".to_string(), "pkg".to_string(), "aarch64".to_string()),
        (
            "p".to_string(),
            "learned-only".to_string(),
            "x86_64".to_string(),
        ),
    ];
    let out = store.declared_requirements_batch(&keys).await.unwrap();
    assert_eq!(out.len(), 2, "empty-declared and missing keys are absent");
    assert_eq!(out[&keys[0]].arch, "x86_64", "exact arch wins");
    assert_eq!(out[&keys[0]].min_mem_kb, Some(4096));
    assert_eq!(
        out[&keys[1]].arch, "any",
        "undeclared arch falls back to any"
    );
    assert_eq!(out[&keys[1]].min_mem_kb, Some(2048));
}

/// 回填播种：时间正序复用在线折算链（ema = round(0.4x + 0.6p)）、
/// max 同批最大、samples = 实折样本数、backend NULL、sample_ncpu 取最新行；
/// 只填 learned_samples = 0 的行（已有学习保留、不触碰 declared）；arch 空
/// 行跳过、NULL 峰值行不占窗口。
#[tokio::test]
async fn backfill_seeds_empty_rows_in_time_order_and_skips_occupied() {
    let (store, _tmp) = create_test_store().await;

    // succeeded 峰值样本行（写入序 = id 序 = 完成时间新→旧，最新最后写）。
    async fn seed_succeeded_peak(
        store: &StateStore,
        product: &str,
        pkg: &str,
        arch: Option<&str>,
        peak: i64,
        cpu_p90: Option<f64>,
        ncpu: Option<i64>,
    ) -> i64 {
        let task_id = crate::state::test_state::seed_task(store, product, pkg).await;
        let id = store
            .insert_build(crate::state::BuildInsert {
                product,
                pkg_name: pkg,
                phase: "pending",
                backend: "chroot",
                user: "tester",
                arch,
                priority: 0,
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store.complete_build(id, "succeeded", None).await.unwrap();
        // $N 名值绑定（双方言口径）；? 顺序占位符 SQLite 专属。
        sqlx::query(
            "UPDATE builds SET peak_rss_kb = $1, cpu_p90_cores = $2, sample_ncpu = $3 WHERE id = $4",
        )
        .bind(peak)
        .bind(cpu_p90)
        .bind(ncpu)
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
        id
    }
    seed_succeeded_peak(&store, "p", "bf", Some("x86_64"), 1000, Some(2.0), Some(4)).await;
    seed_succeeded_peak(&store, "p", "bf", Some("x86_64"), 2000, Some(3.0), Some(8)).await;
    // NULL 峰值行：不占窗口（选样与旧权重源同款），最新 id（压住 sample_ncpu）。
    let null_peak = seed_succeeded_peak(&store, "p", "bf", Some("x86_64"), 0, None, Some(16)).await;
    sqlx::query("UPDATE builds SET peak_rss_kb = NULL WHERE id = $1")
        .bind(null_peak)
        .execute(store.pool())
        .await
        .unwrap();
    seed_succeeded_peak(&store, "p", "bf", Some("x86_64"), 3000, None, None).await;
    // arch 空串行：跳过（无键可归）。
    seed_succeeded_peak(&store, "p", "bf", Some(""), 9000, None, None).await;

    // 已有学习的行：回填不得覆盖。
    store
        .apply_learning_sample(
            "p",
            "occupied",
            "x86_64",
            &succeeded(SampleBackend::Cgroup, 5000, None, Some(16)),
            None,
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    seed_succeeded_peak(&store, "p", "occupied", Some("x86_64"), 7777, None, None).await;
    // 声明-only 空行（samples=0）但无 builds 样本：不在取样窗口，不播种。
    store
        .set_declared_requirements("p", "declared-only", "x86_64", Some(4096), None, None)
        .await
        .unwrap();

    let stats = store
        .backfill_learned_from_builds(None, DEFAULT_CENSOR_HEADROOM)
        .await
        .unwrap();
    assert_eq!(stats.seeded, 1, "only the bf key is seeded");
    assert_eq!(stats.skipped_occupied, 1, "occupied row must be kept");
    assert_eq!(stats.skipped_light, 0, "no gate configured");

    // 时间正序折算：1000 → round(0.4×2000+0.6×1000)=1400 → round(0.4×3000+0.6×1400)=2040。
    let row = store
        .get_profile("p", "bf", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.learned_ema_mem_kb, Some(2040));
    assert_eq!(row.learned_max_mem_kb, Some(3000));
    assert_eq!(row.learned_samples, 3);
    assert_eq!(row.learned_backend, None, "回填行无既立口径");
    assert!(!row.learned_censored);
    assert_eq!(
        row.learned_sample_ncpu, None,
        "sample_ncpu 取最新样本行（NULL 峰值行不进窗口，无则 NULL）"
    );
    assert!(
        (row.learned_ema_ncpu.unwrap() - 2.4).abs() < 1e-9,
        "cpu 维只折叠非空 p90"
    );
    assert_eq!(row.learned_max_ncpu, Some(3.0));

    // 占用行保留在线学习值。
    let occ = store
        .get_profile("p", "occupied", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(occ.learned_ema_mem_kb, Some(5000));
    assert_eq!(occ.learned_samples, 1);

    // 声明-only 行原样（无样本键不播种）。
    let dec = store
        .get_profile("p", "declared-only", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dec.declared_min_mem_kb, Some(4096));
    assert_eq!(dec.learned_samples, 0);
}

/// 回填轻包门槛按组级套用：全轻窗口不播种（在线学习永不为它建行，
/// 播种即僵尸权重）；窗口内有一条达标即整窗折叠播种；门槛 0 等价于不设门槛。
#[tokio::test]
async fn backfill_light_gate_is_group_level() {
    let (store, _tmp) = create_test_store().await;
    async fn sample(store: &StateStore, pkg: &str, peak: i64) {
        let task_id = crate::state::test_state::seed_task(store, "p", pkg).await;
        let id = store
            .insert_build(crate::state::BuildInsert {
                product: "p",
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
        store.complete_build(id, "succeeded", None).await.unwrap();
        sqlx::query("UPDATE builds SET peak_rss_kb = $1 WHERE id = $2")
            .bind(peak)
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap();
    }
    sample(&store, "light", 1000).await;
    sample(&store, "light", 2000).await;
    sample(&store, "heavy", 1000).await;
    sample(&store, "heavy", 4000).await;

    let stats = store
        .backfill_learned_from_builds(Some(3000), DEFAULT_CENSOR_HEADROOM)
        .await
        .unwrap();
    assert_eq!(
        stats.seeded, 1,
        "only the group with a heavy sample is seeded"
    );
    assert_eq!(stats.skipped_light, 1, "all-light group must not be seeded");
    assert!(store
        .get_profile("p", "light", "x86_64")
        .await
        .unwrap()
        .is_none());
    let heavy = store
        .get_profile("p", "heavy", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        heavy.learned_ema_mem_kb,
        Some(2200),
        "seeded group folds the whole window (1000→round(0.4×4000+0.6×1000))"
    );
    assert_eq!(heavy.learned_samples, 2);

    // 门槛 0 = 不设门槛：轻包组也播种（config 允许 0 的语义）；
    // 已播种的 heavy 行被条件 upsert 保留。
    let stats = store
        .backfill_learned_from_builds(Some(0), DEFAULT_CENSOR_HEADROOM)
        .await
        .unwrap();
    assert_eq!(stats.seeded, 1, "threshold zero disables the light gate");
    assert_eq!(stats.skipped_occupied, 1);
    assert_eq!(stats.skipped_light, 0);
    let light = store
        .get_profile("p", "light", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(light.learned_ema_mem_kb, Some(1400));
    assert_eq!(light.learned_samples, 2);
}

/// 画像键是源码包基础名：同一源码包不同 NVR 版本的 succeeded 样本必须折叠
/// 进同一 (product, source_name, arch) 行（取样窗口按 builds.name 分组，版本
/// 只是历史样本维度，不另立画像）。
#[tokio::test]
async fn backfill_groups_nvr_versions_under_source_name() {
    let (store, _tmp) = create_test_store().await;
    async fn sample(store: &StateStore, nvr: &str, peak: i64) {
        let task_id = crate::state::test_state::seed_task(store, "p", nvr).await;
        let id = store
            .insert_build(crate::state::BuildInsert {
                product: "p",
                pkg_name: nvr,
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
        sqlx::query("UPDATE builds SET peak_rss_kb = $1 WHERE id = $2")
            .bind(peak)
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap();
    }
    sample(&store, "gcc-13.2.1-1.fc39", 1000).await;
    sample(&store, "gcc-14.1.1-2.fc40", 3000).await;
    sample(&store, "binutils-2.41-1.fc39", 2000).await;

    let stats = store
        .backfill_learned_from_builds(None, DEFAULT_CENSOR_HEADROOM)
        .await
        .unwrap();
    assert_eq!(stats.seeded, 2, "two source packages, not three NVRs");

    let gcc = store
        .get_profile("p", "gcc", "x86_64")
        .await
        .unwrap()
        .expect("versions of one source package must share one profile row");
    assert_eq!(gcc.learned_samples, 2);
    assert_eq!(gcc.learned_max_mem_kb, Some(3000));
    assert_eq!(
        gcc.learned_ema_mem_kb,
        Some(1800),
        "window folds across versions: 1000 → round(0.4×3000+0.6×1000)"
    );
    assert!(
        store
            .get_profile("p", "gcc-13.2.1-1.fc39", "x86_64")
            .await
            .unwrap()
            .is_none(),
        "no profile may be keyed by NVR"
    );
}

/// 回填入参校验：headroom < 1 / 非有限拒绝（与 apply_learning_sample 同口径）。
#[tokio::test]
async fn backfill_rejects_invalid_headroom() {
    let (store, _tmp) = create_test_store().await;
    for bad in [0.5, f64::NAN, f64::INFINITY] {
        let err = store
            .backfill_learned_from_builds(None, bad)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("headroom"));
    }
}
