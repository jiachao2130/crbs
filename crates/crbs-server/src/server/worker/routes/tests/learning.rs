// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! Worker API 测试：资源画像学习接线端到端。

use super::*;

/// 学习接线夹具：nspawn 构建 + request_json + 已分配 assignment + worker
/// 心跳遥测（mem_total_kb=16_000_000）。
struct LearningFixture {
    app: axum::Router,
    app_state: Arc<AppState>,
    token: String,
    worker_id: i64,
    assignment_id: i64,
    build_id: i64,
    _tmp: tempfile::TempDir,
}

async fn setup_learning_build(request_json: &str) -> LearningFixture {
    setup_learning_build_backend("nspawn", request_json).await
}

/// backend 参数化变体：口径升级重置等跨构建场景用（chroot 建立 proc
/// 口径画像）。
async fn setup_learning_build_backend(backend: &str, request_json: &str) -> LearningFixture {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());

    let (worker_id, token) = seed_worker_secret_for_test(&store, "w-learn", "x86_64")
        .await
        .unwrap();
    store
        .worker_touch_heartbeat(
            worker_id,
            crbs_core::WorkerTelemetry {
                mem_total_kb: Some(16_000_000),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let build_id = store
        .insert_build(BuildInsert {
            product: "mydist",
            pkg_name: "testpkg",
            backend,
            user: "tester",
            arch: Some("x86_64"),
            task_id: Some(crate::test_support::seed_task(&store, "mydist", "testpkg").await),
            ..Default::default()
        })
        .await
        .unwrap();
    if !request_json.is_empty() {
        store
            .set_build_request_info(build_id, "srpm", request_json)
            .await
            .unwrap();
    }
    let (assignment_id, _) = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    LearningFixture {
        app,
        app_state,
        token,
        worker_id,
        assignment_id,
        build_id,
        _tmp: tmp,
    }
}

impl LearningFixture {
    /// 同包追加第二构建并切换 fixture 指向它（首构建已终态，同 worker
    /// 可再领）：口径升级重置等跨构建学习场景用。
    async fn add_second_build(&mut self, backend: &str, request_json: &str) {
        let store = &self.app_state.state_store;
        let build_id = store
            .insert_build(BuildInsert {
                product: "mydist",
                pkg_name: "testpkg",
                backend,
                user: "tester",
                arch: Some("x86_64"),
                task_id: Some(crate::test_support::seed_task(store, "mydist", "testpkg").await),
                ..Default::default()
            })
            .await
            .unwrap();
        if !request_json.is_empty() {
            store
                .set_build_request_info(build_id, "srpm", request_json)
                .await
                .unwrap();
        }
        let (assignment_id, _) = store
            .assign_build_to_worker(build_id, self.worker_id)
            .await
            .unwrap();
        self.assignment_id = assignment_id;
        self.build_id = build_id;
    }
}

/// 以 worker 身份 POST 终态上报，返回状态码。
async fn report_with_resources(f: &LearningFixture, phase: &str, resources: &str) -> StatusCode {
    let body = format!(r#"{{"phase":"{phase}","resources":{resources}}}"#);
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/{}/assignments/{}/result",
                    f.worker_id, f.assignment_id
                ))
                .header("Authorization", format!("Bearer {}", f.token))
                .header("Content-Type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    response.status()
}

/// succeeded 折叠：样本进 EMA、口径由 builds.backend（'nspawn'→cgroup）
/// 推导（payload 无 sample_backend）、learned 计数；终态学习后同包权重
/// 缓存失效（否则新 EMA 要等 5min TTL 才对派发可见）。
#[tokio::test]
async fn report_result_succeeded_folds_profile_ema() {
    let f = setup_learning_build(r#"{"backend":"nspawn"}"#).await;
    let key = (
        "mydist".to_string(),
        "testpkg".to_string(),
        "x86_64".to_string(),
    );
    f.app_state
        .resource_weight_cache
        .fill(&key, Default::default());
    assert_eq!(
        report_with_resources(
            &f,
            "succeeded",
            r#"{"peak_rss_kb":2097152,"cpu_p90_cores":2.5,"sample_ncpu":8}"#
        )
        .await,
        StatusCode::OK
    );
    let row = f
        .app_state
        .state_store
        .get_profile("mydist", "testpkg", "x86_64")
        .await
        .unwrap()
        .expect("succeeded sample must create the profile row");
    assert_eq!(row.learned_ema_mem_kb, Some(2_097_152));
    assert_eq!(row.learned_max_mem_kb, Some(2_097_152));
    assert_eq!(row.learned_samples, 1);
    assert_eq!(row.learned_backend.as_deref(), Some("cgroup"));
    assert!(!row.learned_censored);
    assert_eq!(row.learned_ema_ncpu, Some(2.5));
    assert_eq!(row.learned_sample_ncpu, Some(8));
    assert_eq!(
        f.app_state
            .metrics
            .profile_updates_total(crate::server::metrics::ProfileUpdateKind::Learned),
        1
    );
    assert_eq!(
        f.app_state
            .metrics
            .build_oom_total(crate::server::metrics::BuildOomKind::Cap),
        0
    );
    assert!(
        f.app_state
            .resource_weight_cache
            .lookup("mydist", "testpkg", "x86_64")
            .is_none(),
        "terminal learning must invalidate the package weight cache"
    );
}

/// 偏差单向告警：实测峰值 > 生效放置下限 × 1.5 → error_summary 追加
/// "placement floor looks too low" note（黄卡通道，零 UI 改动）。
#[tokio::test]
async fn report_result_deviation_above_declared_appends_note() {
    let f = setup_learning_build(r#"{"backend":"nspawn"}"#).await;
    f.app_state
        .state_store
        .set_declared_requirements("mydist", "testpkg", "x86_64", Some(1000), None, None)
        .await
        .unwrap();
    assert_eq!(
        report_with_resources(&f, "succeeded", r#"{"peak_rss_kb":2000}"#).await,
        StatusCode::OK
    );
    let record = f
        .app_state
        .state_store
        .get_build(f.build_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        record
            .error_summary
            .as_deref()
            .unwrap_or("")
            .contains("the placement floor looks too low"),
        "deviation note must land in error_summary, got: {:?}",
        record.error_summary
    );
}

/// 阈值内（≤ 声明 × 1.5）不告警：声明的富余方向是故意余量，note 不写。
#[tokio::test]
async fn report_result_deviation_within_threshold_writes_no_note() {
    let f = setup_learning_build(r#"{"backend":"nspawn"}"#).await;
    f.app_state
        .state_store
        .set_declared_requirements("mydist", "testpkg", "x86_64", Some(1000), None, None)
        .await
        .unwrap();
    assert_eq!(
        report_with_resources(&f, "succeeded", r#"{"peak_rss_kb":1400}"#).await,
        StatusCode::OK
    );
    let record = f
        .app_state
        .state_store
        .get_build(f.build_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        record.error_summary.is_none(),
        "no note expected within deviation threshold, got: {:?}",
        record.error_summary
    );
}

/// 口径升级重置端到端：chroot 构建（proc 口径，由 builds.backend 推导）
/// 立画像后，同包 nspawn 构建（cgroup 口径）清零重起算，reset 计数、
/// learned 只计首建。
#[tokio::test]
async fn report_result_backend_upgrade_resets_profile_and_counts() {
    let mut f = setup_learning_build_backend("chroot", "").await;
    assert_eq!(
        report_with_resources(&f, "succeeded", r#"{"peak_rss_kb":2000000}"#).await,
        StatusCode::OK
    );
    let row = f
        .app_state
        .state_store
        .get_profile("mydist", "testpkg", "x86_64")
        .await
        .unwrap()
        .expect("chroot proc sample must create the profile row");
    assert_eq!(row.learned_ema_mem_kb, Some(2_000_000));
    assert_eq!(row.learned_backend.as_deref(), Some("proc"));

    f.add_second_build("nspawn", "").await;
    assert_eq!(
        report_with_resources(&f, "succeeded", r#"{"peak_rss_kb":3000000}"#).await,
        StatusCode::OK
    );
    let row = f
        .app_state
        .state_store
        .get_profile("mydist", "testpkg", "x86_64")
        .await
        .unwrap()
        .expect("cgroup sample must keep the row after reset");
    // 升级重置：EMA/max/samples 清零按 cgroup 首样本重起算。
    assert_eq!(row.learned_ema_mem_kb, Some(3_000_000));
    assert_eq!(row.learned_samples, 1);
    assert_eq!(row.learned_backend.as_deref(), Some("cgroup"));
    assert_eq!(
        f.app_state
            .metrics
            .profile_updates_total(crate::server::metrics::ProfileUpdateKind::Reset),
        1
    );
    assert_eq!(
        f.app_state
            .metrics
            .profile_updates_total(crate::server::metrics::ProfileUpdateKind::Learned),
        1
    );
}

/// 轻包门槛：默认 1GiB 门槛以下的成功样本不建行（Skipped 不计 learned）。
#[tokio::test]
async fn report_result_light_package_skips_profile() {
    let f = setup_learning_build("").await;
    assert_eq!(
        report_with_resources(&f, "succeeded", r#"{"peak_rss_kb":1024}"#).await,
        StatusCode::OK
    );
    assert!(f
        .app_state
        .state_store
        .get_profile("mydist", "testpkg", "x86_64")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        f.app_state
            .metrics
            .profile_updates_total(crate::server::metrics::ProfileUpdateKind::Learned),
        0
    );
}

/// node-OOM 删失：failed + oom_killed → max=峰值×1.25、ema NULL、censored；
/// 计数 node + censored。
#[tokio::test]
async fn report_result_node_oom_censors_profile() {
    let f = setup_learning_build("").await;
    assert_eq!(
        report_with_resources(
            &f,
            "failed",
            r#"{"oom_killed":true,"peak_rss_kb":3000000,"sample_backend":"cgroup","sample_ncpu":4}"#
        )
        .await,
        StatusCode::OK
    );
    let row = f
        .app_state
        .state_store
        .get_profile("mydist", "testpkg", "x86_64")
        .await
        .unwrap()
        .expect("node-OOM must censor-create the profile row");
    assert_eq!(row.learned_max_mem_kb, Some(3_750_000));
    assert_eq!(row.learned_ema_mem_kb, None);
    assert!(row.learned_censored);
    assert_eq!(row.learned_samples, 1);
    assert_eq!(row.learned_backend.as_deref(), Some("cgroup"));
    assert_eq!(row.learned_sample_ncpu, Some(4));
    assert_eq!(
        f.app_state
            .metrics
            .build_oom_total(crate::server::metrics::BuildOomKind::Node),
        1
    );
    assert_eq!(
        f.app_state
            .metrics
            .profile_updates_total(crate::server::metrics::ProfileUpdateKind::Censored),
        1
    );
}

/// 无 peak 的 node-OOM：以节点 mem_total×0.9 为保守下界样本（16000000×0.9
/// ×1.25 = 18000000）。
#[tokio::test]
async fn report_result_node_oom_without_peak_uses_mem_total_lower_bound() {
    let f = setup_learning_build("").await;
    assert_eq!(
        report_with_resources(
            &f,
            "failed",
            r#"{"oom_killed":true,"sample_backend":"cgroup"}"#
        )
        .await,
        StatusCode::OK
    );
    let row = f
        .app_state
        .state_store
        .get_profile("mydist", "testpkg", "x86_64")
        .await
        .unwrap()
        .expect("mem_total lower bound must still censor-create the row");
    assert_eq!(row.learned_max_mem_kb, Some(18_000_000));
    assert!(row.learned_censored);
}

/// cap-OOM：撞自身 memory_max → 计数 cap、归因 note 追加 error_summary、
/// 画像行不动（不进删失学习）。
#[tokio::test]
async fn report_result_cap_oom_excludes_learning_and_attributes_note() {
    let f = setup_learning_build(r#"{"backend":"nspawn","memory_max":"1G"}"#).await;
    // 预置画像行：cap-OOM 上报后必须原样。
    f.app_state
        .state_store
        .apply_learning_sample(
            "mydist",
            "testpkg",
            "x86_64",
            &crbs_core::ResourceSampleOutcome::Succeeded {
                backend: crbs_core::SampleBackend::Cgroup,
                peak_rss_kb: 5_000_000,
                peak_tmpfs_kb: None,
                cpu_p90_cores: None,
                sample_ncpu: None,
            },
            None,
            crbs_core::DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    let before = f
        .app_state
        .state_store
        .get_profile("mydist", "testpkg", "x86_64")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        report_with_resources(
            &f,
            "failed",
            r#"{"oom_killed":true,"peak_total_kb":2000000,"peak_rss_kb":1000000,"sample_backend":"cgroup"}"#
        )
        .await,
        StatusCode::OK
    );

    let after = f
        .app_state
        .state_store
        .get_profile("mydist", "testpkg", "x86_64")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after.learned_samples, before.learned_samples,
        "cap-OOM must not learn"
    );
    assert_eq!(after.learned_max_mem_kb, before.learned_max_mem_kb);
    assert!(!after.learned_censored);
    assert_eq!(
        f.app_state
            .metrics
            .build_oom_total(crate::server::metrics::BuildOomKind::Cap),
        1
    );
    assert_eq!(
        f.app_state
            .metrics
            .profile_updates_total(crate::server::metrics::ProfileUpdateKind::CapHitExcluded),
        1
    );
    let build = f
        .app_state
        .state_store
        .get_build(f.build_id)
        .await
        .unwrap()
        .unwrap();
    let summary = build.error_summary.unwrap_or_default();
    assert!(
        summary.contains("hit its own memory_max cap"),
        "cap-OOM note must be appended to error_summary: {summary}"
    );
}

/// unknown：cap 已声明而两 peak 皆缺 → 计数 unknown、不学习、不写 note
///（无法确认撞 cap）。
#[tokio::test]
async fn report_result_unknown_oom_counts_without_learning() {
    let f = setup_learning_build(r#"{"memory_max":"2G"}"#).await;
    assert_eq!(
        report_with_resources(&f, "failed", r#"{"oom_killed":true,"cpu_secs":9.0}"#).await,
        StatusCode::OK
    );
    assert!(f
        .app_state
        .state_store
        .get_profile("mydist", "testpkg", "x86_64")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        f.app_state
            .metrics
            .build_oom_total(crate::server::metrics::BuildOomKind::Unknown),
        1
    );
    assert_eq!(
        f.app_state
            .metrics
            .profile_updates_total(crate::server::metrics::ProfileUpdateKind::Censored),
        0
    );
    let build = f
        .app_state
        .state_store
        .get_build(f.build_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !build
            .error_summary
            .unwrap_or_default()
            .contains("memory_max"),
        "unknown must not carry the cap attribution note"
    );
}

/// timeout 非 OOM / OOM（非 cap）都不学习、不计数（设计：timeout 不参与
/// 学习，node-OOM 通道仅定义 failed）。
#[tokio::test]
async fn report_result_timeout_never_learns() {
    let f = setup_learning_build("").await;
    assert_eq!(
        report_with_resources(
            &f,
            "timeout",
            r#"{"oom_killed":true,"peak_rss_kb":3000000,"sample_backend":"cgroup"}"#
        )
        .await,
        StatusCode::OK
    );
    assert!(f
        .app_state
        .state_store
        .get_profile("mydist", "testpkg", "x86_64")
        .await
        .unwrap()
        .is_none());
    for kind in crate::server::metrics::ALL_OOM_KINDS {
        assert_eq!(
            f.app_state.metrics.build_oom_total(kind),
            0,
            "timeout OOM must not count {kind:?}"
        );
    }

    // timeout 无 OOM 信号：同样不学习。
    let f = setup_learning_build("").await;
    assert_eq!(
        report_with_resources(&f, "timeout", r#"{"peak_rss_kb":3000000}"#).await,
        StatusCode::OK
    );
    assert!(f
        .app_state
        .state_store
        .get_profile("mydist", "testpkg", "x86_64")
        .await
        .unwrap()
        .is_none());
}

/// 成功构建带 oom_killed=true：峰值照常折叠 succeeded EMA（终态成功说明
/// 容量足够，观测即真实需求），但不进 OOM 计数、不删失；无内存观测的
/// 成功样本不折叠。
#[tokio::test]
async fn report_result_succeeded_with_oom_folds_ema_without_oom_counting() {
    let f = setup_learning_build("").await;
    assert_eq!(
        report_with_resources(
            &f,
            "succeeded",
            r#"{"oom_killed":true,"peak_rss_kb":3000000}"#
        )
        .await,
        StatusCode::OK
    );
    let row = f
        .app_state
        .state_store
        .get_profile("mydist", "testpkg", "x86_64")
        .await
        .unwrap()
        .expect("succeeded-with-OOM peak is a valid demand sample");
    assert_eq!(row.learned_ema_mem_kb, Some(3_000_000));
    assert_eq!(row.learned_max_mem_kb, Some(3_000_000));
    assert!(!row.learned_censored);
    assert_eq!(row.learned_samples, 1);
    assert_eq!(
        f.app_state
            .metrics
            .profile_updates_total(crate::server::metrics::ProfileUpdateKind::Learned),
        1
    );
    for kind in crate::server::metrics::ALL_OOM_KINDS {
        assert_eq!(
            f.app_state.metrics.build_oom_total(kind),
            0,
            "succeeded OOM must not count {kind:?}"
        );
    }

    // 无 peak_rss 的成功样本：无折叠主键，不建行。
    let f = setup_learning_build("").await;
    assert_eq!(
        report_with_resources(&f, "succeeded", r#"{"oom_killed":true,"cpu_secs":1.0}"#).await,
        StatusCode::OK
    );
    assert!(f
        .app_state
        .state_store
        .get_profile("mydist", "testpkg", "x86_64")
        .await
        .unwrap()
        .is_none());
}

/// cancelled：口径不变不学习（取消上报 resources 恒 None，双重防御）。
#[tokio::test]
async fn report_result_cancelled_never_learns() {
    let f = setup_learning_build("").await;
    assert_eq!(
        report_with_resources(
            &f,
            "cancelled",
            r#"{"oom_killed":true,"peak_rss_kb":3000000}"#
        )
        .await,
        StatusCode::OK
    );
    let build = f
        .app_state
        .state_store
        .get_build(f.build_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(build.phase, "cancelled");
    assert!(f
        .app_state
        .state_store
        .get_profile("mydist", "testpkg", "x86_64")
        .await
        .unwrap()
        .is_none());
    for kind in crate::server::metrics::ALL_OOM_KINDS {
        assert_eq!(f.app_state.metrics.build_oom_total(kind), 0);
    }
}

/// 老形态上报（无 resources 字段）：不学习不计数，终态照常落。
#[tokio::test]
async fn report_result_without_resources_never_learns() {
    let f = setup_learning_build("").await;
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/{}/assignments/{}/result",
                    f.worker_id, f.assignment_id
                ))
                .header("Authorization", format!("Bearer {}", f.token))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"phase":"failed"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(f
        .app_state
        .state_store
        .get_profile("mydist", "testpkg", "x86_64")
        .await
        .unwrap()
        .is_none());
    for kind in crate::server::metrics::ALL_OOM_KINDS {
        assert_eq!(f.app_state.metrics.build_oom_total(kind), 0);
    }
}
