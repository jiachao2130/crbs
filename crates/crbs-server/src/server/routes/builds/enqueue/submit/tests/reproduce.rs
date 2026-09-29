// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 复现入口：回放前置校验、时间锚解析与语义剥离。

use super::common::*;
use super::*;

/// 重放 arch 探针硬失败——opts.target 为空（noarch 注入生效域）且 SRPM
/// 不可解析时拒绝重放：Validation（400）点名文件、不含路径（路径不进
/// 信封，全路径在 warn 留痕）；静默跳过会让 noarch 重放 lead arch 与源
/// 构建系统性 diff 污染复现率分母。失败在首个子构建建成前（无 build 行，
/// guard Drop 异步收口，不在此断言防竞态）。
#[tokio::test]
async fn reproduce_fan_out_refuses_replay_when_arch_probe_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
    let app = Arc::new(AppState::for_test(
        store.clone(),
        crbs_core::config::ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));

    let srpm = tmp.path().join("hello-1.0-1.src.rpm");
    tokio::fs::write(&srpm, b"srpm-bytes").await.unwrap();

    let err = reproduce_fan_out(
        app,
        ReproduceFanOutArgs {
            product: "prod-repro".into(),
            result_dir: tmp.path().join("results"),
            opts: BuildOptions::default(),
            entries: vec![ReproduceArchEntry {
                arch: "x86_64".to_string(),
                source_build_id: 1,
                srpm_path: srpm,
            }],
            submit_user: "tester".into(),
            submit_user_id: None,
            source_pkg_name: "hello-1.0-1".into(),
        },
    )
    .await
    .unwrap_err();

    assert!(
        matches!(err,
            ApiError::Validation(ref msg)
                if msg.contains("replay arch probe failed")
                    && msg.contains("refusing replay")
                    && msg.contains("hello-1.0-1.src.rpm")
                    && msg.contains("mismatched lead arch")
                    && !msg.contains('/')
        ),
        "expected probe hard-fail Validation naming the srpm without paths, got: {err:?}"
    );

    let build_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        build_count, 0,
        "probe hard-fail happens before any child build is created"
    );
}

/// repro-from-srpm 探针硬失败——SRPM 不可解析（rpm -qp 必败）时拒绝提交：
/// Validation 点名文件、不含路径。失败在首个子构建建成前（无 build 行，
/// guard Drop 异步收口，不在此断言防竞态）。
#[tokio::test]
async fn fan_out_refuses_submission_when_replay_probe_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
    let app = Arc::new(AppState::for_test(
        store.clone(),
        crbs_core::config::ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));

    let srpm = tmp.path().join("world-2.0-1.src.rpm");
    tokio::fs::write(&srpm, b"srpm-bytes").await.unwrap();

    let err = fan_out_builds(
        app.clone(),
        FanOutArgs {
            product: "prod-replay".to_string(),
            result_dir: tmp.path().join("results"),
            srpm_paths: vec![srpm],
            opts: BuildOptions {
                repro_from_srpm: true,
                ..Default::default()
            },
            arches: arches(&["x86_64"]),
            submit_user: "tester".to_string(),
            submit_user_id: None,
            allow_move: false,
            collapse_noarch: true,
            arch_explicit: false,
            // 既有夹具按跳过语义走预检（不拒绝），显式拒绝路径由专项测试覆盖。
            skip_unsupported_arches: true,
            source_names: Vec::new(),
            task_labels: Vec::new(),
        },
    )
    .await
    .unwrap_err();

    assert!(
        matches!(err,
            ApiError::Validation(ref msg)
                if msg.contains("repro-from-srpm probe failed")
                    && msg.contains("world-2.0-1.src.rpm")
                    && !msg.contains('/')
        ),
        "expected replay probe hard-fail Validation naming the srpm without paths, got: {err:?}"
    );

    let build_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        build_count, 0,
        "replay probe hard-fail happens before any child build is created"
    );
}

/// reproduce_fan_out 入口剥离旗标与回放值：task 级 request_json 必须是
/// 清零后形态；strip 先于序列化，探针失败路径即可断言落库值。
#[tokio::test]
async fn reproduce_fan_out_strips_repro_from_srpm_semantics() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
    let app = Arc::new(AppState::for_test(
        store.clone(),
        crbs_core::config::ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));

    let srpm = tmp.path().join("hello-1.0-1.src.rpm");
    tokio::fs::write(&srpm, b"srpm-bytes").await.unwrap();

    let err = reproduce_fan_out(
        app,
        ReproduceFanOutArgs {
            product: "prod-repro".into(),
            result_dir: tmp.path().join("results"),
            opts: BuildOptions {
                repro_from_srpm: true,
                replay_build_host: Some("probehost".to_string()),
                replay_build_time: Some(42),
                ..Default::default()
            },
            entries: vec![ReproduceArchEntry {
                arch: "x86_64".to_string(),
                source_build_id: 1,
                srpm_path: srpm,
            }],
            submit_user: "tester".into(),
            submit_user_id: None,
            source_pkg_name: "hello-1.0-1".into(),
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, ApiError::Validation(ref msg) if msg.contains("replay arch probe failed")),
        "precondition: arch probe hard-fails on fake bytes (target is None), got: {err:?}"
    );

    let request_json: String = sqlx::query_scalar("SELECT request_json FROM tasks")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let opts: BuildOptions = serde_json::from_str(&request_json).unwrap();
    assert!(
        !opts.repro_from_srpm,
        "reproduce path must strip the repro-from-srpm flag"
    );
    assert_eq!(
        opts.replay_build_host, None,
        "replayed values must be stripped"
    );
    assert_eq!(opts.replay_build_time, None);
}

/// repro_mode_note_text 文案变体：回放值与"环境未还原"声明；BUILDHOST 非
/// 产品自产值追加"仅供参考"；产品值 None 跳过比对；头字段缺失 (none) 占位。
#[test]
fn repro_mode_note_text_variants() {
    let note = repro_mode_note_text(Some("probehost"), Some(1_700_000_000), Some("crbs"));
    assert!(note.contains("BUILDHOST=probehost"), "got: {note}");
    assert!(note.contains("BUILDTIME=1700000000"), "got: {note}");
    assert!(note.contains("NOT restored"), "got: {note}");
    assert!(note.contains("informational only"), "got: {note}");

    let note = repro_mode_note_text(Some("crbs"), Some(0), Some("crbs"));
    assert!(note.contains("BUILDHOST=crbs"), "got: {note}");
    assert!(
        note.contains("BUILDTIME=0"),
        "BUILDTIME=0 must be noted verbatim"
    );
    assert!(!note.contains("informational only"), "got: {note}");

    let note = repro_mode_note_text(Some("probehost"), Some(1), None);
    assert!(!note.contains("informational only"), "got: {note}");

    let note = repro_mode_note_text(None, None, Some("crbs"));
    assert!(note.contains("BUILDHOST=(none)"), "got: {note}");
    assert!(note.contains("BUILDTIME=(none)"), "got: {note}");
}

/// submit 侧确定性前置断言：deterministic 产品 + hub 全局 dnf_cache_enabled
/// =false（AppState 测试默认）→ 提交即拒；产品级 dnf_cache_enabled=true 且
/// build_target 非 ba → 放行；配置读不到 → 按非 deterministic 处理。
#[tokio::test]
async fn deterministic_submit_preconditions_gate() {
    let (app, tmp) = test_app_with_product("det-prod", None).await;
    let cfg = crbs_core::config::ProductConfig::from_str(
        "base_packages = [\"bash\"]\ndeterministic = true\n\n[[repos]]\n\
         name = \"base\"\nbaseurl = \"http://example.com/base/$basearch\"\ngpgcheck = false\n",
    )
    .unwrap();
    update_test_product(&app, "det-prod", &cfg).await;

    let args = FanOutArgs {
        product: "det-prod".into(),
        result_dir: tmp.path().join("results"),
        srpm_paths: vec![],
        opts: Default::default(),
        arches: vec!["x86_64".into()],
        submit_user: "tester".into(),
        submit_user_id: None,
        allow_move: false,
        collapse_noarch: true,
        arch_explicit: false,
        // 既有夹具按跳过语义走预检（不拒绝），显式拒绝路径由专项测试覆盖。
        skip_unsupported_arches: true,
        source_names: Vec::new(),
        task_labels: Vec::new(),
    };
    // 全局 dnf_cache_enabled=false（AppState 测试默认）→ 拒
    let err = assert_deterministic_submit_preconditions(&app, &args)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ApiError::Validation(msg) if msg.contains("dnf_cache_enabled")),
        "expected deterministic submit precondition error, got: {err:?}"
    );

    // 产品级 rescue：dnf_cache_enabled=true + bb → 放行
    let mut rescued = cfg.clone();
    rescued.dnf_cache_enabled = Some(true);
    update_test_product(&app, "det-prod", &rescued).await;
    assert!(
        assert_deterministic_submit_preconditions(&app, &args)
            .await
            .unwrap()
            .0
    );

    // 请求 stage=ba → 拒（stage 覆盖链最优先）
    let mut ba_args = FanOutArgs {
        opts: BuildOptions {
            stage: Some("ba".into()),
            ..Default::default()
        },
        ..args
    };
    ba_args.srpm_paths = vec![];
    let err = assert_deterministic_submit_preconditions(&app, &ba_args)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ApiError::Validation(msg) if msg.contains("'bb'")),
        "expected deterministic build_target validation error, got: {err:?}"
    );

    // 非 deterministic 产品：直接 Ok(false)（含 ba stage 也不受影响）
    let plain = crbs_core::config::ProductConfig::from_str(
        "base_packages = [\"bash\"]\n\n[[repos]]\n\
         name = \"base\"\nbaseurl = \"http://example.com/base/$basearch\"\ngpgcheck = false\n",
    )
    .unwrap();
    update_test_product(&app, "det-prod", &plain).await;
    let (flag, resolved) = assert_deterministic_submit_preconditions(&app, &ba_args)
        .await
        .unwrap();
    assert!(!flag);
    assert!(resolved.is_some());
}
