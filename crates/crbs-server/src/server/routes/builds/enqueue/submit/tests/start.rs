// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 启动路径：repo 消费轴、架构解析与 noarch 映射。

use super::common::*;
use super::*;

/// 消费轴合流三因子矩阵（visibility × 产品 repo-consume × CLI --no-consume，
/// 2×2×2）：private 一票否决、产品显式关闭、逐构建收紧，三者任一命中即
/// 不消费；全部放行才消费。
#[test]
fn repo_consume_effective_matrix() {
    for (public, product_consume, cli_no, want) in [
        (true, None, false, true), // 全默认 → 消费
        (true, None, true, false), // CLI 收紧
        (true, Some(true), false, true),
        (true, Some(true), true, false),
        (true, Some(false), false, false), // 产品关闭
        (true, Some(false), true, false),
        (false, None, false, false), // private 一票否决
        (false, Some(true), false, false),
    ] {
        let got = repo_consume_effective(public, product_consume, cli_no);
        assert_eq!(
            got, want,
            "matrix(public={public}, product_consume={product_consume:?}, cli_no_consume={cli_no})"
        );
    }
}

/// resolve_repo_axis_flags 集成：public + 默认配置 + 默认选项 = 双轴放行；
/// 产品 `repo-consume=false` / CLI `no_consume` / private 产品分别压下消费轴；
/// 发布轴只看 CLI `no_publish`，与产品配置无关。各形态用独立产品（写路径
/// 建行），不走裸 SQL 改 config（绕过 resolve 缓存失效）。
#[tokio::test]
async fn resolve_repo_axis_flags_merges_three_factors() {
    let (app, _tmp) = test_app_with_product("axis-def", Some("[]")).await;
    let default_opts: BuildOptions = serde_json::from_str("{}").unwrap();

    let (publish, consume) = resolve_repo_axis_flags(&app, "axis-def", &default_opts)
        .await
        .unwrap();
    assert!(
        publish && consume,
        "public + defaults must publish and consume"
    );

    let cli_no_consume: BuildOptions = serde_json::from_str(r#"{"no_consume": true}"#).unwrap();
    let (_, consume) = resolve_repo_axis_flags(&app, "axis-def", &cli_no_consume)
        .await
        .unwrap();
    assert!(!consume, "CLI no_consume must tighten consumption");

    let cli_no_publish: BuildOptions = serde_json::from_str(r#"{"no_publish": true}"#).unwrap();
    let (publish, consume) = resolve_repo_axis_flags(&app, "axis-def", &cli_no_publish)
        .await
        .unwrap();
    assert!(!publish, "CLI no_publish must stop publishing");
    assert!(
        consume,
        "publish tightening must not leak into consume axis"
    );

    // 产品 repo-consume=false：消费轴压下，发布轴不动。
    let axis_off = |repo_consume: Option<bool>| crbs_core::config::ProductConfig {
        base_packages: vec!["bash".into()],
        repos: vec![crbs_core::config::RepoConfig {
            name: "base".into(),
            baseurl: "http://example/repo".into(),
            ..Default::default()
        }],
        repo_consume,
        ..Default::default()
    };
    let store = &app.state_store;
    store
        .create_product(crbs_core::CreateProductInput {
            name: "axis-off",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: crbs_core::VISIBILITY_PUBLIC,
            config: &axis_off(Some(false)),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();
    let (publish, consume) = resolve_repo_axis_flags(&app, "axis-off", &default_opts)
        .await
        .unwrap();
    assert!(!consume, "product repo-consume=false must stop consumption");
    assert!(
        publish,
        "product consume switch must not touch the publish axis"
    );

    // private 产品：消费轴一票否决（owner_id 非空满足官方产品 CHECK）。
    store
        .create_product(crbs_core::CreateProductInput {
            name: "axis-priv",
            display_name: None,
            owner_id: Some(
                sqlx::query_scalar::<_, i64>(
                    "INSERT INTO users (name, role) VALUES ('axis-owner', 'admin') RETURNING id",
                )
                .fetch_one(store.pool())
                .await
                .unwrap(),
            ),
            parent_id: None,
            visibility: "private",
            config: &axis_off(None),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();
    let (publish, consume) = resolve_repo_axis_flags(&app, "axis-priv", &default_opts)
        .await
        .unwrap();
    assert!(!consume, "private product must veto consumption");
    assert!(
        publish,
        "private visibility must not touch the publish axis"
    );
}

#[tokio::test]
async fn resolve_arches_rejects_traversal_cli_arch() {
    let (app, _tmp) = test_app_with_product("prod-no-arches", None).await;
    let err = resolve_arches(&app, "prod-no-arches", Some(&arches(&["../foo"])), None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ApiError::Validation(ref msg) if msg.contains("../foo")),
        "expected Validation for '../foo', got: {err:?}"
    );
}

#[tokio::test]
async fn resolve_arches_rejects_slash_cli_arch_for_unknown_product() {
    let (app, _tmp) = test_app_with_product("other-prod", None).await;
    let err = resolve_arches(&app, "does-not-exist", Some(&arches(&["a/b"])), None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ApiError::Validation(ref msg) if msg.contains("a/b")),
        "expected Validation for 'a/b', got: {err:?}"
    );
}

#[tokio::test]
async fn resolve_arches_rejects_empty_cli_arch() {
    let (app, _tmp) = test_app_with_product("prod-no-arches", None).await;
    let err = resolve_arches(&app, "prod-no-arches", Some(&arches(&[""])), None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ApiError::Validation(ref msg) if msg.contains("empty")),
        "expected Validation for empty arch, got: {err:?}"
    );
}

#[tokio::test]
async fn resolve_arches_accepts_valid_cli_arch() {
    let (app, _tmp) = test_app_with_product("prod-no-arches", None).await;
    let resolved = resolve_arches(&app, "prod-no-arches", Some(&arches(&["x86_64"])), None)
        .await
        .unwrap();
    assert_eq!(resolved, vec!["x86_64".to_string()]);
}

#[tokio::test]
async fn resolve_arches_rejects_invalid_product_declared_arch() {
    let (app, _tmp) = test_app_with_product("prod-bad-arches", Some("[\"x86_64\", \"a/b\"]")).await;
    let err = resolve_arches(&app, "prod-bad-arches", None, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ApiError::Validation(ref msg) if msg.contains("a/b")),
        "expected Validation for product-declared 'a/b', got: {err:?}"
    );
}

#[tokio::test]
async fn resolve_arches_maps_product_noarch_to_concrete() {
    let (app, _tmp) = test_app_with_product("prod-mixed", Some("[\"x86_64\", \"noarch\"]")).await;
    let resolved = resolve_arches(&app, "prod-mixed", None, None)
        .await
        .unwrap();
    assert_eq!(resolved, vec!["x86_64".to_string()]);
}

#[tokio::test]
async fn resolve_arches_maps_cli_noarch_to_concrete() {
    let (app, _tmp) =
        test_app_with_product("prod-mixed-cli", Some("[\"x86_64\", \"noarch\"]")).await;
    let resolved = resolve_arches(&app, "prod-mixed-cli", Some(&arches(&["noarch"])), None)
        .await
        .unwrap();
    assert_eq!(resolved, vec!["x86_64".to_string()]);
}

#[tokio::test]
async fn resolve_arches_rejects_pure_noarch_product() {
    let (app, _tmp) = test_app_with_product("prod-noarch-only", Some("[\"noarch\"]")).await;
    let err = resolve_arches(&app, "prod-noarch-only", None, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ApiError::Validation(ref msg) if msg.contains("no concrete arch")),
        "expected no-concrete-arch Validation, got: {err:?}"
    );
}

#[tokio::test]
async fn map_noarch_prefers_input_concrete_arch_over_product_order() {
    let mapped = map_noarch_to_concrete(
        arches(&["noarch", "x86_64"]),
        &arches(&["aarch64", "x86_64"]),
        "prod",
    )
    .unwrap();
    assert_eq!(mapped, vec!["x86_64".to_string()]);

    let mapped =
        map_noarch_to_concrete(arches(&["noarch"]), &arches(&["aarch64", "x86_64"]), "prod")
            .unwrap();
    assert_eq!(mapped, vec!["aarch64".to_string()]);
}

/// 产品配置读取失败（resolve Err 兜底）时 CLI noarch 不放行——无产品
/// arches 无法映射派发键，放行会产出永不派发的死构建；具体 arch 照旧
/// 兜底放行。构造：config 只有 arches，chain_resolve 出口校验拒绝 →
/// Err 兜底分支。
#[tokio::test]
async fn resolve_arches_rejects_cli_noarch_when_product_config_unavailable() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
    let app = Arc::new(AppState::for_test(
        store.clone(),
        crbs_core::config::ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let config =
        crbs_core::config::ProductConfig::from_str("arches = [\"aarch64\", \"x86_64\"]").unwrap();
    store
        .create_product(crbs_core::CreateProductInput {
            name: "prod-broken-shape",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: crbs_core::VISIBILITY_PUBLIC,
            config: &config,
            changed_by_user_id: None,
            reason: Some("noarch fallback rejection test"),
        })
        .await
        .unwrap();

    let err = resolve_arches(&app, "prod-broken-shape", Some(&arches(&["noarch"])), None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ApiError::Validation(ref msg) if msg.contains("product config unavailable")),
        "expected noarch rejection on unavailable product config, got: {err:?}"
    );

    let resolved = resolve_arches(&app, "prod-broken-shape", Some(&arches(&["x86_64"])), None)
        .await
        .unwrap();
    assert_eq!(resolved, vec!["x86_64".to_string()]);
}

#[test]
fn arch_count_limit_rejects_overflow() {
    let arches: Vec<String> = (0..9).map(|i| format!("arch_{i}")).collect();
    let err = ensure_arch_count_within_limit(&arches).unwrap_err();
    assert!(
        matches!(err, ApiError::Validation(ref msg) if msg.contains("max 8")),
        "expected max-8 message, got: {err:?}"
    );
    let arches: Vec<String> = (0..8).map(|i| format!("arch_{i}")).collect();
    assert!(ensure_arch_count_within_limit(&arches).is_ok());
}

#[test]
fn inject_noarch_target_only_fills_missing_noarch() {
    assert_eq!(
        inject_noarch_target("noarch", None).as_deref(),
        Some("noarch")
    );
    // 显式用户 target 优先，不覆盖。
    assert_eq!(inject_noarch_target("noarch", Some("x86_64")), None);
    assert_eq!(inject_noarch_target("x86_64", None), None);
}
