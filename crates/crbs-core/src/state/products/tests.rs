// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产品仓库：`products` / `product_config_history` 表的 CRUD。
//!
//! 契约：`revision` 每次 update 单调 +1（drives history + chain-resolve 缓存失效）；
//! `base_os_revision` 仅触发字段变化时抬到 `= revision`；`update_product_config`
//! 事务 `BEGIN IMMEDIATE` + 可选 `expected_revision` 乐观并发，冲突返回
//! `RevisionConflict { expected, current }` 供 server 映射 HTTP 409；可见性检查在
//! server 层（`AuthContext` 在 crbs-server）。
use super::*;
use crate::config::{ProductConfig, RepoConfig};
use crate::state::StateStore;
use std::path::PathBuf;
use tempfile::TempDir;

fn sample_config() -> ProductConfig {
    ProductConfig {
        product: Some("mydist".into()),
        base_packages: vec!["bash".into(), "gcc".into()],
        repos: vec![RepoConfig {
            name: "base".into(),
            baseurl: "http://example/repo".into(),
            enabled: true,
            gpgcheck: false,
            gpgkey: None,
            priority: 99,
            cost: 1000,
            module_hotfixes: false,
            exclude: vec![],
            includepkgs: vec![],
            extra: None,
        }],
        ..Default::default()
    }
}

async fn fresh_store() -> (StateStore, TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::new_with_db_path(&tmp.path().join("state.db"), tmp.path())
        .await
        .unwrap();
    (store, tmp)
}

/// 测试用官方产品创建包装。
fn official<'a>(name: &'a str, cfg: &'a ProductConfig) -> CreateProductInput<'a> {
    CreateProductInput {
        name,
        display_name: None,
        owner_id: None,
        parent_id: None,
        visibility: "public",
        config: cfg,
        changed_by_user_id: None,
        reason: None,
    }
}

#[tokio::test]
async fn create_and_get_official_product() {
    let (store, _tmp) = fresh_store().await;
    let cfg = sample_config();
    let id = store
        .create_product(CreateProductInput {
            display_name: Some("My Distro 4"),
            reason: Some("seed"),
            ..official("mydist", &cfg)
        })
        .await
        .unwrap();
    let rec = store.get_product_by_id(id).await.unwrap().unwrap();
    assert_eq!(rec.name, "mydist");
    assert_eq!(rec.display_name.as_deref(), Some("My Distro 4"));
    assert_eq!(rec.owner_id, None);
    assert_eq!(rec.visibility, "public");
    assert_eq!(rec.revision, 1);
    assert_eq!(rec.base_os_revision, 1);
    assert_eq!(rec.config.base_packages, vec!["bash", "gcc"]);

    let by_name = store
        .get_official_product_by_name("mydist")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_name.id, id);

    let hist = store.list_product_history(id).await.unwrap();
    assert_eq!(hist.len(), 1);
    assert_eq!(hist[0].revision, 1);
    assert_eq!(hist[0].reason.as_deref(), Some("seed"));
}

#[tokio::test]
async fn list_products_returns_stub() {
    let (store, _tmp) = fresh_store().await;
    let cfg = sample_config();
    store.create_product(official("a", &cfg)).await.unwrap();
    store.create_product(official("b", &cfg)).await.unwrap();
    let list = store.list_products().await.unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].name, "a");
    assert_eq!(list[1].name, "b");
}

/// owner 过滤（/ui/me 镜像）：只回该 owner 产品、按 name 排序，官方/他人不混入。
#[tokio::test]
async fn list_products_by_owner_filters_and_sorts() {
    let (store, _tmp) = fresh_store().await;
    let cfg = sample_config();
    let alice = store.create_user("alice", "builder").await.unwrap();
    let bob = store.create_user("bob", "builder").await.unwrap();

    store
        .create_product(official("official", &cfg))
        .await
        .unwrap();
    for (name, owner) in [("zeta", alice), ("alpha", alice), ("beta", bob)] {
        store
            .create_product(CreateProductInput {
                owner_id: Some(owner),
                visibility: "private",
                ..official(name, &cfg)
            })
            .await
            .unwrap();
    }

    let owned = store.list_products_by_owner(alice).await.unwrap();
    let names: Vec<_> = owned.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "zeta"]);
    assert!(owned.iter().all(|p| p.owner_id == Some(alice)));

    let owned = store.list_products_by_owner(bob).await.unwrap();
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0].name, "beta");

    let carol = store.create_user("carol", "viewer").await.unwrap();
    assert!(store
        .list_products_by_owner(carol)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn update_bumps_revision_but_not_base_os_for_non_trigger_field() {
    let (store, _tmp) = fresh_store().await;
    let cfg = sample_config();
    let id = store
        .create_product(official("mydist", &cfg))
        .await
        .unwrap();

    let mut new_cfg = cfg.clone();
    let mut macros = std::collections::BTreeMap::new();
    macros.insert("dist".into(), ".mydist".into());
    new_cfg.rpm_macros = Some(macros);

    let out = store
        .update_product_config(id, &new_cfg, None, Some("add dist macro"), None)
        .await
        .unwrap();
    assert_eq!(out.revision, 2);
    assert!(!out.base_os_bumped);
    assert_eq!(out.base_os_revision, 1);

    let rec = store.get_product_by_id(id).await.unwrap().unwrap();
    assert_eq!(rec.revision, 2);
    assert_eq!(rec.base_os_revision, 1);
    let hist = store.list_product_history(id).await.unwrap();
    assert_eq!(hist.len(), 2);
    assert_eq!(hist[0].revision, 2);
}

#[tokio::test]
async fn update_bumps_base_os_for_trigger_field() {
    let (store, _tmp) = fresh_store().await;
    let cfg = sample_config();
    let id = store
        .create_product(official("mydist", &cfg))
        .await
        .unwrap();

    let mut new_cfg = cfg.clone();
    new_cfg.base_packages.push("git".into());

    let out = store
        .update_product_config(id, &new_cfg, None, Some("add git"), None)
        .await
        .unwrap();
    assert_eq!(out.revision, 2);
    assert!(out.base_os_bumped);
    assert_eq!(out.base_os_revision, 2);
}

/// 只改 `+base_packages`（append 字段）也抬 base_os_revision——append 同样改变
/// chain 合并后的 base_os 内容；裸 `base_packages` 两侧不动，证明触发来自 append 键。
#[tokio::test]
async fn update_bumps_base_os_for_append_field_only() {
    let (store, _tmp) = fresh_store().await;
    let mut cfg = sample_config();
    cfg.base_packages_append = vec!["git".into()];
    let id = store
        .create_product(official("mydist", &cfg))
        .await
        .unwrap();

    let mut new_cfg = cfg.clone();
    new_cfg.base_packages_append.push("vim".into());

    let out = store
        .update_product_config(id, &new_cfg, None, None, None)
        .await
        .unwrap();
    assert_eq!(out.revision, 2);
    assert!(out.base_os_bumped);
    assert_eq!(out.base_os_revision, 2);
}

#[tokio::test]
async fn update_does_not_bump_base_os_for_path_field_crbs_root() {
    // crbs_root 非触发字段：机器本地路径，chain-resolve 出口剥离、下发必被忽略，编辑不改变 base_os 内容。
    let (store, _tmp) = fresh_store().await;
    let cfg = sample_config();
    let id = store
        .create_product(official("mydist", &cfg))
        .await
        .unwrap();

    let mut new_cfg = cfg.clone();
    new_cfg.crbs_root = Some(PathBuf::from("/var/lib/crbs-alt"));

    let out = store
        .update_product_config(id, &new_cfg, None, None, None)
        .await
        .unwrap();
    assert!(!out.base_os_bumped);
    assert_eq!(out.base_os_revision, 1);
}

#[tokio::test]
async fn all_base_os_trigger_fields_bump_base_os_revision() {
    // 回归护栏：BASE_OS_TRIGGER_FIELDS 每字段逐一变更，钉死实现与常量列表一致（漏项即断言失败）。
    use crate::config::{BoolOrPackages, PostInitCommand};

    for field in BASE_OS_TRIGGER_FIELDS {
        let (store, _tmp) = fresh_store().await;
        let baseline = sample_config();
        let product_name = format!("p-{}", field.replace('_', "-"));
        let id = store
            .create_product(official(&product_name, &baseline))
            .await
            .unwrap();

        let mut mutated = baseline.clone();
        match *field {
                "base_packages" => mutated.base_packages.push("git".into()),
                "repos" => mutated.repos.push(RepoConfig {
                    name: "extra".into(),
                    baseurl: "http://example/extra".into(),
                    enabled: true,
                    gpgcheck: false,
                    gpgkey: None,
                    priority: 50,
                    cost: 1000,
                    module_hotfixes: false,
                    exclude: vec![],
                    includepkgs: vec![],
                    extra: None,
                }),
                "releasever" => mutated.releasever = Some("42".into()),
                "overlay_dir" => mutated.overlay_dir = Some(PathBuf::from("/tmp/overlay")),
                "post_init" => {
                    mutated.post_init = Some(vec![PostInitCommand {
                        command: "echo hi".into(),
                        ..Default::default()
                    }])
                }
                "builder_user" => mutated.builder_user = Some("builder".into()),
                "builder_uid" => mutated.builder_uid = Some(1001),
                "builder_group" => mutated.builder_group = Some("builders".into()),
                "builder_gid" => mutated.builder_gid = Some(1001),
                "arches" => mutated.arches.push("x86_64".into()),
                "shared_layer" => mutated.shared_layer = Some(BoolOrPackages::Bool(true)),
                "shared_layer_staleness" => {
                    mutated.shared_layer_staleness = Some("24h".into())
                }
                "backend" => mutated.backend = Some("bwrap".into()),
                "product_root" => {
                    mutated.product_root = Some(PathBuf::from("/var/lib/crbs-x"))
                }
                "base_os_path" => {
                    mutated.base_os_path = Some(PathBuf::from("/var/lib/base-os"))
                }
                // Bool(true) = 装机清单变化（merge_base_packages 追加 ccache 包 +
                // init 建 /usr/lib64/ccache 符号链接）；多形态由 ccache_enabled_all_shapes 锁定。
                "ccache_enabled" => mutated.ccache_enabled = Some(BoolOrPackages::Bool(true)),
                "+base_packages" => mutated.base_packages_append.push("git".into()),
                "+repos" => mutated.repos_append.push(RepoConfig {
                    name: "extra-append".into(),
                    baseurl: "http://example/extra-append".into(),
                    ..Default::default()
                }),
                "+arches" => mutated.arches_append.push("x86_64".into()),
                "+post_init" => {
                    mutated.post_init_append.push(PostInitCommand {
                        command: "echo append".into(),
                        ..Default::default()
                    })
                }
                other => panic!(
                    "test missing mutation for trigger field '{}'; add it to BASE_OS_TRIGGER_FIELDS coverage",
                    other
                ),
            }
        let out = store
            .update_product_config(id, &mutated, None, None, None)
            .await
            .unwrap_or_else(|e| panic!("update failed for field '{}': {:?}", field, e));

        assert!(
            out.base_os_bumped,
            "field '{}' expected to bump base_os_revision but did not",
            field
        );
        assert_eq!(out.revision, 2, "field '{}' revision", field);
        assert_eq!(
            out.base_os_revision, 2,
            "field '{}' base_os_revision should equal new revision",
            field
        );
    }
}

/// `ccache_enabled` 全形态（Bool / Packages / 翻回 None）都抬 base_os_revision：
/// 它经 merge_base_packages 改装机清单与 `.requested` 指纹，state 层拿不到 global
/// 配置算不出合并值，对原始 JSON 比较保守视同装机清单变化。
#[tokio::test]
async fn ccache_enabled_all_shapes_bump_base_os_revision() {
    use crate::config::BoolOrPackages;

    let shapes: Vec<(&str, Option<BoolOrPackages>, Option<BoolOrPackages>)> = vec![
        ("none-to-bool-true", None, Some(BoolOrPackages::Bool(true))),
        (
            "none-to-packages",
            None,
            Some(BoolOrPackages::Packages(vec!["gcc".into()])),
        ),
        (
            "bool-true-back-to-none",
            Some(BoolOrPackages::Bool(true)),
            None,
        ),
    ];
    for (label, from, to) in shapes {
        let (store, _tmp) = fresh_store().await;
        let mut baseline = sample_config();
        baseline.ccache_enabled = from;
        let product_name = format!("cc-{}", label.replace('_', "-"));
        let id = store
            .create_product(official(&product_name, &baseline))
            .await
            .unwrap();

        let mut mutated = baseline.clone();
        mutated.ccache_enabled = to;

        let out = store
            .update_product_config(id, &mutated, None, None, None)
            .await
            .unwrap_or_else(|e| panic!("update failed for '{}': {:?}", label, e));
        assert!(
            out.base_os_bumped,
            "'{}' should bump base_os_revision",
            label
        );
        assert_eq!(out.revision, 2, "'{}' revision", label);
        assert_eq!(
            out.base_os_revision, 2,
            "'{}' base_os_revision should equal new revision",
            label
        );
    }
}

#[tokio::test]
async fn non_trigger_fields_do_not_bump_base_os_revision() {
    // 反向回归：改运行时行为字段（构建策略、资源限制等）不抬 base_os_revision。
    #[allow(clippy::type_complexity)]
    let cases: Vec<(&str, Box<dyn Fn(&mut ProductConfig)>)> = vec![
        ("nocheck", Box::new(|c| c.nocheck = Some(true))),
        ("memory_max", Box::new(|c| c.memory_max = Some("2G".into()))),
        ("cpu_quota", Box::new(|c| c.cpu_quota = Some("200%".into()))),
        ("network", Box::new(|c| c.network = Some(true))),
        (
            "rpm_macros",
            Box::new(|c| {
                let mut m = std::collections::BTreeMap::new();
                m.insert("dist".into(), ".test".into());
                c.rpm_macros = Some(m);
            }),
        ),
    ];

    for (label, mutate) in cases {
        let (store, _tmp) = fresh_store().await;
        let baseline = sample_config();
        let product_name = format!("np-{}", label.replace('_', "-"));
        let id = store
            .create_product(official(&product_name, &baseline))
            .await
            .unwrap();

        let mut mutated = baseline.clone();
        mutate(&mut mutated);

        let out = store
            .update_product_config(id, &mutated, None, None, None)
            .await
            .unwrap_or_else(|e| panic!("update failed for field '{}': {:?}", label, e));

        assert_eq!(out.revision, 2, "field '{}' revision", label);
        assert!(
            !out.base_os_bumped,
            "field '{}' should not bump base_os_revision",
            label
        );
        assert_eq!(
            out.base_os_revision, 1,
            "field '{}' base_os_revision should stay at 1",
            label
        );
    }
}

#[tokio::test]
async fn update_with_expected_revision_conflict_returns_revision_conflict() {
    let (store, _tmp) = fresh_store().await;
    let cfg = sample_config();
    let id = store
        .create_product(official("mydist", &cfg))
        .await
        .unwrap();

    let mut new_cfg = cfg.clone();
    new_cfg.base_packages.push("git".into());
    let err = store
        .update_product_config(id, &new_cfg, None, None, Some(99))
        .await
        .unwrap_err();
    match err {
        CrbsError::RevisionConflict { expected, current } => {
            assert_eq!(expected, 99);
            assert_eq!(current, 1);
        }
        other => panic!("expected RevisionConflict, got {:?}", other),
    }
    let rec = store.get_product_by_id(id).await.unwrap().unwrap();
    assert_eq!(rec.revision, 1);
    assert_eq!(store.list_product_history(id).await.unwrap().len(), 1);
}

#[tokio::test]
async fn update_with_expected_revision_match_succeeds() {
    let (store, _tmp) = fresh_store().await;
    let cfg = sample_config();
    let id = store
        .create_product(official("mydist", &cfg))
        .await
        .unwrap();

    let mut new_cfg = cfg.clone();
    new_cfg.base_packages.push("git".into());
    let out = store
        .update_product_config(id, &new_cfg, None, None, Some(1))
        .await
        .unwrap();
    assert_eq!(out.revision, 2);
}

#[tokio::test]
async fn update_missing_product_returns_not_found() {
    let (store, _tmp) = fresh_store().await;
    let cfg = sample_config();
    let err = store
        .update_product_config(9999, &cfg, None, None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, CrbsError::NotFound { .. }));
}

#[tokio::test]
async fn get_missing_product_returns_none() {
    let (store, _tmp) = fresh_store().await;
    assert!(store.get_product_by_id(9999).await.unwrap().is_none());
    assert!(store
        .get_official_product_by_name("nope")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn delete_product_cascades_history() {
    let (store, _tmp) = fresh_store().await;
    let cfg = sample_config();
    let id = store
        .create_product(official("mydist", &cfg))
        .await
        .unwrap();
    let mut new_cfg = cfg.clone();
    new_cfg.base_packages.push("git".into());
    store
        .update_product_config(id, &new_cfg, None, None, None)
        .await
        .unwrap();
    assert_eq!(store.list_product_history(id).await.unwrap().len(), 2);

    store.delete_product(id).await.unwrap();
    assert!(store.get_product_by_id(id).await.unwrap().is_none());
    assert!(store.list_product_history(id).await.unwrap().is_empty());
}

#[tokio::test]
async fn delete_missing_product_returns_not_found() {
    let (store, _tmp) = fresh_store().await;
    let err = store.delete_product(9999).await.unwrap_err();
    assert!(matches!(err, CrbsError::NotFound { .. }));
}

/// 画像孤儿清理：删产品按名整行清画像（declared + learned），
/// 其他产品的画像行不受牵连。
#[tokio::test]
async fn delete_product_cleans_orphan_resource_profiles() {
    use crate::state::{ResourceSampleOutcome, SampleBackend, DEFAULT_CENSOR_HEADROOM};

    let (store, _tmp) = fresh_store().await;
    let cfg = sample_config();
    let gone = store
        .create_product(official("mydist", &cfg))
        .await
        .unwrap();
    store
        .create_product(official("otherdist", &cfg))
        .await
        .unwrap();

    store
        .set_declared_requirements("mydist", "gcc", "x86_64", Some(4096), None, None)
        .await
        .unwrap();
    store
        .apply_learning_sample(
            "mydist",
            "gcc",
            "x86_64",
            &ResourceSampleOutcome::Succeeded {
                backend: SampleBackend::Cgroup,
                peak_rss_kb: 600_000,
                peak_tmpfs_kb: None,
                cpu_p90_cores: Some(2.0),
                sample_ncpu: None,
            },
            Some(0),
            DEFAULT_CENSOR_HEADROOM,
        )
        .await
        .unwrap();
    store
        .set_declared_requirements("otherdist", "gcc", "x86_64", Some(2048), None, None)
        .await
        .unwrap();

    store.delete_product(gone).await.unwrap();
    assert!(
        store
            .get_profile("mydist", "gcc", "x86_64")
            .await
            .unwrap()
            .is_none(),
        "deleted product's profile rows must be cleaned up"
    );
    assert!(
        store
            .get_profile("otherdist", "gcc", "x86_64")
            .await
            .unwrap()
            .is_some(),
        "other products' profile rows must survive"
    );
}

#[tokio::test]
async fn history_entries_are_snapshots() {
    let (store, _tmp) = fresh_store().await;
    let cfg = sample_config();
    let id = store
        .create_product(official("mydist", &cfg))
        .await
        .unwrap();

    let mut cfg2 = cfg.clone();
    cfg2.base_packages = vec!["bash".into()];
    store
        .update_product_config(id, &cfg2, None, Some("shrink"), None)
        .await
        .unwrap();

    let h1 = store
        .get_product_history_revision(id, 1)
        .await
        .unwrap()
        .unwrap();
    let h2 = store
        .get_product_history_revision(id, 2)
        .await
        .unwrap()
        .unwrap();

    let v1: ProductConfig = serde_json::from_str(&h1.config_json).unwrap();
    let v2: ProductConfig = serde_json::from_str(&h2.config_json).unwrap();
    assert_eq!(v1.base_packages, vec!["bash", "gcc"]);
    assert_eq!(v2.base_packages, vec!["bash"]);
    assert_eq!(h1.base_os_revision, 1);
    assert_eq!(h2.base_os_revision, 2);
}

#[tokio::test]
async fn partial_unique_official_name_enforced_at_repo_layer() {
    // 锁 repo 层也踩 migrate 层 partial UNIQUE 索引；冲突归 AlreadyExists 供 server 映射 409。
    let (store, _tmp) = fresh_store().await;
    let cfg = sample_config();
    store.create_product(official("dup", &cfg)).await.unwrap();
    let err = store
        .create_product(official("dup", &cfg))
        .await
        .unwrap_err();
    match err {
        CrbsError::AlreadyExists { message } => {
            assert!(message.contains("dup"), "unexpected message: {}", message);
        }
        other => panic!("expected AlreadyExists, got {:?}", other),
    }
}

/// 行内 `config_json` 损坏必须报 `ProductChainInvalid`（classify_chain_error 归
/// Permanent、dispatch 终结分配），不得包成 `Database`——Transient → 无限 re-dispatch。
#[tokio::test]
async fn corrupted_config_json_reports_permanent_chain_error_not_database() {
    let (store, _tmp) = fresh_store().await;
    let cfg = sample_config();
    let id = store
        .create_product(official("mydist", &cfg))
        .await
        .unwrap();

    sqlx::query("UPDATE products SET config_json = '{not json' WHERE id = $1")
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();

    let err = store
        .get_product_by_name("mydist")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.starts_with("product chain invalid: mydist"),
        "must name the product and classify as ProductChainInvalid, got: {err}"
    );
    assert!(
        err.contains("config_json"),
        "must mention the unparseable field, got: {err}"
    );
    assert!(
        !err.starts_with("database error"),
        "parse failure must not classify as Database (Transient → infinite re-dispatch)"
    );
    // 变体级断言：非 Database（且 safe_message 不脱敏语义变化的 Product 族）。
    let err = store.get_product_by_name("mydist").await.unwrap_err();
    match err {
        CrbsError::ProductChainInvalid { product, reason } => {
            assert_eq!(product, "mydist");
            assert!(
                reason.contains("unparseable"),
                "unexpected reason: {reason}"
            );
        }
        CrbsError::Database(db) => {
            panic!("parse failure must not be Database (Transient): {db}")
        }
        other => panic!("expected ProductChainInvalid, got {other:?}"),
    }
}

// 共享的空 child 配置构造器

fn empty_child_config_c3() -> ProductConfig {
    ProductConfig::default()
}

// ─────────── validate_parent_id + update_product_parent ───────────

/// happy path：linear chain 3 层的最底端合法。
#[tokio::test]
async fn validate_parent_id_ok_three_layer_linear() {
    let (store, _tmp) = fresh_store().await;
    let r = store
        .create_product(official("r", &sample_config()))
        .await
        .unwrap();
    let m = store
        .create_product(CreateProductInput {
            name: "m",
            display_name: None,
            owner_id: None,
            parent_id: Some(r),
            visibility: "public",
            config: &empty_child_config_c3(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();
    store.validate_parent_id(None, m).await.unwrap();
}

/// 环检测：re-parent self → 走上去撞到自己。
#[tokio::test]
async fn validate_parent_id_direct_self_cycle_rejected() {
    let (store, _tmp) = fresh_store().await;
    let a = store
        .create_product(official("a", &sample_config()))
        .await
        .unwrap();
    let err = store.validate_parent_id(Some(a), a).await.unwrap_err();
    assert!(matches!(err, CrbsError::ProductChainCycle { .. }));
}

/// 环检测：把 root 指向自己后代 → 沿 parent 走上去必然撞到 self_id。
#[tokio::test]
async fn validate_parent_id_reparent_to_descendant_rejected() {
    let (store, _tmp) = fresh_store().await;
    let r = store
        .create_product(official("r", &sample_config()))
        .await
        .unwrap();
    let m = store
        .create_product(CreateProductInput {
            name: "m",
            display_name: None,
            owner_id: None,
            parent_id: Some(r),
            visibility: "public",
            config: &empty_child_config_c3(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();
    let err = store.validate_parent_id(Some(r), m).await.unwrap_err();
    assert!(matches!(err, CrbsError::ProductChainCycle { .. }));
}

/// 存在性：new_parent 不存在 → NotFound。
#[tokio::test]
async fn validate_parent_id_missing_parent_returns_not_found() {
    let (store, _tmp) = fresh_store().await;
    let err = store.validate_parent_id(None, 9_999_999).await.unwrap_err();
    assert!(matches!(err, CrbsError::NotFound { .. }));
}

/// 深度：构造 MAX_CHAIN_DEPTH 长的 chain，再尝试挂第 MAX+1 层 → TooDeep。
#[tokio::test]
async fn validate_parent_id_depth_cap_rejected() {
    use crate::state::product_resolve::MAX_CHAIN_DEPTH;
    let (store, _tmp) = fresh_store().await;
    let mut prev = store
        .create_product(official("p0", &sample_config()))
        .await
        .unwrap();
    for i in 1..MAX_CHAIN_DEPTH {
        prev = store
            .create_product(CreateProductInput {
                name: &format!("p{}", i),
                display_name: None,
                owner_id: None,
                parent_id: Some(prev),
                visibility: "public",
                config: &empty_child_config_c3(),
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();
    }
    let err = store.validate_parent_id(None, prev).await.unwrap_err();
    assert!(matches!(err, CrbsError::ProductChainTooDeep { .. }));
}

/// re-parent happy path：leaf 从 A 挪到同 root 兄弟 B——parent 变化 = 继承链换根，
/// base_os_revision 抬到 = new revision，history 记 parent_id=new。
#[tokio::test]
async fn update_product_parent_happy_path_bumps_revision_and_base_os() {
    let (store, _tmp) = fresh_store().await;
    let root = store
        .create_product(official("root", &sample_config()))
        .await
        .unwrap();
    let a = store
        .create_product(CreateProductInput {
            name: "a",
            display_name: None,
            owner_id: None,
            parent_id: Some(root),
            visibility: "public",
            config: &empty_child_config_c3(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();
    let b = store
        .create_product(CreateProductInput {
            name: "b",
            display_name: None,
            owner_id: None,
            parent_id: Some(root),
            visibility: "public",
            config: &empty_child_config_c3(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();
    let leaf = store
        .create_product(CreateProductInput {
            name: "leaf",
            display_name: None,
            owner_id: None,
            parent_id: Some(a),
            visibility: "public",
            config: &empty_child_config_c3(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    let before = store.get_product_by_id(leaf).await.unwrap().unwrap();
    let out = store
        .update_product_parent(leaf, Some(b), None, Some("test reparent"), None)
        .await
        .unwrap();

    assert_eq!(out.revision, before.revision + 1);
    assert!(out.base_os_bumped);
    assert_eq!(out.base_os_revision, out.revision);

    let after = store.get_product_by_id(leaf).await.unwrap().unwrap();
    assert_eq!(after.parent_id, Some(b));
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(after.base_os_revision, after.revision);

    let hist = store.list_product_history(leaf).await.unwrap();
    assert!(hist.iter().any(|h| h.revision == after.revision
        && h.parent_id == Some(b)
        && h.base_os_revision == after.revision
        && h.reason.as_deref() == Some("test reparent")));
}

/// re-parent detach：把 leaf 挪到 None → parent_id 变 NULL，revision +1，
/// detach 同样是链拓扑变化 → base_os_bumped。
#[tokio::test]
async fn update_product_parent_detach_to_root() {
    let (store, _tmp) = fresh_store().await;
    let root = store
        .create_product(official("root", &sample_config()))
        .await
        .unwrap();
    let leaf = store
        .create_product(CreateProductInput {
            name: "leaf",
            display_name: None,
            owner_id: None,
            parent_id: Some(root),
            visibility: "public",
            config: &empty_child_config_c3(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    let out = store
        .update_product_parent(leaf, None, None, None, None)
        .await
        .unwrap();
    assert!(out.base_os_bumped);
    assert_eq!(out.base_os_revision, out.revision);
    let after = store.get_product_by_id(leaf).await.unwrap().unwrap();
    assert_eq!(after.parent_id, None);
}

/// no-op reparent（目标 parent 与当前相同）：revision 照常 +1（写路径单调），
/// 但链未变 → base_os_bumped == false、base_os_revision 保持。
#[tokio::test]
async fn update_product_parent_noop_same_parent_bumps_revision_only() {
    let (store, _tmp) = fresh_store().await;
    let root = store
        .create_product(official("root", &sample_config()))
        .await
        .unwrap();
    let leaf = store
        .create_product(CreateProductInput {
            name: "leaf",
            display_name: None,
            owner_id: None,
            parent_id: Some(root),
            visibility: "public",
            config: &empty_child_config_c3(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    let before = store.get_product_by_id(leaf).await.unwrap().unwrap();
    let out = store
        .update_product_parent(leaf, Some(root), None, None, None)
        .await
        .unwrap();

    assert_eq!(out.revision, before.revision + 1);
    assert!(!out.base_os_bumped);
    assert_eq!(out.base_os_revision, before.base_os_revision);
    let after = store.get_product_by_id(leaf).await.unwrap().unwrap();
    assert_eq!(after.parent_id, Some(root));
    assert_eq!(after.base_os_revision, before.base_os_revision);
}

/// 带门的 reparent 在 revision 被并发改动后必须失败：PUT 复合写 = config 更新
/// 事务 + reparent 事务两段，乐观锁契约只盖前半段，无门时 reparent 静默叠在
/// 并发写上（SQLite 串行写语义同理）。对照臂：以最新 revision 为门放行。
#[tokio::test]
async fn update_product_parent_gate_rejects_stale_revision() {
    let (store, _tmp) = fresh_store().await;
    let root = store
        .create_product(official("gate-root", &sample_config()))
        .await
        .unwrap();
    let other = store
        .create_product(CreateProductInput {
            name: "gate-other",
            display_name: None,
            owner_id: None,
            parent_id: Some(root),
            visibility: "public",
            config: &empty_child_config_c3(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();
    let leaf = store
        .create_product(CreateProductInput {
            name: "gate-leaf",
            display_name: None,
            owner_id: None,
            parent_id: Some(root),
            visibility: "public",
            config: &empty_child_config_c3(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    let before = store.get_product_by_id(leaf).await.unwrap().unwrap();
    store
        .update_product_config(leaf, &empty_child_config_c3(), None, None, None)
        .await
        .unwrap();

    let err = store
        .update_product_parent(leaf, Some(other), None, None, Some(before.revision))
        .await
        .unwrap_err();
    match err {
        CrbsError::RevisionConflict { expected, current } => {
            assert_eq!(expected, before.revision);
            assert_eq!(current, before.revision + 1);
        }
        other_err => panic!("expected RevisionConflict, got {:?}", other_err),
    }
    let after = store.get_product_by_id(leaf).await.unwrap().unwrap();
    assert_eq!(
        after.parent_id,
        Some(root),
        "lost reparent must not change parent"
    );
    assert_eq!(after.revision, before.revision + 1);

    let out = store
        .update_product_parent(leaf, Some(other), None, None, Some(after.revision))
        .await
        .unwrap();
    assert_eq!(out.revision, after.revision + 1);
}

/// re-parent 拒环：把 r reparent 到 m（其后代）。
#[tokio::test]
async fn update_product_parent_rejects_cycle() {
    let (store, _tmp) = fresh_store().await;
    let r = store
        .create_product(official("r", &sample_config()))
        .await
        .unwrap();
    let m = store
        .create_product(CreateProductInput {
            name: "m",
            display_name: None,
            owner_id: None,
            parent_id: Some(r),
            visibility: "public",
            config: &empty_child_config_c3(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();
    let before = store.get_product_by_id(r).await.unwrap().unwrap();
    let err = store
        .update_product_parent(r, Some(m), None, None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, CrbsError::ProductChainCycle { .. }));
    let after = store.get_product_by_id(r).await.unwrap().unwrap();
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.parent_id, before.parent_id);
}

/// re-parent 后链上后代 resolve cache 递归失效（`invalidate_resolve_recursive`）：
/// 预热后把 mid 从 r1 挪到 r2，二次 chain_resolve 必须看到 r2-only（未失效则仍返回 r1 结果）。
#[tokio::test]
async fn update_product_parent_invalidates_descendant_cache() {
    let (store, _tmp) = fresh_store().await;
    let mut r1_cfg = sample_config();
    r1_cfg.base_packages = vec!["r1-only".into()];
    let mut r2_cfg = sample_config();
    r2_cfg.base_packages = vec!["r2-only".into()];
    let r1 = store.create_product(official("r1", &r1_cfg)).await.unwrap();
    let r2 = store.create_product(official("r2", &r2_cfg)).await.unwrap();
    let mid = store
        .create_product(CreateProductInput {
            name: "mid",
            display_name: None,
            owner_id: None,
            parent_id: Some(r1),
            visibility: "public",
            config: &empty_child_config_c3(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();
    let leaf = store
        .create_product(CreateProductInput {
            name: "leaf",
            display_name: None,
            owner_id: None,
            parent_id: Some(mid),
            visibility: "public",
            config: &empty_child_config_c3(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    let before = store.chain_resolve(leaf).await.unwrap();
    assert_eq!(before.config.base_packages, vec!["r1-only".to_string()]);

    store
        .update_product_parent(mid, Some(r2), None, Some("swap root"), None)
        .await
        .unwrap();

    let after = store.chain_resolve(leaf).await.unwrap();
    assert_eq!(after.config.base_packages, vec!["r2-only".to_string()]);
}

/// re-parent 缺失产品 → NotFound。
#[tokio::test]
async fn update_product_parent_missing_returns_not_found() {
    let (store, _tmp) = fresh_store().await;
    let err = store
        .update_product_parent(9_999_999, None, None, None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, CrbsError::NotFound { .. }));
}

/// update_product_config 全流程双后端回归：`SET updated_at = <dialect 表达式>` 与
/// 参数绑定混用时 sqlx Any 在 PG 上有 Bind 协议坑，SQLite 临时库测不出。
#[tokio::test]
async fn update_product_config_full_flow_runs_on_both_backends() {
    let (store, _tmp) = crate::state::test_state::create_test_store().await;
    let cfg = sample_config();
    let id = store
        .create_product(official("pg-echo", &cfg))
        .await
        .unwrap();

    let outcome = store
        .update_product_config(id, &cfg, None, Some("regression"), Some(1))
        .await
        .unwrap();
    assert_eq!(outcome.revision, 2);

    let record = store.get_product_by_id(id).await.unwrap().unwrap();
    assert_eq!(record.revision, 2);
}

/// 确定性等待：轮询 `pg_stat_activity`（独立连接而非 A、单查询限时 500ms，出错或
/// 卡顿弃用重连）直到 store 事务挂上 A 的行锁（state='active' 且
/// wait_event_type='Lock'）；10ms 步进、5s 超时 panic。依赖 `--test-threads=1`
/// 纪律：共享库内无其它锁等待连接，计数不误报。
async fn wait_for_row_lock_waiter(url: &str) {
    use sqlx::Connection;
    const POLL: &str = "SELECT count(*) FROM pg_stat_activity \
         WHERE state = 'active' AND wait_event_type = 'Lock' \
         AND pid <> pg_backend_pid()";
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut poll_conn: Option<sqlx::AnyConnection> =
        Some(sqlx::AnyConnection::connect(url).await.unwrap());
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "no transaction blocked on the row lock within 5s"
        );
        let Some(conn) = poll_conn.as_mut() else {
            poll_conn = Some(sqlx::AnyConnection::connect(url).await.unwrap());
            continue;
        };
        match tokio::time::timeout(
            std::time::Duration::from_millis(500),
            sqlx::query_scalar::<_, i64>(POLL).fetch_one(conn),
        )
        .await
        {
            Ok(Ok(0)) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            Ok(Ok(_)) => return,
            // 出错/卡顿：弃用连接，下轮重连
            _ => {
                poll_conn = None;
            }
        }
    }
}

/// PG 并发竞态守卫：裸连接 A 持未提交 revision bump（行锁），store 快照读旧值过
/// 前置检查，UPDATE `AND revision` 谓词阻塞、A 提交后落空（0 行）→
/// `RevisionConflict`（409）。SQLite 被 BEGIN IMMEDIATE 串行化、
/// 结构性不可触发，仅 CRBS_TEST_DATABASE_URL 指向 PG 时运行；快照先于 A 提交由
/// [`wait_for_row_lock_waiter`] 钉死，时序翻转也走前置检查返回同一冲突对。
#[tokio::test]
async fn update_product_config_pg_row_lock_race_returns_revision_conflict() {
    let url = std::env::var("CRBS_TEST_DATABASE_URL").unwrap_or_default();
    if !(url.starts_with("postgres:") || url.starts_with("postgresql:")) {
        // 无 PG（未设置/空/SQLite）跳过；空串按未设置处理，否则报 RelativeUrlWithoutBase。
        eprintln!("skipped: CRBS_TEST_DATABASE_URL is not a PostgreSQL URL");
        return;
    }
    let (store, _tmp) = crate::state::test_state::create_test_store().await;
    let cfg = sample_config();
    let id = store
        .create_product(official("pg-race", &cfg))
        .await
        .unwrap();

    // A：持未提交 revision bump（行锁）。
    use sqlx::Connection;
    StateStore::install_any_drivers();
    let mut a = sqlx::AnyConnection::connect(&url).await.unwrap();
    sqlx::query("BEGIN").execute(&mut a).await.unwrap();
    sqlx::query("UPDATE products SET revision = $1 WHERE id = $2")
        .bind(2_i64)
        .bind(id)
        .execute(&mut a)
        .await
        .unwrap();

    let mut new_cfg = cfg.clone();
    new_cfg.base_packages.push("git".into());
    let handle = tokio::spawn(async move {
        store
            .update_product_config(id, &new_cfg, None, None, Some(1))
            .await
    });
    wait_for_row_lock_waiter(&url).await;
    sqlx::query("COMMIT").execute(&mut a).await.unwrap();

    let err = handle.await.unwrap().unwrap_err();
    match err {
        CrbsError::RevisionConflict { expected, current } => {
            assert_eq!(expected, 1);
            assert_eq!(current, 2);
        }
        other => panic!("expected RevisionConflict, got {:?}", other),
    }
}

/// [`update_product_config_pg_row_lock_race_returns_revision_conflict`] 的 re-parent
/// 同款：old_rev 从事务内快照读出（无调用方传入 expected），守卫兜 PG 上快照与
/// UPDATE 之间的并发提交窗口；[`wait_for_row_lock_waiter`] 保证快照先于 A COMMIT，
/// 消除时序抖动。
#[tokio::test]
async fn update_product_parent_pg_row_lock_race_returns_revision_conflict() {
    let url = std::env::var("CRBS_TEST_DATABASE_URL").unwrap_or_default();
    if !(url.starts_with("postgres:") || url.starts_with("postgresql:")) {
        eprintln!("skipped: CRBS_TEST_DATABASE_URL is not a PostgreSQL URL");
        return;
    }
    let (store, _tmp) = crate::state::test_state::create_test_store().await;
    let root = store
        .create_product(official("race-root", &sample_config()))
        .await
        .unwrap();
    let leaf = store
        .create_product(CreateProductInput {
            name: "race-leaf",
            display_name: None,
            owner_id: None,
            parent_id: Some(root),
            visibility: "public",
            config: &empty_child_config_c3(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    use sqlx::Connection;
    StateStore::install_any_drivers();
    let mut a = sqlx::AnyConnection::connect(&url).await.unwrap();
    sqlx::query("BEGIN").execute(&mut a).await.unwrap();
    sqlx::query("UPDATE products SET revision = $1 WHERE id = $2")
        .bind(2_i64)
        .bind(leaf)
        .execute(&mut a)
        .await
        .unwrap();

    let handle = tokio::spawn(async move {
        store
            .update_product_parent(leaf, None, None, None, None)
            .await
    });
    wait_for_row_lock_waiter(&url).await;
    sqlx::query("COMMIT").execute(&mut a).await.unwrap();

    let err = handle.await.unwrap().unwrap_err();
    match err {
        CrbsError::RevisionConflict { expected, current } => {
            assert_eq!(expected, 1);
            assert_eq!(current, 2);
        }
        other => panic!("expected RevisionConflict, got {:?}", other),
    }
}

/// 唯一键违反文本判定必须覆盖双方言：SQLite 与 PG 的同名冲突都要归到
/// AlreadyExists(409)，否则 PG 错标 Database(500)。纯文本判定，无 DB 也能锁行为。
#[test]
fn unique_violation_msg_matches_both_dialects() {
    assert!(is_unique_violation_msg(
        "UNIQUE constraint failed: products.name"
    ));
    // PostgreSQL: sqlx-postgres（23505）
    assert!(is_unique_violation_msg(
        r#"duplicate key value violates unique constraint "products_name_key""#
    ));
    assert!(!is_unique_violation_msg(
        "FOREIGN KEY constraint failed: product_config_history.product_id"
    ));
    assert!(!is_unique_violation_msg("connection refused"));
}

/// 产品删除的取消域与引用释放（RETURNING 按实际翻转行）：'assigned' 一并取消
///（否则删除后 assigned 构建仍会被 worker 拉取执行）；被取消构建的层引用释放、
/// 终态构建不动（泄漏修复域）；行缺失的层引用（d-gone）容忍（Ok(0) warn 跳过），
/// 不回滚删除事务。
#[tokio::test]
async fn delete_product_cancels_assigned_and_releases_layer_refs() {
    let (store, _tmp) = fresh_store().await;
    let cfg = sample_config();
    let id = store
        .create_product(official("mydist", &cfg))
        .await
        .unwrap();

    let mk = |pkg: String, phase: &'static str, digest: Option<String>| {
        let store = &store;
        async move {
            let task_id = store
                .insert_task(crate::TaskInsert {
                    product: "mydist",
                    pkg_name: &pkg,
                    ..Default::default()
                })
                .await
                .unwrap();
            store
                .insert_build(crate::BuildInsert {
                    product: "mydist",
                    pkg_name: &pkg,
                    phase,
                    layer_digest: digest.as_deref(),
                    backend: "chroot",
                    user: "tester",
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };

    let b_pending = mk("p0".into(), "pending", None).await;
    let b_assigned = mk("p1".into(), "assigned", Some("d-a".into())).await;
    let b_building = mk("p2".into(), "building", Some("d-b".into())).await;
    let b_ghost = mk("p3".into(), "building", Some("d-gone".into())).await;
    let b_done = mk("p4".into(), "succeeded", Some("d-done".into())).await;

    store
        .insert_layer("d-a", "/tmp/la", "mydist", 1)
        .await
        .unwrap();
    store
        .insert_layer("d-b", "/tmp/lb", "mydist", 1)
        .await
        .unwrap();
    store
        .insert_layer("d-done", "/tmp/ldone", "mydist", 1)
        .await
        .unwrap();

    let (builds, _tasks) = store.delete_product(id).await.unwrap();
    assert_eq!(
        builds, 4,
        "pending/assigned/building (incl. ghost-layer) are cancelled, succeeded untouched"
    );

    for (build_id, expected) in [
        (b_pending, "cancelled"),
        (b_assigned, "cancelled"),
        (b_building, "cancelled"),
        (b_ghost, "cancelled"),
        (b_done, "succeeded"),
    ] {
        let (phase, completed_at, duration): (String, Option<String>, Option<i64>) =
            sqlx::query_as("SELECT phase, completed_at, duration FROM builds WHERE id = $1")
                .bind(build_id)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(phase, expected, "build {build_id} phase");
        if expected != "cancelled" {
            continue;
        }
        // 批量取消同为终态：completed_at/duration 与单构建取消同口径落值。
        assert!(
            completed_at.is_some(),
            "cancelled build {build_id} must carry completed_at for GC/retention gates"
        );
        assert!(
            duration.is_some() && duration >= Some(0),
            "cancelled build {build_id} must carry non-negative duration, got {duration:?}"
        );
    }

    let ref_of = |d: &'static str| {
        let store = &store;
        async move { store.get_layer_ref_count(d).await.unwrap() }
    };
    assert_eq!(
        ref_of("d-a").await,
        Some(0),
        "assigned build's ref released"
    );
    assert_eq!(
        ref_of("d-b").await,
        Some(0),
        "building build's ref released"
    );
    assert_eq!(
        ref_of("d-done").await,
        Some(1),
        "terminal build's ref must be untouched"
    );
}

/// 产品删除 bulk 取消按聚合口径收口 task：failed + pending 子构建时，pending 被
/// 取消后 task 收口 failed（聚合优先级 failed > cancelled），不一刀切 cancelled。
#[tokio::test]
async fn delete_product_finalizes_task_by_child_aggregation() {
    let (store, _tmp) = fresh_store().await;
    let cfg = sample_config();
    let id = store
        .create_product(official("mydist", &cfg))
        .await
        .unwrap();

    let task_id = store
        .insert_task(crate::TaskInsert {
            product: "mydist",
            pkg_name: "pkg",
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .insert_build(crate::BuildInsert {
            product: "mydist",
            pkg_name: "pkg-done",
            phase: "failed",
            backend: "chroot",
            user: "tester",
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    let b_pending = store
        .insert_build(crate::BuildInsert {
            product: "mydist",
            pkg_name: "pkg-live",
            phase: "pending",
            backend: "chroot",
            user: "tester",
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    let (_builds, tasks) = store.delete_product(id).await.unwrap();
    assert_eq!(tasks, 1, "one task finalized");

    let (phase, completed_at, duration): (String, Option<String>, Option<i64>) =
        sqlx::query_as("SELECT phase, completed_at, duration FROM tasks WHERE id = $1")
            .bind(task_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(
        phase, "failed",
        "mixed-terminal children must aggregate to failed, not blanket cancelled"
    );
    assert!(
        completed_at.is_some(),
        "finalized task must carry completed_at"
    );
    assert!(
        duration.is_some() && duration >= Some(0),
        "finalized task must carry non-negative duration, got {duration:?}"
    );

    let (b_phase,): (String,) = sqlx::query_as("SELECT phase FROM builds WHERE id = $1")
        .bind(b_pending)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(b_phase, "cancelled", "pending child must be cancelled");
}

/// 私人产品（owner_id 非空 → builds/tasks.product_id 恒 NULL）的级联取消必须按
/// **name** 口径命中，否则级联取消 0 行、构建继续执行、产物写进已删产品目录。
#[tokio::test]
async fn delete_product_cancels_private_product_builds_and_tasks_by_name() {
    use crate::config::ProductConfig;

    let (store, _tmp) = fresh_store().await;
    let owner = store.create_user("powner", "builder").await.unwrap();
    let id = store
        .create_product(CreateProductInput {
            name: "secret",
            display_name: None,
            owner_id: Some(owner),
            parent_id: None,
            visibility: "private",
            config: &ProductConfig::default(),
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    // 前提自证：私人产品 build/task 行 product_id 确为 NULL（insert 自动解析 official-only），product_id 口径不可达。
    let task_id = store
        .insert_task(crate::TaskInsert {
            product: "secret",
            pkg_name: "pkg",
            ..Default::default()
        })
        .await
        .unwrap();
    let build_id = store
        .insert_build(crate::BuildInsert {
            product: "secret",
            pkg_name: "pkg",
            phase: "pending",
            backend: "chroot",
            user: "powner",
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    let build_pid: Option<i64> = sqlx::query_scalar("SELECT product_id FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    let task_pid: Option<i64> = sqlx::query_scalar("SELECT product_id FROM tasks WHERE id = $1")
        .bind(task_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        (build_pid, task_pid),
        (None, None),
        "private product rows must have NULL product_id (official-only resolution)"
    );

    let (builds, tasks) = store.delete_product(id).await.unwrap();
    assert_eq!(
        builds, 1,
        "private product's pending build must be cancelled by name"
    );
    assert_eq!(
        tasks, 1,
        "private product's pending task must be finalized by name"
    );

    let (b_phase,): (String,) = sqlx::query_as("SELECT phase FROM builds WHERE id = $1")
        .bind(build_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(b_phase, "cancelled");
    let (t_phase,): (String,) = sqlx::query_as("SELECT phase FROM tasks WHERE id = $1")
        .bind(task_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(t_phase, "cancelled");
}
