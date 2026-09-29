// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::collections::BTreeMap;
use std::path::PathBuf;

use tempfile::TempDir;

use super::defaults::{
    default_base_snapshot_keep_generations, default_build_max_retries,
    default_build_retry_backoff_ms, default_build_target, default_ccache_dir,
    default_ccache_max_size, default_network, default_package_url_cache_ttl_days,
    default_reproduce_enabled, default_tmpfs_dir,
};
use super::merge::{merge_hooks, merge_product_configs, merge_rpm_macros};
use super::types::{
    BoolOrPackages, Config, CrbsConfig, ProductConfig, RemoteConfig, RemoteProfile, RepoConfig,
};
use super::validation::{
    parse_memory_max_kb, parse_staleness, require_i64_representable_u64, require_positive_u64,
    require_positive_usize, validate_ccache_max_size, validate_cpu_quota, validate_memory_max,
};

/// 测试全局配置：运行时目录全部指向 tempdir 子目录，避免非 root 环境撞默认系统路径 `/var/lib/crbs/*`。
fn test_global_config_with_temp_dirs(tmp: &std::path::Path) -> CrbsConfig {
    let crbs_root = tmp.join("crbs_root");
    CrbsConfig {
        crbs_root: crbs_root.clone(),
        result_dir: Some(crbs_root.join("results")),
        shared_layers_dir: Some(crbs_root.join("shared_layers")),
        tmpfs_dir: tmp.join("tmpfs"),
        tmp_dir: Some(tmp.join("tmp")),
        ccache_dir: crbs_root.join("ccache"),
        ..Default::default()
    }
}

#[test]
fn test_parse_minimal_product_config() {
    let toml = r#"
base_packages = ["bash", "coreutils", "rpm-build"]

[[repos]]
name = "cc9-base"
baseurl = "https://repo.example.com/cc9/os/x86_64/"
gpgcheck = true
gpgkey = "/etc/pki/rpm-gpg/RPM-GPG-KEY-cc9"
"#;
    let cfg: ProductConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.base_packages, vec!["bash", "coreutils", "rpm-build"]);
    assert_eq!(cfg.repos.len(), 1);
    assert_eq!(cfg.builder_user, None);
}

#[test]
fn test_parse_product_with_override() {
    let toml = r#"
base_packages = ["bash"]
builder_user = "builder"
builder_uid = 1001
crbs_root = "/opt/crbs"

[[repos]]
name = "cc9-base"
baseurl = "https://repo.example.com/cc9/os/x86_64/"
"#;
    let cfg: ProductConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.builder_user, Some("builder".to_string()));
    assert_eq!(cfg.builder_uid, Some(1001));
    assert_eq!(cfg.crbs_root, Some(PathBuf::from("/opt/crbs")));
}

#[test]
fn test_parse_global_config() {
    let toml = r#"
crbs_root = "/opt/crbs"
builder_uid = 2000
max_concurrent_builds = 4
"#;
    let cfg: CrbsConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.crbs_root, PathBuf::from("/opt/crbs"));
    assert_eq!(cfg.builder_uid, 2000);
    assert_eq!(cfg.max_concurrent_builds, 4);
    assert_eq!(cfg.builder_user, "ccbuilder");
}

#[test]
fn test_parse_reproduce_enabled() {
    let cfg: CrbsConfig = toml::from_str("").unwrap();
    assert!(!cfg
        .reproduce_enabled
        .is_enabled_for("hello-1.0-1.fc44.src.rpm"));

    let cfg: CrbsConfig = toml::from_str("reproduce_enabled = true").unwrap();
    assert!(cfg
        .reproduce_enabled
        .is_enabled_for("hello-1.0-1.fc44.src.rpm"));

    let cfg: CrbsConfig = toml::from_str(r#"reproduce_enabled = ["hello"]"#).unwrap();
    assert!(cfg
        .reproduce_enabled
        .is_enabled_for("hello-1.0-1.fc44.src.rpm"));
    assert!(!cfg
        .reproduce_enabled
        .is_enabled_for("kernel-6.12.0-1.fc44.src.rpm"));

    let cfg: ProductConfig = toml::from_str(
        r#"
base_packages = ["bash"]
reproduce_enabled = ["kernel"]
[[repos]]
name = "test"
baseurl = "http://example.com"
gpgcheck = false
"#,
    )
    .unwrap();
    assert_eq!(
        cfg.reproduce_enabled,
        Some(BoolOrPackages::Packages(vec!["kernel".into()]))
    );
}

/// 默认值：crbs_root 收归引擎世界（/var/lib/crbs-engine），result_dir /
/// shared_layers_dir / tmp_dir 缺省 None（使用处按 crbs_root 派生）。
#[test]
fn test_crbs_config_defaults_are_engine_world() {
    let cfg = CrbsConfig::default();
    assert_eq!(cfg.crbs_root, PathBuf::from("/var/lib/crbs-engine"));
    assert_eq!(cfg.result_dir, None);
    assert_eq!(cfg.shared_layers_dir, None);
    assert_eq!(cfg.tmp_dir, None);
    assert_eq!(
        cfg.result_dir_or_derived(),
        PathBuf::from("/var/lib/crbs-engine/results")
    );
    assert_eq!(
        cfg.shared_layers_dir_or_derived(),
        PathBuf::from("/var/lib/crbs-engine/shared_layers")
    );
    assert_eq!(
        cfg.tmp_dir_or_derived(),
        PathBuf::from("/var/lib/crbs-engine/tmp")
    );
}

/// 派生链：产品显式 > 全局显式 > {crbs_root}/results、{crbs_root}/shared_layers。
#[test]
fn test_merge_derives_result_and_shared_layers_from_root_when_unset() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();

    let mut global = test_global_config_with_temp_dirs(tmp.path());
    global.crbs_root = root.clone();
    global.result_dir = None;
    global.shared_layers_dir = None;

    let product = ProductConfig {
        product: Some("test".into()),
        base_packages: vec!["bash".into()],
        repos: vec![],
        ..Default::default()
    };
    let cfg = Config::merge_configs("test", global, product).unwrap();
    assert_eq!(cfg.result_dir, root.join("results"));
    assert_eq!(cfg.shared_layers_dir, root.join("shared_layers"));
}

/// 默认值归一：tmp_dir 双层未配置时按 {crbs_root}/tmp 派生、ccache_dir 按
/// {crbs_root}/ccache/{product}；显式值仍覆盖派生默认（产品 > 全局，OR 语义）。
#[test]
fn test_merge_derives_tmp_and_ccache_from_root_when_unset() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();

    let mut global = test_global_config_with_temp_dirs(tmp.path());
    global.crbs_root = root.clone();
    global.tmp_dir = None;

    let product = ProductConfig {
        product: Some("test".into()),
        base_packages: vec!["bash".into()],
        repos: vec![],
        ..Default::default()
    };
    let cfg = Config::merge_configs("test", global, product).unwrap();
    assert_eq!(cfg.tmp_dir, root.join("tmp"));
    assert_eq!(cfg.ccache_dir, root.join("ccache").join("test"));

    // 产品显式 tmp_dir 压过派生默认
    let product_override = ProductConfig {
        product: Some("test".into()),
        base_packages: vec!["bash".into()],
        repos: vec![],
        tmp_dir: Some(root.join("product-tmp")),
        ..Default::default()
    };
    let mut global2 = test_global_config_with_temp_dirs(tmp.path());
    global2.crbs_root = root.clone();
    global2.tmp_dir = None;
    let cfg2 = Config::merge_configs("test", global2, product_override).unwrap();
    assert_eq!(cfg2.tmp_dir, root.join("product-tmp"));

    // 全局显式 tmp_dir 在产品未设时生效
    let mut global3 = test_global_config_with_temp_dirs(tmp.path());
    global3.crbs_root = root.clone();
    global3.tmp_dir = Some(root.join("global-tmp"));
    let product3 = ProductConfig {
        product: Some("test".into()),
        base_packages: vec!["bash".into()],
        repos: vec![],
        ..Default::default()
    };
    let cfg3 = Config::merge_configs("test", global3, product3).unwrap();
    assert_eq!(cfg3.tmp_dir, root.join("global-tmp"));
}

#[test]
fn test_merge_prefers_explicit_global_result_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let explicit = tmp.path().join("explicit-results");

    let mut global = test_global_config_with_temp_dirs(tmp.path());
    global.result_dir = Some(explicit.clone());

    let product = ProductConfig {
        product: Some("test".into()),
        base_packages: vec!["bash".into()],
        repos: vec![],
        ..Default::default()
    };
    let cfg = Config::merge_configs("test", global, product).unwrap();
    assert_eq!(cfg.result_dir, explicit);
}

#[test]
fn test_merge_config() {
    let global = CrbsConfig {
        crbs_root: PathBuf::from("/var/lib/crbs"),
        database_url: None,
        result_dir: Some(PathBuf::from("/var/lib/crbs/results")),
        shared_layers_dir: Some(PathBuf::from("/var/lib/crbs/shared_layers")),
        product_root: None,
        base_os_path: None,
        dnf_cache_path: None,
        builder_user: "ccbuilder".into(),
        builder_uid: 10010,
        builder_group: "ccbuilder".into(),
        builder_gid: 10010,
        shared_layer_gc_grace_hours: 168,
        result_gc_grace_hours: 720,
        shared_layer: BoolOrPackages::Bool(false),
        build_tmpfs: false,
        tmpfs_dir: default_tmpfs_dir(),
        tmp_dir: None,
        max_concurrent_builds: 0,
        shared_layer_poll_interval_ms: 100,
        shared_layer_timeout_secs: 60,
        shared_layer_max_retries: 2,
        shared_layer_staleness: None,
        chain_parallelism: 8,
        chain_max_recovery_rounds: 3,
        backend: None,
        rpm_macros: BTreeMap::new(),
        ccache_enabled: BoolOrPackages::Bool(false),
        ccache_dir: default_ccache_dir(),
        ccache_max_size: default_ccache_max_size(),
        dnf_cache_enabled: false,
        releasever: None,
        package_cache_path: None,
        build_target: default_build_target(),
        nocheck: false,
        noclean: false,
        nodebuginfo: false,
        gpg_signing_key_id: None,
        gpg_home: None,
        gpg_signing_enabled: None,
        memory_max: None,
        cpu_quota: None,
        network: default_network(),
        resource_sample_interval_secs: 15,
        resource_sample_interval_cgroup_secs: None,
        build_max_retries: default_build_max_retries(),
        build_retry_backoff_ms: default_build_retry_backoff_ms(),
        package_cache_max_size_gb: None,
        package_cache_evict_referenced: false,
        result_max_count_per_pkg: None,
        result_retention_days: None,
        package_url_cache_ttl_days: default_package_url_cache_ttl_days(),
        base_snapshot_keep_generations: default_base_snapshot_keep_generations(),
        reproduce_enabled: default_reproduce_enabled(),
        hooks: None,
        remote: RemoteConfig::default(),
        use_privileged_helper: crate::privilege::PrivilegedHelperMode::default(),
        privileged_helper_path: None,
    };
    let product = ProductConfig {
        product: None,
        base_packages: vec!["bash".into()],
        arches: vec![],
        noarch_preferred_arches: Vec::new(),
        noarch_preferred_arches_append: Vec::new(),
        allow_srpm_download: None,
        releasever: None,
        resource_sample_interval_secs: None,
        resource_sample_interval_cgroup_secs: None,
        resource_overrides: None,
        repos: vec![RepoConfig {
            name: "test".into(),
            baseurl: "http://example.com".into(),
            gpgcheck: false,
            gpgkey: None,
            ..Default::default()
        }],
        overlay_dir: None,
        post_init: None,
        builder_user: Some("custom".into()),
        builder_uid: None,
        builder_group: None,
        builder_gid: None,
        crbs_root: None,
        result_dir: None,
        shared_layers_dir: None,
        product_root: None,
        base_os_path: None,
        dnf_cache_path: None,
        shared_layer_gc_grace_hours: Some(72),
        shared_layer_staleness: None,
        result_gc_grace_hours: None,
        shared_layer: None,
        build_tmpfs: None,
        tmpfs_dir: None,
        tmp_dir: None,
        gpg_signing_key_id: None,
        gpg_home: None,
        gpg_signing_enabled: None,
        backend: None,
        rpm_macros: None,
        ccache_enabled: None,
        ccache_dir: None,
        ccache_max_size: None,
        dnf_cache_enabled: None,
        builddep_install_weak_deps: None,
        build_target: None,
        nocheck: None,
        noclean: None,
        nodebuginfo: None,
        memory_max: None,
        cpu_quota: None,
        network: None,
        repo_publish: None,
        repo_consume: None,
        local_repo: None,
        chain_parallelism: None,
        chain_max_recovery_rounds: None,
        build_max_retries: None,
        build_retry_backoff_ms: None,
        package_cache_max_size_gb: None,
        package_cache_evict_referenced: None,
        result_max_count_per_pkg: None,
        result_retention_days: None,
        recipe_retention_days: None,
        package_url_cache_ttl_days: None,
        reproduce_enabled: None,
        noarch_per_arch: None,
        deterministic: false,
        mtime_normalize: false,
        _buildhost: None,
        auto_replay: None,
        replay_sampling: None,
        hooks: None,
        // `_append` 字段：本测试聚焦 config merge，`+field` 空表达"无追加"。
        base_packages_append: vec![],
        repos_append: vec![],
        arches_append: vec![],
        post_init_append: vec![],
    };

    let crbs_root = product.crbs_root.unwrap_or(global.crbs_root);
    let product_root = product
        .product_root
        .clone()
        .or_else(|| global.product_root.clone())
        .unwrap_or_else(|| crbs_root.join("test"));
    let cfg = Config {
        product: "test".into(),
        gpg_signing_enabled: None,
        crbs_root: crbs_root.clone(),
        resource_sample_interval_secs: 15,
        resource_sample_interval_cgroup_secs: None,
        result_dir: product
            .result_dir
            .clone()
            .or(global.result_dir.clone())
            .unwrap_or_else(|| crbs_root.join("results")),
        shared_layers_dir: product
            .shared_layers_dir
            .clone()
            .or(global.shared_layers_dir.clone())
            .unwrap_or_else(|| crbs_root.join("shared_layers")),
        product_root: product_root.clone(),
        base_os_path: product
            .base_os_path
            .clone()
            .or_else(|| global.base_os_path.clone())
            .unwrap_or_else(|| product_root.join("base")),
        dnf_cache_path: product
            .dnf_cache_path
            .clone()
            .or_else(|| global.dnf_cache_path.clone())
            .unwrap_or_else(|| product_root.join("dnf-cache")),
        builder_user: product.builder_user.unwrap_or(global.builder_user),
        builder_uid: product.builder_uid.unwrap_or(global.builder_uid),
        builder_group: product.builder_group.unwrap_or(global.builder_group),
        builder_gid: product.builder_gid.unwrap_or(global.builder_gid),
        shared_layer_gc_grace_hours: product
            .shared_layer_gc_grace_hours
            .unwrap_or(global.shared_layer_gc_grace_hours),
        result_gc_grace_hours: product
            .result_gc_grace_hours
            .unwrap_or(global.result_gc_grace_hours),
        shared_layer: product.shared_layer.unwrap_or(global.shared_layer),
        shared_layer_staleness: parse_staleness(
            product
                .shared_layer_staleness
                .as_deref()
                .or(global.shared_layer_staleness.as_deref())
                .unwrap_or(""),
        )
        .unwrap(),
        build_tmpfs: product.build_tmpfs.unwrap_or(global.build_tmpfs),
        tmpfs_dir: product.tmpfs_dir.unwrap_or(global.tmpfs_dir),
        tmp_dir: product
            .tmp_dir
            .clone()
            .or(global.tmp_dir.clone())
            .unwrap_or_else(|| crbs_root.join("tmp")),
        gpg_signing_key_id: product.gpg_signing_key_id,
        gpg_home: product.gpg_home,
        base_packages: product.base_packages,
        repos: product.repos,
        arches: product.arches,
        releasever: product.releasever.or_else(|| global.releasever.clone()),
        overlay_dir: product.overlay_dir,
        post_init: product.post_init.unwrap_or_default(),
        rpm_macros: merge_rpm_macros(&global.rpm_macros, product.rpm_macros.as_ref()),
        ccache_enabled: product.ccache_enabled.unwrap_or(global.ccache_enabled),
        ccache_dir: product
            .ccache_dir
            .unwrap_or_else(|| crbs_root.join("ccache").join("test")),
        ccache_max_size: product.ccache_max_size.unwrap_or(global.ccache_max_size),
        dnf_cache_enabled: product
            .dnf_cache_enabled
            .unwrap_or(global.dnf_cache_enabled),
        builddep_install_weak_deps: product.builddep_install_weak_deps,
        package_cache_path: global
            .package_cache_path
            .clone()
            .unwrap_or_else(|| crbs_root.join("cache").join("packages")),
        backend: "chroot".to_string(),
        memory_max: None,
        cpu_quota: None,
        network: product.network.unwrap_or(global.network),
        local_repo: product.local_repo,
        chain_parallelism: product
            .chain_parallelism
            .unwrap_or(global.chain_parallelism),
        chain_max_recovery_rounds: product
            .chain_max_recovery_rounds
            .unwrap_or(global.chain_max_recovery_rounds),
        build_target: default_build_target(),
        nocheck: product.nocheck.unwrap_or(global.nocheck),
        noclean: product.noclean.unwrap_or(global.noclean),
        nodebuginfo: product.nodebuginfo.unwrap_or(global.nodebuginfo),
        build_max_retries: product
            .build_max_retries
            .unwrap_or(global.build_max_retries),
        build_retry_backoff_ms: product
            .build_retry_backoff_ms
            .unwrap_or(global.build_retry_backoff_ms),
        package_cache_max_size_gb: product
            .package_cache_max_size_gb
            .or(global.package_cache_max_size_gb),
        package_cache_evict_referenced: product
            .package_cache_evict_referenced
            .unwrap_or(global.package_cache_evict_referenced),
        result_max_count_per_pkg: product
            .result_max_count_per_pkg
            .or(global.result_max_count_per_pkg),
        result_retention_days: product
            .result_retention_days
            .or(global.result_retention_days),
        package_url_cache_ttl_days: product
            .package_url_cache_ttl_days
            .unwrap_or(global.package_url_cache_ttl_days),
        base_snapshot_keep_generations: global.base_snapshot_keep_generations,
        reproduce_enabled: product
            .reproduce_enabled
            .unwrap_or(global.reproduce_enabled),
        deterministic: product.deterministic,
        mtime_normalize: false,
        buildhost: product
            ._buildhost
            .clone()
            .unwrap_or_else(|| "crbs".to_string()),
        hooks: merge_hooks(global.hooks.as_ref(), product.hooks.as_ref()),
    };

    assert_eq!(cfg.builder_user, "custom");
    assert_eq!(cfg.builder_uid, 10010);
    assert_eq!(cfg.shared_layer_gc_grace_hours, 72);
    assert_eq!(cfg.builddep_install_weak_deps, None);
    assert_eq!(
        cfg.rpm_macros.get("_topdir"),
        Some(&"/builddir".to_string())
    );
    assert_eq!(
        cfg.rpm_macros.get("_smp_mflags"),
        Some(&"-j$(nproc)".to_string())
    );
}

#[test]
fn test_parse_staleness() {
    use std::time::Duration;

    assert_eq!(parse_staleness("").unwrap(), None);
    assert_eq!(parse_staleness("  ").unwrap(), None);
    assert_eq!(parse_staleness("0s").unwrap(), None);

    assert_eq!(
        parse_staleness("7d").unwrap(),
        Some(Duration::from_secs(7 * 24 * 60 * 60))
    );
    assert_eq!(
        parse_staleness("24h").unwrap(),
        Some(Duration::from_secs(24 * 60 * 60))
    );
    assert_eq!(
        parse_staleness("30m").unwrap(),
        Some(Duration::from_secs(30 * 60))
    );
    assert_eq!(
        parse_staleness("3600s").unwrap(),
        Some(Duration::from_secs(3600))
    );

    assert!(parse_staleness("abc").is_err());
    assert!(parse_staleness("1x").is_err());
    assert!(parse_staleness("d").is_err());
}

#[test]
fn test_merge_rpm_macros() {
    let global = {
        let mut m = BTreeMap::new();
        m.insert("dist".to_string(), ".global".to_string());
        m.insert("_vendor".to_string(), "GlobalCorp".to_string());
        m
    };
    let product = {
        let mut m = BTreeMap::new();
        m.insert("dist".to_string(), ".product".to_string());
        m.insert("_smp_mflags".to_string(), "-j4".to_string());
        m
    };

    let merged = merge_rpm_macros(&global, Some(&product));

    assert_eq!(merged.get("dist"), Some(&".product".to_string()));
    assert_eq!(merged.get("_vendor"), Some(&"GlobalCorp".to_string()));
    assert_eq!(merged.get("_smp_mflags"), Some(&"-j4".to_string()));
    assert_eq!(merged.get("_topdir"), Some(&"/builddir".to_string()));

    let empty = merge_rpm_macros(&BTreeMap::new(), None);
    assert_eq!(empty.get("_topdir"), Some(&"/builddir".to_string()));
    assert_eq!(empty.get("_smp_mflags"), Some(&"-j$(nproc)".to_string()));
    assert_eq!(empty.len(), 2);
}

#[test]
fn test_validate_memory_max_ok() {
    for v in ["0", "100", "512M", "2G", "8T", "16T", "17592186044416"] {
        assert!(validate_memory_max(v).is_ok(), "expected ok for {}", v);
    }
}

#[test]
fn test_validate_memory_max_err() {
    for v in ["abc", "1.5G", "2GB", "-1M", " "] {
        assert!(validate_memory_max(v).is_err(), "expected err for {}", v);
    }
}

/// parse_memory_max_kb（hub cap-OOM 判定用）：后缀换算 KB、"0" 返回 0（调用方
/// 按未声明处理）、非法值报 ValidationFailed。
#[test]
fn test_parse_memory_max_kb() {
    assert_eq!(parse_memory_max_kb("1G").unwrap(), 1_048_576);
    assert_eq!(parse_memory_max_kb("512M").unwrap(), 524_288);
    assert_eq!(parse_memory_max_kb("2048K").unwrap(), 2048);
    assert_eq!(parse_memory_max_kb("1024").unwrap(), 1);
    assert_eq!(parse_memory_max_kb("0").unwrap(), 0);
    assert!(parse_memory_max_kb("4X").is_err());
}

/// 内存 ≤ 16 TiB；溢出量级（2^54 × T = 2^94）与超限值都在配置加载时拒绝，不等到 nspawn payload 才炸。
#[test]
fn test_validate_memory_max_upper_bound() {
    assert!(
        validate_memory_max("18014398509481984T").is_err(),
        "overflow input"
    );
    assert!(validate_memory_max("17T").is_err(), "just above 16 TiB");
    assert!(
        validate_memory_max("17592186044417").is_err(),
        "16 TiB + 1 byte"
    );
    assert!(validate_memory_max("16T").is_ok());
    assert!(
        validate_memory_max("17592186044416").is_ok(),
        "exactly 16 TiB"
    );
}

#[test]
fn test_validate_cpu_quota_ok() {
    for v in ["1", "50", "100", "200%", "50%", "1024", "10000%"] {
        assert!(validate_cpu_quota(v).is_ok(), "expected ok for {}", v);
    }
}

/// ccache -M SIZE 格式（对齐 ccache `parse_size`：单位 K/k/M/G/T + 可选 i/B；小写 g/m/t 实际被拒）。
#[test]
fn test_validate_ccache_max_size_ok() {
    for v in [
        "512M", "4G", "2GiB", "1T", "100k", "16K", "8Ki", "10GB", "1kB", "4Gib",
    ] {
        assert!(validate_ccache_max_size(v).is_ok(), "expected ok for {v}");
    }
}

#[test]
fn test_validate_ccache_max_size_err() {
    // 小写 g/m/t：ccache 解析器实际拒绝（`ccache -M '4g'` 失败 → || warn 静默降级）
    for v in [
        "4g", "512m", "2t", // 空串 / 空白 / 非数字开头
        "", " ", "  4G", "G", "K",
        "7天", // 裸数字（ccache 默认按 GiB 解释，要求显式单位）
        "4", "100", // 0 值（-M 0 = 无限制，有意不提供）
        "0", "0G", // 小数 / 负数 / 混杂垃圾
        "1.5G", "-1M", "4Gxyz", "4GB2", "4G ", "1e3G",
    ] {
        assert!(validate_ccache_max_size(v).is_err(), "expected err for {v}");
    }
    assert!(validate_ccache_max_size("99999999999999999999999999G").is_err());
}

#[test]
fn test_validate_cpu_quota_err() {
    for v in ["abc", "200%%", "-50%", "1.5", " "] {
        assert!(validate_cpu_quota(v).is_err(), "expected err for {}", v);
    }
}

/// 上限 cores ≤ 1024、percent ≤ 10000；"0"/"0%" 是内核 EINVAL（cpu.max quota=0），无限制应不配置 cpu_quota。
#[test]
fn test_validate_cpu_quota_bounds_and_zero() {
    for v in ["99999%", "10001%", "1025", "0", "0%"] {
        assert!(validate_cpu_quota(v).is_err(), "expected err for {}", v);
    }
    assert!(validate_cpu_quota("1024").is_ok());
    assert!(validate_cpu_quota("10000%").is_ok());
}

#[test]
fn test_require_positive_u64_rejects_zero() {
    assert!(require_positive_u64("package_cache_max_size_gb", 1).is_ok());
    assert!(matches!(
        require_positive_u64("package_cache_max_size_gb", 0),
        Err(crate::error::CrbsError::ValidationFailed { .. })
    ));
}

#[test]
fn test_require_positive_usize_rejects_zero() {
    assert!(require_positive_usize("result_max_count_per_pkg", 5).is_ok());
    assert!(matches!(
        require_positive_usize("result_max_count_per_pkg", 0),
        Err(crate::error::CrbsError::ValidationFailed { .. })
    ));
}

/// u64 时间参数 ≥ 2^63 时 `as i64` 回绕成负数（"N 天前"变未来时刻，retention GC 匹配所有行）；i64::MAX 边界合法。
#[test]
fn test_require_i64_representable_u64_boundary() {
    assert!(require_i64_representable_u64("result_retention_days", 0).is_ok());
    assert!(require_i64_representable_u64("result_retention_days", i64::MAX as u64).is_ok());
    let err =
        require_i64_representable_u64("result_retention_days", i64::MAX as u64 + 1).unwrap_err();
    assert!(matches!(
        err,
        crate::error::CrbsError::ValidationFailed { .. }
    ));
    assert!(
        err.to_string().contains("result_retention_days"),
        "message should name the field: {err}"
    );
    assert!(
        err.to_string().contains("wrap negative"),
        "message should explain the failure mode: {err}"
    );
    assert!(require_i64_representable_u64("result_retention_days", u64::MAX).is_err());
}

/// staleness 秒数上限：TTL 判定走 `as_secs() as i64`，≥ 2^63 秒回绕成负数（层永远 stale → 重建风暴）；i64::MAX 秒合法。
#[test]
fn test_parse_staleness_rejects_beyond_i64_max_seconds() {
    let over = format!("{}s", i64::MAX as u64 + 1);
    let err = parse_staleness(&over).unwrap_err();
    assert!(err.to_string().contains("i64::MAX"), "got: {err}");
    let ok = format!("{}s", i64::MAX as u64);
    assert!(parse_staleness(&ok).is_ok());
}

/// merge 路径：产品覆盖与全局直设两个入口的 u64 时间参数超 i64::MAX 都在合并期拒绝。
#[test]
fn merge_configs_rejects_u64_time_param_beyond_i64_max() {
    let tmp = TempDir::new().expect("tempdir");

    let global = test_global_config_with_temp_dirs(tmp.path());
    let product = ProductConfig {
        result_retention_days: Some(i64::MAX as u64 + 1),
        ..Default::default()
    };
    let err = Config::merge_configs("tt-test", global, product).unwrap_err();
    assert!(matches!(
        err,
        crate::error::CrbsError::ValidationFailed { .. }
    ));
    assert!(
        err.to_string().contains("result_retention_days"),
        "message should name the field: {err}"
    );

    let mut global = test_global_config_with_temp_dirs(tmp.path());
    global.package_url_cache_ttl_days = i64::MAX as u64 + 1;
    let err = Config::merge_configs("tt-test2", global, ProductConfig::default()).unwrap_err();
    assert!(
        err.to_string().contains("package_url_cache_ttl_days"),
        "message should name the field: {err}"
    );
}

/// 合并后的边界值 i64::MAX 本身必须放行（只拦回绕区间，不做更紧的语义收紧）。
#[test]
fn merge_configs_accepts_i64_max_time_params() {
    let tmp = TempDir::new().expect("tempdir");
    let mut global = test_global_config_with_temp_dirs(tmp.path());
    global.shared_layer_gc_grace_hours = i64::MAX as u64;
    global.result_gc_grace_hours = i64::MAX as u64;
    global.result_retention_days = Some(i64::MAX as u64);
    global.package_url_cache_ttl_days = i64::MAX as u64;
    let cfg = Config::merge_configs("tt-ok", global, ProductConfig::default())
        .expect("i64::MAX time params must pass merge validation");
    assert_eq!(cfg.result_retention_days, Some(i64::MAX as u64));
}

/// 产品 `builddep_install_weak_deps` 单层 merge 透传：省略 = None（dnf 默认）、显式 false
/// 保留（pipeline::install_deps_bash 据此加 --setopt）；无全局同名字段，不走 global 兜底。
#[test]
fn merge_configs_passes_through_builddep_install_weak_deps() {
    let tmp = TempDir::new().expect("tempdir");
    let global = test_global_config_with_temp_dirs(tmp.path());

    let omitted = Config::merge_configs("bd-omitted", global.clone(), ProductConfig::default())
        .expect("omitted field must merge");
    assert_eq!(omitted.builddep_install_weak_deps, None);

    let product = ProductConfig {
        builddep_install_weak_deps: Some(false),
        ..Default::default()
    };
    let disabled =
        Config::merge_configs("bd-off", global, product).expect("explicit false must merge");
    assert_eq!(disabled.builddep_install_weak_deps, Some(false));
}

/// 全局加载路径（`crbs gc` 直用 CrbsConfig，不走 merge）：超限 package_url_cache_ttl_days
/// 在 load_from 即拒绝（校验先于 privilege 初始化，拒绝路径无副作用）。
#[test]
fn crbs_config_load_rejects_u64_time_param_beyond_i64_max() {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("crbs.toml");
    std::fs::write(
        &path,
        format!("package_url_cache_ttl_days = {}\n", i64::MAX as u64 + 1),
    )
    .unwrap();
    let err = CrbsConfig::load_from(&path).unwrap_err();
    assert!(
        err.to_string().contains("package_url_cache_ttl_days"),
        "message should name the field: {err}"
    );
}

/// 全局 rpm_macros 坏键（含空格）在 load_from 即拒绝。
#[test]
fn crbs_config_load_rejects_invalid_rpm_macro_key() {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("crbs.toml");
    std::fs::write(&path, "[rpm_macros]\n\"BAD KEY\" = \"1\"\n").unwrap();
    let err = CrbsConfig::load_from(&path).unwrap_err();
    assert!(
        err.to_string().contains("rpm_macros"),
        "message should name the field: {err}"
    );
}

/// 产品侧 rpm_macros 坏键在 merge_configs 单点收口拒绝（五个加载入口全过此函数）；错误带产品名。
#[test]
fn merge_configs_rejects_invalid_rpm_macro_key() {
    let tmp = TempDir::new().expect("tempdir");
    let global = test_global_config_with_temp_dirs(tmp.path());
    let mut macros = BTreeMap::new();
    macros.insert("BAD KEY".to_string(), "1".to_string());
    let product = ProductConfig {
        rpm_macros: Some(macros),
        ..Default::default()
    };
    let err = Config::merge_configs("macro-test", global, product).unwrap_err();
    assert!(
        matches!(err, crate::error::CrbsError::ValidationFailed { .. }),
        "got: {:?}",
        err
    );
    let msg = err.to_string();
    assert!(
        msg.contains("rpm_macros"),
        "message should name the field: {msg}"
    );
    assert!(
        msg.contains("macro-test"),
        "message should name the product: {msg}"
    );
}

/// 产品侧 rpm_macros 的 `dist` 值纳入 validate_dist_tag 白名单：config `%dist` 与 CLI `--dist`
/// 同格进 rpmbuild --define，校验面不得被 config 绕过；合法值照常通过。
#[test]
fn merge_configs_rejects_invalid_rpm_macros_dist_value() {
    let tmp = TempDir::new().expect("tempdir");
    let global = test_global_config_with_temp_dirs(tmp.path());

    for bad in ["fc/44", "%{dist}", "fc 44"] {
        let mut macros = BTreeMap::new();
        macros.insert("dist".to_string(), bad.to_string());
        let product = ProductConfig {
            rpm_macros: Some(macros),
            ..Default::default()
        };
        let err = Config::merge_configs("dist-test", global.clone(), product).unwrap_err();
        assert!(
            matches!(err, crate::error::CrbsError::ValidationFailed { .. }),
            "dist {bad:?} must be rejected: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("rpm_macros") && msg.contains("dist-test"),
            "message should name field and product: {msg}"
        );
    }

    let mut macros = BTreeMap::new();
    macros.insert("dist".to_string(), ".fc44".to_string());
    macros.insert("_smp_mflags".to_string(), "-j8".to_string());
    let product = ProductConfig {
        rpm_macros: Some(macros),
        ..Default::default()
    };
    assert!(Config::merge_configs("dist-test", global, product).is_ok());
}

/// 产品层空串 `releasever` / 空白 `shared_layer_staleness` 视为未设置，全局真值兜底。
#[test]
fn merge_configs_blank_strings_fall_back_to_global() {
    let tmp = TempDir::new().expect("tempdir");
    let mut global = test_global_config_with_temp_dirs(tmp.path());
    global.releasever = Some("9".into());
    global.shared_layer_staleness = Some("7d".into());
    let product = ProductConfig {
        releasever: Some("".into()),
        shared_layer_staleness: Some("  ".into()),
        ..Default::default()
    };
    let cfg = Config::merge_configs("blank-test", global, product).expect("merge ok");
    assert_eq!(cfg.releasever.as_deref(), Some("9"));
    assert_eq!(
        cfg.shared_layer_staleness,
        Some(std::time::Duration::from_secs(7 * 24 * 60 * 60))
    );
}

/// 同族扩面：产品层空串 `ccache_max_size` / `gpg_signing_key_id` 视为未设置、全局真值兜底
///（否则直通 `ccache -M ''` 静默无上限 / 进 gpg 参数槽）；全局 gpg 空串归 None（不签名）。
#[test]
fn merge_configs_blank_ccache_and_gpg_key_fall_back_to_global() {
    let tmp = TempDir::new().expect("tempdir");
    let mut global = test_global_config_with_temp_dirs(tmp.path());
    global.ccache_max_size = "8G".into();
    global.gpg_signing_key_id = Some("admin@example.com".into());
    let product = ProductConfig {
        ccache_max_size: Some("".into()),
        gpg_signing_key_id: Some("".into()),
        ..Default::default()
    };
    let cfg = Config::merge_configs("blank-cc", global, product).expect("merge ok");
    assert_eq!(cfg.ccache_max_size, "8G");
    assert_eq!(cfg.gpg_signing_key_id.as_deref(), Some("admin@example.com"));

    let mut global = test_global_config_with_temp_dirs(tmp.path());
    global.gpg_signing_key_id = Some("".into());
    let cfg = Config::merge_configs("blank-g", global, ProductConfig::default()).expect("merge ok");
    assert_eq!(cfg.gpg_signing_key_id, None);
}

/// 全局层空串 `releasever` 归一为 None（否则 effective_releasever 返回 ""，拼出
/// `dnf --releasever ""`）；归一后与 None 同帧：effective_releasever 一致走宿主推断。
#[test]
fn merge_configs_blank_global_releasever_normalizes_to_none() {
    let tmp = TempDir::new().expect("tempdir");
    let mut global = test_global_config_with_temp_dirs(tmp.path());
    global.releasever = Some("".into());
    let cfg =
        Config::merge_configs("blank-rel", global, ProductConfig::default()).expect("merge ok");
    assert_eq!(
        cfg.releasever, None,
        "global empty releasever must normalize to None"
    );

    // 与 None 同帧：两侧都走宿主推断，同机结果一致；无 /etc/os-release 时同失败也算同帧。
    let mut global = test_global_config_with_temp_dirs(tmp.path());
    global.releasever = None;
    let none_cfg =
        Config::merge_configs("none-rel", global, ProductConfig::default()).expect("merge ok");
    match (cfg.effective_releasever(), none_cfg.effective_releasever()) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "both must resolve via host inference"),
        (Err(_), Err(_)) => {}
        (a, b) => panic!("effective_releasever diverges: {a:?} vs {b:?}"),
    }
}

/// ccache_max_size 坏格式在合并期拒绝（产品与全局两个来源都拦）；合法值放行。
#[test]
fn merge_configs_rejects_bad_ccache_max_size() {
    // 产品来源：小写 g 是 ccache 实际拒绝，裸数字是 crbs 有意收紧
    for bad in ["4g", "100"] {
        let tmp = TempDir::new().expect("tempdir");
        let global = test_global_config_with_temp_dirs(tmp.path());
        let product = ProductConfig {
            ccache_max_size: Some(bad.into()),
            ..Default::default()
        };
        let err = Config::merge_configs("cc-bad", global, product).unwrap_err();
        assert!(
            err.to_string().contains("ccache_max_size"),
            "message should name the field, got: {err}"
        );
    }

    let tmp = TempDir::new().expect("tempdir");
    let mut global = test_global_config_with_temp_dirs(tmp.path());
    global.ccache_max_size = "banana".into();
    let err = Config::merge_configs("cc-bad-g", global, ProductConfig::default()).unwrap_err();
    assert!(err.to_string().contains("ccache_max_size"), "got: {err}");

    let tmp = TempDir::new().expect("tempdir");
    let global = test_global_config_with_temp_dirs(tmp.path());
    let product = ProductConfig {
        ccache_max_size: Some("512M".into()),
        ..Default::default()
    };
    let cfg = Config::merge_configs("cc-ok", global, product).expect("valid size");
    assert_eq!(cfg.ccache_max_size, "512M");
    let global = test_global_config_with_temp_dirs(tmp.path());
    let cfg = Config::merge_configs("cc-ok2", global, ProductConfig::default()).expect("default");
    assert_eq!(cfg.ccache_max_size, "4G");
}

#[test]
fn test_bool_or_packages_is_enabled_for() {
    let all = BoolOrPackages::Bool(true);
    assert!(all.is_enabled_for("kernel-6.12.0-1.el9.src.rpm"));
    assert!(all.is_enabled_for("tmux-3.5a-7.fc42.src.rpm"));

    let none = BoolOrPackages::Bool(false);
    assert!(!none.is_enabled_for("kernel-6.12.0-1.el9.src.rpm"));

    let pkgs = BoolOrPackages::Packages(vec!["kernel".to_string()]);
    assert!(pkgs.is_enabled_for("kernel-6.12.0-1.el9.src.rpm"));
    assert!(!pkgs.is_enabled_for("kernel-rt-6.12.0-1.el9.src.rpm"));
    assert!(!pkgs.is_enabled_for("tmux-3.5a-7.fc42.src.rpm"));

    let pkgs_rt = BoolOrPackages::Packages(vec!["kernel-rt".to_string()]);
    assert!(pkgs_rt.is_enabled_for("kernel-rt-6.12.0-1.el9.src.rpm"));
    assert!(!pkgs_rt.is_enabled_for("kernel-6.12.0-1.el9.src.rpm"));
}

#[test]
fn test_bool_or_packages_serde_roundtrip() {
    #[derive(serde::Deserialize)]
    struct Wrapper {
        v: BoolOrPackages,
    }

    let w: Wrapper = toml::from_str("v = false").unwrap();
    assert!(matches!(w.v, BoolOrPackages::Bool(false)));

    let w: Wrapper = toml::from_str(r#"v = ["kernel"]"#).unwrap();
    assert!(matches!(w.v, BoolOrPackages::Packages(_)));
}

#[test]
fn test_bool_or_packages_is_globally_enabled() {
    assert!(BoolOrPackages::Bool(true).is_globally_enabled());
    assert!(!BoolOrPackages::Bool(false).is_globally_enabled());
    assert!(!BoolOrPackages::Packages(vec!["kernel".into()]).is_globally_enabled());
    assert!(!BoolOrPackages::Packages(vec![]).is_globally_enabled());
}

#[test]
fn test_bool_or_packages_is_configured() {
    assert!(BoolOrPackages::Bool(true).is_configured());
    assert!(!BoolOrPackages::Bool(false).is_configured());
    assert!(BoolOrPackages::Packages(vec!["kernel".into()]).is_configured());
    // 空列表视为未配置：不匹配任何包，不应触发 ccache 准备工作
    assert!(!BoolOrPackages::Packages(vec![]).is_configured());
}

// merge_product_configs 单元测试：直接跑 parent × child → out，按字段类型分组。
mod merge_product_configs_tests {
    use super::super::merge::merge_product_configs;
    use super::super::types::{
        BoolOrPackages, HooksConfig, ProductConfig, RepoConfig, SpecHooksConfig,
    };
    use super::super::PostInitCommand;
    use std::collections::{BTreeMap, HashMap};

    fn repo(name: &str, url: &str) -> RepoConfig {
        RepoConfig {
            name: name.into(),
            baseurl: url.into(),
            ..Default::default()
        }
    }

    /// child.Some 覆盖 parent；取 `builder_user` 作代表，所有 `Option<T>` scalar 分支同型。
    #[test]
    fn scalar_child_overrides_parent() {
        let parent = ProductConfig {
            builder_user: Some("parent-u".into()),
            releasever: Some("9".into()),
            ..Default::default()
        };
        let child = ProductConfig {
            builder_user: Some("child-u".into()),
            ..Default::default()
        };
        let out = merge_product_configs(&parent, &child);
        assert_eq!(out.builder_user.as_deref(), Some("child-u"));
        assert_eq!(out.releasever.as_deref(), Some("9"));
    }

    #[test]
    fn scalar_child_none_inherits_parent() {
        let parent = ProductConfig {
            builder_user: Some("parent-u".into()),
            memory_max: Some("4G".into()),
            ..Default::default()
        };
        let child = ProductConfig::default();
        let out = merge_product_configs(&parent, &child);
        assert_eq!(out.builder_user.as_deref(), Some("parent-u"));
        assert_eq!(out.memory_max.as_deref(), Some("4G"));
    }

    /// `builddep_install_weak_deps` 链合并走 override_some! 同款分支：Some 覆盖 / None 继承。
    #[test]
    fn builddep_install_weak_deps_child_overrides_parent() {
        let parent = ProductConfig {
            builddep_install_weak_deps: Some(false),
            ..Default::default()
        };
        let out = merge_product_configs(&parent, &ProductConfig::default());
        assert_eq!(out.builddep_install_weak_deps, Some(false));

        let child = ProductConfig {
            builddep_install_weak_deps: Some(true),
            ..Default::default()
        };
        let out2 = merge_product_configs(&ProductConfig::default(), &child);
        assert_eq!(out2.builddep_install_weak_deps, Some(true));
    }

    /// 空串归一化链层同款：child 空串 `releasever` / 空白 `shared_layer_staleness` /
    /// 空串 `ccache_max_size` / `gpg_signing_key_id` 视为未设置、继承父层；非空照常覆盖。
    #[test]
    fn blank_string_child_fields_inherit_parent() {
        let parent = ProductConfig {
            releasever: Some("9".into()),
            shared_layer_staleness: Some("7d".into()),
            ccache_max_size: Some("8G".into()),
            gpg_signing_key_id: Some("parent-key".into()),
            ..Default::default()
        };
        let child = ProductConfig {
            releasever: Some("".into()),
            shared_layer_staleness: Some("  ".into()),
            ccache_max_size: Some("".into()),
            gpg_signing_key_id: Some("".into()),
            ..Default::default()
        };
        let out = merge_product_configs(&parent, &child);
        assert_eq!(out.releasever.as_deref(), Some("9"));
        assert_eq!(out.shared_layer_staleness.as_deref(), Some("7d"));
        assert_eq!(out.ccache_max_size.as_deref(), Some("8G"));
        assert_eq!(out.gpg_signing_key_id.as_deref(), Some("parent-key"));

        let child2 = ProductConfig {
            releasever: Some("10".into()),
            shared_layer_staleness: Some("30m".into()),
            ccache_max_size: Some("2G".into()),
            gpg_signing_key_id: Some("child-key".into()),
            ..Default::default()
        };
        let out2 = merge_product_configs(&parent, &child2);
        assert_eq!(out2.releasever.as_deref(), Some("10"));
        assert_eq!(out2.shared_layer_staleness.as_deref(), Some("30m"));
        assert_eq!(out2.ccache_max_size.as_deref(), Some("2G"));
        assert_eq!(out2.gpg_signing_key_id.as_deref(), Some("child-key"));
    }

    /// Vec：child 非空 → replace parent
    #[test]
    fn vec_replaces_when_child_non_empty() {
        let parent = ProductConfig {
            base_packages: vec!["a".into(), "b".into()],
            ..Default::default()
        };
        let child = ProductConfig {
            base_packages: vec!["x".into()],
            ..Default::default()
        };
        let out = merge_product_configs(&parent, &child);
        assert_eq!(out.base_packages, vec!["x"]);
    }

    /// Vec：child 空 + `_append` 非空 → parent 保留 + child._append 追加
    #[test]
    fn vec_append_extends_parent() {
        let parent = ProductConfig {
            base_packages: vec!["a".into(), "b".into()],
            ..Default::default()
        };
        let child = ProductConfig {
            base_packages_append: vec!["c".into()],
            ..Default::default()
        };
        let out = merge_product_configs(&parent, &child);
        assert_eq!(out.base_packages, vec!["a", "b", "c"]);
        // 输出 `_append` 一定为空（已折进 base）
        assert!(out.base_packages_append.is_empty());
    }

    /// Vec：child 同时给 base + `_append` → 先 replace 再拼 append
    #[test]
    fn vec_replace_then_append_when_both_set() {
        let parent = ProductConfig {
            base_packages: vec!["p1".into(), "p2".into()],
            ..Default::default()
        };
        let child = ProductConfig {
            base_packages: vec!["c1".into()],
            base_packages_append: vec!["c2".into()],
            ..Default::default()
        };
        let out = merge_product_configs(&parent, &child);
        assert_eq!(out.base_packages, vec!["c1", "c2"]);
    }

    /// arches 空 Vec = 继承父列表（有意限制）：skip_serializing_if 下
    /// 空 Vec 与未写不可区分，合并只能取父；子想回退单架构需重建产品。
    #[test]
    fn arches_child_empty_vec_inherits_parent() {
        let parent = ProductConfig {
            arches: vec!["x86_64".into(), "aarch64".into()],
            ..Default::default()
        };
        let child = ProductConfig {
            arches: vec![],
            ..Default::default()
        };
        let out = merge_product_configs(&parent, &child);
        assert_eq!(out.arches.len(), 2);
        assert_eq!(
            out.arches,
            vec!["x86_64".to_string(), "aarch64".to_string()]
        );
    }

    /// rpm_macros：两边都 Some 走逐 key 合并；child 覆盖同 key
    #[test]
    fn rpm_macros_key_merge_child_wins() {
        let mut p_macros = BTreeMap::new();
        p_macros.insert("k1".into(), "parent-v1".into());
        p_macros.insert("k2".into(), "parent-v2".into());
        let mut c_macros = BTreeMap::new();
        c_macros.insert("k1".into(), "child-v1".into());
        c_macros.insert("k3".into(), "child-v3".into());
        let parent = ProductConfig {
            rpm_macros: Some(p_macros),
            ..Default::default()
        };
        let child = ProductConfig {
            rpm_macros: Some(c_macros),
            ..Default::default()
        };
        let out = merge_product_configs(&parent, &child).rpm_macros.unwrap();
        assert_eq!(out.get("k1").map(String::as_str), Some("child-v1"));
        assert_eq!(out.get("k2").map(String::as_str), Some("parent-v2"));
        assert_eq!(out.get("k3").map(String::as_str), Some("child-v3"));
    }

    /// hooks：两边 Some → 逐 section key merge（pre / post / spec.pre / spec.post）
    #[test]
    fn hooks_key_merge_across_sections() {
        let mut p_pre = HashMap::new();
        p_pre.insert("step-a".into(), "parent-a".into());
        let mut p_spec_post = HashMap::new();
        p_spec_post.insert("sp-a".into(), "parent-sp-a".into());
        let parent = ProductConfig {
            hooks: Some(HooksConfig {
                pre: p_pre,
                post: HashMap::new(),
                spec: SpecHooksConfig {
                    pre: HashMap::new(),
                    post: p_spec_post,
                },
            }),
            ..Default::default()
        };
        let mut c_pre = HashMap::new();
        c_pre.insert("step-b".into(), "child-b".into());
        c_pre.insert("step-a".into(), "child-a-overrides".into());
        let child = ProductConfig {
            hooks: Some(HooksConfig {
                pre: c_pre,
                post: HashMap::new(),
                spec: SpecHooksConfig::default(),
            }),
            ..Default::default()
        };
        let out = merge_product_configs(&parent, &child).hooks.unwrap();
        assert_eq!(
            out.pre.get("step-a").map(String::as_str),
            Some("child-a-overrides")
        );
        assert_eq!(out.pre.get("step-b").map(String::as_str), Some("child-b"));
        assert_eq!(
            out.spec.post.get("sp-a").map(String::as_str),
            Some("parent-sp-a")
        );
    }

    /// post_init：child.Some(vec) → 完整 replace parent（不是逐条 merge）
    #[test]
    fn post_init_child_some_replaces_parent() {
        let parent = ProductConfig {
            post_init: Some(vec![PostInitCommand {
                command: "parent-cmd".into(),
                ..Default::default()
            }]),
            ..Default::default()
        };
        let child = ProductConfig {
            post_init: Some(vec![PostInitCommand {
                command: "child-cmd".into(),
                ..Default::default()
            }]),
            ..Default::default()
        };
        let out = merge_product_configs(&parent, &child);
        let ps = out.post_init.unwrap();
        assert_eq!(ps.len(), 1);
        assert_eq!(ps[0].command, "child-cmd");
    }

    /// post_init：parent = None, child._append 非空 → 提升为 Some(append)
    #[test]
    fn post_init_promotes_none_to_some_with_append() {
        let parent = ProductConfig::default();
        let child = ProductConfig {
            post_init_append: vec![PostInitCommand {
                command: "appended".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let out = merge_product_configs(&parent, &child);
        let ps = out.post_init.unwrap();
        assert_eq!(ps.len(), 1);
        assert_eq!(ps[0].command, "appended");
        assert!(out.post_init_append.is_empty());
    }

    /// post_init：parent = Some(vec), child._append 非空 → 在 parent 之上 extend
    #[test]
    fn post_init_extends_existing_some_via_append() {
        let parent = ProductConfig {
            post_init: Some(vec![PostInitCommand {
                command: "parent-cmd".into(),
                ..Default::default()
            }]),
            ..Default::default()
        };
        let child = ProductConfig {
            post_init_append: vec![PostInitCommand {
                command: "child-append".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let out = merge_product_configs(&parent, &child);
        let ps = out.post_init.unwrap();
        assert_eq!(
            ps.iter().map(|c| c.command.as_str()).collect::<Vec<_>>(),
            vec!["parent-cmd", "child-append"]
        );
    }

    /// 输出 `_append` 字段必为 empty（fold 语义）：防新 `_append` 字段漏在 merge 里 clear。
    #[test]
    fn output_has_no_append_fields() {
        let parent = ProductConfig::default();
        let child = ProductConfig {
            base_packages_append: vec!["a".into()],
            repos_append: vec![repo("r", "http://r/")],
            arches_append: vec!["x86_64".into()],
            noarch_preferred_arches: Vec::new(),
            noarch_preferred_arches_append: Vec::new(),
            post_init_append: vec![PostInitCommand {
                command: "c".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let out = merge_product_configs(&parent, &child);
        assert!(out.base_packages_append.is_empty());
        assert!(out.repos_append.is_empty());
        assert!(out.arches_append.is_empty());
        assert!(out.post_init_append.is_empty());
        assert!(out.noarch_preferred_arches_append.is_empty());
    }

    /// noarch 偏好集合并语义与 arches 同款：child 非空整体 REPLACE 父层，
    /// `_append` 追加到合并结果末尾。
    #[test]
    fn noarch_preferred_arches_merge_replace_and_append() {
        let parent = ProductConfig {
            noarch_preferred_arches: vec!["x86_64".into(), "aarch64".into()],
            ..Default::default()
        };
        // child 非空 = REPLACE。
        let child = ProductConfig {
            noarch_preferred_arches: vec!["x86_64".into()],
            ..Default::default()
        };
        let out = merge_product_configs(&parent, &child);
        assert_eq!(out.noarch_preferred_arches, vec!["x86_64".to_string()]);

        // append 追加到父层继承值之后。
        let child = ProductConfig {
            noarch_preferred_arches_append: vec!["sw_64".into()],
            ..Default::default()
        };
        let out = merge_product_configs(&parent, &child);
        assert_eq!(
            out.noarch_preferred_arches,
            vec![
                "x86_64".to_string(),
                "aarch64".to_string(),
                "sw_64".to_string()
            ]
        );
    }

    /// 参数化护栏：child 全字段 populate（可辨识 marker），空 parent merge 后 serialize
    /// 出的 JSON 键集 = child 键集——新字段漏 wire merge 分支即红（serde 键集等价于
    /// serialize 字段集合，rename 也能捕获）。不覆盖 `_append` 的值（必空，由
    /// `output_has_no_append_fields` 守护）；`_append` 字段 fixture 显式列空，配合
    /// 无 `..Default::default()` 强制新字段登记。
    #[test]
    fn field_coverage_child_pass_through() {
        let mut rpm_macros = BTreeMap::new();
        rpm_macros.insert("_myopt".into(), "1".into());
        let mut hooks_pre = HashMap::new();
        hooks_pre.insert("stage".into(), "echo".into());

        let child = ProductConfig {
            product: Some("child-slug".into()),
            base_packages: vec!["pkg".into()],
            repos: vec![repo("r", "http://r/")],
            arches: vec!["x86_64".into()],
            noarch_preferred_arches: Vec::new(),
            noarch_preferred_arches_append: Vec::new(),
            allow_srpm_download: None,
            releasever: Some("9".into()),
            resource_sample_interval_secs: None,
            resource_sample_interval_cgroup_secs: None,
            resource_overrides: Some({
                let mut m = BTreeMap::new();
                m.insert(
                    "heavy-pkg".into(),
                    crate::config::ResourceOverride {
                        mem_gb: 16.0,
                        cpu_cores: 8.0,
                    },
                );
                m
            }),
            overlay_dir: Some("/o".into()),
            post_init: Some(vec![PostInitCommand {
                command: "c".into(),
                ..Default::default()
            }]),
            builder_user: Some("bu".into()),
            builder_uid: Some(1000),
            builder_group: Some("bg".into()),
            builder_gid: Some(1000),
            crbs_root: None, // 显式 None：crbs_root 是机器级，merge_product_configs 不从 child 透传（见 merge.rs）
            result_dir: Some("/r".into()),
            shared_layers_dir: Some("/sl".into()),
            product_root: Some("/p".into()),
            base_os_path: Some("/bo".into()),
            dnf_cache_path: Some("/dc".into()),
            shared_layer_gc_grace_hours: Some(1),
            shared_layer_staleness: Some("2h".into()),
            result_gc_grace_hours: Some(3),
            shared_layer: Some(BoolOrPackages::Bool(true)),
            build_tmpfs: Some(true),
            tmpfs_dir: Some("/tf".into()),
            tmp_dir: Some("/tmp".into()),
            gpg_signing_key_id: Some("key".into()),
            gpg_home: Some("/gh".into()),
            gpg_signing_enabled: None,
            backend: Some("native".into()),
            rpm_macros: Some(rpm_macros),
            ccache_enabled: Some(BoolOrPackages::Bool(true)),
            ccache_dir: Some("/cc".into()),
            ccache_max_size: Some("1G".into()),
            dnf_cache_enabled: Some(true),
            builddep_install_weak_deps: Some(false),
            build_target: Some("rpm".into()),
            nocheck: Some(false),
            noclean: Some(false),
            nodebuginfo: Some(false),
            memory_max: Some("4G".into()),
            cpu_quota: Some("100%".into()),
            network: Some(true),
            repo_publish: Some(false),
            repo_consume: Some(true),
            local_repo: Some("/lr".into()),
            chain_parallelism: Some(2),
            chain_max_recovery_rounds: Some(2),
            build_max_retries: Some(3),
            build_retry_backoff_ms: Some(1000),
            package_cache_max_size_gb: Some(10),
            package_cache_evict_referenced: Some(false),
            result_max_count_per_pkg: Some(5),
            result_retention_days: Some(30),
            recipe_retention_days: Some(45),
            package_url_cache_ttl_days: Some(7),
            reproduce_enabled: Some(BoolOrPackages::Bool(true)),
            noarch_per_arch: Some(false),
            deterministic: true,
            mtime_normalize: false,
            _buildhost: Some("child-host".into()),
            auto_replay: Some(false),
            replay_sampling: Some(50),
            hooks: Some(HooksConfig {
                pre: hooks_pre,
                post: HashMap::new(),
                spec: SpecHooksConfig::default(),
            }),
            // 禁止恢复 ..Default::default()：漏列新字段必须在此 E0063 编译红，
            // 护栏才守得住 merge wiring 缺失即红；空 vec 经 skip_serializing_if 与 Default 逐字节等价。
            base_packages_append: vec![],
            repos_append: vec![],
            arches_append: vec![],
            post_init_append: vec![],
        };

        let parent = ProductConfig::default();
        let merged = merge_product_configs(&parent, &child);

        let child_val = serde_json::to_value(&child).unwrap();
        let merged_val = serde_json::to_value(&merged).unwrap();
        let child_obj = child_val.as_object().unwrap();
        let merged_obj = merged_val.as_object().unwrap();

        // child 每个 key merged 必须存在且值相等（缺失 = merge wiring 漏）。
        for (k, v) in child_obj {
            let mv = merged_obj.get(k).unwrap_or_else(|| {
                panic!(
                    "merge_product_configs dropped field {:?}: is merge wiring missing?",
                    k
                )
            });
            assert_eq!(mv, v, "field {:?} value mismatch after merge", k);
        }
    }
}

/// 单层入口 fold：merge_configs 经 fold_appends_into_base 把 `+base_packages` 折进 base。
#[test]
fn merge_configs_folds_plus_field_at_single_layer_entry() {
    let tmp = TempDir::new().expect("tempdir");
    let global = test_global_config_with_temp_dirs(tmp.path());
    let product = ProductConfig {
        base_packages: vec!["base-pkg".into()],
        base_packages_append: vec!["appended-pkg".into()],
        repos: vec![RepoConfig {
            name: "test".into(),
            baseurl: "http://example.com".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let cfg = Config::merge_configs("f5-test", global, product).expect("merge should succeed");
    assert_eq!(cfg.base_packages, vec!["base-pkg", "appended-pkg"]);
}

/// Golden：无 `+field` 配置 fold 后逐字节等同 fold 前——守 fold_appends_into_base
/// 对其它字段零副作用（引入 mem::take 后 push / 重排序列化即红）。
#[test]
fn fold_appends_no_op_on_config_without_plus_fields_byte_identical() {
    let toml_src = r#"
base_packages = ["bash", "gcc"]
arches = ["x86_64", "aarch64"]

[[repos]]
name = "base"
baseurl = "http://example/repo"
"#;
    let cfg = ProductConfig::from_str(toml_src).unwrap();
    let before = cfg.to_toml_string().unwrap();
    let mut cfg2 = cfg.clone();
    cfg2.fold_appends_into_base();
    let after = cfg2.to_toml_string().unwrap();
    assert_eq!(
        before, after,
        "fold_appends_into_base changed a no-`+field` config's serialization"
    );
}

// crbs_root 是机器级配置（state DB = {crbs_root}/crbs.db，所有命令共享），
// 不应被 product config 覆盖：merge 忽略 + warn。

#[test]
fn merge_configs_ignores_product_crbs_root() {
    let tmp = TempDir::new().expect("tempdir");
    let global = test_global_config_with_temp_dirs(tmp.path());
    let product = ProductConfig {
        crbs_root: Some(PathBuf::from("/data/crbs")),
        ..Default::default()
    };
    let cfg = Config::merge_configs("ule3sp4", global, product).expect("merge_configs");
    assert_eq!(cfg.crbs_root, tmp.path().join("crbs_root"));
}

#[test]
fn merge_configs_no_product_crbs_root_uses_global() {
    let tmp = TempDir::new().expect("tempdir");
    let global = test_global_config_with_temp_dirs(tmp.path());
    let product = ProductConfig::default();
    let cfg = Config::merge_configs("ule3sp4", global, product).expect("merge_configs");
    assert_eq!(cfg.crbs_root, tmp.path().join("crbs_root"));
}

// merge_configs 被读路径经 load_with_product_config_async 间接调用，必须零文件系统
// 副作用（内置 mkdir 在目录缺失/无权限时读路径整页 500）；目录创建仅在构建执行
// 路径显式走 Config::ensure_runtime_dirs。

#[test]
fn merge_configs_does_not_create_runtime_dirs() {
    let tmp = TempDir::new().expect("tempdir");
    let global = test_global_config_with_temp_dirs(tmp.path());
    let cfg = Config::merge_configs("p3-read", global, ProductConfig::default())
        .expect("merge must not touch filesystem");
    assert!(!cfg.crbs_root.exists(), "crbs_root must not be created");
    assert!(!cfg.result_dir.exists(), "result_dir must not be created");
    assert!(!cfg.shared_layers_dir.exists());
    assert!(!cfg.tmpfs_dir.exists());
    assert!(!cfg.tmp_dir.exists());
}

#[test]
fn merge_configs_survives_unwritable_runtime_dirs() {
    // 父目录无写权限（EACCES）：读路径 merge 不 mkdir，配置照常解析。
    if nix::unistd::geteuid().is_root() {
        // root 不受 DAC 检查约束，造不出 EACCES，跳过。
        return;
    }
    let tmp = TempDir::new().expect("tempdir");
    let ro = tmp.path().join("ro");
    std::fs::create_dir(&ro).expect("mkdir ro");
    let perms_guard = ReadOnlyGuard::new(&ro);
    let global = test_global_config_with_temp_dirs(&ro);
    let result = Config::merge_configs("p3-ro", global, ProductConfig::default());
    drop(perms_guard);
    let cfg = result.expect("read-path merge must survive unwritable dirs");
    assert!(!cfg.crbs_root.exists());
}

#[test]
fn ensure_runtime_dirs_creates_dirs_and_is_idempotent() {
    let tmp = TempDir::new().expect("tempdir");
    let global = test_global_config_with_temp_dirs(tmp.path());
    let cfg =
        Config::merge_configs("p3-write", global, ProductConfig::default()).expect("merge_configs");
    cfg.ensure_runtime_dirs().expect("ensure creates dirs");
    assert!(cfg.crbs_root.is_dir());
    assert!(cfg.result_dir.is_dir());
    assert!(cfg.shared_layers_dir.is_dir());
    assert!(cfg.tmpfs_dir.is_dir());
    assert!(cfg.tmp_dir.is_dir());
    assert!(cfg.ccache_dir.is_dir());
    // base_os 刻意不建：空 base 目录会让 `crbs init` 的 already-exists 守卫误判已初始化。
    assert!(!cfg.base_os_path.exists());
    cfg.ensure_runtime_dirs().expect("ensure is idempotent");
}

/// 显式指到系统共享 tmp（/var/tmp、/dev/shm）绝不能被 ensure chmod：
/// 全机共享资源，按 crbs 量级改权限会阻断其他用户使用。
/// （默认值已归一到 {crbs_root}/tmp、{crbs_root}/tmpfs，不属系统共享目录。）
#[test]
fn ensure_runtime_dirs_skips_system_tmp_dirs() {
    let tmp = TempDir::new().expect("tempdir");
    let global = test_global_config_with_temp_dirs(tmp.path());
    let mut cfg = Config::merge_configs("p3-systmp", global, ProductConfig::default())
        .expect("merge_configs");
    cfg.tmp_dir = std::path::PathBuf::from("/var/tmp");
    cfg.tmpfs_dir = std::path::PathBuf::from("/dev/shm");
    let before = std::fs::metadata("/var/tmp").unwrap().permissions();
    cfg.ensure_runtime_dirs().expect("ensure succeeds");
    let after = std::fs::metadata("/var/tmp").unwrap().permissions();
    assert_eq!(
        before, after,
        "system tmp dir must not be chmod'd by ensure"
    );
}

/// 测试辅助：目录置 0555，drop 时恢复 0755（TempDir 清理需要写权限）。
struct ReadOnlyGuard {
    path: PathBuf,
}

impl ReadOnlyGuard {
    fn new(path: &std::path::Path) -> Self {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o555)).expect("chmod 0555");
        Self {
            path: path.to_path_buf(),
        }
    }
}

impl Drop for ReadOnlyGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o755));
    }
}

#[test]
fn merge_product_configs_ignores_child_crbs_root() {
    use super::merge::merge_product_configs;

    let parent = ProductConfig {
        crbs_root: Some(PathBuf::from("/var/lib/crbs")),
        ..Default::default()
    };
    let child = ProductConfig {
        crbs_root: Some(PathBuf::from("/data/crbs")),
        ..Default::default()
    };
    let out = merge_product_configs(&parent, &child);
    assert_eq!(
        out.crbs_root.as_deref(),
        Some(PathBuf::from("/var/lib/crbs").as_path())
    );
}

/// 钉住 `repo_publish` 在 `override_some!` 字段清单内：child 覆盖 parent，未设继承。
#[test]
fn merge_product_configs_child_repo_publish_overrides_parent() {
    let parent = ProductConfig {
        repo_publish: Some(true),
        ..Default::default()
    };
    let child = ProductConfig {
        repo_publish: Some(false),
        ..Default::default()
    };
    let merged = merge_product_configs(&parent, &child);
    assert_eq!(merged.repo_publish, Some(false));
    let merged2 = merge_product_configs(&parent, &ProductConfig::default());
    assert_eq!(merged2.repo_publish, Some(true));
}

/// 钉住 `repo_consume` 在 `override_some!` 字段清单内：child 覆盖 parent，
/// 未设继承；与 repo_publish 互不牵连（正交双轴）。
#[test]
fn merge_product_configs_child_repo_consume_overrides_parent() {
    let parent = ProductConfig {
        repo_publish: Some(false),
        repo_consume: Some(true),
        ..Default::default()
    };
    let child = ProductConfig {
        repo_consume: Some(false),
        ..Default::default()
    };
    let merged = merge_product_configs(&parent, &child);
    assert_eq!(merged.repo_consume, Some(false));
    assert_eq!(merged.repo_publish, Some(false), "publish axis untouched");
    let merged2 = merge_product_configs(&parent, &ProductConfig::default());
    assert_eq!(merged2.repo_consume, Some(true));
}

/// CrbsConfig 拒绝未知字段：拼写错误（如 `builder_usr`）不会静默落默认值；其余 7 个配置结构体均已 deny。
#[test]
fn crbs_config_rejects_unknown_field() {
    let err = toml::from_str::<crate::config::CrbsConfig>("builder_usr = \"crbs\"\n").unwrap_err();
    assert!(err.to_string().contains("unknown field"));

    let ok = toml::from_str::<crate::config::CrbsConfig>("builder_user = \"crbs\"\n").unwrap();
    assert_eq!(ok.builder_user, "crbs");
}

/// gpg_home 拒绝相对路径 / 含 `..`（validate_config_path，路径防穿越）：加载期
/// 早失败 + 防御纵深，sign.rs 运行时另有 0700/owner 深度校验。
#[test]
fn merge_configs_rejects_relative_gpg_home() {
    let tmp = TempDir::new().expect("tempdir");
    let global = test_global_config_with_temp_dirs(tmp.path());
    let product = ProductConfig {
        gpg_home: Some("relative/gh".into()),
        gpg_signing_enabled: None,
        ..Default::default()
    };
    let err = Config::merge_configs("gpg-test", global, product).unwrap_err();
    assert!(matches!(
        err,
        crate::error::CrbsError::ValidationFailed { .. }
    ));
    assert!(err.to_string().contains("gpg_home"));
}

/// chain_parallelism=0 → depsolve `Semaphore::new(0)` 永久挂起（无超时无报错），配置层必须拒绝。
#[test]
fn merge_configs_rejects_zero_chain_parallelism() {
    let tmp = TempDir::new().expect("tempdir");
    let global = test_global_config_with_temp_dirs(tmp.path());
    let product = ProductConfig {
        chain_parallelism: Some(0),
        ..Default::default()
    };
    let err = Config::merge_configs("cp-test", global, product).unwrap_err();
    assert!(matches!(
        err,
        crate::error::CrbsError::ValidationFailed { .. }
    ));
    assert!(
        err.to_string().contains("chain_parallelism"),
        "message should name the field: {}",
        err
    );
}

/// repo name 拼接进 dnf `--repofrompath` / `--setopt`：逗号/空白/冒号让 chain 中途 repoquery 失败，加载期拒绝。
#[test]
fn merge_configs_rejects_repo_name_breaking_dnf_args() {
    for bad in ["my repo", "a,b", "x:y", ""] {
        let tmp = TempDir::new().expect("tempdir");
        let global = test_global_config_with_temp_dirs(tmp.path());
        let product = ProductConfig {
            repos: vec![RepoConfig {
                name: bad.into(),
                baseurl: "http://example/repo".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let err = Config::merge_configs("rn-test", global, product).unwrap_err();
        assert!(
            matches!(err, crate::error::CrbsError::ValidationFailed { .. }),
            "repo name {:?} should be rejected",
            bad
        );
        assert!(
            err.to_string().contains("repo name"),
            "message should name the field: {}",
            err
        );
    }
}

/// dnf repo id 惯例字符（字母数字、`_`、`-`、`.`）必须继续合法：存量点分 repo 名不被新校验破坏。
#[test]
fn merge_configs_accepts_repo_name_with_dnf_id_charset() {
    let tmp = TempDir::new().expect("tempdir");
    let global = test_global_config_with_temp_dirs(tmp.path());
    let product = ProductConfig {
        repos: vec![RepoConfig {
            name: "openEuler-24.03-LTS_EPOL".into(),
            baseurl: "http://example/repo".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let cfg = Config::merge_configs("rn-ok", global, product).expect("valid repo name");
    assert_eq!(cfg.repos[0].name, "openEuler-24.03-LTS_EPOL");
}

/// `RemoteProfile::token` 明文密钥，Debug 必须脱敏（意外 `{:?}` 进日志不泄露）；其余字段正常输出便于排障。
#[test]
fn remote_profile_debug_redacts_token() {
    let with_token = RemoteProfile {
        name: "hub".into(),
        url: "https://hub.example.com".into(),
        token: Some("crbs_tok_plaintext_secret".into()),
        token_env: None,
        token_file: None,
        ca_cert: None,
    };
    let debug = format!("{with_token:?}");
    assert!(!debug.contains("crbs_tok_plaintext_secret"), "got: {debug}");
    assert!(debug.contains("<redacted>"), "got: {debug}");
    assert!(debug.contains("hub") && debug.contains("https://hub.example.com"));

    let without_token = RemoteProfile {
        token: None,
        ..with_token
    };
    let debug = format!("{without_token:?}");
    assert!(debug.contains("token: None"), "got: {debug}");
}

/// 多字节末字符（如 "7天"）不能让 `parse_staleness` panic：按字符边界切分，坏输入走 ValidationFailed。
#[test]
fn test_parse_staleness_multibyte_no_panic() {
    // 失败模式：多字节单位 → unknown unit；全角数字 → 数字解析失败；纯多字节 → 数字为空
    let err = parse_staleness("7天").unwrap_err();
    assert!(err.to_string().contains("unknown unit"), "got: {err}");
    assert!(parse_staleness("７d").is_err());
    assert!(parse_staleness("天").is_err());
    let ok = parse_staleness("7d");
    assert!(ok.is_ok(), "got: {ok:?}");
}

/// 裸后缀（数字部分为空）必须拒绝：systemd 对 "K" / "%" 同样报错。
#[test]
fn test_validate_memory_max_bare_suffix_rejected() {
    for v in ["K", "M", "G", "T"] {
        assert!(
            validate_memory_max(v).is_err(),
            "bare suffix '{v}' must be rejected"
        );
    }
    assert!(validate_memory_max("0K").is_ok());
    assert!(validate_memory_max("0").is_ok());
}

#[test]
fn test_validate_cpu_quota_bare_suffix_rejected() {
    assert!(
        validate_cpu_quota("%").is_err(),
        "bare '%' must be rejected"
    );
    // "0"/"0%" = 内核 EINVAL 而非"无限制"，拒绝；非 0 的 % 后缀合法。
    assert!(validate_cpu_quota("0%").is_err());
    assert!(validate_cpu_quota("0").is_err());
    assert!(validate_cpu_quota("50%").is_ok());
}

/// 配置目录必须为非空绝对路径（`CRBS_CONFIG_DIR` / `--config-dir` 共用校验）。
#[test]
fn test_validate_config_dir() {
    assert!(super::validation::validate_config_dir(std::path::Path::new("/etc/crbs")).is_ok());
    for bad in ["", "relative/crbs", "./crbs", "."] {
        let err = super::validation::validate_config_dir(std::path::Path::new(bad)).unwrap_err();
        assert!(
            err.to_string().contains("absolute path"),
            "expected absolute-path error for {bad:?}, got: {err}"
        );
    }
}

/// 产品名校验收严为 ASCII-only（委托 core `validate_product`）：拒绝 Unicode 同形字（西里尔 'а'）与路径穿越。
#[test]
fn test_validate_product_name_rejects_unicode_and_path_tricks() {
    assert!(super::validation::validate_product_name("openEuler-24_03").is_ok());
    for bad in [
        "pr\u{43E}duct",
        "产品",
        "../escape",
        "a/b",
        "",
        "my product",
    ] {
        assert!(
            super::validation::validate_product_name(bad).is_err(),
            "expected rejection for {bad:?}"
        );
    }
}

/// repo exclude/includepkgs 含空格或逗号必须拒绝：查询期（.repo 空格 join）与构建期（--setopt 逗号 join）静默分叉。
#[test]
fn test_validate_repo_config_rejects_space_and_comma_in_pkg_globs() {
    fn repo_with(exclude: Vec<String>, includepkgs: Vec<String>) -> RepoConfig {
        RepoConfig {
            name: "cc9-base".into(),
            baseurl: "https://repo.example.com/cc9/os/x86_64/".into(),
            exclude,
            includepkgs,
            ..Default::default()
        }
    }

    let err =
        super::validation::validate_repo_config(&repo_with(vec!["kernel* debug".into()], vec![]))
            .unwrap_err();
    assert!(
        err.to_string().contains("spaces or commas"),
        "expected space/comma rejection for exclude, got: {err}"
    );

    let err =
        super::validation::validate_repo_config(&repo_with(vec![], vec!["bash,coreutils".into()]))
            .unwrap_err();
    assert!(
        err.to_string().contains("spaces or commas"),
        "expected space/comma rejection for includepkgs, got: {err}"
    );

    assert!(super::validation::validate_repo_config(&repo_with(
        vec!["kernel-*".into()],
        vec!["bash".into()]
    ))
    .is_ok());
}

// 确定性模式：merge 合并后校验与 _buildhost 合并语义。

/// deterministic + 未开 dnf_cache（全局或产品级）合并即报错且带修复指引；产品级 true 可救活全局 false。
#[test]
fn merge_configs_deterministic_requires_dnf_cache() {
    let tmp = TempDir::new().expect("tempdir");
    let global = test_global_config_with_temp_dirs(tmp.path());
    let product = ProductConfig {
        base_packages: vec!["bash".into()],
        deterministic: true,
        mtime_normalize: false,
        repos: vec![],
        ..ProductConfig::default()
    };
    let err = Config::merge_configs("det-test", global.clone(), product.clone()).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("dnf_cache_enabled"), "got: {msg}");
    assert!(msg.contains("crbs.toml"), "must carry fix guidance: {msg}");

    let mut rescued = product.clone();
    rescued.dnf_cache_enabled = Some(true);
    let cfg = Config::merge_configs("det-test", global, rescued).expect("merge ok");
    assert!(cfg.deterministic);
}

/// deterministic + 全局 build_target=ba 在配置合并后报错（产品级 bb 可救）。
#[test]
fn merge_configs_deterministic_rejects_ba() {
    let tmp = TempDir::new().expect("tempdir");
    let mut global = test_global_config_with_temp_dirs(tmp.path());
    global.build_target = "ba".into();
    let product = ProductConfig {
        base_packages: vec!["bash".into()],
        deterministic: true,
        mtime_normalize: false,
        dnf_cache_enabled: Some(true),
        repos: vec![],
        ..ProductConfig::default()
    };
    let err = Config::merge_configs("det-ba", global.clone(), product.clone()).unwrap_err();
    assert!(err.to_string().contains("'bb'"), "got: {err}");

    let mut rescued = product;
    rescued.build_target = Some("bb".into());
    Config::merge_configs("det-ba", global, rescued).expect("product bb override rescues");
}

/// `_buildhost` 合并：未配置默认 "crbs"；产品级覆盖生效；空串归一回落默认。
#[test]
fn merge_configs_buildhost_default_and_override() {
    let tmp = TempDir::new().expect("tempdir");
    let global = test_global_config_with_temp_dirs(tmp.path());
    let product = ProductConfig {
        base_packages: vec!["bash".into()],
        deterministic: true,
        mtime_normalize: false,
        dnf_cache_enabled: Some(true),
        repos: vec![],
        ..ProductConfig::default()
    };
    let cfg = Config::merge_configs("det-host", global.clone(), product.clone()).unwrap();
    assert_eq!(cfg.buildhost, "crbs");

    let mut overridden = product.clone();
    overridden._buildhost = Some("build-pool-a".into());
    let cfg = Config::merge_configs("det-host", global.clone(), overridden).unwrap();
    assert_eq!(cfg.buildhost, "build-pool-a");

    let mut empty = product;
    empty._buildhost = Some("  ".into());
    let cfg = Config::merge_configs("det-host", global, empty).unwrap();
    assert_eq!(
        cfg.buildhost, "crbs",
        "blank _buildhost normalizes to default"
    );
}

/// 链合并 OR 语义：child true 点亮；父层 true 不被 child false 关闭（关闭须改父层，防混跑静默漂移）。
#[test]
fn chain_merge_deterministic_is_or_semantics() {
    let parent = ProductConfig {
        deterministic: true,
        mtime_normalize: false,
        ..ProductConfig::default()
    };
    let child = ProductConfig::default();
    assert!(merge_product_configs(&parent, &child).deterministic);

    let parent = ProductConfig::default();
    let child = ProductConfig {
        deterministic: true,
        mtime_normalize: false,
        ..ProductConfig::default()
    };
    let merged = merge_product_configs(&parent, &child);
    assert!(merged.deterministic);
    // _buildhost 链透传（override_some! 清单内）
    let parent = ProductConfig {
        _buildhost: Some("parent-host".into()),
        ..ProductConfig::default()
    };
    let child = ProductConfig {
        _buildhost: Some("child-host".into()),
        ..ProductConfig::default()
    };
    assert_eq!(
        merge_product_configs(&parent, &child)._buildhost,
        Some("child-host".into())
    );
}

/// 链合并 OR 语义（mtime_normalize，同 deterministic）：child true 点亮；
/// 父层 true 不被 child false 关闭（关闭须改父层）；全 false 保持 false。
#[test]
fn chain_merge_mtime_normalize_is_or_semantics() {
    let parent = ProductConfig {
        deterministic: false,
        mtime_normalize: true,
        ..ProductConfig::default()
    };
    let child = ProductConfig::default();
    assert!(merge_product_configs(&parent, &child).mtime_normalize);

    let parent = ProductConfig::default();
    let child = ProductConfig {
        deterministic: false,
        mtime_normalize: true,
        ..ProductConfig::default()
    };
    assert!(merge_product_configs(&parent, &child).mtime_normalize);

    let parent = ProductConfig::default();
    let child = ProductConfig::default();
    assert!(!merge_product_configs(&parent, &child).mtime_normalize);
}
