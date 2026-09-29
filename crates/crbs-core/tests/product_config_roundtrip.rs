// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
//
// `ProductConfig` 的 TOML round-trip 测试。
//
// 校验：
// - `Serialize` 输出可被 `Deserialize` 无损吃回（语义等价，不要求逐字节一致）
// - `None`/空集合 字段在 serialize 结果中被省略（数据库存储紧凑、TOML 可读）
// - 嵌套结构（Repo、Hooks、post_init）保留顺序与内容

// 整个文件是测试 crate：测试辅助函数（如 roundtrip）不带 #[test] 属性，
// clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use crbs_core::config::{BoolOrPackages, ProductConfig};

const FULL_FIXTURE: &str = include_str!("fixtures/products/full.toml");
const MYDIST_FIXTURE: &str = include_str!("fixtures/products/mydist.toml");

/// 帮助函数：parse → serialize → parse → 断言两次 parse 结果的关键字段相等。
///
/// 不比较原始 TOML 文本（serde toml 输出的表顺序、空白、引号风格与手写 TOML
/// 不同）——只保证语义层面幂等。
fn roundtrip(toml_text: &str) -> ProductConfig {
    let first = ProductConfig::from_str(toml_text).expect("first parse");
    let serialized = first.to_toml_string().expect("serialize");
    let second = ProductConfig::from_str(&serialized).expect("second parse from serialized");
    assert_eq!(first.product, second.product, "product");
    assert_eq!(first.base_packages, second.base_packages, "base_packages");
    assert_eq!(first.repos.len(), second.repos.len(), "repos len");
    for (a, b) in first.repos.iter().zip(second.repos.iter()) {
        assert_eq!(a.name, b.name, "repo.name");
        assert_eq!(a.baseurl, b.baseurl, "repo.baseurl");
        assert_eq!(a.enabled, b.enabled, "repo.enabled");
        assert_eq!(a.gpgcheck, b.gpgcheck, "repo.gpgcheck");
        assert_eq!(a.gpgkey, b.gpgkey, "repo.gpgkey");
        assert_eq!(a.priority, b.priority, "repo.priority");
        assert_eq!(a.cost, b.cost, "repo.cost");
    }
    assert_eq!(first.arches, second.arches, "arches");
    assert_eq!(first.releasever, second.releasever, "releasever");
    assert_eq!(first.overlay_dir, second.overlay_dir, "overlay_dir");
    assert_eq!(first.crbs_root, second.crbs_root, "crbs_root");
    assert_eq!(first.result_dir, second.result_dir, "result_dir");
    assert_eq!(first.product_root, second.product_root, "product_root");
    assert_eq!(first.base_os_path, second.base_os_path, "base_os_path");
    assert_eq!(first.builder_user, second.builder_user, "builder_user");
    assert_eq!(first.builder_uid, second.builder_uid, "builder_uid");
    assert_eq!(first.rpm_macros, second.rpm_macros, "rpm_macros");
    assert_eq!(first.build_tmpfs, second.build_tmpfs, "build_tmpfs");
    assert_eq!(first.backend, second.backend, "backend");
    second
}

#[test]
fn roundtrip_minimal_product() {
    let text = r#"
base_packages = ["glibc", "bash"]

[[repos]]
name = "os"
baseurl = "https://mirror.example.com/os"
"#;
    roundtrip(text);
}

#[test]
fn roundtrip_full_product_fixture() {
    roundtrip(FULL_FIXTURE);
}

#[test]
fn roundtrip_deployment_mydist_fixture() {
    roundtrip(MYDIST_FIXTURE);
}

#[test]
fn roundtrip_omits_none_fields() {
    let cfg = ProductConfig::from_str(
        r#"
base_packages = ["glibc"]

[[repos]]
name = "os"
baseurl = "https://example.com"
"#,
    )
    .expect("parse");
    let serialized = cfg.to_toml_string().expect("serialize");
    // Option::None 字段应完全不出现在输出中
    assert!(
        !serialized.contains("crbs_root"),
        "None field crbs_root should be skipped, got:\n{}",
        serialized
    );
    assert!(
        !serialized.contains("releasever"),
        "None field releasever should be skipped, got:\n{}",
        serialized
    );
    assert!(
        !serialized.contains("gpg_signing_key_id"),
        "None field gpg_signing_key_id should be skipped, got:\n{}",
        serialized
    );
    assert!(
        !serialized.contains("hooks"),
        "None field hooks should be skipped, got:\n{}",
        serialized
    );
}

#[test]
fn roundtrip_omits_empty_arches_vec() {
    let cfg = ProductConfig::from_str(
        r#"
base_packages = ["glibc"]
arches = []

[[repos]]
name = "os"
baseurl = "https://example.com"
"#,
    )
    .expect("parse");
    let serialized = cfg.to_toml_string().expect("serialize");
    assert!(
        !serialized.contains("arches"),
        "empty arches Vec should be skipped, got:\n{}",
        serialized
    );
}

#[test]
fn roundtrip_preserves_repo_order() {
    let text = r#"
base_packages = ["glibc"]

[[repos]]
name = "first"
baseurl = "https://a.example.com"

[[repos]]
name = "second"
baseurl = "https://b.example.com"

[[repos]]
name = "third"
baseurl = "https://c.example.com"
"#;
    let out = roundtrip(text);
    assert_eq!(out.repos[0].name, "first");
    assert_eq!(out.repos[1].name, "second");
    assert_eq!(out.repos[2].name, "third");
}

#[test]
fn roundtrip_preserves_rpm_macros() {
    let text = r#"
base_packages = ["glibc"]

[[repos]]
name = "os"
baseurl = "https://example.com"

[rpm_macros]
_topdir = "/builddir/build"
dist = ".el9"
_binary_payload = "w9.gzdio"
"#;
    let out = roundtrip(text);
    let macros = out.rpm_macros.expect("rpm_macros present");
    assert_eq!(
        macros.get("_topdir").map(String::as_str),
        Some("/builddir/build")
    );
    assert_eq!(macros.get("dist").map(String::as_str), Some(".el9"));
    assert_eq!(
        macros.get("_binary_payload").map(String::as_str),
        Some("w9.gzdio")
    );
    assert_eq!(macros.len(), 3);
}

/// 宏表序列化跨进程确定（终审 L7b）：`rpm_macros` 是 BTreeMap，TOML 输出按
/// key 字典序排列——DB `config_json`、chain-resolve 下发 worker 的 TOML、
/// history diff 归一 TOML 因此逐字节可复现（换 HashMap 则迭代序随进程随机，
/// history diff 出假差异）。
#[test]
fn rpm_macros_toml_output_is_deterministically_sorted() {
    let text = r#"
base_packages = ["glibc"]

[rpm_macros]
zzz_last = "3"
dist = "1"
_topdir = "0"
mid = "2"
"#;
    let cfg = ProductConfig::from_str(text).expect("parse");
    let serialized = cfg.to_toml_string().expect("serialize");
    let positions: Vec<usize> = ["_topdir", "dist", "mid", "zzz_last"]
        .iter()
        .map(|k| {
            serialized
                .find(&format!("{k} ="))
                .unwrap_or_else(|| panic!("key {k} missing in output:\n{serialized}"))
        })
        .collect();
    assert!(
        positions.windows(2).all(|w| w[0] < w[1]),
        "macro keys must appear in lexicographic order in TOML output:\n{serialized}"
    );
}

#[test]
fn roundtrip_preserves_hooks_nested() {
    let text = r#"
base_packages = ["glibc"]

[[repos]]
name = "os"
baseurl = "https://example.com"

[hooks.pre]
"install-srpm" = "echo pre-install"

[hooks.post]
"build" = "echo post-build"

[hooks.spec.pre]
"prep" = "echo pre-prep"

[hooks.spec.post]
"install" = "echo post-install"
"#;
    let out = roundtrip(text);
    let hooks = out.hooks.expect("hooks present");
    assert_eq!(
        hooks.pre.get("install-srpm").map(String::as_str),
        Some("echo pre-install")
    );
    assert_eq!(
        hooks.post.get("build").map(String::as_str),
        Some("echo post-build")
    );
    assert_eq!(
        hooks.spec.pre.get("prep").map(String::as_str),
        Some("echo pre-prep")
    );
    assert_eq!(
        hooks.spec.post.get("install").map(String::as_str),
        Some("echo post-install")
    );
}

#[test]
fn roundtrip_preserves_bool_or_packages_variants() {
    // Bool 变体
    let bool_text = r#"
base_packages = ["glibc"]
shared_layer = true
ccache_enabled = false

[[repos]]
name = "os"
baseurl = "https://example.com"
"#;
    let out = roundtrip(bool_text);
    assert!(matches!(out.shared_layer, Some(BoolOrPackages::Bool(true))));
    assert!(matches!(
        out.ccache_enabled,
        Some(BoolOrPackages::Bool(false))
    ));

    // Packages 变体
    let pkg_text = r#"
base_packages = ["glibc"]
shared_layer = ["kernel", "systemd"]
ccache_enabled = ["gcc"]

[[repos]]
name = "os"
baseurl = "https://example.com"
"#;
    let out = roundtrip(pkg_text);
    match out.shared_layer {
        Some(BoolOrPackages::Packages(pkgs)) => assert_eq!(pkgs, vec!["kernel", "systemd"]),
        other => panic!("expected Packages, got {:?}", other),
    }
    match out.ccache_enabled {
        Some(BoolOrPackages::Packages(pkgs)) => assert_eq!(pkgs, vec!["gcc"]),
        other => panic!("expected Packages, got {:?}", other),
    }
}

#[test]
fn roundtrip_preserves_post_init_order() {
    let text = r#"
base_packages = ["glibc"]

[[repos]]
name = "os"
baseurl = "https://example.com"

[[post_init]]
command = "step-one"

[[post_init]]
command = "step-two"

[[post_init]]
command = "step-three"
"#;
    let out = roundtrip(text);
    let post_init = out.post_init.expect("post_init present");
    assert_eq!(post_init.len(), 3);
    assert_eq!(post_init[0].command, "step-one");
    assert_eq!(post_init[1].command, "step-two");
    assert_eq!(post_init[2].command, "step-three");
}

#[test]
fn roundtrip_preserves_pathbuf_values() {
    let text = r#"
base_packages = ["glibc"]
crbs_root = "/var/lib/crbs"
overlay_dir = "/data/overlay"
base_os_path = "/var/lib/crbs/foo/base"

[[repos]]
name = "os"
baseurl = "https://example.com"
"#;
    let out = roundtrip(text);
    assert_eq!(out.crbs_root, Some(PathBuf::from("/var/lib/crbs")));
    assert_eq!(out.overlay_dir, Some(PathBuf::from("/data/overlay")));
    assert_eq!(
        out.base_os_path,
        Some(PathBuf::from("/var/lib/crbs/foo/base"))
    );
}
