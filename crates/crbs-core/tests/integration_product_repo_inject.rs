// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 集成测试：hub 远端产品 repo 注入 chroot（覆盖点见各测试 doc）。

use std::path::Path;

use crbs_core::engine::product_repo::decide_product_repo_url;
use crbs_core::engine::repo::write_product_repo_conf;
use crbs_core::engine::{validate_product_repo_inject, write_product_repo_to_root};

/// 注入文件：baseurl 正确、`skip_if_unavailable=1`、`gpgcheck=0`（v1 repomd 未签名）、无 `priority`/`cost`。
/// 节名固定 `crbs-product`，不依赖 product 字符串。
#[tokio::test]
async fn chroot_repo_file_has_correct_baseurl_and_no_priority() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let url = "http://hub.example.com/repo/official-prod/x86_64";
    write_product_repo_to_root(root, url).await.unwrap();

    let conf_path = root.join("etc/yum.repos.d/crbs-product.repo");
    assert!(conf_path.exists(), "crbs-product.repo must be written");
    let body = tokio::fs::read_to_string(&conf_path).await.unwrap();

    assert!(
        body.contains(&format!("baseurl={}", url)),
        "must contain correct baseurl, got: {body}"
    );
    assert!(
        body.contains("skip_if_unavailable=1"),
        "must contain skip_if_unavailable=1, got: {body}"
    );
    assert!(
        body.contains("gpgcheck=0"),
        "must set gpgcheck=0, got: {body}"
    );
    assert!(body.contains("enabled=1"), "must be enabled, got: {body}");
    assert!(
        !body.contains("priority="),
        "must NOT set priority, got: {body}"
    );
    assert!(!body.contains("cost="), "must NOT set cost, got: {body}");
    assert!(
        body.contains("[crbs-product]"),
        "must use [crbs-product] section"
    );
}

/// `product_repo_enabled=false` → 不构造 URL、不注入（executor 端 `decide_product_repo_url`）。
#[test]
fn disabled_product_does_not_inject() {
    let url = decide_product_repo_url(
        "http://hub.example.com",
        "private-prod",
        Some("x86_64"),
        "x86_64",
        &["x86_64".to_string()],
        false, // product_repo_enabled = false
        true,  // network = true
    );
    assert!(
        url.is_none(),
        "private product must NOT inject, got: {url:?}"
    );
}

/// 网络门禁：`network=false` → 不构造 URL。
#[test]
fn network_false_skips_injection() {
    let url = decide_product_repo_url(
        "http://hub.example.com",
        "public-prod",
        Some("x86_64"),
        "x86_64",
        &["x86_64".to_string()],
        true,  // product_repo_enabled = true
        false, // network = false
    );
    assert!(
        url.is_none(),
        "network=false must skip injection (http source), got: {url:?}"
    );
}

/// 互斥：`local_repo` 与 `product_repo_url` 同选 → 拒绝。
#[test]
fn local_repo_and_product_repo_url_are_mutually_exclusive() {
    let local = Some(Path::new("/var/lib/crbs/repo"));
    assert!(validate_product_repo_inject(local, None).is_ok());
    assert!(validate_product_repo_inject(None, Some("http://h/r")).is_ok());
    let err = validate_product_repo_inject(local, Some("http://h/r"));
    assert!(err.is_err(), "both set must be rejected");
}

/// `write_product_repo_conf` 输入校验：非 http(s) → 拒绝。
#[test]
fn write_product_repo_conf_rejects_file_scheme_in_integration() {
    let err =
        write_product_repo_conf("file:///mnt/crbs-repo").expect_err("file:// must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("http://") || msg.contains("https://"),
        "error must hint http(s) requirement, got: {msg}"
    );
}

/// worker URL 推导端到端：公开产品 + 显式 arch + hub 尾斜杠 → 规范化 baseurl。
#[test]
fn decide_url_with_trailing_slash_and_explicit_arch() {
    let url = decide_product_repo_url(
        "http://hub.example.com/",
        "official-prod",
        Some("aarch64"),
        "x86_64",
        &["x86_64".to_string()],
        true,
        true,
    )
    .expect("must return Some");
    assert_eq!(url, "http://hub.example.com/repo/official-prod/aarch64");
}
