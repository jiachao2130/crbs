// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! hub 远端产品 repo URL 推导；仅 worker 任务领取路径调用（经
//! `BuildEngine::with_product_repo_url` 注入），`build`/`shell`/`debug` 本地构建不调用（无 hub URL 来源）。

use tracing::warn;

/// 推导产品 repo baseurl：`{hub_url_no_trailing_slash}/repo/{product}/{arch}`。
/// 门禁（任一命中即 `None` 安全回退）：`enabled == false`（产品私有，绝不注入）；
/// `network == false`（dnf 网络关闭，http 源无意义）；`hub_url` 规范化后空；
/// arch 含 [a-zA-Z0-9_] 外字符——arch 直拼 baseurl，空白/控制字符可向
/// `crbs-product.repo` 注入 dnf 指令（`--arch $'x86_64\ngpgcheck=0'`），`/`、`..` 可路径穿越。
/// arch 优先级：`opts_arch`（task / multi-arch 显式）> `worker_arch`（独立构建）。
/// effective arch 为 noarch 时映射到 `product_arches` 第一个具体 arch——hub 从不创建
/// `_repo/{product}/noarch/`，直拼会被 `skip_if_unavailable=1` 静默丢源；纯 noarch → `None` + warn（base 源兜底）。
pub fn decide_product_repo_url(
    hub_url: &str,
    product: &str,
    opts_arch: Option<&str>,
    worker_arch: &str,
    product_arches: &[String],
    enabled: bool,
    network: bool,
) -> Option<String> {
    if !enabled {
        return None;
    }
    if !network {
        return None;
    }
    let arch = opts_arch
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(worker_arch);
    if arch.is_empty() {
        return None;
    }
    let arch = if arch == "noarch" {
        // hub 从不发布 noarch 目录（repo_publish 有测试锁定）；纯 noarch 产品不注入。
        match product_arches.iter().find(|a| a.as_str() != "noarch") {
            Some(concrete) => {
                warn!(
                    product,
                    concrete_arch = %concrete,
                    "noarch task mapped to product's first concrete arch for product repo URL"
                );
                concrete.as_str()
            }
            None => {
                warn!(
                    product,
                    "noarch task on a no-concrete-arch product; skipping product repo injection"
                );
                return None;
            }
        }
    } else {
        arch
    };
    if let Err(e) = crate::validation::validate_arch(arch) {
        warn!(arch = ?arch, error = %e, "Invalid arch, skipping product repo injection");
        return None;
    }
    let hub = hub_url.trim().trim_end_matches('/');
    if hub.is_empty() {
        return None;
    }
    Some(format!("{}/repo/{}/{}", hub, product, arch))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> (&'static str, &'static str, &'static str) {
        ("http://hub.example.com", "prod", "x86_64")
    }

    fn arches(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn decide_enabled_with_opts_arch() {
        let (hub, p, _) = base();
        let url =
            decide_product_repo_url(hub, p, Some("aarch64"), "x86_64", &[], true, true).unwrap();
        assert_eq!(url, "http://hub.example.com/repo/prod/aarch64");
    }

    #[test]
    fn decide_falls_back_to_worker_arch() {
        let (hub, p, _) = base();
        let url = decide_product_repo_url(hub, p, None, "x86_64", &[], true, true).unwrap();
        assert_eq!(url, "http://hub.example.com/repo/prod/x86_64");
    }

    #[test]
    fn decide_strips_trailing_slash() {
        let (_, p, _) = base();
        let url = decide_product_repo_url(
            "http://hub.example.com/",
            p,
            Some("x86_64"),
            "x86_64",
            &[],
            true,
            true,
        )
        .unwrap();
        assert_eq!(url, "http://hub.example.com/repo/prod/x86_64");
    }

    #[test]
    fn decide_disabled_returns_none() {
        assert!(decide_product_repo_url(
            "http://hub.example.com",
            "prod",
            Some("x86_64"),
            "x86_64",
            &[],
            false,
            true
        )
        .is_none());
    }

    #[test]
    fn decide_network_off_returns_none() {
        assert!(decide_product_repo_url(
            "http://hub.example.com",
            "prod",
            Some("x86_64"),
            "x86_64",
            &[],
            true,
            false
        )
        .is_none());
    }

    #[test]
    fn decide_empty_hub_returns_none() {
        assert!(
            decide_product_repo_url("", "prod", Some("x86_64"), "x86_64", &[], true, true)
                .is_none()
        );
        assert!(
            decide_product_repo_url("   ", "prod", Some("x86_64"), "x86_64", &[], true, true)
                .is_none()
        );
        assert!(
            decide_product_repo_url("/", "prod", Some("x86_64"), "x86_64", &[], true, true)
                .is_none()
        );
    }

    #[test]
    fn decide_empty_opts_arch_falls_back() {
        let (hub, p, _) = base();
        let url = decide_product_repo_url(hub, p, Some("   "), "x86_64", &[], true, true).unwrap();
        assert_eq!(url, "http://hub.example.com/repo/prod/x86_64");
    }

    /// 注入形态 `--arch $'x86_64\ngpgcheck=0'` 把 dnf 指令写进 crbs-product.repo，须在拼 URL 前拒绝。
    #[test]
    fn decide_rejects_arch_with_directive_injection() {
        let (hub, p, _) = base();
        assert!(decide_product_repo_url(
            hub,
            p,
            Some("x86_64\ngpgcheck=0"),
            "x86_64",
            &[],
            true,
            true
        )
        .is_none());
    }

    /// 路径穿越与空白同样拒绝：arch 是 URL 的单一路径分量。
    #[test]
    fn decide_rejects_arch_with_traversal_or_whitespace() {
        let (hub, p, _) = base();
        for bad in ["..", "../evil", "x86_64/..", "a/b", "a b", "a\tb"] {
            assert!(
                decide_product_repo_url(hub, p, Some(bad), "x86_64", &[], true, true).is_none(),
                "arch {:?} must be rejected",
                bad
            );
        }
    }

    /// 回退路径同样校验：worker_arch 不可信（server 侧注册字符集更宽）。
    #[test]
    fn decide_rejects_invalid_worker_arch_fallback() {
        let (hub, p, _) = base();
        assert!(decide_product_repo_url(hub, p, None, "x86 64", &[], true, true).is_none());
        assert!(decide_product_repo_url(hub, p, Some("   "), "arm..64", &[], true, true).is_none());
    }

    /// noarch 任务 + 产品配置有具体 arch → URL 用第一个具体 arch。
    #[test]
    fn decide_noarch_maps_to_first_concrete_arch() {
        let (hub, p, _) = base();
        let url = decide_product_repo_url(
            hub,
            p,
            Some("noarch"),
            "x86_64",
            &arches(&["x86_64", "aarch64"]),
            true,
            true,
        )
        .unwrap();
        assert_eq!(url, "http://hub.example.com/repo/prod/x86_64");
        let url = decide_product_repo_url(
            hub,
            p,
            Some("noarch"),
            "x86_64",
            &arches(&["noarch", "aarch64", "riscv64"]),
            true,
            true,
        )
        .unwrap();
        assert_eq!(url, "http://hub.example.com/repo/prod/aarch64");
    }

    /// noarch worker_arch 回退路径同样映射。
    #[test]
    fn decide_noarch_worker_arch_also_maps() {
        let (hub, p, _) = base();
        let arches = arches(&["x86_64"]);
        let url = decide_product_repo_url(hub, p, None, "noarch", &arches, true, true).unwrap();
        assert_eq!(url, "http://hub.example.com/repo/prod/x86_64");
    }

    /// 纯 noarch 产品 / 空配置（如 worker 无产品配置回退本地）→ 不注入（base 源兜底）。
    #[test]
    fn decide_noarch_without_concrete_arches_skips_injection() {
        let (hub, p, _) = base();
        assert!(decide_product_repo_url(
            hub,
            p,
            Some("noarch"),
            "x86_64",
            &arches(&["noarch"]),
            true,
            true
        )
        .is_none());
        assert!(
            decide_product_repo_url(hub, p, Some("noarch"), "x86_64", &[], true, true).is_none()
        );
    }
}
