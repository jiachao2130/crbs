// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! GC 核心逻辑（CLI 和 server 共用）。

use crate::config::CrbsConfig;
use crate::state::StateStore;
use crate::types::GcSummary;
use crate::validation::validate_product;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

mod orphan;

pub(crate) use orphan::fix_created_lock_perms;
mod package_cache;
mod results;
mod shared_layers;

use orphan::gc_orphan_mounts;
use package_cache::{gc_package_cache, gc_package_cache_all};
use results::gc_results;
use shared_layers::gc_shared_layers;

// 目录大小计算（迭代 + 深度限制版），engine::gc::results 也复用它。
pub(crate) use package_cache::calc_dir_size;

/// 删除前断言：target 严格位于 root 之下（词法判定，不触碰文件系统），
/// 防 `remove_dir_all` 路径逃逸（`..`、兄弟目录、共享根自身）；失败返回 `ValidationFailed`。
pub(crate) fn assert_delete_under_root(root: &Path, target: &Path) -> crate::Result<()> {
    use crate::error::CrbsError;

    let abs_root = std::path::absolute(root).map_err(|e| CrbsError::ValidationFailed {
        message: format!(
            "absolutize delete namespace root {} (target {}): {e}",
            root.display(),
            target.display()
        ),
    })?;
    let abs_target = std::path::absolute(target).map_err(|e| CrbsError::ValidationFailed {
        message: format!(
            "absolutize delete target {} (namespace root {}): {e}",
            target.display(),
            root.display()
        ),
    })?;
    let reject = |reason: &str| {
        Err(CrbsError::ValidationFailed {
            message: format!(
                "refuse to delete target {} (namespace root {}): {reason}",
                target.display(),
                root.display()
            ),
        })
    };
    if abs_target == abs_root {
        return reject("target is the namespace root itself");
    }
    let rel = match abs_target.strip_prefix(&abs_root) {
        Ok(rel) => rel,
        Err(_) => return reject("target is outside the namespace root"),
    };
    if rel
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return reject("target escapes the namespace root via ..");
    }
    Ok(())
}

/// layer digest 是否为 blake3 hex（64 位小写十六进制）；形状谓词单一真值在
/// [`crate::util::is_sha256_hex`]（blake3/sha256 hex 形状一致），此处仅域名薄封装。
pub(crate) fn is_layer_digest(digest: &str) -> bool {
    crate::util::is_sha256_hex(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assert_delete_under_root_allows_subpath() {
        let root = Path::new("/var/lib/crbs/cache/packages");
        assert!(assert_delete_under_root(root, &root.join("ab/abc123")).is_ok());
        assert!(
            assert_delete_under_root(root, &root.join("ab/abc123/name/version/file.rpm")).is_ok()
        );
    }

    #[test]
    fn test_assert_delete_under_root_rejects_parent_dir_escape() {
        let root = Path::new("/var/lib/crbs/cache/packages");
        assert!(assert_delete_under_root(
            root,
            Path::new("/var/lib/crbs/cache/packages/ab/../../other")
        )
        .is_err());
    }

    #[test]
    fn test_assert_delete_under_root_rejects_root_itself() {
        let root = Path::new("/var/lib/crbs/cache/packages");
        assert!(assert_delete_under_root(root, root).is_err());
    }

    #[test]
    fn test_assert_delete_under_root_rejects_sibling() {
        let root = Path::new("/var/lib/crbs/cache/packages");
        assert!(assert_delete_under_root(root, Path::new("/var/lib/crbs/cache/other")).is_err());
    }

    #[test]
    fn test_assert_delete_under_root_rejects_trailing_slash_root() {
        // components 级判等把 /a/b/ 与 /a/b 视为同一目录：root 自身不可删。
        let root = Path::new("/a/b/");
        assert!(assert_delete_under_root(root, Path::new("/a/b")).is_err());
    }

    #[test]
    fn test_assert_delete_under_root_degenerate_fs_root() {
        let root = Path::new("/");
        assert!(assert_delete_under_root(root, Path::new("/x")).is_ok());
        assert!(assert_delete_under_root(root, Path::new("/")).is_err());
        assert!(assert_delete_under_root(root, Path::new("/a/../x")).is_err());
    }

    #[test]
    fn test_is_layer_digest_valid_64_hex() {
        assert!(is_layer_digest(&"a".repeat(64)));
        assert!(is_layer_digest(&"0123456789abcdef".repeat(4)));
    }

    #[test]
    fn test_is_layer_digest_rejects_non_hex() {
        assert!(!is_layer_digest(&"g".repeat(64)));
        assert!(!is_layer_digest(""));
    }

    #[test]
    fn test_is_layer_digest_rejects_wrong_length_or_case() {
        assert!(!is_layer_digest(&"a".repeat(63)));
        assert!(!is_layer_digest(&"a".repeat(65)));
        assert!(!is_layer_digest(&"A".repeat(64)));
    }
}

/// GC 命令参数（CLI 和 server 共用）。
#[derive(Debug, Clone, Default)]
pub struct GcArgs {
    pub results: bool,
    pub product: Option<String>,
    pub dry_run: bool,
    pub orphan_mounts: bool,
    pub cache: bool,
    pub all: bool,
    pub policy: bool,
    /// hub 侧 worker 日志副本根覆盖（server.toml `artifact_dir`），结果 GC 联动
    /// 删除按该根定位；None = CLI 世界，派生 `{crbs_root}/artifacts`（非 serde，构造点填充）。
    pub artifact_dir: Option<PathBuf>,
}

/// 执行 GC 并返回结构化摘要。
pub async fn handle_gc(
    args: GcArgs,
    cfg: &CrbsConfig,
    state: &StateStore,
) -> crate::Result<GcSummary> {
    let GcArgs {
        results,
        product,
        dry_run,
        orphan_mounts,
        cache,
        all,
        policy,
        artifact_dir,
    } = args;

    let has_policy = cfg.package_cache_max_size_gb.is_some()
        || cfg.result_max_count_per_pkg.is_some()
        || cfg.result_retention_days.is_some();

    if dry_run && !results && !orphan_mounts && !cache && !policy {
        return Err(crate::error::CrbsError::ValidationFailed {
            message: "--dry-run must be used with --results, --orphan-mounts, --cache, or --policy"
                .into(),
        });
    }
    if product.is_some() && !results && !policy {
        return Err(crate::error::CrbsError::ValidationFailed {
            message: "--product must be used with --results or --policy".into(),
        });
    }
    if all && !cache {
        return Err(crate::error::CrbsError::ValidationFailed {
            message: "--all must be used with --cache".into(),
        });
    }
    if let Some(ref p) = product {
        validate_product(p)?;
    }

    info!(
        "Running garbage collection (results={}, dry_run={}, orphan_mounts={}, cache={}, all={}, policy={})",
        results, dry_run, orphan_mounts, cache, all, policy
    );

    let mut summary = GcSummary::default();

    if orphan_mounts {
        summary.orphan_mounts = Some(gc_orphan_mounts(dry_run, cfg, state).await?);
    }

    let product_ref = product.as_deref();

    if results {
        summary.results =
            Some(gc_results(product_ref, dry_run, cfg, artifact_dir.as_deref(), state).await?);
    }

    if cache {
        summary.package_cache = Some(if all {
            gc_package_cache_all(dry_run, cfg, state).await?
        } else {
            gc_package_cache(dry_run, cfg, state).await?
        });
    }

    // --policy 显式执行策略 GC；默认 `crbs gc` 在有策略配置时也执行策略 GC。
    if policy || (!results && !orphan_mounts && !cache && has_policy) {
        // 跳过显式分支已执行的目标，防重复执行覆盖 summary（--results --policy、--cache --all --policy）。
        if !results {
            info!(
                explicit = policy,
                product = ?product_ref,
                dry_run,
                "policy implies results GC; executing"
            );
            summary.results =
                Some(gc_results(product_ref, dry_run, cfg, artifact_dir.as_deref(), state).await?);
        }
        if !cache {
            info!(
                explicit = policy,
                dry_run, "policy implies package_cache GC; executing"
            );
            summary.package_cache = Some(gc_package_cache(dry_run, cfg, state).await?);
        }
    }

    if !results && !orphan_mounts && !cache && !policy {
        summary.shared_layers = Some(gc_shared_layers(state, cfg).await?);
    }

    // 清理过期 URL 缓存（轻量，伴随任意 GC 操作执行；dry-run 时跳过）
    if !dry_run && cfg.package_url_cache_ttl_days > 0 {
        match state
            .purge_stale_package_urls(cfg.package_url_cache_ttl_days)
            .await
        {
            Ok(purged) if purged > 0 => {
                info!(
                    purged,
                    ttl_days = cfg.package_url_cache_ttl_days,
                    "Purged stale package URL cache"
                )
            }
            Ok(_) => {}
            Err(e) => warn!(error = %e, "Failed to purge stale package URL cache"),
        }
    }

    Ok(summary)
}
