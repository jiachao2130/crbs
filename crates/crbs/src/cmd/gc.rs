// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use crate::cli::{validate_product, OutputFormat};
use crbs_core::config::CrbsConfig;
use crbs_core::gc::{handle_gc as run_gc, GcArgs};
use crbs_core::StateStore;

mod output;

pub(crate) struct GcCliArgs {
    pub results: bool,
    pub product: Option<String>,
    pub dry_run: bool,
    pub orphan_mounts: bool,
    pub cache: bool,
    pub all: bool,
    pub policy: bool,
    pub yes: bool,
    pub format: OutputFormat,
}

pub(crate) async fn handle_gc(
    args: GcCliArgs,
    cfg: &CrbsConfig,
    state: &StateStore,
) -> anyhow::Result<()> {
    if let Some(ref p) = args.product {
        validate_product(p)?;
    }

    if args.all && !args.dry_run {
        crate::cmd::confirm::confirm_or_bail(
            "Delete the ENTIRE package cache without checking build references?",
            args.yes,
        )?;
    }

    let gc_args = GcArgs {
        results: args.results,
        product: args.product,
        dry_run: args.dry_run,
        orphan_mounts: args.orphan_mounts,
        cache: args.cache,
        all: args.all,
        policy: args.policy,

        artifact_dir: None,
    };

    let summary = run_gc(gc_args, cfg, state).await?;

    args.format.print(&output::GcOutput(&summary))?;

    if let Some(ref results) = summary.results {
        for product in &results.affected_products {
            rebuild_product_repo_after_gc(state, cfg, product).await;
        }
    }

    Ok(())
}

/// gc --results 后对单个受影响产品的 repo 对账重建：被删构建若曾发布，硬链接副本仍留在 {result_root}/_repo/{product}，
/// 不重建则已下架的包持续被发布。result_root 与 GC 删除根同源。
async fn rebuild_product_repo_after_gc(state: &StateStore, cfg: &CrbsConfig, product: &str) {
    let (result_root, require_signed) = match state
        .load_merged_config_for_product_with_root(product, cfg)
        .await
    {
        Ok(merged) => {
            let require_signed = crbs_core::sign::SignConfig::signing_required(&merged);
            (merged.result_dir, require_signed)
        }
        Err(e) => {
            tracing::warn!(
                product = %product,
                error = %e,
                "Failed to load product config for repo rebuild; falling back to global result root"
            );
            (cfg.result_dir_or_derived(), false)
        }
    };
    let repo_publish = match state.resolve_any_product_by_name(product).await {
        Ok(resolved) => resolved.config.repo_publish.unwrap_or(true),
        Err(e) => {
            tracing::warn!(
                product = %product,
                error = %e,
                "Failed to resolve repo_publish; defaulting to true"
            );
            true
        }
    };
    match crbs_core::engine::repo_publish::assemble_product_repo(
        state,
        product,
        &result_root,
        repo_publish,
        require_signed,
    )
    .await
    {
        Ok(report) => tracing::info!(
            product = %product,
            arches = ?report.arches,
            linked = report.linked,
            unlinked = report.unlinked,
            "Regenerated product repo after gc --results"
        ),
        Err(e) => tracing::warn!(
            product = %product,
            error = %e,
            "Failed to regenerate product repo after gc; will converge on next build or rebuild-repo"
        ),
    }
}

#[cfg(test)]
mod confirm_gate_tests {
    use super::*;
    use crate::cli::OutputFormat;

    fn cli_args(all: bool, dry_run: bool, yes: bool) -> GcCliArgs {
        GcCliArgs {
            results: false,
            product: None,
            dry_run,
            orphan_mounts: false,

            cache: all,
            all,
            policy: false,
            yes,
            format: OutputFormat::Text,
        }
    }

    #[tokio::test]
    async fn gc_all_without_yes_bails_before_any_work() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();
        let cfg = crbs_core::config::CrbsConfig {
            crbs_root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let err = handle_gc(cli_args(true, false, false), &cfg, &store)
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("stdin is not a TTY"),
            "expected non-TTY refusal, got: {err:#}"
        );
    }

    #[tokio::test]
    async fn gc_all_with_yes_passes_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();
        let cfg = crbs_core::config::CrbsConfig {
            crbs_root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        handle_gc(cli_args(true, false, true), &cfg, &store)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn gc_all_dry_run_never_prompts() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();
        let cfg = crbs_core::config::CrbsConfig {
            crbs_root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        handle_gc(cli_args(true, true, false), &cfg, &store)
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod repo_regen_after_gc_tests {
    use super::*;
    use crate::cli::OutputFormat;

    #[tokio::test]
    async fn gc_results_rebuilds_affected_product_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();

        store
            .create_product(crbs_core::CreateProductInput {
                name: "fedora",
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: crbs_core::VISIBILITY_PUBLIC,
                config: &crbs_core::config::ProductConfig::default(),
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();

        let result_dir = tmp
            .path()
            .join("results")
            .join("fedora")
            .join("hello")
            .join("1.0-1");
        tokio::fs::create_dir_all(&result_dir).await.unwrap();
        let task_id = store
            .insert_task(crbs_core::TaskInsert {
                product: "fedora",
                pkg_name: "hello",
                user: "test",
                ..Default::default()
            })
            .await
            .unwrap();
        let build_id = store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "building",
                backend: "chroot",
                user: "test",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .complete_build(
                build_id,
                "succeeded",
                Some(result_dir.to_string_lossy().as_ref()),
            )
            .await
            .unwrap();

        let stale = tmp
            .path()
            .join("results")
            .join("_repo")
            .join("fedora")
            .join("x86_64")
            .join("Packages")
            .join("hello-1.0-1.x86_64.rpm");
        tokio::fs::create_dir_all(stale.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&stale, b"stale published copy")
            .await
            .unwrap();

        let cfg = crbs_core::config::CrbsConfig {
            crbs_root: tmp.path().to_path_buf(),
            result_max_count_per_pkg: Some(0),
            ..Default::default()
        };
        handle_gc(
            GcCliArgs {
                results: true,
                product: Some("fedora".into()),
                dry_run: false,
                orphan_mounts: false,
                cache: false,
                all: false,
                policy: false,
                yes: false,
                format: OutputFormat::Text,
            },
            &cfg,
            &store,
        )
        .await
        .unwrap();

        assert!(
            !result_dir.exists(),
            "gc must have removed the build result dir"
        );

        let createrepo_available = std::process::Command::new("createrepo_c")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if createrepo_available {
            assert!(
                !stale.exists(),
                "stale published copy must be unlinked by the post-gc repo rebuild"
            );
        } else {
            assert!(
                stale.exists(),
                "createrepo failure must keep the stale published copy in place"
            );
        }
    }
}
