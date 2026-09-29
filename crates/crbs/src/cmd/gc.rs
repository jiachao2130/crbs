// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! GC 命令入口：CLI 参数解析 + 结果输出。

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

    // --all 不查 DB 引用删全部 package cache（gc 族唯一"不看引用就删"）：非交互须显式 --yes（防脚本误触发），dry-run 预览不拦。
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
        // CLI 世界无 server.toml 的 artifact_dir 覆盖：随 cfg 的 crbs_root 派生。
        artifact_dir: None,
    };

    let summary = run_gc(gc_args, cfg, state).await?;

    // 摘要先于 rebuild 循环输出：rebuild 是分钟级同步 await，后打印会被误判 GC 卡死。
    args.format.print(&output::GcOutput(&summary))?;

    // 实删后对账重建受影响产品的发布 repo：被删构建若曾发布，硬链接副本仍留在
    // `{result_root}/_repo/{product}`，不重建则已下架的包持续被发布。
    // affected_products 仅实删时非空（dry-run 为空）；失败仅 warn（收敛性对账，不打红）。
    if let Some(ref results) = summary.results {
        for product in &results.affected_products {
            rebuild_product_repo_after_gc(state, cfg, product).await;
        }
    }

    Ok(())
}

/// `gc --results` 后对单个受影响产品的 repo 对账重建。result_root 与 GC
/// 删除根同源：同一 `load_merged_config_for_product_with_root`，解析失败
/// 回退 `result_dir_or_derived`；repo_publish 缺省/解析失败按发布（防误摘空）。
/// 签名策略从同一份合并配置解析：生效时候选只收已签名构建（解析失败按
/// 不要求，避免瞬时读错把未参与签名的部署 repo 摘空）。
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
            // --all 在 core gc 侧要求与 --cache 同用，gate 测试按真实组合传参。
            cache: all,
            all,
            policy: false,
            yes,
            format: OutputFormat::Text,
        }
    }

    /// `gc --all`（实删）在非 TTY 且无 --yes 时必须在任何 GC 动作前拒绝。
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

    /// `--yes` 放行（空库上 gc 为无操作，验证 gate 之后正常执行）。
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

    /// 接线回归：`gc --results` 实删后必须触发受影响产品的 repo 对账重建
    ///（信号：`{result_root}/_repo/{product}/{arch}/Packages/` 预置的已发布
    /// 陈旧副本被对账摘除）。环境二分各钉一半：有 createrepo_c → 两阶段 swap
    /// 成功摘除；无 → createrepo 失败陈旧副本保位（失败态零 404 窗口），
    /// regen 失败仅 warn、handle_gc 仍须 Ok。候选走 `result_max_count_per_pkg=0`
    /// 策略路径（时间无关）；产品行须先建（reconcile 写盘前有 product_row_exists 复查，行缺失整轮放弃）。
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

        // GC 候选：building 挂 pending 任务，完成后翻 succeeded 落 result_dir（completed_at 随终态写入，满足候选 NOT NULL）。
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

        // result_max_count_per_pkg=0：单构建即超额（rn=1 > 0），时间无关。
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
        // 接线断言：有 createrepo_c → 对账摘除；无 → createrepo 失败保位（零 404 窗口）。
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
