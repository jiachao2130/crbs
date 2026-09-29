// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use crate::cli::{
    validate_container_params, validate_product, BuildBehaviorArgs, BuildInputArgs,
    BuildOutputArgs, BuildReproduceArgs, ContainerParams, GlobalArgs, OutputFormat,
};
use crate::cmd::build::BuildArgs;
use crbs_core::config::Config;
use crbs_core::engine::BuildEngine;
use crbs_core::error::CrbsError;
use crbs_core::privilege::CallerContext;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

/// 为本地构建（chain / batch）准备配置完成的 BuildEngine。配置来源 --offline / --remote / remote.default 由
/// crate::api::product::load_product_config 单点收敛为 Config 注入 engine，engine 不自行 parse 磁盘。
pub(crate) async fn prepare_local_engine(
    args: BuildArgs,
    inputs: &[PathBuf],
    ctx: &CallerContext,
    global: GlobalArgs,
) -> anyhow::Result<(Arc<BuildEngine>, usize)> {
    let BuildArgs {
        input,
        behavior,
        container,
        runtime,
        output,
        reproduce: reproduce_args,
    } = args;

    let BuildInputArgs {
        srpm,
        product,
        list,
        rebuild: _,
    } = input;
    let result_repo_effective = behavior.result_repo_effective();
    let BuildBehaviorArgs {
        chain,
        order_only: _,
        force: _,
        jobs,
        shared_layer,
        tmpfs,
        ccache,
        fail_fast: _,
        timeout,

        timeout_cancel: _,
        stage,
        define,
        with_features,
        without_features,
        nocheck,
        noclean,
        nodebuginfo,
        target,
        dist,
        repo,
        retry,
        priority,
        arch: requested_arches,
        assume_independent: _,

        skip_unsupported_arches: _,

        no_publish: _,
        no_consume: _,

        min_mem: _,
        min_ncpu: _,
        min_disk: _,
        result_repo: _,
        no_result_repo: _,
        label: label_args,
    } = behavior;
    let ContainerParams {
        backend,
        no_network,
        memory_max,
        cpu_quota,
    } = container;
    let BuildOutputArgs {
        format,
        follow_logs,
        ..
    } = output;
    let BuildReproduceArgs {
        reproduce,
        reproduce_keep_tmp_on_failure: _,
        no_reproduce,
        repro_from_srpm,
    } = reproduce_args;

    if let Some(task) = reproduce {
        anyhow::bail!(
            "prepare_local_engine should not be called for reproduce path; task={}",
            task
        );
    }

    let product = product.ok_or_else(|| CrbsError::ValidationFailed {
        message: "--product is required".into(),
    })?;

    validate_product(&product)?;
    let task_labels = super::parse_task_labels(&label_args)?;

    let config_target = crate::remote::resolve_config_target(
        runtime.remote.clone(),
        runtime.token.clone(),
        runtime.ca_cert.clone(),
    )
    .await?;
    let (config, product_config_toml) = crate::api::product::load_product_config_with_snapshot(
        &product,
        config_target.as_ref(),
        global.offline,
    )
    .await?;
    crate::api::product::log_config_source(&product, config_target.as_ref(), global.offline);

    let _effective_backend =
        validate_container_params(&backend, &memory_max, &cpu_quota, &config, true).await?;

    let effective_target = resolve_local_arch(&requested_arches, &target, &config)?;

    if srpm.is_empty() && list.is_none() {
        return Err(CrbsError::ValidationFailed {
            message: "No SRPM input: provide at least one SRPM path or use --list".into(),
        }
        .into());
    }

    if inputs.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: "No SRPM files found".into(),
        }
        .into());
    }

    precheck_local_arch_support(inputs, effective_target.as_deref()).await?;

    let replay_params = if repro_from_srpm {
        let p = super::probe_uniform_replay_params(inputs).await?;
        super::print_repro_from_srpm_hint(&p);
        Some(p)
    } else {
        None
    };

    let total = inputs.len();

    let cli_limits = crbs_core::ResourceLimits {
        memory_max,
        cpu_quota,
    };
    let network = if no_network { Some(false) } else { None };
    let mut engine_builder = BuildEngine::new_from_config(
        &product,
        backend.as_deref(),
        Some(cli_limits),
        network,
        config,
    )
    .await?;

    let jobs = jobs
        .or_else(|| {
            let cfg_jobs = engine_builder.max_concurrent_builds();
            if cfg_jobs > 0 {
                Some(cfg_jobs)
            } else {
                None
            }
        })
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        });
    engine_builder = engine_builder.with_max_concurrent_builds(jobs);

    info!(
        "Building {} SRPM(s) for product: {} (jobs={})",
        total, product, jobs
    );

    if follow_logs && total > 1 && format == OutputFormat::Text {
        eprintln!(
            "Warning: --follow-logs only supports a single SRPM; disabling for {} packages. \
             Use 'crbs logs <id> -f' to follow individual logs.",
            total
        );
    }
    let terminal_tx = if follow_logs && format == OutputFormat::Text && total == 1 {
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<String>(crbs_core::engine::TERMINAL_LOG_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            while let Some(line) = rx.recv().await {
                print!("{}", line);
            }
        });
        Some(tx)
    } else {
        None
    };

    let config_nocheck = engine_builder.config().nocheck;
    let config_noclean = engine_builder.config().noclean;
    let config_nodebuginfo = engine_builder.config().nodebuginfo;

    let opts = crbs_core::build_options::BuildOptions {
        shared_layer: shared_layer.then_some(true),
        tmpfs: tmpfs.then_some(true),
        ccache: ccache.then_some(true),
        timeout,
        nocheck: Some(nocheck || config_nocheck),
        noclean: Some(noclean || config_noclean),
        nodebuginfo: Some(nodebuginfo || config_nodebuginfo),
        target: effective_target,
        dist,
        define,
        with_features,
        without_features,
        retry,
        no_reproduce: no_reproduce.then_some(true),
        repro_from_srpm,
        replay_build_host: replay_params.as_ref().and_then(|(h, _)| h.clone()),
        replay_build_time: replay_params.as_ref().and_then(|(_, t)| *t),
        stage,

        priority: Some(priority),
        ..Default::default()
    };
    let mut engine = crbs_core::build_options::apply_options_to_engine(engine_builder, &opts)?;

    engine = engine
        .with_terminal_tx(terminal_tx)
        .with_follow_logs(follow_logs)
        .with_caller(ctx.caller.clone())
        .with_product_config_toml(product_config_toml)
        .with_task_labels(task_labels);
    if chain && result_repo_effective {
        let repo_dir = repo
            .as_deref()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| engine.config().local_repo_path());
        engine = engine.with_local_repo(repo_dir);
    }
    let engine = Arc::new(engine);

    Ok((engine, jobs))
}

fn host_arch() -> &'static str {
    std::env::consts::ARCH
}

/// 为本地构建解析出**单一** target arch；multi-arch fan-out 只在 --remote 走 hub。规则：--arches 空 → 沿用 --target；
/// 非空含宿主 arch → 取宿主，其余 warn 需 --remote；非空不含宿主或与 --target 冲突 → bail。
fn resolve_local_arch(
    requested: &[String],
    explicit_target: &Option<String>,
    config: &Config,
) -> anyhow::Result<Option<String>> {
    let host = host_arch();

    if requested.is_empty() {
        if config.arches.len() > 1 {
            info!(
                product = %config.product,
                declared = ?config.arches,
                host = %host,
                "product declares multiple arches; local build only produces the host arch. \
                 Use --remote for multi-arch fan-out, or --target ARCH to select explicitly."
            );
        }
        return Ok(explicit_target.clone());
    }

    if let Some(t) = explicit_target {
        if !requested.iter().any(|a| a == t) {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "--target {:?} conflicts with --arches {:?}; specify only one",
                    t, requested
                ),
            }
            .into());
        }
    }

    if requested.iter().any(|a| a == host) {
        if requested.len() > 1 {
            let dropped: Vec<&String> = requested.iter().filter(|a| *a != host).collect();
            tracing::warn!(
                host = %host,
                dropped = ?dropped,
                "local build only produces the host arch; the other requested arches will \
                 need --remote for fan-out."
            );
        }
        Ok(Some(host.to_string()))
    } else {
        Err(CrbsError::ValidationFailed {
            message: format!(
                "local build cannot target {:?}; host arch is {}. \
                 Use --remote for cross-arch fan-out, or pass --arches {} to build for the host.",
                requested, host, host
            ),
        }
        .into())
    }
}

/// 本地构建的 spec 架构约束预检：不兼容在构建开工前拒绝（ValidationFailed → exit 4），比 rpmbuild 跑起来才败更快、报错更准。
/// 探测失败保守放行——预检是优化不是安全裁决。
async fn precheck_local_arch_support(
    inputs: &[PathBuf],
    effective_target: Option<&str>,
) -> anyhow::Result<()> {
    let host = host_arch();
    let target = effective_target.unwrap_or(host);

    if target != host {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "--target {target} is not buildable on this host ({host}); \
                 local builds run on the host arch — cross-arch builds use --arches"
            ),
        }
        .into());
    }
    let probed =
        crbs_core::engine::depsolve::parse_arch_and_constraints_from_srpms(inputs, None).await;
    for (srpm, probe) in inputs.iter().zip(probed) {
        let (srpm_arch, constraints) = match probe {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(
                    srpm = %srpm.display(),
                    error = %e,
                    "arch constraint probe failed; precheck passes conservatively"
                );
                continue;
            }
        };

        if srpm_arch.is_empty()
            || (constraints.exclusive.is_empty() && constraints.exclude.is_empty())
        {
            continue;
        }

        let (check_arch, what) = if srpm_arch == "noarch" {
            (host, format!("noarch build on host {host}"))
        } else {
            (target, format!("target arch {target}"))
        };
        if let Some(reason) = constraints.incompatible_for(&srpm_arch, check_arch) {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "{}: cannot build {what} ({reason}); fix the spec or build on a different host",
                    srpm.display()
                ),
            }
            .into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crbs_core::test_support::SrpmFixture;

    fn cfg_with_arches(arches: &[&str]) -> Config {
        Config {
            product: "test-product".to_string(),
            arches: arches.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn resolve(
        requested: &[&str],
        explicit_target: Option<&str>,
    ) -> anyhow::Result<Option<String>> {
        let requested: Vec<String> = requested.iter().map(|s| s.to_string()).collect();
        let target = explicit_target.map(|s| s.to_string());
        let cfg = cfg_with_arches(&[]);
        resolve_local_arch(&requested, &target, &cfg)
    }

    #[test]
    fn empty_requested_returns_explicit_target() {
        let out = resolve(&[], Some("x86_64_v3")).unwrap();
        assert_eq!(out, Some("x86_64_v3".to_string()));
    }

    #[test]
    fn empty_requested_and_no_target_returns_none() {
        let out = resolve(&[], None).unwrap();
        assert_eq!(out, None);
    }

    #[test]
    fn single_host_arch_promotes_to_target() {
        let host = host_arch();
        let out = resolve(&[host], None).unwrap();
        assert_eq!(out, Some(host.to_string()));
    }

    #[test]
    fn multi_arches_with_host_uses_host_and_warns() {
        let host = host_arch();
        let other = if host == "x86_64" {
            "aarch64"
        } else {
            "x86_64"
        };
        let out = resolve(&[host, other], None).unwrap();
        assert_eq!(out, Some(host.to_string()));
    }

    #[test]
    fn cross_arch_without_host_bails() {
        let host = host_arch();
        let other = if host == "x86_64" {
            "aarch64"
        } else {
            "x86_64"
        };
        let err = resolve(&[other], None).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("cannot target"), "err was: {}", msg);
        assert!(msg.contains("--remote"), "err was: {}", msg);
    }

    #[test]
    fn explicit_target_disagrees_with_requested_bails() {
        let host = host_arch();
        let err = resolve(&[host], Some("some_other_target")).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("conflicts"), "err was: {}", msg);
    }

    fn other_arch() -> &'static str {
        if host_arch() == "x86_64" {
            "aarch64"
        } else {
            "x86_64"
        }
    }

    fn hello_fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../crbs-server/tests/fixtures/hello-1.0-1.src.rpm")
    }

    #[tokio::test]
    async fn precheck_passes_constrained_srpm_on_matching_target() {
        if !crbs_core::test_support::rpm_spawnable()
            || !crbs_core::test_support::rpmbuild_spawnable()
        {
            eprintln!("skipping: rpm/rpmbuild not available");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let srpm = crbs_core::test_support::build_srpm(SrpmFixture {
            topdir: tmp.path(),
            name: "pkgmatch",
            version: "1.0",
            release: "1",
            buildarch: None,
            build_requires: &[],
            exclusive: &[host_arch()],
            exclude: &[],
        });

        precheck_local_arch_support(std::slice::from_ref(&srpm), Some(host_arch()))
            .await
            .unwrap_or_else(|e| panic!("matching target must pass: {e}"));
        precheck_local_arch_support(&[srpm], None)
            .await
            .unwrap_or_else(|e| panic!("default target (= host) must pass: {e}"));

        let srpm_excl = crbs_core::test_support::build_srpm(SrpmFixture {
            topdir: tmp.path(),
            name: "pkgexclpass",
            version: "1.0",
            release: "1",
            buildarch: None,
            build_requires: &[],
            exclusive: &[],
            exclude: &[other_arch()],
        });
        precheck_local_arch_support(std::slice::from_ref(&srpm_excl), Some(host_arch()))
            .await
            .unwrap_or_else(|e| panic!("unrelated ExcludeArch must pass: {e}"));
    }

    #[tokio::test]
    async fn precheck_rejects_constrained_srpm_on_mismatched_target() {
        if !crbs_core::test_support::rpm_spawnable()
            || !crbs_core::test_support::rpmbuild_spawnable()
        {
            eprintln!("skipping: rpm/rpmbuild not available");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let srpm = crbs_core::test_support::build_srpm(SrpmFixture {
            topdir: tmp.path(),
            name: "pkgmismatch",
            version: "1.0",
            release: "1",
            buildarch: None,
            build_requires: &[],
            exclusive: &[other_arch()],
            exclude: &[],
        });

        let err = precheck_local_arch_support(&[srpm], Some(host_arch()))
            .await
            .expect_err("mismatched target must be rejected");
        let crbs_err = err.downcast::<CrbsError>().expect("CrbsError");
        let CrbsError::ValidationFailed { message } = &crbs_err else {
            panic!("expected ValidationFailed, got: {crbs_err:?}");
        };
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(&crbs_err),
            crbs_core::exit_code::USAGE,
            "ValidationFailed must map to exit 4"
        );
        assert!(message.contains("pkgmismatch"), "must name SRPM: {message}");
        assert!(
            message.contains("ExclusiveArch"),
            "must name constraint: {message}"
        );
    }

    #[tokio::test]
    async fn precheck_rejects_noarch_srpm_when_host_excluded() {
        if !crbs_core::test_support::rpm_spawnable()
            || !crbs_core::test_support::rpmbuild_spawnable()
        {
            eprintln!("skipping: rpm/rpmbuild not available");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let srpm = crbs_core::test_support::build_srpm(SrpmFixture {
            topdir: tmp.path(),
            name: "pkgnoexcl",
            version: "1.0",
            release: "1",
            buildarch: Some("noarch"),
            build_requires: &[],
            exclusive: &[],
            exclude: &[host_arch()],
        });

        let err = precheck_local_arch_support(&[srpm], None)
            .await
            .expect_err("excluded noarch build host must be rejected");
        let crbs_err = err.downcast::<CrbsError>().expect("CrbsError");
        let CrbsError::ValidationFailed { message } = &crbs_err else {
            panic!("expected ValidationFailed, got: {crbs_err:?}");
        };
        assert!(message.contains("noarch build on host"), "got: {message}");
    }

    #[tokio::test]
    async fn precheck_rejects_target_not_equal_host() {
        if !crbs_core::test_support::rpm_spawnable() {
            eprintln!("skipping: rpm not available");
            return;
        }
        let fixture = hello_fixture();
        let err = precheck_local_arch_support(std::slice::from_ref(&fixture), Some(other_arch()))
            .await
            .expect_err("target other than host must be rejected");
        let crbs_err = err.downcast::<CrbsError>().expect("CrbsError");
        let CrbsError::ValidationFailed { message } = &crbs_err else {
            panic!("expected ValidationFailed, got: {crbs_err:?}");
        };
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(&crbs_err),
            crbs_core::exit_code::USAGE,
            "ValidationFailed must map to exit 4"
        );
        assert!(
            message.contains(other_arch()) && message.contains(host_arch()),
            "must name target and host: {message}"
        );
        assert!(
            message.contains("--arches"),
            "must hint cross-arch route: {message}"
        );
    }

    #[tokio::test]
    async fn precheck_rejects_micro_variant_target() {
        if !crbs_core::test_support::rpm_spawnable()
            || !crbs_core::test_support::rpmbuild_spawnable()
        {
            eprintln!("skipping: rpm/rpmbuild not available");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let srpm = crbs_core::test_support::build_srpm(SrpmFixture {
            topdir: tmp.path(),
            name: "pkgmicro",
            version: "1.0",
            release: "1",
            buildarch: None,
            build_requires: &[],
            exclusive: &[host_arch()],
            exclude: &[],
        });
        let micro = format!("{}_v3", host_arch());
        let err = precheck_local_arch_support(std::slice::from_ref(&srpm), Some(&micro))
            .await
            .expect_err("micro-variant target must be rejected under exact matching");
        let crbs_err = err.downcast::<CrbsError>().expect("CrbsError");
        let CrbsError::ValidationFailed { message } = &crbs_err else {
            panic!("expected ValidationFailed, got: {crbs_err:?}");
        };
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(&crbs_err),
            crbs_core::exit_code::USAGE,
            "ValidationFailed must map to exit 4"
        );
        assert!(
            message.contains(&micro) && message.contains(host_arch()),
            "must name variant target and host: {message}"
        );
    }

    #[tokio::test]
    async fn precheck_passes_unconstrained_fixture_on_host_target() {
        if !crbs_core::test_support::rpm_spawnable() {
            eprintln!("skipping: rpm not available");
            return;
        }
        let fixture = hello_fixture();
        assert!(
            fixture.is_file(),
            "fixture must exist: {}",
            fixture.display()
        );
        for target in [Some(host_arch()), None] {
            precheck_local_arch_support(std::slice::from_ref(&fixture), target)
                .await
                .unwrap_or_else(|e| panic!("unconstrained SRPM must pass: {e}"));
        }
    }

    #[tokio::test]
    async fn precheck_passes_conservatively_when_probe_fails() {
        precheck_local_arch_support(
            &[PathBuf::from("/nonexistent/pkg-1.0-1.src.rpm")],
            Some(host_arch()),
        )
        .await
        .unwrap_or_else(|e| panic!("probe failure must pass conservatively: {e}"));
    }
}
