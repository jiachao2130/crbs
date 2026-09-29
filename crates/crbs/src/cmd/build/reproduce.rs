// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! reproduce 子命令：复现请求组装与结果判定。

use std::path::{Path, PathBuf};

use crate::cli::OutputFormat;
use crbs_core::engine::retry::RetryPolicy;
use crbs_core::error::CrbsError;
use crbs_core::privilege::CallerContext;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::output::{print_json_reproduce_task, JsonReproduceOutput, JsonReproduceVerification};
use super::ReproduceArgs;

pub(crate) async fn handle_reproduce(
    args: ReproduceArgs,
    ctx: CallerContext,
) -> anyhow::Result<()> {
    // json 错误信封由 dispatch::run 的 json_guard 统一收口（command="build"），
    // 此处不逐层包装 maybe_json_error_exit。
    Ok(handle_reproduce_inner(args, ctx).await?)
}

async fn handle_reproduce_inner(args: ReproduceArgs, ctx: CallerContext) -> crbs_core::Result<()> {
    let ReproduceArgs {
        product,
        task,
        srpm_overrides,
        container,
        keep_tmp_on_failure,
        format,
        remote,
        token,
        ca_cert,
        offline,
        cancel_token,
    } = args;

    if srpm_overrides.len() > 1 {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "--reproduce accepts at most one SRPM override, got {}",
                srpm_overrides.len()
            ),
        });
    }

    let crbs_config = crbs_core::config::CrbsConfig::load_async().await?;
    // marker 护栏，见 StateStore::open_for_engine。
    let state = crbs_core::StateStore::open_for_engine(&crbs_config.crbs_root).await?;
    let user_filter = crate::cmd::visible_user_filter(&ctx);
    // --reproduce 的 ID 是 task 域语义（与远程 `POST /api/v1/tasks/{id}/reproduce`
    // 同口径）；build/task 两表序列独立、同数字两义，不得按 build 域短 ID 解析。
    let task_id = state.resolve_task_id(&task, user_filter).await?;
    let task = state
        .get_task(task_id)
        .await?
        .ok_or_else(|| CrbsError::ValidationFailed {
            message: format!("task {task_id} not found. Run 'crbs status' to list tasks."),
        })?;

    // resolve_task_id 的 user_filter 与本谓词对 user='' 旧记录同放行（纵深防御位）。
    crate::cmd::ensure_record_owner("task", task_id, &task.user, &ctx)?;

    // 聚合 task 全部子构建：多包/多 arch 任务逐个子构建复现。
    let children = state.get_builds_by_task_id(task_id).await?;
    if children.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: format!("task {} has no child builds; cannot reproduce", task_id),
        });
    }
    for child in &children {
        // 判定须含 pending/assigned，否则误报下一分支 "only succeeded builds can be reproduced"。
        if matches!(child.phase.as_str(), "pending" | "assigned" | "building") {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "task {} is still in progress (child build {})",
                    task_id, child.id
                ),
            });
        }
        if child.phase != "succeeded" {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "task {} child build {} has status '{}' \
                     (only succeeded builds can be reproduced)",
                    task_id, child.id, child.phase
                ),
            });
        }
    }

    let product = match product {
        Some(p) => {
            if task.product != p {
                return Err(CrbsError::ValidationFailed {
                    message: format!(
                        "task {} belongs to product '{}', not '{}'",
                        task_id, task.product, p
                    ),
                });
            }
            p
        }
        None => task.product.clone(),
    };

    crate::cli::validate_product(product.as_str())?;
    // 产品名来自本地 task 记录，但配置仍走 hub `/resolved`，避免本地过期磁盘
    // 配置静默漂移；配置链错误经 preserve_config_error 保 CrbsError 变体。
    let config_target = crate::remote::resolve_config_target(remote, token, ca_cert)
        .await
        .map_err(|e| preserve_config_error("resolve config target", e))?;
    let (config, product_config_toml) = crate::api::product::load_product_config_with_snapshot(
        &product,
        config_target.as_ref(),
        offline,
    )
    .await
    .map_err(|e| preserve_config_error("load product config", e))?;
    crate::api::product::log_config_source(&product, config_target.as_ref(), offline);

    // 单个 override 无法映射到多个子构建（各子构建来源 SRPM 各自独立）。
    if !srpm_overrides.is_empty() && children.len() > 1 {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "SRPM override cannot be used with a multi-build task \
                 (task {} has {} child builds)",
                task_id,
                children.len()
            ),
        });
    }

    // 宏级选项重放：task 级 request_json 对全部子构建一致，只读一次。
    let source_opts = load_source_build_options(&state, Some(task_id), task_id).await?;

    let shared = ReproduceTaskCtx {
        product,
        config,
        product_config_toml,
        container,
        source_opts,
        caller: ctx.caller.clone(),
        cancel_token: &cancel_token,
        format,
        keep_tmp_on_failure,
        task_id,
    };
    // task 域 --format json 契约：整份任务恰好输出一个 JSON 文档
    // `{"task_id": ..., "builds": [...]}`（jq 单文档消费者）。
    let mut json_builds: Vec<JsonReproduceOutput> = Vec::new();
    for child in &children {
        match reproduce_one_build(
            &shared,
            child,
            srpm_overrides.first().map(std::path::PathBuf::as_path),
        )
        .await
        {
            Ok(Some(output)) => json_builds.push(output),
            Ok(None) => {}
            Err(e) => {
                // 中途失败：已完成子构建照常进唯一 JSON 文档，错误走 stderr，不打第二个文档。
                if shared.format == OutputFormat::Json {
                    print_json_reproduce_task(task_id, &json_builds)?;
                    eprintln!("Error: {e:#}");
                    let exit = crbs_core::exit_code::crbs_error_exit_code(&e);
                    return Err(CrbsError::SilentExit { code: exit });
                }
                return Err(e);
            }
        }
    }
    if shared.format == OutputFormat::Json {
        print_json_reproduce_task(task_id, &json_builds)?;
    }
    Ok(())
}

/// task 域聚合复现的公共上下文（task 级只构造一次，逐子构建复用）。
struct ReproduceTaskCtx<'a> {
    product: String,
    config: crbs_core::config::Config,
    product_config_toml: Option<String>,
    container: crate::cli::ContainerParams,
    source_opts: Option<crbs_core::BuildOptions>,
    caller: crbs_core::privilege::CallerInfo,
    cancel_token: &'a CancellationToken,
    format: OutputFormat,
    keep_tmp_on_failure: bool,
    task_id: i64,
}

/// 复现单个子构建：环境快照由各自 result_dir 的 build_packages.json 决定，
/// SRPM 从各自 result_dir / 任务 source 定位。
///
/// json 模式成功返回 `Some`（聚合方装进唯一输出文档），text 自打印返回
/// `None`；失败直接上抛，envelope 处理在聚合方。
async fn reproduce_one_build(
    shared: &ReproduceTaskCtx<'_>,
    child: &crbs_core::BuildRecord,
    srpm_override: Option<&Path>,
) -> crbs_core::Result<Option<JsonReproduceOutput>> {
    let result_dir = child.result_dir.as_ref().map(PathBuf::from);

    let srpm = resolve_reproduce_srpm(srpm_override, result_dir.as_deref(), child.id).await?;

    // build_packages.json 是 canonical 数据源；DB build_packages 表只是派生索引。
    let result_dir = result_dir.ok_or_else(|| CrbsError::ValidationFailed {
        message: format!(
            "Build {} has no result_dir and cannot be reproduced",
            child.id
        ),
    })?;

    // 时间锚：从源构建产物头钉 BUILDTIME/BUILDHOST（hub reproduce 同语义）。
    // 不钉 = 墙钟烧进 BUILDTIME 头与 payload mtime，同源两次回放字节必不同。
    // 早退发生在任何临时资源创建前，`?` 直传无需 teardown。
    let anchor =
        crbs_core::engine::reproduce::resolve_replay_anchor(&result_dir, Some(shared.cancel_token))
            .await?;
    if shared.format != OutputFormat::Json {
        println!(
            "REPRODUCE: pinned replay anchor from build {} artifacts: \
             BUILDTIME={} BUILDHOST={}",
            child.id,
            anchor
                .build_time
                .map(|t| t.to_string())
                .unwrap_or_else(|| "<none>".into()),
            anchor.build_host.as_deref().unwrap_or("<none>")
        );
    }

    // cancel_token 贯穿包恢复（url 兜底下载为最长阻塞段），与下方 RetryPolicy
    // 包裹的构建共用同一取消策略。
    let env = crbs_core::engine::reproduce::prepare_reproduce_env(
        &result_dir,
        &shared.config,
        Some(shared.cancel_token),
    )
    .await?;
    let restored_count = env.restored_count;
    let original_packages = env.original_packages.clone();

    if shared.format != OutputFormat::Json {
        match env.mode {
            crbs_core::engine::reproduce::ReplayRepoMode::Snapshot => {
                println!(
                    "REPRODUCE: restored {} packages to temporary repo: {}",
                    restored_count,
                    env.temp_repo.display()
                );
            }
            crbs_core::engine::reproduce::ReplayRepoMode::BaseOnly => {
                println!(
                    "REPRODUCE: record set has no sha256 entries (base-only replay); \
                     resolving from the normal repo domain, no snapshot repo"
                );
            }
        }
    }

    info!(
        task = %shared.task_id,
        build = %child.id,
        mode = ?env.mode,
        "Reproducing build"
    );

    // backend / 资源限制不读复现请求的 CLI 旗标：走与正常构建相同的解析链
    //（create_backend ← config.backend 全局→产品→默认），容器 /proc 挂载语义
    // 与源构建同态；network 仍随 --no-network。
    let network = if shared.container.no_network {
        Some(false)
    } else {
        None
    };

    let engine = match crbs_core::engine::BuildEngine::new_from_config(
        &shared.product,
        None,
        None,
        network,
        shared.config.clone(),
    )
    .await
    {
        // 密闭链按回放仓库模式分派，单点在 crbs-core apply_reproduce_engine。
        Ok(engine) => crbs_core::engine::reproduce::apply_reproduce_engine(engine, &env)
            .with_caller(shared.caller.clone())
            .with_product_config_toml(shared.product_config_toml.clone()),
        Err(e) => {
            // 早退前显式 teardown：TempDir 的同步 Drop 不能在 async 线程随 return 发生。
            env.teardown().await;
            return Err(e);
        }
    };

    // 宏级选项重放：--define/--with/--without 不随环境快照流转，须从来源 task
    // 的 request_json 恢复，否则 -D 构建以默认宏复现却报告成功；旧构建回退并 warn。
    let engine = match &shared.source_opts {
        Some(opts) => {
            match crbs_core::engine::reproduce::apply_source_build_options(engine, opts) {
                Ok(engine) => engine,
                Err(e) => {
                    // 同上：早退前显式 teardown。
                    env.teardown().await;
                    return Err(e);
                }
            }
        }
        None => engine,
    };

    // 锚注入（hub reproduce_fan_out 同款 Option 语义）：BUILDTIME 走
    // SOURCE_DATE_EPOCH、BUILDHOST 走 _buildhost 宏钳制；缺失侧不注。
    let engine = match anchor.build_time {
        Some(t) => engine.with_replay_build_time(t),
        None => engine,
    };
    let engine = match anchor.build_host {
        Some(host) => engine.with_replay_build_host(host),
        None => engine,
    };

    // noarch target 注入（hub reproduce_fan_out 同款语义）：noarch SRPM 须以
    // target=noarch 重放——不注入则平台宏（OPTFLAGS）不加载、lead arch 随宿主，
    // 与源构建系统性 diff；解析失败硬拒（注入不可判定 = 重放不可比）。CLI
    // reproduce 无用户 target 可言，条件较 hub 简化。
    let engine = match crbs_core::engine::depsolve::parse_arch_from_srpms(
        std::slice::from_ref(&srpm),
        Some(shared.cancel_token),
    )
    .await
    .pop()
    {
        Some(Ok(arch)) if arch == "noarch" => engine.with_target_arch(Some(arch)),
        Some(Ok(_)) => engine,
        Some(Err(e)) => {
            // 同上：早退前显式 teardown。
            env.teardown().await;
            return Err(e);
        }
        None => engine,
    };

    let pkg_name = crbs_core::util::srpm_display_name(&srpm).to_string();

    if shared.format != OutputFormat::Json {
        println!("REPRODUCE: building {}...", pkg_name);
    }

    let policy = RetryPolicy::from_config(engine.config());
    let cancel_token = shared.cancel_token;
    let result = policy
        .run(&pkg_name, cancel_token, || {
            let engine = &engine;
            let srpm = &srpm;
            let task_cancel = cancel_token.clone();
            async move {
                let child_token = task_cancel.child_token();
                engine.build(srpm, &child_token, None).await
            }
        })
        .await
        .map(|(mut outputs, retries)| {
            outputs.retries = retries;
            outputs
        });

    // 保留/清理动作不被 JSON 模式跳过（否则失败时临时目录全部泄漏），仅人类可读提示按格式门控。
    //
    // 清理分支（含成功路径）走显式 teardown：TempDir Drop 是同步 remove_dir_all
    //（快照仓可达 GB 级），不能在 async 线程随返回直接 Drop，teardown 内部走
    // spawn_blocking；保留分支经 preserve_temp_dirs 刻意泄漏 guard（目录留给
    // 人工排查），Drop 因 guard 取空而短路。
    let keep_tmp = result.is_err() && shared.keep_tmp_on_failure;
    if result.is_err() {
        if shared.keep_tmp_on_failure {
            if shared.format != OutputFormat::Json {
                // BaseOnly 无快照仓可留（guard 本就 None），仅 Snapshot 提示路径。
                if env.mode == crbs_core::engine::reproduce::ReplayRepoMode::Snapshot {
                    println!(
                        "REPRODUCE: temp repo preserved for debugging: {}",
                        env.temp_repo.display()
                    );
                }
            }
        } else if shared.format != OutputFormat::Json {
            println!(
                "REPRODUCE: cleaning up temp dirs (use --reproduce-keep-tmp-on-failure to keep them)"
            );
        }
    }
    if keep_tmp {
        env.preserve_temp_dirs();
    } else {
        env.teardown().await;
    }

    match result {
        Err(e) => {
            // 原错误直接上抛：包 ValidationFailed 会把构建失败/超时退出码
            // 2/3 改写成 4（用法错误），CI 按退出码契约会误判。
            Err(e)
        }
        Ok(outputs) => {
            // 环境一致性校验（非字节级）：reproduce 只保证"锁定依赖快照 +
            // 时间锚下成功重建"，机制与口径见 build_verification；不做输出
            // RPM 字节级断言，比对是 `crbs verify` 的职责。
            let verification =
                build_verification(original_packages.len(), restored_count, outputs.rpms.len());
            if shared.format == OutputFormat::Json {
                return Ok(Some(JsonReproduceOutput {
                    command: "build",
                    mode: "reproduce",
                    reproduce_build_id: outputs.build_id,
                    outcome: "succeeded",
                    result_dir: outputs.result_dir.display().to_string(),
                    verification,
                }));
            }
            println!("REPRODUCE: ✅ Build succeeded in reproduced environment");
            println!(
                "  environment packages restored from cache: {}",
                verification.restored_packages
            );
            println!("  produced RPMs: {}", verification.produced_rpms);
            println!(
                "  (env restored via SHA256 content-addressed cache; \
                 byte-level output comparison is not asserted)"
            );
            println!("REPRODUCE: result_dir: {}", outputs.result_dir.display());
            Ok(None)
        }
    }
}

/// 定位单个子构建的来源 SRPM：显式 override > `{result_dir}/SRPMS/` >
/// result_dir 祖父目录（rpmbuild -bb 场景 SRPMS 为空时的回退）。定位不到即报错。
async fn resolve_reproduce_srpm(
    srpm_override: Option<&Path>,
    result_dir: Option<&Path>,
    build_id: i64,
) -> crbs_core::Result<PathBuf> {
    if let Some(path) = srpm_override {
        if !tokio::fs::try_exists(path).await? {
            return Err(CrbsError::ValidationFailed {
                message: format!("SRPM not found: {}", path.display()),
            });
        }
        return tokio::fs::canonicalize(path).await.map_err(|e| {
            CrbsError::from_io_context(format!("canonicalize {}", path.display()), e)
        });
    }

    let Some(result_dir) = result_dir else {
        return Err(CrbsError::ValidationFailed {
            message: format!("Build {build_id} has no result_dir and no positional SRPM provided"),
        });
    };

    let srpms_dir = result_dir.join("SRPMS");
    if !tokio::fs::try_exists(&srpms_dir).await? {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "No SRPM directory in result_dir ({}/SRPMS/) and no positional SRPM provided",
                result_dir.display()
            ),
        });
    }
    let mut entries = tokio::fs::read_dir(&srpms_dir).await?;
    let mut found = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let p = entry.path();
        if p.extension().map(|e| e == "rpm").unwrap_or(false) {
            found.push(p);
        }
    }
    match found.len() {
        1 => Ok(found
            .pop()
            .ok_or_else(|| CrbsError::Internal("internal error: SRPM count mismatch".into()))?),
        n if n > 1 => Err(CrbsError::ValidationFailed {
            message: format!(
                "Multiple SRPMs in {}/SRPMS/, please specify which one to use",
                result_dir.display()
            ),
        }),
        _ => {
            // SRPMS 空（rpmbuild -bb 常见）：回退 result_dir 祖父目录找原始 SRPM。
            let parent = result_dir.parent();
            let grandparent = parent.and_then(|p| p.parent());
            let Some(gp) = grandparent else {
                return Err(CrbsError::ValidationFailed {
                    message: format!(
                        "No .src.rpm in {}/SRPMS/ and no positional SRPM provided",
                        result_dir.display()
                    ),
                });
            };
            let mut entries = tokio::fs::read_dir(gp).await?;
            let mut src_rpms = Vec::new();
            while let Some(entry) = entries.next_entry().await? {
                let p = entry.path();
                if p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.ends_with(".src.rpm"))
                    .unwrap_or(false)
                {
                    src_rpms.push(p);
                }
            }
            match src_rpms.len() {
                0 => Err(CrbsError::ValidationFailed {
                    message: format!(
                        "No .src.rpm found in {} or its parent directories; please provide SRPM path",
                        result_dir.display()
                    ),
                }),
                1 => src_rpms.into_iter().next().ok_or_else(|| {
                    CrbsError::Internal("internal error: SRPM count mismatch".into())
                }),
                _ => Err(CrbsError::ValidationFailed {
                    message: format!(
                        "Multiple .src.rpm found in {}, please specify which one to use",
                        gp.display()
                    ),
                }),
            }
        }
    }
}

/// 读取来源 task 档案的构建选项（task 级 `request_json`）供宏级重放。
/// 无档案 / 无 `request_json`（旧构建）/ JSON 损坏均 `None` + warn（复现回退
/// 现状不阻断），DB 错误按 infra 传播；`task_id` 是 **task 域** id（非 build 域），
/// 仅用于 warn 日志定位。
async fn load_source_build_options(
    state: &crbs_core::StateStore,
    source_task_row: Option<i64>,
    task_id: i64,
) -> crbs_core::Result<Option<crbs_core::BuildOptions>> {
    let Some(task_row) = source_task_row else {
        warn!(
            task_id = %task_id,
            "Source build has no task record; stored build options unavailable, \
             --define/--with/--without not replayed"
        );
        return Ok(None);
    };
    let request_json = state
        .get_task_rebuild_info(task_row)
        .await?
        .and_then(|info| info.request_json);
    match request_json {
        Some(json) => match serde_json::from_str(&json) {
            Ok(opts) => Ok(Some(opts)),
            Err(e) => {
                warn!(
                    task_id = %task_id,
                    error = %e,
                    "Failed to parse source build options; --define/--with/--without not replayed"
                );
                Ok(None)
            }
        },
        None => {
            warn!(
                task_id = %task_id,
                "Source build has no stored build options (pre-options-capture task); \
                 --define/--with/--without not replayed"
            );
            Ok(None)
        }
    }
}

/// 构造 reproduce 的环境一致性校验摘要。不做字节级复现：只保证"锁定依赖快照下
/// 成功重建"（SHA256 内容寻址恢复 + builddep fail-fast）；仅汇总可诚实报告的
/// 计数，无字节相等断言。
fn build_verification(
    environment_packages: usize,
    restored_packages: usize,
    produced_rpms: usize,
) -> JsonReproduceVerification {
    JsonReproduceVerification {
        environment_packages,
        restored_packages,
        produced_rpms,
    }
}

/// reproduce 配置链错误的变体保真映射：调用方返回 `crbs_core::Result` 无法走
/// `with_context` 链，故 downcast——CrbsError 原样透传（ValidationFailed /
/// NotFound → USAGE(4)），非 CrbsError 落 Io(6) 保底，context 前缀保留。
fn preserve_config_error(context: &str, e: anyhow::Error) -> CrbsError {
    e.downcast::<CrbsError>()
        .unwrap_or_else(|rest| CrbsError::io_message(format!("{context}: {rest}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_verification_reports_honest_counts() {
        let v = build_verification(368, 368, 4);
        assert_eq!(v.environment_packages, 368);
        assert_eq!(v.restored_packages, 368);
        assert_eq!(v.produced_rpms, 4);
    }

    /// 变体保真回归：CrbsError → USAGE(4)，非 CrbsError 落 Io(6) 且 context 保留。
    #[test]
    fn preserve_config_error_keeps_crbs_variant_and_falls_back_to_io() {
        let e = preserve_config_error(
            "resolve config target",
            anyhow::Error::new(CrbsError::ValidationFailed {
                message: "remote profile not found".into(),
            }),
        );
        assert!(
            matches!(e, CrbsError::ValidationFailed { .. }),
            "variant must survive: {e}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(&e),
            crbs_core::exit_code::USAGE
        );

        let e = preserve_config_error(
            "load product config",
            anyhow::Error::new(CrbsError::NotFound {
                message: "product gone".into(),
            }),
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(&e),
            crbs_core::exit_code::USAGE
        );

        let e = preserve_config_error("load product config", anyhow::anyhow!("disk exploded"));
        assert!(
            matches!(e, CrbsError::Io { .. }),
            "fallback must be Io: {e}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(&e),
            crbs_core::exit_code::ENVIRONMENT
        );
        assert!(
            format!("{e}").contains("load product config: disk exploded"),
            "context prefix must be preserved: {e}"
        );
    }

    /// 宏重放端到端：request_json → BuildOptions → 宏覆盖表流转到 engine 配置。
    #[tokio::test]
    async fn load_source_build_options_replays_task_macros() {
        let tmp = tempfile::tempdir().unwrap();
        let state = crbs_core::StateStore::new(tmp.path()).await.unwrap();
        let task_id = state
            .insert_task(crbs_core::TaskInsert {
                product: "fedora",
                pkg_name: "hello-1.0-1",
                user: "tester",
                phase: "succeeded",
                request_json: Some(r#"{"define": ["optflags=-O3"], "with_features": ["tests"]}"#),
                ..Default::default()
            })
            .await
            .unwrap();

        let opts = load_source_build_options(&state, Some(task_id), 1)
            .await
            .unwrap()
            .expect("source options should load from task archive");
        assert_eq!(opts.define, vec!["optflags=-O3".to_string()]);
        assert_eq!(opts.with_features, vec!["tests".to_string()]);

        let macros = crbs_core::engine::reproduce::source_macro_overrides(&opts).unwrap();
        assert_eq!(macros.get("optflags"), Some(&"-O3".to_string()));
        assert_eq!(macros.get("with_tests"), Some(&"1".to_string()));
    }

    /// 来源构建无 task 档案（本地 CLI 构建）→ 回退现状（None），不报错。
    #[tokio::test]
    async fn load_source_build_options_falls_back_without_task() {
        let tmp = tempfile::tempdir().unwrap();
        let state = crbs_core::StateStore::new(tmp.path()).await.unwrap();
        assert!(load_source_build_options(&state, None, 7)
            .await
            .unwrap()
            .is_none());
    }

    /// 回归守卫：校验摘要 JSON 不得含 sha256/byte 等字节相等性暗示。
    #[test]
    fn build_verification_makes_no_byte_identity_claim() {
        let v = build_verification(10, 9, 3);
        let json = serde_json::to_string(&v).expect("serialize verification");
        assert!(
            !json.contains("sha256"),
            "verification must not assert sha256 equality: {}",
            json
        );
        assert!(!json.contains("byte"));
        assert!(json.contains("environment_packages"));
        assert!(json.contains("restored_packages"));
        assert!(json.contains("produced_rpms"));
    }
}
