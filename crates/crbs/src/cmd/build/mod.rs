// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! build 子命令入口：输入解析、链/复现参数与模式分派。

use std::path::PathBuf;
use std::sync::Arc;

use crate::cli::{BuildArgs, ContainerParams, OutputFormat};
use crbs_core::engine::BuildEngine;
use crbs_core::error::CrbsError;
use crbs_core::privilege::CallerContext;
use crbs_core::sign::sign_build_outputs;
use tokio_util::sync::CancellationToken;
use tracing::warn;

pub(crate) mod attach;
pub(crate) mod batch;
pub(crate) mod chain;
pub(crate) mod dep_hint;
pub(crate) mod detach;
pub(crate) mod engine;
pub(crate) mod follow;
pub(crate) mod output;
pub(crate) mod rebuild_local;
pub(crate) mod remote;
pub(crate) mod reproduce;
pub(crate) mod route;
pub(crate) mod staging;
pub(crate) mod summary;
pub(crate) mod workers;

pub(crate) use engine::prepare_local_engine;
pub(crate) use output::{print_json, DetachBuildEntry, DetachOutput};
pub(crate) use route::{determine_route, BuildRoute};

/// 解析并组校验 `--label KEY=VALUE`（可重复）：首个 `=` 切分，键值字符集、长度、
/// 重复键与总量上限由 `validate_task_labels` 同源收口。
pub(crate) fn parse_task_labels(raw: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    let labels = raw
        .iter()
        .map(|s| crbs_core::validation::parse_task_label_arg(s))
        .collect::<crbs_core::Result<Vec<_>>>()?;
    crbs_core::validation::validate_task_labels(&labels)?;
    Ok(labels)
}

// 结果/汇总类型随 chain 编排下沉 crbs-core，re-export 维持 CLI 侧 `cmd::build::...` 路径。
pub(crate) use crbs_core::types::{BuildOutputs, BuildResult, BuildSummary};

#[derive(Clone, Debug)]
pub(crate) struct ChainParams {
    pub order_only: bool,
    pub force: bool,
    /// 有效 %dist（经 `normalize_dist` 规范化，带前导 `.`）；`None` 时 dist 防线
    ///（注入前 EVR 校验、启动预检 warn）全旁路。
    pub dist: Option<String>,
}

/// reproduce 命令参数（由 CLI 解析后传入）。
pub(crate) struct ReproduceArgs {
    pub product: Option<String>,
    pub task: String,
    pub srpm_overrides: Vec<PathBuf>,
    pub container: ContainerParams,
    pub keep_tmp_on_failure: bool,
    pub format: OutputFormat,
    /// 配置源：`--remote`/`--token`/`--ca-cert`；`--local` 不传入（与配置源正交），offline 走 `GlobalArgs::offline`。
    pub remote: Option<String>,
    pub token: Option<String>,
    pub ca_cert: Option<PathBuf>,
    /// 全局 `--offline`：读磁盘 fallback（存量快照），不 hit hub。
    pub offline: bool,
    /// 进程级取消令牌：reproduce 复用使 Ctrl-C / SIGTERM 优雅取消，避免强杀泄漏临时目录/挂载/容器。
    pub cancel_token: CancellationToken,
}

/// 本地 `--repro-from-srpm` 组装点共用（`prepare_local_engine` 与 detach 父进程）：
/// 要求全部输入 SRPM 头参数一致——回放值是 engine 级注入，批内混源会给部分
/// 构建静默写错头字段，故显式拒绝；探测失败（`rpm -qp` 非零/超时）原样上抛。
pub(crate) async fn probe_uniform_replay_params(
    inputs: &[PathBuf],
) -> anyhow::Result<(Option<String>, Option<i64>)> {
    let mut probed: Option<(Option<String>, Option<i64>)> = None;
    for srpm in inputs {
        let params = crbs_core::engine::depsolve::probe_srpm_replay_params(srpm, None).await?;
        if let Some(prev) = &probed {
            if prev != &params {
                return Err(CrbsError::ValidationFailed {
                    message: format!(
                        "--repro-from-srpm requires all input SRPMs to carry the same \
                         BUILDHOST/BUILDTIME header values, but {} differs from an \
                         earlier input; build them in separate invocations",
                        srpm.display()
                    ),
                }
                .into());
            }
        }
        probed = Some(params);
    }
    Ok(probed.unwrap_or((None, None)))
}

/// stderr 一行模式提示（CLI 交互输出例外；探测成功后必注，与服务端 build note 同语义可对账）。
pub(crate) fn print_repro_from_srpm_hint(params: &(Option<String>, Option<i64>)) {
    let (host, time) = params;
    eprintln!(
        "repro-from-srpm: BUILDHOST={} BUILDTIME={} replayed from SRPM header \
         (environment not restored; payload bytes not guaranteed)",
        host.as_deref().unwrap_or("(none)"),
        time.map(|t| t.to_string()).as_deref().unwrap_or("(none)"),
    );
}

pub(crate) async fn resolve_srpm_inputs(
    srpm: Vec<PathBuf>,
    list: Option<PathBuf>,
) -> anyhow::Result<Vec<PathBuf>> {
    let mut inputs = Vec::new();
    for path in srpm {
        if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
            return Err(CrbsError::ValidationFailed {
                message: format!("SRPM not found: {}", path.display()),
            }
            .into());
        }
        let path = tokio::fs::canonicalize(&path)
            .await
            .map_err(|e| CrbsError::from_io_context("io error", e))?;
        if tokio::fs::metadata(&path)
            .await
            .map_err(|e| CrbsError::from_io_context("metadata", e))?
            .is_dir()
        {
            let mut entries = tokio::fs::read_dir(&path)
                .await
                .map_err(|e| CrbsError::from_io_context("io error", e))?;
            // 读失败必须报错：中途 IO 错误下 `while let Ok(..)` 会假装扫完，只拿到子集还退出 0。
            loop {
                let entry = match entries.next_entry().await {
                    Ok(Some(e)) => e,
                    Ok(None) => break,
                    Err(e) => {
                        return Err(CrbsError::from_io_context(
                            format!("scan dir {}", path.display()),
                            e,
                        )
                        .into());
                    }
                };
                let p = entry.path();
                if p.file_name()
                    .map(|n| n.to_string_lossy().ends_with(".src.rpm"))
                    .unwrap_or(false)
                {
                    inputs.push(p);
                }
            }
        } else {
            inputs.push(path);
        }
    }

    if let Some(ref list_file) = list {
        let content = tokio::fs::read_to_string(list_file)
            .await
            .map_err(|e| CrbsError::from_io_context("io error", e))?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.to_string();
            let matched_paths: Vec<std::path::PathBuf> = tokio::task::spawn_blocking(move || {
                glob::glob(&line)
                    .map_err(|e| CrbsError::ValidationFailed {
                        message: format!("invalid glob pattern '{}': {}", line, e),
                    })
                    .map(|iter| {
                        iter.filter_map(|e| match e {
                            Ok(p) => Some(p),
                            Err(e) => {
                                tracing::warn!(error = %e, "Glob entry error, skipping");
                                None
                            }
                        })
                        .filter(|p| {
                            p.file_name()
                                .map(|n| n.to_string_lossy().ends_with(".src.rpm"))
                                .unwrap_or(false)
                        })
                        .collect()
                    })
            })
            .await
            // JoinError 仅在 glob 闭包 panic 时出现（遍历错误已在闭包内 warn-skip），
            // 真 bug 防御臂，INTERNAL(1) 语义。
            .map_err(|e| CrbsError::Internal(format!("glob task failed: {}", e)))??;
            for path in matched_paths {
                let canonical = tokio::fs::canonicalize(&path)
                    .await
                    .map_err(|e| CrbsError::from_io_context("io error", e))?;
                inputs.push(canonical);
            }
        }
    }

    inputs.sort();
    inputs.dedup();

    Ok(inputs)
}

/// 放置契约下限（--min-mem/--min-ncpu/--min-disk）只对有调度器的路径有意义
///（remote 提交、daemon 即本地 hub）：直连路径（--local/--chain/--attach 与
/// 无 daemon 兜底的本地构建）携带时明确报错拒绝（exit 4），不静默忽略。
pub(crate) fn ensure_req_min_supported_by_route(
    args: &BuildArgs,
    route: &BuildRoute,
) -> Result<(), CrbsError> {
    if !args.behavior.has_req_min() {
        return Ok(());
    }
    let supported = matches!(
        route,
        // 远程 hub 提交与 daemon 提交（daemon = 本地 crbs-server，含调度器）。
        BuildRoute::RemoteSubmit { .. }
            | BuildRoute::LocalDaemonSubmit
            | BuildRoute::LocalDaemonDetach
    );
    if supported {
        return Ok(());
    }
    Err(CrbsError::ValidationFailed {
        message: "--min-mem/--min-ncpu/--min-disk (placement requirements) require a \
             scheduler-backed path (remote or daemon submission); they are not \
             supported with --local/--chain/--attach or direct local builds"
            .into(),
    })
}

pub(crate) async fn handle_build(
    args: BuildArgs,
    ctx: CallerContext,
    // 透传至 `prepare_local_engine` 使 `--offline` 达 `api::product::load_product_config`；远程提交路径忽略。
    global: crate::cli::GlobalArgs,
) -> anyhow::Result<()> {
    // `--format json` 错误信封由 dispatch::run 的 json_guard 统一收口（含 dispatch 层建库等更早失败点）。
    handle_build_inner(args, ctx, global).await
}

async fn handle_build_inner(
    args: BuildArgs,
    ctx: CallerContext,
    global: crate::cli::GlobalArgs,
) -> anyhow::Result<()> {
    if args.reproduce.reproduce.is_some() && args.reproduce.no_reproduce {
        // 参数互斥属参数误用——ValidationFailed（USAGE=4）。
        return Err(CrbsError::ValidationFailed {
            message: "--reproduce and --no-reproduce are mutually exclusive".into(),
        }
        .into());
    }
    // clap conflicts_with 之外的进程内双保险（直构参数同样收口）；--chain 排除
    // 因 chain 复用引擎、逐源探测注入面未覆盖该路径。
    if args.reproduce.repro_from_srpm {
        if args.reproduce.reproduce.is_some() {
            return Err(CrbsError::ValidationFailed {
                message: "--repro-from-srpm and --reproduce are mutually exclusive".into(),
            }
            .into());
        }
        if args.behavior.chain {
            return Err(CrbsError::ValidationFailed {
                message: "--repro-from-srpm cannot be used with --chain \
                          (chain builds are not supported in this mode)"
                    .to_string(),
            }
            .into());
        }
    }

    let remote_target = crate::remote::resolve(
        args.runtime.remote.clone(),
        args.runtime.token.clone(),
        args.runtime.ca_cert.clone(),
        args.runtime.local,
    )
    .await?;
    let prefer_daemon = args.runtime.daemon || crate::local_daemon::daemon_auto_enabled().await;

    // --reproduce 的 fire-and-forget 仅远程提交成立（submit_reproduce 的 detach
    // 分支）；本地复现是同步引擎流，daemon 不理解复现语义（会静默丢
    // reproduce_from_build_id）——两者都必须显式拒绝而非降级。
    if args.reproduce.reproduce.is_some() && args.runtime.detach && remote_target.is_none() {
        return Err(CrbsError::ValidationFailed {
            message: "--reproduce with --detach requires --remote (local and daemon \
                      reproductions cannot be detached)"
                .into(),
        }
        .into());
    }

    let cancel_token = setup_cancel_token();

    // 3.5 --rebuild：`--local` 直连 StateStore 不启 daemon；其余必须经 crbs-server 重放。
    if let Some(rebuild_id) = args.input.rebuild.clone() {
        if args.runtime.local {
            if args.behavior.has_req_min() {
                // 放置契约直连路径硬化（与 determine_route 后同款，--rebuild 分支先于路由返回）。
                return Err(CrbsError::ValidationFailed {
                    message:
                        "--min-mem/--min-ncpu/--min-disk cannot be used with --local --rebuild \
                              (direct rebuilds have no scheduler; requirements are inherited from \
                              the source task)"
                            .into(),
                }
                .into());
            }
            return rebuild_local::handle_rebuild_local(&rebuild_id, &args, &ctx, &cancel_token)
                .await;
        }
        let target = match remote_target {
            Some(t) => t,
            None => match crate::local_daemon::ensure_running(Some(&cancel_token)).await {
                Ok(port) => crate::remote::RemoteTarget::new(
                    crate::local_daemon::base_url(port),
                    None,
                    None,
                ),
                Err(_) => {
                    // 调用误用（无 crbs-server 通道）——ValidationFailed（USAGE=4），非 INTERNAL(1)。
                    return Err(CrbsError::ValidationFailed {
                        message:
                            "--rebuild requires a crbs-server: use --remote, --local, or run the local daemon"
                                .into(),
                    }
                    .into());
                }
            },
        };
        return remote::submit_rebuild(&target, &rebuild_id, &args, Some(&cancel_token)).await;
    }

    // 3.6 --reproduce：有 --remote 由 server 锁定依赖快照复现；否则本地 Reproduce（读本地 StateStore/cache）。
    if let Some(reproduce_id) = args.reproduce.reproduce.clone() {
        if let Some(ref target) = remote_target {
            return remote::submit_reproduce(target, &reproduce_id, &args, Some(&cancel_token))
                .await;
        }
    }

    // --chain 仅本地（依赖 local repo 轮间产物传递，远程无此机制），与远程目标
    // 语义冲突显式拒绝；Some 也可能来自 remote.default 配置，报错须给 --local 出路。
    if args.behavior.chain && remote_target.is_some() {
        let message = "--chain cannot be used with a remote target: chain builds are \
            local-only (use --local to force a local chain build)";
        if args.output.format == OutputFormat::Json {
            output::print_json_error_envelope("build", "validation_failed", message)?;
            return Err(CrbsError::SilentExit {
                code: crbs_core::exit_code::USAGE,
            }
            .into());
        }
        return Err(CrbsError::ValidationFailed {
            message: message.to_string(),
        }
        .into());
    }

    let route = determine_route(
        &args.runtime,
        &args.behavior,
        &args.reproduce,
        remote_target,
        prefer_daemon,
    );
    ensure_req_min_supported_by_route(&args, &route)?;

    match route {
        BuildRoute::AttachRemote { target, attach_id } => {
            remote::attach_build(
                &target.url,
                target.token,
                target.ca_cert,
                &attach_id,
                args.output.follow_logs,
                args.output.format,
                Some(&cancel_token),
            )
            .await
        }
        BuildRoute::AttachDaemon { attach_id } => {
            match crate::local_daemon::ensure_running(Some(&cancel_token)).await {
                Ok(port) => {
                    remote::attach_build(
                        &crate::local_daemon::base_url(port),
                        None,
                        None,
                        &attach_id,
                        args.output.follow_logs,
                        args.output.format,
                        Some(&cancel_token),
                    )
                    .await
                }
                Err(e) => {
                    warn!(error = %e, "Local daemon unavailable, falling back to local attach");
                    attach::attach_local_build(
                        &attach_id,
                        args.output.follow_logs,
                        args.output.format,
                        &ctx,
                        Some(&cancel_token),
                    )
                    .await
                }
            }
        }
        BuildRoute::AttachLocal { attach_id } => {
            attach::attach_local_build(
                &attach_id,
                args.output.follow_logs,
                args.output.format,
                &ctx,
                Some(&cancel_token),
            )
            .await
        }
        BuildRoute::RemoteSubmit { target, wait } => {
            remote::submit_build(
                &target.url,
                target.token,
                target.ca_cert,
                args,
                wait,
                Some(&cancel_token),
            )
            .await
        }
        BuildRoute::LocalDaemonDetach => {
            let inputs =
                resolve_srpm_inputs(args.input.srpm.clone(), args.input.list.clone()).await?;
            match crate::local_daemon::ensure_running(Some(&cancel_token)).await {
                Ok(port) => {
                    crate::local_daemon::submit_builds(
                        &crate::local_daemon::base_url(port),
                        &args,
                        &inputs,
                        false,
                        None,
                    )
                    .await
                }
                Err(e) => {
                    // daemon 不可用回退直连本地 = 换无调度器路径：带放置契约时
                    // 拒绝而非静默降级丢弃声明。
                    ensure_req_min_supported_by_route(&args, &BuildRoute::LocalDetach)?;
                    warn!(error = %e, "Local daemon unavailable, falling back to local detach");
                    detach::submit_local_detach(args, &ctx, global).await
                }
            }
        }
        BuildRoute::LocalDetach => detach::submit_local_detach(args, &ctx, global).await,
        BuildRoute::LocalDaemonSubmit => {
            let inputs =
                resolve_srpm_inputs(args.input.srpm.clone(), args.input.list.clone()).await?;
            match crate::local_daemon::ensure_running(Some(&cancel_token)).await {
                Ok(port) => {
                    crate::local_daemon::submit_builds(
                        &crate::local_daemon::base_url(port),
                        &args,
                        &inputs,
                        true,
                        Some(&cancel_token),
                    )
                    .await
                }
                Err(e) => {
                    // 同 LocalDaemonDetach 回退臂：直连兜底携带放置契约即拒。
                    ensure_req_min_supported_by_route(&args, &BuildRoute::Batch)?;
                    warn!(error = %e, "Local daemon unavailable, falling back to direct local build");
                    let fail_fast = args.behavior.fail_fast;
                    let format = args.output.format;
                    // _staging 须活过构建 await：drop 时自动清理本进程暂存目录。
                    let (inputs, _staging) =
                        staging::stage_srpm_inputs(inputs, Some(&cancel_token)).await?;
                    let (engine, jobs) = prepare_local_engine(args, &inputs, &ctx, global).await?;
                    handle_batch_build(&engine, inputs, jobs, &cancel_token, fail_fast, format)
                        .await
                }
            }
        }
        BuildRoute::Reproduce { task } => {
            reproduce::handle_reproduce(
                ReproduceArgs {
                    product: args.input.product,
                    task,
                    srpm_overrides: args.input.srpm,
                    container: args.container,
                    keep_tmp_on_failure: args.reproduce.reproduce_keep_tmp_on_failure,
                    format: args.output.format,
                    remote: args.runtime.remote,
                    token: args.runtime.token,
                    ca_cert: args.runtime.ca_cert,
                    offline: global.offline,
                    cancel_token: cancel_token.clone(),
                },
                ctx,
            )
            .await
        }
        BuildRoute::ChainDirect => {
            let inputs =
                resolve_srpm_inputs(args.input.srpm.clone(), args.input.list.clone()).await?;
            let chain_args = args.clone();
            let format = args.output.format;
            // _staging 须活过构建 await：drop 时自动清理本进程暂存目录。
            let (inputs, _staging) =
                staging::stage_srpm_inputs(inputs, Some(&cancel_token)).await?;
            let (engine, _jobs) = prepare_local_engine(args, &inputs, &ctx, global).await?;
            let product = engine.product().to_string();
            handle_chain_build(
                &engine,
                &product,
                inputs,
                &chain_args,
                &cancel_token,
                prefer_daemon,
                format,
            )
            .await
        }
        BuildRoute::Batch => {
            let inputs =
                resolve_srpm_inputs(args.input.srpm.clone(), args.input.list.clone()).await?;
            let fail_fast = args.behavior.fail_fast;
            let format = args.output.format;
            // 提示仅对本地批构建有意义（daemon/remote 服务端排队；chain 已拓扑排序）；--assume-independent 静默。
            if inputs.len() >= 2 && !args.behavior.chain && !args.behavior.assume_independent {
                dep_hint::warn_if_inter_srpm_deps(&inputs).await;
            }
            // _staging 须活过构建 await：drop 时自动清理本进程暂存目录。
            let (inputs, _staging) =
                staging::stage_srpm_inputs(inputs, Some(&cancel_token)).await?;
            let (engine, jobs) = prepare_local_engine(args, &inputs, &ctx, global).await?;
            handle_batch_build(&engine, inputs, jobs, &cancel_token, fail_fast, format).await
        }
    }
}

/// 终止信号类别（进程首个收到的）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TermSignal {
    Interrupt,
    Terminate,
    Hangup,
}

/// 进程首个终止信号登记处：信号处理器写入、follow 各出口读取，用于区分
/// "取消远端构建"与"仅放弃跟随"。静态可变的依据：信号 disposition 本就是
/// 进程级单例，与 setup_cancel_token 的处理器一一对应。
static FIRST_TERM_SIGNAL: std::sync::Mutex<Option<TermSignal>> = std::sync::Mutex::new(None);

fn record_term_signal(sig: TermSignal) {
    if let Ok(mut slot) = FIRST_TERM_SIGNAL.lock() {
        // 只记首个信号（首信号定语义，后续信号由吞掉循环消费）。
        if slot.is_none() {
            *slot = Some(sig);
        }
    }
}

/// 首个终止信号；未收到过信号为 `None`（程序化 `cancel_token.cancel()` 与
/// 本地构建路径按取消语义处理，等同 SIGINT）。
pub(crate) fn first_term_signal() -> Option<TermSignal> {
    FIRST_TERM_SIGNAL.lock().ok().and_then(|s| *s)
}

/// 取消成因回查：把"cancel token 已触发"翻译成 follow 决策输入（信号类别
/// 优先，无信号视为程序化取消，等同 SIGINT 的取消语义）。
pub(crate) fn term_trigger() -> FollowTrigger {
    match first_term_signal() {
        Some(s) => FollowTrigger::Signal(s),
        None => FollowTrigger::Programmatic,
    }
}

/// follow 出口的触发来源。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FollowTrigger {
    /// 终止信号（SIGINT/SIGTERM/SIGHUP）。
    Signal(TermSignal),
    /// 无信号伴随的程序化取消（token 直接 cancel）。
    Programmatic,
    /// follow 等待超时。
    Timeout,
}

/// follow 出口"是否对远端补发取消"决策（batch/remote follow 两族共用的纯
/// 函数）：SIGINT（Ctrl-C）与程序化取消补发取消；SIGTERM/SIGHUP 只放弃
/// 跟随、绝不补发取消；超时由 `--timeout-cancel` 决定（默认仅放弃）。
pub(crate) fn follow_should_cancel_remote(trigger: FollowTrigger, timeout_cancel: bool) -> bool {
    match trigger {
        FollowTrigger::Signal(TermSignal::Interrupt) | FollowTrigger::Programmatic => true,
        FollowTrigger::Signal(TermSignal::Terminate)
        | FollowTrigger::Signal(TermSignal::Hangup) => false,
        FollowTrigger::Timeout => timeout_cancel,
    }
}

/// follow 聚合出口的放弃判定（纯函数）：放弃仅适用于 SIGTERM/SIGHUP detach
/// 命中取消桶、或无取消意图时未开 `--timeout-cancel` 的超时桶（不补发取消、
/// 打印提示后按 3 退出）；存在取消意图（首信号 SIGINT、或程序化取消命中
/// 取消桶）时即便混合超时也不放弃，走原路径级联取消远端。failed 桶非空时
/// 真实构建失败优先（退出码 2），放弃不改变结论。
pub(crate) fn follow_abandoned(
    first_signal: Option<TermSignal>,
    failed_count: usize,
    cancelled_count: usize,
    timeout_count: usize,
    timeout_cancel: bool,
) -> bool {
    if failed_count > 0 {
        return false;
    }
    // 取消意图：首信号 SIGINT，或程序化取消（无信号但取消桶非空）。
    let cancel_intent = first_signal == Some(TermSignal::Interrupt)
        || (first_signal.is_none() && cancelled_count > 0);
    if cancel_intent {
        return false;
    }
    let signal_abandoned =
        first_signal.is_some_and(|s| s != TermSignal::Interrupt) && cancelled_count > 0;
    let timeout_abandoned = !timeout_cancel && timeout_count > 0;
    signal_abandoned || timeout_abandoned
}

/// follow 放弃等待标记（SIGTERM/SIGHUP detach 或未开 `--timeout-cancel` 的
/// 超时）：独立类型保证 `is_cancelled_result` 不命中——`Cancelled` 与
/// `SilentExit{INTERRUPTED}` 都会触发 submit 入口对全部 build 补发取消；
/// 提示已在 follow 层打印，submit 收口处映射回 `SilentExit{INTERRUPTED(3)}`。
#[derive(Debug)]
pub(crate) struct FollowAbandoned;

impl std::fmt::Display for FollowAbandoned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "follow abandoned without cancelling remote builds")
    }
}

impl std::error::Error for FollowAbandoned {}

/// follow 放弃提示成因行：detach 信号与超时可同时命中则并列。
pub(crate) fn follow_abandon_reason(
    first_signal: Option<TermSignal>,
    timeout_abandoned: bool,
) -> String {
    let mut causes = Vec::new();
    match first_signal {
        Some(TermSignal::Terminate) => causes.push("received SIGTERM"),
        Some(TermSignal::Hangup) => causes.push("received SIGHUP"),
        _ => {}
    }
    if timeout_abandoned {
        causes.push("follow timeout reached (pass --timeout-cancel to also cancel remote builds)");
    }
    format!(
        "Stopped following remote builds ({}) — remote builds were NOT cancelled.",
        causes.join("; ")
    )
}

/// follow 放弃提示（stderr：stdout 在 JSON 模式是机器可解析信封）：构建仍在
/// 远端进行，给出 task/build id 与后续操作出路。
pub(crate) fn print_follow_abandon_notice(reason: &str, build_ids: &[i64]) {
    eprintln!("{reason}");
    let ids = build_ids
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!(
        "Builds keep running on the server — track with `crbs status` or cancel with `crbs cancel <build_id>` (builds: {ids})."
    );
}

/// 注册全局信号处理器（Ctrl+C / SIGTERM / SIGHUP）：首次信号登记类别并触发
/// `CancellationToken::cancel()`，此后循环消费同类型信号、不恢复默认
/// disposition——防清理完成前进程被默认信号杀死，留下孤儿挂载。
pub(crate) fn setup_cancel_token() -> tokio_util::sync::CancellationToken {
    let cancel_token = tokio_util::sync::CancellationToken::new();
    let cancel_for_signal = cancel_token.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to setup SIGINT handler");
                return;
            }
        };
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to setup SIGTERM handler");
                return;
            }
        };
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to setup SIGHUP handler");
                return;
            }
        };

        // 先登记信号类别再触发 token：follow 侧靠 token 唤醒后回查类别，
        // 顺序颠倒会把 SIGTERM detach 误判成取消远端。
        let which = tokio::select! {
            _ = sigint.recv() => (TermSignal::Interrupt, "SIGINT"),
            _ = sigterm.recv() => (TermSignal::Terminate, "SIGTERM"),
            _ = sighup.recv() => (TermSignal::Hangup, "SIGHUP"),
        };
        record_term_signal(which.0);
        tracing::info!(signal = %which.1, "Received signal, cancelling builds...");
        cancel_for_signal.cancel();

        // 持续消费后续信号、保持自定义 disposition：重复信号被忽略是刻意的
        //（防清理完成前被默认信号杀死留下孤儿挂载）；清理卡死出路 kill -9。
        loop {
            let which = tokio::select! {
                _ = sigint.recv() => "SIGINT",
                _ = sigterm.recv() => "SIGTERM",
                _ = sighup.recv() => "SIGHUP",
            };
            tracing::warn!(
                signal = %which,
                "Received repeated signal while cleanup is in progress; ignoring"
            );
        }
    });
    cancel_token
}

/// 统一处理 chain 构建（始终进程内执行：daemon 容器不挂载 local repo，轮间
/// 产物传递不可用）；JSON 错误收口复用 `json_exit_code_or_internal`。
pub(crate) async fn handle_chain_build(
    engine: &Arc<BuildEngine>,
    product: &str,
    inputs: Vec<PathBuf>,
    chain_args: &BuildArgs,
    cancel_token: &CancellationToken,
    prefer_daemon: bool,
    format: OutputFormat,
) -> anyhow::Result<()> {
    if prefer_daemon {
        // daemon 容器不挂载 local repo、不支持 chain；route 已恒返回 ChainDirect，此处仅提示。
        warn!("chain builds run in-process; the local daemon does not support local repo, ignoring --daemon/daemon_auto for --chain");
    }

    let chain_build_args = chain::ChainBuildArgs {
        jobs: engine.max_concurrent_builds(),
        fail_fast: chain_args.behavior.fail_fast,
        params: ChainParams {
            order_only: chain_args.behavior.order_only,
            force: chain_args.behavior.force,
            dist: crbs_core::build_options::normalize_dist(chain_args.behavior.dist.clone())?,
        },
        // 两独立 flag，no_result_repo 优先（保守关闭）：跳过完整 depsolve，非缓存包全进单轮并行构建。
        use_result_repo: chain_args.behavior.result_repo_effective(),
        format,
        summary_flags: chain::SummaryFlags {
            summary_limit: chain_args.output.summary_limit,
            list_failed: chain_args.output.list_failed,
            list_succeeded: chain_args.output.list_succeeded,
            concise: chain_args.output.concise,
            verbose_summary: chain_args.output.verbose_summary,
        },
    };

    if let Err(e) =
        chain::run_chain_build(engine, product, inputs, cancel_token, &chain_build_args).await
    {
        return json_exit_code_or_internal("build", e, format);
    }

    Ok(())
}

/// 为本地 batch 构建每个 SRPM 附加 target：纯 noarch `Some("noarch")`，其余 `None`（引擎默认）。
pub(crate) async fn attach_targets_to_inputs(
    inputs: Vec<PathBuf>,
) -> anyhow::Result<Vec<(PathBuf, Option<String>)>> {
    futures_util::future::try_join_all(inputs.into_iter().map(|srpm| async move {
        // anyhow context 包装保留 CrbsError downcast（语义退出码
        // BUILD_FAILED=2/INTERRUPTED=3），Display 保持 "{context}: {detail}"。
        let arch = crbs_core::engine::depsolve::parse_arch_from_srpm(&srpm, None)
            .await
            .map_err(|e| {
                anyhow::Error::new(e).context(format!("parse arch from {}", srpm.display()))
            })?;
        let target = if arch == "noarch" {
            Some("noarch".to_string())
        } else {
            None
        };
        Ok::<_, anyhow::Error>((srpm, target))
    }))
    .await
}

/// 统一处理 batch 构建（并发 worker 池）：封装 `run_build_workers` 调用、
/// 结果汇总输出与失败时 JSON/text 错误处理。
pub(crate) async fn handle_batch_build(
    engine: &Arc<BuildEngine>,
    inputs: Vec<PathBuf>,
    jobs: usize,
    cancel_token: &CancellationToken,
    fail_fast: bool,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let srpms_with_targets = attach_targets_to_inputs(inputs).await?;
    let mut summary = workers::run_build_workers(
        engine,
        srpms_with_targets,
        jobs,
        cancel_token,
        fail_fast,
        format,
    )
    .await?;

    // 先签名再构建 Summary，保 signed 字段正确。本地构建不落 build_artifacts 行
    //（无行级哈希可 stale），物理签名成功即可置位 builds.signed；有产物行的路径
    // 须先刷新哈希再置位（见 sign.rs）。
    for (_, outputs, _) in &mut summary.succeeded {
        sign_build_outputs(outputs, engine.config()).await;
        if outputs.signed {
            crbs_core::sign::mark_build_signed_best_effort(engine.state_store(), outputs.build_id)
                .await;
        }
    }

    let output = output::BuildSummaryOutput::new(output::SummaryOutputParams::plain(
        engine.product(),
        &summary,
    ))
    .await?;
    format.print(&output)?;

    if let Some(representative_err) = batch_failure_exit(&summary) {
        return Err(exit_from_representative(format, representative_err));
    }

    Ok(())
}

/// batch 失败退出判定与代表错误（本地 batch / follow / detached-run 共用，
/// 三桶条件与 `batch.rs::follow_builds` 逐字对齐防漂移）：任一失败桶非空即
/// 以代表错误退出，优先级 failed > timeout > cancelled，全空返回 None。
/// batch 代表错误收尾：JSON 结果已由 print_json_summary 输出，SilentExit 携码
/// 返回防 main 再打 "Error: ..." 污染 stdout；text 返回原始 CrbsError 供 main
/// classify_error 映射语义退出码（本地 batch / daemon follow / remote follow 共用）。
pub(crate) fn exit_from_representative(
    format: OutputFormat,
    representative: CrbsError,
) -> anyhow::Error {
    if format == OutputFormat::Json {
        let code = crbs_core::exit_code::crbs_error_exit_code(&representative);
        return CrbsError::SilentExit { code }.into();
    }
    representative.into()
}

pub(crate) fn batch_failure_exit(summary: &BuildSummary) -> Option<CrbsError> {
    if summary.failed.is_empty() && summary.timeout.is_empty() && summary.cancelled.is_empty() {
        return None;
    }
    Some(
        summary
            .representative_error()
            .unwrap_or_else(|| CrbsError::Internal("build failed".into())),
    )
}

/// chain / batch 路径错误收口：JSON 模式 downcast `CrbsError` 映射退出码为
/// `SilentExit`，非 `CrbsError` 出 envelope 落 INTERNAL；非 JSON 原样上抛。
pub(crate) fn json_exit_code_or_internal(
    scope: &'static str,
    e: anyhow::Error,
    format: OutputFormat,
) -> anyhow::Result<()> {
    if format != OutputFormat::Json {
        return Err(e);
    }
    let code = if let Some(ce) = e.downcast_ref::<CrbsError>() {
        crbs_core::exit_code::crbs_error_exit_code(ce)
    } else {
        output::print_json_error_envelope(scope, "internal_error", &e.to_string())?;
        crbs_core::exit_code::INTERNAL
    };
    Err(CrbsError::SilentExit { code }.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// follow 出口决策：SIGINT/程序化取消补发取消；SIGTERM/SIGHUP 只放弃；超时
    /// 默认不补发、--timeout-cancel 开启。
    #[test]
    fn follow_should_cancel_remote_distinguishes_signals_and_timeout() {
        assert!(follow_should_cancel_remote(
            FollowTrigger::Signal(TermSignal::Interrupt),
            false
        ));
        assert!(follow_should_cancel_remote(
            FollowTrigger::Programmatic,
            true
        ));
        assert!(!follow_should_cancel_remote(
            FollowTrigger::Signal(TermSignal::Terminate),
            true
        ));
        assert!(!follow_should_cancel_remote(
            FollowTrigger::Signal(TermSignal::Hangup),
            true
        ));
        assert!(!follow_should_cancel_remote(FollowTrigger::Timeout, false));
        assert!(follow_should_cancel_remote(FollowTrigger::Timeout, true));
    }

    /// 聚合放弃判定：detach 信号命中取消桶、无取消意图时未开 --timeout-cancel
    /// 的超时桶均放弃；SIGINT/程序化取消（即便混合超时）与 failed 桶非空
    ///（真实失败优先）不放弃。
    #[test]
    fn follow_abandoned_detects_detach_and_timeout_only() {
        assert!(follow_abandoned(
            Some(TermSignal::Terminate),
            0,
            2,
            0,
            false
        ));
        assert!(follow_abandoned(Some(TermSignal::Hangup), 0, 1, 0, true));
        assert!(follow_abandoned(None, 0, 0, 1, false));
        // SIGINT 与无信号取消：取消语义，由 submit 级联补发。
        assert!(!follow_abandoned(
            Some(TermSignal::Interrupt),
            0,
            3,
            0,
            false
        ));
        assert!(!follow_abandoned(None, 0, 3, 0, false));
        // 取消意图混合超时：不得折为放弃，走原路径级联取消远端。
        assert!(!follow_abandoned(
            Some(TermSignal::Interrupt),
            0,
            1,
            1,
            false
        ));
        assert!(!follow_abandoned(None, 0, 2, 1, false));
        // --timeout-cancel 开启：超时仍级联补发取消。
        assert!(!follow_abandoned(None, 0, 0, 1, true));
        // 真实构建失败优先，放弃不改变退出结论。
        assert!(!follow_abandoned(
            Some(TermSignal::Terminate),
            1,
            2,
            0,
            false
        ));
        assert!(!follow_abandoned(None, 0, 0, 0, false));
    }

    /// 放弃提示成因行：信号与超时可并列、无成因不崩；提示含后续操作出路关键字。
    #[test]
    fn follow_abandon_reason_lists_causes() {
        let sig = follow_abandon_reason(Some(TermSignal::Terminate), true);
        assert!(
            sig.contains("SIGTERM") && sig.contains("timeout"),
            "got: {sig}"
        );
        assert!(sig.contains("NOT cancelled"), "got: {sig}");

        let timeout_only = follow_abandon_reason(None, true);
        assert!(
            timeout_only.contains("timeout") && !timeout_only.contains("SIG"),
            "got: {timeout_only}"
        );
    }

    /// 全 cancelled 批也必须以代表错误退出并映射 INTERRUPTED(3)（回归防
    /// 退出判定只看 failed 桶、全取消批退出 0 假成功）。
    #[test]
    fn batch_all_cancelled_maps_to_interrupted_exit_3() {
        let summary = BuildSummary {
            succeeded: vec![],
            failed: vec![],
            cancelled: vec![(PathBuf::from("a-1.0-1.src.rpm"), CrbsError::Cancelled, 0)],
            timeout: vec![],
        };
        let err = batch_failure_exit(&summary).expect("all-cancelled batch must exit non-zero");
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(&err),
            crbs_core::exit_code::INTERRUPTED
        );
    }

    /// 三桶全空 → None（退出 0）；桶间优先级 failed > timeout > cancelled。
    #[test]
    fn batch_failure_exit_empty_is_none_and_failed_bucket_wins() {
        let empty = BuildSummary {
            succeeded: vec![],
            failed: vec![],
            cancelled: vec![],
            timeout: vec![],
        };
        assert!(
            batch_failure_exit(&empty).is_none(),
            "all-clear must exit 0"
        );

        let mixed = BuildSummary {
            succeeded: vec![],
            failed: vec![(
                PathBuf::from("f.src.rpm"),
                CrbsError::DepsolveFailed {
                    message: "x".into(),
                },
                0,
            )],
            cancelled: vec![(PathBuf::from("c.src.rpm"), CrbsError::Cancelled, 0)],
            timeout: vec![(PathBuf::from("t.src.rpm"), CrbsError::Timeout, 0)],
        };
        let err = batch_failure_exit(&mixed).expect("failed bucket must produce error");
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(&err),
            crbs_core::exit_code::BUILD_FAILED
        );
    }

    /// 放置契约下限的路径硬化（纯函数层）：调度器路径（RemoteSubmit /
    /// LocalDaemonSubmit / LocalDaemonDetach）放行；直连路径（--local Batch /
    /// --chain ChainDirect / --attach 三形态 / LocalDetach / Reproduce）携带
    /// 即 ValidationFailed（USAGE=4）；未声明 → 全路由放行。
    #[test]
    fn req_min_route_hardening_matrix() {
        fn args_with(min: bool) -> BuildArgs {
            let mut args = BuildArgs::try_parse_from(["crbs-build", "x-1.0-1.src.rpm", "-p", "p"])
                .expect("valid build args");
            if min {
                args.behavior.min_mem = Some("4G".into());
            }
            args
        }

        // 调度器路径放行（声明与未声明两形态）。
        for route in [
            BuildRoute::RemoteSubmit {
                target: crate::remote::RemoteTarget::new(
                    "https://hub.example.com".into(),
                    None,
                    None,
                ),
                wait: true,
            },
            BuildRoute::LocalDaemonSubmit,
            BuildRoute::LocalDaemonDetach,
        ] {
            assert!(ensure_req_min_supported_by_route(&args_with(true), &route).is_ok());
            assert!(ensure_req_min_supported_by_route(&args_with(false), &route).is_ok());
        }

        // 直连路径拒绝。
        for route in [
            BuildRoute::Batch,
            BuildRoute::ChainDirect,
            BuildRoute::LocalDetach,
            BuildRoute::AttachRemote {
                target: crate::remote::RemoteTarget::new(
                    "https://hub.example.com".into(),
                    None,
                    None,
                ),
                attach_id: "42".into(),
            },
            BuildRoute::AttachDaemon {
                attach_id: "42".into(),
            },
            BuildRoute::AttachLocal {
                attach_id: "42".into(),
            },
            BuildRoute::Reproduce { task: "7".into() },
        ] {
            let err = ensure_req_min_supported_by_route(&args_with(true), &route)
                .expect_err("direct path with req_min must be rejected");
            assert!(
                matches!(err, CrbsError::ValidationFailed { ref message }
                    if message.contains("--min-mem")),
                "unexpected error: {err}"
            );
            assert_eq!(
                crbs_core::exit_code::crbs_error_exit_code(&err),
                crbs_core::exit_code::USAGE,
                "hardening rejection must be exit 4"
            );
        }
    }

    /// CLI 解析与硬化（handle_build_inner 层）：--local/--chain/--attach 携带
    /// 任一 min_* 即 ValidationFailed（USAGE=4），错误点名 flag；远端目标在
    /// 隔离 HOME 下解析为 None，走直连臂。
    #[tokio::test]
    async fn req_min_flags_rejected_on_direct_paths() {
        // 钉非 Helper 特权后端：防有 setuid helper 的宿主机上 config 加载把进程楔死。
        crate::test_support::pin_setuid_privilege_backend();
        let tmp = tempfile::tempdir().unwrap();
        // HOME 一并隔离：真实 $HOME 的 remote.default 会使"直连路径"前提失效。
        let _env = crate::test_support::HomeIsolatedEnvGuard::new(tmp.path());
        let ctx = crbs_core::privilege::CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: "tester".to_string(),
            },
            false,
        );

        for flag in [
            vec!["--local", "--min-mem", "4G"],
            vec!["--chain", "--min-disk", "20G"],
            vec!["--attach", "42", "--min-ncpu", "8"],
        ] {
            let mut argv = vec!["crbs-build", "x-1.0-1.src.rpm", "-p", "p"];
            argv.extend(flag.iter().copied());
            let args =
                BuildArgs::try_parse_from(argv).unwrap_or_else(|e| panic!("flags must parse: {e}"));
            let err =
                handle_build_inner(args, ctx.clone(), crate::cli::GlobalArgs { offline: false })
                    .await
                    .expect_err("req_min on direct path must be rejected");
            let ce = err.downcast_ref::<CrbsError>().expect("must be CrbsError");
            assert!(
                matches!(ce, CrbsError::ValidationFailed { ref message }
                    if message.contains("placement requirements")),
                "unexpected error: {ce}"
            );
            assert_eq!(
                crbs_core::exit_code::crbs_error_exit_code(ce),
                crbs_core::exit_code::USAGE
            );
        }

        // --rebuild --local 直连重放同样拒绝（分支先于路由返回）。
        let args = BuildArgs::try_parse_from([
            "crbs-build",
            "--rebuild",
            "42",
            "--local",
            "--min-mem",
            "4G",
        ])
        .expect("valid build args");
        let err = handle_build_inner(args, ctx, crate::cli::GlobalArgs { offline: false })
            .await
            .expect_err("req_min with --rebuild --local must be rejected");
        let ce = err.downcast_ref::<CrbsError>().expect("must be CrbsError");
        assert!(
            matches!(ce, CrbsError::ValidationFailed { ref message }
                if message.contains("--rebuild") && message.contains("--local")),
            "unexpected error: {ce}"
        );
    }

    /// has_req_min 判定：三维任一声明即 true，全 None 即 false（硬化与回显
    /// 告警判定的单一计算点）。
    #[test]
    fn has_req_min_covers_all_three_dims() {
        let none = BuildArgs::try_parse_from(["crbs-build", "x-1.0-1.src.rpm", "-p", "p"])
            .expect("valid build args");
        assert!(!none.behavior.has_req_min());
        for flag in [
            vec!["--min-mem", "4G"],
            vec!["--min-ncpu", "8"],
            vec!["--min-disk", "20G"],
        ] {
            let mut argv = vec!["crbs-build", "x-1.0-1.src.rpm", "-p", "p"];
            argv.extend(flag.iter().copied());
            let args = BuildArgs::try_parse_from(argv).expect("valid build args");
            assert!(
                args.behavior.has_req_min(),
                "flag {flag:?} must set req_min"
            );
        }
    }

    /// --repro-from-srpm 与 --reproduce / --chain 的进程内互斥双保险：两组合
    /// 均 ValidationFailed（USAGE=4），直接改字段模拟绕过 clap 的构造路径。
    #[tokio::test]
    async fn repro_from_srpm_conflicts_with_reproduce_and_chain() {
        // 钉非 Helper 特权后端：防有 setuid helper 的宿主机楔死测试进程。
        crate::test_support::pin_setuid_privilege_backend();

        let ctx = crbs_core::privilege::CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: "tester".to_string(),
            },
            false,
        );
        let base = || {
            let mut args = crate::cli::BuildArgs::try_parse_from([
                "crbs-build",
                "x-1.0-1.src.rpm",
                "--product",
                "p",
            ])
            .expect("valid build args");
            args.reproduce.repro_from_srpm = true;
            args
        };

        let mut args = base();
        args.reproduce.reproduce = Some("424242".into());
        let err = handle_build_inner(args, ctx.clone(), crate::cli::GlobalArgs { offline: false })
            .await
            .expect_err("flag + --reproduce must be rejected");
        let ce = err.downcast_ref::<CrbsError>().expect("must be CrbsError");
        assert!(
            matches!(ce, CrbsError::ValidationFailed { ref message }
                if message.contains("--repro-from-srpm") && message.contains("--reproduce")),
            "unexpected error: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::USAGE
        );

        let mut args = base();
        args.behavior.chain = true;
        let err = handle_build_inner(args, ctx, crate::cli::GlobalArgs { offline: false })
            .await
            .expect_err("flag + --chain must be rejected");
        let ce = err.downcast_ref::<CrbsError>().expect("must be CrbsError");
        assert!(
            matches!(ce, CrbsError::ValidationFailed { ref message }
                if message.contains("--repro-from-srpm") && message.contains("--chain")),
            "unexpected error: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::USAGE
        );
    }

    /// `--reproduce` + `--detach`：允许组合（远程 fire-and-forget 合法），
    /// 无 --remote 时本地/daemon 不能 detach 复现——ValidationFailed（USAGE=4）。
    #[tokio::test]
    async fn reproduce_with_detach_requires_remote() {
        let tmp = tempfile::tempdir().unwrap();
        // HOME 一并隔离：真实 $HOME 的 remote.default 会使"无远程目标"前提失效。
        let _env = crate::test_support::HomeIsolatedEnvGuard::new(tmp.path());

        // clap 层已放行该组合（解析成功）。
        crate::cli::BuildArgs::try_parse_from([
            "crbs-build",
            "x-1.0-1.src.rpm",
            "--product",
            "p",
            "--reproduce",
            "15",
            "--detach",
        ])
        .expect("reproduce + detach must parse");

        let ctx = crbs_core::privilege::CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: "tester".to_string(),
            },
            false,
        );
        let args = crate::cli::BuildArgs::try_parse_from([
            "crbs-build",
            "x-1.0-1.src.rpm",
            "--product",
            "p",
            "--reproduce",
            "15",
            "--detach",
        ])
        .expect("valid build args");
        let err = handle_build_inner(args, ctx, crate::cli::GlobalArgs { offline: false })
            .await
            .expect_err("detach reproduce without remote must be rejected");
        let ce = err.downcast_ref::<CrbsError>().expect("must be CrbsError");
        assert!(
            matches!(ce, CrbsError::ValidationFailed { ref message }
                if message.contains("--reproduce") && message.contains("--remote")),
            "unexpected error: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::USAGE
        );
    }

    /// `--rebuild` 无任何 crbs-server 通道（无 --remote、非 --local、daemon
    /// 不可用）属调用误用——ValidationFailed（USAGE=4）。
    #[tokio::test]
    async fn rebuild_without_server_channel_is_validation_failed_exit_4() {
        // 钉非 Helper 特权后端：防有 setuid helper 的宿主机上 config 加载把进程楔死成 Helper。
        crate::test_support::pin_setuid_privilege_backend();
        let tmp = tempfile::tempdir().unwrap();
        // HOME 一并隔离：真实 $HOME 的 remote.default 会使"无远程目标"前提失效。
        let _env = crate::test_support::HomeIsolatedEnvGuard::new(tmp.path());
        let args = crate::cli::BuildArgs::try_parse_from(["crbs-build", "--rebuild", "424242"])
            .expect("valid build args");
        let ctx = crbs_core::privilege::CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: "tester".to_string(),
            },
            false,
        );

        let err = handle_build_inner(args, ctx, crate::cli::GlobalArgs { offline: false })
            .await
            .expect_err("no server channel must fail");
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::ValidationFailed { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::USAGE
        );
        assert!(
            format!("{ce}").contains(
                "--rebuild requires a crbs-server: use --remote, --local, or run the local daemon"
            ),
            "msg must be preserved verbatim: {ce}"
        );
    }

    /// `--label` 首个 `=` 切分：值可含 `=`（URL 查询串等）。
    #[test]
    fn parse_task_labels_splits_on_first_equals() {
        let labels = parse_task_labels(&[
            "git-repo=https://example.com/x.git".to_string(),
            "ref=heads/main?x=1".to_string(),
        ])
        .expect("valid labels");
        assert_eq!(
            labels,
            vec![
                (
                    "git-repo".to_string(),
                    "https://example.com/x.git".to_string()
                ),
                ("ref".to_string(), "heads/main?x=1".to_string()),
            ]
        );
    }

    /// 语法、键字符集与重复键均在入口拒绝（与 server 同源校验）。
    #[test]
    fn parse_task_labels_rejects_malformed_and_duplicates() {
        let err = parse_task_labels(&["noequals".to_string()]).unwrap_err();
        assert!(format!("{err:#}").contains("KEY=VALUE"), "msg: {err:#}");

        let err = parse_task_labels(&["bad key=v".to_string()]).unwrap_err();
        assert!(
            format!("{err:#}").contains("invalid characters"),
            "msg: {err:#}"
        );

        let err = parse_task_labels(&["k=1".to_string(), "k=2".to_string()]).unwrap_err();
        assert!(
            format!("{err:#}").contains("duplicate task label key"),
            "msg: {err:#}"
        );
    }
}
