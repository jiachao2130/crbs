// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! CLI 命令树与参数定义（clap derive），以及输出格式与全局参数。

use clap::Parser;
use crbs_core::types::BuildPriority;
use std::path::PathBuf;

/// `crbs build` 命令参数。
#[derive(Parser, Clone, Debug)]
pub struct BuildArgs {
    #[command(flatten)]
    pub input: BuildInputArgs,
    #[command(flatten)]
    pub behavior: BuildBehaviorArgs,
    #[command(flatten)]
    pub container: ContainerParams,
    #[command(flatten)]
    pub runtime: BuildRuntimeArgs,
    #[command(flatten)]
    pub output: BuildOutputArgs,
    #[command(flatten)]
    pub reproduce: BuildReproduceArgs,
}

/// 构建输入参数。
#[derive(Parser, Clone, Debug)]
pub struct BuildInputArgs {
    /// SRPM file paths or directories (directories are scanned for *.src.rpm).
    /// Alternatively use --list to read from a file; at least one source is required.
    #[arg(required = false, num_args = 0..)]
    pub srpm: Vec<std::path::PathBuf>,
    /// Product name (can be inferred from the build record in --attach/--reproduce mode).
    #[arg(short, long, required_unless_present_any = ["attach", "reproduce", "rebuild"])]
    pub product: Option<String>,
    /// Read SRPM list from a file (one path per line, glob expansion handled by the program)
    #[arg(short, long)]
    pub list: Option<std::path::PathBuf>,
    /// Rebuild a previously submitted task by ID via crbs-server (remote or local daemon).
    /// Reuses the recorded source SRPMs and build options of the original task.
    #[arg(
        long,
        value_name = "TASK_ID",
        conflicts_with_all = ["srpm", "list", "attach", "reproduce"]
    )]
    pub rebuild: Option<String>,
}

/// 构建行为参数（影响构建过程本身）。
#[derive(Parser, Clone, Debug)]
pub struct BuildBehaviorArgs {
    /// Number of concurrent workers (default: num_cpus)
    #[arg(short, long)]
    pub jobs: Option<usize>,
    /// Enable shared_layer dependency cache (useful when rebuilding the same package)
    #[arg(short, long)]
    pub shared_layer: bool,
    /// Enable tmpfs for the BUILD directory
    #[arg(long)]
    pub tmpfs: bool,
    /// Enable C/C++ compilation cache (useful for repeatedly built C/C++ packages)
    #[arg(long)]
    pub ccache: bool,
    /// Stop all builds if any package fails
    #[arg(long)]
    pub fail_fast: bool,
    /// Per-package build timeout in seconds (0 = unlimited)
    #[arg(short, long)]
    pub timeout: Option<u64>,
    /// Also cancel remote builds when the follow timeout is reached (legacy
    /// behavior); by default the wait is abandoned and the builds keep running
    /// on the server.
    #[arg(long)]
    pub timeout_cancel: bool,
    /// rpmbuild stage (bb=binary package, bs=source package, ba=both)
    #[arg(long, value_parser = ["bb", "bs", "ba"])]
    pub stage: Option<String>,
    /// RPM macro definitions (can be repeated to override config files; reserved keys like _topdir and empty values are rejected)
    #[arg(short = 'D', long, value_name = "KEY=VALUE")]
    pub define: Vec<String>,
    /// Enable conditional build options (can be repeated)
    #[arg(long = "with", value_name = "FEATURE")]
    pub with_features: Vec<String>,
    /// Disable conditional build options (can be repeated)
    #[arg(long = "without", value_name = "FEATURE")]
    pub without_features: Vec<String>,
    /// Skip the %check stage
    #[arg(long)]
    pub nocheck: bool,
    /// Skip the distro cleanup stages (%clean and rmbuild); BUILD-tree reclamation stays with the engine teardown
    #[arg(long)]
    pub noclean: bool,
    /// Do not generate debuginfo packages
    #[arg(long)]
    pub nodebuginfo: bool,
    /// Do not publish this build's RPMs to the product repo (Koji --scratch style;
    /// remote/daemon submissions only — standalone local builds have no hub repo)
    #[arg(long)]
    pub no_publish: bool,
    /// Do not consume the product repo for this build (the injected
    /// crbs-product.repo is omitted; tightening only — no flag can re-enable
    /// consumption disabled by the product config or product visibility;
    /// remote/daemon submissions only)
    #[arg(long)]
    pub no_consume: bool,
    /// Target architecture (e.g. x86_64_v3, aarch64).
    ///
    /// Single-value micro-architecture level target: pin the build to ONE
    /// exact target arch. Mutually exclusive with --arches, which fans the
    /// build out over a LIST of arches (remote builds only).
    #[arg(
        long,
        value_name = "ARCH",
        conflicts_with = "arch",
        long_help = "Target architecture (e.g. x86_64_v3, aarch64).\n\nSingle-value micro-architecture level target: pin the build to ONE exact target arch. Mutually exclusive with --arches (multi-arch fan-out list, remote builds only) — pass either --target or --arches, not both."
    )]
    pub target: Option<String>,
    /// Set the %dist macro (e.g. .fc44, .el9). Restricted to [a-zA-Z0-9._-]; a leading dot is added if missing
    #[arg(long, value_name = "TAG")]
    pub dist: Option<String>,
    /// Enable dependency chain builds (dependency ordering + staged builds + local repo + incremental)
    #[arg(short = 'C', long)]
    pub chain: bool,
    /// With --chain, only output the build order without building (dry-run)
    #[arg(short, long)]
    pub order_only: bool,
    /// Ignore incremental cache and force rebuilding all packages
    #[arg(short, long)]
    pub force: bool,
    /// Specify local repo path (default {crbs_root}/repo/{product}/, overrides config)
    #[arg(long)]
    pub repo: Option<std::path::PathBuf>,
    /// Enable local result repo injection in --chain mode (default ON).
    ///
    /// Only packages that are BuildRequires of other batch packages are
    /// injected (precise injection), avoiding the EVR conflicts that caused
    /// 88% failures when all products were injected unconditionally.
    /// `--no-result-repo` disables injection; the chain still collects
    /// successful RPMs into `{crbs_root}/repo/{product}/`.
    /// The two flags are mutually exclusive: the later one on the command
    /// line wins (`overrides_with`); scripts can append `--result-repo`
    /// after existing args to force injection back on.
    #[arg(
        long = "result-repo",
        default_value_t = true,
        overrides_with = "no_result_repo"
    )]
    pub result_repo: bool,
    /// Disable local result repo injection in --chain mode.
    #[arg(
        long = "no-result-repo",
        action = clap::ArgAction::SetTrue,
    )]
    pub no_result_repo: bool,
    /// Override configured max retry count (default uses global/product config)
    #[arg(long)]
    pub retry: Option<u32>,
    /// Build priority (0=default, 1=high, 2=critical).
    /// Only recorded for local direct builds; participates in queue priority for remote/daemon submissions.
    #[arg(long, default_value = "0")]
    pub priority: BuildPriority,
    /// Minimum memory requirement for placement (e.g. 4G, 512M, 2097152 KB).
    ///
    /// A placement contract, not a local cgroup limit: declares the node tier
    /// this build expects so the hub scheduler only assigns it to workers that
    /// satisfy the floor. Declare the peak under full parallelism (-j$(nproc));
    /// values above actual needs are allowed (deliberate routing). Units are
    /// 1024-based (K/M/G/T); bare digits mean KB; '4G' = 4 GiB. Upper limit:
    /// 1 TiB. Remote/daemon submissions only — rejected with --local, --chain
    /// and --attach.
    #[arg(long, value_name = "SIZE")]
    pub min_mem: Option<String>,
    /// Minimum CPU core count for placement (e.g. 8).
    ///
    /// Placement contract like --min-mem: the hub scheduler only assigns this
    /// build to workers with at least this many cores. Range 1..=1024.
    /// Remote/daemon submissions only — rejected with --local, --chain and
    /// --attach.
    #[arg(long, value_name = "CORES")]
    pub min_ncpu: Option<u32>,
    /// Minimum free disk requirement for placement (e.g. 20G, 1073741824 KB).
    ///
    /// Placement contract like --min-mem: the hub scheduler only assigns this
    /// build to workers whose reported free disk satisfies the floor.
    /// 1024-based units (K/M/G/T); bare digits mean KB. Upper limit: 64 TiB.
    /// Remote/daemon submissions only — rejected with --local, --chain and
    /// --attach.
    #[arg(long, value_name = "SIZE")]
    pub min_disk: Option<String>,
    /// Target architectures, comma-separated or repeatable (e.g. x86_64,aarch64).
    /// Defaults to arches in the product config, or the local architecture if not configured.
    /// Multi-arch fan-out is only supported with --remote; local builds run one host-arch build
    /// (extra arches produce a warning) or reject when the requested arch is not the host arch.
    /// Mutually exclusive with --target: --arches is the multi-arch fan-out LIST form
    /// (remote builds only), while --target pins a single micro-architecture target.
    #[arg(
        long = "arches",
        visible_alias = "arch",
        value_name = "ARCH",
        value_delimiter = ','
    )]
    pub arch: Vec<String>,
    /// With an explicit --arches list, skip arches the SRPM spec excludes (ExclusiveArch/
    /// ExcludeArch) instead of rejecting the whole submission. Skipped arches are named
    /// in the submission output. Default: reject the submission (fail fast).
    /// Only affects explicit arch requests; product-default fan-out and batch builds
    /// already skip incompatible arches. Local builds are unaffected: an incompatible
    /// spec always fails the whole build (exit 4), with or without this flag.
    #[arg(long)]
    pub skip_unsupported_arches: bool,
    /// Skip the batch inter-SRPM BuildRequires check (silences the -C/--chain hint).
    #[arg(long)]
    pub assume_independent: bool,
    /// Task label in KEY=VALUE form (repeatable; max 16 labels, key ≤64 chars,
    /// value ≤256 chars, duplicate keys rejected).
    ///
    /// Free-form task metadata such as git-repo=URL / git-commit=SHA,
    /// stored with the submitted task and filterable via `crbs status --label`.
    /// Local and remote tasks accept labels; a batch submits one task-scoped
    /// label set (not per-SRPM).
    #[arg(long, value_name = "KEY=VALUE")]
    pub label: Vec<String>,
}

/// 构建运行模式参数（决定本地/远程/daemon/attach 等路径）。
#[derive(Parser, Clone, Debug)]
pub struct BuildRuntimeArgs {
    /// Submit the build task and return immediately with build_id / short_id. Available in local, daemon, and remote modes.
    #[arg(long, conflicts_with_all = ["attach", "follow_logs"])]
    pub detach: bool,
    /// Download build artifacts to local result_dir after a successful remote build.
    /// By default artifacts stay on the server; use this to fetch them automatically.
    #[arg(long, conflicts_with_all = ["detach"])]
    pub download: bool,
    /// Attach to a running or finished build task by numeric ID. Available in local, daemon, and remote modes.
    #[arg(long, value_name = "ID", conflicts_with_all = ["detach", "reproduce"])]
    pub attach: Option<String>,
    /// Run build via a remote crbs-server.
    /// Argument is a URL or a profile name from [remote.profiles] in the config file.
    /// If the config sets `remote.default`, this option can be omitted to use the default remote.
    #[arg(long, value_name = "URL|NAME")]
    pub remote: Option<String>,
    /// Remote server API token (Bearer). Defaults to profile token/token_env/token_file → CRBS_TOKEN env var.
    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,
    /// Remote server CA certificate path (self-signed/internal CA scenarios).
    /// Defaults to profile ca_cert → CRBS_CA_CERT env var → system default trust store.
    #[arg(long, value_name = "PATH")]
    pub ca_cert: Option<std::path::PathBuf>,
    /// Force local direct build, ignoring `remote.default` in the config.
    #[arg(long, conflicts_with_all = ["remote", "daemon"])]
    pub local: bool,
    /// Run build via the local crbs-server daemon.
    /// If the daemon is not running, the program will try to start it automatically; falls back to local direct build on failure.
    #[arg(long, conflicts_with_all = ["remote", "local"])]
    pub daemon: bool,
}

/// 构建输出/交互参数。
#[derive(Parser, Clone, Debug)]
pub struct BuildOutputArgs {
    /// Output format: text (default) or json (machine-readable, final summary only)
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
    /// Follow build log output in real time (default: only status lines). Available in local, daemon, and remote modes.
    #[arg(long)]
    pub follow_logs: bool,
    // --- Chain summary tuning ---------------------------------------------
    /// Packages shown per category in the chain summary (default 20, 0 = no truncation).
    /// Has no effect together with `--list-failed` / `--list-succeeded` (those force full lists).
    #[arg(long, default_value_t = 20)]
    pub summary_limit: usize,
    /// Append every failed package name to the summary (one per line), untruncated.
    #[arg(long)]
    pub list_failed: bool,
    /// Append every succeeded package name to the summary (one per line), untruncated.
    #[arg(long)]
    pub list_succeeded: bool,
    /// Concise summary: a single `Total/Succeeded/Failed/Skipped/Wall` line.
    /// Named so it is not confused with the global `--quiet` (tracing level).
    #[arg(long)]
    pub concise: bool,
    /// Restore the legacy verbose summary: full package name lists on every line.
    /// Named so it is not confused with the global `--verbose` (tracing level).
    #[arg(long)]
    pub verbose_summary: bool,
}

/// 复现构建参数。
#[derive(Parser, Clone, Debug)]
pub struct BuildReproduceArgs {
    /// Reproduce the specified task's locked dependency snapshot and rebuild (idempotency check).
    /// The ID is a task ID (same domain as --rebuild and remote reproduce).
    /// With --detach the replay is submitted and not followed; requires --remote.
    #[arg(long, value_name = "TASK_ID")]
    pub reproduce: Option<String>,
    /// Keep temporary repo and base_os on --reproduce failure for debugging (default: cleaned up)
    #[arg(long)]
    pub reproduce_keep_tmp_on_failure: bool,
    /// Do not record provenance (skip URL resolution, package_cache copy, build_packages.json).
    /// This build cannot be reproduced later with `crbs build --reproduce`.
    #[arg(long, conflicts_with = "reproduce")]
    pub no_reproduce: bool,
    /// Replay BUILDHOST/BUILDTIME from the SRPM header into the build
    /// (repro-from-srpm mode): header fields stay true to the source SRPM, the
    /// build environment is NOT restored, so payload bytes are not guaranteed.
    /// The server (or the local build) probes each SRPM and injects the values.
    /// Mutually exclusive with --reproduce and --chain.
    #[arg(long, conflicts_with = "reproduce")]
    pub repro_from_srpm: bool,
}

/// Global arguments
#[derive(Parser, Debug)]
#[command(name = "crbs")]
#[command(about = "Modern RPM batch build engine")]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct App {
    /// Verbose output (debug-level logging)
    #[arg(short, long, global = true, conflicts_with = "quiet")]
    pub verbose: bool,
    /// Quiet mode (warning and error only)
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,
    /// Read product config from local disk instead of the hub.
    ///
    /// Applies to build / reproduce / sign / init / clean / shell / debug.
    /// Orthogonal to `--local`: `--local` picks **where** the build runs,
    /// `--offline` picks **where the product config comes from**.
    #[arg(long, global = true)]
    pub offline: bool,
    #[command(subcommand)]
    pub command: Cli,
}

/// 全局旗标透传容器：只承载 `--offline`（`verbose` / `quiet` 由 main.rs
/// 直接消费日志层）。按值传（`Copy`），避免下游 `&GlobalArgs` 生命周期噪音。
#[derive(Debug, Clone, Copy, Default)]
pub struct GlobalArgs {
    pub offline: bool,
}

/// Container runtime parameters (shared by Build / Shell / Debug)
#[derive(Parser, Clone, Debug)]
pub struct ContainerParams {
    /// Container backend (nspawn=default, chroot)
    #[arg(long)]
    pub backend: Option<String>,
    /// Disable network (enabled by default)
    #[arg(long)]
    pub no_network: bool,
    /// Hard memory limit (nspawn backend only, e.g. 512M / 2G)
    #[arg(long)]
    pub memory_max: Option<String>,
    /// CPU quota limit (nspawn backend only, e.g. 200% = 2 cores)
    #[arg(long)]
    pub cpu_quota: Option<String>,
}

/// `--remote` / `--token` / `--local` 三元组（Status / Logs / Cancel /
/// Sign / Download / Builds 六命令 flatten 共享，help 取公共表述）。
/// Products 是 `global = true` 形态、Build 走 `BuildRuntimeArgs`，不在此列。
#[derive(Parser, Clone, Debug)]
pub struct RemoteCommonArgs {
    /// Operate against a remote crbs-server (URL or profile name from config).
    /// If the config sets `remote.default`, this option can be omitted to use the default remote.
    #[arg(long, value_name = "URL|NAME")]
    pub remote: Option<String>,
    /// Remote server API token (defaults to CRBS_TOKEN or the profile token_env/token_file)
    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,
    /// Force local operation, ignoring `remote.default` in the config
    #[arg(long, conflicts_with = "remote")]
    pub local: bool,
}

impl RemoteCommonArgs {
    /// 远程模式判定：显式 `--remote` 且未 `--local`；config 的
    /// `remote.default` 在 handler 层解析。
    pub fn is_remote(&self) -> bool {
        self.remote.is_some() && !self.local
    }
}

/// `--remote` / `--token` / `--ca-cert` / `--daemon` / `--format` 五元组
///（Nihao / Ping / Whoami 三别名 flatten 共享，doc 为 help 文案逐字节钉死；
/// 与 `RemoteCommonArgs` / `AdminRemoteArgs` 措辞不同源，勿互相搬移）。
#[derive(Parser, Clone, Debug)]
pub struct ProbeArgs {
    /// Remote crbs-server address or configured profile name.
    /// If the config sets `remote.default`, this option can be omitted to use the default remote.
    #[arg(long, value_name = "URL|NAME")]
    pub remote: Option<String>,
    /// Remote server API token (Bearer). Defaults to profile token/token_env/token_file → CRBS_TOKEN env var.
    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,
    /// Remote server CA certificate path (self-signed/internal CA scenarios).
    #[arg(long, value_name = "PATH")]
    pub ca_cert: Option<PathBuf>,
    /// Connect via the local crbs-server daemon
    #[arg(long, conflicts_with = "remote")]
    pub daemon: bool,
    /// Output format: text (default) or json
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
}

/// Output format (shared by build / status, etc.)
#[derive(Clone, Copy, Debug, clap::ValueEnum, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable text (default)
    Text,
    /// Machine-readable JSON
    Json,
}

/// 可被两种格式统一输出的命令结果。
///
/// 实现者提供 JSON 序列化字符串与 text 渲染；`OutputFormat::print` 负责分发。
pub trait CommandOutput {
    /// 返回 pretty JSON 字符串。
    fn to_json(&self) -> anyhow::Result<String>;
    /// 打印 human-readable text。
    fn print_text(&self);
}

impl OutputFormat {
    /// 按当前格式打印输出。
    pub fn print<O: CommandOutput>(&self, output: &O) -> anyhow::Result<()> {
        match self {
            OutputFormat::Json => println!("{}", output.to_json()?),
            OutputFormat::Text => output.print_text(),
        }
        Ok(())
    }
}

impl BuildBehaviorArgs {
    /// result repo 注入的最终值（单一真值来源）：`--result-repo` 与
    /// `--no-result-repo` clap 层后传赢（`overrides_with`），此处收敛
    /// "最终是否注入"的唯一计算点，消费方一律走本方法防公式错位。
    pub fn result_repo_effective(&self) -> bool {
        self.result_repo && !self.no_result_repo
    }

    /// 任一放置契约下限（--min-mem/--min-ncpu/--min-disk）已声明：路径硬化
    /// 判定与回显告警判定的唯一计算点，消费方一律走本方法防三维漏一。
    pub fn has_req_min(&self) -> bool {
        self.min_mem.is_some() || self.min_ncpu.is_some() || self.min_disk.is_some()
    }
}

#[derive(Parser, Debug)]
#[allow(clippy::large_enum_variant)]
#[command(after_help = r"EXAMPLES:
  crbs build hello-1.0.0-1.src.rpm --local    Build an SRPM locally
  crbs builds show 42 --format json           Show one build's artifacts as JSON
  crbs logs 42                                Show build log of task 42
  crbs cancel 42                              Cancel a running task (cascades to child builds)
  crbs status                                 List tasks (or show one task's detail with --task)")]
pub enum Cli {
    /// Initialize the build environment
    Init {
        /// Product name, e.g. cc9
        product: String,
        /// Force overwrite existing base_os
        #[arg(long)]
        force: bool,
        /// Hub URL for config source (falls back to profile / `remote.default`).
        #[arg(long, value_name = "URL|NAME")]
        remote: Option<String>,
        /// Hub API token (defaults to profile token/env → CRBS_TOKEN).
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,
        /// PEM CA cert for hub TLS (falls back to profile / `CRBS_CA_CERT`).
        #[arg(long, value_name = "PATH")]
        ca_cert: Option<PathBuf>,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Build one or more SRPMs
    Build(BuildArgs),
    /// Enter the environment for manual operations
    Shell {
        /// Product name
        product: String,
        /// Run command non-interactively; non-zero exits are reported as failure (exit code 2)
        #[arg(short = 'c')]
        command: Option<String>,
        /// Mount host directories into the container (format: host[:container[:ro|rw]], repeatable)
        #[arg(long)]
        bind: Vec<String>,
        #[command(flatten)]
        container: ContainerParams,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Clean up the environment
    Clean {
        /// Product name
        product: String,
        /// Hub URL for config source (falls back to profile / `remote.default`).
        #[arg(long, value_name = "URL|NAME")]
        remote: Option<String>,
        /// Hub API token (defaults to profile token/env → CRBS_TOKEN).
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,
        /// PEM CA cert for hub TLS (falls back to profile / `CRBS_CA_CERT`).
        #[arg(long, value_name = "PATH")]
        ca_cert: Option<PathBuf>,
        /// Skip the confirmation prompt
        #[arg(long)]
        yes: bool,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Reproduce the build environment and prepare up to rpmbuild
    Debug {
        /// Build ID (incremental integer, execution domain)
        task: String,
        /// Run command non-interactively; non-zero exits are reported as failure (exit code 2)
        #[arg(short = 'c')]
        command: Option<String>,
        /// Mount host directories into the container (format: host[:container[:ro|rw]], repeatable)
        #[arg(long)]
        bind: Vec<String>,
        #[command(flatten)]
        container: ContainerParams,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// View task list, or a single task's detail with its child builds
    Status {
        /// Task ID (positional); use --task for the flag form
        #[arg(value_name = "TASK", conflicts_with = "task")]
        task_pos: Option<String>,
        /// Filter by product
        #[arg(short, long)]
        product: Option<String>,
        /// Number of entries to show (0 = all)
        #[arg(short, long, default_value = "20")]
        limit: usize,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Show all users' build records (default: only current user)
        #[arg(long)]
        all: bool,
        /// Filter by status (comma-separated or repeatable: succeeded,failed,building,pending,timeout,cancelled)
        #[arg(short, long, value_delimiter = ',')]
        filter: Vec<String>,
        /// Refresh in real time (like watch, every 2 seconds)
        #[arg(short, long, conflicts_with_all = ["format", "profile"])]
        watch: bool,
        /// Show a child build's profile (the ID is a build ID in this mode; requires --task and cannot be used with --watch)
        #[arg(long)]
        profile: bool,
        /// Repair stale active build records (phase=building/pending but the process is dead)
        #[arg(long)]
        repair: bool,
        /// Filter by task label (KEY=VALUE, exact key and value match)
        #[arg(long, value_name = "KEY=VALUE")]
        label: Option<String>,
        #[command(flatten)]
        remote_args: RemoteCommonArgs,
        /// Show a single task by ID (flag form; also accepts a positional ID)
        #[arg(long, value_name = "ID")]
        task: Option<String>,
    },
    /// Clean up expired shared layers
    Gc {
        /// Also clean up expired result directory artifacts
        #[arg(short, long)]
        results: bool,
        /// Only clean up result directories for the specified product (requires --results or --policy)
        #[arg(short, long)]
        product: Option<String>,
        /// Preview what would be cleaned without deleting (requires --results, --orphan-mounts, --cache, or --policy)
        #[arg(short, long)]
        dry_run: bool,
        /// Scan and clean orphan mounts for all products
        #[arg(short, long)]
        orphan_mounts: bool,
        /// Clean package cache files not referenced by build_packages
        #[arg(long)]
        cache: bool,
        /// Skip database reference check and delete all package cache (requires --cache)
        #[arg(long)]
        all: bool,
        /// Execute configured GC policies (result count/retention + package_cache capacity)
        #[arg(long)]
        policy: bool,
        /// Skip the confirmation prompt (required for --all in non-interactive use)
        #[arg(long)]
        yes: bool,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// View build logs
    Logs {
        /// Task ID (incremental integer; local and remote modes share task semantics)
        task: String,
        /// Sub-build architecture (required for multi-arch tasks to select the corresponding log)
        #[arg(short, long)]
        arch: Option<String>,
        /// Follow log output in real time (like tail -f)
        #[arg(short, long, conflicts_with = "format")]
        follow: bool,
        /// Show the last N lines (default: 50, 0 = all). No clap default so the
        /// handler can tell "user passed -n" apart from the fallback 50 (remote
        /// --follow rejects only an explicit -n).
        #[arg(short = 'n', long, value_name = "N")]
        lines: Option<usize>,
        /// Open the log in an editor read-only ($CRBS_LOG_VIEWER > $EDITOR > vim -R > vi -R)
        #[arg(short, long, conflicts_with = "format")]
        editor: bool,
        /// Filter lines containing the specified string (repeatable, OR relationship)
        #[arg(short, long)]
        grep: Vec<String>,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        #[command(flatten)]
        remote_args: RemoteCommonArgs,
    },
    /// Cancel a running task (cascades to its child builds)
    Cancel {
        /// Task ID (incremental integer; local and remote modes share task semantics)
        task: String,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        #[command(flatten)]
        remote_args: RemoteCommonArgs,
    },
    /// Local byte-level comparison of two tasks' RPM artifact sets
    Verify {
        /// First task ID
        task_a: i64,
        /// Second task ID (omit to compare task_a's own builds pairwise)
        task_b: Option<i64>,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Compare artifacts and profile differences between two builds
    Diff {
        /// Left build ID (execution domain)
        left: String,
        /// Right build ID (execution domain)
        right: String,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// GPG-sign existing build artifacts
    Sign {
        /// Task ID (incremental integer; local and remote modes share task semantics)
        task: String,
        /// GPG key ID (defaults to the global config)
        #[arg(short, long, value_name = "ID")]
        key_id: Option<String>,
        /// GPG home directory (defaults to the current user's keyring)
        #[arg(long, value_name = "PATH")]
        gpg_home: Option<String>,
        #[command(flatten)]
        remote_args: RemoteCommonArgs,
        /// PEM CA cert used when talking to the hub (config source resolution).
        /// Falls back to profile `ca_cert` / `CRBS_CA_CERT` env.
        #[arg(long, value_name = "PATH")]
        ca_cert: Option<PathBuf>,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Download build artifacts to local
    Download {
        /// Task ID (incremental integer; local and remote modes share task semantics)
        task: String,
        /// Specify output directory (local mode: copy target; remote mode: download save path)
        #[arg(short, long, value_name = "PATH")]
        output_dir: Option<PathBuf>,
        /// Download the source RPM (default: skip it)
        #[arg(long)]
        src: bool,
        /// Download debuginfo/debugsource/debug packages (default: skip them)
        #[arg(long)]
        debuginfo: bool,
        /// Download build logs (build.log and files under crbs-logs/); default: skip them
        #[arg(long)]
        logs: bool,
        /// Only download child builds for these architectures, comma-separated
        /// or repeatable (e.g. x86_64,aarch64). Default: download all architectures;
        /// arches not present in the task are silently ignored.
        #[arg(
            long = "arches",
            visible_alias = "arch",
            value_name = "ARCH",
            value_delimiter = ','
        )]
        arches: Vec<String>,
        /// Overwrite existing files in the output directory (default: fail on conflict).
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        remote_args: RemoteCommonArgs,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Builds management and artifact inspection
    Builds {
        #[command(subcommand)]
        command: BuildsCommand,
        #[command(flatten)]
        remote_args: RemoteCommonArgs,
    },
    /// Server-side whole-repo rebuild batches (remote only): submit / status / cancel
    Rebuild {
        #[command(subcommand)]
        command: RebuildCommand,
        /// Remote crbs-server address or configured profile name.
        /// If the config sets `remote.default`, this option can be omitted to use the default remote.
        #[arg(long, value_name = "URL|NAME", global = true)]
        remote: Option<String>,
        /// Remote server API token (Bearer). Defaults to profile token/token_env/token_file → CRBS_TOKEN env var.
        #[arg(long, value_name = "TOKEN", global = true)]
        token: Option<String>,
        /// Rebuild orchestration runs on the hub; there is no local form
        ///（--local 仅用于抑制 remote.default 误解析后给出明确报错）。
        #[arg(long, global = true, conflicts_with = "remote")]
        local: bool,
    },
    /// List or view product configurations
    Products {
        #[command(subcommand)]
        command: Option<ProductsCommand>,
        /// Remote crbs-server address or configured profile name.
        /// If the config sets `remote.default`, this option can be omitted to use the default remote.
        #[arg(long, value_name = "URL|NAME", global = true)]
        remote: Option<String>,
        /// Remote server API token (Bearer). Defaults to profile token/token_env/token_file → CRBS_TOKEN.
        #[arg(long, value_name = "TOKEN", global = true)]
        token: Option<String>,
        /// Force local product query, ignoring `remote.default` in the config.
        #[arg(long, global = true, conflicts_with = "remote")]
        local: bool,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text, global = true)]
        format: OutputFormat,
    },
    /// Send a greeting request to the server to verify connectivity and authentication;
    /// hidden compat alias — the primary names are `crbs ping` / `crbs whoami`
    /// (same request, same output; kept so existing scripts keep working).
    /// Note: clap_complete 4.5 static generators still list hidden commands,
    /// so `nihao` may remain in packaged completions until upstream filters them.
    #[command(hide = true)]
    Nihao {
        #[command(flatten)]
        probe: ProbeArgs,
    },
    /// Probe server connectivity (reachability + authentication). Same request
    /// and output as the hidden compat alias `crbs nihao`
    Ping {
        #[command(flatten)]
        probe: ProbeArgs,
    },
    /// Show the user and role the server associates with your credentials. Same
    /// request and output as the hidden compat alias `crbs nihao`
    Whoami {
        #[command(flatten)]
        probe: ProbeArgs,
    },
    /// Admin-only operations (grouped)
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Manage remote server profiles in the local config (list / test / add).
    /// Profile removal or in-place editing is done by editing the config file
    /// directly (see examples/config/crbs.toml for the full format).
    Remote {
        #[command(subcommand)]
        command: RemoteCommand,
    },
    /// Configuration file schema operations
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Internal use: run a submitted local build request in the background.
    #[command(hide = true)]
    DetachedRun {
        /// Request file path
        request_file: PathBuf,
    },
    /// Generate shell completion scripts (bash/zsh/fish/powershell)
    Completions {
        /// Target shell
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[derive(Parser, Clone, Debug)]
pub enum ConfigCommand {
    /// Print the JSON Schema (draft-07) of the config files to stdout
    ///
    /// Covers the engine config (crbs.toml), the server config (server.toml),
    /// product configs and worker config.
    Schema,
}

/// `crbs remote` 命令组：远程 server profile 的本地管理。list / test 读
/// 合并视图（系统 + 用户级 `~/.config/crbs/crbs.toml`，与 `--remote`
/// 解析口径一致）；add 只写用户级配置（注释保留式编辑）。
#[derive(Parser, Clone, Debug)]
pub enum RemoteCommand {
    /// List configured remote profiles (name / URL / auth method; token values are never shown)
    List {
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Probe a profile's connectivity and authentication against the hub
    /// (same ping endpoint as `crbs ping`; reports URL and authenticated identity)
    Test {
        /// Profile name as shown by `crbs remote list` (a URL also works)
        profile: String,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Add a remote profile to the user config (~/.config/crbs/crbs.toml),
    /// preserving existing comments and formatting.
    /// Without auth options the profile is created for anonymous access.
    Add {
        /// Profile name (must not look like a URL; `--remote <NAME>` resolves by this name)
        name: String,
        /// Hub base URL (http:// or https://; a bare host defaults to http://)
        #[arg(long, value_name = "URL")]
        url: String,
        /// Name of the environment variable holding the API token (recommended;
        /// `--remote` reads the token from it at resolve time)
        #[arg(long, value_name = "VAR", conflicts_with_all = ["token_file", "token"])]
        token_env: Option<String>,
        /// Path to a file holding the API token (supports a leading ~)
        #[arg(long, value_name = "PATH", conflicts_with_all = ["token_env", "token"])]
        token_file: Option<PathBuf>,
        /// Path to the hub CA certificate for TLS validation (self-signed or
        /// internal-CA hubs; same field the `--ca-cert` flag of other commands reads)
        #[arg(long, value_name = "PATH")]
        ca_cert: Option<PathBuf>,
        /// Inline API token (stored as plaintext in the config file; not recommended)
        #[arg(long, value_name = "TOKEN", conflicts_with_all = ["token_env", "token_file"])]
        token: Option<String>,
        /// Make this profile the default remote (sets `remote.default`, so `--remote` can be omitted)
        #[arg(long)]
        use_default: bool,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

#[derive(Parser, Clone, Debug)]
pub enum BuildsCommand {
    /// Show build artifacts (list of files with metadata)
    Show {
        /// Build ID
        id: i64,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Publish a build's artifacts into the product repo (remote; admin/operator/submitter)
    Publish {
        /// Build ID
        id: i64,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Remove a build's artifacts from the product repo (reversible; an older build may resurface)
    Unpublish {
        /// Build ID
        id: i64,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

/// `crbs rebuild` 子命令组（服务端整仓重建，仅远程）。
#[derive(Parser, Clone, Debug)]
pub enum RebuildCommand {
    /// Submit a whole-repo rebuild batch for a product
    Submit {
        /// Product name
        #[arg(short, long)]
        product: String,
        /// Source repository URL (http/https/file) holding the SRPMs to rebuild;
        /// must point at a repository level whose directory contains a repodata/
        /// directory (e.g. the SRPMS sub-repo of the published product repo)
        #[arg(long, value_name = "URL")]
        repo: String,
        /// Set the %dist macro for the rebuilt packages (e.g. .el9)
        #[arg(long, value_name = "TAG")]
        dist: Option<String>,
        /// Target architectures, comma-separated or repeatable (default: product arches)
        #[arg(long, value_name = "ARCH", value_delimiter = ',')]
        arch: Vec<String>,
        /// Ignore the incremental cache and rebuild every package
        #[arg(long)]
        force: bool,
        /// Batch behavior when a package fails (default: continue)
        #[arg(long, value_parser = ["continue", "abort"])]
        on_failure: Option<String>,
        /// Explicitly allow a dist mismatch with the source repo tag (fail-closed otherwise)
        #[arg(long)]
        allow_dist_mismatch: bool,
        /// Preview the incremental plan (enumerate + skip decision) without
        /// creating a batch or downloading anything
        #[arg(long)]
        dry_run: bool,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Show a rebuild batch: summary, per-round progress, failures by error code
    Status {
        /// Batch ID
        #[arg(long, value_name = "ID", required_unless_present = "latest")]
        id: Option<i64>,
        /// Operate on the most recent batch (mutually exclusive with --id)
        #[arg(long, conflicts_with = "id")]
        latest: bool,
        /// Refresh every 5s until the batch reaches a terminal status
        #[arg(short, long)]
        follow: bool,
        /// Output format: text (default) or json (mutually exclusive with --follow)
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Cancel an in-flight rebuild batch (cascades to in-flight builds)
    Cancel {
        /// Batch ID
        #[arg(long, value_name = "ID")]
        id: i64,
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

#[derive(Parser, Debug)]
pub enum ProductsCommand {
    /// Show detailed configuration for the specified product
    Show {
        /// Product name
        product: String,
    },
    /// Create a new product (remote only). Body config is read from a TOML file.
    Create {
        /// Product name (must be unique among official products)
        product: String,
        /// Path to a TOML file describing the product configuration
        #[arg(long = "config-file", value_name = "PATH")]
        config_file: std::path::PathBuf,
        /// Optional display name
        #[arg(long)]
        display_name: Option<String>,
        /// Optional parent product id (for future inheritance)
        #[arg(long)]
        parent_id: Option<i64>,
        /// Optional audit reason recorded to product_config_history
        #[arg(long)]
        reason: Option<String>,
    },
    /// Update product config (remote only). Requires `expected_revision` for
    /// optimistic locking; a mismatch surfaces as HTTP 409.
    ///
    /// re-parent: pass `--parent-id N` to hook the product under a new
    /// parent, or `--detach-parent` to make it a root (parent_id=NULL). The
    /// two flags are mutually exclusive; omit both to leave the parent link
    /// untouched.
    Update {
        /// Product name
        product: String,
        /// Path to the new TOML config
        #[arg(long = "config-file", value_name = "PATH")]
        config_file: std::path::PathBuf,
        /// The revision the caller believes is current (required; server
        /// returns 409 on mismatch)
        #[arg(long)]
        expected_revision: i64,
        /// Optional audit reason
        #[arg(long)]
        reason: Option<String>,
        /// re-parent this product to the given parent product id.
        #[arg(long, value_name = "ID", conflicts_with = "detach_parent")]
        parent_id: Option<i64>,
        /// detach this product from its parent (become root).
        #[arg(long, conflicts_with = "parent_id")]
        detach_parent: bool,
    },
    /// fork an existing product into a new one.
    ///
    /// Two modes:
    /// - **activelink (default)**: create the new product with an empty own
    ///   config plus `parent_id = <PARENT>`; it inherits everything from the
    ///   parent chain until the fork adds its own overrides via `products
    ///   update`.
    /// - `--detached`: create the new product with a snapshot of the parent's
    ///   chain-resolved config as its own config, and `parent_id = NULL`
    ///   (root). Future changes on the parent do **not** propagate.
    Fork {
        /// Parent product to fork from (source)
        parent: String,
        /// Name of the new product to create
        new_name: String,
        /// Optional display name for the new product
        #[arg(long)]
        display_name: Option<String>,
        /// Snapshot parent's resolved config and set parent_id=NULL (root)
        #[arg(long)]
        detached: bool,
        /// Optional audit reason recorded to product_config_history
        #[arg(long)]
        reason: Option<String>,
    },
    /// Delete a product row (remote only). This does not touch on-disk
    /// artifacts — for that use `crbs products clean`.
    Delete {
        /// Product name
        product: String,
        /// Skip the interactive confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Clean a product's published repo and on-disk artifacts on the hub
    /// (remote only; admin role). The clean task runs asynchronously on the
    /// server and is rejected while the product has active builds.
    Clean {
        /// Product name
        product: String,
        /// Skip the interactive confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Show product config revision history (remote only).
    History {
        /// Product name
        product: String,
        /// Return a specific revision instead of the full list
        #[arg(long)]
        revision: Option<i64>,
    },
    /// Export the chain-resolved product config as TOML (remote only).
    ///
    /// Bridge for the transition window: local CLI subcommands still read
    /// on-disk `products/*.toml`, so run e.g. `crbs products export ule3
    /// --remote hub > /etc/crbs/products/ule3.toml` to sync the file
    /// back from the DB after a `products update`.
    Export {
        /// Product name
        product: String,
        /// Write TOML to this path instead of stdout
        #[arg(long, value_name = "PATH")]
        file: Option<std::path::PathBuf>,
    },
    /// Publish a product (make it public). Remote only.
    Publish {
        /// Product name
        product: String,
        /// Optional audit reason recorded to product_config_history
        #[arg(long)]
        reason: Option<String>,
    },
    /// Unpublish a product (make it private). Remote only.
    Unpublish {
        /// Product name
        product: String,
        /// Optional audit reason recorded to product_config_history
        #[arg(long)]
        reason: Option<String>,
    },
    /// Transfer product ownership to another user. Remote only.
    Transfer {
        /// Product name
        product: String,
        /// Username of the new owner
        new_owner: String,
        /// Optional audit reason recorded to product_config_history
        #[arg(long)]
        reason: Option<String>,
    },
    /// Manage product ACL (list, grant, revoke). Remote only.
    #[command(subcommand)]
    Acl(crate::cmd::products_acl::ProductsAclCommand),
}

/// `crbs admin` 命令组。
#[derive(Parser, Debug)]
pub enum AdminCommand {
    /// Remotely (re)initialize base_os on one or more workers via the hub
    Init(AdminInitArgs),
    /// Rebuild a product's published repo from current DB state (remote; admin only)
    RebuildRepo(AdminRebuildRepoArgs),
    /// Manage package resource profiles (declared placement floors; remote; admin only)
    #[command(subcommand)]
    ResourceProfile(crate::cmd::admin::resource_profile::ResourceProfileCommand),
}

/// `--remote` / `--token` / `--ca-cert` / `--format` 四元组（admin init /
/// rebuild-repo 两命令 flatten 共享）。文案与 `ProbeArgs` 不同源（token
/// 箭头、format 句号），不可互换搬移——help 输出逐字节钉死。
#[derive(Parser, Clone, Debug)]
pub struct AdminRemoteArgs {
    /// Remote crbs-server address or configured profile name.
    /// If the config sets `remote.default`, this option can be omitted to use the default remote.
    #[arg(long, value_name = "URL|NAME")]
    pub remote: Option<String>,
    /// Remote server API token (Bearer). Defaults to profile token/token_env/token_file -> CRBS_TOKEN env var.
    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,
    /// Remote server CA certificate path (self-signed/internal CA scenarios).
    #[arg(long, value_name = "PATH")]
    pub ca_cert: Option<PathBuf>,
    /// Output format: text (default) or json.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
}

/// `crbs admin rebuild-repo` 参数。
#[derive(Parser, Debug, Clone)]
pub struct AdminRebuildRepoArgs {
    /// Product name whose published repo will be reconciled and rebuilt.
    pub product: String,
    #[command(flatten)]
    pub remote_args: AdminRemoteArgs,
}

/// `crbs admin init` 参数。
#[derive(Parser, Debug, Clone)]
pub struct AdminInitArgs {
    /// Product name
    pub product: String,
    /// Target worker ID; repeatable (`-w 1 -w 2`). Mutually exclusive with `--all`.
    #[arg(short = 'w', long = "worker")]
    pub worker: Vec<i64>,
    /// Dispatch init to every currently online worker.
    #[arg(long, conflicts_with = "worker")]
    pub all: bool,
    /// Skip interactive confirmation.
    #[arg(short = 'y', long)]
    pub yes: bool,
    #[command(flatten)]
    pub remote_args: AdminRemoteArgs,
}

// Re-export core validation helpers for CLI convenience.
pub use crbs_core::validation::{
    ensure_product_config_ready, validate_container_params, validate_product,
};

impl Cli {
    /// Whether this subcommand requires loading StateStore first.
    /// Remote mode uses the HTTP API and needs no local StateStore.
    pub fn requires_state_store(&self) -> bool {
        !self.is_remote()
            && matches!(
                self,
                Self::Gc { .. }
                    | Self::Status { .. }
                    | Self::Logs { .. }
                    | Self::Cancel { .. }
                    | Self::Diff { .. }
                    | Self::Verify { .. }
                    | Self::Build(..)
                    | Self::Builds { .. }
                    | Self::Sign { .. }
                    | Self::Download { .. }
            )
    }

    /// Whether this subcommand uses remote mode (no local privileges, StateStore, or crbs_root).
    /// Only checks the explicit `--remote` flag; the config `remote.default` resolves in the handler layer.
    pub fn is_remote(&self) -> bool {
        match self {
            Self::Build(args) => args.runtime.remote.is_some() && !args.runtime.local,
            Self::Status { remote_args, .. }
            | Self::Logs { remote_args, .. }
            | Self::Cancel { remote_args, .. }
            | Self::Sign { remote_args, .. }
            | Self::Download { remote_args, .. }
            | Self::Builds { remote_args, .. } => remote_args.is_remote(),
            // 整仓重建编排只在 hub 侧，无本地形态；--local 仅触发 handler
            // 的 remote-only 报错。
            Self::Rebuild { .. } => true,
            _ => false,
        }
    }

    /// 支持 JSON 错误信封的命令的 `(命令名, format)` 契约；无 `--format`
    /// 的命令返回 `None`。`dispatch::run` 失败收口按此 format 打唯一
    /// JSON 信封（stdout 恰一个 JSON 文档）；命令名 = 实际 CLI 命令路径
    ///（子命令带父路径如 `"builds show"`），与成功输出的命令标识同源。
    pub fn json_error_contract(&self) -> Option<(&'static str, OutputFormat)> {
        match self {
            Self::Init { format, .. } => Some(("init", *format)),
            Self::Build(args) => Some(("build", args.output.format)),
            Self::Shell { format, .. } => Some(("shell", *format)),
            Self::Clean { format, .. } => Some(("clean", *format)),
            Self::Debug { format, .. } => Some(("debug", *format)),
            Self::Status { format, .. } => Some(("status", *format)),
            Self::Gc { format, .. } => Some(("gc", *format)),
            Self::Logs { format, .. } => Some(("logs", *format)),
            Self::Cancel { format, .. } => Some(("cancel", *format)),
            Self::Verify { format, .. } => Some(("verify", *format)),
            Self::Diff { format, .. } => Some(("diff", *format)),
            Self::Sign { format, .. } => Some(("sign", *format)),
            Self::Download { format, .. } => Some(("download", *format)),
            Self::Builds { command, .. } => match command {
                BuildsCommand::Show { format, .. } => Some(("builds show", *format)),
                BuildsCommand::Publish { format, .. } => Some(("builds publish", *format)),
                BuildsCommand::Unpublish { format, .. } => Some(("builds unpublish", *format)),
            },
            // products 的 format 是父命令级 global 旗标，全族共用一个键。
            Self::Products { format, .. } => Some(("products", *format)),
            Self::Nihao { probe } => Some(("nihao", probe.format)),
            Self::Ping { probe } => Some(("ping", probe.format)),
            Self::Whoami { probe } => Some(("whoami", probe.format)),
            Self::Admin { command } => match command {
                AdminCommand::Init(args) => Some(("admin init", args.remote_args.format)),
                AdminCommand::RebuildRepo(args) => {
                    Some(("admin rebuild-repo", args.remote_args.format))
                }
                AdminCommand::ResourceProfile(command) => {
                    use crate::cmd::admin::resource_profile::ResourceProfileCommand as C;
                    let (name, format) = match &command {
                        C::List { remote_args, .. } => {
                            ("admin resource-profile list", remote_args.format)
                        }
                        C::Set { remote_args, .. } => {
                            ("admin resource-profile set", remote_args.format)
                        }
                        C::Unset { remote_args, .. } => {
                            ("admin resource-profile unset", remote_args.format)
                        }
                        C::Export { remote_args, .. } => {
                            ("admin resource-profile export", remote_args.format)
                        }
                        C::Import { remote_args, .. } => {
                            ("admin resource-profile import", remote_args.format)
                        }
                    };
                    Some((name, format))
                }
            },
            Self::Config { .. } | Self::Completions { .. } | Self::DetachedRun { .. } => None,
            Self::Remote { command } => match command {
                RemoteCommand::List { format } => Some(("remote list", *format)),
                RemoteCommand::Test { format, .. } => Some(("remote test", *format)),
                RemoteCommand::Add { format, .. } => Some(("remote add", *format)),
            },
            Self::Rebuild { command, .. } => match command {
                RebuildCommand::Submit { format, .. } => Some(("rebuild submit", *format)),
                RebuildCommand::Status { format, .. } => Some(("rebuild status", *format)),
                RebuildCommand::Cancel { format, .. } => Some(("rebuild cancel", *format)),
            },
        }
    }

    /// 支持 `--remote`/`--local` 的命令提取远程解析四元组 `(remote, token,
    /// ca_cert, local)`，其余返回 `None`；`dispatch::run` 在加载本地
    /// StateStore 前据此探测，让 config 的 `remote.default` 也能跳过本地
    /// 初始化。仅 Build / Sign 暴露 `--ca-cert`，其余传 `None`（resolve
    /// 回退 profile 配置或 `CRBS_CA_CERT`）。
    pub fn remote_resolve_args(&self) -> Option<RemoteResolveArgs> {
        match self {
            Self::Build(args) => Some(RemoteResolveArgs {
                remote: args.runtime.remote.clone(),
                token: args.runtime.token.clone(),
                ca_cert: args.runtime.ca_cert.clone(),
                local: args.runtime.local,
            }),
            Self::Status { remote_args, .. }
            | Self::Logs { remote_args, .. }
            | Self::Cancel { remote_args, .. }
            | Self::Download { remote_args, .. }
            | Self::Builds { remote_args, .. } => {
                // 本臂五命令不暴露 --ca-cert，ca_cert 传 None。
                Some(RemoteResolveArgs {
                    remote: remote_args.remote.clone(),
                    token: remote_args.token.clone(),
                    ca_cert: None,
                    local: remote_args.local,
                })
            }
            Self::Sign {
                remote_args,
                ca_cert,
                ..
            } => Some(RemoteResolveArgs {
                remote: remote_args.remote.clone(),
                token: remote_args.token.clone(),
                ca_cert: ca_cert.clone(),
                local: remote_args.local,
            }),
            _ => None,
        }
    }
}

/// `remote_resolve_args` 的返回值：远程解析所需的四元组。
pub struct RemoteResolveArgs {
    pub remote: Option<String>,
    pub token: Option<String>,
    pub ca_cert: Option<PathBuf>,
    pub local: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn admin_init_parses_repeated_worker_and_yes() {
        let cli = Cli::try_parse_from([
            "crbs",
            "admin",
            "init",
            "cc9",
            "-w",
            "1",
            "-w",
            "2",
            "-y",
            "--remote",
            "https://h",
        ])
        .expect("valid input should parse");
        match cli {
            Cli::Admin {
                command: AdminCommand::Init(a),
            } => {
                assert_eq!(a.product, "cc9");
                assert_eq!(a.worker, vec![1, 2]);
                assert!(a.yes);
                assert!(!a.all);
                assert_eq!(a.remote_args.remote.as_deref(), Some("https://h"));
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn admin_init_all_and_worker_are_mutually_exclusive() {
        let err = Cli::try_parse_from(["crbs", "admin", "init", "cc9", "--all", "-w", "1"])
            .expect_err("clap should reject conflicting flags");
        let msg = err.to_string();
        assert!(
            msg.contains("cannot be used with") || msg.contains("conflict"),
            "unexpected clap error: {}",
            msg
        );
    }

    #[test]
    fn admin_init_all_without_worker_parses() {
        let cli = Cli::try_parse_from(["crbs", "admin", "init", "cc9", "--all", "--yes"]).unwrap();
        match cli {
            Cli::Admin {
                command: AdminCommand::Init(a),
            } => {
                assert!(a.all);
                assert!(a.yes);
                assert!(a.worker.is_empty());
            }
            _ => panic!("unexpected variant"),
        }
    }

    /// download 新旗标：--src 默认关；--arches 逗号分隔展开、可重复累加、
    /// visible alias `--arch` 同解析。
    #[test]
    fn download_src_and_arches_flags_parse() {
        let cli = Cli::try_parse_from(["crbs", "download", "7"]).unwrap();
        match cli {
            Cli::Download { src, arches, .. } => {
                assert!(!src);
                assert!(arches.is_empty());
            }
            _ => panic!("unexpected variant"),
        }

        let cli = Cli::try_parse_from([
            "crbs",
            "download",
            "7",
            "--src",
            "--arches",
            "x86_64,aarch64",
            "--arch",
            "riscv64",
        ])
        .unwrap();
        match cli {
            Cli::Download { src, arches, .. } => {
                assert!(src);
                assert_eq!(arches, ["x86_64", "aarch64", "riscv64"]);
            }
            _ => panic!("unexpected variant"),
        }
    }

    /// 互斥参数组合必须被 clap 拒绝（usage 错误，退出码 4），逐一钉住。
    #[test]
    fn mutually_exclusive_flags_are_rejected_by_clap() {
        let cases: &[&[&str]] = &[
            &["crbs", "status", "--watch", "--format", "json"],
            &["crbs", "status", "--profile", "--watch", "1"],
            &[
                "crbs",
                "build",
                "-p",
                "p",
                "--reproduce",
                "1",
                "--no-reproduce",
            ],
            &["crbs", "logs", "1", "--format", "json", "-f"],
            &["crbs", "logs", "1", "--format", "json", "--editor"],
            // status 位置参数与 --task 是同 ID 的两种形态
            &["crbs", "status", "1", "--task", "2"],
            &[
                "crbs",
                "build",
                "-p",
                "p",
                "--target",
                "x86_64_v3",
                "--arches",
                "x86_64,aarch64",
            ],
            // visible_alias "arch" 形式同样受冲突约束
            &[
                "crbs",
                "build",
                "-p",
                "p",
                "--target",
                "x86_64_v3",
                "--arch",
                "x86_64",
            ],
        ];
        for argv in cases {
            let err = match Cli::try_parse_from(argv.iter().copied()) {
                Err(e) => e,
                Ok(_) => panic!("{argv:?} should be rejected as conflicting flags"),
            };
            // 须精确为 ArgumentConflict，而非缺参/非法值等其他 usage 错误。
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "unexpected clap error kind for {argv:?}: {}",
                err
            );
            let msg = err.to_string();
            assert!(
                msg.contains("cannot be used with") || msg.contains("conflict"),
                "unexpected clap error for {argv:?}: {}",
                msg
            );
        }
    }

    // --- RemoteCommonArgs flatten ----------------------------------------

    /// flatten 三元组仍按原参数名解析到各命令变体，`is_remote` 判定不变；
    /// `builds` 的三元组是父命令参数（非 global），旗标须置于子命令之前。
    #[test]
    fn remote_common_args_flatten_parses_into_variants() {
        for (name, argv) in [
            ("status", vec!["crbs", "status"]),
            ("logs", vec!["crbs", "logs", "1"]),
            ("cancel", vec!["crbs", "cancel", "1"]),
            ("sign", vec!["crbs", "sign", "1"]),
            ("download", vec!["crbs", "download", "1"]),
            (
                "builds",
                vec![
                    "crbs", "builds", "--remote", "prod", "--token", "t", "show", "1",
                ],
            ),
        ] {
            let mut with_flags = argv.clone();
            if name != "builds" {
                with_flags.extend(["--remote", "prod", "--token", "t"]);
            }
            let cli = Cli::try_parse_from(with_flags)
                .unwrap_or_else(|e| panic!("{name} --remote/--token should parse: {e}"));
            assert!(
                cli.is_remote(),
                "{name} with --remote and without --local is remote"
            );
            let args = cli
                .remote_resolve_args()
                .unwrap_or_else(|| panic!("{name} must expose remote resolve args"));
            assert_eq!(args.remote.as_deref(), Some("prod"), "{name} remote");
            assert_eq!(args.token.as_deref(), Some("t"), "{name} token");
            assert!(!args.local, "{name} local default");
            if name != "sign" {
                // 仅 Sign 暴露 --ca-cert（remote_resolve_args 既有契约）。
                assert!(args.ca_cert.is_none(), "{name} must not carry ca_cert");
            }
        }
    }

    /// `--local` 与 `--remote` 互斥在 flatten 结构内仍被 clap 拦截（防
    /// flatten 改变 arg id 解析）。
    #[test]
    fn remote_common_args_local_conflicts_with_remote_in_flatten() {
        for mut argv in [
            vec!["crbs", "status"],
            vec!["crbs", "logs", "1"],
            vec!["crbs", "cancel", "1"],
            vec!["crbs", "sign", "1"],
            vec!["crbs", "download", "1"],
        ] {
            argv.extend(["--remote", "prod", "--local"]);
            let err = Cli::try_parse_from(argv).expect_err("conflicting --remote/--local");
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "unexpected clap error kind: {err}"
            );
        }
        // builds 的三元组在父命令层，旗标置于子命令之前。
        let err =
            Cli::try_parse_from(["crbs", "builds", "--remote", "prod", "--local", "show", "1"])
                .expect_err("conflicting --remote/--local");
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::ArgumentConflict,
            "unexpected clap error kind: {err}"
        );
    }

    // --- Global --offline ---------------------------------

    #[test]
    fn offline_flag_defaults_to_false() {
        let app = App::try_parse_from(["crbs", "status"]).expect("valid input");
        assert!(!app.offline, "--offline should default false");
    }

    // --- json_error_contract: 信封支持矩阵 -------------------------

    /// 每个带 `--format json` 的命令都能解出 (命令名, Json) 契约；缺省
    /// format 为 Text；`--format json` 传入时为 Json。覆盖全部信封族命令。
    #[test]
    fn json_error_contract_covers_every_format_json_command() {
        let cases: &[(&[&str], &str)] = &[
            (&["crbs", "init", "cc9"], "init"),
            (&["crbs", "build", "-p", "cc9", "x.src.rpm"], "build"),
            (&["crbs", "shell", "cc9"], "shell"),
            (&["crbs", "clean", "cc9"], "clean"),
            (&["crbs", "debug", "42"], "debug"),
            (&["crbs", "status"], "status"),
            (&["crbs", "gc"], "gc"),
            (&["crbs", "logs", "42"], "logs"),
            (&["crbs", "cancel", "42"], "cancel"),
            (&["crbs", "verify", "1"], "verify"),
            (&["crbs", "diff", "1", "2"], "diff"),
            (&["crbs", "sign", "42"], "sign"),
            (&["crbs", "download", "42"], "download"),
            (&["crbs", "builds", "show", "42"], "builds show"),
            (&["crbs", "builds", "publish", "42"], "builds publish"),
            (&["crbs", "builds", "unpublish", "42"], "builds unpublish"),
            (&["crbs", "products"], "products"),
            (&["crbs", "products", "delete", "cc9"], "products"),
            (&["crbs", "products", "clean", "cc9"], "products"),
            (&["crbs", "nihao"], "nihao"),
            (&["crbs", "ping"], "ping"),
            (&["crbs", "whoami"], "whoami"),
            (&["crbs", "admin", "init", "cc9", "--all"], "admin init"),
            (
                &["crbs", "admin", "rebuild-repo", "cc9"],
                "admin rebuild-repo",
            ),
            (
                &[
                    "crbs",
                    "admin",
                    "resource-profile",
                    "list",
                    "--product",
                    "cc9",
                ],
                "admin resource-profile list",
            ),
            (
                &[
                    "crbs",
                    "admin",
                    "resource-profile",
                    "set",
                    "cc9",
                    "gcc",
                    "x86_64",
                    "--min-mem",
                    "4G",
                ],
                "admin resource-profile set",
            ),
            (
                &[
                    "crbs",
                    "admin",
                    "resource-profile",
                    "unset",
                    "cc9",
                    "gcc",
                    "x86_64",
                ],
                "admin resource-profile unset",
            ),
            (
                &[
                    "crbs",
                    "admin",
                    "resource-profile",
                    "export",
                    "--product",
                    "cc9",
                ],
                "admin resource-profile export",
            ),
            (
                &[
                    "crbs",
                    "admin",
                    "resource-profile",
                    "import",
                    "--file",
                    "/tmp/profiles.json",
                ],
                "admin resource-profile import",
            ),
            (
                &[
                    "crbs",
                    "rebuild",
                    "submit",
                    "-p",
                    "cc9",
                    "--repo",
                    "https://h/r",
                ],
                "rebuild submit",
            ),
            (&["crbs", "rebuild", "status", "--latest"], "rebuild status"),
            (
                &["crbs", "rebuild", "cancel", "--id", "3"],
                "rebuild cancel",
            ),
            (&["crbs", "remote", "list"], "remote list"),
            (&["crbs", "remote", "test", "prod"], "remote test"),
            (
                &["crbs", "remote", "add", "prod", "--url", "https://h"],
                "remote add",
            ),
        ];
        for (argv, expected_command) in cases {
            let cli = Cli::try_parse_from(*argv)
                .unwrap_or_else(|e| panic!("{} should parse: {}", argv.join(" "), e));
            let (command, default_format) = cli
                .json_error_contract()
                .unwrap_or_else(|| panic!("{argv:?} must carry a JSON error contract"));
            assert_eq!(command, *expected_command, "{argv:?} command name");
            assert_eq!(default_format, OutputFormat::Text, "{argv:?} default");

            let mut with_flag: Vec<&str> = argv.to_vec();
            with_flag.extend(["--format", "json"]);
            let cli = Cli::try_parse_from(with_flag)
                .unwrap_or_else(|e| panic!("{} --format json should parse: {}", argv.join(" "), e));
            let (command, format) = cli
                .json_error_contract()
                .unwrap_or_else(|| panic!("{argv:?} must carry a JSON error contract"));
            assert_eq!(command, *expected_command);
            assert_eq!(format, OutputFormat::Json, "{argv:?} --format json");
        }
    }

    /// 无 `--format json` 的命令没有信封契约（dispatch 收口点对其透传）。
    /// 豁免名单只有 config / completions / detached-run（输出为 JSON Schema、
    /// 补全脚本、内部通道，无表格可 json 化）；remote/rebuild 已入信封矩阵。
    #[test]
    fn json_error_contract_is_none_for_non_json_commands() {
        for argv in [
            vec!["crbs", "config", "schema"],
            vec!["crbs", "completions", "bash"],
            vec!["crbs", "detached-run", "/tmp/request.json"],
        ] {
            let cli = Cli::try_parse_from(argv.iter().copied())
                .unwrap_or_else(|e| panic!("{} should parse: {}", argv.join(" "), e));
            assert!(
                cli.json_error_contract().is_none(),
                "{argv:?} must not carry a JSON error contract"
            );
        }
    }

    #[test]
    fn offline_flag_can_be_placed_after_subcommand() {
        // `global = true`：旗标可置于任意层级，两种位置解析到同一 App 字段。
        let app_pre = App::try_parse_from(["crbs", "--offline", "status"]).expect("pre parses");
        let app_post = App::try_parse_from(["crbs", "status", "--offline"]).expect("post parses");
        assert!(app_pre.offline);
        assert!(app_post.offline);
    }

    // --- Build: --result-repo / --no-result-repo -------------------------

    fn parse_build_chain(extra: &[&str]) -> BuildArgs {
        let mut argv: Vec<&str> = vec!["crbs", "build", "-p", "cc9", "--chain", "--local"];
        argv.extend_from_slice(extra);
        argv.push("pkg.src.rpm");
        let cli = Cli::try_parse_from(argv).expect("valid input should parse");
        match cli {
            Cli::Build(args) => args,
            other => panic!(
                "expected Cli::Build variant, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn result_repo_defaults_to_on_in_chain_mode() {
        // 精准注入后默认安全开启（只灌被依赖的包，不灌全量）。
        let args = parse_build_chain(&[]);
        assert!(
            args.behavior.result_repo,
            "--result-repo must default to true"
        );
        assert!(!args.behavior.no_result_repo);
    }

    #[test]
    fn no_result_repo_flag_disables_injection() {
        let args = parse_build_chain(&["--no-result-repo"]);
        assert!(args.behavior.no_result_repo);
    }

    #[test]
    fn no_result_repo_flag_overrides_result_repo() {
        let args = parse_build_chain(&["--result-repo", "--no-result-repo"]);
        assert!(args.behavior.no_result_repo);
        assert!(!args.behavior.result_repo_effective());
    }

    #[test]
    fn result_repo_after_no_result_repo_wins_later_flag() {
        // overrides_with：后出现的 flag 覆盖先出现的（CLI 惯例，脚本可追加覆盖）。
        let args = parse_build_chain(&["--no-result-repo", "--result-repo"]);
        assert!(args.behavior.result_repo);
        assert!(!args.behavior.no_result_repo);
        assert!(args.behavior.result_repo_effective());
    }

    #[test]
    fn result_repo_effective_single_source_of_truth() {
        let args = parse_build_chain(&[]);
        assert!(args.behavior.result_repo_effective());
        let args = parse_build_chain(&["--no-result-repo"]);
        assert!(!args.behavior.result_repo_effective());
        let args = parse_build_chain(&["--result-repo"]);
        assert!(args.behavior.result_repo_effective());
    }

    // --- Build: --target / --arches 互斥 ---------------------------------

    /// 单独给 --target 或 --arches 都必须正常解析（互斥仅指同时给出）；
    /// 顺带钉住 target 的单值与 arches 的列表语义不被冲突约束误伤。
    #[test]
    fn target_and_arches_are_allowed_individually() {
        let cli = Cli::try_parse_from([
            "crbs",
            "build",
            "-p",
            "cc9",
            "--target",
            "x86_64_v3",
            "pkg.src.rpm",
        ])
        .expect("--target alone should parse");
        match cli {
            Cli::Build(args) => {
                assert_eq!(args.behavior.target.as_deref(), Some("x86_64_v3"));
                assert!(args.behavior.arch.is_empty());
            }
            other => panic!("expected Cli::Build variant, got {other:?}"),
        }

        let cli = Cli::try_parse_from([
            "crbs",
            "build",
            "-p",
            "cc9",
            "--arches",
            "x86_64,aarch64",
            "pkg.src.rpm",
        ])
        .expect("--arches alone should parse");
        match cli {
            Cli::Build(args) => {
                assert!(args.behavior.target.is_none());
                assert_eq!(args.behavior.arch, vec!["x86_64", "aarch64"]);
            }
            other => panic!("expected Cli::Build variant, got {other:?}"),
        }
    }

    // --- init / shell / clean / debug / sign / download: --format ---------

    /// 六命令逐一断言：`--format json` 可解析为 Json，缺省为 Text。
    #[test]
    fn six_commands_parse_format_json_and_default_text() {
        let cases: &[(&str, &[&str])] = &[
            ("init", &["cc9"]),
            ("shell", &["cc9"]),
            ("clean", &["cc9"]),
            ("debug", &["42"]),
            ("sign", &["42"]),
            ("download", &["42"]),
        ];
        for (name, positional) in cases {
            let mut with_flag: Vec<&str> = vec!["crbs", name];
            with_flag.extend_from_slice(positional);
            with_flag.push("--format");
            with_flag.push("json");
            let cli = Cli::try_parse_from(with_flag)
                .unwrap_or_else(|e| panic!("{} --format json should parse: {}", name, e));
            let got = match &cli {
                Cli::Init { format, .. }
                | Cli::Shell { format, .. }
                | Cli::Clean { format, .. }
                | Cli::Debug { format, .. }
                | Cli::Sign { format, .. }
                | Cli::Download { format, .. } => *format,
                other => panic!("unexpected variant for {}: {:?}", name, other),
            };
            assert_eq!(got, OutputFormat::Json, "{} --format json", name);

            let mut without: Vec<&str> = vec!["crbs", name];
            without.extend_from_slice(positional);
            let cli = Cli::try_parse_from(without)
                .unwrap_or_else(|e| panic!("{} default should parse: {}", name, e));
            let got = match &cli {
                Cli::Init { format, .. }
                | Cli::Shell { format, .. }
                | Cli::Clean { format, .. }
                | Cli::Debug { format, .. }
                | Cli::Sign { format, .. }
                | Cli::Download { format, .. } => *format,
                other => panic!("unexpected variant for {}: {:?}", name, other),
            };
            assert_eq!(got, OutputFormat::Text, "{} default format", name);
        }
    }

    // --- nihao 别名：ping / whoami ---------------------------------------

    /// 提取 nihao / ping / whoami 变体的请求参数五元组：三变体共享
    /// `ProbeArgs`（字段同构），dispatch 转发同一 handler
    ///（`cmd::nihao::handle_nihao`），同 argv 解析出同五元组即保证请求与
    /// 输出完全一致。
    fn nihao_request_args(
        cli: Cli,
    ) -> (
        Option<String>,
        Option<String>,
        Option<PathBuf>,
        bool,
        OutputFormat,
    ) {
        match cli {
            Cli::Nihao { probe } | Cli::Ping { probe } | Cli::Whoami { probe } => (
                probe.remote,
                probe.token,
                probe.ca_cert,
                probe.daemon,
                probe.format,
            ),
            other => panic!(
                "expected nihao/ping/whoami variant, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn ping_and_whoami_parse_to_same_request_shape_as_nihao() {
        for name in ["nihao", "ping", "whoami"] {
            let cli = Cli::try_parse_from(["crbs", name])
                .unwrap_or_else(|e| panic!("crbs {name} should parse: {}", e));
            assert_eq!(
                nihao_request_args(cli),
                (None, None, None, false, OutputFormat::Text),
                "crbs {name} defaults"
            );
        }

        // 全量旗标（--daemon 与 --remote 互斥，单独覆盖）。
        let flags = [
            "--remote",
            "prod",
            "--token",
            "sekret",
            "--ca-cert",
            "/tmp/ca.pem",
            "--format",
            "json",
        ];
        let shapes: Vec<_> = ["nihao", "ping", "whoami"]
            .map(|name| {
                let mut argv: Vec<&str> = vec!["crbs", name];
                argv.extend_from_slice(&flags);
                nihao_request_args(
                    Cli::try_parse_from(argv)
                        .unwrap_or_else(|e| panic!("crbs {name} with flags should parse: {}", e)),
                )
            })
            .to_vec();
        assert_eq!(shapes[0], shapes[1], "ping mirrors nihao with full flags");
        assert_eq!(shapes[0], shapes[2], "whoami mirrors nihao with full flags");
        assert_eq!(
            shapes[0],
            (
                Some("prod".into()),
                Some("sekret".into()),
                Some(PathBuf::from("/tmp/ca.pem")),
                false,
                OutputFormat::Json
            )
        );

        let shapes: Vec<_> = ["nihao", "ping", "whoami"]
            .map(|name| {
                nihao_request_args(
                    Cli::try_parse_from(["crbs", name, "--daemon"])
                        .unwrap_or_else(|e| panic!("crbs {name} --daemon should parse: {}", e)),
                )
            })
            .to_vec();
        assert_eq!(shapes[0], shapes[1], "ping mirrors nihao with --daemon");
        assert_eq!(shapes[0], shapes[2], "whoami mirrors nihao with --daemon");
        assert!(shapes[0].3, "--daemon flag is preserved");
    }

    /// nihao 是隐藏别名：help 与补全不展示（ping/whoami 为主名），
    /// 但命令本身仍可解析分发（兼容存量脚本）。
    #[test]
    fn nihao_is_hidden_but_still_dispatchable() {
        let cmd = Cli::command();
        let nihao = cmd
            .find_subcommand("nihao")
            .expect("nihao must remain a dispatchable subcommand");
        assert!(
            nihao.is_hide_set(),
            "nihao must stay hidden from help/completions"
        );
        for name in ["ping", "whoami"] {
            let sub = cmd
                .find_subcommand(name)
                .unwrap_or_else(|| panic!("{name} must remain a subcommand"));
            assert!(
                !sub.is_hide_set(),
                "{name} is a primary name and must stay visible"
            );
        }
        let cli = Cli::try_parse_from(["crbs", "nihao"]).expect("hidden nihao must still parse");
        assert!(
            matches!(cli, Cli::Nihao { .. }),
            "nihao dispatches to Cli::Nihao"
        );
        assert_eq!(
            cli.json_error_contract().map(|(name, _)| name.to_string()),
            Some("nihao".to_string()),
            "nihao JSON envelope name unchanged"
        );
    }

    // --- remote add: 参数解析 ---------------------------------------------

    /// remote add 字段解析：位置名 + --url 必给，token 三来源互斥（clap 层
    /// 拦截）；写入语义由 cmd::remote_profile 单元测试覆盖。
    #[test]
    fn remote_add_parses_fields() {
        let cli = Cli::try_parse_from([
            "crbs",
            "remote",
            "add",
            "prod",
            "--url",
            "https://hub.example.com",
            "--token-env",
            "CRBS_PROD_TOKEN",
            "--use-default",
        ])
        .expect("remote add should parse");
        match cli {
            Cli::Remote {
                command:
                    RemoteCommand::Add {
                        ref name,
                        ref url,
                        ref token_env,
                        ref token_file,
                        ref token,
                        ref ca_cert,
                        use_default,
                        ..
                    },
            } => {
                assert_eq!(name, "prod");
                assert_eq!(url, "https://hub.example.com");
                assert_eq!(token_env.as_deref(), Some("CRBS_PROD_TOKEN"));
                assert!(token_file.is_none() && token.is_none() && ca_cert.is_none());
                assert!(use_default);
            }
            other => panic!("expected Cli::Remote variant, got {other:?}"),
        }
    }

    /// token 三来源互斥由 clap 拦截（避免写出语义含糊的多鉴权字段 profile）。
    #[test]
    fn remote_add_token_sources_are_mutually_exclusive() {
        for extra in [
            vec!["--token-env", "V", "--token-file", "/tmp/t"],
            vec!["--token-env", "V", "--token", "sekret"],
            vec!["--token-file", "/tmp/t", "--token", "sekret"],
        ] {
            let mut argv: Vec<&str> = vec![
                "crbs",
                "remote",
                "add",
                "prod",
                "--url",
                "https://hub.example.com",
            ];
            argv.extend_from_slice(&extra);
            let err = Cli::try_parse_from(argv).expect_err("conflicting token sources");
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "unexpected clap error kind: {err}"
            );
        }
    }

    /// `remote test <profile>` 位置参数解析。
    #[test]
    fn remote_test_takes_profile_positional() {
        let cli = Cli::try_parse_from(["crbs", "remote", "test", "prod"])
            .expect("remote test should parse");
        match cli {
            Cli::Remote {
                command: RemoteCommand::Test { profile, .. },
            } => assert_eq!(profile, "prod"),
            other => panic!("expected Cli::Remote variant, got {other:?}"),
        }
    }
}
