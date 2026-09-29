// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! rpmbuild 阶段与日志：子阶段识别、SOURCE_DATE_EPOCH 与输出流式处理。

use crate::engine::backend::{BindMount, ContainerBackend, SpawnOptions, StdioKind};
use crate::engine::resource_sample::ResourceSampler;
use crate::error::{looks_like_network_failure, CrbsError};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};

/// 失败分类读 build.log 尾部的字节数；tail 未命中子阶段标记时，失败路径再对全文件流式扫描兜底。
const LOG_TAIL_CLASSIFY_BYTES: u64 = 256 * 1024;

/// 单次日志切块上限：构建进程可输出无限长无换行行（恶意/异常），read_until
/// 会把整行攒进内存直至 OOM。超限即切块返回（字节不丢，只是终端视图分段）。
const MAX_LOG_CHUNK_BYTES: usize = 256 * 1024;

/// 剥掉标记行可选的 `#` 前缀：pipeline 注入标记带 `#`，spec 插桩的 `CRBS_RPMBUILD_PHASE` 是 echo 输出、无前缀。
fn strip_marker_prefix(line: &str) -> &str {
    let trimmed = line.trim_start();
    match trimmed.strip_prefix('#') {
        Some(rest) => rest.trim_start(),
        None => trimmed,
    }
}

/// 流式读取 child 输出，按行写入 build.log；`terminal_tx`（bounded）尽力回传每行给
/// 上层实时视图：通道满 `try_send` 丢行（计数、结束 warn），消费端退出后停止回传。
/// 绝不 await send——读循环停摆会让子进程堵在管道写端、`wait()` 不再推进，卡死构建；
/// build.log 持久 sink 不能随终端视图一起停。
///
/// ponytail: 零丢行需读循环加"构建已结束"信号（cancel token 只覆盖取消路径）解除 send 等待；当前丢行计数 + warn 够用。
pub(crate) async fn stream_build_log<R>(
    reader: R,
    mut log_file: tokio::fs::File,
    mut terminal_tx: Option<tokio::sync::mpsc::Sender<String>>,
) where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf_reader = tokio::io::BufReader::new(reader);
    let mut raw = Vec::new();
    let mut dropped_lines = 0u64;
    loop {
        // 按字节读行而非 read_line：非法 UTF-8（Latin-1/二进制 echo）会令 read_line 返回
        // InvalidData 中断循环——读端 drop、构建进程 SIGPIPE 死、build.log 截断；坏字节以 U+FFFD 替换后继续流转。
        // 切块上限防无换行长行 OOM（见 MAX_LOG_CHUNK_BYTES）。
        match read_line_capped(&mut buf_reader, &mut raw).await {
            Ok(0) => break,
            Ok(_) => {
                // 终端回传与 build.log 都写 lossy 转换内容：build.log 恒为合法 UTF-8。
                let line = String::from_utf8_lossy(&raw).into_owned();
                if let Some(tx) = terminal_tx.as_ref() {
                    match tx.try_send(line.clone()) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            dropped_lines += 1;
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            // 消费端已退出：停止回传。
                            terminal_tx = None;
                        }
                    }
                }
                if let Err(e) = log_file.write_all(line.as_bytes()).await {
                    warn!(error = %e, "Failed to write build.log");
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to read build output");
                break;
            }
        }
    }
    if dropped_lines > 0 {
        warn!(
            dropped = dropped_lines,
            "Terminal log consumer stalled; dropped lines (build.log is complete)"
        );
    }
    // flush 确保"函数返回即全部写完"契约（末次写可能滞留 tokio File 内部缓冲），
    // 下游失败分类、日志读取都依赖。
    if let Err(e) = log_file.flush().await {
        warn!(error = %e, "Failed to flush build.log");
    }
}

/// 有界按行读取：语义同 `read_until(b'\n')`，但单次累计不超过
/// [`MAX_LOG_CHUNK_BYTES`]——无换行的长输出切成多块返回（字节不丢）。
async fn read_line_capped<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    out: &mut Vec<u8>,
) -> std::io::Result<usize> {
    out.clear();
    loop {
        let (take, done) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return Ok(out.len());
            }
            let limit = MAX_LOG_CHUNK_BYTES - out.len();
            let newline = available.iter().position(|&b| b == b'\n');
            let take = match newline {
                Some(i) => (i + 1).min(limit),
                None => limit.min(available.len()),
            };
            out.extend_from_slice(&available[..take]);
            let done = newline.is_some_and(|i| take == i + 1) || out.len() >= MAX_LOG_CHUNK_BYTES;
            (take, done)
        };
        reader.consume(take);
        if done {
            return Ok(out.len());
        }
    }
}

/// `run_script_phase` 的参数集合（避免函数签名参数过多）。
pub(crate) struct RunScriptArgs<'a> {
    pub(crate) backend: &'a dyn ContainerBackend,
    pub(crate) root: &'a Path,
    pub(crate) script: &'a str,
    pub(crate) build_log_file: &'a tokio::fs::File,
    /// 若提供（bounded），日志每行回传上层实时输出；停滞丢行，见 `stream_build_log`。
    pub(crate) terminal_tx: Option<tokio::sync::mpsc::Sender<String>>,
    pub(crate) cancel_token: &'a CancellationToken,
    pub(crate) build_start: Instant,
    pub(crate) build_timeout: Option<Duration>,
    pub(crate) network: bool,
    pub(crate) binds: Vec<BindMount>,
    /// nspawn 专用：machine name 后缀，避免并发构建共享 rootfs 时 cgroup 冲突。
    pub(crate) machine_name_suffix: Option<String>,
    /// 确定性模式：补 env 基线（TZ/哈希种子，LC_ALL 已有）+ hostname 钉死（nspawn `--hostname crbs-build`）。
    pub(crate) deterministic: bool,
    /// 回放模式同样钉死 hostname（值见 [`decide_container_hostname`]）：两次同模式构建自一致；仅 nspawn 消费（chroot 忽略）。
    pub(crate) pin_hostname: bool,
    /// 回放的源构建内核主机名（SRPM 头 BUILDHOST；非 det 源构建无宏钳制，头值
    /// 即源容器 `uname -n`）——回放钉同一值使抓 hostname 的包（pmix 类 configure）
    /// 源/回放一致。
    pub(crate) replay_build_host: Option<&'a str>,
    /// worker 真实主机名（容器 hostname 决策入参，见 [`decide_container_hostname`]）。
    pub(crate) worker_hostname: Option<&'a str>,
    /// 回放的 `SOURCE_DATE_EPOCH`（SRPM 头 BUILDTIME，epoch 秒）；Some 时注入 spawn env。
    /// rpmbuild 侧由 StepContext 再补 sudo env 前缀（env_reset 剥脚本环境）。
    pub(crate) source_date_epoch: Option<i64>,
    /// 构建级采样器（跨脚本 phase 累计）；None = 采样关闭（interval = 0）。
    pub(crate) resource_sampler: Option<&'a ResourceSampler>,
    /// tmpfs 观测目标（prepare 产出，构建级恒定；None = build_tmpfs 关闭 /
    /// 基线不可得，不采样 tmpfs）。
    pub(crate) tmpfs_watch: Option<&'a crate::engine::resource_sample::TmpfsWatch>,
}

/// 确定性模式下 rpm 进程可见的 `setting SOURCE_DATE_EPOCH=<n>` 行前缀：
/// rpm ≥4.14 changelog 推导 SDE 时输出（build/build.c），SDE 卫生检查据此提取锚点值。
pub(crate) const SOURCE_DATE_EPOCH_LOG_PREFIX: &str = "setting SOURCE_DATE_EPOCH=";

/// 从单行提取 `setting SOURCE_DATE_EPOCH=<n>` 的 `<n>`（纯函数，可注入测试）。
pub(crate) fn extract_source_date_epoch(line: &str) -> Option<i64> {
    let payload = strip_marker_prefix(line);
    let rest = payload.trim().strip_prefix(SOURCE_DATE_EPOCH_LOG_PREFIX)?;
    let num = rest.split_whitespace().next()?;
    num.parse::<i64>().ok()
}

/// 单行是否为 `setting SOURCE_DATE_EPOCH=<n>` 标记行，与值可否解析无关（非数字/溢出
/// i64 时同样返回 None）；卫生检查据此区分"无标记"与"值不可解析"，避免溢出误报宏未生效。
pub(crate) fn source_date_epoch_marker_present(line: &str) -> bool {
    strip_marker_prefix(line)
        .trim()
        .starts_with(SOURCE_DATE_EPOCH_LOG_PREFIX)
}

/// 确定性 env 基线（单一事实源，禁止别处复制字面量）：脚本头 export、rpmbuild
/// sudo env 前缀、spawn env BTreeMap、recipe.json env 块全部从此派生（顺序即注入
/// 顺序、字节稳定）。
pub(crate) const DETERMINISTIC_ENV_BASELINE: &[(&str, &str)] = &[
    ("TZ", "UTC"),
    ("PYTHONHASHSEED", "0"),
    ("PERL_HASH_SEED", "0"),
    ("PERL_PERTURB_KEYS", "0"),
];

/// `LC_ALL=C` 是无条件基线（非 deterministic 也注入），与确定性追加项分开常量。
pub(crate) const BASE_ENV_LOCALE: (&str, &str) = ("LC_ALL", "C");

/// 构建 SpawnOptions.env（纯函数可单测）：`BASE_ENV_LOCALE` 恒在；deterministic 追加
/// `DETERMINISTIC_ENV_BASELINE`（与 pipeline 脚本头同组同值，覆盖脚本 shell）；repro
/// 回放注入 `SOURCE_DATE_EPOCH`——SRPM 头 BUILDTIME 是时间宏组 epoch 来源，必须进脚本环境。
pub(crate) fn build_spawn_env(
    deterministic: bool,
    source_date_epoch: Option<i64>,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert(BASE_ENV_LOCALE.0.to_string(), BASE_ENV_LOCALE.1.to_string());
    if deterministic {
        for (k, v) in DETERMINISTIC_ENV_BASELINE {
            env.insert((*k).to_string(), (*v).to_string());
        }
    }
    if let Some(epoch) = source_date_epoch {
        env.insert("SOURCE_DATE_EPOCH".to_string(), epoch.to_string());
    }
    env
}

/// 确定性模式的容器 hostname 钉值（单一事实源）。
pub(crate) const DET_HOSTNAME: &str = "crbs-build";

/// 内核主机名上限（Linux HOST_NAME_MAX = 64，含结尾 NUL 前的 64 字节）。
const HOSTNAME_MAX_LEN: usize = 64;

/// nspawn `--hostname` 值合法性（priv-helper spawn.rs 同口径收口：非空、≤64、
/// 无 `/`、无 `..`、无空白/控制字符；priv-helper 拒绝的值在此先回落，避免构建
/// 期特权层报错）。
pub(crate) fn hostname_value_valid(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= HOSTNAME_MAX_LEN
        && !s.contains('/')
        && !s.contains("..")
        && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// worker 真实主机名（gethostname）：非 det 源构建的容器 hostname 钉值源。
/// 读取失败或值非法返回 `None`——容器回落 nspawn 默认（machine name），不阻断。
pub(crate) fn worker_hostname() -> Option<String> {
    let name = nix::unistd::gethostname().ok()?;
    let name = name.to_string_lossy().into_owned();
    hostname_value_valid(&name).then_some(name)
}

/// 容器内核主机名决策（纯函数，nspawn `--hostname` 消费）：
/// - **deterministic**（det 源构建与 det 回放）：钉 [`DET_HOSTNAME`]，语义
///   不变，RPM 头 BUILDHOST 由 `_buildhost` 宏钳制、与内核主机名解耦；
/// - **非 det 回放**（pin_hostname）：钉源构建内核主机名 = SRPM 头 BUILDHOST
///   （非 det 源构建无宏钳制，rpmbuild 头值即源容器 `uname -n`）；回放侧抓
///   hostname 的包（pmix 类 configure 用 `uname -n`）与源构建一致；无 host 锚
///   （头缺 BUILDHOST）回落 worker 主机名；
/// - **非 det 源构建**：钉 worker 真实主机名，同 worker 确定一致、跨回放可
///   对齐（头 BUILDHOST 记下该值供回放钉回），并与 chroot 后端的容器主机名
///   （宿主主机名）同口径。nspawn 默认 machine name = rootfs 随机 tempdir
///   路径哈希，抓 `uname -n` 的包（pmix 类 configure）拿到的是随机值，钉值避开。
///
/// 非法值（[`hostname_value_valid`] 拒绝）按 `None` 处理逐级回落，最终 `None`
/// = 不传 `--hostname`（nspawn 默认 machine name，不阻断构建）。
pub(crate) fn decide_container_hostname(
    deterministic: bool,
    pin_hostname: bool,
    replay_build_host: Option<&str>,
    worker_hostname: Option<&str>,
) -> Option<String> {
    let valid = |s: &str| hostname_value_valid(s).then(|| s.to_string());
    if deterministic {
        return Some(DET_HOSTNAME.to_string());
    }
    if pin_hostname {
        // 头 BUILDHOST 非法（外来 SRPM 可写任意头值）：按缺锚处理，回落 worker 主机名。
        if let Some(replay) = replay_build_host.filter(|v| hostname_value_valid(v)) {
            return Some(replay.to_string());
        }
    }
    worker_hostname.and_then(valid)
}

pub(crate) async fn run_script_phase(args: RunScriptArgs<'_>) -> crate::Result<()> {
    let env = build_spawn_env(args.deterministic, args.source_date_epoch);
    let opts = SpawnOptions {
        user: None,
        env,
        network: args.network,
        process_group: true,
        stdin: StdioKind::Null,
        stdout: StdioKind::Piped,
        stderr: StdioKind::Piped,
        binds: args.binds,
        machine_name_suffix: args.machine_name_suffix,
        hostname: decide_container_hostname(
            args.deterministic,
            args.pin_hostname,
            args.replay_build_host,
            args.worker_hostname,
        ),
    };
    let mut spawned = args.backend.spawn(args.root, &[args.script], &opts).await?;

    // pgid == pid（process_group: true）。`Child::id()` reap 后返回 None，而 reap
    // 后仍需 kill 持管道写端的幸存孙进程，故先捕获。
    let child_pid = spawned.child.id();
    // future 被 abort/drop（poller 总预算、shutdown）时 kill_on_drop 只杀直接
    // 子进程，孙进程会活到 cleanup_guard 拆 rootfs 之后；Drop guard 按 pgid
    // 补刀。正常收尾路径在下方统一 kill 后 disarm，避免误杀复用组。
    let mut pg_guard = PgKillGuard::new(child_pid);

    // 采样口径：cgroup payload 有 → cgroup v2；payload 缺而 nspawn v1（machine
    // 名在场）→ /proc 口径按 machine scope 子树归属；chroot → /proc pgid 匹配。
    // 口径间隔为 0（关闭）时本 phase 不采样。
    let sample_task = match (args.resource_sampler, child_pid) {
        // child_pid 为 None = 已被 reap，无从采样。
        (Some(sampler), Some(pid)) => sampler.spawn_phase(
            pid,
            spawned.cgroup_payload_path(),
            spawned.v1_scope_machine_name(),
            Path::new("/proc"),
            args.tmpfs_watch,
        ),
        _ => None,
    };

    // post-spawn 错误路径子进程仍在跑：先 kill 进程组并限时回收再 return，不给调用方留下活进程容器。
    let stdout = match spawned.child.stdout.take() {
        Some(s) => s,
        None => {
            kill_and_reap(&mut spawned, child_pid).await;
            return Err(CrbsError::io_message("stdout not piped"));
        }
    };
    let stderr = match spawned.child.stderr.take() {
        Some(s) => s,
        None => {
            kill_and_reap(&mut spawned, child_pid).await;
            return Err(CrbsError::io_message("stderr not piped"));
        }
    };

    let stdout_log = clone_log_fd(&mut spawned, child_pid, args.build_log_file).await?;
    let stderr_log = clone_log_fd(&mut spawned, child_pid, args.build_log_file).await?;

    let stdout_handle = tokio::spawn(stream_build_log(
        stdout,
        stdout_log,
        args.terminal_tx.clone(),
    ));
    let stderr_handle = tokio::spawn(stream_build_log(
        stderr,
        stderr_log,
        args.terminal_tx.clone(),
    ));

    /// 脚本运行结果：循环里只记录结果与退出码，失败分类延后到日志流 join 之后（见下）。
    enum Outcome {
        Success,
        ScriptFailed {
            exit_code: Option<i32>,
        },
        Cancelled,
        TimedOut,
        /// wait() 本身失败（子进程状态未知）：kill 进程组后以该错误返回。
        WaitFailed(CrbsError),
    }

    #[allow(clippy::never_loop)]
    let outcome = loop {
        let remaining = args
            .build_timeout
            .map(|t| t.saturating_sub(args.build_start.elapsed()));

        // biased：完成与超时/取消同时就绪时记真实退出而非 Timeout/Cancelled（完成优先）；
        // 进程仍在跑则 wait 未就绪、到期超时照常命中。不抽小包装的原因见 tests 模块头部。
        tokio::select! {
            biased;
            status = spawned.child.wait() => {
                match status {
                    Ok(status) if status.success() => break Outcome::Success,
                    Ok(status) => {
                        // 脚本可能含敏感信息（token/内部 URL/GPG 配置）：只记路径不打印内容。
                        warn!(script = %args.script, "Script failed; see build.log for details");
                        break Outcome::ScriptFailed { exit_code: status.code() };
                    }
                    // select 分支内不能再借用 spawned，kill 延后到循环外统一做。
                    Err(e) => {
                        break Outcome::WaitFailed(CrbsError::from_io_context("wait script", e))
                    }
                }
            }
            _ = args.cancel_token.cancelled() => {
                break Outcome::Cancelled;
            }
            _ = async {
                match remaining {
                    Some(d) if d.is_zero() => {}
                    Some(d) => tokio::time::sleep(d).await,
                    None => std::future::pending().await,
                }
            } => {
                break Outcome::TimedOut;
            }
        }
    };

    match &outcome {
        // 取消/超时/wait 失败：子进程未必已终止，kill 进程组后限时 reap。
        Outcome::Cancelled | Outcome::TimedOut | Outcome::WaitFailed(_) => {
            kill_and_reap(&mut spawned, child_pid).await;
        }
        // 直接子进程已 reap，但孙进程可能仍持继承的管道写端：日志流读不到 EOF、
        // join 必超时，幸存者还阻碍 teardown umount。专属 pgid（process_group: true）
        // 下整组无条件 SIGKILL 安全——直接子进程已死，只有幸存者收到信号。
        Outcome::Success | Outcome::ScriptFailed { .. } => {
            crate::engine::kill_process_tree(&spawned, child_pid).await;
        }
    }
    pg_guard.disarm();

    // 先 join 日志流再做失败分类：管道最后的错误行必须已写入 build.log，否则分类
    // 概率化。上方 SIGKILL 已保证写端全关、流正常 EOF，5s 超时仅兜底。
    if let Err(e) = tokio::time::timeout(Duration::from_secs(5), stdout_handle).await {
        warn!(error = %e, "stdout log stream handle did not finish cleanly");
    }
    if let Err(e) = tokio::time::timeout(Duration::from_secs(5), stderr_handle).await {
        warn!(error = %e, "stderr log stream handle did not finish cleanly");
    }

    // 资源采样收尾（非致命）：先发停止信号（不吃满采样间隔）再限时 join；cgroup
    // 口径 memory.peak 兜底读在收尾内完成。样本已累计进构建级状态，失败只损失样本。
    if let Some((sample_handle, sample_stop)) = sample_task {
        sample_stop.notify_one();
        if let Err(e) = tokio::time::timeout(Duration::from_secs(5), sample_handle).await {
            warn!(error = %e, "resource sampler did not finish in time; keeping collected samples");
        }
    }

    match outcome {
        Outcome::Success => Ok(()),
        Outcome::Cancelled => Err(CrbsError::Cancelled),
        Outcome::TimedOut => Err(CrbsError::Timeout),
        Outcome::WaitFailed(e) => Err(e),
        Outcome::ScriptFailed { exit_code } => {
            Err(classify_script_failure(args.script, args.build_log_file, exit_code).await)
        }
    }
}

/// abort/drop 时的进程组补刀 guard：正常收尾 disarm；未 disarm 即按 pgid
/// SIGKILL（child 尚未 reap 时 pgid 不会被复用）。
struct PgKillGuard {
    pid: Option<u32>,
    armed: bool,
}

impl PgKillGuard {
    fn new(pid: Option<u32>) -> Self {
        Self { pid, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PgKillGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Some(pid) = self.pid.and_then(|p| i32::try_from(p).ok()) else {
            return;
        };
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
}

/// kill 后复核结论（纯函数）：`try_wait` 只认阳性存活证据——`Ok(None)` 仍
/// 活须升级；`Ok(Some(_))` 已退出；`Err`（OS 级异常）状态不明，按已死处理
/// 不升级（升级 kill 是额外火力，误报会掩盖真实收敛路径的噪声）。
enum KillRecheck {
    Dead,
    Alive,
}

/// 复核判活后的升级终局动作。
enum KillEscalation {
    /// 复核判死（或状态不明按已死）：收敛，不再升级。
    Converged,
    /// machine 名已知：施放 terminate-machine 后再复核。
    TerminateMachine,
    /// 无 machine 名（chroot / 注册降级）：无 scope 可指向，直落人工清理出口。
    ManualCleanup,
}

/// kill 升级终局决策（纯函数，单测锚点）：复核三态 × machine 名有无——判死
/// 收敛；判活且有 machine 名升级 terminate-machine；判活而无 machine 名无可
/// 指向的 scope，硬升级无从谈起，直接人工清理。
fn decide_kill_escalation(
    recheck: &std::io::Result<Option<std::process::ExitStatus>>,
    machine_known: bool,
) -> KillEscalation {
    match classify_kill_recheck(recheck) {
        KillRecheck::Dead => KillEscalation::Converged,
        KillRecheck::Alive if machine_known => KillEscalation::TerminateMachine,
        KillRecheck::Alive => KillEscalation::ManualCleanup,
    }
}

fn classify_kill_recheck(
    status: &std::io::Result<Option<std::process::ExitStatus>>,
) -> KillRecheck {
    match status {
        Ok(None) => KillRecheck::Alive,
        Ok(Some(_)) | Err(_) => KillRecheck::Dead,
    }
}

/// kill 进程组并限时回收：post-spawn 错误 / 取消 / 超时路径共用兜底。升级链
/// 依次施加：cgroup 候选 + 进程组 SIGKILL（首轮 / 穷尽轮）→ terminate-machine
///（machine 名已知时；cgroup v2 写 scope cgroup.kill，v1 按 scope 成员 SIGKILL），
/// 每级之间有界复核，全手段用尽未收敛才 error! 留人工清理信息（machine 名 +
/// scope 候选路径 + `machinectl terminate` 提示）。
async fn kill_and_reap(spawned: &mut crate::engine::backend::SpawnedChild, pid: Option<u32>) {
    crate::engine::kill_process_tree(spawned, pid).await;
    let recheck = bounded_recheck(spawned).await;
    if !matches!(classify_kill_recheck(&recheck), KillRecheck::Alive) {
        return;
    }
    error!(
        pid = ?pid.or_else(|| spawned.child.id()),
        machine = ?spawned.machine_name(),
        "Build child survived first kill (cgroup candidates + process group); \
         applying exhaustive kill — if it remains alive, terminate manually \
         (nspawn: `machinectl terminate <machine>`)"
    );
    crate::engine::kill_process_tree_exhaustive(spawned, pid).await;
    let recheck = bounded_recheck(spawned).await;
    let machine_known = spawned.machine_name().is_some();
    match decide_kill_escalation(&recheck, machine_known) {
        KillEscalation::Converged => return,
        KillEscalation::TerminateMachine => {
            // machine 级兜底：精确指向 machined 注册的 scope（machine 名由 spawn
            // 侧携带，与 cgroup 版本无关——v1 宿主上 cgroup.kill 候选与进程组
            // SIGKILL 两路全废，靠这一级收敛）。
            if let Some(name) = spawned.machine_name().map(str::to_string) {
                error!(
                    machine = %name,
                    "exhaustive kill insufficient; terminating the nspawn machine \
                     via privilege layer"
                );
                crate::engine::terminate_machine_via_privilege(&name).await;
                let recheck = bounded_recheck(spawned).await;
                if !matches!(classify_kill_recheck(&recheck), KillRecheck::Alive) {
                    return;
                }
            }
        }
        KillEscalation::ManualCleanup => {}
    }
    error!(
        pid = ?pid.or_else(|| spawned.child.id()),
        machine = ?spawned.machine_name(),
        scope_candidates = ?spawned.machine_scope_hints(),
        "Build child still alive after all kill escalations; manual cleanup required \
         (nspawn: `machinectl terminate <machine>`; chroot: kill the process group by pid)"
    );
}

/// kill 后有界复核（5s 窗口 + `try_wait` 定夺），返回原始三态交
/// [`decide_kill_escalation`]：窗口内退出 → `Ok(Some(_))`；耗尽仍运行 →
/// `Ok(None)`；`Child::wait` 幂等，等待结束后 `try_wait` 即真实状态。
async fn bounded_recheck(
    spawned: &mut crate::engine::backend::SpawnedChild,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    let _ = tokio::time::timeout(Duration::from_secs(5), spawned.child.wait()).await;
    spawned.child.try_wait()
}

/// post-spawn try_clone build.log fd（stdout/stderr 两路日志共用）：失败即 kill
/// 回收子进程再上抛（不留活进程容器）。
async fn clone_log_fd(
    spawned: &mut crate::engine::backend::SpawnedChild,
    pid: Option<u32>,
    log_file: &tokio::fs::File,
) -> crate::Result<tokio::fs::File> {
    match log_file.try_clone().await {
        Ok(f) => Ok(f),
        Err(e) => {
            kill_and_reap(spawned, pid).await;
            Err(CrbsError::from_io_context("clone build.log fd", e))
        }
    }
}

/// 脚本失败最终分类：读 build.log 尾部提取 phase/subphase/reason/network，tail 未命中时
/// 全文件流式扫描兜底；必须在日志流句柄 join 之后调用，否则尾部不完整。
async fn classify_script_failure(
    script: &str,
    log_file: &tokio::fs::File,
    exit_code: Option<i32>,
) -> CrbsError {
    let tail = match read_tail(log_file, LOG_TAIL_CLASSIFY_BYTES).await {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, "Failed to read build.log tail for failure classification");
            String::new()
        }
    };
    let mut classified = classify_build_log_tail(&tail);
    // tail 定位不到失败子阶段时全文件扫描兜底（%build 啰嗦输出把标记推出 256KB 窗口），
    // 恢复 phase/subphase；subphase 为空即覆盖全部待兜底情形（仅 tail phase 为 build 时非空）。
    if classified.subphase.is_none() {
        match scan_rpmbuild_subphase(log_file).await {
            Ok((phase, subphase)) => {
                // 全文件是 tail 的超集，恢复值总是不少于 tail 扫描结果。
                classified.phase = phase;
                classified.subphase = subphase;
            }
            Err(e) => {
                warn!(error = %e, "Failed to scan build.log for rpmbuild subphase")
            }
        }
    }
    if let Some(arch_line) = classified.arch_unsupported {
        // 架构不兼容是请求级错误（调整 --arch 或修 spec 即可重提），归
        // ValidationFailed（exit 4）而非环境类 io 错（exit 6），并把 rpm 原文
        // 带出 CLI 汇总。
        CrbsError::ValidationFailed {
            message: format!(
                "script {} failed: exit_code={:?}: {}",
                script, exit_code, arch_line
            ),
        }
    } else if classified.network {
        CrbsError::Network {
            message: format!(
                "script {} failed: exit_code={:?} (network error detected in build.log tail)",
                script, exit_code
            ),
        }
    } else {
        let mut detail = format!("script {} failed: exit_code={:?}", script, exit_code);
        if let Some(p) = classified.phase {
            detail.push_str(&format!("; phase={}", p));
        }
        if let Some(sp) = classified.subphase {
            detail.push_str(&format!("; subphase={}", sp));
        }
        if let Some(r) = classified.reason {
            detail.push_str(&format!("; reason={}", r));
        }
        CrbsError::io_message(detail)
    }
}

/// 脚本失败时从 build.log 尾部提取的失败定位信息：`phase` 取最后出现的
/// `CRBS_PHASE_START <name>` 标记；`subphase` 仅 build 阶段提取（最后一个
/// `CRBS_RPMBUILD_PHASE` 标记，无标记回退原生 `Executing(%<name>)`）；`reason` 取
/// 匹配关键词的最后一行（≤200 字符）；`network` 为 true 归类网络错误。
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ClassifiedFailure {
    pub(crate) phase: Option<String>,
    pub(crate) subphase: Option<String>,
    pub(crate) reason: Option<String>,
    pub(crate) network: bool,
    /// rpmbuild 架构裁决命中行（`Architecture is excluded/not included`）。
    /// 命中时整个失败归类为 `ValidationFailed`（用户可修正：调整 --arch 或修
    /// spec），区别于环境类 io 错误。best-effort：文案漂移即不命中，回退原路径。
    pub(crate) arch_unsupported: Option<String>,
}

/// 从单行提取 rpmbuild 子阶段名（插桩标记或原生 `Executing(%<name>)`）；不匹配返回 None。
fn extract_rpmbuild_subphase(line: &str) -> Option<String> {
    let payload = strip_marker_prefix(line);
    if let Some(rest) = payload.strip_prefix("CRBS_RPMBUILD_PHASE ") {
        return rest.split_whitespace().next().map(str::to_string);
    }
    // 回退：rpmbuild 原生输出，如 `Executing(%check): /bin/sh -e /var/tmp/rpm-tmp.XXX`
    let rest = payload.strip_prefix("Executing(%")?;
    let end = rest.find(')')?;
    let name = &rest[..end];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// 从 build.log 尾部文本分类失败阶段与原因（纯函数，可注入测试）。
pub(crate) fn classify_build_log_tail(tail: &str) -> ClassifiedFailure {
    // 单次前向扫描：跟踪最后一个 CRBS_PHASE_START 及其后子阶段标记；子阶段仅在
    // 最后 phase 为 build 时有效，避免 build 后失败的步骤（如 ccache-summary）误报残留 marker。
    let mut phase = None;
    let mut subphase = None;
    for line in tail.lines() {
        let payload = strip_marker_prefix(line);
        if let Some(rest) = payload.strip_prefix("CRBS_PHASE_START ") {
            phase = rest.split_whitespace().next().map(str::to_string);
            subphase = None;
            continue;
        }
        if let Some(sp) = extract_rpmbuild_subphase(line) {
            subphase = Some(sp);
        }
    }
    if phase.as_deref() != Some("build") {
        subphase = None;
    }

    let mut reason = None;
    let mut network = false;
    let mut arch_unsupported = None;
    for line in tail.lines().rev() {
        // 架构裁决优先判定：命中行必含 "error: "，会被下方通用关键词抢先命中，
        // 丢失 ValidationFailed 归类机会。
        if ARCH_UNSUPPORTED_PATTERNS.iter().any(|k| line.contains(k)) {
            let clipped: String = line.trim().chars().take(200).collect();
            arch_unsupported = Some(clipped.clone());
            reason = Some(clipped);
            break;
        }
        let lower = line.to_lowercase();
        let matched = if looks_like_network_failure(line) {
            network = true;
            true
        } else {
            DEPS_FAILURE_KEYWORDS.iter().any(|k| lower.contains(k))
                || BUILD_FAILURE_KEYWORDS.iter().any(|k| lower.contains(k))
        };
        if matched {
            let trimmed = line.trim();
            reason = Some(trimmed.chars().take(200).collect());
            break;
        }
    }

    ClassifiedFailure {
        phase,
        subphase,
        reason,
        network,
        arch_unsupported,
    }
}

/// 全文件流式扫描 phase 与 rpmbuild 子阶段标记（tail 窗口未命中时的兜底），内存恒定：
/// 逐行读取、只保留最后匹配。语义与 `classify_build_log_tail` 一致——subphase 只在
/// 最后 phase 为 build 时有效，`Executing(%<name>)` 回退同理。
pub(crate) async fn scan_rpmbuild_subphase(
    log_file: &tokio::fs::File,
) -> std::io::Result<(Option<String>, Option<String>)> {
    let mut file = log_file.try_clone().await?;
    file.seek(std::io::SeekFrom::Start(0)).await?;
    let mut reader = tokio::io::BufReader::new(file);
    let mut line = String::new();
    let mut phase: Option<String> = None;
    let mut subphase: Option<String> = None;
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        let payload = strip_marker_prefix(&line);
        if let Some(rest) = payload.strip_prefix("CRBS_PHASE_START ") {
            phase = rest.split_whitespace().next().map(str::to_string);
            subphase = None;
            continue;
        }
        if let Some(sp) = extract_rpmbuild_subphase(&line) {
            subphase = Some(sp);
        }
    }
    if phase.as_deref() == Some("build") {
        Ok((phase, subphase))
    } else {
        Ok((phase, None))
    }
}

/// install-deps 阶段失败关键词（dnf builddep 报错特征）。
const DEPS_FAILURE_KEYWORDS: &[&str] = &[
    "no match for argument",
    "unable to find a match",
    "nothing to do",
    "package does not exist",
    "no package matched",
];

/// rpmbuild 阶段失败关键词。
const BUILD_FAILURE_KEYWORDS: &[&str] = &[
    "rpm build errors",
    "no space left on device",
    "error: ",
    "error(",
];

/// rpmbuild 架构裁决文案（spec 解析期，`--target` 与 ExclusiveArch/ExcludeArch
/// 不兼容即退出）。best-effort 识别：文案随 rpm 版本漂移时退化为通用 io 路径
/// （不构成回归）；钉 rpm 6.0.2 实测文案。
const ARCH_UNSUPPORTED_PATTERNS: &[&str] =
    &["Architecture is excluded", "Architecture is not included"];

/// 从打开的 build.log fd 读尾部 `max_bytes`（seek 到末尾再回退）。
pub(crate) async fn read_tail(
    log_file: &tokio::fs::File,
    max_bytes: u64,
) -> std::io::Result<String> {
    let len = log_file.metadata().await?.len();
    let start = len.saturating_sub(max_bytes);
    let mut buf = vec![0u8; (len - start) as usize];
    let mut file = log_file.try_clone().await?;
    file.seek(std::io::SeekFrom::Start(start)).await?;
    file.read_exact(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::backend::SpawnedChild;

    // 刻意豁免：三臂 biased select 不抽可单测包装——两 future 形态会把 cancel 与
    // 到期超时同时就绪的归属从 Cancelled 翻成 Timeout（行为变化），`std::future::ready`
    // 双就绪断言需包装体才可写。重构出可测缝时优先补"完成+超时双就绪→完成胜出"测试再消豁免。

    /// 无换行超长行必须切块返回（内存有界），字节流完整且最终 EOF 归零。
    #[tokio::test]
    async fn read_line_capped_splits_unterminated_long_line() {
        let total = MAX_LOG_CHUNK_BYTES * 2 + 5;
        let data = vec![b'x'; total];
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let mut out = Vec::new();
        let mut chunks = Vec::new();
        loop {
            let n = read_line_capped(&mut reader, &mut out).await.unwrap();
            if n == 0 {
                break;
            }
            assert!(n <= MAX_LOG_CHUNK_BYTES, "chunk must be bounded");
            chunks.extend_from_slice(&out);
        }
        assert_eq!(chunks.len(), total);
        assert_eq!(chunks, data);
    }

    /// Mock backend：spawn 真实长命进程但违反 Piped 契约（stdout 接 null）触发 post-spawn 错误路径；记录 pid 供断言 kill/reap。
    #[derive(Debug)]
    struct NoStdoutBackend {
        spawned_pid: std::sync::Arc<std::sync::Mutex<Option<u32>>>,
    }

    #[async_trait::async_trait]
    impl ContainerBackend for NoStdoutBackend {
        fn name(&self) -> &str {
            "mock-no-stdout"
        }

        fn available(&self) -> bool {
            true
        }

        async fn spawn(
            &self,
            _rootfs: &Path,
            command: &[&str],
            opts: &SpawnOptions,
        ) -> crate::Result<SpawnedChild> {
            let mut parts = command[0].split_whitespace();
            let mut cmd = tokio::process::Command::new(parts.next().unwrap_or("sleep"));
            cmd.args(parts);
            crate::engine::backend::apply_spawn_opts(&mut cmd, opts);
            cmd.stdout(std::process::Stdio::null());
            let child = cmd.spawn().map_err(CrbsError::from)?;
            *self.spawned_pid.lock().unwrap() = child.id();
            Ok(SpawnedChild::new(child))
        }

        async fn shell(
            &self,
            _rootfs: &Path,
            _command: Option<&str>,
            _opts: &SpawnOptions,
        ) -> crate::Result<std::process::ExitStatus> {
            Err(CrbsError::io_message("shell not supported by mock backend"))
        }
    }

    /// 回归：post-spawn 错误返回前子进程必须已被 kill/reap（不留活进程给调用方 teardown）。
    #[tokio::test]
    async fn post_spawn_error_kills_child() {
        let spawned_pid = std::sync::Arc::new(std::sync::Mutex::new(None));
        let backend = NoStdoutBackend {
            spawned_pid: spawned_pid.clone(),
        };
        let tmp = tempfile::tempdir().unwrap();
        let log = tokio::fs::File::create(tmp.path().join("build.log"))
            .await
            .unwrap();
        let cancel = CancellationToken::new();

        let err = run_script_phase(RunScriptArgs {
            backend: &backend,
            root: tmp.path(),
            script: "/bin/sleep 60",
            build_log_file: &log,
            terminal_tx: None,
            cancel_token: &cancel,
            build_start: Instant::now(),
            build_timeout: Some(Duration::from_secs(30)),
            network: true,
            binds: vec![],
            machine_name_suffix: None,
            deterministic: false,
            pin_hostname: false,
            replay_build_host: None,
            worker_hostname: None,
            source_date_epoch: None,
            resource_sampler: None,
            tmpfs_watch: None,
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("stdout not piped"));

        // 已 kill 且被 reap 的子进程：kill(pid, 0) 探测应报错（ESRCH）。
        let pid = spawned_pid.lock().unwrap().expect("child was spawned");
        let probed = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None);
        assert!(
            probed.is_err(),
            "post-spawn error must not leave a live child behind"
        );
    }

    /// 复核决策三态：Ok(None) 仍活升级；Ok(Some) 已死；Err 状态不明按已死不升级。
    #[test]
    fn classify_kill_recheck_requires_positive_alive_evidence() {
        #[cfg(unix)]
        fn exited() -> std::process::ExitStatus {
            // WIFEXITED(0) 的原始 wait 状态（exit 0）。
            std::os::unix::process::ExitStatusExt::from_raw(0)
        }
        #[cfg(not(unix))]
        fn exited() -> std::process::ExitStatus {
            std::process::Command::new("cmd")
                .args(["/C", "exit", "0"])
                .status()
                .unwrap()
        }

        assert!(matches!(
            classify_kill_recheck(&Ok(None)),
            KillRecheck::Alive
        ));
        assert!(matches!(
            classify_kill_recheck(&Ok(Some(exited()))),
            KillRecheck::Dead
        ));
        let probe_err = Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert!(matches!(
            classify_kill_recheck(&probe_err),
            KillRecheck::Dead
        ));
    }

    /// 升级终局决策矩阵：复核三态 × machine 名有无——判死（含状态不明按已死）
    /// 收敛，与 machine 名无关；判活 + 有名升级 terminate-machine；判活 + 无名
    ///（chroot / 注册降级）直落人工清理，不给 chroot 打 nspawn 级手段。
    #[test]
    fn decide_kill_escalation_matrix() {
        #[cfg(unix)]
        fn exited() -> std::process::ExitStatus {
            // WIFEXITED(0) 的原始 wait 状态（exit 0）。
            std::os::unix::process::ExitStatusExt::from_raw(0)
        }
        #[cfg(not(unix))]
        fn exited() -> std::process::ExitStatus {
            std::process::Command::new("cmd")
                .args(["/C", "exit", "0"])
                .status()
                .unwrap()
        }

        let dead: std::io::Result<Option<std::process::ExitStatus>> = Ok(Some(exited()));
        let alive: std::io::Result<Option<std::process::ExitStatus>> = Ok(None);
        let unknown: std::io::Result<Option<std::process::ExitStatus>> =
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));

        for recheck in [&dead, &unknown] {
            assert!(matches!(
                decide_kill_escalation(recheck, true),
                KillEscalation::Converged
            ));
            assert!(matches!(
                decide_kill_escalation(recheck, false),
                KillEscalation::Converged
            ));
        }
        assert!(matches!(
            decide_kill_escalation(&alive, true),
            KillEscalation::TerminateMachine
        ));
        assert!(matches!(
            decide_kill_escalation(&alive, false),
            KillEscalation::ManualCleanup
        ));
    }

    /// 回归：非法 UTF-8（Latin-1/二进制 echo）不得中断读循环——read_line 会因
    /// InvalidData 中断并截断 build.log；坏字节行以 U+FFFD 落盘，后续行继续。
    #[tokio::test]
    async fn stream_build_log_survives_non_utf8_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("build.log");
        let log_file = tokio::fs::File::create(&log_path).await.unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        // \xff\xfe 是非法 UTF-8 序列。
        let reader = std::io::Cursor::new(b"line one\n\xff\xfe bad bytes\nline three\n".to_vec());
        stream_build_log(reader, log_file, Some(tx)).await;

        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3, "all three lines must reach build.log");
        assert_eq!(lines[0], "line one");
        assert!(
            lines[1].contains('\u{FFFD}'),
            "bad bytes must be lossy-replaced, not truncate the log: {lines:?}"
        );
        assert_eq!(lines[2], "line three");

        // 函数返回后 sender 已随其 Drop 关闭：drain 通道应收到全部三行。
        let mut received = Vec::new();
        while let Some(l) = rx.recv().await {
            received.push(l);
        }
        assert_eq!(received.len(), 3, "terminal channel must receive all lines");
        assert!(received[1].contains('\u{FFFD}'));
    }

    #[test]
    fn classify_detects_install_deps_failure() {
        let tail = "# CRBS_PHASE_START install-deps 1718723456.000000000\n\
                    Last metadata expiration check: 0:00:01 ago\n\
                    No match for argument: python3-devel\n";
        let c = classify_build_log_tail(tail);
        assert_eq!(c.phase.as_deref(), Some("install-deps"));
        assert_eq!(c.subphase, None);
        assert!(c.reason.unwrap().contains("No match for argument"));
        assert!(!c.network);
    }

    #[test]
    fn classify_detects_build_failure() {
        let tail = "# CRBS_PHASE_START install-deps 1718723456.000000000\n\
                    # CRBS_PHASE_START build 1718723456.500000000\n\
                    gcc: error: file.c: No such file\n\
                    RPM build errors:\n";
        let c = classify_build_log_tail(tail);
        assert_eq!(
            c.phase.as_deref(),
            Some("build"),
            "must pick last phase marker"
        );
        assert!(c.reason.unwrap().contains("RPM build errors"));
    }

    #[test]
    fn classify_detects_network_failure() {
        let tail = "# CRBS_PHASE_START install-deps 1718723456.000000000\n\
                    Failed to connect to repo.example.com: connection timed out\n";
        let c = classify_build_log_tail(tail);
        assert!(c.network);
        assert!(c.reason.unwrap().contains("connection timed out"));
    }

    #[test]
    fn classify_extracts_subphase_from_injected_marker() {
        let tail = "# CRBS_PHASE_START build 1718723456.500000000\n\
                    CRBS_RPMBUILD_PHASE prep 1718723456.600000000\n\
                    prep output\n\
                    CRBS_RPMBUILD_PHASE build 1718723457.000000000\n\
                    CRBS_RPMBUILD_PHASE check 1718723460.000000000\n\
                    error: Bad exit status from /var/tmp/rpm-tmp.xyz (%check)\n";
        let c = classify_build_log_tail(tail);
        assert_eq!(c.phase.as_deref(), Some("build"));
        assert_eq!(c.subphase.as_deref(), Some("check"));
    }

    #[test]
    fn classify_subphase_falls_back_to_executing_lines() {
        // 旧日志（未插桩）只有 rpmbuild 原生 Executing(%...) 输出
        let tail = "# CRBS_PHASE_START build 1718723456.500000000\n\
                    Executing(%prep): /bin/sh -e /var/tmp/rpm-tmp.aaa\n\
                    + umask 022\n\
                    Executing(%build): /bin/sh -e /var/tmp/rpm-tmp.bbb\n\
                    make: *** [Makefile:5: all] Error 1\n\
                    RPM build errors:\n";
        let c = classify_build_log_tail(tail);
        assert_eq!(c.phase.as_deref(), Some("build"));
        assert_eq!(c.subphase.as_deref(), Some("build"));
    }

    #[test]
    fn classify_ignores_subphase_when_failure_after_build_phase() {
        // build 成功、ccache-summary 失败：残留的 build 子阶段 marker 不得误报失败位置。
        let tail = "# CRBS_PHASE_START build 1718723456.500000000\n\
                    CRBS_RPMBUILD_PHASE check 1718723460.000000000\n\
                    # CRBS_PHASE_END build 0 1718723470.000000000\n\
                    # CRBS_PHASE_START ccache-summary 1718723470.100000000\n\
                    error: ccache failed\n";
        let c = classify_build_log_tail(tail);
        assert_eq!(c.phase.as_deref(), Some("ccache-summary"));
        assert_eq!(c.subphase, None);
    }

    #[test]
    fn classify_no_subphase_for_non_build_phase() {
        let tail = "# CRBS_PHASE_START install-deps 1718723456.000000000\n\
                    No match for argument: python3-devel\n";
        let c = classify_build_log_tail(tail);
        assert_eq!(c.phase.as_deref(), Some("install-deps"));
        assert_eq!(c.subphase, None);
    }

    /// 回归：dnf 事务摘要行里包名裸词 curl 不得让反向扫描误判 Network——否则
    /// 确定性失败（GPG 公钥缺失）被当可重试网络错误虚假重建。
    #[test]
    fn classify_does_not_flag_network_for_curl_pkg_in_deps_summary() {
        let tail = "# CRBS_PHASE_START install-deps 1718723456.000000000\n\
                    Installing dependencies: curl libcurl\n\
                    Public key for curl-8.4.0.rpm is not installed\n";
        let c = classify_build_log_tail(tail);
        assert!(!c.network);
        assert_eq!(c.reason, None);
    }

    /// 架构裁决命中：ExcludeArch 文案（rpm 6.0.2 实测）。命中行含 "error: "，必须
    /// 走专属分支而非被通用关键词抢先——reason 与 arch_unsupported 同源即证明。
    #[test]
    fn classify_detects_arch_excluded() {
        let tail = "# CRBS_PHASE_START build 1718723456.500000000\n\
                    error: Architecture is excluded: x86_64\n";
        let c = classify_build_log_tail(tail);
        let arch = c.arch_unsupported.expect("must flag arch unsupported");
        assert!(arch.contains("Architecture is excluded: x86_64"));
        assert_eq!(c.reason.as_deref(), Some(arch.as_str()));
        assert!(!c.network);
    }

    /// 架构裁决命中：ExclusiveArch 文案（"not included" 形态）。
    #[test]
    fn classify_detects_arch_not_included() {
        let tail = "# CRBS_PHASE_START build 1718723456.500000000\n\
                    error: Architecture is not included: aarch64\n";
        let c = classify_build_log_tail(tail);
        assert!(c
            .arch_unsupported
            .unwrap()
            .contains("Architecture is not included: aarch64"));
    }

    /// 负例：普通构建失败不得误标架构裁决。
    #[test]
    fn classify_does_not_flag_arch_for_plain_build_error() {
        let tail = "# CRBS_PHASE_START build 1718723456.500000000\n\
                    gcc: error: file.c: No such file\n";
        let c = classify_build_log_tail(tail);
        assert_eq!(c.arch_unsupported, None);
    }

    /// 回归锚定根修（execution.rs 以 read+write+append 打开 build.log）：生产打开
    /// 模式下写日志后分类器必须读到尾部——若回退为只写 fd，try_clone 读返回 EBADF，
    /// 本测试即以空 tail 落空。同时锚定 ValidationFailed 归类与原文透传。
    #[tokio::test]
    async fn classify_script_failure_reads_production_opened_log() {
        let tmp = tempfile::tempdir().unwrap();
        let mut log = tokio::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .append(true)
            .open(tmp.path().join("build.log"))
            .await
            .unwrap();
        use tokio::io::AsyncWriteExt;
        log.write_all(b"+ rpmbuild -ba --target x86_64 foo.spec\n")
            .await
            .unwrap();
        log.write_all(b"error: Architecture is excluded: x86_64\n")
            .await
            .unwrap();
        log.flush().await.unwrap();

        let err = classify_script_failure("/crbs-build.sh", &log, Some(1)).await;
        match err {
            CrbsError::ValidationFailed { message } => {
                assert!(
                    message.contains("Architecture is excluded: x86_64"),
                    "rpm 原文必须透出: {message}"
                );
                assert!(message.contains("exit_code=Some(1)"));
            }
            other => panic!("expected ValidationFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn scan_subphase_full_file_fallback() {
        // 模拟 tail 窗口未命中：marker 在文件前部，尾部是大量 %build 输出。
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        writeln!(tmp, "# CRBS_PHASE_START build 1.0").unwrap();
        writeln!(tmp, "CRBS_RPMBUILD_PHASE prep 1.1").unwrap();
        writeln!(tmp, "CRBS_RPMBUILD_PHASE build 1.2").unwrap();
        for i in 0..100 {
            writeln!(tmp, "gcc -c file{}.c", i).unwrap();
        }
        tmp.flush().unwrap();

        let file = tokio::fs::File::open(tmp.path()).await.unwrap();
        let (phase, subphase) = scan_rpmbuild_subphase(&file).await.unwrap();
        assert_eq!(phase.as_deref(), Some("build"));
        assert_eq!(subphase.as_deref(), Some("build"));
    }

    #[tokio::test]
    async fn scan_subphase_returns_none_when_last_phase_not_build() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        writeln!(tmp, "# CRBS_PHASE_START build 1.0").unwrap();
        writeln!(tmp, "CRBS_RPMBUILD_PHASE check 1.1").unwrap();
        writeln!(tmp, "# CRBS_PHASE_END build 0 2.0").unwrap();
        writeln!(tmp, "# CRBS_PHASE_START ccache-summary 2.1").unwrap();
        tmp.flush().unwrap();

        let file = tokio::fs::File::open(tmp.path()).await.unwrap();
        let (phase, subphase) = scan_rpmbuild_subphase(&file).await.unwrap();
        // 回退只绑定 build 阶段：最后 phase 非 build 时 phase 保留、subphase 丢弃。
        assert_eq!(phase.as_deref(), Some("ccache-summary"));
        assert_eq!(subphase, None);
    }

    /// 回归：%build 输出超 256KB tail 窗口时，全文件兜底必须恢复出 phase 与 subphase。
    #[tokio::test]
    async fn full_file_scan_recovers_phase_when_tail_has_no_markers() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        writeln!(tmp, "# CRBS_PHASE_START install-srpm 0.9").unwrap();
        writeln!(tmp, "# CRBS_PHASE_START install-deps 1.0").unwrap();
        writeln!(tmp, "# CRBS_PHASE_START build 1.1").unwrap();
        writeln!(tmp, "Executing(%prep): /bin/sh -e /var/tmp/rpm-tmp.aaa").unwrap();
        writeln!(tmp, "CRBS_RPMBUILD_PHASE check 2.0").unwrap();
        let filler = "gcc -c src/some/deep/path/file.c -o obj/file.o ".repeat(3);
        while tmp.as_file().metadata().unwrap().len() < LOG_TAIL_CLASSIFY_BYTES + 4096 {
            writeln!(tmp, "{filler}").unwrap();
        }
        writeln!(tmp, "make: *** [Makefile:5: all] Error 1").unwrap();
        tmp.flush().unwrap();

        let file = tokio::fs::File::open(tmp.path()).await.unwrap();
        let tail = read_tail(&file, LOG_TAIL_CLASSIFY_BYTES).await.unwrap();
        let c = classify_build_log_tail(&tail);
        assert_eq!(c.phase, None, "markers must be outside the tail window");
        assert_eq!(c.subphase, None);

        let (phase, subphase) = scan_rpmbuild_subphase(&file).await.unwrap();
        assert_eq!(phase.as_deref(), Some("build"));
        assert_eq!(subphase.as_deref(), Some("check"));
    }

    #[test]
    fn strip_marker_prefix_with_hash() {
        assert_eq!(
            strip_marker_prefix("# CRBS_PHASE_START build 1.0"),
            "CRBS_PHASE_START build 1.0"
        );
    }

    #[test]
    fn strip_marker_prefix_without_hash() {
        assert_eq!(
            strip_marker_prefix("CRBS_RPMBUILD_PHASE prep 1.0"),
            "CRBS_RPMBUILD_PHASE prep 1.0"
        );
    }

    #[test]
    fn strip_marker_prefix_leading_whitespace() {
        assert_eq!(
            strip_marker_prefix("   # CRBS_PHASE_START build 1.0"),
            "CRBS_PHASE_START build 1.0"
        );
    }

    #[test]
    fn extract_rpmbuild_subphase_injected_marker() {
        assert_eq!(
            extract_rpmbuild_subphase("CRBS_RPMBUILD_PHASE check 1.0"),
            Some("check".to_string())
        );
    }

    #[test]
    fn extract_rpmbuild_subphase_executing_native() {
        assert_eq!(
            extract_rpmbuild_subphase("Executing(%build): /bin/sh -e /var/tmp/rpm-tmp.XXX"),
            Some("build".to_string())
        );
    }

    #[test]
    fn extract_rpmbuild_subphase_no_match() {
        assert_eq!(extract_rpmbuild_subphase("gcc -c file.c"), None);
    }

    #[test]
    fn extract_rpmbuild_subphase_empty_executing() {
        assert_eq!(extract_rpmbuild_subphase("Executing(%): /bin/sh"), None);
    }

    #[test]
    fn classify_empty_tail_is_noop() {
        let c = classify_build_log_tail("");
        assert_eq!(c.phase, None);
        assert_eq!(c.subphase, None);
        assert_eq!(c.reason, None);
        assert!(!c.network);
    }

    #[test]
    fn classify_truncates_reason_to_200_chars() {
        let long = "x".repeat(500);
        let c = classify_build_log_tail(&format!("error: {long}"));
        assert!(c.reason.unwrap().chars().count() <= 200);
    }

    /// env 基线：非 deterministic 仅 LC_ALL=C；deterministic 追加 TZ/哈希种子四件套。
    #[test]
    fn build_spawn_env_baselines() {
        let plain = build_spawn_env(false, None);
        assert_eq!(plain.len(), 1);
        assert_eq!(plain.get("LC_ALL").map(String::as_str), Some("C"));

        let det = build_spawn_env(true, None);
        assert_eq!(det.len(), 5);
        assert_eq!(det.get("LC_ALL").map(String::as_str), Some("C"));
        assert_eq!(det.get("TZ").map(String::as_str), Some("UTC"));
        assert_eq!(det.get("PYTHONHASHSEED").map(String::as_str), Some("0"));
        assert_eq!(det.get("PERL_HASH_SEED").map(String::as_str), Some("0"));
        assert_eq!(det.get("PERL_PERTURB_KEYS").map(String::as_str), Some("0"));
    }

    /// 回放：`source_date_epoch` Some 时注入 `SOURCE_DATE_EPOCH`（0 值照注）；
    /// None 不出现，deterministic 基线不受影响。
    #[test]
    fn build_spawn_env_injects_replay_source_date_epoch() {
        let replay = build_spawn_env(false, Some(1_700_000_000));
        assert_eq!(
            replay.get("SOURCE_DATE_EPOCH").map(String::as_str),
            Some("1700000000")
        );
        assert_eq!(
            replay.get("TZ"),
            None,
            "non-deterministic replay must not pin TZ"
        );

        let zero = build_spawn_env(false, Some(0));
        assert_eq!(zero.get("SOURCE_DATE_EPOCH").map(String::as_str), Some("0"));

        let det_replay = build_spawn_env(true, Some(42));
        assert_eq!(det_replay.len(), 6);
        assert_eq!(
            det_replay.get("SOURCE_DATE_EPOCH").map(String::as_str),
            Some("42")
        );

        assert_eq!(build_spawn_env(true, None).get("SOURCE_DATE_EPOCH"), None);
    }

    /// rpm `setting SOURCE_DATE_EPOCH=<n>` 行解析各形态：命中、`#` 前缀、尾随内容、非数字、无匹配。
    #[test]
    fn extract_source_date_epoch_forms() {
        assert_eq!(
            extract_source_date_epoch("setting SOURCE_DATE_EPOCH=1778284800"),
            Some(1778284800)
        );
        // rpm 4.16+ 的 `Setting source-date-epoch` 形态不在匹配面（以 4.14 为准）；带 # 前缀可解析
        assert_eq!(
            extract_source_date_epoch("# setting SOURCE_DATE_EPOCH=42"),
            Some(42)
        );
        // 行中带额外内容（rpm 4.18 输出 `setting SOURCE_DATE_EPOCH=123 (from ...)`)
        assert_eq!(
            extract_source_date_epoch("setting SOURCE_DATE_EPOCH=123 (from changelog)"),
            Some(123)
        );
        // 负值可解析（保持 i64 全域）
        assert_eq!(
            extract_source_date_epoch("setting SOURCE_DATE_EPOCH=-1"),
            Some(-1)
        );
        // 非数字 / 无前缀 / 大小写不符
        assert_eq!(
            extract_source_date_epoch("setting SOURCE_DATE_EPOCH=abc"),
            None
        );
        assert_eq!(extract_source_date_epoch("SOURCE_DATE_EPOCH=123"), None);
        assert_eq!(extract_source_date_epoch("gcc -c file.c"), None);
    }

    // ===== 容器内核主机名决策（源构建 / 回放确定一致） =====

    /// det（源构建与回放）：恒钉 crbs-build——语义不变，replay_build_host
    /// （det 源的宏值）不参与内核主机名。
    #[test]
    fn det_mode_pins_crbs_build_regardless_of_replay_anchor() {
        assert_eq!(
            decide_container_hostname(true, false, None, Some("CUBS-A64")),
            Some("crbs-build".to_string())
        );
        assert_eq!(
            decide_container_hostname(true, true, Some("crbs"), Some("CUBS-A64")),
            Some("crbs-build".to_string())
        );
    }

    /// 非 det 源构建：钉 worker 主机名；不可得回落 nspawn 默认（None）。
    #[test]
    fn non_det_source_pins_worker_hostname() {
        assert_eq!(
            decide_container_hostname(false, false, None, Some("CUBS-A64")),
            Some("CUBS-A64".to_string())
        );
        assert_eq!(decide_container_hostname(false, false, None, None), None);
    }

    /// 非 det 回放：钉源构建内核主机名（头 BUILDHOST）；缺锚回落 worker 主机名，
    /// 两者皆缺回落 nspawn 默认。回放若恒钉固定串，与源构建（machine name 随机
    /// 值）不一致——抓 `uname -n` 的包（pmix 类 configure）源/回放漂移。
    #[test]
    fn non_det_replay_pins_source_kernel_hostname() {
        assert_eq!(
            decide_container_hostname(false, true, Some("CUBS-A64"), Some("loong-01")),
            Some("CUBS-A64".to_string()),
            "回放必须钉源构建的内核主机名，而非回放 worker 的"
        );
        assert_eq!(
            decide_container_hostname(false, true, None, Some("loong-01")),
            Some("loong-01".to_string())
        );
        assert_eq!(decide_container_hostname(false, true, None, None), None);
    }

    /// 非法值逐级回落：头 BUILDHOST 非法（外来 SRPM 可写任意头值）按缺锚处理；
    /// worker 主机名非法回落 nspawn 默认。
    #[test]
    fn invalid_values_fall_back() {
        assert_eq!(
            decide_container_hostname(false, true, Some("bad host"), Some("CUBS-A64")),
            Some("CUBS-A64".to_string())
        );
        assert_eq!(
            decide_container_hostname(false, true, Some("../evil"), None),
            None
        );
        assert_eq!(
            decide_container_hostname(false, false, None, Some("")),
            None
        );
    }

    /// nspawn --hostname 值合法性（priv-helper spawn.rs 同口径）：非空、≤64、
    /// 无 '/'、无 '..'、无空白/控制字符。
    #[test]
    fn hostname_value_charset_gate() {
        assert!(hostname_value_valid("crbs-build"));
        assert!(hostname_value_valid("CUBS-A64"));
        assert!(hostname_value_valid("loong-01"));
        assert!(hostname_value_valid("a.b.c"));
        assert!(!hostname_value_valid(""));
        assert!(!hostname_value_valid("bad host"));
        assert!(!hostname_value_valid("/etc/passwd"));
        assert!(!hostname_value_valid("a..b"));
        assert!(!hostname_value_valid("a\tb"));
        assert!(!hostname_value_valid("a\u{0}b"));
        let long = "a".repeat(65);
        assert!(!hostname_value_valid(&long), "超 HOST_NAME_MAX 拒绝");
        assert!(hostname_value_valid(&"a".repeat(64)));
    }

    /// worker 主机名：取到即合法（真机环境读取路径回归；值随环境变化不断言内容）。
    #[test]
    fn worker_hostname_value_is_valid_when_present() {
        if let Some(name) = worker_hostname() {
            assert!(hostname_value_valid(&name));
        }
    }
}
