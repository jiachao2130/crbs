// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 外部命令执行封装：超时、取消、输出上限与退出状态。

use std::process::Output;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::error::{looks_like_network_failure, CrbsError};

/// 支持 cancel/timeout 的外部命令执行：取消/到期显式 kill 子进程并 `wait()`
/// 回收，不依赖 drop 时机（避免瞬时 zombie）。
///
/// 非 0 退出按失败传播（quiet 指不捕获输出，非忽略结果）：dnf install 等
/// 事务命令的 "No match" 退出若被吞，后续步骤会在无关位置报错（dnf 失败
/// 被吞后炸在 chown tmp ENOENT）。
pub async fn run_command_quiet_with_cancel_timeout(
    mut cmd: tokio::process::Command,
    context: &str,
    cancel_token: Option<&CancellationToken>,
    timeout: Option<Duration>,
) -> crate::Result<()> {
    // 非捕获：cancel/timeout 按进程组 SIGKILL，孙进程（dnf）不逃逸写 installroot。
    match run_child_core(&mut cmd, false, cancel_token, timeout, context).await? {
        ChildCapture::Status(status) if status.success() => Ok(()),
        ChildCapture::Status(status) => Err(CrbsError::io_message(format!(
            "{context}: exited with {}",
            status
                .code()
                .map_or_else(|| "signal".to_string(), |c| c.to_string())
        ))),
        ChildCapture::Output(_) => Err(CrbsError::io_message(
            "internal error: quiet runner returned captured output",
        )),
    }
}

enum ChildCapture {
    Status(std::process::ExitStatus),
    Output(std::process::Output),
}

/// 执行已配置好的命令并等待，统一各 chroot 执行路径的等待与清理：子进程入
/// 独立进程组并 `kill_on_drop(true)`；cancel/timeout 时 SIGKILL 整组（孙进程
/// 同组终止）并 `wait()` 回收，防孙进程逃逸继续写 overlay/base_os。
/// `capture_output=true` 时并发读 stdout/stderr 组装 `Output`——必须边读边
/// wait，否则子进程写满 pipe 缓冲阻塞、wait 永不返回。
async fn run_child_core(
    cmd: &mut tokio::process::Command,
    capture_output: bool,
    cancel_token: Option<&CancellationToken>,
    timeout: Option<Duration>,
    spawn_context: &str,
) -> crate::Result<ChildCapture> {
    cmd.process_group(0).kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .map_err(|e| CrbsError::io_message(format!("{}: {}", spawn_context, e)))?;

    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let wait_and_collect = async {
        if capture_output {
            let (status, out, err) =
                tokio::join!(child.wait(), read_pipe(&mut stdout), read_pipe(&mut stderr));
            (status, Some(out), Some(err))
        } else {
            (child.wait().await, None, None)
        }
    };

    let run_fut = async {
        match cancel_token {
            Some(token) => {
                tokio::select! {
                    r = wait_and_collect => Ok(r),
                    _ = token.cancelled() => Err(CrbsError::Cancelled),
                }
            }
            None => Ok(wait_and_collect.await),
        }
    };
    let result = match timeout {
        Some(d) => tokio::time::timeout(d, run_fut)
            .await
            .map_err(|_| CrbsError::Timeout)
            .and_then(|r| r),
        None => run_fut.await,
    };

    match result {
        Ok((Ok(status), out, err)) => {
            if capture_output {
                Ok(ChildCapture::Output(Output {
                    status,
                    stdout: out.unwrap_or_default(),
                    stderr: err.unwrap_or_default(),
                }))
            } else {
                Ok(ChildCapture::Status(status))
            }
        }
        Ok((Err(e), _, _)) => Err(CrbsError::io_message(format!("{}: {}", spawn_context, e))),
        Err(e) => {
            kill_group_and_reap(&mut child).await;
            Err(e)
        }
    }
}

/// 单条管道捕获上限（32MB）：超限只丢弃不暂存，防失控子进程打爆捕获端内存；
/// 达限后仍继续读丢弃，防子进程写满 pipe 缓冲死锁。
pub(crate) const MAX_CAPTURE_BYTES: usize = 32 * 1024 * 1024;

const READ_CHUNK_BYTES: usize = 8 * 1024;

fn truncate_to(buf: &[u8], cap: usize) -> Vec<u8> {
    if buf.len() <= cap {
        buf.to_vec()
    } else {
        buf[..cap].to_vec()
    }
}

/// 读取子进程管道直到 EOF；未接管（非捕获模式）返回空。分块累计至
/// `MAX_CAPTURE_BYTES`，之后继续读只丢弃；超限则 warn 并返回截断数据。
async fn read_pipe<R>(pipe: &mut Option<R>) -> Vec<u8>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut collected = Vec::new();
    if let Some(p) = pipe {
        use tokio::io::AsyncReadExt;
        let mut chunk = [0u8; READ_CHUNK_BYTES];
        let mut total = 0usize;
        loop {
            match p.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    if collected.len() < MAX_CAPTURE_BYTES {
                        collected.extend_from_slice(&chunk[..n]);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    warn!(error = %e, "failed to drain child pipe");
                    break;
                }
            }
        }
        let capped = truncate_to(&collected, MAX_CAPTURE_BYTES);
        if total > MAX_CAPTURE_BYTES {
            warn!(
                cap = MAX_CAPTURE_BYTES,
                total_bytes = total,
                "child pipe output exceeded capture cap; excess discarded"
            );
        }
        return capped;
    }
    collected
}

/// cancel/timeout 清理：SIGKILL 子进程进程组（负 pgid）并 `wait()` 回收直接子进程。
async fn kill_group_and_reap(child: &mut tokio::process::Child) {
    if let Some(pid) = child.id() {
        let pgid = nix::unistd::Pid::from_raw(-(pid as nix::libc::pid_t));
        if let Err(e) = nix::sys::signal::kill(pgid, nix::sys::signal::SIGKILL) {
            warn!(pid = %pid, error = %e, "failed to SIGKILL child process group");
        }
    }
    if let Err(e) = tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        warn!(error = %e, "timeout waiting for killed child process");
    }
}

/// 等待子进程退出状态，支持 cancel/timeout。语义详见 `run_child_core`。
pub(crate) async fn run_child_status_with_cancel_timeout(
    cmd: &mut tokio::process::Command,
    cancel_token: Option<&CancellationToken>,
    timeout: Option<Duration>,
    spawn_context: &str,
) -> crate::Result<std::process::ExitStatus> {
    match run_child_core(cmd, false, cancel_token, timeout, spawn_context).await? {
        ChildCapture::Status(s) => Ok(s),
        ChildCapture::Output(_) => Err(CrbsError::io_message(
            "internal error: status runner returned captured output",
        )),
    }
}

/// 等待子进程并捕获 stdout/stderr，支持 cancel/timeout。语义详见 `run_child_core`。
pub(crate) async fn run_child_output_with_cancel_timeout(
    cmd: &mut tokio::process::Command,
    cancel_token: Option<&CancellationToken>,
    timeout: Option<Duration>,
    spawn_context: &str,
) -> crate::Result<Output> {
    match run_child_core(cmd, true, cancel_token, timeout, spawn_context).await? {
        ChildCapture::Output(o) => Ok(o),
        ChildCapture::Status(_) => Err(CrbsError::io_message(
            "internal error: output runner returned status only",
        )),
    }
}

/// cancel 感知变体：token 触发时按进程组 SIGKILL——depsolve 长时 dnf/rpm
/// 批查询可被 chain 取消及时终止，而非拖到自然结束。
pub async fn run_command_capped_output_with_cancel(
    mut cmd: tokio::process::Command,
    spawn_context: &str,
    cancel_token: Option<&CancellationToken>,
) -> crate::Result<Output> {
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    run_child_output_with_cancel_timeout(&mut cmd, cancel_token, None, spawn_context).await
}

/// 限时变体：卡死的外部命令（NFS 停滞的 createrepo_c、黑洞镜像的 dnf
/// repoquery）不得无限占用构建 future——超时按进程组终止并归类 Timeout。
pub async fn run_command_capped_output_with_timeout(
    mut cmd: tokio::process::Command,
    spawn_context: &str,
    timeout: std::time::Duration,
) -> crate::Result<Output> {
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    run_child_output_with_cancel_timeout(&mut cmd, None, Some(timeout), spawn_context).await
}

/// cancel+timeout 组合变体：depsolve 单包 rpm 查询可能被 chain 取消或在
/// 停滞存储上挂死——先触发者按进程组 SIGKILL 并归类 Cancelled/Timeout。
pub async fn run_command_capped_output_with_cancel_and_timeout(
    mut cmd: tokio::process::Command,
    spawn_context: &str,
    cancel_token: Option<&CancellationToken>,
    timeout: std::time::Duration,
) -> crate::Result<Output> {
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    run_child_output_with_cancel_timeout(&mut cmd, cancel_token, Some(timeout), spawn_context).await
}

/// 判断捕获输出是否达 [`MAX_CAPTURE_BYTES`]：stdout/stderr 任一命中即视为
/// "可能被截断"（恰等于上限也命中，false positive）。截断仅 warn、`Output`
/// 形态不变，依赖完整性的调用方（depsolve capability 索引）须显式检查失败。
pub fn output_hit_capture_cap(output: &Output) -> bool {
    output.stdout.len() >= MAX_CAPTURE_BYTES || output.stderr.len() >= MAX_CAPTURE_BYTES
}

/// 对已经获取到的 `Output` 做失败分类，不执行 IO 写回。
pub fn classify_command_failure(context: impl Into<String>, output: &Output) -> CrbsError {
    let context = context.into();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let message = format!(
        "{} failed: exit_code={:?} stderr={}",
        context,
        output.status.code(),
        stderr
    );
    if looks_like_network_failure(&stderr) {
        CrbsError::Network { message }
    } else {
        CrbsError::io_message(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Output};
    use std::time::Duration;

    fn fake_output(stderr: &[u8]) -> Output {
        // WIFEXITED(1) 的原始 wait 状态：免真实 spawn 直接构造 ExitStatus
        //（仅 classify_command_failure 消费 code()，平台语义一致）。
        #[cfg(unix)]
        let status = std::os::unix::process::ExitStatusExt::from_raw(1 << 8);
        #[cfg(not(unix))]
        let status = Command::new("sh")
            .arg("-c")
            .arg("exit 1")
            .output()
            .unwrap()
            .status;
        Output {
            status,
            stdout: vec![],
            stderr: stderr.to_vec(),
        }
    }

    #[test]
    fn test_classify_command_failure_network() {
        let out = fake_output(b"curl: (6) Could not resolve host");
        assert!(matches!(
            classify_command_failure("dnf install", &out),
            CrbsError::Network { .. }
        ));
    }

    #[test]
    fn test_classify_command_failure_io() {
        let out = fake_output(b"No such file or directory");
        assert!(matches!(
            classify_command_failure("cp source dest", &out),
            CrbsError::Io { .. }
        ));
    }

    #[test]
    fn test_truncate_to_below_cap_keeps_all() {
        assert_eq!(truncate_to(b"hello", 10), b"hello".to_vec());
    }

    #[test]
    fn test_truncate_to_at_cap_keeps_all() {
        let data = vec![7u8; 10];
        assert_eq!(truncate_to(&data, 10), data);
    }

    #[test]
    fn test_truncate_to_at_cap_boundary_truncates_above() {
        let data = vec![7u8; 15];
        assert_eq!(truncate_to(&data, 10), vec![7u8; 10]);
    }

    #[test]
    fn test_output_hit_capture_cap() {
        let status = Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .output()
            .unwrap()
            .status;
        let mut output = Output {
            status,
            stdout: vec![],
            stderr: vec![],
        };
        assert!(!output_hit_capture_cap(&output));
        output.stdout = vec![0u8; MAX_CAPTURE_BYTES];
        assert!(output_hit_capture_cap(&output));
        output.stdout = vec![0u8; MAX_CAPTURE_BYTES - 1];
        assert!(!output_hit_capture_cap(&output));
        output.stderr = vec![0u8; MAX_CAPTURE_BYTES];
        assert!(output_hit_capture_cap(&output));
    }

    #[tokio::test]
    async fn test_run_command_quiet_with_cancel_timeout_success() {
        run_command_quiet_with_cancel_timeout(
            tokio::process::Command::new("true"),
            "true",
            None,
            Some(Duration::from_secs(1)),
        )
        .await
        .expect("true should succeed");
    }

    #[tokio::test]
    async fn test_run_command_quiet_with_cancel_timeout_nonzero_exit() {
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c").arg("exit 3");
        let err = run_command_quiet_with_cancel_timeout(
            cmd,
            "failing-cmd",
            None,
            Some(Duration::from_secs(5)),
        )
        .await
        .expect_err("non-zero exit must propagate as an error");
        let message = err.to_string();
        assert!(
            message.contains("failing-cmd") && message.contains("3"),
            "error must carry context and exit code, got: {message}"
        );
    }

    #[tokio::test]
    async fn test_run_command_quiet_with_cancel_timeout_times_out() {
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("10");
        let err = run_command_quiet_with_cancel_timeout(
            cmd,
            "sleep",
            None,
            Some(Duration::from_millis(50)),
        )
        .await
        .expect_err("sleep should time out");
        assert!(matches!(err, CrbsError::Timeout));
    }

    #[tokio::test]
    async fn test_run_command_quiet_with_cancel_timeout_cancelled() {
        let token = CancellationToken::new();
        let token_c = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            token_c.cancel();
        });
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("10");
        let err = run_command_quiet_with_cancel_timeout(cmd, "sleep", Some(&token), None)
            .await
            .expect_err("sleep should be cancelled");
        assert!(matches!(err, CrbsError::Cancelled));
    }

    #[tokio::test]
    async fn test_run_child_status_success() {
        let mut cmd = tokio::process::Command::new("true");
        let status = run_child_status_with_cancel_timeout(&mut cmd, None, None, "spawn true")
            .await
            .expect("true should succeed");
        assert!(status.success());
    }

    #[tokio::test]
    async fn test_run_child_output_captures_both_pipes() {
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c")
            .arg("echo out; echo err >&2")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let output = run_child_output_with_cancel_timeout(&mut cmd, None, None, "spawn sh")
            .await
            .expect("sh should succeed");
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "out");
        assert_eq!(String::from_utf8_lossy(&output.stderr).trim(), "err");
    }

    #[tokio::test]
    async fn test_run_child_output_large_output_no_deadlock() {
        // 输出远超 64KB pipe 缓冲：捕获模式必须边读边 wait，否则死锁。
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c")
            .arg("yes | head -c 1048576")
            .stdout(std::process::Stdio::piped());
        let output = tokio::time::timeout(
            Duration::from_secs(10),
            run_child_output_with_cancel_timeout(&mut cmd, None, None, "spawn sh"),
        )
        .await
        .expect("should not deadlock")
        .expect("command should succeed");
        assert_eq!(output.stdout.len(), 1_048_576);
    }

    #[tokio::test]
    async fn test_run_child_output_over_cap_truncates_without_deadlock() {
        // 34MB > 32MB cap：达限后必须继续丢弃读取（防 pipe 写满死锁），最终截断到 cap。
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c")
            .arg("yes | head -c 34000000")
            .stdout(std::process::Stdio::piped());
        let output = tokio::time::timeout(
            Duration::from_secs(30),
            run_child_output_with_cancel_timeout(&mut cmd, None, None, "spawn sh"),
        )
        .await
        .expect("draining beyond cap must not deadlock")
        .expect("command should succeed");
        assert_eq!(output.stdout.len(), 32 * 1024 * 1024);
        assert_eq!(&output.stdout[..2], b"y\n");
    }

    #[tokio::test]
    async fn test_run_child_timeout_kills_process_group() {
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c").arg("sleep 60 & wait");
        let err = run_child_status_with_cancel_timeout(
            &mut cmd,
            None,
            Some(Duration::from_millis(100)),
            "spawn sh",
        )
        .await
        .expect_err("should time out");
        assert!(matches!(err, CrbsError::Timeout));
    }

    #[tokio::test]
    async fn test_run_child_cancel_kills_process_group() {
        let token = CancellationToken::new();
        token.cancel();
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c").arg("sleep 60 & wait");
        let err = run_child_status_with_cancel_timeout(&mut cmd, Some(&token), None, "spawn sh")
            .await
            .expect_err("should be cancelled");
        assert!(matches!(err, CrbsError::Cancelled));
    }
}
