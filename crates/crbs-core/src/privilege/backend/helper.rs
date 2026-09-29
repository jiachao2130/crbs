// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! privileged helper 后端：JSON 协议调用与 helper 文件基线校验。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;

use super::{MountOverlayRequest, PrivilegeBackend};

/// Helper 后端：调用 `crbs-priv-helper` one-shot 二进制。
pub struct HelperBackend {
    helper_path: PathBuf,
    crbs_root: PathBuf,
}

impl HelperBackend {
    /// 以显式 helper 路径构造（路径有效性由调用方用 `passes_helper_file_baseline` 保证）。
    pub fn new(helper_path: PathBuf, crbs_root: PathBuf) -> Self {
        Self {
            helper_path,
            crbs_root,
        }
    }

    /// 返回 helper 二进制路径；`Always` 模式初始化未显式配置 helper_path 时，借此回填探测到的路径。
    pub fn helper_path(&self) -> &Path {
        &self.helper_path
    }

    /// 探测默认 helper 路径（RPM 安装到 /usr/libexec/crbs）。
    pub fn detect(crbs_root: PathBuf) -> Option<Self> {
        let candidates = [
            PathBuf::from("/usr/libexec/crbs/crbs-priv-helper"),
            PathBuf::from("/usr/bin/crbs-priv-helper"),
            PathBuf::from("/usr/local/bin/crbs-priv-helper"),
        ];
        for path in &candidates {
            if super::passes_helper_file_baseline(path) {
                return Some(Self::new(path.clone(), crbs_root));
            }
        }
        None
    }

    fn run(&self, args: &[&str], stdin_content: Option<&[u8]>) -> crate::Result<()> {
        let mut cmd = Command::new(&self.helper_path);
        cmd.arg("--crbs-root").arg(&self.crbs_root).args(args);

        // 先同步写完全部 stdin 再 wait_with_output 读输出：helper 在写入期间向 stdout/stderr
        // 输出超过 pipe 缓冲（Linux 64KB）会父子互塞死锁。安全前提：write-file 内容小、
        // helper 读完 stdin 只回一行 JSON；大内容/多输出需改独立线程写 stdin 或边写边读。
        let mut stdin_err: Option<std::io::Error> = None;
        let output = if let Some(content) = stdin_content {
            let mut child = cmd
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| {
                    crate::error::CrbsError::io_message(format!(
                        "run helper {}: {e}",
                        self.helper_path.display()
                    ))
                })?;
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                // 写 stdin 失败（典型：helper 校验参数后早退 EPIPE）不能立即返回——真实错误在
                // helper stdout 的 JSON 里且 child 须 wait 收尸；记录错误、drop stdin 送 EOF 继续收集。
                if let Err(e) = stdin.write_all(content) {
                    stdin_err = Some(e);
                }
            }
            child.wait_with_output().map_err(|e| {
                crate::error::CrbsError::io_message(format!(
                    "wait helper {}: {e}",
                    self.helper_path.display()
                ))
            })?
        } else {
            cmd.output().map_err(|e| {
                crate::error::CrbsError::io_message(format!(
                    "run helper {}: {e}",
                    self.helper_path.display()
                ))
            })?
        };

        check_helper_output(&self.helper_path, &output, stdin_err.as_ref())
    }

    /// one-shot 子命令的 deadline 执行：stdio 收口 + try_wait 轮询 + 50ms 睡眠、
    /// 超时 kill 报错（卡死 = 部署异常或 helper 过旧不支持该子命令）。`subcommand`
    /// 与 `timeout_ctx`（超时文案在 "support the subcommand" 之后的尾段）参数化
    /// 各调用语境，文案其余部分逐字节不变。同步方法，async 经 spawn_blocking。
    fn run_with_deadline(
        &self,
        cmd: &mut Command,
        timeout: std::time::Duration,
        subcommand: &str,
        timeout_ctx: &str,
    ) -> crate::Result<()> {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| {
            crate::error::CrbsError::io_message(format!(
                "run helper {}: {e}",
                self.helper_path.display()
            ))
        })?;

        let deadline = std::time::Instant::now() + timeout;
        loop {
            match child.try_wait() {
                // 已退出：wait_with_output 立即返回，错误报告与 run() 同语义（JSON 错误优先）。
                Ok(Some(_)) => {
                    let output = child.wait_with_output().map_err(|e| {
                        crate::error::CrbsError::io_message(format!(
                            "wait helper {}: {e}",
                            self.helper_path.display()
                        ))
                    })?;
                    return check_helper_output(&self.helper_path, &output, None);
                }
                Ok(None) => {}
                Err(e) => {
                    return Err(crate::error::CrbsError::io_message(format!(
                        "poll helper {}: {e}",
                        self.helper_path.display()
                    )));
                }
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(crate::error::CrbsError::io_message(format!(
                    "helper {} {subcommand} timed out after {}s (helper hung, too old to \
                     support the subcommand{timeout_ctx}",
                    self.helper_path.display(),
                    timeout.as_secs()
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

/// 校验 helper 退出输出：非零退出按 JSON 错误 > stdin 写入错误 > stderr 尾行优先级报告，
/// 成功时透传 helper stderr 审计行进 tracing；`run()` 与 `write_cgroup_file()` 共用，报告语义须一致。
fn check_helper_output(
    helper_path: &Path,
    output: &std::process::Output,
    stdin_err: Option<&std::io::Error>,
) -> crate::Result<()> {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let status = output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".into());
        // helper 的 JSON 错误最可信（stdin EPIPE 时它才是真实原因），优先报告。
        if let Some(reason) = parse_helper_error(&stdout) {
            // 权限类错误映射 CrbsError::PermissionDenied（调用方据 code() 区分退出码/HTTP 码）；其余聚合 Io。
            if let Some(detail) = reason.strip_prefix(HELPER_PERMISSION_PREFIX) {
                return Err(crate::error::CrbsError::PermissionDenied {
                    message: detail.to_string(),
                });
            }
            return Err(crate::error::CrbsError::io_message(format!(
                "helper failed ({status}): {reason}; stderr={stderr}"
            )));
        }
        if let Some(e) = stdin_err {
            return Err(crate::error::CrbsError::io_message(format!(
                "write helper {} stdin: {e} (exit={status}; stderr={stderr})",
                helper_path.display()
            )));
        }
        let tail = stdout.lines().rev().take(3).collect::<Vec<_>>();
        let reason = if tail.is_empty() {
            "unknown helper error".to_string()
        } else {
            tail.into_iter().rev().collect::<Vec<_>>().join("\n")
        };
        return Err(crate::error::CrbsError::io_message(format!(
            "helper failed ({status}): {reason}; stderr={stderr}; helper={}",
            helper_path.display()
        )));
    }
    // stdin 写失败但 helper 报成功：可能基于提前 EOF 的截断 stdin 完成操作（写出不完整 write-file），一律按失败。
    if let Some(e) = stdin_err {
        return Err(crate::error::CrbsError::io_message(format!(
            "write helper {} stdin: {e}",
            helper_path.display()
        )));
    }
    // 成功路径透传 helper stderr：setuid one-shot helper 对每个特权操作分发前输出 info 审计行
    //（op+参数+caller uid）由调用方收进构建日志/journal；脱敏在 helper 侧 audit_line（write-file/mount 只记长度）。
    forward_helper_stderr(&output.stderr);
    Ok(())
}

/// 把 helper stderr 逐行透传进 tracing（info 级）。`run()` 只承接 one-shot 操作
///（mount/chown/write-file/rm-rf 等），spawn 类不经 `run()`——stderr 上只有 helper
/// 自身审计行与少量 warn，无构建输出混入，整段透传不会造成输出重复。
fn forward_helper_stderr(stderr: &[u8]) {
    for line in String::from_utf8_lossy(stderr).lines() {
        let line = line.trim();
        if !line.is_empty() {
            let msg = strip_helper_line_prefix(line);
            tracing::info!(target: "crbs::privilege::audit", "{msg}");
        }
    }
}

/// 剥离 priv-helper tracing 默认布局的行前缀（时间戳 级别 target: ），只转发
/// 消息体——前缀进父进程日志层会双重格式化；耦合 crbs-priv-helper/src/main.rs
/// 的 init_tracing，格式变化需两侧同步；不匹配行原样透传。
fn strip_helper_line_prefix(line: &str) -> &str {
    static PREFIX: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    let re = PREFIX.get_or_init(|| {
        // 模式硬编码：编译失败 = 代码 bug，降级为不剥离（原样透传）。
        regex::Regex::new(
            r"^\d{4}-\d{2}-\d{2}T[0-9:.]+Z\s+(?:TRACE|DEBUG|INFO|WARN|ERROR)\s+[A-Za-z0-9_:]+:\s",
        )
        .ok()
    });
    match re.as_ref().and_then(|re| re.find(line)) {
        Some(m) => &line[m.end()..],
        None => line,
    }
}

impl PrivilegeBackend for HelperBackend {
    fn mount(
        &self,
        source: Option<&Path>,
        target: &Path,
        fstype: Option<&str>,
        flags: u64,
        data: Option<&str>,
    ) -> crate::Result<()> {
        let flags_str = flags.to_string();
        let mut args = vec!["mount"];
        if let Some(s) = source {
            args.push("--source");
            args.push(path_arg(s)?);
        }
        args.push("--target");
        args.push(path_arg(target)?);
        if let Some(f) = fstype {
            args.push("--fstype");
            args.push(f);
        }
        if flags != 0 {
            args.push("--flags");
            args.push(&flags_str);
        }
        if let Some(d) = data {
            args.push("--data");
            args.push(d);
        }
        self.run(&args, None)
    }

    fn mount_overlay(&self, req: MountOverlayRequest) -> crate::Result<()> {
        let mut args = vec!["mount-overlay"];
        for lower in &req.lower {
            args.push("--lower");
            args.push(path_arg(lower)?);
        }
        args.push("--upper");
        args.push(path_arg(&req.upper)?);
        args.push("--work");
        args.push(path_arg(&req.work)?);
        args.push("--target");
        args.push(path_arg(&req.target)?);
        self.run(&args, None)
    }

    fn umount2(&self, target: &Path, flags: i32) -> crate::Result<()> {
        let flags_str = flags.to_string();
        let mut args = vec!["umount", "--target", path_arg(target)?];
        if flags != 0 {
            args.push("--flags");
            args.push(&flags_str);
        }
        self.run(&args, None)
    }

    fn mkdir_chown(&self, path: &Path, user: &str, group: &str, mode: u32) -> crate::Result<()> {
        self.run(
            &[
                "mkdir-chown",
                "--path",
                path_arg(path)?,
                "--user",
                user,
                "--group",
                group,
                "--mode",
                &format!("{mode:o}"),
            ],
            None,
        )
    }

    fn chown(&self, path: &Path, uid: u32, gid: u32, recursive: bool) -> crate::Result<()> {
        let uid_s = uid.to_string();
        let gid_s = gid.to_string();
        let mut args = vec![
            "chown",
            "--path",
            path_arg(path)?,
            "--uid",
            &uid_s,
            "--gid",
            &gid_s,
        ];
        if recursive {
            args.push("--recursive");
        }
        self.run(&args, None)
    }

    fn chmod(&self, path: &Path, mode: u32, recursive: bool) -> crate::Result<()> {
        let mode_s = format!("{:o}", mode);
        let mut args = vec!["chmod", "--path", path_arg(path)?, "--mode", &mode_s];
        if recursive {
            args.push("--recursive");
        }
        self.run(&args, None)
    }

    fn write_file(
        &self,
        path: &Path,
        content: &[u8],
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> crate::Result<()> {
        let mode_s = mode.map(|m| format!("{:o}", m));
        let uid_s = uid.map(|u| u.to_string());
        let gid_s = gid.map(|g| g.to_string());
        let mut args: Vec<&str> = vec!["write-file", "--path", path_arg(path)?, "--content-stdin"];
        if let Some(ref m) = mode_s {
            args.push("--mode");
            args.push(m);
        }
        if let Some(ref u) = uid_s {
            args.push("--uid");
            args.push(u);
        }
        if let Some(ref g) = gid_s {
            args.push("--gid");
            args.push(g);
        }
        self.run(&args, Some(content))
    }

    fn gc_orphan_mounts(&self, crbs_root: &Path, tmp_dirs: &[PathBuf]) -> crate::Result<()> {
        // tmp_dir 可重复；空切片不加 --tmp-dir（对齐旧 helper 协议：旧 helper 无该参数，
        // 收到会 clap 校验报 unknown argument 非零退出——错误进调用方日志，不阻断）。
        let mut args: Vec<String> = vec![
            "gc-orphan-mounts".to_string(),
            "--crbs-root".to_string(),
            path_arg(crbs_root)?.to_string(),
        ];
        for tmp in tmp_dirs {
            args.push("--tmp-dir".to_string());
            args.push(path_arg(tmp)?.to_string());
        }
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run(&arg_refs, None)
    }

    fn rm_rf(&self, paths: &[&Path]) -> crate::Result<()> {
        if paths.is_empty() {
            return Ok(());
        }
        let mut args: Vec<String> = Vec::with_capacity(2 + paths.len() * 2);
        args.push("rm-rf".to_string());
        for p in paths {
            let s = path_arg(p)?;
            args.push("--path".to_string());
            args.push(s.to_string());
        }
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run(&arg_refs, None)
    }

    fn is_helper(&self) -> bool {
        true
    }

    /// 写 cgroup v2 控制文件：spawn `crbs-priv-helper write-cgroup-file`。one-shot 毫秒级完成，
    /// wait 循环 10s 上限、超时 kill 报错（卡死 = 部署异常或 helper 过旧不支持该子命令）；同步方法，async 经 spawn_blocking。
    fn write_cgroup_file(&self, path: &str, value: &str) -> crate::Result<()> {
        const WRITE_CGROUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

        let mut cmd = Command::new(&self.helper_path);
        cmd.arg("--crbs-root")
            .arg(&self.crbs_root)
            .arg("write-cgroup-file")
            .arg("--path")
            .arg(path)
            .arg("--value")
            .arg(value);
        // 超时文案尾段：write-cgroup-file 额外列 cgroup 路径缺失成因。
        self.run_with_deadline(
            &mut cmd,
            WRITE_CGROUP_TIMEOUT,
            "write-cgroup-file",
            &format!(", or cgroup path missing); path={path}"),
        )
    }

    /// 取消时杀构建进程组：spawn `crbs-priv-helper kill-process-group`。one-shot 毫秒级完成，
    /// wait 循环 10s 上限、超时 kill 报错（卡死 = 部署异常或 helper 过旧不支持该子命令）；
    /// 同步方法，async 经 spawn_blocking。
    fn kill_process_group(&self, pgid: i32) -> crate::Result<()> {
        const KILL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

        let mut cmd = Command::new(&self.helper_path);
        cmd.arg("kill-process-group")
            .arg("--crbs-root")
            .arg(&self.crbs_root)
            .arg("--pgid")
            .arg(pgid.to_string());
        self.run_with_deadline(
            &mut cmd,
            KILL_TIMEOUT,
            "kill-process-group",
            &format!("); pgid={pgid}"),
        )
    }

    /// 终止 nspawn machine：spawn `crbs-priv-helper terminate-machine`。one-shot
    /// 毫秒级完成，wait 循环 10s 上限、超时 kill 报错（卡死 = 部署异常或 helper
    /// 过旧不支持该子命令）；同步方法，async 经 spawn_blocking。
    fn terminate_machine(&self, machine_name: &str) -> crate::Result<()> {
        const TERMINATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

        let mut cmd = Command::new(&self.helper_path);
        cmd.arg("terminate-machine")
            .arg("--crbs-root")
            .arg(&self.crbs_root)
            .arg("--name")
            .arg(machine_name);
        self.run_with_deadline(
            &mut cmd,
            TERMINATE_TIMEOUT,
            "terminate-machine",
            &format!("); machine={machine_name}"),
        )
    }

    fn spawn_chroot(
        &self,
        rootfs: &Path,
        program: &str,
        args: &[&str],
        network: bool,
    ) -> crate::Result<std::process::Command> {
        let mut cmd = std::process::Command::new(&self.helper_path);
        cmd.arg("spawn-chroot")
            .arg("--crbs-root")
            .arg(&self.crbs_root)
            .arg("--rootfs")
            .arg(path_arg(rootfs)?)
            .arg("--program")
            .arg(program);
        for a in args {
            cmd.arg("--arg").arg(a);
        }
        if !network {
            cmd.arg("--no-network");
        }
        Ok(cmd)
    }

    fn spawn_nspawn(&self, nspawn_argv: &[String]) -> crate::Result<std::process::Command> {
        if nspawn_argv.is_empty() {
            return Err(crate::error::CrbsError::io_message(
                "spawn_nspawn: empty argv",
            ));
        }
        let mut cmd = std::process::Command::new(&self.helper_path);
        cmd.arg("spawn-nspawn")
            .arg("--crbs-root")
            .arg(&self.crbs_root)
            .arg("--")
            .args(nspawn_argv);
        Ok(cmd)
    }

    fn spawn_dnf(
        &self,
        installroot: &Path,
        releasever: &str,
        trusted_repos_dir: &Path,
        args: &[String],
    ) -> crate::Result<std::process::Command> {
        let mut cmd = std::process::Command::new(&self.helper_path);
        cmd.arg("spawn-dnf")
            .arg("--crbs-root")
            .arg(&self.crbs_root)
            .arg("--installroot")
            .arg(path_arg(installroot)?)
            .arg("--releasever")
            .arg(releasever)
            // host 受信 repo 目录：helper 侧布局收死 + fail-closed 检查并固定注入
            // --config/--setopt=reposdir（路径派生与写入在 engine 侧，见 base_os_install 的 prepare）。
            .arg("--repos-dir")
            .arg(path_arg(trusted_repos_dir)?);
        for a in args {
            cmd.arg("--arg").arg(a);
        }
        Ok(cmd)
    }
}

/// helper 候选路径是否过最小安全基线：普通文件、非 symlink、root 属主、
/// 无 group/other 写位（不满足一律拒绝）。**不校验执行位**——x 位缺失要到
/// spawn 时才 EACCES 暴露，部署方须自行确保可执行。
pub fn passes_helper_file_baseline(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "helper candidate metadata failed");
                return false;
            }
        };
        if meta.file_type().is_symlink() {
            tracing::debug!(path = %path.display(), "helper candidate is a symlink, rejecting");
            return false;
        }
        if !meta.is_file() {
            tracing::debug!(path = %path.display(), "helper candidate is not a file, rejecting");
            return false;
        }
        let uid = meta.uid();
        if uid != 0 {
            tracing::debug!(path = %path.display(), uid = %uid, "helper candidate owner is not root, rejecting");
            return false;
        }
        let mode = meta.mode();
        if mode & 0o022 != 0 {
            tracing::debug!(
                path = %path.display(),
                mode = %format!("{:04o}", mode),
                "helper candidate is group/other writable, rejecting"
            );
            return false;
        }
        true
    }
    #[cfg(not(unix))]
    {
        std::fs::metadata(path)
            .map(|m| m.is_file())
            .unwrap_or(false)
    }
}

fn path_arg(path: &Path) -> crate::Result<&str> {
    path.as_os_str().to_str().ok_or_else(|| {
        crate::error::CrbsError::io_message(format!("path is not utf-8: {}", path.display()))
    })
}

#[derive(Debug, Deserialize)]
struct HelperResult {
    err: Option<String>,
}

/// helper 权限类错误串的稳定前缀（crbs-priv-helper `Error::PermissionDenied` 的 thiserror
/// Display）；helper 的 JSON 无结构化类别字段，按前缀映射 `CrbsError::PermissionDenied`。
const HELPER_PERMISSION_PREFIX: &str = "permission denied: ";

/// 解析 helper stdout 最后一行 JSON 的 `err` 字段：失败输出 `{"ok":null,"err":"<原因>"}`，
/// 成功 err 为 null（返回 None）；末行非 JSON（崩溃、exec 类命令）也返回 None。
fn parse_helper_error(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .last()
        .and_then(|line| serde_json::from_str::<HelperResult>(line).ok())
        .and_then(|r| r.err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::with_capture;

    /// 成功路径透传：剥掉子进程 fmt 前缀后只转发消息体（时间戳/级别/target 由
    /// 父进程日志层补全，info 级审计痕迹保留在 journal）。
    #[test]
    fn forward_helper_stderr_emits_audit_line_at_info_level() {
        let audit = "2026-08-21T12:00:00.000000Z  INFO crbs_priv_helper: \
audit op=chown path=/var/lib/crbs/x uid=0 gid=0 recursive=true caller_uid=998";
        let out = with_capture(|| {
            forward_helper_stderr(format!("{audit}\n\n").as_bytes());
        });
        assert!(out.contains("audit op=chown"), "captured: {out}");
        assert!(out.contains("caller_uid=998"), "captured: {out}");
        assert!(out.contains("INFO"), "captured: {out}");
        // 前缀须剥离：子进程时间戳与 target 进入消息体即双重格式化。
        assert!(
            !out.contains("2026-08-21T12:00:00.000000Z"),
            "captured: {out}"
        );
        assert!(!out.contains("crbs_priv_helper"), "captured: {out}");
        assert_eq!(out.matches("audit op=chown").count(), 1, "captured: {out}");
    }

    /// 无前缀行（panic 回溯、libc 报错等）原样透传，不匹配即不剥离。
    #[test]
    fn forward_helper_stderr_passes_through_lines_without_prefix() {
        let raw = "thread 'main' panicked at helper/src/main.rs:1:1:";
        let out = with_capture(|| {
            forward_helper_stderr(format!("{raw}\n").as_bytes());
        });
        assert!(out.contains(raw), "captured: {out}");
    }

    #[test]
    fn forward_helper_stderr_skips_blank_lines() {
        let out = with_capture(|| {
            forward_helper_stderr(b"\n   \n\t\n");
        });
        assert!(
            out.lines().all(|l| l.trim().is_empty()),
            "no event expected, captured: {out}"
        );
    }

    /// 错误 JSON：取出 err 字段原文（含类别前缀，供调用方映射）。
    #[test]
    fn parse_helper_error_extracts_err_from_json() {
        assert_eq!(
            parse_helper_error(r#"{"ok":null,"err":"permission denied: path not allowed"}"#),
            Some("permission denied: path not allowed".to_string())
        );
        assert_eq!(
            parse_helper_error("line1\nline2\n{\"err\":\"boom\"}"),
            Some("boom".to_string())
        );
    }

    #[test]
    fn parse_helper_error_returns_none_for_success_and_garbage() {
        assert_eq!(parse_helper_error(r#"{"ok":null,"err":null}"#), None);
        assert_eq!(parse_helper_error(""), None);
        assert_eq!(parse_helper_error("garbage output\nstill not json"), None);
    }

    /// helper 缺失时快速失败（spawn ENOENT），非挂起/panic——无需真实 helper 即可跑。
    #[test]
    fn write_cgroup_file_fails_fast_when_helper_missing() {
        let backend = HelperBackend::new(
            PathBuf::from("/nonexistent/crbs-priv-helper"),
            PathBuf::from("/var/lib/crbs"),
        );
        let started = std::time::Instant::now();
        let err = backend
            .write_cgroup_file(
                "/sys/fs/cgroup/machine.slice/machine-x.scope/payload/memory.max",
                "1073741824",
            )
            .expect_err("must fail with missing helper");
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        assert!(
            err.to_string().contains("/nonexistent/crbs-priv-helper"),
            "error should mention helper path: {err}"
        );
    }

    /// terminate-machine 同 helper 缺失快速失败（协议往返无真实 root helper，
    /// 以 ENOENT 快路径钉协议构造不挂起）。
    #[test]
    fn terminate_machine_fails_fast_when_helper_missing() {
        let backend = HelperBackend::new(
            PathBuf::from("/nonexistent/crbs-priv-helper"),
            PathBuf::from("/var/lib/crbs"),
        );
        let started = std::time::Instant::now();
        let err = backend
            .terminate_machine("crbs-9c714595-22")
            .expect_err("must fail with missing helper");
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        assert!(
            err.to_string().contains("/nonexistent/crbs-priv-helper"),
            "error should mention helper path: {err}"
        );
    }
}
