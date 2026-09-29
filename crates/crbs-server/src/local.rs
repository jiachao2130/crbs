// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs-server local start|stop|status` 实现。本文件 `println!`/`print!`/`eprintln!`
//! 均为 CLI 交互输出例外，非日志；server 运行时路径（`src/server/**`）禁用。

use nix::libc;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use crbs_core::config::{CrbsConfig, ServerConfig};
use fs4::tokio::AsyncFileExt;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const STARTUP_POLL: Duration = Duration::from_millis(200);
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
/// stop 等待上限：SIGTERM 后 drain 最长 shutdown_timeout（默认 60s）+ 活跃构建宽限，等不到保留文件交 daemon 自己的退出清理。
const STOP_TIMEOUT: Duration = Duration::from_secs(90);
const STOP_POLL: Duration = Duration::from_millis(200);

/// 计算 effective run_dir：CLI > server.toml [local].run_dir > 默认值。
async fn effective_run_dir(run_dir: Option<&Path>, config_dir: Option<&Path>) -> Result<PathBuf> {
    if let Some(d) = run_dir {
        return Ok(d.to_path_buf());
    }
    let server_config = load_server_config(config_dir).await?;
    if let Some(d) = server_config.local.run_dir {
        return Ok(d);
    }
    let crbs_config = CrbsConfig::load_async().await?;
    Ok(crate::server::default_run_dir(&crbs_config.crbs_root))
}

async fn load_server_config(config_dir: Option<&Path>) -> Result<ServerConfig> {
    let path = config_dir
        .map(|d| d.join("server.toml"))
        .unwrap_or_else(|| PathBuf::from("/etc/crbs/server.toml"));
    ServerConfig::load_async(&path)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// 启动本地 daemon：派生 `crbs-server __internal-daemon` 并等待 portfile。
pub async fn start(run_dir: Option<&Path>, config_dir: Option<&Path>) -> Result<()> {
    let run_dir = effective_run_dir(run_dir, config_dir).await?;

    tokio::fs::create_dir_all(&run_dir).await?;

    if let Some(port) = discover(&run_dir).await? {
        println!(
            "Local daemon already running on 127.0.0.1:{} (run_dir: {})",
            port,
            run_dir.display()
        );
        return Ok(());
    }

    // 用文件锁避免多个 client 同时启动多个 daemon。
    let lock_path = run_dir.join("crbs-server.lock");

    // 锁文件权限修正（0660+crbs 组）必须在 open 之前：上一身份遗留的坏权限会让
    // truncate-open EACCES，open 之后再修则目标场景（open 被挡）永远不可达；非 root
    // 修不动走既有降级契约（EPERM），open 的报错给出真实原因。
    #[cfg(unix)]
    fix_lock_file_perms(&lock_path).await;

    let lock_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&lock_path)
        .await
        .with_context(|| format!("open lock file {}", lock_path.display()))?;

    // open 新建文件带 umask 默认权限（如 0644），再归一保证下一身份不被 EACCES 挡（存量合规 no-op）。
    #[cfg(unix)]
    fix_lock_file_perms(&lock_path).await;

    let lock_deadline = tokio::time::Instant::now() + LOCK_TIMEOUT;
    loop {
        match lock_file.try_lock_exclusive() {
            Ok(()) => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if let Some(port) = discover(&run_dir).await? {
                    println!(
                        "Local daemon already running on 127.0.0.1:{} (run_dir: {})",
                        port,
                        run_dir.display()
                    );
                    return Ok(());
                }
                if tokio::time::Instant::now() >= lock_deadline {
                    anyhow::bail!(
                        "Timeout waiting for another crbs-server local start to finish (lock: {})",
                        lock_path.display()
                    );
                }
                tokio::time::sleep(STARTUP_POLL).await;
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "acquire daemon start lock {}: {}",
                    lock_path.display(),
                    e
                ));
            }
        }
    }

    // 拿到锁后再检查一次：可能上一个持锁进程已经启动成功。
    if let Some(port) = discover(&run_dir).await? {
        println!(
            "Local daemon already running on 127.0.0.1:{} (run_dir: {})",
            port,
            run_dir.display()
        );
        return Ok(());
    }

    let mut cmd = tokio::process::Command::new(std::env::current_exe()?);
    cmd.arg("internal-daemon").arg("--run-dir").arg(&run_dir);
    if let Some(dir) = config_dir {
        cmd.arg("--config-dir").arg(dir);
    }

    // stdout/stderr 重定向到 run_dir 日志文件：tracing 写 stderr（crbs-core
    // logging.rs），stdio 全 null 会连 daemon 运行期日志一起丢，启动失败无从排查。
    let log_path = daemon_log_path(&run_dir);
    let daemon_log: Option<std::fs::File> = match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .await
    {
        Ok(f) => {
            // 权限不变量：文件 0660 + crbs 组。chmod 失败要 warn
            //（权限未生效）；chown 失败仅 debug（非 root 必然 EPERM，预期路径）。
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = f
                .set_permissions(std::fs::Permissions::from_mode(0o660))
                .await
            {
                tracing::warn!(
                    path = %log_path.display(),
                    error = %e,
                    "failed to chmod daemon log file to 0660 (perms may not be effective)"
                );
            }
            crbs_core::privilege::chown_to_crbs_group_async(&log_path, false, "local daemon log")
                .await;
            Some(f.into_std().await)
        }
        Err(e) => {
            // 打不开日志不阻断 start：降级 null stdio。
            tracing::warn!(
                path = %log_path.display(),
                error = %e,
                "failed to open daemon log file; falling back to null stdio"
            );
            None
        }
    };

    cmd.stdin(Stdio::null()).kill_on_drop(false);
    let mut stdio_redirected_to_log = false;
    match daemon_log {
        // `From<File> for Stdio` 消费 File，故 stderr try_clone（dup 同一打开文件描述，append 双路原子追加）。
        Some(f) => match f.try_clone() {
            Ok(stderr_file) => {
                cmd.stdout(Stdio::from(f)).stderr(Stdio::from(stderr_file));
                stdio_redirected_to_log = true;
            }
            Err(e) => {
                tracing::warn!(
                    path = %log_path.display(),
                    error = %e,
                    "failed to duplicate daemon log handle; falling back to null stdio"
                );
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
            }
        },
        None => {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }
    }

    unsafe {
        cmd.pre_exec(|| {
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
            Ok(())
        });
    }

    let mut child = cmd.spawn().context("spawn crbs-server internal daemon")?;
    let child_pid = child
        .id()
        .ok_or_else(|| anyhow::anyhow!("daemon pid not available"))?;

    let port_file = run_dir.join("crbs-server.port");
    let mut waited = Duration::ZERO;
    let port = loop {
        if let Ok(text) = tokio::fs::read_to_string(&port_file).await {
            if let Ok(port) = text.trim().parse::<u16>() {
                break port;
            }
        }
        if waited >= STARTUP_TIMEOUT {
            // 杀子进程前最后复读一次 portfile：收窄循环顶读→start_kill 的 µs 级
            // 竞态窗口，不误杀恰在此间隙就绪的实例（误杀后冷启动重付迁移/seed 成本）。
            if let Ok(text) = tokio::fs::read_to_string(&port_file).await {
                if let Ok(port) = text.trim().parse::<u16>() {
                    break port;
                }
            }
            if let Err(e) = child.start_kill() {
                tracing::warn!(
                    pid = %child_pid,
                    error = %e,
                    "failed to kill local daemon after startup timeout"
                );
            }
            anyhow::bail!(
                "{}",
                startup_timeout_message(child_pid, &log_path, stdio_redirected_to_log)
            );
        }
        tokio::time::sleep(STARTUP_POLL).await;
        waited += STARTUP_POLL;
    };

    println!(
        "Started local daemon on 127.0.0.1:{} (pid={}, run_dir: {})",
        port,
        child_pid,
        run_dir.display()
    );
    Ok(())
}

/// 停止本地 daemon。
pub async fn stop(run_dir: Option<&Path>, config_dir: Option<&Path>) -> Result<()> {
    let run_dir = effective_run_dir(run_dir, config_dir).await?;

    let pid_file = run_dir.join("crbs-server.pid");
    if !tokio::fs::try_exists(&pid_file).await.unwrap_or(false) {
        println!(
            "No local daemon pidfile found (run_dir: {})",
            run_dir.display()
        );
        return Ok(());
    }

    let text = tokio::fs::read_to_string(&pid_file).await?;
    // 空 pidfile 消歧：空内容是 daemon create_new→write_all 写入窗口，或 start 被
    // SIGKILL 留下的永久残留，只能靠 start 锁探测——锁空闲=无 start=残留，安全清理；
    // 锁被占=确有 start，保留（误清会把启动中的 daemon 变孤儿：无人续写心跳，idle
    // watcher 误停机）。损坏（非空非数字）按陈旧残留清理并成功返回，防残留卡 parse 错误。
    if text.trim().is_empty() {
        if start_lock_idle(&run_dir).await {
            println!("Pidfile is empty and no start in progress; cleaning stale files");
            let _ = crate::server::remove_pid_port_files(&run_dir).await;
            return Ok(());
        }
        println!("Pidfile is empty; daemon may be starting; leaving files alone");
        return Ok(());
    }
    let pid: i32 = match text.trim().parse() {
        Ok(p) => p,
        Err(_) => {
            println!("Pidfile is corrupt (unparseable content); cleaning stale files");
            let _ = crate::server::remove_pid_port_files(&run_dir).await;
            return Ok(());
        }
    };

    if is_process_alive(pid) {
        // 仅确认是 crbs-server 才发信号；PID 复用或身份不可确认（/proc 不可读）
        // 都只清理文件。三态文案必须区分："不可确认"（hidepid）≠"确认复用"。
        match is_crbs_server_process(pid) {
            Some(true) => {} // 确认是 crbs-server，继续发信号。
            Some(false) => {
                // PID 复用：pidfile 是上次异常退出的残留，现持有者是无关进程。
                println!(
                    "Pidfile is stale (pid {} now belongs to another process); cleaning files only",
                    pid
                );
                let _ = crate::server::remove_pid_port_files(&run_dir).await;
                return Ok(());
            }
            None => {
                println!(
                    "Cannot confirm pid {} identity (hidepid?); cleaning files only",
                    pid
                );
                let _ = crate::server::remove_pid_port_files(&run_dir).await;
                return Ok(());
            }
        }
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGTERM,
        )?;
        println!("Sent SIGTERM to local daemon (pid={})", pid);

        // 等进程真正退出再清文件：SIGTERM 后 drain 可持续到 shutdown_timeout；
        // 立即删 pid/port 会让并发 start 派生第二实例，旧实例退出清理又删新实例文件。
        let deadline = tokio::time::Instant::now() + STOP_TIMEOUT;
        while tokio::time::Instant::now() < deadline {
            if !is_process_alive(pid) {
                break;
            }
            tokio::time::sleep(STOP_POLL).await;
        }
        if is_process_alive(pid) {
            println!(
                "Daemon (pid={}) still draining after {:?}; leaving pid/port files to its own exit cleanup",
                pid, STOP_TIMEOUT
            );
            return Ok(());
        }
    } else {
        println!("Local daemon pid={} is not running", pid);
    }

    let _ = crate::server::remove_pid_port_files(&run_dir).await;
    Ok(())
}

/// 查看本地 daemon 状态。
pub async fn status(run_dir: Option<&Path>, config_dir: Option<&Path>) -> Result<()> {
    let run_dir = effective_run_dir(run_dir, config_dir).await?;

    match discover(&run_dir).await? {
        Some(port) => println!(
            "Local daemon is running on 127.0.0.1:{} (run_dir: {})",
            port,
            run_dir.display()
        ),
        None => println!(
            "Local daemon is not running (run_dir: {})",
            run_dir.display()
        ),
    }
    Ok(())
}

/// 发现本地 daemon，返回监听端口。
async fn discover(run_dir: &Path) -> Result<Option<u16>> {
    let pid_file = run_dir.join("crbs-server.pid");
    let port_file = run_dir.join("crbs-server.port");

    if !tokio::fs::try_exists(&pid_file).await.unwrap_or(false)
        || !tokio::fs::try_exists(&port_file).await.unwrap_or(false)
    {
        return Ok(None);
    }

    let pid_text = match tokio::fs::read_to_string(&pid_file).await {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let pid: i32 = match pid_text.trim().parse() {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };

    if !is_process_alive(pid) {
        return Ok(None);
    }

    // PID 复用（确认无关进程）→ 清残留文件让后续 start 自愈，否则 daemon 的
    // acquire_server_lock fail-closed 拒绝一切启动，CLI 探针永不恢复；身份不可
    // 确认（hidepid，/proc 不可读）保守不清理，按"未发现"返回，清理交 stop / daemon。
    match is_crbs_server_process(pid) {
        Some(true) => {}
        Some(false) => {
            tracing::warn!(
                pid = %pid,
                run_dir = %run_dir.display(),
                "pidfile points to a live non-crbs-server process (pid reuse); cleaning stale files"
            );
            let _ = crate::server::remove_pid_port_files(run_dir).await;
            return Ok(None);
        }
        None => return Ok(None),
    }

    let port_text = match tokio::fs::read_to_string(&port_file).await {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    // portfile 损坏按"未运行"优雅降级：报错会打断 start 的锁等待轮询，并发启动误报失败。
    match port_text.trim().parse::<u16>() {
        Ok(port) => Ok(Some(port)),
        Err(_) => {
            tracing::warn!(
                run_dir = %run_dir.display(),
                "portfile content is not a valid port; treating daemon as not running"
            );
            Ok(None)
        }
    }
}

/// 非阻塞探测 daemon start 锁是否空闲：拿到排他锁 = 无 start 进行中。供 stop 空
/// pidfile 消歧（与 start 同一锁文件、同一 fs4 flock），探测成功即释放；打不开或
/// 探测报错按"锁被占"返回 false——误保留可手工 rm，误清理会把启动中的 daemon 变孤儿。
async fn start_lock_idle(run_dir: &Path) -> bool {
    let lock_path = run_dir.join("crbs-server.lock");
    let file = match tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(
                path = %lock_path.display(),
                error = %e,
                "cannot open start lock for empty-pidfile probe; treating as busy"
            );
            return false;
        }
    };
    match file.try_lock_exclusive() {
        Ok(()) => {
            let _ = file.unlock_async().await;
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(e) => {
            tracing::warn!(
                path = %lock_path.display(),
                error = %e,
                "start lock probe failed; treating as busy"
            );
            false
        }
    }
}

/// 进程判活（同步版 getpgid 语义，与 core 的 async `is_process_alive` 同语义）。
/// `kill(pid, None)` 对存在但无权信号的进程返回 EPERM（root daemon + crbs 组 CLI
/// 属设计内场景），误判为死会让 stop 删活 daemon 的 pid/port 文件；getpgid 对存在
/// 进程不返回 EPERM：ESRCH=死，其余 Err=按活。pid<=0 一律按死（getpgid(0) 退化为调用者进程组）。
fn is_process_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    match nix::unistd::getpgid(Some(nix::unistd::Pid::from_raw(pid))) {
        Ok(_) => true,
        Err(nix::errno::Errno::ESRCH) => false,
        Err(_) => true,
    }
}

/// 锁文件权限归一（0660 + crbs 组）：存在且 mode != 0660 时 chmod（失败要 warn
/// = 权限未生效），再 chown 到 crbs 组（失败仅 debug，非 root 必然 EPERM，见
/// `chown_to_crbs_group_async`）；metadata 读不到按"尚未创建"跳过（open 后二次归一）。
#[cfg(unix)]
async fn fix_lock_file_perms(lock_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let need_fix = match tokio::fs::metadata(lock_path).await {
        Ok(m) => m.permissions().mode() & 0o777 != 0o660,
        Err(_) => false,
    };
    if need_fix {
        let lp = lock_path.to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            std::fs::set_permissions(&lp, std::fs::Permissions::from_mode(0o660))
        })
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e)));
        if let Err(e) = result {
            tracing::warn!(
                path = %lock_path.display(),
                error = %e,
                "failed to chmod lock file to 0660 (perms may not be effective)"
            );
        }
    }
    crbs_core::privilege::chown_to_crbs_group_async(lock_path, false, "local start lock").await;
}

/// daemon 日志文件路径（run_dir 下固定名）。固定名安全：start 全程持排他 flock +
/// pidfile 单活，同一时刻至多一个 daemon 写入；append 保多代日志（tracing 行自带时间戳）。
fn daemon_log_path(run_dir: &Path) -> PathBuf {
    run_dir.join("crbs-server.daemon.log")
}

/// 启动超时错误文案（抽出便于单测）。必须含日志路径：stdio 重定向到该文件后，
/// 那是唯一能查到 daemon 侧失败原因的地方；`log_active` 为 false 表示日志打开
///（或句柄复制）失败、stdio 已降级 null——文案注明降级，避免对着空日志排查。
fn startup_timeout_message(child_pid: u32, log_path: &Path, log_active: bool) -> String {
    let log_hint = if log_active {
        format!("daemon log: {}", log_path.display())
    } else {
        format!(
            "daemon log: {} (unavailable: open failed, daemon stdio fell back to null)",
            log_path.display()
        )
    };
    format!(
        "Local daemon did not write portfile within {:?}; pid={}; {}",
        STARTUP_TIMEOUT, child_pid, log_hint
    )
}

/// PID 身份确认：防 pidfile 残留 + PID 复用后向无关进程发信号或误判 "already
/// running"。三态：`Some(true)` = 确认 crbs-server（Linux 读 `/proc/<pid>/comm`，
/// crbs-server 名长 < 15 不会被内核截断；非 Linux 无 /proc，退化为仅存活判定）；
/// `Some(false)` = comm 可读但非 crbs-server；`None` = /proc 不可读（hidepid），无法确认。
fn is_crbs_server_process(pid: i32) -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string(format!("/proc/{pid}/comm")) {
            Ok(comm) => Some(comm.trim() == "crbs-server"),
            // 进程已退出或不可读：无法确认。
            Err(_) => None,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Some(is_process_alive(pid))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{daemon_log_path, fix_lock_file_perms, is_process_alive, startup_timeout_message};
    use std::path::Path;

    /// getpgid 判活语义回归：自身判活；0/负 pid 按死（getpgid(0) 是调用者进程组）；已退出子进程判死。
    #[test]
    fn is_process_alive_getpgid_semantics() {
        let own = std::process::id() as i32;
        assert!(is_process_alive(own));
        assert!(!is_process_alive(0));
        assert!(!is_process_alive(-5));

        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead_pid = child.id() as i32;
        child.wait().unwrap();
        assert!(!is_process_alive(dead_pid));
    }

    /// 权限修正可达性回归：上一身份遗留的 0644 锁文件在 open 前被归一为 0660。
    #[tokio::test]
    async fn fix_lock_file_perms_normalizes_0644_to_0660() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("crbs-server.lock");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        fix_lock_file_perms(&path).await;

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "lock file must be normalized to 0660");
    }

    /// 文件不存在时不创建、不报错：新文件由 open 之后的第二次归一处理。
    #[tokio::test]
    async fn fix_lock_file_perms_noop_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("absent.lock");
        fix_lock_file_perms(&path).await;
        assert!(!path.exists());
    }

    /// 回归：空 pidfile 消歧靠 start 锁——锁空闲（start 被 SIGKILL 的永久残留）自愈清理。
    #[tokio::test]
    async fn stop_cleans_empty_pidfile_when_start_lock_idle() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_file = tmp.path().join("crbs-server.pid");
        std::fs::write(&pid_file, b"").unwrap();

        super::stop(Some(tmp.path()), None).await.unwrap();

        assert!(
            !pid_file.exists(),
            "empty pidfile with no start in progress is stale residue and must be cleaned"
        );
    }

    /// 回归对偶：锁被占 = start 进行中 = 写入窗口内空 pidfile 必须保留（fs4 flock 模拟）。
    #[tokio::test]
    async fn stop_keeps_empty_pidfile_while_start_lock_held() {
        use fs4::tokio::AsyncFileExt;

        let tmp = tempfile::tempdir().unwrap();
        let pid_file = tmp.path().join("crbs-server.pid");
        std::fs::write(&pid_file, b"").unwrap();

        let lock_path = tmp.path().join("crbs-server.lock");
        let lock = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&lock_path)
            .await
            .unwrap();
        lock.try_lock_exclusive().unwrap();

        super::stop(Some(tmp.path()), None).await.unwrap();

        assert!(
            pid_file.exists(),
            "empty pidfile with a start in progress must be kept, not cleaned"
        );
    }

    /// 回归：启动超时文案必须含 daemon 日志路径与 pid（stdio 重定向后唯一排查线索）。
    #[test]
    fn startup_timeout_message_contains_daemon_log_path() {
        let msg =
            startup_timeout_message(4242, Path::new("/run/crbs/crbs-server.daemon.log"), true);
        assert!(
            msg.contains("crbs-server.daemon.log"),
            "timeout message must point to the daemon log, got: {msg}"
        );
        assert!(
            msg.contains("pid=4242"),
            "timeout message must carry pid, got: {msg}"
        );
        assert_eq!(
            daemon_log_path(Path::new("/run/crbs")).as_path(),
            Path::new("/run/crbs/crbs-server.daemon.log")
        );
    }

    /// 回归：stdio 降级 null 时超时文案必须注明降级（防空日志误导排查）。
    #[test]
    fn startup_timeout_message_notes_degraded_stdio() {
        let msg =
            startup_timeout_message(4242, Path::new("/run/crbs/crbs-server.daemon.log"), false);
        assert!(
            msg.contains("stdio fell back to null"),
            "degraded timeout message must note stdio fallback, got: {msg}"
        );
    }
}
