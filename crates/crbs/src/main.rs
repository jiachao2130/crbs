// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! crbs：CRBS 命令行客户端。本地构建、Hub 提交与产品/任务管理的统一 CLI 入口；按子命令分发到本地引擎或远端 API。

use crate::cli::{App, Cli, GlobalArgs};
use anyhow::{Error, Result};
use clap::Parser;
use crbs_core::exit_code;
use crbs_core::privilege::{get_caller_info, setup_privileges, CallerContext, PrivMode};

mod api;
mod cli;
mod cmd;
mod local_daemon;
mod remote;

#[cfg(test)]
mod test_support;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            let code = classify_error(&e);
            if !is_silent_exit(&e) {
                eprintln!("Error: {e:#}");
                // 语义退出码是稳定契约；错误正文后追加分类提示（4 usage / 5 权限 / 6 环境…）
                if let Some((name, hint)) = exit_code::exit_code_hint(code) {
                    eprintln!("hint: exit code {code} ({name}) - {hint}");
                }
            }
            std::process::ExitCode::from(code as u8)
        }
    }
}

fn classify_error(e: &Error) -> i32 {
    if let Some(crbs_err) = e.downcast_ref::<crbs_core::error::CrbsError>() {
        return exit_code::crbs_error_exit_code(crbs_err);
    }
    exit_code::INTERNAL
}

fn is_silent_exit(e: &Error) -> bool {
    e.downcast_ref::<crbs_core::error::CrbsError>()
        .map(|crbs_err| matches!(crbs_err, crbs_core::error::CrbsError::SilentExit { .. }))
        .unwrap_or(false)
}

async fn run() -> Result<()> {
    let app = match App::try_parse() {
        Ok(app) => app,
        Err(e) => {
            let code = match e.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                    exit_code::SUCCESS
                }
                _ => exit_code::USAGE,
            };
            let _ = e.print();
            std::process::exit(code);
        }
    };

    // RUST_LOG 优先于 -v/-q 映射的默认级别（见 init_tracing）
    init_logging(&app);

    if should_sweep_detach(&app.command) {
        cleanup_stale_detach_requests().await;
    }

    let caller = get_caller_info();
    let is_root = nix::unistd::getuid().is_root();
    let ctx = CallerContext::new(caller, is_root);

    // 远程模式不需要本地特权
    if !app.command.is_remote() {
        setup_privileges_for(&app.command)?;
    }

    let global = GlobalArgs {
        offline: app.offline,
    };
    cmd::dispatch::run(app, ctx, global).await
}

fn init_logging(app: &App) {
    let level = if app.verbose {
        "debug"
    } else if app.quiet {
        "warn"
    } else {
        "info"
    };
    crbs_core::logging::init_tracing(level);
}

/// 是否在启动时清扫过期 detach 请求临时文件。生产/清理方仅 Build（派生
/// detached 子进程）/ Gc（清残留）；其余命令跳过，省高频轮询下每次启动
/// 一次的 /tmp 扫描。
fn should_sweep_detach(cmd: &Cli) -> bool {
    matches!(cmd, Cli::Build { .. } | Cli::Gc { .. })
}

async fn cleanup_stale_detach_requests() {
    match crate::cmd::build::detach::cleanup_stale_detach_requests(std::time::Duration::from_secs(
        24 * 3600,
    ))
    .await
    {
        Ok((removed, skipped)) => {
            tracing::debug!(
                removed,
                skipped,
                "Cleaned up stale detach request files on startup"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to clean up stale detach request files");
        }
    }
}

fn setup_privileges_for(command: &Cli) -> Result<()> {
    match command {
        Cli::Gc { .. } => {
            setup_privileges(PrivMode::Full)?;
        }
        Cli::Init { .. }
        | Cli::Build { .. }
        | Cli::Shell { .. }
        | Cli::Clean { .. }
        | Cli::Debug { .. }
        | Cli::Cancel { .. }
        | Cli::DetachedRun { .. }
        | Cli::Sign { .. } => {
            setup_privileges(PrivMode::Restricted)?;
        }
        Cli::Status { .. }
        | Cli::Logs { .. }
        | Cli::Diff { .. }
        | Cli::Verify { .. }
        | Cli::Products { .. }
        | Cli::Download { .. }
        | Cli::Builds { .. }
        | Cli::Nihao { .. }
        | Cli::Ping { .. }
        | Cli::Whoami { .. }
        | Cli::Admin { .. }
        | Cli::Remote { .. }
        | Cli::Config { .. }
        | Cli::Rebuild { .. } => {
            setup_privileges(PrivMode::Unprivileged)?;
        }
        Cli::Completions { .. } => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::should_sweep_detach;
    use crate::cli::Cli;
    use clap::Parser;

    /// Build / Gc（detach 文件生产与清理方）true，其余（status 为只读代表）false。
    #[test]
    fn should_sweep_detach_build_and_gc_only() {
        let build =
            Cli::try_parse_from(["crbs", "build", "--product", "fedora", "pkg-1.0-1.src.rpm"])
                .unwrap();
        assert!(should_sweep_detach(&build));

        let gc = Cli::try_parse_from(["crbs", "gc"]).unwrap();
        assert!(should_sweep_detach(&gc));

        let status = Cli::try_parse_from(["crbs", "status"]).unwrap();
        assert!(!should_sweep_detach(&status));
    }
}
