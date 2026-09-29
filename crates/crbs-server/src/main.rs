// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! crbs-server：CRBS Hub 服务端——HTTP API（构建调度/产品管理/认证）与
//! 本地管理模式；启动后监听配置端口，向已注册 worker 派发排队构建。

use anyhow::Result;
use clap::{CommandFactory, Parser};
use crbs_core::exit_code;

use crbs_server::{cli, local, server};

fn main() -> std::process::ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            // 顶层错误输出例外：tracing 未初始化，stderr 是唯一通道。
            eprintln!("Error: failed to create tokio runtime: {e}");
            return std::process::ExitCode::from(exit_code::INTERNAL as u8);
        }
    };

    let result = runtime.block_on(run());
    // 强制关停：detached 后台任务（SSE/GC/签名）会阻止进程退出，超时 abort 剩余任务。
    runtime.shutdown_timeout(std::time::Duration::from_secs(3));

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            let code = classify_error(&e);
            // 顶层错误输出例外：终局错误直写 stderr。
            eprintln!("Error: {e:#}");
            std::process::ExitCode::from(code as u8)
        }
    }
}

fn classify_error(e: &anyhow::Error) -> i32 {
    if let Some(crbs_err) = e.downcast_ref::<crbs_core::error::CrbsError>() {
        return exit_code::crbs_error_exit_code(crbs_err);
    }
    exit_code::INTERNAL
}

async fn run() -> Result<()> {
    let app = match cli::App::try_parse() {
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

    crbs_core::logging::init_tracing("info");

    match app.command {
        cli::Command::Run(args) => {
            // 特权操作（mount/chroot/nspawn）已委托给 crbs-priv-helper；server 本身无特权运行。
            server::run(
                args.listen.as_deref(),
                app.config_dir.as_deref(),
                args.allow_product_management,
                Some(args.shutdown_timeout),
                args.run_dir.as_deref(),
                None,
                args.web_ui_enabled,
            )
            .await?;
        }
        cli::Command::User(user_cli) => {
            cli::handle_user(app.config_dir, user_cli).await?;
        }
        cli::Command::Token(token_cli) => {
            cli::handle_token(app.config_dir, token_cli).await?;
        }
        cli::Command::Worker(worker_cli) => {
            cli::handle_worker(app.config_dir, worker_cli).await?;
        }
        cli::Command::Product(product_cli) => {
            cli::handle_product(app.config_dir, product_cli).await?;
        }
        cli::Command::Gpg(gpg_cli) => {
            cli::handle_gpg(gpg_cli).await?;
        }
        cli::Command::Audit(audit_cli) => {
            cli::handle_audit(app.config_dir, audit_cli).await?;
        }
        cli::Command::Local(local_cli) => match local_cli.command {
            cli::LocalCommand::Start { run_dir } => {
                local::start(run_dir.as_deref(), app.config_dir.as_deref()).await?;
            }
            cli::LocalCommand::Stop { run_dir } => {
                local::stop(run_dir.as_deref(), app.config_dir.as_deref()).await?;
            }
            cli::LocalCommand::Status { run_dir } => {
                local::status(run_dir.as_deref(), app.config_dir.as_deref()).await?;
            }
        },
        cli::Command::InternalDaemon(args) => {
            server::run_local_daemon(args.run_dir.as_deref(), app.config_dir.as_deref()).await?;
        }
        cli::Command::Completions { shell } => {
            let mut cmd = cli::App::command();
            clap_complete::generate(shell, &mut cmd, "crbs-server", &mut std::io::stdout());
        }
    }

    Ok(())
}
