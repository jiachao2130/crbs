// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs-server` CLI parsing and subcommand implementations.
//!
//! 子命令按域拆分到子模块，此处只留顶层 `App` / `Command` 与 re-export
//!（`crate::cli::*` 调用路径不变）。本模块及子模块、`src/local.rs` 的
//! `println!` / `print!` / `eprintln!` 为 CLI 交互输出例外，
//! 非日志；`src/server/**` 运行时路径禁用。

pub mod audit;
pub mod common;
pub mod gpg;
pub mod local;
pub mod product;
pub mod run;
pub mod token;
pub mod user;
pub mod worker;

pub use audit::{handle_audit, AuditCli, AuditCommand};
pub use gpg::{handle_gpg, GpgCli, GpgCommand};
pub use local::{InternalDaemonArgs, LocalCli, LocalCommand};
pub use product::{handle_product, AclCli, AclCommand, ProductCli, ProductCommand};
pub use run::RunArgs;
pub use token::{handle_token, TokenCli, TokenCommand};
pub use user::{handle_user, UserCli, UserCommand};
pub use worker::{handle_worker, WorkerCli, WorkerCommand};

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// crbs-server: HTTP API service and management CLI.
#[derive(Parser, Debug)]
#[command(name = "crbs-server")]
#[command(about = "CRBS HTTP API service")]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct App {
    /// Configuration directory (default /etc/crbs; can be set via CRBS_CONFIG_DIR env var)
    #[arg(long, global = true, env = "CRBS_CONFIG_DIR", value_parser = parse_config_dir)]
    pub config_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

/// `--config-dir` / `CRBS_CONFIG_DIR` 必须是非空绝对路径：
/// 相对值会让配置解析依赖进程 CWD（cron / systemd 下不可预测），在参数解析期拒绝。
fn parse_config_dir(s: &str) -> Result<PathBuf, String> {
    let dir = PathBuf::from(s);
    crbs_core::config::validation::validate_config_dir(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

/// crbs-server 子命令入口（各子命令实现见 `cmd` 模块）。
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the HTTP API service
    Run(RunArgs),
    /// Manage users
    User(UserCli),
    /// Manage user tokens
    Token(TokenCli),
    /// Manage worker nodes (register / list / rotate secret / remove)
    Worker(WorkerCli),
    /// Local daemon management
    Local(LocalCli),
    /// Manage product ACLs
    Product(ProductCli),
    /// Query audit logs
    Audit(AuditCli),
    /// Manage GPG keys (used for RPM signing)
    Gpg(GpgCli),
    /// Internal use: run as a local daemon for a long time
    #[command(hide = true)]
    InternalDaemon(InternalDaemonArgs),
    /// Generate shell completion scripts (bash/zsh/fish/powershell)
    Completions {
        /// Target shell
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_dir_rejects_relative_or_empty_at_clap_level() {
        for bad in ["relative/crbs", ".", ""] {
            let err = App::try_parse_from(["crbs-server", "--config-dir", bad, "run"])
                .expect_err(&format!("config dir {bad:?} should be rejected"));
            let msg = err.to_string();
            assert!(
                msg.contains("absolute path"),
                "expected absolute-path rejection for {bad:?}, got: {msg}"
            );
        }
        let app = App::try_parse_from(["crbs-server", "--config-dir", "/etc/crbs", "run"])
            .expect("absolute config dir should parse");
        assert_eq!(
            app.config_dir.as_deref(),
            Some(std::path::Path::new("/etc/crbs"))
        );
    }
}
