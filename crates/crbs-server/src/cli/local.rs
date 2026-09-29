// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs-server local`：本地守护进程管理（start/stop/status）；隐藏的 `internal-daemon` 是 `local start` 的常驻形态，同属本域。

use std::path::PathBuf;

use clap::{Args, Subcommand};

/// Local daemon management subcommands.
#[derive(Args, Debug)]
pub struct LocalCli {
    #[command(subcommand)]
    pub command: LocalCommand,
}

/// Local daemon operations (start / stop / status).
#[derive(Subcommand, Debug)]
pub enum LocalCommand {
    /// Start the local daemon
    Start {
        /// pid/port file directory (default /run/crbs or {crbs_root}/run)
        #[arg(long)]
        run_dir: Option<PathBuf>,
    },
    /// Stop the local daemon
    Stop {
        /// pid/port file directory
        #[arg(long)]
        run_dir: Option<PathBuf>,
    },
    /// Show local daemon status
    Status {
        /// pid/port file directory
        #[arg(long)]
        run_dir: Option<PathBuf>,
    },
}

/// Internal use: run as a local daemon for a long time.
#[derive(Args, Debug)]
pub struct InternalDaemonArgs {
    /// pid/port file directory
    #[arg(long)]
    pub run_dir: Option<PathBuf>,
}
