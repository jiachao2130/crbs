// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs-server run`：HTTP API 服务启动参数。

use std::path::PathBuf;

use clap::Args;

/// Arguments for starting the HTTP API service.
#[derive(Args, Debug)]
pub struct RunArgs {
    /// Listen address (default from server.toml, or 127.0.0.1:9090 if not configured)
    #[arg(short, long)]
    pub listen: Option<String>,
    /// pid/port file directory (default /run/crbs or {crbs_root}/run)
    #[arg(long)]
    pub run_dir: Option<PathBuf>,
    /// Enable product management endpoints (init/clean).
    /// If not specified, uses the value in /etc/crbs/server.toml.
    #[arg(long)]
    pub allow_product_management: Option<bool>,
    /// Graceful shutdown timeout in seconds (default: 60, range 1..=3600)
    #[arg(long, default_value = "60", value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub shutdown_timeout: u64,
    /// Enable the Web UI dashboard and related pages.
    /// If not specified, uses the value in /etc/crbs/server.toml.
    #[arg(long)]
    pub web_ui_enabled: Option<bool>,
}
