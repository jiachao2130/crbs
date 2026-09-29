// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs admin` 命令组：仅管理员可用的运维动作。

pub(crate) mod init;
pub(crate) mod rebuild_repo;
pub(crate) mod resource_profile;

use crate::cli::AdminCommand;
use anyhow::Result;

pub(crate) async fn handle_admin(command: AdminCommand) -> Result<()> {
    match command {
        AdminCommand::Init(args) => init::handle_init(args).await,
        AdminCommand::RebuildRepo(args) => rebuild_repo::handle_rebuild_repo(args).await,
        AdminCommand::ResourceProfile(args) => {
            resource_profile::handle_resource_profile(args).await
        }
    }
}
