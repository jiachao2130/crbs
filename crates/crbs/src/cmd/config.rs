// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs config` 命令入口：配置文件 schema 导出。

use crate::cli::ConfigCommand;

pub(crate) async fn handle_config(command: ConfigCommand) -> anyhow::Result<()> {
    match command {
        ConfigCommand::Schema => {
            // 零副作用导出（不读配置文件、不初始化特权后端、不落状态）；schema 编译期内嵌（include_str!），与代码同版本发布。
            println!("{}", crbs_core::config::CONFIG_SCHEMA_JSON);
        }
    }
    Ok(())
}
