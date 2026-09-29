// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 各子命令域共享的 helper：StateStore 构造、配置装载、按名查用户、
//! 列表类命令的 `--format` 输出格式。

use std::path::{Path, PathBuf};

use crbs_core::config::ServerConfig;
use crbs_core::StateStore;

/// 列表类命令的输出格式（与 crbs CLI 的同名枚举同语义；server 侧独立定义，
/// 不为两个值引 CLI crate）。仅成功路径 json 化，错误仍走 anyhow 文本 + 退出码；
/// json 恒为顶层对象含 `command` 键 + 资源复数键（与 crbs CLI 信封同构），
/// 字段手动选列——token hash / 密码哈希类敏感列绝不进任何形态输出。
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable text (default)
    Text,
    /// Machine-readable JSON (envelope with a command key)
    Json,
}

pub(super) async fn find_user_by_name(
    store: &StateStore,
    name: &str,
) -> anyhow::Result<crbs_core::User> {
    store
        .find_user_by_name(name)
        .await
        .map_err(|e| anyhow::anyhow!("find user '{}': {}", name, e))?
        .ok_or_else(|| anyhow::anyhow!("user '{}' not found", name))
}

pub(super) async fn load_state_store(config_dir: Option<&Path>) -> anyhow::Result<StateStore> {
    // root 唯一来源：server.toml 的 crbs_root（缺省 /var/lib/crbs），对 CLI 全部子命令生效；
    // crbs.toml 仅供 database_url 等引擎可调项，不提供 root。
    let server_root = load_server_root(config_dir).await?;
    let crbs_config = load_crbs_config(config_dir).await?;

    let store = match &crbs_config.database_url {
        Some(url) => StateStore::new_with_url(url, &server_root).await,
        None => {
            let db_path = resolve_db_path(config_dir, &server_root).await?;
            StateStore::new_with_db_path(&db_path, &server_root).await
        }
    };

    store.map_err(|e| anyhow::anyhow!("open state store: {e}"))
}

async fn load_server_root(config_dir: Option<&Path>) -> anyhow::Result<PathBuf> {
    let cfg = load_server_config(config_dir).await?;
    Ok(cfg.server_crbs_root())
}

/// 加载 server.toml（`--config-dir` 写入 CRBS_CONFIG_DIR 后走 `load_async`）。
async fn load_server_config(config_dir: Option<&Path>) -> anyhow::Result<ServerConfig> {
    if let Some(dir) = config_dir {
        if let Some(s) = dir.to_str() {
            std::env::set_var("CRBS_CONFIG_DIR", s);
        }
    }
    let server_config_path = config_dir
        .map(|d| d.join("server.toml"))
        .unwrap_or_else(|| PathBuf::from("/etc/crbs/server.toml"));
    Ok(ServerConfig::load_async(&server_config_path).await?)
}

async fn load_crbs_config(
    config_dir: Option<&Path>,
) -> anyhow::Result<crbs_core::config::CrbsConfig> {
    // CrbsConfig::load_async() 无参，配置目录经 CRBS_CONFIG_DIR env 传入。
    if let Some(dir) = config_dir {
        if let Some(s) = dir.to_str() {
            std::env::set_var("CRBS_CONFIG_DIR", s);
        }
    }
    Ok(crbs_core::config::CrbsConfig::load_async().await?)
}

async fn resolve_db_path(config_dir: Option<&Path>, crbs_root: &Path) -> anyhow::Result<PathBuf> {
    let server_config_path = config_dir
        .map(|d| d.join("server.toml"))
        .unwrap_or_else(|| PathBuf::from("/etc/crbs/server.toml"));
    let cfg = ServerConfig::load_async(&server_config_path).await?;
    Ok(cfg.state_db_path(crbs_root))
}
