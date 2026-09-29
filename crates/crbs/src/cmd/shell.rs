// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! shell/debug 子命令：进入构建环境或执行单条命令。

use crate::cli::validate_product;
use crate::cli::{CommandOutput, ContainerParams, OutputFormat};
use crbs_core::bind::parse_bind_spec;
use crbs_core::config::CrbsConfig;
use crbs_core::engine::BuildEngine;
use crbs_core::privilege::CallerContext;
use crbs_core::StateStore;
use std::io::IsTerminal;
use tracing::info;

pub(crate) struct ShellArgs {
    pub product: String,
    pub command: Option<String>,
    pub binds: Vec<String>,
    pub container: ContainerParams,
    pub format: OutputFormat,
}

pub(crate) struct DebugArgs {
    pub task: String,
    pub command: Option<String>,
    pub binds: Vec<String>,
    pub container: ContainerParams,
    pub format: OutputFormat,
}

/// `crbs shell` 统一输出：json 摘要在 shell 退出后打印，text 模式 stdout 静默；
/// 顶层 `command` 信封键（同 json_error_contract），会话命令撞名改 `session_command`。
#[derive(serde::Serialize)]
struct ShellOutput {
    command: &'static str,
    product: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_command: Option<String>,
    interactive: bool,
}

impl CommandOutput for ShellOutput {
    fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    fn print_text(&self) {
        // 会话 stdout 属容器内进程：crbs 自身不追加输出（进入提示走 info!/stderr）。
    }
}

/// `crbs debug` 统一输出。interactive 由 engine 判定（stdin is_terminal），handler
/// 不强加；顶层 `command` 信封键，会话命令撞名改 `session_command`（同 ShellOutput）。
#[derive(serde::Serialize)]
struct DebugOutput {
    command: &'static str,
    task_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_command: Option<String>,
}

impl CommandOutput for DebugOutput {
    fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    fn print_text(&self) {
        // 同 ShellOutput：debug 会话结束后 stdout 保持静默。
    }
}

async fn parse_binds(specs: &[String]) -> anyhow::Result<Vec<crbs_core::bind::UserBind>> {
    let mut binds = Vec::with_capacity(specs.len());
    for spec in specs {
        binds.push(parse_bind_spec(spec).await?);
    }
    Ok(binds)
}

pub(crate) async fn handle_shell(
    args: ShellArgs,
    _ctx: &CallerContext,
    global: crate::cli::GlobalArgs,
) -> anyhow::Result<()> {
    let ShellArgs {
        product,
        command,
        binds,
        container,
        format,
    } = args;

    validate_product(&product)?;

    let ContainerParams {
        backend,
        no_network,
        memory_max,
        cpu_quota,
    } = container;

    // hub `/resolved` 加载配置；显式 `--remote`/`--token`/`--ca-cert` override 未接入，
    // 仍走 profile `remote.default` / `CRBS_TOKEN` env fallback；--offline 由全局 `GlobalArgs` 控制。
    let config_target = crate::remote::resolve_config_target(None, None, None).await?;
    let config =
        crate::api::product::load_product_config(&product, config_target.as_ref(), global.offline)
            .await?;
    crate::api::product::log_config_source(&product, config_target.as_ref(), global.offline);

    let _effective_backend =
        crate::cli::validate_container_params(&backend, &memory_max, &cpu_quota, &config, false)
            .await?;

    let user_binds = parse_binds(&binds).await?;

    info!("Entering shell for product: {}", product);
    let interactive = command.is_none() && std::io::stdin().is_terminal();
    let network = if no_network { Some(false) } else { None };
    let engine =
        BuildEngine::new_from_config(&product, backend.as_deref(), None, network, config).await?;
    // engine 消费 command；json 摘要需要留存一份。
    let command_summary = command.clone();
    engine.shell(command, interactive, user_binds).await?;
    let output = ShellOutput {
        command: "shell",
        product,
        session_command: command_summary,
        interactive,
    };
    format.print(&output)?;
    Ok(())
}

pub(crate) async fn handle_debug(
    args: DebugArgs,
    ctx: &CallerContext,
    global: crate::cli::GlobalArgs,
) -> anyhow::Result<()> {
    let DebugArgs {
        task,
        command,
        binds,
        container,
        format,
    } = args;

    let ContainerParams {
        backend,
        no_network,
        memory_max,
        cpu_quota,
    } = container;

    let crbs_cfg = CrbsConfig::load_async().await?;
    let state = StateStore::open_for_engine(&crbs_cfg.crbs_root).await?;
    let user_filter = crate::cmd::visible_user_filter(ctx);
    // debug 的 ID 域是 build；DebugOutput.task_id 字段名属 CLI/JSON 接口契约，实存 build_id。
    let build_id = super::resolve_short_id(&task, &state, user_filter).await?;

    info!("Debugging build: {}", build_id);

    let record = state
        .get_build(build_id)
        .await?
        // 记录不存在 = NotFound（USAGE=4），提示补 id 来源（build id 见任务详情 child builds）。
        .ok_or_else(|| crbs_core::error::CrbsError::NotFound {
            message: format!("Build {build_id} not found. Run 'crbs status' to list builds."),
        })?;

    if record.phase == "building" {
        // 构建未终态属状态机冲突——Conflict（USAGE=4），不落 INTERNAL(1)。
        return Err(crbs_core::error::CrbsError::Conflict {
            message: format!("Build {} is still in progress", build_id),
        }
        .into());
    }

    let recorded_backend = record.backend.as_deref().unwrap_or("chroot");
    if let Some(ref cli_backend) = backend {
        if cli_backend != recorded_backend {
            // 参数与记录不一致属参数误用——ValidationFailed（USAGE=4）。
            return Err(crbs_core::error::CrbsError::ValidationFailed {
                message: format!(
                    "Build {} was created with backend '{}'; cannot debug with '{}'. \
                     Remove --backend or use --backend {}",
                    build_id, recorded_backend, cli_backend, recorded_backend
                ),
            }
            .into());
        }
    }

    let config = resolve_debug_config(&state, build_id, &record.product, global.offline).await?;

    let _effective_backend = crate::cli::validate_container_params(
        &Some(recorded_backend.to_string()),
        &memory_max,
        &cpu_quota,
        &config,
        true,
    )
    .await?;

    let user_binds = parse_binds(&binds).await?;

    let cli_limits = crbs_core::ResourceLimits {
        memory_max,
        cpu_quota,
    };
    let network = if no_network { Some(false) } else { None };
    let engine = BuildEngine::new_from_config(
        &record.product,
        Some(recorded_backend),
        Some(cli_limits),
        network,
        config,
    )
    .await?;
    // engine 消费 command；json 摘要需要留存一份。
    let command_summary = command.clone();
    engine.debug(build_id, command, user_binds).await?;
    let output = DebugOutput {
        command: "debug",
        task_id: build_id,
        session_command: command_summary,
    };
    format.print(&output)?;
    Ok(())
}

/// 优先使用构建时锚定的产品配置快照：debug 环境与构建环境同源，不受 hub
/// `/resolved` 或磁盘配置后续变更影响；旧构建无快照或快照不可解析时回落当前配置。
async fn resolve_debug_config(
    state: &StateStore,
    build_id: i64,
    product: &str,
    offline: bool,
) -> anyhow::Result<crbs_core::config::Config> {
    match state.get_build_product_config_toml(build_id).await? {
        Some(toml) => {
            match crate::api::product::load_product_config_from_snapshot(product, &toml).await {
                Ok(config) => {
                    info!(build_id, "Using product config recorded at build time");
                    Ok(config)
                }
                Err(e) => {
                    tracing::warn!(
                        build_id,
                        error = %e,
                        "Recorded product config snapshot is unusable; falling back to the current product config"
                    );
                    load_current_debug_config(product, offline).await
                }
            }
        }
        None => {
            tracing::warn!(
                build_id,
                "Build has no product config snapshot; falling back to the current product config, debug environment may differ from build time"
            );
            load_current_debug_config(product, offline).await
        }
    }
}

/// 无可用快照时的回落路径：沿用 hub `/resolved`（或磁盘/offline）当前配置。
async fn load_current_debug_config(
    product: &str,
    offline: bool,
) -> anyhow::Result<crbs_core::config::Config> {
    let config_target = crate::remote::resolve_config_target(None, None, None).await?;
    let config =
        crate::api::product::load_product_config(product, config_target.as_ref(), offline).await?;
    crate::api::product::log_config_source(product, config_target.as_ref(), offline);
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_output_json_roundtrip() {
        let out = ShellOutput {
            command: "shell",
            product: "cc9".to_string(),
            session_command: None,
            interactive: true,
        };
        let parsed: serde_json::Value = serde_json::from_str(&out.to_json().unwrap()).unwrap();
        assert_eq!(parsed["command"], "shell");
        assert_eq!(parsed["product"], "cc9");
        assert!(parsed.get("session_command").is_none(), "None 字段应省略");
        assert_eq!(parsed["interactive"], true);

        let out = ShellOutput {
            command: "shell",
            product: "cc9".to_string(),
            session_command: Some("rpmbuild -ba hello.spec".to_string()),
            interactive: false,
        };
        let parsed: serde_json::Value = serde_json::from_str(&out.to_json().unwrap()).unwrap();
        assert_eq!(parsed["command"], "shell");
        assert_eq!(parsed["session_command"], "rpmbuild -ba hello.spec");
        assert_eq!(parsed["interactive"], false);
    }

    #[test]
    fn debug_output_json_roundtrip() {
        let out = DebugOutput {
            command: "debug",
            task_id: 42,
            session_command: Some("bash".to_string()),
        };
        let parsed: serde_json::Value = serde_json::from_str(&out.to_json().unwrap()).unwrap();
        assert_eq!(parsed["command"], "debug");
        assert_eq!(parsed["task_id"], 42);
        assert_eq!(parsed["session_command"], "bash");

        let out = DebugOutput {
            command: "debug",
            task_id: 7,
            session_command: None,
        };
        let parsed: serde_json::Value = serde_json::from_str(&out.to_json().unwrap()).unwrap();
        assert_eq!(parsed["command"], "debug");
        assert_eq!(parsed["task_id"], 7);
        assert!(parsed.get("session_command").is_none(), "None 字段应省略");
    }

    /// 隔离全局配置与磁盘产品配置：磁盘配置固定 bash，用于对照快照内容。
    fn write_debug_fixture(dir: &std::path::Path) {
        let root = dir.join("crbs_root");
        std::fs::write(
            dir.join("crbs.toml"),
            format!(
                "crbs_root = \"{}\"\nresult_dir = \"{}\"\nshared_layers_dir = \"{}\"\n\
                 tmp_dir = \"{}\"\ntmpfs_dir = \"{}\"\n",
                root.display(),
                root.join("results").display(),
                root.join("shared_layers").display(),
                dir.join("tmp").display(),
                dir.join("tmpfs").display(),
            ),
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("products")).unwrap();
        std::fs::write(
            dir.join("products/mydist.toml"),
            "product = \"mydist\"\nbase_packages = [\"bash\"]\nrepos = []\n",
        )
        .unwrap();
    }

    /// 造一条挂任务的构建行（任务行是 builds.task_id NOT NULL 的前置）。
    async fn seed_build(store: &StateStore) -> i64 {
        let task_id = store
            .insert_task(crbs_core::TaskInsert {
                product: "mydist",
                pkg_name: "hello",
                user: "",
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .insert_build(crbs_core::BuildInsert {
                product: "mydist",
                pkg_name: "hello",
                backend: "chroot",
                user: "",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap()
    }

    /// 快照优先：构建时配置（zsh）覆盖磁盘当前配置（bash）——debug 与构建同源。
    #[tokio::test]
    async fn resolve_debug_config_prefers_recorded_snapshot() {
        crate::test_support::pin_setuid_privilege_backend();
        let tmp = tempfile::tempdir().unwrap();
        write_debug_fixture(tmp.path());
        let _env = crate::test_support::EnvGuard::new(tmp.path());
        let store = StateStore::new(tmp.path()).await.unwrap();
        let build_id = seed_build(&store).await;
        store
            .set_build_product_config_toml(
                build_id,
                "product = \"mydist\"\nbase_packages = [\"zsh\"]\nrepos = []\n",
            )
            .await
            .unwrap();

        let config = resolve_debug_config(&store, build_id, "mydist", true)
            .await
            .unwrap();
        assert!(config.base_packages.contains(&"zsh".to_string()));
        assert!(!config.base_packages.contains(&"bash".to_string()));
    }

    /// 旧构建无快照：debug 回落当前配置（磁盘 / offline 分支）。
    #[tokio::test]
    async fn resolve_debug_config_falls_back_without_snapshot() {
        crate::test_support::pin_setuid_privilege_backend();
        let tmp = tempfile::tempdir().unwrap();
        write_debug_fixture(tmp.path());
        let _env = crate::test_support::EnvGuard::new(tmp.path());
        let store = StateStore::new(tmp.path()).await.unwrap();
        let build_id = seed_build(&store).await;

        let config = resolve_debug_config(&store, build_id, "mydist", true)
            .await
            .unwrap();
        assert!(config.base_packages.contains(&"bash".to_string()));
    }

    /// 快照损坏：只降级回落当前配置，不让 debug 直接失败。
    #[tokio::test]
    async fn resolve_debug_config_falls_back_on_unparsable_snapshot() {
        crate::test_support::pin_setuid_privilege_backend();
        let tmp = tempfile::tempdir().unwrap();
        write_debug_fixture(tmp.path());
        let _env = crate::test_support::EnvGuard::new(tmp.path());
        let store = StateStore::new(tmp.path()).await.unwrap();
        let build_id = seed_build(&store).await;
        store
            .set_build_product_config_toml(build_id, "not = [valid toml")
            .await
            .unwrap();

        let config = resolve_debug_config(&store, build_id, "mydist", true)
            .await
            .unwrap();
        assert!(config.base_packages.contains(&"bash".to_string()));
    }
}
