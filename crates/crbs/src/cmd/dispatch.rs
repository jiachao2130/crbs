// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! CLI 命令分发：全局参数、权限上下文与 JSON 错误信封。

use anyhow::Result;
use clap::CommandFactory;

use crate::cli::{App, Cli, GlobalArgs, ProbeArgs};
use crate::cmd;
use crate::remote;
use crbs_core::privilege::CallerContext;

/// 分发 CLI 命令到对应 handler；`main.rs` 只做参数解析→日志→权限→状态加载。
/// **note**：`global` 横切标志（`--offline` 等）仅穿给加载**产品配置**的
/// handler（build / init / clean / shell / debug / sign），其余路径不接。
pub async fn run(app: App, ctx: CallerContext, global: GlobalArgs) -> Result<()> {
    let json_guard = app.command.json_error_contract();
    if let Err(e) = dispatch(app, ctx, global).await {
        if let Some((command, format)) = json_guard {
            cmd::build::output::maybe_json_error_exit(command, &e, &format)?;
        }
        return Err(e);
    }
    Ok(())
}

/// nihao/ping/whoami 三别名共用的转发体：ProbeArgs 五元组直透
/// `cmd::nihao::handle_nihao`，仅命令名随入口变体参数化。
async fn handle_probe(command: &'static str, probe: ProbeArgs) -> Result<()> {
    cmd::nihao::handle_nihao(cmd::nihao::NihaoArgs {
        command,
        remote: probe.remote,
        token: probe.token,
        ca_cert: probe.ca_cert,
        daemon: probe.daemon,
        format: probe.format,
    })
    .await
}

/// dispatch 主体（状态加载 + 命令臂 match）；错误统一上抛，
/// 由 [`run`] 的 json_guard 收口。
async fn dispatch(app: App, ctx: CallerContext, global: GlobalArgs) -> Result<()> {
    let state_opt = if app.command.requires_state_store() {
        let needs_local = if let Some(args) = app.command.remote_resolve_args() {
            remote::resolve(args.remote, args.token, args.ca_cert, args.local)
                .await?
                .is_none()
        } else {
            true
        };
        if needs_local {
            let init_local = async {
                let cfg = crbs_core::config::CrbsConfig::load_async().await?;
                let state = crbs_core::StateStore::open_for_engine(&cfg.crbs_root).await?;
                Ok::<_, anyhow::Error>((cfg, state))
            };
            Some(init_local.await?)
        } else {
            None
        }
    } else {
        None
    };

    match app.command {
        Cli::DetachedRun { request_file } => {
            cmd::build::detach::run_detached_build(&request_file).await?;
        }
        Cli::Init {
            product,
            force,
            remote,
            token,
            ca_cert,
            format,
        } => {
            cmd::handle_init(
                cmd::InitArgs {
                    product,
                    force,
                    remote,
                    token,
                    ca_cert,
                    format,
                },
                ctx,
                global,
            )
            .await?;
        }
        Cli::Build(args) => {
            cmd::build::handle_build(args, ctx, global).await?;
        }
        Cli::Shell {
            product,
            command,
            bind,
            container,
            format,
        } => {
            cmd::shell::handle_shell(
                cmd::shell::ShellArgs {
                    product,
                    command,
                    binds: bind,
                    container,
                    format,
                },
                &ctx,
                global,
            )
            .await?;
        }
        Cli::Clean {
            product,
            remote,
            token,
            ca_cert,
            yes,
            format,
        } => {
            cmd::handle_clean(
                cmd::CleanArgs {
                    product,
                    remote,
                    token,
                    ca_cert,
                    yes,
                    format,
                },
                ctx,
                global,
            )
            .await?;
        }
        Cli::Debug {
            task,
            command,
            bind,
            container,
            format,
        } => {
            cmd::shell::handle_debug(
                cmd::shell::DebugArgs {
                    task,
                    command,
                    binds: bind,
                    container,
                    format,
                },
                &ctx,
                global,
            )
            .await?;
        }
        Cli::Status {
            task_pos,
            task,
            product,
            limit,
            format,
            all,
            filter,
            label,
            watch,
            profile,
            repair,
            remote_args,
        } => {
            cmd::status::handle_status(
                cmd::status::StatusArgs {
                    task: task_pos.or(task),
                    product,
                    limit,
                    format,
                    all,
                    filter,
                    label,
                    watch,
                    profile,
                    repair,
                    remote: remote_args.remote,
                    token: remote_args.token,
                    local: remote_args.local,
                },
                &ctx,
                state_opt.as_ref().map(|s| &s.1),
            )
            .await?;
        }
        Cli::Gc {
            results,
            product,
            dry_run,
            orphan_mounts,
            cache,
            all,
            policy,
            yes,
            format,
        } => match state_opt.as_ref() {
            Some((cfg, state)) => {
                cmd::gc::handle_gc(
                    cmd::gc::GcCliArgs {
                        results,
                        product,
                        dry_run,
                        orphan_mounts,
                        cache,
                        all,
                        policy,
                        yes,
                        format,
                    },
                    cfg,
                    state,
                )
                .await?;
            }
            None => {
                return Err(crbs_core::error::CrbsError::Internal(
                    "state store not initialized for 'gc'".to_string(),
                )
                .into());
            }
        },
        Cli::Logs {
            task,
            arch,
            follow,
            lines,
            editor,
            grep,
            format,
            remote_args,
        } => {
            cmd::logs::handle_logs(
                cmd::logs::LogsArgs {
                    task,
                    arch,
                    follow,
                    lines,
                    editor,
                    grep,
                    format,
                    remote: remote_args.remote,
                    token: remote_args.token,
                    local: remote_args.local,
                },
                &ctx,
                state_opt.as_ref().map(|s| &s.1),
            )
            .await?;
        }
        Cli::Cancel {
            task,
            format,
            remote_args,
        } => {
            cmd::handle_cancel(
                cmd::CancelArgs {
                    task,
                    format,
                    remote: remote_args.remote,
                    token: remote_args.token,
                    local: remote_args.local,
                },
                ctx,
                state_opt.as_ref().map(|s| &s.1),
            )
            .await?;
        }
        Cli::Verify {
            task_a,
            task_b,
            format,
        } => match state_opt.as_ref() {
            Some((_, state)) => {
                cmd::verify::handle_verify(task_a, task_b, format, &ctx, state).await?;
            }
            None => {
                return Err(crbs_core::error::CrbsError::Internal(
                    "state store not initialized for 'verify'".to_string(),
                )
                .into());
            }
        },
        Cli::Diff {
            left,
            right,
            format,
        } => match state_opt.as_ref() {
            Some((cfg, state)) => {
                cmd::diff::handle_diff(left, right, format, &ctx, cfg, state).await?;
            }
            None => {
                return Err(crbs_core::error::CrbsError::Internal(
                    "state store not initialized for 'diff'".to_string(),
                )
                .into());
            }
        },
        Cli::Builds {
            command,
            remote_args,
        } => {
            let state = state_opt.as_ref().map(|s| &s.1);
            cmd::builds::handle_builds(
                command,
                remote_args.remote,
                remote_args.token,
                remote_args.local,
                state,
                &ctx,
            )
            .await?;
        }
        Cli::Products {
            command,
            remote,
            token,
            local,
            format,
        } => {
            cmd::products::handle_products(command, remote, token, local, format).await?;
        }
        Cli::Rebuild {
            command,
            remote,
            token,
            local,
        } => {
            cmd::rebuild::handle_rebuild(cmd::rebuild::RebuildArgs {
                command,
                remote,
                token,
                local,
            })
            .await?;
        }
        Cli::Sign {
            task,
            key_id,
            gpg_home,
            remote_args,
            ca_cert,
            format,
        } => {
            let state = state_opt.as_ref().map(|s| &s.1);
            cmd::sign::handle_sign(
                cmd::sign::SignArgs {
                    task,
                    key_id,
                    gpg_home,
                    remote: remote_args.remote,
                    token: remote_args.token,
                    ca_cert,
                    local: remote_args.local,
                    format,
                },
                ctx,
                state,
                global,
            )
            .await?;
        }
        Cli::Download {
            task,
            output_dir,
            src,
            debuginfo,
            logs,
            arches,
            force,
            remote_args,
            format,
        } => {
            let state = state_opt.as_ref().map(|s| &s.1);
            cmd::download::handle_download(
                cmd::download::DownloadArgs {
                    task,
                    output_dir,
                    src,
                    debuginfo,
                    logs,
                    arches,
                    force,
                    remote: remote_args.remote,
                    token: remote_args.token,
                    local: remote_args.local,
                    format,
                },
                ctx,
                state,
            )
            .await?;
        }
        Cli::Nihao { probe } => handle_probe("nihao", probe).await?,
        Cli::Ping { probe } => handle_probe("ping", probe).await?,
        Cli::Whoami { probe } => handle_probe("whoami", probe).await?,
        Cli::Admin { command } => {
            cmd::admin::handle_admin(command).await?;
        }
        Cli::Remote { command } => {
            cmd::remote_profile::handle_remote(command).await?;
        }
        Cli::Config { command } => {
            cmd::config::handle_config(command).await?;
        }
        Cli::Completions { shell } => {
            let mut cmd = App::command();
            clap_complete::generate(shell, &mut cmd, "crbs", &mut std::io::stdout());
        }
    }

    Ok(())
}
