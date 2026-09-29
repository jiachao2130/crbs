// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs-server worker`：worker 节点管理子命令，含 `--output-config` 生成可部署 worker.toml。

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};

use super::common::load_state_store;

/// Worker management command entry.
#[derive(Args, Debug)]
pub struct WorkerCli {
    #[command(subcommand)]
    pub command: WorkerCommand,
}

/// Worker management subcommands.
#[derive(Subcommand, Debug)]
pub enum WorkerCommand {
    /// Register a worker and generate a secret (secret is shown only once)
    Add {
        /// Worker name (unique identifier)
        name: String,
        /// Worker architecture (e.g. x86_64, aarch64)
        #[arg(long)]
        arch: String,
        /// Maximum concurrent builds
        #[arg(long, default_value = "1")]
        capacity: i64,
        /// Write a complete deployable worker.toml (8 fields + secret) to this path
        /// with mode 0640 (root:crbs — the worker runs as the unprivileged
        /// crbs-worker user and reads it via group membership). Defaults:
        /// hub_ca_cert=/etc/crbs/certs/ca.crt,
        /// build_dir=/var/lib/crbs/worker/builds,
        /// crbs_root=/var/lib/crbs.
        /// --hub-url is required when this flag is set.
        #[arg(long, value_name = "PATH")]
        output_config: Option<PathBuf>,
        /// Hub URL the worker will reach (e.g. `https://<hub-ip>:18443`).
        /// Required when --output-config is set.
        #[arg(long, value_name = "URL")]
        hub_url: Option<String>,
        /// Path to the hub's TLS CA certificate (default /etc/crbs/certs/ca.crt)
        #[arg(long, value_name = "PATH")]
        hub_ca_cert: Option<PathBuf>,
        /// Worker-local build staging directory (default /var/lib/crbs/worker/builds)
        #[arg(long, value_name = "PATH")]
        build_dir: Option<PathBuf>,
        /// Worker-local crbs_root (default /var/lib/crbs)
        #[arg(long, value_name = "PATH")]
        crbs_root: Option<PathBuf>,
    },
    /// List all workers (secrets are masked)
    List {
        /// Output format: text (default) or json
        #[arg(long, value_enum, default_value_t = crate::cli::common::OutputFormat::Text)]
        format: crate::cli::common::OutputFormat,
    },
    /// Rotate a worker's secret (old secret becomes invalid immediately)
    RotateSecret {
        /// Worker name
        name: String,
        /// Write a complete deployable worker.toml (current arch/capacity + new secret)
        /// to this path with mode 0640 (root:crbs, see `add --output-config`).
        /// --hub-url is required when this flag is set.
        #[arg(long, value_name = "PATH")]
        output_config: Option<PathBuf>,
        /// Hub URL the worker will reach. Required when --output-config is set.
        #[arg(long, value_name = "URL")]
        hub_url: Option<String>,
        /// Path to the hub's TLS CA certificate (default /etc/crbs/certs/ca.crt)
        #[arg(long, value_name = "PATH")]
        hub_ca_cert: Option<PathBuf>,
        /// Worker-local build staging directory (default /var/lib/crbs/worker/builds)
        #[arg(long, value_name = "PATH")]
        build_dir: Option<PathBuf>,
        /// Worker-local crbs_root (default /var/lib/crbs)
        #[arg(long, value_name = "PATH")]
        crbs_root: Option<PathBuf>,
    },
    /// Revoke a worker's secret (worker can no longer authenticate)
    RevokeSecret {
        /// Worker name
        name: String,
    },
    /// Remove a worker
    Remove {
        /// Worker name
        name: String,
    },
}

/// `worker add` 保留名校验：hub 本地车道伪 worker 专用名不得被外部 worker 占用
/// （与 server 注册端点同口径）。
fn ensure_worker_name_not_reserved(name: &str) -> anyhow::Result<()> {
    if name == crbs_core::HUB_LOCAL_WORKER_NAME {
        anyhow::bail!(
            "worker name '{}' is reserved for the hub local lane",
            crbs_core::HUB_LOCAL_WORKER_NAME
        );
    }
    Ok(())
}

/// Handle `crbs-server worker ...` commands.
pub async fn handle_worker(
    config_dir: Option<PathBuf>,
    worker_cli: WorkerCli,
) -> anyhow::Result<()> {
    use crbs_core::auth::secret::{Secret, SecretKind};

    let store = load_state_store(config_dir.as_deref()).await?;

    match worker_cli.command {
        WorkerCommand::Add {
            name,
            arch,
            capacity,
            output_config,
            hub_url,
            hub_ca_cert,
            build_dir,
            crbs_root,
        } => {
            // 上限与 server 注册端点同口径：放行 i64::MAX 幽灵 worker 会派发后必因
            // 心跳超时回收，形成队列 DoS；fail-fast 报错，不静默钳制。
            const MAX_WORKER_CAPACITY: i64 = 1024;
            if name.is_empty() || arch.is_empty() || !(1..=MAX_WORKER_CAPACITY).contains(&capacity)
            {
                anyhow::bail!(
                    "name and arch required; capacity must be in 1..={MAX_WORKER_CAPACITY}, got {capacity}"
                );
            }
            ensure_worker_name_not_reserved(&name)?;
            if output_config.is_some() && hub_url.is_none() {
                anyhow::bail!("--hub-url is required when --output-config is set");
            }
            // 破坏性：覆盖 = 无警告重置现有 worker secret；改走 rotate-secret / remove+add。
            let existing = store
                .list_workers()
                .await
                .map_err(|e| anyhow::anyhow!("list workers: {e}"))?;
            if existing.iter().any(|w| w.name == name) {
                anyhow::bail!(
                    "worker '{}' already exists; refusing to overwrite \
                     (add would silently reset its secret). \
                     To rotate the secret: 'crbs-server worker rotate-secret {}'. \
                     To change arch/capacity: 'crbs-server worker remove {}' then re-add.",
                    name,
                    name,
                    name
                );
            }
            let secret = Secret::generate(SecretKind::WorkerSecret)
                .map_err(|e| anyhow::anyhow!("generate worker secret: {e}"))?;
            let hash = secret.hash();

            // 预置 status='offline'：未发心跳不参与调度；worker 上线后由
            // register/heartbeat（worker_recover_online）翻回 online。
            let worker_id = store
                .upsert_worker(&name, &arch, capacity, "", "offline", None)
                .await
                .map_err(|e| anyhow::anyhow!("upsert worker: {e}"))?;
            store
                .set_worker_secret(worker_id, hash.as_str())
                .await
                .map_err(|e| anyhow::anyhow!("set worker secret: {e}"))?;
            let detail = serde_json::json!({
                "worker_id": worker_id,
                "arch": arch,
                "capacity": capacity,
            })
            .to_string();
            store
                .audit_log("cli", "cli", "add_worker", Some(&name), Some(&detail))
                .await
                .map_err(|e| anyhow::anyhow!("audit add_worker: {e}"))?;

            println!("Worker registered: {} (id={})", name, worker_id);
            println!("Secret: {}", secret.as_str());
            println!(
                "\nAdd this to the worker's /etc/crbs/worker.toml:\n  token = \"{}\"",
                secret.as_str()
            );
            println!("\nKeep it secret; it will not be shown again.");

            write_output_config(OutputConfigOpts {
                output_config: output_config.as_deref(),
                hub_url: hub_url.as_deref(),
                name: &name,
                arch: &arch,
                capacity,
                token: secret.as_str(),
                hub_ca_cert: hub_ca_cert.as_deref(),
                build_dir: build_dir.as_deref(),
                crbs_root: crbs_root.as_deref(),
            })?;
            Ok(())
        }
        WorkerCommand::List { format } => {
            let workers = store
                .list_workers()
                .await
                .map_err(|e| anyhow::anyhow!("list workers: {e}"))?;
            if format == crate::cli::common::OutputFormat::Json {
                let items: Vec<serde_json::Value> = workers
                    .iter()
                    .map(|w| {
                        serde_json::json!({
                            "id": w.id,
                            "name": w.name,
                            "arch": w.arch,
                            "capacity": w.capacity,
                            "status": w.status,
                            "has_secret": w.has_secret,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "command": "worker list",
                        "workers": items,
                    }))
                    .map_err(|e| anyhow::anyhow!("serialize worker list: {e}"))?
                );
                return Ok(());
            }
            if workers.is_empty() {
                println!("No workers registered.");
                return Ok(());
            }
            println!(
                "{:<5} {:<20} {:<10} {:<8} {:<10} {:<12}",
                "id", "name", "arch", "capacity", "status", "has_secret"
            );
            for w in workers {
                println!(
                    "{:<5} {:<20} {:<10} {:<8} {:<10} {:<12}",
                    w.id, w.name, w.arch, w.capacity, w.status, w.has_secret
                );
            }
            Ok(())
        }
        WorkerCommand::RotateSecret {
            name,
            output_config,
            hub_url,
            hub_ca_cert,
            build_dir,
            crbs_root,
        } => {
            if output_config.is_some() && hub_url.is_none() {
                anyhow::bail!("--hub-url is required when --output-config is set");
            }
            let worker = find_worker_by_name(&store, &name).await?;

            let secret = Secret::generate(SecretKind::WorkerSecret)
                .map_err(|e| anyhow::anyhow!("generate worker secret: {e}"))?;
            let hash = secret.hash();
            store
                .set_worker_secret(worker.id, hash.as_str())
                .await
                .map_err(|e| anyhow::anyhow!("rotate worker secret: {e}"))?;
            // 审计直写；secret 不进审计。
            let detail = serde_json::json!({ "worker_id": worker.id }).to_string();
            store
                .audit_log(
                    "cli",
                    "cli",
                    "rotate_worker_secret",
                    Some(&name),
                    Some(&detail),
                )
                .await
                .map_err(|e| anyhow::anyhow!("audit rotate_worker_secret: {e}"))?;

            println!("Worker {} secret rotated.", name);
            println!("New secret: {}", secret.as_str());
            println!("\nThe old secret is now invalid.");
            println!(
                "Update the worker's /etc/crbs/worker.toml:\n  token = \"{}\"",
                secret.as_str()
            );

            // 保留 DB 的 arch/capacity，仅换 token；其余字段取 flag / 默认。
            write_output_config(OutputConfigOpts {
                output_config: output_config.as_deref(),
                hub_url: hub_url.as_deref(),
                name: &worker.name,
                arch: &worker.arch,
                capacity: worker.capacity,
                token: secret.as_str(),
                hub_ca_cert: hub_ca_cert.as_deref(),
                build_dir: build_dir.as_deref(),
                crbs_root: crbs_root.as_deref(),
            })?;
            Ok(())
        }
        WorkerCommand::RevokeSecret { name } => {
            let worker = find_worker_by_name(&store, &name).await?;

            store
                .clear_worker_secret(worker.id)
                .await
                .map_err(|e| anyhow::anyhow!("revoke worker secret: {e}"))?;
            let detail = serde_json::json!({ "worker_id": worker.id }).to_string();
            store
                .audit_log(
                    "cli",
                    "cli",
                    "revoke_worker_secret",
                    Some(&name),
                    Some(&detail),
                )
                .await
                .map_err(|e| anyhow::anyhow!("audit revoke_worker_secret: {e}"))?;
            println!(
                "Worker {} secret revoked. The worker can no longer authenticate.",
                name
            );
            Ok(())
        }
        WorkerCommand::Remove { name } => {
            let worker = find_worker_by_name(&store, &name).await?;

            // 原子"仅 offline 可删"：消除 get+delete 间 TOCTOU；在线删除会连带丢
            // worker_tasks，在跑构建既收不到结果也无人回收。
            match store
                .delete_worker_if_offline(worker.id)
                .await
                .map_err(|e| anyhow::anyhow!("delete worker: {e}"))?
            {
                crbs_core::DeleteWorkerOutcome::NotFound => {
                    anyhow::bail!("worker '{}' not found", name);
                }
                crbs_core::DeleteWorkerOutcome::Online => {
                    anyhow::bail!(
                        "worker '{}' is online; stop it (or wait for it to go offline / be \
                         reclaimed) before removal",
                        name
                    );
                }
                crbs_core::DeleteWorkerOutcome::Deleted => {}
            }

            let detail = serde_json::json!({ "worker_id": worker.id }).to_string();
            store
                .audit_log("cli", "cli", "remove_worker", Some(&name), Some(&detail))
                .await
                .map_err(|e| anyhow::anyhow!("audit remove_worker: {e}"))?;

            println!("Worker {} (id={}) removed.", name, worker.id);
            Ok(())
        }
    }
}

/// 按名取 worker 行：list 全量后过滤（无按名单查端点），未注册 →
/// "worker '{name}' not found"。
async fn find_worker_by_name(
    store: &crbs_core::StateStore,
    name: &str,
) -> anyhow::Result<crbs_core::WorkerStatus> {
    let workers = store
        .list_workers()
        .await
        .map_err(|e| anyhow::anyhow!("list workers: {e}"))?;
    workers
        .into_iter()
        .find(|w| w.name == name)
        .ok_or_else(|| anyhow::anyhow!("worker '{}' not found", name))
}

/// 传给 `write_worker_config_toml` 的字段集合，由 `write_output_config` 统一构造：
/// name/arch/capacity 两臂来源不同（Add 取 CLI flag，RotateSecret 取 DB 记录），
/// token 均为新生成 secret。hub_url 等 Option 字段先 `unwrap_or(DEFAULT_*)`，
/// `write_worker_config_toml` 不背默认策略（见 `DEFAULT_*`）。
struct WorkerTomlFields<'a> {
    name: &'a str,
    hub_url: &'a str,
    arch: &'a str,
    capacity: i64,
    token: &'a str,
    hub_ca_cert: Option<&'a str>,
    build_dir: Option<&'a str>,
    crbs_root: Option<&'a str>,
}

/// `--output-config` 默认值，与 crbs-worker 内建 serde 默认一致：显式写出与省略字段等价。
/// `build_dir` 不采用 /data 缺省值：默认必须落在 worker unit
/// `ProtectSystem=strict` 的 `ReadWritePaths` 内——/tmp 在 strict 下只读（EROFS）。
const DEFAULT_HUB_CA_CERT: &str = "/etc/crbs/certs/ca.crt";
const DEFAULT_BUILD_DIR: &str = "/var/lib/crbs/worker/builds";
const DEFAULT_CRBS_ROOT: &str = "/var/lib/crbs";

/// 校验 --output-config 路径：拒绝穿越、既存 dir、symlink（防 TOCTOU）。
fn validate_output_config_path(path: &Path) -> anyhow::Result<()> {
    if path.as_os_str().is_empty() {
        anyhow::bail!("--output-config path cannot be empty");
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        anyhow::bail!(
            "--output-config path cannot contain '..' traversal: {}",
            path.display()
        );
    }
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        anyhow::bail!("--output-config path cannot contain NUL byte");
    }
    if path.exists() {
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| anyhow::anyhow!("stat output path {}: {e}", path.display()))?;
        if meta.file_type().is_symlink() {
            anyhow::bail!(
                "--output-config path is a symlink (refusing to follow): {}",
                path.display()
            );
        }
        if meta.is_dir() {
            anyhow::bail!(
                "--output-config path exists but is a directory: {}",
                path.display()
            );
        }
    }
    Ok(())
}

/// 渲染 8 字段 worker.toml：固定字段顺序便于人眼对照，不写
/// heartbeat_interval_secs / poll_timeout_secs（worker 端走默认 30/60s）。Option 字段 None
/// 时写注释行（use worker default），不静默插 None 字符串；三字段有 #[serde(default)]。
fn render_worker_config_toml(fields: &WorkerTomlFields<'_>) -> String {
    let opt_line = |label: &str, v: Option<&str>| match v {
        Some(s) => format!("{label} = \"{s}\"\n"),
        None => format!("# {label} omitted (use worker default)\n"),
    };
    format!(
        "# crbs worker config; written by `crbs-server worker add --output-config`.\n\
         # Mode 0640 (root:crbs); this file contains a plaintext secret — keep it off shared storage.\n\
         name = \"{}\"\n\
         hub_url = \"{}\"\n\
         arch = \"{}\"\n\
         capacity = {}\n\
         token = \"{}\"\n\
         {}\
         {}\
         {}",
        fields.name,
        fields.hub_url,
        fields.arch,
        fields.capacity,
        fields.token,
        opt_line("hub_ca_cert", fields.hub_ca_cert),
        opt_line("build_dir", fields.build_dir),
        opt_line("crbs_root", fields.crbs_root),
    )
}

/// 写 worker.toml 到指定路径，mode 0o640（root:crbs）——非 root 的 crbs-worker 用户
/// 须凭 crbs 组读权限加载（0640 而非 0600）。Unix 显式 set_permissions(0o640)，
/// Windows no-op（worker spec Linux-only）；写盘前 validate_output_config_path 拒穿越。
fn write_worker_config_toml(path: &Path, fields: &WorkerTomlFields<'_>) -> anyhow::Result<()> {
    validate_output_config_path(path)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!(
                    "create parent dir {} for --output-config: {e}",
                    parent.display()
                )
            })?;
        }
    }
    let content = render_worker_config_toml(fields);
    // 原子写 + 创建即 0640：明文 secret 不得先以 umask 默认（0644）落盘；
    // 同目录随机临时名 + rename 还消除了"校验后路径被换成 symlink"的窗口
    //（rename 替换目录项本身，不跟随目标）。root 运行时补 crbs 组，worker
    // 非 root 用户凭组读；非 root/chown 失败仅 warn（目标机也可能非 root 部署）。
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("worker.toml");
    let tmp = parent
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".{file_name}.tmp.{}", uuid::Uuid::new_v4()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o640);
    }
    let write_result = (|| -> anyhow::Result<()> {
        let mut f = opts
            .open(&tmp)
            .map_err(|e| anyhow::anyhow!("create --output-config temp {}: {e}", tmp.display()))?;
        use std::io::Write;
        f.write_all(content.as_bytes())
            .map_err(|e| anyhow::anyhow!("write --output-config temp {}: {e}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o640))
                .map_err(|e| anyhow::anyhow!("chmod 0640 --output-config: {e}"))?;
            if nix::unistd::geteuid().is_root() {
                if let Ok(Some(group)) = nix::unistd::Group::from_name("crbs") {
                    use std::os::fd::AsRawFd;
                    if let Err(e) = nix::unistd::fchown(f.as_raw_fd(), None, Some(group.gid)) {
                        eprintln!("warning: chown worker.toml to group crbs failed: {e}");
                    }
                }
            }
        }
        f.sync_all()
            .map_err(|e| anyhow::anyhow!("fsync --output-config: {e}"))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| anyhow::anyhow!("install --output-config {}: {e}", path.display()))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    write_result
}

/// `--output-config` 落盘（Add / RotateSecret 两臂共用）：name/arch/capacity
/// 来源不同（CLI flag vs DB 记录）作参数，其余 flag 原样透传；hub_url 缺省
/// bail（fail-closed）、DEFAULT_* 默认化、写盘与 stdout 文案两臂一致。
struct OutputConfigOpts<'a> {
    output_config: Option<&'a Path>,
    hub_url: Option<&'a str>,
    name: &'a str,
    arch: &'a str,
    capacity: i64,
    token: &'a str,
    hub_ca_cert: Option<&'a Path>,
    build_dir: Option<&'a Path>,
    crbs_root: Option<&'a Path>,
}

fn write_output_config(opts: OutputConfigOpts<'_>) -> anyhow::Result<()> {
    let OutputConfigOpts {
        output_config,
        hub_url,
        name,
        arch,
        capacity,
        token,
        hub_ca_cert,
        build_dir,
        crbs_root,
    } = opts;
    let Some(out_path) = output_config else {
        return Ok(());
    };
    let config = WorkerTomlFields {
        name,
        // 调用方前置校验已保证 output_config ⇒ hub_url；仍 fail-closed 而非 expect（禁 panic 路径）。
        hub_url: hub_url
            .ok_or_else(|| anyhow::anyhow!("--hub-url is required when --output-config is set"))?,
        arch,
        capacity,
        token,
        hub_ca_cert: hub_ca_cert
            .map(|p| p.to_str().unwrap_or(DEFAULT_HUB_CA_CERT))
            .or(Some(DEFAULT_HUB_CA_CERT)),
        build_dir: build_dir
            .map(|p| p.to_str().unwrap_or(DEFAULT_BUILD_DIR))
            .or(Some(DEFAULT_BUILD_DIR)),
        crbs_root: crbs_root
            .map(|p| p.to_str().unwrap_or(DEFAULT_CRBS_ROOT))
            .or(Some(DEFAULT_CRBS_ROOT)),
    };
    write_worker_config_toml(out_path, &config)?;
    println!(
        "\nWrote deployable worker.toml to: {}\n  (mode 0640 root:crbs; scp to the worker host)",
        out_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    //! 单测：--output-config 路径校验 / render / write 闭环，走真实 fs + chmod 0o640，不 mock。
    //! 端到端 `worker add --output-config`（含 StateStore upsert）见 tests/integration_worker_cli.rs。
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn sample_fields<'a>(token: &'a str) -> WorkerTomlFields<'a> {
        WorkerTomlFields {
            name: "wkr-01",
            hub_url: "https://hub:18443",
            arch: "x86_64",
            capacity: 2,
            token,
            hub_ca_cert: Some("/etc/crbs/certs/ca.crt"),
            build_dir: Some("/var/lib/crbs/worker/builds"),
            crbs_root: Some("/var/lib/crbs"),
        }
    }

    #[test]
    fn validate_accepts_plain_relative_path() {
        let p = std::path::PathBuf::from("/tmp/crbs-test-validate-ok.toml");
        // 不存在 = OK（write 时会创建）
        let r = validate_output_config_path(&p);
        let _ = std::fs::remove_file(&p); // 保险
        assert!(r.is_ok(), "expected ok, got {r:?}");
    }

    #[test]
    fn validate_rejects_parent_dir_traversal() {
        // `..` 须为独立 path component 才算 traversal，纯文件名内的 `..` 只是普通字符。
        let p = std::path::PathBuf::from("/tmp/../etc/passwd");
        let err = validate_output_config_path(&p).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("'..' traversal"),
            "expected traversal error, got: {msg}"
        );
    }

    #[test]
    fn validate_accepts_filename_containing_double_dot() {
        // `crbs-..` 是个普通文件名，**不是** traversal，必须放行。
        let p = std::path::PathBuf::from("/tmp/crbs-..-not-traversal.toml");
        let r = validate_output_config_path(&p);
        let _ = std::fs::remove_file(&p); // 保险：万一有人扩展成允许既存文件
        assert!(r.is_ok(), "filename with '..' should be allowed, got {r:?}");
    }

    #[test]
    fn validate_rejects_existing_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = validate_output_config_path(dir.path()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("exists but is a directory"),
            "expected dir error, got: {msg}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn validate_rejects_existing_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.toml");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = validate_output_config_path(&link).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("is a symlink"),
            "expected symlink error, got: {msg}"
        );
    }

    #[test]
    fn validate_rejects_empty_path() {
        let p = std::path::PathBuf::new();
        let err = validate_output_config_path(&p).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cannot be empty"), "got: {msg}");
    }

    #[test]
    fn render_emits_eight_fields_in_expected_order() {
        let s = render_worker_config_toml(&sample_fields("crbs_wkr_TOKEN"));
        let mut lines = s.lines();
        assert!(lines.next().unwrap().starts_with("# crbs"));
        assert!(lines.next().unwrap().starts_with("# Mode"));
        let name = lines.next().unwrap();
        let hub = lines.next().unwrap();
        let arch = lines.next().unwrap();
        let cap = lines.next().unwrap();
        let tok = lines.next().unwrap();
        let ca = lines.next().unwrap();
        let bd = lines.next().unwrap();
        let cr = lines.next().unwrap();
        assert_eq!(name, r#"name = "wkr-01""#);
        assert_eq!(hub, r#"hub_url = "https://hub:18443""#);
        assert_eq!(arch, r#"arch = "x86_64""#);
        assert_eq!(cap, "capacity = 2");
        assert_eq!(tok, r#"token = "crbs_wkr_TOKEN""#);
        assert_eq!(ca, r#"hub_ca_cert = "/etc/crbs/certs/ca.crt""#);
        assert_eq!(bd, r#"build_dir = "/var/lib/crbs/worker/builds""#);
        assert_eq!(cr, r#"crbs_root = "/var/lib/crbs""#);
        assert!(lines.next().is_none());
    }

    #[test]
    fn render_emits_comment_line_for_none_optional_fields() {
        let mut f = sample_fields("crbs_wkr_T");
        f.hub_ca_cert = None;
        f.build_dir = None;
        f.crbs_root = None;
        let s = render_worker_config_toml(&f);
        assert!(
            s.contains("# hub_ca_cert omitted (use worker default)"),
            "got:\n{s}"
        );
        assert!(
            s.contains("# build_dir omitted (use worker default)"),
            "got:\n{s}"
        );
        assert!(
            s.contains("# crbs_root omitted (use worker default)"),
            "got:\n{s}"
        );
        assert!(!s.contains("None"), "render leaked literal 'None':\n{s}");
    }

    #[test]
    #[cfg(unix)]
    fn write_creates_file_sets_0640_and_creates_parent() {
        let base = tempfile::tempdir().expect("tempdir");
        let nested = base.path().join("a/b/c");
        let target = nested.join("worker.toml");
        write_worker_config_toml(&target, &sample_fields("crbs_wkr_xyz"))
            .expect("write should succeed");
        assert!(target.exists(), "file not created: {}", target.display());
        let meta = std::fs::metadata(&target).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "expected 0o640, got 0o{mode:o}");
        let body = std::fs::read_to_string(&target).unwrap();
        assert!(
            body.contains(r#"name = "wkr-01""#),
            "missing name in {body}"
        );
        assert!(
            body.contains(r#"token = "crbs_wkr_xyz""#),
            "missing token in {body}"
        );
        assert!(
            body.contains(r#"hub_url = "https://hub:18443""#),
            "missing hub_url in {body}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn write_overwrites_existing_regular_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("worker.toml");
        std::fs::write(&target, b"OLD").unwrap();
        write_worker_config_toml(&target, &sample_fields("crbs_wkr_NEW")).unwrap();
        let body = std::fs::read_to_string(&target).unwrap();
        assert!(!body.contains("OLD"));
        assert!(body.contains("crbs_wkr_NEW"));
        let meta = std::fs::metadata(&target).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[test]
    #[cfg(unix)]
    fn write_refuses_to_overwrite_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.toml");
        let link = dir.path().join("worker.toml");
        std::fs::write(&target, b"ORIGINAL").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = write_worker_config_toml(&link, &sample_fields("crbs_wkr_X")).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("is a symlink"), "got: {msg}");
        assert_eq!(std::fs::read(&target).unwrap(), b"ORIGINAL");
    }

    #[test]
    fn write_refuses_to_overwrite_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = write_worker_config_toml(dir.path(), &sample_fields("crbs_wkr_X")).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("exists but is a directory"), "got: {msg}");
    }

    /// 保留名拒绝：add 不得占用 hub 本地车道伪 worker 专用名。
    #[test]
    fn add_rejects_reserved_hub_local_name() {
        assert!(ensure_worker_name_not_reserved("wkr-01").is_ok());
        let err = ensure_worker_name_not_reserved(crbs_core::HUB_LOCAL_WORKER_NAME).unwrap_err();
        assert!(format!("{err}").contains("reserved"), "got: {err}");
    }
}
