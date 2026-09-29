// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::info;

use crbs_core::config::Config;
use crbs_core::privilege::CallerContext;
use crbs_core::sign::{SignConfig, Signer};
use crbs_core::types::build_phase_is_terminal;

pub(crate) struct SignArgs {
    pub task: String,
    pub key_id: Option<String>,
    pub gpg_home: Option<String>,
    pub remote: Option<String>,
    pub token: Option<String>,

    pub ca_cert: Option<PathBuf>,
    pub local: bool,
    pub format: crate::cli::OutputFormat,
}

#[derive(serde::Serialize)]
struct SignOutput {
    command: &'static str,
    task_id: i64,
    signed_count: usize,
}

impl crate::cli::CommandOutput for SignOutput {
    fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    fn print_text(&self) {
        println!(
            "Signed {} RPM(s) for task {}",
            self.signed_count, self.task_id
        );
    }
}

/// 对指定任务的 RPM/SRPM 产物执行 GPG 签名。本地：逐个终态子构建原地签名 result_dir 下 *.rpm 并刷新 signed 标记与 artifact 指纹。远程（签名在
/// hub 产物库原地执行，私钥不出 hub）：逐个触发 POST /api/v1/builds/{id}/sign，签名幂等（504 / 中途失败重跑即收敛）；触发需
/// operator/admin token。
pub(crate) async fn handle_sign(
    args: SignArgs,
    ctx: CallerContext,
    state: Option<&crbs_core::StateStore>,
    global: crate::cli::GlobalArgs,
) -> Result<()> {
    let remote = args.remote.clone();
    let token = args.token.clone();
    if let Some(target) = crate::remote::resolve(remote, token, None, args.local).await? {
        handle_sign_remote(&args, &target).await
    } else {
        let state = crate::cmd::require_state_store(
            state,
            "state store required for local sign; did you mean --remote?",
        )?;
        let ca_cert = args.ca_cert.clone();
        handle_sign_local(args, ctx, state, ca_cert, global).await
    }
}

async fn handle_sign_local(
    args: SignArgs,
    ctx: CallerContext,
    state: &crbs_core::StateStore,
    ca_cert: Option<PathBuf>,
    global: crate::cli::GlobalArgs,
) -> Result<()> {
    let user_filter = crate::cmd::visible_user_filter(&ctx);
    let task_id = state.resolve_task_id(&args.task, user_filter).await?;
    let task = state
        .get_task(task_id)
        .await?
        .ok_or_else(|| crate::cmd::task_not_found(task_id))?;
    let children = state.get_builds_by_task_id(task_id).await?;

    let config = load_config_for_product(
        &task.product,
        args.remote.clone(),
        args.token.clone(),
        ca_cert,
        global.offline,
    )
    .await?;

    let mut total_count = 0usize;
    for build in &children {
        if !build_phase_is_terminal(&build.phase) {
            info!(
                task_id = %task_id,
                build_id = %build.id,
                phase = %build.phase,
                "Skipping non-terminal child build for signing"
            );
            continue;
        }

        let result_dir = build.result_dir.as_ref().map(Path::new).ok_or_else(|| {
            crbs_core::error::CrbsError::NotFound {
                message: format!("build {} (task {}) has no result_dir", build.id, task_id),
            }
        })?;
        if !result_dir.exists() {
            return Err(crbs_core::error::CrbsError::NotFound {
                message: format!("result_dir does not exist: {}", result_dir.display()),
            }
            .into());
        }

        let count = do_sign(
            result_dir,
            &task.product,
            &config,
            args.key_id.clone(),
            args.gpg_home.clone(),
            Some(&SignDb {
                store: state,
                user: ctx.caller.username.clone(),
            }),
            build.id,
        )
        .await?;
        total_count += count;
    }

    let output = SignOutput {
        command: "sign",
        task_id,
        signed_count: total_count,
    };
    args.format.print(&output)?;

    Ok(())
}

async fn handle_sign_remote(args: &SignArgs, target: &crate::remote::RemoteTarget) -> Result<()> {
    let task_id = crate::cmd::parse_task_id(&args.task)?;
    let detail = crate::remote::fetch_task_record(target, task_id, None).await?;

    let body = serde_json::json!({
        "key_id": args.key_id,
        "gpg_home": args.gpg_home.clone(),
    });

    let mut signed_count = 0usize;
    for build in &detail.builds {
        if !build_phase_is_terminal(&build.phase) {
            continue;
        }
        let url = format!("{}/api/v1/builds/{}/sign", target.url, build.id);
        let parsed: serde_json::Value = crate::remote::remote_send_json(
            target,
            reqwest::Method::POST,
            |client| client.post(&url).json(&body),
            None,
            None,
        )
        .await?;
        if parsed.get("signed").and_then(|v| v.as_bool()) == Some(true) {
            signed_count += 1;
        }
    }

    let output = SignOutput {
        command: "sign",
        task_id,
        signed_count,
    };
    args.format.print(&output)?;

    Ok(())
}

async fn load_config_for_product(
    product: &str,
    remote: Option<String>,
    token: Option<String>,
    ca_cert: Option<PathBuf>,
    offline: bool,
) -> Result<Config> {
    let config_target = crate::remote::resolve_config_target(remote, token, ca_cert)
        .await
        .with_context(|| "resolve config target")?;
    let config = crate::api::product::load_product_config(product, config_target.as_ref(), offline)
        .await
        .with_context(|| format!("load product config for '{}'", product))?;
    crate::api::product::log_config_source(product, config_target.as_ref(), offline);
    Ok(config)
}

struct SignDb<'a> {
    store: &'a crbs_core::StateStore,

    user: String,
}

async fn sign_audit(
    db: &SignDb<'_>,
    event: &str,
    build_id: i64,
    key_id: &str,
    error: Option<&str>,
) -> anyhow::Result<()> {
    let mut detail = serde_json::json!({
        "build_id": build_id,
        "key_id": key_id,
        "operator": db.user,
    });
    if let Some(err) = error {
        detail["error"] = serde_json::json!(err);
    }
    db.store
        .audit_log(
            &db.user,
            "cli",
            event,
            Some(&build_id.to_string()),
            Some(&detail.to_string()),
        )
        .await
        .map_err(|e| anyhow::anyhow!("audit {event}: {e}"))
}

async fn do_sign(
    result_dir: &Path,
    product: &str,
    config: &Config,
    key_id: Option<String>,
    gpg_home: Option<String>,
    db: Option<&SignDb<'_>>,
    build_id: i64,
) -> Result<usize> {
    let rpm_paths = crbs_core::util::collect_rpm_paths(result_dir, false).await?;
    if rpm_paths.is_empty() {
        return Err(crbs_core::error::CrbsError::NotFound {
            message: format!("no RPM files found in {}", result_dir.display()),
        }
        .into());
    }

    let base_sign_config = SignConfig::from_config_async(config).await;

    let key_id = key_id
        .or_else(|| base_sign_config.as_ref().map(|c| c.key_id.clone()))
        .ok_or_else(|| {

            crbs_core::error::CrbsError::ValidationFailed {
                message: format!(
                    "no GPG key_id configured for product '{}'; use --key-id or set gpg_signing_key_id in config",
                    product
                ),
            }
        })?;

    let euid = nix::unistd::geteuid().as_raw();
    let gpg_home = match gpg_home {
        Some(home) => Some(
            SignConfig::validate_gpg_home_async(home, euid)
                .await
                .with_context(|| "invalid --gpg-home")?,
        ),
        None => base_sign_config.and_then(|c| c.gpg_home),
    };

    let sign_config = SignConfig { key_id, gpg_home };

    if let Some(db) = db {
        sign_audit(db, "sign_triggered", build_id, &sign_config.key_id, None).await?;
    }

    let signer = Signer::new();
    let paths_refs: Vec<&Path> = rpm_paths.iter().map(|p| p.as_path()).collect();
    if let Err(e) = signer
        .sign_rpms(&sign_config, result_dir, &paths_refs)
        .await
    {
        if let Some(db) = db {
            if let Err(audit_err) = sign_audit(
                db,
                "sign_failed",
                build_id,
                &sign_config.key_id,
                Some(&format!("{e:#}")),
            )
            .await
            {
                tracing::warn!(error = %audit_err, "Failed to write sign_failed audit log");
            }
        }
        return Err(e.into());
    }

    if let Some(db) = db {
        let state = db.store;
        let refresh: anyhow::Result<()> = async {
            let mut files = Vec::with_capacity(rpm_paths.len());
            for rpm in &rpm_paths {
                let (sha256, size) =
                    crbs_core::engine::artifact_harvest::sha256_file_with_size(rpm)
                        .await
                        .with_context(|| {
                            format!(
                                "signed {} RPM(s) on disk, but failed to hash {}; \
                             on-disk files ARE signed — re-run `crbs sign` to complete \
                             (signing is idempotent)",
                                rpm_paths.len(),
                                rpm.display()
                            )
                        })?;

                let rel = rpm
                    .strip_prefix(result_dir)
                    .map(|r| r.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| rpm.to_string_lossy().replace('\\', "/"));
                files.push((rel, sha256, size as i64));
            }

            let refreshed = state
                .refresh_signed_files(build_id, &files)
                .await
                .with_context(|| {
                    format!(
                        "signed {} RPM(s) on disk, but failed to refresh artifact metadata; \
                         on-disk files ARE signed — re-run `crbs sign` to complete \
                         (signing is idempotent — metadata refresh will be retried)",
                        rpm_paths.len()
                    )
                })?;
            info!(build_id = %build_id, refreshed = refreshed, "build_artifact metadata refreshed");

            state.update_build_signed(build_id, true).await?;
            Ok(())
        }
        .await;

        match refresh {
            Ok(()) => {
                sign_audit(db, "sign_completed", build_id, &sign_config.key_id, None).await?;
            }
            Err(e) => {
                if let Err(audit_err) = sign_audit(
                    db,
                    "sign_failed",
                    build_id,
                    &sign_config.key_id,
                    Some(&format!("{e:#}")),
                )
                .await
                {
                    tracing::warn!(error = %audit_err, "Failed to write sign_failed audit log");
                }
                return Err(e);
            }
        }
    }

    info!(
        build_id = %build_id,
        count = rpm_paths.len(),
        "RPMs signed successfully"
    );
    Ok(rpm_paths.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::CommandOutput as _;

    #[test]
    fn sign_output_json_roundtrip() {
        let out = SignOutput {
            command: "sign",
            task_id: 42,
            signed_count: 3,
        };
        let parsed: serde_json::Value = serde_json::from_str(&out.to_json().unwrap()).unwrap();
        assert_eq!(parsed["command"], "sign");
        assert_eq!(parsed["task_id"], 42);
        assert_eq!(parsed["signed_count"], 3);
    }

    #[tokio::test]
    async fn handle_sign_local_not_found_shape() {
        let tmp = tempfile::tempdir().unwrap();
        let store = crbs_core::StateStore::new(tmp.path()).await.unwrap();
        let _env = crate::test_support::EnvGuard::new(tmp.path());
        let ctx = CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: "tester".to_string(),
            },
            false,
        );
        let args = SignArgs {
            task: "424242".to_string(),
            key_id: None,
            gpg_home: None,
            remote: None,
            token: None,
            ca_cert: None,
            local: true,
            format: crate::cli::OutputFormat::Text,
        };
        let err = handle_sign(
            args,
            ctx,
            Some(&store),
            crate::cli::GlobalArgs { offline: false },
        )
        .await
        .expect_err("missing task must fail");
        assert!(
            err.to_string().contains("task 424242 not found"),
            "unexpected message: {err}"
        );
    }
}
