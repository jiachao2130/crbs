// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! sign 子命令：构建产物签名与密钥/CA 参数处理。

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::info;

use crbs_core::config::Config;
use crbs_core::privilege::CallerContext;
use crbs_core::sign::{SignConfig, Signer};
use crbs_core::types::build_phase_is_terminal;

/// sign 命令参数。
pub(crate) struct SignArgs {
    pub task: String,
    pub key_id: Option<String>,
    pub gpg_home: Option<String>,
    pub remote: Option<String>,
    pub token: Option<String>,
    /// CA 证书仅用于 hub 配置源（影响 `/api/v1/products/{name}/resolved` 拉取；
    /// 与 `--local` 执行路径选择无关）。
    pub ca_cert: Option<PathBuf>,
    pub local: bool,
    pub format: crate::cli::OutputFormat,
}

/// `crbs sign` 统一输出：本地 / 远程两路径共用（签名原地改写 result_dir）。
#[derive(serde::Serialize)]
struct SignOutput {
    /// 成功信封 command（与 json_error_contract 同源）。
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

/// 对指定任务的 RPM/SRPM 产物执行 GPG 签名。
/// 本地：按 task id 解析取全部子构建，逐个终态子构建原地签名 result_dir 下
/// *.rpm，并逐子构建刷新 signed 标记与 artifact 指纹。
/// 远程（签名在 hub 产物库原地执行，私钥不出 hub）：逐个终态子构建触发
/// `POST /api/v1/builds/{id}/sign`，哈希刷新 / signed 置位 / 审计 / 发布仓重建
/// 均由服务端完成，签名幂等（504 / 中途失败重跑即收敛）；`key_id` / `gpg_home`
/// 透传由 server 身份解释（server 侧 keyring 覆盖，缺省取 hub 产品配置）；触发需
/// operator/admin token（builder 得 403）；个人自签用 `--local` 配自有 keyring（与服务端密钥无关）。
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
        // 缺本地 StateStore 属调用误用——ValidationFailed（USAGE=4），消息补 --remote 出路提示。
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
    // root 不限用户（同 logs/diff 口径）：恒定过滤会让 root 签他人构建误报 "not found"。
    let user_filter = crate::cmd::visible_user_filter(&ctx);
    let task_id = state.resolve_task_id(&args.task, user_filter).await?;
    let task = state
        .get_task(task_id)
        .await?
        // 任务不存在属"未找到"语义——NotFound（USAGE=4）。
        .ok_or_else(|| crate::cmd::task_not_found(task_id))?;
    let children = state.get_builds_by_task_id(task_id).await?;

    // 配置源走 hub（产品名来自任务记录）：key_id/gpg_home 须与远端配置一致，避免本地旧磁盘 key 签名后被验证方拒绝的静默漂移。
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
        // 非终态子构建产物未定型，跳过（与远程路径同口径）。
        if !build_phase_is_terminal(&build.phase) {
            info!(
                task_id = %task_id,
                build_id = %build.id,
                phase = %build.phase,
                "Skipping non-terminal child build for signing"
            );
            continue;
        }
        // result_dir 缺失属"未找到"语义——NotFound（USAGE=4）。
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
    // task id 解析失败属参数误用——ValidationFailed（USAGE=4），不落 INTERNAL(1)。
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

/// 解析 hub 配置源 → 加载 Config → 打印 `config: <source>` 提示；`--local` 不参与。
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

/// CLI 本地签名的 DB 附属（`--local`）：签名发生在 CLI 本机、hub 无从感知，
/// 故携 hub StateStore 刷元数据并落审计；远程路径签名在 hub 侧自足，不经此。
struct SignDb<'a> {
    store: &'a crbs_core::StateStore,
    /// 审计 operator（本机调用者用户名，role 恒 "cli"）。
    user: String,
}

/// 落一条签名审计：写失败视为操作失败（签名幂等重跑收敛）；`sign_failed` 臂由调用方降级 warn，不掩盖原始签名错误。
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

/// 公共签名逻辑：收集 RPM → 检查 key → 签名 → 可选更新 DB；`config` 由调用方自 hub `/resolved` 预加载传入。
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
        // 目录里没有 RPM 属"未找到"语义——NotFound（USAGE=4）。
        return Err(crbs_core::error::CrbsError::NotFound {
            message: format!("no RPM files found in {}", result_dir.display()),
        }
        .into());
    }

    let base_sign_config = SignConfig::from_config_async(config).await;

    let key_id = key_id
        .or_else(|| base_sign_config.as_ref().map(|c| c.key_id.clone()))
        .ok_or_else(|| {
            // 缺 key 配置属参数/配置问题——ValidationFailed（USAGE=4）。
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

    // 签名互斥锁（{result_dir}/.sign.lock）唯一锁点在 Signer::sign_rpms 内部，此处不另获取。
    let signer = Signer::new();
    let paths_refs: Vec<&Path> = rpm_paths.iter().map(|p| p.as_path()).collect();
    if let Err(e) = signer
        .sign_rpms(&sign_config, result_dir, &paths_refs)
        .await
    {
        // 失败审计写失败仅 warn：不掩盖原始签名错误。
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

    // 本地签名原地改 result_dir 字节且无 _repo 组装：hub 同机时 repodata 不自动重建
    //（CLI 无 regen 机制），需 `crbs admin rebuild-repo` 或等下次构建收敛。

    // 签名成功 = 磁盘 RPM 已原地改写（不可逆）；build_artifacts 指纹须刷为签名后
    // sha256/size（完整性要求），刷新失败 = 操作未完成（非零退出），重跑 `crbs sign`
    // 幂等收敛（覆盖式 UPDATE）。
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
                // relative_path 与 harvest 存库口径一致：相对 result_dir + 反斜杠归一。
                let rel = rpm
                    .strip_prefix(result_dir)
                    .map(|r| r.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| rpm.to_string_lossy().replace('\\', "/"));
                files.push((rel, sha256, size as i64));
            }

            // 刷新事务化（全量或全不）：任一失败回滚保持签名前旧值；磁盘文件无对应 build_artifacts 行同样整体报错。
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

            // 标志最后置位，且只在刷新成功后：维持不变量 signed=1 ⇒ artifact 行哈希新鲜。
            state.update_build_signed(build_id, true).await?;
            Ok(())
        }
        .await;

        match refresh {
            Ok(()) => {
                // 完成审计：元数据刷新 + 置位成功后落。
                sign_audit(db, "sign_completed", build_id, &sign_config.key_id, None).await?;
            }
            Err(e) => {
                // 失败审计写失败仅 warn：不掩盖原始错误。
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

    /// 本地 sign 按 task id 解析，NotFound 形态与服务端同形（签名本体需 GPG 环境，
    /// 任务级聚合正确性由解析入口 + 逐子构建 do_sign 承载）。
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
