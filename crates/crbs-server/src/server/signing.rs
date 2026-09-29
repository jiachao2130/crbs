// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 服务端签名相关辅助函数。

use std::path::Path;
use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::server::state::AppState;

/// 服务端默认 GPG keyring 路径。
const SERVER_GPG_HOME_DEFAULT: &str = "/var/lib/crbs-gnupg";

/// `config.gpg_home` 未配置时的默认 keyring 决策核心（纯函数：env 由调用方注入，
/// 不读写进程级 `GNUPGHOME`，测试可并行直呼）。依次尝试 `GNUPGHOME`、
/// `/var/lib/crbs-gnupg`，须过 validate_gpg_home 安全校验（owner/权限/符号链接）。
fn decide_gpg_home_default(env_home: Option<&std::path::Path>, euid: u32) -> Option<String> {
    if let Some(p) = env_home {
        if let Ok(abs) = crbs_core::sign::SignConfig::validate_gpg_home(p, euid) {
            info!(gpg_home = %abs, "Using GNUPGHOME as server default gpg_home");
            return Some(abs);
        }
        debug!(
            gpg_home = %p.display(),
            "GNUPGHOME is set but rejected by validation; trying fallback"
        );
    }

    let default = std::path::Path::new(SERVER_GPG_HOME_DEFAULT);
    match crbs_core::sign::SignConfig::validate_gpg_home(default, euid) {
        Ok(abs) => {
            info!(
                gpg_home = %abs,
                "Using /var/lib/crbs-gnupg as server default gpg_home"
            );
            Some(abs)
        }
        Err(e) => {
            debug!(
                gpg_home = %default.display(),
                error = %e,
                "Server default gpg_home not available; falling back to default keyring"
            );
            None
        }
    }
}

pub(crate) async fn apply_server_gpg_home_default(config: &mut crbs_core::config::Config) {
    if config.gpg_home.is_some() {
        return;
    }
    let euid = nix::unistd::geteuid().as_raw();
    let env_home = std::env::var_os("GNUPGHOME").map(std::path::PathBuf::from);
    // validate_gpg_home 含 canonicalize/stat 等 sync fs 调用，整个决策进 spawn_blocking。
    let decided =
        tokio::task::spawn_blocking(move || decide_gpg_home_default(env_home.as_deref(), euid))
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "gpg_home default decision task failed");
                None
            });
    if let Some(abs) = decided {
        config.gpg_home = Some(abs);
    }
}

/// 签名成功后的共享后置动作：重算哈希 → 事务化刷新 `build_artifacts` 行 → 置位
/// `builds.signed=1`。不变量：signed=1 ⇒ 行哈希为签名后字节，置位必须在
/// [`StateStore::refresh_signed_files`]（全量或全不）提交成功之后；任一步失败
/// 返回 `Err` 且不置位（磁盘 RPM 已不可逆签名、DB 保持未签名，重跑幂等收敛）。
/// `rpm_tuples` = (绝对路径, relative_path)，同 `build_artifacts.relative_path`
/// 口径（相对 result_dir、`/` 分隔）；返回刷新行数。
pub(crate) async fn refresh_signed_and_mark(
    state: &crbs_core::StateStore,
    build_id: i64,
    rpm_tuples: &[(std::path::PathBuf, String)],
) -> crbs_core::Result<usize> {
    // 先全量重算哈希：任一文件读失败即整体放弃（半新半旧的行集比全旧更难排查）。
    let mut files = Vec::with_capacity(rpm_tuples.len());
    for (abs_path, rel_path) in rpm_tuples {
        let (sha256, size) =
            crbs_core::engine::artifact_harvest::sha256_file_with_size(abs_path).await?;
        files.push((rel_path.clone(), sha256, size as i64));
    }

    let refreshed = state.refresh_signed_files(build_id, &files).await?;

    state.update_build_signed(build_id, true).await?;
    Ok(refreshed)
}

/// 签名审计留痕（三事件 `sign_triggered`/`sign_completed`/`sign_failed`，
/// detail 恒带 build_id/key_id/operator）；审计失败仅 warn，不影响签名语义。
pub(crate) async fn sign_audit(
    state: &crbs_core::StateStore,
    event: &str,
    build_id: i64,
    key_id: &str,
    operator: &str,
    role: &str,
    error: Option<&str>,
) {
    let mut detail = serde_json::json!({
        "build_id": build_id,
        "key_id": key_id,
        "operator": operator,
    });
    if let Some(err) = error {
        detail["error"] = serde_json::json!(err);
    }
    if let Err(e) = state
        .audit_log(
            operator,
            role,
            event,
            Some(&build_id.to_string()),
            Some(&detail.to_string()),
        )
        .await
    {
        warn!(error = %e, event, build_id = %build_id, "Failed to write sign audit log");
    }
}

/// 对 Worker 上传到 Hub 的产物执行服务端 GPG 签名：加载产品配置、应用服务端
/// 默认 keyring，对全部 `.rpm`/`.src.rpm` 签名；失败或未启用仅 warn 不阻断上传。
/// 签名后经共享 helper 重算 SHA256/size、事务化刷新 DB 后置位 `builds.signed`。
pub(crate) async fn sign_uploaded_artifacts(
    app: &Arc<AppState>,
    product: &str,
    build_id: i64,
    pkg_name: &str,
    result_dir: &Path,
    artifact_paths: &[(std::path::PathBuf, String)],
) {
    let state = &app.state_store;

    // 重放跳签：replay 构建（request_json 带 reproduce_from_build_id）产物
    // repo_publish=0 无发布价值且 .sign.lock 是串行热点，跳签；读错按非 replay
    // 继续签——跳签只是省 signer 负载，读错即跳会把普通构建 signed=0 发布出去。
    match state.get_build_reproduce_source(build_id).await {
        Ok(Some(source_id)) => {
            debug!(
                build_id = build_id,
                source_build_id = source_id,
                "Replay build: skipping server-side GPG signing (repo_publish=0)"
            );
            return;
        }
        Ok(None) => {}
        Err(e) => {
            warn!(
                build_id = build_id,
                error = %e,
                "Failed to check replay marker before signing; treating as non-replay and signing"
            );
        }
    }

    let mut config = match state
        .load_merged_config_for_any_product_by_name(product)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            warn!(
                build_id = %build_id,
                product = %product,
                error = %e,
                "Failed to load product config for signing; skipping"
            );
            return;
        }
    };
    apply_server_gpg_home_default(&mut config).await;

    let mut rpm_tuples = Vec::new();
    for (abs_path, rel_path) in artifact_paths {
        let s = abs_path.to_string_lossy();
        if s.ends_with(".rpm") {
            rpm_tuples.push((abs_path.clone(), rel_path.clone()));
        }
    }

    if rpm_tuples.is_empty() {
        return;
    }

    // 签名互斥：{result_dir}/.sign.lock 由 Signer::sign_rpms 统一持有（唯一锁点，
    // 与 CLI `crbs sign` / 手动 sign API 互斥）；拿不到锁时 signed 保持 false。
    let (abs_paths, _rel_paths): (Vec<_>, Vec<_>) = rpm_tuples.iter().cloned().unzip();

    let mut outputs = crbs_core::types::BuildOutputs {
        build_id,
        pkg_name: pkg_name.to_string(),
        rpms: abs_paths,
        srpms: Vec::new(), // 已包含在 rpms 中（.src.rpm 也是 .rpm）
        logs: Vec::new(),
        result_dir: result_dir.to_path_buf(),
        retries: 0,
        signed: false,
    };

    crbs_core::sign::sign_build_outputs(&mut outputs, &config).await;

    // 审计：无 key 配置 = 签名未启用，与 sign_build_outputs 的静默跳过同口径
    // 不留痕；key 已配置且 outputs.signed 为假即签名失败臂。
    let key_id = config.gpg_signing_key_id.clone();
    if let Some(key_id) = &key_id {
        sign_audit(
            state,
            "sign_triggered",
            build_id,
            key_id,
            "system",
            "system",
            None,
        )
        .await;
        if !outputs.signed {
            sign_audit(
                state,
                "sign_failed",
                build_id,
                key_id,
                "system",
                "system",
                Some("sign_build_outputs did not mark outputs signed"),
            )
            .await;
        }
    }

    // 仅物理签名成功才刷新+置位；失败仅 warn 不回滚上传——磁盘 RPM 已签名、
    // builds.signed 保持 0，重跑签名路径幂等收敛（可重入语义见 helper 注释）。
    if outputs.signed {
        match refresh_signed_and_mark(state, build_id, &rpm_tuples).await {
            Ok(refreshed) => {
                debug!(
                    build_id = %build_id,
                    refreshed = refreshed,
                    "Refreshed signed file hashes in DB and marked build signed"
                );
                if let Some(key_id) = &key_id {
                    sign_audit(
                        state,
                        "sign_completed",
                        build_id,
                        key_id,
                        "system",
                        "system",
                        None,
                    )
                    .await;
                }
                // signed 置位发生在 `sign_rpms` 释放 `.sign.lock` 之后：终态上报
                // 若恰在此窗口拿锁并读到 signed=0，会跳过 regen 且不再重试。
                // phase 已 succeeded 时由本任务补一次（regen 自去重、幂等）。
                match state.get_build(build_id).await {
                    Ok(Some(rec)) if rec.phase == "succeeded" => {
                        crate::server::repo_regen::regenerate_product_repo(app, &rec.product).await;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!(
                            build_id = %build_id,
                            error = %e,
                            "Failed to check build phase after signing; \
                             repo regen will converge on the next trigger"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    build_id = %build_id,
                    error = %e,
                    "Signed RPMs on disk but DB hash refresh/mark failed; \
                     builds.signed stays 0 — re-signing converges (signing is idempotent)"
                );
                if let Some(key_id) = &key_id {
                    sign_audit(
                        state,
                        "sign_failed",
                        build_id,
                        key_id,
                        "system",
                        "system",
                        Some(&e.to_string()),
                    )
                    .await;
                }
            }
        }
    } else {
        debug!(
            build_id = %build_id,
            "sign_build_outputs did not set signed=true; skipping DB refresh"
        );
    }

    // regen 触发在 worker/routes/results.rs `report_result` succeeded 臂：该处拿同一
    // .sign.lock 等本签名任务完成后再 regen（保证 phase='succeeded' 已翻、
    // createrepo 读产物时无并发签名原地改写），本函数不持锁。
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn create_test_gpg_home(dir: &std::path::Path) -> std::path::PathBuf {
        let home = dir.join("gnupg");
        std::fs::create_dir_all(&home).unwrap();
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(&home, perms).unwrap();
        home
    }

    #[test]
    fn apply_default_uses_existing_server_gpg_home() {
        let tmp = tempfile::tempdir().unwrap();
        let home = create_test_gpg_home(tmp.path());

        let got = decide_gpg_home_default(Some(&home), nix::unistd::geteuid().as_raw());

        assert_eq!(
            got,
            Some(home.canonicalize().unwrap().to_string_lossy().to_string())
        );
    }

    #[tokio::test]
    async fn apply_default_leaves_existing_gpg_home_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let home = create_test_gpg_home(tmp.path());
        let home_str = home.to_str().unwrap().to_string();

        let mut config = crbs_core::config::Config {
            product: "test".to_string(),
            gpg_home: Some(home_str.clone()),
            ..Default::default()
        };

        apply_server_gpg_home_default(&mut config).await;
        assert_eq!(config.gpg_home, Some(home_str));
    }

    #[test]
    fn apply_default_ignores_unsafe_env_gpg_home() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("gnupg");
        std::fs::create_dir_all(&home).unwrap();
        // gpg_home 权限 755 不安全。
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&home, perms).unwrap();

        let got = decide_gpg_home_default(Some(&home), nix::unistd::geteuid().as_raw());

        // 不安全候选被拒；测试环境无 /var/lib/crbs-gnupg，回退也为 None。
        assert!(got.is_none());
    }

    /// 共享 helper 测试基建：建 store + succeeded build + 指定相对路径的产物行
    ///（旧哈希、未签名），返回 (store, build_id, result_dir, TempDir guard)；
    /// guard 须具名绑定到测试结束——提前 drop 删掉 SQLite 库文件，连接池
    /// 负载下新开连接报 SQLITE_CANTOPEN（与 test_support::setup_app 同约定）。
    async fn setup_build_with_artifact_rows(
        rel_paths: &[&str],
    ) -> (
        std::sync::Arc<crbs_core::StateStore>,
        i64,
        std::path::PathBuf,
        tempfile::TempDir,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());

        let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
        let result_dir = tmp.path().join("result");
        std::fs::create_dir_all(&result_dir).unwrap();
        let build_id = store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "succeeded",
                result_dir: Some(result_dir.to_str().unwrap()),
                backend: "chroot",
                user: "test",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        let artifacts: Vec<crbs_core::NewArtifact> = rel_paths
            .iter()
            .map(|rel| crbs_core::NewArtifact {
                relative_path: rel.to_string(),
                kind: crbs_core::ArtifactKind::Rpm,
                size_bytes: 100,
                sha256: format!("old-hash-{rel}"),
                unsigned_sha256: None,
                arch: Some("x86_64".to_string()),
                name: Some("hello".to_string()),
                version: Some("1.0".to_string()),
                release: Some("1".to_string()),
                epoch: None,
                metadata_json: None,
                signed: false,
            })
            .collect();
        let now = chrono::Utc::now()
            .format(crbs_core::util::DB_TIME_FMT)
            .to_string();
        let mut tx = store.pool().begin().await.unwrap();
        store
            .insert_artifacts_tx(&mut tx, build_id, &artifacts, &now)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        (store, build_id, result_dir, tmp)
    }

    async fn find_row(
        store: &crbs_core::StateStore,
        build_id: i64,
        rel: &str,
    ) -> crbs_core::Artifact {
        store
            .list_artifacts(build_id)
            .await
            .unwrap()
            .into_iter()
            .find(|a| a.relative_path == rel)
            .unwrap_or_else(|| panic!("artifact row {rel} must exist"))
    }

    /// 成功路径：行哈希/size 刷新为签名后字节、行 signed=1、builds.signed=1（置位在刷新成功之后）。
    #[tokio::test]
    async fn refresh_signed_and_mark_updates_rows_then_flag() {
        let rels = [
            "RPMS/x86_64/hello-1.0-1.x86_64.rpm",
            "SRPMS/hello-1.0-1.src.rpm",
        ];
        let (store, build_id, result_dir, _tmp) = setup_build_with_artifact_rows(&rels).await;

        // 磁盘上是"签名后"字节。
        let mut tuples = Vec::new();
        for rel in rels {
            let abs = result_dir.join(rel);
            std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
            std::fs::write(&abs, format!("signed-bytes-{rel}")).unwrap();
            tuples.push((abs, rel.to_string()));
        }

        let refreshed = refresh_signed_and_mark(&store, build_id, &tuples)
            .await
            .unwrap();
        assert_eq!(refreshed, 2);

        for (abs, rel) in &tuples {
            let row = find_row(&store, build_id, rel).await;
            assert!(row.signed, "row {rel} must be signed=1");
            let (expect_sha, expect_size) =
                crbs_core::engine::artifact_harvest::sha256_file_with_size(abs)
                    .await
                    .unwrap();
            assert_eq!(row.sha256, expect_sha, "row {rel} hash must be post-sign");
            assert_eq!(row.size_bytes, expect_size);
        }

        let rec = store.get_build(build_id).await.unwrap().unwrap();
        assert!(
            rec.signed,
            "builds.signed must be set after refresh succeeds"
        );
    }

    /// 失败路径：任一 relative_path 无对应行 → 整体失败、不置位；已命中的行
    /// 保持签名前旧值（全量或全不），builds.signed 保持 0（可重入重签收敛）。
    #[tokio::test]
    async fn refresh_signed_and_mark_missing_row_rolls_back_and_skips_flag() {
        let rels = ["RPMS/x86_64/hello-1.0-1.x86_64.rpm"];
        let (store, build_id, result_dir, _tmp) = setup_build_with_artifact_rows(&rels).await;

        let hit = result_dir.join(rels[0]);
        std::fs::create_dir_all(hit.parent().unwrap()).unwrap();
        std::fs::write(&hit, b"signed-bytes-hit").unwrap();
        // 磁盘存在但 DB 无行 → refresh_signed_files 报"no build_artifacts row"。
        let missing = result_dir.join("RPMS/x86_64/ghost-1.0-1.x86_64.rpm");
        std::fs::write(&missing, b"signed-bytes-ghost").unwrap();

        let tuples = vec![
            (hit, rels[0].to_string()),
            (missing, "RPMS/x86_64/ghost-1.0-1.x86_64.rpm".to_string()),
        ];
        let err = refresh_signed_and_mark(&store, build_id, &tuples).await;
        assert!(err.is_err(), "missing row must fail the whole refresh");

        let row = find_row(&store, build_id, rels[0]).await;
        assert!(!row.signed, "rolled-back row must stay unsigned");
        assert_eq!(row.sha256, format!("old-hash-{}", rels[0]));

        let rec = store.get_build(build_id).await.unwrap().unwrap();
        assert!(!rec.signed, "builds.signed must stay 0 when refresh fails");
    }
}
