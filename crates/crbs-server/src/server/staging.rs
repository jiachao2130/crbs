// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Server 侧 SRPM 暂存：崩溃恢复时保证 pending 任务仍能找到源包。布局
//! `{upload_dir}/{build_id}/{file_name}`（每 build 独立命名空间，并发路径隔离）；
//! 构建结束由 [`StagedSrpmGuard`] 清理，失效残留由 [`sweep_stale_staging`] 兜底。

use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use tracing::{info, warn};

use crate::server::error::ApiError;
use crate::server::routes::logs::build_phase_is_terminal;
use crate::server::state::AppState;

/// `stage_srpm` 入口防御校验：`build_id` 纯数字（暂存目录名即 DB 自增 id，
/// 须与 sweep 的纯数字判定口径一致）；`file_name` 拒绝路径分隔符与 `.`/`..`
/// （暂存路径由拼接得出，防穿越）。
fn validate_stage_inputs(build_id: &str, file_name: &str) -> Result<(), ApiError> {
    if build_id.is_empty() || !build_id.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ApiError::Validation(format!(
            "staging build_id must be numeric, got {build_id:?}"
        )));
    }
    if file_name.is_empty()
        || file_name == "."
        || file_name == ".."
        || file_name.contains(['/', '\\', '\0'])
    {
        return Err(ApiError::Validation(format!(
            "unsafe staged file name {file_name:?}"
        )));
    }
    Ok(())
}

/// 单目录补权限不变量（2770 + crbs 组），补回 `create_dir_all` 被 umask 削减
/// 掉的 group 写与 setgid 位；chmod 失败 warn、chown 失败仅 debug（非 root
/// chown 别人必然 EPERM）。
pub(crate) async fn enforce_dir_invariant(dir: &Path, label: &'static str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o2770)).await
        {
            warn!(
                path = %dir.display(),
                error = %e,
                "Failed to chmod {label} to 2770; group rw may not be in effect"
            );
        }
        crbs_core::privilege::chown_to_crbs_group_async(dir, false, label).await;
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, label);
    }
}

/// 从 `root` 之下到 `leaf`（含）逐级补权限不变量：`create_dir_all` 隐式创建
/// 的中间目录受 umask 削减（0755，父带 SGID 时 2755），逐级补 2770 保证结果
/// 子树每层三身份可读写；`leaf` 不在 `root` 下或等于 `root` 时 no-op（防误改共享根）。
pub(crate) async fn enforce_result_tree_invariant(leaf: &Path, root: &Path) {
    if !leaf.starts_with(root) || leaf == root {
        return;
    }
    let mut segments = vec![leaf.to_path_buf()];
    let mut cur = leaf.parent();
    while let Some(p) = cur {
        if p == root || !p.starts_with(root) {
            break;
        }
        segments.push(p.to_path_buf());
        cur = p.parent();
    }
    for dir in &segments {
        enforce_dir_invariant(dir, "result dir segment").await;
    }
}

/// 把 SRPM 放入 `{upload_dir}/{build_id}/{file_name}`：`move_source` 用
/// `rename`（multipart 临时文件），否则 `copy`。文件权限不变量：目录 2770、
/// 文件 0660，chown 到 crbs 组。
pub(crate) async fn stage_srpm(
    upload_dir: &Path,
    build_id: &str,
    src: &Path,
    file_name: &str,
    move_source: bool,
) -> Result<PathBuf, ApiError> {
    validate_stage_inputs(build_id, file_name)?;

    let dir = upload_dir.join(build_id);
    // 先建目录再显式 chmod：mkdir 的 mode 参数受 umask 削减（022 下 2770 →
    // 2750 丢 group write），set_permissions 不受 umask 影响。
    tokio::fs::create_dir_all(&dir).await.map_err(|e| {
        // dir 是服务端绝对路径，不得进 500 信封（信息泄露）；helper 无路径
        // 字段位，路径在此补结构化 error!，响应固定 internal error 文案。
        tracing::error!(path = %dir.display(), "Failed to create upload staging dir");
        ApiError::log_and_internal_with_context("create upload dir", e)
    })?;
    // upload_dir 根可能由本次 create_dir_all 级联创建，同补不变量。
    enforce_dir_invariant(upload_dir, "upload staging root").await;
    enforce_dir_invariant(&dir, "staging dir").await;

    let dest = dir.join(file_name);

    if move_source {
        if let Err(e) = tokio::fs::rename(src, &dest).await {
            // 跨文件系统 rename 会失败，退化为 copy + 删除源文件
            if e.raw_os_error() == Some(libc::EXDEV) {
                if let Err(copy_err) = tokio::fs::copy(src, &dest).await {
                    // 半截副本必须清：残缺 SRPM 会被崩溃恢复当作有效暂存认领。
                    remove_partial_copy(&dest).await;
                    // io 细节只进结构化日志，响应固定 internal error 文案。
                    return Err(ApiError::log_and_internal_with_context(
                        "copy srpm to stage",
                        copy_err,
                    ));
                }
                // copy 已成功、暂存不受影响：删源失败不阻断流程，仅 warn 留源 SRPM 残留线索。
                if let Err(rm_err) = tokio::fs::remove_file(src).await {
                    warn!(
                        path = %src.display(),
                        error = %rm_err,
                        "Failed to remove source srpm after cross-fs copy; source left behind"
                    );
                }
            } else {
                return Err(ApiError::log_and_internal_with_context(
                    "rename srpm to stage",
                    e,
                ));
            }
        }
    } else if let Err(copy_err) = tokio::fs::copy(src, &dest).await {
        remove_partial_copy(&dest).await;
        return Err(ApiError::log_and_internal_with_context(
            "copy srpm to stage",
            copy_err,
        ));
    }

    #[cfg(unix)]
    {
        if let Err(e) =
            tokio::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o660)).await
        {
            warn!(
                path = %dest.display(),
                error = %e,
                "Failed to chmod staged srpm to 0660; group rw may not be in effect"
            );
        }
        crbs_core::privilege::chown_to_crbs_group_async(&dest, false, "staged srpm").await;
    }

    Ok(dest)
}

/// copy 半截失败后的 best-effort 清理：失败（除 NotFound——dest 未及创建）
/// 仅 debug，不得掩盖调用方上抛的原始 copy 错误。
async fn remove_partial_copy(dest: &Path) {
    if let Err(e) = tokio::fs::remove_file(dest).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::debug!(
                path = %dest.display(),
                error = %e,
                "Failed to remove partially copied staged srpm"
            );
        }
    }
}

/// 构建结束时删除暂存的 SRPM，并尝试清理空的上传目录。
pub(crate) struct StagedSrpmGuard {
    pub path: PathBuf,
}

/// 某 build 的暂存副本路径 `{upload_dir}/{build_id}/{file_name}`（取共享
/// `srpm_path` 文件名拼出）。守卫据此只清该 build 独有的 upload 副本，不碰
/// `builds.srpm_path` 指向的共享 `source/` SRPM——同 task 所有架构共用、供
/// 远程 worker 下载，误删致后续拉取 404。
pub(crate) fn staged_srpm_copy_path(
    upload_dir: &Path,
    build_id: i64,
    srpm_path: &Path,
) -> Option<PathBuf> {
    srpm_path
        .file_name()
        .map(|file_name| upload_dir.join(build_id.to_string()).join(file_name))
}

impl Drop for StagedSrpmGuard {
    fn drop(&mut self) {
        let path = self.path.clone();
        let parent = path.parent().map(PathBuf::from);
        // Drop 为同步上下文：文件删除是异步 IO，交由当前运行时后台执行，
        // 避免同步删除阻塞 worker 线程。
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    if let Err(e) = tokio::fs::remove_file(&path).await {
                        if e.kind() != std::io::ErrorKind::NotFound {
                            warn!(path = %path.display(), error = %e, "Failed to remove staged srpm");
                        }
                    }
                    if let Some(parent) = parent {
                        if let Err(e) = tokio::fs::remove_dir(&parent).await {
                            tracing::debug!(dir = %parent.display(), error = %e, "Failed to remove upload dir (may not be empty)");
                        }
                    }
                });
            }
            Err(_) => {
                warn!(
                    path = %path.display(),
                    "Staged srpm guard dropped outside a tokio runtime; staged copy leaks until staging sweep"
                );
            }
        }
    }
}

/// 行不存在目录的孤儿判定宽限：目录 mtime 超过该时长且 DB 行不存在才删。
/// 24h 对齐 `artifacts_gc::ORPHAN_ARTIFACT_GRACE`（同款"行不存在"孤儿语义），
/// 须覆盖 submit 建行事务提交前的秒级窗口、retention prune 删行与 sweep 读取的竞态
///（被 prune 行的目录 mtime 至少已是 retention_days 量级）。
const ORPHAN_STAGING_GRACE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// 清理 upload_dir 下已终态 build 的暂存残留目录（`{upload_dir}/{build_id}/`），
/// 兜底 `StagedSrpmGuard` 不触发的路径（worker 派发、调度快速失败、hub 崩溃）。
/// 删除条件（二选一）：DB 行存在且已终态（pending/building 跳过——并发窗口
/// 内行可能尚未可见，误删在途副本致 worker 下载 404）；或行不存在 + mtime
/// 超过 [`ORPHAN_STAGING_GRACE`]（`prune_old_records` 清行后的残留，新鲜目录
/// 保留防建行前窗口）。DB 点查单条批量（`get_existing_build_phases`），失败
/// 跳过本轮全部数字目录（宁漏删不误删）。路径隔离：删除前断言目录名纯数字、
/// 严格位于 upload_dir 之下且不等于其本身。
pub(crate) async fn sweep_stale_staging(app: &Arc<AppState>) {
    sweep_stale_staging_with_grace(app, ORPHAN_STAGING_GRACE).await;
}

/// 实际实现（grace 可注入，测试用 `ZERO` 直接触发行不存在分支的删除）。
async fn sweep_stale_staging_with_grace(app: &Arc<AppState>, grace: std::time::Duration) {
    let upload_dir = app.upload_dir();
    let mut rd = match tokio::fs::read_dir(&upload_dir).await {
        Ok(rd) => rd,
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            warn!(
                path = %upload_dir.display(),
                error = %e,
                "Failed to read upload_dir for staging sweep"
            );
            return;
        }
    };

    // Pass 1：只收集纯数字候选目录（{build_id}），`.incoming/{uuid}` 等非数字目录交尾部兜底。
    let mut candidates: Vec<(tokio::fs::DirEntry, i64)> = Vec::new();
    loop {
        let entry = match rd.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(e) => {
                warn!(
                    path = %upload_dir.display(),
                    error = %e,
                    "Failed to iterate upload_dir during staging sweep"
                );
                return;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(build_id) = name.parse::<i64>() else {
            continue;
        };
        candidates.push((entry, build_id));
    }

    // Pass 2：单条批量点查（id → phase，行不存在的 id 无键）消除逐目录 N+1。
    // 行存在 → 终态才删、活跃保留（与 freshness 无关）；行不存在 → mtime 超宽限
    // 才删、新鲜保留防在途提交窗口。批量失败 → 跳过本轮数字目录（瞬时故障不得当"行不存在"删数据）。
    let ids: Vec<i64> = candidates.iter().map(|(_, id)| *id).collect();
    match app.state_store.get_existing_build_phases(&ids).await {
        Ok(phases) => {
            for (entry, build_id) in candidates {
                let name = entry.file_name();
                let reason: Option<&'static str> = match phases.get(&build_id) {
                    Some(p) if build_phase_is_terminal(p) => Some("terminal build"),
                    Some(_) => None,
                    None => {
                        let stale =
                            crate::server::artifacts_gc::dir_entry_stale(&entry, grace).await;
                        if stale {
                            Some("rowless stale dir (build row pruned or never created)")
                        } else {
                            None
                        }
                    }
                };
                let Some(reason) = reason else { continue };

                let target = upload_dir.join(&name);
                // 隔离断言：目标严格位于 upload_dir 之下、不等于共享根本身。
                if !target.starts_with(&upload_dir) || target == upload_dir {
                    warn!(
                        target = %target.display(),
                        "Staging sweep target failed isolation assertion; refusing to remove"
                    );
                    continue;
                }
                match tokio::fs::remove_dir_all(&target).await {
                    Ok(()) => info!(
                        build_id = build_id,
                        path = %target.display(),
                        reason = reason,
                        "Swept stale staging dir"
                    ),
                    Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => warn!(
                        build_id = build_id,
                        path = %target.display(),
                        error = %e,
                        "Failed to remove stale staging dir"
                    ),
                }
            }
        }
        Err(e) => {
            warn!(
                path = %upload_dir.display(),
                candidates = candidates.len(),
                error = %e,
                "Failed to batch look up builds for staging sweep; skipping numeric dirs this round"
            );
        }
    }

    // `.incoming/{uuid}` 兜底进程崩溃/被杀残留（extract 失败路径已在请求内回收，
    // 见 multipart.rs）。阈值 24h 而非 1h：流式写盘只新增/追加目录内文件，目录
    // 自身 mtime 冻结在请求开始时刻，慢链路（500MB 低带宽）超 1h 在途请求会误删。
    let incoming = upload_dir.join(".incoming");
    if let Ok(mut rd) = tokio::fs::read_dir(&incoming).await {
        while let Ok(Some(entry)) = rd.next_entry().await {
            let path = entry.path();
            let stale = entry
                .metadata()
                .await
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .map(|e| e > ORPHAN_STAGING_GRACE)
                .unwrap_or(false);
            if stale {
                if let Err(e) = tokio::fs::remove_dir_all(&path).await {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        warn!(
                            path = %path.display(),
                            error = %e,
                            "Failed to remove stale incoming dir"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crbs_core::config::ServerConfig;
    use crbs_core::{BuildInsert, StateStore};

    #[test]
    fn staged_copy_path_points_into_upload_dir_not_source() {
        let upload_dir = Path::new("/var/lib/crbs/uploads");
        // 共享 source SRPM 路径（builds.srpm_path 指向的位置，供所有架构与远程 worker 使用）。
        let source = Path::new("/data/crbs-results/5/source/openssh-8.8p1-41.oe2203sp4.src.rpm");
        let staged = staged_srpm_copy_path(upload_dir, 42, source).unwrap();
        assert_eq!(
            staged,
            upload_dir
                .join("42")
                .join("openssh-8.8p1-41.oe2203sp4.src.rpm")
        );
        assert_ne!(staged, source);
        assert!(staged.starts_with(upload_dir));
    }

    #[tokio::test]
    async fn stage_srpm_rejects_unsafe_inputs() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("pkg.src.rpm");
        tokio::fs::write(&src, b"srpm").await.unwrap();

        for bad_id in ["build-123", "7/8", "", "..", "-1"] {
            let err = stage_srpm(tmp.path(), bad_id, &src, "pkg.src.rpm", false).await;
            assert!(err.is_err(), "build_id {bad_id:?} must be rejected");
        }
        for bad_name in ["a/b", "a\\b", "..", ".", "", "a\0b"] {
            let err = stage_srpm(tmp.path(), "7", &src, bad_name, false).await;
            assert!(err.is_err(), "file_name {bad_name:?} must be rejected");
        }
        // 校验失败时连目录都不应创建。
        assert!(!tmp.path().join("7").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn staged_srpm_mode_is_0660_and_dir_2770() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("pkg.src.rpm");
        tokio::fs::write(&src, b"srpm").await.unwrap();

        let staged = stage_srpm(&tmp.path().join("uploads"), "7", &src, "pkg.src.rpm", false)
            .await
            .unwrap();

        let fmode = std::fs::metadata(&staged).unwrap().permissions().mode() & 0o777;
        assert_eq!(fmode, 0o660, "staged srpm must be 0660");
        let dmode = std::fs::metadata(staged.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(dmode, 0o2770, "staging dir must be 2770");
    }

    /// helper 直测钉清理语义 + stage_srpm copy 失败路径接线（真实短写注入需特殊文件系统）。
    #[tokio::test]
    async fn stage_srpm_copy_failure_cleans_partial_dest() {
        let tmp = tempfile::tempdir().unwrap();
        let upload_dir = tmp.path().join("uploads");
        let staged = upload_dir.join("7").join("pkg.src.rpm");

        tokio::fs::create_dir_all(staged.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&staged, b"partial-bytes").await.unwrap();
        remove_partial_copy(&staged).await;
        assert!(!staged.exists(), "partial dest must be removed");

        // ① 接线：copy 失败（src 缺失）时 stage_srpm 报错且不留 dest。
        let missing_src = tmp.path().join("no-such.src.rpm");
        let err = stage_srpm(&upload_dir, "8", &missing_src, "pkg.src.rpm", false)
            .await
            .unwrap_err();
        // io 细节只进结构化日志，信封固定 internal error 文案。
        assert!(
            matches!(err, ApiError::Internal(ref msg) if msg == "internal error"),
            "copy failure must map to redacted internal error: {err:?}"
        );
        assert!(
            !upload_dir.join("8").join("pkg.src.rpm").exists(),
            "no dest residue after copy failure"
        );

        // ② NotFound 静默：dest 未创建时清理 no-op（不误报）。
        remove_partial_copy(&tmp.path().join("never-created")).await;
    }

    /// 守卫只清 upload_dir 暂存副本，绝不删远程 worker 仍需下载的共享 source
    /// SRPM；drop 清理是 spawn 异步的，轮询等待。
    #[tokio::test]
    async fn guard_cleans_upload_copy_but_leaves_shared_source_intact() {
        let tmp = tempfile::tempdir().unwrap();
        let upload_dir = tmp.path().join("uploads");
        let source_dir = tmp.path().join("results/7/source");
        tokio::fs::create_dir_all(&source_dir).await.unwrap();
        let source = source_dir.join("pkg.src.rpm");
        tokio::fs::write(&source, b"srpm").await.unwrap();

        let staged = stage_srpm(&upload_dir, "7", &source, "pkg.src.rpm", false)
            .await
            .unwrap();
        assert!(staged.exists());

        let guard_path = staged_srpm_copy_path(&upload_dir, 7, &source).unwrap();
        assert_eq!(guard_path, staged);
        {
            let _guard = StagedSrpmGuard { path: guard_path };
        }

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while staged.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("staged copy should be cleaned up by guard");

        assert!(source.exists(), "共享 source SRPM 不得被删除");
    }

    /// 构造测试用 AppState（upload_dir = {crbs_root}/uploads）。
    async fn setup_app() -> (Arc<AppState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store,
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        (app, tmp)
    }

    /// pkg 由调用方传入；insert_build 拒绝同 product+pkg+arch 活跃重复，多种子须错开 pkg。
    async fn seed_build(store: &StateStore, pkg: &str, phase: &'static str) -> i64 {
        let task_id = crate::test_support::seed_task(store, "test", pkg).await;
        store
            .insert_build(BuildInsert {
                product: "test",
                pkg_name: pkg,
                phase,
                backend: "chroot",
                user: "tester",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn sweep_removes_terminal_and_keeps_active_staging() {
        let (app, tmp) = setup_app().await;
        let upload_dir = app.upload_dir();
        let src = tmp.path().join("pkg.src.rpm");
        tokio::fs::write(&src, b"srpm").await.unwrap();

        let done = seed_build(&app.state_store, "pkg", "succeeded").await;
        let pending = seed_build(&app.state_store, "pkg2", "pending").await;
        let building = seed_build(&app.state_store, "pkg3", "building").await;

        for id in [done, pending, building] {
            stage_srpm(&upload_dir, &id.to_string(), &src, "pkg.src.rpm", false)
                .await
                .unwrap();
        }
        // 无 DB 行的纯数字目录（在途提交窗口）与 .incoming、非数字目录。
        tokio::fs::create_dir_all(upload_dir.join("999999"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(upload_dir.join(".incoming/uuid"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(upload_dir.join("junk"))
            .await
            .unwrap();

        sweep_stale_staging(&app).await;

        assert!(
            !upload_dir.join(done.to_string()).exists(),
            "terminal build staging dir must be swept"
        );
        assert!(
            upload_dir.join(pending.to_string()).exists(),
            "pending build staging dir must be kept"
        );
        assert!(
            upload_dir.join(building.to_string()).exists(),
            "building build staging dir must be kept"
        );
        assert!(
            upload_dir.join("999999").exists(),
            "fresh rowless dir must be kept (grace window / in-flight submit)"
        );
        assert!(upload_dir.join(".incoming").exists());
        assert!(upload_dir.join("junk").exists());
    }

    /// grace=ZERO 注入直触发行不存在分支的删除（默认宽限下新鲜目录保留见上一测试）。
    #[tokio::test]
    async fn sweep_removes_stale_rowless_dirs_beyond_grace() {
        let (app, _tmp) = setup_app().await;
        let upload_dir = app.upload_dir();
        tokio::fs::create_dir_all(upload_dir.join("999999"))
            .await
            .unwrap();
        sweep_stale_staging_with_grace(&app, std::time::Duration::ZERO).await;
        assert!(
            !upload_dir.join("999999").exists(),
            "rowless dir beyond grace must be swept"
        );
    }

    #[tokio::test]
    async fn sweep_noop_when_upload_dir_missing() {
        let (app, _tmp) = setup_app().await;
        sweep_stale_staging(&app).await;
        assert!(!app.upload_dir().exists());
    }
}
