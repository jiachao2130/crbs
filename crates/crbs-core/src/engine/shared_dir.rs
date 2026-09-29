// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 共享目录权限 helper。
//!
//! server / worker / 本地 CLI 多身份共享同一目录树：目录 0o2770（setgid +
//! group rwx）属组 `crbs`，新文件/子目录自动继承属组，写入不因权限不足失败。

use std::collections::HashSet;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use nix::sys::stat::{fchmodat, FchmodatFlags, Mode};
use nix::unistd::{chown, Gid, Uid};
use tracing::{debug, warn};

use crate::error::CrbsError;

const SHARED_DIR_MODE: u32 = 0o2770;

/// 容量帽：条目无失效语义，长寿命进程遇新路径无界增长；HashSet 无插入序
/// 不做逐出，超帽整集清空（代价 = 各路径多付一次幂等 prepare 修正）。
const PREPARED_DIRS_CAP: usize = 4096;

/// 本进程内已准备好的共享目录，避免重复调用特权后端。
static PREPARED_DIRS: LazyLock<Mutex<HashSet<PathBuf>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// 返回 `path` 下尚不存在的各级父目录（浅→深，不含 `path`）；`create_dir_all`
/// 按 umask 新建这些层级，须逐级修正属组/权限，否则父链挡住组内其他进程。
async fn missing_parents(path: &Path) -> crate::Result<Vec<PathBuf>> {
    let mut missing = Vec::new();
    let mut cur = path.parent();
    while let Some(dir) = cur {
        if tokio::fs::try_exists(dir)
            .await
            .map_err(|e| CrbsError::from_io_context("stat shared dir parent", e))?
        {
            break;
        }
        missing.push(dir.to_path_buf());
        cur = dir.parent();
    }
    missing.reverse();
    Ok(missing)
}

/// symlink 复核链：可信锚（首个已存在祖先）→ 新建父链 → leaf。missing 为空时
/// 锚 = `path.parent()`——已存在中间层预置 symlink 会被 create_dir_all 穿过建出
/// leaf 且自身非 symlink，只查 leaf 会漏检；missing 非空时锚 = `created_parents[0]`
/// 的父（break 层）。更浅祖先在共享树外（预置 symlink 需系统目录写权限），不在攻击面。
fn symlink_review_chain<'a>(path: &'a Path, created_parents: &'a [PathBuf]) -> Vec<&'a Path> {
    let mut chain: Vec<&Path> = Vec::new();
    match created_parents.first() {
        Some(first) => {
            if let Some(anchor) = first.parent() {
                chain.push(anchor);
            }
        }
        None => {
            if let Some(parent) = path.parent() {
                chain.push(parent);
            }
        }
    }
    chain.extend(created_parents.iter().map(|p| p.as_path()));
    chain.push(path);
    chain
}

/// 沿复核链逐级 `symlink_metadata` 拒绝（fail-closed）；链覆盖语义见 [`symlink_review_chain`]。
fn reject_symlink_chain(chain: &[&Path]) -> crate::Result<()> {
    for dir in chain {
        let lmeta = std::fs::symlink_metadata(dir).map_err(|e| {
            CrbsError::io_message(format!("stat shared dir {}: {e}", dir.display()))
        })?;
        if lmeta.file_type().is_symlink() {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "shared dir path traverses a symlink (possible tampering): {}",
                    dir.display()
                ),
            });
        }
    }
    Ok(())
}

/// 确保 `path` 存在且对 `crbs` 组共享可写（0o2770），新建中间父目录逐级修正；
/// 属主/root 直接 syscall，否则回退 `PrivilegeBackend`。进程内幂等，已准备目录跳过。
pub(crate) async fn ensure_shared_dir(path: &Path) -> crate::Result<()> {
    if is_prepared(path) {
        return Ok(());
    }

    let created_parents = missing_parents(path).await?;

    tokio::fs::create_dir_all(path)
        .await
        .map_err(|e| CrbsError::from_io_context("create shared dir", e))?;

    let crbs_gid = crate::privilege::crbs_group_gid_async()
        .await
        .map_err(|e| CrbsError::io_message(format!("lookup crbs group gid for shared dir: {e}")))?;
    let uid = nix::unistd::getuid().as_raw();
    let path = path.to_path_buf();
    let prepared_path = path.clone();

    tokio::task::spawn_blocking(move || -> crate::Result<()> {
        let target_mode = Mode::from_bits_truncate(SHARED_DIR_MODE as nix::libc::mode_t);

        // 组可写父目录可被预置 symlink 指向攻击者树（digest 可预测）——
        // create_dir_all 会穿过创建，跟随链接的 chown/metadata 校验会在攻击者
        // 树上通过；沿复核链逐级 symlink_metadata，任何一级是 symlink 即拒绝。
        reject_symlink_chain(&symlink_review_chain(&path, &created_parents))?;

        // 新建中间父目录：逐级 chown（仅 debug：非 root 改他人属主必然 EPERM，
        // 组 rw 已够本进程）+ chmod 2770（warn：通常权限未生效）。leaf 走下方严格校验。
        for dir in &created_parents {
            if let Err(e) = chown(
                dir,
                Some(Uid::from_raw(uid)),
                Some(Gid::from_raw(crbs_gid)),
            ) {
                debug!(path = %dir.display(), error = %e, "chown intermediate shared dir to crbs group failed");
            }
            if let Err(e) = fchmodat(None, dir, target_mode, FchmodatFlags::NoFollowSymlink) {
                warn!(path = %dir.display(), error = %e, "chmod intermediate shared dir to 2770 failed");
            }
        }

        if let Err(e) = chown(
            &path,
            Some(Uid::from_raw(uid)),
            Some(Gid::from_raw(crbs_gid)),
        ) {
            debug!(path = %path.display(), error = %e, "direct chown to crbs group failed");
        }
        if let Err(e) = fchmodat(None, &path, target_mode, FchmodatFlags::NoFollowSymlink) {
            debug!(path = %path.display(), error = %e, "direct chmod to 2770 failed");
        }

        // 校验不符即回退特权后端。symlink_metadata：leaf 复核后被换 symlink（组
        // 可写窗口）时读到链接自身属主/模式，回退 + helper 拒 symlink，fail-closed。
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| CrbsError::from_io_context("metadata shared dir", e))?;
        let actual_mode = meta.permissions().mode() & 0o7777;
        let actual_gid = meta.gid();
        if actual_mode != SHARED_DIR_MODE || actual_gid != crbs_gid {
            crate::privilege::chown(&path, uid, crbs_gid, false)
                .map_err(|e| CrbsError::io_message(format!("chown shared dir: {e}")))?;
            crate::privilege::chmod(&path, SHARED_DIR_MODE, false)
                .map_err(|e| CrbsError::io_message(format!("chmod shared dir: {e}")))?;
        }
        Ok(())
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("spawn_blocking prepare shared dir: {e}")))??;

    mark_prepared(&prepared_path);
    Ok(())
}

fn is_prepared(path: &Path) -> bool {
    // 锁中毒视为“未准备”：触发一次幂等的 prepare，而非 panic。
    PREPARED_DIRS
        .lock()
        .map(|g| is_prepared_locked(&g, path))
        .unwrap_or(false)
}

fn mark_prepared(path: &Path) {
    // 锁中毒时跳过记录：下次访问会重新走幂等的 prepare 流程。
    if let Ok(mut g) = PREPARED_DIRS.lock() {
        mark_prepared_locked(&mut g, path);
    }
}

/// 集合引用内核：测试全程持锁调用，隔离 PREPARED_DIRS 进程级单例
/// 被同二进制其他测试（ensure_shared_dir → mark_prepared）的并发写入。
fn is_prepared_locked(g: &HashSet<PathBuf>, path: &Path) -> bool {
    g.contains(path)
}

/// 同 [`is_prepared_locked`] 的集合引用内核。
fn mark_prepared_locked(g: &mut HashSet<PathBuf>, path: &Path) {
    if g.len() >= PREPARED_DIRS_CAP {
        g.clear();
    }
    g.insert(path.to_path_buf());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 回归：`created_parents` 为空（leaf 父目录已存在）时，复核链须含该已存在
    /// 中间层——只查 leaf 会漏检预置在中间层的 symlink（可被 create_dir_all 穿过）。
    #[test]
    fn review_chain_covers_existing_parent_when_nothing_new() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ab").join("sha");
        let chain = symlink_review_chain(&path, &[]);
        let rendered: Vec<String> = chain.iter().map(|p| p.display().to_string()).collect();
        assert_eq!(
            rendered,
            vec![
                tmp.path().join("ab").display().to_string(),
                path.display().to_string(),
            ],
            "existing middle layer must be in the review chain"
        );
    }

    /// created_parents 非空：锚（missing_parents 的 break 层）→ 新建父链 → leaf。
    #[test]
    fn review_chain_anchors_at_first_existing_ancestor() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("root").join("ab").join("sha");
        let created = vec![tmp.path().join("root").join("ab")];
        let chain = symlink_review_chain(&path, &created);
        let rendered: Vec<String> = chain.iter().map(|p| p.display().to_string()).collect();
        assert_eq!(
            rendered,
            vec![
                tmp.path().join("root").display().to_string(),
                tmp.path().join("root").join("ab").display().to_string(),
                path.display().to_string(),
            ]
        );
    }

    /// 注入：中间层 `ab` 预置 symlink 指向攻击者树，请求 `ab/sha`——missing
    /// 为空、只查 leaf 会放行，链含 `ab` 后须拒绝。复刻 ensure_shared_dir 的
    /// missing_parents → create_dir_all → 复核顺序（跳过 gid/chown 段，跨平台可跑）。
    #[tokio::test]
    async fn prepared_dir_rejects_preexisting_middle_layer_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let attacker_tree = tempfile::tempdir().unwrap();
        let ab = tmp.path().join("ab");
        std::os::unix::fs::symlink(attacker_tree.path(), &ab).unwrap();

        let path = ab.join("sha");
        let created_parents = missing_parents(&path).await.unwrap();
        assert!(
            created_parents.is_empty(),
            "existing symlink counts as existing for missing_parents"
        );
        tokio::fs::create_dir_all(&path).await.unwrap();
        assert!(
            attacker_tree.path().join("sha").is_dir(),
            "create_dir_all must traverse the symlink (precondition)"
        );

        let err = reject_symlink_chain(&symlink_review_chain(&path, &created_parents))
            .expect_err("pre-existing middle-layer symlink must be rejected");
        match err {
            CrbsError::ValidationFailed { message } => {
                assert!(message.contains("symlink"), "got: {message}");
            }
            other => panic!("expected ValidationFailed, got {other:?}"),
        }
    }

    /// 对照臂：无 symlink 的正常树同流程须放行（拒绝确来自中间层 symlink）。
    #[tokio::test]
    async fn prepared_dir_accepts_plain_preexisting_middle_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let ab = tmp.path().join("ab");
        tokio::fs::create_dir_all(&ab).await.unwrap();

        let path = ab.join("sha");
        let created_parents = missing_parents(&path).await.unwrap();
        tokio::fs::create_dir_all(&path).await.unwrap();
        reject_symlink_chain(&symlink_review_chain(&path, &created_parents))
            .expect("plain pre-existing middle layer must be accepted");
    }

    /// 端到端（Linux + crbs 组，无组时跳过）：中间层预置 symlink 使 prepare 整体失败。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ensure_shared_dir_rejects_preexisting_middle_layer_symlink() {
        if crate::privilege::crbs_group_gid().is_err() {
            eprintln!("skipping: crbs group not available");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let attacker_tree = tempfile::tempdir().unwrap();
        let ab = tmp.path().join("ab");
        std::os::unix::fs::symlink(attacker_tree.path(), &ab).unwrap();

        let err = ensure_shared_dir(&ab.join("sha"))
            .await
            .expect_err("symlinked middle layer must fail the prepare");
        assert!(
            err.to_string().contains("symlink"),
            "unexpected error: {err}"
        );
    }

    /// 预备记忆集 4096 封顶——超帽插入整集清空，清空前旧路径复检为"未预备"
    /// （下次访问多付一次幂等 prepare）；mark/is_prepared 纯集合不触盘，假路径
    /// 可注入。PREPARED_DIRS 为进程级单例，须全程持锁调 _locked 内核并自 clear
    /// 开始，否则其他测试经 ensure_shared_dir 写入会令断言不确定。
    #[test]
    fn prepared_dirs_cap_clears_on_overflow() {
        let mut g = PREPARED_DIRS.lock().unwrap();
        g.clear();
        let base = PathBuf::from("/nonexistent/crbs-cap-test");
        for i in 0..PREPARED_DIRS_CAP {
            mark_prepared_locked(&mut g, &base.join(format!("d{i}")));
        }
        let first = base.join("d0");
        assert!(
            is_prepared_locked(&g, &first),
            "precondition: entry below cap must be prepared"
        );

        let overflow = base.join("overflow");
        mark_prepared_locked(&mut g, &overflow);
        assert!(
            !is_prepared_locked(&g, &first),
            "cap overflow must clear earlier entries (is_prepared re-check)"
        );
        assert!(
            is_prepared_locked(&g, &overflow),
            "the overflowing insert itself must be recorded"
        );
    }
}
