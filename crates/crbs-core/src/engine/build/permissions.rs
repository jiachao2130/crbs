// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建结果目录权限 helper。

use std::path::Path;

use crate::error::CrbsError;

/// Build 前 `result_dir` 预备：chown builder:crbs + setgid 0o2770，chroot 内 builder 与 crbs 主进程均可写。
pub(crate) async fn prepare_for_build(
    result_dir: &Path,
    builder_uid: u32,
    crbs_gid: u32,
) -> crate::Result<()> {
    chown_chmod_2770(result_dir, builder_uid, crbs_gid, "result dir").await
}

/// chown builder:crbs + setgid group-writable（0o2770）；`label` 进错误消息。
pub(crate) async fn chown_chmod_2770(
    dir: &Path,
    builder_uid: u32,
    crbs_gid: u32,
    label: &str,
) -> crate::Result<()> {
    crate::engine::layer::chown_recursive(dir, builder_uid, crbs_gid)
        .await
        .map_err(|e| CrbsError::io_message(format!("chown {label} to builder: {e}")))?;
    crate::engine::layer::chmod_recursive(dir, 0o2770)
        .await
        .map_err(|e| CrbsError::io_message(format!("chmod {label} to 2770: {e}")))?;
    Ok(())
}

/// 构建（含可选签名）后把 `result_dir` 收敛到权限不变量：目录
/// 0o2770（setgid + group rwx）、文件 0o0660（walker 对 file 走 `mode & 0o666`），
/// 均 group `crbs`；走特权 backend，目录属主为 builder 等他者时仍可收敛。
pub(crate) async fn finalize_result_dir(result_dir: &Path) -> crate::Result<()> {
    crate::engine::layer::chmod_recursive(result_dir, 0o2770)
        .await
        .map_err(|e| CrbsError::io_message(format!("finalize result dir: {e}")))?;
    if !result_dir_setgid_ok(result_dir).await {
        // priv-helper 的 chmod 保 CAP_FOWNER 不保 CAP_FSETID，调用者不在文件
        // 属组时内核剥离 S_ISGID——目录落成 0770 而非 2770、模式位跨执行身份
        // 漂移且无失败信号，读回实际 mode 告警；修复属操作面。
        match tokio::fs::metadata(result_dir).await {
            Ok(meta) => tracing::warn!(
                path = %result_dir.display(),
                mode = format!("0o{:o}", std::os::unix::fs::PermissionsExt::mode(
                    &meta.permissions()
                ) & 0o7777),
                "setgid bit missing on result dir after chmod: caller is likely outside the \
                 file's group (helper chmod does not retain CAP_FSETID); group access and \
                 reproducible directory modes are degraded - add the invoking user to the \
                 crbs group"
            ),
            Err(e) => tracing::warn!(
                path = %result_dir.display(),
                error = %e,
                "stat result dir for setgid verification failed"
            ),
        }
    }
    Ok(())
}

/// setgid 自校验：读回 result_dir 实际 mode，判断 S_ISGID 是否真的生效。
async fn result_dir_setgid_ok(result_dir: &Path) -> bool {
    match tokio::fs::metadata(result_dir).await {
        Ok(meta) => std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o2000 != 0,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn test_finalize_result_dir_sets_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("result");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let file = dir.join("file.rpm");
        tokio::fs::write(&file, b"").await.unwrap();

        tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o2770))
            .await
            .unwrap();
        tokio::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o664))
            .await
            .unwrap();

        // 无需特权：temp dir 属主即当前用户。
        finalize_result_dir(&dir).await.unwrap();

        let dir_meta = tokio::fs::metadata(&dir).await.unwrap();
        let file_meta = tokio::fs::metadata(&file).await.unwrap();

        assert_eq!(dir_meta.permissions().mode() & 0o7777, 0o2770);
        assert_eq!(file_meta.permissions().mode() & 0o7777, 0o660);

        assert!(result_dir_setgid_ok(&dir).await);
        tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o0770))
            .await
            .unwrap();
        assert!(!result_dir_setgid_ok(&dir).await);
    }
}
