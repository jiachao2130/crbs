// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建脚本文件生成：磁盘落盘、字节写入与钩子文件。

use crate::engine::pipeline::HookFile;
use crate::error::CrbsError;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tracing::warn;

/// 原子写入构建脚本/hook 文件：同目录 tmp + rename，读取方只见旧或完整新内容；write+fsync、
/// chmod 均在 rename 前完成（崩溃不落空/半截脚本，最终权限即 `mode`）；tmp 名含 pid + uuid，并发构建互不冲突。
pub(crate) async fn write_script(path: &Path, content: &str, mode: u32) -> crate::Result<()> {
    write_script_bytes(path, content.as_bytes(), mode).await
}

/// [`write_script`] 的字节版：落盘非 UTF-8 内容（如沙箱内 helper 二进制）
/// 走同一条原子替换路径。
pub(crate) async fn write_script_bytes(
    path: &Path,
    content: &[u8],
    mode: u32,
) -> crate::Result<()> {
    let tmp_path = path.with_extension(format!(
        "sh.tmp.{}.{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));

    let mut file = match tokio::fs::File::create(&tmp_path).await {
        Ok(f) => f,
        Err(e) => return Err(CrbsError::from_io_context("create temp script", e)),
    };
    if let Err(e) = file.write_all(content).await {
        cleanup_temp(&tmp_path).await;
        return Err(CrbsError::from_io_context("write temp script", e));
    }
    if let Err(e) = file.sync_all().await {
        cleanup_temp(&tmp_path).await;
        return Err(CrbsError::from_io_context("sync temp script", e));
    }
    drop(file);
    if let Err(e) =
        tokio::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(mode)).await
    {
        cleanup_temp(&tmp_path).await;
        return Err(CrbsError::from_io_context("chmod script", e));
    }
    if let Err(e) = tokio::fs::rename(&tmp_path, path).await {
        cleanup_temp(&tmp_path).await;
        return Err(CrbsError::from_io_context("rename script", e));
    }
    Ok(())
}

/// 将 hook 文件落进构建根的 `crbs-hooks/`（容器内 `/crbs-hooks`）。权限不变量：目录 0750、
/// 文件 0640、属主 = builder uid:gid——nosuid rootfs（build_tmpfs）上 setuid sudo 不可用，
/// spec hook 注入行靠 builder 身份普通 `cat` 读文件，须 builder 可读；hook 体本就以
/// builder 身份在 scriptlet shell 内 eval，可读不扩大执行权限。chown 必须在全部文件
/// 写入完成之后收尾：转属 builder 后引擎进程（非 builder 及其组）对目录即失去写权。
/// 低于仓库"文件 0660 组可写"的协作不变量属刻意豁免（随构建根消亡、无协作读写需求
/// 的运行时资产）。构建脚本（0755）只引用路径，失败日志只带路径不带内容。
pub(crate) async fn write_hook_files(
    root: &Path,
    files: &[HookFile],
    builder_uid: u32,
    builder_gid: u32,
) -> crate::Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    let dir = root.join("crbs-hooks");
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| CrbsError::from_io_context("create crbs-hooks dir", e))?;
    tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750))
        .await
        .map_err(|e| CrbsError::from_io_context("chmod crbs-hooks dir 0750", e))?;
    for file in files {
        let path = root.join(file.container_path.trim_start_matches('/'));
        write_script(&path, &file.content, 0o640)
            .await
            .map_err(|e| {
                CrbsError::io_message(format!("write hook file {}: {}", file.container_path, e))
            })?;
    }
    // chown 收尾（见 doc 顺序约束）；失败仅 debug——非 root 进程 chown 别人必然
    // EPERM（测试即此形态），mode 已保证本进程可读写。
    if let Err(e) = crate::privilege::chown_async(&dir, builder_uid, builder_gid, false).await {
        tracing::debug!(path = %dir.display(), error = %e, "chown crbs-hooks dir to builder failed; skip");
    }
    for file in files {
        let path = root.join(file.container_path.trim_start_matches('/'));
        if let Err(e) = crate::privilege::chown_async(&path, builder_uid, builder_gid, false).await
        {
            tracing::debug!(path = %path.display(), error = %e, "chown hook file to builder failed; skip");
        }
    }
    Ok(())
}

async fn cleanup_temp(tmp_path: &Path) {
    if let Err(e) = tokio::fs::remove_file(tmp_path).await {
        warn!(path = %tmp_path.display(), error = %e, "Failed to clean up temp script file");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 多次写入后目标为完整最新内容、带执行位、无 tmp 残留（rename 语义）。
    #[tokio::test]
    async fn write_script_replaces_atomically_and_leaves_no_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("crbs-build.sh");

        write_script(&script, "#!/bin/sh\necho v1\n", 0o755)
            .await
            .unwrap();
        write_script(&script, "#!/bin/sh\necho v2\n", 0o755)
            .await
            .unwrap();

        let content = tokio::fs::read_to_string(&script).await.unwrap();
        assert_eq!(content, "#!/bin/sh\necho v2\n");
        let mode = std::fs::metadata(&script).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);

        let mut entries: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        assert_eq!(entries, vec!["crbs-build.sh".to_string()]);
    }

    #[tokio::test]
    async fn write_script_applies_requested_mode() {
        let dir = tempfile::tempdir().unwrap();
        let hook = dir.path().join("pre-build.sh");
        write_script(&hook, "echo secret\n", 0o600).await.unwrap();
        let mode = std::fs::metadata(&hook).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// 字节版：非 UTF-8 内容原样落盘、模式生效、同目标重复写为原子替换。
    #[tokio::test]
    async fn write_script_bytes_writes_binary_content_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("crbs-normalize");
        write_script_bytes(&bin, b"\x7fELF\x01payload", 0o755)
            .await
            .unwrap();
        write_script_bytes(&bin, &[0u8, 159, 146, 150], 0o755)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&bin).unwrap(), &[0u8, 159, 146, 150]);
        let mode = std::fs::metadata(&bin).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        let entries: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["crbs-normalize".to_string()]);
    }

    /// 容器内路径映射到构建根 `crbs-hooks/`，0750/0640、内容原样落盘（尾换行补齐在 pipeline::hook_files）；空清单不创建目录。
    /// 属主不断言：chown 到 builder 在非 root 测试进程必然 EPERM（仅 debug 跳过），mode 不受影响。
    #[tokio::test]
    async fn write_hook_files_applies_builder_readable_modes() {
        let root = tempfile::tempdir().unwrap();
        let files = vec![
            HookFile {
                container_path: "/crbs-hooks/pre-build.sh".to_string(),
                content: "echo 'hook body'\n".to_string(),
            },
            HookFile {
                container_path: "/crbs-hooks/spec-pre-prep.sh".to_string(),
                content: "echo 'spec body'\n".to_string(),
            },
        ];
        write_hook_files(root.path(), &files, 1000, 1000)
            .await
            .unwrap();

        let dir_mode = std::fs::metadata(root.path().join("crbs-hooks"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o750);

        let hook_path = root.path().join("crbs-hooks/pre-build.sh");
        assert_eq!(
            tokio::fs::read_to_string(&hook_path).await.unwrap(),
            "echo 'hook body'\n"
        );
        assert_eq!(
            std::fs::metadata(&hook_path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(
            tokio::fs::read_to_string(root.path().join("crbs-hooks/spec-pre-prep.sh"))
                .await
                .unwrap(),
            "echo 'spec body'\n"
        );
        let empty_root = tempfile::tempdir().unwrap();
        write_hook_files(empty_root.path(), &[], 1000, 1000)
            .await
            .unwrap();
        assert!(!empty_root.path().join("crbs-hooks").exists());
    }
}
