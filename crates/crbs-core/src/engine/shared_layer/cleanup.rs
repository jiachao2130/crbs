// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 共享层目录清理：失效层体的受控删除。

use std::path::Path;

use chrono::Utc;
use tracing::warn;

use crate::engine::shared_layer::ttl::parse_stale_upper_timestamp;
use crate::error::CrbsError;
use crate::gc::assert_delete_under_root;

/// 清理 layer 目录内容（保留 .lock 与近期 stale upper 备份）：先 umount merged
///（overlay 可能残留）再删全部文件；`upper.stale.*` 保留 24 小时内 rename 移走的
///（可能仍被进行中构建引用），更老的删除；保留判定用文件名内嵌 rename 时间戳
/// 而非 mtime（rename 保留原 mtime，见 `parse_stale_upper_timestamp`）。
pub(crate) async fn cleanup_layer_dir(layer_dir: &Path) -> crate::Result<()> {
    const STALE_RETENTION: std::time::Duration = std::time::Duration::from_secs(24 * 3600);
    let merged = layer_dir.join("merged");
    if tokio::fs::try_exists(&merged).await.unwrap_or(false) {
        let merged_clone = merged.clone();
        match crate::privilege::umount_detach(merged_clone).await {
            Ok(()) => {}
            Err(e) => {
                warn!(
                    path = %merged.display(),
                    error = %e,
                    "Failed to umount merged layer dir, continuing cleanup"
                );
            }
        }
    }

    let mut entries = tokio::fs::read_dir(layer_dir)
        .await
        .map_err(|e| CrbsError::from_io_context("read layer dir", e))?;

    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(e)) => e,
            // 中途 IO 错误静默截断会把清理伪装成功——残留半成品 upper 被新
            // overlay 挂载并 .complete 共享给全部同 digest 构建；返回 Err 重试。
            Ok(None) => break,
            Err(e) => {
                return Err(CrbsError::io_message(format!(
                    "iterate layer dir {}: {e}",
                    layer_dir.display()
                )));
            }
        };
        let path = entry.path();
        if path.file_name() == Some(std::ffi::OsStr::new(".lock")) {
            continue;
        }
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("upper.stale."))
            .unwrap_or(false)
        {
            // 判定必须用文件名内嵌 rename 时间戳：rename 保留原 mtime，旧
            // upper 的 mtime 天然早于 TTL，按 mtime 会立即删掉刚移走、仍被
            // 进行中构建引用的 upper；解析失败保守保留。
            let keep = match path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(parse_stale_upper_timestamp)
            {
                Some(renamed_at) => {
                    Utc::now().signed_duration_since(renamed_at)
                        < chrono::Duration::seconds(STALE_RETENTION.as_secs() as i64)
                }
                None => true,
            };
            if keep {
                continue;
            }
        }
        // 删除前断言目标严格位于 layer_dir 命名空间之下（防路径逃逸，
        // 与 gc::cleanup_stale_shared_layer_uppers 的守卫一致）。
        if let Err(e) = assert_delete_under_root(layer_dir, &path) {
            warn!(
                path = %path.display(),
                error = %e,
                "Refusing to remove layer dir entry outside namespace"
            );
            continue;
        }
        let is_dir = match entry.file_type().await {
            Ok(t) => t.is_dir(),
            Err(e) => {
                return Err(CrbsError::io_message(format!(
                    "stat layer dir entry {}: {e}",
                    path.display()
                )));
            }
        };
        if is_dir {
            // 特权 rm_rf：upper 是 dnf/rpmbuild 以 root/builder 写入的树，
            // 非 root 进程 remove_dir_all 会 EACCES 永久泄漏。
            if let Err(e) = crate::privilege::rm_rf_async(&[path.as_path()]).await {
                warn!(path = %path.display(), error = %e, "Failed to remove layer dir entry");
            }
        } else if let Err(e) = tokio::fs::remove_file(&path).await {
            warn!(path = %path.display(), error = %e, "Failed to remove layer file entry");
        }
    }
    Ok(())
}
