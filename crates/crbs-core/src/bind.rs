// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 用户自定义 bind mount（`--bind`）：宿主机目录挂到容器 `/mnt/` 下，默认只读（`:rw` 可写）；用于 `crbs shell` / `crbs debug`。

use std::path::{Component, PathBuf};

/// 一条用户指定的 bind mount：`host` 已 canonicalize 且存在，`container` 强制 `/mnt/` 子目录。
#[derive(Debug, Clone)]
pub struct UserBind {
    pub host: PathBuf,
    pub container: PathBuf,
    pub read_only: bool,
}

/// 解析 `--bind` 规格字符串：`host[:container[:ro|rw]]`，按 `:` 最多切三段（host 路径
/// 不支持含 `:`，无转义机制）；省略 container → `/mnt/<host basename>`，省略 mode →
/// `ro`（默认只读）。container 必须 `/mnt/` 子目录；host 必须存在、拒绝字面 `..`——
/// canonicalize 会跟随符号链接，该检查非安全边界，实际隔离由下游 privilege/priv-helper 负责。
pub async fn parse_bind_spec(spec: &str) -> crate::Result<UserBind> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    let host_str = parts[0];
    let host = std::path::Path::new(host_str);

    // 拒绝字面包含 '..' 的规格（非安全边界，实际隔离在 privilege 层）
    if host.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(crate::error::CrbsError::ValidationFailed {
            message: format!("--bind host path contains '..': {}", host_str),
        });
    }

    let host_canon = tokio::fs::canonicalize(host)
        .await
        .map_err(|e| crate::error::CrbsError::from_io_context("--bind host not found", e))?;

    let container = match parts.get(1).filter(|s| !s.is_empty()) {
        Some(c) => PathBuf::from(c),
        None => PathBuf::from(format!(
            "/mnt/{}",
            host_canon
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("bind")
        )),
    };

    // 防止容器路径穿越
    if container
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(crate::error::CrbsError::ValidationFailed {
            message: format!(
                "--bind container path contains '..': {}",
                container.display()
            ),
        });
    }

    // 强制 /mnt/ 前缀（必须是 /mnt/ 下的子目录，不能是 /mnt 本身）
    let container_str = container.as_os_str().to_str().ok_or_else(|| {
        crate::error::CrbsError::ValidationFailed {
            message: "--bind container path is not valid UTF-8".to_string(),
        }
    })?;
    if !container_str.starts_with("/mnt/") {
        return Err(crate::error::CrbsError::ValidationFailed {
            message: format!(
                "--bind container path must be a subdirectory of /mnt/: got {}",
                container.display()
            ),
        });
    }

    let read_only = match parts.get(2) {
        Some(&"rw") => false,
        Some(&"ro") | None => true,
        Some(mode) => {
            return Err(crate::error::CrbsError::ValidationFailed {
                message: format!("--bind mode must be 'ro' or 'rw', got: {}", mode),
            });
        }
    };

    Ok(UserBind {
        host: host_canon,
        container,
        read_only,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_bind_explicit_ro_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let host = tmp.path().join("data");
        tokio::fs::create_dir(&host).await.unwrap();
        let spec = format!("{}:/mnt/data:ro", host.display());
        let bind = parse_bind_spec(&spec).await.unwrap();
        assert_eq!(bind.host, host.canonicalize().unwrap());
        assert_eq!(bind.container, PathBuf::from("/mnt/data"));
        assert!(bind.read_only);
    }

    #[tokio::test]
    async fn test_parse_bind_rejects_invalid_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let host = tmp.path().join("data");
        tokio::fs::create_dir(&host).await.unwrap();
        let spec = format!("{}:/mnt/data:abc", host.display());
        let err = parse_bind_spec(&spec).await.unwrap_err();
        assert!(format!("{}", err).contains("mode must be 'ro' or 'rw'"));
    }

    #[tokio::test]
    async fn test_parse_bind_defaults_to_ro_and_basename() {
        let tmp = tempfile::tempdir().unwrap();
        let host = tmp.path().join("data");
        tokio::fs::create_dir(&host).await.unwrap();
        let spec = format!("{}:", host.display());
        let bind = parse_bind_spec(&spec).await.unwrap();
        assert_eq!(bind.container, PathBuf::from("/mnt/data"));
        assert!(bind.read_only);
    }

    #[tokio::test]
    async fn test_parse_bind_rw_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let host = tmp.path().join("data");
        tokio::fs::create_dir(&host).await.unwrap();
        let spec = format!("{}:/mnt/data:rw", host.display());
        let bind = parse_bind_spec(&spec).await.unwrap();
        assert!(!bind.read_only);
    }

    #[tokio::test]
    async fn test_parse_bind_rejects_host_parent_dir() {
        let spec = "/tmp/../etc:/mnt/etc";
        let err = parse_bind_spec(spec).await.unwrap_err();
        assert!(format!("{}", err).contains("host path contains '..'"));
    }

    #[tokio::test]
    async fn test_parse_bind_rejects_container_parent_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let host = tmp.path().join("data");
        tokio::fs::create_dir(&host).await.unwrap();
        let spec = format!("{}:/mnt/../etc", host.display());
        let err = parse_bind_spec(&spec).await.unwrap_err();
        assert!(format!("{}", err).contains("container path contains '..'"));
    }

    #[tokio::test]
    async fn test_parse_bind_rejects_missing_host() {
        let spec = "/does/not/exist:/mnt/x";
        let err = parse_bind_spec(spec).await.unwrap_err();
        assert!(format!("{}", err).contains("host not found"));
    }

    #[tokio::test]
    async fn test_parse_bind_rejects_invalid_container_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let host = tmp.path().join("data");
        tokio::fs::create_dir(&host).await.unwrap();
        let spec = format!("{}:/tmp/data", host.display());
        let err = parse_bind_spec(&spec).await.unwrap_err();
        assert!(format!("{}", err).contains("subdirectory of /mnt"));
    }

    #[tokio::test]
    async fn test_parse_bind_rejects_container_exact_mnt() {
        let tmp = tempfile::tempdir().unwrap();
        let host = tmp.path().join("data");
        tokio::fs::create_dir(&host).await.unwrap();
        let spec = format!("{}:/mnt", host.display());
        let err = parse_bind_spec(&spec).await.unwrap_err();
        assert!(format!("{}", err).contains("subdirectory of /mnt"));
    }
}
