// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! depsolve 阶段 SRPM 的 BR 提取结果磁盘缓存：跨次 `--chain` 构建复用
//! `rpm -qpR`（读 BR）结果，省每包重复的 rpm 子进程启动开销。BR 只取决于
//! SRPM 文件本身、不依赖 repo 状态：无 repo 指纹，按 mtime（纳秒）+ size 失效。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tracing::warn;

use crate::engine::depsolve::SrpmInfo;
use crate::error::CrbsError;

/// 缓存文件版本号，格式不兼容时自增（旧缓存一次性失效重建）。
const CACHE_VERSION: u32 = 4;

fn cache_path(repo_dir: &Path) -> PathBuf {
    repo_dir.join("depsolve-br-cache.json")
}

/// 原子写临时文件路径。仅 pid 不够——同进程并发 save 会互踩固定 tmp 名，
/// 追加 uuid 保证唯一。
fn tmp_path(repo_dir: &Path) -> PathBuf {
    let pid = std::process::id();
    repo_dir.join(format!(
        "depsolve-br-cache.tmp.{}.{}",
        pid,
        uuid::Uuid::new_v4()
    ))
}

/// SRPM 的 BR 提取结果磁盘缓存。仅在 `prepare_chain_context` 串行 for 循环
/// 里使用——无并发、无 Arc/RwLock；命中条件：path + mtime + size 全部匹配。
#[derive(Debug, Clone)]
pub struct BrCache {
    version: u32,
    srpms: HashMap<PathBuf, BrCacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrCacheEntry {
    /// SRPM mtime：UNIX_EPOCH 起的**纳秒**；秒级粒度会让同秒重建的 SRPM 误命中。
    mtime: u64,
    size: u64,
    name: String,
    arch: String,
    build_requires: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheFile {
    version: u32,
    srpms: HashMap<PathBuf, BrCacheEntry>,
}

impl Default for BrCache {
    fn default() -> Self {
        Self::empty()
    }
}

impl BrCache {
    /// 加载 `{repo_dir}/depsolve-br-cache.json`。失败语义：损坏返回 `Err`（NotFound
    /// 返回空 cache），降级由调用方定（典型 `unwrap_or_default()` + warn，不阻断 chain）。
    pub async fn load(repo_dir: &Path) -> crate::Result<Self> {
        let path = cache_path(repo_dir);
        match tokio::fs::read(&path).await {
            Ok(bytes) => match serde_json::from_slice::<CacheFile>(&bytes) {
                Ok(file) => {
                    if file.version != CACHE_VERSION {
                        warn!(
                            path = %path.display(),
                            file_version = file.version,
                            expected_version = CACHE_VERSION,
                            "BR cache version mismatch; ignoring"
                        );
                        Ok(Self::empty())
                    } else {
                        Ok(Self {
                            version: file.version,
                            srpms: file.srpms,
                        })
                    }
                }
                Err(e) => Err(CrbsError::io_message(format!(
                    "parse BR cache {}: {}",
                    path.display(),
                    e
                ))),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::empty()),
            Err(e) => Err(CrbsError::io_message(format!(
                "read BR cache {}: {}",
                path.display(),
                e
            ))),
        }
    }

    /// 原子保存：写 `.tmp.{pid}.{uuid}` → `rename()` 覆盖目标文件。失败返回
    /// Err（调用方 warn 降级，不阻断 chain）；失败路径兜底删除 tmp，防残留累积。
    pub async fn save(&self, repo_dir: &Path) -> crate::Result<()> {
        let target = cache_path(repo_dir);
        let tmp = tmp_path(repo_dir);

        let file = CacheFile {
            version: self.version,
            srpms: self.srpms.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(|e| CrbsError::io_message(format!("serialize BR cache: {}", e)))?;

        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| CrbsError::io_message(format!("create BR cache dir: {}", e)))?;
        }

        let write_result: crate::Result<()> = async {
            let mut f = tokio::fs::File::create(&tmp)
                .await
                .map_err(|e| CrbsError::io_message(format!("create tmp BR cache: {}", e)))?;
            f.write_all(&bytes)
                .await
                .map_err(|e| CrbsError::io_message(format!("write tmp BR cache: {}", e)))?;
            f.sync_all()
                .await
                .map_err(|e| CrbsError::io_message(format!("sync tmp BR cache: {}", e)))?;
            drop(f);

            tokio::fs::rename(&tmp, &target)
                .await
                .map_err(|e| CrbsError::io_message(format!("rename BR cache: {}", e)))?;
            Ok(())
        }
        .await;
        if let Err(e) = write_result {
            if let Err(rm) = tokio::fs::remove_file(&tmp).await {
                if rm.kind() != std::io::ErrorKind::NotFound {
                    warn!(path = %tmp.display(), error = %rm, "Failed to clean up tmp BR cache file");
                }
            }
            return Err(e);
        }
        // 权限不变量：rename 后对目标文件收敛 0660 + crbs 组（跨身份可读写）。
        crate::engine::cache::normalize_cache_file_perms(&target).await;
        Ok(())
    }

    /// 查缓存：path + mtime + size 全部匹配返回 [`SrpmInfo`]（不含 path，由调用方注入）。
    pub fn get(&self, path: &Path, mtime: u64, size: u64) -> Option<SrpmInfo> {
        let entry = self.srpms.get(path)?;
        if entry.mtime != mtime || entry.size != size {
            return None;
        }
        Some(SrpmInfo {
            name: entry.name.clone(),
            path: path.to_path_buf(),
            arch: entry.arch.clone(),
            build_requires: entry.build_requires.clone(),
        })
    }

    /// 回填：写入/覆盖指定 SRPM 的提取结果。
    pub fn insert(&mut self, path: &Path, mtime: u64, size: u64, info: &SrpmInfo) {
        self.srpms.insert(
            path.to_path_buf(),
            BrCacheEntry {
                mtime,
                size,
                name: info.name.clone(),
                arch: info.arch.clone(),
                build_requires: info.build_requires.clone(),
            },
        );
    }

    /// 裁剪：只保留 `keep` 里的路径条目，删除其余（清理已不存在的 SRPM 条目）。
    pub fn prune_to(&mut self, keep: &HashSet<PathBuf>) {
        self.srpms.retain(|p, _| keep.contains(p));
    }

    /// entries 数量（测试用）。
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.srpms.len()
    }

    /// 是否为空（测试用）。
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.srpms.is_empty()
    }

    fn empty() -> Self {
        Self {
            version: CACHE_VERSION,
            srpms: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tokio_test_block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn load_blocking(p: &Path) -> BrCache {
        tokio_test_block_on(BrCache::load(p)).unwrap()
    }

    fn save_blocking(c: &BrCache, p: &Path) {
        tokio_test_block_on(c.save(p)).unwrap();
    }

    fn sample_info(name: &str, br: Vec<&str>) -> SrpmInfo {
        SrpmInfo {
            name: name.to_string(),
            path: PathBuf::from("/nonexistent"),
            arch: "x86_64".to_string(),
            build_requires: br.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cache = BrCache::default();
        let path = tmp.path().join("glibc-2.34.src.rpm");
        let info = sample_info("glibc", vec!["gcc >= 7.0", "make"]);
        cache.insert(&path, 1722700000, 28521248, &info);

        save_blocking(&cache, tmp.path());
        let loaded = load_blocking(tmp.path());
        assert_eq!(loaded.len(), 1);

        let got = loaded.get(&path, 1722700000, 28521248).unwrap();
        assert_eq!(got.name, "glibc");
        assert_eq!(got.build_requires, vec!["gcc >= 7.0", "make"]);
    }

    #[test]
    fn get_returns_none_on_mtime_change() {
        let mut cache = BrCache::default();
        let path = PathBuf::from("/x.src.rpm");
        cache.insert(&path, 100, 1000, &sample_info("x", vec![]));

        assert!(cache.get(&path, 200, 1000).is_none());
    }

    #[test]
    fn get_returns_none_on_size_change() {
        let mut cache = BrCache::default();
        let path = PathBuf::from("/x.src.rpm");
        cache.insert(&path, 100, 1000, &sample_info("x", vec![]));

        assert!(cache.get(&path, 100, 2000).is_none());
    }

    #[test]
    fn get_returns_none_on_missing_path() {
        let cache = BrCache::default();
        assert!(cache.get(Path::new("/missing.src.rpm"), 0, 0).is_none());
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = load_blocking(tmp.path());
        assert!(cache.is_empty());
    }

    #[test]
    fn load_corrupt_file_returns_err() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path()).unwrap();
        std::fs::write(cache_path(tmp.path()), b"not json {{{").unwrap();

        let result = tokio_test_block_on(BrCache::load(tmp.path()));
        assert!(result.is_err(), "corrupt cache should return Err, got Ok");
    }

    #[test]
    fn load_wrong_version_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path()).unwrap();
        let file = serde_json::json!({
            "version": 999,
            "srpms": {}
        });
        std::fs::write(cache_path(tmp.path()), serde_json::to_vec(&file).unwrap()).unwrap();

        let cache = load_blocking(tmp.path());
        assert!(cache.is_empty());
    }

    #[test]
    fn save_atomic_via_tmp_then_rename() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path()).unwrap();

        let path = PathBuf::from("/x.src.rpm");
        let mut c1 = BrCache::default();
        c1.insert(&path, 1, 1, &sample_info("x", vec!["a"]));
        save_blocking(&c1, tmp.path());

        let mut c2 = BrCache::default();
        c2.insert(&path, 1, 1, &sample_info("x", vec!["b"]));
        save_blocking(&c2, tmp.path());

        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries.len(), 1, "tmp file leaked: {:?}", entries);
        assert_eq!(entries[0], "depsolve-br-cache.json");

        let loaded = load_blocking(tmp.path());
        let got = loaded.get(&path, 1, 1).unwrap();
        assert_eq!(got.build_requires, vec!["b".to_string()]);
    }

    #[test]
    fn prune_to_keeps_only_listed() {
        let mut cache = BrCache::default();
        let p1 = PathBuf::from("/a.src.rpm");
        let p2 = PathBuf::from("/b.src.rpm");
        let p3 = PathBuf::from("/c.src.rpm");
        cache.insert(&p1, 1, 1, &sample_info("a", vec![]));
        cache.insert(&p2, 1, 1, &sample_info("b", vec![]));
        cache.insert(&p3, 1, 1, &sample_info("c", vec![]));
        assert_eq!(cache.len(), 3);

        let keep: HashSet<PathBuf> = [p1.clone(), p3.clone()].into_iter().collect();
        cache.prune_to(&keep);

        assert_eq!(cache.len(), 2);
        assert!(cache.get(&p1, 1, 1).is_some());
        assert!(cache.get(&p2, 1, 1).is_none());
        assert!(cache.get(&p3, 1, 1).is_some());
    }

    #[test]
    fn insert_overwrites_existing() {
        let mut cache = BrCache::default();
        let path = PathBuf::from("/x.src.rpm");
        cache.insert(&path, 1, 1, &sample_info("x", vec!["old"]));
        cache.insert(&path, 2, 2, &sample_info("x", vec!["new"]));

        assert_eq!(cache.len(), 1);
        let got = cache.get(&path, 2, 2).unwrap();
        assert_eq!(got.build_requires, vec!["new".to_string()]);
    }
}
