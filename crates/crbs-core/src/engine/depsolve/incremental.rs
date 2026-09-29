// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 增量构建辅助：result_dir 产物命中检查。

use std::path::{Path, PathBuf};

/// 检查 SRPM 是否已在 result_dir 有构建产物。路径用 `srpm_pkg_name`（SRPM
/// 文件名去掉 `.src.rpm`，含 NEVR 但无 dist）定位子目录，不经 rpm 宏展开：
/// 宿主机 vs 容器 `%dist` 不一致（如 `.mydist` vs `.ule3`）会让宏展开出的
/// 文件名永久 miss。判定：`{result_dir}/{product}/{srpm_stem}/` 存在且
/// 至少一个 timestamp 子目录、子目录树内含 `.rpm` 文件。
pub async fn is_built_in_results(
    result_dir: &Path,
    product: &str,
    srpm: &Path,
) -> crate::Result<bool> {
    let pkg_name = crate::engine::build::srpm_pkg_name(srpm)?;
    let pkg_root = result_dir.join(product).join(&pkg_name);
    if !tokio::fs::try_exists(&pkg_root).await? {
        return Ok(false);
    }
    let mut entries = tokio::fs::read_dir(&pkg_root).await?;
    while let Some(entry) = entries.next_entry().await? {
        if !entry.file_type().await?.is_dir() {
            continue;
        }
        if has_rpm_file(entry.path()).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 迭代（Vec 栈，规避 async fn 递归编译问题）检查目录树内是否含 `.rpm` 文件；
/// 深度上限 3（timestamp/RPMS/{arch}/xxx.rpm 共 3 层）防异常大目录无限遍历。
async fn has_rpm_file(path: PathBuf) -> crate::Result<bool> {
    const MAX_DEPTH: usize = 3;
    let mut stack: Vec<(PathBuf, usize)> = vec![(path, 0)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            continue;
        }
        let mut entries = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let file_type = entry.file_type().await?;
            let name = entry.file_name();
            let name_lossy = name.to_string_lossy();
            if file_type.is_file() && name_lossy.ends_with(".rpm") {
                return Ok(true);
            }
            if file_type.is_dir() {
                stack.push((entry.path(), depth + 1));
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_built_in_results ────────────────────────────────────────────
    #[tokio::test]
    async fn is_built_in_results_returns_false_when_pkg_root_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let srpm = tmp.path().join("foo-1.0-1.oe2203sp4.src.rpm");
        std::fs::write(&srpm, b"").unwrap();
        let result_dir = tmp.path().join("results");
        let got = is_built_in_results(&result_dir, "ule3sp4", &srpm)
            .await
            .unwrap();
        assert!(!got);
    }

    #[tokio::test]
    async fn is_built_in_results_returns_false_when_no_rpm_inside() {
        // 模拟 build 失败：timestamp 子目录存在但里面没 .rpm
        let tmp = tempfile::tempdir().unwrap();
        let srpm = tmp.path().join("foo-1.0-1.oe2203sp4.src.rpm");
        std::fs::write(&srpm, b"").unwrap();
        let result_dir = tmp.path().join("results");
        let pkg_root = result_dir.join("ule3sp4").join("foo-1.0-1.oe2203sp4");
        let ts_dir = pkg_root.join("20260805-120000-0001");
        std::fs::create_dir_all(&ts_dir).unwrap();
        std::fs::write(ts_dir.join("build.log"), b"FAILED").unwrap();
        let got = is_built_in_results(&result_dir, "ule3sp4", &srpm)
            .await
            .unwrap();
        assert!(!got, "build 失败（有 timestamp 但无 .rpm）应不命中");
    }

    #[tokio::test]
    async fn is_built_in_results_returns_true_when_rpm_present() {
        let tmp = tempfile::tempdir().unwrap();
        let srpm = tmp.path().join("foo-1.0-1.oe2203sp4.src.rpm");
        std::fs::write(&srpm, b"").unwrap();
        let result_dir = tmp.path().join("results");
        let pkg_root = result_dir.join("ule3sp4").join("foo-1.0-1.oe2203sp4");
        let ts_dir = pkg_root.join("20260805-120000-0002");
        std::fs::create_dir_all(&ts_dir).unwrap();
        // rpm 文件名 dist 后缀故意与 SRPM 不同（模拟 host vs container %dist 不一致）。
        std::fs::write(
            ts_dir.join("foo-1.0-1.ule3.aarch64.rpm"),
            b"fake-rpm-content",
        )
        .unwrap();
        let got = is_built_in_results(&result_dir, "ule3sp4", &srpm)
            .await
            .unwrap();
        assert!(got);
    }

    #[tokio::test]
    async fn is_built_in_results_finds_rpm_in_any_timestamp_subdir() {
        // 多个 timestamp 子目录，任意一个含 .rpm 即命中（失败 build 留下的旧目录不阻塞）。
        let tmp = tempfile::tempdir().unwrap();
        let srpm = tmp.path().join("foo-1.0-1.oe2203sp4.src.rpm");
        std::fs::write(&srpm, b"").unwrap();
        let result_dir = tmp.path().join("results");
        let pkg_root = result_dir.join("ule3sp4").join("foo-1.0-1.oe2203sp4");
        // 第一个 timestamp：失败（无 rpm）
        let ts_failed = pkg_root.join("20260805-120000-0001");
        std::fs::create_dir_all(&ts_failed).unwrap();
        std::fs::write(ts_failed.join("build.log"), b"FAILED").unwrap();
        // 第二个 timestamp：成功（产物在真实路径 RPMS/noarch/ 下）
        let ts_success = pkg_root.join("20260805-130000-0002");
        let rpms_dir = ts_success.join("RPMS").join("noarch");
        std::fs::create_dir_all(&rpms_dir).unwrap();
        std::fs::write(rpms_dir.join("foo-1.0-1.ule3.noarch.rpm"), b"rpm").unwrap();
        let got = is_built_in_results(&result_dir, "ule3sp4", &srpm)
            .await
            .unwrap();
        assert!(got);
    }

    #[tokio::test]
    async fn is_built_in_results_finds_srpm_in_srpms_subdir() {
        // 仅 SRPMS 下有产物（例如只构建 source rpm 的场景）也应命中。
        let tmp = tempfile::tempdir().unwrap();
        let srpm = tmp.path().join("foo-1.0-1.oe2203sp4.src.rpm");
        std::fs::write(&srpm, b"").unwrap();
        let result_dir = tmp.path().join("results");
        let pkg_root = result_dir.join("ule3sp4").join("foo-1.0-1.oe2203sp4");
        let ts = pkg_root.join("20260805-130000-0002");
        let srpms_dir = ts.join("SRPMS");
        std::fs::create_dir_all(&srpms_dir).unwrap();
        std::fs::write(srpms_dir.join("foo-1.0-1.ule3.src.rpm"), b"srpm").unwrap();
        let got = is_built_in_results(&result_dir, "ule3sp4", &srpm)
            .await
            .unwrap();
        assert!(got);
    }

    #[tokio::test]
    async fn is_built_in_results_returns_true_when_rpm_only_in_toplevel_timestamp() {
        // rpm 直接放在 timestamp 下（非 RPMS/{arch} 布局）也命中：向后兼容。
        let tmp = tempfile::tempdir().unwrap();
        let srpm = tmp.path().join("foo-1.0-1.oe2203sp4.src.rpm");
        std::fs::write(&srpm, b"").unwrap();
        let result_dir = tmp.path().join("results");
        let pkg_root = result_dir.join("ule3sp4").join("foo-1.0-1.oe2203sp4");
        let ts = pkg_root.join("20260805-130000-0002");
        std::fs::create_dir_all(&ts).unwrap();
        std::fs::write(ts.join("foo-1.0-1.ule3.aarch64.rpm"), b"rpm").unwrap();
        let got = is_built_in_results(&result_dir, "ule3sp4", &srpm)
            .await
            .unwrap();
        assert!(got);
    }
}
