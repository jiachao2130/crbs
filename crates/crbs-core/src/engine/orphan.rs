// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 孤儿挂载点扫描与清理：解析 /proc/mounts，找出产品根下残留的挂载并 umount。

use std::path::{Path, PathBuf};

use tracing::{info, warn};

/// 孤儿挂载点记录。
#[derive(Debug, Clone)]
pub struct OrphanMount {
    /// 挂载点路径。
    pub path: PathBuf,
    /// 文件系统类型。
    pub fstype: String,
}

/// 解码 /proc/mounts 字段的八进制转义：内核把挂载点/源路径里的空白与 `\`
/// 转义为 `\040`/`\011`/`\012`/`\134`（空格/tab/换行/`\`）；不还原则含空白
/// 路径永远匹配不上，孤儿扫描整体失效。单遍扫描，结果不二次解释——`\134`
/// 还原的 `\` 不当作转义序列开头（内核也不递归转义，`\134040` 的原始路径
/// 即字面 `\040`）。pub(crate)：clean.rs mounts_under 共用同一解码。
pub(crate) fn decode_proc_mounts_field(s: &str) -> String {
    // 快路径：绝大多数字段不含反斜杠。
    if !s.contains('\\') {
        return s.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        match chars.get(i..i + 4) {
            Some(['\\', '0', '4', '0']) => {
                out.push(' ');
                i += 4;
            }
            Some(['\\', '0', '1', '1']) => {
                out.push('\t');
                i += 4;
            }
            Some(['\\', '0', '1', '2']) => {
                out.push('\n');
                i += 4;
            }
            Some(['\\', '1', '3', '4']) => {
                out.push('\\');
                i += 4;
            }
            // 其余序列（截断、非内核转义）原样保留。
            _ => {
                out.push(chars[i]);
                i += 1;
            }
        }
    }
    out
}

/// 判断一条 /proc/mounts 行（字段已解码）是否与 crbs 相关。纯函数便于单测。
///
/// 命中规则（满足其一）：
/// 1. bind 源路径（第 1 字段）在 crbs_root 下（含相等，加 `/` 边界）——bind 的
///    源只出现在设备位、options 无 `bind=`，fstype 为源文件系统不命中容器伪 fs
///    白名单，只能按源识别；真实设备名（/dev/sda1、UUID=…）天然不匹配。
/// 2. options 中的路径在 crbs_root 下（`/` 边界防兄弟目录误匹配；lowerdir
///    冒号分隔多路径，逐个检查）。
/// 3. 挂载点在临时目录 `.tmp*/` 下且 fstype 为容器伪文件系统。
///
/// 已知误卸面（知悉后刻意接受）：`.tmp` 前缀是 tempfile 默认命名而非 crbs
/// 专属，共享 tmp 目录（/dev/shm、/var/tmp）下第三方工具的同形挂载会被规则 3
/// 误判遭懒卸载（MNT_DETACH 不删数据但中断其负载）；同机多 crbs 实例互不在
/// 对方活跃 build 守卫内，A 实例的 gc 可懒卸 B 实例在用的挂载。
fn mount_line_is_crbs_related(
    source: &str,
    mountpoint: &str,
    fstype: &str,
    options: &str,
    crbs_root: &str,
    tmp_dir_prefixes: &[String],
    container_fstypes: &[&str],
) -> bool {
    let is_crbs_path = |p: &str| p == crbs_root || p.starts_with(&format!("{}/", crbs_root));

    if is_crbs_path(source) {
        return true;
    }

    let in_options = options.split(',').any(|opt| {
        if let Some(lowerdir) = opt.strip_prefix("lowerdir=") {
            return lowerdir.split(':').any(is_crbs_path);
        }
        opt.strip_prefix("upperdir=")
            .or_else(|| opt.strip_prefix("workdir="))
            .or_else(|| opt.strip_prefix("dir="))
            .or_else(|| opt.strip_prefix("bind="))
            .or(Some(opt))
            .map(is_crbs_path)
            .unwrap_or(false)
    });
    if in_options {
        return true;
    }

    tmp_dir_prefixes
        .iter()
        .any(|prefix| mountpoint.starts_with(prefix.as_str()))
        && container_fstypes.contains(&fstype)
}

/// 扫描 /proc/mounts，找出指定根目录下的所有挂载点，按路径深度倒序（深层先 umount）。
pub async fn scan_mounts_under(roots: &[&Path]) -> crate::Result<Vec<OrphanMount>> {
    scan_mounts_from("/proc/mounts", roots).await
}

/// 从指定 mounts 文件扫描挂载点（内部实现，支持测试注入）。
pub(crate) async fn scan_mounts_from(
    mounts_file: &str,
    roots: &[&Path],
) -> crate::Result<Vec<OrphanMount>> {
    let content = tokio::fs::read_to_string(mounts_file)
        .await
        .map_err(|e| crate::error::CrbsError::from_io_context("read", e))?;

    // 预 canonicalize roots，避免每行重复
    let mut roots_canon = Vec::with_capacity(roots.len());
    for r in roots {
        match tokio::fs::canonicalize(r).await {
            Ok(p) => roots_canon.push(p),
            Err(e) => {
                warn!(root = %r.display(), error = %e, "Failed to canonicalize scan root, skipping");
            }
        }
    }

    let mut mounts = Vec::new();
    for line in content.lines() {
        // split 在解码前：转义保证字段内无真实空白，字段边界安全；解码逐字段做。
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        // 挂载点用于构路径/比较，先解码八进制转义（fstype 不参与路径比较）。
        let mountpoint = PathBuf::from(decode_proc_mounts_field(parts[1]));
        let fstype = parts[2].to_string();

        let canon = match tokio::fs::canonicalize(&mountpoint).await {
            Ok(p) => p,
            Err(_) => continue,
        };

        for root_canon in &roots_canon {
            if canon.starts_with(root_canon) {
                mounts.push(OrphanMount {
                    path: canon,
                    fstype,
                });
                break;
            }
        }
    }

    sort_mounts_deepest_first(&mut mounts);

    Ok(mounts)
}

/// 过滤掉仍属活跃构建的挂载点：路径以任一 building build 的 result_dir 开头则保留。
/// 限制：只能识别 result_dir 下的挂载；chroot 内挂载（proc/sys/dev、bind）在
/// tempdir 下，过滤不到——依赖 init/shell 自动 cleanup 的全局
/// count_building_builds 守卫 + umount 前第二道复检（`post_scan_guard`）兜底，
/// 误卸窗口收窄到复检后毫秒级；`crbs gc --orphan-mounts` 同样以本函数次级过滤。
pub async fn filter_active_builds(
    mounts: Vec<OrphanMount>,
    state: &crate::state::StateStore,
) -> crate::Result<Vec<OrphanMount>> {
    // 内层已 db_ctx（含 DatabaseUnavailable 分类与 is_transient），二次包成
    // Database(format!) 会把不可用错误降级成普通 Database 且 Display 双重嵌套——透传。
    let active_dirs = state.list_active_build_result_dirs().await?;

    if active_dirs.is_empty() {
        return Ok(mounts);
    }

    // 对活跃构建目录做 canonicalize（失败时回退原路径），避免 symlink/相对路径导致误判。
    let mut canon_active_dirs = Vec::with_capacity(active_dirs.len());
    for d in active_dirs {
        canon_active_dirs.push(tokio::fs::canonicalize(&d).await.unwrap_or(d));
    }

    let mut canon_mounts = Vec::with_capacity(mounts.len());
    for m in mounts {
        let m_canon = tokio::fs::canonicalize(&m.path)
            .await
            .unwrap_or_else(|_| m.path.clone());
        canon_mounts.push((m, m_canon));
    }

    let filtered: Vec<OrphanMount> = canon_mounts
        .into_iter()
        .filter(|(_, m_canon)| {
            // 命中活跃 result_dir 前缀即跳过。
            !canon_active_dirs.iter().any(|d| m_canon.starts_with(d))
        })
        .map(|(m, _)| m)
        .collect();

    Ok(filtered)
}

/// 扫描 /proc/mounts，找出与 crbs 相关的挂载点（含临时目录下的临时容器挂载）。
/// 匹配规则见 `mount_line_is_crbs_related`；`tmp_dirs` 通常为配置的 tmpfs_dir
/// 与 tmp_dir（默认 /dev/shm、{crbs_root}/tmp）。overlay 目标在
/// `{tmp_dir}/.tmpXXXX/root`，全内存构建另在 `.tmpXXXX/memroot/root`。
/// 返回按路径深度倒序（深层先 umount）。
pub async fn scan_crbs_mounts(
    crbs_root: &Path,
    tmp_dirs: &[&Path],
) -> crate::Result<Vec<OrphanMount>> {
    scan_crbs_mounts_from("/proc/mounts", crbs_root, tmp_dirs).await
}

/// 合并扫描：根目录下挂载 + /proc/mounts 中 crbs 相关挂载；任一侧失败仅告警
/// 并保留另一侧结果，最终排序去重。
pub async fn scan_all_orphan_mounts(
    roots: &[&Path],
    crbs_root: &Path,
    tmp_dirs: &[&Path],
) -> Vec<OrphanMount> {
    let mut mounts = Vec::new();
    match scan_mounts_under(roots).await {
        Ok(m) => mounts.extend(m),
        Err(e) => warn!(error = %e, "Failed to scan mounts under given roots"),
    }
    match scan_crbs_mounts(crbs_root, tmp_dirs).await {
        Ok(m) => mounts.extend(m),
        Err(e) => warn!(error = %e, "Failed to scan crbs mounts from /proc/mounts"),
    }
    sort_and_dedup_mounts(mounts)
}

/// 深度倒序排序（深层先 umount）；路径长度次排序防同深度的父子路径先卸掉父
///（收口与合并两路径共用；sort_and_dedup_mounts 另加字典序 tiebreaker 保全序）。
fn sort_mounts_deepest_first(mounts: &mut [OrphanMount]) {
    mounts.sort_by(|a, b| {
        let depth_a = a.path.components().count();
        let depth_b = b.path.components().count();
        depth_b
            .cmp(&depth_a)
            .then_with(|| b.path.as_os_str().len().cmp(&a.path.as_os_str().len()))
    });
}

/// 合并结果排序去重：按路径深度倒序（深层先 umount），同深度按路径字典序。
/// dedup_by 只删**相邻**重复：排序须为全序（深度 + 路径 tiebreaker），否则
/// 同一路径被同深度的其它路径隔开而逃过去重，同一挂载点被 umount 两次。
pub(crate) fn sort_and_dedup_mounts(mounts: Vec<OrphanMount>) -> Vec<OrphanMount> {
    let mut mounts = mounts;
    mounts.sort_by(|a, b| {
        b.path
            .components()
            .count()
            .cmp(&a.path.components().count())
            .then_with(|| a.path.cmp(&b.path))
    });
    mounts.dedup_by(|a, b| a.path == b.path);
    mounts
}

/// 从指定 mounts 文件扫描 crbs 相关挂载点（内部实现，支持测试注入）。
pub(crate) async fn scan_crbs_mounts_from(
    mounts_file: &str,
    crbs_root: &Path,
    tmp_dirs: &[&Path],
) -> crate::Result<Vec<OrphanMount>> {
    let content = tokio::fs::read_to_string(mounts_file)
        .await
        .map_err(|e| crate::error::CrbsError::from_io_context("read", e))?;

    let crbs_root_str = crbs_root.to_string_lossy();
    let container_fstypes: &[&str] = &["overlay", "proc", "sysfs", "tmpfs", "devpts"];
    let tmp_dir_prefixes: Vec<String> = tmp_dirs
        .iter()
        .map(|p| format!("{}/.tmp", p.to_string_lossy()))
        .collect();

    let mut mounts = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let mountpoint = PathBuf::from(decode_proc_mounts_field(parts[1]));
        let fstype = parts[2].to_string();
        // bind 源路径只出现在第 1 字段、options 路径参与前缀比较，均需先解码。
        let source = decode_proc_mounts_field(parts[0]);
        let options = decode_proc_mounts_field(parts[3]);

        let mountpoint_str = mountpoint.to_string_lossy();

        if mount_line_is_crbs_related(
            &source,
            &mountpoint_str,
            &fstype,
            &options,
            &crbs_root_str,
            &tmp_dir_prefixes,
            container_fstypes,
        ) {
            mounts.push(OrphanMount {
                path: mountpoint,
                fstype,
            });
        }
    }

    // 深度倒序（深层先 umount）；路径长度次排序防同深度的父子路径先卸掉父。
    sort_mounts_deepest_first(&mut mounts);

    // 去重（同一路径可能出现多次，如 bind mount 和 remount）
    mounts.dedup_by(|a, b| a.path == b.path);

    Ok(mounts)
}

/// 按路径深度倒序 umount（深层先卸）。
///
/// 返回成功 umount 的路径列表：shared layer 目录回收只应对成功卸载的层执行，
/// umount 失败说明挂载仍活跃，rm 会穿过挂载点删掉挂载源内容（失败不计入，
/// 含伪 fs 降级 debug 分支）。同一路径可能被列两次（两次扫描合并、bind 与
/// remount 各占一行），调用方已按路径去重；`MS_BIND|MS_REMOUNT` 是原地修改
/// 而非叠加新层，每个挂载点单次 umount 即可完全卸载。
pub async fn umount_all(mounts: Vec<OrphanMount>) -> Vec<PathBuf> {
    let mut unmounted = Vec::new();
    for m in mounts {
        let path = m.path;
        let path_str = path.display().to_string();
        let fstype = m.fstype;
        info!(path = %path_str, fstype = %fstype, "Lazy umount orphan mount");
        match crate::privilege::umount_detach(path.clone()).await {
            Ok(()) => {
                unmounted.push(path);
            }
            Err(e) => {
                // 伪 fs（proc/sysfs/devpts/tmpfs）在父 overlay 卸载后多已失效，失败降级 debug。
                let pseudo_fs = ["proc", "sysfs", "devpts", "tmpfs"].contains(&fstype.as_str());
                if pseudo_fs {
                    tracing::debug!(
                        path = %path_str,
                        fstype = %fstype,
                        error = %e,
                        "lazy umount failed for container pseudo-fs, ignoring"
                    );
                } else {
                    warn!(
                        path = %path_str,
                        error = %e,
                        "Failed to lazy umount orphan mount"
                    );
                }
            }
        }
    }
    unmounted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan_mounts_from_parse_filter_sort() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().join("root");
        let sub = root.join("sub");
        let deep = sub.join("deep");
        std::fs::create_dir_all(&deep).unwrap();

        // macOS 上 /var 是 /private/var 的 symlink，canonicalize 后与挂载点一致
        let root = root.canonicalize().unwrap();
        let sub = sub.canonicalize().unwrap();
        let deep = deep.canonicalize().unwrap();

        let mounts_file = tmpdir.path().join("mounts");
        let mounts_content = format!(
            "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n\
             tmpfs /tmp tmpfs rw 0 0\n\
             overlay {} overlay rw 0 0\n\
             proc {} proc rw 0 0\n\
             sysfs {} sysfs rw 0 0\n",
            root.display(),
            sub.display(),
            deep.display(),
        );
        std::fs::write(&mounts_file, mounts_content).unwrap();

        let mounts = scan_mounts_from(mounts_file.to_str().unwrap(), &[&root])
            .await
            .unwrap();

        assert_eq!(mounts.len(), 3);

        // 深度倒序：deep (4) > sub (3) > root (2)
        assert_eq!(mounts[0].path, deep);
        assert_eq!(mounts[0].fstype, "sysfs");
        assert_eq!(mounts[1].path, sub);
        assert_eq!(mounts[1].fstype, "proc");
        assert_eq!(mounts[2].path, root);
        assert_eq!(mounts[2].fstype, "overlay");
    }

    #[tokio::test]
    async fn test_filter_active_builds_skips_active() {
        let tmp = tempfile::tempdir().unwrap();
        let store = crate::state::StateStore::new(tmp.path()).await.unwrap();

        let _b1_id = store
            .insert_build(crate::state::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "building",
                result_dir: Some("/results/fedora/hello/b1"),
                backend: "chroot",
                user: "test",
                task_id: Some(crate::state::test_state::seed_task(&store, "fedora", "hello").await),
                ..Default::default()
            })
            .await
            .unwrap();

        let mounts = vec![
            OrphanMount {
                path: PathBuf::from("/results/fedora/hello/b1/proc"),
                fstype: "proc".to_string(),
            },
            OrphanMount {
                path: PathBuf::from("/results/fedora/hello/b2/proc"),
                fstype: "proc".to_string(),
            },
            OrphanMount {
                path: PathBuf::from("/results/centos/world/b3/sys"),
                fstype: "sysfs".to_string(),
            },
        ];

        let filtered = filter_active_builds(mounts, &store).await.unwrap();
        assert_eq!(filtered.len(), 2);
        assert!(filtered
            .iter()
            .any(|m| m.path.as_path() == Path::new("/results/fedora/hello/b2/proc")));
        assert!(filtered
            .iter()
            .any(|m| m.path.as_path() == Path::new("/results/centos/world/b3/sys")));
    }

    #[tokio::test]
    async fn test_filter_active_builds_no_active() {
        let tmp = tempfile::tempdir().unwrap();
        let store = crate::state::StateStore::new(tmp.path()).await.unwrap();

        let mounts = vec![OrphanMount {
            path: PathBuf::from("/results/fedora/hello/b1/proc"),
            fstype: "proc".to_string(),
        }];

        let filtered = filter_active_builds(mounts, &store).await.unwrap();
        assert_eq!(filtered.len(), 1);
    }

    /// 回归：同深度路径隔开的重复项也须被去重（dedup_by 只删相邻，排序须全序）。
    #[test]
    fn test_sort_and_dedup_mounts_removes_interleaved_duplicates() {
        let m = |p: &str| OrphanMount {
            path: PathBuf::from(p),
            fstype: "overlay".to_string(),
        };
        // 模拟两次扫描合并：同一路径出现两段，被同深度的另一路径隔开。
        let merged = vec![
            m("/t/.tmpA/root"),
            m("/t/.tmpB/root"),
            m("/t/.tmpA/root"),
            m("/t/.tmpA/root/proc"),
            m("/t/.tmpA"),
        ];

        let out = sort_and_dedup_mounts(merged);

        let mut paths: Vec<&Path> = out.iter().map(|x| x.path.as_path()).collect();
        let before = paths.len();
        paths.dedup();
        assert_eq!(
            before,
            paths.len(),
            "no duplicate paths expected: {:?}",
            out
        );

        // 深度倒序不变：root/proc (5) → root (4) → .tmpA/.tmpB (3)
        assert_eq!(out[0].path, Path::new("/t/.tmpA/root/proc"));
        assert_eq!(
            out.iter()
                .filter(|x| x.path == Path::new("/t/.tmpA/root"))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn test_scan_crbs_mounts_from_proc() {
        let tmpdir = tempfile::tempdir().unwrap();
        let crbs_root = PathBuf::from("/var/lib/crbs");
        let tmp_dirs: Vec<&Path> = vec![Path::new("/dev/shm"), Path::new("/var/tmp")];

        let mounts_file = tmpdir.path().join("mounts");
        let mounts_content = "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n\
             tmpfs /dev/shm tmpfs rw 0 0\n\
             overlay /dev/shm/.tmpABC/root overlay rw,lowerdir=/var/lib/crbs/shared_layers/xxx:/var/lib/crbs/fedora/base,upperdir=/dev/shm/.tmpABC/upper,workdir=/dev/shm/.tmpABC/work 0 0\n\
             proc /dev/shm/.tmpABC/root/proc proc rw 0 0\n\
             sysfs /dev/shm/.tmpABC/root/sys sysfs rw 0 0\n\
             devpts /dev/shm/.tmpABC/root/dev/pts devpts rw 0 0\n\
             overlay /var/tmp/.tmpDEF/root overlay rw,lowerdir=/other/path,upperdir=/var/tmp/.tmpDEF/upper,workdir=/var/tmp/.tmpDEF/work 0 0\n\
             proc /var/tmp/.tmpDEF/root/proc proc rw 0 0\n\
             /dev/sda1 /mnt/data ext4 rw 0 0\n";
        std::fs::write(&mounts_file, mounts_content).unwrap();

        let mounts = scan_crbs_mounts_from(mounts_file.to_str().unwrap(), &crbs_root, &tmp_dirs)
            .await
            .unwrap();

        // 应匹配 6 个：/dev/shm 下 overlay/proc/sysfs/devpts + /var/tmp 下 overlay/proc
        assert_eq!(mounts.len(), 6, "expected 6 crbs mounts, got: {:?}", mounts);
        assert!(
            mounts
                .iter()
                .any(|m| m.path.as_path() == Path::new("/dev/shm/.tmpABC/root")
                    && m.fstype == "overlay"),
            "missing overlay mount"
        );
        assert!(
            mounts.iter().any(
                |m| m.path.as_path() == Path::new("/dev/shm/.tmpABC/root/proc")
                    && m.fstype == "proc"
            ),
            "missing proc mount"
        );
        assert!(
            mounts.iter().any(
                |m| m.path.as_path() == Path::new("/dev/shm/.tmpABC/root/sys")
                    && m.fstype == "sysfs"
            ),
            "missing sysfs mount"
        );
        assert!(
            mounts.iter().any(
                |m| m.path.as_path() == Path::new("/dev/shm/.tmpABC/root/dev/pts")
                    && m.fstype == "devpts"
            ),
            "missing devpts mount"
        );
        assert!(
            mounts
                .iter()
                .any(|m| m.path.as_path() == Path::new("/var/tmp/.tmpDEF/root")
                    && m.fstype == "overlay"),
            "missing /var/tmp overlay mount"
        );
        assert!(
            mounts.iter().any(
                |m| m.path.as_path() == Path::new("/var/tmp/.tmpDEF/root/proc")
                    && m.fstype == "proc"
            ),
            "missing /var/tmp proc mount"
        );

        assert!(!mounts
            .iter()
            .any(|m| m.path.as_path() == Path::new("/proc")));
        assert!(!mounts
            .iter()
            .any(|m| m.path.as_path() == Path::new("/dev/shm")));
        assert!(!mounts
            .iter()
            .any(|m| m.path.as_path() == Path::new("/mnt/data")));
    }

    #[tokio::test]
    async fn test_scan_crbs_mounts_from_no_false_positive() {
        let tmpdir = tempfile::tempdir().unwrap();
        let crbs_root = PathBuf::from("/var/lib/crbs");
        let tmp_dirs: Vec<&Path> = vec![Path::new("/dev/shm"), Path::new("/var/tmp")];

        let mounts_file = tmpdir.path().join("mounts");
        // overlay 的 lowerdir 不含 crbs_root，不应匹配
        let mounts_content = "overlay /var/tmp/.tmpXYZ/root overlay rw,lowerdir=/other/path,upperdir=/var/tmp/.tmpXYZ/upper 0 0\n";
        std::fs::write(&mounts_file, mounts_content).unwrap();

        let _ = scan_crbs_mounts_from(mounts_file.to_str().unwrap(), &crbs_root, &tmp_dirs)
            .await
            .unwrap();

        let mounts_content = "ext4 /var/tmp/.tmpXYZ/root ext4 rw 0 0\n";
        std::fs::write(&mounts_file, mounts_content).unwrap();

        let mounts = scan_crbs_mounts_from(mounts_file.to_str().unwrap(), &crbs_root, &tmp_dirs)
            .await
            .unwrap();
        assert!(mounts.is_empty(), "ext4 in tmp dir should not be matched");
    }

    /// decode_proc_mounts_field：四种内核八进制转义 + 非转义原样 + 不递归解释。
    #[test]
    fn test_decode_proc_mounts_field() {
        assert_eq!(decode_proc_mounts_field("/plain/path"), "/plain/path");
        assert_eq!(decode_proc_mounts_field("/a\\040b"), "/a b");
        assert_eq!(decode_proc_mounts_field("a\\011b"), "a\tb");
        assert_eq!(decode_proc_mounts_field("a\\012b"), "a\nb");
        assert_eq!(decode_proc_mounts_field("a\\134b"), "a\\b");
        // `\134040` 的原始路径是字面 `\040`：解码出的 `\` 不得被再次解释为空格。
        assert_eq!(decode_proc_mounts_field("a\\134040b"), "a\\040b");
        assert_eq!(decode_proc_mounts_field("a\\04"), "a\\04");
        assert_eq!(decode_proc_mounts_field("a\\999b"), "a\\999b");
        assert_eq!(
            decode_proc_mounts_field("/my\\040dir/x\\011y"),
            "/my dir/x\ty"
        );
    }

    /// bind 源路径（第 1 字段）命中；真实设备名不命中；lowerdir 命中维持。
    #[test]
    fn test_mount_line_is_crbs_related_bind_source() {
        let crbs_root = "/var/lib/crbs";
        let tmp_dir_prefixes: Vec<String> = vec![
            format!("{}/.tmp", "/dev/shm"),
            format!("{}/.tmp", "/var/tmp"),
        ];
        let fstypes: &[&str] = &["overlay", "proc", "sysfs", "tmpfs", "devpts"];
        let check = |source: &str, mountpoint: &str, fstype: &str, options: &str| {
            mount_line_is_crbs_related(
                source,
                mountpoint,
                fstype,
                options,
                crbs_root,
                &tmp_dir_prefixes,
                fstypes,
            )
        };

        // bind 源在 crbs_root 下：fstype 为源文件系统 ext4、mountpoint 不在 tmp 白名单——只有源路径规则命中。
        assert!(check(
            "/var/lib/crbs/dnf-cache",
            "/var/tmp/.tmpZ/root/var/cache/dnf",
            "ext4",
            "rw"
        ));
        assert!(check("/var/lib/crbs", "/somewhere", "ext4", "rw"));
        assert!(!check("/dev/sda1", "/mnt/data", "ext4", "rw"));
        assert!(!check("UUID=1234-5678", "/mnt/data", "ext4", "rw"));
        assert!(!check("/var/lib/crbs-other/x", "/mnt", "ext4", "rw"));
        assert!(check(
            "overlay",
            "/var/tmp/.tmpZ/root",
            "overlay",
            "rw,lowerdir=/other:/var/lib/crbs/layers/x,upperdir=/var/tmp/.tmpZ/upper"
        ));
        // 临时目录容器伪文件系统命中维持；同路径 ext4 不命中。
        assert!(check("proc", "/dev/shm/.tmpABC/root/proc", "proc", "rw"));
        assert!(!check(
            "/dev/sda1",
            "/dev/shm/.tmpABC/root/data",
            "ext4",
            "rw"
        ));
    }

    /// 端到端：空白八进制转义后，含空格的挂载点/源路径仍被两个扫描函数识别。
    #[tokio::test]
    async fn test_scan_mounts_decodes_octal_escapes() {
        let tmpdir = tempfile::tempdir().unwrap();
        // crbs_root / 扫描根带空格：内核在 /proc/mounts 中转义为 \040。
        let crbs_root = tmpdir.path().join("crbs root");
        std::fs::create_dir_all(crbs_root.join("ccache")).unwrap();

        let mounts_file = tmpdir.path().join("mounts");
        let esc = |p: &std::path::Path| p.display().to_string().replace(' ', "\\040");
        let mounts_content = format!(
            // scan_mounts_under：挂载点含空格（转义后），解码前 canonicalize 失败被跳过。
            "/dev/sda1 {} ext4 rw 0 0\n\
             /var/lib/crbs/x /mnt/data ext4 rw 0 0\n",
            esc(&crbs_root),
        );
        std::fs::write(&mounts_file, mounts_content).unwrap();

        let canon = crbs_root.canonicalize().unwrap();
        let mounts = scan_mounts_from(mounts_file.to_str().unwrap(), &[&canon])
            .await
            .unwrap();
        assert_eq!(mounts.len(), 1, "escaped mountpoint should be found");
        assert_eq!(mounts[0].path, canon);

        // scan_crbs_mounts：bind 源在含空格 crbs_root 下（ext4、不在 tmp 白名单）——只有源路径规则命中。
        let mounts_file2 = tmpdir.path().join("mounts2");
        let bind_src = crbs_root.join("ccache");
        let mounts_content2 = format!(
            "{} {} ext4 rw 0 0\n",
            esc(&bind_src),
            "/var/tmp/.tmpZ/root/home/builder/.ccache"
        );
        std::fs::write(&mounts_file2, mounts_content2).unwrap();

        let tmp_dirs: Vec<&Path> = vec![Path::new("/dev/shm"), Path::new("/var/tmp")];
        let mounts2 = scan_crbs_mounts_from(mounts_file2.to_str().unwrap(), &crbs_root, &tmp_dirs)
            .await
            .unwrap();
        assert_eq!(
            mounts2.len(),
            1,
            "escaped bind source under crbs_root should be found"
        );
        assert_eq!(
            mounts2[0].path,
            Path::new("/var/tmp/.tmpZ/root/home/builder/.ccache")
        );
    }
}
