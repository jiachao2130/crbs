// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 汇总 helper 允许操作的额外路径（/etc/crbs 配置中可能位于 crbs_root 之外的路径）。
//! setuid-root 进程不能信任可写的配置：配置目录与文件必须 root 所有，且组/其他不可写，
//! 否则篡改配置即可扩大 helper 的可操作范围。

use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use crate::validate::normalize_path;
use crate::Error;

#[cfg(target_os = "linux")]
const SYSTEM_CONFIG_DIR: &str = "/etc/crbs";

/// server 世界 root 的默认值（server.toml 未配置 crbs_root 时），与 crbs-core 的
/// ServerConfig 默认保持一致。
pub const DEFAULT_CRBS_ROOT: &str = "/var/lib/crbs";

/// 引擎世界 root 的默认值（crbs.toml 未配置 crbs_root 时），与 crbs-core 的
/// CrbsConfig 默认保持一致。
pub const DEFAULT_ENGINE_CRBS_ROOT: &str = "/var/lib/crbs-engine";

#[cfg(target_os = "linux")]
fn is_under_system_config_dir(path: &Path) -> bool {
    let sys = Path::new(SYSTEM_CONFIG_DIR);
    path == sys || path.starts_with(sys)
}

#[derive(Debug, Default, serde::Deserialize)]
struct GlobalConfigPaths {
    #[serde(default)]
    crbs_root: Option<PathBuf>,
    #[serde(default)]
    result_dir: Option<PathBuf>,
    #[serde(default)]
    shared_layers_dir: Option<PathBuf>,
    #[serde(default)]
    product_root: Option<PathBuf>,
    #[serde(default)]
    base_os_path: Option<PathBuf>,
    #[serde(default)]
    dnf_cache_path: Option<PathBuf>,
    #[serde(default)]
    package_cache_path: Option<PathBuf>,
    #[serde(default)]
    ccache_dir: Option<PathBuf>,
    #[serde(default)]
    local_repo: Option<PathBuf>,
    #[serde(default)]
    tmpfs_dir: Option<PathBuf>,
    #[serde(default)]
    tmp_dir: Option<PathBuf>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct ProductConfigPaths {
    #[serde(default)]
    result_dir: Option<PathBuf>,
    #[serde(default)]
    product_root: Option<PathBuf>,
    #[serde(default)]
    base_os_path: Option<PathBuf>,
    #[serde(default)]
    dnf_cache_path: Option<PathBuf>,
    #[serde(default)]
    ccache_dir: Option<PathBuf>,
    #[serde(default)]
    local_repo: Option<PathBuf>,
    #[serde(default)]
    overlay_dir: Option<PathBuf>,

    #[serde(default)]
    tmp_dir: Option<PathBuf>,
    #[serde(default)]
    tmpfs_dir: Option<PathBuf>,
}

pub const HELPER_CONFIG_FILE: &str = "priv-helper.toml";

#[cfg(target_os = "linux")]
const RELAX_HINT: &str =
    " (or set relax_config_permissions = true in /etc/crbs/priv-helper.toml for single-tenant/dev)";

#[derive(Debug, Default, serde::Deserialize)]
pub struct HelperConfig {
    #[serde(default)]
    pub relax_config_permissions: bool,

    #[serde(default)]
    pub allowed_paths: Vec<PathBuf>,
}

fn read_toml<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Error> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("read {}: {}", path.display(), e),
        ))
    })?;
    toml::from_str(&content)
        .map_err(|e| Error::Validation(format!("parse {}: {}", path.display(), e)))
}

pub fn load_helper_config(config_dir: &Path) -> Result<HelperConfig, Error> {
    let path = normalize_path(config_dir)?.join(HELPER_CONFIG_FILE);
    if !path.is_file() {
        return Ok(HelperConfig::default());
    }

    verify_helper_config_ownership(&path)?;
    let cfg: HelperConfig = read_toml(&path)?;
    if cfg.relax_config_permissions {
        tracing::debug!(path = %path.display(), "config permission checks relaxed");
    }
    Ok(cfg)
}

#[cfg(target_os = "linux")]
fn verify_helper_config_ownership(path: &Path) -> Result<(), Error> {
    let meta = std::fs::metadata(path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("metadata {}: {}", path.display(), e),
        ))
    })?;
    let uid = meta.uid();
    let mode = meta.permissions().mode();
    if uid != 0 || mode & 0o022 != 0 {
        return Err(Error::PermissionDenied(format!(
            "helper config {} must be owned by root and not group/other writable \
             (uid={}, mode={:04o}); fix: sudo chown root:crbs {} && sudo chmod 0640 {}",
            path.display(),
            uid,
            mode & 0o777,
            path.display(),
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_helper_config_ownership(_path: &Path) -> Result<(), Error> {
    Ok(())
}

#[derive(Debug, Default, serde::Deserialize)]
struct ServerConfigPaths {
    #[serde(default)]
    crbs_root: Option<PathBuf>,
}

/// 读取受信配置中的引擎 root：crbs.toml 缺失或未设置时返回
/// /var/lib/crbs-engine（语义归引擎世界）。helper 以配置值为准，`--crbs-root`
/// 仅作一致性校验，不得扩大允许集合。
pub fn load_configured_crbs_root(config_dir: &Path, relaxed: bool) -> Result<PathBuf, Error> {
    let config_dir = normalize_path(config_dir)?;
    let global_file = config_dir.join("crbs.toml");
    if global_file.is_file() {
        verify_config_file_permissions(&global_file, relaxed)?;
        let cfg: GlobalConfigPaths = read_toml(&global_file)?;
        if let Some(root) = cfg.crbs_root {
            return normalize_path(&root);
        }
    }
    Ok(PathBuf::from(DEFAULT_ENGINE_CRBS_ROOT))
}

/// 读取受信配置中的 server root：server.toml 缺失或未设置时返回 /var/lib/
/// crbs（并入允许集合）。
pub fn load_configured_server_root(config_dir: &Path, relaxed: bool) -> Result<PathBuf, Error> {
    let config_dir = normalize_path(config_dir)?;
    let server_file = config_dir.join("server.toml");
    if server_file.is_file() {
        verify_config_file_permissions(&server_file, relaxed)?;
        let cfg: ServerConfigPaths = read_toml(&server_file)?;
        if let Some(root) = cfg.crbs_root {
            return normalize_path(&root);
        }
    }
    Ok(PathBuf::from(DEFAULT_CRBS_ROOT))
}

#[derive(Debug, Default, serde::Deserialize)]
struct WorkerConfigPaths {
    #[serde(default)]
    crbs_root: Option<PathBuf>,
}

/// 读取受信配置中的 worker root：worker.toml 缺失或未设置 `crbs_root` 时返
/// 回 `None`（worker 进程缺省沿用 server root，无需单列）；配置了即采信——
/// worker 与引擎各自允许同机配置不同的 crbs_root，不得以引擎 root 硬套
/// worker。
pub fn load_configured_worker_root(
    config_dir: &Path,
    relaxed: bool,
) -> Result<Option<PathBuf>, Error> {
    let config_dir = normalize_path(config_dir)?;
    let worker_file = config_dir.join("worker.toml");
    if worker_file.is_file() {
        verify_config_file_permissions(&worker_file, relaxed)?;
        let cfg: WorkerConfigPaths = read_toml(&worker_file)?;
        return cfg.crbs_root.map(|root| normalize_path(&root)).transpose();
    }
    Ok(None)
}

/// [`load_allowed_paths`] 的结果：规范化去重后的允许集合，加上三个世界
/// root 的单次读盘快照（缺省值同各自 loader：DEFAULT_CRBS_ROOT、
/// DEFAULT_ENGINE_CRBS_ROOT 与 `None`），供 `--crbs-root` 一致性校验复用，
/// 避免调用方二次读配置。
#[derive(Debug)]
pub struct AllowedPaths {
    /// 允许路径集合（已含各世界 root 的并集）。
    pub paths: Vec<PathBuf>,
    pub server_root: PathBuf,
    pub engine_root: PathBuf,
    pub worker_root: Option<PathBuf>,
}

/// 允许集合来源：priv-helper.toml 的显式 allowed_paths、crbs.toml、worker.toml、
/// products/*.toml 的路径字段，以及 server / engine / worker 三个 root。三个 root
/// 在加载点单次读入并随结果返回，调用方不得再次读配置。
pub fn load_allowed_paths(
    config_dir: &Path,
    helper_cfg: &HelperConfig,
) -> Result<AllowedPaths, Error> {
    let config_dir = normalize_path(config_dir)?;
    let relaxed = helper_cfg.relax_config_permissions;
    verify_config_dir_permissions(&config_dir, relaxed)?;

    let mut paths: Vec<PathBuf> = Vec::new();

    for p in &helper_cfg.allowed_paths {
        paths.push(normalize_path(p)?);
    }

    let global_file = config_dir.join("crbs.toml");
    if global_file.is_file() {
        verify_config_file_permissions(&global_file, relaxed)?;
        let cfg: GlobalConfigPaths = read_toml(&global_file)?;
        push_option(&mut paths, cfg.crbs_root);
        push_option(&mut paths, cfg.result_dir);
        push_option(&mut paths, cfg.shared_layers_dir);
        push_option(&mut paths, cfg.product_root);
        push_option(&mut paths, cfg.base_os_path);
        push_option(&mut paths, cfg.dnf_cache_path);
        push_option(&mut paths, cfg.package_cache_path);
        push_option(&mut paths, cfg.ccache_dir);
        push_option(&mut paths, cfg.local_repo);
        push_option(&mut paths, cfg.tmpfs_dir);
        push_option(&mut paths, cfg.tmp_dir);
    }

    let products_dir = config_dir.join("products");
    if products_dir.is_dir() {
        verify_config_dir_permissions(&products_dir, relaxed)?;
        let entries = std::fs::read_dir(&products_dir).map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("read {}: {}", products_dir.display(), e),
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                Error::Io(std::io::Error::new(
                    e.kind(),
                    format!("read entry in {}: {}", products_dir.display(), e),
                ))
            })?;
            let path = entry.path();

            let file_type = entry.file_type().map_err(|e| {
                Error::Io(std::io::Error::new(
                    e.kind(),
                    format!("file type {}: {}", path.display(), e),
                ))
            })?;
            if file_type.is_symlink() {
                // symlink 条目跳过：防止经链接把允许集合注大。
                tracing::warn!(
                    path = %path.display(),
                    "skip symlink in products config dir"
                );
                continue;
            }
            if file_type.is_file()
                && path
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case("toml"))
                    .unwrap_or(false)
            {
                verify_config_file_permissions(&path, relaxed)?;
                let cfg: ProductConfigPaths = read_toml(&path)?;
                // 产品自定义的 tmp_dir/tmpfs_dir（如 /data/tmp）不是标准临时目录，
                // validate_path 不会放行，必须进允许集合，否则 reproduce/bind 的
                // mount 会被白名单错误拒绝。
                push_option(&mut paths, cfg.result_dir);
                push_option(&mut paths, cfg.product_root);
                push_option(&mut paths, cfg.base_os_path);
                push_option(&mut paths, cfg.dnf_cache_path);
                push_option(&mut paths, cfg.ccache_dir);
                push_option(&mut paths, cfg.local_repo);
                push_option(&mut paths, cfg.overlay_dir);
                push_option(&mut paths, cfg.tmp_dir);
                push_option(&mut paths, cfg.tmpfs_dir);
            }
        }
    }

    let server_root = load_configured_server_root(&config_dir, relaxed)?;
    let engine_root = load_configured_crbs_root(&config_dir, relaxed)?;
    let worker_root = load_configured_worker_root(&config_dir, relaxed)?;
    paths.push(server_root.clone());
    paths.push(engine_root.clone());
    if let Some(worker_root) = &worker_root {
        paths.push(worker_root.clone());
    }

    paths.sort();
    paths.dedup();
    Ok(AllowedPaths {
        paths,
        server_root,
        engine_root,
        worker_root,
    })
}

fn push_option(paths: &mut Vec<PathBuf>, opt: Option<PathBuf>) {
    if let Some(p) = opt {
        if let Ok(normalized) = normalize_path(&p) {
            paths.push(normalized);
        }
    }
}

#[cfg(target_os = "linux")]
/// 校验 /etc/crbs 下的配置目录为 root 所有且组/其他不可写；relaxed 时跳过。
/// 目录必须查：目录可写时，即使文件本身合规，攻击者也能 unlink/rename 换入伪造文件。
fn verify_config_dir_permissions(path: &Path, relaxed: bool) -> Result<(), Error> {
    if relaxed || !is_under_system_config_dir(path) {
        return Ok(());
    }
    let meta = std::fs::metadata(path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("metadata {}: {}", path.display(), e),
        ))
    })?;
    let mode = meta.permissions().mode();
    let uid = meta.uid();

    if uid != 0 {
        return Err(Error::PermissionDenied(format!(
            "config dir {} is not owned by root (uid={}); \
             fix: sudo chown root:crbs {} && sudo chmod 0750 {}{}",
            path.display(),
            uid,
            path.display(),
            path.display(),
            RELAX_HINT
        )));
    }
    if mode & 0o022 != 0 {
        return Err(Error::PermissionDenied(format!(
            "config dir {} is group or world writable ({:04o}); \
             fix: sudo chmod 0750 {}{}",
            path.display(),
            mode & 0o777,
            path.display(),
            RELAX_HINT
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_config_dir_permissions(_path: &Path, _relaxed: bool) -> Result<(), Error> {
    Ok(())
}

#[cfg(target_os = "linux")]
/// 不受 relaxed 开关影响的严格检查，须在读取 priv-helper.toml 之前执行：relax 标志
/// 保存在被检目录的文件里，必须先查目录、后读文件，顺序不能反。
pub fn verify_config_dir_strict(path: &Path) -> Result<(), Error> {
    if !is_under_system_config_dir(path) {
        return Ok(());
    }
    match std::fs::metadata(path) {
        Ok(_) => verify_config_dir_permissions(path, false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Io(std::io::Error::new(
            e.kind(),
            format!("metadata {}: {}", path.display(), e),
        ))),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn verify_config_dir_strict(_path: &Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(target_os = "linux")]
/// 校验 /etc/crbs 下任意深度的单个配置文件为 root 所有且组/其他不可写；relaxed 时跳过。
fn verify_config_file_permissions(path: &Path, relaxed: bool) -> Result<(), Error> {
    if relaxed || !is_under_system_config_dir(path) {
        return Ok(());
    }
    let meta = std::fs::metadata(path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("metadata {}: {}", path.display(), e),
        ))
    })?;
    let mode = meta.permissions().mode();
    let uid = meta.uid();

    if uid != 0 {
        return Err(Error::PermissionDenied(format!(
            "config file {} is not owned by root (uid={}); \
             fix: sudo chown root:crbs {} && sudo chmod 0640 {}{}",
            path.display(),
            uid,
            path.display(),
            path.display(),
            RELAX_HINT
        )));
    }
    if mode & 0o022 != 0 {
        return Err(Error::PermissionDenied(format!(
            "config file {} is group or world writable ({:04o}); \
             fix: sudo chmod 0640 {}{}",
            path.display(),
            mode & 0o777,
            path.display(),
            RELAX_HINT
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_config_file_permissions(_path: &Path, _relaxed: bool) -> Result<(), Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn load_allowed_paths_from_helper_config_field() {
        let tmp = tempfile::tempdir().unwrap();
        let helper_cfg = HelperConfig {
            relax_config_permissions: false,
            allowed_paths: vec![PathBuf::from("/data/results"), PathBuf::from("/data/cache")],
        };

        let paths = load_allowed_paths(tmp.path(), &helper_cfg).unwrap().paths;

        assert_eq!(paths.len(), 4);
        assert!(paths.contains(&PathBuf::from("/data/results")));
        assert!(paths.contains(&PathBuf::from("/data/cache")));
    }

    #[test]
    fn load_allowed_paths_from_global_config() {
        let tmp = tempfile::tempdir().unwrap();
        let mut file = std::fs::File::create(tmp.path().join("crbs.toml")).unwrap();
        writeln!(
            file,
            r#"
result_dir = "/data/results"
product_root = "/data/products"
"#
        )
        .unwrap();

        let paths = load_allowed_paths(tmp.path(), &HelperConfig::default())
            .unwrap()
            .paths;
        assert!(paths.contains(&PathBuf::from("/data/results")));
        assert!(paths.contains(&PathBuf::from("/data/products")));
    }

    #[test]
    fn load_allowed_paths_from_product_config() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("products")).unwrap();
        let mut file = std::fs::File::create(tmp.path().join("products/mydist.toml")).unwrap();
        writeln!(
            file,
            r#"
base_packages = ["bash"]
result_dir = "/data/mydist-results"
"#
        )
        .unwrap();

        let paths = load_allowed_paths(tmp.path(), &HelperConfig::default())
            .unwrap()
            .paths;
        assert!(paths.contains(&PathBuf::from("/data/mydist-results")));
    }

    #[test]
    fn load_allowed_paths_collects_product_tmp_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("products")).unwrap();
        let mut file = std::fs::File::create(tmp.path().join("products/mydist.toml")).unwrap();
        writeln!(
            file,
            r#"
base_packages = ["bash"]
tmp_dir = "/data/mydist-tmp"
tmpfs_dir = "/data/mydist-tmpfs"
"#
        )
        .unwrap();

        let paths = load_allowed_paths(tmp.path(), &HelperConfig::default())
            .unwrap()
            .paths;
        assert!(paths.contains(&PathBuf::from("/data/mydist-tmp")));
        assert!(paths.contains(&PathBuf::from("/data/mydist-tmpfs")));
    }

    #[test]
    fn load_allowed_paths_dedupes_across_sources() {
        let tmp = tempfile::tempdir().unwrap();
        let mut global = std::fs::File::create(tmp.path().join("crbs.toml")).unwrap();
        writeln!(global, r#"result_dir = "/data/results""#).unwrap();

        let helper_cfg = HelperConfig {
            relax_config_permissions: false,
            allowed_paths: vec![PathBuf::from("/data/results")],
        };
        let paths = load_allowed_paths(tmp.path(), &helper_cfg).unwrap().paths;

        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn load_configured_crbs_root_defaults_to_engine_root_when_config_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let root = load_configured_crbs_root(tmp.path(), false).unwrap();
        assert_eq!(root, PathBuf::from(DEFAULT_ENGINE_CRBS_ROOT));
    }

    #[test]
    fn load_configured_crbs_root_defaults_to_engine_root_when_key_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let mut global = std::fs::File::create(tmp.path().join("crbs.toml")).unwrap();
        writeln!(global, r#"result_dir = "/data/results""#).unwrap();

        let root = load_configured_crbs_root(tmp.path(), false).unwrap();
        assert_eq!(root, PathBuf::from(DEFAULT_ENGINE_CRBS_ROOT));
    }

    #[test]
    fn load_configured_server_root_defaults_when_config_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let root = load_configured_server_root(tmp.path(), false).unwrap();
        assert_eq!(root, PathBuf::from(DEFAULT_CRBS_ROOT));
    }

    #[test]
    fn load_configured_server_root_reads_from_server_config() {
        let tmp = tempfile::tempdir().unwrap();
        let mut server = std::fs::File::create(tmp.path().join("server.toml")).unwrap();
        writeln!(server, r#"crbs_root = "/data/server-root""#).unwrap();

        let root = load_configured_server_root(tmp.path(), false).unwrap();
        assert_eq!(root, PathBuf::from("/data/server-root"));
    }

    #[test]
    fn load_allowed_paths_includes_both_world_roots_by_default() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = load_allowed_paths(tmp.path(), &HelperConfig::default())
            .unwrap()
            .paths;
        assert!(
            paths.contains(&PathBuf::from(DEFAULT_CRBS_ROOT)),
            "server root must be in allowed set: {paths:?}"
        );
        assert!(
            paths.contains(&PathBuf::from(DEFAULT_ENGINE_CRBS_ROOT)),
            "engine root must be in allowed set: {paths:?}"
        );
    }

    #[test]
    fn load_configured_crbs_root_reads_from_global_config() {
        let tmp = tempfile::tempdir().unwrap();
        let mut global = std::fs::File::create(tmp.path().join("crbs.toml")).unwrap();
        writeln!(global, r#"crbs_root = "/data/crbs""#).unwrap();

        let root = load_configured_crbs_root(tmp.path(), false).unwrap();
        assert_eq!(root, PathBuf::from("/data/crbs"));
    }

    #[test]
    fn load_configured_worker_root_reads_from_worker_config() {
        let tmp = tempfile::tempdir().unwrap();
        let mut worker = std::fs::File::create(tmp.path().join("worker.toml")).unwrap();
        writeln!(worker, r#"crbs_root = "/data/crbs-worker""#).unwrap();

        let root = load_configured_worker_root(tmp.path(), false).unwrap();
        assert_eq!(root, Some(PathBuf::from("/data/crbs-worker")));
    }

    #[test]
    fn load_configured_worker_root_none_when_config_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let root = load_configured_worker_root(tmp.path(), false).unwrap();
        assert_eq!(root, None);
    }

    #[test]
    fn load_configured_worker_root_none_when_key_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let mut worker = std::fs::File::create(tmp.path().join("worker.toml")).unwrap();
        writeln!(worker, r#"capacity = 4"#).unwrap();

        let root = load_configured_worker_root(tmp.path(), false).unwrap();
        assert_eq!(root, None);
    }

    #[test]
    fn load_allowed_paths_includes_worker_root_when_configured() {
        let tmp = tempfile::tempdir().unwrap();
        let mut worker = std::fs::File::create(tmp.path().join("worker.toml")).unwrap();
        writeln!(worker, r#"crbs_root = "/data/crbs-worker""#).unwrap();

        let paths = load_allowed_paths(tmp.path(), &HelperConfig::default())
            .unwrap()
            .paths;
        assert!(
            paths.contains(&PathBuf::from("/data/crbs-worker")),
            "worker root must be in allowed set: {paths:?}"
        );
    }

    #[test]
    fn load_allowed_paths_skips_symlink_in_products() {
        let tmp = tempfile::tempdir().unwrap();
        let products = tmp.path().join("products");
        std::fs::create_dir(&products).unwrap();
        let real = tmp.path().join("real.toml");
        {
            let mut f = std::fs::File::create(&real).unwrap();
            writeln!(f, r#"result_dir = "/data/real-results""#).unwrap();
        }
        std::os::unix::fs::symlink(&real, products.join("link.toml")).unwrap();

        let paths = load_allowed_paths(tmp.path(), &HelperConfig::default())
            .unwrap()
            .paths;
        assert!(!paths.contains(&PathBuf::from("/data/real-results")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn under_system_config_dir_covers_subdirs() {
        assert!(is_under_system_config_dir(Path::new("/etc/crbs")));
        assert!(is_under_system_config_dir(Path::new("/etc/crbs/products")));
        assert!(is_under_system_config_dir(Path::new(
            "/etc/crbs/products/mydist.toml"
        )));
        assert!(!is_under_system_config_dir(Path::new("/etc/crbs-evil")));
        assert!(!is_under_system_config_dir(Path::new("/tmp")));
    }

    #[test]
    fn load_helper_config_absent_is_strict() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = load_helper_config(tmp.path()).unwrap();
        assert!(!cfg.relax_config_permissions);
    }

    #[test]
    fn load_helper_config_reads_relax_flag() {
        #[cfg(target_os = "linux")]
        {
            if !nix::unistd::geteuid().is_root() {
                eprintln!(
                    "skipping: priv-helper.toml bootstrap ownership check requires root-owned file"
                );
                return;
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let mut f = std::fs::File::create(tmp.path().join(HELPER_CONFIG_FILE)).unwrap();
        writeln!(f, "relax_config_permissions = true").unwrap();

        let cfg = load_helper_config(tmp.path()).unwrap();
        assert!(cfg.relax_config_permissions);
    }

    #[test]
    fn load_helper_config_rejects_bad_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let mut f = std::fs::File::create(tmp.path().join(HELPER_CONFIG_FILE)).unwrap();
        writeln!(f, "not [valid toml").unwrap();

        assert!(load_helper_config(tmp.path()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verify_permissions_relaxed_skips_checks() {
        let missing = Path::new("/etc/crbs/__definitely_not_exist__.toml");
        assert!(verify_config_file_permissions(missing, true).is_ok());
        assert!(verify_config_file_permissions(missing, false).is_err());
        assert!(verify_config_dir_permissions(missing, true).is_ok());
        assert!(verify_config_dir_permissions(missing, false).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn load_helper_config_rejects_non_root_owned() {
        if !nix::unistd::geteuid().is_root() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(HELPER_CONFIG_FILE);
        std::fs::write(&path, "relax_config_permissions = true").unwrap();
        std::os::unix::fs::chown(&path, Some(1000), Some(1000)).unwrap();

        let err = load_helper_config(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("must be owned by root"), "unexpected: {err}");
        assert!(err.contains("fix:"), "missing remediation hint: {err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn strict_error_contains_remediation_hint() {
        if !nix::unistd::geteuid().is_root() || !Path::new("/etc/crbs").is_dir() {
            return;
        }
        let path = Path::new("/etc/crbs/.helper-hint-test.toml");
        std::fs::write(path, "").unwrap();
        std::os::unix::fs::chown(path, Some(1000), Some(1000)).unwrap();

        let result = verify_config_file_permissions(path, false);

        let _ = std::fs::remove_file(path);

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("fix: sudo chown"),
            "missing fix command: {err}"
        );
        assert!(
            err.contains("relax_config_permissions"),
            "missing relax hint: {err}"
        );
    }
}
