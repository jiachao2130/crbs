// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs remote` 命令族：远程 server profile 的本地管理（list / test / add）。
//! list/test 读合并视图（系统配置 + `~/.config/crbs/crbs.toml`，与 `--remote`
//! 解析口径一致）；add 只写用户级配置（toml_edit 注释保留式编辑 + rename 原子
//! 落盘），不提供删除/编辑（直接改配置文件，样例见 examples/config/crbs.toml 的
//! `[[remote.profiles]]`）。结果走 stdout，warning/交互提示走 stderr（stdout
//! 可安全重定向）；三个子命令均支持 `--format json`（信封含 command 键，
//! token 值任何形态都不回显）。

use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::Result;
use crbs_core::config::CrbsConfig;
use crbs_core::error::CrbsError;

/// `remote add` 的写参数（与 CLI 字段一一对应，独立 struct 便于单测直接构造）。
#[derive(Debug, Clone)]
pub(crate) struct NewProfile {
    pub name: String,
    pub url: String,
    pub token_env: Option<String>,
    pub token_file: Option<PathBuf>,
    pub ca_cert: Option<PathBuf>,
    pub token: Option<String>,
    pub use_default: bool,
}

pub(crate) async fn handle_remote(command: crate::cli::RemoteCommand) -> Result<()> {
    match command {
        crate::cli::RemoteCommand::List { format } => list_profiles(format).await,
        crate::cli::RemoteCommand::Test { profile, format } => test_profile(&profile, format).await,
        crate::cli::RemoteCommand::Add {
            name,
            url,
            token_env,
            token_file,
            ca_cert,
            token,
            use_default,
            format,
        } => {
            add_profile(
                NewProfile {
                    name,
                    url,
                    token_env,
                    token_file,
                    ca_cert,
                    token,
                    use_default,
                },
                format,
            )
            .await
        }
    }
}

/// `crbs remote list`：表格输出 name / url / 鉴权方式（不回显 token 值）。
async fn list_profiles(format: crate::cli::OutputFormat) -> Result<()> {
    let cfg = CrbsConfig::load_merged_async().await?;
    if format == crate::cli::OutputFormat::Json {
        let default = cfg.remote.default_profile();
        let remotes: Vec<serde_json::Value> = cfg
            .remote
            .profiles
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "url": p.url,
                    "auth": auth_summary(p),
                    "default": default == Some(p.name.as_str()),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "command": "remote list",
                "remotes": remotes,
            }))?
        );
        return Ok(());
    }
    if cfg.remote.profiles.is_empty() {
        println!("No remote profiles configured.");
        println!();
        println!(
            "  Add one:      crbs remote add <name> --url <URL> [--token-env VAR | --token-file PATH]"
        );
        println!("  Full example: examples/config/crbs.toml ([[remote.profiles]] section)");
        return Ok(());
    }
    let default = cfg.remote.default_profile().map(str::to_string);
    let mut table = crate::cmd::status::new_table_with_style(crate::cmd::status::ansi_allowed(
        std::io::stdout().is_terminal(),
        std::env::var_os("NO_COLOR").as_deref(),
    ));
    table.set_header(vec!["NAME", "URL", "AUTH"]);
    for p in &cfg.remote.profiles {
        let name = if default.as_deref() == Some(p.name.as_str()) {
            format!("{} (default)", p.name)
        } else {
            p.name.clone()
        };
        table.add_row(vec![name, p.url.clone(), auth_summary(p)]);
    }
    println!("{table}");
    Ok(())
}

/// `crbs remote test <profile>`：连通 + 鉴权自检（`crbs ping` 同端点）。
async fn test_profile(name: &str, format: crate::cli::OutputFormat) -> Result<()> {
    // 解析与错误映射继承 remote::resolve 统一契约（profile 缺失 → USAGE=4 列出可用名）。
    let target = crate::remote::resolve(Some(name.to_string()), None, None, false)
        .await?
        .ok_or_else(|| {
            CrbsError::Internal("remote profile resolution returned no target".into())
        })?;

    // 错误映射继承 remote.rs 契约：传输不通 → Network(6)、401/403 → PermissionDenied(5)。
    let url = format!("{}/api/v1/nihao", target.url);
    let resp: crate::cmd::nihao::NihaoResponse = crate::remote::remote_send_json(
        &target,
        reqwest::Method::GET,
        |client| client.get(&url),
        None,
        None,
    )
    .await?;

    if format == crate::cli::OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "command": "remote test",
                "profile": name,
                "url": target.url,
                "auth": resp.auth,
                "user": resp.user,
                "role": resp.role,
                "server_version": resp.server_version,
                "server_time": resp.server_time,
                "message": resp.message,
            }))?
        );
        return Ok(());
    }
    println!("OK: profile '{name}' -> {}", target.url);
    println!(
        "  auth:   {} (user: {}, role: {})",
        resp.auth, resp.user, resp.role
    );
    println!(
        "  server: version {}, message \"{}\"",
        resp.server_version, resp.message
    );
    Ok(())
}

/// `crbs remote add <name> --url <URL> ...`：校验 → 写用户配置 → 回显摘要。
async fn add_profile(profile: NewProfile, format: crate::cli::OutputFormat) -> Result<()> {
    validate_profile_name(&profile.name)?;
    // normalize_base_url 校验 scheme（仅 http/https）并规范化（裸主机名补 http://、去尾 `/`），与 --remote 一致。
    let url = crate::remote::normalize_base_url(&profile.url)?;
    let path = user_config_path()?;

    let summary_name = profile.name.clone();
    let summary_url = url.clone();
    let summary_auth = auth_summary(&to_core_profile(&profile));
    let summary_default = profile.use_default;
    let summary_token_env = profile.token_env.clone();
    let summary_ca_cert = profile.ca_cert.clone();
    let summary_path = path.display().to_string();

    // 文件读写与 toml 解析全程 sync，按 async 纪律放 spawn_blocking。
    tokio::task::spawn_blocking(move || {
        write_profile_blocking(path, NewProfile { url, ..profile })
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("join user config writer: {e}")))??;

    // 安全/完整性提示走 stderr，写入成功后才输出（校验失败不产生无关告警）；
    // json 形态下同样保留（stdout 的机器可读性不受影响）。
    if summary_auth == "inline token" {
        eprintln!(
            "warning: --token stores the API token as plaintext in {summary_path}; \
             prefer --token-env or --token-file"
        );
    }
    if let Some(env_name) = &summary_token_env {
        if std::env::var(env_name).is_err() {
            eprintln!(
                "warning: environment variable {env_name} (token_env) is not currently set; \
                 export it (e.g. `export {env_name}=crbs_tok_...`) before use"
            );
        }
    }
    if summary_auth == "anonymous" {
        eprintln!(
            "warning: no auth configured for profile '{summary_name}'; requests will be anonymous \
             (acceptable for hubs that allow anonymous read-only access)"
        );
    }

    if format == crate::cli::OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "command": "remote add",
                "name": summary_name,
                "url": summary_url,
                "auth": summary_auth,
                "default": summary_default,
                "ca_cert": summary_ca_cert.as_ref().map(|p| p.display().to_string()),
                "config_path": summary_path,
            }))?
        );
        return Ok(());
    }
    println!("Added remote profile '{summary_name}'");
    println!("  url:  {summary_url}");
    println!("  auth: {summary_auth}");
    if let Some(p) = &summary_ca_cert {
        println!("  ca:   {}", p.display());
    }
    if summary_default {
        println!("  default: yes (remote.default = '{summary_name}')");
    }
    println!("Run 'crbs remote test {summary_name}' to verify connectivity and authentication.");
    Ok(())
}

/// profile 名校验：非空、非 URL 形态、非保留名 "local"（大小写不敏感）。
/// URL 形态名在 `--remote` 永远按 ad-hoc 解析（is_remote_url 优先），配了也配不到；
/// "local" 被 core 当本地构建语义吞掉，default 指向它永远不可达。
fn validate_profile_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: "remote profile name must not be empty".into(),
        }
        .into());
    }
    if name.trim().eq_ignore_ascii_case("local") {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "remote profile name '{name}' is reserved: the name 'local' selects \
                 the local build target (remote.default = \"local\" means build \
                 locally), so a profile with this name could never be reached via \
                 the default — pick a plain name like 'prod'"
            ),
        }
        .into());
    }
    if crate::remote::is_remote_url(name) {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "remote profile name '{name}' looks like a URL; `--remote` treats \
                 URL-shaped values as ad-hoc targets so the profile would never resolve — \
                 pick a plain name like 'prod'"
            ),
        }
        .into());
    }
    Ok(())
}

/// 用户级配置路径 `~/.config/crbs/crbs.toml`（core `CrbsConfig::user_config_path` 同款解析未公开）。
fn user_config_path() -> Result<PathBuf> {
    let home = home::home_dir().ok_or_else(|| CrbsError::Io {
        context: "resolve home directory for user config".into(),
        kind: std::io::ErrorKind::NotFound,
        detail: "home directory not found".into(),
    })?;
    Ok(home.join(".config").join("crbs").join("crbs.toml"))
}

/// 阻塞侧写路径（spawn_blocking 内执行）：读用户配置 → 插入 profile → 原子落盘。
/// 并发语义：不加锁，最后写入者胜出（读-改-写之间他人落盘的改动被整文件覆盖）。
fn write_profile_blocking(path: PathBuf, profile: NewProfile) -> Result<()> {
    let mut doc =
        match std::fs::read_to_string(&path) {
            Ok(content) => content.parse::<toml_edit::DocumentMut>().map_err(|e| {
                CrbsError::ValidationFailed {
                    message: format!("parse user config {}: {e}", path.display()),
                }
            })?,
            // 文件不存在 → 从空文档构造（连同父目录一起创建）。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml_edit::DocumentMut::new(),
            Err(e) => {
                return Err(CrbsError::Io {
                    context: format!("read user config {}", path.display()),
                    kind: e.kind(),
                    detail: e.to_string(),
                }
                .into());
            }
        };
    upsert_profile(&mut doc, &path, &profile)?;
    write_atomic(&path, &doc)
}

/// 把 profile 插入文档的 `[remote.profiles]` 数组（toml_edit 注释/格式保留）。
/// 同名已存在即报错；`--use-default` 同时写 `remote.default = <name>`（覆盖既有 default）。
fn upsert_profile(
    doc: &mut toml_edit::DocumentMut,
    path: &Path,
    profile: &NewProfile,
) -> Result<()> {
    let remote = doc
        .entry("remote")
        .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    let remote_table = remote
        .as_table_mut()
        .ok_or_else(|| CrbsError::ValidationFailed {
            message: format!(
                "user config {} has a non-table value at key `remote`; expected a [remote] section",
                path.display()
            ),
        })?;

    let shape_ok = remote_table
        .get("profiles")
        .map(|item| item.as_array_of_tables().is_some())
        .unwrap_or(true);
    if !shape_ok {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "user config {} key `remote.profiles` is not an array of tables \
                 ([[remote.profiles]])",
                path.display()
            ),
        }
        .into());
    }
    if remote_table.get("profiles").is_none() {
        remote_table.insert(
            "profiles",
            toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()),
        );
    }
    let profiles = remote_table
        .get_mut("profiles")
        .and_then(|item| item.as_array_of_tables_mut())
        .ok_or_else(|| CrbsError::Internal("remote.profiles vanished after insert".into()))?;

    if profiles
        .iter()
        .any(|t| t.get("name").and_then(|i| i.as_str()) == Some(profile.name.as_str()))
    {
        return Err(CrbsError::AlreadyExists {
            message: format!(
                "remote profile '{}' already exists in {}; remove it or pick another name",
                profile.name,
                path.display()
            ),
        }
        .into());
    }
    profiles.push(new_profile_table(profile));

    if profile.use_default {
        // toml_edit insert 整体替换 key-value 会丢两侧 decor（key 行前注释、
        // value 前缀空白），覆写 default 前先摘出贴回，防覆写路径掉注释。
        let old_key_prefix = remote_table
            .key("default")
            .and_then(|k| k.leaf_decor().prefix())
            .and_then(|p| p.as_str())
            .map(str::to_string);
        let old_value_prefix = remote_table
            .get("default")
            .and_then(|item| item.as_value())
            .and_then(|v| v.decor().prefix())
            .and_then(|p| p.as_str())
            .map(str::to_string);

        remote_table.insert("default", toml_edit::value(profile.name.clone()));
        if let Some(prefix) = old_key_prefix {
            if let Some(mut key) = remote_table.key_mut("default") {
                key.leaf_decor_mut().set_prefix(prefix);
            }
        }
        if let Some(prefix) = old_value_prefix {
            if let Some(v) = remote_table
                .get_mut("default")
                .and_then(|item| item.as_value_mut())
            {
                v.decor_mut().set_prefix(prefix);
            }
        }
    }
    Ok(())
}

/// 构造新 profile 的 `[[remote.profiles]]` 表（字段名对齐 core `RemoteProfile`；只写用户给过的字段，其余 serde default）。
fn new_profile_table(profile: &NewProfile) -> toml_edit::Table {
    let mut t = toml_edit::Table::new();
    t.insert("name", toml_edit::value(profile.name.clone()));
    t.insert("url", toml_edit::value(profile.url.clone()));
    if let Some(v) = &profile.token_env {
        t.insert("token_env", toml_edit::value(v.clone()));
    }
    if let Some(p) = &profile.token_file {
        t.insert("token_file", toml_edit::value(p.display().to_string()));
    }
    if let Some(p) = &profile.ca_cert {
        t.insert("ca_cert", toml_edit::value(p.display().to_string()));
    }
    if let Some(v) = &profile.token {
        t.insert("token", toml_edit::value(v.clone()));
    }
    t
}

/// 原子落盘：父目录新建时 0700、临时文件 0600 后 rename，避免半成品配置。
fn write_atomic(path: &Path, doc: &toml_edit::DocumentMut) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let created_dir = !dir.exists();
    std::fs::create_dir_all(dir).map_err(|e| CrbsError::Io {
        context: format!("create user config dir {}", dir.display()),
        kind: e.kind(),
        detail: e.to_string(),
    })?;
    #[cfg(unix)]
    {
        if created_dir {
            use std::os::unix::fs::PermissionsExt;
            // 只对本次新建的目录收口 0700，不改动用户既有目录的权限。
            if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
                tracing::warn!(
                    path = %dir.display(),
                    error = %e,
                    "failed to chmod user config dir to 0700 (perms may not be effective)"
                );
            }
        }
    }

    // 同目录临时文件 + rename：中途崩溃不产生半截 TOML；tempfile 在 unix 默认
    // 0600 创建，rename 后权限随最终文件保留。
    let tmp = tempfile::NamedTempFile::new_in(dir).map_err(|e| CrbsError::Io {
        context: format!("create temp user config in {}", dir.display()),
        kind: e.kind(),
        detail: e.to_string(),
    })?;
    tmp.as_file()
        .write_all(doc.to_string().as_bytes())
        .map_err(|e| CrbsError::Io {
            context: format!("write user config to {}", tmp.path().display()),
            kind: e.kind(),
            detail: e.to_string(),
        })?;
    tmp.as_file().sync_all().map_err(|e| CrbsError::Io {
        context: format!("sync user config to {}", tmp.path().display()),
        kind: e.kind(),
        detail: e.to_string(),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 显式 set_permissions 收口（create 默认值受 umask 语义影响时兜底）。
        if let Err(e) = tmp
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
        {
            tracing::warn!(
                path = %tmp.path().display(),
                error = %e,
                "failed to chmod user config temp file to 0600 (perms may not be effective)"
            );
        }
    }
    tmp.persist(path).map_err(|e| {
        let inner = e.error;
        CrbsError::Io {
            context: format!("finalize user config {}", path.display()),
            kind: inner.kind(),
            detail: inner.to_string(),
        }
    })?;
    // rename 仅本进程视角原子；父目录 fsync 刷目录项，掉电后文件才保证存在于目标路径。
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| CrbsError::Io {
            context: format!("fsync user config dir {}", dir.display()),
            kind: e.kind(),
            detail: e.to_string(),
        })?;
    Ok(())
}

/// 鉴权方式纯文本描述（优先级同 `resolve_profile_token`：token > token_env > token_file）；不回显 token 值。
fn auth_summary(profile: &crbs_core::config::RemoteProfile) -> String {
    if profile.token.is_some() {
        "inline token".to_string()
    } else if let Some(env_name) = &profile.token_env {
        format!("token_env={env_name}")
    } else if let Some(path) = &profile.token_file {
        format!("token_file={}", path.display())
    } else {
        "anonymous".to_string()
    }
}

/// `NewProfile` → core `RemoteProfile`（仅供鉴权描述/展示复用，不落盘）。
fn to_core_profile(profile: &NewProfile) -> crbs_core::config::RemoteProfile {
    crbs_core::config::RemoteProfile {
        name: profile.name.clone(),
        url: profile.url.clone(),
        token: profile.token.clone(),
        token_env: profile.token_env.clone(),
        token_file: profile.token_file.clone(),
        ca_cert: profile.ca_cert.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crbs_core::exit_code::{crbs_error_exit_code, ENVIRONMENT, PERMISSION, USAGE};

    fn new_profile(name: &str, url: &str) -> NewProfile {
        NewProfile {
            name: name.to_string(),
            url: url.to_string(),
            token_env: None,
            token_file: None,
            ca_cert: None,
            token: None,
            use_default: false,
        }
    }

    #[test]
    fn validate_name_rejects_url_shaped_and_empty() {
        for bad in ["https://hub.example.com", "hub.example.com:9090", "   ", ""] {
            let err = validate_profile_name(bad).expect_err("must reject");
            let ce = err
                .downcast_ref::<CrbsError>()
                .expect("must surface as CrbsError");
            assert!(
                matches!(ce, CrbsError::ValidationFailed { .. }),
                "unexpected variant for {bad:?}: {ce:?}"
            );
            assert_eq!(
                crbs_error_exit_code(ce),
                USAGE,
                "name {bad:?} maps to USAGE"
            );
        }
        validate_profile_name("prod").expect("plain name should pass");
        validate_profile_name("lab-01").expect("name with dash should pass");
    }

    #[test]
    fn validate_name_rejects_reserved_local() {
        for bad in ["local", "Local", "LOCAL", "lOcAl", "  local  "] {
            let err = validate_profile_name(bad).expect_err("must reject");
            let ce = err
                .downcast_ref::<CrbsError>()
                .expect("must surface as CrbsError");
            assert!(
                matches!(ce, CrbsError::ValidationFailed { .. }),
                "unexpected variant for {bad:?}: {ce:?}"
            );
            assert_eq!(
                crbs_error_exit_code(ce),
                USAGE,
                "name {bad:?} maps to USAGE"
            );
            let msg = format!("{ce}");
            assert!(
                msg.contains("reserved"),
                "reason missing for {bad:?}: {msg}"
            );
        }
        validate_profile_name("localhost-hub").expect("name merely containing 'local' passes");
    }

    /// 注释保留写入：既有内容原样保留，新 profile 字段齐全，--use-default 覆写 default。
    #[test]
    fn add_preserves_comments_and_existing_sections() {
        let original = r#"# top comment
crbs_root = "/tmp/engine"

[remote]
# default hub — this comment must survive
default = "old"

[[remote.profiles]]
name = "old"
url = "http://old.example.com"
token_env = "OLD_TOKEN"

# tail comment
[rpm_macros]
dist = ".el9"
"#;
        let mut doc: toml_edit::DocumentMut = original.parse().unwrap();
        let profile = NewProfile {
            token_env: Some("CRBS_PROD_TOKEN".into()),
            token_file: None,
            token: None,
            use_default: true,
            ..new_profile("prod", "https://hub.example.com")
        };
        upsert_profile(&mut doc, Path::new("/tmp/user-cfg.toml"), &profile).unwrap();

        let out = doc.to_string();
        for marker in ["# top comment", "# default hub", "# tail comment"] {
            assert!(out.contains(marker), "comment lost: {out}");
        }
        assert!(out.contains("crbs_root = \"/tmp/engine\""), "out: {out}");
        assert!(out.contains("[rpm_macros]"), "out: {out}");
        assert!(out.contains("dist = \".el9\""), "out: {out}");
        assert!(out.contains("name = \"old\""), "out: {out}");
        assert!(out.contains("token_env = \"OLD_TOKEN\""), "out: {out}");

        let remote = doc.get("remote").and_then(|i| i.as_table()).unwrap();
        assert_eq!(
            remote.get("default").and_then(|i| i.as_str()),
            Some("prod"),
            "use_default must overwrite remote.default"
        );
        let profiles = remote
            .get("profiles")
            .and_then(|i| i.as_array_of_tables())
            .unwrap();
        assert_eq!(profiles.len(), 2, "old profile must remain: {out}");
        let new = profiles
            .iter()
            .find(|t| t.get("name").and_then(|i| i.as_str()) == Some("prod"))
            .expect("new profile present");
        assert_eq!(
            new.get("url").and_then(|i| i.as_str()),
            Some("https://hub.example.com")
        );
        assert_eq!(
            new.get("token_env").and_then(|i| i.as_str()),
            Some("CRBS_PROD_TOKEN")
        );
        assert!(
            new.get("token").is_none() && new.get("token_file").is_none(),
            "unset optional fields must not be written"
        );
    }

    #[test]
    fn add_into_empty_document_creates_structure() {
        let mut doc = toml_edit::DocumentMut::new();
        upsert_profile(
            &mut doc,
            Path::new("/tmp/fresh.toml"),
            &new_profile("lab", "http://lab.example.com"),
        )
        .unwrap();
        let remote = doc.get("remote").and_then(|i| i.as_table()).unwrap();
        assert!(
            remote.get("default").is_none(),
            "no --use-default must not write remote.default"
        );
        let profiles = remote
            .get("profiles")
            .and_then(|i| i.as_array_of_tables())
            .unwrap();
        assert_eq!(profiles.len(), 1);
        let first = profiles.iter().next().expect("single profile present");
        assert_eq!(
            first.get("url").and_then(|i| i.as_str()),
            Some("http://lab.example.com")
        );
        // 产物须能过 crbs-core 的 toml 解析（deny_unknown_fields 兜底字段名）。
        let cfg: CrbsConfig = toml::from_str(&doc.to_string()).unwrap();
        assert_eq!(cfg.remote.profiles.len(), 1);
    }

    /// --ca-cert 落盘为 `ca_cert`（自签/内网 CA）；未提供不写键（serde default 省略语义）。
    #[test]
    fn add_writes_ca_cert_when_provided() {
        let mut profile = new_profile("secure", "https://hub.internal.example.com");
        profile.ca_cert = Some(PathBuf::from("/etc/crbs/certs/ca.crt"));
        let mut doc = toml_edit::DocumentMut::new();
        upsert_profile(&mut doc, Path::new("/tmp/fresh.toml"), &profile).unwrap();
        let profiles = doc
            .get("remote")
            .and_then(|i| i.as_table())
            .unwrap()
            .get("profiles")
            .and_then(|i| i.as_array_of_tables())
            .unwrap();
        let first = profiles.iter().next().expect("single profile present");
        assert_eq!(
            first.get("ca_cert").and_then(|i| i.as_str()),
            Some("/etc/crbs/certs/ca.crt")
        );
        let cfg: CrbsConfig = toml::from_str(&doc.to_string()).unwrap();
        assert_eq!(
            cfg.remote.profiles[0].ca_cert.as_deref(),
            Some(Path::new("/etc/crbs/certs/ca.crt"))
        );

        let mut doc = toml_edit::DocumentMut::new();
        upsert_profile(
            &mut doc,
            Path::new("/tmp/fresh.toml"),
            &new_profile("plain", "http://hub.example.com"),
        )
        .unwrap();
        let raw = doc.to_string();
        assert!(
            !raw.contains("ca_cert"),
            "no --ca-cert must not write the key"
        );
    }

    /// 隐式 `[remote]` 表（只有 `[[remote.profiles]]` 数组、无显式表头，TOML 允许）：
    /// --use-default 须落隐式表且不破坏数组、round-trip 正确——钉 toml_edit 行为防升级回归。
    #[test]
    fn add_into_implicit_remote_table_roundtrips() {
        let original = "[[remote.profiles]]\nname = \"old\"\nurl = \"http://old.example.com\"\n";
        let mut doc: toml_edit::DocumentMut = original.parse().unwrap();
        let profile = NewProfile {
            use_default: true,
            ..new_profile("prod", "https://hub.example.com")
        };
        upsert_profile(&mut doc, Path::new("/tmp/user-cfg.toml"), &profile).unwrap();

        let out = doc.to_string();
        let cfg: CrbsConfig = toml::from_str(&out).expect("round-trip output must parse");
        assert_eq!(
            cfg.remote.default.as_deref(),
            Some("prod"),
            "remote.default must land on the implicit [remote] table: {out}"
        );
        assert_eq!(cfg.remote.profiles.len(), 2, "out: {out}");
        let old = cfg
            .remote
            .profiles
            .iter()
            .find(|p| p.name == "old")
            .expect("old profile kept");
        assert_eq!(
            old.url, "http://old.example.com",
            "original content preserved: {out}"
        );
        let new = cfg
            .remote
            .profiles
            .iter()
            .find(|p| p.name == "prod")
            .expect("new profile present");
        assert_eq!(new.url, "https://hub.example.com", "out: {out}");
    }

    /// 同名 profile 已存在 → AlreadyExists（USAGE=4），原文档不被改动。
    #[test]
    fn add_rejects_duplicate_profile_name() {
        let original = "[[remote.profiles]]\nname = \"prod\"\nurl = \"http://keep.me\"\n";
        let mut doc: toml_edit::DocumentMut = original.parse().unwrap();
        let err = upsert_profile(
            &mut doc,
            Path::new("/tmp/user-cfg.toml"),
            &new_profile("prod", "https://other.example.com"),
        )
        .unwrap_err();
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::AlreadyExists { .. }),
            "unexpected variant: {ce:?}"
        );
        assert_eq!(crbs_error_exit_code(ce), USAGE);
        assert!(
            format!("{ce}").contains("remove it or pick another name"),
            "hint missing: {ce}"
        );
        assert!(
            doc.to_string().contains("http://keep.me"),
            "existing profile must stay untouched"
        );
    }

    /// `remote.profiles` 非数组（如误写成单表）→ ValidationFailed，原文档不动。
    #[test]
    fn add_rejects_non_array_profiles() {
        let mut doc: toml_edit::DocumentMut = "[remote.profiles]\nname = \"x\"\n".parse().unwrap();
        let err = upsert_profile(
            &mut doc,
            Path::new("/tmp/user-cfg.toml"),
            &new_profile("prod", "https://y"),
        )
        .unwrap_err();
        let ce = err.downcast_ref::<CrbsError>().unwrap();
        assert!(matches!(ce, CrbsError::ValidationFailed { .. }), "{ce:?}");
        assert!(format!("{ce}").contains("array of tables"), "{ce}");
    }

    /// 原子落盘：新建目录 0700、文件 0600；再次写入（目录已存在）不改目录权限。
    #[cfg(unix)]
    #[test]
    fn write_atomic_sets_0700_dir_and_0600_file() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("cfg").join("crbs.toml");

        let mut doc: toml_edit::DocumentMut = "[remote]\ndefault = \"prod\"\n".parse().unwrap();
        upsert_profile(&mut doc, &path, &new_profile("prod", "https://h")).unwrap();
        write_atomic(&path, &doc).unwrap();

        let dir_mode = path
            .parent()
            .unwrap()
            .metadata()
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700, "new dir must be 0700");
        let file_mode = path.metadata().unwrap().permissions().mode();
        assert_eq!(file_mode & 0o777, 0o600, "config file must be 0600");
        assert!(path.metadata().unwrap().len() > 0, "content written");

        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        upsert_profile(&mut doc, &path, &new_profile("lab", "https://l")).unwrap();
        write_atomic(&path, &doc).unwrap();
        let dir_mode = path
            .parent()
            .unwrap()
            .metadata()
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o750, "existing dir perms must be kept");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("name = \"lab\""), "second profile written");
    }

    /// 与 resolve_profile_token 的解析优先级一致（token > token_env > token_file）；不回显 token 值。
    #[test]
    fn auth_summary_matches_resolution_precedence() {
        let label = |token: Option<&str>, env: Option<&str>, file: Option<&str>| {
            auth_summary(&crbs_core::config::RemoteProfile {
                name: "p".into(),
                url: "https://h".into(),
                token: token.map(str::to_string),
                token_env: env.map(str::to_string),
                token_file: file.map(PathBuf::from),
                ca_cert: None,
            })
        };
        assert_eq!(
            label(Some("crbs_tok_x"), Some("V"), Some("/t")),
            "inline token"
        );
        assert_eq!(
            label(None, Some("CRBS_TOK"), Some("/t")),
            "token_env=CRBS_TOK"
        );
        assert_eq!(label(None, None, Some("~/.crbs/t")), "token_file=~/.crbs/t");
        assert_eq!(label(None, None, None), "anonymous");
        assert!(!label(Some("crbs_tok_x"), None, None).contains("crbs_tok_x"));
    }

    /// 用户配置不存在 → 连同父目录一起创建并写入（0700/0600）。
    #[cfg(unix)]
    #[test]
    fn write_profile_blocking_creates_missing_config() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".config").join("crbs").join("crbs.toml");
        let mut profile = new_profile("prod", "https://hub.example.com");
        profile.token_env = Some("CRBS_PROD_TOKEN".into());
        write_profile_blocking(path.clone(), profile).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[remote]"), "out: {content}");
        assert!(content.contains("[[remote.profiles]]"), "out: {content}");
        assert!(content.contains("token_env = \"CRBS_PROD_TOKEN\""));
        assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            path.parent()
                .unwrap()
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    /// 把 profile 写进临时 $HOME 的用户配置（HomeIsolatedEnvGuard 隔离，drop 时恢复环境）。
    fn seed_home_profile(
        tmp: &Path,
        profile: NewProfile,
    ) -> crate::test_support::HomeIsolatedEnvGuard {
        let cfg_dir = tmp.join(".config").join("crbs");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        write_profile_blocking(cfg_dir.join("crbs.toml"), profile).unwrap();
        crate::test_support::HomeIsolatedEnvGuard::new(tmp)
    }

    #[tokio::test]
    async fn test_profile_succeeds_against_mock_hub() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/nihao"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string(
                    r#"{"message":"nihao","server_version":"1.0.0","server_time":"2026-01-01T00:00:00Z","auth":"authenticated","user":"alice","role":"admin"}"#,
                ),
            )
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let _env = seed_home_profile(tmp.path(), new_profile("lab", &server.uri()));
        test_profile("lab", crate::cli::OutputFormat::Text)
            .await
            .expect("healthy profile should pass");
    }

    /// 退出码契约：401 → PermissionDenied（PERMISSION=5）。
    #[tokio::test]
    async fn test_profile_maps_401_to_permission_denied_exit_5() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/nihao"))
            .respond_with(wiremock::ResponseTemplate::new(401).set_body_string("denied"))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let _env = seed_home_profile(tmp.path(), new_profile("lab", &server.uri()));
        let err = test_profile("lab", crate::cli::OutputFormat::Text)
            .await
            .expect_err("401 must fail");
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::PermissionDenied { .. }),
            "unexpected variant: {ce:?}"
        );
        assert_eq!(crbs_error_exit_code(ce), PERMISSION);
    }

    /// 退出码契约：传输层不通 → Network（ENVIRONMENT=6）。
    #[tokio::test]
    async fn test_profile_maps_transport_error_to_network_exit_6() {
        let tmp = tempfile::tempdir().unwrap();
        // 127.0.0.1:1 为 privileged 端口，连接必然被拒。
        let _env = seed_home_profile(tmp.path(), new_profile("lab", "http://127.0.0.1:1"));
        let err = test_profile("lab", crate::cli::OutputFormat::Text)
            .await
            .expect_err("unreachable must fail");
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::Network { .. }),
            "unexpected variant: {ce:?}"
        );
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
    }

    /// profile 缺失 → ValidationFailed（USAGE=4），消息列出可用 profile 名。
    #[tokio::test]
    async fn test_profile_missing_lists_available_profiles() {
        let server = wiremock::MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let _env = seed_home_profile(tmp.path(), new_profile("lab", &server.uri()));

        let err = test_profile("nope", crate::cli::OutputFormat::Text)
            .await
            .expect_err("missing profile");
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::ValidationFailed { .. }),
            "unexpected variant: {ce:?}"
        );
        assert_eq!(crbs_error_exit_code(ce), USAGE);
        let msg = format!("{ce}");
        assert!(
            msg.contains("remote profile 'nope' not found"),
            "msg: {msg}"
        );
        assert!(msg.contains("lab"), "must list available profiles: {msg}");
    }
}
