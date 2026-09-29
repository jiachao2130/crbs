// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs-server gpg`：GPG 密钥管理子命令（import / list / export，供 RPM 签名用）。

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};

/// GPG key management command entry.
#[derive(Args, Debug)]
pub struct GpgCli {
    /// GPG home directory (default from GNUPGHOME env var, or /var/lib/crbs-gnupg if unset)
    #[arg(long, global = true)]
    pub gpg_home: Option<PathBuf>,
    #[command(subcommand)]
    pub command: GpgCommand,
}

/// GPG key management subcommands.
#[derive(Subcommand, Debug)]
pub enum GpgCommand {
    /// Import a GPG private key into the specified GPG home
    Import {
        /// Private key file path (ASCII-armored .asc)
        #[arg(long, value_name = "PATH")]
        key_file: PathBuf,
    },
    /// List imported keys
    List,
    /// Export public key (binary by default; pass --armor for ASCII armor)
    Export {
        /// Output in ASCII armor format
        #[arg(long)]
        armor: bool,
    },
}

/// Handle `crbs-server gpg ...` commands.
pub async fn handle_gpg(gpg_cli: GpgCli) -> anyhow::Result<()> {
    let gpg_home = resolve_gpg_home(gpg_cli.gpg_home.as_deref())?;

    tokio::fs::create_dir_all(&gpg_home)
        .await
        .map_err(|e| anyhow::anyhow!("create gpg home {}: {e}", gpg_home.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        tokio::fs::set_permissions(&gpg_home, perms)
            .await
            .map_err(|e| anyhow::anyhow!("chmod gpg home {}: {e}", gpg_home.display()))?;
    }

    // 拒绝 symlink 指向的 gpg_home：否则 chmod 与密钥导入会作用于链接目标；
    // 规则与 server 侧 apply_server_gpg_home_default 同一套。
    let gpg_home_display = gpg_home.display().to_string();
    let euid = nix::unistd::geteuid().as_raw();
    let probe = gpg_home.clone();
    let validated = tokio::task::spawn_blocking(move || {
        crbs_core::sign::SignConfig::validate_gpg_home(&probe, euid)
    })
    .await
    .map_err(|e| anyhow::anyhow!("gpg home validation task: {e}"))?
    .map_err(|e| anyhow::anyhow!("gpg home {} failed validation: {e}", gpg_home_display))?;
    let gpg_home = std::path::PathBuf::from(validated);

    match gpg_cli.command {
        GpgCommand::Import { key_file } => gpg_import(&gpg_home, &key_file).await,
        GpgCommand::List => gpg_list(&gpg_home).await,
        GpgCommand::Export { armor } => gpg_export(&gpg_home, armor).await,
    }
}

fn resolve_gpg_home(cli_path: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(p) = cli_path {
        return Ok(p.to_path_buf());
    }
    if let Ok(env) = std::env::var("GNUPGHOME") {
        return Ok(PathBuf::from(env));
    }
    Ok(PathBuf::from("/var/lib/crbs-gnupg"))
}

async fn gpg_import(gpg_home: &Path, key_file: &Path) -> anyhow::Result<()> {
    if !key_file.exists() {
        return Err(anyhow::anyhow!(
            "key file not found: {}",
            key_file.display()
        ));
    }

    let output = tokio::process::Command::new("gpg")
        .arg("--homedir")
        .arg(gpg_home)
        .arg("--batch")
        .arg("--yes")
        .arg("--import")
        .arg(key_file)
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("failed to run gpg import: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("gpg import failed: {stderr}"));
    }

    println!("GPG key imported successfully to {}", gpg_home.display());

    let verify = tokio::process::Command::new("gpg")
        .arg("--homedir")
        .arg(gpg_home)
        .arg("--list-secret-keys")
        .arg("--with-colons")
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("failed to run gpg list-secret-keys: {e}"))?;

    if !verify.status.success() {
        let stderr = String::from_utf8_lossy(&verify.stderr);
        return Err(anyhow::anyhow!("gpg list-secret-keys failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&verify.stdout);
    let key_count = stdout.lines().filter(|l| l.starts_with("sec:")).count();
    println!("  Secret keys: {key_count}");
    Ok(())
}

async fn gpg_list(gpg_home: &Path) -> anyhow::Result<()> {
    let output = tokio::process::Command::new("gpg")
        .arg("--homedir")
        .arg(gpg_home)
        .arg("--list-secret-keys")
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("failed to run gpg list-secret-keys: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("gpg list-secret-keys failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        println!("No secret keys in {}", gpg_home.display());
    } else {
        println!("{}", stdout);
    }
    Ok(())
}

async fn gpg_export(gpg_home: &Path, armor: bool) -> anyhow::Result<()> {
    let mut cmd = tokio::process::Command::new("gpg");
    cmd.arg("--homedir").arg(gpg_home);
    if armor {
        cmd.arg("--armor");
    }
    cmd.arg("--export");

    let output = cmd
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("failed to run gpg export: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("gpg export failed: {stderr}"));
    }

    if armor {
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("{}", stdout);
    } else {
        // spawn_blocking：二进制 stdout 写是同步 IO，避免阻塞 async 运行时。
        let data = output.stdout;
        tokio::task::spawn_blocking(move || {
            use std::io::Write;
            let mut stdout = std::io::stdout();
            stdout.write_all(&data)?;
            stdout.flush()
        })
        .await
        .map_err(|e| anyhow::anyhow!("gpg export stdout write task: {e}"))??;
    }
    Ok(())
}
