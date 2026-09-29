// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs admin resource-profile list|set|unset|export|import`：包资源画像
//! declared 放置契约的远程管理。export/import 是 AI 分析闭环
//! 的进出两端：JSON 文档整存整取，画像行含样本数与末次样本核数（@nC）上下文。

use anyhow::Result;
use clap::Subcommand;

use crate::cli::{AdminRemoteArgs, CommandOutput, OutputFormat};
use crate::remote::RemoteTarget;

/// `crbs admin resource-profile` 子命令。
#[derive(Subcommand, Clone, Debug)]
pub(crate) enum ResourceProfileCommand {
    /// List resource profiles of a product (declared + learned groups)
    List {
        /// Product name
        #[arg(long)]
        product: String,
        #[command(flatten)]
        remote_args: AdminRemoteArgs,
    },
    /// Declare a placement floor (declared group) for product/source/arch
    Set {
        /// Product name
        product: String,
        /// Source package base name (builds.name, without version/release)
        source: String,
        /// Architecture ('x86_64' / 'noarch', or 'any' for arch-independent)
        arch: String,
        /// Minimum memory floor, e.g. '4G' / '512M' (K/M/G/T 1024-based, bare digits = KB)
        #[arg(long, value_name = "SIZE")]
        min_mem: Option<String>,
        /// Minimum CPU cores floor (1..=1024)
        #[arg(long, value_name = "N")]
        min_ncpu: Option<u32>,
        /// Minimum disk floor, e.g. '64G' (K/M/G/T 1024-based, bare digits = KB)
        #[arg(long, value_name = "SIZE")]
        min_disk: Option<String>,
        #[command(flatten)]
        remote_args: AdminRemoteArgs,
    },
    /// Clear the declared placement floor of product/source/arch (learned data is kept)
    Unset {
        /// Product name
        product: String,
        /// Source package base name (builds.name, without version/release)
        source: String,
        /// Architecture ('x86_64' / 'noarch', or 'any')
        arch: String,
        #[command(flatten)]
        remote_args: AdminRemoteArgs,
    },
    /// Export resource profiles of a product as a JSON document (round-trips with import)
    Export {
        /// Product name
        #[arg(long)]
        product: String,
        /// Write JSON to this path instead of stdout
        #[arg(long, value_name = "PATH")]
        file: Option<std::path::PathBuf>,
        #[command(flatten)]
        remote_args: AdminRemoteArgs,
    },
    /// Import declared floors from an export JSON document (one PUT per row;
    /// rows apply individually and are not transactional — the first failure aborts)
    Import {
        /// JSON document path, or '-' to read stdin
        #[arg(long, value_name = "PATH")]
        file: String,
        #[command(flatten)]
        remote_args: AdminRemoteArgs,
    },
}

/// import 文档形态（export 的往返对偶；行 schema = 服务端画像行全列）。
/// 行数组缺失/null 按空文档处理：`null` 本身不含任何行，
/// 导入 0 行即为正确语义。
#[derive(serde::Deserialize)]
struct ProfileImportDoc {
    product: String,
    #[serde(default)]
    resource_profiles: Option<Vec<serde_json::Value>>,
}

/// 远程目标解析（无 --remote 且无 remote.default 配置 = ValidationFailed，
/// USAGE=4；与 rebuild-repo 同文案口径）。
async fn resolve_target(args: &AdminRemoteArgs) -> Result<RemoteTarget> {
    crate::remote::resolve(
        args.remote.clone(),
        args.token.clone(),
        args.ca_cert.clone(),
        false,
    )
    .await?
    .ok_or_else(|| {
        crbs_core::error::CrbsError::ValidationFailed {
            message: "crbs admin resource-profile requires a remote server. \
                      Use --remote or configure remote.default"
                .to_string(),
        }
        .into()
    })
}

pub(crate) async fn handle_resource_profile(command: ResourceProfileCommand) -> Result<()> {
    use ResourceProfileCommand as C;
    match command {
        C::List {
            product,
            remote_args,
        } => {
            let target = resolve_target(&remote_args).await?;
            list_profiles(&target, &product, remote_args.format).await
        }
        C::Set {
            product,
            source,
            arch,
            min_mem,
            min_ncpu,
            min_disk,
            remote_args,
        } => {
            let target = resolve_target(&remote_args).await?;
            set_profile(
                &target,
                &product,
                &source,
                &arch,
                FloorInput {
                    min_mem,
                    min_ncpu,
                    min_disk,
                },
                remote_args.format,
            )
            .await
        }
        C::Unset {
            product,
            source,
            arch,
            remote_args,
        } => {
            let target = resolve_target(&remote_args).await?;
            unset_profile(&target, &product, &source, &arch, remote_args.format).await
        }
        C::Export {
            product,
            file,
            remote_args,
        } => {
            let target = resolve_target(&remote_args).await?;
            export_profiles(&target, &product, file).await
        }
        C::Import { file, remote_args } => {
            let target = resolve_target(&remote_args).await?;
            import_profiles(&target, &file, remote_args.format).await
        }
    }
}

/// set 子命令的三维声明输入（原始 CLI 串，人类单位；parse 换算 KB）。
struct FloorInput {
    min_mem: Option<String>,
    min_ncpu: Option<u32>,
    min_disk: Option<String>,
}

/// `parse_resource_min_kb` + 提交期同界收口（上界：mem ≤ 1 TiB、
/// disk ≤ 64 TiB、ncpu 1..=1024）。错误文案点名字段。
fn parse_floor(input: &FloorInput) -> Result<(Option<i64>, Option<i64>, Option<i64>)> {
    let mem = match input.min_mem.as_deref() {
        Some(s) => {
            let kb = crbs_core::config::parse_resource_min_kb("min_mem", s)?;
            if kb > crbs_core::build_options::MAX_REQ_MIN_MEM_KB {
                return Err(crbs_core::error::CrbsError::ValidationFailed {
                    message: format!(
                        "min_mem '{s}' exceeds the {} TiB upper limit",
                        crbs_core::build_options::MAX_REQ_MIN_MEM_KB / (1024 * 1024 * 1024)
                    ),
                }
                .into());
            }
            Some(kb)
        }
        None => None,
    };
    let disk = match input.min_disk.as_deref() {
        Some(s) => {
            let kb = crbs_core::config::parse_resource_min_kb("min_disk", s)?;
            if kb > crbs_core::build_options::MAX_REQ_MIN_DISK_KB {
                return Err(crbs_core::error::CrbsError::ValidationFailed {
                    message: format!(
                        "min_disk '{s}' exceeds the {} TiB upper limit",
                        crbs_core::build_options::MAX_REQ_MIN_DISK_KB / (1024 * 1024 * 1024)
                    ),
                }
                .into());
            }
            Some(kb)
        }
        None => None,
    };
    if let Some(n) = input.min_ncpu {
        if n == 0 || n > crbs_core::build_options::MAX_REQ_MIN_NCPU {
            return Err(crbs_core::error::CrbsError::ValidationFailed {
                message: format!(
                    "min_ncpu must be 1..={}, got: {n}",
                    crbs_core::build_options::MAX_REQ_MIN_NCPU
                ),
            }
            .into());
        }
    }
    Ok((mem, input.min_ncpu.map(i64::from), disk))
}

async fn list_profiles(target: &RemoteTarget, product: &str, format: OutputFormat) -> Result<()> {
    crbs_core::validation::validate_product(product)?;
    let url = format!(
        "{}/api/v1/resource-profiles?product={}",
        target.url,
        urlencoding::encode(product)
    );
    let parsed: serde_json::Value = crate::remote::remote_send_json(
        target,
        reqwest::Method::GET,
        |client| client.get(&url),
        None,
        None,
    )
    .await?;
    let total = parsed["total"].as_i64().unwrap_or(0);
    format.print(&ProfileListOutput {
        product,
        total,
        value: &parsed,
    })?;
    Ok(())
}

async fn set_profile(
    target: &RemoteTarget,
    product: &str,
    source: &str,
    arch: &str,
    input: FloorInput,
    format: OutputFormat,
) -> Result<()> {
    crbs_core::validation::validate_product(product)?;
    let (mem_kb, ncpu, disk_kb) = parse_floor(&input)?;
    if mem_kb.is_none() && ncpu.is_none() && disk_kb.is_none() {
        // set 语义是"写声明"：至少一维，纯清空走 unset（否则 PUT 全 None 与
        // unset 行为重合，命令语义含糊）。
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: "at least one of --min-mem / --min-ncpu / --min-disk is required \
                      (to clear a declaration use 'resource-profile unset')"
                .to_string(),
        }
        .into());
    }
    let url = profile_url(&target.url, product, source, arch);
    let body = serde_json::json!({
        "min_mem_kb": mem_kb,
        "min_ncpu": ncpu,
        "min_disk_kb": disk_kb,
    });
    let client = target.client().await?;
    let resp =
        crate::remote::retry_http("resource_profile_set", reqwest::Method::PUT, None, || {
            client.put(&url).json(&body)
        })
        .await?;
    if !resp.status.is_success() {
        return Err(crate::remote::http_status_error(
            "resource_profile_set",
            resp.status,
            &resp.body,
        )
        .into());
    }
    format.print(&ProfileSetOutput {
        product,
        source,
        arch,
        min_mem: input.min_mem.as_deref(),
        min_ncpu: input.min_ncpu,
        min_disk: input.min_disk.as_deref(),
    })?;
    Ok(())
}

async fn unset_profile(
    target: &RemoteTarget,
    product: &str,
    source: &str,
    arch: &str,
    format: OutputFormat,
) -> Result<()> {
    crbs_core::validation::validate_product(product)?;
    let url = profile_url(&target.url, product, source, arch);
    let client = target.client().await?;
    let resp = crate::remote::retry_http(
        "resource_profile_unset",
        reqwest::Method::DELETE,
        None,
        || client.delete(&url),
    )
    .await?;
    if !resp.status.is_success() {
        return Err(crate::remote::http_status_error(
            "resource_profile_unset",
            resp.status,
            &resp.body,
        )
        .into());
    }
    format.print(&ProfileUnsetOutput {
        product,
        source,
        arch,
    })?;
    Ok(())
}

async fn export_profiles(
    target: &RemoteTarget,
    product: &str,
    file: Option<std::path::PathBuf>,
) -> Result<()> {
    crbs_core::validation::validate_product(product)?;
    let url = format!(
        "{}/api/v1/resource-profiles?product={}",
        target.url,
        urlencoding::encode(product)
    );
    let parsed: serde_json::Value = crate::remote::remote_send_json(
        target,
        reqwest::Method::GET,
        |client| client.get(&url),
        None,
        None,
    )
    .await?;
    // 行 schema = 服务端画像行全列（含样本数 learned_samples 与末次样本核数
    // learned_sample_ncpu——外部工具按并行度归一声明值的依据）。
    let doc = serde_json::json!({
        "version": 2,
        "product": product,
        "resource_profiles": parsed["profiles"].clone(),
    });
    let text = serde_json::to_string_pretty(&doc)?;
    match file {
        Some(path) => {
            std::fs::write(&path, text + "\n")?;
            eprintln!(
                "Exported resource profiles of '{product}' to {}",
                path.display()
            );
        }
        None => println!("{text}"),
    }
    Ok(())
}

async fn import_profiles(target: &RemoteTarget, file: &str, format: OutputFormat) -> Result<()> {
    let text = if file == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(file)?
    };
    let doc: ProfileImportDoc =
        serde_json::from_str(&text).map_err(|e| crbs_core::error::CrbsError::ValidationFailed {
            message: format!("invalid import document {file}: {e}"),
        })?;
    let product = doc.product.clone();
    let client = target.client().await?;
    let mut imported = 0u64;
    for row in doc.resource_profiles.iter().flatten() {
        let source = row["source_name"].as_str().unwrap_or_default();
        let arch = row["arch"].as_str().unwrap_or_default();
        if source.is_empty() || arch.is_empty() {
            return Err(crbs_core::error::CrbsError::ValidationFailed {
                message: format!(
                    "import document row missing source_name/arch for product '{product}'"
                ),
            }
            .into());
        }
        let url = profile_url(&target.url, &product, source, arch);
        let body = serde_json::json!({
            "min_mem_kb": row["declared_min_mem_kb"],
            "min_ncpu": row["declared_min_ncpu"],
            "min_disk_kb": row["declared_min_disk_kb"],
        });
        let resp = crate::remote::retry_http(
            "resource_profile_import",
            reqwest::Method::PUT,
            None,
            || client.put(&url).json(&body),
        )
        .await?;
        if !resp.status.is_success() {
            // 报错附当前行键：逐行生效非事务，失败停在那一行，按键定位补传。
            let op = format!("resource_profile_import {product}/{source}/{arch}");
            return Err(crate::remote::http_status_error(&op, resp.status, &resp.body).into());
        }
        imported += 1;
    }
    format.print(&ProfileImportOutput {
        product: &product,
        imported,
    })?;
    Ok(())
}

fn profile_url(base: &str, product: &str, source: &str, arch: &str) -> String {
    format!(
        "{}/api/v1/resource-profiles/{}/{}/{}",
        base,
        urlencoding::encode(product),
        urlencoding::encode(source),
        urlencoding::encode(arch)
    )
}

// ===== 输出信封（json_error_contract 命令名 = "admin resource-profile ..."）=====

struct ProfileListOutput<'a> {
    product: &'a str,
    total: i64,
    value: &'a serde_json::Value,
}

impl CommandOutput for ProfileListOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "command": "admin resource-profile list",
            "product": self.product,
            "total": self.total,
            "resource_profiles": self.value["profiles"].clone(),
        }))?)
    }

    fn print_text(&self) {
        let rows = self
            .value
            .get("profiles")
            .and_then(|v| v.as_array())
            .map(|a| a.as_slice())
            .unwrap_or_default();
        if rows.is_empty() {
            println!("No resource profiles for '{}'.", self.product);
            return;
        }
        let mut table: Vec<[String; 8]> = vec![[
            "Source pkg",
            "Arch",
            "Declared (mem/ncpu/disk)",
            "EMA/Max Mem",
            "EMA/Max tmpfs",
            "EMA ncpu",
            "Samples",
            "State",
        ]
        .map(str::to_string)];
        for row in rows {
            let declared = format_declared(row);
            let ema = row["learned_ema_mem_kb"]
                .as_i64()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into());
            let max = row["learned_max_mem_kb"]
                .as_i64()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into());
            let kb_text = |key: &str| {
                row[key]
                    .as_i64()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into())
            };
            let tmpfs_text = format!(
                "{}/{}",
                kb_text("learned_ema_tmpfs_kb"),
                kb_text("learned_max_tmpfs_kb")
            );
            let ema_ncpu = row["learned_ema_ncpu"].as_f64();
            let ncpu_text = match (ema_ncpu, row["learned_sample_ncpu"].as_i64()) {
                (Some(v), Some(n)) => format!("{v:.1}@{n}C"),
                (Some(v), None) => format!("{v:.1}"),
                (None, _) => "-".into(),
            };
            let state = if row["learned_censored"].as_bool() == Some(true) {
                "censored"
            } else {
                "ok"
            };
            table.push([
                row["source_name"].as_str().unwrap_or("-").to_string(),
                row["arch"].as_str().unwrap_or("-").to_string(),
                declared,
                format!("{ema}/{max}"),
                tmpfs_text,
                ncpu_text,
                row["learned_samples"].as_i64().unwrap_or(0).to_string(),
                state.to_string(),
            ]);
        }
        print!("{}", render_table(&table));
    }
}

/// 逐列按实际内容算宽后渲染（左对齐，Samples 列右对齐）。KB 原始值
/// （如 `1048576/2097152`）超过旧静态列宽会串列，不能写死宽度。
fn render_table(table: &[[String; 8]]) -> String {
    const SAMPLES_COL: usize = 6;
    let mut widths = [0usize; 8];
    for row in table {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for row in table {
        let mut line = String::new();
        for (i, cell) in row.iter().enumerate() {
            if i > 0 {
                line.push_str("  ");
            }
            let width = widths[i];
            if i == SAMPLES_COL {
                line.push_str(&format!("{cell:>width$}"));
            } else {
                line.push_str(&format!("{cell:<width$}"));
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// declared 三维紧凑串（KB 值带 K 后缀如 "8388608K/4/-"；全空 = "-"）。
fn format_declared(row: &serde_json::Value) -> String {
    let mem = row["declared_min_mem_kb"].as_i64();
    let ncpu = row["declared_min_ncpu"].as_i64();
    let disk = row["declared_min_disk_kb"].as_i64();
    if mem.is_none() && ncpu.is_none() && disk.is_none() {
        return "-".into();
    }
    let kb_text = |v: Option<i64>| v.map(|x| format!("{x}K")).unwrap_or_else(|| "-".into());
    format!(
        "{}/{}/{}",
        kb_text(mem),
        ncpu.map(|x| x.to_string()).unwrap_or_else(|| "-".into()),
        kb_text(disk)
    )
}

struct ProfileSetOutput<'a> {
    product: &'a str,
    source: &'a str,
    arch: &'a str,
    min_mem: Option<&'a str>,
    min_ncpu: Option<u32>,
    min_disk: Option<&'a str>,
}

impl CommandOutput for ProfileSetOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "command": "admin resource-profile set",
            "product": self.product,
            "source": self.source,
            "arch": self.arch,
            "min_mem": self.min_mem,
            "min_ncpu": self.min_ncpu,
            "min_disk": self.min_disk,
            "set": true,
        }))?)
    }

    fn print_text(&self) {
        let mem = self.min_mem.unwrap_or("-");
        let ncpu = self
            .min_ncpu
            .map(|n| n.to_string())
            .unwrap_or_else(|| "-".into());
        let disk = self.min_disk.unwrap_or("-");
        println!(
            "Declared placement floor for {}/{}/{}: min_mem={} min_ncpu={} min_disk={}",
            self.product, self.source, self.arch, mem, ncpu, disk
        );
    }
}

struct ProfileUnsetOutput<'a> {
    product: &'a str,
    source: &'a str,
    arch: &'a str,
}

impl CommandOutput for ProfileUnsetOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "command": "admin resource-profile unset",
            "product": self.product,
            "source": self.source,
            "arch": self.arch,
            "unset": true,
        }))?)
    }

    fn print_text(&self) {
        println!(
            "Cleared declared placement floor for {}/{}/{} (learned profile data kept)",
            self.product, self.source, self.arch
        );
    }
}

struct ProfileImportOutput<'a> {
    product: &'a str,
    imported: u64,
}

impl CommandOutput for ProfileImportOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "command": "admin resource-profile import",
            "product": self.product,
            "imported": self.imported,
        }))?)
    }

    fn print_text(&self) {
        println!(
            "Imported {} declared floor(s) for '{}'",
            self.imported, self.product
        );
    }
}

#[cfg(test)]
mod tests {
    use super::render_table;

    /// 宽 KB 值（15+ 字符）不得把后续列顶出对齐：所有列的起始偏移在
    /// 各行一致；Samples 列右对齐。
    #[test]
    fn render_table_keeps_columns_aligned_for_wide_cells() {
        let row = |source: &str, ema_max: &str| {
            [
                source.to_string(),
                "x86_64".to_string(),
                "1048576K/4/68719476736K".to_string(),
                ema_max.to_string(),
                "524288/1048576".to_string(),
                "4.0@16C".to_string(),
                "42".to_string(),
                "censored".to_string(),
            ]
        };
        let out = render_table(&[
            row("short", "1/2"),
            row("a-much-longer-source-package", "1048576/2097152"),
        ]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "{out}");
        for marker in [
            "x86_64",
            "1048576K/4/68719476736K",
            "524288/1048576",
            "4.0@16C",
            "censored",
        ] {
            let col = lines[0]
                .find(marker)
                .unwrap_or_else(|| panic!("{marker} missing:\n{out}"));
            assert_eq!(
                lines[1].find(marker),
                Some(col),
                "column '{marker}' misaligned:\n{out}"
            );
        }
        assert_eq!(
            lines[0].find("42"),
            lines[1].find("42"),
            "samples column must be right-aligned:\n{out}"
        );
    }
}
