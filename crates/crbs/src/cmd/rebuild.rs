// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2/
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs rebuild` 命令组：服务端整仓重建批次（**仅远程**形态）。
//!
//! 子命令：submit（提交 / dry-run 预览）、status（详情 / --follow 轮询）、
//! cancel（取消）。错误净化与退出码走 remote 模块既有契约
//! （`remote_send_json` → `http_status_error` → `crbs_error_exit_code`）。

use anyhow::Result;
use crbs_core::error::CrbsError;
use std::io::IsTerminal;

use crate::cli::{OutputFormat, RebuildCommand};
use crate::remote::{remote_send_json, RemoteTarget};

/// rebuild 命令组参数（父级 remote/token/local 旗标已并入）。
pub(crate) struct RebuildArgs {
    pub(crate) command: RebuildCommand,
    pub(crate) remote: Option<String>,
    pub(crate) token: Option<String>,
    pub(crate) local: bool,
}

// ---------- 服务端响应类型 ----------

#[derive(Debug, serde::Deserialize)]
struct SubmitResponse {
    batch_id: i64,
    status: String,
}

#[derive(Debug, serde::Deserialize)]
struct DryRunResponse {
    product: String,
    to_build_count: usize,
    to_build: Vec<String>,
    skipped_count: usize,
    skipped: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BatchSummaryDto {
    id: i64,
    product: String,
    status: String,
    total_items: i64,
    n_succeeded: i64,
    n_failed: i64,
    n_skipped: i64,
    n_cancelled: i64,
    created_at: String,
    finished_at: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct BatchListResponse {
    batches: Vec<BatchSummaryDto>,
}

/// 详情的项状态计数（CLI 只消费在途两项；终态计数走 summary 的 n_*，
/// 服务端多出的字段 serde 默认忽略）。
#[derive(Debug, serde::Deserialize)]
struct ProgressDto {
    pending: i64,
    released: i64,
}

#[derive(Debug, serde::Deserialize)]
struct RoundDto {
    round: i64,
    total: usize,
    pending: usize,
    released: usize,
    succeeded: usize,
    failed: usize,
    skipped: usize,
    cancelled: usize,
}

#[derive(Debug, serde::Deserialize)]
struct FailureDto {
    error_code: String,
    count: usize,
    sample: String,
}

#[derive(Debug, serde::Deserialize)]
struct BatchDetailDto {
    #[serde(flatten)]
    summary: BatchSummaryDto,
    #[serde(default)]
    dist: Option<String>,
    #[serde(default)]
    arch_targets: Option<Vec<String>>,
    on_failure: String,
    force_all: bool,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    started_at: Option<String>,
    progress: ProgressDto,
    rounds: Vec<RoundDto>,
    #[serde(default)]
    failures: Vec<FailureDto>,
}

#[derive(Debug, serde::Deserialize)]
struct CancelResponse {
    batch_id: i64,
    status: String,
}

// ---------- 入口 ----------

pub(crate) async fn handle_rebuild(args: RebuildArgs) -> Result<()> {
    // 整仓重建编排（枚举/下载/分轮/栅栏）全部发生在 hub 侧，本地无实现。
    let target = crate::remote::resolve(args.remote, args.token, None, args.local)
        .await?
        .ok_or_else(|| CrbsError::ValidationFailed {
            message: "server-side whole-repo rebuild is remote-only; pass \
                           --remote <url|profile> or set remote.default in the config"
                .into(),
        })?;
    match args.command {
        RebuildCommand::Submit { .. } => submit(&target, args.command).await,
        RebuildCommand::Status {
            id,
            latest,
            follow,
            format,
        } => status(&target, id, latest, follow, format).await,
        RebuildCommand::Cancel { id, format } => cancel(&target, id, format).await,
    }
}

// ---------- submit ----------

async fn submit(target: &RemoteTarget, cmd: RebuildCommand) -> Result<()> {
    let RebuildCommand::Submit {
        product,
        repo,
        dist,
        arch,
        force,
        on_failure,
        allow_dist_mismatch,
        dry_run,
        format,
    } = cmd
    else {
        unreachable!("submit is only dispatched for RebuildCommand::Submit")
    };
    let body = serde_json::json!({
        "product": product,
        "source_repo_url": repo,
        "dist": dist,
        "arch_targets": arch,
        "on_failure": on_failure,
        "force_all": force,
        "allow_dist_mismatch": allow_dist_mismatch,
        "dry_run": dry_run,
    });
    let url = format!("{}/api/v1/batches", target.url);

    if dry_run {
        let resp: DryRunResponse = remote_send_json(
            target,
            reqwest::Method::POST,
            |client| client.post(&url).json(&body),
            None,
            None,
        )
        .await?;
        if format == OutputFormat::Json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "command": "rebuild submit",
                    "dry_run": true,
                    "product": resp.product,
                    "to_build_count": resp.to_build_count,
                    "to_build": resp.to_build,
                    "skipped_count": resp.skipped_count,
                    "skipped": resp.skipped,
                }))?
            );
        } else {
            println!("{}", render_dry_run(&resp).trim_end());
        }
        return Ok(());
    }

    let resp: SubmitResponse = remote_send_json(
        target,
        reqwest::Method::POST,
        |client| client.post(&url).json(&body),
        None,
        None,
    )
    .await?;
    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "command": "rebuild submit",
                "batch_id": resp.batch_id,
                "status": resp.status,
            }))?
        );
    } else {
        println!(
            "Submitted rebuild batch {} (status: {})",
            resp.batch_id, resp.status
        );
        println!(
            "Track progress: crbs rebuild status --id {} --follow",
            resp.batch_id
        );
    }
    Ok(())
}

/// dry-run 预览表：单表两态（to build / skipped），计数为全量、行集即
/// 服务端截断后的名单（≤200）。返回渲染文本（打印在调用方，可测）。
fn render_dry_run(resp: &DryRunResponse) -> String {
    let mut out = format!(
        "Dry-run preview for product '{}' ({} to build, {} skipped):\n",
        resp.product, resp.to_build_count, resp.skipped_count
    );
    let mut table = crate::cmd::status::new_table_with_style(crate::cmd::status::ansi_allowed(
        std::io::stdout().is_terminal(),
        std::env::var_os("NO_COLOR").as_deref(),
    ));
    table.set_header(vec!["Package", "Result"]);
    for name in &resp.to_build {
        table.add_row(vec![name.as_str(), "build"]);
    }
    for name in &resp.skipped {
        table.add_row(vec![name.as_str(), "skipped (already built)"]);
    }
    out.push_str(&format!("{table}\n"));
    let listed = resp.to_build.len() + resp.skipped.len();
    let total = resp.to_build_count + resp.skipped_count;
    if listed < total {
        out.push_str(&format!(
            "… (+{} more, lists capped at 200 entries)\n",
            total - listed
        ));
    }
    out
}

// ---------- status ----------

/// 批次终态集合（follow 轮询的退出条件）。
fn batch_is_terminal(status: &str) -> bool {
    matches!(status, "completed" | "partial" | "failed" | "cancelled")
}

async fn status(
    target: &RemoteTarget,
    id: Option<i64>,
    latest: bool,
    follow: bool,
    format: OutputFormat,
) -> Result<()> {
    let batch_id = match (id, latest) {
        (Some(id), _) => id,
        // --latest：取列表首行（服务端 id DESC），空列表按未找到报。
        (None, true) => {
            let url = format!("{}/api/v1/batches?limit=1", target.url);
            let list: BatchListResponse = remote_send_json(
                target,
                reqwest::Method::GET,
                |client| client.get(&url),
                None,
                None,
            )
            .await?;
            list.batches
                .first()
                .map(|b| b.id)
                .ok_or_else(|| CrbsError::NotFound {
                    message: "no rebuild batches recorded on the server".into(),
                })?
        }
        (None, false) => unreachable!("clap requires --id or --latest"),
    };

    if follow {
        // json 是单帧快照契约，与清屏重绘的轮询形态互斥（同 logs --follow 口径）。
        if format == OutputFormat::Json {
            return Err(CrbsError::ValidationFailed {
                message: "--format json cannot be used with --follow".into(),
            }
            .into());
        }
        // 轮询刷新（对齐 status --watch 的节流形态：tty 清屏 + 定时重绘）；
        // 批次推进以 tick（秒级）为节奏，5s 采样足够。
        let cancel = crate::cmd::ctrl_c_cancel_token();
        let is_tty = std::io::stdout().is_terminal();
        loop {
            if cancel.is_cancelled() {
                break;
            }
            let detail = fetch_detail(target, batch_id).await?;
            if is_tty {
                print!("\x1B[2J\x1B[1;1H");
            }
            println!("Batch {} (every 5s, Ctrl+C to quit)\n", detail.summary.id);
            print!("{}", render_detail(&detail));
            if batch_is_terminal(&detail.summary.status) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        Ok(())
    } else {
        let detail = fetch_detail(target, batch_id).await?;
        if format == OutputFormat::Json {
            println!("{}", render_detail_json(&detail)?);
        } else {
            print!("{}", render_detail(&detail));
        }
        Ok(())
    }
}

async fn fetch_detail(target: &RemoteTarget, batch_id: i64) -> Result<BatchDetailDto> {
    let url = format!("{}/api/v1/batches/{}", target.url, batch_id);
    let msg = format!("Batch {batch_id} not found");
    remote_send_json(
        target,
        reqwest::Method::GET,
        |client| client.get(&url),
        Some(&msg),
        None,
    )
    .await
}

/// 详情渲染：头部摘要行 + 轮次进度表 + 失败分桶表。返回渲染文本
///（打印在调用方，可测）。
fn render_detail(detail: &BatchDetailDto) -> String {
    let mut out = String::new();
    let s = &detail.summary;
    out.push_str(&format!(
        "Batch {}  product: {}  status: {}\n",
        s.id, s.product, s.status
    ));
    out.push_str(&format!(
        "  items: {} total, {} succeeded, {} failed, {} skipped, {} cancelled\n",
        s.total_items, s.n_succeeded, s.n_failed, s.n_skipped, s.n_cancelled
    ));
    let in_flight = detail.progress.pending + detail.progress.released;
    out.push_str(&format!(
        "  on_failure: {}{}  created: {}  started: {}  finished: {}\n",
        detail.on_failure,
        if detail.force_all {
            "  mode: force-all"
        } else {
            ""
        },
        s.created_at,
        detail.started_at.as_deref().unwrap_or("—"),
        s.finished_at.as_deref().unwrap_or("—")
    ));
    if let Some(dist) = detail.dist.as_deref() {
        out.push_str(&format!("  dist: {dist}\n"));
    }
    if let Some(arches) = detail.arch_targets.as_ref().filter(|a| !a.is_empty()) {
        out.push_str(&format!("  arches: {}\n", arches.join(",")));
    }
    if in_flight > 0 {
        out.push_str(&format!(
            "  in flight: {} pending, {} released\n",
            detail.progress.pending, detail.progress.released
        ));
    }
    if let Some(notes) = detail.notes.as_deref().filter(|n| !n.is_empty()) {
        out.push_str(&format!("  notes: {notes}\n"));
    }

    if !detail.rounds.is_empty() {
        let mut table = crate::cmd::status::new_table_with_style(crate::cmd::status::ansi_allowed(
            std::io::stdout().is_terminal(),
            std::env::var_os("NO_COLOR").as_deref(),
        ));
        table.set_header(vec![
            "Round",
            "Total",
            "Pending",
            "Released",
            "Succeeded",
            "Failed",
            "Skipped",
            "Cancelled",
        ]);
        for r in &detail.rounds {
            table.add_row(vec![
                r.round.to_string(),
                r.total.to_string(),
                r.pending.to_string(),
                r.released.to_string(),
                r.succeeded.to_string(),
                r.failed.to_string(),
                r.skipped.to_string(),
                r.cancelled.to_string(),
            ]);
        }
        out.push_str(&format!("\nRounds:\n{table}\n"));
    }

    if !detail.failures.is_empty() {
        let mut table = crate::cmd::status::new_table_with_style(crate::cmd::status::ansi_allowed(
            std::io::stdout().is_terminal(),
            std::env::var_os("NO_COLOR").as_deref(),
        ));
        table.set_header(vec!["Error code", "Count", "Sample"]);
        for f in &detail.failures {
            table.add_row(vec![
                f.error_code.clone(),
                f.count.to_string(),
                f.sample.clone(),
            ]);
        }
        out.push_str(&format!("\nFailures by error code:\n{table}\n"));
    }
    out
}

/// 详情的 JSON 形态（与 text 渲染同源数据）。batch 内计数脱 `n_` 前缀——
/// 嵌套对象内无歧义、键名自释；时间字段经 RFC3339 规范化（与 status 同构，
/// server 侧朴素 UTC 串无时区标记）。
fn render_detail_json(detail: &BatchDetailDto) -> Result<String> {
    let norm = crate::cmd::status::naive_utc_to_rfc3339;
    let s = &detail.summary;
    let v = serde_json::json!({
        "command": "rebuild status",
        "batch": {
            "id": s.id,
            "product": s.product,
            "status": s.status,
            "total_items": s.total_items,
            "succeeded": s.n_succeeded,
            "failed": s.n_failed,
            "skipped": s.n_skipped,
            "cancelled": s.n_cancelled,
            "created_at": norm(&s.created_at),
            "finished_at": s.finished_at.as_deref().map(norm),
            "started_at": detail.started_at.as_deref().map(norm),
            "dist": detail.dist,
            "arch_targets": detail.arch_targets,
            "on_failure": detail.on_failure,
            "force_all": detail.force_all,
            "notes": detail.notes,
            "in_flight": {
                "pending": detail.progress.pending,
                "released": detail.progress.released,
            },
        },
        "rounds": detail
            .rounds
            .iter()
            .map(|r| serde_json::json!({
                "round": r.round,
                "total": r.total,
                "pending": r.pending,
                "released": r.released,
                "succeeded": r.succeeded,
                "failed": r.failed,
                "skipped": r.skipped,
                "cancelled": r.cancelled,
            }))
            .collect::<Vec<_>>(),
        "failures": detail
            .failures
            .iter()
            .map(|f| serde_json::json!({
                "code": f.error_code,
                "count": f.count,
                "sample": f.sample,
            }))
            .collect::<Vec<_>>(),
    });
    Ok(serde_json::to_string_pretty(&v)?)
}

// ---------- cancel ----------

async fn cancel(target: &RemoteTarget, id: i64, format: OutputFormat) -> Result<()> {
    let url = format!("{}/api/v1/batches/{}/cancel", target.url, id);
    let msg = format!("Batch {id} not found");
    let resp: CancelResponse = remote_send_json(
        target,
        reqwest::Method::POST,
        |client| client.post(&url),
        Some(&msg),
        None,
    )
    .await?;
    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "command": "rebuild cancel",
                "batch_id": resp.batch_id,
                "status": resp.status,
            }))?
        );
    } else {
        println!(
            "Cancelled rebuild batch {} (status: {})",
            resp.batch_id, resp.status
        );
    }
    Ok(())
}

// ---------- 小工具 ----------

#[cfg(test)]
mod tests {
    use super::*;

    fn detail(status: &str) -> BatchDetailDto {
        BatchDetailDto {
            summary: BatchSummaryDto {
                id: 7,
                product: "p".into(),
                status: status.into(),
                total_items: 3,
                n_succeeded: 2,
                n_failed: 1,
                n_skipped: 0,
                n_cancelled: 0,
                created_at: "2026-09-18 00:00:00".into(),
                finished_at: None,
            },
            dist: None,
            arch_targets: None,
            on_failure: "continue".into(),
            force_all: false,
            notes: None,
            started_at: None,
            progress: ProgressDto {
                pending: 0,
                released: 0,
            },
            rounds: vec![RoundDto {
                round: 0,
                total: 3,
                pending: 0,
                released: 0,
                succeeded: 2,
                failed: 1,
                skipped: 0,
                cancelled: 0,
            }],
            failures: vec![FailureDto {
                error_code: "build_failed".into(),
                count: 1,
                sample: "rpmbuild exited 1".into(),
            }],
        }
    }

    /// follow 轮询的退出条件：四个终态退出，在途状态继续轮询。
    #[test]
    fn batch_is_terminal_covers_four_terminal_statuses() {
        for s in ["completed", "partial", "failed", "cancelled"] {
            assert!(batch_is_terminal(s), "{s} must be terminal");
        }
        for s in ["preparing", "planning", "running"] {
            assert!(!batch_is_terminal(s), "{s} must not be terminal");
        }
    }

    /// 详情 JSON 形态钉死：信封 command 键、batch 计数脱 n_ 前缀、轮次与失败
    /// 分桶数组、朴素时间串规范化为 RFC3339 UTC。
    #[test]
    fn render_detail_json_shape() {
        let out = render_detail_json(&detail("partial")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "rebuild status");
        let batch = &v["batch"];
        assert_eq!(batch["id"], 7);
        assert_eq!(batch["succeeded"], 2, "n_succeeded drops the n_ prefix");
        assert_eq!(batch["failed"], 1);
        assert_eq!(batch["in_flight"]["pending"], 0);
        assert_eq!(
            batch["created_at"], "2026-09-18T00:00:00Z",
            "naive UTC string normalized to RFC3339"
        );
        assert_eq!(v["rounds"][0]["round"], 0);
        assert_eq!(v["rounds"][0]["succeeded"], 2);
        assert_eq!(v["failures"][0]["code"], "build_failed");
        assert_eq!(v["failures"][0]["count"], 1);
        assert_eq!(v["failures"][0]["sample"], "rpmbuild exited 1");
    }

    /// 服务端响应形状回归：详情 JSON 可反序列化（flatten + 默认字段）。
    #[test]
    fn detail_dto_parses_server_shape() {
        let raw = serde_json::json!({
            "id": 7, "product": "p", "status": "running",
            "total_items": 3, "n_succeeded": 2, "n_failed": 1,
            "n_skipped": 0, "n_cancelled": 0,
            "created_at": "2026-09-18 00:00:00", "finished_at": null,
            "source_repo_url": "https://r",
            "on_failure": "continue", "force_all": false,
            "progress": {"pending": 0, "released": 1, "succeeded": 2, "failed": 0,
                          "dep_skipped": 0, "skipped_conflict": 0, "arch_skipped": 0,
                          "cancelled": 0},
            "rounds": [{"round": 0, "total": 3, "pending": 0, "released": 1,
                         "succeeded": 2, "failed": 0, "skipped": 0, "cancelled": 0}],
            "failures": []
        });
        let dto: BatchDetailDto = serde_json::from_value(raw).unwrap();
        assert_eq!(dto.summary.id, 7);
        assert_eq!(dto.rounds.len(), 1);
        assert!(dto.dist.is_none() && dto.arch_targets.is_none());
    }

    /// dry-run 渲染：截断提示只在名单被截断时出现。
    #[test]
    fn dry_run_note_appears_only_when_capped() {
        let resp = DryRunResponse {
            product: "p".into(),
            to_build_count: 2,
            to_build: vec!["a".into(), "b".into()],
            skipped_count: 1,
            skipped: vec!["c".into()],
        };
        // 全量名单（未截断）：渲染不包含 "+N more"。
        let out = render_dry_run(&resp);
        assert!(out.contains("2 to build, 1 skipped"), "{out}");
        assert!(!out.contains("more"), "{out}");

        let capped = DryRunResponse {
            product: "p".into(),
            to_build_count: 300,
            to_build: vec!["a".into()],
            skipped_count: 0,
            skipped: vec![],
        };
        let out = render_dry_run(&capped);
        assert!(out.contains("+299 more"), "{out}");
    }

    /// 详情渲染冒烟：状态行 + 轮次表头 + 失败分桶都在输出里。
    #[test]
    fn render_detail_renders_rounds_and_failures() {
        let out = render_detail(&detail("partial"));
        assert!(out.contains("status: partial"), "{out}");
        assert!(out.contains("Rounds:"), "{out}");
        assert!(out.contains("Failures by error code:"), "{out}");
        assert!(out.contains("build_failed"), "{out}");
    }
}
