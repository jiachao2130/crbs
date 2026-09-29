// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建摘要输出：文本表格、JSON 信封与失败分组。

use crate::cli::{CommandOutput, OutputFormat};
use crbs_core::error::CrbsError;
use std::time::Duration;
use tracing::warn;

use super::summary::{group_failures, FailureBucket};
use super::BuildSummary;
use std::collections::HashMap;

#[derive(serde::Serialize)]
struct JsonPackageResult {
    srpm: String,
    build_id: Option<i64>,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<JsonProfileSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retries: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signed: Option<bool>,
}

#[derive(Clone, serde::Serialize)]
struct JsonProfileSummary {
    slowest_phase: String,
    slowest_phase_seconds: f64,
    shared_layer_hit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ccache_hit_rate: Option<f64>,
}

#[derive(serde::Serialize)]
struct JsonError {
    code: String,
    message: String,
}

#[derive(serde::Serialize)]
struct JsonBuildSummary {
    total: usize,
    succeeded: usize,
    failed: usize,
    cancelled: usize,
    timeout: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    cached: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dep_skipped: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cycle_failed: Option<usize>,
    // PR-B：chain 元数据 + 失败分桶，全 `Option` + `skip_serializing_if`——
    // 单包 build 路径不填，旧 schema consumer 仍按 total/succeeded/failed 工作。
    #[serde(skip_serializing_if = "Option::is_none")]
    wall_time_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rounds: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parallelism: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovered: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_by_reason: Option<Vec<JsonFailureBucket>>,
}

/// PR-B：JSON (code, phase) 失败桶；phase 值与 `ScriptPhase::as_str()` 对齐（snake_case）。
#[derive(serde::Serialize)]
struct JsonFailureBucket {
    code: &'static str,
    phase: &'static str,
    count: usize,
    sample_message: String,
    sample_packages: Vec<String>,
}

impl From<&FailureBucket> for JsonFailureBucket {
    fn from(b: &FailureBucket) -> Self {
        Self {
            code: b.code,
            phase: b.phase.as_str(),
            count: b.count,
            sample_message: b.sample_message.clone(),
            sample_packages: b.sample_packages.clone(),
        }
    }
}

#[derive(serde::Serialize)]
struct JsonBuildOutput {
    command: &'static str,
    product: String,
    outcome: &'static str,
    summary: JsonBuildSummary,
    packages: Vec<JsonPackageResult>,
}

/// build 命令 summary 统一输出（JSON 依赖预读的 profile 数据，text 复用 workers::print_summary）。
pub(crate) struct BuildSummaryOutput<'a> {
    product: &'a str,
    summary: &'a BuildSummary,
    profile_summaries: HashMap<i64, JsonProfileSummary>,
    cached: Option<usize>,
    dep_skipped: Option<usize>,
    cycle_failed: Option<usize>,
    wall_time: Option<Duration>,
    rounds: Option<usize>,
    parallelism: Option<usize>,
    recovered: Option<usize>,
}

/// build summary 输出元数据包。单包 build 路径 chain 字段全传 `None`（JSON 经
/// `skip_serializing_if` 省略，旧 consumer 不受影响）。
pub(crate) struct SummaryOutputParams<'a> {
    pub(crate) product: &'a str,
    pub(crate) summary: &'a BuildSummary,
    pub(crate) cached: Option<usize>,
    pub(crate) dep_skipped: Option<usize>,
    pub(crate) cycle_failed: Option<usize>,
    pub(crate) wall_time: Option<Duration>,
    pub(crate) rounds: Option<usize>,
    pub(crate) parallelism: Option<usize>,
    pub(crate) recovered: Option<usize>,
}

impl<'a> SummaryOutputParams<'a> {
    /// 单包 build 路径构造器：chain-only 元数据全 `None`（JSON 经
    /// `skip_serializing_if` 省略，旧 consumer 不受影响）。
    pub(crate) fn plain(product: &'a str, summary: &'a BuildSummary) -> Self {
        Self {
            product,
            summary,
            cached: None,
            dep_skipped: None,
            cycle_failed: None,
            wall_time: None,
            rounds: None,
            parallelism: None,
            recovered: None,
        }
    }
}

impl<'a> BuildSummaryOutput<'a> {
    pub(crate) async fn new(params: SummaryOutputParams<'a>) -> anyhow::Result<Self> {
        let SummaryOutputParams {
            product,
            summary,
            cached,
            dep_skipped,
            cycle_failed,
            wall_time,
            rounds,
            parallelism,
            recovered,
        } = params;
        let mut profile_summaries = HashMap::new();
        for (_, outputs, _) in &summary.succeeded {
            match crbs_core::engine::profile::read_profile(&outputs.result_dir).await {
                Ok(Some(profile)) => {
                    if let Some((name, seconds)) = profile.slowest_phase() {
                        profile_summaries.insert(
                            outputs.build_id,
                            JsonProfileSummary {
                                slowest_phase: name.to_string(),
                                slowest_phase_seconds: seconds,
                                shared_layer_hit: profile.shared_layer_hit,
                                ccache_hit_rate: profile.ccache.as_ref().map(|c| c.hit_rate),
                            },
                        );
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(
                        build_id = %outputs.build_id,
                        error = %e,
                        "read profile.json for JSON summary failed"
                    );
                }
            }
        }
        Ok(Self {
            product,
            summary,
            profile_summaries,
            cached,
            dep_skipped,
            cycle_failed,
            wall_time,
            rounds,
            parallelism,
            recovered,
        })
    }

    fn outcome(&self) -> &'static str {
        if self.summary.failed.is_empty()
            && self.summary.cancelled.is_empty()
            && self.summary.timeout.is_empty()
        {
            "succeeded"
        } else {
            "failed"
        }
    }

    fn to_json_build_output(&self) -> JsonBuildOutput {
        let mut packages = Vec::new();
        for (srpm, outputs, duration) in &self.summary.succeeded {
            packages.push(JsonPackageResult {
                srpm: srpm.display().to_string(),
                build_id: Some(outputs.build_id),
                outcome: "succeeded",
                duration_seconds: Some(*duration),
                result_dir: Some(outputs.result_dir.display().to_string()),
                error: None,
                profile: self.profile_summaries.get(&outputs.build_id).cloned(),
                retries: Some(outputs.retries),
                signed: Some(outputs.signed),
            });
        }
        for (srpm, e, duration) in &self.summary.failed {
            packages.push(JsonPackageResult {
                srpm: srpm.display().to_string(),
                build_id: None,
                outcome: "failed",
                duration_seconds: Some(*duration),
                result_dir: None,
                error: Some(JsonError {
                    code: e.code().to_string(),
                    message: e.to_string(),
                }),
                profile: None,
                retries: None,
                signed: None,
            });
        }
        for (srpm, e, duration) in &self.summary.cancelled {
            packages.push(JsonPackageResult {
                srpm: srpm.display().to_string(),
                build_id: None,
                outcome: "cancelled",
                duration_seconds: Some(*duration),
                result_dir: None,
                error: Some(JsonError {
                    code: e.code().to_string(),
                    message: e.to_string(),
                }),
                profile: None,
                retries: None,
                signed: None,
            });
        }
        for (srpm, e, duration) in &self.summary.timeout {
            packages.push(JsonPackageResult {
                srpm: srpm.display().to_string(),
                build_id: None,
                outcome: "timeout",
                duration_seconds: Some(*duration),
                result_dir: None,
                error: Some(JsonError {
                    code: e.code().to_string(),
                    message: e.to_string(),
                }),
                profile: None,
                retries: None,
                signed: None,
            });
        }

        JsonBuildOutput {
            command: "build",
            product: self.product.to_string(),
            outcome: self.outcome(),
            summary: JsonBuildSummary {
                total: self.summary.succeeded.len()
                    + self.summary.failed.len()
                    + self.summary.cancelled.len()
                    + self.summary.timeout.len(),
                succeeded: self.summary.succeeded.len(),
                failed: self.summary.failed.len(),
                cancelled: self.summary.cancelled.len(),
                timeout: self.summary.timeout.len(),
                cached: self.cached,
                dep_skipped: self.dep_skipped,
                cycle_failed: self.cycle_failed,
                wall_time_seconds: self.wall_time.map(|d| d.as_secs()),
                rounds: self.rounds,
                parallelism: self.parallelism,
                recovered: self.recovered,
                failed_by_reason: if self.wall_time.is_some() {
                    // 仅在 chain 路径填充（wall_time 存在 ⇒ chain）。
                    Some(
                        group_failures(
                            &self.summary.failed,
                            &self.summary.cancelled,
                            &self.summary.timeout,
                        )
                        .iter()
                        .map(JsonFailureBucket::from)
                        .collect(),
                    )
                } else {
                    None
                },
            },
            packages,
        }
    }
}

impl CommandOutput for BuildSummaryOutput<'_> {
    fn to_json(&self) -> anyhow::Result<String> {
        serde_json::to_string_pretty(&self.to_json_build_output()).map_err(|_e| {
            CrbsError::SilentExit {
                code: crbs_core::exit_code::INTERNAL,
            }
            .into()
        })
    }

    fn print_text(&self) {
        crate::cmd::build::workers::print_summary(self.summary);
    }
}

#[derive(serde::Serialize)]
pub(crate) struct JsonChainPlan {
    pub command: &'static str,
    pub mode: &'static str,
    pub product: String,
    pub outcome: &'static str,
    pub rounds: Vec<Vec<String>>,
    pub cached: Vec<String>,
    pub cycle_failed: Vec<String>,
}

/// `crbs build --detach` 的统一 JSON schema（direct/daemon/remote 三路由同构，
/// 同命令同旗标不因 `daemon_auto` 配置漂移键集）。子构建条目各带 `task_id`：
/// direct 每个 SRPM 一条本地任务行、remote/daemon 整批共享，顶层取首个子构建 task。
#[derive(serde::Serialize)]
pub(crate) struct DetachOutput {
    pub command: &'static str,
    pub mode: &'static str,
    /// "direct" | "daemon" | "remote"
    pub transport: &'static str,
    pub product: String,
    pub task_id: i64,
    pub builds: Vec<DetachBuildEntry>,
}

#[derive(serde::Serialize)]
pub(crate) struct DetachBuildEntry {
    pub build_id: i64,
    pub task_id: i64,
    pub pkg_name: String,
}

/// 三路由共用的 schema 钉：顶层键集恰 {command, mode, transport, product, task_id, builds}、
/// 子构建条目键集恰 {build_id, task_id, pkg_name}，`mode` 恒 `"detach"`（防键集漂移）。
#[cfg(test)]
pub(crate) fn assert_detach_envelope(value: &serde_json::Value, transport: &str) {
    let obj = value
        .as_object()
        .expect("detach envelope must be an object");
    let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "builds",
            "command",
            "mode",
            "product",
            "task_id",
            "transport"
        ],
        "detach envelope key set drifted: {value}"
    );
    assert_eq!(obj["command"], "build");
    assert_eq!(obj["mode"], "detach", "mode must be unified to \"detach\"");
    assert_eq!(obj["transport"], transport);
    for entry in obj["builds"].as_array().expect("builds must be an array") {
        let mut entry_keys: Vec<&str> = entry
            .as_object()
            .expect("build entry must be an object")
            .keys()
            .map(|k| k.as_str())
            .collect();
        entry_keys.sort_unstable();
        assert_eq!(
            entry_keys,
            vec!["build_id", "pkg_name", "task_id"],
            "build entry key set drifted: {entry}"
        );
    }
}

#[derive(serde::Serialize)]
pub(crate) struct JsonReproduceVerification {
    /// 原始构建记录的环境包总数（base_os + builddep）。
    pub environment_packages: usize,
    /// 从 package cache 按 SHA256 内容寻址恢复到临时 repo 的包数。
    pub restored_packages: usize,
    /// 本次重新构建产出的 RPM 数（仅计数，不做字节级比对）。
    pub produced_rpms: usize,
}

#[derive(serde::Serialize)]
pub(crate) struct JsonReproduceOutput {
    pub command: &'static str,
    pub mode: &'static str,
    pub reproduce_build_id: i64,
    pub outcome: &'static str,
    pub result_dir: String,
    pub verification: JsonReproduceVerification,
}

/// 错误信封的纯构造函数。schema：顶层恰为 `{command, outcome, error:{code, message}}`；
/// `command` 取实际 CLI 命令名（按 command 分流的消费者依赖），`outcome` 恒 `"error"`。
pub(crate) fn json_error_envelope(
    command: &'static str,
    code: &str,
    message: &str,
) -> serde_json::Value {
    serde_json::json!({
        "command": command,
        "outcome": "error",
        "error": { "code": code, "message": message },
    })
}

/// 通用 JSON 序列化到 stdout。
pub(crate) fn print_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    match serde_json::to_string_pretty(value) {
        Ok(json) => {
            println!("{}", json);
            Ok(())
        }
        Err(e) => {
            eprintln!("Error serializing JSON output: {}", e);
            Err(CrbsError::SilentExit {
                code: crbs_core::exit_code::INTERNAL,
            }
            .into())
        }
    }
}

/// 在 --format json 模式下输出错误信封到 stdout 并返回（不退出，由调用方决定退出码）。
pub(crate) fn print_json_error_envelope(
    command: &'static str,
    code: &str,
    message: &str,
) -> anyhow::Result<()> {
    print_json(&json_error_envelope(command, code, message))
}

/// --format json 模式下把错误输出为 JSON 信封并返回 SilentExit；text 模式直接
/// 返回由调用方继续传播。`command` 是实际 CLI 命令名（信封字段语义见 [`json_error_envelope`]）。
pub(crate) fn maybe_json_error_exit(
    command: &'static str,
    e: &anyhow::Error,
    format: &OutputFormat,
) -> anyhow::Result<()> {
    // SilentExit = 内层已打印过错误信封/摘要（batch/reproduce/chain 失败路径
    // 用它退出），再打会输出第二个 JSON 文档破坏 CI 按 error.code 解析契约，原样透传。
    if let Some(CrbsError::SilentExit { code }) = e.downcast_ref::<CrbsError>() {
        return Err(CrbsError::SilentExit { code: *code }.into());
    }
    if *format == OutputFormat::Json {
        let code = if let Some(ce) = e.downcast_ref::<CrbsError>() {
            print_json_error_envelope(command, ce.code(), &ce.to_string())?;
            crbs_core::exit_code::crbs_error_exit_code(ce)
        } else {
            // 非 CrbsError = anyhow 内部错误（IO/序列化 bug 等），归
            // internal_error（与 core code() 对 Internal 的串一致）而非 validation。
            print_json_error_envelope(command, "internal_error", &e.to_string())?;
            crbs_core::exit_code::INTERNAL
        };
        return Err(CrbsError::SilentExit { code }.into());
    }
    Ok(())
}

/// 将 BuildSummary 序列化为 JSON 并打印到 stdout；仅供仅需 JSON 输出的调用方，
/// 需同时支持 text 的路径用 `BuildSummaryOutput` + `OutputFormat::print`。
pub(crate) async fn print_json_summary(params: SummaryOutputParams<'_>) -> anyhow::Result<()> {
    let output = BuildSummaryOutput::new(params).await?;
    print_json(&output.to_json_build_output())
}

/// task 域聚合 reproduce 的 JSON envelope（`--format json` 唯一输出文档）：
/// `{"command": "build", "task_id": <id>, "builds": [<单构建 JSON 对象>...]}`，
/// `command` 与错误信封同源。纯构造函数，子构建对象复用 [`JsonReproduceOutput`]。
pub(crate) fn json_reproduce_task_envelope(
    task_id: i64,
    builds: &[JsonReproduceOutput],
) -> serde_json::Value {
    serde_json::json!({ "command": "build", "task_id": task_id, "builds": builds })
}

/// 打印 task 域聚合 reproduce 的唯一 JSON 文档。契约：`--format json` 恰输出一个
/// 文档（jq 单文档消费者依赖），中途失败时已完成者照常进数组、错误走 stderr。
pub(crate) fn print_json_reproduce_task(
    task_id: i64,
    builds: &[JsonReproduceOutput],
) -> crbs_core::Result<()> {
    print_json(&json_reproduce_task_envelope(task_id, builds)).map_err(|e| {
        e.downcast_ref::<CrbsError>()
            .cloned()
            .unwrap_or_else(|| CrbsError::io_message(e.to_string()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repro_output(build_id: i64) -> JsonReproduceOutput {
        JsonReproduceOutput {
            command: "build",
            mode: "reproduce",
            reproduce_build_id: build_id,
            outcome: "succeeded",
            result_dir: format!("/tmp/results/{build_id}"),
            verification: JsonReproduceVerification {
                environment_packages: 10,
                restored_packages: 10,
                produced_rpms: 2,
            },
        }
    }

    /// task 域 --format json 契约：envelope 恰 {command, task_id, builds} 三键、子构建原样进数组。
    #[test]
    fn json_reproduce_task_envelope_shape() {
        let env = json_reproduce_task_envelope(7, &[repro_output(71), repro_output(72)]);
        assert_eq!(env.get("command"), Some(&serde_json::json!("build")));
        assert_eq!(env.get("task_id"), Some(&serde_json::json!(7)));
        let builds = env
            .get("builds")
            .and_then(|b| b.as_array())
            .expect("builds must be an array");
        assert_eq!(builds.len(), 2);
        assert_eq!(builds[0]["reproduce_build_id"], serde_json::json!(71));
        assert_eq!(builds[1]["reproduce_build_id"], serde_json::json!(72));
        let mut keys: Vec<&str> = env
            .as_object()
            .expect("envelope must be an object")
            .keys()
            .map(|k| k.as_str())
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["builds", "command", "task_id"]);
    }

    /// 空任务（无已完成子构建）仍是合法单文档：builds 为空数组。
    #[test]
    fn json_reproduce_task_envelope_empty_builds() {
        let env = json_reproduce_task_envelope(3, &[]);
        assert_eq!(
            env.get("builds")
                .and_then(|b| b.as_array())
                .map(|a| a.len()),
            Some(0)
        );
    }

    /// 错误信封契约：顶层恰 {command, outcome, error} 三键，`command` 取传入值、`outcome` 恒 "error"。
    #[test]
    fn json_error_envelope_carries_actual_command_and_error_outcome() {
        for command in ["build", "verify", "status", "builds show"] {
            let env = json_error_envelope(command, "not_found", "task 9 not found");
            let mut keys: Vec<&str> = env
                .as_object()
                .expect("envelope must be an object")
                .keys()
                .map(|k| k.as_str())
                .collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                vec!["command", "error", "outcome"],
                "envelope key set drifted: {env}"
            );
            assert_eq!(env["command"], command, "command must pass through");
            assert_eq!(
                env["outcome"], "error",
                "error envelope outcome must be fixed to \"error\""
            );
            assert_eq!(env["error"]["code"], "not_found");
            assert_eq!(env["error"]["message"], "task 9 not found");
        }
    }
}
