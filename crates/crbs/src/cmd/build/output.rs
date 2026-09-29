// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

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

#[derive(serde::Serialize)]
pub(crate) struct DetachOutput {
    pub command: &'static str,
    pub mode: &'static str,

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

#[cfg(test)]
/// crbs build --detach 的统一 JSON schema（direct/daemon/remote 三路由同构，同命令同标志键集一致）。子构建条目各带 task_id。
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
    pub environment_packages: usize,

    pub restored_packages: usize,

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

/// 错误信封的纯构造函数。schema：顶层恰为 {command, outcome, error:{code, message}}；command 取实际 CLI 命令名（按 command
/// 分流的消费者依赖），outcome 恒 "error"。
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

pub(crate) fn print_json_error_envelope(
    command: &'static str,
    code: &str,
    message: &str,
) -> anyhow::Result<()> {
    print_json(&json_error_envelope(command, code, message))
}

pub(crate) fn maybe_json_error_exit(
    command: &'static str,
    e: &anyhow::Error,
    format: &OutputFormat,
) -> anyhow::Result<()> {
    if let Some(CrbsError::SilentExit { code }) = e.downcast_ref::<CrbsError>() {
        return Err(CrbsError::SilentExit { code: *code }.into());
    }
    if *format == OutputFormat::Json {
        let code = if let Some(ce) = e.downcast_ref::<CrbsError>() {
            print_json_error_envelope(command, ce.code(), &ce.to_string())?;
            crbs_core::exit_code::crbs_error_exit_code(ce)
        } else {
            print_json_error_envelope(command, "internal_error", &e.to_string())?;
            crbs_core::exit_code::INTERNAL
        };
        return Err(CrbsError::SilentExit { code }.into());
    }
    Ok(())
}

pub(crate) async fn print_json_summary(params: SummaryOutputParams<'_>) -> anyhow::Result<()> {
    let output = BuildSummaryOutput::new(params).await?;
    print_json(&output.to_json_build_output())
}

pub(crate) fn json_reproduce_task_envelope(
    task_id: i64,
    builds: &[JsonReproduceOutput],
) -> serde_json::Value {
    serde_json::json!({ "command": "build", "task_id": task_id, "builds": builds })
}

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
