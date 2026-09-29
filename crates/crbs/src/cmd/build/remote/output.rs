// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 远程构建终态渲染：错误摘要、退出码与下载输出。

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use crate::cli::OutputFormat;
use crate::cmd::build::output;
use crate::cmd::build::workers;
use crate::cmd::build::{BuildOutputs, BuildSummary, DetachBuildEntry, DetachOutput};

use super::make_local_result_dir;

/// [`handle_terminal_record`] 的参数包：连接目标、构建标识、展示格式与下载凭据。
pub(crate) struct TerminalRecordParams<'a> {
    pub(crate) base_url: &'a str,
    pub(crate) build_id: i64,
    pub(crate) pkg_name: &'a str,
    pub(crate) record: &'a crbs_core::BuildRecord,
    pub(crate) format: OutputFormat,
    pub(crate) token: Option<String>,
    pub(crate) ca_cert: Option<PathBuf>,
    pub(crate) cancel_token: Option<&'a CancellationToken>,
}

/// 远端构建非成功终态的失败消息（attach 与 follow 路径共用）。尾部附下一步提示
/// `crbs logs <task_id> --remote (or re-run with --attach)`——远程构建挂在服务端
/// task 下，task_id 取 `record.task_id`；None 时整句省略，不打印无凭据的提示。
pub(crate) fn remote_failure_message(build_id: i64, phase: &str, task_id: Option<i64>) -> String {
    let base = format!("Remote build {} ended with phase '{}'", build_id, phase);
    match task_id {
        Some(tid) => format!("{base}\nNext: crbs logs {tid} --remote (or re-run with --attach)"),
        None => base,
    }
}

/// 远端构建终态 phase → 语义 CrbsError，与 follow 路径映射同款（cancelled/timeout →
/// 专属变体，failed 及未知 phase → `ContainerExecFailed`）；信封 code 与退出码同变体派生不漂移。
pub(crate) fn remote_phase_error(phase: &str, message: String) -> crbs_core::error::CrbsError {
    match phase {
        "cancelled" => crbs_core::error::CrbsError::Cancelled,
        "timeout" => crbs_core::error::CrbsError::Timeout,
        _ => crbs_core::error::CrbsError::ContainerExecFailed {
            exit_code: None,
            signal: None,
            stderr: message,
        },
    }
}

/// 远端构建终态 phase → CLI 退出码：与本地 attach 路径（`exit_with_outcome`）
/// 同口径——cancelled/timeout → INTERRUPTED(3)、其余（failed 等）→ BUILD_FAILED(2)。
pub(crate) fn remote_phase_exit_code(phase: &str) -> i32 {
    crbs_core::exit_code::crbs_error_exit_code(&remote_phase_error(phase, String::new()))
}

pub(crate) async fn handle_terminal_record(params: TerminalRecordParams<'_>) -> Result<()> {
    let TerminalRecordParams {
        base_url,
        build_id,
        pkg_name,
        record,
        format,
        token,
        ca_cert,
        cancel_token,
    } = params;
    if record.phase != "succeeded" {
        // 失败由本处打印后以 SilentExit 携码返回（main 不重复打印）；JSON 模式
        //（--attach --format json，follow.rs JSON 分支同走此处）maybe_json_error_exit
        // 对 SilentExit 透传不补打信封，{"error": ...} 信封必须由本处输出。
        let message = remote_failure_message(build_id, &record.phase, record.task_id);
        let phase_err = remote_phase_error(&record.phase, message.clone());
        match format {
            OutputFormat::Json => {
                output::print_json_error_envelope("build", phase_err.code(), &message)?;
            }
            OutputFormat::Text => {
                eprintln!("Error: {message}");
            }
        }
        return Err(crbs_core::error::CrbsError::SilentExit {
            code: remote_phase_exit_code(&record.phase),
        }
        .into());
    }

    let local_result_dir = make_local_result_dir(&record.product, pkg_name, build_id)?;
    // 目录创建失败映射 Io（kind 保真 → ENVIRONMENT=6 而非 INTERNAL(1)），context 保留含路径原串。
    tokio::fs::create_dir_all(&local_result_dir)
        .await
        .map_err(|e| crbs_core::error::CrbsError::Io {
            context: format!("create local result dir {}", local_result_dir.display()),
            kind: e.kind(),
            detail: e.to_string(),
        })?;

    let target = crate::remote::RemoteTarget::new(base_url.to_string(), token.clone(), ca_cert);
    let artifacts = crate::remote::list_artifacts(&target, build_id, cancel_token).await?;
    crate::remote::download_artifacts(
        &target,
        build_id,
        &artifacts,
        &local_result_dir,
        cancel_token,
    )
    .await?;

    let duration = record.duration.unwrap_or(0) as u64;
    print_summary(RemoteSummaryParams {
        product: &record.product,
        pkg_name,
        build_id,
        local_result_dir: &local_result_dir,
        artifacts: &artifacts,
        duration,
        format,
        signed: record.signed,
    })
    .await?;

    Ok(())
}
pub(crate) fn print_status_line(
    pkg_name: &str,
    arch: Option<&str>,
    phase: &str,
    elapsed_secs: u64,
) {
    // 服务器可控值先剥终端控制序列（防伪造状态行），见 remote::strip_terminal_control。
    let pkg_name = crate::remote::strip_terminal_control(pkg_name);
    let phase = crate::remote::strip_terminal_control(phase);
    let label = match arch {
        Some(a) => format!(
            "{} ({})",
            pkg_name,
            crate::remote::strip_terminal_control(a)
        ),
        None => pkg_name,
    };
    if std::io::stdout().is_terminal() {
        print!(
            "\rcrbs build: {:<40} phase={:<12} elapsed={:>4}s",
            label, phase, elapsed_secs
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
    } else {
        println!(
            "crbs build: {:<40} phase={:<12} elapsed={:>4}s",
            label, phase, elapsed_secs
        );
    }
}
/// SRPM 集合的记录/展示包名：hub 返回的 NEVR 优先（空串按未返回处理，只覆盖
/// 首个输入）→ 本地 rpm -qp 批量探测（单次批量调用）→ 文件名派生回退。
/// detach 展示、direct 记录身份、本地 daemon 记录身份三处共用。
pub(crate) async fn resolve_srpm_pkg_names(
    hub_pkg_name: Option<&str>,
    inputs: &[PathBuf],
) -> Vec<String> {
    let parsed = crbs_core::engine::depsolve::parse_nevr_from_srpms(inputs, None).await;
    inputs
        .iter()
        .enumerate()
        .map(|(i, srpm)| {
            let hub = if i == 0 { hub_pkg_name } else { None };
            hub.filter(|s| !s.is_empty())
                .map(str::to_string)
                .or_else(|| parsed.get(i).and_then(|r| r.as_ref().ok().cloned()))
                .unwrap_or_else(|| crbs_core::util::srpm_display_name(srpm).to_string())
        })
        .collect()
}

/// remote 路由的 detach envelope 构造：与 direct/daemon 路由同构，整批共享一个 task。
/// build_ids 多于输入（多架构）时 pkg_names 循环对齐。
fn detach_output(
    task_id: i64,
    build_ids: &[i64],
    product: &str,
    pkg_names: &[String],
) -> DetachOutput {
    let builds = build_ids
        .iter()
        .zip(pkg_names.iter().cycle())
        .map(|(id, pkg_name)| DetachBuildEntry {
            build_id: *id,
            task_id,
            pkg_name: pkg_name.clone(),
        })
        .collect();
    DetachOutput {
        command: "build",
        mode: "detach",
        transport: "remote",
        product: product.to_string(),
        task_id,
        builds,
    }
}

pub(crate) async fn print_detach_results(
    base_url: &str,
    task_id: i64,
    build_ids: &[i64],
    product: &str,
    inputs: &[PathBuf],
    hub_pkg_name: Option<&str>,
    format: OutputFormat,
) -> Result<()> {
    let pkg_names = resolve_srpm_pkg_names(hub_pkg_name, inputs).await;
    match format {
        OutputFormat::Json => {
            // detach 统一 JSON schema（见 detach_output）；不得输出 location 键。
            let output = detach_output(task_id, build_ids, product, &pkg_names);
            output::print_json(&output)?;
        }
        OutputFormat::Text => {
            println!("Builds submitted:");
            println!("  mode:       detach");
            println!("  transport:  remote");
            println!("  location:   {}", base_url);
            println!("  task_id:    {}", task_id);
            println!("  builds:");
            for (id, pkg_name) in build_ids.iter().zip(pkg_names.iter().cycle()) {
                println!("    - build_id:  {}", id);
                println!("      pkg_name:  {}", pkg_name);
            }
            println!();
            println!(
                "Check status: crbs status --remote {} --task {}",
                base_url, task_id
            );
            if let Some(id) = build_ids.first() {
                println!(
                    "Attach later: crbs build --remote {} --attach {}",
                    base_url, id
                );
            }
        }
    }
    Ok(())
}

/// [`print_summary`] 的参数包：远端构建终态摘要的展示上下文。
struct RemoteSummaryParams<'a> {
    product: &'a str,
    pkg_name: &'a str,
    build_id: i64,
    local_result_dir: &'a Path,
    artifacts: &'a crate::remote::ArtifactsResponse,
    duration: u64,
    format: OutputFormat,
    signed: bool,
}

async fn print_summary(params: RemoteSummaryParams<'_>) -> Result<()> {
    let RemoteSummaryParams {
        product,
        pkg_name,
        build_id,
        local_result_dir,
        artifacts,
        duration,
        format,
        signed,
    } = params;
    let srpm_path = PathBuf::from(format!("{}.src.rpm", pkg_name));
    let outputs = BuildOutputs {
        build_id,
        pkg_name: pkg_name.to_string(),
        rpms: artifacts
            .rpms
            .iter()
            .map(|r| local_result_dir.join(r))
            .collect(),
        srpms: artifacts
            .srpms
            .iter()
            .map(|r| local_result_dir.join(r))
            .collect(),
        logs: vec![],
        result_dir: local_result_dir.to_path_buf(),
        retries: 0,
        signed,
    };

    let summary = BuildSummary {
        succeeded: vec![(srpm_path, outputs, duration)],
        failed: vec![],
        cancelled: vec![],
        timeout: vec![],
    };

    match format {
        OutputFormat::Json => {
            // remote 走 daemon 单包路径，chain-only 元数据全部 None。
            output::print_json_summary(output::SummaryOutputParams::plain(product, &summary))
                .await?;
        }
        OutputFormat::Text => {
            workers::print_summary(&summary);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        detach_output, remote_failure_message, remote_phase_error, remote_phase_exit_code,
        resolve_srpm_pkg_names,
    };
    use crate::cmd::build::output;
    use crate::cmd::build::output::assert_detach_envelope;

    /// 取值优先级钉：hub 值只落首个输入，其余走探测失败后的文件名回退。
    #[tokio::test]
    async fn resolve_srpm_pkg_names_prefers_hub_for_first_input_only() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let inputs = vec![
            tmp.path().join("hello-1.0-1.src.rpm"),
            tmp.path().join("world-2.0-1.src.rpm"),
        ];
        let names = resolve_srpm_pkg_names(Some("real-9.9-1"), &inputs).await;
        assert_eq!(names[0], "real-9.9-1");
        // 非 RPM 文件探测必败 → 文件名派生回退。
        assert_eq!(names[1], "world-2.0-1");

        let names = resolve_srpm_pkg_names(None, &inputs).await;
        assert_eq!(names[0], "hello-1.0-1");
        assert_eq!(names[1], "world-2.0-1");

        // hub 空串按未返回处理：首输入走探测失败后的文件名回退。
        let names = resolve_srpm_pkg_names(Some(""), &inputs).await;
        assert_eq!(names[0], "hello-1.0-1");
        assert_eq!(names[1], "world-2.0-1");
    }

    /// 钉终态 phase → 退出码映射与本地 attach 路径同口径（含未知 phase 防御归类）。
    #[test]
    fn remote_phase_exit_code_matches_local_attach_semantics() {
        assert_eq!(
            remote_phase_exit_code("failed"),
            crbs_core::exit_code::BUILD_FAILED
        );
        assert_eq!(
            remote_phase_exit_code("cancelled"),
            crbs_core::exit_code::INTERRUPTED
        );
        assert_eq!(
            remote_phase_exit_code("timeout"),
            crbs_core::exit_code::INTERRUPTED
        );
        // 未知 / 防御 phase：按构建失败归类（不冒充内部错误）。
        assert_eq!(
            remote_phase_exit_code("weird-future-phase"),
            crbs_core::exit_code::BUILD_FAILED
        );
    }

    /// 钉 batch follow 与 remote follow 共用的分桶谓词输入：未知 phase 归
    /// ContainerExecFailed（build_failed 桶），cancelled/timeout 保持专属变体
    ///（batch 汇总按 matches! 变体分桶，变体即桶位）。
    #[test]
    fn remote_phase_error_buckets_unknown_phase_as_build_failure() {
        assert!(matches!(
            remote_phase_error("weird-future-phase", "m".into()),
            crbs_core::error::CrbsError::ContainerExecFailed { .. }
        ));
        assert!(matches!(
            remote_phase_error("cancelled", "m".into()),
            crbs_core::error::CrbsError::Cancelled
        ));
        assert!(matches!(
            remote_phase_error("timeout", "m".into()),
            crbs_core::error::CrbsError::Timeout
        ));
    }

    /// 钉 remote 路由 detach JSON schema：三路由统一 envelope，`location` 键不得出现。
    #[test]
    fn detach_output_remote_envelope_schema() {
        let out = detach_output(5, &[21, 22], "fedora", &["hello-1.0-1".to_string()]);
        let value = serde_json::to_value(&out).expect("serialize detach output");
        assert_detach_envelope(&value, "remote");
        assert_eq!(value["task_id"], 5);
        let builds = value["builds"].as_array().expect("builds array");
        assert_eq!(builds.len(), 2);
        assert_eq!(builds[0]["build_id"], 21);
        assert_eq!(builds[0]["task_id"], 5);
        assert_eq!(builds[1]["build_id"], 22);
        assert_eq!(builds[1]["task_id"], 5);
        // 单输入对多 build_id（多架构）循环对齐。
        assert_eq!(builds[0]["pkg_name"], "hello-1.0-1");
        assert_eq!(builds[1]["pkg_name"], "hello-1.0-1");
    }

    /// 失败消息附下一步提示（logs --remote / re-run --attach）；task_id 缺失时整句省略。
    #[test]
    fn remote_failure_message_appends_next_step_hint() {
        let msg = remote_failure_message(42, "failed", Some(7));
        assert!(
            msg.starts_with("Remote build 42 ended with phase 'failed'"),
            "msg: {msg}"
        );
        assert!(
            msg.contains("\nNext: crbs logs 7 --remote (or re-run with --attach)"),
            "msg: {msg}"
        );

        assert_eq!(
            remote_failure_message(42, "failed", None),
            "Remote build 42 ended with phase 'failed'"
        );
    }

    /// 钉 JSON 失败信封三件事：`error.code` 为映射后语义码（非 silent_exit/internal）、
    /// 信封形状恰 {command, outcome, error} / {code, message}、code 与退出码同变体派生。
    #[test]
    fn remote_failure_json_envelope_carries_semantic_code() {
        for (phase, expected_code) in [
            ("failed", "container_exec_failed"),
            ("cancelled", "cancelled"),
            ("timeout", "timeout"),
            // 未知 / 防御 phase：按构建失败归类。
            ("weird-future-phase", "container_exec_failed"),
        ] {
            let err = remote_phase_error(phase, "boom".to_string());
            assert_eq!(err.code(), expected_code, "phase {phase}");

            let env = output::json_error_envelope("build", err.code(), "boom");
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
            assert_eq!(env["command"], "build");
            assert_eq!(env["outcome"], "error");
            assert_eq!(env["error"]["code"], expected_code, "phase {phase}");
            assert_eq!(env["error"]["message"], "boom");
            assert_eq!(
                remote_phase_exit_code(phase),
                crbs_core::exit_code::crbs_error_exit_code(&err),
                "exit code must derive from the same variant as the envelope code (phase {phase})"
            );
        }
    }
}
