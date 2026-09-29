// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use crbs_core::engine::chain::{
    ChainBuildExecutor, ChainPlanData, ChainProgressSink, ChainRunInput, ChainSummaryData,
};
use crbs_core::engine::BuildEngine;
use crbs_core::error::CrbsError;
use crbs_core::types::BuildSummary;

use crate::cli::OutputFormat;

use super::output::{
    print_json, print_json_error_envelope, print_json_summary, JsonChainPlan, SummaryOutputParams,
};
use super::summary::{
    extract_pkg_name, group_failures, print_failures_by_phase, print_summary_header,
    print_truncated_list, SummaryHeaderParams,
};
use super::workers::run_build_workers;
use super::ChainParams;

#[derive(Clone, Debug)]
pub(crate) struct ChainBuildArgs {
    pub jobs: usize,
    pub fail_fast: bool,
    pub params: ChainParams,
    pub format: OutputFormat,

    pub use_result_repo: bool,

    pub summary_flags: SummaryFlags,
}

#[derive(Clone, Debug)]
pub(crate) struct SummaryFlags {
    pub summary_limit: usize,
    pub list_failed: bool,
    pub list_succeeded: bool,
    pub concise: bool,
    pub verbose_summary: bool,
}

struct CliChainExecutor {
    engine: Arc<BuildEngine>,
    cancel_token: CancellationToken,
    jobs: usize,
    fail_fast: bool,
    format: OutputFormat,
}

impl ChainBuildExecutor for CliChainExecutor {
    fn run_round(
        &self,
        round_inputs: Vec<(PathBuf, Option<String>)>,
        _round_names: Vec<String>,
    ) -> Pin<Box<dyn Future<Output = Result<BuildSummary>> + Send + '_>> {
        let engine = Arc::clone(&self.engine);
        let cancel_for_round = self.cancel_token.clone();
        let jobs = self.jobs;
        let fail_fast = self.fail_fast;
        let format = self.format;
        Box::pin(async move {
            let mut summary = run_build_workers(
                &engine,
                round_inputs,
                jobs,
                &cancel_for_round,
                fail_fast,
                format,
            )
            .await?;
            for (_, outputs, _) in &mut summary.succeeded {
                crbs_core::sign::sign_build_outputs(outputs, engine.config()).await;

                if outputs.signed {
                    crbs_core::sign::mark_build_signed_best_effort(
                        engine.state_store(),
                        outputs.build_id,
                    )
                    .await;
                }
            }
            Ok(summary)
        })
    }
}

struct CliChainSink {
    format: OutputFormat,
    order_only: bool,
    summary_flags: SummaryFlags,
}

impl ChainProgressSink for CliChainSink {
    fn prepare_error(&mut self, error: anyhow::Error) -> anyhow::Error {
        prepare_json_error(self.format, error)
    }

    fn missing_required_tool(&mut self, tool: &str) -> anyhow::Error {
        let message = format!("--chain requires '{}' to be installed", tool);
        if self.format == OutputFormat::Json {
            return match print_json_error_envelope("build", "validation_failed", &message) {
                Ok(()) => CrbsError::SilentExit {
                    code: crbs_core::exit_code::USAGE,
                }
                .into(),

                Err(e) => e,
            };
        }
        CrbsError::ValidationFailed { message }.into()
    }

    fn empty_input(&mut self, product: &str) -> Result<()> {
        if self.format == OutputFormat::Json {
            let plan = JsonChainPlan {
                command: "build",
                mode: "chain-plan",
                product: product.to_string(),
                outcome: "empty",
                rounds: Vec::new(),
                cached: Vec::new(),
                cycle_failed: Vec::new(),
            };
            print_json(&plan)
        } else {
            println!("No SRPM files to process");
            Ok(())
        }
    }

    fn plan(&mut self, plan: &ChainPlanData<'_>) -> Result<()> {
        if self.format == OutputFormat::Json {
            if self.order_only {
                let json_plan = JsonChainPlan {
                    command: "build",
                    mode: "chain-plan",
                    product: plan.product.to_string(),
                    outcome: "planned",
                    rounds: plan.rounds.clone(),
                    cached: plan.cached.to_vec(),
                    cycle_failed: plan.cycle_attempted.to_vec(),
                };
                print_json(&json_plan)?;
            }
            return Ok(());
        }
        println!(
            "\nBuild plan ({} rounds, {} cached):",
            plan.rounds.len(),
            plan.cached.len()
        );
        if !plan.cached.is_empty() {
            println!("  CACHED:   {}", plan.cached.join("  "));
        }
        for (i, round) in plan.rounds.iter().enumerate() {
            println!("  Round {}:  {}", i + 1, round.join("  "));
        }
        if !plan.cycle_attempted.is_empty() {
            println!(
                "  CYCLE:    {} (will be attempted in round 0)",
                plan.cycle_attempted.join("  ")
            );
        }
        Ok(())
    }

    fn round_start(&mut self, round_index: usize, total_rounds: usize, packages: usize) {
        if self.format == OutputFormat::Text {
            println!(
                "\n--- Round {}/{} ({} packages) ---",
                round_index + 1,
                total_rounds,
                packages
            );
        }
    }

    fn recovery_round_start(&mut self, recovery_round: usize, max_rounds: usize, packages: usize) {
        if self.format == OutputFormat::Text {
            println!(
                "\n--- Recovery Round {}/{} ({} packages) ---",
                recovery_round, max_rounds, packages
            );
        }
    }

    fn summary<'a>(
        &'a mut self,
        data: ChainSummaryData<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            match self.format {
                OutputFormat::Json => {
                    print_json_summary(SummaryOutputParams {
                        product: data.product,
                        summary: data.summary,
                        cached: Some(data.cached_names.len()),
                        dep_skipped: Some(data.dep_skipped.len()),
                        cycle_failed: Some(data.cycle_attempted.len()),
                        wall_time: Some(data.wall_time),
                        rounds: Some(data.rounds),
                        parallelism: Some(data.parallelism),
                        recovered: Some(data.recovered.len()),
                    })
                    .await
                }
                OutputFormat::Text => {
                    let wall_time = data.wall_time;
                    let total = data.summary.succeeded.len()
                        + data.summary.failed.len()
                        + data.summary.cancelled.len()
                        + data.summary.timeout.len()
                        + data.cached_names.len()
                        + data.dep_skipped.len();
                    print_text_chain_summary(TextChainSummaryParams {
                        total,
                        summary: data.summary,
                        dep_skipped: data.dep_skipped,
                        cycle_attempted: data.cycle_attempted,
                        recovered: data.recovered,
                        wall_time,
                        rounds: data.rounds,
                        parallelism: data.parallelism,
                        flags: &self.summary_flags,
                    });
                    Ok(())
                }
            }
        })
    }
}

/// CLI 适配层的 chain 构建入口：编排已下沉 crbs-core，本层只做参数装配（ChainBuildArgs → ChainRunInput）、构建执行器注入（worker 池 +
/// 成功产物签名）与输出渲染注入（text/JSON）。
pub(crate) async fn run_chain_build(
    engine: &Arc<BuildEngine>,
    product: &str,
    inputs: Vec<PathBuf>,
    cancel_token: &CancellationToken,
    args: &ChainBuildArgs,
) -> anyhow::Result<()> {
    let exec = CliChainExecutor {
        engine: Arc::clone(engine),
        cancel_token: cancel_token.clone(),
        jobs: args.jobs,
        fail_fast: args.fail_fast,
        format: args.format,
    };
    let mut sink = CliChainSink {
        format: args.format,
        order_only: args.params.order_only,
        summary_flags: args.summary_flags.clone(),
    };
    crbs_core::engine::chain::run_chain_build(
        ChainRunInput {
            engine,
            product,
            inputs,
            cancel_token,
            jobs: args.jobs,
            fail_fast: args.fail_fast,
            order_only: args.params.order_only,
            force: args.params.force,
            dist: args.params.dist.clone(),
            use_result_repo: args.use_result_repo,
        },
        &exec,
        &mut sink,
    )
    .await
}

/// chain prepare 阶段错误的 JSON 模式收口：prepare 失败若裸 `?` 上抛，上层只算退出码不打印，stdout/stderr 全空破坏 --format json
/// 恰好一个 JSON 文档契约——按错误变体补发唯一 envelope 并转 SilentExit。
fn prepare_json_error(format: OutputFormat, e: anyhow::Error) -> anyhow::Error {
    if format != OutputFormat::Json {
        return e;
    }
    if matches!(
        e.downcast_ref::<CrbsError>(),
        Some(CrbsError::SilentExit { .. })
    ) {
        return e;
    }
    let printed = match e.downcast_ref::<CrbsError>() {
        Some(ce) => print_json_error_envelope("build", ce.code(), &ce.to_string())
            .map(|_| crbs_core::exit_code::crbs_error_exit_code(ce)),
        None => print_json_error_envelope("build", "internal_error", &e.to_string())
            .map(|_| crbs_core::exit_code::INTERNAL),
    };
    match printed {
        Ok(code) => CrbsError::SilentExit { code }.into(),
        Err(_) => e,
    }
}

struct TextChainSummaryParams<'a> {
    total: usize,
    summary: &'a BuildSummary,
    dep_skipped: &'a [String],
    cycle_attempted: &'a [String],
    recovered: &'a [String],
    wall_time: std::time::Duration,
    rounds: usize,
    parallelism: usize,
    flags: &'a SummaryFlags,
}

fn print_text_chain_summary(params: TextChainSummaryParams<'_>) {
    let TextChainSummaryParams {
        total,
        summary,
        dep_skipped,
        cycle_attempted,
        recovered,
        wall_time,
        rounds,
        parallelism,
        flags,
    } = params;
    println!("\n═══ Chain Summary ═══");

    if flags.concise {
        let failed_total = summary.failed.len() + summary.cancelled.len() + summary.timeout.len();
        println!(
            "Total: {}  Succeeded: {}  Failed: {}  Skipped: {}  Wall: {}s",
            total,
            summary.succeeded.len(),
            failed_total,
            dep_skipped.len(),
            wall_time.as_secs()
        );
        return;
    }

    print_summary_header(SummaryHeaderParams {
        total,
        succeeded: summary.succeeded.len(),
        failed: summary.failed.len(),
        cancelled: summary.cancelled.len(),
        timeout: summary.timeout.len(),
        dep_skipped: dep_skipped.len(),
        recovered: recovered.len(),
        wall_time,
        rounds,
        parallelism,
    });

    let buckets = group_failures(&summary.failed, &summary.cancelled, &summary.timeout);
    print_failures_by_phase(&buckets, flags.summary_limit);

    let succeeded_names: Vec<String> = summary
        .succeeded
        .iter()
        .map(|(_, o, _)| o.pkg_name.clone())
        .collect();
    let failed_names: Vec<String> = summary
        .failed
        .iter()
        .map(|(p, _, _)| extract_pkg_name(p))
        .collect();

    if flags.verbose_summary {
        if !succeeded_names.is_empty() {
            println!("\nSUCCEEDED     {}", succeeded_names.len());
            for n in &succeeded_names {
                println!("  {}", n);
            }
        }
        if !failed_names.is_empty() {
            println!("\nFAILED        {}", failed_names.len());
            for n in &failed_names {
                println!("  {}", n);
            }
        }
        if !recovered.is_empty() {
            println!(
                "\nRECOVERED     {} (succeeded in a recovery round)",
                recovered.len()
            );
            for n in recovered {
                println!("  {}", n);
            }
        }
        if !cycle_attempted.is_empty() {
            println!(
                "\nCYCLE         {} (attempted in round 0)",
                cycle_attempted.len()
            );
            for n in cycle_attempted {
                println!("  {}", n);
            }
        }
        return;
    }

    let limit = flags.summary_limit;
    let full_by_limit = limit == 0;
    if flags.list_succeeded || full_by_limit {
        print_truncated_list("\nSucceeded: ", &succeeded_names, 0, true, "");
    } else {
        print_truncated_list(
            &format!("\nSucceeded (top {limit}): "),
            &succeeded_names,
            limit,
            false,
            "use --list-succeeded to show all",
        );
    }

    if flags.list_failed || full_by_limit {
        print_truncated_list("\nFailed: ", &failed_names, 0, true, "");
    } else {
        print_truncated_list(
            &format!("\nFailed (top {limit}): "),
            &failed_names,
            limit,
            false,
            "use --list-failed to show all",
        );
    }

    if !recovered.is_empty() {
        if flags.list_succeeded || full_by_limit {
            print_truncated_list("\nRecovered: ", recovered, 0, true, "");
        } else {
            print_truncated_list(
                &format!("\nRecovered (top {limit}): "),
                recovered,
                limit,
                false,
                "use --list-succeeded to show all",
            );
        }
    }

    if !cycle_attempted.is_empty() {
        if full_by_limit {
            print_truncated_list("\nCycle (round 0): ", cycle_attempted, 0, true, "");
        } else {
            print_truncated_list(
                &format!("\nCycle (round 0, top {limit}): "),
                cycle_attempted,
                limit,
                false,
                "",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_json_error_envelopes_once_and_maps_exit_code() {
        let err = prepare_json_error(
            OutputFormat::Json,
            CrbsError::ValidationFailed {
                message: "bad input".into(),
            }
            .into(),
        );
        assert!(
            matches!(
                err.downcast_ref::<CrbsError>(),
                Some(CrbsError::SilentExit { code }) if *code == crbs_core::exit_code::USAGE
            ),
            "must wrap into SilentExit with the variant's exit code, got {err:#}"
        );

        let err = prepare_json_error(
            OutputFormat::Json,
            CrbsError::SilentExit {
                code: crbs_core::exit_code::USAGE,
            }
            .into(),
        );
        assert!(matches!(
            err.downcast_ref::<CrbsError>(),
            Some(CrbsError::SilentExit { .. })
        ));

        let err = prepare_json_error(OutputFormat::Json, anyhow::anyhow!("boom"));
        assert!(matches!(
            err.downcast_ref::<CrbsError>(),
            Some(CrbsError::SilentExit { code }) if *code == crbs_core::exit_code::INTERNAL
        ));

        let err = prepare_json_error(
            OutputFormat::Text,
            CrbsError::ValidationFailed {
                message: "bad input".into(),
            }
            .into(),
        );
        assert!(matches!(
            err.downcast_ref::<CrbsError>(),
            Some(CrbsError::ValidationFailed { .. })
        ));
    }
}
