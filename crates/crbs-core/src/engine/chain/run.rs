// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Chain 编排入口：prepare → 逐轮构建（+ 恢复轮）→ 无主挂载清理。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use tokio_util::sync::CancellationToken;

use crate::engine::BuildEngine;

use super::prepare;
use super::rounds::{execute_chain_rounds, ChainRoundsParams};
use super::{ChainBuildExecutor, ChainProgressSink};

/// chain 编排的调用参数（构建执行与输出渲染经 `exec`/`out` 注入）。
pub struct ChainRunInput<'a> {
    /// 构建引擎（prepare 与退出前无主挂载清理共用其 config/state）。
    pub engine: &'a Arc<BuildEngine>,
    /// 产品名。
    pub product: &'a str,
    /// 输入 SRPM 路径（已解析、canonicalize、去重）。
    pub inputs: Vec<PathBuf>,
    /// 进程级取消令牌（Ctrl-C / SIGTERM）。
    pub cancel_token: &'a CancellationToken,
    /// 并行度（worker 数；兼作摘要元数据透传）。
    pub jobs: usize,
    /// 首个失败即取消整链。
    pub fail_fast: bool,
    /// `--order-only`：只输出构建计划，不执行构建。
    pub order_only: bool,
    /// `--force`：跳过增量缓存判定。
    pub force: bool,
    /// 有效 %dist（`--dist` 经 normalize_dist）；`None` = 未显式指定，注入前 EVR 校验完全旁路。
    pub dist: Option<String>,
    /// 维护/注入 local result repo（`--no-result-repo` 时跳过 depsolve，非缓存包全进单轮并行）。
    pub use_result_repo: bool,
}

/// 执行完整 chain 构建（prepare → 逐轮构建 → 退出前无主挂载清理）。
/// `Ok(())` = 完成（含 `--order-only` / 空输入早退）；`Err` 携带失败语义
///（代表错误 / 中途轮失败 / prepare 失败），由调用方映射退出码。
pub async fn run_chain_build(
    input: ChainRunInput<'_>,
    exec: &dyn ChainBuildExecutor,
    out: &mut dyn ChainProgressSink,
) -> anyhow::Result<()> {
    let chain_start = Instant::now();
    let Some(ctx) = prepare::prepare_chain_context(&input, out)
        .await
        .map_err(|e| out.prepare_error(e))?
    else {
        return Ok(());
    };

    let chain_result = execute_chain_rounds(
        ctx,
        ChainRoundsParams {
            cancel_token: input.cancel_token,
            fail_fast: input.fail_fast,
            chain_start,
            parallelism: input.jobs,
        },
        exec,
        out,
    )
    .await;
    let engine = input.engine;
    let config = engine.config();
    let product_root = config.product_root();
    BuildEngine::cleanup_orphan_mounts_for_product(
        &product_root,
        input.product,
        &crate::engine::gc::OrphanScanRoots::from_engine_config(config),
        engine.state_store().as_ref(),
    )
    .await;

    chain_result
}
