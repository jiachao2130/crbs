// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Chain 编排入口：prepare → 逐轮构建（+ 恢复轮）→ 残留挂载清理。

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
    /// 构建引擎（prepare 与退出前孤儿挂载清理共用其 config/state）。
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

/// 执行完整 chain 构建（prepare → 逐轮构建 → 退出前孤儿挂载清理）。
/// `Ok(())` = 完成（含 `--order-only` / 空输入早退）；`Err` 携带失败语义
///（代表错误 / 中途轮失败 / prepare 失败），由调用方映射退出码。
pub async fn run_chain_build(
    input: ChainRunInput<'_>,
    exec: &dyn ChainBuildExecutor,
    out: &mut dyn ChainProgressSink,
) -> anyhow::Result<()> {
    // 计时覆盖整个 chain run，供摘要 wall_time（秒级精度）。
    let chain_start = Instant::now();
    // prepare 失败输出收口交 sink：JSON 模式恰一个错误信封，prepare_error
    // 按变体补发并转 SilentExit；内层已打过信封 / 非 JSON 模式原样透传。
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
    // Err 必须原样传播（吞掉则失败/取消的 chain 假成功）；orphan cleanup 在
    // 返回前无条件执行，两不相误。cancel/失败时 nspawn fd 异步释放残留 lazy
    // mount，扫 product_root 后 MNT_DETACH；chain 退出 build 已结束，守卫放行。
    let engine = input.engine;
    let config = engine.config();
    let product_root = config.product_root();
    BuildEngine::cleanup_orphan_mounts_for_product(
        &product_root,
        input.product,
        // 扫描域用引擎 pin 后的配置（不在清理路径重读全局配置文件）。
        &crate::engine::gc::OrphanScanRoots::from_engine_config(config),
        engine.state_store().as_ref(),
    )
    .await;

    chain_result
}
