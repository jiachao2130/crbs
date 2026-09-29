// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Chain 构建编排：工具检查 / local repo 初始化 / 增量判定 / BR 提取 /
//! 依赖建图 / 拓扑分轮 / 逐轮构建（轮间精准注入）/ 恢复轮不动点 / 汇总。
//!
//! 编排与执行、输出分离：构建执行器与进度回调经 trait 注入，core 不持有 CLI 类型。

mod prepare;
mod run;

pub(crate) mod rounds;

pub use run::{run_chain_build, ChainRunInput};
// 批次 dist 硬预检（crbs-server）复用同一后缀判定：prepare 内私有，经此 re-export 取用。
pub use prepare::release_dist_suffix;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use crate::types::BuildSummary;

/// 构建执行器注入：完成一轮（拓扑轮或恢复轮）构建并返回四桶汇总，轮间把
/// 成功产物灌入 local repo。真实实现由调用方提供（CLI：worker 池 + 产物签名）。
pub trait ChainBuildExecutor: Send + Sync {
    /// 执行一轮构建。`targets` 为 (SRPM 路径, 目标 arch) 列表（noarch 包显式 `Some("noarch")`，
    /// 其余 `None` 跟随主机 arch）；`round_names` 为与本轮 targets 同序的裸包名（失败登记键）。
    fn run_round(
        &self,
        targets: Vec<(PathBuf, Option<String>)>,
        round_names: Vec<String>,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<BuildSummary>> + Send + '_>>;

    /// 精准注入缝：把 `rpm_paths` 灌入 local repo（`dist` 显式时先做 release
    /// EVR 校验）。默认委托真实 `update_local_repo`，探测缝传真实
    /// `rpm_query_release`（Timeout 分流为整链中止）；测试 mock 覆写以记录注入请求。
    fn inject_rpms<'a>(
        &'a self,
        repo_dir: &'a Path,
        rpm_paths: &'a [PathBuf],
        dist: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = crate::Result<()>> + Send + 'a>> {
        Box::pin(crate::engine::repo::update_local_repo(
            repo_dir,
            rpm_paths,
            dist,
            crate::engine::repo::rpm_query_release,
        ))
    }
}

/// 构建计划数据（拓扑分轮结果），供输出回调渲染。
pub struct ChainPlanData<'a> {
    /// 产品名。
    pub product: &'a str,
    /// 各轮包名（拓扑序；环并入轮 0）。
    pub rounds: Vec<Vec<String>>,
    /// 增量缓存命中（result_dir 已有成功产物）的包名。
    pub cached: &'a [String],
    /// 拓扑排不出顺序的节点名（环 + 解析残留，已并入轮 0 尝试）。
    pub cycle_attempted: &'a [String],
}

/// chain 汇总数据（最终摘要与中途失败的 partial 摘要同用一份结构）。
pub struct ChainSummaryData<'a> {
    /// 产品名。
    pub product: &'a str,
    /// 四桶汇总。
    pub summary: &'a BuildSummary,
    /// 增量缓存命中的包名。
    pub cached_names: &'a [String],
    /// 因依赖失败被跳过的包名。
    pub dep_skipped: &'a [String],
    /// 拓扑排不出顺序、已并入轮 0 尝试的节点名。
    pub cycle_attempted: &'a [String],
    /// 恢复轮成功构建的包名。
    pub recovered: &'a [String],
    /// 整个 chain run 的墙钟时长（含 prepare + rounds + recovery）。
    pub wall_time: std::time::Duration,
    /// 拓扑轮数。
    pub rounds: usize,
    /// 并行度（worker 数）。
    pub parallelism: usize,
}

/// 进度/输出回调注入：core 编排在既定输出点调用，调用方负责按 text/json
/// 渲染；core 自身不做任何用户可见输出，输出点与文案的既有契约由调用方
/// 实现逐字保持。
pub trait ChainProgressSink: Send {
    /// prepare 阶段失败的输出收口：JSON 模式按错误变体补发唯一错误 envelope
    /// 并转 SilentExit（退出码保真），text 模式原样透传；返回转换后的错误由编排上抛。
    fn prepare_error(&mut self, error: anyhow::Error) -> anyhow::Error;
    /// 必需工具（dnf / createrepo_c）缺失：JSON 模式打印 `validation_failed`
    /// 错误信封（裸消息，不带变体 Display 前缀）并转 SilentExit(USAGE)；text 转 ValidationFailed。
    fn missing_required_tool(&mut self, tool: &str) -> anyhow::Error;
    /// 输入为空：JSON 输出 `chain-plan`（`outcome: "empty"`）文档，
    /// text 打印 "No SRPM files to process"。
    fn empty_input(&mut self, product: &str) -> anyhow::Result<()>;
    /// 构建计划：text 打印轮次表（含 CACHED/CYCLE 行）；JSON 仅 order-only
    /// 模式输出 `chain-plan`（`outcome: "planned"`）文档，其余 JSON 路径静默。
    fn plan(&mut self, plan: &ChainPlanData<'_>) -> anyhow::Result<()>;
    /// 拓扑轮开始头（text 打印 `--- Round i/n ---`；JSON 静默；`round_index` 从 0 计）。
    fn round_start(&mut self, round_index: usize, total_rounds: usize, packages: usize);
    /// 恢复轮开始头（text 打印；JSON 静默）。
    fn recovery_round_start(&mut self, recovery_round: usize, max_rounds: usize, packages: usize);
    /// chain 汇总（最终与中途失败的 partial 摘要走同一出口）。
    fn summary<'a>(
        &'a mut self,
        data: ChainSummaryData<'a>,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;
}
