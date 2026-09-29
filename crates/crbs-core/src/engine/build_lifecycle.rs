// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 本地构建生命周期：构建身份、上下文与终态结果收口。

use std::sync::Arc;
use std::time::Duration;

use crate::engine::resource_sample::ResourceUsage;
use crate::error::{CrbsError, DbResultExt};
use crate::http_retry::{retry_with_policy, RetryBreak, RetryCause};
use crate::state::{BuildInsert, StateStore, TaskInsert};
use crate::types::BuildPriority;

/// 单包构建的终态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildOutcome {
    /// 构建成功。
    Succeeded,
    /// 构建失败。
    Failed,
    /// 已取消。
    Cancelled,
    /// 超时。
    Timeout,
}

impl BuildOutcome {
    pub(crate) fn phase(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
        }
    }
}

/// 构建身份标识（必填字段）。
#[derive(Debug, Clone)]
pub struct BuildIdentity<'a> {
    /// 产品名。
    pub product: &'a str,
    /// 包名。
    pub pkg_name: &'a str,
}

impl<'a> BuildIdentity<'a> {
    /// 以必填字段构造构建身份。
    pub fn new(product: &'a str, pkg_name: &'a str) -> Self {
        Self { product, pkg_name }
    }
}

/// 构建运行上下文（可选覆盖字段）。
#[derive(Debug, Clone)]
pub struct BuildContext<'a> {
    /// 提交者用户名。
    pub user: Option<&'a str>,
    /// DB 用户 ID（server 提交时填写；本地 CLI 无对应用户则为 None）。
    pub user_id: Option<i64>,
    /// 发起构建的 crbs 进程 PID。
    pub crbs_pid: Option<i64>,
    /// 构建优先级。
    pub priority: BuildPriority,
    /// 关联到的 task_id（server 批量任务场景使用）。None 时（引擎本地路径）
    /// 先插本地任务行再以该 id 插 build，满足 `builds.task_id` NOT NULL 约束。
    pub task_id: Option<i64>,
    /// SRPM 路径（本地构建可得时填写本地任务的 srpm_path）。
    pub srpm_path: Option<&'a str>,
    /// 目标架构：insert 时即随行写入 builds.arch——活跃构建去重复查按真值
    /// arch 命中，先插 NULL 后补写会让并发双提交的复查不命中、照样插入。
    /// 引擎本地构建不带 arch（保持 NULL）。
    pub arch: Option<&'a str>,
    /// 调度宿主约束 CSV（仅 arch='noarch' 行有值，语义见 builds 表列注）；
    /// 由提交侧物化（显式架构集 > 产品偏好集 > None；复现入口为源宿主单架构）。
    pub host_arches: Option<&'a str>,
    /// 发布轴生效值（提交时快照进 builds.repo_publish）：false = 产物不进
    /// 产品 repo 候选集。默认 true。
    pub repo_publish: bool,
    /// 消费轴生效值（提交时合流快照进 builds.repo_consume）：false = 派发不
    /// 注入产品 repo。默认 true；合流谓词由提交侧收口。
    pub repo_consume: bool,
    /// 放置契约下限（提交时解析快照进 builds.req_min_*，单位 KB/核）：
    /// 声明落列无害、消费受 resource_requirements_enabled 开关。
    /// 默认全 None；解析口径与 validate_options 同源（ReqMinKb）。
    pub req_min_mem_kb: Option<i64>,
    /// 放置契约下限——最低 CPU 核数（同上组，单位核）。
    pub req_min_ncpu: Option<i64>,
    /// 放置契约下限——最低磁盘（同上组，单位 KB）。
    pub req_min_disk_kb: Option<i64>,
    /// 构建创建时的产品配置原文快照（本地构建携带）：随 build 行写入
    /// `product_config_toml`，供 `crbs debug` 锚定当时的配置。None = 不锚定。
    pub product_config_toml: Option<&'a str>,
    /// 任务级标签：仅本地自建任务行使用（server 提交的任务由提交入口写入）。
    pub task_labels: &'a [(String, String)],
}

impl Default for BuildContext<'_> {
    fn default() -> Self {
        Self {
            user: None,
            user_id: None,
            crbs_pid: None,
            priority: BuildPriority::default(),
            task_id: None,
            srpm_path: None,
            arch: None,
            host_arches: None,
            repo_publish: true,
            repo_consume: true,
            req_min_mem_kb: None,
            req_min_ncpu: None,
            req_min_disk_kb: None,
            product_config_toml: None,
            task_labels: &[],
        }
    }
}

impl<'a> BuildContext<'a> {
    /// 快速构造一个只含必填字段的 BuildContext，其余字段默认。
    pub fn new(priority: BuildPriority) -> Self {
        Self {
            priority,
            ..Default::default()
        }
    }

    /// 设置提交者（用户名 + 可选 DB 用户 ID）。
    pub fn with_user(mut self, user: &'a str, user_id: Option<i64>) -> Self {
        self.user = Some(user);
        self.user_id = user_id;
        self
    }

    /// 设置 crbs_pid。
    pub fn with_crbs_pid(mut self, crbs_pid: Option<i64>) -> Self {
        self.crbs_pid = crbs_pid;
        self
    }

    /// 设置关联 task_id。
    pub fn with_task_id(mut self, task_id: Option<i64>) -> Self {
        self.task_id = task_id;
        self
    }

    /// 设置 SRPM 路径（本地任务行 srpm_path 记录用）。
    pub fn with_srpm_path(mut self, srpm_path: Option<&'a str>) -> Self {
        self.srpm_path = srpm_path;
        self
    }

    /// 设置目标架构（insert 时随行写入 builds.arch，见字段文档）。
    pub fn with_arch(mut self, arch: Option<&'a str>) -> Self {
        self.arch = arch;
        self
    }

    /// 设置调度宿主约束（insert 时随行写入 builds.host_arches，见字段文档）。
    pub fn with_host_arches(mut self, host_arches: Option<&'a str>) -> Self {
        self.host_arches = host_arches;
        self
    }

    /// 设置双轴生效值（insert 时随行写入 builds.repo_publish / repo_consume，
    /// 见字段文档）。
    pub fn with_repo_flags(mut self, repo_publish: bool, repo_consume: bool) -> Self {
        self.repo_publish = repo_publish;
        self.repo_consume = repo_consume;
        self
    }

    /// 设置放置契约下限（insert 时随行写入 builds.req_min_*，见字段文档）。
    pub fn with_req_min(
        mut self,
        mem_kb: Option<i64>,
        ncpu: Option<i64>,
        disk_kb: Option<i64>,
    ) -> Self {
        self.req_min_mem_kb = mem_kb;
        self.req_min_ncpu = ncpu;
        self.req_min_disk_kb = disk_kb;
        self
    }

    /// 设置产品配置原文快照（insert 时随 db 行写 builds.product_config_toml）。
    pub fn with_product_config_toml(mut self, toml: Option<&'a str>) -> Self {
        self.product_config_toml = toml;
        self
    }

    /// 设置任务级标签（本地自建任务行连同标签原子创建）。
    pub fn with_task_labels(mut self, labels: &'a [(String, String)]) -> Self {
        self.task_labels = labels;
        self
    }
}

/// 封装构建状态机：pending → building → succeeded/failed/cancelled/timeout。
/// 创建时插入 pending 记录并获取自增 ID，状态转换统一经本类型走 StateStore。
pub struct BuildLifecycle {
    build_id: i64,
    /// 关联任务 id（server 传入或本地任务化自建；`builds.task_id` NOT NULL 恒有值）。
    task_id: i64,
    state: Arc<StateStore>,
    /// 构建资源采样结果（脚本执行期间由资源采样器累计，终态写入时随
    /// `complete_build` 落资源列：三值 + 采集包络）。`None` = 未采样 / 无数据，落 NULL。
    resources: Option<ResourceUsage>,
}

impl BuildLifecycle {
    /// 创建生命周期实例并插入 pending 记录，获取自增 ID。插入失败返回
    /// `CrbsError::Database`（同 identity 活跃构建重复为 `Conflict`），由调用方处理。
    pub async fn new(
        state: Arc<StateStore>,
        product: &str,
        pkg_name: &str,
        user: Option<&str>,
        crbs_pid: Option<i64>,
        priority: BuildPriority,
    ) -> crate::Result<Self> {
        let identity = BuildIdentity::new(product, pkg_name);
        let context = BuildContext::new(priority)
            .with_user(user.unwrap_or(""), None)
            .with_crbs_pid(crbs_pid);
        Self::new_with_request(state, &identity, &context).await
    }

    /// 创建生命周期实例并插入 pending 记录，同时关联到用户可见任务。
    pub async fn new_with_task(
        state: Arc<StateStore>,
        identity: &BuildIdentity<'_>,
        context: &BuildContext<'_>,
    ) -> crate::Result<Self> {
        Self::new_with_request(state, identity, context).await
    }

    /// 使用打包后的 `BuildIdentity` 和 `BuildContext` 创建生命周期实例。
    /// 引擎本地任务化：task_id=None（引擎本地路径；server 恒带 Some 不经此
    /// 分支）先插本地任务行再插 build，满足 `builds.task_id NOT NULL`；
    /// phase 回写复用 store 事务内聚合（单构建任务镜像构建终态），本层无需回写。
    async fn new_with_request(
        state: Arc<StateStore>,
        identity: &BuildIdentity<'_>,
        context: &BuildContext<'_>,
    ) -> crate::Result<Self> {
        // local_task：本函数是否自建了本地任务行——insert_build 失败时只有
        // 自建的行才做补偿（server 传入的 task 不归本函数生命周期管）。
        let (task_id, local_task) = match context.task_id {
            Some(t) => (t, false),
            None => {
                let operation = format!("insert local task for build of {}", identity.pkg_name);
                // db_ctx 上下文以 &str 预绑定：async move 块若直接按值捕获
                // String，FnMut 第二次尝试即 E0507。
                let ctx: &str = operation.as_str();
                (
                    retry_local_insert(&state, &operation, || {
                        // Arc 按尝试克隆：async move 若按值捕获外层 state，
                        // FnMut 第二次尝试即 E0507。
                        let state = state.clone();
                        let task = TaskInsert {
                            product: identity.product,
                            pkg_name: identity.pkg_name,
                            user: context.user.unwrap_or(""),
                            user_id: None,
                            phase: "pending",
                            priority: context.priority,
                            srpm_path: context.srpm_path,
                            result_dir: None,
                            request_json: None,
                            pkg_names: None,
                        };
                        let labels = context.task_labels;
                        async move {
                            if labels.is_empty() {
                                state.insert_task(task).await.db_ctx(ctx)
                            } else {
                                state
                                    .create_task_with_labels(task, labels)
                                    .await
                                    .db_ctx(ctx)
                            }
                        }
                    })
                    .await?,
                    true,
                )
            }
        };
        let operation = format!("insert pending build for {}", identity.pkg_name);
        let build_id = match retry_local_insert(&state, &operation, || {
            state.insert_build(BuildInsert {
                product: identity.product,
                pkg_name: identity.pkg_name,
                phase: "pending",
                result_dir: None,
                layer_digest: None,
                base_os_digest: None,
                backend: "",
                user: context.user.unwrap_or(""),
                user_id: context.user_id,
                crbs_pid: context.crbs_pid,
                priority: context.priority,
                arch: context.arch,
                host_arches: context.host_arches,
                repo_publish: context.repo_publish,
                repo_consume: context.repo_consume,
                req_min_mem_kb: context.req_min_mem_kb,
                req_min_ncpu: context.req_min_ncpu,
                req_min_disk_kb: context.req_min_disk_kb,
                task_id: Some(task_id),
            })
        })
        .await
        {
            Ok(id) => id,
            Err(e) => {
                // 补偿：insert_build 失败（Conflict 或 DB 故障）时自建任务行
                // 成 0-build pending 孤儿——引擎本地库无 sweeper 永久滞留；
                // mark_task_failed 收口（自带仅 pending 可翻终态守卫），补偿
                // 失败仅 warn；server 传入 task（local_task=false）不动。
                if local_task {
                    if let Err(comp) = state.mark_task_failed(task_id).await {
                        tracing::warn!(
                            task_id = %task_id,
                            error = %comp,
                            "insert_build failed; compensating local task row also failed (orphan pending task left for sweeper)"
                        );
                    }
                }
                match e {
                    // Conflict 原样透传（服务端映射 409）；db_ctx 会把 CrbsError
                    // 一律重包成 Database 丢变体，409 退化 500。
                    e @ crate::error::CrbsError::Conflict { .. } => return Err(e),
                    // 其余错误沿用 db_ctx 包装（含 DatabaseUnavailable 分类）。
                    e => Err::<i64, crate::error::CrbsError>(e).db_ctx(&operation)?,
                }
            }
        };
        // 快照是审计/调试锚：写失败只降级（debug 回落当前配置），不阻断构建。
        if let Some(toml) = context.product_config_toml {
            if let Err(e) = state.set_build_product_config_toml(build_id, toml).await {
                tracing::warn!(
                    build_id,
                    error = %e,
                    "failed to persist product config snapshot; debug will fall back to current config"
                );
            }
        }
        Ok(Self {
            build_id,
            task_id,
            state,
            resources: None,
        })
    }

    /// 本次构建的 build id。
    pub fn build_id(&self) -> i64 {
        self.build_id
    }

    /// 关联任务 id（server 批量提交传入的 task，或引擎本地任务化自建的 task）。
    pub fn task_id(&self) -> i64 {
        self.task_id
    }

    /// 关联到一条已存在的 pending 构建记录并把 crbs_pid 更新为当前进程
    ///（server 崩溃重启恢复用，防 zombie repair 误判孤儿）。0 行（构建不
    /// 存在）报错——静默成功会让后续状态转换作用在幽灵 build_id 上。
    pub async fn attach(
        state: Arc<StateStore>,
        build_id: i64,
        crbs_pid: i64,
    ) -> crate::Result<Self> {
        let affected = state.update_build_crbs_pid(build_id, crbs_pid).await?;
        if affected == 0 {
            return Err(crate::error::CrbsError::ValidationFailed {
                message: format!("Build {} does not exist; cannot attach lifecycle", build_id),
            });
        }
        // task_id NOT NULL；缺失属前代遗留行，报内部错误而非静默占位。
        let task_id = state
            .get_build(build_id)
            .await?
            .and_then(|r| r.task_id)
            .ok_or_else(|| {
                crate::error::CrbsError::Internal(format!(
                    "build {build_id} has no task_id (pre-v6 legacy row)"
                ))
            })?;
        Ok(Self {
            build_id,
            task_id,
            state,
            resources: None,
        })
    }

    /// worker 远程任务生命周期：以 hub 下发的 build id 落本地镜像行并 attach
    ///（本地行缺失先经 `StateStore::seed_remote_build_mirror` 播种，终态行
    /// 重置 pending）。attach 后 `build_id()` 即 hub id——profile.json /
    /// crbs-artifacts.json / 结果目录叶子随之统一 hub id 空间，不写引擎
    /// 本地自增 id。
    pub async fn attach_remote(
        state: Arc<StateStore>,
        build_id: i64,
        product: &str,
        pkg_name: &str,
        crbs_pid: i64,
    ) -> crate::Result<Self> {
        state
            .seed_remote_build_mirror(build_id, product, pkg_name)
            .await?;
        Self::attach(state, build_id, crbs_pid).await
    }

    /// 统一 `update_*` 状态调用的错误包装：失败转 `CrbsError::Database`（后端
    /// 不可用经 `DbErrorClassify` 转 `DatabaseUnavailable`），消息带 what/build_id。
    async fn db_op<E: std::fmt::Display + crate::error::DbErrorClassify>(
        &self,
        what: &str,
        fut: impl std::future::Future<Output = Result<(), E>>,
    ) -> crate::Result<()> {
        fut.await.db_ctx(&format!("{} for {}", what, self.build_id))
    }

    /// pending → building。重复调用安全：SQL 守卫只允许 assigned/building
    ///（终态不可回退，见 state/builds.rs），server 早期调用后引擎可再调；失败返回 `Err`。
    /// 瞬态 DB 故障（池耗尽 / 锁忙等后端不可用）退避重试后仍失败才返回——
    /// 高并发下单次忙等不得把构建判死。
    pub async fn start_building(&self) -> crate::Result<()> {
        retry_transient_db(
            &self.state,
            "update build phase to building",
            self.build_id,
            || {
                self.db_op(
                    "update build phase to building",
                    self.state.update_build_phase(self.build_id, "building"),
                )
            },
        )
        .await
    }

    /// 补充 result_dir / base_os_digest / backend 等构建信息；失败返回 `Err`。
    pub async fn set_info(
        &self,
        result_dir: Option<&str>,
        base_os_digest: Option<&str>,
        backend: &str,
    ) -> crate::Result<()> {
        self.db_op(
            "update build info",
            self.state
                .update_build_info(self.build_id, result_dir, base_os_digest, backend),
        )
        .await
    }

    /// 补充 SharedLayer digest；失败返回 `Err`。
    pub async fn set_layer_digest(&self, digest: &str) -> crate::Result<()> {
        self.db_op(
            "update build layer info",
            self.state.update_build_layer_info(self.build_id, digest),
        )
        .await
    }

    /// 记录资源采样结果（脚本执行结束后、终态写入前调用；取消路径等
    /// 无采样数据的场景不调用，资源列保持 NULL）。
    pub fn set_resources(&mut self, resources: Option<ResourceUsage>) {
        self.resources = resources;
    }

    /// 标记构建终态。消费 self，防终态后再转换。失败返回 `Err`（DB 故障）；
    /// 守卫拒绝（0 行：已被并发取消/完成）不算 DB 失败，仅 warn 返回 Ok。
    /// 返回 `true` = 赢下终态写入（first-writer-wins）；`false` = 并发方
    ///（取消/修复器）已先到——"恰好一次"副作用（引用释放）以返回值为准，输家不得执行。
    pub async fn complete(
        self,
        outcome: BuildOutcome,
        result_dir: Option<&str>,
    ) -> crate::Result<bool> {
        let phase = outcome.phase();
        // 取消终态不落资源（与 worker 上报取消臂同一口径：取消不是执行方的
        // 能力度量场景），三列保持 NULL；failed/timeout 尽力携带已采值。
        let resources = match outcome {
            BuildOutcome::Cancelled => None,
            _ => self.resources,
        };
        // 终态写纳入 transient 重试：高并发突发下 busy 单次烧穿曾被清理护栏
        // 吞掉，本地行滞留活跃态、反手封死同 identity 的后续构建（陈旧
        // 活跃行的主要来源）。busy 路径语句未提交、重放安全；守卫拒绝
        // （Ok(0)）非错误，不经重试。
        let op = format!("complete build {} as {}", self.build_id, phase);
        let affected = retry_transient_db(&self.state, &op, self.build_id, || {
            self.state
                .complete_build_with_resources(self.build_id, phase, result_dir, resources)
        })
        .await
        .db_ctx(&op)?;
        if affected == 0 {
            tracing::warn!(
                build_id = %self.build_id,
                phase = phase,
                "Terminal-state guard rejected completion (concurrently cancelled/completed); keeping existing terminal phase"
            );
            return Ok(false);
        }
        Ok(true)
    }
}

/// 引擎本地库全部写路径（本地任务行 / pending build 行插入、相位更新、终态
/// 收口）统一的 transient 重试预算：5 次尝试、退避满值 400ms → 3.2s（half
/// jitter）。预算依据（冷启动写风暴实测）：单次尝试最多等待 busy_timeout
/// 5s，风暴窗口为数十秒量级——3 次预算 ≈ 15s 只够短风暴，相位路径 35 次
/// 重试事件耗尽 12 次（34%）；insert 路径同参数 5 次预算挽回 89%，故全写
/// 路径拉齐到该档（上限 ≈ 5 × 5s busy 等待 + 退避 3-6s ≈ 28-31s，清理护栏
/// 的终态步骤预算须随之覆盖，见 engine::build::cleanup_guard）。单次尝试内
/// 的短争用由 busy_timeout 吸收，重试只兜长持锁。
const LOCAL_WRITE_RETRY_ATTEMPTS: u32 = 5;
const LOCAL_WRITE_RETRY_BASE_DELAY: Duration = Duration::from_millis(400);

/// 引擎本地库非幂等插入（本地任务行、pending build 行）的热路径写入口：
/// 先取进程内写漏斗许可（SQLite 方言下该库生命周期短写串行执行——写者在
/// 进程内微秒级排队，而非各自撞 SQLITE_BUSY 再按秒退避；PG 返回空许可
/// 原样并发），再进 transient 退避重试（预算与重放安全语义见
/// [`retry_local_insert_core`]，保留为外部进程持锁场景的兜底）。
async fn retry_local_insert<T, F, Fut>(
    state: &StateStore,
    operation: &str,
    f: F,
) -> crate::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = crate::Result<T>>,
{
    let _permit = state.local_write_permit().await;
    retry_local_insert_core(operation, f).await
}

/// 本地插入的 transient 退避重试（预算 = [`LOCAL_WRITE_RETRY_ATTEMPTS`]
/// 全写路径统一档）：仅 [`CrbsError::is_transient`] 重试（后端不可用族：
/// SQLite busy 等锁超 busy_timeout、池耗尽；SQL 语义 Database、
/// ValidationFailed、Conflict、Cancelled 不重试原样返回），每次重试 warn
/// 带操作名、尝试序号与退避，预算耗尽返回最后一次原始错误。重放安全性：
/// BUSY 路径语句未提交、重放无副作用；is_transient 尾部语义（PoolClosed
/// 等）理论上丢提交，由调用方终态化兜底，不依赖重放。
async fn retry_local_insert_core<T, F, Fut>(operation: &str, mut f: F) -> crate::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = crate::Result<T>>,
{
    let outcome = retry_with_policy(
        LOCAL_WRITE_RETRY_ATTEMPTS,
        LOCAL_WRITE_RETRY_BASE_DELAY,
        None,
        |e: &CrbsError| e.is_transient(),
        |_: &T| false,
        |cause, attempt, delay| {
            if let RetryCause::Error(e) = cause {
                tracing::warn!(
                    operation = %operation,
                    attempt,
                    delay_ms = delay.as_millis() as u64,
                    error = %e,
                    "Transient local insert failure; retrying"
                );
            }
        },
        |_| f(),
    )
    .await;
    match outcome {
        Ok(v) => Ok(v),
        Err(RetryBreak::Inner(e)) => Err(e),
        // 无令牌传入，取消臂不可达；映射与相位重试层同型。
        Err(RetryBreak::Cancelled) => Err(CrbsError::Cancelled),
    }
}

/// 生命周期相位写（中间态更新、终态收口）的热路径写入口：先取进程内写
/// 漏斗许可（语义同 [`retry_local_insert`]），再进 transient 退避重试
///（预算与幂等性依据见 [`retry_transient_db_core`]）。
async fn retry_transient_db<T, F, Fut>(
    state: &StateStore,
    operation: &str,
    build_id: i64,
    f: F,
) -> crate::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = crate::Result<T>>,
{
    let _permit = state.local_write_permit().await;
    retry_transient_db_core(operation, build_id, f).await
}

/// 相位写的 transient 退避重试（预算 = [`LOCAL_WRITE_RETRY_ATTEMPTS`]
/// 全写路径统一档）：仅 [`CrbsError::is_transient`]
/// 重试（后端不可用族；4xx 族 ValidationFailed、SQL 语义 Database、取消原样
/// 返回），每次重试 warn 带尝试序号与错误。无取消令牌：预算上限 ≈31s +
/// 逐次 busy_timeout，取消感知接线仍不划算——清理护栏终态步骤预算与构建
/// 总预算在上游兜底；重放安全依赖相位 CAS / 终态守卫的幂等性（busy 路径
/// 语句未提交）。
async fn retry_transient_db_core<T, F, Fut>(
    operation: &str,
    build_id: i64,
    mut f: F,
) -> crate::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = crate::Result<T>>,
{
    let outcome = retry_with_policy(
        LOCAL_WRITE_RETRY_ATTEMPTS,
        LOCAL_WRITE_RETRY_BASE_DELAY,
        None,
        |e: &CrbsError| e.is_transient(),
        |_: &T| false,
        |cause, attempt, delay| {
            if let RetryCause::Error(e) = cause {
                tracing::warn!(
                    build_id = %build_id,
                    operation = %operation,
                    attempt,
                    delay_ms = delay.as_millis() as u64,
                    error = %e,
                    "Transient phase update failure; retrying"
                );
            }
        },
        |_| f(),
    )
    .await;
    match outcome {
        Ok(v) => Ok(v),
        Err(RetryBreak::Inner(e)) => Err(e),
        // 无令牌传入，取消臂不可达；映射与 worker retry 层同型。
        Err(RetryBreak::Cancelled) => Err(CrbsError::Cancelled),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_lifecycle_creates_pending_record() {
        let tmp = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::state::StateStore::new(tmp.path()).await.unwrap());

        let lifecycle = BuildLifecycle::new(
            state.clone(),
            "fedora",
            "hello",
            Some("tester"),
            Some(1234),
            0,
        )
        .await
        .unwrap();
        let record = state
            .get_build(lifecycle.build_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.phase, "pending");
        assert_eq!(record.product, "fedora");
        assert_eq!(record.pkg_name, "hello");
        assert_eq!(record.user, "tester");
        assert_eq!(record.crbs_pid, Some(1234));
        assert!(lifecycle.build_id() >= 1);
    }

    /// 构建行创建时同写配置快照与任务标签；标签与任务行同事务落库。
    #[tokio::test]
    async fn test_lifecycle_anchors_config_snapshot_and_task_labels() {
        let tmp = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::state::StateStore::new(tmp.path()).await.unwrap());
        let snapshot = "product = \"fedora\"\nbase_packages = [\"bash\"]\nrepos = []\n";
        let labels = vec![
            (
                "git-repo".to_string(),
                "https://example.com/a.git".to_string(),
            ),
            ("git-commit".to_string(), "abc123".to_string()),
        ];
        let context = BuildContext::new(0)
            .with_user("tester", None)
            .with_product_config_toml(Some(snapshot))
            .with_task_labels(&labels);
        let identity = BuildIdentity::new("fedora", "hello");

        let lifecycle = BuildLifecycle::new_with_task(state.clone(), &identity, &context)
            .await
            .unwrap();
        assert_eq!(
            state
                .get_build_product_config_toml(lifecycle.build_id())
                .await
                .unwrap()
                .as_deref(),
            Some(snapshot)
        );
        // 读取按 key 排序，与插入顺序无关。
        let mut expected = labels.clone();
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            state.get_task_labels(lifecycle.task_id()).await.unwrap(),
            expected
        );
    }

    #[tokio::test]
    async fn test_lifecycle_transitions_to_building_and_succeeded() {
        let tmp = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::state::StateStore::new(tmp.path()).await.unwrap());

        let lifecycle = BuildLifecycle::new(state.clone(), "fedora", "hello", None, None, 0)
            .await
            .unwrap();
        let build_id = lifecycle.build_id();

        lifecycle.start_building().await.unwrap();
        lifecycle
            .set_info(Some("/tmp/result"), Some("digest-abc"), "chroot")
            .await
            .unwrap();
        assert!(
            lifecycle
                .complete(BuildOutcome::Succeeded, Some("/tmp/result"))
                .await
                .unwrap(),
            "first terminal write must win the race (Ok(true))"
        );

        let record = state.get_build(build_id).await.unwrap().unwrap();
        assert_eq!(record.phase, "succeeded");
        assert_eq!(record.result_dir.as_deref(), Some("/tmp/result"));
        assert_eq!(record.base_os_digest.as_deref(), Some("digest-abc"));
        assert_eq!(record.backend.as_deref(), Some("chroot"));
        assert!(record.completed_at.is_some());
        assert!(record.duration >= Some(0));
    }

    #[tokio::test]
    async fn test_start_building_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::state::StateStore::new(tmp.path()).await.unwrap());

        let lifecycle = BuildLifecycle::new(state.clone(), "fedora", "hello", None, None, 0)
            .await
            .unwrap();
        let build_id = lifecycle.build_id();

        lifecycle.start_building().await.unwrap();
        lifecycle.start_building().await.unwrap();

        let record = state.get_build(build_id).await.unwrap().unwrap();
        assert_eq!(record.phase, "building");
    }

    /// transient 重试：第 2 次尝试成功（后端不可用一次后自愈）。
    #[tokio::test]
    async fn retry_transient_db_succeeds_on_second_attempt() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let result: crate::Result<()> = retry_transient_db_core("op", 7, || {
            let c = calls.fetch_add(1, Ordering::Relaxed) + 1;
            async move {
                if c == 1 {
                    Err(CrbsError::DatabaseUnavailable {
                        context: "begin write".into(),
                        error: "database is locked".into(),
                    })
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert!(
            result.is_ok(),
            "second attempt must succeed, got {result:?}"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    /// 非 transient（4xx 族 ValidationFailed）不重试：单次尝试原样返回。
    #[tokio::test]
    async fn retry_transient_db_does_not_retry_validation_error() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let result: crate::Result<()> = retry_transient_db_core("op", 7, || {
            calls.fetch_add(1, Ordering::Relaxed);
            async {
                Err(CrbsError::ValidationFailed {
                    message: "invalid build phase 'cancelled'".into(),
                })
            }
        })
        .await;
        assert!(matches!(result, Err(CrbsError::ValidationFailed { .. })));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    /// transient 耗尽：烧满 5 次预算（全写路径统一档）后返回最后一次原始
    /// 错误（分类不丢失）。
    #[tokio::test]
    async fn retry_transient_db_exhaustion_returns_original_error() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let result: crate::Result<()> = retry_transient_db_core("op", 7, || {
            calls.fetch_add(1, Ordering::Relaxed);
            async {
                Err(CrbsError::DatabaseUnavailable {
                    context: "acquire conn".into(),
                    error: "pool timed out".into(),
                })
            }
        })
        .await;
        assert!(
            matches!(
                result,
                Err(CrbsError::DatabaseUnavailable { ref context, .. }) if context == "acquire conn"
            ),
            "exhaustion must return the original error, got {result:?}"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 5);
    }

    /// 本地库插入 transient 重试：第 2 次尝试成功（busy 一次后自愈），
    /// 返回值（task id / build id）原样透出。
    #[tokio::test]
    async fn retry_local_insert_succeeds_after_transient_busy() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let result: crate::Result<i64> = retry_local_insert_core(
            "insert local task for build of hello",
            || {
                let c = calls.fetch_add(1, Ordering::Relaxed) + 1;
                async move {
                    if c == 1 {
                        Err(CrbsError::DatabaseUnavailable {
                            context: "insert local task for build of hello".into(),
                            error:
                                "insert task: error returned from database: database is locked (code: 5)"
                                    .into(),
                        })
                    } else {
                        Ok(42)
                    }
                }
            },
        )
        .await;
        assert_eq!(
            result.unwrap(),
            42,
            "task id must pass through the retry layer"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    /// 非 transient（SQL 语义 Database，如唯一约束）不重试：单次尝试原样返回。
    #[tokio::test]
    async fn retry_local_insert_does_not_retry_semantic_error() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let result: crate::Result<i64> = retry_local_insert_core("insert local task", || {
            calls.fetch_add(1, Ordering::Relaxed);
            async {
                Err(CrbsError::Database(
                    "insert task: error returned from database: UNIQUE constraint failed".into(),
                ))
            }
        })
        .await;
        assert!(
            matches!(result, Err(CrbsError::Database(ref msg)) if msg.contains("UNIQUE constraint")),
            "semantic error must propagate as-is, got {result:?}"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    /// transient 耗尽：烧满 5 次预算后返回最后一次原始错误（变体与上下文不丢失）。
    #[tokio::test]
    async fn retry_local_insert_exhaustion_returns_original_error() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let result: crate::Result<i64> = retry_local_insert_core(
            "insert local task for build of hello",
            || {
                calls.fetch_add(1, Ordering::Relaxed);
                async {
                    Err(CrbsError::DatabaseUnavailable {
                        context: "insert local task for build of hello".into(),
                        error: "insert task: error returned from database: database is locked (code: 5)"
                            .into(),
                    })
                }
            },
        )
        .await;
        assert!(
            matches!(
                result,
                Err(CrbsError::DatabaseUnavailable { ref context, .. })
                    if context == "insert local task for build of hello"
            ),
            "exhaustion must return the original error, got {result:?}"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 5);
    }

    /// 本地库写锁短争用（< busy_timeout）：busy_timeout 独自吸收，插入单次
    /// 成功——第二连接 BEGIN EXCLUSIVE 持锁后定时提交，insert 等锁至提交后
    /// 落行。elapsed < 5s（首次 busy 预算）即未走重试臂。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn insert_local_task_waits_out_sub_busy_timeout_contention() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let blocker = contended_exclusive_conn(tmp.path().join("crbs.db")).await;

        let mut conn = blocker.acquire().await.unwrap();
        sqlx::query("BEGIN EXCLUSIVE")
            .execute(&mut *conn)
            .await
            .unwrap();

        let started = std::time::Instant::now();
        let holder = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            sqlx::query("COMMIT").execute(&mut *conn).await.unwrap();
        });
        let lifecycle = BuildLifecycle::new(store.clone(), "fedora", "hello", None, None, 0)
            .await
            .expect("sub-busy_timeout contention must be absorbed by busy_timeout alone");
        let elapsed = started.elapsed();
        holder.await.unwrap();

        assert!(
            elapsed >= Duration::from_secs(1),
            "insert must have waited out the lock holder, got {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "single-attempt busy wait must resolve under busy_timeout; the retry arm would push elapsed past 5s, got {elapsed:?}"
        );
        let record = store
            .get_build(lifecycle.build_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.phase, "pending");
    }

    /// 本地库写锁长持锁（> busy_timeout 5s）：单次尝试烧穿 busy_timeout 得
    /// SQLITE_BUSY → DatabaseUnavailable（transient）→ 重试臂兜底，持锁释放
    /// 后重插成功——压测突发下 insert-local-task 即时烧单的回归钉。持锁 6s：
    /// 首次 busy_timeout 5s 到期，退避 ~0.2-0.4s 后第二次尝试在 busy 预算内
    /// 等到锁释放即成功。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn insert_local_task_retries_after_busy_timeout_exhaustion() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let blocker = contended_exclusive_conn(tmp.path().join("crbs.db")).await;

        let mut conn = blocker.acquire().await.unwrap();
        sqlx::query("BEGIN EXCLUSIVE")
            .execute(&mut *conn)
            .await
            .unwrap();

        let started = std::time::Instant::now();
        let holder = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(6)).await;
            sqlx::query("COMMIT").execute(&mut *conn).await.unwrap();
        });
        let lifecycle = BuildLifecycle::new(store.clone(), "fedora", "hello", None, None, 0)
            .await
            .expect("retry arm must recover after the lock is released");
        let elapsed = started.elapsed();
        holder.await.unwrap();

        assert!(
            elapsed >= Duration::from_secs(5),
            "first attempt must have exhausted busy_timeout before the retry arm engaged, got {elapsed:?}"
        );
        let record = store
            .get_build(lifecycle.build_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.phase, "pending");
    }

    /// 本地库写锁长持锁命中 insert pending build 调用点：task_id 预置跳过
    /// 任务行插入，生命周期首个本地库写即 insert_build——持锁 6s 烧穿首次
    /// busy_timeout（5s）得 SQLITE_BUSY → DatabaseUnavailable（transient）→
    /// 重试臂兜底，持锁释放后重插成功。压测突发下 pending build 插入即时
    /// 烧单的回归钉（insert-local-task 调用点已有同型钉）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn insert_pending_build_retries_after_busy_timeout_exhaustion() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let existing_task = store
            .insert_task(crate::state::TaskInsert {
                product: "fedora",
                pkg_name: "hello-1.0-1",
                user: "tester",
                phase: "pending",
                ..Default::default()
            })
            .await
            .unwrap();
        let blocker = contended_exclusive_conn(tmp.path().join("crbs.db")).await;

        let mut conn = blocker.acquire().await.unwrap();
        sqlx::query("BEGIN EXCLUSIVE")
            .execute(&mut *conn)
            .await
            .unwrap();

        let started = std::time::Instant::now();
        let holder = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(6)).await;
            sqlx::query("COMMIT").execute(&mut *conn).await.unwrap();
        });
        let identity = BuildIdentity::new("fedora", "hello");
        let context = BuildContext::new(0)
            .with_user("tester", None)
            .with_task_id(Some(existing_task));
        let lifecycle = BuildLifecycle::new_with_task(store.clone(), &identity, &context)
            .await
            .expect("retry arm must recover after the lock is released");
        let elapsed = started.elapsed();
        holder.await.unwrap();

        assert!(
            elapsed >= Duration::from_secs(5),
            "first attempt must have exhausted busy_timeout before the retry arm engaged, got {elapsed:?}"
        );
        let record = store
            .get_build(lifecycle.build_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.phase, "pending");
        assert_eq!(record.task_id, Some(existing_task));
    }

    /// 本地库写锁长持锁命中终态收口（complete）：持锁 6s 烧穿首次
    /// busy_timeout（5s）→ DatabaseUnavailable（transient）→ 重试臂兜底，
    /// 持锁释放后终态写成功。陈旧活跃行回归钉——单次 busy 失败被清理护栏
    /// 吞掉时，行滞留 building 会封死同 identity 的后续构建。预算界：
    /// 5 × busy_timeout + 退避 ≈ 28-31s < 清理护栏终态步骤预算 60s（见
    /// LOCAL_WRITE_RETRY 与 COMPLETE_STEP_BUDGET 常量 doc），耗尽臂不另做
    /// 集成测试（18s 级挂锁不可接受）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn complete_retries_after_busy_timeout_exhaustion() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let lifecycle = BuildLifecycle::new(store.clone(), "fedora", "hello", None, None, 0)
            .await
            .unwrap();
        lifecycle.start_building().await.unwrap();
        let build_id = lifecycle.build_id();

        let blocker = contended_exclusive_conn(tmp.path().join("crbs.db")).await;
        let mut conn = blocker.acquire().await.unwrap();
        sqlx::query("BEGIN EXCLUSIVE")
            .execute(&mut *conn)
            .await
            .unwrap();
        let holder = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(6)).await;
            sqlx::query("COMMIT").execute(&mut *conn).await.unwrap();
        });

        let started = std::time::Instant::now();
        let won = lifecycle
            .complete(BuildOutcome::Succeeded, None)
            .await
            .expect("retry arm must land the terminal write after the lock is released");
        let elapsed = started.elapsed();
        holder.await.unwrap();

        assert!(won, "complete must win the terminal write");
        assert!(
            elapsed >= Duration::from_secs(5),
            "first attempt must have exhausted busy_timeout before the retry arm engaged, got {elapsed:?}"
        );
        let record = store.get_build(build_id).await.unwrap().unwrap();
        assert_eq!(record.phase, "succeeded");
    }

    /// 打开指向同一 SQLite 文件的独立阻塞连接（busy 谓词测试的持锁方）。
    /// 默认连接选项即可：BEGIN EXCLUSIVE 在无并发写者时即时拿锁，COMMIT
    /// 不受 busy_timeout 影响。
    async fn contended_exclusive_conn(db_path: std::path::PathBuf) -> sqlx::sqlite::SqlitePool {
        sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&format!("sqlite://{}", db_path.display()))
            .await
            .unwrap()
    }

    /// 漏斗互斥钉：并发生命周期写共用每库一把写漏斗——任一时刻至多一个
    /// 写者在闸内（进出计数峰值 = 1），串行化是"漏斗后 busy 重试退为罕见
    /// 兜底"的正确性前提。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn local_write_permit_admits_one_writer_at_a_time() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());

        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let (store, in_flight, max_in_flight) =
                (store.clone(), in_flight.clone(), max_in_flight.clone());
            handles.push(tokio::spawn(async move {
                for _ in 0..16 {
                    let _permit = store.local_write_permit().await;
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    max_in_flight.fetch_max(now, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(
            max_in_flight.load(Ordering::SeqCst),
            1,
            "write funnel must admit exactly one writer at a time"
        );
    }

    /// 并发风暴：16 个并发生命周期（本地任务行 / pending build / 相位 / 终态，
    /// 计 64 条短写）穿越外部 BEGIN EXCLUSIVE 持锁窗口（1s）全部成功——写
    /// 漏斗把进程内写者串行化，只有队头写者进 busy 等待窗口（1s < busy_timeout
    /// 5s，单次尝试吸收、不进重试臂），其余写者在漏斗上排队、持锁释放后毫秒
    /// 级放行。elapsed < 5s（单次 busy 预算）钉住无 BUSY 逃逸——逃逸即烧穿
    /// busy_timeout 进重试臂，总耗时必过 5s；终态逐行核对。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_lifecycle_writes_funnel_through_busy_window() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let blocker = contended_exclusive_conn(tmp.path().join("crbs.db")).await;

        let mut conn = blocker.acquire().await.unwrap();
        sqlx::query("BEGIN EXCLUSIVE")
            .execute(&mut *conn)
            .await
            .unwrap();
        let holder = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            sqlx::query("COMMIT").execute(&mut *conn).await.unwrap();
        });

        let started = std::time::Instant::now();
        let mut handles = Vec::new();
        for i in 0..16 {
            let store = store.clone();
            let pkg = format!("storm-pkg-{i}");
            handles.push(tokio::spawn(async move {
                let lifecycle = BuildLifecycle::new(store, "fedora", &pkg, None, None, 0)
                    .await
                    .expect("funneled lifecycle creation must not fail under write storm");
                let build_id = lifecycle.build_id();
                lifecycle
                    .start_building()
                    .await
                    .expect("funneled phase write must not fail under write storm");
                lifecycle
                    .complete(BuildOutcome::Succeeded, None)
                    .await
                    .expect("funneled terminal write must not fail under write storm");
                build_id
            }));
        }
        let mut build_ids = Vec::new();
        for h in handles {
            build_ids.push(h.await.unwrap());
        }
        let elapsed = started.elapsed();
        holder.await.unwrap();

        let unique: std::collections::HashSet<_> = build_ids.iter().collect();
        assert_eq!(
            unique.len(),
            16,
            "every lifecycle must land its own build row"
        );
        for build_id in &build_ids {
            let record = store.get_build(*build_id).await.unwrap().unwrap();
            assert_eq!(
                record.phase, "succeeded",
                "storm build {build_id} must reach terminal phase"
            );
        }
        assert!(
            elapsed < Duration::from_secs(5),
            "storm must drain inside a single busy_timeout budget (no BUSY escape into the retry arm), got {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn test_lifecycle_failed_outcome() {
        let tmp = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::state::StateStore::new(tmp.path()).await.unwrap());

        let lifecycle = BuildLifecycle::new(state.clone(), "fedora", "hello", None, None, 0)
            .await
            .unwrap();
        let build_id = lifecycle.build_id();

        lifecycle.start_building().await.unwrap();
        lifecycle
            .complete(BuildOutcome::Failed, None)
            .await
            .unwrap();

        let record = state.get_build(build_id).await.unwrap().unwrap();
        assert_eq!(record.phase, "failed");
        assert!(record.completed_at.is_some());
    }

    #[tokio::test]
    async fn test_lifecycle_layer_digest_update() {
        let tmp = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::state::StateStore::new(tmp.path()).await.unwrap());

        let lifecycle = BuildLifecycle::new(state.clone(), "fedora", "hello", None, None, 0)
            .await
            .unwrap();
        let build_id = lifecycle.build_id();
        lifecycle.set_layer_digest("layer-digest-1").await.unwrap();

        let record = state.get_build(build_id).await.unwrap().unwrap();
        assert_eq!(record.layer_digest.as_deref(), Some("layer-digest-1"));
    }

    #[tokio::test]
    async fn test_lifecycle_attach_updates_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::state::StateStore::new(tmp.path()).await.unwrap());

        let lifecycle = BuildLifecycle::new(state.clone(), "fedora", "hello", None, Some(1), 0)
            .await
            .unwrap();
        let build_id = lifecycle.build_id();

        let attached = BuildLifecycle::attach(state.clone(), build_id, 12345)
            .await
            .unwrap();
        assert_eq!(attached.build_id(), build_id);

        let record = state.get_build(build_id).await.unwrap().unwrap();
        assert_eq!(record.crbs_pid, Some(12345));
        assert_eq!(record.phase, "pending");
    }

    /// attach 到不存在的 build_id 不得静默成功（0 行 → 报错），防幽灵 build_id。
    #[tokio::test]
    async fn test_lifecycle_attach_rejects_nonexistent_build() {
        let tmp = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::state::StateStore::new(tmp.path()).await.unwrap());

        // 不用 expect_err：BuildLifecycle 无 Debug 实现（内部持有 StateStore）。
        let err = match BuildLifecycle::attach(state, 424242, 12345).await {
            Ok(_) => panic!("attach to nonexistent build should fail"),
            Err(e) => e,
        };
        match err {
            crate::error::CrbsError::ValidationFailed { ref message } => {
                assert!(
                    message.contains("424242") && message.contains("cannot attach"),
                    "error should name the build and the action, got: {}",
                    message
                );
            }
            other => panic!("expected ValidationFailed, got: {:?}", other),
        }
    }

    /// worker hub id 镜像行（attach_remote）：lifecycle.build_id() == hub 下发
    /// id——profile.json / crbs-artifacts.json 的 build_id 与结果目录叶子均取
    /// 此值（provenance 与 BuildOutputs 同源于 lifecycle.build_id()），不得再
    /// 写本地自增 id（实证 hub build 101 曾落成 25）。重派重执行臂：终态行
    /// 重置 pending、attach 续跑同一 hub id。
    #[tokio::test]
    async fn attach_remote_seeds_mirror_row_and_lands_hub_build_id() {
        let tmp = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::state::StateStore::new(tmp.path()).await.unwrap());

        let lifecycle = BuildLifecycle::attach_remote(state.clone(), 101, "mydist", "hello", 12345)
            .await
            .unwrap();
        assert_eq!(
            lifecycle.build_id(),
            101,
            "lifecycle must land on the hub-assigned build id"
        );
        let record = state.get_build(101).await.unwrap().unwrap();
        assert!(
            record.task_id.is_some(),
            "mirror row must satisfy the NOT NULL task_id invariant"
        );

        lifecycle
            .complete(BuildOutcome::Failed, None)
            .await
            .unwrap();

        // 重派重执行：终态镜像行重置 pending，attach 续跑同一 hub id。
        let retried = BuildLifecycle::attach_remote(state.clone(), 101, "mydist", "hello", 12345)
            .await
            .unwrap();
        assert_eq!(retried.build_id(), 101);
        let record = state.get_build(101).await.unwrap().unwrap();
        assert_eq!(
            record.phase, "pending",
            "terminal mirror row must be reset for re-execution"
        );

        // 撞号守卫：hub id 与本地自增序列共用整数空间，同 id 的异名行（回退
        // 路径自插的引擎行）拒绝复用/重置——attach 降级由调用方兜底。
        assert!(
            BuildLifecycle::attach_remote(state.clone(), 101, "other", "world", 12345)
                .await
                .is_err(),
            "foreign row under the same id must refuse to seed/attach"
        );
        let record = state.get_build(101).await.unwrap().unwrap();
        assert_eq!(
            record.product, "mydist",
            "collision guard must leave the existing row untouched"
        );
    }

    /// 本地任务化：task_id=None 先插本地任务行，builds.task_id 指向它（user/srpm_path 沿用）。
    #[tokio::test]
    async fn test_lifecycle_without_task_id_creates_local_task() {
        let tmp = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::state::StateStore::new(tmp.path()).await.unwrap());

        let lifecycle = BuildLifecycle::new(
            state.clone(),
            "fedora",
            "hello",
            Some("tester"),
            Some(4321),
            0,
        )
        .await
        .unwrap();

        let record = state
            .get_build(lifecycle.build_id())
            .await
            .unwrap()
            .unwrap();
        let task_id = record
            .task_id
            .expect("local build must reference a task row (no NULL task_id path)");
        let task = state.get_task(task_id).await.unwrap().unwrap();
        assert_eq!(task.phase, "pending");
        assert_eq!(task.product, "fedora");
        assert_eq!(task.pkg_name, "hello");
        assert_eq!(task.user, "tester");
    }

    /// server 提交路径恒带 task_id——不额外建任务，build 挂到既有任务。
    #[tokio::test]
    async fn test_lifecycle_with_task_id_does_not_create_task() {
        let tmp = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::state::StateStore::new(tmp.path()).await.unwrap());

        let existing_task = state
            .insert_task(crate::state::TaskInsert {
                product: "fedora",
                pkg_name: "hello-1.0-1",
                user: "submitter",
                phase: "pending",
                ..Default::default()
            })
            .await
            .unwrap();

        let identity = BuildIdentity::new("fedora", "hello");
        let context = BuildContext::new(0)
            .with_user("submitter", None)
            .with_task_id(Some(existing_task));
        let lifecycle = BuildLifecycle::new_with_task(state.clone(), &identity, &context)
            .await
            .unwrap();

        let record = state
            .get_build(lifecycle.build_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.task_id, Some(existing_task));
        let task = state.get_task(existing_task).await.unwrap().unwrap();
        assert_eq!(task.phase, "pending");
    }

    /// 本地构建终态经 store 事务内聚合链路镜像到本地任务 phase。
    #[tokio::test]
    async fn test_local_task_phase_mirrors_build_terminal_state() {
        let tmp = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::state::StateStore::new(tmp.path()).await.unwrap());

        let lifecycle = BuildLifecycle::new(state.clone(), "fedora", "hello", None, None, 0)
            .await
            .unwrap();
        let build_id = lifecycle.build_id();
        lifecycle.start_building().await.unwrap();
        lifecycle
            .complete(BuildOutcome::Succeeded, Some("/tmp/result"))
            .await
            .unwrap();

        let record = state.get_build(build_id).await.unwrap().unwrap();
        let task = state
            .get_task(record.task_id.expect("local build has task_id"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.phase, "succeeded");
        assert_eq!(task.phase, "succeeded");
    }

    /// 同 identity 活跃重复：insert_build 的 `Conflict` 必须原样透传（服务端
    /// 映射 409）；改走 db_ctx 重包会丢变体退化 500，本测试即红。
    #[tokio::test]
    async fn test_lifecycle_conflict_duplicate_identity_propagates_unwrapped() {
        let (store, _tmp) = crate::state::test_state::create_test_store().await;
        let state = Arc::new(store);

        let identity = BuildIdentity::new("fedora", "hello");
        let context = BuildContext::new(0)
            .with_user("submitter", None)
            .with_arch(Some("x86_64"));
        let first = BuildLifecycle::new_with_task(state.clone(), &identity, &context)
            .await
            .unwrap();
        let record = state.get_build(first.build_id()).await.unwrap().unwrap();
        assert_eq!(record.phase, "pending");

        // 不用 expect_err：BuildLifecycle 无 Debug 实现（内部持有 StateStore）。
        let err = match BuildLifecycle::new_with_task(state, &identity, &context).await {
            Ok(_) => panic!("duplicate active identity must be rejected"),
            Err(e) => e,
        };
        assert!(
            matches!(err, crate::error::CrbsError::Conflict { .. }),
            "Conflict must propagate unwrapped for 409 mapping, got: {err:?}"
        );
    }

    /// 本地任务行补偿：insert_build Conflict 时自建任务行收口为 failed
    ///（0-build pending 孤儿在无 sweeper 的本地库永久滞留），首单任务仍 pending。
    #[tokio::test]
    async fn test_local_task_row_compensated_when_insert_build_conflicts() {
        let (store, _tmp) = crate::state::test_state::create_test_store().await;
        let state = Arc::new(store);

        let identity = BuildIdentity::new("fedora", "hello");
        let context = BuildContext::new(0)
            .with_user("submitter", None)
            .with_arch(Some("x86_64"));
        BuildLifecycle::new_with_task(state.clone(), &identity, &context)
            .await
            .unwrap();

        // 不用 expect_err：BuildLifecycle 无 Debug 实现（内部持有 StateStore）。
        let err = match BuildLifecycle::new_with_task(state.clone(), &identity, &context).await {
            Ok(_) => panic!("duplicate active identity must be rejected"),
            Err(e) => e,
        };
        assert!(matches!(err, crate::error::CrbsError::Conflict { .. }));

        let (failed_total, failed) = state
            .list_tasks(&crate::types::TaskListFilter {
                phase: Some("failed"),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            failed_total, 1,
            "orphaned local task row must be compensated to failed"
        );
        assert!(failed[0].completed_at.is_some());

        let (pending_total, _) = state
            .list_tasks(&crate::types::TaskListFilter {
                phase: Some("pending"),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            pending_total, 1,
            "only the first submission's task may stay pending"
        );
    }

    /// complete 输掉终态竞争（mark_build_cancelled 先到）必须返回 Ok(false)
    /// 而非 Err（守卫拒绝不算 DB 失败），"恰好一次"副作用以返回值为准、输家
    /// 不得执行；cancelled 终态保持不变。正常 Ok(true) 路径由
    /// test_lifecycle_transitions_to_building_and_succeeded 锁定。
    #[tokio::test]
    async fn test_complete_returns_false_when_cancel_won_the_race() {
        let (store, _tmp) = crate::state::test_state::create_test_store().await;
        let state = Arc::new(store);

        let lifecycle = BuildLifecycle::new(state.clone(), "fedora", "hello", None, None, 0)
            .await
            .unwrap();
        let build_id = lifecycle.build_id();
        lifecycle.start_building().await.unwrap();

        state.mark_build_cancelled(build_id).await.unwrap();

        let won = lifecycle
            .complete(BuildOutcome::Succeeded, None)
            .await
            .unwrap();
        assert!(!won, "losing the race to cancel must return Ok(false)");
        let record = state.get_build(build_id).await.unwrap().unwrap();
        assert_eq!(
            record.phase, "cancelled",
            "terminal phase must be kept unchanged"
        );
    }

    /// 资源钉：execute_build 持有的 attach 形态 lifecycle，引擎侧经
    /// [`BuildLifecycle::set_resources`] 交采样累计、[`BuildLifecycle::complete`]
    /// 随终态落资源列，任一环退回"不传/不落"即红。钉到 lifecycle → store
    /// 收口链（完整 execute_build 需真实构建后端）；读回走裸 query（BuildRecord
    /// 未透出三列，口径对齐 state 层 complete_build_writes_resource_columns）。
    #[tokio::test]
    async fn complete_writes_sampled_resources_on_attach_lifecycle() {
        let (store, _tmp) = crate::state::test_state::create_test_store().await;
        let state = Arc::new(store);

        async fn mk_pending(state: &Arc<StateStore>, pkg: &str) -> i64 {
            let task_id = crate::state::test_state::seed_task(state, "fedora", pkg).await;
            state
                .insert_build(BuildInsert {
                    product: "fedora",
                    pkg_name: pkg,
                    phase: "pending",
                    backend: "chroot",
                    user: "tester",
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
                .unwrap()
        }
        async fn read_resources(
            state: &Arc<StateStore>,
            id: i64,
        ) -> (Option<i64>, Option<f64>, Option<f64>) {
            let row = sqlx::query(
                "SELECT peak_rss_kb, cpu_secs, cpu_p90_cores FROM builds WHERE id = $1",
            )
            .bind(id)
            .fetch_one(state.pool())
            .await
            .unwrap();
            use sqlx::Row as _;
            (
                row.get("peak_rss_kb"),
                row.get::<Option<f64>, _>("cpu_secs"),
                row.get::<Option<f64>, _>("cpu_p90_cores"),
            )
        }

        // 成功臂：attach（execute 路径同款）→ set_resources → complete → 三列非 NULL。
        let build_id = mk_pending(&state, "res-hub-1.0").await;
        let mut lifecycle = BuildLifecycle::attach(state.clone(), build_id, 4321)
            .await
            .unwrap();
        lifecycle.set_resources(Some(ResourceUsage {
            peak_rss_kb: Some(250_000),
            cpu_secs: Some(41.5),
            cpu_p90_cores: Some(0.99),
            ..Default::default()
        }));
        assert!(
            lifecycle
                .complete(BuildOutcome::Succeeded, Some("/tmp/result"))
                .await
                .unwrap(),
            "first terminal write must win the race"
        );
        let (peak, cpu, p90) = read_resources(&state, build_id).await;
        assert_eq!(
            peak,
            Some(250_000),
            "peak_rss_kb must land with the terminal write"
        );
        assert_eq!(
            cpu,
            Some(41.5),
            "cpu_secs must land with the terminal write"
        );
        assert_eq!(
            p90,
            Some(0.99),
            "cpu_p90_cores must land with the terminal write"
        );

        // 取消臂：即便采到值，取消终态的资源列保持 NULL。
        let cancelled_id = mk_pending(&state, "res-cancel-1.0").await;
        let mut cancelled = BuildLifecycle::attach(state.clone(), cancelled_id, 4321)
            .await
            .unwrap();
        cancelled.set_resources(Some(ResourceUsage {
            peak_rss_kb: Some(1),
            cpu_secs: Some(1.0),
            cpu_p90_cores: Some(1.0),
            ..Default::default()
        }));
        cancelled
            .complete(BuildOutcome::Cancelled, None)
            .await
            .unwrap();
        let (peak, cpu, p90) = read_resources(&state, cancelled_id).await;
        assert_eq!(
            peak, None,
            "cancelled terminal must keep resource columns NULL"
        );
        assert_eq!(cpu, None);
        assert_eq!(p90, None);
    }
}
