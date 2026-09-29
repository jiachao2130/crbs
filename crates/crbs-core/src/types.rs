// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 跨模块公共类型：构建优先级、构建时长样本等共享定义。

/// 构建优先级类型别名：0=默认（Default），1=高优（High），2=紧急（Critical）。
pub type BuildPriority = i32;

/// 构建优先级常量：0 用户默认档、1 高优、2 紧急（仅 operator 及以上可提交）、-1 系统
/// 后台档（自动重放专用，仅 hub 跟跑路径程序化设置）。校验层
/// `validate_build_priority` 只放行 0-2 用户值；aging 权重
/// `priority*86400+等待秒` 下重放走默认档会插队，自动重放一律用后台档。
pub const PRIORITY_DEFAULT: BuildPriority = 0;
/// 系统后台档（-1）：仅服务端内部路径（自动重放、批处理驱动）程序化设置，
/// 用户提交入口校验只放行 0-2；同等待时长下 aging 权重恒低于全部用户档，
/// picking 侧另有后台档让行前台的前置闸兜底（存在 priority>=0 pending 时不入候选），
/// 重放不挤占新提交。
pub const PRIORITY_BACKGROUND: BuildPriority = -1;
/// 紧急档（2）：用户档上限，仅 operator 及以上可提交（operator 以下由服务端校验拒绝）。
pub const PRIORITY_CRITICAL: BuildPriority = 2;

/// 构建 phase 终态值集（单源常量）：`succeeded` / `failed` / `cancelled` /
/// `timeout`。消费方：[`build_phase_is_terminal`] 与 state retention 的 SQL
/// `IN` 列表（`terminal_phases_sql_list`）；扩容只改这一处，补集侧（follow
/// 白名单）与下方谓词文档列出的 SQL / JS 内联残余站点仍需人工同审。
pub const TERMINAL_BUILD_PHASES: &[&str] = &["succeeded", "failed", "cancelled", "timeout"];

/// 构建 phase 是否已进入终态（集合 = [`TERMINAL_BUILD_PHASES`]）。补集即
/// `crbs logs -f` follow 的"进行中"白名单（pending / assigned / building /
/// running，running 为历史兼容冗余，见 crates/crbs/src/cmd/logs.rs）；新增
/// phase 两处必须同步（穷举护栏测试钉住）；task phase 值域同构，谓词同样
/// 适用。SQL 内联（insert_build 守卫、UPDATE_TASK_PHASE、迁移史）与前端
/// JS（sse_script.rs）为收不了口的手写副本，新增终态值须人工同步。
pub fn build_phase_is_terminal(phase: &str) -> bool {
    TERMINAL_BUILD_PHASES.contains(&phase)
}

/// deterministic 溯源硬门失败文案的稳定片段（契约常量）：engine 失败时拼进
/// `builds.error_summary`，state `classify_replay_failure` 据此归
/// infra_error（不进复现率分母）；改文案须保持本片段不变，否则判据静默失配。
pub(crate) const PROVENANCE_HARD_GATE_MARKER: &str = "provenance integrity hard gate";

/// overlay 已装包清单读取失败文案的稳定片段（契约常量）：engine
/// deterministic/replay 收严失败拼进 `builds.error_summary`，state
/// `classify_replay_failure` 据此归 infra_error（不进复现率分母）；改文案
/// 须保持本片段不变，否则判据静默失配。
pub(crate) const OVERLAY_READ_FAILURE_MARKER: &str = "read overlay installed packages";

use std::path::PathBuf;

/// 构建请求（CLI / server API 共用描述）：运行时选项经 serde flatten 拍平
/// 内嵌 [`crate::BuildOptions`]（扁平 snake_case 线格式，roundtrip 测试钉住）。
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(default, rename_all = "snake_case")]
pub struct BuildRequest {
    pub product: String,
    pub srpms: Vec<String>,
    /// 多架构构建的架构列表（仅用于解析阶段，写入 DB 时拆分）。
    /// JSON: "arch_list": ["x86_64", "aarch64"]；Multipart: arch_list=x86_64&arch_list=aarch64
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch_list: Option<Vec<String>>,
    /// 任务标签（任务级，仅 JSON 入口）：multipart 入口走重复 `label` 字段
    /// （`KEY=VALUE`），两者最终都落到 `task_labels` 表。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<TaskLabel>,
    #[serde(flatten)]
    pub options: crate::BuildOptions,
}

/// serde `skip_serializing_if` 辅助：false 不序列化（线格式向后兼容）。
pub(crate) fn is_false(v: &bool) -> bool {
    !*v
}

/// 子构建摘要（用于任务聚合展示）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChildBuildSummary {
    pub id: i64,
    pub arch: String,
    pub phase: String,
    pub result_dir: Option<String>,
    pub started_at: Option<String>,
    /// 完成时由 complete_build 写入的执行时长（秒）；未完成为 None。
    /// `#[serde(default)]`：旧 server 响应缺字段时解析回 None（版本偏斜防线）；
    /// JSON 键 `duration_seconds` 与 task 级同名义同单位，`alias` 兼读旧键名。
    #[serde(default, rename = "duration_seconds", alias = "duration")]
    pub duration: Option<i64>,
    /// 执行该构建的 worker 名（最新归属；本地构建/无归属/public 脱敏路径为
    /// None，键省略）。纯归档信息：结果同步到 hub 后与构建无功能耦合。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker: Option<String>,
}

/// 复现血缘源：本任务是复现任务时，指向其源（源构建 id + 源任务 id）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LineageSource {
    pub build_id: i64,
    pub task_id: i64,
}

/// 指向本任务子构建的一条复现任务引用（task_id + phase）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReplayRef {
    pub task_id: i64,
    pub phase: String,
}

/// 任务标签（任务详情线格式）：提交时声明的 key/value 元数据，按键排序。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaskLabel {
    pub key: String,
    pub value: String,
}

/// 任务详情页/API 的复现血缘（双向）：`replay_source` = 本任务是复现任务时
/// 的源；`replays` = 指向本任务子构建的复现任务列表，按 task_id 排序。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TaskLineage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_source: Option<LineageSource>,
    #[serde(default)]
    pub replays: Vec<ReplayRef>,
}

/// 构建时长条形图样本：最近 N 个已成功构建的 (pkg_name, arch, duration)，
/// 每 arch 一条。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildDurationSample {
    pub pkg_name: String,
    pub arch: String,
    /// complete_build 写入的执行时长（秒）。
    pub duration_secs: i64,
}

/// 单条构建的产物清单（包名 + rpms/srpms/logs/result_dir 路径与签名标记）：
/// engine 成功路径产出，worker 据此上传产物到 hub，server 签名与 CLI 汇总渲染共用。
#[derive(Debug, Clone, serde::Serialize)]
pub struct BuildOutputs {
    pub build_id: i64,
    pub pkg_name: String,
    pub rpms: Vec<PathBuf>,
    pub srpms: Vec<PathBuf>,
    pub logs: Vec<PathBuf>,
    pub result_dir: PathBuf,
    /// 本次构建最终成功前经历的额外重试次数。
    pub retries: u32,
    pub signed: bool,
}

/// 单个 SRPM 的构建结果：成功携带产物，失败携带错误（时长秒）。
/// batch / chain worker 池与 chain 编排共用（汇总进 [`BuildSummary`]）。
#[derive(Debug)]
pub enum BuildResult {
    /// 构建成功：SRPM 路径、产物、耗时（秒）。
    Succeeded(PathBuf, BuildOutputs, u64),
    /// 构建失败：SRPM 路径、错误、耗时（秒）。
    Failed(PathBuf, crate::error::CrbsError, u64),
}

/// 一批构建的四桶汇总（成功 / 失败 / 取消 / 超时），CLI 渲染与 chain
/// 编排（恢复轮、退出码代表错误）都以此为单位传递。
#[derive(Debug, Clone, Default)]
pub struct BuildSummary {
    pub succeeded: Vec<(PathBuf, BuildOutputs, u64)>,
    pub failed: Vec<(PathBuf, crate::error::CrbsError, u64)>,
    /// 取消（`CrbsError::Cancelled`）。
    pub cancelled: Vec<(PathBuf, crate::error::CrbsError, u64)>,
    /// 超时（`CrbsError::Timeout`）。
    pub timeout: Vec<(PathBuf, crate::error::CrbsError, u64)>,
}

impl BuildSummary {
    /// 代表错误：任一失败桶非空时取 failed→timeout→cancelled 首个（batch
    /// 出口与 chain 收口共用的取序）；全空返回 `None`，回退变体由调用方定。
    pub fn representative_error(&self) -> Option<crate::error::CrbsError> {
        self.failed
            .first()
            .or(self.timeout.first())
            .or(self.cancelled.first())
            .map(|(_, e, _)| e.clone())
    }
}

/// 构建执行结果：成功失败均携带本次构建的 `result_dir`，失败时调用方仍能
/// 定位并上传 build.log。不变量：`result_dir` 为**空路径**当且仅当"早失败"
///（结果目录创建前即失败：SRPM 解析 / 包名校验 / lifecycle 创建），其余分支
/// 保证非空；空路径 join 文件名得 CWD 相对路径，会被上传逻辑
/// `strip_prefix("")` 放行而误传 worker 工作目录下的同名文件——
/// [`Self::existing_log_paths`] 对空路径早退封住该口。
#[derive(Debug)]
pub struct BuildExecutionResult {
    pub result_dir: PathBuf,
    pub outputs: std::result::Result<BuildOutputs, crate::error::CrbsError>,
    /// 构建资源采样结果（成功/失败路径尽力携带，早失败/取消/未采样为 `None`）；
    /// worker 随结果上报回 hub 落资源列（三值 + 采集包络），引擎本地落库不经此字段（lifecycle 直采）。
    pub resources: Option<crate::engine::ResourceUsage>,
}

impl BuildExecutionResult {
    /// 返回该 result_dir 下存在的日志文件路径（build.log）；空 result_dir
    ///（早失败不变量，见 struct doc）返回空列表：空 join 得 CWD 相对路径，
    /// 会把 worker 工作目录下的同名文件误判为本次构建日志。
    pub async fn existing_log_paths(&self) -> Vec<PathBuf> {
        if self.result_dir.as_os_str().is_empty() {
            return Vec::new();
        }
        let mut logs = Vec::new();
        for name in &["build.log"] {
            let p = self.result_dir.join(name);
            match tokio::fs::try_exists(&p).await {
                Ok(true) => logs.push(p),
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(path = %p.display(), error = %e, "Failed to check log file existence");
                }
            }
        }
        logs
    }
}

/// 构建列表查询条件：server 列表路由（API / UI 页）从查询参数组装，state
/// `list_builds` 据此拼过滤与分页 SQL；`Default`（全 `None`）即无过滤全量。
#[derive(Debug, Default)]
pub struct BuildListFilter<'a> {
    pub product: Option<&'a str>,
    pub user: Option<&'a str>,
    pub phase: Option<&'a str>,
    pub name: Option<&'a str>,
    /// 精确匹配源码包基础名（`builds.name`，不含版本/release）；画像详情的
    /// 历史构建列表用（`name` 是 pkg_name 前缀过滤，会跨包误匹配）。
    pub source_name: Option<&'a str>,
    pub arch: Option<&'a str>,
    /// 精确匹配输入 SRPM 血缘锚（`canonical_srpm_sha256`）：按内容反查构建；
    /// `None` 不过滤，NULL 历史行不命中。
    pub srpm_sha256: Option<&'a str>,
    /// 精确匹配优先级（取值语义见 [`BuildPriority`]）；UI 列表过滤用，
    /// `None` 不过滤。整数列走独立 typed bind（非字符串 binds）。
    pub priority: Option<BuildPriority>,
    pub task_id: Option<i64>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub order_by: Option<&'a str>,
    /// 可选的产品可见性白名单（语义与 `NvrGroupFilter::visible_products` 一致）：
    /// `Some(list)` SQL 层拼可见性子查询、分页前过滤（total 同口径，孤儿豁免由
    /// SQL 子句处理）；`Some(empty)` 仅孤儿豁免；`None` 不过滤（admin/operator
    /// bypass）。owned `Vec<String>` 对齐 `compute_visible_products` 返回类型。
    pub visible_products: Option<Vec<String>>,
}

/// 任务列表查询条件：server 任务列表路由、各 UI 页与 CLI `crbs status` 组装，
/// state 层任务查询消费；过滤与可见性三态语义同 [`BuildListFilter`]。
#[derive(Debug, Default)]
pub struct TaskListFilter<'a> {
    pub product: Option<&'a str>,
    pub user: Option<&'a str>,
    pub phase: Option<&'a str>,
    pub name: Option<&'a str>,
    /// 精确匹配主 NVR（pkg_name = ?），用于“同 NVR 尝试列表”。
    pub nvr: Option<&'a str>,
    /// 任务标签精确过滤 `(key, value)`：`EXISTS task_labels` 子查询命中；
    /// `None` 不过滤。值大小写敏感。
    pub label: Option<(String, String)>,
    /// `None` = 不限页（**有意全量**，契约见 `pagination_clause`）：仅限仓库内部
    /// 调用方；用户输入入口必须先过 server `validate_list_pagination`（MAX_LIST_LIMIT）。
    pub limit: Option<usize>,
    /// `None` = 不偏移（契约同 [`TaskListFilter::limit`]）。
    pub offset: Option<usize>,
    pub order_by: Option<&'a str>,
    /// 可选的产品可见性白名单，语义与 [`BuildListFilter::visible_products`] /
    /// `NvrGroupFilter::visible_products` 一致（`Some(list)` 分页前过滤 /
    /// `Some(empty)` 仅孤儿豁免 / `None` 不过滤）；owned `Vec<String>` 理由同彼处。
    pub visible_products: Option<Vec<String>>,
}

/// GC 结果聚合结构（CLI / server API 共用）。
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct GcSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orphan_mounts: Option<GcOrphanMountsSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<GcResultsSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_cache: Option<GcPackageCacheSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_layers: Option<GcSharedLayersSummary>,
}

/// GC 孤儿 overlay 挂载清理小计（[`GcSummary::orphan_mounts`] 段，gc::orphan 产出）：
/// 全局扫描 crbs_root + tmp 的残留挂载；存在真实活跃构建时整体跳过（计数全 0）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct GcOrphanMountsSummary {
    pub found: usize,
    pub cleaned: usize,
    pub removed_dirs: usize,
    pub dry_run: bool,
}

/// 构建结果目录保留策略 GC 小计（[`GcSummary::results`] 段，gc::results 产出）：
/// `removed` / `would_remove` 按 dry_run 互斥填充，另一个恒 0。
#[derive(Debug, Clone, serde::Serialize)]
pub struct GcResultsSummary {
    pub removed: usize,
    pub would_remove: usize,
    pub bytes: u64,
    pub policy_removed: usize,
    /// 被跳过候选的观测计数：latest 软链接保护 / 目录已缺失（走自愈清行）/
    /// 越界或 IO 异常。additive 序列化（API / CLI JSON 自动透出）。
    pub skipped_latest: usize,
    pub skipped_missing: usize,
    pub skipped_invalid: usize,
    /// 观测计数：删除失败 / 翻 on_disk 落库失败 / 清 result_dir 后落库失败
    /// 的候选数（留待下一轮 GC 重试）；removed/failed 可对同一候选双计——
    /// 目录已删计入 removed、其后的落库失败同时计入 failed。additive 序列化。
    pub failed: usize,
    /// 实际删除结果目录、需重建发布 repo 的产品集合。
    /// 进程内传递给 GC 触发点，不进 API 响应（`#[serde(skip)]`）。
    #[serde(skip)]
    pub affected_products: Vec<String>,
}

/// dnf 包缓存 GC 小计（[`GcSummary::package_cache`] 段，gc::package_cache 产出）：
/// 默认按 DB 引用判定可删；`all` = `--all` 全清（绕过引用检查，活跃构建在用也删）；
/// `lru_evicted` / `lru_bytes` 为超出 `package_cache_max_size_gb` 的 LRU 淘汰部分。
/// dry-run 口径：`removed` 恒 0，`lru_*` 与 `bytes` 填"将驱逐/将释放"值
///（与 `GcResultsSummary` 的 removed/would_remove 互斥契约不同形，消费方注意）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct GcPackageCacheSummary {
    pub removed: usize,
    pub kept: usize,
    pub bytes: u64,
    pub lru_evicted: usize,
    pub lru_bytes: u64,
    pub dry_run: bool,
    pub all: bool,
}

impl GcPackageCacheSummary {
    /// 零值小计（跳过 GC / 缓存根缺失等早退路径）：计数与字节全 0，仅
    /// `dry_run` / `all` 旗标按调用语境保留。
    pub fn empty(dry_run: bool, all: bool) -> Self {
        Self {
            removed: 0,
            kept: 0,
            bytes: 0,
            lru_evicted: 0,
            lru_bytes: 0,
            dry_run,
            all,
        }
    }
}

/// 共享层存储 GC 小计（[`GcSummary::shared_layers`] 段，gc::shared_layers 产出）：
/// 按 24h 宽限清理无行孤儿层目录与 stale upper 目录，`stale_upper_bytes` 为后者释放字节。
#[derive(Debug, Clone, serde::Serialize)]
pub struct GcSharedLayersSummary {
    pub removed: usize,
    pub stale_uppers: usize,
    pub stale_upper_bytes: u64,
    /// 观测计数：disk→DB 对账清理的孤儿层目录数。additive 序列化（JSON 自动透出）。
    pub orphan_dirs_removed: usize,
}

/// set_current_dir 是进程全局副作用：CWD 敏感测试经此锁串行；其他模块的
/// CWD 变更类测试经 `crate::types::CWD_SENSITIVE_TEST_LOCK` 共持。锁跨
/// await 持有，故用 tokio::sync::Mutex。
#[cfg(test)]
pub(crate) static CWD_SENSITIVE_TEST_LOCK: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod tests {
    use super::*;

    /// ChildBuildSummary 的 JSON 键契约：写出恒 `duration_seconds`；读侧
    /// `duration` 旧键（旧 server 偏斜）与缺键都回 None/取值。
    #[test]
    fn child_build_summary_duration_key_contract() {
        let s = ChildBuildSummary {
            id: 1,
            arch: "x86_64".into(),
            phase: "succeeded".into(),
            result_dir: None,
            started_at: None,
            duration: Some(42),
            worker: None,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["duration_seconds"], 42, "must serialize under new key");

        let legacy = serde_json::from_str::<ChildBuildSummary>(
            r#"{"id":1,"arch":"x86_64","phase":"succeeded","result_dir":null,"started_at":null,"duration":7}"#,
        )
        .unwrap();
        assert_eq!(legacy.duration, Some(7), "alias reads legacy key");

        let missing = serde_json::from_str::<ChildBuildSummary>(
            r#"{"id":1,"arch":"x86_64","phase":"succeeded","result_dir":null,"started_at":null}"#,
        )
        .unwrap();
        assert!(missing.duration.is_none(), "missing key defaults to None");
    }

    /// TaskLineage 命名字段形状：写出/读回都是命名对象（非位置元组）；
    /// replay_source 为 None 时键省略（呈现层空值收敛）。
    #[test]
    fn task_lineage_named_field_shape() {
        let l = TaskLineage {
            replay_source: Some(LineageSource {
                build_id: 1,
                task_id: 1,
            }),
            replays: vec![ReplayRef {
                task_id: 7,
                phase: "succeeded".into(),
            }],
        };
        let v = serde_json::to_value(&l).unwrap();
        assert_eq!(v["replay_source"]["build_id"], 1);
        assert_eq!(v["replay_source"]["task_id"], 1);
        assert_eq!(v["replays"][0]["task_id"], 7);
        assert_eq!(v["replays"][0]["phase"], "succeeded");

        let back: TaskLineage = serde_json::from_value(v).unwrap();
        assert_eq!(back.replay_source.as_ref().unwrap().task_id, 1);
        assert_eq!(back.replays[0].task_id, 7);

        let empty = serde_json::to_value(TaskLineage::default()).unwrap();
        assert!(empty.get("replay_source").is_none(), "None omits the key");
    }

    // ─── build_phase_is_terminal ───

    /// 穷举护栏：每个已知 phase 必须恰好落在"终态"或 `crbs logs -f` follow
    /// 白名单之一——两边都占 follow 在终态后空转，两边都不占提前退出。
    #[test]
    fn known_phases_are_exactly_terminal_or_follow_whitelist() {
        const KNOWN_PHASES: [&str; 8] = [
            "pending",
            "assigned",
            "building",
            "running",
            "succeeded",
            "failed",
            "cancelled",
            "timeout",
        ];
        const FOLLOW_WHITELIST: [&str; 4] = ["pending", "assigned", "building", "running"];
        for phase in KNOWN_PHASES {
            let terminal = build_phase_is_terminal(phase);
            let whitelisted = FOLLOW_WHITELIST.contains(&phase);
            assert_ne!(
                terminal, whitelisted,
                "phase {phase:?} must be exactly one of terminal / follow-whitelist"
            );
        }
    }

    /// CWD 恢复 guard：断言 panic 时也在 drop 时回原目录，不污染后续测试。
    struct RestoreCwd(PathBuf);

    impl Drop for RestoreCwd {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.0);
        }
    }

    /// 空 result_dir（早失败不变量）必须早退返回空列表——空 join 的 CWD 相对路径
    /// 不得交给上传侧；CWD 预置同名 build.log 诱饵保证判别力（守卫缺失即命中变红）。
    #[tokio::test]
    async fn existing_log_paths_empty_result_dir_returns_empty() {
        let _guard = CWD_SENSITIVE_TEST_LOCK.lock().await;
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("build.log"), b"decoy in cwd")
            .await
            .unwrap();
        let origin = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let _restore = RestoreCwd(origin);

        let result = BuildExecutionResult {
            result_dir: PathBuf::new(),
            outputs: Err(crate::error::CrbsError::Timeout),
            resources: None,
        };
        assert!(
            result.existing_log_paths().await.is_empty(),
            "empty result_dir must early-return even when CWD contains a same-named build.log"
        );
    }

    /// 正常 result_dir：有 build.log 时返回该路径，无时返回空。
    #[tokio::test]
    async fn existing_log_paths_normal_dir_contains_build_log() {
        let tmp = tempfile::tempdir().unwrap();
        let empty = BuildExecutionResult {
            result_dir: tmp.path().to_path_buf(),
            outputs: Err(crate::error::CrbsError::Timeout),
            resources: None,
        };
        assert!(empty.existing_log_paths().await.is_empty());
        tokio::fs::write(tmp.path().join("build.log"), b"log body")
            .await
            .unwrap();
        let result = BuildExecutionResult {
            result_dir: tmp.path().to_path_buf(),
            outputs: Err(crate::error::CrbsError::Timeout),
            resources: None,
        };
        assert_eq!(
            result.existing_log_paths().await,
            vec![tmp.path().join("build.log")]
        );
    }

    /// 旧版扁平 JSON 必须仍能反序列化，且序列化回写后字段集合不变
    /// （flatten 不得改变 enqueue API 的线格式）。
    #[test]
    fn build_request_json_roundtrip_keeps_flat_wire_format() {
        let json = serde_json::json!({
            "product": "mydist",
            "srpms": ["/tmp/a.src.rpm"],
            "arch_list": ["x86_64", "aarch64"],
            "stage": "build",
            "tmpfs": true,
            "ccache": false,
            "no_network": true,
            "define": ["FOO=1"],
            "with_features": ["f1"],
            "without_features": ["f2"],
            "retry": 3,
            "priority": 2,
            "arch": "x86_64"
        });
        let req: BuildRequest = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(req.product, "mydist");
        assert_eq!(req.srpms, vec!["/tmp/a.src.rpm"]);
        assert_eq!(
            req.arch_list,
            Some(vec!["x86_64".to_string(), "aarch64".to_string()])
        );
        assert_eq!(req.options.stage.as_deref(), Some("build"));
        assert_eq!(req.options.tmpfs, Some(true));
        assert_eq!(req.options.no_network, Some(true));
        assert_eq!(req.options.define, vec!["FOO=1".to_string()]);
        assert_eq!(req.options.priority, Some(2));
        assert_eq!(req.options.arch.as_deref(), Some("x86_64"));

        let out = serde_json::to_value(&req).unwrap();
        for key in [
            "product",
            "srpms",
            "arch_list",
            "stage",
            "tmpfs",
            "ccache",
            "no_network",
            "define",
            "with_features",
            "without_features",
            "retry",
            "priority",
            "arch",
        ] {
            assert_eq!(out.get(key), json.get(key), "wire field {key} changed");
        }
    }

    /// 缺省选项字段时全部回退默认值（flatten 下 `#[serde(default)]` 仍生效）。
    #[test]
    fn build_request_defaults_when_options_absent() {
        let req: BuildRequest = serde_json::from_str("{}").unwrap();
        assert!(req.product.is_empty());
        assert!(req.srpms.is_empty());
        assert!(req.arch_list.is_none());
        assert!(req.options.stage.is_none());
        assert!(req.options.define.is_empty());
        assert!(req.options.priority.is_none());
        assert!(req.options.arch.is_none());
    }
}
