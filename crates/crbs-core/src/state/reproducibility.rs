// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 比对结果存储（`build_reproducibility` 表 CRUD）+ 纯比对/分类逻辑。
//! 比对输入恒为 [`crate::state::artifacts::Artifact::unsigned_sha256`]（签名前哈希留档，
//! 签名刷新不触碰该列），与签名时序解耦、事后执行。
//! 复现率分母口径（单一事实源）：只计 `same` / `diff` / `build_failed`（包自身问题）；
//! `dep_unavailable` 与 `infra_error` 单独统计不进分母，否则滚动源修剪伪装成"包不可复现"。

use crate::error::DbResultExt;
use crate::state::artifacts::Artifact;
use crate::state::StateStore;
use sqlx::Row;

/// 比对行 kind：`replay`（source vs 重放构建）/ `cross_arch_noarch`（同 task 跨架构 noarch 互比），按 kind 分查。
pub const KIND_REPLAY: &str = "replay";
/// 比对行 kind 值：同 task 跨架构 noarch 互比；同 source 至多一行（partial UNIQUE，`insert_cross_arch_if_absent` 幂等）。
pub const KIND_CROSS_ARCH_NOARCH: &str = "cross_arch_noarch";

/// 比对 verdict（值与表 CHECK 域一致）：`same` = 双方 unsigned_sha256 集合全等（字节级可复现）；
/// `diff` = 有差异（detail 记逐 RPM 对照与差异清单）；`build_failed` = 重放构建自身失败
///（rpmbuild 非零退出）；`dep_unavailable` = 重放取包失败（restore fail-fast / URL 下载失败）；
/// `infra_error` = 基础设施类失败（dnf/下载/沙箱/磁盘/超时/数据缺失）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ReplayVerdict {
    /// 双方 unsigned_sha256 集合全等（字节级可复现）；进复现率分母。
    Same,
    /// 哈希差异或文件集单侧缺失；进复现率分母。
    Diff,
    /// 重放构建自身失败（rpmbuild 非零退出，含不可归类兜底）；进复现率分母。
    BuildFailed,
    /// 重放取包失败（restore fail-fast / URL 下载失败，上游修剪）；不进复现率分母。
    DepUnavailable,
    /// 基础设施类失败（网络/沙箱/磁盘/超时/比对锚缺失）；不进复现率分母。
    InfraError,
}

/// 五类 verdict 固定输出序（Prometheus label / 看板行序，与表 CHECK 域一致）：
/// 缺数据 verdict 由调用方按 0 补齐，label 集恒定抓取端才能按 label 相减。
pub const ALL_VERDICTS: [ReplayVerdict; 5] = [
    ReplayVerdict::Same,
    ReplayVerdict::Diff,
    ReplayVerdict::BuildFailed,
    ReplayVerdict::DepUnavailable,
    ReplayVerdict::InfraError,
];

impl ReplayVerdict {
    /// CHECK 约束域存储值（`"same"` 等）；落库绑定与 Prometheus label 键共用。
    pub fn as_str(self) -> &'static str {
        match self {
            ReplayVerdict::Same => "same",
            ReplayVerdict::Diff => "diff",
            ReplayVerdict::BuildFailed => "build_failed",
            ReplayVerdict::DepUnavailable => "dep_unavailable",
            ReplayVerdict::InfraError => "infra_error",
        }
    }
}

/// 比对结果行（API/CLI 透出形态；`detail_json` 原样透传，调用方按需解析）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReproducibilityRecord {
    pub id: i64,
    pub kind: String,
    pub source_build_id: i64,
    pub replay_build_id: Option<i64>,
    pub verdict: String,
    pub detail_json: Option<String>,
    pub compared_at: String,
}

/// 新比对行插入参数。
#[derive(Debug, Clone)]
pub struct NewReproducibility {
    pub kind: &'static str,
    pub source_build_id: i64,
    pub replay_build_id: Option<i64>,
    pub verdict: ReplayVerdict,
    pub detail_json: Option<String>,
}

mod sql {
    pub(super) const INSERT_ROW: &str =
        "INSERT INTO build_reproducibility (kind, source_build_id, replay_build_id, verdict, detail_json) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id";

    /// cross_arch_noarch 幂等插入：partial UNIQUE
    /// `idx_build_repro_cross_arch (source_build_id) WHERE kind = 'cross_arch_noarch'`
    /// 作 conflict target（任务级收口去重，同 task 只记一行，重跑新 build 不撞键）；
    /// 双方言均支持带谓词 conflict target；项目 SQLite 下限实为 ≥3.35（同语句 RETURNING
    /// 同批落地，单看 conflict target 的 ≥3.24 会低估门槛）。
    pub(super) const INSERT_CROSS_ARCH_IF_ABSENT: &str =
        "INSERT INTO build_reproducibility (kind, source_build_id, replay_build_id, verdict, detail_json) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (source_build_id) WHERE kind = 'cross_arch_noarch' \
         DO NOTHING RETURNING id";

    /// replay 幂等插入（双保险）：已有同 `(kind='replay', replay_build_id)` 行则跳过，终态钩子
    /// double-fire 不得制造重复比对行。单语句 `WHERE NOT EXISTS`：SQLite 单语句串行写原子，
    /// PG READ COMMITTED 并发双插理论上可漏过（顺序 double-fire 为目标场景）——升级路径：
    /// 部分唯一索引 `ON replay_build_id WHERE kind='replay'` + ON CONFLICT（ponytail）。
    /// `$3` 绑 None 时三值逻辑恒不命中（NOT EXISTS 恒真 → 无限插行），NULL 防御在函数入口。
    pub(super) const INSERT_REPLAY_IF_ABSENT: &str =
        "INSERT INTO build_reproducibility (kind, source_build_id, replay_build_id, verdict, detail_json) \
         SELECT $1, $2, $3, $4, $5 \
         WHERE NOT EXISTS ( \
             SELECT 1 FROM build_reproducibility WHERE kind = 'replay' AND replay_build_id = $3 \
         ) RETURNING id";

    pub(super) const LIST_FOR_BUILD: &str =
        "SELECT id, kind, source_build_id, replay_build_id, verdict, detail_json, compared_at \
         FROM build_reproducibility \
         WHERE source_build_id = $1 OR replay_build_id = $1 \
         ORDER BY id";

    pub(super) const LATEST_FOR_BUILD: &str =
        "SELECT id, kind, source_build_id, replay_build_id, verdict, detail_json, compared_at \
         FROM build_reproducibility \
         WHERE source_build_id = $1 OR replay_build_id = $1 \
         ORDER BY id DESC LIMIT 1";

    /// 对账候选（方言同一，无 JSON 函数）：疑似"应比对未比对"的 replay 构建 id——
    /// 终态且不含 `cancelled`（操作员取消本就不落比对行，入集只会启动空转钩子）；
    /// `request_json` LIKE 血缘键粗筛（serde `skip_serializing_if`
    /// 下普通构建不含该子串，`_` 宽匹配无害、键值合法性交复核）。LIKE 大小写双方言不同
    ///（SQLite ASCII 不分、PG 分）：模式与 serde 键名均全小写现无比对面，键名引入大写会
    /// 单侧静默漏报、须双侧同审；且无同 replay_build_id 的 replay 行。精确血缘判定在调用
    /// 方逐 id [`StateStore::get_build_reproduce_source`]，键非 id（JSON null/非整数）在此
    /// 剔除。
    pub(super) const RECONCILE_MISSING_REPLAY_CANDIDATES: &str = "\
        SELECT builds.id FROM builds \
         WHERE builds.phase IN ('succeeded', 'failed', 'timeout') \
           AND builds.completed_at >= $1 \
           AND builds.request_json LIKE '%reproduce_from_build_id%' \
           AND NOT EXISTS ( \
               SELECT 1 FROM build_reproducibility r \
               WHERE r.kind = 'replay' AND r.replay_build_id = builds.id \
           ) \
         ORDER BY builds.id";

    /// 对账候选（auto-replay 创建侧崩溃窗口，与上方比对行对账互为另一半面）：源任务 =
    /// "存在 succeeded + det + 非血缘触发子构建，且任务内全部子构建 succeeded 且非血缘"，
    /// 镜像 maybe_auto_replay 任务级收口判据（血缘子构建宿主任务本身是 replay 任务，
    /// 单代血缘不得再触发下一代）；`MIN(id)` 取最早满足条件的子构建做触发点（任意满足者
    /// 等价：钩子只消费 task_id / product / phase / deterministic）。LIKE 子串粗筛比运行时
    /// JSON 顶层键判定更严，用户值（如 `--define` 值）含血缘子串的任务被整体排除、永不
    /// 补发（保守漏报角落）；已有 replay 的剔除在 Rust 侧（血缘值是 JSON 方言中立无法解析）。
    pub(super) const RECONCILE_AUTO_REPLAY_SOURCE_CANDIDATES: &str = "\
        SELECT b.task_id, MIN(b.id) FROM builds b \
         WHERE b.task_id IS NOT NULL \
           AND b.phase = 'succeeded' \
           AND b.completed_at >= $1 \
           AND b.deterministic = 1 \
           AND (b.request_json IS NULL OR b.request_json NOT LIKE '%reproduce_from_build_id%') \
           AND NOT EXISTS ( \
               SELECT 1 FROM builds sib \
               WHERE sib.task_id = b.task_id \
                 AND (sib.phase != 'succeeded' OR sib.request_json LIKE '%reproduce_from_build_id%') \
           ) \
         GROUP BY b.task_id \
         ORDER BY b.task_id";

    /// replay 血缘构建全体（id 集）：创建侧对账折算 source build id 集后按候选任务剔除
    ///（精确解析走 [`StateStore::get_build_reproduce_source`]，SQL 侧不重复实现 JSON 解析）。
    pub(super) const REPRODUCE_LINEAGE_BUILD_IDS: &str = "\
        SELECT id FROM builds WHERE request_json LIKE '%reproduce_from_build_id%'";

    /// 对账剔除用子构建 id 轻量查询：只取 id 列，分配较全列拉取降约一个数量级，查询次数不变。
    pub(super) const CHILD_BUILD_IDS_BY_TASK: &str = "\
        SELECT id FROM builds WHERE task_id = $1";
}

fn record_from_row(r: &sqlx::any::AnyRow) -> ReproducibilityRecord {
    ReproducibilityRecord {
        id: r.get("id"),
        kind: r.get("kind"),
        source_build_id: r.get("source_build_id"),
        replay_build_id: r.get("replay_build_id"),
        verdict: r.get("verdict"),
        detail_json: r.get("detail_json"),
        compared_at: r.get("compared_at"),
    }
}

/// 对账候选时间窗（近 7 天）：对账是崩溃窗口恢复机制而非全量审计，窗口外断头不再补发，
/// 免 succeeded 全集 `request_json LIKE` 宽列扫描。仅适用候选查询（终态行 completed_at 恒
/// 有值）；血缘剔除集必须全量——活跃 replay completed_at 为 NULL，窗口谓词滤掉它致源任务重复补发。
fn replay_reconcile_cutoff() -> String {
    (chrono::Utc::now() - chrono::Duration::days(7))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

impl StateStore {
    /// 插入一条比对结果行，返回行 id。
    pub async fn insert_reproducibility(&self, row: &NewReproducibility) -> crate::Result<i64> {
        sqlx::query_scalar(sql::INSERT_ROW)
            .bind(row.kind)
            .bind(row.source_build_id)
            .bind(row.replay_build_id)
            .bind(row.verdict.as_str())
            .bind(&row.detail_json)
            .fetch_one(self.pool())
            .await
            .db_ctx("insert build_reproducibility row")
    }

    /// replay 幂等插入（double-fire 去重双保险，见 `sql::INSERT_REPLAY_IF_ABSENT`）：已有同
    /// `(kind='replay', replay_build_id)` 行 no-op，同 source 换新重放构建（重试）照常插入，
    /// 返回是否真正插入。`replay_build_id` 是幂等锚，None 属调用方 bug（SQL 三值逻辑恒不
    /// 命中 → 无限插行），入口 ValidationFailed 拒绝：丢比对行必须有信号（钩子外壳 warn 承接）。
    pub async fn insert_replay_if_absent(&self, row: &NewReproducibility) -> crate::Result<bool> {
        let Some(replay_build_id) = row.replay_build_id else {
            return Err(crate::error::CrbsError::ValidationFailed {
                message:
                    "insert_replay_if_absent requires replay_build_id: kind='replay' rows are \
                     idempotency-keyed by it; None would defeat the belt"
                        .into(),
            });
        };
        let inserted: Option<i64> = sqlx::query_scalar(sql::INSERT_REPLAY_IF_ABSENT)
            .bind(row.kind)
            .bind(row.source_build_id)
            .bind(replay_build_id)
            .bind(row.verdict.as_str())
            .bind(&row.detail_json)
            .fetch_optional(self.pool())
            .await
            .db_ctx("insert replay reproducibility row")?;
        Ok(inserted.is_some())
    }

    /// cross_arch_noarch 幂等插入（任务级收口去重，见 `sql::INSERT_CROSS_ARCH_IF_ABSENT`）：同 source 已有行 no-op。
    pub async fn insert_cross_arch_if_absent(
        &self,
        row: &NewReproducibility,
    ) -> crate::Result<bool> {
        let inserted: Option<i64> = sqlx::query_scalar(sql::INSERT_CROSS_ARCH_IF_ABSENT)
            .bind(row.kind)
            .bind(row.source_build_id)
            .bind(row.replay_build_id)
            .bind(row.verdict.as_str())
            .bind(&row.detail_json)
            .fetch_optional(self.pool())
            .await
            .db_ctx("insert cross-arch reproducibility row")?;
        Ok(inserted.is_some())
    }

    /// 该 build 作为 source（或 replay）的全部比对行（`id` 升序）。
    pub async fn list_reproducibility_for_build(
        &self,
        build_id: i64,
    ) -> crate::Result<Vec<ReproducibilityRecord>> {
        let rows = sqlx::query(sql::LIST_FOR_BUILD)
            .bind(build_id)
            .fetch_all(self.pool())
            .await
            .db_ctx("list reproducibility for build")?;
        Ok(rows.iter().map(record_from_row).collect())
    }

    /// 该 build 最新一条比对行（`crbs builds show` 的 verdict 列 / JSON 内嵌）。
    pub async fn latest_reproducibility_for_build(
        &self,
        build_id: i64,
    ) -> crate::Result<Option<ReproducibilityRecord>> {
        let row = sqlx::query(sql::LATEST_FOR_BUILD)
            .bind(build_id)
            .fetch_optional(self.pool())
            .await
            .db_ctx("latest reproducibility for build")?;
        Ok(row.as_ref().map(record_from_row))
    }

    /// 启动对账（终态钩子崩溃窗口的存量修复面）：返回"replay 血缘 + 已终态（cancelled
    /// 除外）+ 无同 replay_build_id 比对行"的 builds id（升序）。hub 崩在 builds 终态 COMMIT
    /// 与 on_build_terminal 执行之间时比对行永缺、链断头；调用方（bootstrap 启动期）逐 id
    /// 补发终态钩子闭环，[`Self::insert_replay_if_absent`] 双保险保证重复补发 / zombie 交叠
    /// 零副作用。SQL 粗筛 + 逐 id [`Self::get_build_reproduce_source`] 精确复核，点查只在
    /// 崩溃存量发生（稳态空集，非热路径）。返回集是候选非承诺：source 已 GC / 非 det 等
    /// 钩子自行早退的形态留在集里，由 retention 出清。
    pub async fn list_builds_missing_replay_comparison(&self) -> crate::Result<Vec<i64>> {
        let candidates: Vec<i64> = sqlx::query_scalar(sql::RECONCILE_MISSING_REPLAY_CANDIDATES)
            .bind(replay_reconcile_cutoff())
            .fetch_all(self.pool())
            .await
            .db_ctx("list builds missing replay comparison")?;
        let mut ids = Vec::new();
        for id in candidates {
            if self.get_build_reproduce_source(id).await?.is_some() {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    /// 启动对账（auto-replay 创建侧崩溃窗口）：返回 `(task_id, trigger_build_id)` 集，
    /// 源任务满足"det + 全子构建 succeeded + 无任何 replay 任务"（存活/终态一视同仁，
    /// cancelled 补偿行计入）。覆盖 hub 崩在 `maybe_auto_replay` 落库 replay task 前的
    /// 窗口（inflight guard 内存态重启即清，无新终态事件再触发，跟跑链永久断头）；调用方
    ///（bootstrap 启动期）对 trigger_build_id 补发终态钩子，钩子重走全套门禁
    ///（auto_replay / replay_sampling / manifest），抽样按 task_id 确定性哈希、重跑判定
    /// 一致。核心不变量：必须先剔除"已有 replay"——`maybe_auto_replay` 无持久判定
    ///（inflight guard 进程内；`reproduce_fan_out` 每次建新 task 行，`insert_build_guarded`
    /// 终态守卫拦不住），不剔除则每次启动重复建重放。剔除在 Rust 侧：血缘构建全体解析出
    /// source id 集（键不可解析返 None 不折算，其源任务补发一次后自愈），候选任一子构建
    /// 被引用即剔除。成本：候选集常态非空（已有 replay 的源任务子构建本就非血缘），每次
    /// 启动稳态开销 = 血缘逐行点查 + 每候选一次子构建 id 轻量查询，O(血缘构建数 + 全成功
    /// det 任务数)，受 retention 视界约束、非每请求热路径。误报（入集但钩子自行跳过，无
    /// 副作用）：门禁关闭 / 未抽中 / manifest 缺失，重判后 info 跳过；漏报：replay 行被
    /// retention 修剪的源任务再补发一次（重建 lineage 后稳定），恢复观测面非重复创建。
    pub async fn list_tasks_missing_auto_replay(&self) -> crate::Result<Vec<(i64, i64)>> {
        let candidates: Vec<(i64, i64)> =
            sqlx::query_as(sql::RECONCILE_AUTO_REPLAY_SOURCE_CANDIDATES)
                .bind(replay_reconcile_cutoff())
                .fetch_all(self.pool())
                .await
                .db_ctx("list tasks missing auto replay")?;
        if candidates.is_empty() {
            return Ok(candidates);
        }
        let lineage_build_ids: Vec<i64> = sqlx::query_scalar(sql::REPRODUCE_LINEAGE_BUILD_IDS)
            .fetch_all(self.pool())
            .await
            .db_ctx("list reproduce lineage builds")?;
        let mut replayed_source_ids: std::collections::HashSet<i64> =
            std::collections::HashSet::new();
        for id in lineage_build_ids {
            if let Some(source) = self.get_build_reproduce_source(id).await? {
                replayed_source_ids.insert(source);
            }
        }
        let mut out = Vec::new();
        for (task_id, trigger_build_id) in candidates {
            let child_ids: Vec<i64> = sqlx::query_scalar(sql::CHILD_BUILD_IDS_BY_TASK)
                .bind(task_id)
                .fetch_all(self.pool())
                .await
                .db_ctx("list child build ids by task")?;
            if child_ids.iter().any(|id| replayed_source_ids.contains(id)) {
                continue;
            }
            out.push((task_id, trigger_build_id));
        }
        Ok(out)
    }
}

// ===== 纯比对/分类逻辑（无 IO，单测直测）=====

/// 单个 RPM 的双方哈希对照（`CompareDetail::rpm` 行）。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct RpmCompareEntry {
    /// RPM 文件名（NVRA.rpm，双方对齐键）。
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_sha256: Option<String>,
}

/// 比对明细（`build_reproducibility.detail_json` 的载荷）。`serde(default)` 宽容
/// 解析：历史行缺字段走空默认（未知字段忽略），读旧数据不炸。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct CompareDetail {
    /// 双方都产出的 RPM（哈希不同即差异；相同也列出供审计）。
    pub rpm: Vec<RpmCompareEntry>,
    /// 仅 source 产出的 RPM 文件名。
    pub only_in_source: Vec<String>,
    /// 仅 replay 产出的 RPM 文件名。
    pub only_in_replay: Vec<String>,
    /// 任一侧 unsigned_sha256 缺失（NULL）的 RPM 文件名（比对锚缺失，数据留档缺口非构建问题）。
    pub missing_unsigned: Vec<String>,
}

impl CompareDetail {
    /// 需关注包数 = 哈希不一致 + 单侧缺失 + 缺锚（看板第三级默认展开集的大小，
    /// 与"一致的包折叠"互补）。
    pub fn attention_count(&self) -> usize {
        let mismatched = self
            .rpm
            .iter()
            .filter(|e| {
                e.source_sha256.is_some()
                    && e.replay_sha256.is_some()
                    && e.source_sha256 != e.replay_sha256
            })
            .count();
        mismatched
            + self.only_in_source.len()
            + self.only_in_replay.len()
            + self.missing_unsigned.len()
    }
}

/// 产物行的 unsigned_sha256（比对锚；NULL → None）。
fn unsigned_of(a: &Artifact) -> Option<&str> {
    a.unsigned_sha256.as_deref()
}

/// RPM 文件名对齐键：`relative_path` 的 basename（NVRA.rpm）。
fn rpm_file_key(a: &Artifact) -> String {
    std::path::Path::new(&a.relative_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| a.relative_path.clone())
}

/// 按 unsigned_sha256 集合比对 source 与 replay 的 RPM 产物（纯函数）：键 = RPM 文件名
///（NVRA 对齐；SRPM 是共享 canonical 输入，不参与比对）；`same` = 文件名集合相等且全部
/// 哈希相等且无缺失锚；任一哈希差异或单侧缺失 → `diff`（明细含逐 RPM 对照）；无差异但
/// 有缺失锚 → `infra_error`（无法比对的数据缺口，不进复现率分母）。
pub fn compare_unsigned_sets(
    source: &[Artifact],
    replay: &[Artifact],
) -> (ReplayVerdict, CompareDetail) {
    let is_rpm = |a: &Artifact| a.kind.as_str() == "rpm";
    let mut detail = CompareDetail::default();
    let mut mismatch = false;

    let source_map: std::collections::BTreeMap<String, &Artifact> = source
        .iter()
        .filter(|a| is_rpm(a))
        .map(|a| (rpm_file_key(a), a))
        .collect();
    let replay_map: std::collections::BTreeMap<String, &Artifact> = replay
        .iter()
        .filter(|a| is_rpm(a))
        .map(|a| (rpm_file_key(a), a))
        .collect();

    for (file, s) in &source_map {
        match replay_map.get(file) {
            Some(r) => {
                let (s_sha, r_sha) = (unsigned_of(s), unsigned_of(r));
                if s_sha.is_none() || r_sha.is_none() {
                    detail.missing_unsigned.push(file.clone());
                } else if s_sha != r_sha {
                    mismatch = true;
                }
                detail.rpm.push(RpmCompareEntry {
                    file: file.clone(),
                    source_sha256: s_sha.map(str::to_string),
                    replay_sha256: r_sha.map(str::to_string),
                });
            }
            None => detail.only_in_source.push(file.clone()),
        }
    }
    for file in replay_map.keys() {
        if !source_map.contains_key(file) {
            detail.only_in_replay.push(file.clone());
        }
    }

    let verdict =
        if mismatch || !detail.only_in_source.is_empty() || !detail.only_in_replay.is_empty() {
            ReplayVerdict::Diff
        } else if !detail.missing_unsigned.is_empty() {
            ReplayVerdict::InfraError
        } else {
            ReplayVerdict::Same
        };
    (verdict, detail)
}

/// dnf 缺包族文案（dnf5 "no match for argument"、dnf4 "unable to find a match" /
/// builddep "no matching package to install"）：replay verdict 的 dep 判据与 base
/// 快照 resolve 的 no-match 降级判据（engine/init/snapshot.rs）共用同一清单，
/// 避免双源漂移。
pub(crate) const DNF_NO_MATCH_MARKERS: [&str; 3] = [
    "no match for argument",
    "unable to find a match",
    "no matching package to install",
];

/// 重放构建失败的 verdict 分类（纯函数，判据写进 detail_json 由调用方负责）。输入 =
/// 重放构建的终态 phase 与 `builds.error_summary`（worker/hub-local 失败路径写入的
/// `CrbsError::to_string()` 文本）。映射：`cancelled` → None（操作员
/// 干预不落行）；`timeout` → infra_error；`failed` 按错误文本匹配下方 marker 数组判类，
/// 顺序 dep（最特异，restore fail-fast / URL 取包失败 / dnf 缺包族文案，上游修剪，
/// URL 判据先于通用网络判据命中）→ infra（网络/沙箱/磁盘 + 环境锚缺失或不可读两类产
/// 错侧常量）→ 默认
/// build_failed（rpmbuild 非零退出）。环境锚两类：deterministic provenance 硬门
///（types.rs `PROVENANCE_HARD_GATE_MARKER`，重放环境锚不齐是"无法验证"而非包自身
/// 问题；共享层 `.lockfile` 缺失或不可读统一降级为空 sha256 后也由此门收口）与 overlay
/// 清单读取失败（types.rs `OVERLAY_READ_FAILURE_MARKER`，deterministic/replay 收严
/// 路径）——与 `compare_unsigned_sets` 缺锚同口径，不进复现率分母。
pub fn classify_replay_failure(phase: &str, error_summary: Option<&str>) -> Option<ReplayVerdict> {
    match phase {
        "cancelled" => return None,
        "timeout" => return Some(ReplayVerdict::InfraError),
        _ => {}
    }
    let text = error_summary.unwrap_or_default().to_lowercase();
    let dep_markers: Vec<&str> = [
        "reproduce fail-fast",
        "missing from phase 1 dnf cache",
        "failed to restore packages from cache",
        // install-deps 的 dnf builddep 缺包（复现快照域无解）：reason= 取 build.log
        // 尾部 dnf 缺包族文案——wrapper 前缀本身不进判据，metadata 拉取/磁盘等
        // 基础设施失败不得伪装成 dep_unavailable（清单见 DNF_NO_MATCH_MARKERS）
        "download failed: url is empty",
        "sha256 mismatch",
        // 包 URL 拉取（engine/cache.rs download_url_verified，url 回退路径）
        "download http",
        "download https",
        "download file://",
        "read chunk from http",
        "read chunk from https",
    ]
    .into_iter()
    .chain(DNF_NO_MATCH_MARKERS)
    .collect();
    let infra_markers = [
        "network error",
        "(network error detected in build.log tail)",
        "no space left on device",
        "enospc",
        "errors during downloading metadata",
        "failed to download metadata",
        "cannot download",
        "nspawn",
        "unshare",
        // 沙箱/挂载类：用带动作的短语而非裸 "mount"（"amount" 会误命中）。
        "failed to mount",
        "mount failed",
        "mounting",
        "sandbox",
        "read-only file system",
        // 环境锚缺失/不可读（产错侧常量）：deterministic provenance 硬门（types.rs）
        crate::types::PROVENANCE_HARD_GATE_MARKER,
        // overlay 清单读取失败（types.rs，deterministic/replay 收严路径）
        crate::types::OVERLAY_READ_FAILURE_MARKER,
    ];
    if dep_markers.iter().any(|m| text.contains(m)) {
        return Some(ReplayVerdict::DepUnavailable);
    }
    if infra_markers.iter().any(|m| text.contains(m)) {
        return Some(ReplayVerdict::InfraError);
    }
    Some(ReplayVerdict::BuildFailed)
}

/// 自动跟跑抽样判定（纯函数）：sha256(task_id) 首 u64 % 100 < percent，重复触发（崩溃
/// 恢复/重试）判定一致；`percent = 100` 恒真、`0` 恒假。判据由调用方写日志。
pub fn sampling_hit(task_id: i64, percent: u8) -> bool {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(task_id.to_le_bytes());
    let v = u64::from_le_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    (v % 100) < u64::from(percent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::artifacts::{Artifact, ArtifactKind, NewArtifact};
    use crate::state::test_state::create_test_store;

    fn rpm_artifact(rel: &str, unsigned: Option<&str>) -> Artifact {
        let relative_path = rel.to_string();
        Artifact {
            id: 0,
            build_id: 0,
            relative_path,
            kind: ArtifactKind::Rpm,
            size_bytes: 1,
            sha256: "signed-hash".to_string(),
            unsigned_sha256: unsigned.map(str::to_string),
            arch: Some("x86_64".to_string()),
            name: None,
            version: None,
            release: None,
            epoch: None,
            signed: false,
            on_disk: true,
            metadata_json: None,
            created_at: String::new(),
        }
    }

    /// 全等集合 → same；目录前缀不同（跨机布局差异）不影响文件名对齐。
    #[test]
    fn compare_all_equal_is_same() {
        let source = vec![
            rpm_artifact("RPMS/x86_64/foo-1.0-1.x86_64.rpm", Some("aa")),
            rpm_artifact("RPMS/noarch/foo-doc-1.0-1.noarch.rpm", Some("bb")),
        ];
        let replay = vec![
            rpm_artifact("RPMS/noarch/foo-doc-1.0-1.noarch.rpm", Some("bb")),
            rpm_artifact("RPMS/x86_64/foo-1.0-1.x86_64.rpm", Some("aa")),
        ];
        let (verdict, detail) = compare_unsigned_sets(&source, &replay);
        assert_eq!(verdict, ReplayVerdict::Same);
        assert_eq!(detail.rpm.len(), 2);
        assert!(detail.only_in_source.is_empty());
        assert!(detail.only_in_replay.is_empty());
    }

    /// 哈希差异 → diff，且明细行双方哈希对得上号。
    #[test]
    fn compare_hash_mismatch_is_diff() {
        let source = vec![rpm_artifact("RPMS/x86_64/foo-1.0-1.x86_64.rpm", Some("aa"))];
        let replay = vec![rpm_artifact("RPMS/x86_64/foo-1.0-1.x86_64.rpm", Some("dd"))];
        let (verdict, detail) = compare_unsigned_sets(&source, &replay);
        assert_eq!(verdict, ReplayVerdict::Diff);
        assert_eq!(detail.rpm.len(), 1);
        assert_eq!(detail.rpm[0].source_sha256.as_deref(), Some("aa"));
        assert_eq!(detail.rpm[0].replay_sha256.as_deref(), Some("dd"));
    }

    /// 集合差（单侧缺失文件）→ diff。
    #[test]
    fn compare_set_difference_is_diff() {
        let source = vec![
            rpm_artifact("RPMS/x86_64/foo-1.0-1.x86_64.rpm", Some("aa")),
            rpm_artifact("RPMS/x86_64/bar-1.0-1.x86_64.rpm", Some("bb")),
        ];
        let replay = vec![
            rpm_artifact("RPMS/x86_64/foo-1.0-1.x86_64.rpm", Some("aa")),
            rpm_artifact("RPMS/x86_64/baz-1.0-1.x86_64.rpm", Some("cc")),
        ];
        let (verdict, detail) = compare_unsigned_sets(&source, &replay);
        assert_eq!(verdict, ReplayVerdict::Diff);
        assert_eq!(detail.only_in_source, vec!["bar-1.0-1.x86_64.rpm"]);
        assert_eq!(detail.only_in_replay, vec!["baz-1.0-1.x86_64.rpm"]);
    }

    /// 无差异但有缺失锚 → infra_error（数据缺口不伪装成 diff/same）。
    #[test]
    fn compare_missing_anchor_is_infra_error() {
        let source = vec![rpm_artifact("RPMS/x86_64/foo-1.0-1.x86_64.rpm", None)];
        let replay = vec![rpm_artifact("RPMS/x86_64/foo-1.0-1.x86_64.rpm", Some("aa"))];
        let (verdict, detail) = compare_unsigned_sets(&source, &replay);
        assert_eq!(verdict, ReplayVerdict::InfraError);
        assert_eq!(detail.missing_unsigned, vec!["foo-1.0-1.x86_64.rpm"]);
    }

    /// SRPM 不参与比对（canonical 输入共享同一字节）。
    #[test]
    fn compare_ignores_srpm_rows() {
        let mut srpm = rpm_artifact("SRPMS/foo-1.0-1.src.rpm", Some("xx"));
        srpm.kind = ArtifactKind::Srpm;
        let (verdict, detail) = compare_unsigned_sets(&[srpm], &[]);
        assert_eq!(verdict, ReplayVerdict::Same, "no rpm rows compared");
        assert!(detail.rpm.is_empty());
    }

    /// verdict 分类（样例取自仓库真实错误信息样式）。
    #[test]
    fn classify_replay_failure_matrix() {
        assert_eq!(classify_replay_failure("cancelled", None), None);
        assert_eq!(
            classify_replay_failure("timeout", Some("build timeout")),
            Some(ReplayVerdict::InfraError)
        );
        // rpmbuild 非零退出（phase.rs classify_script_failure 输出样式）→ build_failed
        assert_eq!(
            classify_replay_failure(
                "failed",
                Some("script /crbs-build.sh failed: exit_code=Some(1); phase=build; subphase=%install; reason=make: *** [Makefile:20: install] Error 1")
            ),
            Some(ReplayVerdict::BuildFailed)
        );
        assert_eq!(
            classify_replay_failure(
                "failed",
                Some("error: Bad exit status from /var/tmp/rpm-tmp.XXX (%check)")
            ),
            Some(ReplayVerdict::BuildFailed)
        );
        // restore fail-fast（execution.rs）→ dep_unavailable
        assert_eq!(
            classify_replay_failure(
                "failed",
                Some("validation failed: Reproduce fail-fast: 2 builddep package(s) missing from Phase 1 dnf cache, snapshot repo Packages, and base_os manifest:\n  gcc-12.3.1-1.x86_64 (sha256)")
            ),
            Some(ReplayVerdict::DepUnavailable)
        );
        // restore 失败被 prepare_reproduce_env 包装（reproduce.rs restore_failure_wrapped_with_cache_prefix 实测形态）→ dep_unavailable
        assert_eq!(
            classify_replay_failure(
                "failed",
                Some("io error: Failed to restore packages from cache: validation failed: package gcc-14.0-1.x86_64 missing from cache and has no url; not recordable for reproduce")
            ),
            Some(ReplayVerdict::DepUnavailable)
        );
        // URL 取包失败（cache.rs download_url_verified）→ dep_unavailable
        assert_eq!(
            classify_replay_failure(
                "failed",
                Some("network error: download http://repo/gcc.rpm: HTTP 404 Not Found")
            ),
            Some(ReplayVerdict::DepUnavailable)
        );
        assert_eq!(
            classify_replay_failure(
                "failed",
                Some("validation failed: download failed: url is empty (package not recordable for reproduce)")
            ),
            Some(ReplayVerdict::DepUnavailable)
        );
        // install-deps 的 dnf builddep 失败（快照域缺包/无解，reason 取 build.log
        // 尾部）→ dep_unavailable
        assert_eq!(
            classify_replay_failure(
                "failed",
                Some("script /crbs-build.sh failed: exit_code=Some(1); phase=install-deps; reason=No match for argument: openssh-clients")
            ),
            Some(ReplayVerdict::DepUnavailable)
        );
        // dnf4 缺包文案族同样命中 dep 判据 → dep_unavailable
        assert_eq!(
            classify_replay_failure(
                "failed",
                Some("script /crbs-build.sh failed: exit_code=Some(1); phase=install-deps; reason=Error: Unable to find a match: gcc-c++")
            ),
            Some(ReplayVerdict::DepUnavailable)
        );
        // install-deps 的 metadata 拉取失败属基础设施故障，不得误判成
        // dep_unavailable → infra_error
        assert_eq!(
            classify_replay_failure(
                "failed",
                Some("script /crbs-build.sh failed: exit_code=Some(1); phase=install-deps; reason=Errors during downloading metadata for repository 'crbs-local'")
            ),
            Some(ReplayVerdict::InfraError)
        );
        // 磁盘耗尽同理 → infra_error
        assert_eq!(
            classify_replay_failure(
                "failed",
                Some("script /crbs-build.sh failed: exit_code=Some(1); phase=install-deps; reason=No space left on device")
            ),
            Some(ReplayVerdict::InfraError)
        );
        // dnf 元数据 / 网络 / 磁盘 / 沙箱 → infra_error
        assert_eq!(
            classify_replay_failure(
                "failed",
                Some("script /crbs-build.sh failed: exit_code=Some(1); phase=install-deps; reason=Errors during downloading metadata for repository 'base'")
            ),
            Some(ReplayVerdict::InfraError)
        );
        assert_eq!(
            classify_replay_failure(
                "failed",
                Some("script /crbs-build.sh failed: exit_code=Some(1) (network error detected in build.log tail)")
            ),
            Some(ReplayVerdict::InfraError)
        );
        assert_eq!(
            classify_replay_failure("failed", Some("write script: No space left on device")),
            Some(ReplayVerdict::InfraError)
        );
        // deterministic provenance 硬门（provenance.rs 真实文案）→ infra_error（环境锚不齐
        // = 无法验证非包自身问题）；共享层 .lockfile 缺失/不可读降级后也从本门收口
        //（shared_layer_dep_index），文案尾部 "check shared layer .lockfile" 即排障指引。
        assert_eq!(
            classify_replay_failure(
                "failed",
                Some("validation failed: deterministic mode provenance integrity hard gate: 2 of 283 package entries have empty sha256 or missing url (first offenders: bash-5.2.26-3.el9.x86_64 (sha256=EMPTY, url=MISSING)); refusing to succeed — the replay environment would be silently unanchored (check shared layer .lockfile / base_os .packages.json / repo url resolution)")
            ),
            Some(ReplayVerdict::InfraError)
        );
        // overlay 清单读取失败（build/mod.rs deterministic/replay 收严路径真实文案，io error 前缀）→ infra_error
        assert_eq!(
            classify_replay_failure(
                "failed",
                Some("io error: read overlay installed packages (rpm -qa --root=/crbs/root/x): rpm -qa for root failed: error: cannot open Packages index")
            ),
            Some(ReplayVerdict::InfraError)
        );
        // 空错误文本兜底 → build_failed（rpmbuild 域默认）
        assert_eq!(
            classify_replay_failure("failed", None),
            Some(ReplayVerdict::BuildFailed)
        );
    }

    /// 抽样：0% 恒假、100% 恒真、确定性（同 task 重复判定一致）、50% 大样本命中数有界。
    #[test]
    fn sampling_hit_bounds_and_determinism() {
        for id in 1..50 {
            assert!(!sampling_hit(id, 0), "0% must never hit");
            assert!(sampling_hit(id, 100), "100% must always hit");
            assert_eq!(sampling_hit(id, 37), sampling_hit(id, 37));
        }
        let hits = (1..=1000).filter(|id| sampling_hit(*id, 50)).count();
        assert!(
            (300..=700).contains(&hits),
            "50% sampling hit {hits}/1000, expected roughly half"
        );
        let hits10 = (1..=1000).filter(|id| sampling_hit(*id, 10)).count();
        assert!(
            hits10 < 300,
            "10% sampling hit {hits10}/1000, expected a small minority"
        );
    }

    /// CRUD：插入 / 按 build 列举（source 或 replay 两侧）/ 最新行 / cross_arch 幂等。
    #[tokio::test]
    async fn reproducibility_crud_roundtrip() {
        let (store, _tmp) = create_test_store().await;
        // fixture：task 1 + builds 1(source)/2(replay)。
        sqlx::query(
            "INSERT INTO tasks (product, pkg_name, \"user\", phase) VALUES ('t', 'p', '', 'succeeded')",
        )
        .execute(store.pool())
        .await
        .unwrap();
        for id in [1i64, 2] {
            sqlx::query(&format!(
                "INSERT INTO builds (id, product, pkg_name, phase, backend, \"user\", task_id) \
                 VALUES ({id}, 't', 'p-1.0-1', 'succeeded', 'chroot', '', 1)"
            ))
            .execute(store.pool())
            .await
            .unwrap();
        }

        let detail = serde_json::to_string(&CompareDetail::default()).unwrap();
        store
            .insert_reproducibility(&NewReproducibility {
                kind: KIND_REPLAY,
                source_build_id: 1,
                replay_build_id: Some(2),
                verdict: ReplayVerdict::Same,
                detail_json: Some(detail),
            })
            .await
            .unwrap();

        for build_id in [1i64, 2] {
            let rows = store
                .list_reproducibility_for_build(build_id)
                .await
                .unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].verdict, "same");
            assert_eq!(rows[0].kind, "replay");
            let latest = store
                .latest_reproducibility_for_build(build_id)
                .await
                .unwrap()
                .expect("latest row must exist");
            assert_eq!(latest.id, rows[0].id);
        }

        // cross_arch 幂等：同 source 第二次 no-op；replay 行不受 partial UNIQUE 限制。
        let inserted = store
            .insert_cross_arch_if_absent(&NewReproducibility {
                kind: KIND_CROSS_ARCH_NOARCH,
                source_build_id: 1,
                replay_build_id: None,
                verdict: ReplayVerdict::Diff,
                detail_json: None,
            })
            .await
            .unwrap();
        assert!(inserted, "first cross_arch row must insert");
        let dup = store
            .insert_cross_arch_if_absent(&NewReproducibility {
                kind: KIND_CROSS_ARCH_NOARCH,
                source_build_id: 1,
                replay_build_id: None,
                verdict: ReplayVerdict::Diff,
                detail_json: None,
            })
            .await
            .unwrap();
        assert!(!dup, "duplicate cross_arch row must be a no-op");

        store
            .insert_reproducibility(&NewReproducibility {
                kind: KIND_REPLAY,
                source_build_id: 1,
                replay_build_id: Some(2),
                verdict: ReplayVerdict::Diff,
                detail_json: None,
            })
            .await
            .unwrap();
        let rows = store.list_reproducibility_for_build(1).await.unwrap();
        assert_eq!(rows.len(), 3, "2 replay + 1 cross_arch");
    }

    /// 双保险：同 `(kind='replay', replay_build_id)` 第二次插入 no-op；同 source 换新
    /// replay 构建（重试）照常插入，不被双保险误伤。
    #[tokio::test]
    async fn replay_if_absent_absorbs_duplicate_and_allows_retry() {
        let (store, _tmp) = create_test_store().await;
        sqlx::query(
            "INSERT INTO tasks (product, pkg_name, \"user\", phase) VALUES ('t', 'p', '', 'succeeded')",
        )
        .execute(store.pool())
        .await
        .unwrap();
        for id in [1i64, 2, 3] {
            sqlx::query(&format!(
                "INSERT INTO builds (id, product, pkg_name, phase, backend, \"user\", task_id) \
                 VALUES ({id}, 't', 'p-1.0-1', 'succeeded', 'chroot', '', 1)"
            ))
            .execute(store.pool())
            .await
            .unwrap();
        }

        let row = |replay: Option<i64>, verdict| NewReproducibility {
            kind: KIND_REPLAY,
            source_build_id: 1,
            replay_build_id: replay,
            verdict,
            detail_json: None,
        };

        assert!(
            store
                .insert_replay_if_absent(&row(Some(2), ReplayVerdict::Same))
                .await
                .unwrap(),
            "first replay row must insert"
        );
        assert!(
            !store
                .insert_replay_if_absent(&row(Some(2), ReplayVerdict::Diff))
                .await
                .unwrap(),
            "duplicate (kind=replay, replay_build_id) must be absorbed"
        );
        let rows = store.list_reproducibility_for_build(2).await.unwrap();
        assert_eq!(rows.len(), 1, "absorbed duplicate must not create a row");
        assert_eq!(rows[0].verdict, "same", "first-write wins on double-fire");

        assert!(
            store
                .insert_replay_if_absent(&row(Some(3), ReplayVerdict::BuildFailed))
                .await
                .unwrap(),
            "retry with a new replay build must insert"
        );
        let rows = store.list_reproducibility_for_build(1).await.unwrap();
        assert_eq!(rows.len(), 2, "source keeps one row per replay build");
    }

    /// `insert_replay_if_absent` 的 None 防御：kind='replay' 行的幂等锚 replay_build_id
    /// 绑 None 时 SQL 三值逻辑恒不命中（无限插行），入口拒绝且不落行。
    #[tokio::test]
    async fn replay_if_absent_rejects_null_replay_build_id() {
        let (store, _tmp) = create_test_store().await;
        let err = store
            .insert_replay_if_absent(&NewReproducibility {
                kind: KIND_REPLAY,
                source_build_id: 1,
                replay_build_id: None,
                verdict: ReplayVerdict::Same,
                detail_json: None,
            })
            .await;
        assert!(
            err.is_err(),
            "None replay_build_id must be rejected at the entry"
        );
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM build_reproducibility")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(n, 0, "rejected call must not leave a row behind");
    }

    /// `NewArtifact.unsigned_sha256` 随行落列（worker 路径顺手存列的底层前提）。
    #[tokio::test]
    async fn artifact_insert_persists_unsigned_sha256() {
        let (store, _tmp) = create_test_store().await;
        sqlx::query(
            "INSERT INTO tasks (product, pkg_name, \"user\", phase) VALUES ('t', 'p', '', 'succeeded')",
        )
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO builds (id, product, pkg_name, phase, backend, \"user\", task_id) \
             VALUES (1, 't', 'p-1.0-1', 'succeeded', 'chroot', '', 1)",
        )
        .execute(store.pool())
        .await
        .unwrap();

        let a = NewArtifact {
            relative_path: "RPMS/x86_64/p-1.0-1.x86_64.rpm".to_string(),
            kind: ArtifactKind::Rpm,
            size_bytes: 10,
            sha256: "unsigned-hash".to_string(),
            unsigned_sha256: Some("unsigned-hash".to_string()),
            arch: Some("x86_64".to_string()),
            name: None,
            version: None,
            release: None,
            epoch: None,
            metadata_json: None,
            signed: false,
        };
        let mut tx = store.pool().begin().await.unwrap();
        store
            .insert_artifacts_tx(&mut tx, 1, std::slice::from_ref(&a), "2026-01-01 00:00:00")
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let listed = store.list_artifacts(1).await.unwrap();
        assert_eq!(listed[0].unsigned_sha256.as_deref(), Some("unsigned-hash"));

        // 签名刷新只动 sha256/size/signed，不触碰 unsigned_sha256。
        store
            .refresh_signed_files(
                1,
                &[(
                    "RPMS/x86_64/p-1.0-1.x86_64.rpm".into(),
                    "signed-hash".into(),
                    20,
                )],
            )
            .await
            .unwrap();
        let listed = store.list_artifacts(1).await.unwrap();
        assert_eq!(listed[0].sha256, "signed-hash");
        assert_eq!(
            listed[0].unsigned_sha256.as_deref(),
            Some("unsigned-hash"),
            "sign refresh must not touch unsigned_sha256"
        );
    }

    /// RECONCILE 候选集 core 层直测（server 侧 replay.rs 同族测试的最小版，双方言工厂跑
    /// SQLite/PG 腿随 CI）：血缘终态构建（request_json 带 reproduce_from_build_id 键且值为
    /// id、det=1、终态、无 replay 比对行）入集；非血缘终态不入集；已落比对行的不重入。
    #[tokio::test]
    async fn reconcile_candidates_filter_lineage_and_existing_rows() {
        let (store, _tmp) = create_test_store().await;
        sqlx::query(
            "INSERT INTO tasks (product, pkg_name, \"user\", phase) VALUES ('t', 'p', '', 'succeeded')",
        )
        .execute(store.pool())
        .await
        .unwrap();
        // build 1 = 血缘 source（det=1、request_json 无血缘键）；2 = 血缘终态
        // 无比对行（应入集）；3 = 血缘终态但已有 replay 行（不入集）；
        // 4 = 非血缘终态 det=1（LIKE 粗筛即排除）。
        // completed_at 走方言感知 now（SQLite 专属 datetime() 在 PG 腿直接语法炸）。
        for id in [1i64, 2, 3, 4] {
            sqlx::query(&format!(
                "INSERT INTO builds (id, product, pkg_name, phase, backend, \"user\", task_id, \
                 completed_at) VALUES ({id}, 't', 'p-1.0-1', 'succeeded', 'chroot', '', 1, {})",
                crate::state::db::Dialect::sql_now(store.dialect())
            ))
            .execute(store.pool())
            .await
            .unwrap();
        }
        for id in [1i64, 2, 3, 4] {
            store.set_build_deterministic(id, true).await.unwrap();
        }
        // build 1 = source：request_json 无血缘键（普通构建形态）；血缘键只落在 2/3
        //（replay 形态），键值为 id（get_build_reproduce_source 只认整数，JSON null 形态由 server 侧测试钉）。
        store
            .set_build_request_info(1, "/tmp/x.src.rpm", r#"{"note":"plain source"}"#)
            .await
            .unwrap();
        for id in [2i64, 3] {
            let lineage = r#"{"reproduce_from_build_id":1}"#;
            store
                .set_build_request_info(id, "/tmp/x.src.rpm", lineage)
                .await
                .unwrap();
        }
        assert!(
            store
                .insert_replay_if_absent(&NewReproducibility {
                    kind: KIND_REPLAY,
                    source_build_id: 1,
                    replay_build_id: Some(3),
                    verdict: ReplayVerdict::Same,
                    detail_json: None,
                })
                .await
                .unwrap(),
            "replay row for build 3 must insert"
        );

        let ids = store.list_builds_missing_replay_comparison().await.unwrap();
        assert_eq!(
            ids,
            vec![2],
            "only the lineage terminal build without a comparison row is a candidate"
        );
    }
}

/// 对账候选终态集的"有意子集"钉（lifecycle.rs `terminal_in_list_pins` 同族，断言子集而非
/// 等集——收编 `TERMINAL_BUILD_PHASES` 时本常量是结构性豁免点位：const SQL 无法挂运行时
/// 渲染器）。IN 集 == `TERMINAL_BUILD_PHASES` 渲染集 − {cancelled}：cancelled 的 replay
/// 构建本就不落比对行，入集只会每次启动空转钩子；未来加第 5 终态本钉必红，强制显式决策。
#[cfg(test)]
mod reconcile_terminal_subset_pins {
    use super::sql;
    use crate::state::test_state::sql_in_value_sets;

    #[test]
    fn reconcile_missing_replay_in_set_is_terminal_minus_cancelled() {
        let expected: std::collections::BTreeSet<&str> = crate::types::TERMINAL_BUILD_PHASES
            .iter()
            .copied()
            .filter(|p| *p != "cancelled")
            .collect();
        let sets = sql_in_value_sets(sql::RECONCILE_MISSING_REPLAY_CANDIDATES);
        assert_eq!(sets.len(), 1, "expected exactly one IN list, got: {sets:?}");
        assert_eq!(
            sets[0], expected,
            "RECONCILE_MISSING_REPLAY_CANDIDATES terminal set must stay \
             TERMINAL_BUILD_PHASES minus cancelled (intentional subset)"
        );
    }
}
