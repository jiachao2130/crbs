// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建产物元数据存储（build_artifacts 表 CRUD）：每个 build 对应 N 个
//! artifact 行；TEXT 时间 / INTEGER bool / ON DELETE CASCADE / ON CONFLICT 幂等。

use crate::error::DbResultExt;
use crate::state::StateStore;
use sqlx::Row;
use std::fmt;

/// artifact 类型枚举（与 CHECK 约束值严格一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ArtifactKind {
    /// 二进制 RPM（repo 发布候选与复现比对主体）。
    Rpm,
    /// 源码 RPM（changelog 优先解析源；不参与复现比对）。
    Srpm,
    /// 构建日志（.log）。
    Log,
    /// 元数据文件（profile.json / build_packages.json）。
    Metadata,
    /// 构建脚本留档（crbs-build.sh）。
    Script,
    /// 兜底：未识别扩展/文件名（`From<&str>` 未知值也归此）。
    Other,
}

impl ArtifactKind {
    /// CHECK 约束域存储值（`"rpm"` 等）；落库绑定与 [`fmt::Display`] 共用。
    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::Rpm => "rpm",
            ArtifactKind::Srpm => "srpm",
            ArtifactKind::Log => "log",
            ArtifactKind::Metadata => "metadata",
            ArtifactKind::Script => "script",
            ArtifactKind::Other => "other",
        }
    }
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for ArtifactKind {
    fn from(s: &str) -> Self {
        match s {
            "rpm" => ArtifactKind::Rpm,
            "srpm" => ArtifactKind::Srpm,
            "log" => ArtifactKind::Log,
            "metadata" => ArtifactKind::Metadata,
            "script" => ArtifactKind::Script,
            _ => ArtifactKind::Other,
        }
    }
}

/// DB 行 → 业务模型中间类型（AnyRow 上 FromRow derive 不可用，手动映射）。
#[derive(Debug)]
struct ArtifactRow {
    id: i64,
    build_id: i64,
    relative_path: String,
    kind: String,
    size_bytes: i64,
    sha256: String,
    unsigned_sha256: Option<String>,
    arch: Option<String>,
    name: Option<String>,
    version: Option<String>,
    release: Option<String>,
    epoch: Option<i64>,
    signed: bool,
    on_disk: bool,
    metadata_json: Option<String>,
    created_at: String,
}

impl ArtifactRow {
    fn from_row(row: &sqlx::any::AnyRow) -> Self {
        let signed_i: i64 = row.get("signed");
        let on_disk_i: i64 = row.get("on_disk");
        Self {
            id: row.get("id"),
            build_id: row.get("build_id"),
            relative_path: row.get("relative_path"),
            kind: row.get("kind"),
            size_bytes: row.get("size_bytes"),
            sha256: row.get("sha256"),
            unsigned_sha256: row.get("unsigned_sha256"),
            arch: row.get("arch"),
            name: row.get("name"),
            version: row.get("version"),
            release: row.get("release"),
            epoch: row.get("epoch"),
            signed: signed_i == 1,
            on_disk: on_disk_i == 1,
            metadata_json: row.get("metadata_json"),
            created_at: row.get("created_at"),
        }
    }
}

/// 构建产物元数据（业务模型）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct Artifact {
    pub id: i64,
    pub build_id: i64,
    pub relative_path: String,
    pub kind: ArtifactKind,
    pub size_bytes: u64,
    pub sha256: String,
    /// 签名前哈希留档：worker 首插 = sha256 初值；hub-local 签名前预计算；签名刷新不触碰；None = 未记录（比对锚缺失）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<i64>,
    pub signed: bool,
    pub on_disk: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_json: Option<String>,
    pub created_at: String,
}

impl From<ArtifactRow> for Artifact {
    fn from(row: ArtifactRow) -> Self {
        Self {
            id: row.id,
            build_id: row.build_id,
            relative_path: row.relative_path,
            kind: ArtifactKind::from(row.kind.as_str()),
            size_bytes: row.size_bytes as u64,
            sha256: row.sha256,
            unsigned_sha256: row.unsigned_sha256,
            arch: row.arch,
            name: row.name,
            version: row.version,
            release: row.release,
            epoch: row.epoch,
            signed: row.signed,
            on_disk: row.on_disk,
            metadata_json: row.metadata_json,
            created_at: row.created_at,
        }
    }
}

/// 新产物入库参数。
#[derive(Debug, Clone)]
pub struct NewArtifact {
    pub relative_path: String,
    pub kind: ArtifactKind,
    pub size_bytes: u64,
    pub sha256: String,
    /// 签名前哈希留档：worker 上传传 `Some(sha256.clone())`（首插即未签名
    /// 哈希），hub-local 传签名前预计算值；`None` = 不写（COALESCE 保旧见 INSERT_ARTIFACT）。
    pub unsigned_sha256: Option<String>,
    pub arch: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub release: Option<String>,
    pub epoch: Option<i64>,
    pub metadata_json: Option<String>,
    /// 行级 signed 标志：仅 RPM/SRPM 在 hub-local 签完后为 true。
    pub signed: bool,
}

/// worker 产物上传落库事务的提交结果。
#[derive(Debug)]
pub enum UploadedArtifactsCommit {
    /// 相位/归属 CAS 守卫通过并 COMMIT 成功；携带新产物行 id（空上传为空表）。
    Committed(Vec<i64>),
    /// 守卫 UPDATE 0 行（相位翻终态 / assignment 被 reclaim 删行重派）：已回滚，**确定未提交**。
    GuardRejected,
}

/// 上传落库事务的失败形态——区分"确定未提交"与"提交结果不确定"，调用方据此决定清盘策略。
#[derive(Debug)]
pub enum UploadedArtifactsCommitError {
    /// begin / 产物插入 / 守卫 UPDATE 失败：已回滚，确定未提交，可安全清掉本次已写盘文件。
    RolledBack(crate::error::CrbsError),
    /// COMMIT 失败：结果不确定（可能已持久化、仅响应丢失），**不得**清盘，worker 重试上传覆盖收敛兜底。
    CommitUncertain(crate::error::CrbsError),
}

/// 指纹反查联表行：by-sha256 端点一次 JOIN 取回产物 + 所属构建的
/// product/phase/result_dir（可见性过滤 / changelog 磁盘定位），消 N+1。
#[derive(Debug, Clone)]
pub struct ArtifactWithBuild {
    pub artifact: Artifact,
    /// 所属构建的产品名（可见性过滤键 + 展示）。
    pub product: String,
    pub phase: String,
    /// 所属构建的结果目录（changelog 端点定位磁盘 RPM 用；GC 清空后为 None）。
    pub result_dir: Option<String>,
}

/// crbs-artifacts.json 磁盘 provenance 格式（版本 1）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArtifactsJson {
    pub version: u32,
    pub build_id: Option<i64>,
    pub artifacts: Vec<ArtifactJsonEntry>,
}

/// crbs-artifacts.json 单条 entry。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArtifactJsonEntry {
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<i64>,
}

/// 可发布 RPM/SRPM（`list_publishable_rpms` 返回行，过滤/去重语义见该 SQL）：
/// 每组 (name,version,release,arch,kind,relative_path) 取 `MAX(build_id)`；行按
/// `build_id` 降序——撞同 basename 时调用方（repo_publish 首行胜出）newest-wins。
#[derive(Debug, Clone)]
pub struct PublishableRpm {
    /// 产出该文件的构建 id（`MAX(build_id)`）。
    pub build_id: i64,
    /// 该构建的结果目录（绝对路径；GC 清空后为 None）。
    pub result_dir: Option<String>,
    /// 产物相对 `result_dir` 的路径。
    pub relative_path: String,
    /// 产物 arch（srpm 可能为 `src`/NULL）。
    pub arch: Option<String>,
    pub kind: String,
}

mod sql {
    /// 插入单行（幂等：UNIQUE(build_id, relative_path) 冲突原地更新，行 id 不变）；
    /// ON CONFLICT DO UPDATE 双方言（SQLite ≥3.24 / PG）语义一致。unsigned_sha256
    /// 插入侧写 `$6`（None → NULL）；upsert 分支 COALESCE 保旧——签名后重采集拿
    /// 不到签名前哈希时，不用签名后哈希覆盖比对锚。
    pub(super) const INSERT_ARTIFACT: &str =
        "INSERT INTO build_artifacts (build_id, relative_path, kind, \
         size_bytes, sha256, unsigned_sha256, arch, name, version, release, epoch, \
         signed, on_disk, metadata_json, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
         ON CONFLICT (build_id, relative_path) DO UPDATE SET \
             size_bytes = EXCLUDED.size_bytes, \
             sha256 = EXCLUDED.sha256, \
             unsigned_sha256 = COALESCE(EXCLUDED.unsigned_sha256, build_artifacts.unsigned_sha256), \
             arch = EXCLUDED.arch, \
             name = EXCLUDED.name, \
             version = EXCLUDED.version, \
             release = EXCLUDED.release, \
             epoch = EXCLUDED.epoch, \
             signed = EXCLUDED.signed, \
             on_disk = EXCLUDED.on_disk, \
             metadata_json = EXCLUDED.metadata_json \
         RETURNING id";

    /// 列出 build 的所有 artifact（默认只查 on_disk=1，GC 翻 0 后不返回）。
    pub(super) const LIST_BY_BUILD: &str =
        "SELECT id, build_id, relative_path, kind, size_bytes, sha256, \
         unsigned_sha256, arch, name, version, release, epoch, signed, on_disk, \
         metadata_json, created_at \
         FROM build_artifacts WHERE build_id = $1 AND on_disk = 1 \
         ORDER BY kind, relative_path";

    /// 指纹反查联表版 SQL 骨架：`{where}` 由调用方叠加可见性白名单（必须在
    /// LIMIT 之前——先 LIMIT 再过滤会在同一哈希重复产出 >200 时丢掉可见旧行）。
    pub(super) fn find_by_sha256_join_build(where_sql: &str) -> String {
        format!(
            "SELECT a.id, a.build_id, a.relative_path, a.kind, a.size_bytes, a.sha256, \
             a.unsigned_sha256, a.arch, a.name, a.version, a.release, a.epoch, a.signed, a.on_disk, \
             a.metadata_json, a.created_at, b.product, b.phase, b.result_dir \
             FROM build_artifacts a JOIN builds b ON b.id = a.build_id \
             WHERE {where_sql} \
             ORDER BY a.created_at DESC \
             LIMIT 200"
        )
    }

    /// 同构建的在盘 SRPM 行（changelog SRPM 优先解析用）：ORDER BY relative_path
    /// LIMIT 1 使多行时确定；走 UNIQUE (build_id, relative_path) 约束索引（build_id 前缀）。
    pub(super) const FIND_SRPM_FOR_BUILD: &str =
        "SELECT id, build_id, relative_path, kind, size_bytes, sha256, \
         unsigned_sha256, arch, name, version, release, epoch, signed, on_disk, \
         metadata_json, created_at \
         FROM build_artifacts WHERE build_id = $1 AND on_disk = 1 AND kind = 'srpm' \
         ORDER BY relative_path \
         LIMIT 1";

    /// 同构建首个在盘 rpm/srpm 行（changelog build 作用域回退源，srpm 缺失/
    /// 不可达时用）：ORDER BY relative_path LIMIT 1 使多行时确定；走 UNIQUE
    /// (build_id, relative_path) 约束索引（build_id 前缀）。
    pub(super) const FIND_RPM_OR_SRPM_FOR_BUILD: &str =
        "SELECT id, build_id, relative_path, kind, size_bytes, sha256, \
         unsigned_sha256, arch, name, version, release, epoch, signed, on_disk, \
         metadata_json, created_at \
         FROM build_artifacts WHERE build_id = $1 AND on_disk = 1 AND kind IN ('rpm', 'srpm') \
         ORDER BY relative_path \
         LIMIT 1";

    /// 签名哈希刷新：同时翻 signed=1（签名成功的语义）；created_at 创建时间不可变。
    pub(super) const REFRESH_SIGNED_FILE: &str =
        "UPDATE build_artifacts SET sha256 = $1, size_bytes = $2, signed = 1 \
         WHERE build_id = $3 AND relative_path = $4";

    /// GC：build 删文件后翻 on_disk=0，保留行（审计/复现价值）。
    pub(super) const MARK_OFF_DISK: &str =
        "UPDATE build_artifacts SET on_disk = 0 WHERE build_id = $1 AND on_disk = 1";

    /// 产品 repo 候选集（发布轴候选查询）：组键 (name,version,release,arch,kind,
    /// relative_path) 取 `MAX(build_id)`；过滤链：产品名 / `phase='succeeded'` /
    /// `repo_publish=1`（在去重前——收紧构建整体消失而非顶掉上一次）/
    /// `$2=0 OR bb.signed=1`（签名策略门控，同样在去重前：未签名新构建不得
    /// 顶掉已签名的同 N-V-R 旧构建）/ `on_disk=1` / `kind IN ('rpm','srpm')`；
    /// 有意不含 epoch（冲突键 = 文件名键 N-V-R.A）。GROUP BY 含 relative_path
    /// 使组内恒定、回连以 `MAX(build_id)` 取 result_dir，免对可空 arch 做不便携
    /// null-safe 等值；外层 ORDER BY build_id DESC 使撞 basename 时首行胜出 =
    /// newest-wins。`$n` 占位符 + IN 常量列表双方言可移植。
    pub(super) const LIST_PUBLISHABLE_RPMS: &str = "SELECT b.id AS build_id, \
         b.result_dir AS result_dir, latest.relative_path AS relative_path, \
         latest.arch AS arch, latest.kind AS kind \
         FROM ( \
           SELECT a.name, a.version, a.release, a.arch, a.kind, a.relative_path, \
                  MAX(a.build_id) AS max_build_id \
           FROM build_artifacts a \
           JOIN builds bb ON bb.id = a.build_id \
           WHERE bb.product = $1 AND bb.phase = 'succeeded' \
             AND bb.repo_publish = 1 \
             AND ($2 = 0 OR bb.signed = 1) \
             AND a.on_disk = 1 AND a.kind IN ('rpm', 'srpm') \
           GROUP BY a.name, a.version, a.release, a.arch, a.kind, a.relative_path \
         ) latest \
         JOIN builds b ON b.id = latest.max_build_id \
         ORDER BY build_id DESC";
}

impl StateStore {
    /// 批量插入产物（事务内幂等）：新行共享同一 created_at（调用方传，Rust 侧
    /// 生成）；ON CONFLICT 原地更新（行 id 不变）。`signed` 由调用方按 kind 逐行
    /// 设置：worker 上传一律 false；hub-local 仅 RPM/SRPM 签完后 true。
    pub async fn insert_artifacts_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        build_id: i64,
        artifacts: &[NewArtifact],
        created_at: &str,
    ) -> crate::Result<Vec<i64>> {
        let sql = sql::INSERT_ARTIFACT;
        let mut ids = Vec::with_capacity(artifacts.len());
        for a in artifacts {
            let id: i64 = sqlx::query_scalar(sql)
                .bind(build_id)
                .bind(&a.relative_path)
                .bind(a.kind.as_str())
                .bind(a.size_bytes as i64)
                .bind(&a.sha256)
                .bind(&a.unsigned_sha256)
                .bind(&a.arch)
                .bind(&a.name)
                .bind(&a.version)
                .bind(&a.release)
                .bind(a.epoch)
                .bind(if a.signed { 1 } else { 0 })
                .bind(1) // on_disk 默认为 1
                .bind(&a.metadata_json)
                .bind(created_at)
                .fetch_one(&mut **tx)
                .await
                .db_ctx(&format!("insert artifact {}", a.relative_path))?;
            ids.push(id);
        }
        Ok(ids)
    }

    /// worker 产物上传落库事务：result_dir 与产物行同一事务——拆开提交崩在中间
    /// 会留 "succeeded + result_dir=NULL" 毒化态（下载/日志定位失效、无自愈）。
    /// 写入经 `Self::update_build_info_tx_guarded` 复查 phase + assignment 归属
    ///（双 CAS；入口复查是事务外读，PG BEGIN 不锁行，UPDATE 在写入时刻复查）。
    /// 0 行 = 相位被并发取消/超时/收口翻终态（或行已删），或 assignment 被
    /// reclaim 删行重派（旧执行产物不进重派 build 的命名空间）→ 回滚返回
    /// [`UploadedArtifactsCommit::GuardRejected`]（确定未提交），调用方清盘后 409。
    /// 空 `artifacts` 仍执行守卫 UPDATE 与 COMMIT（result_dir 落定不依赖产物行）；
    /// `backend` 传 build record 原值（UPDATE 无条件 SET backend，空串会覆写引擎
    /// set_info 的真实值）。残留竞态：按路径清盘可能删掉剥夺窗口内新 worker 写的
    /// 同名文件（可容忍残留，协议级 lease 为升级路径）。COMMIT 成功即广播（result_dir
    /// 是 log SSE 来源探测信号）；失败上抛 CommitUncertain，不清盘（重试覆盖收敛）。
    pub async fn commit_uploaded_artifacts(
        &self,
        build_id: i64,
        artifacts: &[NewArtifact],
        result_dir: &str,
        backend: &str,
        worker_id: i64,
        assignment_id: Option<i64>,
    ) -> std::result::Result<UploadedArtifactsCommit, UploadedArtifactsCommitError> {
        let created_at = crate::util::db_now_utc();
        let mut tx = self
            .pool()
            .begin()
            .await
            .db_ctx("begin upload artifacts tx")
            .map_err(UploadedArtifactsCommitError::RolledBack)?;

        let insert_result = if artifacts.is_empty() {
            Ok(Vec::new())
        } else {
            self.insert_artifacts_tx(&mut tx, build_id, artifacts, &created_at)
                .await
        };
        let ids = match insert_result {
            Ok(ids) => ids,
            Err(e) => {
                let _ = tx.rollback().await;
                return Err(UploadedArtifactsCommitError::RolledBack(e));
            }
        };

        let rows = self
            .update_build_info_tx_guarded(
                &mut tx,
                super::builds::GuardedBuildInfo {
                    id: build_id,
                    result_dir: Some(result_dir),
                    base_os_digest: None,
                    backend,
                    worker_id,
                    assignment_id,
                },
            )
            .await;
        match rows {
            // CAS 第二道防线拒绝：rollback 确定未提交，调用方清盘 + 409。
            Ok(0) => {
                let _ = tx.rollback().await;
                return Ok(UploadedArtifactsCommit::GuardRejected);
            }
            Ok(_) => {}
            Err(e) => {
                let _ = tx.rollback().await;
                return Err(UploadedArtifactsCommitError::RolledBack(e));
            }
        }

        if let Err(e) = tx.commit().await.db_ctx("commit upload artifacts tx") {
            return Err(UploadedArtifactsCommitError::CommitUncertain(e));
        }
        self.notify_state_changed();
        Ok(UploadedArtifactsCommit::Committed(ids))
    }

    /// hub-local 收尾的产物落库事务：单事务 insert，产物行全量或全无；引擎已
    /// 先行翻终态并落 result_dir，本事务只管产物行（成功 / 失败采集 / 崩溃
    /// reconcile 三处共用），失败由调用方降级 warn（终态不受影响，reconcile
    /// 兜底）。空 `artifacts` 不开事务；不广播（result_dir 由引擎侧更早写入时广播）。
    pub async fn commit_local_build_artifacts(
        &self,
        build_id: i64,
        artifacts: &[NewArtifact],
    ) -> crate::Result<Vec<i64>> {
        if artifacts.is_empty() {
            return Ok(Vec::new());
        }
        let created_at = crate::util::db_now_utc();
        let mut tx = self
            .pool()
            .begin()
            .await
            .db_ctx("begin local build artifacts tx")?;
        let ids = match self
            .insert_artifacts_tx(&mut tx, build_id, artifacts, &created_at)
            .await
        {
            Ok(ids) => ids,
            Err(e) => {
                // 回滚保证已插部分不落地（全量或全无）。
                let _ = tx.rollback().await;
                return Err(e);
            }
        };
        tx.commit()
            .await
            .db_ctx("commit local build artifacts tx")?;
        Ok(ids)
    }

    /// 列出 build 的所有在盘产物（on_disk=1）。
    pub async fn list_artifacts(&self, build_id: i64) -> crate::Result<Vec<Artifact>> {
        let rows = sqlx::query(sql::LIST_BY_BUILD)
            .bind(build_id)
            .fetch_all(self.pool())
            .await
            .db_ctx("list artifacts")?;
        Ok(rows
            .iter()
            .map(|r| ArtifactRow::from_row(r).into())
            .collect())
    }

    /// 批量列出多个 build 的在盘产物（单条 `WHERE build_id IN` 消除 N+1）；空
    /// `build_ids` 返回空 Vec。
    // ponytail: IN 参数上限由 in_placeholders 守卫约束（MAX_BIND_PARAMS=30_000）；
    // 实际 child build 数远低于此，无需分片。
    pub async fn list_artifacts_for_builds(
        &self,
        build_ids: &[i64],
    ) -> crate::Result<Vec<Artifact>> {
        if build_ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = crate::state::db::in_placeholders(1, build_ids.len())?;
        let sql_text = format!(
            "SELECT id, build_id, relative_path, kind, size_bytes, sha256, \
             unsigned_sha256, arch, name, version, release, epoch, signed, on_disk, \
             metadata_json, created_at \
             FROM build_artifacts WHERE build_id IN ({}) AND on_disk = 1 \
             ORDER BY build_id, kind, relative_path",
            placeholders
        );
        let mut q = sqlx::query(&sql_text);
        for &id in build_ids {
            q = q.bind(id);
        }
        let rows = q
            .fetch_all(self.pool())
            .await
            .db_ctx("list artifacts for builds")?;
        Ok(rows
            .iter()
            .map(|r| ArtifactRow::from_row(r).into())
            .collect())
    }

    /// 指纹反查联表版：artifact + 所属 build 的 product/phase 一次 JOIN 取回。
    /// `visible_products` 尽力在 SQL 内（LIMIT 之前）过滤；None = 不限制。
    pub async fn find_artifacts_by_sha256_with_build(
        &self,
        sha256: &str,
        visible_products: Option<&Vec<String>>,
    ) -> crate::Result<Vec<ArtifactWithBuild>> {
        let mut binds = vec![sha256.to_string()];
        let where_sql = Self::apply_visible_products(
            "a.sha256 = $1 AND a.on_disk = 1".to_string(),
            &mut binds,
            visible_products,
        )?;
        let statement = sql::find_by_sha256_join_build(&where_sql);
        let mut query = sqlx::query(&statement);
        for bind in &binds {
            query = query.bind(bind);
        }
        let rows = query
            .fetch_all(self.pool())
            .await
            .db_ctx("find by sha256 with build")?;
        Ok(rows
            .iter()
            .map(|r| ArtifactWithBuild {
                artifact: ArtifactRow::from_row(r).into(),
                product: r.get("product"),
                phase: r.get("phase"),
                result_dir: r.get("result_dir"),
            })
            .collect())
    }

    /// 查同构建的在盘 SRPM 行（changelog SRPM 优先解析用）：产物共享
    /// `builds.result_dir`，`relative_path` 配该目录即定位磁盘文件；无 srpm 行
    /// 或已 GC（on_disk=0）返回 None。
    pub async fn find_srpm_for_build(&self, build_id: i64) -> crate::Result<Option<Artifact>> {
        let row = sqlx::query(sql::FIND_SRPM_FOR_BUILD)
            .bind(build_id)
            .fetch_optional(self.pool())
            .await
            .db_ctx("find srpm for build")?;
        Ok(row.map(|r| ArtifactRow::from_row(&r).into()))
    }

    /// 查同构建首个在盘 rpm/srpm 行（changelog 回退源，`relative_path` 字典序）：
    /// 调用方先试 [`Self::find_srpm_for_build`]，缺失/不可达时回退本查询。
    pub async fn find_rpm_or_srpm_for_build(
        &self,
        build_id: i64,
    ) -> crate::Result<Option<Artifact>> {
        let row = sqlx::query(sql::FIND_RPM_OR_SRPM_FOR_BUILD)
            .bind(build_id)
            .fetch_optional(self.pool())
            .await
            .db_ctx("find rpm or srpm for build")?;
        Ok(row.map(|r| ArtifactRow::from_row(&r).into()))
    }

    /// 事务化刷新多文件 sha256/size（全量或全不）：单条失败仅 warn 会留 "部分行
    /// 新鲜 + builds.signed 已置位" 半刷新态，故任一 UPDATE 错 → best-effort
    /// ROLLBACK，全行保持签名前旧值（重跑收敛）。`begin_write()`（SQLite
    /// `BEGIN IMMEDIATE` / PG `BEGIN`）+ 显式 COMMIT；`relative_path` 无对应行
    ///（0 rows）= 磁盘与表不一致，ROLLBACK 整体报错（产物文件必有行）。`files`
    /// 为 (relative_path, sha256, size_bytes) 三元组；返回成功行数。
    pub async fn refresh_signed_files(
        &self,
        build_id: i64,
        files: &[(String, String, i64)],
    ) -> crate::Result<usize> {
        let mut conn = self.begin_write().await?;
        let mut refreshed = 0usize;
        for (relative_path, sha256, size_bytes) in files {
            let res = match sqlx::query(sql::REFRESH_SIGNED_FILE)
                .bind(sha256)
                .bind(size_bytes)
                .bind(build_id)
                .bind(relative_path)
                .execute(&mut *conn)
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    return Err::<usize, _>(e).db_ctx("refresh signed file");
                }
            };
            if res.rows_affected() == 0 {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                // 消息含 relative_path/build_id 的脱敏考量：`crbs sign` CLI 操作者
                // 本就掌握服务端路径；server 只写服务端日志，HTTP 响应走调用方
                // 自备脱敏消息（routes/builds/sign.rs），不透传客户端。
                return Err(crate::error::CrbsError::ValidationFailed {
                    message: format!(
                        "no build_artifacts row for signed file '{relative_path}' (build {build_id})"
                    ),
                });
            }
            refreshed += 1;
        }
        // COMMIT 失败也 best-effort ROLLBACK，防开事务连接回池（PG 25P02 / SQLite 持写锁）。
        if let Err(e) = sqlx::query("COMMIT").execute(&mut *conn).await {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(e).db_ctx("commit refresh signed files");
        }
        Ok(refreshed)
    }

    /// GC：build 删文件后翻 on_disk=0，保留行（审计/复现价值）；幂等。
    pub async fn mark_artifacts_off_disk(&self, build_id: i64) -> crate::Result<u64> {
        let affected = sqlx::query(sql::MARK_OFF_DISK)
            .bind(build_id)
            .execute(self.pool())
            .await
            .db_ctx("mark off disk")?;
        Ok(affected.rows_affected())
    }

    /// 产品 repo 候选集：可发布的 RPM/SRPM（step 1，SQL 语义见
    /// `sql::LIST_PUBLISHABLE_RPMS`）；供 `engine::repo_publish` 组装产品 repo。
    /// `require_signed=true`（产品声明了签名策略）时只取 `builds.signed=1`
    /// 的构建：未签名产物不得进发布 repo。
    pub async fn list_publishable_rpms(
        &self,
        product: &str,
        require_signed: bool,
    ) -> crate::Result<Vec<PublishableRpm>> {
        let rows = sqlx::query(sql::LIST_PUBLISHABLE_RPMS)
            .bind(product)
            .bind(if require_signed { 1i64 } else { 0i64 })
            .fetch_all(self.pool())
            .await
            .db_ctx("list publishable rpms")?;
        Ok(rows
            .iter()
            .map(|r| PublishableRpm {
                build_id: r.get("build_id"),
                result_dir: r.get("result_dir"),
                relative_path: r.get("relative_path"),
                arch: r.get("arch"),
                kind: r.get("kind"),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 导入 test_state 模块的双后端测试 helper
    use crate::state::test_state::create_test_store;

    /// 夹具：插一对 task + id=1 的 succeeded build（产物测试共用宿主行）。
    async fn seed_build_row(store: &StateStore) {
        sqlx::query(
            // 双方言：PG prepared protocol 不允许多语句字符串，tasks/builds 分两条。
            "INSERT INTO tasks (product, pkg_name, \"user\", phase) VALUES ('test', 'hello', '', 'succeeded')",
        )
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            // arch 随行落定：fixture 与生产（insert_build 随行写 arch）形态一致。
            "INSERT INTO builds (id, product, pkg_name, phase, backend, name, version, release, started_at, arch, task_id) \
             VALUES (1, 'test', 'hello', 'succeeded', 'mock', 'hello', '1.0', '1', 'now', 'x86_64', 1)",
        )
        .execute(store.pool())
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_artifact_crud_flow() {
        let (store, _tmp_guard) = create_test_store().await;

        let artifacts = vec![NewArtifact {
            relative_path: "RPMS/x86_64/hello-1.0-1.x86_64.rpm".to_string(),
            kind: ArtifactKind::Rpm,
            size_bytes: 1024,
            sha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            unsigned_sha256: None,
            arch: Some("x86_64".to_string()),
            name: Some("hello".to_string()),
            version: Some("1.0".to_string()),
            release: Some("1".to_string()),
            epoch: Some(1),
            metadata_json: None,
            signed: false,
        }];

        seed_build_row(&store).await;

        let mut tx = store.pool().begin().await.unwrap();
        let ids = store
            .insert_artifacts_tx(&mut tx, 1, &artifacts, "2026-01-01 00:00:00")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(ids.len(), 1);

        let list = store.list_artifacts(1).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].relative_path, artifacts[0].relative_path);
        assert_eq!(list[0].size_bytes, artifacts[0].size_bytes);
        assert_eq!(list[0].sha256, artifacts[0].sha256);
        assert!(list[0].on_disk);
        assert!(!list[0].signed);

        let found = store
            .find_artifacts_by_sha256_with_build(&artifacts[0].sha256, None)
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].artifact.build_id, 1);

        let new_sha256 = "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff";
        store
            .refresh_signed_files(
                1,
                &[(
                    artifacts[0].relative_path.clone(),
                    new_sha256.to_string(),
                    2048,
                )],
            )
            .await
            .unwrap();
        let after_sign = store.list_artifacts(1).await.unwrap();
        assert_eq!(after_sign[0].sha256, new_sha256);
        assert_eq!(after_sign[0].size_bytes, 2048);
        assert!(after_sign[0].signed);

        let affected = store.mark_artifacts_off_disk(1).await.unwrap();
        assert_eq!(affected, 1);
        let list_after_gc = store.list_artifacts(1).await.unwrap();
        assert_eq!(list_after_gc.len(), 0, "list_artifacts 应该只返 on_disk=1");
    }

    /// refresh_signed_files 事务化多文件：命中行更新哈希/size 并返回数；无行文件整体报错且已刷新部分回滚。
    #[tokio::test]
    async fn test_refresh_signed_files_hits_and_missing() {
        let (store, _tmp_guard) = create_test_store().await;

        seed_build_row(&store).await;

        let rel = "RPMS/x86_64/hello-1.0-1.x86_64.rpm".to_string();
        let artifacts = vec![NewArtifact {
            relative_path: rel.clone(),
            kind: ArtifactKind::Rpm,
            size_bytes: 1024,
            sha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            unsigned_sha256: None,
            arch: Some("x86_64".to_string()),
            name: Some("hello".to_string()),
            version: Some("1.0".to_string()),
            release: Some("1".to_string()),
            epoch: Some(1),
            metadata_json: None,
            signed: false,
        }];
        let mut tx = store.pool().begin().await.unwrap();
        store
            .insert_artifacts_tx(&mut tx, 1, &artifacts, "2026-01-01 00:00:00")
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let new_sha = "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff";
        let err = store
            .refresh_signed_files(
                1,
                &[
                    (rel.clone(), new_sha.to_string(), 2048),
                    (
                        "RPMS/x86_64/ghost-9.9-9.x86_64.rpm".to_string(),
                        new_sha.to_string(),
                        4096,
                    ),
                ],
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("ghost-9.9-9"),
            "error must name the unrowed file: {err}"
        );

        let after = store.list_artifacts(1).await.unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].sha256, artifacts[0].sha256);
        assert_eq!(after[0].size_bytes, 1024);
        assert!(!after[0].signed, "rolled-back refresh must not flip signed");

        let refreshed = store
            .refresh_signed_files(1, &[(rel.clone(), new_sha.to_string(), 2048)])
            .await
            .unwrap();
        assert_eq!(refreshed, 1);
        let after = store.list_artifacts(1).await.unwrap();
        assert_eq!(after[0].sha256, new_sha);
        assert_eq!(after[0].size_bytes, 2048);
        assert!(after[0].signed, "命中的行应翻 signed=1");
    }

    /// ON CONFLICT DO UPDATE 幂等：重复插同一 (build_id, relative_path) 原地更新而非造新行。
    #[tokio::test]
    async fn test_artifact_insert_idempotent() {
        let (store, _tmp_guard) = create_test_store().await;

        seed_build_row(&store).await;

        let v1 = NewArtifact {
            relative_path: "RPMS/x86_64/hello-1.0-1.x86_64.rpm".to_string(),
            kind: ArtifactKind::Rpm,
            size_bytes: 1000,
            sha256: "hashv1".to_string(),
            unsigned_sha256: None,
            arch: Some("x86_64".to_string()),
            name: Some("hello".to_string()),
            version: Some("1.0".to_string()),
            release: Some("1".to_string()),
            epoch: None,
            metadata_json: None,
            signed: false,
        };

        let mut tx1 = store.pool().begin().await.unwrap();
        let ids1 = store
            .insert_artifacts_tx(
                &mut tx1,
                1,
                std::slice::from_ref(&v1),
                "2026-01-01 00:00:00",
            )
            .await
            .unwrap();
        tx1.commit().await.unwrap();
        assert_eq!(ids1.len(), 1);

        let v2 = NewArtifact {
            relative_path: v1.relative_path.clone(), // 同一路径
            kind: ArtifactKind::Rpm,
            size_bytes: 2000,
            sha256: "hashv2".to_string(),
            unsigned_sha256: None,
            arch: v1.arch.clone(),
            name: v1.name.clone(),
            version: v1.version.clone(),
            release: v1.release.clone(),
            epoch: Some(2),
            metadata_json: Some(r#"{"updated": true}"#.to_string()),
            signed: true, // upsert 时 signed 也会更新
        };

        let mut tx2 = store.pool().begin().await.unwrap();
        let ids2 = store
            .insert_artifacts_tx(
                &mut tx2,
                1,
                std::slice::from_ref(&v2),
                "2026-01-01 00:00:01",
            )
            .await
            .unwrap();
        tx2.commit().await.unwrap();

        // 应更新而非新行：双方言统一 ON CONFLICT DO UPDATE（非 INSERT OR REPLACE
        // 删+重插），行 id 双侧不漂移（重 harvest 复用首插 id）。
        assert_eq!(
            ids2, ids1,
            "re-harvest must update in place, keeping row id"
        );
        let list = store.list_artifacts(1).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, ids1[0], "row id must not change on upsert");
        assert_eq!(list[0].size_bytes, 2000);
        assert_eq!(list[0].sha256, "hashv2");
        assert_eq!(list[0].epoch, Some(2));
        assert_eq!(
            list[0].metadata_json.as_deref(),
            Some(r#"{"updated": true}"#)
        );
        assert!(list[0].signed, "upsert must refresh the signed flag too");
    }

    /// 测试 build_artifacts.build_id ON DELETE CASCADE：删除 build 应该级联删 artifacts。
    #[tokio::test]
    async fn test_build_delete_cascades_artifacts() {
        let (store, _tmp_guard) = create_test_store().await;

        seed_build_row(&store).await;

        let artifact = NewArtifact {
            relative_path: "build.log".to_string(),
            kind: ArtifactKind::Log,
            size_bytes: 500,
            sha256: "loghash".to_string(),
            unsigned_sha256: None,
            arch: None,
            name: None,
            version: None,
            release: None,
            epoch: None,
            metadata_json: None,
            signed: false,
        };

        let mut tx = store.pool().begin().await.unwrap();
        store
            .insert_artifacts_tx(&mut tx, 1, &[artifact], "2026-01-01 00:00:00")
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let list_before = store.list_artifacts(1).await.unwrap();
        assert_eq!(list_before.len(), 1);

        sqlx::query("DELETE FROM builds WHERE id = 1")
            .execute(store.pool())
            .await
            .unwrap();

        let list_after = store.list_artifacts(1).await.unwrap();
        assert_eq!(list_after.len(), 0, "CASCADE 应该删除 artifacts");
    }

    /// list_artifacts_for_builds 批量：多 build 各有产物，一次查出全部在盘且按 build_id 排序。
    #[tokio::test]
    async fn test_list_artifacts_for_builds() {
        let (store, _tmp_guard) = create_test_store().await;

        for (id, product) in [(1i64, "p1"), (2, "p2")] {
            // task_id NOT NULL：每个 build 先插一条本地 task 行。
            let task_id: i64 = sqlx::query_scalar(
                "INSERT INTO tasks (product, pkg_name, \"user\", phase) \
                 VALUES ($1, 'pkg', '', 'succeeded') RETURNING id",
            )
            .bind(product)
            .fetch_one(store.pool())
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO builds (id, product, pkg_name, phase, backend, name, version, release, started_at, task_id) \
                 VALUES ($1, $2, 'pkg', 'succeeded', 'mock', 'pkg', '1.0', '1', 'now', $3)",
            )
            .bind(id)
            .bind(product)
            .bind(task_id)
            .execute(store.pool())
            .await
            .unwrap();
        }

        // build 1: 2 个 artifact；build 2: 1 个 artifact
        let mut tx = store.pool().begin().await.unwrap();
        store
            .insert_artifacts_tx(
                &mut tx,
                1,
                &[
                    NewArtifact {
                        relative_path: "a1.rpm".to_string(),
                        kind: ArtifactKind::Rpm,
                        size_bytes: 100,
                        sha256: "hash_a1".to_string(),
                        unsigned_sha256: None,
                        arch: Some("x86_64".to_string()),
                        name: None,
                        version: None,
                        release: None,
                        epoch: None,
                        metadata_json: None,
                        signed: false,
                    },
                    NewArtifact {
                        relative_path: "a2.log".to_string(),
                        kind: ArtifactKind::Log,
                        size_bytes: 50,
                        sha256: "hash_a2".to_string(),
                        unsigned_sha256: None,
                        arch: None,
                        name: None,
                        version: None,
                        release: None,
                        epoch: None,
                        metadata_json: None,
                        signed: false,
                    },
                ],
                "2026-01-01 00:00:00",
            )
            .await
            .unwrap();
        store
            .insert_artifacts_tx(
                &mut tx,
                2,
                &[NewArtifact {
                    relative_path: "b1.rpm".to_string(),
                    kind: ArtifactKind::Rpm,
                    size_bytes: 200,
                    sha256: "hash_b1".to_string(),
                    unsigned_sha256: None,
                    arch: Some("aarch64".to_string()),
                    name: None,
                    version: None,
                    release: None,
                    epoch: None,
                    metadata_json: None,
                    signed: false,
                }],
                "2026-01-01 00:00:00",
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let all = store.list_artifacts_for_builds(&[1, 2]).await.unwrap();
        assert_eq!(all.len(), 3);
        assert!(all.iter().all(|a| a.on_disk));

        let empty = store.list_artifacts_for_builds(&[]).await.unwrap();
        assert!(empty.is_empty());

        let only_b2 = store.list_artifacts_for_builds(&[2]).await.unwrap();
        assert_eq!(only_b2.len(), 1);
        assert_eq!(only_b2[0].build_id, 2);

        let none = store.list_artifacts_for_builds(&[999]).await.unwrap();
        assert!(none.is_empty());

        store.mark_artifacts_off_disk(1).await.unwrap();
        let after_gc = store.list_artifacts_for_builds(&[1, 2]).await.unwrap();
        assert_eq!(after_gc.len(), 1, "off_disk 的应被过滤");
        assert_eq!(after_gc[0].build_id, 2);
    }

    /// 超 MAX_BIND_PARAMS 拒绝：守卫在 SQL 构造前触发，Rust 侧 ValidationFailed 含上限值。
    #[tokio::test]
    async fn test_list_artifacts_for_builds_rejects_oversized_in_list() {
        let (store, _tmp_guard) = create_test_store().await;
        let limit = crate::state::db::MAX_BIND_PARAMS;
        let ids: Vec<i64> = (0..=limit as i64).collect();
        let msg = store
            .list_artifacts_for_builds(&ids)
            .await
            .unwrap_err()
            .to_string();
        assert!(msg.contains("exceed"), "unexpected error: {msg}");
        assert!(msg.contains(&limit.to_string()), "unexpected error: {msg}");
    }

    /// find_srpm_for_build：srpm+rpm 并存只返 srpm；行 GC（on_disk=0）或无 srpm 行均 None。
    #[tokio::test]
    async fn test_find_srpm_for_build() {
        let (store, _tmp_guard) = create_test_store().await;

        seed_build_row(&store).await;

        let mk = |relative_path: &str, kind: ArtifactKind, sha256: &str| NewArtifact {
            relative_path: relative_path.to_string(),
            kind,
            size_bytes: 1024,
            sha256: sha256.to_string(),
            unsigned_sha256: None,
            arch: None,
            name: None,
            version: None,
            release: None,
            epoch: None,
            metadata_json: None,
            signed: false,
        };
        let mut tx = store.pool().begin().await.unwrap();
        store
            .insert_artifacts_tx(
                &mut tx,
                1,
                &[
                    mk(
                        "RPMS/x86_64/hello-1.0-1.x86_64.rpm",
                        ArtifactKind::Rpm,
                        "hash_rpm",
                    ),
                    mk("SRPMS/hello-1.0-1.src.rpm", ArtifactKind::Srpm, "hash_srpm"),
                ],
                "2026-01-01 00:00:00",
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let srpm = store
            .find_srpm_for_build(1)
            .await
            .unwrap()
            .expect("srpm row must be found");
        assert_eq!(srpm.kind, ArtifactKind::Srpm);
        assert_eq!(srpm.relative_path, "SRPMS/hello-1.0-1.src.rpm");
        assert_eq!(srpm.build_id, 1);

        sqlx::query("UPDATE build_artifacts SET on_disk = 0 WHERE kind = 'srpm'")
            .execute(store.pool())
            .await
            .unwrap();
        assert!(store.find_srpm_for_build(1).await.unwrap().is_none());

        assert!(store.find_srpm_for_build(999).await.unwrap().is_none());
    }

    /// find_rpm_or_srpm_for_build：只命中 rpm/srpm、首行 relative_path 字典序、GC 或 log-only 后 None。
    #[tokio::test]
    async fn test_find_rpm_or_srpm_for_build() {
        let (store, _tmp_guard) = create_test_store().await;

        seed_build_row(&store).await;

        let mk = |relative_path: &str, kind: ArtifactKind| NewArtifact {
            relative_path: relative_path.to_string(),
            kind,
            size_bytes: 1024,
            sha256: format!("hash_{relative_path}"),
            unsigned_sha256: None,
            arch: None,
            name: None,
            version: None,
            release: None,
            epoch: None,
            metadata_json: None,
            signed: false,
        };
        let mut tx = store.pool().begin().await.unwrap();
        store
            .insert_artifacts_tx(
                &mut tx,
                1,
                &[
                    // 字典序上 RPMS/z.rpm > RPMS/a.rpm：首行必须是 a.rpm 而非插入序。
                    mk("RPMS/z.rpm", ArtifactKind::Rpm),
                    mk("RPMS/a.rpm", ArtifactKind::Rpm),
                    // log 行不参与回退源。
                    mk("build.log", ArtifactKind::Log),
                ],
                "2026-01-01 00:00:00",
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let row = store
            .find_rpm_or_srpm_for_build(1)
            .await
            .unwrap()
            .expect("rpm row must be found");
        assert_eq!(row.relative_path, "RPMS/a.rpm");
        assert_eq!(row.kind, ArtifactKind::Rpm);

        sqlx::query("UPDATE build_artifacts SET on_disk = 0 WHERE kind IN ('rpm', 'srpm')")
            .execute(store.pool())
            .await
            .unwrap();
        assert!(store.find_rpm_or_srpm_for_build(1).await.unwrap().is_none());
        assert!(store
            .find_rpm_or_srpm_for_build(999)
            .await
            .unwrap()
            .is_none());
    }

    // ===== 组合落库事务（commit_uploaded_artifacts / commit_local_build_artifacts）=====

    /// upload 落库事务测试夹具：task + pending build + assignment + building；返回 (build_id, worker_id)。
    async fn seed_upload_target(store: &StateStore, arch: &str) -> (i64, i64) {
        let task_id =
            crate::state::test_state::seed_task(store, "fedora", "hello-1.0-1.fc42").await;
        let b = crate::state::BuildInsert {
            product: "fedora",
            pkg_name: "hello-1.0-1.fc42",
            phase: "pending",
            backend: "chroot",
            user: "alice",
            task_id: Some(task_id),
            arch: Some(arch),
            ..Default::default()
        };
        let build_id = store.insert_build(b).await.unwrap();
        let worker_id = store
            .upsert_worker("upload-w", arch, 2, "0.15.0-dev", "online", None)
            .await
            .unwrap();
        store
            .assign_build_to_worker(build_id, worker_id)
            .await
            .unwrap();
        sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
            .bind(build_id)
            .execute(store.pool())
            .await
            .unwrap();
        (build_id, worker_id)
    }

    fn upload_artifact_fixture(relative_path: &str) -> NewArtifact {
        NewArtifact {
            relative_path: relative_path.to_string(),
            kind: ArtifactKind::Rpm,
            size_bytes: 1024,
            sha256: format!("hash_{relative_path}"),
            unsigned_sha256: None,
            arch: Some("x86_64".to_string()),
            name: Some("hello".to_string()),
            version: Some("1.0".to_string()),
            release: Some("1".to_string()),
            epoch: None,
            metadata_json: None,
            signed: false,
        }
    }

    #[tokio::test]
    async fn commit_uploaded_artifacts_commits_rows_and_result_dir() {
        let (store, _tmp) = create_test_store().await;
        let (build_id, worker_id) = seed_upload_target(&store, "x86_64").await;

        let out = store
            .commit_uploaded_artifacts(
                build_id,
                &[
                    upload_artifact_fixture("RPMS/x86_64/hello-1.0-1.x86_64.rpm"),
                    upload_artifact_fixture("RPMS/x86_64/hello-doc-1.0-1.noarch.rpm"),
                ],
                "/tmp/results/upload",
                "chroot",
                worker_id,
                None,
            )
            .await
            .unwrap();
        let UploadedArtifactsCommit::Committed(ids) = out else {
            panic!("active build must accept the upload: {out:?}");
        };
        assert_eq!(ids.len(), 2);
        assert_eq!(store.list_artifacts(build_id).await.unwrap().len(), 2);
        assert_eq!(
            store
                .get_build(build_id)
                .await
                .unwrap()
                .unwrap()
                .result_dir
                .as_deref(),
            Some("/tmp/results/upload")
        );
    }

    /// 空产物列表：跳过插入但守卫 UPDATE + COMMIT 照常——result_dir 落定不依赖产物行（仅 debug 文件形态）。
    #[tokio::test]
    async fn commit_uploaded_artifacts_empty_list_still_commits_result_dir() {
        let (store, _tmp) = create_test_store().await;
        let (build_id, worker_id) = seed_upload_target(&store, "x86_64").await;

        let out = store
            .commit_uploaded_artifacts(
                build_id,
                &[],
                "/tmp/results/debug-only",
                "",
                worker_id,
                None,
            )
            .await
            .unwrap();
        assert!(
            matches!(out, UploadedArtifactsCommit::Committed(ref ids) if ids.is_empty()),
            "empty upload must commit result_dir: {out:?}"
        );
        assert_eq!(store.list_artifacts(build_id).await.unwrap().len(), 0);
        assert_eq!(
            store
                .get_build(build_id)
                .await
                .unwrap()
                .unwrap()
                .result_dir
                .as_deref(),
            Some("/tmp/results/debug-only")
        );
    }

    /// CAS 0 行回滚 + 产物全量或全无：产物行随 ROLLBACK 消失，result_dir 不泄漏拒写值。
    #[tokio::test]
    async fn commit_uploaded_artifacts_rejects_terminal_and_rolls_back_artifacts() {
        let (store, _tmp) = create_test_store().await;
        let (build_id, worker_id) = seed_upload_target(&store, "x86_64").await;
        sqlx::query("UPDATE builds SET phase = 'cancelled' WHERE id = $1")
            .bind(build_id)
            .execute(store.pool())
            .await
            .unwrap();

        let out = store
            .commit_uploaded_artifacts(
                build_id,
                &[
                    upload_artifact_fixture("RPMS/x86_64/hello-1.0-1.x86_64.rpm"),
                    upload_artifact_fixture("RPMS/x86_64/hello-doc-1.0-1.noarch.rpm"),
                ],
                "/tmp/results/late",
                "chroot",
                worker_id,
                None,
            )
            .await
            .unwrap();
        assert!(
            matches!(out, UploadedArtifactsCommit::GuardRejected),
            "terminal build must reject at commit: {out:?}"
        );
        assert_eq!(
            store.list_artifacts(build_id).await.unwrap().len(),
            0,
            "inserted rows must roll back with the rejected tx (all-or-nothing)"
        );
        assert_eq!(
            store.get_build(build_id).await.unwrap().unwrap().result_dir,
            None,
            "rejected write must not leak result_dir"
        );
    }

    /// 归属 CAS：reclaim 删行重派后，被剥夺 worker 的在途上传提交点被拒（phase 活跃时归属谓词是唯一防线）。
    #[tokio::test]
    async fn commit_uploaded_artifacts_rejects_revoked_assignment() {
        let (store, _tmp) = create_test_store().await;
        let (build_id, old_worker) = seed_upload_target(&store, "x86_64").await;

        // reclaim 全语义：删分配行 + 回 pending，重派新 worker 后再开跑。
        sqlx::query("DELETE FROM worker_tasks WHERE build_id = $1 AND worker_id = $2")
            .bind(build_id)
            .bind(old_worker)
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE builds SET phase = 'pending' WHERE id = $1")
            .bind(build_id)
            .execute(store.pool())
            .await
            .unwrap();
        let new_worker = store
            .upsert_worker("upload-w2", "x86_64", 2, "0.15.0-dev", "online", None)
            .await
            .unwrap();
        store
            .assign_build_to_worker(build_id, new_worker)
            .await
            .unwrap();
        sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
            .bind(build_id)
            .execute(store.pool())
            .await
            .unwrap();

        let out = store
            .commit_uploaded_artifacts(
                build_id,
                &[upload_artifact_fixture(
                    "RPMS/x86_64/hello-1.0-1.x86_64.rpm",
                )],
                "/tmp/results/revoked",
                "chroot",
                old_worker,
                None,
            )
            .await
            .unwrap();
        assert!(
            matches!(out, UploadedArtifactsCommit::GuardRejected),
            "revoked worker must be rejected at commit: {out:?}"
        );
        assert_eq!(store.list_artifacts(build_id).await.unwrap().len(), 0);
        assert_eq!(
            store.get_build(build_id).await.unwrap().unwrap().result_dir,
            None
        );
    }

    /// hub-local 落库事务：产物行提交成功；空列表不开事务（终态行照常可插——reconcile 目标形态）。
    #[tokio::test]
    async fn commit_local_build_artifacts_commits_and_empty_is_noop() {
        let (store, _tmp) = create_test_store().await;
        let task_id =
            crate::state::test_state::seed_task(&store, "fedora", "hello-1.0-1.fc42").await;
        let build_id = store
            .insert_build(crate::state::BuildInsert {
                product: "fedora",
                pkg_name: "hello-1.0-1.fc42",
                phase: "succeeded",
                backend: "chroot",
                user: "alice",
                task_id: Some(task_id),
                arch: Some("x86_64"),
                ..Default::default()
            })
            .await
            .unwrap();

        let ids = store
            .commit_local_build_artifacts(
                build_id,
                &[upload_artifact_fixture(
                    "RPMS/x86_64/hello-1.0-1.x86_64.rpm",
                )],
            )
            .await
            .unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(store.list_artifacts(build_id).await.unwrap().len(), 1);

        let empty = store
            .commit_local_build_artifacts(build_id, &[])
            .await
            .unwrap();
        assert!(empty.is_empty());
        assert_eq!(store.list_artifacts(build_id).await.unwrap().len(), 1);
    }

    /// 双轴四象限：repo_publish × repo_consume 各 0/1 组合下，repo 候选集只按
    /// 发布轴过滤（repo_publish=1 入选），消费轴列对候选集无影响——两轴正交
    /// 的 state 层证据（消费轴过滤在 dispatch 读 repo_consume，不经本 SQL）。
    #[tokio::test]
    async fn list_publishable_rpms_filters_publish_axis_only() {
        let (store, _tmp) = create_test_store().await;

        for (id, (publish, consume)) in [(1, (1i64, 1i64)), (2, (1, 0)), (3, (0, 1)), (4, (0, 0))] {
            let task_id =
                crate::state::test_state::seed_task(&store, "quad", &format!("pkg-{id}")).await;
            store
                .insert_build(crate::state::BuildInsert {
                    product: "quad",
                    pkg_name: &format!("pkg-{id}"),
                    phase: "succeeded",
                    backend: "chroot",
                    user: "alice",
                    arch: Some("x86_64"),
                    repo_publish: publish == 1,
                    repo_consume: consume == 1,
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
                .unwrap();
            let mut tx = store.pool().begin().await.unwrap();
            store
                .insert_artifacts_tx(
                    &mut tx,
                    id,
                    &[NewArtifact {
                        relative_path: format!("RPMS/x86_64/pkg-{id}-1.0-1.x86_64.rpm"),
                        kind: ArtifactKind::Rpm,
                        size_bytes: 1,
                        sha256: format!("sha-{id}"),
                        unsigned_sha256: None,
                        arch: Some("x86_64".into()),
                        name: Some(format!("pkg-{id}")),
                        version: Some("1.0".into()),
                        release: Some("1".into()),
                        epoch: None,
                        metadata_json: None,
                        signed: false,
                    }],
                    "2026-01-01 00:00:00",
                )
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }

        let candidates = store.list_publishable_rpms("quad", false).await.unwrap();
        let mut build_ids: Vec<i64> = candidates.iter().map(|c| c.build_id).collect();
        build_ids.sort();
        assert_eq!(
            build_ids,
            vec![1, 2],
            "only repo_publish=1 rows are candidates; consume axis must not filter here"
        );
    }

    /// 签名门控：require_signed=true 只取 builds.signed=1；过滤在去重前，
    /// 未签名的同 N-V-R 新构建不得顶掉已签名旧构建。
    #[tokio::test]
    async fn list_publishable_rpms_signed_filter_keeps_older_signed_row() {
        let (store, _tmp) = create_test_store().await;
        let rel = "RPMS/x86_64/dup-1.0-1.x86_64.rpm";

        for id in [1i64, 2] {
            let task_id = crate::state::test_state::seed_task(&store, "sig", "dup").await;
            store
                .insert_build(crate::state::BuildInsert {
                    product: "sig",
                    pkg_name: "dup",
                    phase: "succeeded",
                    backend: "chroot",
                    user: "alice",
                    arch: Some("x86_64"),
                    repo_publish: true,
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
                .unwrap();
            let mut tx = store.pool().begin().await.unwrap();
            store
                .insert_artifacts_tx(
                    &mut tx,
                    id,
                    &[NewArtifact {
                        relative_path: rel.to_string(),
                        kind: ArtifactKind::Rpm,
                        size_bytes: 1,
                        sha256: format!("sha-{id}"),
                        unsigned_sha256: None,
                        arch: Some("x86_64".into()),
                        name: Some("dup".into()),
                        version: Some("1.0".into()),
                        release: Some("1".into()),
                        epoch: None,
                        metadata_json: None,
                        signed: id == 1,
                    }],
                    "2026-01-01 00:00:00",
                )
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
        store.update_build_signed(1, true).await.unwrap();

        let unfiltered = store.list_publishable_rpms("sig", false).await.unwrap();
        assert_eq!(
            unfiltered.iter().map(|c| c.build_id).collect::<Vec<_>>(),
            vec![2],
            "newest unsigned row wins without the policy filter"
        );

        let signed_only = store.list_publishable_rpms("sig", true).await.unwrap();
        assert_eq!(
            signed_only.iter().map(|c| c.build_id).collect::<Vec<_>>(),
            vec![1],
            "signed-only filter must drop the unsigned newest row and keep the signed older one"
        );
    }
}
