// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产品仓库：`products` / `product_config_history` 表的 CRUD。
//! 契约：`revision` 每 update 单调 +1（drives history + chain-resolve 缓存失效）；
//! `base_os_revision` 仅触发字段变化时抬到 `= revision`；`update_product_config`
//! 事务 `BEGIN IMMEDIATE` + 可选 `expected_revision`，冲突返回 `RevisionConflict
//! { expected, current }`（server 映射 409）；可见性检查在 server 层（`AuthContext` 在 crbs-server）。
use crate::config::ProductConfig;
use crate::error::CrbsError;
use crate::error::DbResultExt;
use crate::state::StateStore;
use tracing::warn;

mod sql {
    use crate::state::Dialect;

    pub(super) const INSERT_PRODUCT: &str = "\
        INSERT INTO products \
        (name, display_name, owner_id, parent_id, visibility, config_json, \
         revision, base_os_revision) \
         VALUES ($1, $2, $3, $4, $5, $6, 1, 1) \
         RETURNING id";

    pub(super) const INSERT_HISTORY: &str = "\
        INSERT INTO product_config_history \
        (product_id, revision, config_json, parent_id, base_os_revision, \
         changed_by_user_id, reason) \
        VALUES ($1, $2, $3, $4, $5, $6, $7)";

    pub(super) const SELECT_PRODUCT_BY_ID: &str = "\
        SELECT id, name, display_name, owner_id, parent_id, visibility, \
               config_json, revision, base_os_revision, created_at, updated_at \
        FROM products WHERE id = $1";

    pub(super) const SELECT_PRODUCT_BY_NAME: &str = "\
        SELECT id, name, display_name, owner_id, parent_id, visibility, \
               config_json, revision, base_os_revision, created_at, updated_at \
        FROM products WHERE name = $1 \
        ORDER BY (owner_id IS NOT NULL) LIMIT 1";

    /// 官方产品按 slug 查（owner_id IS NULL 唯一）。
    pub(super) const SELECT_OFFICIAL_PRODUCT_BY_NAME: &str = "\
        SELECT id, name, display_name, owner_id, parent_id, visibility, \
               config_json, revision, base_os_revision, created_at, updated_at \
        FROM products WHERE name = $1 AND owner_id IS NULL";

    pub(super) const LIST_PRODUCTS: &str = "\
        SELECT id, name, display_name, owner_id, parent_id, visibility, \
        revision, base_os_revision \
        FROM products ORDER BY name";

    pub(super) const LIST_PRODUCTS_BY_OWNER: &str = "\
        SELECT id, name, display_name, owner_id, parent_id, visibility, \
        revision, base_os_revision \
        FROM products WHERE owner_id = $1 ORDER BY name";

    /// 全量产品行（含 config_json），`load_product_summaries` 一次性载入做内存父链合并。
    pub(super) const LIST_PRODUCTS_FULL: &str = "\
        SELECT id, name, display_name, owner_id, parent_id, visibility, \
               config_json, revision, base_os_revision, created_at, updated_at \
        FROM products ORDER BY name";

    /// 事务内取 revision & config_json 快照。SELECT 不带 FOR UPDATE（sqlx Any 拿不到
    /// 行锁）——行级守卫靠 UPDATE `AND revision = $N` 谓词（PG）/ BEGIN IMMEDIATE（SQLite）。
    pub(super) const SELECT_PRODUCT_REV_SNAPSHOT: &str = "\
        SELECT revision, base_os_revision, parent_id, config_json \
        FROM products WHERE id = $1";

    /// 乐观守卫落空（UPDATE 谓词 0 行）后回读 revision，填 `RevisionConflict::current`。
    pub(super) const SELECT_PRODUCT_REVISION: &str = "SELECT revision FROM products WHERE id = $1";

    /// 更新产品配置（时间方言感知）。`AND revision = $5` 乐观守卫：PG BEGIN 不锁行，
    /// old_rev 可被并发提交抬走，落空 0 行 → `RevisionConflict`（server 映射 409）；
    /// SQLite 由 BEGIN IMMEDIATE 串行化，谓词结构性不会落空。
    pub(super) fn update_product_config(dialect: Dialect) -> String {
        format!(
            "UPDATE products \
             SET config_json = $1, revision = $2, base_os_revision = $3, \
                 updated_at = {} \
             WHERE id = $4 AND revision = $5",
            dialect.sql_now()
        )
    }

    /// re-parent 专用 UPDATE：改 `parent_id` + bump `revision`；parent 实际变化时抬
    /// `base_os_revision`（换根 = 合并结果变化）、不动 `config_json`（新 history row
    /// 复用旧 config_json）。乐观守卫同 [`update_product_config`]。`$4` 出现在 `$3`
    /// 之后——$N 名值绑定出现序无关，改 `?` 顺序占位符须按绑定序重排。
    pub(super) fn update_product_parent(dialect: Dialect) -> String {
        format!(
            "UPDATE products \
             SET parent_id = $1, revision = $2, base_os_revision = $4, updated_at = {} \
             WHERE id = $3 AND revision = $5",
            dialect.sql_now()
        )
    }

    pub(super) const SELECT_PARENT_ID_ONLY: &str = "\
        SELECT parent_id FROM products WHERE id = $1";

    pub(super) const SELECT_VISIBILITY_AND_PARENT: &str = "\
        SELECT visibility, name, parent_id FROM products WHERE id = $1";

    pub(super) const DELETE_PRODUCT: &str = "DELETE FROM products WHERE id = $1";

    /// 画像孤儿清理：profiles 键是产品名字符串，产品行删除前
    /// 按名清行——learned 学习资产不与死产品名一起留成孤儿。
    pub(super) const DELETE_PROFILES_BY_PRODUCT: &str =
        "DELETE FROM package_resource_profiles WHERE product = $1";

    pub(super) const COUNT_CHILD_PRODUCTS: &str =
        "SELECT COUNT(*) FROM products WHERE parent_id = $1";

    pub(super) const SELECT_CHILDREN_ID_VISIBILITY: &str =
        "SELECT id, visibility FROM products WHERE parent_id = $1";

    pub(super) const LIST_HISTORY: &str = "\
        SELECT product_id, revision, config_json, parent_id, base_os_revision, \
               changed_by_user_id, changed_at, reason \
        FROM product_config_history \
        WHERE product_id = $1 \
        ORDER BY revision DESC";

    pub(super) const SELECT_HISTORY_REV: &str = "\
        SELECT product_id, revision, config_json, parent_id, base_os_revision, \
               changed_by_user_id, changed_at, reason \
        FROM product_config_history \
        WHERE product_id = $1 AND revision = $2";
}

/// 公开产品（未认证亦可读，公开 repo 通道仅此可见性发布）
pub const VISIBILITY_PUBLIC: &str = "public";

/// 私人产品（仅 owner + ACL 授权用户可见）
pub const VISIBILITY_PRIVATE: &str = "private";

/// 触发 `base_os_revision` 抬升的配置字段：按新旧 JSON 顶层键深度值相等判定
///（缺失键视为 `Null`），不依赖 struct 字段以免演进漂移；4 个 `+` 追加键同样
/// 改变 chain 合并后的 base_os 内容，必须触发重建。`crbs_root` 不在清单
///（chain-resolve 出口剥离，见 `product_resolve::merge_and_validate_chain`）；
/// `ccache_enabled` 全形态触发（Bool / Packages / 置 None）：经 `merge_base_packages`
/// 改装机清单与 `.requested` 指纹、init 建 /usr/lib64/ccache 链接；state 层算不出
/// 有效合并值只能比原始 JSON，保守多触发无害（多重建不漏）；`ccache_max_size`
/// 不在清单（只影响构建期 `ccache -M`）；`parent_id` 是表列（非 config_json 内容），单独处理。
pub const BASE_OS_TRIGGER_FIELDS: &[&str] = &[
    "base_packages",
    "+base_packages",
    "repos",
    "+repos",
    "releasever",
    "overlay_dir",
    "post_init",
    "+post_init",
    "builder_user",
    "builder_uid",
    "builder_group",
    "builder_gid",
    "arches",
    "+arches",
    "shared_layer",
    "shared_layer_staleness",
    "backend",
    "product_root",
    "base_os_path",
    "ccache_enabled",
];

/// 完整产品记录（含解析后的 `ProductConfig`）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProductRecord {
    pub id: i64,
    pub name: String,
    pub display_name: Option<String>,
    pub owner_id: Option<i64>,
    pub parent_id: Option<i64>,
    pub visibility: String,
    pub config: ProductConfig,
    pub revision: i64,
    pub base_os_revision: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// 列表用的轻量视图（不解析 config_json）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProductStub {
    pub id: i64,
    pub name: String,
    pub display_name: Option<String>,
    pub owner_id: Option<i64>,
    /// 产品继承的 parent 产品 id。`None` = 根产品。
    pub parent_id: Option<i64>,
    pub visibility: String,
    pub revision: i64,
    pub base_os_revision: i64,
}

/// 列表页批量摘要视图（`load_product_summaries` 产出）：比 [`ProductStub`] 多
/// parent_name 与**链合并后**的产品层 `backend` / `build_target`（`None` = 链上
/// 未设置，调用方回退全局 `CrbsConfig`）；不含 base_packages/repos 等重字段。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProductSummary {
    pub id: i64,
    pub name: String,
    pub owner_id: Option<i64>,
    pub parent_id: Option<i64>,
    pub parent_name: Option<String>,
    pub visibility: String,
    pub revision: i64,
    pub base_os_revision: i64,
    pub backend: Option<String>,
    pub build_target: Option<String>,
}

/// 单条 history 记录。`config_json` 保留 raw String，调用方按需 `serde_json::from_str`。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProductConfigHistoryEntry {
    pub product_id: i64,
    pub revision: i64,
    pub config_json: String,
    pub parent_id: Option<i64>,
    pub base_os_revision: i64,
    pub changed_by_user_id: Option<i64>,
    pub changed_at: String,
    pub reason: Option<String>,
}

/// 更新结果：新 revision 与本次是否触发 base_os 抬升。
#[derive(Debug, Clone, Copy)]
pub struct UpdateOutcome {
    pub revision: i64,
    pub base_os_revision: i64,
    pub base_os_bumped: bool,
}

/// transfer 结果：更新结果 + cancel 计数。
#[derive(Debug, Clone, Copy)]
pub struct TransferOutcome {
    pub revision: i64,
    pub base_os_revision: i64,
    pub base_os_bumped: bool,
    pub builds_cancelled: u64,
    pub tasks_cancelled: u64,
}

impl From<TransferOutcome> for UpdateOutcome {
    fn from(t: TransferOutcome) -> Self {
        Self {
            revision: t.revision,
            base_os_revision: t.base_os_revision,
            base_os_bumped: t.base_os_bumped,
        }
    }
}

#[derive(sqlx::FromRow)]
struct ProductRow {
    id: i64,
    name: String,
    display_name: Option<String>,
    owner_id: Option<i64>,
    parent_id: Option<i64>,
    visibility: String,
    config_json: String,
    revision: i64,
    base_os_revision: i64,
    created_at: String,
    updated_at: String,
}

impl ProductRow {
    fn into_record(self) -> crate::Result<ProductRecord> {
        // 解析失败 = 永久性配置错误，报 ProductChainInvalid（归 Permanent）而非
        // db_ctx 包成 Database（归 Transient → release→re-dispatch 无限空转）。
        let config: ProductConfig = serde_json::from_str(&self.config_json).map_err(|e| {
            CrbsError::ProductChainInvalid {
                product: self.name.clone(),
                reason: format!("stored config_json is unparseable: {e}"),
            }
        })?;
        Ok(ProductRecord {
            id: self.id,
            name: self.name,
            display_name: self.display_name,
            owner_id: self.owner_id,
            parent_id: self.parent_id,
            visibility: self.visibility,
            config,
            revision: self.revision,
            base_os_revision: self.base_os_revision,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct ProductStubRow {
    id: i64,
    name: String,
    display_name: Option<String>,
    owner_id: Option<i64>,
    parent_id: Option<i64>,
    visibility: String,
    revision: i64,
    base_os_revision: i64,
}

impl From<ProductStubRow> for ProductStub {
    fn from(r: ProductStubRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            display_name: r.display_name,
            owner_id: r.owner_id,
            parent_id: r.parent_id,
            visibility: r.visibility,
            revision: r.revision,
            base_os_revision: r.base_os_revision,
        }
    }
}

#[derive(sqlx::FromRow)]
struct HistoryRow {
    product_id: i64,
    revision: i64,
    config_json: String,
    parent_id: Option<i64>,
    base_os_revision: i64,
    changed_by_user_id: Option<i64>,
    changed_at: String,
    reason: Option<String>,
}

impl From<HistoryRow> for ProductConfigHistoryEntry {
    fn from(r: HistoryRow) -> Self {
        Self {
            product_id: r.product_id,
            revision: r.revision,
            config_json: r.config_json,
            parent_id: r.parent_id,
            base_os_revision: r.base_os_revision,
            changed_by_user_id: r.changed_by_user_id,
            changed_at: r.changed_at,
            reason: r.reason,
        }
    }
}

fn base_os_fields_changed(old: &serde_json::Value, new: &serde_json::Value) -> bool {
    let null = serde_json::Value::Null;
    for field in BASE_OS_TRIGGER_FIELDS {
        let a = old.get(*field).unwrap_or(&null);
        let b = new.get(*field).unwrap_or(&null);
        if a != b {
            return true;
        }
    }
    false
}

/// 新建产品入参（[`StateStore::create_product`] 用）：products 行以 revision = 1、
/// base_os_revision = 1 起步，并与首条 history 同事务写入；`name` 命名空间全局唯一。
pub struct CreateProductInput<'a> {
    pub name: &'a str,
    pub display_name: Option<&'a str>,
    /// `None` 表示官方产品（`owner_id IS NULL`），`Some` 表示私人产品。
    pub owner_id: Option<i64>,
    /// 父产品 id；`None` = 根产品（链上节点由 create 校验并落库）。
    pub parent_id: Option<i64>,
    /// `"public"` 或 `"private"`。官方产品必须传 `VISIBILITY_PUBLIC`（否则 CHECK 拒绝）。
    pub visibility: &'a str,
    pub config: &'a ProductConfig,
    pub changed_by_user_id: Option<i64>,
    pub reason: Option<&'a str>,
}

/// 唯一键违反的文本判定：sqlx Any 不透出原生错误码（SQLSTATE 23505 /
/// SQLITE_CONSTRAINT），只能按 Display 文本匹配双方言——SQLite
/// "UNIQUE constraint failed: products.name" / PG `duplicate key ... "products_name_key"`；
/// 裸文本包 `Database` 委托 [`crate::error::is_unique_violation`] 判定。
pub(super) fn is_unique_violation_msg(msg: &str) -> bool {
    crate::error::is_unique_violation(&CrbsError::Database(msg.to_string()))
}

fn classify_insert_product_error(name: &str, e: sqlx::Error) -> CrbsError {
    // 唯一键冲突按 Display 文本归 AlreadyExists(409)；否则 PG 同名冲突错标 Database(500)。
    if is_unique_violation_msg(&e.to_string()) {
        CrbsError::AlreadyExists {
            message: format!("product name '{}' already exists", name),
        }
    } else {
        // 豁免 .db_ctx：需按文本归一唯一键冲突为 AlreadyExists、其余落 Database，db_ctx 无法表达。
        CrbsError::Database(format!("insert product: {}", e))
    }
}

pub(super) async fn insert_product_and_history_tx(
    conn: &mut sqlx::AnyConnection,
    input: &CreateProductInput<'_>,
    config_json: &str,
) -> crate::Result<i64> {
    let id = sqlx::query_scalar::<_, i64>(sql::INSERT_PRODUCT)
        .bind(input.name)
        .bind(input.display_name)
        .bind(input.owner_id)
        .bind(input.parent_id)
        .bind(input.visibility)
        .bind(config_json)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| classify_insert_product_error(input.name, e))?;

    sqlx::query(sql::INSERT_HISTORY)
        .bind(id)
        .bind(1_i64)
        .bind(config_json)
        .bind(input.parent_id)
        .bind(1_i64)
        .bind(input.changed_by_user_id)
        .bind(input.reason)
        .execute(conn)
        .await
        .db_ctx("insert product history")?;
    Ok(id)
}

impl StateStore {
    async fn count_external_children(
        &self,
        id: i64,
        current_owner_id: Option<i64>,
        conn: &mut sqlx::AnyConnection,
    ) -> crate::Result<i64> {
        let external_count: i64 = match current_owner_id {
            Some(owner_id) => {
                // 私人产品：owner 不同的 child 是外部的
                // SQLite: IS NOT / PG: IS DISTINCT FROM（NULL 感知比较）
                let compare_sql = self.dialect.sql_is_distinct_from("owner_id", "$2");
                sqlx::query_scalar(&format!(
                    "SELECT COUNT(*) FROM products WHERE parent_id = $1 AND {}",
                    compare_sql
                ))
                .bind(id)
                .bind(owner_id)
                .fetch_one(conn)
                .await
            }
            None => {
                // 官方产品：任何有 owner 的 child 都是外部的
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM products WHERE parent_id = $1 AND owner_id IS NOT NULL",
                )
                .bind(id)
                .fetch_one(conn)
                .await
            }
        }
        .db_ctx("count external children")?;
        Ok(external_count)
    }

    async fn cancel_builds_and_tasks_tx(
        &self,
        id: i64,
        conn: &mut sqlx::AnyConnection,
    ) -> crate::Result<(u64, u64)> {
        // UPDATE ... RETURNING 按实际翻转行收集 layer_digest：先 SELECT 快照再 UPDATE
        // 在语句间隙遇并发翻转会双扣引用或 dec 落空回滚（RETURNING 双方言支持，SQLite
        // ≥3.35）。IN 含 'assigned'：否则 assigned 构建会被 worker 正常拉取继续执行；
        // duration 同步落值（started_at 起算）。按 **name**（EXISTS products）而非
        // `product_id` 过滤：product_id 自动解析 official-only（owner_id IS NULL），私人
        // 产品行恒 NULL，会漏掉全部私人产品构建/任务——级联取消 0 行、产物写进已删
        // 产品目录。调用时产品行尚在本事务内 EXISTS 可命中；产品名全局唯一，name 匹配即该产品全部行。
        let cancelled: Vec<Option<String>> = sqlx::query_scalar(&format!(
            "UPDATE builds SET phase = 'cancelled', completed_at = {}, duration = {} \
             WHERE EXISTS ( \
                 SELECT 1 FROM products p WHERE p.id = $1 AND p.name = builds.product \
             ) AND phase IN ('pending', 'assigned', 'building') \
             RETURNING layer_digest",
            self.dialect.sql_now(),
            self.dialect.sql_seconds_since("started_at")
        ))
        .bind(id)
        .fetch_all(&mut *conn)
        .await
        .db_ctx("cancel builds for product")?;
        let builds_cancelled = cancelled.len() as u64;

        // 释放被取消构建持有的共享层引用（归零即安装 GC schedule；pending 行未 attach
        // layer、digest 为 NULL 无引用可释放），宽限恒用编译期默认 168h（非配置值）。
        // dec Ok(0)（层行已被并发 GC 删/泄漏修复归零）warn 跳过不回滚——取消是主语义，
        // 残留计数由泄漏修复路径收敛。
        let grace_hours = crate::config::defaults::default_shared_layer_gc_grace_hours() as i64;
        for digest in cancelled.into_iter().flatten() {
            match self.layer_ref_dec_in_tx(conn, &digest, grace_hours).await {
                Ok(0) => {
                    warn!(digest = %digest, "layer row missing or ref already 0 on cancel; nothing to release")
                }
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }

        // 非一刀切 'cancelled'：收集活跃任务后逐 task 按子构建聚合推导终态（failed >
        // cancelled > timeout > succeeded；子构建已在上方同事务取消，已有 failed/timeout
        // 时应收口 failed），completed_at / duration 按 submitted_at 起算。守卫不含
        // 'assigned' 有意为之——task 相位永不产 'assigned'（聚合写路径只产 pending/building/终态），
        // 新增相位写入点须同步此处与 LIST_STUCK_TASKS；task 侧与 builds 侧同切 name 口径，取消域两侧一致。
        let task_ids: Vec<i64> = sqlx::query_scalar(
            "SELECT id FROM tasks \
             WHERE EXISTS ( \
                 SELECT 1 FROM products p WHERE p.id = $1 AND p.name = tasks.product \
             ) AND phase IN ('pending', 'building')",
        )
        .bind(id)
        .fetch_all(&mut *conn)
        .await
        .db_ctx("list active tasks for product")?;
        let mut tasks_cancelled: u64 = 0;
        for task_id in task_ids {
            tasks_cancelled +=
                super::tasks::finalize_cancelled_task_on(conn, self.dialect, task_id).await?;
        }

        Ok((builds_cancelled, tasks_cancelled))
    }

    /// 提交后失效 resolve 缓存（crud / hierarchy / ownership / delete 写路径共用）：
    /// 失败不得把已提交变更报成失败（调用方映射 5xx），陈旧条目由下次成功写入兜底——warn 并继续。
    pub(super) async fn invalidate_resolve_warned(&self, id: i64) {
        if let Err(e) = self.invalidate_resolve_recursive(id).await {
            warn!(product_id = id, error = %e, "invalidate resolve cache failed; stale entry persists until next write");
        }
    }
}

pub(crate) mod crud;
pub(crate) mod delete;
pub(crate) mod hierarchy;
pub(crate) mod history;
pub(crate) mod ownership;
#[cfg(test)]
pub(crate) mod tests;
