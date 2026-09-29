// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! DB-backed 用户、Token、产品 ACL 存储方法。

use super::rollback_and_return;
use super::StateStore;
use crate::error::{CrbsError, DbResultExt};

mod sql {
    use crate::state::Dialect;

    pub(super) const INSERT_USER: &str =
        "INSERT INTO users (name, role, status) VALUES ($1, $2, 'active') \
         RETURNING id";

    /// 自服务注册：用户 + 密码单条 INSERT 原子落库（两步写会留无密码
    /// 半成品行）。must_change 用 i64 绑定（口径见 UPDATE_USER_PASSWORD）。
    pub(super) const INSERT_USER_WITH_PASSWORD: &str =
        "INSERT INTO users (name, role, status, password_hash, must_change_password) \
         VALUES ($1, $2, 'active', $3, $4) RETURNING id";

    pub(super) const SELECT_USER_BY_ID: &str =
        "SELECT id, name, role, status, created_at FROM users WHERE id = $1";

    pub(super) const SELECT_USER_BY_NAME: &str =
        "SELECT id, name, role, status, created_at FROM users WHERE name = $1";

    pub(super) const LIST_USERS: &str =
        "SELECT id, name, role, status, created_at FROM users ORDER BY id";

    /// 过滤列表前缀：WHERE 1=1 后由调用方追加过滤条件、ORDER BY、LIMIT/OFFSET。
    pub(super) const LIST_USERS_FILTERED_PREFIX: &str =
        "SELECT id, name, role, status, created_at FROM users WHERE 1=1";

    /// 过滤计数查询前缀（同上，仅追加过滤条件）。
    pub(super) const COUNT_USERS_FILTERED_PREFIX: &str = "SELECT COUNT(*) FROM users WHERE 1=1";

    pub(super) const UPDATE_USER_ROLE: &str = "UPDATE users SET role = $1 WHERE id = $2";

    pub(super) const UPDATE_USER_STATUS: &str = "UPDATE users SET status = $1 WHERE id = $2";

    /// 最后活跃管理员守卫：目标外活跃 admin 计数（==0 时降级/禁用锁死零管理员态）。
    pub(super) const COUNT_OTHER_ACTIVE_ADMINS: &str =
        "SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active' AND id <> $1";

    /// 密码列写入（admin 重置与自改共用）；must_change 用 i64 绑定：
    /// SQLite / PG 在 Any 驱动下统一按整数解码，bool 不可移植。
    pub(super) const UPDATE_USER_PASSWORD: &str =
        "UPDATE users SET password_hash = $1, must_change_password = $2 WHERE id = $3";

    /// 独立行映射：只取认证三列，绝不加进 Serialize 的 [`User`]。
    pub(super) const SELECT_USER_AUTH_ROW: &str =
        "SELECT id, password_hash, must_change_password FROM users WHERE id = $1";

    pub(super) const INSERT_USER_TOKEN: &str =
        "INSERT INTO user_tokens (user_id, name, hash, expires_at) VALUES ($1, $2, $3, $4) \
         RETURNING id";

    pub(super) const SELECT_USER_TOKEN_BY_HASH: &str =
        "SELECT id, user_id, name, hash, expires_at, created_at, revoked_at \
         FROM user_tokens WHERE hash = $1";

    pub(super) const LIST_USER_TOKENS_BY_USER: &str =
        "SELECT id, user_id, name, hash, expires_at, created_at, revoked_at \
         FROM user_tokens WHERE user_id = $1 ORDER BY id";

    /// /ui/me 令牌卡：只列活跃（未撤销）token，新→旧，LIMIT $2 封顶由调用方传。
    pub(super) const LIST_ACTIVE_USER_TOKENS_BY_USER: &str =
        "SELECT id, user_id, name, hash, expires_at, created_at, revoked_at \
         FROM user_tokens WHERE user_id = $1 AND revoked_at IS NULL \
         ORDER BY id DESC LIMIT $2";

    /// 活跃（未撤销）token 计数（总览带：不受展示封顶截断）。
    pub(super) const COUNT_ACTIVE_USER_TOKENS: &str =
        "SELECT COUNT(*) FROM user_tokens WHERE user_id = $1 AND revoked_at IS NULL";

    /// 撤销用户 token（方言感知时间戳）。
    pub(super) fn revoke_user_token(dialect: Dialect) -> String {
        format!(
            "UPDATE user_tokens SET revoked_at = {} WHERE id = $1",
            dialect.sql_now()
        )
    }

    /// 周期清理：过期（expires_at <= $1，RFC 3339 字典序比较）或已撤销的
    /// 行。revoked 必须纳入：永久 token（expires_at NULL）撤销后不触发
    /// 过期谓词，不删会占死 UNIQUE(user_id, name)，同名 token 无法再建。
    pub(super) const DELETE_EXPIRED_USER_TOKENS: &str =
        "DELETE FROM user_tokens WHERE (expires_at IS NOT NULL AND expires_at <= $1) \
         OR revoked_at IS NOT NULL";

    /// 撤销产品 ACL 时取消用户构建（方言感知时间戳）。completed_at /
    /// duration 必须落值：result-GC / retention 以 completed_at IS NOT
    /// NULL 为门，缺失则 result_dir 永不回收。按 **name** 口径过滤
    ///（EXISTS products）而非 `product_id = $1`：私人产品构建行
    /// product_id 恒 NULL，product_id 口径漏掉全部私人产品构建（级联
    /// 取消 0 行、产物写进 owner 将删目录）。RETURNING layer_digest 按
    /// 实际翻转的行释放共享层引用（先 SELECT 快照会双扣/漏扣）。IN
    /// 含 'assigned'：漏了会被 worker 正常拉取继续执行。
    pub(super) fn cancel_builds_on_acl_revoke(dialect: Dialect) -> String {
        format!(
            "UPDATE builds SET phase = 'cancelled', completed_at = {}, duration = {} \
             WHERE user_id = $2 \
               AND EXISTS ( \
                   SELECT 1 FROM products p WHERE p.id = $1 AND p.name = builds.product \
               ) \
               AND phase IN ('pending', 'assigned', 'building') RETURNING layer_digest",
            dialect.sql_now(),
            dialect.sql_seconds_since("started_at")
        )
    }

    /// 撤销产品 ACL 时收集待收口的活跃任务。逐 task 按子构建聚合推导终态
    ///（failed > cancelled > timeout > succeeded，对齐 finalize_cancelled_task），
    /// duration/completed_at 由收口写入落值（submitted_at 起算）。守卫不含
    /// 'assigned'：task 相位永不产 'assigned'；新增 task 相位写入点须同步
    /// 此处与 LIST_STUCK_TASKS。name 口径同上方 builds 侧。
    pub(super) const LIST_ACTIVE_TASKS_ON_ACL_REVOKE: &str = "SELECT id FROM tasks \
         WHERE user_id = $2 \
           AND EXISTS ( \
               SELECT 1 FROM products p WHERE p.id = $1 AND p.name = tasks.product \
           ) \
           AND phase IN ('pending', 'building')";

    // product_acl (product_id, user_id) PK + role 列
    pub(super) const INSERT_PRODUCT_ACL: &str =
        "INSERT INTO product_acl (product_id, user_id, role) VALUES ($1, $2, $3) \
         ON CONFLICT(product_id, user_id) DO UPDATE SET role = excluded.role";

    pub(super) const DELETE_PRODUCT_ACL: &str =
        "DELETE FROM product_acl WHERE user_id = $1 AND product_id = $2";

    pub(super) const COUNT_PRODUCT_ACL: &str =
        "SELECT COUNT(*) FROM product_acl WHERE user_id = $1 AND product_id = $2";

    pub(super) const LIST_PRODUCTS_BY_USER: &str =
        "SELECT p.name FROM product_acl a JOIN products p ON a.product_id = p.id \
         WHERE a.user_id = $1 ORDER BY p.name";

    /// role/created_at 均取 product_acl 的授权语义：a.role 是产品角色（非
    /// users 全局角色），a.created_at 是授权时间（非账号创建时间）。
    pub(super) const LIST_USERS_BY_PRODUCT: &str =
        "SELECT u.id, u.name, a.role, u.status, a.created_at \
         FROM users u JOIN product_acl a ON u.id = a.user_id \
         WHERE a.product_id = $1 ORDER BY u.id";

    pub(super) const LIST_PRODUCT_ACLS_BY_USER: &str =
        "SELECT a.user_id, p.name AS product, a.role, a.created_at \
         FROM product_acl a JOIN products p ON a.product_id = p.id \
         WHERE a.user_id = $1 ORDER BY p.name";
}

/// 用户记录。
#[derive(Debug, Clone, serde::Serialize)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub role: String,
    pub status: String,
    pub created_at: String,
}

/// 用户列表查询过滤条件。
#[derive(Debug, Default)]
pub struct UserFilter<'a> {
    /// 用户名子串（LIKE 模糊匹配）。
    pub name: Option<&'a str>,
    /// 全局角色（精确匹配）。
    pub role: Option<&'a str>,
    /// 账号状态（精确匹配）。
    pub status: Option<&'a str>,
    pub limit: i64,
    pub offset: i64,
}

impl UserFilter<'_> {
    /// limit 归一化：<=0 取 100，上限 1000。
    pub fn normalized_limit(&self) -> i64 {
        super::db::clamp_list_limit(self.limit)
    }
}

/// 用户 token 记录（明文 token 仅生成时存在，DB 只存 SHA-256 hash）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct UserToken {
    pub id: i64,
    pub user_id: i64,
    pub name: Option<String>,
    pub hash: String,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

/// 用户认证行（密码列专用独立映射）。
/// 刻意不派生 `Serialize`：`password_hash` 绝不出现在
/// 任何 API/UI 输出，仅登录校验与 must_change 判定读取。
#[derive(Debug, Clone)]
pub struct UserAuthRow {
    pub id: i64,
    /// argon2id PHC 串；`None` = 未设密码（token-only 用户）。
    pub password_hash: Option<String>,
    /// admin 重置后置位；用户下次改密时清零。
    pub must_change_password: bool,
}

/// 产品 ACL 记录（无 id 列，复合主键 + role）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProductAcl {
    pub user_id: i64,
    pub product: String,
    pub role: String,
    pub created_at: String,
}

/// 过滤条件追加为 WHERE 片段与绑定参数（`list_users_filtered` /
/// `count_users_filtered` 共用，两者条件与 bind 顺序必须完全一致）。
/// 手动维护 `$N` 编号：QueryBuilder<sqlx::Any> 生成 `?` 占位符，PG 上
/// 直接语法错。
fn push_user_filter(parts: &mut Vec<String>, binds: &mut Vec<String>, filter: &UserFilter<'_>) {
    if let Some(v) = filter.name {
        // name 先经 escape_like（\ % _）配 ESCAPE '\' 子句：通配符按字面
        // 匹配。不走 push_eq_and：ESCAPE 子句须跟在占位符之后。
        let idx = binds.len() + 1;
        parts.push(format!(" AND name LIKE ${} ESCAPE '\\'", idx));
        binds.push(format!("%{}%", crate::state::db::escape_like(v)));
    }
    if let Some(v) = filter.role {
        crate::state::db::push_eq_and(parts, binds, "role", "=", v.to_string());
    }
    if let Some(v) = filter.status {
        crate::state::db::push_eq_and(parts, binds, "status", "=", v.to_string());
    }
}

/// "最后活跃管理员"守卫（set_user_role / set_user_status 的事务内第一步）。
/// 拒绝（`CrbsError::Conflict`，HTTP 409，调用方 ROLLBACK）：目标是活跃
/// admin、本次写把它移出活跃 admin 集合、且其余活跃 admin 计数为 0。
/// 恒放行：行不存在（no-op 契约）、非活跃 admin 目标（disabled admin 仍
/// 可降级）、升级/保持方向写。恢复路径：CLI `crbs-server user add --role
/// admin` 直连 store 不经此守卫。已知残余竞态（不修）：PG READ
/// COMMITTED 下两个活跃 admin 并发自降可同时通过、留下零管理员；窗口
/// 极窄，SQLite 免疫（写事务串行化），实际触发再考虑 CAS/加锁。
async fn ensure_not_last_active_admin(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
    user_id: i64,
    removes_from_active_admins: bool,
) -> crate::Result<()> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT role, status FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&mut **conn)
            .await
            .db_ctx("get user role/status for last admin guard")?;
    let Some((role, status)) = row else {
        return Ok(());
    };
    if role != "admin" || status != "active" || !removes_from_active_admins {
        return Ok(());
    }
    let others: i64 = sqlx::query_scalar(sql::COUNT_OTHER_ACTIVE_ADMINS)
        .bind(user_id)
        .fetch_one(&mut **conn)
        .await
        .db_ctx("count other active admins")?;
    if others == 0 {
        return Err(CrbsError::Conflict {
            message: "cannot demote or disable the last active admin; promote another admin first"
                .to_string(),
        });
    }
    Ok(())
}

impl StateStore {
    /// 创建用户，返回用户 ID。用户名经 `validate_user_name` 收口校验
    ///（slug 字符集 + ≤128）：所有创建路径汇聚于此、绕不过。
    pub async fn create_user(&self, name: &str, role: &str) -> crate::Result<i64> {
        crate::validation::validate_user_name(name)?;
        let id = sqlx::query_scalar::<_, i64>(sql::INSERT_USER)
            .bind(name)
            .bind(role)
            .fetch_one(&self.pool)
            .await
            .db_ctx("create user")?;
        self.bump_user_generation();
        Ok(id)
    }

    /// 创建带密码的用户（自服务注册路径），返回用户 ID。调用方先
    /// `hash_password`（纯计算，消除 INSERT 失败窗口）再调本方法；
    /// 用户名收口校验同 [`Self::create_user`]。
    pub async fn create_user_with_password(
        &self,
        name: &str,
        role: &str,
        password_hash: &str,
        must_change: bool,
    ) -> crate::Result<i64> {
        crate::validation::validate_user_name(name)?;
        let id = sqlx::query_scalar::<_, i64>(sql::INSERT_USER_WITH_PASSWORD)
            .bind(name)
            .bind(role)
            .bind(password_hash)
            .bind(must_change as i64)
            .fetch_one(&self.pool)
            .await
            .db_ctx("create user with password")?;
        self.bump_user_generation();
        Ok(id)
    }

    /// 按 ID 获取用户。
    pub async fn get_user(&self, id: i64) -> crate::Result<Option<User>> {
        sqlx::query_as::<_, UserRow>(sql::SELECT_USER_BY_ID)
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .db_ctx("get user")
            .map(|row| row.map(|r| r.into()))
    }

    /// 按名称查找用户。
    pub async fn find_user_by_name(&self, name: &str) -> crate::Result<Option<User>> {
        sqlx::query_as::<_, UserRow>(sql::SELECT_USER_BY_NAME)
            .bind(name)
            .fetch_optional(self.pool())
            .await
            .db_ctx("find user by name")
            .map(|row| row.map(|r| r.into()))
    }

    /// 列出所有用户。
    pub async fn list_users(&self) -> crate::Result<Vec<User>> {
        sqlx::query_as::<_, UserRow>(sql::LIST_USERS)
            .fetch_all(self.pool())
            .await
            .db_ctx("list users")
            .map(|rows| rows.into_iter().map(|r| r.into()).collect())
    }

    /// 按过滤条件分页查询用户（name LIKE 子串搜索，role/status 精确匹配）。
    pub async fn list_users_filtered(&self, filter: &UserFilter<'_>) -> crate::Result<Vec<User>> {
        let mut parts = Vec::new();
        let mut binds = Vec::new();
        push_user_filter(&mut parts, &mut binds, filter);
        // limit/offset 已归一化为 i64，字面量拼接无注入面，且避开
        // "参数 + 表达式混合"在 sqlx Any 下的 Bind 协议坑。
        let sql_text = format!(
            "{}{} ORDER BY id LIMIT {} OFFSET {}",
            sql::LIST_USERS_FILTERED_PREFIX,
            parts.join(""),
            filter.normalized_limit(),
            filter.offset.max(0),
        );

        let mut q = sqlx::query_as::<_, UserRow>(&sql_text);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        q.fetch_all(self.pool())
            .await
            .db_ctx("list users filtered")
            .map(|rows| rows.into_iter().map(|r| r.into()).collect())
    }

    /// 按相同过滤条件统计用户总数（忽略 limit/offset）。
    pub async fn count_users_filtered(&self, filter: &UserFilter<'_>) -> crate::Result<i64> {
        let mut parts = Vec::new();
        let mut binds = Vec::new();
        push_user_filter(&mut parts, &mut binds, filter);
        let sql_text = format!("{}{}", sql::COUNT_USERS_FILTERED_PREFIX, parts.join(""));

        let mut q = sqlx::query_scalar::<_, i64>(&sql_text);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        q.fetch_one(self.pool())
            .await
            .db_ctx("count users filtered")
    }

    /// 设置用户角色（单事务：守卫 → UPDATE → COMMIT）。行不存在返回 Ok
    ///（no-op 契约：存在性预检由路由层 404 负责）。
    pub async fn set_user_role(&self, id: i64, role: &str) -> crate::Result<()> {
        self.update_user_field_tx(
            "set user role",
            sql::UPDATE_USER_ROLE,
            id,
            role,
            role != "admin",
        )
        .await
    }

    /// 设置用户状态（active / disabled）；事务与守卫语义同
    /// [`Self::set_user_role`]。
    pub async fn set_user_status(&self, id: i64, status: &str) -> crate::Result<()> {
        self.update_user_field_tx(
            "set user status",
            sql::UPDATE_USER_STATUS,
            id,
            status,
            status != "active",
        )
        .await
    }

    /// set_user_role / set_user_status 共用的单事务写路径：守卫判定 →
    /// UPDATE → COMMIT → bump。
    async fn update_user_field_tx(
        &self,
        op: &'static str,
        sql_text: &str,
        id: i64,
        value: &str,
        removes_from_active_admins: bool,
    ) -> crate::Result<()> {
        let mut conn = self.begin_write().await?;

        // BEGIN 后任何错误（含 COMMIT 失败）先 ROLLBACK：开事务连接回池
        // 会持 SQLite 写锁 / 污染 PG 池。

        match ensure_not_last_active_admin(&mut conn, id, removes_from_active_admins).await {
            Ok(()) => {}
            Err(e) => rollback_and_return!(conn, e),
        }

        match sqlx::query(sql_text)
            .bind(value)
            .bind(id)
            .execute(&mut *conn)
            .await
            .db_ctx(op)
        {
            Ok(_) => {}
            Err(e) => rollback_and_return!(conn, e),
        }

        match sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit user field update")
        {
            Ok(_) => {}
            Err(e) => rollback_and_return!(conn, e),
        }
        self.bump_user_generation();
        Ok(())
    }

    /// 设置用户密码（hash 为 argon2id PHC 串，策略校验与哈希由调用方完成）。
    /// must_change：admin 重置传 true（强制下次改密），自改传 false（清标志）。
    pub async fn set_user_password(
        &self,
        user_id: i64,
        hash: &str,
        must_change: bool,
    ) -> crate::Result<()> {
        sqlx::query(sql::UPDATE_USER_PASSWORD)
            .bind(hash)
            .bind(must_change as i64)
            .bind(user_id)
            .execute(self.pool())
            .await
            .db_ctx("set user password")?;
        self.bump_user_generation();
        Ok(())
    }

    /// 读取用户认证行；独立映射，password_hash 不进序列化输出（见 [`UserAuthRow`]）。
    pub async fn get_user_auth_row(&self, user_id: i64) -> crate::Result<Option<UserAuthRow>> {
        sqlx::query_as::<_, UserAuthDbRow>(sql::SELECT_USER_AUTH_ROW)
            .bind(user_id)
            .fetch_optional(self.pool())
            .await
            .db_ctx("get user auth row")
            .map(|row| row.map(|r| r.into()))
    }

    /// 创建用户 token，返回 token ID。
    pub async fn create_user_token(
        &self,
        user_id: i64,
        name: Option<&str>,
        hash: &str,
        expires_at: Option<&str>,
    ) -> crate::Result<i64> {
        let id = sqlx::query_scalar::<_, i64>(sql::INSERT_USER_TOKEN)
            .bind(user_id)
            .bind(name)
            .bind(hash)
            .bind(expires_at)
            .fetch_one(&self.pool)
            .await
            .db_ctx("create user token")?;
        self.bump_user_generation();
        Ok(id)
    }

    /// 按 hash 查找用户 token（用于认证）。
    pub async fn find_user_token_by_hash(&self, hash: &str) -> crate::Result<Option<UserToken>> {
        sqlx::query_as::<_, UserTokenRow>(sql::SELECT_USER_TOKEN_BY_HASH)
            .bind(hash)
            .fetch_optional(self.pool())
            .await
            .db_ctx("find user token by hash")
            .map(|row| row.map(|r| r.into()))
    }

    /// 列出用户的所有 token。
    pub async fn list_user_tokens(&self, user_id: i64) -> crate::Result<Vec<UserToken>> {
        sqlx::query_as::<_, UserTokenRow>(sql::LIST_USER_TOKENS_BY_USER)
            .bind(user_id)
            .fetch_all(self.pool())
            .await
            .db_ctx("list user tokens")
            .map(|rows| rows.into_iter().map(|r| r.into()).collect())
    }

    /// 列出用户的活跃（未撤销）token，新→旧，封顶 `limit` 条（/ui/me
    /// 令牌卡口径；全量含已撤销走 [`Self::list_user_tokens`]）。
    pub async fn list_active_user_tokens(
        &self,
        user_id: i64,
        limit: i64,
    ) -> crate::Result<Vec<UserToken>> {
        sqlx::query_as::<_, UserTokenRow>(sql::LIST_ACTIVE_USER_TOKENS_BY_USER)
            .bind(user_id)
            .bind(limit)
            .fetch_all(self.pool())
            .await
            .db_ctx("list active user tokens")
            .map(|rows| rows.into_iter().map(|r| r.into()).collect())
    }

    /// 用户的活跃（未撤销）token 计数（/ui/me 总览带；不受展示封顶截断）。
    pub async fn count_active_user_tokens(&self, user_id: i64) -> crate::Result<i64> {
        sqlx::query_scalar::<_, i64>(sql::COUNT_ACTIVE_USER_TOKENS)
            .bind(user_id)
            .fetch_one(self.pool())
            .await
            .db_ctx("count active user tokens")
    }

    /// 撤销用户 token。
    pub async fn revoke_user_token(&self, token_id: i64) -> crate::Result<()> {
        sqlx::query(&sql::revoke_user_token(self.dialect))
            .bind(token_id)
            .execute(self.pool())
            .await
            .db_ctx("revoke user token")?;
        self.bump_user_generation();
        Ok(())
    }

    /// 删除过期与已撤销 token，返回删除行数（周期清理入口）。不 bump
    /// 代数（认证本就拒绝过期/撤销行）；`now` 须与写入侧同为 RFC 3339。
    pub async fn delete_expired_user_tokens(&self, now: &str) -> crate::Result<u64> {
        let result = sqlx::query(sql::DELETE_EXPIRED_USER_TOKENS)
            .bind(now)
            .execute(self.pool())
            .await
            .db_ctx("delete expired user tokens")?;
        Ok(result.rows_affected())
    }

    /// 按名查产品 id（ACL 接口入口用）；不存在返回 NotFound。
    async fn find_product_id_by_name(&self, product: &str) -> crate::Result<i64> {
        sqlx::query_scalar("SELECT id FROM products WHERE name = $1")
            .bind(product)
            .fetch_optional(self.pool())
            .await
            .db_ctx("find product")?
            .ok_or_else(|| crate::error::CrbsError::NotFound {
                message: format!("product {} not found", product),
            })
    }

    /// 授予用户产品 ACL（默认 role=viewer）。
    pub async fn grant_product_acl(&self, user_id: i64, product: &str) -> crate::Result<()> {
        self.grant_product_acl_with_role(user_id, product, "viewer")
            .await
    }

    /// 授予用户产品 ACL 并指定角色。
    pub async fn grant_product_acl_with_role(
        &self,
        user_id: i64,
        product: &str,
        role: &str,
    ) -> crate::Result<()> {
        let product_id = self.find_product_id_by_name(product).await?;

        sqlx::query(sql::INSERT_PRODUCT_ACL)
            .bind(product_id)
            .bind(user_id)
            .bind(role)
            .execute(self.pool())
            .await
            .db_ctx("grant product acl")?;
        self.bump_user_generation();
        Ok(())
    }

    /// 撤销用户产品 ACL：取消构建 + 撤销同事务，无 TOCTOU。返回值是
    /// 级联取消的构建数、**不是存在性判据**（ACL 不存在时 DELETE 落空
    /// 返回 0）——"未授权 → 404"预检由 handler 层 is_product_acl_granted 承担。
    pub async fn revoke_product_acl(&self, user_id: i64, product: &str) -> crate::Result<u64> {
        let mut conn = self.begin_write().await?;

        // BEGIN 后任何错误（含 COMMIT 失败）先 ROLLBACK：开事务连接回池
        // 会持 SQLite 写锁 / 污染 PG 池。
        let product_row: Option<i64> =
            match sqlx::query_scalar("SELECT id FROM products WHERE name = $1")
                .bind(product)
                .fetch_optional(&mut *conn)
                .await
                .db_ctx("find product")
            {
                Ok(v) => v,
                Err(e) => rollback_and_return!(conn, e),
            };
        let product_id: i64 = match product_row {
            Some(id) => id,
            None => rollback_and_return!(
                conn,
                CrbsError::NotFound {
                    message: format!("product {} not found", product),
                }
            ),
        };

        // 取消该用户对该产品的 pending/assigned/building 构建，
        // RETURNING 按实际翻转的行收集 layer_digest（见 SQL 注释）。
        let cancelled_digests: Vec<Option<String>> =
            match sqlx::query_scalar(&sql::cancel_builds_on_acl_revoke(self.dialect))
                .bind(product_id)
                .bind(user_id)
                .fetch_all(&mut *conn)
                .await
                .db_ctx("cancel user builds on ACL revoke")
            {
                Ok(v) => v,
                Err(e) => rollback_and_return!(conn, e),
            };
        let builds_cancelled = cancelled_digests.len() as u64;

        // 释放共享层引用（归零即安装 GC schedule）。宽限恒用编译期默认
        // 168h（非配置值）；Ok(0)（行已被并发 GC 删 / 已归零）warn 跳过、
        // 不回滚，残留计数由泄漏修复路径收敛。
        let grace_hours = crate::config::defaults::default_shared_layer_gc_grace_hours() as i64;
        for digest in cancelled_digests.into_iter().flatten() {
            match self
                .layer_ref_dec_in_tx(&mut conn, &digest, grace_hours)
                .await
            {
                Ok(0) => {
                    tracing::warn!(
                        digest = %digest,
                        "layer row missing or ref already 0 on ACL revoke; nothing to release"
                    )
                }
                Ok(_) => {}
                // 内层已 db_ctx（错误已是 CrbsError）：二次包 Database(String)
                // 会把不可用错误降级（503/is_transient 丢失）且双重嵌套——透传。
                Err(e) => rollback_and_return!(conn, e),
            }
        }

        // 收口相关任务（聚合口径见 SQL 注释，子构建已在上方同事务取消）；
        // 实际翻转的行数计入下方广播门卫（翻转了任务才广播）。
        let task_ids: Vec<i64> = match sqlx::query_scalar(sql::LIST_ACTIVE_TASKS_ON_ACL_REVOKE)
            .bind(product_id)
            .bind(user_id)
            .fetch_all(&mut *conn)
            .await
            .db_ctx("list active tasks on ACL revoke")
        {
            Ok(v) => v,
            Err(e) => rollback_and_return!(conn, e),
        };
        let mut tasks_cancelled: u64 = 0;
        for task_id in task_ids {
            match super::tasks::finalize_cancelled_task_on(&mut conn, self.dialect, task_id).await {
                Ok(rows) => tasks_cancelled += rows,
                Err(e) => rollback_and_return!(conn, e),
            }
        }

        match sqlx::query(sql::DELETE_PRODUCT_ACL)
            .bind(user_id)
            .bind(product_id)
            .execute(&mut *conn)
            .await
            .db_ctx("revoke product acl")
        {
            Ok(_) => {}
            Err(e) => rollback_and_return!(conn, e),
        };

        match sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit revoke product acl")
        {
            Ok(_) => {}
            Err(e) => rollback_and_return!(conn, e),
        }
        self.bump_user_generation();
        // 仅实际取消构建/任务才广播：终态写入漏通知会使通知驱动的 select
        // 退化为 5s 兜底轮询；task pending/building→cancelled 同是状态面
        // 变更（聚合滞后时可仅任务翻转）。ACL 行删除本身不广播。
        if builds_cancelled > 0 || tasks_cancelled > 0 {
            self.notify_state_changed();
        }

        Ok(builds_cancelled)
    }

    /// 检查指定用户是否已授予某产品的 ACL（按产品名）。
    pub async fn is_product_acl_granted(&self, user_id: i64, product: &str) -> crate::Result<bool> {
        let product_id = self.find_product_id_by_name(product).await?;

        self.is_product_acl_granted_by_id(user_id, product_id).await
    }

    /// 检查指定用户是否已授予某产品的 ACL（按产品 ID）。
    async fn is_product_acl_granted_by_id(
        &self,
        user_id: i64,
        product_id: i64,
    ) -> crate::Result<bool> {
        let count: i64 = sqlx::query_scalar(sql::COUNT_PRODUCT_ACL)
            .bind(user_id)
            .bind(product_id)
            .fetch_one(self.pool())
            .await
            .db_ctx("check product acl by id")?;
        Ok(count > 0)
    }

    /// 列出用户可访问的产品。
    pub async fn list_products_by_user(&self, user_id: i64) -> crate::Result<Vec<String>> {
        sqlx::query_scalar(sql::LIST_PRODUCTS_BY_USER)
            .bind(user_id)
            .fetch_all(self.pool())
            .await
            .db_ctx("list products by user")
    }

    /// 列出某产品的所有授权用户。`role` 是 product_acl 的产品角色（非
    /// users 表全局角色）；`created_at` 是授权时间（非账号创建时间）。
    pub async fn list_users_by_product(&self, product: &str) -> crate::Result<Vec<User>> {
        let product_id = self.find_product_id_by_name(product).await?;

        sqlx::query_as::<_, UserRow>(sql::LIST_USERS_BY_PRODUCT)
            .bind(product_id)
            .fetch_all(self.pool())
            .await
            .db_ctx("list users by product")
            .map(|rows| rows.into_iter().map(|r| r.into()).collect())
    }

    /// 获取用户对指定产品的 ACL 角色（按产品名）；`None` 表示无授权。
    pub async fn get_product_acl_role(
        &self,
        user_id: i64,
        product: &str,
    ) -> crate::Result<Option<String>> {
        let product_id = self.find_product_id_by_name(product).await?;

        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM product_acl WHERE user_id = $1 AND product_id = $2",
        )
        .bind(user_id)
        .bind(product_id)
        .fetch_optional(self.pool())
        .await
        .db_ctx("get product acl role")?;

        Ok(role)
    }

    /// 列出用户的所有 ACL 记录。
    pub async fn list_product_acls(&self, user_id: i64) -> crate::Result<Vec<ProductAcl>> {
        sqlx::query_as::<_, ProductAclRow>(sql::LIST_PRODUCT_ACLS_BY_USER)
            .bind(user_id)
            .fetch_all(self.pool())
            .await
            .db_ctx("list product acls")
            .map(|rows| rows.into_iter().map(|r| r.into()).collect())
    }
}

#[derive(sqlx::FromRow)]
struct UserRow {
    id: i64,
    name: String,
    role: String,
    status: String,
    created_at: String,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            role: row.role,
            status: row.status,
            created_at: row.created_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct UserTokenRow {
    id: i64,
    user_id: i64,
    name: Option<String>,
    hash: String,
    expires_at: Option<String>,
    created_at: String,
    revoked_at: Option<String>,
}

impl From<UserTokenRow> for UserToken {
    fn from(row: UserTokenRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            name: row.name,
            hash: row.hash,
            expires_at: row.expires_at,
            created_at: row.created_at,
            revoked_at: row.revoked_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct UserAuthDbRow {
    id: i64,
    password_hash: Option<String>,
    must_change_password: i64,
}

impl From<UserAuthDbRow> for UserAuthRow {
    fn from(row: UserAuthDbRow) -> Self {
        Self {
            id: row.id,
            password_hash: row.password_hash,
            must_change_password: row.must_change_password != 0,
        }
    }
}

#[derive(sqlx::FromRow)]
struct ProductAclRow {
    user_id: i64,
    product: String,
    role: String,
    created_at: String,
}

impl From<ProductAclRow> for ProductAcl {
    fn from(row: ProductAclRow) -> Self {
        Self {
            user_id: row.user_id,
            product: row.product,
            role: row.role,
            created_at: row.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::secret::{Secret, SecretKind};
    use crate::state::test_state::create_test_store;
    use crate::state::Dialect;

    /// 方言工厂直连（PG 门控可达本模块）；TempDir 生命周期由
    /// crate::state::test_state 管理。
    async fn store() -> (StateStore, Option<tempfile::TempDir>) {
        create_test_store().await
    }

    /// 夹具：官方 public 产品（owner/parent/display_name/reason 全默认）。
    async fn mk_product(store: &StateStore, name: &str) {
        store
            .create_product(crate::CreateProductInput {
                name,
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: "public",
                config: &crate::config::ProductConfig::default(),
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn user_crud_roundtrip() {
        let (store, _tmp) = store().await;
        let id = store.create_user("alice", "builder").await.unwrap();
        let user = store.get_user(id).await.unwrap().unwrap();
        assert_eq!(user.name, "alice");
        assert_eq!(user.role, "builder");
        assert_eq!(user.status, "active");

        store.set_user_role(id, "operator").await.unwrap();
        let user = store.get_user(id).await.unwrap().unwrap();
        assert_eq!(user.role, "operator");

        store.set_user_status(id, "disabled").await.unwrap();
        let user = store.get_user(id).await.unwrap().unwrap();
        assert_eq!(user.status, "disabled");
    }

    /// 守卫全矩阵：降级/禁用唯一活跃 admin 拒（Conflict 且状态未变）；
    /// 非 admin、提升/重新启用、disabled admin 降级、双活跃 admin、
    /// 不存在 id 均放行（no-op 契约）。
    #[tokio::test]
    async fn last_active_admin_guard_matrix() {
        let (store, _tmp) = store().await;
        let sole = store.create_user("sole", "admin").await.unwrap();

        let err = store.set_user_role(sole, "viewer").await.unwrap_err();
        assert!(matches!(err, CrbsError::Conflict { .. }), "got: {err}");
        assert!(err.to_string().contains("last active admin"), "got: {err}");
        assert_eq!(
            store.get_user(sole).await.unwrap().unwrap().role,
            "admin",
            "rejected demote must not change role"
        );

        let err = store.set_user_status(sole, "disabled").await.unwrap_err();
        assert!(matches!(err, CrbsError::Conflict { .. }), "got: {err}");
        assert_eq!(
            store.get_user(sole).await.unwrap().unwrap().status,
            "active",
            "rejected disable must not change status"
        );

        let bob = store.create_user("bob", "builder").await.unwrap();
        store.set_user_role(bob, "viewer").await.unwrap();
        store.set_user_status(bob, "disabled").await.unwrap();

        store.set_user_role(bob, "admin").await.unwrap();

        store.set_user_status(bob, "disabled").await.unwrap();
        store.set_user_status(bob, "active").await.unwrap();

        store.set_user_status(bob, "disabled").await.unwrap();
        store.set_user_role(bob, "viewer").await.unwrap();

        let second = store.create_user("second", "admin").await.unwrap();
        store.set_user_role(second, "viewer").await.unwrap();

        store.set_user_role(99999, "viewer").await.unwrap();
        store.set_user_status(99999, "disabled").await.unwrap();
    }

    #[tokio::test]
    async fn find_user_by_name_and_unique_constraint() {
        let (store, _tmp) = store().await;
        store.create_user("alice", "builder").await.unwrap();
        let user = store.find_user_by_name("alice").await.unwrap().unwrap();
        assert_eq!(user.name, "alice");

        assert!(store.create_user("alice", "viewer").await.is_err());
    }

    /// create_user 收口校验：用户名须满足 slug 语义（[a-z0-9_-]、非空、
    /// ≤128），任何入口不得绕过。
    #[tokio::test]
    async fn create_user_enforces_slug_name_validation() {
        let (store, _tmp) = store().await;

        assert!(store.create_user("admin", "admin").await.is_ok());
        assert!(store.create_user("dev-01", "builder").await.is_ok());
        assert!(store.create_user(&"a".repeat(128), "viewer").await.is_ok());

        let err = store
            .create_user(&"a".repeat(129), "viewer")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("too long"), "got: {err}");

        let err = store.create_user("", "viewer").await.unwrap_err();
        assert!(err.to_string().contains("cannot be empty"), "got: {err}");
        for bad in ["BadName", "user name!", "alice@corp"] {
            let err = store.create_user(bad, "viewer").await.unwrap_err();
            assert!(
                err.to_string().contains("invalid characters"),
                "{bad}: got: {err}"
            );
        }
    }

    /// 注册原子性：单条 INSERT 后认证行完整可读，无"无密码半成品行"。
    #[tokio::test]
    async fn create_user_with_password_roundtrip() {
        let (store, _tmp) = store().await;
        let phc = crate::auth::password::hash_password("register-pw-123").unwrap();
        let user_id = store
            .create_user_with_password("reg-alice", "viewer", &phc, false)
            .await
            .unwrap();

        let user = store.get_user(user_id).await.unwrap().unwrap();
        assert_eq!(user.role, "viewer");
        assert_eq!(user.status, "active");

        let row = store.get_user_auth_row(user_id).await.unwrap().unwrap();
        assert_eq!(row.password_hash.as_deref(), Some(phc.as_str()));
        assert!(!row.must_change_password);
        assert!(crate::auth::password::verify_password(
            "register-pw-123",
            &phc
        ));
    }

    /// 同名二插的 Err 须能被 `is_unique_violation` 识别——注册页并发竞态
    /// 分支依赖该判定（双方言唯一冲突文本经 Display 可达）。
    #[tokio::test]
    async fn create_user_with_password_duplicate_err_is_unique_violation() {
        let (store, _tmp) = store().await;
        let phc = crate::auth::password::hash_password("dup-pw-123456").unwrap();
        store
            .create_user_with_password("dup-alice", "viewer", &phc, false)
            .await
            .unwrap();

        let err = store
            .create_user_with_password("dup-alice", "viewer", &phc, false)
            .await
            .unwrap_err();
        assert!(
            crate::error::is_unique_violation(&err),
            "duplicate insert must classify as unique violation, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn user_token_crud() {
        let (store, _tmp) = store().await;
        let user_id = store.create_user("alice", "builder").await.unwrap();

        let secret = Secret::generate(SecretKind::UserToken).unwrap();
        let hash = secret.hash();
        let token_id = store
            .create_user_token(user_id, Some("laptop"), hash.as_str(), None)
            .await
            .unwrap();

        let found = store
            .find_user_token_by_hash(hash.as_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.user_id, user_id);
        assert_eq!(found.name, Some("laptop".to_string()));

        store.revoke_user_token(token_id).await.unwrap();
        let found = store
            .find_user_token_by_hash(hash.as_str())
            .await
            .unwrap()
            .unwrap();
        assert!(found.revoked_at.is_some());
    }

    /// 密码列读写：未设密码 → NULL/0；重置置位 / 自改清零 must_change；
    /// 不存在的用户返回 None。
    #[tokio::test]
    async fn user_password_roundtrip() {
        let (store, _tmp) = store().await;
        let user_id = store.create_user("alice", "builder").await.unwrap();

        let row = store.get_user_auth_row(user_id).await.unwrap().unwrap();
        assert_eq!(row.id, user_id);
        assert_eq!(row.password_hash, None);
        assert!(!row.must_change_password);

        let phc = crate::auth::password::hash_password("reset-password-1").unwrap();
        store.set_user_password(user_id, &phc, true).await.unwrap();
        let row = store.get_user_auth_row(user_id).await.unwrap().unwrap();
        assert_eq!(row.password_hash.as_deref(), Some(phc.as_str()));
        assert!(row.must_change_password);

        let phc2 = crate::auth::password::hash_password("own-password-12").unwrap();
        store
            .set_user_password(user_id, &phc2, false)
            .await
            .unwrap();
        let row = store.get_user_auth_row(user_id).await.unwrap().unwrap();
        assert_eq!(row.password_hash.as_deref(), Some(phc2.as_str()));
        assert!(!row.must_change_password);

        assert!(store.get_user_auth_row(99999).await.unwrap().is_none());

        assert!(crate::auth::password::verify_password(
            "own-password-12",
            &phc2
        ));
        assert!(!crate::auth::password::verify_password(
            "reset-password-1",
            &phc2
        ));
    }

    #[tokio::test]
    async fn product_acl_roundtrip() {
        let (store, _tmp) = store().await;
        let alice = store.create_user("alice", "builder").await.unwrap();
        let bob = store.create_user("bob", "builder").await.unwrap();

        // ACL 引用 product_id，须先建产品
        mk_product(&store, "foo").await;
        mk_product(&store, "bar").await;

        store.grant_product_acl(alice, "foo").await.unwrap();
        store.grant_product_acl(alice, "bar").await.unwrap();
        // bob 的 ACL 角色与全局角色（builder）不同，用于验证列表返回 ACL 角色
        store
            .grant_product_acl_with_role(bob, "foo", "admin")
            .await
            .unwrap();

        let acls = store.list_product_acls(alice).await.unwrap();
        let products: Vec<_> = acls.iter().map(|a| a.product.as_str()).collect();
        assert_eq!(products, vec!["bar", "foo"]);
        assert!(acls.iter().all(|a| a.user_id == alice));
        assert!(acls.iter().all(|a| a.role == "viewer"));

        let products = store.list_products_by_user(alice).await.unwrap();
        assert_eq!(products, vec!["bar", "foo"]);

        let users = store.list_users_by_product("foo").await.unwrap();
        assert_eq!(users.len(), 2);
        let listed: Vec<(&str, &str)> = users
            .iter()
            .map(|u| (u.name.as_str(), u.role.as_str()))
            .collect();
        assert_eq!(listed, vec![("alice", "viewer"), ("bob", "admin")]);

        store.revoke_product_acl(alice, "foo").await.unwrap();
        let acls = store.list_product_acls(alice).await.unwrap();
        assert_eq!(acls.len(), 1);
        assert_eq!(acls[0].product, "bar");
    }

    /// 撤销取消的活跃构建须同时落 phase='cancelled' 与 completed_at
    ///（result-GC / retention 门）。
    #[tokio::test]
    async fn revoke_product_acl_cancels_active_builds_with_completed_at() {
        let (store, _tmp) = store().await;
        let alice = store.create_user("alice", "builder").await.unwrap();
        mk_product(&store, "foo").await;
        store.grant_product_acl(alice, "foo").await.unwrap();

        // 三个活跃构建（pending / assigned / building）：user_id 须落库
        //（取消 SQL 按 user_id 匹配）；task_id 非空约束，先插宿主任务。
        let task_id = store
            .insert_task(crate::TaskInsert {
                product: "foo",
                pkg_name: "pkg",
                user: "alice",
                ..Default::default()
            })
            .await
            .unwrap();
        let mut ids = Vec::new();
        for (i, phase) in ["pending", "assigned", "building"].iter().enumerate() {
            // assigned/building 持层引用（d-acl），pending 未 attach 层。
            let digest = if *phase == "pending" {
                None
            } else {
                Some("d-acl")
            };
            let id = store
                .insert_build(crate::BuildInsert {
                    product: "foo",
                    pkg_name: &format!("pkg-{i}"),
                    phase,
                    layer_digest: digest,
                    backend: "chroot",
                    user: "alice",
                    user_id: Some(alice),
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
                .unwrap();
            ids.push(id);
        }
        // 终态构建（succeeded）：层引用不在取消域，不得误释放。
        let done_id = store
            .insert_build(crate::BuildInsert {
                product: "foo",
                pkg_name: "pkg-done",
                phase: "succeeded",
                layer_digest: Some("d-done"),
                backend: "chroot",
                user: "alice",
                user_id: Some(alice),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        // 行缺失的层引用（d-gone）：dec 须容忍 Ok(0)，不让撤销事务回滚。
        let ghost_id = store
            .insert_build(crate::BuildInsert {
                product: "foo",
                pkg_name: "pkg-ghost",
                phase: "building",
                layer_digest: Some("d-gone"),
                backend: "chroot",
                user: "alice",
                user_id: Some(alice),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .insert_layer("d-acl", "/tmp/l-acl", "foo", 2)
            .await
            .unwrap();
        store
            .insert_layer("d-done", "/tmp/l-done", "foo", 1)
            .await
            .unwrap();

        let cancelled = store.revoke_product_acl(alice, "foo").await.unwrap();
        assert_eq!(
            cancelled, 4,
            "all active builds (pending/assigned/building, incl. ghost-layer) must be cancelled"
        );

        for id in ids.iter().chain([&ghost_id]) {
            let (phase, completed_at, duration): (String, Option<String>, Option<i64>) =
                sqlx::query_as("SELECT phase, completed_at, duration FROM builds WHERE id = $1")
                    .bind(id)
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            assert_eq!(phase, "cancelled");
            assert!(
                completed_at.is_some(),
                "cancelled build {id} must carry completed_at for GC/retention gates"
            );
            // duration 同口径落值；NULL started_at → NULL duration 传播
            // 由 mark_build_cancelled 测试覆盖。
            assert!(
                duration.is_some() && duration >= Some(0),
                "cancelled build {id} must carry non-negative duration, got {duration:?}"
            );
        }
        let (done_phase, _): (String, Option<String>) =
            sqlx::query_as("SELECT phase, completed_at FROM builds WHERE id = $1")
                .bind(done_id)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(done_phase, "succeeded", "terminal build must be untouched");

        let acl_ref = store.get_layer_ref_count("d-acl").await.unwrap();
        assert_eq!(
            acl_ref,
            Some(0),
            "cancelled builds' layer refs must be released"
        );
        let done_ref = store.get_layer_ref_count("d-done").await.unwrap();
        assert_eq!(
            done_ref,
            Some(1),
            "terminal build's layer ref must be untouched"
        );
    }

    /// 级联取消是终态写入，须广播状态变更（漏通知使通知驱动的 select 退化
    /// 为 5s 兜底轮询）。唤醒断言先挂等待方、再触发写（`notify_waiters` 只
    /// 唤醒已挂起的等待方、不记 permit，sleep 让步落座）。
    #[tokio::test]
    async fn revoke_product_acl_notifies_state_change_when_builds_cancelled() {
        let (store, _tmp) = store().await;
        let alice = store.create_user("alice", "builder").await.unwrap();
        mk_product(&store, "foo").await;
        store.grant_product_acl(alice, "foo").await.unwrap();
        let task_id = store
            .insert_task(crate::TaskInsert {
                product: "foo",
                pkg_name: "pkg",
                user: "alice",
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .insert_build(crate::BuildInsert {
                product: "foo",
                pkg_name: "pkg",
                phase: "building",
                backend: "chroot",
                user: "alice",
                user_id: Some(alice),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        // seed 写入（insert_task/insert_build 各广播一次）完成后再挂等待方。
        let waiter_store = store.clone();
        let waiter = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(2), waiter_store.changed())
                .await
                .is_ok()
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let cancelled = store.revoke_product_acl(alice, "foo").await.unwrap();
        assert_eq!(cancelled, 1);
        assert!(
            waiter.await.unwrap(),
            "revoke that cancels builds must wake store.changed() waiters"
        );
    }

    /// 聚合滞后形态：builds 已全终态（此处未建）而 task 仍 pending 时，
    /// revoke 只翻转 task 行——同样须广播（任务 SSE 与 UI 轮询，门卫 OR
    /// tasks_cancelled）；返回值仍只数 build（== 0）。
    #[tokio::test]
    async fn revoke_product_acl_notifies_state_change_when_only_tasks_cancelled() {
        let (store, _tmp) = store().await;
        let alice = store.create_user("alice", "builder").await.unwrap();
        mk_product(&store, "foo").await;
        store.grant_product_acl(alice, "foo").await.unwrap();
        // 只 seed 一个 task（TaskInsert::default 即 pending），不插 build；
        // user_id 必填（取消按 tasks.user_id 匹配）。
        store
            .insert_task(crate::TaskInsert {
                product: "foo",
                pkg_name: "pkg",
                user: "alice",
                user_id: Some(alice),
                ..Default::default()
            })
            .await
            .unwrap();

        // seed 写入（insert_task 广播一次）完成后再挂等待方。
        let waiter_store = store.clone();
        let waiter = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(2), waiter_store.changed())
                .await
                .is_ok()
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let cancelled = store.revoke_product_acl(alice, "foo").await.unwrap();
        assert_eq!(
            cancelled, 0,
            "no builds existed: return value counts builds only"
        );
        assert!(
            waiter.await.unwrap(),
            "revoke that cancels only tasks must wake store.changed() waiters"
        );
    }

    /// bulk 取消按聚合口径收口 task：一 failed + 一 pending 子构建 →
    /// task 收口 failed（优先级 failed > cancelled），非一刀切 cancelled。
    #[tokio::test]
    async fn revoke_product_acl_finalizes_task_by_child_aggregation() {
        let (store, _tmp) = store().await;
        let alice = store.create_user("alice", "builder").await.unwrap();
        mk_product(&store, "foo").await;
        store.grant_product_acl(alice, "foo").await.unwrap();

        // user_id 必须落库：task 收口按 product_id + user_id 匹配。
        let task_id = store
            .insert_task(crate::TaskInsert {
                product: "foo",
                pkg_name: "pkg",
                user: "alice",
                user_id: Some(alice),
                ..Default::default()
            })
            .await
            .unwrap();
        let b_failed = store
            .insert_build(crate::BuildInsert {
                product: "foo",
                pkg_name: "pkg-done",
                phase: "failed",
                backend: "chroot",
                user: "alice",
                user_id: Some(alice),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let b_pending = store
            .insert_build(crate::BuildInsert {
                product: "foo",
                pkg_name: "pkg-live",
                phase: "pending",
                backend: "chroot",
                user: "alice",
                user_id: Some(alice),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        store.revoke_product_acl(alice, "foo").await.unwrap();

        let phase_of = |id: i64| {
            let store = &store;
            async move {
                let (phase,): (String,) = sqlx::query_as("SELECT phase FROM builds WHERE id = $1")
                    .bind(id)
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
                phase
            }
        };
        assert_eq!(phase_of(b_pending).await, "cancelled");
        assert_eq!(phase_of(b_failed).await, "failed");

        let (phase, completed_at, duration): (String, Option<String>, Option<i64>) =
            sqlx::query_as("SELECT phase, completed_at, duration FROM tasks WHERE id = $1")
                .bind(task_id)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(
            phase, "failed",
            "mixed-terminal children must aggregate to failed, not blanket cancelled"
        );
        assert!(
            completed_at.is_some(),
            "finalized task must carry completed_at"
        );
        assert!(
            duration.is_some() && duration >= Some(0),
            "finalized task must carry non-negative duration, got {duration:?}"
        );
    }

    /// 私人产品（owner_id 非空 → builds/tasks.product_id 恒 NULL）的级联
    /// 取消须按 **name** 口径命中：协作者的 pending 构建被取消、宿主
    /// 任务被收口。
    #[tokio::test]
    async fn revoke_product_acl_cancels_private_product_builds_by_name() {
        let (store, _tmp) = store().await;
        let alice = store.create_user("alice", "builder").await.unwrap();
        let bob = store.create_user("bob", "builder").await.unwrap();
        store
            .create_product(crate::CreateProductInput {
                name: "secret",
                display_name: None,
                owner_id: Some(alice),
                parent_id: None,
                visibility: "private",
                config: &crate::config::ProductConfig::default(),
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();
        store.grant_product_acl(bob, "secret").await.unwrap();

        let task_id = store
            .insert_task(crate::TaskInsert {
                product: "secret",
                pkg_name: "pkg",
                user: "bob",
                user_id: Some(bob),
                ..Default::default()
            })
            .await
            .unwrap();
        let build_id = store
            .insert_build(crate::BuildInsert {
                product: "secret",
                pkg_name: "pkg",
                phase: "pending",
                backend: "chroot",
                user: "bob",
                user_id: Some(bob),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        let cancelled = store.revoke_product_acl(bob, "secret").await.unwrap();
        assert_eq!(
            cancelled, 1,
            "private product's pending build must be cancelled by name"
        );

        let (b_phase,): (String,) = sqlx::query_as("SELECT phase FROM builds WHERE id = $1")
            .bind(build_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(b_phase, "cancelled");
        let (t_phase,): (String,) = sqlx::query_as("SELECT phase FROM tasks WHERE id = $1")
            .bind(task_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            t_phase, "cancelled",
            "private product's pending task must be finalized by name"
        );
    }

    #[tokio::test]
    async fn list_users_by_product_created_at_is_grant_time() {
        let (store, _tmp) = store().await;
        let alice = store.create_user("alice", "builder").await.unwrap();
        mk_product(&store, "foo").await;
        store.grant_product_acl(alice, "foo").await.unwrap();

        // 把账号创建时间改成远早于授权时间的哨兵值，区分 u.created_at 与 a.created_at
        sqlx::query("UPDATE users SET created_at = '2000-01-01 00:00:00' WHERE id = $1")
            .bind(alice)
            .execute(store.pool())
            .await
            .unwrap();

        let users = store.list_users_by_product("foo").await.unwrap();
        assert_eq!(users.len(), 1);
        assert_ne!(users[0].created_at, "2000-01-01 00:00:00");
        // 与授权时间正源（list_product_acls 的 a.created_at）一致
        let acls = store.list_product_acls(alice).await.unwrap();
        assert_eq!(acls.len(), 1);
        assert_eq!(users[0].created_at, acls[0].created_at);
    }

    /// 锁定过滤 SQL 形态（纯文本，不执行）：bind 占位符必须是 `$N` 编号
    ///（QueryBuilder<Any> 生成 `?`，PG 上语法错）。
    #[test]
    fn users_filtered_query_uses_numbered_placeholders() {
        let filter = UserFilter {
            name: Some("ali"),
            role: Some("admin"),
            status: Some("active"),
            ..Default::default()
        };
        let mut parts = Vec::new();
        let mut binds = Vec::new();
        push_user_filter(&mut parts, &mut binds, &filter);
        let sql = format!(
            "{}{} ORDER BY id LIMIT {} OFFSET {}",
            super::sql::LIST_USERS_FILTERED_PREFIX,
            parts.join(""),
            filter.normalized_limit(),
            filter.offset.max(0),
        );
        assert!(!sql.contains('?'), "must use $N placeholders, got: {sql}");
        assert!(
            sql.contains("$1") && sql.contains("$2") && sql.contains("$3"),
            "each condition gets its own numbered bind: {sql}"
        );
        assert_eq!(
            binds,
            vec![
                "%ali%".to_string(),
                "admin".to_string(),
                "active".to_string()
            ]
        );

        let mut parts = Vec::new();
        let mut binds = Vec::new();
        push_user_filter(&mut parts, &mut binds, &UserFilter::default());
        assert!(parts.is_empty());
        assert!(binds.is_empty());
    }

    #[tokio::test]
    async fn list_users_filtered_filters_and_paginates() {
        let (store, _tmp) = store().await;
        store.create_user("alice", "admin").await.unwrap();
        store.create_user("alina", "operator").await.unwrap();
        store.create_user("bob", "builder").await.unwrap();
        store.create_user("carol", "builder").await.unwrap();
        let dave = store.create_user("dave", "viewer").await.unwrap();
        store.set_user_status(dave, "disabled").await.unwrap();

        let got = store
            .list_users_filtered(&UserFilter {
                name: Some("ali"),
                ..Default::default()
            })
            .await
            .unwrap();
        let names: Vec<_> = got.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, vec!["alice", "alina"]);

        let got = store
            .list_users_filtered(&UserFilter {
                role: Some("builder"),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|u| u.role == "builder"));

        let got = store
            .list_users_filtered(&UserFilter {
                status: Some("disabled"),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "dave");

        // 分页切片与 list_users 全量 ORDER BY id 对齐。
        let all = store.list_users().await.unwrap();
        let page = store
            .list_users_filtered(&UserFilter {
                limit: 2,
                offset: 2,
                ..Default::default()
            })
            .await
            .unwrap();
        let expect: Vec<i64> = all.iter().skip(2).take(2).map(|u| u.id).collect();
        let got: Vec<i64> = page.iter().map(|u| u.id).collect();
        assert_eq!(got, expect);

        // count 与过滤联合，且忽略 limit/offset。
        let count = store
            .count_users_filtered(&UserFilter {
                role: Some("builder"),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(count, 2);
        let count = store
            .count_users_filtered(&UserFilter {
                limit: 1,
                offset: 4,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(count, 5);
    }

    /// LIKE 通配符转义回归：store 层过滤不依赖上游校验——直插含通配符的
    /// 行，锁定搜 "a%b" 只命中字面 a%b。
    #[tokio::test]
    async fn list_users_filtered_escapes_like_wildcards() {
        let (store, _tmp) = store().await;
        for name in ["a%b", "axb", "a_b"] {
            sqlx::query("INSERT INTO users (name, role, status) VALUES ($1, 'builder', 'active')")
                .bind(name)
                .execute(store.pool())
                .await
                .unwrap();
        }

        let got = store
            .list_users_filtered(&UserFilter {
                name: Some("a%b"),
                ..Default::default()
            })
            .await
            .unwrap();
        let names: Vec<&str> = got.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, vec!["a%b"]);

        let got = store
            .list_users_filtered(&UserFilter {
                name: Some("a_b"),
                ..Default::default()
            })
            .await
            .unwrap();
        let names: Vec<&str> = got.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, vec!["a_b"]);

        let got = store
            .list_users_filtered(&UserFilter {
                name: Some("xb"),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "axb");
    }

    /// 撤销事务原子性：末步 DELETE product_acl 注入失败（SQLite
    /// `RAISE(ABORT)` / PG plpgsql `RAISE EXCEPTION` 触发器）须整体回滚——
    /// ACL 行仍在、取消 + 层引用释放 + task 收口全部回退，无部分收口；
    /// 拆注入后二次 revoke 全链成功（失败路径不残留坏事务状态回池）。
    #[tokio::test]
    async fn revoke_product_acl_delete_failure_rolls_back_whole_tx() {
        let (store, _tmp) = store().await;
        let alice = store.create_user("alice", "builder").await.unwrap();
        mk_product(&store, "foo").await;
        store.grant_product_acl(alice, "foo").await.unwrap();
        let task_id = store
            .insert_task(crate::TaskInsert {
                product: "foo",
                pkg_name: "pkg",
                user: "alice",
                user_id: Some(alice),
                ..Default::default()
            })
            .await
            .unwrap();
        // 两个活跃构建：building 持层引用 d-acl（dec 为回滚断言点），pending 裸行。
        let building_id = store
            .insert_build(crate::BuildInsert {
                product: "foo",
                pkg_name: "pkg-b",
                phase: "building",
                layer_digest: Some("d-acl"),
                backend: "chroot",
                user: "alice",
                user_id: Some(alice),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let pending_id = store
            .insert_build(crate::BuildInsert {
                product: "foo",
                pkg_name: "pkg-p",
                phase: "pending",
                layer_digest: None,
                backend: "chroot",
                user: "alice",
                user_id: Some(alice),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .insert_layer("d-acl", "/tmp/l-acl", "foo", 2)
            .await
            .unwrap();
        let ref_before: i64 = sqlx::query_scalar("SELECT ref_count FROM layers WHERE digest = $1")
            .bind("d-acl")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(ref_before, 2);

        // 故障注入：任意 DELETE 必然失败（PG 须先建 plpgsql 函数再挂触发器）。
        match store.dialect() {
            Dialect::Sqlite => {
                sqlx::query(
                    "CREATE TRIGGER abort_acl_delete BEFORE DELETE ON product_acl \
                     BEGIN SELECT RAISE(ABORT, 'boom'); END",
                )
                .execute(store.pool())
                .await
                .unwrap();
            }
            #[cfg(feature = "postgres")]
            Dialect::Postgres => {
                sqlx::query(
                    "CREATE OR REPLACE FUNCTION crbs_test_abort_acl_delete() \
                     RETURNS trigger LANGUAGE plpgsql AS \
                     $$ BEGIN RAISE EXCEPTION 'boom'; END $$",
                )
                .execute(store.pool())
                .await
                .unwrap();
                sqlx::query(
                    "CREATE TRIGGER abort_acl_delete BEFORE DELETE ON product_acl \
                     FOR EACH ROW EXECUTE FUNCTION crbs_test_abort_acl_delete()",
                )
                .execute(store.pool())
                .await
                .unwrap();
            }
        }

        let err = store.revoke_product_acl(alice, "foo").await.unwrap_err();
        assert!(
            !matches!(err, CrbsError::NotFound { .. }),
            "must fail at the injected DELETE step (not an earlier guard), got: {err:?}"
        );
        assert!(
            err.to_string().contains("boom"),
            "injected failure message must surface, got: {err:?}"
        );

        // 拆注入恢复现场（后续 SELECT 断言不受触发器影响）。
        match store.dialect() {
            Dialect::Sqlite => {
                sqlx::query("DROP TRIGGER abort_acl_delete")
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
            #[cfg(feature = "postgres")]
            Dialect::Postgres => {
                sqlx::query("DROP TRIGGER abort_acl_delete ON product_acl")
                    .execute(store.pool())
                    .await
                    .unwrap();
                sqlx::query("DROP FUNCTION crbs_test_abort_acl_delete()")
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
        }

        let acl: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM product_acl")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(acl, 1, "ACL row must survive the rolled-back revoke");

        for (id, phase) in [(building_id, "building"), (pending_id, "pending")] {
            let (p, completed_at): (String, Option<String>) =
                sqlx::query_as("SELECT phase, completed_at FROM builds WHERE id = $1")
                    .bind(id)
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            assert_eq!(p, phase, "cancel of active build must be rolled back");
            assert!(
                completed_at.is_none(),
                "completed_at stamp must be rolled back"
            );
        }

        let ref_after: i64 = sqlx::query_scalar("SELECT ref_count FROM layers WHERE digest = $1")
            .bind("d-acl")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(ref_after, 2, "layer ref release must be rolled back");

        let (task_phase, task_completed): (String, Option<String>) =
            sqlx::query_as("SELECT phase, completed_at FROM tasks WHERE id = $1")
                .bind(task_id)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(
            task_phase, "pending",
            "task finalization must be rolled back"
        );
        assert!(task_completed.is_none());

        // 拆注入后二次 revoke 全链成功：失败路径不残留坏事务状态回池。
        let cancelled = store.revoke_product_acl(alice, "foo").await.unwrap();
        assert_eq!(
            cancelled, 2,
            "retry after teardown must cancel both active builds"
        );
        let acl: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM product_acl")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(acl, 0, "successful retry must remove the ACL row");
    }
}
