// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 审计日志统一入口：`StateStore::audit_log` 写入 + 过滤分页查询。

use super::StateStore;
use crate::error::{CrbsError, DbResultExt};

mod sql {
    use crate::state::Dialect;

    /// 插入审计日志（方言感知时间）。
    pub(super) fn insert_audit_log(dialect: Dialect) -> String {
        format!(
            "INSERT INTO audit_logs (\"user\", role, action, target, detail, created_at) \
             VALUES ($1, $2, $3, $4, $5, {})",
            dialect.sql_now()
        )
    }

    /// 列表查询前缀（WHERE 1=1，调用方追加过滤条件、ORDER BY、LIMIT/OFFSET）。
    /// `AS "user"`：USER 是 PG 保留字，裸别名 PG 语法错（双方言双引号别名均合法）。
    pub(super) const LIST_AUDIT_LOGS_PREFIX: &str =
        "SELECT id, \"user\" AS \"user\", role, action, target, detail, created_at FROM audit_logs WHERE 1=1";

    /// 计数查询前缀（同上，仅追加过滤条件）。
    pub(super) const COUNT_AUDIT_LOGS_PREFIX: &str = "SELECT COUNT(*) FROM audit_logs WHERE 1=1";
}

/// 单条审计日志记录。
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditLog {
    pub id: i64,
    pub user: String,
    pub role: String,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
    pub created_at: String,
}

/// 审计日志查询过滤条件：`user`/`role`/`action`/`target` 精确匹配，
/// `since`/`until` 含端点（RFC3339，经 normalize_time_filter 规整）。
#[derive(Debug, Default)]
pub struct AuditLogFilter<'a> {
    pub user: Option<&'a str>,
    pub role: Option<&'a str>,
    pub action: Option<&'a str>,
    pub target: Option<&'a str>,
    pub since: Option<&'a str>,
    pub until: Option<&'a str>,
    pub limit: i64,
    pub offset: i64,
}

impl AuditLogFilter<'_> {
    /// 返回合理的 limit（默认 100，最大 1000）。
    pub fn normalized_limit(&self) -> i64 {
        super::db::clamp_list_limit(self.limit)
    }
}

#[derive(sqlx::FromRow)]
struct AuditLogRow {
    id: i64,
    user: String,
    role: String,
    action: String,
    target: Option<String>,
    detail: Option<String>,
    created_at: String,
}

impl From<AuditLogRow> for AuditLog {
    fn from(r: AuditLogRow) -> Self {
        Self {
            id: r.id,
            user: r.user,
            role: r.role,
            action: r.action,
            target: r.target,
            detail: r.detail,
            created_at: r.created_at,
        }
    }
}

/// 过滤条件追加为 WHERE 片段与 `$N` 绑定（list/count 共用，保证条件与 bind
/// 顺序一致）。不用 QueryBuilder<Any>：其 `?` 占位符（SQLite 风格）PG 语法错。
fn push_audit_filter(
    parts: &mut Vec<String>,
    binds: &mut Vec<String>,
    filter: &AuditLogFilter<'_>,
) -> crate::Result<()> {
    if let Some(v) = filter.user {
        crate::state::db::push_eq_and(parts, binds, "\"user\"", "=", v.to_string());
    }
    if let Some(v) = filter.role {
        crate::state::db::push_eq_and(parts, binds, "role", "=", v.to_string());
    }
    if let Some(v) = filter.action {
        crate::state::db::push_eq_and(parts, binds, "action", "=", v.to_string());
    }
    if let Some(v) = filter.target {
        crate::state::db::push_eq_and(parts, binds, "target", "=", v.to_string());
    }
    if let Some(v) = filter.since {
        crate::state::db::push_eq_and(
            parts,
            binds,
            "created_at",
            ">=",
            normalize_time_filter(v, false)?,
        );
    }
    if let Some(v) = filter.until {
        crate::state::db::push_eq_and(
            parts,
            binds,
            "created_at",
            "<=",
            normalize_time_filter(v, true)?,
        );
    }
    Ok(())
}

/// 把过滤输入规整为与存储相同的 `YYYY-MM-DD HH:MM:SS` 词法可比形态
///（存储列 TEXT，sql_now 写 UTC 墙钟）。RFC3339（含偏移/Z）→ 绝对时刻换算
/// UTC 墙钟；无偏移（`T`/空格分隔）→ 按 UTC 解析并规整为空格分隔
///（`'T'`(0x54) > `' '`(0x20)，原样比较错位）；纯日期 → 上界补
/// `23:59:59`、下界保留日期前缀（词法即时间序；上界不补会漏掉当天全部
/// 非零点行）。无法解析返回 Validation 错误（调用方 400）。
fn normalize_time_filter(v: &str, upper_bound: bool) -> crate::Result<String> {
    const STORAGE_FMT: &str = crate::util::DB_TIME_FMT;
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(v) {
        return Ok(dt.naive_utc().format(STORAGE_FMT).to_string());
    }
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(v, fmt) {
            return Ok(naive.format(STORAGE_FMT).to_string());
        }
    }
    if v.len() == 10
        && v.as_bytes().iter().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                *b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
    {
        return Ok(if upper_bound {
            format!("{v} 23:59:59")
        } else {
            v.to_string()
        });
    }
    Err(CrbsError::ValidationFailed {
        message: format!(
            "invalid time filter {v:?}: expected RFC3339, 'YYYY-MM-DD HH:MM:SS', or 'YYYY-MM-DD' (UTC)"
        ),
    })
}

impl StateStore {
    /// 记录一条审计日志；`action` 为操作类型词汇（如 `create_user`、
    /// `revoke_user_token`），`target` 为可选操作对象，`detail` 为可选 JSON。
    pub async fn audit_log(
        &self,
        actor: &str,
        role: &str,
        action: &str,
        target: Option<&str>,
        detail: Option<&str>,
    ) -> crate::Result<()> {
        sqlx::query(&sql::insert_audit_log(self.dialect))
            .bind(actor)
            .bind(role)
            .bind(action)
            .bind(target)
            .bind(detail)
            .execute(self.pool())
            .await
            .db_ctx("insert audit log")?;
        Ok(())
    }

    /// 按过滤条件查询审计日志。
    pub async fn list_audit_logs(
        &self,
        filter: AuditLogFilter<'_>,
    ) -> crate::Result<Vec<AuditLog>> {
        let mut parts = Vec::new();
        let mut binds = Vec::new();
        push_audit_filter(&mut parts, &mut binds, &filter)?;
        // limit/offset 已归一化 i64，字面量拼接无注入面；避开 sqlx Any 下
        // "参数 + 表达式混合" 的 Bind 协议坑。
        let sql_text = format!(
            "{}{} ORDER BY id DESC LIMIT {} OFFSET {}",
            sql::LIST_AUDIT_LOGS_PREFIX,
            parts.join(""),
            filter.normalized_limit(),
            filter.offset.max(0),
        );

        let mut q = sqlx::query_as::<_, AuditLogRow>(&sql_text);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        q.fetch_all(self.pool())
            .await
            .db_ctx("list audit logs")
            .map(|rows| rows.into_iter().map(|r| r.into()).collect())
    }

    /// 按相同过滤条件统计审计日志总数。
    pub async fn count_audit_logs(&self, filter: AuditLogFilter<'_>) -> crate::Result<i64> {
        let mut parts = Vec::new();
        let mut binds = Vec::new();
        push_audit_filter(&mut parts, &mut binds, &filter)?;
        let sql_text = format!("{}{}", sql::COUNT_AUDIT_LOGS_PREFIX, parts.join(""));

        let mut q = sqlx::query_scalar::<_, i64>(&sql_text);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        q.fetch_one(self.pool()).await.db_ctx("count audit logs")
    }
}

#[cfg(test)]
mod tests {
    use super::{push_audit_filter, AuditLogFilter, StateStore};

    /// 锁定过滤 SQL 形态（纯文本，不执行）：占位符必须 `$N` 编号（PG 兼容）。
    #[test]
    fn audit_list_query_uses_numbered_placeholders() {
        let filter = AuditLogFilter {
            user: Some("admin"),
            action: Some("user.create"),
            limit: 50,
            offset: 0,
            ..Default::default()
        };
        let mut parts = Vec::new();
        let mut binds = Vec::new();
        push_audit_filter(&mut parts, &mut binds, &filter).unwrap();
        let sql = format!(
            "{}{} ORDER BY id DESC LIMIT {} OFFSET {}",
            super::sql::LIST_AUDIT_LOGS_PREFIX,
            parts.join(""),
            filter.normalized_limit(),
            filter.offset.max(0),
        );
        assert!(!sql.contains('?'), "must use $N placeholders, got: {sql}");
        assert!(
            sql.contains("AS \"user\""),
            "reserved-word alias must be quoted"
        );
        assert!(sql.contains("$1") && sql.contains("$2"));
        assert_eq!(binds, vec!["admin".to_string(), "user.create".to_string()]);
    }

    #[tokio::test]
    async fn audit_log_writes_record() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();

        store
            .audit_log(
                "admin",
                "admin",
                "test_action",
                Some("target-1"),
                Some(r#"{"k":"v"}"#),
            )
            .await
            .unwrap();

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE action = $1 AND target = $2")
                .bind("test_action")
                .bind("target-1")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn list_audit_logs_filters() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();

        store
            .audit_log("admin", "admin", "create_user", Some("1"), None)
            .await
            .unwrap();
        store
            .audit_log("operator", "operator", "create_user", Some("2"), None)
            .await
            .unwrap();
        store
            .audit_log("admin", "admin", "grant_product_acl", Some("foo"), None)
            .await
            .unwrap();

        let all = store
            .list_audit_logs(AuditLogFilter {
                limit: 10,
                offset: 0,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(all.len(), 3);

        let admin_only = store
            .list_audit_logs(AuditLogFilter {
                user: Some("admin"),
                limit: 10,
                offset: 0,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(admin_only.len(), 2);
        assert!(admin_only.iter().all(|l| l.user == "admin"));

        let create_user = store
            .list_audit_logs(AuditLogFilter {
                action: Some("create_user"),
                limit: 10,
                offset: 0,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(create_user.len(), 2);

        let count = store
            .count_audit_logs(AuditLogFilter {
                action: Some("create_user"),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(count, 2);
    }
}

#[cfg(test)]
mod time_filter_tests {
    use super::normalize_time_filter;

    #[test]
    fn normalizes_rfc3339_to_storage_format() {
        assert_eq!(
            normalize_time_filter("2026-08-24T00:00:00Z", false).unwrap(),
            "2026-08-24 00:00:00"
        );
    }

    /// 回归：时区偏移输入须换算 UTC 墙钟（+08:00 的 `23:59:59` = UTC `15:59:59`）。
    #[test]
    fn converts_tz_offset_to_utc_wall_clock() {
        assert_eq!(
            normalize_time_filter("2026-08-24T23:59:59+08:00", false).unwrap(),
            "2026-08-24 15:59:59"
        );
        assert_eq!(
            normalize_time_filter("2026-08-25T04:00:00-05:00", false).unwrap(),
            "2026-08-25 09:00:00"
        );
    }

    /// 无偏移形态按 UTC 解析；`T`/空格两种分隔都规整为存储格式。
    #[test]
    fn parses_offsetless_forms_as_utc() {
        assert_eq!(
            normalize_time_filter("2026-08-24 00:00:00", false).unwrap(),
            "2026-08-24 00:00:00"
        );
        assert_eq!(
            normalize_time_filter("2026-08-24T12:34:56", false).unwrap(),
            "2026-08-24 12:34:56"
        );
    }

    /// 纯日期：下界保留前缀（词法即时间序）；上界补 23:59:59 覆盖当天全部行。
    #[test]
    fn passes_date_only_through() {
        assert_eq!(
            normalize_time_filter("2026-08-24", false).unwrap(),
            "2026-08-24"
        );
        assert_eq!(
            normalize_time_filter("2026-08-24", true).unwrap(),
            "2026-08-24 23:59:59"
        );
    }

    /// 垃圾输入：Validation 错误（调用方 400）。
    #[test]
    fn rejects_garbage_input() {
        assert!(normalize_time_filter("yesterday", false).is_err());
        assert!(normalize_time_filter("2026-13-99 99:99:99", false).is_err());
        assert!(normalize_time_filter("", false).is_err());
    }
}
