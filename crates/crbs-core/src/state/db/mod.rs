// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 数据库方言抽象（SQLite / PostgreSQL）。

/// SQL 方言枚举，用于逐站选择兼容的 SQL 语句（BEGIN IMMEDIATE 等）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Sqlite,
    #[cfg(feature = "postgres")]
    Postgres,
}

impl Dialect {
    /// 根据数据库 URL 方案自动检测方言。
    pub fn from_url(url: &str) -> crate::Result<Self> {
        if url.starts_with("sqlite:") {
            Ok(Dialect::Sqlite)
        } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            #[cfg(feature = "postgres")]
            {
                Ok(Dialect::Postgres)
            }
            #[cfg(not(feature = "postgres"))]
            {
                Err(crate::error::CrbsError::Database(
                    "postgres support not compiled in; rebuild with --features postgres"
                        .to_string(),
                ))
            }
        } else {
            Err(crate::error::CrbsError::Database(format!(
                "unknown database scheme: {}; expected 'sqlite:' or 'postgres:'",
                url.split(':').next().unwrap_or("")
            )))
        }
    }

    /// 返回写事务开启语句（SQLite 需要 BEGIN IMMEDIATE 避免升级死锁）。
    pub fn begin_write(self) -> &'static str {
        match self {
            Dialect::Sqlite => "BEGIN IMMEDIATE",
            #[cfg(feature = "postgres")]
            Dialect::Postgres => "BEGIN",
        }
    }

    /// 是否 PostgreSQL 方言；`postgres` feature 未编译时恒 false。
    pub fn is_postgres(self) -> bool {
        #[cfg(feature = "postgres")]
        {
            matches!(self, Dialect::Postgres)
        }
        #[cfg(not(feature = "postgres"))]
        {
            false
        }
    }

    /// 当前时间 SQL（TEXT 格式，与 SQLite `datetime('now')` 一致）；PG 侧统一
    /// `AT TIME ZONE 'UTC'`——裸 `NOW()` 按会话时区渲染，与 SQLite / Rust 侧
    /// （写入与解析均按 UTC，见 util.rs）混用会歪曲 staleness 计算，各时间辅助函数同此帧约束。
    pub fn sql_now(self) -> &'static str {
        match self {
            Dialect::Sqlite => "datetime('now')",
            #[cfg(feature = "postgres")]
            Dialect::Postgres => "to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')",
        }
    }

    /// 浮点参数的 SQL 侧 CAST（`$N` TEXT 绑定 → 浮点列赋值，Rust 侧 `Option<f64>`
    /// 转字符串绑定）：SQLite `CAST($N AS REAL)`、PG `CAST($N AS DOUBLE PRECISION)`。
    /// TEXT 绑定规避 sqlx `Any` 驱动 NULL 浮点的 Real/Double 映射互换（`convert_to`）：
    /// `Option<f64>` 直绑时，首个带 NULL 的语句把参数钉在 FLOAT4，后续 `Some(f64)`
    /// 的 8 字节 binary 触发 PG "incorrect binary data format"；TEXT 双方言无歧义、
    /// NULL 语义不变，无损还原。
    pub fn float_param_cast(self, param: usize) -> String {
        match self {
            Dialect::Sqlite => format!("CAST(${param} AS REAL)"),
            #[cfg(feature = "postgres")]
            Dialect::Postgres => format!("CAST(${param} AS DOUBLE PRECISION)"),
        }
    }

    /// 返回 N 天前的时间 SQL（统一 TEXT 格式，与 SQLite datetime 格式一致）。
    pub fn sql_days_ago(self, days: i64) -> String {
        match self {
            Dialect::Sqlite => format!("datetime('now', '-{} days')", days),
            #[cfg(feature = "postgres")]
            Dialect::Postgres => pg_utc_offset_text('-', &days.to_string(), "days"),
        }
    }

    /// 返回 N 分钟前的时间 SQL（统一 TEXT 格式）。
    pub fn sql_minutes_ago(self, minutes: i64) -> String {
        match self {
            Dialect::Sqlite => format!("datetime('now', '-{} minutes')", minutes),
            #[cfg(feature = "postgres")]
            Dialect::Postgres => pg_utc_offset_text('-', &minutes.to_string(), "minutes"),
        }
    }

    /// 返回 N 秒前的时间 SQL（统一 TEXT 格式，秒级窗口的谓词用）。
    pub fn sql_seconds_ago(self, secs: i64) -> String {
        match self {
            Dialect::Sqlite => format!("datetime('now', '-{} seconds')", secs),
            #[cfg(feature = "postgres")]
            Dialect::Postgres => pg_utc_offset_text('-', &secs.to_string(), "seconds"),
        }
    }

    /// 两时间差秒数的 SQL 表达式。PG 两侧必须 naive timestamp：`to_timestamp`
    /// 返回 timestamptz（按会话时区解释文本），与 naive `NOW() AT TIME ZONE 'UTC'`
    /// 相减被隐式转回会话时区——TZ=+8 时 duration 偏 8h；`{col}::timestamp` 按
    /// naive 解析 UTC 墙钟。`ROUND(EXTRACT(...))` 依赖 EXTRACT 返回 numeric：
    /// PG ≥ 14（更早返回 float8、无 round(float8)）；测试矩阵 postgres:16，≤13 改 `EXTRACT(...)::numeric`。
    pub fn sql_seconds_since(self, col: &str) -> String {
        match self {
            Dialect::Sqlite => format!(
                "ROUND((julianday(datetime('now')) - julianday({})) * 86400)",
                col
            ),
            #[cfg(feature = "postgres")]
            Dialect::Postgres => format!(
                "ROUND(EXTRACT(EPOCH FROM ((NOW() AT TIME ZONE 'UTC') - {}::timestamp)))",
                col
            ),
        }
    }

    /// 按优先级+等待时间排序：权重 = priority * 86400 + 等待秒数，越高越先。
    /// PG 侧 `started_at::timestamp` naive 解析与 UTC naive 同帧；不用
    /// to_timestamp（按会话时区解释文本，见 `sql_seconds_since`）。
    pub fn sql_priority_wait_weight(self) -> &'static str {
        match self {
            Dialect::Sqlite => {
                "(priority * 86400 + ROUND((julianday('now') - julianday(started_at)) * 86400)) DESC"
            }
            #[cfg(feature = "postgres")]
            Dialect::Postgres => {
                "(priority * 86400 + ROUND(EXTRACT(EPOCH FROM ((NOW() AT TIME ZONE 'UTC') - started_at::timestamp)))) DESC"
            }
        }
    }

    /// CSV 集合的成员判定（领取谓词用）：`col` 为逗号分隔架构集（host_arches），
    /// 判定参数 `$param` 是否为其成员。SQLite `instr` 字面包含（无 LIKE 通配符
    /// 歧义，','|| 防前缀误配）；PG `= ANY(string_to_array(...))` 精确成员。
    /// 成员值恒经 validate_arch（[A-Za-z0-9_]，排除逗号），无注入面。
    pub fn sql_csv_contains(self, col: &str, param: usize) -> String {
        match self {
            Dialect::Sqlite => {
                format!("instr(',' || {col} || ',', ',' || ${param} || ',') > 0")
            }
            #[cfg(feature = "postgres")]
            Dialect::Postgres => format!("${param} = ANY(string_to_array({col}, ','))"),
        }
    }

    /// NULL 感知的 "不等于" 表达式：SQLite `IS NOT` / PG `IS DISTINCT FROM`。
    pub fn sql_is_distinct_from(self, lhs: &str, rhs: &str) -> String {
        match self {
            Dialect::Sqlite => format!("{} IS NOT {}", lhs, rhs),
            #[cfg(feature = "postgres")]
            Dialect::Postgres => format!("{} IS DISTINCT FROM {}", lhs, rhs),
        }
    }
}

/// PG 相对当前时间的 UTC 墙钟 TEXT 渲染单源模板：生产 `sql_days_ago` /
/// `sql_minutes_ago` 与测试基建 sql_time_offset 共用，保证两侧渲染同步。
/// 强制 `(NOW() AT TIME ZONE 'UTC')` 帧（帧约束见 [`Dialect::sql_now`]）；
/// `sign` 取 '-' / '+'（PG interval 字面量接受前导符号）。
#[cfg(feature = "postgres")]
pub(crate) fn pg_utc_offset_text(sign: char, amount: &str, unit: &str) -> String {
    format!(
        "to_char((NOW() AT TIME ZONE 'UTC') {sign} INTERVAL '{amount} {unit}', 'YYYY-MM-DD HH24:MI:SS')"
    )
}

/// 单语句绑定参数上限：SQLite（≥3.32）默认 32766、PG 扩展协议 UInt16 上限
/// 65535，取 30000 双侧留量。start 计入既有绑定（既有数 = start-1），错误条件
/// IN 列表 count 上限 MAX-start（start=1 时 29999），总绑定数可恰达 MAX
///（自测 in_placeholders_accepts_at_limit 放行 total=30000），仍双侧安全。
pub(crate) const MAX_BIND_PARAMS: usize = 30_000;

/// 动态 IN(...) 的 $N 占位符串，编号从 start（既有 binds 数量 + 1）起；超限报 ValidationFailed。
pub(crate) fn in_placeholders(start: usize, count: usize) -> crate::Result<String> {
    let total = start + count;
    if total > MAX_BIND_PARAMS {
        return Err(crate::error::CrbsError::ValidationFailed {
            message: format!(
                "IN list too long: {} bind params exceed max {}",
                total, MAX_BIND_PARAMS
            ),
        });
    }
    Ok((start..start + count)
        .map(|i| format!("${i}"))
        .collect::<Vec<_>>()
        .join(","))
}

/// 动态行值 IN 的 $N 占位符串（二元组）：`(($1,$2),($3,$4),…)`，编号从 start 起。
/// 行值表达式 SQLite 3.15+ / PG 通用（可吃 (product,pkg) 前缀索引）；占位符
/// 手动 $N 编号（QueryBuilder<Any> 生成 `?`，PG 语法错——users.rs 同论证）。
pub(crate) fn row_value_in_placeholders(start: usize, tuple_count: usize) -> crate::Result<String> {
    let total = start + tuple_count * 2;
    if total > MAX_BIND_PARAMS {
        return Err(crate::error::CrbsError::ValidationFailed {
            message: format!(
                "row-value IN list too long: {} bind params exceed max {}",
                total, MAX_BIND_PARAMS
            ),
        });
    }
    let mut idx = start;
    let tuples: Vec<String> = (0..tuple_count)
        .map(|_| {
            let s = format!("(${},${})", idx, idx + 1);
            idx += 2;
            s
        })
        .collect();
    Ok(format!("({})", tuples.join(",")))
}

/// 动态行值 IN 的 $N 占位符串（三元组）：`(($1,$2,$3),($4,$5,$6),…)`，编号从
/// start 起。(product, source_name, arch) 画像键批量回源专用；预算与错误口径同
/// [`row_value_in_placeholders`]。
pub(crate) fn row_value_in_placeholders3(
    start: usize,
    tuple_count: usize,
) -> crate::Result<String> {
    let total = start + tuple_count * 3;
    if total > MAX_BIND_PARAMS {
        return Err(crate::error::CrbsError::ValidationFailed {
            message: format!(
                "row-value IN list too long: {} bind params exceed max {}",
                total, MAX_BIND_PARAMS
            ),
        });
    }
    let mut idx = start;
    let tuples: Vec<String> = (0..tuple_count)
        .map(|_| {
            let s = format!("(${},${},${})", idx, idx + 1, idx + 2);
            idx += 3;
            s
        })
        .collect();
    Ok(format!("({})", tuples.join(",")))
}

/// 分页 SQL 子句：占位符编号从 `base_idx` 起（基于既有 binds 数量）。
/// 方言差异：PG 拒绝 `LIMIT -1`，offset-only 必须整个省略 LIMIT（裸 `OFFSET $n`
/// 合法）；SQLite 需 `LIMIT -1` 显式表示"无上限"。契约：`(None, None)` = 有意
/// 全量（内部调用方合法形态），勿在此强插 LIMIT；面向用户输入的列表入口必须
/// 上游过 `validate_list_pagination`（`MAX_LIST_LIMIT`），新增公开查询函数照此办。
pub(crate) fn pagination_clause(
    dialect: Dialect,
    limit: Option<usize>,
    offset: Option<usize>,
    base_idx: usize,
) -> String {
    match (limit, offset) {
        (Some(_), Some(_)) => format!(" LIMIT ${base_idx} OFFSET ${}", base_idx + 1),
        (Some(_), None) => format!(" LIMIT ${base_idx}"),
        (None, Some(_)) => match dialect {
            Dialect::Sqlite => format!(" LIMIT -1 OFFSET ${base_idx}"),
            #[cfg(feature = "postgres")]
            Dialect::Postgres => format!(" OFFSET ${base_idx}"),
        },
        (None, None) => String::new(),
    }
}

/// 追加一个过滤条件：占位符编号自动取当前 binds 长度 + 1。
pub(crate) fn push_filter(
    parts: &mut Vec<String>,
    binds: &mut Vec<String>,
    cond: &str,
    value: String,
) {
    let idx = binds.len() + 1;
    parts.push(cond.replace("$N", &format!("${}", idx)));
    binds.push(value);
}

/// 追加一个 ` AND {frag} {op} ${N}` 过滤片段（users / workers / audit 的 list+count
/// 过滤构造共用；片段自带 AND 前缀，调用方 parts.join("") 直接拼接，LIKE-ESCAPE
/// 站点占位符后须跟子句、不适用本函数）。
pub(crate) fn push_eq_and(
    parts: &mut Vec<String>,
    binds: &mut Vec<String>,
    frag: &str,
    op: &str,
    value: String,
) {
    let idx = binds.len() + 1;
    parts.push(format!(" AND {} {} ${}", frag, op, idx));
    binds.push(value);
}

/// 列表 limit 归一化：<=0 取默认 100，上限 1000（UserFilter / AuditLogFilter /
/// WorkerFilter 的 normalized_limit 共用）。
pub(crate) fn clamp_list_limit(limit: i64) -> i64 {
    if limit <= 0 {
        100
    } else {
        limit.min(1000)
    }
}

/// 转义 LIKE 特殊字符 `\` `%` `_`（前插反斜杠），其余字符（含多字节）原样透传；
/// 须配 SQL 侧 `ESCAPE '\'` 子句生效（SQLite LIKE 默认无转义符，必须显式声明；
/// PG 显式声明后与默认一致）。用户输入直接拼 LIKE 模式时 `%`/`_` 被当通配符
/// （搜 "100%" 会命中 "100x"），`\` 自身也须转义否则 `\%` 会还原成通配符。
/// 所有把用户输入拼进 LIKE 模式的站点必须先过本函数，新增站点同样收口到这里。
pub(crate) fn escape_like(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// 构建列表查询的公共过滤器（product / user / phase / pkg_name 前缀），
/// builds 与 tasks 的列表查询共用；差异项（arch / 源码包名）由调用方追加。
pub(crate) fn push_common_filters(
    parts: &mut Vec<String>,
    binds: &mut Vec<String>,
    product: Option<&str>,
    user: Option<&str>,
    phase: Option<&str>,
    name: Option<&str>,
) {
    if let Some(product) = product.filter(|v| !v.is_empty()) {
        push_filter(parts, binds, "product = $N", product.to_string());
    }
    if let Some(user) = user {
        push_filter(
            parts,
            binds,
            "(\"user\" = $N OR \"user\" = '')",
            user.to_string(),
        );
    }
    if let Some(phase) = phase.filter(|v| !v.is_empty()) {
        push_filter(parts, binds, "phase = $N", phase.to_string());
    }
    // Package 框按 pkg_name 前缀匹配，兼容粘贴完整包名（含版本/ release）。
    if let Some(name) = name.filter(|v| !v.is_empty()) {
        push_filter(
            parts,
            binds,
            "pkg_name LIKE $N ESCAPE '\\'",
            format!("{}%", escape_like(name)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagination_clause_offset_only_is_dialect_aware() {
        #[cfg(feature = "postgres")]
        assert_eq!(
            pagination_clause(Dialect::Postgres, None, Some(3), 7),
            " OFFSET $7"
        );
        assert_eq!(
            pagination_clause(Dialect::Sqlite, None, Some(3), 7),
            " LIMIT -1 OFFSET $7"
        );
    }

    #[test]
    fn pagination_clause_limit_variants_shared() {
        assert_eq!(
            pagination_clause(Dialect::Sqlite, Some(10), Some(20), 1),
            " LIMIT $1 OFFSET $2"
        );
        #[cfg(feature = "postgres")]
        assert_eq!(
            pagination_clause(Dialect::Postgres, Some(10), None, 2),
            " LIMIT $2"
        );
        assert_eq!(pagination_clause(Dialect::Sqlite, None, None, 1), "");
    }

    #[test]
    fn in_placeholders_numbers_from_start() {
        assert_eq!(in_placeholders(2, 3).unwrap(), "$2,$3,$4");
        assert_eq!(in_placeholders(1, 1).unwrap(), "$1");
    }

    #[test]
    fn in_placeholders_rejects_over_limit() {
        let err = in_placeholders(1, MAX_BIND_PARAMS).unwrap_err();
        match err {
            crate::error::CrbsError::ValidationFailed { message } => {
                assert!(message.contains("exceed"), "message: {message}");
                assert!(message.contains("30001"), "message: {message}");
            }
            other => panic!("expected ValidationFailed, got {other:?}"),
        }
    }

    #[test]
    fn in_placeholders_accepts_at_limit() {
        // start + count == MAX_BIND_PARAMS 恰好不超限（1 + 29999 = 30000）。
        assert!(in_placeholders(1, MAX_BIND_PARAMS - 1).is_ok());
    }

    /// PG 相对时间串回归：精确文本锚定 pg_utc_offset_text 模板（UTC 帧约束见
    /// sql_now 文档），防 sign/unit 实参翻转在无 PG 库的默认测试下静默漂移。
    #[test]
    #[cfg(feature = "postgres")]
    fn sql_relative_time_pg_output_is_pinned() {
        assert_eq!(
            Dialect::Postgres.sql_days_ago(10),
            "to_char((NOW() AT TIME ZONE 'UTC') - INTERVAL '10 days', 'YYYY-MM-DD HH24:MI:SS')"
        );
        assert_eq!(
            Dialect::Postgres.sql_minutes_ago(5),
            "to_char((NOW() AT TIME ZONE 'UTC') - INTERVAL '5 minutes', 'YYYY-MM-DD HH24:MI:SS')"
        );
    }

    #[test]
    fn escape_like_escapes_wildcards_and_backslash() {
        assert_eq!(escape_like("100%"), "100\\%");
        assert_eq!(escape_like("a_b"), "a\\_b");
        assert_eq!(escape_like("a\\b"), "a\\\\b");
    }

    #[test]
    fn escape_like_passthrough_plain_and_multibyte() {
        assert_eq!(escape_like("plain-Name_9"), "plain-Name\\_9");
        assert_eq!(escape_like("内核 kernel"), "内核 kernel");
        assert_eq!(escape_like("a\u{1F600}b"), "a\u{1F600}b");
        assert_eq!(escape_like(""), "");
    }

    #[test]
    fn escape_like_mixed_input() {
        assert_eq!(escape_like("100%_\\内核"), "100\\%\\_\\\\内核");
        // 连续通配符逐个转义，不合并。
        assert_eq!(escape_like("%%"), "\\%\\%");
    }
}
