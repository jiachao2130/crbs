// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 工作区中央错误类型：域错误聚合进 [`CrbsError`]，附共享 `Result` 别名与 DB 错误上下文 helper。

use std::io;

/// CRBS 工作区中央错误类型。
#[derive(Debug, Clone, thiserror::Error)]
pub enum CrbsError {
    /// depsolve 失败。双语义（有意，勿"统一"）：HTTP 侧"请求的包集无法解析"
    /// → server 映射 400 validation_failed（用户可修正请求）；CLI/worker 侧
    /// "构建过程失败" → exit 2 BUILD_FAILED（不盲目重试）。
    #[error("depsolve failed: {message}")]
    DepsolveFailed { message: String },
    /// reserved：生产零构造点（仅 exit_code 测试引用），server 映射为防御臂；待首个消费者落地回填。
    #[error("layer creation failed: {message}")]
    LayerCreateFailed { message: String },
    /// 共享层缓存未命中（按 digest 查无记录）→ HTTP 404 not_found、exit 2 BUILD_FAILED；
    /// 与通用 [`CrbsError::NotFound`] 区分，本变体专指共享层。
    #[error("shared layer not found: {digest}")]
    LayerNotFound { digest: String },
    /// 容器内命令失败：非零退出或被信号终止（二者互斥，signal 有值时 exit_code 为
    /// None）；stderr 本地路径为固定判语（输出已直通终端）、远端路径为 hub 消息
    /// → exit 2 BUILD_FAILED；server 无构造点，映射为防御臂。
    #[error("container exec failed: exit={exit_code:?}, signal={signal:?}, stderr={stderr}")]
    ContainerExecFailed {
        exit_code: Option<i32>,
        signal: Option<i32>,
        stderr: String,
    },
    /// 构建步骤超时（worker per-attempt 预算耗尽、rpmsign 超时等）→ exit 3 INTERRUPTED
    ///（调度器：超时可重试）；server 无构造点，映射为防御臂 504；is_transient=true。
    #[error("build timeout")]
    Timeout,
    /// RPM 签名失败（rpmsign --addsign 非零退出，message 含 key id、退出状态与
    /// stderr 尾部）→ exit 2 BUILD_FAILED；server 无构造点，映射为防御臂。
    #[error("sign failed: {message}")]
    SignFailed { message: String },
    /// 构建被取消（CancellationToken 触发：Ctrl-C、`crbs cancel`、worker 收到取消令）
    /// → exit 3 INTERRUPTED（取消不重试）；server 无构造点，映射为防御臂 409。
    #[error("build cancelled")]
    Cancelled,
    /// 权限不足：非 crbs 组成员、helper 拒绝特权操作、hub 401/403 等 → HTTP 403
    /// permission_denied、exit 5 PERMISSION（不重试，需修正组员身份或凭据）。
    #[error("permission denied: {message}")]
    PermissionDenied { message: String },
    /// 复现校验失败（重建产物与原构建不一致）→ HTTP 400 validation_failed、exit 2
    /// BUILD_FAILED；生产零构造点，映射臂已就位待首个消费方落地回填。
    #[error("reproduce verification failed: {message}")]
    ReproduceVerificationFailed { message: String },
    /// 请求/配置校验失败（参数不合法、build_options 反序列化失败等用户可修正错误）
    /// → HTTP 400 validation_failed、exit 4 USAGE（修正后重提交，不自动重试）。
    #[error("validation failed: {message}")]
    ValidationFailed { message: String },
    /// 资源不存在（task/build/product 等按 id 查无记录）→ HTTP 404 not_found、exit 4
    /// USAGE；与 [`CrbsError::LayerNotFound`] 区分：后者专指共享层缓存。
    #[error("not found: {message}")]
    NotFound { message: String },
    /// 出口校验失败（`base_packages`/`repos` 为空、`+repos` 致 repo `name` 冲突等）；
    /// `product` 为 leaf slug，`reason` 含具体违规与来源层 slug 便于排查。
    #[error("product chain invalid: {product}: {reason}")]
    ProductChainInvalid { product: String, reason: String },
    /// 产品链存在环：`chain` 按 walk 顺序（root→leaf）列出，末项与前面某项重复即
    /// 环点；写路径 `validate_parent_id` + 读路径 `walk_chain` visited-set 双保险。
    #[error("product chain cycle: {chain:?}")]
    ProductChainCycle { chain: Vec<String> },
    /// 产品链层数超过 `MAX_CHAIN_DEPTH`；写路径拒建，读路径 `walk_chain` 兜底防 DoS。
    #[error("product chain too deep: max {max}")]
    ProductChainTooDeep { max: usize },
    /// 乐观锁失败：revision 与 DB 当前值不一致 → HTTP 409 Conflict；客户端应
    /// 重读当前状态、修正请求后重提交（退出码 USAGE=4），而非盲目重试同一请求。
    #[error("revision conflict: expected {expected}, current {current}")]
    RevisionConflict { expected: i64, current: i64 },
    /// 资源已存在（UNIQUE 约束冲突等）→ HTTP 409 Conflict。
    #[error("already exists: {message}")]
    AlreadyExists { message: String },
    /// 状态机冲突：前置状态不满足（如给非 pending 的 build 分配 worker）→ HTTP 409 Conflict。
    #[error("conflict: {message}")]
    Conflict { message: String },
    /// 删除受限：资源有未清理引用（子产品、构建记录等）→ HTTP 409 Conflict。
    #[error("delete restricted: {message}")]
    DeleteRestricted { message: String },
    /// `context` 为失败操作（无上下文时 "io error"），`detail` 为原始错误文本；
    /// 分类前缀由 `code()`/`safe_message()` 表达，Display 不叠加避免重复前缀。
    #[error("{context}: {detail}")]
    Io {
        context: String,
        kind: io::ErrorKind,
        /// 原始错误文本（非 `std::error::Error`，故不命名为 `source`）。
        detail: String,
    },
    /// 网络/下载失败（[`CrbsError::from_io_context`] 将网络类 `io::ErrorKind` 归到本
    /// 变体）→ HTTP 503 service_unavailable（响应走 safe_message 固定文案）、exit 6
    /// ENVIRONMENT；is_transient=true 可自动重试。
    #[error("network error: {message}")]
    Network { message: String },
    /// SQL 语义错误（`db_ctx` 包装且非后端不可用）→ HTTP 500，信封 error=database_error、
    /// message 固定 "database error"（脱敏）；exit 6 ENVIRONMENT。与
    /// [`CrbsError::DatabaseUnavailable`] 区分：后者是 503 可重试的可用性故障。
    #[error("database error: {0}")]
    Database(String),
    /// DB 后端不可用（池 acquire 超时/关闭/网络不可达），由 `db_ctx` 按
    /// [`DbErrorClassify::is_backend_unavailable`] 产出。`error` 保留底层 Display
    ///（PoolTimedOut 等，CLI/worker 直消费 Display 路径靠它区分故障形态，对齐
    /// `Database` 形态），两字段均不含连接串等敏感细节；HTTP 503（响应走
    /// `safe_message` 固定文案，Display 变化不影响脱敏）；`is_transient` 为真。
    #[error("database unavailable: {context}: {error}")]
    DatabaseUnavailable { context: String, error: String },
    /// reserved：生产零构造点（仅 exit_code 测试引用），server 映射为防御臂；待首个消费者落地回填。
    #[error("cgroup setup failed: {0}")]
    CgroupSetupFailed(String),
    /// 内部不变量破坏或不可分类错误（预期不发生）→ HTTP 500 internal_error（safe_message
    /// 脱敏为固定文案）、exit 1 INTERNAL（告警人工排查，CLI 提示 "this is a bug"）。
    #[error("internal error: {0}")]
    Internal(String),
    /// CLI 已自行输出结论，main 跳过 "Error:" 行与 hint，以 `code` 原样作为进程退出码
    /// （如 verify 无可比对内容时回 USAGE）。
    #[error("silent exit with code {code}")]
    SilentExit { code: i32 },
}

impl From<std::io::Error> for CrbsError {
    fn from(e: std::io::Error) -> Self {
        Self::Io {
            context: "io error".into(),
            kind: e.kind(),
            detail: e.to_string(),
        }
    }
}

impl CrbsError {
    /// 返回面向最终用户/HTTP 客户端的安全消息：含内部路径/系统调用细节的
    /// `Io`/`Database`/`Internal`/`CgroupSetupFailed` 等只返回分类描述（原始细节
    /// 走服务端结构化日志），业务语义错误（如 `ValidationFailed`）保留原消息。
    pub fn safe_message(&self) -> String {
        match self {
            Self::ValidationFailed { message }
            | Self::ReproduceVerificationFailed { message }
            | Self::DepsolveFailed { message }
            | Self::SignFailed { message }
            | Self::PermissionDenied { message }
            | Self::NotFound { message }
            | Self::AlreadyExists { message }
            | Self::Conflict { message }
            | Self::DeleteRestricted { message }
            | Self::LayerCreateFailed { message } => message.clone(),
            Self::ProductChainInvalid { product, reason } => {
                format!("product chain invalid: {}: {}", product, reason)
            }
            Self::ProductChainCycle { chain } => {
                format!("product chain cycle: {:?}", chain)
            }
            Self::ProductChainTooDeep { max } => {
                format!("product chain too deep: max {}", max)
            }
            Self::LayerNotFound { digest } => format!("shared layer {} not found", digest),
            Self::ContainerExecFailed { .. } => "build command failed".into(),
            Self::Timeout => "build timed out".into(),
            Self::Cancelled => "build cancelled".into(),
            Self::Network { .. } => "network or download failure".into(),
            Self::Io { .. } => "internal I/O error".into(),
            Self::Database(_) => "database error".into(),
            Self::DatabaseUnavailable { .. } => "database unavailable".into(),
            Self::CgroupSetupFailed(_) => "cgroup setup failed".into(),
            Self::Internal(_) => "internal error".into(),
            Self::SilentExit { .. } => "silent exit".into(),
            Self::RevisionConflict { expected, current } => {
                format!(
                    "revision conflict: expected {}, current {}",
                    expected, current
                )
            }
        }
    }

    /// 机器可读错误码（kebab-case，对外契约）：与 variant 名解耦，variant 改名
    /// 不影响返回值（CI 脚本/集群调度器据此分类）；变更需在 CHANGELOG 说明。
    pub fn code(&self) -> &'static str {
        match self {
            Self::DepsolveFailed { .. } => "depsolve_failed",
            Self::LayerCreateFailed { .. } => "layer_create_failed",
            Self::LayerNotFound { .. } => "layer_not_found",
            Self::ContainerExecFailed { .. } => "container_exec_failed",
            Self::Timeout => "timeout",
            Self::SignFailed { .. } => "sign_failed",
            Self::Cancelled => "cancelled",
            Self::PermissionDenied { .. } => "permission_denied",
            Self::ReproduceVerificationFailed { .. } => "reproduce_verification_failed",
            Self::ValidationFailed { .. } => "validation_failed",
            Self::NotFound { .. } => "not_found",
            Self::ProductChainInvalid { .. } => "product_chain_invalid",
            Self::ProductChainCycle { .. } => "product_chain_cycle",
            Self::ProductChainTooDeep { .. } => "product_chain_too_deep",
            Self::RevisionConflict { .. } => "revision_conflict",
            Self::AlreadyExists { .. } => "already_exists",
            Self::Conflict { .. } => "conflict",
            Self::DeleteRestricted { .. } => "delete_restricted",
            Self::Io { .. } => "io_error",
            Self::Network { .. } => "network_error",
            Self::Database(_) => "database_error",
            Self::DatabaseUnavailable { .. } => "database_unavailable",
            Self::CgroupSetupFailed(_) => "cgroup_setup_failed",
            Self::Internal(_) => "internal_error",
            Self::SilentExit { .. } => "silent_exit",
        }
    }

    /// 将 IO 错误按上下文分类为 `Network` 或 `Io`；仅限明确涉及网络/下载的调用点，
    /// 普通文件 IO 仍用 `?` 走 `From` 产生的 `Io`。
    pub fn from_io_context(context: impl Into<String>, e: io::Error) -> Self {
        let context = context.into();
        if is_network_io_kind(e.kind()) {
            Self::Network {
                message: format!("{}: {}", context, e),
            }
        } else {
            Self::Io {
                context,
                kind: e.kind(),
                detail: e.to_string(),
            }
        }
    }

    /// 以自由格式消息构造 `Io` 错误（来源非 `std::io::Error` 但归类为 I/O 时用）。
    pub fn io_message(message: impl Into<String>) -> Self {
        let message = message.into();
        Self::Io {
            context: "io error".into(),
            kind: io::ErrorKind::Other,
            detail: message,
        }
    }

    /// 判断该错误是否属于 transient，可以被自动重试。
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Network { .. } | Self::Timeout | Self::DatabaseUnavailable { .. } => true,
            Self::DepsolveFailed { message } | Self::LayerCreateFailed { message } => {
                looks_like_network_failure(message)
            }
            Self::Io { kind, detail, .. } => {
                is_network_io_kind(*kind) || looks_like_network_failure(detail)
            }
            Self::CgroupSetupFailed(message) => looks_like_network_failure(message),
            _ => false,
        }
    }

    /// 判断该错误是否为 "未找到"（NotFound）。
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::NotFound { .. }
                | Self::Io {
                    kind: std::io::ErrorKind::NotFound,
                    ..
                }
        )
    }
}

/// 判断 `std::io::ErrorKind` 是否为网络/连接类错误。
pub fn is_network_io_kind(kind: io::ErrorKind) -> bool {
    use io::ErrorKind::*;
    matches!(
        kind,
        ConnectionRefused
            | ConnectionReset
            | ConnectionAborted
            | NotConnected
            | TimedOut
            | UnexpectedEof
    )
}

/// 判断一段文本是否含网络/下载失败特征（dnf stderr、build.log 尾部、错误消息分类）。
pub fn looks_like_network_failure(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    let lower = text.to_lowercase();
    // 用短语而非裸词：包名/安装清单里的 curl、wget、"connection" 等裸词不是网络错误。
    let keywords = [
        // curl/wget 裸词出现在 dnf 安装清单里，只匹配错误输出短语前缀。
        "curl error",
        "curl: (",
        "wget: ",
        "connection timed out",
        "connection timeout",
        "timeout was reached",
        "download timeout",
        "connection refused",
        "connection reset",
        "connection aborted",
        "connection failed",
        "failed to connect",
        "could not connect",
        "unable to connect",
        "connect timed out",
        "connect timeout",
        // 不匹配裸词 "timed out"/"time out"——make/gcc 失败行带该字样，误判会无意义重试。
        "network is unreachable",
        "network unreachable",
        "cannot download",
        "failed to download",
        "download failed",
        // dnf5 "Status code: NNN"：5xx 瞬时可重试，4xx（如 404 仓库缺失）永久。
        "status code: 5",
        "tcp connection",
        "reset by peer",
        "broken pipe",
        "no route",
        "temporary failure",
        "name resolution",
        "could not resolve",
        "transfer failed",
        "ssl connection",
        "tls connection",
        // 仓库 HTTP 5xx 以 status-line 文本透出（dnf/curl 原样），判 transient 可重试。
        "503 service unavailable",
        "502 bad gateway",
        "504 gateway timeout",
        "service unavailable",
        "returned error: 5",
    ];
    keywords.iter().any(|kw| lower.contains(kw))
}

/// crate 统一 Result 别名：错误类型固定为 CrbsError。
pub type Result<T> = std::result::Result<T, CrbsError>;

/// `db_ctx` 包装时的错误分类：为真产出 [`CrbsError::DatabaseUnavailable`]
///（HTTP 503、transient 可重试）而非 [`CrbsError::Database`]（HTTP 500）；
/// 默认 false——多数错误（SQL 语义、序列化失败）与后端可用性无关。
pub trait DbErrorClassify {
    /// 该错误是否表示数据库后端不可用（连接池超时/关闭、网络不可达）。
    fn is_backend_unavailable(&self) -> bool {
        false
    }
}

impl DbErrorClassify for sqlx::Error {
    fn is_backend_unavailable(&self) -> bool {
        match self {
            sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::WorkerCrashed => {
                true
            }
            sqlx::Error::Io(e) => is_network_io_kind(e.kind()),
            // 裸 Display 文本判定（sqlx Any 不暴露结构化错误码）：SQLite 存储
            // 侧故障与 PG 资源枯竭文案。
            _ => {
                let msg = self.to_string();
                is_sqlite_storage_failure(&msg) || is_db_resource_exhausted(&msg)
            }
        }
    }
}

/// SQLite 存储侧故障特征（大小写不敏感）：三条依次为 SQLITE_FULL（13）、
/// SQLITE_IOERR、SQLITE_BUSY（5）的驱动文案。SQLITE_BUSY 是超过 busy_timeout
/// 的瞬态忙等（与前两条确定性故障不同），但同属"稍后重试可能成功"——归
/// 503 族而非 500，客户端得以区分"服务端依赖问题"与"内部 bug"。
fn is_sqlite_storage_failure(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("database or disk is full")
        || lower.contains("disk i/o error")
        || lower.contains("database is locked")
}

/// PG 资源枯竭文案（大小写不敏感，保守最小集）：`"no space left"` = 满盘
///（SQLSTATE 53100 disk_full，典型文案 "could not extend file ...: No space
/// left on device"）；`"disk full"`/`"out of memory"` = 53100/53200 直陈。
/// 经 sqlx::Error::Database 的 Display 到达（不暴露 SQLSTATE），故裸文本判定。
/// 刻意最小集：避免把碰巧含近似词的 SQL 语义错误（如回显用户数据的约束
/// 冲突）误判为可用性问题。
fn is_db_resource_exhausted(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("disk full")
        || lower.contains("out of memory")
        || lower.contains("no space left")
}

impl DbErrorClassify for serde_json::Error {}
/// 已分类错误再入 `db_ctx`（如 `BuildLifecycle::db_op` 对 state 层结果二次加
/// 上下文）不得把 `DatabaseUnavailable` 降级为 `Database`——降级即 503 → 500
/// 且 `is_transient` 翻假，重试层据此漏判。
impl DbErrorClassify for CrbsError {
    fn is_backend_unavailable(&self) -> bool {
        matches!(self, CrbsError::DatabaseUnavailable { .. })
    }
}

/// Extension trait：以 `.db_ctx("<查询语义>")` 替代
/// `.map_err(|e| CrbsError::Database(format!(...)))` 样板。
pub trait DbResultExt<T> {
    /// 包装为 `CrbsError::Database("{context}: {error}")`；后端不可用
    ///（[`DbErrorClassify`]）时改产出 `DatabaseUnavailable { context, error }`。
    fn db_ctx(self, context: &str) -> Result<T>;
}

impl<T, E: std::fmt::Display + DbErrorClassify> DbResultExt<T> for std::result::Result<T, E> {
    fn db_ctx(self, context: &str) -> Result<T> {
        self.map_err(|e| {
            if e.is_backend_unavailable() {
                CrbsError::DatabaseUnavailable {
                    context: context.to_string(),
                    error: e.to_string(),
                }
            } else {
                CrbsError::Database(format!("{context}: {e}"))
            }
        })
    }
}

/// 双方言唯一键冲突识别（裸 Display 文本匹配：sqlx Any 不暴露结构化错误码）。
/// 入参须为 `db_ctx` 包装后的 [`CrbsError`]（Display 含 `{context}: {error}`，
/// 底层驱动文本可达）；`crate::state::products::is_unique_violation_msg` 已委托本函数。
pub fn is_unique_violation(err: &CrbsError) -> bool {
    let msg = err.to_string();
    msg.contains("UNIQUE constraint failed")
        || msg.contains("duplicate key value violates unique constraint")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 钉调用方前提：`db_ctx` 包装后的 CrbsError（Display 链含底层驱动文本）
    /// 仍可识别双方言唯一冲突。
    #[test]
    fn is_unique_violation_matches_both_dialects() {
        assert!(is_unique_violation(&CrbsError::Database(
            "create user: error returned from database: UNIQUE constraint failed: users.name"
                .to_string()
        )));
        assert!(is_unique_violation(&CrbsError::Database(
            "create user: error returned from database: duplicate key value \
             violates unique constraint \"users_name_key\""
                .to_string()
        )));
        // 负例：按 Display 纯文本匹配，不含冲突关键词即不误报。
        assert!(!is_unique_violation(&CrbsError::Database(
            "create user: connection refused".to_string()
        )));
        assert!(!is_unique_violation(&CrbsError::ValidationFailed {
            message: "invalid characters in user name".to_string()
        }));
    }

    #[test]
    fn test_network_io_kind_classification() {
        let e = io::Error::new(io::ErrorKind::TimedOut, "download timeout");
        assert!(matches!(
            CrbsError::from_io_context("dnf install", e),
            CrbsError::Network { .. }
        ));

        let e = io::Error::new(io::ErrorKind::NotFound, "no such file");
        assert!(matches!(
            CrbsError::from_io_context("open srpm", e),
            CrbsError::Io { .. }
        ));
    }

    #[test]
    fn test_looks_like_network_failure() {
        assert!(looks_like_network_failure(
            "curl: (6) Could not resolve host"
        ));
        assert!(looks_like_network_failure(
            "Cannot download repomd.xml: connection timed out"
        ));
        assert!(looks_like_network_failure(
            "Failed to download metadata for repo 'foo': HTTP 503 Service Unavailable"
        ));
        assert!(looks_like_network_failure(
            "curl error (22): The requested URL returned error: 502"
        ));
        assert!(looks_like_network_failure(
            "mirror returned 504 Gateway Timeout"
        ));
        // dnf5 "Status code: NNN"：5xx 瞬时可重试，4xx（如仓库文件缺失）永久。
        assert!(looks_like_network_failure(
            "Status code: 503 for https://mirrors.example.com/repomd.xml"
        ));
        assert!(!looks_like_network_failure(
            "Status code: 404 for https://mirrors.example.com/repomd.xml"
        ));
        assert!(!looks_like_network_failure("No such file or directory"));
        assert!(!looks_like_network_failure(
            "nothing provides python3-connection"
        ));
        // 包名内裸 '503' 不得判为 transient。
        assert!(!looks_like_network_failure(
            "nothing provides libfoo503-bar-2.0"
        ));
        assert!(!looks_like_network_failure(""));
        // dnf 安装清单/事务摘要里的裸 curl/wget 不判网络失败。
        assert!(!looks_like_network_failure(
            "Installing dependencies: curl wget libcurl"
        ));
        assert!(!looks_like_network_failure("  curl  x86_64  8.4.0-1"));
        // 真实 curl/wget 失败带短语级前缀。
        assert!(looks_like_network_failure(
            "curl: (56) Recv failure: Connection was reset"
        ));
        assert!(looks_like_network_failure(
            "wget: unable to resolve host address 'mirrors.example.com'"
        ));
        // 裸词 "timed out"/"time out" 不是网络错误——误判会让 worker 重试确定性失败。
        assert!(!looks_like_network_failure(
            "make: *** [check] Error timed out"
        ));
        assert!(!looks_like_network_failure(
            "make: *** [Makefile:5: all] time out"
        ));
        assert!(!looks_like_network_failure("operation timed out"));
        assert!(looks_like_network_failure("connection timed out"));
        assert!(looks_like_network_failure("connect timed out"));
        assert!(looks_like_network_failure("timeout was reached"));
        assert!(looks_like_network_failure("download timeout"));
    }

    #[test]
    fn test_is_transient() {
        assert!(CrbsError::Network {
            message: "foo".into()
        }
        .is_transient());
        assert!(CrbsError::Timeout.is_transient());
        assert!(CrbsError::DepsolveFailed {
            message: "Cannot download foo".into()
        }
        .is_transient());
        assert!(!CrbsError::ValidationFailed {
            message: "bad srpm".into()
        }
        .is_transient());
        assert!(!CrbsError::io_message("permission denied").is_transient());
    }

    #[test]
    fn test_is_not_found() {
        assert!(CrbsError::NotFound {
            message: "no such product".into()
        }
        .is_not_found());
        assert!(
            CrbsError::from(io::Error::new(io::ErrorKind::NotFound, "no such file")).is_not_found()
        );
        assert!(!CrbsError::ValidationFailed {
            message: "bad srpm".into()
        }
        .is_not_found());
        assert!(
            !CrbsError::from(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
                .is_not_found()
        );
    }

    #[test]
    fn test_from_io_error_default() {
        let io = io::Error::new(io::ErrorKind::NotFound, "no such file");
        let err = CrbsError::from(io);
        assert!(matches!(
            err,
            CrbsError::Io {
                ref context,
                kind: io::ErrorKind::NotFound,
                ..
            } if context == "io error"
        ));
        assert!(err.to_string().contains("no such file"));
    }

    #[test]
    fn test_display_messages_byte_stable() {
        // Display 输出是对外契约（日志、API detail），改文案需显式评审。
        let cases: Vec<(CrbsError, &str)> = vec![
            (
                CrbsError::DepsolveFailed {
                    message: "m".into(),
                },
                "depsolve failed: m",
            ),
            (
                CrbsError::LayerCreateFailed {
                    message: "m".into(),
                },
                "layer creation failed: m",
            ),
            (
                CrbsError::LayerNotFound { digest: "d".into() },
                "shared layer not found: d",
            ),
            (
                CrbsError::ContainerExecFailed {
                    exit_code: Some(1),
                    signal: None,
                    stderr: "s".into(),
                },
                "container exec failed: exit=Some(1), signal=None, stderr=s",
            ),
            (CrbsError::Timeout, "build timeout"),
            (
                CrbsError::SignFailed {
                    message: "m".into(),
                },
                "sign failed: m",
            ),
            (CrbsError::Cancelled, "build cancelled"),
            (
                CrbsError::PermissionDenied {
                    message: "m".into(),
                },
                "permission denied: m",
            ),
            (
                CrbsError::ReproduceVerificationFailed {
                    message: "m".into(),
                },
                "reproduce verification failed: m",
            ),
            (
                CrbsError::ValidationFailed {
                    message: "m".into(),
                },
                "validation failed: m",
            ),
            (
                CrbsError::NotFound {
                    message: "m".into(),
                },
                "not found: m",
            ),
            (
                CrbsError::ProductChainInvalid {
                    product: "p".into(),
                    reason: "r".into(),
                },
                "product chain invalid: p: r",
            ),
            (
                CrbsError::ProductChainCycle {
                    chain: vec!["a".into(), "b".into()],
                },
                "product chain cycle: [\"a\", \"b\"]",
            ),
            (
                CrbsError::ProductChainTooDeep { max: 8 },
                "product chain too deep: max 8",
            ),
            (
                CrbsError::RevisionConflict {
                    expected: 3,
                    current: 5,
                },
                "revision conflict: expected 3, current 5",
            ),
            (
                CrbsError::AlreadyExists {
                    message: "product 'foo' already exists".into(),
                },
                "already exists: product 'foo' already exists",
            ),
            (
                CrbsError::Conflict {
                    message: "m".into(),
                },
                "conflict: m",
            ),
            (
                CrbsError::DeleteRestricted {
                    message: "m".into(),
                },
                "delete restricted: m",
            ),
            (
                CrbsError::Io {
                    context: "c".into(),
                    kind: io::ErrorKind::Other,
                    detail: "d".into(),
                },
                "c: d",
            ),
            (
                CrbsError::Network {
                    message: "m".into(),
                },
                "network error: m",
            ),
            (CrbsError::Database("d".into()), "database error: d"),
            (
                CrbsError::DatabaseUnavailable {
                    context: "c".into(),
                    error: "e".into(),
                },
                "database unavailable: c: e",
            ),
            (
                CrbsError::CgroupSetupFailed("c".into()),
                "cgroup setup failed: c",
            ),
            (CrbsError::Internal("i".into()), "internal error: i"),
            (CrbsError::SilentExit { code: 7 }, "silent exit with code 7"),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }

        // Io 三种构造路径：分类前缀至多出现一次，不允许 `io error: io error:` 重复。
        let e = io::Error::new(io::ErrorKind::NotFound, "no such file");
        assert_eq!(
            CrbsError::from_io_context("open srpm", e).to_string(),
            "open srpm: no such file"
        );
        assert_eq!(
            CrbsError::io_message("spawn chroot: boom").to_string(),
            "io error: spawn chroot: boom"
        );
        let e = io::Error::new(io::ErrorKind::NotFound, "no such file");
        assert_eq!(CrbsError::from(e).to_string(), "io error: no such file");
    }

    #[test]
    fn test_safe_message_redacts_sensitive_errors() {
        assert_eq!(
            CrbsError::Io {
                context: "open /secret/key.pem".into(),
                kind: io::ErrorKind::NotFound,
                detail: "no such file".into(),
            }
            .safe_message(),
            "internal I/O error"
        );
        assert_eq!(
            CrbsError::Internal("detailed stack trace".into()).safe_message(),
            "internal error"
        );
        assert_eq!(
            CrbsError::Database("connection string".into()).safe_message(),
            "database error"
        );
        assert_eq!(
            CrbsError::DatabaseUnavailable {
                context: "postgres://secret@db/crbs".into(),
                error: "password auth failed for user secret".into(),
            }
            .safe_message(),
            "database unavailable"
        );
    }

    #[test]
    fn test_db_ctx_classifies_backend_unavailable() {
        // 池 acquire 超时 → DatabaseUnavailable（503 语义），而非 Database（500）。
        let r: std::result::Result<(), sqlx::Error> = Err(sqlx::Error::PoolTimedOut);
        let err = r.db_ctx("acquire conn").unwrap_err();
        assert!(matches!(
            err,
            CrbsError::DatabaseUnavailable { ref context, .. } if context == "acquire conn"
        ));
        // Display 保留底层错误形态（CLI/worker 直消费路径靠它区分故障形态）。
        let display = err.to_string();
        assert!(
            display.starts_with("database unavailable: acquire conn: "),
            "Display must retain the underlying error, got: {display}"
        );
        assert!(
            !display.trim_end_matches(' ').ends_with(':'),
            "underlying error text must be non-empty, got: {display}"
        );
        assert_eq!(err.code(), "database_unavailable");
        assert!(err.is_transient(), "DB outage must stay retryable");

        // 池关闭 / worker 崩溃 / 网络类 IO 同分类，且各自的底层形态都保留。
        for e in [
            sqlx::Error::PoolClosed,
            sqlx::Error::WorkerCrashed,
            sqlx::Error::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "refused",
            )),
        ] {
            let r: std::result::Result<(), sqlx::Error> = Err(e);
            let err = r.db_ctx("x").unwrap_err();
            let display = err.to_string();
            assert!(
                matches!(err, CrbsError::DatabaseUnavailable { .. }),
                "pool-level failure must classify as unavailable"
            );
            assert!(
                display.starts_with("database unavailable: x: ")
                    && display.len() > "database unavailable: x: ".len(),
                "underlying error Display must be retained, got: {display}"
            );
        }

        // SQL 语义错误仍是 Database（非可用性问题）。
        let other: std::result::Result<(), sqlx::Error> = Err(sqlx::Error::RowNotFound);
        assert!(matches!(
            other.db_ctx("query").unwrap_err(),
            CrbsError::Database(_)
        ));

        // serde_json 错误默认非可用性（trait 默认实现）。
        let json: std::result::Result<(), serde_json::Error> = serde_json::from_str("not json");
        assert!(matches!(
            json.db_ctx("parse").unwrap_err(),
            CrbsError::Database(_)
        ));
    }

    /// `CrbsError` 二次入 `db_ctx`（生命周期层对 state 层结果再包上下文）：
    /// `DatabaseUnavailable` 保持 503 族且 `is_transient` 不翻假；非可用性
    /// 错误仍归 `Database`，不得被抬升为可重试。
    #[test]
    fn test_db_ctx_preserves_classification_when_rewrapping_crbs_error() {
        let unavailable: crate::Result<()> = Err(CrbsError::DatabaseUnavailable {
            context: "begin write".into(),
            error: "error returned from database: (code: 5) database is locked".into(),
        });
        let err = unavailable
            .db_ctx("update build phase to building for 7")
            .unwrap_err();
        assert!(matches!(
            err,
            CrbsError::DatabaseUnavailable { ref context, .. }
                if context == "update build phase to building for 7"
        ));
        assert!(
            err.is_transient(),
            "re-wrapped unavailability must stay retryable"
        );

        let semantic: crate::Result<()> = Err(CrbsError::ValidationFailed {
            message: "invalid build phase 'cancelled'".into(),
        });
        let err = semantic.db_ctx("update build phase").unwrap_err();
        assert!(matches!(err, CrbsError::Database(_)));
        assert!(
            !err.is_transient(),
            "4xx-class error must not become retryable"
        );
    }

    #[test]
    fn test_db_ctx_wraps_error_with_context() {
        // 最小假错误：Display + 默认 DbErrorClassify，满足 blanket impl bounds。
        struct FakeDbError;
        impl std::fmt::Display for FakeDbError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "connection refused")
            }
        }
        impl DbErrorClassify for FakeDbError {}

        let r: std::result::Result<(), FakeDbError> = Err(FakeDbError);
        let err = r.db_ctx("load tasks").unwrap_err();
        assert!(matches!(err, CrbsError::Database(_)));
        assert_eq!(
            err.to_string(),
            "database error: load tasks: connection refused"
        );
    }

    #[test]
    fn test_db_ctx_passes_through_ok() {
        let r: std::result::Result<i32, sqlx::Error> = Ok(7);
        assert_eq!(r.db_ctx("noop").unwrap(), 7);
    }

    /// SQLite 存储故障文案经 db_ctx 须产出 DatabaseUnavailable（503 族）；
    /// sqlx Any 不暴露结构化错误码，用最小 fake DatabaseError 钉 Display 通道。
    #[test]
    fn test_db_ctx_classifies_sqlite_storage_failures() {
        #[derive(Debug)]
        struct FakeDbError(&'static str);
        impl std::fmt::Display for FakeDbError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.0)
            }
        }
        impl std::error::Error for FakeDbError {}
        impl sqlx::error::DatabaseError for FakeDbError {
            fn message(&self) -> &str {
                self.0
            }
            fn kind(&self) -> sqlx::error::ErrorKind {
                sqlx::error::ErrorKind::Other
            }
            fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
                self
            }
            fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
                self
            }
            fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
                self
            }
        }

        // 正例（经 sqlx 包装后 Display 为 "error returned from database:
        // {message}"，双方言同走 Database Display 通道）：SQLITE_FULL/IOERR/BUSY
        // 驱动文案 + PG 满盘/OOM 文案，实文见下方列表。
        for msg in [
            "database or disk is full",
            "disk I/O error",
            "database is locked",
            "could not extend file \"base/16384/16385\" with 4096 blocks: No space left on device",
            "out of memory",
        ] {
            let e = sqlx::Error::Database(Box::new(FakeDbError(msg)));
            let r: std::result::Result<(), sqlx::Error> = Err(e);
            let err = r.db_ctx("insert task").unwrap_err();
            assert!(
                matches!(err, CrbsError::DatabaseUnavailable { ref context, .. } if context == "insert task"),
                "SQLite storage failure must classify as unavailable (503): {err}"
            );
            assert_eq!(err.code(), "database_unavailable");
        }

        // 负例：普通 SQL 语义错误仍是 Database（500）。
        for msg in [
            "UNIQUE constraint failed: builds.id",
            "no such table: builds",
        ] {
            let e = sqlx::Error::Database(Box::new(FakeDbError(msg)));
            let r: std::result::Result<(), sqlx::Error> = Err(e);
            assert!(
                matches!(r.db_ctx("query").unwrap_err(), CrbsError::Database(_)),
                "SQL semantic errors must stay Database (500)"
            );
        }
    }
}
