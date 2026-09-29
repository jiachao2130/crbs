// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! CLI 子命令入口与共享 helper；各命令实现位于同名子模块。

pub(crate) mod admin;
pub(crate) mod build;
pub(crate) mod builds;
pub(crate) mod cancel;
pub(crate) mod clean;
pub(crate) mod config;
pub(crate) mod confirm;
pub(crate) mod diff;
pub(crate) mod dispatch;
pub(crate) mod download;
pub(crate) mod gc;
pub(crate) mod init;
pub(crate) mod logs;
pub(crate) mod nihao;
pub(crate) mod products;
pub(crate) mod products_acl;
pub(crate) mod rebuild;
pub(crate) mod remote_profile;
pub(crate) mod shell;
pub(crate) mod sign;
pub(crate) mod status;
pub(crate) mod verify;

pub(crate) use cancel::{handle_cancel, CancelArgs};
pub(crate) use clean::{handle_clean, CleanArgs};
pub(crate) use init::{handle_init, InitArgs};

use crbs_core::privilege::CallerContext;
use crbs_core::StateStore;

/// 解析构建任务 ID（数字）并验证用户权限；`user_filter` 为 Some 时只查该
/// 用户记录（非 root 用户隔离）。逻辑在 `StateStore::resolve_short_id`。
pub(crate) async fn resolve_short_id(
    task: &str,
    state: &crbs_core::StateStore,
    user_filter: Option<&str>,
) -> crbs_core::Result<i64> {
    state.resolve_short_id(task, user_filter).await
}

/// 本地命令缺 StateStore 属调用方式误用（缺 `--local`/误配远程）→
/// `ValidationFailed`（USAGE=4，不落 INTERNAL(1)）；文案由调用方逐字传入。
/// 任务/构建查询的用户过滤口径（logs/diff/cancel/sign/attach/reproduce 等
/// 共用）：root 全量（None），普通用户仅本人——恒定过滤会让 root 查他人
/// 任务误报 not found。
pub(crate) fn visible_user_filter(ctx: &CallerContext) -> Option<&str> {
    if ctx.is_root {
        None
    } else {
        Some(ctx.caller.username.as_str())
    }
}

/// 任务号解析统一入口（logs/download/sign/cancel 共用）：失败为
/// ValidationFailed（USAGE=4）——anyhow 裸错误会落 INTERNAL(1)。
pub(crate) fn parse_task_id(input: &str) -> anyhow::Result<i64> {
    input.parse::<i64>().map_err(|e| -> anyhow::Error {
        crbs_core::error::CrbsError::ValidationFailed {
            message: format!("invalid task id: {e}"),
        }
        .into()
    })
}

/// 任务号未找到的统一文案（status/cancel/verify/sign 共用；文案与 core
/// resolve_task_id 逐字统一）。
/// Ctrl-C → CancellationToken 的标准接线（status/rebuild 的 watch 循环共用）：
/// 后台任务监听信号触发取消，返回的 token 供循环轮询。
pub(crate) fn ctrl_c_cancel_token() -> tokio_util::sync::CancellationToken {
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_for_ctrlc = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_for_ctrlc.cancel();
        }
    });
    cancel
}

pub(crate) fn task_not_found(id: impl std::fmt::Display) -> crbs_core::error::CrbsError {
    crbs_core::error::CrbsError::NotFound {
        message: format!("task {id} not found. Run 'crbs status' to list tasks."),
    }
}

pub(crate) fn require_state_store(
    state: Option<&StateStore>,
    message: impl Into<String>,
) -> anyhow::Result<&StateStore> {
    state.ok_or_else(|| {
        crbs_core::error::CrbsError::ValidationFailed {
            message: message.into(),
        }
        .into()
    })
}

/// 成功信封公共构造：`--format json` 成功输出统一为顶层对象且含 `command`
/// 键，取 [`crate::cli::Cli::json_error_contract`] 同名值（信封同源，脚本按
/// command 分流不漂移）。对象本体平铺合并 `command`、schema 原样保留，自带
/// 该键时嵌套 `response` 避撞（当前已知 server 响应均无该键，防御分支）；
/// 裸数组不进本函数，由站点显式包资源复数键（如 `{command, tasks}`），键名
/// 随资源语义命名，不在公共层猜测。
pub(crate) fn json_success_envelope(
    command: &'static str,
    body: serde_json::Value,
) -> serde_json::Value {
    match body {
        serde_json::Value::Object(mut map) if !map.contains_key("command") => {
            map.insert("command".to_string(), serde_json::json!(command));
            serde_json::Value::Object(map)
        }
        other => serde_json::json!({ "command": command, "response": other }),
    }
}

/// 记录归属校验（本地 CLI 直连路径共用谓词）：root 豁免；旧记录 `user=''` 视为
/// 无主放行；非本人记录返回 `CrbsError::PermissionDenied`（退出码 PERMISSION=5），
/// 消息点名归属；`kind` 是类别名词（"build"/"task"），进错误消息。
pub(crate) fn ensure_record_owner(
    kind: &str,
    id: i64,
    owner: &str,
    ctx: &CallerContext,
) -> Result<(), crbs_core::error::CrbsError> {
    if !ctx.is_root && !owner.is_empty() && owner != ctx.caller.username {
        return Err(crbs_core::error::CrbsError::PermissionDenied {
            message: format!(
                "{kind} {id} belongs to '{owner}', not '{}'",
                ctx.caller.username
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 覆盖 `json_success_envelope` 三形态：平铺合并 / 撞键嵌套 response / 数组不进。
    #[test]
    fn json_success_envelope_merges_or_nests() {
        let merged = json_success_envelope(
            "products",
            serde_json::json!({ "revision": 6, "base_os_bumped": false }),
        );
        assert_eq!(merged["command"], "products");
        assert_eq!(merged["revision"], 6);
        assert_eq!(merged["base_os_bumped"], false);
        assert_eq!(
            merged.as_object().map(|m| m.len()),
            Some(3),
            "no extra keys"
        );

        let nested =
            json_success_envelope("products", serde_json::json!({ "command": "server-says" }));
        assert_eq!(nested["command"], "products");
        assert_eq!(nested["response"]["command"], "server-says");
    }

    /// 归属谓词决策表：root 豁免 / 本人放行 / 无主（user=''）放行 / 非本人
    /// PermissionDenied（PERMISSION=5）。
    #[test]
    fn ensure_record_owner_decision_table() {
        let user = crbs_core::privilege::CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: "tester".to_string(),
            },
            false,
        );
        let root = crbs_core::privilege::CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 0,
                gid: 0,
                username: "root".to_string(),
            },
            true,
        );
        assert!(ensure_record_owner("task", 1, "tester", &user).is_ok());
        assert!(ensure_record_owner("task", 1, "", &user).is_ok());
        assert!(ensure_record_owner("task", 1, "someone", &root).is_ok());
        let err = ensure_record_owner("task", 1, "someone", &user).unwrap_err();
        assert!(
            matches!(err, crbs_core::error::CrbsError::PermissionDenied { .. }),
            "{err:?}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(&err),
            crbs_core::exit_code::PERMISSION
        );
    }

    async fn tmp_store() -> (tempfile::TempDir, crbs_core::StateStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = crbs_core::StateStore::new(tmp.path()).await.unwrap();
        (tmp, store)
    }

    /// `builds.task_id` NOT NULL：测试造 build 前先插一条本地任务行。
    async fn seed_task(store: &crbs_core::StateStore, product: &str, pkg_name: &str) -> i64 {
        store
            .insert_task(crbs_core::TaskInsert {
                product,
                pkg_name,
                user: "",
                ..Default::default()
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn resolve_short_id_invalid_number() {
        let (_tmp, store) = tmp_store().await;
        let err = resolve_short_id("abc", &store, None).await.unwrap_err();
        assert!(format!("{}", err).contains("must be a number"));
    }

    #[tokio::test]
    async fn resolve_short_id_not_found() {
        let (_tmp, store) = tmp_store().await;
        let err = resolve_short_id("999", &store, None).await.unwrap_err();
        assert!(
            matches!(err, crbs_core::error::CrbsError::NotFound { .. }),
            "expected NotFound error, got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn resolve_short_id_found() {
        let (_tmp, store) = tmp_store().await;
        let id = store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "succeeded",
                backend: "chroot",
                user: "alice",
                task_id: Some(seed_task(&store, "fedora", "hello").await),
                ..Default::default()
            })
            .await
            .unwrap();

        let resolved = resolve_short_id(&id.to_string(), &store, None)
            .await
            .unwrap();
        assert_eq!(resolved, id);
    }

    #[tokio::test]
    async fn resolve_short_id_user_filter() {
        let (_tmp, store) = tmp_store().await;
        let id_alice = store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "succeeded",
                backend: "chroot",
                user: "alice",
                task_id: Some(seed_task(&store, "fedora", "hello").await),
                ..Default::default()
            })
            .await
            .unwrap();
        let _id_bob = store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "succeeded",
                backend: "chroot",
                user: "bob",
                task_id: Some(seed_task(&store, "fedora", "hello").await),
                ..Default::default()
            })
            .await
            .unwrap();

        let resolved = resolve_short_id(&id_alice.to_string(), &store, Some("alice"))
            .await
            .unwrap();
        assert_eq!(resolved, id_alice);
    }

    #[tokio::test]
    async fn resolve_task_id_not_found_shape() {
        let (_tmp, store) = tmp_store().await;
        let err = store.resolve_task_id("999", None).await.unwrap_err();
        assert!(
            matches!(err, crbs_core::error::CrbsError::NotFound { .. }),
            "expected NotFound error, got {:?}",
            err
        );
        // NotFound 形态与服务端 ApiError::not_found("task", id) 同形。
        assert!(
            format!("{}", err).contains("task 999 not found"),
            "unexpected message: {err}"
        );
    }

    #[tokio::test]
    async fn resolve_task_id_invalid_number() {
        let (_tmp, store) = tmp_store().await;
        let err = store.resolve_task_id("abc", None).await.unwrap_err();
        assert!(format!("{}", err).contains("must be a number"));
    }

    /// 两表自增序列独立：task id 与 build id 同数字不同资源，解析器必须
    /// 各查各的表（同数字两义回归钉）。
    #[tokio::test]
    async fn resolve_task_id_and_short_id_hit_disjoint_tables() {
        let (_tmp, store) = tmp_store().await;
        let task1 = seed_task(&store, "fedora", "hello").await;
        let task2 = seed_task(&store, "fedora", "world").await;
        assert_ne!(task1, task2);
        // task2 的子构建拿到 build id 1（与 task id 1 撞号）。
        let build1 = store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "world",
                phase: "succeeded",
                backend: "chroot",
                user: "alice",
                task_id: Some(task2),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            build1, task1,
            "fixture requires colliding ids across tables"
        );

        let as_task = store
            .resolve_task_id(&task2.to_string(), None)
            .await
            .unwrap();
        assert_eq!(as_task, task2);
        // 同数字按 build 域解析则查无此 build（build 表只有 id 1）。
        assert!(resolve_short_id(&task2.to_string(), &store, None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn resolve_task_id_user_filter_conceals_others() {
        // 非 root 查他人任务按 NotFound 隐藏存在性（与服务端 404 同口径）。
        let (_tmp, store) = tmp_store().await;
        let id = store
            .insert_task(crbs_core::TaskInsert {
                product: "fedora",
                pkg_name: "hello",
                user: "alice",
                ..Default::default()
            })
            .await
            .unwrap();

        let err = store
            .resolve_task_id(&id.to_string(), Some("bob"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, crbs_core::error::CrbsError::NotFound { .. }),
            "expected NotFound (existence concealed), got: {:?}",
            err
        );
        let resolved = store
            .resolve_task_id(&id.to_string(), Some("alice"))
            .await
            .unwrap();
        assert_eq!(resolved, id);
    }
}
