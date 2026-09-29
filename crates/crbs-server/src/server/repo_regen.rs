// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 服务端产品 repo 重建触发器：封装"解析 result_root 与 `repo_publish`
//! 开关 → `engine::repo_publish` 对账式重建"，供全部触发点复用。
//!
//! 失败语义分两路：自动触发点用 [`regenerate_product_repo`]（fire-and-forget，
//! 失败仅 warn、绝不传播给构建）；手动命令（publish/unpublish/rebuild-repo）
//! 用 [`assemble_for_product`] 拿 `Result`，撞锁超时等失败归给操作员。

use std::path::Path;
use std::sync::Arc;

use tracing::{info, warn};

use crbs_core::engine::repo_publish::{assemble_product_repo, RepoAssembleReport};

use crate::server::state::AppState;

use crate::server::REPO_ROOT_DIR;

/// 解析产品 `repo_publish` 开关（缺省 / 产品未 seed → 默认发布）。
async fn resolve_repo_publish(app: &Arc<AppState>, product: &str) -> bool {
    match app.state_store.resolve_any_product_by_name(product).await {
        Ok(resolved) => resolved.config.repo_publish.unwrap_or(true),
        Err(e) => {
            // 产品配置临时不可读时保守按"发布"处理，避免误把 repo 摘空。
            warn!(
                product = %product,
                error = %e,
                "Failed to resolve repo_publish; defaulting to true"
            );
            true
        }
    }
}

/// 解析产品签名策略：声明了签名策略（未显式关闭且配置 key）时发布 repo
/// 只收已签名构建。配置读失败向上传播（fail-closed）：绝不在策略未知时做
/// 无过滤重建——那会把 repo_publish=1 的未签名构建并进发布树，替换掉旧树
/// 中原本受保护的内容；失败由自动 regen 的 warn / 手动命令的错误返回收敛。
async fn resolve_requires_signed(app: &Arc<AppState>, product: &str) -> crbs_core::Result<bool> {
    let config = app
        .state_store
        .load_merged_config_for_any_product_by_name(product)
        .await?;
    Ok(crbs_core::sign::SignConfig::signing_required(&config))
}

/// 对账式重建产品发布型 repo，`Result` 交回调用方（手动命令等需把失败归属
/// 操作员的路径）：撞 `.repodata-{arch}.lock` 超时等错误向上传播，HTTP 层转可重试提示。
/// 签名策略生效时未签名构建不入选（`resolve_requires_signed`）。
pub async fn assemble_for_product(
    app: &Arc<AppState>,
    product: &str,
) -> crbs_core::Result<RepoAssembleReport> {
    let result_root = app.result_dir_for_or_default(product).await;
    let repo_publish = resolve_repo_publish(app, product).await;
    let require_signed = resolve_requires_signed(app, product).await?;
    assemble_product_repo(
        &app.state_store,
        product,
        &result_root,
        repo_publish,
        require_signed,
    )
    .await
}

/// 自动触发点用的 fire-and-forget 重建：调用 `.await` 立即返回（保留 async 签名
/// 兼容现有调用点），重建在独立后台任务执行到完成，失败仅 warn、绝不传播给构建。
/// 任务不持有任何调用方取消 token——regen 是收敛性对账，调用方取消不应中断重建。
///
/// 并发互斥：重建路径 `reconcile_dir` 对每个 arch 目录全程持有
/// `.repodata-{arch}.lock`（`lock_exclusive_async`，超时 300s，与 `engine::repo`
/// 的本地快照仓锁同一机制），同产品并发
/// regen 串行化、不交错产出损坏元数据；但锁挡不住排队堆积，故做 per-product 在途
/// 去重 + dirty re-arm：spawn 前 `claim_regen` 占位，已在途则记入 `regen_dirty` 后
/// 返回。候选快照取定于 spawn 后毫秒级，在途期到达的触发若只跳过不补跑，其 RPM
/// 会缺席到下次触发（多包同产品并行收尾无此兜底），故收尾取脏非空则补跑一轮，
/// 收敛到最新状态。
pub async fn regenerate_product_repo(app: &Arc<AppState>, product: &str) {
    // 占位在 spawn 前同步段完成：并发第二触发必见在途名额（测试据此确定性断言）。
    let Some(mut _inflight) = claim_regen(app, product) else {
        tracing::debug!(
            product = %product,
            "Product repo regen already in flight; marked dirty for re-run after current round"
        );
        return;
    };
    let app = app.clone();
    let product = product.to_string();
    tokio::spawn(async move {
        // guard 随任务体 move：consumed 置位后 Drop 不重复移除（防误删后续
        // claimant 名额），panic / 早退未置位由 Drop 兜底释放。
        // dirty re-arm 循环：跑一轮 → 收尾原子决策"取脏补跑 / 释放退出"；
        // 新触发再置脏再决策，触发流有限则收敛；guard 在途全程保持，无递归。
        loop {
            match assemble_for_product(&app, &product).await {
                Ok(report) => {
                    info!(
                        product = %product,
                        arches = ?report.arches,
                        linked = report.linked,
                        unlinked = report.unlinked,
                        skipped_missing = report.skipped_missing,
                        skipped_exdev = report.skipped_exdev,
                        skipped_other = report.skipped_other,
                        "Regenerated product repo"
                    );
                }
                Err(e) => {
                    // 失败语义：regen 失败不影响构建，等下一次触发或 rebuild-repo 收敛。
                    warn!(
                        product = %product,
                        error = %e,
                        "Failed to regenerate product repo; will converge on next trigger"
                    );
                }
            }
            if !release_or_rerun(&mut _inflight) {
                break;
            }
            tracing::debug!(
                product = %product,
                "regen dirty re-arm: triggers arrived while in flight; rerunning round"
            );
        }
    });
}

/// regen 在途占位 guard：Drop 移除名额，panic / 早退也保证释放；正常收尾走
/// [`release_or_rerun`]（原子释放 + 置 `consumed`），Drop 仅作 fallback。
struct RegenInflightGuard {
    app: Arc<AppState>,
    product: String,
    /// [`release_or_rerun`] 释放名额时置位，Drop 不再重复移除；必须在临界区
    /// 内置位——置位前 panic 的话 Drop 二次移除会误删后续 claimant 刚占的名额。
    consumed: bool,
}

impl Drop for RegenInflightGuard {
    fn drop(&mut self) {
        if self.consumed {
            return;
        }
        self.app
            .regen_inflight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.product);
    }
}

/// 占位 per-product regen 在途名额：已在途则记入 `regen_dirty`（dirty re-arm，
/// 见 [`regenerate_product_repo`]）并返回 `None`；成功则返回 guard，并在**同一
/// 临界区**清除遗留脏标记——拆开两步有丢失窗口：占位与清脏之间置脏会被误吞。
/// 同步短临界区、不跨 await；锁序固定 `regen_inflight` → `regen_dirty`（与
/// [`release_or_rerun`] 一致，全局唯一加锁次序）。
fn claim_regen(app: &Arc<AppState>, product: &str) -> Option<RegenInflightGuard> {
    let mut inflight = app.regen_inflight.lock().unwrap_or_else(|e| e.into_inner());
    if !inflight.insert(product.to_string()) {
        drop(inflight);
        app.regen_dirty
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(product.to_string());
        return None;
    }
    app.regen_dirty
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(product);
    Some(RegenInflightGuard {
        app: app.clone(),
        product: product.to_string(),
        consumed: false,
    })
}

/// regen 一轮收尾的原子决策：有脏标记 → 取走标记、**保留名额**，返回 `true`
/// 补跑一轮；无标记 → 同一临界区释放在途名额并置 `guard.consumed`，返回
/// `false` 退出。两步必须原子：取脏与释放分离时，其间隙到达的触发置脏后无人
/// 消费、触发丢失。锁序 `regen_inflight` → `regen_dirty`（与 [`claim_regen`] 一致）。
fn release_or_rerun(guard: &mut RegenInflightGuard) -> bool {
    let app = &guard.app;
    let product = guard.product.as_str();
    let mut inflight = app.regen_inflight.lock().unwrap_or_else(|e| e.into_inner());
    let rerun = app
        .regen_dirty
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(product);
    if rerun {
        return true;
    }
    inflight.remove(product);
    guard.consumed = true;
    false
}

/// 删除产品整个 `_repo/{product}` 子树（产品删除路径）。路径隔离不变量：断言
/// 目标严格位于 `{result_root}/_repo/` 之下且不等于共享根，绝不误删 result_root
/// 或 `_repo`。失败仅 warn，repo 残留交 rebuild / 人工清理，不阻断删除流程。
pub(crate) async fn remove_product_repo(result_root: &Path, product: &str) {
    // 安全边界：产品名防路径逃逸。
    if product.is_empty()
        || product == "."
        || product == ".."
        || product.contains(['/', '\\', '\0'])
    {
        warn!(product = %product, "Refusing to remove repo for unsafe product name");
        return;
    }

    let repo_root = result_root.join(REPO_ROOT_DIR);
    let target = repo_root.join(product);

    if !target.starts_with(&repo_root) || target == repo_root || target == result_root {
        warn!(
            target = %target.display(),
            "Repo cleanup target failed isolation assertion; refusing to remove"
        );
        return;
    }

    match tokio::fs::metadata(&target).await {
        Ok(_) => match tokio::fs::remove_dir_all(&target).await {
            Ok(()) => info!(product = %product, path = %target.display(), "Removed product repo"),
            Err(e) => warn!(
                product = %product,
                path = %target.display(),
                error = %e,
                "Failed to remove product repo"
            ),
        },
        // NotFound 即已达成目标（幂等）。
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            product = %product,
            path = %target.display(),
            error = %e,
            "Failed to stat product repo for removal"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn touch(path: &Path) {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.unwrap();
        }
        tokio::fs::write(path, b"x").await.unwrap();
    }

    /// 只删目标产品子树，兄弟产品 repo 与 build 结果目录（`_repo` 的兄弟）不受影响。
    #[tokio::test]
    async fn remove_product_repo_removes_only_target() {
        let root = tempfile::tempdir().unwrap();
        let rp = root.path();
        touch(&rp.join("_repo/prod/x86_64/Packages/a.rpm")).await;
        touch(&rp.join("_repo/other/x86_64/Packages/b.rpm")).await;
        touch(&rp.join("1/RPMS/a.rpm")).await;

        remove_product_repo(rp, "prod").await;

        assert!(!tokio::fs::try_exists(rp.join("_repo/prod")).await.unwrap());
        assert!(tokio::fs::try_exists(rp.join("_repo/other")).await.unwrap());
        assert!(tokio::fs::try_exists(rp.join("1/RPMS/a.rpm"))
            .await
            .unwrap());
    }

    /// 不安全产品名（含分隔符 / `..`）拒绝删除，绝不逃逸命名空间。
    #[tokio::test]
    async fn remove_product_repo_rejects_unsafe_name() {
        let root = tempfile::tempdir().unwrap();
        let rp = root.path();
        touch(&rp.join("_repo/keep/x86_64/Packages/a.rpm")).await;

        for bad in ["..", "a/b", "", "."] {
            remove_product_repo(rp, bad).await;
        }

        assert!(tokio::fs::try_exists(rp.join("_repo/keep")).await.unwrap());
        assert!(tokio::fs::try_exists(rp.join("_repo")).await.unwrap());
    }

    /// 目标不存在 → no-op（幂等，不报错）。
    #[tokio::test]
    async fn remove_product_repo_noop_when_missing() {
        let root = tempfile::tempdir().unwrap();
        remove_product_repo(root.path(), "ghost").await;
    }

    /// fire-and-forget 语义：调用必须立即返回，不等重建完成。测试侧独占
    /// `.repodata-{arch}.lock`（fs4 flock 与 `lock_exclusive_async` 同一锁域）令 spawn
    /// 的重建阻塞在锁上；若实现退回内联 await，2s 超时即失败。
    #[tokio::test]
    async fn regenerate_product_repo_returns_before_rebuild_completes() {
        use std::time::Duration;

        use crbs_core::config::ServerConfig;

        use crate::server::state::AppState;

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store,
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));

        // 预置磁盘 arch 目录，使重建确实进入 reconcile_dir（锁获取点）。
        let result_root = app.result_dir_for_or_default("prod").await;
        let arch_repo = result_root.join("_repo").join("prod").join("x86_64");
        tokio::fs::create_dir_all(&arch_repo).await.unwrap();

        // 锁在换位树之外（repo_base，见 engine::repo_publish 模块 doc）。
        let lock_path = result_root
            .join("_repo")
            .join("prod")
            .join(".repodata-x86_64.lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        fs4::fs_std::FileExt::try_lock_exclusive(&lock_file)
            .expect("test must hold the repodata lock");

        tokio::time::timeout(
            Duration::from_secs(2),
            regenerate_product_repo(&app, "prod"),
        )
        .await
        .expect("regenerate_product_repo must return before rebuild completes");

        // 释放锁；测试运行时随测试结束销毁，spawn 的重建任务随之取消，无残留。
        drop(lock_file);
    }

    /// claim 互斥 + guard Drop 释放（panic / 早退路径由 Drop 兜底）。
    #[tokio::test]
    async fn regen_claim_is_exclusive_and_guard_drop_releases() {
        use crbs_core::config::ServerConfig;

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store,
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));

        let g1 = claim_regen(&app, "prod");
        assert!(g1.is_some(), "首次占位必须成功");
        assert!(
            claim_regen(&app, "prod").is_none(),
            "在途产品的重复占位必须被拒"
        );
        assert!(
            claim_regen(&app, "other").is_some(),
            "不同产品的占位互不影响"
        );
        drop(g1);
        assert!(
            claim_regen(&app, "prod").is_some(),
            "guard Drop 后名额必须释放"
        );
    }

    /// 并发触发只跑一次：占位在 spawn 前同步段完成，第二触发必见在途名额而
    /// 跳过（记脏，收尾补跑，见 [`regenerate_product_repo`]）。测试预置 products
    /// 行（写盘前守卫要求）并独占 `.repodata-{arch}.lock`，名额在断言期间保持在途。
    #[tokio::test]
    async fn regenerate_product_repo_dedupes_concurrent_triggers() {
        use crbs_core::config::ServerConfig;

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store,
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));

        sqlx::query(
            "INSERT INTO products (name, visibility, config_json) VALUES ('prod', 'public', '{}') \
             ON CONFLICT (name) DO NOTHING",
        )
        .execute(app.state_store.pool())
        .await
        .unwrap();
        let result_root = app.result_dir_for_or_default("prod").await;
        let arch_repo = result_root.join("_repo").join("prod").join("x86_64");
        tokio::fs::create_dir_all(&arch_repo).await.unwrap();
        // 锁在换位树之外（repo_base，见 engine::repo_publish 模块 doc）。
        let lock_path = result_root
            .join("_repo")
            .join("prod")
            .join(".repodata-x86_64.lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        fs4::fs_std::FileExt::try_lock_exclusive(&lock_file)
            .expect("test must hold the repodata lock");

        regenerate_product_repo(&app, "prod").await;
        regenerate_product_repo(&app, "prod").await;

        let inflight = app.regen_inflight.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(inflight.len(), 1, "同产品并发触发只允许一个在途 regen");
        assert!(inflight.contains("prod"));

        drop(lock_file);
    }

    /// dirty re-arm：claim 失败（同产品在途）置脏，占位成功清除遗留脏标记（本轮即补跑轮）。
    #[tokio::test]
    async fn regen_claim_failure_marks_dirty_and_success_clears_it() {
        use crbs_core::config::ServerConfig;

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store,
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));

        let g1 = claim_regen(&app, "prod");
        assert!(g1.is_some());
        assert!(
            claim_regen(&app, "prod").is_none(),
            "在途产品的重复占位必须被拒"
        );
        assert!(
            app.regen_dirty
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains("prod"),
            "claim 失败必须置脏（在途轮收尾补跑）"
        );
        drop(g1);
        assert!(
            claim_regen(&app, "prod").is_some(),
            "guard Drop 后名额必须释放"
        );
        assert!(
            app.regen_dirty
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "占位成功必须清除遗留脏标记（本轮即补跑轮）"
        );
    }

    /// dirty re-arm 收尾决策原子性：有脏标记 → 取脏、保留名额（补跑）；
    /// 无脏标记 → 释放名额、置 consumed（Drop 不再重复移除）。
    #[tokio::test]
    async fn regen_release_or_rerun_takes_dirty_then_releases_slot() {
        use crbs_core::config::ServerConfig;

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store,
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));

        let mut guard = claim_regen(&app, "prod").expect("first claim");
        app.regen_dirty
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert("prod".to_string());

        assert!(release_or_rerun(&mut guard), "有脏标记必须决策补跑");
        assert!(
            app.regen_inflight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains("prod"),
            "补跑决策必须保留在途名额"
        );
        assert!(
            !app.regen_dirty
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains("prod"),
            "补跑决策必须取走脏标记"
        );

        assert!(!release_or_rerun(&mut guard), "无脏标记必须决策退出");
        assert!(guard.consumed, "退出决策必须在临界区内置 consumed");
        assert!(
            app.regen_inflight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "退出决策必须释放在途名额"
        );
        // consumed 后 Drop 不得误删后续 claimant 名额：重新占位验证。
        drop(guard);
        let successor = claim_regen(&app, "prod").expect("successor claim after release");
        drop(successor);
        assert!(
            app.regen_inflight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "consumed guard 的 Drop 不得影响后续 claimant 的名额"
        );
    }

    /// dirty re-arm 端到端：在途轮（阻塞在 `.repodata-{arch}.lock` 上）期间的触发置脏；
    /// 收尾取脏补跑一轮后释放退出，脏标记被消费，不留悬空触发。
    #[tokio::test]
    async fn regen_in_flight_trigger_is_rerun_by_dirty_rearm() {
        use std::time::Duration;

        use crbs_core::config::ServerConfig;

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store,
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));

        sqlx::query(
            "INSERT INTO products (name, visibility, config_json) VALUES ('prod', 'public', '{}') \
             ON CONFLICT (name) DO NOTHING",
        )
        .execute(app.state_store.pool())
        .await
        .unwrap();
        let result_root = app.result_dir_for_or_default("prod").await;
        let arch_repo = result_root.join("_repo").join("prod").join("x86_64");
        tokio::fs::create_dir_all(&arch_repo).await.unwrap();
        // 锁在换位树之外（repo_base，见 engine::repo_publish 模块 doc）。
        let lock_path = result_root
            .join("_repo")
            .join("prod")
            .join(".repodata-x86_64.lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        fs4::fs_std::FileExt::try_lock_exclusive(&lock_file)
            .expect("test must hold the repodata lock");

        // 第一触发：占位，任务阻塞在 repodata 锁上（在途）。
        regenerate_product_repo(&app, "prod").await;
        // 在途期间的第二触发：claim 失败置脏。
        regenerate_product_repo(&app, "prod").await;
        assert!(
            app.regen_dirty
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains("prod"),
            "在途期间到达的触发必须置脏"
        );

        // 释放锁：在途轮继续跑完 → 收尾取脏补跑一轮 → 无脏释放退出。
        drop(lock_file);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let quiesced = app
                .regen_inflight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty();
            if quiesced {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "regen task must quiesce after lock release"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            app.regen_dirty
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "收尾补跑必须消费脏标记，不留悬空触发"
        );
    }
}
