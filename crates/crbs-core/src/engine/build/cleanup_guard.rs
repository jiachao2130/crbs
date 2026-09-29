// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建清理护栏：终态/取消路径的受限删除与挂载回收。

use crate::engine::mount_guard::MountGuard;
use crate::engine::{BuildLifecycle, BuildOutcome};
use crate::error::CrbsError;
use tracing::warn;

/// 确保构建终态一定写入 SQLite、引用计数不漏更新，即使外层任务被 abort。
/// `run().await` 按 umount → complete → ref_dec（first-winner 才 dec）→ env
/// tempdir 删除收尾；清理 spawn 成独立任务再 await，外层 abort 时（inner 已
/// 被消费、Drop 无事可做）独立任务仍跑完，Drop 另起独立线程跑同流程兜底；
/// 在 `BuildEngine::build()` 共享层创建成功后即构造，mount_guard 后置注入，
/// 覆盖 overlay 之前的取消/超时/挂载失败路径，防 shared_layer 引用计数泄漏。
pub(crate) struct BuildCleanupGuard {
    inner: Option<BuildCleanupInner>,
}

struct BuildCleanupInner {
    lifecycle: BuildLifecycle,
    mount_guard: MountGuard,
    outcome: BuildOutcome,
    result_dir: String,
    layer_digest: Option<String>,
    state: std::sync::Arc<crate::state::StateStore>,
    shared_layer_gc_grace_hours: u64,
    /// overlay 临时目录（setup_overlay 后经 `set_env_temp` 注入）。交给 guard
    /// 而非 build() 局部变量：TempDir 的 Drop 是同步 remove_dir_all（upperdir
    /// 可达 GB 级）落在 async worker 线程，且与 abort 时 guard Drop 的分离清理
    /// 线程同 tick 竞态；折入后 umount 成功才删（spawn_blocking 移出 worker 线程，
    /// run 与 Drop 两路径同序串行），超时跳过删除防穿活挂载，残留由 tmp_sweep 兜底。
    env_temp: Option<tempfile::TempDir>,
}

impl BuildCleanupGuard {
    pub(crate) fn new(
        lifecycle: BuildLifecycle,
        mount_guard: MountGuard,
        outcome: BuildOutcome,
        result_dir: String,
        layer_digest: Option<String>,
        state: std::sync::Arc<crate::state::StateStore>,
        shared_layer_gc_grace_hours: u64,
    ) -> Self {
        Self {
            inner: Some(BuildCleanupInner {
                lifecycle,
                mount_guard,
                outcome,
                result_dir,
                layer_digest,
                state,
                shared_layer_gc_grace_hours,
                env_temp: None,
            }),
        }
    }

    /// overlay 建立后注入临时目录（后置注入：guard 构造早于 setup_overlay）；
    /// 删除由 `perform_cleanup` 收口，build() 出口不依赖 TempDir 同步 Drop。
    pub(crate) fn set_env_temp(&mut self, env_temp: Option<tempfile::TempDir>) {
        if let Some(inner) = self.inner.as_mut() {
            inner.env_temp = env_temp;
        }
    }

    /// overlay 建立后注入 mount_guard（正常路径必须调用；失败则持空 MountGuard）。
    pub(crate) fn set_mount_guard(&mut self, mount_guard: MountGuard) {
        if let Some(inner) = self.inner.as_mut() {
            inner.mount_guard = mount_guard;
        }
    }

    /// 取已注入 mount_guard 的可变引用（继续挂载公共/结果目录，须在 set_mount_guard() 后调用）。
    pub(crate) fn mount_guard(&mut self) -> crate::Result<&mut MountGuard> {
        self.inner
            .as_mut()
            .map(|inner| &mut inner.mount_guard)
            .ok_or_else(|| {
                CrbsError::io_message("BuildCleanupGuard already consumed or dropped".to_string())
            })
    }

    pub(crate) fn set_outcome(&mut self, outcome: BuildOutcome) {
        if let Some(inner) = self.inner.as_mut() {
            inner.outcome = outcome;
        }
    }

    /// 记录资源采样结果（透传给持有的 lifecycle，终态写入时随行落资源列）。
    pub(crate) fn set_resources(&mut self, resources: Option<crate::engine::ResourceUsage>) {
        if let Some(inner) = self.inner.as_mut() {
            inner.lifecycle.set_resources(resources);
        }
    }

    pub(crate) async fn run(mut self) {
        if let Some(inner) = self.inner.take() {
            // spawn 成独立任务后再 await：外层在 await 期间被 abort 时 JoinHandle
            // 被丢弃但任务继续跑完清理（inner 已消费，Drop 兜底不介入）。
            let handle = tokio::spawn(perform_cleanup(inner, false));
            if let Err(e) = handle.await {
                warn!(error = ?e, "cleanup task join failed after abort");
            }
        }
    }
}

/// umount/ref_dec 步骤的生产预算（umount 测试 seam 见 [`perform_cleanup_with_budget`]）。
const DEFAULT_STEP_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// complete 步骤的生产预算：须 ≥ 终态写重试预算上限（全写路径统一档 5 次 ×
/// busy_timeout 5s + 退避 ≈ 31s，见 build_lifecycle `LOCAL_WRITE_RETRY_*`），
/// 否则 timeout 臂会在重试中途放弃——白烧重试又留滞留行。umount 步骤维持
/// DEFAULT：hung 挂载多等无益，残留就地由 tmp_sweep 兜底。
const COMPLETE_STEP_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);

async fn perform_cleanup(inner: BuildCleanupInner, from_drop: bool) {
    perform_cleanup_with_budget(inner, from_drop, DEFAULT_STEP_BUDGET).await;
}

/// umount → complete → ref_dec → env tempdir 删除的清理序列（run 与 Drop 共用，
/// 新增清理步骤只改此处，不漏 Drop 兜底路径）。umount+ref_dec 与 complete 各
/// 持独立超时预算：前者超时只弃挂载/引用清理，complete 仍被尝试——单一预算
/// 超时会把构建行永久留在 running；umount 超时跳过 tempdir 删除（见
/// [`should_remove_env_temp`]）。`umount_budget` 仅作用 umount 步骤（complete
/// 恒用 [`COMPLETE_STEP_BUDGET`]），测试参数化 seam。
async fn perform_cleanup_with_budget(
    inner: BuildCleanupInner,
    from_drop: bool,
    umount_budget: std::time::Duration,
) {
    let suffix = if from_drop {
        " in cleanup guard drop"
    } else {
        ""
    };
    let BuildCleanupInner {
        lifecycle,
        mut mount_guard,
        outcome,
        result_dir,
        layer_digest,
        state,
        shared_layer_gc_grace_hours,
        env_temp,
    } = inner;

    // umount_completed 是 env tempdir 删除的门控前置；cfg(test) 行 = 测试注入点
    //（`maybe_block_umount` 令 umount 阻塞到放行，hung NFS/FUSE 替身），生产构建
    // 整体编译剔除。build_id 提前析出供超时日志（lifecycle 随后在 complete 被消费）。
    let build_id = lifecycle.build_id().to_string();
    let umount_fut = mount_guard.umount();
    #[cfg(test)]
    let umount_fut = self::tests::maybe_block_umount(umount_fut);
    let umount_completed = timed_umount(umount_fut, umount_budget, &build_id, suffix).await;

    // 先抢终态再 dec（first-winner）：反序在两步间崩溃时行仍 building，僵尸
    // 修复器赢终态会再 dec——双 dec 偷走并发引用、可把在用层推到 0 被 GC 删；
    // 输掉/超时侧不 dec，泄漏由 leaked-layer 修复兜底（泄漏可恢复、双扣不可恢复）。
    // complete 内含 transient 重试（全写路径统一档 5 次，预算见
    // COMPLETE_STEP_BUDGET）；重试/预算仍耗尽时行滞留活跃态，留痕于两条
    // error 臂——自愈通道：同 identity 下次镜像播种前的拆引信认领，worker
    // 重启 GC 兜底（陈旧活跃行的主要来源，滞留必须可发现）。
    let phase = outcome.phase();
    let won = match tokio::time::timeout(
        COMPLETE_STEP_BUDGET,
        lifecycle.complete(outcome, Some(&result_dir)),
    )
    .await
    {
        Err(_) => {
            tracing::error!(
                build_id = %build_id,
                phase = phase,
                "lifecycle complete timed out after 60s{suffix}; build row left active - next same-identity mirror seed claims it as stale, worker-restart GC is the last resort"
            );
            false
        }
        Ok(Err(e)) => {
            tracing::error!(
                build_id = %build_id,
                phase = phase,
                error = %e,
                "Failed to complete build{suffix}; build row left active - next same-identity mirror seed claims it as stale, worker-restart GC is the last resort"
            );
            false
        }
        Ok(Ok(won)) => won,
    };
    if won {
        if let Some(ref d) = layer_digest {
            if let Err(e) = state.layer_ref_dec(d, shared_layer_gc_grace_hours).await {
                warn!(digest = %d, error = %e, "layer_ref_dec failed{suffix}");
            }
        }
    }

    remove_env_temp_after_umount(env_temp, umount_completed, &build_id, suffix).await;
}

/// env tempdir 删除的唯一门控：umount 预算内完成后才允许删除。数据销毁防线：
/// umount 超时只是放弃 JoinHandle，blocking umount 仍在分离运行，并发
/// remove_dir_all 会穿活挂载删宿主内容；必须跳过删除、残留就地保留。回归
///（挪回 umount 前 / 去门控）在决策表与行为测试双处变红。
fn should_remove_env_temp(umount_completed: bool) -> bool {
    umount_completed
}

/// umount 步骤计时：预算内 true / 超时 false（[`should_remove_env_temp`] 的
/// 门控输入）。umount future 参数化是测试 seam（`std::future::pending()` 替身
/// 即可驱动超时臂）；`build_id` 仅用于超时 error 日志的结构化字段。
async fn timed_umount<F>(
    umount: F,
    budget: std::time::Duration,
    build_id: &str,
    suffix: &str,
) -> bool
where
    F: std::future::Future<Output = ()>,
{
    if tokio::time::timeout(budget, umount).await.is_err() {
        tracing::error!(
            build_id = %build_id,
            "umount timed out after {budget:?}{suffix}, continuing to build state completion"
        );
        return false;
    }
    true
}

/// env tempdir 删除收口（清理序列最末）：umount 成功后经 spawn_blocking 删除
///（同步 remove_dir_all，upperdir 可达 GB 级），Drop 兜底线程与本路径在同一
/// 清理序列内串行。umount 超时**跳过删除**（防线见 [`should_remove_env_temp`]），
/// 残留 temp 目录**就地保留**——孤儿清理（gc/orphan + engine/orphan 规则 3）
/// 只匹配 `.tmp*` 下的挂载做懒卸载、不回收目录体，目录体由 engine::tmp_sweep
/// 周期清扫兜底回收（口径对齐 reproduce.rs `ReproduceEnv::drop`）：env tempdir
/// 恰含 upper/work/root 三子目录、命中形态 A 布局签名；残留挂载仍被引用期间
/// 复扫守卫 fail-closed 跳过，umount 解除（NFS 恢复 / 重启 / 人工 umount）后才回收。
async fn remove_env_temp_after_umount(
    env_temp: Option<tempfile::TempDir>,
    umount_completed: bool,
    build_id: &str,
    suffix: &str,
) {
    if should_remove_env_temp(umount_completed) {
        if let Some(t) = env_temp {
            if let Err(e) = tokio::task::spawn_blocking(move || drop(t)).await {
                warn!(build_id = %build_id, error = %e, "env tempdir cleanup task failed{suffix}");
            }
        }
    } else if let Some(t) = env_temp {
        // 必须显式拆掉 TempDir 自毁 Drop：只 warn 会让 t 活到作用域尾、出口同步
        // remove_dir_all——门控被架空且与分离运行的 umount 并发。into_path 把
        // 目录留在磁盘（tempfile 3.14 尚无 keep()），残留由 tmp_sweep 形态 A 兜底。
        let residue = t.into_path();
        tracing::warn!(
            build_id = %build_id,
            path = %residue.display(),
            "env tempdir deletion skipped: umount did not finish within budget{suffix}; residue kept in place - worker periodic tmp_sweep reclaims the directory once the residual mount reference is gone; remove manually if it still exists"
        );
    }
}

impl Drop for BuildCleanupGuard {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            // 正常路径必须 run().await 消费 guard；Drop 仅 abort/runtime 关闭兜底：
            // 独立线程新建 tokio runtime 阻塞跑完清理，防 runtime 提前退出漏状态。
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                match runtime {
                    Ok(rt) => {
                        // 预算由 perform_cleanup 按步骤持有（umount/ref_dec 30s、complete
                        // 60s），此处不得叠加外层总预算——否则仍会静默丢弃 complete。
                        rt.block_on(perform_cleanup(inner, true));
                    }
                    Err(e) => {
                        warn!(
                            error = ?e,
                            "BuildCleanupGuard failed to create cleanup runtime; async cleanup skipped"
                        );
                    }
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    // ===== 门控决策表契约测试（跨平台，macOS 可跑） =====

    #[test]
    fn should_remove_env_temp_decision_table() {
        assert!(
            should_remove_env_temp(true),
            "umount completed: tempdir deletion must be allowed"
        );
        assert!(
            !should_remove_env_temp(false),
            "umount timed out: tempdir deletion must be skipped (live-mount hazard)"
        );
    }

    /// ===== timed_umount 两臂（跨平台：pending/ready 替身，无需真实挂载） =====

    #[tokio::test]
    async fn timed_umount_returns_true_when_umount_completes_in_budget() {
        let completed = timed_umount(
            std::future::ready(()),
            Duration::from_secs(1),
            "test-build",
            "",
        )
        .await;
        assert!(completed);
    }

    #[tokio::test]
    async fn timed_umount_returns_false_when_umount_exceeds_budget() {
        let start = std::time::Instant::now();
        let completed = timed_umount(
            std::future::pending::<()>(),
            Duration::from_millis(50),
            "test-build",
            "",
        )
        .await;
        assert!(
            !completed,
            "blocked umount must be reported as not completed"
        );
        assert!(
            start.elapsed() >= Duration::from_millis(50),
            "timeout must wait out the budget before giving up"
        );
    }

    /// ===== remove_env_temp_after_umount 决策行为（跨平台） =====

    #[tokio::test]
    async fn remove_env_temp_deletes_dir_after_umount_completed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().to_path_buf();
        remove_env_temp_after_umount(Some(temp), true, "test-build", "").await;
        assert!(
            !path.exists(),
            "umount completed: tempdir must be removed once the await returns"
        );
    }

    #[tokio::test]
    async fn remove_env_temp_keeps_dir_on_umount_timeout() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().to_path_buf();
        remove_env_temp_after_umount(Some(temp), false, "test-build", "").await;
        assert!(
            path.exists(),
            "umount timed out: tempdir must survive (deletion skipped; residue reclaimed by worker periodic tmp_sweep once the residual mount is gone)"
        );
        tokio::fs::remove_dir_all(&path).await.unwrap();
        assert!(
            !path.exists(),
            "test residue must be cleaned up by the test itself"
        );
    }

    #[tokio::test]
    async fn remove_env_temp_none_is_noop() {
        remove_env_temp_after_umount(None, true, "test-build", "").await;
        remove_env_temp_after_umount(None, false, "test-build", "").await;
    }

    // ===== perform_cleanup e2e（run 路径真实序列：umount → complete → 删除门控） =====
    // 注入取舍：真实 umount2(MNT_DETACH) 在非挂载点快速失败、hung NFS/FUSE 在
    // CI 不可构造，故经 `maybe_block_umount`（cfg(test) 门）包住 umount future
    // 实现可阻塞替身；生产构建整体编译剔除、MountGuard 零改动；快臂保留 Linux 门控。

    /// umount 阻塞门：Some(receiver) = armed（umount future 等待翻 true 才放行）。
    static UMOUNT_GATE: std::sync::Mutex<Option<tokio::sync::watch::Receiver<bool>>> =
        std::sync::Mutex::new(None);

    /// 两臂 e2e 互斥：armed 窗口内不允许其他 perform_cleanup 测试并发进入门。
    static E2E_SERIALIZER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// 被 perform_cleanup 内 cfg(test) 行调用的门包装（见上文注入点说明）。
    pub(super) async fn maybe_block_umount<F>(umount: F)
    where
        F: std::future::Future<Output = ()>,
    {
        let rx = UMOUNT_GATE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(mut rx) = rx {
            let _ = rx.wait_for(|open| *open).await;
        }
        umount.await;
    }

    /// 构造完整 BuildCleanupInner（真实 sqlite StateStore + 真实 pending BuildLifecycle + 独立 env tempdir），句柄供断言。
    #[allow(clippy::type_complexity)]
    async fn make_cleanup_inner() -> (
        BuildCleanupInner,
        Arc<crate::state::StateStore>,
        tempfile::TempDir,
        std::path::PathBuf,
        i64,
    ) {
        let db_tmp = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::state::StateStore::new(db_tmp.path()).await.unwrap());
        let lifecycle = crate::engine::BuildLifecycle::new(
            state.clone(),
            "fedora",
            "cleanup-guard-test",
            None,
            None,
            0,
        )
        .await
        .unwrap();
        let build_id = lifecycle.build_id();
        let env_temp = tempfile::tempdir().unwrap();
        let env_path = env_temp.path().to_path_buf();
        let inner = BuildCleanupInner {
            lifecycle,
            mount_guard: MountGuard::new(),
            outcome: BuildOutcome::Succeeded,
            result_dir: db_tmp.path().join("results").to_string_lossy().into_owned(),
            layer_digest: None,
            state: state.clone(),
            shared_layer_gc_grace_hours: 168,
            env_temp: Some(env_temp),
        };
        (inner, state, db_tmp, env_path, build_id)
    }

    /// 超时臂（跨平台）：umount 被门卡 → 50ms 预算耗尽 → complete() 照常落终态，
    /// 全程 temp 绝不能被删（空 tempdir 不在 tmp_sweep 形态 A 签名内）；
    /// 回归（挪回 umount 前 / 去门控）在此变红。
    #[tokio::test]
    async fn perform_cleanup_umount_timeout_skips_temp_deletion_and_completes_state() {
        let _serial = E2E_SERIALIZER.lock().await;
        let (inner, state, _db_tmp, env_path, build_id) = make_cleanup_inner().await;

        let (gate_tx, gate_rx) = tokio::sync::watch::channel(false);
        *UMOUNT_GATE.lock().unwrap_or_else(|e| e.into_inner()) = Some(gate_rx);

        let handle = tokio::spawn(perform_cleanup_with_budget(
            inner,
            false,
            Duration::from_millis(50),
        ));

        // 轮询至 complete 落库（umount 仍被门卡的窗口内），期间 temp 必须存活。
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                env_path.exists(),
                "env tempdir must never be deleted while umount is in flight"
            );
            if let Some(record) = state.get_build(build_id).await.unwrap() {
                if record.phase == "succeeded" {
                    break;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "perform_cleanup did not reach complete within 5s"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // 放行门、等清理任务收尾（umount future 已被 50ms 超时丢弃，放行只是撤防）。
        let _ = gate_tx.send(true);
        handle.await.unwrap();

        assert!(
            env_path.exists(),
            "umount timeout must skip env tempdir deletion (residue persists; worker periodic tmp_sweep reclaims it once the residual mount is gone)"
        );

        tokio::fs::remove_dir_all(&env_path).await.unwrap();
        assert!(
            !env_path.exists(),
            "test residue must be cleaned up by the test itself"
        );

        *UMOUNT_GATE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// 快臂（Linux 门控，真实 umount2）：非挂载点使 umount2(MNT_DETACH) 立即
    /// EINVAL 快速失败（记入 STALE_UMOUNTS 后正常返回）→ temp 必删、终态必落。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn perform_cleanup_umount_fail_fast_still_removes_env_temp() {
        let _serial = E2E_SERIALIZER.lock().await;
        let (mut inner, state, _db_tmp, env_path, build_id) = make_cleanup_inner().await;
        let not_a_mount = tempfile::tempdir().unwrap();
        inner.mount_guard.push(not_a_mount.path().to_path_buf());

        perform_cleanup_with_budget(inner, false, DEFAULT_STEP_BUDGET).await;

        assert!(
            !env_path.exists(),
            "umount step returned within budget: env tempdir must be removed"
        );
        let record = state.get_build(build_id).await.unwrap().unwrap();
        assert_eq!(
            record.phase, "succeeded",
            "complete must land on fast path too"
        );

        // 快速失败 umount 已记入 STALE_UMOUNTS 供重试；取走清空，不外溢其他测试。
        let stale = crate::engine::mount_guard::take_stale_umounts();
        assert!(
            stale.contains(&not_a_mount.path().to_path_buf()),
            "fast-fail umount must be recorded in STALE_UMOUNTS for retry"
        );
    }
}
