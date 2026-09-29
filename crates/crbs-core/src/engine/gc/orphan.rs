// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 引擎侧孤儿挂载回收与僵尸构建修复。

use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::engine::orphan;
use crate::engine::BuildEngine;

/// 孤儿挂载清理的三个扫描域（crbs_root / tmpfs_dir / tmp_dir），必须取引擎
/// pin 后的运行时配置：重读磁盘全局配置会扫错域、或在配置加载失败时静默
/// 回落 /var/lib/crbs 等默认根（误判/漏判孤儿）。
#[derive(Debug, Clone)]
pub struct OrphanScanRoots {
    /// 数据根：其下（products/、results/ 等）的残留挂载属孤儿候选。
    pub crbs_root: PathBuf,
    /// tmpfs 构建域（默认 /dev/shm）：其下 `.tmp*/` 容器挂载属孤儿候选。
    pub tmpfs_dir: PathBuf,
    /// 磁盘构建临时域（默认 {crbs_root}/tmp）：其下 `.tmp*/` 容器挂载属孤儿候选。
    pub tmp_dir: PathBuf,
}

impl OrphanScanRoots {
    /// 从引擎运行时配置取扫描域（pin 后的真值，不读磁盘配置）。
    pub fn from_engine_config(config: &crate::config::Config) -> Self {
        Self {
            crbs_root: config.crbs_root.clone(),
            tmpfs_dir: config.tmpfs_dir.clone(),
            tmp_dir: config.tmp_dir.clone(),
        }
    }
}

impl BuildEngine {
    /// 扫描并清理指定产品根目录下的孤儿挂载点。守卫必须全局而非按产品：
    /// umount 扫描/卸载范围是全局的，误卸会跨产品杀掉其它产品正在构建的
    /// 挂载。init 路径持 `.init.lock`（Exclusive），shell 路径的
    /// `acquire_shell_lock()`（Shared）不构成跨产品互斥——安全边界是全局
    /// 活跃 build 守卫，umount 前另有第二防线 `post_scan_guard`。
    pub async fn cleanup_orphan_mounts_for_product(
        product_root: &Path,
        product: &str,
        scan_roots: &OrphanScanRoots,
        state: &crate::state::StateStore,
    ) {
        if should_skip_orphan_cleanup(state).await {
            return;
        }

        let tmp_dirs: Vec<&std::path::Path> = vec![&scan_roots.tmpfs_dir, &scan_roots.tmp_dir];
        let mounts =
            orphan::scan_all_orphan_mounts(&[product_root], &scan_roots.crbs_root, &tmp_dirs).await;

        if mounts.is_empty() {
            return;
        }

        let Some(mounts) = post_scan_guard(mounts, state, "/proc/mounts").await else {
            return;
        };
        if mounts.is_empty() {
            return;
        }

        info!(
            count = mounts.len(),
            product = product,
            "crbs: cleaning up orphan mount(s) from previous run"
        );
        let cleaned = orphan::umount_all(mounts).await.len();
        info!(cleaned, "Orphan mounts cleaned");

        let stale = crate::engine::mount_guard::take_stale_umounts();
        if !stale.is_empty() {
            info!(count = stale.len(), "Retrying stale umounts");
            let mut retry_cleaned = 0usize;
            for m in stale {
                let path = m.clone();
                match crate::privilege::umount_detach(path.clone()).await {
                    Ok(()) => {
                        retry_cleaned += 1;
                    }
                    Err(e) => {
                        warn!(path = %m.display(), error = %e, "Retry umount failed");
                        if let Ok(mut s) = crate::engine::mount_guard::STALE_UMOUNTS.lock() {
                            s.push(m);
                        }
                    }
                }
            }
            info!(retry_cleaned, "Stale umounts retried");
        }
    }
}

/// 全局孤儿清理守卫：先全局修复僵尸构建记录（固定 product = None；只修本
/// 产品会让其它产品的 building 僵尸记录令守卫永久命中、清理静默失效），再
/// 判断是否跳过。返回 `true` = 存在活跃 build 或查询失败（宁不清理不误卸）。
pub(crate) async fn should_skip_orphan_cleanup(state: &crate::state::StateStore) -> bool {
    should_skip_orphan_cleanup_from(state, "/proc/mounts").await
}

/// [`should_skip_orphan_cleanup`] 的内部实现，`mounts_file` 支持测试注入。
async fn should_skip_orphan_cleanup_from(
    state: &crate::state::StateStore,
    mounts_file: &str,
) -> bool {
    do_repair_zombie_builds(state, mounts_file).await;

    match state.count_building_builds().await {
        Ok(count) if count > 0 => {
            info!(
                count,
                "Skipping orphan mount cleanup: active builds in progress"
            );
            true
        }
        Ok(_) => false,
        Err(e) => {
            warn!(error = %e, "Failed to query active builds, skipping orphan cleanup");
            true
        }
    }
}

/// [`cleanup_orphan_mounts_for_product`] 的扫描后第二防线：首检守卫只覆盖
/// 扫描开始前，扫描期间新启动构建的挂载可能已被本轮扫进孤儿集。umount 前
/// ①守卫复检，活跃 build 或查询失败 → 返回 `None` 放弃本轮；②
/// [`orphan::filter_active_builds`] 摘除活跃 result_dir 下挂载，覆盖复检到
/// umount 间的残余窗口（tempdir 下 chroot 内挂载无法按 result_dir 识别，见其限制说明）。
async fn post_scan_guard(
    mounts: Vec<orphan::OrphanMount>,
    state: &crate::state::StateStore,
    mounts_file: &str,
) -> Option<Vec<orphan::OrphanMount>> {
    // 复检重复跑一次僵尸修复：修复幂等（已修复记录不再命中 stale 条件）。
    if should_skip_orphan_cleanup_from(state, mounts_file).await {
        warn!("Abandoning orphan mount cleanup round: active build appeared during scan");
        return None;
    }
    match orphan::filter_active_builds(mounts, state).await {
        Ok(filtered) => Some(filtered),
        Err(e) => {
            warn!(
                error = %e,
                "Failed to filter mounts of active builds, abandoning cleanup round"
            );
            None
        }
    }
}

/// 全局修复僵尸构建记录（gc 入口调用）：building/pending 超 30 分钟、
/// `crbs_pid` 已死且无次级存活信号 → 标记 failed。
pub async fn repair_zombie_builds(state: &crate::state::StateStore) {
    do_repair_zombie_builds(state, "/proc/mounts").await;
}

/// 全局僵尸构建修复的公共实现（存活判定见 [`is_zombie_build`]；`mounts_file` 测试可注入）。
async fn do_repair_zombie_builds(state: &crate::state::StateStore, mounts_file: &str) {
    const STALE_MINUTES: i64 = 30;

    let stale = match state.list_stale_builds(STALE_MINUTES, None).await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "Failed to list stale builds");
            return;
        }
    };

    if stale.is_empty() {
        return;
    }

    // 收集 stale builds 的 result_dir 作为扫描根（scan_mounts_from 需要非空 roots）
    let mut scan_roots = Vec::new();
    for b in &stale {
        if let Some(ref d) = b.result_dir {
            if let Ok(canon) = tokio::fs::canonicalize(d).await {
                scan_roots.push(canon);
            }
        }
    }

    let scan_refs: Vec<&std::path::Path> = scan_roots.iter().map(|p| p.as_path()).collect();
    let active_mounts = match orphan::scan_mounts_from(mounts_file, &scan_refs).await {
        Ok(mounts) => mounts,
        Err(e) => {
            warn!(error = %e, "Failed to scan /proc/mounts, skipping zombie repair");
            return;
        }
    };

    let mut zombies = Vec::new();
    for b in stale {
        if is_zombie_build(&b, &active_mounts).await {
            zombies.push(b.id);
        }
    }

    if !zombies.is_empty() {
        warn!(count = zombies.len(), "Zombie builds detected, repairing");
        match state.repair_stale_builds(&zombies).await {
            Ok(n) => info!(repaired = n, "Zombie builds repaired"),
            Err(e) => warn!(error = %e, "Failed to repair zombie builds"),
        }
    }
}

/// 判断超时构建记录是否为僵尸，以 `crbs_pid` 判存活：存活 → 非僵尸（超阈值
/// 也不误杀）；NULL → 远程 worker 构建，生命周期由 worker 上报推进，server
/// 侧不判定、视同存活；已死 → 以 [`has_active_overlay_mount`] 次级确认，
/// 仍有挂载保守视为存活。不能只看挂载：活跃构建挂载点全在其临时目录
/// {tmp}/.tmpXXX/root 下、不会落在 result_dir（bind 源路径）之下——仅凭
/// 挂载会把超阈值活跃构建误判为僵尸（标 failed + 递减 layer 引用 + 误卸挂载）。
async fn is_zombie_build(
    build: &crate::state::BuildRecord,
    active_mounts: &[orphan::OrphanMount],
) -> bool {
    match build.crbs_pid {
        Some(pid) if crate::util::is_process_alive(pid).await => false,
        None => false,
        Some(_) => !has_active_overlay_mount(build, active_mounts).await,
    }
}

/// result_dir 下是否有挂载（仅 pid 已死时的次级确认）："无挂载"不能证明
/// 已死（活跃构建挂载点不在其下，见 [`is_zombie_build`]）；有挂载保守视为存活。
async fn has_active_overlay_mount(
    build: &crate::state::BuildRecord,
    active_mounts: &[orphan::OrphanMount],
) -> bool {
    let Some(ref dir) = build.result_dir else {
        return false;
    };
    let result_dir = std::path::Path::new(dir);
    match tokio::fs::try_exists(result_dir).await {
        Ok(false) | Err(_) => return false,
        Ok(true) => {}
    }
    active_mounts.iter().any(|m| m.path.starts_with(result_dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn dummy_build_record(
        result_dir: Option<&str>,
        crbs_pid: Option<i64>,
    ) -> crate::state::BuildRecord {
        crate::state::BuildRecord {
            id: 1,
            product: "p".to_string(),
            pkg_name: "pkg".to_string(),
            name: "pkg".to_string(),
            version: "1.0".to_string(),
            release: "1".to_string(),
            phase: "building".to_string(),
            result_dir: result_dir.map(|s| s.to_string()),
            srpm_path: None,
            started_at: None,
            completed_at: None,
            duration: None,
            layer_digest: None,
            base_os_digest: None,
            backend: None,
            user: "user".to_string(),
            user_id: Some(1),
            crbs_pid,
            rpms: vec![],
            signed: false,
            priority: 0,
            arch: None,
            task_id: None,
            error_summary: None,
            deterministic: false,
            repo_publish: true,
            repo_consume: true,
            canonical_srpm_sha256: None,
            peak_rss_kb: None,
            peak_total_kb: None,
            cpu_secs: None,
            cpu_p90_cores: None,
            disk_wbytes: None,
            oom_killed: None,
            sample_backend: None,
            sample_ncpu: None,
            peak_tmpfs_kb: None,
            req_min_mem_kb: None,
            req_min_ncpu: None,
            req_min_disk_kb: None,
        }
    }

    /// pid 存活（本测试进程）→ 非僵尸（result_dir 下无挂载也不误判）。
    #[tokio::test]
    async fn zombie_check_false_when_pid_alive() {
        let tmp = TempDir::new().unwrap();
        let result_dir = tmp.path().join("result");
        std::fs::create_dir(&result_dir).unwrap();

        let build = dummy_build_record(
            Some(result_dir.to_str().unwrap()),
            Some(std::process::id() as i64),
        );
        assert!(!is_zombie_build(&build, &[]).await);
    }

    /// pid 已死且 result_dir 下无挂载 → 僵尸。
    #[tokio::test]
    async fn zombie_check_true_when_pid_dead_and_no_mount() {
        let tmp = TempDir::new().unwrap();
        let result_dir = tmp.path().join("result");
        std::fs::create_dir(&result_dir).unwrap();

        let build = dummy_build_record(Some(result_dir.to_str().unwrap()), Some(999_999));
        assert!(is_zombie_build(&build, &[]).await);
    }

    /// pid 已死但 result_dir 下仍有挂载 → 次级确认命中，保守视为存活。
    #[tokio::test]
    async fn zombie_check_false_when_pid_dead_but_mount_under_result_dir() {
        let tmp = TempDir::new().unwrap();
        let result_dir = tmp.path().join("result");
        std::fs::create_dir(&result_dir).unwrap();
        let sub = result_dir.join("sub");
        std::fs::create_dir(&sub).unwrap();

        let build = dummy_build_record(Some(result_dir.to_str().unwrap()), Some(999_999));
        let mounts = vec![orphan::OrphanMount {
            path: sub,
            fstype: "overlay".to_string(),
        }];
        assert!(!is_zombie_build(&build, &mounts).await);
    }

    /// crbs_pid 为 NULL（远程 worker 构建）→ 不判定，视同存活。
    #[tokio::test]
    async fn zombie_check_false_when_pid_null_remote() {
        let tmp = TempDir::new().unwrap();
        let result_dir = tmp.path().join("result");
        std::fs::create_dir(&result_dir).unwrap();

        let build = dummy_build_record(Some(result_dir.to_str().unwrap()), None);
        assert!(!is_zombie_build(&build, &[]).await);
    }

    /// 次级挂载确认：result_dir 下有挂载 → true。
    #[tokio::test]
    async fn mount_check_true_when_mount_under_result_dir() {
        let tmp = TempDir::new().unwrap();
        let result_dir = tmp.path().join("result");
        std::fs::create_dir(&result_dir).unwrap();
        let sub = result_dir.join("sub");
        std::fs::create_dir(&sub).unwrap();

        let build = dummy_build_record(Some(result_dir.to_str().unwrap()), None);
        let mounts = vec![orphan::OrphanMount {
            path: sub,
            fstype: "overlay".to_string(),
        }];
        assert!(has_active_overlay_mount(&build, &mounts).await);
    }

    /// 次级挂载确认：挂载在其它目录 → false。
    #[tokio::test]
    async fn mount_check_false_when_no_mount_under_result_dir() {
        let tmp = TempDir::new().unwrap();
        let result_dir = tmp.path().join("result");
        std::fs::create_dir(&result_dir).unwrap();

        let build = dummy_build_record(Some(result_dir.to_str().unwrap()), None);
        let mounts = vec![orphan::OrphanMount {
            path: tmp.path().join("other"),
            fstype: "overlay".to_string(),
        }];
        assert!(!has_active_overlay_mount(&build, &mounts).await);
    }

    /// 次级挂载确认：result_dir 缺失 → false。
    #[tokio::test]
    async fn mount_check_false_when_result_dir_none_or_missing() {
        let build = dummy_build_record(None, None);
        assert!(!has_active_overlay_mount(&build, &[]).await);

        let tmp = TempDir::new().unwrap();
        let result_dir = tmp.path().join("missing");
        let build = dummy_build_record(Some(result_dir.to_str().unwrap()), None);
        assert!(!has_active_overlay_mount(&build, &[]).await);
    }

    use crate::state::test_state::{create_test_store, set_build_started_at};
    use crate::state::BuildInsert;

    /// builds.task_id NOT NULL：building 行挂到先插好的本地任务行上。
    async fn building_insert(
        store: &crate::state::StateStore,
        product: &'static str,
        result_dir: Option<&'static str>,
        crbs_pid: Option<i64>,
    ) -> BuildInsert<'static> {
        let task_id = crate::state::test_state::seed_task(store, product, "hello").await;
        BuildInsert {
            product,
            pkg_name: "hello",
            phase: "building",
            result_dir,
            backend: "chroot",
            user: "test",
            crbs_pid,
            task_id: Some(task_id),
            ..Default::default()
        }
    }

    // ① 其它产品有真实活跃 build（未超时）→ 全局守卫命中，跳过清理。
    #[tokio::test]
    async fn guard_skips_when_other_product_has_active_build() {
        let (store, _tmp) = create_test_store().await;
        store
            .insert_build(building_insert(&store, "product-y", None, None).await)
            .await
            .unwrap();

        // mounts_file 空文件即可：记录未超时，不会真正扫描
        let td = TempDir::new().unwrap();
        let empty_mounts = td.path().join("empty_mounts");
        tokio::fs::write(&empty_mounts, b"").await.unwrap();

        let skip = should_skip_orphan_cleanup_from(&store, empty_mounts.to_str().unwrap()).await;
        assert!(skip, "其它产品有活跃 build 时必须跳过全局孤儿清理");
    }

    // ①b 超时但 pid 存活的 build（如长时间构建）→ 不是僵尸，守卫仍命中。
    #[tokio::test]
    async fn guard_skips_when_stale_build_process_alive() {
        let (store, _tmp) = create_test_store().await;
        let id = store
            .insert_build(
                building_insert(
                    &store,
                    "product-y",
                    Some("/nonexistent/crbs/slow-build"),
                    Some(std::process::id() as i64),
                )
                .await,
            )
            .await
            .unwrap();
        set_build_started_at(&store, id, "-60 minutes").await;
        let td = TempDir::new().unwrap();
        let empty_mounts = td.path().join("empty_mounts");
        tokio::fs::write(&empty_mounts, b"").await.unwrap();

        let skip = should_skip_orphan_cleanup_from(&store, empty_mounts.to_str().unwrap()).await;
        assert!(skip, "超时但 pid 存活的构建必须保留，并令守卫跳过清理");

        let rec = store.get_build(id).await.unwrap().unwrap();
        assert_eq!(rec.phase, "building", "pid 存活的超时构建不能被误标 failed");
    }

    // ② 其它产品有僵尸记录（超时 + pid 已死 + 无挂载）→ 先被全局修复，不再挡路。
    #[tokio::test]
    async fn guard_repairs_other_product_zombie_then_proceeds() {
        let (store, _tmp) = create_test_store().await;
        let id = store
            .insert_build(
                building_insert(
                    &store,
                    "product-y",
                    Some("/nonexistent/crbs/zombie"),
                    Some(999_999),
                )
                .await,
            )
            .await
            .unwrap();
        set_build_started_at(&store, id, "-60 minutes").await;

        let td = TempDir::new().unwrap();
        let empty_mounts = td.path().join("empty_mounts");
        tokio::fs::write(&empty_mounts, b"").await.unwrap();

        let skip = should_skip_orphan_cleanup_from(&store, empty_mounts.to_str().unwrap()).await;
        assert!(!skip, "僵尸记录应先被全局修复，不应永久阻塞孤儿清理");

        let rec = store.get_build(id).await.unwrap().unwrap();
        assert_eq!(
            rec.phase, "failed",
            "超时、pid 已死且无挂载的 building 记录应被修复为 failed"
        );
    }

    // ③ 全局空闲 → 正常进入扫描（不跳过）。
    #[tokio::test]
    async fn guard_proceeds_when_globally_idle() {
        let (store, _tmp) = create_test_store().await;

        let td = TempDir::new().unwrap();
        let empty_mounts = td.path().join("empty_mounts");
        tokio::fs::write(&empty_mounts, b"").await.unwrap();

        let skip = should_skip_orphan_cleanup_from(&store, empty_mounts.to_str().unwrap()).await;
        assert!(!skip, "全局无活跃 build 时应正常进入孤儿清理扫描");
    }

    // ④ 扫描后守卫复检：轮内出现活跃 build → 放弃本轮（None）。
    #[tokio::test]
    async fn post_scan_guard_abandons_when_build_became_active() {
        let (store, _tmp) = create_test_store().await;
        store
            .insert_build(building_insert(&store, "product-y", None, None).await)
            .await
            .unwrap();

        let td = TempDir::new().unwrap();
        let empty_mounts = td.path().join("empty_mounts");
        tokio::fs::write(&empty_mounts, b"").await.unwrap();

        let mounts = vec![orphan::OrphanMount {
            path: std::path::PathBuf::from("/tmp/orphan-candidate"),
            fstype: "overlay".to_string(),
        }];
        let out = post_scan_guard(mounts, &store, empty_mounts.to_str().unwrap()).await;
        assert!(out.is_none(), "扫描期间出现活跃 build 必须放弃本轮 umount");
    }

    // ⑤ 全局空闲 → 复检通过，挂载集原样通过。
    #[tokio::test]
    async fn post_scan_guard_passes_when_globally_idle() {
        let (store, _tmp) = create_test_store().await;

        let td = TempDir::new().unwrap();
        let empty_mounts = td.path().join("empty_mounts");
        tokio::fs::write(&empty_mounts, b"").await.unwrap();

        let mounts = vec![orphan::OrphanMount {
            path: std::path::PathBuf::from("/tmp/orphan-candidate"),
            fstype: "overlay".to_string(),
        }];
        let out = post_scan_guard(mounts, &store, empty_mounts.to_str().unwrap()).await;
        let out = out.expect("全局空闲时复检必须通过");
        assert_eq!(out.len(), 1, "无活跃 build 时挂载集不得被过滤");
    }

    // ---- 扫描域参数化（pin 跟随）----

    /// 最小引擎运行时配置：只填三个扫描域字段，其余走 Default。
    fn engine_config_with_scan_domains(
        crbs_root: &std::path::Path,
        tmpfs_dir: &std::path::Path,
        tmp_dir: &std::path::Path,
    ) -> crate::config::Config {
        crate::config::Config {
            crbs_root: crbs_root.to_path_buf(),
            tmpfs_dir: tmpfs_dir.to_path_buf(),
            tmp_dir: tmp_dir.to_path_buf(),
            ..Default::default()
        }
    }

    /// 回归：扫描域必须原样跟随引擎 pin 后配置，不重读全局配置（见 [`OrphanScanRoots`]）。
    #[test]
    fn orphan_scan_roots_follow_engine_config_pin() {
        let tmp = TempDir::new().unwrap();
        let pinned_root = tmp.path().join("pin-root");
        let pinned_tmpfs = tmp.path().join("pin-shm");
        let pinned_tmp = tmp.path().join("pin-tmp");
        let config = engine_config_with_scan_domains(&pinned_root, &pinned_tmpfs, &pinned_tmp);

        let roots = OrphanScanRoots::from_engine_config(&config);

        assert_eq!(roots.crbs_root, pinned_root);
        assert_eq!(roots.tmpfs_dir, pinned_tmpfs);
        assert_eq!(roots.tmp_dir, pinned_tmp);
        // 钉住"pin 生效"前提：三域互不相同且都不是全局默认值。
        assert_ne!(roots.crbs_root, roots.tmpfs_dir);
        assert_ne!(roots.crbs_root, PathBuf::from("/var/lib/crbs"));
        assert_ne!(roots.tmpfs_dir, PathBuf::from("/dev/shm"));
        assert_ne!(roots.tmp_dir, PathBuf::from("/var/tmp"));
    }

    /// 回归：合成挂载表按 pin 域命中、全局默认域不可见——孤儿判定消费传入
    /// 参数而非重读全局配置。合成 mounts 注入，非 Linux 可测。
    #[tokio::test]
    async fn scan_domain_selection_uses_passed_pin_not_global_default() {
        let tmp = TempDir::new().unwrap();
        let pinned_root = tmp.path().join("pin-root");
        let pinned_tmpfs = tmp.path().join("pin-shm");
        let pinned_tmp = tmp.path().join("pin-tmp");
        let mount_point = pinned_tmp.join(".tmpABC").join("root");

        let mounts_file = tmp.path().join("mounts");
        let line = format!(
            "overlay {} overlay rw,lowerdir=/x,upperdir=/y 0 0\n",
            mount_point.display()
        );
        tokio::fs::write(&mounts_file, line).await.unwrap();

        let pinned = OrphanScanRoots {
            crbs_root: pinned_root.clone(),
            tmpfs_dir: pinned_tmpfs.clone(),
            tmp_dir: pinned_tmp.clone(),
        };
        let tmp_dirs: Vec<&std::path::Path> = vec![&pinned.tmpfs_dir, &pinned.tmp_dir];
        let hits = crate::engine::orphan::scan_crbs_mounts_from(
            mounts_file.to_str().unwrap(),
            &pinned.crbs_root,
            &tmp_dirs,
        )
        .await
        .unwrap();
        assert_eq!(
            hits.len(),
            1,
            "pin 域下的 .tmp* 容器挂载必须被 pin 扫描命中"
        );
        assert_eq!(hits[0].path, mount_point);

        let global_shm = PathBuf::from("/dev/shm");
        let global_tmp = PathBuf::from("/var/tmp");
        let global_tmp_dirs: Vec<&std::path::Path> = vec![&global_shm, &global_tmp];
        let global_root = PathBuf::from("/var/lib/crbs");
        let misses = crate::engine::orphan::scan_crbs_mounts_from(
            mounts_file.to_str().unwrap(),
            &global_root,
            &global_tmp_dirs,
        )
        .await
        .unwrap();
        assert!(
            misses.is_empty(),
            "全局默认域不得命中 pin 域下的挂载: {misses:?}"
        );
    }
}
