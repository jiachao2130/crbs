// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::fs::OpenOptions;
use std::path::Path;
use std::time::Duration;

use chrono::Utc;
use fs4::fs_std::FileExt;

use crate::config::RepoConfig;
use crate::engine::shared_layer::cleanup::cleanup_layer_dir;
use crate::engine::shared_layer::create::{builddep_args, create_shared_layer_locked};
use crate::engine::shared_layer::lock::acquire_layer_lock;
use crate::engine::shared_layer::persist::restore_install_args;
use crate::engine::shared_layer::repo_fingerprint;
use crate::engine::shared_layer::ttl::{
    is_layer_stale, parse_stale_upper_timestamp, read_layer_timestamp, timestamp_marker,
    write_layer_timestamp, STALE_UPPER_TS_FORMAT,
};
use crate::engine::shared_layer::SharedLayerParams;

#[test]
fn shared_layer_dnf_commands_force_metadata_refresh() {
    // 层创建/恢复必须带 --refresh：dnf metadata_expire 48h 内不回源，陈旧
    // repodata 会在 TTL 内被长期复用（无层路径同要求，见 pipeline/tests.rs）。
    let args = builddep_args("/builddir/SPECS/pkg.spec");
    assert!(args.iter().any(|a| a == "--refresh"));
    assert_eq!(args[0], "builddep");
    assert_eq!(args[1], "-y");
    assert_eq!(args.last().unwrap(), "/builddir/SPECS/pkg.spec");

    let args = restore_install_args();
    assert!(args.iter().any(|a| a == "--refresh"));
    assert_eq!(args[0], "install");
}

/// 层内 builddep 固定关 weak deps（setopt 在列）：弱依赖非 BR 硬要求，关掉
/// 收窄装包集、降低构建环境方差。
#[test]
fn builddep_args_keep_weak_deps_disabled() {
    let args = builddep_args("/builddir/SPECS/pkg.spec");
    assert!(args.contains(&"--setopt=install_weak_deps=False".to_string()));
}

#[test]
fn repo_fingerprint_deterministic_and_sensitive() {
    let repo = |name: &str, url: &str, enabled: bool| RepoConfig {
        name: name.into(),
        baseurl: url.into(),
        enabled,
        ..Default::default()
    };
    let a = vec![
        repo("os", "https://x/os", true),
        repo("extras", "https://x/e", true),
    ];
    let b = vec![
        repo("extras", "https://x/e", true),
        repo("os", "https://x/os", true),
    ];
    assert_eq!(repo_fingerprint(&a), repo_fingerprint(&b));
    // baseurl / 开关任一变化 → 指纹不同（旧层失效）。
    let c = vec![
        repo("os", "https://x/os", true),
        repo("extras", "https://x/e2", true),
    ];
    assert_ne!(repo_fingerprint(&a), repo_fingerprint(&c));
    let d = vec![
        repo("os", "https://x/os", true),
        repo("extras", "https://x/e", false),
    ];
    assert_ne!(repo_fingerprint(&a), repo_fingerprint(&d));
    // 空仓库集 → 空指纹（只含空行分隔块）。
    assert_eq!(repo_fingerprint(&[]), "");

    // 影响 dnf 结果集的其余字段也必须进指纹。
    let with = |mut r: RepoConfig, f: &dyn Fn(&mut RepoConfig)| {
        f(&mut r);
        r
    };
    let base = repo("os", "https://x/os", true);
    let variants: Vec<(&str, RepoConfig)> = vec![
        ("gpgcheck", with(base.clone(), &|r| r.gpgcheck = true)),
        (
            "gpgkey",
            with(base.clone(), &|r| r.gpgkey = Some("https://x/key".into())),
        ),
        ("priority", with(base.clone(), &|r| r.priority = 50)),
        ("cost", with(base.clone(), &|r| r.cost = 500)),
        (
            "module_hotfixes",
            with(base.clone(), &|r| r.module_hotfixes = true),
        ),
        (
            "exclude",
            with(base.clone(), &|r| r.exclude = vec!["kernel*".into()]),
        ),
        (
            "includepkgs",
            with(base.clone(), &|r| r.includepkgs = vec!["bash".into()]),
        ),
        (
            "extra",
            with(base.clone(), &|r| {
                r.extra = Some("metadata_expire=3600\n".into())
            }),
        ),
    ];
    for (label, v) in &variants {
        assert_ne!(
            repo_fingerprint(std::slice::from_ref(&base)),
            repo_fingerprint(std::slice::from_ref(v)),
            "fingerprint must change when {label} changes"
        );
    }

    // exclude 是集合语义：书写顺序不影响指纹。
    let mut x1 = base.clone();
    x1.exclude = vec!["a*".into(), "b*".into()];
    let mut x2 = base.clone();
    x2.exclude = vec!["b*".into(), "a*".into()];
    assert_eq!(repo_fingerprint(&[x1]), repo_fingerprint(&[x2]));
}

/// 返回按 `CRBS_TEST_TIMEOUT_SCALE` 线性缩放的等待时长（慢 CI 下竞争类 sleep 稳定用）。
fn scaled_millis(millis: u64) -> Duration {
    let scale = std::env::var("CRBS_TEST_TIMEOUT_SCALE")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(1.0)
        .max(0.0);
    Duration::from_millis((millis as f64 * scale).round() as u64)
}

/// 无竞争场景：直接获取锁并实际持有 flock。
#[tokio::test]
async fn test_acquire_lock_no_contention() {
    let tmp = tempfile::tempdir().unwrap();
    let lock_path = tmp.path().join(".lock");

    let _held_file = acquire_layer_lock(
        Duration::from_millis(10),
        Duration::from_secs(1),
        &lock_path,
        "test-digest",
    )
    .await
    .expect("acquire should succeed");

    let probe = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    assert!(
        probe.try_lock_exclusive().is_err(),
        "lock should be held by _held_file"
    );
}

/// `.complete` 已存在时仍然返回锁，由调用方判断是否过期。
#[tokio::test]
async fn test_acquire_lock_complete_marker_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let lock_path = tmp.path().join(".lock");

    std::fs::write(tmp.path().join(".complete"), "").unwrap();

    let _held_file = acquire_layer_lock(
        Duration::from_millis(10),
        Duration::from_secs(1),
        &lock_path,
        "test-digest",
    )
    .await
    .expect("should acquire lock even when .complete exists");

    let probe = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    assert!(probe.try_lock_exclusive().is_err(), "lock should be held");
}

/// 回归：wait 路径返回后锁必须仍持有——break 曾因 lock_file 出 scope drop 立即释放 flock。
#[tokio::test]
async fn test_lock_held_after_wait_path() {
    let tmp = tempfile::tempdir().unwrap();
    let lock_path = tmp.path().join(".lock");

    let blocker = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    blocker
        .try_lock_exclusive()
        .expect("blocker should get lock");

    let lock_path_clone = lock_path.clone();
    let task = tokio::spawn(async move {
        acquire_layer_lock(
            Duration::from_millis(20),
            Duration::from_secs(5),
            &lock_path_clone,
            "test-digest",
        )
        .await
    });

    // 等 task 进入 wait loop
    tokio::time::sleep(scaled_millis(100)).await;
    drop(blocker);

    let held_file = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .expect("task should complete within 3s")
        .expect("task should not panic")
        .expect("acquire should succeed");

    // 关键断言：新 fd try_lock_exclusive 必须失败（否则 held_file 已被提前 drop）。
    let probe = OpenOptions::new().write(true).open(&lock_path).unwrap();
    assert!(
        probe.try_lock_exclusive().is_err(),
        "BUG: lock not held after wait path (held_file dropped prematurely)"
    );

    // 高负载下 close 后锁释放对其他线程的可见性可能滞后一个调度节拍，轮询探测吸收噪声。
    drop(held_file);
    let mut released = false;
    for _ in 0..40 {
        let probe2 = OpenOptions::new().write(true).open(&lock_path).unwrap();
        if probe2.try_lock_exclusive().is_ok() {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(released, "lock should be released after held_file drops");
}

#[tokio::test]
async fn test_acquire_lock_timeout() {
    let tmp = tempfile::tempdir().unwrap();
    let lock_path = tmp.path().join(".lock");

    let blocker = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    blocker.try_lock_exclusive().unwrap();

    let result = acquire_layer_lock(
        Duration::from_millis(10),
        Duration::from_millis(100),
        &lock_path,
        "test-digest",
    )
    .await;

    assert!(result.is_err(), "should timeout");
}

/// TTL 未配置（None）按缺省 TTL（7 天）判定，并非永不过期。
#[tokio::test]
async fn test_is_layer_stale_none_uses_default_ttl() {
    let tmp = tempfile::tempdir().unwrap();
    let marker = timestamp_marker(tmp.path());

    // 时间戳缺失 → 过期（缺省 TTL 也走重建后重写时间戳的路径）。
    assert!(is_layer_stale(tmp.path(), None).await.unwrap());

    write_layer_timestamp(&marker).await.unwrap();
    assert!(!is_layer_stale(tmp.path(), None).await.unwrap());

    let old = Utc::now() - chrono::Duration::days(8);
    tokio::fs::write(&marker, old.to_rfc3339()).await.unwrap();
    assert!(is_layer_stale(tmp.path(), None).await.unwrap());

    // 显式配置覆盖缺省：更大的 TTL 下同一时间戳不过期。
    let longer = Duration::from_secs(30 * 24 * 3600);
    assert!(!is_layer_stale(tmp.path(), Some(longer)).await.unwrap());
}

#[tokio::test]
async fn test_is_layer_stale_fresh_and_stale() {
    let tmp = tempfile::tempdir().unwrap();
    let ttl = Duration::from_secs(60);

    write_layer_timestamp(&timestamp_marker(tmp.path()))
        .await
        .unwrap();
    assert!(!is_layer_stale(tmp.path(), Some(ttl)).await.unwrap());

    let old = Utc::now() - chrono::Duration::seconds(120);
    tokio::fs::write(&timestamp_marker(tmp.path()), old.to_rfc3339())
        .await
        .unwrap();
    assert!(is_layer_stale(tmp.path(), Some(ttl)).await.unwrap());
}

#[tokio::test]
async fn test_is_layer_stale_missing_timestamp_treated_as_stale() {
    let tmp = tempfile::tempdir().unwrap();
    let ttl = Duration::from_secs(1);

    assert!(
        is_layer_stale(tmp.path(), Some(ttl)).await.unwrap(),
        "missing timestamp should be treated as stale"
    );
    assert!(
        !timestamp_marker(tmp.path()).exists(),
        ".timestamp should not be created by staleness check"
    );
}

#[tokio::test]
async fn test_read_layer_timestamp_io_error_fails_closed() {
    // I/O 错误必须显式 Err（fail-closed），与"缺失"（Ok(None)，调用方按过期重建）区分。
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let path = timestamp_marker(tmp.path());

    assert!(read_layer_timestamp(&path).await.unwrap().is_none());

    // 无读权限 → Err（fail-closed）。root 不受权限位限制，退化为 Ok。
    tokio::fs::write(&path, "2026-01-01T00:00:00Z")
        .await
        .unwrap();
    tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
        .await
        .unwrap();
    match read_layer_timestamp(&path).await {
        Err(_) => {} // 非 root：期望路径
        Ok(v) => assert!(v.is_some(), "root 下权限位不生效时仍应读到值"),
    }
}

/// 构造 stale upper 目录名（与 create.rs rename-aside 共用同一格式常量）。
fn stale_upper_name(renamed_at: chrono::DateTime<Utc>) -> String {
    format!("upper.stale.{}", renamed_at.format(STALE_UPPER_TS_FORMAT))
}

#[test]
fn test_parse_stale_upper_timestamp_valid_and_invalid() {
    use chrono::TimeZone;
    let ts = parse_stale_upper_timestamp("upper.stale.20260824-101500").unwrap();
    assert_eq!(ts, Utc.with_ymd_and_hms(2026, 8, 24, 10, 15, 0).unwrap());

    // 非 stale-upper 名 / 时间戳格式错误 → None（调用方保守保留）。
    assert!(parse_stale_upper_timestamp("upper").is_none());
    assert!(parse_stale_upper_timestamp("upper.stale.").is_none());
    assert!(parse_stale_upper_timestamp("upper.stale.20260824").is_none());
    assert!(parse_stale_upper_timestamp("upper.stale.garbage").is_none());
}

/// stale-upper 时间戳写读往返：写侧命名（STALE_UPPER_TS_FORMAT）与读侧解析
/// 必须自洽，防"可写不可解析"的格式上线后 parse 恒 None 静默泄漏；截断亚秒再比较（%S 无亚秒位）。
#[test]
fn test_stale_upper_timestamp_roundtrip() {
    use chrono::SubsecRound;
    let now = Utc::now().trunc_subsecs(0);
    let parsed = parse_stale_upper_timestamp(&stale_upper_name(now)).unwrap();
    assert_eq!(parsed, now);
}

#[tokio::test]
async fn test_cleanup_layer_dir_retains_stale_uppers_by_rename_timestamp() {
    // 回归：rename 保留原 mtime，保留判定必须用文件名内嵌的 rename 时间戳
    // 而非 mtime——两个 upper 的 mtime 都是"现在"，旧的（>24h）仍必须删除。
    let tmp = tempfile::tempdir().unwrap();
    let layer_dir = tmp.path().join("layer");
    tokio::fs::create_dir_all(&layer_dir).await.unwrap();

    let recent = layer_dir.join(stale_upper_name(Utc::now()));
    let old = layer_dir.join(stale_upper_name(Utc::now() - chrono::Duration::hours(25)));
    let unparsable = layer_dir.join("upper.stale.garbage");
    for dir in [&recent, &old, &unparsable] {
        tokio::fs::create_dir_all(dir).await.unwrap();
    }
    let lock = layer_dir.join(".lock");
    tokio::fs::write(&lock, "").await.unwrap();
    let log = layer_dir.join("builddep.log");
    tokio::fs::write(&log, "x").await.unwrap();
    let merged = layer_dir.join("merged");
    tokio::fs::create_dir_all(&merged).await.unwrap();

    cleanup_layer_dir(&layer_dir).await.unwrap();

    assert!(recent.exists(), "24h 内 rename 移走的 stale upper 必须保留");
    assert!(
        unparsable.exists(),
        "时间戳解析失败的 stale upper 必须保守保留"
    );
    assert!(!old.exists(), "rename 超过 24h 的 stale upper 必须删除");
    assert!(lock.exists(), ".lock 必须保留");
    assert!(!log.exists(), "普通残留文件必须删除");
    assert!(!merged.exists(), "merged 目录必须删除");
}

async fn state_store() -> (crate::state::StateStore, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    (
        crate::state::StateStore::new(tmp.path()).await.unwrap(),
        tmp,
    )
}

/// 构造 SharedLayerParams：base_os / srpm 指向不存在路径，创建流程在残留清理
/// 后挂载一步失败（非 root EPERM / 非 Linux 桩 EINVAL / ENOENT），断言"已走到创建路径"。
fn test_params<'a>(
    state: &'a crate::state::StateStore,
    base_os: &'a Path,
    srpm: &'a Path,
    staleness: Option<Duration>,
) -> SharedLayerParams<'a> {
    SharedLayerParams {
        product: "test",
        build_requires: &[],
        base_os_digest: "test-base-os-digest",
        repo_fingerprint: "",
        srpm,
        base_os,
        shared_layers_dir: Path::new("/nonexistent"),
        tmp_dir: Path::new("/nonexistent"),
        state,
        poll_interval: Duration::from_millis(10),
        timeout: Duration::from_secs(1),
        max_retries: 1,
        staleness,
        dnf_cache_enabled: false,
        dnf_cache_path: Path::new("/nonexistent"),
        package_cache_path: Path::new("/nonexistent"),
        record_provenance: false,
        cancel_token: None,
        operation_timeout: Some(Duration::from_secs(5)),
    }
}

/// 残留清理条件：有 upperdir 无 .complete（"先摘标志后 rename"窗口或创建
/// 中途硬崩溃残局）——创建必须清掉旧 upper 从头重建，不能叠旧内容（dnf
/// builddep 依赖已满足会 no-op，TTL 重建拿不到新版本）。直接调锁内创建入口
///（非 try_create_shared_layer 路径），断言 Err 不走 reuse、旧内容不残留。
#[tokio::test]
async fn test_create_cleans_upper_leftover_without_complete_marker() {
    let (store, _state_tmp) = state_store().await;
    let tmp = tempfile::tempdir().unwrap();
    let layer_dir = tmp.path().join("layer");
    let upperdir = layer_dir.join("upper");
    tokio::fs::create_dir_all(&upperdir).await.unwrap();
    tokio::fs::write(upperdir.join("old-content"), "stale")
        .await
        .unwrap();
    let complete_marker = layer_dir.join(".complete");

    let base_os = tmp.path().join("no-such-base-os");
    let srpm = tmp.path().join("no-such.src.rpm");
    let params = test_params(&store, &base_os, &srpm, None);

    let mut dir_touched = false;
    let result = create_shared_layer_locked(
        &params,
        "digest-leftover",
        &layer_dir,
        &upperdir,
        &complete_marker,
        &mut dir_touched,
    )
    .await;

    assert!(result.is_err(), "no .complete marker: must not reuse");
    assert!(dir_touched, "marker-less dir must be treated as touched");
    assert!(
        !upperdir.join("old-content").exists(),
        "leftover upper content must be cleaned before rebuild"
    );
}

/// ENOENT 崩溃残留分支：.complete 在但 upperdir 不在（崩溃残局）——陈旧
/// 重建必须走重建而非 reuse 返回不存在的 upperdir（reuse 恒 Ok，Err 即重建）。
#[tokio::test]
async fn test_stale_rebuild_with_missing_upper_rebuilds_instead_of_reuse() {
    let (store, _state_tmp) = state_store().await;
    let tmp = tempfile::tempdir().unwrap();
    let layer_dir = tmp.path().join("layer");
    tokio::fs::create_dir_all(&layer_dir).await.unwrap();
    let upperdir = layer_dir.join("upper");
    let complete_marker = layer_dir.join(".complete");
    tokio::fs::write(&complete_marker, "").await.unwrap();

    let base_os = tmp.path().join("no-such-base-os");
    let srpm = tmp.path().join("no-such.src.rpm");
    let params = test_params(&store, &base_os, &srpm, Some(Duration::from_secs(60)));

    let mut dir_touched = false;
    let result = create_shared_layer_locked(
        &params,
        "digest-enoent",
        &layer_dir,
        &upperdir,
        &complete_marker,
        &mut dir_touched,
    )
    .await;

    // 误 reuse 会返回不存在的 upperdir，该 digest 反复构建失败直到 GC 宽限期。
    assert!(result.is_err(), "missing upper: must rebuild, not reuse");
    assert!(
        dir_touched,
        "ENOENT residue branch must mark dir as touched"
    );
    assert!(
        !complete_marker.exists(),
        "stale marker must be removed before rename"
    );
}

// ===== 快路径复用（try_fast_path_reuse：try_lock + 锁内 inc/复核 + 对称回滚）=====

use crate::engine::shared_layer::{try_fast_path_reuse, FastPathOutcome};

/// 铺一个"已完成层"的目录与 DB 行，返回 (layer_dir, lock_path, complete_marker)。
async fn seed_complete_layer(
    root: &Path,
    store: &crate::state::StateStore,
    digest: &str,
    initial_ref: i64,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let layer_dir = root.join(digest);
    tokio::fs::create_dir_all(layer_dir.join("upper"))
        .await
        .unwrap();
    tokio::fs::write(layer_dir.join(".complete"), "")
        .await
        .unwrap();
    let upperdir = layer_dir.join("upper");
    store
        .insert_layer(digest, &upperdir.to_string_lossy(), "test", initial_ref)
        .await
        .unwrap();
    (
        layer_dir.clone(),
        layer_dir.join(".lock"),
        layer_dir.join(".complete"),
    )
}

#[tokio::test]
async fn fast_path_reuses_under_lock_and_incs_ref() {
    let (store, _state_tmp) = state_store().await;
    let tmp = tempfile::tempdir().unwrap();
    let (_dir, lock_path, complete_marker) =
        seed_complete_layer(tmp.path(), &store, "d-fast-ok", 1).await;

    let base_os = tmp.path().join("no-such-base-os");
    let srpm = tmp.path().join("no-such.src.rpm");
    let params = test_params(&store, &base_os, &srpm, None);

    let outcome = try_fast_path_reuse(&params, "d-fast-ok", &lock_path, &complete_marker)
        .await
        .unwrap();
    assert!(matches!(outcome, FastPathOutcome::Reused));
    assert_eq!(
        store.get_layer_ref_count("d-fast-ok").await.unwrap(),
        Some(2)
    );
}

/// 锁被占（GC/clean/重建持锁）：跳过快路径且不 inc——inc 只能发生在锁内，
/// 否则 GC 锁内复检 ref==0 后的删除段仍可能追上本次复用（TOCTOU）。
#[tokio::test]
async fn fast_path_falls_through_when_lock_held_and_does_not_inc() {
    let (store, _state_tmp) = state_store().await;
    let tmp = tempfile::tempdir().unwrap();
    let (_dir, lock_path, complete_marker) =
        seed_complete_layer(tmp.path(), &store, "d-fast-busy", 1).await;

    // 测试线程用 std flock 占住锁（与 fs4 tokio 同为 flock，跨 fd 冲突）。
    // File 必须先绑定再上锁：链式写在临时值上会让 File 立即 drop、锁随释。
    let held = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .unwrap();
    held.try_lock_exclusive().unwrap();
    let _held = held;

    let base_os = tmp.path().join("no-such-base-os");
    let srpm = tmp.path().join("no-such.src.rpm");
    let params = test_params(&store, &base_os, &srpm, None);

    let outcome = try_fast_path_reuse(&params, "d-fast-busy", &lock_path, &complete_marker)
        .await
        .unwrap();
    assert!(
        matches!(outcome, FastPathOutcome::FallThrough("digest lock held")),
        "busy lock must fall through, got {outcome:?}"
    );
    assert_eq!(
        store.get_layer_ref_count("d-fast-busy").await.unwrap(),
        Some(1),
        "fast path must not inc without holding the digest lock"
    );
}

/// 锁内 inc 成功但 .complete 已消失（目录被并发处置的残留）：对称回滚本次 inc，幽灵 ref 不落库。
#[tokio::test]
async fn fast_path_rolls_back_inc_when_complete_vanished() {
    let (store, _state_tmp) = state_store().await;
    let tmp = tempfile::tempdir().unwrap();
    let (dir, lock_path, _marker) =
        seed_complete_layer(tmp.path(), &store, "d-fast-ghost", 1).await;
    tokio::fs::remove_file(dir.join(".complete")).await.unwrap();

    let base_os = tmp.path().join("no-such-base-os");
    let srpm = tmp.path().join("no-such.src.rpm");
    let params = test_params(&store, &base_os, &srpm, None);

    let outcome = try_fast_path_reuse(&params, "d-fast-ghost", &lock_path, &dir.join(".complete"))
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        FastPathOutcome::FallThrough("complete marker vanished")
    ));
    assert_eq!(
        store.get_layer_ref_count("d-fast-ghost").await.unwrap(),
        Some(1),
        "the speculative inc must be symmetrically rolled back"
    );
}

/// .complete 在磁盘但 DB 行缺失（注册前崩溃）：未发生有效 inc 无需回滚，落锁内路径自愈注册。
#[tokio::test]
async fn fast_path_falls_through_without_inc_when_db_row_missing() {
    let (store, _state_tmp) = state_store().await;
    let tmp = tempfile::tempdir().unwrap();
    let layer_dir = tmp.path().join("d-fast-norow");
    tokio::fs::create_dir_all(layer_dir.join("upper"))
        .await
        .unwrap();
    tokio::fs::write(layer_dir.join(".complete"), "")
        .await
        .unwrap();

    let base_os = tmp.path().join("no-such-base-os");
    let srpm = tmp.path().join("no-such.src.rpm");
    let params = test_params(&store, &base_os, &srpm, None);

    let outcome = try_fast_path_reuse(
        &params,
        "d-fast-norow",
        &layer_dir.join(".lock"),
        &layer_dir.join(".complete"),
    )
    .await
    .unwrap();
    assert!(matches!(
        outcome,
        FastPathOutcome::FallThrough("db row missing")
    ));
    assert_eq!(
        store.get_layer_ref_count("d-fast-norow").await.unwrap(),
        None
    );
}

// ---- fix_layer_file_perms 权限收敛 ----

// Linux-only 直调（engine 域权限语义按 Linux 测试）。回归：fix 必须在文件创建后
// 调用才生效——0644 缺省形态 fix 后须收敛到 0660，fix 先于 create 则首建文件永不收敛。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn fix_layer_file_perms_converges_created_file_to_0660() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("packages.txt");
    std::fs::write(&path, b"pkg-1.0-1.noarch\n").unwrap();

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let before = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        before, 0o644,
        "precondition: file starts at umask default 0644"
    );

    super::fix_layer_file_perms(&path).await;

    let after = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(after, 0o660, "layer file must converge to 0660 after fix");
}
