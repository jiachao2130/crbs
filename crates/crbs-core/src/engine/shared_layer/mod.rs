// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! SharedLayer 恒用 chroot backend：dep-layer 是 dnf install 的纯文件系统产物（无
//! backend-sensitive 行为）、多 backend 共享 content-addressed cache、chroot 全 host 可用（nspawn 不一定）。

pub(crate) mod cleanup;
pub(crate) mod create;
pub(crate) mod lock;
pub(crate) mod persist;
pub(crate) mod ttl;

use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::engine::shared_layer::create::try_create_shared_layer;
use crate::engine::shared_layer::ttl::is_layer_stale;
use crate::error::CrbsError;

/// 在 SharedLayer 的 merged overlay 内执行命令并捕获输出，支持 cancel/timeout。
/// Command 经 PrivilegeBackend 构造：setuid 模式 Linux 直接 syscall chroot、非
/// Linux 保留外部 chroot 命令供开发编译；helper 模式经 crbs-priv-helper
/// spawn-chroot，主进程免 CAP_SYS_CHROOT。
pub(crate) async fn chroot_output_with_cancel(
    merged: &std::path::Path,
    program: &str,
    args: &[&str],
    cancel_token: Option<&tokio_util::sync::CancellationToken>,
    timeout: Option<std::time::Duration>,
) -> crate::Result<std::process::Output> {
    let mut cmd = layer_chroot_command(merged, program, args)?;
    cmd.env("TERM", "dumb")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    crate::engine::command::run_child_output_with_cancel_timeout(
        &mut cmd,
        cancel_token,
        timeout,
        "spawn chroot",
    )
    .await
}

/// 构造进入 SharedLayer merged 的 chroot Command，统一走 PrivilegeBackend；network=true
/// 时层内 dnf builddep / dnf install / rpm -qa 需要网络与宿主仓库回源，不做网络隔离。
fn layer_chroot_command(
    merged: &std::path::Path,
    program: &str,
    args: &[&str],
) -> crate::Result<tokio::process::Command> {
    let std_cmd = crate::privilege::get_privilege_backend()
        .spawn_chroot(merged, program, args, true)
        .map_err(|e| CrbsError::io_message(format!("setup chroot command {program}: {e}")))?;
    Ok(tokio::process::Command::from(std_cmd))
}

/// SharedLayer 创建参数。
pub(crate) struct SharedLayerParams<'a> {
    pub product: &'a str,
    pub build_requires: &'a [String],
    pub base_os_digest: &'a str,
    pub repo_fingerprint: &'a str,
    pub srpm: &'a Path,
    pub base_os: &'a Path,
    pub shared_layers_dir: &'a Path,
    pub tmp_dir: &'a Path,
    pub state: &'a crate::state::StateStore,
    pub poll_interval: std::time::Duration,
    pub timeout: std::time::Duration,
    pub max_retries: u32,
    pub staleness: Option<std::time::Duration>,
    pub dnf_cache_enabled: bool,
    pub dnf_cache_path: &'a Path,
    pub package_cache_path: &'a Path,
    pub record_provenance: bool,
    pub cancel_token: Option<&'a tokio_util::sync::CancellationToken>,
    pub operation_timeout: Option<std::time::Duration>,
}

/// 计算产品仓库配置的稳定指纹（参与 SharedLayer digest）：影响 dnf builddep
/// 结果集的仓库字段全部入指纹、任一变化令旧层失效重建——后续新增此类字段
/// 必须同步入指纹，否则配置变更被旧层缓存吞掉。
pub(crate) fn repo_fingerprint(repos: &[crate::config::RepoConfig]) -> String {
    let mut lines: Vec<String> = repos
        .iter()
        .map(|r| {
            // exclude/includepkgs 集合语义排序：消除书写顺序噪声，同集不同序不产生新 digest。
            let mut exclude = r.exclude.clone();
            exclude.sort();
            let mut includepkgs = r.includepkgs.clone();
            includepkgs.sort();
            format!(
                "{}|{}|{}|gpgcheck={}|gpgkey={}|priority={}|cost={}|\
                 module_hotfixes={}|exclude={}|includepkgs={}|extra={}",
                r.name,
                r.baseurl,
                r.enabled,
                r.gpgcheck,
                r.gpgkey.as_deref().unwrap_or(""),
                r.priority,
                r.cost,
                r.module_hotfixes,
                exclude.join(","),
                includepkgs.join(","),
                r.extra.as_deref().unwrap_or(""),
            )
        })
        .collect();
    lines.sort();
    lines.join("\n")
}

/// 复用 SharedLayer 前的统一引用计数入口：每次复用必须 inc，与 cleanup guard 的
/// 无条件 dec 对称，否则并发构建的 dec 把计数压 0、GC 在构建期间删仍在用的层；
/// inc 失败硬失败（层可能已被 GC 删、复用不安全），LayerNotFound 原样传播走自愈/回退。
pub(crate) async fn inc_layer_ref_on_reuse(
    state: &crate::state::StateStore,
    digest: &str,
) -> crate::Result<()> {
    state.layer_ref_inc(digest).await.map_err(|e| match e {
        CrbsError::LayerNotFound { .. } => e,
        e => CrbsError::io_message(format!(
            "increment SharedLayer ref_count on reuse for: {}",
            e
        )),
    })?;
    Ok(())
}

/// 返回 `(shared_layer_upperdir_path, digest)`；`Ok(None)` = 已降级无层构建
///（同 digest 并发首建超锁等待预算），调用方以 base_os 为唯一 lowerdir 继续。
pub(crate) async fn get_or_create_shared_layer(
    params: SharedLayerParams<'_>,
) -> crate::Result<Option<(PathBuf, String)>> {
    // digest 必须含 record_provenance：false 的层不写 .lockfile，被 true 的构建
    // 复用会让 build_packages.json 缺少 builddep 的 sha256/repo。
    let mut sorted = params.build_requires.to_vec();
    sorted.sort();
    let digest_input = format!(
        "{}\n{}\n{}\nrecord_provenance={}\nrepos=\n{}",
        params.product,
        sorted.join("\n"),
        params.base_os_digest,
        params.record_provenance,
        params.repo_fingerprint,
    );
    let digest = blake3::hash(digest_input.as_bytes()).to_hex().to_string();

    let layer_dir = params.shared_layers_dir.join(&digest);
    let upperdir = layer_dir.join("upper");
    let complete_marker = layer_dir.join(".complete");
    let lock_path = layer_dir.join(".lock");

    if tokio::fs::try_exists(&complete_marker).await? {
        match is_layer_stale(&layer_dir, params.staleness).await {
            Ok(false) => {
                info!(digest = %digest, "SharedLayer cache hit");
                // 快路径：非阻塞 try_lock → 锁内 inc + 复核 .complete，语义见 try_fast_path_reuse。
                match try_fast_path_reuse(&params, &digest, &lock_path, &complete_marker).await? {
                    FastPathOutcome::Reused => return Ok(Some((upperdir, digest))),
                    FastPathOutcome::FallThrough(reason) => {
                        warn!(
                            digest = %digest,
                            reason = reason,
                            "SharedLayer fast path skipped, falling through to locked path"
                        );
                    }
                }
            }
            Ok(true) => {
                info!(digest = %digest, "SharedLayer stale, will rebuild");
            }
            Err(e) => {
                // fail-closed：I/O 错误按"过期"处理，走锁内复检+重建，不复用可能陈旧的层。
                warn!(digest = %digest, error = %e, "Failed to check SharedLayer staleness; treating as stale");
            }
        }
    }

    crate::engine::shared_dir::ensure_shared_dir(params.shared_layers_dir).await?;

    // 带重试创建（0..=max_retries，共 max_retries+1 次尝试）。失败目录清理在
    // try_create_shared_layer 内部、锁仍持有时执行——此处 Err 返回时锁已随
    // guard drop 释放，无锁清理会删掉另一进程 mid-create 正在写的文件。
    let mut last_err = None;
    for attempt in 0..=params.max_retries {
        match try_create_shared_layer(
            &params,
            &digest,
            &layer_dir,
            &upperdir,
            &complete_marker,
            &lock_path,
        )
        .await
        {
            Ok(result) => return Ok(Some(result)),
            Err(e) if attempt < params.max_retries => {
                warn!(digest = %digest, attempt = attempt + 1, max = params.max_retries, error = %e, "SharedLayer creation failed, retrying");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                last_err = Some(e);
            }
            Err(e) => {
                // 锁等待预算耗尽（同 digest 并发首建未完成）：降级无层构建——层只是
                // 性能优化。不写 .dirty：锁仍归首建者，无权标记其层目录状态。
                if matches!(
                    e,
                    CrbsError::Io {
                        kind: std::io::ErrorKind::TimedOut,
                        ..
                    }
                ) {
                    warn!(
                        digest = %digest,
                        timeout = ?params.timeout,
                        attempts = params.max_retries + 1,
                        "Timed out waiting for concurrent SharedLayer creation; \
                         degrading to layerless build"
                    );
                    return Ok(None);
                }
                let _ = tokio::fs::write(layer_dir.join(".dirty"), "").await;
                // .dirty 标记落盘的唯一日志，保留 warn 级别。
                warn!(digest = %digest, error = %e, "SharedLayer creation failed after retries, marked dirty");
                return Err(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| CrbsError::io_message("SharedLayer creation failed")))
}

#[derive(Debug)]
enum FastPathOutcome {
    Reused,
    FallThrough(&'static str),
}

/// 快路径复用：digest `.lock` try_lock（非阻塞）→ 锁内 inc 引用 + 复核 `.complete`。
/// 锁的必要性（TOCTOU）：GC/clean 删除 = 持 flock → 锁内复检 ref==0 → rm_rf；不取锁
/// 时 inc 可落在 GC 复检后、rm_rf 前，rm_rf 遍历顺序不定（upper 可先于 `.complete`
/// 消失），复核通过仍会挂载半删目录；持锁完成 inc+复核，释放后 ref>0 使 GC 复检
/// 不命中即安全；拿不到锁 → 落锁内创建路径阻塞等锁。
/// 对称回滚（幽灵 inc）：inc 后 `.complete` 消失必须回滚（否则幽灵 ref 永久钉死
/// 该层）；LayerNotFound 未发生有效 inc，无需回滚，落锁内路径自愈注册。
async fn try_fast_path_reuse(
    params: &SharedLayerParams<'_>,
    digest: &str,
    lock_path: &Path,
    complete_marker: &Path,
) -> crate::Result<FastPathOutcome> {
    use fs4::tokio::AsyncFileExt;

    let lock_file = match tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            // 锁文件打不开（EACCES 等）无法判断占用状态：落锁内路径，由 acquire_layer_lock 给权威错误。
            warn!(digest = %digest, path = %lock_path.display(), error = %e, "Failed to open digest lock for fast path");
            return Ok(FastPathOutcome::FallThrough("digest lock unopenable"));
        }
    };
    if lock_file.try_lock_exclusive().is_err() {
        return Ok(FastPathOutcome::FallThrough("digest lock held"));
    }
    // create(true) 建出的锁文件受 umask（0644）：补 0660+crbs 组，否则跨身份的后续 GC/创建永久 EACCES。
    let lp = lock_path.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || crate::gc::fix_created_lock_perms(&lp)).await;

    match inc_layer_ref_on_reuse(params.state, digest).await {
        Ok(()) => {}
        Err(CrbsError::LayerNotFound { .. }) => {
            // .complete 在磁盘但 DB 行缺失（注册前崩溃/GC 残留）：未发生有效 inc，锁内路径自愈注册。
            return Ok(FastPathOutcome::FallThrough("db row missing"));
        }
        Err(e) => return Err(e),
    }

    if tokio::fs::try_exists(complete_marker).await? {
        return Ok(FastPathOutcome::Reused);
    }

    // inc 后 .complete 消失：对称回滚本次 inc；宽限取编译期全局缺省 168h（非配置值）。
    // 回滚失败只 warn：构建改走锁内重建，泄漏的计数由泄漏修复路径收敛，不硬失败。
    let grace = crate::config::defaults::default_shared_layer_gc_grace_hours();
    if let Err(e) = params.state.layer_ref_dec(digest, grace).await {
        warn!(digest = %digest, error = %e, "Failed to roll back fast-path layer ref inc; ref may leak until leak repair");
    }
    Ok(FastPathOutcome::FallThrough("complete marker vanished"))
}

/// 层内跨身份重写文件（packages.txt / *.log）的权限修正：创建者 umask 会留 0644，
/// 另一身份的陈旧重建会因截断写 EACCES 退化为全量 dnf builddep。必须在 create/write
/// 成功之后调用（after-create）——建前调用因文件不存在整体跳过，首建文件永久落 umask 缺省。
pub(crate) async fn fix_layer_file_perms(path: &std::path::Path) {
    crate::engine::cache::fix_shared_file_perms(
        path,
        "layer file",
        "cross-identity rebuild may degrade",
    )
    .await;
}

#[cfg(test)]
mod tests;
