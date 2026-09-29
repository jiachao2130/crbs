// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 共享层 GC：引用集合、配方钉住与失效层回收。

use crate::config::CrbsConfig;
use crate::engine::gc::repair_zombie_builds;
use crate::engine::shared_layer::ttl::parse_stale_upper_timestamp;
use crate::state::StateStore;
use crate::types::GcSharedLayersSummary;
use std::collections::HashSet;
use tracing::{debug, info, warn};

use super::package_cache::calc_dir_size;

/// 无行孤儿层目录的删除宽限：24h 远大于注册窗口（`.complete` → `insert_layer`
/// 仅 REGISTER_LAYER_RETRIES × 100ms 量级、整次创建含 dnf builddep 也仅分钟
/// 级），与同文件 stale upper 宽限一致；有行但 ref 泄漏的层不在此路径（行驱动
/// GC 与泄漏修复负责，两者正交）。
const ORPHAN_LAYER_DIR_GRACE: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

pub(crate) async fn gc_shared_layers(
    state: &StateStore,
    cfg: &CrbsConfig,
) -> crate::Result<GcSharedLayersSummary> {
    repair_zombie_builds(state).await;

    // 泄漏 = ref_count > 0 但无 build 引用
    match state.list_leaked_layers().await {
        Ok(leaked) => {
            for layer in leaked {
                warn!(
                    digest = %layer.digest,
                    ref_count = layer.ref_count,
                    product = %layer.product,
                    "Leaked layer detected, resetting ref_count"
                );
                match state
                    .reset_layer_ref_count(
                        &layer.digest,
                        cfg.shared_layer_gc_grace_hours,
                        layer.ref_count,
                    )
                    .await
                {
                    // 0 行 = 扫描到重置间 ref_count 被并发改动：归零会清掉在用
                    // 计数、GC 可能在构建期间删层——跳过，下轮按新值再判。
                    Ok(0) => warn!(
                        digest = %layer.digest,
                        "Leaked layer ref_count changed concurrently, reset skipped"
                    ),
                    Ok(_) => {}
                    Err(e) => warn!(
                        digest = %layer.digest,
                        error = %e,
                        "Failed to reset layer ref_count, layer may not be GC'd"
                    ),
                }
            }
        }
        Err(e) => warn!(error = %e, "Failed to list leaked layers"),
    }

    let cleaned = state.run_gc(&cfg.shared_layers_dir_or_derived()).await?;

    // disk→DB 对账：回收行驱动 GC 看不见的"DB 无行"孤儿目录（.complete 已写、
    // 注册未成的崩溃窗口 / 删行成功但 rm_rf 失败的残留）；计数进 summary
    //（orphan_dirs_removed），失败记 0 保持 warn，不阻断汇总返回。
    let orphan_dirs_removed = match cleanup_orphan_layer_dirs(
        state,
        &cfg.shared_layers_dir_or_derived(),
        ORPHAN_LAYER_DIR_GRACE,
    )
    .await
    {
        Ok(n) if n > 0 => {
            info!(
                removed = n,
                "Removed orphan SharedLayer dirs without DB rows"
            );
            n
        }
        Ok(n) => n,
        Err(e) => {
            warn!(error = %e, "Failed to scan shared_layers_dir for orphan dirs");
            0
        }
    };

    let (stale_uppers, stale_upper_bytes) =
        cleanup_stale_shared_layer_uppers(&cfg.shared_layers_dir_or_derived()).await?;
    Ok(GcSharedLayersSummary {
        removed: cleaned,
        stale_uppers,
        stale_upper_bytes,
        orphan_dirs_removed,
    })
}

/// disk→DB 对账：扫描顶层 digest 目录，删"DB 无行且 mtime 超 `grace`"的孤儿
/// 目录并返回删除数（`grace` 供测试注入）。宽限必须远大于注册窗口：层创建全程
/// DB 无行，新鲜无行目录是在建正常形态；删除前 try_lock `.lock`（被占 = 创建
/// 者/GC 持锁则跳过），特权 rm_rf + 命名空间断言（run_gc/stale upper 同口径）。
async fn cleanup_orphan_layer_dirs(
    state: &StateStore,
    shared_layers_dir: &std::path::Path,
    grace: std::time::Duration,
) -> crate::Result<usize> {
    use fs4::tokio::AsyncFileExt;

    let mut removed = 0usize;
    let mut entries = match tokio::fs::read_dir(shared_layers_dir).await {
        Ok(d) => d,
        Err(e) => {
            // 目录不存在 = 未启用 shared layer，无事可对账。
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(0);
            }
            return Err(crate::error::CrbsError::from_io_context(
                format!(
                    "read shared_layers_dir {} for orphan scan",
                    shared_layers_dir.display()
                ),
                e,
            ));
        }
    };

    while let Some(entry) = entries.next_entry().await? {
        let Ok(ft) = entry.file_type().await else {
            continue;
        };
        if !ft.is_dir() {
            continue;
        }
        // digest 形态过滤（blake3 hex 64）：非层命名空间目录绝不触碰。
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !super::is_layer_digest(&name_str) {
            continue;
        }
        let digest = name_str.to_string();
        let dir_path = entry.path();

        // 有行层归行驱动 GC / 泄漏修复，此路径不碰。
        match state.get_layer_ref_count(&digest).await {
            Ok(Some(_)) => continue,
            Ok(None) => {}
            Err(e) => {
                warn!(
                    digest = %digest,
                    error = %e,
                    "Failed to query layer row during orphan dir scan, skipping"
                );
                continue;
            }
        }

        let age = match tokio::fs::metadata(&dir_path).await {
            Ok(m) => m
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .unwrap_or_default(),
            Err(e) => {
                warn!(digest = %digest, error = %e, "Failed to stat orphan dir candidate, skipping");
                continue;
            }
        };
        if age <= grace {
            continue;
        }

        let lock_path = dir_path.join(".lock");
        let lock_file = match tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .await
        {
            Ok(f) => f,
            Err(e) => {
                warn!(digest = %digest, error = %e, "Failed to open orphan dir lock, skipping");
                continue;
            }
        };
        // create(true) 建出的锁文件受 umask（0644）：补 0660+crbs 组——root 扫过的
        // 残锁若不收敛，非 root 的后续 GC/创建对同一目录永久 EACCES。
        let _ =
            tokio::task::spawn_blocking(move || super::fix_created_lock_perms(&lock_path)).await;
        if lock_file.try_lock_exclusive().is_err() {
            info!(digest = %digest, "Orphan dir candidate is locked, skipping");
            continue;
        }

        // 命名空间断言：digest 目录必须严格位于 shared_layers 根之下。
        if let Err(e) = super::assert_delete_under_root(shared_layers_dir, &dir_path) {
            warn!(
                digest = %digest,
                path = %dir_path.display(),
                error = %e,
                "Refusing to remove orphan SharedLayer dir outside root"
            );
            continue;
        }
        // 先摘 merged 残挂载（创建半途崩溃残留）：setuid 后端裸 remove_dir_all
        // 会穿 bind 删宿主 lower 层文件；helper 后端有 st_dev 边界但残挂载目录
        // rm 恒 ENOTEMPTY 不可回收。umount 失败照删（MNT_DETACH 对 busy 几乎总
        // 成功，失败多为"非挂载点"，照删即自愈）。
        let merged = dir_path.join("merged");
        if tokio::fs::try_exists(&merged).await.unwrap_or(false) {
            if let Err(e) = crate::privilege::umount_detach(merged.clone()).await {
                warn!(
                    digest = %digest,
                    path = %merged.display(),
                    error = %e,
                    "Failed to umount merged before orphan GC removal, continuing"
                );
            }
        }
        // 特权 rm_rf：层树属 root/builder，非 root 进程 remove_dir_all 会 EACCES 永久泄漏。
        match crate::privilege::rm_rf_async(&[dir_path.as_path()]).await {
            Ok(()) => {
                info!(digest = %digest, "Removed orphan SharedLayer dir (no DB row, past grace)");
                removed += 1;
            }
            Err(e) => {
                warn!(digest = %digest, error = %e, "Failed to remove orphan SharedLayer dir");
            }
        }
    }

    Ok(removed)
}

/// 清理 SharedLayer 过期重建留下的 `upper.stale.*` 目录；位于仍活跃 layer_dir
/// 内部，run_gc 不会删。只删 rename 时间（文件名内嵌时间戳）超 24h 者，避免
/// 误删长构建仍占用旧层；mtime 不可用——rename 保留原 mtime，天然早于 TTL。
pub(crate) async fn cleanup_stale_shared_layer_uppers(
    shared_layers_dir: &std::path::Path,
) -> crate::Result<(usize, u64)> {
    use std::time::Duration;

    const STALE_UPPER_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

    let mut removed = 0usize;
    let mut bytes = 0u64;

    let mut digest_dirs = match tokio::fs::read_dir(shared_layers_dir).await {
        Ok(d) => d,
        Err(e) => {
            warn!(dir = %shared_layers_dir.display(), error = %e, "Failed to read shared_layers_dir");
            return Ok((0, 0));
        }
    };

    // 迭代错误必须传播：`while let Ok(Some(..))` 会把 IO 错误当迭代结束，清扫
    // 静默截断仍伪装成"扫描完成"（失败可见优于静默漏清）。
    while let Some(digest_dir) = digest_dirs
        .next_entry()
        .await
        .map_err(|e| crate::error::CrbsError::from_io_context("iterate shared_layers dir", e))?
    {
        let dir_type = match digest_dir.file_type().await {
            Ok(t) => t,
            Err(_) => continue,
        };
        if !dir_type.is_dir() {
            continue;
        }

        let mut entries = match tokio::fs::read_dir(digest_dir.path()).await {
            Ok(e) => e,
            Err(_) => continue,
        };
        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            crate::error::CrbsError::from_io_context("iterate shared layer digest dir", e)
        })? {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with("upper.stale.") {
                continue;
            }
            let entry_type = match entry.file_type().await {
                Ok(t) => t,
                Err(_) => continue,
            };
            if !entry_type.is_dir() {
                continue;
            }

            // 判定用文件名内嵌 rename 时间戳；解析失败保守保留。
            let renamed_at = match parse_stale_upper_timestamp(&name_str) {
                Some(ts) => ts,
                None => continue,
            };
            if chrono::Utc::now().signed_duration_since(renamed_at)
                < chrono::Duration::seconds(STALE_UPPER_GRACE.as_secs() as i64)
            {
                continue;
            }

            let size = calc_dir_size(&entry.path()).await;
            if let Err(e) = super::assert_delete_under_root(shared_layers_dir, &entry.path()) {
                warn!(
                    path = %entry.path().display(),
                    error = %e,
                    "Refusing to remove stale SharedLayer upper dir"
                );
                continue;
            }
            // 特权 rm_rf：属 root/builder 产物，非 root 进程 remove_dir_all 会 EACCES。
            if let Err(e) = crate::privilege::rm_rf_async(&[entry.path().as_path()]).await {
                warn!(
                    path = %entry.path().display(),
                    error = %e,
                    "Failed to remove stale SharedLayer upper dir"
                );
            } else {
                removed += 1;
                bytes += size;
            }
        }
    }

    Ok((removed, bytes))
}

/// 扫描 result_dir/build_packages.json 与各产品 base_os/.packages.json，收集
/// 被引用的 SHA256 集合。result_dir 列表来自 DB 但包内容权威在 JSON 文件；
/// base_os 包必须常驻 package_cache，否则 --reproduce 无法重建 base_os。
pub(crate) async fn collect_referenced_sha256(
    crbs_cfg: &CrbsConfig,
    state: &StateStore,
) -> crate::Result<HashSet<String>> {
    let result_dirs = state.list_all_result_dirs().await?;
    let mut referenced = HashSet::new();

    for result_dir in result_dirs {
        let packages_json = result_dir.join("build_packages.json");
        collect_sha256_from_packages_json(&packages_json, "build_packages.json", &mut referenced)
            .await;
    }

    // base_os 位于 {crbs_root}/{product}/base/.packages.json（与 /etc/crbs/products 配置目录无关）。
    let mut root_entries = tokio::fs::read_dir(&crbs_cfg.crbs_root)
        .await
        .map_err(|e| {
            crate::error::CrbsError::from_io_context(
                format!(
                    "read crbs_root {} for referenced package scan",
                    crbs_cfg.crbs_root.display()
                ),
                e,
            )
        })?;
    while let Some(entry) = root_entries.next_entry().await? {
        let ft = match entry.file_type().await {
            Ok(ft) => ft,
            Err(e) => {
                warn!(path = %entry.path().display(), error = %e, "Failed to read file type for cache GC");
                continue;
            }
        };
        if !ft.is_dir() {
            continue;
        }
        let product_dir = entry.path();
        let base_packages_json = product_dir.join("base").join(".packages.json");
        collect_sha256_from_packages_json(
            &base_packages_json,
            "base .packages.json",
            &mut referenced,
        )
        .await;
    }

    Ok(referenced)
}

/// GC 钉住：扫描 retention 窗口内的 `recipe.json` 收集引用 sha256，返回
/// (引用集, 窗口内 recipe 数)。性能优化、非正确性前提：缓存缺失可经 url
/// 重下载 + sha256 校验恢复，钉住只决定热缓存窗口（命中秒级 vs 多 1~3 分钟）。引用
/// 两层：recipe 字面引用（`srpm_sha256` 为 SRPM 原样字节锚、包缓存通常无对应
/// 项冗余无害；`build_packages_sha256` / `unsigned_artifacts[].sha256`），以及
/// `builds.result_dir` 指向的 per-build `build_packages.json` 包内容 sha256
/// ——钉住实质：结果 GC 清走 per-build 目录后引用行消失，窗口内 recipe 令包
/// 免驱逐（路径取 builds 表权威指针，不从 recipe 字段重建布局）。hub 模式
/// worker 侧 recipe 无状态行、钉住不生效（backlog，仅可用性差异）。单 recipe
/// 损坏/超窗/配置缺失只降级该条目不中断；DB 失败由调用方定（宁少钉不误删）。
pub(crate) async fn collect_recipe_pinned_sha256(
    state: &StateStore,
) -> crate::Result<(HashSet<String>, usize)> {
    let tasks = state.list_task_result_dirs().await?;
    let mut referenced = HashSet::new();
    let mut retention_cache: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();
    let mut pinned_recipes = 0usize;
    let now = chrono::Utc::now().naive_utc();

    for (task_id, product, task_dir) in tasks {
        let recipe_path = crate::recipe::recipe_path(&task_dir);
        if !tokio::fs::try_exists(&recipe_path).await.unwrap_or(false) {
            continue;
        }
        let content = match tokio::fs::read_to_string(&recipe_path).await {
            Ok(c) => c,
            Err(e) => {
                debug!(path = %recipe_path.display(), error = %e, "Failed to read recipe.json for GC pinning");
                continue;
            }
        };
        let recipe: crate::recipe::Recipe = match serde_json::from_str(&content) {
            Ok(r) => r,
            Err(e) => {
                debug!(task_id = task_id, error = %e, "Corrupt recipe.json; skipping pinning for this task");
                continue;
            }
        };
        // generated_at 解析失败 = 不可信配方不钉（性能特性，保守跳过即回归默认驱逐）。
        let generated = match crate::util::parse_db_time(&recipe.generated_at) {
            Some(t) => t,
            None => {
                debug!(task_id = task_id, generated_at = %recipe.generated_at, "Unparsable recipe generated_at; not pinned");
                continue;
            }
        };
        let retention_days = recipe_retention_days_for(state, &product, &mut retention_cache).await;
        if retention_days == 0 {
            continue;
        }
        // 无需 try_days 饱和：resolve 出口 MAX_RETENTION_DAYS 已拒超 chrono 表示域值，不 panic。
        if now.signed_duration_since(generated) > chrono::Duration::days(retention_days as i64) {
            continue;
        }
        pinned_recipes += 1;

        let build_dirs = state.list_build_result_dirs_for_task(task_id).await?;
        if let Some(sha) = &recipe.srpm_sha256 {
            if crate::util::is_sha256_hex(sha) {
                referenced.insert(sha.clone());
            }
        }
        for pa in &recipe.per_arch {
            if let Some(sha) = &pa.build_packages_sha256 {
                if crate::util::is_sha256_hex(sha) {
                    referenced.insert(sha.clone());
                }
            }
            for a in &pa.unsigned_artifacts {
                if crate::util::is_sha256_hex(&a.sha256) {
                    referenced.insert(a.sha256.clone());
                }
            }
            let bp = build_dirs
                .get(&pa.build_id)
                .and_then(|d| d.as_deref())
                .filter(|d| !d.is_empty())
                .map(|dir| std::path::Path::new(dir).join("build_packages.json"));
            match bp {
                Some(bp) => {
                    collect_sha256_from_packages_json(
                        &bp,
                        "recipe build_packages.json",
                        &mut referenced,
                    )
                    .await;
                }
                None => {
                    debug!(
                        task_id = task_id,
                        build_id = pa.build_id,
                        "build result_dir unavailable; skipping per-arch snapshot pinning"
                    );
                }
            }
        }
    }

    Ok((referenced, pinned_recipes))
}

/// 产品的 recipe 钉住窗口（跨调用缓存）：产品级 `recipe_retention_days`，
/// 缺省/产品记录缺失/解析失败回退默认 90 天；0 = 禁用钉住。
async fn recipe_retention_days_for(
    state: &StateStore,
    product: &str,
    cache: &mut std::collections::HashMap<String, u64>,
) -> u64 {
    if let Some(&d) = cache.get(product) {
        return d;
    }
    let days = match state.resolve_any_product_by_name(product).await {
        Ok(resolved) => resolved
            .config
            .recipe_retention_days
            .unwrap_or(crate::recipe::DEFAULT_RECIPE_RETENTION_DAYS),
        Err(e) => {
            debug!(product = %product, error = %e, "Product config unavailable for recipe retention; using default");
            crate::recipe::DEFAULT_RECIPE_RETENTION_DAYS
        }
    };
    cache.insert(product.to_string(), days);
    days
}

/// 读取 JSON 包清单（数组或对象形式），把非空 sha256 加入 `referenced`；
/// 不存在直接返回，检查/读取/解析失败告警跳过（单个损坏文件不中断收集）。
async fn collect_sha256_from_packages_json(
    path: &std::path::Path,
    label: &str,
    referenced: &mut HashSet<String>,
) {
    match tokio::fs::try_exists(path).await {
        Ok(true) => {}
        Ok(false) => return,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "Failed to check {} for cache GC", label);
            return;
        }
    }
    let content = match tokio::fs::read_to_string(path).await {
        Ok(c) => c,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "Failed to read {} for cache GC", label);
            return;
        }
    };
    let packages: serde_json::Value = match serde_json::from_str(&content) {
        Ok(p) => p,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "Failed to parse {} for cache GC", label);
            return;
        }
    };
    // build_packages.json 为数组，base/.packages.json 为对象；两者只取包记录值。
    let pkgs: Vec<&serde_json::Value> = match &packages {
        serde_json::Value::Array(arr) => arr.iter().collect(),
        serde_json::Value::Object(map) => map.values().collect(),
        _ => Vec::new(),
    };
    for pkg in pkgs {
        if let Some(sha) = pkg.get("sha256").and_then(|v| v.as_str()) {
            if !sha.is_empty() {
                referenced.insert(sha.to_string());
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::ProductConfig;
    use crate::engine::shared_layer::ttl::STALE_UPPER_TS_FORMAT;
    use crate::state::StateStore;

    /// 测试 fixture：任务目录（recipe.json + per-arch build_packages.json），
    /// `sha` 为包内容哈希；跨 GC 测试模块复用（package_cache 驱逐测试也播种）。
    pub(crate) async fn seed_recipe_task(
        store: &StateStore,
        results_root: &std::path::Path,
        product: &str,
        pkg: &str,
        generated_at: &str,
        sha: &str,
    ) -> crate::Result<i64> {
        let task_id = store
            .insert_task(crate::TaskInsert {
                product,
                pkg_name: pkg,
                user: "tester",
                phase: "succeeded",
                request_json: Some("{}"),
                ..Default::default()
            })
            .await?;
        let build_id = store
            .insert_build(crate::BuildInsert {
                product,
                pkg_name: pkg,
                phase: "succeeded",
                backend: "chroot",
                user: "tester",
                priority: 0,
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await?;
        let task_dir = results_root.join(task_id.to_string());
        let build_dir = task_dir.join("x86_64").join(build_id.to_string());
        tokio::fs::create_dir_all(&build_dir).await.unwrap();
        tokio::fs::write(
            build_dir.join("build_packages.json"),
            format!(
                r#"[
                {{"nevra": "gcc-12-1.x86_64", "sha256": "{sha}"}}
            ]"#
            ),
        )
        .await
        .unwrap();
        store
            .update_build_info(build_id, Some(build_dir.to_str().unwrap()), None, "chroot")
            .await?;
        let recipe = serde_json::json!({
            "schema_version": 1,
            "product": product,
            "task_id": task_id,
            "generated_at": generated_at,
            "srpm_sha256": crate::util::is_sha256_hex(sha).then(|| sha.to_string()),
            "macros": {"source": "test", "values": {}},
            "env": {"source": "test", "values": {"LC_ALL": "C"}},
            "ccache": {"enabled": false, "compiler_check": null, "sloppy": ""},
            "instrumentation_disclosure": "test",
            "repos": [],
            "per_arch": [{
                "arch": "x86_64",
                "build_id": build_id,
                "base_os_digest": null,
                "build_packages_sha256": "bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111",
                "unsigned_artifacts": [
                    {"name": "hello-1.0-1.x86_64.rpm", "sha256": "cccc2222cccc2222cccc2222cccc2222cccc2222cccc2222cccc2222cccc2222"}
                ]
            }]
        });
        tokio::fs::write(
            crate::recipe::recipe_path(&task_dir),
            serde_json::to_string_pretty(&recipe).unwrap(),
        )
        .await
        .unwrap();
        store
            .update_task_result_dir(task_id, Some(task_dir.to_str().unwrap()))
            .await?;
        Ok(task_id)
    }

    fn recent_ts(days_ago: i64) -> String {
        chrono::Utc::now()
            .checked_sub_signed(chrono::Duration::days(days_ago))
            .unwrap()
            .format(crate::util::DB_TIME_FMT)
            .to_string()
    }

    /// retention 窗口内的 recipe：字面引用（srpm 锚 / build_packages 文件哈希 /
    /// unsigned）+ per-arch build_packages.json 内的包内容哈希都被钉住；
    /// 窗口外 / 损坏 / 时间不可解析的 recipe 不产生钉住。
    #[tokio::test]
    async fn recipe_pin_window_in_out_and_degraded_entries() {
        let (store, db_tmp) = crate::state::test_state::create_test_store().await;
        let results = db_tmp.as_ref().unwrap().path().join("results");
        tokio::fs::create_dir_all(&results).await.unwrap();

        let pkg_sha = "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000";
        seed_recipe_task(
            &store,
            &results,
            "det",
            "fresh-1.0-1",
            &recent_ts(0),
            pkg_sha,
        )
        .await
        .unwrap();
        seed_recipe_task(
            &store,
            &results,
            "det",
            "stale-1.0-1",
            &recent_ts(91),
            "dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333",
        )
        .await
        .unwrap();
        let corrupt_task = store
            .insert_task(crate::TaskInsert {
                product: "det",
                pkg_name: "corrupt-1.0-1",
                user: "tester",
                phase: "succeeded",
                request_json: Some("{}"),
                ..Default::default()
            })
            .await
            .unwrap();
        let corrupt_dir = results.join(corrupt_task.to_string());
        tokio::fs::create_dir_all(&corrupt_dir).await.unwrap();
        tokio::fs::write(corrupt_dir.join("recipe.json"), b"{half")
            .await
            .unwrap();
        store
            .update_task_result_dir(corrupt_task, Some(corrupt_dir.to_str().unwrap()))
            .await
            .unwrap();

        let (pinned, count) = collect_recipe_pinned_sha256(&store).await.unwrap();
        assert!(
            pinned.contains(pkg_sha),
            "in-window recipe pins package content sha"
        );
        // 字面引用：unsigned 产物 + build_packages 文件哈希（fresh 任务）。
        assert!(pinned.contains("cccc2222cccc2222cccc2222cccc2222cccc2222cccc2222cccc2222cccc2222"));
        assert!(pinned.contains("bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111"));
        assert!(
            !pinned.contains("dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333"),
            "out-of-window recipe must not pin"
        );
        assert_eq!(count, 1, "only the in-window recipe counts as pinned");

        let (pinned2, _) = collect_recipe_pinned_sha256(&store).await.unwrap();
        assert!(pinned2.contains(pkg_sha));
    }

    /// 产品级 `recipe_retention_days = 0` 覆盖默认窗口：刚生成也不钉（运维关闭口子）。
    #[tokio::test]
    async fn recipe_pin_product_zero_retention_disables() {
        let (store, db_tmp) = crate::state::test_state::create_test_store().await;
        // 合法 shape（chain_resolve 出口校验要求 base_packages/repos 非空）+ 0 天窗口。
        let cfg = ProductConfig::from_str(
            "base_packages = [\"bash\"]\nrecipe_retention_days = 0\n\n[[repos]]\nname = \"base\"\nbaseurl = \"http://example.com/base/$basearch\"\ngpgcheck = false\n",
        )
        .unwrap();
        store
            .create_product(crate::CreateProductInput {
                name: "pinoff",
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: crate::VISIBILITY_PUBLIC,
                config: &cfg,
                changed_by_user_id: None,
                reason: Some("recipe pin off"),
            })
            .await
            .unwrap();

        let results = db_tmp.as_ref().unwrap().path().join("results");
        tokio::fs::create_dir_all(&results).await.unwrap();
        seed_recipe_task(
            &store,
            &results,
            "pinoff",
            "off-1.0-1",
            &recent_ts(0),
            "eeee4444eeee4444eeee4444eeee4444eeee4444eeee4444eeee4444eeee4444",
        )
        .await
        .unwrap();

        let (pinned, count) = collect_recipe_pinned_sha256(&store).await.unwrap();
        assert!(
            !pinned.contains("eeee4444eeee4444eeee4444eeee4444eeee4444eeee4444eeee4444eeee4444"),
            "recipe_retention_days=0 must disable pinning for the product"
        );
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn cleanup_stale_uppers_uses_rename_timestamp_not_mtime() {
        // 回归：rename 保留原 mtime，判定必须用文件名内嵌 rename 时间戳。
        // 三个 upper 的 mtime 都是"现在"，仅 rename 超 24h 者应删；解析失败保守保留。
        let tmp = tempfile::tempdir().unwrap();
        let digest_dir = tmp.path().join("digest1");
        tokio::fs::create_dir_all(&digest_dir).await.unwrap();

        let recent = digest_dir.join(format!(
            "upper.stale.{}",
            chrono::Utc::now().format(STALE_UPPER_TS_FORMAT)
        ));
        let old = digest_dir.join(format!(
            "upper.stale.{}",
            (chrono::Utc::now() - chrono::Duration::hours(25)).format(STALE_UPPER_TS_FORMAT)
        ));
        let unparsable = digest_dir.join("upper.stale.garbage");
        for dir in [&recent, &old, &unparsable] {
            tokio::fs::create_dir_all(dir).await.unwrap();
        }

        let (removed, _) = cleanup_stale_shared_layer_uppers(tmp.path()).await.unwrap();
        assert_eq!(removed, 1, "只有 rename 超过 24h 的 stale upper 被删除");
        assert!(!old.exists());
        assert!(recent.exists(), "24h 内 rename 移走的必须保留");
        assert!(unparsable.exists(), "解析失败的必须保守保留");
    }

    // ===== disk→DB 对账（cleanup_orphan_layer_dirs）=====

    const TEST_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// 建 digest 目录并把 mtime 回退指定时长（File::open 目录 + set_times 生效）。
    async fn seed_dir(
        root: &std::path::Path,
        name: &str,
        mtime_age: std::time::Duration,
    ) -> std::path::PathBuf {
        let dir = root.join(name);
        tokio::fs::create_dir_all(dir.join("upper")).await.unwrap();
        let f = std::fs::File::open(&dir).unwrap();
        let old = std::time::SystemTime::now() - mtime_age;
        f.set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
        dir
    }

    async fn gc_test_store() -> (StateStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();
        (store, tmp)
    }

    /// DB 无行 + mtime 超宽限 → 删除（注册前崩溃 / 删行后 rm_rf 失败的残局）。
    #[tokio::test]
    async fn orphan_layer_dir_without_row_removed_after_grace() {
        let (store, _db) = gc_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let dir = seed_dir(
            root.path(),
            TEST_DIGEST,
            std::time::Duration::from_secs(3600),
        )
        .await;

        let removed =
            cleanup_orphan_layer_dirs(&store, root.path(), std::time::Duration::from_secs(60))
                .await
                .unwrap();
        assert_eq!(removed, 1, "past-grace rowless digest dir must be removed");
        assert!(!dir.exists());
    }

    /// 锁被他人持有时跳过，但本扫描 open(create) 过的锁文件必须收敛到 0660 组可锁
    /// （root umask 残留的 0644 锁会让非 root 后续 GC 对该目录永久 EACCES）。
    #[tokio::test]
    async fn orphan_dir_lock_converged_to_group_writable_when_busy() {
        use std::os::unix::fs::PermissionsExt;

        let (store, _db) = gc_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join(TEST_DIGEST);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        // 测试自持锁（0644 形态）模拟他人占用：GC 跳过删除，但权限收敛仍须发生。
        let lock_path = dir.join(".lock");
        let holder = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        fs4::fs_std::FileExt::lock_exclusive(&holder).unwrap();
        // 建 .lock 已把目录 mtime 刷回 now：mtime 回退必须最后做，否则被宽限豁免。
        seed_dir(
            root.path(),
            TEST_DIGEST,
            std::time::Duration::from_secs(3600),
        )
        .await;

        let removed =
            cleanup_orphan_layer_dirs(&store, root.path(), std::time::Duration::from_secs(60))
                .await
                .unwrap();
        assert_eq!(removed, 0, "locked candidate must be skipped");
        assert!(dir.exists());
        let mode = std::fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o660,
            "lock file must converge to group-writable 0660"
        );
    }

    /// `merged/` 为 mkdir 手造（非真挂载），umount 必败（恒 Err/EINVAL），照删不得滞留。
    #[tokio::test]
    async fn orphan_layer_dir_with_merged_dir_removed_despite_umount_failure() {
        let (store, _db) = gc_test_store().await;
        let root = tempfile::tempdir().unwrap();
        // merged 先建、mtime 后回退：set_times 必须最后做，否则目录 mtime 刷回 now 被宽限豁免。
        let dir = root.path().join(TEST_DIGEST);
        tokio::fs::create_dir_all(dir.join("merged")).await.unwrap();
        seed_dir(
            root.path(),
            TEST_DIGEST,
            std::time::Duration::from_secs(3600),
        )
        .await;

        let removed =
            cleanup_orphan_layer_dirs(&store, root.path(), std::time::Duration::from_secs(60))
                .await
                .unwrap();
        assert_eq!(
            removed, 1,
            "merged 存在但 umount 失败时仍必须整目录删除（照删自愈）"
        );
        assert!(!dir.exists());
    }

    /// DB 有行（无论 ref 多少）→ 行驱动 GC / 泄漏修复的领地，对账不碰。
    #[tokio::test]
    async fn layer_dir_with_row_is_kept() {
        let (store, _db) = gc_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let dir = seed_dir(
            root.path(),
            TEST_DIGEST,
            std::time::Duration::from_secs(3600),
        )
        .await;
        store
            .insert_layer(
                TEST_DIGEST,
                &dir.join("upper").to_string_lossy(),
                "fedora",
                1,
            )
            .await
            .unwrap();

        let removed = cleanup_orphan_layer_dirs(&store, root.path(), std::time::Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(removed, 0, "row-backed dir must never be disk-scanned away");
        assert!(dir.exists());
    }

    /// mtime 在宽限内的无行目录 = 在建层的正常形态（创建全程无行），必须豁免。
    #[tokio::test]
    async fn orphan_layer_dir_within_grace_is_kept() {
        let (store, _db) = gc_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let dir = seed_dir(root.path(), TEST_DIGEST, std::time::Duration::ZERO).await;

        let removed = cleanup_orphan_layer_dirs(
            &store,
            root.path(),
            std::time::Duration::from_secs(24 * 60 * 60),
        )
        .await
        .unwrap();
        assert_eq!(removed, 0, "in-grace dir must be exempt (creation window)");
        assert!(dir.exists());
    }

    /// 非 digest 名目录不属于层命名空间，绝不触碰。
    #[tokio::test]
    async fn non_digest_named_dir_is_kept() {
        let (store, _db) = gc_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let dir = seed_dir(
            root.path(),
            "scratch-junk",
            std::time::Duration::from_secs(3600),
        )
        .await;

        let removed =
            cleanup_orphan_layer_dirs(&store, root.path(), std::time::Duration::from_secs(60))
                .await
                .unwrap();
        assert_eq!(removed, 0);
        assert!(dir.exists());
    }
}
