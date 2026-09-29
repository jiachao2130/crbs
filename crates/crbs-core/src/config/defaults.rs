// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 配置默认值函数集，供 serde default 与模板生成复用。

use std::path::PathBuf;

use super::types::BoolOrPackages;

pub(crate) fn default_builder_user() -> String {
    "ccbuilder".into()
}

pub(crate) fn default_builder_uid() -> u32 {
    10010
}

pub(crate) fn default_builder_group() -> String {
    "ccbuilder".into()
}

pub(crate) fn default_builder_gid() -> u32 {
    10010
}

/// server / worker / priv-helper 世界的默认 root（crbs-server 独占）。
pub(crate) fn default_crbs_root() -> PathBuf {
    PathBuf::from("/var/lib/crbs")
}

/// 引擎世界（crbs CLI / BuildEngine）的默认 root；crbs.toml 的 crbs_root 语义收归
/// 引擎世界。与 server root 分离：server root 由 server.toml 决定，
/// 缺省 /var/lib/crbs。字面值常量而非读 crbs.toml：serde 缺省在解析前就需要，语义不随配置漂移。
pub fn default_engine_crbs_root() -> PathBuf {
    PathBuf::from("/var/lib/crbs-engine")
}

pub(crate) fn default_shared_layer_gc_grace_hours() -> u64 {
    168
}

/// 未配置 `shared_layer_staleness` 时的 SharedLayer TTL 缺省（7 天）：太短吃掉层
/// 复用收益（重建付整层 dnf builddep），永不过期则仓库更新进不了已建层；7 天与
/// GC 宽限 168h 同量级（每周重建一次），显式配置可覆盖。
pub(crate) fn default_shared_layer_staleness() -> std::time::Duration {
    std::time::Duration::from_secs(7 * 24 * 3600)
}

pub(crate) fn default_result_gc_grace_hours() -> u64 {
    720
}

pub(crate) fn default_build_max_retries() -> u32 {
    1
}

pub(crate) fn default_build_retry_backoff_ms() -> u64 {
    1000
}

pub(crate) fn default_package_url_cache_ttl_days() -> u64 {
    90
}

/// base 快照保留代数缺省（8）：快照包体是 package cache 的硬链，多留的边际
/// 成本主要是 repodata 与最后引用钉住的缓存页，保守多留换恢复余地。
pub(crate) fn default_base_snapshot_keep_generations() -> u32 {
    8
}

pub(crate) fn default_reproduce_enabled() -> BoolOrPackages {
    BoolOrPackages::Bool(false)
}

pub(crate) fn default_build_target() -> String {
    "bb".into()
}

pub(crate) fn default_shared_layer_poll_interval_ms() -> u64 {
    100
}

pub(crate) fn default_shared_layer_timeout_secs() -> u64 {
    60
}

pub(crate) fn default_shared_layer_max_retries() -> u32 {
    2
}

pub(crate) fn default_chain_parallelism() -> usize {
    8
}

/// chain 恢复轮上限：拓扑单遍跑完后对"依赖已解锁"的 failed 包重试的轮数；0 = 禁用。
/// 默认 1：救回瞬时失败（dnf mirror 抖动），真编译错误不多轮重试。
pub(crate) fn default_chain_max_recovery_rounds() -> usize {
    1
}

pub(crate) fn default_ccache_dir() -> PathBuf {
    // 占位值，实际在 Config::load 中用 crbs_root.join("ccache").join(product) 计算
    PathBuf::from("/var/lib/crbs/ccache")
}

pub(crate) fn default_ccache_max_size() -> String {
    "4G".into()
}

pub(crate) fn default_tmpfs_dir() -> PathBuf {
    PathBuf::from("/dev/shm")
}

pub(crate) fn default_network() -> bool {
    true
}

/// 构建资源采样间隔默认 15 秒（0 = 关闭）。
pub(crate) fn default_resource_sample_interval_secs() -> u64 {
    15
}
