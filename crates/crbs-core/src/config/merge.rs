// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 配置加载与合并：产品链补默认、宏/钩子叠加、子层覆盖。

use std::collections::BTreeMap;

use tracing::warn;

use super::defaults::default_ccache_dir;
use super::types::{Config, CrbsConfig, Hooks, HooksConfig, ProductConfig};
use super::validation;
use crate::error::CrbsError;
use crate::privilege;

/// 合并 RPM 宏：全局默认值 → 全局配置 → 产品配置（逐 key 覆盖）；_topdir 强制
/// /builddir、_smp_mflags 默认 -j$(nproc)；BTreeMap key 有序，序列化跨进程确定。
pub(crate) fn merge_rpm_macros(
    global: &BTreeMap<String, String>,
    product: Option<&BTreeMap<String, String>>,
) -> BTreeMap<String, String> {
    let mut merged = BTreeMap::new();
    merged.extend(global.iter().map(|(k, v)| (k.clone(), v.clone())));
    if let Some(p) = product {
        merged.extend(p.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    merged.insert("_topdir".to_string(), "/builddir".to_string());
    merged
        .entry("_smp_mflags".to_string())
        .or_insert_with(|| "-j$(nproc)".to_string());
    merged
}

/// 合并 hooks：全局默认值 → 产品覆盖（产品存在则覆盖，不存在则继承全局）。
pub(crate) fn merge_hooks(global: Option<&HooksConfig>, product: Option<&HooksConfig>) -> Hooks {
    let mut merged = Hooks::default();

    if let Some(g) = global {
        merged
            .pre
            .extend(g.pre.iter().map(|(k, v)| (k.clone(), v.clone())));
        merged
            .post
            .extend(g.post.iter().map(|(k, v)| (k.clone(), v.clone())));
        merged
            .spec_pre
            .extend(g.spec.pre.iter().map(|(k, v)| (k.clone(), v.clone())));
        merged
            .spec_post
            .extend(g.spec.post.iter().map(|(k, v)| (k.clone(), v.clone())));
    }

    if let Some(p) = product {
        for (k, v) in &p.pre {
            merged.pre.insert(k.clone(), v.clone());
        }
        for (k, v) in &p.post {
            merged.post.insert(k.clone(), v.clone());
        }
        for (k, v) in &p.spec.pre {
            merged.spec_pre.insert(k.clone(), v.clone());
        }
        for (k, v) in &p.spec.post {
            merged.spec_post.insert(k.clone(), v.clone());
        }
    }

    merged
}

/// 链合并（parent × child）：child 层已生效字段叠到 parent 上，产出新
/// `ProductConfig`；4 个 `*_append` 折进对应 base Vec，输出 `_append` 全空。
/// 字段规则：`Option<T>` scalar child Some → 覆盖、未设 → 继承；`Vec` 非空 →
/// 替换再拼 `child.*_append`；rpm_macros / hooks / resource_overrides 双 Some
/// 逐 key 合并（child 覆盖）、单侧 Some 取该侧。post_init 例外：child 未设但
/// `post_init_append` 非空时在 parent 上 extend（parent None 则提升 Some）——
/// append 可从无到有创建字段，与 scalar"未设→继承"相反。
/// 前置：`parent` 须已 `fold_appends_into_base`（chain_resolve 根层显式 fold，
/// 本函数输出亦已 fold，链上成立）。不校验 `base_packages` / `repos` 非空与
/// repo name 唯一（出口校验 `validate_resolved_shape` +
/// `check_repo_names_unique` 的职责）。
/// 字段清单显式列出：新增 scalar Option 字段漏列不会编译报错，而是静默继承
/// 父层值，靠参数化护栏测试失败暴露——新增字段须同步本清单与护栏 fixture。
macro_rules! override_some {
    ($out:ident, $child:ident, [$( $f:ident ),* $(,)?]) => {
        $( if $child.$f.is_some() {
            $out.$f = $child.$f.clone();
        } )*
    };
}

/// 父子产品配置合并：以 parent 克隆起手，child 的显式设置按字段规则覆盖
/// （各字段覆盖/追加语义见函数体注释）。
pub fn merge_product_configs(parent: &ProductConfig, child: &ProductConfig) -> ProductConfig {
    let mut out = parent.clone();

    if child.product.is_some() {
        out.product = child.product.clone();
    }

    // crbs_root 刻意不在 override_some! 清单：child 层值丢弃并 warn（root 层值
    // 经 parent.clone() 存活，merge_configs 统一 warn）。
    if let Some(ref p) = child.crbs_root {
        warn!(
            child_crbs_root = %p.display(),
            "product chain layer 'crbs_root' is ignored; state DB path is determined by /etc/crbs/crbs.toml"
        );
    }

    // ==== Vec 字段：child 非空覆盖，然后合并 child 的 `+field` 追加 ====
    if !child.base_packages.is_empty() {
        out.base_packages = child.base_packages.clone();
    }
    out.base_packages
        .extend(child.base_packages_append.iter().cloned());

    if !child.repos.is_empty() {
        out.repos = child.repos.clone();
    }
    out.repos.extend(child.repos_append.iter().cloned());

    if !child.arches.is_empty() {
        out.arches = child.arches.clone();
    }
    out.arches.extend(child.arches_append.iter().cloned());

    if !child.noarch_preferred_arches.is_empty() {
        out.noarch_preferred_arches = child.noarch_preferred_arches.clone();
    }
    out.noarch_preferred_arches
        .extend(child.noarch_preferred_arches_append.iter().cloned());

    out.base_packages_append.clear();
    out.repos_append.clear();
    out.arches_append.clear();
    out.post_init_append.clear();
    out.noarch_preferred_arches_append.clear();

    if child.post_init.is_some() {
        out.post_init = child.post_init.clone();
    }
    if !child.post_init_append.is_empty() {
        out.post_init
            .get_or_insert_with(Vec::new)
            .extend(child.post_init_append.iter().cloned());
    }

    // ==== 空串归一化（"" = 未设置）：releasever / shared_layer_staleness /
    // ccache_max_size / gpg_signing_key_id 不走 override_some!，child 空串
    // 继承父（与 merge_configs 入口归一化同语义），非空照常覆盖 ====
    if child.releasever.as_deref().is_some_and(|s| !s.is_empty()) {
        out.releasever = child.releasever.clone();
    }
    if child
        .shared_layer_staleness
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty())
    {
        out.shared_layer_staleness = child.shared_layer_staleness.clone();
    }
    if child
        .ccache_max_size
        .as_deref()
        .is_some_and(|s| !s.is_empty())
    {
        out.ccache_max_size = child.ccache_max_size.clone();
    }
    if child
        .gpg_signing_key_id
        .as_deref()
        .is_some_and(|s| !s.is_empty())
    {
        out.gpg_signing_key_id = child.gpg_signing_key_id.clone();
    }

    // ==== gpg_signing_enabled：三态开关，Some 即覆盖（含 Some(false)）——
    // fork 写 false 关派生产品签名，子层显式 false 必须能压过父层缺省开启 ====
    if child.gpg_signing_enabled.is_some() {
        out.gpg_signing_enabled = child.gpg_signing_enabled;
    }

    // ==== deterministic：plain bool，链上任一层置 true 即生效（OR）——
    // 父层开启无法被子层关闭（防字节流静默漂移），关闭须改父层；_buildhost
    // 走普通覆盖 ====
    if child.deterministic {
        out.deterministic = true;
    }
    // ==== mtime_normalize（时间自锚定）：同 deterministic——卫生属性链上
    // 任一层开启即生效，父层开启子层无法关闭（防时间域静默漂移）====
    if child.mtime_normalize {
        out.mtime_normalize = true;
    }

    // ==== 其余 Option<T> scalar：清单见 override_some!（product / post_init /
    // 空串归一化四字段已各自特判，不重复列入）。BoolOrPackages 族（shared_layer
    // / ccache_enabled / reproduce_enabled）Some 即覆盖——Some(Packages([]))
    // 空列表 = 显式禁用父层启用集，与 plain Vec "空 = 继承父"相反 ====
    override_some!(
        out,
        child,
        [
            overlay_dir,
            builder_user,
            builder_uid,
            builder_group,
            builder_gid,
            result_dir,
            shared_layers_dir,
            product_root,
            base_os_path,
            dnf_cache_path,
            shared_layer_gc_grace_hours,
            result_gc_grace_hours,
            shared_layer,
            build_tmpfs,
            tmpfs_dir,
            tmp_dir,
            allow_srpm_download,
            gpg_home,
            ccache_enabled,
            ccache_dir,
            dnf_cache_enabled,
            builddep_install_weak_deps,
            build_target,
            nocheck,
            noclean,
            nodebuginfo,
            backend,
            memory_max,
            cpu_quota,
            network,
            repo_publish,
            repo_consume,
            local_repo,
            chain_parallelism,
            chain_max_recovery_rounds,
            build_max_retries,
            build_retry_backoff_ms,
            package_cache_max_size_gb,
            package_cache_evict_referenced,
            result_max_count_per_pkg,
            result_retention_days,
            recipe_retention_days,
            package_url_cache_ttl_days,
            resource_sample_interval_secs,
            resource_sample_interval_cgroup_secs,
            reproduce_enabled,
            noarch_per_arch,
            _buildhost,
            auto_replay,
            replay_sampling,
        ]
    );

    // ==== rpm_macros：都 Some → 逐 key 合并（child 覆盖）；单侧 Some → 该侧。
    // 无删除语义（toml 无 null，父 key 只能覆盖值不能移除）====
    out.rpm_macros = match (&out.rpm_macros, &child.rpm_macros) {
        (Some(p), Some(c)) => {
            let mut merged = p.clone();
            for (k, v) in c {
                merged.insert(k.clone(), v.clone());
            }
            Some(merged)
        }
        (Some(_), None) => out.rpm_macros,
        (None, Some(c)) => Some(c.clone()),
        (None, None) => None,
    };

    // ==== hooks：都 Some → 逐字段合并；单侧 Some → 该侧。无删除语义（子 hook
    // 只能覆盖父同名 hook 的命令，不能移除）====
    out.hooks = match (&out.hooks, &child.hooks) {
        (Some(p), Some(c)) => Some(merge_hooks_configs(p, c)),
        (Some(_), None) => out.hooks,
        (None, Some(c)) => Some(c.clone()),
        (None, None) => None,
    };

    // ==== resource_overrides：逐 key 覆盖（同 rpm_macros 形态），无删除语义。
    // 合并值随 resolved config 供 hub 消费；wire TOML 侧该键剔除，worker 永不见 ====
    out.resource_overrides = match (&out.resource_overrides, &child.resource_overrides) {
        (Some(p), Some(c)) => {
            let mut merged = p.clone();
            for (k, v) in c {
                merged.insert(k.clone(), *v);
            }
            Some(merged)
        }
        (Some(_), None) => out.resource_overrides,
        (None, Some(c)) => Some(c.clone()),
        (None, None) => None,
    };

    out
}

/// 逐字段合并 `HooksConfig`：`pre` / `post` / `spec.pre` / `spec.post` 均为
/// `HashMap<String, String>`，同 key child 覆盖父。链合并的私有 helper。
fn merge_hooks_configs(parent: &HooksConfig, child: &HooksConfig) -> HooksConfig {
    let mut merged = parent.clone();
    for (k, v) in &child.pre {
        merged.pre.insert(k.clone(), v.clone());
    }
    for (k, v) in &child.post {
        merged.post.insert(k.clone(), v.clone());
    }
    for (k, v) in &child.spec.pre {
        merged.spec.pre.insert(k.clone(), v.clone());
    }
    for (k, v) in &child.spec.post {
        merged.spec.post.insert(k.clone(), v.clone());
    }
    merged
}

impl Config {
    /// 异步版本：在 `spawn_blocking` 中完成文件 IO、解析与校验。
    pub async fn load_async(product: &str) -> crate::Result<Self> {
        let product = product.to_string();
        tokio::task::spawn_blocking(move || Self::load_blocking(&product))
            .await
            .map_err(|e| CrbsError::io_message(format!("load product config: {}", e)))?
    }

    /// 异步版本：从 Hub 下发的产品配置 TOML 字符串加载。
    pub async fn load_with_product_config_async(
        product: &str,
        product_toml: &str,
    ) -> crate::Result<Self> {
        let product = product.to_string();
        let toml = product_toml.to_string();
        tokio::task::spawn_blocking(move || {
            Self::load_with_product_config_blocking(&product, &toml)
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("load product config from string: {}", e)))?
    }

    fn load_blocking(product: &str) -> crate::Result<Self> {
        validation::validate_product_name(product)?;
        let global = CrbsConfig::load()?;
        let product_cfg = ProductConfig::load(product)?;
        Self::merge_configs(product, global, product_cfg)
    }

    fn load_with_product_config_blocking(product: &str, product_toml: &str) -> crate::Result<Self> {
        validation::validate_product_name(product)?;
        let global = CrbsConfig::load()?;
        let product_cfg = ProductConfig::from_str(product_toml)?;
        Self::merge_configs(product, global, product_cfg)
    }

    /// 与 [`Self::load_with_product_config_async`] 相同，但全局 crbs_root 固定为
    /// 传入值（worker pin root，防引擎世界默认值漂移 worker 结果位置）。
    pub(crate) async fn load_with_product_config_and_root_async(
        product: &str,
        product_toml: &str,
        crbs_root: &std::path::Path,
    ) -> crate::Result<Self> {
        let product = product.to_string();
        let toml = product_toml.to_string();
        let root = crbs_root.to_path_buf();
        tokio::task::spawn_blocking(move || {
            validation::validate_product_name(&product)?;
            let global = CrbsConfig::load()?.pinned_to_root(&root);
            let product_cfg = ProductConfig::from_str(&toml)?;
            Self::merge_configs(&product, global, product_cfg)
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("load product config from string: {}", e)))?
    }

    /// 与 [`Self::load_with_product_config_async`] 相同，但用调用方已加载的
    /// 全局 `CrbsConfig`（GC 等"世界配置已在手"路径，不重读
    /// /etc/crbs/crbs.toml）。与 `load_with_product_config_and_root_async` 的
    /// 差异：显式 `result_dir` / `shared_layers_dir` 也随调用方世界生效（只 pin
    /// root 会清掉引擎 toml 显式目录，GC 安全根偏离真实结果位置）。
    pub(crate) async fn load_with_product_config_and_global_async(
        product: &str,
        product_toml: &str,
        global: CrbsConfig,
    ) -> crate::Result<Self> {
        let product = product.to_string();
        let toml = product_toml.to_string();
        tokio::task::spawn_blocking(move || {
            validation::validate_product_name(&product)?;
            let product_cfg = ProductConfig::from_str(&toml)?;
            Self::merge_configs(&product, global, product_cfg)
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("load product config from string: {}", e)))?
    }

    /// 与 [`Self::load_async`] 相同，但全局 crbs_root 固定为传入值（server pin root）。
    pub(crate) async fn load_with_root_async(
        product: &str,
        crbs_root: &std::path::Path,
    ) -> crate::Result<Self> {
        let product = product.to_string();
        let root = crbs_root.to_path_buf();
        tokio::task::spawn_blocking(move || {
            validation::validate_product_name(&product)?;
            let global = CrbsConfig::load()?.pinned_to_root(&root);
            let product_cfg = ProductConfig::load(&product)?;
            Self::merge_configs(&product, global, product_cfg)
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("load product config: {}", e)))?
    }

    /// 合并全局 + 单层产品配置产出运行时 `Config`。纯内存：不创建运行时目录
    ///（产品详情 / 签名 / GC / diff 等读路径间接调用），需要目录的执行路径显式
    /// 调 [`Config::ensure_runtime_dirs`]。入口先
    /// `product_cfg.fold_appends_into_base()`：worker / offline / standalone
    /// 单层路径不走 chain_resolve，也要能吃用户 toml 里的 `+base_packages` 等
    /// append 字段。
    pub(crate) fn merge_configs(
        product: &str,
        mut global: CrbsConfig,
        mut product_cfg: ProductConfig,
    ) -> crate::Result<Self> {
        product_cfg.fold_appends_into_base();

        // 空串归一化（"" = 未设置 → None，让全局兜底；指纹侧已把 ""≡None 钉为
        // 同帧，engine/init/mod.rs）：产品层 releasever / shared_layer_staleness
        // / ccache_max_size / gpg_signing_key_id 与全局层 gpg / releasever。
        // staleness 按 trim 判空（对齐 parse_staleness 空白语义）；全局 ccache
        // 是 String 兜底字段无 None 可归，空串由下方格式校验拒绝。
        if product_cfg.releasever.as_deref() == Some("") {
            product_cfg.releasever = None;
        }
        if product_cfg
            ._buildhost
            .as_deref()
            .is_some_and(|s| s.trim().is_empty())
        {
            // _buildhost "" = 未设置，回落默认 "crbs"，避免空 BUILDHOST 进包头。
            product_cfg._buildhost = None;
        }
        if product_cfg
            .shared_layer_staleness
            .as_deref()
            .is_some_and(|s| s.trim().is_empty())
        {
            product_cfg.shared_layer_staleness = None;
        }
        if product_cfg.ccache_max_size.as_deref() == Some("") {
            product_cfg.ccache_max_size = None;
        }
        if product_cfg.gpg_signing_key_id.as_deref() == Some("") {
            product_cfg.gpg_signing_key_id = None;
        }
        if global.gpg_signing_key_id.as_deref() == Some("") {
            global.gpg_signing_key_id = None;
        }
        if global.releasever.as_deref() == Some("") {
            global.releasever = None;
        }

        // crbs_root 是机器级配置（state DB / privilege helper / crbs_group 等所有
        // 命令共享）。ProductConfig.crbs_root 仅向后兼容保留，忽略并 warn——产品级
        // 值会让 build 与 status/gc 路径写不同 state DB，crbs status 看不到记录。
        if let Some(ref p) = product_cfg.crbs_root {
            warn!(
                product = %product,
                product_crbs_root = %p.display(),
                effective_crbs_root = %global.crbs_root.display(),
                "product toml 'crbs_root' is ignored; state DB path is determined by /etc/crbs/crbs.toml"
            );
        }
        let crbs_root = global.crbs_root.clone();

        // 全局 ccache_dir 不参与合并（ccache 按产品隔离到 {crbs_root}/ccache/
        // {product}）；字段非 Option，显式设置靠"偏离默认值"检测，非默认即 warn。
        if global.ccache_dir != default_ccache_dir() {
            warn!(
                product = %product,
                global_ccache_dir = %global.ccache_dir.display(),
                "global 'ccache_dir' has no effect; set ccache_dir per product in products/<product>.toml instead"
            );
        }

        let product_root = product_cfg
            .product_root
            .or_else(|| global.product_root.clone())
            .unwrap_or_else(|| crbs_root.join(product));

        let mut cfg = Self {
            product: product.to_string(),
            crbs_root: crbs_root.clone(),
            // result_dir / shared_layers_dir：产品 > 全局显式 > 随 crbs_root 派生
            //（未配置随各自世界 root 派生，引擎与 server 的结果/共享层天然隔离）。
            result_dir: product_cfg
                .result_dir
                .or(global.result_dir.clone())
                .unwrap_or_else(|| global.result_dir_or_derived()),
            shared_layers_dir: product_cfg
                .shared_layers_dir
                .or(global.shared_layers_dir.clone())
                .unwrap_or_else(|| global.shared_layers_dir_or_derived()),
            product_root: product_root.clone(),
            base_os_path: product_cfg
                .base_os_path
                .or_else(|| global.base_os_path.clone())
                .unwrap_or_else(|| product_root.join("base")),
            dnf_cache_path: product_cfg
                .dnf_cache_path
                .or_else(|| global.dnf_cache_path.clone())
                .unwrap_or_else(|| product_root.join("dnf-cache")),
            builder_user: product_cfg.builder_user.unwrap_or(global.builder_user),
            builder_uid: product_cfg.builder_uid.unwrap_or(global.builder_uid),
            builder_group: product_cfg.builder_group.unwrap_or(global.builder_group),
            builder_gid: product_cfg.builder_gid.unwrap_or(global.builder_gid),
            shared_layer_gc_grace_hours: product_cfg
                .shared_layer_gc_grace_hours
                .unwrap_or(global.shared_layer_gc_grace_hours),
            result_gc_grace_hours: product_cfg
                .result_gc_grace_hours
                .unwrap_or(global.result_gc_grace_hours),
            shared_layer: product_cfg.shared_layer.unwrap_or(global.shared_layer),
            shared_layer_staleness: validation::parse_staleness(
                product_cfg
                    .shared_layer_staleness
                    .as_deref()
                    .or(global.shared_layer_staleness.as_deref())
                    .unwrap_or(""),
            )?,
            build_tmpfs: product_cfg.build_tmpfs.unwrap_or(global.build_tmpfs),
            tmpfs_dir: product_cfg.tmpfs_dir.unwrap_or(global.tmpfs_dir),
            // tmp_dir 不能复用 global 的派生 helper：本结构体前序字段已部分
            // move global，closure 借用会撞 E0382——用已克隆的 crbs_root 本地量。
            tmp_dir: product_cfg
                .tmp_dir
                .clone()
                .or(global.tmp_dir.clone())
                .unwrap_or_else(|| crbs_root.join("tmp")),
            gpg_signing_key_id: product_cfg
                .gpg_signing_key_id
                .or_else(|| global.gpg_signing_key_id.clone()),
            gpg_home: product_cfg.gpg_home.or_else(|| global.gpg_home.clone()),
            gpg_signing_enabled: product_cfg
                .gpg_signing_enabled
                .or(global.gpg_signing_enabled),

            base_packages: product_cfg.base_packages,
            repos: product_cfg.repos,
            arches: product_cfg.arches,
            releasever: product_cfg.releasever.or_else(|| global.releasever.clone()),
            overlay_dir: product_cfg.overlay_dir,
            post_init: product_cfg.post_init.unwrap_or_default(),
            rpm_macros: merge_rpm_macros(&global.rpm_macros, product_cfg.rpm_macros.as_ref()),
            ccache_enabled: product_cfg.ccache_enabled.unwrap_or(global.ccache_enabled),
            ccache_dir: product_cfg
                .ccache_dir
                .unwrap_or_else(|| crbs_root.join("ccache").join(product)),
            ccache_max_size: product_cfg
                .ccache_max_size
                .unwrap_or(global.ccache_max_size),
            dnf_cache_enabled: product_cfg
                .dnf_cache_enabled
                .unwrap_or(global.dnf_cache_enabled),
            builddep_install_weak_deps: product_cfg.builddep_install_weak_deps,
            package_cache_path: global
                .package_cache_path
                .clone()
                .unwrap_or_else(|| crbs_root.join("cache").join("packages")),
            build_target: validation::validate_build_target(
                product_cfg.build_target.as_deref(),
                &global.build_target,
            )?,
            nocheck: product_cfg.nocheck.unwrap_or(global.nocheck),
            noclean: product_cfg.noclean.unwrap_or(global.noclean),
            nodebuginfo: product_cfg.nodebuginfo.unwrap_or(global.nodebuginfo),
            backend: validation::validate_backend(
                product_cfg.backend.as_deref().or(global.backend.as_deref()),
            )?,
            memory_max: validation::validate_memory_max_optional(
                product_cfg
                    .memory_max
                    .as_deref()
                    .or(global.memory_max.as_deref()),
            )?,
            cpu_quota: validation::validate_cpu_quota_optional(
                product_cfg
                    .cpu_quota
                    .as_deref()
                    .or(global.cpu_quota.as_deref()),
            )?,
            network: product_cfg.network.unwrap_or(global.network),
            local_repo: product_cfg.local_repo,
            chain_parallelism: product_cfg
                .chain_parallelism
                .unwrap_or(global.chain_parallelism),
            chain_max_recovery_rounds: product_cfg
                .chain_max_recovery_rounds
                .unwrap_or(global.chain_max_recovery_rounds),
            resource_sample_interval_secs: product_cfg
                .resource_sample_interval_secs
                .unwrap_or(global.resource_sample_interval_secs),
            resource_sample_interval_cgroup_secs: product_cfg
                .resource_sample_interval_cgroup_secs
                .or(global.resource_sample_interval_cgroup_secs),
            build_max_retries: product_cfg
                .build_max_retries
                .unwrap_or(global.build_max_retries),
            build_retry_backoff_ms: product_cfg
                .build_retry_backoff_ms
                .unwrap_or(global.build_retry_backoff_ms),
            package_cache_max_size_gb: product_cfg
                .package_cache_max_size_gb
                .or(global.package_cache_max_size_gb),
            package_cache_evict_referenced: product_cfg
                .package_cache_evict_referenced
                .unwrap_or(global.package_cache_evict_referenced),
            result_max_count_per_pkg: product_cfg
                .result_max_count_per_pkg
                .or(global.result_max_count_per_pkg),
            result_retention_days: product_cfg
                .result_retention_days
                .or(global.result_retention_days),
            package_url_cache_ttl_days: product_cfg
                .package_url_cache_ttl_days
                .unwrap_or(global.package_url_cache_ttl_days),
            // base 快照保留代数为全局基础设施配置（无产品级覆盖入口）。
            base_snapshot_keep_generations: global.base_snapshot_keep_generations,
            reproduce_enabled: product_cfg
                .reproduce_enabled
                .unwrap_or(global.reproduce_enabled),
            deterministic: product_cfg.deterministic,
            mtime_normalize: product_cfg.mtime_normalize,
            // `_buildhost` 默认 "crbs"：固定值消除宿主机名这一环境变量，产品可
            // 按产品覆盖；默认字面量收口在此单点。
            buildhost: product_cfg
                ._buildhost
                .clone()
                .unwrap_or_else(|| "crbs".to_string()),
            hooks: merge_hooks(global.hooks.as_ref(), product_cfg.hooks.as_ref()),
        };

        // 确定性前置跨层校验：deterministic 在产品级、dnf_cache_enabled / build_target
        // 兜底在全局，须在三者合并为生效值后校验，坏组合加载期 fail-fast
        //（含 worker 收到 hub 下发 TOML 后的启动路径）。
        validation::validate_deterministic_preconditions(
            cfg.deterministic,
            &cfg.build_target,
            cfg.dnf_cache_enabled,
        )?;

        validation::validate_unix_name(&cfg.builder_user, "builder_user")?;
        validation::validate_unix_name(&cfg.builder_group, "builder_group")?;

        // ccache_max_size 直通 `ccache -M {size}`：坏格式运行期经 `|| warn`
        // 静默降级为无上限缓存，加载期在合并值上拦截（全局/产品来源都覆盖）。
        validation::validate_ccache_max_size(&cfg.ccache_max_size)?;

        // chain_parallelism=0 令 depsolve Semaphore::new(0) 永久挂起（chain 卡死
        // 无超时无报错），配置层直接拒绝。
        validation::require_positive_usize("chain_parallelism", cfg.chain_parallelism)?;

        // repo name 拼接进 dnf --repofrompath/--setopt，逗号/空白/冒号会让
        // chain 中途的 repoquery / installroot 失败。
        for repo in &cfg.repos {
            validation::validate_repo_name(&repo.name)?;
        }

        // 产品侧 rpm_macros 键名 / dist 值白名单：五个加载入口全过 merge_configs，
        // 坏条目在磁盘/下发字符串加载期即拒。
        if let Some(macros) = &product_cfg.rpm_macros {
            for (key, value) in macros {
                if let Err(e) = crate::build_options::validate_rpm_macro_entry(key, value) {
                    return Err(CrbsError::ValidationFailed {
                        message: format!("product '{}': rpm_macros: {}", product, e),
                    });
                }
            }
        }

        if let Some(v) = cfg.package_cache_max_size_gb {
            validation::require_positive_u64("package_cache_max_size_gb", v)?;
        }
        if let Some(v) = cfg.result_max_count_per_pkg {
            validation::require_positive_usize("result_max_count_per_pkg", v)?;
        }
        if let Some(v) = cfg.result_retention_days {
            validation::require_positive_u64("result_retention_days", v)?;
        }

        // u64 时间参数上界：≥ 2^63 在 SQL 侧 `as i64` 回绕成负，"N 天前"变未来
        // 时刻，retention/ttl GC 会匹配所有行；全局/产品来源都在合并值上拦截。
        validation::require_i64_representable_u64(
            "shared_layer_gc_grace_hours",
            cfg.shared_layer_gc_grace_hours,
        )?;
        validation::require_i64_representable_u64(
            "result_gc_grace_hours",
            cfg.result_gc_grace_hours,
        )?;
        if let Some(v) = cfg.result_retention_days {
            validation::require_i64_representable_u64("result_retention_days", v)?;
        }
        validation::require_i64_representable_u64(
            "package_url_cache_ttl_days",
            cfg.package_url_cache_ttl_days,
        )?;

        // 校验所有来自配置或推导出的路径：绝对、规范化、不含 `..` 穿越。
        cfg.crbs_root = validation::validate_config_path(&cfg.crbs_root, "crbs_root")?;
        cfg.result_dir = validation::validate_config_path(&cfg.result_dir, "result_dir")?;
        cfg.shared_layers_dir =
            validation::validate_config_path(&cfg.shared_layers_dir, "shared_layers_dir")?;
        cfg.product_root = validation::validate_config_path(&cfg.product_root, "product_root")?;
        cfg.base_os_path = validation::validate_config_path(&cfg.base_os_path, "base_os_path")?;
        cfg.dnf_cache_path =
            validation::validate_config_path(&cfg.dnf_cache_path, "dnf_cache_path")?;
        cfg.ccache_dir = validation::validate_config_path(&cfg.ccache_dir, "ccache_dir")?;
        cfg.package_cache_path =
            validation::validate_config_path(&cfg.package_cache_path, "package_cache_path")?;
        cfg.tmpfs_dir = validation::validate_config_path(&cfg.tmpfs_dir, "tmpfs_dir")?;
        cfg.tmp_dir = validation::validate_config_path(&cfg.tmp_dir, "tmp_dir")?;
        validation::validate_opt_path(&mut cfg.overlay_dir, "overlay_dir")?;
        validation::validate_opt_path(&mut cfg.local_repo, "local_repo")?;
        if let Some(ref p) = cfg.gpg_home {
            cfg.gpg_home = Some(
                validation::validate_config_path(std::path::Path::new(p), "gpg_home")?
                    .to_string_lossy()
                    .into_owned(),
            );
        }

        if cfg.package_cache_evict_referenced {
            warn!(
                product = %product,
                "package_cache_evict_referenced=true: referenced packages may be evicted from cache, breaking reproduce"
            );
        }

        Ok(cfg)
    }

    /// 系统共享 tmp 目录（tmpfs_dir/tmp_dir 的默认值）：由 systemd-tmpfiles
    /// 管理（1777 sticky），绝不能按 crbs 不变量改属主/权限。
    fn is_system_tmp(p: &std::path::Path) -> bool {
        matches!(
            p.to_str(),
            Some("/tmp") | Some("/var/tmp") | Some("/dev/shm")
        )
    }

    /// 按需创建所有运行时目录（crbs_root / result_dir / ... 必建 + overlay_dir
    /// / local_repo 可选；系统共享 tmp 除外，见 `is_system_tmp`），并保证目录
    /// 属组/权限符合项目不变量（2770 + crbs 组）。**仅构建执行路径调用**，读
    /// 路径不建目录。幂等（create_dir_all 对已存在目录 no-op）：Linux 快路径下
    /// 目录已就绪时跳过 chmod/chown（见 `privilege::ensure_directory`）；非
    /// Linux 无 stat 快路径，每次调用执行一次 chmod。
    pub fn ensure_runtime_dirs(&self) -> crate::Result<()> {
        privilege::ensure_directory(&self.crbs_root, "crbs_root")?;
        privilege::ensure_directory(&self.result_dir, "result_dir")?;
        privilege::ensure_directory(&self.shared_layers_dir, "shared_layers_dir")?;
        privilege::ensure_directory(&self.product_root, "product_root")?;
        // base_os_path 刻意不 ensure：空 base 目录会让 `crbs init` 的
        // "already exists" 守卫与引擎 init 快路径把「未初始化」误判为「已初始化」；
        // base 由 init 的 tmp→rename 产出，未 init 产品在挂载 base 处自然报错。
        privilege::ensure_directory(&self.dnf_cache_path, "dnf_cache_path")?;
        privilege::ensure_directory(&self.ccache_dir, "ccache_dir")?;
        privilege::ensure_directory(&self.package_cache_path, "package_cache_path")?;
        // 系统共享 tmp（/dev/shm、/var/tmp）由 systemd-tmpfiles 管理（1777
        // sticky）：按 crbs 不变量 chmod 2770 会让 root 引擎破坏其它用户的
        // rpmbuild/dnf 临时文件；仅当用户显式指到自有目录时才纳入 ensure。
        if !Self::is_system_tmp(&self.tmpfs_dir) {
            privilege::ensure_directory(&self.tmpfs_dir, "tmpfs_dir")?;
        }
        if !Self::is_system_tmp(&self.tmp_dir) {
            privilege::ensure_directory(&self.tmp_dir, "tmp_dir")?;
        }
        if let Some(ref p) = self.overlay_dir {
            privilege::ensure_directory(p, "overlay_dir")?;
        }
        if let Some(ref p) = self.local_repo {
            privilege::ensure_directory(p, "local_repo")?;
        }
        Ok(())
    }
}
