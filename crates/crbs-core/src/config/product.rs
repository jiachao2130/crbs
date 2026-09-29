// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产品配置模型与 TOML 读写，含仓库、发布/消费轴与资源覆盖。

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::config_path;
use crate::config::BoolOrPackages;
use crate::config::HooksConfig;
use crate::config::RepoConfig;
use crate::error::CrbsError;

/// 产品配置（`/etc/crbs/products/{product}.toml`）。
///
/// 产品特有字段（`base_packages` / `repos`）入口放开为可选（`serde(default)`）
/// 供子产品只写 `+field` 追加，空非法性由 chain-resolve 出口校验兜底（下发
/// 结果必须非空，否则 `ProductChainInvalid`）。`+field` = 追加到 parent 合并
/// 后的 Vec 末尾（非 replace），仅存在于用户输入 / DB 存储，chain_resolve
/// 出口 fold 后 wire 永不出现，不进入 worker 输入面。同名字段用 `Option`：
/// 省略 = 继承全局值；反序列化缺失视为默认值。`Default` 供 Fork 命令建
/// "空 config + parent_id"活链接子产品。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductConfig {
    // 产品标识：与文件名一致，仅供人读；程序内部以 load(product) 参数为准
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,

    // 产品特有：serde(default) 放开，非空由 validate_resolved_shape 出口兜底
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub base_packages: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<RepoConfig>,

    /// `+base_packages` 追加：折进 parent 合并后的 `base_packages` 末尾。
    #[serde(
        default,
        rename = "+base_packages",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub base_packages_append: Vec<String>,
    /// `+repos` 追加：折进 parent 合并后的 `repos` 末尾；`name` 冲突由出口
    /// `check_repo_names_unique` 报 `ProductChainInvalid`。
    #[serde(default, rename = "+repos", skip_serializing_if = "Vec::is_empty")]
    pub repos_append: Vec<RepoConfig>,
    /// `+arches` 追加：折进 parent 合并后的 `arches` 末尾。
    #[serde(default, rename = "+arches", skip_serializing_if = "Vec::is_empty")]
    pub arches_append: Vec<String>,
    /// `+post_init` 追加：折进 parent 的 `post_init` 末尾；parent 为 None 时提升为 Some。
    #[serde(default, rename = "+post_init", skip_serializing_if = "Vec::is_empty")]
    pub post_init_append: Vec<PostInitCommand>,

    /// 产品支持的架构列表：不写 = 单架构模式（按提交指定架构构建），写 =
    /// 多架构构建的默认架构集。继承边界：空 `Vec` 与未写不可
    /// 区分，合并时继承父列表，空列表的"单架构回退"无法经继承链表达（只能
    /// 重建产品或等 reset 语法；`base_packages`/`repos` 尚可非空整体替换脱钩）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arches: Vec<String>,

    /// noarch 构建的宿主偏好架构集（集合语义，无序）：收敛 noarch 行在
    /// fan-out 时物化为 builds.host_arches，仅这些架构的 worker 可领取——
    /// 依赖覆盖不全的架构（如 loong/sw）可经此排除。空/未写 = 不限制（现
    /// 行为）。token 经 validate_arch 白名单校验；约束随构建行提交时冻结。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub noarch_preferred_arches: Vec<String>,
    /// `+noarch_preferred_arches` 追加：折进 parent 合并后的偏好集末尾。
    #[serde(
        default,
        rename = "+noarch_preferred_arches",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub noarch_preferred_arches_append: Vec<String>,

    // dnf --releasever，未配置时尝试从宿主 /etc/os-release 推断
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub releasever: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_dir: Option<PathBuf>,
    /// `post_init = []` = 整体替换继承列表——唯一可"替换为空"的 Vec 字段
    ///（`Option<Vec>`，空 `Some` 即 REPLACE）；普通 Vec 字段空列表 = 继承父层。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_init: Option<Vec<PostInitCommand>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_gid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crbs_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_layers_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_os_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnf_cache_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_layer_gc_grace_hours: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_gc_grace_hours: Option<u64>,
    /// 共享层启用开关。链合并：Some 即覆盖父层，`Packages([])` = 显式禁用
    /// 父层启用集（省略 = 继承父层）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_layer: Option<BoolOrPackages>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_layer_staleness: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_tmpfs: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmpfs_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmp_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpg_signing_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpg_home: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpg_signing_enabled: Option<bool>,

    // RPM 宏。BTreeMap：key 排序迭代，DB config_json / chain-resolve TOML /
    // history diff 序列化跨进程逐字节确定。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpm_macros: Option<BTreeMap<String, String>>,

    /// ccache 启用开关。链合并同 `shared_layer`：`Packages([])` = 显式禁用
    /// 父层启用集（省略 = 继承）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ccache_enabled: Option<BoolOrPackages>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ccache_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ccache_max_size: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnf_cache_enabled: Option<bool>,

    /// `dnf builddep` 是否安装 weak deps（Recommends），仅 builddep 装包路径
    ///（pipeline::install_deps_bash）读取，base_os init 装包不读。省略 = dnf
    /// 默认（安装）；显式 false 追加 `--setopt=install_weak_deps=False`，收窄
    /// 装包集、降低构建环境方差（同 Koji install_weak_deps=False）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builddep_install_weak_deps: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_target: Option<String>,

    // 跳过 %check 阶段
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nocheck: Option<bool>,

    // 跳过 distro 收尾清理段（%clean 与 rmbuild）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noclean: Option<bool>,

    // 不生成 debuginfo 包
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodebuginfo: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,

    // 资源限制（仅 nspawn backend 生效）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_max: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_quota: Option<String>,

    // 网络控制（true = 共享宿主网络，false = 隔离）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<bool>,

    /// 发布开关（发布轴，产品配置肯定式）：成功构建的 RPM 是否发布进产品
    /// repo。省略 = 默认发布；显式 false = 长期不发布（regen 候选集按空收敛，
    /// repo 目录保留零包）。与消费轴正交，与逐构建收紧（--no-publish）独立
    /// 叠加；私有产品的 repo 访问另有可见性门（两层互不影响）。
    #[serde(
        rename = "repo-publish",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub repo_publish: Option<bool>,

    /// 消费开关（消费轴，产品配置肯定式）：后续构建的 builddep 是否注入本
    /// 产品 repo（crbs-product.repo）。省略 = 默认消费；显式 false = 长期不
    /// 注入。与发布轴 `repo-publish` 正交——发布侧清空候选集不影响本开关，
    /// 反之亦然。生效值随构建行提交时快照（private 产品一票否决、逐构建
    /// `--no-consume` 只许收紧），产品配置后续变更不影响已排队构建。
    #[serde(
        rename = "repo-consume",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub repo_consume: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_repo: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_parallelism: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_max_recovery_rounds: Option<usize>,

    // 构建资源采样间隔（秒），0 = 关闭
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_sample_interval_secs: Option<u64>,

    // cgroup 口径采样间隔（秒，采样分级）：None = 5s 引擎常量、Some(0) = 关闭
    // cgroup 口径、Some(n) = n 秒，与 resource_sample_interval_secs 互不牵连。
    // 随产品 wire TOML 下发 worker（同键形态）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_sample_interval_cgroup_secs: Option<u32>,

    /// 包级静态资源画像覆盖（键 = 包名），仅 hub 调度器读取：该包资源 EMA
    /// 缺失时的回退值（冷启动/样本稀疏期让重型包提前进入准入门量纲）。
    /// 不下发 worker：`chain_resolve_to_toml` 组装 wire 前剔除本键（worker
    /// 侧 `ProductConfig` 禁未知键）。BTreeMap 同 `rpm_macros`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_overrides: Option<BTreeMap<String, ResourceOverride>>,

    // 构建 transient 失败自动重试
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_max_retries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_retry_backoff_ms: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_cache_max_size_gb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_cache_evict_referenced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_max_count_per_pkg: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_retention_days: Option<u64>,

    /// recipe GC 钉住窗口：`recipe.json` 生成后该天数内其引用 sha256 免
    /// package cache GC 驱逐（热重放窗口）。性能优化非正确性前提：缺失可经
    /// build_packages.json 的 url 重下载 + sha256 校验恢复，只影响重放首跑
    /// 耗时。省略 = 90 天；0 = 禁用。扫描入口是 tasks.result_dir 行，tasks 行
    /// 由 `db_retention_days`（默认同为 90 天）prune：本值更大时有效窗口被
    /// 静默截断为两者较小值（前提：部署在跑 result GC）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipe_retention_days: Option<u64>,

    // URL 解析缓存 TTL（天）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_url_cache_ttl_days: Option<u64>,

    /// 是否记录 provenance 用于 reproduce。链合并同 `shared_layer`：
    /// `Packages([])` = 显式禁用父层启用集（省略 = 继承）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reproduce_enabled: Option<BoolOrPackages>,

    /// 纯 noarch SRPM 是否每架构各建一次。缺省 false = 收敛单构建：按 NVR
    /// 稳定哈希轮转选派发架构（同 NVR 恒定同架构），`--target noarch` 注入
    /// 不变。true = 每架构构建并激活 cross-arch 字节互比探针（replay 判定仅
    /// 此形态有数据）；Some 即覆盖父层；rebuild 不受影响。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noarch_per_arch: Option<bool>,

    /// 确定性构建模式，默认 false。true 时自动携带确定性
    /// 宏组 / env 基线 / hostname 钉死 / ccache 守卫，强制溯源落盘 + 完整性
    /// 硬门（无视 `reproduce_enabled`）。合并后校验（merge_configs）：生效
    /// `dnf_cache_enabled` 须为 true（产品级显式 false 覆盖全局 true 仍报错）、
    /// `build_target` 不得为 `ba`（每架构 `-ba` 重造 SRPM 引入字节歧义）。
    /// 链合并 plain bool：任一层 true 即生效（OR），父层开启子层无法关闭。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deterministic: bool,

    /// 普通构建时间自锚定（非 det 产品的可复现卫生）：构建起点取墙钟 S，
    /// BUILDTIME 头与 payload 文件 mtime 统一为 S。效果：回放（锚 = 源构建
    /// BUILDTIME）与源构建逐字节一致；两次普通构建之间仍不同（各自 S）。
    /// det 产品忽略本开关（changelog-SDE 语义更强，宏组天然覆盖）。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mtime_normalize: bool,

    /// 自动跟跑：deterministic 产品构建成功后 hub 跟跑一次锁定环境重放。
    /// 省略 = true；显式 false 关闭（重放受后台档 + 空闲派发约束，资源占用有界）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_replay: Option<bool>,

    /// 跟跑抽样（总量闸）：0-100 百分比，按 task 哈希确定性抽样。省略 =
    /// 100（全量）；0 = 关闭；>100 触发点按 100 收敛并 warn（不阻塞构建）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_sampling: Option<u8>,

    /// `_buildhost` 宏值（RPM 包头 BUILDHOST）。未配置时合并后用 "crbs"
    ///（固定值消除宿主机名环境变量，溯源区分由 builds.product 承担，不进构建字节）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub _buildhost: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hooks: Option<HooksConfig>,

    /// 本产品 SRPM 下载策略覆盖（消费点：artifacts 下载路由的 `*.src.rpm`
    /// 分支）。三态：省略 = 跟随 server.toml 全局 `allow_srpm_download`；
    /// `true` = 本产品源码包公开可下（覆盖全局 false）；`false` = 仅
    /// operator/admin 可下（覆盖全局 true）。`public_access.download` 全局门
    /// 在其之上独立生效（false 时任何下载都先要登录）。链合并 Some 覆盖父层。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_srpm_download: Option<bool>,
}

impl ProductConfig {
    /// 读取产品配置 `{config_dir}/products/{product}.toml`（config_dir 优先
    /// `CRBS_CONFIG_DIR`，未设置用 `/etc/crbs`）。同步 IO：async 上下文须
    /// `tokio::task::spawn_blocking` 包裹。
    pub fn load(product: &str) -> crate::Result<Self> {
        // pub API 防御纵深：product 拼进文件路径，独立于调用方校验再拦一次。
        crate::validation::validate_product(product)?;
        let path = config_path(format!("products/{}.toml", product))?;
        let content = std::fs::read_to_string(&path).map_err(|e| {
            CrbsError::from_io_context(format!("read product config {}", path.display()), e)
        })?;
        Self::from_str(&content)
    }

    /// 从 TOML 字符串解析产品配置（用于 Worker 接收 Hub 下发的配置）。
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(content: &str) -> crate::Result<Self> {
        let cfg: ProductConfig =
            toml::from_str(content).map_err(|e| CrbsError::ValidationFailed {
                message: format!("parse product config: {}", e),
            })?;
        Ok(cfg)
    }

    /// 序列化为 TOML 字符串（chain-resolved 配置下发 worker）。失败视为内部
    /// 错误：`Serialize` 只在字符串编码时出错。
    pub fn to_toml_string(&self) -> crate::Result<String> {
        toml::to_string(self)
            .map_err(|e| CrbsError::io_message(format!("serialize product config: {}", e)))
    }

    /// 把 4 个 `*_append` 字段折进对应 base Vec 后清空。调用契约：chain_resolve
    /// 须先对根层调用（否则根层 `+field` 被后续 replace 逻辑丢弃），merge child
    /// 时对 child 侧再折；merge_configs 入口同样调用（不走 chain_resolve 的
    /// 路径）。`post_init` 为 None 时提升为 `Some(vec![])` 再 extend。
    pub fn fold_appends_into_base(&mut self) {
        if !self.base_packages_append.is_empty() {
            let append = std::mem::take(&mut self.base_packages_append);
            self.base_packages.extend(append);
        }
        if !self.repos_append.is_empty() {
            let append = std::mem::take(&mut self.repos_append);
            self.repos.extend(append);
        }
        if !self.arches_append.is_empty() {
            let append = std::mem::take(&mut self.arches_append);
            self.arches.extend(append);
        }
        if !self.post_init_append.is_empty() {
            let append = std::mem::take(&mut self.post_init_append);
            self.post_init.get_or_insert_with(Vec::new).extend(append);
        }
    }
}

/// 收集显式设置（`Some`）的机器本地路径覆盖字段（透传可见化）：任一层设置
/// 都随 chain-resolved TOML 原样下发并在 worker 生效（同构 NFS 舰队合法
/// 用法），非空时 dispatch 侧聚合一条 info 日志。`crbs_root` 不收：链出口
/// 已剥离。
pub fn path_overrides(cfg: &ProductConfig) -> Vec<(&'static str, &std::path::Path)> {
    let mut out = Vec::new();
    if let Some(p) = &cfg.result_dir {
        out.push(("result_dir", p.as_path()));
    }
    if let Some(p) = &cfg.shared_layers_dir {
        out.push(("shared_layers_dir", p.as_path()));
    }
    if let Some(p) = &cfg.product_root {
        out.push(("product_root", p.as_path()));
    }
    if let Some(p) = &cfg.base_os_path {
        out.push(("base_os_path", p.as_path()));
    }
    if let Some(p) = &cfg.dnf_cache_path {
        out.push(("dnf_cache_path", p.as_path()));
    }
    if let Some(p) = &cfg.ccache_dir {
        out.push(("ccache_dir", p.as_path()));
    }
    out
}

/// base_os init 收尾时执行的产品级后置命令（证书、镜像源等定制钩子）。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostInitCommand {
    pub command: String,
    /// 命令失败时是否继续 init。默认 false：失败 → init 失败，防定制静默
    /// 缺失后 base_os 被标完成。
    #[serde(default)]
    pub ignore_failure: bool,
}

/// 单包静态资源画像（`resource_overrides` 值类型）。两字段均必填（画像缺
/// 维度 = 没配）。量纲：`mem_gb` = 峰值常驻内存 GiB（换算 KB 与
/// `builds.peak_rss_kb` 同纲）、`cpu_cores` 同 `builds.cpu_p90_cores`；
/// 有限正值校验收口在 `validate_resolved_shape`。
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceOverride {
    pub mem_gb: f64,
    pub cpu_cores: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `+base_packages` 反序列化到 `base_packages_append`，与老 `base_packages`
    /// 共存不冲突。
    #[test]
    fn plus_field_deserializes_into_append() {
        let toml_src = r#"
"+base_packages" = ["extra-pkg"]
"+arches" = ["riscv64"]
"#;
        let cfg = ProductConfig::from_str(toml_src).unwrap();
        assert!(cfg.base_packages.is_empty());
        assert!(cfg.repos.is_empty());
        assert_eq!(cfg.base_packages_append, vec!["extra-pkg"]);
        assert_eq!(cfg.arches_append, vec!["riscv64"]);
        assert!(cfg.repos_append.is_empty());
        assert!(cfg.post_init_append.is_empty());
    }

    /// `+repos` 追加解析到 `repos_append`；同一 TOML 同时含 `repos` 和 `+repos` 合法。
    #[test]
    fn plus_repos_and_repos_coexist() {
        let toml_src = r#"
base_packages = ["base"]

[[repos]]
name = "root-repo"
baseurl = "http://root/"

[["+repos"]]
name = "child-append-repo"
baseurl = "http://child/"
"#;
        let cfg = ProductConfig::from_str(toml_src).unwrap();
        assert_eq!(cfg.base_packages, vec!["base"]);
        assert_eq!(cfg.repos.len(), 1);
        assert_eq!(cfg.repos[0].name, "root-repo");
        assert_eq!(cfg.repos_append.len(), 1);
        assert_eq!(cfg.repos_append[0].name, "child-append-repo");
    }

    /// `+field` roundtrip（rename 双向）。序列化保留 `"+base_packages"` key
    ///（DB `config_json` 人类可认），wire 侧由 chain_resolve fold 移除。TOML
    /// 语法：顶层标量键必须放在 `[[table]]` 表头之前，否则归属上一表。
    #[test]
    fn plus_field_roundtrip() {
        let original = r#"
base_packages = ["a"]
"+base_packages" = ["b", "c"]
"+arches" = ["aarch64"]

[[repos]]
name = "r"
baseurl = "http://r/"
"#;
        let cfg1 = ProductConfig::from_str(original).unwrap();
        assert_eq!(cfg1.base_packages, vec!["a"]);
        assert_eq!(cfg1.base_packages_append, vec!["b", "c"]);
        assert_eq!(cfg1.arches_append, vec!["aarch64"]);
        assert_eq!(cfg1.repos.len(), 1);

        let s = cfg1.to_toml_string().unwrap();
        let cfg2 = ProductConfig::from_str(&s).unwrap();
        assert_eq!(cfg1.base_packages, cfg2.base_packages);
        assert_eq!(cfg1.base_packages_append, cfg2.base_packages_append);
        assert_eq!(cfg1.arches_append, cfg2.arches_append);
        assert_eq!(cfg1.repos_append.len(), cfg2.repos_append.len());
    }

    /// `Default` 可构造、序列化为近乎空 TOML、空 TOML 可反解（Fork 命令依赖
    /// `default()` 建"空 config + parent_id"活链接）。
    #[test]
    fn default_config_is_constructible_and_roundtrips() {
        let cfg = ProductConfig::default();
        assert!(cfg.base_packages.is_empty());
        assert!(cfg.repos.is_empty());
        assert!(cfg.base_packages_append.is_empty());
        assert!(cfg.product.is_none());

        let s = cfg.to_toml_string().unwrap();
        assert!(!s.contains("base_packages"), "unexpected key: {}", s);
        assert!(!s.contains("+base_packages"), "unexpected key: {}", s);

        let cfg2 = ProductConfig::from_str(&s).unwrap();
        assert!(cfg2.base_packages.is_empty());
        assert!(cfg2.repos.is_empty());
    }

    /// 无 `base_packages` / `repos` 的 TOML 反序列化 OK；非空由出口
    /// `validate_resolved_shape` 兜底。
    #[test]
    fn missing_base_and_repos_deserializes_ok() {
        let toml_src = r#"
arches = ["x86_64"]
"#;
        let cfg = ProductConfig::from_str(toml_src).unwrap();
        assert!(cfg.base_packages.is_empty());
        assert!(cfg.repos.is_empty());
        assert_eq!(cfg.arches, vec!["x86_64"]);
    }

    /// `repo-publish`（kebab）：省略 = None（默认发布），显式值如实解析，
    /// roundtrip 保持 kebab 键；旧 snake 键 `repo_publish` 拒绝（改名 breaking）。
    #[test]
    fn repo_publish_deserializes_and_defaults_none() {
        let omitted = ProductConfig::from_str("base_packages = [\"a\"]\n").unwrap();
        assert_eq!(omitted.repo_publish, None);

        let explicit_false = ProductConfig::from_str("repo-publish = false\n").unwrap();
        assert_eq!(explicit_false.repo_publish, Some(false));

        let s = explicit_false.to_toml_string().unwrap();
        assert!(s.contains("repo-publish"));
        assert_eq!(
            ProductConfig::from_str(&s).unwrap().repo_publish,
            Some(false)
        );
        assert!(
            !omitted.to_toml_string().unwrap().contains("repo"),
            "omitted dual-axis keys must not serialize"
        );
        // snake_case 键不受支持（deny_unknown_fields 拒绝）。
        let legacy = ProductConfig::from_str("repo_publish = false\n");
        assert!(legacy.is_err(), "legacy snake key must be rejected");
    }

    /// `repo-consume`：省略 = None（默认消费），显式值如实解析，roundtrip
    /// 保持 kebab 键；与 repo-publish 相互独立（正交双轴）。
    #[test]
    fn repo_consume_deserializes_and_defaults_none() {
        let omitted = ProductConfig::from_str("base_packages = [\"a\"]\n").unwrap();
        assert_eq!(omitted.repo_consume, None);

        let explicit_false = ProductConfig::from_str("repo-consume = false\n").unwrap();
        assert_eq!(explicit_false.repo_consume, Some(false));

        let s = explicit_false.to_toml_string().unwrap();
        assert!(s.contains("repo-consume"));
        assert_eq!(
            ProductConfig::from_str(&s).unwrap().repo_consume,
            Some(false)
        );

        let both = ProductConfig::from_str("repo-publish = false\nrepo-consume = false\n").unwrap();
        assert_eq!(both.repo_publish, Some(false));
        assert_eq!(both.repo_consume, Some(false));
    }

    /// `deny_unknown_fields` 守 typo：未知 key 必须拒绝。
    #[test]
    fn unknown_field_still_rejected() {
        let toml_src = r#"
base_packages = ["a"]

[[repos]]
name = "r"
baseurl = "http://r/"

typo_field = "oops"
"#;
        let err = ProductConfig::from_str(toml_src).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("typo_field") || msg.contains("unknown"),
            "got: {}",
            msg
        );
    }

    /// `resource_overrides` 解析：typo 包内字段与缺字段均拒绝（两字段必填）。
    #[test]
    fn resource_overrides_parse_and_reject_bad_shape() {
        let ok = ProductConfig::from_str(
            r#"
base_packages = ["a"]

[resource_overrides.gcc]
mem_gb = 16.0
cpu_cores = 8.0
"#,
        )
        .unwrap();
        let ov = ok.resource_overrides.as_ref().unwrap();
        assert_eq!(
            ov.get("gcc"),
            Some(&ResourceOverride {
                mem_gb: 16.0,
                cpu_cores: 8.0
            })
        );

        let typo = ProductConfig::from_str(
            r#"
[resource_overrides.gcc]
mem_gb = 16.0
cpu_core = 8.0
"#,
        )
        .unwrap_err();
        assert!(typo.to_string().contains("cpu_core"), "got: {typo}");

        let missing = ProductConfig::from_str(
            r#"
[resource_overrides.gcc]
mem_gb = 16.0
"#,
        )
        .unwrap_err();
        assert!(missing.to_string().contains("cpu_cores"), "got: {missing}");

        assert!(!ProductConfig::default()
            .to_toml_string()
            .unwrap()
            .contains("resource_overrides"));
    }

    /// fold 全 4 字段；折入后 repo 同名冲突由出口 `check_repo_names_unique`
    /// 收口，fold 本身纯追加。
    #[test]
    fn fold_appends_into_base_moves_all_four() {
        let mut cfg = ProductConfig {
            base_packages: vec!["a".into()],
            base_packages_append: vec!["b".into(), "c".into()],
            repos: vec![RepoConfig {
                name: "base".into(),
                baseurl: "http://base/".into(),
                ..Default::default()
            }],
            repos_append: vec![RepoConfig {
                name: "epel".into(),
                baseurl: "http://epel/".into(),
                ..Default::default()
            }],
            arches: vec!["x86_64".into()],
            arches_append: vec!["aarch64".into()],
            post_init: None,
            post_init_append: vec![PostInitCommand {
                command: "echo hi".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        cfg.fold_appends_into_base();
        assert_eq!(cfg.base_packages, vec!["a", "b", "c"]);
        assert!(cfg.base_packages_append.is_empty());
        assert_eq!(
            cfg.repos
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>(),
            vec!["base", "epel"]
        );
        assert!(cfg.repos_append.is_empty());
        assert_eq!(cfg.arches, vec!["x86_64", "aarch64"]);
        assert!(cfg.arches_append.is_empty());
        assert_eq!(cfg.post_init.as_ref().unwrap().len(), 1);
        assert!(cfg.post_init_append.is_empty());
    }

    /// `fold_appends_into_base`：post_init 已有 Some 时 extend 不覆盖。
    #[test]
    fn fold_appends_post_init_extends_existing_some() {
        let mut cfg = ProductConfig {
            base_packages: vec!["a".into()],
            post_init: Some(vec![PostInitCommand {
                command: "first".into(),
                ..Default::default()
            }]),
            post_init_append: vec![PostInitCommand {
                command: "second".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        cfg.fold_appends_into_base();
        let pi = cfg.post_init.as_ref().unwrap();
        assert_eq!(pi.len(), 2);
        assert_eq!(pi[0].command, "first");
        assert_eq!(pi[1].command, "second");
    }

    /// `ignore_failure`：缺省 false（失败即 init 失败）；true 降级为 warn。
    #[test]
    fn post_init_ignore_failure_deserializes_with_default() {
        let toml_src = r#"
"+post_init" = [
    { command = "hard-required" },
    { command = "best-effort", ignore_failure = true },
]
"#;
        let cfg = ProductConfig::from_str(toml_src).unwrap();
        let cmds = &cfg.post_init_append;
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].command, "hard-required");
        assert!(!cmds[0].ignore_failure);
        assert_eq!(cmds[1].command, "best-effort");
        assert!(cmds[1].ignore_failure);
    }

    /// `fold_appends_into_base`：空 `_append` 时 no-op（不改动 base / 不假造 Some）。
    #[test]
    fn fold_appends_noop_when_all_empty() {
        let mut cfg = ProductConfig {
            base_packages: vec!["a".into()],
            post_init: None,
            ..Default::default()
        };
        cfg.fold_appends_into_base();
        assert_eq!(cfg.base_packages, vec!["a"]);
        assert!(cfg.post_init.is_none());
        assert!(cfg.post_init_append.is_empty());
    }

    /// `path_overrides` 三形态：全 None → 空、部分 Some、全 Some。
    #[test]
    fn path_overrides_collects_only_some_fields() {
        assert!(path_overrides(&ProductConfig::default()).is_empty());

        let cfg = ProductConfig {
            result_dir: Some("/r".into()),
            ccache_dir: Some("/cc".into()),
            ..Default::default()
        };
        let got = path_overrides(&cfg);
        assert_eq!(
            got,
            vec![
                ("result_dir", std::path::Path::new("/r")),
                ("ccache_dir", std::path::Path::new("/cc")),
            ]
        );

        let cfg = ProductConfig {
            result_dir: Some("/r".into()),
            shared_layers_dir: Some("/sl".into()),
            product_root: Some("/p".into()),
            base_os_path: Some("/bo".into()),
            dnf_cache_path: Some("/dc".into()),
            ccache_dir: Some("/cc".into()),
            ..Default::default()
        };
        assert_eq!(path_overrides(&cfg).len(), 6);
    }
}
