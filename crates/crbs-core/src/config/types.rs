// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 配置共享类型：布尔/包集合开关与路径字段的序列化语义。

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// 解析配置文件路径：设置了 `CRBS_CONFIG_DIR` 则返回 `{CRBS_CONFIG_DIR}/{name}`，否则 `/etc/crbs/{name}`。
/// `CRBS_CONFIG_DIR` 必须为非空绝对路径：相对值会让配置解析依赖进程 CWD（cron/systemd 下不可预测），在读取处直接报错。
pub fn config_path(name: impl AsRef<Path>) -> crate::Result<PathBuf> {
    let base = match std::env::var_os("CRBS_CONFIG_DIR") {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            super::validation::validate_config_dir(&dir)?;
            dir
        }
        None => PathBuf::from("/etc/crbs"),
    };
    Ok(base.join(name))
}

/// 配置值：bool 开关 或 包名列表（TOML：`shared_layer = false` 或 `= ["kernel"]`）。
/// 链合并语义（与 plain `Vec` 族相反）：本类型字段（shared_layer / ccache_enabled /
/// reproduce_enabled）**Some 即覆盖父层**，`Packages([])` 空列表 = 显式禁用父层启用集，
/// 省略 = 继承父层；plain `Vec` 字段（base_packages / repos / arches）空列表 = 继承。
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum BoolOrPackages {
    /// 全局开关：`true`/`false` 对该能力整体生效，不区分包。
    Bool(bool),
    /// 按包启用：仅列出的包生效（从 SRPM 文件名提取包名后精确匹配）。空列表
    /// 双重语义：链合并 = 显式禁用父层启用集；[`Self::is_configured`] = 未配置。
    Packages(Vec<String>),
}

impl Default for BoolOrPackages {
    fn default() -> Self {
        Self::Bool(false)
    }
}

impl BoolOrPackages {
    /// 判断指定包是否启用：`srpm_name` 为 SRPM 文件名，从中提取包名（去掉版本-释放.src.rpm）与配置列表精确匹配。
    pub fn is_enabled_for(&self, srpm_name: &str) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::Packages(pkgs) => {
                let name = crate::util::extract_rpm_name(srpm_name);
                pkgs.iter().any(|p| name == p.as_str())
            }
        }
    }

    /// 是否为全局启用（Bool(true)）。
    pub fn is_globally_enabled(&self) -> bool {
        matches!(self, Self::Bool(true))
    }

    /// 是否配置了启用（Bool(true) 或非空 Packages）：决定是否做安装 ccache 基础包、
    /// 创建符号链接等准备工作；`Packages([])` 视为未配置（无缓存收益，白装）。
    /// 此处"未配置"仅运行时准备判断，与链合并语义不同（链内 `Packages([])` 是显式覆盖）。
    pub fn is_configured(&self) -> bool {
        match self {
            Self::Bool(false) => false,
            Self::Packages(pkgs) => !pkgs.is_empty(),
            Self::Bool(true) => true,
        }
    }
}

/// TOML 中的 spec phase hooks 配置（`[hooks.spec.pre]` / `[hooks.spec.post]`）。
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SpecHooksConfig {
    #[serde(default)]
    pub pre: HashMap<String, String>,
    #[serde(default)]
    pub post: HashMap<String, String>,
}

/// TOML 中的 hooks 配置（`[hooks.pre]` / `[hooks.post]` / `[hooks.spec.pre]` / `[hooks.spec.post]`）。
/// key 为步骤名，value 为 bash 片段，运行时转为 `Hooks`（BTreeMap）。
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HooksConfig {
    #[serde(default)]
    pub pre: HashMap<String, String>,
    #[serde(default)]
    pub post: HashMap<String, String>,
    #[serde(default)]
    pub spec: SpecHooksConfig,
}

/// 构建脚本 hook 点：key 为步骤名（如 `"install-srpm"`），value 为 bash 片段，解析自 product.toml `[hooks.*]`
/// （四个 section 名见 `HooksConfig`）。四字段 `#[serde(default)]`：wire 响应
/// （如 ProductDetail JSON）可省略其中任意字段仍可反序列化。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Hooks {
    #[serde(default)]
    pub pre: BTreeMap<String, String>,
    #[serde(default)]
    pub post: BTreeMap<String, String>,
    #[serde(default)]
    pub spec_pre: BTreeMap<String, String>,
    #[serde(default)]
    pub spec_post: BTreeMap<String, String>,
}

/// 客户端远程 server 配置。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    /// 默认远程 profile 名：`None` 或 `"local"` = 本地直接构建；其他值必须匹配 `profiles` 中某 profile 名，走该远程 server。
    #[serde(default)]
    pub default: Option<String>,

    /// 已命名的远程 server 列表。
    #[serde(default)]
    pub profiles: Vec<RemoteProfile>,
}

impl RemoteConfig {
    /// 合并用户配置中的 remote 段到当前配置：同名 profile 与默认 profile 均由用户配置覆盖。
    pub fn merge(&mut self, user: RemoteConfig) {
        if user.default.is_some() {
            self.default = user.default;
        }
        for up in user.profiles {
            if let Some(pos) = self.profiles.iter().position(|p| p.name == up.name) {
                self.profiles[pos] = up;
            } else {
                self.profiles.push(up);
            }
        }
    }

    /// 返回默认的远程 profile 名（`"local"` 视为 None）。
    pub fn default_profile(&self) -> Option<&str> {
        self.default
            .as_deref()
            .filter(|d| !d.eq_ignore_ascii_case("local"))
    }
}

/// 单个远程 server profile。
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteProfile {
    pub name: String,
    pub url: String,

    /// 直接写入配置文件的 token（不推荐）。明文密钥，`skip_serializing` 确保任何
    /// 序列化产物不携带明文 token，与 Debug 脱敏同一姿态。
    #[serde(default, skip_serializing)]
    pub token: Option<String>,

    /// 存放 token 的环境变量名。
    #[serde(default)]
    pub token_env: Option<String>,

    /// 存放 token 的文件路径，支持 `~` 前缀。
    #[serde(default)]
    pub token_file: Option<PathBuf>,

    /// 可选的 Hub CA 证书路径（自签/内网 CA 场景）。
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
}

/// `token` 是明文密钥，Debug 输出一律脱敏为 `<redacted>`，防止意外进日志。
impl fmt::Debug for RemoteProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteProfile")
            .field("name", &self.name)
            .field("url", &self.url)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("token_env", &self.token_env)
            .field("token_file", &self.token_file)
            .field("ca_cert", &self.ca_cert)
            .finish()
    }
}

/// 仓库配置
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepoConfig {
    pub name: String,
    pub baseurl: String,
    #[serde(default = "default_repo_enabled")]
    pub enabled: bool,
    #[serde(default = "default_repo_gpgcheck")]
    pub gpgcheck: bool,
    pub gpgkey: Option<String>,
    #[serde(default = "default_repo_priority")]
    pub priority: u32,
    #[serde(default = "default_repo_cost")]
    pub cost: u32,
    #[serde(default)]
    pub module_hotfixes: bool,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub includepkgs: Vec<String>,
    /// 透传给 dnf/yum 的额外 repo 选项：`key=value` 格式的行（可包含注释行和空行），
    /// 原样追加到生成的 `.repo` 文件，并经 `--setopt` 传给 dnf repoquery。
    #[serde(default)]
    pub extra: Option<String>,
}

impl Default for RepoConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            baseurl: String::new(),
            enabled: default_repo_enabled(),
            gpgcheck: default_repo_gpgcheck(),
            gpgkey: None,
            priority: default_repo_priority(),
            cost: default_repo_cost(),
            module_hotfixes: false,
            exclude: Vec::new(),
            includepkgs: Vec::new(),
            extra: None,
        }
    }
}

// pub(crate)：schema_tests 完备性测试直接取值，钉住 config.schema.json 里 RepoConfig def 的 "Default:" 文案。
pub(crate) fn default_repo_enabled() -> bool {
    true
}

pub(crate) fn default_repo_gpgcheck() -> bool {
    false
}

pub(crate) fn default_repo_priority() -> u32 {
    99
}

pub(crate) fn default_repo_cost() -> u32 {
    1000
}

pub use crate::config::crbs_config::CrbsConfig;
pub use crate::config::product::{PostInitCommand, ProductConfig, ResourceOverride};
pub use crate::config::runtime::{Config, ProductDetail};

pub use crate::config::templates::{GLOBAL_CONFIG_TEMPLATE, PRODUCT_CONFIG_TEMPLATE};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ccache_enabled_bool() {
        let cfg: CrbsConfig = toml::from_str("ccache_enabled = false\n").unwrap();
        assert_eq!(cfg.ccache_enabled, BoolOrPackages::Bool(false));
    }

    #[test]
    fn parse_example_crbs_toml() {
        let s = include_str!("../../../../examples/config/crbs.toml");
        let cfg: CrbsConfig = match toml::from_str(s) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("parse error: {}", e);
                panic!("{}", e);
            }
        };
        println!("{:?}", cfg.ccache_enabled);
    }

    #[test]
    fn parse_product_config_template() {
        let s = PRODUCT_CONFIG_TEMPLATE.replace("{product}", "fedora");
        let cfg: ProductConfig = match toml::from_str(&s) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("parse error: {}", e);
                panic!("{}", e);
            }
        };
        assert_eq!(cfg.product, None);
        assert!(!cfg.base_packages.is_empty());
        assert!(!cfg.repos.is_empty());
        // +field 追加语法必须在模板中有文档（全注释状态）——删掉即文档回退。
        assert!(PRODUCT_CONFIG_TEMPLATE.contains("+base_packages"));
    }

    #[test]
    fn parse_global_config_template() {
        // 生成路径（validation.rs::ensure_product_config_ready）原样写入模板、无替换：解析模板即等价于解析生成文件。
        let cfg: CrbsConfig = match toml::from_str(GLOBAL_CONFIG_TEMPLATE) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("parse error: {}", e);
                panic!("{}", e);
            }
        };
        assert_eq!(cfg.ccache_enabled, BoolOrPackages::Bool(false));
        assert_eq!(cfg.build_target, "bb");
        assert_eq!(cfg.ccache_max_size, "4G");
        assert!(cfg.network, "container network defaults to true");
        // 全局 ccache_dir 不参与配置合并（merge.rs 只取产品级值或计算默认值），模板必须
        // 保持注释状态——否则编辑它静默无效；解除注释需先让 merge.rs 读取全局值。
        assert!(
            GLOBAL_CONFIG_TEMPLATE
                .lines()
                .all(|l| !l.trim_start().starts_with("ccache_dir")),
            "global ccache_dir must stay commented out until merge.rs reads it"
        );
    }

    #[test]
    fn parse_repo_config_defaults() {
        let toml = r#"
name = "base"
baseurl = "http://example.com/base/$basearch"
gpgcheck = false
"#;
        let cfg: RepoConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.name, "base");
        assert_eq!(cfg.baseurl, "http://example.com/base/$basearch");
        assert!(cfg.enabled);
        assert!(!cfg.gpgcheck);
        assert_eq!(cfg.priority, 99);
        assert_eq!(cfg.cost, 1000);
        assert!(!cfg.module_hotfixes);
        assert!(cfg.exclude.is_empty());
        assert!(cfg.includepkgs.is_empty());
    }

    #[test]
    fn parse_repo_config_all_fields() {
        let toml = r#"
name = "updates"
baseurl = "http://example.com/updates/$basearch"
enabled = false
priority = 10
cost = 500
module_hotfixes = true
exclude = ["kernel", "glibc"]
includepkgs = ["pkg1", "pkg2"]
extra = """
sslverify=0
proxy=http://proxy.example.com:8080
"""
"#;
        let cfg: RepoConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.name, "updates");
        assert!(!cfg.enabled);
        assert_eq!(cfg.priority, 10);
        assert_eq!(cfg.cost, 500);
        assert!(cfg.module_hotfixes);
        assert_eq!(cfg.exclude, vec!["kernel", "glibc"]);
        assert_eq!(cfg.includepkgs, vec!["pkg1", "pkg2"]);
        assert!(cfg.extra.as_ref().unwrap().contains("sslverify=0"));
    }
}
