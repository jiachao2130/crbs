// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 配置模块：全局配置、产品配置、运行时合并配置。

/// 全局配置 [`CrbsConfig`]（`/etc/crbs/crbs.toml`）：结构定义与加载入口。
pub mod crbs_config;
/// serde `default` 默认值函数集：构建用户/UID、目录路径等未配置时的硬编码默认。
pub mod defaults;
/// 配置合并：RPM 宏与 hooks 的全局→产品叠加、父子产品配置合并（`+field` 追加落点）。
pub mod merge;
/// 产品配置 [`ProductConfig`]（`/etc/crbs/products/{product}.toml`）：定义、加载与 TOML 序列化。
pub mod product;
/// 合并后的运行时配置 [`Config`]（BuildEngine 的配置入口）与产品展示详情 [`ProductDetail`]。
pub mod runtime;
pub mod server;
/// `crbs init` 生成配置文件用的内嵌 TOML 模板（全局 / 产品各一份）。
pub mod templates;
/// 配置线格式共享类型（BoolOrPackages、Hooks、Remote、Repo 等）、`config_path`
/// 解析与跨子模块类型 re-export。
pub mod types;
/// 配置字段校验：build_target、资源限额、确定性模式前置、产品/仓库名与配置目录。
pub mod validation;

pub use server::{
    LogSanitizationConfig, PublicAccessConfig, SchedulerMode, ServerConfig, ServerTlsConfig,
};
pub use types::{
    BoolOrPackages, Config, CrbsConfig, Hooks, HooksConfig, PostInitCommand, ProductConfig,
    ProductDetail, RemoteConfig, RemoteProfile, RepoConfig, ResourceOverride, SpecHooksConfig,
    GLOBAL_CONFIG_TEMPLATE, PRODUCT_CONFIG_TEMPLATE,
};

pub use types::config_path;

// 供 config::validation 之外使用：build_options 资源限额校验、server submit 确定性前置、
// hub 终态 cap-OOM 判定（parse_memory_max_kb）、放置契约下限解析（parse_resource_min_kb）。
pub use validation::{
    parse_memory_max_kb, parse_resource_min_kb, validate_cpu_quota,
    validate_deterministic_preconditions, validate_memory_max,
};

/// 各侧配置文件的手写 JSON Schema（draft-07），随二进制嵌入（`crbs config schema` 导出）。
/// 校验入口：crbs.toml / products/*.toml / server.toml / worker.toml → `#/$defs/` 下
/// CrbsConfig / ProductConfig / ServerConfig / WorkerConfig。`schema_tests.rs` 完备性
/// 测试锁定与结构体同步：默认配置字段路径必须存在于 schema properties，schema 属性
/// 反推回 TOML 必须过 `deny_unknown_fields` 反序列化，新增 Deserialize 结构体必须
/// 显式登记（入 schema / 声明非文件配置）；扫描 crbs-core config+privilege 与
/// crbs-worker config.rs，crbs-core 不反向依赖 crbs-worker，WorkerConfig def 免反推
/// 防线，由样例键覆盖与 worker 自身测试兜底。
pub const CONFIG_SCHEMA_JSON: &str = include_str!("config.schema.json");

#[cfg(test)]
mod schema_tests;

#[cfg(test)]
mod tests;
